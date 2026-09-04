// axum file server + QR code endpoint.
// The Tauri window loads http://localhost:PORT directly; the phone scans the QR
// code in the window to reach the same page.
// Files are no longer piled into shared/: a catalog index + inbox directory,
// with the transfer layer dispatching per source.
use axum::{
    body::Body,
    extract::{connect_info::ConnectInfo, Multipart, Query, Request, State},
    http::{header, HeaderMap, HeaderValue, StatusCode, Uri},
    middleware::{from_fn, Next},
    response::{Html, IntoResponse, Json, Response, sse::{Event, Sse, KeepAlive}},
    routing::{get, post},
    Router,
};
use axum::extract::DefaultBodyLimit;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use std::sync::{Mutex, OnceLock};
use tokio::io::AsyncWriteExt;
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt as _;
use tokio_util::io::ReaderStream;

use crate::catalog;
use crate::logger::{loge, logf, logw};
use tauri::Manager;

/// The app logo, embedded so the frontend can show it (header brand, connect
/// gate, favicon) without shipping a separate file next to the exe.
static LOGO: &[u8] = include_bytes!("logo.svg");

/// Events pushed over the /events SSE channel. The frontend used to poll four
/// endpoints (/list, /dl-status, /info, /fw-status); now each of those states
/// arrives here as a typed, payload-carrying event, so a page only renders what
/// changed and polls no state endpoints.
#[derive(Clone)]
pub(crate) enum PushEvent {
    /// The full message list, on any add/delete/reference change.
    List(Vec<catalog::MsgItem>),
    /// Download progress for one transfer (throttled to ~1/s server-side; the
    /// final `sent >= total` tick fires immediately).
    Progress { id: String, total: u64, sent: u64, paused: bool },
    /// Firewall repair flag changed.
    Fw(bool),
    /// A LAN device connected/disconnected, or the server address changed.
    /// Consumers: the PC scan gate's first-connect latch + URL display, and
    /// the presence logs. There is no ambient online/offline UI on either end
    /// anymore (see the LIVENESS block — connectivity feedback is action-
    /// coupled), so a later `info` transition past the first connect only
    /// refreshes the shown address.
    Info { mobile_connected: bool, url: String, ip: String, port: u16 },
    /// [LIVENESS/reconcile] The one catch-up event: "you may have missed
    /// pushes — re-fetch /dl-status and reconcile your mirror, so no corner
    /// freezes on a stale percent or a pause/cancel affordance". The complete
    /// server trigger list:
    ///   - events(): a subscriber lagged the broadcast channel and dropped
    ///     events (surfaced as BroadcastStream lag),
    ///   - StreamCutGuard::drop: a stream was cut/cancelled and its live
    ///     entry was reaped,
    ///   - monitor_loop: stale entries were pruned (finished, or paused/
    ///     abandoned past the prune window),
    ///   - cancel(): a transfer was stopped by the PC — it pushes no terminal
    ///     progress tick, so clients must reconcile their mirrors away.
    /// Clients additionally reconcile on (re)connect and on visibilitychange
    /// (each pass pulls /list and /dl-status once). The phone keeps no
    /// /dl-status poll: its only transfer mirror is its own upload (page-owned,
    /// see the corner block), so the connect/resync passes cover it.
    Resync,
}

/// Live download progress keyed by message id, aggregated across the parallel
/// Range requests of one transfer. Both the PC and the phone render a shared
/// progress bar + speed on the timeline from pushed `progress` events (which
/// also covers browser-native downloads the client cannot measure itself).
#[derive(Clone, Default)]
struct DlProg {
    total: u64,
    sent: u64,
    /// Monotonic seconds-since-start of the last byte written / registration /
    /// pause flip (see touch_entry). Compared against now_mono() by the
    /// monitor's stall scan and prune, and by presence.
    last_ts: u64,
    /// Either side can pause a transfer via /dl-pause; the flag rides the next
    /// progress push so both devices converge on a shared paused state. The
    /// downloading side reacts by aborting (pause) or relaunching (resume).
    paused: bool,
    /// Last time a progress event was pushed for this transfer, to throttle SSE
    /// emissions to ~1/s per transfer (the frontend used to poll /dl-status).
    last_emit_ms: u64,
    /// Owner token of the stream currently serving this transfer (see
    /// StreamCutGuard): bumped on every /dl registration so a dropped older
    /// stream cannot reap an entry a newer resume has just re-registered.
    owner: u64,
}

/// Monotonic source of the owner tokens above.
static DL_OWNER_SEQ: AtomicU64 = AtomicU64::new(0);

static DL_PROGRESS: OnceLock<Mutex<std::collections::HashMap<String, DlProg>>> = OnceLock::new();

fn dl_progress() -> &'static Mutex<std::collections::HashMap<String, DlProg>> {
    DL_PROGRESS.get_or_init(|| Mutex::new(std::collections::HashMap::new()))
}

/// [LIVENESS/death] Mark a transfer as alive. The single writer of
/// DlProg::last_ts: registration, every chunk (either direction), pause flips
/// and the monitor's auto-pause all go through here. Read by the monitor's
/// stall scan and prune, and by presence (transfer_active_recently).
fn touch_entry(e: &mut DlProg) {
    e.last_ts = now_mono();
}

/// Ids whose transfer the PC asked to stop (/cancel). The upload writer and the
/// download stream poll this on every chunk and tear down when they see their
/// id. A fresh /dl request for the same id clears it, so stopping one download
/// never silently kills a later one of the same file.
static CANCELLED: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
fn cancelled() -> &'static Mutex<HashSet<String>> {
    CANCELLED.get_or_init(|| Mutex::new(HashSet::new()))
}

/// Poison-safe lock for the transfer map. A handler that panics while holding
/// this lock poisons the Mutex, after which every unwrap() would panic in turn
/// and take down the whole transfer + presence pipeline. DlProg holds only
/// counters with no cross-field invariant, so recovering the guard is safe:
/// the partial write is a stale progress value at worst, healed by the next
/// push or resync.
fn dl_lock() -> std::sync::MutexGuard<'static, std::collections::HashMap<String, DlProg>> {
    dl_progress().lock().unwrap_or_else(|e| e.into_inner())
}

/// Poison-safe lock for the cancelled-ids set (same rationale as dl_lock).
fn cancel_lock() -> std::sync::MutexGuard<'static, HashSet<String>> {
    cancelled().lock().unwrap_or_else(|e| e.into_inner())
}

/// Millisecond clock for throttling progress pushes (wall clock; fine for a
/// coarse >= 1s gate).
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Push a progress event for `id`, throttled to ~1/s per transfer. Completion
/// (`sent >= total`) always emits immediately so both ends hide the row without
/// waiting for the next tick, as does `force` (pause/resume flips must reach
/// the other end right away). The caller already holds the dl_progress lock.
fn push_progress(
    map: &mut std::collections::HashMap<String, DlProg>,
    id: &str,
    now: u64,
    force: bool,
) {
    let Some(e) = map.get_mut(id) else { return };
    let done = e.sent >= e.total;
    if force || done || now.saturating_sub(e.last_emit_ms) >= 1000 {
        e.last_emit_ms = now;
        let _ = notifier().send(PushEvent::Progress {
            id: id.to_string(),
            total: e.total,
            sent: e.sent,
            paused: e.paused,
        });
    }
}

/// Preferred port; when taken, fall forward within the same range, and as a
/// last resort fall back to a kernel-assigned free port.
const PORT: u16 = 8765;

/// The port actually bound (written after a successful bind; used by handlers
/// like /qr to build URLs consistent with the window).
static BOUND_PORT: OnceLock<u16> = OnceLock::new();

/// Push channel: after any state change, a send notifies all clients subscribed
/// to /events with the new state (list, download progress, firewall, phone
/// presence). pub(crate) so firewall.rs can push the repair flag.
pub(crate) fn notifier() -> &'static broadcast::Sender<PushEvent> {
    static TX: OnceLock<broadcast::Sender<PushEvent>> = OnceLock::new();
    TX.get_or_init(|| broadcast::channel(64).0)
}

#[derive(serde::Deserialize)]
struct IdParam {
    id: String,
}

/// Upload query: the sender's declared file size (drives the pending row's
/// total for the shared ring). Absent -> total unknown until the body lands.
#[derive(serde::Deserialize)]
struct UpQuery {
    size: Option<u64>,
}

#[derive(serde::Deserialize)]
struct TextPayload {
    text: String,
}

/// Determine the sender from the requesting peer IP: loopback (127.x / ::1) ->
/// "pc", anything else -> "phone".
fn from_by_peer(peer: SocketAddr) -> &'static str {
    match peer.ip() {
        std::net::IpAddr::V4(v4) if v4.is_loopback() => "pc",
        std::net::IpAddr::V6(v6) if v6.is_loopback() => "pc",
        _ => "phone",
    }
}

/// Monotonic seconds-since-start of the most recent request from a non-local
/// (phone) device; 0 means no LAN request has ever arrived. The firewall
/// module reads it as positive proof that inbound traffic reaches this
/// machine. The PC's own requests go over loopback and never update it, so
/// the PC never counts itself.
static LAST_PHONE_ACT: AtomicU64 = AtomicU64::new(0);

/// Peers already warned about coming from a different subnet than the QR IP.
static SUBNET_WARNED: OnceLock<Mutex<std::collections::HashSet<String>>> = OnceLock::new();

/// Monotonic seconds since process start, offset to begin at 1 so that 0 can
/// serve as the permanent "never" sentinel for stamped values (LAST_PHONE_ACT,
/// DlProg::last_ts). With a 0-based clock, `now - 0` = uptime, which made a
/// freshly started process read as "a device was seen PRESENCE_ACT_SECS ago":
/// a phantom `device present` that latched the PC scan gate away before any
/// phone ever connected, and 30s of fake inbound-proof for the firewall. Every
/// liveness stamp in the pipeline is only ever compared against a later
/// `now_mono()`, so wall-clock jumps (NTP correction, manual clock change)
/// cannot freeze stall detection, pruning or presence either: a backward step
/// would otherwise make `now - stamp` saturate to 0 and hold every dead
/// transfer "alive" for the whole step duration.
fn now_mono() -> u64 {
    static T0: OnceLock<std::time::Instant> = OnceLock::new();
    T0.get_or_init(std::time::Instant::now).elapsed().as_secs() + 1
}

/// ── LIVENESS — the four-mechanism pipeline that keeps both ends honest ────
/// Every timer in the app belongs to exactly one of these; do not add more.
///
///   keep-alive    SSE_HEARTBEAT_SECS — the server emits bytes on an idle
///                 /events stream: NAT/AP cannot reap the socket, and the
///                 client's watchdog measures server death by its silence.
///   presence      PRESENCE_ACT_SECS — a LAN device is online while it holds
///                 an open /events stream or was active recently. Evidence
///                 writers (the only three): `log_requests` -> LAST_PHONE_ACT,
///                 `events`/PresenceGuard -> LAN_EVENTS_OPEN, transfer chunk
///                 writers -> DlProg::last_ts (via touch_entry). The monitor
///                 is the single announcer of transitions.
///                 Consumers are the PC scan gate's first-connect latch, the
///                 firewall's inbound-proof, and the logs — no UI light.
///                 KNOWN LIMITS (deliberate): presence is OPTIMISTIC — a phone
///                 that dies without a FIN keeps its stream "open" (and thus
///                 counts online) until TCP gives up, minutes later; and it is
///                 a GLOBAL aggregate, not per-device, so with several phones
///                 one active device covers the others. Fine because nothing
///                 destructive or user-facing depends on the bit.
///   death         a transfer ends only through its stream: cut ->
///                 StreamCutGuard (the only reaper of live entries), silence
///                 -> monitor auto-pause scan.
///   reconcile     PushEvent::Resync — the one catch-up event for "you may
///                 have missed pushes"; its full trigger list lives on that
///                 variant's doc. Clients also reconcile on (re)connect and
///                 on visibilitychange, each pass pulling /list and
///                 /dl-status once; there are no polling timers.
///
/// Desk-range profile: both devices are in hand and sessions are short, so
/// the numbers below are tight. One floor to respect: the presence window
/// must stay above the EventSource reconnect delay (retry, 1s, set on every
/// replayed event in events()) or a stream blip flaps the presence bit.
const SSE_HEARTBEAT_SECS: u64 = 1;

/// [LIVENESS/death] Seconds a served download may go without a byte written
/// before the monitor auto-pauses it: the peer died or its connection went
/// silent (a killed browser, a half-open TCP). Without this the sender would
/// show a stuck "Transferring…" forever; pausing makes the row read "Paused"
/// and a later resume (/dl-pause paused=0) re-arms it. Floor: the longest
/// legitimate write gap of a healthy LAN transfer (milliseconds), with margin.
const STALL_AUTO_PAUSE_SECS: u64 = 3;

/// [LIVENESS/presence] Seconds of LAN silence (no request at all) before a
/// device that holds no /events stream is treated as gone. A download or page
/// load counts as proof of presence too — "the phone can reach the server" is
/// what presence evidence means, not just "its /events stream is open". Must
/// stay above the SSE retry delay (see the LIVENESS block) so a blip cannot
/// flap.
const PRESENCE_ACT_SECS: u64 = 3;

/// Whether a non-loopback (LAN) device has made a request within the last
/// `secs` seconds. This is positive proof that inbound traffic is not blocked:
/// rule inspection can be wrong or unavailable, but packets arriving are
/// packets arriving. The firewall module uses it as the ground truth to clear
/// the repair flag.
pub(crate) fn lan_seen_recently(secs: u64) -> bool {
    let last = LAST_PHONE_ACT.load(Ordering::Relaxed);
    // 0 = "never" sentinel: without this guard, `now - 0` = uptime, which read
    // as recent activity for the first `secs` of every process start.
    last != 0 && now_mono().saturating_sub(last) < secs
}

/// How many /events streams are currently open from a non-loopback peer. A
/// device is "online" exactly while it holds one open — its page is alive and
/// reachable for pushes. No periodic ping: a live page keeps its EventSource
/// open (the server's keepalives keep it warm), and after any drop it
/// reconnects, reopening a stream and flipping presence back on. The monitor
/// debounces the count so a quick reconnect never reads as a drop.
static LAN_EVENTS_OPEN: AtomicU64 = AtomicU64::new(0);

/// Whether a LAN device is present: it either holds an open /events stream, or
/// is actively reaching this machine (a request in the last few seconds, or a
/// transfer whose bytes are still flowing — e.g. a native download running even
/// while its page's /events is down). "The phone can reach the server" is the
/// question, so any of those counts. See the KNOWN LIMITS in the LIVENESS
/// block: optimistic under no-FIN death, and global rather than per-device.
fn lan_peer_connected() -> bool {
    LAN_EVENTS_OPEN.load(Ordering::Relaxed) > 0
        || lan_seen_recently(PRESENCE_ACT_SECS)
        || transfer_active_recently(PRESENCE_ACT_SECS)
}

/// Any in-flight download whose streams pushed bytes within the last `secs`
/// seconds: a transfer can hold its Range streams open with no new HTTP request
/// arriving (which lan_seen_recently would miss), so the firewall treats
/// flowing bytes as positive evidence inbound is open.
pub(crate) fn transfer_active_recently(secs: u64) -> bool {
    let now = now_mono();
    let map = dl_lock();
    map.iter()
        .any(|(_, e)| {
            e.sent < e.total
                && e.last_ts != 0  // 0 = never touched (defensive; creators always touch)
                && now.saturating_sub(e.last_ts) < secs
        })
}

/// One-line snapshot of the three presence evidence sources, for the monitor's
/// transition log: how many /events streams are open, how long ago the last
/// LAN request arrived, how long ago an in-flight transfer last wrote a byte.
/// "never" marks a still-0 stamp (see now_mono's sentinel). Mirrors what
/// lan_peer_connected() actually reads — completed transfers are not evidence,
/// so xfer only tracks entries with sent < total.
fn presence_evidence() -> String {
    let now = now_mono();
    let streams = LAN_EVENTS_OPEN.load(Ordering::Relaxed);
    let req = match LAST_PHONE_ACT.load(Ordering::Relaxed) {
        0 => "never".to_string(),
        t => format!("{}s ago", now.saturating_sub(t)),
    };
    let xfer = dl_lock()
        .values()
        .filter(|e| e.sent < e.total && e.last_ts != 0)
        .map(|e| e.last_ts)
        .max()
        .map_or("never".to_string(), |t| format!("{}s ago", now.saturating_sub(t)));
    format!("streams={streams} req={req} xfer={xfer}")
}

/// Log every incoming HTTP request and its source IP (key diagnostic: if a
/// phone request never shows up here, the request never reached this machine —
/// firewall, wrong IP, AP isolation, or the phone is not on this network at
/// all). Responses with status >= 400 get a second line, since a request that
/// arrives and then fails server-side is a different failure mode than one
/// that never arrives.
async fn log_requests(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Response {
    let is_lan = !peer.ip().is_loopback();
    if is_lan {
        LAST_PHONE_ACT.store(now_mono(), Ordering::Relaxed);
        note_foreign_subnet(&peer);
    }
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    // High-frequency endpoints would otherwise log a line every second
    // (dl-status on each connect/resync, list on every SSE re-render) and bury
    // meaningful events. Log them only when they error below.
    if method.as_str() != "GET" || !is_quiet_poll(&path) {
        logf(&format!("{} {} <- {}", method, path, peer));
    }
    let resp = next.run(req).await;
    if resp.status().as_u16() >= 400 {
        logf(&format!(
            "{} {} <- {} -> error response {}",
            method,
            path,
            peer,
            resp.status().as_u16()
        ));
    }
    resp
}

/// Endpoints hit once per SSE connect (or on a rare one-shot resync), whose
/// successful responses are not worth a log line. /info and /fw-status are gone
/// entirely: their state now arrives over the /events push channel.
fn is_quiet_poll(path: &str) -> bool {
    matches!(path, "/dl-status" | "/list")
}

/// A LAN peer whose /24 differs from the address the QR code points at is the
/// classic "phone joined the guest network / the other band" symptom: packets
/// still arrive but the user thinks they scanned the right URL. Warn once per
/// peer.
fn note_foreign_subnet(peer: &SocketAddr) {
    let IpAddr::V4(peer_v4) = peer.ip() else { return };
    let Some(qr_ip) = collect_ips().first().cloned() else { return };
    let Ok(qr_v4) = qr_ip.parse::<Ipv4Addr>() else { return };
    let same = qr_v4.octets()[..3] == peer_v4.octets()[..3];
    if same {
        return;
    }
    let key = peer.ip().to_string();
    let set = SUBNET_WARNED.get_or_init(|| Mutex::new(std::collections::HashSet::new()));
    let mut set = set.lock().unwrap_or_else(|e| e.into_inner());
    if set.contains(&key) {
        return;
    }
    set.insert(key);
    logf(&format!(
        "warning: request from {} is in a different subnet than the QR IP {} (phone may be on a guest network or another WiFi band)",
        peer.ip(), qr_ip
    ));
}

/// Find an available port starting from the preferred one: try 8765..8780 one
/// by one; if all are taken, bind port 0 (kernel assigns a free port).
async fn bind_any() -> std::io::Result<(tokio::net::TcpListener, u16)> {
    for port in PORT..PORT + 16 {
        match bind_listener(port).await {
            Ok(l) => return Ok((l, port)),
            Err(_) => logw(&format!("port {port} is in use, trying the next one")),
        }
    }
    let l = bind_listener(0).await?;
    let port = l.local_addr()?.port();
    Ok((l, port))
}

/// Bind a listening socket with SO_REUSEADDR. On Windows a killed server's
/// accepted connections linger in TIME_WAIT for ~2 minutes; without reuse the
/// same port cannot rebind right after a restart, the app flips to the next
/// port, and the already-open phone has to rescan the QR. Reuse keeps the same
/// URL across restarts so the phone reconnects by itself.
async fn bind_listener(port: u16) -> std::io::Result<tokio::net::TcpListener> {
    let socket = tokio::net::TcpSocket::new_v4()?;
    socket.set_reuseaddr(true)?;
    // Windows' default SO_SNDBUF is ~64 KB, which caps one LAN stream at
    // buffer/RTT (64 KB / 5 ms ~ 12 MB/s, far less on congested WiFi), and the
    // parallel chunks each inherit that ceiling. A large send buffer lets the
    // server keep the pipe full; accepted sockets inherit SO_SNDBUF on Windows.
    socket.set_send_buffer_size(4 * 1024 * 1024)?;
    socket.bind(std::net::SocketAddr::from(([0, 0, 0, 0], port)))?;
    socket.listen(1024)
}

/// Start axum on a separate thread; once the port is bound, send the actual
/// port back through a channel (so Tauri setup can wait, then build the window
/// URL). The app_handle goes into the Router state for handlers like /repair
/// and /quit.
pub fn spawn(app_handle: tauri::AppHandle) -> tokio::sync::oneshot::Receiver<Option<u16>> {
    let (tx, rx) = tokio::sync::oneshot::channel::<Option<u16>>();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            // Exe path matters for diagnosis: Windows Firewall rules are keyed
            // to it, so a moved/renamed exe silently loses its Allow rule.
            let exe = std::env::current_exe()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_else(|_| "<unknown>".to_string());
            logf(&format!(
                "tinbox v{} starting; exe={}; log file at tinbox.log next to the exe",
                env!("CARGO_PKG_VERSION"),
                exe
            ));

            // Inbox directory (next to the exe); ensure it exists on first run.
            if let Err(e) = std::fs::create_dir_all(catalog::inbox_dir()) {
                loge(&format!("could not create inbox directory: {}", e));
            }

            // Load the index; if empty and a legacy shared directory exists,
            // run the one-time migration (transparent to existing users).
            catalog::load();
            if catalog::all_items().is_empty() {
                migrate_legacy_shared();
            }
            // A crash can leave a pending upload behind (entry + partial file);
            // drop them so no stale half-file surfaces in the timeline.
            catalog::purge_pending();

            let app = Router::new()
                .route("/", get(index))
                .route("/list", get(list))
                .route("/upload", post(upload))
                .route("/add-local", post(add_local))
                .route("/send-text", post(send_text))
                .route("/log", post(client_log))
                .route("/dl", get(download))
                .route("/dl-status", get(dl_status))
                .route("/dl-pause", post(dl_pause))
                .route("/cancel", post(cancel))
                .route("/view", get(view))
                .route("/open", post(open_file))
                .route("/rm", post(remove))
                .route("/qr", get(qr))
                .route("/logo", get(logo))
                .route("/favicon.ico", get(logo))
                .route("/apple-touch-icon.png", get(logo))
                .route("/apple-touch-icon-precomposed.png", get(logo))
                .route("/open-dir", post(open_dir))
                .route("/reveal", post(reveal))
                .route("/events", get(events))
                .route("/repair", post(repair))
                .route("/quit", post(quit))
                .route("/untop", post(untop))
                .layer(from_fn(log_requests))
                .layer(DefaultBodyLimit::max(2 * 1024 * 1024 * 1024))
                .with_state(app_handle);

            // Find an available port: preferred 8765, fall forward when taken,
            // and let the kernel pick a free port when the range is exhausted.
            let (listener, actual) = match bind_any().await {
                Ok(v) => v,
                Err(e) => {
                    loge(&format!("could not bind any port: {}", e));
                    let _ = tx.send(None);
                    return;
                }
            };
            let _ = BOUND_PORT.set(actual);
            // IP encoded in the QR code: take the first (WiFi segment
            // preferred). If the phone cannot connect, compare this IP with the
            // machine's actual subnet.
            let ips = collect_ips();
            let ip = ips.first().cloned().unwrap_or_else(|| "127.0.0.1".to_string());
            logf(&format!(
                "listening on 0.0.0.0:{}; QR code points at http://{}:{}; candidate IPs={:?}",
                actual, ip, actual, ips
            ));
            logf(
                "diagnostics - how to read this log: every phone request logs a '<phone-ip> GET ...' \
                 line. If the phone cannot open the page, those lines are absent, meaning requests \
                 never reached this PC (firewall block, wrong QR IP, or router AP isolation / \
                 another network). Any failure the server does see appears as an 'error response' \
                 line",
            );
            let _ = tx.send(Some(actual));
            // Background state monitor: device presence, the firewall repair flag
            // and stale download entries are watched here and pushed over
            // /events, so the frontend never polls /info or /fw-status.
            tokio::spawn(monitor_loop());
            if let Err(e) = axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            {
                loge(&format!("server error: {}", e));
            }
        });
    });
    rx
}

/// Old versions piled files into shared/; after an upgrade, move them into
/// inbox and register them as remote entries.
fn migrate_legacy_shared() {
    let shared = catalog::legacy_shared_dir();
    if !shared.exists() {
        return;
    }
    let inbox = catalog::inbox_dir();
    let _ = std::fs::create_dir_all(&inbox);
    let mut moved = 0;
    if let Ok(entries) = std::fs::read_dir(&shared) {
        for entry in entries.flatten() {
            if let Ok(meta) = entry.metadata() {
                if !meta.is_file() {
                    continue;
                }
                let name = entry.file_name().to_string_lossy().to_string();
                let safe = safe_name(&name);
                if safe.is_empty() {
                    continue;
                }
                let id = catalog::new_id();
                let stored = inbox.join(format!("{id}__{safe}"));
                // shared and inbox are on the same disk, so rename is an
                // instant move, not a copy.
                if std::fs::rename(entry.path(), &stored).is_ok() {
                    catalog::add_remote("phone", &id, &stored, &safe);
                    moved += 1;
                }
            }
        }
    }
    if moved > 0 {
        logf(&format!(
            "migrated {} files from the old shared directory to inbox",
            moved
        ));
    }
    // Remove the now-empty directory so it is not mistaken for being still in
    // use.
    let _ = std::fs::remove_dir(&shared);
}

fn safe_name(s: &str) -> String {
    let name = Path::new(s.trim())
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_string();
    if name.is_empty() || name == "." || name == ".." {
        String::new()
    } else {
        name
    }
}

async fn index() -> impl IntoResponse {
    // The page is compiled into this binary; a browser-cached copy would drift
    // from the server's behavior after an update (phone Safari caches
    // heuristically), so forbid reuse and always re-fetch.
    (
        [(header::CACHE_CONTROL, "no-cache")],
        Html(include_str!("index.html")),
    )
}

async fn list() -> impl IntoResponse {
    // all_items is already sorted by ts ascending (timeline order).
    Json(catalog::all_items())
}

async fn upload(Query(q): Query<UpQuery>, mut multipart: Multipart) -> impl IntoResponse {
    loop {
        let mut field = match multipart.next_field().await {
            Ok(Some(f)) => f,
            Ok(None) => return (StatusCode::BAD_REQUEST, "no file field").into_response(),
            Err(e) => return (StatusCode::BAD_REQUEST, format!("read: {e}")).into_response(),
        };
        if field.name() != Some("file") {
            continue;
        }
        let filename = safe_name(field.file_name().unwrap_or("unnamed"));
        if filename.is_empty() {
            return (StatusCode::BAD_REQUEST, "bad filename").into_response();
        }
        // Write to inbox, prefixing the filename with the id to prevent
        // same-name overwrites; the catalog id matches this prefix.
        let id = catalog::new_id();
        let stored = catalog::inbox_dir().join(format!("{id}__{filename}"));
        // Register the row as `pending` the moment the request lands, and seed a
        // shared byte counter, so BOTH ends render a progress ring immediately.
        // The sender reports its declared total via ?size=.
        let size = q.size.unwrap_or(0);
        catalog::add_remote_pending(&id, &stored, &filename, size);
        let _ = notifier().send(PushEvent::List(catalog::all_items()));
        {
            let mut map = dl_lock();
            let e = map.entry(id.clone()).or_default();
            e.total = size;
            e.sent = 0;
            touch_entry(e);
        }
        // Stream the body straight to disk instead of buffering it whole in
        // memory: a phone can send multi-GB videos, and buffering those would
        // spike RSS to the file size. The 512 KiB BufWriter coalesces the
        // small chunks the HTTP layer delivers (like LocalSend's save path).
        let file = match tokio::fs::File::create(&stored).await {
            Ok(f) => tokio::io::BufWriter::with_capacity(512 * 1024, f),
            Err(e) => {
                loge(&format!("upload create failed {}: {}", filename, e));
                catalog::remove(&id);
                dl_lock().remove(&id);
                let _ = notifier().send(PushEvent::List(catalog::all_items()));
                return (StatusCode::INTERNAL_SERVER_ERROR, format!("write: {e}"))
                    .into_response();
            }
        };
        let mut file = file;
        let mut total: u64 = 0;
        let write_result: Result<(), String> = loop {
            // The PC (receiver) asked to stop this upload (/cancel): drop it as a
            // failure so the row + partial file are cleaned up below. Noticed per
            // chunk, so latency is one body chunk once the flag is set.
            if cancel_lock().contains(&id) {
                break Err("cancelled by peer".to_string());
            }
            // [LIVENESS/death] A peer that dies without a FIN (WiFi drop, phone
            // crash) leaves this await pending forever — hyper has no body read
            // timeout. Wrap each chunk in a silence timeout so the upload tears
            // down exactly like the download side's stall auto-pause; the Err
            // arm below then drops the pending row + partial file. This works
            // here because the handler actively awaits the body — unlike the
            // download body stream, which backpressure stops polling, so it
            // needs the monitor's scan instead.
            match tokio::time::timeout(
                Duration::from_secs(STALL_AUTO_PAUSE_SECS),
                field.next(),
            )
            .await
            {
                Ok(Some(Ok(chunk))) => {
                    let n = chunk.len() as u64;
                    total += n;
                    if let Err(e) = file.write_all(&chunk).await {
                        break Err(format!("write: {e}"));
                    }
                    // Count received bytes and push ~1/s, mirroring download
                    // progress, so the ring on both ends tracks this counter.
                    let mut map = dl_lock();
                    if let Some(e) = map.get_mut(&id) {
                        e.sent += n;
                        touch_entry(e);
                    }
                    push_progress(&mut map, &id, now_ms(), false);
                }
                Ok(Some(Err(e))) => break Err(format!("read: {e}")),
                Ok(None) => {
                    break match file.flush().await {
                        Ok(()) => Ok(()),
                        Err(e) => Err(format!("flush: {e}")),
                    }
                }
                Err(_) => {
                    logf(&format!("upload stalled {id} after {total} bytes"));
                    break Err("peer stalled".to_string());
                }
            }
        };
        match write_result {
            Ok(()) => {
                catalog::mark_remote_ready(&id);
                logf(&format!("upload done: {} ({} bytes) -> inbox", filename, total));
                // Final tick (sent == total) closes the ring on both ends.
                {
                    let mut map = dl_lock();
                    if let Some(e) = map.get_mut(&id) {
                        e.sent = e.total.max(e.sent);
                        touch_entry(e);
                    }
                    push_progress(&mut map, &id, now_ms(), true);
                }
                let _ = notifier().send(PushEvent::List(catalog::all_items()));
                return (StatusCode::OK, format!("uploaded: {filename}")).into_response();
            }
            Err(e) => {
                // Aborted or failed mid-transfer: drop the pending row and the
                // partial file; do NOT leave the entry in the catalog.
                drop(file);
                catalog::remove(&id);
                let _ = std::fs::remove_file(&stored);
                dl_lock().remove(&id);
                let _ = notifier().send(PushEvent::List(catalog::all_items()));
                logw(&format!("upload failed {} after {} bytes: {}", filename, total, e));
                return (StatusCode::BAD_REQUEST, e).into_response();
            }
        }
    }
}

/// Send a text message. The sender is determined from the source IP (loopback
/// = pc, anything else = phone).
async fn send_text(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    axum::Json(payload): axum::Json<TextPayload>,
) -> impl IntoResponse {
    let text = payload.text.trim();
    if text.is_empty() {
        return (StatusCode::BAD_REQUEST, "empty text").into_response();
    }
    let from = from_by_peer(peer);
    catalog::add_text(from, text);
    logf(&format!("send-text: from={} len={}", from, text.chars().count()));
    let _ = notifier().send(PushEvent::List(catalog::all_items()));
    (StatusCode::OK, "sent").into_response()
}

#[derive(serde::Deserialize)]
struct AddLocalPayload {
    paths: Vec<String>,
}

/// After the PC side's plus button picks real paths via the Tauri dialog, POST
/// them here. Each chosen file is COPIED into the inbox folder (`{id}__{name}`)
/// and only then registered as a ready from="pc" entry — a card appears only once
/// the copy is complete, so there is no intermediate "copying" state to confuse
/// with a real transfer. Not routed through a custom command, avoiding the ACL
/// restrictions on external URLs.
///
/// Copying reads arbitrary PC-local paths, so this endpoint is PC-only (the same
/// guard /cancel and /rm use): the phone must not be able to reach it.
async fn add_local(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    axum::Json(payload): axum::Json<AddLocalPayload>,
) -> impl IntoResponse {
    if from_by_peer(peer) != "pc" {
        logw("add-local: rejected from phone (would copy PC-local paths)");
        return (StatusCode::FORBIDDEN, "phone cannot add PC-local files").into_response();
    }
    let inbox = catalog::inbox_dir();
    if let Err(e) = std::fs::create_dir_all(&inbox) {
        loge(&format!("add-local: inbox unavailable: {e}"));
        return (StatusCode::INTERNAL_SERVER_ERROR, "inbox unavailable").into_response();
    }
    // Canonical inbox path, so a re-drag of a file already inside inbox is skipped.
    let inbox_canon = std::fs::canonicalize(&inbox).unwrap_or_else(|_| inbox.clone());

    // Expand directories into a flat file list.
    let mut files: Vec<PathBuf> = Vec::new();
    for raw in payload.paths {
        let p = PathBuf::from(raw);
        if p.is_dir() {
            catalog::collect_files(&p, &mut files);
        } else if p.is_file() {
            files.push(p);
        } else {
            logw(&format!("add-local: skipped (not a file/dir): {}", p.display()));
        }
    }

    let mut added = 0usize;
    let mut attempted = 0usize;
    for src in files {
        // Re-adding a path that already lives in inbox would copy inbox into
        // itself; skip it.
        let Ok(canon) = std::fs::canonicalize(&src) else {
            logw(&format!("add-local: source missing: {}", src.display()));
            continue;
        };
        if canon.starts_with(&inbox_canon) {
            logf(&format!("add-local: skip already-in-inbox {}", canon.display()));
            continue;
        }
        attempted += 1;
        match copy_into_inbox(&canon).await {
            Ok((id, dest, safe)) => {
                catalog::add_remote("pc", &id, &dest, &safe);
                added += 1;
                // The card appears now that the file is fully in inbox.
                let _ = notifier().send(PushEvent::List(catalog::all_items()));
                logf(&format!(
                    "add-local: copied {} -> {}",
                    canon.display(),
                    dest.display()
                ));
            }
            Err(e) => logw(&format!("add-local: copy failed {}: {}", canon.display(), e)),
        }
    }
    if attempted > 0 && added == 0 {
        return (StatusCode::BAD_REQUEST, "could not add any file").into_response();
    }
    logf(&format!("add-local: added {added} file(s) to inbox"));
    (StatusCode::OK, format!("added: {added}")).into_response()
}

/// Stream one file into inbox as `{id}__{safe_name}` with async I/O (never
/// blocks a runtime thread). Returns (id, inbox path, display name) only once the
/// whole file is on disk; on error the partial destination is removed so no
/// half-written file lingers.
async fn copy_into_inbox(src: &Path) -> std::io::Result<(String, PathBuf, String)> {
    let safe = safe_name(
        src.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unnamed"),
    );
    if safe.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "bad file name",
        ));
    }
    let id = catalog::new_id();
    let dest = catalog::inbox_dir().join(format!("{id}__{safe}"));

    let src_f = tokio::fs::File::open(src).await?;
    let dst_f = tokio::fs::File::create(&dest).await?;
    let mut reader = tokio::io::BufReader::with_capacity(512 * 1024, src_f);
    let mut writer = tokio::io::BufWriter::with_capacity(512 * 1024, dst_f);
    if let Err(e) = tokio::io::copy_buf(&mut reader, &mut writer).await {
        drop(writer); // release the handle so remove_file works on Windows
        let _ = tokio::fs::remove_file(&dest).await;
        return Err(e);
    }
    // Flush to surface disk-full / late write errors before registering ready.
    if let Err(e) = writer.flush().await {
        drop(writer);
        let _ = tokio::fs::remove_file(&dest).await;
        return Err(e);
    }
    drop(writer);
    Ok((id, dest, safe))
}

/// For frontend error reporting: write client-side exceptions into the server
/// log (e.g. invoke failures, dialog permission denials, etc.).
#[derive(serde::Deserialize)]
struct ClientLogPayload {
    msg: String,
}
async fn client_log(axum::Json(payload): axum::Json<ClientLogPayload>) -> impl IntoResponse {
    logf(&format!("client: {}", payload.msg));
    (StatusCode::OK, "logged").into_response()
}

/// Frontend "Repair" click: launch elevated UAC to delete the Block and add an
/// Allow rule.
async fn repair(State(_app): State<tauri::AppHandle>) -> impl IntoResponse {
    // repair() blocks synchronously waiting for UAC + Block removal (can take
    // 10s+), so run it in spawn_blocking to keep the axum runtime responsive.
    let ok = tokio::task::spawn_blocking(crate::firewall::repair)
        .await
        .unwrap_or(false);
    logf(if ok { "/repair: repair succeeded" } else { "/repair: not fixed (UAC cancelled or failed)" });
    (StatusCode::OK, if ok { "ok" } else { "failed" }).into_response()
}

/// Frontend "Quit" click: without network access the app is pointless.
async fn quit(State(app): State<tauri::AppHandle>) -> impl IntoResponse {
    crate::firewall::quit(&app);
    (StatusCode::OK, "quitting").into_response()
}

/// Once the repair-overlay disappears, un-pin the window (back to normal).
async fn untop(State(app): State<tauri::AppHandle>) -> impl IntoResponse {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.set_always_on_top(false);
    }
    (StatusCode::OK, "ok").into_response()
}

/// Infer Content-Type from the file extension for /view so the browser can
/// preview images/videos/PDFs/text inline. Types the browser cannot open
/// (office docs, archives, etc.) return octet-stream and automatically fall
/// back to download.
fn mime_for(name: &str) -> String {
    let ext = Path::new(name)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();
    let m = match ext.as_str() {
        "txt" | "md" | "log" | "csv" => "text/plain; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" => "text/javascript; charset=utf-8",
        "json" => "application/json",
        "xml" => "application/xml",
        "pdf" => "application/pdf",
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "bmp" => "image/bmp",
        "svg" => "image/svg+xml",
        "mp4" => "video/mp4",
        "webm" => "video/webm",
        "mov" => "video/quicktime",
        "mkv" => "video/x-matroska",
        "mp3" => "audio/mpeg",
        "m4a" => "audio/mp4",
        "wav" => "audio/wav",
        "ogg" => "audio/ogg",
        "flac" => "audio/flac",
        // Rendering HTML inline would execute scripts, which is risky; leave it
        // unrecognized -> download instead of rendering directly.
        _ => "application/octet-stream",
    };
    m.to_string()
}

/// [LIVENESS/death] Drop-guard on a served download body, and the only reaper
/// of live transfer entries. When hyper drops the response body before the
/// file was fully sent, the downloading peer is gone (browser cancel, killed
/// tab, WiFi drop) — axum surfaces a disconnect as the body being dropped, not
/// as an error inside the stream, so a per-chunk error arm never sees it.
/// This guard removes the shared counter and asks every client to reconcile
/// its mirror, so a dead transfer cannot leave a corner stuck on a stale
/// percent or a pause/cancel affordance. It only reaps its OWN stream's entry
/// (checked via the owner token, so a Range resume that has already
/// re-registered the id is never clobbered), and never a paused one — pause
/// state must survive the stream and is retired by the monitor's prune.
struct StreamCutGuard {
    id: String,
    owner: u64,
}
impl Drop for StreamCutGuard {
    fn drop(&mut self) {
        let mut map = dl_lock();
        let owned_incomplete = match map.get(&self.id) {
            Some(e) => e.owner == self.owner && e.sent < e.total && !e.paused,
            None => false,
        };
        if owned_incomplete {
            map.remove(&self.id);
            drop(map);
            logf(&format!("download aborted by peer {}: counter dropped", self.id));
            let _ = notifier().send(PushEvent::Resync);
        }
    }
}

/// Shared file dispatch: inline=true previews in the browser (/view), false
/// forces a download (/dl). Looks up the message by id; only File messages can
/// be dispatched, Text returns 400.
async fn serve(Query(p): Query<IdParam>, inline: bool, headers: HeaderMap, uri: Uri) -> impl IntoResponse {
    let Some(entry) = catalog::find(&p.id) else {
        logw(&format!("serve: id {} not found", p.id));
        return (StatusCode::NOT_FOUND, "not found").into_response();
    };
    // A file still being uploaded has nothing to serve yet (partial on disk).
    if entry.pending {
        return (StatusCode::NOT_FOUND, "still uploading").into_response();
    }
    let (path, name) = match &entry.body {
        catalog::MsgBody::File { source, name, .. } => (source.path(), name.as_str()),
        catalog::MsgBody::Text { .. } => {
            return (StatusCode::BAD_REQUEST, "not a file").into_response();
        }
    };
    let mut file = match tokio::fs::File::open(path).await {
        Ok(f) => f,
        // The backing file may be missing: a Remote inbox copy was deleted, or a
        // legacy Local original was moved/deleted -> friendly message.
        Err(_) => {
            logw(&format!("serve: file not on disk {} ({})", name, path));
            return (StatusCode::NOT_FOUND, "file missing").into_response();
        }
    };
    // Read the file size to set Content-Length so the frontend can show a
    // download progress bar and speed.
    let len = file.metadata().await.map(|m| m.len()).unwrap_or(0);

    // Range support: the phone resumes interrupted downloads by asking for
    // bytes=N- instead of re-fetching the whole file, and media previews get
    // seekable playback for free. Malformed / multi-range headers fall through
    // to a full 200 body.
    logf(&format!(
        "serve {} q={:?} range={:?} ua={:?}",
        p.id,
        uri.query(),
        headers.get(header::RANGE).and_then(|v| v.to_str().ok()),
        headers.get(header::USER_AGENT).and_then(|v| v.to_str().ok())
    ));
    let (start, end, partial) = match headers
        .get(header::RANGE)
        .and_then(|v| v.to_str().ok())
        .and_then(|r| parse_range(r, len))
    {
        Some(Ok((s, e))) => (s, e, true),
        // Unsatisfiable: start is past the end of the file -> 416 with the
        // resource length advertised for a retry.
        Some(Err(())) => {
            return (
                StatusCode::RANGE_NOT_SATISFIABLE,
                [(header::CONTENT_RANGE, format!("bytes */{len}"))],
            )
                .into_response();
        }
        None => (0, len.saturating_sub(1), false),
    };

    use tokio::io::{AsyncReadExt, AsyncSeekExt};
    if start > 0 {
        if let Err(e) = file.seek(std::io::SeekFrom::Start(start)).await {
            logw(&format!("serve: seek failed {}: {}", path, e));
            return (StatusCode::INTERNAL_SERVER_ERROR, "seek failed").into_response();
        }
    }
    // Progress tracking: real downloads (not inline previews) register a
    // shared counter per message id, and each chunk written to the socket is
    // counted and pushed as a `progress` event, so both ends show the same
    // bar/speed. Parallel Range requests accumulate into the same entry.
    let prog_id = if inline { None } else { Some(p.id.clone()) };
    let mut owner = 0u64;
    if let Some(id) = &prog_id {
        // Any /dl request is a fresh transfer (or an OS resume of one): clear an
        // earlier stop so it can run — a cancelled download must not silently
        // kill the next attempt at the same file.
        cancel_lock().remove(id);
        let mut map = dl_lock();
        let fresh = {
            let e = map.entry(id.clone()).or_default();
            // A full-body (no-Range) request means "fetch the whole file from 0":
            // reset the counter so a re-download (or a download that restarted)
            // never looks complete because an older entry still holds sent==total.
            // Range requests instead continue the existing counter — an
            // interrupted native download resuming exactly where it stopped. Any
            // new stream also clears a stale auto-pause.
            let fresh = !partial || e.total == 0;
            if fresh {
                // A full-body request re-downloads from byte 0. A Range resume of a
                // file the peer already partially holds (whose earlier entry was
                // dropped on a stream cut) seeds the counter with the bytes it has,
                // so the resumed transfer reads true progress instead of restarting
                // at 0 and never reaching 100%.
                e.sent = if partial { start } else { 0 };
            }
            e.paused = false;
            e.total = len;
            touch_entry(e);
            // This stream now owns the entry: bump the token so an older dropped
            // stream's guard cannot reap it (see StreamCutGuard).
            e.owner = DL_OWNER_SEQ.fetch_add(1, Ordering::Relaxed) + 1;
            owner = e.owner;
            fresh
        };
        if fresh {
            logf(&format!("download start {id}: {name} [{start}-{end}]/{len}"));
        }
    }
    // Take() caps the read at the range end so a partial response carries
    // exactly end-start+1 bytes, not the rest of the file. A large read buffer
    // matters for throughput: 16KB chunks (ReaderStream default) saturate the
    // LAN poorly, 512KB keeps the TCP send buffer full and pushes real WiFi
    // speeds instead of 2 MB/s.
    let base = ReaderStream::with_capacity(file.take(end - start + 1), 1024 * 1024);
    let stream: std::pin::Pin<
        Box<dyn tokio_stream::Stream<Item = Result<axum::body::Bytes, std::io::Error>> + Send>,
    > = match &prog_id {
        Some(id) => {
            let id = id.clone();
            // Held for the stream's whole life: on drop (peer gone mid-transfer)
            // it removes the counter and tells clients to reconcile.
            let cut = StreamCutGuard { id: id.clone(), owner };
            Box::pin(base.map(move |chunk| {
                // Referencing `cut` keeps it captured, so it is dropped only when
                // the whole stream (and thus this closure) is dropped by hyper.
                let _alive = &cut;
                // The PC asked to stop this download (/cancel): end the stream so
                // the receiver's in-flight download is cut (its OS then reports it
                // interrupted) instead of being allowed to drain.
                if cancel_lock().contains(&id) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Interrupted,
                        "transfer cancelled by PC",
                    ));
                }
                match &chunk {
                    Ok(b) => {
                        let mut map = dl_lock();
                        if let Some(e) = map.get_mut(&id) {
                            let before = e.sent;
                            e.sent += b.len() as u64;
                            touch_entry(e);
                            if before < e.total && e.sent >= e.total {
                                logf(&format!("download done {id}: {} bytes", e.sent));
                            }
                        }
                        // Push throttled ~1/s per transfer (instant on completion)
                        // so both ends get live progress without polling.
                        push_progress(&mut map, &id, now_ms(), false);
                    }
                    Err(err) => {
                        // The peer closed/cut this stream (pause, tab killed, WiFi
                        // drop) or a /cancel interrupted it. hyper surfaces a real
                        // disconnect as the response body being dropped, not as an
                        // error here, so cleanup happens in StreamCutGuard::drop.
                        logw(&format!("download stream cut {id}: {err}"));
                    }
                }
                chunk
            }))
        }
        None => Box::pin(base),
    };
    // Downloads (not inline previews) get a throughput measurement: when the
    // stream completes, log MB/s server->socket. If the server logs fast but
    // the phone UI is slow, the bottleneck is the client/WiFi, not this side.
    let body = if inline {
        Body::from_stream(stream)
    } else {
        Body::from_stream(Measured {
            inner: stream,
            label: format!("{} [{start}-{end}]", name),
            start: tokio::time::Instant::now(),
            bytes: 0,
        })
    };
    let ct = if inline {
        mime_for(name)
    } else {
        "application/octet-stream".to_string()
    };
    let disp = if inline { "inline" } else { "attachment" };
    let cd = format!("{}; filename=\"{}\"", disp, name);
    let mut resp = (
        StatusCode::OK,
        [
            (header::ACCEPT_RANGES, "bytes".to_string()),
            (header::CONTENT_DISPOSITION, cd),
            (header::CONTENT_LENGTH, len.to_string()),
            (header::CONTENT_TYPE, ct),
        ],
        body,
    )
        .into_response();
    if partial {
        *resp.status_mut() = StatusCode::PARTIAL_CONTENT;
        let cr = format!("bytes {start}-{end}/{len}");
        if let Ok(v) = HeaderValue::from_str(&cr) {
            resp.headers_mut().insert(header::CONTENT_RANGE, v);
        }
        if let Ok(v) = HeaderValue::from_str(&(end - start + 1).to_string()) {
            resp.headers_mut().insert(header::CONTENT_LENGTH, v);
        }
    }
    resp
}

/// Parse a single HTTP Range header for a resource of `len` bytes.
/// Returns Ok((start, end)) inclusive when satisfiable, Err(()) when the
/// requested start is past the end (416), and None for malformed or
/// multi-range values (caller serves the full body).
fn parse_range(range: &str, len: u64) -> Option<Result<(u64, u64), ()>> {
    let spec = range.trim().strip_prefix("bytes=")?;
    if spec.contains(',') {
        return None; // only single ranges are handled
    }
    let (s, e) = spec.split_once('-')?;
    let (s, e) = (s.trim(), e.trim());
    if s.is_empty() {
        // Suffix range "bytes=-N": the last N bytes.
        let n = e.parse::<u64>().ok()?;
        if n == 0 || len == 0 {
            return None;
        }
        let n = n.min(len);
        return Some(Ok((len - n, len - 1)));
    }
    let start = s.parse::<u64>().ok()?;
    if start >= len {
        return Some(Err(())); // unsatisfiable
    }
    let end = if e.is_empty() {
        len - 1
    } else {
        e.parse::<u64>().ok()?.min(len - 1)
    };
    if end < start {
        return None;
    }
    Some(Ok((start, end)))
}

async fn download(q: Query<IdParam>, headers: HeaderMap, uri: Uri) -> impl IntoResponse {
    serve(q, false, headers, uri).await
}

async fn view(q: Query<IdParam>, headers: HeaderMap, uri: Uri) -> impl IntoResponse {
    serve(q, true, headers, uri).await
}

/// Wraps a download stream and logs server-side throughput when it completes.
struct Measured<S> {
    inner: S,
    label: String,
    start: tokio::time::Instant,
    bytes: u64,
}

impl<S, E> tokio_stream::Stream for Measured<S>
where
    S: tokio_stream::Stream<Item = Result<axum::body::Bytes, E>> + Unpin,
{
    type Item = Result<axum::body::Bytes, E>;
    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        match std::pin::Pin::new(&mut self.inner).poll_next(cx) {
            std::task::Poll::Ready(Some(Ok(b))) => {
                self.bytes += b.len() as u64;
                std::task::Poll::Ready(Some(Ok(b)))
            }
            std::task::Poll::Ready(Some(Err(e))) => std::task::Poll::Ready(Some(Err(e))),
            std::task::Poll::Ready(None) => {
                if self.bytes >= 4 * 1024 * 1024 {
                    let secs = self.start.elapsed().as_secs_f64();
                    let mbps = if secs > 0.0 {
                        self.bytes as f64 / secs / (1024.0 * 1024.0)
                    } else {
                        0.0
                    };
                    logf(&format!(
                        "dl {}: {:.1} MB in {:.2}s = {:.1} MB/s",
                        self.label,
                        self.bytes as f64 / (1024.0 * 1024.0),
                        secs,
                        mbps
                    ));
                }
                std::task::Poll::Ready(None)
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

/// Live transfer progress snapshot: every download the server is currently
/// serving (or recently finished — the monitor prunes finished entries after
/// 15s). Now only hit once on SSE connect (and on a one-shot resync after a
/// lagged push) - steady-state progress rides /events `progress` pushes.
/// Pruning lives in the monitor alone, so the map has exactly one janitor.
async fn dl_status() -> impl IntoResponse {
    let map = dl_lock();
    let items: Vec<_> = map
        .iter()
        .map(|(id, e)| {
            serde_json::json!({ "id": id, "total": e.total, "sent": e.sent, "paused": e.paused })
        })
        .collect();
    Json(items)
}

/// Pause/resume a transfer from either end (POST /dl-pause?id=X&paused=1|0).
/// Flips the shared paused flag, which is pushed to both devices immediately as
/// a `progress` event; the downloading side aborts (pause) or relaunches
/// unfinished chunks (resume). The entry may not exist yet if a pause races the
/// first request - create it so the flag survives until the transfer registers.
#[derive(serde::Deserialize)]
struct PauseParam {
    id: String,
    paused: u8,
}

async fn dl_pause(Query(p): Query<PauseParam>) -> impl IntoResponse {
    let mut map = dl_lock();
    {
        let e = map.entry(p.id.clone()).or_default();
        e.paused = p.paused != 0;
        touch_entry(e);
    }
    // Push immediately (force, not throttled) so the downloading side
    // aborts/relaunches right away instead of waiting for the next progress tick.
    push_progress(&mut map, &p.id, now_ms(), true);
    logf(&format!(
        "dl-pause {} -> paused={} ({} bytes)",
        p.id,
        p.paused != 0,
        map.get(&p.id).map(|e| e.sent).unwrap_or(0)
    ));
    (StatusCode::OK, "ok").into_response()
}

/// Stop a transfer by id. Only the PC can do this — it is the role that hosts a
/// download the phone is pulling (revoke it) and the one receiving a phone
/// upload (refuse it). The id is flagged so the in-flight upload writer /
/// download stream tear down on their next chunk; shared progress is dropped
/// right away. For a pending upload the record and partial file are also removed
/// so the sending phone (which sees its row vanish and aborts) is not left
/// streaming into nothing. A ready file's record is kept — cancelling a download
/// must not delete the file.
async fn cancel(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Query(p): Query<IdParam>,
) -> impl IntoResponse {
    if from_by_peer(peer) != "pc" {
        logw(&format!("cancel: rejected stop request from phone id={}", p.id));
        return (StatusCode::FORBIDDEN, "phone cannot stop transfers").into_response();
    }
    cancel_lock().insert(p.id.clone());
    let was_pending = catalog::find(&p.id).map(|e| e.pending).unwrap_or(false);
    // Drop the shared counter so neither end keeps mirroring a dead transfer.
    dl_lock().remove(&p.id);
    if was_pending {
        // An incoming upload: remove the pending row and best-effort the partial
        // file. If the writer still holds the handle open (Windows), it deletes
        // the file itself when it wakes on the cancel flag.
        if let Some(e) = catalog::remove(&p.id) {
            if let catalog::MsgBody::File {
                source: catalog::Source::Remote { path },
                ..
            } = &e.body
            {
                let _ = std::fs::remove_file(path);
            }
        }
        let _ = notifier().send(PushEvent::List(catalog::all_items()));
    }
    // A cancelled download pushes no terminal progress tick, so broadcast a
    // resync: every client reconciles its mirror corner away instead of leaving
    // it frozen on a pause/cancel affordance.
    let _ = notifier().send(PushEvent::Resync);
    logf(&format!(
        "cancel {}: {} stopped",
        p.id,
        if was_pending { "upload" } else { "download" }
    ));
    (StatusCode::OK, "stopped").into_response()
}

async fn remove(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Query(p): Query<IdParam>,
) -> impl IntoResponse {
    // Deleting is the PC owner's privilege: the phone (non-local visitor) has
    // no permission to delete any entry - the directory is shared, so if the
    // phone deletes one entry, the PC's chat history disappears with it,
    // irreversibly. Enforced on the backend to prevent bypassing the frontend.
    if from_by_peer(peer) != "pc" {
        logw(&format!("remove: rejected delete request from phone id={}", p.id));
        return (StatusCode::FORBIDDEN, "phone cannot delete").into_response();
    }
    // Resolve the entry first so a materialized inbox file can be deleted before
    // the record is dropped.
    let Some(entry) = catalog::find(&p.id) else {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    };

    let label = match &entry.body {
        catalog::MsgBody::File { source, name, .. } => match source {
            // Every Remote file is a tinbox-owned inbox copy (a phone upload, or a
            // PC file copied in on add): deleting the record deletes the copy too.
            catalog::Source::Remote { path } => {
                let ok = match std::fs::remove_file(path) {
                    Ok(()) => true,
                    Err(e) => {
                        logw(&format!("remove: could not delete inbox file {}: {}", path, e));
                        false
                    }
                };
                format!(
                    "{name}: record removed (inbox file {})",
                    if ok { "deleted" } else { "left on disk (delete failed)" }
                )
            }
            // Legacy zero-copy rows point at an original PC path tinbox does not
            // own: remove the record only.
            catalog::Source::Local { path } => format!(
                "{name}: record removed (original kept: {path})"
            ),
        },
        catalog::MsgBody::Text { .. } => "text message deleted".to_string(),
    };

    // Deleting an in-flight upload's pending row directly: flag it so the upload
    // writer tears down on its next chunk and removes its own partial file.
    if entry.pending {
        cancel_lock().insert(entry.id.clone());
    }
    catalog::remove(&entry.id);
    // Drop its progress entry so no further `progress` events advertise a
    // deleted file to whichever side is still downloading it.
    dl_lock().remove(&entry.id);
    logf(&format!("remove: {}", label));
    let _ = notifier().send(PushEvent::List(catalog::all_items()));
    (StatusCode::OK, "deleted").into_response()
}

/// Locate a file in Explorer: on Windows use `explorer /select,`, with a
/// cross-platform fallback that opens the containing directory.
fn reveal_path(path: &str) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // explorer's parser does not understand a "/select,<path>" wrapped
        // entirely in quotes (it falls back to opening a default directory,
        // e.g. Documents). The correct form is /select, followed by a quoted
        // path: explorer.exe /select,"C:\...\file". std's arg() quotes the
        // whole thing when it sees a space, so raw_arg must be used to pass it
        // verbatim.
        let arg = format!("/select,\"{}\"", path);
        match std::process::Command::new("explorer").raw_arg(&arg).spawn() {
            Ok(_) => return,
            Err(e) => logw(&format!("reveal: explorer /select failed: {}", e)),
        }
    }
    let dir = Path::new(path)
        .parent()
        .unwrap_or_else(|| Path::new("."));
    if let Err(e) = open::that(dir) {
        logw(&format!("reveal: could not open containing dir {}: {}", dir.display(), e));
    }
}

/// Open a file with the system default viewer (PC side single-click on a file
/// card). Only File messages; Text has no file to open.
async fn open_file(Query(p): Query<IdParam>) -> impl IntoResponse {
    let Some(entry) = catalog::find(&p.id) else {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    };
    let path = match &entry.body {
        catalog::MsgBody::File { source, .. } => source.path(),
        catalog::MsgBody::Text { .. } => {
            return (StatusCode::BAD_REQUEST, "not a file").into_response();
        }
    };
    if !Path::new(path).exists() {
        return (StatusCode::NOT_FOUND, "file missing").into_response();
    }
    let p = path.to_string();
    // open::that goes through ShellExecute and returns immediately;
    // spawn_blocking keeps the tokio runtime free.
    let opened = tokio::task::spawn_blocking(move || open::that(&p)).await;
    match opened {
        Ok(Ok(_)) => (StatusCode::OK, "opened").into_response(),
        Ok(Err(e)) => {
            loge(&format!("open: could not open {} with the default viewer: {}", path, e));
            (StatusCode::INTERNAL_SERVER_ERROR, "open failed").into_response()
        }
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "task failed").into_response(),
    }
}

/// Reveal a file's location on the PC side by id: Remote rows select the inbox
/// copy (phone upload or PC add), legacy Local rows the original PC file. Only
/// File messages.
async fn reveal(Query(p): Query<IdParam>) -> impl IntoResponse {
    let Some(entry) = catalog::find(&p.id) else {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    };
    let path = match &entry.body {
        catalog::MsgBody::File { source, .. } => source.path(),
        catalog::MsgBody::Text { .. } => {
            return (StatusCode::BAD_REQUEST, "not a file").into_response();
        }
    };
    // Show a message if the original file is gone (moved/deleted) so explorer
    // does not open the wrong location.
    if !Path::new(path).exists() {
        return (StatusCode::NOT_FOUND, "file missing").into_response();
    }
    reveal_path(path);
    (StatusCode::OK, "opened").into_response()
}

/// Open the PC-side inbox directory (the phone frontend hides this button).
async fn open_dir() -> impl IntoResponse {
    match open::that(catalog::inbox_dir()) {
        Ok(_) => (StatusCode::OK, "opened").into_response(),
        Err(e) => {
            logw(&format!("open-dir: could not open inbox folder: {}", e));
            (StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")).into_response()
        }
    }
}

/// RAII guard that decrements LAN_EVENTS_OPEN when its /events stream ends. It
/// rides inside GuardedStream, which axum drops when the client disconnects, so
/// the counter tracks exactly the currently-open LAN streams. Logs the close so
/// a dead page's stream (tab swiped away) is distinguishable in tinbox.log from
/// the other two presence evidence sources still holding the bit.
struct PresenceGuard {
    /// Source of the stream, for the open/close diagnostic lines.
    ip: String,
}
impl Drop for PresenceGuard {
    fn drop(&mut self) {
        let n = LAN_EVENTS_OPEN.fetch_sub(1, Ordering::Relaxed) - 1;
        logf(&format!(
            "events stream closed from {} ({n} open)",
            self.ip
        ));
    }
}

/// A boxed SSE stream carrying an optional PresenceGuard for the whole life of
/// the connection (present for LAN peers, absent for the PC's own loopback
/// page).
type SseItem = Result<Event, std::convert::Infallible>;
struct GuardedStream {
    inner: std::pin::Pin<Box<dyn tokio_stream::Stream<Item = SseItem> + Send>>,
    _guard: Option<PresenceGuard>,
}
impl tokio_stream::Stream for GuardedStream {
    type Item = SseItem;
    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.inner.as_mut().poll_next(cx)
    }
}

/// Server push: typed events over one SSE connection. On connect it replays the
/// current state (list + firewall + device presence) so a fresh page needs no
/// poll, then streams live PushEvents. A periodic keepalive keeps the socket
/// warm so a phone that backgrounds/sleeps is not silently reaped.
async fn events(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
) -> Sse<impl tokio_stream::Stream<Item = Result<Event, std::convert::Infallible>>> {
    // Device presence: opening this stream from a LAN peer is what makes a
    // device "online". Only COUNT it here — the monitor is the single writer
    // that announces the resulting state to everyone, so a connecting device's
    // own `info` replay (built after this increment) shows it as online. The
    // guard decrements when the connection (and thus this handler's stream)
    // ends. Deliberately no broadcast on open: that would double the monitor's
    // transition report, and arrival within one 1s tick is plenty.
    let is_lan = !peer.ip().is_loopback();
    let guard = if is_lan {
        let n = LAN_EVENTS_OPEN.fetch_add(1, Ordering::Relaxed) + 1;
        logf(&format!(
            "events stream open from {} ({n} open)",
            peer.ip()
        ));
        Some(PresenceGuard { ip: peer.ip().to_string() })
    } else {
        None
    };
    let rx = notifier().subscribe();
    // Replay current state first: covers the gap between page load and the
    // first live event, so the PC/phone never has to fetch /list, /info or
    // /fw-status on start.
    let initial = tokio_stream::iter(vec![list_event(), info_event(), fw_event()])
        .map(Ok::<_, std::convert::Infallible>);
    let stream = initial.chain(BroadcastStream::new(rx).map(|msg| {
        Ok::<_, std::convert::Infallible>(match msg {
            Ok(ev) => push_event_to_sse(ev),
            // A slow subscriber fell behind and missed events; ask it to
            // re-fetch /dl-status once so progress bars self-heal.
            Err(_) => Event::default().event("resync").data("1"),
        })
    }));
    // [LIVENESS/keep-alive] Heartbeat every SSE_HEARTBEAT_SECS so an idle
    // stream still moves bytes (NAT/AP idle timeouts cannot reap it) and the
    // client watchdog has a clock (it declares the link dead after ~3x this
    // of total silence — EventSource itself has no read timeout).
    Sse::new(GuardedStream { inner: Box::pin(stream), _guard: guard }).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(SSE_HEARTBEAT_SECS))
            .event(Event::default().data("{}")),
    )
}

fn list_event() -> Event {
    Event::default()
        .retry(Duration::from_secs(1))
        .event("list")
        .json_data(catalog::all_items())
        .unwrap()
}

fn fw_event() -> Event {
    Event::default()
        .retry(Duration::from_secs(1))
        .event("fw")
        .json_data(serde_json::json!({ "needRepair": crate::firewall::need_repair() }))
        .unwrap()
}

fn info_event() -> Event {
    let (ip, port, url) = current_url();
    let online = lan_peer_connected();
    Event::default()
        .retry(Duration::from_secs(1))
        .event("info")
        .json_data(serde_json::json!({
            "mobileConnected": online, "ip": ip, "port": port, "url": url
        }))
        .unwrap()
}

fn push_event_to_sse(ev: PushEvent) -> Event {
    match ev {
        PushEvent::List(items) => Event::default().event("list").json_data(&items).unwrap(),
        PushEvent::Progress { id, total, sent, paused } => Event::default()
            .event("progress")
            .json_data(serde_json::json!({ "id": id, "total": total, "sent": sent, "paused": paused }))
            .unwrap(),
        PushEvent::Fw(need) => Event::default()
            .event("fw")
            .json_data(serde_json::json!({ "needRepair": need }))
            .unwrap(),
        PushEvent::Info { mobile_connected, url, ip, port } => Event::default()
            .event("info")
            .json_data(serde_json::json!({
                "mobileConnected": mobile_connected, "url": url, "ip": ip, "port": port
            }))
            .unwrap(),
        PushEvent::Resync => Event::default().event("resync").data("1"),
    }
}

/// Best LAN IP + bound port + full URL, shared by the /qr code and `info` events.
fn current_url() -> (String, u16, String) {
    let ip = collect_ips()
        .first()
        .cloned()
        .unwrap_or_else(|| "127.0.0.1".to_string());
    let port = BOUND_PORT.get().copied().unwrap_or(PORT);
    let url = format!("http://{}:{}", ip, port);
    (ip, port, url)
}

/// Background monitor: reports the live device-presence bit, the firewall
/// repair flag and stale download entries, pushing /events on every change so
/// the frontend never polls. Runs every 1s; need_repair() already throttles
/// its powershell rule check.
///
/// Presence is a single writer here. The monitor announces both ARRIVAL (a LAN
/// peer holds an open /events stream, or is downloading/requesting without one)
/// and the silent DEPARTURE (a closed stream has no event of its own); events()
/// only maintains the stream count. There is deliberately no debounce counter:
/// `online` is just `lan_peer_connected()` sampled now, and the activity
/// windows inside it (PRESENCE_ACT_SECS) already provide the hysteresis that
/// keeps a phone whose stream briefly reconnects from flipping the presence
/// bit. Presence drives no user-facing light (see the LIVENESS block), so a
/// genuinely absent device may read "gone" within one tick — honesty beats a
/// state machine.
async fn monitor_loop() {
    let mut prev_online: Option<bool> = None;
    let mut prev_repair: Option<bool> = None;
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
        // Report transitions only, so a cold start with no device stays quiet
        // (prev_online starts None and the first false->false match announces
        // nothing) instead of manufacturing a spurious event.
        let online = lan_peer_connected();
        if prev_online != Some(online) {
            let was_online = prev_online.unwrap_or(false);
            prev_online = Some(online);
            if was_online != online {
                let (ip, port, url) = current_url();
                let evidence = presence_evidence();
                if online {
                    logf(&format!("device present: LAN device reachable ({evidence})"));
                    let _ = notifier().send(PushEvent::Info { mobile_connected: true, url, ip, port });
                } else {
                    logf(&format!("device disconnected: no LAN device present ({evidence})"));
                    let _ = notifier().send(PushEvent::Info { mobile_connected: false, url, ip, port });
                }
            }
        }
        // Firewall repair flag transitions.
        let repair = crate::firewall::need_repair();
        if prev_repair != Some(repair) {
            prev_repair = Some(repair);
            let _ = notifier().send(PushEvent::Fw(repair));
        }
        // Prune transfers whose entries went stale: finished ones after 15s, and
        // auto-paused (abandoned) ones nobody resumed within 30s. Broadcast
        // `resync` when anything drops so clients reconcile their mirror corners
        // back to idle (a silent prune would otherwise leave a paused ring stuck).
        let now = now_mono();
        {
            let mut map = dl_lock();
            let before = map.len();
            map.retain(|_, e| {
                let stale = now.saturating_sub(e.last_ts);
                !(e.sent >= e.total && stale > 15)
                    && !(e.paused && e.sent < e.total && stale > 30)
            });
            if map.len() < before {
                let _ = notifier().send(PushEvent::Resync);
            }
        }
        // Auto-pause a download whose bytes have stopped moving: the peer died
        // or its connection went silent, so the sender should show "Paused"
        // instead of a stuck "Transferring…". Uploads are NOT considered here —
        // a stalled upload is caught by its own per-chunk timeout in upload()
        // (which errors and self-cleans) — only served downloads (non-pending
        // files) need the scan; a later resume (/dl-pause paused=0) clears the
        // paused flag.
        let stalled: Vec<String> = dl_lock()
            .iter()
            .filter(|(_, e)| {
                e.total > 0
                    && e.sent < e.total
                    && !e.paused
                    && now.saturating_sub(e.last_ts) >= STALL_AUTO_PAUSE_SECS
            })
            .map(|(id, _)| id.clone())
            .collect();
        for id in stalled {
            let is_upload = catalog::find(&id).map(|e| e.pending).unwrap_or(false);
            if is_upload {
                continue;
            }
            let mut map = dl_lock();
            if let Some(e) = map.get_mut(&id) {
                if e.total > 0
                    && e.sent < e.total
                    && !e.paused
                    && now.saturating_sub(e.last_ts) >= STALL_AUTO_PAUSE_SECS
                {
                    e.paused = true;
                    touch_entry(e);
                    logf(&format!(
                        "auto-paused stalled download {} at {}/{} bytes",
                        id, e.sent, e.total
                    ));
                    push_progress(&mut map, &id, now_ms(), true);
                }
            }
        }
    }
}

/// Return a QR code PNG whose content is http://<best-LAN-IP>:<port>. The IP
/// is picked by the scoring in collect_ips (gateway-in-subnet evidence), which
/// stays correct even with TUN-mode VPNs or virtual adapters active. The page
/// shows it via <img src="/qr">; the phone scans it to open this page.
async fn qr() -> impl IntoResponse {
    let ips = collect_ips();
    let ip = ips.first().cloned().unwrap_or_else(|| "127.0.0.1".to_string());
    let port = BOUND_PORT.get().copied().unwrap_or(PORT);
    let url = format!("http://{}:{}", ip, port);
    let qr = match qrcode::QrCode::new(url.as_bytes()) {
        Ok(q) => q,
        Err(e) => {
            loge(&format!("QR generation failed: {}  url={}", e, url));
            return (StatusCode::INTERNAL_SERVER_ERROR, "qr error").into_response();
        }
    };
    let modules = qr.width();
    // Scale 10 keeps the PNG crisp when the frontend displays it at ~104 CSS px.
    let scale = 10u32;
    let border = 4 * scale;
    let size = modules as u32 * scale + border * 2;
    let mut img = image::GrayImage::new(size, size);
    for y in 0..size {
        for x in 0..size {
            let mx = (x as i64 - border as i64) / scale as i64;
            let my = (y as i64 - border as i64) / scale as i64;
            let dark = mx >= 0
                && my >= 0
                && (mx as usize) < modules
                && (my as usize) < modules
                && qr[(mx as usize, my as usize)] == qrcode::Color::Dark;
            img.put_pixel(x, y, image::Luma([if dark { 0 } else { 255 }]));
        }
    }
    let mut buf = std::io::Cursor::new(Vec::new());
    if img
        .write_to(&mut buf, image::ImageFormat::Png)
        .is_err()
    {
        return (StatusCode::INTERNAL_SERVER_ERROR, "encode error").into_response();
    }
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "image/png")],
        buf.into_inner(),
    )
        .into_response()
}

/// Return the embedded app logo (header brand, connect gate emblem and
/// favicon). Served as SVG, which stays crisp at any size.
async fn logo() -> impl IntoResponse {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "image/svg+xml")],
        LOGO.to_vec(),
    )
        .into_response()
}

/// Enumerate this machine's IPv4 candidates for the QR code.
///
/// Virtual adapters (TUN VPNs, Docker/WSL vswitches) can never be reached by
/// the phone, so they are excluded outright by name/description keyword and are
/// never returned, not even as a fallback. The remaining real adapters are
/// ordered by gateway reachability (alive first), but a probe miss does NOT
/// remove an adapter: an active VPN TUN hijacks the ICMP to the real gateway
/// and produces false "dead"s, and any real IP is still a better QR target
/// than a vswitch address.
fn collect_ips() -> Vec<String> {
    // All private IPv4s with their interface names, deduplicated.
    let mut cands: Vec<(String, Ipv4Addr)> = Vec::new();
    if let Ok(ifaces) = local_ip_address::list_afinet_netifas() {
        for (name, ip) in ifaces {
            if let IpAddr::V4(v4) = ip {
                if is_private(v4) && !cands.iter().any(|(_, v)| *v == v4) {
                    cands.push((name, v4));
                }
            }
        }
    }
    if cands.is_empty() {
        return vec![];
    }

    let facts = adapter_facts();

    // Filter 1: known virtual adapters out. Name matching always applies even
    // when facts are missing; description matching adds the adapter's type.
    let mut real: Vec<(String, Ipv4Addr)> = Vec::new();
    let mut dropped_virtual: Vec<String> = Vec::new();
    for (name, v4) in &cands {
        let desc = facts.get(name).map(|(d, _)| d.as_str()).unwrap_or("");
        if virtual_adapter(name) || virtual_adapter(desc) {
            dropped_virtual.push(format!("{name} {v4}"));
        } else {
            real.push((name.clone(), *v4));
        }
    }

    // Nothing real survived (an all-virtual machine). Still never emit a
    // vswitch address - fall back to the machine's default-route private IP, or
    // nothing at all. A blank/unreachable QR is honest; a vswitch IP is always
    // a lie.
    if real.is_empty() {
        let mut out: Vec<String> = Vec::new();
        if let Ok(IpAddr::V4(v4)) = local_ip_address::local_ip() {
            if is_private(v4) {
                out.push(v4.to_string());
            }
        }
        let mut last = LAST_DECISION.lock().unwrap_or_else(|e| e.into_inner());
        let signature = format!("{}|{}", out.join(","), dropped_virtual.join(","));
        if *last != signature {
            *last = signature;
            logf(&format!(
                "LAN IP selection: no real adapter; using default route {}; virtual [{}]",
                out.first().map(String::as_str).unwrap_or("(none)"),
                dropped_virtual.join(", ")
            ));
        }
        return out;
    }

    // Filter 2: gateway reachability, probed with the candidate's own
    // address as source so the answer is per-interface, not whatever the
    // default route happens to pick. No gateway configured -> cannot probe,
    // kept last. A failed probe only demotes the adapter in the ordering; it
    // never drops it from the list (false negatives are common with a VPN TUN
    // active, and any real IP beats a virtual one).
    let probes: Vec<(Ipv4Addr, Ipv4Addr)> = real
        .iter()
        .filter_map(|(name, v4)| {
            facts
                .get(name)
                .and_then(|(_, gw)| gw.as_deref())
                .and_then(|g| g.parse::<Ipv4Addr>().ok())
                .map(|g| (*v4, g))
        })
        .collect();
    let probed = probe_gateways(&probes);

    let mut alive: Vec<Ipv4Addr> = Vec::new();
    let mut unprobed: Vec<Ipv4Addr> = Vec::new();
    let mut dead: Vec<(Ipv4Addr, String)> = Vec::new();
    for (name, v4) in real {
        let gw = facts
            .get(&name)
            .and_then(|(_, gw)| gw.as_deref())
            .and_then(|g| g.parse::<Ipv4Addr>().ok());
        match gw {
            Some(g) if probed.get(&(v4, g)) == Some(&true) => alive.push(v4),
            Some(g) => dead.push((v4, format!("{v4} (gateway {g} unreachable)"))),
            None => unprobed.push(v4),
        }
    }
    alive.sort_by_key(|v| v.octets());
    unprobed.sort_by_key(|v| v.octets());
    dead.sort_by_key(|(v, _)| v.octets());
    let ips: Vec<String> = alive
        .iter()
        .chain(&unprobed)
        .chain(dead.iter().map(|(v, _)| v))
        .map(ToString::to_string)
        .collect();

    // Log whenever any bucket changes, not just the winner: a new virtual
    // adapter appearing or a candidate flipping to dead is diagnostic noise
    // worth one line, while steady-state checks stay silent.
    let best = ips.first().cloned().unwrap_or_default();
    let signature = format!("{best}|{alive:?}|{unprobed:?}|{dead:?}|{dropped_virtual:?}");
    {
        let mut last = LAST_DECISION.lock().unwrap_or_else(|e| e.into_inner());
        if *last != signature {
            let list = |v: &[Ipv4Addr]| {
                v.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")
            };
            logf(&format!(
                "LAN IP selection: using {best}; alive [{}]; no gateway [{}]; dead [{}]; virtual [{}]",
                list(&alive),
                list(&unprobed),
                dead.iter().map(|(_, r)| r.clone()).collect::<Vec<_>>().join(", "),
                dropped_virtual.join(", "),
            ));
            *last = signature;
        }
    }
    ips
}

/// Private-range addresses only: loopback, link-local (169.254/16) and
/// public addresses can never be reached from the phone's browser.
fn is_private(v4: Ipv4Addr) -> bool {
    match v4.octets() {
        [10, ..] | [192, 168, ..] => true,
        [172, b, ..] => (16..=31).contains(&b),
        _ => false,
    }
}

fn virtual_adapter(s: &str) -> bool {
    const KW: &[&str] = &[
        "tun", "tap", "vpn", "docker", "wsl", "vmware", "virtual", "hyper-v", "vethernet",
        "loopback", "clash", "xray", "sing-box", "singbox", "wireguard", "zerotier", "tailscale",
        "wi-fi direct", "bluetooth",
    ];
    let l = s.to_lowercase();
    KW.iter().any(|k| l.contains(k))
}

/// Probe several (source address, gateway) pairs concurrently; each answer
/// is cached for 60s because collect_ips runs on every `info` event / connect
/// replay and a probe costs up to 1s of ping timeout.
fn probe_gateways(
    probes: &[(Ipv4Addr, Ipv4Addr)],
) -> std::collections::HashMap<(Ipv4Addr, Ipv4Addr), bool> {
    // (last probe unix, (src addr, gateway)) -> reachable, invalidated after 60s
    type ProbeCache = (u64, std::collections::HashMap<(Ipv4Addr, Ipv4Addr), bool>);
    static CACHE: OnceLock<Mutex<ProbeCache>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new((0, Default::default())));
    let mut g = cache.lock().unwrap_or_else(|e| e.into_inner());
    let now = now_mono();
    if now.saturating_sub(g.0) >= 60 {
        g.0 = now;
        g.1.clear();
    }
    let missing: Vec<(Ipv4Addr, Ipv4Addr)> = probes
        .iter()
        .copied()
        .filter(|p| !g.1.contains_key(p))
        .collect();
    if !missing.is_empty() {
        let handles: Vec<_> = missing
            .iter()
            .map(|p| {
                let p = *p;
                std::thread::spawn(move || (p, gateway_reachable(p.0, p.1)))
            })
            .collect();
        for h in handles {
            if let Ok((p, ok)) = h.join() {
                g.1.insert(p, ok);
            }
        }
    }
    probes
        .iter()
        .map(|p| (*p, g.1.get(p).copied().unwrap_or(false)))
        .collect()
}

/// One ICMP echo to the gateway with the interface address pinned as source
/// (`ping -S`), 1s cap per attempt, up to two attempts. A single dropped ICMP
/// (transient WiFi blip, or a VPN TUN capturing the packet) is otherwise a
/// false "dead" that misorders multi-adapter machines. Exit code 0 means at
/// least one reply came back.
/// Each real probe (60s cache miss) logs target, verdict and latency.
#[cfg(windows)]
fn gateway_reachable(src: Ipv4Addr, gw: Ipv4Addr) -> bool {
    use std::os::windows::process::CommandExt;
    use std::process::Command;
    use std::time::Instant;
    let started = Instant::now();
    let mut ok = false;
    for _ in 0..2 {
        let out = Command::new("ping")
            .args(["-n", "1", "-w", "1000", "-S", &src.to_string(), &gw.to_string()])
            .creation_flags(0x0800_0000) // CREATE_NO_WINDOW
            .output();
        if out.map(|o| o.status.success()).unwrap_or(false) {
            ok = true;
            break;
        }
    }
    logf(&format!(
        "gateway probe from {src} to {gw}: {} in {}ms",
        if ok { "alive" } else { "no reply" },
        started.elapsed().as_millis()
    ));
    ok
}

/// Never called: adapter facts are empty off-Windows, so collect_ips returns
/// before probing. Kept only so the crate compiles on other platforms.
#[cfg(not(windows))]
fn gateway_reachable(_src: Ipv4Addr, _gw: Ipv4Addr) -> bool {
    false
}

/// Adapter metadata used for filtering: interface name -> (description,
/// default gateway if any). Gathered by one powershell call, cached 30s —
/// `info` events fire on connect and on phone transitions, so the query must
/// not spawn a process each time.
#[cfg(windows)]
type AdapterFacts = std::collections::HashMap<String, (String, Option<String>)>;

#[cfg(not(windows))]
type AdapterFacts = std::collections::HashMap<String, (String, Option<String>)>;

static ADAPTER_FACTS: OnceLock<Mutex<(u64, AdapterFacts)>> = OnceLock::new();
static LAST_DECISION: Mutex<String> = Mutex::new(String::new());

fn adapter_facts() -> AdapterFacts {
    let cache = ADAPTER_FACTS.get_or_init(|| Mutex::new((0, Default::default())));
    let mut g = cache.lock().unwrap_or_else(|e| e.into_inner());
    let now = now_mono();
    if now.saturating_sub(g.0) < 30 {
        return g.1.clone();
    }
    let facts = gather_adapter_facts();
    if !facts.is_empty() {
        g.0 = now;
        g.1 = facts.clone();
    }
    facts
}

/// One read-only powershell query: for every adapter, its name, description,
/// IPv4 addresses and default gateway, tab-separated per address.
#[cfg(windows)]
fn gather_adapter_facts() -> AdapterFacts {
    let ps = r#"Get-NetAdapter | Where-Object Status -eq 'Up' | ForEach-Object {
  $n = $_.Name; $d = $_.InterfaceDescription; $i = $_.ifIndex
  Get-NetIPAddress -InterfaceIndex $i -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object {
    $g = (Get-NetRoute -InterfaceIndex $i -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Select-Object -First 1).NextHop
    "{0}`t{1}`t{2}`t{3}" -f $n, $d, $_.IPAddress, $g
  }
}"#;
    let mut map = AdapterFacts::new();
    if let Some((true, out)) = crate::firewall::run_ps(ps) {
        for line in out.lines() {
            let parts: Vec<&str> = line.split('\t').collect();
            if parts.len() != 4 {
                continue;
            }
            let gw = parts[3].trim();
            map.insert(
                parts[0].trim().to_string(),
                (
                    parts[1].trim().to_string(),
                    if gw.is_empty() { None } else { Some(gw.to_string()) },
                ),
            );
        }
    }
    map
}

#[cfg(not(windows))]
fn gather_adapter_facts() -> AdapterFacts {
    AdapterFacts::new()
}

