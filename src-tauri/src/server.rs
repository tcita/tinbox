// axum file server + QR code endpoint.
// The Tauri window loads http://localhost:PORT directly; the phone scans the QR
// code in the window to reach the same page.
// Files are no longer piled into shared/: a catalog index + inbox directory,
// with the transfer layer dispatching per source.
use axum::{
    body::Body,
    extract::{connect_info::ConnectInfo, Multipart, Query, Request, State},
    http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode, Uri},
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
    /// Upload progress for one pending row (throttled to ~1/s server-side; the
    /// final `sent >= total` tick fires immediately). Receiver-side only: the
    /// PC is the receiver of pushes and draws its ring from these; per-byte
    /// download progress is still never pushed — the puller's browser owns
    /// that UI. Download ACTIVITY is a coarser, separate event (DlState).
    Progress { id: String, total: u64, sent: u64 },
    /// A download just completed (every requested byte left the socket). The
    /// PC stamps its 'downloaded to phone' delivery marker from this; the
    /// phone ignores it (its browser owns the download UI).
    Delivered { id: String },
    /// Sender-side download activity, aggregated per message id (the union of
    /// its live per-request "msg#n" transfers): true while any pull of the
    /// file is being served, false once none is. The PC pulses its card from
    /// this — the symmetric counterpart of the sending phone's "Uploading…"
    /// pulse — and deliberately paints no cancel affordance: a pull's cancel
    /// belongs to the puller's browser, so this end gets no ✕, no percent and
    /// no tap action. Hard-dead pulls are covered by the monitor's prune,
    /// which broadcasts Resync for the reconcile path.
    DlState { id: String, active: bool },
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
    /// freezes on a stale percent". The complete server trigger list:
    ///   - events(): a subscriber lagged the broadcast channel and dropped
    ///     events (surfaced as BroadcastStream lag),
    ///   - monitor_loop: stale entries were pruned (finished past 15s, or
    ///     silent past 30s),
    ///   - cancel(): a push was refused by the PC — it pushes no terminal
    ///     progress tick, so clients must reconcile their mirrors away.
    /// Clients additionally reconcile on (re)connect and on visibilitychange
    /// (each pass pulls /list and /dl-status once). The phone keeps no
    /// /dl-status poll and no transfer mirror at all (rings are the
    /// receiver's — see the corner block), so the connect/resync passes
    /// cover it.
    Resync,
}

/// Live transfer counters. Two key spaces share the map:
///   - uploads are keyed by their message id (the pending row IS the transfer;
///     the PC — the receiver of the push — draws its ring from these),
///   - downloads are keyed by a unique per-request transfer id ("msg#n"), so
///     two concurrent pulls of the same file are two independent counters and
///     dropping one can never disturb the other. Download entries feed the
///     outcome log, presence, and the sender-side DlState mirror (the PC's
///     "being pulled" card pulse aggregates the incomplete entries of one
///     message id — see msg_has_active_download), and are pruned by the
///     monitor's time windows.
#[derive(Clone, Default)]
struct DlProg {
    total: u64,
    sent: u64,
    /// Monotonic seconds-since-start of the last byte written / registration
    /// (see touch_entry). Compared against now_mono() by the monitor's prune,
    /// and by presence (transfer_active_recently).
    last_ts: u64,
    /// Last time a progress event was pushed for this transfer, to throttle SSE
    /// emissions to ~1/s per transfer (the frontend used to poll /dl-status).
    last_emit_ms: u64,
}

/// Monotonic source of per-request download transfer ids ("msg#n").
static DL_XFER_SEQ: AtomicU64 = AtomicU64::new(0);

static DL_PROGRESS: OnceLock<Mutex<std::collections::HashMap<String, DlProg>>> = OnceLock::new();

fn dl_progress() -> &'static Mutex<std::collections::HashMap<String, DlProg>> {
    DL_PROGRESS.get_or_init(|| Mutex::new(std::collections::HashMap::new()))
}

/// [LIVENESS/death] Mark a transfer as alive. The single writer of
/// DlProg::last_ts: registration, every chunk (either direction) and the
/// upload-silence timeout all go through here. Read by the monitor's prune,
/// and by presence (transfer_active_recently).
fn touch_entry(e: &mut DlProg) {
    e.last_ts = now_mono();
}

/// Ids of uploads the PC (receiver) refused via /cancel. The upload writer
/// polls this on every chunk and tears down when it sees its id, dropping the
/// pending row and the partial file. Only uploads can be refused: pulls are
/// the puller's business — their only cancel is the receiver's own browser UI.
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
        });
    }
}

/// True while any download transfer of `msg_id` (entries keyed "msg#n") is
/// still incomplete — the sender-side card pulse is the UNION of these: it
/// stays lit until every concurrent pull of the file is done or reaped, so
/// cancelling one of two parallel pulls never darkens the card while the
/// other still runs. The caller already holds the dl_progress lock.
fn msg_has_active_download(map: &std::collections::HashMap<String, DlProg>, msg_id: &str) -> bool {
    let prefix = format!("{msg_id}#");
    map.iter()
        .any(|(k, e)| k.starts_with(&prefix) && e.total > 0 && e.sent < e.total)
}

/// Re-evaluate and push the DlState mirror for `msg_id`. Pushed on every
/// transition point (pull registered, one pull completed/cut); a redundant
/// same-state push is one tiny SSE event the frontend applies idempotently.
/// The caller already holds the dl_progress lock.
fn push_dl_state(map: &std::collections::HashMap<String, DlProg>, msg_id: &str) {
    let active = msg_has_active_download(map, msg_id);
    let _ = notifier().send(PushEvent::DlState { id: msg_id.to_string(), active });
}

/// Preferred port; when taken, fall forward within the same range, and as a
/// last resort fall back to a kernel-assigned free port.
const PORT: u16 = 7765;

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

/// Monotonic seconds since start of the most recent request from a **paired**
/// LAN device — same traffic stream as LAST_PHONE_ACT, minus what the pairing
/// gate refused. Presence (the QR gate latch, the device transitions the
/// monitor announces) must mean "a paired device is alive", so an expired or
/// never-paired web page — which gets 403s for everything — cannot lift the
/// PC's gate into "connected" by merely refetching. Transit evidence reaches
/// this stamp only through log_requests and the presence guard after the
/// pairing middleware has let the request through.
static LAST_PAIRED_ACT: AtomicU64 = AtomicU64::new(0);

/// A LAN device is online while it holds an open /events stream or was active
/// recently. Evidence writers (the only three): events()/PresenceGuard ->
/// LAN_EVENTS_OPEN (paired only: /events itself is behind the gate), transfer
/// chunk writers -> DlProg::last_ts (uploads need a paired cookie). Requests
/// arrive via log_requests, which stamps LAST_PAIRED_ACT for every response
/// the pairing middleware did not refuse.

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
///                 writers (the only three): `log_requests` ->
///                 LAST_PAIRED_ACT (paired requests only — the pairing gate
///                 marks its refusals, and unpaired 403 traffic must never
///                 count as "device present", or an expired tab could lift the
///                 PC scan gate), `events`/PresenceGuard -> LAN_EVENTS_OPEN
///                 (itself behind the pairing gate), transfer chunk writers ->
///                 DlProg::last_ts (via touch_entry; uploads need a paired
///                 cookie, so this is paired by construction). The monitor
///                 is the single announcer of transitions.
///                 Consumers are the PC scan gate's first-connect latch, the
///                 firewall's inbound-proof, and the logs — no UI light.
///                 KNOWN LIMITS (deliberate): presence is OPTIMISTIC — a phone
///                 that dies without a FIN keeps its stream "open" (and thus
///                 counts online) until TCP gives up, minutes later; and it is
///                 a GLOBAL aggregate, not per-device, so with several phones
///                 one active device covers the others. Fine because nothing
///                 destructive or user-facing depends on the bit.
///   death         a transfer ends only through its own stream: an upload dies
///                 via the writer's per-chunk silence timeout (or a refusal
///                 flag), a pull dies when hyper drops the response body —
///                 StreamCutGuard reaps its counter and writes the outcome to
///                 the log; a hanging entry is reaped by the monitor's prune.
///   reconcile     PushEvent::Resync — the one catch-up event for "you may
///                 have missed pushes"; its full trigger list lives on that
///                 variant's doc. Clients also reconcile on (re)connect and
///                 on visibilitychange, each pass pulling /list and
///                 /dl-status once; there are no polling timers.
///
/// Ownership follows the receiver: rings and cancel live on the device that
/// receives a transfer (the PC for pushes — its refuse is /cancel; the phone
/// for pulls — the browser's own download UI), and the sender gets only an
/// event log. No cross-device transfer state is mirrored anywhere, so there
/// is nothing to sync.
///
/// Desk-range profile: both devices are in hand and sessions are short, so
/// the numbers below are tight. One floor to respect: the presence window
/// must stay above the EventSource reconnect delay (retry, 1s, set on every
/// replayed event in events()) or a stream blip flaps the presence bit.
const SSE_HEARTBEAT_SECS: u64 = 1;

/// [LIVENESS/death] Seconds an upload body may go silent before the upload
/// handler aborts it: the peer died or its connection went silent (a killed
/// phone, a half-open TCP), and hyper has no body read timeout, so the
/// actively-awaited read needs this wrapper. Without it the pending row would
/// hang forever. Floor: the longest legitimate chunk gap of a healthy LAN
/// push (milliseconds), with margin. The download side needs no mirror of
/// this: a stalled pull's socket write simply stops draining, and the
/// monitor's prune reaps its entry after the idle window.
const UPLOAD_SILENCE_SECS: u64 = 3;

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
        || lan_paired_recently(PRESENCE_ACT_SECS)
        || transfer_active_recently(PRESENCE_ACT_SECS)
}

/// Recent activity from a PAIRED LAN device: identical shape to
/// lan_seen_recently, but reading LAST_PAIRED_ACT. This is the stamp presence
/// and the PC gate latch run on; unpaired 403 traffic must not lift the gate.
fn lan_paired_recently(secs: u64) -> bool {
    let last = LAST_PAIRED_ACT.load(Ordering::Relaxed);
    last != 0 && now_mono().saturating_sub(last) < secs
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
    let req = match LAST_PAIRED_ACT.load(Ordering::Relaxed) {
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
    if is_lan {
        // Two stamps, two consumers, out of the same request stream:
        //   LAST_PHONE_ACT proves packets can arrive — firewall evidence — and
        //   a pairing refusal is still an arrival, so it was already stamped
        //   above.
        //   LAST_PAIRED_ACT proves a PAIRED device is present, and only gets
        //   this request when the pairing gate let it through. Previously ONE
        //   stamp fed presence: an expired tab (403 for everything) visibly
        //   lifted the PC's QR gate into "Paired" by merely refetching — the
        //   report that produced this split.
        if resp.headers().get(UNPAIRED_MARKER).is_none() {
            LAST_PAIRED_ACT.store(now_mono(), Ordering::Relaxed);
        }
    }
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

// ── Pairing token ─────────────────────────────────────────────────────────
// The QR code encodes http://IP:PORT/?t=<token>; a phone's first visit with the
// correct ?t= is handed a cookie and needs no further interaction. The PC's own
// window rides loopback and never needs the token. Token lifetime = process
// lifetime (no persistence): the app runs desk-range sessions of minutes to a
// few hours, so every restart is also a natural "expire all pairings" event,
// and knowing the bare IP:PORT on this LAN is not enough after a restart.
static REQ_TOKEN: OnceLock<String> = OnceLock::new();

/// The per-process pairing token, lazily generated on first use. Desktop-sized
/// secrets are plenty against a LAN attacker who might see but mistype the
/// QR once; 8 characters are also hand-typable for manual phone entry, which
/// is why the alphabet avoids look-alike glyphs.
fn request_token() -> &'static String {
    REQ_TOKEN.get_or_init(|| {
        // No crypto dependency here: RandomState's SipHash keys come from the
        // OS CSPRNG, so folding a process id through two fresh hashers yields
        // two independent words of OS-grade randomness per run.
        use std::hash::{BuildHasher, Hasher};
        const RAND_CHARS: &[u8] = b"abcdefghjkmnpqrstuvwxyz23456789";
        let mut buf = String::with_capacity(8);
        let pid = std::process::id() as u64;
        for salt in [0u8, 1] {
            let mut h = std::collections::hash_map::RandomState::new()
                .build_hasher();
            h.write_u64(pid ^ 0x5a1fe93b2346_0000 | (salt as u64) << 24);
            let mut v = h.finish();
            for _ in 0..4 {
                buf.push(RAND_CHARS[(v % 31) as usize] as char);
                v /= 31;
            }
        }
        buf
    })
}

const COOKIE_NAME: &str = "tb_auth";

/// Deterministic axum query split: token is alnum-only, so a plain byte check
/// needs no percent-decoding.
fn query_has_token(q: Option<&str>, tok: &str) -> bool {
    let Some(q) = q else { return false };
    q.split('&').any(|kv| match kv.split_once('=') {
        Some((k, v)) => k == "t" && v == tok,
        None => false,
    })
}

fn cookie_carries_token(headers: &HeaderMap, tok: &str) -> bool {
    headers.get(header::COOKIE).and_then(|v| v.to_str().ok())
        .map_or(false, |c| {
            c.split(';').any(|p| {
                let p = p.trim();
                match p.split_once('=') {
                    Some((k, v)) => k == COOKIE_NAME && v == tok,
                    None => false,
                }
            })
        })
}

/// What an unpaired, non-loopback visitor sees: a card visually identical to
/// the in-app "Pairing expired" overlay (same glyph, card geometry, type,
/// theme-following palette and the SAME wording — one message for every
/// unpaired arrival: expired session, first-time visitor, stale link; the
/// instruction is the same "rescan", so the wording is one). All CSS and the
/// emoji are inline; the page makes ZERO further requests (every asset it
/// could want is behind the very gate that served it). The PC's loopback
/// window never reaches this branch, so the text below is visitor-only.
const UNPAIRED_PAGE: &str = concat!(
    "<!doctype html><html><head><meta charset=\"utf-8\">",
    "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">",
    "<title>tinbox — pairing expired</title><style>",
    "body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;",
    "box-sizing:border-box;background:#f2f2f7;font-family:system-ui,-apple-system,'Segoe UI',Roboto,sans-serif}",
    "@media (prefers-color-scheme: dark){body{background:#000000}}",
    ".card{max-width:380px;width:100%;box-sizing:border-box;text-align:center;padding:36px 32px 30px;",
    "background:#ffffff;border-radius:28px;border:1px solid rgba(0,0,0,0.04);",
    "box-shadow:0 16px 48px rgba(0,0,0,0.08)}",
    "@media (prefers-color-scheme: dark){.card{background:#1c1c1e;border-color:rgba(255,255,255,0.08)}}",
    ".glyph{font-size:44px;line-height:1;margin-bottom:12px}",
    "h1{font-size:20px;font-weight:700;letter-spacing:-0.4px;margin:0 0 6px;color:#1a1a1e}",
    "@media (prefers-color-scheme: dark){h1{color:#ffffff}}",
    "p{font-size:13px;line-height:1.55;margin:0;color:#86868b}",
    "@media (prefers-color-scheme: dark){p{color:#8e8e93}}",
    "</style></head><body><div class=\"card\">",
    "<div class=\"glyph\">📦</div>",
    "<h1>Pairing expired</h1>",
    "<p>Pairing does not survive a restart. Scan the QR code shown on the tinbox window on the PC to connect.</p>",
    "</div></body></html>"
);

/// Response marker the pairing gate attaches to every refusal: log_requests
/// reads it after the fact to decide which of the two presence stamps this
/// request may update (firewall proof: any inbound; device presence: paired
/// only).
const UNPAIRED_MARKER: HeaderName = HeaderName::from_static("x-tinbox-unpaired");

/// Gate every non-loopback request: no valid pairing cookie, no access. A valid
/// `?t=<token>` query (the QR payload / hand-typed URL) passes once and sets
/// the long-lived cookie, so afterwards the pairing rides the browser jar with
/// no URL decoration — the /view URLs the immutable cache keys on stay stable
/// across restarts.
async fn require_token(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Response {
    if peer.ip().is_loopback() {
        return next.run(req).await;
    }
    let tok = request_token().clone();
    if cookie_carries_token(req.headers(), &tok) {
        return next.run(req).await;
    }
    if query_has_token(req.uri().query(), &tok) {
        let mut resp = next.run(req).await;
        // 30-day browser-side life; server restart is the real expiry.
        let cookie = format!(
            "{COOKIE_NAME}={tok}; Path=/; Max-Age=2592000; HttpOnly"
        );
        if let Ok(v) = HeaderValue::from_str(&cookie) {
            resp.headers_mut().append(header::SET_COOKIE, v);
        }
        return resp;
    }
    let mut resp = (
        StatusCode::FORBIDDEN,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8".to_string()),
            (header::CACHE_CONTROL, "no-cache".to_string()),
        ],
        UNPAIRED_PAGE,
    )
        .into_response();
    resp.headers_mut().insert(UNPAIRED_MARKER, HeaderValue::from_static("1"));
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

/// Find an available port starting from the preferred one: try 7765..7780 one
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

            // One-time cleanup of the retired thumbnail layer: /thumb is gone
            // (both ends pull /view originals), so inbox/.thumbs from older
            // versions is dead weight on disk.
            let _ = std::fs::remove_dir_all(catalog::inbox_dir().join(".thumbs"));

            let app = Router::new()
                .route("/", get(index))
                .route("/list", get(list))
                // /upload is exempt from the body cap: it streams the body
            // straight to disk (see upload()), so RSS stays flat however big
            // the push is, and a full disk fails the write cleanly (row +
            // partial file are dropped on the error path). Every other POST
            // buffers through the Json extractor, which reads the WHOLE body
            // into memory before deserializing — those keep axum's default
            // 2MB limit so an unbounded body cannot spike RSS.
            .route(
                "/upload",
                post(upload).layer(DefaultBodyLimit::disable()),
            )
                .route("/add-local", post(add_local))
                .route("/send-text", post(send_text))
                .route("/log", post(client_log))
                .route("/dl", get(download))
                .route("/dl-status", get(dl_status))
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
                .route("/copy-file", post(copy_file))
                .route("/events", get(events))
                .route("/repair", post(repair))
                .route("/quit", post(quit))
                .route("/untop", post(untop))
                // Inner-to-outer: token gate first, access log outermost (the
                // log must also see refused requests).
                .layer(from_fn(require_token))
                .layer(from_fn(log_requests))
                .with_state(app_handle);

            // Find an available port: preferred 7765, fall forward when taken,
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
            logf(&format!("pairing token: {} (changes every app restart)", request_token()));
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

async fn upload(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Query(q): Query<UpQuery>,
    mut multipart: Multipart,
) -> impl IntoResponse {
    // The sender follows the peer, exactly like /send-text: LAN pushes are
    // "phone", the desktop's own paste-to-send (no real path to /add-local)
    // is "pc" and must not be misattributed to the phone.
    let from = from_by_peer(peer);
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
        catalog::add_remote_pending(from, &id, &stored, &filename, size);
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
            // timeout. Wrap each chunk in a silence timeout so a dead push
            // tears down on its own; the Err arm below then drops the pending
            // row + partial file. This works here because the handler
            // actively awaits the body — unlike the download body stream,
            // which backpressure stops polling, so its cleanup rides the
            // monitor's prune instead.
            match tokio::time::timeout(
                Duration::from_secs(UPLOAD_SILENCE_SECS),
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

/// [LIVENESS/death] Drop-guard on a served download body. When hyper drops the
/// response body before the file was fully sent, the receiving peer is gone
/// (a declined or cancelled browser download, a killed tab, a WiFi drop): axum
/// surfaces a disconnect as the body being dropped, not as an error inside
/// the stream, so a per-chunk error arm never sees it. The guard reaps THIS
/// transfer's counter — its own per-request id, so a sibling pull of the same
/// file is never touched — writes the outcome into the log, and re-evaluates
/// the message's DlState mirror (the card pulse ends only when the LAST pull
/// of the file ends).
struct StreamCutGuard {
    tid: String,
    msg_id: String,
    name: String,
}
impl Drop for StreamCutGuard {
    fn drop(&mut self) {
        let mut map = dl_lock();
        let incomplete = match map.get(&self.tid) {
            Some(e) => e.sent < e.total,
            None => false,
        };
        if incomplete {
            let sent = map.get(&self.tid).map(|e| e.sent).unwrap_or(0);
            let total = map.get(&self.tid).map(|e| e.total).unwrap_or(0);
            map.remove(&self.tid);
            push_dl_state(&map, &self.msg_id);
            drop(map);
            logf(&format!(
                "download closed by receiver {} ({}): {}/{} bytes",
                self.tid, self.name, sent, total
            ));
        }
    }
}

/// One shared-file dispatch: inline=true previews in the browser (/view), false
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

    // Range support: media previews get seekable playback, and a download
    // manager may resume an interrupted pull with bytes=N-. Whether any given
    // client resumes, and when, is that client's business and changes between
    // versions; what HTTP asks of the server is a strong validator so a
    // resume can be proven safe — without one, clients that would otherwise
    // resume restart from zero. Content behind an id is immutable, so the id
    // doubles as the ETag; a stale client's mismatched If-Range falls through
    // to a full 200 body. Malformed / multi-range headers also fall through
    // to a full 200 body.
    let etag = format!("\"{}\"", p.id);
    let if_range_ok = headers
        .get(header::IF_RANGE)
        .and_then(|v| v.to_str().ok())
        .map_or(true, |ir| ir == etag);
    logf(&format!(
        "serve {} q={:?} range={:?} if_range_ok={} ua={:?}",
        p.id,
        uri.query(),
        headers.get(header::RANGE).and_then(|v| v.to_str().ok()),
        if_range_ok,
        headers.get(header::USER_AGENT).and_then(|v| v.to_str().ok()),
    ));
    let range_hdr = if if_range_ok { headers.get(header::RANGE) } else { None };
    let (start, end, partial) = match range_hdr
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
    // per-request transfer counter — a fresh unique id per /dl, so two
    // concurrent pulls of the same file are two independent entries and
    // dropping one can never disturb the other. Per-byte progress is not
    // pushed (the puller's browser owns that UI); what IS pushed is the
    // aggregated DlState mirror, so the sending PC's card pulses while any
    // pull of the file is being served.
    let prog_id = if inline {
        None
    } else {
        Some(format!(
            "{}#{}",
            p.id,
            DL_XFER_SEQ.fetch_add(1, Ordering::Relaxed) + 1
        ))
    };
    if let Some(id) = &prog_id {
        let mut map = dl_lock();
        {
            let e = map.entry(id.clone()).or_default();
            // A Range request seeds the counter with the byte offset it asks
            // from, so the outcome log reads true bytes-served instead of
            // always-from-zero. A full body starts at 0.
            e.sent = start;
            e.total = len;
            touch_entry(e);
        }
        // The new pull makes the file "being served" (a fresh counter is
        // incomplete by construction, so this is always a false->true flip).
        push_dl_state(&map, &p.id);
        logf(&format!("download start {id}: {name} [{start}-{end}]/{len}"));
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
        Some(tid) => {
            let tid = tid.clone();
            let msg_id = p.id.clone();
            let name = name.to_string();
            // Held for the stream's whole life: on drop (peer gone mid-transfer)
            // it reaps this transfer's counter and logs the outcome.
            let cut = StreamCutGuard { tid: tid.clone(), msg_id: msg_id.clone(), name: name.clone() };
            // Stream-local byte count: this pull's authoritative sent figure,
            // independent of the shared counter's lifetime. The monitor reaps a
            // counter after 30s of silence (a paused puller); the stream
            // outlives the reap, so the rebuild below needs the stream's own
            // numbers, not whatever a dead entry remembers.
            let mut sent: u64 = start;
            Box::pin(base.map(move |chunk| {
                // Referencing `cut` keeps it captured, so it is dropped only when
                // the whole stream (and thus this closure) is dropped by hyper.
                let _alive = &cut;
                match &chunk {
                    Ok(b) => {
                        sent += b.len() as u64;
                        let mut map = dl_lock();
                        let e = match map.get_mut(&tid) {
                            Some(e) => e,
                            None => {
                                // Re-seed a pruned counter from the stream's own
                                // count: the pull was paused past the monitor's
                                // 30s window, the entry went away, and without
                                // this rebuild the resumed stream would finish
                                // uncounted — no done log, no Delivered push,
                                // and a wrong active-set for sibling pulls.
                                logf(&format!(
                                    "download counter rebuilt {tid}: {sent}/{} bytes (was pruned while paused)",
                                    len
                                ));
                                let e = map.entry(tid.clone()).or_default();
                                e.total = len;
                                e.sent = sent;
                                touch_entry(e);
                                map.get_mut(&tid).unwrap()
                            }
                        };
                        e.sent = sent;
                        touch_entry(e);
                        if e.sent >= e.total && e.total > 0 {
                            logf(&format!("download done {tid}: {} bytes", e.sent));
                            // The receiver just got the whole file: stamp the
                            // PC's delivery marker. Per-byte progress stays
                            // unpushed — the puller's browser owns that UI.
                            let _ = notifier().send(PushEvent::Delivered { id: msg_id.clone() });
                            // This pull no longer counts as active; if it was
                            // the LAST active pull of the file, end the
                            // sender's card pulse. (A sibling pull still
                            // mid-flight keeps the union lit.)
                            push_dl_state(&map, &msg_id);
                        }
                    }
                    Err(err) => {
                        // The receiver closed/cut this stream (a declined or
                        // cancelled browser download, a killed tab, a WiFi
                        // drop). hyper surfaces a real disconnect as the body
                        // being dropped, not as an error here, so the outcome
                        // logging happens in StreamCutGuard::drop.
                        logw(&format!("download stream cut {tid}: {err}"));
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
    // Inline previews are zero-cache: card previews and fullscreen views both
    // ride /view, refetched on re-render. Nothing here intends to live in a
    // browser cache after the session — a deleted message should leave
    // nothing retrievable on the phone. The id never changes content, but
    // retention is the phone's, not the app's, problem.
    let cc = "no-store";
    let mut resp = (
        StatusCode::OK,
        [
            (header::ACCEPT_RANGES, "bytes".to_string()),
            (header::CONTENT_DISPOSITION, cd),
            (header::CONTENT_LENGTH, len.to_string()),
            (header::CONTENT_TYPE, ct),
            (header::ETAG, etag),
            (header::CACHE_CONTROL, cc.to_string()),
            // Inline responses get navigated to directly now (a tapped card
            // hands the file to the browser). A sandboxed document can never
            // execute scripts on this app's origin: an inbox .svg opened by
            // navigation stays inert, while <img>/<video> subresource loads
            // are unaffected — CSP applies to documents, not images.
            (header::CONTENT_SECURITY_POLICY, "sandbox".to_string()),
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
        .map(|(id, e)| serde_json::json!({ "id": id, "total": e.total, "sent": e.sent }))
        .collect();
    Json(items)
}

/// Refuse an incoming upload (receiver-side cancel). Only the PC can do this —
/// it is the device receiving the push. The id is flagged so the in-flight
/// upload writer tears down on its next chunk; the pending row and the partial
/// file are removed right away, so the sending phone (which sees its row
/// vanish and aborts) is not left streaming into nothing. Downloads have no
/// server-side cancel at all: the puller's own browser UI is that cancel.
async fn cancel(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Query(p): Query<IdParam>,
) -> impl IntoResponse {
    if from_by_peer(peer) != "pc" {
        logw(&format!("cancel: rejected stop request from phone id={}", p.id));
        return (StatusCode::FORBIDDEN, "phone cannot stop transfers").into_response();
    }
    cancel_lock().insert(p.id.clone());
    // Remove the pending row and best-effort the partial file. If the writer
    // still holds the handle open (Windows), it deletes the file itself when
    // it wakes on the cancel flag.
    if let Some(e) = catalog::remove(&p.id) {
        if let catalog::MsgBody::File {
            source: catalog::Source::Remote { path },
            ..
        } = &e.body
        {
            let _ = std::fs::remove_file(path);
        }
    }
    // Drop the shared counter so neither end keeps mirroring a dead transfer,
    // then push the corrected list.
    dl_lock().remove(&p.id);
    let _ = notifier().send(PushEvent::List(catalog::all_items()));
    logf(&format!("cancel {}: upload refused", p.id));
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
/// File messages. PC-only: a phone request must not pop Explorer windows on
/// the PC (same guard posture as /cancel and /add-local).
async fn reveal(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Query(p): Query<IdParam>,
) -> impl IntoResponse {
    if from_by_peer(peer) != "pc" {
        logw("reveal: rejected from phone (would open Explorer on the PC)");
        return (StatusCode::FORBIDDEN, "phone cannot open PC folders").into_response();
    }
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

/// Copy an inbox file to the system clipboard as a file (CF_HDROP), so an
/// Explorer paste — or Ctrl+V into any app's file target — receives the file
/// itself. The web Clipboard API cannot carry files, so this rides the
/// same-process server exactly like /open and /reveal. PC-only: the phone
/// must not reach the desktop clipboard (same guard posture as /reveal).
async fn copy_file(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Query(p): Query<IdParam>,
) -> impl IntoResponse {
    use clipboard_win::{formats, Clipboard, Setter};
    if from_by_peer(peer) != "pc" {
        logw("copy-file: rejected from phone (would write the PC clipboard)");
        return (StatusCode::FORBIDDEN, "phone cannot use the PC clipboard").into_response();
    }
    let Some(entry) = catalog::find(&p.id) else {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    };
    if entry.pending {
        return (StatusCode::NOT_FOUND, "still uploading").into_response();
    }
    let path = match &entry.body {
        catalog::MsgBody::File { source, .. } => source.path().to_string(),
        catalog::MsgBody::Text { .. } => {
            return (StatusCode::BAD_REQUEST, "not a file").into_response();
        }
    };
    if !Path::new(&path).exists() {
        return (StatusCode::NOT_FOUND, "file missing").into_response();
    }
    // The clipboard is a global, contended resource: open with retries, then
    // clear stale formats so the paste target sees only the file list.
    // FileList.write_clipboard builds the DROPFILES header + double-NUL
    // wide path list CF_HDROP requires.
    let _clip = match Clipboard::new_attempts(10) {
        Ok(c) => c,
        Err(e) => {
            logw(&format!("copy-file: clipboard busy: {e:?}"));
            return (StatusCode::INTERNAL_SERVER_ERROR, "clipboard busy").into_response();
        }
    };
    let _ = clipboard_win::empty();
    match formats::FileList.write_clipboard(&[path.as_str()]) {
        Ok(()) => (StatusCode::OK, "copied").into_response(),
        Err(e) => {
            logw(&format!("copy-file: write failed: {e:?}"));
            (StatusCode::INTERNAL_SERVER_ERROR, "copy failed").into_response()
        }
    }
}

/// Open the PC-side inbox directory (the phone frontend hides this button).
/// Frontend "Inbox" click: open the inbox folder on the PC. PC-only for the
/// same reason as /reveal — a phone request must not pop windows on the PC.
async fn open_dir(ConnectInfo(peer): ConnectInfo<SocketAddr>) -> impl IntoResponse {
    if from_by_peer(peer) != "pc" {
        logw("open-dir: rejected from phone (would open Explorer on the PC)");
        return (StatusCode::FORBIDDEN, "phone cannot open PC folders").into_response();
    }
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
        PushEvent::Progress { id, total, sent } => Event::default()
            .event("progress")
            .json_data(serde_json::json!({ "id": id, "total": total, "sent": sent }))
            .unwrap(),
        PushEvent::Delivered { id } => Event::default()
            .event("delivered")
            .json_data(serde_json::json!({ "id": id }))
            .unwrap(),
        PushEvent::DlState { id, active } => Event::default()
            .event("dlstate")
            .json_data(serde_json::json!({ "id": id, "active": active }))
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
/// The URL carries the pairing token, so scanning the QR and copy-pasting the
/// address elsewhere are one and the same gesture.
fn current_url() -> (String, u16, String) {
    let ip = collect_ips()
        .first()
        .cloned()
        .unwrap_or_else(|| "127.0.0.1".to_string());
    let port = BOUND_PORT.get().copied().unwrap_or(PORT);
    let url = format!("http://{}:{}/?t={}", ip, port, request_token());
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
        // Prune transfer counters on pure time windows: finished ones after 15s
        // (a lingering completion would keep reappearing in /dl-status), and
        // in-flight ones after 30s of silence — a dead pull's socket write can
        // hang past any timeout, so its entry dies here rather than through
        // the stream. A pruned-but-alive stream rebuilds its counter on its
        // next chunk (see the chunk loop in serve), so a paused-then-resumed
        // pull goes: pruned here with this log line, rebuilt below with that
        // one. Upload entries whose writer already failed were removed by the
        // writer itself. Broadcast `resync` when anything drops so clients
        // reconcile their upload rings back to idle (a silent prune would
        // otherwise leave a ring stuck).
        let now = now_mono();
        {
            let mut map = dl_lock();
            let before = map.len();
            map.retain(|id, e| {
                let stale = now.saturating_sub(e.last_ts);
                let keep = if e.sent >= e.total { stale <= 15 } else { stale <= 30 };
                if !keep && e.sent < e.total {
                    // Only the incomplete reap gets a line: the finished one is
                    // lifecycle noise. Say "stalled pull" so it reads next to
                    // started/done/cut in the same vocabulary.
                    logw(&format!(
                        "prune stalled pull {id}: {}/{} bytes (30s silent)",
                        e.sent, e.total
                    ));
                }
                keep
            });
            if map.len() < before {
                let _ = notifier().send(PushEvent::Resync);
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
    let url = format!("http://{}:{}/?t={}", ip, port, request_token());
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

