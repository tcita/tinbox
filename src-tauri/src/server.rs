// axum LAN server + the transfer page it serves. This file is the shell:
// bootstrap, router, access log, SSE push channel and the simple JSON
// handlers. The specialized halves live in their own modules:
//   pairing  - the QR token gate and the unpaired page
//   transfer - upload, ranged file dispatch, counters, cancel/delete
//   presence - liveness counters + the one-second monitor
//   desktop  - PC-only OS integrations (open/reveal/clipboard/inbox)
//   netinfo  - LAN IP selection and the QR code

use crate::catalog;
use crate::desktop::{copy_file, open_dir, open_file, reveal};
use crate::logger::{loge, logf, logw};
use crate::netinfo::{collect_ips, note_foreign_subnet, qr};
use crate::pairing::{request_token, require_token, UNPAIRED_MARKER};
use crate::presence::{
    lan_peer_connected, monitor_loop, now_mono, LAST_PAIRED_ACT, LAN_EVENTS_OPEN,
    SSE_HEARTBEAT_SECS,
};
use crate::transfer::{cancel, dl_status, download, remove, upload, view};
use axum::{
    extract::{connect_info::ConnectInfo, DefaultBodyLimit, Request, State},
    http::{header, StatusCode},
    middleware::{from_fn, Next},
    response::{Html, IntoResponse, Json, Response, sse::{Event, Sse, KeepAlive}},
    routing::{get, post},
    Router,
};

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;
use tokio::sync::broadcast;
use tokio_stream::{wrappers::BroadcastStream, StreamExt as _};
use tauri::Manager;
// axum file server + QR code endpoint. The Tauri window loads
// http://localhost:PORT directly; the phone scans the QR code in the window
// to open the same transfer page.

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
    Info { mobile_connected: bool, url: String },
    /// [LIVENESS/reconcile] The one catch-up event: "you may have missed
    /// pushes — re-fetch /dl-status and reconcile your mirror, so no corner
    /// freezes on a stale percent". The complete server trigger list:
    ///   - events(): a subscriber lagged the broadcast channel and dropped
    ///     events (surfaced as BroadcastStream lag),
    ///   - monitor_loop: stale entries were pruned (finished past 15s, or
    ///     silent past 5s),
    ///   - cancel(): a push was refused by the PC — it pushes no terminal
    ///     progress tick, so clients must reconcile their mirrors away.
    /// Clients additionally reconcile on (re)connect and on visibilitychange
    /// (each pass pulls /list and /dl-status once). The phone keeps no
    /// /dl-status poll and no transfer mirror at all (rings are the
    /// receiver's — see the corner block), so the connect/resync passes
    /// cover it.
    Resync,
}

/// Preferred port; when taken, fall forward within the same range (7765..),
/// and as a last resort fall back to a kernel-assigned free port.
pub(crate) const PORT: u16 = 7765;

/// The port actually bound (written after a successful bind; used by handlers
/// like /qr to build URLs consistent with the window).
pub(crate) static BOUND_PORT: OnceLock<u16> = OnceLock::new();

/// Push channel: after any state change, a send notifies all clients subscribed
/// to /events with the new state (list, download progress, firewall, phone
/// presence). pub(crate) so firewall.rs can push the repair flag.
pub(crate) fn notifier() -> &'static broadcast::Sender<PushEvent> {
    static TX: OnceLock<broadcast::Sender<PushEvent>> = OnceLock::new();
    TX.get_or_init(|| broadcast::channel(64).0)
}

#[derive(serde::Deserialize)]
pub(crate) struct IdParam {
    pub id: String,
}

#[derive(serde::Deserialize)]
struct TextPayload {
    text: String,
}

/// Determine the sender from the requesting peer IP: loopback (127.x / ::1) ->
/// "pc", anything else -> "phone".
pub(crate) fn from_by_peer(peer: SocketAddr) -> &'static str {
    match peer.ip() {
        std::net::IpAddr::V4(v4) if v4.is_loopback() => "pc",
        std::net::IpAddr::V6(v6) if v6.is_loopback() => "pc",
        _ => "phone",
    }
}

async fn log_requests(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Response {
    let is_lan = !peer.ip().is_loopback();
    if is_lan {
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
        // Stamped only when the pairing gate let the request through (a
        // refusal carries the marker and never reaches here). Presence and
        // the PC gate latch must mean "a PAIRED device is alive": previously
        // ONE stamp fed presence, and an expired tab (403 for everything)
        // visibly lifted the PC's QR gate into "Paired" by merely refetching
        // — the report that produced the paired-only stamp.
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

/// Endpoints hit once per SSE connect (or on a rare one-shot resync), whose
/// successful responses are not worth a log line. /info and /fw-status are gone
/// entirely: their state now arrives over the /events push channel.
/// /log, /events and the static brand assets are also quiet: they fire on
/// every reconnect/page load and would otherwise bury meaningful events.
fn is_quiet_poll(path: &str) -> bool {
    matches!(
        path,
        "/dl-status"
            | "/list"
            | "/log"
            | "/events"
            | "/logo"
            | "/favicon.ico"
            | "/apple-touch-icon.png"
            | "/apple-touch-icon-precomposed.png"
    )
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

            // Reconcile the index with the inbox directory (adopt orphans,
            // drop dangling records) — after purge_pending, so interrupted
            // upload leftovers are not mistaken for orphans.
            catalog::reconcile();

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

pub(crate) fn safe_name(s: &str) -> String {
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
        match crate::transfer::copy_into_inbox(&canon).await {
            Ok((_id, dest, _safe)) => {
                added += 1;
                // copy_into_inbox registered the pending row, graduated it
                // (sentinel rename + mark_remote_ready) and already pushed its
                // registration List; this push repaints the row as ready.
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

/// For frontend error reporting: write client-side exceptions into the server
/// log (e.g. invoke failures, dialog permission denials, etc.).
#[derive(serde::Deserialize)]
struct ClientLogPayload {
    msg: String,
}
async fn client_log(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    axum::Json(payload): axum::Json<ClientLogPayload>,
) -> impl IntoResponse {
    // Sanitize: single line + bounded length, so a client cannot inject fake
    // log lines via embedded newlines or bloat the file with a 2MB body.
    let mut msg = payload.msg.replace(['\r', '\n'], " ");
    if msg.chars().count() > 1000 {
        msg = msg.chars().take(1000).collect();
    }
    logf(&format!("client {}: {}", peer.ip(), msg));
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
    let url = current_url();
    let online = lan_peer_connected();
    Event::default()
        .retry(Duration::from_secs(1))
        .event("info")
        .json_data(serde_json::json!({
            "mobileConnected": online, "url": url
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
        PushEvent::DlState { id, active } => Event::default()
            .event("dlstate")
            .json_data(serde_json::json!({ "id": id, "active": active }))
            .unwrap(),
        PushEvent::Fw(need) => Event::default()
            .event("fw")
            .json_data(serde_json::json!({ "needRepair": need }))
            .unwrap(),
        PushEvent::Info { mobile_connected, url } => Event::default()
            .event("info")
            .json_data(serde_json::json!({
                "mobileConnected": mobile_connected, "url": url
            }))
            .unwrap(),
        PushEvent::Resync => Event::default().event("resync").data("1"),
    }
}

/// The full pairing URL (best LAN IP + bound port + token): shown on the PC
/// (header, gate, lightbox) and pushed in `info` events. The URL carries the
/// pairing token, so scanning the QR and copy-pasting the address elsewhere
/// are one and the same gesture. This is the ONE place the URL is assembled —
/// netinfo's /qr route reuses it so the QR and the displayed address can never
/// drift apart.
pub(crate) fn current_url() -> String {
    let ip = collect_ips()
        .first()
        .cloned()
        .unwrap_or_else(|| "127.0.0.1".to_string());
    let port = BOUND_PORT.get().copied().unwrap_or(PORT);
    format!("http://{}:{}/?t={}", ip, port, request_token())
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
