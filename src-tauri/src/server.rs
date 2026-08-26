// axum file server + QR code endpoint.
// The Tauri window loads http://localhost:PORT directly; the phone scans the QR
// code in the window to reach the same page.
// Files are no longer piled into shared/: a catalog index + inbox directory,
// with the transfer layer dispatching per source.
use axum::{
    body::Body,
    extract::{connect_info::ConnectInfo, Multipart, Query, Request, State},
    http::{header, StatusCode},
    middleware::{from_fn, Next},
    response::{Html, IntoResponse, Json, Response, sse::{Event, Sse, KeepAlive}},
    routing::{get, post},
    Router,
};
use axum::extract::DefaultBodyLimit;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt as _;
use tokio_util::io::ReaderStream;

use crate::catalog;
use crate::logger::logf;
use tauri::Manager;

/// Preferred port; when taken, fall forward within the same range, and as a
/// last resort fall back to a kernel-assigned free port.
const PORT: u16 = 8765;

/// The port actually bound (written after a successful bind; used by handlers
/// like /qr to build URLs consistent with the window).
static BOUND_PORT: OnceLock<u16> = OnceLock::new();

/// Change broadcast: after any upload/delete/add-reference, a send notifies all
/// clients subscribed to /events to refresh their lists automatically.
/// pub(crate) so Tauri commands (main runtime) can trigger a refresh after
/// writing.
pub(crate) fn notifier() -> &'static broadcast::Sender<()> {
    static TX: OnceLock<broadcast::Sender<()>> = OnceLock::new();
    TX.get_or_init(|| broadcast::channel(16).0)
}

#[derive(serde::Deserialize)]
struct IdParam {
    id: String,
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

/// Timestamp (unix seconds) of the most recent request from a non-local
/// (phone) device, used to tell whether a mobile device is online. The PC's own
/// requests go over loopback and never update it, so the PC never counts itself.
static LAST_PHONE_ACT: AtomicU64 = AtomicU64::new(0);

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Whether a phone is online: a non-local request within the last 8 seconds
/// (the phone polls fw-status every 2s and pulls the list every 4s, which is
/// plenty).
fn mobile_connected() -> bool {
    now_unix().saturating_sub(LAST_PHONE_ACT.load(Ordering::Relaxed)) < 8
}

/// Log every incoming HTTP request and its source IP (key diagnostic: if a
/// phone request never shows up here, the firewall is blocking it).
async fn log_requests(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Response {
    if !peer.ip().is_loopback() {
        LAST_PHONE_ACT.store(now_unix(), Ordering::Relaxed);
    }
    logf(&format!("{} {} <- {}", req.method(), req.uri().path(), peer));
    next.run(req).await
}

/// Find an available port starting from the preferred one: try 8765..8780 one
/// by one; if all are taken, bind port 0 (kernel assigns a free port).
async fn bind_any() -> std::io::Result<(tokio::net::TcpListener, u16)> {
    for port in PORT..PORT + 16 {
        match tokio::net::TcpListener::bind(("0.0.0.0", port)).await {
            Ok(l) => return Ok((l, port)),
            Err(_) => logf(&format!("port {port} is in use, trying the next one")),
        }
    }
    let l = tokio::net::TcpListener::bind(("0.0.0.0", 0)).await?;
    let port = l.local_addr()?.port();
    Ok((l, port))
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
            logf(&format!("tinbox started, log file at tinbox.log next to the exe"));

            // Inbox directory (next to the exe); ensure it exists on first run.
            std::fs::create_dir_all(catalog::inbox_dir()).ok();

            // Load the index; if empty and a legacy shared directory exists,
            // run the one-time migration (transparent to existing users).
            catalog::load();
            if catalog::all_items().is_empty() {
                migrate_legacy_shared();
            }

            let app = Router::new()
                .route("/", get(index))
                .route("/list", get(list))
                .route("/upload", post(upload))
                .route("/add-local", post(add_local))
                .route("/send-text", post(send_text))
                .route("/log", post(client_log))
                .route("/dl", get(download))
                .route("/view", get(view))
                .route("/open", post(open_file))
                .route("/rm", post(remove))
                .route("/qr", get(qr))
                .route("/open-dir", post(open_dir))
                .route("/reveal", post(reveal))
                .route("/events", get(events))
                .route("/info", get(info))
                .route("/fw-status", get(fw_status))
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
                    logf(&format!("could not bind any port: {}", e));
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
                "listening on 0.0.0.0:{}  QR URL http://{}:{}  candidate IPs={:?}",
                actual, ip, actual, ips
            ));
            logf("if the phone cannot scan it: check that Windows Firewall allows tinbox.exe inbound (clicking Cancel on the first prompt blocks it)");
            let _ = tx.send(Some(actual));
            if let Err(e) = axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            {
                logf(&format!("server error: {}", e));
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
                    catalog::add_remote(&id, &stored, &safe);
                    moved += 1;
                }
            }
        }
    }
    if moved > 0 {
        println!("migrated {} files from the old shared directory to inbox", moved);
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

async fn index() -> Html<&'static str> {
    Html(include_str!("index.html"))
}

async fn list() -> impl IntoResponse {
    // all_items is already sorted by ts ascending (timeline order).
    Json(catalog::all_items())
}

async fn upload(mut multipart: Multipart) -> impl IntoResponse {
    while let Ok(Some(field)) = multipart.next_field().await {
        if field.name() == Some("file") {
            let filename = safe_name(field.file_name().unwrap_or("unnamed"));
            if filename.is_empty() {
                return (StatusCode::BAD_REQUEST, "bad filename").into_response();
            }
            // Write to inbox, prefixing the filename with the id to prevent
            // same-name overwrites; the catalog id matches this prefix.
            let id = catalog::new_id();
            let stored = catalog::inbox_dir().join(format!("{id}__{filename}"));
            let data = match field.bytes().await {
                Ok(d) => d,
                Err(e) => {
                    return (StatusCode::BAD_REQUEST, format!("read: {e}")).into_response()
                }
            };
            if let Err(e) = std::fs::write(&stored, &data) {
                logf(&format!("upload write failed {}: {}", filename, e));
                return (StatusCode::INTERNAL_SERVER_ERROR, format!("write: {e}"))
                    .into_response();
            }
            catalog::add_remote(&id, &stored, &filename);
            logf(&format!("upload done: {} ({} bytes) -> inbox", filename, data.len()));
            let _ = notifier().send(());
            return (StatusCode::OK, format!("uploaded: {filename}")).into_response();
        }
    }
    (StatusCode::BAD_REQUEST, "no file field").into_response()
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
    let _ = notifier().send(());
    (StatusCode::OK, "sent").into_response()
}

#[derive(serde::Deserialize)]
struct AddLocalPayload {
    paths: Vec<String>,
}

/// After the PC side's plus button picks real paths via the Tauri dialog, POST
/// them here to register as local references (zero-copy). Not routed through a
/// custom command, avoiding the ACL restrictions on external URLs.
async fn add_local(axum::Json(payload): axum::Json<AddLocalPayload>) -> impl IntoResponse {
    let paths: Vec<_> = payload.paths.into_iter().map(PathBuf::from).collect();
    let n = catalog::add_local(paths);
    if n > 0 {
        logf(&format!("add-local: registered {} local references", n));
        let _ = notifier().send(());
    }
    (StatusCode::OK, format!("added: {n}")).into_response()
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

/// Frontend poll: whether the firewall repair overlay should be shown.
async fn fw_status() -> impl IntoResponse {
    Json(serde_json::json!({ "needRepair": crate::firewall::need_repair() }))
}

/// Basic server info: LAN IP + whether a mobile device is online (the PC badge
/// shows green/gray accordingly).
async fn info() -> impl IntoResponse {
    let ip = collect_ips().first().cloned().unwrap_or_else(|| "127.0.0.1".to_string());
    Json(serde_json::json!({ "ip": ip, "mobileConnected": mobile_connected() }))
}

/// Frontend "Repair" click: launch elevated UAC to delete the Block and add an
/// Allow rule.
async fn repair(State(_app): State<tauri::AppHandle>) -> impl IntoResponse {
    // repair() blocks synchronously waiting for UAC + Block removal (can take
    // 10s+), so run it in spawn_blocking to keep the axum runtime responsive.
    let ok = tokio::task::spawn_blocking(|| crate::firewall::repair())
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

/// Shared file dispatch: inline=true previews in the browser (/view), false
/// forces a download (/dl). Looks up the message by id; only File messages can
/// be dispatched, Text returns 400.
async fn serve(Query(p): Query<IdParam>, inline: bool) -> impl IntoResponse {
    let Some(entry) = catalog::find(&p.id) else {
        logf(&format!("serve: id {} not found", p.id));
        return (StatusCode::NOT_FOUND, "not found").into_response();
    };
    let (path, name) = match &entry.body {
        catalog::MsgBody::File { source, name, .. } => (source.path(), name.as_str()),
        catalog::MsgBody::Text { .. } => {
            return (StatusCode::BAD_REQUEST, "not a file").into_response();
        }
    };
    match tokio::fs::File::open(path).await {
        Ok(file) => {
            // Read the file size to set Content-Length so the frontend can show
            // a download progress bar and speed.
            let len = file.metadata().await.map(|m| m.len()).unwrap_or(0);
            let stream = ReaderStream::new(file);
            let body = Body::from_stream(stream);
            let ct = if inline {
                mime_for(name)
            } else {
                "application/octet-stream".to_string()
            };
            let disp = if inline { "inline" } else { "attachment" };
            let cd = format!("{}; filename=\"{}\"", disp, name);
            (
                StatusCode::OK,
                [
                    (header::CONTENT_DISPOSITION, cd),
                    (header::CONTENT_LENGTH, len.to_string()),
                    (header::CONTENT_TYPE, ct),
                ],
                body,
            )
                .into_response()
        }
        // The original file of a local reference may have been moved/deleted ->
        // friendly message.
        Err(_) => {
            logf(&format!("serve: file not on disk {} ({})", name, path));
            (StatusCode::NOT_FOUND, "file missing").into_response()
        }
    }
}

async fn download(q: Query<IdParam>) -> impl IntoResponse {
    serve(q, false).await
}

async fn view(q: Query<IdParam>) -> impl IntoResponse {
    serve(q, true).await
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
        logf(&format!("remove: rejected delete request from phone id={}", p.id));
        return (StatusCode::FORBIDDEN, "phone cannot delete").into_response();
    }
    match catalog::remove(&p.id) {
        // Principle: tinbox never deletes files on disk - removal only removes
        // the record. Local references leave the original file untouched;
        // remote files stay in inbox (managed by the user via the inbox entry).
        Some(entry) => {
            let label = match &entry.body {
                catalog::MsgBody::File { name, .. } => {
                    format!("{name} record removed (file kept)")
                }
                catalog::MsgBody::Text { .. } => "text message deleted".to_string(),
            };
            logf(&format!("remove: {}", label));
            let _ = notifier().send(());
            (StatusCode::OK, "deleted").into_response()
        }
        None => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
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
            Err(_) => {}
        }
    }
    let dir = Path::new(path)
        .parent()
        .unwrap_or_else(|| Path::new("."));
    let _ = open::that(dir);
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
            logf(&format!("open: could not open {} with the default viewer: {}", path, e));
            (StatusCode::INTERNAL_SERVER_ERROR, "open failed").into_response()
        }
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "task failed").into_response(),
    }
}

/// Reveal a file's location on the PC side by id (local = original directory,
/// remote = inbox). Only File messages.
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
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")).into_response(),
    }
}

/// Server push: notify all connected clients (including across devices) to
/// refresh when the file list changes.
async fn events() -> Sse<impl tokio_stream::Stream<Item = Result<Event, std::convert::Infallible>>> {
    let rx = notifier().subscribe();
    let stream = BroadcastStream::new(rx).map(|_| {
        Ok::<_, std::convert::Infallible>(Event::default().data("change"))
    });
    Sse::new(stream).keep_alive(KeepAlive::default())
}

/// Return a QR code PNG whose content is http://<local-WiFi-IP>:<port>. The
/// page shows it via <img src="/qr">; the phone scans it to open this page.
async fn qr() -> impl IntoResponse {
    let ips = collect_ips();
    let ip = ips.first().cloned().unwrap_or_else(|| "127.0.0.1".to_string());
    let port = BOUND_PORT.get().copied().unwrap_or(PORT);
    let url = format!("http://{}:{}", ip, port);
    let qr = match qrcode::QrCode::new(url.as_bytes()) {
        Ok(q) => q,
        Err(e) => {
            eprintln!("QR generation failed: {}  url={}", e, url);
            return (StatusCode::INTERNAL_SERVER_ERROR, "qr error").into_response();
        }
    };
    let modules = qr.width();
    let scale = 8u32;
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

/// Enumerate all NICs' IPv4 addresses, sorted with WiFi preferred.
fn collect_ips() -> Vec<String> {
    let mut ips: Vec<(u8, String)> = Vec::new();
    if let Ok(ifaces) = local_ip_address::list_afinet_netifas() {
        for (_name, ip) in ifaces {
            if let IpAddr::V4(v4) = ip {
                let octets = v4.octets();
                if octets[0] == 127 || (octets[0] == 169 && octets[1] == 254) {
                    continue;
                }
                let prio = match octets[0] {
                    192 => 0,
                    10 => 1,
                    172 => 2,
                    _ => 3,
                };
                ips.push((prio, v4.to_string()));
            }
        }
    }
    ips.sort();
    ips.dedup_by(|a, b| a.1 == b.1);
    ips.into_iter().map(|(_, ip)| ip).collect()
}
