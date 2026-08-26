// axum 文件服务器 + 二维码端点。
// Tauri 窗口直接加载 http://localhost:PORT,手机扫窗口里的二维码访问同一页面。
// 文件不再统一堆在 shared/:catalog 索引 + inbox 目录,传输层按 source 分派。
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

/// 首选端口;被占用时顺延同段端口,仍不行退回内核分配的空闲端口。
const PORT: u16 = 8765;

/// 实际绑定到的端口(bind 成功后写入;供 /qr 等 handler 拼 URL,与窗口保持一致)。
static BOUND_PORT: OnceLock<u16> = OnceLock::new();

/// 变更广播:任何一端上传/删除/添加引用后 send,所有订阅 /events 的客户端收到后自动刷新列表。
/// pub(crate) 供 Tauri 命令(主 runtime)写入后触发刷新。
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

/// 按请求来源 IP 判定发送方:本机(127.x / ::1)→ "pc",其它 → "phone"。
fn from_by_peer(peer: SocketAddr) -> &'static str {
    match peer.ip() {
        std::net::IpAddr::V4(v4) if v4.is_loopback() => "pc",
        std::net::IpAddr::V6(v6) if v6.is_loopback() => "pc",
        _ => "phone",
    }
}

/// 最近一次来自非本机(手机)请求的时间戳(unix 秒),用于判断"是否有移动设备在线"。
/// PC 自身请求走 loopback,不会更新它,所以 PC 不会把自己算进去。
static LAST_PHONE_ACT: AtomicU64 = AtomicU64::new(0);

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 手机是否在线:8 秒内有过来自非本机的请求(手机每 2s 轮询 fw-status、每 4s 拉列表,窗口足够)。
fn mobile_connected() -> bool {
    now_unix().saturating_sub(LAST_PHONE_ACT.load(Ordering::Relaxed)) < 8
}

/// 记录每个进来的 HTTP 请求及其来源 IP(关键诊断:手机请求若不出现于此,即被防火墙挡住)。
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

/// 从首选端口起找可用端口:8765..8780 逐个尝试,全被占则绑定端口 0(内核分配空闲端口)。
async fn bind_any() -> std::io::Result<(tokio::net::TcpListener, u16)> {
    for port in PORT..PORT + 16 {
        match tokio::net::TcpListener::bind(("0.0.0.0", port)).await {
            Ok(l) => return Ok((l, port)),
            Err(_) => logf(&format!("端口 {port} 被占用,尝试下一个")),
        }
    }
    let l = tokio::net::TcpListener::bind(("0.0.0.0", 0)).await?;
    let port = l.local_addr()?.port();
    Ok((l, port))
}

/// 在独立线程里启动 axum,bind 成功后通过 channel 传回实际端口(供 Tauri setup 等待后拼窗口 URL)。
/// app_handle 放进 Router state,供 /repair、/quit 等 handler 用。
pub fn spawn(app_handle: tauri::AppHandle) -> tokio::sync::oneshot::Receiver<Option<u16>> {
    let (tx, rx) = tokio::sync::oneshot::channel::<Option<u16>>();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            logf(&format!("tinbox 启动,日志文件位于 exe 同级 tinbox.log"));

            // 收件箱目录(exe 所在目录下),首次启动确保存在。
            std::fs::create_dir_all(catalog::inbox_dir()).ok();

            // 加载索引;若为空且存在旧 shared 目录,做一次性迁移(老用户无感)。
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

            // 找可用端口:首选 8765,被占用顺延,范围耗尽让内核挑空闲端口。
            let (listener, actual) = match bind_any().await {
                Ok(v) => v,
                Err(e) => {
                    logf(&format!("无法绑定任何端口: {}", e));
                    let _ = tx.send(None);
                    return;
                }
            };
            let _ = BOUND_PORT.set(actual);
            // 二维码里编码的 IP:取首个(优先 WiFi 段)。手机连不上时对照此 IP 与本机实际网段。
            let ips = collect_ips();
            let ip = ips.first().cloned().unwrap_or_else(|| "127.0.0.1".to_string());
            logf(&format!(
                "监听成功 0.0.0.0:{}  二维码URL http://{}:{}  候选IP={:?}",
                actual, ip, actual, ips
            ));
            logf("若手机扫不到:检查 Windows 防火墙是否放行了 tinbox.exe 入站(首次监听时弹窗若点了取消即被禁)");
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

/// 老版本把文件堆在 shared/;升级后把它们 move 进 inbox 并登记为 remote 条目。
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
                // shared 与 inbox 同盘,rename 是瞬时移动,不拷贝。
                if std::fs::rename(entry.path(), &stored).is_ok() {
                    catalog::add_remote(&id, &stored, &safe);
                    moved += 1;
                }
            }
        }
    }
    if moved > 0 {
        println!("迁移旧 shared 目录 {} 个文件到 inbox", moved);
    }
    // 空目录清掉,避免误以为还在用 shared。
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
    // all_items 已按 ts 升序(时间线顺序)。
    Json(catalog::all_items())
}

async fn upload(mut multipart: Multipart) -> impl IntoResponse {
    while let Ok(Some(field)) = multipart.next_field().await {
        if field.name() == Some("file") {
            let filename = safe_name(field.file_name().unwrap_or("unnamed"));
            if filename.is_empty() {
                return (StatusCode::BAD_REQUEST, "bad filename").into_response();
            }
            // 落盘到 inbox,文件名前缀 id 防同名覆盖;catalog id 与此前缀一致。
            let id = catalog::new_id();
            let stored = catalog::inbox_dir().join(format!("{id}__{filename}"));
            let data = match field.bytes().await {
                Ok(d) => d,
                Err(e) => {
                    return (StatusCode::BAD_REQUEST, format!("read: {e}")).into_response()
                }
            };
            if let Err(e) = std::fs::write(&stored, &data) {
                logf(&format!("upload 写盘失败 {}: {}", filename, e));
                return (StatusCode::INTERNAL_SERVER_ERROR, format!("write: {e}"))
                    .into_response();
            }
            catalog::add_remote(&id, &stored, &filename);
            logf(&format!("upload 完成: {} ({} bytes) -> inbox", filename, data.len()));
            let _ = notifier().send(());
            return (StatusCode::OK, format!("uploaded: {filename}")).into_response();
        }
    }
    (StatusCode::BAD_REQUEST, "no file field").into_response()
}

/// 发送文本消息。发送方按来源 IP 判定(本机=pc,其它=phone)。
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

/// PC 端加号经 Tauri dialog 选到真实路径后,POST 到这里登记为 local 引用(零拷贝)。
/// 不经自定义命令,避开外部 URL 的 ACL 限制。
async fn add_local(axum::Json(payload): axum::Json<AddLocalPayload>) -> impl IntoResponse {
    let paths: Vec<_> = payload.paths.into_iter().map(PathBuf::from).collect();
    let n = catalog::add_local(paths);
    if n > 0 {
        logf(&format!("add-local: 登记 {} 项 local 引用", n));
        let _ = notifier().send(());
    }
    (StatusCode::OK, format!("added: {n}")).into_response()
}

/// 前端报错用:把客户端异常写进服务端日志(如 invoke 失败、dialog 权限被拒等)。
#[derive(serde::Deserialize)]
struct ClientLogPayload {
    msg: String,
}
async fn client_log(axum::Json(payload): axum::Json<ClientLogPayload>) -> impl IntoResponse {
    logf(&format!("client: {}", payload.msg));
    (StatusCode::OK, "logged").into_response()
}

/// 前端轮询:是否需要显示防火墙修复浮层。
async fn fw_status() -> impl IntoResponse {
    Json(serde_json::json!({ "needRepair": crate::firewall::need_repair() }))
}

/// 服务器基本信息:局域网 IP + 是否有移动设备在线(PC 端徽标据此显示 绿/灰)。
async fn info() -> impl IntoResponse {
    let ip = collect_ips().first().cloned().unwrap_or_else(|| "127.0.0.1".to_string());
    Json(serde_json::json!({ "ip": ip, "mobileConnected": mobile_connected() }))
}

/// 前端点"修复":拉起 UAC 删 Block 补 Allow。
async fn repair(State(_app): State<tauri::AppHandle>) -> impl IntoResponse {
    // repair() 同步阻塞等 UAC + 删 Block(可能 10s+),放 spawn_blocking 不卡 axum runtime。
    let ok = tokio::task::spawn_blocking(|| crate::firewall::repair())
        .await
        .unwrap_or(false);
    logf(if ok { "/repair: 修复成功" } else { "/repair: 未修成(取消 UAC 或失败)" });
    (StatusCode::OK, if ok { "ok" } else { "failed" }).into_response()
}

/// 前端点"退出":无法联网则无意义。
async fn quit(State(app): State<tauri::AppHandle>) -> impl IntoResponse {
    crate::firewall::quit(&app);
    (StatusCode::OK, "quitting").into_response()
}

/// 修复成功浮层消失后,取消窗口置顶(恢复正常)。
async fn untop(State(app): State<tauri::AppHandle>) -> impl IntoResponse {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.set_always_on_top(false);
    }
    (StatusCode::OK, "ok").into_response()
}

/// 按扩展名推断 Content-Type,供 /view 在浏览器内直接预览图片/视频/PDF/文本等。
/// 浏览器打不开的类型(office、压缩包等)返回 octet-stream,会自动回退成下载。
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
        // html 内联渲染会执行脚本,有风险;不识别 → 走下载,不直接渲染。
        _ => "application/octet-stream",
    };
    m.to_string()
}

/// 共用文件分发:inline=true 浏览器内预览(/view),false 强制下载(/dl)。
/// 按 id 查消息;仅 File 消息可分发,Text 返回 400。
async fn serve(Query(p): Query<IdParam>, inline: bool) -> impl IntoResponse {
    let Some(entry) = catalog::find(&p.id) else {
        logf(&format!("serve: id {} 未找到", p.id));
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
            // 取文件大小设 Content-Length,前端才能显示下载进度条与速度。
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
        // local 引用的原文件可能已被移走/删除 → 友好提示。
        Err(_) => {
            logf(&format!("serve: 文件不在磁盘 {} ({})", name, path));
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
    // 删除是 PC 主人的权限:手机(非本机访客)无权删任何条目——目录是共享的,
    // 手机删一条,PC 的聊天历史也跟着消失,不可撤销。后端强制校验,防绕过前端。
    if from_by_peer(peer) != "pc" {
        logf(&format!("remove: 拒绝手机请求删除 id={}", p.id));
        return (StatusCode::FORBIDDEN, "phone cannot delete").into_response();
    }
    match catalog::remove(&p.id) {
        // 原则:tinbox 永远不删磁盘文件——删除只移除记录。
        // local 引用不动原文件;remote 文件仍保留在 inbox(由用户经「收件箱」入口自己管理)。
        Some(entry) => {
            let label = match &entry.body {
                catalog::MsgBody::File { name, .. } => {
                    format!("{name} 已移除记录(文件保留)")
                }
                catalog::MsgBody::Text { .. } => "文本消息已删除".to_string(),
            };
            logf(&format!("remove: {}", label));
            let _ = notifier().send(());
            (StatusCode::OK, "deleted").into_response()
        }
        None => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
}

/// 在资源管理器中定位文件:Windows 用 `explorer /select,`,跨平台 fallback 打开所在目录。
fn reveal_path(path: &str) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // explorer 的解析器不认识被整体引号包裹的 "/select,<path>"(会退回打开默认目录,如 Documents)。
        // 正确形式是 /select, 后跟带引号的路径:explorer.exe /select,"C:\...\file"
        // std 的 arg() 见到空格会整个加引号,必须用 raw_arg 逐字传。
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

/// 用系统默认查看器打开文件(PC 端单击文件卡片)。仅 File 消息;Text 无文件可开。
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
    // open::that 走 ShellExecute,瞬时返回;spawn_blocking 避免占 tokio runtime。
    let opened = tokio::task::spawn_blocking(move || open::that(&p)).await;
    match opened {
        Ok(Ok(_)) => (StatusCode::OK, "opened").into_response(),
        Ok(Err(e)) => {
            logf(&format!("open: 无法用默认查看器打开 {}: {}", path, e));
            (StatusCode::INTERNAL_SERVER_ERROR, "open failed").into_response()
        }
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "task failed").into_response(),
    }
}

/// 按 id 在 PC 端打开文件所在位置(local=原目录,remote=inbox)。仅 File 消息。
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
    // 原文件已不在(被移走/删除)时给出提示,避免 explorer 打开错位置。
    if !Path::new(path).exists() {
        return (StatusCode::NOT_FOUND, "file missing").into_response();
    }
    reveal_path(path);
    (StatusCode::OK, "opened").into_response()
}

/// 打开 PC 端的 inbox 目录(手机端前端会隐藏此按钮)。
async fn open_dir() -> impl IntoResponse {
    match open::that(catalog::inbox_dir()) {
        Ok(_) => (StatusCode::OK, "opened").into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")).into_response(),
    }
}

/// 服务器推送:文件列表变更时通知所有已连接客户端(含跨设备)刷新。
async fn events() -> Sse<impl tokio_stream::Stream<Item = Result<Event, std::convert::Infallible>>> {
    let rx = notifier().subscribe();
    let stream = BroadcastStream::new(rx).map(|_| {
        Ok::<_, std::convert::Infallible>(Event::default().data("change"))
    });
    Sse::new(stream).keep_alive(KeepAlive::default())
}

/// 返回二维码 PNG,内容为 http://<本机WiFi IP>:<port>。
/// 页面里 <img src="/qr"> 直接显示,手机扫码即打开本页。
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

/// 枚举所有网卡的 IPv4,按 WiFi 优先排序
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
