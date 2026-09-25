// User settings, persisted as settings.json under the app data root.
//
// Two knobs: the inbox directory and the window-close behavior. The data root
// itself (%LOCALAPPDATA%\tinbox) stays fixed — making THAT configurable would
// be a chicken-and-egg problem (the settings file lives inside it).
//
// Application timing differs per knob: a new inbox directory takes a restart
// (in-flight uploads and the in-memory catalog hold the old absolute paths),
// while the close behavior is read live on every close click.
//
// Migration honesty: entries store absolute paths, and reconcile() drops
// records whose files are gone — so after a switch + restart, old file rows
// disappear from the timeline (their files stay on disk where they were) while
// text history is untouched. The settings UI states exactly this.
use crate::logger::{logf, logw};
use crate::server::from_by_peer;
use axum::{
    extract::{ConnectInfo, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

/// On-disk shape. Every field optional so a hand-edited or half-written file
/// degrades to defaults instead of bricking the start.
#[derive(serde::Serialize, serde::Deserialize, Default)]
struct SettingsFile {
    inbox_dir: Option<String>,
    /// "tray" | "quit"; absent means the default (tray).
    close_behavior: Option<String>,
}

/// Memoized custom inbox directory (None = default). Loaded once at startup
/// before inbox_dir() is first used; refreshed by the save handler.
static MEMO: OnceLock<Mutex<Option<PathBuf>>> = OnceLock::new();

/// Memoized close behavior (true = minimize to tray). Read live on every
/// window close, so flipping it needs no restart.
static CLOSE_TRAY: OnceLock<Mutex<bool>> = OnceLock::new();

fn memo() -> &'static Mutex<Option<PathBuf>> {
    MEMO.get_or_init(|| Mutex::new(None))
}

fn settings_path() -> PathBuf {
    crate::logger::data_root().join("settings.json")
}

fn close_tray() -> &'static Mutex<bool> {
    CLOSE_TRAY.get_or_init(|| Mutex::new(true))
}

/// Read the settings file, defaulting on any failure. Load() adds the
/// logging; savers stay quiet and just preserve what they don't touch.
fn read_settings_file() -> SettingsFile {
    let raw = match std::fs::read_to_string(settings_path()) {
        Ok(s) => s,
        Err(_) => return SettingsFile::default(),
    };
    serde_json::from_str(&raw).unwrap_or_default()
}

fn persist(file: &SettingsFile) -> Result<(), String> {
    let text = serde_json::to_string_pretty(file).map_err(|e| format!("保存失败: {e}"))?;
    std::fs::write(settings_path(), text).map_err(|e| format!("保存失败: {e}"))
}

/// The inbox location when the user never customized anything.
pub fn default_inbox_dir() -> PathBuf {
    crate::logger::data_root().join("inbox")
}

/// The effective inbox directory: the custom override when one is stored,
/// otherwise the default. Every caller (catalog, transfer, desktop) goes
/// through here so a switch moves ALL of them together.
pub fn effective_inbox_dir() -> PathBuf {
    memo()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
        .unwrap_or_else(default_inbox_dir)
}

/// Hermetic-test override for the inbox dir. See logger::set_test_data_root.
#[cfg(test)]
pub(crate) fn set_test_inbox_dir(dir: Option<PathBuf>) {
    *memo().lock().unwrap_or_else(|e| e.into_inner()) = dir;
}

/// True when the effective directory is the default (for the UI hint).
pub fn is_default() -> bool {
    memo()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .is_none()
}

/// True when closing the window should minimize to the tray (the default);
/// false quits the process outright. Read live on every close click.
pub fn close_to_tray() -> bool {
    *close_tray().lock().unwrap_or_else(|e| e.into_inner())
}

/// Load the stored overrides, if any. Lenient by design: a missing file means
/// "never customized", a corrupt or unusable one logs and falls back to the
/// defaults — settings must never prevent startup.
pub fn load() {
    if !settings_path().exists() {
        return;
    }
    let raw = std::fs::read_to_string(settings_path()).unwrap_or_default();
    let file: SettingsFile = match serde_json::from_str(&raw) {
        Ok(f) => f,
        Err(e) => {
            logw(&format!("settings: unreadable settings.json, using defaults: {e}"));
            return;
        }
    };
    match file.close_behavior.as_deref().map(str::trim) {
        Some("quit") => *close_tray().lock().unwrap_or_else(|e| e.into_inner()) = false,
        Some("tray") | None | Some("") => {}
        Some(other) => {
            logw(&format!("settings: unknown close_behavior '{other}', using default (tray)"));
        }
    }
    let Some(dir) = file.inbox_dir.map(|s| s.trim().to_string()) else {
        return;
    };
    if dir.is_empty() {
        return;
    }
    let path = PathBuf::from(&dir);
    if !path.is_absolute() {
        logw(&format!("settings: stored inbox_dir is not absolute, using default: {dir}"));
        return;
    }
    // The directory may have been deleted or unplugged while the app was
    // away: fall back loudly instead of writing uploads into the void.
    if !path.is_dir() && std::fs::create_dir_all(&path).is_err() {
        logw(&format!("settings: stored inbox_dir unusable, using default: {dir}"));
        return;
    }
    *memo().lock().unwrap_or_else(|e| e.into_inner()) = Some(path.clone());
    logf(&format!("settings: custom inbox_dir loaded: {}", path.display()));
}

/// Normalize + validate a candidate directory and persist it.
///
/// Safety first: the persisted directory becomes a landing zone that
/// reconcile() adopts wholesale (every file becomes an entry, and /rm really
/// deletes files) — so the chosen location is NEVER used directly. The
/// effective inbox is ALWAYS an `inbox` child inside it, meaning picking
/// Desktop (or any lived-in folder, or even a drive root) cannot swallow the
/// user's own files. The child is created here and is always fresh: if
/// `base/inbox` already exists and is not the current effective path, the pick
/// is rejected rather than adopted (tinbox never merges or reuses a
/// pre-existing inbox it did not create). No sentinel marker is needed —
/// ownership is enforced by "create it fresh or refuse", not by inspecting
/// contents.
/// Picking a directory already named `inbox` therefore yields `inbox/inbox`,
/// accepted on purpose rather than risking someone else's folder.
///
/// Creates the directory (with a write probe, so a read-only or bogus
/// location fails HERE with a message instead of failing uploads later).
/// Does NOT move existing files and does NOT touch the running state — the
/// caller restarts.
pub fn save_inbox_dir(raw: &str) -> Result<PathBuf, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("路径为空".to_string());
    }
    let path = PathBuf::from(trimmed);
    if !path.is_absolute() {
        return Err("请使用绝对路径".to_string());
    }
    if path.is_file() {
        return Err("该路径已是一个文件，请选择目录".to_string());
    }
    // Strip trailing separators for stable display + comparison, but never
    // reduce a root (C:\, \\) to nothing.
    let mut normalized = trimmed.to_string();
    while normalized.len() > 3 && (normalized.ends_with(['\\', '/'])) {
        normalized.pop();
    }
    let base = PathBuf::from(&normalized);
    // Always nest `inbox`: never reuse a same-named folder the user happened to
    // pick, so the effective directory is always one we created — its ownership
    // is unambiguous without any marker file.
    let final_path = base.join("inbox");
    // tinbox only ever uses an inbox it created itself: refuse to adopt a
    // pre-existing `inbox` folder, which would merge someone else's files into
    // the timeline (and let /rm delete them). The sole exception is the CURRENT
    // effective path — re-picking it is a no-op and it is by definition ours.
    if final_path.exists() {
        let current = effective_inbox_dir();
        let same = match (
            std::fs::canonicalize(&final_path),
            std::fs::canonicalize(&current),
        ) {
            (Ok(a), Ok(b)) => a == b,
            _ => final_path
                .to_string_lossy()
                .eq_ignore_ascii_case(&current.to_string_lossy()),
        };
        if !same {
            return Err(
                "该位置已有 inbox 文件夹，请另选位置或先移除它".to_string(),
            );
        }
    }
    if let Err(e) = std::fs::create_dir_all(&final_path) {
        return Err(format!("无法创建目录: {e}"));
    }
    // Write probe: create_dir_all succeeding does not prove writability
    // (ACLs, read-only mounts). A probe file that cannot be removed is still
    // proof enough of writability — leave no litter on the remove failure.
    let probe = final_path.join(".tinbox_write_test");
    if let Err(e) = std::fs::write(&probe, b"ok") {
        return Err(format!("目录不可写: {e}"));
    }
    let _ = std::fs::remove_file(&probe);
    let mut file = read_settings_file();
    file.inbox_dir = Some(final_path.to_string_lossy().into_owned());
    persist(&file)?;
    *memo().lock().unwrap_or_else(|e| e.into_inner()) = Some(final_path.clone());
    logf(&format!("settings: inbox_dir set to {} (restart to take effect)", final_path.display()));
    Ok(final_path)
}

/// Persist the window-close behavior ("tray" | "quit"). Takes effect
/// immediately — the close handler reads the memo live, no restart involved.
pub fn save_close_behavior(raw: &str) -> Result<String, String> {
    let v = raw.trim().to_string();
    if v != "tray" && v != "quit" {
        return Err("未知选项".to_string());
    }
    let mut file = read_settings_file();
    file.close_behavior = Some(v.clone());
    persist(&file)?;
    *close_tray().lock().unwrap_or_else(|e| e.into_inner()) = v == "tray";
    logf(&format!("settings: close_behavior set to {v} (effective immediately)"));
    Ok(v)
}

// --- HTTP surface (all PC-only: a guest must not move the owner's inbox) ---

/// Current settings for the settings card.
pub(crate) async fn get_settings(ConnectInfo(peer): ConnectInfo<SocketAddr>) -> impl IntoResponse {
    if from_by_peer(peer) != "owner" {
        return (StatusCode::FORBIDDEN, "guest cannot read settings").into_response();
    }
    Json(serde_json::json!({
        "inbox_dir": effective_inbox_dir().to_string_lossy(),
        "is_default": is_default(),
        "default_dir": default_inbox_dir().to_string_lossy(),
        "data_root": crate::logger::data_root().to_string_lossy(),
        "close_behavior": if close_to_tray() { "tray" } else { "quit" },
    }))
    .into_response()
}

#[derive(serde::Deserialize)]
pub(crate) struct CloseBehaviorPayload {
    behavior: String,
}

#[derive(serde::Deserialize)]
pub(crate) struct InboxDirPayload {
    path: String,
}

/// Persist the window-close behavior. Effective on the very next close click.
pub(crate) async fn set_close_behavior(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(payload): Json<CloseBehaviorPayload>,
) -> impl IntoResponse {
    if from_by_peer(peer) != "owner" {
        return (StatusCode::FORBIDDEN, "guest cannot change settings").into_response();
    }
    match save_close_behavior(&payload.behavior) {
        Ok(v) => Json(serde_json::json!({ "ok": true, "close_behavior": v })).into_response(),
        Err(msg) => (StatusCode::BAD_REQUEST, msg).into_response(),
    }
}

/// Persist a new inbox directory. Answers ok + restart-required: the running
/// process keeps serving the old directory until it exits.
pub(crate) async fn set_inbox_dir(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(payload): Json<InboxDirPayload>,
) -> impl IntoResponse {
    if from_by_peer(peer) != "owner" {
        return (StatusCode::FORBIDDEN, "guest cannot change settings").into_response();
    }
    match save_inbox_dir(&payload.path) {
        Ok(p) => Json(serde_json::json!({
            "ok": true,
            "inbox_dir": p.to_string_lossy(),
            "restart_required": true,
        }))
        .into_response(),
        Err(msg) => {
            logw(&format!("settings: rejected inbox_dir '{}': {msg}", payload.path.trim()));
            (StatusCode::BAD_REQUEST, msg).into_response()
        }
    }
}

/// Open the data directory (log/index/settings) in Explorer. PC-only: a guest
/// request must not pop windows on the PC (same guard as /open-dir).
pub(crate) async fn open_data_dir(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
) -> impl IntoResponse {
    if from_by_peer(peer) != "owner" {
        return (StatusCode::FORBIDDEN, "guest cannot open PC folders").into_response();
    }
    match open::that(crate::logger::data_root()) {
        Ok(_) => (StatusCode::OK, "opened").into_response(),
        Err(e) => {
            logw(&format!("settings: could not open data directory: {e}"));
            (StatusCode::INTERNAL_SERVER_ERROR, "open failed").into_response()
        }
    }
}

/// Open the native directory picker on the PC and return the chosen path
/// (null when cancelled). Server-driven — not the webview's Tauri JS dialog —
/// so a loopback desktop browser gets the same picker as the app window, and
/// guests are refused by the same guard as everything else PC-side.
pub(crate) async fn pick_dir(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(app): State<tauri::AppHandle>,
) -> impl IntoResponse {
    if from_by_peer(peer) != "owner" {
        return (StatusCode::FORBIDDEN, "guest cannot pick directories").into_response();
    }
    // blocking_* must never run on the main thread (deadlock with the event
    // loop); the axum worker is already off it, and spawn_blocking keeps the
    // async runtime free while the modal sits open — same posture as /repair.
    // Start at the BASE (the parent of the active inbox, e.g. ...\foo for
    // ...\foo\inbox), NOT the inbox itself: the effective path is always
    // base/inbox, so opening inside it would make a plain re-confirm nest
    // inbox/inbox. Starting one level up keeps "pick the same spot" a no-op.
    let start = effective_inbox_dir();
    let start = start.parent().map(|p| p.to_path_buf()).unwrap_or(start);
    let picked = tokio::task::spawn_blocking(move || {
        use tauri_plugin_dialog::DialogExt;
        app.dialog()
            .file()
            .set_title("选择收件箱位置（将创建 inbox 文件夹）")
            // Starting from the active base preserves the user's context;
            // without an explicit directory Windows commonly opens Downloads.
            .set_directory(start)
            .blocking_pick_folder()
    })
    .await
    .unwrap_or(None);
    let path = picked
        .as_ref()
        .and_then(|fp| fp.as_path())
        .map(|p| p.to_string_lossy().into_owned());
    // Show the raw &str (not the Path) so non-UTF8 locations log lossily
    // instead of panicking on an unwrap.
    logf(&format!("settings: picker chose: {}", path.as_deref().unwrap_or("<cancelled>")));
    Json(serde_json::json!({ "path": path })).into_response()
}
