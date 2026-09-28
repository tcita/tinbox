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
// Inbox switches do not move data. On the next startup, reconcile() releases
// tinbox-owned file records outside the active inbox without deleting their
// bytes; those old files stop appearing in the timeline and are no longer
// managed by tinbox. Text history and legacy Local references are untouched.
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

const MANAGED_MARKER: &str = ".tinbox-managed";
const MANAGED_MARKER_CONTENT: &[u8] = b"tinbox managed inbox v1\n";

/// On-disk shape. Every field optional so a hand-edited or half-written file
/// degrades to defaults instead of bricking the start.
#[derive(serde::Serialize, serde::Deserialize, Default)]
struct SettingsFile {
    inbox_dir: Option<String>,
    /// "tray" | "quit"; absent means the default (tray).
    close_behavior: Option<String>,
}

/// Active process inbox directory (None = default). Loaded once at startup;
/// changing the configured directory does not mutate it before restart.
static MEMO: OnceLock<Mutex<Option<PathBuf>>> = OnceLock::new();

/// Memoized close behavior (true = minimize to tray). Read live on every
/// window close, so flipping it needs no restart.
static CLOSE_TRAY: OnceLock<Mutex<bool>> = OnceLock::new();

/// Set for this process when startup rejected a custom inbox and fell back.
/// The settings UI uses it to explain why the displayed location is default.
static INBOX_FALLBACK: OnceLock<Mutex<Option<String>>> = OnceLock::new();

fn memo() -> &'static Mutex<Option<PathBuf>> {
    MEMO.get_or_init(|| Mutex::new(None))
}

fn settings_path() -> PathBuf {
    crate::logger::data_root().join("settings.json")
}

fn close_tray() -> &'static Mutex<bool> {
    CLOSE_TRAY.get_or_init(|| Mutex::new(true))
}

fn inbox_fallback() -> &'static Mutex<Option<String>> {
    INBOX_FALLBACK.get_or_init(|| Mutex::new(None))
}

#[cfg(test)]
pub(crate) fn clear_test_fallback() {
    *inbox_fallback().lock().unwrap_or_else(|e| e.into_inner()) = None;
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

/// The active inbox directory for this process. Every caller (catalog,
/// transfer, desktop) goes through here; it changes only at process startup.
pub fn effective_inbox_dir() -> PathBuf {
    memo()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
        .unwrap_or_else(default_inbox_dir)
}

/// The directory configured on disk, which may differ from the active
/// process directory while a saved change is waiting for restart.
fn configured_inbox_dir() -> PathBuf {
    read_settings_file()
        .inbox_dir
        .map(|s| PathBuf::from(s.trim()))
        .filter(|p| p.is_absolute())
        .unwrap_or_else(default_inbox_dir)
}

fn same_location(a: &std::path::Path, b: &std::path::Path) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => a
            .to_string_lossy()
            .eq_ignore_ascii_case(&b.to_string_lossy()),
    }
}

fn managed_marker(dir: &std::path::Path) -> PathBuf {
    dir.join(MANAGED_MARKER)
}

fn has_managed_marker(dir: &std::path::Path) -> bool {
    std::fs::read(managed_marker(dir))
        .map(|bytes| bytes == MANAGED_MARKER_CONTENT)
        .unwrap_or(false)
}

fn hide_managed_marker(dir: &std::path::Path) {
    if let Err(e) = set_hidden_attribute(&managed_marker(dir)) {
        logw(&format!(
            "settings: could not hide ownership marker {}: {e}",
            managed_marker(dir).display()
        ));
    }
}

#[cfg(windows)]
fn set_hidden_attribute(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::Storage::FileSystem::{
        GetFileAttributesW, SetFileAttributesW, FILE_ATTRIBUTE_HIDDEN, FILE_FLAGS_AND_ATTRIBUTES,
        INVALID_FILE_ATTRIBUTES,
    };

    let wide: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
    let path_wide = windows::core::PCWSTR(wide.as_ptr());
    let attributes = unsafe { GetFileAttributesW(path_wide) };
    if attributes == INVALID_FILE_ATTRIBUTES {
        return Err(std::io::Error::last_os_error());
    }
    unsafe {
        SetFileAttributesW(
            path_wide,
            FILE_FLAGS_AND_ATTRIBUTES(attributes | FILE_ATTRIBUTE_HIDDEN.0),
        )
    }
    .map_err(|e| std::io::Error::other(e.to_string()))
}

#[cfg(not(windows))]
fn set_hidden_attribute(_path: &std::path::Path) -> std::io::Result<()> {
    // The leading dot hides the marker in Unix-style file managers.
    Ok(())
}

/// Atomically create the ownership marker. `true` means this call created it;
/// `false` means a valid marker was already present.
fn create_managed_marker(dir: &std::path::Path) -> Result<bool, String> {
    use std::fs::OpenOptions;
    use std::io::Write;
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(managed_marker(dir))
    {
        Ok(mut f) => {
            if let Err(e) = f.write_all(MANAGED_MARKER_CONTENT) {
                let _ = std::fs::remove_file(managed_marker(dir));
                return Err(format!("无法写入目录标记: {e}"));
            }
            drop(f);
            hide_managed_marker(dir);
            Ok(true)
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            if has_managed_marker(dir) {
                hide_managed_marker(dir);
                Ok(false)
            } else {
                Err("目录中存在无效的 tinbox 标记文件".to_string())
            }
        }
        Err(e) => Err(format!("无法创建目录标记: {e}")),
    }
}

fn write_probe(dir: &std::path::Path) -> Result<(), String> {
    use std::io::Write;
    use std::time::SystemTime;
    let stamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let probe = dir.join(format!(
        ".tinbox_write_test_{}_{}",
        std::process::id(),
        stamp
    ));
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)
        .map_err(|e| format!("目录不可写: {e}"))?;
    if let Err(e) = f.write_all(b"ok") {
        drop(f);
        let _ = std::fs::remove_file(&probe);
        return Err(format!("目录不可写: {e}"));
    }
    drop(f);
    std::fs::remove_file(probe).map_err(|e| format!("无法清理写入测试文件: {e}"))
}

fn fallback_to_default(file: &mut SettingsFile, path: &str, reason: &str) {
    *memo().lock().unwrap_or_else(|e| e.into_inner()) = None;
    file.inbox_dir = None;
    if let Err(e) = persist(file) {
        logw(&format!(
            "settings: could not persist inbox fallback to default: {e}"
        ));
    }
    *inbox_fallback().lock().unwrap_or_else(|e| e.into_inner()) = Some(reason.to_string());
    logw(&format!(
        "settings: inbox_dir fallback to default; custom_path={path}; reason={reason}; original files were left untouched"
    ));
}

/// True when the directory holds ordinary top-level files that reconcile()
/// adopts and bulk-clear manages. Dotfiles and subdirectories are deliberately
/// ignored by both, so they don't make a directory unsafe to use.
fn dir_holds_managed_files(dir: &std::path::Path) -> bool {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return false;
    };
    rd.flatten().any(|e| {
        let name = e.file_name().to_string_lossy().to_string();
        !name.starts_with('.') && e.metadata().map(|m| m.is_file()).unwrap_or(false)
    })
}

fn create_numbered_inbox(base: &std::path::Path) -> Result<PathBuf, String> {
    for n in 1..=1000u32 {
        let name = if n == 1 {
            "inbox".to_string()
        } else {
            format!("inbox ({n})")
        };
        let candidate = base.join(name);
        // create_dir is atomic: if another process/user creates this name
        // after our check, never adopt their directory by accident.
        match std::fs::create_dir(&candidate) {
            Ok(()) => return Ok(candidate),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(format!("无法创建收件箱子目录: {e}")),
        }
    }
    Err("该位置子目录过多，请另选位置".to_string())
}

/// Hermetic-test override for the inbox dir. See logger::set_test_data_root.
#[cfg(test)]
pub(crate) fn set_test_inbox_dir(dir: Option<PathBuf>) {
    *memo().lock().unwrap_or_else(|e| e.into_inner()) = dir;
}

/// True when the configured directory is the default.
pub fn is_default() -> bool {
    inbox_fallback()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .is_some()
        || same_location(&configured_inbox_dir(), &default_inbox_dir())
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
    *inbox_fallback().lock().unwrap_or_else(|e| e.into_inner()) = None;
    if !settings_path().exists() {
        return;
    }
    let raw = std::fs::read_to_string(settings_path()).unwrap_or_default();
    let mut file: SettingsFile = match serde_json::from_str(&raw) {
        Ok(f) => f,
        Err(e) => {
            logw(&format!(
                "settings: unreadable settings.json, using defaults: {e}"
            ));
            return;
        }
    };
    match file.close_behavior.as_deref().map(str::trim) {
        Some("quit") => *close_tray().lock().unwrap_or_else(|e| e.into_inner()) = false,
        Some("tray") | None | Some("") => {}
        Some(other) => {
            logw(&format!(
                "settings: unknown close_behavior '{other}', using default (tray)"
            ));
        }
    }
    let Some(dir) = file
        .inbox_dir
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
    else {
        return;
    };
    let path = PathBuf::from(&dir);
    if !path.is_absolute() {
        fallback_to_default(&mut file, &dir, "stored path is not absolute");
        return;
    }
    // The built-in app-data inbox is trusted by location and needs no marker.
    if same_location(&path, &default_inbox_dir()) {
        *memo().lock().unwrap_or_else(|e| e.into_inner()) = None;
        return;
    }
    if !path.is_dir() {
        fallback_to_default(
            &mut file,
            &dir,
            "custom directory is missing or inaccessible",
        );
        return;
    }
    if !has_managed_marker(&path) {
        fallback_to_default(
            &mut file,
            &dir,
            "ownership marker is missing or invalid; treated as released",
        );
        return;
    }
    // Also hide markers created by an older version that only used the dot
    // prefix (which Windows Explorer does not treat as a hidden attribute).
    hide_managed_marker(&path);
    if let Err(reason) = write_probe(&path) {
        fallback_to_default(&mut file, &dir, &reason);
        return;
    }
    *memo().lock().unwrap_or_else(|e| e.into_inner()) = Some(path.clone());
    *inbox_fallback().lock().unwrap_or_else(|e| e.into_inner()) = None;
    logf(&format!(
        "settings: custom inbox_dir loaded: {}",
        path.display()
    ));
}

/// Normalize + validate a candidate directory and persist it.
///
/// Safety first: the persisted directory becomes a landing zone that
/// reconcile() adopts wholesale (every file becomes an entry, and /rm really
/// deletes files) — so a directory is only ever used directly when it holds
/// nothing adoptable (an empty or not-yet-existing directory, any name), or
/// has a valid tinbox ownership marker. Anything else gets a tinbox-created
/// empty child instead: `inbox`, then Explorer-style `inbox (2)`, `inbox (3)`,
/// … — never a merge or rejection. Removing the marker revokes ownership; on
/// the next startup tinbox falls back to default and leaves the folder intact.
///
/// Creates the directory (with a write probe, so a read-only or bogus
/// location fails HERE with a message instead of failing uploads later).
/// Does NOT move existing files or change the active process directory — the
/// caller restarts to apply it.
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
    // The built-in inbox is trusted by its app-data location. A custom inbox
    // is trusted only with its marker. Any other empty directory is safe to
    // adopt; a non-empty unmarked one gets a tinbox-created child.
    let is_default = same_location(&base, &default_inbox_dir());
    let marker_exists = managed_marker(&base).exists();
    let final_path = if is_default
        || has_managed_marker(&base)
        || (!marker_exists && !dir_holds_managed_files(&base))
    {
        base
    } else {
        create_numbered_inbox(&base)?
    };
    if let Err(e) = std::fs::create_dir_all(&final_path) {
        return Err(format!("无法创建目录: {e}"));
    }
    write_probe(&final_path)?;
    let is_default = same_location(&final_path, &default_inbox_dir());
    let marker_created = if is_default {
        false
    } else {
        create_managed_marker(&final_path)?
    };
    let mut file = read_settings_file();
    file.inbox_dir = if is_default {
        None
    } else {
        Some(final_path.to_string_lossy().into_owned())
    };
    if let Err(e) = persist(&file) {
        if marker_created {
            let _ = std::fs::remove_file(managed_marker(&final_path));
        }
        return Err(e);
    }
    *inbox_fallback().lock().unwrap_or_else(|e| e.into_inner()) = None;
    logf(&format!(
        "settings: inbox_dir set to {} (restart to take effect)",
        final_path.display()
    ));
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
    logf(&format!(
        "settings: close_behavior set to {v} (effective immediately)"
    ));
    Ok(v)
}

// --- HTTP surface (all PC-only: a guest must not move the owner's inbox) ---

/// Current settings for the settings card.
pub(crate) async fn get_settings(ConnectInfo(peer): ConnectInfo<SocketAddr>) -> impl IntoResponse {
    if from_by_peer(peer) != "owner" {
        return (StatusCode::FORBIDDEN, "guest cannot read settings").into_response();
    }
    let fallback = inbox_fallback()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let active = effective_inbox_dir();
    let configured = configured_inbox_dir();
    Json(serde_json::json!({
        "inbox_dir": if fallback.is_some() { active.to_string_lossy() } else { configured.to_string_lossy() },
        "active_inbox_dir": active.to_string_lossy(),
        "restart_required": fallback.is_none() && !same_location(&configured, &active),
        "inbox_fallback": fallback.is_some(),
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
            "active_inbox_dir": effective_inbox_dir().to_string_lossy(),
            "restart_required": !same_location(&p, &effective_inbox_dir()),
        }))
        .into_response(),
        Err(msg) => {
            logw(&format!(
                "settings: rejected inbox_dir '{}': {msg}",
                payload.path.trim()
            ));
            (StatusCode::BAD_REQUEST, msg).into_response()
        }
    }
}

/// Apply a saved inbox-dir switch now: restart the process so the new
/// directory takes effect without hunting the tray icon (the default close
/// hides to the tray, so "close and reopen" never restarts). PC-only like
/// every other settings write — a guest must not reboot the owner's app.
/// Delayed ~800ms so this POST can answer ok first; the frontend treats even
/// a dropped connection as success. The pairing token rotates on restart, so
/// the phone must rescan — the button says so up front, and the phone's next
/// request lands on the unpaired page regardless.
pub(crate) async fn restart_now(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(app): State<tauri::AppHandle>,
) -> impl IntoResponse {
    if from_by_peer(peer) != "owner" {
        return (StatusCode::FORBIDDEN, "guest cannot restart").into_response();
    }
    logf("settings: restarting to apply new inbox_dir (pairing token rotates, phone must rescan)");
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(800));
        app.restart();
    });
    Json(serde_json::json!({ "ok": true })).into_response()
}

/// Open the data directory (log/index/settings) in Explorer. PC-only: a guest
/// request must not pop windows on the PC (same guard as /open-dir).
pub(crate) async fn open_data_dir(ConnectInfo(peer): ConnectInfo<SocketAddr>) -> impl IntoResponse {
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
    // Start at the configured inbox itself: a valid ownership marker lets the
    // save rule safely reuse it. Starting at its parent would select a
    // different directory under the empty-adopt / numbered-child rule.
    let start = configured_inbox_dir();
    let picked = tokio::task::spawn_blocking(move || {
        use tauri_plugin_dialog::DialogExt;
        app.dialog()
            .file()
            .set_title("选择收件箱位置")
            // Starting from the configured inbox preserves the user's context;
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
    logf(&format!(
        "settings: picker chose: {}",
        path.as_deref().unwrap_or("<cancelled>")
    ));
    Json(serde_json::json!({ "path": path })).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inbox_selection_reuses_empty_and_numbers_conflicts() {
        let env = crate::test_support::TestEnv::setup("settings-inbox-select");
        let root = env.inbox().parent().unwrap();

        let empty = root.join("empty-any-name");
        std::fs::create_dir_all(&empty).unwrap();
        let selected = save_inbox_dir(empty.to_str().unwrap()).unwrap();
        assert_eq!(
            selected, empty,
            "empty folders are reused regardless of name"
        );
        assert!(has_managed_marker(&selected));
        assert_eq!(effective_inbox_dir(), env.inbox(), "save waits for restart");

        let hidden_only = root.join("hidden-only");
        std::fs::create_dir_all(&hidden_only).unwrap();
        std::fs::write(hidden_only.join(".private"), b"preserve").unwrap();
        assert!(!dir_holds_managed_files(&hidden_only));
        assert_eq!(
            save_inbox_dir(hidden_only.to_str().unwrap()).unwrap(),
            hidden_only,
            "dotfiles are outside the managed inbox contract"
        );

        let busy = root.join("occupied");
        std::fs::create_dir_all(busy.join("inbox")).unwrap();
        std::fs::write(busy.join("photo.jpg"), b"user file").unwrap();
        let selected = save_inbox_dir(busy.to_str().unwrap()).unwrap();
        assert_eq!(selected, busy.join("inbox (2)"));
        assert!(has_managed_marker(&selected));
        assert_eq!(std::fs::read(busy.join("photo.jpg")).unwrap(), b"user file");
    }

    #[test]
    fn missing_marker_falls_back_and_preserves_custom_files() {
        let env = crate::test_support::TestEnv::setup("settings-inbox-release");
        let custom = env.inbox().parent().unwrap().join("custom");
        std::fs::create_dir_all(&custom).unwrap();
        let file = custom.join("keep.txt");
        std::fs::write(&file, b"keep me").unwrap();
        let settings = SettingsFile {
            inbox_dir: Some(custom.to_string_lossy().into_owned()),
            close_behavior: None,
        };
        persist(&settings).unwrap();
        set_test_inbox_dir(None);

        // No marker means explicit release: fallback is persisted, logged, and
        // the released directory is never touched.
        load();
        assert_eq!(effective_inbox_dir(), default_inbox_dir());
        assert_eq!(std::fs::read(&file).unwrap(), b"keep me");
        assert_eq!(configured_inbox_dir(), default_inbox_dir());
        assert!(inbox_fallback().lock().unwrap().is_some());
    }

    #[cfg(windows)]
    #[test]
    fn managed_marker_is_hidden_in_windows_explorer() {
        use std::os::windows::ffi::OsStrExt;
        use windows::Win32::Storage::FileSystem::{
            GetFileAttributesW, FILE_ATTRIBUTE_HIDDEN, INVALID_FILE_ATTRIBUTES,
        };

        let env = crate::test_support::TestEnv::setup("settings-marker-hidden");
        let dir = env.inbox().parent().unwrap().join("marker-inbox");
        std::fs::create_dir_all(&dir).unwrap();
        create_managed_marker(&dir).unwrap();
        let marker = managed_marker(&dir);
        let wide: Vec<u16> = marker.as_os_str().encode_wide().chain([0]).collect();
        let attributes = unsafe { GetFileAttributesW(windows::core::PCWSTR(wide.as_ptr())) };
        assert_ne!(attributes, INVALID_FILE_ATTRIBUTES);
        assert_ne!(attributes & FILE_ATTRIBUTE_HIDDEN.0, 0);
    }
}
