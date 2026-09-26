// Desktop-integration endpoints, all PC-only (pairing gate plus the loopback
// guard): open with the default viewer, reveal in Explorer, copy the file
// itself onto the clipboard, open the inbox folder.

use crate::catalog;
use crate::logger::{loge, logw};
use crate::server::{from_by_peer, IdParam};
use axum::{
    extract::{ConnectInfo, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use std::net::SocketAddr;
use std::path::Path;
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
pub(crate) async fn open_file(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Query(p): Query<IdParam>,
) -> impl IntoResponse {
    if from_by_peer(peer) != "owner" {
        logw("open: rejected from guest (would open viewer on the PC)");
        return (StatusCode::FORBIDDEN, "guest cannot open PC files").into_response();
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
/// copy (guest upload or owner add), legacy Local rows the original PC file. Only
/// File messages. PC-only: a guest request must not pop Explorer windows on
/// the PC (same guard posture as /cancel and /add-local).
pub(crate) async fn reveal(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Query(p): Query<IdParam>,
) -> impl IntoResponse {
    if from_by_peer(peer) != "owner" {
        logw("reveal: rejected from guest (would open Explorer on the PC)");
        return (StatusCode::FORBIDDEN, "guest cannot open PC folders").into_response();
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
/// same-process server exactly like /open and /reveal. PC-only: a guest
/// must not reach the desktop clipboard (same guard posture as /reveal).
pub(crate) async fn copy_file(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Query(p): Query<IdParam>,
) -> impl IntoResponse {
    use clipboard_win::{formats, Clipboard, Setter};
    if from_by_peer(peer) != "owner" {
        logw("copy-file: rejected from guest (would write the PC clipboard)");
        return (StatusCode::FORBIDDEN, "guest cannot use the PC clipboard").into_response();
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

/// "Save as" a file to an arbitrary location: opens the native save dialog
/// (default name = the timeline name, so renaming happens there — Windows
/// convention) and copies the bytes. PC-only like /open and /reveal: the
/// dialog pops on the PC and reads PC-local paths.
/// Answers "saved" / "cancelled" as plain text; missing/still-uploading ids
/// are 404/409 so the menu can surface them.
pub(crate) async fn save_as(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(app): State<tauri::AppHandle>,
    Query(p): Query<IdParam>,
) -> impl IntoResponse {
    use crate::logger::{loge, logf};
    if from_by_peer(peer) != "owner" {
        logw("save-as: rejected from guest (would pop a save dialog on the PC)");
        return (StatusCode::FORBIDDEN, "guest cannot save PC files").into_response();
    }
    let Some(entry) = catalog::find(&p.id) else {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    };
    if entry.pending {
        return (StatusCode::CONFLICT, "still uploading").into_response();
    }
    let (src, default_name) = match &entry.body {
        catalog::MsgBody::File { source, name, .. } => (source.path().to_string(), name.clone()),
        catalog::MsgBody::Text { .. } => {
            return (StatusCode::BAD_REQUEST, "not a file").into_response();
        }
    };
    if !Path::new(&src).exists() {
        return (StatusCode::NOT_FOUND, "file missing").into_response();
    }
    // blocking_* must never run on the main thread; the axum worker is
    // already off it, and spawn_blocking keeps the async runtime free while
    // the modal sits open — same posture as settings::pick_dir. Dialog +
    // copy share one blocking task so the copy never blocks the runtime.
    let outcome = tokio::task::spawn_blocking(move || {
        use tauri_plugin_dialog::DialogExt;
        let dest = app
            .dialog()
            .file()
            .set_title("另存为")
            .set_file_name(&default_name)
            .blocking_save_file();
        let Some(fp) = dest else {
            return Ok::<_, String>(None);
        };
        let Some(dest_path) = fp.as_path() else {
            return Err("unsupported save location".to_string());
        };
        std::fs::copy(&src, dest_path)
            .map_err(|e| format!("copy failed: {e}"))
            .map(|_| Some(dest_path.to_path_buf()))
    })
    .await;
    match outcome {
        Ok(Ok(None)) => (StatusCode::OK, "cancelled").into_response(),
        Ok(Ok(Some(dest))) => {
            logf(&format!("save-as: {} -> {}", p.id, dest.display()));
            (StatusCode::OK, "saved").into_response()
        }
        Ok(Err(msg)) => {
            loge(&format!("save-as {}: {msg}", p.id));
            (StatusCode::INTERNAL_SERVER_ERROR, "save failed").into_response()
        }
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "task failed").into_response(),
    }
}

/// Open the PC-side inbox directory (guest frontends hide this button).
/// Frontend "Inbox" click: open the inbox folder on the PC. PC-only for the
/// same reason as /reveal — a guest request must not pop windows on the PC.
pub(crate) async fn open_dir(ConnectInfo(peer): ConnectInfo<SocketAddr>) -> impl IntoResponse {
    if from_by_peer(peer) != "owner" {
        logw("open-dir: rejected from guest (would open Explorer on the PC)");
        return (StatusCode::FORBIDDEN, "guest cannot open PC folders").into_response();
    }
    match open::that(catalog::inbox_dir()) {
        Ok(_) => (StatusCode::OK, "opened").into_response(),
        Err(e) => {
            logw(&format!("open-dir: could not open inbox folder: {}", e));
            (StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")).into_response()
        }
    }
}
