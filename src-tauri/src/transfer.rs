// Byte-transfer machinery: the upload endpoint, the shared file dispatch
// (serve: Range/ETag + per-request counters), /dl, /view, /dl-status,
// /cancel, /rm, and the ledger (DlProg map + refused-push set) they share.
// Push events ride crate::server::notifier; the catalog is the source of
// truth; the transfer page's rings and pulses render what these counters say.

use crate::catalog;
use crate::logger::{loge, logf, logw};
use crate::presence::now_mono;
use crate::server::from_by_peer;
use crate::server::{notifier, safe_name, IdParam, PushEvent};
use axum::{
    body::Body,
    extract::{ConnectInfo, Multipart, Query},
    http::{header, HeaderMap, HeaderValue, StatusCode, Uri},
    response::IntoResponse,
    Json,
};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_stream::StreamExt as _;
use tokio_util::io::ReaderStream;
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
pub(crate) struct DlProg {
    pub(crate) total: u64,
    pub(crate) sent: u64,
    /// Monotonic seconds-since-start of the last byte written / registration
    /// (see touch_entry). Compared against now_mono() by the monitor's prune —
    /// its only reader.
    pub(crate) last_ts: u64,
    /// Last time a progress event was pushed for this transfer, to throttle SSE
    /// emissions to ~1/s per transfer (the frontend used to poll /dl-status).
    last_emit_ms: u64,
    /// Wall ms when this pull registered (0 = unset): feeds the abort-speed
    /// line in StreamCutGuard::drop, so a cut transfer still reports the rate
    /// it was achieving instead of just a byte count.
    start_ms: u64,
}

/// Monotonic source of per-request download transfer ids ("msg#n").
static DL_XFER_SEQ: AtomicU64 = AtomicU64::new(0);

static DL_PROGRESS: OnceLock<Mutex<std::collections::HashMap<String, DlProg>>> = OnceLock::new();

fn dl_progress() -> &'static Mutex<std::collections::HashMap<String, DlProg>> {
    DL_PROGRESS.get_or_init(|| Mutex::new(std::collections::HashMap::new()))
}

/// [LIVENESS/death] Mark a transfer as alive. The single writer of
/// DlProg::last_ts: registration, every chunk (either direction) and the
/// upload-silence timeout all go through here. Read by the monitor's prune —
/// its only reader.
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
pub(crate) fn dl_lock() -> std::sync::MutexGuard<'static, std::collections::HashMap<String, DlProg>> {
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

/// Upload query: the sender's declared file size (drives the pending row's
/// total for the shared ring). Absent -> total unknown until the body lands.
#[derive(serde::Deserialize)]
pub(crate) struct UpQuery {
    pub(crate) size: Option<u64>,
}

/// [LIVENESS/death] Seconds an upload body may go silent before the upload
/// handler aborts it: the peer died or its connection went silent (a killed
/// phone, a half-open TCP), and hyper has no body read timeout, so the
/// actively-awaited read needs this wrapper. Without it the pending row would
/// hang forever. Floor: the longest legitimate chunk gap of a healthy LAN
/// push (milliseconds), with margin. Same number as the monitor's prune
/// window, different kind of timeout: this one aborts a TASK (uploads have
/// no legitimate pause state, so prompt is safe), that one reaps a LEDGER
/// entry (pulls do — a paused puller is reaped too, accepted as a false
/// alarm; a live stream rebuilds its counter on the next chunk).
const UPLOAD_SILENCE_SECS: u64 = 5;

pub(crate) async fn upload(
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
            // Early rejections happen before any pending row exists, so the
            // access log's error line is the only trace — log the reason here
            // or the next silent 400 is undebuggable (e.g. pasted clipboard
            // images once arrived with empty filenames).
            Ok(None) => {
                logw(&format!("upload rejected: no file field from {peer} (?size={:?})", q.size));
                return (StatusCode::BAD_REQUEST, "no file field").into_response();
            }
            Err(e) => {
                logw(&format!("upload rejected: multipart read from {peer}: {e}"));
                return (StatusCode::BAD_REQUEST, format!("read: {e}")).into_response();
            }
        };
        if field.name() != Some("file") {
            continue;
        }
        let filename = safe_name(field.file_name().unwrap_or("unnamed"));
        if filename.is_empty() {
            logw(&format!("upload rejected: empty filename from {peer} (?size={:?})", q.size));
            return (StatusCode::BAD_REQUEST, "bad filename").into_response();
        }
        // Write to inbox under a SENTINEL name, not the final one:
        // `pending__{id}__{filename}` until the whole body is on disk, then a
        // same-volume rename strips the prefix (atomic — same directory). The
        // sentinel makes a partial file self-identifying, independent of the
        // catalog index: after a crash + index loss, reconcile kills anything
        // wearing `pending__` instead of adopting a truncated file as
        // complete. The prefix cannot collide with a user's filename — `{id}`
        // is a server-generated nanosecond stamp, unknowable in advance. The
        // catalog id matches the inner `{id}__` prefix.
        let id = catalog::new_id();
        let stored = catalog::inbox_dir().join(format!("pending__{id}__{filename}"));
        let final_path = catalog::inbox_dir().join(format!("{id}__{filename}"));
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
        // Upload-direction twin of the download `Measured` wrapper below:
        // when the body lands, log MB/s socket->disk for >= 4 MB pushes, so
        // either direction can prove whether the code or the WiFi is the
        // ceiling. (Create time excluded — pure body time.)
        let t0 = tokio::time::Instant::now();
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
        let write_result = match write_result {
            Ok(()) => match tokio::fs::rename(&stored, &final_path).await {
                Ok(()) => Ok(()),
                // Graduation failed (file locked by AV/backup): the bytes may
                // be complete, but the sentinel is still on — serving it as
                // ready would survive this session only to be killed by the
                // next reconcile. Fail the upload instead; the cleanup below
                // deletes the file, and even a lost delete race leaves the
                // sentinel on for the next reconcile to finish.
                Err(e) => Err(format!("promote: {e}")),
            },
            other => other,
        };
        match write_result {
            Ok(()) => {
                catalog::mark_remote_ready(&id, &final_path);
                logf(&format!("upload done: {} ({} bytes) -> inbox", filename, total));
                if total >= 4 * 1024 * 1024 {
                    let secs = t0.elapsed().as_secs_f64();
                    if secs > 0.0 {
                        logf(&format!(
                            "ul {}: {:.1} MB in {:.2}s = {:.1} MB/s",
                            filename,
                            total as f64 / (1024.0 * 1024.0),
                            secs,
                            total as f64 / secs / (1024.0 * 1024.0)
                        ));
                    }
                }
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
                // partial file; do NOT leave the entry in the catalog. The
                // unlink targets the sentinel-named file, so even if THIS
                // delete fails (locked), the name still reads "partial" and
                // the next startup's reconcile finishes the job — a residue
                // can never be mistaken for a complete file.
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

/// PC drag-and-drop / paste: copy a local file into the inbox through the
/// SAME pipeline as a phone upload — pending row registered first (the card
/// and its ring appear at drop instant instead of after a silent copy), a
/// sentinel-named destination, a chunked copy that feeds the shared ledger so
/// the throttled `progress` pushes move the PC's corner ring, and the
/// graduation rename that strips the sentinel. Failure cleans itself exactly
/// like a failed upload, so even a mid-copy process death leaves a residue
/// that self-identifies (reconcile kills the sentinel; the original never
/// left the source disk, so nothing is lost).
pub(crate) async fn copy_into_inbox(src: &Path) -> std::io::Result<(String, PathBuf, String)> {
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
    let stored = catalog::inbox_dir().join(format!("pending__{id}__{safe}"));
    let final_path = catalog::inbox_dir().join(format!("{id}__{safe}"));
    let size = tokio::fs::metadata(src).await.map(|m| m.len()).unwrap_or(0);

    // Self-clean on any failure past registration: the pending row, the
    // ledger entry and the sentinel file all go; the List push repaints both
    // ends. Mirrors the upload handler's Err arm one-for-one.
    async fn fail(stored: &Path, id: &str) {
        catalog::remove(id);
        let _ = tokio::fs::remove_file(stored).await;
        dl_lock().remove(id);
        let _ = notifier().send(PushEvent::List(catalog::all_items()));
    }

    // Register the pending row + ledger entry FIRST, so feedback starts at
    // drop instant and the copy below just fills the ring. The declared total
    // is exact (a local stat, not the sender's claim).
    catalog::add_remote_pending("pc", &id, &stored, &safe, size);
    let _ = notifier().send(PushEvent::List(catalog::all_items()));
    {
        let mut map = dl_lock();
        let e = map.entry(id.clone()).or_default();
        e.total = size;
        e.sent = 0;
        touch_entry(e);
    }

    let src_f = match tokio::fs::File::open(src).await {
        Ok(f) => f,
        Err(e) => {
            fail(&stored, &id).await;
            return Err(e);
        }
    };
    let dst_f = match tokio::fs::File::create(&stored).await {
        Ok(f) => f,
        Err(e) => {
            fail(&stored, &id).await;
            return Err(e);
        }
    };
    let mut reader = tokio::io::BufReader::with_capacity(512 * 1024, src_f);
    let mut writer = tokio::io::BufWriter::with_capacity(512 * 1024, dst_f);
    // Chunked copy instead of copy_buf (a black box): every 512 KiB lands in
    // the ledger and drives the throttled ring update. Same buffering
    // profile, so throughput is unchanged.
    let mut buf = vec![0u8; 512 * 1024];
    let mut sent: u64 = 0;
    let copy = loop {
        match reader.read(&mut buf).await {
            Ok(0) => break Ok(()),
            Ok(n) => {
                if let Err(e) = writer.write_all(&buf[..n]).await {
                    break Err(e);
                }
                sent += n as u64;
                {
                    let mut map = dl_lock();
                    let e = map.entry(id.clone()).or_default();
                    e.sent = sent;
                    touch_entry(e);
                    push_progress(&mut map, &id, now_ms(), false);
                }
            }
            Err(e) => break Err(e),
        }
    };
    // Flush to surface disk-full / late write errors before registering ready.
    let copy = match copy {
        Ok(()) => writer.flush().await,
        Err(e) => Err(e),
    };
    if let Err(e) = copy {
        drop(writer); // release the handle so remove_file works on Windows
        fail(&stored, &id).await;
        return Err(e);
    }
    drop(writer);
    // Graduation: strip the sentinel with a same-volume atomic rename, then
    // flip the row ready. The crash windows fail safe on both sides, exactly
    // like uploads: before the rename the sentinel still marks the (maybe
    // complete) bytes for reconcile — the source disk holds the original;
    // after the rename the final name is a complete file, so even if the
    // catalog update is lost, reconcile's adoption of it is correct.
    if let Err(e) = tokio::fs::rename(&stored, &final_path).await {
        fail(&stored, &id).await;
        return Err(e);
    }
    catalog::mark_remote_ready(&id, &final_path);
    {
        // Final tick (sent == total) closes the ring immediately, unthrottled.
        let mut map = dl_lock();
        if let Some(e) = map.get_mut(&id) {
            e.sent = e.total.max(sent);
            touch_entry(e);
        }
        push_progress(&mut map, &id, now_ms(), true);
    }
    Ok((id, final_path, safe))
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
            let start_ms = map.get(&self.tid).map(|e| e.start_ms).unwrap_or(0);
            map.remove(&self.tid);
            push_dl_state(&map, &self.msg_id);
            drop(map);
            // Cuts of real size carry their achieved rate (same shape as the
            // completion `dl` line): an abort with a speed needs no follow-up
            // test to judge the pipeline.
            let ms = now_ms().saturating_sub(start_ms);
            if sent >= 4 * 1024 * 1024 && start_ms > 0 && ms > 0 {
                logf(&format!(
                    "download cut by receiver {} ({}): {}/{} bytes, {:.1} MB/s",
                    self.tid,
                    self.name,
                    sent,
                    total,
                    sent as f64 / (ms as f64 / 1000.0) / (1024.0 * 1024.0)
                ));
            } else {
                logf(&format!(
                    "download closed by receiver {} ({}): {}/{} bytes",
                    self.tid, self.name, sent, total
                ));
            }
        }
    }
}

/// One shared-file dispatch: inline=true previews in the browser (/view), false
/// forces a download (/dl). Looks up the message by id; only File messages can
/// be dispatched, Text returns 400.
async fn serve(Query(p): Query<IdParam>, inline: bool, headers: HeaderMap, uri: Uri) -> impl IntoResponse {
    let Some(entry) = catalog::find(&p.id) else {
        logw(&format!("serve: id {} not found", p.id));
        // no-store on every error arm: a 404 is heuristically cacheable, and
        // a cached miss (deleted, or "still uploading" that later completes)
        // must never outlive the state it reported.
        return (
            StatusCode::NOT_FOUND,
            [(header::CACHE_CONTROL, "no-store".to_string())],
            "not found",
        )
            .into_response();
    };
    // A file still being uploaded has nothing to serve yet (partial on disk).
    if entry.pending {
        return (
            StatusCode::NOT_FOUND,
            [(header::CACHE_CONTROL, "no-store".to_string())],
            "still uploading",
        )
            .into_response();
    }
    let (path, name) = match &entry.body {
        catalog::MsgBody::File { source, name, .. } => (source.path(), name.as_str()),
        catalog::MsgBody::Text { .. } => {
            return (
                StatusCode::BAD_REQUEST,
                [(header::CACHE_CONTROL, "no-store".to_string())],
                "not a file",
            )
                .into_response();
        }
    };
    let mut file = match tokio::fs::File::open(path).await {
        Ok(f) => f,
        // The backing file may be missing: a Remote inbox copy was deleted, or a
        // legacy Local original was moved/deleted -> friendly message.
        Err(_) => {
            logw(&format!("serve: file not on disk {} ({})", name, path));
            return (
                StatusCode::NOT_FOUND,
                [(header::CACHE_CONTROL, "no-store".to_string())],
                "file missing",
            )
                .into_response();
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
    // Cache policy splits by dispatch: previews ride the browser cache
    // (`private, no-cache` + this strong id ETag) — bytes are kept locally
    // but every reuse revalidates, so a deleted message 404s instead of
    // serving stale. Retention matches no-store to within one validation
    // roundtrip, while a reopen costs N 304s instead of N full downloads.
    // `private` (never shared) because every response is per-pairing LAN
    // bytes with no shared cache in the path anyway. Downloads stay
    // `no-store`: an explicit pull owns its bytes via the download manager,
    // nothing should linger past it.
    let cc: &str = if inline { "private, no-cache" } else { "no-store" };
    // Conditional reuse, previews only: a client holding cached bytes sends
    // If-None-Match (`*` or the echoed ETag) and gets an empty 304 instead of
    // megabytes re-read and re-sent. Placement is load-bearing: this sits
    // AFTER the existence checks above, so a deleted message 404s and the
    // client's entry is purged on its next view attempt. Downloads never 304:
    // their responses are no-store, so no validator exists to send, and a
    // bodiless answer to an explicit pull would read as a broken download.
    if inline {
        let fresh = headers
            .get(header::IF_NONE_MATCH)
            .and_then(|v| v.to_str().ok())
            .map_or(false, |inm| {
                inm.trim() == "*" || inm.split(',').any(|t| t.trim() == etag)
            });
        if fresh {
            logf(&format!("serve {} -> 304 (revalidated)", p.id));
            return (
                StatusCode::NOT_MODIFIED,
                [
                    (header::ETAG, etag),
                    (header::CACHE_CONTROL, cc.to_string()),
                ],
            )
                .into_response();
        }
    }
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
                [
                    (header::CONTENT_RANGE, format!("bytes */{len}")),
                    (header::CACHE_CONTROL, "no-store".to_string()),
                ],
            )
                .into_response();
        }
        None => (0, len.saturating_sub(1), false),
    };

    use tokio::io::{AsyncReadExt, AsyncSeekExt};
    if start > 0 {
        if let Err(e) = file.seek(std::io::SeekFrom::Start(start)).await {
            logw(&format!("serve: seek failed {}: {}", path, e));
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                [(header::CACHE_CONTROL, "no-store".to_string())],
                "seek failed",
            )
                .into_response();
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
            e.start_ms = now_ms();
            touch_entry(e);
        }
        // The new pull makes the file "being served" (a fresh counter is
        // incomplete by construction, so this is always a false->true flip).
        push_dl_state(&map, &p.id);
        logf(&format!("download start {id}: {name} [{start}-{end}]/{len}"));
    }
    // Take() caps the read at the range end so a partial response carries
    // exactly end-start+1 bytes, not the rest of the file. 1 MiB read buffer:
    // A/B-tested 2026-09-11 (16 KiB vs 1 MiB, same spot, same file class):
    // 39.0 vs 42.6 MB/s — noise, chunk size is insensitive here. The old
    // "16K -> 2MB/s" story was weak signal misattributed to code. Kept at
    // 1 MiB anyway: fewer syscalls per GB for free, and 1 MiB in flight per
    // stream is nothing.
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
            // counter after 5s of silence (a paused puller reaped too); the
            // stream outlives the reap, so the rebuild below needs the
            // stream's own numbers, not whatever a dead entry remembers.
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
                                // count: the pull was silent past the monitor's
                                // 5s window, the entry went away, and without
                                // this rebuild the resumed stream would finish
                                // uncounted — no done log, no dlstate flip,
                                // and a wrong active-set for sibling pulls.
                                logf(&format!(
                                    "download counter rebuilt {tid}: {sent}/{} bytes (was pruned while paused)",
                                    len
                                ));
                                let e = map.entry(tid.clone()).or_default();
                                e.total = len;
                                e.sent = sent;
                                // Fresh entry, fresh clock: the rate a resumed
                                // pull reports is post-resume, not whole-life.
                                e.start_ms = now_ms();
                                touch_entry(e);
                                map.get_mut(&tid).unwrap()
                            }
                        };
                        e.sent = sent;
                        touch_entry(e);
                        if e.sent >= e.total && e.total > 0 {
                            // Completion throughput, measured here and not in
                            // a stream wrapper: hyper drops the body once
                            // Content-Length is satisfied WITHOUT a final
                            // None poll, so an end-of-stream hook never fires
                            // on a normal complete pull (verified: the old
                            // Measured wrapper only ever fired on truncated
                            // bodies). The ledger's start_ms is the clock.
                            let ms = now_ms().saturating_sub(e.start_ms);
                            if e.start_ms > 0 && ms > 0 {
                                logf(&format!(
                                    "dl {}: {:.1} MB in {:.1}s = {:.1} MB/s",
                                    name,
                                    e.total as f64 / (1024.0 * 1024.0),
                                    ms as f64 / 1000.0,
                                    e.total as f64 / (ms as f64 / 1000.0) / (1024.0 * 1024.0)
                                ));
                            }
                            logf(&format!("download done {tid}: {} bytes", e.sent));
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
    // Downloads ride the counted stream directly: completion (and abort)
    // throughput is logged at the ledger sites above, not in a wrapper.
    let body = Body::from_stream(stream);
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

pub(crate) async fn download(q: Query<IdParam>, headers: HeaderMap, uri: Uri) -> impl IntoResponse {
    serve(q, false, headers, uri).await
}

pub(crate) async fn view(q: Query<IdParam>, headers: HeaderMap, uri: Uri) -> impl IntoResponse {
    serve(q, true, headers, uri).await
}

/// Live transfer progress snapshot: every download the server is currently
/// serving (or recently finished — the monitor prunes finished entries after
/// 15s). Now only hit once on SSE connect (and on a one-shot resync after a
/// lagged push) - steady-state progress rides /events `progress` pushes.
/// Pruning lives in the monitor alone, so the map has exactly one janitor.
pub(crate) async fn dl_status() -> impl IntoResponse {
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
pub(crate) async fn cancel(
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

pub(crate) async fn remove(
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
