// Catalog index layer: uniformly manages "message entries" (files and text).
//   File messages: reuse Source. Remote = materialized into the inbox folder (a
//     phone upload, or a PC file the app copied in when it was added). Local is
//     legacy only: pre-change rows that reference an original PC path by
//     zero-copy and are never file-deleted.
//   Text messages: content inlined directly, no source.
// Each message carries from("owner"/"guest") and ts; the frontend renders them
// on a timeline with left/right bubbles per sender.
//
// State is shared globally (`CATALOG`) so axum handlers (server thread
// runtime) and Tauri commands (main runtime) use the same instance. The entry
// count is small and critical sections are short, so std Mutex + full
// persistence is enough.
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use crate::media::MediaMeta;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Serialize, Deserialize, Clone)]
#[serde(tag = "type")]
pub enum Source {
    /// Legacy zero-copy reference to an original PC path (registered before adds
    /// started copying into inbox). `/rm` removes only the record, never the file.
    Local { path: String },
    /// A tinbox-owned file materialized in the inbox folder — a phone upload, or
    /// a PC file copied in when it was added. `/rm` deletes it with the record.
    Remote { path: String },
}

impl Source {
    /// The actual disk path to read/write, regardless of source.
    pub fn path(&self) -> &str {
        match self {
            Source::Local { path } => path,
            Source::Remote { path } => path,
        }
    }
    pub fn is_remote(&self) -> bool {
        matches!(self, Source::Remote { .. })
    }
    /// Source label for the frontend: "local" / "remote".
    pub fn kind_str(&self) -> &'static str {
        match self {
            Source::Local { .. } => "local",
            Source::Remote { .. } => "remote",
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(tag = "kind")]
pub enum MsgBody {
    File {
        source: Source,
        size: u64,
        name: String,
        /// Video duration + dimensions for the timeline's compact row
        /// (probed from moov, no decoding). None for non-video, unparseable
        /// files, and rows written before probing existed (reconcile
        /// backfills those). Skipped in JSON when absent so old rows stay
        /// byte-identical; missing on read means None either way.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        media: Option<MediaMeta>,
        /// True once a Shell-extracted JPEG lives at posters/{id}.jpg.
        /// Presence of the file is the disk truth; this flag is its index
        /// so the frontend can pick brick vs compact row without a 404.
        #[serde(default, skip_serializing_if = "is_false")]
        poster: bool,
    },
    Text { text: String },
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Entry {
    pub id: String,
    pub ts: String,
    pub from: String, // "owner" | "guest"
    pub body: MsgBody,
    /// True while a phone upload is still landing (the file on disk is
    /// incomplete). Missing on older files -> false.
    #[serde(default)]
    pub pending: bool,
}

/// List item for the frontend; carries different fields per kind, which the
/// frontend renders according to kind. Clone so the SSE push channel can
/// broadcast the full list on every change.
#[derive(Serialize, Clone)]
pub struct MsgItem {
    pub id: String,
    pub ts: String,
    pub from: String,
    pub kind: String, // "file" | "text"
    // valid for file:
    pub name: String,
    pub size: u64,
    pub source_kind: String, // "local" | "remote"; empty for text
    /// Video duration + dimensions ({dur_ms, w, h}), null when absent.
    pub media: Option<MediaMeta>,
    /// True when a JPEG poster is ready at /poster?id=.
    pub poster: bool,
    /// True while this remote file is still being uploaded.
    pub pending: bool,
    // valid for text:
    pub text: String,
}

impl Entry {
    pub fn to_item(&self) -> MsgItem {
        match &self.body {
            MsgBody::File {
                source,
                size,
                name,
                media,
                poster,
            } => MsgItem {
                id: self.id.clone(),
                ts: self.ts.clone(),
                from: self.from.clone(),
                kind: "file".to_string(),
                name: name.clone(),
                size: *size,
                source_kind: source.kind_str().to_string(),
                media: media.clone(),
                poster: *poster,
                pending: self.pending,
                text: String::new(),
            },
            MsgBody::Text { text } => MsgItem {
                id: self.id.clone(),
                ts: self.ts.clone(),
                from: self.from.clone(),
                kind: "text".to_string(),
                name: String::new(),
                size: 0,
                source_kind: String::new(),
                media: None,
                poster: false,
                pending: false,
                text: text.clone(),
            },
        }
    }
}

static COUNTER: AtomicUsize = AtomicUsize::new(0);

/// Zero-dependency id: nanoseconds + incrementing counter, avoiding collisions
/// within the same millisecond.
pub fn new_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let c = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{nanos}-{c}")
}

/// Current second-resolution timestamp string (message send time).
pub fn now_ts() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs().to_string())
        .unwrap_or_default()
}

/// Directory of the exe: now ONLY the legacy-shared-dir lookup below. Live
/// data (inbox, catalog.json) lives under the app data root, which survives
/// exe moves and read-only install dirs.
fn exe_parent() -> PathBuf {
    let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("."));
    exe.parent().unwrap_or_else(|| Path::new(".")).to_path_buf()
}

pub fn inbox_dir() -> PathBuf {
    crate::logger::data_root().join("inbox")
}

pub fn catalog_path() -> PathBuf {
    crate::logger::data_root().join("catalog.json")
}

/// Legacy shared directory (only used for a one-time migration).
pub fn legacy_shared_dir() -> PathBuf {
    exe_parent().join("shared")
}

static CATALOG: OnceLock<Arc<Mutex<Vec<Entry>>>> = OnceLock::new();

pub fn catalog() -> &'static Arc<Mutex<Vec<Entry>>> {
    CATALOG.get_or_init(|| Arc::new(Mutex::new(Vec::new())))
}

/// Poison-safe lock for the catalog. A handler that panics while holding this
/// lock poisons the Mutex, after which every unwrap() would panic in turn and
/// take down every list/upload/delete/reference handler. Entries are plain
/// rows with no cross-field invariants, so recovering the guard is safe: the
/// partial write is a missing or stale row at worst, healed by the next save
/// or list push.
fn cat_lock() -> std::sync::MutexGuard<'static, Vec<Entry>> {
    catalog().lock().unwrap_or_else(|e| e.into_inner())
}

/// Convert a legacy entry (top-level source/size/name/mtime, no body/from) to
/// a new-format Entry. Local -> from="owner", Remote -> from="guest"; ts takes the
/// legacy mtime.
fn migrate_old_entry(v: &serde_json::Value) -> Option<Entry> {
    // New format has a body field, legacy format does not. Entries with a body
    // go straight through normal deserialization.
    if v.get("body").is_some() {
        return serde_json::from_value(v.clone()).ok();
    }
    let id = v.get("id")?.as_str()?.to_string();
    let name = v.get("name")?.as_str()?.to_string();
    let size = v.get("size").and_then(|s| s.as_u64()).unwrap_or(0);
    let ts = v
        .get("mtime")
        .and_then(|s| s.as_str())
        .unwrap_or("")
        .to_string();
    let source_val = v.get("source")?;
    let source: Source = serde_json::from_value(source_val.clone()).ok()?;
    let from = if source.is_remote() { "guest" } else { "owner" }.to_string();
    Some(Entry {
        id,
        ts,
        from,
        body: MsgBody::File {
            source,
            size,
            name,
            media: None,
            poster: false,
        },
        pending: false,
    })
}

fn is_false(v: &bool) -> bool {
    !*v
}

pub fn load() {
    let mut v = cat_lock();
    v.clear();
    match std::fs::read_to_string(catalog_path()) {
        Ok(txt) => match serde_json::from_str::<Vec<serde_json::Value>>(&txt) {
            Ok(arr) => {
                let before = arr.len();
                for item in arr {
                    if let Some(e) = migrate_old_entry(&item) {
                        v.push(e);
                    }
                }
                if v.len() < before {
                    crate::logger::logw(&format!(
                        "catalog: skipped {} unreadable entries",
                        before - v.len()
                    ));
                }
            }
        Err(e) => {
            // Corrupt index: quarantine the file so the empty in-memory
            // catalog cannot overwrite it on the next save (the records
            // would be lost for good). The startup reconcile pass then
            // re-adopts every file from inbox, so nothing but text history
            // is lost.
            let bad = catalog_path().with_extension("json.bad");
            let renamed = std::fs::rename(catalog_path(), &bad);
            crate::logger::loge(&format!(
                "catalog: corrupt index ({}); quarantined to {}: {e}",
                catalog_path().display(),
                bad.display()
            ));
            if renamed.is_err() {
                crate::logger::loge("catalog: quarantine rename failed — the corrupt file may be overwritten by the next save");
            }
        }
        },
        // A missing index on first run is normal, not an error.
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => crate::logger::loge(&format!(
            "catalog: could not read {}: {}",
            catalog_path().display(),
            e
        )),
        Err(_) => {}
    }
}

pub fn save() {
    let v = cat_lock();
    match serde_json::to_string_pretty(&*v) {
        Ok(json) => {
            if let Err(e) = std::fs::write(catalog_path(), json) {
                crate::logger::loge(&format!(
                    "catalog: could not save index {}: {}",
                    catalog_path().display(),
                    e
                ));
            }
        }
        Err(e) => crate::logger::loge(&format!("catalog: could not serialize index: {}", e)),
    }
}

/// Startup reconciliation: the inbox directory is the disk truth, the catalog
/// is its index. Three divergences are repaired, both bounded to startup so the
/// runtime keeps its single-writer simplicity:
///   - orphan files (on disk, no record) are ADOPTED as from="owner" entries.
///     This is also the self-heal path after a lost or quarantined index:
///     every file becomes manageable again, only text history is lost.
///   - dangling records (indexed, file gone — the user deleted or moved the
///     file via Explorer) are DROPPED, matching that intent; keeping them
///     would leave dead "file missing" bubbles.
///   - `pending__`-prefixed files are a dead upload's residue — the sentinel
///     stamped at registration and stripped only by the success-path rename,
///     so its presence proves the body never graduated. They are DELETED on
///     sight. This is the one carve-out from "the index yields to the disk":
///     a sentinel file is not disk truth, it is a transfer that never became
///     a file. The prefix is namespaced with a server-generated nanosecond
///     id, so no user filename can collide; deletion retries every startup
///     until it wins (a locked file just waits), and a residue can never be
///     adopted as a complete file after an index loss.
/// Disk files are otherwise NEVER deleted here: the index yields to the disk,
/// never the reverse. Runs after purge_pending so interrupted-upload
/// leftovers do not count as orphans.
pub fn reconcile() {
    let dir = inbox_dir();
    let mut on_disk: Vec<(PathBuf, String)> = Vec::new();
    let mut skipped_dirs = 0usize;
    if let Ok(rd) = std::fs::read_dir(&dir) {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            let Ok(meta) = e.metadata() else { continue };
            // Inbox is a flat landing zone: no recursion, no dot-dirs. A
            // hand-dropped subfolder is ignored whole (its files are never
            // adopted) — counted here so the log says so instead of silence.
            if !meta.is_file() || name.starts_with('.') {
                if meta.is_dir() && !name.starts_with('.') {
                    skipped_dirs += 1;
                }
                continue;
            }
            // Kill the sentinel-named residue before it can be mistaken for
            // an orphan to adopt (see the doc block above).
            if name.starts_with("pending__") {
                let p = e.path();
                match std::fs::remove_file(&p) {
                    Ok(()) => crate::logger::logf(&format!("catalog: deleted partial upload {name}")),
                    Err(err) => crate::logger::logw(&format!(
                        "catalog: partial upload {name} still locked, retry next startup: {err}"
                    )),
                }
                continue;
            }
            on_disk.push((e.path(), name));
        }
    }
    let known: std::collections::HashSet<String> = cat_lock()
        .iter()
        .filter_map(|e| match &e.body {
            MsgBody::File { source, .. } => Some(source.path().to_string()),
            MsgBody::Text { .. } => None,
        })
        .collect();

    let mut adopted = 0usize;
    for (path, name) in &on_disk {
        let ps = path.to_string_lossy().to_string();
        if known.contains(&ps) {
            continue;
        }
        let display = strip_stored_prefix(name);
        // add_remote stamps now_ts(); the entry is then corrected to the
        // file's mtime, which is the honest history moment.
        let ts = file_mtime_secs(path);
        let entry = add_remote("owner", &new_id(), path, &display);
        {
            let mut v = cat_lock();
            if let Some(e) = v.iter_mut().find(|e| e.id == entry.id) {
                if let Some(t) = ts {
                    e.ts = t;
                }
            }
        }
        adopted += 1;
        crate::logger::logf(&format!("catalog: adopted orphan file {name} (id {})", entry.id));
    }

    let dropped;
    {
        let mut v = cat_lock();
        let before = v.len();
        v.retain(|e| match &e.body {
            MsgBody::File { source, .. } => Path::new(source.path()).exists(),
            MsgBody::Text { .. } => true,
        });
        dropped = before - v.len();
    }
    // Backfill video metadata for rows written before probing existed: one
    // header-only walk per file (seeks, milliseconds), then a single save.
    // Runs at startup only — never on the hot list/push path.
    let mut probed = 0usize;
    {
        let mut v = cat_lock();
        for e in v.iter_mut() {
            if let MsgBody::File {
                source,
                name,
                media: ref mut m,
                ..
            } = &mut e.body
            {
                if m.is_none() && crate::media::is_bmff_name(name) {
                    let pth = Path::new(source.path());
                    if pth.exists() {
                        *m = crate::media::probe_for(name, pth);
                        if m.is_some() {
                            probed += 1;
                        }
                    }
                }
            }
        }
    }
    if probed > 0 {
        crate::logger::logf(&format!(
            "catalog: backfilled video metadata for {probed} entr{}",
            if probed == 1 { "y" } else { "ies" }
        ));
        save();
    }
    if adopted > 0 || dropped > 0 {
        crate::logger::logf(&format!(
            "catalog: reconciled with inbox — {adopted} adopted, {dropped} dangling record(s) dropped"
        ));
        save();
    }
    if skipped_dirs > 0 {
        crate::logger::logf(&format!(
            "catalog: ignored {skipped_dirs} subdirector{} in inbox (flat layout — files inside are not indexed)",
            if skipped_dirs == 1 { "y" } else { "ies" }
        ));
    }
}

/// Adopted files may still carry the stored `{nanos}-{seq}__` prefix; show
/// the clean name instead. Anything that does not match the shape (a user
/// file like "2024-report__draft.jpg") is kept verbatim.
fn strip_stored_prefix(name: &str) -> String {
    if let Some((head, rest)) = name.split_once("__") {
        let looks_like_id = !head.is_empty()
            && head.contains('-')
            && head.split('-').all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()));
        if looks_like_id {
            return rest.to_string();
        }
    }
    name.to_string()
}

/// Adoption timestamps come from the file's mtime, not the adoption moment:
/// a file dropped into inbox three months ago should read as three months
/// old in the timeline.
fn file_mtime_secs(p: &Path) -> Option<String> {
    let t = std::fs::metadata(p).ok()?.modified().ok()?;
    Some(t.duration_since(std::time::UNIX_EPOCH).ok()?.as_secs().to_string())
}

/// Recursively collect every file under a directory into `out`.
pub fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for e in entries.flatten() {
            if let Ok(meta) = e.metadata() {
                if meta.is_file() {
                    out.push(e.path());
                } else if meta.is_dir() {
                    collect_files(&e.path(), out);
                }
            }
        }
    }
}

/// Register a file already materialized in inbox as a from="<from>" file message:
/// "owner" for a file the owner side added (the app copied it into inbox),
/// "guest" for an inbound upload. The row is ready immediately (never pending).
pub fn add_remote(from: &str, id: &str, inbox_path: &Path, display_name: &str) -> Entry {
    let size = std::fs::metadata(inbox_path).map(|m| m.len()).unwrap_or(0);
    // Probe once, at rest: the file is complete here (PC add, orphan
    // adoption), so moov is final. Pending uploads probe at graduation
    // instead (mark_remote_ready) — a partial moov would misreport.
    let media = crate::media::probe_for(display_name, inbox_path);
    let entry = Entry {
        id: id.to_string(),
        ts: now_ts(),
        from: from.to_string(),
        body: MsgBody::File {
            source: Source::Remote {
                path: inbox_path.to_string_lossy().to_string(),
            },
            size,
            name: display_name.to_string(),
            media,
            poster: false,
        },
        pending: false,
    };
    let mut v = cat_lock();
    v.push(entry.clone());
    drop(v);
    save();
    entry
}

/// Register an upload the moment its request arrives, marked `pending` so both
/// devices can render the row and a progress ring while bytes stream in. The
/// sender is the peer-determined `from` ("guest" for LAN pushes, "owner" for the
/// desktop's own paste-to-send, which has no real path and rides /upload).
/// `size` is the declared total (sent in the query string); it is corrected to
/// the on-disk length when the upload finishes.
pub fn add_remote_pending(from: &str, id: &str, inbox_path: &Path, display_name: &str, size: u64) -> Entry {
    let entry = Entry {
        id: id.to_string(),
        ts: now_ts(),
        from: from.to_string(),
        body: MsgBody::File {
            source: Source::Remote {
                path: inbox_path.to_string_lossy().to_string(),
            },
            size,
            name: display_name.to_string(),
            // No probe while landing: the moov may be incomplete (or, for
            // moov-at-end files, entirely absent until the last byte).
            media: None,
            poster: false,
        },
        pending: true,
    };
    let mut v = cat_lock();
    v.push(entry.clone());
    drop(v);
    save();
    entry
}

/// Flip a pending upload to a real entry once the whole body has been written
/// and renamed off its `pending__` sentinel: clears the flag, repoints the
/// stored path at the final (sentinel-free) name and fixes `size` to the
/// actual on-disk length. No-op (false) if the id is gone or not a pending
/// remote file.
pub fn mark_remote_ready(id: &str, final_path: &Path) -> bool {
    let mut v = cat_lock();
    let Some(e) = v.iter_mut().find(|e| e.id == id) else {
        return false;
    };
    let is_pending_remote_file = e.pending
        && matches!(&e.body, MsgBody::File { source: Source::Remote { .. }, .. });
    if !is_pending_remote_file {
        return false;
    }
    e.pending = false;
    if let MsgBody::File {
        source: Source::Remote { path },
        size,
        name,
        media,
        poster: _,
    } = &mut e.body
    {
        *path = final_path.to_string_lossy().to_string();
        *size = std::fs::metadata(final_path).map(|m| m.len()).unwrap_or(*size);
        // Graduation probe: the bytes are complete and the sentinel is gone,
        // so this is the first moment moov is trustworthy.
        *media = crate::media::probe_for(name, final_path);
    }
    drop(v);
    save();
    true
}

/// Drop catalog entries left pending by a crashed/interrupted upload and delete
/// their partial files (the sentinel-named path recorded at registration).
/// Called once at startup, before reconcile; a delete that loses to a file
/// lock is retried by reconcile's sentinel sweep on the same startup.
pub fn purge_pending() {
    let mut v = cat_lock();
    let before = v.len();
    v.retain(|e| {
        if e.pending {
            if let MsgBody::File { source: Source::Remote { path }, .. } = &e.body {
                let _ = std::fs::remove_file(path);
            }
            false
        } else {
            true
        }
    });
    let removed = before - v.len();
    drop(v);
    if removed > 0 {
        save();
        crate::logger::logf(&format!(
            "catalog: purged {removed} interrupted upload{}",
            if removed == 1 { "" } else { "s" }
        ));
    }
}

/// Register a text message (the caller passes the `from` value determined from
/// the source IP).
pub fn add_text(from: &str, text: &str) -> Entry {
    let entry = Entry {
        id: new_id(),
        ts: now_ts(),
        from: from.to_string(),
        body: MsgBody::Text {
            text: text.to_string(),
        },
        pending: false,
    };
    let mut v = cat_lock();
    v.push(entry.clone());
    drop(v);
    save();
    entry
}

pub fn find(id: &str) -> Option<Entry> {
    cat_lock().iter().find(|e| e.id == id).cloned()
}

/// Remove an entry from the index by id (does not touch the physical file).
/// Returns the removed entry; the caller decides whether to delete the file on
/// disk.
pub fn remove(id: &str) -> Option<Entry> {
    let mut v = cat_lock();
    if let Some(pos) = v.iter().position(|e| e.id == id) {
        let e = v.remove(pos);
        drop(v);
        save();
        Some(e)
    } else {
        None
    }
}

/// Drain the whole index, persisting once. The caller owns the per-entry
/// aftermath (file deletes, mirror drops) with remove() semantics per entry.
pub fn take_all() -> Vec<Entry> {
    let mut v = cat_lock();
    let all: Vec<Entry> = v.drain(..).collect();
    drop(v);
    save();
    all
}

/// Re-insert records withheld from a destructive sweep (bin-refused files
/// whose bytes + poster were left untouched): single persist. Timeline order
/// is by ts at read time, so append order is free.
pub fn restore(mut items: Vec<Entry>) {
    if items.is_empty() {
        return;
    }
    let mut v = cat_lock();
    v.append(&mut items);
    drop(v);
    save();
}

/// Flip the poster flag after a sidecar lands (or is lost). Returns true when
/// the stored value actually changed, so the caller can skip a redundant save
/// and List push.
pub fn set_poster(id: &str, yes: bool) -> bool {
    let mut v = cat_lock();
    let Some(e) = v.iter_mut().find(|e| e.id == id) else {
        return false;
    };
    let Some(flag) = (match &mut e.body {
        MsgBody::File { poster, .. } => Some(poster),
        MsgBody::Text { .. } => None,
    }) else {
        return false;
    };
    if *flag == yes {
        return false;
    }
    *flag = yes;
    drop(v);
    save();
    true
}

/// Message list sorted by ts ascending (timeline order).
pub fn all_items() -> Vec<MsgItem> {
    let mut v = cat_lock();
    v.sort_by(|a, b| a.ts.cmp(&b.ts));
    v.iter().map(|e| e.to_item()).collect()
}
