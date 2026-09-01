// Catalog index layer: uniformly manages "message entries" (files and text).
//   File messages: reuse Source (Local = zero-copy reference to a PC-local
//     file / Remote = pushed from the phone, materialized into inbox).
//   Text messages: content inlined directly, no source.
// Each message carries from("pc"/"phone") and ts; the frontend renders them
// on a timeline with left/right bubbles per sender.
//
// State is shared globally (`CATALOG`) so axum handlers (server thread
// runtime) and Tauri commands (main runtime) use the same instance. The entry
// count is small and critical sections are short, so std Mutex + full
// persistence is enough.
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Serialize, Deserialize, Clone)]
#[serde(tag = "type")]
pub enum Source {
    Local { path: String },
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
    File { source: Source, size: u64, name: String },
    Text { text: String },
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Entry {
    pub id: String,
    pub ts: String,
    pub from: String, // "pc" | "phone"
    pub body: MsgBody,
}

/// List item for the frontend; carries different fields per kind, which the
/// frontend renders according to kind.
#[derive(Serialize)]
pub struct MsgItem {
    pub id: String,
    pub ts: String,
    pub from: String,
    pub kind: String, // "file" | "text"
    // valid for file:
    pub name: String,
    pub size: u64,
    pub source_kind: String, // "local" | "remote"; empty for text
    // valid for text:
    pub text: String,
}

impl Entry {
    pub fn to_item(&self) -> MsgItem {
        match &self.body {
            MsgBody::File { source, size, name } => MsgItem {
                id: self.id.clone(),
                ts: self.ts.clone(),
                from: self.from.clone(),
                kind: "file".to_string(),
                name: name.clone(),
                size: *size,
                source_kind: source.kind_str().to_string(),
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

/// Directory of the exe: portable base (data always lands in the same place,
/// no matter where the app is launched from).
fn exe_parent() -> PathBuf {
    let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("."));
    exe.parent().unwrap_or_else(|| Path::new(".")).to_path_buf()
}

pub fn inbox_dir() -> PathBuf {
    exe_parent().join("inbox")
}

pub fn catalog_path() -> PathBuf {
    exe_parent().join("catalog.json")
}

/// Legacy shared directory (only used for a one-time migration).
pub fn legacy_shared_dir() -> PathBuf {
    exe_parent().join("shared")
}

static CATALOG: OnceLock<Arc<Mutex<Vec<Entry>>>> = OnceLock::new();

pub fn catalog() -> &'static Arc<Mutex<Vec<Entry>>> {
    CATALOG.get_or_init(|| Arc::new(Mutex::new(Vec::new())))
}

/// Convert a legacy entry (top-level source/size/name/mtime, no body/from) to
/// a new-format Entry. Local -> from="pc", Remote -> from="phone"; ts takes the
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
    let from = if source.is_remote() { "phone" } else { "pc" }.to_string();
    Some(Entry {
        id,
        ts,
        from,
        body: MsgBody::File { source, size, name },
    })
}

pub fn load() {
    let mut v = catalog().lock().unwrap();
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
            Err(e) => crate::logger::loge(&format!(
                "catalog: corrupt index {}: {}",
                catalog_path().display(),
                e
            )),
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
    let v = catalog().lock().unwrap();
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

/// Register several PC-local paths as from="pc" file messages (zero-copy).
/// Returns the number of newly added entries. If a directory is passed in, all
/// files under it are collected recursively.
pub fn add_local(paths: Vec<PathBuf>) -> usize {
    if paths.is_empty() {
        return 0;
    }
    // Expand directories into a flat file list.
    let mut all = Vec::new();
    for p in paths {
        if p.is_dir() {
            collect_files(&p, &mut all);
        } else {
            all.push(p);
        }
    }
    if all.is_empty() {
        return 0;
    }
    let mut v = catalog().lock().unwrap();
    let mut added = 0;
    for p in all {
        let Ok(meta) = std::fs::metadata(&p) else { continue };
        if !meta.is_file() {
            continue;
        }
        let name = p
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unnamed")
            .to_string();
        v.push(Entry {
            id: new_id(),
            ts: now_ts(),
            from: "pc".to_string(),
            body: MsgBody::File {
                source: Source::Local {
                    path: p.to_string_lossy().to_string(),
                },
                size: meta.len(),
                name,
            },
        });
        added += 1;
    }
    drop(v);
    if added > 0 {
        save();
    }
    added
}

/// Register a file already written to inbox as a from="phone" file message.
pub fn add_remote(id: &str, inbox_path: &Path, display_name: &str) -> Entry {
    let size = std::fs::metadata(inbox_path).map(|m| m.len()).unwrap_or(0);
    let entry = Entry {
        id: id.to_string(),
        ts: now_ts(),
        from: "phone".to_string(),
        body: MsgBody::File {
            source: Source::Remote {
                path: inbox_path.to_string_lossy().to_string(),
            },
            size,
            name: display_name.to_string(),
        },
    };
    let mut v = catalog().lock().unwrap();
    v.push(entry.clone());
    drop(v);
    save();
    entry
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
    };
    let mut v = catalog().lock().unwrap();
    v.push(entry.clone());
    drop(v);
    save();
    entry
}

pub fn find(id: &str) -> Option<Entry> {
    catalog().lock().unwrap().iter().find(|e| e.id == id).cloned()
}

/// Remove an entry from the index by id (does not touch the physical file).
/// Returns the removed entry; the caller decides whether to delete the file on
/// disk.
pub fn remove(id: &str) -> Option<Entry> {
    let mut v = catalog().lock().unwrap();
    if let Some(pos) = v.iter().position(|e| e.id == id) {
        let e = v.remove(pos);
        drop(v);
        save();
        Some(e)
    } else {
        None
    }
}

/// Message list sorted by ts ascending (timeline order).
pub fn all_items() -> Vec<MsgItem> {
    let mut v = catalog().lock().unwrap();
    v.sort_by(|a, b| a.ts.cmp(&b.ts));
    v.iter().map(|e| e.to_item()).collect()
}
