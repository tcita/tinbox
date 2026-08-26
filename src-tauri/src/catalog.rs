// Catalog 索引层:统一管理"消息条目"(文件与文本)。
//   文件消息:复用 Source(Local=PC 本地引用零拷贝 / Remote=手机推来物化到 inbox)。
//   文本消息:内容直接内联,无 source。
// 每条消息带 from("pc"/"phone")与 ts,前端按时间线渲染、左右气泡区分发送方。
//
// 状态全局共享(`CATALOG`),供 axum handler(server 线程 runtime)与
// Tauri 命令(主 runtime)共用同一份。条目量小,临界区短,用 std Mutex + 全量持久化。
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
    /// 不论来源,实际要读/写的磁盘路径。
    pub fn path(&self) -> &str {
        match self {
            Source::Local { path } => path,
            Source::Remote { path } => path,
        }
    }
    pub fn is_remote(&self) -> bool {
        matches!(self, Source::Remote { .. })
    }
    /// 给前端的来源标签:"local" / "remote"。
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

/// 给前端的列表项;按 kind 携带不同字段,前端按 kind 渲染。
#[derive(Serialize)]
pub struct MsgItem {
    pub id: String,
    pub ts: String,
    pub from: String,
    pub kind: String, // "file" | "text"
    // file 时有效:
    pub name: String,
    pub size: u64,
    pub source_kind: String, // "local" | "remote";text 时为空
    // text 时有效:
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

/// 零依赖 id:纳秒 + 自增计数,避免同毫秒碰撞。
pub fn new_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let c = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{nanos}-{c}")
}

/// 当前秒级时间戳字符串(消息发送时刻)。
pub fn now_ts() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs().to_string())
        .unwrap_or_default()
}

/// exe 所在目录:便携版基准(无论从哪启动,数据都落同一处)。
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

/// 旧的 shared 目录(仅用于一次性迁移)。
pub fn legacy_shared_dir() -> PathBuf {
    exe_parent().join("shared")
}

static CATALOG: OnceLock<Arc<Mutex<Vec<Entry>>>> = OnceLock::new();

pub fn catalog() -> &'static Arc<Mutex<Vec<Entry>>> {
    CATALOG.get_or_init(|| Arc::new(Mutex::new(Vec::new())))
}

/// 旧格式条目(顶层 source/size/name/mtime,无 body/from)→ 新格式 Entry。
/// Local→from="pc",Remote→from="phone";ts 取旧 mtime。
fn migrate_old_entry(v: &serde_json::Value) -> Option<Entry> {
    // 新格式有 body 字段,旧格式没有。有 body 的直接走正常反序列化。
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
    if let Ok(txt) = std::fs::read_to_string(catalog_path()) {
        if let Ok(arr) = serde_json::from_str::<Vec<serde_json::Value>>(&txt) {
            for item in arr {
                if let Some(e) = migrate_old_entry(&item) {
                    v.push(e);
                }
            }
        }
    }
}

pub fn save() {
    let v = catalog().lock().unwrap();
    let json = serde_json::to_string_pretty(&*v).unwrap_or_default();
    let _ = std::fs::write(catalog_path(), json);
}

/// 递归收集目录下所有文件到 out。
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

/// 把若干 PC 本地路径登记为 from="pc" 的文件消息(零拷贝)。返回新增条数。
/// 若传入目录,递归收集其下所有文件。
pub fn add_local(paths: Vec<PathBuf>) -> usize {
    if paths.is_empty() {
        return 0;
    }
    // 展开目录为文件列表。
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

/// 把一个已写入 inbox 的文件登记为 from="phone" 的文件消息。
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

/// 登记一条文本消息(from 由调用方按来源 IP 判定后传入)。
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

/// 按 id 从索引移除(不碰物理文件)。返回被移除条目,由调用方决定是否删盘上文件。
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

/// 按 ts 升序的消息列表(时间线)。
pub fn all_items() -> Vec<MsgItem> {
    let mut v = catalog().lock().unwrap();
    v.sort_by(|a, b| a.ts.cmp(&b.ts));
    v.iter().map(|e| e.to_item()).collect()
}
