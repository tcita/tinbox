// Minimal file logger: writes to tinbox.log next to the exe.
// Release builds use windows_subsystem=windows with no console, so logs are
// written to disk to be inspectable.
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::Mutex;

fn log_path() -> PathBuf {
    let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("."));
    exe.parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .join("tinbox.log")
}

static F: Mutex<()> = Mutex::new(());

fn write_line(line: &str) {
    let line = format!(
        "[{}] {}\n",
        chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
        line
    );
    // Poison-safe: the mutex guards only the write sequence (no data, no
    // invariants), and logf runs inside the request-logging middleware — a
    // poisoned F would panic on every future logf call and kill every HTTP
    // request. See the stderr note below for the same hazard, avoided at the
    // source.
    let _g = F.lock().unwrap_or_else(|e| e.into_inner());
    rotate_if_large(line.as_bytes().len() as u64);
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(log_path()) {
        let _ = f.write_all(line.as_bytes());
    }
    // Ignore stderr failures: when launched from a console that later closes,
    // the inherited stderr pipe breaks. eprint! would panic here — while
    // holding the mutex — poisoning it and panicking every future logf call,
    // which kills every HTTP request in the logging middleware.
    let _ = io::stderr().write_all(line.as_bytes());
}

/// Plain informational line (the default: request lines, lifecycle events).
pub fn logf(msg: &str) {
    write_line(msg);
}

/// Warning: expected-but-notable (a port fell through, a phone dropped, a
/// request came from the wrong subnet).
pub fn logw(msg: &str) {
    write_line(&format!("[WARN] {msg}"));
}

/// Error: an operation failed and the user-visible path degraded.
pub fn loge(msg: &str) {
    write_line(&format!("[ERROR] {msg}"));
}

/// The log is diagnostic-only: the active file is capped at 1 MB with 3
/// generations (tinbox.log.1/.2/.3, ~4 MB total), so a long session stays
/// scannable without losing the startup lines (version/port/QR/token) that a
/// single 500 KB truncation would rotate away too fast. Runs under the write
/// lock with single-instance guarantee, so no cross-process race.
fn rotate_if_large(incoming: u64) {
    const MAX_BYTES: u64 = 1024 * 1024;
    const KEEP: u32 = 3;
    let path = log_path();
    let over = std::fs::metadata(&path)
        .map(|m| m.len().saturating_add(incoming) > MAX_BYTES)
        .unwrap_or(false);
    if !over {
        return;
    }
    let name = |i: u32| PathBuf::from(format!("{}.{}", path.display(), i));
    // Shift descending so .2 -> .3 cannot clobber a live .1; failures are
    // ignored except the last-resort truncate below that keeps the bound.
    let _ = std::fs::remove_file(name(KEEP));
    for i in (1..=KEEP).rev() {
        let dst = name(i);
        if i == 1 {
            let _ = std::fs::rename(&path, &dst);
        } else if name(i - 1).exists() {
            let _ = std::fs::rename(name(i - 1), &dst);
        }
    }
    // If the active file is still over budget (rename blocked, e.g. a tail
    // holding .1 open), truncate it so growth stays bounded.
    if std::fs::metadata(&path)
        .map(|m| m.len() > MAX_BYTES)
        .unwrap_or(false)
    {
        let _ = OpenOptions::new().write(true).truncate(true).open(&path);
    }
}
