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

/// Append one line to the log file and also print it to stderr (visible when a
/// debug console is attached). Timestamps are local wall-clock time so entries
/// can be correlated with what the user did on the phone/PC.
pub fn logf(msg: &str) {
    let line = format!(
        "[{}] {}\n",
        chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
        msg
    );
    let _g = F.lock().unwrap();
    rotate_if_large();
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(log_path()) {
        let _ = f.write_all(line.as_bytes());
    }
    // Ignore stderr failures: when launched from a console that later closes,
    // the inherited stderr pipe breaks. eprint! would panic here — while
    // holding the mutex — poisoning it and panicking every future logf call,
    // which kills every HTTP request in the logging middleware.
    let _ = io::stderr().write_all(line.as_bytes());
}

/// The log is diagnostic-only: once it exceeds 8 MB, rename it to .old so the
/// active file stays small and scannable. Long-running instances would
/// otherwise grow the file without bound.
fn rotate_if_large() {
    const MAX_BYTES: u64 = 8 * 1024 * 1024;
    let path = log_path();
    if let Ok(m) = std::fs::metadata(&path) {
        if m.len() > MAX_BYTES {
            let old = path.with_extension("log.old");
            let _ = std::fs::rename(&path, &old);
        }
    }
}
