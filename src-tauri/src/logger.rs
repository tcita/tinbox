// Minimal file logger: writes to tinbox.log next to the exe.
// Release builds use windows_subsystem=windows with no console, so logs are
// written to disk to be inspectable.
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

fn log_path() -> PathBuf {
    let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("."));
    exe.parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .join("tinbox.log")
}

static F: Mutex<()> = Mutex::new(());

/// Append one line to the log file and also print it to stderr (visible when a
/// debug console is attached).
pub fn logf(msg: &str) {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let line = format!("[{}] {}\n", secs, msg);
    let _g = F.lock().unwrap();
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(log_path()) {
        let _ = f.write_all(line.as_bytes());
    }
    eprint!("{}", line);
}
