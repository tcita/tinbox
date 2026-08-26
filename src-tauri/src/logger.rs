// 极简文件日志:写到 exe 旁边的 tinbox.log。
// release 构建 windows_subsystem=windows 无控制台,所以日志落盘才能看到。
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

/// 把一行追加到日志文件,同时打到 stderr(debug 有控制台时可见)。
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
