//! Hermetic red-team harness: points the data root, inbox dir and catalog at a
//! per-test temp directory, and serializes all stateful tests (the catalog,
//! writers map and settings memo are process-wide globals; Rust runs tests
//! in threads). Pure-function tests need none of this.
//!
//! Usage: hold a `TestEnv` for the whole test body. On drop it drains the
//! catalog, removes the temp dirs and clears the overrides — panic-safe, so
//! a failing test cannot poison the next one or the real machine state.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

static SERIAL: OnceLock<Mutex<()>> = OnceLock::new();

fn serial() -> &'static Mutex<()> {
    SERIAL.get_or_init(|| Mutex::new(()))
}

pub(crate) struct TestEnv {
    _lock: std::sync::MutexGuard<'static, ()>,
    base: PathBuf,
    inbox_dir: PathBuf,
}

impl TestEnv {
    pub(crate) fn setup(name: &str) -> Self {
        let lock = serial().lock().unwrap_or_else(|e| e.into_inner());
        let base =
            std::env::temp_dir().join(format!("tinbox-redteam-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let data_dir = base.join("data");
        let inbox_dir = base.join("inbox");
        std::fs::create_dir_all(&data_dir).expect("redteam temp data dir");
        std::fs::create_dir_all(&inbox_dir).expect("redteam temp inbox dir");
        crate::logger::set_test_data_root(Some(data_dir));
        crate::settings::set_test_inbox_dir(Some(inbox_dir.clone()));
        // Starts from a cleared catalog (load clears first, then finds no
        // index in the temp dir).
        crate::catalog::load();
        assert!(
            crate::catalog::take_all().is_empty(),
            "redteam catalog not empty at setup"
        );
        Self {
            _lock: lock,
            base,
            inbox_dir,
        }
    }

    pub(crate) fn inbox(&self) -> &Path {
        &self.inbox_dir
    }

    /// Non-sentinel files currently in the temp inbox, sorted.
    pub(crate) fn inbox_files(&self) -> Vec<String> {
        let mut out: Vec<String> = std::fs::read_dir(&self.inbox_dir)
            .map(|rd| {
                rd.flatten()
                    .map(|e| e.file_name().to_string_lossy().to_string())
                    .collect()
            })
            .unwrap_or_default();
        out.sort();
        out
    }

    /// Sentinel (`pending__`) files currently in the temp inbox, sorted.
    pub(crate) fn sentinel_files(&self) -> Vec<String> {
        self.inbox_files()
            .into_iter()
            .filter(|n| n.starts_with("pending__"))
            .collect()
    }
}

impl Drop for TestEnv {
    fn drop(&mut self) {
        let _ = crate::catalog::take_all();
        crate::settings::set_test_inbox_dir(None);
        crate::settings::clear_test_fallback();
        crate::logger::set_test_data_root(None);
        let _ = std::fs::remove_dir_all(&self.base);
    }
}
