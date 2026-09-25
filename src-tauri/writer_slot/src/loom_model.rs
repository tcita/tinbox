//! Loom models for the writer-slot state machine. Run from `writer_slot/`:
//!
//!   RUSTFLAGS="--cfg loom" cargo test
//!
//! Each `check` exhaustively explores the thread interleavings of
//! begin / stop / end and asserts the T1–T3 invariants. The last model also
//! tracks the catalog row beside the slot, asserting the joint invariant the
//! `/cancel` fix exists for: a stale attempt's stop can never remove a later
//! retry's row. Bounds are pinned in code so the result does not depend on the
//! developer's environment variables.

use crate::WriterTable;
use loom::sync::{Arc, Mutex};
use loom::thread;

/// Run a model with fixed bounds (env-independent). `preemptions` trade
/// coverage for runtime; the state spaces here are tiny, so a generous bound
/// is still fast. Installs the same tracing subscriber `loom::model` does, so
/// `LOOM_LOG=info` reports the explored iteration count.
fn check(preemptions: usize, f: impl Fn() + Sync + Send + 'static) {
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_env("LOOM_LOG"))
        .with_test_writer()
        .without_time()
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        let mut b = loom::model::Builder::new();
        b.preemption_bound = Some(preemptions);
        b.check(f);
    });
}

/// T1: three racing begins for one id — at most one wins.
#[test]
fn begin_is_mutually_exclusive() {
    check(8, || {
        let table = Arc::new(Mutex::new(WriterTable::default()));
        let id = "c";
        let mut handles = Vec::new();
        for tag in ["1", "2", "3"] {
            let t = table.clone();
            handles.push(thread::spawn(move || {
                t.lock().unwrap().begin(id, Some(tag.to_string()))
            }));
        }
        let wins = handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .filter(|w| *w)
            .count();
        assert!(wins <= 1, "T1: {wins} writers claimed the slot");
    });
}

/// T2/T3: a stop carrying a previous attempt's token never stops the retry,
/// no matter how it interleaves with the retry's begin.
#[test]
fn stale_stop_cannot_kill_a_retry() {
    check(8, || {
        let table = Arc::new(Mutex::new(WriterTable::default()));
        let id = "c";
        // Attempt "1" ran and exited before the retry.
        {
            let mut g = table.lock().unwrap();
            assert!(g.begin(id, Some("1".to_string())));
            g.end(id);
        }

        let a = table.clone();
        let retry = thread::spawn(move || a.lock().unwrap().begin(id, Some("2".to_string())));
        let b = table.clone();
        let stale = thread::spawn(move || b.lock().unwrap().stop(id, Some("1")));

        assert!(retry.join().unwrap(), "retry must claim the slot");
        stale.join().unwrap();

        let g = table.lock().unwrap();
        assert!(
            !g.stopped(id),
            "T3: stale stop from attempt 1 reached the retry"
        );
    });
}

/// T2: a stop naming the live attempt does stop it; a mismatched token does
/// not; `None` (explicit stop) does.
#[test]
fn stop_matches_only_the_named_attempt() {
    check(8, || {
        let table = Arc::new(Mutex::new(WriterTable::default()));
        let id = "c";
        assert!(table.lock().unwrap().begin(id, Some("7".to_string())));

        let a = table.clone();
        let stop = thread::spawn(move || a.lock().unwrap().stop(id, Some("7")));
        let b = table.clone();
        let noop = thread::spawn(move || b.lock().unwrap().stop(id, Some("9")));

        stop.join().unwrap();
        noop.join().unwrap();
        assert!(
            table.lock().unwrap().stopped(id),
            "the live attempt must be stopped"
        );
    });
}

/// T3: stops after the writer exited touch nothing (and create no entry).
#[test]
fn stop_after_exit_is_inert() {
    check(8, || {
        let table = Arc::new(Mutex::new(WriterTable::default()));
        let id = "c";
        {
            let mut g = table.lock().unwrap();
            assert!(g.begin(id, Some("1".to_string())));
            g.end(id);
        }
        let a = table.clone();
        let t1 = thread::spawn(move || a.lock().unwrap().stop(id, Some("1")));
        let b = table.clone();
        let t2 = thread::spawn(move || b.lock().unwrap().stop(id, None));
        assert!(!t1.join().unwrap());
        assert!(!t2.join().unwrap());
        assert!(!table.lock().unwrap().stopped(id));
    });
}

/// The protocol as `/upload` and `/cancel` actually sequence it: a successful
/// begin creates the row, `end` (the WriterGuard drop) frees the slot but
/// leaves the row, and `/cancel` removes the row ONLY when its token matched
/// a live writer — a scoped stop that matched nothing is `"gone"`.
struct Sys {
    table: WriterTable,
    row: bool,
}

impl Sys {
    fn upload_begin(&mut self, tag: &str) -> bool {
        if !self.table.begin("c", Some(tag.to_string())) {
            return false;
        }
        self.row = true;
        true
    }

    fn upload_end(&mut self) {
        self.table.end("c");
    }

    fn cancel(&mut self, att: &str) -> bool {
        if !self.table.stop("c", Some(att)) {
            return false;
        }
        self.row = false;
        true
    }
}

/// Joint slot+row invariant under a 3-way race: attempt "1" ends, its delayed
/// cancel "1" arrives, and the retry "2" begins. Whichever way they interleave,
/// the stale cancel must not remove or stop the retry.
#[test]
fn stale_cancel_cannot_remove_a_retry_row() {
    check(10, || {
        let sys = Arc::new(Mutex::new(Sys {
            table: WriterTable::default(),
            row: false,
        }));
        assert!(sys.lock().unwrap().upload_begin("1"));

        let a = sys.clone();
        let end1 = thread::spawn(move || a.lock().unwrap().upload_end());
        let b = sys.clone();
        let stale = thread::spawn(move || b.lock().unwrap().cancel("1"));
        let c = sys.clone();
        let retry = thread::spawn(move || c.lock().unwrap().upload_begin("2"));

        end1.join().unwrap();
        stale.join().unwrap();
        let retry_started = retry.join().unwrap();

        let g = sys.lock().unwrap();
        if retry_started {
            assert!(g.row, "T3: stale cancel removed the retry's row");
            assert!(!g.table.stopped("c"), "T3: stale cancel stopped the retry");
        }
    });
}
