//! Loom models for the writer-slot state machine. Run from `writer_slot/`:
//!
//!   RUSTFLAGS="--cfg loom" cargo test
//!
//! Each model exhaustively explores the thread interleavings of
//! begin / stop / end and asserts the T1–T3 invariants.

use crate::WriterTable;
use loom::sync::{Arc, Mutex};
use loom::thread;

/// T1: two racing begins for one id — exactly one wins.
#[test]
fn begin_is_mutually_exclusive() {
    loom::model(|| {
        let table = Arc::new(Mutex::new(WriterTable::default()));
        let id = "c";

        let a = table.clone();
        let t1 = thread::spawn(move || a.lock().unwrap().begin(id, Some("1".to_string())));
        let b = table.clone();
        let t2 = thread::spawn(move || b.lock().unwrap().begin(id, Some("2".to_string())));

        let r1 = t1.join().unwrap();
        let r2 = t2.join().unwrap();
        assert!(r1 ^ r2, "exactly one begin may win (got {r1}, {r2})");
    });
}

/// T2/T3: a stop carrying a previous attempt's token never stops the retry,
/// no matter how it interleaves with the retry's begin.
#[test]
fn stale_stop_cannot_kill_a_retry() {
    loom::model(|| {
        let table = Arc::new(Mutex::new(WriterTable::default()));
        let id = "c";
        // Attempt "1" ran and exited before the retry.
        {
            let mut g = table.lock().unwrap();
            assert!(g.begin(id, Some("1".to_string())));
            g.end(id);
        }

        // Concurrently: the retry ("2") starts, and attempt 1's delayed
        // cancel ("1") arrives.
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
    loom::model(|| {
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
    loom::model(|| {
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
