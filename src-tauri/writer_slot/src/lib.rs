//! Upload writer-slot state machine.
//!
//! Extracted from the app so the `loom` concurrency model can exhaustively
//! explore its transitions without dragging the whole dependency graph
//! (tauri, axum, tokio, windows-rs) under `--cfg loom` — which breaks those
//! crates. The app wraps this table in a std Mutex; the model wraps the same
//! type in a loom Mutex.
//!
//! Invariants (T1–T3 of the fault-handling review):
//!   T1  at most one writer per id — `begin` is mutually exclusive;
//!   T2  a `stop` only affects the attempt whose token it names;
//!   T3  a `stop` for a finished attempt cannot reach a later retry.

use std::collections::HashMap;

#[derive(Default)]
struct Writer {
    /// Attempt token from `?att=`; `None` for writers started without one
    /// (hand-rolled clients). Compared verbatim against the stop's token.
    tag: Option<String>,
    stopped: bool,
}

/// The writer-slot state machine, independent of the lock that guards it.
#[derive(Default)]
pub struct WriterTable {
    map: HashMap<String, Writer>,
}

impl WriterTable {
    /// Register the writer for `id`. `false` if a writer is already present —
    /// the catalog row is removed before the writer notices a cancel, so a
    /// retry in that window must not open a second handle on the same file.
    pub fn begin(&mut self, id: &str, tag: Option<String>) -> bool {
        if self.map.contains_key(id) {
            return false;
        }
        self.map.insert(
            id.to_string(),
            Writer {
                tag,
                stopped: false,
            },
        );
        true
    }

    /// Signal the live writer for `id`, if one exists. `att=None`
    /// (explicit/hand-rolled stop) matches the live writer; `att=Some` only
    /// matches a writer holding the same token, so a delayed stop from a
    /// previous attempt cannot kill a retry. Missing/finished is a no-op.
    pub fn stop(&mut self, id: &str, att: Option<&str>) -> bool {
        let Some(e) = self.map.get_mut(id) else {
            return false;
        };
        if att.is_some() && e.tag.as_deref() != att {
            return false;
        }
        e.stopped = true;
        true
    }

    pub fn stopped(&self, id: &str) -> bool {
        self.map.get(id).is_some_and(|e| e.stopped)
    }

    pub fn end(&mut self, id: &str) {
        self.map.remove(id);
    }
}

#[cfg(all(test, loom))]
mod loom_model;
