// Liveness: the presence evidence counter (open /events streams), the
// last-paired-activity diagnostic stamp, the shared monotonic clock, and the
// one-second background monitor that announces device / firewall / prune
// transitions over the transfer page's push channel.

use crate::logger::{logf, logw};
use crate::server::{current_url, notifier, refresh_url, PushEvent};
use crate::transfer::dl_lock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::Duration;
/// Monotonic seconds since start of the most recent request from a **paired**
/// LAN device — stamped only for responses the pairing middleware let
/// through. Presence no longer reads it (see lan_peer_connected): it survives
/// only as the `req=` diagnostic in presence_evidence(). Keeping it
/// paired-only still matters for that line, so an unpaired page's 403
/// refetches cannot look like activity.
pub(crate) static LAST_PAIRED_ACT: AtomicU64 = AtomicU64::new(0);

/// A LAN device is online exactly while it holds an open /events stream. The
/// evidence writer is events()/PresenceGuard -> LAN_EVENTS_OPEN (/events
/// itself is behind the pairing gate). log_requests still stamps
/// LAST_PAIRED_ACT for every response the pairing middleware did not refuse,
/// but that is diagnostics now, not evidence. Transfer bytes are not presence
/// evidence either — byte stamps serve only the ledger prune.


/// Monotonic seconds since process start, offset to begin at 1 so that 0 can
/// serve as the permanent "never" sentinel for stamped values (LAST_PAIRED_ACT,
/// DlProg::last_ts). With a 0-based clock, `now - 0` = uptime, which made a
/// freshly started process read as "a device was seen moments ago":
/// a phantom `device present` before any phone ever connected (historically this also faked inbound-proof for the
/// firewall veto; that veto is removed — the flag is worker-verdict only). Every
/// liveness stamp in the pipeline is only ever compared against a later
/// `now_mono()`, so wall-clock jumps (NTP correction, manual clock change)
/// cannot freeze stall detection, pruning or the presence diagnostics: a backward step
/// would otherwise make `now - stamp` saturate to 0 and hold every dead
/// transfer "alive" for the whole step duration.
pub(crate) fn now_mono() -> u64 {
    static T0: OnceLock<std::time::Instant> = OnceLock::new();
    T0.get_or_init(std::time::Instant::now).elapsed().as_secs() + 1
}

/// ── LIVENESS — the four-mechanism pipeline that keeps both ends honest ────
/// Every timer in the app belongs to exactly one of these; do not add more.
///
///   keep-alive    SSE_HEARTBEAT_SECS — the server emits bytes on an idle
///                 /events stream: NAT/AP cannot reap the socket, and the
///                 client's watchdog measures server death by its silence.
///   presence      a LAN device is online exactly while it holds an open
///                 /events stream. The one evidence writer is
///                 `events`/PresenceGuard -> LAN_EVENTS_OPEN (itself behind
///                 the pairing gate). `log_requests` -> LAST_PAIRED_ACT is
///                 kept for the diagnostic line only: it does not feed the
///                 bit, so an unpaired 403 refetch cannot fake presence. The
///                 monitor is the single announcer of transitions.
///                 Consumers are the arrival toast and the transition logs —
///                 no UI light. Byte-flow evidence is
///                 deliberately not folded in: byte stamps serve only the
///                 ledger prune, and the firewall flag is worker-verdict
///                 only.
///                 KNOWN LIMITS (deliberate): presence is OPTIMISTIC — a phone
///                 that dies without a FIN keeps its stream "open" (and thus
///                 counts online) until TCP gives up, minutes later; and it is
///                 a GLOBAL aggregate, not per-device, so with several phones
///                 one active device covers the others. Fine because nothing
///                 destructive or user-facing depends on the bit.
///   death         a transfer ends only through its own stream: an upload dies
///                 via the writer's per-chunk silence timeout (or a stop
///                 flag), a pull dies when hyper drops the response body —
///                 StreamCutGuard reaps its counter and writes the outcome to
///                 the log; a hanging entry is reaped by the monitor's prune.
///   reconcile     PushEvent::Resync — the one catch-up event for "you may
///                 have missed pushes"; its full trigger list lives on that
///                 variant's doc. Clients also reconcile on (re)connect and
///                 on visibilitychange, each pass pulling /list and
///                 /dl-status once; there are no polling timers.
///
/// Ownership follows the transfer: progress rings mirror on the receiving PC,
/// stopping lives on the sending phone (its card ✕ aborts locally, then
/// /cancel clears the server row); pulls are the phone's business — the
/// browser's own download UI. The sender gets only an event log. No
/// cross-device transfer state is mirrored anywhere, so there is nothing to
/// sync.
///
/// Desk-range profile: both devices are in hand and sessions are short, so
/// the numbers below are tight.
pub(crate) const SSE_HEARTBEAT_SECS: u64 = 1;

/// How many /events streams are currently open from a non-loopback peer. A
/// device is "online" exactly while it holds one open — its page is alive and
/// reachable for pushes. No periodic ping: a live page keeps its EventSource
/// open (the server's keepalives keep it warm), and after any drop it
/// reconnects, reopening a stream and flipping presence back on. There is no
/// debounce, so a quick reconnect can read as a drop for one tick; accepted,
/// because the bit drives nothing user-facing (see lan_peer_connected).
pub(crate) static LAN_EVENTS_OPEN: AtomicU64 = AtomicU64::new(0);

/// Whether a LAN device is present: it holds an open /events stream. "The
/// phone can reach the server and is holding the push channel" is the question
/// this answers. Byte flow is not evidence: after the firewall's traffic veto
/// was removed, nothing consumes byte stamps beyond the ledger prune. After
/// the first arrival toast, nothing consumes this bit behaviorally except the
/// transition logs. See the KNOWN LIMITS in the LIVENESS block: optimistic
/// under no-FIN death, and global rather than per-device.
pub(crate) fn lan_peer_connected() -> bool {
    LAN_EVENTS_OPEN.load(Ordering::Relaxed) > 0
}

/// One-line snapshot for the monitor's transition log: how many /events
/// streams are open, how long ago the last paired request arrived, and how
/// long ago an in-flight transfer last wrote a byte. Only `streams` feeds
/// lan_peer_connected(); `req` and `xfer` are pure diagnostic context (the
/// paired stamp and byte flow are consumed by nothing but this line and the
/// ledger prune). "never" marks a still-0 stamp (see now_mono's sentinel);
/// xfer only tracks entries with sent < total.
fn presence_evidence() -> String {
    let now = now_mono();
    let streams = LAN_EVENTS_OPEN.load(Ordering::Relaxed);
    let req = match LAST_PAIRED_ACT.load(Ordering::Relaxed) {
        0 => "never".to_string(),
        t => format!("{}s ago", now.saturating_sub(t)),
    };
    let xfer = dl_lock()
        .values()
        .filter(|e| e.sent < e.total && e.last_ts != 0)
        .map(|e| e.last_ts)
        .max()
        .map_or("never".to_string(), |t| format!("{}s ago", now.saturating_sub(t)));
    format!("streams={streams} req={req} xfer={xfer}")
}

/// Background monitor: reports the live device-presence bit, the firewall
/// repair flag and stale download entries, pushing /events on every change so
/// the frontend never polls. Runs every 1s; need_repair() already throttles
/// its powershell rule check.
///
/// Presence is a single writer here. The monitor announces both ARRIVAL (a LAN
/// peer holds an open /events stream) and the silent DEPARTURE (a closed
/// stream has no event of its own); events() only maintains the stream count.
/// There is deliberately no debounce counter: `online` is just
/// `lan_peer_connected()` sampled now, so a stream blip can read as a drop for
/// one tick. That is accepted — nothing user-facing consumes the bit (see the
/// LIVENESS block), so honesty beats a state machine.
pub(crate) async fn monitor_loop() {
    let mut prev_online: Option<bool> = None;
    let mut prev_repair: Option<bool> = None;
    let mut prev_url: Option<String> = None;
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
        // Report transitions only, so a cold start with no device stays quiet
        // (prev_online starts None and the first false->false match announces
        // nothing) instead of manufacturing a spurious event.
        let online = lan_peer_connected();
        if prev_online != Some(online) {
            let was_online = prev_online.unwrap_or(false);
            prev_online = Some(online);
            if was_online != online {
                let url = current_url();
                let evidence = presence_evidence();
                if online {
                    logf(&format!("device present: LAN device reachable ({evidence})"));
                    let _ = notifier().send(PushEvent::Info { mobile_connected: true, url });
                } else {
                    logf(&format!("device disconnected: no LAN device present ({evidence})"));
                    let _ = notifier().send(PushEvent::Info { mobile_connected: false, url });
                }
            }
        }
        // Network change: the advertised pairing URL's LAN IP moved (WiFi <->
        // hotspot, cable <-> WiFi, a new subnet), which invalidates the QR the
        // phone already scanned. The server cannot reach a phone now on another
        // network, so the only useful signal is to the PC: re-push `info` with
        // the new url so the page can flag its connect button and tell the user
        // to rescan. Sampled every tick: once warm, refresh_url() is just the
        // adapter enumeration (the gateway probes and the PowerShell adapter
        // query are cached 30-60s), and the 1s beat is the difference between
        // "the new QR is already rendered when you open it" and "you opened it
        // into a blank box".
        let url = refresh_url();
        let changed = prev_url.as_deref().is_some_and(|p| p != url);
        if changed {
            if crate::server::lan_usable() {
                logf(&format!("network changed: pairing URL is now {url}"));
            } else {
                logw(&format!(
                    "network changed: no LAN address available; pairing URL {url} is unusable (QR withheld)"
                ));
            }
            let _ = notifier().send(PushEvent::Info {
                mobile_connected: online,
                url: url.clone(),
            });
        }
        // Pre-render on the first sample and on every change, so the QR the user
        // opens next is already an in-memory PNG (netinfo::refresh_qr) instead
        // of a request that must probe the new gateway first.
        if changed || prev_url.is_none() {
            crate::netinfo::refresh_qr();
        }
        prev_url = Some(url);
        // Firewall repair flag transitions.
        let repair = crate::firewall::need_repair();
        if prev_repair != Some(repair) {
            prev_repair = Some(repair);
            let _ = notifier().send(PushEvent::Fw(repair));
        }
        // Prune transfer counters on pure time windows: finished ones after 15s
        // (a lingering completion would keep reappearing in /dl-status), and
        // in-flight ones after 5s of silence — same number as the upload
        // silence timeout, different kind of timeout: this one judges the
        // LEDGER only, never the task. Silence means two things here — a dead
        // pull (its socket write can hang past any timeout, so the entry dies
        // here rather than through the stream) and a legitimate pause — and
        // both are reaped alike; the false alarm is accepted because a
        // pruned-but-alive stream rebuilds its counter on its next chunk (see
        // the chunk loop in serve), so a paused-then-resumed pull goes: pruned
        // here with this log line, rebuilt below with that one — hence the
        // line says "stalled", not "dead". Upload entries whose writer already
        // failed were removed by the writer itself. Broadcast `resync` when
        // anything drops so clients reconcile their upload rings back to idle
        // (a silent prune would otherwise leave a ring stuck).
        let now = now_mono();
        {
            let mut map = dl_lock();
            let before = map.len();
            map.retain(|id, e| {
                let stale = now.saturating_sub(e.last_ts);
                let keep = if e.sent >= e.total { stale <= 15 } else { stale <= 5 };
                if !keep && e.sent < e.total {
                    // Only the incomplete reap gets a line: the finished one is
                    // lifecycle noise. Say "stalled pull" so it reads next to
                    // started/done/cut in the same vocabulary.
                    logw(&format!(
                        "prune stalled pull {id}: {}/{} bytes (5s silent)",
                        e.sent, e.total
                    ));
                }
                keep
            });
            if map.len() < before {
                let _ = notifier().send(PushEvent::Resync);
            }
        }
    }
}
