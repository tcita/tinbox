// Liveness: the presence evidence counters (open /events streams, last paired
// activity), the shared monotonic clock, and the one-second background monitor
// that announces device / firewall / prune transitions over the transfer
// page's push channel.

use crate::logger::{logf, logw};
use crate::server::{current_url, notifier, PushEvent};
use crate::transfer::dl_lock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::Duration;
/// Monotonic seconds-since-start of the most recent request from a non-local
/// (phone) device; 0 means no LAN request has ever arrived. The firewall
/// module reads it as positive proof that inbound traffic reaches this
/// machine. The PC's own requests go over loopback and never update it, so
/// the PC never counts itself.
pub(crate) static LAST_PHONE_ACT: AtomicU64 = AtomicU64::new(0);

/// Monotonic seconds since start of the most recent request from a **paired**
/// LAN device — same traffic stream as LAST_PHONE_ACT, minus what the pairing
/// gate refused. Presence (the QR gate latch, the device transitions the
/// monitor announces) must mean "a paired device is alive", so an expired or
/// never-paired web page — which gets 403s for everything — cannot lift the
/// PC's gate into "connected" by merely refetching. Transit evidence reaches
/// this stamp only through log_requests and the presence guard after the
/// pairing middleware has let the request through.
pub(crate) static LAST_PAIRED_ACT: AtomicU64 = AtomicU64::new(0);

/// A LAN device is online while it holds an open /events stream or was active
/// recently. Evidence writers (the only three): events()/PresenceGuard ->
/// LAN_EVENTS_OPEN (paired only: /events itself is behind the gate), transfer
/// chunk writers -> DlProg::last_ts (uploads need a paired cookie). Requests
/// arrive via log_requests, which stamps LAST_PAIRED_ACT for every response
/// the pairing middleware did not refuse.


/// Monotonic seconds since process start, offset to begin at 1 so that 0 can
/// serve as the permanent "never" sentinel for stamped values (LAST_PHONE_ACT,
/// DlProg::last_ts). With a 0-based clock, `now - 0` = uptime, which made a
/// freshly started process read as "a device was seen PRESENCE_ACT_SECS ago":
/// a phantom `device present` that latched the PC scan gate away before any
/// phone ever connected, and 30s of fake inbound-proof for the firewall. Every
/// liveness stamp in the pipeline is only ever compared against a later
/// `now_mono()`, so wall-clock jumps (NTP correction, manual clock change)
/// cannot freeze stall detection, pruning or presence either: a backward step
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
///   presence      PRESENCE_ACT_SECS — a LAN device is online while it holds
///                 an open /events stream or was active recently. Evidence
///                 writers (the only three): `log_requests` ->
///                 LAST_PAIRED_ACT (paired requests only — the pairing gate
///                 marks its refusals, and unpaired 403 traffic must never
///                 count as "device present", or an expired tab could lift the
///                 PC scan gate), `events`/PresenceGuard -> LAN_EVENTS_OPEN
///                 (itself behind the pairing gate), transfer chunk writers ->
///                 DlProg::last_ts (via touch_entry; uploads need a paired
///                 cookie, so this is paired by construction). The monitor
///                 is the single announcer of transitions.
///                 Consumers are the PC scan gate's first-connect latch, the
///                 firewall's inbound-proof, and the logs — no UI light.
///                 KNOWN LIMITS (deliberate): presence is OPTIMISTIC — a phone
///                 that dies without a FIN keeps its stream "open" (and thus
///                 counts online) until TCP gives up, minutes later; and it is
///                 a GLOBAL aggregate, not per-device, so with several phones
///                 one active device covers the others. Fine because nothing
///                 destructive or user-facing depends on the bit.
///   death         a transfer ends only through its own stream: an upload dies
///                 via the writer's per-chunk silence timeout (or a refusal
///                 flag), a pull dies when hyper drops the response body —
///                 StreamCutGuard reaps its counter and writes the outcome to
///                 the log; a hanging entry is reaped by the monitor's prune.
///   reconcile     PushEvent::Resync — the one catch-up event for "you may
///                 have missed pushes"; its full trigger list lives on that
///                 variant's doc. Clients also reconcile on (re)connect and
///                 on visibilitychange, each pass pulling /list and
///                 /dl-status once; there are no polling timers.
///
/// Ownership follows the receiver: rings and cancel live on the device that
/// receives a transfer (the PC for pushes — its refuse is /cancel; the phone
/// for pulls — the browser's own download UI), and the sender gets only an
/// event log. No cross-device transfer state is mirrored anywhere, so there
/// is nothing to sync.
///
/// Desk-range profile: both devices are in hand and sessions are short, so
/// the numbers below are tight. One floor to respect: the presence window
/// must stay above the EventSource reconnect delay (retry, 1s, set on every
/// replayed event in events()) or a stream blip flaps the presence bit.
pub(crate) const SSE_HEARTBEAT_SECS: u64 = 1;

/// [LIVENESS/presence] Seconds of LAN silence (no request at all) before a
/// device that holds no /events stream is treated as gone. A download or page
/// load counts as proof of presence too — "the phone can reach the server" is
/// what presence evidence means, not just "its /events stream is open". Must
/// stay above the SSE retry delay (see the LIVENESS block) so a blip cannot
/// flap.
const PRESENCE_ACT_SECS: u64 = 3;

/// Whether a non-loopback (LAN) device has made a request within the last
/// `secs` seconds. This is positive proof that inbound traffic is not blocked:
/// rule inspection can be wrong or unavailable, but packets arriving are
/// packets arriving. The firewall module uses it as the ground truth to clear
/// the repair flag.
pub(crate) fn lan_seen_recently(secs: u64) -> bool {
    let last = LAST_PHONE_ACT.load(Ordering::Relaxed);
    // 0 = "never" sentinel: without this guard, `now - 0` = uptime, which read
    // as recent activity for the first `secs` of every process start.
    last != 0 && now_mono().saturating_sub(last) < secs
}

/// How many /events streams are currently open from a non-loopback peer. A
/// device is "online" exactly while it holds one open — its page is alive and
/// reachable for pushes. No periodic ping: a live page keeps its EventSource
/// open (the server's keepalives keep it warm), and after any drop it
/// reconnects, reopening a stream and flipping presence back on. The monitor
/// debounces the count so a quick reconnect never reads as a drop.
pub(crate) static LAN_EVENTS_OPEN: AtomicU64 = AtomicU64::new(0);

/// Whether a LAN device is present: it either holds an open /events stream, or
/// is actively reaching this machine (a request in the last few seconds, or a
/// transfer whose bytes are still flowing — e.g. a native download running even
/// while its page's /events is down). "The phone can reach the server" is the
/// question, so any of those counts. See the KNOWN LIMITS in the LIVENESS
/// block: optimistic under no-FIN death, and global rather than per-device.
pub(crate) fn lan_peer_connected() -> bool {
    LAN_EVENTS_OPEN.load(Ordering::Relaxed) > 0
        || lan_paired_recently(PRESENCE_ACT_SECS)
        || transfer_active_recently(PRESENCE_ACT_SECS)
}

/// Recent activity from a PAIRED LAN device: identical shape to
/// lan_seen_recently, but reading LAST_PAIRED_ACT. This is the stamp presence
/// and the PC gate latch run on; unpaired 403 traffic must not lift the gate.
fn lan_paired_recently(secs: u64) -> bool {
    let last = LAST_PAIRED_ACT.load(Ordering::Relaxed);
    last != 0 && now_mono().saturating_sub(last) < secs
}

/// Any in-flight download whose streams pushed bytes within the last `secs`
/// seconds: a transfer can hold its Range streams open with no new HTTP request
/// arriving (which lan_seen_recently would miss), so the firewall treats
/// flowing bytes as positive evidence inbound is open.
pub(crate) fn transfer_active_recently(secs: u64) -> bool {
    let now = now_mono();
    let map = dl_lock();
    map.iter()
        .any(|(_, e)| {
            e.sent < e.total
                && e.last_ts != 0  // 0 = never touched (defensive; creators always touch)
                && now.saturating_sub(e.last_ts) < secs
        })
}

/// One-line snapshot of the three presence evidence sources, for the monitor's
/// transition log: how many /events streams are open, how long ago the last
/// LAN request arrived, how long ago an in-flight transfer last wrote a byte.
/// "never" marks a still-0 stamp (see now_mono's sentinel). Mirrors what
/// lan_peer_connected() actually reads — completed transfers are not evidence,
/// so xfer only tracks entries with sent < total.
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

/// Log every incoming HTTP request and its source IP (key diagnostic: if a
/// phone request never shows up here, the request never reached this machine —
/// firewall, wrong IP, AP isolation, or the phone is not on this network at
/// all). Responses with status >= 400 get a second line, since a request that
/// arrives and then fails server-side is a different failure mode than one


/// Background monitor: reports the live device-presence bit, the firewall
/// repair flag and stale download entries, pushing /events on every change so
/// the frontend never polls. Runs every 1s; need_repair() already throttles
/// its powershell rule check.
///
/// Presence is a single writer here. The monitor announces both ARRIVAL (a LAN
/// peer holds an open /events stream, or is downloading/requesting without one)
/// and the silent DEPARTURE (a closed stream has no event of its own); events()
/// only maintains the stream count. There is deliberately no debounce counter:
/// `online` is just `lan_peer_connected()` sampled now, and the activity
/// windows inside it (PRESENCE_ACT_SECS) already provide the hysteresis that
/// keeps a phone whose stream briefly reconnects from flipping the presence
/// bit. Presence drives no user-facing light (see the LIVENESS block), so a
/// genuinely absent device may read "gone" within one tick — honesty beats a
/// state machine.
pub(crate) async fn monitor_loop() {
    let mut prev_online: Option<bool> = None;
    let mut prev_repair: Option<bool> = None;
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
                let (ip, port, url) = current_url();
                let evidence = presence_evidence();
                if online {
                    logf(&format!("device present: LAN device reachable ({evidence})"));
                    let _ = notifier().send(PushEvent::Info { mobile_connected: true, url, ip, port });
                } else {
                    logf(&format!("device disconnected: no LAN device present ({evidence})"));
                    let _ = notifier().send(PushEvent::Info { mobile_connected: false, url, ip, port });
                }
            }
        }
        // Firewall repair flag transitions.
        let repair = crate::firewall::need_repair();
        if prev_repair != Some(repair) {
            prev_repair = Some(repair);
            let _ = notifier().send(PushEvent::Fw(repair));
        }
        // Prune transfer counters on pure time windows: finished ones after 15s
        // (a lingering completion would keep reappearing in /dl-status), and
        // in-flight ones after 30s of silence — a dead pull's socket write can
        // hang past any timeout, so its entry dies here rather than through
        // the stream. A pruned-but-alive stream rebuilds its counter on its
        // next chunk (see the chunk loop in serve), so a paused-then-resumed
        // pull goes: pruned here with this log line, rebuilt below with that
        // one. Upload entries whose writer already failed were removed by the
        // writer itself. Broadcast `resync` when anything drops so clients
        // reconcile their upload rings back to idle (a silent prune would
        // otherwise leave a ring stuck).
        let now = now_mono();
        {
            let mut map = dl_lock();
            let before = map.len();
            map.retain(|id, e| {
                let stale = now.saturating_sub(e.last_ts);
                let keep = if e.sent >= e.total { stale <= 15 } else { stale <= 30 };
                if !keep && e.sent < e.total {
                    // Only the incomplete reap gets a line: the finished one is
                    // lifecycle noise. Say "stalled pull" so it reads next to
                    // started/done/cut in the same vocabulary.
                    logw(&format!(
                        "prune stalled pull {id}: {}/{} bytes (30s silent)",
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
