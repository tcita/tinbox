// Windows firewall self-handling: solves the "first-run dialog dismissed with
// Cancel -> a Block inbound rule is created -> the phone can never connect,
// and a normal user cannot delete the Block rule from the 'Allow an app
// through Windows Firewall' screen" problem.
//
// Mechanism (normal privileges can only read rules; New/Remove need admin):
//   1. the firewall worker: ONE long-lived powershell process owns the ENTIRE rule
//      judgment — there is no separate startup pre-check (the worker's first
//      pass ~1s after launch IS the startup check; two judges would either
//      duplicate the logic or disagree with it). The script loops in-process
//      (~100ms per pass, 500ms cadence) and emits a line only when the state
//      changes, judged against an EXACT invariant: the app maintains exactly
//      one rule (tinbox_Allow_Inbound — enabled, Allow, Any profile) and
//      accepts NOTHING else pointing at the exe. Anything else — zero rules,
//      the Windows dialog's Query rules, hand-made blocks, duplicates,
//      disabled strays — is 'dirty' and gets flagged; the repair wipes every
//      rule pointing at the exe and recreates the canonical one, so the rule
//      table stays readable and the judgment is a simple equality, not
//      coverage math. Zero rules is 'dirty:empty', flagged immediately like
//      any other deviation — there is no 'none' hold-fire state (the OS
//      dialog's answer is never canonical, so waiting on it only delays the
//      one-time repair, and a late dialog answer after the repair is just
//      another dirty the next repair converges).
//      The invariant being met clears the flag and retires the worker
//      (rules cannot change by themselves — nothing left to watch). The
//      script self-exits when its parent dies (an app quit never leaks the
//      child), and an unexpected child death respawns after 5s.
//   2. The flag is pushed over the SSE channel as an `fw` event; the
//      frontend shows the HTML repair overlay (Allow / Quit, no dismiss —
//      the flag means the phone would be blocked on some network) and the
//      window is pinned on top so the overlay cannot be missed. "Allow"
//      writes a temp .ps1 and launches it elevated via ShellExecute runas +
//      SW_HIDE (the elevated console is born hidden — no terminal flash):
//      delete all Block rules for our exe and add one all-profile Allow
//      rule. The repair return only means "UAC granted" — the worker
//      confirms the invariant within ~1s and the overlay closes through the
//      same flag path as everything else. Rule changes take effect
//      immediately, so the phone connects within the same session.
//
// A temp .ps1 file is used instead of passing the script via -ArgumentList to
// avoid quotes/braces being mangled while being passed on the command line.
// Only takes effect on Windows; a no-op on other platforms.
use crate::logger::{loge, logf};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Mutex;
use tauri::{AppHandle, Manager};

const RULE_ALLOW: &str = "tinbox_Allow_Inbound";

#[cfg(windows)]
fn exe_path() -> Option<String> {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.to_str().map(|s| s.to_string()))
}

/// Scratch home for the repair helper files (the .ps1 + its result file).
/// This is %TEMP%, deliberately NOT the exe directory: the exe may live
/// somewhere read-only (Program Files), and an app dir that litters scripts
/// next to the binary reads as malware to humans and AV alike. %TEMP% is the
/// standard home for such helpers and is per-user, so no collisions. NOT
/// embedded via -EncodedCommand on purpose: a base64 blob on a runas command
/// line is more opaque — to AV heuristics and to anyone auditing — than a
/// plain-text script, and opacity is the wrong trade for an app asking for
/// firewall elevation. (The run_ps one-liners elsewhere stay inline: short
/// enough to survive -Command quoting, unlike the repair script.)
#[cfg(windows)]
fn data_dir() -> PathBuf {
    std::env::temp_dir()
}

/// Quote a string for embedding in a PowerShell single-quoted literal: `'`
/// escapes as `''`. Paths with apostrophes (e.g. `D:\Bob's Tools\...`) would
/// otherwise terminate the literal early and break the generated script —
/// silently misdirecting both the worker's rule query and the repair's rule
/// edit at once.
#[cfg(windows)]
fn ps_quote(s: &str) -> String {
    s.replace('\'', "''")
}

/// Windows process creation flag: CREATE_NO_WINDOW, so launching powershell
/// does not flash a console window.
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x08000000;

/// Run a PowerShell snippet, returning (success, stdout). Uses
/// CREATE_NO_WINDOW to avoid flashing a terminal.
#[cfg(windows)]
pub(crate) fn run_ps(script: &str) -> Option<(bool, String)> {
    use std::os::windows::process::CommandExt;
    use std::process::Command;
    // Force UTF-8 stdout: on localized Windows (e.g. Chinese) PowerShell's
    // default output encoding is the legacy ANSI codepage, which garbles
    // non-ASCII output like NIC names once decoded as UTF-8.
    let script = format!(
        "$OutputEncoding = [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new(); {script}"
    );
    let out = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .creation_flags(CREATE_NO_WINDOW)
        .output();
    match out {
        Ok(o) => {
            let ok = o.status.success();
            if !ok {
                let err = String::from_utf8_lossy(&o.stderr);
                loge(&format!("ps failed: stderr={}", err.trim()));
            }
            Some((ok, String::from_utf8_lossy(&o.stdout).to_string()))
        }
        Err(e) => {
                loge(&format!("ps: could not launch powershell: {}", e));
            None
        }
    }
}

/// Log the active network profile(s) (Private/Public/Domain). A Public profile
/// combined with stricter inbound handling is one of the most common reasons a
/// phone cannot connect while the PC's own browser (loopback) works fine.
#[cfg(windows)]
fn log_network_profile() {
    let ps = "(Get-NetConnectionProfile | ForEach-Object { $_.InterfaceAlias + '=' + $_.NetworkCategory }) -join ', '";
    if let Some((true, out)) = run_ps(ps) {
        let s = out.trim();
        if !s.is_empty() {
            logf(&format!(
                "firewall: active network profile(s): {s} (a Public profile is a common cause of blocked inbound)"
            ));
        }
    }
}

/// One-time backdrop for the speed question: this PC's Wi-Fi link (PHY) rate.
/// Source is Get-NetAdapter's LinkSpeed (pure PowerShell, unelevated) —
/// deliberately NOT `netsh wlan show interfaces`: since Win11 24H2 it needs
/// location permission/elevation for unprivileged callers (WlanQueryInterface
/// error 5), so netsh fails exactly where we run. Only Up WLAN*/Wi-Fi*
/// adapters are listed (tunnels, vEthernet and wired are not this leg);
/// silent on wired-only PCs. Labeled as what it is — ONE leg's negotiated
/// rate, not end-to-end throughput (the phone's leg is invisible from here,
/// real TCP runs ~50-65% of PHY on WiFi). Context for reading the
/// per-transfer `ul`/`dl` MB/s verdicts, never a verdict itself.
#[cfg(windows)]
fn log_wifi_link_rate() {
    let ps = "(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' -and ($_.Name -like 'WLAN*' -or $_.Name -like 'Wi-Fi*') } | ForEach-Object { $_.Name + '=' + $_.LinkSpeed }) -join ', '";
    if let Some((true, out)) = run_ps(ps) {
        let s = out.trim();
        if !s.is_empty() {
            logf(&format!(
                "wifi: this PC's link {s} (PHY rate, this leg only — end-to-end is the ul/dl MB/s lines)"
            ));
        }
    }
}

static PENDING_REPAIR: AtomicBool = AtomicBool::new(false);

/// Per-process repair-attempt counter. Each attempt gets its own scratch files
/// (`tinbox_fw_fix_<pid>_<seq>.ps1` / `.result`) so overlapping attempts can
/// never clobber each other's script or result; combined with the named mutex
/// that serializes the actual rule edit inside the elevated script, concurrent
/// repairs are safe. Stale files from crashed runs are swept at startup.
#[cfg_attr(not(windows), allow(dead_code))]
static ATTEMPT_SEQ: AtomicU32 = AtomicU32::new(0);

/// Entry point: run the firewall check in the background, without blocking
/// setup/window creation (otherwise a cold powershell start can hang for
/// seconds). Any deviation from the canonical exactly-one-Allow (block,
/// stray, duplicate, or zero rules) -> flag PENDING_REPAIR and bring the
/// window to the front; the server pushes the repair flag over /events so
/// the frontend shows the HTML repair overlay.
pub fn ensure_background(app: AppHandle) {
    #[cfg(windows)]
    {
        std::thread::spawn(move || {
            // Sweep stale repair scratch files first (exe-independent): a
            // UAC-denied click leaves the .ps1 behind — the elevated run
            // never starts, so nothing self-deletes it — and a crash can
            // leave the result too. Anything present at startup is residue by
            // definition. Names are per-attempt (tinbox_fw_fix_<id>.ps1/.result),
            // so match the shared prefix rather than one fixed pair.
            if let Ok(rd) = std::fs::read_dir(data_dir()) {
                for e in rd.flatten() {
                    let name = e.file_name();
                    if name.to_string_lossy().starts_with("tinbox_fw_fix") {
                        if std::fs::remove_file(e.path()).is_ok() {
                            logf(&format!(
                                "firewall: removed stale repair scratch file {}",
                                name.to_string_lossy()
                            ));
                        }
                    }
                }
            }
            let Some(exe) = exe_path() else {
                logf("firewall: could not get exe path, skipping");
                return;
            };
            log_network_profile();
            log_wifi_link_rate();
            // No startup rule pre-check: the worker's FIRST pass (~1s after
            // launch) IS the startup check. One judge, one verdict — a
            // separate pre-check would either duplicate the worker's logic
            // or disagree with it. Unhealthy → flag + overlay + the worker
            // stays watching; healthy → the worker retires immediately
            // (nothing can change the rules by itself).
            spawn_fw_worker(app, exe);
        });
    }
    #[cfg(not(windows))]
    {
        let _ = app;
    }
}

/// One long-lived powershell process owns ALL rule watching after startup
/// (it replaces two spawn-per-tick pollers: the dialog watcher and the
/// need_repair confirm check). Each spawn of powershell costs ~1.1s of CPU
/// (engine init dominates; the WMI query itself is ~60ms), so the script
/// loops IN-PROCESS and emits one line only when the state changes:
///   'ok'                 — CANONICAL state: exactly one inbound rule for
///                          the exe, and it is our enabled all-profile Allow
///   'dirty:<detail>'     — anything else (zero rules, dialog Query rules,
///                          hand-made blocks, duplicates, disabled strays);
///                          detail is 'block' when an applicable block is the
///                          reason, 'empty' when no inbound rule exists at
///                          all, 'shape' otherwise
///
/// The invariant is deliberately EXACT: the app maintains exactly one rule
/// (tinbox_Allow_Inbound, Any profile, enabled) and accepts nothing else.
/// Every deviation — including a "harmless" extra allow the OS dialog left
/// behind — gets flagged and cleaned by the repair, so the rule table stays
/// readable and the judgment is a simple equality, not coverage math.
/// Retirement happens only when the invariant holds — rules cannot change
/// by themselves, so nothing is left to watch.
///
/// The Rust side translates transitions into flag moves: dirty → flag
/// (overlay up); ok → clear (overlay down) and retire. The script self-
/// exits when its parent process dies (an app quit never leaks the child),
/// and an unexpected child death respawns after 5s.
#[cfg(windows)]
fn spawn_fw_worker(app: AppHandle, exe: String) {
    std::thread::spawn(move || {
        let ppid = std::process::id();
        let exe = ps_quote(&exe);
        let script = format!(
            r#"$exe = '{exe}'
$ppid = {ppid}
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new()
$prev = ''
while ($true) {{
  if (-not (Get-Process -Id $ppid -ErrorAction SilentlyContinue)) {{ break }}
  $rules = @(Get-NetFirewallApplicationFilter -Program $exe -ErrorAction SilentlyContinue | Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object {{ $_.Direction -eq 'Inbound' }})
  $s = ''
  if ($rules.Count -eq 0) {{
    $s = 'dirty:empty'
  }} elseif ($rules.Count -eq 1 -and $rules[0].Enabled -eq 'True' -and $rules[0].Action -eq 'Allow' -and $rules[0].Profile -eq 'Any' -and $rules[0].DisplayName -eq 'tinbox_Allow_Inbound') {{
    $s = 'ok'
  }} else {{
    $detail = 'shape'
    $active = @((Get-NetConnectionProfile -ErrorAction SilentlyContinue | ForEach-Object {{ $_.NetworkCategory }}) | ForEach-Object {{ if ($_ -eq 'DomainAuthenticated') {{ 'Domain' }} else {{ $_ }} }} | Sort-Object -Unique)
    foreach ($r in $rules) {{
      if ($r.Enabled -eq 'True' -and $r.Action -eq 'Block') {{
        $applies = $false
        if ($r.Profile -eq 'Any') {{ $applies = $true }}
        else {{ foreach ($p in (($r.Profile -split ',') | ForEach-Object {{ $_.Trim() }})) {{ if ($active -contains $p) {{ $applies = $true }} }} }}
        if ($applies) {{ $detail = 'block'; break }}
      }}
    }}
    $s = 'dirty:' + $detail
  }}
  if ($s -ne $prev) {{
    $prev = $s; [Console]::WriteLine($s)
    # Dirty-transition rule dump (the "before" picture): verdicts alone
    # (dirty:block) never show WHAT the table looks like — a surviving Block,
    # a mis-scoped Allow, dialog Query strays. Transitions only, so no spam.
    if ($s.StartsWith('dirty')) {{
      $info = @($rules | ForEach-Object {{ $p = ($_ | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue).Program; '{{0}}|{{1}}|{{2}}|{{3}}|{{4}}' -f $_.DisplayName,$_.Action,$_.Enabled,$_.Profile,$p }}) -join ' ;; '
      [Console]::WriteLine('rules:' + $info)
    }}
  }}
  Start-Sleep -Milliseconds 500
}}"#
        );

        // Respawn loop: a dead child that was not policy-killed comes back
        // after 5s, self-healing a transiently broken powershell.
        loop {
            use std::io::{BufReader, BufRead};
            use std::os::windows::process::CommandExt;
            use std::process::{Command, Stdio};
            use std::sync::mpsc;
            use std::time::Duration;

            let mut child = match Command::new("powershell.exe")
                .args(["-NoProfile", "-NonInteractive", "-Command", &script])
                .stdout(Stdio::piped())
                .creation_flags(CREATE_NO_WINDOW)
                .spawn()
            {
                Ok(c) => c,
                Err(e) => {
                    loge(&format!("firewall worker: could not launch powershell: {e}"));
                    std::thread::sleep(Duration::from_secs(5));
                    continue;
                }
            };
            let stdout = match child.stdout.take() {
                Some(s) => s,
                None => {
                    loge("firewall worker: stdout unavailable");
                    std::thread::sleep(Duration::from_secs(5));
                    continue;
                }
            };
            let (tx, rx) = mpsc::channel::<String>();
            std::thread::spawn(move || {
                for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                    if tx.send(line).is_err() {
                        break;
                    }
                }
            });

            let mut policy_dead = false;
            loop {
                match rx.recv_timeout(Duration::from_secs(1)) {
                    Ok(line) => {
                        let state = line.trim().to_string();
                        match state.as_str() {
                            s if s.starts_with("dirty:") => {
                            let detail = &s["dirty:".len()..];
                            if !PENDING_REPAIR.load(Ordering::SeqCst) {
                                logf(&format!(
                                    "firewall worker: rule set is not canonical ({detail}) — flagging repair to restore it"
                                ));
                                mark_need_repair(&app);
                            }
                            // Stay alive: the repair wipes everything pointing
                            // at the exe and recreates the canonical rule,
                            // flipping this to 'ok'.
                        }
                        "ok" => {
                            if PENDING_REPAIR.load(Ordering::SeqCst) {
                                logf("firewall worker: coverage restored, clearing repair flag");
                                clear_need_repair();
                            } else {
                                logf("firewall worker: all-profile Allow coverage in place — invariant met");
                            }
                            // The invariant is roaming-proof: rules cannot
                            // change by themselves, so there is nothing left
                            // to watch this session.
                            policy_dead = true;
                        }
                        // Table line from the dirty-transition dump above —
                        // WHAT the rules look like, not just the verdict.
                        // Never touches the flag or the worker's life cycle;
                        // pure evidence.
                        s if s.starts_with("rules:") => {
                            let t = s["rules:".len()..].trim();
                            logf(&format!(
                                "firewall worker: rule table [{}]",
                                if t.is_empty() { "(empty)" } else { t }
                            ));
                        }
                        _ => {}
                        }
                    },
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                    Err(mpsc::RecvTimeoutError::Disconnected) => break, // child died
                }
                if policy_dead {
                    break;
                }
            }
            let _ = child.kill();
            let _ = child.wait();
            if policy_dead {
                return;
            }
            // Not a policy retirement: the powershell child died on its own
            // (crash, AV kill, engine fault). Say so — a silent respawn would
            // be indistinguishable from a healthy worker in the log.
            logf("firewall worker: powershell exited unexpectedly - respawning in 5s");
            std::thread::sleep(Duration::from_secs(5));
        }
    });
}

/// Flag that repair is needed and bring the window to the front so the user is
/// sure to see the frontend's HTML repair overlay (not hidden behind
/// minimize/occlusion).
#[cfg(windows)]
fn mark_need_repair(app: &AppHandle) {
    PENDING_REPAIR.store(true, Ordering::SeqCst);
    logf("firewall: repair flag SET — overlay up");
    // Push the repair flag over the SSE channel so the frontend shows the
    // overlay immediately instead of waiting for the background monitor.
    let _ = crate::server::notifier().send(crate::server::PushEvent::Fw(true));
    // The window may be tray-destroyed: rebuild it first or the overlay has
    // nowhere to show (a blocked phone with no visible repair path).
    crate::ensure_main_window(app);
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.unminimize();
        let _ = w.set_focus();
        let _ = w.set_always_on_top(true);
    }
}

/// Mirror of mark_need_repair: clear the flag and push the change so the
/// overlay closes without waiting for the monitor's next tick (the fw worker
/// calls this when the block rule vanishes).
#[cfg(windows)]
fn clear_need_repair() {
    PENDING_REPAIR.store(false, Ordering::SeqCst);
    logf("firewall: repair flag CLEARED — overlay down");
    let _ = crate::server::notifier().send(crate::server::PushEvent::Fw(false));
}

/// Queried by the frontend (the monitor pushes transitions as SSE `fw`
/// events): whether the firewall repair overlay should be shown. ONE writer
/// moves the flag: the fw worker's rule verdicts (dirty sets it, canonical
/// clears it). A traffic-evidence veto (any request or transfer byte within
/// 30s pinned the flag down) was deliberately removed: the invariant is
/// roaming-proof and the overlay is PREVENTIVE — "rules not canonical, the
/// NEXT network breaks" — so working traffic does not contradict the flag,
/// and suppressing the overlay mid-transfer only postpones the one-click
/// permanent fix. Silence sets nothing either way: only the worker's
/// inspection raises the flag, and a restart re-judges everything, which
/// covers the accepted "external mutation after retirement" risk.
pub fn need_repair() -> bool {
    PENDING_REPAIR.load(Ordering::SeqCst)
}

/// Frontend "Repair" click: launch the elevated UAC script that deletes the
/// Block and adds an Allow rule. Returns whether the launch succeeded.
pub fn repair() -> bool {
    #[cfg(windows)]
    {
        // Every click is a genuine request and spawns its own UAC — a cancelled
        // prompt must be retry-able instantly, never gated by a cooldown. So
        // concurrent attempts ARE possible (a retry while a first prompt is
        // still up) and are made safe structurally rather than by rejecting
        // them: each attempt owns uniquely-named scratch files, and the
        // elevated script serializes the rule edit under a named mutex, so N
        // attempts converge to exactly one canonical rule.
        let Some(exe) = exe_path() else {
            loge("firewall repair: could not get exe path");
            return false;
        };
        let id = format!(
            "{}_{}",
            std::process::id(),
            ATTEMPT_SEQ.fetch_add(1, Ordering::SeqCst)
        );
        let started = repair_as_admin(&exe, &id);
        if started {
            // The elevated run is fire-and-forget, so its outcome is reported
            // by watchers rather than a return value: the launcher watcher logs
            // when the prompt was answered, and this watcher logs the elevated
            // script's result file (STARTED / OK / FAIL:<reason>). No separate
            // rule re-check: the fw worker already re-judges the invariant
            // within ~1s of the rules landing and logs the transition, and a
            // second judge would only duplicate it.
            std::thread::spawn(move || watch_repair_result(id));
            logf("firewall repair: awaiting elevated script result (120s window)");
        }
        started
    }
    #[cfg(not(windows))]
    {
        false
    }
}

/// Result file the elevated repair script writes next to the .ps1 (STARTED,
/// then OK or FAIL:<reason>, UTF-8 — localized Windows errors are non-ASCII,
/// hence the explicit encoding on the write side and the BOM trim on the read
/// side). Per-attempt, so concurrent repairs never share it.
#[cfg(windows)]
fn attempt_result_path(id: &str) -> PathBuf {
    data_dir().join(format!("tinbox_fw_fix_{id}.result"))
}

/// Watcher for the elevated script's result: ShellExecute runas is
/// fire-and-forget, so without this the log can never separate "UAC
/// dismissed" from "granted but the script failed" from "rules landed".
/// A missing file after 120s means the elevated run never reported back
/// (UAC still sitting, dismissed, or the launch died silently).
#[cfg(windows)]
fn watch_repair_result(id: String) {
    let path = attempt_result_path(&id);
    let mut granted = false;
    for _ in 0..120 {
        std::thread::sleep(std::time::Duration::from_secs(1));
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let s = String::from_utf8_lossy(&bytes)
            .trim_start_matches('\u{FEFF}')
            .trim()
            .to_string();
        if s.is_empty() {
            continue;
        }
        if s == "STARTED" {
            // The elevated script is running — UAC was granted. This is the
            // ground-truth "repair really started" signal the frontend freezes
            // on. Keep polling for the final OK/FAIL.
            if !granted {
                granted = true;
                logf("firewall repair: elevated script started (UAC granted)");
                let _ = crate::server::notifier()
                    .send(crate::server::PushEvent::FwRepair("granted"));
            }
            continue;
        }
        // A final result (OK / FAIL:<reason>): the script ran to completion.
        if s == "OK" {
            logf("firewall repair: elevated script reports OK — canonical rule written, awaiting worker 'ok' verdict");
        } else {
            logf(&format!("firewall repair: elevated script reports {s}"));
        }
        let _ = std::fs::remove_file(&path);
        return;
    }
    logf("firewall repair: no result file after 120s - elevated script never reported back");
}

/// Frontend "Quit" click: no network access means the app is pointless, just
/// exit.
pub fn quit(app: &AppHandle) {
    logf("firewall: user chose to quit (without repairing)");
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.close();
    }
    std::process::exit(0);
}

/// Write a temp .ps1 and launch it elevated with NO console flash.
///
/// Why not `Start-Process -Verb RunAs -WindowStyle Hidden`: the elevated
/// console is created VISIBLY first and the hidden style is applied only
/// after powershell parses its arguments — the gap between the two is the
/// blue terminal flash (Windows Terminal as the default host makes it
/// worse). Instead, ShellExecute's `runas` verb carries a SHOW command, and
/// SW_HIDE is honored at process creation, so the elevated console is born
/// hidden; the UAC consent prompt itself is unaffected.
///
/// The launcher is fire-and-forget (no -Wait): the /repair handler returns
/// instantly (the UAC dialog may sit unanswered for minutes, and blocking on
/// it once froze the overlay's buttons for 11 minutes). A detached thread
/// polls the launcher's exit code purely to LOG when the prompt was answered
/// (the code cannot say granted vs cancelled); the verdict on the rules
/// belongs to the firewall worker, which re-judges the invariant within ~1s
/// and closes the overlay via the SSE flag.
#[cfg(windows)]
fn repair_as_admin(exe: &str, id: &str) -> bool {
    let dir = data_dir();
    let ps1 = dir.join(format!("tinbox_fw_fix_{id}.ps1"));

    // Self-contained script: restore the CANONICAL rule set — create the one
    // all-profile Allow, then wipe EVERY other inbound rule pointing at the
    // exe (dialog Query rules, hand-made blocks, duplicates, disabled
    // strays). New-first ordering: at least one valid Allow exists at every
    // instant. The canonical check on the worker side requires exactly this
    // rule set, so a successful run always flips the worker to 'ok'.
    // Filter-FIRST deletion (ApplicationFilter -Program, the worker's own
    // query direction): the old code enumerated the WHOLE inbound table and
    // ran a per-rule filter query — ~40s on a rule-heavy machine (Allow
    // landed in seconds, the duplicate Blocks survived another half minute).
    // Scoped to our exe it is a handful of rules and returns in ~1s. The
    // Direction guard stays: only inbound rules are ours to touch, a user's
    // hand-made outbound rules are never wiped.
    // The outcome (OK / FAIL:<reason>) is written to a result file for the
    // Rust watcher — the elevated console is born hidden and its stdout is
    // unread, so without this a failed repair is silent. UTF-8 explicitly:
    // localized Windows errors are non-ASCII and WinPS 5.1 defaults to ANSI.
    // Note: Get-NetFirewallRule's -DisplayName cannot be combined with
    // -Direction/-Action (different parameter sets).
    let res = ps_quote(&attempt_result_path(id).to_string_lossy());
    let exe = ps_quote(exe);
    let script = format!(
        r#"$exe = '{exe}'
$res = '{res}'
# Proof the elevated run actually started (i.e. UAC was granted). ShellExecute
# returns success even when the UAC prompt is cancelled, so the launcher exit
# code cannot tell; the Rust watcher keys "granted" off this marker instead.
Set-Content -LiteralPath $res -Value 'STARTED' -Encoding UTF8 -ErrorAction SilentlyContinue
# Serialize the rule edit across concurrent repair attempts: two scripts racing
# their create-then-delete-others would delete each other's fresh rule and can
# leave ZERO rules — the worker reports that as 'dirty:empty' and the overlay
# stays up until the next repair converges. A session-local named mutex makes
# each attempt's edit atomic, so N attempts converge to exactly one canonical
# rule.
# Bounded wait: if a previous holder is wedged, fail rather than edit
# unsynchronized.
$mtx = $null
$held = $false
try {{
  $mtx = New-Object System.Threading.Mutex($false, 'TinboxFwRepair')
  $held = $mtx.WaitOne(120000)
}} catch {{ $held = $false }}
try {{
  if (-not $held) {{ throw 'could not acquire rule-edit mutex (timeout)' }}
  $new = New-NetFirewallRule -DisplayName '{RULE_ALLOW}' -Direction Inbound -Action Allow -Program $exe -Profile Any -ErrorAction Stop
  Get-NetFirewallApplicationFilter -Program $exe -ErrorAction SilentlyContinue | Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object {{ $_.Direction -eq 'Inbound' -and $_.Name -ne $new.Name }} | ForEach-Object {{
    Remove-NetFirewallRule -Name $_.Name -ErrorAction SilentlyContinue
  }}
  # Per-path isolation is INTENTIONAL, not a gap: Windows keys rules by exact
  # program path, so two copies (release/ vs Desktop/) are disjoint rule sets
  # and each worker judges only its own exe. In particular this script must
  # NEVER touch another path's tinbox_Allow_Inbound: with two instances
  # running, deleting A's Allow while A's worker has already retired on
  # 'canonical' orphans A with no rule and no watcher — its phone dies
  # silently with no overlay. Each copy minds its own rules; stale Allows
  # after moving the exe are cosmetic litter (one manual sweep clears them).
  # One-time migration: clean up the old (filedrop-era) allow rule — its
  # program points at the old exe path, so the program scan above misses it.
  Get-NetFirewallRule -DisplayName 'FileDrop_Allow_Inbound' -ErrorAction SilentlyContinue | ForEach-Object {{
    Remove-NetFirewallRule -Name $_.Name -ErrorAction SilentlyContinue
  }}
  $out = 'OK'
}} catch {{
  $out = 'FAIL:' + $_.Exception.Message
}} finally {{
  if ($held) {{ try {{ $mtx.ReleaseMutex() }} catch {{}} }}
}}
Set-Content -LiteralPath $res -Value $out -Encoding UTF8 -ErrorAction SilentlyContinue
Remove-Item $MyInvocation.MyCommand.Path -ErrorAction SilentlyContinue"#
    );
    if std::fs::write(&ps1, &script).is_err() {
        loge("firewall repair: failed to write temp ps1");
        return false;
    }

    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};
    // Fire-and-forget at the handler level: the launcher's ONLY job is to
    // carry the runas verb (the UAC consent + the elevated run happen inside
    // it). A detached thread polls the launcher ONLY to learn when the prompt
    // was answered — its exit code cannot say which answer, since ShellExecute
    // returns success even on cancel; "granted" comes from the elevated
    // script's STARTED marker instead. It is NEVER waited on by the /repair
    // handler: doing that once froze the overlay's buttons for 11 minutes
    // while the prompt sat unanswered.
    let launcher = format!(
        "$sh = New-Object -ComObject Shell.Application; \
         try {{ $sh.ShellExecute('powershell.exe', \
         '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File \"{ps1}\"', \
         '', 'runas', 0) }} catch {{ exit 1 }}",
        ps1 = ps1.to_string_lossy()
    );
    match Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &launcher])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
    {
        Ok(mut child) => {
            // The launcher exits once the UAC prompt is answered, but its exit
            // code does NOT say which answer — Shell.Application's ShellExecute
            // returns success even when the user cancels. So "granted" comes
            // from the elevated script's STARTED marker (see
            // watch_repair_result), and "cancelled" is launcher-exited plus a
            // 3s grace with still no marker: the elevated run never started.
            // The grace covers the STARTED write racing the launcher exit
            // (consent → both happen within ~a second). A still-alive launcher
            // means the prompt is still open — keep the button locked, never
            // time out into a second stacked UAC. Detached, never the /repair
            // handler, so a prompt left open cannot freeze the UI; the poll is
            // bounded so it cannot leak. A late STARTED landing just after the
            // grace may re-arm the button while the first repair runs — safe
            // by construction (per-attempt files + the mutex), at worst one
            // redundant UAC.
            let result_path = attempt_result_path(id);
            std::thread::spawn(move || {
                use std::time::{Duration, Instant};
                let deadline = Instant::now() + Duration::from_secs(180);
                loop {
                    match child.try_wait() {
                        Ok(Some(status)) => {
                            logf(&format!("firewall repair: launcher exited ({status})"));
                            std::thread::sleep(Duration::from_secs(3));
                            let started = std::fs::read(&result_path)
                                .ok()
                                .map(|b| {
                                    let s = String::from_utf8_lossy(&b)
                                        .trim_start_matches('\u{FEFF}')
                                        .trim()
                                        .to_string();
                                    s == "STARTED" || s == "OK" || s.starts_with("FAIL:")
                                })
                                .unwrap_or(false);
                            if !started {
                                logf("firewall repair: no elevated start after launcher exit — UAC was cancelled, re-arming repair button");
                                let _ = crate::server::notifier().send(
                                    crate::server::PushEvent::FwRepair("cancelled"),
                                );
                            }
                            return;
                        }
                        Ok(None) => {
                            if Instant::now() >= deadline {
                                logf("firewall repair: launcher still alive after 180s - UAC prompt left open?");
                                return;
                            }
                            std::thread::sleep(Duration::from_millis(500));
                        }
                        Err(e) => {
                            loge(&format!("firewall repair: launcher wait failed: {e}"));
                            return;
                        }
                    }
                }
            });
            true
        }
        Err(e) => {
            loge(&format!("firewall repair: could not launch powershell: {e}"));
            false
        }
    }
}

// Suppress unused warnings on non-Windows.
#[allow(dead_code)]
fn _silence() {
    let _ = Mutex::new(());
    let _ = PathBuf::new();
}
