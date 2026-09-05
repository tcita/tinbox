// Windows firewall self-handling: solves the "first-run dialog dismissed with
// Cancel -> a Block inbound rule is created -> the phone can never connect,
// and a normal user cannot delete the Block rule from the 'Allow an app
// through Windows Firewall' screen" problem.
//
// Mechanism (normal privileges can only read rules; New/Remove need admin):
//   1. the fw worker: ONE long-lived powershell process owns the ENTIRE rule
//      judgment — there is no separate startup pre-check (the worker's first
//      pass ~1s after launch IS the startup check; two judges would either
//      duplicate the logic or disagree with it). The script loops in-process
//      (~100ms per pass, 500ms cadence) and emits a line only when the state
//      changes, judged against an EXACT invariant: the app maintains exactly
//      one rule (tinbox_Allow_Inbound — enabled, Allow, Any profile) and
//      accepts NOTHING else pointing at the exe. Anything else — the Windows
//      dialog's Query rules, hand-made blocks, duplicates, disabled strays —
//      is 'dirty' and gets flagged; the repair wipes every rule pointing at
//      the exe and recreates the canonical one, so the rule table stays
//      readable and the judgment is a simple equality, not coverage math.
//      The invariant being met clears the flag and retires the worker
//      (rules cannot change by themselves — nothing left to watch). The
//      script self-exits when its parent dies (an app quit never leaks the
//      child), and an unexpected child death respawns after 5s. The one
//      long-lived case is the fresh-install window where the Windows dialog
//      is still unanswered — the OS gets the first chance (its answer is
//      never canonical, so the overlay then demands the one-time repair).
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
//   3. the fw worker: ONE long-lived powershell process owns every rule
//      transition after startup (a per-tick "powershell spawn" costs ~1.1s
//      of CPU, so the old spawn-per-tick pollers are gone). The script
//      loops in-process (~100ms per pass, 500ms cadence) and emits a line
//      only when the state changes, judged against a ROAMING-PROOF
//      invariant: the app's enabled inbound Allow rules must collectively
//      cover every profile ({Public, Private, Domain}) — the Windows
//      dialog's Allow is scoped to the category active at answer time, so
//      "current network works" does not survive a network switch, and
//      retiring on it would reopen the silent-failure hole. A block
//      appearing sets the flag; missing coverage sets it too (preventive:
//      the phone may still work right now, the NEXT network would not);
//      the invariant being met clears it and retires the worker (rules
//      cannot change by themselves — nothing left to watch). The script
//      self-exits when its parent dies (an app quit never leaks the
//      child), and an unexpected child death respawns after 5s. The one
//      long-lived case is the fresh-install window where the Windows
//      dialog is still unanswered — the OS gets the first chance to
//      satisfy the invariant before the overlay demands the repair.
//
// A temp .ps1 file is used instead of passing the script via -ArgumentList to
// avoid quotes/braces being mangled while being passed on the command line.
// Only takes effect on Windows; a no-op on other platforms.
use crate::logger::{loge, logf};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use tauri::{AppHandle, Manager};

const RULE_ALLOW: &str = "tinbox_Allow_Inbound";

#[cfg(windows)]
fn exe_path() -> Option<String> {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.to_str().map(|s| s.to_string()))
}

/// Directory next to the exe, used to hold the temp .ps1 and result files.
#[cfg(windows)]
fn data_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."))
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
            loge(&format!("could not launch powershell: {}", e));
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

static PENDING_REPAIR: AtomicBool = AtomicBool::new(false);

/// Entry point: run the firewall check in the background, without blocking
/// setup/window creation (otherwise a cold powershell start can hang for
/// seconds). A detected Block -> flag PENDING_REPAIR and bring the window to
/// the front; the server pushes the repair flag over /events so the frontend
/// shows the HTML repair overlay. No Block but missing Allow -> poll after
/// startup (wait for the Windows dialog to be answered).
pub fn ensure_background(app: AppHandle) {
    #[cfg(windows)]
    {
        std::thread::spawn(move || {
            let Some(exe) = exe_path() else {
                logf("firewall: could not get exe path, skipping");
                return;
            };
            log_network_profile();
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
///   'dirty:<detail>'     — anything else (dialog Query rules, hand-made
///                          blocks, duplicates, disabled strays); detail is
///                          'block' when an applicable block is the reason,
///                          'shape' otherwise
///   'none'               — no inbound rules at all: the Windows dialog is
///                          pending, so hold fire and let the OS have its
///                          chance first
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
        let script = format!(
            r#"$exe = '{exe}'
$ppid = {ppid}
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new()
$prev = ''
while ($true) {{
  if (-not (Get-Process -Id $ppid -ErrorAction SilentlyContinue)) {{ break }}
  $rules = @(Get-NetFirewallApplicationFilter -Program $exe -ErrorAction SilentlyContinue | Get-NetFirewallRule | Where-Object {{ $_.Direction -eq 'Inbound' }})
  $s = ''
  if ($rules.Count -eq 0) {{
    $s = 'none'
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
  if ($s -ne $prev) {{ $prev = $s; [Console]::WriteLine($s) }}
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
                    loge(&format!("fw worker: could not launch powershell: {e}"));
                    std::thread::sleep(Duration::from_secs(5));
                    continue;
                }
            };
            let stdout = match child.stdout.take() {
                Some(s) => s,
                None => {
                    loge("fw worker: stdout unavailable");
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
                    Ok(line) => match line.trim() {
                        s if s.starts_with("dirty:") => {
                            let detail = &s["dirty:".len()..];
                            if !PENDING_REPAIR.load(Ordering::SeqCst) {
                                logf(&format!(
                                    "fw worker: rule set is not canonical ({detail}) — flagging repair to restore it"
                                ));
                                mark_need_repair(&app);
                            }
                            // Stay alive: the repair wipes everything pointing
                            // at the exe and recreates the canonical rule,
                            // flipping this to 'ok'.
                        }
                        "ok" => {
                            if PENDING_REPAIR.load(Ordering::SeqCst) {
                                logf("fw worker: coverage restored, clearing repair flag");
                                clear_need_repair();
                            } else {
                                logf("fw worker: all-profile Allow coverage in place — invariant met");
                            }
                            // The invariant is roaming-proof: rules cannot
                            // change by themselves, so there is nothing left
                            // to watch this session.
                            policy_dead = true;
                        }
                        "none" => {
                            if PENDING_REPAIR.load(Ordering::SeqCst) {
                                logf("fw worker: applicable Block rule gone, clearing repair flag");
                                clear_need_repair();
                            }
                            // No rules at all: the Windows dialog is pending.
                            // Hold fire — the OS gets the first chance to
                            // satisfy the invariant, the worker re-judges on
                            // the next pass.
                        }
                        _ => {}
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
    // Push the repair flag over the SSE channel so the frontend shows the
    // overlay immediately instead of waiting for the background monitor.
    let _ = crate::server::notifier().send(crate::server::PushEvent::Fw(true));
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
    let _ = crate::server::notifier().send(crate::server::PushEvent::Fw(false));
}

/// Queried by the frontend (the monitor pushes transitions as SSE `fw`
/// events): whether the firewall repair overlay should be shown.
///
/// The flag is moved by two writers, in order of trustworthiness:
///   1. Positive evidence (this branch): a LAN device's requests or transfer
///      bytes still arriving is proof that inbound is open, whatever the
///      rules say. It clears the flag and closes the overlay — including
///      after a repair whose result could not be confirmed by inspection.
///      Positive evidence also includes bytes flowing to a phone mid-
///      download: a request that opens a Range stream proved inbound is
///      open, and a transfer can then hold that stream for many seconds
///      with no new requests arriving (which lan_seen_recently alone would
///      miss).
///   2. The fw worker's rule transitions: a block appearing sets the flag,
///     the block vanishing clears it. An unparseable check emits nothing,
///     so it can neither set nor clear — "could not verify" is not
///     "verified fine".
pub fn need_repair() -> bool {
    #[cfg(windows)]
    {
        if crate::server::lan_seen_recently(30)
            || crate::server::transfer_active_recently(30)
        {
            PENDING_REPAIR.store(false, Ordering::SeqCst);
            return false;
        }
        PENDING_REPAIR.load(Ordering::SeqCst)
    }
    #[cfg(not(windows))]
    {
        false
    }
}

/// Frontend "Repair" click: launch the elevated UAC script that deletes the
/// Block and adds an Allow rule. Returns whether the launch succeeded.
pub fn repair() -> bool {
    #[cfg(windows)]
    {
        // No click dedup on purpose: every click is a genuine request and
        // spawns its own UAC — a cancelled prompt must be retry-able
        // instantly, never gated by a cooldown. Stacked grants are safe: the
        // script deletes the previous tinbox_Allow_Inbound before creating
        // the new one, so N grants still converge to exactly one rule.
        let Some(exe) = exe_path() else { return false; };
        repair_as_admin(&exe)
    }
    #[cfg(not(windows))]
    {
        false
    }
}

/// Frontend "Quit" click: no network access means the app is pointless, just
/// exit.
pub fn quit(app: &AppHandle) {
    logf("user chose to quit (without repairing)");
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
/// ShellExecute is fire-and-forget (no -Wait), so the launcher — itself a
/// hidden powershell — is spawned and never waited on: the /repair handler
/// must return instantly (the UAC dialog may sit unanswered for minutes, and
/// blocking on it once froze the overlay's buttons for 11 minutes). A
/// cancelled UAC simply changes nothing; the user retries. The verdict
/// belongs to the fw worker: it re-judges the invariant within ~1s and
/// closes the overlay via the SSE flag.
///
/// Blocks the calling thread: but the frontend modal already covers the UI
/// while the user waits for the repair, so blocking is fine.
#[cfg(windows)]
fn repair_as_admin(exe: &str) -> bool {
    let dir = data_dir();
    let ps1 = dir.join("tinbox_fw_fix.ps1");

    // Self-contained script: restore the CANONICAL rule set — create the one
    // all-profile Allow, then wipe EVERY other inbound rule pointing at the
    // exe (dialog Query rules, hand-made blocks, duplicates, disabled
    // strays). New-first ordering: at least one valid Allow exists at every
    // instant. The canonical check on the worker side requires exactly this
    // rule set, so a successful run always flips the worker to 'ok'.
    // Note: Get-NetFirewallRule's -DisplayName cannot be combined with
    // -Direction/-Action (different parameter sets).
    let script = format!(
        r#"$exe = '{exe}'
try {{
  $new = New-NetFirewallRule -DisplayName '{RULE_ALLOW}' -Direction Inbound -Action Allow -Program $exe -Profile Any -ErrorAction Stop
  Get-NetFirewallRule -Direction Inbound -ErrorAction SilentlyContinue | ForEach-Object {{
    $f = $_ | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue
    if ($f -and $f.Program -ieq $exe -and $_.Name -ne $new.Name) {{
      Remove-NetFirewallRule -Name $_.Name -ErrorAction SilentlyContinue
    }}
  }}
  # One-time migration: clean up the old (filedrop-era) allow rule — its
  # program points at the old exe path, so the program scan above misses it.
  Get-NetFirewallRule -DisplayName 'FileDrop_Allow_Inbound' -ErrorAction SilentlyContinue | ForEach-Object {{
    Remove-NetFirewallRule -Name $_.Name -ErrorAction SilentlyContinue
  }}
}} catch {{
  Write-Host ('FAIL:' + $_.Exception.Message)
}}
Remove-Item $MyInvocation.MyCommand.Path -ErrorAction SilentlyContinue"#
    );
    if std::fs::write(&ps1, &script).is_err() {
        loge("repair: failed to write temp ps1");
        return false;
    }

    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};
    // Fire-and-forget: the launcher's ONLY job is to carry the runas verb
    // (the UAC consent + the elevated run happen inside it). It is spawned
    // and never waited on — waiting here would block the /repair handler for
    // as long as the UAC dialog sits unanswered, with both buttons disabled
    // (the regression: an 11-minute hang). Confirmation belongs to the fw
    // worker, which re-judges the invariant within ~1s of the rules landing
    // and closes the overlay through the flag; a cancelled UAC simply means
    // nothing changes and the user can retry.
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
        // The launcher outlives this call by design; dropping the Child does
        // not kill it, and it exits on its own once ShellExecute returns.
        Ok(_) => true,
        Err(e) => {
            loge(&format!("repair: could not launch powershell: {e}"));
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
