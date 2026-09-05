// Windows firewall self-handling: solves the "first-run dialog dismissed with
// Cancel -> a Block inbound rule is created -> the phone can never connect,
// and a normal user cannot delete the Block rule from the 'Allow an app
// through Windows Firewall' screen" problem.
//
// Mechanism (normal privileges can only read rules; New/Remove need admin):
//   1. ensure(): read-only detection before startup - is there an ENABLED
//      Block rule targeting our own exe whose profile covers the ACTIVE
//      network (an applicable block = the phone is certainly blocked)? A
//      live self-test connection cannot do this job: loopback traffic (any
//      connection to a local IP, own LAN IP included) is exempt from Windows
//      firewall filtering by design, so only another machine could test the
//      inbound path. Rule inspection with the applicability filter is the
//      strongest local equivalent, and when it confirms a block the overlay
//      is raised immediately - no grace window needed, the state is certain.
//   2. The flag is pushed over the SSE channel as an `fw` event; the
//      frontend shows the HTML repair overlay (Allow / Quit, no dismiss —
//      a shown overlay means the phone is certainly blocked, and a false
//      alarm self-heals via connection evidence) and the window is pinned
//      on top so the overlay cannot be missed. "Allow" writes a temp .ps1
//      and triggers an elevated run (ShellExecute runas + SW_HIDE, so the
//      elevated console never flashes): delete all Block rules for our exe
//      and add one Allow rule. Rule changes take effect immediately, so the
//      phone connects within the same session.
//   3. the fw worker: ONE long-lived powershell process owns every rule
//      transition after startup (a per-tick "powershell spawn" costs ~1.1s
//      of CPU, so the old spawn-per-tick pollers are gone). The script
//      loops in-process (~100ms per pass, 500ms cadence) and emits a line
//      only when the state changes: a block appearing sets the flag
//      (overlay up, caught within ~1s of the dialog's Cancel); the block
//      vanishing clears it (overlay down, ~0.6s after the rule leaves —
//      this used to be a 4s-throttled re-check); an Allow appearing means
//      the dialog was answered and the worker retires. The script self-
//      exits when its parent dies (an app quit never leaks the child), and
//      an unexpected child death respawns after 5s. A LAN device proving
//      inbound open with no flag retires the worker too — its only
//      long-lived case is a dialog hanging unanswered, which is exactly
//      what it must keep watching.
//
// A temp .ps1 file is used instead of passing the script via -ArgumentList to
// avoid quotes/braces being mangled while being passed on the command line.
// Only takes effect on Windows; a no-op on other platforms.
use crate::logger::{loge, logf, logw};
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

/// Outcome of looking for a Block rule that targets our own exe. "Absent" and
/// "Unknown" must not be conflated: hiding the repair overlay because a check
/// failed (powershell unavailable, script error) would leave the phone blocked
/// with the UI claiming everything is fine.
#[cfg(windows)]
enum BlockCheck {
    /// Confirmed: no such Block rule exists.
    Absent,
    /// Confirmed: a Block rule exists, with its display name.
    Present(String),
    /// The check itself failed; no conclusion either way.
    Unknown,
}

/// Look for an ENABLED Block inbound rule for our own exe that APPLIES to the
/// currently active network(s). Filters by program first (one indexed query)
/// instead of walking every inbound Block rule and fetching its filter one by
/// one — the latter takes seconds, which directly adds to the detection
/// latency.
///
/// Two applicability guards keep this from crying wolf (the overlay locks the
/// app behind Quit/Allow, so the check must be strict):
///   - Enabled only: an inactive rule blocks nothing (disabling the Block in
///     wf.msc is a common manual fix).
///   - Profile coverage: a rule scoped to Public does not block on a Private
///     network. The rule's profile set is intersected with the active
///     NetworkCategory values ('DomainAuthenticated' folds to 'Domain'); an
///     uncovered-but-present rule is reported as "dormant:" in the output so
///     the log keeps the diagnosis without flagging a repair.
#[cfg(windows)]
fn find_block_rule(exe: &str) -> BlockCheck {
    let ps = format!(
        r#"$exe = '{exe}'
$active = @((Get-NetConnectionProfile -ErrorAction SilentlyContinue | ForEach-Object {{ $_.NetworkCategory }}) | ForEach-Object {{ if ($_ -eq 'DomainAuthenticated') {{ 'Domain' }} else {{ $_ }} }} | Sort-Object -Unique)
$applicable = ''
$dormant = ''
Get-NetFirewallApplicationFilter -Program $exe -ErrorAction SilentlyContinue | ForEach-Object {{
  $r = $_ | Get-NetFirewallRule -ErrorAction SilentlyContinue
  if ($r -and $r.Enabled -eq 'True' -and $r.Direction -eq 'Inbound' -and $r.Action -eq 'Block') {{
    $applies = $false
    if ($r.Profile -eq 'Any') {{ $applies = $true }}
    else {{ foreach ($p in (($r.Profile -split ',') | ForEach-Object {{ $_.Trim() }})) {{ if ($active -contains $p) {{ $applies = $true }} }} }}
    if ($applies) {{ if (-not $applicable) {{ $applicable = $r.DisplayName }} }}
    else {{ if (-not $dormant) {{ $dormant = $r.DisplayName }} }}
  }}
}}
if ($applicable) {{ $applicable }} elseif ($dormant) {{ 'dormant:' + $dormant }} else {{ '' }}"#
    );
    match run_ps(&ps) {
        Some((true, out)) => {
            let s = out.trim();
            if s.is_empty() {
                BlockCheck::Absent
            } else if let Some(dormant) = s.strip_prefix("dormant:") {
                logf(&format!(
                    "firewall: Block rule '{dormant}' exists but its profile does not cover the active network — not blocking"
                ));
                BlockCheck::Absent
            } else {
                BlockCheck::Present(s.to_string())
            }
        }
        _ => BlockCheck::Unknown,
    }
}

/// The Program path our Allow inbound rule points at, if the rule exists.
/// Comparing this against the current exe path catches the "exe was moved or
/// renamed after the rule was created" case: the rule still shows up in the
/// firewall UI but no longer matches this binary, so the phone stays blocked
/// with no visible reason.
#[cfg(windows)]
fn allow_rule_program() -> Option<String> {
    let ps = format!(
        r#"$r = Get-NetFirewallRule -DisplayName '{RULE_ALLOW}' -ErrorAction SilentlyContinue
if ($r) {{ ($r | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue).Program }}"#
    );
    match run_ps(&ps) {
        Some((true, out)) => {
            let s = out.trim().to_string();
            if s.is_empty() {
                None
            } else {
                Some(s)
            }
        }
        _ => None,
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
            // First check whether an applicable Block already exists before
            // startup (left over from last time). The result only sets the
            // initial flag and the diagnostic logs — ALL subsequent rule
            // watching belongs to the fw worker, which is spawned below in
            // every branch.
            match find_block_rule(&exe) {
                BlockCheck::Present(name) => {
                    let allow = allow_rule_program();
                    logf(&format!(
                        "firewall needs repair: found applicable Block inbound rule name={name} (allow rule present={}{})",
                        allow.is_some(),
                        allow.map(|p| format!(", program={p}")).unwrap_or_default()
                    ));
                    // Applicable = enabled AND profile covers the active
                    // network: the phone is certainly blocked right now, so
                    // flag immediately — no grace window, the state itself is
                    // the evidence. The worker's transition logic no-ops on
                    // its first read (flag already set) and keeps watching
                    // for the rule to vanish.
                    mark_need_repair(&app);
                }
                BlockCheck::Unknown => {
                    // Cannot inspect rules right now; do not guess. The
                    // worker's respawn loop keeps retrying the query, and a
                    // phone actually connecting remains the other signal.
                    logw("firewall: could not inspect rules (powershell failed), relying on connection evidence");
                }
                BlockCheck::Absent => {
                    match allow_rule_program() {
                        Some(prog) => {
                            if prog.eq_ignore_ascii_case(&exe) {
                                logf("firewall OK: Allow rule covers this exe, no Block");
                            } else {
                                // The rule exists but was created for another
                                // copy of tinbox (exe moved/renamed). Windows
                                // re-prompts for the new path at bind time;
                                // the worker watches for whatever the user
                                // answers.
                                logf(&format!(
                                    "firewall: Allow rule points at a different exe (rule={prog}, current={exe}); watching for a Block rule"
                                ));
                            }
                        }
                        None => {
                            logf("firewall: no Allow rule yet — the Windows dialog may be up; worker watching for the answer");
                        }
                    }
                }
            }
            // One long-lived worker owns every rule transition from here on:
            // the dialog answer (block appears → flag; allow appears → stand
            // down) and the flagged block's disappearance (flag cleared →
            // overlay down). See spawn_fw_worker for the lifetime policy.
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
///   'block:<DisplayName>' — an applicable enabled Block rule appeared
///   'allow'               — an Allow rule for this exe appeared
///   'none'                — neither (also the initial state at start)
///
/// The Rust side translates transitions into flag moves:
///   → Blocked: flag set (overlay up) — the worker STAYS ALIVE so the
///     overlay closes the moment the rule vanishes;
///   → away from Blocked: flag cleared (overlay down) — the confirm path
///     need_repair() used to throttle at 4s; this closes it within one
///     worker pass (~0.6s);
///   → Allowed with no flag: the dialog will never re-appear for this path,
///     nothing left to watch — worker retires.
/// A 1s Rust tick additionally retires the worker when a LAN device has
/// proven inbound open with no flag (the old watcher's stand-down), so the
/// lifetime is bounded in every case except a dialog hanging unanswered —
/// which is exactly what it must keep watching.
///
/// Robustness: the script self-exits when its parent process dies (an app
/// quit must not leak the child), and an unexpected child death (powershell
/// crashed, AV killed it) respawns after 5s — cost-equivalent to the old
/// confirm throttle and self-healing.
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
  $active = $null
  $block = ''
  $allow = $false
  Get-NetFirewallApplicationFilter -Program $exe -ErrorAction SilentlyContinue | ForEach-Object {{
    $r = $_ | Get-NetFirewallRule -ErrorAction SilentlyContinue
    if ($r -and $r.Enabled -eq 'True' -and $r.Direction -eq 'Inbound') {{
      if ($r.Action -eq 'Block') {{
        if ($null -eq $active) {{
          $active = @((Get-NetConnectionProfile -ErrorAction SilentlyContinue | ForEach-Object {{ $_.NetworkCategory }}) | ForEach-Object {{ if ($_ -eq 'DomainAuthenticated') {{ 'Domain' }} else {{ $_ }} }} | Sort-Object -Unique)
        }}
        $applies = $false
        if ($r.Profile -eq 'Any') {{ $applies = $true }}
        else {{ foreach ($p in (($r.Profile -split ',') | ForEach-Object {{ $_.Trim() }})) {{ if ($active -contains $p) {{ $applies = $true }} }} }}
        if ($applies -and -not $block) {{ $block = $r.DisplayName }}
      }} elseif ($r.Action -eq 'Allow') {{
        $allow = $true
      }}
    }}
  }}
  $s = if ($block) {{ 'block:' + $block }} elseif ($allow) {{ 'allow' }} else {{ 'none' }}
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
                        s if s.starts_with("block:") => {
                            let name = s.strip_prefix("block:").unwrap_or(s);
                            if !PENDING_REPAIR.load(Ordering::SeqCst) {
                                logf(&format!(
                                    "fw worker: applicable Block rule '{name}' appeared, flagging repair"
                                ));
                                mark_need_repair(&app);
                            }
                            // Stay alive: this side now watches for the rule
                            // to vanish (overlay must close when it does).
                        }
                        "allow" => {
                            if PENDING_REPAIR.load(Ordering::SeqCst) {
                                logf("fw worker: Block rule gone (Allow present), clearing repair flag");
                                clear_need_repair();
                            } else {
                                logf("fw worker: Allow rule covers this exe — dialog answered with Allow");
                            }
                            // The dialog will never re-appear for this path;
                            // there is nothing left to watch.
                            policy_dead = true;
                        }
                        "none" => {
                            if PENDING_REPAIR.load(Ordering::SeqCst) {
                                logf("fw worker: applicable Block rule gone, clearing repair flag");
                                clear_need_repair();
                            }
                            // Keep watching: the dialog may still be pending.
                        }
                        _ => {}
                    },
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                    Err(mpsc::RecvTimeoutError::Disconnected) => break, // child died
                }
                if policy_dead {
                    break;
                }
                // Stand-down with no flag: a connected device proved inbound
                // open, so the dialog question is moot. (With the flag set
                // the worker must live on: the overlay waits for the rule to
                // vanish. Evidence clearing the flag is need_repair()'s own
                // branch; the next tick retires the worker then.)
                if !PENDING_REPAIR.load(Ordering::SeqCst)
                    && (crate::server::lan_seen_recently(30)
                        || crate::server::transfer_active_recently(30))
                {
                    logf("fw worker: device connected, inbound proven open — standing down");
                    policy_dead = true;
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
/// hidden powershell — waits for the script's self-delete instead. A
/// cancelled UAC throws inside the launcher → it exits at once, so a refused
/// prompt fails fast instead of stalling through the wait cap. The caller
/// re-checks the rule afterwards either way, so the verdict stays honest.
///
/// Blocks the calling thread: but the frontend modal already covers the UI
/// while the user waits for the repair, so blocking is fine.
#[cfg(windows)]
fn repair_as_admin(exe: &str) -> bool {
    let dir = data_dir();
    let ps1 = dir.join("tinbox_fw_fix.ps1");

    // Self-contained script: delete Block + add Allow, then self-delete the ps1.
    // Note: Get-NetFirewallRule's -DisplayName cannot be combined with
    // -Direction/-Action (different parameter sets).
    let script = format!(
        r#"$exe = '{exe}'
try {{
  Get-NetFirewallRule -Direction Inbound -Action Block -ErrorAction SilentlyContinue | ForEach-Object {{
    $f = $_ | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue
    if ($f -and $f.Program -ieq $exe) {{
      Remove-NetFirewallRule -Name $_.Name -ErrorAction SilentlyContinue
    }}
  }}
  Get-NetFirewallRule -DisplayName '{RULE_ALLOW}' -ErrorAction SilentlyContinue | ForEach-Object {{
    Remove-NetFirewallRule -Name $_.Name -ErrorAction SilentlyContinue
  }}
  # One-time migration: clean up the old (filedrop-era) allow rule to avoid
  # orphaned rules lingering.
  Get-NetFirewallRule -DisplayName 'FileDrop_Allow_Inbound' -ErrorAction SilentlyContinue | ForEach-Object {{
    Remove-NetFirewallRule -Name $_.Name -ErrorAction SilentlyContinue
  }}
  New-NetFirewallRule -DisplayName '{RULE_ALLOW}' -Direction Inbound -Action Allow -Program $exe -Profile Any -ErrorAction Stop | Out-Null
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
    use std::process::Command;
    // ShellExecute with the runas verb + SW_HIDE (the trailing 0): the hidden
    // show-command travels with process creation, so the elevated console is
    // born hidden — no flash. The launcher then waits for the script's
    // self-delete (ShellExecute cannot wait); a cancelled UAC throws and
    // exits the launcher at once (exit 1 → launched=no).
    let launcher = format!(
        "$sh = New-Object -ComObject Shell.Application; \
         try {{ $sh.ShellExecute('powershell.exe', \
         '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File \"{ps1}\"', \
         '', 'runas', 0) }} catch {{ exit 1 }}; \
         $deadline = (Get-Date).AddSeconds(30); \
         while ((Test-Path -LiteralPath '{ps1}') -and ((Get-Date) -lt $deadline)) {{ \
           Start-Sleep -Milliseconds 300 \
         }}",
        ps1 = ps1.to_string_lossy()
    );
    let launched = match Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &launcher])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
    {
        Ok(o) => o.status.success(),
        Err(_) => false,
    };
    // The real success criterion: whether the Block is really gone (the
    // launcher can only report that the launch itself succeeded). An
    // unverifiable outcome is reported as not fixed — the repair may still
    // have worked, and the overlay will close by itself once a device
    // actually connects.
    let fixed = match find_block_rule(exe) {
        BlockCheck::Absent => "yes (success)",
        BlockCheck::Present(_) => "no (still blocked)",
        BlockCheck::Unknown => "unverifiable (check failed)",
    };
    logf(&format!(
        "repair: launched={}, Block removed={}",
        if launched { "yes" } else { "no" },
        fixed
    ));
    fixed == "yes (success)"
}

// Suppress unused warnings on non-Windows.
#[allow(dead_code)]
fn _silence() {
    let _ = Mutex::new(());
    let _ = PathBuf::new();
}
