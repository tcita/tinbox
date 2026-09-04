// Windows firewall self-handling: solves the "first-run dialog dismissed with
// Cancel -> a Block inbound rule is created -> the phone can never connect,
// and a normal user cannot delete the Block rule from the 'Allow an app
// through Windows Firewall' screen" problem.
//
// Mechanism (normal privileges can only read rules; New/Remove need admin):
//   1. ensure(): read-only detection before startup - is there a Block rule
//      targeting our own exe (left over from a previous session)? If so, flag
//      PENDING_REPAIR. Also read the result file left by the last repair and
//      log it.
//   2. prompt_repair_if_needed(): once the window is ready, if repair was
//      flagged, show a MessageBox (Yes/No); clicking "Yes" writes a temp .ps1
//      and triggers Start-Process -Verb RunAs to elevate and execute it:
//      delete all Block rules for our exe and add one Allow rule. Rule changes
//      take effect immediately, so the phone connects within the same session.
//   3. schedule_post_startup_check(): poll for ~45s after startup (~1.5s
//      cadence) - because the Windows firewall dialog only appears at bind
//      time, and ensure() runs before bind, it cannot detect a block created
//      "this run". Polling lets us pop the repair dialog within a second or
//      two of the user creating a block with a Cancel click, so the session is
//      not wasted. The flag is also pushed over the SSE channel so the
//      frontend overlay appears immediately.
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

/// Look for a Block inbound rule for our own exe. Filters by program first
/// (one indexed query) instead of walking every inbound Block rule and
/// fetching its filter one by one — the latter takes seconds, which directly
/// adds to the detection latency.
#[cfg(windows)]
fn find_block_rule(exe: &str) -> BlockCheck {
    let ps = format!(
        r#"$exe = '{exe}'
$name = ''
Get-NetFirewallApplicationFilter -Program $exe -ErrorAction SilentlyContinue | ForEach-Object {{
  $r = $_ | Get-NetFirewallRule -ErrorAction SilentlyContinue
  if ($r -and $r.Direction -eq 'Inbound' -and $r.Action -eq 'Block') {{ $name = $r.DisplayName }}
}}
$name"#
    );
    match run_ps(&ps) {
        Some((true, out)) => {
            let s = out.trim();
            if s.is_empty() {
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

/// Rate limit for the confirmatory rule re-checks in need_repair(): while the
/// repair overlay is up, the background monitor re-checks every couple of
/// seconds; re-running powershell on every check is wasteful.
static LAST_RULE_CHECK: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

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
            // First check whether a Block already exists before startup
            // (left over from last time).
            match find_block_rule(&exe) {
                BlockCheck::Present(name) => {
                    let allow = allow_rule_program();
                    logf(&format!(
                        "firewall needs repair: found Block inbound rule name={name} (allow rule present={}{})",
                        allow.is_some(),
                        allow.map(|p| format!(", program={p}")).unwrap_or_default()
                    ));
                    mark_need_repair(&app);
                    return; // pre-existing block: the frontend shows the overlay, stop polling.
                }
                BlockCheck::Unknown => {
                    // Cannot inspect rules; do not guess. The repair overlay
                    // stays off, and a phone actually connecting remains the
                    // only (and sufficient) signal that inbound works.
                    logw("firewall: could not inspect rules (powershell failed), relying on connection evidence");
                    return;
                }
                BlockCheck::Absent => {}
            }
            match allow_rule_program() {
                Some(prog) => {
                    if prog.eq_ignore_ascii_case(&exe) {
                        logf("firewall OK: Allow rule covers this exe, no Block");
                    } else {
                        // The rule exists but was created for another copy of
                        // tinbox (exe moved/renamed). This alone is not "the
                        // phone is blocked": Windows re-prompts for the new
                        // path at bind time, and if the user clicks Allow a
                        // rule for this path appears; if they cancel, a Block
                        // rule appears and the poll below flags it — which the
                        // need_repair() Block check then confirms. So: log it,
                        // keep watching, do not raise the overlay on a guess.
                        logf(&format!(
                            "firewall: Allow rule points at a different exe (rule={prog}, current={exe}); watching for a Block rule"
                        ));
                        post_startup_poll(&app, &exe);
                    }
                }
                None => {
                    // No Allow and no Block: Windows only asks at bind time, so
                    // poll after startup waiting for the user's answer to the
                    // dialog.
                    logf("firewall: no Allow rule yet, polling after startup for the Windows dialog");
                    post_startup_poll(&app, &exe);
                }
            }
        });
    }
    #[cfg(not(windows))]
    {
        let _ = app;
    }
}

/// Poll after startup: the Windows firewall dialog only appears at bind time,
/// so a block created this run cannot be detected up front. Check every ~1.5s
/// (1s sleep + the powershell run itself) for ~45s; as soon as a block
/// appears, flag that repair is needed and push an event so the frontend shows
/// the overlay immediately instead of waiting for its next poll.
#[cfg(windows)]
fn post_startup_poll(app: &AppHandle, exe: &str) {
    for _ in 0..30 {
        if PENDING_REPAIR.load(Ordering::SeqCst) {
            return;
        }
        if let BlockCheck::Present(name) = find_block_rule(exe) {
            logf(&format!(
                "post-startup poll found Block inbound rule name={name}, flagging repair"
            ));
            mark_need_repair(app);
            return;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    // No block within the window: the user most likely clicked Allow or no
    // dialog appeared, which is fine.
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

/// Queried by the frontend: whether the firewall repair overlay should be
/// shown.
///
/// Two signals decide this, in order of trustworthiness:
///   1. Positive evidence: a LAN device's requests still arriving is proof
///      that inbound is open, whatever the rules say. It clears the flag and
///      closes the overlay — including after a repair whose result could not
///      be confirmed by inspection.
///   2. Rule inspection: a confirmed Block keeps the overlay up; a confirmed
///      Absent clears it. An Unknown check (powershell failed) does NOT clear
///      the flag — the overlay stays until positive evidence arrives, because
///      "could not verify" is not "verified fine".
pub fn need_repair() -> bool {
    #[cfg(windows)]
    {
        // Positive evidence also includes bytes flowing to a phone mid-download:
        // a request that opens a Range stream proved inbound is open, and a
        // transfer can then hold that stream for many seconds with no new
        // requests arriving (which lan_seen_recently alone would miss).
        if crate::server::lan_seen_recently(30)
            || crate::server::transfer_active_recently(30)
        {
            PENDING_REPAIR.store(false, Ordering::SeqCst);
            return false;
        }
        let Some(exe) = exe_path() else {
            return PENDING_REPAIR.load(Ordering::SeqCst);
        };
        // A false flag returns immediately (avoids invoking powershell every
        // time); when true, confirm with a real check.
        if !PENDING_REPAIR.load(Ordering::SeqCst) {
            return false;
        }
        // Throttle: the monitor loop calls this every 1s (the result is pushed
        // to clients as an SSE `fw` event), so one powershell check per 4s is
        // plenty; interim callers just re-read the pending flag.
        let now = now_unix();
        let last = LAST_RULE_CHECK.load(Ordering::SeqCst);
        if now.saturating_sub(last) < 4 {
            return true;
        }
        LAST_RULE_CHECK.store(now, Ordering::SeqCst);
        match find_block_rule(&exe) {
            BlockCheck::Absent => {
                // Block is gone (repair succeeded): clear the flag.
                PENDING_REPAIR.store(false, Ordering::SeqCst);
                false
            }
            // Still blocked, or cannot verify: keep the overlay. In the
            // Unknown case a phone connecting remains the way out.
            _ => true,
        }
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

/// Write a temp .ps1 and use Start-Process -Verb RunAs -Wait to trigger an
/// elevated UAC run: delete all Block rules for our exe and add one Allow rule.
/// -Wait blocks until the script ends (= UAC grant + Block removal done);
/// before returning, re-check whether the Block is really gone so the frontend
/// gets a definite result instead of guessing/ polling.
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
    // -Wait: block until the elevated script ends (it only runs after the UAC
    // grant and returns once done).
    // -WindowStyle Hidden: keep the elevated PowerShell window hidden, leaving
    // only the UAC box.
    let launcher = format!(
        "Start-Process powershell.exe -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-WindowStyle','Hidden','-File','{}' -Verb RunAs -Wait",
        ps1.to_string_lossy()
    );
    let launched = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &launcher])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .is_ok();
    // If the launch failed (user cancelled UAC), the launcher's Start-Process
    // errors and output is still returned but non-zero. The real success
    // criterion: whether the Block is really gone. An unverifiable outcome is
    // reported as not fixed — the repair may still have worked, and the
    // overlay will close by itself once a device actually connects.
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
