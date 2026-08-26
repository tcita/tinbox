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
//   3. schedule_post_startup_check(): poll for ~30s after startup - because
//      the Windows firewall dialog only appears at bind time, and ensure() runs
//      before bind, it cannot detect a block created "this run". Polling lets
//      us pop the repair dialog within seconds of the user creating a block
//      with a Cancel click, so the session is not wasted.
//
// A temp .ps1 file is used instead of passing the script via -ArgumentList to
// avoid quotes/braces being mangled while being passed on the command line.
// Only takes effect on Windows; a no-op on other platforms.
use crate::logger::logf;
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
fn run_ps(script: &str) -> Option<(bool, String)> {
    use std::os::windows::process::CommandExt;
    use std::process::Command;
    let out = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .creation_flags(CREATE_NO_WINDOW)
        .output();
    match out {
        Ok(o) => {
            let ok = o.status.success();
            if !ok {
                let err = String::from_utf8_lossy(&o.stderr);
                logf(&format!("ps failed: stderr={}", err.trim()));
            }
            Some((ok, String::from_utf8_lossy(&o.stdout).to_string()))
        }
        Err(e) => {
            logf(&format!("could not launch powershell: {}", e));
            None
        }
    }
}

/// Whether a Block inbound rule exists for our own exe; returns the matched
/// rule name.
#[cfg(windows)]
fn find_block_rule(exe: &str) -> Option<String> {
    let ps = format!(
        r#"$exe = '{exe}'
$name = ''
Get-NetFirewallRule -Direction Inbound -Action Block -ErrorAction SilentlyContinue | ForEach-Object {{
  $f = $_ | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue
  if ($f -and $f.Program -ieq $exe) {{ $name = $_.DisplayName }}
}}
$name"#
    );
    match run_ps(&ps) {
        Some((true, out)) => {
            let s = out.trim();
            if s.is_empty() {
                None
            } else {
                Some(s.to_string())
            }
        }
        _ => None,
    }
}

/// Whether our own Allow inbound rule exists (read-only).
#[cfg(windows)]
fn has_allow_rule() -> bool {
    let ps = format!(
        "[bool](Get-NetFirewallRule -DisplayName '{RULE_ALLOW}' -ErrorAction SilentlyContinue)"
    );
    matches!(run_ps(&ps), Some((true, ref s)) if s.trim().eq_ignore_ascii_case("true"))
}

static PENDING_REPAIR: AtomicBool = AtomicBool::new(false);

/// Entry point: run the firewall check in the background, without blocking
/// setup/window creation (otherwise a cold powershell start can hang for
/// seconds). A detected Block -> flag PENDING_REPAIR and bring the window to
/// the front; the frontend polls /fw-status to show the HTML repair overlay.
/// No Block but missing Allow -> poll after startup (wait for the Windows
/// dialog to be answered).
pub fn ensure_background(app: AppHandle) {
    #[cfg(windows)]
    {
        std::thread::spawn(move || {
            let Some(exe) = exe_path() else {
                logf("firewall: could not get exe path, skipping");
                return;
            };
            // First check whether a Block already exists before startup
            // (left over from last time).
            if let Some(name) = find_block_rule(&exe) {
                let has_allow = has_allow_rule();
                logf(&format!(
                    "firewall needs repair: found Block inbound rule name={name} (allow coexists={has_allow})"
                ));
                mark_need_repair(&app);
                return; // pre-existing block: the frontend shows the overlay, stop polling.
            }
            if has_allow_rule() {
                logf("firewall OK: Allow exists, no Block");
                return;
            }
            // No Allow and no Block: Windows only asks at bind time, so poll
            // after startup waiting for the user's answer to the dialog.
            logf("firewall: no Allow rule yet, polling after startup for the Windows dialog");
            post_startup_poll(&app, &exe);
        });
    }
    #[cfg(not(windows))]
    {
        let _ = app;
    }
}

/// Poll after startup: the Windows firewall dialog only appears at bind time,
/// so a block created this run cannot be detected up front. Check every 3s for
/// ~30s; as soon as a block appears, flag that repair is needed (the frontend
/// shows the overlay).
#[cfg(windows)]
fn post_startup_poll(app: &AppHandle, exe: &str) {
    // Give the Windows dialog a moment to appear and be answered.
    std::thread::sleep(std::time::Duration::from_secs(2));
    for _ in 0..10 {
        if PENDING_REPAIR.load(Ordering::SeqCst) {
            return;
        }
        if let Some(name) = find_block_rule(exe) {
            logf(&format!(
                "post-startup poll found Block inbound rule name={name}, flagging repair"
            ));
            mark_need_repair(app);
            return;
        }
        std::thread::sleep(std::time::Duration::from_secs(3));
    }
    // No block within 30s: the user most likely clicked Allow or no dialog
    // appeared, which is fine.
}

/// Flag that repair is needed and bring the window to the front so the user is
/// sure to see the frontend's HTML repair overlay (not hidden behind
/// minimize/occlusion).
#[cfg(windows)]
fn mark_need_repair(app: &AppHandle) {
    PENDING_REPAIR.store(true, Ordering::SeqCst);
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.unminimize();
        let _ = w.set_focus();
        let _ = w.set_always_on_top(true);
    }
}

/// Queried by the frontend: whether the firewall repair overlay should be
/// shown. Actually re-checks whether the Block rule still exists (instead of
/// relying on a cached flag), so the overlay correctly disappears after a
/// successful repair.
pub fn need_repair() -> bool {
    #[cfg(windows)]
    {
        let Some(exe) = exe_path() else { return false; };
        // A false flag returns immediately (avoids invoking powershell every
        // time); when true, confirm with a real check.
        if !PENDING_REPAIR.load(Ordering::SeqCst) {
            return false;
        }
        let still_blocked = find_block_rule(&exe).is_some();
        if !still_blocked {
            // Block is gone (repair succeeded): clear the flag.
            PENDING_REPAIR.store(false, Ordering::SeqCst);
        }
        still_blocked
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
        logf("repair: failed to write temp ps1");
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
    // criterion: whether the Block still exists. If it does, the repair failed
    // (UAC cancelled or script failed).
    let fixed = find_block_rule(exe).is_none();
    logf(&format!(
        "repair: launched={}, Block removed={}",
        if launched { "yes" } else { "no" },
        if fixed { "yes (success)" } else { "no (not fixed)" }
    ));
    fixed
}

// Suppress unused warnings on non-Windows.
#[allow(dead_code)]
fn _silence() {
    let _ = Mutex::new(());
    let _ = PathBuf::new();
}
