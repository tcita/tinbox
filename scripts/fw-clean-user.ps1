# User-side helper: remove ONLY the inbound firewall rules pointing at ONE
# tinbox.exe — the copy one level above this scripts\ folder (i.e. next to the
# scripts\ folder itself), or -Exe <path> — so a portable install can be wiped
# without touching any other copy's rules.
# It deliberately never deletes by bare DisplayName: that would nuke another
# path's tinbox_Allow_Inbound (each copy owns only its own rules; see the
# per-path isolation note in src-tauri/src/firewall.rs).
#
# Usage (auto-elevates when needed; output lands in the elevated console):
#   scripts\fw-clean-user.bat ["path\to\tinbox.exe"]
#   powershell -ExecutionPolicy Bypass -File scripts\fw-clean-user.ps1 -Exe <path>
# Close tinbox first if it is running, then relaunch to re-trigger the dialog.

param(
    [string]$Exe = ''
)

# Terminating errors pause here: a double-clicked console (and especially the
# elevated child, which has no bat to fall back on) must never close before
# the red text is readable.
trap {
    Write-Host ('[ERROR] ' + $_.Exception.Message) -ForegroundColor Red
    Read-Host 'Press Enter to close'
    break
}

# --- resolve the single exe to clean up after ---
# Default is the tinbox.exe in the PowerShell's current directory; the bat
# shim always passes an explicit path (one level above the scripts\ folder),
# so this fallback only matters for direct ps1 runs.
if (-not $Exe) {
    $Exe = Join-Path (Get-Location) 'tinbox.exe'
}
if (-not (Test-Path -LiteralPath $Exe)) {
    # Pause before bailing: the elevated launcher runs this script directly, so
    # without this the console (a right-click "Run as administrator" window,
    # whose cwd is System32) would flash closed before the error is readable.
    Write-Host "tinbox.exe not found: $Exe"
    Write-Host 'Put the scripts\ folder next to tinbox.exe, or pass -Exe <path>.'
    Read-Host 'Press Enter to close'
    exit 1
}

# --- removing rules needs admin: self-elevate once and wait ---
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host 'Relaunching elevated (confirm the UAC prompt)...'
    Start-Process powershell.exe -ArgumentList @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"",
        '-Exe', "`"$Exe`""
    ) -Verb RunAs -Wait
    exit
}

function Show-State {
    param([string]$Title)
    Write-Host "`n$Title"
    $rules = @(Get-NetFirewallApplicationFilter -Program $Exe -ErrorAction SilentlyContinue | Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.Direction -eq 'Inbound' })
    if ($rules) {
        $rules | Select-Object DisplayName, Enabled, Direction, Action, Profile | Format-Table -AutoSize
    } else {
        Write-Host '  (none)'
    }
}

Show-State 'Rules BEFORE:'

$removed = 0
Write-Host "`nCleaning: $Exe"
Get-NetFirewallApplicationFilter -Program $Exe -ErrorAction SilentlyContinue | Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.Direction -eq 'Inbound' } | ForEach-Object {
    Remove-NetFirewallRule -Name $_.Name -ErrorAction SilentlyContinue
    $removed++
}
Write-Host "`nRemoved $removed rule(s)."

Show-State 'Rules AFTER:'
Read-Host 'Press Enter to close'
