# Dev helper: remove EVERY firewall rule tied to tinbox (the Allow rule the
# repair creates, any Block rules from cancelled dialogs, and legacy names),
# so the next launch exercises the full first-run path again:
#   Windows dialog -> Cancel/Allow -> fw worker -> overlay -> repair
#
# Usage (auto-elevates when needed; output lands in the elevated console):
#   powershell -ExecutionPolicy Bypass -File scripts\fw-clean.ps1
#   powershell -ExecutionPolicy Bypass -File scripts\fw-clean.ps1 -Exe <path>
# Close tinbox first if it is running, then relaunch to re-trigger the dialog.

param(
    [string]$Exe = ''
)

# --- resolve the exe to clean up after (debug/release, whichever exists) ---
# $PSScriptRoot is the scripts/ folder; the repo root is its parent.
if (-not $Exe) {
    $repoRoot = Split-Path -Parent $PSScriptRoot
    $candidates = @(
        (Join-Path $repoRoot 'src-tauri\target\release\tinbox.exe'),
        (Join-Path $repoRoot 'src-tauri\target\debug\tinbox.exe')
    )
    foreach ($c in $candidates) {
        if (Test-Path -LiteralPath $c) { $Exe = $c; break }
    }
}
if (-not $Exe) {
    Write-Host 'tinbox.exe not found under src-tauri\target (build with cargo first, or pass -Exe <path>)'
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
    $byExe = Get-NetFirewallApplicationFilter -Program $Exe -ErrorAction SilentlyContinue | Get-NetFirewallRule
    $byName = Get-NetFirewallRule -DisplayName 'tinbox_Allow_Inbound', 'FileDrop_Allow_Inbound' -ErrorAction SilentlyContinue
    $all = @($byExe) + @($byName) | Sort-Object DisplayName -Unique
    if ($all) {
        $all | Select-Object DisplayName, Enabled, Direction, Action, Profile | Format-Table -AutoSize
    } else {
        Write-Host '  (none)'
    }
}

Show-State 'Rules BEFORE:'
$ExePath = $Exe

$removed = 0
Get-NetFirewallApplicationFilter -Program $ExePath -ErrorAction SilentlyContinue | Get-NetFirewallRule | ForEach-Object {
    Remove-NetFirewallRule -Name $_.Name -ErrorAction SilentlyContinue
    $removed++
}
Get-NetFirewallRule -DisplayName 'tinbox_Allow_Inbound', 'FileDrop_Allow_Inbound' -ErrorAction SilentlyContinue | ForEach-Object {
    Remove-NetFirewallRule -Name $_.Name -ErrorAction SilentlyContinue
    $removed++
}
Write-Host "`nRemoved $removed rule(s)."

Show-State 'Rules AFTER:'
Read-Host 'Press Enter to close'
