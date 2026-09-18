# Dev helper: remove EVERY firewall rule tied to tinbox (the Allow rule the
# repair creates, any Block/Allow rules from Windows-dialog answers, and
# legacy names), for BOTH debug and release builds, so the next launch
# exercises the full first-run path again:
#   Windows dialog -> Cancel/Allow -> fw worker -> overlay -> repair
#
# Usage (auto-elevates when needed; output lands in the elevated console):
#   powershell -ExecutionPolicy Bypass -File scripts\fw-clean-dev.ps1
#   powershell -ExecutionPolicy Bypass -File scripts\fw-clean-dev.ps1 <path> [<path>...]
# Close tinbox first if it is running, then relaunch to re-trigger the dialog.

param(
    # [string[]], NOT [string]: the default resolution below assigns BOTH
    # build paths; a [string]-constrained variable would collapse the array
    # into one space-joined string and the Program filter would match
    # nothing ("Removed 0" while rules exist).
    #
    # ValueFromRemainingArguments: the self-elevating relaunch passes the paths
    # POSITIONALLY. Passing them as repeated -Exe <p> is a hard error
    # ("parameter 'Exe' is specified more than once") that fires during
    # parameter binding -- before the script body and its trap -- so the
    # elevated window would flash red and close. Positional args bind here
    # instead; a normal "-Exe <p>" invocation still works.
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Exe = @()
)

# Terminating errors pause here: a double-clicked console (and especially the
# elevated child, which has no bat to fall back on) must never close before
# the red text is readable.
trap {
    Write-Host ('[ERROR] ' + $_.Exception.Message) -ForegroundColor Red
    Read-Host 'Press Enter to close'
    break
}

# --- resolve the exe path(s) to clean up after ---
# Both debug and release builds are cleaned: the running exe may be either,
# and cleaning only one leaves the other's rules suppressing the first-run
# dialog silently. $PSScriptRoot is the scripts/ folder; the repo root is
# its parent.
if (-not $Exe) {
    $repoRoot = Split-Path -Parent $PSScriptRoot
    $Exe = @(
        (Join-Path $repoRoot 'src-tauri\target\release\tinbox.exe'),
        (Join-Path $repoRoot 'src-tauri\target\debug\tinbox.exe')
    ) | Where-Object { Test-Path -LiteralPath $_ }
}
if (-not $Exe) {
    Write-Host 'tinbox.exe not found under src-tauri\target (build with cargo first, or pass -Exe <path>)'
    exit 1
}

# --- removing rules needs admin: self-elevate once and wait ---
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host 'Relaunching elevated (confirm the UAC prompt)...'
    $psArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
    foreach ($e in $Exe) { $psArgs += "`"$e`"" }
    Start-Process powershell.exe -ArgumentList $psArgs -Verb RunAs -Wait
    exit
}

function Show-State {
    param([string]$Title, [string[]]$ExePaths)
    Write-Host "`n$Title"
    $all = @()
    foreach ($p in $ExePaths) {
        $all += @(Get-NetFirewallApplicationFilter -Program $p -ErrorAction SilentlyContinue | Get-NetFirewallRule)
    }
    $all += @(Get-NetFirewallRule -DisplayName 'tinbox_Allow_Inbound', 'FileDrop_Allow_Inbound' -ErrorAction SilentlyContinue)
    $all = $all | Sort-Object DisplayName -Unique
    if ($all) {
        $all | Select-Object DisplayName, Enabled, Direction, Action, Profile | Format-Table -AutoSize
    } else {
        Write-Host '  (none)'
    }
}

Show-State 'Rules BEFORE:' -ExePaths $Exe

$removed = 0
foreach ($exePath in @($Exe)) {
    Write-Host "`nCleaning: $exePath"
    Get-NetFirewallApplicationFilter -Program $exePath -ErrorAction SilentlyContinue | Get-NetFirewallRule | ForEach-Object {
        Remove-NetFirewallRule -Name $_.Name -ErrorAction SilentlyContinue
        $removed++
    }
}
Get-NetFirewallRule -DisplayName 'tinbox_Allow_Inbound', 'FileDrop_Allow_Inbound' -ErrorAction SilentlyContinue | ForEach-Object {
    Remove-NetFirewallRule -Name $_.Name -ErrorAction SilentlyContinue
    $removed++
}
Write-Host "`nRemoved $removed rule(s)."

Show-State 'Rules AFTER:' -ExePaths $Exe
Read-Host 'Press Enter to close'
