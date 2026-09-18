@echo off
rem User-side helper: wipe firewall rules for the ONE tinbox.exe this scripts\
rem folder is placed next to (one level up), without touching any other copy's
rem rules. Logic lives in fw-clean-user.ps1 (same folder) - this is only a
rem double-click shim (path-independent via %~dp0).
rem
rem Located one level up on purpose: Explorer's "Run as administrator" starts
rem the process with cwd=C:\Windows\System32, so a %CD%-relative lookup misses
rem tinbox.exe and the window flashes closed. Put the scripts\ folder next to
rem tinbox.exe, or pass the exe path explicitly.
setlocal
for %%I in ("%~dp0..") do set "PARENT=%%~fI"
if not "%~1"=="" (
  set "TARGET=%~1"
) else (
  set "TARGET=%PARENT%\tinbox.exe"
)
if not exist "%~dp0fw-clean-user.ps1" (
  echo [ERROR] fw-clean-user.ps1 not found next to this bat: %~dp0
  pause
  exit /b 1
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0fw-clean-user.ps1" -Exe "%TARGET%"
set "RC=%ERRORLEVEL%"
if not "%RC%"=="0" (
  echo.
  echo [fw-clean-user] powershell exited with code %RC% - read the error above.
  pause
)
