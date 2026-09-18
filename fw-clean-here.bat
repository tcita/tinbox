@echo off
rem User/test helper: wipe firewall rules for the ONE tinbox.exe this bat sits
rem next to, without touching any other copy's rules. Logic lives in
rem scripts\fw-clean-here.ps1 - this is only a double-click shim
rem (path-independent via %~dp0).
rem
rem Anchored to %~dp0 on purpose: Explorer's "Run as administrator" starts the
rem process with cwd=C:\Windows\System32, so a %CD%-relative lookup misses
rem tinbox.exe and the window flashes closed. Put this bat (and scripts\) next
rem to tinbox.exe, or pass the exe path explicitly.
setlocal
if not "%~1"=="" (
  set "TARGET=%~1"
) else (
  set "TARGET=%~dp0tinbox.exe"
)
if not exist "%~dp0scripts\fw-clean-here.ps1" (
  echo [ERROR] scripts\fw-clean-here.ps1 not found next to this bat: %~dp0scripts\
  pause
  exit /b 1
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\fw-clean-here.ps1" -Exe "%TARGET%"
set "RC=%ERRORLEVEL%"
if not "%RC%"=="0" (
  echo.
  echo [fw-clean-here] powershell exited with code %RC% - read the error above.
  pause
)
