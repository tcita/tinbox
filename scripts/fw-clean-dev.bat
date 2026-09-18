@echo off
rem Dev helper: wipe all tinbox firewall rules so the next launch exercises
rem the first-run dialog again. Logic lives in fw-clean-dev.ps1 (same folder) -
rem this is only a double-click shim (path-independent via %~dp0).
setlocal
if not exist "%~dp0fw-clean-dev.ps1" (
  echo [ERROR] fw-clean-dev.ps1 not found next to this bat: %~dp0
  pause
  exit /b 1
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0fw-clean-dev.ps1" %*
set "RC=%ERRORLEVEL%"
if not "%RC%"=="0" (
  echo.
  echo [fw-clean] powershell exited with code %RC% - read the error above.
  pause
)
