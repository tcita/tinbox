@echo off
rem User-side helper: wipe inbound firewall rules for ONE explicitly given
rem tinbox.exe. The exe path is REQUIRED - no auto-detection, so a portable
rem install can never wipe the wrong copy's rules.
rem
rem Logic lives in fw-clean-user.ps1 (same folder) - this is only a
rem double-click shim that forwards the explicit path.
rem
rem Usage:
rem   fw-clean-user.bat "path\to\tinbox.exe"
setlocal
if "%~1"=="" (
  echo [ERROR] exe path is required.
  echo Usage: fw-clean-user.bat "path\to\tinbox.exe"
  echo Example: fw-clean-user.bat "D:\tinbox.exe"
  pause
  exit /b 1
)
set "TARGET=%~1"
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
