@echo off
rem Dev helper: wipe all tinbox firewall rules so the next launch exercises
rem the first-run dialog again. Logic lives in scripts\fw-clean.ps1 — this is
rem only a double-click shim (path-independent via %~dp0).
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\fw-clean.ps1" %*
