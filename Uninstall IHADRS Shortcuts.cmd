@echo off
setlocal
set "ROOT=%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%ROOT%scripts\windows\Uninstall-IHADRS-Shortcuts.ps1"
echo.
pause
