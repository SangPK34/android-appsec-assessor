@echo off
setlocal
chcp 65001 >nul
set "ROOT=%~dp0"
echo Reinstalling versions pinned in config\tools.lock.json.
echo This command does not discover or install unreviewed latest versions.
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%ROOT%setup.ps1" -Repair -ForceTools %*
exit /b %ERRORLEVEL%
