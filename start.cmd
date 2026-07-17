@echo off
setlocal
chcp 65001 >nul
set "ROOT=%~dp0"
set "STATE=%ROOT%runtime\state\setup.complete.json"
set "URL=http://127.0.0.1:8765"

if not exist "%STATE%" (
  echo Setup has not completed.
  choice /C YN /N /M "Run setup now? [Y/N] "
  if errorlevel 2 exit /b 2
  call "%ROOT%setup.cmd"
  if errorlevel 1 exit /b 1
)

set "PYTHON=%ROOT%runtime\venv\Scripts\python.exe"
if not exist "%PYTHON%" set "PYTHON=%ROOT%runtime\python\python.exe"
if not exist "%PYTHON%" (
  echo Local Python runtime is missing. Run repair.cmd.
  exit /b 2
)

powershell.exe -NoLogo -NoProfile -Command "try { $h=Invoke-RestMethod -Uri '%URL%/health' -TimeoutSec 2; if ($h.service -eq 'android-security-lab') { exit 0 } } catch {}; exit 1"
if not errorlevel 1 (
  start "" "%URL%"
  exit /b 0
)

echo Starting Android Security Lab on %URL%
echo Log: %ROOT%logs\app.log
set "PYTHONPATH=%ROOT%"
start "AndroidSecurityLab" /D "%ROOT%" "%PYTHON%" -m android_assessor web --host 127.0.0.1 --port 8765

powershell.exe -NoLogo -NoProfile -Command "$deadline=(Get-Date).AddSeconds(30); do { try { $h=Invoke-RestMethod -Uri '%URL%/health' -TimeoutSec 2; if ($h.service -eq 'android-security-lab') { Start-Process '%URL%'; exit 0 } } catch {}; Start-Sleep -Milliseconds 500 } while ((Get-Date) -lt $deadline); exit 1"
if errorlevel 1 (
  echo Web server did not become healthy. See "%ROOT%logs\app.log".
  exit /b 1
)
exit /b 0
