@echo off
setlocal
chcp 65001 >nul
set "ROOT=%~dp0"
set "PYTHON=%ROOT%runtime\venv\Scripts\python.exe"
if not exist "%PYTHON%" set "PYTHON=%ROOT%runtime\python\python.exe"

if not exist "%PYTHON%" (
  echo Local Python runtime is missing. Run setup.cmd first.
  exit /b 2
)

set "PYTHONPATH=%ROOT%"
"%PYTHON%" -m android_assessor %*
exit /b %ERRORLEVEL%
