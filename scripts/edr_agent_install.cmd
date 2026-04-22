@echo off
REM Bypass ExecutionPolicy for this run only; forwards all args to the .ps1 beside this file.
set "PS1=%~dp0edr_agent_install.ps1"
if not exist "%PS1%" (
  echo Missing "%PS1%" >&2
  exit /b 1
)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%PS1%" %*
