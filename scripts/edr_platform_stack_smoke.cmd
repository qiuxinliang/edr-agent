@echo off
:: ASCII-only: cmd.exe misparses UTF-8 without careful codepage. Do not add non-ASCII here.
:: Usage: edr_platform_stack_smoke.cmd
::        edr_platform_stack_smoke.cmd 20
::        set EDR_SMOKE_LOOPS=15  (if no first arg)
cd /d "%~dp0"
if not exist "%~dp0edr_platform_stack_smoke.ps1" (
  echo ERROR: edr_platform_stack_smoke.ps1 not found next to this file: %~dp0
  echo Copy both .cmd and .ps1 from edr-agent\scripts\ into the same folder, then re-run.
  exit /b 1
)
echo [edr_platform_stack_smoke] working dir: %cd%
set "PS=powershell.exe"
if defined EDR_SMOKE_POWERSHELL set "PS=%EDR_SMOKE_POWERSHELL%"
set "IT=%~1"
if "%IT%"=="" set "IT=%EDR_SMOKE_LOOPS%"
if "%IT%"=="" (
  "%PS%" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0edr_platform_stack_smoke.ps1"
) else (
  "%PS%" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0edr_platform_stack_smoke.ps1" -Iterations %IT%
)
exit /b %ERRORLEVEL%
