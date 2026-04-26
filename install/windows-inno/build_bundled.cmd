@echo off
setlocal
cd /d "%~dp0"

set "ISCC=%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe"
if not exist "%ISCC%" set "ISCC=%ProgramFiles%\Inno Setup 6\ISCC.exe"
if not exist "%ISCC%" (
  echo [ERROR] Inno Setup 6 not found. Install from https://jrsoftware.org/isinfo.php
  echo Then re-run this script, or set ISCC to the full path of ISCC.exe
  exit /b 1
)

set "VER=2.2.0"
if not "%~1"=="" set "VER=%~1"

echo Using ISCC: %ISCC%
echo AppVersion: %VER%
echo.

"%ISCC%" /DMyAppVersion=%VER% "%~dp0EDRAgentSetup.bundled.iss"
if errorlevel 1 exit /b 1

echo.
echo OK: %~dp0Output\EDRAgentSetup-bundled.exe
exit /b 0
