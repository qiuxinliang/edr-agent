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

set "VER=%~1"
if "%VER%"=="" if exist "%~dp0..\..\VERSION" set /p VER=<"%~dp0..\..\VERSION"
if "%VER%"=="" (
  echo [ERROR] AppVersion not provided and VERSION was not found.
  echo Usage: build_bundled.cmd 3.2.0
  exit /b 1
)

echo Using ISCC: %ISCC%
echo AppVersion: %VER%
echo.

"%ISCC%" /DMyAppVersion=%VER% "%~dp0EDRAgentSetup.bundled.iss"
if errorlevel 1 exit /b 1

echo.
echo OK: %~dp0Output\FDSecuritySetup-bundled.exe
copy /Y "%~dp0Output\FDSecuritySetup-bundled.exe" "%~dp0Output\EDRAgentSetup-bundled.exe" >nul
if errorlevel 1 exit /b 1
echo OK: legacy compatibility alias: %~dp0Output\EDRAgentSetup-bundled.exe
exit /b 0
