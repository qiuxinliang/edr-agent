@echo off
setlocal
cd /d "%~dp0"

set "VER=%~1"
if "%VER%"=="" if exist "%~dp0..\..\VERSION" set /p VER=<"%~dp0..\..\VERSION"
if "%VER%"=="" (
  echo [ERROR] AppVersion not provided and VERSION was not found.
  echo Usage: build_bundled.cmd 3.2.0 [staged-bin-dir]
  exit /b 1
)

echo AppVersion: %VER%
echo.

if "%~2"=="" (
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Build-BundledInstaller.ps1" -AppVersion "%VER%"
) else (
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Build-BundledInstaller.ps1" -AppVersion "%VER%" -BinDir "%~2"
)
exit /b %ERRORLEVEL%
