@echo off
setlocal EnableExtensions
REM No PowerShell: cmd + curl. Put smoke_body.json in the same folder as this file.
REM Example:
REM   set EDR_SMOKE_BASE=http://192.168.1.35:8080/api/v1
REM   set EDR_SMOKE_BEARER=your_jwt
REM   set EDR_SMOKE_TENANT=demo-tenant
REM   smoke_http_ingest.cmd
REM
REM Create smoke_body.json on a dev PC (folder: edr-backend\platform, Go installed):
REM   go run ./cmd/edr-ingest-sample -endpoint YOUR_ENDPOINT_UUID -tenant demo-tenant 1>smoke_body.json
REM Copy smoke_body.json next to this .cmd on the test machine.
REM Or copy smoke_body.json.example to smoke_body.json and set endpoint_id to an enrolled id
REM (inner payload tenant is demo-tenant; for other tenants regenerate with go run above).

if not defined EDR_SMOKE_BASE (
  echo [smoke] SET EDR_SMOKE_BASE=http://host:port/api/v1
  exit /b 1
)
if not defined EDR_SMOKE_BEARER (
  echo [smoke] SET EDR_SMOKE_BEARER=JWT
  exit /b 1
)
if "%EDR_SMOKE_TENANT%"=="" set "EDR_SMOKE_TENANT=demo-tenant"
if "%EDR_SMOKE_USER%"=="" set "EDR_SMOKE_USER=edr-agent"

set "JSON=%~dp0smoke_body.json"
if not exist "%JSON%" (
  echo [smoke] Missing file: %JSON%
  echo [smoke] On dev PC in edr-backend\platform run:
  echo   go run ./cmd/edr-ingest-sample -endpoint YOUR_ENDPOINT_UUID -tenant %EDR_SMOKE_TENANT% 1^>smoke_body.json
  exit /b 1
)

set "B=%EDR_SMOKE_BASE%"
if "%B:~-1%"=="/" set "B=%B:~0,-1%"
set "URL=%B%/ingest/report-events"

where curl.exe >nul 2>&1
if errorlevel 1 (
  echo [smoke] curl.exe not in PATH. Use Windows 10+ curl or Git for Windows.
  exit /b 1
)

echo [smoke] POST %URL%
curl.exe -fsS -w "\nHTTP %%{http_code}\n" -X POST "%URL%" ^
  -H "Content-Type: application/json" ^
  -H "X-Tenant-ID: %EDR_SMOKE_TENANT%" ^
  -H "X-User-ID: %EDR_SMOKE_USER%" ^
  -H "X-Permission-Set: telemetry:write" ^
  -H "Authorization: Bearer %EDR_SMOKE_BEARER%" ^
  --data-binary "@%JSON%"
exit /b %ERRORLEVEL%
