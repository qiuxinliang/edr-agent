@echo off
:: Export smoke 10m stats to edr-agent\scripts\exports\ — edit vars below, then run.
setlocal
cd /d "%~dp0"
set "PS=powershell.exe"
if defined EDR_SMOKE_POWERSHELL set "PS=%EDR_SMOKE_POWERSHELL%"

set "MYSQL_HOST=192.168.1.35"
set "MYSQL_PORT=3306"
set "MYSQL_USER=root"
set "MYSQL_DB=edr"
set "MYSQL_PWD="
set "ENDPOINT_IP=192.168.64.2"
set "HOURS_AGO=4"

"%PS%" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0qa_smoke_stats_export.ps1" ^
  -MysqlHost "%MYSQL_HOST%" -MysqlPort %MYSQL_PORT% -MysqlUser "%MYSQL_USER%" -MysqlDatabase "%MYSQL_DB%" ^
  -MysqlPassword "%MYSQL_PWD%" -EndpointIp "%ENDPOINT_IP%" -HoursAgo %HOURS_AGO%
exit /b %ERRORLEVEL%
