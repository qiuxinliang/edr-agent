#Requires -Version 5.1
# Export qa_smoke_stats_by_10m_ip.sql -> UTF-8 text (mysql stdout). mysql client in PATH, or -MysqlBin.
# Example:
#   powershell -NoP -File qa_smoke_stats_export.ps1 -EndpointIp 192.168.64.2 -HoursAgo 2 -MysqlHost 192.168.1.35 -MysqlUser root -MysqlDatabase edr -MysqlPassword "secret"
param(
    [string] $MysqlHost = "192.168.1.35",
    [int] $MysqlPort = 3306,
    [string] $MysqlUser = "root",
    [string] $MysqlDatabase = "edr",
    [string] $MysqlPassword = "",
    [string] $EndpointIp = "192.168.64.2",
    [int] $HoursAgo = 4,
    [string] $OutDir = "",
    [string] $MysqlBin = "mysql"
)

$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$sqlPath = Join-Path $here "qa_smoke_stats_by_10m_ip.sql"
if (-not (Test-Path -LiteralPath $sqlPath)) {
    Write-Error "Missing: $sqlPath"
    exit 1
}

$raw = Get-Content -LiteralPath $sqlPath -Raw -Encoding UTF8
$raw = $raw -replace "(?m)^SET @ip = '[^']*';\s*\r?\n", ""
$raw = $raw -replace "(?m)^SET @hours_ago = \d+;\s*\r?\n", ""
$ipEsc = $EndpointIp -replace "'", "''"
$header = "SET NAMES utf8mb4;`r`nSET @ip = '$ipEsc';`r`nSET @hours_ago = $HoursAgo;`r`n"
$scriptSql = $header + $raw

if (-not $OutDir) { $OutDir = Join-Path $here "exports" }
if (-not (Test-Path -LiteralPath $OutDir)) {
    New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
}
$ts = Get-Date -Format "yyyyMMdd_HHmmss"
$safeIp = $EndpointIp -replace '\.', '_'
$outFile = Join-Path $OutDir ("smoke_stats_by10m_{0}_{1}.txt" -f $safeIp, $ts)

$arg = "-h$MysqlHost -P$MysqlPort -u$MysqlUser $MysqlDatabase --default-character-set=utf8mb4"
if ($MysqlPassword) { $arg = "-h$MysqlHost -P$MysqlPort -u$MysqlUser -p$MysqlPassword $MysqlDatabase --default-character-set=utf8mb4" }

$p = New-Object System.Diagnostics.ProcessStartInfo
$p.FileName = $MysqlBin
$p.Arguments = $arg
$p.UseShellExecute = $false
$p.RedirectStandardInput = $true
$p.RedirectStandardOutput = $true
$p.RedirectStandardError = $true
$proc = [System.Diagnostics.Process]::Start($p)
$proc.StandardInput.Write($scriptSql)
$proc.StandardInput.Close()
$out = $proc.StandardOutput.ReadToEnd()
$err = $proc.StandardError.ReadToEnd()
$proc.WaitForExit()
if ($proc.ExitCode -ne 0) {
    Write-Host $err -ForegroundColor Red
    exit $proc.ExitCode
}
[System.IO.File]::WriteAllText($outFile, $out, [System.Text.UTF8Encoding]::new($false))
Write-Host "Wrote: $outFile" -ForegroundColor Green
exit 0
