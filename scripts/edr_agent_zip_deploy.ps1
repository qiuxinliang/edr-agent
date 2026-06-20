#Requires -Version 5.1
<#
.SYNOPSIS
  Copy an unpacked Windows zip package into the install directory and run FDSensor.exe --install.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\scripts\edr_agent_zip_deploy.ps1 `
    -ApiBase "https://edr.example.com:8080" -EnrollToken "<token>" -TrustCa
#>
param(
  [Parameter(Mandatory = $true)]
  [string]$ApiBase,
  [Parameter(Mandatory = $true)]
  [string]$EnrollToken,
  [string]$InstallDir = "C:\Program Files\FDSecurity",
  [ValidateSet("service", "autorun", "none")]
  [string]$RuntimeMode = "service",
  [string]$ServiceName = "FDSecurityAgent",
  [switch]$TrustCa,
  [switch]$ForceEnroll,
  [switch]$EnableResponseActions,
  [string]$ExpectedAgentSha256 = $(if ($env:EDR_EXPECTED_AGENT_SHA256) { $env:EDR_EXPECTED_AGENT_SHA256 } else { "" }),
  [switch]$KeepOfflineQueue,
  [switch]$KeepEvidenceCache,
  [switch]$SkipPreflight,
  [switch]$NoCopy
)

$ErrorActionPreference = "Stop"

function Assert-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p = New-Object Security.Principal.WindowsPrincipal($id)
  if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run from an elevated PowerShell session."
  }
}

function Get-PackageRoot {
  $scriptDir = Split-Path -Parent $PSCommandPath
  if ((Split-Path -Leaf $scriptDir) -ieq "scripts") {
    return (Split-Path -Parent $scriptDir)
  }
  return $scriptDir
}

function Assert-FileSha256 {
  param([string]$Path, [string]$Expected)
  $Expected = ($Expected -replace '\s+', '').ToLowerInvariant()
  if (-not $Expected) { return }
  if (-not (Test-Path -LiteralPath $Path)) {
    throw "Hash check failed: file not found: $Path"
  }
  $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
  if ($actual -ne $Expected) {
    throw "Hash check failed for $Path. expected=$Expected actual=$actual"
  }
  Write-Host "SHA256 verified: $Path"
}

function Write-DeployReport {
  param([string]$InstallDir, [object]$Report)
  try {
    $logDir = Join-Path $InstallDir "logs"
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    $path = Join-Path $logDir "zip-deploy-report.json"
    [System.IO.File]::WriteAllText(([System.IO.Path]::GetFullPath($path)), ($Report | ConvertTo-Json -Depth 6))
    Write-Host "Deploy report: $path"
  } catch {
    Write-Warning ("failed to write deploy report: " + $_)
  }
}

Assert-Admin
$packageRoot = Get-PackageRoot

if (-not $SkipPreflight) {
  $preflight = Join-Path $packageRoot "scripts\edr_agent_preflight.ps1"
  if (-not (Test-Path -LiteralPath $preflight)) {
    $preflight = Join-Path $packageRoot "edr_agent_preflight.ps1"
  }
  if (Test-Path -LiteralPath $preflight) {
    $preArgs = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $preflight,
      "-InstallDir", $InstallDir, "-ServiceName", $ServiceName)
    if ($KeepOfflineQueue) { $preArgs += "-KeepOfflineQueue" }
    if ($KeepEvidenceCache) { $preArgs += "-KeepEvidenceCache" }
    & powershell.exe @preArgs
    if ($LASTEXITCODE -ne 0) {
      throw "EDR preflight failed with exit code $LASTEXITCODE"
    }
  } else {
    Write-Warning "edr_agent_preflight.ps1 not found; falling back to built-in runtime stop"
    Stop-Process -Name FDSensor -Force -ErrorAction SilentlyContinue
    Stop-Process -Name edr_agent -Force -ErrorAction SilentlyContinue
  }
}

New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null

$rootFull = [System.IO.Path]::GetFullPath($packageRoot).TrimEnd([char]'\')
$installFull = [System.IO.Path]::GetFullPath($InstallDir).TrimEnd([char]'\')
if (-not $NoCopy -and ($rootFull -ine $installFull)) {
  $exclude = @("agent.toml", "queue", "evidence", "logs", "forensic", "isolation")
  Get-ChildItem -LiteralPath $packageRoot -Force | Where-Object {
    $exclude -notcontains $_.Name
  } | ForEach-Object {
    Copy-Item -LiteralPath $_.FullName -Destination $InstallDir -Recurse -Force
  }
}

$exe = Join-Path $InstallDir "FDSensor.exe"
if (-not (Test-Path -LiteralPath $exe)) {
  $legacyExe = Join-Path $InstallDir "edr_agent.exe"
  if (Test-Path -LiteralPath $legacyExe) {
    Copy-Item -LiteralPath $legacyExe -Destination $exe -Force
    Write-Warning "FDSensor.exe was missing; created compatibility alias from edr_agent.exe."
  } else {
    throw "FDSensor.exe not found after package copy: $exe"
  }
}
$shaSidecar = Join-Path $packageRoot "FDSensor.exe.sha256"
if (-not (Test-Path -LiteralPath $shaSidecar)) {
  $shaSidecar = Join-Path $packageRoot "edr_agent.exe.sha256"
}
if (-not $ExpectedAgentSha256 -and (Test-Path -LiteralPath $shaSidecar)) {
  $ExpectedAgentSha256 = ((Get-Content -LiteralPath $shaSidecar -TotalCount 1) -split '\s+')[0]
}
Assert-FileSha256 -Path $exe -Expected $ExpectedAgentSha256

$args = @(
  "--install",
  "--api-base", $ApiBase,
  "--enroll-token", $EnrollToken,
  "--install-dir", $InstallDir,
  "--service-name", $ServiceName
)

if ($TrustCa) { $args += "--trust-ca" }
if ($ForceEnroll) { $args += "--force-enroll" }
if ($RuntimeMode -eq "service") { $args += "--install-service" }
if ($RuntimeMode -eq "autorun") { $args += "--install-autorun" }
if ($EnableResponseActions) { $args += "--enable-response-actions" }

Write-Host "Running FDSensor.exe --install (token redacted)"
& $exe @args
$rc = $LASTEXITCODE
Write-DeployReport -InstallDir $InstallDir -Report ([ordered]@{
  created_at = (Get-Date).ToUniversalTime().ToString("o")
  api_base = $ApiBase
  install_dir = $InstallDir
  runtime_mode = $RuntimeMode
  force_enroll = [bool]$ForceEnroll
  trust_ca = [bool]$TrustCa
  expected_agent_sha256 = $ExpectedAgentSha256
  exit_code = $rc
  status = if ($rc -eq 0) { "ok" } else { "failed" }
})
exit $rc
