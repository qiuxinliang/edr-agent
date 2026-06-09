#Requires -Version 5.1
<#
.SYNOPSIS
  Copy an unpacked Windows zip package into the install directory and run edr_agent.exe --install.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\scripts\edr_agent_zip_deploy.ps1 `
    -ApiBase "https://edr.example.com:8080" -EnrollToken "<token>" -TrustCa
#>
param(
  [Parameter(Mandatory = $true)]
  [string]$ApiBase,
  [Parameter(Mandatory = $true)]
  [string]$EnrollToken,
  [string]$InstallDir = "C:\Program Files\EDR Agent",
  [ValidateSet("service", "autorun", "none")]
  [string]$RuntimeMode = "service",
  [string]$ServiceName = "EdrAgent",
  [switch]$TrustCa,
  [switch]$ForceEnroll,
  [switch]$EnableResponseActions,
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

$exe = Join-Path $InstallDir "edr_agent.exe"
if (-not (Test-Path -LiteralPath $exe)) {
  throw "edr_agent.exe not found after package copy: $exe"
}

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

Write-Host "Running edr_agent.exe --install (token redacted)"
& $exe @args
exit $LASTEXITCODE
