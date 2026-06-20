#Requires -Version 5.1
<#
.SYNOPSIS
  Install or manage FDSecurity as a native Windows service.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\scripts\windows_service_install.ps1 -Action Install `
    -ExePath "C:\Program Files\FDSecurity\FDSensor.exe" `
    -ConfigPath "C:\Program Files\FDSecurity\agent.toml" -EnableResponseActions
#>
param(
  [ValidateSet("Install", "Uninstall", "Start", "Stop", "Status")]
  [string]$Action = "Install",
  [string]$ServiceName = "FDSecurityAgent",
  [string]$DisplayName = "FDSecurity Endpoint Agent",
  [string]$ExePath = "C:\Program Files\FDSecurity\FDSensor.exe",
  [string]$ConfigPath = "C:\Program Files\FDSecurity\agent.toml",
  [string]$InstallDir = "C:\Program Files\FDSecurity",
  [string]$DataDir = "C:\Program Files\FDSecurity",
  [string]$Account = "LocalSystem",
  [switch]$SkipPreflight,
  [switch]$KeepOfflineQueue,
  [switch]$KeepEvidenceCache,
  [switch]$NoStart,
  [switch]$EnableResponseActions
)

$ErrorActionPreference = "Stop"

function Assert-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p = New-Object Security.Principal.WindowsPrincipal($id)
  if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script from an elevated PowerShell session."
  }
}

function Ensure-Dir([string]$Path) {
  if (-not (Test-Path -LiteralPath $Path)) {
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
  }
}

function Set-MachineEnv([string]$Name, [string]$Value) {
  [Environment]::SetEnvironmentVariable($Name, $Value, "Machine")
  Write-Host "Machine env $Name=$Value"
}

function Remove-MachineEnv([string]$Name) {
  [Environment]::SetEnvironmentVariable($Name, $null, "Machine")
}

function Set-AgentAcl {
  Ensure-Dir $InstallDir
  Ensure-Dir $DataDir
  Ensure-Dir (Join-Path $DataDir "logs")
  Ensure-Dir (Join-Path $DataDir "queue")
  Ensure-Dir (Join-Path $DataDir "evidence")
  Ensure-Dir (Join-Path $DataDir "forensic")
  Ensure-Dir (Join-Path $DataDir "isolation")
  Ensure-Dir (Join-Path $DataDir "certs")

  & icacls.exe $InstallDir /inheritance:r /grant "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" "Users:(OI)(CI)RX" /T | Out-Host
  & icacls.exe $DataDir /inheritance:r /grant "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" /T | Out-Host
  if ($Account -match "LocalService") {
    & icacls.exe $DataDir /grant "NT AUTHORITY\LOCAL SERVICE:(OI)(CI)M" /T | Out-Host
  } elseif ($Account -match "NetworkService") {
    & icacls.exe $DataDir /grant "NT AUTHORITY\NETWORK SERVICE:(OI)(CI)M" /T | Out-Host
  }
}

function Invoke-AgentPreflight {
  if ($SkipPreflight) {
    Write-Host "Preflight skipped"
    return
  }
  $preflight = Join-Path $InstallDir "edr_agent_preflight.ps1"
  if (-not (Test-Path -LiteralPath $preflight)) {
    $preflight = Join-Path $PSScriptRoot "edr_agent_preflight.ps1"
  }
  if (-not (Test-Path -LiteralPath $preflight)) {
    Write-Warning "edr_agent_preflight.ps1 not found; falling back to service stop only"
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    return
  }
  $args = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $preflight,
    "-InstallDir", $InstallDir, "-ServiceName", $ServiceName)
  if ($KeepOfflineQueue) { $args += "-KeepOfflineQueue" }
  if ($KeepEvidenceCache) { $args += "-KeepEvidenceCache" }
  & powershell.exe @args
  if ($LASTEXITCODE -ne 0) {
    throw "EDR preflight failed with exit code $LASTEXITCODE"
  }
}

function Install-AgentService {
  Assert-Admin
  if (-not (Test-Path -LiteralPath $ExePath)) {
    throw "FDSensor.exe not found: $ExePath"
  }
  if (-not (Test-Path -LiteralPath $ConfigPath)) {
    throw "agent.toml not found: $ConfigPath"
  }

  Invoke-AgentPreflight
  Set-AgentAcl

  $hook = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$InstallDir\windows_isolate_host.ps1`" -Action Enable"
  Set-MachineEnv "EDR_GRPC_REQUIRE_MTLS" "1"
  Set-MachineEnv "EDR_UPLOAD_FILE_RETRIES" "3"
  Set-MachineEnv "EDR_UPLOAD_FILE_RETRY_BACKOFF_MS" "750"
  Set-MachineEnv "EDR_FORENSIC_OUT" (Join-Path $DataDir "forensic")
  Set-MachineEnv "EDR_CMD_AUDIT_PATH" (Join-Path $DataDir "logs\command_audit.log")
  Set-MachineEnv "EDR_SELF_PROTECT_PIDFILE" (Join-Path $DataDir "FDSensor.pid")
  Set-MachineEnv "EDR_ISOLATE_STAMP_PATH" (Join-Path $DataDir "isolation\isolated.stamp")
  Set-MachineEnv "EDR_ISOLATE_HOOK" $hook
  if ($EnableResponseActions) {
    Set-MachineEnv "EDR_CMD_ENABLED" "1"
  }

  $binPath = "`"$ExePath`" --service --service-name `"$ServiceName`" --config `"$ConfigPath`""
  $existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
  if ($existing) {
    Write-Host "Service $ServiceName already exists; refreshing configuration"
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    & sc.exe config $ServiceName "binPath= $binPath" "start= auto" "obj= $Account" "DisplayName= $DisplayName" | Out-Host
    & sc.exe failure $ServiceName "actions= restart/60000/restart/60000" "reset= 86400" | Out-Host
    if (-not $NoStart) {
      Start-Service -Name $ServiceName
    }
    Get-Service -Name $ServiceName
    return
  }

  & sc.exe create $ServiceName "binPath= $binPath" "start= auto" "obj= $Account" "DisplayName= $DisplayName" | Out-Host
  & sc.exe description $ServiceName "FDSecurity endpoint sensor" | Out-Host
  & sc.exe failure $ServiceName "actions= restart/60000/restart/60000" "reset= 86400" | Out-Host
  if (-not $NoStart) {
    Start-Service -Name $ServiceName
  }
  Get-Service -Name $ServiceName
}

function Uninstall-AgentService {
  Assert-Admin
  foreach ($name in @($ServiceName, "EdrAgent")) {
    $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
    if ($svc) {
      if ($svc.Status -ne "Stopped") {
        Stop-Service -Name $name -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
      }
      & sc.exe delete $name | Out-Host
    }
  }
  foreach ($procName in @("FDSensor", "edr_agent")) {
    Get-Process -Name $procName -ErrorAction SilentlyContinue | ForEach-Object {
      Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
      Start-Sleep -Seconds 2
    }
  }
  foreach ($name in @(
      "EDR_GRPC_REQUIRE_MTLS",
      "EDR_UPLOAD_FILE_RETRIES",
      "EDR_UPLOAD_FILE_RETRY_BACKOFF_MS",
      "EDR_FORENSIC_OUT",
      "EDR_CMD_AUDIT_PATH",
      "EDR_SELF_PROTECT_PIDFILE",
      "EDR_ISOLATE_STAMP_PATH",
      "EDR_ISOLATE_HOOK",
      "EDR_CMD_ENABLED"
    )) {
    Remove-MachineEnv $name
  }
}

switch ($Action) {
  "Install" { Install-AgentService }
  "Uninstall" { Uninstall-AgentService }
  "Start" { Start-Service -Name $ServiceName; Get-Service -Name $ServiceName }
  "Stop" { Stop-Service -Name $ServiceName; Get-Service -Name $ServiceName }
  "Status" { Get-Service -Name $ServiceName }
}
