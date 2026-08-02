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
  [string]$PlatformBaseUrl = "",
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

function Read-AgentTomlScalar {
  param([string]$Path, [string]$Key)
  if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return "" }
  $pattern = '^\s*' + [regex]::Escape($Key) + '\s*=\s*"([^"]*)"'
  try {
    foreach ($line in [System.IO.File]::ReadLines(([System.IO.Path]::GetFullPath($Path)))) {
      $m = [regex]::Match($line, $pattern)
      if ($m.Success) { return $m.Groups[1].Value }
    }
  } catch {}
  return ""
}

function Invoke-AgentEtwUninstallCleanup {
  $exe = $ExePath
  if (-not (Test-Path -LiteralPath $exe)) {
    $exe = Join-Path $InstallDir "FDSensor.exe"
  }
  if (-not (Test-Path -LiteralPath $exe)) {
    $exe = Join-Path $InstallDir "edr_agent.exe"
  }
  if (-not (Test-Path -LiteralPath $exe)) {
    Write-Host "ETW cleanup skipped: Agent executable not found"
    return
  }
  try {
    & $exe --etw-uninstall-cleanup | Out-Host
  } catch {
    Write-Warning ("ETW cleanup failed: " + $_.Exception.Message)
  }
}

function Remove-AgentClientCertificate {
  $thumbprint = (Read-AgentTomlScalar -Path $ConfigPath -Key "client_cert_thumbprint") -replace '\s+', ''
  $store = Read-AgentTomlScalar -Path $ConfigPath -Key "client_cert_store"
  $endpointID = Read-AgentTomlScalar -Path $ConfigPath -Key "endpoint_id"
  if ($endpointID) {
    Write-Host "Uninstall endpoint_id=$endpointID"
  }
  if (-not $thumbprint) {
    Write-Host "Client certificate cleanup skipped: thumbprint not found in agent.toml"
    return
  }
  $scope = if ($store -match "CurrentUser") { "CurrentUser" } else { "LocalMachine" }
  $certPath = "Cert:\$scope\My\$thumbprint"
  try {
    if (Test-Path -LiteralPath $certPath) {
      Remove-Item -LiteralPath $certPath -DeleteKey -Force -ErrorAction Stop
      Write-Host "Removed client certificate and private key: $scope\My\$thumbprint"
    } else {
      Write-Host "Client certificate not found: $scope\My\$thumbprint"
    }
  } catch {
    Write-Warning ("Client certificate cleanup failed: " + $_.Exception.Message)
  }
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

  & icacls.exe $InstallDir /grant "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" "Users:(OI)(CI)RX" /C | Out-Host

  foreach ($runtimeDir in @("logs", "queue", "evidence", "forensic", "isolation", "certs")) {
    $path = Join-Path $DataDir $runtimeDir
    if (Test-Path -LiteralPath $path) {
      & icacls.exe $path /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" /T /C | Out-Host
    }
  }
  if ($Account -match "LocalService") {
    & icacls.exe $DataDir /grant "NT AUTHORITY\LOCAL SERVICE:(OI)(CI)M" /T | Out-Host
  } elseif ($Account -match "NetworkService") {
    & icacls.exe $DataDir /grant "NT AUTHORITY\NETWORK SERVICE:(OI)(CI)M" /T | Out-Host
  }

  foreach ($uninstaller in @(
    @{ Name = "unins000.exe"; Grant = "Users:RX" },
    @{ Name = "unins000.dat"; Grant = "Users:R" }
  )) {
    $path = Join-Path $InstallDir $uninstaller.Name
    if (Test-Path -LiteralPath $path) {
      & icacls.exe $path /grant:r "SYSTEM:F" "Administrators:F" $uninstaller.Grant /C | Out-Host
    }
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

function Get-FDWindowsArch {
  $raw = if ($env:EDR_BUNDLE_ARCH) { $env:EDR_BUNDLE_ARCH } elseif ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
  $v = if ($raw) { $raw.Trim().ToLowerInvariant() } else { "" }
  switch ($v) {
    "arm64" { return "arm64" }
    "aarch64" { return "arm64" }
    default { return "amd64" }
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
  # 启用外置取证采集器(forensic_collector.exe → Velociraptor;不可用时 agent 回退 C builtin,
  # 再回退 in-process)。不设 STRICT(保留兜底)。
  Set-MachineEnv "EDR_FORENSIC_COLLECTOR" "1"
  Set-MachineEnv "EDR_FORENSIC_COLLECTOR_BIN" (Join-Path $InstallDir "collector\forensic_collector.exe")
  Set-MachineEnv "EDR_FORENSIC_COLLECTOR_BUILTIN_BIN" (Join-Path $InstallDir "collector\forensic_collector_builtin.exe")
  Set-MachineEnv "EDR_VELOCIRAPTOR_BIN" (Join-Path $InstallDir "collector\velociraptor.exe")
  Set-MachineEnv "EDR_FORENSIC_VERSION_CHECK_SEC" "900"
  Set-MachineEnv "EDR_FORENSIC_PREFETCH_RETRY_SEC" "900"
  # 按需下载:agent 经平台「固定地址」manifest 分别刷新 Go adapter 与 Velociraptor。
  # 默认开启;manifest 地址由 -PlatformBaseUrl 推导(留空则仅用安装包内置/手动部署件)。
  Set-MachineEnv "EDR_FORENSIC_COLLECTOR_AUTOFETCH" "1"
  if ($PlatformBaseUrl) {
    $base = $PlatformBaseUrl.TrimEnd('/')
    $arch = Get-FDWindowsArch
    Set-MachineEnv "EDR_FORENSIC_ADAPTER_MANIFEST_URL" "$base/api/v1/agent/forensic-collector/manifest?kind=adapter&os=windows&arch=$arch"
    Set-MachineEnv "EDR_FORENSIC_COLLECTOR_MANIFEST_URL" "$base/api/v1/agent/forensic-collector/manifest?kind=velociraptor&os=windows&arch=$arch"
  }
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
  Invoke-AgentEtwUninstallCleanup
  foreach ($procName in @("FDSensor", "edr_agent")) {
    Get-Process -Name $procName -ErrorAction SilentlyContinue | ForEach-Object {
      Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
      Start-Sleep -Seconds 2
    }
  }
  Remove-AgentClientCertificate
  foreach ($name in @(
      "EDR_GRPC_REQUIRE_MTLS",
      "EDR_UPLOAD_FILE_RETRIES",
      "EDR_UPLOAD_FILE_RETRY_BACKOFF_MS",
      "EDR_FORENSIC_OUT",
      "EDR_FORENSIC_COLLECTOR",
      "EDR_FORENSIC_COLLECTOR_BIN",
      "EDR_FORENSIC_COLLECTOR_BUILTIN_BIN",
      "EDR_VELOCIRAPTOR_BIN",
      "EDR_FORENSIC_COLLECTOR_AUTOFETCH",
      "EDR_FORENSIC_ADAPTER_MANIFEST_URL",
      "EDR_FORENSIC_COLLECTOR_MANIFEST_URL",
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
