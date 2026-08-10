#Requires -Version 5.1
<#
.SYNOPSIS
  Remove a headless FDSecurity installation's runtime registration.

.DESCRIPTION
  Headless packages are ZIP/SFX bundles, not Inno Setup packages, so Windows
  does not create unins000.exe automatically. This script is copied into the
  install directory by edr_agent_install.ps1 and provides the equivalent
  elevated cleanup entry point for services, scheduled tasks, certificates,
  machine environment variables, runtime data and program files.

  The default action removes runtime registration and identity material but
  leaves program files for a recoverable administrator-driven cleanup.
  uninstall.exe always invokes this script with -RemoveProgramFiles. It either
  passes -RemoveData for a complete uninstall or -PreserveDiagnostics to archive
  logs and diagnostics outside the installation directory before removal.
#>
[CmdletBinding()]
param(
  [string]$InstallDir = "",
  [switch]$RemoveData,
  [switch]$RemoveProgramFiles,
  [switch]$PreserveDiagnostics,
  [string]$ServiceName = "FDSecurityAgent",
  [int]$ParentProcessId = 0
)

$ErrorActionPreference = "Continue"

if ([string]::IsNullOrWhiteSpace($InstallDir)) {
  $InstallDir = Split-Path -Parent $MyInvocation.MyCommand.Path
}
$InstallDir = [System.IO.Path]::GetFullPath($InstallDir)
$ConfigPath = Join-Path $InstallDir "agent.toml"

function Assert-Admin {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($identity)
  if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run uninstall.ps1 from an elevated PowerShell session."
  }
}

function Read-AgentTomlScalar {
  param([string]$Path, [string]$Key)
  if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return "" }
  $pattern = '^\s*' + [regex]::Escape($Key) + '\s*=\s*"([^"]*)"'
  try {
    foreach ($line in [System.IO.File]::ReadLines(([System.IO.Path]::GetFullPath($Path)))) {
      $match = [regex]::Match($line, $pattern)
      if ($match.Success) { return $match.Groups[1].Value }
    }
  } catch {}
  return ""
}

function Remove-AgentClientCertificate {
  $thumbprint = (Read-AgentTomlScalar -Path $ConfigPath -Key "client_cert_thumbprint") -replace '\s+', ''
  $store = Read-AgentTomlScalar -Path $ConfigPath -Key "client_cert_store"
  if (-not $thumbprint) {
    Write-Host "Client certificate cleanup skipped: thumbprint not found in agent.toml"
    return
  }
  $scope = if ($store -match "CurrentUser") { "CurrentUser" } else { "LocalMachine" }
  $certPath = "Cert:\$scope\My\$thumbprint"
  try {
    if (Test-Path -LiteralPath $certPath) {
      Remove-Item -LiteralPath $certPath -DeleteKey -Force -ErrorAction Stop
      Write-Host "Removed client certificate: $scope\My\$thumbprint"
    } else {
      Write-Host "Client certificate not found: $scope\My\$thumbprint"
    }
  } catch {
    Write-Warning ("Client certificate cleanup failed: " + $_.Exception.Message)
  }
}

function Invoke-AgentEtwUninstallCleanup {
  foreach ($name in @("FDSensor.exe", "edr_agent.exe")) {
    $exe = Join-Path $InstallDir $name
    if (-not (Test-Path -LiteralPath $exe)) { continue }
    try { & $exe --etw-uninstall-cleanup | Out-Host } catch {
      Write-Warning ("ETW cleanup failed: " + $_.Exception.Message)
    }
    break
  }
}

function Stop-AgentProcesses {
  foreach ($name in @("FDSensor", "edr_agent")) {
    Get-Process -Name $name -ErrorAction SilentlyContinue | ForEach-Object {
      Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
    }
  }
}

function Wait-AgentServiceDeleted {
  param(
    [string]$Name,
    [int]$TimeoutSeconds = 30
  )
  $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
  do {
    $escapedName = $Name.Replace("'", "''")
    if (-not (Get-CimInstance Win32_Service -Filter "Name='$escapedName'" -ErrorAction SilentlyContinue)) {
      return $true
    }
    Start-Sleep -Milliseconds 500
  } while ([DateTime]::UtcNow -lt $deadline)
  return $false
}

function Remove-AgentServices {
  $serviceNames = @($ServiceName, "FDSecurityAgent", "EdrAgent")
  if ($env:EDR_SERVICE_NAME) { $serviceNames += $env:EDR_SERVICE_NAME }
  foreach ($name in ($serviceNames | Select-Object -Unique)) {
    $service = Get-Service -Name $name -ErrorAction SilentlyContinue
    if (-not $service) { continue }
    Stop-Service -Name $name -Force -ErrorAction SilentlyContinue
    try {
      $service.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(20))
    } catch {
      Stop-AgentProcesses
      Start-Sleep -Milliseconds 500
    } finally {
      # A service remains DELETE_PENDING while a ServiceController handle is
      # open. Release this handle before asking SCM to delete the service.
      try { $service.Close() } catch {}
      try { $service.Dispose() } catch {}
      $service = $null
    }
    $deleteExitCode = 0
    for ($attempt = 0; $attempt -lt 3; $attempt++) {
      $deleteOutput = (& sc.exe delete $name 2>&1 | Out-String).Trim()
      $deleteExitCode = $LASTEXITCODE
      if ($deleteOutput) { Write-Host $deleteOutput }
      if (Wait-AgentServiceDeleted -Name $name -TimeoutSeconds 1) { break }
      Start-Sleep -Seconds 1
    }
    if (-not (Wait-AgentServiceDeleted -Name $name)) {
      throw "Windows service '$name' still exists after delete attempts; last sc.exe exit code $deleteExitCode."
    }
    Write-Host "Removed Windows service: $name"
  }
}

function Export-AgentDiagnostics {
  $programData = if ($env:ProgramData) { $env:ProgramData } else { Join-Path $env:SystemDrive "ProgramData" }
  $archiveRoot = Join-Path $programData "FDSecurity\UninstallArchive"
  $stamp = [DateTime]::UtcNow.ToString("yyyyMMddTHHmmssfffZ")
  $archiveDir = Join-Path $archiveRoot $stamp
  New-Item -ItemType Directory -Path $archiveDir -Force -ErrorAction Stop | Out-Null
  $copied = @()
  foreach ($relative in @("logs", "diagnostics")) {
    $source = Join-Path $InstallDir $relative
    if (-not (Test-Path -LiteralPath $source)) { continue }
    Copy-Item -LiteralPath $source -Destination (Join-Path $archiveDir $relative) `
      -Recurse -Force -ErrorAction Stop
    $copied += $relative
  }
  [ordered]@{
    schema = "edr.agent.uninstall.archive.v1"
    archived_at = [DateTime]::UtcNow.ToString("o")
    hostname = $env:COMPUTERNAME
    source_install_dir = $InstallDir
    contents = $copied
  } | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath (Join-Path $archiveDir "manifest.json") `
    -Encoding UTF8 -ErrorAction Stop
  Write-Host "Archived local diagnostics: $archiveDir"
  return $archiveDir
}

function Remove-AgentScheduledTasks {
  foreach ($name in @("FDSecurityAgent", "EdrAgent")) {
    try { Stop-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue } catch {}
    try {
      Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction SilentlyContinue
      Write-Host "Removed scheduled task: $name"
    } catch {}
  }
}

function Remove-MachineEnvironment {
  foreach ($name in @(
      "EDR_GRPC_REQUIRE_MTLS",
      "EDR_UPLOAD_FILE_RETRIES",
      "EDR_UPLOAD_FILE_RETRY_BACKOFF_MS",
      "EDR_FORENSIC_OUT",
      "EDR_FORENSIC_COLLECTOR",
      "EDR_FORENSIC_COLLECTOR_BIN",
      "EDR_FORENSIC_COLLECTOR_BUILTIN_BIN",
      "EDR_VELOCIRAPTOR_BIN",
      "EDR_FORENSIC_VERSION_CHECK_SEC",
      "EDR_FORENSIC_PREFETCH_RETRY_SEC",
      "EDR_FORENSIC_COLLECTOR_AUTOFETCH",
      "EDR_FORENSIC_ADAPTER_MANIFEST_URL",
      "EDR_FORENSIC_COLLECTOR_MANIFEST_URL",
      "EDR_CMD_AUDIT_PATH",
      "EDR_SELF_PROTECT_PIDFILE",
      "EDR_ISOLATE_STAMP_PATH",
      "EDR_ISOLATE_HOOK",
      "EDR_CMD_ENABLED"
    )) {
    try { [Environment]::SetEnvironmentVariable($name, $null, "Machine") } catch {
      Write-Warning ("Failed to remove machine environment variable " + $name + ": " + $_.Exception.Message)
    }
  }
}

function Remove-HeadlessUninstallRegistration {
  $key = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\FDSecurityAgentHeadless"
  try {
    Remove-Item -LiteralPath $key -Recurse -Force -ErrorAction SilentlyContinue
  } catch {
    Write-Warning ("Failed to remove uninstall registry entry: " + $_.Exception.Message)
  }
}

function Grant-InstallDirectoryRemovalRights {
  if (-not (Test-Path -LiteralPath $InstallDir)) { return }
  try {
    & takeown.exe /F $InstallDir /A /R /D Y | Out-Null
  } catch {
    Write-Warning ("Failed to take ownership of install directory: " + $_.Exception.Message)
  }
  try {
    & icacls.exe $InstallDir /inheritance:e /T /C /Q | Out-Null
    & icacls.exe $InstallDir /reset /T /C /Q | Out-Null
  } catch {
    Write-Warning ("Failed to reset install directory ACL: " + $_.Exception.Message)
  }
  try {
    & icacls.exe $InstallDir /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" /T /C /Q | Out-Null
  } catch {
    Write-Warning ("Failed to prepare install directory ACL for removal: " + $_.Exception.Message)
  }
  Get-ChildItem -LiteralPath $InstallDir -Force -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
    try { $_.Attributes = [IO.FileAttributes]::Normal } catch {}
  }
}

function Start-DeferredProgramFilesRemoval {
  if (-not $RemoveProgramFiles) { return }
  Grant-InstallDirectoryRemovalRights

  $quotedDir = $InstallDir.Replace("'", "''")
  $programData = if ($env:ProgramData) { $env:ProgramData } else { Join-Path $env:SystemDrive "ProgramData" }
  $receiptDir = Join-Path $programData "FDSecurity\state"
  New-Item -ItemType Directory -Path $receiptDir -Force -ErrorAction Stop | Out-Null
  $quotedReceipt = (Join-Path $receiptDir "uninstall-cleanup-last.json").Replace("'", "''")
  $cleanup = @"
`$ErrorActionPreference = 'SilentlyContinue'
`$parentId = $ParentProcessId
if (`$parentId -gt 0) {
  `$parent = Get-Process -Id `$parentId -ErrorAction SilentlyContinue
  if (`$parent) { `$null = `$parent.WaitForExit(30000) }
}
Start-Sleep -Milliseconds 750
`$target = '$quotedDir'
`$receipt = '$quotedReceipt'
try { & takeown.exe /F `$target /A /R /D Y | Out-Null } catch {}
try {
  & icacls.exe `$target /inheritance:e /T /C /Q | Out-Null
  & icacls.exe `$target /reset /T /C /Q | Out-Null
  & icacls.exe `$target /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' /T /C /Q | Out-Null
} catch {}
Get-ChildItem -LiteralPath `$target -Force -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
  try { `$_.Attributes = [IO.FileAttributes]::Normal } catch {}
}
for (`$attempt = 0; `$attempt -lt 120 -and (Test-Path -LiteralPath `$target); `$attempt++) {
  Remove-Item -LiteralPath `$target -Recurse -Force -ErrorAction SilentlyContinue
  if (Test-Path -LiteralPath `$target) { Start-Sleep -Milliseconds 500 }
}
`$remaining = Test-Path -LiteralPath `$target
[ordered]@{
  schema = 'edr.agent.uninstall.cleanup.v1'
  completed_at = [DateTime]::UtcNow.ToString('o')
  status = if (`$remaining) { 'failed' } else { 'succeeded' }
  install_dir = `$target
} | ConvertTo-Json -Depth 2 | Set-Content -LiteralPath `$receipt -Encoding UTF8 -Force
if (`$remaining) { exit 1 }
"@
  try {
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cleanup))
    $powershell = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
    Start-Process -FilePath $powershell -WorkingDirectory $env:SystemRoot -WindowStyle Hidden -ArgumentList @(
      "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", $encoded
    ) | Out-Null
    Write-Host "Scheduled program directory removal: $InstallDir"
  } catch {
    Write-Warning ("Failed to schedule program directory removal: " + $_.Exception.Message)
    exit 1
  }
}

function Remove-AgentData {
  foreach ($relative in @(
      "agent.toml",
      "certs",
      "queue",
      "evidence",
      "state",
      "logs",
      "diagnostics",
      "upload_outbox",
      "forensic",
      "isolation",
      "FDSensor.pid"
    )) {
    $path = Join-Path $InstallDir $relative
    if (Test-Path -LiteralPath $path) {
      Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue
      Write-Host "Removed runtime data: $relative"
    }
  }
}

Assert-Admin
Write-Host "Uninstalling FDSecurity runtime from $InstallDir"
Remove-AgentServices
Remove-AgentScheduledTasks
Stop-AgentProcesses
Invoke-AgentEtwUninstallCleanup
Remove-AgentClientCertificate
Remove-MachineEnvironment
Remove-HeadlessUninstallRegistration
$diagnosticArchive = ""
if ($PreserveDiagnostics) {
  $diagnosticArchive = Export-AgentDiagnostics
}
if ($RemoveData -or $RemoveProgramFiles) {
  Grant-InstallDirectoryRemovalRights
}
if ($RemoveData) {
  Remove-AgentData
} elseif ($PreserveDiagnostics) {
  Write-Host "Only logs and diagnostics were archived; credentials, configuration and runtime state will not be retained."
} else {
  Write-Host "Runtime data preserved. Use -RemoveData to remove config, certificates, queue, evidence and logs."
}
if ($RemoveProgramFiles) {
  Start-DeferredProgramFilesRemoval
  if ($diagnosticArchive) {
    Write-Host "FDSecurity Agent uninstalled successfully. Program files are scheduled for removal; diagnostics archive: $diagnosticArchive"
  } else {
    Write-Host "FDSecurity Agent uninstalled successfully. Program files are scheduled for removal."
  }
} else {
  Write-Host "FDSecurity runtime unregistered successfully. Program files remain in place for audit/recovery."
}
