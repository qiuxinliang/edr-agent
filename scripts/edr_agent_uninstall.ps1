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
  preserves queue/evidence/log data. uninstall.exe invokes this script with
  -RemoveData and -RemoveProgramFiles for a complete uninstall. Administrators
  may run the script directly without those switches for recoverable cleanup.
#>
[CmdletBinding()]
param(
  [string]$InstallDir = "",
  [switch]$RemoveData,
  [switch]$RemoveProgramFiles,
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

function Remove-AgentServices {
  $serviceNames = @("FDSecurityAgent", "EdrAgent")
  if ($env:EDR_SERVICE_NAME) { $serviceNames += $env:EDR_SERVICE_NAME }
  foreach ($name in ($serviceNames | Select-Object -Unique)) {
    $service = Get-Service -Name $name -ErrorAction SilentlyContinue
    if (-not $service) { continue }
    Stop-Service -Name $name -Force -ErrorAction SilentlyContinue
    & sc.exe delete $name | Out-Host
    Write-Host "Removed Windows service: $name"
  }
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
    & icacls.exe $InstallDir /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" /T /C /Q | Out-Null
  } catch {
    Write-Warning ("Failed to prepare install directory ACL for removal: " + $_.Exception.Message)
  }
}

function Start-DeferredProgramFilesRemoval {
  if (-not $RemoveProgramFiles) { return }
  Grant-InstallDirectoryRemovalRights

  $quotedDir = $InstallDir.Replace("'", "''")
  $cleanup = @"
`$ErrorActionPreference = 'SilentlyContinue'
`$parentId = $ParentProcessId
if (`$parentId -gt 0) {
  `$parent = Get-Process -Id `$parentId -ErrorAction SilentlyContinue
  if (`$parent) { `$null = `$parent.WaitForExit(30000) }
}
Start-Sleep -Milliseconds 750
`$target = '$quotedDir'
for (`$attempt = 0; `$attempt -lt 20 -and (Test-Path -LiteralPath `$target); `$attempt++) {
  Remove-Item -LiteralPath `$target -Recurse -Force -ErrorAction SilentlyContinue
  if (Test-Path -LiteralPath `$target) { Start-Sleep -Milliseconds 500 }
}
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
if ($RemoveData) {
  Remove-AgentData
} else {
  Write-Host "Runtime data preserved. Use -RemoveData to remove config, certificates, queue, evidence and logs."
}
if ($RemoveProgramFiles) {
  Start-DeferredProgramFilesRemoval
  Write-Host "FDSecurity Agent uninstalled successfully. Program files are scheduled for removal."
} else {
  Write-Host "FDSecurity runtime unregistered successfully. Program files remain in place for audit/recovery."
}
