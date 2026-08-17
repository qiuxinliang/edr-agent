#Requires -Version 5.1
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)] [string] $BaselineSetupExe,
  [Parameter(Mandatory = $true)] [string] $TargetSetupExe,
  [Parameter(Mandatory = $true)] [string] $BaselineVersion,
  [Parameter(Mandatory = $true)] [string] $TargetVersion,
  [Parameter(Mandatory = $true)]
  [ValidateSet("amd64", "arm64")]
  [string] $Architecture,
  [string] $InstallDir = "C:\edr-agent-setup-lifecycle-smoke",
  [string] $ServiceName = "FDSecurityAgent",
  [string] $EvidenceDir = "setup-exe-evidence"
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
$archVerifier = Join-Path $PSScriptRoot "Assert-WindowsPeArchitecture.ps1"
$bootstrapVerifier = Join-Path $PSScriptRoot "Assert-WindowsInstallerBootstrapArchitecture.ps1"
$BaselineSetupExe = (Resolve-Path -LiteralPath $BaselineSetupExe).Path
$TargetSetupExe = (Resolve-Path -LiteralPath $TargetSetupExe).Path
$InstallDir = [IO.Path]::GetFullPath($InstallDir)
$EvidenceDir = [IO.Path]::GetFullPath($EvidenceDir)
New-Item -ItemType Directory -Path $EvidenceDir -Force | Out-Null

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw "Setup EXE lifecycle smoke must run elevated"
}
if ($InstallDir -notmatch '^C:\\edr-agent-setup-lifecycle-[A-Za-z0-9._-]+$') {
  throw "Refusing unsafe lifecycle install directory: $InstallDir"
}
if (Test-Path -LiteralPath $InstallDir) {
  throw "Lifecycle install directory already exists; use a clean runner: $InstallDir"
}

& $bootstrapVerifier -Path $BaselineSetupExe -PayloadArchitecture $Architecture
& $bootstrapVerifier -Path $TargetSetupExe -PayloadArchitecture $Architecture

$events = New-Object System.Collections.Generic.List[object]
function Add-Evidence([string] $Stage, [string] $Status, [string] $Detail) {
  $events.Add([ordered]@{
    at = [DateTime]::UtcNow.ToString("o")
    stage = $Stage
    status = $Status
    detail = $Detail
  })
}
function Invoke-Installer([string] $Path, [string] $Stage, [bool] $UpgradeExisting) {
  $log = Join-Path $EvidenceDir ($Stage + ".setup.log")
  $arguments = @(
    "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/SP-",
    ('/DIR="{0}"' -f $InstallDir),
    '/TASKS="windowsservice"',
    ('/LOG="{0}"' -f $log)
  )
  if ($UpgradeExisting) { $arguments += "/EDR_UPGRADE_EXISTING=1" }
  Add-Evidence $Stage "started" $Path
  $process = Start-Process -FilePath $Path -ArgumentList $arguments -Wait -PassThru
  if ($process.ExitCode -ne 0) {
    throw "Setup EXE stage '$Stage' failed with exit code $($process.ExitCode); log=$log"
  }
  Add-Evidence $Stage "completed" "exit_code=0"
}
function Assert-InstalledRuntime([string] $ExpectedVersion, [string] $Stage) {
  $versionPath = Join-Path $InstallDir "VERSION"
  if (-not (Test-Path -LiteralPath $versionPath -PathType Leaf)) {
    throw "$Stage did not install VERSION"
  }
  $actualVersion = ([IO.File]::ReadAllText($versionPath)).Trim()
  if ($actualVersion -ne $ExpectedVersion) {
    throw "$Stage version mismatch: expected=$ExpectedVersion actual=$actualVersion"
  }
  foreach ($name in @("FDSensor.exe", "FDSecurityInstallerWorker.exe", "uninstall.exe")) {
    $path = Join-Path $InstallDir $name
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "$Stage is missing $name" }
    & $archVerifier -Path $path -Architecture $Architecture
  }
  foreach ($name in @("uninstall.ps1", "native-package-integrity.json", "package-capabilities.json", "unins000.exe")) {
    if (-not (Test-Path -LiteralPath (Join-Path $InstallDir $name) -PathType Leaf)) {
      throw "$Stage is missing $name"
    }
  }
  $capabilities = [IO.File]::ReadAllText((Join-Path $InstallDir "package-capabilities.json")) | ConvertFrom-Json
  if ([string]$capabilities.target_arch -ne $Architecture) {
    throw "$Stage package capability architecture mismatch: $($capabilities.target_arch)"
  }
  $deadline = (Get-Date).AddSeconds(60)
  do {
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    $runtime = Get-Process -Name "FDSensor" -ErrorAction SilentlyContinue
    if ($service -and $service.Status -eq "Running" -and $runtime) { break }
    Start-Sleep -Milliseconds 500
  } while ((Get-Date) -lt $deadline)
  if (-not $service -or $service.Status -ne "Running" -or -not $runtime) {
    throw "$Stage did not leave the Agent service and process healthy"
  }
  Add-Evidence $Stage "verified" "version=$actualVersion service=running process=running"
}

$status = "failed"
try {
  Invoke-Installer $BaselineSetupExe "install-baseline" $false
  Assert-InstalledRuntime $BaselineVersion "install-baseline"
  Invoke-Installer $TargetSetupExe "upgrade-target" $true
  Assert-InstalledRuntime $TargetVersion "upgrade-target"
  Invoke-Installer $BaselineSetupExe "rollback-baseline" $true
  Assert-InstalledRuntime $BaselineVersion "rollback-baseline"

  $uninstaller = Join-Path $InstallDir "unins000.exe"
  $uninstallLog = Join-Path $EvidenceDir "uninstall.setup.log"
  Add-Evidence "uninstall" "started" $uninstaller
  $uninstallProcess = Start-Process -FilePath $uninstaller -ArgumentList @(
    "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", ('/LOG="{0}"' -f $uninstallLog)
  ) -Wait -PassThru
  if ($uninstallProcess.ExitCode -ne 0) {
    throw "Setup uninstaller failed with exit code $($uninstallProcess.ExitCode); log=$uninstallLog"
  }
  $deadline = (Get-Date).AddSeconds(120)
  do {
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    $runtime = Get-Process -Name "FDSensor" -ErrorAction SilentlyContinue
    if (-not $service -and -not $runtime -and -not (Test-Path -LiteralPath $InstallDir)) { break }
    Start-Sleep -Seconds 1
  } while ((Get-Date) -lt $deadline)
  if ($service -or $runtime -or (Test-Path -LiteralPath $InstallDir)) {
    throw "Setup uninstall residue: service=$([bool]$service) process=$([bool]$runtime) install_dir=$([bool](Test-Path -LiteralPath $InstallDir))"
  }
  Add-Evidence "uninstall" "verified" "service_removed=true process_stopped=true install_dir_removed=true"
  $status = "succeeded"
} catch {
  Add-Evidence "lifecycle" "failed" $_.Exception.Message
  throw
} finally {
  $summary = [ordered]@{
    schema = "edr.agent.setup-exe.lifecycle.v1"
    completed_at = [DateTime]::UtcNow.ToString("o")
    status = $status
    architecture = $Architecture
    baseline_version = $BaselineVersion
    target_version = $TargetVersion
    install_dir = $InstallDir
    events = @($events)
  }
  [IO.File]::WriteAllText(
    (Join-Path $EvidenceDir "summary.json"),
    ($summary | ConvertTo-Json -Depth 8),
    (New-Object Text.UTF8Encoding($false))
  )
}
