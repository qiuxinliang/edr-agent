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
  [string] $EvidenceDir = "setup-exe-evidence",
  [switch] $SkipSetupRollback
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
  }) | Out-Null
}
function Copy-InstallerDiagnostics([string] $Stage, [string] $SetupLog) {
  # Evidence collection must never hide the original installer failure.
  try {
    if (Test-Path -LiteralPath $SetupLog -PathType Leaf) {
      Write-Host "--- $Stage Inno Setup log tail ---"
      Get-Content -LiteralPath $SetupLog -Tail 120 | ForEach-Object { Write-Host $_ }
    } else {
      Write-Warning "$Stage did not create its requested Inno Setup log: $SetupLog"
    }

    $diagnosticsRoot = Join-Path $env:ProgramData "FDSecurity\setup-ui\agent-diagnostics"
    if (Test-Path -LiteralPath $diagnosticsRoot -PathType Container) {
      $stageDiagnostics = Join-Path $EvidenceDir ($Stage + ".agent-diagnostics")
      New-Item -ItemType Directory -Path $stageDiagnostics -Force | Out-Null
      Get-ChildItem -LiteralPath $diagnosticsRoot -Force -ErrorAction SilentlyContinue | ForEach-Object {
        Copy-Item -LiteralPath $_.FullName -Destination $stageDiagnostics -Recurse -Force -ErrorAction SilentlyContinue
      }
      $stageLog = Join-Path $diagnosticsRoot "install-stage.log"
      if (Test-Path -LiteralPath $stageLog -PathType Leaf) {
        Write-Host "--- $Stage Agent install-stage.log ---"
        Get-Content -LiteralPath $stageLog -Tail 120 | ForEach-Object { Write-Host $_ }
      }
    } else {
      Write-Warning "$Stage did not create Agent installer diagnostics: $diagnosticsRoot"
    }

    $diagnosticsBundle = Join-Path $env:ProgramData "FDSecurity\setup-ui\install-diagnostics.zip"
    if (Test-Path -LiteralPath $diagnosticsBundle -PathType Leaf) {
      Copy-Item -LiteralPath $diagnosticsBundle `
        -Destination (Join-Path $EvidenceDir ($Stage + ".install-diagnostics.zip")) -Force
    }
  } catch {
    Write-Warning ("Unable to collect diagnostics for {0}: {1}" -f $Stage, $_.Exception.Message)
  }
}
function Invoke-Installer([string] $Path, [string] $Stage, [bool] $UpgradeExisting) {
  $log = Join-Path $EvidenceDir ($Stage + ".setup.log")
  $script:LastLifecycleStage = $Stage
  $script:LastSetupLog = $log
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
function Assert-InstalledRuntime([string] $ExpectedVersion, [string] $Stage, [bool] $RequireModernLifecycleAssets = $true) {
  $versionPath = Join-Path $InstallDir "VERSION"
  if (-not (Test-Path -LiteralPath $versionPath -PathType Leaf)) {
    throw "$Stage did not install VERSION"
  }
  $actualVersion = ([IO.File]::ReadAllText($versionPath)).Trim()
  if ($actualVersion -ne $ExpectedVersion) {
    throw "$Stage version mismatch: expected=$ExpectedVersion actual=$actualVersion"
  }
  foreach ($name in @("FDSensor.exe", "FDSecurityInstallerWorker.exe")) {
    $path = Join-Path $InstallDir $name
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "$Stage is missing $name" }
    & $archVerifier -Path $path -Architecture $Architecture
  }
  foreach ($name in @("package-capabilities.json", "unins000.exe")) {
    if (-not (Test-Path -LiteralPath (Join-Path $InstallDir $name) -PathType Leaf)) {
      throw "$Stage is missing $name"
    }
  }
  $capabilities = [IO.File]::ReadAllText((Join-Path $InstallDir "package-capabilities.json")) | ConvertFrom-Json
  if ([string]$capabilities.target_arch -ne $Architecture) {
    throw "$Stage package capability architecture mismatch: $($capabilities.target_arch)"
  }
  if ($RequireModernLifecycleAssets) {
    foreach ($name in @("uninstall.exe", "uninstall.ps1", "native-package-integrity.json")) {
      if (-not (Test-Path -LiteralPath (Join-Path $InstallDir $name) -PathType Leaf)) {
        throw "$Stage is missing modern lifecycle asset $name"
      }
    }
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
function Invoke-UninstallerAndAssertCleanup([string] $Stage) {
  $uninstaller = Join-Path $InstallDir "unins000.exe"
  $uninstallLog = Join-Path $EvidenceDir ($Stage + ".setup.log")
  $script:LastLifecycleStage = $Stage
  $script:LastSetupLog = $uninstallLog
  if (-not (Test-Path -LiteralPath $uninstaller -PathType Leaf)) {
    throw "$Stage is missing the Inno Setup uninstaller: $uninstaller"
  }
  Add-Evidence $Stage "started" $uninstaller
  $uninstallProcess = Start-Process -FilePath $uninstaller -ArgumentList @(
    "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", ('/LOG="{0}"' -f $uninstallLog)
  ) -Wait -PassThru
  if ($uninstallProcess.ExitCode -ne 0) {
    throw "$Stage failed with exit code $($uninstallProcess.ExitCode); log=$uninstallLog"
  }
  $deadline = (Get-Date).AddSeconds(120)
  do {
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    $runtime = Get-Process -Name "FDSensor" -ErrorAction SilentlyContinue
    if (-not $service -and -not $runtime -and -not (Test-Path -LiteralPath $InstallDir)) { break }
    Start-Sleep -Seconds 1
  } while ((Get-Date) -lt $deadline)
  if ($service -or $runtime -or (Test-Path -LiteralPath $InstallDir)) {
    $residue = @()
    if (Test-Path -LiteralPath $InstallDir -PathType Container) {
      $residue = @(Get-ChildItem -LiteralPath $InstallDir -Force -Recurse -ErrorAction SilentlyContinue |
        ForEach-Object {
          $relative = $_.FullName.Substring($InstallDir.TrimEnd('\').Length).TrimStart('\')
          if ($_.PSIsContainer) { $relative + '\' } else { $relative }
        })
      $residuePath = Join-Path $EvidenceDir ($Stage + ".install-dir-residue.txt")
      [IO.File]::WriteAllLines($residuePath, [string[]]$residue, [Text.UTF8Encoding]::new($false))
      Write-Host "--- $Stage install directory residue ---"
      $residue | ForEach-Object { Write-Host $_ }
    }
    throw "$Stage residue: service=$([bool]$service) process=$([bool]$runtime) install_dir=$([bool](Test-Path -LiteralPath $InstallDir)) entries=$($residue -join '|')"
  }
  Add-Evidence $Stage "verified" "service_removed=true process_stopped=true install_dir_removed=true"
}

$status = "failed"
$script:LastLifecycleStage = "lifecycle"
$script:LastSetupLog = ""
try {
  # Validate the target independently first. A broken historical baseline must
  # not hide whether the candidate can install and uninstall on a clean host.
  Invoke-Installer $TargetSetupExe "install-target-fresh" $false
  Assert-InstalledRuntime $TargetVersion "install-target-fresh"
  Invoke-UninstallerAndAssertCleanup "uninstall-target-fresh"

  # Then verify the cross-version compatibility path using a baseline that is
  # freshly installed and validated in this same native-runner job.
  Invoke-Installer $BaselineSetupExe "install-baseline" $false
  Assert-InstalledRuntime $BaselineVersion "install-baseline" (-not $SkipSetupRollback)
  Invoke-Installer $TargetSetupExe "upgrade-target" $true
  Assert-InstalledRuntime $TargetVersion "upgrade-target"
  if ($SkipSetupRollback) {
    Add-Evidence "rollback-baseline" "skipped" "legacy baseline predates the immutable full-Setup rollback contract; native runtime rollback remains mandatory"
    Invoke-UninstallerAndAssertCleanup "uninstall-after-upgrade"
  } else {
    Invoke-Installer $BaselineSetupExe "rollback-baseline" $true
    Assert-InstalledRuntime $BaselineVersion "rollback-baseline"
    Invoke-UninstallerAndAssertCleanup "uninstall-after-rollback"
  }
  $status = "succeeded"
} catch {
  Copy-InstallerDiagnostics -Stage $script:LastLifecycleStage -SetupLog $script:LastSetupLog
  Add-Evidence "lifecycle" "failed" $_.Exception.Message
  throw
} finally {
  # PowerShell 7 can throw "Argument types do not match" when a generic
  # List[object] is expanded with @($list) inside an ordered hashtable. Convert
  # it explicitly so summary serialization cannot mask the lifecycle result.
  [object[]]$eventArray = $events.ToArray()
  $summary = [ordered]@{
    schema = "edr.agent.setup-exe.lifecycle.v1"
    completed_at = [DateTime]::UtcNow.ToString("o")
    status = $status
    architecture = $Architecture
    baseline_version = $BaselineVersion
    target_version = $TargetVersion
    setup_rollback_skipped = [bool]$SkipSetupRollback
    install_dir = $InstallDir
    events = $eventArray
  }
  [IO.File]::WriteAllText(
    (Join-Path $EvidenceDir "summary.json"),
    ($summary | ConvertTo-Json -Depth 8),
    (New-Object Text.UTF8Encoding($false))
  )
}
