#Requires -Version 5.1
<#
.SYNOPSIS
  Replace a running Windows Agent binary with hash, architecture, and rollback checks.

.DESCRIPTION
  Run this script from a separate elevated process or scheduled task. It preserves
  enrollment, policy, queue, evidence, and configuration data under InstallDir.
#>
[CmdletBinding()]
param(
  [string]$InstallDir = "C:\Program Files\FDSecurity",
  [string]$StagedBinary = "FDSensor.next.exe",
  [string]$RuntimeManifest = "",
  [Parameter(Mandatory = $true)]
  [ValidatePattern("^[0-9A-Fa-f]{64}$")]
  [string]$ExpectedSha256,
  [Parameter(Mandatory = $true)]
  [string]$TargetVersion,
  [ValidateSet("x64", "arm64")]
  [string]$ExpectedArchitecture = "x64",
  [string]$ExpectedInternalName = "FDSensor",
  [Parameter(Mandatory = $true)]
  [string]$TrustedPublisherThumbprint,
  [Parameter(Mandatory = $true)]
  [string]$TrustedPublisherSubject,
  [string]$MinCurrentVersion = "",
  [string]$MaxCurrentVersion = "",
  [ValidateSet("auto", "scheduled_task", "service")]
  [string]$DeploymentMode = "auto",
  [string]$ScheduledTaskName = "FDSecurityAgent",
  [string]$ScheduledTaskPath = "\",
  [string]$ServiceName = "FDSecurityAgent",
  [ValidateRange(0, 1099511627776)]
  [UInt64]$MinFreeBytes = 0,
  [string]$CommandId = "manual",
  [string]$RuntimeManifestSha256 = "",
  [ValidateRange(0, 60)]
  [int]$DrainDelaySeconds = 5,
  [ValidateRange(10, 300)]
  [int]$StartupTimeoutSeconds = 60
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

function Get-Sha256 {
  param([Parameter(Mandatory = $true)][string]$Path)
  return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Convert-SemVer {
  param([Parameter(Mandatory = $true)][string]$Version)
  if ($Version -notmatch '^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$') {
    throw "invalid semantic version: $Version"
  }
  return [pscustomobject]@{ Major=[UInt64]$Matches[1]; Minor=[UInt64]$Matches[2]; Patch=[UInt64]$Matches[3]; Pre=[string]$Matches[4] }
}

function Compare-SemVer {
  param([string]$Left, [string]$Right)
  $a = Convert-SemVer $Left; $b = Convert-SemVer $Right
  foreach ($field in @('Major','Minor','Patch')) {
    if ($a.$field -lt $b.$field) { return -1 }
    if ($a.$field -gt $b.$field) { return 1 }
  }
  if ([string]::IsNullOrEmpty($a.Pre) -and -not [string]::IsNullOrEmpty($b.Pre)) { return 1 }
  if (-not [string]::IsNullOrEmpty($a.Pre) -and [string]::IsNullOrEmpty($b.Pre)) { return -1 }
  return [string]::CompareOrdinal($a.Pre, $b.Pre)
}

function Get-VersionIdentity {
  param([Parameter(Mandatory = $true)][string]$Path)
  $info = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($Path)
  $version = [string]$info.ProductVersion
  if ($version) { $version = ($version -split '[ +]')[0].Trim() }
  return [pscustomobject]@{ InternalName=[string]$info.InternalName; ProductVersion=$version }
}

function Assert-AuthenticodePublisher {
  param([string]$Path, [string]$Thumbprint, [string]$Subject)
  $signature = Get-AuthenticodeSignature -LiteralPath $Path
  if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid -or -not $signature.SignerCertificate) {
    throw "candidate Authenticode signature is not Valid: $($signature.Status) $($signature.StatusMessage)"
  }
  $actualThumbprint = ($signature.SignerCertificate.Thumbprint -replace '\s','').ToUpperInvariant()
  $expectedThumbprint = ($Thumbprint -replace '\s','').ToUpperInvariant()
  if ($actualThumbprint -ne $expectedThumbprint) { throw "candidate publisher thumbprint is not trusted" }
  if ($signature.SignerCertificate.Subject -ne $Subject) { throw "candidate publisher subject is not trusted" }
}

function Write-AtomicJson {
  param([string]$Path, [object]$Value)
  $directory = Split-Path -Parent $Path
  New-Item -ItemType Directory -Path $directory -Force | Out-Null
  $temporary = "$Path.tmp-$PID"
  [System.IO.File]::WriteAllText([System.IO.Path]::GetFullPath($temporary),
    ($Value | ConvertTo-Json -Depth 10), (New-Object System.Text.UTF8Encoding($false)))
  Move-Item -LiteralPath $temporary -Destination $Path -Force
}

function Get-PeMachine {
  param([Parameter(Mandatory = $true)][string]$Path)

  $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open,
    [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
  try {
    $reader = New-Object System.IO.BinaryReader($stream)
    if ($reader.ReadUInt16() -ne 0x5A4D) {
      throw "staged binary is not a PE file"
    }
    $stream.Position = 0x3C
    $peOffset = $reader.ReadInt32()
    if ($peOffset -lt 0x40 -or $peOffset -gt ($stream.Length - 6)) {
      throw "staged binary has an invalid PE header offset"
    }
    $stream.Position = $peOffset
    if ($reader.ReadUInt32() -ne 0x00004550) {
      throw "staged binary has an invalid PE signature"
    }
    return $reader.ReadUInt16()
  } finally {
    $stream.Dispose()
  }
}

function Get-RuntimeUpdatePlan {
  param(
    [Parameter(Mandatory = $true)][string]$StagedBinaryPath,
    [Parameter(Mandatory = $true)][string]$InstallDirectory,
    [string]$ManifestPath,
    [Parameter(Mandatory = $true)][string]$Version,
    [Parameter(Mandatory = $true)][string]$Timestamp
  )

  if ([string]::IsNullOrWhiteSpace($ManifestPath)) {
    return @()
  }

  $stagingDirectory = Split-Path -Parent $StagedBinaryPath
  $resolvedManifest = if ([System.IO.Path]::IsPathRooted($ManifestPath)) {
    [System.IO.Path]::GetFullPath($ManifestPath)
  } else {
    [System.IO.Path]::GetFullPath((Join-Path $stagingDirectory $ManifestPath))
  }
  if (-not (Test-Path -LiteralPath $resolvedManifest -PathType Leaf)) {
    throw "runtime manifest not found: $resolvedManifest"
  }

  $manifest = Get-Content -LiteralPath $resolvedManifest -Raw | ConvertFrom-Json
  if ([int]$manifest.schema_version -ne 1) {
    throw "unsupported runtime manifest schema_version: $($manifest.schema_version)"
  }
  $files = @($manifest.files)
  if ($files.Count -lt 1 -or $files.Count -gt 64) {
    throw "runtime manifest must contain between 1 and 64 files"
  }

  $seen = @{}
  $plan = @()
  foreach ($entry in $files) {
    $name = [string]$entry.name
    $hash = ([string]$entry.sha256).ToLowerInvariant()
    if ($name -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.dll$' -or
        [System.IO.Path]::GetFileName($name) -ne $name) {
      throw "invalid runtime DLL name in manifest: $name"
    }
    $key = $name.ToLowerInvariant()
    if ($seen.ContainsKey($key)) {
      throw "duplicate runtime DLL in manifest: $name"
    }
    $seen[$key] = $true
    if ($hash -notmatch '^[0-9a-f]{64}$') {
      throw "invalid SHA256 for runtime DLL: $name"
    }

    $sourcePath = [System.IO.Path]::GetFullPath((Join-Path (Split-Path -Parent $resolvedManifest) $name))
    if (-not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) {
      throw "staged runtime DLL not found: $sourcePath"
    }
    $actualHash = Get-Sha256 -Path $sourcePath
    if ($actualHash -ne $hash) {
      throw "staged runtime DLL hash mismatch: name=$name expected=$hash actual=$actualHash"
    }

    $targetPath = Join-Path $InstallDirectory $name
    $plan += [pscustomobject]@{
      Name = $name
      ExpectedSha256 = $hash
      SourcePath = $sourcePath
      TargetPath = $targetPath
      CandidatePath = "$targetPath.candidate-$Version"
      BackupPath = "$targetPath.rollback-$Version-$Timestamp"
      FailedPath = "$targetPath.failed-$Version-$Timestamp"
      TargetExisted = (Test-Path -LiteralPath $targetPath -PathType Leaf)
      Committed = $false
      Status = "validated"
    }
  }
  return $plan
}

function Stage-RuntimeUpdatePlan {
  param([object[]]$Plan)

  foreach ($item in @($Plan)) {
    Copy-Item -LiteralPath $item.SourcePath -Destination $item.CandidatePath -Force
    $actualHash = Get-Sha256 -Path $item.CandidatePath
    if ($actualHash -ne $item.ExpectedSha256) {
      throw "runtime DLL hash changed after local staging: name=$($item.Name)"
    }
    $item.Status = "staged"
  }
}

function Commit-RuntimeUpdatePlan {
  param([object[]]$Plan)

  foreach ($item in @($Plan)) {
    if ($item.TargetExisted) {
      [System.IO.File]::Replace($item.CandidatePath, $item.TargetPath, $item.BackupPath, $true)
    } else {
      Move-Item -LiteralPath $item.CandidatePath -Destination $item.TargetPath -Force
    }
    $item.Committed = $true
    $item.Status = "committed"
    $actualHash = Get-Sha256 -Path $item.TargetPath
    if ($actualHash -ne $item.ExpectedSha256) {
      throw "installed runtime DLL hash mismatch: name=$($item.Name)"
    }
  }
}

function Rollback-RuntimeUpdatePlan {
  param([object[]]$Plan)

  for ($index = @($Plan).Count - 1; $index -ge 0; $index--) {
    $item = @($Plan)[$index]
    if (-not $item.Committed) {
      continue
    }
    if ($item.TargetExisted) {
      if (-not (Test-Path -LiteralPath $item.BackupPath -PathType Leaf)) {
        throw "runtime DLL rollback backup missing: name=$($item.Name)"
      }
      $restoreCandidate = "$($item.BackupPath).restore"
      Copy-Item -LiteralPath $item.BackupPath -Destination $restoreCandidate -Force
      if (Test-Path -LiteralPath $item.TargetPath -PathType Leaf) {
        [System.IO.File]::Replace($restoreCandidate, $item.TargetPath, $item.FailedPath, $true)
      } else {
        Move-Item -LiteralPath $restoreCandidate -Destination $item.TargetPath -Force
      }
    } elseif (Test-Path -LiteralPath $item.TargetPath -PathType Leaf) {
      Move-Item -LiteralPath $item.TargetPath -Destination $item.FailedPath -Force
    }
    $item.Status = "rolled_back"
  }
}

function Get-AgentProcesses {
  param([Parameter(Mandatory = $true)][string]$ExecutablePath)

  $expected = [System.IO.Path]::GetFullPath($ExecutablePath)
  return @(Get-CimInstance Win32_Process -Filter "Name='FDSensor.exe'" -ErrorAction SilentlyContinue |
    Where-Object {
      $actual = [string]$_.ExecutablePath
      if (-not $actual) { return $false }
      try { return [System.IO.Path]::GetFullPath($actual) -ieq $expected } catch { return $false }
    })
}

function Wait-AgentProcess {
  param(
    [Parameter(Mandatory = $true)][string]$ExecutablePath,
    [Parameter(Mandatory = $true)][bool]$Running,
    [Parameter(Mandatory = $true)][int]$TimeoutSeconds
  )

  $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
  do {
    $count = @(Get-AgentProcesses -ExecutablePath $ExecutablePath).Count
    if (($Running -and $count -gt 0) -or ((-not $Running) -and $count -eq 0)) {
      return
    }
    Start-Sleep -Milliseconds 500
  } while ((Get-Date) -lt $deadline)

  $wanted = if ($Running) { "start" } else { "stop" }
  throw "timed out waiting for FDSensor.exe to $wanted"
}

function Stop-AgentTask {
  param([string]$TaskName, [string]$TaskPath, [string]$ExecutablePath)

  Stop-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue
  foreach ($process in @(Get-AgentProcesses -ExecutablePath $ExecutablePath)) {
    Stop-Process -Id ([int]$process.ProcessId) -Force -ErrorAction SilentlyContinue
  }
  Wait-AgentProcess -ExecutablePath $ExecutablePath -Running $false -TimeoutSeconds 30
}

function Prepare-AgentRuntimeForUpdate {
  param(
    [string]$InstallDirectory,
    [string]$TaskName,
    [string]$TaskPath,
    [string]$ExecutablePath
  )

  $autorun = Join-Path $InstallDirectory "edr_windows_autorun.ps1"
  if (Test-Path -LiteralPath $autorun -PathType Leaf) {
    $powershell = Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe"
    if (-not (Test-Path -LiteralPath $powershell -PathType Leaf)) {
      $powershell = "powershell.exe"
    }
    & $powershell -NoProfile -ExecutionPolicy Bypass -File $autorun -Action Install -NoStart | Out-Null
    if ($LASTEXITCODE -ne 0) {
      throw "Agent autorun preflight failed with exit code $LASTEXITCODE"
    }
    Wait-AgentProcess -ExecutablePath $ExecutablePath -Running $false -TimeoutSeconds 30
    return "autorun_rebuilt"
  }

  Stop-AgentTask -TaskName $TaskName -TaskPath $TaskPath -ExecutablePath $ExecutablePath
  return "existing_task_stopped"
}

function Resolve-DeploymentMode {
  param([string]$Mode, [string]$TaskName, [string]$TaskPath, [string]$WindowsServiceName)
  if ($Mode -ne 'auto') { return $Mode }
  if (Get-Service -Name $WindowsServiceName -ErrorAction SilentlyContinue) { return 'service' }
  if (Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue) { return 'scheduled_task' }
  throw 'auto deployment mode could not find the configured service or scheduled task'
}

function Stop-AgentRuntime {
  param([string]$Mode, [string]$TaskName, [string]$TaskPath, [string]$WindowsServiceName, [string]$ExecutablePath)
  if ($Mode -eq 'service') {
    Stop-Service -Name $WindowsServiceName -Force -ErrorAction Stop
  } else {
    Stop-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue
  }
  foreach ($process in @(Get-AgentProcesses -ExecutablePath $ExecutablePath)) {
    Stop-Process -Id ([int]$process.ProcessId) -Force -ErrorAction SilentlyContinue
  }
  Wait-AgentProcess -ExecutablePath $ExecutablePath -Running $false -TimeoutSeconds 30
}

function Start-AgentRuntime {
  param([string]$Mode, [string]$TaskName, [string]$TaskPath, [string]$WindowsServiceName,
    [string]$ExecutablePath, [int]$TimeoutSeconds)
  if ($Mode -eq 'service') {
    Start-Service -Name $WindowsServiceName -ErrorAction Stop
  } else {
    Start-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath
  }
  Wait-AgentProcess -ExecutablePath $ExecutablePath -Running $true -TimeoutSeconds $TimeoutSeconds
  Start-Sleep -Seconds 5
  if (@(Get-AgentProcesses -ExecutablePath $ExecutablePath).Count -eq 0) {
    throw "FDSensor.exe exited during the startup stability check"
  }
  if ($Mode -eq 'service' -and (Get-Service -Name $WindowsServiceName).Status -ne 'Running') {
    throw "Agent service exited during the startup stability check"
  }
}

function Write-UpdateReport {
  param([string]$Path, [object]$Report)

  $directory = Split-Path -Parent $Path
  New-Item -ItemType Directory -Path $directory -Force | Out-Null
  Write-AtomicJson -Path $Path -Value $Report
}

$installFull = [System.IO.Path]::GetFullPath($InstallDir)
$stateRoot = Join-Path $env:ProgramData 'FDSecurity\state'
$logRoot = Join-Path $env:ProgramData 'FDSecurity\logs'
$currentPath = Join-Path $installFull "FDSensor.exe"
$stagedPath = if ([System.IO.Path]::IsPathRooted($StagedBinary)) {
  [System.IO.Path]::GetFullPath($StagedBinary)
} else {
  Join-Path $installFull $StagedBinary
}
$safeCommandId = $CommandId -replace '[^A-Za-z0-9._-]', '_'
$reportPath = Join-Path $logRoot ("agent-update-{0}-report.json" -f $safeCommandId)
$journalPath = Join-Path $stateRoot ("agent-update-{0}.journal.json" -f $safeCommandId)
$expectedHash = $ExpectedSha256.ToLowerInvariant()
$machineExpected = if ($ExpectedArchitecture -eq "arm64") { 0xAA64 } else { 0x8664 }
$stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
$backupPath = Join-Path $installFull ("FDSensor.exe.rollback-{0}-{1}" -f $TargetVersion, $stamp)
$candidatePath = Join-Path $installFull ("FDSensor.exe.candidate-{0}" -f $TargetVersion)
$failedPath = Join-Path $installFull ("FDSensor.exe.failed-{0}-{1}" -f $TargetVersion, $stamp)
$replacementCommitted = $false
$failureMessage = ""
$runtimePlan = @()
$resolvedDeploymentMode = $null
$journal = [ordered]@{
  schema_version = 1
  command_id = $CommandId
  target_version = $TargetVersion
  status = 'running'
  stage = 'initialized'
  replacement_committed = $false
  error = $null
  updated_at = (Get-Date).ToUniversalTime().ToString('o')
}
function Set-UpdateStage {
  param([string]$Stage, [string]$Status = 'running')
  $journal['stage'] = $Stage; $journal['status'] = $Status
  if ($Status -ne 'running' -and $report -and $report['error']) { $journal['error'] = $report['error'] }
  $journal['updated_at'] = (Get-Date).ToUniversalTime().ToString('o')
  Write-AtomicJson -Path $journalPath -Value $journal
  if ($report) { $report['stage'] = $Stage }
}

$report = [ordered]@{
  created_at = (Get-Date).ToUniversalTime().ToString("o")
  completed_at = $null
  status = "running"
  stage = "initialized"
  failed_stage = $null
  target_version = $TargetVersion
  expected_architecture = $ExpectedArchitecture
  expected_sha256 = $expectedHash
  previous_sha256 = $null
  installed_sha256 = $null
  backup_path = $backupPath
  runtime_preparation = $null
  runtime_manifest = $RuntimeManifest
  runtime_files = @()
  rollback = "not_required"
  error = $null
  error_type = $null
  error_position = $null
  error_stack = $null
}

try {
  if (Test-Path -LiteralPath $journalPath -PathType Leaf) {
    $prior = Get-Content -LiteralPath $journalPath -Raw | ConvertFrom-Json
    if ([string]$prior.status -in @('succeeded','failed_rolled_back','failed_recovered','failed')) {
      $prior | ConvertTo-Json -Depth 10 -Compress
      if ([string]$prior.status -eq 'succeeded') { exit 0 }
      exit 1
    }
    if ([bool]$prior.replacement_committed -or [string]$prior.stage -in @('replacement_committed','start_new_runtime','completed','rollback_started','rollback_completed')) {
      throw 'recovered update journal proves replacement already committed; refusing duplicate replacement'
    }
  }
  Set-UpdateStage -Stage "validate_identity"
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($identity)
  if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Agent update requires an elevated Administrator or SYSTEM context"
  }
  if (-not (Test-Path -LiteralPath $currentPath -PathType Leaf)) {
    throw "current Agent binary not found: $currentPath"
  }
  if (-not (Test-Path -LiteralPath $stagedPath -PathType Leaf)) {
    throw "staged Agent binary not found: $stagedPath"
  }

  Set-UpdateStage -Stage "validate_candidate"
  $candidateLength = (Get-Item -LiteralPath $stagedPath).Length
  $requiredFree = [Math]::Max([UInt64]($candidateLength * 3), $MinFreeBytes)
  $drive = Get-PSDrive -Name ([System.IO.Path]::GetPathRoot($installFull).Substring(0,1))
  if ([UInt64]$drive.Free -lt $requiredFree) { throw "insufficient disk space: required=$requiredFree available=$($drive.Free)" }
  $stagedHash = Get-Sha256 -Path $stagedPath
  if ($stagedHash -ne $expectedHash) {
    throw "staged Agent hash mismatch: expected=$expectedHash actual=$stagedHash"
  }
  $machineActual = Get-PeMachine -Path $stagedPath
  if ($machineActual -ne $machineExpected) {
    throw ("staged Agent architecture mismatch: expected={0} PE_machine=0x{1:X4}" -f
      $ExpectedArchitecture, $machineActual)
  }
  $currentIdentity = Get-VersionIdentity -Path $currentPath
  $candidateIdentity = Get-VersionIdentity -Path $stagedPath
  if ($candidateIdentity.InternalName -ne $ExpectedInternalName) { throw 'candidate InternalName mismatch' }
  if ($candidateIdentity.ProductVersion -ne $TargetVersion) { throw 'candidate ProductVersion does not match target_version' }
  if ((Compare-SemVer $TargetVersion $currentIdentity.ProductVersion) -le 0) { throw 'candidate version is not an upgrade' }
  if ($MinCurrentVersion -and (Compare-SemVer $currentIdentity.ProductVersion $MinCurrentVersion) -lt 0) { throw 'current version is below update compatibility floor' }
  if ($MaxCurrentVersion -and (Compare-SemVer $currentIdentity.ProductVersion $MaxCurrentVersion) -gt 0) { throw 'current version is above update compatibility ceiling' }
  Assert-AuthenticodePublisher -Path $stagedPath -Thumbprint $TrustedPublisherThumbprint -Subject $TrustedPublisherSubject
  $resolvedDeploymentMode = Resolve-DeploymentMode -Mode $DeploymentMode -TaskName $ScheduledTaskName -TaskPath $ScheduledTaskPath -WindowsServiceName $ServiceName

  Set-UpdateStage -Stage "validate_runtime_manifest"
  if ($RuntimeManifest) {
    if ($RuntimeManifestSha256 -notmatch '^[0-9A-Fa-f]{64}$') { throw 'RuntimeManifestSha256 is required for runtime manifest' }
    if ((Get-Sha256 -Path $RuntimeManifest) -ne $RuntimeManifestSha256.ToLowerInvariant()) { throw 'runtime manifest SHA256 mismatch' }
  }
  $runtimePlan = @(Get-RuntimeUpdatePlan -StagedBinaryPath $stagedPath `
    -InstallDirectory $installFull -ManifestPath $RuntimeManifest `
    -Version $TargetVersion -Timestamp $stamp)

  Set-UpdateStage -Stage "stage_candidate"
  $report["previous_sha256"] = Get-Sha256 -Path $currentPath
  Copy-Item -LiteralPath $stagedPath -Destination $candidatePath -Force
  if ((Get-Sha256 -Path $candidatePath) -ne $expectedHash) {
    throw "candidate Agent hash changed after local staging"
  }
  Stage-RuntimeUpdatePlan -Plan $runtimePlan

  if ($DrainDelaySeconds -gt 0) {
    Set-UpdateStage -Stage "drain"
    Start-Sleep -Seconds $DrainDelaySeconds
  }
  Set-UpdateStage -Stage "prepare_runtime"
  Stop-AgentRuntime -Mode $resolvedDeploymentMode -TaskName $ScheduledTaskName `
    -TaskPath $ScheduledTaskPath -WindowsServiceName $ServiceName -ExecutablePath $currentPath
  $report["runtime_preparation"] = "$resolvedDeploymentMode-stopped"

  Set-UpdateStage -Stage "replace_runtime"
  Commit-RuntimeUpdatePlan -Plan $runtimePlan
  Set-UpdateStage -Stage "replace_binary"
  [System.IO.File]::Replace($candidatePath, $currentPath, $backupPath, $true)
  $replacementCommitted = $true
  $journal["replacement_committed"] = $true
  Set-UpdateStage -Stage "replacement_committed"
  if ((Get-Sha256 -Path $currentPath) -ne $expectedHash) {
    throw "installed Agent hash does not match the staged binary"
  }

  Set-UpdateStage -Stage "start_new_runtime"
  Start-AgentRuntime -Mode $resolvedDeploymentMode -TaskName $ScheduledTaskName `
    -TaskPath $ScheduledTaskPath -WindowsServiceName $ServiceName `
    -ExecutablePath $currentPath -TimeoutSeconds $StartupTimeoutSeconds
  $report["installed_sha256"] = Get-Sha256 -Path $currentPath
  $report["status"] = "succeeded"
  Set-UpdateStage -Stage "completed" -Status "succeeded"
  Remove-Item -LiteralPath $stagedPath -Force -ErrorAction SilentlyContinue
} catch {
  $failureMessage = $_.Exception.Message
  $report["failed_stage"] = $report["stage"]
  $report["error"] = $failureMessage
  $report["error_type"] = $_.Exception.GetType().FullName
  $report["error_position"] = $_.InvocationInfo.PositionMessage
  $report["error_stack"] = $_.ScriptStackTrace
  $report["status"] = "failed"

  $runtimeCommitted = @($runtimePlan | Where-Object { $_.Committed }).Count -gt 0
  if ($replacementCommitted -or $runtimeCommitted) {
    try {
      Set-UpdateStage -Stage "rollback_started"
      Stop-AgentRuntime -Mode $resolvedDeploymentMode -TaskName $ScheduledTaskName -TaskPath $ScheduledTaskPath -WindowsServiceName $ServiceName -ExecutablePath $currentPath
      if ($replacementCommitted) {
        Set-UpdateStage -Stage "rollback_restore_binary"
        if (-not (Test-Path -LiteralPath $backupPath -PathType Leaf)) {
          throw "Agent binary rollback backup missing: $backupPath"
        }
        $restoreCandidate = "$backupPath.restore"
        Copy-Item -LiteralPath $backupPath -Destination $restoreCandidate -Force
        if (Test-Path -LiteralPath $currentPath -PathType Leaf) {
          [System.IO.File]::Replace($restoreCandidate, $currentPath, $failedPath, $true)
        } else {
          Move-Item -LiteralPath $restoreCandidate -Destination $currentPath -Force
        }
      }
      Set-UpdateStage -Stage "rollback_restore_runtime"
      Rollback-RuntimeUpdatePlan -Plan $runtimePlan
      Set-UpdateStage -Stage "rollback_start_runtime"
      Start-AgentRuntime -Mode $resolvedDeploymentMode -TaskName $ScheduledTaskName `
        -TaskPath $ScheduledTaskPath -WindowsServiceName $ServiceName `
        -ExecutablePath $currentPath -TimeoutSeconds $StartupTimeoutSeconds
      $report["rollback"] = "succeeded"
      $report["status"] = "failed_rolled_back"
      $report["installed_sha256"] = Get-Sha256 -Path $currentPath
      Set-UpdateStage -Stage "rollback_completed" -Status "failed_rolled_back"
    } catch {
      $report["rollback"] = "failed"
      $report["error"] = "$failureMessage; rollback failed: $($_.Exception.Message)"
      Set-UpdateStage -Stage "rollback_failed" -Status "failed"
    }
  } elseif (Test-Path -LiteralPath $currentPath -PathType Leaf) {
    try {
      Set-UpdateStage -Stage "recovery_start_runtime"
      Start-AgentRuntime -Mode $resolvedDeploymentMode -TaskName $ScheduledTaskName `
        -TaskPath $ScheduledTaskPath -WindowsServiceName $ServiceName `
        -ExecutablePath $currentPath -TimeoutSeconds $StartupTimeoutSeconds
      $report["rollback"] = "not_required_runtime_restarted"
      $report["status"] = "failed_recovered"
      $report["installed_sha256"] = Get-Sha256 -Path $currentPath
      Set-UpdateStage -Stage "recovery_completed" -Status "failed_recovered"
    } catch {
      $report["rollback"] = "failed"
      $report["error"] = "$failureMessage; runtime recovery failed: $($_.Exception.Message)"
      Set-UpdateStage -Stage "recovery_failed" -Status "failed"
    }
  } else {
    Set-UpdateStage -Stage "failed_before_stop" -Status "failed"
  }
} finally {
  Remove-Item -LiteralPath $candidatePath -Force -ErrorAction SilentlyContinue
  foreach ($item in @($runtimePlan)) {
    Remove-Item -LiteralPath $item.CandidatePath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath "$($item.BackupPath).restore" -Force -ErrorAction SilentlyContinue
  }
  $report["runtime_files"] = @($runtimePlan | ForEach-Object {
    [ordered]@{
      name = $_.Name
      expected_sha256 = $_.ExpectedSha256
      target_existed = $_.TargetExisted
      status = $_.Status
    }
  })
  $report["completed_at"] = (Get-Date).ToUniversalTime().ToString("o")
  try {
    Write-UpdateReport -Path $reportPath -Report $report
  } catch {
    Write-Error ("failed to persist Agent update report: " + $_.Exception.Message)
  }
}

if ($report["status"] -ne "succeeded") {
  Write-Error ("Agent update failed: " + $report["error"])
  exit 1
}

Write-Output ($report | ConvertTo-Json -Depth 8 -Compress)
exit 0
