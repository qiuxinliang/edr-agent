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
  [string]$UpdaterTaskName = "",
  [string]$StagingDirectory = "",
  [ValidateRange(0, 1099511627776)]
  [UInt64]$MinFreeBytes = 0,
  [string]$CommandId = "manual",
  [Parameter(Mandatory = $true)]
  [string]$TaskId,
  [string]$CampaignId = "",
  [ValidateSet("upgrade", "rollback")]
  [string]$Operation = "upgrade",
  [Parameter(Mandatory = $true)]
  [string]$ArtifactId,
  [ValidateRange(1, 9007199254740991)]
  [UInt64]$IssuedAtUnixMs = 1,
  [ValidateRange(1, 9007199254740991)]
  [UInt64]$DeadlineUnixMs = 2,
  [ValidateRange(1, 86400000)]
  [UInt64]$HealthObserveMs = 30000,
  [string]$RuntimeManifestSha256 = "",
  [ValidateRange(0, 60)]
  [int]$DrainDelaySeconds = 5,
  [ValidateRange(10, 300)]
  [int]$StartupTimeoutSeconds = 60
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$AgentUpdateUpdaterProtocolVersion = 2

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

function Normalize-ProductVersion {
  param([Parameter(Mandatory = $true)][string]$Version)
  $value = ($Version -split '[ +]')[0].Trim()
  if ($value -match '^((?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*))(?:\.0)?$') {
    return [string]$Matches[1]
  }
  throw "invalid Windows ProductVersion: $Version"
}

function Get-VersionIdentity {
  param([Parameter(Mandatory = $true)][string]$Path)
  $info = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($Path)
  $version = [string]$info.ProductVersion
  if ($version) { $version = Normalize-ProductVersion $version }
  return [pscustomobject]@{ InternalName=[string]$info.InternalName; ProductVersion=$version }
}

function Assert-AuthenticodePublisher {
  param([string]$Path, [string]$Thumbprint, [string]$Subject)
  if ($Thumbprint -eq 'SHA256_ONLY_UNSIGNED') {
    if ($Subject -ne 'Unsigned release; SHA-256 integrity only') {
      throw "unsigned release publisher marker is inconsistent"
    }
    Write-Warning "Agent candidate is unsigned; accepting the already verified task-pinned SHA-256 because the platform explicitly published this release in optional-signing mode."
    return
  }
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
    Sync-RuntimePlanJournal
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
    $item.Committed = $false
    $item.Status = "rolled_back"
    Sync-RuntimePlanJournal
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
  for ($stableCheck = 0; $stableCheck -lt 3; $stableCheck++) {
    Start-Sleep -Seconds 1
    if (@(Get-AgentProcesses -ExecutablePath $ExecutablePath).Count -eq 0) {
      throw "FDSensor.exe exited during the startup stability check"
    }
    if ($Mode -eq 'service') {
      $service = Get-Service -Name $WindowsServiceName -ErrorAction SilentlyContinue
      if (-not $service -or $service.Status -ne 'Running') {
        throw "Agent service exited during the startup stability check"
      }
    } else {
      $task = Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue
      if (-not $task -or [string]$task.State -ne 'Running') {
        throw "Agent scheduled task exited during the startup stability check"
      }
    }
  }
}

function Get-UnixTimeMilliseconds {
  return [UInt64][Math]::Floor((((Get-Date).ToUniversalTime()) - [DateTime]'1970-01-01T00:00:00Z').TotalMilliseconds)
}

function Wait-AgentHealthObservation {
  param(
    [string]$Mode,
    [string]$TaskName,
    [string]$TaskPath,
    [string]$WindowsServiceName,
    [string]$ExecutablePath,
    [UInt64]$ObserveUntilUnixMs
  )

  $nextCheckpoint = Get-UnixTimeMilliseconds
  while ((Get-UnixTimeMilliseconds) -lt $ObserveUntilUnixMs) {
    if (@(Get-AgentProcesses -ExecutablePath $ExecutablePath).Count -eq 0) {
      throw 'FDSensor.exe exited during the local health observation window'
    }
    if ($Mode -eq 'service') {
      $service = Get-Service -Name $WindowsServiceName -ErrorAction SilentlyContinue
      if (-not $service -or $service.Status -ne 'Running') {
        throw 'Agent service stopped during the local health observation window'
      }
    } else {
      $task = Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue
      if (-not $task -or [string]$task.State -ne 'Running') {
        throw 'Agent scheduled task stopped during the local health observation window'
      }
    }
    $now = Get-UnixTimeMilliseconds
    if ($now -ge $nextCheckpoint) {
      $journal['health_last_checked_unix_ms'] = $now
      Set-UpdateStage -Stage 'health_observation'
      $nextCheckpoint = $now + 10000
    }
    $remainingMs = [Int64]$ObserveUntilUnixMs - [Int64](Get-UnixTimeMilliseconds)
    if ($remainingMs -gt 0) {
      $sleepMs = [int][Math]::Min(1000, [Math]::Max(100, $remainingMs))
      Start-Sleep -Milliseconds $sleepMs
    }
  }
  if (@(Get-AgentProcesses -ExecutablePath $ExecutablePath).Count -eq 0) {
    throw 'FDSensor.exe exited at the end of the local health observation window'
  }
}

function Write-UpdateReport {
  param([string]$Path, [object]$Report)

  $directory = Split-Path -Parent $Path
  New-Item -ItemType Directory -Path $directory -Force | Out-Null
  Write-AtomicJson -Path $Path -Value $Report
}

function Clear-StaleUpdateWork {
  param([string]$CurrentStagingDirectory)

  $workRoot = [System.IO.Path]::GetFullPath((Join-Path ([System.IO.Path]::GetTempPath()) 'FDSecurity\agent-update'))
  if (-not (Test-Path -LiteralPath $workRoot -PathType Container)) { return }
  $current = if ([string]::IsNullOrWhiteSpace($CurrentStagingDirectory)) { '' } else {
    [System.IO.Path]::GetFullPath($CurrentStagingDirectory)
  }
  $cutoff = (Get-Date).ToUniversalTime().AddHours(-24)
  foreach ($directory in @(Get-ChildItem -LiteralPath $workRoot -Directory -ErrorAction SilentlyContinue)) {
    if ($current -and [string]::Equals($directory.FullName, $current, [StringComparison]::OrdinalIgnoreCase)) { continue }
    if ($directory.LastWriteTimeUtc -ge $cutoff) { continue }
    $taskName = 'FDSecurityAgentUpdate-' + $directory.Name
    try {
      $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
      if ($task) {
        if ([string]$task.State -eq 'Running') { continue }
        $taskInfo = Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction SilentlyContinue
        if ($taskInfo -and $taskInfo.LastRunTime -and $taskInfo.LastRunTime.ToUniversalTime() -ge $cutoff) { continue }
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop
      }
      Remove-Item -LiteralPath $directory.FullName -Recurse -Force -ErrorAction Stop
    } catch {
      Write-Warning ("failed to clean stale Agent update work {0}: {1}" -f $directory.FullName, $_.Exception.Message)
    }
  }
}

function Remove-CurrentUpdateWork {
  param([string]$Directory, [string]$StagedPath, [string]$SafeCommandId)

  if ([string]::IsNullOrWhiteSpace($Directory)) { return }
  try {
    $full = [System.IO.Path]::GetFullPath($Directory)
    $stagedParent = [System.IO.Path]::GetFullPath((Split-Path -Parent $StagedPath))
    $workRoot = [System.IO.Path]::GetFullPath((Join-Path ([System.IO.Path]::GetTempPath()) 'FDSecurity\agent-update'))
    $prefix = $workRoot.TrimEnd('\') + '\'
    if (-not [string]::Equals($full, $stagedParent, [StringComparison]::OrdinalIgnoreCase) -or
        -not $full.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) -or
        -not [string]::Equals((Split-Path -Leaf $full), $SafeCommandId, [StringComparison]::OrdinalIgnoreCase)) {
      Write-Warning ("refusing unsafe Agent update staging cleanup: " + $full)
      return
    }
    Remove-Item -LiteralPath $full -Recurse -Force -ErrorAction Stop
  } catch {
    Write-Warning ("failed to clean current Agent update work: " + $_.Exception.Message)
  }
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
Clear-StaleUpdateWork -CurrentStagingDirectory $StagingDirectory
$journal = [ordered]@{
  schema_version = 2
  task_id = $TaskId
  command_id = $CommandId
  operation = $Operation
  artifact_id = $ArtifactId
  hash = $expectedHash
  version = $TargetVersion
  issued_at_unix_ms = $IssuedAtUnixMs
  deadline_unix_ms = $DeadlineUnixMs
  health_observe_ms = $HealthObserveMs
  status = 'running'
  stage = 'initialized'
  replacement_committed = $false
  backup_path = $backupPath
  failed_path = $failedPath
  resolved_deployment_mode = $null
  previous_sha256 = $null
  health_observation_started_at_unix_ms = 0
  health_observation_deadline_unix_ms = 0
  health_last_checked_unix_ms = 0
  runtime_files = @()
  last_event_seq = 2
  events = @()
  error = $null
  updated_at = (Get-Date).ToUniversalTime().ToString('o')
}
function Add-UpdateEvent {
  param([string]$Status, [int]$Progress, [hashtable]$Detail)
  $nextSequence = [UInt64]$journal['last_event_seq'] + 1
  $journal['last_event_seq'] = $nextSequence
  $journal['events'] = @($journal['events']) + [ordered]@{
    event_seq = $nextSequence
    status = $Status
    progress = $Progress
    detail = $Detail
    reported_at = (Get-Date).ToUniversalTime().ToString('o')
  }
}
function Set-UpdateStage {
  param([string]$Stage, [string]$Status = 'running')
  $journal['stage'] = $Stage; $journal['status'] = $Status
  if ($Status -ne 'running' -and $report -and $report['error']) { $journal['error'] = $report['error'] }
  $journal['updated_at'] = (Get-Date).ToUniversalTime().ToString('o')
  Write-AtomicJson -Path $journalPath -Value $journal
  if ($report) { $report['stage'] = $Stage }
}

function Sync-RuntimePlanJournal {
  $journal['runtime_files'] = @($runtimePlan | ForEach-Object {
    [ordered]@{
      name = $_.Name
      expected_sha256 = $_.ExpectedSha256
      target_path = $_.TargetPath
      candidate_path = $_.CandidatePath
      backup_path = $_.BackupPath
      failed_path = $_.FailedPath
      target_existed = [bool]$_.TargetExisted
      committed = [bool]$_.Committed
      status = [string]$_.Status
    }
  })
  $journal['updated_at'] = (Get-Date).ToUniversalTime().ToString('o')
  Write-AtomicJson -Path $journalPath -Value $journal
}

function Restore-RuntimePlanFromJournal {
  param([object[]]$Entries)
  $restored = @()
  foreach ($entry in @($Entries)) {
    if (-not $entry) { continue }
    $committed = [bool]$entry.committed
    $targetPath = [string]$entry.target_path
    $candidatePath = [string]$entry.candidate_path
    $backupPath = [string]$entry.backup_path
    $expected = ([string]$entry.expected_sha256).ToLowerInvariant()
    $status = [string]$entry.status
    $targetExists = $targetPath -and (Test-Path -LiteralPath $targetPath -PathType Leaf)
    $targetHash = if ($targetExists) { Get-Sha256 -Path $targetPath } else { '' }
    $backupExists = $backupPath -and (Test-Path -LiteralPath $backupPath -PathType Leaf)
    if ($status -eq 'rolled_back') {
      $committed = $false
    } elseif ($committed -and [bool]$entry.target_existed -and $backupExists -and
        $targetHash -eq (Get-Sha256 -Path $backupPath)) {
      # The restore moved the original bytes back before the journal checkpoint.
      $committed = $false
      $status = 'rolled_back'
    } elseif ($committed -and -not [bool]$entry.target_existed -and -not $targetExists) {
      # A newly added runtime file was already removed by rollback.
      $committed = $false
      $status = 'rolled_back'
    } elseif (-not $committed -and $targetHash -eq $expected -and
        (($entry.target_existed -and $backupExists) -or
         (-not $entry.target_existed -and -not (Test-Path -LiteralPath $candidatePath -PathType Leaf)))) {
      # The commit completed before its durable checkpoint.
      $committed = $true
      $status = 'committed'
    }
    $restored += [pscustomobject]@{
      Name = [string]$entry.name
      ExpectedSha256 = $expected
      SourcePath = ''
      TargetPath = $targetPath
      CandidatePath = $candidatePath
      BackupPath = $backupPath
      FailedPath = [string]$entry.failed_path
      TargetExisted = [bool]$entry.target_existed
      Committed = $committed
      Status = $status
    }
  }
  return @($restored)
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
$resumeCommitted = $false
$resumeRollback = $false
$resumeHealthObservation = $false
$priorLastStatus = ''

try {
  if ($DeadlineUnixMs -le $IssuedAtUnixMs) {
    throw 'deadline_unix_ms must be after issued_at_unix_ms'
  }
  if (Test-Path -LiteralPath $journalPath -PathType Leaf) {
    $prior = Get-Content -LiteralPath $journalPath -Raw | ConvertFrom-Json
    if ([int]$prior.schema_version -ne 2 -or [string]$prior.task_id -ne $TaskId -or
        [string]$prior.command_id -ne $CommandId -or [string]$prior.operation -ne $Operation -or
        [string]$prior.artifact_id -ne $ArtifactId -or
        ([string]$prior.hash).ToLowerInvariant() -ne $expectedHash -or
        [string]$prior.version -ne $TargetVersion) {
      throw 'recovered update journal identity does not match launch arguments'
    }
    if ([string]$prior.status -in @('succeeded','failed_rolled_back','failed_recovered','failed')) {
      $prior | ConvertTo-Json -Depth 10 -Compress
      if ([string]$prior.status -eq 'succeeded') { exit 0 }
      exit 1
    }
    $journal['last_event_seq'] = [UInt64]$prior.last_event_seq
    $journal['events'] = @($prior.events)
    $journal['status'] = [string]$prior.status
    $journal['stage'] = [string]$prior.stage
    $journal['replacement_committed'] = [bool]$prior.replacement_committed
    $journal['error'] = $prior.error
    $priorProperties = @($prior.PSObject.Properties.Name)
    foreach ($field in @('backup_path','failed_path','resolved_deployment_mode','previous_sha256',
        'health_observation_started_at_unix_ms','health_observation_deadline_unix_ms','health_last_checked_unix_ms')) {
      if ($priorProperties -contains $field) { $journal[$field] = $prior.$field }
    }
    if ($priorProperties -contains 'backup_path' -and -not [string]::IsNullOrWhiteSpace([string]$prior.backup_path)) {
      $backupPath = [string]$prior.backup_path
    }
    if ($priorProperties -contains 'failed_path' -and -not [string]::IsNullOrWhiteSpace([string]$prior.failed_path)) {
      $failedPath = [string]$prior.failed_path
    }
    if ($priorProperties -contains 'runtime_files') {
      $runtimePlan = @(Restore-RuntimePlanFromJournal -Entries @($prior.runtime_files))
      Sync-RuntimePlanJournal
    }
    if (@($journal['events']).Count -gt 0) {
      $priorLastStatus = [string]@($journal['events'])[-1].status
    }
    $runtimeCommitDetected = @($runtimePlan | Where-Object { $_.Committed }).Count -gt 0
    $currentHash = if (Test-Path -LiteralPath $currentPath -PathType Leaf) { Get-Sha256 -Path $currentPath } else { '' }
    $currentMatchesCandidate = $currentHash -eq $expectedHash
    $replacementMayHaveStarted = [bool]$prior.replacement_committed -or $currentMatchesCandidate -or
      [string]$prior.stage -in @('replace_binary','replacement_committed','start_new_runtime','health_observation','resume_after_commit') -or
      [string]$prior.stage -like 'rollback_*'
    if ($replacementMayHaveStarted -and -not (Test-Path -LiteralPath $backupPath -PathType Leaf)) {
      $fallbackBackup = Get-ChildItem -LiteralPath $installFull -Filter ("FDSensor.exe.rollback-{0}-*" -f $TargetVersion) -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1
      if ($fallbackBackup) {
        $backupPath = $fallbackBackup.FullName
        $journal['backup_path'] = $backupPath
      }
    }
    $currentMatchesBackup = (Test-Path -LiteralPath $backupPath -PathType Leaf) -and
      $currentHash -eq (Get-Sha256 -Path $backupPath)
    $binaryCommitDetected = $currentMatchesCandidate -or ([bool]$prior.replacement_committed -and -not $currentMatchesBackup)
    $resumeHealthObservation = [string]$prior.stage -eq 'health_observation' -and
      [UInt64]$journal['health_observation_deadline_unix_ms'] -gt 0
    $resumeRollback = [string]$prior.stage -like 'rollback_*' -or
      ($currentMatchesBackup -and $replacementMayHaveStarted) -or
      ($runtimeCommitDetected -and -not $binaryCommitDetected)
    $resumeCommitted = $binaryCommitDetected -or [string]$prior.stage -in @(
      'replacement_committed','start_new_runtime','health_observation','completed','resume_after_commit') -or $resumeRollback
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
  if ($resumeCommitted) {
    $replacementCommitted = $binaryCommitDetected
    $journal['replacement_committed'] = $replacementCommitted
    $report['backup_path'] = $backupPath
    $report['previous_sha256'] = $journal['previous_sha256']
    $resolvedDeploymentMode = [string]$journal['resolved_deployment_mode']
    if ([string]::IsNullOrWhiteSpace($resolvedDeploymentMode)) {
      $resolvedDeploymentMode = Resolve-DeploymentMode -Mode $DeploymentMode -TaskName $ScheduledTaskName -TaskPath $ScheduledTaskPath -WindowsServiceName $ServiceName
      $journal['resolved_deployment_mode'] = $resolvedDeploymentMode
    }
    if ($resumeRollback) {
      throw 'resuming interrupted local rollback from durable journal'
    }
    if (-not $replacementCommitted -or (Get-Sha256 -Path $currentPath) -ne $expectedHash) {
      throw 'committed Agent binary no longer matches the task-pinned candidate hash'
    }
    foreach ($item in @($runtimePlan | Where-Object { $_.Committed })) {
      if (-not (Test-Path -LiteralPath $item.TargetPath -PathType Leaf) -or
          (Get-Sha256 -Path $item.TargetPath) -ne $item.ExpectedSha256) {
        throw "committed runtime DLL is missing or corrupt: name=$($item.Name)"
      }
    }
    Set-UpdateStage -Stage 'resume_after_commit'
    $running = @(Get-AgentProcesses -ExecutablePath $currentPath).Count -gt 0
    if ($resumeHealthObservation -and -not $running) {
      throw 'Agent exited while recovering the local health observation window'
    }
    if (-not $resumeHealthObservation -and $priorLastStatus -notin @('restarting','rolling_back','health_check','rollback_health_check')) {
      $resumeStatus = if ($Operation -eq 'rollback') { 'rolling_back' } else { 'restarting' }
      Add-UpdateEvent -Status $resumeStatus -Progress 80 -Detail @{ stage = 'resume_start_new_runtime'; recovered = $true }
      Set-UpdateStage -Stage 'start_new_runtime'
    }
    if (-not $running) {
      Start-AgentRuntime -Mode $resolvedDeploymentMode -TaskName $ScheduledTaskName `
        -TaskPath $ScheduledTaskPath -WindowsServiceName $ServiceName `
        -ExecutablePath $currentPath -TimeoutSeconds $StartupTimeoutSeconds
    }
    if (-not $resumeHealthObservation) {
      $observationStarted = Get-UnixTimeMilliseconds
      $journal['health_observation_started_at_unix_ms'] = $observationStarted
      $journal['health_observation_deadline_unix_ms'] = $observationStarted + $HealthObserveMs
      $observingStatus = if ($Operation -eq 'rollback') { 'rolling_back' } else { 'restarting' }
      Add-UpdateEvent -Status $observingStatus -Progress 90 -Detail @{
        stage = 'local_health_observation'; health_observe_ms = $HealthObserveMs; local_watchdog = 'observing'; recovered = $true
      }
    }
    $observeUntil = [UInt64]$journal['health_observation_deadline_unix_ms']
    if ($observeUntil -le 0) {
      $observeUntil = (Get-UnixTimeMilliseconds) + $HealthObserveMs
      $journal['health_observation_deadline_unix_ms'] = $observeUntil
    }
    Set-UpdateStage -Stage 'health_observation'
    Wait-AgentHealthObservation -Mode $resolvedDeploymentMode -TaskName $ScheduledTaskName `
      -TaskPath $ScheduledTaskPath -WindowsServiceName $ServiceName -ExecutablePath $currentPath `
      -ObserveUntilUnixMs $observeUntil
    $healthStatus = if ($Operation -eq 'rollback') { 'rollback_health_check' } else { 'health_check' }
    Add-UpdateEvent -Status $healthStatus -Progress 100 -Detail @{
      stage = 'local_health_observation_passed'; health_observe_ms = $HealthObserveMs; local_watchdog = 'passed'; recovered = $true
    }
    $report['installed_sha256'] = Get-Sha256 -Path $currentPath
    $report['status'] = 'succeeded'
    Set-UpdateStage -Stage 'completed' -Status 'succeeded'
    Remove-Item -LiteralPath $stagedPath -Force -ErrorAction SilentlyContinue
    return
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
  $versionDirection = Compare-SemVer $TargetVersion $currentIdentity.ProductVersion
  if ($Operation -eq 'upgrade' -and $versionDirection -le 0) { throw 'candidate version is not an upgrade' }
  if ($Operation -eq 'rollback' -and $versionDirection -ge 0) { throw 'rollback target is not older than the current version' }
  if ($Operation -eq 'upgrade' -and $MinCurrentVersion -and (Compare-SemVer $currentIdentity.ProductVersion $MinCurrentVersion) -lt 0) { throw 'current version is below update compatibility floor' }
  if ($Operation -eq 'upgrade' -and $MaxCurrentVersion -and (Compare-SemVer $currentIdentity.ProductVersion $MaxCurrentVersion) -gt 0) { throw 'current version is above update compatibility ceiling' }
  Assert-AuthenticodePublisher -Path $stagedPath -Thumbprint $TrustedPublisherThumbprint -Subject $TrustedPublisherSubject
  $resolvedDeploymentMode = Resolve-DeploymentMode -Mode $DeploymentMode -TaskName $ScheduledTaskName -TaskPath $ScheduledTaskPath -WindowsServiceName $ServiceName
  $journal['resolved_deployment_mode'] = $resolvedDeploymentMode
  Set-UpdateStage -Stage 'deployment_resolved'

  Set-UpdateStage -Stage "validate_runtime_manifest"
  if ($RuntimeManifest) {
    if ($RuntimeManifestSha256 -notmatch '^[0-9A-Fa-f]{64}$') { throw 'RuntimeManifestSha256 is required for runtime manifest' }
    if ((Get-Sha256 -Path $RuntimeManifest) -ne $RuntimeManifestSha256.ToLowerInvariant()) { throw 'runtime manifest SHA256 mismatch' }
  }
  $runtimePlan = @(Get-RuntimeUpdatePlan -StagedBinaryPath $stagedPath `
    -InstallDirectory $installFull -ManifestPath $RuntimeManifest `
    -Version $TargetVersion -Timestamp $stamp)
  Sync-RuntimePlanJournal
  $verifiedStatus = if ($Operation -eq 'rollback') { 'rolling_back' } else { 'verified' }
  if ($priorLastStatus -notin @('verified','installing','rolling_back')) {
    Add-UpdateEvent -Status $verifiedStatus -Progress 35 -Detail @{ stage = 'candidate_verified'; recovered = [bool]$priorLastStatus }
  }
  Set-UpdateStage -Stage "verified"

  $installingStatus = if ($Operation -eq 'rollback') { 'rolling_back' } else { 'installing' }
  if ($priorLastStatus -notin @('installing','rolling_back')) {
    Add-UpdateEvent -Status $installingStatus -Progress 50 -Detail @{ stage = 'stage_candidate'; recovered = [bool]$priorLastStatus }
  }
  Set-UpdateStage -Stage "stage_candidate"
  $report["previous_sha256"] = Get-Sha256 -Path $currentPath
  $journal['previous_sha256'] = $report['previous_sha256']
  $journal['backup_path'] = $backupPath
  $journal['failed_path'] = $failedPath
  Set-UpdateStage -Stage 'stage_candidate'
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

  $restartingStatus = if ($Operation -eq 'rollback') { 'rolling_back' } else { 'restarting' }
  Add-UpdateEvent -Status $restartingStatus -Progress 80 -Detail @{ stage = 'start_new_runtime' }
  Set-UpdateStage -Stage "start_new_runtime"
  Start-AgentRuntime -Mode $resolvedDeploymentMode -TaskName $ScheduledTaskName `
    -TaskPath $ScheduledTaskPath -WindowsServiceName $ServiceName `
    -ExecutablePath $currentPath -TimeoutSeconds $StartupTimeoutSeconds
  $report["installed_sha256"] = Get-Sha256 -Path $currentPath
  $observationStarted = Get-UnixTimeMilliseconds
  $observationDeadline = $observationStarted + $HealthObserveMs
  $journal['health_observation_started_at_unix_ms'] = $observationStarted
  $journal['health_observation_deadline_unix_ms'] = $observationDeadline
  Add-UpdateEvent -Status $restartingStatus -Progress 90 -Detail @{
    stage = 'local_health_observation'; health_observe_ms = $HealthObserveMs; local_watchdog = 'observing'
  }
  Set-UpdateStage -Stage 'health_observation'
  Wait-AgentHealthObservation -Mode $resolvedDeploymentMode -TaskName $ScheduledTaskName `
    -TaskPath $ScheduledTaskPath -WindowsServiceName $ServiceName -ExecutablePath $currentPath `
    -ObserveUntilUnixMs $observationDeadline
  $healthStatus = if ($Operation -eq 'rollback') { 'rollback_health_check' } else { 'health_check' }
  Add-UpdateEvent -Status $healthStatus -Progress 100 -Detail @{
    stage = 'local_health_observation_passed'; health_observe_ms = $HealthObserveMs; local_watchdog = 'passed'
  }
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
  if ($replacementCommitted -or $runtimeCommitted -or $resumeRollback) {
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
        $replacementCommitted = $false
        $journal['replacement_committed'] = $false
        Set-UpdateStage -Stage 'rollback_binary_restored'
      }
      Set-UpdateStage -Stage "rollback_restore_runtime"
      Rollback-RuntimeUpdatePlan -Plan $runtimePlan
      Set-UpdateStage -Stage "rollback_start_runtime"
      Start-AgentRuntime -Mode $resolvedDeploymentMode -TaskName $ScheduledTaskName `
        -TaskPath $ScheduledTaskPath -WindowsServiceName $ServiceName `
        -ExecutablePath $currentPath -TimeoutSeconds $StartupTimeoutSeconds
      $rollbackObserveUntil = (Get-UnixTimeMilliseconds) + [UInt64][Math]::Min([double]$HealthObserveMs, 60000.0)
      Set-UpdateStage -Stage 'rollback_health_observation'
      Wait-AgentHealthObservation -Mode $resolvedDeploymentMode -TaskName $ScheduledTaskName `
        -TaskPath $ScheduledTaskPath -WindowsServiceName $ServiceName -ExecutablePath $currentPath `
        -ObserveUntilUnixMs $rollbackObserveUntil
      $report["rollback"] = "succeeded"
      $report["status"] = "failed_rolled_back"
      $report["installed_sha256"] = Get-Sha256 -Path $currentPath
      if ($Operation -eq 'rollback') {
        Add-UpdateEvent -Status 'rollback_health_check' -Progress 100 -Detail @{
          stage = 'rollback_runtime_healthy'; health_observe_ms = $HealthObserveMs
        }
        Set-UpdateStage -Stage "rollback_health_check"
      } else {
        Add-UpdateEvent -Status 'failed' -Progress 100 -Detail @{
          stage = 'rollback_completed'; rolled_back = $true; local_watchdog = $true; error = $report['error']
        }
      }
      Set-UpdateStage -Stage "rollback_completed" -Status "failed_rolled_back"
    } catch {
      $report["rollback"] = "failed"
      $report["error"] = "$failureMessage; rollback failed: $($_.Exception.Message)"
      Add-UpdateEvent -Status 'failed' -Progress 100 -Detail @{
        stage = 'rollback_failed'; rolled_back = $false; error = $report['error']
      }
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
      Add-UpdateEvent -Status 'failed' -Progress 100 -Detail @{
        stage = 'recovery_completed'; runtime_recovered = $true; error = $report['error']
      }
      Set-UpdateStage -Stage "recovery_completed" -Status "failed_recovered"
    } catch {
      $report["rollback"] = "failed"
      $report["error"] = "$failureMessage; runtime recovery failed: $($_.Exception.Message)"
      Add-UpdateEvent -Status 'failed' -Progress 100 -Detail @{
        stage = 'recovery_failed'; runtime_recovered = $false; error = $report['error']
      }
      Set-UpdateStage -Stage "recovery_failed" -Status "failed"
    }
  } else {
    Add-UpdateEvent -Status 'failed' -Progress 100 -Detail @{
      stage = 'failed_before_stop'; error = $report['error']
    }
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
  if (-not [string]::IsNullOrWhiteSpace($UpdaterTaskName)) {
    try {
      Unregister-ScheduledTask -TaskName $UpdaterTaskName -Confirm:$false -ErrorAction Stop
    } catch {
      Write-Warning ("failed to remove temporary Agent updater task: " + $_.Exception.Message)
    }
  }
  Remove-CurrentUpdateWork -Directory $StagingDirectory -StagedPath $stagedPath -SafeCommandId $safeCommandId
}

if ($report["status"] -ne "succeeded") {
  Write-Error ("Agent update failed: " + $report["error"])
  exit 1
}

Write-Output ($report | ConvertTo-Json -Depth 8 -Compress)
exit 0
