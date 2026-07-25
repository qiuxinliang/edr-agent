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
  [string]$ScheduledTaskName = "FDSecurityAgent",
  [string]$ScheduledTaskPath = "\",
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

function Start-AgentTask {
  param(
    [string]$TaskName,
    [string]$TaskPath,
    [string]$ExecutablePath,
    [int]$TimeoutSeconds
  )

  Start-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath
  Wait-AgentProcess -ExecutablePath $ExecutablePath -Running $true -TimeoutSeconds $TimeoutSeconds
  Start-Sleep -Seconds 3
  if (@(Get-AgentProcesses -ExecutablePath $ExecutablePath).Count -eq 0) {
    throw "FDSensor.exe exited during the startup stability check"
  }
}

function Write-UpdateReport {
  param([string]$Path, [object]$Report)

  $directory = Split-Path -Parent $Path
  New-Item -ItemType Directory -Path $directory -Force | Out-Null
  $temporary = "$Path.tmp"
  [System.IO.File]::WriteAllText(
    [System.IO.Path]::GetFullPath($temporary),
    ($Report | ConvertTo-Json -Depth 8),
    (New-Object System.Text.UTF8Encoding($false)))
  Move-Item -LiteralPath $temporary -Destination $Path -Force
}

$installFull = [System.IO.Path]::GetFullPath($InstallDir)
$currentPath = Join-Path $installFull "FDSensor.exe"
$stagedPath = if ([System.IO.Path]::IsPathRooted($StagedBinary)) {
  [System.IO.Path]::GetFullPath($StagedBinary)
} else {
  Join-Path $installFull $StagedBinary
}
$reportPath = Join-Path $installFull ("logs\agent-update-{0}-report.json" -f $TargetVersion)
$expectedHash = $ExpectedSha256.ToLowerInvariant()
$machineExpected = if ($ExpectedArchitecture -eq "arm64") { 0xAA64 } else { 0x8664 }
$stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
$backupPath = Join-Path $installFull ("FDSensor.exe.rollback-{0}-{1}" -f $TargetVersion, $stamp)
$candidatePath = Join-Path $installFull ("FDSensor.exe.candidate-{0}" -f $TargetVersion)
$failedPath = Join-Path $installFull ("FDSensor.exe.failed-{0}-{1}" -f $TargetVersion, $stamp)
$replacementCommitted = $false
$failureMessage = ""
$runtimePlan = @()

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
  $report["stage"] = "validate_identity"
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

  $report["stage"] = "validate_candidate"
  $stagedHash = Get-Sha256 -Path $stagedPath
  if ($stagedHash -ne $expectedHash) {
    throw "staged Agent hash mismatch: expected=$expectedHash actual=$stagedHash"
  }
  $machineActual = Get-PeMachine -Path $stagedPath
  if ($machineActual -ne $machineExpected) {
    throw ("staged Agent architecture mismatch: expected={0} PE_machine=0x{1:X4}" -f
      $ExpectedArchitecture, $machineActual)
  }

  $report["stage"] = "validate_runtime_manifest"
  $runtimePlan = @(Get-RuntimeUpdatePlan -StagedBinaryPath $stagedPath `
    -InstallDirectory $installFull -ManifestPath $RuntimeManifest `
    -Version $TargetVersion -Timestamp $stamp)

  $report["stage"] = "stage_candidate"
  $report["previous_sha256"] = Get-Sha256 -Path $currentPath
  Copy-Item -LiteralPath $stagedPath -Destination $candidatePath -Force
  if ((Get-Sha256 -Path $candidatePath) -ne $expectedHash) {
    throw "candidate Agent hash changed after local staging"
  }
  Stage-RuntimeUpdatePlan -Plan $runtimePlan

  if ($DrainDelaySeconds -gt 0) {
    $report["stage"] = "drain"
    Start-Sleep -Seconds $DrainDelaySeconds
  }
  $report["stage"] = "prepare_runtime"
  $report["runtime_preparation"] = Prepare-AgentRuntimeForUpdate `
    -InstallDirectory $installFull -TaskName $ScheduledTaskName `
    -TaskPath $ScheduledTaskPath -ExecutablePath $currentPath

  $report["stage"] = "replace_runtime"
  Commit-RuntimeUpdatePlan -Plan $runtimePlan
  $report["stage"] = "replace_binary"
  [System.IO.File]::Replace($candidatePath, $currentPath, $backupPath, $true)
  $replacementCommitted = $true
  $report["stage"] = "verify_installed_binary"
  if ((Get-Sha256 -Path $currentPath) -ne $expectedHash) {
    throw "installed Agent hash does not match the staged binary"
  }

  $report["stage"] = "start_new_runtime"
  Start-AgentTask -TaskName $ScheduledTaskName -TaskPath $ScheduledTaskPath `
    -ExecutablePath $currentPath -TimeoutSeconds $StartupTimeoutSeconds
  $report["installed_sha256"] = Get-Sha256 -Path $currentPath
  $report["status"] = "succeeded"
  $report["stage"] = "completed"
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
      $report["stage"] = "rollback_stop_runtime"
      Stop-AgentTask -TaskName $ScheduledTaskName -TaskPath $ScheduledTaskPath -ExecutablePath $currentPath
      if ($replacementCommitted) {
        $report["stage"] = "rollback_restore_binary"
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
      $report["stage"] = "rollback_restore_runtime"
      Rollback-RuntimeUpdatePlan -Plan $runtimePlan
      $report["stage"] = "rollback_start_runtime"
      Start-AgentTask -TaskName $ScheduledTaskName -TaskPath $ScheduledTaskPath `
        -ExecutablePath $currentPath -TimeoutSeconds $StartupTimeoutSeconds
      $report["rollback"] = "succeeded"
      $report["status"] = "failed_rolled_back"
      $report["installed_sha256"] = Get-Sha256 -Path $currentPath
      $report["stage"] = "rollback_completed"
    } catch {
      $report["rollback"] = "failed"
      $report["error"] = "$failureMessage; rollback failed: $($_.Exception.Message)"
    }
  } elseif (Test-Path -LiteralPath $currentPath -PathType Leaf) {
    try {
      $report["stage"] = "recovery_start_runtime"
      Start-AgentTask -TaskName $ScheduledTaskName -TaskPath $ScheduledTaskPath `
        -ExecutablePath $currentPath -TimeoutSeconds $StartupTimeoutSeconds
      $report["rollback"] = "not_required_runtime_restarted"
      $report["status"] = "failed_recovered"
      $report["installed_sha256"] = Get-Sha256 -Path $currentPath
      $report["stage"] = "recovery_completed"
    } catch {
      $report["rollback"] = "failed"
      $report["error"] = "$failureMessage; runtime recovery failed: $($_.Exception.Message)"
    }
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
