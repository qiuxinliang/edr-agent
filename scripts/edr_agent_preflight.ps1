#Requires -Version 5.1
<#
.SYNOPSIS
  Prepare an installed FDSecurity directory for upgrade/redeploy.

.DESCRIPTION
  Stops the Windows service/process and removes runtime-only queue/evidence
  cache files that commonly block redeploys or replay legacy batches. It keeps
  agent.toml, certificates, models, rules, logs, and forensic artifacts.
#>
param(
  [string]$InstallDir = $(if ($env:EDR_INSTALL_DIR) { $env:EDR_INSTALL_DIR } else { "C:\Program Files\FDSecurity" }),
  [string]$ServiceName = $(if ($env:EDR_SERVICE_NAME) { $env:EDR_SERVICE_NAME } else { "FDSecurityAgent" }),
  [switch]$SkipStop,
  [switch]$SkipRuntimeCleanup,
  [switch]$KeepOfflineQueue,
  [switch]$KeepEvidenceCache,
  [switch]$DryRun,
  [switch]$CheckOnly,
  [string]$ReportPath = $(if ($env:EDR_PREFLIGHT_REPORT) { $env:EDR_PREFLIGHT_REPORT } else { "" })
)

$ErrorActionPreference = "Stop"
$AgentProcessNames = @("FDSensor", "edr_agent")
$ServiceNames = @($ServiceName, "EdrAgent") | Select-Object -Unique

function Write-Preflight([string]$Message) {
  Write-Host "[preflight] $Message"
}

function Test-IsWindows {
  return ($env:OS -match "Windows_NT" -or $PSVersionTable.Platform -eq "Win32NT" -or -not $PSVersionTable.Platform)
}

function Test-IsElevated {
  if (-not (Test-IsWindows)) { return $true }
  try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  } catch {
    return $false
  }
}

function Get-PathCount {
  param([string]$Pattern)
  if (-not $Pattern) { return 0 }
  try {
    return @((Get-ChildItem -Path $Pattern -Force -ErrorAction SilentlyContinue)).Count
  } catch {
    return 0
  }
}

function Test-CngKeyContainerExists {
  param([string]$Name)
  if (-not (Test-IsWindows) -or -not $Name) { return $false }
  $certutil = Get-Command "certutil.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
  if (-not $certutil) { return $false }
  try {
    $out = & $certutil.Source -csp "Microsoft Software Key Storage Provider" -key 2>&1
    foreach ($line in $out) {
      if (([string]$line).Trim() -eq $Name) {
        return $true
      }
    }
  } catch {
    return $false
  }
  return $false
}

function New-Check {
  param([string]$Name, [string]$Status, [string]$Message)
  return [ordered]@{
    name = $Name
    status = $Status
    message = $Message
  }
}

function New-PreflightReport {
  param([string]$Phase)
  $dir = [System.IO.Path]::GetFullPath($InstallDir)
  $isWindows = Test-IsWindows
  $isElevated = Test-IsElevated
  $svc = $null
  if ($isWindows) {
    foreach ($name in $ServiceNames) {
      $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
      if ($svc) { break }
    }
  }
  $procCount = 0
  foreach ($name in $AgentProcessNames) {
    $procCount += @((Get-Process -Name $name -ErrorAction SilentlyContinue)).Count
  }
  $queueCount = Get-PathCount -Pattern (Join-Path $dir "queue\edr_queue.db*")
  $evidenceCount = Get-PathCount -Pattern (Join-Path $dir "evidence\local_evidence_cache.db*")
  $legacyKeyName = if ($env:COMPUTERNAME) { "EDR-Agent-$($env:COMPUTERNAME)" } else { "" }
  $legacyKeyExists = Test-CngKeyContainerExists -Name $legacyKeyName
  $checks = New-Object System.Collections.Generic.List[object]
  $checks.Add((New-Check -Name "windows" -Status $(if ($isWindows) { "ok" } else { "failed" }) -Message $(if ($isWindows) { "Windows endpoint" } else { "not Windows" }))) | Out-Null
  $checks.Add((New-Check -Name "elevated" -Status $(if ($isElevated) { "ok" } else { "warning" }) -Message $(if ($isElevated) { "running with administrator privilege" } else { "administrator privilege recommended" }))) | Out-Null
  $checks.Add((New-Check -Name "install_dir" -Status $(if (Test-Path -LiteralPath $dir) { "ok" } else { "warning" }) -Message $dir)) | Out-Null
  if ($legacyKeyName) {
    $checks.Add((New-Check -Name "legacy_cng_key" -Status $(if ($legacyKeyExists) { "warning" } else { "ok" }) -Message $(if ($legacyKeyExists) { "legacy fixed key container exists: $legacyKeyName; current installer uses a unique CNG key name" } else { "legacy fixed key container not found: $legacyKeyName" }))) | Out-Null
  }
  $checks.Add((New-Check -Name "service" -Status "ok" -Message $(if ($svc) { "$ServiceName status=$($svc.Status)" } else { "$ServiceName not installed" }))) | Out-Null
  $checks.Add((New-Check -Name "process" -Status $(if ($procCount -gt 0) { "warning" } else { "ok" }) -Message "agent process count=$procCount")) | Out-Null
  $checks.Add((New-Check -Name "offline_queue" -Status "ok" -Message "files=$queueCount action=$(if ($KeepOfflineQueue) { 'keep' } else { 'cleanup' })")) | Out-Null
  $checks.Add((New-Check -Name "evidence_cache" -Status "ok" -Message "files=$evidenceCount action=$(if ($KeepEvidenceCache) { 'keep' } else { 'cleanup' })")) | Out-Null
  return [ordered]@{
    created_at = (Get-Date).ToUniversalTime().ToString("o")
    status = $(if ($isWindows) { "ok" } else { "failed" })
    phase = $Phase
    mode = $(if ($CheckOnly) { "check_only" } elseif ($DryRun) { "dry_run" } else { "apply" })
    install_dir = $dir
    service_name = $ServiceName
    keep_offline_queue = [bool]$KeepOfflineQueue
    keep_evidence_cache = [bool]$KeepEvidenceCache
    checks = $checks
  }
}

function Write-PreflightReport {
  param([object]$Report)
  if (-not $ReportPath) { return }
  $path = [System.IO.Path]::GetFullPath($ReportPath)
  $dir = Split-Path -Parent $path
  if ($dir -and -not (Test-Path -LiteralPath $dir)) {
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
  }
  $Report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $path -Encoding UTF8
  Write-Preflight "report=$path"
}

function Remove-PathPattern {
  param([string]$Pattern, [string]$Label)
  if (-not $Pattern) { return }
  $items = Get-ChildItem -Path $Pattern -Force -ErrorAction SilentlyContinue
  foreach ($item in $items) {
    if ($DryRun) {
      Write-Preflight "would remove $Label $($item.FullName)"
      continue
    }
    try {
      Remove-Item -LiteralPath $item.FullName -Force -Recurse -ErrorAction Stop
      Write-Preflight "removed $Label $($item.FullName)"
    } catch {
      if (Test-IsWindows) {
        try { & takeown.exe /F $item.FullName /A 2>$null | Out-Null } catch {}
        try {
          & icacls.exe $item.FullName /inheritance:r /grant:r "*S-1-5-18:F" /grant:r "*S-1-5-32-544:F" /C /Q | Out-Null
        } catch {}
      }
      try {
        Remove-Item -LiteralPath $item.FullName -Force -Recurse -ErrorAction Stop
        Write-Preflight "repaired ACL and removed $Label $($item.FullName)"
      } catch {
        Write-Warning "[preflight] failed to remove $Label $($item.FullName): $_"
      }
    }
  }
}

function Get-ParentProcessId {
  try {
    $p = Get-CimInstance Win32_Process -Filter "ProcessId=$PID" -ErrorAction Stop
    if ($p -and $p.ParentProcessId) { return [int]$p.ParentProcessId }
  } catch {
    try {
      $p = Get-WmiObject Win32_Process -Filter "ProcessId=$PID" -ErrorAction Stop
      if ($p -and $p.ParentProcessId) { return [int]$p.ParentProcessId }
    } catch {
      return 0
    }
  }
  return 0
}

function Stop-AgentRuntime {
  if ($SkipStop) {
    Write-Preflight "runtime stop skipped"
    return
  }
  if (-not (Test-IsWindows)) {
    return
  }
  foreach ($name in $ServiceNames) {
    $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
    if ($svc) {
      if ($svc.Status -ne "Stopped") {
        if ($DryRun) {
          Write-Preflight "would stop service $name"
        } else {
          Write-Preflight "stopping service $name"
          Stop-Service -Name $name -Force -ErrorAction SilentlyContinue
          $svc.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(20))
        }
      }
    }
  }
  $skipPid = Get-ParentProcessId
  foreach ($procName in $AgentProcessNames) {
    $procs = Get-Process -Name $procName -ErrorAction SilentlyContinue
    foreach ($p in $procs) {
      if ($skipPid -gt 0 -and $p.Id -eq $skipPid) {
        Write-Preflight "skipping installer parent process $procName pid=$($p.Id)"
        continue
      }
      if ($DryRun) {
        Write-Preflight "would stop process $procName pid=$($p.Id)"
        continue
      }
      try {
        Write-Preflight "stopping process $procName pid=$($p.Id)"
        Stop-Process -Id $p.Id -Force -ErrorAction Stop
      } catch {
        Write-Warning "[preflight] failed to stop $procName pid=$($p.Id): $_"
      }
    }
  }
}

function Invoke-RuntimeCleanup {
  if ($SkipRuntimeCleanup) {
    Write-Preflight "runtime cleanup skipped"
    return
  }
  $dir = [System.IO.Path]::GetFullPath($InstallDir)
  if (-not (Test-Path -LiteralPath $dir)) {
    Write-Preflight "install dir not present yet: $dir"
    return
  }
  if (-not $KeepOfflineQueue) {
    Remove-PathPattern -Pattern (Join-Path $dir "queue\edr_queue.db*") -Label "offline queue"
  }
  if (-not $KeepEvidenceCache) {
    Remove-PathPattern -Pattern (Join-Path $dir "evidence\local_evidence_cache.db*") -Label "evidence cache"
  }
  Remove-PathPattern -Pattern (Join-Path $dir "FDSensor.pid") -Label "pid file"
  Remove-PathPattern -Pattern (Join-Path $dir "edr_agent.pid") -Label "legacy pid file"
}

if ($CheckOnly) {
  try {
    Write-Preflight "check-only complete"
    Write-PreflightReport -Report (New-PreflightReport -Phase "check_only")
  } catch {
    Write-Warning "[preflight] check-only report failed: $_"
    if ($env:EDR_PREFLIGHT_STRICT -eq "1") { exit 1 }
  }
  exit 0
}

try {
  Stop-AgentRuntime
  Invoke-RuntimeCleanup
  Write-PreflightReport -Report (New-PreflightReport -Phase "completed")
  Write-Preflight "complete"
  exit 0
} catch {
  Write-Warning "[preflight] non-fatal preflight failure: $_"
  try {
    $report = New-PreflightReport -Phase "completed_with_warning"
    $report.status = "warning"
    $report.error = [string]$_
    Write-PreflightReport -Report $report
  } catch {
    Write-Warning "[preflight] failed to write warning report: $_"
  }
  if ($env:EDR_PREFLIGHT_STRICT -eq "1") { exit 1 }
  exit 0
}
