#Requires -Version 5.1
<#
.SYNOPSIS
  Prepare an installed EDR Agent directory for upgrade/redeploy.

.DESCRIPTION
  Stops the Windows service/process and removes runtime-only queue/evidence
  cache files that commonly block redeploys or replay legacy batches. It keeps
  agent.toml, certificates, models, rules, logs, and forensic artifacts.
#>
param(
  [string]$InstallDir = $(if ($env:EDR_INSTALL_DIR) { $env:EDR_INSTALL_DIR } else { "C:\Program Files\EDR Agent" }),
  [string]$ServiceName = $(if ($env:EDR_SERVICE_NAME) { $env:EDR_SERVICE_NAME } else { "EdrAgent" }),
  [switch]$SkipStop,
  [switch]$SkipRuntimeCleanup,
  [switch]$KeepOfflineQueue,
  [switch]$KeepEvidenceCache,
  [switch]$DryRun
)

$ErrorActionPreference = "Stop"

function Write-Preflight([string]$Message) {
  Write-Host "[preflight] $Message"
}

function Test-IsWindows {
  return ($env:OS -match "Windows_NT" -or $PSVersionTable.Platform -eq "Win32NT" -or -not $PSVersionTable.Platform)
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
      Write-Warning "[preflight] failed to remove $Label $($item.FullName): $_"
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
  $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
  if ($svc) {
    if ($svc.Status -ne "Stopped") {
      if ($DryRun) {
        Write-Preflight "would stop service $ServiceName"
      } else {
        Write-Preflight "stopping service $ServiceName"
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        $svc.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(20))
      }
    }
  }
  $skipPid = Get-ParentProcessId
  $procs = Get-Process -Name "edr_agent" -ErrorAction SilentlyContinue
  foreach ($p in $procs) {
    if ($skipPid -gt 0 -and $p.Id -eq $skipPid) {
      Write-Preflight "skipping installer parent process edr_agent pid=$($p.Id)"
      continue
    }
    if ($DryRun) {
      Write-Preflight "would stop process edr_agent pid=$($p.Id)"
      continue
    }
    try {
      Write-Preflight "stopping process edr_agent pid=$($p.Id)"
      Stop-Process -Id $p.Id -Force -ErrorAction Stop
    } catch {
      Write-Warning "[preflight] failed to stop edr_agent pid=$($p.Id): $_"
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
  Remove-PathPattern -Pattern (Join-Path $dir "edr_agent.pid") -Label "pid file"
}

Stop-AgentRuntime
Invoke-RuntimeCleanup
Write-Preflight "complete"
