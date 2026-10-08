[CmdletBinding()]
param(
  [string] $RepoRoot = (Split-Path -Parent $PSScriptRoot)
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$updaterPath = Join-Path $RepoRoot 'scripts/edr_agent_inplace_update.ps1'
$updater = Get-Content -LiteralPath $updaterPath -Raw -Encoding UTF8

function Get-UpdaterFunctionSource([string] $Name, [string] $NextName) {
  $start = $updater.IndexOf("function $Name")
  $end = $updater.IndexOf("function $NextName", $start + 1)
  if ($start -lt 0 -or $end -lt 0) {
    throw "could not extract updater function $Name"
  }
  return $updater.Substring($start, $end - $start)
}

function Get-Sha256([string] $Path) {
  return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

# Intentional isolation stub: this fixture exercises file transaction behavior;
# it does not prove journal persistence, crash recovery, or restart durability.
function Sync-RuntimePlanJournal {}

Invoke-Expression (Get-UpdaterFunctionSource 'Test-SupportedNativeRuntimeComponent' 'Assert-InstalledRuntimeIdentity')
Invoke-Expression (Get-UpdaterFunctionSource 'Stage-RuntimeUpdatePlan' 'Commit-RuntimeUpdatePlan')
Invoke-Expression (Get-UpdaterFunctionSource 'Commit-RuntimeUpdatePlan' 'Rollback-RuntimeUpdatePlan')
Invoke-Expression (Get-UpdaterFunctionSource 'Rollback-RuntimeUpdatePlan' 'Get-AgentProcesses')
Invoke-Expression (Get-UpdaterFunctionSource 'Get-InstallerLogEvidence' 'Get-InstallerEvidenceId')
Invoke-Expression (Get-UpdaterFunctionSource 'New-InstallerDiagnosticEvidence' 'Invoke-FullInstallerUpgrade')

& (Join-Path $RepoRoot 'tests/test_installer_log_redaction.ps1') -RepoRoot $RepoRoot

$requiredRootComponents = @('FDSecurityInstallerWorker.exe', 'uninstall.exe')
if (-not (Test-SupportedNativeRuntimeComponent -Name 'collector/forensic_collector_builtin.exe' -RequiredRootComponents $requiredRootComponents)) {
  throw 'updater rejected the canonical nested collector identity path'
}
foreach ($unsupportedPath in @(
    'collector\forensic_collector_builtin.exe',
    'other/forensic_collector_builtin.exe',
    '../collector/forensic_collector_builtin.exe'
  )) {
  if (Test-SupportedNativeRuntimeComponent -Name $unsupportedPath -RequiredRootComponents $requiredRootComponents) {
    throw "updater accepted a non-canonical nested collector identity path: $unsupportedPath"
  }
}

function New-CollectorPlan(
  [string] $Root,
  [string] $CaseName,
  [bool] $TargetExisted
) {
  $source = Join-Path $Root "$CaseName/source/collector/forensic_collector_builtin.exe"
  $target = Join-Path $Root "$CaseName/install/collector/forensic_collector_builtin.exe"
  New-Item -ItemType Directory -Path (Split-Path -Parent $source) -Force | Out-Null
  [IO.File]::WriteAllText($source, 'new-collector', [Text.UTF8Encoding]::new($false))
  if ($TargetExisted) {
    New-Item -ItemType Directory -Path (Split-Path -Parent $target) -Force | Out-Null
    [IO.File]::WriteAllText($target, 'old-collector', [Text.UTF8Encoding]::new($false))
  }
  return [pscustomobject]@{
    Name = 'collector/forensic_collector_builtin.exe'
    ExpectedSha256 = Get-Sha256 $source
    SourcePath = $source
    TargetPath = $target
    CandidatePath = "$target.candidate-fixture"
    BackupPath = "$target.rollback-fixture"
    FailedPath = "$target.failed-fixture"
    TargetExisted = $TargetExisted
    Committed = $false
    Status = 'validated'
  }
}

$fixtureRoot = Join-Path ([IO.Path]::GetTempPath()) ("edr-inplace-collector-" + [guid]::NewGuid().ToString('N'))
try {
  $logPath = Join-Path $fixtureRoot 'installer-transitions/install.log'
  New-Item -ItemType Directory -Path (Split-Path -Parent $logPath) -Force | Out-Null
  $previousSnapshotHash = ''
  foreach ($stage in @('first', 'second', 'after-diagnostic')) {
    $rawLog = @"
stage=$stage
Authorization: Bearer fixture-$stage-bearer
token=fixture-$stage-token
password=fixture-$stage-password
-----BEGIN PRIVATE KEY-----
fixture-$stage-private-body
-----END PRIVATE KEY-----
https://example.invalid/install?token=fixture-$stage-query
"@
    [IO.File]::WriteAllText($logPath, $rawLog, [Text.UTF8Encoding]::new($false))
    $ready = Get-InstallerLogEvidence -Path $logPath
    $snapshot = [IO.File]::ReadAllText($ready.Path)
    if ($ready.Status -cne 'ready' -or $snapshot -cne $ready.Summary -or
        -not $snapshot.Contains("stage=$stage") -or $snapshot -match 'fixture-' -or
        -not $snapshot.Contains('Authorization: [REDACTED]') -or
        -not $snapshot.Contains('token=[REDACTED]') -or
        -not $snapshot.Contains('password=[REDACTED]') -or
        -not $snapshot.Contains('[PRIVATE_KEY_REDACTED]') -or
        -not $snapshot.Contains('[URL_REDACTED]')) {
      throw "$stage installer snapshot was stale or did not redact the new log"
    }
    if ($ready.Sha256 -cne (Get-Sha256 $ready.Path) -or
        $ready.Size -ne (Get-Item -LiteralPath $ready.Path).Length -or
        $ready.OriginalSize -ne (Get-Item -LiteralPath $logPath).Length -or
        $ready.Sha256 -ceq $previousSnapshotHash) {
      throw "$stage installer snapshot metadata did not bind the replaced bytes"
    }
    $previousSnapshotHash = $ready.Sha256

    if ($stage -ceq 'second') {
      foreach ($diagnosticStatus in @('too_large', 'missing')) {
        $originalSize = if ($diagnosticStatus -ceq 'too_large') { 1048577 } else { 0 }
        $diagnostic = New-InstallerDiagnosticEvidence -Path $logPath -Status $diagnosticStatus -OriginalSize $originalSize
        $content = [IO.File]::ReadAllText($diagnostic.Path)
        $document = $content | ConvertFrom-Json
        if ($document.schema -cne 'edr.agent-upgrade.installer-log-diagnostic.v1' -or
            $document.status -cne $diagnosticStatus -or $document.original_size -ne $originalSize -or
            $content.Contains('stage=') -or $content -match 'fixture-' -or
            $diagnostic.Sha256 -cne (Get-Sha256 $diagnostic.Path) -or
            $diagnostic.Size -ne (Get-Item -LiteralPath $diagnostic.Path).Length -or
            $diagnostic.Sha256 -ceq $previousSnapshotHash) {
          throw "$diagnosticStatus installer diagnostic did not replace the prior snapshot"
        }
        $previousSnapshotHash = $diagnostic.Sha256
      }
    }
  }

  $snapshotHashBeforeLock = Get-Sha256 $ready.Path
  $snapshotLock = [IO.File]::Open($ready.Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None)
  $replaceFailed = $false
  try {
    try {
      New-InstallerDiagnosticEvidence -Path $logPath -Status 'missing' -OriginalSize 0 | Out-Null
    } catch {
      $replaceFailed = $true
    }
  } finally {
    $snapshotLock.Dispose()
  }
  if (-not $replaceFailed -or (Get-Sha256 $ready.Path) -cne $snapshotHashBeforeLock) {
    throw 'locked installer snapshot replacement hid failure or modified the existing evidence'
  }

  $unsafeLogPath = Join-Path $fixtureRoot 'unsafe-install.log'
  [IO.File]::WriteAllText($unsafeLogPath, 'stage=unsafe', [Text.UTF8Encoding]::new($false))
  New-Item -ItemType Directory -Path "$unsafeLogPath.redacted" | Out-Null
  foreach ($operation in @('ready', 'diagnostic')) {
    $unsafeFailure = ''
    try {
      if ($operation -ceq 'ready') { Get-InstallerLogEvidence -Path $unsafeLogPath | Out-Null }
      else { New-InstallerDiagnosticEvidence -Path $unsafeLogPath -Status 'missing' -OriginalSize 0 | Out-Null }
    } catch {
      $unsafeFailure = $_.Exception.Message
    }
    if ($unsafeFailure -cne 'INSTALL_LOG_UNSAFE_PATH') {
      throw "$operation installer snapshot accepted an unsafe destination"
    }
  }

  Write-Host 'PASS: installer snapshot replacements, redaction, state transitions, and visible failure'

  $invalidHashItem = New-CollectorPlan $fixtureRoot 'invalid-hash' $true
  $targetHashBeforeFailure = Get-Sha256 $invalidHashItem.TargetPath
  $invalidHashItem.ExpectedSha256 = '0' * 64
  $stageFailure = $null
  try {
    Stage-RuntimeUpdatePlan @($invalidHashItem)
  } catch {
    $stageFailure = $_.Exception.Message
  }
  if ($stageFailure -cne 'runtime component hash changed after local staging: name=collector/forensic_collector_builtin.exe') {
    throw "unexpected invalid-hash stage result: $stageFailure"
  }
  if ((Get-Sha256 $invalidHashItem.TargetPath) -cne $targetHashBeforeFailure -or $invalidHashItem.Committed) {
    throw 'invalid-hash staging modified or committed the installed collector target'
  }

  foreach ($targetExisted in @($false, $true)) {
    $caseName = if ($targetExisted) { 'replace' } else { 'create' }
    $item = New-CollectorPlan $fixtureRoot $caseName $targetExisted
    $plan = @($item)

    Stage-RuntimeUpdatePlan $plan
    if (-not (Test-Path -LiteralPath $item.CandidatePath -PathType Leaf)) {
      throw "$caseName did not stage the nested collector candidate"
    }
    Commit-RuntimeUpdatePlan $plan
    if ([IO.File]::ReadAllText($item.TargetPath) -cne 'new-collector') {
      throw "$caseName did not commit the nested collector"
    }
    Rollback-RuntimeUpdatePlan $plan

    if ($targetExisted) {
      if ([IO.File]::ReadAllText($item.TargetPath) -cne 'old-collector') {
        throw 'replace rollback did not restore the historical collector'
      }
    } elseif (Test-Path -LiteralPath $item.TargetPath -PathType Leaf) {
      throw 'create rollback did not remove the newly introduced collector target'
    }
    if ([IO.File]::ReadAllText($item.FailedPath) -cne 'new-collector') {
      throw "$caseName rollback did not preserve the failed collector bytes"
    }
  }

  Write-Host 'PASS: canonical nested collector validation and file transactions (journal durability not exercised)'
} finally {
  if (Test-Path -LiteralPath $fixtureRoot) {
    Remove-Item -LiteralPath $fixtureRoot -Recurse -Force
  }
}
