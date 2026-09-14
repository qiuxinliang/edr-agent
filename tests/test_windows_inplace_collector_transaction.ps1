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
