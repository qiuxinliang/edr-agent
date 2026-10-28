#Requires -Version 5.1
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$UpdaterPath)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($UpdaterPath,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'updater_parse_failed'}
foreach($name in @('Assert-AgentStorageStartup','Start-AgentRuntime','Wait-AgentHealthObservation','Get-UnixTimeMilliseconds')) {
  $defs=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$true))
  if($defs.Count -ne 1){throw ('missing_owner_'+$name)}
  Invoke-Expression $defs[0].Extent.Text
}
$script:checks=0;$script:starts=0;$script:stages=@()
function Check($Value,$Cause){$script:checks++;if(-not $Value){throw $Cause}}
function Start-Service {param($Name,$ErrorAction);$script:starts++}
function Start-ScheduledTask {param($TaskName,$TaskPath);$script:starts++}
function Wait-AgentProcess {param($ExecutablePath,$Running,$TimeoutSeconds)}
function Get-AgentProcesses {param($ExecutablePath);return [pscustomobject]@{ProcessId=1}}
function Get-Service {param($Name,$ErrorAction);return [pscustomobject]@{Status='Running'}}
function Get-ScheduledTask {param($TaskName,$TaskPath,$ErrorAction);return [pscustomobject]@{State='Running'}}
function Start-Sleep {param($Seconds)}
function Set-UpdateStage {param($Stage,$Status);$script:stages+=@($Stage)}
function Stop-AgentRuntime {param($Mode,$TaskName,$TaskPath,$WindowsServiceName,$ExecutablePath)}
function Rollback-RuntimeUpdatePlan {param($Plan)}
function Add-UpdateEvent {param($Status,$Progress,$Detail)}
function Get-Sha256 {param($Path);return 'synthetic-hash'}
$root=Join-Path $env:TEMP ('edr-updater-storage-'+[Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($root)
$currentPath=Join-Path $root 'PublicStorageProbe.exe'
$config=Join-Path $root 'agent.toml'
try {
# External process is synthetic. The production CLI, schema compatibility and
# immutable evidence are independently exercised by the C/old-owner tests.
Add-Type -TypeDefinition @'
using System; using System.IO; using System.Threading;
public class PublicStorageProbe {
  public static int Main(string[] a) {
    if(a.Length!=5 || a[0]!="--storage-space-preflight" || a[1]!="--config" || a[3]!="--output")return 2;
    string mode=File.ReadAllText(a[2]);
    if(mode=="reject")return 12;
    if(mode=="timeout")Thread.Sleep(30000);
    if(mode=="absent")return 0;
    File.WriteAllText(a[4],mode=="bad" ? "not-a-floor" : "28311552");
    return 0;
  }
}
'@ -OutputAssembly $currentPath -OutputType ConsoleApplication
Add-Type -TypeDefinition @'
using System; using System.Runtime.InteropServices;
public static class StorageFixtureClock {
  [DllImport("kernel32.dll")]
  static extern bool QueryUnbiasedInterruptTime(out ulong time);
  public static ulong Read100ns() {
    ulong time;
    if(!QueryUnbiasedInterruptTime(out time))throw new InvalidOperationException("fixture_interrupt_clock_unavailable");
    return time;
  }
}
'@
  foreach($mode in @('service','scheduled_task')) {
    foreach($fixtureInput in @('reject','absent','bad')) {
      [IO.File]::WriteAllText($config,$fixtureInput);$script:starts=0;$caught=$false
      try{Start-AgentRuntime -Mode $mode -ExecutablePath $currentPath -TimeoutSeconds 10}catch{$caught=$true}
      Check ($caught -and $script:starts -eq 0) ('startup_refused_before_launch_'+$mode+'_'+$fixtureInput)
      Check (@(Get-ChildItem $root -Directory -Filter '.storage-preflight-*').Count -eq 0) 'probe_files_bounded'
    }
    [IO.File]::WriteAllText($config,'ok');$script:starts=0
    Start-AgentRuntime -Mode $mode -ExecutablePath $currentPath -TimeoutSeconds 10
    Check ($script:starts -eq 1) ('compatible_runtime_started_'+$mode)
  }
  # A resumed/full-installer observation with a live process cannot turn a
  # storage rejection into a passed journal stage.
  [IO.File]::WriteAllText($config,'reject');$journal=[ordered]@{};$script:stages=@();$caught=$false
  try{Wait-AgentHealthObservation -Mode service -ExecutablePath $currentPath -ObserveForMs 0}catch{$caught=$true}
  Check ($caught -and $journal.Count -eq 0 -and $script:stages.Count -eq 0) 'live_process_is_not_storage_success'
  $passed=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.IfStatementAst] -and $n.Clauses[0].Item1.Extent.Text -eq '$resumeHealthObservationPassed'},$true))
  Check ($passed.Count -eq 1) 'passed_observation_recovery_unique'
  $text=$passed[0].Clauses[0].Item2.Extent.Text;$running=$true;$caught=$false;$report=@{}
  try{& ([scriptblock]::Create($text.Substring(1,$text.Length-2)))}catch{$caught=$true;Check ($_.Exception.Message -like 'storage startup preflight failed:*') 'passed_observation_storage_cause'}
  Check ($caught -and $report.Count -eq 0) 'old_passed_stage_cannot_hide_storage_failure'
  # Run the actual automatic rollback catch branch, with only runtime/service
  # effects isolated. The same startup gate is used by explicit rollback.
  $bodies=@()
  foreach($node in @($ast.FindAll({param($n)$n -is [Management.Automation.Language.IfStatementAst]},$true))) {
    foreach($clause in $node.Clauses) {
      if($clause.Item1.Extent.Text -eq '$replacementCommitted -or $runtimeCommitted -or $resumeRollback'){$bodies+=@($clause.Item2)}
    }
  }
  Check ($bodies.Count -eq 1) 'automatic_rollback_owner_unique'
  $body=$bodies[0].Extent.Text;$rollback=[scriptblock]::Create($body.Substring(1,$body.Length-2))
  foreach($operationKind in @('upgrade','rollback')) {
    $Operation=$operationKind;$replacementCommitted=$false;$runtimeCommitted=$true;$resumeRollback=$false
    $resolvedDeploymentMode='service';$ScheduledTaskName='isolated';$ScheduledTaskPath='\';$ServiceName='isolated'
    $runtimePlan=@();$StartupTimeoutSeconds=10;$HealthObserveMs=0;$failureMessage='synthetic-upgrade-failure'
    $report=@{status='failed'};$journal=@{};$script:starts=0
    [IO.File]::WriteAllText($config,'reject');. $rollback
    Check ($report.rollback -eq 'failed' -and $report.status -ne 'failed_rolled_back' -and $script:starts -eq 0) ('rollback_storage_failure_visible_'+$operationKind)
    $report=@{status='failed'};$journal=@{};$script:starts=0
    [IO.File]::WriteAllText($config,'ok');. $rollback
    Check ($report.rollback -eq 'succeeded' -and $report.status -eq 'failed_rolled_back' -and $script:starts -eq 1) ('compatible_rollback_succeeds_'+$operationKind)
  }
  [IO.File]::WriteAllText($config,'timeout');$watch=[Diagnostics.Stopwatch]::StartNew();$caught=$false
  # Relative waits are scheduled from the interrupt clock's latest tick.
  # Use that same clock domain for the unchanged 20-second minimum instead of
  # comparing its tick phase against the independent high-resolution counter.
  # https://learn.microsoft.com/windows/win32/api/realtimeapiset/nf-realtimeapiset-queryunbiasedinterrupttime
  $interruptStarted=[StorageFixtureClock]::Read100ns()
  try{Assert-AgentStorageStartup $currentPath}catch{$caught=$true;Check ($_.Exception.Message -like '*timed out*') 'timeout_cause'}
  $interruptEnded=[StorageFixtureClock]::Read100ns()
  Check ($interruptEnded -ge $interruptStarted) 'interrupt_clock_is_monotonic'
  $interruptElapsedMilliseconds=($interruptEnded-$interruptStarted)/10000.0
  $elapsedMilliseconds=$watch.Elapsed.TotalMilliseconds
  Check ($caught -and $interruptElapsedMilliseconds -ge 20000 -and $elapsedMilliseconds -lt 28000) (
    'probe_deadline_enforced elapsed_ms={0:F3} interrupt_elapsed_ms={1:F3}' -f $elapsedMilliseconds,$interruptElapsedMilliseconds)
  Check (@(Get-ChildItem $root -Directory -Filter '.storage-preflight-*').Count -eq 0) 'timeout_output_cleanup'
  @{schema='edr.test.updater_storage_start.v1';checks=$script:checks;passed=$true;runtime_effects='stubbed';probe_process='synthetic';timeout_elapsed_ms=$elapsedMilliseconds;timeout_interrupt_elapsed_ms=$interruptElapsedMilliseconds}|ConvertTo-Json -Compress
} finally {
  Remove-Item -LiteralPath $root -Recurse -Force
}
