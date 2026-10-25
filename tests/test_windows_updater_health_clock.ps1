#Requires -Version 5.1
# Extracts only two health functions and selected recovery AST. Never runs updater main.
[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$UpdaterPath,
  [Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9]{64}$')][string]$UpdaterSha256
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$script:checks=0
function Check($Condition,[string]$Cause) { $script:checks++;if(-not $Condition){throw $Cause} }
Check ((Get-FileHash -LiteralPath $UpdaterPath -Algorithm SHA256).Hash.ToLowerInvariant() -ceq $UpdaterSha256) 'updater_pin'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($UpdaterPath,[ref]$tokens,[ref]$errors)
Check ($errors.Count -eq 0) 'updater_ast'
foreach($name in @('Get-UnixTimeMilliseconds','Wait-AgentHealthObservation')) {
  $defs=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$true))
  Check ($defs.Count -eq 1) ('unique_function_'+$name)
  Invoke-Expression $defs[0].Extent.Text
}
$script:realEpoch=(Get-Command Get-UnixTimeMilliseconds -CommandType Function).ScriptBlock
$low=[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds();$actual=& $script:realEpoch;$high=[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
Check ($actual -ge $low -and $actual -le $high) 'real_utc_epoch_must_match_standard'

# Test boundaries for actual function calls: no SCM, task scheduler or files.
$script:wallOffset=0L;$script:fixtureMode='healthy';$script:processCalls=0
$script:stages=New-Object 'System.Collections.Generic.List[string]'
function Get-UnixTimeMilliseconds { return [UInt64]([Int64](& $script:realEpoch)+$script:wallOffset) }
function Get-AgentProcesses([string]$ExecutablePath) {
  $script:processCalls++
  if($script:fixtureMode -eq 'wall_forward'){$script:wallOffset=86400000L}
  if($script:fixtureMode -eq 'wall_backward'){$script:wallOffset=-86400000L}
  if($script:fixtureMode -eq 'absent' -or ($script:fixtureMode -eq 'exit' -and $script:processCalls -ge 2)){return @()}
  return [pscustomobject]@{Id=1}
}
function Get-Service {
  [CmdletBinding()]param([string]$Name)
  return [pscustomobject]@{Status=$(if($script:fixtureMode -eq 'service_stopped'){'Stopped'}else{'Running'})}
}
function Get-ScheduledTask {
  [CmdletBinding()]param([string]$TaskName,[string]$TaskPath)
  return [pscustomobject]@{State=$(if($script:fixtureMode -eq 'task_stopped'){'Ready'}else{'Running'})}
}
function Set-UpdateStage([string]$Stage,[string]$Status='running') { [void]$script:stages.Add($Stage) }
function Assert-AgentStorageStartup([string]$ExecutablePath) { }
$timings=New-Object 'System.Collections.Generic.List[object]'
foreach($mode in @('healthy','wall_forward','wall_backward','legacy_future','legacy_past','versioned_recovery')) {
  $script:fixtureMode=$mode;$script:wallOffset=0L;$script:processCalls=0;$script:stages.Clear()
  $journal=[ordered]@{health_observation_started_at_unix_ms=1L;health_observation_deadline_unix_ms=1L;health_last_checked_unix_ms=1L}
  if($mode -eq 'legacy_future'){$journal.health_observation_deadline_unix_ms=([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()+28800000L)}
  if($mode -eq 'legacy_past'){$journal.health_observation_deadline_unix_ms=([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()-28800000L)}
  if($mode -eq 'versioned_recovery'){$journal['health_observation_clock_version']=1;$journal.health_observation_deadline_unix_ms=1L}
  $watch=[Diagnostics.Stopwatch]::StartNew()
  Wait-AgentHealthObservation -Mode service -WindowsServiceName fixture -ExecutablePath fixture -ObserveForMs 120
  $elapsed=$watch.ElapsedMilliseconds
  Check ($elapsed -ge 120 -and $elapsed -lt 10000) ('relative_window_'+$mode)
  Check ($journal.health_observation_clock_version -eq 1 -and $journal.health_observation_deadline_unix_ms -eq 0 -and ($journal.health_observation_utc_deadline_unix_ms-$journal.health_observation_started_at_unix_ms) -eq 120) ('fresh_diagnostic_window_'+$mode)
  Check ($journal.health_observation_started_at_unix_ms -gt 1 -and $script:processCalls -ge 2 -and $script:stages.Count -ge 2) ('health_checks_'+$mode)
  [void]$timings.Add(@{case=$mode;elapsed_ms=$elapsed;process_checks=$script:processCalls})
}
# Preserve zero-duration semantics: only the final live-process check remains.
$script:fixtureMode='healthy';$script:wallOffset=0L;$script:processCalls=0;$script:stages.Clear();$journal=[ordered]@{}
Wait-AgentHealthObservation -Mode service -WindowsServiceName fixture -ExecutablePath fixture -ObserveForMs 0
Check ($script:processCalls -eq 1 -and $journal.health_observation_deadline_unix_ms -eq 0 -and $journal.health_observation_utc_deadline_unix_ms -eq $journal.health_observation_started_at_unix_ms) 'zero_duration_final_process_check'
$script:fixtureMode='absent';$script:processCalls=0;$caught=$false
try {Wait-AgentHealthObservation -Mode service -ExecutablePath fixture -ObserveForMs 0} catch {$caught=$true;Check ($_.Exception.Message -eq 'FDSensor.exe exited at the end of the local health observation window') 'zero_duration_dead_cause'}
Check $caught 'zero_duration_dead_runtime_refused'
# This is an arithmetic boundary, not a new business cap. Reject before writes.
$script:fixtureMode='healthy';$script:processCalls=0;$script:stages.Clear();$journal=[ordered]@{sentinel=1};$caught=$false
try {Wait-AgentHealthObservation -Mode service -ExecutablePath fixture -ObserveForMs ([UInt64]::MaxValue)} catch {$caught=$true;Check ($_.Exception.Message -eq 'health observation duration exceeds supported elapsed range') 'unrepresentable_duration_cause'}
Check ($caught -and $script:processCalls -eq 0 -and $script:stages.Count -eq 0 -and $journal.Count -eq 1) 'unrepresentable_duration_refused_before_writes'
foreach($mode in @('exit','service_stopped','task_stopped')) {
  $script:fixtureMode=$mode;$script:wallOffset=0L;$script:processCalls=0
  $journal=[ordered]@{};$caught=$false
  try {
    $kind=if($mode -eq 'task_stopped'){'scheduled_task'}else{'service'}
    Wait-AgentHealthObservation -Mode $kind -WindowsServiceName fixture -TaskName fixture -TaskPath '\' -ExecutablePath fixture -ObserveForMs 250
  } catch {
    $caught=$true
    Check ($_.Exception.Message -match '(exited|service stopped|scheduled task stopped)') ('failure_cause_'+$mode)
  }
  Check $caught ('failure_not_swallowed_'+$mode)
}

# The actual recovery selection must recognize even a legacy full-installer
# journal whose old health deadline was zero; timestamps do not authorize credit.
$assignment=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq '$resumeHealthObservation' -and $n.Right.Extent.Text -like '*$prior.stage*'},$true))
Check ($assignment.Count -eq 1) 'recovery_stage_assignment'
$prior=[pscustomobject]@{stage='health_observation'};$resumeHealthObservation=$false
Invoke-Expression $assignment[0].Extent.Text
Check $resumeHealthObservation 'zero_or_missing_legacy_deadline_still_inflight'

# Execute the unchanged real durable-passed branch with only unrelated file
# operations replaced. It must return before reopening any health observation.
$passed=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.IfStatementAst] -and $n.Clauses[0].Item1.Extent.Text -eq '$resumeHealthObservationPassed'},$true))
Check ($passed.Count -eq 1) 'durable_passed_branch_unique'
function Get-Sha256([string]$Path){return 'fixture-hash'}
function Remove-Item { [CmdletBinding()]param([string]$LiteralPath,[switch]$Force) }
$resumeHealthObservationPassed=$true;$running=$true;$report=@{};$currentPath='fixture';$stagedPath='fixture';$script:stages.Clear()
& ([scriptblock]::Create($passed[0].Extent.Text+"`nthrow 'durable_passed_did_not_return'"))
Check ($report.status -eq 'succeeded' -and $script:stages.Count -eq 1 -and $script:stages[0] -eq 'completed') 'durable_passed_no_reobservation'
$running=$false;$caught=$false
try { & ([scriptblock]::Create($passed[0].Extent.Text)) } catch {$caught=$true;Check ($_.Exception.Message -eq 'Agent exited after the durable local health observation passed') 'durable_passed_dead_cause'}
Check $caught 'durable_passed_still_requires_live_process'
$calls=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Wait-AgentHealthObservation'},$true))
Check ($calls.Count -eq 5 -and @($calls | Where-Object {$_.Extent.Text -notmatch '-ObserveForMs'}).Count -eq 0) 'all_five_consumers_use_relative_duration'
@{schema='edr.updater-health-clock-tests.v1';checks=$script:checks;status='passed';updater_sha256=$UpdaterSha256;function_extraction_only=$true;updater_main_executed=$false;system_timezone_changed=$false;timings=$timings.ToArray()} | ConvertTo-Json -Depth 5 -Compress
