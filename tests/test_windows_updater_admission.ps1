#Requires -Version 5.1
# Production admission/failure statements only. No updater main, Task, Service,
# installer, process termination, or installed Agent files are executed here.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$UpdaterPath)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($UpdaterPath,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'updater_parse_failed'}
$script:checks=0
function Check($Condition,[string]$Cause){$script:checks++;if(-not $Condition){throw $Cause}}
foreach($name in @('Assert-UpdateStartDeadline','Add-UpdateEvent','Set-UpdateStage')) {
  $definition=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$true))
  Check ($definition.Count -eq 1) ('unique_owner_'+$name)
  Invoke-Expression $definition[0].Extent.Text
}
function Get-UnixTimeMilliseconds {return [UInt64]1000}
foreach($case in @(
  @{deadline=1001;provided=$true;recovering=$false;reject=$false},
  @{deadline=1000;provided=$true;recovering=$false;reject=$true},
  @{deadline=999;provided=$true;recovering=$false;reject=$true},
  @{deadline=2;provided=$false;recovering=$false;reject=$false},
  @{deadline=2;provided=$true;recovering=$true;reject=$false}
)) {
  $failure=$null
  try{Assert-UpdateStartDeadline -Deadline $case.deadline -Provided $case.provided -Recovering $case.recovering}catch{$failure=$_.Exception.Message}
  Check (($null -ne $failure) -eq $case.reject) 'deadline_admission_result'
  if($case.reject){Check ($failure -ceq 'UPDATE_DEADLINE_EXPIRED|runtime_stop_not_started') 'fixed_deadline_cause'}
}

$main=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.TryStatementAst] -and
  $n.Body.Extent.Text -like '*$DeadlineUnixMs -le $IssuedAtUnixMs*'},$true))
Check ($main.Count -eq 1) 'unique_transaction_owner'
$recovering=@($main[0].Body.FindAll({param($n) $n -is [Management.Automation.Language.IfStatementAst] -and
  $n.Clauses[0].Item1.Extent.Text -eq '$priorProperties -contains ''stop_intent'''},$true))
Check ($recovering.Count -eq 1) 'unique_recovery_classification'
$inherit=@($main[0].Body.FindAll({param($n) $n -is [Management.Automation.Language.AssignmentStatementAst] -and
  $n.Left.Extent.Text -eq '$journal[''stop_intent'']' -and $n.Right.Extent.Text -eq '$recoveringUpdate'},$true))
Check ($inherit.Count -eq 1) 'unique_stop_intent_inheritance'
$recoveryStatement=[scriptblock]::Create($recovering[0].Extent.Text+"`n"+$inherit[0].Extent.Text)
$journalPath='synthetic-journal'
function Write-AtomicJson {param($Path,$Value);$script:persisted=$Value|ConvertTo-Json -Depth 10 -Compress}
foreach($stage in @('initialized','validate_identity','verified','stage_candidate','drain','full_installer_backup','unexpected')) {
  $prior=[pscustomobject]@{stage=$stage;stop_intent=$false};$priorProperties=@($prior.PSObject.Properties.Name);$journal=@{stop_intent=$false};. $recoveryStatement
  Check (-not $recoveringUpdate) ('prestop_journal_cannot_bypass_deadline_'+$stage)
  $failure=$null;try{Assert-UpdateStartDeadline -Deadline 2 -Provided $true -Recovering $recoveringUpdate}catch{$failure=$_.Exception.Message}
  Check ($failure -ceq 'UPDATE_DEADLINE_EXPIRED|runtime_stop_not_started') 'explicit_no_stop_journal_expires'
}
foreach($stage in @('validate_identity','prepare_runtime','replacement_committed')) {
  $prior=[pscustomobject]@{stage=$stage};$priorProperties=@($prior.PSObject.Properties.Name);$journal=@{stop_intent=$false};. $recoveryStatement
  Check ($recoveringUpdate -and $journal.stop_intent) ('legacy_journal_keeps_recovery_'+$stage)
  Assert-UpdateStartDeadline -Deadline 2 -Provided $true -Recovering $recoveringUpdate
}
$prior=[pscustomobject]@{stage='validate_identity';stop_intent='false'};$priorProperties=@($prior.PSObject.Properties.Name);$journal=@{stop_intent=$false}
$failure=$null;try{. $recoveryStatement}catch{$failure=$_.Exception.Message}
Check ($failure -ceq 'recovered update journal stop intent is invalid') 'malformed_stop_intent_refused'

# Reopen the production journal twice, crashing after recovery rewrites its
# stage to validate_identity each time. Stop intent must never regress to false.
foreach($stage in @('prepare_runtime','full_installer_upgrade','replacement_committed')) {
  $prior=[pscustomobject]@{stage=$stage;stop_intent=$true}
  foreach($attempt in @(1,2)) {
    $priorProperties=@($prior.PSObject.Properties.Name);$journal=@{stop_intent=$false};$report=@{stage='initialized'}
    . $recoveryStatement
    Assert-UpdateStartDeadline -Deadline 2 -Provided $true -Recovering $recoveringUpdate
    Set-UpdateStage -Stage validate_identity
    $prior=ConvertFrom-Json $script:persisted
    Check ($recoveringUpdate -and $prior.stop_intent -and $prior.stage -ceq 'validate_identity') ('repeated_recovery_keeps_stop_intent_'+$stage+'_'+$attempt)
  }
}

# Execute the actual catch's cause capture before its recovery branch.
$captureStatements=@()
foreach($statement in $main[0].CatchClauses[0].Body.Statements) {
  if($statement -is [Management.Automation.Language.AssignmentStatementAst] -and $statement.Left.Extent.Text -eq '$runtimeCommitted'){break}
  $captureStatements+=@($statement.Extent.Text)
}
Check ($captureStatements.Count -gt 0) 'failure_capture_available'
$capture=[scriptblock]::Create($captureStatements -join "`n")
$TaskId='';$CommandId=''
$journal=@{stage='full_installer_upgrade';last_event_seq=2;events=@();failed_stage=$null;error_code=$null;first_error=$null}
$report=@{stage='full_installer_upgrade';error_code=$null}
try{throw 'INSTALL_EXIT_NONZERO|installer_exit_code=7'}catch{. $capture}
Set-UpdateStage -Stage rollback_full_installer_started
Check ($journal.failed_stage -ceq 'full_installer_upgrade' -and $journal.error_code -ceq 'INSTALL_EXIT_NONZERO' -and $journal.first_error -ceq 'INSTALL_EXIT_NONZERO') 'initial_cause_recorded_before_rollback'
$saved=ConvertFrom-Json $script:persisted

# Reopen a current journal and a legacy one through the actual optional import.
$imports=@($main[0].Body.FindAll({param($n) $n -is [Management.Automation.Language.ForEachStatementAst] -and
  $n.Variable.Extent.Text -eq '$field' -and $n.Body.Extent.Text -like '*$priorProperties -contains $field*'},$true))
Check ($imports.Count -eq 1) 'unique_optional_journal_import'
$import=[scriptblock]::Create($imports[0].Extent.Text)
$prior=$saved;$priorProperties=@($prior.PSObject.Properties.Name)
$journal=@{failed_stage=$null;error_code=$null;first_error=$null};. $import
Check ($journal.failed_stage -ceq 'full_installer_upgrade' -and $journal.error_code -ceq 'INSTALL_EXIT_NONZERO') 'first_cause_survives_journal_reopen'
$report=@{stage='rollback_restore_binary';error_code=$null}
try{throw 'INSTALL_LOG_UNAVAILABLE|installer_exit_code=-1'}catch{. $capture}
Check ($report.failed_stage -ceq 'full_installer_upgrade' -and $report.error_code -ceq 'INSTALL_EXIT_NONZERO') 'recovery_failure_does_not_replace_first_cause'
$journal.last_event_seq=2;$journal.events=@()
Add-UpdateEvent -Status failed -Progress 100 -Detail @{stage='full_installer_rollback_failed';error='local_failure'}
$detail=$journal.events[0].detail
Check ($detail.stage -ceq 'full_installer_rollback_failed' -and -not $detail.ContainsKey('failed_stage') -and -not $detail.ContainsKey('error_code')) 'failure_wire_stays_compatible_with_old_reporter'

$prior=[pscustomobject]@{stage='health_observation';schema_version=2}
$priorProperties=@($prior.PSObject.Properties.Name);$journal=@{failed_stage=$null;error_code=$null;first_error=$null};. $import
Check ($null -eq $journal.failed_stage -and $null -eq $journal.error_code -and $null -eq $journal.first_error) 'legacy_journal_without_new_fields'
$journal.last_event_seq=2;$journal.events=@()
Add-UpdateEvent -Status failed -Progress 100 -Detail @{stage='rollback_failed'}
Check (-not $journal.events[0].detail.ContainsKey('failed_stage') -and -not $journal.events[0].detail.ContainsKey('error_code')) 'legacy_failure_payload_unchanged'

# Ordinary runtime exceptions have no INSTALL_* code. Preserve their original
# local message through restart while keeping the latest rollback error too.
$journal=@{failed_stage=$null;error_code=$null;first_error=$null};$report=@{stage='health_observation';error_code=$null}
try{throw 'synthetic original health observation failure'}catch{. $capture}
Set-UpdateStage -Stage rollback_started
$prior=ConvertFrom-Json $script:persisted;$priorProperties=@($prior.PSObject.Properties.Name)
$journal=@{failed_stage=$null;error_code=$null;first_error=$null};. $import
$report=@{stage='rollback_restore_runtime';error_code=$null}
try{throw 'synthetic later runtime restore failure'}catch{. $capture}
Check ($report.first_error -ceq 'synthetic original health observation failure' -and $report.error -ceq 'synthetic later runtime restore failure') 'plain_first_error_survives_reopen_and_second_failure'
Check ($report.failed_stage -ceq 'health_observation' -and $null -eq $journal.error_code) 'plain_first_error_keeps_original_stage_without_invented_code'

# Execute the runtime/binary branch from the end of drain through its stop
# boundary. An expired preparation must not invoke the existing stop owner.
$stopStatements=@();$collect=$false
foreach($statement in $main[0].Body.Statements) {
  if($statement -is [Management.Automation.Language.IfStatementAst] -and
      $statement.Clauses[0].Item1.Extent.Text -eq '$DrainDelaySeconds -gt 0'){$collect=$true;continue}
  if($collect) {
    if($statement -is [Management.Automation.Language.AssignmentStatementAst] -and $statement.Left.Extent.Text -eq '$report["runtime_preparation"]'){break}
    $stopStatements+=@($statement.Extent.Text)
  }
}
Check ($stopStatements.Count -gt 0) 'runtime_stop_boundary_available'
$stopBoundary=[scriptblock]::Create($stopStatements -join "`n")
function Stop-AgentRuntime {
  param($Mode,$TaskName,$TaskPath,$WindowsServiceName,$ExecutablePath)
  $script:stopCalls++
  Check ((ConvertFrom-Json $script:persisted).stop_intent -eq $true) 'stop_intent_durable_before_runtime_stop'
}
$resolvedDeploymentMode='service';$ScheduledTaskName='synthetic';$ScheduledTaskPath='\';$ServiceName='synthetic';$currentPath='synthetic.exe'
$updateDeadlineProvided=$true;$recoveringUpdate=$false
foreach($deadline in @(999,1001)) {
  $DeadlineUnixMs=[UInt64]$deadline;$script:stopCalls=0;$failure=$null
  $journal=@{stop_intent=$false};$report=@{stage='drain'}
  try{. $stopBoundary}catch{$failure=$_.Exception.Message}
  if($deadline -lt 1000){Check ($failure -ceq 'UPDATE_DEADLINE_EXPIRED|runtime_stop_not_started' -and $script:stopCalls -eq 0) 'expired_runtime_branch_never_stops'}
  else{Check ($null -eq $failure -and $script:stopCalls -eq 1) 'admitted_runtime_branch_uses_existing_stop_owner'}
}

# Run the actual whole recovery dispatch after an admission refusal. Any
# lifecycle I/O is a test failure, including the old generic restart branch.
$dispatch=@($main[0].CatchClauses[0].Body.Statements|Where-Object {$_ -is [Management.Automation.Language.IfStatementAst] -and
  $_.Clauses[0].Item1.Extent.Text -like '$UpgradeClass -eq *$fullInstallerStarted*fullInstallerBackupPath*'})
Check ($dispatch.Count -eq 1) 'unique_recovery_dispatch'
$dispatchBody=[scriptblock]::Create($dispatch[0].Extent.Text)
function Stop-AgentRuntime {throw 'unexpected_runtime_stop'}
function Start-AgentRuntime {throw 'unexpected_runtime_start'}
function Invoke-FullInstallerRuntimeMirror {throw 'unexpected_runtime_restore'}
function Test-Path {throw 'unexpected_runtime_probe'}
foreach($upgradeClass in @('binary_hot','runtime_bundle','installer_required')) {
  $UpgradeClass=$upgradeClass;$fullInstallerStarted=$false;$replacementCommitted=$false;$runtimeCommitted=$false;$resumeRollback=$false;$recoveringUpdate=$false
  $journal=@{last_event_seq=2;events=@();failed_stage=$null;error_code=$null;first_error=$null};$report=@{stage='drain';error_code=$null}
  try{throw 'UPDATE_DEADLINE_EXPIRED|runtime_stop_not_started'}catch{. $capture}
  . $dispatchBody
  Check ($report.status -ceq 'failed' -and $report.stage -ceq 'failed_before_stop') ('deadline_refuses_without_lifecycle_'+$upgradeClass)
  Check ($journal.error_code -ceq 'UPDATE_DEADLINE_EXPIRED' -and $journal.failed_stage -ceq 'drain') 'deadline_cause_retained_locally'
  Check (-not $journal.events[0].detail.ContainsKey('failed_stage') -and -not $journal.events[0].detail.ContainsKey('error_code')) 'deadline_wire_keeps_legacy_shape'
}
@{schema='edr.updater-admission-tests.v1';status='passed';checks=$script:checks;updater_main_executed=$false;runtime_effects='forbidden';journal_io='synthetic'}|ConvertTo-Json -Compress
