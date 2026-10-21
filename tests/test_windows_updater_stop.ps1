#Requires -Version 5.1
# Execute pinned production updater branches with external I/O isolated below.
# This is not a real Agent/installer rollback acceptance.
[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$UpdaterPath,
  [Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9]{64}$')][string]$UpdaterSha256
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$script:checks=0
function Check($Condition,[string]$Cause) {
  $script:checks++
  if(-not $Condition){throw $Cause}
}
Check ((Get-FileHash -LiteralPath $UpdaterPath -Algorithm SHA256).Hash.ToLowerInvariant() -ceq $UpdaterSha256) 'updater_pin'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($UpdaterPath,[ref]$tokens,[ref]$errors)
Check ($errors.Count -eq 0) 'updater_ast'
$defs=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Stop-AgentRuntime'},$true))
Check ($defs.Count -eq 1) 'unique_stop_owner'
Invoke-Expression $defs[0].Extent.Text

# The strict production query must not turn CIM failure or an unreadable process
# path into an empty result. Only CIM I/O is substituted in these checks.
$queryDefs=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-AgentProcesses'},$true))
Check ($queryDefs.Count -eq 1) 'unique_process_query'
Invoke-Expression $queryDefs[0].Extent.Text
function Get-CimInstance {
  [CmdletBinding()]param([string]$ClassName,[string]$Filter)
  Check ($ClassName -ceq 'Win32_Process' -and $Filter -ceq "Name='FDSensor.exe'") 'bounded_query_scope'
  if($script:queryCase -eq 'failure'){Write-Error 'fixture_cim_failed';return}
  if($script:queryCase -eq 'unknown'){return [pscustomobject]@{ExecutablePath=$null}}
  if($script:queryCase -eq 'present'){return [pscustomobject]@{ExecutablePath='C:\public\FDSensor.exe';ProcessId=42}}
  return @()
}
foreach($queryCase in @('failure','unknown','present','absent')){
  $script:queryCase=$queryCase;$failure=$null;$rows=@()
  try{$rows=@(Get-AgentProcesses -ExecutablePath 'C:\public\FDSensor.exe' -RequireKnown)}catch{$failure=$_.Exception.Message}
  if($queryCase -in @('failure','unknown')){
    Check ($null -ne $failure) ('query_unknown_refused_'+$queryCase)
  }else{
    Check ($null -eq $failure -and $rows.Count -eq $(if($queryCase -eq 'present'){1}else{0})) ('query_result_'+$queryCase)
  }
}

function Get-Service {
  [CmdletBinding()]param([string]$Name)
  Check ($Name -ceq 'public-fixture') 'only_named_service'
  if($script:case -eq 'missing'){throw 'fixture_service_missing'}
  if($script:case -eq 'late_query'){Start-Sleep -Milliseconds 30100}
  return $script:controller
}
function Get-AgentProcesses([string]$ExecutablePath,[switch]$RequireKnown) {
  Check ($ExecutablePath -ceq 'public-fixture.exe') 'only_expected_process_path'
  Check ($RequireKnown -eq ($script:case -ne 'task')) 'service_requires_known_process_query'
  $script:processChecks++
  if($script:case -eq 'process_query_failed'){throw 'fixture_process_query_failed'}
  if($script:case -in @('leftover','task')){return [pscustomobject]@{ProcessId=42}}
  if($script:case -eq 'late_process' -and $script:processChecks -eq 1){return [pscustomobject]@{ProcessId=42}}
  return @()
}
function Stop-Process {
  [CmdletBinding()]param([int]$Id,[switch]$Force)
  Check ($script:case -eq 'task' -and $Id -eq 42 -and $Force) 'service_must_not_force_kill'
  $script:kills++
}
function Stop-ScheduledTask {
  [CmdletBinding()]param([string]$TaskName,[string]$TaskPath)
  Check ($script:case -eq 'task' -and $TaskName -ceq 'fixture-task' -and $TaskPath -ceq '\') 'task_contract'
  $script:taskStops++
}
function Wait-AgentProcess([string]$ExecutablePath,[bool]$Running,[int]$TimeoutSeconds) {
  Check ($script:case -eq 'task' -and -not $Running -and $TimeoutSeconds -eq 30) 'task_wait_contract'
  $script:taskWaits++
}

$results=New-Object 'System.Collections.Generic.List[object]'
foreach($name in @('pending','stopped','running','paused','starting','race_pending','race_stopped',
                  'denied','missing','query_failed','process_query_failed','late_process','pending_timeout','leftover','late_query','task')) {
  $script:case=$name
  $script:stops=0;$script:refreshes=0;$script:disposed=0;$script:kills=0
  $script:processChecks=0;$script:taskStops=0;$script:taskWaits=0
  $initial=switch($name){
    'pending'{'StopPending'};'pending_timeout'{'StopPending'}
    'stopped'{'Stopped'};'leftover'{'Stopped'};'late_process'{'Stopped'};'process_query_failed'{'Stopped'}
    'paused'{'Paused'};'starting'{'StartPending'};default{'Running'}
  }
  $script:controller=[pscustomobject]@{Status=$initial}
  $script:controller | Add-Member ScriptMethod Refresh {
    $script:refreshes++
    if($script:case -eq 'query_failed'){throw 'fixture_query_failed'}
    if($script:case -eq 'pending' -and $script:refreshes -ge 2){$this.Status='Stopped'}
    if($script:case -eq 'starting' -and $script:refreshes -ge 2){$this.Status='Running'}
    if($script:stops -eq 1 -and $script:case -notin @('denied','race_stopped') -and $script:refreshes -ge 4){$this.Status='Stopped'}
  }
  $script:controller | Add-Member ScriptMethod Stop {
    $script:stops++
    if($script:case -eq 'denied'){throw 'fixture_access_denied'}
    if($script:case -eq 'race_pending'){$this.Status='StopPending';throw 'fixture_concurrent_stop'}
    if($script:case -eq 'race_stopped'){$this.Status='Stopped';throw 'fixture_concurrent_stop'}
    $this.Status='StopPending'
  }
  $script:controller | Add-Member ScriptMethod Dispose {$script:disposed++}
  $watch=[Diagnostics.Stopwatch]::StartNew();$failure=$null
  try {
    $mode=if($name -eq 'task'){'scheduled_task'}else{'service'}
    Stop-AgentRuntime -Mode $mode -WindowsServiceName public-fixture -ExecutablePath public-fixture.exe -TaskName fixture-task -TaskPath '\'
  }catch{$failure=$_.Exception.Message}
  $elapsed=$watch.ElapsedMilliseconds
  if($name -in @('pending_timeout','leftover','late_query')){
    Check ($failure -like '*timed out waiting for Agent service and process to stop*') ('timeout_cause_'+$name)
    Check ($elapsed -ge 30000 -and $elapsed -lt 35000) ('original_30s_monotonic_budget_'+$name)
  }elseif($name -in @('denied','missing','query_failed','process_query_failed')){
    $cause=switch($name){'denied'{'fixture_access_denied'};'missing'{'fixture_service_missing'};'process_query_failed'{'fixture_process_query_failed'};default{'fixture_query_failed'}}
    Check ($failure -like ('*'+$cause+'*') -and $elapsed -lt 5000) ('original_error_preserved_'+$name)
  }else{
    Check ($null -eq $failure -and $elapsed -lt 5000) ('stop_completed_'+$name)
  }
  if($name -ne 'task'){
    $expectedStops=if($name -in @('running','paused','starting','race_pending','race_stopped','denied')){1}else{0}
    Check ($script:stops -eq $expectedStops -and $script:kills -eq 0 -and $script:taskStops -eq 0 -and $script:taskWaits -eq 0) ('single_request_no_force_'+$name)
    Check ($script:disposed -eq $(if($name -eq 'missing'){0}else{1})) ('controller_disposed_'+$name)
    if($name -eq 'late_process'){Check ($script:processChecks -ge 2) 'scm_stopped_does_not_prove_process_exit'}
  }else{
    Check ($script:stops -eq 0 -and $script:taskStops -eq 1 -and $script:kills -eq 1 -and $script:taskWaits -eq 1) 'task_behavior_preserved'
  }
  [void]$results.Add(@{case=$name;elapsed_ms=$elapsed;stop_requests=$script:stops;force_kills=$script:kills;failure=$failure})
}
# Run the actual full-installer rollback catch branch with only its external
# mirror/start/health/file operations substituted. A failed stop must not restore
# runtime files or report a successful rollback.
$rollback=@($ast.FindAll({param($n)
  $n -is [Management.Automation.Language.IfStatementAst] -and
  $n.Clauses[0].Item1.Extent.Text -like '$UpgradeClass -eq *$fullInstallerStarted*fullInstallerBackupPath*'
},$true))
Check ($rollback.Count -eq 1) 'unique_full_installer_rollback'
$body=$rollback[0].Clauses[0].Item2.Extent.Text
$rollbackBody=[scriptblock]::Create($body.Substring(1,$body.Length-2))
function Test-Path { [CmdletBinding()]param([string]$LiteralPath,[string]$PathType);return $false }
function Set-UpdateStage([string]$Stage,[string]$Status){$script:lastStage=$Stage}
function Invoke-FullInstallerRuntimeMirror([string]$Source,[string]$Destination,[string]$Stage){$script:mirrors++}
function Start-AgentRuntime {param($Mode,$TaskName,$TaskPath,$WindowsServiceName,$ExecutablePath,$TimeoutSeconds);$script:starts++}
function Wait-AgentHealthObservation {param($Mode,$TaskName,$TaskPath,$WindowsServiceName,$ExecutablePath,$ObserveForMs);$script:healthChecks++}
function Get-Sha256([string]$Path){return 'public-restored-hash'}
function Add-UpdateEvent {param($Status,$Progress,$Detail)}
$resolvedDeploymentMode='service';$ScheduledTaskName='fixture-task';$ScheduledTaskPath='\'
$ServiceName='public-fixture';$currentPath='public-fixture.exe'
$fullInstallerBackupPath='public-backup';$fullInstallerConfigBackupPath='public-config'
$installFull='public-install';$StartupTimeoutSeconds=30;$HealthObserveMs=30000
$failureMessage='public_health_failure'
$rollbackResults=New-Object 'System.Collections.Generic.List[object]'
foreach($name in @('pending','denied','process_query_failed')){
  $script:case=$name;$script:stops=0;$script:refreshes=0;$script:processChecks=0
  $script:mirrors=0;$script:starts=0;$script:healthChecks=0;$script:lastStage=''
  $script:controller.Status=$(if($name -eq 'pending'){'StopPending'}elseif($name -eq 'denied'){'Running'}else{'Stopped'})
  # The enclosing production catch records failed before selecting this branch.
  $report=@{error=$failureMessage;status='failed'}
  & $rollbackBody
  if($name -eq 'pending'){
    Check ($script:stops -eq 0 -and $script:mirrors -eq 1 -and $script:starts -eq 1 -and $script:healthChecks -eq 1) 'pending_join_then_restore_restart_observe'
    Check ($report.status -ceq 'failed_rolled_back' -and $report.rollback -ceq 'succeeded' -and $script:lastStage -ceq 'rollback_completed') 'actual_rollback_success_projection'
  }else{
    Check ($script:mirrors -eq 0 -and $script:starts -eq 0 -and $script:healthChecks -eq 0) ('stop_failure_blocks_runtime_restore_'+$name)
    Check ($report.status -ceq 'failed' -and $report.rollback -ceq 'failed' -and $script:lastStage -ceq 'rollback_failed') ('actual_rollback_failure_projection_'+$name)
  }
  [void]$rollbackResults.Add(@{case=$name;mirrors=$script:mirrors;starts=$script:starts;status=$report.status;rollback=$report.rollback})
}
# Execute the production full-installer and interrupted-stage bodies. Only I/O
# is replaced: a live synthetic owner refuses inventory until runtime stop.
$install=@($ast.FindAll({param($n)
  $n -is [Management.Automation.Language.IfStatementAst] -and
  $n.Clauses[0].Item1.Extent.Text -ceq '$UpgradeClass -eq ''installer_required''' -and
  $n.Clauses[0].Item2.Extent.Text -like '*full_installer_backup*'
},$true))
$resume=@($ast.FindAll({param($n)
  $n -is [Management.Automation.Language.IfStatementAst] -and
  $n.Clauses[0].Item1.Extent.Text -ceq '$interruptedFullInstaller'
},$true))
Check ($install.Count -eq 1 -and $resume.Count -eq 1) 'unique_installer_and_recovery_bodies'
$body=$install[0].Clauses[0].Item2.Extent.Text
$installBody=[scriptblock]::Create($body.Substring(1,$body.Length-2))
$body=$resume[0].Clauses[0].Item2.Extent.Text
$resumeBody=[scriptblock]::Create($body.Substring(1,$body.Length-2))
function Get-SetupInstallerFromPackage {param($PackagePath,$DestinationDirectory,$ExpectedAgentSha256,$ExpectedVersion);return @{SetupPath='C:\public\setup.exe';RuntimeIdentitySha256='public-identity'}}
function Assert-AuthenticodePublisher {param($Path,$Thumbprint,$Subject)}
function Assert-InstalledRuntimeIdentity {param($InstallDirectory,$ExpectedIdentitySha256)}
function Write-AtomicJson {param($Path,$Value)}
function Remove-Item { [CmdletBinding()]param($LiteralPath,[switch]$Force)}
function Test-Path { [CmdletBinding()]param($LiteralPath,$PathType);return $true }
function Get-Sha256 {param($Path);if($script:flowCase -eq 'interrupted'){return 'old-hash'};return 'target-hash'}
function Save-AgentTaskDefinition {
  param($TaskName,$TaskPath,$Path,[switch]$AllowMissing)
  $script:taskSnapshots++
  if($script:flowCase -eq 'task_backup_failure'){throw 'fixture_task_backup_failed'}
  return ('a'*64)
}
function Restore-AgentTaskDefinition {param($TaskName,$TaskPath,$Path,$ExpectedSha256);$script:taskRestores++;Check ($ExpectedSha256 -ceq ('a'*64)) 'task_restore_bound_to_snapshot'}
function Copy-Item { [CmdletBinding()]param($LiteralPath,$Destination,[switch]$Force);$script:configCopies++ }
function Set-UpdateStage {param($Stage,$Status);$script:lastStage=$Stage;$report['stage']=$Stage}
function Invoke-FullInstallerRuntimeMirror {
  param($Source,$Destination,$Stage)
  if($Stage -eq 'backup'){
    if($script:flowCase -eq 'backup_failure'){throw 'fixture_backup_failed'}
    $script:backupReady=$true
  }else{$script:restores++}
}
function Stop-AgentRuntime {
  param($Mode,$TaskName,$TaskPath,$WindowsServiceName,$ExecutablePath)
  Check ($Mode -ceq $resolvedDeploymentMode -and $ExecutablePath -ceq $currentPath) 'stop_expected_runtime'
  $script:installStops++
  if($script:flowCase -eq 'stop_failure'){throw 'fixture_stop_failed'}
  if($script:installStops -eq 1 -and $script:flowCase -ne 'interrupted'){
    Check ($script:backupReady -and $script:configCopies -eq 2 -and
      $script:lastStage -ceq 'full_installer_upgrade' -and $fullInstallerStarted) 'recovery_ready_before_quiesce'
    if($Mode -eq 'scheduled_task'){Check ($script:taskSnapshots -eq 1 -and $journal['full_installer_task_backup_sha256'] -ceq ('a'*64)) 'task_snapshot_ready_before_quiesce'}
  }
  $script:ownerBusy=$false
}
function Invoke-FullInstallerUpgrade {
  param($SetupPath,$Mode,$RuntimeBackupPath)
  $script:installerCalls++
  if($script:ownerBusy){throw 'fixture_owner_lock_timeout'}
  if($script:flowCase -eq 'inventory_failure'){throw 'fixture_inventory_unavailable'}
  return @{ExitCode=0;Evidence=@{Sha256='public-log';Size=1;OriginalSize=1;Status='ready';Path='C:\public\setup.log'};EvidenceId='public-id';StorageKey='public-key';BaselineMode='upgrade_existing'}
}
function Wait-FullInstallerProcess {param($SetupPath);$script:recoveryWaits++}
$RuntimeManifest='C:\public\package.zip';$stagedPath='C:\public\FDSensor.exe';$expectedHash='target-hash'
$TargetVersion='3.2.704';$TrustedPublisherThumbprint='';$TrustedPublisherSubject=''
$UpgradeClass='installer_required';$Operation='upgrade';$verifiedStatus='verified';$journalPath='C:\public\journal.json'
$fullInstallerTaskBackupPath='C:\public\task-backup.json'
$installerResults=New-Object 'System.Collections.Generic.List[object]'
foreach($mode in @('scheduled_task','service')){
  foreach($flowCase in @('success','backup_failure','task_backup_failure','stop_failure','inventory_failure','interrupted')){
    if($mode -eq 'service' -and $flowCase -eq 'task_backup_failure'){continue}
    $script:flowCase=$flowCase;$resolvedDeploymentMode=$mode
    $script:ownerBusy=$true;$script:backupReady=$false;$script:configCopies=0
    $script:installStops=0;$script:installerCalls=0;$script:restores=0;$script:starts=0;$script:healthChecks=0;$script:recoveryWaits=0
    $script:taskSnapshots=0;$script:taskRestores=0
    $fullInstallerStarted=$false;$fullInstallerExpectedRuntimeIdentity='public-identity'
    $report=@{status='running'};$journal=@{resolved_deployment_mode=$mode;full_installer_task_backup_sha256=('a'*64)};$failure=$null
    try{
      if($flowCase -eq 'interrupted'){
        # Simulate death immediately after stop, before invoking the installer.
        $script:ownerBusy=$false;$script:backupReady=$true;$script:configCopies=2
        & $resumeBody
      }else{& $installBody}
    }catch{
      $failure=$_.Exception.Message;$failureMessage=$failure;$report.status='failed';$report['error']=$failure
      if($flowCase -in @('stop_failure','inventory_failure','interrupted')){& $rollbackBody}
    }
    Check ($script:taskRestores -eq $(if($mode -eq 'scheduled_task' -and $flowCase -in @('inventory_failure','interrupted')){1}else{0})) 'only_task_rollback_restores_definition'
    switch($flowCase){
      'success'{Check ($null -eq $failure -and $report.status -ceq 'succeeded' -and $script:installStops -eq 1 -and $script:installerCalls -eq 1 -and $script:healthChecks -eq 1 -and $script:restores -eq 0) 'quiesce_then_inventory_then_health'}
      'backup_failure'{Check ($failure -ceq 'fixture_backup_failed' -and $script:installStops -eq 0 -and $script:installerCalls -eq 0 -and $script:restores -eq 0) 'backup_failure_keeps_owner_running'}
      'task_backup_failure'{Check ($failure -ceq 'fixture_task_backup_failed' -and $script:installStops -eq 0 -and $script:installerCalls -eq 0 -and $script:restores -eq 0) 'task_snapshot_failure_keeps_owner_running'}
      'stop_failure'{Check ($failure -ceq 'fixture_stop_failed' -and $script:installerCalls -eq 0 -and $script:restores -eq 0 -and $script:starts -eq 0 -and $report.rollback -ceq 'failed') 'stop_failure_never_installs_or_restores'}
      'inventory_failure'{Check ($failure -ceq 'fixture_inventory_unavailable' -and $script:installerCalls -eq 1 -and $report.rollback -ceq 'succeeded' -and $script:restores -eq 1 -and $script:starts -eq 1 -and $script:healthChecks -eq 1) 'inventory_failure_restores_original_runtime'}
      'interrupted'{Check ($failure -ceq 'recovered full installer did not complete the task-pinned Agent replacement' -and $script:recoveryWaits -eq 1 -and $script:installerCalls -eq 0 -and $report.rollback -ceq 'succeeded' -and $script:restores -eq 1 -and $script:starts -eq 1 -and $script:healthChecks -eq 1) 'interrupted_quiesce_uses_existing_recovery'}
    }
    [void]$installerResults.Add(@{mode=$mode;case=$flowCase;status=$report.status;installer_calls=$script:installerCalls;restores=$script:restores;starts=$script:starts;failure=$failure})
  }
}

# Exercise the real exception projection: PrepareToInstall also reports storage
# failures and must not by itself imply an unsupported installation baseline.
$invoke=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Invoke-FullInstallerUpgrade'},$true))
Check ($invoke.Count -eq 1) 'unique_installer_invoke'
Invoke-Expression $invoke[0].Extent.Text
function Get-InstallerLogPath {param($TaskId,$CommandId);return 'C:\public\setup.log'}
function Get-InstallerLogEvidence {param($Path);return @{Status='ready';Sha256='public-log';Size=1;Summary=$script:summary}}
function Start-Process {param($FilePath,$ArgumentList,[switch]$Wait,[switch]$PassThru);return @{ExitCode=7}}
$InstallDir='C:\public';$TaskId='public-task';$CommandId='public-command';$MinFreeBytes=[UInt64]64MB
$errorResults=New-Object 'System.Collections.Generic.List[object]'
foreach($item in @(
  @('PrepareToInstall failed: EDR: local storage preflight failed; existing runtime was not stopped.','INSTALL_EXIT_NONZERO'),
  @('uninstall baseline present. PrepareToInstall failed: insufficient space.','INSTALL_EXIT_NONZERO'),
  @('PrepareToInstall failed: EDR: /EDR_UPGRADE_EXISTING requires a completed existing Setup installation.','INSTALL_BASELINE_UNSUPPORTED'),
  @('PrepareToInstall failed: EDR: baseline repair backup is incomplete; refusing to modify the existing Agent.','INSTALL_BASELINE_UNSUPPORTED')
)){
  $script:summary=$item[0];$failure=$null
  try{Invoke-FullInstallerUpgrade -SetupPath 'C:\public\setup.exe' -Mode service -RuntimeBackupPath 'C:\public\backup'}catch{$failure=$_.Exception.Message}
  Check ($null -ne $failure -and $failure.StartsWith($item[1]+'|installer_exit_code=7|')) 'installer_failure_classification'
  [void]$errorResults.Add(@{expected=$item[1];error=$failure})
}
@{schema='edr.updater-stop-tests.v1';status='passed';checks=$script:checks;updater_sha256=$UpdaterSha256;function_extraction_only=$true;scm_stub=$true;process_query_stub=$true;rollback_external_io_stub=$true;updater_main_executed=$false;cases=$results.ToArray();rollback_cases=$rollbackResults.ToArray();installer_cases=$installerResults.ToArray();installer_error_cases=$errorResults.ToArray();installer_external_io_stub=$true} | ConvertTo-Json -Depth 5 -Compress
