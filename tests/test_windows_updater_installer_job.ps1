#Requires -Version 5.1
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$UpdaterPath)
# Extract production owners only. All native processes and files belong to this
# unique fixture directory; no installed Agent, service, task, or Setup runs.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($UpdaterPath,[ref]$tokens,[ref]$errors)
if($errors.Count){throw ($errors|Out-String)}
$script:checks=0
function Check($Value,[string]$Name){$script:checks++;if(-not $Value){throw $Name}}
foreach($name in @('Initialize-InstallerJobType','Confirm-FullInstallerQuiesced','Test-InstallerOwnerBeforeBoot','Get-InstallerUptimeMilliseconds','Invoke-FullInstallerUpgrade','Get-UnixTimeMilliseconds','Set-UpdateStage')) {
  $function=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$true))
  Check ($function.Count -eq 1) ('owner_'+$name)
  Invoke-Expression $function[0].Extent.Text
}
Initialize-InstallerJobType
$root=Join-Path ([IO.Path]::GetTempPath()) ('edr-upgrade-installer-job-'+[Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $root|Out-Null
$powershell=Join-Path $PSHOME 'powershell.exe'
$journalPath=Join-Path $root 'journal.json'
$report=@{}
$script:persisted=$null
function Write-AtomicJson {param($Path,$Value);$script:persisted=$Value|ConvertTo-Json -Depth 10 -Compress;[IO.File]::WriteAllText($Path,$script:persisted)}
function New-Owner {return [FDSecurity.InstallerJob]::Create(('Global\FDSecurity.Installer.'+[Guid]::NewGuid().ToString('N')))}
function Wait-File([string]$Path) {
  $clock=[Diagnostics.Stopwatch]::StartNew()
  while(-not [IO.File]::Exists($Path)) {if($clock.ElapsedMilliseconds -gt 15000){throw ('child_ready_timeout:'+([IO.Path]::GetFileName($Path)))};Start-Sleep -Milliseconds 50}
}
function Encoded([string]$Code){return [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Code))}
function Start-Tree($Owner,[string]$Name,[bool]$RootExits) {
  $pidPath=Join-Path $root ($Name+'.pid');$writePath=Join-Path $root ($Name+'.writes')
  $child="[IO.File]::WriteAllText('$pidPath',`$PID.ToString());while(`$true){[IO.File]::AppendAllText('$writePath','x');Start-Sleep -Milliseconds 10}"
  $parent="`$p=Start-Process -FilePath '$powershell' -ArgumentList '-NoProfile -NonInteractive -EncodedCommand $(Encoded $child)' -PassThru;"
  if(-not $RootExits){$parent+='while($true){Start-Sleep -Seconds 1}'}
  $Owner.Launch($powershell,('-NoProfile -NonInteractive -EncodedCommand '+(Encoded $parent)),$root)
  Wait-File $pidPath
  $childProcess=[Diagnostics.Process]::GetProcessById([int][IO.File]::ReadAllText($pidPath))
  $null=$childProcess.Handle # Retain the exact process object, never kill by PID.
  return [pscustomobject]@{Child=$childProcess;Writes=$writePath}
}
$fullInstallerOwner=$null;$tree=$null;$fullInstallerLegacyWaitCompleted=$false
try {
  # Root exits first; a live descendant still writing must prevent completion.
  $fullInstallerOwner=New-Owner
  $journal=@{installer_job_name=$fullInstallerOwner.Name;installer_quiesced=$false;installer_owner_started_at=[DateTime]::UtcNow.ToString('o')}
  $tree=Start-Tree $fullInstallerOwner 'parent-exit' $true
  Check (-not $fullInstallerOwner.WaitForEmpty(200)) 'root_exit_is_not_subtree_completion'
  Check ($fullInstallerOwner.ActiveProcesses() -gt 0) 'descendant_remains_owned'
  $collision=$false
  try{$unexpected=[FDSecurity.InstallerJob]::Create($fullInstallerOwner.Name);$unexpected.Dispose()}catch{$collision=$true}
  Check $collision 'existing_job_is_not_adopted'
  Check (-not $tree.Child.HasExited) 'collision_does_not_terminate_owned_child'
  Confirm-FullInstallerQuiesced
  Check ($tree.Child.WaitForExit(5000)) 'timeout_barrier_drains_actual_child'
  Check ($fullInstallerOwner.ActiveProcesses() -eq 0) 'job_accounting_zero'
  Check ((ConvertFrom-Json $script:persisted).installer_quiesced -eq $true) 'zero_receipt_persisted'
  $before=([IO.File]::ReadAllText($tree.Writes)).Length;Start-Sleep -Milliseconds 150
  Check (([IO.File]::ReadAllText($tree.Writes)).Length -eq $before) 'no_writes_after_rollback_barrier'
  $fullInstallerOwner.Dispose();$fullInstallerOwner=$null;$tree.Child.Dispose();$tree=$null
  # Reopen the real persisted receipt; no process scan/boot query is necessary.
  $saved=ConvertFrom-Json ([IO.File]::ReadAllText($journalPath))
  $journal=@{installer_job_name=$saved.installer_job_name;installer_quiesced=$saved.installer_quiesced;installer_owner_started_at=$saved.installer_owner_started_at}
  Confirm-FullInstallerQuiesced
  Check $journal.installer_quiesced 'closed_owner_receipt_survives_reopen'

  # Simulate updater process death by closing its sole owner handle. KILL_ON_CLOSE
  # terminates the real writer tree, but absent name alone must NOT allow restore.
  $fullInstallerOwner=New-Owner
  $journal=@{installer_job_name=$fullInstallerOwner.Name;installer_quiesced=$false;installer_owner_started_at=[DateTime]::UtcNow.AddMinutes(1).ToString('o')}
  $tree=Start-Tree $fullInstallerOwner 'owner-close' $false
  $fullInstallerOwner.Dispose();$fullInstallerOwner=$null
  Check ($tree.Child.WaitForExit(5000)) 'owner_close_kills_actual_descendant'
  $tree.Child.Dispose();$tree=$null
  $blocked=$false
  try{Confirm-FullInstallerQuiesced}catch{$blocked=$_.Exception.Message -like '*INSTALL_WRITERS_UNCONFIRMED*'}
  Check ($blocked -and -not $journal.installer_quiesced) 'missing_job_without_receipt_remains_blocked'
  # Repeated blocked writes cannot turn the receipt into success.
  Set-UpdateStage -Stage full_installer_recovery_blocked
  $saved=ConvertFrom-Json ([IO.File]::ReadAllText($journalPath))
  $journal=@{installer_job_name=$saved.installer_job_name;installer_quiesced=$saved.installer_quiesced;installer_owner_started_at=$saved.installer_owner_started_at}
  $blocked=$false
  try{Confirm-FullInstallerQuiesced}catch{$blocked=$_.Exception.Message -like '*INSTALL_WRITERS_UNCONFIRMED*'}
  Check ($blocked -and -not $journal.installer_quiesced) 'repeated_recovery_cannot_erase_uncertainty'

  # Recovery with another live job handle can prove/drain the actual subtree.
  $keeper=New-Owner
  try {
    $journal=@{installer_job_name=$keeper.Name;installer_quiesced=$false;installer_owner_started_at=[DateTime]::UtcNow.ToString('o')}
    $tree=Start-Tree $keeper 'reopen-owner' $false
    Confirm-FullInstallerQuiesced
    Check ($tree.Child.WaitForExit(5000) -and $keeper.ActiveProcesses() -eq 0) 'reopened_job_drains_entire_tree'
    Check $journal.installer_quiesced 'reopened_job_records_zero_receipt'
    $tree.Child.Dispose();$tree=$null
  } finally {$keeper.Dispose()}

  # Real controller death (not Dispose): the OS closes its sole production
  # Job handle. Retain the writer's exact handle before terminating controller.
  $controllerPath=Join-Path $root 'controller.ps1'
  $controllerPidPath=Join-Path $root 'crash-child.pid'
  $crashName='Global\FDSecurity.Installer.'+[Guid]::NewGuid().ToString('N')
  $init=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Initialize-InstallerJobType'},$true))[0].Extent.Text
  $childCode="[IO.File]::WriteAllText('$controllerPidPath',`$PID.ToString());while(`$true){Start-Sleep -Seconds 1}"
  $controllerCode=$init+"`nInitialize-InstallerJobType;`$owner=[FDSecurity.InstallerJob]::Create('$crashName');`$owner.Launch('$powershell','-NoProfile -NonInteractive -EncodedCommand $(Encoded $childCode)','$root');while(`$true){Start-Sleep -Seconds 1}"
  [IO.File]::WriteAllText($controllerPath,$controllerCode)
  # Load the extracted fixture source as a scriptblock, as the release gate
  # does; do not depend on the machine's unsigned .ps1 execution policy.
  $controllerCommand="& ([scriptblock]::Create([IO.File]::ReadAllText('$controllerPath')))"
  $controller=Start-Process -FilePath $powershell -ArgumentList @('-NoProfile','-NonInteractive','-EncodedCommand',(Encoded $controllerCommand)) -PassThru
  $null=$controller.Handle
  $crashChild=$null
  try {
    Wait-File $controllerPidPath
    $crashChild=[Diagnostics.Process]::GetProcessById([int][IO.File]::ReadAllText($controllerPidPath));$null=$crashChild.Handle
    $controller.Kill()
    Check ($controller.WaitForExit(5000)) 'actual_controller_process_terminated'
    Check ($crashChild.WaitForExit(5000)) 'actual_controller_crash_closes_job_and_terminates_writer'
    $journal=@{installer_job_name=$crashName;installer_quiesced=$false;installer_owner_uptime_ms=(Get-InstallerUptimeMilliseconds)}
    $blocked=$false;try{Confirm-FullInstallerQuiesced}catch{$blocked=$_.Exception.Message -like '*INSTALL_WRITERS_UNCONFIRMED*'}
    Check ($blocked -and -not $journal.installer_quiesced) 'actual_crash_without_receipt_does_not_guess_completion'
  } finally {
    if(-not $controller.HasExited){$controller.Kill();$controller.WaitForExit(5000)|Out-Null}
    $controller.Dispose();if($crashChild){$crashChild.Dispose()}
  }

  # Real native monotonic uptime is available; wall clock is not a proof.
  Check ((Get-InstallerUptimeMilliseconds) -gt 0) 'native_monotonic_uptime_available'
  foreach($case in @(@{old=100L;now=99L;reboot=$true},@{old=100L;now=100L;reboot=$false},@{old=100L;now=101L;reboot=$false},@{old=$null;now=1L;reboot=$false})) {
    Check ((Test-InstallerOwnerBeforeBoot -RecordedUptime $case.old -CurrentUptime $case.now) -eq $case.reboot) 'monotonic_reboot_evidence'
  }
  foreach($invalid in @('100',$true,-1,1.5)) {
    $blocked=$false;try{Test-InstallerOwnerBeforeBoot -RecordedUptime $invalid -CurrentUptime 1|Out-Null}catch{$blocked=$true}
    Check $blocked 'damaged_generation_never_proves_reboot'
  }
  $originalUptimeFunction=${function:Get-InstallerUptimeMilliseconds}
  $script:uptime=100L
  function Get-InstallerUptimeMilliseconds {return $script:uptime}
  function Get-Date {throw 'wall_clock_must_not_prove_exit'}
  $journal=@{installer_job_name=$null;installer_quiesced=$false;installer_owner_started_at='1970-01-01T00:00:00Z'}
  $blocked=$false;try{Confirm-FullInstallerQuiesced}catch{$blocked=$_.Exception.Message -like '*INSTALL_WRITERS_UNCONFIRMED*'}
  Check ($blocked -and $journal.installer_owner_uptime_ms -eq 100L -and -not $journal.installer_quiesced) 'legacy_first_recovery_checkpoints_uncertainty'
  $saved=ConvertFrom-Json ([IO.File]::ReadAllText($journalPath))
  $journal=@{installer_job_name=$null;installer_quiesced=$false;installer_owner_uptime_ms=$saved.installer_owner_uptime_ms}
  $script:uptime=1L
  Confirm-FullInstallerQuiesced
  Check (-not $journal.installer_quiesced) 'legacy_reboot_does_not_create_unbound_receipt'
  Confirm-FullInstallerQuiesced
  Check ($journal.installer_owner_uptime_ms -eq 100L) 'legacy_reopen_retains_original_generation'
  Remove-Item Function:Get-Date
  Set-Item Function:Get-InstallerUptimeMilliseconds $originalUptimeFunction

  # Execute production rollback dispatch with a failed barrier. SCM/mirror/start
  # are forbidden and the existing AtStartup recovery task must be retained.
  $main=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.TryStatementAst] -and $n.Body.Extent.Text -like '*$DeadlineUnixMs -le $IssuedAtUnixMs*'},$true))[0]
  $dispatch=@($main.CatchClauses[0].Body.FindAll({param($n)$n -is [Management.Automation.Language.IfStatementAst] -and $n.Clauses[0].Item1.Extent.Text -like '$UpgradeClass -eq *$fullInstallerStarted*fullInstallerBackupPath*'},$true))
  Check ($dispatch.Count -eq 1) 'production_rollback_dispatch'
  function Test-Path {return $true}
  function Stop-AgentRuntime {throw 'fixture_forbidden_stop'}
  function Start-AgentRuntime {throw 'fixture_forbidden_start'}
  function Invoke-FullInstallerRuntimeMirror {throw 'fixture_forbidden_restore'}
  function Add-UpdateEvent {param($Status,$Progress,$Detail)}
  $UpgradeClass='installer_required';$fullInstallerStarted=$true;$fullInstallerBackupPath=$root
  $failureMessage='INSTALL_TIMEOUT';$fullInstallerRecoveryBlocked=$false
  $journal=@{installer_job_name=$null;installer_quiesced=$false;installer_owner_started_at=[DateTime]::UtcNow.AddMinutes(1).ToString('o')};$report=@{}
  . ([scriptblock]::Create($dispatch[0].Extent.Text))
  Check ($fullInstallerRecoveryBlocked -and $journal.stage -eq 'full_installer_recovery_blocked' -and $journal.status -eq 'running') 'unconfirmed_writers_keep_recoverable_journal'
  Check ($report.error -notlike '*fixture_forbidden*') 'barrier_precedes_every_runtime_mutation'
  $cleanup=@($main.Finally.Statements|Where-Object {$_ -is [Management.Automation.Language.IfStatementAst] -and $_.Extent.Text -like '*Unregister-ScheduledTask*'})
  Check ($cleanup.Count -eq 1) 'production_task_cleanup_owner'
  function Unregister-ScheduledTask {throw 'fixture_forbidden_task_removal'}
  $UpdaterTaskName='fixture-not-a-real-task'
  $journalRecoveryUnverified=$false
  . ([scriptblock]::Create($cleanup[0].Extent.Text))
  Check $fullInstallerRecoveryBlocked 'blocked_recovery_preserves_startup_trigger'

  # The production early guard precedes optional-field validation/hash I/O.
  # Malformed receipts and locked/missing current files must take the barrier,
  # never the generic runtime restart branch.
  $guards=@($main.Body.FindAll({param($n)$n -is [Management.Automation.Language.IfStatementAst] -and
    $n.Clauses[0].Item1.Extent.Text -like '$UpgradeClass -eq *$priorProperties -notcontains*' -and $n.Extent.Text -like '*$ownerField*'},$true))
  Check ($guards.Count -eq 1) 'early_recovery_guard_owner'
  $hashRead=@($main.Body.FindAll({param($n)$n -is [Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq '$currentHash'},$true))[0]
  function Get-Sha256 {throw 'fixture_current_file_read_failed'}
  foreach($badReceipt in @('true',1,$true,$false)) {
    $fullInstallerStarted=$false;$fullInstallerRecoveryBlocked=$false
    $journal=@{stop_intent=$false;installer_quiesced=$false;installer_job_name=$null;installer_owner_uptime_ms=$null;installer_owner_started_at=$null};$report=@{}
    $prior=[pscustomobject]@{stop_intent=$true;installer_quiesced=$badReceipt;updated_at='1970-01-01T00:00:00Z';resolved_deployment_mode='service'}
    $priorProperties=@($prior.PSObject.Properties.Name)
    . ([scriptblock]::Create($guards[0].Extent.Text))
    Check $fullInstallerStarted 'early_exception_cannot_lose_installer_obligation'
    $currentPath='synthetic-current-file'
    try{. ([scriptblock]::Create($hashRead.Extent.Text))}catch{$failureMessage=$_.Exception.Message}
    . ([scriptblock]::Create($dispatch[0].Extent.Text))
    Check ($fullInstallerRecoveryBlocked -and $journal.status -eq 'running') 'early_exception_remains_reenterable'
    Check ($report.error -notlike '*fixture_forbidden*') 'bad_receipt_or_hash_never_bypasses_barrier'
  }
  $journal=@{installer_quiesced=$true;installer_job_name='untrusted-other-job'}
  $blocked=$false;try{Confirm-FullInstallerQuiesced}catch{$blocked=$true}
  Check $blocked 'receipt_requires_valid_owner_identity'
  $classification=@($main.Body.FindAll({param($n)$n -is [Management.Automation.Language.AssignmentStatementAst] -and
    $n.Left.Extent.Text -in @('$fullInstallerLegacyWaitCompleted','$interruptedFullInstaller')},$true))
  $interruptedBranch=@($main.Body.FindAll({param($n)$n -is [Management.Automation.Language.IfStatementAst] -and $n.Clauses[0].Item1.Extent.Text -eq '$interruptedFullInstaller'},$true))[0]
  foreach($legacyStage in @('validate_identity','full_installer_recovery_blocked')) {
    $prior=[pscustomobject]@{stage=$legacyStage;updated_at='1970-01-01T00:00:00Z'};$priorProperties=@($prior.PSObject.Properties.Name)
    $journal=@{installer_job_name=$null;installer_quiesced=$false;resolved_deployment_mode='service';installer_owner_started_at=$prior.updated_at};$report=@{}
    $recoveringUpdate=$true;$currentHash='target-already-matches';$expectedHash=$currentHash
    . ([scriptblock]::Create(($classification.Extent.Text -join "`n")))
    Check $interruptedFullInstaller 'legacy_recovery_stage_cannot_hide_installer'
    $blocked=$false;try{. ([scriptblock]::Create($interruptedBranch.Extent.Text))}catch{$blocked=$_.Exception.Message -like '*INSTALL_WRITERS_UNCONFIRMED*'}
    Check ($blocked -and -not $journal.installer_quiesced) 'legacy_candidate_hash_does_not_bypass_writer_barrier'
  }
  $fullInstallerOwner=[pscustomobject]@{Name=('Global\FDSecurity.Installer.'+[Guid]::NewGuid().ToString('N'))}
  $fullInstallerOwner|Add-Member ScriptMethod StopAndDrain {param($budget);throw 'fixture_native_termination_failed'}
  $journal=@{installer_quiesced=$false;installer_job_name=$fullInstallerOwner.Name};$report=@{}
  . ([scriptblock]::Create($dispatch[0].Extent.Text))
  Check ($fullInstallerRecoveryBlocked -and $journal.status -eq 'running' -and $report.error -notlike '*fixture_forbidden*') 'termination_failure_never_enters_runtime_rollback'
  $fullInstallerOwner=$null

  # Replay production read/identity statements and the complete catch for
  # unreadable bytes, invalid JSON, and a different transaction. Original bytes
  # and its existing recovery trigger must survive all three failures.
  $recoveryIf=@($main.Body.Statements|Where-Object {$_ -is [Management.Automation.Language.IfStatementAst] -and $_.Clauses[0].Item1.Extent.Text -eq '$journalRecoveryUnverified'})[0]
  $readStatements=@()
  foreach($statement in $recoveryIf.Clauses[0].Item2.Statements) {
    $readStatements+=@($statement.Extent.Text)
    if($statement -is [Management.Automation.Language.AssignmentStatementAst] -and $statement.Left.Extent.Text -eq '$journalRecoveryUnverified'){break}
  }
  $readIdentity=[scriptblock]::Create(($readStatements -join "`n"))
  $fullCatch=[scriptblock]::Create(($main.CatchClauses[0].Body.Statements.Extent.Text -join "`n"))
  $TaskId='fixture';$CommandId='fixture';$Operation='repair';$ArtifactId='fixture';$expectedHash=('a'*64);$TargetVersion='3.2.724'
  $identity=@{schema_version=2;task_id=$TaskId;command_id=$CommandId;operation=$Operation;artifact_id=$ArtifactId;hash=$expectedHash;version=$TargetVersion}
  $missingStatus=$identity|ConvertTo-Json -Compress
  $identity.status=1;$invalidStatus=$identity|ConvertTo-Json -Compress
  foreach($badJournal in @('read_error','{invalid_json','{"schema_version":1}',$missingStatus,$invalidStatus)) {
    [IO.File]::WriteAllText($journalPath,$badJournal)
    $journalRecoveryUnverified=$true;$fullInstallerRecoveryBlocked=$false;$report=@{}
    if($badJournal -eq 'read_error'){function Get-Content {throw 'fixture_journal_read_failed'}}
    try{. $readIdentity;throw 'fixture_expected_identity_failure'}catch{. $fullCatch}
    if($badJournal -eq 'read_error'){Remove-Item Function:Get-Content}
    Check ($journalRecoveryUnverified -and $report.rollback -eq 'recovery_blocked') 'unverified_journal_never_enters_lifecycle'
    Check ([IO.File]::ReadAllText($journalPath) -ceq $badJournal) 'unverified_journal_preserves_original_bytes'
    . ([scriptblock]::Create($cleanup[0].Extent.Text))
  }
  $journalRecoveryUnverified=$false

  # Execute the production installer wait/deadline with a real native owner.
  # Only the launch arguments are isolated from Inno, to create a harmless
  # sleeping PowerShell process instead of installing on the test host.
  $native=New-Owner
  try {
    $fullInstallerOwner=[pscustomobject]@{Native=$native;Name=$native.Name;Executable=$powershell;Directory=$root}
    $fullInstallerOwner|Add-Member ScriptMethod Launch {param($exe,$arguments,$directory);$this.Native.Launch($this.Executable,'-NoProfile -NonInteractive -Command "Start-Sleep -Seconds 60"',$this.Directory)}
    $fullInstallerOwner|Add-Member ScriptMethod WaitForEmpty {param($budget);return $this.Native.WaitForEmpty($budget)}
    $fullInstallerOwner|Add-Member ScriptMethod StopAndDrain {param($budget);$this.Native.StopAndDrain($budget)}
    $fullInstallerOwner|Add-Member ScriptMethod Dispose {$this.Native.Dispose()}
    function Get-InstallerLogPath {param($TaskId,$CommandId);return (Join-Path $root 'unused.log')}
    $TaskId='fixture';$CommandId='fixture';$InstallDir=$root;$MinFreeBytes=[UInt64]0
    $updateDeadlineProvided=$true;$DeadlineUnixMs=[UInt64]((Get-UnixTimeMilliseconds)+1000)
    $journal=@{installer_job_name=$native.Name;installer_quiesced=$false;installer_owner_uptime_ms=(Get-InstallerUptimeMilliseconds)}
    $timeout=$false
    try{Invoke-FullInstallerUpgrade -SetupPath $powershell -Mode service -RuntimeBackupPath $root}catch{$timeout=$_.Exception.Message -eq 'INSTALL_TIMEOUT|execution_deadline_exceeded'}
    Check $timeout 'production_installer_deadline_terminates_wait'
    Check (-not $journal.installer_quiesced) 'timeout_alone_does_not_receipt_zero'
    Confirm-FullInstallerQuiesced
    Check ($native.ActiveProcesses() -eq 0 -and $journal.installer_quiesced) 'production_timeout_then_barrier_drains_before_rollback'
  } finally {$native.Dispose();$fullInstallerOwner=$null}

  # Timeout diagnostics use the existing redaction owner after quiescence.
  # Failure to collect them cannot erase the timeout or prevent restoration.
  Remove-Item Function:Test-Path
  Remove-Item Function:Get-Sha256
  foreach($name in @('Get-Sha256','Get-InstallerLogEvidence','Get-InstallerEvidenceId','Save-FullInstallerFailureLog')) {
    $definition=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$true))[0]
    Invoke-Expression $definition.Extent.Text
  }
  [IO.File]::WriteAllText((Join-Path $root 'unused.log'),"installer reached child writer`nAuthorization: sensitive-fixture-token`n")
  $journal=@{first_error='INSTALL_TIMEOUT'};$report=@{first_error='INSTALL_TIMEOUT';error_code='INSTALL_TIMEOUT'}
  Save-FullInstallerFailureLog
  Check ($journal.installer_log_sha256 -match '^[0-9a-f]{64}$' -and $journal.installer_evidence_status -eq 'pending_upload') 'timeout_preserves_existing_log_upload_descriptor'
  Check ([IO.File]::ReadAllText((Join-Path $root $journal.installer_log_file)) -notlike '*sensitive-fixture-token*') 'timeout_diagnostic_uses_existing_redaction'
  function Get-InstallerLogEvidence {throw 'fixture_log_read_failed'}
  Save-FullInstallerFailureLog
  Check ($report.installer_log_status -eq 'collection_failed' -and $report.first_error -eq 'INSTALL_TIMEOUT' -and $journal.first_error -eq 'INSTALL_TIMEOUT') 'diagnostic_failure_preserves_timeout_first_cause'
} finally {
  if($fullInstallerOwner){$fullInstallerOwner.Dispose()}
  if($tree){$tree.Child.WaitForExit(5000)|Out-Null;$tree.Child.Dispose()}
  Remove-Item -LiteralPath $root -Recurse -Force
}
@{schema='edr.updater-installer-job-tests.v1';status='passed';checks=$script:checks;updater_main_executed=$false;runtime_effects='temporary_fixture_processes_only'}|ConvertTo-Json -Compress
