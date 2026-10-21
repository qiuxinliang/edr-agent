#Requires -Version 5.1
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$UpdaterPath, [string]$BaselinePath='')
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($UpdaterPath,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'updater_parse_failed'}
foreach($name in @('Get-AgentTaskFolder','Save-AgentTaskDefinition','Test-AgentTaskSecurityDescriptor','Restore-AgentTaskDefinition','Write-AtomicJson','Get-Sha256')){
  $defs=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$true))
  if($defs.Count -ne 1){throw "missing_recovery_owner_$name"}
  Invoke-Expression $defs[0].Extent.Text
}
function RollbackBody($Tree){
  $nodes=@($Tree.FindAll({param($n) $n -is [Management.Automation.Language.IfStatementAst] -and
    $n.Clauses[0].Item1.Extent.Text -like '$UpgradeClass -eq *$fullInstallerStarted*fullInstallerBackupPath*'},$true))
  if($nodes.Count -ne 1){throw 'rollback_owner_not_unique'}
  $s=$nodes[0].Clauses[0].Item2.Extent.Text
  return [scriptblock]::Create($s.Substring(1,$s.Length-2))
}
$oldBody=$null
if($BaselinePath){
  $baseline=[Management.Automation.Language.Parser]::ParseFile($BaselinePath,[ref]$tokens,[ref]$errors)
  if($errors.Count){throw 'baseline_parse_failed'}
  $oldBody=RollbackBody $baseline
}
$newBody=RollbackBody $ast
$script:checks=0
function Check($Value,[string]$Cause){$script:checks++;if(-not $Value){throw $Cause}}
$tag=[Guid]::NewGuid().ToString('N')
$root=Join-Path $env:TEMP ('edr-task-recovery-'+$tag)
[IO.Directory]::CreateDirectory($root)|Out-Null
$ScheduledTaskName='EDR-Isolated-Recovery-'+$tag;$ScheduledTaskPath='\'
$fullInstallerTaskBackupPath=Join-Path $root 'task.json'
$fullInstallerConfigBackupPath=Join-Path $root 'absent-config'
$fullInstallerBackupPath=Join-Path $root 'fixture-backup';$installFull=$root
$currentPath=Join-Path $root 'restored.bin';[IO.File]::WriteAllText($currentPath,'public old runtime')
$marker=Join-Path $root 'started.txt'
$resolvedDeploymentMode='scheduled_task';$ServiceName='unused-fixture'
$StartupTimeoutSeconds=10;$HealthObserveMs=1000;$failureMessage='fixture_install_task_timeout'
$folder=Get-AgentTaskFolder '\'
try{
  $args='-NoProfile -NonInteractive -Command "[IO.File]::WriteAllText('''+$marker+''',''old-owner'')"'
  $action=New-ScheduledTaskAction -Execute (Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe') -Argument $args -WorkingDirectory $root
  $principal=New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest
  $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
  Register-ScheduledTask -TaskName $ScheduledTaskName -Action $action -Principal $principal -Settings $settings | Out-Null
  $original=$folder.GetTask($ScheduledTaskName)
  $originalXml=[string]$original.Xml;$originalSddl=[string]$original.GetSecurityDescriptor(7)
  $hash=Save-AgentTaskDefinition -TaskName $ScheduledTaskName -TaskPath '\' -Path $fullInstallerTaskBackupPath
  $journal=@{full_installer_task_backup_sha256=$hash}
  $snapshotBytes=[IO.File]::ReadAllBytes($fullInstallerTaskBackupPath)
  Check ($hash -match '^[a-f0-9]{64}$') 'snapshot_digest'
  $folder.DeleteTask($ScheduledTaskName,0)

  # Actual production rollback bodies; only runtime file mirror/health are
  # synthetic. Task restore, ACLs, deletion and launch use Windows APIs.
  function Set-UpdateStage {param($Stage,$Status);$script:stage=$Stage}
  function Stop-AgentRuntime {param($Mode,$TaskName,$TaskPath,$WindowsServiceName,$ExecutablePath);Check ($TaskName -ceq $ScheduledTaskName) 'stop_scope'}
  function Invoke-FullInstallerRuntimeMirror {param($Source,$Destination,$Stage);$script:mirrored=$true}
  function Start-AgentRuntime {param($Mode,$TaskName,$TaskPath,$WindowsServiceName,$ExecutablePath,$TimeoutSeconds);Start-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction Stop}
  function Wait-AgentHealthObservation {
    param($Mode,$TaskName,$TaskPath,$WindowsServiceName,$ExecutablePath,$ObserveForMs)
    $w=[Diagnostics.Stopwatch]::StartNew()
    while(-not (Test-Path -LiteralPath $marker)){
      if($w.ElapsedMilliseconds -gt 10000){throw 'fixture_original_action_did_not_run'}
      Start-Sleep -Milliseconds 100
    }
    Check ([IO.File]::ReadAllText($marker) -ceq 'old-owner') 'original_action_executed'
  }
  function Add-UpdateEvent {param($Status,$Progress,$Detail)}
  $report=@{status='failed';error=$failureMessage};$script:mirrored=$false
  if($oldBody){
    & $oldBody
    Check ($script:mirrored -and $report.rollback -ceq 'failed' -and $script:stage -ceq 'rollback_failed') 'baseline_missing_task_reproduced'
  }
  $report=@{status='failed';error=$failureMessage};$script:mirrored=$false
  & $newBody
  if($report.rollback -ne 'succeeded'){
    @{fixture_snapshot_sddl=$originalSddl;fixture_restored_sddl=[string]$folder.GetTask($ScheduledTaskName).GetSecurityDescriptor(7)}|ConvertTo-Json -Compress|Write-Host
  }
  Check ($script:mirrored -and $report.rollback -ceq 'succeeded' -and $report.status -ceq 'failed_rolled_back') ('patched_rollback_restores_owner: '+$report.error)
  $restored=$folder.GetTask($ScheduledTaskName)
  Check (Test-AgentTaskSecurityDescriptor $originalSddl $restored.GetSecurityDescriptor(7)) 'original_task_security_preserved'
  # Windows adds RegistrationInfo/SecurityDescriptor when sddl is supplied.
  # Verify that ACL above, then compare every other XML field without ignoring
  # actions, principal, triggers, settings or registration identity.
  $a=[xml]$originalXml;$b=[xml]$restored.Xml
  foreach($doc in @($a,$b)){
    $node=$doc.SelectSingleNode("/*[local-name()='Task']/*[local-name()='RegistrationInfo']/*[local-name()='SecurityDescriptor']")
    if($node){[void]$node.ParentNode.RemoveChild($node)}
  }
  Check ($a.OuterXml -ceq $b.OuterXml) 'original_task_definition_preserved'
  $private='O:BAG:SYD:P(A;;FA;;;SY)(A;;FR;;;BA)'
  Check (Test-AgentTaskSecurityDescriptor $private $private) 'identical_permissions'
  foreach($changed in @('O:SYG:SYD:P(A;;FA;;;SY)(A;;FR;;;BA)',
    'O:BAG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)', 'O:BAG:SYD:P(D;;FR;;;BA)(A;;FA;;;SY)(A;;FR;;;BA)',
    'O:BAG:SYD:(A;;FA;;;SY)(A;;FR;;;BA)')){
    Check (-not (Test-AgentTaskSecurityDescriptor $private $changed)) 'changed_permissions_refused'
  }

  # A replacement Task is restored too, not merely recreated when absent.
  $restored.Enabled=$false
  Restore-AgentTaskDefinition $ScheduledTaskName '\' $fullInstallerTaskBackupPath $hash
  Check ($folder.GetTask($ScheduledTaskName).Enabled) 'changed_task_settings_restored'
  foreach($case in @('tampered','wrong_name','wrong_path','missing_hash','missing_file')){
    $folder.DeleteTask($ScheduledTaskName,0)
    [IO.File]::WriteAllBytes($fullInstallerTaskBackupPath,$snapshotBytes)
    $name=$ScheduledTaskName;$path='\';$digest=$hash
    switch($case){
      'tampered'{[IO.File]::AppendAllText($fullInstallerTaskBackupPath,' ')}
      'wrong_name'{$name='EDR-Isolated-Wrong-'+$tag}
      'wrong_path'{$path='\Wrong\'}
      'missing_hash'{$digest=''}
      'missing_file'{Remove-Item -LiteralPath $fullInstallerTaskBackupPath}
    }
    $failed=$false
    try{Restore-AgentTaskDefinition $name $path $fullInstallerTaskBackupPath $digest}catch{$failed=$true}
    Check $failed ('refuse_'+$case)
    Check (@(Get-ScheduledTask | Where-Object {$_.TaskName -ceq $ScheduledTaskName}).Count -eq 0) ('no_registration_'+$case)
    [IO.File]::WriteAllBytes($fullInstallerTaskBackupPath,$snapshotBytes)
    Restore-AgentTaskDefinition $ScheduledTaskName '\' $fullInstallerTaskBackupPath $hash
  }
  $folder.DeleteTask($ScheduledTaskName,0)
  $failed=$false
  try{Save-AgentTaskDefinition $ScheduledTaskName '\' $fullInstallerTaskBackupPath}catch{$failed=$true}
  Check $failed 'upgrade_requires_known_task'
  $absentHash=Save-AgentTaskDefinition $ScheduledTaskName '\' $fullInstallerTaskBackupPath -AllowMissing
  Check (-not (Get-Content $fullInstallerTaskBackupPath -Raw|ConvertFrom-Json).present) 'repair_can_record_original_absence'
  $failed=$false
  try{Restore-AgentTaskDefinition $ScheduledTaskName '\' $fullInstallerTaskBackupPath $absentHash}catch{$failed=$true}
  Check $failed 'no_fabricated_owner_for_absent_original'
  [IO.File]::WriteAllBytes($fullInstallerTaskBackupPath,$snapshotBytes)
  Restore-AgentTaskDefinition $ScheduledTaskName '\' $fullInstallerTaskBackupPath $hash

  # Resume must retain the digest and select full-installer rollback even
  # after old runtime bytes have already been restored before a crash.
  $copy=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.ForEachStatementAst] -and $n.Variable.VariablePath.UserPath -ceq 'field' -and $n.Extent.Text.Contains('full_installer_task_backup_sha256')},$true))
  Check ($copy.Count -eq 1) 'journal_restore_owner'
  $prior=[pscustomobject]@{full_installer_task_backup_sha256=$hash;stage='rollback_full_installer_started'}
  $priorProperties=@('full_installer_task_backup_sha256');$journal=@{}
  . ([scriptblock]::Create($copy[0].Extent.Text))
  Check ($journal.full_installer_task_backup_sha256 -ceq $hash) 'journal_restores_snapshot_digest'
  $route=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.IfStatementAst] -and $n.Clauses[0].Item1.Extent.Text.Contains('$currentMatchesCandidate') -and $n.Clauses[0].Item1.Extent.Text.Contains('rollback_*')},$true))
  Check ($route.Count -eq 1) 'full_rollback_resume_owner'
  $UpgradeClass='installer_required';$currentMatchesCandidate=$false;$fullInstallerStarted=$false
  . ([scriptblock]::Create($route[0].Extent.Text))
  Check $fullInstallerStarted 'interrupted_full_rollback_keeps_task_recovery'
  # RegisterTask must not fire a registration trigger while restoring.
  $snapshot=Get-Content -LiteralPath $fullInstallerTaskBackupPath -Raw|ConvertFrom-Json
  $xml=[xml]$snapshot.xml;$ns=New-Object Xml.XmlNamespaceManager($xml.NameTable);$ns.AddNamespace('t',$xml.DocumentElement.NamespaceURI)
  $triggers=$xml.SelectSingleNode('/t:Task/t:Triggers',$ns)
  $trigger=$xml.CreateElement('RegistrationTrigger',$xml.DocumentElement.NamespaceURI)
  $enabled=$xml.CreateElement('Enabled',$xml.DocumentElement.NamespaceURI);$enabled.InnerText='true';[void]$trigger.AppendChild($enabled);[void]$triggers.AppendChild($trigger)
  $snapshot.xml=$xml.OuterXml;Write-AtomicJson $fullInstallerTaskBackupPath $snapshot
  $hash=Get-Sha256 $fullInstallerTaskBackupPath
  Remove-Item -LiteralPath $marker
  Restore-AgentTaskDefinition $ScheduledTaskName '\' $fullInstallerTaskBackupPath $hash
  Start-Sleep -Seconds 2
  Check (-not (Test-Path -LiteralPath $marker)) 'registration_trigger_suppressed'
  @{status='passed';checks=$script:checks;native_task_apis=$true;runtime_mirror_stub=$true;health_fixture_only=$true;active_agent_controlled=$false}|ConvertTo-Json -Compress
}finally{
  # Only the GUID task owned by this fixture is deleted.
  Unregister-ScheduledTask -TaskName $ScheduledTaskName -TaskPath '\' -Confirm:$false -ErrorAction SilentlyContinue
}
