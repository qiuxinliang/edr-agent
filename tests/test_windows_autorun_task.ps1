#Requires -Version 5.1
param([Parameter(Mandatory=$true)][string]$AutorunPath)
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($AutorunPath,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'autorun_parse_failed'}
$start=$ast.Extent.Text.IndexOf('# --- Install ---')
if($start -lt 0){throw 'install_owner_missing'}
$body=@($ast.EndBlock.Statements|Where-Object {$_.Extent.StartOffset -gt $start}|ForEach-Object {
  if($_ -is [Management.Automation.Language.ExitStatementAst]){return}
  # Machine-wide registry/broadcast I/O is explicitly excluded. All other
  # production install statements execute with the external boundaries below.
  if($_ -is [Management.Automation.Language.TryStatementAst] -and $_.Extent.Text.Contains('[Environment]::SetEnvironmentVariable')){return}
  $_.Extent.Text
}) -join "`n"
$install=[scriptblock]::Create($body)
function Test-Path {return $true}
function Stop-AgentProcess {}
function Remove-StaleQueueLock {}
function Set-InstallDirAclHarden {}
function Set-AgentTomlAcl {}
function Repair-RuntimeDependencyAcls {}
function Repair-SensitiveRuntimeAcls {if($script:case -eq 'acl_failure'){throw 'fixture_acl_failure'}}
function Repair-ExecutableAcl {}
function Write-TaskLauncher {if($script:case -eq 'launcher_failure'){throw 'fixture_launcher_failure'};return 'C:\public\launcher.ps1'}
function Stop-ScheduledTask {}
function Remove-ScheduledTaskIfPresent {$script:existing=$false}
function Unregister-ScheduledTask {param($TaskName,$Confirm);if($TaskName -eq $TaskNameFixture){$script:existing=$false};$script:legacyRemoved++}
function New-ScheduledTaskAction {return 'action'}
function New-ScheduledTaskTrigger {return 'trigger'}
function New-ScheduledTaskPrincipal {return 'principal'}
function New-ScheduledTaskSettingsSet {return 'settings'}
function Register-ScheduledTask {if($script:case -eq 'register_failure'){throw 'fixture_register_failure'};$script:registered=$true;$script:existing=$true}
function Start-ScheduledTask {throw 'NoStart_was_ignored'}
$instDir='C:\public';$TaskName='fixture-task';$TaskNameFixture=$TaskName;$LegacyTaskName='legacy-fixture'
$HardenAcl=$true;$NoStart=$true
foreach($name in @('acl_failure','launcher_failure','register_failure','success')){
  $script:case=$name;$script:existing=$true;$script:registered=$false;$script:legacyRemoved=0;$failure=$null
  try{& $install}catch{$failure=$_.Exception.Message}
  if(-not $script:existing){throw ('original_owner_removed_before_commit_'+$name)}
  if($name -eq 'success'){
    if($failure -or -not $script:registered -or $script:legacyRemoved -ne 1){throw 'successful_task_replacement_contract'}
  }elseif($failure -cne ('fixture_'+$name) -or $script:registered -or $script:legacyRemoved){throw ('failed_task_replacement_contract_'+$name)}
}
@{status='passed';cases=4;production_install_body=$true;external_io_stub=$true;machine_environment_skipped=$true}|ConvertTo-Json -Compress
