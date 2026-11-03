#Requires -Version 5.1
[CmdletBinding()]
param([string]$RepoRoot=(Split-Path -Parent $PSScriptRoot))
# Only AST-extracted harness owners run. OS process/service/task/Setup boundaries
# are fixtures; this test never creates a task, installs software or touches an Agent.
$ErrorActionPreference='Stop'
$root=Join-Path ([IO.Path]::GetTempPath()) ('edr-lifecycle-mode-'+[Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($root)|Out-Null
$cases=New-Object 'System.Collections.Generic.List[string]'
function Put([string]$Path,[string]$Text) { [IO.File]::WriteAllText($Path,$Text,[Text.UTF8Encoding]::new($false)) }
function Pass([string]$Name,[scriptblock]$Action) { & $Action; $cases.Add($Name) }
function Reject([string]$Name,[string]$Expected,[scriptblock]$Action) {
  $caught=$false
  try { & $Action } catch {
    $caught=$true
    if ($_.Exception.Message -notlike $Expected) { throw ($Name+': unexpected failure: '+$_.Exception.Message) }
  }
  if (-not $caught) { throw ($Name+': unexpectedly accepted') }
  $cases.Add($Name)
}
try {
  . ([scriptblock]::Create([IO.File]::ReadAllText((Join-Path $RepoRoot 'scripts/Start-LifecycleWindowsPowerShell.ps1'))))
  $tokens=$null;$errors=$null
  $ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $RepoRoot 'scripts/windows_setup_exe_lifecycle_smoke.ps1'),[ref]$tokens,[ref]$errors)
  if ($errors.Count -ne 0) { throw 'lifecycle script parse failed' }
  foreach($name in @('Get-LifecycleAgentProcesses','Get-LifecycleRuntimeProcess','Get-LifecycleRuntimeOwner',
      'New-LifecyclePreservationSnapshot','Assert-LifecyclePreservationSnapshot','Invoke-Installer','Invoke-BaselineRepair')) {
    $owners=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name},$true))
    if ($owners.Count -ne 1) { throw ('missing unique harness owner '+$name) }
    . ([scriptblock]::Create($owners[0].Extent.Text))
  }
  $recovery=[Management.Automation.Language.Parser]::ParseFile((Join-Path $RepoRoot 'tests/Invoke-RealInstallerTimeoutRecovery.ps1'),[ref]$tokens,[ref]$errors)
  if($errors.Count -ne 0){throw 'recovery script parse failed'}
  $owners=@($recovery.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Get-RecoveryOwnerSnapshot'},$true))
  if($owners.Count -ne 1){throw 'missing unique recovery snapshot owner'}
  . ([scriptblock]::Create($owners[0].Extent.Text))
  $InstallDir=Join-Path $root 'installed';$EvidenceDir=Join-Path $root 'evidence';$ServiceName='FixtureService'
  [IO.Directory]::CreateDirectory($InstallDir)|Out-Null;[IO.Directory]::CreateDirectory($EvidenceDir)|Out-Null
  Put (Join-Path $InstallDir 'agent.toml') 'isolated configuration'
  $launcher=Join-Path $InstallDir 'FDSensorTaskLaunch.ps1';Put $launcher '# data fixture only; never executed'
  $script:service=[pscustomobject]@{State='Running';PathName=(Join-Path $InstallDir 'FDSensor.exe');StartName='LocalSystem';StartMode='Auto';ProcessId=123}
  $script:processes=@([pscustomobject]@{ExecutablePath=(Join-Path $InstallDir 'FDSensor.exe');ProcessId=123})
  $script:task=[pscustomobject]@{TaskName=$ServiceName;TaskPath='\';State='Running';
    Principal=[pscustomobject]@{UserId='SYSTEM';LogonType='ServiceAccount';RunLevel='Highest'};
    Actions=@([pscustomobject]@{Execute=(Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe');
      Arguments=('-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "'+$launcher+'"');WorkingDirectory=$InstallDir})}
  $script:definition=[pscustomobject]@{xml='<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><RegistrationInfo><Date>2026-01-01T00:00:00</Date></RegistrationInfo><Triggers><BootTrigger><Enabled>true</Enabled></BootTrigger></Triggers><Settings><ExecutionTimeLimit>PT0S</ExecutionTimeLimit><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><RestartOnFailure><Interval>PT1M</Interval><Count>3</Count></RestartOnFailure></Settings></Task>';sddl='O:SYG:SYD:P(A;;FA;;;SY)'}
  function Get-CimInstance {
    [CmdletBinding()]param($ClassName,[string]$Filter)
    if($ClassName -ceq 'Win32_Service'){return $script:service}
    if($ClassName -ceq 'Win32_Process'){return $script:processes}
    throw 'unexpected CIM boundary'
  }
  function Get-ScheduledTask {
    [CmdletBinding()]param([string]$TaskName,[string]$TaskPath)
    if($TaskName -cne $ServiceName -or $TaskPath -cne '\'){throw 'task query must use exact name/path'}
    return $script:task
  }
  function Get-LifecycleTaskDefinition { return $script:definition }
  function Add-Evidence { param($Stage,$Status,$Detail) }
  $InputBinding=[pscustomobject]@{target_version='3.2.999'}
  function Get-ItemProperty {
    [CmdletBinding()]param([string]$Path)
    if($Path -like '*WOW6432Node*'){return $null}
    return [pscustomobject]@{InstallLocation=$InstallDir;DisplayVersion=$InputBinding.target_version;PSPath='fixture';PSChildName='fixture-key';UninstallString='fixture-uninstall';QuietUninstallString='fixture-quiet'}
  }
  function Start-Process {
    [CmdletBinding()]param([string]$FilePath,[string[]]$ArgumentList,[switch]$Wait,[switch]$PassThru)
    $script:invocation=@{path=$FilePath;arguments=$ArgumentList;wait=[bool]$Wait;pass_thru=[bool]$PassThru}
    return [pscustomobject]@{ExitCode=0}
  }
  foreach($RuntimeMode in @('service','scheduled_task')) {
    $taskArgument=if($RuntimeMode -ceq 'service'){'/TASKS="windowsservice"'}else{'/TASKS="windowsautorun"'}
    foreach($upgrade in @($false,$true)) {
      Pass ('original_Setup_'+$RuntimeMode+'_upgrade_'+$upgrade) {
        Invoke-Installer 'original-immutable-setup.exe' 'fixture' $upgrade
        if($script:invocation.path -cne 'original-immutable-setup.exe' -or
            @($script:invocation.arguments|Where-Object{$_ -like '/TASKS=*'}).Count -ne 1 -or
            $script:invocation.arguments -cnotcontains $taskArgument -or
            ($script:invocation.arguments -ccontains '/EDR_UPGRADE_EXISTING=1') -ne $upgrade -or
            -not $script:invocation.wait -or -not $script:invocation.pass_thru){throw 'original Setup task selection changed'}
      }
    }
    Pass ('repair_Setup_'+$RuntimeMode) {
      Invoke-BaselineRepair 'original-immutable-setup.exe' 'fixture' (Join-Path $root 'backup')
      if($script:invocation.arguments -cnotcontains $taskArgument -or
          $script:invocation.arguments -cnotcontains '/EDR_REPAIR_BASELINE=1' -or
          $script:invocation.arguments -cnotcontains '/EDR_KEEP_OFFLINE_QUEUE=1' -or
          $script:invocation.arguments -cnotcontains '/EDR_KEEP_EVIDENCE_CACHE=1'){throw 'repair task selection or preservation flags changed'}
    }
  }
  $RuntimeMode='service'
  Reject 'service_with_task_owner' '*unexpected scheduled-task owner*' {Get-LifecycleRuntimeOwner|Out-Null}
  $taskFixture=$script:task;$script:task=$null
  Pass 'service_owner_and_runtime_unchanged' {
    $owner=Get-LifecycleRuntimeOwner;$runtime=Get-LifecycleRuntimeProcess
    if($owner.mode -cne 'service' -or $owner.account -cne 'LocalSystem' -or $runtime.State -cne 'Running' -or $runtime.ProcessId -ne 123){throw 'service identity mismatch'}
  }
  Pass 'service_recovery_v1_owner_alias_compatible' {
    $snapshot=Get-RecoveryOwnerSnapshot
    if($snapshot.runtime_mode -cne 'service' -or $snapshot.service.path -cne $script:service.PathName -or
        $snapshot.service.account -cne 'LocalSystem' -or $snapshot.service.start_mode -cne 'Auto' -or
        $snapshot.service.Keys.Count -ne 3 -or $snapshot.uninstall.Count -ne 1){throw 'existing recovery service evidence changed'}
  }
  $script:service.ProcessId=999
  Reject 'service_process_mismatch' '*does not own*' {Get-LifecycleRuntimeProcess|Out-Null}
  $script:service.ProcessId=123
  $script:task=$taskFixture
  $RuntimeMode='scheduled_task'
  Reject 'task_with_service_owner' '*unexpected service owner*' {Get-LifecycleRuntimeOwner|Out-Null}
  Reject 'task_process_with_service_owner' '*unexpected service owner*' {Get-LifecycleRuntimeProcess|Out-Null}
  $script:service=$null
  Pass 'task_owner_and_runtime_from_original_launcher' {
    $owner=Get-LifecycleRuntimeOwner;$runtime=Get-LifecycleRuntimeProcess
    if($owner.mode -cne 'scheduled_task' -or $owner.sddl -cne $script:definition.sddl -or $runtime.State -cne 'Running' -or $runtime.ProcessId -ne 123){throw 'task identity mismatch'}
  }
  Pass 'task_recovery_owner_has_XML_and_SDDL' {
    $snapshot=Get-RecoveryOwnerSnapshot
    if($snapshot.Contains('service') -or $snapshot.runtime_mode -cne 'scheduled_task' -or
        $snapshot.runtime_owner.sddl -cne $script:definition.sddl -or -not $snapshot.runtime_owner.xml -or
        $snapshot.uninstall.Count -ne 1){throw 'task recovery owner missing identity'}
  }
  foreach($identity in @('SYSTEM','NT AUTHORITY\SYSTEM','S-1-5-18')) {
    $script:task.Principal.UserId=$identity
    Pass ('system_principal_'+$identity) {$null=Get-LifecycleRuntimeOwner}
  }
  $script:task.Principal.UserId='SYSTEM'
  foreach($entry in @(@($script:task,'TaskName','Other'),@($script:task,'TaskPath','\Other\'),@($script:task,'State','Ready'),
      @($script:task.Principal,'UserId','User'),@($script:task.Principal,'LogonType','InteractiveToken'),@($script:task.Principal,'RunLevel','Limited'),
      @($script:task.Actions[0],'Execute','C:\other\powershell.exe'),@($script:task.Actions[0],'Arguments','-File other.ps1'),
      @($script:task.Actions[0],'WorkingDirectory','C:\other'))) {
    $original=$entry[0].($entry[1]);$entry[0].($entry[1])=$entry[2]
    Reject ('task_invalid_'+$entry[1]) '*owner, principal or original launcher*' {Get-LifecycleRuntimeOwner|Out-Null}
    $entry[0].($entry[1])=$original
  }
  $originalXml=$script:definition.xml
  foreach($bad in @($originalXml.Replace('BootTrigger','TimeTrigger'),$originalXml.Replace('PT0S','PT72H'),$originalXml.Replace('IgnoreNew','Parallel'))) {
    $script:definition.xml=$bad
    Reject 'task_runtime_settings' '*startup, unlimited lifetime or security definition*' {Get-LifecycleRuntimeOwner|Out-Null}
  }
  $script:definition.xml=$originalXml
  $originalSddl=$script:definition.sddl;$script:definition.sddl=''
  Reject 'task_missing_security' '*startup, unlimited lifetime or security definition*' {Get-LifecycleRuntimeOwner|Out-Null}
  $script:definition.sddl=$originalSddl
  $script:processes+=@([pscustomobject]@{ExecutablePath='C:\unrelated\FDSensor.exe';ProcessId=987})
  Pass 'unrelated_process_is_excluded' {if((Get-LifecycleRuntimeProcess).ProcessId -ne 123){throw 'unrelated process selected'}}
  $script:processes+=@([pscustomobject]@{ExecutablePath=(Join-Path $InstallDir 'FDSensor.exe');ProcessId=124})
  Reject 'multiple_directory_processes' '*multiple Agent processes*' {Get-LifecycleRuntimeProcess|Out-Null}
  $script:processes=@($script:processes[1])
  Pass 'no_directory_process_never_claims_running_pid' {if((Get-LifecycleRuntimeProcess).ProcessId -ne 0){throw 'foreign runtime accepted'}}
  $snapshot=New-LifecyclePreservationSnapshot 'task-fixture'
  Pass 'task_config_XML_SDDL_and_marker_preservation' {Assert-LifecyclePreservationSnapshot $snapshot 'fixture'}
  $script:definition.xml=$originalXml.Replace('2026-01-01','2026-01-02')
  Pass 'registration_date_only_is_metadata' {Assert-LifecyclePreservationSnapshot $snapshot 'fixture'}
  $script:definition.xml=$originalXml.Replace('<Count>3</Count>','<Count>4</Count>')
  Reject 'task_XML_changed' '*scheduled_task deployment identity*' {Assert-LifecyclePreservationSnapshot $snapshot 'fixture'}
  $script:definition.xml=$originalXml;$script:definition.sddl+='(A;;FR;;;BA)'
  Reject 'task_SDDL_changed' '*scheduled_task deployment identity*' {Assert-LifecyclePreservationSnapshot $snapshot 'fixture'}
  $script:definition.sddl=$originalSddl
  [ordered]@{status='succeeded';case_count=$cases.Count;cases=$cases.ToArray();scope='AST harness owners with isolated task, service, process and Setup I/O; no actual Agent or task operation'}|ConvertTo-Json -Depth 5
} finally {
  foreach($name in @('Get-CimInstance','Get-ScheduledTask','Get-ItemProperty','Start-Process')) {
    if(Test-Path -LiteralPath ('Function:'+$name)){Remove-Item -LiteralPath ('Function:'+$name)}
  }
  Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction Stop
}
