#Requires -Version 5.1
[CmdletBinding()]
param([string]$RepoRoot=(Split-Path -Parent $PSScriptRoot))
# Only AST-extracted harness owners run. OS process/service/task/Setup boundaries
# are fixtures; this test never creates a task, installs software or touches an Agent.
$ErrorActionPreference='Stop'
$root=Join-Path ([IO.Path]::GetTempPath()) ('edr-lifecycle-mode-'+[Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($root)|Out-Null
$cases=New-Object 'System.Collections.Generic.List[string]'
$script:missingProcessError=$null
$script:repairSequence=$null
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
  foreach($name in @('Get-LifecycleAgentProcesses','Open-LifecycleAgentProcess',
      'Get-LifecycleUpdaterIdentity','Get-LifecycleStoragePreflight','Get-LifecycleRuntimeProcess','Get-LifecycleRuntimeOwner',
      'New-LifecyclePreservationSnapshot','Assert-LifecyclePreservationSnapshot','Invoke-Installer','Invoke-BaselineRepair',
      'Assert-BaselineRepair','New-BaselineRepairBackup')) {
    $owners=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name},$true))
    if ($owners.Count -ne 1) { throw ('missing unique harness owner '+$name) }
    . ([scriptblock]::Create($owners[0].Extent.Text))
  }
  $storage=[Management.Automation.Language.Parser]::ParseFile((Join-Path $RepoRoot 'tests/Invoke-LifecycleStorageCompatibility.ps1'),[ref]$tokens,[ref]$errors)
  if($errors.Count -ne 0){throw 'storage owner parse failed'}
  foreach($name in @('Get-LifecycleStorageNative','Assert-LifecycleStorageQuiescent','Invoke-LifecycleStorageRuntimeAction',
      'Invoke-LifecycleStorageProcess','Assert-LifecycleStorageRegular')) {
    $owners=@($storage.FindAll({param($node)$node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name},$true))
    if($owners.Count -ne 1){throw ('missing unique storage owner '+$name)}
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
    if($ClassName -ceq 'Win32_Process'){
      if($Filter -match '^ProcessId=([0-9]+)$') {
        $wanted=[uint32]$Matches[1]
        if($script:updaterRow -and $wanted -eq $script:updaterRow.ProcessId){return $script:updaterRow}
        return @($script:processes|Where-Object{$_.ProcessId -eq $wanted})
      }
      return $script:processes
    }
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
  Pass 'actual_host_missing_process_error_record_is_observable' {
    try {Microsoft.PowerShell.Management\Get-Process -Id 2147483647 -ErrorAction Stop|Out-Null} catch {
      $chain=@();$cause=$_.Exception
      for($depth=0;$cause -and $depth -lt 8;$depth++) {
        $chain+=@([ordered]@{type=$cause.GetType().FullName;native_error_code=$(if($cause -is [ComponentModel.Win32Exception]){$cause.NativeErrorCode}else{$null})})
        $cause=$cause.InnerException
      }
      $script:missingProcessError=[ordered]@{powershell_version=$PSVersionTable.PSVersion.ToString();
        type=$_.Exception.GetType().FullName;error_id=$_.FullyQualifiedErrorId;category=[string]$_.CategoryInfo.Category;exception_chain=$chain}
    }
    if(-not $script:missingProcessError -or $script:missingProcessError.category -cne 'ObjectNotFound'){throw 'native missing process error was not observed'}
  }
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
  # Real current-process identity is read only. Agent child handles and every
  # stop/kill boundary below are fixtures; no actual process is terminated.
  # The held-process fixture never invokes an OS API; Kill is a failure trap.
  if(-not ('EdrLifecycleFixtureProcess' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
public sealed class EdrLifecycleFixtureProcess {
    public int Id;
    public IntPtr Handle = new IntPtr(7);
    public string Path, mode;
    public DateTime StartTime;
    public bool HasExited, disposed, killed;
    public int wait_ms;
    public Action<int> OnWait;
    public void Dispose() { disposed = true; }
    public void Kill() {
        killed = true;
        throw new InvalidOperationException("PID-only kill must never be used");
    }
    public bool WaitForExit(int milliseconds) {
        wait_ms = milliseconds;
        if (mode == "wait-timeout") return false;
        if (OnWait != null) OnWait(Id);
        return HasExited;
    }
}
public sealed class EdrLifecycleFixtureChild {
    public IntPtr Handle = new IntPtr(8);
    public bool HasExited, disposed, killed, timeout;
    public int ExitCode, first_wait_ms;
    public bool WaitForExit(int milliseconds) {
        if (first_wait_ms == 0) first_wait_ms = milliseconds;
        if (timeout && !killed) return false;
        HasExited = true;
        return true;
    }
    public void WaitForExit() { }
    public void Kill() { killed = true; HasExited = true; }
    public void Dispose() { disposed = true; }
}
'@
  }
  $savedProcesses=$script:processes
  $updater=[Diagnostics.Process]::GetCurrentProcess()
  try {
    $null=$updater.Handle
    $script:updaterRow=[pscustomobject]@{ProcessId=$updater.Id;ExecutablePath=$updater.Path;CreationDate=$updater.StartTime}
    $childTime=$updater.StartTime.AddSeconds(1)
    $image=Join-Path $InstallDir 'FDSensor.exe';$config=Join-Path $InstallDir 'agent.toml'
    $output=Join-Path (Join-Path $InstallDir ('.storage-preflight-'+('a'*32))) 'floor'
    $probeCommand='"'+$image+'" --storage-space-preflight --config "'+$config+'" --output "'+$output+'"'
    $runtimeRow=[pscustomobject]@{ExecutablePath=$image;ProcessId=123;ParentProcessId=700;CreationDate=$childTime;CommandLine='runtime fixture'}
    $probeRow=[pscustomobject]@{ExecutablePath=$image;ProcessId=124;ParentProcessId=$updater.Id;CreationDate=$childTime;CommandLine=$probeCommand}
    $script:handleMode='live';$script:lastHandle=$null
    function Get-Process {
      [CmdletBinding()]param([int]$Id)
      if($null -ne $script:repairSequence){$script:repairSequence.Add('open')}
      if($script:handleMode -ceq 'access-denied'){throw [ComponentModel.Win32Exception]::new(5,'fixture_access_denied')}
      if($script:handleMode -ceq 'wrong-missing-error'){throw [ArgumentException]::new('fixture_wrong_missing_error')}
      if($script:handleMode -cin @('missing','missing-still-present')) {
        if($script:handleMode -ceq 'missing'){$script:processes=@($script:processes|Where-Object{$_.ProcessId -ne $Id})}
        # An impossible Windows PID obtains the real cmdlet's exact error type
        # and ErrorId, without opening or operating any actual Agent process.
        Microsoft.PowerShell.Management\Get-Process -Id 2147483647 -ErrorAction Stop
      }
      $row=@($script:processes|Where-Object{$_.ProcessId -eq $Id})[0]
      $h=New-Object EdrLifecycleFixtureProcess
      $h.Id=$Id;$h.Path=$row.ExecutablePath;$h.StartTime=$row.CreationDate
      $h.HasExited=($script:handleMode -ceq 'exited');$h.mode=$script:handleMode
      if($h.mode -ceq 'reused'){$h.StartTime=$h.StartTime.AddSeconds(1)}
      if($h.mode -ceq 'image-changed'){$h.Path='C:\outside\FDSensor.exe'}
      if($h.HasExited){$script:processes=@($script:processes|Where-Object{$_.ProcessId -ne $Id})}
      $script:lastHandle=$h;return $h
    }
    function Stop-Process {throw 'PID-only stop must never be used'}
    $script:processes=@($runtimeRow,$probeRow)
    Reject 'default_still_counts_preflight' '*multiple Agent processes*' {Get-LifecycleRuntimeProcess|Out-Null}
    Pass 'owned_updater_preflight_is_separate_from_runtime' {
      $state=Get-LifecycleRuntimeProcess -UpdaterProcess $updater
      if($state.ProcessId -ne 123 -or @($state.StoragePreflightProcesses).Count -ne 1 -or
          $state.StoragePreflightProcesses[0].observation -cne 'live' -or
          $state.StoragePreflightProcesses[0].parent_pid -ne $updater.Id -or
          $state.StoragePreflightProcesses[0].output -cne $output -or -not $script:lastHandle.disposed -or $updater.HasExited){throw 'probe identity or handle ownership changed'}
    }
    $script:processes=@($probeRow)
    Pass 'probe_alone_never_claims_runtime_pid' {if((Get-LifecycleRuntimeProcess -UpdaterProcess $updater).ProcessId -ne 0){throw 'probe became runtime'}}
    $script:processes=@($runtimeRow,$probeRow);$script:handleMode='missing'
    Pass 'verified_probe_naturally_exits_before_handle_open' {
      $state=Get-LifecycleRuntimeProcess -UpdaterProcess $updater
      if($state.ProcessId -ne 123 -or $state.StoragePreflightProcesses[0].observation -cne 'observed_then_exited'){throw 'exited probe was not retained as observation'}
    }
    $script:processes=@($runtimeRow,$probeRow);$script:handleMode='exited'
    Pass 'verified_probe_exited_held_handle_is_disposed' {
      $state=Get-LifecycleRuntimeProcess -UpdaterProcess $updater
      if($state.ProcessId -ne 123 -or $state.StoragePreflightProcesses[0].observation -cne 'observed_then_exited' -or -not $script:lastHandle.disposed){throw 'exited held probe was not safely released'}
    }
    $script:processes=@($runtimeRow,$probeRow)
    $script:handleMode='live'
    foreach($bad in @('',($probeCommand+' --extra'),$probeCommand.Replace('--storage-space-preflight','--storage-space-preflight-other'),
        $probeCommand.Replace('agent.toml','other.toml'),$probeCommand.Replace('.storage-preflight-','.other-'),
        $probeCommand.Replace(('a'*32),('a'*31)),$probeCommand.Replace('\floor"','\other"'),
        $probeCommand.Replace($InstallDir,'C:\outside'))) {
      $probeRow.CommandLine=$bad;$script:processes=@($runtimeRow,$probeRow)
      Reject 'unknown_or_inexact_command_is_not_ignored' '*multiple Agent processes*' {Get-LifecycleRuntimeProcess -UpdaterProcess $updater|Out-Null}
    }
    $probeRow.CommandLine=$probeCommand;$probeRow.ParentProcessId=$updater.Id+4
    Reject 'probe_wrong_parent' '*parent generation is unverified*' {Get-LifecycleRuntimeProcess -UpdaterProcess $updater|Out-Null}
    $probeRow.ParentProcessId=$updater.Id;$probeRow.CreationDate=$updater.StartTime.AddSeconds(-1)
    Reject 'probe_predates_updater' '*parent generation is unverified*' {Get-LifecycleRuntimeProcess -UpdaterProcess $updater|Out-Null}
    $probeRow.CreationDate=$childTime;$script:updaterRow.CreationDate=$updater.StartTime.AddSeconds(1)
    Reject 'updater_parent_PID_reused' '*parent generation is unverified*' {Get-LifecycleRuntimeProcess -UpdaterProcess $updater|Out-Null}
    $script:updaterRow.CreationDate=$updater.StartTime
    Reject 'fake_updater_handle' '*owned updater Process*' {Get-LifecycleRuntimeProcess -UpdaterProcess ([pscustomobject]@{Id=$updater.Id})|Out-Null}
    $script:handleMode='reused'
    Reject 'probe_child_PID_reused' '*generation or image changed*' {Get-LifecycleRuntimeProcess -UpdaterProcess $updater|Out-Null}
    $script:handleMode='access-denied'
    Reject 'probe_handle_access_denied_is_fatal' '*fixture_access_denied*' {Get-LifecycleRuntimeProcess -UpdaterProcess $updater|Out-Null}
    $script:handleMode='image-changed'
    Reject 'probe_handle_image_changed_is_fatal' '*generation or image changed*' {Get-LifecycleRuntimeProcess -UpdaterProcess $updater|Out-Null}
    $script:handleMode='live';$probeRow.CommandLine='second genuine runtime'
    Pass 'two_runtimes_rejected_with_bounded_identity_diagnostic' {
      try {Get-LifecycleRuntimeProcess -UpdaterProcess $updater|Out-Null;throw 'unexpected acceptance'} catch {
        if($_.Exception.Message -notlike '*multiple Agent processes*'){throw}
        $detail=[string]$_.Exception.Data['lifecycle_process_snapshot']
        $parsed=if($detail){$detail|ConvertFrom-Json}else{$null}
        $overbroad=$detail -match 'CommandLine|second genuine runtime'
        if(-not $detail -or $overbroad -or @($parsed).Count -ne 2){
          throw ('ambiguous runtime evidence missing or overbroad: present='+[bool]$detail+' parsed_count='+@($parsed).Count+' overbroad='+$overbroad+' exception_type='+$_.Exception.GetType().FullName)
        }
      }
    }
    foreach($mode in @('access-denied','wrong-missing-error','missing-still-present')) {
      $script:handleMode=$mode;$script:processes=@($runtimeRow)
      Pass ('process_open_failure_keeps_original_error_and_bounded_diagnostic_'+$mode) {
        $failure=$null
        try {Open-LifecycleAgentProcess $runtimeRow|Out-Null}catch{$failure=$_}
        if(-not $failure){throw 'process open failure unexpectedly accepted'}
        $json=[string]$failure.Exception.Data['lifecycle_process_open_failure']
        $detail=$json|ConvertFrom-Json
        $isMissing=$mode -ceq 'missing-still-present'
        if(-not $json -or [Text.Encoding]::UTF8.GetByteCount($json) -gt 8192 -or
            $detail.schema -cne 'edr.test.lifecycle-process-open-failure.v1' -or $detail.pid -ne $runtimeRow.ProcessId -or
            $detail.error_id -cne $failure.FullyQualifiedErrorId -or
            $detail.exception_chain[0].type -cne $failure.Exception.GetType().FullName -or
            $detail.missing -ne $isMissing -or $detail.cim_recheck_attempted -ne $isMissing -or
            $detail.cim_recheck_completed -ne $isMissing -or @($detail.exception_chain).Count -gt 8 -or
            $json -match 'CommandLine|runtime fixture') {throw 'process open diagnostic lost identity or exposed extra fields'}
        if($isMissing) {
          if($detail.cim_recheck_count -ne 1 -or @($detail.cim_rows).Count -ne 1 -or
              $detail.cim_rows[0].pid -ne $runtimeRow.ProcessId -or $detail.cim_rows[0].path -cne $runtimeRow.ExecutablePath){throw 'process recheck evidence changed'}
          if($failure.Exception.Message -notlike '*2147483647*'){throw 'original missing process error changed'}
        } elseif($mode -ceq 'access-denied') {
          if($failure.Exception.Message -cne 'fixture_access_denied' -or @($detail.exception_chain|Where-Object{$_.native_error_code -eq 5}).Count -ne 1){throw 'access denial was masked'}
        } elseif($failure.Exception.Message -cne 'fixture_wrong_missing_error'){throw 'unknown process error was masked'}
      }
    }
  } finally {$updater.Dispose();$script:updaterRow=$null;$script:processes=$savedProcesses}
  $snapshot=New-LifecyclePreservationSnapshot 'task-fixture'
  Pass 'task_config_XML_SDDL_and_marker_preservation' {Assert-LifecyclePreservationSnapshot $snapshot 'fixture'}
  $script:definition.xml=$originalXml.Replace('2026-01-01','2026-01-02')
  Pass 'registration_date_only_is_metadata' {Assert-LifecyclePreservationSnapshot $snapshot 'fixture'}
  $script:definition.xml=$originalXml.Replace('<Count>3</Count>','<Count>4</Count>')
  Reject 'task_XML_changed' '*scheduled_task deployment identity*' {Assert-LifecyclePreservationSnapshot $snapshot 'fixture'}
  $script:definition.xml=$originalXml;$script:definition.sddl+='(A;;FR;;;BA)'
  Reject 'task_SDDL_changed' '*scheduled_task deployment identity*' {Assert-LifecyclePreservationSnapshot $snapshot 'fixture'}
  $script:definition.sddl=$originalSddl
  # Actual hosted task definitions from run 41689201966: only a redundant
  # RegistrationInfo/SecurityDescriptor appeared. These contain isolated test
  # paths and a disposable host group SID, with no credentials or tenant data.
  $observedBefore=@'
<?xml version="1.0" encoding="UTF-16"?><Task version="1.3" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><RegistrationInfo><URI>\FDSecurityAgent</URI></RegistrationInfo><Principals><Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals><Settings><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><ExecutionTimeLimit>PT0S</ExecutionTimeLimit><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><RestartOnFailure><Count>3</Count><Interval>PT1M</Interval></RestartOnFailure><StartWhenAvailable>true</StartWhenAvailable><IdleSettings><Duration>PT10M</Duration><WaitTimeout>PT1H</WaitTimeout><StopOnIdleEnd>true</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings><UseUnifiedSchedulingEngine>true</UseUnifiedSchedulingEngine></Settings><Triggers><BootTrigger /></Triggers><Actions Context="Author"><Exec><Command>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Command><Arguments>-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "C:\edr-agent-setup-lifecycle-smoke\FDSensorTaskLaunch.ps1"</Arguments><WorkingDirectory>C:\edr-agent-setup-lifecycle-smoke</WorkingDirectory></Exec></Actions></Task>
'@
  $observedAfter=@'
<?xml version="1.0" encoding="UTF-16"?><Task version="1.3" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><RegistrationInfo><SecurityDescriptor>O:BAG:S-1-5-21-3977851545-3833041388-3993362562-513D:(A;ID;0x1f019f;;;BA)(A;ID;0x1f019f;;;SY)(A;ID;FA;;;BA)(A;;FR;;;SY)</SecurityDescriptor><URI>\FDSecurityAgent</URI></RegistrationInfo><Principals><Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals><Settings><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><ExecutionTimeLimit>PT0S</ExecutionTimeLimit><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><RestartOnFailure><Count>3</Count><Interval>PT1M</Interval></RestartOnFailure><StartWhenAvailable>true</StartWhenAvailable><IdleSettings><Duration>PT10M</Duration><WaitTimeout>PT1H</WaitTimeout><StopOnIdleEnd>true</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings><UseUnifiedSchedulingEngine>true</UseUnifiedSchedulingEngine></Settings><Triggers><BootTrigger /></Triggers><Actions Context="Author"><Exec><Command>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Command><Arguments>-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "C:\edr-agent-setup-lifecycle-smoke\FDSensorTaskLaunch.ps1"</Arguments><WorkingDirectory>C:\edr-agent-setup-lifecycle-smoke</WorkingDirectory></Exec></Actions></Task>
'@
  $observedSddl='O:BAG:S-1-5-21-3977851545-3833041388-3993362562-513D:(A;ID;0x1f019f;;;BA)(A;ID;0x1f019f;;;SY)(A;ID;FA;;;BA)(A;;FR;;;SY)'
  $script:definition.xml=$observedBefore;$script:definition.sddl=$observedSddl
  $observedOwner=Get-LifecycleRuntimeOwner
  $observedPreservation=[pscustomobject]@{config_sha256=$snapshot.config_sha256;deployment_mode=$RuntimeMode;runtime_owner=$observedOwner;markers=$snapshot.markers}
  $observedRecovery=Get-RecoveryOwnerSnapshot|ConvertTo-Json -Depth 8 -Compress
  $script:definition.xml=$observedAfter
  Pass 'actual_rollback_inline_security_descriptor_is_redundant' {
    Assert-LifecyclePreservationSnapshot $observedPreservation 'observed'
    if((Get-RecoveryOwnerSnapshot|ConvertTo-Json -Depth 8 -Compress) -cne $observedRecovery -or
        (Get-LifecycleRuntimeOwner).sddl -cne $observedSddl){throw 'actual recovery owner or permissions changed'}
  }
  $inline='<SecurityDescriptor>'+$observedSddl+'</SecurityDescriptor>'
  foreach($bad in @(
      $observedAfter.Replace($inline,('<SecurityDescriptor>'+$observedSddl+'(A;;FR;;;BA)</SecurityDescriptor>')),
      $observedAfter.Replace($inline,('<SecurityDescriptor><Value>'+$observedSddl+'</Value></SecurityDescriptor>')),
      $observedAfter.Replace('<SecurityDescriptor>','<SecurityDescriptor ignored="true">'),
      $observedAfter.Replace($inline,('<SecurityDescriptor>'+$observedSddl+'<!-- extra --></SecurityDescriptor>')),
      $observedAfter.Replace($inline,('<SecurityDescriptor><![CDATA['+$observedSddl+']]></SecurityDescriptor>'))
    )) {
    $script:definition.xml=$bad
    Reject 'inline_security_must_be_exact_simple_text' '*inline security descriptor differs from actual permissions or is not simple text*' {Get-LifecycleRuntimeOwner|Out-Null}
  }
  $script:definition.xml=$observedAfter.Replace($inline,($inline+$inline))
  Reject 'inline_security_must_be_unique' '*inline security descriptor must be unique*' {Get-LifecycleRuntimeOwner|Out-Null}
  $script:definition.xml=$observedAfter.Replace($inline,('<Wrapper>'+$inline+'</Wrapper>'))
  Reject 'non_direct_inline_security_is_not_removed' '*scheduled_task deployment identity*' {Assert-LifecyclePreservationSnapshot $observedPreservation 'observed'}
  foreach($changed in @(
      $observedSddl.Replace('O:BA','O:SY'),
      $observedSddl.Replace('G:S-1-5-21-3977851545-3833041388-3993362562-513','G:SY'),
      $observedSddl.Replace('(A;;FR;;;SY)','(A;;FR;;;BA)'),
      $observedSddl.Replace('(A;;FR;;;SY)','(A;;FA;;;SY)'),
      $observedSddl.Replace('(A;ID;0x1f019f;;;BA)','(A;;0x1f019f;;;BA)'),
      $observedSddl.Replace('D:','D:P'),
      $observedSddl.Replace('D:','D:AI'),
      $observedSddl.Replace('(A;ID;0x1f019f;;;BA)(A;ID;0x1f019f;;;SY)','(A;ID;0x1f019f;;;SY)(A;ID;0x1f019f;;;BA)')
    )) {
    $script:definition.sddl=$changed;$script:definition.xml=$observedAfter.Replace($observedSddl,$changed)
    Reject 'actual_security_change_still_rejected' '*scheduled_task deployment identity*' {Assert-LifecyclePreservationSnapshot $observedPreservation 'observed'}
  }
  $script:definition.sddl=$observedSddl
  foreach($bad in @($observedAfter.Replace('<Count>3</Count>','<Count>4</Count>'),
      $observedAfter.Replace('FDSensorTaskLaunch.ps1','OtherTaskLaunch.ps1'),
      $observedAfter.Replace('<URI>\FDSecurityAgent</URI>','<URI>\OtherTask</URI>'))) {
    $script:definition.xml=$bad
    Reject 'remaining_observed_XML_stays_exact' '*scheduled_task deployment identity*' {Assert-LifecyclePreservationSnapshot $observedPreservation 'observed'}
  }
  $script:definition.xml=$originalXml;$script:definition.sddl=$originalSddl
  # Exercise the actual repair orchestration and storage stop/identity owners.
  # Only OS process I/O and final Setup/installed-runtime verification are fakes.
  $BaselineVersion='3.2.738'
  function Reset-RepairFixture([string]$Case) {
    $script:repairCase=$Case;$script:repairSequence=New-Object 'System.Collections.Generic.List[string]'
    $script:lastHandle=$null;$script:controlChild=$null
    $script:handleMode=if($Case -ceq 'runtime-timeout'){'wait-timeout'}elseif($Case -ceq 'reused'){'reused'}else{'live'}
    $script:repairRow=[pscustomobject]@{ExecutablePath=$image;ProcessId=123;CreationDate=$childTime;CommandLine=('"'+$image+'" --config "'+$config+'"')}
    if($Case -ceq 'foreign-config'){$script:repairRow.CommandLine=$script:repairRow.CommandLine.Replace('agent.toml','other.toml')}
    $script:processes=@($script:repairRow)
    $script:service=if($RuntimeMode -ceq 'service'){[pscustomobject]@{State='Running';PathName=$image;StartName='LocalSystem';StartMode='Auto';ProcessId=123}}else{$null}
    $taskFixture.State='Running';$taskFixture.Principal.UserId='SYSTEM'
    $script:task=if($RuntimeMode -ceq 'scheduled_task'){$taskFixture}else{$null}
    if($Case -ceq 'unknown-owner'){if($script:service){$script:service.State='Stopped'}else{$script:task.Principal.UserId='User'}}
    foreach($name in @('FDSensor.exe','unins000.exe','unins000.dat')){Put (Join-Path $InstallDir $name) ('fixture-'+$name)}
  }
  function Get-Service {[CmdletBinding()]param($Name);if($Name -cne $ServiceName){throw 'unexpected repair service'};return [pscustomobject]@{Status=$script:service.State}}
  function Stop-Service {throw 'repair must use the bounded original owner process'}
  function Stop-ScheduledTask {throw 'repair must use the bounded original owner process'}
  function Start-Process {
    [CmdletBinding()]param($FilePath,[string[]]$ArgumentList,[switch]$Wait,[switch]$PassThru,$RedirectStandardOutput,$RedirectStandardError)
    if($RedirectStandardOutput) {
      $body=[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($ArgumentList[-1].Trim('"')))
      $expected=if($RuntimeMode -ceq 'service'){'Stop-Service -InputObject $service -ErrorAction Stop'}else{"Stop-ScheduledTask -TaskName 'FixtureService' -TaskPath '\' -ErrorAction Stop"}
      if($FilePath -ine (Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe') -or -not $PassThru -or $Wait -or
          -not $body.Contains($expected) -or -not $script:lastHandle -or $script:lastHandle.disposed -or $script:lastHandle.HasExited -or
          ($script:repairSequence -join ',') -cne 'open'){throw 'owner stop occurred before the original handle was bound'}
      $script:repairSequence.Add('stop')
      [IO.File]::WriteAllText($RedirectStandardOutput,'{"status":"completed"}')
      [IO.File]::WriteAllText($RedirectStandardError,'fixture_owner_stop_failure')
      $script:controlChild=New-Object EdrLifecycleFixtureChild
      if($script:repairCase -ceq 'owner-stop-failure'){$script:controlChild.ExitCode=7;return $script:controlChild}
      if($script:repairCase -ceq 'owner-timeout'){$script:controlChild.timeout=$true;return $script:controlChild}
      if($script:repairCase -cne 'owner-running'){if($script:service){$script:service.State='Stopped'}else{$script:task.State='Ready'}}
      $script:lastHandle.HasExited=$script:repairCase -cne 'runtime-timeout'
      $script:lastHandle.OnWait=[Action[int]]{
        param([int]$OwnedId)
        $script:repairSequence.Add('wait')
        if($script:repairCase -ceq 'writer-remains'){return}
        $script:processes=if($script:repairCase -ceq 'unknown-writer'){@([pscustomobject]@{ProcessId=$OwnedId;ExecutablePath=$null})}else{@()}
      }
      return $script:controlChild
    }
    if($FilePath -cne 'original-immutable-setup.exe' -or ($script:repairSequence -join ',') -cne 'open,stop,wait' -or
        -not $script:lastHandle.disposed -or (Test-Path -LiteralPath (Join-Path $InstallDir 'unins000.exe')) -or
        (Test-Path -LiteralPath (Join-Path $InstallDir 'unins000.dat')) -or
        [IO.File]::ReadAllText((Join-Path $EvidenceDir 'repair-baseline-backup/agent.toml')) -cne 'isolated configuration') {throw 'repair setup started before quiescence and authorized backup'}
    $script:repairSequence.Add('setup')
    foreach($name in @('unins000.exe','unins000.dat')){Put (Join-Path $InstallDir $name) ('restored-'+$name)}
    if($script:service){$script:service.State='Running'}else{$script:task.State='Running'}
    $script:processes=@($script:repairRow)
    return [pscustomobject]@{ExitCode=0}
  }
  function Assert-InstalledRuntime {
    param($ExpectedVersion,$Stage)
    if($ExpectedVersion -cne $BaselineVersion -or $Stage -cne 'repair-baseline' -or [IO.File]::ReadAllText((Join-Path $InstallDir 'unins000.exe')) -cne 'restored-unins000.exe'){throw 'wrong repair result'}
    $null=Get-LifecycleRuntimeOwner
  }
  foreach($RuntimeMode in @('service','scheduled_task')) {
    $EvidenceDir=Join-Path $root ('repair-'+$RuntimeMode+'-success');[IO.Directory]::CreateDirectory($EvidenceDir)|Out-Null
    Reset-RepairFixture 'success'
    Pass ($RuntimeMode+'_repair_binds_before_bounded_owner_stop_and_reuses_held_process') {
      Assert-BaselineRepair 'original-immutable-setup.exe'
      if(($script:repairSequence -join ',') -cne 'open,stop,wait,setup' -or $script:lastHandle.wait_ms -ne 30000 -or
          -not $script:lastHandle.disposed -or $script:lastHandle.killed -or $script:controlChild.first_wait_ms -ne 35000 -or
          -not $script:controlChild.disposed -or $script:controlChild.killed){throw 'repair lost the original finite stop boundary'}
    }
    foreach($entry in @(@('unknown-owner',$(if($RuntimeMode -ceq 'service'){'*running lifecycle service*'}else{'*owner, principal or original launcher*'})),
        @('foreign-config','*config/process binding mismatch*'),@('reused','*config/process binding mismatch*'),
        @('owner-stop-failure','*exit=7 cause=fixture_owner_stop_failure*'),@('owner-timeout','*finite deadline*'),
        @('runtime-timeout','*before baseline repair within 30 seconds*'),@('writer-remains','*writer remains or its path is unknown*'),
        @('unknown-writer','*writer remains or its path is unknown*'),@('owner-running','*is not stopped*'))) {
      $EvidenceDir=Join-Path $root ('repair-'+$RuntimeMode+'-'+$entry[0]);[IO.Directory]::CreateDirectory($EvidenceDir)|Out-Null
      Reset-RepairFixture $entry[0]
      Reject ($RuntimeMode+'_repair_rejects_'+$entry[0]) $entry[1] {Assert-BaselineRepair 'original-immutable-setup.exe'}
      Pass ($RuntimeMode+'_repair_failure_preserves_installer_files_'+$entry[0]) {
        if($script:repairSequence -ccontains 'setup' -or (Test-Path -LiteralPath (Join-Path $EvidenceDir 'repair-baseline-backup')) -or
            [IO.File]::ReadAllText((Join-Path $InstallDir 'agent.toml')) -cne 'isolated configuration'){throw 'failed stop mutated repair inputs'}
        foreach($name in @('unins000.exe','unins000.dat')){if([IO.File]::ReadAllText((Join-Path $InstallDir $name)) -cne ('fixture-'+$name)){throw 'failed stop removed installer files'}}
        if($script:lastHandle -and (-not $script:lastHandle.disposed -or $script:lastHandle.killed)){throw 'repair leaked or killed Agent handle'}
        if($script:controlChild -and (-not $script:controlChild.disposed -or $script:controlChild.first_wait_ms -ne 35000 -or
            $script:controlChild.killed -ne ($entry[0] -ceq 'owner-timeout'))){throw 'repair control child exceeded its original boundary'}
      }
    }
  }
  [ordered]@{status='succeeded';case_count=$cases.Count;cases=$cases.ToArray();missing_process_error=$script:missingProcessError;scope='AST harness owners with isolated task, service, process and Setup I/O; no actual Agent or task operation'}|ConvertTo-Json -Depth 5
} catch {
  if($script:missingProcessError){Write-Warning ('native_missing_process_error='+($script:missingProcessError|ConvertTo-Json -Depth 5 -Compress))}
  throw
} finally {
  foreach($name in @('Get-CimInstance','Get-ScheduledTask','Get-ItemProperty','Start-Process','Get-Process','Stop-Process','Get-Service','Stop-Service','Stop-ScheduledTask')) {
    if(Test-Path -LiteralPath ('Function:'+$name)){Remove-Item -LiteralPath ('Function:'+$name)}
  }
  Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction Stop
}
