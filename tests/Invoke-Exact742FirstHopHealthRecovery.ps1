#Requires -Version 5.1
# Disposable hosted ARM only. The original CAE updater owns all runtime recovery.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$FirstHopInput,[Parameter(Mandatory=$true)][string]$FirstHopInputSha256,[Parameter(Mandatory=$true)][string]$EvidenceDir)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Exact742FirstHopRecovery.Common.ps1')
. Import-Exact742TestDefinitions
$InstallDir='C:\Program Files\FDSecurity';$RuntimeMode='scheduled_task';$ServiceName='FDSecurityAgent';$Architecture='arm64'
$EvidenceDir=[IO.Path]::GetFullPath($EvidenceDir)
if(Test-Path -LiteralPath $EvidenceDir){throw 'Fresh exact first-hop evidence directory required'}
New-Item -ItemType Directory $EvidenceDir|Out-Null
$request=Read-Exact742BoundJson $FirstHopInput $FirstHopInputSha256
$source=Read-Exact742BoundJson $request.source_consumer_receipt_path $request.source_consumer_receipt_sha256
$target=Read-Exact742BoundJson $request.target_release_binding_path $request.target_release_binding_sha256
Assert-Exact742FirstHopBinding $request $source $target
$qualification=Read-Exact742BoundJson $request.qualification_input_path $request.qualification_input_sha256
Assert-Exact742FileBindings $qualification
$principal=[Security.Principal.WindowsIdentity]::GetCurrent()
if(-not ([Security.Principal.WindowsPrincipal]::new($principal)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Original updater requires an elevated controller'}
$beforeOwner=Get-LifecycleRuntimeOwner
if(($beforeOwner|ConvertTo-Json -Depth 8 -Compress) -cne ($source.task_owner|ConvertTo-Json -Depth 8 -Compress)){throw 'Source task changed after qualification'}
$beforeRegistry=@(Get-Exact742RegistryState)
Assert-Exact742RegistryRestored @($source.uninstall) $beforeRegistry
$files=[ordered]@{}
foreach($name in @('FDSensor.exe','edr_agent_inplace_update.ps1','FDSensorTaskLaunch.ps1','native-package-integrity.json','agent.toml','VERSION','unins000.exe','unins000.dat')){
 $path=Join-Path $InstallDir $name;$null=Assert-LifecycleStorageRegular $path
 $files[$name]=(Get-FileHash $path).Hash.ToLowerInvariant()
}
Assert-Exact742ProgramHash (Join-Path $InstallDir 'FDSensor.exe') $source.consumer_identity.agent_sha256
Assert-Exact742ProgramHash $request.source_updater_path $source.consumer_identity.updater_sha256
Assert-Exact742ProgramHash (Join-Path $InstallDir 'FDSensorTaskLaunch.ps1') $source.consumer_identity.launcher_sha256
Assert-Exact742Integrity $InstallDir $source.consumer_identity.native_integrity_sha256
if($files['agent.toml'] -cne $source.config_sha256){throw 'Source synthetic configuration changed'}
$native=[IO.File]::ReadAllText((Join-Path $InstallDir 'native-package-integrity.json'))|ConvertFrom-Json
foreach($entry in $native.files){$files[$entry.name]=$entry.sha256}
$publisher=Get-LifecycleTrustedPublisher $target
Assert-LifecyclePublisherProtocol $request.source_updater_path $source.consumer_identity.updater_sha256 $publisher
$nativeFloor=Read-Exact742NativeFloor $EvidenceDir
$effectiveFloor=[Math]::Max([UInt64]2147483648,[Math]::Max([UInt64]$target.min_free_bytes,[UInt64]$nativeFloor.floor_bytes))
if((Get-PSDrive C).Free -lt $effectiveFloor){throw 'Actual native/manifest/2GiB storage floor is unavailable'}
$commandId=[Guid]::NewGuid().ToString('D')
$stage=Join-Path (Join-Path ([IO.Path]::GetTempPath()) 'FDSecurity\agent-update') $commandId
if(Test-Path $stage){throw 'Fresh command staging required'}
New-Item -ItemType Directory $stage -Force|Out-Null
$acl=New-Object Security.AccessControl.DirectorySecurity;$acl.SetAccessRuleProtection($true,$false)
foreach($sid in @('S-1-5-18','S-1-5-32-544')){$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))};Set-Acl $stage $acl
$binary=Join-Path $stage 'FDSensor.next.exe';$package=Join-Path $stage 'full-installer.zip'
Copy-Item -LiteralPath $target.binary_path -Destination $binary
Copy-Item -LiteralPath $target.runtime_package -Destination $package
$null=Assert-LifecycleStorageRegular $binary;$null=Assert-LifecycleStorageRegular $package
if((Get-FileHash $binary).Hash.ToLowerInvariant() -cne $target.binary_sha256 -or (Get-FileHash $package).Hash.ToLowerInvariant() -cne $target.runtime_package_sha256){throw 'First-hop immutable target staging changed'}
$parameters=[ordered]@{InstallDir=$InstallDir;StagedBinary=$binary;ExpectedSha256=$target.binary_sha256;TargetVersion='3.2.747';ExpectedArchitecture='arm64';ExpectedInternalName='FDSensor';TrustedPublisherThumbprint=$publisher.Thumbprint;TrustedPublisherSubject=$publisher.Subject;TrustedPublisherSubjectDerSha256=$publisher.SubjectDerSha256;DeploymentMode='scheduled_task';ScheduledTaskName='FDSecurityAgent';ScheduledTaskPath='\';ServiceName=$ServiceName;CommandId=$commandId;TaskId=$commandId;ArtifactId=('ci-exact742-health-'+$commandId);Operation='upgrade';UpgradeClass='installer_required';HealthObserveMs=30000;StartupTimeoutSeconds=60;MinFreeBytes=$effectiveFloor;RuntimeManifest=$package;RuntimeManifestSha256=$target.runtime_package_sha256;StagingDirectory=$stage}
# Both issue/deadline arguments are absent: preserve original defaults and 300000ms installer budget.
$entries=@($parameters.GetEnumerator()|ForEach-Object{"'{0}'='{1}'" -f $_.Key,([string]$_.Value).Replace("'","''")})
$code="`$ErrorActionPreference='Stop';`$p=@{"+($entries -join ';')+"};& '"+$request.source_updater_path.Replace("'","''")+"' @p;`$ok=`$?;if(`$ok){exit 0};if((Test-Path variable:LASTEXITCODE)-and `$LASTEXITCODE -is [int]-and `$LASTEXITCODE -ne 0){exit `$LASTEXITCODE};exit 1"
$encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($code))
$journalPath=Join-Path $env:ProgramData ('FDSecurity\state\agent-update-'+$commandId+'.journal.json')
$reportPath=Join-Path $env:ProgramData ('FDSecurity\logs\agent-update-'+$commandId+'-report.json')
$process=$null;$setupProcess=$null;$oldRuntime=[IntPtr]::Zero;$targetRuntime=[IntPtr]::Zero;$rootHandle=[IntPtr]::Zero;$job=[IntPtr]::Zero;$first=$null
$result=[ordered]@{schema='edr.exact742.late-health-recovery.v1';started_utc=[DateTime]::UtcNow.ToString('o');command_id=$commandId;controller_principal=$principal.Name;controller_sid=$principal.User.Value;controller_temp_path=[IO.Path]::GetTempPath();controller_scope='Inline recovery under actual CI elevated principal/TempPath; Agent task is SYSTEM. Does not prove SYSTEM/SystemTemp or startup-task recovery or original-volume disk pressure';stage=$stage;native_floor=$nativeFloor;manifest_min_free_bytes=$target.min_free_bytes;effective_min_free_bytes=$effectiveFloor;source_cli_sha256=$source.consumer_identity.updater_sha256;target_version='3.2.747';expected_recovery='3.2.742';installer_budget_ms=300000;observer_limit_ms=600000;budget_note='Not a 300000ms whole-process claim; original recovery and drain bounds unchanged';protected_files=$files;owner_before=$beforeOwner;fault_injected=$false;case_passed=$false;full_gate=$false;full_gate_passed=$false;deployment_authorized=$false;first_failure=$null;cleanup_failure=$null;registry_before=$beforeRegistry;registry_after=$null;source_report_first_error=$null;data_scope='No queue/cache readability or ACK proof; no full Setup downgrade'}
try{
 $old=Get-LifecycleRuntimeProcess
 if($old.State -cne 'Running' -or $old.ProcessId -le 0){throw 'Exact742 runtime is not running'}
 $oldRuntime=[LifecycleInstallerFault]::Open([uint32]$old.ProcessId,$false)
 $result.source_generation=@{pid=$old.ProcessId;birth=[LifecycleInstallerFault]::Created($oldRuntime)}
 # Recheck all immutable inputs and actual source immediately before launch.
 $null=Read-Exact742BoundJson $FirstHopInput $FirstHopInputSha256
 Assert-Exact742ProgramHash $request.source_updater_path $source.consumer_identity.updater_sha256
 Assert-RecoveryFiles $files
 $process=Start-LifecycleWindowsPowerShell -EncodedCommand $encoded -StandardOutput (Join-Path $EvidenceDir 'updater.stdout.log') -StandardError (Join-Path $EvidenceDir 'updater.stderr.log')
 $null=$process.Handle;$clock=[Diagnostics.Stopwatch]::StartNew()
 $result.updater_generation=@{pid=$process.Id;birth=$process.StartTime.ToFileTimeUtc()}
 while(!$process.HasExited -and $clock.ElapsedMilliseconds -lt 600000){
  $logBytes=[long]0;foreach($name in @('updater.stdout.log','updater.stderr.log')){$log=Join-Path $EvidenceDir $name;if(Test-Path $log){$logBytes+=(Get-Item $log).Length}};if($logBytes -gt 1MB){throw 'Observed source updater logs exceeded1MiB'}
  $journal=Read-RecoveryJournal $journalPath
  if($journal){
   if($journal.command_id -cne $commandId -or $journal.version -cne '3.2.747' -or $journal.operation -cne 'upgrade' -or $journal.hash -cne $target.binary_sha256){throw 'Original updater journal identity changed'}
   if($job -eq [IntPtr]::Zero -and $journal.installer_job_name){if($journal.installer_job_name -cnotmatch '^Global\\FDSecurity\.Installer\.[a-f0-9]{32}$'){throw 'Original installer Job name is invalid'};$job=[LifecycleInstallerFault]::OpenJob($journal.installer_job_name);if($job -ne [IntPtr]::Zero){$result.installer_job_name=$journal.installer_job_name}}
   if($job -ne [IntPtr]::Zero -and $journal.stage -like 'rollback*' -and @([LifecycleInstallerFault]::Pids($job)).Count -ne 0){throw 'Original rollback began while installer Job still had writers'}
   if($job -ne [IntPtr]::Zero -and !$setupProcess -and $journal.stage -ceq 'full_installer_upgrade'){
    foreach($pidValue in @([LifecycleInstallerFault]::Pids($job))){
     $handle=[LifecycleInstallerFault]::Open([uint32]$pidValue,$false)
     $retained=$false
     try{
      $expectedSetup=Join-Path $stage 'FDSecuritySetup.exe'
      if([LifecycleInstallerFault]::Image($handle) -ieq $expectedSetup){
       if(![LifecycleInstallerFault]::Member($handle,$job) -or (Get-FileHash $expectedSetup).Hash.ToLowerInvariant() -cne $target.installer_sha256){throw 'Real747 Setup Job/image/hash binding failed'}
       $setupProcess=Get-Process -Id $pidValue -ErrorAction Stop;$null=$setupProcess.Handle
       if($setupProcess.StartTime.ToFileTimeUtc() -ne [LifecycleInstallerFault]::Created($handle)){throw 'Real747 Setup generation changed'}
       $rootHandle=$handle;$retained=$true;$result.setup_generation=@{pid=$pidValue;birth=[LifecycleInstallerFault]::Created($handle);sha256=$target.installer_sha256}
      }
     }finally{if(!$retained){[void][LifecycleInstallerFault]::CloseHandle($handle)}}
     if($retained){break}
    }
   }
   if(!$result.fault_injected -and $journal.stage -ceq 'health_observation' -and $job -ne [IntPtr]::Zero -and $setupProcess){
    $setupProcess.Refresh();$setupExited=$setupProcess.HasExited;$setupExit=-1;if($setupExited){$setupExit=$setupProcess.ExitCode}
    $runtime=Get-LifecycleRuntimeProcess -UpdaterProcess $process
    if($runtime.State -ceq 'Running' -and $runtime.ProcessId -gt 0){
     $held=[LifecycleInstallerFault]::Open([uint32]$runtime.ProcessId,$false)
     try{
      $registry=@(Get-Exact742RegistryState);$owner=Get-LifecycleRuntimeOwner
      $raw=(Get-FileHash (Join-Path $InstallDir 'FDSensor.exe')).Hash.ToLowerInvariant();$version=[Diagnostics.FileVersionInfo]::GetVersionInfo((Join-Path $InstallDir 'FDSensor.exe')).ProductVersion
      $generation=([LifecycleInstallerFault]::Image($held) -ieq (Join-Path $InstallDir 'FDSensor.exe') -and [LifecycleInstallerFault]::Created($held) -gt $result.source_generation.birth -and ![LifecycleInstallerFault]::Exited($held))
      if(Test-Exact742LateHealthReady $journal $commandId ([LifecycleInstallerFault]::Exited($oldRuntime)) $setupExited $setupExit @([LifecycleInstallerFault]::Pids($job)).Count $raw $version $registry $generation ($owner.mode -ceq 'scheduled_task')){
       # Re-read immediately; never stop an unverified generation or a post-health task.
       $again=Read-RecoveryJournal $journalPath;$againRegistry=@(Get-Exact742RegistryState);$againOwner=Get-LifecycleRuntimeOwner
       if(Test-Exact742LateHealthReady $again $commandId ([LifecycleInstallerFault]::Exited($oldRuntime)) $setupExited $setupExit @([LifecycleInstallerFault]::Pids($job)).Count (Get-FileHash (Join-Path $InstallDir 'FDSensor.exe')).Hash.ToLowerInvariant() $version $againRegistry (![LifecycleInstallerFault]::Exited($held)) (($againOwner|ConvertTo-Json -Depth 8 -Compress) -ceq ($owner|ConvertTo-Json -Depth 8 -Compress))){
        $targetRuntime=$held;$held=[IntPtr]::Zero
        $result.fault_observation=@{stage=$again.stage;installed_raw_sha256=$raw;display_version=$againRegistry[0].version;setup_exit_code=$setupExit;job_members=0;target_pid=$runtime.ProcessId;target_birth=[LifecycleInstallerFault]::Created($targetRuntime)}
        Stop-ScheduledTask -TaskName FDSecurityAgent -TaskPath '\'
        $result.fault_injected=$true
       }
      }
     }finally{if($held -ne [IntPtr]::Zero){[void][LifecycleInstallerFault]::CloseHandle($held)}}
    }
   }
  }
  Start-Sleep -Milliseconds 100
 }
 if(!$process.HasExited){throw 'Original742 updater did not exit within bounded observation; recovery unconfirmed'}
 $process.WaitForExit();$result.updater_exit_code=$process.ExitCode
 $report=[IO.File]::ReadAllText($reportPath)|ConvertFrom-Json;$journal=Read-RecoveryJournal $journalPath
 $result.source_report_first_error=$report.first_error;$result.source_report_status=$report.status;$result.source_rollback=$report.rollback
 if(!$result.fault_injected){throw 'fault_not_injected: complete real747 late-health boundary was not observed'}
 if($process.ExitCode -eq 0 -or $report.target_version -cne '3.2.747' -or $report.operation -cne 'upgrade' -or $report.upgrade_class -cne 'installer_required' -or $report.expected_sha256 -cne $target.binary_sha256 -or $report.installed_sha256 -cne $source.consumer_identity.agent_sha256 -or $journal.failed_stage -cne $report.failed_stage -or $journal.resolved_deployment_mode -cne 'scheduled_task' -or $report.status -cne 'failed_rolled_back' -or $report.rollback -cne 'succeeded' -or $report.failed_stage -cne 'health_observation' -or !$report.first_error -or $report.first_error -cne $journal.first_error -or $report.installer_exit_code -ne 0 -or $journal.installer_quiesced -ne $true -or @([LifecycleInstallerFault]::Pids($job)).Count -ne 0){throw 'Original742 failure/recovery report or empty installer Job contract failed'}
 $result.registry_after=@(Get-Exact742RegistryState)
 $validationFailures=New-Object 'System.Collections.Generic.List[string]'
 try{Assert-Exact742RegistryRestored $beforeRegistry $result.registry_after;$result.registry_restored=$true}catch{$result.registry_restored=$false;$validationFailures.Add($_.Exception.Message)}
 try{Assert-RecoveryFiles $files;$result.protected_runtime_restored=$true}catch{$result.protected_runtime_restored=$false;$validationFailures.Add($_.Exception.Message)}
 try{$actualOwner=Get-LifecycleRuntimeOwner;if(($actualOwner|ConvertTo-Json -Depth 8 -Compress) -cne ($beforeOwner|ConvertTo-Json -Depth 8 -Compress)){throw 'Original742 task identity was not restored'};$result.task_restored=$true}catch{$result.task_restored=$false;$validationFailures.Add($_.Exception.Message)}
 try{
  $restored=Get-LifecycleRuntimeProcess -UpdaterProcess $process
  if($restored.State -cne 'Running' -or $restored.ProcessId -le 0){throw 'Restored742 runtime is not running'}
  $recoveredHandle=[LifecycleInstallerFault]::Open([uint32]$restored.ProcessId,$false)
  $recoveryValidationFirst=$null
  try{
   $result.injected747_exited=[LifecycleInstallerFault]::Exited($targetRuntime)
   $birth=[LifecycleInstallerFault]::Created($recoveredHandle)
   Assert-Exact742RecoveredGeneration $result.injected747_exited $result.fault_observation.target_birth $birth ([LifecycleInstallerFault]::Image($recoveredHandle)) (Join-Path $InstallDir 'FDSensor.exe')
   if([LifecycleInstallerFault]::Exited($recoveredHandle)){throw 'Restored742 process exited during verification'}
   $result.recovered_generation=@{pid=$restored.ProcessId;birth=$birth}
  }catch{$recoveryValidationFirst=$_;throw}
  finally{if(![LifecycleInstallerFault]::CloseHandle($recoveredHandle)){if(!$result.cleanup_failure){$result.cleanup_failure='Recovered process handle release failed'};if(!$recoveryValidationFirst){throw 'Recovered process handle release failed'}else{Write-Warning 'Recovered handle cleanup failed; generation failure preserved'}}}
  $result.runtime_running=$true
 }catch{$result.runtime_running=$false;$validationFailures.Add($_.Exception.Message)}
 if($validationFailures.Count){throw ($validationFailures -join '; ')}
 $result.case_passed=$true
}catch{$first=$_;$result.first_failure=$_.Exception.Message}
finally{
 if($job -ne [IntPtr]::Zero){
  try{if(@([LifecycleInstallerFault]::Pids($job)).Count -gt 0){[LifecycleInstallerFault]::Terminate($job)};$drain=[Diagnostics.Stopwatch]::StartNew();while(@([LifecycleInstallerFault]::Pids($job)).Count -gt 0 -and $drain.ElapsedMilliseconds -lt 15000){Start-Sleep -Milliseconds 100};$result.installer_job_empty=(@([LifecycleInstallerFault]::Pids($job)).Count -eq 0);if(!$result.installer_job_empty){throw 'Installer Job cleanup exit unconfirmed'}}catch{$result.cleanup_failure=$_.Exception.Message;if(!$first){$first=$_;$result.first_failure=$_.Exception.Message}}
 }
 if($process){try{if(!$process.HasExited){$result.updater_exit_confirmed=$process.WaitForExit(90000)}else{$result.updater_exit_confirmed=$true};if(!$result.updater_exit_confirmed){throw 'Original updater recovery still active; no external runtime/registry repair attempted'}}catch{if(!$result.cleanup_failure){$result.cleanup_failure=$_.Exception.Message};if(!$first){$first=$_;$result.first_failure=$_.Exception.Message}}}
 foreach($pair in @(@($journalPath,'journal.json'),@($reportPath,'report.json'))){try{if(Test-Path $pair[0]){Copy-Item $pair[0] (Join-Path $EvidenceDir $pair[1])}}catch{if(!$first){$first=$_;$result.first_failure=$_.Exception.Message}else{Write-Warning 'Unable to retain source updater evidence; first failure preserved'}}}
 foreach($handle in @($targetRuntime,$oldRuntime,$rootHandle,$job)){
  if($handle -ne [IntPtr]::Zero){try{if(![LifecycleInstallerFault]::CloseHandle($handle)){throw 'Retained lifecycle handle release failed'}}catch{if(!$result.cleanup_failure){$result.cleanup_failure=$_.Exception.Message};if(!$first){$first=$_;$result.first_failure=$_.Exception.Message}}}
 }
 foreach($resource in @($setupProcess,$process)){
  if($resource){try{$resource.Dispose()}catch{if(!$result.cleanup_failure){$result.cleanup_failure=$_.Exception.Message};if(!$first){$first=$_;$result.first_failure=$_.Exception.Message}}}
 }
 $result.completed_utc=[DateTime]::UtcNow.ToString('o');$result.case_passed=($result.case_passed -and !$first)
 try{$result|ConvertTo-Json -Depth 10|Set-Content (Join-Path $EvidenceDir 'result.json') -Encoding UTF8}catch{if(!$first){$first=$_}else{Write-Warning 'Cannot save case receipt; original failure preserved'}}
}
if($first){throw $first}
