# Test-only direct signed Setup maintenance/recovery, never endpoint repair code.
function Assert-Exact742MaintenanceContext($InputBinding,$Source) {
 Assert-Exact742QualificationContract $InputBinding 'C:\Program Files\FDSecurity' arm64 scheduled_task FDSecurityAgent
 if($Source.schema -cne 'edr.exact-installed742.qualification-result.v1' -or $Source.complete -ne $true -or $Source.qualification_only -ne $true -or $Source.full_gate_passed -ne $false -or $Source.deployment_authorized -ne $false -or
  $Source.runner_environment -cne 'github-hosted' -or $Source.architecture -cne 'arm64' -or $Source.target_version -cne '3.2.747' -or $Source.source_version -cne '3.2.742' -or $Source.source_setup_sha256 -cne '6122591c151953e0416ca70815f4c437e62425cd1f5f48676087b25e32783c92' -or
  $InputBinding.first_hop_inputs_staged -ne $false -or $InputBinding.upgrade_input -or $InputBinding.storage_tools_input){throw 'Direct maintenance requires fresh qualification-only742 source'}
 foreach($pair in @(@('harness_commit',$env:GITHUB_SHA),@('run_id',$env:GITHUB_RUN_ID),@('run_attempt',$env:GITHUB_RUN_ATTEMPT),@('job',$env:GITHUB_JOB))){if(!$pair[1] -or $Source.($pair[0]) -cne $pair[1]){throw 'Direct maintenance source is not from this job'}}
 $consumer=$Source.consumer_identity
 if($consumer.install_dir -cne 'C:\Program Files\FDSecurity' -or $consumer.runtime_mode -cne 'scheduled_task' -or $consumer.agent_sha256 -cne $InputBinding.source_installed_agent_sha256 -or $consumer.updater_sha256 -cne $InputBinding.source_installed_updater_sha256 -or $consumer.launcher_sha256 -cne $InputBinding.source_installed_launcher_sha256 -or $consumer.native_integrity_sha256 -cne '5399c68ef8860199c2efccc4ece6b8e489b01cd7e6f89cfe582df3332e4f37f9'){throw 'Direct maintenance source consumer differs from actual qualification'}
}
function Assert-ExactMaintenanceSetup([string]$Path,[string]$ExpectedHash) {
 Assert-Exact742ProgramHash $Path $ExpectedHash
 $signature=Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
 if([string]$signature.Status -cne 'Valid' -or !$signature.TimeStamperCertificate -or $signature.SignerCertificate.Thumbprint -cne '01BB4E940A8E9CD5C09DEE81F17B5FB016750C3F'){throw 'Direct Setup signature/timestamp/publisher mismatch'}
 $hash=[Security.Cryptography.SHA256]::Create()
 try{$der=([BitConverter]::ToString($hash.ComputeHash($signature.SignerCertificate.SubjectName.RawData))).Replace('-','').ToLowerInvariant()}finally{$hash.Dispose()}
 if($der -cne 'fb7a1b9fa95054b69d11e982bc77c6bb78f778b7e85943b3d1b198923d172a8a'){throw 'Direct Setup publisher subject DER mismatch'}
 & (Join-Path (Split-Path -Parent $PSScriptRoot) 'scripts/Assert-WindowsInstallerBootstrapArchitecture.ps1') -Path $Path -PayloadArchitecture arm64
}
function Invoke-ExactMaintenanceSetupJob([string]$Setup,[string]$Label,[UInt64]$MinFreeBytes,[string]$ExpectedHash) {
 if($Label -cnotin @('direct747-maintenance','signed742-setup-recovery')){throw 'Unknown direct maintenance stage'}
 Assert-ExactMaintenanceSetup $Setup $ExpectedHash
 $log=Join-Path $EvidenceDir ($Label+'.setup.log')
 $arguments='/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP- /DIR="C:\Program Files\FDSecurity" /TASKS="windowsautorun" /EDR_UPGRADE_EXISTING=1 /EDR_KEEP_OFFLINE_QUEUE=1 /EDR_KEEP_EVIDENCE_CACHE=1 /EDR_MIN_FREE_BYTES='+$MinFreeBytes+' /LOG="'+$log+'"'
 $owner=$null;$first=$null;$clock=[Diagnostics.Stopwatch]::StartNew()
 $record=[ordered]@{stage=$Label;setup_sha256=$ExpectedHash;setup_path=$Setup;limit_ms=300000;drain_limit_ms=5000;exit_code=$null;job_empty=$false;first_failure=$null;cleanup_failure=$null;min_free_bytes=$MinFreeBytes;log=$log}
 try{
  $owner=[FDSecurity.InstallerJob]::Create('Global\Exact742.Maintenance.'+[Guid]::NewGuid().ToString('N'))
  $oldModulePath=[Environment]::GetEnvironmentVariable('PSModulePath','Process')
  try{[Environment]::SetEnvironmentVariable('PSModulePath',$null,'Process');$owner.Launch($Setup,$arguments,$InstallDir)}finally{[Environment]::SetEnvironmentVariable('PSModulePath',$oldModulePath,'Process')}
  while($true){
   $remaining=300000-$clock.ElapsedMilliseconds;if($remaining -le 0){throw 'Direct signed Setup exceeded300s'}
   if($owner.WaitForEmpty([int][Math]::Min(1000,$remaining))){break}
   if((Get-PSDrive C).Free -lt $MinFreeBytes){throw 'Observed direct Setup storage floor breached'}
  }
  $record.job_empty=$true;$record.exit_code=$owner.ExitCode()
  if($record.exit_code -ne 0){throw ('Direct signed Setup failed: '+$Label+' exit='+$record.exit_code)}
  Assert-Exact742ProgramHash $Setup $ExpectedHash
 }catch{$first=$_;$record.first_failure=$_.Exception.Message}
 finally{
  if($owner){
   try{$owner.StopAndDrain(5000);$record.job_empty=$owner.WaitForEmpty(0);if(!$record.job_empty){throw 'Direct Setup process-tree exit unconfirmed'}}catch{$record.cleanup_failure=$_.Exception.Message;if(!$first){$first=$_;$record.first_failure=$_.Exception.Message}}
   finally{try{$owner.Dispose()}catch{if(!$record.cleanup_failure){$record.cleanup_failure=$_.Exception.Message};if(!$first){$first=$_;$record.first_failure=$_.Exception.Message}}}
  }
  $record.elapsed_ms=$clock.ElapsedMilliseconds
  try{$record|ConvertTo-Json -Depth 5|Set-Content (Join-Path $EvidenceDir ($Label+'.result.json')) -Encoding UTF8}catch{if(!$first){$first=$_}else{Write-Warning 'Cannot retain Setup receipt; first failure preserved'}}
 }
 if($first){throw $first}
 return $record
}
function Get-ExactMaintenanceHealthyRuntime([string]$Version,[string]$AgentHash,[string]$IntegrityHash,[long]$PreviousBirth,[IntPtr]$PreviousHandle) {
 Assert-Exact742ProgramHash (Join-Path $InstallDir 'FDSensor.exe') $AgentHash
 if(([IO.File]::ReadAllText((Join-Path $InstallDir 'VERSION'))).Trim() -cne $Version){throw 'Direct Setup installed wrong version'}
 Assert-Exact742Integrity $InstallDir $IntegrityHash
 $runtime=Get-LifecycleRuntimeProcess
 if($runtime.State -cne 'Running' -or $runtime.ProcessId -le 0){throw 'Direct Setup did not leave a running runtime'}
 $handle=[LifecycleInstallerFault]::Open([uint32]$runtime.ProcessId,$false);$retained=$false;$first=$null
 try{
  $birth=[LifecycleInstallerFault]::Created($handle)
  Assert-Exact742RecoveredGeneration ([LifecycleInstallerFault]::Exited($PreviousHandle)) $PreviousBirth $birth ([LifecycleInstallerFault]::Image($handle)) (Join-Path $InstallDir 'FDSensor.exe')
  $registry=@(Get-Exact742RegistryState)
  if($registry.Count -ne 1 -or $registry[0].version -cne $Version){throw 'Direct Setup registry version does not match running runtime'}
  $owner=Get-LifecycleRuntimeOwner
  $clock=[Diagnostics.Stopwatch]::StartNew()
  while($clock.ElapsedMilliseconds -lt 30000){
   if([LifecycleInstallerFault]::Exited($handle)){throw 'Direct Setup runtime exited during30s health observation'}
   $actual=Get-LifecycleRuntimeProcess
   if($actual.State -cne 'Running' -or $actual.ProcessId -ne $runtime.ProcessId){throw 'Direct Setup runtime generation changed during health observation'}
   $null=Get-LifecycleRuntimeOwner
   Start-Sleep -Milliseconds 500
  }
  $retained=$true
  return @{handle=$handle;pid=$runtime.ProcessId;birth=$birth;version=$Version;agent_sha256=$AgentHash;integrity_sha256=$IntegrityHash;registry=$registry;task_owner=$owner;health_observe_ms=30000}
 }catch{$first=$_;throw}
 finally{if(!$retained){if(![LifecycleInstallerFault]::CloseHandle($handle)){if(!$first){throw 'Health-observation handle release failed'}else{Write-Warning 'Runtime handle cleanup failed; first failure preserved'}}}}
}
function Invoke-ExactMaintenanceAcceptanceBoundary($Observed) {
 if($Observed.version -cne '3.2.747' -or $Observed.agent_sha256 -cne 'c1ea2133d925ff688dd6f15419ecd5dd2065525466e78b8a44c51212a6464fd0' -or
  $Observed.setup_exit_code -ne 0 -or $Observed.setup_job_empty -ne $true -or $Observed.setup_cleanup_failure -or $Observed.health_observe_ms -lt 30000 -or
  $Observed.target_generation_alive -ne $true -or $Observed.task_mode -cne 'scheduled_task' -or @($Observed.registry).Count -ne 1 -or $Observed.registry[0].version -cne '3.2.747'){
  throw 'Controlled acceptance refusal requires completed/quiescent and healthy747; no blind recovery is authorized'
 }
 $failure=[InvalidOperationException]::new('Controlled post-install747 acceptance refusal; original signed742 Setup recovery is required')
 $failure.Data['exact_maintenance_fault']='TEST_POST_INSTALL_ACCEPTANCE_REFUSED'
 throw $failure
}
