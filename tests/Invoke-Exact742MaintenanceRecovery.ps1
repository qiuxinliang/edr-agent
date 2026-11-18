#Requires -Version 5.1
# Disposable cloud fixture only: direct signed Setup maintenance and formal recovery.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$QualificationInput,[Parameter(Mandatory=$true)][string]$QualificationInputSha256,[Parameter(Mandatory=$true)][string]$SourceConsumerReceipt,[Parameter(Mandatory=$true)][string]$SourceConsumerReceiptSha256,[Parameter(Mandatory=$true)][string]$EvidenceDir,[string]$StorageToolsInput='',[string]$StorageToolsInputSha256='',[switch]$ExistingHeadlessRegistrationFixture)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Exact742FirstHopRecovery.Common.ps1')
. Import-Exact742TestDefinitions
. (Join-Path $PSScriptRoot 'Exact742MaintenanceRecovery.Common.ps1')
$InstallDir='C:\Program Files\FDSecurity';$RuntimeMode='scheduled_task';$ServiceName='FDSecurityAgent';$Architecture='arm64'
$inputBinding=Read-Exact742BoundJson $QualificationInput $QualificationInputSha256
$source=Read-Exact742BoundJson $SourceConsumerReceipt $SourceConsumerReceiptSha256
Assert-Exact742MaintenanceContext $inputBinding $source
Assert-Exact742FileBindings $inputBinding
$events=New-Object 'System.Collections.Generic.List[object]'
$storageTools=$null;$storageContext=$null;$storageStages=@();$storageRetiredHandles=@()
if($StorageToolsInput -or $StorageToolsInputSha256){
 if(!$StorageToolsInput -or !$StorageToolsInputSha256){throw 'Phase2 storage tools require a path and exact digest together'}
 $null=Read-Exact742BoundJson $StorageToolsInput $StorageToolsInputSha256
 $pe=Join-Path (Split-Path -Parent $PSScriptRoot) 'scripts/Assert-WindowsPeArchitecture.ps1'
 $storageTools=Import-LifecycleStorageTools $StorageToolsInput 'arm64' $pe 'installed742-to747'
}
$EvidenceDir=[IO.Path]::GetFullPath($EvidenceDir)
if(Test-Path $EvidenceDir){throw 'Fresh direct maintenance evidence directory required'}
New-Item -ItemType Directory $EvidenceDir|Out-Null
$principal=[Security.Principal.WindowsIdentity]::GetCurrent()
if(-not ([Security.Principal.WindowsPrincipal]::new($principal)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Direct signed Setup test must run elevated'}
if($ExistingHeadlessRegistrationFixture -and ($StorageToolsInput -or $StorageToolsInputSha256)){throw 'Headless registration case does not rerun storage tools'}
$legacyBaseline=$null
$beforeOwner=Get-LifecycleRuntimeOwner
$beforeRegistry=@(Get-Exact742RegistryState)
Assert-Exact742RegistryRestored @($source.uninstall) $beforeRegistry
if(($beforeOwner|ConvertTo-Json -Depth 8 -Compress) -cne ($source.task_owner|ConvertTo-Json -Depth 8 -Compress)){throw 'Direct maintenance source task changed after qualification'}
Assert-Exact742ProgramHash (Join-Path $InstallDir 'FDSensor.exe') $source.consumer_identity.agent_sha256
Assert-Exact742ProgramHash (Join-Path $InstallDir 'edr_agent_inplace_update.ps1') $source.consumer_identity.updater_sha256
Assert-Exact742ProgramHash (Join-Path $InstallDir 'FDSensorTaskLaunch.ps1') $source.consumer_identity.launcher_sha256
Assert-Exact742Integrity $InstallDir $source.consumer_identity.native_integrity_sha256
if((Get-FileHash (Join-Path $InstallDir 'agent.toml')).Hash.ToLowerInvariant() -cne $source.config_sha256){throw 'Direct maintenance source configuration changed'}
if($ExistingHeadlessRegistrationFixture){$legacyBaseline=New-ExactHeadlessRegistrationFixture;$null=Get-ExactMaintenanceRegistryState '3.2.742' $legacyBaseline;$sourceUninstallers=Get-ExactMaintenanceUninstallerIdentity;$canonicalBefore=@(Get-ExactMaintenanceRegistrationInventory|Where-Object {$_.key -cne 'FDSecurityAgentHeadless'})[0]}
$roles=@{};foreach($binding in $inputBinding.file_bindings){$roles[$binding.role]=$binding}
$proof=[IO.File]::ReadAllText($inputBinding.target_publisher_proof)|ConvertFrom-Json
$manifest=[IO.File]::ReadAllText($roles.target_manifest.path)|ConvertFrom-Json
$raw=@($manifest.artifacts|Where-Object {$_.name -ceq 'edr-agent-win_3.2.747-windows-arm64-FDSensor.exe'})
$setup=@($manifest.artifacts|Where-Object {$_.name -ceq [IO.Path]::GetFileName($inputBinding.target_setup_exe)})
if($proof.schema -cne 'edr.windows.publisher-verification.v1' -or $proof.version -cne '3.2.747' -or $proof.arch -cne 'arm64' -or $proof.verifier_source_commit -cne 'c59eda045e3e2b9c882d462b74533e2c4b6c45da' -or $proof.artifact_sha256 -cne 'c1ea2133d925ff688dd6f15419ecd5dd2065525466e78b8a44c51212a6464fd0' -or $proof.manifest_sha256 -cne $roles.target_manifest.sha256 -or $proof.signature_sha256 -cne $roles.target_cms.sha256 -or $manifest.version -cne '3.2.747' -or $raw.Count -ne 1 -or $raw[0].sha256 -cne $proof.artifact_sha256 -or $raw[0].update.runtime_identity_sha256 -cnotmatch '^[a-f0-9]{64}$' -or $setup.Count -ne 1 -or $setup[0].sha256 -cne $roles.target_setup.sha256){throw 'Direct maintenance target747 immutable release binding mismatch'}
Assert-ExactMaintenanceSetup $inputBinding.source_setup_exe $source.source_setup_sha256
Assert-ExactMaintenanceSetup $inputBinding.target_setup_exe $setup[0].sha256
# Authenticate and load only the existing original742 bounded process-tree owner.
$updater=Join-Path $InstallDir 'edr_agent_inplace_update.ps1';$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($updater,[ref]$tokens,[ref]$errors)
$initializers=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Initialize-InstallerJobType'},$true))
if(@($errors).Count -or $initializers.Count -ne 1){throw 'Original742 bounded Setup owner is not unique/parseable'}
. ([scriptblock]::Create($initializers[0].Extent.Text));Initialize-InstallerJobType
$result=[ordered]@{schema='edr.exact742.direct-setup-maintenance-recovery.v1';started_utc=[DateTime]::UtcNow.ToString('o');controller_principal=$principal.Name;controller_sid=$principal.User.Value;controller_temp_path=[IO.Path]::GetTempPath();controller_scope='Actual elevated hosted controller; not claimed original SYSTEM/SystemTemp controller';case_passed=$false;maintenance_passed=$false;signed_setup_recovery_passed=$false;full_gate=$false;full_gate_passed=$false;deployment_authorized=$false;automatic_updater_recovery_tested=$false;controlled_acceptance_refusal_injected=$false;acceptance_error_code=$null;acceptance_first_failure=$null;failure_recovery_tested=$false;failure_recovery_scope='controlled post-install acceptance refusal after real747 Setup exit0/Jobempty/30s healthy only';setup_midflight_recovery_tested=$false;setup_timeout_recovery_tested=$false;data_scope=$false;data_preservation_passed=$false;queue_retry_metadata_preservation_tested=$false;shared_owner_ref_tested=$false;protection_deadline_tested=$false;cross_database_atomic=$false;outbox_tested=$false;server_ack_tested=$false;data_note='No real database copy; this case does not prove synthetic WAL/queue reader preservation or ACK';first_failure=$null;cleanup_failure=$null;registry_before=$beforeRegistry;maintenance=$null;recovery=$null}
$oldHandle=[IntPtr]::Zero;$targetRuntime=$null;$recoveredRuntime=$null;$first=$null
try{
 if($storageTools){
  $storageContext=New-LifecycleStorageChain $storageTools 'exact742-maintenance-data'
  Write-LifecycleStorageFixture $storageContext 'seed' 'source742-seed'
  Test-LifecycleStorageReadback $storageContext 'source742-restarted'
  $storageStages+=Get-ExactMaintenanceStorageStage $storageContext 'source742-restarted'
 }
 # Hold only the current source generation AFTER seed/restart, never its predecessor.
 $old=Get-LifecycleRuntimeProcess
 if($old.State -cne 'Running' -or $old.ProcessId -le 0){throw 'Direct maintenance source runtime is not running'}
 $oldHandle=[LifecycleInstallerFault]::Open([uint32]$old.ProcessId,$false);$oldBirth=[LifecycleInstallerFault]::Created($oldHandle)
 $native=Read-Exact742NativeFloor $EvidenceDir
 $minimum=[Math]::Max([UInt64]2147483648,[Math]::Max([UInt64]$raw[0].update.min_free_bytes,[UInt64]$native.floor_bytes))
 if((Get-PSDrive C).Free -lt $minimum){throw 'Direct747 maintenance native/manifest/2GiB floor unavailable'}
 $result.source_native_floor=$native;$result.maintenance_min_free_bytes=$minimum
 $null=Read-Exact742BoundJson $QualificationInput $QualificationInputSha256
 Assert-Exact742FileBindings $inputBinding
 $result.maintenance=Invoke-ExactMaintenanceSetupJob $inputBinding.target_setup_exe 'direct747-maintenance' $minimum $setup[0].sha256
 $targetRuntime=Get-ExactMaintenanceHealthyRuntime '3.2.747' $proof.artifact_sha256 $raw[0].update.runtime_identity_sha256 $oldBirth $oldHandle $legacyBaseline
 if((Get-FileHash (Join-Path $InstallDir 'agent.toml')).Hash.ToLowerInvariant() -cne $source.config_sha256){throw 'Direct747 maintenance changed protected synthetic config'}
 if($legacyBaseline){$legacy747=@(Get-ExactMaintenanceRegistrationInventory|Where-Object {$_.key -ceq 'FDSecurityAgentHeadless'})[0];$targetUninstallers=Get-ExactMaintenanceUninstallerIdentity}
 $result.target_generation=@{pid=$targetRuntime.pid;birth=$targetRuntime.birth};$result.registry_at747=$targetRuntime.registry;$result.maintenance_passed=$true
 if($storageContext){
  $previousTarget=$targetRuntime
  Write-LifecycleStorageFixture $storageContext 'append' 'target747-append'
  Test-LifecycleStorageReadback $storageContext 'target747-restarted'
  $storageStages+=Get-ExactMaintenanceStorageStage $storageContext 'target747-restarted'
  $afterAppend=Get-ExactMaintenanceHealthyRuntime '3.2.747' $proof.artifact_sha256 $raw[0].update.runtime_identity_sha256 $previousTarget.birth $previousTarget.handle $legacyBaseline
  $storageRetiredHandles+=$previousTarget.handle;$targetRuntime=$afterAppend
  $result.target_generation=@{pid=$targetRuntime.pid;birth=$targetRuntime.birth}
 }
 # The only simulated failure is this late test-side acceptance refusal.
 # A genuine Setup/health/Job failure never reaches this boundary or a blind retry.
 $acceptanceObservation=@{version=$targetRuntime.version;agent_sha256=(Get-FileHash (Join-Path $InstallDir 'FDSensor.exe')).Hash.ToLowerInvariant();setup_exit_code=$result.maintenance.exit_code;setup_job_empty=$result.maintenance.job_empty;setup_cleanup_failure=$result.maintenance.cleanup_failure;health_observe_ms=$targetRuntime.health_observe_ms;target_generation_alive=(![LifecycleInstallerFault]::Exited($targetRuntime.handle));task_mode=(Get-LifecycleRuntimeOwner).mode;registry=@(Get-ExactMaintenanceRegistryState '3.2.747' $legacyBaseline)}
 try{Invoke-ExactMaintenanceAcceptanceBoundary $acceptanceObservation}
 catch{
  $cause=$_.Exception
  while($cause.InnerException -and !$cause.Data['exact_maintenance_fault']){$cause=$cause.InnerException}
  if($cause.Data['exact_maintenance_fault'] -cne 'TEST_POST_INSTALL_ACCEPTANCE_REFUSED'){throw}
  $result.controlled_acceptance_refusal_injected=$true;$result.acceptance_error_code=$cause.Data['exact_maintenance_fault'];$result.acceptance_first_failure=$cause.Message
 }
 if(!$result.controlled_acceptance_refusal_injected){throw 'Expected late acceptance boundary did not refuse; recovery was not exercised'}
 # Read target's native authority too; never reuse an old floor after a version change.
 $floorRoot=Join-Path $EvidenceDir 'target-native-floor';New-Item -ItemType Directory $floorRoot|Out-Null
 $targetFloor=Read-Exact742NativeFloor $floorRoot $proof.artifact_sha256
 $sourceManifest=[IO.File]::ReadAllText($roles.source_manifest.path)|ConvertFrom-Json
 $sourceRaw=@($sourceManifest.artifacts|Where-Object {$_.name -ceq 'edr-agent-win_3.2.742-windows-arm64-FDSensor.exe'})
 if($sourceRaw.Count -ne 1 -or $sourceRaw[0].sha256 -cne $source.consumer_identity.agent_sha256){throw 'Signed742 recovery manifest binding mismatch'}
 $recoveryMinimum=[Math]::Max([UInt64]2147483648,[Math]::Max([UInt64]$sourceRaw[0].update.min_free_bytes,[Math]::Max([UInt64]$native.floor_bytes,[UInt64]$targetFloor.floor_bytes)))
 if((Get-PSDrive C).Free -lt $recoveryMinimum){throw 'Signed742 Setup recovery native/manifest/2GiB floor unavailable'}
 $result.target_native_floor=$targetFloor;$result.recovery_min_free_bytes=$recoveryMinimum
 $null=Read-Exact742BoundJson $QualificationInput $QualificationInputSha256
 Assert-Exact742FileBindings $inputBinding
 if([LifecycleInstallerFault]::Exited($targetRuntime.handle) -or (Get-FileHash (Join-Path $InstallDir 'FDSensor.exe')).Hash.ToLowerInvariant() -cne $proof.artifact_sha256){throw 'Uncontrolled runtime change after acceptance refusal; no blind recovery'}
 $null=Get-LifecycleRuntimeOwner
 $result.recovery=Invoke-ExactMaintenanceSetupJob $inputBinding.source_setup_exe 'signed742-setup-recovery' $recoveryMinimum $source.source_setup_sha256
 $recoveredRuntime=Get-ExactMaintenanceHealthyRuntime '3.2.742' $source.consumer_identity.agent_sha256 $source.consumer_identity.native_integrity_sha256 $targetRuntime.birth $targetRuntime.handle $legacyBaseline
 Assert-Exact742ProgramHash (Join-Path $InstallDir 'edr_agent_inplace_update.ps1') $source.consumer_identity.updater_sha256
 Assert-Exact742ProgramHash (Join-Path $InstallDir 'FDSensorTaskLaunch.ps1') $source.consumer_identity.launcher_sha256
 if((Get-FileHash (Join-Path $InstallDir 'agent.toml')).Hash.ToLowerInvariant() -cne $source.config_sha256){throw 'Signed742 Setup recovery changed protected synthetic config'}
 $result.registry_after=$recoveredRuntime.registry
 Assert-Exact742RegistryRestored $beforeRegistry $result.registry_after
 if(($recoveredRuntime.task_owner|ConvertTo-Json -Depth 8 -Compress) -cne ($beforeOwner|ConvertTo-Json -Depth 8 -Compress)){throw 'Signed742 Setup recovery changed original SYSTEM task identity'}
 if($storageContext){
  Test-LifecycleStorageReadback $storageContext 'source742-after-recovery'
  $storageStages+=Get-ExactMaintenanceStorageStage $storageContext 'source742-after-recovery'
  $result.data_scope=$true;$result.data_preservation_passed=$true;$result.storage_stages=$storageStages
  $result.data_note='Synthetic frozen writer records checked field-by-field by b307/388d consumers on separate committed SQLite snapshots per database; WAL resolved if present, no cross-database atomicity, outbox or ACK claim'
 }
 if($legacyBaseline){
  $null=Get-ExactMaintenanceRegistryState '3.2.742' $legacyBaseline
  $finalInventory=@(Get-ExactMaintenanceRegistrationInventory)
  $legacy742=@($finalInventory|Where-Object {$_.key -ceq 'FDSecurityAgentHeadless'})[0]
  $canonicalAfter=@($finalInventory|Where-Object {$_.key -cne 'FDSecurityAgentHeadless'})[0]
  if((Get-ExactRegistrationDigest $canonicalBefore) -cne (Get-ExactRegistrationDigest $canonicalAfter)){throw 'Canonical AppId complete values/types/ACL were not restored by signed742 Setup'}
  foreach($entry in @($legacy747,$legacy742)){if((Get-ExactRegistrationDigest $entry) -cne (Get-ExactRegistrationDigest $legacyBaseline)){throw 'Legacy complete entry preservation failed'}}
  $result.existing_headless_registration=@{tested=$true;preserved=$true;version='3.2.530';before_sha256=(Get-ExactRegistrationDigest $legacyBaseline);at747_sha256=(Get-ExactRegistrationDigest $legacy747);after742_sha256=(Get-ExactRegistrationDigest $legacy742);before=$legacyBaseline;at747=$legacy747;after742=$legacy742;canonical_before=$canonicalBefore;canonical_after742=$canonicalAfter;source_uninstallers=$sourceUninstallers;target_uninstallers=$targetUninstallers;recovered_uninstallers=(Get-ExactMaintenanceUninstallerIdentity)}
 }
 $result.recovered_generation=@{pid=$recoveredRuntime.pid;birth=$recoveredRuntime.birth};$result.signed_setup_recovery_passed=$true;$result.failure_recovery_tested=$true;$result.case_passed=$true
}catch{$first=$_;$result.first_failure=$_.Exception.Message}
finally{
 $handles=@($oldHandle)+@($storageRetiredHandles);if($targetRuntime){$handles+=$targetRuntime.handle};if($recoveredRuntime){$handles+=$recoveredRuntime.handle}
 foreach($handle in $handles){if($handle -ne [IntPtr]::Zero){try{if(![LifecycleInstallerFault]::CloseHandle($handle)){throw 'Direct maintenance runtime handle release failed'}}catch{if(!$result.cleanup_failure){$result.cleanup_failure=$_.Exception.Message};if(!$first){$first=$_;$result.first_failure=$_.Exception.Message}}}}
 $result.storage_events=$events.ToArray()
 $result.completed_utc=[DateTime]::UtcNow.ToString('o');$result.case_passed=($result.case_passed -and !$first)
 try{$result|ConvertTo-Json -Depth 10|Set-Content (Join-Path $EvidenceDir 'result.json') -Encoding UTF8}catch{if(!$first){$first=$_}else{Write-Warning 'Cannot retain direct maintenance result; first failure preserved'}}
}
if($first){throw $first}
