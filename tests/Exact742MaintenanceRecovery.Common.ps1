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
function Get-ExactMaintenanceHealthyRuntime([string]$Version,[string]$AgentHash,[string]$IntegrityHash,[long]$PreviousBirth,[IntPtr]$PreviousHandle,$LegacyBaseline=$null) {
 Assert-Exact742ProgramHash (Join-Path $InstallDir 'FDSensor.exe') $AgentHash
 if(([IO.File]::ReadAllText((Join-Path $InstallDir 'VERSION'))).Trim() -cne $Version){throw 'Direct Setup installed wrong version'}
 Assert-Exact742Integrity $InstallDir $IntegrityHash
 $runtime=Get-LifecycleRuntimeProcess
 if($runtime.State -cne 'Running' -or $runtime.ProcessId -le 0){throw 'Direct Setup did not leave a running runtime'}
 $handle=[LifecycleInstallerFault]::Open([uint32]$runtime.ProcessId,$false);$retained=$false;$first=$null
 try{
  $birth=[LifecycleInstallerFault]::Created($handle)
  Assert-Exact742RecoveredGeneration ([LifecycleInstallerFault]::Exited($PreviousHandle)) $PreviousBirth $birth ([LifecycleInstallerFault]::Image($handle)) (Join-Path $InstallDir 'FDSensor.exe')
  $registry=@(Get-ExactMaintenanceRegistryState $Version $LegacyBaseline)
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

# Phase2 only: summarize receipts already fully checked by the existing storage owner.
function Get-ExactMaintenanceStorageStage($Context,[string]$Stage) {
 $databases=@()
 foreach($kind in @('cache','queue')){
  $proofPath=Join-Path $Context.root ($Stage+'-'+$kind+'-snapshot.stdout.json')
  $null=Assert-LifecycleStorageRegular $proofPath 65536
  $proof=[IO.File]::ReadAllText($proofPath)|ConvertFrom-Json
  if($proof.database_kind -cne $kind -or $proof.source_journal_mode -cne 'wal' -or $proof.snapshot_scope -cne 'single_database_committed_read_view' -or $proof.cross_database_atomic -ne $false -or $proof.wal_resolution -cne 'sqlite_read_transaction_resolves_committed_wal_if_present'){throw 'Phase2 per-database WAL snapshot evidence is incomplete'}
  $readers=@()
  foreach($role in @('legacy','candidate')){
   $path=Join-Path $Context.root ($Stage+'-'+$kind+'-'+$role+'-read.stdout.json')
   $null=Assert-LifecycleStorageRegular $path 65536
   $read=[IO.File]::ReadAllText($path)|ConvertFrom-Json
   if($read.source_commit -cne $Context.tools.$role.source_commit -or $read.action -cne 'read' -or @($read.records).Count -ne $Context.generation*2){throw 'Phase2 storage reader evidence is incomplete'}
   $readers+=@{role=$role;source_commit=$read.source_commit;receipt_sha256=(Get-FileHash $path).Hash.ToLowerInvariant();record_count=@($read.records).Count}
  }
  $databases+=@{kind=$kind;snapshot_sha256=$proof.sha256;snapshot_bytes=$proof.size;journal_mode=$proof.source_journal_mode;wal_before=$proof.wal_before;wal_after=$proof.wal_after;readers=$readers;source_readonly=$proof.source_readonly}
 }
 return @{stage=$Stage;generation=$Context.generation;databases=$databases;queue_retry_metadata_preservation_tested=$false;shared_owner_ref_tested=$false;protection_deadline_tested=$false;cross_database_atomic=$false;outbox_tested=$false;server_ack_tested=$false;wal_only_frozen_rows_proven=$false}
}

# Optional disposable hosted fixture. No original-machine ACL is transported.
function Get-ExactHeadlessFixtureValues {
 $root='C:\Program Files\FDSecurity';$exe=$root+'\uninstall.exe'
 return [ordered]@{DisplayName='FDSecurity Endpoint Agent';DisplayVersion='3.2.530';Publisher='FDSecurity';InstallLocation=$root;DisplayIcon=$exe;UninstallString='"'+$exe+'"';QuietUninstallString='"'+$exe+'" /S';NoModify=1;NoRepair=1}
}
function Convert-ExactRegistrationPath([string]$Path) {
 if(!$Path){return ''}
 return [IO.Path]::GetFullPath(($Path -replace '\\+','\')).TrimEnd('\').ToLowerInvariant()
}
# Classify unrelated products without making their malformed paths our contract.
# Named EDR keys always proceed to the strict value/path validator below.
function Test-ExactMaintenanceRegistrationRelevant([string]$Name,[string]$Location) {
 if($Name -ceq 'FDSecurityAgentHeadless' -or $Name -ceq '{A73C1E7F-8D94-4A2C-BF5D-1E2F3A4B5C6D}}_is1'){return $true}
 $expected=Convert-ExactRegistrationPath $InstallDir
 try{return (Convert-ExactRegistrationPath $Location) -ceq $expected}
 catch{
  $cause=$_.Exception.GetBaseException()
  if($cause -is [ArgumentException] -or $cause -is [NotSupportedException] -or $cause -is [IO.PathTooLongException]){return $false}
  throw
 }
}
function Get-ExactRegistrationDigest($Entry) {
 $sha=[Security.Cryptography.SHA256]::Create()
 try{return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes(($Entry|ConvertTo-Json -Depth 12 -Compress))))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
}
function Get-ExactMaintenanceRegistrationInventory {
 $rows=@();$parentPath='SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
 foreach($view in @([Microsoft.Win32.RegistryView]::Registry64,[Microsoft.Win32.RegistryView]::Registry32)){
  $base=$null;$parent=$null
  try{
   $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$view);$parent=$base.OpenSubKey($parentPath,$false)
   if(!$parent){throw 'Uninstall registry view unavailable'}
   $names=@($parent.GetSubKeyNames());if($names.Count -gt 4096){throw 'Uninstall inventory exceeds finite4096-key bound'}
   foreach($name in $names){
    $key=$null
    try{
     $key=$parent.OpenSubKey($name,$false);if(!$key){throw 'Uninstall key disappeared during inventory'}
     $location=[string]$key.GetValue('InstallLocation','',[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
     if(!(Test-ExactMaintenanceRegistrationRelevant $name $location)){continue}
     $values=@();$valueNames=@($key.GetValueNames()|Sort-Object);if($valueNames.Count -gt 64){throw 'Uninstall value inventory exceeds64 bound'}
     foreach($valueName in $valueNames){$value=$key.GetValue($valueName,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames);if(($value|ConvertTo-Json -Compress).Length -gt 16384){throw 'Uninstall registry value exceeds16KiB bound'};$values+=[ordered]@{name=$valueName;kind=[string]$key.GetValueKind($valueName);value=$value}}
     $acl=$key.GetAccessControl();$rows+=[ordered]@{key=$name;view=[string]$view;values=$values;subkey_count=$key.SubKeyCount;acl_protected=$acl.AreAccessRulesProtected;parent_acl_protected=$parent.GetAccessControl().AreAccessRulesProtected;sddl=$acl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::All)}
    }finally{if($key){$key.Dispose()}}
   }
  }finally{if($parent){$parent.Dispose()};if($base){$base.Dispose()}}
 }
 return $rows
}
function Assert-ExactMaintenanceRegistrationInventory($Rows,[string]$Version,$LegacyBaseline) {
 $canonical=@($Rows|Where-Object {$_.key -ceq '{A73C1E7F-8D94-4A2C-BF5D-1E2F3A4B5C6D}}_is1'})
 $legacy=@($Rows|Where-Object {$_.key -ceq 'FDSecurityAgentHeadless'})
 if(@($Rows).Count -ne 2 -or $canonical.Count -ne 1 -or $legacy.Count -ne 1 -or @($Rows|Where-Object {$_.view -cne 'Registry64'}).Count){throw 'Dual registration requires only the canonical AppId and one Registry64 headless entry'}
 $expected=Get-ExactHeadlessFixtureValues;$entry=$legacy[0]
 if(@($entry.values).Count -ne 9 -or $entry.subkey_count -ne 0 -or $entry.acl_protected -ne $false -or $entry.parent_acl_protected -ne $true -or !$entry.sddl){throw 'Legacy registration value/ACL inheritance shape differs'}
 foreach($name in $expected.Keys){$value=@($entry.values|Where-Object {$_.name -ceq $name});$kind=if($name -cin @('NoModify','NoRepair')){'DWord'}else{'String'};if($value.Count -ne 1 -or $value[0].kind -cne $kind -or $value[0].value -cne $expected[$name]){throw ('Legacy registration value/type differs: '+$name)}}
 if($LegacyBaseline -and (Get-ExactRegistrationDigest $entry) -cne (Get-ExactRegistrationDigest $LegacyBaseline)){throw 'Legacy registration values/types/ACL changed on this host'}
 $values=@{};foreach($value in $canonical[0].values){$values[$value.name]=$value.value}
 $exe=Join-Path $InstallDir 'unins000.exe'
 $uninstall=[regex]::Match([string]$values.UninstallString,'^"([^"\r\n]+)"$')
 $quiet=[regex]::Match([string]$values.QuietUninstallString,'^"([^"\r\n]+)" /SILENT$')
 if($values.DisplayVersion -cne $Version -or (Convert-ExactRegistrationPath $values.InstallLocation) -cne (Convert-ExactRegistrationPath $InstallDir) -or !$uninstall.Success -or !$quiet.Success -or (Convert-ExactRegistrationPath $uninstall.Groups[1].Value) -cne (Convert-ExactRegistrationPath $exe) -or (Convert-ExactRegistrationPath $quiet.Groups[1].Value) -cne (Convert-ExactRegistrationPath $exe)){throw 'Canonical AppId registration identity differs'}
 return [ordered]@{key=$canonical[0].key;version=$values.DisplayVersion;location=$values.InstallLocation;uninstall=$values.UninstallString;quiet_uninstall=$values.QuietUninstallString}
}
function New-ExactHeadlessRegistrationFixture {
 if($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or $env:RUNNER_ARCH -cne 'ARM64' -or $InstallDir -cne 'C:\Program Files\FDSecurity'){throw 'Headless registry fixture is restricted to disposable hosted ARM standard-directory qualification'}
 $rows=@(Get-ExactMaintenanceRegistrationInventory)
 if($rows.Count -ne 1 -or $rows[0].key -cne '{A73C1E7F-8D94-4A2C-BF5D-1E2F3A4B5C6D}}_is1' -or $rows[0].view -cne 'Registry64'){throw 'Headless fixture requires exactly one clean canonical registration; existing keys are never overwritten'}
 $base=$null;$parent=$null;$created=$null
 try{
  $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64)
  $parent=$base.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',$true)
  if(!$parent -or !$parent.GetAccessControl().AreAccessRulesProtected){throw 'Cloud uninstall parent ACL inheritance model differs'}
  $existing=$parent.OpenSubKey('FDSecurityAgentHeadless',$false);if($existing){$existing.Dispose();throw 'Headless key appeared before creation; never overwrite'}
  $created=$parent.CreateSubKey('FDSecurityAgentHeadless');$expected=Get-ExactHeadlessFixtureValues
  foreach($name in $expected.Keys){$kind=if($name -cin @('NoModify','NoRepair')){[Microsoft.Win32.RegistryValueKind]::DWord}else{[Microsoft.Win32.RegistryValueKind]::String};$created.SetValue($name,$expected[$name],$kind)}
 }finally{if($created){$created.Dispose()};if($parent){$parent.Dispose()};if($base){$base.Dispose()}}
 $rows=@(Get-ExactMaintenanceRegistrationInventory);$null=Assert-ExactMaintenanceRegistrationInventory $rows '3.2.742' $null
 return @($rows|Where-Object {$_.key -ceq 'FDSecurityAgentHeadless'})[0]
}
function Get-ExactMaintenanceRegistryState([string]$Version,$LegacyBaseline) {
 if(!$LegacyBaseline){return @(Get-Exact742RegistryState)}
 return Assert-ExactMaintenanceRegistrationInventory @(Get-ExactMaintenanceRegistrationInventory) $Version $LegacyBaseline
}
function Get-ExactMaintenanceUninstallerIdentity {
 $native=[IO.File]::ReadAllText((Join-Path $InstallDir 'native-package-integrity.json'))|ConvertFrom-Json
 $member=@($native.files|Where-Object {$_.name -ceq 'uninstall.exe'})
 if($member.Count -ne 1){throw 'Native uninstall.exe identity is not unique'}
 Assert-Exact742ProgramHash (Join-Path $InstallDir 'uninstall.exe') $member[0].sha256
 $inno=Join-Path $InstallDir 'unins000.exe';$null=Assert-LifecycleStorageRegular $inno 16777216
 # unins000 is generated by the real signed Setup; do not invent a golden build hash.
 $stream=[IO.File]::OpenRead($inno)
 try{if($stream.ReadByte() -ne 77 -or $stream.ReadByte() -ne 90){throw 'Canonical uninstaller is not a PE'}}finally{$stream.Dispose()}
 return @{native_uninstall_sha256=$member[0].sha256;canonical_uninstaller_sha256=(Get-FileHash $inno).Hash.ToLowerInvariant();canonical_identity_scope='Actual Inno AppId unins000.exe from the just-completed signed Setup; never executed'}
}
