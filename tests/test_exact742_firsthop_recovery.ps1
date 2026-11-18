#Requires -Version 5.1
# No Setup, Agent, registry, task operation, process launch or product execution.
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Exact742FirstHopRecovery.Common.ps1')
$count=0
function Need($Value,$Message){if(!$Value){throw $Message};$script:count++}
function Reject([scriptblock]$Action,[string]$Contains=''){try{& $Action}catch{if($Contains){Need ($_.Exception.Message.Contains($Contains)) 'Wrong failure classification'};$script:count++;return};throw 'Expected refusal absent'}
$old=@{};foreach($key in @('GITHUB_ACTIONS','RUNNER_ENVIRONMENT','RUNNER_ARCH','GITHUB_SHA','GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT','GITHUB_JOB')){$old[$key]=[Environment]::GetEnvironmentVariable($key,'Process')}
try{
 $env:GITHUB_ACTIONS='true';$env:RUNNER_ENVIRONMENT='github-hosted';$env:RUNNER_ARCH='ARM64';$env:GITHUB_SHA='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';$env:GITHUB_RUN_ID='123';$env:GITHUB_RUN_ATTEMPT='1';$env:GITHUB_JOB='exact742'
 $consumer=@{install_dir='C:\Program Files\FDSecurity';runtime_mode='scheduled_task';agent_sha256='e6ea9736829d0c0be5284c570f198ec888bcaad1845a074ea8838ebf6b326dbe';updater_sha256='cae170855648559201c20b62d2d72d1bf2f030b61f5fda8ba27aa7534bd7a183';launcher_sha256='656d349640d5403af0881bb5db7a4811074450cb93b6602c1322f03edfafd8c3';native_integrity_sha256='5399c68ef8860199c2efccc4ece6b8e489b01cd7e6f89cfe582df3332e4f37f9'}
 $source=@{schema='edr.exact-installed742.qualification-result.v1';complete=$true;qualification_only=$true;full_gate_passed=$false;deployment_authorized=$false;source_version='3.2.742';source_setup_sha256='6122591c151953e0416ca70815f4c437e62425cd1f5f48676087b25e32783c92';consumer_identity=$consumer;config_sha256=('b'*64);task_owner=@{mode='scheduled_task';name='FDSecurityAgent'};uninstall=@{version='3.2.742'};harness_commit=$env:GITHUB_SHA;run_id='123';run_attempt='1';job='exact742';runner_environment='github-hosted';architecture='arm64';target_version='3.2.747'}
 $target=@{schema='edr.windows.lifecycle-upgrade.v1';baseline_version='3.2.742';target_version='3.2.747';architecture='arm64';deployment_mode='service';service_name='FDSecurityAgent';signature_status='signed';upgrade_class='installer_required';binary_sha256='c1ea2133d925ff688dd6f15419ecd5dd2065525466e78b8a44c51212a6464fd0';publisher_subject_der_sha256='fb7a1b9fa95054b69d11e982bc77c6bb78f778b7e85943b3d1b198923d172a8a';runtime_package='test-only-not-opened.zip';baseline_updater_sha256='88912072d0e842bb07c1ee730b91233f39e0e8dad57e403990c702bda58edc2a'}
 $request=@{schema='edr.exact742-to747.first-hop.v1';harness=@{harness_commit=$env:GITHUB_SHA;run_id='123';run_attempt='1';job='exact742'};install_dir=$consumer.install_dir;architecture='arm64';runtime_mode='scheduled_task';full_gate=$false;deployment_authorized=$false;old_full_setup_rollback_supported=$false;target_agent_sha256=$target.binary_sha256;source_updater_path='C:\Program Files\FDSecurity\edr_agent_inplace_update.ps1';packaged_source_runtime_sha256='35068437d8fc507a7146dc603cea15d900d388a4edfc3c829a3aaae3c76eede7';packaged_source_updater_sha256=$target.baseline_updater_sha256;expected_recovery=@{version='3.2.742';agent_sha256=$consumer.agent_sha256;updater_sha256=$consumer.updater_sha256;launcher_sha256=$consumer.launcher_sha256;native_integrity_sha256=$consumer.native_integrity_sha256;config_sha256=$source.config_sha256;task_owner=$source.task_owner;uninstall=$source.uninstall}}
 Assert-Exact742FirstHopBinding $request $source $target
 $bad=$source.Clone();$bad.source_version='3.2.747';Reject {Assert-Exact742FirstHopBinding $request $bad $target}
 $bad=$source.Clone();$bad.job='other-job';Reject {Assert-Exact742FirstHopBinding $request $bad $target}
 $bad=$source.Clone();$bad.complete=$false;Reject {Assert-Exact742FirstHopBinding $request $bad $target}
 $bad=$request.Clone();$bad.expected_recovery=$request.expected_recovery.Clone();$bad.expected_recovery.version='3.2.747';Reject {Assert-Exact742FirstHopBinding $bad $source $target}
 $bad=$request.Clone();$bad.full_gate=$true;Reject {Assert-Exact742FirstHopBinding $bad $source $target}
 $bad=$target.Clone();$bad.binary_sha256=$consumer.agent_sha256;Reject {Assert-Exact742FirstHopBinding $request $source $bad}
 $bad=$target.Clone();$bad.baseline_updater_sha256=$consumer.updater_sha256;Reject {Assert-Exact742FirstHopBinding $request $source $bad}
 $journal=@{command_id='exact-command';version='3.2.747';stage='health_observation';installer_quiesced=$true}
 $ready=@{Journal=$journal;CommandId='exact-command';SourceExited=$true;SetupExited=$true;SetupExit=0;JobMembers=0;RawHash=$target.binary_sha256;Version='3.2.747';Registry=@(@{version='3.2.747'});TargetGenerationVerified=$true;TaskVerified=$true}
 Need (Test-Exact742LateHealthReady @ready) 'Actual late-health boundary was rejected'
 foreach($pair in @(@('SourceExited',$false),@('SetupExited',$false),@('SetupExit',9),@('JobMembers',1),@('RawHash',$consumer.agent_sha256),@('Version','3.2.742'),@('TargetGenerationVerified',$false),@('TaskVerified',$false),@('CommandId','other-command'))){$bad=$ready.Clone();$bad[$pair[0]]=$pair[1];Need (!(Test-Exact742LateHealthReady @bad)) 'Incomplete/raced boundary allowed injection'}
 $bad=$ready.Clone();$bad.Journal=$journal.Clone();$bad.Journal.stage='full_installer_upgrade';Need (!(Test-Exact742LateHealthReady @bad)) 'Early installer boundary allowed injection'
 $bad=$ready.Clone();$bad.Registry=@(@{version='3.2.742'});Need (!(Test-Exact742LateHealthReady @bad)) 'Registry not yet747 allowed injection'
 $before=@([ordered]@{key='product';version='3.2.742';location='C:\Program Files\FDSecurity';uninstall='source-uninstaller';quiet_uninstall='source-quiet'})
 $after=@($before[0].Clone());Assert-Exact742RegistryRestored $before $after
 $after[0].version='3.2.747';$frozen=$after|ConvertTo-Json -Compress
 Reject {Assert-Exact742RegistryRestored $before $after} 'registry_restoration_gap'
 Need (($after|ConvertTo-Json -Compress) -ceq $frozen) 'Registry validator repaired the failed state'
 Assert-Exact742RecoveredGeneration $true 100 200 'C:\Program Files\FDSecurity\FDSensor.exe' 'C:\Program Files\FDSecurity\FDSensor.exe'
 Reject {Assert-Exact742RecoveredGeneration $false 100 200 'C:\Program Files\FDSecurity\FDSensor.exe' 'C:\Program Files\FDSecurity\FDSensor.exe'}
 Reject {Assert-Exact742RecoveredGeneration $true 100 100 'C:\Program Files\FDSecurity\FDSensor.exe' 'C:\Program Files\FDSecurity\FDSensor.exe'}
 Reject {Assert-Exact742RecoveredGeneration $true 100 200 'C:\other.exe' 'C:\Program Files\FDSecurity\FDSensor.exe'}
 Need ((Convert-Exact742NativeFloor ([Text.Encoding]::ASCII.GetBytes('143479824'))) -eq 143479824) 'Native floor value changed'
 foreach($text in @('',"12`r`n",'-1','01','9007199254740992','12345678901234567','1x')){Reject {Convert-Exact742NativeFloor ([Text.Encoding]::ASCII.GetBytes($text))}}
 Write-Host "PASS: $count exact source-hop/late-health/recovery boundary assertions; no product execution"
}finally{foreach($key in $old.Keys){[Environment]::SetEnvironmentVariable($key,$old[$key],'Process')}}
