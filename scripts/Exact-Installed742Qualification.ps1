function Assert-Exact742ParametersUnchanged([string]$Path,[string]$ExpectedSha256) {
 $null=Assert-LifecycleStorageRegular $Path 65536
 if($ExpectedSha256 -cnotmatch '^[a-f0-9]{64}$' -or (Get-FileHash -LiteralPath $Path).Hash.ToLowerInvariant() -cne $ExpectedSha256){throw 'Qualification parameter file changed before Setup'}
}
# Test-only qualification of the actual signed Setup output. No fixture program writes.
function Assert-Exact742QualificationContract($InputBinding,[string]$RequestedInstallDir,[string]$RequestedArchitecture,[string]$RequestedMode,[string]$RequestedServiceName) {
 if($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or $env:RUNNER_ARCH -cne 'ARM64' -or
    $InputBinding.schema -cne 'edr.exact-installed-742-to-747.inputs.v1' -or $InputBinding.source_version -cne '3.2.742' -or $InputBinding.target_version -cne '3.2.747' -or
    $RequestedServiceName -cne 'FDSecurityAgent' -or $RequestedArchitecture -cne 'arm64' -or $InputBinding.architecture -cne 'arm64' -or $RequestedMode -cne 'scheduled_task' -or $InputBinding.runtime_mode -cne 'scheduled_task' -or
    $RequestedInstallDir -cne 'C:\Program Files\FDSecurity' -or $InputBinding.old_full_setup_rollback_supported -ne $false){throw 'Exact742 qualification requires clean hosted ARM task fixture and explicit no-full-Setup-rollback scope'}
 foreach($pair in @(@('source_installed_agent_sha256','e6ea9736829d0c0be5284c570f198ec888bcaad1845a074ea8838ebf6b326dbe'),@('source_installed_updater_sha256','cae170855648559201c20b62d2d72d1bf2f030b61f5fda8ba27aa7534bd7a183'),@('source_installed_launcher_sha256','656d349640d5403af0881bb5db7a4811074450cb93b6602c1322f03edfafd8c3'))){if($InputBinding.($pair[0]) -cne $pair[1]){throw 'Exact installed742 consumer identity mismatch'}}
}
function Assert-Exact742CleanHost {
 if(Test-Path -LiteralPath $InstallDir){throw 'Exact742 standard installation directory is occupied'}
 if(Get-ScheduledTask -TaskName FDSecurityAgent -ErrorAction SilentlyContinue){throw 'Exact742 task already exists'}
 if(Get-Service -Name FDSecurityAgent -ErrorAction SilentlyContinue){throw 'Exact742 service already exists'}
 foreach($key in @('HKLM:\SOFTWARE\FDSecurity','HKLM:\SOFTWARE\WOW6432Node\FDSecurity','HKLM:\SYSTEM\CurrentControlSet\Services\FDSecurityAgent','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{A73C1E7F-8D94-4A2C-BF5D-1E2F3A4B5C6D}_is1','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{A73C1E7F-8D94-4A2C-BF5D-1E2F3A4B5C6D}_is1')){if(Test-Path -LiteralPath $key){throw 'Exact742 product registry already exists'}}
 if(Get-Process FDSensor -ErrorAction SilentlyContinue){throw 'Exact742 Agent process already exists'}
}
function Assert-Exact742ProgramHash([string]$Path,[string]$Expected) {
 $null=Assert-LifecycleStorageRegular $Path 16777216
 if((Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $Expected){throw ('Exact742 program digest mismatch: '+[IO.Path]::GetFileName($Path))}
}
function Assert-Exact742Integrity([string]$Runtime,[string]$OriginalIntegrityHash) {
 $path=Join-Path $Runtime 'native-package-integrity.json'
 if((Get-FileHash $path).Hash.ToLowerInvariant() -cne $OriginalIntegrityHash){throw 'Fixture changed original signed native integrity metadata'}
 $data=[IO.File]::ReadAllText($path)|ConvertFrom-Json
 foreach($entry in $data.files){
  if([IO.Path]::IsPathRooted($entry.name) -or $entry.name -match '(^|[/\\])\.\.([/\\]|$)'){throw 'Unsafe native integrity member'}
  $file=Join-Path $Runtime $entry.name;$null=Assert-LifecycleStorageRegular $file
  if((Get-FileHash $file).Hash.ToLowerInvariant() -cne $entry.sha256){throw ('Fixture native integrity mismatch: '+$entry.name)}
 }
}
function Assert-Exact742FileBindings($Fixture) {
 $required=@('source_setup','target_setup','source_manifest','source_cms','source_proof','target_manifest','target_cms','target_proof','source_runtime_archive')
 $seen=@{}
 foreach($binding in $Fixture.file_bindings){
  if($binding.role -cnotin $required -or $seen.ContainsKey($binding.role) -or $binding.sha256 -cnotmatch '^[a-f0-9]{64}$'){throw 'Exact qualification file-binding set is invalid'}
  $null=Assert-LifecycleStorageRegular $binding.path 16777216
  if((Get-FileHash -LiteralPath $binding.path).Hash.ToLowerInvariant() -cne $binding.sha256){throw 'Staged qualification input changed'}
  $seen[$binding.role]=[IO.Path]::GetFullPath($binding.path)
 }
 if($seen.Count -ne $required.Count){throw 'Exact qualification input binding missing'}
 foreach($pair in @(@('source_setup','source_setup_exe'),@('target_setup','target_setup_exe'),@('source_proof','source_publisher_proof'),@('target_proof','target_publisher_proof'))){if($seen[$pair[0]] -ine [IO.Path]::GetFullPath($Fixture.($pair[1]))){throw 'Qualification role points to different file'}}
}
function Get-Exact742UninstallRegistration([string]$ExpectedVersion) {
 $entries=@(@('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*') | ForEach-Object {Get-ItemProperty -Path $_ -ErrorAction SilentlyContinue} | Where-Object {$_.InstallLocation -and ([string]$_.InstallLocation).TrimEnd('\') -ieq $InstallDir.TrimEnd('\')} | Sort-Object PSPath | ForEach-Object {[ordered]@{key=$_.PSChildName;version=$_.DisplayVersion;location=$_.InstallLocation;uninstall=$_.UninstallString;quiet_uninstall=$_.QuietUninstallString}})
 if($entries.Count -ne 1 -or $entries[0].version -cne $ExpectedVersion){throw 'Exact installed-consumer uninstall registration version mismatch'}
 return $entries[0]
}
function Invoke-Exact742Qualification($Fixture) {
 Assert-Exact742FileBindings $Fixture
 $null=Assert-LifecycleStorageRegular $Fixture.source_publisher_proof 8192
 $proof=[IO.File]::ReadAllText($Fixture.source_publisher_proof)|ConvertFrom-Json
 if($proof.schema -cne 'edr.windows.publisher-verification.v1' -or $proof.version -cne '3.2.742' -or $proof.arch -cne 'arm64' -or $proof.artifact_sha256 -cne $Fixture.source_installed_agent_sha256 -or $proof.manifest_sha256 -cne '32b77e511853047a87f43c75d7c739f8f3be467fc57374cf2cce5fc65efa73be' -or $proof.signature_sha256 -cne '3ec9d6a9bf4ce1c3f1762847f7e6c70b15f202596f9acdabf9862a102779f519' -or $proof.thumbprint -cne '01BB4E940A8E9CD5C09DEE81F17B5FB016750C3F' -or $proof.subject_der_sha256 -cne 'fb7a1b9fa95054b69d11e982bc77c6bb78f778b7e85943b3d1b198923d172a8a' -or $proof.verifier_source_commit -cne 'c59eda045e3e2b9c882d462b74533e2c4b6c45da'){throw 'Source742 production publisher proof binding mismatch'}
 Assert-Exact742ProgramHash $Fixture.source_setup_exe '6122591c151953e0416ca70815f4c437e62425cd1f5f48676087b25e32783c92'
 $signature=Get-AuthenticodeSignature -LiteralPath $Fixture.source_setup_exe
 if([string]$signature.Status -cne 'Valid' -or !$signature.TimeStamperCertificate -or $signature.SignerCertificate.Thumbprint -cne '01BB4E940A8E9CD5C09DEE81F17B5FB016750C3F'){throw 'Source742 Setup publisher/timestamp is invalid'}
 $integrity=Join-Path $Fixture.source_runtime_directory 'native-package-integrity.json'
 Assert-Exact742ProgramHash $integrity '5399c68ef8860199c2efccc4ece6b8e489b01cd7e6f89cfe582df3332e4f37f9'
 $originalIntegrityHash=(Get-FileHash $integrity).Hash.ToLowerInvariant()
 $configHash=Initialize-LifecycleOfflineConfig $BaselineConfigTemplate
 Assert-Exact742ParametersUnchanged $ExactInstalledTransitionInput $ExactInstalledTransitionInputSha256
 Assert-Exact742FileBindings $Fixture
 Invoke-Installer $Fixture.source_setup_exe 'exact742-source-setup-bootstrap' $false
 Assert-InstalledRuntime '3.2.742' 'exact742-source-setup-output' $true $true
 Assert-Exact742ProgramHash (Join-Path $InstallDir 'FDSensor.exe') $Fixture.source_installed_agent_sha256
 Assert-Exact742Integrity $InstallDir $originalIntegrityHash
 $setupOutput=@{updater_sha256=(Get-FileHash (Join-Path $InstallDir 'edr_agent_inplace_update.ps1')).Hash.ToLowerInvariant();launcher_sha256=(Get-FileHash (Join-Path $InstallDir 'FDSensorTaskLaunch.ps1')).Hash.ToLowerInvariant();native_integrity_sha256=$originalIntegrityHash}
 $setupOutput|ConvertTo-Json|Set-Content (Join-Path $EvidenceDir 'exact742-actual-setup-output.json') -Encoding UTF8
 foreach($pair in @(@('FDSensor.exe',$Fixture.source_installed_agent_sha256),@('edr_agent_inplace_update.ps1',$Fixture.source_installed_updater_sha256),@('FDSensorTaskLaunch.ps1',$Fixture.source_installed_launcher_sha256))){Assert-Exact742ProgramHash (Join-Path $InstallDir $pair[0]) $pair[1]}
 Assert-Exact742Integrity $InstallDir $originalIntegrityHash
 if((Get-FileHash (Join-Path $InstallDir 'agent.toml')).Hash.ToLowerInvariant() -cne $configHash){throw 'Signed742 Setup changed synthetic configuration identity'}
 $registration=Get-Exact742UninstallRegistration '3.2.742'
 @{schema='edr.exact-installed742.qualification-result.v1';complete=$true;qualification_only=$true;full_gate=$false;full_gate_passed=$false;deployment_authorized=$false;scope='qualification-only; no first-hop upgrade, fault, recovery or full Setup rollback performed';setup_output=$setupOutput;fixture_initialization='actual signed742 Setup output; no source script replacement, task restart or integrity rewrite';config_sha256=$configHash;uninstall=$registration;source_version='3.2.742';source_setup_sha256=(Get-FileHash $Fixture.source_setup_exe).Hash.ToLowerInvariant();consumer_identity=@{install_dir=$InstallDir;runtime_mode=$RuntimeMode;agent_sha256=(Get-FileHash (Join-Path $InstallDir 'FDSensor.exe')).Hash.ToLowerInvariant();updater_sha256=$setupOutput.updater_sha256;launcher_sha256=$setupOutput.launcher_sha256;native_integrity_sha256=$originalIntegrityHash};task_owner=(Get-LifecycleRuntimeOwner)}|ConvertTo-Json -Depth 8|Set-Content (Join-Path $EvidenceDir 'exact742-qualification.json') -Encoding UTF8
}
