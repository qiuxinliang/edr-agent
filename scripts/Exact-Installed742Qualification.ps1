function Assert-Exact742ParametersUnchanged([string]$Path,[string]$ExpectedSha256) {
 $null=Assert-LifecycleStorageRegular $Path 65536
 if($ExpectedSha256 -cnotmatch '^[a-f0-9]{64}$' -or (Get-FileHash -LiteralPath $Path).Hash.ToLowerInvariant() -cne $ExpectedSha256){throw 'Qualification parameter file changed before Setup'}
}
function Invoke-Exact742Materialization([string]$SourceUpdater,[string]$LauncherScript,[string]$OutputDirectory) {
 # Reuse the authenticated original742 process-tree owner for this finite job.
 $tokens=$null;$errors=$null;$updaterAst=[Management.Automation.Language.Parser]::ParseFile($SourceUpdater,[ref]$tokens,[ref]$errors)
 $initializers=@($updaterAst.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Initialize-InstallerJobType'},$true))
 if(@($errors).Count -or $initializers.Count -ne 1){throw 'Original742 Job initializer is not unique/parseable'}
 . ([scriptblock]::Create($initializers[0].Extent.Text))
 Initialize-InstallerJobType
 $owner=$null;$first=$null
 $materialization=@{scope='test-only fixture initialization';limit_ms=20000;tree_empty=$false;exit_code=$null;first_failure=$null;cleanup_failure=$null}
 try{
  $owner=[FDSecurity.InstallerJob]::Create('Global\Exact742.Materialize.'+[Guid]::NewGuid().ToString('N'))
  $owner.Launch((Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'),('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$launcherScript+'"'),$OutputDirectory)
  if(!$owner.WaitForEmpty(20000)){throw 'Original742 launcher materialization exceeded20s'}
  $materialization.tree_empty=$true;$materialization.exit_code=$owner.ExitCode()
  if($materialization.exit_code -ne 0){throw 'Original742 launcher materialization failed'}
 }catch{$first=$_;$materialization.first_failure=$_.Exception.Message}
 finally{
  if($owner){
   try{$owner.StopAndDrain(5000);$materialization.tree_empty=$owner.WaitForEmpty(0);if(!$materialization.tree_empty){throw 'Materialization process tree exit unconfirmed'}}
   catch{$materialization.cleanup_failure=$_.Exception.Message;if(!$first){$first=$_;$materialization.first_failure=$_.Exception.Message}}
   finally{try{$owner.Dispose()}catch{if(!$materialization.cleanup_failure){$materialization.cleanup_failure=$_.Exception.Message};if(!$first){$first=$_;$materialization.first_failure=$_.Exception.Message}}}
  }
  try{$materialization|ConvertTo-Json|Set-Content (Join-Path $OutputDirectory 'exact742-materialization-result.json') -Encoding UTF8}catch{if(!$first){$first=$_}else{Write-Warning 'Cannot save materialization receipt; first failure preserved'}}
 }
 if($first){throw $first}
}
# Test-only fixture initialization. Never used on endpoints or during recovery.
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
 $required=@('source_setup','target_setup','source_fixture_updater','source_fixture_task_owner','source_manifest','source_cms','source_proof','target_manifest','target_cms','target_proof','source_runtime_archive')
 $seen=@{}
 foreach($binding in $Fixture.file_bindings){
  if($binding.role -cnotin $required -or $seen.ContainsKey($binding.role) -or $binding.sha256 -cnotmatch '^[a-f0-9]{64}$'){throw 'Exact qualification file-binding set is invalid'}
  $null=Assert-LifecycleStorageRegular $binding.path 16777216
  if((Get-FileHash -LiteralPath $binding.path).Hash.ToLowerInvariant() -cne $binding.sha256){throw 'Staged qualification input changed'}
  $seen[$binding.role]=[IO.Path]::GetFullPath($binding.path)
 }
 if($seen.Count -ne $required.Count){throw 'Exact qualification input binding missing'}
 foreach($pair in @(@('source_setup','source_setup_exe'),@('target_setup','target_setup_exe'),@('source_fixture_updater','source_fixture_updater'),@('source_fixture_task_owner','source_fixture_task_owner'),@('source_proof','source_publisher_proof'),@('target_proof','target_publisher_proof'))){if($seen[$pair[0]] -ine [IO.Path]::GetFullPath($Fixture.($pair[1]))){throw 'Qualification role points to different file'}}
}
function Get-Exact742LauncherProcesses {
 $launcher=Join-Path $InstallDir 'FDSensorTaskLaunch.ps1'
 return @(Get-CimInstance Win32_Process -Filter "Name='powershell.exe' OR Name='pwsh.exe'" | Where-Object {$_.CommandLine -and $_.CommandLine.IndexOf($launcher,[StringComparison]::OrdinalIgnoreCase) -ge 0} | Select-Object ProcessId,CreationDate)
}
function Invoke-Exact742Qualification($Fixture) {
 Assert-Exact742FileBindings $Fixture
 $null=Assert-LifecycleStorageRegular $Fixture.source_publisher_proof 8192
 $proof=[IO.File]::ReadAllText($Fixture.source_publisher_proof)|ConvertFrom-Json
 if($proof.schema -cne 'edr.windows.publisher-verification.v1' -or $proof.version -cne '3.2.742' -or $proof.arch -cne 'arm64' -or $proof.artifact_sha256 -cne $Fixture.source_installed_agent_sha256 -or $proof.manifest_sha256 -cne '32b77e511853047a87f43c75d7c739f8f3be467fc57374cf2cce5fc65efa73be' -or $proof.signature_sha256 -cne '3ec9d6a9bf4ce1c3f1762847f7e6c70b15f202596f9acdabf9862a102779f519' -or $proof.thumbprint -cne '01BB4E940A8E9CD5C09DEE81F17B5FB016750C3F' -or $proof.subject_der_sha256 -cne 'fb7a1b9fa95054b69d11e982bc77c6bb78f778b7e85943b3d1b198923d172a8a' -or $proof.verifier_source_commit -cne 'c59eda045e3e2b9c882d462b74533e2c4b6c45da'){throw 'Source742 production publisher proof binding mismatch'}
 Assert-Exact742ProgramHash $Fixture.source_setup_exe '6122591c151953e0416ca70815f4c437e62425cd1f5f48676087b25e32783c92'
 Assert-Exact742ProgramHash $Fixture.source_fixture_updater $Fixture.source_installed_updater_sha256
 Assert-Exact742ProgramHash $Fixture.source_fixture_task_owner 'e8795f44ac8727dc99eebdaf3c696678340e1fe4b32ec8e9e0d5acfadd2bca9a'
 $signature=Get-AuthenticodeSignature -LiteralPath $Fixture.source_setup_exe
 if([string]$signature.Status -cne 'Valid' -or !$signature.TimeStamperCertificate -or $signature.SignerCertificate.Thumbprint -cne '01BB4E940A8E9CD5C09DEE81F17B5FB016750C3F'){throw 'Source742 Setup publisher/timestamp is invalid'}
 $integrity=Join-Path $Fixture.source_runtime_directory 'native-package-integrity.json'
 Assert-Exact742ProgramHash $integrity '5399c68ef8860199c2efccc4ece6b8e489b01cd7e6f89cfe582df3332e4f37f9'
 $originalIntegrityHash=(Get-FileHash $integrity).Hash.ToLowerInvariant()
 $null=Initialize-LifecycleOfflineConfig $BaselineConfigTemplate
 Assert-Exact742ParametersUnchanged $ExactInstalledTransitionInput $ExactInstalledTransitionInputSha256
 Assert-Exact742FileBindings $Fixture
 Invoke-Installer $Fixture.source_setup_exe 'exact742-source-setup-bootstrap' $false
 Assert-InstalledRuntime '3.2.742' 'exact742-source-setup-output' $true $true
 Assert-Exact742ProgramHash (Join-Path $InstallDir 'FDSensor.exe') $Fixture.source_installed_agent_sha256
 Assert-Exact742Integrity $InstallDir $originalIntegrityHash
 $setupOutput=@{updater_sha256=(Get-FileHash (Join-Path $InstallDir 'edr_agent_inplace_update.ps1')).Hash.ToLowerInvariant();launcher_sha256=(Get-FileHash (Join-Path $InstallDir 'FDSensorTaskLaunch.ps1')).Hash.ToLowerInvariant();native_integrity_sha256=$originalIntegrityHash}
 $setupOutput|ConvertTo-Json|Set-Content (Join-Path $EvidenceDir 'exact742-actual-setup-output.json') -Encoding UTF8
 # Only disposable fixture initialization may normalize source-script bytes.
 # This is never a recovery operation and is not described as Setup output.
 Stop-ScheduledTask -TaskName FDSecurityAgent -TaskPath '\'
 $deadline=[DateTime]::UtcNow.AddSeconds(20)
 do{$remaining=@(Get-LifecycleAgentProcesses);$launchers=@(Get-Exact742LauncherProcesses);$taskRunning=(Get-ScheduledTask -TaskName FDSecurityAgent -TaskPath '\').State -eq 'Running';if(!$remaining.Count -and !$launchers.Count -and !$taskRunning){break};Start-Sleep -Milliseconds 200}while([DateTime]::UtcNow -lt $deadline)
 if($remaining.Count -or $launchers.Count -or $taskRunning){throw 'Source742 bootstrap owner/process did not exit before fixture initialization'}
 Assert-Exact742ProgramHash $Fixture.source_fixture_updater $Fixture.source_installed_updater_sha256
 Assert-Exact742ProgramHash $Fixture.source_fixture_task_owner 'e8795f44ac8727dc99eebdaf3c696678340e1fe4b32ec8e9e0d5acfadd2bca9a'
 Copy-Item -LiteralPath $Fixture.source_fixture_updater -Destination (Join-Path $InstallDir 'edr_agent_inplace_update.ps1') -Force
 $tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($Fixture.source_fixture_task_owner,[ref]$tokens,[ref]$errors)
 if(@($errors).Count){throw 'Original742 task-owner parser failure'}
 $definitions=@();foreach($name in @('Quote-ForSingleQuotedPowerShell','Write-TaskLauncher')){$nodes=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$true));if($nodes.Count -ne 1){throw 'Original742 task-owner function is not unique'};$definitions+=$nodes[0].Extent.Text}
 $launcherScript=Join-Path $EvidenceDir 'exact742-materialize-launcher.ps1'
 $call="`nWrite-TaskLauncher -Exe 'C:\Program Files\FDSecurity\FDSensor.exe' -Config 'C:\Program Files\FDSecurity\agent.toml' -Dir 'C:\Program Files\FDSecurity' | Out-Null"
 [IO.File]::WriteAllText($launcherScript,($definitions -join "`n")+$call,[Text.UTF8Encoding]::new($false))
 Invoke-Exact742Materialization $Fixture.source_fixture_updater $launcherScript $EvidenceDir
 foreach($pair in @(@('FDSensor.exe',$Fixture.source_installed_agent_sha256),@('edr_agent_inplace_update.ps1',$Fixture.source_installed_updater_sha256),@('FDSensorTaskLaunch.ps1',$Fixture.source_installed_launcher_sha256))){Assert-Exact742ProgramHash (Join-Path $InstallDir $pair[0]) $pair[1]}
 Assert-Exact742Integrity $InstallDir $originalIntegrityHash
 Start-ScheduledTask -TaskName FDSecurityAgent -TaskPath '\'
 Assert-InstalledRuntime '3.2.742' 'exact742-constructed-consumer' $true $true
 foreach($pair in @(@('FDSensor.exe',$Fixture.source_installed_agent_sha256),@('edr_agent_inplace_update.ps1',$Fixture.source_installed_updater_sha256),@('FDSensorTaskLaunch.ps1',$Fixture.source_installed_launcher_sha256))){Assert-Exact742ProgramHash (Join-Path $InstallDir $pair[0]) $pair[1]}
 Assert-Exact742Integrity $InstallDir $originalIntegrityHash
 @{schema='edr.exact-installed742.qualification-result.v1';complete=$true;qualification_only=$true;full_gate=$false;full_gate_passed=$false;deployment_authorized=$false;scope='qualification-only; no first-hop upgrade, fault, recovery or full Setup rollback performed';setup_output=$setupOutput;fixture_initialization='b307 exact LF updater and original owner launcher; signed media unchanged';source_version='3.2.742';task_owner=(Get-LifecycleRuntimeOwner)}|ConvertTo-Json -Depth 8|Set-Content (Join-Path $EvidenceDir 'exact742-qualification.json') -Encoding UTF8
}
