# Test-only validation and definition reuse; never executes imported script bodies.
function Import-Exact742TestDefinitions {
 $repo=Split-Path -Parent $PSScriptRoot
 . (Join-Path $repo 'scripts/Start-LifecycleWindowsPowerShell.ps1')
 . (Join-Path $PSScriptRoot 'Invoke-LifecycleStorageCompatibility.ps1')
 . (Join-Path $repo 'scripts/Exact-Installed742Qualification.ps1')
 $sources=@(
  @{path=(Join-Path $repo 'scripts/windows_setup_exe_lifecycle_smoke.ps1');names=@('Get-LifecycleAgentProcesses','Open-LifecycleAgentProcess','Get-LifecycleUpdaterIdentity','Get-LifecycleStoragePreflight','Get-LifecycleRuntimeProcess','Get-LifecycleTaskDefinition','Get-LifecycleRuntimeOwner','Get-LifecycleTrustedPublisher','Assert-LifecyclePublisherProtocol')},
  @{path=(Join-Path $PSScriptRoot 'Invoke-RealInstallerTimeoutRecovery.ps1');names=@('Read-RecoveryJournal','Assert-RecoveryFiles')}
 )
 foreach($source in $sources){
  $tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($source.path,[ref]$tokens,[ref]$errors)
  if(@($errors).Count){throw 'Existing lifecycle helper source does not parse'}
  foreach($name in $source.names){
   $nodes=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$true))
   if($nodes.Count -ne 1){throw ('Existing lifecycle definition is not unique: '+$name)}
   # Caller dot-sources this function, so definitions stay only in this test process.
   . ([scriptblock]::Create($nodes[0].Extent.Text))
  }
  if($source.path -like '*Invoke-RealInstallerTimeoutRecovery.ps1'){
   $classes=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.StringConstantExpressionAst] -and $n.Value.Contains('public static class LifecycleInstallerFault')},$true))
   if($classes.Count -ne 1){throw 'Existing lifecycle handle helper is not unique'}
   Add-Type -TypeDefinition $classes[0].Value
  }
 }
}
function Read-Exact742BoundJson([string]$Path,[string]$Sha256) {
 $null=Assert-LifecycleStorageRegular $Path 1048576
 if($Sha256 -cnotmatch '^[a-f0-9]{64}$' -or (Get-FileHash $Path).Hash.ToLowerInvariant() -cne $Sha256){throw 'Exact first-hop input digest mismatch'}
 return ([IO.File]::ReadAllText($Path)|ConvertFrom-Json)
}
function Assert-Exact742FirstHopBinding($Request,$Source,$Target) {
 if($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or $env:RUNNER_ARCH -cne 'ARM64' -or
  $Request.schema -cne 'edr.exact742-to747.first-hop.v1' -or $Source.schema -cne 'edr.exact-installed742.qualification-result.v1' -or
  $Source.complete -ne $true -or $Source.qualification_only -ne $true -or $Source.full_gate_passed -ne $false -or $Source.deployment_authorized -ne $false -or
  $Source.source_setup_sha256 -cne '6122591c151953e0416ca70815f4c437e62425cd1f5f48676087b25e32783c92' -or
  $Target.schema -cne 'edr.windows.lifecycle-upgrade.v1' -or $Target.baseline_version -cne '3.2.742' -or $Target.target_version -cne '3.2.747' -or
  $Target.deployment_mode -cne 'service' -or $Target.service_name -cne 'FDSecurityAgent' -or $Target.architecture -cne 'arm64' -or $Target.signature_status -cne 'signed' -or $Target.upgrade_class -cne 'installer_required' -or
  $Target.binary_sha256 -cne 'c1ea2133d925ff688dd6f15419ecd5dd2065525466e78b8a44c51212a6464fd0' -or -not $Target.publisher_subject_der_sha256 -or -not $Target.runtime_package){throw 'Exact742 source/target first-hop identity mismatch'}
 foreach($pair in @(@('harness_commit',$env:GITHUB_SHA),@('run_id',$env:GITHUB_RUN_ID),@('run_attempt',$env:GITHUB_RUN_ATTEMPT),@('job',$env:GITHUB_JOB))){if(!$pair[1] -or $Source.($pair[0]) -cne $pair[1] -or $Request.harness.($pair[0]) -cne $pair[1]){throw 'Exact first-hop qualification is not from this job'}}
 if($Source.runner_environment -cne 'github-hosted' -or $Source.architecture -cne 'arm64' -or $Source.target_version -cne '3.2.747' -or $Request.install_dir -cne 'C:\Program Files\FDSecurity' -or $Request.architecture -cne 'arm64' -or $Request.runtime_mode -cne 'scheduled_task' -or $Request.full_gate -ne $false -or $Request.deployment_authorized -ne $false -or $Request.old_full_setup_rollback_supported -ne $false -or $Request.target_agent_sha256 -cne $Target.binary_sha256){throw 'Exact first-hop scope differs from the fixed hosted task case'}
 if($Source.harness_commit -cnotmatch '^[a-f0-9]{40}$' -or $Source.run_id -cnotmatch '^[1-9][0-9]*$' -or $Source.run_attempt -cnotmatch '^[1-9][0-9]*$'){throw 'Exact first-hop harness identity format is invalid'}
 $consumer=$Source.consumer_identity
 if($consumer.install_dir -cne 'C:\Program Files\FDSecurity' -or $consumer.runtime_mode -cne 'scheduled_task' -or $Source.source_version -cne '3.2.742' -or
  $consumer.agent_sha256 -cne 'e6ea9736829d0c0be5284c570f198ec888bcaad1845a074ea8838ebf6b326dbe' -or
  $consumer.updater_sha256 -cne 'cae170855648559201c20b62d2d72d1bf2f030b61f5fda8ba27aa7534bd7a183' -or
  $consumer.launcher_sha256 -cne '656d349640d5403af0881bb5db7a4811074450cb93b6602c1322f03edfafd8c3' -or
  $consumer.native_integrity_sha256 -cne '5399c68ef8860199c2efccc4ece6b8e489b01cd7e6f89cfe582df3332e4f37f9' -or
  $Request.source_updater_path -ine (Join-Path $consumer.install_dir 'edr_agent_inplace_update.ps1') -or
  $Request.packaged_source_runtime_sha256 -cne '35068437d8fc507a7146dc603cea15d900d388a4edfc3c829a3aaae3c76eede7' -or
  $Request.packaged_source_updater_sha256 -cne '88912072d0e842bb07c1ee730b91233f39e0e8dad57e403990c702bda58edc2a' -or $Target.baseline_updater_sha256 -cne $Request.packaged_source_updater_sha256){throw 'Exact installed source consumer differs from authenticated Setup output'}
 if($Request.expected_recovery.version -cne '3.2.742' -or $Request.expected_recovery.agent_sha256 -cne $consumer.agent_sha256 -or $Request.expected_recovery.updater_sha256 -cne $consumer.updater_sha256 -or $Request.expected_recovery.launcher_sha256 -cne $consumer.launcher_sha256 -or $Request.expected_recovery.config_sha256 -cne $Source.config_sha256 -or $Request.expected_recovery.native_integrity_sha256 -cne $consumer.native_integrity_sha256 -or ($Request.expected_recovery.task_owner|ConvertTo-Json -Depth 8 -Compress) -cne ($Source.task_owner|ConvertTo-Json -Depth 8 -Compress) -or ($Request.expected_recovery.uninstall|ConvertTo-Json -Depth 8 -Compress) -cne ($Source.uninstall|ConvertTo-Json -Depth 8 -Compress)){throw 'Expected recovery must remain the original742 consumer'}
}
function Get-Exact742RegistryState {
 return @(@('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*') | ForEach-Object {Get-ItemProperty -Path $_ -ErrorAction SilentlyContinue} | Where-Object {$_.InstallLocation -and ([string]$_.InstallLocation).TrimEnd('\') -ieq $InstallDir.TrimEnd('\')} | Sort-Object PSPath | ForEach-Object {[ordered]@{key=$_.PSChildName;version=$_.DisplayVersion;location=$_.InstallLocation;uninstall=$_.UninstallString;quiet_uninstall=$_.QuietUninstallString}})
}
function Assert-Exact742RegistryRestored($Before,$After) {
 if(@($Before).Count -ne 1 -or @($After).Count -ne 1 -or $Before[0].version -cne '3.2.742' -or ($Before|ConvertTo-Json -Depth 5 -Compress) -cne ($After|ConvertTo-Json -Depth 5 -Compress)){throw 'registry_restoration_gap: original742 uninstall registration was not restored'}
}
function Test-Exact742LateHealthReady($Journal,[string]$CommandId,[bool]$SourceExited,[bool]$SetupExited,[int]$SetupExit,[int]$JobMembers,[string]$RawHash,[string]$Version,$Registry,[bool]$TargetGenerationVerified,[bool]$TaskVerified) {
 return ($Journal -and $Journal.command_id -ceq $CommandId -and $Journal.version -ceq '3.2.747' -and $Journal.stage -ceq 'health_observation' -and
  $Journal.installer_quiesced -eq $true -and $SourceExited -and $SetupExited -and $SetupExit -eq 0 -and $JobMembers -eq 0 -and
  $RawHash -ceq 'c1ea2133d925ff688dd6f15419ecd5dd2065525466e78b8a44c51212a6464fd0' -and $Version -ceq '3.2.747' -and
  @($Registry).Count -eq 1 -and $Registry[0].version -ceq '3.2.747' -and $TargetGenerationVerified -and $TaskVerified)
}
function Convert-Exact742NativeFloor([byte[]]$Bytes) {
 if(!$Bytes -or $Bytes.Length -gt 16 -or @($Bytes|Where-Object {$_ -lt 48 -or $_ -gt 57}).Count){throw 'Native storage floor must be bounded ASCII digits'}
 $raw=[Text.Encoding]::ASCII.GetString($Bytes);[UInt64]$value=0
 if($raw -cnotmatch '^(0|[1-9][0-9]*)$' -or ![UInt64]::TryParse($raw,[ref]$value) -or $value -gt 9007199254740991){throw 'Native storage floor is invalid'}
 return $value
}
function Read-Exact742NativeFloor([string]$Destination,[ValidateSet('e6ea9736829d0c0be5284c570f198ec888bcaad1845a074ea8838ebf6b326dbe','c1ea2133d925ff688dd6f15419ecd5dd2065525466e78b8a44c51212a6464fd0')][string]$ExpectedAgentSha256='e6ea9736829d0c0be5284c570f198ec888bcaad1845a074ea8838ebf6b326dbe') {
 # Same original CLI and finite20s/5s contract as the verified native floor reader.
 $exe=Join-Path $InstallDir 'FDSensor.exe';$config=Join-Path $InstallDir 'agent.toml'
 Assert-Exact742ProgramHash $exe $ExpectedAgentSha256
 $configHash=(Get-FileHash $config).Hash.ToLowerInvariant()
 $directory=Join-Path $InstallDir ('.storage-preflight-'+[Guid]::NewGuid().ToString('N'));New-Item -ItemType Directory $directory|Out-Null
 $output=Join-Path $directory 'floor';$process=$null;$first=$null;$record=$null;$cleanupFailure=$null
 $start=New-Object Diagnostics.ProcessStartInfo;$start.FileName=$exe;$start.WorkingDirectory=$InstallDir;$start.UseShellExecute=$false;$start.CreateNoWindow=$true;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
 $start.Arguments='--storage-space-preflight --config "'+$config+'" --output "'+$output+'"'
 try{
  $process=[Diagnostics.Process]::Start($start);$null=$process.Handle
  $stdout=$process.StandardOutput.ReadToEndAsync();$stderr=$process.StandardError.ReadToEndAsync()
  if(!$process.WaitForExit(20000)){throw 'Native signed-Agent storage authority exceeded20s'}
  if(![Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($stdout,$stderr),5000)){throw 'Native storage preflight output drain exceeded5s'}
  if($stdout.Result.Length+$stderr.Result.Length -gt 65536){throw 'Native storage authority output exceeds64KiB'}
  [IO.File]::WriteAllText((Join-Path $Destination 'native-floor.stdout.log'),$stdout.Result,[Text.UTF8Encoding]::new($false))
  [IO.File]::WriteAllText((Join-Path $Destination 'native-floor.stderr.log'),$stderr.Result,[Text.UTF8Encoding]::new($false))
  if($process.ExitCode -ne 0){throw ('Native signed-Agent storage authority rejected with exit '+$process.ExitCode)}
  $null=Assert-LifecycleStorageRegular $output 16
  $bytes=[IO.File]::ReadAllBytes($output);$floor=Convert-Exact742NativeFloor $bytes
  if((Get-FileHash $config).Hash.ToLowerInvariant() -cne $configHash){throw 'Configuration changed during native storage preflight'}
  Assert-Exact742ProgramHash $exe $ExpectedAgentSha256
  [IO.File]::WriteAllBytes((Join-Path $Destination 'native-floor.txt'),$bytes)
  $record=@{floor_bytes=$floor;output_sha256=(Get-FileHash $output).Hash.ToLowerInvariant();exe_sha256=$ExpectedAgentSha256;config_sha256=$configHash;role='storage_space_preflight';pid=$process.Id;birth_filetime=$process.StartTime.ToFileTimeUtc();observation='directly started exact preflight arguments; retained Process handle confirmed exit';exit_code=$process.ExitCode;parent_pid=$PID;limit_ms=20000}
 }catch{$first=$_}
 finally{
  if($process){
   try{if(!$process.HasExited){$process.Kill();if(!$process.WaitForExit(5000)){throw 'Native storage preflight exit unconfirmed'}}}catch{$cleanupFailure=$_.Exception.Message;if(!$first){$first=$_}}
   finally{try{$process.Dispose()}catch{if(!$cleanupFailure){$cleanupFailure=$_.Exception.Message};if(!$first){$first=$_}}}
  }
  if(!$first){try{Remove-Item -LiteralPath $directory -Recurse -Force}catch{$first=$_;$cleanupFailure=$_.Exception.Message}}
  $diagnostic=@{complete=(!$first);native=$record;first_failure=$(if($first){$first.Exception.Message}else{$null});cleanup_failure=$cleanupFailure;temporary_output_directory=$directory}
  try{$diagnostic|ConvertTo-Json -Depth 5|Set-Content (Join-Path $Destination 'native-floor-result.json') -Encoding UTF8}catch{if(!$first){$first=$_}else{Write-Warning 'Cannot save native floor receipt; first failure preserved'}}
 }
 if($first){throw $first}
 return $record
}
function Assert-Exact742RecoveredGeneration([bool]$TargetExited,[long]$TargetBirth,[long]$RecoveredBirth,[string]$RecoveredImage,[string]$ExpectedImage) {
 if(!$TargetExited -or $RecoveredBirth -le $TargetBirth -or $RecoveredImage -ine $ExpectedImage){throw 'Original742 recovery did not replace the injected747 process generation'}
}
