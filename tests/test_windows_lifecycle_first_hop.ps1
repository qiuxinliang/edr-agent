#Requires -Version 5.1
[CmdletBinding()]
param([string]$RepoRoot = (Split-Path -Parent $PSScriptRoot))

# Run the real lifecycle orchestration functions; synthetic child updaters are
# the only external boundary. No service, task, installed Agent or real package
# is used by this regression.
$ErrorActionPreference = 'Stop'
$root = Join-Path ([IO.Path]::GetTempPath()) ('edr-upgrade-stability-ci-' + [Guid]::NewGuid().ToString('N'))
$savedProgramData = $env:ProgramData
$savedModulePath = [Environment]::GetEnvironmentVariable('PSModulePath', [EnvironmentVariableTarget]::Process)
New-Item -ItemType Directory -Path $root | Out-Null
function Check([bool]$Condition, [string]$Name) { if (-not $Condition) { throw "failed: $Name" } }
function Hash([string]$Path) { return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
function Put([string]$Path, [string]$Text) { [IO.File]::WriteAllText($Path, $Text, [Text.UTF8Encoding]::new($false)) }
function Must-Fail([scriptblock]$Action, [string]$Expected) {
  $caught = $false
  try { & $Action } catch { $caught = $true; Check ($_.Exception.Message -like $Expected) ('cause: '+$Expected) }
  Check $caught ('must reject: '+$Expected)
}
try {
  . (Join-Path $RepoRoot 'scripts/Start-LifecycleWindowsPowerShell.ps1')
  $tokens=$null; $errors=$null
  $ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $RepoRoot 'scripts/windows_setup_exe_lifecycle_smoke.ps1'),[ref]$tokens,[ref]$errors)
  Check ($errors.Count -eq 0) 'native parser'
  foreach ($name in @('Initialize-LifecycleOfflineConfig','Wait-LifecycleEmbeddedUpdater','Assert-LifecycleUpgradeResult','Get-LifecycleTrustedPublisher','Invoke-BaselineUpdaterUpgrade')) {
    $functions=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name},$true))
    Check ($functions.Count -eq 1) ('unique owner '+$name)
    . ([scriptblock]::Create($functions[0].Extent.Text))
  }
  $BaselineVersion='3.2.673'; $TargetVersion='3.2.725'; $Architecture='arm64'; $ServiceName='FDSecurityAgent'
  $InstallDir=Join-Path $root 'installed'; $EvidenceDir=Join-Path $root 'evidence'
  $env:ProgramData=Join-Path $root 'program-data'
  foreach($path in @($InstallDir,$EvidenceDir,(Join-Path $env:ProgramData 'FDSecurity\logs'))) {
    New-Item -ItemType Directory -Path $path -Force | Out-Null
  }
  $script:events=@()
  function Add-Evidence([string]$Stage,[string]$Status,[string]$Detail) { $script:events+=@{stage=$Stage;status=$Status;detail=$Detail} }
  $templatePath=Join-Path $root 'baseline-template.toml'
  $templateText=[IO.File]::ReadAllText((Join-Path $RepoRoot 'config/agent_windows_production.example.toml'))
  # Published baseline templates use CRLF even when the host checkout uses LF.
  $templateText=$templateText.Replace("`r`n","`n").Replace("`n","`r`n")
  Put $templatePath $templateText
  $templateHash=Hash $templatePath
  $configHash=Initialize-LifecycleOfflineConfig $templatePath
  $configPath=Join-Path $InstallDir 'agent.toml'
  $configured=[IO.File]::ReadAllText($configPath)
  Check ((Hash $templatePath) -ceq $templateHash) 'baseline template remains immutable'
  Check ((Hash $configPath) -ceq $configHash) 'prepared configuration digest'
  foreach($pattern in @('(?m)^endpoint_id = "ci-setup-lifecycle-[a-f0-9]{32}"\r?$',
      '(?m)^tenant_id = "ci-lifecycle"\r?$', '(?m)^rest_base_url = "https://127\.0\.0\.1:9/api/v1"\r?$',
      '(?m)^proxy_mode = "off"\r?$', '(?m)^proxy_url = ""\r?$', '(?m)^relay_url = ""\r?$')) {
    Check ([regex]::Matches($configured,$pattern).Count -eq 1) ('active config field '+$pattern)
  }
  Check ($configured.Contains($InstallDir.Replace('\','\\')+'\\certs\\ca.pem')) 'TLS paths stay in isolated install root'
  $normalizeConfig={param($text)
    $text=[regex]::Replace($text,'(?m)^(endpoint_id|tenant_id|rest_base_url|proxy_mode|proxy_url|relay_url)\s*=\s*"[^"\r\n]*"','$1 = "<fixture>"')
    return $text.Replace($InstallDir.Replace('\','\\'),'C:\\Program Files\\FDSecurity')
  }
  Check ((& $normalizeConfig $configured) -ceq (& $normalizeConfig $templateText)) 'all other configuration and TLS fields preserved'
  Must-Fail {Initialize-LifecycleOfflineConfig $templatePath} '*configuration already exists*'
  Check ((Hash $configPath) -ceq $configHash) 'repeated preparation never overwrites configuration'
  Remove-Item -LiteralPath $configPath
  foreach($badTemplate in @(
      $templateText.Replace('[platform]','# [platform]'),
      ([regex]::Replace($templateText,'(?m)^rest_base_url','# rest_base_url')),
      ($templateText+"`nrest_base_url = `"https://127.0.0.1:9/api/v1`"`n"))) {
    Put $templatePath $badTemplate
    Must-Fail {Initialize-LifecycleOfflineConfig $templatePath} '*requires one active*'
    Check (-not(Test-Path -LiteralPath $configPath)) 'invalid template writes no configuration'
  }
  Put $templatePath ''
  Must-Fail {Initialize-LifecycleOfflineConfig $templatePath} '*bounded nonempty file*'
  Check (-not(Test-Path -LiteralPath $configPath)) 'empty template writes no configuration'
  Put $templatePath $templateText
  $configHash=Initialize-LifecycleOfflineConfig $templatePath
  $target=Join-Path $root 'FDSensor.next.exe'
  # An unsigned PE library is data for hash, copy and native NotSigned checks;
  # it is never executed as an Agent. Library output works in the workflow's
  # PowerShell 7 host, which cannot emit ConsoleApplication assemblies.
  # Invalid/trust outcomes below isolate only the Authenticode OS boundary.
  Add-Type -TypeDefinition 'public static class LifecycleUnsignedFixture { public static int Main() { return 0; } }' `
    -OutputAssembly $target -OutputType Library
  $setup=Join-Path $root 'FDSecuritySetup.exe';Copy-Item -LiteralPath $target -Destination $setup
  # A real child must discover PS5.1 inbox modules, not merely run core cmdlets
  # such as Copy-Item. No Get-FileHash or ScheduledTasks function is stubbed.
  $null=Get-Command Start-Process,Get-AuthenticodeSignature,Get-FileHash
  $foreignModules=Join-Path $root 'foreign-powershell-modules'
  New-Item -ItemType Directory -Path $foreignModules | Out-Null
  $probe=@'
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$phase='hash_lookup'
try {
  # Match the existing cache-recovery child-environment contract: Desktop 5.1
  # can expose the inbox hash command as a Function. ModuleBase is diagnostic,
  # not a fixed directory-layout contract across Windows PowerShell hosts.
  $command=Get-Command Get-FileHash -CommandType Cmdlet,Function -ErrorAction Stop
  if($command.ModuleName -cne 'Microsoft.PowerShell.Utility'){throw "unexpected_hash_owner:$($command.ModuleName)"}
  if($PSVersionTable.PSVersion.Major -ne 5){throw 'windows_powershell_5_required'}
  $phase='hash_read'
  $hash=(& $command -LiteralPath '__PROBE_FILE__' -Algorithm SHA256).Hash.ToLowerInvariant()
  $phase='scheduled_tasks'
  $taskCommand=Get-Command Get-ScheduledTask -CommandType Cmdlet,Function -ErrorAction Stop
  if($taskCommand.ModuleName -cne 'ScheduledTasks' -or $hash -cne '__PROBE_HASH__'){throw 'probe_contract_failed'}
  $modulePath='';$moduleBase='';$moduleVersion=''
  if($null -ne $command.Module){
    $modulePath=[string]$command.Module.Path;$moduleBase=[string]$command.Module.ModuleBase
    if($null -ne $command.Module.Version){$moduleVersion=$command.Module.Version.ToString()}
  }
  [Console]::Out.WriteLine((@{status='ok';sha256=$hash;ps_major=$PSVersionTable.PSVersion.Major;
    hash_command_type=[string]$command.CommandType;hash_module=$command.ModuleName;
    hash_module_path=$modulePath;hash_module_base=$moduleBase;hash_module_version=$moduleVersion;ps_home=$PSHOME;
    scheduled_tasks_module=$taskCommand.ModuleName}|ConvertTo-Json -Compress));exit 0
} catch { [Console]::Out.WriteLine('probe-failed:'+ $phase+':'+ $_.Exception.GetType().Name+':'+$_.Exception.Message);exit 71 }
'@
  $probe=$probe.Replace('__PROBE_FILE__',$target.Replace("'","''")).Replace('__PROBE_HASH__',(Hash $target))
  $encodedProbe=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($probe))
  $counterfactualFailure=$false
  foreach($isolated in @($false,$true)) {
    $probeOut=Join-Path $root ("module-probe-{0}.out" -f $isolated)
    $probeErr=Join-Path $root ("module-probe-{0}.err" -f $isolated)
    $probeProcess=$null
    try {
      [Environment]::SetEnvironmentVariable('PSModulePath',$foreignModules,[EnvironmentVariableTarget]::Process)
      try {
        if($isolated) {
          $probeProcess=Start-LifecycleWindowsPowerShell $encodedProbe $probeOut $probeErr
        } else {
          $probeProcess=Start-Process -FilePath (Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe') `
            -ArgumentList @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-EncodedCommand',$encodedProbe) `
            -RedirectStandardOutput $probeOut -RedirectStandardError $probeErr -PassThru
        }
        Check ($probeProcess -is [Diagnostics.Process]) 'launcher returns one owned Process object'
        Check ([Environment]::GetEnvironmentVariable('PSModulePath',[EnvironmentVariableTarget]::Process) -ceq $foreignModules) 'launch restores parent module path'
      } finally { [Environment]::SetEnvironmentVariable('PSModulePath',$savedModulePath,[EnvironmentVariableTarget]::Process) }
      $null=$probeProcess.Handle
      Check ($probeProcess.WaitForExit(10000)) 'bounded real module probe'
      $probeProcess.WaitForExit()
      $probeText=[IO.File]::ReadAllText($probeOut).Trim()
      Write-Output ("Windows PowerShell module probe isolated={0} exit={1}: {2}" -f $isolated,$probeProcess.ExitCode,$probeText.Substring(0,[Math]::Min(4096,$probeText.Length)))
      $probeError=[IO.File]::ReadAllText($probeErr)
      Check ($probeError.Length -eq 0) ("module probe stderr empty (isolated={0}, exit={1}): {2}" -f $isolated,$probeProcess.ExitCode,$probeError.Substring(0,[Math]::Min(4096,$probeError.Length)))
      $probeData=if($probeProcess.ExitCode -eq 0){$probeText|ConvertFrom-Json}else{$null}
      $probeOk=$probeData -and $probeData.status -ceq 'ok' -and $probeData.sha256 -ceq (Hash $target) -and
        $probeData.ps_major -eq 5 -and $probeData.hash_module -ceq 'Microsoft.PowerShell.Utility' -and
        $probeData.hash_command_type -in @('Cmdlet','Function') -and $probeData.scheduled_tasks_module -ceq 'ScheduledTasks'
      if($isolated) {
        Check ($probeProcess.ExitCode -eq 0 -and $probeOk) 'isolated child hashes real bytes and discovers ScheduledTasks'
      } else {
        # OS versions may repair inherited module paths. Record that real
        # result; the corrected launch must work on every supported host.
        Check ($probeProcess.ExitCode -in @(0,71)) 'counterfactual child has known terminal result'
        $counterfactualFailure=$probeProcess.ExitCode -eq 71 -and (
          $probeText.StartsWith('probe-failed:hash_lookup:CommandNotFoundException:') -or
          $probeText.StartsWith('probe-failed:scheduled_tasks:CommandNotFoundException:'))
        Check ($counterfactualFailure -or $probeOk) 'counterfactual module discovery result'
      }
    } finally {
      if($probeProcess) {
        try { if(-not $probeProcess.HasExited){$probeProcess.Kill();Check ($probeProcess.WaitForExit(10000)) 'owned module probe cleanup'} }
        finally { $probeProcess.Dispose() }
      }
    }
  }
  [Environment]::SetEnvironmentVariable('PSModulePath',$foreignModules,[EnvironmentVariableTarget]::Process)
  function Start-Process { throw 'synthetic_launch_failure' }
  try {
    Must-Fail {Start-LifecycleWindowsPowerShell $encodedProbe (Join-Path $root 'unused.out') (Join-Path $root 'unused.err')} 'synthetic_launch_failure'
    Check ([Environment]::GetEnvironmentVariable('PSModulePath',[EnvironmentVariableTarget]::Process) -ceq $foreignModules) 'failed launch restores parent module path'
  } finally {
    Remove-Item Function:\Start-Process
    [Environment]::SetEnvironmentVariable('PSModulePath',$savedModulePath,[EnvironmentVariableTarget]::Process)
  }
  $newUpdater='throw "candidate updater must never execute the first hop"'
  Put (Join-Path $root 'new-updater.txt') $newUpdater
  Put (Join-Path $InstallDir 'uninstall.exe') 'synthetic uninstaller'
  $native=@{schema='edr.windows.native-package-integrity.v1';files=@(@{name='uninstall.exe';sha256=(Hash (Join-Path $InstallDir 'uninstall.exe'))})}
  Put (Join-Path $InstallDir 'native-package-integrity.json') ($native|ConvertTo-Json -Depth 5)
  $oldScript=@'
param($InstallDir,$StagedBinary,$ExpectedSha256,$TargetVersion,$ExpectedArchitecture,
  $TrustedPublisherThumbprint,$TrustedPublisherSubject,$DeploymentMode,$ServiceName,
  $CommandId,$TaskId,$ArtifactId,$Operation,$UpgradeClass,$IssuedAtUnixMs,$DeadlineUnixMs,
  $HealthObserveMs,$StartupTimeoutSeconds,$MinCurrentVersion,$MaxCurrentVersion,$MinFreeBytes,
  $RuntimeManifest,$RuntimeManifestSha256)
$ErrorActionPreference='Stop'
if((Get-FileHash -LiteralPath $StagedBinary -Algorithm SHA256).Hash.ToLowerInvariant() -cne $ExpectedSha256){throw 'synthetic child hash mismatch'}
$null=Get-Command Get-ScheduledTask -ErrorAction Stop
Copy-Item -LiteralPath $StagedBinary -Destination (Join-Path $InstallDir 'FDSensor.exe') -Force
Copy-Item -LiteralPath (Join-Path (Split-Path $StagedBinary -Parent) 'new-updater.txt') -Destination (Join-Path $InstallDir ("edr_agent_inplace_update-{0}.ps1" -f $TargetVersion)) -Force
$report=@{status='succeeded';target_version=$TargetVersion;upgrade_class=$UpgradeClass;operation=$Operation;
 expected_sha256=$ExpectedSha256;installed_sha256=$ExpectedSha256}
[IO.File]::WriteAllText((Join-Path $env:ProgramData ("FDSecurity\logs\agent-update-{0}-report.json" -f $CommandId)),($report|ConvertTo-Json))
[IO.File]::WriteAllText((Join-Path (Split-Path $StagedBinary -Parent) 'actual-arguments.json'),(@{class=$UpgradeClass;
 mode=$DeploymentMode;floor=$MinFreeBytes;health_ms=$HealthObserveMs;package=$RuntimeManifest;
 package_sha=$RuntimeManifestSha256;caller=$PSCommandPath}|ConvertTo-Json))
exit 0
'@
  $oldPath=Join-Path $InstallDir ('edr_agent_inplace_update-'+$BaselineVersion+'.ps1'); Put $oldPath $oldScript
  $inputBinding=[pscustomobject]@{schema='edr.windows.lifecycle-upgrade.v1';baseline_version=$BaselineVersion;
    target_version=$TargetVersion;architecture=$Architecture;deployment_mode='service';service_name=$ServiceName;
    upgrade_class='runtime_bundle';binary_path=$target;binary_sha256=(Hash $target);
    runtime_identity_sha256=(Hash (Join-Path $InstallDir 'native-package-integrity.json'));
    signature_status='unsigned';publisher_thumbprint='';publisher_subject='';installer_path=$setup;installer_sha256=(Hash $setup);
    baseline_updater_sha256=(Hash $oldPath);target_updater_sha256=(Hash (Join-Path $root 'new-updater.txt'));
    runtime_package=(Join-Path $root 'original-runtime.zip');runtime_package_sha256=('a'*64);
    min_current_version='0.0.0';max_current_version=$TargetVersion;min_free_bytes=268435456}
  foreach($class in @('binary_hot','runtime_bundle','installer_required')) {
    $inputBinding.upgrade_class=$class
    $inputBinding.runtime_package=if($class -eq 'binary_hot'){''}else{Join-Path $root 'original-runtime.zip'}
    [Environment]::SetEnvironmentVariable('PSModulePath',$foreignModules,[EnvironmentVariableTarget]::Process)
    try {
      Invoke-BaselineUpdaterUpgrade $inputBinding
      Check ([Environment]::GetEnvironmentVariable('PSModulePath',[EnvironmentVariableTarget]::Process) -ceq $foreignModules) 'first hop restores parent module path'
    } finally { [Environment]::SetEnvironmentVariable('PSModulePath',$savedModulePath,[EnvironmentVariableTarget]::Process) }
    $actual=Get-Content -LiteralPath (Join-Path $root 'actual-arguments.json') -Raw|ConvertFrom-Json
    Check ($actual.class -ceq $class -and $actual.mode -ceq 'service') ('manifest class/mode '+$class)
    Check ($actual.caller -ceq $oldPath) ('old script actually invoked '+$class)
    Check ([uint64]$actual.floor -eq 268435456 -and [uint64]$actual.health_ms -eq 30000) 'floor/observation preserved'
    Check ([string]$actual.package -ceq $inputBinding.runtime_package) ('package forwarding '+$class)
    Check ((Hash $oldPath) -ceq $inputBinding.baseline_updater_sha256) 'old script unchanged'
    Check ((Hash $configPath) -ceq $configHash) 'configuration preserved through original updater invocation'
  }
  function Get-AuthenticodeSignature {
    [CmdletBinding()]param([string]$LiteralPath)
    if($LiteralPath -ceq $script:rejectedInstaller){return [pscustomobject]@{Status='NotTrusted';SignerCertificate=$null}}
    return $script:authResult
  }
  try {
    $script:rejectedInstaller=''
    foreach($status in @('HashMismatch','NotTrusted','UnknownError','Valid')) {
      $script:authResult=[pscustomobject]@{Status=$status;SignerCertificate=$null}
      Must-Fail {Get-LifecycleTrustedPublisher $inputBinding} '*requires NotSigned*'
    }
    $inputBinding.signature_status='signed';$inputBinding.publisher_thumbprint='A'*40;$inputBinding.publisher_subject='CN=Release Publisher'
    foreach($status in @('NotSigned','HashMismatch','NotTrusted','UnknownError','Valid')) {
      $script:authResult=[pscustomobject]@{Status=$status;SignerCertificate=$null}
      Must-Fail {Get-LifecycleTrustedPublisher $inputBinding} '*requires Valid*'
    }
    $script:authResult=[pscustomobject]@{Status='Valid';SignerCertificate=[pscustomobject]@{Thumbprint=('B'*40);Subject='CN=Release Publisher'}}
    Must-Fail {Get-LifecycleTrustedPublisher $inputBinding} '*publisher differs*'
    $script:authResult.SignerCertificate.Thumbprint='A'*40;$script:authResult.SignerCertificate.Subject='CN=Other Publisher'
    Must-Fail {Get-LifecycleTrustedPublisher $inputBinding} '*publisher differs*'
    $script:authResult.SignerCertificate.Subject='CN=Release Publisher'
    $trusted=Get-LifecycleTrustedPublisher $inputBinding
    Check ($trusted.Thumbprint -ceq $inputBinding.publisher_thumbprint -and $trusted.Subject -ceq $inputBinding.publisher_subject) 'manifest owns signed publisher'
    $inputBinding.signature_status='unsigned';$inputBinding.publisher_thumbprint='';$inputBinding.publisher_subject=''
    $script:authResult=[pscustomobject]@{Status='NotSigned';SignerCertificate=$null};$script:rejectedInstaller=$setup
    Must-Fail {Get-LifecycleTrustedPublisher $inputBinding} '*requires NotSigned*'
  } finally { Remove-Item -LiteralPath Function:Get-AuthenticodeSignature }
  $inputBinding.deployment_mode='scheduled_task'
  Must-Fail {Invoke-BaselineUpdaterUpgrade $inputBinding} '*input identity/mode mismatch*'
  $inputBinding.deployment_mode='service'
  $savedHash=$inputBinding.baseline_updater_sha256; $inputBinding.baseline_updater_sha256='b'*64
  Must-Fail {Invoke-BaselineUpdaterUpgrade $inputBinding} '*differs from its immutable release*'
  $inputBinding.baseline_updater_sha256=$savedHash
  $goodReport=Get-Content -LiteralPath (Join-Path $EvidenceDir 'old-updater-report.json') -Raw|ConvertFrom-Json
  $goodReport.status='failed_rolled_back'
  Must-Fail {Assert-LifecycleUpgradeResult $inputBinding $goodReport} '*did not report*'
  $goodReport.status='succeeded'
  Put (Join-Path $InstallDir 'uninstall.exe') 'wrong runtime bytes'
  Must-Fail {Assert-LifecycleUpgradeResult $inputBinding $goodReport} '*mixed native runtime*'
  Put $oldPath "exit 7"; $inputBinding.baseline_updater_sha256=Hash $oldPath
  Must-Fail {Invoke-BaselineUpdaterUpgrade $inputBinding} '*failed with exit code 7*'
  Check (@($script:events|Where-Object{$_.status -eq 'verified'}).Count -eq 3) 'failures never counted as passed'
  Write-Output ("module environment: foreign counterfactual failed={0}; corrected child hash/ScheduledTasks and parent restoration passed" -f $counterfactualFailure)
  Write-Output 'old updater lifecycle orchestration: offline configuration preservation and 5 rejection cases; 3 class executions, signed publisher binding and 17 negative controls passed'
} finally {
  [Environment]::SetEnvironmentVariable('PSModulePath',$savedModulePath,[EnvironmentVariableTarget]::Process)
  $env:ProgramData=$savedProgramData
  Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction Stop
}
