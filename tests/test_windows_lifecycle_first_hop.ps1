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
function Read-ModuleProbeDiagnostic([string]$Path) {
  if (-not [IO.File]::Exists($Path)) { return '<not-created>' }
  $stream=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
  try {
    $bytes=New-Object byte[] 4096
    $count=$stream.Read($bytes,0,$bytes.Length)
    $text=[Text.Encoding]::UTF8.GetString($bytes,0,$count)
    if($stream.Length -gt $count){$text+=' <truncated>'}
    return $text
  } finally { $stream.Dispose() }
}
try {
  . ([scriptblock]::Create([IO.File]::ReadAllText((Join-Path $RepoRoot 'scripts/Start-LifecycleWindowsPowerShell.ps1'))))
  $tokens=$null; $errors=$null
  $ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $RepoRoot 'scripts/windows_setup_exe_lifecycle_smoke.ps1'),[ref]$tokens,[ref]$errors)
  Check ($errors.Count -eq 0) 'native parser'
  foreach ($name in @('Initialize-LifecycleOfflineConfig','Wait-LifecycleEmbeddedUpdater','Assert-LifecycleUpgradeResult','Assert-LifecyclePublisherProtocol','Get-LifecycleTrustedPublisher','Invoke-BaselineUpdaterUpgrade')) {
    $functions=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name},$true))
    Check ($functions.Count -eq 1) ('unique owner '+$name)
    . ([scriptblock]::Create($functions[0].Extent.Text))
  }
  $BaselineVersion='3.2.673'; $TargetVersion='3.2.725'; $Architecture='arm64'; $ServiceName='FDSecurityAgent';$RuntimeMode='service'
  $InstallDir=Join-Path $root 'installed'; $EvidenceDir=Join-Path $root 'evidence'
  $env:ProgramData=Join-Path $root 'program-data'
  foreach($path in @($InstallDir,$EvidenceDir,(Join-Path $env:ProgramData 'FDSecurity\logs'))) {
    New-Item -ItemType Directory -Path $path -Force | Out-Null
  }
  $faultAst=[Management.Automation.Language.Parser]::ParseFile((Join-Path $RepoRoot 'tests/Invoke-RealInstallerTimeoutRecovery.ps1'),[ref]$tokens,[ref]$errors)
  Check ($errors.Count -eq 0) 'recovery evidence native parser'
  $copyOwner=@($faultAst.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Copy-RecoveryInstallerEvidence'},$true))
  Check ($copyOwner.Count -eq 1) 'unique recovery evidence owner'
  . ([scriptblock]::Create($copyOwner[0].Extent.Text))
  # This fixture adds a temporary profile root above ProgramData. Keep its
  # command short so the native symlink API stays inside the legacy path bound.
  $evidenceCommand='e'+[Guid]::NewGuid().ToString('N')
  $evidenceLeaf="agent-update-$evidenceCommand-$evidenceCommand-installer.log.redacted"
  $evidenceSource=Join-Path (Join-Path $env:ProgramData 'FDSecurity\logs') $evidenceLeaf
  $evidenceCopy=Join-Path $EvidenceDir 'installer.log.redacted'
  foreach($logStatus in @('ready','missing','too_large')) {
    $originalSize=switch($logStatus){ready {512} missing {0} too_large {1048577}}
    $logText=if($logStatus -ceq 'ready'){'Authorization: [REDACTED]'}else{@{status=$logStatus;original_size=$originalSize}|ConvertTo-Json -Compress}
    Put $evidenceSource $logText
    $logReport=[pscustomobject]@{installer_log_sha256=(Hash $evidenceSource);installer_log_size=(Get-Item $evidenceSource).Length;
      installer_log_original_size=$originalSize;installer_log_status=$logStatus;first_error='INSTALL_TIMEOUT|execution_deadline_exceeded';
      error_code='INSTALL_TIMEOUT';failed_stage='full_installer_upgrade'}
    $logJournal=$logReport.PSObject.Copy();$logJournal|Add-Member -NotePropertyName installer_log_file -NotePropertyValue $evidenceLeaf
    $retained=Copy-RecoveryInstallerEvidence $logReport $logJournal $evidenceCommand $EvidenceDir
    Check ($retained.status -ceq $logStatus -and (Hash $evidenceCopy) -ceq $logReport.installer_log_sha256) ('exact bounded evidence retained '+$logStatus)
    Must-Fail {Copy-RecoveryInstallerEvidence $logReport $logJournal $evidenceCommand $EvidenceDir} '*destination already exists*'
    Remove-Item -LiteralPath $evidenceCopy
  }
  foreach($change in @(
      @{installer_log_file='../outside.log'},@{installer_log_sha256=('b'*64)},
      @{installer_log_size=1},@{installer_log_original_size=0})) {
    $badJournal=$logJournal.PSObject.Copy()
    foreach($key in $change.Keys){$badJournal.$key=$change[$key]}
    Must-Fail {Copy-RecoveryInstallerEvidence $logReport $badJournal $evidenceCommand $EvidenceDir} '*identity, bounds or report/journal agreement*'
  }
  $badReport=$logReport.PSObject.Copy();$badJournal=$logJournal.PSObject.Copy()
  $badReport.installer_log_size=4097;$badJournal.installer_log_size=4097
  Must-Fail {Copy-RecoveryInstallerEvidence $badReport $badJournal $evidenceCommand $EvidenceDir} '*identity, bounds or report/journal agreement*'
  $badReport=$logReport.PSObject.Copy();$badReport.installer_log_status='ready'
  Must-Fail {Copy-RecoveryInstallerEvidence $badReport $logJournal $evidenceCommand $EvidenceDir} '*status does not match*'
  foreach($field in @('first_error','error_code','failed_stage')) {
    $badJournal=$logJournal.PSObject.Copy();$badJournal.$field='changed'
    Must-Fail {Copy-RecoveryInstallerEvidence $logReport $badJournal $evidenceCommand $EvidenceDir} '*first failure was not preserved*'
  }
  Put $evidenceSource 'wrong size'
  Must-Fail {Copy-RecoveryInstallerEvidence $logReport $logJournal $evidenceCommand $EvidenceDir} '*not a regular file of the reported size*'
  Put $evidenceSource ('x'*[int]$logReport.installer_log_size)
  Must-Fail {Copy-RecoveryInstallerEvidence $logReport $logJournal $evidenceCommand $EvidenceDir} '*differs from the updater report*'
  Remove-Item -LiteralPath $evidenceCopy,$evidenceSource
  New-Item -ItemType Directory -Path $evidenceSource | Out-Null
  Must-Fail {Copy-RecoveryInstallerEvidence $logReport $logJournal $evidenceCommand $EvidenceDir} '*not a regular file of the reported size*'
  Remove-Item -LiteralPath $evidenceSource
  $linkTarget=Join-Path $root 'evidence-link-target.txt';Put $linkTarget $logText
  Check ([IO.Directory]::Exists((Split-Path $evidenceSource -Parent)) -and [IO.File]::Exists($linkTarget)) 'symlink fixture parent and target exist'
  Check ($evidenceSource.Length -lt 248 -and $linkTarget.Length -lt 248) 'symlink fixture stays within native path bounds'
  Write-Output ("recovery evidence fixture: link_path_length={0}; target_path_length={1}; parent_and_target_exist=true" -f $evidenceSource.Length,$linkTarget.Length)
  New-Item -ItemType SymbolicLink -Path $evidenceSource -Target $linkTarget | Out-Null
  Must-Fail {Copy-RecoveryInstallerEvidence $logReport $logJournal $evidenceCommand $EvidenceDir} '*not a regular file of the reported size*'
  Remove-Item -LiteralPath $evidenceSource,$linkTarget
  Write-Output 'recovery installer evidence: 3 bounded status cases and 16 rejection cases passed'
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
  foreach($pattern in @('(?m)^endpoint_id = "ci-lifecycle-[a-f0-9]{32}"\r?$',
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
  # such as Copy-Item. Hash, Security ACL and ScheduledTasks commands are real.
  $null=Get-Command Start-Process,Get-AuthenticodeSignature,Get-FileHash
  $foreignModules=Join-Path $root 'foreign-powershell-modules'
  New-Item -ItemType Directory -Path $foreignModules | Out-Null
  # Reproduce the CI PS7 -> native Setup/worker -> PS5.1 boundary using the
  # installed incompatible module directory when this test runs under PS7.
  $hostModules=Join-Path $PSHOME 'Modules'
  if($PSVersionTable.PSVersion.Major -ge 7 -and [IO.File]::Exists((Join-Path $hostModules 'Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1'))) {
    $foreignModules=$hostModules
    Write-Output ('module probe foreign owner: PowerShell ' + $PSVersionTable.PSVersion.Major + ' inbox modules')
  }
  $probe=@'
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$phase='starting'
function Set-ProbePhase([string]$Name) {
  $script:phase=$Name
  # Synchronous .NET writes preserve progress even when command discovery never
  # returns. This trace uses no PowerShell module or backend connection.
  [IO.File]::AppendAllText('__PROBE_TRACE__',$Name+[Environment]::NewLine,[Text.UTF8Encoding]::new($false))
}
try {
  Set-ProbePhase 'hash_lookup'
  # Match the existing cache-recovery child-environment contract: Desktop 5.1
  # can expose the inbox hash command as a Function. ModuleBase is diagnostic,
  # not a fixed directory-layout contract across Windows PowerShell hosts.
  $command=Get-Command Get-FileHash -CommandType Cmdlet,Function -ErrorAction Stop
  if($command.ModuleName -cne 'Microsoft.PowerShell.Utility'){throw "unexpected_hash_owner:$($command.ModuleName)"}
  if($PSVersionTable.PSVersion.Major -ne 5){throw 'windows_powershell_5_required'}
  Set-ProbePhase 'hash_read'
  $hash=(& $command -LiteralPath '__PROBE_FILE__' -Algorithm SHA256).Hash.ToLowerInvariant()
  Set-ProbePhase 'security_lookup'
  $getAcl=Get-Command Get-Acl -CommandType Cmdlet -ErrorAction Stop
  $setAcl=Get-Command Set-Acl -CommandType Cmdlet -ErrorAction Stop
  if($getAcl.ModuleName -cne 'Microsoft.PowerShell.Security' -or $setAcl.ModuleName -cne 'Microsoft.PowerShell.Security'){throw 'unexpected_acl_owner'}
  Set-ProbePhase 'acl_roundtrip'
  [IO.File]::WriteAllText('__PROBE_ACL__','isolated ACL fixture')
  $acl=& $getAcl -LiteralPath '__PROBE_ACL__'
  $access=[Security.AccessControl.AccessControlSections]::Access
  $originalAcl=$acl.GetSecurityDescriptorSddlForm($access)
  $acl.SetAccessRuleProtection($true,$true)
  & $setAcl -LiteralPath '__PROBE_ACL__' -AclObject $acl
  $readAcl=& $getAcl -LiteralPath '__PROBE_ACL__'
  if(-not $readAcl.AreAccessRulesProtected){throw 'acl_write_not_observed'}
  $readAcl.SetSecurityDescriptorSddlForm($originalAcl,$access)
  & $setAcl -LiteralPath '__PROBE_ACL__' -AclObject $readAcl
  if((& $getAcl -LiteralPath '__PROBE_ACL__').GetSecurityDescriptorSddlForm($access) -cne $originalAcl){throw 'acl_restore_not_observed'}
  Set-ProbePhase 'scheduled_tasks'
  $taskCommand=Get-Command Get-ScheduledTask -CommandType Cmdlet,Function -ErrorAction Stop
  if($taskCommand.ModuleName -cne 'ScheduledTasks' -or $hash -cne '__PROBE_HASH__'){throw 'probe_contract_failed'}
  $modulePath='';$moduleBase='';$moduleVersion=''
  if($null -ne $command.Module){
    $modulePath=[string]$command.Module.Path;$moduleBase=[string]$command.Module.ModuleBase
    if($null -ne $command.Module.Version){$moduleVersion=$command.Module.Version.ToString()}
  }
  Set-ProbePhase 'native_wait'
  . ([scriptblock]::Create([IO.File]::ReadAllText('__PROBE_HELPER__')))
  $null=Get-Command Start-Process -ErrorAction Stop
  $previousModulePath=[Environment]::GetEnvironmentVariable('PSModulePath',[EnvironmentVariableTarget]::Process)
  $nativeProcess=$null
  try {
    [Environment]::SetEnvironmentVariable('PSModulePath','__PROBE_FOREIGN__',[EnvironmentVariableTarget]::Process)
    # The outer probe has a deadline and owns this process tree. Keep Wait in
    # the actual call: Setup requires its process-tree completion semantics.
    $nativeProcess=Start-LifecycleWindowsProcess -ProcessParameters @{
      FilePath=(Join-Path $env:WINDIR 'System32\cmd.exe');ArgumentList=@('/d','/c','exit /b 23');Wait=$true;PassThru=$true
      RedirectStandardOutput='__PROBE_NATIVE_OUT__';RedirectStandardError='__PROBE_NATIVE_ERR__'
    }
    if($nativeProcess -isnot [Diagnostics.Process] -or -not $nativeProcess.HasExited -or $nativeProcess.ExitCode -ne 23){throw 'native_wait_or_original_exit_lost'}
    if([Environment]::GetEnvironmentVariable('PSModulePath',[EnvironmentVariableTarget]::Process) -cne '__PROBE_FOREIGN__'){throw 'native_wait_parent_environment_changed'}
    if([IO.File]::ReadAllText('__PROBE_NATIVE_OUT__').Length -ne 0 -or [IO.File]::ReadAllText('__PROBE_NATIVE_ERR__').Length -ne 0){throw 'native_redirect_contract_failed'}
  } finally {
    [Environment]::SetEnvironmentVariable('PSModulePath',$previousModulePath,[EnvironmentVariableTarget]::Process)
    if($nativeProcess){$nativeProcess.Dispose()}
  }
  Set-ProbePhase 'result_serialization'
  [Console]::Out.WriteLine((@{status='ok';sha256=$hash;ps_major=$PSVersionTable.PSVersion.Major;
    hash_command_type=[string]$command.CommandType;hash_module=$command.ModuleName;
    hash_module_path=$modulePath;hash_module_base=$moduleBase;hash_module_version=$moduleVersion;ps_home=$PSHOME;
    scheduled_tasks_module=$taskCommand.ModuleName;security_module=$setAcl.ModuleName;acl_roundtrip=$true;
    native_wait_exit=23;native_wait_parent_restored=$true}|ConvertTo-Json -Compress));exit 0
} catch { [Console]::Out.WriteLine('probe-failed:'+ $phase+':'+ $_.Exception.GetType().Name+':'+$_.Exception.Message);exit 71 }
'@
  $probe=$probe.Replace('__PROBE_FILE__',$target.Replace("'","''")).Replace('__PROBE_HASH__',(Hash $target))
  $probe=$probe.Replace('__PROBE_HELPER__',(Join-Path $RepoRoot 'scripts/Start-LifecycleWindowsPowerShell.ps1').Replace("'","''"))
  $probe=$probe.Replace('__PROBE_FOREIGN__',$foreignModules.Replace("'","''"))
  $counterfactualFailure=$false
  foreach($probeCase in @(@{native=$false;isolated=$false},@{native=$false;isolated=$true},@{native=$true;isolated=$false},@{native=$true;isolated=$true})) {
    $isolated=$probeCase.isolated;$nativeRelay=$probeCase.native
    $probeName='module-probe-native-{0}-isolated-{1}' -f $nativeRelay,$isolated
    $probeOut=Join-Path $root ($probeName+'.out')
    $probeErr=Join-Path $root ($probeName+'.err')
    $probeTrace=Join-Path $root ($probeName+'.phases')
    $caseProbe=$probe.Replace('__PROBE_TRACE__',$probeTrace.Replace("'","''"))
    $caseProbe=$caseProbe.Replace('__PROBE_ACL__',(Join-Path $root ($probeName+'.acl')).Replace("'","''"))
    $caseProbe=$caseProbe.Replace('__PROBE_NATIVE_OUT__',(Join-Path $root ($probeName+'.native.out')).Replace("'","''"))
    $caseProbe=$caseProbe.Replace('__PROBE_NATIVE_ERR__',(Join-Path $root ($probeName+'.native.err')).Replace("'","''"))
    $probeScript=Join-Path $root ($probeName+'.ps1')
    [IO.File]::WriteAllText($probeScript,$caseProbe,[Text.Encoding]::Unicode)
    $encodedProbe=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($caseProbe))
    $probeProcess=$null;$probeFailure=$null
    $probeClock=[Diagnostics.Stopwatch]::StartNew()
    try {
      [Environment]::SetEnvironmentVariable('PSModulePath',$foreignModules,[EnvironmentVariableTarget]::Process)
      try {
        if($nativeRelay) {
          $nativeParameters=@{
            FilePath=(Join-Path $env:WINDIR 'System32\cmd.exe')
            # A file avoids cmd.exe's 8191-character command-line limit.
            ArgumentList=('/d /s /c ""{0}" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{1}""' -f (Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'),$probeScript)
            RedirectStandardOutput=$probeOut;RedirectStandardError=$probeErr;PassThru=$true
          }
          $probeProcess=if($isolated){Start-LifecycleWindowsProcess -ProcessParameters $nativeParameters}else{Start-Process @nativeParameters}
        } elseif($isolated) {
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
      # This is a diagnostic cold-start window, not a product deadline. The
      # earlier 10-second probe timed out before emitting its command result.
      # A 60-second timeout still fails, including the counterfactual launch.
      Write-Output ("Windows PowerShell module probe started native={0} isolated={1} pid={2} wait_seconds=60" -f $nativeRelay,$isolated,$probeProcess.Id)
      Check ($probeProcess.WaitForExit(60000)) 'bounded real module probe'
      $probeProcess.WaitForExit()
      Write-Output ("Windows PowerShell module probe phases isolated={0}: {1}" -f $isolated,(Read-ModuleProbeDiagnostic $probeTrace))
      $probeText=[IO.File]::ReadAllText($probeOut).Trim()
      Write-Output ("Windows PowerShell module probe isolated={0} exit={1}: {2}" -f $isolated,$probeProcess.ExitCode,$probeText.Substring(0,[Math]::Min(4096,$probeText.Length)))
      $probeError=[IO.File]::ReadAllText($probeErr)
      Check ($probeError.Length -eq 0) ("module probe stderr empty (isolated={0}, exit={1}): {2}" -f $isolated,$probeProcess.ExitCode,$probeError.Substring(0,[Math]::Min(4096,$probeError.Length)))
      $probeData=if($probeProcess.ExitCode -eq 0){$probeText|ConvertFrom-Json}else{$null}
      $probeOk=$probeData -and $probeData.status -ceq 'ok' -and $probeData.sha256 -ceq (Hash $target) -and
        $probeData.ps_major -eq 5 -and $probeData.hash_module -ceq 'Microsoft.PowerShell.Utility' -and
        $probeData.hash_command_type -in @('Cmdlet','Function') -and $probeData.scheduled_tasks_module -ceq 'ScheduledTasks' -and
        $probeData.security_module -ceq 'Microsoft.PowerShell.Security' -and $probeData.acl_roundtrip -eq $true -and
        $probeData.native_wait_exit -eq 23 -and $probeData.native_wait_parent_restored -eq $true
      if($isolated) {
        Check ($probeProcess.ExitCode -eq 0 -and $probeOk) 'isolated direct/native child performs real hash/ACL and preserves native Wait/exit'
      } else {
        # OS versions may repair inherited module paths. Record that real
        # result; the corrected launch must work on every supported host.
        Check ($probeProcess.ExitCode -in @(0,71)) 'counterfactual child has known terminal result'
        $caseCounterfactualFailure=$probeProcess.ExitCode -eq 71 -and (
          $probeText.StartsWith('probe-failed:hash_lookup:CommandNotFoundException:') -or
          $probeText.StartsWith('probe-failed:security_lookup:CommandNotFoundException:') -or
          $probeText.StartsWith('probe-failed:acl_roundtrip:CommandNotFoundException:') -or
          $probeText.StartsWith('probe-failed:scheduled_tasks:CommandNotFoundException:'))
        Check ($caseCounterfactualFailure -or $probeOk) 'counterfactual module discovery result'
        $counterfactualFailure=$counterfactualFailure -or $caseCounterfactualFailure
      }
    } catch { $probeFailure=$_;throw } finally {
      $cleanupFailure=$null
      if($probeProcess) {
        try {
          if(-not $probeProcess.HasExited){
            # Native relays and the Wait probe can have descendants. Terminate
            # only this still-owned process tree, then bound the cleanup wait.
            $cleanupProcess=Start-Process -FilePath (Join-Path $env:WINDIR 'System32\taskkill.exe') -ArgumentList @('/PID',[string]$probeProcess.Id,'/T','/F') -PassThru -WindowStyle Hidden
            try {
              $null=$cleanupProcess.Handle
              if(-not $cleanupProcess.WaitForExit(10000)){$cleanupProcess.Kill();Check ($cleanupProcess.WaitForExit(10000)) 'owned taskkill cleanup';throw 'owned process-tree cleanup timed out'}
              Check ($probeProcess.WaitForExit(10000)) 'owned module probe tree cleanup'
            } finally {$cleanupProcess.Dispose()}
          }
        }
        catch { $cleanupFailure=$_ }
      }
      if($probeFailure -or $cleanupFailure) {
        # Preserve the original failure. Only these bounded, public synthetic
        # child logs are captured; no process environment is emitted.
        try {
          Write-Output ("Windows PowerShell module probe failure isolated={0} elapsed_ms={1} cleanup_error={2}" -f $isolated,$probeClock.ElapsedMilliseconds,([string]$cleanupFailure))
          foreach($entry in @(@('phases',$probeTrace),@('stdout',$probeOut),@('stderr',$probeErr))) {
            Write-Output ("module probe {0}: {1}" -f $entry[0],(Read-ModuleProbeDiagnostic $entry[1]))
          }
        } catch { Write-Warning ("module probe diagnostic capture failed: " + $_.Exception.GetType().Name) }
      }
      if($probeProcess){$probeProcess.Dispose()}
      if(-not $probeFailure -and $cleanupFailure){throw $cleanupFailure}
    }
  }
  [Environment]::SetEnvironmentVariable('PSModulePath',$foreignModules,[EnvironmentVariableTarget]::Process)
  function Start-Process { throw 'synthetic_launch_failure' }
  try {
    Must-Fail {Start-LifecycleWindowsPowerShell $encodedProbe (Join-Path $root 'unused.out') (Join-Path $root 'unused.err')} 'synthetic_launch_failure'
    Check ([Environment]::GetEnvironmentVariable('PSModulePath',[EnvironmentVariableTarget]::Process) -ceq $foreignModules) 'failed launch restores parent module path'
    Must-Fail {Start-LifecycleWindowsProcess -ProcessParameters @{FilePath='synthetic-missing.exe';Wait=$true;PassThru=$true}} 'synthetic_launch_failure'
    Check ([Environment]::GetEnvironmentVariable('PSModulePath',[EnvironmentVariableTarget]::Process) -ceq $foreignModules) 'failed native launch preserves cause and restores parent module path'
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
if($DeploymentMode -ceq 'auto') {
  $state=Join-Path $env:ProgramData 'FDSecurity\state'
  [IO.Directory]::CreateDirectory($state)|Out-Null
  [IO.File]::WriteAllText((Join-Path $state ("agent-update-{0}.journal.json" -f $CommandId)),(@{resolved_deployment_mode='scheduled_task'}|ConvertTo-Json))
}
[IO.File]::WriteAllText((Join-Path (Split-Path $StagedBinary -Parent) 'actual-arguments.json'),(@{class=$UpgradeClass;
 mode=$DeploymentMode;floor=$MinFreeBytes;health_ms=$HealthObserveMs;package=$RuntimeManifest;
 package_sha=$RuntimeManifestSha256;caller=$PSCommandPath;staged_binary=$StagedBinary;staged_sha=$ExpectedSha256}|ConvertTo-Json))
# Match the original updater's successful consumption of its disposable input.
Remove-Item -LiteralPath $StagedBinary -Force -ErrorAction Stop
if($UpgradeClass -eq 'installer_required') {
  # Reproduce the original updater's successful native copy followed by return.
  # Run the real Windows tool on fresh, isolated files; never stub its exit code.
  $fixtureRoot=Split-Path $StagedBinary -Parent
  $copySource=Join-Path $fixtureRoot ('robocopy-source-'+$CommandId)
  $copyTarget=Join-Path $fixtureRoot ('robocopy-target-'+$CommandId)
  [IO.Directory]::CreateDirectory($copySource)|Out-Null
  [IO.File]::WriteAllText((Join-Path $copySource 'proof.txt'),'public copy fixture')
  & (Join-Path $env:WINDIR 'System32\robocopy.exe') $copySource $copyTarget 'proof.txt' /R:0 /W:0 /NFL /NDL /NJH /NJS /NP | Out-Null
  $copyExit=$LASTEXITCODE
  if($copyExit -ne 1 -or [IO.File]::ReadAllText((Join-Path $copyTarget 'proof.txt')) -cne 'public copy fixture') {throw 'real robocopy fixture did not copy successfully with exit 1'}
  [IO.File]::WriteAllText((Join-Path $fixtureRoot 'robocopy-return.json'),(@{native_exit=$copyExit;normal_return=$true}|ConvertTo-Json))
  return
}
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
    Check ($actual.staged_binary -cne $target -and (Split-Path $actual.staged_binary -Parent) -ceq (Split-Path $target -Parent)) ('disposable sibling staging '+$class)
    Check ($actual.staged_sha -ceq $inputBinding.binary_sha256 -and -not (Test-Path -LiteralPath $actual.staged_binary)) ('verified staged binary consumed '+$class)
    Check ((Hash $target) -ceq $inputBinding.binary_sha256) ('immutable transition binary preserved '+$class)
    $retainedPublisher=Get-LifecycleTrustedPublisher $inputBinding
    Check ($retainedPublisher.Thumbprint -ceq 'SHA256_ONLY_UNSIGNED') ('repair publisher validation still available '+$class)
    Check ((Hash $oldPath) -ceq $inputBinding.baseline_updater_sha256) 'old script unchanged'
    Check ((Hash $configPath) -ceq $configHash) 'configuration preserved through original updater invocation'
  }
  $copyReceipt=Get-Content -LiteralPath (Join-Path $root 'robocopy-return.json') -Raw|ConvertFrom-Json
  Check ($copyReceipt.native_exit -eq 1 -and $copyReceipt.normal_return -eq $true) 'real robocopy 1 plus normal script return accepted'
  Write-Output ("real robocopy native_exit={0}; successful script return and strict release report passed" -f $copyReceipt.native_exit)
  $RuntimeMode='scheduled_task'
  Invoke-BaselineUpdaterUpgrade $inputBinding
  $actual=Get-Content -LiteralPath (Join-Path $root 'actual-arguments.json') -Raw|ConvertFrom-Json
  Check ($actual.mode -ceq 'auto' -and $inputBinding.deployment_mode -ceq 'service' -and $actual.caller -ceq $oldPath) 'original updater receives auto while immutable manifest retains service packaging'
  $journal=Get-Content -LiteralPath (Join-Path $EvidenceDir 'old-updater-journal.json') -Raw|ConvertFrom-Json
  Check ($journal.resolved_deployment_mode -ceq 'scheduled_task') 'resolved task mode is retained as evidence'
  Put $oldPath ($oldScript.Replace("resolved_deployment_mode='scheduled_task'","resolved_deployment_mode='service'"));$inputBinding.baseline_updater_sha256=Hash $oldPath
  Must-Fail {Invoke-BaselineUpdaterUpgrade $inputBinding} '*auto upgrade did not retain the scheduled-task deployment*'
  Put $oldPath $oldScript;$inputBinding.baseline_updater_sha256=Hash $oldPath;$RuntimeMode='service'
  function Copy-Item {
    [CmdletBinding()]param([string]$LiteralPath,[string]$Destination)
    Microsoft.PowerShell.Management\Copy-Item -LiteralPath $LiteralPath -Destination $Destination -ErrorAction Stop
    [IO.File]::WriteAllText($Destination,'corrupted disposable copy')
  }
  try {
    Must-Fail {Invoke-BaselineUpdaterUpgrade $inputBinding} '*staging copy differs from the immutable release*'
    Check ((Hash $target) -ceq $inputBinding.binary_sha256) 'rejected copy preserves immutable transition binary'
  } finally { Remove-Item -LiteralPath Function:Copy-Item }
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
  Put $oldPath "throw 'synthetic_updater_exception'"; $inputBinding.baseline_updater_sha256=Hash $oldPath
  Must-Fail {Invoke-BaselineUpdaterUpgrade $inputBinding} '*failed with exit code 1*'
  Check ((Get-Content -LiteralPath (Join-Path $EvidenceDir 'old-updater.stderr.log') -Raw) -match 'synthetic_updater_exception') 'updater exception retained'
  Put $oldPath ($oldScript.Replace("status='succeeded'","status='failed_rolled_back'")); $inputBinding.baseline_updater_sha256=Hash $oldPath
  Must-Fail {Invoke-BaselineUpdaterUpgrade $inputBinding} '*did not report*'
  Check (@($script:events|Where-Object{$_.status -eq 'verified'}).Count -eq 4) 'failures never counted as passed'
  Write-Output ("module environment: foreign counterfactual failed={0}; corrected direct/native child hash/Security ACL/ScheduledTasks, native Wait/exit 23 and parent restoration passed" -f $counterfactualFailure)
  Write-Output 'old updater lifecycle orchestration: offline configuration preservation and 5 rejection cases; 3 service class executions plus auto task selection and resolved-mode rejection, consumed staging preservation, signed publisher binding and 20 negative controls passed'
} finally {
  [Environment]::SetEnvironmentVariable('PSModulePath',$savedModulePath,[EnvironmentVariableTarget]::Process)
  $env:ProgramData=$savedProgramData
  Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction Stop
}
