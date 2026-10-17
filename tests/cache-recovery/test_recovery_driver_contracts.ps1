#Requires -Version 5.1
# Pure local function tests: no SCM, native child, installer, Agent, or network.
[CmdletBinding()]
param(
  [string]$DriverSource=(Join-Path $PSScriptRoot 'windows_cache_recovery_ci.ps1'),
  [Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9]{64}$')][string]$DriverSha256
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$source=$DriverSource
$sourceFile=Get-Item -LiteralPath $source -Force
if ($sourceFile.PSIsContainer -or ($sourceFile.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $sourceFile.Length -gt 65536 -or (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant() -cne $DriverSha256) {throw 'driver_source_pin'}
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($source,[ref]$tokens,[ref]$errors)
if (@($errors).Count) {throw 'driver_parse_failed'}
if ((Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant() -cne $DriverSha256) {throw 'driver_source_changed'}
$wanted=@('Need','Regular','SHA','ReadBounded','ConfigBinding','WaitProcess','ReadOwnedBytes','ReadOwnedUpdateJson','SaveOwnedOriginal','SaveTransitionFinalEvidence','Save','SaveRecoverySummary','ServiceObserverError','ServiceWorkerSource','ServiceSamplerSource','ServiceChildStatus','ServiceRaw','FinishServiceObserver','ServiceAction')
$functions=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -in $wanted},$false))
if ($functions.Count -ne $wanted.Count) {throw 'function_inventory'}
# Only these source-owned function definitions are loaded, never driver top-level.
foreach($function in $functions) {Invoke-Expression $function.Extent.Text}
$count=0
function Fails([scriptblock]$Body,[string]$Prefix) {
  $caught=$false
  try {& $Body | Out-Null} catch {
    $caught=$true
    if (-not $_.Exception.Message.StartsWith($Prefix,[StringComparison]::Ordinal)) {throw 'unexpected_failure_type'}
    if ($_.Exception.Message.Contains('unexported-test-message')) {throw 'raw_cleanup_message_leaked'}
  }
  if (-not $caught) {throw 'expected_failure_missing'}
  $script:count++
}
function Checked($Condition,[string]$Cause) {
  if(-not $Condition){throw $Cause}
  $script:count++
}
function FailsType([scriptblock]$Body,[type]$Expected) {
  $caught=$false;$matched=$false
  try{& $Body | Out-Null}catch{
    $caught=$true;$e=$_.Exception
    for($depth=0;$depth -lt 8 -and $null -ne $e;$depth++){
      if($Expected.IsInstanceOfType($e)){$matched=$true;break};$e=$e.InnerException
    }
  }
  if(-not $caught -or -not $matched){throw 'typed_failure_contract'}
  $script:count++
}
function FailsHard([scriptblock]$Body) {
  $caught=$false
  try{& $Body | Out-Null}catch{$caught=$true}
  if(-not $caught){throw 'malformed_json_became_ready_or_transient'}
  $script:count++
}
# Deterministic metadata-race seam only. Every non-stub call still uses the
# real cmdlet; the underlying file/stream remains a small public temporary file.
$metadataMode='';$metadataPath='';$metadataCalls=0
function Get-Item {
  [CmdletBinding()]
  param([string]$LiteralPath,[switch]$Force)
  $item=Microsoft.PowerShell.Management\Get-Item @PSBoundParameters
  if(-not $script:metadataMode -or $LiteralPath -cne $script:metadataPath){return $item}
  $script:metadataCalls++
  $v=[pscustomobject]@{PSIsContainer=$item.PSIsContainer;Attributes=$item.Attributes;Length=$item.Length;LastWriteTimeUtc=$item.LastWriteTimeUtc;CreationTimeUtc=$item.CreationTimeUtc}
  if($script:metadataMode -ceq 'before_oversize' -and $script:metadataCalls -eq 1){$v.Length=1048577}
  if($script:metadataCalls -eq 2){
    if($script:metadataMode -ceq 'after_oversize'){$v.Length=1048577}
    if($script:metadataMode -ceq 'after_reparse'){$v.Attributes=$v.Attributes -bor [IO.FileAttributes]::ReparsePoint}
    if($script:metadataMode -ceq 'changed'){$v.LastWriteTimeUtc=$v.LastWriteTimeUtc.AddTicks(1)}
  }
  return $v
}
function PublicText([string]$Text) {[IO.File]::WriteAllText($script:ownedPath,$Text,[Text.UTF8Encoding]::new($false))}
function ChildStub([bool]$Exited,$Code) {
  $v=[pscustomobject]@{HasExited=$Exited;ExitCode=$Code}
  $v | Add-Member ScriptMethod Refresh {}
  return $v
}
function DiagnosticStub {
  return @{terminal_known=$false;exit_known=$false;exit_code=$null;primary_failure_type='public-primary-sentinel';originals=@{report=@{status='not_attempted'};journal=@{status='not_attempted'}}}
}
$dir=Join-Path ([IO.Path]::GetTempPath()) ('edr-driver-contract-'+[Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $dir | Out-Null
try {
  $configPath=Join-Path $dir 'public.toml'
  $expectedConfigPairs=@(@('endpoint_id','public-synthetic'),@('tenant_id','synthetic'),@('evidence_cache_path',(Join-Path $dir 'cache.db')))
  $lines=@($expectedConfigPairs | ForEach-Object {$_[0]+' = "'+$_[1].Replace('\','\\')+'"'})
  $original=($lines -join "`n")+"`n"
  [IO.File]::WriteAllText($configPath,$original,[Text.UTF8Encoding]::new($false))
  $configSha256=SHA $configPath;ConfigBinding;$count++
  [IO.File]::AppendAllText($configPath,'# changed')
  Fails {ConfigBinding} 'fixture_configuration_hash_changed'
  [IO.File]::WriteAllText($configPath,$original.Replace('public-synthetic','wrong-public'),[Text.UTF8Encoding]::new($false))
  $configSha256=SHA $configPath
  Fails {ConfigBinding} 'fixture_configuration_scalar_binding'
  [IO.File]::WriteAllText($configPath,($original+'endpoint_id = "public-synthetic"'),[Text.UTF8Encoding]::new($false))
  $configSha256=SHA $configPath
  Fails {ConfigBinding} 'fixture_configuration_scalar_binding'
  $normal=[pscustomobject]@{ExitCode=7}
  $normal | Add-Member ScriptMethod WaitForExit {param($unused) return $true}
  $normal | Add-Member ScriptMethod Refresh {}
  if ((WaitProcess $normal 1 'unused') -ne 7) {throw 'exit_code_contract'};$count++
  $clean=[pscustomobject]@{WaitCount=0;Killed=$false}
  $clean | Add-Member ScriptMethod WaitForExit {param($unused) $this.WaitCount++;return $this.WaitCount -gt 1}
  $clean | Add-Member ScriptMethod Kill {$this.Killed=$true}
  Fails {WaitProcess $clean 1 'synthetic_timeout'} 'synthetic_timeout'
  if (-not $clean.Killed) {throw 'owned_kill_not_called'}
  $bad=[pscustomobject]@{}
  $bad | Add-Member ScriptMethod WaitForExit {param($unused) return $false}
  $bad | Add-Member ScriptMethod Kill {throw [InvalidOperationException]::new('unexported-test-message')}
  Fails {WaitProcess $bad 1 'synthetic_timeout'} 'synthetic_timeout;cleanup_unknown_type='
  $unknown=[pscustomobject]@{}
  $unknown | Add-Member ScriptMethod WaitForExit {param($unused) return $false}
  $unknown | Add-Member ScriptMethod Kill {}
  Fails {WaitProcess $unknown 1 'synthetic_timeout'} 'synthetic_timeout;cleanup_unknown_type=System.TimeoutException'
  # Actual public temporary files exercise the new live/strict byte boundary.
  $root=$dir;$ownedPath=Join-Path $dir 'owned-journal.json'
  $owner=@{task_id='public-task';command_id='public-command';hash=('a'*64);version='3.2.695';operation='upgrade';class='agent_only';artifact_id='public-artifact';arch='arm64';manifest=(Join-Path $dir 'public-manifest.json')}
  $journal=[ordered]@{schema_version=2;task_id=$owner.task_id;command_id=$owner.command_id;hash=$owner.hash;version=$owner.version;operation=$owner.operation;upgrade_class=$owner.class;artifact_id=$owner.artifact_id;stage='health_observation';status='running'}
  $journalText=($journal | ConvertTo-Json -Depth 8 -Compress)
  PublicText $journalText
  $ready=ReadOwnedUpdateJson 'journal' $ownedPath $owner -Live
  Checked ($ready.state -ceq 'ready' -and $ready.value.stage -ceq 'health_observation') 'valid_live_journal'
  $missing=Join-Path $dir 'missing-owned-journal.json'
  $absent=ReadOwnedUpdateJson 'journal' $missing $owner -Live
  Checked ($absent.state -ceq 'transient' -and $absent.reason -ceq 'not_found') 'missing_live_not_transient'
  FailsType {ReadOwnedUpdateJson 'journal' $missing $owner} ([Management.Automation.ItemNotFoundException])
  [IO.File]::WriteAllBytes($ownedPath,[byte[]]@(255))
  FailsType {ReadOwnedUpdateJson 'journal' $ownedPath $owner -Live} ([Text.DecoderFallbackException])
  PublicText '{"schema_version":'
  FailsHard {ReadOwnedUpdateJson 'journal' $ownedPath $owner -Live}
  foreach($text in @(('['+$journalText+','+$journalText+']'),('['+$journalText+']'),'null','"public-scalar"','7')){
    PublicText $text
    Fails {ReadOwnedUpdateJson 'journal' $ownedPath $owner -Live} 'owned_json_object_required'
  }
  foreach($badSchema in @('"2"','[2]','2.0','true')){
    PublicText ($journalText.Replace('"schema_version":2',('"schema_version":'+$badSchema)))
    Fails {ReadOwnedUpdateJson 'journal' $ownedPath $owner -Live} 'owned_journal_identity'
  }
  PublicText ($journalText.Replace(('"hash":"'+$owner.hash+'"'),('"hash":["'+$owner.hash+'"]')))
  Fails {ReadOwnedUpdateJson 'journal' $ownedPath $owner -Live} 'owned_journal_field_type'
  PublicText ($journalText.Replace('public-task','wrong-public-task'))
  Fails {ReadOwnedUpdateJson 'journal' $ownedPath $owner -Live} 'owned_journal_identity'
  $report=[ordered]@{target_version=$owner.version;operation=$owner.operation;upgrade_class=$owner.class;expected_architecture=$owner.arch;expected_sha256=$owner.hash;runtime_manifest=$owner.manifest;status='succeeded'}
  $reportText=$report | ConvertTo-Json -Depth 8 -Compress
  PublicText ($reportText.Replace(('"expected_sha256":"'+$owner.hash+'"'),('"expected_sha256":["'+$owner.hash+'"]')))
  Fails {ReadOwnedUpdateJson 'report' $ownedPath $owner} 'owned_report_field_type'
  [IO.File]::WriteAllBytes($ownedPath,(New-Object byte[] 1048577))
  Fails {ReadOwnedUpdateJson 'journal' $ownedPath $owner -Live} 'owned_read_regular_cap_required'
  PublicText $journalText
  $link=Join-Path $dir 'owned-file-symlink.json'
  # The Windows runner is already elevated; no privilege is enabled by this test.
  New-Item -ItemType SymbolicLink -Path $link -Value $ownedPath | Out-Null
  Fails {ReadOwnedUpdateJson 'journal' $link $owner -Live} 'owned_read_regular_cap_required'
  $locked=[IO.File]::Open($ownedPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None)
  try {
    $sharing=ReadOwnedUpdateJson 'journal' $ownedPath $owner -Live
    Checked ($sharing.state -ceq 'transient' -and $sharing.reason -ceq 'sharing') 'sharing_live_not_transient'
    FailsType {ReadOwnedUpdateJson 'journal' $ownedPath $owner} ([IO.IOException])
  }finally{$locked.Dispose()}
  # These four cases stub metadata races, not a real concurrent writer.
  $metadataPath=[IO.Path]::GetFullPath($ownedPath)
  foreach($mode in @('before_oversize','after_oversize','after_reparse')){
    $metadataMode=$mode;$metadataCalls=0
    try{Fails {ReadOwnedUpdateJson 'journal' $ownedPath $owner -Live} 'owned_read_regular_cap_required'}finally{$metadataMode=''}
  }
  $metadataMode='changed';$metadataCalls=0
  try{
    $changed=ReadOwnedUpdateJson 'journal' $ownedPath $owner -Live
    Checked ($changed.state -ceq 'transient' -and $changed.reason -ceq 'source_changed') 'changed_live_not_transient'
  }finally{$metadataMode=''}
  $metadataMode='changed';$metadataCalls=0
  try{Fails {ReadOwnedUpdateJson 'journal' $ownedPath $owner} 'owned_source_changed'}finally{$metadataMode=''}
  # Final originals must be the exact validated bytes, including whitespace.
  $originalJournal=" `r`n"+$journalText+"`r`n"
  PublicText $originalJournal
  $journalBytes=[IO.File]::ReadAllBytes($ownedPath)
  $saved=SaveOwnedOriginal 'journal' $ownedPath $owner 'public-byte-proof'
  $savedBytes=[IO.File]::ReadAllBytes((Join-Path $dir 'public-byte-proof.original-journal.json'))
  Checked ($saved.status -ceq 'captured' -and [Convert]::ToBase64String($journalBytes) -ceq [Convert]::ToBase64String($savedBytes)) 'journal_original_bytes_changed'
  $reportPath=Join-Path $dir 'owned-report.json'
  [IO.File]::WriteAllText($reportPath,("`r`n"+$reportText+" `r`n"),[Text.UTF8Encoding]::new($false))
  $reportBytes=[IO.File]::ReadAllBytes($reportPath)
  $saved=SaveOwnedOriginal 'report' $reportPath $owner 'public-byte-proof'
  $savedBytes=[IO.File]::ReadAllBytes((Join-Path $dir 'public-byte-proof.original-report.json'))
  Checked ($saved.status -ceq 'captured' -and [Convert]::ToBase64String($reportBytes) -ceq [Convert]::ToBase64String($savedBytes)) 'report_original_bytes_changed'
  $d=DiagnosticStub;$failed=SaveTransitionFinalEvidence (ChildStub $false ([int]0)) $d $owner 'public-running' $ownedPath $reportPath
  Checked ($failed -and -not $d.terminal_known -and $d.originals.report.status -ceq 'not_captured' -and -not(Test-Path -LiteralPath (Join-Path $dir 'public-running.original-report.json'))) 'active_child_evidence_captured'
  $d=DiagnosticStub;$failed=SaveTransitionFinalEvidence $null $d $owner 'public-no-child' $ownedPath $reportPath
  Checked ($failed -and -not $d.exit_known -and $d.originals.report.status -ceq 'not_captured') 'missing_child_became_terminal'
  foreach($badExit in @($null,([long]7))){
    $d=DiagnosticStub;$failed=SaveTransitionFinalEvidence (ChildStub $true $badExit) $d $owner 'public-unknown-exit' $ownedPath $reportPath
    Checked ($failed -and $d.terminal_known -and -not $d.exit_known -and $d.originals.journal.status -ceq 'not_captured') 'non_int32_exit_became_known'
  }
  $d=DiagnosticStub;$failed=SaveTransitionFinalEvidence (ChildStub $true ([int]7)) $d $owner 'public-exited' $ownedPath $reportPath
  Checked (-not $failed -and $d.terminal_known -and $d.exit_known -and $d.exit_code -eq 7 -and $d.originals.report.status -ceq 'captured' -and $d.originals.journal.status -ceq 'captured' -and $d.primary_failure_type -ceq 'public-primary-sentinel') 'terminal_evidence_capture_contract'
  $d=DiagnosticStub;$failed=SaveTransitionFinalEvidence (ChildStub $true ([int]7)) $d $owner 'public-missing-report' $ownedPath $missing
  Checked ($failed -and $d.originals.report.status -ceq 'capture_failed' -and $d.originals.journal.status -ceq 'captured' -and $d.primary_failure_type -ceq 'public-primary-sentinel') 'secondary_capture_masked_primary'
  $summary=SaveRecoverySummary @{public=$true} $false
  Checked ($summary.saved -and (Test-Path -LiteralPath (Join-Path $dir 'recovery-subset-summary.json'))) 'summary_success_missing'
  # Stub only the output I/O owner; neither driver top-level nor SCM runs here.
  $originalSave=@($functions | Where-Object {$_.Name -ceq 'Save'})[0].Extent.Text
  function Save([string]$Name,$Value){throw [IO.IOException]::new('public-summary-write-failure')}
  try {
    $secondary=SaveRecoverySummary @{public=$true} $true 3>$null
    Checked (-not $secondary.saved -and $secondary.exception_type -ceq 'System.IO.IOException') 'summary_secondary_not_typed'
    FailsType {SaveRecoverySummary @{public=$true} $false} ([IO.IOException])
    $primaryCaught=$null;$mainHadPrimary=$false
    try {
      try{throw 'public-original-primary'}catch{$mainHadPrimary=$true;throw}finally{SaveRecoverySummary @{public=$true} $mainHadPrimary 3>$null | Out-Null}
    }catch{$primaryCaught=$_.Exception.Message}
    Checked ($primaryCaught -ceq 'public-original-primary') 'summary_failure_replaced_primary'
  }finally{Invoke-Expression $originalSave}
  # Service observers: only public temporary files and fake exact-owned child
  # objects. StartWindowsPowerShellChild is shadowed; no generated SCM script runs.
  $script:serviceMock='';$script:serviceMockId=2147483000;$script:serviceWaits=New-Object Collections.ArrayList
  function ServiceMockChild([string]$Role) {
    $script:serviceMockId++
    $v=[pscustomobject]@{Id=$script:serviceMockId;StartTime=[DateTime]::Parse('2026-01-01T00:00:00Z').ToUniversalTime();HasExited=$false;ExitCode=$null;Role=$Role;Killed=$false;WaitCount=0}
    $v | Add-Member ScriptMethod Refresh {}
    $v | Add-Member ScriptMethod Kill {
      if($this.Role -ceq 'sampler' -and $script:serviceMock -ceq 'timeout_and_sampler_cleanup'){throw [IO.IOException]::new('public-cleanup-error')}
      $this.Killed=$true;$this.HasExited=$true;$this.ExitCode=[int]-1
    }
    $v | Add-Member ScriptMethod WaitForExit {
      param($Ms)
      $null=$script:serviceWaits.Add([int]$Ms);$this.WaitCount++
      if($this.Role -ceq 'worker'){
        if($script:serviceMock -ceq 'timeout_and_sampler_cleanup' -and $this.WaitCount -eq 1){return $false}
        $this.HasExited=$true
        if(-not $this.Killed){$this.ExitCode=if($script:serviceMock -ceq 'nonzero'){[int]7}elseif($script:serviceMock -ceq 'null_exit'){$null}else{[int]0}}
      }
      return $true
    }
    return $v
  }
  function StartWindowsPowerShellChild([string]$ScriptPath,[string]$StandardOutput,[string]$StandardError) {
    $role=if($ScriptPath.EndsWith('.service-sampler.ps1',[StringComparison]::Ordinal)){'sampler'}else{'worker'}
    if($role -ceq 'sampler' -and $script:serviceMock -ceq 'sampler_launch'){throw [InvalidOperationException]::new('public-launch-error')}
    $public=if($role -ceq 'sampler'){'{"schema":"edr.service-scm-sample.v1","state":"Unknown"}'}else{'{"schema":"edr.service-action.phase.v1","phase":"completed","state":""}'}
    if($role -ceq 'worker' -and $script:serviceMock -ceq 'oversize'){$public='x'*4097}
    [IO.File]::WriteAllText($StandardOutput,$public,[Text.UTF8Encoding]::new($false));[IO.File]::WriteAllBytes($StandardError,[byte[]]@())
    return (ServiceMockChild $role)
  }
  function ServiceCase([string]$Mode) {
    $script:serviceMock=$Mode;$script:serviceWaits=New-Object Collections.ArrayList
    $script:root=Join-Path $dir ('service-'+$Mode);New-Item -ItemType Directory -Path $script:root | Out-Null
    $script:serviceActionDiagnostics=New-Object Collections.ArrayList
  }
  foreach($action in @('Stop','Start','stop')){
    $body=ServiceWorkerSource $action;$pt=$null;$pe=$null
    $null=[Management.Automation.Language.Parser]::ParseInput($body,[ref]$pt,[ref]$pe)
    Checked (@($pe).Count -eq 0 -and $body.Contains("Get-Service -Name FDSecurityAgent -ErrorAction Stop") -and $body.Contains("[TimeSpan]::FromSeconds(30)")) 'worker_source_parse_and_fixed_owner'
  }
  $samplerSource=ServiceSamplerSource;$pt=$null;$pe=$null
  $samplerAst=[Management.Automation.Language.Parser]::ParseInput($samplerSource,[ref]$pt,[ref]$pe)
  Checked (@($pe).Count -eq 0 -and $samplerSource.Contains('$i -lt 46') -and $samplerSource.Contains('16384') -and $samplerSource.Contains("Name='FDSecurityAgent'")) 'sampler_source_bounds_and_parse'
  # Execute only the source-owned nullable scalar loop, with no CIM invocation.
  $nullable=@($samplerAst.FindAll({param($n) $n -is [Management.Automation.Language.ForEachStatementAst] -and $n.Variable.VariablePath.UserPath -ceq 'field'},$true))
  if($nullable.Count -ne 1){throw 'sampler_nullable_loop_inventory'}
  $row=@{checkpoint=$null;wait_hint_ms=$null;service_pid=$null;win32_exit_code=$null;service_exit_code=$null}
  $s=[pscustomobject]@{CheckPoint=$null;WaitHint=$null;ProcessId=$null;ExitCode=$null;ServiceSpecificExitCode=$null}
  Invoke-Expression $nullable[0].Extent.Text
  Checked ($null -eq $row.checkpoint -and $null -eq $row.wait_hint_ms -and $null -eq $row.service_pid -and $null -eq $row.win32_exit_code -and $null -eq $row.service_exit_code) 'nullable_scm_fields_not_zero'
  $s=[pscustomobject]@{CheckPoint=0;WaitHint=1000;ProcessId=0;ExitCode=5;ServiceSpecificExitCode=0}
  Invoke-Expression $nullable[0].Extent.Text
  Checked ($row.checkpoint -eq 0 -and $row.wait_hint_ms -eq 1000 -and $row.service_pid -eq 0 -and $row.win32_exit_code -eq 5 -and $row.service_exit_code -eq 0) 'observed_scm_zero_and_nonzero_preserved'
  try{throw [ComponentModel.Win32Exception]::new(5,'private-error-not-exported')}catch{$typed=ServiceObserverError $_}
  Checked ($typed.native_error_code -eq 5 -and ($typed|ConvertTo-Json -Compress) -notmatch 'private-error-not-exported') 'native_error_actual_chain_only'
  try{throw [IO.IOException]::new('private-error-not-exported')}catch{$typed=ServiceObserverError $_}
  Checked ($null -eq $typed.native_error_code) 'native_error_not_invented'
  ServiceCase 'normal';ServiceAction 'Stop' 'health-failed-upgrade-health-stop'
  $v=$serviceActionDiagnostics[0]
  Checked ($serviceWaits[0] -eq 45000 -and $v.worker.terminal_known -and $v.worker.exit_known -and $v.worker.exit_code -eq 0 -and $v.sampler.cancel_requested -and $v.sampler.terminal_known -and $v.observer_complete) 'observed_stop_exact_wait_and_sampler_cleanup'
  $bytes=[Convert]::FromBase64String($v.worker.stdout.base64);$sha=[Security.Cryptography.SHA256]::Create()
  try{$digest=([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
  Checked ($bytes.Length -eq $v.worker.stdout.bytes -and $digest -ceq $v.worker.stdout.sha256 -and $v.worker.stdout.original_bytes_preserved) 'service_raw_same_bytes_hash'
  ServiceCase 'repair';ServiceAction 'Start' 'repair-start'
  Checked (-not $serviceActionDiagnostics[0].sampler.requested -and $serviceWaits.Count -eq 1 -and $serviceWaits[0] -eq 45000) 'repair_no_sampler_or_extra_control'
  ServiceCase 'nonzero';Fails {ServiceAction 'Stop' 'health-failed-upgrade-health-stop'} 'service_control_failed'
  Checked ($serviceActionDiagnostics[0].worker.exit_known -and $serviceActionDiagnostics[0].worker.exit_code -eq 7) 'service_nonzero_recorded'
  ServiceCase 'null_exit';Fails {ServiceAction 'Stop' 'health-failed-upgrade-health-stop'} 'service_control_exit_unknown'
  Checked ($serviceActionDiagnostics[0].worker.terminal_known -and -not $serviceActionDiagnostics[0].worker.exit_known) 'service_null_not_pass'
  ServiceCase 'timeout_and_sampler_cleanup';Fails {ServiceAction 'Stop' 'health-failed-upgrade-health-stop'} 'service_control_unknown_no_retry'
  $v=$serviceActionDiagnostics[0]
  Checked ($serviceWaits[0] -eq 45000 -and $serviceWaits[1] -eq 10000 -and $null -ne $v.sampler.cleanup_error -and $v.sampler.stdout.status -ceq 'not_captured' -and $null -ne $v.primary_failure) 'cleanup_failure_preserves_primary_and_no_live_read'
  ServiceCase 'sampler_launch';Fails {ServiceAction 'Stop' 'health-failed-upgrade-health-stop'} 'service_action_diagnostic_incomplete'
  Checked ($serviceActionDiagnostics[0].worker.exit_code -eq 0 -and $null -ne $serviceActionDiagnostics[0].sampler.launch_error) 'sampler_launch_unknown_not_pass'
  ServiceCase 'oversize';Fails {ServiceAction 'Stop' 'health-failed-upgrade-health-stop'} 'service_action_diagnostic_incomplete'
  Checked ($serviceActionDiagnostics[0].worker.stdout.status -ceq 'capture_failed') 'worker_raw_cap_hard_failure'
  $rawOut=Join-Path $dir 'public-sampler-out';$rawErr=Join-Path $dir 'public-sampler-err'
  [IO.File]::WriteAllText($rawOut,('a'*16000),[Text.UTF8Encoding]::new($false));[IO.File]::WriteAllText($rawErr,('b'*500),[Text.UTF8Encoding]::new($false))
  $s=ServiceMockChild 'sampler';$s.HasExited=$true;$s.ExitCode=[int]0
  $v=@{pid=$null;birth_filetime=$null;terminal_known=$false;exit_known=$false;exit_code=$null}
  $failed=FinishServiceObserver $s $v $rawOut $rawErr 16384 -Combined
  Checked ($failed -and $v.stdout.bytes -eq 16000 -and $v.stderr.status -ceq 'capture_failed' -and -not $v.stderr.ContainsKey('base64')) 'sampler_combined_cap_no_extra_raw'
  [IO.File]::WriteAllBytes($rawOut,[byte[]]@(255))
  FailsType {ServiceRaw $rawOut 4096} ([Text.DecoderFallbackException])
  Write-Output ('driver_pure_contracts passed='+$count+' source_sha256='+$DriverSha256+' top_level_executed=false native_child_executed=false')
} finally {Remove-Item -LiteralPath $dir -Recurse -Force}
