#Requires -Version 5.1
# Pure local function tests: one public PowerShell file-writer child; no SCM, installer, Agent, or network.
[CmdletBinding()]
param(
  [string]$DriverSource=(Join-Path $PSScriptRoot 'windows_cache_recovery_ci.ps1'),
  [Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9]{64}$')][string]$DriverSha256
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$source=$DriverSource
$sourceFile=Get-Item -LiteralPath $source -Force
if ($sourceFile.PSIsContainer -or ($sourceFile.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $sourceFile.Length -gt 131072 -or (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant() -cne $DriverSha256) {throw 'driver_source_pin'}
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($source,[ref]$tokens,[ref]$errors)
if (@($errors).Count) {throw 'driver_parse_failed'}
if ((Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant() -cne $DriverSha256) {throw 'driver_source_changed'}
$wanted=@('Need','Regular','SHA','Wait-EmbeddedUpdaterMaterialized','ReadBounded','ConfigBinding','WaitProcess','ReadOwnedBytes','ReadOwnedUpdateJson','SaveOwnedOriginal','SaveTransitionFinalEvidence','Save','SaveRecoverySummary','ServiceObserverError','ServiceWorkerSource','ServiceSamplerSource','ServiceChildStatus','ServiceRaw','FinishServiceObserver','ServiceAction','StopLogNative','StopLogInfo','StopLogOpen','StopLogConfig','StopLogTarget','NewStopLogContext','StopLogAnchor','ReadStopLogSlice','ObserveStopLog','CloseStopLogContext')
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
  # Real public files exercise the source-owned readiness function. Only this
  # same-host PowerShell worker writes; no installer/Agent/resolver is invoked.
  $readinessHadInstall=$null -ne (Get-Variable -Name install -Scope Script -ErrorAction SilentlyContinue)
  if($readinessHadInstall){$readinessOldInstall=$script:install}
  $script:install=Join-Path $dir 'public-updater-readiness';New-Item -ItemType Directory -Path $script:install | Out-Null
  try {
    $publicExpected=Join-Path $dir 'public-expected-updater.ps1'
    [IO.File]::WriteAllText($publicExpected,'public-updater-body',[Text.UTF8Encoding]::new($false))
    $publicReady=Join-Path $script:install 'edr_agent_inplace_update-0.0.1.ps1'
    FailsType {Regular $publicReady 1048576} ([Management.Automation.ItemNotFoundException])
    $writerSource=Join-Path $dir 'public-updater-file-writer.ps1'
    $writerBody=@'
$ErrorActionPreference='Stop'
Start-Sleep -Milliseconds 300
[IO.File]::WriteAllText('__DEST__.public-tmp','public-updater-body',[Text.UTF8Encoding]::new($false))
[IO.File]::Move('__DEST__.public-tmp','__DEST__')
'@
    [IO.File]::WriteAllText($writerSource,$writerBody.Replace('__DEST__',$publicReady.Replace("'","''")),[Text.UTF8Encoding]::new($false))
    $writerOut=Join-Path $dir 'public-updater-file-writer.stdout';$writerErr=Join-Path $dir 'public-updater-file-writer.stderr'
    $hostExe=(Microsoft.PowerShell.Management\Get-Process -Id $PID).Path
    $writer=$null;$writerPrimary=$null
    try {
      $writer=Microsoft.PowerShell.Management\Start-Process -FilePath $hostExe -ArgumentList @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',('"'+$writerSource+'"')) -PassThru -RedirectStandardOutput $writerOut -RedirectStandardError $writerErr
      # Test only: cache this owned handle before terminal on Windows PowerShell.
      $null=$writer.Handle
      $ready=Wait-EmbeddedUpdaterMaterialized -Version '0.0.1' -ExpectedScript $publicExpected -Seconds 10
      Checked ($ready -ceq $publicReady -and (SHA (Regular $ready 1048576)) -ceq (SHA $publicExpected)) 'embedded_updater_delayed_natural_file_ready'
      Need ($writer.WaitForExit(5000)) 'public_updater_writer_terminal_unknown'
      $writer.Refresh()
      Checked ($writer.HasExited -and $writer.ExitCode -is [int] -and $writer.ExitCode -eq 0 -and (Get-Item -LiteralPath $writerOut).Length -eq 0 -and (Get-Item -LiteralPath $writerErr).Length -eq 0) 'public_updater_writer_known_exit_and_empty_streams'
    }catch{$writerPrimary=$_;throw}finally{
      if($null -ne $writer){
        try{if(-not $writer.HasExited){$writer.Kill();Need ($writer.WaitForExit(5000)) 'public_updater_writer_cleanup_unknown'}}
        catch{if($null -eq $writerPrimary){throw};[Console]::Error.WriteLine('public_updater_writer_secondary_cleanup_unknown')}
        finally{try{$writer.Dispose()}catch{if($null -eq $writerPrimary){throw};[Console]::Error.WriteLine('public_updater_writer_secondary_dispose_unknown')}}
      }
    }
    Checked ((Wait-EmbeddedUpdaterMaterialized -Version '0.0.1' -ExpectedScript $publicExpected -Seconds 1) -ceq $publicReady) 'embedded_updater_stable_correct_file_ready'
    [IO.File]::WriteAllText($publicReady,'wrong-public-updater-body',[Text.UTF8Encoding]::new($false))
    Fails {Wait-EmbeddedUpdaterMaterialized -Version '0.0.1' -ExpectedScript $publicExpected -Seconds 1} 'embedded_updater_hash_mismatch'
    Remove-Item -LiteralPath $publicReady -Force
    Fails {Wait-EmbeddedUpdaterMaterialized -Version '0.0.1' -ExpectedScript $publicExpected -Seconds 1} 'embedded_updater_materialization_timeout'
  }finally{if($readinessHadInstall){$script:install=$readinessOldInstall}else{Remove-Variable -Name install -Scope Script -ErrorAction SilentlyContinue}}
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
  try{throw 'stop_log_anchor_changed'}catch{$typed=ServiceObserverError $_}
  Checked ($typed.cause_code -ceq 'stop_log_anchor_changed') 'observer_exact_need_code'
  try{throw 'private-synthetic-path stop_log_anchor_changed private-text'}catch{$typed=ServiceObserverError $_}
  Checked ($typed.cause_code -ceq 'unknown' -and ($typed|ConvertTo-Json -Depth 8 -Compress) -notmatch 'private-synthetic-path|private-text') 'observer_unknown_text_never_exported'
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
  # New selected-log tests: real public files/Win32 file identity, current test
  # process as the public target stand-in. No Agent, service, or native child.
  $originalLogVariables=@{}
  foreach($name in @('install','agent','configPath','configSha256')){$v=Get-Variable -Name $name -Scope Script -ErrorAction SilentlyContinue;if($null -ne $v){$originalLogVariables[$name]=$v.Value}}
  StopLogNative
  Checked ([Runtime.InteropServices.Marshal]::SizeOf([type]'EdrRecoveryLogReadV1+Info') -eq 52) 'log_native_file_information_layout'
  # Canonicalize this existing public temp directory by its own handle, so
  # RUNNER~1 and the long name are not confused with a different file.
  $publicDirectoryHandle=[EdrRecoveryLogReadV1]::CreateFileW($dir,0x80,7,[IntPtr]::Zero,3,0x02200000,[IntPtr]::Zero)
  Need (-not $publicDirectoryHandle.IsInvalid) 'public_log_test_directory_handle'
  try{$publicDirectoryName=New-Object Text.StringBuilder 1024;$n=[EdrRecoveryLogReadV1]::GetFinalPathNameByHandleW($publicDirectoryHandle,$publicDirectoryName,1024,0);Need ($n -gt 4 -and $n -lt 1024) 'public_log_test_directory_name';$publicDirectory=$publicDirectoryName.ToString().Substring(4)}finally{$publicDirectoryHandle.Dispose()}
  $script:install=Join-Path $publicDirectory 'public-log-fixture';$null=New-Item -ItemType Directory -Path (Join-Path $script:install 'logs')
  $self=Get-Process -Id $PID
  $script:agent=$self.Path;$script:configPath=Join-Path $script:install 'agent.toml'
  $logPath=Join-Path $script:install 'logs\agent.log'
  $publicConfig='[logging]'+"`n"+'log_dir = "'+(Join-Path $script:install 'logs').Replace('\','\\')+'"'+"`n"
  function ResetPublicLog {
    [IO.File]::WriteAllText($script:configPath,$publicConfig,[Text.UTF8Encoding]::new($false));$script:configSha256=SHA $script:configPath
    [IO.File]::WriteAllText($logPath,"public pre-trigger line`n",[Text.UTF8Encoding]::new($false))
  }
  function PublicLogContext {
    $native=@{pid=$PID;birth_filetime=$self.StartTime.ToUniversalTime().ToFileTimeUtc().ToString();exe_sha256=('a'*64);config_sha256=$script:configSha256;fixture_config_binding_verified=$true;service_config_argv_verified=$true}
    return (NewStopLogContext $native $source)
  }
  function PublicAppend([string]$Text) {[IO.File]::AppendAllText($logPath,$Text,[Text.UTF8Encoding]::new($false))}
  $ctx=$null
  try {
    ResetPublicLog;$ctx=PublicLogContext
    Checked ($ctx.ready -and $ctx.diagnostic.driver_source_sha256 -ceq $DriverSha256 -and $ctx.diagnostic.start_offset -gt 0 -and $ctx.diagnostic.file_identity) 'log_real_file_identity_source_and_before_offset'
    PublicAppend "unexported-test-message and command body`n[shutdown] SCM stage publication failed stage=18 error=5`n[preprocess] shutdown timed out; retaining worker dependencies`n"
    ReadStopLogSlice $ctx 1
    Checked ($ctx.diagnostic.matches.Count -eq 2 -and $ctx.diagnostic.matches[0].kind -ceq 'scm_stage_publication_failed' -and $ctx.diagnostic.matches[0].stage -eq 18 -and $ctx.diagnostic.matches[0].error -eq 5 -and $ctx.diagnostic.matches[1].kind -ceq 'preprocess_thread_join_timeout') 'log_only_fixed_numeric_and_preprocess_lines'
    Checked (($ctx.diagnostic|ConvertTo-Json -Depth 8 -Compress) -notmatch 'unexported-test-message|command body') 'log_other_body_never_exported'
    PublicAppend '[preprocess] shutdown timed out: AVE still '
    ReadStopLogSlice $ctx 2
    Checked ($ctx.diagnostic.matches.Count -eq 2 -and $ctx.diagnostic.trailing_bytes -gt 0) 'log_partial_line_not_classified'
    PublicAppend "owns the batch sink`n";ReadStopLogSlice $ctx 3
    Checked ($ctx.diagnostic.matches.Count -eq 3 -and $ctx.diagnostic.matches[2].kind -ceq 'preprocess_AVE_drain_timeout') 'log_partial_line_joins_before_exact_match'
    PublicAppend "prefix [shutdown] SCM status publication failed error=5`n[Preprocess] shutdown timed out; retaining worker dependencies`n[shutdown] SCM status publication failed error=5`r`r`n";ReadStopLogSlice $ctx 4
    Checked ($ctx.diagnostic.matches.Count -eq 3) 'log_near_matches_not_classified'
    $publicBytes=[IO.File]::ReadAllBytes($logPath);$sha=[Security.Cryptography.SHA256]::Create()
    try{$expectedNewHash=([BitConverter]::ToString($sha.ComputeHash($publicBytes,[int]$ctx.diagnostic.start_offset,[int]$ctx.diagnostic.bytes_read))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
    CloseStopLogContext $ctx;Checked ($ctx.diagnostic.validated_new_bytes_sha256 -ceq $expectedNewHash) 'log_exact_validated_new_source_bytes_hash'
    Checked ($null -eq $ctx.stream -and $null -eq $ctx.process -and $ctx.diagnostic.cleanup_error_types.Count -eq 0) 'log_owned_readers_closed_no_kill'
    ResetPublicLog;$ctx=PublicLogContext;PublicAppend "[shutdown] SCM stage publication failed stage=99 error=5`n"
    Fails {ReadStopLogSlice $ctx 1} 'stop_log_numeric_shape';CloseStopLogContext $ctx
    ResetPublicLog;$ctx=PublicLogContext;Move-Item -LiteralPath $logPath -Destination ($logPath+'.old')
    [IO.File]::WriteAllText($logPath,"replacement`n",[Text.UTF8Encoding]::new($false))
    Fails {ReadStopLogSlice $ctx 1} 'stop_log_rotation_or_replacement';CloseStopLogContext $ctx
    ResetPublicLog;$ctx=PublicLogContext;[IO.File]::WriteAllText($logPath,'',[Text.UTF8Encoding]::new($false))
    Fails {ReadStopLogSlice $ctx 1} 'stop_log_truncated_or_changed';CloseStopLogContext $ctx
    ResetPublicLog;$ctx=PublicLogContext;[IO.File]::WriteAllText($logPath,(('x'*128)+"`n"),[Text.UTF8Encoding]::new($false))
    Fails {ReadStopLogSlice $ctx 1} 'stop_log_anchor_changed';CloseStopLogContext $ctx
    ResetPublicLog;$ctx=PublicLogContext;[IO.File]::AppendAllText($script:configPath,"#changed`n",[Text.UTF8Encoding]::new($false))
    Fails {ReadStopLogSlice $ctx 1} 'stop_log_config_hash_changed';CloseStopLogContext $ctx
    ResetPublicLog;$ctx=PublicLogContext;PublicAppend ('x'*65537)
    Fails {ReadStopLogSlice $ctx 1} 'stop_log_new_bytes_bound';CloseStopLogContext $ctx
    ResetPublicLog;$ctx=PublicLogContext;$publicChunk=('x'*4095)+"`n"
    PublicAppend ($publicChunk*8);ReadStopLogSlice $ctx 1
    PublicAppend ($publicChunk*8);ReadStopLogSlice $ctx 2
    Checked ($ctx.diagnostic.bytes_read -eq 65536 -and $ctx.diagnostic.matches.Count -eq 0) 'log_cumulative_budget_across_reads'
    PublicAppend "`n";Fails {ReadStopLogSlice $ctx 3} 'stop_log_new_bytes_bound';CloseStopLogContext $ctx
    ResetPublicLog;$ctx=PublicLogContext;PublicAppend ('x'*4090);ReadStopLogSlice $ctx 1
    PublicAppend ('x'*7);Fails {ReadStopLogSlice $ctx 2} 'stop_log_line_bound';CloseStopLogContext $ctx
    ResetPublicLog;$ctx=PublicLogContext;PublicAppend (('x'*4097)+"`n")
    Fails {ReadStopLogSlice $ctx 1} 'stop_log_line_bound';CloseStopLogContext $ctx
    ResetPublicLog;$ctx=PublicLogContext;ObserveStopLog $ctx 0
    Checked ($ctx.diagnostic.status -ceq 'unknown' -and $ctx.diagnostic.matches.Count -eq 0 -and -not $ctx.diagnostic.action_result_can_change) 'log_absence_is_unknown_not_exclusion_or_success';CloseStopLogContext $ctx
    # Test-only real read followed by an injected delay exceeding the selected
    # small observation window. No hard-realtime/storage-latency claim.
    $oldSlice=(Get-Item Function:\ReadStopLogSlice).ScriptBlock;$script:delayedSliceReads=0
    function ReadStopLogSlice($Context,[long]$ElapsedMs) {& $oldSlice $Context $ElapsedMs;$script:delayedSliceReads++;Start-Sleep -Milliseconds 120}
    try {
      ResetPublicLog;$ctx=PublicLogContext;PublicAppend "[preprocess] shutdown failed: pending batch has no durable owner`n"
      $primarySentinel=@{type='unchanged-original-action-failure';exit_code=[int]-1}
      ObserveStopLog $ctx 100
      Checked ($delayedSliceReads -eq 1 -and $ctx.diagnostic.status -ceq 'unknown' -and -not $ctx.diagnostic.within_observation_budget -and $ctx.diagnostic.matches.Count -eq 1 -and $primarySentinel.exit_code -eq -1 -and $primarySentinel.type -ceq 'unchanged-original-action-failure') 'log_after_io_deadline_preserves_matches_but_not_success'
    }finally{CloseStopLogContext $ctx;Set-Item Function:\ReadStopLogSlice $oldSlice}
    # A deterministic target-exit seam, not a real target/process operation.
    $oldTarget=(Get-Item Function:\StopLogTarget).ScriptBlock
    function StopLogTarget($Context) {throw 'stop_log_target_generation_not_live'}
    try{ResetPublicLog;$ctx=PublicLogContext;Checked (-not $ctx.ready -and $ctx.diagnostic.cause -ceq 'context_binding_unknown') 'log_target_exit_binding_is_unknown'}finally{CloseStopLogContext $ctx;Set-Item Function:\StopLogTarget $oldTarget}
    # Held-object state seams. These mocks test acceptance/failure decisions;
    # they do not prove .NET Framework Process behavior after a real exit.
    function PublicMockHeldProcess($Context,[bool]$Exited,$Code=7) {
      $mock=[pscustomobject]@{Handle=$Context.processHandle;HasExited=$Exited;ExitCode=$Code;Id=$Context.native.pid;StartTime=$self.StartTime;Path=$Context.agentPath}
      $mock|Add-Member ScriptMethod Refresh {}; $mock|Add-Member ScriptMethod Dispose {}
      $Context.process.Dispose();$Context.process=$mock
    }
    ResetPublicLog;$ctx=PublicLogContext;PublicMockHeldProcess $ctx $true 7
    PublicAppend "[preprocess] shutdown timed out; retaining worker dependencies`n"
    ObserveStopLog $ctx 500
    Checked ($ctx.diagnostic.held_process.has_exited -and $ctx.diagnostic.held_process.exit_code_known -and $ctx.diagnostic.held_process.exit_code -eq 7 -and $ctx.diagnostic.final_tail.attempted -and $ctx.diagnostic.final_tail.sealed -and $ctx.diagnostic.polls -eq 1 -and $ctx.diagnostic.matches.Count -eq 1 -and -not $ctx.diagnostic.action_result_can_change) 'log_known_held_exit_reads_one_final_fixed_line'
    $sealedOffset=$ctx.offset;PublicAppend "[preprocess] shutdown timed out: AVE still owns the batch sink`n"
    Fails {ReadStopLogSlice $ctx 2} 'stop_log_final_tail_already_attempted'
    Checked ($ctx.offset -eq $sealedOffset -and $ctx.diagnostic.matches.Count -eq 1) 'log_append_after_seal_not_consumed';CloseStopLogContext $ctx
    ResetPublicLog;$ctx=PublicLogContext;PublicMockHeldProcess $ctx $true $null
    PublicAppend "[preprocess] shutdown timed out; retaining worker dependencies`n"
    Fails {ReadStopLogSlice $ctx 1} 'stop_log_target_exit_code_unknown'
    Checked ($ctx.diagnostic.held_process.has_exited -and -not $ctx.diagnostic.held_process.exit_code_known -and -not $ctx.diagnostic.final_tail.attempted -and $ctx.diagnostic.bytes_read -eq 0) 'log_unknown_exit_code_never_reads_tail';CloseStopLogContext $ctx
    ResetPublicLog;$ctx=PublicLogContext;PublicMockHeldProcess $ctx $true 7
    $ctx.process.PSObject.Properties.Remove('ExitCode')
    $ctx.process|Add-Member ScriptProperty ExitCode {throw [InvalidOperationException]::new('unexported-test-message')}
    Fails {ReadStopLogSlice $ctx 1} 'stop_log_target_exit_code_unknown'
    Checked (-not $ctx.diagnostic.held_process.exit_code_known -and -not $ctx.diagnostic.final_tail.attempted -and ($ctx.diagnostic|ConvertTo-Json -Depth 8 -Compress) -notmatch 'unexported-test-message') 'log_throwing_exit_code_no_tail_or_raw_error';CloseStopLogContext $ctx
    ResetPublicLog;$ctx=PublicLogContext;PublicMockHeldProcess $ctx $false 7;$ctx.process.Id++
    Fails {ReadStopLogSlice $ctx 1} 'stop_log_target_generation_not_live'
    Checked (-not $ctx.diagnostic.held_process.has_exited -and -not $ctx.diagnostic.held_process.live_identity_verified -and -not $ctx.diagnostic.final_tail.attempted) 'log_live_mismatch_not_relabelled_exit';CloseStopLogContext $ctx
    ResetPublicLog;$ctx=PublicLogContext;PublicMockHeldProcess $ctx $true 7;$ctx.process.Handle=[IntPtr]::Zero
    Fails {ReadStopLogSlice $ctx 1} 'stop_log_held_handle_changed';CloseStopLogContext $ctx
    # NewStopLogContext refuses a target already exited before its initial bind.
    $oldGetProcessFunction=Get-Item Function:\Get-Process -ErrorAction SilentlyContinue
    $initialDead=[pscustomobject]@{Handle=[IntPtr]1;HasExited=$true;ExitCode=[int]7;Id=$PID;StartTime=$self.StartTime;Path=$script:agent}
    $initialDead|Add-Member ScriptMethod Refresh {}; $initialDead|Add-Member ScriptMethod Dispose {}
    function Get-Process {[CmdletBinding()]param([int]$Id);return $initialDead}
    try {
      ResetPublicLog;$ctx=PublicLogContext
      Checked (-not $ctx.ready -and $ctx.diagnostic.cause -ceq 'context_binding_unknown' -and -not $ctx.diagnostic.final_tail.attempted) 'log_initially_exited_context_never_bound';CloseStopLogContext $ctx
    }finally{Remove-Item Function:\Get-Process;if($null -ne $oldGetProcessFunction){Set-Item Function:\Get-Process $oldGetProcessFunction.ScriptBlock}}
    # A context which was not live-bound before Stop can never gain final-tail authority.
    ResetPublicLog;$ctx=PublicLogContext;PublicMockHeldProcess $ctx $true 7;$ctx.ready=$false
    Fails {ReadStopLogSlice $ctx 1} 'stop_log_target_generation_not_live'
    Checked (-not $ctx.diagnostic.final_tail.attempted) 'log_initial_dead_or_unbound_target_no_tail';CloseStopLogContext $ctx
    # The exit happens during a live read. Discard that buffer; one later final
    # read from the unchanged offset is allowed only inside Observe's budget.
    $oldInfo=(Get-Item Function:\StopLogInfo).ScriptBlock;$script:heldInfoCalls=0
    function StopLogInfo($Stream) {
      if([Object]::ReferenceEquals($Stream,$ctx.stream)){$script:heldInfoCalls++;if($script:heldInfoCalls -eq 2){$ctx.process.HasExited=$true}}
      & $oldInfo $Stream
    }
    try {
      ResetPublicLog;$ctx=PublicLogContext;PublicMockHeldProcess $ctx $false 7;$script:heldInfoCalls=0
      PublicAppend "[preprocess] shutdown failed: pending batch has no durable owner`n"
      ReadStopLogSlice $ctx 1
      Checked ($ctx.exitTailPending -and $ctx.diagnostic.bytes_read -eq 0 -and $ctx.diagnostic.matches.Count -eq 0) 'log_transition_read_not_committed'
      ObserveStopLog $ctx 500
      Checked ($ctx.diagnostic.final_tail.sealed -and $ctx.diagnostic.matches.Count -eq 1 -and $ctx.diagnostic.matches[0].kind -ceq 'preprocess_batch_handoff_failed') 'log_transition_then_one_final_tail';CloseStopLogContext $ctx
      ResetPublicLog;$ctx=PublicLogContext;PublicMockHeldProcess $ctx $false 7;$script:heldInfoCalls=0
      PublicAppend (((('x'*3999)+"`n"))*10)
      ReadStopLogSlice $ctx 1
      Checked ($ctx.diagnostic.read_attempt_bytes -eq 40000 -and $ctx.diagnostic.bytes_read -eq 0) 'log_discarded_read_charged_to_same_budget'
      ObserveStopLog $ctx 500
      Checked ($ctx.diagnostic.status -ceq 'unknown' -and $ctx.diagnostic.error.cause_code -ceq 'stop_log_new_bytes_bound' -and $ctx.diagnostic.read_attempt_bytes -eq 40000 -and -not $ctx.diagnostic.final_tail.sealed) 'log_final_tail_cannot_reread_past_total_budget';CloseStopLogContext $ctx
    }finally{Set-Item Function:\StopLogInfo $oldInfo}
    # Existing file/config/anchor/cap boundaries remain active after known exit.
    ResetPublicLog;$ctx=PublicLogContext;PublicMockHeldProcess $ctx $true 7
    Move-Item -LiteralPath $logPath -Destination ($logPath+'.final-old')
    [IO.File]::WriteAllText($logPath,"replacement`n",[Text.UTF8Encoding]::new($false))
    Fails {ReadStopLogSlice $ctx 1} 'stop_log_rotation_or_replacement';CloseStopLogContext $ctx
    ResetPublicLog;$ctx=PublicLogContext;PublicMockHeldProcess $ctx $true 7;[IO.File]::WriteAllText($logPath,'',[Text.UTF8Encoding]::new($false))
    Fails {ReadStopLogSlice $ctx 1} 'stop_log_truncated_or_changed';CloseStopLogContext $ctx
    ResetPublicLog;$ctx=PublicLogContext;PublicMockHeldProcess $ctx $true 7;[IO.File]::AppendAllText($script:configPath,"#changed`n",[Text.UTF8Encoding]::new($false))
    Fails {ReadStopLogSlice $ctx 1} 'stop_log_config_hash_changed';CloseStopLogContext $ctx
    ResetPublicLog;$ctx=PublicLogContext;PublicMockHeldProcess $ctx $true 7;[IO.File]::WriteAllText($logPath,(('x'*128)+"`n"),[Text.UTF8Encoding]::new($false))
    Fails {ReadStopLogSlice $ctx 1} 'stop_log_anchor_changed';CloseStopLogContext $ctx
    ResetPublicLog;$ctx=PublicLogContext;PublicMockHeldProcess $ctx $true 7;PublicAppend ('x'*65537)
    Fails {ReadStopLogSlice $ctx 1} 'stop_log_new_bytes_bound';CloseStopLogContext $ctx
    # A final read sees a growing file: do not seal or submit its bytes.
    $oldInfo=(Get-Item Function:\StopLogInfo).ScriptBlock;$script:heldInfoCalls=0
    function StopLogInfo($Stream) {
      if([Object]::ReferenceEquals($Stream,$ctx.stream)){$script:heldInfoCalls++;if($script:heldInfoCalls -eq 2){PublicAppend "public concurrent append`n"}}
      & $oldInfo $Stream
    }
    try {
      ResetPublicLog;$ctx=PublicLogContext;PublicMockHeldProcess $ctx $true 7;$script:heldInfoCalls=0
      PublicAppend "[preprocess] shutdown timed out; retaining worker dependencies`n"
      Fails {ReadStopLogSlice $ctx 1} 'stop_log_final_tail_changed_during_read'
      Checked ($ctx.diagnostic.final_tail.attempted -and -not $ctx.diagnostic.final_tail.sealed -and $ctx.diagnostic.bytes_read -eq 0) 'log_unstable_final_tail_unknown';CloseStopLogContext $ctx
    }finally{Set-Item Function:\StopLogInfo $oldInfo}
    $oldSlice=(Get-Item Function:\ReadStopLogSlice).ScriptBlock
    function ReadStopLogSlice($Context,[long]$ElapsedMs) {& $oldSlice $Context $ElapsedMs;Start-Sleep -Milliseconds 120}
    try {
      ResetPublicLog;$ctx=PublicLogContext;PublicMockHeldProcess $ctx $true 7
      PublicAppend "[preprocess] shutdown timed out; retaining worker dependencies`n"
      ObserveStopLog $ctx 100
      Checked ($ctx.diagnostic.status -ceq 'unknown' -and -not $ctx.diagnostic.within_observation_budget -and $ctx.diagnostic.matches.Count -eq 1 -and $ctx.diagnostic.polls -eq 1) 'log_final_tail_slow_io_never_accepts_deadline_overrun';CloseStopLogContext $ctx
    }finally{Set-Item Function:\ReadStopLogSlice $oldSlice}
    ResetPublicLog;$ctx=PublicLogContext;PublicMockHeldProcess $ctx $true 7
    ObserveStopLog $ctx 500
    Checked ($ctx.diagnostic.status -ceq 'unknown' -and $ctx.diagnostic.cause -ceq 'held_process_exited_final_tail_no_match_not_exclusion') 'log_final_tail_zero_matches_still_not_exclusion';CloseStopLogContext $ctx
    # Integration seam only: no 60s delay. Original Stop action fails first;
    # a secondary log exception must not replace that primary failure.
    $oldObserve=(Get-Item Function:\ObserveStopLog).ScriptBlock;$script:logObserveCalls=0;$script:primaryFrozenBeforeLog=$false
    function ObserveStopLog($Context,[int]$MaxMilliseconds=60000) {
      $script:logObserveCalls++;$script:primaryFrozenBeforeLog=($null -ne $script:serviceActionDiagnostics[0].primary_failure -and $script:serviceActionDiagnostics[0].worker.exit_code -eq 7 -and $MaxMilliseconds -eq 60000)
      throw [IO.IOException]::new('unexported-test-message')
    }
    try {
      ResetPublicLog;$ctx=PublicLogContext;ServiceCase 'log-secondary';$script:serviceMock='nonzero'
      Fails {ServiceAction 'Stop' 'health-failed-upgrade-health-stop' $ctx} 'service_control_failed'
      Checked ($primaryFrozenBeforeLog -and $logObserveCalls -eq 1 -and $serviceActionDiagnostics[0].worker.exit_code -eq 7 -and $serviceActionDiagnostics[0].shutdown_log_observation.status -ceq 'unknown' -and $null -eq $ctx.stream) 'log_secondary_does_not_mask_original_failure'
      ResetPublicLog;$ctx=PublicLogContext;ServiceCase 'log-normal';$beforeCalls=$logObserveCalls
      ServiceAction 'Stop' 'health-failed-upgrade-health-stop' $ctx
      Checked ($logObserveCalls -eq $beforeCalls -and $serviceActionDiagnostics[0].worker.exit_code -eq 0 -and $null -eq $ctx.stream) 'log_not_run_for_successful_control'
    }finally{Set-Item Function:\ObserveStopLog $oldObserve}
    ResetPublicLog;$ctx=PublicLogContext;PublicMockHeldProcess $ctx $true 7
    PublicAppend "[preprocess] shutdown timed out; retaining worker dependencies`n"
    ServiceCase 'log-final-tail-primary';$script:serviceMock='nonzero'
    Fails {ServiceAction 'Stop' 'health-failed-upgrade-health-stop' $ctx} 'service_control_failed'
    Checked ($serviceActionDiagnostics[0].worker.exit_code -eq 7 -and $null -ne $serviceActionDiagnostics[0].primary_failure -and $serviceActionDiagnostics[0].shutdown_log_observation.final_tail.sealed -and -not $serviceActionDiagnostics[0].shutdown_log_observation.action_result_can_change) 'log_completed_final_tail_does_not_change_primary_action_failure'
    # Actual public log files: only the fixed numeric join frontier is projected.
    $joinLine='[preprocess] worker join diagnostic wait_rc=258 error=0 phase_before=0 phase_after=2 loops_before=17 loops_after=18 slots_before=3 slots_after=3 stop=1 exited=0'
    ResetPublicLog;$ctx=PublicLogContext;PublicAppend ($joinLine+"`n");ReadStopLogSlice $ctx 1
    $numeric=$ctx.diagnostic.matches[0]
    Checked ($ctx.diagnostic.matches.Count -eq 1 -and $numeric.kind -ceq 'preprocess_worker_join' -and $numeric.wait_rc -eq 258 -and $numeric.error -eq 0 -and $numeric.phase[0] -eq 0 -and $numeric.phase[1] -eq 2 -and $numeric.loops[0] -eq 17 -and $numeric.loops[1] -eq 18 -and $numeric.slots[0] -eq 3 -and $numeric.slots[1] -eq 3 -and $numeric.stop -eq 1 -and $numeric.exited -eq 0) 'join_numeric_public_file_projection';CloseStopLogContext $ctx
    ResetPublicLog;$ctx=PublicLogContext
    PublicAppend ($joinLine.Replace('wait_rc=258 error=0','wait_rc=4294967295 error=5').Replace('phase_after=2','phase_after=12').Replace('slots_after=3','slots_after=18446744073709551615')+"`n");ReadStopLogSlice $ctx 2
    Checked ($ctx.diagnostic.matches.Count -eq 1 -and $ctx.diagnostic.matches[0].wait_rc -eq [uint32]::MaxValue -and $ctx.diagnostic.matches[0].error -eq 5 -and $ctx.diagnostic.matches[0].slots[1] -eq [uint64]::MaxValue) 'join_wait_failed_actual_error_and_uint64_max';CloseStopLogContext $ctx
    foreach($bad in @($joinLine.Replace('wait_rc=258','wait_rc=0'),$joinLine.Replace('error=0','error=5'),$joinLine.Replace('phase_after=2','phase_after=13'),$joinLine.Replace('slots_after=3','slots_after=18446744073709551616'))){
      ResetPublicLog;$ctx=PublicLogContext;PublicAppend ($bad+"`n");Fails {ReadStopLogSlice $ctx 3} 'stop_log_numeric_shape';CloseStopLogContext $ctx
    }
    ResetPublicLog;$ctx=PublicLogContext
    PublicAppend ('unexported-test-message '+$joinLine+"`n"+$joinLine+' command-body-path'+"`n");ReadStopLogSlice $ctx 4
    Checked ($ctx.diagnostic.matches.Count -eq 0 -and ($ctx.diagnostic|ConvertTo-Json -Depth 8 -Compress) -notmatch 'unexported-test-message|command-body-path') 'join_near_match_exports_no_raw_text';CloseStopLogContext $ctx
    ResetPublicLog;$ctx=PublicLogContext;PublicAppend $joinLine;ReadStopLogSlice $ctx 5
    Checked ($ctx.diagnostic.matches.Count -eq 0) 'join_partial_numeric_line_not_projected'
    PublicAppend "`n";ReadStopLogSlice $ctx 6
    Checked ($ctx.diagnostic.matches.Count -eq 1 -and $ctx.diagnostic.matches[0].kind -ceq 'preprocess_worker_join') 'join_partial_numeric_line_completed_once';CloseStopLogContext $ctx
    $max=@{schema='edr.ci-selected-shutdown-log.v1';target=@{pid=4294967295;birth_filetime=('9'*20);exe_sha256=('f'*64);config_sha256=('f'*64)};matches=@()}
    for($i=0;$i -lt 64;$i++){$max.matches+=,@{kind='scm_stage_publication_failed';stage=28;error=[uint32]::MaxValue;read_started_elapsed_ms=60000}}
    Checked ([Text.Encoding]::UTF8.GetByteCount(($max|ConvertTo-Json -Depth 8 -Compress)) -lt 16384) 'log_fixed_max_matches_small_inside_summary_file_cap'
  }finally{
    if($null -ne $ctx){CloseStopLogContext $ctx}
    $self.Dispose()
    foreach($name in @('install','agent','configPath','configSha256')){if($originalLogVariables.ContainsKey($name)){Set-Variable -Name $name -Value $originalLogVariables[$name] -Scope Script}else{Remove-Variable -Name $name -Scope Script -ErrorAction SilentlyContinue}}
  }
  Write-Output ('driver_pure_contracts passed='+$count+' source_sha256='+$DriverSha256+' top_level_executed=false product_or_service_child_executed=false public_powershell_fixture_child_executed=true')
} finally {Remove-Item -LiteralPath $dir -Recurse -Force}
