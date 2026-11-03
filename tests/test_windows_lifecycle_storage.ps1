#Requires -Version 5.1
[CmdletBinding()]
param([string]$RepoRoot=(Split-Path -Parent $PSScriptRoot))
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$root=Join-Path ([IO.Path]::GetTempPath()) ('edr-storage-harness-'+[Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($root)|Out-Null
$cases=New-Object 'System.Collections.Generic.List[string]'
function Pass([string]$Name,[scriptblock]$Action){& $Action;$cases.Add($Name)}
function Reject([string]$Name,[string]$Expected,[scriptblock]$Action){
  $caught=$false
  try{& $Action}catch{$caught=$true;if($_.Exception.Message -notlike $Expected){throw ($Name+': '+$_.Exception.Message)}}
  if(-not $caught){throw ($Name+': unexpectedly accepted')};$cases.Add($Name)
}
try {
  $tokens=$null;$errors=$null
  $driver=[Management.Automation.Language.Parser]::ParseFile((Join-Path $RepoRoot 'scripts/windows_setup_exe_lifecycle_smoke.ps1'),[ref]$tokens,[ref]$errors)
  Pass 'signed_driver_native_syntax_and_optional_legacy_tool_parameter' {
    if($errors.Count -ne 0 -or @($driver.ParamBlock.Parameters|Where-Object{$_.Name.VariablePath.UserPath -ceq 'StorageToolsInput' -and $_.DefaultValue.Extent.Text -ceq "''"}).Count -ne 1){throw 'driver syntax or legacy parameter default changed'}
  }
  $ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $RepoRoot 'tests/Invoke-LifecycleStorageCompatibility.ps1'),[ref]$tokens,[ref]$errors)
  if($errors.Count -ne 0){throw 'storage helper parse failed'}
  foreach($owner in @($ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst]},$true))){. ([scriptblock]::Create($owner.Extent.Text))}
  $InstallDir=Join-Path $root 'installed';$EvidenceDir=$root;$ServiceName='FixtureService';$RuntimeMode='service'
  [IO.Directory]::CreateDirectory($InstallDir)|Out-Null
  $path=Join-Path $InstallDir 'agent.toml';[IO.File]::WriteAllText($path,'private configuration fixture')
  $exe=Join-Path $root 'consumer.exe';[IO.File]::WriteAllText($exe,'fake PE I/O boundary')
  $sha=(Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant()
  $role=@{source_commit='b51bc3d825e6d5666535463b34eb708201e6fda7';cache_path=$exe;queue_path=$exe;cache_sha256=$sha;queue_sha256=$sha}
  $tools=[pscustomobject]@{schema='edr.windows.storage-compat-tools.v1';architecture='arm64';python_path=$exe;legacy=$role;candidate=@{source_commit='d4e837790c53861c99d31ee127c55a5ef1f06f4a';cache_path=$exe;queue_path=$exe;cache_sha256=$sha;queue_sha256=$sha}}
  $manifestPath=Join-Path $root 'tools.json';[IO.File]::WriteAllText($manifestPath,($tools|ConvertTo-Json -Depth 5))
  function Test-StoragePe {param($Path,$Architecture);if($Path -cne $exe -or $Architecture -cne 'arm64'){throw 'wrong native architecture'};$script:peChecks++}
  $script:peChecks=0
  Pass 'pinned_dual_consumer_and_native_arch_admission' {$actual=Import-LifecycleStorageTools $manifestPath 'arm64' 'Test-StoragePe';if($script:peChecks -ne 4 -or $actual.schema -cne $tools.schema){throw 'admission failed'}}
  Reject 'wrong_tool_architecture' '*identity mismatch*' {Import-LifecycleStorageTools $manifestPath 'amd64' 'Test-StoragePe'|Out-Null}
  $tools.legacy.source_commit='c'*40;[IO.File]::WriteAllText($manifestPath,($tools|ConvertTo-Json -Depth 5))
  Reject 'wrong_tool_source' '*immutable product source*' {Import-LifecycleStorageTools $manifestPath 'arm64' 'Test-StoragePe'|Out-Null}
  $tools.legacy.source_commit=$role.source_commit='b51bc3d825e6d5666535463b34eb708201e6fda7'
  $tools.legacy.cache_sha256='0'*64;[IO.File]::WriteAllText($manifestPath,($tools|ConvertTo-Json -Depth 5))
  Reject 'wrong_tool_digest' '*hash mismatch*' {Import-LifecycleStorageTools $manifestPath 'arm64' 'Test-StoragePe'|Out-Null}
  $tools.legacy.cache_sha256=$sha
  $policy=[pscustomobject]@{max_mb=512;retention_hours=72;selected_retention_hours=72;path=(Join-Path $InstallDir 'cache.db')}
  $context=@{tools=$tools;root=$root;install=$InstallDir;config=$path;epoch=1793700000;generation=1;writer_uncertain=$false;
    binding=[pscustomobject]@{config_sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant();tenant_id='fixture';endpoint_id='fixture-ep';cache=$policy;queue=$policy};
    expected=@{cache=@([pscustomobject]@{pid=96010;process_start_key='18446744073709551010';cmdline='兼容'},[pscustomobject]@{pid=96011;process_start_key='18446744073709551011';cmdline='fixture'});queue=@([pscustomobject]@{batch_id='storage-compat-1-0';wire_sha256=('a'*64);wire_bytes=123;compressed=$false},[pscustomobject]@{batch_id='storage-compat-1-1';wire_sha256=('b'*64);wire_bytes=99;compressed=$true})}}
  function Receipt([string]$Kind,[string]$Action='read'){
    return [pscustomobject]@{schema='edr.test.storage-compat.v1';owner=$(if($Kind -ceq 'cache'){'evidence_cache'}else{'queue'});action=$Action;
      platform='Windows';native_windows=$true;process_machine=0;native_machine=0xaa64;
      source_commit=$tools.legacy.source_commit;input_origin='synthetic_records_via_original_storage_owner_api';direct_sql_writes=$false;network=$false;sensor_capture=$false;
      epoch=$context.epoch;tenant_id='fixture';endpoint_id='fixture-ep';storage_policy=$policy;records=@($context.expected[$Kind]);
      read_from_reopened_sqlite=($Action -ceq 'read');real_codec=$true;server_ack=$false;delivery_clock_advance_s=$(if($Action -ceq 'read'){301}else{0});virtual_retry_eligibility_only=($Action -ceq 'read');read_by_poll_drain=($Action -ceq 'read')}
  }
  foreach($kind in @('cache','queue')){
    $receipt=Receipt $kind
    Pass ($kind+'_exact_payload_and_provenance') {Assert-LifecycleStorageReceipt $context $receipt 'legacy' $kind 'read' 1}
    $receipt.records=@($receipt.records[1],$receipt.records[0])
    Pass ($kind+'_record_order_independent') {Assert-LifecycleStorageReceipt $context $receipt 'legacy' $kind 'read' 1}
    foreach($field in @('source_commit','epoch','tenant_id','endpoint_id','action','owner','input_origin','direct_sql_writes','network','sensor_capture','platform','native_windows','process_machine','native_machine')){
      $bad=$receipt.PSObject.Copy();$bad.$field='wrong'
      Reject ($kind+'_receipt_'+$field) '*receipt identity, policy or record count mismatch*' {Assert-LifecycleStorageReceipt $context $bad 'legacy' $kind 'read' 1}
    }
    $bad=$receipt.PSObject.Copy();$bad.records=@($receipt.records[0])
    Reject ($kind+'_missing_record') '*record count mismatch*' {Assert-LifecycleStorageReceipt $context $bad 'legacy' $kind 'read' 1}
    $bad=$receipt.PSObject.Copy();$bad.records=@($receipt.records[0],$receipt.records[0])
    Reject ($kind+'_duplicate_record') '*duplicate storage record identity*' {Assert-LifecycleStorageReceipt $context $bad 'legacy' $kind 'read' 1}
    $bad=$receipt|ConvertTo-Json -Depth 8|ConvertFrom-Json
    if($kind -ceq 'cache'){$bad.records[0].process_start_key='18446744073709551000'}else{$bad.records[0].wire_sha256='c'*64}
    Reject ($kind+'_payload_changed') '*storage record field changed*' {Assert-LifecycleStorageReceipt $context $bad 'legacy' $kind 'read' 1}
  }
  foreach($field in @('real_codec','server_ack','virtual_retry_eligibility_only','read_by_poll_drain','delivery_clock_advance_s')){
    $bad=Receipt 'queue';$bad.$field=if($field -ceq 'delivery_clock_advance_s'){302}else{-not $bad.$field}
    Reject ('queue_'+$field) '*codec/ACK/clock contract mismatch*' {Assert-LifecycleStorageReceipt $context $bad 'legacy' 'queue' 'read' 1}
  }
  $bad=Receipt 'cache';$bad.read_from_reopened_sqlite=$false
  Reject 'cache_no_reopened_consumer' '*reopen persistent SQLite*' {Assert-LifecycleStorageReceipt $context $bad 'legacy' 'cache' 'read' 1}
  $script:nativeDisposed=0
  $script:nativeProcess=[pscustomobject]@{HasExited=$false;Id=42;Path=(Join-Path $InstallDir 'FDSensor.exe');StartTime=[DateTime]::UtcNow;Handle=[IntPtr]1}
  $script:nativeProcess|Add-Member ScriptMethod Dispose {$script:nativeDisposed++}
  $script:processRow=[pscustomobject]@{ExecutablePath=$script:nativeProcess.Path;CommandLine=('"'+$script:nativeProcess.Path+'" --config "'+$path+'"');CreationDate=$script:nativeProcess.StartTime}
  function Get-LifecycleRuntimeOwner {return [ordered]@{mode='service'}}
  function Get-LifecycleRuntimeProcess {return [pscustomobject]@{State='Running';ProcessId=42}}
  function Get-Process {[CmdletBinding()]param($Id);if($Id -ne 42){throw 'wrong native PID'};return $script:nativeProcess}
  function Get-CimInstance {[CmdletBinding()]param($ClassName,$Filter);if($null -ne $script:processRow){return $script:processRow}}
  Pass 'native_process_handle_config_and_creation_binding' {$native=Get-LifecycleStorageNative;if($native.pid -ne 42){throw 'wrong original runtime'};$native.process.Dispose()}
  $script:processRow.CommandLine='FDSensor.exe --config "C:\other\agent.toml"'
  Reject 'foreign_config_rejected' '*config/process binding mismatch*' {Get-LifecycleStorageNative|Out-Null}
  $script:processRow.CommandLine=('"'+$script:nativeProcess.Path+'" --config "'+$path+'"')
  $script:processRow.CreationDate=$script:nativeProcess.StartTime.AddSeconds(-1)
  Reject 'reused_PID_generation_rejected' '*config/process binding mismatch*' {Get-LifecycleStorageNative|Out-Null}
  $script:processRow.CreationDate=$script:nativeProcess.StartTime;$script:nativeProcess.HasExited=$true
  Reject 'exited_runtime_rejected' '*config/process binding mismatch*' {Get-LifecycleStorageNative|Out-Null}
  Pass 'failed_native_queries_release_handle' {if($script:nativeDisposed -ne 4){throw 'process handle leaked'}}
  $script:processRow=$null;$script:serviceStatus='Stopped';$script:taskStatus='Ready'
  function Get-Service {[CmdletBinding()]param($Name);return [pscustomobject]@{Status=$script:serviceStatus}}
  function Get-ScheduledTask {[CmdletBinding()]param($TaskName,$TaskPath);return [pscustomobject]@{State=$script:taskStatus}}
  $quiescent=@{process=$script:nativeProcess}
  Pass 'exited_handle_and_zero_writers_allow_quiescence' {Assert-LifecycleStorageQuiescent $quiescent}
  $script:nativeProcess.HasExited=$false
  Reject 'live_original_handle_blocks_write' '*original runtime process has not exited*' {Assert-LifecycleStorageQuiescent $quiescent}
  $script:nativeProcess.HasExited=$true;$script:processRow=[pscustomobject]@{ExecutablePath=$null}
  Reject 'unknown_process_path_blocks_write' '*writer remains or its path is unknown*' {Assert-LifecycleStorageQuiescent $quiescent}
  $script:processRow=$null;$RuntimeMode='scheduled_task'
  Pass 'ready_task_with_no_writer_is_quiescent' {Assert-LifecycleStorageQuiescent $quiescent}
  $script:taskStatus='Running'
  Reject 'running_task_blocks_write' '*task is not stopped*' {Assert-LifecycleStorageQuiescent $quiescent}
  $RuntimeMode='service';$script:serviceStatus='Running'
  Reject 'running_service_blocks_write' '*service is not stopped*' {Assert-LifecycleStorageQuiescent $quiescent}
  function Start-Process {
    [CmdletBinding()]param($FilePath,$ArgumentList,[switch]$PassThru,$RedirectStandardOutput,$RedirectStandardError)
    [IO.File]::WriteAllText($RedirectStandardOutput,'{"status":"ok"}');[IO.File]::WriteAllText($RedirectStandardError,'fixture_child_cause')
    $script:child=[pscustomobject]@{Handle=[IntPtr]1;HasExited=$false;ExitCode=$(if($script:childCase -ceq 'nonzero'){7}else{0});killed=$false;disposed=$false}
    $script:child|Add-Member ScriptMethod WaitForExit {param($ms);if($script:childCase -ceq 'timeout' -and -not $this.killed){return $false};$this.HasExited=$true;return $true}
    $script:child|Add-Member ScriptMethod Kill {$this.killed=$true}
    $script:child|Add-Member ScriptMethod Dispose {$this.disposed=$true}
    return $script:child
  }
  $script:childCase='success'
  Pass 'bounded_child_receipt_and_handle_cleanup' {$result=Invoke-LifecycleStorageProcess $context $exe @('read') 'child-success';if($result.status -cne 'ok' -or -not $script:child.disposed){throw 'child receipt/cleanup mismatch'}}
  $script:childCase='nonzero'
  Reject 'child_failure_preserves_bounded_cause' '*exit=7 cause=fixture_child_cause*' {Invoke-LifecycleStorageProcess $context $exe @('read') 'child-failure'|Out-Null}
  $script:childCase='timeout'
  Reject 'child_timeout_is_terminal' '*finite deadline*' {Invoke-LifecycleStorageProcess $context $exe @('read') 'child-timeout'|Out-Null}
  Pass 'timed_out_owned_child_is_killed_and_reaped' {if(-not $script:child.killed -or -not $script:child.disposed -or $context.writer_uncertain){throw 'timeout cleanup failed'}}
  function Invoke-LifecycleStorageProcess {
    param($Context,$Executable,$Arguments,$Label,$Seconds)
    $script:runtimeRequest=[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($Arguments[-1]));$script:runtimeBudget=$Seconds
    return [pscustomobject]@{status='completed'}
  }
  foreach($RuntimeMode in @('service','scheduled_task')){foreach($runtimeAction in @('Stop','Start')){
    Pass ($RuntimeMode+'_'+$runtimeAction+'_uses_existing_owner_without_recreation') {
      Invoke-LifecycleStorageRuntimeAction $context $runtimeAction 'fixture'
      $command=if($RuntimeMode -ceq 'service'){$runtimeAction+'-Service -InputObject $service'}else{$runtimeAction+"-ScheduledTask -TaskName 'FixtureService' -TaskPath '\'"}
      if(-not $script:runtimeRequest.Contains($command) -or $script:runtimeBudget -ne 35 -or $script:runtimeRequest -match 'Register|Remove|Stop-Process|Force'){throw 'runtime action broadened scope'}
    }
  }}
  $RuntimeMode='service'
  # OS lifecycle mutations are isolated below. Keep actual orchestration and
  # require zero writes before complete quiescence; injected first failure wins.
  $script:sequence=New-Object 'System.Collections.Generic.List[string]'
  $script:fake=[pscustomobject]@{HasExited=$false;Id=42;Path=(Join-Path $InstallDir 'FDSensor.exe');StartTime=[DateTime]::UtcNow;Handle=[IntPtr]1}
  $script:fake|Add-Member ScriptMethod WaitForExit {param($ms)return $this.HasExited}
  $script:fake|Add-Member ScriptMethod Dispose {$script:sequence.Add('dispose')}
  function Get-LifecycleStorageNative {return @{process=$script:fake;owner='{"mode":"service"}';pid=42;created_utc='fixture'}}
  function Assert-LifecycleStorageBinding {param($Context)}
  function Invoke-LifecycleStorageRuntimeAction {param($Context,$Action,$Label);$script:sequence.Add($Action);if($Action -ceq 'Stop'){$script:fake.HasExited=$true}elseif($script:restartFails){throw 'restart_secondary'}}
  function Assert-LifecycleStorageQuiescent {param($Native);$script:sequence.Add('quiescent');if($script:writerRemains){throw 'writer_remains'}}
  function Get-LifecycleRuntimeProcess {return [pscustomobject]@{State='Running';ProcessId=43}}
  function Get-LifecycleRuntimeOwner {return [ordered]@{mode='service'}}
  function Invoke-LifecycleStorageOwner {
    param($Context,$Role,$Kind,$Action,$Database,$Generation,$Label)
    $script:sequence.Add('write-'+$Kind)
    if($script:writeFails){throw 'write_primary'}
    if($Database -cne $Context.binding.$Kind.path -or $Role -cne 'legacy' -or $Action -cne 'seed' -or $Generation -ne 1){throw 'write did not use actual configured old database'}
    return [pscustomobject]@{records=@([pscustomobject]@{pid=1},[pscustomobject]@{pid=2})}
  }
  $script:writerRemains=$false;$script:writeFails=$false;$script:restartFails=$false
  $context.generation=0;$context.expected=@{cache=@();queue=@()}
  Pass 'seed_stops_then_writes_then_restarts_same_owner' {
    Write-LifecycleStorageFixture $context 'seed' 'fixture'
    if(($script:sequence -join ',') -cne 'Stop,quiescent,quiescent,write-cache,quiescent,write-queue,Start,dispose' -or $context.generation -ne 1){throw 'unsafe storage action ordering'}
  }
  $context.generation=0;$script:sequence.Clear();$script:writerRemains=$true;$script:fake.HasExited=$false
  Reject 'remaining_writer_blocks_all_writes' '*writer_remains*' {Write-LifecycleStorageFixture $context 'seed' 'fixture'}
  if(@($script:sequence|Where-Object{$_ -like 'write-*'}).Count){throw 'write occurred with unresolved writer'}
  $script:writerRemains=$false;$script:writeFails=$true;$script:restartFails=$true;$script:sequence.Clear();$script:fake.HasExited=$false
  Reject 'first_write_failure_survives_restart_failure' '*write_primary*' {Write-LifecycleStorageFixture $context 'seed' 'fixture' 3>$null}
  if($script:sequence -cnotcontains 'Start' -or $context.generation -ne 0){throw 'failed fixture projection changed'}
  $context.generation=1;$script:fake.HasExited=$false;$script:copies=New-Object 'System.Collections.Generic.List[string]'
  function Invoke-LifecycleStoragePython {
    param($Context,$Arguments,$Label)
    if($Arguments[0] -cne 'backup' -or $Arguments[3] -cne $Context.binding.config_sha256){throw 'snapshot lost actual configuration binding'}
    [IO.File]::WriteAllText($Arguments[5],'sealed actual-database snapshot fixture')
    return [pscustomobject]@{schema='edr.test.storage-snapshot.v1';sqlite_backup=$true;source_readonly=$true;source=$Context.binding.($Arguments[4]).path;config_sha256=$Context.binding.config_sha256;sha256=(Get-FileHash -LiteralPath $Arguments[5] -Algorithm SHA256).Hash.ToLowerInvariant()}
  }
  function Invoke-LifecycleStorageOwner {
    param($Context,$Role,$Kind,$Action,$Database,$Generation,$Label)
    if($Action -cne 'read' -or [IO.File]::ReadAllText($Database) -cne 'sealed actual-database snapshot fixture'){throw 'consumer did not receive fresh snapshot copy'}
    $script:copies.Add($Database);[IO.File]::WriteAllText($Database,'consumer maintenance touched only its own copy')
  }
  function Add-Evidence {param($Stage,$Status,$Detail)}
  Pass 'each_legacy_candidate_reader_gets_independent_actual_snapshot_copy' {
    Test-LifecycleStorageReadback $context 'readback'
    if($script:copies.Count -ne 4 -or @($script:copies|Select-Object -Unique).Count -ne 4){throw 'consumer copies shared'}
  }
  [ordered]@{status='succeeded';case_count=$cases.Count;cases=$cases.ToArray();scope='Actual helper AST owners; lifecycle and external tool I/O stubbed; no Agent/service/task/registry operations'}|ConvertTo-Json -Depth 5
} catch {throw ('storage harness: '+$_.Exception.Message+'; '+$_.ScriptStackTrace)} finally {Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction Stop}
