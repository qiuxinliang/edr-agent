#Requires -Version 7.0
#Requires -PSEdition Core
<# Pure source-owned projection contracts. No harness top-level, process,
SCM, Agent, network or generated worker body is executed. The extracted profile
validator runs on public in-memory fixtures; the byte helpers and positive-frame
reader run on public files. Native held-process/FileID guards have explicit test
seams below; these checks do not prove Windows process or file identity. #>
[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$DriverSource,
  [Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9]{64}$')][string]$DriverSha256
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$sourceFile=Get-Item -LiteralPath $DriverSource -Force -ErrorAction Stop
if($sourceFile.PSIsContainer -or ($sourceFile.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $sourceFile.Length -le 0 -or $sourceFile.Length -gt 131072){throw 'prepared_source_regular_bound'}
for($parent=$sourceFile.Directory;$null -ne $parent;$parent=$parent.Parent){if(($parent.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'prepared_source_parent_reparse'}}
if((Get-FileHash -LiteralPath $sourceFile.FullName -Algorithm SHA256).Hash.ToLowerInvariant() -cne $DriverSha256){throw 'prepared_source_sha_mismatch'}
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($sourceFile.FullName,[ref]$tokens,[ref]$errors)
if(@($errors).Count){throw 'prepared_source_parse_failure'}
if((Get-FileHash -LiteralPath $sourceFile.FullName -Algorithm SHA256).Hash.ToLowerInvariant() -cne $DriverSha256){throw 'prepared_source_changed_during_parse'}
Add-Type -AssemblyName System.Text.Json -ErrorAction Stop
if($null -eq ('System.Text.Json.JsonDocument' -as [type])){throw 'prepared_consumer_requires_core7_system_text_json'}

# Read only the two reviewed literal arrays, never execute their assignments.
foreach($name in @('publicFailureCodes','stageFailureCodes')){
  $wanted='script:'+$name
  $nodes=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.AssignmentStatementAst] -and $node.Left -is [Management.Automation.Language.VariableExpressionAst] -and $node.Left.VariablePath.UserPath -ceq $wanted},$true))
  if($nodes.Count -ne 1){throw 'prepared_literal_inventory'}
  $literal=$nodes[0].Right.Extent.Text
  if($literal -cnotmatch "(?s)^\s*@\(\s*(?:'[a-z][a-z0-9_]{0,100}'\s*,?\s*)+\)\s*$"){throw 'prepared_literal_array_only'}
  $codes=@([regex]::Matches($literal,"'([a-z][a-z0-9_]{0,100})'")|ForEach-Object {$_.Groups[1].Value})
  $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
  if($codes.Count -lt 1 -or $codes.Count -gt 256){throw 'prepared_literal_count'}
  foreach($code in $codes){if(-not $seen.Add($code)){throw 'prepared_literal_duplicate'}}
  Set-Variable -Name $name -Value $codes -Scope Script
}

# Loading a function definition does not call it. This fixed inventory excludes
# StartOwned/RunOwned/SCM/cleanup/main. Reject newly introduced command owners.
$wantedFunctions=@('Check','ProjectPrimaryFailure','WriteDiagnosticSummary','ProjectSampler','ReadFailureProjection','ProjectWorkerFailure','PowerShellWorkerSource','ServicePreflightSource','ReadPreflightReceipt','ReadPreflightProgress','ProjectCachePositiveFrame','ReadCachePositiveProof')
$allowedCommands=@('Check','ConvertFrom-Json','ConvertTo-Json','New-Object','ReadOwnedBytes','ForEach-Object','StopLogTarget','StopLogConfig','StopLogOpen','StopLogInfo','StopLogAnchor','ProjectCachePositiveFrame')
foreach($name in $wantedFunctions){
  $defs=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name},$true))
  if($defs.Count -ne 1){throw 'prepared_pure_function_inventory'}
  foreach($command in @($defs[0].Body.FindAll({param($node) $node -is [Management.Automation.Language.CommandAst]},$true))){
    if($command.GetCommandName() -cnotin $allowedCommands){throw 'prepared_pure_command_inventory'}
  }
  foreach($type in @($defs[0].Body.FindAll({param($node) $node -is [Management.Automation.Language.TypeExpressionAst]},$true))){
    if($type.TypeName.FullName -match '(^|\.)(Process|ServiceController)$'){throw 'prepared_pure_process_type_refused'}
  }
  Invoke-Expression $defs[0].Extent.Text
}

$script:passed=0;$script:fixtureNumber=0
$script:publicFixtureRoot=Join-Path ([IO.Path]::GetTempPath()) ('prepared-service-pure-'+[guid]::NewGuid().ToString('N'))
if(Test-Path -LiteralPath $script:publicFixtureRoot){throw 'prepared_fixture_exists'}
$null=New-Item -ItemType Directory -Path $script:publicFixtureRoot -ErrorAction Stop
$script:privateMarker='unexported_test_private_atom'
function AssertContract($Condition,[string]$Cause){if(-not $Condition){throw $Cause};$script:passed++}
function Rejects([scriptblock]$Body,[string]$Expected=''){
  $caught=$false
  try{& $Body|Out-Null}catch{$caught=$true;if($Expected -and $_.Exception.Message -cne $Expected){throw 'prepared_rejection_cause_changed'}}
  AssertContract $caught 'prepared_expected_rejection_missing'
}
function PublicFixture([byte[]]$Bytes){
  if($Bytes.Length -gt 32768){throw 'prepared_fixture_bound'}
  $script:fixtureNumber++;$path=Join-Path $script:publicFixtureRoot ($script:fixtureNumber.ToString()+'.public')
  $stream=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
  try{$stream.Write($Bytes,0,$Bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
  return $path
}
function PublicText([string]$Text){return PublicFixture ([Text.UTF8Encoding]::new($false).GetBytes($Text))}

# Explicit test I/O seam: actual bounded bytes from this test's public files.
# It is not a substitute for the QA owner's live-file/identity/EOF contract.
function ReadOwnedBytes([string]$Path,[int]$Cap){
  $full=[IO.Path]::GetFullPath($Path);$prefix=$script:publicFixtureRoot+[IO.Path]::DirectorySeparatorChar
  if(-not $full.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase) -or $Cap -le 0 -or $Cap -gt 1048576){throw 'prepared_public_read_scope'}
  $info=Get-Item -LiteralPath $full -Force -ErrorAction Stop
  if($info.PSIsContainer -or ($info.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $info.Length -gt $Cap){throw 'prepared_public_read_cap'}
  $bytes=[IO.File]::ReadAllBytes($full)
  if($bytes.Length -ne $info.Length -or $bytes.Length -gt $Cap){throw 'prepared_public_read_changed'}
  return @{bytes=$bytes;length=$bytes.Length}
}
# Declared test-only seams for the already tested QA native guards. The reader
# still reads/seeks/hashes real public bytes and enforces its actual budgets.
function StopLogTarget($Context,[switch]$AllowExited){
  if(-not $AllowExited -or -not $Context.testNaturalExit){throw 'stop_log_target_generation_not_live'}
  $Context.exitConfirmed=$true;$Context.diagnostic.held_process.exit_code_known=$true;$Context.diagnostic.held_process.exit_code=$Context.testExitCode
}
function StopLogConfig($Path,$Expected,$LogDirectory){if($script:proofConfigChanged){throw 'stop_log_config_hash_changed'}}
function StopLogInfo($Stream){
  $f=Get-Item -LiteralPath $Stream.Name -Force;$ticks=[uint64]$f.LastWriteTimeUtc.Ticks
  return @{Identity=$script:proofFileIdentity;Length=[long]$Stream.Length;WriteHigh=[uint32]($ticks -shr 32);WriteLow=[uint32]($ticks -band 4294967295)}
}
function StopLogOpen($Path){
  $stream=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
  return @{stream=$stream;info=(StopLogInfo $stream)}
}
function StopLogAnchor($Context){
  $null=$Context.stream.Seek($Context.anchorOffset,[IO.SeekOrigin]::Begin);$bytes=New-Object byte[] $Context.anchor.Length;$got=0
  while($got -lt $bytes.Length){$n=$Context.stream.Read($bytes,$got,$bytes.Length-$got);if($n -le 0){throw 'stop_log_anchor_changed'};$got+=$n}
  for($i=0;$i -lt $bytes.Length;$i++){if($bytes[$i] -ne $Context.anchor[$i]){throw 'stop_log_anchor_changed'}}
  $null=$Context.stream.Seek($Context.offset,[IO.SeekOrigin]::Begin)
}
function ProofLine($Changes=@{}){
  $row=[ordered]@{schema='edr.test.service-cache-positive-proof.v1';version=1;pid=4242;tid=99;status_getter_calls=1;db_open=1;storage_format=1;path_hash_valid=1;cache_path_sha256=$script:proofPathSha;context_facts_written=[uint64]2;context_refs_written=[uint64]3;candidate_records_written=[uint64]0;retention_clock_valid=1;pipeline_source_sha256=$script:proofPipelineSha;cache_source_sha256=$script:proofCacheSha}
  foreach($key in $Changes.Keys){$row[$key]=$Changes[$key]}
  return '[preprocess] worker cache proof '+($row|ConvertTo-Json -Compress)
}
function ProofContext([string]$Body,[long]$Already=0){
  $header=[Text.UTF8Encoding]::new($false).GetBytes("public-header`n");$path=PublicText ("public-header`n"+$Body)
  $stream=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete));$null=$stream.Seek($header.Length,[IO.SeekOrigin]::Begin)
  return @{ready=$true;native=@{pid=4242;config_sha256=('a'*64)};diagnostic=@{start_offset=[long]$header.Length;read_attempt_bytes=$Already;held_process=@{bound_live_before_stop=$true;exit_code_known=$false;exit_code=$null}};stream=$stream;fileIdentity=$script:proofFileIdentity;offset=[long]$header.Length;readAttemptBytes=$Already;anchorOffset=[long]0;anchor=$header;configPath='public-config';logDirectory=$script:publicFixtureRoot;logPath=$path;exitConfirmed=$false;testNaturalExit=$true;testExitCode=[int]0}
}
function ProofRead([string]$Body,[long]$Already=0){
  $context=ProofContext $Body $Already
  try{return ReadCachePositiveProof $context $script:proofCleanup $script:proofCachePath $script:proofPipelineSha $script:proofCacheSha ($script:experimentClock.ElapsedMilliseconds+5000)}finally{$context.stream.Dispose()}
}
function SamplerLine($Changes=@{},[string[]]$Drop=@()){
  $row=[ordered]@{schema='edr.service-scm-sample.v1';index=0;state='Running';elapsed_ms=0;checkpoint=1;wait_hint_ms=30000;service_pid=4242;win32_exit_code=0;service_exit_code=0;pid_birth_filetime='134369379834341476'}
  foreach($key in $Changes.Keys){$row[$key]=$Changes[$key]}
  foreach($key in $Drop){$row.Remove($key)}
  return ($row|ConvertTo-Json -Depth 6 -Compress)
}
function SamplerProjection([string]$Text,[bool]$Cancelled=$false){
  $path=PublicText $Text;$info=Get-Item -LiteralPath $path
  $receipt=@{stdout=@{bytes=$info.Length;sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()};cancelled=$Cancelled;exit_code=if($Cancelled){-1}else{0}}
  return ProjectSampler @{stdout=$path} $receipt
}
function FailureCase([string]$Text,[string]$Origin,[string]$Status,[string]$Cause='unknown'){
  $path=PublicText $Text;$value=ReadFailureProjection $path $Origin
  AssertContract ($value.status -ceq $Status -and $value.cause_code -ceq $Cause) 'prepared_failure_projection_contract'
  $encoded=$value|ConvertTo-Json -Depth 8 -Compress
  AssertContract (-not $encoded.Contains($script:privateMarker) -and -not $encoded.Contains('prepared-service-pure-')) 'prepared_failure_private_text_export'
  AssertContract ($value.Count -eq 9 -and @($value.Keys|Where-Object {$_ -cnotin @('schema','status','origin','exception_type','hresult','cause_code','operation_id','cim_native_error','cim_status_code')}).Count -eq 0) 'prepared_failure_output_keys'
  if($Status -ceq 'unknown'){AssertContract ($null -eq $value.origin -and $null -eq $value.exception_type -and $null -eq $value.hresult -and $null -eq $value.operation_id -and $null -eq $value.cim_native_error -and $null -eq $value.cim_status_code) 'prepared_unknown_does_not_invent_fields'}
  return $value
}

try{
  Check $true 'public_check_should_not_throw'
  Rejects {Check $false 'public_fixed_failure'} 'public_fixed_failure'
  AssertContract ('preexisting_agent_or_service' -cin $script:publicFailureCodes -and 'dependency_file_count_cap' -cin $script:stageFailureCodes -and $script:privateMarker -cnotin $script:publicFailureCodes -and $script:privateMarker -cnotin $script:stageFailureCodes) 'prepared_closed_code_lists'

  $row=SamplerLine
  $value=SamplerProjection ($row+"`n")
  AssertContract ($value.complete_rows -eq 1 -and $value.rows[0].index -eq 0 -and $value.rows[0].state -ceq 'Running' -and $value.worker_natural_exit -and -not $value.scm_success_claimed -and -not $value.raw_tail_exported) 'prepared_sampler_legal_frame'
  $value=SamplerProjection ((SamplerLine @{index=45;state='Unknown';elapsed_ms=60000;checkpoint=[long]4294967295;wait_hint_ms=$null;service_pid=$null;win32_exit_code=[long]4294967295;service_exit_code=$null;pid_birth_filetime=$null})+"`n")
  AssertContract ($value.rows[0].checkpoint -eq [uint32]::MaxValue -and $null -eq $value.rows[0].service_pid -and $value.rows[0].index -eq 45) 'prepared_sampler_uint32_and_null_edges'
  foreach($bad in @(@{index=-1},@{index=46},@{index='0'},@{index=1.5},@{state='running'},@{state=$script:privateMarker},@{schema='private_schema'})){
    $text=(SamplerLine $bad)+"`n";Rejects {SamplerProjection $text} 'sampler_projection_shape'
  }
  foreach($bad in @(@{checkpoint=-1},@{checkpoint=[long]4294967296},@{win32_exit_code=$true},@{service_exit_code='1'})){
    $text=(SamplerLine $bad)+"`n";Rejects {SamplerProjection $text} 'sampler_projection_number'
  }
  foreach($bad in @(@{elapsed_ms=-1},@{elapsed_ms=60001},@{elapsed_ms='1'},@{elapsed_ms=$true})){
    $text=(SamplerLine $bad)+"`n";Rejects {SamplerProjection $text} 'sampler_projection_elapsed'
  }
  foreach($bad in @(@{pid_birth_filetime=123},@{pid_birth_filetime=''},@{pid_birth_filetime=('1'*21)})){
    $text=(SamplerLine $bad)+"`n";Rejects {SamplerProjection $text} 'sampler_projection_birth'
  }
  $text=(SamplerLine @{} @('checkpoint'))+"`n";Rejects {SamplerProjection $text}
  Rejects {SamplerProjection ('x'*16385)} 'sampler_projection_bound'
  Rejects {SamplerProjection ("{not-json}`n")}
  $all=@();for($i=0;$i -lt 46;$i++){$all+=SamplerLine @{index=$i;elapsed_ms=$i*1000}}
  $value=SamplerProjection (($all -join "`n")+"`n")
  AssertContract ($value.complete_rows -eq 46) 'prepared_sampler_max_rows'
  $all+=SamplerLine @{index=0};$text=($all -join "`n")+"`n";Rejects {SamplerProjection $text} 'sampler_projection_count'
  $tail=$script:privateMarker;$value=SamplerProjection ($row+"`n"+$tail) $true
  AssertContract ($value.complete_rows -eq 1 -and $value.trailing_bytes -eq [Text.Encoding]::UTF8.GetByteCount($tail) -and -not $value.worker_natural_exit -and $value.cancelled_after_primary_frozen -and -not (($value|ConvertTo-Json -Depth 8 -Compress).Contains($tail))) 'prepared_sampler_partial_tail_not_exported'
  $value=SamplerProjection ((SamplerLine @{extra_private=$script:privateMarker})+"`n")
  AssertContract (-not (($value|ConvertTo-Json -Depth 8 -Compress).Contains($script:privateMarker))) 'prepared_sampler_extra_fields_not_exported'

  $known='{"schema":"edr.ci-owned-failure.v2","origin":"powershell_worker","exception_type":"System.Management.Automation.RuntimeException","hresult":-2146233087,"cause_code":"preexisting_agent_or_service","operation_id":2,"cim_native_error":null,"cim_status_code":null}'
  $value=FailureCase $known powershell_worker projected preexisting_agent_or_service
  AssertContract ($value.hresult -is [int] -and $value.hresult -eq -2146233087) 'prepared_hresult_real_int32'
  foreach($number in @('-2147483648','0','2147483647')){$null=FailureCase ($known.Replace('-2146233087',$number)) powershell_worker projected preexisting_agent_or_service}
  $null=FailureCase ($known.Replace('preexisting_agent_or_service','unknown')) powershell_worker projected unknown
  foreach($text in @($known.Replace('preexisting_agent_or_service',$script:privateMarker),$known.Replace('preexisting_agent_or_service','PREEXISTING_AGENT_OR_SERVICE'),$known.Replace('"hresult":-2146233087','"hresult":true'),$known.Replace('"hresult":-2146233087','"hresult":2147483648'),$known.Replace('"hresult":-2146233087','"hresult":-2147483649'),$known.Replace('"hresult":-2146233087','"hresult":1.0'),$known.Replace('"hresult":-2146233087','"hresult":"0"'),$known.Replace('"hresult":-2146233087','"hresult":null'),$known.Replace('"cause_code":','"cause_code":"unknown","cause_code":'),$known.Replace('"hresult":',('"'+$script:privateMarker+'":1,"hresult":')),('['+$known+']'),($known+'{}'),$known.Replace('edr.ci-owned-failure.v2','private_schema'),$known.Replace('System.Management.Automation.RuntimeException','C:\\private path'),$known.Replace('"origin":"powershell_worker"','"origin":false'),$known.Replace('"hresult":-2146233087,',''))){
    $null=FailureCase $text powershell_worker unknown
  }
  $null=FailureCase $known python_stage unknown
  $null=FailureCase $known unsupported unknown
  $null=FailureCase ('x'*4097) powershell_worker unknown
  $null=FailureCase ($known+(' '*(4096-[Text.Encoding]::UTF8.GetByteCount($known)))) powershell_worker projected preexisting_agent_or_service
  $invalid=PublicFixture ([byte[]]@(255));$bad=ReadFailureProjection $invalid powershell_worker
  AssertContract ($bad.status -ceq 'unknown' -and $bad.cause_code -ceq 'unknown') 'prepared_invalid_utf8_not_projected'
  $python='{"schema":"edr.ci-owned-failure.v1","origin":"python_stage","exception_type":"builtins.ValueError","hresult":null,"cause_code":"dependency_file_count_cap"}'
  $pythonValue=FailureCase $python python_stage projected dependency_file_count_cap
  AssertContract ($null -eq $pythonValue.hresult) 'prepared_python_does_not_invent_hresult'
  $null=FailureCase ($python.Replace('"hresult":null','"hresult":0')) python_stage unknown
  $null=FailureCase ($python.Replace('dependency_file_count_cap',$script:privateMarker)) python_stage unknown

  foreach($op in 0..7){$v=FailureCase ($known.Replace('"operation_id":2',('"operation_id":'+$op))) powershell_worker projected preexisting_agent_or_service;AssertContract ($v.operation_id -is [int] -and $v.operation_id -eq $op) 'prepared_closed_operation_positive'}
  foreach($bad in @('-1','8','true','"2"','2.0','null')){$null=FailureCase ($known.Replace('"operation_id":2',('"operation_id":'+$bad))) powershell_worker unknown}
  $null=FailureCase ($known.Replace('preexisting_agent_or_service','firewall_profiles_shape')) powershell_worker projected firewall_profiles_shape
  foreach($field in @('operation_id','cim_native_error','cim_status_code')){
    $null=FailureCase ($known.Replace(('"'+$field+'":'),('"'+$field+'":0,"'+$field+'":'))) powershell_worker unknown
    $null=FailureCase ([regex]::Replace($known,',"'+$field+'":(?:2|null)','')) powershell_worker unknown
  }
  foreach($n in @('-2147483648','0','2147483647')){$v=FailureCase ($known.Replace('"cim_native_error":null',('"cim_native_error":'+$n))) powershell_worker projected preexisting_agent_or_service;AssertContract ($v.cim_native_error -is [int]) 'prepared_cim_native_int32'}
  foreach($n in @('0','4294967295')){$v=FailureCase ($known.Replace('"cim_status_code":null',('"cim_status_code":'+$n))) powershell_worker projected preexisting_agent_or_service;AssertContract ($v.cim_status_code -is [uint32]) 'prepared_cim_status_uint32'}
  foreach($bad in @('-2147483649','2147483648','true','"0"','0.0')){$null=FailureCase ($known.Replace('"cim_native_error":null',('"cim_native_error":'+$bad))) powershell_worker unknown}
  foreach($bad in @('-1','4294967296','false','"0"','0.0')){$null=FailureCase ($known.Replace('"cim_status_code":null',('"cim_status_code":'+$bad))) powershell_worker unknown}
  $null=FailureCase ($known.Replace('edr.ci-owned-failure.v2','edr.ci-owned-failure.v1')) powershell_worker unknown
  AssertContract ($null -eq $pythonValue.operation_id -and $null -eq $pythonValue.cim_native_error -and $null -eq $pythonValue.cim_status_code) 'prepared_python_has_no_cim_or_operation_claim'

  # Exercise the actual producer helper with a real MI exception. Optional
  # getter values use the real MI enum's numeric value / UInt32 status, never a
  # mock, message-derived code or invented property.
  $plain=[Exception]::new($script:privateMarker)
  $plainRecord=[Management.Automation.ErrorRecord]::new($plain,'public',[Management.Automation.ErrorCategory]::NotSpecified,$null)
  $plainValue=ProjectWorkerFailure $plainRecord 0 $script:publicFailureCodes
  AssertContract ($plainValue.exception_type -ceq 'System.Exception' -and $plainValue.cause_code -ceq 'unknown' -and $plainValue.hresult -eq $plain.HResult -and $null -eq $plainValue.cim_native_error -and $null -eq $plainValue.cim_status_code) 'prepared_plain_exception_has_no_cim_dependency'
  Add-Type -AssemblyName Microsoft.Management.Infrastructure -ErrorAction Stop
  $realCim=[Microsoft.Management.Infrastructure.CimException]::new($script:privateMarker)
  $cimRecord=[Management.Automation.ErrorRecord]::new($realCim,$script:privateMarker,[Management.Automation.ErrorCategory]::NotSpecified,$script:privateMarker)
  $v=ProjectWorkerFailure $cimRecord 1 $script:publicFailureCodes
  $expectedNative=$null;$expectedStatus=$null
  try{$prop=$realCim.PSObject.Properties['NativeErrorCode'];if($null -ne $prop){$actualNative=$prop.Value;if($actualNative -is [Microsoft.Management.Infrastructure.NativeErrorCode]){$expectedNative=[int]$actualNative}elseif($actualNative -is [int]){$expectedNative=$actualNative}}}catch{$expectedNative=$null}
  try{$prop=$realCim.PSObject.Properties['StatusCode'];if($null -ne $prop -and $prop.Value -is [uint32]){$expectedStatus=$prop.Value}}catch{$expectedStatus=$null}
  AssertContract ($v.Count -eq 8 -and $v.schema -ceq 'edr.ci-owned-failure.v2' -and $v.exception_type -ceq $realCim.GetType().FullName -and $v.hresult -eq $realCim.HResult -and $v.operation_id -eq 1 -and $v.cim_native_error -eq $expectedNative -and $v.cim_status_code -eq $expectedStatus) 'prepared_real_cim_getter_types_preserved'
  $null=FailureCase ($v|ConvertTo-Json -Compress) powershell_worker projected unknown
  AssertContract (-not (($v|ConvertTo-Json -Compress).Contains($script:privateMarker))) 'prepared_real_cim_private_message_not_exported'
  $nested=[InvalidOperationException]::new($script:privateMarker,$realCim)
  $r=[Management.Automation.ErrorRecord]::new($nested,$script:privateMarker,[Management.Automation.ErrorCategory]::NotSpecified,$null)
  $v=ProjectWorkerFailure $r 4 $script:publicFailureCodes
  AssertContract ($v.exception_type -ceq $nested.GetType().FullName -and $v.hresult -eq $nested.HResult -and $v.cim_native_error -eq $expectedNative -and $v.cim_status_code -eq $expectedStatus) 'prepared_cim_inner_keeps_outer_hresult'
  $deep=[Exception]::new('preexisting_agent_or_service');for($i=0;$i -lt 8;$i++){$deep=[Exception]::new($script:privateMarker,$deep)}
  $r=[Management.Automation.ErrorRecord]::new($deep,'public',[Management.Automation.ErrorCategory]::NotSpecified,$null)
  $v=ProjectWorkerFailure $r 0 $script:publicFailureCodes
  AssertContract ($v.cause_code -ceq 'unknown' -and $null -eq $v.cim_native_error -and $null -eq $v.cim_status_code) 'prepared_worker_walk_stops_at_eight'
  foreach($op in @(6,7)){
    $v=ProjectWorkerFailure $cimRecord $op $script:publicFailureCodes
    AssertContract ($v.operation_id -is [int] -and $v.operation_id -eq $op -and $v.cim_native_error -eq $expectedNative -and $v.cim_status_code -eq $expectedStatus) 'prepared_real_cim_import_operations_preserved'
    $null=FailureCase ($v|ConvertTo-Json -Compress) powershell_worker projected unknown
  }
  foreach($op in @(-1,8,'1',$true,$null)){Rejects {ProjectWorkerFailure $cimRecord $op $script:publicFailureCodes} 'worker_operation_id_invalid'}

  $success='{"schema":"edr.ci-service-preflight.v1","clean_aliases":true,"machine_edr_override_count":0,"firewall_profiles_enabled":true,"operation_id":5,"ps_major":7,"ps_edition":"Core"}'
  $preflight=@{stdout=(PublicText $success);stderr=(PublicText '');terminal_known=$true;exit_known=$true;exit_code=[int]0;cancelled=$false}
  $v=ReadPreflightReceipt $preflight
  AssertContract ($null -ne $v -and $v.Count -eq 7 -and $v.ps_major -eq 7 -and $v.ps_edition -ceq 'Core') 'prepared_preflight_normal_exact_receipt'
  foreach($text in @($success.Replace('"operation_id":5','"operation_id":4'),$success.Replace('"operation_id":5','"operation_id":6'),$success.Replace('"operation_id":5','"operation_id":7'),$success.Replace('"operation_id":5','"operation_id":5.0'),$success.Replace('"ps_major":7','"ps_major":5'),$success.Replace('Core','Desktop'),$success.Replace('"ps_major":7','"ps_major":5').Replace('Core','Desktop'),$success.Replace('"clean_aliases":true','"clean_aliases":false'),$success.Replace('"machine_edr_override_count":0','"machine_edr_override_count":"0"'),$success.Replace('"schema":','"schema":"x","schema":'),$success.Replace('"schema":','"private":1,"schema":'),('['+$success+']'),$known)){
    $preflight.stdout=PublicText $text;AssertContract ($null -eq (ReadPreflightReceipt $preflight)) 'prepared_preflight_bad_or_failure_frame_rejected'
  }
  $preflight.stdout=PublicText $success
  foreach($changes in @(@{exit_code=[int]1},@{exit_code=[int]7},@{exit_code=$null},@{exit_code='0'},@{terminal_known=$false},@{exit_known=$false},@{cancelled=$true},@{stderr=(PublicText $script:privateMarker)})){
    $bad=$preflight.Clone();foreach($key in $changes.Keys){$bad[$key]=$changes[$key]};AssertContract ($null -eq (ReadPreflightReceipt $bad)) 'prepared_preflight_nonzero_unknown_or_stderr_never_accepted'
  }
  # Actual public byte files through the same bounded-read seam. No child or
  # SCM call: the terminal-known input is a deliberately explicit test seam.
  foreach($op in 0..7){
    $path=PublicFixture ([byte[]]@($op));$value=ReadPreflightProgress $path $true
    $expectedProgressStatus=if($op -eq 0){'no_child_progress_observed'}else{'observed'}
    AssertContract ($value.Count -eq 2 -and $value.status -ceq $expectedProgressStatus -and $value.last_operation_id -is [int] -and $value.last_operation_id -eq $op) 'prepared_progress_one_byte_closed_values'
    AssertContract (-not (($value|ConvertTo-Json -Compress).Contains($path))) 'prepared_progress_path_not_exported'
  }
  $badProgress=@((PublicFixture ([byte[]]@())),(PublicFixture ([byte[]]@(0,1))),(PublicFixture ([byte[]]@(8))),(PublicFixture ([byte[]]@(48))),(PublicFixture ([byte[]]@(255))),(Join-Path $script:publicFixtureRoot 'missing-progress.public'))
  foreach($path in $badProgress){$value=ReadPreflightProgress $path $true;AssertContract ($value.Count -eq 2 -and $value.status -ceq 'unknown' -and $null -eq $value.last_operation_id) 'prepared_progress_bad_length_value_or_missing_unknown'}
  $path=PublicFixture ([byte[]]@(5))
  foreach($terminal in @($false,$null,1,'true')){$value=ReadPreflightProgress $path $terminal;AssertContract ($value.status -ceq 'unknown' -and $null -eq $value.last_operation_id) 'prepared_progress_requires_known_terminal_bool'}
  $progressTokens=$null;$progressErrors=$null
  $progressAst=[Management.Automation.Language.Parser]::ParseInput((ServicePreflightSource),[ref]$progressTokens,[ref]$progressErrors)
  AssertContract ($null -eq $progressErrors -or @($progressErrors).Count -eq 0) 'prepared_progress_body_parse_only'
  $progressDefs=@($progressAst.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'SetPreflightProgress'},$true))
  AssertContract ($progressDefs.Count -eq 1 -and @($progressDefs[0].Body.FindAll({param($n)$n -is [Management.Automation.Language.CommandAst]},$true)).Count -eq 0) 'prepared_progress_file_helper_only'
  Invoke-Expression $progressDefs[0].Extent.Text
  # Load only the real source-owned in-memory profile validator. No import,
  # query, generated worker body or firewall setting is executed here.
  $profileDefs=@($progressAst.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'AssertEffectiveFirewallProfiles'},$true))
  AssertContract ($profileDefs.Count -eq 1 -and @($profileDefs[0].Body.FindAll({param($n)$n -is [Management.Automation.Language.CommandAst]},$true)).Count -eq 0) 'prepared_firewall_profile_helper_only'
  Invoke-Expression $profileDefs[0].Extent.Text
  $profiles=@([pscustomobject]@{Name='Domain';Enabled=$true},[pscustomobject]@{Name='Private';Enabled=$true},[pscustomobject]@{Name='Public';Enabled=$true})
  AssertContract (@(AssertEffectiveFirewallProfiles $profiles).Count -eq 0) 'prepared_three_effective_profiles_accepted_without_output'
  AssertContract (@(AssertEffectiveFirewallProfiles @($profiles[2],$profiles[0],$profiles[1])).Count -eq 0) 'prepared_profile_order_not_a_business_rule'
  $stringProfiles=@([pscustomobject]@{Name='Domain';Enabled='True'},[pscustomobject]@{Name='Private';Enabled='True'},[pscustomobject]@{Name='Public';Enabled='True'})
  AssertContract (@(AssertEffectiveFirewallProfiles $stringProfiles).Count -eq 0) 'prepared_profile_true_representation_preserved'
  Rejects {AssertEffectiveFirewallProfiles $null} 'firewall_profiles_shape'
  Rejects {AssertEffectiveFirewallProfiles @()} 'firewall_profiles_shape'
  Rejects {AssertEffectiveFirewallProfiles @($profiles[0],$profiles[1])} 'firewall_profiles_shape'
  Rejects {AssertEffectiveFirewallProfiles @($profiles[0],$profiles[1],$profiles[2],$profiles[2])} 'firewall_profiles_shape'
  Rejects {AssertEffectiveFirewallProfiles @($profiles[0],$profiles[1],$profiles[1])} 'firewall_profiles_shape'
  foreach($badName in @('Unknown','domain',$script:privateMarker,1,$null)){
    $badProfile=[pscustomobject]@{Name=$badName;Enabled=$true}
    Rejects {AssertEffectiveFirewallProfiles @($profiles[0],$profiles[1],$badProfile)} 'firewall_profiles_shape'
  }
  Rejects {AssertEffectiveFirewallProfiles @($profiles[0],$profiles[1],$null)} 'firewall_profiles_shape'
  Rejects {AssertEffectiveFirewallProfiles @($profiles[0],$profiles[1],[pscustomobject]@{Enabled=$true})} 'firewall_profiles_shape'
  Rejects {AssertEffectiveFirewallProfiles @($profiles[0],$profiles[1],[pscustomobject]@{Name='Public'})} 'firewall_profiles_shape'
  foreach($badEnabled in @($false,$null,0,1,'False','NotConfigured','true',$script:privateMarker)){
    $badProfile=[pscustomobject]@{Name='Public';Enabled=$badEnabled}
    Rejects {AssertEffectiveFirewallProfiles @($profiles[0],$profiles[1],$badProfile)} 'firewall_profile_disabled'
  }
  try{AssertEffectiveFirewallProfiles @($profiles[0],$profiles[1],[pscustomobject]@{Name=$script:privateMarker;Enabled=$true})}catch{$profileFailure=$_}
  $profileProjection=ProjectWorkerFailure $profileFailure 4 $script:publicFailureCodes
  AssertContract ($profileProjection.cause_code -ceq 'firewall_profiles_shape' -and -not (($profileProjection|ConvertTo-Json -Compress).Contains($script:privateMarker))) 'prepared_profile_rejection_does_not_export_private_name'
  $null=FailureCase ($profileProjection|ConvertTo-Json -Compress) powershell_worker projected firewall_profiles_shape
  $script:preflightProgressPath=PublicFixture ([byte[]]@(0))
  foreach($op in 1..7){
    SetPreflightProgress $op;$value=ReadPreflightProgress $script:preflightProgressPath $true
    AssertContract ((Get-Item -LiteralPath $script:preflightProgressPath).Length -eq 1 -and $value.status -ceq 'observed' -and $value.last_operation_id -eq $op) 'prepared_progress_write_overwrites_one_byte'
  }
  foreach($op in @(0,8,255)){
    Rejects {SetPreflightProgress $op} 'preflight_progress_file_shape'
    AssertContract ((Get-Item -LiteralPath $script:preflightProgressPath).Length -eq 1 -and [IO.File]::ReadAllBytes($script:preflightProgressPath)[0] -eq 7) 'prepared_progress_invalid_operation_does_not_mutate'
  }
  foreach($path in @((PublicFixture ([byte[]]@())),(PublicFixture ([byte[]]@(1,2))))){
    $script:preflightProgressPath=$path;$beforeLength=(Get-Item -LiteralPath $path).Length;$beforeHash=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
    Rejects {SetPreflightProgress 1} 'preflight_progress_file_shape'
    AssertContract ((Get-Item -LiteralPath $path).Length -eq $beforeLength -and (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ceq $beforeHash) 'prepared_progress_wrong_length_never_expands'
  }
  # Real source-owned frame parser/reader, real public file IO, explicit native
  # identity seams. No Agent, query, log body export or generated worker runs.
  $script:experimentClock=[Diagnostics.Stopwatch]::StartNew();$script:proofConfigChanged=$false
  $script:proofFileIdentity='00000001:0000000000000002:0000000000000003'
  $script:proofPipelineSha='d'*64;$script:proofCacheSha='e'*64;$script:proofCachePath='C:\public\cache.db'
  $sha=[Security.Cryptography.SHA256]::Create();try{$script:proofPathSha=([BitConverter]::ToString($sha.ComputeHash([Text.UTF8Encoding]::new($false).GetBytes($script:proofCachePath)))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
  $script:proofCleanup=@{target_terminal_known=$true;target_exit_code=[int]0;exact_target_kill_attempted=$false}
  $line=ProofLine;$frame=ProjectCachePositiveFrame $line 4242 $script:proofPathSha $script:proofPipelineSha $script:proofCacheSha
  AssertContract ($frame.Count -eq 15 -and $frame.context_facts_written -is [uint64] -and $frame.pid -is [uint32] -and $frame.candidate_records_written -eq 0) 'prepared_cache_frame_exact_typed_keys'
  foreach($key in @('context_facts_written','context_refs_written','candidate_records_written')){
    $max=ProjectCachePositiveFrame (ProofLine @{$key=[uint64]::MaxValue}) 4242 $script:proofPathSha $script:proofPipelineSha $script:proofCacheSha
    AssertContract ($max[$key] -eq [uint64]::MaxValue) 'prepared_cache_u64_not_rounded'
  }
  $max=ProjectCachePositiveFrame (ProofLine @{tid=[uint32]::MaxValue}) 4242 $script:proofPathSha $script:proofPipelineSha $script:proofCacheSha
  AssertContract ($max.tid -eq [uint32]::MaxValue) 'prepared_cache_tid_u32_boundary'
  foreach($bad in @($line.Replace('"pid":4242','"pid":4242,"pid":4242'),$line.Replace('"pid":4242,',''),(ProofLine @{extra=$script:privateMarker}),(ProofLine @{pid=4243}),(ProofLine @{version=2}),(ProofLine @{status_getter_calls=2}),(ProofLine @{tid=0}),(ProofLine @{storage_format=3}),(ProofLine @{cache_path_sha256=('b'*64)}),(ProofLine @{pipeline_source_sha256=('c'*64)}),(ProofLine @{cache_source_sha256=('c'*64)}),($line+'x'),('['+$line+']'))){Rejects {ProjectCachePositiveFrame $bad 4242 $script:proofPathSha $script:proofPipelineSha $script:proofCacheSha}}
  foreach($bad in @('true','"1"','1.0','-1','4294967296')){Rejects {ProjectCachePositiveFrame ($line.Replace('"db_open":1',('"db_open":'+$bad))) 4242 $script:proofPathSha $script:proofPipelineSha $script:proofCacheSha}}
  foreach($bad in @('true','"2"','2.0','-1','18446744073709551616')){Rejects {ProjectCachePositiveFrame ($line.Replace('"context_facts_written":2',('"context_facts_written":'+$bad))) 4242 $script:proofPathSha $script:proofPipelineSha $script:proofCacheSha}}
  $positive=ProofRead ($line+"`n")
  AssertContract ($positive.status -ceq 'verified_positive' -and $positive.frame.candidate_records_written -eq 0 -and $positive.expected_cache_path_sha256 -ceq $script:proofPathSha -and $positive.expected_cache_path_sha256 -ceq $positive.frame.cache_path_sha256 -and $positive.read_attempt_bytes -gt 0 -and -not $positive.observation_can_change_stop_result) 'prepared_cache_positive_actual_public_read'
  foreach($pidValue in @([int]4242,[long]4242,[uint32]4242)){
    $context=ProofContext ($line+"`n");$context.native.pid=$pidValue
    try{$value=ReadCachePositiveProof $context $script:proofCleanup $script:proofCachePath $script:proofPipelineSha $script:proofCacheSha ($script:experimentClock.ElapsedMilliseconds+5000);AssertContract ($value.status -ceq 'verified_positive') 'prepared_cache_json_pid_integer_width'}finally{$context.stream.Dispose()}
  }
  foreach($pidValue in @($true,'4242',[long]0,[long]-1,([long][int]::MaxValue+1))){
    $context=ProofContext ($line+"`n");$context.native.pid=$pidValue
    try{$value=ReadCachePositiveProof $context $script:proofCleanup $script:proofCachePath $script:proofPipelineSha $script:proofCacheSha ($script:experimentClock.ElapsedMilliseconds+5000);AssertContract ($value.status -ceq 'unknown' -and $value.cause -ceq 'cache_proof_expected_identity' -and $value.read_attempt_bytes -eq 0) 'prepared_cache_pid_not_coerced_or_wrapped'}finally{$context.stream.Dispose()}
  }
  $positive2=ProofRead ((ProofLine @{storage_format=2})+"`n")
  AssertContract ($positive2.status -ceq 'verified_positive') 'prepared_cache_format2_positive'
  foreach($case in @(@{change=@{storage_format=0};cause='compact_not_enabled'},@{change=@{db_open=0};cause='cache_not_open'},@{change=@{retention_clock_valid=0};cause='clock_not_valid'},@{change=@{context_facts_written=[uint64]0};cause='durable_context_not_observed'},@{change=@{context_refs_written=[uint64]0};cause='durable_context_not_observed'})){
    $negative=ProofRead ((ProofLine $case.change)+"`n")
    AssertContract ($negative.status -ceq 'observed_not_positive' -and $negative.cause -ceq $case.cause -and $null -ne $negative.frame) 'prepared_cache_actual_negative_not_fabricated_positive'
  }
  foreach($case in @(@{body='';cause='cache_proof_frame_missing'},@{body=$line;cause='cache_proof_frame_partial'},@{body=($line+"`n"+$line+"`n");cause='cache_proof_frame_duplicate'},@{body=('[preprocess] worker cache proof {'+"`n");cause='cache_proof_frame_json'})){
    $negative=ProofRead $case.body
    AssertContract ($negative.status -ceq 'unknown' -and $negative.cause -ceq $case.cause -and $null -eq $negative.frame) 'prepared_cache_missing_duplicate_partial_or_malformed_unknown'
  }
  $length=[Text.Encoding]::UTF8.GetByteCount($line+"`n");$exact=ProofRead ($line+"`n") (65536-$length)
  AssertContract ($exact.status -ceq 'verified_positive' -and $exact.cumulative_log_data_read_bytes -eq 65536) 'prepared_cache_shared_read_cap_exact'
  $over=ProofRead ($line+"`n") (65537-$length)
  AssertContract ($over.status -ceq 'unknown' -and $over.cause -ceq 'cache_proof_log_budget' -and $over.read_attempt_bytes -eq 0) 'prepared_cache_existing_reads_never_reset_budget'
  $context=ProofContext ("unrelated "+$script:privateMarker+"`n"+$line+"`n")
  try{
    $beforeDiagnostic=$context.diagnostic.Clone();$beforePosition=$context.stream.Position;$beforeLedger=$context.readAttemptBytes
    $script:primary='original_failure';$script:result=@{stop_result=@{status='timed_out_unknown_service_state';wait_ms=45000};primary_failure=@{cause_code='original_failure'}};$beforeResult=$script:result|ConvertTo-Json -Depth 8 -Compress
    $value=ReadCachePositiveProof $context $script:proofCleanup $script:proofCachePath $script:proofPipelineSha $script:proofCacheSha ($script:experimentClock.ElapsedMilliseconds+5000)
    AssertContract ($value.status -ceq 'verified_positive' -and -not (($value|ConvertTo-Json -Depth 8 -Compress).Contains($script:privateMarker))) 'prepared_cache_only_selected_metadata_exported'
    $beforeDiagnostic.read_attempt_bytes=$context.readAttemptBytes
    AssertContract (($context.diagnostic|ConvertTo-Json -Depth 8 -Compress) -ceq ($beforeDiagnostic|ConvertTo-Json -Depth 8 -Compress) -and $context.stream.Position -eq $beforePosition -and $context.readAttemptBytes -eq $beforeLedger+$value.read_attempt_bytes -and $value.bytes_read -eq $value.read_attempt_bytes) 'prepared_cache_only_shared_ledger_and_position_updated'
    AssertContract ($script:primary -ceq 'original_failure' -and ($script:result|ConvertTo-Json -Depth 8 -Compress) -ceq $beforeResult) 'prepared_cache_late_positive_cannot_rewrite_frozen_or_primary'
    $second=ReadCachePositiveProof $context $script:proofCleanup $script:proofCachePath $script:proofPipelineSha $script:proofCacheSha ($script:experimentClock.ElapsedMilliseconds+5000)
    AssertContract ($second.status -ceq 'not_collected' -and $second.cause -ceq 'already_attempted' -and $second.read_attempt_bytes -eq 0 -and $context.readAttemptBytes -eq $value.cumulative_log_data_read_bytes) 'prepared_cache_one_attempt_only'
  }finally{$context.stream.Dispose()}
  foreach($badCleanup in @(@{target_terminal_known=$false;target_exit_code=[int]0;exact_target_kill_attempted=$false},@{target_terminal_known=$true;target_exit_code=[int]0;exact_target_kill_attempted=$true},@{target_terminal_known=$true;target_exit_code=$null;exact_target_kill_attempted=$false})){
    $context=ProofContext ($line+"`n")
    try{$value=ReadCachePositiveProof $context $badCleanup $script:proofCachePath $script:proofPipelineSha $script:proofCacheSha ($script:experimentClock.ElapsedMilliseconds+5000);AssertContract ($value.status -ceq 'not_collected' -and $value.read_attempt_bytes -eq 0) 'prepared_cache_unknown_or_killed_terminal_not_read'}finally{$context.stream.Dispose()}
  }
  $context=ProofContext ($line+"`n")
  try{$value=ReadCachePositiveProof $context $script:proofCleanup $script:proofCachePath $script:proofPipelineSha $script:proofCacheSha 0;AssertContract ($value.status -ceq 'unknown' -and $value.cause -ceq 'cache_proof_deadline' -and $value.read_attempt_bytes -eq 0) 'prepared_cache_no_new_deadline_or_wait'}finally{$context.stream.Dispose()}
  $context=ProofContext ($line+"`n");$context.fileIdentity='changed';$script:proofConfigChanged=$false
  try{$value=ReadCachePositiveProof $context $script:proofCleanup $script:proofCachePath $script:proofPipelineSha $script:proofCacheSha ($script:experimentClock.ElapsedMilliseconds+5000);AssertContract ($value.status -ceq 'unknown' -and $value.read_attempt_bytes -eq 0) 'prepared_cache_replaced_path_identity_refused'}finally{$context.stream.Dispose()}
  $context=ProofContext ($line+"`n");$context.anchor[0]=0
  try{$value=ReadCachePositiveProof $context $script:proofCleanup $script:proofCachePath $script:proofPipelineSha $script:proofCacheSha ($script:experimentClock.ElapsedMilliseconds+5000);AssertContract ($value.status -ceq 'unknown' -and $value.read_attempt_bytes -eq 0) 'prepared_cache_anchor_overwrite_refused'}finally{$context.stream.Dispose()}
  # Explicit stream seams around real FileStream I/O: short reads, an actual
  # IOException before the first payload byte, and a final position failure.
  $context=ProofContext ($line+"`n") (65536-$length)
  $context.stream|Add-Member -MemberType NoteProperty -Name ProofReadCalls -Value 0
  $context.stream|Add-Member -MemberType ScriptMethod -Name Read -Force -Value {
    param([byte[]]$Buffer,[int]$Offset,[int]$Count)
    $this.ProofReadCalls++;$invokeArguments=[object[]]@($null,$Offset,[Math]::Min(7,$Count));$invokeArguments[0]=$Buffer
    return [IO.FileStream].GetMethod('Read',[type[]]@([byte[]],[int],[int])).Invoke($this.PSObject.BaseObject,$invokeArguments)
  }
  try{$value=ReadCachePositiveProof $context $script:proofCleanup $script:proofCachePath $script:proofPipelineSha $script:proofCacheSha ($script:experimentClock.ElapsedMilliseconds+5000);AssertContract ($value.status -ceq 'verified_positive' -and $value.read_attempt_bytes -eq $length -and $value.bytes_read -eq $length -and $context.readAttemptBytes -eq 65536 -and $context.diagnostic.read_attempt_bytes -eq 65536 -and $context.stream.ProofReadCalls -gt 1) 'prepared_cache_short_reads_charge_window_once'}finally{$context.stream.Dispose()}
  $context=ProofContext ($line+"`n");$beforePosition=$context.stream.Position
  $context.stream|Add-Member -MemberType NoteProperty -Name ProofPayloadStart -Value $beforePosition
  $context.stream|Add-Member -MemberType ScriptMethod -Name Read -Force -Value {
    param([byte[]]$Buffer,[int]$Offset,[int]$Count)
    if($this.Position -ge $this.ProofPayloadStart){throw [IO.IOException]::new('unexported_payload_io_failure')}
    $invokeArguments=[object[]]@($null,$Offset,$Count);$invokeArguments[0]=$Buffer
    return [IO.FileStream].GetMethod('Read',[type[]]@([byte[]],[int],[int])).Invoke($this.PSObject.BaseObject,$invokeArguments)
  }
  try{
    $value=ReadCachePositiveProof $context $script:proofCleanup $script:proofCachePath $script:proofPipelineSha $script:proofCacheSha ($script:experimentClock.ElapsedMilliseconds+5000)
    AssertContract ($value.status -ceq 'unknown' -and $value.read_attempt_bytes -eq $length -and $value.bytes_read -eq 0 -and $context.readAttemptBytes -eq $length -and $context.diagnostic.read_attempt_bytes -eq $length -and $context.stream.Position -eq $beforePosition -and -not (($value|ConvertTo-Json -Depth 8 -Compress).Contains('unexported_payload_io_failure'))) 'prepared_cache_failed_io_retains_reserved_shared_charge'
    $second=ReadCachePositiveProof $context $script:proofCleanup $script:proofCachePath $script:proofPipelineSha $script:proofCacheSha ($script:experimentClock.ElapsedMilliseconds+5000)
    AssertContract ($second.cause -ceq 'already_attempted' -and $second.read_attempt_bytes -eq 0 -and $context.readAttemptBytes -eq $length) 'prepared_cache_failed_io_not_retried_or_ledger_reset'
  }finally{$context.stream.Dispose()}
  $context=ProofContext ($line+"`n");$frozenBefore=$script:result|ConvertTo-Json -Depth 8 -Compress;$primaryBefore=$script:primary
  $context.stream|Add-Member -MemberType NoteProperty -Name ProofSeekCalls -Value 0
  $context.stream|Add-Member -MemberType ScriptMethod -Name Seek -Force -Value {
    param([long]$Offset,[IO.SeekOrigin]$Origin)
    $this.ProofSeekCalls++;if($this.ProofSeekCalls -eq 6){throw [IO.IOException]::new('unexported_restore_io_failure')}
    return [IO.FileStream].GetMethod('Seek',[type[]]@([long],[IO.SeekOrigin])).Invoke($this.PSObject.BaseObject,[object[]]@($Offset,$Origin))
  }
  try{$value=ReadCachePositiveProof $context $script:proofCleanup $script:proofCachePath $script:proofPipelineSha $script:proofCacheSha ($script:experimentClock.ElapsedMilliseconds+5000);AssertContract ($value.status -ceq 'unknown' -and $value.cause -ceq 'cache_proof_stream_restore_failed' -and $null -eq $value.frame -and $script:primary -ceq $primaryBefore -and ($script:result|ConvertTo-Json -Depth 8 -Compress) -ceq $frozenBefore -and $context.readAttemptBytes -eq $length) 'prepared_cache_restore_failure_does_not_override_primary_or_frozen'}finally{$context.stream.Dispose()}
  $script:proofConfigChanged=$true
  $negative=ProofRead ($line+"`n");$script:proofConfigChanged=$false
  AssertContract ($negative.status -ceq 'unknown' -and $negative.read_attempt_bytes -eq 0 -and $null -eq $negative.frame) 'prepared_cache_changed_config_not_read'
  # Synthetic maximum projection serialization bound. These shapes are an
  # explicit size fixture; native QA parsing remains covered by its own tests.
  $maxProof=$positive.Clone();$maxProof.frame=$positive.frame.Clone()
  foreach($key in @('context_facts_written','context_refs_written','candidate_records_written')){$maxProof.frame[$key]=[uint64]::MaxValue}
  $maxProof.read_attempt_bytes=65536;$maxProof.bytes_read=65536;$maxProof.cumulative_log_data_read_bytes=65536;$maxProof.start_offset=[long]::MaxValue;$maxProof.end_offset=[long]::MaxValue
  $hist=@{kind='preprocess_worker_join_samples';version=3;interval_ms=10;samples=6001;capped=$true;phase_hits=@();callsite_hits=@();read_started_elapsed_ms=[long]::MaxValue}
  for($i=0;$i -lt 13;$i++){$hist.phase_hits+=,[uint32]$(if($i -eq 12){6001}else{0})}
  for($i=0;$i -lt 135;$i++){$hist.callsite_hits+=,[uint32]$(if($i -eq 134){6001}else{0})}
  $maxObservation=@{schema='edr.ci-selected-shutdown-log.v1';matches=@($hist)}
  for($i=0;$i -lt 63;$i++){
    $maxBus=@();for($side=0;$side -lt 2;$side++){$maxBus+=,@{known=$true;used=[uint64]65536;pushed=[uint64]::MaxValue;dropped=[uint64]::MaxValue}}
    $maxObservation.matches+=,@{kind='preprocess_stop_queues';bus=$maxBus;pmfe=@{running=@(1,1);active=@([uint32]::MaxValue,[uint32]::MaxValue);submitted=@([uint32]::MaxValue,[uint32]::MaxValue);completed=@([uint32]::MaxValue,[uint32]::MaxValue);dropped=@([uint32]::MaxValue,[uint32]::MaxValue);pending_known=$false;pending=$null};read_started_elapsed_ms=[long]::MaxValue}
  }
  $maxMetadata=@{shutdown_log_observation=$maxObservation;cache_positive_proof=$maxProof}
  AssertContract ([Text.Encoding]::UTF8.GetByteCount(($maxMetadata|ConvertTo-Json -Depth 16)) -lt (131072-16384)) 'prepared_cache_proof_plus_max_numeric_matches_leaves_metadata_headroom'
  # Real ErrorRecords, including preparation failures before a bound intent
  # exists. Do not export their messages, target objects or invocation text.
  try{Check $false 'qa_function_inventory'}catch{$failureRecord=$_}
  $value=ProjectPrimaryFailure $failureRecord
  AssertContract ($value.cause_code -ceq 'qa_function_inventory' -and $value.hresult -eq $failureRecord.Exception.HResult -and $null -eq $value.native_error) 'prepared_primary_closed_cause_and_real_hresult'
  AssertContract ($value.source_line -is [int] -and $value.source_line -gt 0 -and $value.source_column -is [int]) 'prepared_primary_actual_source_position'
  AssertContract ($value.Count -eq 6 -and @($value.Keys|Where-Object {$_ -cnotin @('exception_type','hresult','native_error','source_line','source_column','cause_code')}).Count -eq 0) 'prepared_primary_fixed_fields'
  try{throw ($script:privateMarker+' C:\private\invocation target')}catch{$failureRecord=$_}
  $value=ProjectPrimaryFailure $failureRecord
  $encoded=$value|ConvertTo-Json -Compress
  AssertContract ($value.cause_code -ceq 'unclassified_no_message_export' -and -not $encoded.Contains($script:privateMarker) -and -not $encoded.Contains('private')) 'prepared_primary_unknown_message_not_exported'
  $nativeError=[ComponentModel.Win32Exception]::new(5,$script:privateMarker)
  $wrapper=[InvalidOperationException]::new($script:privateMarker,$nativeError)
  $failureRecord=[Management.Automation.ErrorRecord]::new($wrapper,$script:privateMarker,[Management.Automation.ErrorCategory]::NotSpecified,$script:privateMarker)
  $value=ProjectPrimaryFailure $failureRecord
  AssertContract ($value.native_error -eq 5 -and $value.hresult -eq $wrapper.HResult -and $null -eq $value.source_line -and $null -eq $value.source_column) 'prepared_primary_win32_error_is_observed_not_hresult_guess'
  AssertContract (-not (($value|ConvertTo-Json -Compress).Contains($script:privateMarker))) 'prepared_primary_nested_exception_privacy'
  $deep=$nativeError;for($depth=0;$depth -lt 4;$depth++){$deep=[InvalidOperationException]::new($script:privateMarker,$deep)}
  $failureRecord=[Management.Automation.ErrorRecord]::new($deep,$script:privateMarker,[Management.Automation.ErrorCategory]::NotSpecified,$null)
  $value=ProjectPrimaryFailure $failureRecord
  AssertContract ($null -eq $value.native_error -and $value.cause_code -ceq 'unclassified_no_message_export') 'prepared_primary_exception_walk_is_bounded'
  $SourceSha='a'*40;$Token='b'*32
  $script:experimentClock=[Diagnostics.Stopwatch]::StartNew()
  $script:result=@{stop_result=$null;phase='preflight';preparation_stage_id=4;intent_recorded=$false;primary_failure=$value}
  $oldOutput=[Console]::Out;$summaryOutput=[IO.StringWriter]::new()
  try{[Console]::SetOut($summaryOutput);WriteDiagnosticSummary $false}finally{[Console]::SetOut($oldOutput)}
  $summary=$summaryOutput.ToString();$summaryOutput.Dispose();$summaryValue=$summary|ConvertFrom-Json
  AssertContract ($summaryValue.schema -ceq 'edr.ci-isolated-service-summary.v1' -and -not $summaryValue.diagnostic_accepted -and -not $summaryValue.whole_recovery_accepted -and $summaryValue.stop_status -ceq 'not_reached' -and $summaryValue.preparation_stage_id -eq 4 -and -not $summaryValue.intent_recorded) 'prepared_primary_console_survives_missing_intent'
  AssertContract ($summaryValue.primary_failure.cause_code -ceq 'unclassified_no_message_export' -and -not $summary.Contains($script:privateMarker)) 'prepared_primary_console_keeps_safe_first_failure'

  # Text generation and ParseInput only. Never invoke the generated try/catch,
  # its body, or its exit statement in this test process or a child process.
  $body=PowerShellWorkerSource "throw 'preexisting_agent_or_service'"
  $producerTokens=$null;$producerErrors=$null
  $producerAst=[Management.Automation.Language.Parser]::ParseInput($body,[ref]$producerTokens,[ref]$producerErrors)
  $embedded=@($producerAst.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'ProjectWorkerFailure'},$true))
  AssertContract ($embedded.Count -eq 1) 'prepared_single_embedded_projector'
  Invoke-Expression $embedded[0].Extent.Text
  $embeddedValue=ProjectWorkerFailure $cimRecord 1 $script:publicFailureCodes
  AssertContract ($embeddedValue.exception_type -ceq $realCim.GetType().FullName -and $embeddedValue.cim_native_error -eq $expectedNative -and $embeddedValue.cim_status_code -eq $expectedStatus) 'prepared_real_generated_projector_loaded_only'
  AssertContract (@($producerErrors).Count -eq 0 -and $body.Contains('edr.ci-owned-failure.v2') -and -not $body.Contains('__CODES__') -and -not $body.Contains('__BODY__') -and $body -notmatch 'ScriptStackTrace|Exception\.ToString\(') 'prepared_generated_producer_parse_only'
  if((Get-FileHash -LiteralPath $sourceFile.FullName -Algorithm SHA256).Hash.ToLowerInvariant() -cne $DriverSha256){throw 'prepared_source_changed_after_contracts'}
  $finalLine='prepared_service_pure_contracts passed='+$script:passed+' source_sha256='+$DriverSha256+' top_level_executed=false product_or_service_child_executed=false'
}finally{
  $owned=Get-Item -LiteralPath $script:publicFixtureRoot -Force -ErrorAction Stop
  if(-not $owned.PSIsContainer -or ($owned.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'prepared_fixture_cleanup_identity'}
  Remove-Item -LiteralPath $script:publicFixtureRoot -Recurse -Force -ErrorAction Stop
}
[Console]::Out.WriteLine($finalLine)
