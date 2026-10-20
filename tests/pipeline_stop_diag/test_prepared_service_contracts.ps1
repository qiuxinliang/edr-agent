#Requires -Version 7.0
#Requires -PSEdition Core
<# Pure source-owned projection contracts. No harness top-level, process,
SCM, Agent, network or generated worker body is executed. The extracted profile
validator runs on public in-memory fixtures; the one-byte progress file helper
additionally runs against this test's public file. #>
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
$wantedFunctions=@('Check','ProjectPrimaryFailure','WriteDiagnosticSummary','ProjectSampler','ReadFailureProjection','ProjectWorkerFailure','PowerShellWorkerSource','ServicePreflightSource','ReadPreflightReceipt','ReadPreflightProgress')
$allowedCommands=@('Check','ConvertFrom-Json','ConvertTo-Json','New-Object','ReadOwnedBytes','ForEach-Object')
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
