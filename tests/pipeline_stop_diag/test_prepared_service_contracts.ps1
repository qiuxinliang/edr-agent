#Requires -Version 7.0
#Requires -PSEdition Core
<# Pure source-owned projection contracts. No harness top-level, process,
SCM, Agent, network or generated worker body is executed. #>
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
$wantedFunctions=@('Check','ProjectSampler','ReadFailureProjection','PowerShellWorkerSource')
$allowedCommands=@('Check','ConvertFrom-Json','New-Object','ReadOwnedBytes','ForEach-Object')
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
  AssertContract ($value.Count -eq 6 -and @($value.Keys|Where-Object {$_ -cnotin @('schema','status','origin','exception_type','hresult','cause_code')}).Count -eq 0) 'prepared_failure_output_keys'
  if($Status -ceq 'unknown'){AssertContract ($null -eq $value.origin -and $null -eq $value.exception_type -and $null -eq $value.hresult) 'prepared_unknown_does_not_invent_fields'}
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

  $known='{"schema":"edr.ci-owned-failure.v1","origin":"powershell_worker","exception_type":"System.Management.Automation.RuntimeException","hresult":-2146233087,"cause_code":"preexisting_agent_or_service"}'
  $value=FailureCase $known powershell_worker projected preexisting_agent_or_service
  AssertContract ($value.hresult -is [int] -and $value.hresult -eq -2146233087) 'prepared_hresult_real_int32'
  foreach($number in @('-2147483648','0','2147483647')){$null=FailureCase ($known.Replace('-2146233087',$number)) powershell_worker projected preexisting_agent_or_service}
  $null=FailureCase ($known.Replace('preexisting_agent_or_service','unknown')) powershell_worker projected unknown
  foreach($text in @($known.Replace('preexisting_agent_or_service',$script:privateMarker),$known.Replace('preexisting_agent_or_service','PREEXISTING_AGENT_OR_SERVICE'),$known.Replace('"hresult":-2146233087','"hresult":true'),$known.Replace('"hresult":-2146233087','"hresult":2147483648'),$known.Replace('"hresult":-2146233087','"hresult":-2147483649'),$known.Replace('"hresult":-2146233087','"hresult":1.0'),$known.Replace('"hresult":-2146233087','"hresult":"0"'),$known.Replace('"hresult":-2146233087','"hresult":null'),$known.Replace('"cause_code":','"cause_code":"unknown","cause_code":'),$known.Replace('"hresult":',('"'+$script:privateMarker+'":1,"hresult":')),('['+$known+']'),($known+'{}'),$known.Replace('edr.ci-owned-failure.v1','private_schema'),$known.Replace('System.Management.Automation.RuntimeException','C:\\private path'),$known.Replace('"origin":"powershell_worker"','"origin":false'),$known.Replace('"hresult":-2146233087,',''))){
    $null=FailureCase $text powershell_worker unknown
  }
  $null=FailureCase $known python_stage unknown
  $null=FailureCase $known unsupported unknown
  $null=FailureCase ('x'*4097) powershell_worker unknown
  $null=FailureCase ($known+(' '*(4096-[Text.Encoding]::UTF8.GetByteCount($known)))) powershell_worker projected preexisting_agent_or_service
  $invalid=PublicFixture ([byte[]]@(255));$bad=ReadFailureProjection $invalid powershell_worker
  AssertContract ($bad.status -ceq 'unknown' -and $bad.cause_code -ceq 'unknown') 'prepared_invalid_utf8_not_projected'
  $python='{"schema":"edr.ci-owned-failure.v1","origin":"python_stage","exception_type":"builtins.ValueError","hresult":null,"cause_code":"dependency_file_count_cap"}'
  $value=FailureCase $python python_stage projected dependency_file_count_cap
  AssertContract ($null -eq $value.hresult) 'prepared_python_does_not_invent_hresult'
  $null=FailureCase ($python.Replace('"hresult":null','"hresult":0')) python_stage unknown
  $null=FailureCase ($python.Replace('dependency_file_count_cap',$script:privateMarker)) python_stage unknown

  # Text generation and ParseInput only. Never invoke the generated try/catch,
  # its body, or its exit statement in this test process or a child process.
  $body=PowerShellWorkerSource "throw 'preexisting_agent_or_service'"
  $producerTokens=$null;$producerErrors=$null
  $null=[Management.Automation.Language.Parser]::ParseInput($body,[ref]$producerTokens,[ref]$producerErrors)
  AssertContract (@($producerErrors).Count -eq 0 -and $body.Contains('edr.ci-owned-failure.v1') -and -not $body.Contains('__CODES__') -and -not $body.Contains('__BODY__') -and $body -notmatch 'ScriptStackTrace|Exception\.ToString\(') 'prepared_generated_producer_parse_only'
  if((Get-FileHash -LiteralPath $sourceFile.FullName -Algorithm SHA256).Hash.ToLowerInvariant() -cne $DriverSha256){throw 'prepared_source_changed_after_contracts'}
  $finalLine='prepared_service_pure_contracts passed='+$script:passed+' source_sha256='+$DriverSha256+' top_level_executed=false product_or_service_child_executed=false'
}finally{
  $owned=Get-Item -LiteralPath $script:publicFixtureRoot -Force -ErrorAction Stop
  if(-not $owned.PSIsContainer -or ($owned.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'prepared_fixture_cleanup_identity'}
  Remove-Item -LiteralPath $script:publicFixtureRoot -Recurse -Force -ErrorAction Stop
}
[Console]::Out.WriteLine($finalLine)
