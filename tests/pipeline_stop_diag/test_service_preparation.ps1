#Requires -Version 7.0
#Requires -PSEdition Core
[CmdletBinding()]
param(
 [Parameter(Mandatory=$true)][string]$DriverSource,
 [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-f]{64}$')][string]$DriverSha256,
 [Parameter(Mandatory=$true)][string]$QADriverSource,
 [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-f]{64}$')][string]$QADriverSha256
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$probeClock=[Diagnostics.Stopwatch]::StartNew();$probeRoot=$null;$probeCreated=$false;$projectLoaded=$false
$probeOldRunnerTemp=$env:RUNNER_TEMP;$probeStatement=$null;$probeParserSelected=$false;$errors=$null
$script:result=@{preparation_stage_id=0;intent_recorded=$false}
$probe=[ordered]@{schema='edr.ci-service-preparation-contract.v1';status='failed_or_unknown';source_sha=$env:GITHUB_SHA;driver_sha256=$DriverSha256;qa_driver_sha256=$QADriverSha256;phase='source_validation';preparation_stage_id=0;statement_start_line=$null;statement_start_column=$null;prefix_statement_count=0;executed_statements=0;parser_errors_is_null=$null;parser_errors_type=$null;parser_errors_safe_count=$null;primary_failure=$null;cleanup_failure=$null;elapsed_ms=0;prefix_only=$true;service_or_agent_started=$false;preflight_worker_started=$false;dummy_agent_inputs=$true;runner_temp_public_subroot=$true;public_tree_cleaned=$false}
function Guard($Value,[string]$Cause){if(-not $Value){throw $Cause}}
function ReadSource([string]$Path,[string]$Expected){
 $f=Get-Item -LiteralPath $Path -Force
 Guard (-not $f.PSIsContainer -and $f.Length -gt 0 -and $f.Length -le 131072 -and ($f.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'source_shape'
 for($d=$f.Directory;$null -ne $d;$d=$d.Parent){Guard (($d.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'source_reparse'}
 Guard ((Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash.ToLowerInvariant() -ceq $Expected) 'source_sha'
 $ts=$null;$es=$null;$a=[Management.Automation.Language.Parser]::ParseFile($f.FullName,[ref]$ts,[ref]$es)
 $errorCount=if($null -eq $es){0}else{@($es).Count};Guard ($errorCount -eq 0) 'source_parse'
 Guard ((Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash.ToLowerInvariant() -ceq $Expected) 'source_changed'
 return @{ast=$a;path=$f.FullName}
}
try{
 Guard ($IsWindows -and $env:GITHUB_ACTIONS -ceq 'true' -and $env:RUNNER_ENVIRONMENT -ceq 'github-hosted') 'windows_hosted_core7_required'
 Guard ($env:GITHUB_SHA -cmatch '^[a-f0-9]{40}$') 'source_commit_required'
 $probeHarness=ReadSource $DriverSource $DriverSha256;$probeQA=ReadSource $QADriverSource $QADriverSha256
 $probeExpectedQA=Join-Path $env:GITHUB_WORKSPACE 'tests\cache-recovery\windows_cache_recovery_ci.ps1'
 Guard ($probeQA.path -ieq [IO.Path]::GetFullPath($probeExpectedQA)) 'qa_checkout_path_required'
 $probeMain=@($probeHarness.ast.EndBlock.Statements|Where-Object {$_ -is [Management.Automation.Language.TryStatementAst]})
 Guard ($probeMain.Count -eq 1) 'one_top_level_main_try_required'
 $probeStatements=@($probeMain[0].Body.Statements);$probeBoundary=-1
 for($i=0;$i -lt $probeStatements.Count;$i++){
  $node=$probeStatements[$i]
  if($node -is [Management.Automation.Language.AssignmentStatementAst] -and $node.Left -is [Management.Automation.Language.VariableExpressionAst] -and $node.Left.VariablePath.UserPath -ceq 'preflight'){
   Guard ($probeBoundary -eq -1) 'unique_preflight_boundary_required';$probeBoundary=$i
  }
 }
 Guard ($probeBoundary -ge 1 -and $probeBoundary -le 80) 'bounded_prefix_required'
 $probePrefix=@($probeStatements[0..($probeBoundary-1)]);$probe.prefix_statement_count=$probePrefix.Count
 # Check every selected statement before executing any selected statement.
 $probeAllowed=@('Check','Add-Type','Get-Item','Test-Path','Join-Path','New-Item','SaveNew','Out-Null','Get-Acl','RegularPath','Hash','Invoke-Expression','SampleLimits','OriginalReadStopLogSlice')
 foreach($probeNode in $probePrefix){
  Guard (@($probeNode.FindAll({param($n)$n -is [Management.Automation.Language.ExitStatementAst]},$true)).Count -eq 0) 'prefix_exit_refused'
  foreach($c in @($probeNode.FindAll({param($n)$n -is [Management.Automation.Language.CommandAst]},$true))){
   $cn=$c.GetCommandName()
   if($null -eq $cn){Guard ($c.Extent.Text.StartsWith("& (Join-Path `$env:WINDIR 'System32\icacls.exe') ",[StringComparison]::Ordinal)) 'prefix_dynamic_command_refused'}
   else{Guard ($cn -cin $probeAllowed) 'prefix_command_refused'}
  }
 }
 $probeIntent=@($probePrefix|Where-Object {$_.Extent.Text -cmatch "^SaveNew 'intent[.]json' "})
 Guard ($probeIntent.Count -eq 1) 'prefix_intent_inventory'
 $probeCodes=@($probeHarness.ast.FindAll({param($n)$n -is [Management.Automation.Language.AssignmentStatementAst] -and $n.Left -is [Management.Automation.Language.VariableExpressionAst] -and $n.Left.VariablePath.UserPath -ceq 'script:publicFailureCodes'},$true))
 Guard ($probeCodes.Count -eq 1 -and $probeCodes[0].Right.Extent.Text -cmatch "(?s)^\s*@\(\s*(?:'[a-z][a-z0-9_]{0,100}'\s*,?\s*)+\)\s*$") 'literal_failure_codes_required'
 $script:publicFailureCodes=@([regex]::Matches($probeCodes[0].Right.Extent.Text,"'([a-z][a-z0-9_]{0,100})'")|ForEach-Object {$_.Groups[1].Value})
 foreach($probeName in @('Check','Hash','RegularPath','SaveNew','ProjectPrimaryFailure')){
  $defs=@($probeHarness.ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $probeName},$true))
  Guard ($defs.Count -eq 1) 'prefix_helper_inventory'
  Invoke-Expression $defs[0].Extent.Text
 }
 $projectLoaded=$true
 $probeParent=Get-Item -LiteralPath $probeOldRunnerTemp -Force
 Guard ($probeParent.PSIsContainer -and [IO.Path]::IsPathRooted($probeParent.FullName)) 'runner_temp_shape'
 for($d=$probeParent;$null -ne $d;$d=$d.Parent){Guard (($d.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'runner_temp_reparse'}
 $probeRoot=Join-Path $probeParent.FullName ('edr-ci-preparation-contract-'+[guid]::NewGuid().ToString('N'))
 Guard (-not (Test-Path -LiteralPath $probeRoot)) 'public_root_exists'
 $null=New-Item -ItemType Directory -Path $probeRoot -ErrorAction Stop;$probeCreated=$true
 $env:RUNNER_TEMP=$probeRoot
 # Only test-local inputs/state. No supplied EXE or product bytes are opened.
 $SourceSha=$env:GITHUB_SHA;$Token=[guid]::NewGuid().ToString('N');$Architecture='arm64'
 $AgentPath='UNBOUND';$AgentSha256='0'*64;$ConfigTemplateSha256='0'*64
 $script:serviceName='FDSecurityAgentCI_'+$Token;$script:case=$null;$script:root=$null
 $script:result=@{preparation_stage_id=0;intent_recorded=$false};$script:experimentClock=[Diagnostics.Stopwatch]::StartNew()
 $probe.phase='actual_main_prefix'
 foreach($probeStatement in $probePrefix){
  $probe.statement_start_line=$probeStatement.Extent.StartLineNumber;$probe.statement_start_column=$probeStatement.Extent.StartColumnNumber
  if($probeStatement.Extent.Text -match 'Parser\]::ParseFile'){$probeParserSelected=$true}
  # Each exact original statement is executed once; there is no full-main call.
  Invoke-Expression $probeStatement.Extent.Text
  $probe.executed_statements++
 }
 $probe.preparation_stage_id=$script:result.preparation_stage_id
 Guard ($probe.preparation_stage_id -eq 8 -and $script:result.intent_recorded) 'prefix_completion_state'
 $probeIntentPath=Join-Path $script:case 'intent.json';$probeIntentFile=Get-Item -LiteralPath $probeIntentPath -Force
 Guard ($probeIntentFile.Length -gt 0 -and $probeIntentFile.Length -le 131072) 'public_intent_bound'
 Guard ((Get-FileHash -LiteralPath $probeHarness.path -Algorithm SHA256).Hash.ToLowerInvariant() -ceq $DriverSha256 -and (Get-FileHash -LiteralPath $probeQA.path -Algorithm SHA256).Hash.ToLowerInvariant() -ceq $QADriverSha256) 'source_changed'
 $probe.phase='prefix_completed';$probe.status='preparation_prefix_completed'
}catch{
 if($projectLoaded){$probe.primary_failure=ProjectPrimaryFailure $_}else{$probe.primary_failure=@{exception_type=$_.Exception.GetType().FullName;hresult=[int]$_.Exception.HResult;native_error=$null;source_line=$null;source_column=$null;cause_code='bootstrap_source_rejected_no_message'}}
 if($projectLoaded){$probe.preparation_stage_id=$script:result.preparation_stage_id}
}finally{
 if($probeParserSelected){$probe.parser_errors_is_null=($null -eq $errors);if($null -ne $errors){$probe.parser_errors_type=$errors.GetType().FullName};$probe.parser_errors_safe_count=if($null -eq $errors){0}else{@($errors).Count}}
 $env:RUNNER_TEMP=$probeOldRunnerTemp
 if($probeCreated){
  try{
   $own=Get-Item -LiteralPath $probeRoot -Force
   Guard ($own.PSIsContainer -and ($own.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0 -and $own.Parent.FullName -ieq $probeParent.FullName) 'public_cleanup_identity'
   $stack=[Collections.Generic.Stack[string]]::new();$stack.Push($own.FullName);$count=0
   while($stack.Count){foreach($entry in Get-ChildItem -LiteralPath $stack.Pop() -Force){$count++;Guard ($count -le 32 -and ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'public_cleanup_bound';if($entry.PSIsContainer){$stack.Push($entry.FullName)}}}
   Remove-Item -LiteralPath $own.FullName -Recurse -Force -ErrorAction Stop;$probe.public_tree_cleaned=$true
  }catch{$probe.cleanup_failure=@{exception_type=$_.Exception.GetType().FullName;hresult=[int]$_.Exception.HResult};$probe.status='failed_or_unknown'}
 }
 $probe.elapsed_ms=$probeClock.ElapsedMilliseconds
}
[Console]::Out.WriteLine(($probe|ConvertTo-Json -Depth 8 -Compress))
if($probe.status -ceq 'preparation_prefix_completed' -and $probe.public_tree_cleaned){exit 0}else{exit 2}
