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
$script:ownedChildren=New-Object Collections.ArrayList;$script:cleanupErrors=New-Object Collections.ArrayList
$script:cleanupMode=$false;$script:cleanupDeadline=270000;$script:lastLimitSample=-1000
$probe=[ordered]@{schema='edr.ci-service-preparation-contract.v2';status='failed_or_unknown';source_sha=$env:GITHUB_SHA;driver_sha256=$DriverSha256;qa_driver_sha256=$QADriverSha256;phase='source_validation';preparation_stage_id=0;statement_start_line=$null;statement_start_column=$null;prefix_statement_count=0;executed_statements=0;acl_contract=$null;parser_errors_is_null=$null;parser_errors_type=$null;parser_errors_safe_count=$null;primary_failure=$null;cleanup_failure=$null;elapsed_ms=0;prefix_only=$false;service_or_agent_started=$false;preflight_worker_started=$false;preflight=$null;failed_control_receipt=$null;worker_cleanup=@();dummy_agent_inputs=$true;runner_temp_public_subroot=$true;public_tree_cleaned=$false}
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
 $probeAllowed=@('Check','Add-Type','Get-Item','Test-Path','Join-Path','New-Item','SaveNew','SetDiagnosticCaseAcl','RegularPath','Hash','Invoke-Expression','SampleLimits','OriginalReadStopLogSlice')
 foreach($probeNode in $probePrefix){
  Guard (@($probeNode.FindAll({param($n)$n -is [Management.Automation.Language.ExitStatementAst]},$true)).Count -eq 0) 'prefix_exit_refused'
  foreach($c in @($probeNode.FindAll({param($n)$n -is [Management.Automation.Language.CommandAst]},$true))){
   $cn=$c.GetCommandName()
   Guard ($null -ne $cn -and $cn -cin $probeAllowed) 'prefix_command_refused'
  }
 }
 $probeIntent=@($probePrefix|Where-Object {$_.Extent.Text -cmatch "^SaveNew 'intent[.]json' "})
 Guard ($probeIntent.Count -eq 1) 'prefix_intent_inventory'
 foreach($codeName in @('publicFailureCodes','stageFailureCodes')){
  $wanted='script:'+$codeName
  $probeCodes=@($probeHarness.ast.FindAll({param($n)$n -is [Management.Automation.Language.AssignmentStatementAst] -and $n.Left -is [Management.Automation.Language.VariableExpressionAst] -and $n.Left.VariablePath.UserPath -ceq $wanted},$true))
  Guard ($probeCodes.Count -eq 1 -and $probeCodes[0].Right.Extent.Text -cmatch "(?s)^\s*@\(\s*(?:'[a-z][a-z0-9_]{0,100}'\s*,?\s*)+\)\s*$") 'literal_failure_codes_required'
  Set-Variable -Scope Script -Name $codeName -Value @([regex]::Matches($probeCodes[0].Right.Extent.Text,"'([a-z][a-z0-9_]{0,100})'")|ForEach-Object {$_.Groups[1].Value})
 }
 foreach($probeName in @('Check','Hash','RegularPath','SetDiagnosticCaseAcl','SaveNew','ProjectPrimaryFailure','WritePublic','Remaining','SampleLimits','StartOwned','WaitOwned','FinishOwned','ReadFailureProjection','RunOwned','ProjectWorkerFailure','PowerShellWorkerSource','PowerShellWorker','ServicePreflightSource','ReadPreflightReceipt','RunServicePreflight')){
  $defs=@($probeHarness.ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $probeName},$true))
  Guard ($defs.Count -eq 1) 'prefix_helper_inventory'
  Invoke-Expression $defs[0].Extent.Text
 }
 $projectLoaded=$true
 # The only executed worker body is the same source-owned read-only preflight.
 # Validate it before running any selected main-prefix statement.
 $probePreflightBody=ServicePreflightSource;$pt=$null;$pe=$null
 $pa=[Management.Automation.Language.Parser]::ParseInput($probePreflightBody,[ref]$pt,[ref]$pe)
 Guard ($null -eq $pe -or @($pe).Count -eq 0) 'preflight_source_parse'
 foreach($c in @($pa.FindAll({param($n)$n -is [Management.Automation.Language.CommandAst]},$true))){Guard ($c.GetCommandName() -cin @('Get-CimInstance','Where-Object','Get-NetFirewallProfile','ConvertTo-Json')) 'readonly_preflight_commands_required'}
 $probeParent=Get-Item -LiteralPath $probeOldRunnerTemp -Force
 Guard ($probeParent.PSIsContainer -and [IO.Path]::IsPathRooted($probeParent.FullName)) 'runner_temp_shape'
 for($d=$probeParent;$null -ne $d;$d=$d.Parent){Guard (($d.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'runner_temp_reparse'}
 $probeRoot=Join-Path $probeParent.FullName ('edr-ci-preparation-contract-'+[guid]::NewGuid().ToString('N'))
 Guard (-not (Test-Path -LiteralPath $probeRoot)) 'public_root_exists'
 $null=New-Item -ItemType Directory -Path $probeRoot -ErrorAction Stop;$probeCreated=$true
 # A public controlled counterexample, not the unknown historical ACL.
 # Incremental grants retain an extra explicit ACE; the actual owner must
 # replace it, preserve owner/group, remain idempotent and protect children.
 $probe.phase='acl_counterexample'
 $aclPath=Join-Path $probeRoot 'acl-contract';$null=New-Item -ItemType Directory -Path $aclPath
 $script:case=$aclPath;$acl=Get-Acl -LiteralPath $aclPath
 $ownerBefore=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value;$groupBefore=$acl.GetGroup([Security.Principal.SecurityIdentifier]).Value
 $acl.SetSecurityDescriptorSddlForm('D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FR;;;AU)',[Security.AccessControl.AccessControlSections]::Access)
 Set-Acl -LiteralPath $aclPath -AclObject $acl
 & (Join-Path $env:WINDIR 'System32\icacls.exe') $aclPath /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
 Guard ($LASTEXITCODE -eq 0) 'legacy_grant_failed'
 $acl=Get-Acl -LiteralPath $aclPath;$rules=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
 Guard ($rules.Count -ge 3 -and @($rules|Where-Object {$_.IdentityReference.Value -ceq 'S-1-5-11' -and -not $_.IsInherited}).Count -eq 1) 'legacy_explicit_ace_counterexample_missing'
 SetDiagnosticCaseAcl $aclPath;SetDiagnosticCaseAcl $aclPath
 $acl=Get-Acl -LiteralPath $aclPath
 Guard ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ceq $ownerBefore -and $acl.GetGroup([Security.Principal.SecurityIdentifier]).Value -ceq $groupBefore) 'acl_owner_or_group_changed'
 $child=Join-Path $aclPath 'child';$null=New-Item -ItemType Directory -Path $child
 $childAcl=Get-Acl -LiteralPath $child;$childRules=@($childAcl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
 Guard ($childRules.Count -eq 2) 'child_acl_rule_count'
 foreach($rule in $childRules){Guard ($rule.IdentityReference.Value -cin @('S-1-5-18','S-1-5-32-544') -and $rule.IsInherited -and $rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and $rule.FileSystemRights -eq [Security.AccessControl.FileSystemRights]::FullControl) 'child_acl_not_private'}
 $marker=Join-Path $child 'public.txt';[IO.File]::WriteAllText($marker,'acl-public-fixture',[Text.UTF8Encoding]::new($false))
 Guard ([IO.File]::ReadAllText($marker) -ceq 'acl-public-fixture') 'private_child_roundtrip'
 $probe.acl_contract=@{controlled_extra_explicit_ace_preserved_by_legacy_grant=$true;canonical_reset_twice_passed=$true;owner_group_preserved=$true;child_inherits_private_acl=$true;public_marker_roundtrip=$true;historical_acl_replayed=$false}
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
 $probe.phase='winps51_readonly_preflight'
 $probe.preflight=RunServicePreflight $probePreflightBody
 $probe.preflight_worker_started=($script:ownedChildren.Count -gt 0)
 Guard ((Get-FileHash -LiteralPath $probeHarness.path -Algorithm SHA256).Hash.ToLowerInvariant() -ceq $DriverSha256 -and (Get-FileHash -LiteralPath $probeQA.path -Algorithm SHA256).Hash.ToLowerInvariant() -ceq $QADriverSha256) 'source_changed'
 $probe.phase='preparation_and_preflight_completed';$probe.status='preparation_and_preflight_completed'
}catch{
 if($projectLoaded){$probe.primary_failure=ProjectPrimaryFailure $_}else{$probe.primary_failure=@{exception_type=$_.Exception.GetType().FullName;hresult=[int]$_.Exception.HResult;native_error=$null;source_line=$null;source_column=$null;cause_code='bootstrap_source_rejected_no_message'}}
 if($projectLoaded){$probe.preparation_stage_id=$script:result.preparation_stage_id}
}finally{
 $probe.preflight_worker_started=($script:ownedChildren.Count -gt 0)
 if($script:result.Contains('failed_control_receipt')){$probe.failed_control_receipt=$script:result.failed_control_receipt}
 if($probeParserSelected){$probe.parser_errors_is_null=($null -eq $errors);if($null -ne $errors){$probe.parser_errors_type=$errors.GetType().FullName};$probe.parser_errors_safe_count=if($null -eq $errors){0}else{@($errors).Count}}
 $env:RUNNER_TEMP=$probeOldRunnerTemp
 # Held objects only. Never reopen an arbitrary PID or invoke full SCM cleanup.
 # Unknown identity/exit/EOF retains the public tree and fails this test.
 $workersClean=$true;$script:cleanupMode=$true
 foreach($v in $script:ownedChildren){
  try{
   Guard ($null -ne $v.pid -and $null -ne $v.birth -and $v.process.Id -eq $v.pid -and $v.process.StartTime.ToUniversalTime().ToFileTimeUtc().ToString() -ceq $v.birth) 'public_worker_identity_unknown'
   if(-not $v.process.HasExited){$v.cancelled=$true;$v.process.Kill();Guard ($v.process.WaitForExit(2000)) 'public_worker_cleanup_unknown'}
   Guard ($v.process.HasExited -and $v.process.ExitCode -is [int]) 'public_worker_terminal_unknown'
   Guard ($null -ne $v.out_task -and $null -ne $v.err_task -and $v.out_task.Wait(2000) -and $v.err_task.Wait(2000)) 'public_worker_stream_eof_unknown'
   $v.out_file.Dispose();$v.err_file.Dispose()
   $probe.worker_cleanup+=@{pid=$v.pid;birth_filetime=$v.birth;terminal_known=$true;exit_code=$v.process.ExitCode;cancelled=$v.cancelled;streams_closed=$true}
   $v.process.Dispose()
  }catch{$workersClean=$false;$probe.cleanup_failure=@{exception_type=$_.Exception.GetType().FullName;hresult=[int]$_.Exception.HResult};$probe.status='failed_or_unknown'}
 }
 if($script:cleanupErrors.Count){$workersClean=$false;$probe.cleanup_failure=@{exception_type='owned_worker_cleanup_reported';hresult=$null};$probe.status='failed_or_unknown'}
 if($probeCreated -and $workersClean){
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
if($probe.status -ceq 'preparation_and_preflight_completed' -and $probe.public_tree_cleaned){exit 0}else{exit 2}
