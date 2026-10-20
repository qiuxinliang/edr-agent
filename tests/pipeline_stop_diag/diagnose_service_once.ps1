#Requires -Version 7.0
#Requires -PSEdition Core
<# PRIVATE DRAFT. Run only on a fresh GitHub-hosted Windows native CI runner.
No installer/updater/release operation. No Agent on an endpoint is addressed.
The 45s stop outcome is durably frozen BEFORE observation or cleanup.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{32}$')][string]$Token,
  [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{40}$')][string]$SourceSha,
  [Parameter(Mandatory)][ValidateSet('amd64','arm64')][string]$Architecture,
  [Parameter(Mandatory)][string]$AgentPath,
  [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$AgentSha256,
  [Parameter(Mandatory)][ValidateCount(1,4)][string[]]$DllRoots,
  [Parameter(Mandatory)][string]$DumpbinPath,
  [Parameter(Mandatory)][string]$PythonPath,
  [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$QADriverSha256,
  [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$NativeStagerSha256,
  [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$StageAdapterSha256,
  [Parameter(Mandatory)][string]$NativeToolManifestPath,
  [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$NativeToolManifestSha256,
  [Parameter(Mandatory)][string]$ConfigTemplatePath,
  [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$ConfigTemplateSha256
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$script:experimentClock=[Diagnostics.Stopwatch]::StartNew()
$script:case=$null;$script:leases=New-Object Collections.ArrayList
$script:ownedChildren=New-Object Collections.ArrayList
$script:createIntent=$false;$script:firewallIntent=$false;$script:target=$null
$script:lastLimitSample=-1000
$script:cleanupMode=$false;$script:cleanupDeadline=270000
$script:context=$null;$script:primary=$null;$script:cleanupErrors=New-Object Collections.ArrayList
$script:serviceName='FDSecurityAgentCI_'+$Token
$script:ruleName='EDR-CI-Service-Offline-'+$Token
$script:result=[ordered]@{schema='edr.ci-isolated-service-diagnostic.v1';source_sha=$SourceSha;token=$Token;arch=$Architecture;status='prepared_not_run';phase='preflight';preparation_stage_id=0;intent_recorded=$false;primary_failure=$null;stop_result=$null;target=$null;shutdown_log_observation=$null;cleanup=$null;whole_recovery_accepted=$false;actual_original_service_cause_proven=$false;model_or_rule_ready_claimed=$false;all_8192_slots_exercised=$false;framework_parent_job_covers_service=$false;diagnostic_agent_not_release=$true;pipeline_instrumentor_thread_safe_claimed=$false}

$script:publicFailureCodes=@(
  'actual_692_701_template_required',
  'administrator_required',
  'agent_loader_or_startup_failed',
  'bounded_regular_file_required',
  'bounded_worker_nonzero_no_retry',
  'bounded_worker_timed_out_no_retry',
  'config_template_identity',
  'control_stream_capture_failed',
  'control_worker_still_live',
  'created_service_shape',
  'dedicated_ci_agent_target_required',
  'exact_service_exit_unknown',
  'exact_service_process_cleanup_unknown',
  'experiment_deadline_before_launch',
  'experiment_entry_cap',
  'experiment_live_log_cap',
  'experiment_reparse_refused',
  'experiment_sampled_file_length_cap',
  'experiment_sampled_volume_free_floor',
  'experiment_work_deadline_after_sample',
  'firewall_name_exists',
  'firewall_profile_disabled',
  'fixture_scalar_control',
  'fixture_scalar_not_unique',
  'fixture_section_not_unique',
  'fresh_case_required',
  'fresh_source_bound_github_hosted_only',
  'insufficient_budget_before_full_stop_observation',
  'insufficient_budget_before_service_create',
  'machine_edr_override_present',
  'native_seed_receipt',
  'offline_rule_readback',
  'original_budget_literals_required',
  'owned_service_deletion_unconfirmed',
  'owned_worker_cleanup_unknown',
  'owned_worker_exit_unknown',
  'owned_worker_launch_failed',
  'owned_worker_output_bound',
  'owned_worker_stream_eof_unknown',
  'owned_worker_terminal_unknown',
  'pre_stop_log_binding_unknown',
  'preexisting_agent_or_service',
  'preflight_progress_file_shape',
  'preflight_progress_source_shape',
  'preflight_receipt_invalid',
  'private_case_acl_not_protected',
  'private_case_acl_unexpected_principal',
  'public_worker_source_bound',
  'qa_function_inventory',
  'qa_owner_parse_failure',
  'reparse_parent_refused',
  'rule_count',
  'rule_owner',
  'rule_still_present',
  'runner_temp_invalid',
  'sampler_cleanup_unknown',
  'sampler_projection_birth',
  'sampler_projection_bound',
  'sampler_projection_count',
  'sampler_projection_elapsed',
  'sampler_projection_number',
  'sampler_projection_shape',
  'seed_manifest_changed',
  'seed_stderr_unclassified',
  'seed_tool_closure_changed',
  'service_count',
  'service_disappeared',
  'service_exited_before_stop',
  'service_owner_or_state_mismatch',
  'service_owner_terminal_unknown',
  'service_snapshot_shape',
  'service_startup_not_running',
  'service_target_generation_changed',
  'service_target_identity_incomplete',
  'stage_adapter_hash_mismatch',
  'staged_runtime_changed',
  'stop_worker_cleanup_unknown',
  'summary_bound',
  'synthetic_copy_hash',
  'synthetic_seed_directory_escape',
  'synthetic_seed_main_missing',
  'synthetic_seed_source_changed',
  'unexpected_template_detection_section',
  'unexpected_template_policy_section',
  'workflow_bound_qa_owner_changed'
)
$script:stageFailureCodes=@(
  'ambiguous_dependency_bytes',
  'compiled_agent_architecture_mismatch',
  'compiled_agent_identity_mismatch',
  'dependency_architecture_mismatch',
  'dependency_copy_readback_mismatch',
  'dependency_file_count_cap',
  'dependency_not_in_pinned_compiler_roots',
  'dependency_source_changed',
  'dependency_stage_deadline',
  'dependency_total_cap',
  'owner_artifact_hash_or_size',
  'owner_artifact_machine',
  'owner_artifact_path',
  'owner_directory_missing',
  'owner_dll_name_ambiguous',
  'owner_dumpbin_diagnostic',
  'owner_dumpbin_failed',
  'owner_dumpbin_shape',
  'owner_file_cap',
  'owner_import_shape',
  'owner_imports_empty',
  'owner_inventory_mismatch',
  'owner_pe_dos_header',
  'owner_pe_offset',
  'owner_pe_optional_header',
  'owner_pe_signature',
  'owner_regular_file_missing',
  'owner_reparse_refused',
  'owner_stage_deadline',
  'pinned_import_owner_mismatch',
  'runtime_inventory_mismatch',
  'same_source_passed_seed_tool_required',
  'seed_manifest_sha_mismatch'
)
function Check($Value,[string]$Cause){if(-not $Value){throw $Cause}}
function ProjectPrimaryFailure([Management.Automation.ErrorRecord]$Record){
  # Only runtime types, closed causes and numeric positions; never exception
  # messages, invocation text, paths, stack traces or arbitrary error IDs.
  $exception=$Record.Exception;$kind=$exception.GetType().FullName
  if($kind -cnotmatch '^[A-Za-z_][A-Za-z0-9_.]{0,255}$'){$kind='unknown'}
  $native=$null;$inner=$exception
  for($depth=0;$depth -lt 4 -and $null -ne $inner;$depth++){
    if($inner -is [ComponentModel.Win32Exception]){$native=[int]$inner.NativeErrorCode;break}
    $inner=$inner.InnerException
  }
  $line=$null;$column=$null;$info=$Record.InvocationInfo
  if($null -ne $info){
    if($info.ScriptLineNumber -ge 1 -and $info.ScriptLineNumber -le 100000){$line=[int]$info.ScriptLineNumber}
    if($info.OffsetInLine -ge 1 -and $info.OffsetInLine -le 16384){$column=[int]$info.OffsetInLine}
  }
  return @{exception_type=$kind;hresult=[int]$exception.HResult;native_error=$native;source_line=$line;source_column=$column;cause_code=if($exception.Message -cin $script:publicFailureCodes){$exception.Message}else{'unclassified_no_message_export'}}
}
function WriteDiagnosticSummary([bool]$Accepted){
  [Console]::Out.WriteLine((@{schema='edr.ci-isolated-service-summary.v1';source_sha=$SourceSha;token=$Token;diagnostic_accepted=$Accepted;stop_status=if($null -ne $script:result.stop_result){$script:result.stop_result.status}else{'not_reached'};elapsed_ms=$script:experimentClock.ElapsedMilliseconds;phase=$script:result.phase;preparation_stage_id=$script:result.preparation_stage_id;intent_recorded=$script:result.intent_recorded;primary_failure=$script:result.primary_failure;whole_recovery_accepted=$false}|ConvertTo-Json -Depth 8 -Compress))
}
function Hash([string]$Path){(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()}
function RegularPath([string]$Path,[long]$Cap=67108864){
  $p=Get-Item -LiteralPath $Path -Force -ErrorAction Stop
  Check (-not $p.PSIsContainer -and ($p.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0 -and $p.Length -ge 0 -and $p.Length -le $Cap) 'bounded_regular_file_required'
  $parent=$p.Directory
  while($null -ne $parent){Check (($parent.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'reparse_parent_refused';$parent=$parent.Parent}
  return $p.FullName
}
function SetDiagnosticCaseAcl([string]$Path){
  $item=Get-Item -LiteralPath $Path -Force -ErrorAction Stop
  Check ($item.PSIsContainer -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0 -and $item.FullName -ceq $script:case) 'private_case_acl_unexpected_principal'
  # Replace Access only. Incremental grants can retain other explicit ACEs.
  # Preserve the current owner/group/SACL; grant no additional identity.
  $acl=Get-Acl -LiteralPath $item.FullName
  $acl.SetSecurityDescriptorSddlForm('D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)',[Security.AccessControl.AccessControlSections]::Access)
  Set-Acl -LiteralPath $item.FullName -AclObject $acl -ErrorAction Stop
  $acl=Get-Acl -LiteralPath $item.FullName
  $rules=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
  Check ($acl.AreAccessRulesProtected -and $rules.Count -eq 2) 'private_case_acl_not_protected'
  $seen=@{};$inherit=[Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
  foreach($rule in $rules){
    $sid=$rule.IdentityReference.Value
    Check ($sid -cin @('S-1-5-18','S-1-5-32-544') -and -not $seen.ContainsKey($sid) -and
      $rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and -not $rule.IsInherited -and
      $rule.FileSystemRights -eq [Security.AccessControl.FileSystemRights]::FullControl -and
      $rule.InheritanceFlags -eq $inherit -and $rule.PropagationFlags -eq [Security.AccessControl.PropagationFlags]::None) 'private_case_acl_unexpected_principal'
    $seen[$sid]=$true
  }
}
function SaveNew([string]$Name,$Value){
  $text=$Value|ConvertTo-Json -Depth 24 -Compress;$bytes=[Text.UTF8Encoding]::new($false).GetBytes($text+"`n")
  Check ($bytes.Length -le 131072) 'summary_bound'
  $s=[IO.File]::Open((Join-Path $script:case $Name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
  try{$s.Write($bytes,0,$bytes.Length);$s.Flush($true)}finally{$s.Dispose()}
}
function WritePublic([string]$Name,[string]$Text){
  $path=Join-Path $script:case $Name;$bytes=[Text.UTF8Encoding]::new($false).GetBytes($Text)
  Check ($bytes.Length -le 262144) 'public_worker_source_bound'
  $s=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
  try{$s.Write($bytes,0,$bytes.Length);$s.Flush($true)}finally{$s.Dispose()};return $path
}
function Remaining([int]$Reserve=30){if($script:cleanupMode){return [Math]::Max(0,$script:cleanupDeadline-$script:experimentClock.ElapsedMilliseconds)};[Math]::Max(0,270000-$script:experimentClock.ElapsedMilliseconds-$Reserve*1000)}
function SampleLimits {
  if($script:cleanupMode -or $script:experimentClock.ElapsedMilliseconds-$script:lastLimitSample -lt 1000){return}
  $script:lastLimitSample=$script:experimentClock.ElapsedMilliseconds
  $pending=New-Object Collections.Generic.Stack[string];$pending.Push($script:case);$count=0;$bytes=[uint64]0
  while($pending.Count){
    $path=$pending.Pop()
    foreach($child in [IO.Directory]::EnumerateFileSystemEntries($path)){
      $count++;Check ($count -le 4096) 'experiment_entry_cap'
      $item=Get-Item -LiteralPath $child -Force -ErrorAction Stop
      Check (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'experiment_reparse_refused'
      if($item.PSIsContainer){$pending.Push($item.FullName)}else{
        $bytes+=[uint64]$item.Length;Check ($bytes -le 268435456) 'experiment_sampled_file_length_cap'
        if($item.Name -ceq 'agent.log'){Check ($item.Length -le 1048576) 'experiment_live_log_cap'}
      }
    }
  }
  $drive=[IO.DriveInfo]::new([IO.Path]::GetPathRoot($script:case))
  Check ($drive.AvailableFreeSpace -ge 268435456) 'experiment_sampled_volume_free_floor'
  $script:result.last_resource_sample=@{elapsed_ms=$script:experimentClock.ElapsedMilliseconds;entries=$count;file_length_bytes=$bytes;volume_available_bytes=$drive.AvailableFreeSpace;file_length_cap_bytes=268435456;volume_free_floor_bytes=268435456;agent_log_length_cap_bytes=1048576;atomic_quota=$false;allocated_file_bytes_measured=$false}
  Check ($script:experimentClock.ElapsedMilliseconds -le 240000) 'experiment_work_deadline_after_sample'
}
function StartOwned([string]$Label,[string]$Exe,[string[]]$Arguments){
  $out=Join-Path $script:case ($Label+'.stdout.log');$err=Join-Path $script:case ($Label+'.stderr.log')
  $info=[Diagnostics.ProcessStartInfo]::new();$info.FileName=$Exe;$info.UseShellExecute=$false;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true;$info.CreateNoWindow=$true
  foreach($a in $Arguments){$info.ArgumentList.Add($a)}
  $info.WorkingDirectory=$script:case
  if($Label -ceq 'seed'){ $info.Environment['TEMP']=$script:seedTemp;$info.Environment['TMP']=$script:seedTemp }
  # Control workers are not the SCM Agent. Their environment is never treated
  # as proof of SCM's effective environment. Do not export environment values.
  $null=$info.Environment.Remove('PSModulePath')
  foreach($key in @($info.Environment.Keys)){if($key.StartsWith('EDR_',[StringComparison]::OrdinalIgnoreCase)){$null=$info.Environment.Remove($key)}}
  $p=[Diagnostics.Process]::new();$p.StartInfo=$info
  $ofs=[IO.File]::Open($out,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
  $efs=[IO.File]::Open($err,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
  $v=@{label=$Label;process=$p;pid=$null;birth=$null;stdout=$out;stderr=$err;terminal_known=$false;exit_known=$false;exit_code=$null;cancelled=$false;out_task=$null;err_task=$null;out_file=$ofs;err_file=$efs}
  try {
    Check ($p.Start()) 'owned_worker_launch_failed'
    $null=$script:ownedChildren.Add($v)
    $null=$p.Handle;$v.pid=$p.Id;$v.birth=$p.StartTime.ToUniversalTime().ToFileTimeUtc().ToString()
    $v.out_task=[CiServiceBoundedPump]::Copy($p.StandardOutput.BaseStream,$ofs,131072)
    $v.err_task=[CiServiceBoundedPump]::Copy($p.StandardError.BaseStream,$efs,131072)
    return $v
  }catch{
    try{if($p.Id -gt 0 -and -not $p.HasExited){$p.Kill();$null=$p.WaitForExit(2000)}}catch{$null=$script:cleanupErrors.Add(@{phase='launch_initialization';exception_type=$_.Exception.GetType().FullName})}
    $ofs.Dispose();$efs.Dispose();throw
  }
}
function WaitOwned($Value,[int]$Milliseconds,[switch]$KeepOnTimeout){
  $p=$Value.process
  $deadline=[Diagnostics.Stopwatch]::StartNew();$finished=$false
  while($deadline.ElapsedMilliseconds -lt $Milliseconds){
    $left=[int][Math]::Max(1,$Milliseconds-$deadline.ElapsedMilliseconds)
    if($p.WaitForExit([int][Math]::Min(200,$left))){$finished=$true;break}
    SampleLimits
    Check (-not $Value.out_task.IsFaulted -and -not $Value.err_task.IsFaulted) 'control_stream_capture_failed'
  }
  if(-not $finished){if(-not $KeepOnTimeout){$Value.cancelled=$true;$p.Kill();Check ($p.WaitForExit(2000)) 'owned_worker_cleanup_unknown'};return $false}
  $Value.terminal_known=$true;$code=$p.ExitCode
  Check ($null -ne $code -and $code -is [int]) 'owned_worker_exit_unknown'
  $Value.exit_known=$true;$Value.exit_code=$code;return $true
}
function FinishOwned($Value,[int]$Cap=16384){
  Check ($Value.terminal_known -or $Value.process.HasExited) 'owned_worker_terminal_unknown'
  $null=WaitOwned $Value 1
  Check ($Value.out_task.Wait(2000) -and $Value.err_task.Wait(2000)) 'owned_worker_stream_eof_unknown'
  $Value.out_file.Flush($true);$Value.err_file.Flush($true);$Value.out_file.Dispose();$Value.err_file.Dispose()
  $rows=@{}
  foreach($kind in @('stdout','stderr')){$path=$Value[$kind];$f=Get-Item -LiteralPath $path;Check ($f.Length -le $Cap) 'owned_worker_output_bound';$rows[$kind]=@{bytes=$f.Length;sha256=Hash $path}}
  return @{pid=$Value.pid;birth_filetime=$Value.birth;terminal_known=$Value.terminal_known;exit_known=$Value.exit_known;exit_code=$Value.exit_code;cancelled=$Value.cancelled;stdout=$rows.stdout;stderr=$rows.stderr}
}
function ReadFailureProjection([string]$Path,[ValidateSet('powershell_worker','python_stage','unsupported')][string]$ExpectedOrigin){
  $unknown=@{schema='edr.ci-owned-failure-projection.v2';status='unknown';origin=$null;exception_type=$null;hresult=$null;cause_code='unknown';operation_id=$null;cim_native_error=$null;cim_status_code=$null}
  if($ExpectedOrigin -ceq 'unsupported'){return $unknown}
  $document=$null
  try{
    # FinishOwned already confirmed terminal/EOF. Read the same bounded bytes;
    # do not export the text on malformed, extra-key or unknown output.
    $raw=ReadOwnedBytes $Path 4096
    $text=[Text.UTF8Encoding]::new($false,$true).GetString($raw.bytes)
    $document=[Text.Json.JsonDocument]::Parse($text);$root=$document.RootElement
    if($root.ValueKind -ne [Text.Json.JsonValueKind]::Object){throw 'projection_root'}
    $expected=@('schema','origin','exception_type','hresult','cause_code')
    $schema='edr.ci-owned-failure.v1'
    if($ExpectedOrigin -ceq 'powershell_worker'){$expected+=@('operation_id','cim_native_error','cim_status_code');$schema='edr.ci-owned-failure.v2'}
    $keys=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach($property in $root.EnumerateObject()){
      if(-not $keys.Add($property.Name) -or $property.Name -cnotin $expected){throw 'projection_key'}
    }
    if($keys.Count -ne $expected.Count){throw 'projection_keys_missing'}
    foreach($key in @('schema','origin','exception_type','cause_code')){
      if($root.GetProperty($key).ValueKind -ne [Text.Json.JsonValueKind]::String){throw 'projection_string_type'}
    }
    if($root.GetProperty('schema').GetString() -cne $schema -or $root.GetProperty('origin').GetString() -cne $ExpectedOrigin){throw 'projection_identity'}
    $kind=$root.GetProperty('exception_type').GetString()
    if($kind -cnotmatch '^[A-Za-z_][A-Za-z0-9_.+`]{0,255}$'){throw 'projection_exception_type'}
    $code=$root.GetProperty('cause_code').GetString()
    $allowed=if($ExpectedOrigin -ceq 'python_stage'){$script:stageFailureCodes}else{$script:publicFailureCodes}
    if($code -cne 'unknown' -and $code -cnotin $allowed){throw 'projection_cause'}
    $hresult=$null;$operation=$null;$native=$null;$status=$null;$number=$root.GetProperty('hresult')
    if($ExpectedOrigin -ceq 'python_stage'){
      if($number.ValueKind -ne [Text.Json.JsonValueKind]::Null){throw 'projection_python_hresult'}
    }else{
      $integer=[int]0
      if($number.ValueKind -ne [Text.Json.JsonValueKind]::Number -or -not $number.TryGetInt32([ref]$integer)){throw 'projection_hresult'}
      $hresult=$integer
      $number=$root.GetProperty('operation_id');$integer=[int]0
      if($number.ValueKind -ne [Text.Json.JsonValueKind]::Number -or -not $number.TryGetInt32([ref]$integer) -or $integer -lt 0 -or $integer -gt 5){throw 'projection_operation'}
      $operation=$integer
      $number=$root.GetProperty('cim_native_error');$integer=[int]0
      if($number.ValueKind -ne [Text.Json.JsonValueKind]::Null){
        if($number.ValueKind -ne [Text.Json.JsonValueKind]::Number -or -not $number.TryGetInt32([ref]$integer)){throw 'projection_cim_native'};$native=$integer
      }
      $number=$root.GetProperty('cim_status_code');$unsigned=[uint32]0
      if($number.ValueKind -ne [Text.Json.JsonValueKind]::Null){
        if($number.ValueKind -ne [Text.Json.JsonValueKind]::Number -or -not $number.TryGetUInt32([ref]$unsigned)){throw 'projection_cim_status'};$status=$unsigned
      }
    }
    return @{schema='edr.ci-owned-failure-projection.v2';status='projected';origin=$ExpectedOrigin;exception_type=$kind;hresult=$hresult;cause_code=$code;operation_id=$operation;cim_native_error=$native;cim_status_code=$status}
  }catch{return $unknown}
  finally{if($null -ne $document){$document.Dispose()}}
}
function RunOwned([string]$Label,[string]$Exe,[string[]]$Arguments,[int]$Milliseconds=5000,[int]$Cap=16384){
  Check ((Remaining) -ge $Milliseconds) 'experiment_deadline_before_launch'
  $v=StartOwned $Label $Exe $Arguments
  Check (WaitOwned $v $Milliseconds) 'bounded_worker_timed_out_no_retry'
  $receipt=FinishOwned $v $Cap
  $v.receipt=$receipt
  if($receipt.exit_code -ne 0 -and -not $script:result.Contains('failed_control_receipt')){
    $origin=if($Label -ceq 'stage-runtime'){'python_stage'}elseif($Exe -ieq $script:winPS){'powershell_worker'}else{'unsupported'}
    $script:result.failed_control_receipt=@{label=$Label;receipt=$receipt;failure=(ReadFailureProjection $v.stdout $origin)}
  }
  Check ($receipt.exit_code -eq 0) 'bounded_worker_nonzero_no_retry';return $v
}
function ProjectWorkerFailure {
  param([Management.Automation.ErrorRecord]$Record,$OperationId,[string[]]$Codes)
  if($OperationId -isnot [int] -or $OperationId -lt 0 -or $OperationId -gt 5){throw 'worker_operation_id_invalid'}
  $cause='unknown';$native=$null;$status=$null;$e=$Record.Exception
  $cimType='Microsoft.Management.Infrastructure.CimException' -as [type]
  for($depth=0;$null -ne $e -and $depth -lt 8;$depth++){
    if($cause -ceq 'unknown' -and $e.Message -cin $Codes){$cause=$e.Message}
    if($null -ne $cimType -and $cimType.IsInstanceOfType($e)){
      # Normalize only the real MI enum's Int32 backing value; never infer a
      # code from HResult, messages, ErrorData or arbitrary ErrorRecord IDs.
      if($null -eq $native){try{
        $p=$e.PSObject.Properties['NativeErrorCode'];if($null -ne $p){
          $v=$p.Value
          if($v -is [int]){$native=$v}
          elseif($null -ne $v -and $v.GetType().FullName -ceq 'Microsoft.Management.Infrastructure.NativeErrorCode' -and $v.GetType().IsEnum -and [Enum]::GetUnderlyingType($v.GetType()) -eq [int]){$native=[Convert]::ToInt32($v,[Globalization.CultureInfo]::InvariantCulture)}
        }
      }catch{$native=$null}}
      if($null -eq $status){try{$p=$e.PSObject.Properties['StatusCode'];if($null -ne $p){$v=$p.Value;if($v -is [uint32]){$status=$v}}}catch{$status=$null}}
    }
    $e=$e.InnerException
  }
  $kind=$Record.Exception.GetType().FullName
  if($kind -cnotmatch '^[A-Za-z_][A-Za-z0-9_.+`]{0,255}$'){$kind='unknown'}
  return @{schema='edr.ci-owned-failure.v2';origin='powershell_worker';exception_type=$kind;hresult=[int]$Record.Exception.HResult;cause_code=$cause;operation_id=$OperationId;cim_native_error=$native;cim_status_code=$status}
}
function PowerShellWorkerSource([string]$Body){
  $template=@'
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
$publicFailureCodes=@(__CODES__)
$operationId=0
function ProjectWorkerFailure {
__PROJECT__
}
try {
__BODY__
}catch{
  $projection=ProjectWorkerFailure $_ $operationId $publicFailureCodes
  [Console]::Out.WriteLine(($projection|ConvertTo-Json -Compress));[Console]::Out.Flush()
  exit 1
}
'@
  $literals=($script:publicFailureCodes|ForEach-Object {"'"+$_+"'"}) -join ','
  return $template.Replace('__CODES__',$literals).Replace('__PROJECT__',${function:ProjectWorkerFailure}.ToString()).Replace('__BODY__',$Body)
}
function PowerShellWorker([string]$Label,[string]$Body,[int]$Milliseconds=5000,[int]$Cap=16384){
  $path=WritePublic ($Label+'.ps1') (PowerShellWorkerSource $Body)
  RunOwned $Label $script:winPS @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',$path) $Milliseconds $Cap
}
function ServicePreflightSource {
  # One read-only query owner, shared with the early WinPS5.1 contract.
  return @'
$script:preflightProgressPath='__PREFLIGHT_PROGRESS_PATH__'
function SetPreflightProgress([byte]$Operation){
  $stream=[IO.File]::Open($script:preflightProgressPath,[IO.FileMode]::Open,[IO.FileAccess]::Write,[IO.FileShare]::Read)
  try{
    if($stream.Length -ne 1 -or $Operation -lt 1 -or $Operation -gt 5){throw 'preflight_progress_file_shape'}
    $stream.Position=0;$stream.WriteByte($Operation);$stream.Flush()
  }finally{$stream.Dispose()}
}
$operationId=1
SetPreflightProgress $operationId
$s=@(Get-CimInstance Win32_Service -Property Name,PathName -OperationTimeoutSec 1 -ErrorAction Stop|Where-Object {$_.Name -in @('FDSecurityAgent','EdrAgent','FDSecurityAgentCISmoke','__SERVICE__') -or $_.PathName -match '(?i)(FDSensor|edr_agent)\.exe'})
$operationId=2
SetPreflightProgress $operationId
$p=@(Get-CimInstance Win32_Process -Property Name -OperationTimeoutSec 1 -ErrorAction Stop|Where-Object {$_.Name -in @('FDSensor.exe','edr_agent.exe')})
if($s.Count -or $p.Count){throw 'preexisting_agent_or_service'}
$operationId=3
SetPreflightProgress $operationId
$m=[Environment]::GetEnvironmentVariables([EnvironmentVariableTarget]::Machine);$keys=@($m.Keys|Where-Object {[string]$_ -like 'EDR_*'})
if($keys.Count){throw 'machine_edr_override_present'}
$operationId=4
SetPreflightProgress $operationId
if(@(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop|Where-Object {-not $_.Enabled}).Count){throw 'firewall_profile_disabled'}
$operationId=5
SetPreflightProgress $operationId
[Console]::Out.WriteLine((@{schema='edr.ci-service-preflight.v1';clean_aliases=$true;machine_edr_override_count=0;firewall_profiles_enabled=$true;operation_id=$operationId;ps_major=$PSVersionTable.PSVersion.Major;ps_edition=$PSVersionTable.PSEdition}|ConvertTo-Json -Compress));exit 0
'@
}
function ReadPreflightReceipt($Value){
  $document=$null
  try{
    if($Value.terminal_known -isnot [bool] -or -not $Value.terminal_known -or $Value.exit_known -isnot [bool] -or -not $Value.exit_known -or $Value.exit_code -isnot [int] -or $Value.exit_code -ne 0 -or $Value.cancelled -isnot [bool] -or $Value.cancelled){return $null}
    $err=ReadOwnedBytes $Value.stderr 4096;if($err.bytes.Length -ne 0){return $null}
    $raw=ReadOwnedBytes $Value.stdout 4096
    $document=[Text.Json.JsonDocument]::Parse([Text.UTF8Encoding]::new($false,$true).GetString($raw.bytes));$root=$document.RootElement
    if($root.ValueKind -ne [Text.Json.JsonValueKind]::Object){return $null}
    $expected=@('schema','clean_aliases','machine_edr_override_count','firewall_profiles_enabled','operation_id','ps_major','ps_edition')
    $keys=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach($p in $root.EnumerateObject()){if(-not $keys.Add($p.Name) -or $p.Name -cnotin $expected){return $null}}
    if($keys.Count -ne 7){return $null}
    foreach($key in @('schema','ps_edition')){if($root.GetProperty($key).ValueKind -ne [Text.Json.JsonValueKind]::String){return $null}}
    if($root.GetProperty('schema').GetString() -cne 'edr.ci-service-preflight.v1' -or $root.GetProperty('ps_edition').GetString() -cne 'Desktop'){return $null}
    foreach($key in @('clean_aliases','firewall_profiles_enabled')){if($root.GetProperty($key).ValueKind -ne [Text.Json.JsonValueKind]::True){return $null}}
    foreach($pair in @(@('machine_edr_override_count',0),@('operation_id',5),@('ps_major',5))){
      $v=[int]0;$p=$root.GetProperty($pair[0]);if($p.ValueKind -ne [Text.Json.JsonValueKind]::Number -or -not $p.TryGetInt32([ref]$v) -or $v -ne $pair[1]){return $null}
    }
    return @{schema='edr.ci-service-preflight.v1';clean_aliases=$true;machine_edr_override_count=0;firewall_profiles_enabled=$true;operation_id=5;ps_major=5;ps_edition='Desktop'}
  }catch{return $null}
  finally{if($null -ne $document){$document.Dispose()}}
}
function ReadPreflightProgress([string]$Path,$TerminalKnown){
  $unknown=@{status='unknown';last_operation_id=$null}
  if($TerminalKnown -isnot [bool] -or -not $TerminalKnown){return $unknown}
  try{
    $raw=ReadOwnedBytes $Path 1
    if($raw.bytes.Length -ne 1 -or $raw.bytes[0] -gt 5){return $unknown}
    $op=[int]$raw.bytes[0]
    return @{status=if($op -eq 0){'no_child_progress_observed'}else{'observed'};last_operation_id=$op}
  }catch{return $unknown}
}
function RunServicePreflight([string]$Body){
  $script:preflightProgressPath=Join-Path $script:case 'preflight-progress.bin'
  $first=$script:ownedChildren.Count
  try{
    Check ([regex]::Matches($Body,"'__PREFLIGHT_PROGRESS_PATH__'").Count -eq 1) 'preflight_progress_source_shape'
    $stream=[IO.File]::Open($script:preflightProgressPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
    try{$stream.WriteByte(0);$stream.Flush()}finally{$stream.Dispose()}
    $literal="'"+$script:preflightProgressPath.Replace("'","''")+"'"
    $bodyWithPath=$Body.Replace("'__PREFLIGHT_PROGRESS_PATH__'",$literal).Replace('__SERVICE__',$script:serviceName)
    $v=PowerShellWorker 'preflight' $bodyWithPath 20000 4096
    $accepted=ReadPreflightReceipt $v;Check ($null -ne $accepted) 'preflight_receipt_invalid'
    return @{worker=$v.receipt;preflight=$accepted}
  }finally{
    # No retry or extra wait. Read only after this invocation's held child is
    # known terminal; a published operation is not a stack or timeout cause.
    $known=$false
    if($script:ownedChildren.Count -eq $first + 1){
      $child=$script:ownedChildren[$first]
      try{$known=($child.label -ceq 'preflight' -and $null -ne $child.pid -and $null -ne $child.birth -and $child.process.Id -eq $child.pid -and $child.process.StartTime.ToUniversalTime().ToFileTimeUtc().ToString() -ceq $child.birth -and $child.process.HasExited -and $child.process.ExitCode -is [int])}catch{$known=$false}
    }
    $script:result.preflight_progress=ReadPreflightProgress $script:preflightProgressPath $known
  }
}
function Snapshot([string]$Label,[switch]$AllowAbsent){
  $body=@'
$s=@(Get-CimInstance Win32_Service -Filter "Name='__SERVICE__'" -Property Name,State,ProcessId,PathName,StartMode,StartName,CheckPoint,WaitHint,ExitCode,ServiceSpecificExitCode -OperationTimeoutSec 1 -ErrorAction Stop)
if($s.Count -eq 0){[Console]::Out.WriteLine('{"schema":"edr.ci-service-snapshot.v1","present":false}');exit 0}
if($s.Count -ne 1){throw 'service_count'}
$s=$s[0];$expected=__EXPECTED__
$r=@{schema='edr.ci-service-snapshot.v1';present=$true;path_matches=([string]$s.PathName -ceq $expected);state=[string]$s.State;pid=[uint32]$s.ProcessId;checkpoint=$s.CheckPoint;wait_hint_ms=$s.WaitHint;win32_exit=$s.ExitCode;service_exit=$s.ServiceSpecificExitCode;start_mode=[string]$s.StartMode;account=[string]$s.StartName;birth_filetime=$null;exe_path_matches=$false;process_argv_matches=$false}
if($r.pid -gt 0){$p=[Diagnostics.Process]::GetProcessById([int]$r.pid);try{$null=$p.Handle;$r.birth_filetime=$p.StartTime.ToUniversalTime().ToFileTimeUtc().ToString();$r.exe_path_matches=($p.Path -ieq __EXE__);$cmd=@(Get-CimInstance Win32_Process -Filter ("ProcessId="+$r.pid) -Property CommandLine -OperationTimeoutSec 1 -ErrorAction Stop);$r.process_argv_matches=($cmd.Count -eq 1 -and [string]$cmd[0].CommandLine -ceq $expected)}finally{$p.Dispose()}}
[Console]::Out.WriteLine(($r|ConvertTo-Json -Compress));exit 0
'@
  $body=$body.Replace('__SERVICE__',$script:serviceName).Replace('__EXPECTED__',("'"+$script:binPath.Replace("'","''")+"'")).Replace('__EXE__',("'"+$script:agent.Replace("'","''")+"'"))
  $v=PowerShellWorker $Label $body 5000 4096
  $r=[IO.File]::ReadAllText($v.stdout,[Text.UTF8Encoding]::new($false,$true))|ConvertFrom-Json
  Check ($r.schema -ceq 'edr.ci-service-snapshot.v1' -and $r.present -is [bool]) 'service_snapshot_shape'
  if($r.present){Check ($r.path_matches -eq $true -and $r.state -cin @('Stopped','Start Pending','Stop Pending','Running','Continue Pending','Pause Pending','Paused','Unknown')) 'service_owner_or_state_mismatch'}else{Check $AllowAbsent 'service_disappeared'}
  return $r
}
function BindTarget($Snapshot){
  Check ($Snapshot.present -and $Snapshot.pid -gt 0 -and $Snapshot.exe_path_matches -eq $true -and $Snapshot.process_argv_matches -eq $true -and $Snapshot.birth_filetime -cmatch '^[0-9]{1,20}$') 'service_target_identity_incomplete'
  $p=[Diagnostics.Process]::GetProcessById([int]$Snapshot.pid);$null=$p.Handle
  Check (-not $p.HasExited -and $p.StartTime.ToUniversalTime().ToFileTimeUtc().ToString() -ceq $Snapshot.birth_filetime -and $p.Path -ieq $script:agent) 'service_target_generation_changed'
  return $p
}
function ProjectSampler($Child,$Receipt){
  $bytes=[IO.File]::ReadAllBytes($Child.stdout);Check ($bytes.Length -le 16384) 'sampler_projection_bound'
  $text=[Text.UTF8Encoding]::new($false,$true).GetString($bytes);$parts=$text.Split([char]10)
  $rows=New-Object Collections.ArrayList
  for($i=0;$i -lt $parts.Length-1;$i++){
    $r=$parts[$i]|ConvertFrom-Json -ErrorAction Stop
    Check ($r.schema -ceq 'edr.service-scm-sample.v1' -and ($r.index -is [int] -or $r.index -is [long]) -and $r.index -ge 0 -and $r.index -le 45 -and $r.state -cin @('Stopped','Start Pending','Stop Pending','Running','Continue Pending','Pause Pending','Paused','Unknown')) 'sampler_projection_shape'
    $v=@{index=$r.index;state=$r.state;elapsed_ms=$r.elapsed_ms;pid_birth_filetime=$null}
    foreach($key in @('checkpoint','wait_hint_ms','service_pid','win32_exit_code','service_exit_code')){
      $n=$r.$key
      if($null -eq $n){$v[$key]=$null}else{Check (($n -is [int] -or $n -is [long]) -and $n -ge 0 -and $n -le [uint32]::MaxValue) 'sampler_projection_number';$v[$key]=[uint32]$n}
    }
    if($null -ne $r.pid_birth_filetime){Check ($r.pid_birth_filetime -is [string] -and $r.pid_birth_filetime -cmatch '^[0-9]{1,20}$') 'sampler_projection_birth';$v.pid_birth_filetime=$r.pid_birth_filetime}
    Check (($r.elapsed_ms -is [int] -or $r.elapsed_ms -is [long]) -and $r.elapsed_ms -ge 0 -and $r.elapsed_ms -le 60000) 'sampler_projection_elapsed'
    $null=$rows.Add($v)
  }
  Check ($rows.Count -le 46) 'sampler_projection_count'
  $tail=[Text.Encoding]::UTF8.GetBytes($parts[$parts.Length-1]);$h=[Security.Cryptography.SHA256]::Create()
  try{$tailHash=([BitConverter]::ToString($h.ComputeHash($tail))).Replace('-','').ToLowerInvariant()}finally{$h.Dispose()}
  return @{schema='edr.ci-scm-numeric-projection.v1';rows=@($rows);complete_rows=$rows.Count;raw_stdout=$Receipt.stdout;trailing_bytes=$tail.Length;trailing_sha256=$tailHash;raw_tail_exported=$false;worker_natural_exit=(-not $Receipt.cancelled -and $Receipt.exit_code -eq 0);cancelled_after_primary_frozen=$Receipt.cancelled;scm_success_claimed=$false}
}

try {
  Check ($IsWindows -and $env:GITHUB_ACTIONS -ceq 'true' -and $env:RUNNER_ENVIRONMENT -ceq 'github-hosted' -and $env:GITHUB_SHA -ceq $SourceSha) 'fresh_source_bound_github_hosted_only'
  $script:result.preparation_stage_id=1
  Add-Type -AssemblyName System.Text.Json -ErrorAction Stop
  Add-Type -TypeDefinition @'
using System.IO;
using System.Threading.Tasks;
public static class CiServiceBoundedPump {
 public static async Task Copy(Stream source,Stream destination,int cap) {
  byte[] b=new byte[8192];int used=0,n;
  while((n=await source.ReadAsync(b,0,b.Length))!=0) {
   if(n>cap-used) throw new InvalidDataException("control_stream_cap");
   await destination.WriteAsync(b,0,n);used+=n;
  }
 }
}
'@
  $script:result.preparation_stage_id=2
  $id=[Security.Principal.WindowsIdentity]::GetCurrent();Check ([Security.Principal.WindowsPrincipal]::new($id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) 'administrator_required'
  $script:result.preparation_stage_id=3
  $temp=Get-Item -LiteralPath $env:RUNNER_TEMP -Force;Check ($temp.PSIsContainer -and ($temp.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'runner_temp_invalid'
  $candidateCase=Join-Path $temp.FullName ('edr-ci-service-'+$Token);Check (-not (Test-Path -LiteralPath $candidateCase)) 'fresh_case_required'
  $createdCase=New-Item -ItemType Directory -Path $candidateCase -ErrorAction Stop;$script:case=$createdCase.FullName;$script:root=$script:case
  # These are declared public inputs, not a claim that preparation or Agent
  # validation succeeded. Preserve them before ACL/owner import can fail.
  SaveNew 'intent.json' @{schema='edr.ci-isolated-service-intent.v1';source_sha=$SourceSha;token=$Token;service=$script:serviceName;agent_sha256=$AgentSha256;config_template_sha256=$ConfigTemplateSha256;qa_driver_sha256=$QADriverSha256;budget_profile='match512';stop_ms=45000;observe_max_ms=60000;overall_cooperative_ms=270000;cleanup_reserve_ms=30000;no_installer_or_updater=$true;no_release=$true;no_endpoint=$true}
  $script:result.intent_recorded=$true
  $script:result.preparation_stage_id=4
  SetDiagnosticCaseAcl $script:case
  $script:result.preparation_stage_id=5
  $script:winPS=RegularPath (Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe')
  $sc=RegularPath (Join-Path $env:WINDIR 'System32\sc.exe')
  $repo=[IO.Path]::GetFullPath($env:GITHUB_WORKSPACE)
  $driver=RegularPath (Join-Path $repo 'tests\cache-recovery\windows_cache_recovery_ci.ps1') 131072
  Check ((Hash $driver) -ceq $QADriverSha256) 'workflow_bound_qa_owner_changed'
  $script:result.preparation_stage_id=6
  $imports=@('Need','Regular','SHA','ReadOwnedBytes','ServiceObserverError','ServiceWorkerSource','ServiceSamplerSource','StopLogNative','StopLogInfo','StopLogOpen','StopLogConfig','StopLogTarget','NewStopLogContext','StopLogAnchor','ReadStopLogSlice','ObserveStopLog','CloseStopLogContext')
  $tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($driver,[ref]$tokens,[ref]$errors);Check ($errors.Count -eq 0) 'qa_owner_parse_failure'
  $script:result.preparation_stage_id=7
  foreach($name in $imports){$defs=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$true));Check ($defs.Count -eq 1) 'qa_function_inventory';if($name -ceq 'ReadStopLogSlice'){Invoke-Expression ($defs[0].Extent.Text.Replace('function ReadStopLogSlice(', 'function OriginalReadStopLogSlice('))}else{Invoke-Expression $defs[0].Extent.Text}}
  function ReadStopLogSlice($Context,[long]$ElapsedMs){SampleLimits;OriginalReadStopLogSlice $Context $ElapsedMs;SampleLimits}
  $script:result.preparation_stage_id=8
  $preflight=ServicePreflightSource
  $script:result.preflight=RunServicePreflight $preflight
  $script:install=Join-Path $script:case 'runtime';$script:agent=Join-Path $script:install 'FDSensor.exe';$script:configPath=Join-Path $script:install 'agent.toml'
  $stage=RegularPath (Join-Path $PSScriptRoot 'stage_ci_agent.py') 262144
  Check ((Hash $stage) -ceq $StageAdapterSha256) 'stage_adapter_hash_mismatch'
  Check ((RegularPath $AgentPath) -ieq (Join-Path $repo 'contract-build\tests\service-stop-agent\FDSensor.exe')) 'dedicated_ci_agent_target_required'
  $owner=RegularPath (Join-Path $repo 'scripts\stage_retention_native_tools.py') 65536
  $args=@('-B',$stage,'--owner',$owner,'--owner-sha256',$NativeStagerSha256,'--agent',(RegularPath $AgentPath),'--agent-sha256',$AgentSha256,'--dumpbin',(RegularPath $DumpbinPath),'--destination',$script:install,'--receipt',(Join-Path $script:case 'runtime-closure.json'),'--arch',$Architecture,'--native-manifest',(RegularPath $NativeToolManifestPath 1048576),'--native-manifest-sha256',$NativeToolManifestSha256,'--source',$SourceSha,'--run-id',$env:GITHUB_RUN_ID,'--run-attempt',$env:GITHUB_RUN_ATTEMPT)
  foreach($directory in $DllRoots){$args+=@('--dll-root',$directory)}
  $script:result.phase='dependency_stage'
  $null=RunOwned 'stage-runtime' (RegularPath $PythonPath) $args 55000 16384
  $closure=[IO.File]::ReadAllText((Join-Path $script:case 'runtime-closure.json'))|ConvertFrom-Json
  foreach($file in $closure.files){$path=RegularPath (Join-Path $script:install $file.name);Check ((Hash $path) -ceq $file.sha256) 'staged_runtime_changed';$lease=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);$null=$script:leases.Add($lease)}
  Check ($ConfigTemplateSha256 -ceq 'ac17ecd8c849e207888ad188fee997747d594aa871806ed039798cf39894a2a6') 'actual_692_701_template_required'
  $template=RegularPath $ConfigTemplatePath 131072;Check ((Hash $template) -ceq $ConfigTemplateSha256) 'config_template_identity'
  $text=[IO.File]::ReadAllText($template,[Text.UTF8Encoding]::new($false,$true))
  function SetScalar([string]$Section,[string]$Key,[string]$Value){
    $pattern='(?ms)^\['+[regex]::Escape($Section)+'\][^\r\n]*\r?\n(?<body>.*?)(?=^\[|\z)';$matches=[regex]::Matches($script:configText,$pattern)
    Check ($matches.Count -eq 1) 'fixture_section_not_unique';$m=$matches[0];$body=$m.Groups['body'].Value
    $keyPattern='(?m)^'+[regex]::Escape($Key)+'\s*=[^\r\n]*';Check ([regex]::Matches($body,$keyPattern).Count -eq 1) 'fixture_scalar_not_unique'
    $replacement=[regex]::Replace($body,$keyPattern,([Text.RegularExpressions.MatchEvaluator]{param($unused)$Key+' = '+$Value}))
    $script:configText=$script:configText.Substring(0,$m.Groups['body'].Index)+$replacement+$script:configText.Substring($m.Groups['body'].Index+$body.Length)
  }
  function TomlString([string]$v){Check ($v -notmatch '[\r\n\x00]') 'fixture_scalar_control';'"'+$v.Replace('\','\\').Replace('"','\"')+'"'}
  $script:configText=$text
  foreach($row in @(@('agent','endpoint_id',('ci-service-'+$Token)),@('agent','tenant_id','ci-isolated'),@('platform','rest_base_url','https://127.0.0.1:9/api/v1'),@('platform','proxy_mode','direct'),@('platform','rest_bearer_token',''),@('platform','relay_url',''),@('platform','proxy_url',''),@('offline','queue_db_path',(Join-Path $script:install 'queue\edr_queue.db')),@('offline','evidence_cache_path',(Join-Path $script:install 'evidence\cache.db')),@('logging','log_dir',(Join-Path $script:install 'logs')))) {SetScalar $row[0] $row[1] (TomlString $row[2])}
  Check ([regex]::Matches($script:configText,'(?m)^max_event_queue_size\s*=\s*8192\s*\r?$').Count -eq 1 -and [regex]::Matches($script:configText,'(?m)^evidence_cache_max_size_mb\s*=\s*512\s*\r?$').Count -eq 1 -and [regex]::Matches($script:configText,'(?m)^max_queue_size_mb\s*=\s*512\s*\r?$').Count -eq 1) 'original_budget_literals_required'
  $script:result.budget_sources=@{profile='match512';original_template_sha256=$ConfigTemplateSha256;collection_slots=8192;queue_mb=512;cache_mb=512;cli_budget_override=$false;historical_machine_environment='not_observed';this_runner_machine_edr_override_count=0;scm_effective_environment_directly_observed=$false}
  SetScalar 'command' 'allow_dangerous' 'false';SetScalar 'command' 'allow_lifecycle_maintenance' 'false';SetScalar 'forensic_auto' 'enabled' 'false'
  SetScalar 'ave' 'behavior_monitor_enabled' 'false';SetScalar 'attack_surface' 'enabled' 'false'
  Check (-not ($script:configText -cmatch '(?m)^\[policy_v2\]')) 'unexpected_template_policy_section'
  $script:configText+="`n[policy_v2]`n";foreach($name in @('credential','lateral','privilege','evasion','persistence','script','webshell','exfil','impact')){$script:configText+=($name+'_mode = "alert"'+"`n")}
  # Existing default pmfe_mode=0; no ML model or P0 IR is copied to runtime.
  Check (-not ($script:configText -cmatch '(?m)^\[detection\]')) 'unexpected_template_detection_section'
  $script:configText+="`n[detection]`npmfe_mode = 0`n"
  [IO.File]::WriteAllText($script:configPath,$script:configText,[Text.UTF8Encoding]::new($false));$script:configSha256=Hash $script:configPath
  $configLease=[IO.File]::Open($script:configPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);$null=$script:leases.Add($configLease)
  foreach($directory in @('logs','queue','evidence')){$null=New-Item -ItemType Directory -Path (Join-Path $script:install $directory)}
  # Same existing synthetic seed entry and 45s bound as cache-recovery QA.
  # This is a fresh seed and fresh ETW observation, never the historical events.
  $nativeManifest=RegularPath $NativeToolManifestPath 1048576
  Check ((Hash $nativeManifest) -ceq $NativeToolManifestSha256) 'seed_manifest_changed'
  $nativeMetadata=[IO.File]::ReadAllText($nativeManifest)|ConvertFrom-Json
  $toolRoot=Split-Path -Parent $nativeManifest
  foreach($file in $nativeMetadata.files){
    $path=RegularPath (Join-Path $toolRoot $file.name)
    Check ((Hash $path) -ceq $file.sha256) 'seed_tool_closure_changed'
    $null=$script:leases.Add([IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read))
  }
  $script:seedTemp=Join-Path $script:case 'seed-temp';$null=New-Item -ItemType Directory -Path $script:seedTemp
  $seedTool=RegularPath (Join-Path $toolRoot 'test_local_evidence_cache_candidate.exe')
  $script:result.phase='synthetic_seed'
  $seed=RunOwned 'seed' $seedTool @('--alert-parent-soak','2') 45000 65536
  Check ((Get-Item -LiteralPath $seed.stderr).Length -eq 0) 'seed_stderr_unclassified'
  $seedText=[IO.File]::ReadAllText($seed.stdout,[Text.UTF8Encoding]::new($false,$true))
  $begin=[regex]::Matches($seedText,'(?m)^parent_soak_begin .*native_machine=(\d+) process_machine=(\d+) io_available=1\r?$')
  $end=[regex]::Matches($seedText,'(?m)^parent_soak_end label=short_smoke .*requested_seconds=2 .*partial=0 .*db_preserved=1 directory=(\S+)\r?$')
  Check ($begin.Count -eq 1 -and $end.Count -eq 1 -and [int]$begin[0].Groups[1].Value -eq $(if($Architecture -ceq 'arm64'){43620}else{34404}) -and $begin[0].Groups[2].Value -ceq '0') 'native_seed_receipt'
  $sourceDir=[IO.Path]::GetFullPath($end[0].Groups[1].Value)
  Check ($sourceDir.StartsWith($script:seedTemp+'\',[StringComparison]::OrdinalIgnoreCase)) 'synthetic_seed_directory_escape'
  $seedCopies=New-Object Collections.ArrayList
  foreach($suffix in @('','-wal','-shm')){
    $source=Join-Path $sourceDir ('cache.db'+$suffix)
    if(Test-Path -LiteralPath $source){
      $source=RegularPath $source;$before=Get-Item -LiteralPath $source
      $src=[IO.File]::Open($source,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
      $destination=Join-Path $script:install ('evidence\cache.db'+$suffix)
      try{
        $dst=[IO.File]::Open($destination,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
        try{$src.CopyTo($dst,1048576);$dst.Flush($true)}finally{$dst.Dispose()}
        $digest=Hash $source;Check ((Hash $destination) -ceq $digest) 'synthetic_copy_hash'
        $after=Get-Item -LiteralPath $source;Check ($before.Length -eq $after.Length -and $before.LastWriteTimeUtc -eq $after.LastWriteTimeUtc) 'synthetic_seed_source_changed'
        $null=$seedCopies.Add(@{name=('cache.db'+$suffix);bytes=$after.Length;sha256=$digest})
      }finally{$src.Dispose()}
    }else{Check ($suffix -cne '') 'synthetic_seed_main_missing'}
  }
  $script:result.fixture_input=@{kind='fresh_same_entry_synthetic_seed';argv=@('--alert-parent-soak','2');seed_manifest_sha256=$NativeToolManifestSha256;files=@($seedCopies);historical_events_replayed=$false;db_or_event_body_exported=$false}
  SaveNew 'seed-copy-receipt.json' $script:result.fixture_input
  $script:result.phase='config_test'
  $null=RunOwned 'config-test' $script:agent @('--config',$script:configPath,'--config-test') 5000 4096
  $script:binPath='"'+$script:agent+'" --service --service-name "'+$script:serviceName+'" --config "'+$script:configPath+'"'
  $script:result.phase='offline_rule';$script:firewallIntent=$true
  $fw=@'
if(Get-NetFirewallRule -Name '__RULE__' -ErrorAction SilentlyContinue){throw 'firewall_name_exists'}
New-NetFirewallRule -Name '__RULE__' -DisplayName '__RULE__' -Direction Outbound -Action Block -Program __EXE__ -Profile Any -Enabled True -ErrorAction Stop|Out-Null
$r=@(Get-NetFirewallRule -PolicyStore ActiveStore -Name '__RULE__' -ErrorAction Stop)
if($r.Count -ne 1 -or [string]$r[0].Action -ne 'Block' -or [string]$r[0].Direction -ne 'Outbound' -or [string]$r[0].Enabled -ne 'True' -or [string](($r[0]|Get-NetFirewallApplicationFilter).Program) -ine __EXE__){throw 'offline_rule_readback'}
exit 0
'@
  $null=PowerShellWorker 'offline-rule' ($fw.Replace('__RULE__',$script:ruleName).Replace('__EXE__',("'"+$script:agent.Replace("'","''")+"'"))) 10000 4096
  Check ((Remaining) -ge 175000) 'insufficient_budget_before_service_create'
  $script:result.phase='service_create';$script:createIntent=$true
  $null=RunOwned 'sc-create' $sc @('create',$script:serviceName,'binPath=',$script:binPath,'start=','demand','obj=','LocalSystem') 5000 4096
  $s=Snapshot 'created';Check ($s.state -ceq 'Stopped' -and $s.start_mode -ceq 'Manual' -and $s.account -ceq 'LocalSystem') 'created_service_shape'
  # No failure/restart configuration is installed. No broad installer is run.
  $script:result.phase='service_start'
  $null=RunOwned 'sc-start' $sc @('start',$script:serviceName) 45000 4096
  $startup=[Diagnostics.Stopwatch]::StartNew();$index=0
  do{$s=Snapshot ('startup-'+$index);$index++;if($s.state -ceq 'Running'){break};Check ($s.state -cne 'Stopped') 'agent_loader_or_startup_failed';Start-Sleep -Milliseconds 500}while($startup.ElapsedMilliseconds -lt 30000)
  Check ($s.state -ceq 'Running') 'service_startup_not_running'
  $script:target=BindTarget $s
  $script:result.target=@{pid=$s.pid;birth_filetime=$s.birth_filetime;exe_sha256=$AgentSha256;config_sha256=$script:configSha256;template_sha256=$ConfigTemplateSha256;service_config_argv_verified=$true;fixture_config_binding_verified=$true;runtime_mode='service'}
  $native=@{};foreach($k in $script:result.target.Keys){$native[$k]=$script:result.target[$k]}
  $script:context=NewStopLogContext $native $driver
  Check ($script:context.ready) 'pre_stop_log_binding_unknown'
  $script:result.phase='running_fresh_etw_10s';for($idle=0;$idle -lt 10;$idle++){Start-Sleep -Seconds 1;SampleLimits}
  Check (-not $script:target.HasExited) 'service_exited_before_stop'
  Check ((Remaining) -ge 105000) 'insufficient_budget_before_full_stop_observation'
  $samplerScript=WritePublic 'stop-sampler.ps1' ((ServiceSamplerSource).Replace('FDSecurityAgent',$script:serviceName))
  $sampler=StartOwned 'stop-sampler' $script:winPS @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',$samplerScript)
  $script:result.phase='stop_45s'
  $stopSource=(ServiceWorkerSource 'Stop').Replace('FDSecurityAgent',$script:serviceName)
  $stopScript=WritePublic 'stop-control.ps1' $stopSource
  $stop=StartOwned 'stop-control' $script:winPS @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',$stopScript)
  $stopClock=[Diagnostics.Stopwatch]::StartNew();$returned=WaitOwned $stop 45000 -KeepOnTimeout
  $frozen=[ordered]@{schema='edr.ci-service-stop-frozen.v1';worker_pid=$stop.pid;worker_birth_filetime=$stop.birth;elapsed_ms=$stopClock.ElapsedMilliseconds;wait_ms=45000;status=if($returned -and $stop.exit_code -eq 0){'returned_zero'}elseif($returned){'returned_nonzero'}else{'timed_out_unknown_service_state'};terminal_known=$stop.terminal_known;exit_known=$stop.exit_known;exit_code=$stop.exit_code;observation_can_change_result=$false}
  SaveNew 'stop-result-frozen.json' $frozen;$script:result.stop_result=$frozen
  if(-not $returned){$stop.cancelled=$true;$stop.process.Kill();Check ($stop.process.WaitForExit(2000)) 'stop_worker_cleanup_unknown';$null=WaitOwned $stop 1}
  $script:result.stop_worker=FinishOwned $stop 4096
  if(-not (WaitOwned $sampler 1 -KeepOnTimeout)){$sampler.cancelled=$true;$sampler.process.Kill();Check ($sampler.process.WaitForExit(2000)) 'sampler_cleanup_unknown';$null=WaitOwned $sampler 1}
  $script:result.scm_sampler=FinishOwned $sampler 16384
  $selected=ProjectSampler $sampler $script:result.scm_sampler
  SaveNew 'scm-sampler-selected.json' $selected;$script:result.scm_selected=$selected
  if($frozen.status -cne 'returned_zero'){$script:result.phase='post_failure_observation';ObserveStopLog $script:context 60000}
  else{ReadStopLogSlice $script:context 0}
  $script:result.shutdown_log_observation=$script:context.diagnostic
  $script:result.status=if($frozen.status -ceq 'returned_zero'){'stop_returned_zero_pending_cleanup_verification'}else{'stop_failed_observation_only'}
} catch {
  $script:primary=$_.Exception.GetType().FullName
  $script:result.primary_failure=ProjectPrimaryFailure $_
  $script:result.status='failed_or_unknown'
} finally {
  # Independent cleanup never rewrites stop-result-frozen.json or promotes a
  # failed stop. SCM children are not descendants of this PowerShell process.
  if($null -ne $script:case){
    $script:cleanupMode=$true;$script:cleanupDeadline=[Math]::Min(270000,$script:experimentClock.ElapsedMilliseconds+30000)
    $cleanup=[ordered]@{scm_stopped_zero_before_delete=$false;target_terminal_known=$false;target_exit_code=$null;exact_target_kill_attempted=$false;service_absent_confirmed=$false;offline_rule_removed=$false;unknown_or_errors=@();artifact_inputs_retained=$true}
    if($script:createIntent){
      try{
        $s=Snapshot 'cleanup-snapshot' -AllowAbsent
        if($s.present){
          if($null -eq $script:target -and $s.pid -gt 0){$script:target=BindTarget $s}
          $cleanup.scm_stopped_zero_before_delete=($s.state -ceq 'Stopped' -and $s.pid -eq 0 -and $null -ne $s.win32_exit -and $null -ne $s.service_exit -and $s.win32_exit -eq 0 -and $s.service_exit -eq 0)
          if($null -ne $script:target){
            if(-not $script:target.HasExited){$null=$script:target.WaitForExit(1000)}
            if(-not $script:target.HasExited){$cleanup.exact_target_kill_attempted=$true;$script:target.Kill();Check ($script:target.WaitForExit(5000)) 'exact_service_process_cleanup_unknown'}
            $code=$script:target.ExitCode;Check ($null -ne $code -and $code -is [int]) 'exact_service_exit_unknown';$cleanup.target_terminal_known=$true;$cleanup.target_exit_code=$code
          }else{Check ($s.state -ceq 'Stopped' -and $s.pid -eq 0) 'service_owner_terminal_unknown'}
          $null=RunOwned 'sc-delete' $sc @('delete',$script:serviceName) 5000 4096
          $s=Snapshot 'cleanup-absent' -AllowAbsent;Check (-not $s.present) 'owned_service_deletion_unconfirmed'
        }
        $cleanup.service_absent_confirmed=$true
      }catch{$cleanup.unknown_or_errors+=,@{phase='service_cleanup';exception_type=$_.Exception.GetType().FullName}}
      finally{
        # A failed/absent SCM query does not discard the already held exact
        # process identity. Still attempt bounded cleanup of that object.
        if($null -ne $script:target -and -not $cleanup.target_terminal_known){
          try{
            if(-not $script:target.HasExited){$cleanup.exact_target_kill_attempted=$true;$script:target.Kill();Check ($script:target.WaitForExit(5000)) 'exact_service_process_cleanup_unknown'}
            $code=$script:target.ExitCode;Check ($null -ne $code -and $code -is [int]) 'exact_service_exit_unknown'
            $cleanup.target_terminal_known=$true;$cleanup.target_exit_code=$code
          }catch{$cleanup.unknown_or_errors+=,@{phase='held_target_cleanup';exception_type=$_.Exception.GetType().FullName}}
        }
      }
    }else{$cleanup.service_absent_confirmed=$true}
    if($script:firewallIntent -and $cleanup.service_absent_confirmed -and ($null -eq $script:target -or $cleanup.target_terminal_known)){
      try{
        $fwRemove="`$r=@(Get-NetFirewallRule -Name '$($script:ruleName)' -ErrorAction SilentlyContinue);if(`$r.Count -gt 1){throw 'rule_count'};if(`$r.Count -eq 1){if([string]((`$r[0]|Get-NetFirewallApplicationFilter).Program) -ine '$($script:agent.Replace("'","''"))'){throw 'rule_owner'};`$r[0]|Remove-NetFirewallRule -ErrorAction Stop};if(Get-NetFirewallRule -Name '$($script:ruleName)' -ErrorAction SilentlyContinue){throw 'rule_still_present'};exit 0"
        $null=PowerShellWorker 'remove-offline-rule' $fwRemove 8000 4096;$cleanup.offline_rule_removed=$true
      }catch{$cleanup.unknown_or_errors+=,@{phase='firewall_cleanup';exception_type=$_.Exception.GetType().FullName}}
    }elseif(-not $script:firewallIntent){$cleanup.offline_rule_removed=$true}
    foreach($item in $script:cleanupErrors){$cleanup.unknown_or_errors+=,$item}
    foreach($v in $script:ownedChildren){
      try{if(-not $v.process.HasExited){$v.cancelled=$true;$v.process.Kill();Check ($v.process.WaitForExit(2000)) 'control_worker_still_live'}}catch{$cleanup.unknown_or_errors+=,@{phase='control_worker_cleanup';exception_type=$_.Exception.GetType().FullName}}
      foreach($f in @($v.out_file,$v.err_file)){try{$f.Dispose()}catch{$cleanup.unknown_or_errors+=,@{phase='stream_close';exception_type=$_.Exception.GetType().FullName}}};$v.process.Dispose()
    }
    if($null -ne $script:context){try{CloseStopLogContext $script:context;$script:result.shutdown_log_observation=$script:context.diagnostic}catch{$cleanup.unknown_or_errors+=,@{phase='log_context_close';exception_type=$_.Exception.GetType().FullName}}}
    foreach($lease in $script:leases){try{$lease.Dispose()}catch{$cleanup.unknown_or_errors+=,@{phase='runtime_lease_close';exception_type=$_.Exception.GetType().FullName}}}
    if($null -ne $script:target){$script:target.Dispose()}
    $script:result.cleanup=$cleanup;$script:result.elapsed_ms=$script:experimentClock.ElapsedMilliseconds
    $script:result.within_cooperative_budget=($script:experimentClock.ElapsedMilliseconds -le 270000)
    $ok=($null -eq $script:primary -and $null -ne $script:result.stop_result -and $script:result.stop_result.status -ceq 'returned_zero' -and $cleanup.scm_stopped_zero_before_delete -and $cleanup.target_terminal_known -and $cleanup.target_exit_code -eq 0 -and -not $cleanup.exact_target_kill_attempted -and $cleanup.service_absent_confirmed -and $cleanup.offline_rule_removed -and $cleanup.unknown_or_errors.Count -eq 0 -and $script:result.within_cooperative_budget)
    $script:result.diagnostic_accepted=$ok
    try{SaveNew 'result.json' $script:result}catch{[Console]::Error.WriteLine('isolated_service_receipt_write_failed');$ok=$false}
    WriteDiagnosticSummary $ok
    if($ok){exit 0}else{exit 2}
  }else{WriteDiagnosticSummary $false}
}
exit 2
