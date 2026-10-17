#Requires -Version 5.1
# PRIVATE finite synthetic PS5.1 children only. No updater main, SCM operation,
# Agent, cache, install, network, user/machine environment or timezone changes.
[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$DriverSource,
  [Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9]{64}$')][string]$DriverSha256,
  [switch]$CacheOwnedHandleForTest,
  [switch]$RequireCounterfactualFailureForTest
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if ($env:OS -ne 'Windows_NT') {throw 'windows_required_not_native_tested_on_host'}
$source=Get-Item -LiteralPath $DriverSource -Force
if ($source.PSIsContainer -or ($source.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $source.Length -gt 65536) {throw 'driver_regular_bound'}
function FileSHA([string]$Path) {
  $sha=[Security.Cryptography.SHA256]::Create()
  try {return ([BitConverter]::ToString($sha.ComputeHash([IO.File]::ReadAllBytes($Path)))).Replace('-','').ToLowerInvariant()} finally {$sha.Dispose()}
}
if ((FileSHA $source.FullName) -cne $DriverSha256) {throw 'driver_source_pin'}
$tokens=$null;$parseErrors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($source.FullName,[ref]$tokens,[ref]$parseErrors)
if (@($parseErrors).Count -or (FileSHA $source.FullName) -cne $DriverSha256) {throw 'driver_parse_or_changed'}
$wanted=@('WaitProcess','StartWindowsPowerShellChild')
$functions=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -in $wanted},$false))
if ($functions.Count -ne 2) {throw 'source_function_inventory'}
foreach($f in $functions) {Invoke-Expression $f.Extent.Text}
# Load the parent's diagnostic cmdlets before changing only its process-level
# PSModulePath for the controlled CreateProcess inheritance counterfactual.
$null=Get-Command Start-Process,Get-Service,ConvertTo-Json,ConvertFrom-Json -CommandType Cmdlet -ErrorAction Stop
# Desktop 5.1 may export Get-FileHash as an inbox Utility function. This is
# command discovery, not a replacement implementation or a module-path fallback.
$parentHashCommand=Get-Command Get-FileHash -CommandType Cmdlet,Function -ErrorAction Stop
if ($parentHashCommand.ModuleName -cne 'Microsoft.PowerShell.Utility') {throw 'file_hash_command_module'}
if (Test-Path Function:\Start-Process) {throw 'unexpected_parent_start_function'}
$winps=Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
$winpsFile=Get-Item -LiteralPath $winps -Force
if ($winpsFile.PSIsContainer -or ($winpsFile.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $winpsFile.Length -gt 16777216) {throw 'system_windows_powershell_required'}
$original=[Environment]::GetEnvironmentVariable('PSModulePath',[EnvironmentVariableTarget]::Process)
$dir=Join-Path ([IO.Path]::GetTempPath()) ('edr-ps51-env-private-'+[Guid]::NewGuid().ToString('N'))
if ([IO.Directory]::Exists($dir) -or [IO.File]::Exists($dir)) {throw 'fixture_already_exists'}
$null=[IO.Directory]::CreateDirectory($dir)
$file=Join-Path $dir 'public-synthetic.bin'
[IO.File]::WriteAllBytes($file,[byte[]](0..31))
$expected=FileSHA $file
$worker=Join-Path $dir 'probe.ps1'
$body=@'
$ErrorActionPreference='Stop'
$hashAvailable=$false;$hashRead=$false;$hashLookupCause='none';$hashType='';$hashModule='';$serviceAvailable=$false;$value=''
try {$hashCommand=Get-Command Get-FileHash -CommandType Cmdlet,Function -ErrorAction Stop;if($hashCommand.ModuleName -cne 'Microsoft.PowerShell.Utility'){throw 'file_hash_command_module'};$hashType=[string]$hashCommand.CommandType;$hashModule=$hashCommand.ModuleName;$hashAvailable=$true} catch {$hashLookupCause=if($_.Exception -is [Management.Automation.CommandNotFoundException]){'command_not_found'}else{'lookup_failed'}}
if($hashAvailable){try {$value=(& $hashCommand -LiteralPath '__FILE__' -Algorithm SHA256).Hash.ToLowerInvariant();$hashRead=$true} catch {$hashRead=$false}}
try {$null=Get-Command Get-Service -CommandType Cmdlet -ErrorAction Stop;$serviceAvailable=$true} catch {$serviceAvailable=$false}
$ok=$hashAvailable -and $hashRead -and $serviceAvailable -and $value -ceq '__EXPECTED__'
[Console]::Out.WriteLine('{"schema":"edr.ps51-public-file-probe.v1","child_pid":'+$PID+',"ps_major":'+$PSVersionTable.PSVersion.Major+',"hash_available":'+$hashAvailable.ToString().ToLowerInvariant()+',"hash_read_succeeded":'+$hashRead.ToString().ToLowerInvariant()+',"hash_lookup_cause":"'+$hashLookupCause+'","hash_command_type":"'+$hashType+'","hash_module":"'+$hashModule+'","service_command_discoverable":'+$serviceAvailable.ToString().ToLowerInvariant()+',"sha256":"'+$value+'"}')
if ($ok) {exit 0} else {exit 71}
'@
$body=$body.Replace('__FILE__',$file.Replace("'","''")).Replace('__EXPECTED__',$expected)
[IO.File]::WriteAllText($worker,$body,[Text.UTF8Encoding]::new($false))
$rows=New-Object Collections.ArrayList

function ReadSmall([string]$Path) {
  $f=Get-Item -LiteralPath $Path -Force
  if ($f.PSIsContainer -or ($f.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $f.Length -gt 4096) {throw 'probe_log_bound'}
  $s=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
  try {
    $b=New-Object byte[] 4097;$count=0
    while($count -lt $b.Length) {$n=$s.Read($b,$count,$b.Length-$count);if($n -eq 0){break};$count+=$n}
    if ($count -ne $f.Length -or $count -gt 4096) {throw 'probe_log_changed'}
    return [Text.UTF8Encoding]::new($false,$true).GetString($b,0,$count)
  } finally {$s.Dispose()}
}

function Probe([string]$Label,[bool]$Isolated,[string]$ModulePath,[string]$Script=$worker,[int]$ExpectedExit=-1) {
  $out=Join-Path $dir ($Label+'.out');$err=Join-Path $dir ($Label+'.err');$p=$null
  $clock=[Diagnostics.Stopwatch]::StartNew()
  try {
    [Environment]::SetEnvironmentVariable('PSModulePath',$ModulePath,[EnvironmentVariableTarget]::Process)
    $inherited=[Environment]::GetEnvironmentVariable('PSModulePath',[EnvironmentVariableTarget]::Process)
    try {
      if ($Isolated) {$p=StartWindowsPowerShellChild $Script $out $err}
      else {$p=Start-Process -FilePath $winps -ArgumentList @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',('"'+$Script+'"')) -PassThru -RedirectStandardOutput $out -RedirectStandardError $err}
      if ([Environment]::GetEnvironmentVariable('PSModulePath',[EnvironmentVariableTarget]::Process) -cne $inherited) {throw 'launch_changed_parent_modulepath'}
    } finally {[Environment]::SetEnvironmentVariable('PSModulePath',$original,[EnvironmentVariableTarget]::Process)}
    # Test-only .NET Framework observation fix, never part of driver WaitProcess.
    if($CacheOwnedHandleForTest){$ownedHandle=$p.Handle;if($ownedHandle -eq [IntPtr]::Zero){throw 'test_handle_cache_failed'}}
    $code=WaitProcess $p 5 'probe_child_terminal_unknown_no_retry'
    $stdout=ReadSmall $out;$stderr=ReadSmall $err
    if ($stderr.Length) {throw 'probe_stderr_nonempty'}
    $data=$stdout | ConvertFrom-Json -ErrorAction Stop
    if ($data.schema -cne 'edr.ps51-public-file-probe.v1' -or $data.child_pid -ne $p.Id -or $data.ps_major -ne 5) {throw 'actual_ps51_child_identity'}
    $good=$data.hash_available -eq $true -and $data.hash_read_succeeded -eq $true -and $data.service_command_discoverable -eq $true -and $data.sha256 -ceq $expected
    if ($ExpectedExit -ge 0 -and $code -ne $ExpectedExit) {throw 'actual_child_exit_mismatch'}
    if ($Isolated -and -not $good) {throw 'isolated_child_missing_builtin_cmdlet'}
    if (-not $Isolated -and $code -notin @(0,71)) {throw 'unexpected_old_probe_exit'}
    $null=$rows.Add(@{case=$Label;isolated=$Isolated;actual_pid=$p.Id;worker_pid=$data.child_pid;ps_major=$data.ps_major;exit_code=$code;hash_available=$data.hash_available;hash_read_succeeded=$data.hash_read_succeeded;hash_lookup_cause=$data.hash_lookup_cause;hash_command_type=$data.hash_command_type;hash_module=$data.hash_module;service_command_discoverable=$data.service_command_discoverable;hash_match=($data.sha256 -ceq $expected);elapsed_ms=$clock.ElapsedMilliseconds;parent_process_environment_restored=$true;requested_empty_modulepath=($ModulePath -ceq '');actual_inherited_key_present=($null -ne $inherited);native_child_executed=$true})
  } finally {
    [Environment]::SetEnvironmentVariable('PSModulePath',$original,[EnvironmentVariableTarget]::Process)
    if ($null -ne $p) {
      if (-not $p.HasExited) {$p.Kill();if(-not $p.WaitForExit(10000)){throw 'probe_cleanup_unknown'}}
      $p.Dispose()
    }
  }
}

try {
  $foreign=Join-Path $dir 'foreign-powershell-modules';$null=[IO.Directory]::CreateDirectory($foreign)
  # Record the direct parent launch as a diagnostic. The formal driver requires
  # Core; this library harness also supports Desktop with test-only Handle caching.
  Probe 'original_parent_direct' $false $original $worker $(if($PSVersionTable.PSVersion.Major -eq 5){0}else{-1})
  Probe 'isolated_parent_direct' $true $original $worker 0
  Probe 'old_foreign' $false $foreign
  Probe 'new_foreign' $true $foreign $worker 0
  # Some PS5.1 startups normalize empty to absent and repair it themselves.
  # Preserve that real outcome rather than manufacturing an old empty failure.
  Probe 'old_empty' $false ''
  Probe 'new_empty' $true '' $worker 0
  $failedWorker=Join-Path $dir 'known-exit-seven.ps1'
  [IO.File]::WriteAllText($failedWorker,$body.Replace('if ($ok) {exit 0} else {exit 71}','exit 7'),[Text.UTF8Encoding]::new($false))
  Probe 'new_known_exit_seven' $true $foreign $failedWorker 7

  # Deterministic launch fault injection tests finally-restoration only.
  # It is not reported as a real CreateProcess or native execution.
  [Environment]::SetEnvironmentVariable('PSModulePath',$foreign,[EnvironmentVariableTarget]::Process)
  $prior=[Environment]::GetEnvironmentVariable('PSModulePath',[EnvironmentVariableTarget]::Process)
  $injected=$false
  function Start-Process {throw [InvalidOperationException]::new('synthetic_launch_failure')}
  try {
    try {$null=StartWindowsPowerShellChild $worker (Join-Path $dir 'fault.out') (Join-Path $dir 'fault.err');throw 'missing_launch_fault'}
    catch {
      if ($_.Exception.Message -cne 'synthetic_launch_failure') {throw 'unexpected_launch_fault'}
      if ([Environment]::GetEnvironmentVariable('PSModulePath',[EnvironmentVariableTarget]::Process) -cne $prior) {throw 'helper_launch_fault_did_not_restore_parent'}
      $injected=$true
    }
  } finally {Remove-Item Function:\Start-Process;[Environment]::SetEnvironmentVariable('PSModulePath',$original,[EnvironmentVariableTarget]::Process)}
  if (-not $injected -or [Environment]::GetEnvironmentVariable('PSModulePath',[EnvironmentVariableTarget]::Process) -cne $original) {throw 'launch_fault_did_not_restore_parent'}
  $null=$rows.Add(@{case='injected_launch_failure_restore';injected=$true;native_child_executed=$false;parent_process_environment_restored=$true})

  # Exercise the unchanged source-owned 1-second WaitProcess failure and its
  # exact owned child cleanup. This is not the Transition's 900-second loop.
  $slow=Join-Path $dir 'fixed-sleep.ps1';[IO.File]::WriteAllText($slow,'[Threading.Thread]::Sleep(5000);exit 0',[Text.UTF8Encoding]::new($false))
  $p=StartWindowsPowerShellChild $slow (Join-Path $dir 'slow.out') (Join-Path $dir 'slow.err')
  $clock=[Diagnostics.Stopwatch]::StartNew();$timed=$false
  try {
    if($CacheOwnedHandleForTest){$ownedHandle=$p.Handle;if($ownedHandle -eq [IntPtr]::Zero){throw 'test_handle_cache_failed'}}
    try {$null=WaitProcess $p 1 'synthetic_one_second_timeout';throw 'expected_wait_failure_missing'}
    catch {if ($_.Exception.Message -cne 'synthetic_one_second_timeout') {throw 'unexpected_wait_failure'};$timed=$true}
    $p.Refresh()
    if (-not $timed -or -not $p.HasExited -or $clock.ElapsedMilliseconds -lt 900) {throw 'real_one_second_wait_cleanup'}
    $null=$rows.Add(@{case='real_one_second_wait';actual_pid=$p.Id;native_child_executed=$true;expected_timeout_observed=$true;owned_child_exited=$p.HasExited;elapsed_ms=$clock.ElapsedMilliseconds;requested_wait_seconds=1;transition_loop_executed=$false})
  } finally {if(-not $p.HasExited){$p.Kill();if(-not $p.WaitForExit(10000)){throw 'slow_cleanup_unknown'}};$p.Dispose()}

  if ([Environment]::GetEnvironmentVariable('PSModulePath',[EnvironmentVariableTarget]::Process) -cne $original) {throw 'final_parent_environment_changed'}
  $old=@($rows | Where-Object {$_.case -eq 'old_foreign'})[0]
  $new=@($rows | Where-Object {$_.case -eq 'new_foreign'})[0]
  $direct=@($rows | Where-Object {$_.case -eq 'original_parent_direct'})[0]
  $isolatedDirect=@($rows | Where-Object {$_.case -eq 'isolated_parent_direct'})[0]
  $parentDefaultProven=$direct.exit_code -eq 71 -and -not $direct.hash_available -and $direct.hash_lookup_cause -ceq 'command_not_found' -and $isolatedDirect.exit_code -eq 0 -and $isolatedDirect.hash_match
  $proven=$old.exit_code -eq 71 -and -not $old.hash_available -and $old.hash_lookup_cause -ceq 'command_not_found' -and $new.exit_code -eq 0 -and $new.hash_match
  $hostFix=$PSVersionTable.PSVersion.Major -eq 5 -and $direct.exit_code -eq 0 -and $direct.hash_match -and $direct.service_command_discoverable
  Write-Output ((@{schema='edr.recovery-ps51-child-environment-tests.v1';status='checks_completed';driver_sha256=$DriverSha256;system_powershell_sha256=(FileSHA $winps);parent_ps_major=$PSVersionTable.PSVersion.Major;parent_ps_edition=$PSVersionTable.PSEdition;owned_handle_cache_test_only=[bool]$CacheOwnedHandleForTest;counterfactual_failure_required_for_test=[bool]$RequireCounterfactualFailureForTest;parent_file_hash_command_type=([string]$parentHashCommand.CommandType);parent_file_hash_module=$parentHashCommand.ModuleName;checks=$rows.Count;environment_mechanism_reproduced=$proven;parent_default_modulepath_counterfactual_reproduced=$parentDefaultProven;matching_host_original_launch_proven=$hostFix;parent_process_environment_restored=$true;user_or_machine_environment_changed=$false;updater_main_executed=$false;scm_operations=0;rows=@($rows)}) | ConvertTo-Json -Depth 8 -Compress)
  # The current-helper invariants above must all pass on every supported host.
  # Old-host failure is diagnostic: an OS may repair an inherited module path.
  if ($rows.Count -ne 9) {exit 3}
  if ($RequireCounterfactualFailureForTest -and -not $proven) {exit 3}
} finally {
  [Environment]::SetEnvironmentVariable('PSModulePath',$original,[EnvironmentVariableTarget]::Process)
  # Preserve this bounded synthetic fixture's raw logs on success and failure.
}
# Set the normal call-operator consumer result; terminating failures never reach here.
exit 0
