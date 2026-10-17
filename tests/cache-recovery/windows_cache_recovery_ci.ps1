#Requires -Version 7.0
#Requires -PSEdition Core
<#!
Disposable GitHub-hosted Windows only. Requires caller-verified immutable
Headless stages, a REAL backend-built protocol5 installer package and passed
same-source native tools. No download, signing, transport adapter or DB writer.
The library fixture prepares the new schema BEFORE either installed runtime.
This verifies a local full-installer rollback/repair subset, not remote delivery.
!#>
[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$InputJson,
  [Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9]{64}$')][string]$InputSha256
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
function Need($Condition,[string]$Cause) { if (-not $Condition) { throw $Cause } }
function Regular([string]$Path,[UInt64]$Cap) {
  $p=Get-Item -LiteralPath $Path -Force -ErrorAction Stop
  Need (-not $p.PSIsContainer -and ($p.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0 -and $p.Length -le $Cap) 'regular_bounded_file_required'
  return $p.FullName
}
function SHA([string]$Path) { return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
function ReadBounded([string]$Path,[int]$Cap) {
  $path=Regular $Path $Cap;$before=Get-Item -LiteralPath $path -Force
  $s=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
  try {
    $buffer=New-Object byte[] ($before.Length+1);$count=0
    while($count -lt $buffer.Length) {$n=$s.Read($buffer,$count,$buffer.Length-$count);if($n -eq 0){break};$count+=$n}
  } finally {$s.Dispose()}
  $after=Get-Item -LiteralPath $path -Force
  Need ($count -eq $before.Length -and $before.Length -eq $after.Length -and $before.LastWriteTimeUtc -eq $after.LastWriteTimeUtc -and ($after.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'input_changed_during_bounded_read'
  return [Text.UTF8Encoding]::new($false,$true).GetString($buffer,0,$count)
}
# QA only: strict byte snapshot is shared by live journal polling and final copy.
# It does not change ReadBounded/PinnedJson's immutable-input/terminal contract.
function ReadOwnedBytes([string]$Path,[int]$Cap=1048576) {
  Need ($Cap -gt 0 -and $Cap -le 1048576) 'owned_read_cap_invalid'
  $path=[IO.Path]::GetFullPath($Path);$before=Get-Item -LiteralPath $path -Force -ErrorAction Stop
  Need (-not $before.PSIsContainer -and ($before.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'owned_read_regular_cap_required'
  $beforeLength=[long]$before.Length
  Need ($beforeLength -ge 0 -and $beforeLength -le $Cap) 'owned_read_regular_cap_required'
  $s=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
  try {
    Need ($s.Length -le $Cap) 'owned_read_cap_exceeded'
    $buffer=New-Object byte[] ([int]($beforeLength+1));$count=0
    while($count -lt $buffer.Length){$n=$s.Read($buffer,$count,$buffer.Length-$count);if($n -eq 0){break};$count+=$n}
    Need ($s.Length -le $Cap) 'owned_read_cap_exceeded'
    $streamLength=$s.Length
  } finally {$s.Dispose()}
  # Separate the hard shape/cap check from a legitimate replacement transient.
  $after=Get-Item -LiteralPath $path -Force -ErrorAction Stop
  Need (-not $after.PSIsContainer -and ($after.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'owned_read_regular_cap_required'
  $afterLength=[long]$after.Length
  Need ($afterLength -ge 0 -and $afterLength -le $Cap) 'owned_read_regular_cap_required'
  if($count -ne $beforeLength -or $streamLength -ne $beforeLength -or $beforeLength -ne $afterLength -or
     $before.LastWriteTimeUtc -ne $after.LastWriteTimeUtc -or $before.CreationTimeUtc -ne $after.CreationTimeUtc){throw 'owned_source_changed'}
  $bytes=New-Object byte[] $count
  if($count){[Buffer]::BlockCopy($buffer,0,$bytes,0,$count)}
  return @{bytes=$bytes;length=$count}
}
function ReadOwnedUpdateJson([ValidateSet('journal','report')][string]$Kind,[string]$Path,$Owner,[switch]$Live) {
  Need (-not $Live -or $Kind -ceq 'journal') 'live_read_only_owned_journal'
  try {$raw=ReadOwnedBytes $Path}
  catch {
    if($Live){
      $e=$_.Exception;$reason=$null
      if($e.Message -ceq 'owned_source_changed'){$reason='source_changed'}
      for($depth=0;$depth -lt 8 -and $null -ne $e;$depth++){
        if($e -is [Management.Automation.ItemNotFoundException] -or $e -is [IO.FileNotFoundException] -or $e -is [IO.DirectoryNotFoundException]){$reason='not_found';break}
        if($e -is [IO.IOException] -and ($e.HResult -band 65535) -in @(32,33)){$reason='sharing';break}
        $e=$e.InnerException
      }
      if($reason){return @{state='transient';reason=$reason}}
    }
    throw
  }
  # Decode/parse/identity failures are never transients or an empty success.
  $text=[Text.UTF8Encoding]::new($false,$true).GetString($raw.bytes)
  Need ($text.TrimStart().StartsWith('{',[StringComparison]::Ordinal)) 'owned_json_object_required'
  $value=$text | ConvertFrom-Json -ErrorAction Stop
  Need ($value -is [pscustomobject]) 'owned_json_object_required'
  if($Kind -ceq 'journal'){
    foreach($key in @('task_id','command_id','hash','version','operation','upgrade_class','artifact_id','stage')){Need ($value.$key -is [string]) 'owned_journal_field_type'}
    Need (($value.schema_version -is [int] -or $value.schema_version -is [long]) -and $value.schema_version -eq 2 -and $value.task_id -ceq $Owner.task_id -and $value.command_id -ceq $Owner.command_id -and
      $value.hash -ceq $Owner.hash -and $value.version -ceq $Owner.version -and $value.operation -ceq $Owner.operation -and
      $value.upgrade_class -ceq $Owner.class -and $value.artifact_id -ceq $Owner.artifact_id) 'owned_journal_identity'
  }else{
    foreach($key in @('target_version','operation','upgrade_class','expected_architecture','expected_sha256','runtime_manifest')){Need ($value.$key -is [string]) 'owned_report_field_type'}
    Need ($value.target_version -ceq $Owner.version -and $value.operation -ceq $Owner.operation -and
      $value.upgrade_class -ceq $Owner.class -and $value.expected_architecture -ceq $Owner.arch -and
      $value.expected_sha256 -ceq $Owner.hash -and [string]$value.runtime_manifest -ieq [string]$Owner.manifest) 'owned_report_identity'
  }
  return @{state='ready';value=$value;bytes=$raw.bytes;length=$raw.length}
}
function SaveOwnedOriginal([ValidateSet('journal','report')][string]$Kind,[string]$Path,$Owner,[string]$Label) {
  $read=ReadOwnedUpdateJson $Kind $Path $Owner
  $destination=Join-Path $script:root ($Label+'.original-'+$Kind+'.json')
  $s=[IO.File]::Open($destination,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
  try{$s.Write($read.bytes,0,$read.length);$s.Flush($true)}finally{$s.Dispose()}
  return @{status='captured';bytes=$read.length;original_bytes_preserved=$true;identity_verified=$true}
}
function SaveTransitionFinalEvidence($Child,$Diagnostic,$Owner,[string]$Label,[string]$Journal,[string]$Report) {
  $failed=$false
  $Diagnostic.terminal_known=$false;$Diagnostic.exit_known=$false;$Diagnostic.exit_code=$null
  if($null -ne $Child){
    try {
      $Child.Refresh()
      if($Child.HasExited){
        $Diagnostic.terminal_known=$true
        $exit=$Child.ExitCode
        if($null -ne $exit -and $exit -is [int]){$Diagnostic.exit_known=$true;$Diagnostic.exit_code=$exit}
      }
    }catch{$Diagnostic.child_status_exception_type=$_.Exception.GetType().FullName}
  }
  if($Diagnostic.terminal_known -and $Diagnostic.exit_known){
    foreach($kind in @('report','journal')){
      try {
        $path=if($kind -ceq 'report'){$Report}else{$Journal}
        $Diagnostic.originals[$kind]=SaveOwnedOriginal $kind $path $Owner $Label
      }catch{
        $failed=$true
        $Diagnostic.originals[$kind]=@{status='capture_failed';exception_type=$_.Exception.GetType().FullName;hresult=$_.Exception.HResult}
      }
    }
  }else{
    $failed=$true
    foreach($kind in @('report','journal')){$Diagnostic.originals[$kind]=@{status='not_captured';reason='child_terminal_or_exit_unknown'}}
  }
  return $failed
}

function PinnedJson([string]$Path,[string]$Expected,[UInt64]$Cap=1048576) {
  $path=Regular $Path $Cap; Need ($Expected -cmatch '^[a-f0-9]{64}$' -and (SHA $path) -ceq $Expected) 'input_pin_mismatch'
  $text=ReadBounded $path $Cap
  Need ((SHA $path) -ceq $Expected) 'input_pin_changed'
  return ($text | ConvertFrom-Json -ErrorAction Stop)
}
function Save([string]$Name,$Value) {
  $path=Join-Path $script:root $Name
  $data=[Text.UTF8Encoding]::new($false).GetBytes(($Value | ConvertTo-Json -Depth 16)+"`n")
  $h=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
  try {$h.Write($data,0,$data.Length);$h.Flush($true)} finally {$h.Dispose()}
}
function SaveRecoverySummary($Value,[bool]$PrimaryFailure) {
  try {Save 'recovery-subset-summary.json' $Value;return @{saved=$true}}
  catch {
    if(-not $PrimaryFailure){throw}
    $failureType=$_.Exception.GetType().FullName
    # A secondary diagnostic write must not replace the original update error.
    Write-Warning -Message ('secondary_summary_capture_failed type='+$failureType) -WarningAction Continue
    return @{saved=$false;exception_type=$failureType}
  }
}
function StartWindowsPowerShellChild([string]$ScriptPath,[string]$StandardOutput,[string]$StandardError) {
  # pwsh's module path is not a Windows PowerShell module path. Match the
  # existing CTest startup owner: let PS5.1 rebuild its own default path.
  # This driver is sequential; only the current process value is changed,
  # just while Start-Process copies the child environment, then restored.
  $previousModulePath=[Environment]::GetEnvironmentVariable('PSModulePath',[EnvironmentVariableTarget]::Process)
  try {
    [Environment]::SetEnvironmentVariable('PSModulePath',$null,[EnvironmentVariableTarget]::Process)
    return (Start-Process -FilePath (Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe') -ArgumentList @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',('"'+$ScriptPath+'"')) -PassThru -RedirectStandardOutput $StandardOutput -RedirectStandardError $StandardError)
  } finally {
    [Environment]::SetEnvironmentVariable('PSModulePath',$previousModulePath,[EnvironmentVariableTarget]::Process)
  }
}
function WaitProcess($Process,[int]$Seconds,[string]$Cause) {
  if (-not $Process.WaitForExit($Seconds*1000)) {
    # This object denotes only our own child; unknown update state is preserved.
    $cleanupType=$null
    try {
      $Process.Kill()
      if (-not $Process.WaitForExit(10000)) {$cleanupType='System.TimeoutException'}
    } catch {$cleanupType=$_.Exception.GetType().FullName}
    if ($cleanupType) {throw ($Cause+';cleanup_unknown_type='+$cleanupType)}
    throw $Cause
  }
  $Process.Refresh(); return $Process.ExitCode
}
# QA diagnostics only. The action and its existing 45/30 second limits are unchanged.
function ServiceObserverError($Record) {
  $e=$Record.Exception;$types=New-Object Collections.ArrayList;$native=$null
  for($depth=0;$null -ne $e -and $depth -lt 8;$depth++){
    $null=$types.Add($e.GetType().FullName)
    if($e -is [ComponentModel.Win32Exception]){$native=$e.NativeErrorCode}
    $e=$e.InnerException
  }
  return @{exception_types=@($types);hresult=$Record.Exception.HResult;native_error_code=$native}
}
function ServiceWorkerSource([ValidateSet('Stop','Start')][string]$Action) {
  $source=@'
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
function EventLine([string]$Phase,[string]$State='') {
  [Console]::Out.WriteLine((@{schema='edr.service-action.phase.v1';phase=$Phase;state=$State}|ConvertTo-Json -Compress));[Console]::Out.Flush()
}
try {
  EventLine 'query_initial'
  $s=Get-Service -Name FDSecurityAgent -ErrorAction Stop
  EventLine 'initial_state' ([string]$s.Status)
  EventLine 'request___ACTION__'
  __REQUEST__
  EventLine 'wait_status_30'
  $s.WaitForStatus('__STATUS__',[TimeSpan]::FromSeconds(30))
  EventLine 'completed'
  exit 0
}catch{
  $e=$_.Exception;$types=New-Object Collections.ArrayList;$native=$null
  for($depth=0;$null -ne $e -and $depth -lt 8;$depth++){
    $null=$types.Add($e.GetType().FullName)
    if($e -is [ComponentModel.Win32Exception]){$native=$e.NativeErrorCode};$e=$e.InnerException
  }
  [Console]::Error.WriteLine((@{schema='edr.service-action.exception.v1';exception_types=@($types);hresult=$_.Exception.HResult;native_error_code=$native}|ConvertTo-Json -Compress));[Console]::Error.Flush()
  exit 1
}
'@
  $request=if($Action -eq 'Stop'){'Stop-Service -InputObject $s -Force -ErrorAction Stop'}else{'Start-Service -InputObject $s -ErrorAction Stop'}
  $status=if($Action -eq 'Stop'){'Stopped'}else{'Running'}
  return $source.Replace('__ACTION__',$Action.ToLowerInvariant()).Replace('__REQUEST__',$request).Replace('__STATUS__',$status)
}
function ServiceSamplerSource {
  # A separate owned process is the only observer that calls SCM/CIM. A hung
  # read cannot extend the parent's original WaitProcess(45) control boundary.
  return @'
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$clock=[Diagnostics.Stopwatch]::StartNew();$written=0
for($i=0;$i -lt 46;$i++){
  $row=[ordered]@{schema='edr.service-scm-sample.v1';index=$i;elapsed_ms=$clock.ElapsedMilliseconds;state='Unknown';checkpoint=$null;wait_hint_ms=$null;service_pid=$null;win32_exit_code=$null;service_exit_code=$null;pid_birth_filetime=$null;exception_types=@();hresult=$null;native_error_code=$null;birth_exception_type=$null}
  try {
    $services=@(Get-CimInstance Win32_Service -Filter "Name='FDSecurityAgent'" -Property @('State','CheckPoint','WaitHint','ProcessId','ExitCode','ServiceSpecificExitCode') -ErrorAction Stop)
    if($services.Count -ne 1){throw [InvalidOperationException]::new('service_record_count')}
    $s=$services[0]
    if([string]$s.State -notin @('Stopped','Start Pending','Stop Pending','Running','Continue Pending','Pause Pending','Paused','Unknown')){throw [InvalidOperationException]::new('service_state_outside_contract')}
    $row.state=[string]$s.State
    foreach($field in @(@('checkpoint','CheckPoint'),@('wait_hint_ms','WaitHint'),@('service_pid','ProcessId'),@('win32_exit_code','ExitCode'),@('service_exit_code','ServiceSpecificExitCode'))){
      $number=$s.($field[1]);if($null -ne $number){$row[$field[0]]=[uint32]$number}
    }
    if($row.service_pid -gt 0){
      try{$p=[Diagnostics.Process]::GetProcessById([int]$row.service_pid);try{$row.pid_birth_filetime=$p.StartTime.ToUniversalTime().ToFileTimeUtc().ToString()}finally{$p.Dispose()}}
      catch{$row.birth_exception_type=$_.Exception.GetType().FullName}
    }
  }catch{
    $e=$_.Exception;$types=New-Object Collections.ArrayList
    for($depth=0;$null -ne $e -and $depth -lt 8;$depth++){
      $null=$types.Add($e.GetType().FullName)
      if($e -is [ComponentModel.Win32Exception]){$row.native_error_code=$e.NativeErrorCode};$e=$e.InnerException
    }
    $row.exception_types=@($types);$row.hresult=$_.Exception.HResult
  }
  $line=$row|ConvertTo-Json -Depth 4 -Compress;$bytes=[Text.Encoding]::UTF8.GetByteCount($line)+2
  if($written+$bytes -gt 16384){exit 2}
  [Console]::Out.WriteLine($line);[Console]::Out.Flush();$written+=$bytes
  if($clock.ElapsedMilliseconds -ge 45000){break};Start-Sleep -Milliseconds 1000
}
exit 0
'@
}
function ServiceChildStatus($Child,$Value) {
  $Value.terminal_known=$false;$Value.exit_known=$false;$Value.exit_code=$null
  if($null -eq $Child){return $false}
  try{
    $Value.pid=$Child.Id
    if($null -eq $Value.birth_filetime){$Value.birth_filetime=$Child.StartTime.ToUniversalTime().ToFileTimeUtc().ToString()}
    $Child.Refresh();$Value.terminal_known=[bool]$Child.HasExited
    if($Value.terminal_known){$code=$Child.ExitCode;if($null -ne $code -and $code -is [int]){$Value.exit_known=$true;$Value.exit_code=$code}}
  }catch{$Value.status_error=ServiceObserverError $_}
  return ($Value.terminal_known -and $Value.exit_known -and $null -ne $Value.birth_filetime)
}
function ServiceRaw([string]$Path,[int]$Cap) {
  # Reuse the existing stable, bounded byte owner; the digest is of these same
  # bytes, rather than a second path read. No original product log is selected.
  $raw=ReadOwnedBytes $Path $Cap
  $null=[Text.UTF8Encoding]::new($false,$true).GetString($raw.bytes)
  $sha=[Security.Cryptography.SHA256]::Create()
  try{$digest=([BitConverter]::ToString($sha.ComputeHash($raw.bytes))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
  return @{status='captured';bytes=$raw.length;sha256=$digest;base64=[Convert]::ToBase64String($raw.bytes);original_bytes_preserved=$true}
}
function FinishServiceObserver($Child,$Value,[string]$Stdout,[string]$Stderr,[int]$Cap,[switch]$Cancel,[switch]$Combined) {
  $failed=$false
  if($null -ne $Child -and $Cancel){
    try{$Child.Refresh();if(-not $Child.HasExited){$Value.cancel_requested=$true;$Child.Kill();Need ($Child.WaitForExit(1000)) 'service_sampler_reap_unknown'}}
    catch{$failed=$true;$Value.cleanup_error=ServiceObserverError $_}
  }
  if(-not (ServiceChildStatus $Child $Value)){$failed=$true}
  $remaining=$Cap
  foreach($stream in @('stdout','stderr')){
    if(-not $Value.terminal_known){$Value[$stream]=@{status='not_captured';reason='owned_child_terminal_unknown'};continue}
    try{
      $path=if($stream -ceq 'stdout'){$Stdout}else{$Stderr};$limit=if($Combined){[Math]::Max(1,$remaining)}else{$Cap}
      $capture=ServiceRaw $path $limit;Need (-not $Combined -or $capture.bytes -le $remaining) 'service_combined_raw_cap'
      $Value[$stream]=$capture;if($Combined){$remaining-=$capture.bytes}
    }
    catch{$failed=$true;$Value[$stream]=@{status='capture_failed';error=(ServiceObserverError $_)}}
  }
  return $failed
}
function ServiceAction([ValidateSet('Stop','Start')][string]$Action,[string]$Label) {
  $worker=Join-Path $script:root ($Label+'.service.ps1');$stdout=Join-Path $script:root ($Label+'.service.stdout.log');$stderr=Join-Path $script:root ($Label+'.service.stderr.log')
  $value=@{label=$Label;action=$Action;phase='prepare';started_at_utc=[DateTime]::UtcNow.ToString('o');worker_source_sha256=$null;primary_failure=$null;worker=@{pid=$null;birth_filetime=$null;terminal_known=$false;exit_known=$false;exit_code=$null};sampler=@{requested=$false;pid=$null;birth_filetime=$null;terminal_known=$false;exit_known=$false;exit_code=$null}}
  $null=$script:serviceActionDiagnostics.Add($value)
  $owned=$null;$sampler=$null;$samplerOut=$null;$samplerErr=$null;$primary=$false;$observerFailed=$false;$clock=[Diagnostics.Stopwatch]::StartNew()
  try{
    Need (-not (Test-Path -LiteralPath $worker)) 'service_worker_exists'
    [IO.File]::WriteAllText($worker,(ServiceWorkerSource $Action),[Text.UTF8Encoding]::new($false));$value.worker_source_sha256=SHA $worker
    if($Action -eq 'Stop' -and $Label -ceq 'health-failed-upgrade-health-stop'){
      $value.sampler.requested=$true
      $samplerScript=Join-Path $script:root ($Label+'.service-sampler.ps1');$samplerOut=Join-Path $script:root ($Label+'.service-sampler.stdout.log');$samplerErr=Join-Path $script:root ($Label+'.service-sampler.stderr.log')
      try{
        Need (-not (Test-Path -LiteralPath $samplerScript)) 'service_sampler_exists'
        [IO.File]::WriteAllText($samplerScript,(ServiceSamplerSource),[Text.UTF8Encoding]::new($false));$value.sampler.source_sha256=SHA $samplerScript
        $sampler=StartWindowsPowerShellChild $samplerScript $samplerOut $samplerErr
        $null=ServiceChildStatus $sampler $value.sampler
      }catch{$observerFailed=$true;$value.sampler.launch_error=ServiceObserverError $_}
    }
    $value.phase='launch_action'
    $owned=StartWindowsPowerShellChild $worker $stdout $stderr
    $null=ServiceChildStatus $owned $value.worker
    $value.phase='wait_action_45';$value.wait_started_at_utc=[DateTime]::UtcNow.ToString('o');$waitClock=[Diagnostics.Stopwatch]::StartNew()
    try{$code=WaitProcess $owned 45 'service_control_unknown_no_retry'}finally{$value.wait_elapsed_ms=$waitClock.ElapsedMilliseconds;$value.wait_finished_at_utc=[DateTime]::UtcNow.ToString('o')}
    Need ($null -ne $code -and $code -is [int]) 'service_control_exit_unknown'
    Need ($code -eq 0) 'service_control_failed'
    $value.phase='action_returned'
  }catch{$primary=$true;$value.primary_failure=ServiceObserverError $_;throw}
  finally{
    if($value.sampler.requested){
      try{if(FinishServiceObserver $sampler $value.sampler $samplerOut $samplerErr 16384 -Cancel -Combined){$observerFailed=$true}}
      catch{$observerFailed=$true;$value.sampler.observer_error=ServiceObserverError $_}
    }
    try{if(FinishServiceObserver $owned $value.worker $stdout $stderr 4096){$observerFailed=$true}}
    catch{$observerFailed=$true;$value.worker.observer_error=ServiceObserverError $_}
    $value.elapsed_ms=$clock.ElapsedMilliseconds;$value.finished_at_utc=[DateTime]::UtcNow.ToString('o');$value.observer_complete=(-not $observerFailed)
    if(-not $primary -and $observerFailed){throw 'service_action_diagnostic_incomplete'}
  }
}

function ConfigBinding {
  $path=Regular $script:configPath 131072
  Need ((SHA $path) -ceq $script:configSha256) 'fixture_configuration_hash_changed'
  $text=ReadBounded $path 131072
  foreach ($pair in $script:expectedConfigPairs) {
    $key=[regex]::Escape($pair[0]);$encoded=[regex]::Escape($pair[1].Replace('\','\\'))
    Need ([regex]::Matches($text,('(?m)^'+$key+'\s*=')).Count -eq 1 -and [regex]::Matches($text,('(?m)^'+$key+'\s*=\s*"'+$encoded+'"[^\S\r\n]*(?:#[^\r\n]*)?\r?$')).Count -eq 1) 'fixture_configuration_scalar_binding'
  }
  Need ((SHA $path) -ceq $script:configSha256) 'fixture_configuration_changed_during_check'
}
function Installed([string]$ExpectedHash,[string]$Version) {
  ConfigBinding
  Need ((SHA $script:agent) -ceq $ExpectedHash) 'installed_agent_hash'
  $actualVersion=[Diagnostics.FileVersionInfo]::GetVersionInfo($script:agent).ProductVersion
  $versionMatch=[regex]::Match($actualVersion,'^([0-9]+\.[0-9]+\.[0-9]+)(?:\.0)?(?:[ +].*)?$')
  Need ($versionMatch.Success -and $versionMatch.Groups[1].Value -eq $Version) 'installed_agent_version'
  $stage=if($ExpectedHash -ceq $script:baseline.agent_binary_sha256){$script:baseline}else{$script:target}
  $identity=PinnedJson (Join-Path $script:install 'native-package-integrity.json') $stage.runtime_identity_sha256
  Need ($identity.schema -eq 'edr.windows.native-package-integrity.v1' -and @($identity.files).Count -ge 1 -and @($identity.files).Count -le 64) 'installed_runtime_identity'
  foreach($component in $identity.files) {
    Need ($component.name -cmatch '^[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)?$' -and $component.name -notmatch '(^|/)\.\.(/|$)') 'runtime_component_path'
    $componentPath=Regular (Join-Path $script:install $component.name) 67108864
    Need ((SHA $componentPath) -ceq $component.sha256.ToLowerInvariant()) 'installed_runtime_component_hash'
  }
  $s=Get-CimInstance Win32_Service -Filter "Name='FDSecurityAgent'" -ErrorAction Stop
  Need ($s.State -eq 'Running' -and $s.ProcessId -gt 0) 'exact_service_not_running'
  $p=Get-Process -Id $s.ProcessId -ErrorAction Stop
  Need ($p.Path -ieq $script:agent) 'service_process_path'
  $process=Get-CimInstance Win32_Process -Filter ("ProcessId="+$p.Id) -ErrorAction Stop
  $expected='"'+$script:agent+'" --service --service-name "FDSecurityAgent" --config "'+$script:configPath+'"'
  Need ($process.ExecutablePath -ieq $script:agent -and [string]$process.CommandLine -ieq $expected -and [string]$s.PathName -ieq $expected -and [regex]::Matches([string]$process.CommandLine,'(?i)(?<!\S)--config(?=\s)').Count -eq 1) 'service_process_config_argv_binding'
  $again=Get-Process -Id $p.Id -ErrorAction Stop
  Need ($again.Path -ieq $script:agent -and $again.StartTime.ToUniversalTime().ToFileTimeUtc() -eq $p.StartTime.ToUniversalTime().ToFileTimeUtc()) 'service_generation_changed_during_configuration_check'
  ConfigBinding
  return @{pid=$p.Id;birth_filetime=$p.StartTime.ToUniversalTime().ToFileTimeUtc().ToString();exe_sha256=$ExpectedHash;config_sha256=$script:configSha256;fixture_config_binding_verified=$true;service_config_argv_verified=$true}
}
function Snapshot([string]$Name,[string]$Expected='') {
  $path=Join-Path $script:root ($Name+'.json')
  $snapshotArguments=@($script:inspector,'--db',$script:db,'--output',$path)
  if ($Expected) {$snapshotArguments+=@('--expected',$Expected)}
  & $script:python -I -B @snapshotArguments | Out-Null
  Need ($LASTEXITCODE -eq 0) ('owner_snapshot_failed_'+$Name)
  return $path
}
function Transition([string]$Operation,[string]$Label,[bool]$FailHealth,[string]$Updater) {
  $id=[Guid]::NewGuid().ToString('N');$command='ci-cache-recovery-'+$id
  $journal=Join-Path $env:ProgramData ('FDSecurity\state\agent-update-'+$command+'.journal.json')
  $report=Join-Path $env:ProgramData ('FDSecurity\logs\agent-update-'+$command+'-report.json')
  $owner=@{task_id=$id;command_id=$command;hash=$script:target.agent_binary_sha256;version=$script:target.version;operation=$Operation;class=$script:actualClass;artifact_id=('ci-cache-recovery-'+$script:target.version);arch=$script:updateArch;manifest=$script:package}
  $diagnostic=@{label=$Label;task_id=$id;command_id=$command;phase='prepare';child_pid=$null;child_birth_filetime=$null;terminal_known=$false;exit_known=$false;exit_code=$null;poll_attempts=0;poll_transients=@{not_found=0;sharing=0;source_changed=0};primary_failure_type=$null;originals=@{report=@{status='not_attempted'};journal=@{status='not_attempted'}}}
  $null=$script:transitionDiagnostics.Add($diagnostic)
  $child=$null;$primaryFailure=$false;$clock=[Diagnostics.Stopwatch]::StartNew()
  try {
    $work=Join-Path ([IO.Path]::GetTempPath()) ('FDSecurity\agent-update\'+$command)
    Need (-not (Test-Path -LiteralPath $work)) 'update_work_already_exists'
    New-Item -ItemType Directory -Path $work | Out-Null
    $staged=Join-Path $work 'FDSensor.next.exe';Copy-Item -LiteralPath $script:targetAgent -Destination $staged
    $issued=[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
    $params=@{InstallDir=$script:install;StagedBinary=$staged;ExpectedSha256=$script:target.agent_binary_sha256;
      TargetVersion=$script:target.version;ExpectedArchitecture=$script:updateArch;
      TrustedPublisherThumbprint='SHA256_ONLY_UNSIGNED';TrustedPublisherSubject='Unsigned release; SHA-256 integrity only';
      DeploymentMode='service';ServiceName='FDSecurityAgent';CommandId=$command;TaskId=$id;
      Operation=$Operation;ArtifactId=('ci-cache-recovery-'+$script:target.version);
      UpgradeClass=$script:actualClass;RuntimeManifest=$script:package;RuntimeManifestSha256=$script:binding.protocol5_package.sha256;
      StagingDirectory=$work;IssuedAtUnixMs=$issued;DeadlineUnixMs=($issued+900000);HealthObserveMs=30000;
      MinFreeBytes=$script:effectiveMinFreeBytes;
      MinCurrentVersion=[string]$script:raw[0].update.min_current_version;
      MaxCurrentVersion=[string]$script:raw[0].update.max_current_version}
    $paramFile=Join-Path $script:root ($Label+'.parameters.xml');$params | Export-Clixml -LiteralPath $paramFile
    $invoke=Join-Path $script:root ($Label+'.invoke.ps1')
    Need ($Updater -notmatch "['\r\n]" -and $paramFile -notmatch "['\r\n]") 'invocation_path'
    [IO.File]::WriteAllText($invoke,("`$ErrorActionPreference='Stop';`$p=Import-Clixml -LiteralPath '"+$paramFile+"';& '"+$Updater+"' @p;exit `$LASTEXITCODE"),[Text.UTF8Encoding]::new($false))
    Save ($Label+'.intent.json') @{task_id=$id;command_id=$command;operation=$Operation;class=$script:actualClass;expected_hash=$script:target.agent_binary_sha256;health_failure_requested=$FailHealth;no_automatic_retry=$true}
    $diagnostic.phase='launch'
    $child=StartWindowsPowerShellChild $invoke (Join-Path $script:root ($Label+'.stdout.log')) (Join-Path $script:root ($Label+'.stderr.log'))
    $diagnostic.child_pid=$child.Id
    try{$diagnostic.child_birth_filetime=$child.StartTime.ToUniversalTime().ToFileTimeUtc().ToString()}catch{$diagnostic.child_birth_exception_type=$_.Exception.GetType().FullName}
    $triggered=$false;$deadline=[DateTime]::UtcNow.AddSeconds(900)
    while (-not $child.HasExited -and [DateTime]::UtcNow -lt $deadline) {
      if ($FailHealth -and -not $triggered) {
        $diagnostic.phase='live_journal_read'
        $diagnostic.poll_attempts++
      $reading=ReadOwnedUpdateJson 'journal' $journal $owner -Live
        if($reading.state -ceq 'transient'){$diagnostic.poll_transients[$reading.reason]++}
        elseif($reading.state -ceq 'ready' -and $reading.value.stage -ceq 'health_observation') {
          $diagnostic.phase='health_observation_bind'
          $j=$reading.value
          $native=Installed $script:target.agent_binary_sha256 $script:target.version
          Snapshot ($Label+'-before-trigger') $script:seed | Out-Null
          $backup=Join-Path ([string]$j.full_installer_backup_path) 'FDSensor.exe'
          Need ((SHA (Regular $backup 16777216)) -ceq $script:baseline.agent_binary_sha256) 'actual_previous_backup_not692'
          $again=Installed $script:target.agent_binary_sha256 $script:target.version
          Need ($again.pid -eq $native.pid -and $again.birth_filetime -eq $native.birth_filetime) 'trigger_generation_changed'
          Save ($Label+'.health-trigger.json') @{native=$native;actual_previous_sha256=(SHA $backup);owner_snapshot_sha256=(SHA (Join-Path $script:root ($Label+'-before-trigger.json')));action='stop_exact_owned_service';fixture_only=$true}
          ServiceAction 'Stop' ($Label+'-health-stop')
          $triggered=$true
        }
      }
      Start-Sleep -Milliseconds 100;$child.Refresh()
    }
    $diagnostic.phase='wait_terminal'
    $code=WaitProcess $child 1 'updater_terminal_unknown_no_retry'
    Need ($null -ne $code -and $code -is [int]) 'owned_child_exit_unavailable'
    $diagnostic.terminal_known=$true;$diagnostic.exit_known=$true;$diagnostic.exit_code=$code
    $diagnostic.phase='terminal_report_read'
    $result=(ReadOwnedUpdateJson 'report' $report $owner).value
    $diagnostic.phase='terminal_journal_read'
    $j=(ReadOwnedUpdateJson 'journal' $journal $owner).value
    Need ($j.task_id -eq $id -and $j.command_id -eq $command -and $j.hash -ceq $script:target.agent_binary_sha256) 'terminal_journal_binding'
    $diagnostic.phase='terminal_contract'
    if ($FailHealth) {
      Need ($triggered -and $code -ne 0 -and $result.status -eq 'failed_rolled_back' -and $result.rollback -eq 'succeeded' -and $j.status -eq 'failed_rolled_back') 'real_automatic_rollback_not_observed'
      Installed $script:baseline.agent_binary_sha256 '3.2.692' | Out-Null
    } else {
      Need ($code -eq 0 -and $result.status -eq 'succeeded' -and $j.status -eq 'succeeded') 'normal_updater_not_succeeded'
      Installed $script:target.agent_binary_sha256 $script:target.version | Out-Null
      if ($Operation -eq 'repair') {Need ($result.installer_baseline_mode -eq 'repair_baseline') 'normal_missing_inno_repair_not_observed'}
    }
    $diagnostic.phase='after_snapshot'
    Snapshot ($Label+'-after') $script:seed | Out-Null
    $diagnostic.phase='completed'
  }catch{
    $primaryFailure=$true
    $diagnostic.primary_failure_phase=$diagnostic.phase
    $diagnostic.primary_failure_type=$_.Exception.GetType().FullName
    $diagnostic.primary_failure_hresult=$_.Exception.HResult
    throw
  }finally{
    try{$captureFailed=SaveTransitionFinalEvidence $child $diagnostic $owner $Label $journal $report}
    catch{$captureFailed=$true;$diagnostic.evidence_observer_exception_type=$_.Exception.GetType().FullName}
    $diagnostic.elapsed_ms=$clock.ElapsedMilliseconds
    if(-not $primaryFailure -and $captureFailed){
      $diagnostic.primary_failure_phase='terminal_evidence_capture'
      $diagnostic.primary_failure_type='System.InvalidOperationException'
      throw 'terminal_original_evidence_unavailable'
    }
  }
}
# Refuse missing immutable inputs before creating any machine or fixture state.
$binding=PinnedJson $InputJson $InputSha256
Need ($binding.schema -eq 'edr.ci-cache-recovery-input.v1' -and $binding.prepared_only -is [bool] -and $binding.prepared_only -eq $false) 'recovery_input_unbound'
Need ($env:OS -eq 'Windows_NT' -and $env:GITHUB_ACTIONS -eq 'true' -and $env:RUNNER_ENVIRONMENT -eq 'github-hosted') 'disposable_github_hosted_windows_only'
$principal=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
Need ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) 'existing_elevated_ci_owner_required'
Need ($binding.arch -in @('arm64','amd64')) 'native_arch_required'
$baseline=PinnedJson $binding.baseline.stage_path $binding.baseline.stage_sha256
$target=PinnedJson $binding.target.stage_path $binding.target.stage_sha256
Need ($baseline.version -eq '3.2.692' -and $baseline.source_commit -ceq 'a978ec83deacf7cd78c273d82630b457c5f39251' -and $baseline.target_arch -eq $binding.arch) 'exact692_stage_required'
Need ($target.source_commit -ceq $binding.target.source_sha -and $target.source_commit -cmatch '^[a-f0-9]{40}$' -and [version]$target.version -gt [version]'3.2.692' -and $target.target_arch -eq $binding.arch) 'target_stage_required'
Need ($baseline.package_scope -eq 'headless' -and $target.package_scope -eq 'headless' -and $baseline.validation_scope -eq 'headless_subset' -and $target.validation_scope -eq 'headless_subset') 'verified_headless_stage_scope'
$manifest=PinnedJson $binding.target.artifact_manifest_path $binding.target.artifact_manifest_sha256
$raw=@($manifest.artifacts | Where-Object {$_.name -clike '*-FDSensor.exe'})
Need ($raw.Count -eq 1 -and $raw[0].sha256 -ceq $target.agent_binary_sha256 -and $manifest.build_provenance.commit -ceq $target.source_commit -and $manifest.version -eq $target.version -and $manifest.signature.status -eq 'unsigned') 'actual_headless_artifact_binding'
Need ($raw[0].update.internal_name -eq 'FDSensor' -and $raw[0].update.internal_version -eq $target.version -and $raw[0].update.deployment_mode -eq 'service' -and $raw[0].update.service_name -eq 'FDSecurityAgent' -and $raw[0].update.runtime_identity_sha256 -ceq $target.runtime_identity_sha256) 'actual_artifact_runtime_owner'
Need ([string]$binding.requested_min_free_bytes -cmatch '^(0|[1-9][0-9]{0,12})$' -and [UInt64]$binding.requested_min_free_bytes -le 1099511627776) 'optional_explicit_higher_disk_floor_required'
$actualClass=[string]$raw[0].update.upgrade_class
Need ($actualClass -eq 'installer_required') 'actual_installer_required_class_required'
Need ($binding.protocol5_package.builder_owner -ceq 'edr-backend/platform/internal/installer/full_installer.go' -and $binding.protocol5_package.builder_output_verified_by_caller -eq $true) 'original_backend_builder_input_required'
$package=Regular $binding.protocol5_package.path 268435456;Need ((SHA $package) -ceq $binding.protocol5_package.sha256) 'protocol5_package_pin'
$python=Regular $binding.python_path 16777216
Need ((SHA $python) -ceq $binding.python_sha256) 'existing_ci_python_pin'
$inspector=Regular (Join-Path $PSScriptRoot 'cache_recovery_snapshot.py') 65536
Need ((SHA $inspector) -ceq $binding.snapshot_helper_sha256) 'snapshot_helper_pin'
# Original packager remains authoritative for PE/hash/size/path verification.
# The strict consumer additionally requires one reachable TOOL and complete named dependency graph.
& $python -I -B $inspector --verify-native-tools --manifest $binding.native_tools.manifest_path --manifest-sha256 $binding.native_tools.manifest_sha256 --validation-owner $binding.native_tools.validation_owner_path --validation-owner-sha256 $binding.native_tools.validation_owner_sha256 --arch $binding.arch --source $target.source_commit --run-id $binding.native_tools.run_id | Out-Null
Need ($LASTEXITCODE -eq 0) 'same_source_passed_native_fixture_closure_required'
$toolRoot=Split-Path -Parent $binding.native_tools.manifest_path
$tool=Join-Path $toolRoot 'test_local_evidence_cache_candidate.exe'
$install='C:\Program Files\FDSecurity';$agent=Join-Path $install 'FDSensor.exe'
Need (-not (Test-Path -LiteralPath $install) -and -not (Test-Path -LiteralPath (Join-Path $env:ProgramData 'FDSecurity'))) 'clean_disposable_paths_required'
# Exact aliases touched by installer_worker_win.c stage_stop_runtime; no prior owner may exist.
$priorServices=@(Get-Service -ErrorAction Stop);$priorTasks=@(Get-ScheduledTask -ErrorAction Stop);$priorProcesses=@(Get-Process -ErrorAction Stop)
foreach ($alias in @('FDSecurityAgent','EdrAgent')) {
  Need (-not ($priorServices | Where-Object {$_.Name -ieq $alias}) -and -not ($priorTasks | Where-Object {$_.TaskName -ieq $alias})) 'clean_disposable_service_task_alias_required'
}
foreach ($alias in @('FDSensor','edr_agent')) {
  Need (-not ($priorProcesses | Where-Object {$_.ProcessName -ieq $alias})) 'clean_disposable_process_alias_required'
}
$token=[Guid]::NewGuid().ToString('N');$root=Join-Path $env:RUNNER_TEMP ('edr-cache-recovery-'+$token)
New-Item -ItemType Directory -Path $root | Out-Null
$db=Join-Path $root 'evidence\cache.db';$updateArch=if($binding.arch -eq 'arm64'){'arm64'}else{'x64'}
$targetAgent=Join-Path $target.runtime_dir 'FDSensor.exe'
foreach ($stage in @($baseline,$target)) {
  Need ((SHA (Regular (Join-Path $stage.runtime_dir 'FDSensor.exe') 16777216)) -ceq $stage.agent_binary_sha256) 'staged_agent_hash'
  Need ((SHA (Regular $stage.setup_exe 268435456)) -ceq $stage.setup_exe_sha256) 'staged_headless_setup_hash'
}
$completed=$false;$mainPrimaryFailure=$false
$transitionDiagnostics=New-Object Collections.ArrayList
$serviceActionDiagnostics=New-Object Collections.ArrayList
try {
  $temp=Join-Path $root 'seed-temp';New-Item -ItemType Directory -Path $temp | Out-Null
  $oldTemp=$env:TEMP;$oldTmp=$env:TMP
  try {
    $env:TEMP=$temp;$env:TMP=$temp
    $seedProcess=Start-Process -FilePath $tool -ArgumentList @('--alert-parent-soak','2') -PassThru -RedirectStandardOutput (Join-Path $root 'seed.stdout.log') -RedirectStandardError (Join-Path $root 'seed.stderr.log')
    Need ((WaitProcess $seedProcess 45 'synthetic_seed_timeout') -eq 0) 'synthetic_seed_failed'
  } finally {$env:TEMP=$oldTemp;$env:TMP=$oldTmp}
  Need ((Get-Item -LiteralPath (Join-Path $root 'seed.stderr.log')).Length -eq 0) 'seed_stderr_unclassified'
  $out=ReadBounded (Join-Path $root 'seed.stdout.log') 65536
  $begin=[regex]::Matches($out,'(?m)^parent_soak_begin .*native_machine=(\d+) process_machine=(\d+) io_available=1\r?$')
  $end=[regex]::Matches($out,'(?m)^parent_soak_end label=short_smoke .*requested_seconds=2 .*partial=0 .*db_preserved=1 directory=(\S+)\r?$')
  Need ($begin.Count -eq 1 -and $end.Count -eq 1 -and [int]$begin[0].Groups[1].Value -eq $(if($binding.arch -eq 'arm64'){43620}else{34404}) -and $begin[0].Groups[2].Value -eq '0') 'native_seed_receipt'
  $sourceDir=[IO.Path]::GetFullPath($end[0].Groups[1].Value)
  Need ($sourceDir.StartsWith($temp+'\',[StringComparison]::OrdinalIgnoreCase)) 'seed_directory_escape'
  New-Item -ItemType Directory -Path (Split-Path -Parent $db) | Out-Null
  foreach ($suffix in @('','-wal','-shm')) {
    $source=Join-Path $sourceDir ('cache.db'+$suffix)
    if (Test-Path -LiteralPath $source) {
      $source=Regular $source 67108864;Copy-Item -LiteralPath $source -Destination ($db+$suffix)
      Need ((SHA $source) -ceq (SHA ($db+$suffix))) 'synthetic_copy_hash'
    }
  }
  $seed=Snapshot 'seed-owner'
  New-Item -ItemType Directory -Path $install | Out-Null
  $template=Join-Path $baseline.runtime_dir 'agent_windows_production.example.toml'
  $config=ReadBounded $template 131072
  $expectedConfigPairs=@(@('endpoint_id',('ci-cache-recovery-'+$token)),@('tenant_id','ci-cache-recovery'),@('rest_base_url','https://127.0.0.1:9/api/v1'),@('queue_db_path',(Join-Path $root 'queue\edr_queue.db')),@('evidence_cache_path',$db))
  foreach ($pair in $expectedConfigPairs) {
    $pattern='(?m)^'+[regex]::Escape($pair[0])+'\s*=\s*"[^"\r\n]*"'
    Need ([regex]::Matches($config,$pattern).Count -eq 1) 'single_config_owner_required'
    $value=$pair[1].Replace('\','\\');$config=[regex]::Replace($config,$pattern,($pair[0]+' = "'+$value+'"'))
  }
  $configPath=Join-Path $install 'agent.toml'
  [IO.File]::WriteAllText($configPath,$config,[Text.UTF8Encoding]::new($false))
  $configSha256=SHA $configPath;ConfigBinding
  # The real installer-only owner reads its normal local configuration and owner
  # inventory. It performs no Agent init, migration, maintenance or network.
  # Keep its production 15s watchdog; the parent gives process teardown 20s.
  $floorPath=Join-Path $root 'native-storage-space.floor'
  $floorProcess=Start-Process -FilePath $targetAgent -WorkingDirectory $target.runtime_dir -ArgumentList @('--storage-space-preflight','--config',('"'+$configPath+'"'),'--output',('"'+$floorPath+'"')) -PassThru -RedirectStandardOutput (Join-Path $root 'storage-space.stdout.log') -RedirectStandardError (Join-Path $root 'storage-space.stderr.log')
  Need ((WaitProcess $floorProcess 20 'native_storage_floor_unknown_no_retry') -eq 0) 'native_storage_floor_failed'
  Need ((Get-Item -LiteralPath (Join-Path $root 'storage-space.stdout.log')).Length -eq 0 -and (Get-Item -LiteralPath (Join-Path $root 'storage-space.stderr.log')).Length -eq 0) 'native_storage_floor_output_unclassified'
  $floorText=ReadBounded $floorPath 32
  Need ($floorText -cmatch '^[1-9][0-9]{0,15}$') 'native_storage_floor_decimal_required'
  $localFloor=[UInt64]$floorText
  $effectiveMinFreeBytes=$localFloor
  if ($effectiveMinFreeBytes -lt [UInt64]$raw[0].update.min_free_bytes) {$effectiveMinFreeBytes=[UInt64]$raw[0].update.min_free_bytes}
  if ($effectiveMinFreeBytes -lt [UInt64]$binding.requested_min_free_bytes) {$effectiveMinFreeBytes=[UInt64]$binding.requested_min_free_bytes}
  Save 'storage-floor-proof.json' @{schema='edr.ci-original-storage-floor.v1';native_owner='src/core/storage_space_preflight.h';agent_sha256=$target.agent_binary_sha256;config_sha256=$configSha256;native_output_sha256=(SHA $floorPath);native_floor_bytes=$localFloor;manifest_min_free_bytes=[UInt64]$raw[0].update.min_free_bytes;explicit_higher_override_bytes=[UInt64]$binding.requested_min_free_bytes;effective_min_free_bytes=$effectiveMinFreeBytes;formula='max(native_original_owner_floor,manifest_minimum,explicit_higher_override)';agent_initialized=$false;cache_migrated=$false}
  ConfigBinding
  $setup=Start-Process -FilePath $baseline.setup_exe -ArgumentList @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART','/SP-',('/DIR="'+$install+'"'),'/TASKS="windowsservice"') -PassThru
  Need ((WaitProcess $setup 600 'baseline_setup_timeout') -eq 0) 'baseline_setup_failed'
  Installed $baseline.agent_binary_sha256 '3.2.692' | Out-Null
  Snapshot '692-before-upgrade' $seed | Out-Null
  $oldUpdater=Join-Path $install 'edr_agent_inplace_update-3.2.692.ps1'
  Need ((SHA (Regular $oldUpdater 1048576)) -ceq (SHA (Join-Path $baseline.runtime_dir 'edr_agent_inplace_update.ps1'))) 'actual692_embedded_updater_required'
  Transition 'upgrade' 'health-failed-upgrade' $true $oldUpdater
  # After automatic rollback the exact692 embedded owner is required again.
  Need ((SHA (Regular $oldUpdater 1048576)) -ceq (SHA (Join-Path $baseline.runtime_dir 'edr_agent_inplace_update.ps1'))) 'restored692_updater_required'
  Transition 'upgrade' 'normal-recovery-upgrade' $false $oldUpdater
  $newUpdater=Join-Path $install ('edr_agent_inplace_update-'+$target.version+'.ps1')
  Need ((SHA (Regular $newUpdater 1048576)) -ceq (SHA (Join-Path $target.runtime_dir 'edr_agent_inplace_update.ps1'))) 'actual_new_embedded_updater_required'
  Installed $target.agent_binary_sha256 $target.version | Out-Null
  ServiceAction 'Stop' 'repair-stop'
  foreach ($name in @('unins000.exe','unins000.dat')) {Remove-Item -LiteralPath (Regular (Join-Path $install $name) 16777216) -Force}
  ServiceAction 'Start' 'repair-start'
  Transition 'repair' 'normal-headless-repair' $false $newUpdater
  $completed=$true
} catch {$mainPrimaryFailure=$true;throw} finally {
  SaveRecoverySummary @{schema='edr.ci-cache-recovery-result.v1';status=$(if($completed){'local_subset_passed'}else{'failed_or_unknown'});baseline='win_3.2.692';target_source=$target.source_commit;input_sha256=$InputSha256;install_dir=$install;fixture_root=$root;automatic_retry=$false;library_prepared_schema=$true;actual_agent_first_migration_proven=$false;actual_agent_alert_admission_proven=$false;signed_control_delivery_proven=$false;power_loss_proven=$false;real_data_touched=$false;transition_diagnostics=@($transitionDiagnostics);service_action_diagnostics=@($serviceActionDiagnostics)} $mainPrimaryFailure | Out-Null
}
Need $completed 'recovery_subset_incomplete'
