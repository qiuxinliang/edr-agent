#Requires -Version 5.1
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$UpdaterPath, [string]$BaselinePath='')
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
function LoadWriter([string]$Source){
  $tokens=$null;$errors=$null
  $ast=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$errors)
  if($errors.Count){throw 'updater_parse_failed'}
  $defs=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Write-AtomicJson'},$true))
  if($defs.Count -ne 1){throw 'atomic_writer_not_unique'}
  return $defs[0].Extent.Text
}
$script:checks=0
function Check($Value,[string]$Cause){$script:checks++;if(-not $Value){throw $Cause}}
function NativeError($Exception){while($Exception.InnerException){$Exception=$Exception.InnerException};return ($Exception.HResult -band 0xffff)}
$root=Join-Path ([IO.Path]::GetTempPath()) ('edr-atomic-json-'+[Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($root)|Out-Null
Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Threading;
public static class EdrAtomicFixture {
  public static Timer ReleaseAfter(FileStream stream, int milliseconds) {
    return new Timer(_ => stream.Dispose(), null, milliseconds, Timeout.Infinite);
  }
}
'@
try {
  if($BaselinePath){
    Invoke-Expression (LoadWriter $BaselinePath)
    $path=Join-Path $root 'baseline.json';$temp="$path.tmp-$PID"
    [IO.File]::WriteAllText($path,'{"old":true}');[IO.File]::WriteAllText($temp,'public')
    $lock=[IO.File]::Open($temp,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
    try{
      $failure=$null;try{Write-AtomicJson $path @{new=$true}}catch{$failure=$_.Exception}
      Check ($failure -and (NativeError $failure) -eq 32) 'baseline_sharing_conflict'
      Check (-not [IO.File]::Exists($path)) 'baseline_deletes_old_state_before_failed_move'
    }finally{$lock.Dispose()}
  }
  Invoke-Expression (LoadWriter $UpdaterPath)
  $path=Join-Path $root 'nested\normal.json'
  Write-AtomicJson $path @{generation=1;public='fixture'}
  Check ((Get-Content $path -Raw|ConvertFrom-Json).generation -eq 1) 'create_readback'
  Write-AtomicJson $path @{generation=2;public='fixture'}
  Check ((Get-Content $path -Raw|ConvertFrom-Json).generation -eq 2) 'replace_readback'
  Check (-not [IO.File]::Exists("$path.tmp-$PID")) 'success_consumes_temporary'

  # Real Windows handles deny rename while permitting the writer's temp write.
  foreach($case in @('source-existing','target-existing','source-new')){
    $path=Join-Path $root ($case+'.json');$temp="$path.tmp-$PID"
    $existing=$case -ne 'source-new'
    if($existing){[IO.File]::WriteAllText($path,'{"old":true}')}
    [IO.File]::WriteAllText($temp,'public')
    $locked=if($case -eq 'target-existing'){$path}else{$temp}
    $lock=[IO.File]::Open($locked,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
    $watch=[Diagnostics.Stopwatch]::StartNew()
    try{
      $failure=$null;try{Write-AtomicJson $path @{new=$true}}catch{$failure=$_.Exception}
      Check ($failure -and (NativeError $failure) -eq 32) ('persistent_conflict_'+$case)
      Check ($watch.ElapsedMilliseconds -lt 5000) ('bounded_failure_'+$case)
      Check ([IO.File]::Exists($temp)) ('failed_temporary_retained_'+$case)
      if($existing){Check ([IO.File]::ReadAllText($path) -ceq '{"old":true}') ('previous_state_preserved_'+$case)}
      else{Check (-not [IO.File]::Exists($path)) 'failed_first_write_not_published'}
    }finally{$lock.Dispose()}
  }
  foreach($case in @('source-existing','target-existing','source-new')){
    $path=Join-Path $root ('transient-'+$case+'.json');$temp="$path.tmp-$PID"
    if($case -ne 'source-new'){[IO.File]::WriteAllText($path,'{"old":true}')}
    [IO.File]::WriteAllText($temp,'public')
    $locked=if($case -eq 'target-existing'){$path}else{$temp}
    $lock=[IO.File]::Open($locked,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
    $timer=[EdrAtomicFixture]::ReleaseAfter($lock,150);$watch=[Diagnostics.Stopwatch]::StartNew()
    try{
      Write-AtomicJson $path @{new=$true}
      Check ((Get-Content $path -Raw|ConvertFrom-Json).new -eq $true) ('transient_conflict_recovers_'+$case)
      Check ($watch.ElapsedMilliseconds -ge 100 -and $watch.ElapsedMilliseconds -lt 5000) ('transient_bound_'+$case)
      Check (-not [IO.File]::Exists($temp)) ('transient_temporary_consumed_'+$case)
    }finally{$timer.Dispose();$lock.Dispose()}
  }
  # Non-sharing errors remain terminal and do not destroy the prior state.
  $path=Join-Path $root 'readonly.json';[IO.File]::WriteAllText($path,'{"old":true}')
  [IO.File]::SetAttributes($path,[IO.FileAttributes]::ReadOnly)
  try{
    $failure=$null;try{Write-AtomicJson $path @{new=$true}}catch{$failure=$_.Exception}
    Check ($failure -and (NativeError $failure) -eq 5) 'access_denied_not_success'
    Check ([IO.File]::ReadAllText($path) -ceq '{"old":true}') 'access_denied_preserves_old'
  }finally{[IO.File]::SetAttributes($path,[IO.FileAttributes]::Normal)}
  @{status='passed';checks=$script:checks;native_file_locks=$true;baseline_checked=[bool]$BaselinePath;active_agent_touched=$false}|ConvertTo-Json -Compress
}finally{
  Remove-Item -LiteralPath $root -Recurse -Force
}
