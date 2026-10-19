#Requires -Version 5.1
[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$ContractExe,
  [Parameter(Mandatory=$true)][string]$DriverSource,
  [Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9]{64}$')][string]$DriverSha256
)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
function Need($Value,[string]$Cause){if(-not $Value){throw $Cause}}
function Digest([byte[]]$Raw){$h=[Security.Cryptography.SHA256]::Create();try{return ([BitConverter]::ToString($h.ComputeHash($Raw))).Replace('-','').ToLowerInvariant()}finally{$h.Dispose()}}
function ReadSmall([string]$Path,[int]$Cap){
  $item=Get-Item -LiteralPath $Path -Force
  Need (-not $item.PSIsContainer -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0 -and $item.Length -le $Cap) 'public_file_bound'
  $stream=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
  try{
    $raw=New-Object byte[] ($Cap+1);$used=0
    while($used -lt $raw.Length){$n=$stream.Read($raw,$used,$raw.Length-$used);if($n -eq 0){break};$used+=$n}
    Need ($used -le $Cap -and $used -eq $stream.Length) 'public_file_grew'
    if($used -eq 0){return ,([byte[]]@())};return ,([byte[]]$raw[0..($used-1)])
  }finally{$stream.Dispose()}
}
# Parse only the pinned writer expression. Do not evaluate the recovery driver
# main, Transition, service/task, installer, Agent or database code.
$stream=[IO.File]::Open($DriverSource,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
try{
  Need ($stream.Length -gt 0 -and $stream.Length -le 131072) 'driver_source_bound'
  $bytes=New-Object byte[] ([int]$stream.Length);$used=0
  while($used -lt $bytes.Length){$n=$stream.Read($bytes,$used,$bytes.Length-$used);Need ($n -gt 0) 'driver_source_short_read';$used+=$n}
  Need ((Digest $bytes) -ceq $DriverSha256) 'driver_source_sha256'
  $tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseInput([Text.UTF8Encoding]::new($false,$true).GetString($bytes),[ref]$tokens,[ref]$errors)
  Need (@($errors).Count -eq 0) 'driver_source_parse'
  $transitions=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Transition'},$true))
  Need ($transitions.Count -eq 1) 'transition_owner_unique'
  $writers=@($transitions[0].Body.FindAll({param($n)
    $n -is [Management.Automation.Language.InvokeMemberExpressionAst] -and $n.Static -and $n.Member.Value -ceq 'WriteAllText' -and $n.Expression -is [Management.Automation.Language.TypeExpressionAst] -and $n.Expression.TypeName.FullName -ceq 'IO.File' -and $n.Arguments.Count -eq 3 -and $n.Arguments[0] -is [Management.Automation.Language.VariableExpressionAst] -and $n.Arguments[0].VariablePath.UserPath -ceq 'invoke'
  },$true))
  Need ($writers.Count -eq 1) 'QA_invocation_writer_unique'
  $writeQA=[scriptblock]::Create($writers[0].Extent.Text)
}finally{$stream.Dispose()}
$strings=@('StagedBinary','ExpectedSha256','TargetVersion','ExpectedArchitecture','ExpectedInternalName','TrustedPublisherThumbprint','TrustedPublisherSubject','MinCurrentVersion','MaxCurrentVersion','UpgradeClass','DeploymentMode','ScheduledTaskName','ScheduledTaskPath','ServiceName','CommandId','RuntimeManifest','RuntimeManifestSha256','TaskId','CampaignId','Operation','ArtifactId','UpdaterTaskName','StagingDirectory')
$uints=@('MinFreeBytes','IssuedAtUnixMs','DeadlineUnixMs','HealthObserveMs')
function ArgumentsDigest([Collections.IDictionary]$Map){
  $b=New-Object Text.StringBuilder
  foreach($name in $strings+$uints){
    $v=$Map[$name];$number=$name -cin $uints
    Need (($number -and $v -is [UInt64]) -or (-not $number -and $v -is [string])) 'argument_type'
    $s=if($number){$v.ToString([Globalization.CultureInfo]::InvariantCulture)}else{$v}
    $null=$b.Append($name).Append(':').Append($(if($number){'U'}else{'S'})).Append(':').Append([Text.Encoding]::UTF8.GetByteCount($s)).Append(':').Append($s).Append(';')
  }
  return Digest ([Text.Encoding]::UTF8.GetBytes($b.ToString()))
}
# Parameter binder only: deliberately permits test UInt64 extremes/empty fields.
# It is not an authorized request and does not invoke updater business validators.
$declarations=@($strings|ForEach-Object {'[AllowEmptyString()][string]$'+$_})+@($uints|ForEach-Object {'[UInt64]$'+$_})
$workerTemplate='param('+($declarations -join ',')+")`n"+@'
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$names=@('__NAMES__');$nums=@('__NUMS__');$b=New-Object Text.StringBuilder
foreach($name in $names){
  $v=$PSBoundParameters[$name];$number=$name -cin $nums
  if(($number -and $v -isnot [UInt64]) -or (-not $number -and $v -isnot [string])){throw 'public_argument_type'}
  $s=if($number){$v.ToString([Globalization.CultureInfo]::InvariantCulture)}else{$v}
  $null=$b.Append($name).Append(':').Append($(if($number){'U'}else{'S'})).Append(':').Append([Text.Encoding]::UTF8.GetByteCount($s)).Append(':').Append($s).Append(';')
}
$h=[Security.Cryptography.SHA256]::Create()
try{$digest=([BitConverter]::ToString($h.ComputeHash([Text.Encoding]::UTF8.GetBytes($b.ToString())))).Replace('-','').ToLowerInvariant()}finally{$h.Dispose()}
[IO.File]::WriteAllText((Join-Path $PSScriptRoot 'record.json'),(@{argument_count=$PSBoundParameters.Count;arguments_sha256=$digest}|ConvertTo-Json -Compress),[Text.UTF8Encoding]::new($false))
switch -CaseSensitive ($Operation){
  'success_return' { & (Join-Path $env:WINDIR 'System32\cmd.exe') /d /c 'exit 1';if($LASTEXITCODE -ne 1){throw 'public_native1_required'};return }
  'exit1' { exit 1 }
  'exit7' { exit 7 }
  'throw' { throw 'public_updater_failure' }
  'args_only' { return }
  default { throw 'closed_public_operation' }
}
'@
$workerTemplate=$workerTemplate.Replace('__NAMES__',(($strings+$uints) -join "','")).Replace('__NUMS__',($uints -join "','"))
$root=Join-Path ([IO.Path]::GetTempPath()) ('edr-invocation-'+[Guid]::NewGuid().ToString('N'))
$oldPathExt=[Environment]::GetEnvironmentVariable('PATHEXT','Process');$rows=New-Object Collections.ArrayList;$clock=[Diagnostics.Stopwatch]::StartNew();$passed=$false
try{
  Need (-not (Test-Path -LiteralPath $root)) 'fresh_public_root'
  New-Item -ItemType Directory -Path $root | Out-Null
  [Environment]::SetEnvironmentVariable('PATHEXT','.EXE','Process')
  foreach($owner in @('C','QA')){
    foreach($kind in @('success_return','exit1','exit7','throw','args_only')){
      Need ($clock.ElapsedMilliseconds -lt 60000) 'invocation_test_deadline'
      $part=if($owner -ceq 'C'){"C'quote-"+$kind}else{'QA-'+$kind}
      $dir=Join-Path $root $part;New-Item -ItemType Directory -Path $dir | Out-Null
      $Updater=Join-Path $dir 'worker.ps1';$invoke=Join-Path $dir 'invoke.ps1';$paramFile=Join-Path $dir 'arguments.clixml'
      [IO.File]::WriteAllText($Updater,$workerTemplate,[Text.UTF8Encoding]::new($false))
      $p=[ordered]@{StagedBinary='';ExpectedSha256=('a'*64);TargetVersion='3.2.699-public';ExpectedArchitecture='arm64';ExpectedInternalName='public ''"name"\';TrustedPublisherThumbprint='';TrustedPublisherSubject='CN=Public ''" subject\';MinCurrentVersion='';MaxCurrentVersion='3.2.999';UpgradeClass='installer_required';DeploymentMode='scheduled_task';ScheduledTaskName='public ''" task\';ScheduledTaskPath='\public ''" path\';ServiceName='public service';CommandId='public-command';RuntimeManifest='C:\public path\manifest''".json';RuntimeManifestSha256='';TaskId='public-task';CampaignId='';Operation=$kind;ArtifactId='public-artifact';UpdaterTaskName='public updater';StagingDirectory='';MinFreeBytes=[UInt64]::MaxValue;IssuedAtUnixMs=[UInt64]0;DeadlineUnixMs=[UInt64]9007199254740991;HealthObserveMs=[UInt64]9223372036854775808}
      if($owner -ceq 'C'){
        & $ContractExe --write-public-invocation $invoke $Updater $kind
        Need ($LASTEXITCODE -eq 0) 'actual_C_invocation_writer'
      }else{
        Need ($Updater -notmatch "['\r\n]" -and $paramFile -notmatch "['\r\n]") 'QA_public_path_scope'
        $p|Export-Clixml -LiteralPath $paramFile
        & $writeQA
      }
      $out=Join-Path $dir 'stdout.log';$err=Join-Path $dir 'stderr.log'
      $receipt=& $ContractExe --run-public-invocation $invoke $out $err
      Need ($LASTEXITCODE -eq 0) 'known_owned_PowerShell_receipt'
      $received=($receipt|ConvertFrom-Json)
      Need ($received.child_exit_code -is [int] -and $received.job_natural_zero -eq $true -and $received.termination_attempted -eq $false) 'natural_Job_receipt'
      $want=if($kind -ceq 'exit7'){7}elseif($kind -cin @('exit1','throw')){1}else{0}
      Need ($received.child_exit_code -eq $want) ('caller_exit_'+$owner+'_'+$kind)
      $recordBytes=ReadSmall (Join-Path $dir 'record.json') 4096
      $record=([Text.UTF8Encoding]::new($false,$true).GetString($recordBytes)|ConvertFrom-Json)
      Need ($record.argument_count -eq 27 -and $record.arguments_sha256 -ceq (ArgumentsDigest $p)) 'all27_parameters_preserved'
      $stdout=ReadSmall $out 8192;$stderr=ReadSmall $err 8192
      Need ($stdout.Length -eq 0 -and (($kind -ceq 'throw' -and $stderr.Length -gt 0) -or ($kind -cne 'throw' -and $stderr.Length -eq 0))) 'public_child_streams'
      $null=$rows.Add(@{owner=$owner;case=$kind;exit_code=$received.child_exit_code;argument_count=27;arguments_sha256=$record.arguments_sha256;job_natural_zero=$true;termination_attempted=$false})
    }
  }
  Need ($rows.Count -eq 10 -and $clock.ElapsedMilliseconds -lt 60000) 'ten_bounded_invocation_contracts'
  @{test='windows_agent_update_invocation';passed=10;cases=@($rows);actual_C_writer=$true;actual_QA_writer=$true;real_Agent_or_updater_executions=0}|ConvertTo-Json -Depth 5 -Compress|Write-Host
  $passed=$true
}finally{
  [Environment]::SetEnvironmentVariable('PATHEXT',$oldPathExt,'Process')
  # Preserve fixed public files on failure for CTest diagnostics. Each child Job
  # has already reached natural0 or was explicitly failed/cleaned by the C target.
  if($passed){Remove-Item -LiteralPath $root -Recurse -Force}
}
