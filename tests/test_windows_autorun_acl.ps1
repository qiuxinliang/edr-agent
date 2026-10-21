#Requires -Version 5.1
[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$AutorunPath,
  [ValidateRange(1,2000)][int]$FileCount=686,
  [Parameter(Mandatory=$true)][string]$ProgressPath
)
# Only extracted ACL functions run against newly created synthetic files.
# No installer main, process control, machine environment or Task mutation.
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($AutorunPath,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'autorun_parse_failed'}
foreach($name in @('Repair-UninstallerAcls','Repair-RuntimeFileAcls','Repair-RuntimeDependencyAcls','Repair-SensitiveRuntimeAcls')){
  $defs=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$true))
  if($defs.Count -ne 1){throw "missing_acl_owner_$name"}
  Invoke-Expression $defs[0].Extent.Text
}
$root=Join-Path $env:TEMP ('edr-autorun-acl-'+[Guid]::NewGuid().ToString('N'))
$watch=[Diagnostics.Stopwatch]::StartNew()
$times=[ordered]@{}
function Progress([string]$Stage){
  [IO.File]::WriteAllText($ProgressPath,(@{stage=$Stage;elapsed_ms=$watch.ElapsedMilliseconds;completed=$times}|ConvertTo-Json -Compress))
}
function Assert-Private([string]$Path){
  $acl=Get-Acl -LiteralPath $Path
  $grants=@{}
  foreach($ace in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){
    if($ace.AccessControlType -ne 'Allow'){continue}
    $sid=$ace.IdentityReference.Value
    if($sid -notin @('S-1-5-18','S-1-5-32-544')){throw 'sensitive_file_has_public_grant'}
    if(($ace.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -eq 0 -and
       ($ace.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -eq [Security.AccessControl.FileSystemRights]::FullControl){$grants[$sid]=$true}
  }
  if(-not $grants['S-1-5-18'] -or -not $grants['S-1-5-32-544']){throw 'required_direct_or_inherited_grant_missing'}
}
try{
  $sensitive=@('certs','queue','evidence','state','logs','diagnostics','upload_outbox')
  foreach($name in $sensitive){
    $dir=Join-Path $root ($name+'\nested');[IO.Directory]::CreateDirectory($dir)|Out-Null
    [IO.File]::WriteAllText((Join-Path $dir 'existing.bin'),'public fixture')
  }
  foreach($i in 1..$FileCount){[IO.File]::WriteAllText((Join-Path $root "upload_outbox\result-$i.json"),'public fixture')}
  & icacls.exe (Join-Path $root 'upload_outbox\result-1.json') /grant:r '*S-1-5-32-545:RX' /Q | Out-Null
  if($LASTEXITCODE -ne 0){throw 'fixture_explicit_grant_failed'}
  [IO.File]::WriteAllText((Join-Path $root 'agent.toml'),'# public fixture')
  foreach($round in 1..2){
    Progress "dependency_$round";$start=$watch.ElapsedMilliseconds
    Repair-RuntimeDependencyAcls -Dir $root
    $times["dependency_$round"]=$watch.ElapsedMilliseconds-$start
    Progress "sensitive_$round";$start=$watch.ElapsedMilliseconds
    Repair-SensitiveRuntimeAcls -Dir $root
    $times["sensitive_$round"]=$watch.ElapsedMilliseconds-$start
    foreach($name in $sensitive){
      $dir=Join-Path $root ($name+'\nested')
      Assert-Private (Join-Path $dir 'existing.bin')
      if([IO.File]::ReadAllText((Join-Path $dir 'existing.bin')) -cne 'public fixture'){throw 'fixture_content_changed'}
      $future=Join-Path $dir "future-$round.bin";[IO.File]::WriteAllText($future,'public fixture');Assert-Private $future
    }
    Assert-Private (Join-Path $root 'upload_outbox\result-1.json')
  }
  # Fail closed for both the batched file operation and non-queue directories.
  function icacls.exe {$global:LASTEXITCODE=5}
  $refused=$false
  try{Repair-RuntimeFileAcls -Path (Join-Path $root 'evidence')}catch{$refused=$true}
  if(-not $refused){throw 'file_acl_failure_silenced'}
  $refused=$false
  try{Repair-SensitiveRuntimeAcls -Dir $root}catch{$refused=$true}
  if(-not $refused){throw 'non_queue_acl_failure_silenced'}
  Progress 'passed'
  @{status='passed';files=$FileCount;times=$times;elapsed_ms=$watch.ElapsedMilliseconds;live_runtime_touched=$false}|ConvertTo-Json -Compress
}catch{
  [IO.File]::WriteAllText($ProgressPath,(@{stage='failed';completed=$times;error=$_.Exception.Message;line=$_.InvocationInfo.ScriptLineNumber;elapsed_ms=$watch.ElapsedMilliseconds}|ConvertTo-Json -Compress))
  throw
}finally{
  # Unique synthetic tree only; never enumerate or clean the installed Agent.
  if($times.Count -eq 4 -and (Test-Path -LiteralPath $root)){Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction Continue}
}
