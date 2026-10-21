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
$passed=$false
$forensicCases=[Collections.Generic.List[object]]::new()
$forensic=Join-Path $root 'forensic'
$forensicCounts=[ordered]@{json=1254;txt=3763;bin=1270}
$forensicDirectories=630
$checks=0
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
  $script:checks++
}
function Assert-LegacyUsersGrant([string]$Path){
  $acl=Get-Acl -LiteralPath $Path
  $rules=@($acl.GetAccessRules($true,$false,[Security.Principal.SecurityIdentifier])|Where-Object {
    $_.IdentityReference.Value -eq 'S-1-5-32-545' -and $_.AccessControlType -eq 'Allow' -and
    ($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::ReadData) -ne 0
  })
  if($rules.Count -eq 0){throw 'fixture_legacy_users_grant_missing'}
}
try{
  $sensitive=@('certs','queue','evidence','state','logs','diagnostics','upload_outbox')
  foreach($name in $sensitive){
    $dir=Join-Path $root ($name+'\nested');[IO.Directory]::CreateDirectory($dir)|Out-Null
    [IO.File]::WriteAllText((Join-Path $dir 'existing.bin'),'public fixture')
  }
  # Match the observed outbox population without adding it to the public JSON
  # loop. The forensic tree supplies the historical JSON/TXT workload.
  foreach($i in 1..$FileCount){[IO.File]::WriteAllText((Join-Path $root "upload_outbox\result-$i.bin"),'public fixture')}
  & icacls.exe (Join-Path $root 'upload_outbox\result-1.bin') /grant:r '*S-1-5-32-545:RX' /Q | Out-Null
  if($LASTEXITCODE -ne 0){throw 'fixture_explicit_grant_failed'}
  foreach($i in 0..($forensicDirectories-1)){
    [IO.Directory]::CreateDirectory((Join-Path $forensic ('case-{0:D4}' -f $i)))|Out-Null
  }
  foreach($ext in $forensicCounts.Keys){
    foreach($i in 0..($forensicCounts[$ext]-1)){
      $path=Join-Path $forensic ('case-{0:D4}\item-{1:D4}.{2}' -f ($i%$forensicDirectories),$i,$ext)
      $content="public forensic fixture $ext $i"
      $bytes=[Text.Encoding]::UTF8.GetBytes($content)
      [IO.File]::WriteAllBytes($path,$bytes)
      $forensicCases.Add(@{path=$path;bytes64=[Convert]::ToBase64String($bytes)})
    }
  }
  # A recursive explicit grant reproduces existing bad ACEs, including files
  # that native /inheritance:r plus SYSTEM/Admin grants cannot repair alone.
  & icacls.exe $forensic /grant:r '*S-1-5-32-545:RX' /T /C /Q | Out-Null
  if($LASTEXITCODE -ne 0){throw 'fixture_forensic_grant_failed'}
  Assert-LegacyUsersGrant $forensicCases[0].path
  Assert-LegacyUsersGrant $forensicCases[$forensicCounts.json].path
  if(@(Get-ChildItem -LiteralPath $forensic -File -Recurse).Count -ne 6287){throw 'fixture_forensic_file_count'}
  if(@(Get-ChildItem -LiteralPath $forensic -Directory -Recurse).Count -ne $forensicDirectories){throw 'fixture_forensic_directory_count'}
  [IO.File]::WriteAllText((Join-Path $root 'agent.toml'),'# public fixture')
  foreach($round in 1..2){
    Progress "dependency_$round";$start=$watch.ElapsedMilliseconds
    Repair-RuntimeDependencyAcls -Dir $root
    $times["dependency_$round"]=$watch.ElapsedMilliseconds-$start
    Progress "sensitive_$round";$start=$watch.ElapsedMilliseconds
    Repair-SensitiveRuntimeAcls -Dir $root
    $times["sensitive_$round"]=$watch.ElapsedMilliseconds-$start
    if(($times["dependency_$round"]+$times["sensitive_$round"]) -ge 120000){throw 'acl_stage_exceeds_installer_budget'}
    Progress "verify_$round"
    foreach($name in $sensitive){
      $dir=Join-Path $root ($name+'\nested')
      Assert-Private (Join-Path $dir 'existing.bin')
      if([IO.File]::ReadAllText((Join-Path $dir 'existing.bin')) -cne 'public fixture'){throw 'fixture_content_changed'}
      $future=Join-Path $dir "future-$round.bin";[IO.File]::WriteAllText($future,'public fixture');Assert-Private $future
    }
    Assert-Private (Join-Path $root 'upload_outbox\result-1.bin')
    Assert-Private $forensic
    foreach($case in $forensicCases){
      Assert-Private $case.path
      if([Convert]::ToBase64String([IO.File]::ReadAllBytes($case.path)) -cne $case.bytes64){throw 'forensic_fixture_bytes_changed'}
    }
    foreach($dir in @(Get-ChildItem -LiteralPath $forensic -Directory -Recurse)){
      Assert-Private $dir.FullName
    }
    $future=Join-Path $forensic "case-0000\future-$round.bin"
    [IO.File]::WriteAllText($future,'public fixture');Assert-Private $future
    if(@(Get-ChildItem -LiteralPath $forensic -File -Recurse).Count -ne (6287+$round)){throw 'forensic_fixture_population_changed'}
    $times["verify_$round"]=$watch.ElapsedMilliseconds-$start-$times["sensitive_$round"]
  }
  # Fail closed for both the batched file operation and non-queue directories.
  function icacls.exe {$global:LASTEXITCODE=5}
  $refused=$false
  try{Repair-RuntimeFileAcls -Path (Join-Path $root 'evidence')}catch{$refused=$true}
  if(-not $refused){throw 'file_acl_failure_silenced'}
  $refused=$false
  try{Repair-SensitiveRuntimeAcls -Dir $root}catch{$refused=$true}
  if(-not $refused){throw 'non_queue_acl_failure_silenced'}
  # Target the newly covered directory: a failure there must reach the caller.
  # Only these negative cases replace native operations with failing adapters.
  function takeown.exe {$global:LASTEXITCODE=0}
  function icacls.exe {
    $global:LASTEXITCODE=0
    if($args[0] -eq $forensic -and $args -contains $script:failSwitch){
      $script:targetFailureSeen=$true;$global:LASTEXITCODE=5
    }
  }
  foreach($script:failSwitch in @('/inheritance:r','/remove:g','/grant')){
    $script:targetFailureSeen=$false;$refused=$false
    try{Repair-SensitiveRuntimeAcls -Dir $root}catch{$refused=$true}
    if(-not $targetFailureSeen -or -not $refused){throw 'forensic_acl_failure_silenced'}
  }
  $passed=$true
  Progress 'passed'
  @{status='passed';outbox_files=$FileCount;forensic_files=6287;forensic_directories=631;forensic_file_types=$forensicCounts;permission_checks=$checks;forensic_failure_cases=3;times=$times;elapsed_ms=$watch.ElapsedMilliseconds;live_runtime_touched=$false}|ConvertTo-Json -Depth 4 -Compress
}catch{
  [IO.File]::WriteAllText($ProgressPath,(@{stage='failed';completed=$times;error=$_.Exception.Message;line=$_.InvocationInfo.ScriptLineNumber;elapsed_ms=$watch.ElapsedMilliseconds}|ConvertTo-Json -Compress))
  throw
}finally{
  # Unique synthetic tree only; never enumerate or clean the installed Agent.
  if($passed -and (Test-Path -LiteralPath $root)){Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction Continue}
}
