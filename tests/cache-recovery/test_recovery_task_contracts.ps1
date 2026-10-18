#Requires -Version 5.1
# Pure QA functions only: all Task/CIM/process/control calls below are synthetic.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$DriverSource,[Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9]{64}$')][string]$DriverSha256)
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
$f=Get-Item -LiteralPath $DriverSource -Force
if($f.PSIsContainer -or ($f.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $f.Length -gt 131072 -or (Get-FileHash -LiteralPath $DriverSource -Algorithm SHA256).Hash.ToLowerInvariant() -cne $DriverSha256){throw 'driver_source_pin'}
$t=$null;$e=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($DriverSource,[ref]$t,[ref]$e)
if(@($e).Count -or (Get-FileHash -LiteralPath $DriverSource -Algorithm SHA256).Hash.ToLowerInvariant() -cne $DriverSha256){throw 'driver_source_changed'}
$wanted=@('Need','Regular','SHA','TaskDefinition','TaskProcesses','InstalledTask','RecoveryMode','TaskChildPrelude','TaskWorkerSource','TaskSamplerSource','TaskNativeBinding','TaskDefinitionMatches','TaskAction','RuntimeAction','ServiceObserverError','ServiceChildStatus','ServiceRaw','ReadOwnedBytes','FinishServiceObserver','WaitProcess')
$defs=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -in $wanted},$false))
if($defs.Count -ne $wanted.Count){throw 'task_function_inventory'}
foreach($d in $defs){Invoke-Expression $d.Extent.Text}
$count=0
function Check($Value,[string]$Cause){if(-not $Value){throw $Cause};$script:count++}
function Fails([scriptblock]$Body,[string]$Cause){$caught=$false;try{& $Body|Out-Null}catch{$caught=$true;if(-not $_.Exception.Message.StartsWith($Cause,[StringComparison]::Ordinal)){throw 'unexpected_task_failure'}};Check $caught 'expected_task_failure_missing'}
$dir=Join-Path ([IO.Path]::GetTempPath()) ('edr-task-contract-'+[guid]::NewGuid().ToString('N'));New-Item -ItemType Directory -Path $dir|Out-Null
try {
  $script:install=$dir;$script:agent=Join-Path $dir 'FDSensor.exe';$script:configPath=Join-Path $dir 'agent.toml';$script:configSha256='a'*64;$script:driverSourcePath=$DriverSource
  $launcher=Join-Path $dir 'FDSensorTaskLaunch.ps1'
  $text='$exe = '+"'"+$agent+"'`n"+'$cfg = '+"'"+$configPath+"'`n"+'$wd = '+"'"+$install+"'`n"
  [IO.File]::WriteAllText($launcher,$text,[Text.UTF8Encoding]::new($false))
  $action=[pscustomobject]@{Execute=(Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe');Arguments=('-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "'+$launcher+'"');WorkingDirectory=$dir}
  $task=[pscustomobject]@{TaskPath='\';TaskName='FDSecurityAgent';State='Running';Settings=[pscustomobject]@{Enabled=$true};Principal=[pscustomobject]@{UserId='SYSTEM';LogonType='ServiceAccount';RunLevel='Highest'};Actions=@($action)}
  function Get-ScheduledTask {param($TaskPath,$TaskName,$ErrorAction) if($TaskPath -cne '\' -or $TaskName -cne 'FDSecurityAgent'){throw 'wrong_task_query'};return $script:task}
  function Export-ScheduledTask {param($TaskPath,$TaskName,$ErrorAction) return '<Task>public synthetic definition</Task>'}
  $d=TaskDefinition $install $agent $configPath;Check ($d.system_principal_verified -and $d.action_config_verified -and $d.state -ceq 'Running') 'valid_task_definition'
  $task.Principal.UserId='Everyone';Fails {TaskDefinition $install $agent $configPath} 'task_system_principal';$task.Principal.UserId='SYSTEM'
  $action.Arguments+=' -EncodedCommand public';Fails {TaskDefinition $install $agent $configPath} 'task_action_config_owner';$action.Arguments=$action.Arguments.Replace(' -EncodedCommand public','')
  $task.Actions=@($action,$action);Fails {TaskDefinition $install $agent $configPath} 'exact_task_definition';$task.Actions=@($action)
  [IO.File]::WriteAllText($launcher,$text.Replace("'$configPath'",'$env:PUBLIC'),[Text.UTF8Encoding]::new($false));Fails {TaskDefinition $install $agent $configPath} 'task_launcher_literal_required'
  [IO.File]::WriteAllText($launcher,$text.Replace($configPath,(Join-Path $dir 'wrong.toml')),[Text.UTF8Encoding]::new($false));Fails {TaskDefinition $install $agent $configPath} 'task_launcher_config_binding'
  [IO.File]::WriteAllText($launcher,$text,[Text.UTF8Encoding]::new($false))
  # Read the literal AST value, including PowerShell's doubled single quote;
  # do not evaluate the containing PipelineAst or any launcher statement.
  $quoted=Join-Path $dir "owner'quoted.toml"
  $quotedText=$text.Replace(("'"+$configPath+"'"),("'"+$quoted.Replace("'","''")+"'"))
  [IO.File]::WriteAllText($launcher,$quotedText,[Text.UTF8Encoding]::new($false))
  $q=TaskDefinition $install $agent $quoted;Check $q.action_config_verified 'escaped_single_quote_value'
  Fails {TaskDefinition $install $agent $configPath} 'task_launcher_config_binding'
  $marker=Join-Path $dir 'must-not-be-created.txt'
  $subexpression='$('+'Set-Content -LiteralPath '+"'"+$marker+"' -Value 'public'; 'public')"
  foreach($rhs in @('"public double quoted"','$env:PUBLIC',"'public' | Write-Output",$subexpression)){
    $badText=$text.Replace(("'"+$configPath+"'"),$rhs)
    [IO.File]::WriteAllText($launcher,$badText,[Text.UTF8Encoding]::new($false))
    Fails {TaskDefinition $install $agent $configPath} 'task_launcher_literal_required'
  }
  Check (-not (Test-Path -LiteralPath $marker)) 'launcher_expression_not_executed'
  [IO.File]::WriteAllText($launcher,$text,[Text.UTF8Encoding]::new($false))
  $script:birth=[DateTime]::UtcNow;$script:processRows=@([pscustomobject]@{ExecutablePath=$agent;ProcessId=1234;CommandLine=('"'+$agent+'" --config "'+$configPath+'"')})
  function Get-CimInstance {param($ClassName,$Filter,$ErrorAction) if($ClassName -ceq 'Win32_Service'){return @()};if($ClassName -cne 'Win32_Process' -or $Filter -cne "Name='FDSensor.exe'"){throw 'wrong_process_query'};return $script:processRows}
  function Get-Process {param($Id,$ErrorAction) $script:processCalls++;$when=$script:birth;if($script:changeBirth -and $script:processCalls -eq 2){$when=$when.AddTicks(1)};return [pscustomobject]@{Id=1234;Path=$script:agent;StartTime=$when}}
  $script:processCalls=0;$script:changeBirth=$false
  function ConfigBinding {}
  $rows=@(TaskProcesses $agent $configPath);Check ($rows.Count -eq 1 -and $rows[0].pid -eq 1234) 'one_bound_task_generation'
  $native=InstalledTask ('b'*64);Check ($native.task_config_argv_verified -and $native.runtime_mode -ceq 'scheduled_task') 'installed_task_native_binding'
  # The original launcher uses WindowsPowerShell5.1 Start-Process. Its fixed
  # argv may have terminal SP/TAB; no leading, embedded, CR/LF or extra argv is accepted.
  $canonicalCommandLine=[string]$processRows[0].CommandLine
  foreach($suffix in @(' ',"`t"," `t `t")){
    $processRows[0].CommandLine=$canonicalCommandLine+$suffix
    $padded=@(TaskProcesses $agent $configPath)
    Check ($padded.Count -eq 1 -and $padded[0].pid -eq 1234 -and $padded[0].birth_filetime -ceq $native.birth_filetime) 'task_terminal_ascii_padding_same_generation'
  }
  foreach($badLine in @(
    (' '+$canonicalCommandLine),
    $canonicalCommandLine.Replace(' --config ','  --config '),
    ($canonicalCommandLine+"`r"),($canonicalCommandLine+"`n"),($canonicalCommandLine+"`r`n"),
    ($canonicalCommandLine+' --service'),
    $canonicalCommandLine.Replace($configPath,(Join-Path $dir 'other.toml')),
    $canonicalCommandLine.Replace($agent,(Join-Path $dir 'other.exe')))){
    $processRows[0].CommandLine=$badLine
    Fails {TaskProcesses $agent $configPath} 'task_process_config_argv_binding'
  }
  $processRows[0].CommandLine=$canonicalCommandLine
  $processRows[0].CommandLine+=' --config "public"';Fails {TaskProcesses $agent $configPath} 'task_process_config_argv_binding';$processRows[0].CommandLine='"'+$agent+'" --config "'+$configPath+'"'
  $single=$processRows[0];$processRows=@($single,$single);Fails {TaskProcesses $agent $configPath} 'task_process_ambiguous';$processRows=@($single)
  $script:processCalls=0;$script:changeBirth=$true;Fails {TaskProcesses $agent $configPath} 'task_generation_changed';$script:changeBirth=$false
  foreach($actionName in @('Stop','Start')){
    $body=TaskWorkerSource $actionName $native;$pt=$null;$pe=$null;$null=[Management.Automation.Language.Parser]::ParseInput($body,[ref]$pt,[ref]$pe)
    Check (@($pe).Count -eq 0 -and $body.Contains('ElapsedMilliseconds -lt 30000') -and $body.Contains("-TaskPath '\' -TaskName 'FDSecurityAgent'") -and -not $body.Contains('Stop-Service') -and -not $body.Contains('Stop-Process')) 'task_worker_parse_owner_and_no_force_fallback'
  }
  Fails {TaskWorkerSource 'Stop' $null} 'task_native_closed_fields'
  TaskNativeBinding $native;Check $true 'task_native_closed_positive'
  foreach($actionName in @('Stop','Start')){
    $bad=$native.Clone();$bad.extra='public';Fails {TaskWorkerSource $actionName $bad} 'task_native_closed_fields'
    $bad=$native.Clone();$bad.task_definition_sha256='A'*64;Fails {TaskWorkerSource $actionName $bad} 'task_native_sha_shape'
  }
  $definition=@{definition_sha256=$native.task_definition_sha256;launcher_sha256=$native.task_launcher_sha256}
  TaskDefinitionMatches $definition $native;Check $true 'task_owner_hashes_match'
  $bad=$definition.Clone();$bad.definition_sha256='0'*64;Fails {TaskDefinitionMatches $bad $native} 'task_definition_or_launcher_changed'
  $bad=$definition.Clone();$bad.launcher_sha256='0'*64;Fails {TaskDefinitionMatches $bad $native} 'task_definition_or_launcher_changed'
  $body=TaskSamplerSource;$pt=$null;$pe=$null;$null=[Management.Automation.Language.Parser]::ParseInput($body,[ref]$pt,[ref]$pe)
  Check (@($pe).Count -eq 0 -and $body.Contains('edr.scheduled-task-sample.v1') -and $body.Contains('$i -lt 46') -and $body.Contains('16384') -and -not $body.Contains('checkpoint=')) 'task_sampler_shape_not_scm'
  foreach($mode in @('service','scheduled_task')){Check ((RecoveryMode $mode) -ceq $mode) 'closed_mode_positive'}
  foreach($mode in @('auto','Service',$null,1)){Fails {RecoveryMode $mode} 'closed_recovery_runtime_mode_required'}
  # Reuse real bounded action/capture owner with child objects only; no OS control.
  function FakeChild([string]$Role){
    $v=[pscustomobject]@{Id=1234;StartTime=[DateTime]::UtcNow;HasExited=($Role -ceq 'worker');ExitCode=[int]0;Role=$Role}
    if($Role -ceq 'worker' -and $script:mock -ceq 'nonzero'){$v.ExitCode=[int]7}
    if($Role -ceq 'worker' -and $script:mock -ceq 'null'){$v.ExitCode=$null}
    $v|Add-Member ScriptMethod Refresh {};$v|Add-Member ScriptMethod WaitForExit {param($Ms)$null=$script:waits.Add($Ms);return $true};$v|Add-Member ScriptMethod Kill {$this.HasExited=$true};return $v
  }
  function StartWindowsPowerShellChild {param($ScriptPath,$StandardOutput,$StandardError)
    $role=if($ScriptPath.EndsWith('.task-sampler.ps1')){'sampler'}else{'worker'}
    [IO.File]::WriteAllText($StandardOutput,"public task synthetic`n",[Text.UTF8Encoding]::new($false));[IO.File]::WriteAllBytes($StandardError,[byte[]]@());return (FakeChild $role)
  }
  foreach($mock in @('ok','nonzero','null')){
    $script:mock=$mock;$script:root=Join-Path $dir $mock;New-Item -ItemType Directory -Path $root|Out-Null;$script:taskActionDiagnostics=New-Object Collections.ArrayList;$script:waits=New-Object Collections.ArrayList
    if($mock -ceq 'ok'){TaskAction 'Stop' 'health-failed-upgrade-health-stop' $native;Check ($taskActionDiagnostics[0].observer_complete -and $taskActionDiagnostics[0].sampler.cancel_requested) 'task_observer_complete'}
    elseif($mock -ceq 'nonzero'){Fails {TaskAction 'Stop' 'health-failed-upgrade-health-stop' $native} 'task_control_failed'}
    else{Fails {TaskAction 'Stop' 'health-failed-upgrade-health-stop' $native} 'task_control_exit_unknown'}
    Check ($waits[0] -eq 45000) 'task_exact_outer_wait_45'
  }
} finally {Remove-Item -LiteralPath $dir -Recurse -Force}
if($count -ne 53){throw 'task_pure_check_inventory'}
[Console]::Out.WriteLine(('driver_pure_contracts passed='+$count+' source_sha256='+$DriverSha256+' top_level_executed=false native_child_executed=false'))
