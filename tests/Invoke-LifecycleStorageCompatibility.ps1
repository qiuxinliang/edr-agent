#Requires -Version 5.1
# Test-only orchestration. The installed Agent and embedded updater are never replaced.
function Assert-LifecycleStorageRegular([string]$Path,[long]$Cap=1073741824) {
  $item=Get-Item -LiteralPath $Path -Force -ErrorAction Stop
  if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $item.Length -le 0 -or $item.Length -gt $Cap) {throw 'storage input must be a bounded regular file'}
  for($parent=$item.Directory;$null -ne $parent;$parent=$parent.Parent) {
    if(($parent.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'storage input traverses a reparse point'}
  }
  return $item.FullName
}
function Invoke-LifecycleStorageProcess($Context,[string]$Executable,[string[]]$Arguments,[string]$Label,[int]$Seconds=20) {
  if($Label -cnotmatch '^[a-z0-9-]+$'){throw 'invalid storage process label'}
  $stdout=Join-Path $Context.root ($Label+'.stdout.json');$stderr=Join-Path $Context.root ($Label+'.stderr.log')
  if((Test-Path -LiteralPath $stdout) -or (Test-Path -LiteralPath $stderr)){throw 'storage process evidence already exists'}
  $quoted=@($Arguments|ForEach-Object {
    if($_ -match '["\r\n]' -or $_.EndsWith('\')){throw 'unsupported storage child argument'}
    '"'+$_+'"'
  })
  $process=$null;$failure=$null
  try {
    $process=Start-Process -FilePath $Executable -ArgumentList $quoted -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    $null=$process.Handle
    if(-not $process.WaitForExit($Seconds*1000)){throw 'storage child exceeded its finite deadline'}
    $process.WaitForExit()
    if($process.ExitCode -ne 0) {
      $detail=''
      if((Test-Path -LiteralPath $stderr) -and (Get-Item -LiteralPath $stderr).Length -le 4096){$detail=[IO.File]::ReadAllText($stderr).Trim()}
      throw ('storage child failed: '+$Label+' exit='+$process.ExitCode+' cause='+$detail)
    }
    $null=Assert-LifecycleStorageRegular $stdout 65536
    return ([IO.File]::ReadAllText($stdout)|ConvertFrom-Json)
  } catch {$failure=$_;throw} finally {
    if($process) {
      try {
        if(-not $process.HasExited){$process.Kill();if(-not $process.WaitForExit(5000)){$Context.writer_uncertain=$true;throw 'storage child could not be reaped'}}
      } catch {$Context.writer_uncertain=$true;if(-not $failure){throw}else{Write-Warning 'storage child cleanup failed; original failure preserved'}}
      finally {$process.Dispose()}
    }
  }
}
function Get-LifecycleStoragePython {
  return @'
import hashlib,json,os,re,sqlite3,stat,sys,time,tomllib
from pathlib import Path

def regular(path,cap):
    for p in (path,*path.parents):
        s=p.lstat()
        if stat.S_ISLNK(s.st_mode) or getattr(s,'st_file_attributes',0)&1024:raise ValueError('storage_reparse')
    s=path.stat()
    if not stat.S_ISREG(s.st_mode) or not 0<s.st_size<=cap:raise ValueError('storage_file_bound')
    return s

def config(path,install):
    before=regular(path,131072);raw=path.read_bytes();after=regular(path,131072)
    if len(raw)!=before.st_size or (before.st_size,before.st_mtime_ns)!=(after.st_size,after.st_mtime_ns):raise ValueError('config_changed')
    value=tomllib.loads(raw.decode('utf-8-sig'));offline=value['offline'];agent=value['agent'];install=install.resolve()
    result={'config_sha256':hashlib.sha256(raw).hexdigest(),'tenant_id':agent['tenant_id'],'endpoint_id':agent['endpoint_id']}
    for key in ('tenant_id','endpoint_id'):
        if not re.fullmatch('[A-Za-z0-9_-]{1,63}',result[key]):raise ValueError('fixture_identity')
    for kind,key,budget,retention in (('queue','queue_db_path','max_queue_size_mb','retention_hours'),('cache','evidence_cache_path','evidence_cache_max_size_mb','evidence_cache_retention_hours')):
        target=Path(offline[key])
        if not target.is_absolute():raise ValueError('database_path_not_absolute')
        regular(target,1073741824)
        target=target.resolve();target.relative_to(install)
        if target==install:raise ValueError('database_path_not_file')
        mb=offline[budget];hours=offline[retention]
        selected=offline.get('evidence_cache_selected_retention_hours',0) if kind=='cache' else hours
        if type(selected) is not int or selected<0:raise ValueError('selected_policy')
        if kind=='cache':selected=max(hours,selected or offline['retention_hours'])
        if any(type(x) is not int or not 0<x<=2147483647 for x in (mb,hours,selected)):raise ValueError('storage_policy')
        result[kind]={'path':str(target),'max_mb':mb,'retention_hours':hours,'selected_retention_hours':selected}
    if os.path.normcase(result['cache']['path'])==os.path.normcase(result['queue']['path']):raise ValueError('database_alias')
    return result

mode,config_path,install=sys.argv[1:4];cfg=config(Path(config_path),Path(install))
if mode=='config':print(json.dumps(cfg,separators=(',',':')))
elif mode=='backup':
    expected,kind,destination=sys.argv[4:7]
    if cfg['config_sha256']!=expected or kind not in ('cache','queue'):raise ValueError('backup_binding')
    source=Path(cfg[kind]['path']);destination=Path(destination)
    regular(source,1073741824)
    for p in (destination.parent,*destination.parent.parents):
        if p.is_symlink() or getattr(p.lstat(),'st_file_attributes',0)&1024:raise ValueError('backup_reparse')
    deadline=time.monotonic()+8
    def progress(status,remaining,total):
        if time.monotonic()>deadline or total*65536>17179869184:raise TimeoutError('sqlite_backup_deadline_or_bound')
    # Never copy a live main DB without its WAL. The read transaction/backup API
    # copies one committed SQLite view into a fresh, standalone destination.
    with destination.open('xb'):pass
    src=dst=None
    try:
        src=sqlite3.connect(source.as_uri()+'?mode=ro',uri=True,timeout=.2)
        src.execute('PRAGMA query_only=ON');src.execute('BEGIN');src.execute('SELECT count(*) FROM sqlite_master').fetchone()
        dst=sqlite3.connect(destination,timeout=.2)
        src.backup(dst,pages=128,progress=progress,sleep=.01)
        dst.execute('PRAGMA journal_mode=DELETE').fetchone();dst.close();dst=None
        src.rollback();src.close();src=None
        regular(destination,1073741824)
        if time.monotonic()>deadline:raise TimeoutError('sqlite_backup_deadline')
        print(json.dumps({'schema':'edr.test.storage-snapshot.v1','source':str(source),'config_sha256':expected,'sqlite_backup':True,'source_readonly':True,'sha256':hashlib.sha256(destination.read_bytes()).hexdigest(),'size':destination.stat().st_size},separators=(',',':')))
    finally:
        if dst is not None:dst.close()
        if src is not None:src.close()
else:raise ValueError('snapshot_mode')
'@
}
function Invoke-LifecycleStoragePython($Context,[string[]]$Arguments,[string]$Label) {
  $encoded=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((Get-LifecycleStoragePython)))
  return Invoke-LifecycleStorageProcess $Context $Context.tools.python_path (@('-I','-B','-c',("import base64;exec(base64.b64decode('"+$encoded+"'))"))+$Arguments) $Label
}
function Import-LifecycleStorageTools([string]$InputPath,[string]$Architecture,[string]$PeVerifier) {
  $path=Assert-LifecycleStorageRegular $InputPath 65536;$tools=[IO.File]::ReadAllText($path)|ConvertFrom-Json
  if($tools.schema -cne 'edr.windows.storage-compat-tools.v1' -or $tools.architecture -cne $Architecture){throw 'storage tools identity mismatch'}
  $pins=@{legacy='b51bc3d825e6d5666535463b34eb708201e6fda7';candidate='d4e837790c53861c99d31ee127c55a5ef1f06f4a'}
  foreach($role in @('legacy','candidate')) {
    if($tools.$role.source_commit -cne $pins[$role]){throw 'storage consumer source differs from immutable product source'}
    foreach($kind in @('cache','queue')) {
      $exe=Assert-LifecycleStorageRegular $tools.$role.($kind+'_path')
      $hash=$tools.$role.($kind+'_sha256')
      if($hash -cnotmatch '^[a-f0-9]{64}$' -or (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant() -cne $hash){throw 'storage consumer hash mismatch'}
      & $PeVerifier -Path $exe -Architecture $Architecture | Out-Null
    }
  }
  $null=Assert-LifecycleStorageRegular $tools.python_path
  return $tools
}
function Assert-LifecycleStorageEnvironment {
  foreach($name in @('EDR_QUEUE_PATH','EDR_EVIDENCE_CACHE_PATH')) {
    foreach($scope in @('Process','Machine')) {
      if(-not [string]::IsNullOrEmpty([Environment]::GetEnvironmentVariable($name,$scope))){throw ('storage path override present: '+$name+' '+$scope)}
    }
  }
  $serviceKey='HKLM:\SYSTEM\CurrentControlSet\Services\'+$ServiceName
  if(Test-Path -LiteralPath $serviceKey) {
    $values=(Get-ItemProperty -LiteralPath $serviceKey -ErrorAction Stop).PSObject.Properties['Environment']
    if($values -and @($values.Value|Where-Object{$_ -match '^(?i:EDR_QUEUE_PATH|EDR_EVIDENCE_CACHE_PATH)='}).Count -gt 0){throw 'service storage path override present'}
  }
}
function New-LifecycleStorageChain($Tools,[string]$Name) {
  if($Name -cnotmatch '^[a-z0-9-]+$'){throw 'invalid storage chain name'}
  $root=Join-Path $EvidenceDir ('storage-compat-'+$Name)
  if(Test-Path -LiteralPath $root){throw 'storage chain already exists'}
  [IO.Directory]::CreateDirectory($root)|Out-Null
  $context=@{tools=$Tools;root=$root;config=(Join-Path $InstallDir 'agent.toml');install=$InstallDir;epoch=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds();generation=0;expected=@{cache=@();queue=@()};writer_uncertain=$false}
  Assert-LifecycleStorageEnvironment
  $context.binding=Invoke-LifecycleStoragePython $context @('config',$context.config,$context.install) 'initial-config'
  return $context
}
function Assert-LifecycleStorageBinding($Context) {
  Assert-LifecycleStorageEnvironment
  if((Get-FileHash -LiteralPath $Context.config -Algorithm SHA256).Hash.ToLowerInvariant() -cne $Context.binding.config_sha256){throw 'storage chain configuration changed'}
}
function Get-LifecycleStorageNative {
  $owner=Get-LifecycleRuntimeOwner;$runtime=Get-LifecycleRuntimeProcess
  if($runtime.State -cne 'Running' -or $runtime.ProcessId -le 0){throw 'storage action requires running original owner'}
  $process=Get-Process -Id $runtime.ProcessId -ErrorAction Stop
  $null=$process.Handle
  try {
    $rows=@(Get-CimInstance Win32_Process -Filter ('ProcessId='+$runtime.ProcessId) -ErrorAction Stop)
    $config=Join-Path $InstallDir 'agent.toml'
    $pattern='(?i)(?<!\S)--config\s+"'+[regex]::Escape($config)+'"(?=\s|$)'
    if($process.HasExited -or $process.Path -ine (Join-Path $InstallDir 'FDSensor.exe') -or $rows.Count -ne 1 -or
        $rows[0].ExecutablePath -ine $process.Path -or [regex]::Matches([string]$rows[0].CommandLine,$pattern).Count -ne 1 -or
        [regex]::Matches([string]$rows[0].CommandLine,'(?i)(?<!\S)--config(?=\s)').Count -ne 1 -or
        [Math]::Abs(($process.StartTime.ToUniversalTime()-$rows[0].CreationDate.ToUniversalTime()).Ticks) -gt 10){throw 'storage runtime config/process binding mismatch'}
    return @{process=$process;owner=($owner|ConvertTo-Json -Depth 12 -Compress);pid=$process.Id;created_utc=$process.StartTime.ToUniversalTime().ToString('o')}
  } catch {$process.Dispose();throw}
}
function Assert-LifecycleStorageQuiescent($Native) {
  if(-not $Native.process.HasExited){throw 'original runtime process has not exited'}
  $rows=@(Get-CimInstance Win32_Process -Filter "Name='FDSensor.exe'" -ErrorAction Stop)
  if(@($rows|Where-Object{-not $_.ExecutablePath -or $_.ExecutablePath -ieq (Join-Path $InstallDir 'FDSensor.exe')}).Count -ne 0){throw 'storage writer remains or its path is unknown'}
  if($RuntimeMode -ceq 'service') {
    $service=Get-Service -Name $ServiceName -ErrorAction Stop
    if($service.Status -cne 'Stopped'){throw 'storage service is not stopped'}
  } else {
    $task=Get-ScheduledTask -TaskName $ServiceName -TaskPath '\' -ErrorAction Stop
    if($task.State -cne 'Ready'){throw 'storage task is not stopped'}
  }
}
function Invoke-LifecycleStorageRuntimeAction($Context,[ValidateSet('Stop','Start')][string]$Action,[string]$Label) {
  if($ServiceName -cnotmatch '^[A-Za-z0-9_-]+$'){throw 'unsafe lifecycle owner name'}
  if($RuntimeMode -ceq 'service') {
    $body=('$service=Get-Service -Name ''{0}'' -ErrorAction Stop;{1}-Service -InputObject $service -ErrorAction Stop;$service.WaitForStatus(''{2}'',[TimeSpan]::FromSeconds(30))' -f $ServiceName,$Action,$(if($Action -ceq 'Stop'){'Stopped'}else{'Running'}))
  } else {$body=('{0}-ScheduledTask -TaskName ''{1}'' -TaskPath ''\'' -ErrorAction Stop' -f $Action,$ServiceName)}
  $source='$ErrorActionPreference=''Stop'';$ProgressPreference=''SilentlyContinue'';$env:PSModulePath=$PSHOME+''\Modules'';'+$body+';[Console]::Out.WriteLine(''{"status":"completed"}'')'
  $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($source))
  $result=Invoke-LifecycleStorageProcess $Context (Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe') @('-NoProfile','-NonInteractive','-EncodedCommand',$encoded) $Label 35
  if($result.status -cne 'completed'){throw 'storage runtime action did not complete'}
}
function Assert-LifecycleStorageReceipt($Context,$Receipt,[string]$Role,[string]$Kind,[string]$Action,[int]$Generation) {
  $policy=$Context.binding.$Kind
  $count=if($Action -ceq 'read'){$Generation*2}else{2}
  if($Receipt.schema -cne 'edr.test.storage-compat.v1' -or $Receipt.source_commit -cne $Context.tools.$Role.source_commit -or
      $Receipt.platform -cne 'Windows' -or $Receipt.native_windows -ne $true -or $Receipt.process_machine -ne 0 -or
      $Receipt.native_machine -ne $(if($Context.tools.architecture -ceq 'amd64'){0x8664}else{0xaa64}) -or
      $Receipt.owner -cne $(if($Kind -ceq 'cache'){'evidence_cache'}else{'queue'}) -or $Receipt.action -cne $Action -or
      $Receipt.input_origin -cne 'synthetic_records_via_original_storage_owner_api' -or $Receipt.direct_sql_writes -ne $false -or
      $Receipt.network -ne $false -or $Receipt.sensor_capture -ne $false -or $Receipt.epoch -ne $Context.epoch -or
      $Receipt.tenant_id -cne $Context.binding.tenant_id -or $Receipt.endpoint_id -cne $Context.binding.endpoint_id -or
      $Receipt.storage_policy.max_mb -ne $policy.max_mb -or $Receipt.storage_policy.retention_hours -ne $policy.retention_hours -or
      $Receipt.storage_policy.selected_retention_hours -ne $policy.selected_retention_hours -or @($Receipt.records).Count -ne $count){throw 'storage consumer receipt identity, policy or record count mismatch'}
  if($Kind -ceq 'queue' -and ($Receipt.real_codec -ne $true -or $Receipt.server_ack -ne $false -or
      $Receipt.delivery_clock_advance_s -ne $(if($Action -ceq 'read'){301}else{0}) -or
      $Receipt.virtual_retry_eligibility_only -ne ($Action -ceq 'read') -or $Receipt.read_by_poll_drain -ne ($Action -ceq 'read'))){throw 'queue consumer codec/ACK/clock contract mismatch'}
  if($Kind -ceq 'cache' -and $Receipt.read_from_reopened_sqlite -ne ($Action -ceq 'read')){throw 'cache consumer did not reopen persistent SQLite'}
  $key=if($Kind -ceq 'cache'){'pid'}else{'batch_id'}
  if(@($Receipt.records|Select-Object -ExpandProperty $key -Unique).Count -ne $count){throw 'duplicate storage record identity'}
  if($Action -ceq 'read') {
    if(@($Context.expected[$Kind]).Count -ne $count){throw 'missing original storage writer receipt'}
    foreach($expected in $Context.expected[$Kind]) {
      $matches=@($Receipt.records|Where-Object{$_.$key -ceq $expected.$key})
      if($matches.Count -ne 1 -or @($matches[0].PSObject.Properties).Count -ne @($expected.PSObject.Properties).Count){throw 'storage record identity or field count changed'}
      foreach($field in $expected.PSObject.Properties) {
        if(($matches[0].($field.Name)|ConvertTo-Json -Compress) -cne ($field.Value|ConvertTo-Json -Compress)){throw ('storage record field changed: '+$field.Name)}
      }
    }
  }
}
function Invoke-LifecycleStorageOwner($Context,[string]$Role,[string]$Kind,[string]$Action,[string]$Database,[int]$Generation,[string]$Label) {
  Assert-LifecycleStorageBinding $Context
  $exe=$Context.tools.$Role.($Kind+'_path');$hash=$Context.tools.$Role.($Kind+'_sha256')
  $null=Assert-LifecycleStorageRegular $exe
  if((Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant() -cne $hash){throw 'storage consumer changed after admission'}
  $policy=$Context.binding.$Kind
  $arguments=@($Action,$Database,[string]$Context.epoch,[string]$Generation,$Context.binding.tenant_id,$Context.binding.endpoint_id,[string]$policy.max_mb,[string]$policy.retention_hours,[string]$policy.selected_retention_hours)
  $result=Invoke-LifecycleStorageProcess $Context $exe $arguments $Label
  Assert-LifecycleStorageReceipt $Context $result $Role $Kind $Action $Generation
  return $result
}
function Write-LifecycleStorageFixture($Context,[ValidateSet('seed','append')][string]$Action,[string]$Stage) {
  Assert-LifecycleStorageBinding $Context
  $generation=if($Action -ceq 'seed'){1}else{2};$role=if($Action -ceq 'seed'){'legacy'}else{'candidate'}
  if($Context.generation -ne ($generation-1)){throw 'storage generation transition is not sequential'}
  $native=Get-LifecycleStorageNative;$stopped=$false;$failure=$null
  try {
    Invoke-LifecycleStorageRuntimeAction $Context 'Stop' ($Stage+'-stop')
    if(-not $native.process.WaitForExit(30000)){throw 'original runtime did not exit before storage write'}
    Assert-LifecycleStorageQuiescent $native;$stopped=$true
    foreach($kind in @('cache','queue')) {
      Assert-LifecycleStorageQuiescent $native
      $result=Invoke-LifecycleStorageOwner $Context $role $kind $Action $Context.binding.$kind.path $generation ($Stage+'-'+$kind+'-'+$Action)
      $Context.expected[$kind]=@($Context.expected[$kind])+@($result.records)
    }
    $Context.generation=$generation
  } catch {$failure=$_;throw} finally {
    try {
      if($stopped -and -not $Context.writer_uncertain) {
        Invoke-LifecycleStorageRuntimeAction $Context 'Start' ($Stage+'-restart')
        $clock=[Diagnostics.Stopwatch]::StartNew()
        do {$runtime=Get-LifecycleRuntimeProcess;if($runtime.State -ceq 'Running' -and $runtime.ProcessId -gt 0){break};Start-Sleep -Milliseconds 200}while($clock.Elapsed.TotalSeconds -lt 30)
        if($runtime.State -cne 'Running' -or $runtime.ProcessId -le 0 -or (Get-LifecycleRuntimeOwner|ConvertTo-Json -Depth 12 -Compress) -cne $native.owner){throw 'storage write did not restore original runtime owner'}
        Assert-LifecycleStorageBinding $Context
      }
    } catch {if(-not $failure){throw}else{Write-Warning ('Storage owner restart also failed: '+$_.Exception.Message)}}
    finally {$native.process.Dispose()}
  }
}
function Test-LifecycleStorageReadback($Context,[string]$Stage) {
  Assert-LifecycleStorageBinding $Context
  if($Stage -cnotmatch '^[a-z0-9-]+$' -or $Context.generation -notin @(1,2)){throw 'invalid storage readback stage'}
  $directory=Join-Path $Context.root $Stage
  if(Test-Path -LiteralPath $directory){throw 'storage readback stage already exists'}
  [IO.Directory]::CreateDirectory($directory)|Out-Null
  $native=Get-LifecycleStorageNative
  try { foreach($kind in @('cache','queue')) {
    $snapshot=Join-Path $directory ($kind+'.snapshot.db')
    $proof=Invoke-LifecycleStoragePython $Context @('backup',$Context.config,$Context.install,$Context.binding.config_sha256,$kind,$snapshot) ($Stage+'-'+$kind+'-snapshot')
    if($proof.schema -cne 'edr.test.storage-snapshot.v1' -or $proof.sqlite_backup -ne $true -or $proof.source_readonly -ne $true -or
        $proof.source -ine $Context.binding.$kind.path -or $proof.config_sha256 -cne $Context.binding.config_sha256 -or
        $proof.sha256 -cne (Get-FileHash -LiteralPath $snapshot -Algorithm SHA256).Hash.ToLowerInvariant()){throw 'actual storage snapshot binding failed'}
    foreach($role in @('legacy','candidate')) {
      $copy=Join-Path $directory ($kind+'.'+$role+'.db')
      Copy-Item -LiteralPath $snapshot -Destination $copy -ErrorAction Stop
      if((Get-FileHash -LiteralPath $copy -Algorithm SHA256).Hash.ToLowerInvariant() -cne $proof.sha256){throw 'consumer copy differs from sealed snapshot'}
      $null=Invoke-LifecycleStorageOwner $Context $role $kind 'read' $copy $Context.generation ($Stage+'-'+$kind+'-'+$role+'-read')
    }
    if((Get-FileHash -LiteralPath $snapshot -Algorithm SHA256).Hash.ToLowerInvariant() -cne $proof.sha256){throw 'sealed storage snapshot was modified'}
  }
  if($native.process.HasExited){throw 'bound runtime exited during storage readback'}
  Assert-LifecycleStorageBinding $Context
  Add-Evidence $Stage 'verified' ('actual_configured_databases=true owner_api_readback=legacy,candidate generations='+$Context.generation+' input_origin=synthetic_owner_api queue_retry_clock=disposable_copy_only')
  } finally {$native.process.Dispose()}
}
