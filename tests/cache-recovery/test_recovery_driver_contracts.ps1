#Requires -Version 5.1
# Pure local function tests: no SCM, native child, installer, Agent, or network.
[CmdletBinding()]
param(
  [string]$DriverSource=(Join-Path $PSScriptRoot 'windows_cache_recovery_ci.ps1'),
  [Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9]{64}$')][string]$DriverSha256
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$source=$DriverSource
$sourceFile=Get-Item -LiteralPath $source -Force
if ($sourceFile.PSIsContainer -or ($sourceFile.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $sourceFile.Length -gt 65536 -or (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant() -cne $DriverSha256) {throw 'driver_source_pin'}
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($source,[ref]$tokens,[ref]$errors)
if (@($errors).Count) {throw 'driver_parse_failed'}
if ((Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant() -cne $DriverSha256) {throw 'driver_source_changed'}
$wanted=@('Need','Regular','SHA','ReadBounded','ConfigBinding','WaitProcess')
$functions=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -in $wanted},$false))
if ($functions.Count -ne $wanted.Count) {throw 'function_inventory'}
# Only these source-owned function definitions are loaded, never driver top-level.
foreach($function in $functions) {Invoke-Expression $function.Extent.Text}
$count=0
function Fails([scriptblock]$Body,[string]$Prefix) {
  $caught=$false
  try {& $Body | Out-Null} catch {
    $caught=$true
    if (-not $_.Exception.Message.StartsWith($Prefix,[StringComparison]::Ordinal)) {throw 'unexpected_failure_type'}
    if ($_.Exception.Message.Contains('unexported-test-message')) {throw 'raw_cleanup_message_leaked'}
  }
  if (-not $caught) {throw 'expected_failure_missing'}
  $script:count++
}
$dir=Join-Path ([IO.Path]::GetTempPath()) ('edr-driver-contract-'+[Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $dir | Out-Null
try {
  $configPath=Join-Path $dir 'public.toml'
  $expectedConfigPairs=@(@('endpoint_id','public-synthetic'),@('tenant_id','synthetic'),@('evidence_cache_path',(Join-Path $dir 'cache.db')))
  $lines=@($expectedConfigPairs | ForEach-Object {$_[0]+' = "'+$_[1].Replace('\','\\')+'"'})
  $original=($lines -join "`n")+"`n"
  [IO.File]::WriteAllText($configPath,$original,[Text.UTF8Encoding]::new($false))
  $configSha256=SHA $configPath;ConfigBinding;$count++
  [IO.File]::AppendAllText($configPath,'# changed')
  Fails {ConfigBinding} 'fixture_configuration_hash_changed'
  [IO.File]::WriteAllText($configPath,$original.Replace('public-synthetic','wrong-public'),[Text.UTF8Encoding]::new($false))
  $configSha256=SHA $configPath
  Fails {ConfigBinding} 'fixture_configuration_scalar_binding'
  [IO.File]::WriteAllText($configPath,($original+'endpoint_id = "public-synthetic"'),[Text.UTF8Encoding]::new($false))
  $configSha256=SHA $configPath
  Fails {ConfigBinding} 'fixture_configuration_scalar_binding'
  $normal=[pscustomobject]@{ExitCode=7}
  $normal | Add-Member ScriptMethod WaitForExit {param($unused) return $true}
  $normal | Add-Member ScriptMethod Refresh {}
  if ((WaitProcess $normal 1 'unused') -ne 7) {throw 'exit_code_contract'};$count++
  $clean=[pscustomobject]@{WaitCount=0;Killed=$false}
  $clean | Add-Member ScriptMethod WaitForExit {param($unused) $this.WaitCount++;return $this.WaitCount -gt 1}
  $clean | Add-Member ScriptMethod Kill {$this.Killed=$true}
  Fails {WaitProcess $clean 1 'synthetic_timeout'} 'synthetic_timeout'
  if (-not $clean.Killed) {throw 'owned_kill_not_called'}
  $bad=[pscustomobject]@{}
  $bad | Add-Member ScriptMethod WaitForExit {param($unused) return $false}
  $bad | Add-Member ScriptMethod Kill {throw [InvalidOperationException]::new('unexported-test-message')}
  Fails {WaitProcess $bad 1 'synthetic_timeout'} 'synthetic_timeout;cleanup_unknown_type='
  $unknown=[pscustomobject]@{}
  $unknown | Add-Member ScriptMethod WaitForExit {param($unused) return $false}
  $unknown | Add-Member ScriptMethod Kill {}
  Fails {WaitProcess $unknown 1 'synthetic_timeout'} 'synthetic_timeout;cleanup_unknown_type=System.TimeoutException'
  Write-Output ('driver_pure_contracts passed='+$count+' source_sha256='+$DriverSha256+' top_level_executed=false native_child_executed=false')
} finally {Remove-Item -LiteralPath $dir -Recurse -Force}
