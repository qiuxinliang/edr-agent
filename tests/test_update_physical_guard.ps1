#Requires -Version 5.1
param([Parameter(Mandatory=$true)][string]$UpdaterPath)
$ErrorActionPreference='Stop'
$tokens=$null; $errors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile($UpdaterPath,[ref]$tokens,[ref]$errors)
if($errors.Count){ throw ($errors | ForEach-Object Message | Out-String) }
$function=$ast.Find({param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Assert-UpdateFreeSpace'},$true)
if(-not $function){ throw 'space helper missing' }
$parameter=@($ast.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'MinFreeBytes' })
if($parameter.Count -ne 1){throw 'space parameter missing'}
$bind=[scriptblock]::Create(('param('+ $parameter[0].Extent.Text +')' + "`n" + '$MinFreeBytes'))
[UInt64]$largeLocalFloor=3*[UInt64]1099511627776+24MB
if((& $bind -MinFreeBytes $largeLocalFloor) -ne $largeLocalFloor){throw 'supported derived floor cannot bind'}
# Import only the production guard. Never execute the installer, stop a process,
# or consume disk space to simulate a full volume.
. ([scriptblock]::Create($function.Extent.Text))
[UInt64]$MinFreeBytes=0
Assert-UpdateFreeSpace -Path $env:TEMP -GrowthBytes 4096
Assert-UpdateFreeSpace -Path (Join-Path $env:TEMP 'edr-missing-test-parent\child\file') -GrowthBytes 4096
[UInt64]$MinFreeBytes=[UInt64]::MaxValue
$overflow=$false
try { Assert-UpdateFreeSpace -Path $env:TEMP -GrowthBytes 1 } catch { if($_.Exception.Message -ne 'update space arithmetic overflow'){throw}; $overflow=$true }
if(-not $overflow){throw 'overflow accepted'}
[UInt64]$available=0; [UInt64]$total=0; [UInt64]$free=0
if(-not [FDSecurityUpdateDiskSpace]::GetDiskFreeSpaceExW($env:TEMP,[ref]$available,[ref]$total,[ref]$free)){throw 'native test volume probe failed'}
[UInt64]$MinFreeBytes=$available+1GB
$full=$false
try { Assert-UpdateFreeSpace -Path $env:TEMP -GrowthBytes 1 } catch { if($_.Exception.Message -notlike 'insufficient disk space:*'){throw}; $full=$true }
if(-not $full){throw 'low-space accepted'}
[ordered]@{test='native_updater_physical_guard';powershell=$PSVersionTable.PSVersion.ToString();parser_errors=0;normal_allow=$true;missing_parent_allow=$true;large_local_floor_binds=$true;overflow_rejected=$overflow;real_volume_low_space_rejected=$full;installer_executed=$false} | ConvertTo-Json -Compress
