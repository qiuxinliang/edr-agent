#Requires -Version 5.1
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [ValidateSet('win-x64', 'win-arm64')]
  [string] $RuntimeIdentifier,
  [string] $RepositoryRoot = ""
)

$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) {
  $RepositoryRoot = Split-Path -Parent $PSScriptRoot
}
$RepositoryRoot = [IO.Path]::GetFullPath($RepositoryRoot)

$project = Join-Path $RepositoryRoot 'install\windows-setup-ui\EDRAgent.SetupUi.csproj'
$nugetConfig = Join-Path $RepositoryRoot 'NuGet.Config'
$lockRelative = 'install\windows-setup-ui\packages.{0}.lock.json' -f $RuntimeIdentifier
$lock = Join-Path $RepositoryRoot $lockRelative
foreach ($requiredPath in @($project, $nugetConfig, $lock)) {
  if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
    throw "required Setup UI restore input is missing: $requiredPath"
  }
}

$lockJson = Get-Content -LiteralPath $lock -Raw | ConvertFrom-Json
$baseGraph = 'net8.0-windows10.0.17763'
$runtimeGraph = "$baseGraph/$RuntimeIdentifier"
$lockGraphs = @($lockJson.dependencies.PSObject.Properties | ForEach-Object { [string]$_.Name })
if ($lockGraphs.Count -ne 1 -or $lockGraphs[0] -ne $runtimeGraph) {
  throw "Setup UI NuGet lock must contain exactly runtime graph '$runtimeGraph' in $lock"
}

$restoreArgs = @(
  $project,
  "-p:RuntimeIdentifier=$RuntimeIdentifier",
  '--configfile', $nugetConfig,
  '--locked-mode',
  '--verbosity', 'normal'
)
$restoreLog = Join-Path ([System.IO.Path]::GetTempPath()) "edr-setup-ui-locked-restore-$RuntimeIdentifier.log"
& dotnet restore @restoreArgs 2>&1 | Tee-Object -FilePath $restoreLog
$restoreExitCode = $LASTEXITCODE
if ($restoreExitCode -ne 0) {
  Write-Host '---- Setup UI locked restore diagnostic (last 160 lines) ----'
  Get-Content -LiteralPath $restoreLog -Tail 160 | ForEach-Object { Write-Host $_ }
  throw "Setup UI locked restore failed for $RuntimeIdentifier with exit $restoreExitCode; diagnostic log: $restoreLog"
}

Write-Host "Setup UI locked restore verified: runtime=$RuntimeIdentifier lock=$lock source=$nugetConfig"
