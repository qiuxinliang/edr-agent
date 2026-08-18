#Requires -Version 5.1
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [ValidateSet('win-x64', 'win-arm64')]
  [string] $RuntimeIdentifier,
  [ValidateSet('true', 'false')]
  [string] $SelfContained = 'true',
  [ValidateSet('true', 'false')]
  [string] $PublishReadyToRun = 'false',
  [string] $Configuration = 'Release',
  [switch] $VerifyPublish,
  [string] $RepositoryRoot = ""
)

$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) {
  $RepositoryRoot = Split-Path -Parent $PSScriptRoot
}
$RepositoryRoot = [IO.Path]::GetFullPath($RepositoryRoot)
$SelfContained = $SelfContained.ToLowerInvariant()
$PublishReadyToRun = $PublishReadyToRun.ToLowerInvariant()
if ([string]::IsNullOrWhiteSpace($Configuration)) {
  throw 'Setup UI Configuration must not be empty'
}

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
  "-p:SelfContained=$SelfContained",
  "-p:PublishReadyToRun=$PublishReadyToRun",
  '-p:PublishSingleFile=false',
  "-p:Configuration=$Configuration",
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

Write-Host "Setup UI locked restore verified: runtime=$RuntimeIdentifier selfContained=$SelfContained readyToRun=$PublishReadyToRun configuration=$Configuration lock=$lock source=$nugetConfig"

if ($VerifyPublish) {
  $smokeId = [Guid]::NewGuid().ToString('N')
  $smokePublishDir = Join-Path ([System.IO.Path]::GetTempPath()) "edr-setup-ui-publish-smoke-$RuntimeIdentifier-$smokeId"
  $smokeLog = Join-Path ([System.IO.Path]::GetTempPath()) "edr-setup-ui-publish-smoke-$RuntimeIdentifier-$smokeId.log"
  try {
    $publishArgs = @(
      $project,
      '-c', $Configuration,
      "-p:RuntimeIdentifier=$RuntimeIdentifier",
      '--self-contained', $SelfContained,
      "-p:PublishReadyToRun=$PublishReadyToRun",
      '-p:PublishSingleFile=false',
      '-p:DebugType=None',
      '-p:DebugSymbols=false',
      '--no-restore',
      '--verbosity', 'normal',
      '-o', $smokePublishDir
    )
    & dotnet publish @publishArgs 2>&1 | Tee-Object -FilePath $smokeLog
    $publishExitCode = $LASTEXITCODE
    if ($publishExitCode -ne 0) {
      Write-Host '---- Setup UI publish smoke diagnostic (last 160 lines) ----'
      Get-Content -LiteralPath $smokeLog -Tail 160 | ForEach-Object { Write-Host $_ }
      throw "Setup UI publish smoke failed for $RuntimeIdentifier with exit $publishExitCode; diagnostic log: $smokeLog"
    }
    $smokeExe = Join-Path $smokePublishDir 'FDSecuritySetupUI.exe'
    if (-not (Test-Path -LiteralPath $smokeExe -PathType Leaf)) {
      throw "Setup UI publish smoke did not produce FDSecuritySetupUI.exe for $RuntimeIdentifier"
    }
    Write-Host "Setup UI publish smoke verified: runtime=$RuntimeIdentifier output=$smokeExe"
  } finally {
    Remove-Item -LiteralPath $smokePublishDir -Recurse -Force -ErrorAction SilentlyContinue
  }
}
