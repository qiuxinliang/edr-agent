#Requires -Version 5.1
[CmdletBinding()]
param(
  [string] $RepositoryRoot = ""
)

$ErrorActionPreference = "Stop"
if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) {
  $RepositoryRoot = Split-Path -Parent $PSScriptRoot
}
$RepositoryRoot = [IO.Path]::GetFullPath($RepositoryRoot)

function Read-JsonFile([string] $RelativePath) {
  $path = Join-Path $RepositoryRoot $RelativePath
  if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
    throw "Required dependency lock file is missing: $RelativePath"
  }
  return [IO.File]::ReadAllText($path) | ConvertFrom-Json
}

$dependencyLock = Read-JsonFile "dependencies.lock.json"
if ([string]$dependencyLock.schema -ne "edr.native-dependencies.lock.v1") {
  throw "Unsupported dependency lock schema: $($dependencyLock.schema)"
}
if ([string]$dependencyLock.visual_studio.generation -ne "2022" -or
    [string]$dependencyLock.visual_studio.version_range -ne "[17.0,18.0)") {
  throw "Visual Studio must be locked to generation 2022 and range [17.0,18.0)"
}

$globalJson = Read-JsonFile "global.json"
if ([string]$globalJson.sdk.version -ne [string]$dependencyLock.dotnet_sdk.version) {
  throw "global.json SDK version does not match dependencies.lock.json"
}
if ([string]$globalJson.sdk.rollForward -ne [string]$dependencyLock.dotnet_sdk.roll_forward -or
    [string]$globalJson.sdk.rollForward -ne "disable") {
  throw "The .NET SDK lock must disable roll-forward in both lock files"
}

$nugetConfigPath = Join-Path $RepositoryRoot "NuGet.Config"
if (-not (Test-Path -LiteralPath $nugetConfigPath -PathType Leaf)) {
  throw "Repository NuGet source policy is missing: $nugetConfigPath"
}
[xml]$nugetConfig = [IO.File]::ReadAllText($nugetConfigPath)
$packageSources = $nugetConfig.configuration.packageSources
$configuredSources = @($packageSources.add)
if ($null -eq $packageSources.clear -or $configuredSources.Count -ne 1 -or
    [string]$configuredSources[0].key -ne "nuget.org" -or
    [string]$configuredSources[0].value -ne "https://api.nuget.org/v3/index.json") {
  throw "NuGet source policy must clear runner-local feeds and use only https://api.nuget.org/v3/index.json"
}

$vcpkgManifest = Read-JsonFile "vcpkg.json"
$vcpkgBaseline = [string]$vcpkgManifest.'builtin-baseline'
if ($vcpkgBaseline -notmatch '^[0-9a-f]{40}$' -or
    $vcpkgBaseline -ne [string]$dependencyLock.vcpkg.builtin_baseline) {
  throw "vcpkg builtin-baseline is invalid or inconsistent with dependencies.lock.json"
}

$projectPath = Join-Path $RepositoryRoot "install\windows-setup-ui\EDRAgent.SetupUi.csproj"
[xml]$project = [IO.File]::ReadAllText($projectPath)
$packageReferences = @($project.Project.ItemGroup.PackageReference | Where-Object { $_.Include })
if ($packageReferences.Count -eq 0) {
  throw "Setup UI project has no package references to validate"
}

$setupUiFramework = "net8.0-windows10.0.17763"
$setupUiLocks = @(
  @{ Path = "install\windows-setup-ui\packages.lock.json"; Target = $setupUiFramework },
  @{ Path = "install\windows-setup-ui\packages.win-x64.lock.json"; Target = "$setupUiFramework/win-x64" },
  @{ Path = "install\windows-setup-ui\packages.win-arm64.lock.json"; Target = "$setupUiFramework/win-arm64" }
)
foreach ($setupUiLockSpec in $setupUiLocks) {
  $nugetLock = Read-JsonFile $setupUiLockSpec.Path
  $lockTargets = @($nugetLock.dependencies.PSObject.Properties)
  if ([int]$nugetLock.version -ne 1 -or $lockTargets.Count -ne 1 -or
      [string]$lockTargets[0].Name -ne [string]$setupUiLockSpec.Target) {
    throw "Setup UI NuGet lock '$($setupUiLockSpec.Path)' must contain exactly runtime graph '$($setupUiLockSpec.Target)'"
  }
  $lockedFramework = $lockTargets[0].Value
  foreach ($packageReference in $packageReferences) {
    $name = [string]$packageReference.Include
    $version = [string]$packageReference.Version
    $locked = $lockedFramework.PSObject.Properties[$name].Value
    if ($null -eq $locked -or [string]$locked.type -ne "Direct" -or
        [string]$locked.resolved -ne $version -or
        [string]$locked.contentHash -notmatch '^[A-Za-z0-9+/]+={0,2}$') {
      throw "Setup UI package '$name' is not exactly bound by $($setupUiLockSpec.Path)"
    }
  }
}
$projectText = [IO.File]::ReadAllText($projectPath)
$requiredPortableLockSelector = '<NuGetLockFilePath Condition="''$(RuntimeIdentifier)'' == ''''">packages.lock.json</NuGetLockFilePath>'
$requiredRuntimeLockSelectors = @(
  '<NuGetLockFilePath Condition="''$(RuntimeIdentifier)'' == ''win-x64''">packages.win-x64.lock.json</NuGetLockFilePath>',
  '<NuGetLockFilePath Condition="''$(RuntimeIdentifier)'' == ''win-arm64''">packages.win-arm64.lock.json</NuGetLockFilePath>'
)
if ($projectText -notmatch '<RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>' -or
    $projectText -notmatch '<RestoreLockedMode>true</RestoreLockedMode>' -or
    -not $projectText.Contains($requiredPortableLockSelector) -or
    @($requiredRuntimeLockSelectors | Where-Object { -not $projectText.Contains($_) }).Count -ne 0) {
  throw "Setup UI restore must select its committed RID lock during MSBuild project evaluation and preserve packages.lock.json for portable restores"
}

$releaseRequirements = Join-Path $RepositoryRoot "requirements-release.txt"
if (-not (Test-Path -LiteralPath $releaseRequirements -PathType Leaf) -or
    -not ([IO.File]::ReadAllText($releaseRequirements) -match '(?m)^cryptography==44\.0\.3\s*$')) {
  throw "Release P0 encryption dependency must pin cryptography==44.0.3 in requirements-release.txt"
}

Write-Host "Dependency locks verified: VS2022, .NET $($globalJson.sdk.version), vcpkg $vcpkgBaseline, NuGet source policy and RID closures, P0 cryptography"
