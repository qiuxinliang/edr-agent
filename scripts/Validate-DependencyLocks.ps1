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

$vcpkgManifest = Read-JsonFile "vcpkg.json"
$vcpkgBaseline = [string]$vcpkgManifest.'builtin-baseline'
if ($vcpkgBaseline -notmatch '^[0-9a-f]{40}$' -or
    $vcpkgBaseline -ne [string]$dependencyLock.vcpkg.builtin_baseline) {
  throw "vcpkg builtin-baseline is invalid or inconsistent with dependencies.lock.json"
}

$onnxVersion = [string]$dependencyLock.onnxruntime.version
if ($onnxVersion -notmatch '^\d+\.\d+\.\d+$') {
  throw "Invalid ONNX Runtime version in dependencies.lock.json"
}
foreach ($architecture in @("x64", "arm64")) {
  $archive = $dependencyLock.onnxruntime.archives.$architecture
  $expectedName = "onnxruntime-win-$architecture-$onnxVersion.zip"
  if ([string]$archive.name -ne $expectedName) {
    throw "ONNX Runtime archive name mismatch for $architecture"
  }
  if ([Int64]$archive.size_bytes -le 0) {
    throw "ONNX Runtime archive size is not locked for $architecture"
  }
  if ([string]$archive.sha256 -notmatch '^[0-9a-f]{64}$') {
    throw "ONNX Runtime archive SHA256 is not locked for $architecture"
  }
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
    throw "Setup UI NuGet lock '$($setupUiLockSpec.Path)' must contain exactly target '$($setupUiLockSpec.Target)'"
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
$requiredRidLockSelector = '<NuGetLockFilePath Condition="''$(RuntimeIdentifier)'' != ''''">packages.$(RuntimeIdentifier).lock.json</NuGetLockFilePath>'
if ($projectText -notmatch '<RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>' -or
    $projectText -notmatch '<RestoreLockedMode>true</RestoreLockedMode>' -or
    -not $projectText.Contains($requiredRidLockSelector)) {
  throw "Setup UI restore must require committed per-RID NuGet locks"
}

Write-Host "Dependency locks verified: VS2022, .NET $($globalJson.sdk.version), vcpkg $vcpkgBaseline, ONNX Runtime $onnxVersion, NuGet locked mode"
