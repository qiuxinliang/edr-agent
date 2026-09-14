#Requires -Version 5.1
[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

function Assert-VsHostTest([bool] $Condition, [string] $Message) {
  if (-not $Condition) { throw "VS2022 host architecture test failed: $Message" }
}

$productionScript = Join-Path $PSScriptRoot "..\scripts\Initialize-VS2022Environment.ps1"
$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$tokens = $null
$parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($productionScript, [ref]$tokens, [ref]$parseErrors)
if (@($parseErrors).Count -ne 0) {
  throw "production script has $(@($parseErrors).Count) parser error(s)"
}
foreach ($functionAst in @($ast.FindAll({
      param($node)
      $node -is [Management.Automation.Language.FunctionDefinitionAst]
    }, $true))) {
  Invoke-Expression $functionAst.Extent.Text
}

$actualHostArchitecture = Get-WindowsHostArchitecture
Assert-VsHostTest ($actualHostArchitecture -in @("x64", "arm64")) `
  "the real Windows host probe must return a supported architecture"
$actualNativeArchitecture = Get-WindowsNativeMachineArchitecture
Assert-VsHostTest ($actualHostArchitecture -eq $actualNativeArchitecture) `
  "the selected host must follow the Windows kernel native architecture"
$productionSource = [IO.File]::ReadAllText($productionScript)
Assert-VsHostTest ($productionSource -match 'IsWow64Process2') `
  "host detection must use the Windows native machine architecture"
Assert-VsHostTest ($productionSource -notmatch 'GetNativeSystemInfo|PROCESSOR_ARCHITEW6432|RuntimeInformation\]::OSArchitecture') `
  "host detection must not fall back to emulation-sensitive architecture sources"
Assert-VsHostTest ($productionSource -match '-host_arch=\{2\}') `
  "VsDevCmd must receive the detected host architecture"
Assert-VsHostTest ($productionSource -notmatch '-host_arch=x64') `
  "VsDevCmd must not retain the fixed x64 host"

& {
  function Get-WindowsNativeMachineArchitecture { return "arm64" }
  Assert-VsHostTest ((Get-WindowsHostArchitecture) -eq "arm64") `
    "the Windows native API result must override emulated process architecture fields"
}

Assert-VsHostTest `
  ((Resolve-WindowsNativeMachineArchitecture -NativeMachine 0xAA64) -eq "arm64") `
  "IMAGE_FILE_MACHINE_ARM64 must select an ARM64 host"
Assert-VsHostTest `
  ((Resolve-WindowsNativeMachineArchitecture -NativeMachine 0x8664) -eq "x64") `
  "IMAGE_FILE_MACHINE_AMD64 must select an x64 host"
$unsupportedFailed = $false
try {
  [void](Resolve-WindowsNativeMachineArchitecture -NativeMachine 0x014c)
} catch {
  $unsupportedFailed = $_.Exception.Message -match "Unsupported Windows native machine architecture"
}
Assert-VsHostTest $unsupportedFailed "unsupported x86 hosts must fail before Visual Studio discovery"

$testRoot = Join-Path ([IO.Path]::GetTempPath()) ("edr-vs-host-" + [Guid]::NewGuid().ToString("N"))
$savedRunnerTemp = $env:RUNNER_TEMP
$savedVcpkgRoot = $env:VCPKG_ROOT
$savedMarker = $env:EDR_VS_HOST_TEST_VALUE
try {
  New-Item -ItemType Directory -Path $testRoot -Force | Out-Null
  $env:RUNNER_TEMP = $testRoot
  $env:VCPKG_ROOT = "C:\caller-vcpkg"

  $script:fixtureVsRoot = Join-Path $testRoot "Visual Studio\2022\BuildTools"
  $script:fixtureVsWhere = Join-Path $testRoot "vswhere.exe"
  $fixtureDevCmd = Join-Path $script:fixtureVsRoot "Common7\Tools\VsDevCmd.bat"
  New-Item -ItemType Directory -Path (Split-Path -Parent $fixtureDevCmd) -Force | Out-Null
  New-Item -ItemType File -Path $script:fixtureVsWhere -Force | Out-Null
  New-Item -ItemType File -Path $fixtureDevCmd -Force | Out-Null

  function Invoke-DependencyLockValidation([string] $RepositoryRoot) {
    Assert-VsHostTest ($RepositoryRoot -eq $repositoryRoot) "repository root changed"
  }
  function Get-WindowsHostArchitecture { return $script:testCase.Host }
  function Get-VsWherePath { return $script:fixtureVsWhere }
  function Find-VS2022Installation {
    param([string] $VsWherePath, [string] $VersionRange, [string[]] $RequiredComponents)
    Assert-VsHostTest ($VsWherePath -eq $script:fixtureVsWhere) "vswhere boundary path changed"
    Assert-VsHostTest ($VersionRange -eq "[17.0,18.0)") "dependency lock range changed"
    $script:capturedComponents = @($RequiredComponents)
    return [pscustomobject]@{ Path = $script:fixtureVsRoot; Version = $script:testCase.Version }
  }
  function Invoke-VsDevCmdEnvironment {
    param([string] $DevCmd, [string] $TargetArchitecture,
      [string] $HostArchitecture, [string] $EnvironmentDump)
    Assert-VsHostTest ($DevCmd -eq $fixtureDevCmd) "VsDevCmd path changed"
    $script:capturedHost = $HostArchitecture
    $script:capturedTarget = $TargetArchitecture
    [IO.File]::WriteAllLines($EnvironmentDump, [string[]]@(
        "EDR_VS_HOST_TEST_VALUE=$($script:testCase.Name)",
        "VCPKG_ROOT=C:\from-vsdevcmd"
      ))
    return 0
  }
  function Get-VSCompilerPath { return $script:testCase.Compiler }

  $cases = @(
    @{ Name = "x64-x64"; Host = "x64"; Target = "x64";
      Component = "Microsoft.VisualStudio.Component.VC.Tools.x86.x64";
      Compiler = (Join-Path $script:fixtureVsRoot "VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\cl.exe");
      Version = "17.14.12" },
    @{ Name = "x64-arm64"; Host = "x64"; Target = "arm64";
      Component = "Microsoft.VisualStudio.Component.VC.Tools.ARM64";
      Compiler = (Join-Path $script:fixtureVsRoot "VC\Tools\MSVC\14.44.35207\bin\Hostx64\ARM64\cl.exe");
      Version = "17.14.12" },
    @{ Name = "arm64-arm64"; Host = "arm64"; Target = "arm64";
      Component = "Microsoft.VisualStudio.Component.VC.Tools.ARM64";
      Compiler = (Join-Path $script:fixtureVsRoot "VC\Tools\MSVC\14.44.35207\bin\HostARM64\ARM64\cl.exe");
      Version = "17.14.12" },
    @{ Name = "arm64-x64"; Host = "arm64"; Target = "x64";
      Component = "Microsoft.VisualStudio.Component.VC.Tools.x86.x64";
      Compiler = (Join-Path $script:fixtureVsRoot "VC\Tools\MSVC\14.44.35207\bin\HostARM64\x64\cl.exe");
      Version = "17.14.12" }
  )
  foreach ($script:testCase in $cases) {
    $githubEnvironment = Join-Path $testRoot ("github-{0}.env" -f $script:testCase.Name)
    $script:capturedComponents = @()
    $script:capturedHost = ""
    $script:capturedTarget = ""
    Initialize-VS2022Environment -TargetArchitecture $script:testCase.Target `
      -GithubEnvPath $githubEnvironment -RepositoryRoot $repositoryRoot
    Assert-VsHostTest ($script:capturedHost -eq $script:testCase.Host) "$($script:testCase.Name) host"
    Assert-VsHostTest ($script:capturedTarget -eq $script:testCase.Target) "$($script:testCase.Name) target"
    Assert-VsHostTest ($script:capturedComponents.Count -eq 1) "$($script:testCase.Name) component count"
    Assert-VsHostTest ($script:capturedComponents[0] -eq $script:testCase.Component) "$($script:testCase.Name) component"
    Assert-VsHostTest ($env:VCPKG_ROOT -eq "C:\caller-vcpkg") "$($script:testCase.Name) caller VCPKG_ROOT"
    $githubText = [IO.File]::ReadAllText($githubEnvironment)
    Assert-VsHostTest ($githubText -match "VCPKG_ROOT=C:\\caller-vcpkg") "$($script:testCase.Name) exported VCPKG_ROOT"
  }

  $script:testCase = @{
    Name = "mismatched-host"; Host = "arm64"; Target = "arm64";
    Compiler = (Join-Path $script:fixtureVsRoot "VC\Tools\MSVC\14.44.35207\bin\Hostx64\ARM64\cl.exe");
    Version = "17.14.12"
  }
  $mismatchEnvironment = Join-Path $testRoot "github-mismatch.env"
  $mismatchFailed = $false
  try {
    Initialize-VS2022Environment -TargetArchitecture arm64 `
      -GithubEnvPath $mismatchEnvironment -RepositoryRoot $repositoryRoot
  } catch {
    $mismatchFailed = $_.Exception.Message -match "compiler architecture mismatch"
  }
  Assert-VsHostTest $mismatchFailed "a Hostx64 compiler must be rejected on an ARM64 host"
  Assert-VsHostTest (-not (Test-Path -LiteralPath $mismatchEnvironment)) "invalid compiler environment must not be exported"

  $script:testCase = @{
    Name = "mismatched-target"; Host = "x64"; Target = "arm64";
    Compiler = (Join-Path $script:fixtureVsRoot "VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\cl.exe");
    Version = "17.14.12"
  }
  $wrongTargetFailed = $false
  try {
    Initialize-VS2022Environment -TargetArchitecture arm64 `
      -GithubEnvPath "" -RepositoryRoot $repositoryRoot
  } catch {
    $wrongTargetFailed = $_.Exception.Message -match "compiler architecture mismatch"
  }
  Assert-VsHostTest $wrongTargetFailed "an x64-targeting compiler must be rejected for an ARM64 target"

  $script:testCase = @{
    Name = "old-arm64-vs"; Host = "arm64"; Target = "arm64";
    Compiler = (Join-Path $script:fixtureVsRoot "VC\Tools\MSVC\14.33.1\bin\HostARM64\ARM64\cl.exe");
    Version = "17.3.6"
  }
  $oldVersionFailed = $false
  try {
    Initialize-VS2022Environment -TargetArchitecture arm64 `
      -GithubEnvPath "" -RepositoryRoot $repositoryRoot
  } catch {
    $oldVersionFailed = $_.Exception.Message -match "17.4 or later"
  }
  Assert-VsHostTest $oldVersionFailed "native ARM64 host must reject Visual Studio older than 17.4"

  Write-Host "VS2022 host architecture selection tests passed; actual_host=$actualHostArchitecture native_host=$actualNativeArchitecture."
} finally {
  $env:RUNNER_TEMP = $savedRunnerTemp
  $env:VCPKG_ROOT = $savedVcpkgRoot
  $env:EDR_VS_HOST_TEST_VALUE = $savedMarker
  if (Test-Path -LiteralPath $testRoot) {
    Remove-Item -LiteralPath $testRoot -Recurse -Force
  }
}
