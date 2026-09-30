#Requires -Version 5.1
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [ValidateSet("x64", "arm64")]
  [string] $Architecture,
  [string] $GithubEnvPath = $env:GITHUB_ENV
)

$ErrorActionPreference = "Stop"

function Resolve-WindowsNativeMachineArchitecture([uint16] $NativeMachine) {
  switch ([int]$NativeMachine) {
    0x8664 { return "x64" }
    0xAA64 { return "arm64" }
    default {
      throw ("Unsupported Windows native machine architecture: 0x{0:X4}" -f $NativeMachine)
    }
  }
}

function Get-WindowsNativeMachineArchitecture {
  if ($null -eq ("EdrVsHostArchitectureNativeMethods" -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class EdrVsHostArchitectureNativeMethods {
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool IsWow64Process2(
        IntPtr process, out ushort processMachine, out ushort nativeMachine);

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();
}
'@
  }

  [uint16]$processMachine = 0
  [uint16]$nativeMachine = 0
  try {
    $succeeded = [EdrVsHostArchitectureNativeMethods]::IsWow64Process2(
      [EdrVsHostArchitectureNativeMethods]::GetCurrentProcess(),
      [ref]$processMachine, [ref]$nativeMachine)
  } catch [System.EntryPointNotFoundException] {
    throw "IsWow64Process2 is unavailable; Visual Studio host detection requires Windows 10 or Windows Server version 1709 or later"
  }
  if (-not $succeeded) {
    $nativeError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    throw "IsWow64Process2 failed while determining the Windows host architecture: error=$nativeError"
  }
  return Resolve-WindowsNativeMachineArchitecture -NativeMachine $nativeMachine
}

function Get-WindowsHostArchitecture {
  return Get-WindowsNativeMachineArchitecture
}

function Invoke-DependencyLockValidation([string] $RepositoryRoot) {
  & (Join-Path $RepositoryRoot "scripts\Validate-DependencyLocks.ps1") -RepositoryRoot $RepositoryRoot
}

function Get-VsWherePath {
  return Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
}

function Find-VSInstallation {
  param(
    [string] $VsWherePath,
    [string] $VersionRange,
    [string[]] $RequiredComponents
  )
  $installationPath = (& $VsWherePath -products * -version $VersionRange -requires $RequiredComponents -property installationPath -latest | Select-Object -First 1)
  if ([string]::IsNullOrWhiteSpace([string]$installationPath)) {
    throw "Visual Studio in locked range $VersionRange with the required C++ target toolchain is required: $($RequiredComponents -join ',')"
  }
  $installationVersion = (& $VsWherePath -path $installationPath -property installationVersion | Select-Object -First 1)
  return [pscustomobject]@{
    Path = [string]$installationPath
    Version = [string]$installationVersion
  }
}

function Invoke-VsDevCmdEnvironment {
  param(
    [string] $DevCmd,
    [string] $TargetArchitecture,
    [string] $HostArchitecture,
    [string] $EnvironmentDump
  )
  $command = 'call "{0}" -no_logo -arch={1} -host_arch={2} && set > "{3}"' -f `
    $DevCmd, $TargetArchitecture, $HostArchitecture, $EnvironmentDump
  & $env:ComSpec /d /s /c $command
  return $LASTEXITCODE
}

function Get-VSCompilerPath {
  return (& where.exe cl.exe | Select-Object -First 1)
}

function Assert-VSCompilerPath {
  param(
    [string] $Compiler,
    [string] $InstallationPath,
    [string] $HostArchitecture,
    [string] $TargetArchitecture
  )
  if ([string]::IsNullOrWhiteSpace($Compiler)) {
    throw "cl.exe was not found after Visual Studio initialization"
  }
  $compilerFull = [IO.Path]::GetFullPath($Compiler).Replace('/', '\')
  $installationFull = [IO.Path]::GetFullPath($InstallationPath).TrimEnd('\', '/')
  $hostDirectory = if ($HostArchitecture -eq "arm64") { "HostARM64" } else { "Hostx64" }
  $targetDirectory = if ($TargetArchitecture -eq "arm64") { "ARM64" } else { "x64" }
  $expectedPattern = '^' + [regex]::Escape($installationFull.Replace('/', '\')) +
    '\\VC\\Tools\\MSVC\\[^\\]+\\bin\\' + $hostDirectory + '\\' + $targetDirectory + '\\cl\.exe$'
  if ($compilerFull -notmatch $expectedPattern) {
    throw "Visual Studio compiler architecture mismatch: host=$HostArchitecture target=$TargetArchitecture compiler=$compilerFull"
  }
  return $compilerFull
}

function Initialize-VSEnvironment {
  param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("x64", "arm64")]
    [string] $TargetArchitecture,
    [string] $GithubEnvPath = "",
    [Parameter(Mandatory = $true)]
    [string] $RepositoryRoot
  )

  $callerVcpkgRoot = [Environment]::GetEnvironmentVariable("VCPKG_ROOT", "Process")
  Invoke-DependencyLockValidation -RepositoryRoot $repositoryRoot
  $dependencyLock = [IO.File]::ReadAllText((Join-Path $repositoryRoot "dependencies.lock.json")) | ConvertFrom-Json
  $hostArchitecture = Get-WindowsHostArchitecture
  $hostContract = $dependencyLock.visual_studio.PSObject.Properties[$hostArchitecture].Value
  if ($null -eq $hostContract) { throw "Visual Studio lock missing for host=$hostArchitecture" }
  $visualStudioVersionRange = [string]$hostContract.version_range

  $vswhere = Get-VsWherePath
  if (-not (Test-Path -LiteralPath $vswhere -PathType Leaf)) {
    throw "vswhere.exe was not found: $vswhere"
  }
  $requiredComponents = if ($TargetArchitecture -eq "arm64") {
    @("Microsoft.VisualStudio.Component.VC.Tools.ARM64")
  } else {
    @("Microsoft.VisualStudio.Component.VC.Tools.x86.x64")
  }
  $installation = Find-VSInstallation -VsWherePath $vswhere `
    -VersionRange $visualStudioVersionRange -RequiredComponents $requiredComponents
  $range = [regex]::Match($visualStudioVersionRange, '^\[(\d+\.\d+),(\d+\.\d+)\)$')
  if (-not $range.Success -or
      [version]$installation.Version -lt [version]$range.Groups[1].Value -or
      [version]$installation.Version -ge [version]$range.Groups[2].Value) {
    throw "Visual Studio generation mismatch: host=$hostArchitecture expected=$visualStudioVersionRange actual=$($installation.Version)"
  }
  $devCmd = Join-Path $installation.Path "Common7\Tools\VsDevCmd.bat"
  if (-not (Test-Path -LiteralPath $devCmd -PathType Leaf)) {
    throw "VsDevCmd.bat was not found: $devCmd"
  }

  $environmentDump = Join-Path $env:RUNNER_TEMP ("vs-{0}-{1}-{2}.env" -f `
    $hostArchitecture, $TargetArchitecture, [Guid]::NewGuid().ToString("N"))
  try {
    $exitCode = Invoke-VsDevCmdEnvironment -DevCmd $devCmd `
      -TargetArchitecture $TargetArchitecture -HostArchitecture $hostArchitecture `
      -EnvironmentDump $environmentDump
    if ($exitCode -ne 0 -or -not (Test-Path -LiteralPath $environmentDump -PathType Leaf)) {
      throw "Visual Studio environment initialization failed for host=$hostArchitecture target=$TargetArchitecture"
    }

    $environmentEntries = New-Object 'System.Collections.Generic.List[object]'
    foreach ($line in [IO.File]::ReadAllLines($environmentDump)) {
      $separator = $line.IndexOf('=')
      if ($separator -le 0) { continue }
      $name = $line.Substring(0, $separator)
      $value = $line.Substring($separator + 1)
      if ($name -ieq "VCPKG_ROOT" -and -not [string]::IsNullOrWhiteSpace($callerVcpkgRoot)) {
        continue
      }
      $environmentEntries.Add([pscustomobject]@{ Name = $name; Value = $value })
      [Environment]::SetEnvironmentVariable($name, $value, 'Process')
    }
    if (-not [string]::IsNullOrWhiteSpace($callerVcpkgRoot)) {
      [Environment]::SetEnvironmentVariable("VCPKG_ROOT", $callerVcpkgRoot, 'Process')
    }

    $compiler = Assert-VSCompilerPath -Compiler (Get-VSCompilerPath) `
      -InstallationPath $installation.Path -HostArchitecture $hostArchitecture `
      -TargetArchitecture $TargetArchitecture
    if (-not [string]::IsNullOrWhiteSpace($GithubEnvPath)) {
      foreach ($entry in $environmentEntries) {
        Add-Content -LiteralPath $GithubEnvPath `
          -Value ("{0}={1}" -f $entry.Name, $entry.Value) -Encoding UTF8
      }
      if (-not [string]::IsNullOrWhiteSpace($callerVcpkgRoot)) {
        Add-Content -LiteralPath $GithubEnvPath -Value ("VCPKG_ROOT={0}" -f $callerVcpkgRoot) -Encoding UTF8
      }
    }
  } finally {
    Remove-Item -LiteralPath $environmentDump -Force -ErrorAction SilentlyContinue
  }

  Write-Host "Visual Studio $($hostContract.generation) ready: version=$($installation.Version) host=$hostArchitecture target=$TargetArchitecture compiler=$compiler"
}

$repositoryRoot = Split-Path -Parent $PSScriptRoot
Initialize-VSEnvironment -TargetArchitecture $Architecture `
  -GithubEnvPath $GithubEnvPath -RepositoryRoot $repositoryRoot
