# Stage the Microsoft Visual C++ runtime beside the Windows Agent binaries.
# The release uses /MD, so clean endpoints must not depend on a machine-wide
# Visual C++ Redistributable being installed before FDSensor.exe can start.
[CmdletBinding()]
param(
  [ValidateSet("amd64", "arm64")]
  [string]$Architecture = "amd64"
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$releaseDir = Join-Path $root "build\Release"
$agentExe = Join-Path $releaseDir "FDSensor.exe"
if (-not (Test-Path -LiteralPath $agentExe -PathType Leaf)) {
  throw "FDSensor.exe not found under build\Release. Stage the compiled Agent before the MSVC runtime."
}

$redistArch = if ($Architecture -eq "arm64") { "arm64" } else { "x64" }
$requiredDlls = @(
  "vcruntime140.dll",
  "msvcp140.dll"
)
if ($Architecture -eq "amd64") {
  # The x64 product imports the extended runtime. The VS ARM64 redist directory
  # can contain an x64 compatibility copy of this DLL, which must not leak into
  # a native ARM64 package.
  $requiredDlls += "vcruntime140_1.dll"
}
$expectedMachine = if ($Architecture -eq "arm64") { [UInt16]0xaa64 } else { [UInt16]0x8664 }
$architectureVerifier = Join-Path $PSScriptRoot "Assert-WindowsPeArchitecture.ps1"

function Get-PeMachine {
  param([Parameter(Mandatory = $true)][string]$Path)
  try {
    $bytes = [IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -lt 256 -or $bytes[0] -ne 0x4d -or $bytes[1] -ne 0x5a) {
      return $null
    }
    $peOffset = [BitConverter]::ToInt32($bytes, 0x3c)
    if ($peOffset -lt 0 -or $peOffset + 6 -gt $bytes.Length -or
        $bytes[$peOffset] -ne 0x50 -or $bytes[$peOffset + 1] -ne 0x45) {
      return $null
    }
    return [BitConverter]::ToUInt16($bytes, $peOffset + 4)
  } catch {
    return $null
  }
}

function Test-TargetPeArchitecture {
  param([Parameter(Mandatory = $true)][string]$Path)
  $machine = Get-PeMachine -Path $Path
  return ($null -ne $machine -and $machine -eq $expectedMachine)
}

$candidateRoots = New-Object System.Collections.Generic.List[string]
if ($env:VCToolsRedistDir) {
  $candidateRoots.Add((Join-Path $env:VCToolsRedistDir "$redistArch\Microsoft.VC143.CRT"))
  $candidateRoots.Add((Join-Path $env:VCToolsRedistDir "$redistArch\Microsoft.VC142.CRT"))
}

$vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
if (Test-Path -LiteralPath $vswhere -PathType Leaf) {
  $installations = @(& $vswhere -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath)
  foreach ($installation in $installations) {
    if (-not $installation) { continue }
    $redistRoot = Join-Path $installation "VC\Redist\MSVC"
    if (-not (Test-Path -LiteralPath $redistRoot -PathType Container)) { continue }
    Get-ChildItem -LiteralPath $redistRoot -Directory | Sort-Object Name -Descending | ForEach-Object {
      Get-ChildItem -LiteralPath (Join-Path $_.FullName $redistArch) -Directory -Filter "Microsoft.VC*.CRT" -ErrorAction SilentlyContinue | ForEach-Object {
        $candidateRoots.Add($_.FullName)
      }
    }
  }
}

$crtDir = $null
foreach ($candidate in @($candidateRoots | Select-Object -Unique)) {
  if (-not (Test-Path -LiteralPath $candidate -PathType Container)) { continue }
  $complete = $true
  foreach ($dll in $requiredDlls) {
    $candidateDll = Join-Path $candidate $dll
    if (-not (Test-Path -LiteralPath $candidateDll -PathType Leaf) -or
        -not (Test-TargetPeArchitecture -Path $candidateDll)) {
      $complete = $false
      break
    }
  }
  if ($complete) {
    $crtDir = $candidate
    break
  }
}

if (-not $crtDir) {
  throw "A complete Microsoft VC runtime for $redistArch was not found. Checked VCToolsRedistDir and Visual Studio VC\Redist\MSVC."
}

# A reused build directory may still contain CRT files from another target.
# Remove only the MSVC app-local runtime family before staging the selected
# target; vcpkg-owned dependency DLLs are deliberately left untouched.
Get-ChildItem -LiteralPath $releaseDir -Filter "*.dll" -File -ErrorAction SilentlyContinue |
  Where-Object { $_.Name -match '^(?i:concrt|msvcp|vccorlib|vcruntime)\d.*\.dll$' } |
  Remove-Item -Force

$staged = 0
Get-ChildItem -LiteralPath $crtDir -Filter "*.dll" -File | ForEach-Object {
  $machine = Get-PeMachine -Path $_.FullName
  if ($null -eq $machine) {
    throw "MSVC runtime candidate is not a valid PE DLL: $($_.FullName)"
  }
  if ($machine -ne $expectedMachine) {
    Write-Warning ("Skipping non-target MSVC runtime DLL: path={0} expected={1}/0x{2:x4} actual=0x{3:x4}" -f `
      $_.FullName, $Architecture, $expectedMachine, $machine)
    return
  }
  Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $releaseDir $_.Name) -Force
  & $architectureVerifier -Path (Join-Path $releaseDir $_.Name) -Architecture $Architecture
  $staged++
}

foreach ($dll in $requiredDlls) {
  $destination = Join-Path $releaseDir $dll
  if (-not (Test-Path -LiteralPath $destination -PathType Leaf)) {
    throw "Required app-local MSVC runtime DLL was not staged: $dll"
  }
}

Write-Host "Staged $staged Microsoft VC runtime DLL(s) for $Architecture from $crtDir into $releaseDir"
