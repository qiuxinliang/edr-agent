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
  "vcruntime140_1.dll",
  "msvcp140.dll"
)

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
    if (-not (Test-Path -LiteralPath (Join-Path $candidate $dll) -PathType Leaf)) {
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

$staged = 0
Get-ChildItem -LiteralPath $crtDir -Filter "*.dll" -File | ForEach-Object {
  Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $releaseDir $_.Name) -Force
  $staged++
}

foreach ($dll in $requiredDlls) {
  $destination = Join-Path $releaseDir $dll
  if (-not (Test-Path -LiteralPath $destination -PathType Leaf)) {
    throw "Required app-local MSVC runtime DLL was not staged: $dll"
  }
}

Write-Host "Staged $staged Microsoft VC runtime DLL(s) for $Architecture from $crtDir into $releaseDir"
