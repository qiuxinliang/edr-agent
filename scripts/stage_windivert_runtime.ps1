#Requires -Version 5.1
<#
.SYNOPSIS
Stages the pinned official WinDivert x64 runtime next to FDSensor.exe.

The official DLL discovers WinDivert64.sys in the same directory and installs
the signed driver on demand when FDSensor calls WinDivertOpen as Administrator.
#>
param(
  [Parameter(Mandatory = $true)]
  [string] $DestinationDir
)

$ErrorActionPreference = "Stop"
$agentRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$runtimeDir = Join-Path $agentRoot "third_party\windivert\runtime\amd64"
$licensePath = Join-Path $agentRoot "third_party\windivert\LICENSE"
$sourcePath = Join-Path $agentRoot "third_party\windivert\SOURCE.json"
$expected = @{
  "WinDivert.dll" = "c1e060ee19444a259b2162f8af0f3fe8c4428a1c6f694dce20de194ac8d7d9a2"
  "WinDivert64.sys" = "8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2"
}

New-Item -ItemType Directory -Path $DestinationDir -Force | Out-Null
foreach ($name in $expected.Keys) {
  $source = Join-Path $runtimeDir $name
  if (-not (Test-Path -LiteralPath $source)) {
    throw "Pinned WinDivert runtime file is missing: $source"
  }
  $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $source).Hash.ToLowerInvariant()
  if ($actual -ne $expected[$name]) {
    throw "Pinned WinDivert runtime hash mismatch for $name. expected=$($expected[$name]) actual=$actual"
  }
  Copy-Item -LiteralPath $source -Destination (Join-Path $DestinationDir $name) -Force
}

$licensesDir = Join-Path $DestinationDir "licenses"
New-Item -ItemType Directory -Path $licensesDir -Force | Out-Null
foreach ($asset in @(
  @{ Source = $licensePath; Destination = "WinDivert-LICENSE.txt" },
  @{ Source = $sourcePath; Destination = "WinDivert-SOURCE.json" }
)) {
  if (-not (Test-Path -LiteralPath $asset.Source)) {
    throw "Pinned WinDivert metadata is missing: $($asset.Source)"
  }
  Copy-Item -LiteralPath $asset.Source -Destination (Join-Path $licensesDir $asset.Destination) -Force
}

Write-Host "Staged WinDivert 2.2.2 runtime (x64) into $DestinationDir"
