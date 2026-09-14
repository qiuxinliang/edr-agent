[CmdletBinding()]
param(
  [string] $RepoRoot = (Split-Path -Parent $PSScriptRoot)
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$workflowPath = Join-Path $RepoRoot '.github/workflows/edr-agent-client-release.yml'
$workflow = Get-Content -LiteralPath $workflowPath -Raw -Encoding UTF8
$closureStart = $workflow.IndexOf('$runtimePeFiles = @(Get-ChildItem -LiteralPath $outDir -File')
$closureEnd = $workflow.IndexOf('Write-Host "Verified Runtime PE closure:', $closureStart)
if ($closureStart -lt 0 -or $closureEnd -lt 0) {
  throw 'release Runtime PE closure block is missing'
}
$closureBlock = $workflow.Substring($closureStart, $closureEnd - $closureStart)
if ($closureBlock.Contains('-Recurse')) {
  throw 'release Runtime PE closure must remain root-only'
}
$appendMatch = [regex]::Match(
  $closureBlock,
  '(?m)^\s*(\$runtimePeFiles \+= Get-Item -LiteralPath \$builtinCollectorPackagePath)\s*$'
)
if (-not $appendMatch.Success) {
  throw 'release Runtime PE closure must append the collector as a FileInfo'
}
$packageGateStart = $workflow.IndexOf('$builtinCollectorEntries = @($zipObj.Entries')
$packageGateEnd = $workflow.IndexOf('$pcre2ContractEntries =', $packageGateStart)
if ($packageGateStart -lt 0 -or $packageGateEnd -lt 0) {
  throw 'release builtin collector package gate block is missing'
}
$packageGateBlock = $workflow.Substring($packageGateStart, $packageGateEnd - $packageGateStart)

Add-Type -AssemblyName System.IO.Compression.FileSystem

function New-RuntimePackageFixture([string] $Root, [string] $Name, [bool] $IncludeCollector) {
  $source = Join-Path $Root ($Name + '-source')
  New-Item -ItemType Directory -Path $source -Force | Out-Null
  $files = @()
  if ($IncludeCollector) {
    $collectorPath = Join-Path $source 'collector/forensic_collector_builtin.exe'
    New-Item -ItemType Directory -Path (Split-Path -Parent $collectorPath) -Force | Out-Null
    [IO.File]::WriteAllBytes($collectorPath, [Text.Encoding]::UTF8.GetBytes('collector'))
    $files += [ordered]@{
      name = 'collector/forensic_collector_builtin.exe'
      sha256 = (Get-FileHash -LiteralPath $collectorPath -Algorithm SHA256).Hash.ToLowerInvariant()
    }
  }
  $manifest = [ordered]@{
    schema = 'edr.windows.native-package-integrity.v1'
    files = $files
  }
  $manifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $source 'native-package-integrity.json') -Encoding UTF8
  $package = Join-Path $Root ($Name + '.zip')
  [IO.Compression.ZipFile]::CreateFromDirectory(
    $source,
    $package,
    [IO.Compression.CompressionLevel]::Optimal,
    $false
  )
  return $package
}

$fixtureRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("edr-release-pe-closure-" + [guid]::NewGuid().ToString('N'))
$previousUpgradeClass = [Environment]::GetEnvironmentVariable('EDR_UPGRADE_CLASS', 'Process')
try {
  $outDir = Join-Path $fixtureRoot 'build'
  $collectorDir = Join-Path $outDir 'collector'
  $tryCompileDir = Join-Path $outDir 'tests/try_compile'
  New-Item -ItemType Directory -Path $collectorDir, $tryCompileDir -Force | Out-Null
  New-Item -ItemType File -Path (Join-Path $outDir 'FDSensor.exe') -Force | Out-Null
  $builtinCollectorPackagePath = Join-Path $collectorDir 'forensic_collector_builtin.exe'
  New-Item -ItemType File -Path $builtinCollectorPackagePath -Force | Out-Null
  New-Item -ItemType File -Path (Join-Path $tryCompileDir 'unrelated-test.exe') -Force | Out-Null

  $runtimePeFiles = @(Get-ChildItem -LiteralPath $outDir -File -ErrorAction Stop | Where-Object {
      $_.Extension -ieq '.exe' -or $_.Extension -ieq '.dll'
    })
  Invoke-Expression $appendMatch.Groups[1].Value

  if ($runtimePeFiles.Count -ne 2) {
    throw "release Runtime PE closure fixture expected 2 files; found $($runtimePeFiles.Count)"
  }
  foreach ($runtimePeFile in $runtimePeFiles) {
    if ($runtimePeFile -isnot [System.IO.FileInfo] -or [string]::IsNullOrWhiteSpace($runtimePeFile.FullName)) {
      throw 'release Runtime PE closure contains a non-FileInfo or an empty FullName'
    }
  }
  if (@($runtimePeFiles | Where-Object { $_.Name -eq 'unrelated-test.exe' }).Count -ne 0) {
    throw 'release Runtime PE closure recursively included a test artifact'
  }
  if (@($runtimePeFiles | Where-Object { $_.FullName -ceq $builtinCollectorPackagePath }).Count -ne 1) {
    throw 'release Runtime PE closure did not include exactly the staged builtin collector'
  }

  $validPackage = New-RuntimePackageFixture $fixtureRoot 'valid' $true
  foreach ($upgradeClass in @('binary_hot', 'runtime_bundle', 'installer_required')) {
    $env:EDR_UPGRADE_CLASS = $upgradeClass
    $zipObj = [IO.Compression.ZipFile]::OpenRead($validPackage)
    try {
      Invoke-Expression $packageGateBlock
    } finally {
      $zipObj.Dispose()
    }
  }

  $legacyPackage = New-RuntimePackageFixture $fixtureRoot 'legacy-missing-collector' $false
  $zipObj = [IO.Compression.ZipFile]::OpenRead($legacyPackage)
  $legacyRejection = $null
  try {
    Invoke-Expression $packageGateBlock
  } catch {
    $legacyRejection = $_.Exception.Message
  } finally {
    $zipObj.Dispose()
  }
  if ($legacyRejection -cne 'package must contain exactly one collector/forensic_collector_builtin.exe; found 0') {
    throw "legacy package rejection reason mismatch: $legacyRejection"
  }

  Write-Host 'PASS: release PE closure and all upgrade-class collector package gates'
} finally {
  [Environment]::SetEnvironmentVariable('EDR_UPGRADE_CLASS', $previousUpgradeClass, 'Process')
  if (Test-Path -LiteralPath $fixtureRoot) {
    Remove-Item -LiteralPath $fixtureRoot -Recurse -Force
  }
}
