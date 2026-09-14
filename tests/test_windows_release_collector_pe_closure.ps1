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

function Test-CollectorBuildStaging([string] $Root) {
  # Exercise the shared staging script followed by each workflow's real package
  # prefix. PE bytes and dumpbin are fixtures; no native executable is launched.
  $previousVcpkg = $env:VCPKG_INSTALLED_ROOT
  $previousArch = $env:EDR_RELEASE_ARCH
  function dumpbin.exe { $global:LASTEXITCODE = 0; 'fixture: no dynamic PCRE2 import' }
  try {
    foreach ($architecture in @('amd64', 'arm64')) {
      $env:EDR_RELEASE_ARCH = $architecture
      foreach ($multiConfig in @($false, $true)) {
        foreach ($scenario in @('fresh', 'stale', 'missing')) {
          $missing = $scenario -eq 'missing'
          $caseRoot = Join-Path $Root "$architecture-multi$multiConfig-$scenario"
          $build = Join-Path $caseRoot 'build'
          $release = Join-Path $build 'Release'
          $scripts = Join-Path $caseRoot 'scripts'
          $env:VCPKG_INSTALLED_ROOT = Join-Path $caseRoot 'vcpkg'
          $bin = Join-Path $env:VCPKG_INSTALLED_ROOT 'bin'
          New-Item -ItemType Directory -Path $release, $scripts, $bin -Force | Out-Null
          foreach ($script in @('stage_vcpkg_runtime_dlls_build_release.ps1', 'Assert-WindowsPeArchitecture.ps1')) {
            Copy-Item -LiteralPath (Join-Path $RepoRoot "scripts/$script") -Destination $scripts
          }
          $contract = Join-Path $build 'matcher-contract.json'
          [IO.File]::WriteAllText($contract, '{}')
          $cache = "EDR_PCRE2_MATCHER_CONTRACT_AUDIT_PATH:INTERNAL=$contract`n"
          if ($multiConfig) { $cache += "CMAKE_CONFIGURATION_TYPES:STRING=Debug;Release;RelWithDebInfo`n" }
          else { $cache += "CMAKE_BUILD_TYPE:STRING=Release`n" }
          [IO.File]::WriteAllText((Join-Path $build 'CMakeCache.txt'), $cache)
          [IO.File]::WriteAllText((Join-Path $bin 'yara.dll'), 'fixture')
          $nativeDir = if ($multiConfig) { $release } else { $build }
          $otherDir = if ($multiConfig) { $build } else { $release }
          [IO.File]::WriteAllText((Join-Path $nativeDir 'FDSensor.exe'), 'agent fixture')
          $collectorName = 'forensic_collector_builtin.exe'
          # A stale copy in the other layout must never substitute for this build.
          if ($scenario -ne 'fresh') {
            [IO.File]::WriteAllText((Join-Path $otherDir $collectorName), 'stale collector')
          }
          $pe = New-Object byte[] 256
          $pe[0] = 0x4d; $pe[1] = 0x5a; $pe[0x3c] = 0x80
          $pe[0x80] = 0x50; $pe[0x81] = 0x45
          if ($architecture -eq 'arm64') { $pe[0x84] = 0x64; $pe[0x85] = 0xaa }
          else { $pe[0x84] = 0x64; $pe[0x85] = 0x86 }
          $source = Join-Path $nativeDir $collectorName
          if (-not $missing) { [IO.File]::WriteAllBytes($source, $pe) }
          $failure = $null
          try { & (Join-Path $scripts 'stage_vcpkg_runtime_dlls_build_release.ps1') }
          catch { $failure = $_.Exception.Message }
          if ($missing) {
            if (-not $failure -or -not $failure.Contains($source)) {
              throw "staging must reject the missing CMake output, not use a stale copy: $source; failure=$failure"
            }
            continue
          }
          if ($failure) { throw $failure }
          $expectedHash = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
          foreach ($workflowName in @('edr-agent-client-release.yml', 'edr-agent-client-build.yml')) {
            $text = Get-Content -LiteralPath (Join-Path $RepoRoot ".github/workflows/$workflowName") -Raw
            $start = $text.IndexOf('$outDir = $null')
            $end = $text.IndexOf('$workerExe = Join-Path $outDir', $start)
            if ($start -lt 0 -or $end -lt 0) { throw "missing packaging prefix: $workflowName" }
            # The manual workflow supports AMD64 only; the formal workflow covers both.
            if ($architecture -eq 'arm64' -and $workflowName -eq 'edr-agent-client-build.yml') { continue }
            Push-Location $caseRoot
            try {
              Invoke-Expression $text.Substring($start, $end - $start)
              if ((Get-FileHash -LiteralPath $builtinCollectorPackagePath -Algorithm SHA256).Hash -ne $expectedHash) {
                throw "packaging changed or selected the wrong collector: $workflowName"
              }
            } finally { Pop-Location }
          }
        }
      }
    }
    Write-Host 'PASS: collector staging for single/multi-config, both architectures, and missing/stale outputs'
  } finally {
    $env:VCPKG_INSTALLED_ROOT = $previousVcpkg
    $env:EDR_RELEASE_ARCH = $previousArch
  }
}

$fixtureRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("edr-release-pe-closure-" + [guid]::NewGuid().ToString('N'))
$previousUpgradeClass = [Environment]::GetEnvironmentVariable('EDR_UPGRADE_CLASS', 'Process')
try {
  Test-CollectorBuildStaging (Join-Path $fixtureRoot 'staging')
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
