# Exercise the real runner's orchestration without starting native fixtures,
# services, network receivers, or installers. CTest label behavior is separately
# exercised by test_windows_release_gate.py with real CTest execution.
$ErrorActionPreference = 'Stop'
$runner = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'run_telemetry_windows_native.ps1') -Raw
$tokens = $null
$parseErrors = $null
$null = [Management.Automation.Language.Parser]::ParseInput($runner, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw ($parseErrors | Out-String) }
$requiredBlock = [regex]::Match($runner, '(?s)\$required = @\((.*?)\)')
$required = @([regex]::Matches($requiredBlock.Groups[1].Value, "'([^']+)'") | ForEach-Object { $_.Groups[1].Value })
if ($required.Count -eq 0) { throw 'Native runner declares no required contracts.' }
$invokeRunner = [scriptblock]::Create($runner)
$root = Join-Path ([IO.Path]::GetTempPath()) ('edr-native-gate-test-' + [Guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $root
$null = New-Item -ItemType File -Path (Join-Path $root 'CMakeCache.txt')
$oldMarker = [Environment]::GetEnvironmentVariable('EDR_GATE_RUNNER_TEST', 'Process')

$state = [pscustomobject]@{ Scenario = ''; BuildArguments = @(); Inventory = @(); Phases = $null; TestArguments = $null }

function openssl { throw 'The orchestration fixture must not execute OpenSSL.' }
function cmake {
  $state.buildArguments = @($args | ForEach-Object { $_ })
  $global:LASTEXITCODE = if ($state.scenario -eq 'build failure') { 1 } else { 0 }
}
function ctest {
  $arguments = @($args | ForEach-Object { $_ })
  if ($arguments -contains '--show-only=json-v1') {
    $global:LASTEXITCODE = 0
    return (@{ tests = $state.inventory } | ConvertTo-Json -Depth 8)
  }
  if (-not [string]::IsNullOrEmpty($env:EDR_GATE_RUNNER_TEST)) { throw 'Inherited EDR overrides reached a native test.' }
  $phase = if ($arguments -contains '--label-regex') { 'release' } else { 'telemetry' }
  $state.phases.Add($phase)
  $state.testArguments.Add($arguments)
  $global:LASTEXITCODE = if ($state.scenario -eq "$phase failure") { 1 } else { 0 }
}

try {
  foreach ($case in @('standalone', 'combined', 'all overlap', 'release failure', 'telemetry failure',
                      'build failure', 'empty release', 'unlabelled required', 'missing required')) {
    $state.scenario = $case
    $state.phases = New-Object 'System.Collections.Generic.List[string]'
    $state.testArguments = New-Object 'System.Collections.Generic.List[object]'
    $state.buildArguments = @()
    $state.inventory = @()
    foreach ($name in $required) {
      if ($case -eq 'missing required' -and $name -eq $required[0]) { continue }
      $labels = @('telemetry-minimization')
      if ($case -eq 'all overlap' -or ($case -ne 'empty release' -and $name -eq $required[0])) {
        $labels += 'windows-release-gate'
      }
      if ($case -eq 'unlabelled required' -and $name -eq $required[0]) { $labels = @('windows-release-gate') }
      $state.inventory += @{ name = $name; properties = @(@{ name = 'LABELS'; value = $labels }) }
    }
    $env:EDR_GATE_RUNNER_TEST = 'must be restored'
    $caught = ''
    try { & $invokeRunner -BuildDir $root -IncludeReleaseGate:($case -ne 'standalone') | Out-Null }
    catch { $caught = $_.Exception.Message }
    if ($env:EDR_GATE_RUNNER_TEST -cne 'must be restored') { throw "$case did not restore inherited environment." }
    $expectedPhases = switch ($case) {
      'standalone' { 'telemetry' }
      'combined' { 'release,telemetry' }
      'all overlap' { 'release' }
      'release failure' { 'release' }
      'telemetry failure' { 'release,telemetry' }
      default { '' }
    }
    if (($state.phases -join ',') -cne $expectedPhases) { throw "${case}: unexpected phases $($state.phases -join ','); error: $caught" }
    $expectedError = switch ($case) {
      'release failure' { 'Native Windows release gate failed' }
      'telemetry failure' { 'Native telemetry contract failed' }
      'build failure' { 'Native contract executables failed to build' }
      'empty release' { 'Required Windows release gate is empty' }
      'unlabelled required' { 'Required native telemetry test missing or unlabelled' }
      'missing required' { 'Required native telemetry test missing or unlabelled' }
      default { '' }
    }
    if (($expectedError -and -not $caught.Contains($expectedError)) -or (-not $expectedError -and $caught)) {
      throw "${case}: expected error '$expectedError', got '$caught'"
    }
    foreach ($arguments in $state.testArguments) {
      if ($arguments -notcontains '--no-tests=error') { throw "${case}: empty test selection can pass." }
      if ($arguments -contains '-L') {
        if (($arguments -contains '--label-exclude') -ne ($case -ne 'standalone')) { throw "${case}: wrong telemetry exclusion." }
        if ($arguments -notcontains '150') { throw "${case}: telemetry deadline changed." }
      } elseif ($arguments -contains '--timeout') { throw "${case}: release deadlines were overridden." }
    }
    if ($case -in @('standalone', 'combined', 'all overlap')) {
      if ($state.buildArguments -notcontains 'telemetry_minimization_tests') { throw "${case}: telemetry target omitted." }
      if (($state.buildArguments -contains 'windows_release_gate_tests') -ne ($case -ne 'standalone')) { throw "${case}: wrong release build target." }
    }
    Write-Host "PASS: native gate runner $case"
  }
} finally {
  [Environment]::SetEnvironmentVariable('EDR_GATE_RUNNER_TEST', $oldMarker, 'Process')
  Remove-Item -LiteralPath $root -Recurse -Force
}
