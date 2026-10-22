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
$lastTest = Join-Path $root 'Testing/Temporary/LastTest.log'
$savedRelease = Join-Path $root 'native-release-LastTest.log'
$null = New-Item -ItemType Directory -Path (Split-Path $lastTest -Parent) -Force
$oldMarker = [Environment]::GetEnvironmentVariable('EDR_GATE_RUNNER_TEST', 'Process')
$oldTempEnvironment = @{}
foreach ($name in @('TMP', 'TEMP', 'RUNNER_TEMP', 'GITHUB_ACTIONS')) {
  $oldTempEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}

$state = [pscustomobject]@{ Scenario = ''; BuildArguments = @(); Inventory = @(); Phases = $null; TestArguments = $null; ExpectedTemp = $null }

function openssl { throw 'The orchestration fixture must not execute OpenSSL.' }
function cmake {
  $state.buildArguments = @($args | ForEach-Object { $_ })
  $global:LASTEXITCODE = if ($state.scenario -eq 'build failure') { 1 } else { 0 }
}
function ctest {
  $arguments = @($args | ForEach-Object { $_ })
  if ($null -ne $state.ExpectedTemp -and
      ($env:TMP -cne $state.ExpectedTemp -or $env:TEMP -cne $state.ExpectedTemp)) {
    throw 'Native test child did not receive the intended temporary directory.'
  }
  if ($arguments -contains '--show-only=json-v1') {
    $global:LASTEXITCODE = 0
    return (@{ tests = $state.inventory } | ConvertTo-Json -Depth 8)
  }
  if (-not [string]::IsNullOrEmpty($env:EDR_GATE_RUNNER_TEST)) { throw 'Inherited EDR overrides reached a native test.' }
  $phase = if ($arguments -contains '--label-regex') { 'release' } else { 'telemetry' }
  $state.phases.Add($phase)
  $state.testArguments.Add($arguments)
  if ($state.scenario -eq 'release log missing' -and $phase -eq 'release') {
    if (Test-Path -LiteralPath $lastTest) { Remove-Item -LiteralPath $lastTest -Force }
  } elseif ($state.scenario -eq 'release log oversized' -and $phase -eq 'release') {
    [IO.File]::WriteAllBytes($lastTest, (New-Object byte[] (8 * 1024 * 1024 + 1)))
  } else {
    [IO.File]::WriteAllText($lastTest, "synthetic $phase $($state.scenario)`n")
  }
  $global:LASTEXITCODE = if ($state.scenario -eq "$phase failure") { 1 } else { 0 }
}

try {
  foreach ($case in @('standalone', 'combined', 'combined again', 'all overlap', 'release failure', 'telemetry failure',
                      'release log missing', 'release log oversized',
                      'build failure', 'empty release', 'unlabelled required', 'missing required')) {
    if ($case -eq 'combined again' -and [IO.File]::ReadAllText($savedRelease) -cne "synthetic release combined`n") { throw 'Repeat fixture did not retain the first invocation.' }
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
    if ($case -eq 'combined') { $validCombinedInventory = $state.inventory }
    $env:EDR_GATE_RUNNER_TEST = 'must be restored'
    $caught = ''
    try { & $invokeRunner -BuildDir $root -IncludeReleaseGate:($case -ne 'standalone') | Out-Null }
    catch { $caught = $_.Exception.Message }
    if ($env:EDR_GATE_RUNNER_TEST -cne 'must be restored') { throw "$case did not restore inherited environment." }
    $expectedPhases = switch ($case) {
      'standalone' { 'telemetry' }
      'combined' { 'release,telemetry' }
      'combined again' { 'release,telemetry' }
      'release log missing' { 'release' }
      'release log oversized' { 'release' }
      'all overlap' { 'release' }
      'release failure' { 'release' }
      'telemetry failure' { 'release,telemetry' }
      default { '' }
    }
    if (($state.phases -join ',') -cne $expectedPhases) { throw "${case}: unexpected phases $($state.phases -join ','); error: $caught" }
    $expectedError = switch ($case) {
      'release failure' { 'Native Windows release gate failed' }
      'release log missing' { 'Native release LastTest log is missing' }
      'release log oversized' { 'Native release LastTest exceeds the 8MiB' }
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
    if ($case -in @('combined', 'combined again', 'all overlap', 'telemetry failure')) {
      if ([IO.File]::ReadAllText($savedRelease) -cne "synthetic release $case`n") { throw "${case}: stale or incomplete release log." }
      $lastPhase = if ($case -eq 'all overlap') { 'release' } else { 'telemetry' }
      if ([IO.File]::ReadAllText($lastTest) -cne "synthetic $lastPhase $case`n") { throw "${case}: fixture did not overwrite the current LastTest." }
    } elseif (Test-Path -LiteralPath $savedRelease) { throw "${case}: failed or standalone invocation retained a stale release log." }
    foreach ($arguments in $state.testArguments) {
      if ($arguments -notcontains '--no-tests=error') { throw "${case}: empty test selection can pass." }
      $resultFlag = [Array]::IndexOf($arguments, '--output-junit')
      if ($resultFlag -lt 0 -or $resultFlag + 1 -ge $arguments.Count) { throw "${case}: native results are not retained." }
      $resultName = if ($arguments -contains '-L') { 'native-telemetry-results.xml' } else { 'native-release-results.xml' }
      if ($arguments[$resultFlag + 1] -cne (Join-Path $root $resultName)) { throw "${case}: native phases overwrite or misplace their results." }
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
  # Each early-preflight failure follows a real successful mocked invocation
  # in this same BuildDir; a previous pass log must not remain as this result.
  foreach ($earlyFailure in @('missing cache', 'missing openssl')) {
    $state.scenario = 'prior success ' + $earlyFailure
    $state.inventory = $validCombinedInventory
    $state.phases = New-Object 'System.Collections.Generic.List[string]'
    $state.testArguments = New-Object 'System.Collections.Generic.List[object]'
    & $invokeRunner -BuildDir $root -IncludeReleaseGate | Out-Null
    if ([IO.File]::ReadAllText($savedRelease) -cne "synthetic release $($state.scenario)`n") { throw "${earlyFailure}: prior success fixture did not publish a complete log." }
    $state.phases.Clear()
    $state.testArguments.Clear()
    $cachePath = Join-Path $root 'CMakeCache.txt'
    $earlyArgs = @{ BuildDir = $root; IncludeReleaseGate = $true }
    if ($earlyFailure -eq 'missing cache') {
      Remove-Item -LiteralPath $cachePath -Force
      $expectedEarlyError = 'Configure a native Windows EDR build'
    } else {
      $emptyOpenSsl = Join-Path $root 'empty-openssl'
      $null = New-Item -ItemType Directory -Path $emptyOpenSsl
      $earlyArgs.OpenSslBin = $emptyOpenSsl
      $expectedEarlyError = 'OpenSslBin must contain openssl.exe'
    }
    $caught = ''
    try { & $invokeRunner @earlyArgs | Out-Null }
    catch { $caught = $_.Exception.Message }
    finally {
      if (!(Test-Path -LiteralPath $cachePath)) { $null = New-Item -ItemType File -Path $cachePath }
    }
    if (-not $caught.Contains($expectedEarlyError)) { throw "${earlyFailure}: expected early preflight failure, got '$caught'." }
    if (Test-Path -LiteralPath $savedRelease) { throw "${earlyFailure}: early failure retained a previous pass log." }
    if ($state.phases.Count -ne 0) { throw "${earlyFailure}: early preflight unexpectedly reached CTest." }
    if ($env:EDR_GATE_RUNNER_TEST -cne 'must be restored') { throw "${earlyFailure}: early preflight changed the inherited environment." }
    Write-Host "PASS: native gate runner early $earlyFailure"
  }
  $profileTemp = Join-Path $root 'profile-temp'
  $runnerTemp = Join-Path $root 'runner-temp'
  $null = New-Item -ItemType Directory -Path $profileTemp, $runnerTemp
  foreach ($case in @('ci success', 'ci failure', 'ci unset directory', 'ci missing directory', 'ci file directory', 'local unchanged')) {
    $env:TMP = $profileTemp
    $env:TEMP = $profileTemp
    $env:GITHUB_ACTIONS = if ($case -eq 'local unchanged') { 'false' } else { 'true' }
    $env:RUNNER_TEMP = switch ($case) {
      'ci unset directory' { $null }
      'ci missing directory' { Join-Path $root 'absent' }
      'ci file directory' { Join-Path $root 'CMakeCache.txt' }
      'local unchanged' { $null }
      default { $runnerTemp }
    }
    $state.ExpectedTemp = if ($case -eq 'local unchanged') { $profileTemp } else { $runnerTemp }
    $state.scenario = if ($case -eq 'ci failure') { 'release failure' } else { $case }
    $state.inventory = $validCombinedInventory
    $state.phases.Clear()
    $state.testArguments.Clear()
    $caught = ''
    try { & $invokeRunner -BuildDir $root -IncludeReleaseGate | Out-Null }
    catch { $caught = $_.Exception.Message }
    if ($env:TMP -cne $profileTemp -or $env:TEMP -cne $profileTemp) { throw "${case}: temporary environment was not restored." }
    $invalidDirectory = $case -in @('ci unset directory', 'ci missing directory', 'ci file directory')
    $expectedError = if ($invalidDirectory) { 'GitHub CI requires an existing RUNNER_TEMP directory' }
      elseif ($case -eq 'ci failure') { 'Native Windows release gate failed' } else { '' }
    if (($expectedError -and -not $caught.Contains($expectedError)) -or (-not $expectedError -and $caught)) {
      throw "${case}: unexpected result '$caught'."
    }
    $expectedPhases = if ($invalidDirectory) { '' } elseif ($case -eq 'ci failure') { 'release' } else { 'release,telemetry' }
    if (($state.phases -join ',') -cne $expectedPhases) { throw "${case}: unexpected native test selection." }
    Write-Host "PASS: native gate runner temp $case"
  }
} finally {
  foreach ($name in $oldTempEnvironment.Keys) {
    [Environment]::SetEnvironmentVariable($name, $oldTempEnvironment[$name], 'Process')
  }
  [Environment]::SetEnvironmentVariable('EDR_GATE_RUNNER_TEST', $oldMarker, 'Process')
  Remove-Item -LiteralPath $root -Recurse -Force
}
