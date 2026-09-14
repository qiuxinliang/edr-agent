#Requires -Version 5.1
# Executes the production retry script against a fake native vcpkg process.
$ErrorActionPreference = 'Stop'

function Assert-RetryTest([bool] $Condition, [string] $Message) {
  if (-not $Condition) { throw "vcpkg retry regression: $Message" }
}

$retryScript = Join-Path $PSScriptRoot '../scripts/Invoke-VcpkgInstallWithRetry.ps1'
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('edr-vcpkg-retry-' + [guid]::NewGuid().ToString('N'))
$isWindowsHost = $env:OS -eq 'Windows_NT'
$originalStateDir = $env:EDR_FAKE_VCPKG_STATE_DIR
$originalMode = $env:EDR_FAKE_VCPKG_MODE
$originalFailures = $env:EDR_FAKE_VCPKG_FAILURES
$originalConcurrency = [Environment]::GetEnvironmentVariable('VCPKG_MAX_CONCURRENCY', 'Process')

try {
  New-Item -ItemType Directory -Path $testRoot | Out-Null
  if ($isWindowsHost) {
    $fakeVcpkg = Join-Path $testRoot 'fake-vcpkg.cmd'
    $fakeSource = @'
@echo off
setlocal EnableExtensions EnableDelayedExpansion
set /p ATTEMPT=<"%EDR_FAKE_VCPKG_STATE_DIR%\attempt.txt"
set /a ATTEMPT+=1
>"%EDR_FAKE_VCPKG_STATE_DIR%\attempt.txt" echo !ATTEMPT!
echo fake-vcpkg stdout attempt=!ATTEMPT! args=%*
echo fake-vcpkg stderr attempt=!ATTEMPT! 1>&2
if !ATTEMPT! GTR 1 if not exist "%EDR_FAKE_VCPKG_STATE_DIR%\download-cache.marker" exit /b 91
>"%EDR_FAKE_VCPKG_STATE_DIR%\download-cache.marker" echo retained
if !ATTEMPT! GTR %EDR_FAKE_VCPKG_FAILURES% exit /b 0
if "%EDR_FAKE_VCPKG_MODE%"=="curl35" echo error: curl operation failed with error code 35 ^(SSL connect error^). 1>&2
if "%EDR_FAKE_VCPKG_MODE%"=="curl35summary" (
  echo error: curl operation failed with error code 35 ^(SSL connect error^). 1>&2
  echo error: building cmake:x64-windows failed with: BUILD_FAILED. 1>&2
)
if "%EDR_FAKE_VCPKG_MODE%"=="timeout28" echo error: curl operation failed with error code 28 ^(operation timed out^). 1>&2
if "%EDR_FAKE_VCPKG_MODE%"=="rate429" echo error: response code 429: Too Many Requests. 1>&2
if "%EDR_FAKE_VCPKG_MODE%"=="rate429curl22" (
  echo error: response code 429: Too Many Requests. 1>&2
  echo error: curl operation failed with error code 22. 1>&2
)
if "%EDR_FAKE_VCPKG_MODE%"=="rate429curl23" (
  echo error: response code 429: Too Many Requests. 1>&2
  echo error: curl operation failed with error code 23. 1>&2
)
if "%EDR_FAKE_VCPKG_MODE%"=="rate429curl58" (
  echo error: response code 429: Too Many Requests. 1>&2
  echo error: curl operation failed with error code 58. 1>&2
)
if "%EDR_FAKE_VCPKG_MODE%"=="rate429curl59" (
  echo error: response code 429: Too Many Requests. 1>&2
  echo error: curl operation failed with error code 59. 1>&2
)
if "%EDR_FAKE_VCPKG_MODE%"=="compilecurl35" (
  echo error: curl operation failed with error code 35 ^(SSL connect error^). 1>&2
  echo source.c:42:1: error: syntax error. 1>&2
  echo error: building yara:x64-windows failed with: BUILD_FAILED. 1>&2
)
if "%EDR_FAKE_VCPKG_MODE%"=="cert60" echo error: curl operation failed with error code 60 ^(SSL certificate problem^). 1>&2
if "%EDR_FAKE_VCPKG_MODE%"=="cert77" echo error: curl operation failed with error code 77 ^(problem with the SSL CA cert^). 1>&2
if "%EDR_FAKE_VCPKG_MODE%"=="hash" echo error: SHA512 mismatch for downloaded archive. 1>&2
if "%EDR_FAKE_VCPKG_MODE%"=="compile" echo error: building yara:x64-windows failed with: BUILD_FAILED. 1>&2
exit /b 42
'@
    [IO.File]::WriteAllText($fakeVcpkg, $fakeSource, [Text.Encoding]::ASCII)
  }
  else {
    $fakeVcpkg = Join-Path $testRoot 'fake-vcpkg'
    $fakeSource = @'
#!/bin/sh
attempt=$(cat "$EDR_FAKE_VCPKG_STATE_DIR/attempt.txt")
attempt=$((attempt + 1))
printf '%s\n' "$attempt" > "$EDR_FAKE_VCPKG_STATE_DIR/attempt.txt"
printf 'fake-vcpkg stdout attempt=%s args=%s\n' "$attempt" "$*"
printf 'fake-vcpkg stderr attempt=%s\n' "$attempt" >&2
if [ "$attempt" -gt 1 ] && [ ! -f "$EDR_FAKE_VCPKG_STATE_DIR/download-cache.marker" ]; then exit 91; fi
printf 'retained\n' > "$EDR_FAKE_VCPKG_STATE_DIR/download-cache.marker"
if [ "$attempt" -gt "$EDR_FAKE_VCPKG_FAILURES" ]; then exit 0; fi
case "$EDR_FAKE_VCPKG_MODE" in
  curl35) printf 'error: curl operation failed with error code 35 (SSL connect error).\n' >&2 ;;
  curl35summary) printf 'error: curl operation failed with error code 35 (SSL connect error).\nerror: building cmake:x64-windows failed with: BUILD_FAILED.\n' >&2 ;;
  timeout28) printf 'error: curl operation failed with error code 28 (operation timed out).\n' >&2 ;;
  rate429) printf 'error: response code 429: Too Many Requests.\n' >&2 ;;
  rate429curl22) printf 'error: response code 429: Too Many Requests.\nerror: curl operation failed with error code 22.\n' >&2 ;;
  rate429curl23) printf 'error: response code 429: Too Many Requests.\nerror: curl operation failed with error code 23.\n' >&2 ;;
  rate429curl58) printf 'error: response code 429: Too Many Requests.\nerror: curl operation failed with error code 58.\n' >&2 ;;
  rate429curl59) printf 'error: response code 429: Too Many Requests.\nerror: curl operation failed with error code 59.\n' >&2 ;;
  compilecurl35) printf 'error: curl operation failed with error code 35 (SSL connect error).\nsource.c(42): error C2143: syntax error.\nerror: building yara:x64-windows failed with: BUILD_FAILED.\n' >&2 ;;
  cert60) printf 'error: curl operation failed with error code 60 (SSL certificate problem).\n' >&2 ;;
  cert77) printf 'error: curl operation failed with error code 77 (problem with the SSL CA cert).\n' >&2 ;;
  hash) printf 'error: SHA512 mismatch for downloaded archive.\n' >&2 ;;
  compile) printf 'error: building yara:x64-windows failed with: BUILD_FAILED.\n' >&2 ;;
esac
exit 42
'@
    [IO.File]::WriteAllText($fakeVcpkg, $fakeSource, [Text.UTF8Encoding]::new($false))
    & chmod 700 $fakeVcpkg
    if ($LASTEXITCODE -ne 0) { throw "chmod failed for fake vcpkg: $LASTEXITCODE" }
  }

  $cases = @(
    @{ Name = 'curl35-recovers'; Mode = 'curl35'; Failures = 1; MaxAttempts = 4; Attempts = 2; Delays = @(2); Error = ''; UnsetConcurrency = $true },
    @{ Name = 'curl35-build-summary-recovers'; Mode = 'curl35summary'; Failures = 1; MaxAttempts = 4; Attempts = 2; Delays = @(2); Error = '' },
    @{ Name = 'timeout28-recovers'; Mode = 'timeout28'; Failures = 1; MaxAttempts = 4; Attempts = 2; Delays = @(2); Error = '' },
    @{ Name = 'curl35-exhausted'; Mode = 'curl35'; Failures = 99; MaxAttempts = 3; Attempts = 3; Delays = @(2, 4); Error = 'exhausted retryable download failures after 3 attempts.*last exit code 42' },
    @{ Name = 'http429-recovers'; Mode = 'rate429'; Failures = 1; MaxAttempts = 4; Attempts = 2; Delays = @(2); Error = '' },
    @{ Name = 'http429-curl22-recovers'; Mode = 'rate429curl22'; Failures = 1; MaxAttempts = 4; Attempts = 2; Delays = @(2); Error = '' },
    @{ Name = 'http429-curl23-fails-fast'; Mode = 'rate429curl23'; Failures = 99; MaxAttempts = 4; Attempts = 1; Delays = @(); Error = 'exit code 42.*non-retryable curl error 23' },
    @{ Name = 'http429-curl58-fails-fast'; Mode = 'rate429curl58'; Failures = 99; MaxAttempts = 4; Attempts = 1; Delays = @(); Error = 'exit code 42.*non-retryable curl error 58' },
    @{ Name = 'http429-curl59-fails-fast'; Mode = 'rate429curl59'; Failures = 99; MaxAttempts = 4; Attempts = 1; Delays = @(); Error = 'exit code 42.*non-retryable curl error 59' },
    @{ Name = 'compiler-evidence-beats-curl35'; Mode = 'compilecurl35'; Failures = 99; MaxAttempts = 4; Attempts = 1; Delays = @(); Error = 'exit code 42.*compiler or linker failure' },
    @{ Name = 'certificate60-fails-fast'; Mode = 'cert60'; Failures = 99; MaxAttempts = 4; Attempts = 1; Delays = @(); Error = 'exit code 42.*certificate validation failure' },
    @{ Name = 'certificate77-fails-fast'; Mode = 'cert77'; Failures = 99; MaxAttempts = 4; Attempts = 1; Delays = @(); Error = 'exit code 42.*certificate validation failure' },
    @{ Name = 'hash-fails-fast'; Mode = 'hash'; Failures = 99; MaxAttempts = 4; Attempts = 1; Delays = @(); Error = 'exit code 42.*download integrity failure' },
    @{ Name = 'build-summary-alone-fails-fast'; Mode = 'compile'; Failures = 99; MaxAttempts = 4; Attempts = 1; Delays = @(); Error = 'exit code 42.*unclassified failure' }
  )

  foreach ($case in $cases) {
    $caseDir = Join-Path $testRoot $case.Name
    New-Item -ItemType Directory -Path $caseDir | Out-Null
    [IO.File]::WriteAllText((Join-Path $caseDir 'attempt.txt'), '0')
    $env:EDR_FAKE_VCPKG_STATE_DIR = $caseDir
    $env:EDR_FAKE_VCPKG_MODE = $case.Mode
    $env:EDR_FAKE_VCPKG_FAILURES = [string]$case.Failures
    if ($case.ContainsKey('UnsetConcurrency') -and $case.UnsetConcurrency) {
      Remove-Item Env:VCPKG_MAX_CONCURRENCY -ErrorAction SilentlyContinue
    }
    else {
      $env:VCPKG_MAX_CONCURRENCY = '7'
    }

    $delays = New-Object 'System.Collections.Generic.List[int]'
    $sleepAction = { param($Seconds) $delays.Add([int]$Seconds) }.GetNewClosure()
    $jitterAction = { param($Attempt) return 0 }
    $stream = New-Object 'System.Collections.Generic.List[string]'
    $failure = ''
    try {
      & $retryScript -VcpkgExe $fakeVcpkg -FeatureArgs @('--x-feature=sqlite', '--x-feature=yara') `
        -MaxAttempts $case.MaxAttempts -InitialBackoffSeconds 2 `
        -SleepAction $sleepAction -JitterAction $jitterAction *>&1 |
        ForEach-Object { $stream.Add([string]$_) }
    }
    catch {
      $failure = $_.Exception.Message
    }

    $attempts = [int](Get-Content -LiteralPath (Join-Path $caseDir 'attempt.txt') -Raw)
    Assert-RetryTest ($attempts -eq $case.Attempts) "$($case.Name) attempt count was $attempts"
    Assert-RetryTest (($delays -join ',') -ceq ($case.Delays -join ',')) "$($case.Name) delays were $($delays -join ',')"
    if ($case.ContainsKey('UnsetConcurrency') -and $case.UnsetConcurrency) {
      $restoredConcurrency = [Environment]::GetEnvironmentVariable('VCPKG_MAX_CONCURRENCY', 'Process')
      Assert-RetryTest ([string]::IsNullOrEmpty($restoredConcurrency)) "$($case.Name) leaked managed concurrency"
    }
    else {
      Assert-RetryTest ($env:VCPKG_MAX_CONCURRENCY -ceq '7') "$($case.Name) changed caller concurrency"
    }
    Assert-RetryTest (Test-Path -LiteralPath (Join-Path $caseDir 'download-cache.marker')) "$($case.Name) removed cached download state"
    $diagnostic = ($stream -join [Environment]::NewLine)
    Assert-RetryTest ($diagnostic -match 'fake-vcpkg stdout attempt=1') "$($case.Name) lost native stdout"
    Assert-RetryTest ($diagnostic -match 'fake-vcpkg stderr attempt=1') "$($case.Name) lost native stderr"
    Assert-RetryTest ($diagnostic -match '\[vcpkg\] total install elapsed_seconds=') "$($case.Name) lost elapsed-time diagnostic"
    if ([string]::IsNullOrEmpty($case.Error)) {
      Assert-RetryTest ([string]::IsNullOrEmpty($failure)) "$($case.Name) failed unexpectedly: $failure"
      Assert-RetryTest ($diagnostic -match "install succeeded on attempt $($case.Attempts)") "$($case.Name) did not report recovery"
    }
    else {
      Assert-RetryTest ($failure -match $case.Error) "$($case.Name) wrong failure: $failure"
    }
    Write-Host "PASS $($case.Name)"
  }

  Write-Host "Passed $($cases.Count) vcpkg retry cases"
}
finally {
  $env:EDR_FAKE_VCPKG_STATE_DIR = $originalStateDir
  $env:EDR_FAKE_VCPKG_MODE = $originalMode
  $env:EDR_FAKE_VCPKG_FAILURES = $originalFailures
  if ($null -eq $originalConcurrency) {
    Remove-Item Env:VCPKG_MAX_CONCURRENCY -ErrorAction SilentlyContinue
  }
  else {
    $env:VCPKG_MAX_CONCURRENCY = $originalConcurrency
  }
  if (Test-Path -LiteralPath $testRoot) { Remove-Item -LiteralPath $testRoot -Recurse -Force }
}
