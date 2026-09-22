#Requires -Version 5.1
<#
  Installs a pinned vcpkg manifest with bounded download recovery.

  GitHub source archive downloads are an external dependency. HTTP 429 and a
  small allow-list of curl transport failures may be retried, but certificate,
  hash, compiler, and linker failures must fail immediately so CI does not hide
  security or build regressions.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string] $VcpkgExe,
  [string[]] $FeatureArgs = @(),
  [ValidateRange(1, 8)]
  [int] $MaxAttempts = 5,
  [ValidateRange(1, 300)]
  [int] $InitialBackoffSeconds = 20,
  [Parameter(DontShow = $true)]
  [scriptblock] $SleepAction,
  [Parameter(DontShow = $true)]
  [scriptblock] $JitterAction
)

$ErrorActionPreference = "Stop"
if (-not (Test-Path -LiteralPath $VcpkgExe -PathType Leaf)) {
  throw "vcpkg executable was not found: $VcpkgExe"
}

function Get-VcpkgFailureDisposition {
  param([Parameter(Mandatory = $true)][string] $OutputText)

  # Permanent failures take precedence over retryable-looking text. A failed
  # certificate or integrity check must never be hidden by an earlier network
  # diagnostic emitted in the same vcpkg invocation.
  $certificateFailure = $OutputText -match '(?im)(curl operation failed with error code\s+(60|77)\b|ssl certificate problem|certificate verify failed|certificate verification failed|problem with the ssl ca cert|CERT_E_[A-Z_]+)'
  if ($certificateFailure) {
    return [pscustomobject]@{ Retry = $false; Reason = 'certificate validation failure' }
  }

  $integrityFailure = $OutputText -match '(?im)(hash mismatch|sha-?(256|512)[^\r\n]*mismatch|unexpected hash|does not have the expected hash)'
  if ($integrityFailure) {
    return [pscustomobject]@{ Retry = $false; Reason = 'download integrity failure' }
  }

  # BUILD_FAILED by itself is only vcpkg's summary and can follow a source-tool
  # download failure. Require concrete compiler, linker, or build-tool evidence.
  $buildFailure = $OutputText -match '(?im)(\b(fatal\s+)?error\s+C\d{4}\b|\b(fatal\s+)?error\s+LNK\d+\b|[^\r\n:]+:\d+:\d+:\s+(fatal\s+)?error:|ninja:\s+build stopped|MSB\d+:\s*error|linker command failed|compilation terminated)'
  if ($buildFailure) {
    return [pscustomobject]@{ Retry = $false; Reason = 'compiler or linker failure' }
  }

  $rateLimited = $OutputText -match '(?im)(response\s+code\s+429|http\s*429|too\s+many\s+requests|rate\s*limit)'
  $curlMatches = [regex]::Matches($OutputText, '(?im)curl operation failed with error code\s+(\d+)\b')
  if ($curlMatches.Count -gt 0) {
    # These codes describe failures before a verified archive is available:
    # DNS/connect, partial transfer, timeout, TLS connect, or connection I/O.
    # Local writes (23), certificate checks (60/77), HTTP status failures other
    # than an explicit 429+curl-22 pair, and unclassified codes remain fail-fast.
    $retryableCurlCodes = @(5, 6, 7, 18, 28, 35, 52, 55, 56)
    $observedCodes = New-Object 'System.Collections.Generic.List[int]'
    foreach ($match in $curlMatches) {
      $code = [int]$match.Groups[1].Value
      $null = $observedCodes.Add($code)
      # curl 22 represents an HTTP status failure. It is retryable only when
      # the same invocation explicitly identifies that status as HTTP 429.
      $isExplicitRateLimitCode = $code -eq 22 -and $rateLimited
      if (($retryableCurlCodes -notcontains $code) -and -not $isExplicitRateLimitCode) {
        return [pscustomobject]@{ Retry = $false; Reason = "non-retryable curl error $code" }
      }
    }
    if ($rateLimited) {
      return [pscustomobject]@{ Retry = $true; Reason = 'HTTP 429 rate limit' }
    }
    $codeText = ($observedCodes | Sort-Object -Unique) -join ','
    return [pscustomobject]@{ Retry = $true; Reason = "transient curl transport error $codeText" }
  }

  if ($rateLimited) {
    return [pscustomobject]@{ Retry = $true; Reason = 'HTTP 429 rate limit' }
  }

  return [pscustomobject]@{ Retry = $false; Reason = 'unclassified failure' }
}

function Get-VcpkgAttemptSummary {
  param([string[]] $Lines, [int] $Attempt, [int] $ExitCode, [double] $ElapsedSeconds)

  $restored = 0
  $restoreCountObserved = $false
  $sourcePackages = [ordered]@{}
  foreach ($line in $Lines) {
    # Only vcpkg's binary restore result proves an ABI cache hit. A downloaded
    # source archive, or a restored Actions archive, does not prove reuse.
    if ($line -match '^Restored (\d+) package\(s\) from ') {
      $restored += [int]$Matches[1]
      $restoreCountObserved = $true
    }
    elseif ($line -match '^Building ([A-Za-z0-9_.+-]+)(?:\[[A-Za-z0-9_,.+-]*\])?:([A-Za-z0-9_-]+)(?:@|\.\.\.|\s|$)') {
      $package = $Matches[1] + ':' + $Matches[2]
      if (-not $sourcePackages.Contains($package)) {
        $sourcePackages[$package] = [pscustomobject]@{ Package = $package; Elapsed = ''; Completed = $false }
      }
    }
    elseif ($line -match '^Elapsed time to handle ([A-Za-z0-9_.+-]+):([A-Za-z0-9_-]+):\s*([0-9.,]+\s*[A-Za-z]+)\s*$') {
      $package = $Matches[1] + ':' + $Matches[2]
      if ($sourcePackages.Contains($package)) {
        $sourcePackages[$package].Elapsed = $Matches[3]
        $sourcePackages[$package].Completed = $true
      }
    }
  }
  $completed = @($sourcePackages.Values | Where-Object { $_.Completed }).Count
  return [pscustomobject]@{
    Attempt = $Attempt
    ExitCode = $ExitCode
    ElapsedSeconds = $ElapsedSeconds
    BinaryRestored = if ($restoreCountObserved) { [string]$restored } else { 'unknown' }
    SourceStarted = $sourcePackages.Count
    SourceCompleted = $completed
    SourcePackages = @($sourcePackages.Values)
  }
}

function Write-VcpkgInstallSummary {
  param([object[]] $Attempts, [double] $ElapsedSeconds, [bool] $Succeeded)

  $result = if ($Succeeded) { 'success' } else { 'failure' }
  Write-Host ("[vcpkg] total install elapsed_seconds={0:F1} attempts={1} result={2}" -f $ElapsedSeconds, $Attempts.Count, $result)
  $summary = New-Object 'System.Collections.Generic.List[string]'
  $summary.Add('### vcpkg install')
  $summary.Add('')
  $summary.Add(('Result: {0}; attempts: {1}; total elapsed: {2:F1} seconds (including retry waits).' -f $result, $Attempts.Count, $ElapsedSeconds))
  $summary.Add('')
  $summary.Add('| Attempt | Exit code | Seconds | Binary packages restored | Source builds started | Source builds completed |')
  $summary.Add('| --- | --- | --- | --- | --- | --- |')
  foreach ($item in $Attempts) {
    Write-Host ("[vcpkg] attempt summary attempt={0} exit_code={1} elapsed_seconds={2:F1} binary_restored={3} source_started={4} source_completed={5}" -f $item.Attempt, $item.ExitCode, $item.ElapsedSeconds, $item.BinaryRestored, $item.SourceStarted, $item.SourceCompleted)
    $summary.Add(('| {0} | {1} | {2:F1} | {3} | {4} | {5} |' -f $item.Attempt, $item.ExitCode, $item.ElapsedSeconds, $item.BinaryRestored, $item.SourceStarted, $item.SourceCompleted))
  }
  $summary.Add('')
  $summary.Add('Binary restores are reported by vcpkg after ABI selection; source-download cache hits are not binary restores. Counts are per attempt and are not added across retries. Unknown means vcpkg emitted no restore count. Source completion requires a matching package elapsed-time line.')
  $summary.Add('')
  foreach ($item in $Attempts) {
    foreach ($package in $item.SourcePackages) {
      $state = if ($package.Completed) { 'completed' } else { 'started; no completion reported' }
      $elapsed = if ($package.Elapsed) { $package.Elapsed } else { 'unknown' }
      Write-Host ("[vcpkg] source package attempt={0} package={1} state={2} elapsed={3}" -f $item.Attempt, $package.Package, $state, $elapsed)
      $summary.Add(('- Attempt {0}: {1}; {2}; elapsed: {3}.' -f $item.Attempt, $package.Package, $state, $elapsed))
    }
  }
  if (-not [string]::IsNullOrWhiteSpace($env:GITHUB_STEP_SUMMARY)) {
    Add-Content -LiteralPath $env:GITHUB_STEP_SUMMARY -Value ($summary -join [Environment]::NewLine) -Encoding UTF8
  }
}

$installArgs = @("install") + @($FeatureArgs)
$previousConcurrency = [Environment]::GetEnvironmentVariable("VCPKG_MAX_CONCURRENCY", "Process")
$restoreConcurrency = $false
if ([string]::IsNullOrWhiteSpace($previousConcurrency)) {
  # AMD64 and ARM64 run independently; bound each runner's local fan-out.
  # Keep a small local fan-out for port builds rather than forcing every
  # OpenSSL/YARA dependency to compile one at a time.
  $parallelism = [Math]::Max(1, [Math]::Min(4, [Environment]::ProcessorCount))
  $env:VCPKG_MAX_CONCURRENCY = [string]$parallelism
  $restoreConcurrency = $true
}

$installTimer = [Diagnostics.Stopwatch]::StartNew()
$attemptSummaries = New-Object 'System.Collections.Generic.List[object]'
$installSucceeded = $false
try {
  for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
    Write-Host "[vcpkg] install attempt $attempt/$MaxAttempts (max parallel build jobs: $env:VCPKG_MAX_CONCURRENCY)"
    $output = New-Object 'System.Collections.Generic.List[string]'
    $attemptTimer = [Diagnostics.Stopwatch]::StartNew()
    $previousErrorActionPreference = $ErrorActionPreference
    $hasNativeErrorPreference = $PSVersionTable.PSVersion.Major -ge 7
    if ($hasNativeErrorPreference) {
      $previousNativeErrorPreference = $PSNativeCommandUseErrorActionPreference
      $PSNativeCommandUseErrorActionPreference = $false
    }
    try {
      # Windows PowerShell 5.1 turns redirected native stderr into non-terminating
      # ErrorRecords. Keep those records in the diagnostic stream without letting
      # the script-level Stop preference abort before $LASTEXITCODE is inspected.
      $ErrorActionPreference = 'Continue'
      & $VcpkgExe @installArgs 2>&1 | ForEach-Object {
        $line = [string]$_
        $null = $output.Add($line)
        Write-Host $line
      }
      $exitCode = $LASTEXITCODE
    }
    finally {
      $ErrorActionPreference = $previousErrorActionPreference
      if ($hasNativeErrorPreference) {
        $PSNativeCommandUseErrorActionPreference = $previousNativeErrorPreference
      }
      $attemptTimer.Stop()
    }
    $attemptSummaries.Add((Get-VcpkgAttemptSummary -Lines $output.ToArray() -Attempt $attempt -ExitCode $exitCode -ElapsedSeconds $attemptTimer.Elapsed.TotalSeconds))
    if ($exitCode -eq 0) {
      $installSucceeded = $true
      Write-Host "[vcpkg] install succeeded on attempt $attempt"
      return
    }

    $outputText = $output -join [Environment]::NewLine
    $disposition = Get-VcpkgFailureDisposition -OutputText $outputText
    if (-not $disposition.Retry) {
      throw "vcpkg install failed with exit code $exitCode; not retrying because the failure is not an HTTP 429 rate limit or allow-listed transient download transport error ($($disposition.Reason))"
    }
    if ($attempt -eq $MaxAttempts) {
      throw "vcpkg install exhausted retryable download failures after $MaxAttempts attempts ($($disposition.Reason); last exit code $exitCode)"
    }

    $exponent = [Math]::Pow(2, $attempt - 1)
    $backoff = [Math]::Min(300, [int]($InitialBackoffSeconds * $exponent))
    $jitter = if ($null -ne $JitterAction) { [int](& $JitterAction $attempt) } else { Get-Random -Minimum 0 -Maximum 16 }
    if ($jitter -lt 0 -or $jitter -gt 15) {
      throw "vcpkg retry jitter must be between 0 and 15 seconds; got $jitter"
    }
    $delay = [Math]::Min(300, $backoff + $jitter)
    Write-Warning "[vcpkg] $($disposition.Reason) detected; retrying in $delay seconds. Cached downloads are retained."
    if ($null -ne $SleepAction) {
      & $SleepAction $delay
    }
    else {
      Start-Sleep -Seconds $delay
    }
  }
}
finally {
  $installTimer.Stop()
  if ($restoreConcurrency) {
    Remove-Item Env:VCPKG_MAX_CONCURRENCY -ErrorAction SilentlyContinue
  }
  elseif ($null -ne $previousConcurrency) {
    $env:VCPKG_MAX_CONCURRENCY = $previousConcurrency
  }
  try {
    Write-VcpkgInstallSummary -Attempts $attemptSummaries.ToArray() -ElapsedSeconds $installTimer.Elapsed.TotalSeconds -Succeeded $installSucceeded
  }
  catch {
    # Preserve an existing install failure, but never claim successful diagnostics
    # when their required GitHub destination could not be written.
    Write-Warning "[vcpkg] install summary could not be written: $($_.Exception.Message)"
    if ($installSucceeded) { throw }
  }
}
