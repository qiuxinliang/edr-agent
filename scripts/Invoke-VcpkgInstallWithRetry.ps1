#Requires -Version 5.1
<#
  Installs a pinned vcpkg manifest with bounded rate-limit recovery.

  GitHub source archive downloads are an external dependency. A 429 must not
  be mistaken for a port or compiler failure, but non-rate-limit errors must
  still fail immediately so CI does not hide real build regressions.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string] $VcpkgExe,
  [string[]] $FeatureArgs = @(),
  [ValidateRange(1, 8)]
  [int] $MaxAttempts = 5,
  [ValidateRange(1, 300)]
  [int] $InitialBackoffSeconds = 20
)

$ErrorActionPreference = "Stop"
if (-not (Test-Path -LiteralPath $VcpkgExe -PathType Leaf)) {
  throw "vcpkg executable was not found: $VcpkgExe"
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
try {
  for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
    Write-Host "[vcpkg] install attempt $attempt/$MaxAttempts (max parallel build jobs: $env:VCPKG_MAX_CONCURRENCY)"
    $output = New-Object 'System.Collections.Generic.List[string]'
    & $VcpkgExe @installArgs 2>&1 | ForEach-Object {
      $line = [string]$_
      $null = $output.Add($line)
      Write-Host $line
    }
    $exitCode = $LASTEXITCODE
    if ($exitCode -eq 0) {
      Write-Host "[vcpkg] install succeeded on attempt $attempt"
      return
    }

    $outputText = $output -join [Environment]::NewLine
    $rateLimited = $outputText -match '(?im)(response\s+code\s+429|http\s*429|too\s+many\s+requests|rate\s*limit)'
    if (-not $rateLimited) {
      throw "vcpkg install failed with exit code $exitCode; not retrying because the failure is not an HTTP 429 rate limit"
    }
    if ($attempt -eq $MaxAttempts) {
      throw "vcpkg install remained GitHub-rate-limited after $MaxAttempts attempts (last exit code $exitCode)"
    }

    $exponent = [Math]::Pow(2, $attempt - 1)
    $backoff = [Math]::Min(300, [int]($InitialBackoffSeconds * $exponent))
    $jitter = Get-Random -Minimum 0 -Maximum 16
    $delay = $backoff + $jitter
    Write-Warning "[vcpkg] GitHub archive rate limit detected; retrying in $delay seconds. Cached downloads are retained."
    Start-Sleep -Seconds $delay
  }
}
finally {
  $installTimer.Stop()
  Write-Host ("[vcpkg] total install elapsed_seconds={0:F1}" -f $installTimer.Elapsed.TotalSeconds)
  if ($restoreConcurrency) {
    Remove-Item Env:VCPKG_MAX_CONCURRENCY -ErrorAction SilentlyContinue
  }
  elseif ($null -ne $previousConcurrency) {
    $env:VCPKG_MAX_CONCURRENCY = $previousConcurrency
  }
}
