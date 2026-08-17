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
# Source fallbacks are rare. Keep them serialized so a cold ARM64 and AMD64
# cache miss cannot multiply requests against GitHub's archive endpoint.
$env:VCPKG_MAX_CONCURRENCY = "1"

try {
  for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
    Write-Host "[vcpkg] install attempt $attempt/$MaxAttempts (serialized source fallback)"
    $output = @(& $VcpkgExe @installArgs 2>&1)
    $exitCode = $LASTEXITCODE
    $output | ForEach-Object { Write-Host $_ }
    if ($exitCode -eq 0) {
      Write-Host "[vcpkg] install succeeded on attempt $attempt"
      return
    }

    $outputText = $output | Out-String
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
  if ($null -eq $previousConcurrency) {
    Remove-Item Env:VCPKG_MAX_CONCURRENCY -ErrorAction SilentlyContinue
  }
  else {
    $env:VCPKG_MAX_CONCURRENCY = $previousConcurrency
  }
}
