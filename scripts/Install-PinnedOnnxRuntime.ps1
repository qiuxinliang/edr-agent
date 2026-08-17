#Requires -Version 5.1
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [ValidateSet("x64", "arm64")]
  [string] $Architecture,
  [ValidatePattern('^[0-9a-fA-F]{64}$')]
  [string] $ExpectedSha256 = "",
  [string] $Version = "",
  [Int64] $ExpectedSize = 0,
  [string] $LockFile = "",
  [string] $DestinationRoot = "",
  [string] $GithubEnvPath = $env:GITHUB_ENV
)

$ErrorActionPreference = "Stop"
$repositoryRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($LockFile)) {
  $LockFile = Join-Path $repositoryRoot "dependencies.lock.json"
}
& (Join-Path $PSScriptRoot "Validate-DependencyLocks.ps1") -RepositoryRoot $repositoryRoot
if ([string]::IsNullOrWhiteSpace($Version) -or [string]::IsNullOrWhiteSpace($ExpectedSha256)) {
  if (-not (Test-Path -LiteralPath $LockFile -PathType Leaf)) {
    throw "Dependency lock file was not found: $LockFile"
  }
  $lock = [IO.File]::ReadAllText($LockFile) | ConvertFrom-Json
  $onnx = $lock.onnxruntime
  if ([string]::IsNullOrWhiteSpace($Version)) { $Version = [string]$onnx.version }
  if ([string]::IsNullOrWhiteSpace($ExpectedSha256)) {
    $ExpectedSha256 = [string]$onnx.archives.$Architecture.sha256
  }
  if ($ExpectedSize -le 0) {
    $ExpectedSize = [Int64]$onnx.archives.$Architecture.size_bytes
  }
}
if ($Version -notmatch '^\d+\.\d+\.\d+$') { throw "Invalid locked ONNX Runtime version: $Version" }
if ($ExpectedSha256 -notmatch '^[0-9a-fA-F]{64}$') {
  throw "Invalid locked ONNX Runtime SHA256 for $Architecture"
}
if ([string]::IsNullOrWhiteSpace($DestinationRoot)) {
  $DestinationRoot = Join-Path $repositoryRoot "onnxrt-win"
}
$DestinationRoot = [IO.Path]::GetFullPath($DestinationRoot)
New-Item -ItemType Directory -Path $DestinationRoot -Force | Out-Null

$archiveName = "onnxruntime-win-$Architecture-$Version"
$zipPath = Join-Path $DestinationRoot ($archiveName + ".zip")
$runtimeRoot = Join-Path $DestinationRoot $archiveName
$markerPath = Join-Path $runtimeRoot ".archive-sha256"
$expected = $ExpectedSha256.ToLowerInvariant()
$cachedMarker = if (Test-Path -LiteralPath $markerPath -PathType Leaf) {
  ([IO.File]::ReadAllText($markerPath)).Trim().ToLowerInvariant()
} else { "" }
$requiredHeader = Join-Path $runtimeRoot "include\onnxruntime_c_api.h"
$requiredLibrary = Join-Path $runtimeRoot "lib\onnxruntime.lib"
if ($cachedMarker -eq $expected -and
    (Test-Path -LiteralPath $requiredHeader -PathType Leaf) -and
    (Test-Path -LiteralPath $requiredLibrary -PathType Leaf)) {
  Write-Host "Pinned ONNX Runtime cache verified: arch=$Architecture version=$Version sha256=$expected"
} else {
  $download = $zipPath + ".download"
  Remove-Item -LiteralPath $download -Force -ErrorAction SilentlyContinue
  $url = "https://github.com/microsoft/onnxruntime/releases/download/v$Version/$archiveName.zip"
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  $progressPreference = 'SilentlyContinue'
  for ($attempt = 1; $attempt -le 5; $attempt++) {
    try {
      Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $download
      break
    } catch {
      Remove-Item -LiteralPath $download -Force -ErrorAction SilentlyContinue
      if ($attempt -eq 5) { throw "ONNX Runtime download exhausted retries: $($_.Exception.Message)" }
      Start-Sleep -Seconds ([Math]::Min(30, 5 * $attempt))
    }
  }
  $actualSize = (Get-Item -LiteralPath $download).Length
  if ($ExpectedSize -gt 0 -and $actualSize -ne $ExpectedSize) {
    Remove-Item -LiteralPath $download -Force -ErrorAction SilentlyContinue
    throw "ONNX Runtime ZIP size mismatch: arch=$Architecture expected=$ExpectedSize actual=$actualSize"
  }
  $actual = (Get-FileHash -LiteralPath $download -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($actual -ne $expected) {
    Remove-Item -LiteralPath $download -Force -ErrorAction SilentlyContinue
    throw "ONNX Runtime ZIP SHA256 mismatch: arch=$Architecture expected=$expected actual=$actual"
  }
  Move-Item -LiteralPath $download -Destination $zipPath -Force
  Remove-Item -LiteralPath $runtimeRoot -Recurse -Force -ErrorAction SilentlyContinue
  Expand-Archive -LiteralPath $zipPath -DestinationPath $DestinationRoot -Force
  if (-not (Test-Path -LiteralPath $requiredHeader -PathType Leaf) -or
      -not (Test-Path -LiteralPath $requiredLibrary -PathType Leaf)) {
    throw "ONNX Runtime extracted layout is incomplete: $runtimeRoot"
  }
  [IO.File]::WriteAllText($markerPath, $expected + [Environment]::NewLine, [Text.Encoding]::ASCII)
  Write-Host "Pinned ONNX Runtime installed: arch=$Architecture version=$Version sha256=$expected"
}
if (-not [string]::IsNullOrWhiteSpace($GithubEnvPath)) {
  Add-Content -LiteralPath $GithubEnvPath -Value ("ONNXRUNTIME_ROOT={0}" -f $runtimeRoot) -Encoding UTF8
}
Write-Output $runtimeRoot
