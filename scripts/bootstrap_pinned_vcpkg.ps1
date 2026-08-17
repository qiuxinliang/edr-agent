#Requires -Version 5.1
[CmdletBinding()]
param(
  [string] $RepositoryRoot = "",
  [string] $VcpkgRoot = ""
)

$ErrorActionPreference = "Stop"
if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) {
  $RepositoryRoot = Split-Path -Parent $PSScriptRoot
}
$RepositoryRoot = [IO.Path]::GetFullPath($RepositoryRoot)
& (Join-Path $PSScriptRoot "Validate-DependencyLocks.ps1") -RepositoryRoot $RepositoryRoot
if ([string]::IsNullOrWhiteSpace($VcpkgRoot)) {
  $VcpkgRoot = Join-Path $RepositoryRoot "vcpkg"
}
$VcpkgRoot = [IO.Path]::GetFullPath($VcpkgRoot)

$manifestPath = Join-Path $RepositoryRoot "vcpkg.json"
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
  throw "Missing vcpkg manifest: $manifestPath"
}
$manifest = [IO.File]::ReadAllText($manifestPath) | ConvertFrom-Json
$baseline = [string]$manifest.'builtin-baseline'
if ($baseline -notmatch '^[0-9a-f]{40}$') {
  throw "vcpkg.json must contain a lowercase 40-character builtin-baseline"
}

if (-not (Test-Path -LiteralPath $VcpkgRoot -PathType Container)) {
  New-Item -ItemType Directory -Path $VcpkgRoot -Force | Out-Null
  & git -C $VcpkgRoot init --quiet
  if ($LASTEXITCODE -ne 0) { throw "git init failed for pinned vcpkg" }
  & git -C $VcpkgRoot remote add origin https://github.com/microsoft/vcpkg.git
  if ($LASTEXITCODE -ne 0) { throw "git remote add failed for pinned vcpkg" }
}
if (-not (Test-Path -LiteralPath (Join-Path $VcpkgRoot ".git") -PathType Container)) {
  throw "Existing vcpkg path is not a Git repository: $VcpkgRoot"
}

$origin = (& git -C $VcpkgRoot remote get-url origin 2>$null | Select-Object -First 1)
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace([string]$origin)) {
  & git -C $VcpkgRoot remote add origin https://github.com/microsoft/vcpkg.git
  if ($LASTEXITCODE -ne 0) { throw "cannot configure vcpkg origin" }
}
& git -C $VcpkgRoot fetch --depth 1 origin $baseline
if ($LASTEXITCODE -ne 0) { throw "cannot fetch pinned vcpkg commit $baseline" }
& git -C $VcpkgRoot checkout --detach --force FETCH_HEAD
if ($LASTEXITCODE -ne 0) { throw "cannot checkout pinned vcpkg commit $baseline" }
$actual = ((& git -C $VcpkgRoot rev-parse HEAD) | Select-Object -First 1).Trim().ToLowerInvariant()
if ($LASTEXITCODE -ne 0 -or $actual -ne $baseline) {
  throw "vcpkg checkout mismatch: expected=$baseline actual=$actual"
}

$bootstrap = Join-Path $VcpkgRoot "bootstrap-vcpkg.bat"
if (-not (Test-Path -LiteralPath $bootstrap -PathType Leaf)) {
  throw "Pinned vcpkg checkout is missing bootstrap-vcpkg.bat"
}
& $bootstrap -disableMetrics
if ($LASTEXITCODE -ne 0) { throw "vcpkg bootstrap failed for $baseline" }
Write-Host "Pinned vcpkg ready: commit=$baseline root=$VcpkgRoot"
