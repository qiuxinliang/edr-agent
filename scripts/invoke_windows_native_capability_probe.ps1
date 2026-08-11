#Requires -Version 5.1
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$ExecutablePath,
  [Parameter(Mandatory = $true)][string]$ProbePath,
  [Parameter(Mandatory = $true)][string]$ComponentName
)

$ErrorActionPreference = "Stop"
$resolvedExecutable = (Resolve-Path -LiteralPath $ExecutablePath).Path
$resolvedProbe = [IO.Path]::GetFullPath($ProbePath)
$probeDirectory = Split-Path -Parent $resolvedProbe
if ([string]::IsNullOrWhiteSpace($probeDirectory)) {
  throw "$ComponentName capability probe has no output directory: $resolvedProbe"
}

New-Item -ItemType Directory -Path $probeDirectory -Force | Out-Null
Remove-Item -LiteralPath $resolvedProbe -Force -ErrorAction SilentlyContinue
if (Test-Path -LiteralPath $resolvedProbe) {
  throw "$ComponentName capability probe could not remove stale result: $resolvedProbe"
}

# fd_headless_uninstaller is a Windows GUI subsystem executable. PowerShell's
# call operator can return before a GUI process exits, leaving LASTEXITCODE
# stale and racing the probe file. Start-Process -Wait handles both GUI and
# console subsystem executables consistently.
$quotedProbe = '"' + $resolvedProbe + '"'
$process = Start-Process `
  -FilePath $resolvedExecutable `
  -ArgumentList @("--capability-probe", $quotedProbe) `
  -Wait `
  -PassThru
if ($process.ExitCode -ne 0) {
  throw "$ComponentName capability probe failed with exit code $($process.ExitCode)"
}
if (-not (Test-Path -LiteralPath $resolvedProbe -PathType Leaf)) {
  throw "$ComponentName capability probe exited successfully without creating $resolvedProbe"
}

$raw = Get-Content -LiteralPath $resolvedProbe -Raw
if ([string]::IsNullOrWhiteSpace($raw)) {
  throw "$ComponentName capability probe created an empty result: $resolvedProbe"
}
try {
  return ($raw | ConvertFrom-Json)
} catch {
  throw "$ComponentName capability probe returned invalid JSON: $($_.Exception.Message)"
}
