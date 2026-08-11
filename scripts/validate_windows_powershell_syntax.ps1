#Requires -Version 5.1
[CmdletBinding()]
param(
  [string]$RepositoryRoot = ""
)

$ErrorActionPreference = "Stop"
if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) {
  $RepositoryRoot = Split-Path -Parent $PSScriptRoot
}
$RepositoryRoot = [IO.Path]::GetFullPath($RepositoryRoot)

$relativePaths = @(
  "scripts\validate_windows_powershell_syntax.ps1",
  "scripts\edr_agent_install.ps1",
  "scripts\edr_agent_preflight.ps1",
  "scripts\edr_agent_inplace_update.ps1",
  "scripts\edr_agent_zip_deploy.ps1",
  "scripts\edr_agent_uninstall.ps1",
  "scripts\windows_service_install.ps1",
  "scripts\windows_isolate_host.ps1",
  "scripts\windows_release_lifecycle_smoke.ps1"
)

$failureCount = 0
foreach ($relativePath in $relativePaths) {
  $path = Join-Path $RepositoryRoot $relativePath
  if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
    throw "PowerShell syntax validation target is missing: $relativePath"
  }
  $tokens = $null
  $parseErrors = $null
  [void][Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$parseErrors)
  foreach ($parseError in @($parseErrors)) {
    $failureCount++
    Write-Host ("::error file={0},line={1},col={2}::{3}" -f `
      $relativePath,
      $parseError.Extent.StartLineNumber,
      $parseError.Extent.StartColumnNumber,
      $parseError.Message)
  }
}

if ($failureCount -gt 0) {
  throw "Windows PowerShell syntax validation failed with $failureCount parser error(s)"
}
Write-Host "Windows PowerShell syntax validation passed for $($relativePaths.Count) release scripts."
