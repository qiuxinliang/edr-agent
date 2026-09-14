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
  "scripts\Validate-DependencyLocks.ps1",
  "scripts\Restore-SetupUiLocked.ps1",
  "scripts\edr_agent_install.ps1",
  "scripts\edr_agent_preflight.ps1",
  "scripts\edr_agent_inplace_update.ps1",
  "scripts\edr_agent_postinstall_verify.ps1",
  "scripts\edr_agent_zip_deploy.ps1",
  "scripts\windows_service_install.ps1",
  "scripts\windows_isolate_host.ps1",
  "scripts\invoke_windows_native_capability_probe.ps1",
  "scripts\bootstrap_pinned_vcpkg.ps1",
  "scripts\Invoke-VcpkgInstallWithRetry.ps1",
  "scripts\Initialize-VS2022Environment.ps1",
  "scripts\Assert-WindowsPeArchitecture.ps1",
  "scripts\Assert-WindowsInstallerBootstrapArchitecture.ps1",
  "scripts\stage_vcpkg_runtime_dlls_build_release.ps1",
  "scripts\stage_msvc_runtime_dlls_build_release.ps1",
  "scripts\write_windows_package_capabilities.ps1",
  "scripts\test_windows_package_capabilities_contract.ps1",
  "scripts\windows_setup_exe_lifecycle_smoke.ps1",
  "scripts\windows_release_lifecycle_smoke.ps1",
  "tests\test_windows_install_compatibility.ps1",
  "tests\test_windows_install_cng_behavior.ps1",
  "tests\test_vcpkg_install_retry.ps1",
  "tests\test_vs2022_host_architecture.ps1",
  "install\windows-inno\Build-BundledInstaller.ps1",
  "install\windows-inno\edr_install_wizard_enroll.ps1",
  "install\windows-inno\edr_windows_autorun.ps1",
  "install\windows-setup-ui\Build-SetupUi.ps1"
)

$failureCount = 0
foreach ($relativePath in $relativePaths) {
  $path = Join-Path $RepositoryRoot $relativePath
  if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
    throw "PowerShell syntax validation target is missing: $relativePath"
  }
  [byte[]]$sourceBytes = [IO.File]::ReadAllBytes($path)
  $hasUtf8Bom = (
    $sourceBytes.Length -ge 3 -and
    $sourceBytes[0] -eq 0xEF -and
    $sourceBytes[1] -eq 0xBB -and
    $sourceBytes[2] -eq 0xBF
  )
  $hasNonAsciiBytes = $false
  foreach ($sourceByte in $sourceBytes) {
    if ($sourceByte -gt 0x7F) {
      $hasNonAsciiBytes = $true
      break
    }
  }
  if ($hasNonAsciiBytes -and -not $hasUtf8Bom) {
    $failureCount++
    Write-Host ("::error file={0},line=1,col=1::Non-ASCII Windows PowerShell 5.1 script must be UTF-8 with BOM" -f $relativePath)
    continue
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
