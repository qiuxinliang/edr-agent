#Requires -Version 5.1
# Headless-only unsigned candidate metadata. No UI runtime or signing fallback.
param(
  [Parameter(Mandatory = $true)][string] $SetupExe,
  [Parameter(Mandatory = $true)][string] $AppVersion,
  [Parameter(Mandatory = $true)][ValidateSet('amd64', 'arm64')][string] $TargetArch,
  [Parameter(Mandatory = $true)][string] $AgentBinarySha256,
  [Parameter(Mandatory = $true)][string] $RuntimeIdentitySha256,
  [Parameter(Mandatory = $true)][string] $PackageCapabilitiesPath,
  [Parameter(Mandatory = $true)][string] $OutputPath
)

$ErrorActionPreference = 'Stop'
if ($AppVersion -cnotmatch '\A[0-9]+\.[0-9]+\.[0-9]+\z') { throw 'Invalid Headless installer version' }
foreach ($hash in @($AgentBinarySha256, $RuntimeIdentitySha256)) {
  if ($hash -cnotmatch '\A[0-9A-Fa-f]{64}\z') { throw 'Headless component SHA256 must contain exactly 64 hex characters' }
}
$TargetArch = $TargetArch.ToLowerInvariant()
$setupPath = (Resolve-Path -LiteralPath $SetupExe -ErrorAction Stop).Path
$capabilitiesPath = (Resolve-Path -LiteralPath $PackageCapabilitiesPath -ErrorAction Stop).Path
$archPath = $setupPath + '.arch'
foreach ($path in @($setupPath, $capabilitiesPath, $archPath)) {
  $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
  if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'Headless installer inputs must be regular files'
  }
}
$setupBefore = Get-Item -LiteralPath $setupPath
if ($setupBefore.Length -le 0 -or $setupBefore.Length -gt 256MB) { throw 'Headless installer size is outside its protocol bound' }
if ((Get-Item -LiteralPath $capabilitiesPath).Length -gt 1MB -or (Get-Item -LiteralPath $archPath).Length -gt 32) {
  throw 'Headless installer capability or architecture metadata exceeds its bound'
}
if (([IO.File]::ReadAllText($archPath)).Trim().ToLowerInvariant() -cne $TargetArch) {
  throw 'Headless installer architecture sidecar does not match the payload'
}
$capabilities = [IO.File]::ReadAllText($capabilitiesPath) | ConvertFrom-Json -ErrorAction Stop
if ([string]$capabilities.schema -cne 'edr.windows.package-capabilities.v1' -or
    [string]$capabilities.target_arch -cne $TargetArch -or
    [string]$capabilities.signature_status -cne 'unsigned') {
  throw 'Headless installer requires matching unsigned package capabilities'
}
$setupHash = (Get-FileHash -LiteralPath $setupPath -Algorithm SHA256).Hash.ToLowerInvariant()
& (Join-Path $PSScriptRoot 'Assert-WindowsInstallerBootstrapArchitecture.ps1') -Path $setupPath -PayloadArchitecture $TargetArch
$signature = Get-AuthenticodeSignature -LiteralPath $setupPath -ErrorAction Stop
if ([string]$signature.Status -cne 'NotSigned') {
  throw 'Unsigned Headless installer must have an explicitly NotSigned Authenticode result'
}
$setupAfter = Get-Item -LiteralPath $setupPath
if ($setupAfter.Length -ne $setupBefore.Length -or $setupAfter.LastWriteTimeUtc -ne $setupBefore.LastWriteTimeUtc -or
    (Get-FileHash -LiteralPath $setupPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $setupHash) {
  throw 'Headless installer changed while its manifest was being constructed'
}
$manifest = [ordered]@{
  name = 'FDSecurity Headless Installer'
  version = $AppVersion
  target_arch = $TargetArch
  setup_target_arch = $TargetArch
  capabilities = $capabilities
  setup_exe = 'edr_agent_setup.exe'
  agent_binary_sha256 = $AgentBinarySha256.ToLowerInvariant()
  runtime_identity_sha256 = $RuntimeIdentitySha256.ToLowerInvariant()
  publisher_thumbprint = ''
  setup_exe_sha256 = $setupHash
  upgrade_protocol = 'edr.windows.full-installer-upgrade.v1'
  preserves_existing_identity = $true
  preserves_offline_queue = $true
  preserves_evidence_cache = $true
  setup_exe_signed = $false
  generated_at_utc = [DateTime]::UtcNow.ToString('o')
}
$bytes = ([Text.UTF8Encoding]::new($false)).GetBytes(($manifest | ConvertTo-Json -Depth 12) + "`n")
if ($bytes.Length -gt 1MB) { throw 'Headless installer manifest exceeds its protocol bound' }
$output = [IO.File]::Open([IO.Path]::GetFullPath($OutputPath), [IO.FileMode]::CreateNew,
  [IO.FileAccess]::Write, [IO.FileShare]::None)
try { $output.Write($bytes, 0, $bytes.Length); $output.Flush($true) } finally { $output.Dispose() }
Write-Host 'Verified unsigned Headless installer manifest; no UI executable or UI manifest was used'
