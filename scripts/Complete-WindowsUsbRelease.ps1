#Requires -Version 5.1
param(
    [Parameter(Mandatory=$true)][string]$InputDirectory,
    [Parameter(Mandatory=$true)][string]$OutputDirectory,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9]{40}$')][string]$ExpectedCommit,
    [Parameter(Mandatory=$true)][string]$Thumbprint,
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$ManifestSignerSubject,
    [Parameter(Mandatory=$true)][string]$SignTool,
    [Parameter(Mandatory=$true)][string]$Inno
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'WindowsStoreSigning.ps1')
$certificate = Get-EdRStoreSigningCertificate -Thumbprint $Thumbprint
$inputRoot = (Resolve-Path -LiteralPath $InputDirectory).Path.TrimEnd('\')
$inventory = Get-Content -LiteralPath (Join-Path $inputRoot 'signing-input.json') -Raw -Encoding UTF8 | ConvertFrom-Json
if ($inventory.schema -ne 'edr.windows.usb-signing-input.v1' -or $inventory.source_commit -cne $ExpectedCommit -or
    $inventory.architecture -cnotin @('amd64','arm64') -or $inventory.version -cnotmatch '^\d+\.\d+\.\d+$') {
    throw 'USB signing input does not match the requested native build commit/version/architecture'
}
function Get-SafeChild([string]$Root, [string]$Relative) {
    if (-not $Relative -or $Relative -match '[:\x00-\x1f]' -or [IO.Path]::IsPathRooted($Relative)) { throw 'Invalid signing input path' }
    $path = [IO.Path]::GetFullPath((Join-Path $Root $Relative))
    if (-not $path.StartsWith($Root.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Signing input path escapes its root' }
    return $path
}
function Get-Sha([string]$Path) { (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
function Write-Json([string]$Path, $Object) {
    [IO.File]::WriteAllText($Path, ($Object | ConvertTo-Json -Depth 12), (New-Object Text.UTF8Encoding($false)))
}
$seen = @{}
foreach ($file in $inventory.files) {
    $path = Get-SafeChild $inputRoot $file.path
    if ($seen.ContainsKey($path)) { throw 'Duplicate signing input file' }
    $seen[$path] = $true
    $item = Get-Item -LiteralPath $path -ErrorAction Stop
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        $item.Length -ne $file.size -or (Get-Sha $path) -cne $file.sha256) { throw "Signing input integrity mismatch: $($file.path)" }
}
if (@(Get-ChildItem -LiteralPath $inputRoot -Recurse -File).Count -ne $seen.Count + 1) { throw 'Unexpected untracked files in signing input' }
$arch = $inventory.architecture
$version = $inventory.version
$prefix = "edr-agent-win_$version-windows-$arch-"
$assets = Join-Path $inputRoot 'assets'
$manifest = Get-Content -LiteralPath (Join-Path $assets ($prefix + 'artifact-manifest.json')) -Raw -Encoding UTF8 | ConvertFrom-Json
if ($manifest.version -ne $version -or $manifest.signature.status -ne 'unsigned') { throw 'Expected unsigned native build manifest' }
foreach ($entry in $manifest.artifacts) {
    $path = Get-SafeChild $assets $entry.name
    if ((Get-Item -LiteralPath $path).Length -ne $entry.size -or (Get-Sha $path) -ne $entry.sha256) { throw "Native build asset hash mismatch: $($entry.name)" }
}
if (Test-Path -LiteralPath $OutputDirectory) { throw 'USB output directory must not already exist; preserve previous attempts for diagnosis' }
$out = (New-Item -ItemType Directory -Path $OutputDirectory).FullName
$runtime = Join-Path $out 'runtime'
$ui = Join-Path $out 'ui'
$dist = Join-Path $out 'dist'
New-Item -ItemType Directory -Path $dist | Out-Null
Add-Type -AssemblyName System.IO.Compression.FileSystem
function Expand-CheckedZip([string]$Zip, [string]$Destination) {
    $archive = [IO.Compression.ZipFile]::OpenRead($Zip)
    try {
        foreach ($entry in $archive.Entries) { $null = Get-SafeChild $Destination $entry.FullName }
    } finally { $archive.Dispose() }
    [IO.Compression.ZipFile]::ExtractToDirectory($Zip, $Destination)
}
Expand-CheckedZip (Join-Path $assets ($prefix + 'exe.zip')) $runtime
Expand-CheckedZip (Join-Path $assets ($prefix + 'setup-ui.zip')) $ui
$agent = Join-Path $runtime 'FDSensor.exe'
if ((Get-Sha $agent) -ne (Get-Sha (Join-Path $assets ($prefix + 'FDSensor.exe')))) { throw 'Raw Agent and native runtime ZIP disagree before signing' }
if ((Get-Content -LiteralPath (Join-Path $runtime 'VERSION') -Raw).Trim() -ne $version) { throw 'Native runtime version mismatch' }
$source = Join-Path $inputRoot 'source'
$collector = Join-Path $runtime 'collector'
New-Item -ItemType Directory -Path $collector -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $inputRoot 'forensic_collector_builtin.exe') -Destination (Join-Path $collector 'forensic_collector_builtin.exe') -Force
$targets = @($agent, (Join-Path $runtime 'FDSecurityInstallerWorker.exe'), (Join-Path $runtime 'uninstall.exe'))
$targets += @(Get-ChildItem -LiteralPath $collector -Filter *.exe -File | Where-Object Name -ne 'velociraptor.exe' | ForEach-Object FullName)
foreach ($target in $targets) {
    & (Join-Path $source 'scripts\Assert-WindowsPeArchitecture.ps1') -Path $target -Architecture $arch
    Invoke-EdRStoreAuthenticodeSign -Path $target -Thumbprint $Thumbprint -SignTool $SignTool
}
$integrityPath = Join-Path $runtime 'native-package-integrity.json'
$integrity = Get-Content -LiteralPath $integrityPath -Raw -Encoding UTF8 | ConvertFrom-Json
if ($integrity.schema -ne 'edr.windows.native-package-integrity.v1') { throw 'Unknown native runtime integrity schema' }
$builtinIdentityName = 'collector/forensic_collector_builtin.exe'
$builtinIdentityEntries = @($integrity.files | Where-Object { $_.name -ceq $builtinIdentityName })
if ($builtinIdentityEntries.Count -gt 1) { throw 'Native runtime integrity contains duplicate forensic builtin entries' }
if ($builtinIdentityEntries.Count -eq 0) {
    $integrity.files = @($integrity.files) + [pscustomobject]@{ name=$builtinIdentityName; sha256=(Get-Sha (Join-Path $collector 'forensic_collector_builtin.exe')) }
}
foreach ($entry in $integrity.files) { $entry.sha256 = Get-Sha (Get-SafeChild $runtime $entry.name) }
Write-Json $integrityPath $integrity
# The old bundled installer is not a native runtime component. It must be
# rebuilt from signed inputs, never patched inside the previous EXE.
Remove-Item -LiteralPath (Join-Path $runtime 'edr_agent_setup.exe') -Force
& (Join-Path $source 'install\windows-inno\Build-BundledInstaller.ps1') -BinDir $runtime -AppVersion $version -TargetArch $arch -SignatureStatus signed -SkipForensicCollectorBuild -Inno $Inno
if ($LASTEXITCODE -ne 0) { throw 'Signed Inno payload rebuild failed' }
$setup = Join-Path $dist ($prefix + 'setup.exe')
Copy-Item -LiteralPath (Join-Path $source 'install\windows-inno\Output\FDSecuritySetup-bundled.exe') -Destination $setup
Invoke-EdRStoreAuthenticodeSign -Path $setup -Thumbprint $Thumbprint -SignTool $SignTool
Copy-Item -LiteralPath $setup -Destination (Join-Path $runtime 'edr_agent_setup.exe')
Copy-Item -LiteralPath $setup -Destination (Join-Path $ui 'FDSecuritySetup.exe') -Force
$uiExe = Join-Path $ui 'FDSecuritySetupUI.exe'
Invoke-EdRStoreAuthenticodeSign -Path $uiExe -Thumbprint $Thumbprint -SignTool $SignTool
$uiManifestPath = Join-Path $ui 'setup-ui-manifest.json'
$uiManifest = Get-Content -LiteralPath $uiManifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
if ($uiManifest.version -ne $version -or $uiManifest.target_arch -ne $arch -or $uiManifest.setup_target_arch -ne $arch) { throw 'Native Setup UI metadata mismatch' }
$uiManifest.agent_binary_sha256 = Get-Sha $agent
$uiManifest.runtime_identity_sha256 = Get-Sha $integrityPath
$uiManifest.publisher_thumbprint = $certificate.Thumbprint
$uiManifest.setup_exe_sha256 = Get-Sha $setup
$uiManifest.ui_exe_sha256 = Get-Sha $uiExe
$uiManifest.setup_exe_signed = $true
$uiManifest.ui_exe_signed = $true
$uiManifest.capabilities.signature_status = 'signed'
$uiManifest.generated_at_utc = [DateTime]::UtcNow.ToString('o')
Write-Json $uiManifestPath $uiManifest
Write-EdRStoreDetachedCms -ContentPath $uiManifestPath -SignaturePath (Join-Path $ui 'setup-ui-manifest.p7s') -Thumbprint $Thumbprint -SignTool $SignTool
Copy-Item -LiteralPath $uiManifestPath -Destination (Join-Path $runtime 'full-installer-manifest.json') -Force
Copy-Item -LiteralPath (Join-Path $ui 'setup-ui-manifest.p7s') -Destination (Join-Path $runtime 'full-installer-manifest.p7s') -Force
Copy-Item -LiteralPath $agent -Destination (Join-Path $dist ($prefix + 'FDSensor.exe'))
[IO.Compression.ZipFile]::CreateFromDirectory($runtime, (Join-Path $dist ($prefix + 'exe.zip')))
[IO.Compression.ZipFile]::CreateFromDirectory($ui, (Join-Path $dist ($prefix + 'setup-ui.zip')))
# The platform binds this text to Go x509.Certificate.Subject.String(). Windows
# X500 display formatting differs (escaping, ordering and unknown OIDs). Keep
# the canonical public subject alongside the pinned thumbprint in release vars;
# do not relax the platform's exact certificate-identity check.
$manifest.signature = [pscustomobject]@{ format='cms-detached-sha256'; status='signed'; signer_thumbprint=$certificate.Thumbprint; signer_subject=$ManifestSignerSubject }
foreach ($entry in $manifest.artifacts) {
    $path = Get-SafeChild $dist $entry.name
    $entry.sha256 = Get-Sha $path
    $entry.size = (Get-Item -LiteralPath $path).Length
    if ($entry.name -eq ($prefix + 'FDSensor.exe')) {
        # Signing changes worker/uninstaller identities too; binary_hot is not
        # valid for this transition even if the unsigned build classified it so.
        $entry.update.upgrade_class = 'installer_required'
        $entry.update.runtime_identity_sha256 = Get-Sha $integrityPath
    }
}
$manifestPath = Join-Path $dist ($prefix + 'artifact-manifest.json')
Write-Json $manifestPath $manifest
Write-EdRStoreDetachedCms -ContentPath $manifestPath -SignaturePath ($manifestPath + '.p7s') -Thumbprint $Thumbprint -SignTool $SignTool
Write-Json (Join-Path $out 'signing-receipt.json') ([ordered]@{ status='signed'; version=$version; architecture=$arch; source_commit=$ExpectedCommit; publisher=$certificate.Thumbprint; agent_sha256=(Get-Sha $agent); runtime_identity_sha256=(Get-Sha $integrityPath); native_lifecycle='pending' })
Write-Host "Signed $arch bundle ready for native lifecycle validation: $dist"
