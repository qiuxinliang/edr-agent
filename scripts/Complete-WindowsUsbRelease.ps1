#Requires -Version 5.1
# GitHub-hosted packaging only: this script has no private-key access.
param(
    [Parameter(Mandatory=$true)][ValidateSet('Prepare','Installer','Bundle','Verify')][string]$Stage,
    [string]$InputDirectory,
    [Parameter(Mandatory=$true)][string]$OutputDirectory,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9]{40}$')][string]$ExpectedCommit,
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Fa-f0-9]{40}$')][string]$Thumbprint,
    [Parameter(Mandatory=$true)][string]$ManifestSignerSubject,
    [string]$ResponseDirectory,
    [string]$Inno
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'WindowsUsbSigningExchange.ps1')
function Get-SafeChild([string]$Root, [string]$Relative) {
    if (-not $Relative -or $Relative -match '[:\x00-\x1f]' -or [IO.Path]::IsPathRooted($Relative)) { throw 'Invalid packaging path' }
    $path = [IO.Path]::GetFullPath((Join-Path $Root $Relative))
    if (-not $path.StartsWith($Root.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Packaging path escapes root' }
    return $path
}
function Get-Sha([string]$Path) { Get-ExchangeHash $Path }
function Write-Json([string]$Path, $Object) { Write-ExchangeJson $Path $Object }
if ($Stage -eq 'Prepare') {
$inputRoot = (Resolve-Path -LiteralPath $InputDirectory).Path.TrimEnd('\')
$inventory = Get-Content -LiteralPath (Join-Path $inputRoot 'packaging-input.json') -Raw -Encoding UTF8 | ConvertFrom-Json
if ($inventory.schema -ne 'edr.windows.hosted-packaging-input.v1' -or $inventory.source_commit -cne $ExpectedCommit -or
    $inventory.architecture -cnotin @('amd64','arm64') -or $inventory.version -cnotmatch '^\d+\.\d+\.\d+$') {
    throw 'USB signing input does not match the requested native build commit/version/architecture'
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
    }
    # Sources and archives stay on hosted runners, never in the signing request.
    Copy-Item -LiteralPath $source -Destination (Join-Path $out 'source') -Recurse
    Copy-Item -LiteralPath (Join-Path $assets ($prefix+'artifact-manifest.json')) -Destination (Join-Path $out 'original-manifest.json')
    New-SigningRequest (Join-Path $out 'native-request') native $ExpectedCommit $version $arch ($targets + (Join-Path $ui 'FDSecuritySetupUI.exe'))
    Write-Json (Join-Path $out 'state.json') ([ordered]@{stage='native'; source_commit=$ExpectedCommit; version=$version; architecture=$arch})
    exit 0
}
$out = (Resolve-Path -LiteralPath $OutputDirectory).Path
$state = Get-Content -LiteralPath (Join-Path $out 'state.json') -Raw | ConvertFrom-Json
$phase = switch($Stage) { Installer {'native'} Bundle {'installer'} Verify {'manifest'} }
if ($state.source_commit -cne $ExpectedCommit -or $state.stage -cne $phase) { throw 'Packaging state commit/phase mismatch' }
$version=$state.version; $arch=$state.architecture
$prefix="edr-agent-win_$version-windows-$arch-"
$runtime=Join-Path $out 'runtime'; $ui=Join-Path $out 'ui'; $dist=Join-Path $out 'dist'; $source=Join-Path $out 'source'
$request=Join-Path $out ($phase+'-request')
$validatedRequest=Read-SigningRequest $request $phase $ExpectedCommit $version $arch
Assert-SigningResponse $request $ResponseDirectory $Thumbprint
$manifest=Get-Content -LiteralPath (Join-Path $out 'original-manifest.json') -Raw | ConvertFrom-Json
$agent=Join-Path $runtime 'FDSensor.exe'
$collector=Join-Path $runtime 'collector'
$uiExe=Join-Path $ui 'FDSecuritySetupUI.exe'
$setup=Join-Path $dist ($prefix+'setup.exe')
$integrityPath=Join-Path $runtime 'native-package-integrity.json'
$uiManifestPath=Join-Path $ui 'setup-ui-manifest.json'
if ($Stage -eq 'Installer') {
    foreach ($name in @('FDSensor.exe','FDSecurityInstallerWorker.exe','uninstall.exe')) {
        Copy-Item -LiteralPath (Join-Path $ResponseDirectory $name) -Destination (Join-Path $runtime $name) -Force
    }
    # Copy exactly the collectors in the validated request, not a fixed list.
    # Assert-SigningResponse above still requires every requested signed EXE.
    foreach ($name in @($validatedRequest.files | Where-Object { $_.name -cin @('forensic_collector.exe','forensic_collector_builtin.exe') } | ForEach-Object name)) {
        Copy-Item -LiteralPath (Join-Path $ResponseDirectory $name) -Destination (Join-Path $collector $name) -Force
    }
    Copy-Item -LiteralPath (Join-Path $ResponseDirectory 'FDSecuritySetupUI.exe') -Destination $uiExe -Force
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

$uiManifestPath = Join-Path $ui 'setup-ui-manifest.json'
$uiManifest = Get-Content -LiteralPath $uiManifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
if ($uiManifest.version -ne $version -or $uiManifest.target_arch -ne $arch -or $uiManifest.setup_target_arch -ne $arch) { throw 'Native Setup UI metadata mismatch' }
$uiManifest.agent_binary_sha256 = Get-Sha $agent
$uiManifest.runtime_identity_sha256 = Get-Sha $integrityPath
$uiManifest.publisher_thumbprint = $Thumbprint
$uiManifest.setup_exe_sha256 = Get-Sha $setup
$uiManifest.ui_exe_sha256 = Get-Sha $uiExe
$uiManifest.setup_exe_signed = $true
$uiManifest.ui_exe_signed = $true
$uiManifest.capabilities.signature_status = 'signed'
$uiManifest.generated_at_utc = [DateTime]::UtcNow.ToString('o')
Write-Json $uiManifestPath $uiManifest

    # USB signs only the installer EXE, substitutes its resulting hash in this
    # small manifest, then signs that manifest. Hosted validation allows no other change.
    $installerRequestFile = Join-Path $out 'FDSecuritySetup.exe'
    Copy-Item -LiteralPath $setup -Destination $installerRequestFile
    New-SigningRequest (Join-Path $out 'installer-request') installer $ExpectedCommit $version $arch @($installerRequestFile,$uiManifestPath)
    $state.stage='installer'
} elseif ($Stage -eq 'Bundle') {
    Copy-Item -LiteralPath (Join-Path $ResponseDirectory 'FDSecuritySetup.exe') -Destination $setup -Force
    Copy-Item -LiteralPath $setup -Destination (Join-Path $runtime 'edr_agent_setup.exe') -Force
    Copy-Item -LiteralPath $setup -Destination (Join-Path $ui 'FDSecuritySetup.exe') -Force
    Copy-Item -LiteralPath (Join-Path $ResponseDirectory 'setup-ui-manifest.json') -Destination $uiManifestPath -Force
    Copy-Item -LiteralPath (Join-Path $ResponseDirectory 'setup-ui-manifest.json.p7s') -Destination (Join-Path $ui 'setup-ui-manifest.p7s') -Force
    Add-Type -AssemblyName System.IO.Compression.FileSystem
Copy-Item -LiteralPath $uiManifestPath -Destination (Join-Path $runtime 'full-installer-manifest.json') -Force
Copy-Item -LiteralPath (Join-Path $ui 'setup-ui-manifest.p7s') -Destination (Join-Path $runtime 'full-installer-manifest.p7s') -Force
Copy-Item -LiteralPath $agent -Destination (Join-Path $dist ($prefix + 'FDSensor.exe'))
[IO.Compression.ZipFile]::CreateFromDirectory($runtime, (Join-Path $dist ($prefix + 'exe.zip')))
[IO.Compression.ZipFile]::CreateFromDirectory($ui, (Join-Path $dist ($prefix + 'setup-ui.zip')))
# The platform binds this text to Go x509.Certificate.Subject.String(). Windows
# X500 display formatting differs (escaping, ordering and unknown OIDs). Keep
# the canonical public subject alongside the pinned thumbprint in release vars;
# do not relax the platform's exact certificate-identity check.
$manifest.signature = [pscustomobject]@{ format='cms-detached-sha256'; status='signed'; signer_thumbprint=$Thumbprint; signer_subject=$ManifestSignerSubject }
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

    $requestManifest=Join-Path $out 'artifact-manifest.json'
    Copy-Item -LiteralPath $manifestPath -Destination $requestManifest
    New-SigningRequest (Join-Path $out 'manifest-request') manifest $ExpectedCommit $version $arch @($requestManifest)
    $state.stage='manifest'
} else {
    $manifestPath=Join-Path $dist ($prefix+'artifact-manifest.json')
    if ((Get-Sha $manifestPath) -cne (Get-Sha (Join-Path $ResponseDirectory 'artifact-manifest.json'))) { throw 'Final manifest differs from packaged assets' }
    $sealed=Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    foreach ($entry in $sealed.artifacts) {
        $path=Get-SafeChild $dist $entry.name
        if ((Get-Sha $path) -cne $entry.sha256 -or (Get-Item -LiteralPath $path).Length -ne $entry.size) { throw 'Final asset hash/size mismatch' }
    }
    Copy-Item -LiteralPath (Join-Path $ResponseDirectory 'artifact-manifest.json.p7s') -Destination ($manifestPath+'.p7s')
    if (@(Get-ChildItem -LiteralPath $dist -File).Count -ne 6) { throw 'Incomplete final release set' }
    $state.stage='verified'
    Write-Host "Signed $arch bundle verified on hosted runner; native lifecycle gates still required"
}
Write-Json (Join-Path $out 'state.json') $state
