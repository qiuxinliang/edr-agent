#Requires -Version 5.1
<#
  Builds the WebView2 product installer shell.

  The UI shell is intentionally separate from the Inno installer:
  - FDSecuritySetupUI.exe renders the HTML-quality installer experience.
  - FDSecuritySetup.exe remains the authoritative elevated installer.

  Example:
    .\install\windows-setup-ui\Build-SetupUi.ps1 `
      -SetupExe .\FDSecuritySetup.exe `
      -AppVersion 2.1.150 `
      -BootstrapTrustPublicKeyPem .\bootstrap_trust_public_key.pem `
      -OutputZip .\FDSecuritySetupUI.zip
#>
param(
    [string] $SetupExe = "",
    [string] $AppVersion = "0.0.0",
    [string] $Configuration = "Release",
    [string] $OutputZip = "",
    [string] $PreconfigJson = "",
    [string] $BootstrapTrustPublicKeyPem = "",
    [ValidateSet("", "self-contained", "compact", "framework-dependent")]
    [string] $RuntimeMode = "",
    [ValidateSet("", "win-x64", "win-arm64")]
    [string] $RuntimeIdentifier = ""
)

$ErrorActionPreference = "Stop"
$scriptDir = $PSScriptRoot
$project = Join-Path $scriptDir "EDRAgent.SetupUi.csproj"
if (-not (Test-Path -LiteralPath $project)) {
    throw "Missing setup UI project: $project"
}

if (-not $SetupExe) {
    $candidate = Join-Path (Join-Path $scriptDir "..\windows-inno\Output") "FDSecuritySetup-bundled.exe"
    if (-not (Test-Path -LiteralPath $candidate)) {
        $candidate = Join-Path (Join-Path $scriptDir "..\windows-inno\Output") "EDRAgentSetup-bundled.exe"
    }
    if (Test-Path -LiteralPath $candidate) {
        $SetupExe = (Resolve-Path -LiteralPath $candidate).Path
    }
}
if (-not (Test-Path -LiteralPath $SetupExe)) {
    throw "Missing setup exe. Pass -SetupExe or build install\windows-inno\Output\FDSecuritySetup-bundled.exe first."
}

function Get-FileSha256Hex([string] $Path) {
    if (-not (Test-Path -LiteralPath $Path)) {
        return ""
    }
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Resolve-SignToolPath {
    $signtool = [string]$env:EDR_SIGNTOOL_PATH
    if (-not $signtool) {
        $cmd = Get-Command signtool.exe -ErrorAction SilentlyContinue
        if ($cmd) {
            $signtool = $cmd.Source
        }
    }
    return $signtool
}

function Assert-AuthenticodeSignature([string] $Path) {
    $signtool = Resolve-SignToolPath
    if ($signtool) {
        & $signtool verify /pa /all $Path
        if ($LASTEXITCODE -ne 0) {
            throw "signtool verify failed for $Path"
        }
        return
    }
    $sig = Get-AuthenticodeSignature -LiteralPath $Path
    if ($sig.Status -ne 'Valid') {
        throw "Authenticode signature verification failed for $Path: $($sig.Status) $($sig.StatusMessage)"
    }
}

function Invoke-SignIfConfigured([string] $Path) {
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Cannot sign missing file: $Path"
    }
    $custom = [string]$env:EDR_WINDOWS_SIGN_COMMAND
    if ($custom) {
        $cmd = $custom.Replace('{path}', $Path)
        Write-Host "Signing via EDR_WINDOWS_SIGN_COMMAND: $Path"
        cmd.exe /c $cmd
        if ($LASTEXITCODE -ne 0) {
            throw "custom signing command failed for $Path"
        }
        Assert-AuthenticodeSignature $Path
        return $true
    }

    $certB64 = [string]$env:EDR_WINDOWS_SIGNING_CERT_BASE64
    if (-not $certB64) {
        return $false
    }
    $signtool = Resolve-SignToolPath
    if (-not $signtool) {
        throw "EDR_WINDOWS_SIGNING_CERT_BASE64 is set but signtool.exe was not found"
    }
    $pfx = Join-Path ([System.IO.Path]::GetTempPath()) ("edr-sign-" + [Guid]::NewGuid().ToString("N") + ".pfx")
    try {
        [System.IO.File]::WriteAllBytes($pfx, [Convert]::FromBase64String($certB64))
        $timestamp = if ($env:EDR_WINDOWS_SIGN_TIMESTAMP_URL) { [string]$env:EDR_WINDOWS_SIGN_TIMESTAMP_URL } else { "http://timestamp.digicert.com" }
        $password = [string]$env:EDR_WINDOWS_SIGNING_CERT_PASSWORD
        $args = @("sign", "/fd", "SHA256", "/td", "SHA256", "/tr", $timestamp, "/f", $pfx)
        if ($password) {
            $args += @("/p", $password)
        }
        $args += $Path
        Write-Host "Signing with signtool: $Path"
        & $signtool @args
        if ($LASTEXITCODE -ne 0) {
            throw "signtool failed for $Path"
        }
        Assert-AuthenticodeSignature $Path
        return $true
    }
    finally {
        Remove-Item -LiteralPath $pfx -Force -ErrorAction SilentlyContinue
    }
}

function Format-SetupUiBytes([Int64] $Bytes) {
    if ($Bytes -ge 1GB) {
        return ("{0:N2} GB" -f ($Bytes / 1GB))
    }
    if ($Bytes -ge 1MB) {
        return ("{0:N2} MB" -f ($Bytes / 1MB))
    }
    if ($Bytes -ge 1KB) {
        return ("{0:N2} KB" -f ($Bytes / 1KB))
    }
    return ("{0} B" -f $Bytes)
}

function Write-SetupUiSizeReport([string] $PublishDir, [string] $OutputZipPath) {
    Write-Host ""
    Write-Host "Setup UI package size report"
    if (Test-Path -LiteralPath $OutputZipPath) {
        $zipItem = Get-Item -LiteralPath $OutputZipPath
        Write-Host ("  zip: {0} ({1})" -f $zipItem.FullName, (Format-SetupUiBytes $zipItem.Length))
    }
    if (-not (Test-Path -LiteralPath $PublishDir)) {
        return
    }
    $files = Get-ChildItem -LiteralPath $PublishDir -File -Recurse -Force
    $total = ($files | Measure-Object -Property Length -Sum).Sum
    Write-Host ("  publish dir total: {0}" -f (Format-SetupUiBytes ([Int64]$total)))

    $setupExe = $files | Where-Object { $_.Name -eq "FDSecuritySetup.exe" } | Select-Object -First 1
    if ($setupExe) {
        Write-Host ("  bundled setup: {0}" -f (Format-SetupUiBytes $setupExe.Length))
    }

    $runtimePrefixes = @(
        "coreclr", "clrjit", "hostfxr", "hostpolicy", "System.", "Microsoft.",
        "Presentation", "WindowsBase", "DirectWriteForwarder", "wpfgfx"
    )
    $runtimeBytes = 0L
    foreach ($file in $files) {
        foreach ($prefix in $runtimePrefixes) {
            if ($file.Name.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
                $runtimeBytes += [Int64]$file.Length
                break
            }
        }
    }
    if ($runtimeBytes -gt 0) {
        Write-Host ("  estimated .NET/WPF runtime files: {0}" -f (Format-SetupUiBytes $runtimeBytes))
    }

    Write-Host "  top files:"
    $files |
        Sort-Object Length -Descending |
        Select-Object -First 12 |
        ForEach-Object {
            $rel = $_.FullName.Substring($PublishDir.Length).TrimStart('\', '/')
            $sizeText = Format-SetupUiBytes ([Int64]$_.Length)
            Write-Host ("    {0,10}  {1}" -f $sizeText, $rel)
        }
    Write-Host ""
}

$targetFramework = "net8.0-windows10.0.17763.0"
$runtime = if ($RuntimeIdentifier) { $RuntimeIdentifier } elseif ($env:EDR_SETUP_UI_RUNTIME_IDENTIFIER) { [string]$env:EDR_SETUP_UI_RUNTIME_IDENTIFIER } else { "win-x64" }
if ($runtime -notin @("win-x64", "win-arm64")) {
    throw "Invalid RuntimeIdentifier: $runtime"
}
$platformDir = if ($runtime -eq "win-arm64") { "arm64" } else { "x64" }
$publishDirCandidates = @(
    (Join-Path $scriptDir "bin\$Configuration\$targetFramework\$runtime\publish"),
    (Join-Path $scriptDir "bin\$platformDir\$Configuration\$targetFramework\$runtime\publish")
)
foreach ($candidate in $publishDirCandidates) {
    Remove-Item -LiteralPath $candidate -Recurse -Force -ErrorAction SilentlyContinue
}

$resolvedRuntimeMode = if ($RuntimeMode) { $RuntimeMode } elseif ($env:EDR_SETUP_UI_RUNTIME_MODE) { [string]$env:EDR_SETUP_UI_RUNTIME_MODE } else { "compact" }
if ($resolvedRuntimeMode -notin @("self-contained", "compact", "framework-dependent")) {
    throw "Invalid RuntimeMode: $resolvedRuntimeMode"
}
$selfContained = if ($resolvedRuntimeMode -eq "framework-dependent") { "false" } else { "true" }
$defaultReadyToRun = if ($resolvedRuntimeMode -eq "self-contained") { "true" } else { "false" }
$readyToRun = if ($env:EDR_SETUP_UI_READYTORUN) { [string]$env:EDR_SETUP_UI_READYTORUN } else { $defaultReadyToRun }
Write-Host "Setup UI runtime mode: $resolvedRuntimeMode (self-contained=$selfContained, readyToRun=$readyToRun)"

$publishArgs = @(
    $project,
    "-c", $Configuration,
    "-r", $runtime,
    "--self-contained", $selfContained,
    "-p:Version=$AppVersion",
    "-p:PublishSingleFile=false",
    "-p:PublishReadyToRun=$readyToRun",
    "-p:DebugType=None",
    "-p:DebugSymbols=false"
)
dotnet publish @publishArgs
if ($LASTEXITCODE -ne 0) {
    throw "dotnet publish failed with exit $LASTEXITCODE"
}

$publishDir = $null
foreach ($candidate in $publishDirCandidates) {
    if (Test-Path -LiteralPath $candidate) {
        $publishDir = (Resolve-Path -LiteralPath $candidate).Path
        break
    }
}

if (-not $publishDir) {
    throw "Publish directory not found. Checked: $($publishDirCandidates -join '; ')"
}

$requiredPublishFiles = @(
    "FDSecuritySetupUI.exe",
    "Microsoft.Web.WebView2.Core.dll",
    "Microsoft.Web.WebView2.Wpf.dll"
)
if ($selfContained -eq "true") {
    $requiredPublishFiles += "System.Drawing.dll"
}
foreach ($requiredPublishFile in $requiredPublishFiles) {
    $requiredPath = Join-Path $publishDir $requiredPublishFile
    if (-not (Test-Path -LiteralPath $requiredPath)) {
        throw "Publish missing required runtime file: $requiredPublishFile"
    }
}

Copy-Item -LiteralPath $SetupExe -Destination (Join-Path $publishDir "FDSecuritySetup.exe") -Force
$uiExe = Join-Path $publishDir "FDSecuritySetupUI.exe"
$bundledSetupExe = Join-Path $publishDir "FDSecuritySetup.exe"
$uiSigned = Invoke-SignIfConfigured $uiExe
$setupSigned = Invoke-SignIfConfigured $bundledSetupExe

if ($PreconfigJson) {
    if (-not (Test-Path -LiteralPath $PreconfigJson)) {
        throw "Missing preconfig JSON: $PreconfigJson"
    }
    Copy-Item -LiteralPath $PreconfigJson -Destination (Join-Path $publishDir "setup-preconfig.json") -Force
}

$bootstrapTrustPublicKey = ""
if ($BootstrapTrustPublicKeyPem) {
    if (-not (Test-Path -LiteralPath $BootstrapTrustPublicKeyPem)) {
        throw "Missing bootstrap trust public key PEM: $BootstrapTrustPublicKeyPem"
    }
    $bootstrapTrustPublicKey = Get-Content -LiteralPath $BootstrapTrustPublicKeyPem -Raw -Encoding UTF8
    if ($bootstrapTrustPublicKey -notmatch "-----BEGIN (RSA )?PUBLIC KEY-----") {
        throw "Bootstrap trust public key must be a PEM public key, not a certificate or private key"
    }
    Copy-Item -LiteralPath $BootstrapTrustPublicKeyPem -Destination (Join-Path $publishDir "bootstrap_trust_public_key.pem") -Force
}

$versionFile = Join-Path (Resolve-Path (Join-Path $scriptDir "..\..")).Path "VERSION"
if (Test-Path -LiteralPath $versionFile) {
    Copy-Item -LiteralPath $versionFile -Destination (Join-Path $publishDir "VERSION") -Force
} else {
    [System.IO.File]::WriteAllText((Join-Path $publishDir "VERSION"), $AppVersion)
}

$manifest = @{
    name = "FDSecurity Setup UI"
    version = $AppVersion
    runtime_mode = $resolvedRuntimeMode
    runtime_identifier = $runtime
    setup_exe = "FDSecuritySetup.exe"
    ui_exe = "FDSecuritySetupUI.exe"
    setup_exe_sha256 = Get-FileSha256Hex $bundledSetupExe
    ui_exe_sha256 = Get-FileSha256Hex $uiExe
    setup_exe_signed = [bool]$setupSigned
    ui_exe_signed = [bool]$uiSigned
    preconfig_embedded = [bool]$PreconfigJson
    bootstrap_trust_public_key_file = if ($bootstrapTrustPublicKey) { "bootstrap_trust_public_key.pem" } else { "" }
    bootstrap_trust_public_key_pem = $bootstrapTrustPublicKey
    generated_at_utc = [DateTime]::UtcNow.ToString("o")
    dotnet_runtime = if ($selfContained -eq "true") { "Self-contained .NET Desktop runtime" } else { "Requires .NET Desktop Runtime 8 on the endpoint" }
    webview2_runtime = "Evergreen runtime required; Windows 11 normally includes it"
}
$manifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $publishDir "setup-ui-manifest.json") -Encoding UTF8

if (-not $OutputZip) {
    $OutputZip = Join-Path $scriptDir ("Output\FDSecuritySetupUI-{0}-{1}.zip" -f $runtime, $resolvedRuntimeMode)
}
$outParent = Split-Path -Parent $OutputZip
if ($outParent) {
    New-Item -ItemType Directory -Force -Path $outParent | Out-Null
}
Remove-Item -LiteralPath $OutputZip -Force -ErrorAction SilentlyContinue

$items = Get-ChildItem -LiteralPath $publishDir -Force | Where-Object { $_.Name -notmatch '\.(pdb|xml)$' }
Compress-Archive -Path $items.FullName -DestinationPath $OutputZip -CompressionLevel Optimal -Force
if (-not (Test-Path -LiteralPath $OutputZip)) {
    throw "Setup UI package was not created: $OutputZip"
}

Add-Type -AssemblyName System.IO.Compression.FileSystem
$zipObj = [System.IO.Compression.ZipFile]::OpenRead((Resolve-Path -LiteralPath $OutputZip))
try {
    $entries = $zipObj.Entries.FullName
    foreach ($required in @(
        'FDSecuritySetupUI.exe',
        'FDSecuritySetup.exe',
        'Assets/installer.html',
        'setup-ui-manifest.json',
        'VERSION'
    )) {
        $pattern = [regex]::Escape($required).Replace('/', '[/\\]')
        if (-not ($entries -match "(^|[/\\])$pattern$")) {
            throw "Setup UI package missing required entry: $required"
        }
    }
    if ($bootstrapTrustPublicKey) {
        if (-not ($entries -match '(^|[/\\])bootstrap_trust_public_key\.pem$')) {
            throw "Setup UI package missing required entry: bootstrap_trust_public_key.pem"
        }
    }
}
finally {
    $zipObj.Dispose()
}

Write-SetupUiSizeReport $publishDir $OutputZip
Write-Host "OK: $OutputZip"
