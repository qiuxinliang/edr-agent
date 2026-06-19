#Requires -Version 5.1
<#
  Builds the WebView2 product installer shell.

  The UI shell is intentionally separate from the Inno installer:
  - edr_agent_setup_ui.exe renders the HTML-quality installer experience.
  - edr_agent_setup.exe remains the authoritative elevated installer.

  Example:
    .\install\windows-setup-ui\Build-SetupUi.ps1 `
      -SetupExe .\edr_agent_setup.exe `
      -AppVersion 2.1.150 `
      -OutputZip .\edr_agent_setup_ui.zip
#>
param(
    [string] $SetupExe = "",
    [string] $AppVersion = "0.0.0",
    [string] $Configuration = "Release",
    [string] $OutputZip = "",
    [string] $PreconfigJson = ""
)

$ErrorActionPreference = "Stop"
$scriptDir = $PSScriptRoot
$project = Join-Path $scriptDir "EDRAgent.SetupUi.csproj"
if (-not (Test-Path -LiteralPath $project)) {
    throw "Missing setup UI project: $project"
}

if (-not $SetupExe) {
    $candidate = Join-Path (Join-Path $scriptDir "..\windows-inno\Output") "EDRAgentSetup-bundled.exe"
    if (Test-Path -LiteralPath $candidate) {
        $SetupExe = (Resolve-Path -LiteralPath $candidate).Path
    }
}
if (-not (Test-Path -LiteralPath $SetupExe)) {
    throw "Missing setup exe. Pass -SetupExe or build install\windows-inno\Output\EDRAgentSetup-bundled.exe first."
}

function Get-FileSha256Hex([string] $Path) {
    if (-not (Test-Path -LiteralPath $Path)) {
        return ""
    }
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
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
        return $true
    }

    $certB64 = [string]$env:EDR_WINDOWS_SIGNING_CERT_BASE64
    if (-not $certB64) {
        return $false
    }
    $signtool = [string]$env:EDR_SIGNTOOL_PATH
    if (-not $signtool) {
        $cmd = Get-Command signtool.exe -ErrorAction SilentlyContinue
        if ($cmd) {
            $signtool = $cmd.Source
        }
    }
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
        return $true
    }
    finally {
        Remove-Item -LiteralPath $pfx -Force -ErrorAction SilentlyContinue
    }
}

$targetFramework = "net8.0-windows10.0.17763.0"
$runtime = "win-x64"
$publishDirCandidates = @(
    (Join-Path $scriptDir "bin\$Configuration\$targetFramework\$runtime\publish"),
    (Join-Path $scriptDir "bin\x64\$Configuration\$targetFramework\$runtime\publish")
)
foreach ($candidate in $publishDirCandidates) {
    Remove-Item -LiteralPath $candidate -Recurse -Force -ErrorAction SilentlyContinue
}

$readyToRun = if ($env:EDR_SETUP_UI_READYTORUN) { [string]$env:EDR_SETUP_UI_READYTORUN } else { "true" }
dotnet publish $project `
    -c $Configuration `
    -r win-x64 `
    --self-contained true `
    -p:Version=$AppVersion `
    -p:PublishSingleFile=false `
    "-p:PublishReadyToRun=$readyToRun" `
    -p:DebugType=None `
    -p:DebugSymbols=false
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

Copy-Item -LiteralPath $SetupExe -Destination (Join-Path $publishDir "edr_agent_setup.exe") -Force
$uiExe = Join-Path $publishDir "edr_agent_setup_ui.exe"
$bundledSetupExe = Join-Path $publishDir "edr_agent_setup.exe"
$uiSigned = Invoke-SignIfConfigured $uiExe
$setupSigned = Invoke-SignIfConfigured $bundledSetupExe

if ($PreconfigJson) {
    if (-not (Test-Path -LiteralPath $PreconfigJson)) {
        throw "Missing preconfig JSON: $PreconfigJson"
    }
    Copy-Item -LiteralPath $PreconfigJson -Destination (Join-Path $publishDir "setup-preconfig.json") -Force
}

$versionFile = Join-Path (Resolve-Path (Join-Path $scriptDir "..\..")).Path "VERSION"
if (Test-Path -LiteralPath $versionFile) {
    Copy-Item -LiteralPath $versionFile -Destination (Join-Path $publishDir "VERSION") -Force
} else {
    [System.IO.File]::WriteAllText((Join-Path $publishDir "VERSION"), $AppVersion)
}

$manifest = @{
    name = "EDR Agent Setup UI"
    version = $AppVersion
    setup_exe = "edr_agent_setup.exe"
    ui_exe = "edr_agent_setup_ui.exe"
    setup_exe_sha256 = Get-FileSha256Hex $bundledSetupExe
    ui_exe_sha256 = Get-FileSha256Hex $uiExe
    setup_exe_signed = [bool]$setupSigned
    ui_exe_signed = [bool]$uiSigned
    preconfig_embedded = [bool]$PreconfigJson
    generated_at_utc = [DateTime]::UtcNow.ToString("o")
    dotnet_runtime = "Self-contained .NET Desktop runtime"
    webview2_runtime = "Evergreen runtime required; Windows 11 normally includes it"
}
$manifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $publishDir "setup-ui-manifest.json") -Encoding UTF8

if (-not $OutputZip) {
    $OutputZip = Join-Path $scriptDir "Output\EDRAgentSetupUI-win-x64.zip"
}
$outParent = Split-Path -Parent $OutputZip
if ($outParent) {
    New-Item -ItemType Directory -Force -Path $outParent | Out-Null
}
Remove-Item -LiteralPath $OutputZip -Force -ErrorAction SilentlyContinue

$items = Get-ChildItem -LiteralPath $publishDir -Force | Where-Object { $_.Name -notmatch '\.(pdb|xml)$' }
Compress-Archive -Path $items.FullName -DestinationPath $OutputZip -Force
if (-not (Test-Path -LiteralPath $OutputZip)) {
    throw "Setup UI package was not created: $OutputZip"
}

Add-Type -AssemblyName System.IO.Compression.FileSystem
$zipObj = [System.IO.Compression.ZipFile]::OpenRead((Resolve-Path -LiteralPath $OutputZip))
try {
    $entries = $zipObj.Entries.FullName
    foreach ($required in @(
        'edr_agent_setup_ui.exe',
        'edr_agent_setup.exe',
        'Assets/installer.html',
        'setup-ui-manifest.json',
        'VERSION'
    )) {
        $pattern = [regex]::Escape($required).Replace('/', '[/\\]')
        if (-not ($entries -match "(^|[/\\])$pattern$")) {
            throw "Setup UI package missing required entry: $required"
        }
    }
}
finally {
    $zipObj.Dispose()
}

Write-Host "OK: $OutputZip"
