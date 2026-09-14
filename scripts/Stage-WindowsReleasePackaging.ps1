#Requires -Version 5.1
# Hosted-only staging. This directory must never be downloaded by a USB runner;
# Complete-WindowsUsbRelease -Stage Prepare emits the separate file-only request.
param(
    [Parameter(Mandatory=$true)][ValidateSet('amd64','arm64')][string]$Architecture,
    [Parameter(Mandatory=$true)][ValidatePattern('^\d+\.\d+\.\d+$')][string]$Version,
    [Parameter(Mandatory=$true)][string]$OutputDirectory
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$out = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $out) { throw 'Hosted packaging input destination must not already exist' }
$source = Join-Path $out 'source'
New-Item -ItemType Directory -Path $source -ErrorAction Stop | Out-Null
# Reuse the exact generated rules and installer sources from the native build.
# Do not send .git, build caches, PFX files or unrelated working directories.
foreach ($name in @('scripts','install','config','rules','third_party\windivert','src\shellcode_detector\rules','src\webshell_detector\rules','VERSION','agent.toml.example')) {
    $path = Join-Path $root $name
    if (-not (Test-Path -LiteralPath $path)) { throw "Hosted packaging source is missing: $name" }
    $destination = Join-Path $source $name
    $parent = Split-Path -Parent $destination
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
    # Copy only tracked source files plus the generated encrypted rule bundle.
    if (Test-Path -LiteralPath $path -PathType Leaf) {
        Copy-Item -LiteralPath $path -Destination $destination
    } else {
        $tracked = @(git -C $root ls-files -- $name)
        if ($LASTEXITCODE -ne 0) { throw 'Cannot enumerate release source files' }
        foreach ($relative in $tracked) {
            $target = Join-Path $source $relative
            New-Item -ItemType Directory -Path (Split-Path -Parent $target) -Force | Out-Null
            Copy-Item -LiteralPath (Join-Path $root $relative) -Destination $target
        }
    }
}
foreach ($name in @('p0_rule_bundle_ir_v1.json.enc','sensor_interest_manifest.json')) {
    Copy-Item -LiteralPath (Join-Path $root "config\$name") -Destination (Join-Path $source "config\$name") -Force
}
$assets = Join-Path $out 'assets'
New-Item -ItemType Directory -Path $assets | Out-Null
$prefix = "edr-agent-win_$Version-windows-$Architecture-"
foreach ($suffix in @('artifact-manifest.json','FDSensor.exe','exe.zip','setup.exe','setup-ui.zip')) {
    Copy-Item -LiteralPath (Join-Path $root "dist\$prefix$suffix") -Destination $assets
}
# Headless legacy ZIPs do not include the builtin collector independently;
# carry the native build product explicitly so no binary is recompiled locally.
$builtin = @(Get-ChildItem -LiteralPath (Join-Path $root 'build') -Filter forensic_collector_builtin.exe -Recurse -File | Sort-Object FullName | Select-Object -First 1)
if ($builtin.Count -ne 1) { throw 'Native builtin collector is missing from the build' }
Copy-Item -LiteralPath $builtin[0].FullName -Destination (Join-Path $out 'forensic_collector_builtin.exe')
$sha = (& git -C $root rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $sha -cnotmatch '^[a-f0-9]{40}$') { throw 'Cannot bind hosted packaging input to its source commit' }
$inventory = @(
    Get-ChildItem -LiteralPath $out -Recurse -File | Sort-Object FullName | ForEach-Object {
        [ordered]@{ path=$_.FullName.Substring($out.Length + 1).Replace('\','/'); sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant(); size=$_.Length }
    }
)
[ordered]@{ schema='edr.windows.hosted-packaging-input.v1'; version=$Version; architecture=$Architecture; source_commit=$sha; files=$inventory } |
    ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $out 'packaging-input.json') -Encoding UTF8
Write-Host "Hosted packaging input staged: $Architecture $Version source=$sha files=$($inventory.Count)"
