#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $OutputPath,

    [Parameter(Mandatory = $true)]
    [ValidateSet("amd64", "arm64")]
    [string] $TargetArch,

    [ValidateSet("signed", "unsigned")]
    [string] $SignatureStatus = "unsigned"
)

$ErrorActionPreference = "Stop"

# v1 signature_status describes the verified executable launch closure inside
# the package: signed means every required executable has valid Authenticode;
# unsigned means none does. Producers must reject mixed closures before calling
# this serializer. Detached CMS manifest signing is an independent trust layer.
#
# v1 deliberately permits only native Windows packages. AMD64-on-ARM64 can be
# introduced in a new schema after the complete service, PMFE, update and
# uninstall chain passes a native ARM64 end-to-end gate.
$networkPacketCapture = ($TargetArch -eq "amd64")
$capabilities = [ordered]@{
    schema = "edr.windows.package-capabilities.v1"
    target_arch = $TargetArch
    arm64_emulation_supported = $false
    arm64_emulation_network_packet_capture = $false
    network_packet_capture = $networkPacketCapture
    windows_firewall_isolation = $true
    signature_status = $SignatureStatus
}

$json = $capabilities | ConvertTo-Json -Depth 3 -Compress
$outputFullPath = [System.IO.Path]::GetFullPath($OutputPath)
$outputDir = Split-Path -Parent $outputFullPath
if ($outputDir -and -not (Test-Path -LiteralPath $outputDir)) {
    New-Item -ItemType Directory -Force -Path $outputDir | Out-Null
}
$utf8NoBom = [System.Text.UTF8Encoding]::new($false)
[System.IO.File]::WriteAllText($outputFullPath, $json, $utf8NoBom)

# Fail in the producer, before packaging, if PowerShell serialization changes
# the strict installer contract.
$roundTrip = [System.IO.File]::ReadAllText($outputFullPath, [System.Text.Encoding]::UTF8) | ConvertFrom-Json
$expectedFields = @(
    "schema",
    "target_arch",
    "arm64_emulation_supported",
    "arm64_emulation_network_packet_capture",
    "network_packet_capture",
    "windows_firewall_isolation",
    "signature_status"
)
$actualFields = @($roundTrip.PSObject.Properties.Name)
if ($actualFields.Count -ne $expectedFields.Count) {
    throw "package capability field count mismatch: expected=$($expectedFields.Count) actual=$($actualFields.Count)"
}
foreach ($field in $expectedFields) {
    if ($actualFields -notcontains $field) {
        throw "package capability field missing after serialization: $field"
    }
}
if ($roundTrip.schema -ne "edr.windows.package-capabilities.v1" -or
    $roundTrip.target_arch -ne $TargetArch -or
    $roundTrip.signature_status -ne $SignatureStatus -or
    $roundTrip.arm64_emulation_supported -ne $false -or
    $roundTrip.arm64_emulation_network_packet_capture -ne $false -or
    $roundTrip.network_packet_capture -ne $networkPacketCapture -or
    $roundTrip.windows_firewall_isolation -ne $true) {
    throw "package capability values changed during serialization"
}

Write-Host "Wrote Windows package capabilities: arch=$TargetArch signature=$SignatureStatus network_packet_capture=$networkPacketCapture path=$outputFullPath"
