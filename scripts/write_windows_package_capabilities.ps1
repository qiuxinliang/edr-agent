#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $OutputPath,

    [Parameter(Mandatory = $true)]
    [ValidateSet("amd64", "arm64")]
    [string] $TargetArch,

    [ValidateSet("signed", "unsigned")]
    [string] $SignatureStatus = "unsigned",

    [ValidateSet("platform_autofetch", "bundled")]
    [string] $VelociraptorDelivery = "platform_autofetch"
)

$ErrorActionPreference = "Stop"

# v1 signature_status describes the verified executable launch closure inside
# the package: signed means every required executable has valid Authenticode;
# unsigned means none does. Producers must reject mixed closures before calling
# this serializer. Detached CMS manifest signing is an independent trust layer.
#
# v1 permits only native Agent packages. The Velociraptor user-mode child is a
# deliberately isolated exception: the ARM64 package may consume the official
# AMD64 Velociraptor binary through Windows x64 emulation, while the Agent,
# service, updater, uninstaller and every driver remain native ARM64.
$networkPacketCapture = ($TargetArch -eq "amd64")
$velociraptorExecutionMode = if ($TargetArch -eq "arm64") { "windows_x64_emulation" } else { "native" }
$capabilities = [ordered]@{
    schema = "edr.windows.package-capabilities.v1"
    target_arch = $TargetArch
    arm64_emulation_supported = $false
    arm64_emulation_network_packet_capture = $false
    network_packet_capture = $networkPacketCapture
    windows_firewall_isolation = $true
    signature_status = $SignatureStatus
    components = [ordered]@{
        velociraptor = [ordered]@{
            delivery = $VelociraptorDelivery
            binary_arch = "amd64"
            execution_mode = $velociraptorExecutionMode
            optional = $true
            network_packet_capture = $false
        }
    }
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
    "signature_status",
    "components"
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
$expectedVelociraptorFields = @(
    "delivery",
    "binary_arch",
    "execution_mode",
    "optional",
    "network_packet_capture"
)
$actualVelociraptorFields = @($roundTrip.components.velociraptor.PSObject.Properties.Name)
if ($actualVelociraptorFields.Count -ne $expectedVelociraptorFields.Count) {
    throw "Velociraptor capability field count mismatch: expected=$($expectedVelociraptorFields.Count) actual=$($actualVelociraptorFields.Count)"
}
foreach ($field in $expectedVelociraptorFields) {
    if ($actualVelociraptorFields -notcontains $field) {
        throw "Velociraptor capability field missing after serialization: $field"
    }
}
if ($roundTrip.schema -ne "edr.windows.package-capabilities.v1" -or
    $roundTrip.target_arch -ne $TargetArch -or
    $roundTrip.signature_status -ne $SignatureStatus -or
    $roundTrip.arm64_emulation_supported -ne $false -or
    $roundTrip.arm64_emulation_network_packet_capture -ne $false -or
    $roundTrip.network_packet_capture -ne $networkPacketCapture -or
    $roundTrip.windows_firewall_isolation -ne $true -or
    $roundTrip.components.velociraptor.delivery -ne $VelociraptorDelivery -or
    $roundTrip.components.velociraptor.binary_arch -ne "amd64" -or
    $roundTrip.components.velociraptor.execution_mode -ne $velociraptorExecutionMode -or
    $roundTrip.components.velociraptor.optional -ne $true -or
    $roundTrip.components.velociraptor.network_packet_capture -ne $false) {
    throw "package capability values changed during serialization"
}

Write-Host "Wrote Windows package capabilities: arch=$TargetArch signature=$SignatureStatus network_packet_capture=$networkPacketCapture velociraptor=amd64/$velociraptorExecutionMode/$VelociraptorDelivery path=$outputFullPath"
