#Requires -Version 5.1
$ErrorActionPreference = "Stop"

$writer = Join-Path $PSScriptRoot "write_windows_package_capabilities.ps1"
if (-not (Test-Path -LiteralPath $writer -PathType Leaf)) {
    throw "Missing package capability writer: $writer"
}

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
$expectedVelociraptorFields = @(
    "delivery",
    "binary_arch",
    "execution_mode",
    "optional",
    "network_packet_capture"
)
$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("edr-package-capabilities-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null
try {
    foreach ($arch in @("amd64", "arm64")) {
        foreach ($signatureStatus in @("signed", "unsigned")) {
            $path = Join-Path $tempRoot ("$arch-$signatureStatus.json")
            & $writer -OutputPath $path -TargetArch $arch -SignatureStatus $signatureStatus
            $roundTrip = [System.IO.File]::ReadAllText($path) | ConvertFrom-Json
            $actualFields = @($roundTrip.PSObject.Properties.Name | Sort-Object)
            $expectedSorted = @($expectedFields | Sort-Object)
            if (($actualFields -join "|") -ne ($expectedSorted -join "|")) {
                throw "Unexpected v1 capability fields for $arch/${signatureStatus}: $($actualFields -join ',')"
            }
            $actualVelociraptorFields = @($roundTrip.components.velociraptor.PSObject.Properties.Name | Sort-Object)
            $expectedVelociraptorSorted = @($expectedVelociraptorFields | Sort-Object)
            if (($actualVelociraptorFields -join "|") -ne ($expectedVelociraptorSorted -join "|")) {
                throw "Unexpected Velociraptor component capability fields for $arch/${signatureStatus}: $($actualVelociraptorFields -join ',')"
            }
            $expectedNetworkCapture = ($arch -eq "amd64")
            $expectedVelociraptorMode = if ($arch -eq "arm64") { "windows_x64_emulation" } else { "native" }
            if ($roundTrip.schema -ne "edr.windows.package-capabilities.v1" -or
                $roundTrip.target_arch -ne $arch -or
                $roundTrip.signature_status -ne $signatureStatus -or
                $roundTrip.arm64_emulation_supported -ne $false -or
                $roundTrip.arm64_emulation_network_packet_capture -ne $false -or
                $roundTrip.network_packet_capture -ne $expectedNetworkCapture -or
                $roundTrip.windows_firewall_isolation -ne $true -or
                $roundTrip.components.velociraptor.delivery -ne "platform_autofetch" -or
                $roundTrip.components.velociraptor.binary_arch -ne "amd64" -or
                $roundTrip.components.velociraptor.execution_mode -ne $expectedVelociraptorMode -or
                $roundTrip.components.velociraptor.optional -ne $true -or
                $roundTrip.components.velociraptor.network_packet_capture -ne $false) {
                throw "Capability round-trip mismatch for $arch/$signatureStatus"
            }
        }
    }
    Write-Host "Windows package capability v1 round-trip passed for AMD64 and ARM64."
}
finally {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
}
