#Requires -Version 5.1
param(
  [Parameter(Mandatory = $true)]
  [string] $Path,
  [Parameter(Mandatory = $true)]
  [ValidateSet("amd64", "arm64")]
  [string] $PayloadArchitecture
)

$ErrorActionPreference = "Stop"
$resolved = (Resolve-Path -LiteralPath $Path).Path
$bytes = [System.IO.File]::ReadAllBytes($resolved)
if ($bytes.Length -lt 256 -or $bytes[0] -ne 0x4d -or $bytes[1] -ne 0x5a) {
  throw "Not a valid installer bootstrap PE file: $resolved"
}
$peOffset = [BitConverter]::ToInt32($bytes, 0x3c)
if ($peOffset -lt 0 -or $peOffset + 6 -gt $bytes.Length -or
    $bytes[$peOffset] -ne 0x50 -or $bytes[$peOffset + 1] -ne 0x45) {
  throw "Invalid installer bootstrap PE header: $resolved"
}

# Inno Setup 6 intentionally emits an x86 bootstrap even when it installs an
# AMD64 or ARM64 payload in native 64-bit install mode. The operating-system
# architecture remains restricted by ArchitecturesAllowed in the .iss file.
# Do not weaken the separate native Runtime PE checks to accommodate this
# bootstrap exception.
$machine = [BitConverter]::ToUInt16($bytes, $peOffset + 4)
$expectedInno6Bootstrap = [UInt16]0x014c
if ($machine -ne $expectedInno6Bootstrap) {
  throw ("Installer bootstrap architecture mismatch: path={0} payload={1} expected=Inno6-x86/0x{2:x4} actual=0x{3:x4}" -f `
    $resolved, $PayloadArchitecture, $expectedInno6Bootstrap, $machine)
}
Write-Host ("Verified Inno Setup 6 bootstrap: payload={0} machine=0x{1:x4} path={2}" -f `
  $PayloadArchitecture, $machine, $resolved)
