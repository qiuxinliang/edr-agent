#Requires -Version 5.1
param(
  [Parameter(Mandatory = $true)]
  [string] $Path,
  [Parameter(Mandatory = $true)]
  [ValidateSet("amd64", "arm64")]
  [string] $Architecture
)

$ErrorActionPreference = "Stop"
$resolved = (Resolve-Path -LiteralPath $Path).Path
$bytes = [System.IO.File]::ReadAllBytes($resolved)
if ($bytes.Length -lt 256 -or $bytes[0] -ne 0x4d -or $bytes[1] -ne 0x5a) {
  throw "Not a valid PE file: $resolved"
}
$peOffset = [BitConverter]::ToInt32($bytes, 0x3c)
if ($peOffset -lt 0 -or $peOffset + 6 -gt $bytes.Length -or
    $bytes[$peOffset] -ne 0x50 -or $bytes[$peOffset + 1] -ne 0x45) {
  throw "Invalid PE header: $resolved"
}
$machine = [BitConverter]::ToUInt16($bytes, $peOffset + 4)
$expected = if ($Architecture -eq "arm64") { [UInt16]0xaa64 } else { [UInt16]0x8664 }
if ($machine -ne $expected) {
  throw ("PE architecture mismatch: path={0} expected={1}/0x{2:x4} actual=0x{3:x4}" -f $resolved, $Architecture, $expected, $machine)
}
Write-Host ("Verified PE architecture: {0} machine=0x{1:x4} path={2}" -f $Architecture, $machine, $resolved)
