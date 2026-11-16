#Requires -Version 5.1
param(
 [Parameter(Mandatory=$true)][string]$Original,
 [Parameter(Mandatory=$true)][string]$Signed,
 [Parameter(Mandatory=$true)][ValidatePattern('^[a-fA-F0-9]{40}$')][string]$Thumbprint
)
$ErrorActionPreference='Stop'
$Thumbprint=$Thumbprint.ToUpperInvariant()
function Assert-SignedExecutable([string]$Original, [string]$Signed, [string]$Thumbprint) {
    $sig = Get-AuthenticodeSignature -LiteralPath $Signed
    if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Thumbprint -ne $Thumbprint -or -not $sig.TimeStamperCertificate) {
        throw 'Returned EXE does not have the pinned publisher and valid timestamp'
    }
    # Signing may change only checksum, certificate directory and appended WIN_CERTIFICATE.
    # A different, otherwise valid publisher-signed executable is not an acceptable response.
    [byte[]]$a = [IO.File]::ReadAllBytes($Original); [byte[]]$b = [IO.File]::ReadAllBytes($Signed)
    if ($a.Length -lt 256 -or $b.Length -lt $a.Length) { throw 'Invalid returned PE length' }
    $pe = [BitConverter]::ToInt32($a,60); $optional = $pe+24
    if ($pe -lt 64 -or $optional+152 -gt $a.Length -or [BitConverter]::ToUInt32($a,$pe) -ne 0x4550) { throw 'Invalid input PE header' }
    $magic = [BitConverter]::ToUInt16($a,$optional)
    $security = $optional + $(if($magic -eq 0x20b){144}elseif($magic -eq 0x10b){128}else{throw 'Unknown PE format'})
    if ([BitConverter]::ToUInt64($a,$security) -ne 0) { throw 'Signing input must be an unsigned build output' }
    $offset = [BitConverter]::ToUInt32($b,$security); $size = [BitConverter]::ToUInt32($b,$security+4)
    if ($offset -lt $a.Length -or $offset-$a.Length -gt 7 -or $size -lt 8 -or [long]$offset+$size -ne $b.Length) { throw 'Invalid appended PE certificate range' }
    for ($i=$a.Length; $i -lt $offset; $i++) { if ($b[$i] -ne 0) { throw 'Unexpected data appended before PE certificate' } }
    foreach ($range in @(@(($optional+64),4),@($security,8))) {
        [Array]::Clear($a,$range[0],$range[1]); [Array]::Clear($b,$range[0],$range[1])
    }
    $hash = [Security.Cryptography.SHA256]::Create()
    try {
        if ([Convert]::ToBase64String($hash.ComputeHash($a)) -cne [Convert]::ToBase64String($hash.ComputeHash($b,0,$a.Length))) {
            throw 'Signing response changed executable payload'
        }
    } finally { $hash.Dispose() }
}
function Assert-ExchangeCms([string]$Content, [string]$Signature, [string]$Thumbprint) {
    Add-Type -AssemblyName System.Security
    $cms = [Security.Cryptography.Pkcs.SignedCms]::new([Security.Cryptography.Pkcs.ContentInfo]::new([IO.File]::ReadAllBytes($Content)), $true)
    $cms.Decode([IO.File]::ReadAllBytes($Signature)); $cms.CheckSignature($true)
    if ($cms.SignerInfos.Count -ne 1 -or $cms.SignerInfos[0].Certificate.Thumbprint -ne $Thumbprint -or
        $cms.SignerInfos[0].DigestAlgorithm.Value -ne '2.16.840.1.101.3.4.2.1') { throw 'Returned CMS publisher/digest mismatch' }
}
function Assert-UnsignedExecutable([string]$Path) {
    if ((Get-AuthenticodeSignature -LiteralPath $Path).Status -ne 'NotSigned') {
        throw 'Setup UI executable must remain unsigned'
    }
}
function Assert-UnchangedUnsignedExecutable([string]$Original, [string]$Returned) {
    Assert-UnsignedExecutable $Returned
    if ((Get-FileHash -LiteralPath $Original -Algorithm SHA256).Hash -cne
        (Get-FileHash -LiteralPath $Returned -Algorithm SHA256).Hash) {
        throw 'Setup UI wrapper changed; only the Headless executable closure may be signed'
    }
}

# The caller first verifies/extracts both complete bundles with windows_usb_bundle.py.
$names=@('FDSensor.exe','FDSecurityInstallerWorker.exe','uninstall.exe','collector/forensic_collector_builtin.exe')
if(Test-Path (Join-Path $Original 'runtime/collector/forensic_collector.exe')) { $names += 'collector/forensic_collector.exe' }
foreach($name in $names) { Assert-SignedExecutable (Join-Path $Original "runtime/$name") (Join-Path $Signed "runtime/$name") $Thumbprint }
Assert-UnchangedUnsignedExecutable (Join-Path $Original 'ui/FDSecuritySetupUI.exe') (Join-Path $Signed 'ui/FDSecuritySetupUI.exe')
# The Inno payload is built once. Its GUI copy remains unsigned; only the
# Headless copy acquires Authenticode, with no executable payload differences.
Assert-UnsignedExecutable (Join-Path $Signed 'ui/FDSecuritySetup.exe')
Assert-SignedExecutable (Join-Path $Signed 'ui/FDSecuritySetup.exe') (Join-Path $Signed 'runtime/edr_agent_setup.exe') $Thumbprint
Assert-ExchangeCms (Join-Path $Signed 'runtime/full-installer-manifest.json') (Join-Path $Signed 'runtime/full-installer-manifest.p7s') $Thumbprint
Assert-ExchangeCms (Join-Path $Signed 'ui/setup-ui-manifest.json') (Join-Path $Signed 'ui/setup-ui-manifest.p7s') $Thumbprint
$manifest=@(Get-ChildItem -LiteralPath (Join-Path $Signed 'assets') -Filter '*artifact-manifest.json' -File)
if($manifest.Count -ne 1) { throw 'Expected one final artifact manifest' }
Assert-ExchangeCms $manifest[0].FullName ($manifest[0].FullName+'.p7s') $Thumbprint
Write-Host 'Headless signatures, independent manifest CMS, timestamps, unchanged payloads and unsigned GUI entry points verified'
