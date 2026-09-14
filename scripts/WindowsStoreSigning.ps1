#Requires -Version 5.1
# USB/HSM keys stay in the current user's Windows certificate provider.
# No key export, PIN storage, store auto-selection, or unsigned fallback.
function Invoke-EdRSignTool {
    param([string]$SignTool, [string[]]$Arguments, [int]$TimeoutSeconds = 180)
    if (-not $SignTool) { $SignTool = (Get-Command signtool.exe -ErrorAction Stop).Source }
    $quoted = @($Arguments | ForEach-Object {
        if ($_ -match '["\r\n]' -or $_.EndsWith('\')) { throw 'Invalid signing argument' }
        '"' + $_ + '"'
    })
    $start = New-Object Diagnostics.ProcessStartInfo
    $start.FileName = (Resolve-Path -LiteralPath $SignTool).Path
    $start.Arguments = $quoted -join ' '
    $start.UseShellExecute = $false
    $process = [Diagnostics.Process]::Start($start)
    try {
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            $process.Kill()
            if (-not $process.WaitForExit(5000)) { throw 'SignTool did not exit after termination; check USB middleware and storage before retrying' }
            throw "USB signing timed out after ${TimeoutSeconds}s; unlock the token in this Windows user session and retry"
        }
        if ($process.ExitCode -ne 0) { throw "SignTool failed with exit $($process.ExitCode); check USB token/PIN, certificate provider and timestamp connectivity" }
    } finally { $process.Dispose() }
}

function Get-EdRStoreSigningCertificate {
    param([Parameter(Mandatory=$true)][string]$Thumbprint)
    $normalized = ($Thumbprint -replace '\s', '').ToUpperInvariant()
    if ($normalized -cnotmatch '\A[0-9A-F]{40}\z') { throw 'Signing thumbprint must contain exactly 40 hexadecimal characters' }
    $certificate = Get-Item -LiteralPath "Cert:\CurrentUser\My\$normalized" -ErrorAction Stop
    if (-not $certificate.HasPrivateKey) { throw 'The selected signing certificate has no accessible private key; check USB connection and user session' }
    $now = Get-Date
    if ($now -lt $certificate.NotBefore -or $now -gt $certificate.NotAfter) { throw 'The selected signing certificate is outside its validity period' }
    $eku = @($certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' })
    if ($eku.Count -ne 1 -or @($eku[0].EnhancedKeyUsages | Where-Object { $_.Value -eq '1.3.6.1.5.5.7.3.3' }).Count -eq 0) {
        throw 'The selected certificate is not a code-signing certificate'
    }
    return $certificate
}

function Invoke-EdRStoreAuthenticodeSign {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][string]$Thumbprint,
        [string]$SignTool = $env:EDR_SIGNTOOL_PATH
    )
    $certificate = Get-EdRStoreSigningCertificate -Thumbprint $Thumbprint
    if (-not $SignTool) { $SignTool = (Get-Command signtool.exe -ErrorAction Stop).Source }
    $target = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
    Invoke-EdRSignTool -SignTool $SignTool -Arguments @('sign','/fd','SHA256','/td','SHA256','/tr','http://timestamp.digicert.com','/s','My','/sha1',$certificate.Thumbprint,$target)
    Invoke-EdRSignTool -SignTool $SignTool -Arguments @('verify','/pa','/all','/tw',$target)
    $signature = Get-AuthenticodeSignature -LiteralPath $target
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Thumbprint -ne $certificate.Thumbprint -or -not $signature.TimeStamperCertificate) {
        throw "Signed executable does not match the selected publisher or lacks a valid timestamp: $target"
    }
}

function Write-EdRStoreDetachedCms {
    param(
        [Parameter(Mandatory=$true)][string]$ContentPath,
        [Parameter(Mandatory=$true)][string]$SignaturePath,
        [Parameter(Mandatory=$true)][string]$Thumbprint,
        [string]$SignTool = $env:EDR_SIGNTOOL_PATH
    )
    Add-Type -AssemblyName System.Security
    $certificate = Get-EdRStoreSigningCertificate -Thumbprint $Thumbprint
    $content = [System.Security.Cryptography.Pkcs.ContentInfo]::new([IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $ContentPath)))
    # SignTool supports hardware providers that cannot be accessed through
    # Framework SignedCms.ComputeSignature (notably emulated USB middleware).
    # Use standard id-data detached CMS, not Authenticode's indirect-data OID.
    $scratch = Join-Path ([IO.Path]::GetTempPath()) ('edr-cms-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $scratch -ErrorAction Stop | Out-Null
    try {
        $inputFile = Join-Path $scratch 'manifest.json'
        [IO.File]::WriteAllBytes($inputFile, $content.Content)
        Invoke-EdRSignTool -SignTool $SignTool -Arguments @('sign','/fd','SHA256','/s','My','/sha1',$certificate.Thumbprint,'/p7',$scratch,'/p7co','1.2.840.113549.1.7.1','/p7ce','DetachedSignedData',$inputFile)
        $encoded = [IO.File]::ReadAllBytes($inputFile + '.p7')
    } finally {
        Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction Stop
    }
    $verify = [System.Security.Cryptography.Pkcs.SignedCms]::new($content, $true)
    $verify.Decode($encoded)
    $verify.CheckSignature($true)
    if ($verify.SignerInfos.Count -ne 1 -or $verify.SignerInfos[0].Certificate.Thumbprint -ne $certificate.Thumbprint -or
        $verify.SignerInfos[0].DigestAlgorithm.Value -ne '2.16.840.1.101.3.4.2.1') {
        throw 'Detached CMS does not match the SHA-256 publisher contract'
    }
    [IO.File]::WriteAllBytes($SignaturePath, $encoded)
}
