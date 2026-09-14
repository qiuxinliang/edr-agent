#Requires -Version 5.1
param([Parameter(Mandatory=$true)][string]$SignTool, [string]$Thumbprint = '')
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..\scripts\WindowsStoreSigning.ps1')
$scratch = Join-Path ([IO.Path]::GetTempPath()) ('edr-store-signing-test-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $scratch | Out-Null
$certificate = $null
try {
    $rejected = $false
    try { Get-EdRStoreSigningCertificate -Thumbprint 'not-a-thumbprint' | Out-Null } catch { $rejected = $true }
    if (-not $rejected) { throw 'Malformed publisher thumbprint was accepted' }
    $rejected = $false
    try { Invoke-EdRSignTool -SignTool $SignTool -Arguments @('sign', "bad`nargument") } catch { $rejected = $true }
    if (-not $rejected) { throw 'Unsafe signing argument was accepted' }
    # Only a temporary CurrentUser leaf; never add test certificates to Roots.
    if ($Thumbprint) { $certificate = Get-EdRStoreSigningCertificate -Thumbprint $Thumbprint }
    else {
        $certificate = New-SelfSignedCertificate -Type CodeSigningCert -Subject 'CN=EDR USB signing regression only' `
            -CertStoreLocation Cert:\CurrentUser\My -Provider 'Microsoft Software Key Storage Provider' `
            -KeyLength 2048 -NotAfter (Get-Date).AddDays(1)
    }
    $contentPath = Join-Path $scratch 'contract.json'
    $signaturePath = Join-Path $scratch 'contract.p7s'
    [IO.File]::WriteAllText($contentPath, '{"test_only":true,"version":"1.2.3"}', (New-Object Text.UTF8Encoding($false)))
    Write-EdRStoreDetachedCms -ContentPath $contentPath -SignaturePath $signaturePath -Thumbprint $certificate.Thumbprint -SignTool $SignTool
    $content = [System.Security.Cryptography.Pkcs.ContentInfo]::new([IO.File]::ReadAllBytes($contentPath))
    $cms = [System.Security.Cryptography.Pkcs.SignedCms]::new($content, $true)
    $cms.Decode([IO.File]::ReadAllBytes($signaturePath))
    $cms.CheckSignature($true)
    if (-not $cms.Detached -or $cms.ContentInfo.ContentType.Value -ne '1.2.840.113549.1.7.1' -or
        $cms.SignerInfos[0].Certificate.Thumbprint -ne $certificate.Thumbprint -or
        $cms.SignerInfos[0].DigestAlgorithm.Value -ne '2.16.840.1.101.3.4.2.1') { throw 'CMS output violates the publisher contract' }
    $tampered = [System.Security.Cryptography.Pkcs.ContentInfo]::new([Text.Encoding]::UTF8.GetBytes('{"test_only":false}'))
    $bad = [System.Security.Cryptography.Pkcs.SignedCms]::new($tampered, $true)
    $bad.Decode([IO.File]::ReadAllBytes($signaturePath))
    $rejected = $false
    try { $bad.CheckSignature($true) } catch { $rejected = $true }
    if (-not $rejected) { throw 'Modified manifest passed signature verification' }
    Write-Host 'PASS: publisher validation, argument validation, real detached SHA256 CMS, tamper rejection'
} finally {
    if ($certificate -and -not $Thumbprint) {
        Remove-Item -LiteralPath ('Cert:\CurrentUser\My\' + $certificate.Thumbprint) -DeleteKey -Force
    }
    Remove-Item -LiteralPath $scratch -Recurse -Force
}
