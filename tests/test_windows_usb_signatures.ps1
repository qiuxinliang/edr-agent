#Requires -Version 5.1
# Unit-test PE identity with Authenticode isolated; this is not a USB probe.
$ErrorActionPreference='Stop'
$path=Join-Path $PSScriptRoot '../scripts/Verify-WindowsUsbSignatures.ps1'
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
if($errors.Count) { throw 'Signature verifier parse failure' }
foreach($fn in $ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst]},$false)) {
 . ([scriptblock]::Create($fn.Extent.Text))
}
$scratch=Join-Path ([IO.Path]::GetTempPath()) ('edr-usb-identity-test-'+[Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $scratch | Out-Null
$pin='A'*40
$script:signatureStatus='Valid'
function Get-AuthenticodeSignature { param($LiteralPath) [pscustomobject]@{Status=$script:signatureStatus;SignerCertificate=[pscustomobject]@{Thumbprint=$pin};TimeStamperCertificate=$true} }
function Reject([scriptblock]$Call) { $failed=$false; try { & $Call } catch { $failed=$true }; if(-not $failed) { throw 'Expected identity validation failure' } }
try {
 [byte[]]$a=New-Object byte[] 512
 [BitConverter]::GetBytes([int]128).CopyTo($a,60)
 [BitConverter]::GetBytes([uint32]0x4550).CopyTo($a,128)
 [BitConverter]::GetBytes([uint16]0x20b).CopyTo($a,152)
 [byte[]]$b=New-Object byte[] 528
 $a.CopyTo($b,0)
 [BitConverter]::GetBytes([uint32]512).CopyTo($b,296)
 [BitConverter]::GetBytes([uint32]16).CopyTo($b,300)
 $original=Join-Path $scratch 'original.exe'; $signed=Join-Path $scratch 'signed.exe'
 [IO.File]::WriteAllBytes($original,$a); [IO.File]::WriteAllBytes($signed,$b)
 Assert-SignedExecutable $original $signed $pin
 $b[400]=1; [IO.File]::WriteAllBytes($signed,$b)
 Reject { Assert-SignedExecutable $original $signed $pin }
 $b[400]=0; [BitConverter]::GetBytes([uint32]500).CopyTo($b,296); [IO.File]::WriteAllBytes($signed,$b)
 Reject { Assert-SignedExecutable $original $signed $pin }
 Reject { Assert-SignedExecutable $original $signed ('B'*40) }
 # GUI entry points must really be unsigned, and their wrapper byte-identical.
 Reject { Assert-UnsignedExecutable $original }
 $script:signatureStatus='NotSigned'
 Assert-UnsignedExecutable $original
 Assert-UnchangedUnsignedExecutable $original $original
 Reject { Assert-UnchangedUnsignedExecutable $original $signed }
 $script:signatureStatus='UnknownError'
 Reject { Assert-UnsignedExecutable $original }
 $script:signatureStatus='Valid'
 # Exercise the actual CMS verifier with a disposable in-memory key.
 Add-Type -AssemblyName System.Security
 $rsa=[Security.Cryptography.RSA]::Create(2048)
 try {
  $request=[Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=EDR unit test',$rsa,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)
  $cert=$request.CreateSelfSigned([DateTimeOffset]::Now.AddMinutes(-1),[DateTimeOffset]::Now.AddDays(1))
  try {
   $json=Join-Path $scratch 'manifest.json'; $cmsPath=$json+'.p7s'
   [IO.File]::WriteAllText($json,'{"test":true}')
   $cms=[Security.Cryptography.Pkcs.SignedCms]::new([Security.Cryptography.Pkcs.ContentInfo]::new([IO.File]::ReadAllBytes($json)),$true)
   $signer=[Security.Cryptography.Pkcs.CmsSigner]::new($cert)
   $signer.DigestAlgorithm=[Security.Cryptography.Oid]::new('2.16.840.1.101.3.4.2.1')
   $cms.ComputeSignature($signer); [IO.File]::WriteAllBytes($cmsPath,$cms.Encode())
   Assert-ExchangeCms $json $cmsPath $cert.Thumbprint
   Reject { Assert-ExchangeCms $json $cmsPath ('B'*40) }
   [IO.File]::WriteAllText($json,'{"test":false}')
   Reject { Assert-ExchangeCms $json $cmsPath $cert.Thumbprint }
  } finally { $cert.Dispose() }
 } finally { $rsa.Dispose() }
 Write-Host 'PASS: PE payload identity, publisher mismatch, certificate bounds, real CMS and tamper rejection'
} finally { Remove-Item -LiteralPath $scratch -Recurse -Force }
