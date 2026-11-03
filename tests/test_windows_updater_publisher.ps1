#Requires -Version 5.1
[CmdletBinding()]
param(
  [string]$UpdaterPath = (Join-Path $PSScriptRoot '..\scripts\edr_agent_inplace_update.ps1'),
  [string]$PublisherCertificatePath = '',
  [string]$ExpectedSubjectDerSha256 = ''
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
Set-StrictMode -Version Latest

# Extract the actual verifier without running installation, service, or task code.
$tokens = $null; $parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile((Resolve-Path -LiteralPath $UpdaterPath).Path, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -ne 0) { throw 'updater PowerShell parse failed' }
$definitions = @($ast.FindAll({param($node)
  $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Assert-AuthenticodePublisher'
}, $true))
if ($definitions.Count -ne 1) { throw 'updater publisher verifier was not uniquely found' }
. ([scriptblock]::Create($definitions[0].Extent.Text))

# A synthetic public certificate only; its private key is not retained. The
# expected digest was calculated from the original ASN.1 subject TLV, not from
# a Windows/Go display string. Authenticode I/O alone is stubbed below.
$certificateBase64 = 'MIIFQDCCBCgCCQDVGaXzxVq6cjANBgkqhkiG9w0BAQsFADCCAV8xCzAJBgNVBAYTAlpaMUUwQwYDVQQIDDxFeGFtcGxlIHByb3ZpbmNlIHVzZWQgb25seSBmb3IgZGV0ZXJtaW5pc3RpYyBwdWJsaXNoZXIgdGVzdHMxQTA/BgNVBAcMOEV4YW1wbGUgY2l0eSB1c2VkIG9ubHkgZm9yIGRldGVybWluaXN0aWMgcHVibGlzaGVyIHRlc3RzMUQwQgYDVQQKDDtFeGFtcGxlIHB1Ymxpc2hlciBvcmdhbml6YXRpb24gd2l0aCBhIGxvbmcgY2VydGlmaWNhdGUgbmFtZTE/MD0GA1UECww2RXhhbXBsZSBwdWJsaXNoZXIgb3JnYW5pemF0aW9uYWwgdW5pdCB3aXRoIGEgbG9uZyBuYW1lMT8wPQYDVQQDDDZFeGFtcGxlIHB1Ymxpc2hlciBmaXh0dXJlIHdpdGggYSBsb25nIGNlcnRpZmljYXRlIG5hbWUwIBcNMjYxMTAzMDgwMTE5WhgPMjEyNjEwMTAwODAxMTlaMIIBXzELMAkGA1UEBhMCWloxRTBDBgNVBAgMPEV4YW1wbGUgcHJvdmluY2UgdXNlZCBvbmx5IGZvciBkZXRlcm1pbmlzdGljIHB1Ymxpc2hlciB0ZXN0czFBMD8GA1UEBww4RXhhbXBsZSBjaXR5IHVzZWQgb25seSBmb3IgZGV0ZXJtaW5pc3RpYyBwdWJsaXNoZXIgdGVzdHMxRDBCBgNVBAoMO0V4YW1wbGUgcHVibGlzaGVyIG9yZ2FuaXphdGlvbiB3aXRoIGEgbG9uZyBjZXJ0aWZpY2F0ZSBuYW1lMT8wPQYDVQQLDDZFeGFtcGxlIHB1Ymxpc2hlciBvcmdhbml6YXRpb25hbCB1bml0IHdpdGggYSBsb25nIG5hbWUxPzA9BgNVBAMMNkV4YW1wbGUgcHVibGlzaGVyIGZpeHR1cmUgd2l0aCBhIGxvbmcgY2VydGlmaWNhdGUgbmFtZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAN6rDV4tm70C/HeQu4CawI4i+5KmS56+BX4ozA1QZHq/YM1BPUg3/YLNIBvtz2OAi8W0kGhPZHtQVh0gJk5SE7D1cpz0BkGgpVATcusZQP2ZEgg4PcaSlkrtkscBv2GgteS2XfV8iiMkgIzOtBbueulJwdoqevST3LdoQz/3JpEvJW5xgoShLnrFyERaq1OZIcAookDn314zmLcgk5Z2zaDsKNzVqBY1Qo/l98TPTGw0qOGuxXEIGrmkKDkzvn9pXXFkk514wEwAkxAtkKvJAxp9fDXIFrGeSbppJV0EcswRLMZsynnd9aSjUEC1yAkkmy/YfjEVdmOI4o4a58x2tWsCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEA2y4rfsWdQ+5l/j6Ljtjwjr/o1RUFsFdAh1ntpZZ0alxnZHABqpi/tPgt7kEf8voFOrPfO5Azw34HlUi8L4XAtKy7GLW2z5JHKkDd9u43bOi53//IxRKTAf5C9RAaF960XbS5FHybd4w6kpSVvtqIHt/O7xnVOFWMknnhOVfYKGAPNqeEV/38hT7LcE53pcj39uP6Z/Gtwt43tNfG4Psg2YUi7HxhMu1OfQbulcKJFG14DbsPjbAsGZz+W8PKJcNtv4HeN7w31mTbLLccINum/Z7wk06O313gSC9VutmTcKJeoIW/dM7PANQRiK5QNt2VES1OyYs6vVHLlVnX+b50zA=='
$subjectHash = '7688d56dcd4da2448be5ef1b6e0da5180b65efdf65fd6c0b9b7b00e155f4fb18'
$certificate = New-Object Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList (,[Convert]::FromBase64String($certificateBase64))
$cases = New-Object 'System.Collections.Generic.List[string]'
$script:signatureQueries = 0
$script:fixtureSignature = $null
function Get-AuthenticodeSignature {
  [CmdletBinding()]
  param([string]$LiteralPath)
  $script:signatureQueries++
  return $script:fixtureSignature
}
function Use-Signature($Signer, [string]$Status = 'Valid') {
  $script:fixtureSignature = [pscustomobject]@{
    Status = [Enum]::Parse([Management.Automation.SignatureStatus], $Status)
    SignerCertificate = $Signer
    StatusMessage = $Status
  }
}
function Pass([string]$Name, [scriptblock]$Action) {
  & $Action
  $cases.Add($Name)
}
function Reject([string]$Name, [string]$Expected, [scriptblock]$Action) {
  $caught = $false
  try { & $Action } catch {
    $caught = $true
    if ($_.Exception.Message -notlike $Expected) { throw ($Name + ': unexpected rejection: ' + $_.Exception.Message) }
  }
  if (-not $caught) { throw ($Name + ': unexpectedly accepted') }
  $cases.Add($Name)
}
try {
  if ([Text.Encoding]::UTF8.GetByteCount($certificate.Subject) -le 256) { throw 'certificate fixture must exercise the historical subject length boundary' }
  Use-Signature $certificate
  Pass 'der_identity_survives_display_difference' {
    Assert-AuthenticodePublisher -Path 'fixture.exe' -Thumbprint $certificate.Thumbprint -Subject 'different platform display name' -SubjectDerSha256 $subjectHash
  }
  Pass 'der_hash_case_is_not_identity' {
    Assert-AuthenticodePublisher -Path 'fixture.exe' -Thumbprint $certificate.Thumbprint.ToLowerInvariant() -Subject $certificate.Subject -SubjectDerSha256 $subjectHash.ToUpperInvariant()
  }
  Pass 'legacy_exact_subject_without_new_parameter' {
    Assert-AuthenticodePublisher -Path 'fixture.exe' -Thumbprint $certificate.Thumbprint -Subject $certificate.Subject
  }
  Pass 'legacy_exact_subject_with_empty_new_parameter' {
    Assert-AuthenticodePublisher -Path 'fixture.exe' -Thumbprint $certificate.Thumbprint -Subject $certificate.Subject -SubjectDerSha256 ''
  }
  Reject 'legacy_display_mismatch_stays_rejected' '*publisher subject is not trusted' {
    Assert-AuthenticodePublisher -Path 'fixture.exe' -Thumbprint $certificate.Thumbprint -Subject 'different platform display name'
  }
  Reject 'wrong_der_hash_never_falls_back_to_matching_display' '*subject DER SHA-256 is not trusted' {
    Assert-AuthenticodePublisher -Path 'fixture.exe' -Thumbprint $certificate.Thumbprint -Subject $certificate.Subject -SubjectDerSha256 ('0' * 64)
  }
  Reject 'thumbprint_remains_required_with_matching_der' '*publisher thumbprint is not trusted' {
    Assert-AuthenticodePublisher -Path 'fixture.exe' -Thumbprint ('0' * 40) -Subject $certificate.Subject -SubjectDerSha256 $subjectHash
  }
  foreach ($badHash in @('abc', ('g' * 64), ('a' * 65), (' ' + $subjectHash), ($subjectHash + "`n"))) {
    $before = $script:signatureQueries
    Reject ('malformed_der_hash_' + $cases.Count) '*must contain 64 hexadecimal characters' {
      Assert-AuthenticodePublisher -Path 'fixture.exe' -Thumbprint $certificate.Thumbprint -Subject $certificate.Subject -SubjectDerSha256 $badHash
    }
    if ($script:signatureQueries -ne $before) { throw 'malformed publisher proof reached Authenticode I/O' }
  }
  foreach ($status in @('NotSigned', 'HashMismatch', 'NotTrusted', 'UnknownError')) {
    Use-Signature $certificate $status
    Reject ('invalid_signature_' + $status) '*signature is not Valid*' {
      Assert-AuthenticodePublisher -Path 'fixture.exe' -Thumbprint $certificate.Thumbprint -Subject $certificate.Subject -SubjectDerSha256 $subjectHash
    }
  }
  Use-Signature $null
  Reject 'missing_signer_rejected' '*signature is not Valid*' {
    Assert-AuthenticodePublisher -Path 'fixture.exe' -Thumbprint $certificate.Thumbprint -Subject $certificate.Subject -SubjectDerSha256 $subjectHash
  }
  Use-Signature ([pscustomobject]@{ Thumbprint=$certificate.Thumbprint; Subject=$certificate.Subject; SubjectName=[pscustomobject]@{RawData=[byte[]]@()} })
  Reject 'missing_raw_subject_rejected' '*subject DER is unavailable' {
    Assert-AuthenticodePublisher -Path 'fixture.exe' -Thumbprint $certificate.Thumbprint -Subject $certificate.Subject -SubjectDerSha256 $subjectHash
  }
  $before = $script:signatureQueries
  Pass 'legacy_unsigned_marker_preserved' {
    Assert-AuthenticodePublisher -Path 'fixture.exe' -Thumbprint 'SHA256_ONLY_UNSIGNED' -Subject 'Unsigned release; SHA-256 integrity only'
  }
  Reject 'unsigned_cannot_claim_signed_subject_proof' '*unsigned release publisher marker is inconsistent' {
    Assert-AuthenticodePublisher -Path 'fixture.exe' -Thumbprint 'SHA256_ONLY_UNSIGNED' -Subject 'Unsigned release; SHA-256 integrity only' -SubjectDerSha256 $subjectHash
  }
  Reject 'unsigned_marker_mismatch_stays_rejected' '*unsigned release publisher marker is inconsistent' {
    Assert-AuthenticodePublisher -Path 'fixture.exe' -Thumbprint 'SHA256_ONLY_UNSIGNED' -Subject 'untrusted marker'
  }
  if ($script:signatureQueries -ne $before) { throw 'unsigned marker handling unexpectedly queried a signer' }

  $observedCertificate = $null
  if ($PublisherCertificatePath -or $ExpectedSubjectDerSha256) {
    if (-not $PublisherCertificatePath -or $ExpectedSubjectDerSha256 -cnotmatch '\A[0-9A-Fa-f]{64}\z') { throw 'public certificate validation requires its independently calculated DER subject SHA-256' }
    $live = New-Object Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList (,[IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $PublisherCertificatePath).Path))
    try {
      Use-Signature $live
      Pass 'provided_public_certificate_der_binding' {
        Assert-AuthenticodePublisher -Path 'fixture.exe' -Thumbprint $live.Thumbprint -Subject 'cross-platform display text' -SubjectDerSha256 $ExpectedSubjectDerSha256
      }
      $observedCertificate = @{thumbprint=$live.Thumbprint; subject_der_sha256=$ExpectedSubjectDerSha256.ToLowerInvariant(); subject_utf8_bytes=[Text.Encoding]::UTF8.GetByteCount($live.Subject)}
    } finally { $live.Dispose() }
  }
  [ordered]@{
    status='succeeded'; case_count=$cases.Count; cases=$cases.ToArray()
    fixture_subject_der_sha256=$subjectHash; fixture_subject_utf8_bytes=[Text.Encoding]::UTF8.GetByteCount($certificate.Subject)
    provided_certificate=$observedCertificate
    scope='Actual production publisher verifier; Authenticode I/O stubbed; real public X509 subject bytes; no installation or certificate-store writes'
  } | ConvertTo-Json -Depth 5
} finally {
  $certificate.Dispose()
  Remove-Item -LiteralPath Function:Get-AuthenticodeSignature
}
