#Requires -Version 5.1
[CmdletBinding()]
param([string]$RepoRoot=(Split-Path -Parent $PSScriptRoot))
$ErrorActionPreference='Stop'
$root=Join-Path ([IO.Path]::GetTempPath()) ('edr-lifecycle-publisher-'+[Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($root)|Out-Null
$cases=New-Object 'System.Collections.Generic.List[string]'
function Hash([string]$Path) { return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
function Put([string]$Path,[string]$Text) { [IO.File]::WriteAllText($Path,$Text,[Text.UTF8Encoding]::new($false)) }
function Pass([string]$Name,[scriptblock]$Action) { & $Action; $cases.Add($Name) }
function Reject([string]$Name,[string]$Expected,[scriptblock]$Action) {
  $caught=$false
  try { & $Action } catch {
    $caught=$true
    if ($_.Exception.Message -notlike $Expected) { throw ($Name+': unexpected failure: '+$_.Exception.Message) }
  }
  if (-not $caught) { throw ($Name+': unexpectedly accepted') }
  $cases.Add($Name)
}
$certificate=$null
try {
  $tokens=$null;$errors=$null
  $ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $RepoRoot 'scripts/windows_setup_exe_lifecycle_smoke.ps1'),[ref]$tokens,[ref]$errors)
  if ($errors.Count -ne 0) { throw 'lifecycle script parse failed' }
  foreach ($name in @('Get-LifecycleTrustedPublisher','Assert-LifecyclePublisherProtocol','New-LifecyclePreservationSnapshot','Assert-LifecyclePreservationSnapshot')) {
    $owners=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name},$true))
    if ($owners.Count -ne 1) { throw ('missing unique production test owner '+$name) }
    . ([scriptblock]::Create($owners[0].Extent.Text))
  }
  # Reuse the public X509 fixture from the production publisher regression.
  # The only substituted boundary is Authenticode OS I/O; no key or trust-store write.
  $fixture=[Management.Automation.Language.Parser]::ParseFile((Join-Path $RepoRoot 'tests/test_windows_updater_publisher.ps1'),[ref]$tokens,[ref]$errors)
  $encoded=@($fixture.EndBlock.Statements | Where-Object {
    $_ -is [Management.Automation.Language.AssignmentStatementAst] -and $_.Left.Extent.Text -ceq '$certificateBase64'
  })
  $digest=@($fixture.EndBlock.Statements | Where-Object {
    $_ -is [Management.Automation.Language.AssignmentStatementAst] -and $_.Left.Extent.Text -ceq '$subjectHash'
  })
  if ($encoded.Count -ne 1 -or $digest.Count -ne 1) { throw 'public certificate fixture is not unique' }
  $certificate=New-Object Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList (,[Convert]::FromBase64String($encoded[0].Right.Extent.Text.Trim("'")))
  $subjectHash=$digest[0].Right.Extent.Text.Trim("'")
  $binary=Join-Path $root 'binary.exe';$setup=Join-Path $root 'setup.exe'
  $manifest=Join-Path $root 'manifest.json';$cms=Join-Path $root 'manifest.p7s'
  Put $binary 'external Authenticode fixture';Put $setup 'external setup fixture'
  Put $manifest 'immutable manifest fixture';Put $cms 'immutable CMS fixture'
  $proof=[pscustomobject]@{schema='edr.windows.publisher-verification.v1';version='3.2.737';arch='arm64';
    subject=('A'*378);thumbprint=$certificate.Thumbprint;subject_der_sha256=$subjectHash;
    manifest_sha256=(Hash $manifest);signature_sha256=(Hash $cms);artifact_sha256=(Hash $binary);verifier_source_commit=('c'*40)}
  $binding=[pscustomobject]@{signature_status='signed';target_version='3.2.737';architecture='arm64';
    publisher_thumbprint=$certificate.Thumbprint;publisher_subject=$proof.subject;publisher_subject_der_sha256=$subjectHash;
    publisher_verification=$proof;target_manifest_sha256=(Hash $manifest);target_signature_sha256=(Hash $cms);
    target_manifest_path=$manifest;target_signature_path=$cms;upgrade_class='installer_required';
    binary_path=$binary;binary_sha256=(Hash $binary);installer_path=$setup;installer_sha256=(Hash $setup)}
  $script:signature=[pscustomobject]@{Status='Valid';SignerCertificate=$certificate}
  function Get-AuthenticodeSignature { [CmdletBinding()]param([string]$LiteralPath) return $script:signature }
  Pass 'verified_DER_accepts_different_378_byte_display' {
    $trusted=Get-LifecycleTrustedPublisher $binding
    if ($trusted.Subject -cne $proof.subject -or $trusted.SubjectDerSha256 -cne $subjectHash) { throw 'verified identity was not forwarded' }
  }
  foreach ($field in @('schema','version','arch','subject','thumbprint','subject_der_sha256','manifest_sha256','signature_sha256','artifact_sha256','verifier_source_commit')) {
    $old=$proof.$field;$proof.$field='invalid'
    Reject ('proof_'+$field) '*not bound to the verified release*' { Get-LifecycleTrustedPublisher $binding|Out-Null }
    $proof.$field=$old
  }
  foreach ($path in @($manifest,$cms)) {
    $original=[IO.File]::ReadAllText($path);Put $path 'changed proof input'
    Reject 'original_proof_bytes_changed' '*differs from the verified publisher proof*' { Get-LifecycleTrustedPublisher $binding|Out-Null }
    Put $path $original
  }
  $binding.publisher_subject=$certificate.Subject;$proof.subject=$certificate.Subject
  $binding.publisher_subject_der_sha256='f'*64;$proof.subject_der_sha256=$binding.publisher_subject_der_sha256
  Reject 'wrong_DER_never_uses_matching_display' '*subject DER differs*' { Get-LifecycleTrustedPublisher $binding|Out-Null }
  $binding.publisher_subject_der_sha256=$subjectHash;$proof.subject_der_sha256=$subjectHash
  $binding.publisher_subject='A'*378;$proof.subject=$binding.publisher_subject
  foreach ($status in @('NotSigned','NotTrusted','HashMismatch','UnknownError')) {
    $script:signature.Status=$status
    Reject ('invalid_signature_'+$status) '*requires Valid*' { Get-LifecycleTrustedPublisher $binding|Out-Null }
  }
  $script:signature.Status='Valid';$script:signature.SignerCertificate=$null
  Reject 'missing_signer' '*requires Valid*' { Get-LifecycleTrustedPublisher $binding|Out-Null }
  $script:signature.SignerCertificate=[pscustomobject]@{Thumbprint=('B'*40);Subject=$certificate.Subject;SubjectName=$certificate.SubjectName}
  Reject 'wrong_thumbprint' '*publisher differs*' { Get-LifecycleTrustedPublisher $binding|Out-Null }
  $script:signature.SignerCertificate=$certificate
  $binding.signature_status='unsigned'
  Reject 'unsigned_cannot_claim_DER' '*contains a publisher identity*' { Get-LifecycleTrustedPublisher $binding|Out-Null }
  $binding.signature_status='signed'

  $updater=Join-Path $root 'installed-updater.ps1'
  $script6='param([string]$TrustedPublisherSubjectDerSha256)' + "`n" + '$AgentUpdateUpdaterProtocolVersion = 6'
  Put $updater $script6
  $publisher=Get-LifecycleTrustedPublisher $binding
  Pass 'installed_protocol_6_and_parameter' { Assert-LifecyclePublisherProtocol $updater (Hash $updater) $publisher }
  Reject 'wrong_installed_updater_hash' '*immutable installed updater*' { Assert-LifecyclePublisherProtocol $updater ('0'*64) $publisher }
  foreach ($bad in @(
      $script6.Replace('= 6','= 5'),$script6.Replace('TrustedPublisherSubjectDerSha256','Other'),
      ($script6+"`n"+'$AgentUpdateUpdaterProtocolVersion = 6'),$script6.Replace('= 6','= (3+3)'))) {
    Put $updater $bad
    Reject 'original_updater_cannot_claim_protocol_6' '*does not declare publisher identity protocol 6*' { Assert-LifecyclePublisherProtocol $updater (Hash $updater) $publisher }
  }
  Pass 'legacy_no_DER_does_not_inject_protocol_requirement' { Assert-LifecyclePublisherProtocol $updater (Hash $updater) @{SubjectDerSha256=''} }
  $binding.publisher_subject_der_sha256='';$binding.publisher_verification=$null;$binding.publisher_subject=$certificate.Subject
  Pass 'legacy_exact_subject_still_accepted' { $null=Get-LifecycleTrustedPublisher $binding }
  $binding.publisher_subject='legacy mismatch'
  Reject 'legacy_display_mismatch_stays_rejected' '*publisher differs*' { Get-LifecycleTrustedPublisher $binding|Out-Null }

  $InstallDir=Join-Path $root 'installed';$EvidenceDir=Join-Path $root 'evidence';$ServiceName='FixtureService'
  [IO.Directory]::CreateDirectory($InstallDir)|Out-Null;[IO.Directory]::CreateDirectory($EvidenceDir)|Out-Null
  Put (Join-Path $InstallDir 'agent.toml') 'private fixture configuration is never emitted'
  $script:service=[pscustomobject]@{State='Running';PathName=(Join-Path $InstallDir 'FDSensor.exe');StartName='LocalSystem';StartMode='Auto'}
  function Get-CimInstance { [CmdletBinding()]param($ClassName,[string]$Filter) return $script:service }
  function Add-Evidence { param($Stage,$Status,$Detail) }
  $snapshot=New-LifecyclePreservationSnapshot 'fixture'
  Pass 'actual_config_and_synthetic_marker_preservation' { Assert-LifecyclePreservationSnapshot $snapshot 'fixture' }
  $script:service.StartName='Other'
  Reject 'service_account_change' '*service deployment identity*' { Assert-LifecyclePreservationSnapshot $snapshot 'fixture' }
  $script:service.StartName='LocalSystem'
  Put (Join-Path $InstallDir 'agent.toml') 'changed'
  Reject 'configuration_change' '*configuration or identity*' { Assert-LifecyclePreservationSnapshot $snapshot 'fixture' }
  Put (Join-Path $InstallDir 'agent.toml') 'private fixture configuration is never emitted'
  Put (Join-Path $InstallDir $snapshot.markers[0].name) 'changed'
  Reject 'queue_marker_change' '*marker bytes*' { Assert-LifecyclePreservationSnapshot $snapshot 'fixture' }
  [ordered]@{status='succeeded';case_count=$cases.Count;cases=$cases.ToArray();scope='Actual lifecycle owners; Authenticode and service I/O isolated; no installed Agent or trust store touched'}|ConvertTo-Json -Depth 5
} finally {
  if ($certificate) { $certificate.Dispose() }
  foreach ($name in @('Get-AuthenticodeSignature','Get-CimInstance')) {
    if (Test-Path -LiteralPath ('Function:'+ $name)) { Remove-Item -LiteralPath ('Function:'+ $name) }
  }
  Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction Stop
}
