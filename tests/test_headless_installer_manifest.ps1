#Requires -Version 5.1
# Authenticode is isolated in this unit fixture. Release packaging calls the
# writer with the real cmdlet against the real bundled installer.
$ErrorActionPreference = 'Stop'
$writer = Join-Path $PSScriptRoot '../scripts/Write-HeadlessInstallerManifest.ps1'
$tokens = $null; $parseErrors = $null
$null = [Management.Automation.Language.Parser]::ParseFile($writer, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw 'Headless installer writer parse failure' }
$scratch = Join-Path ([IO.Path]::GetTempPath()) ('edr-headless-manifest-test-' + [Guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $scratch
# The writer runs in a child script scope. Capture a mutable holder explicitly;
# $script: inside its mock would resolve against that caller's script scope.
$signatureFixture = [pscustomobject]@{ Status = 'NotSigned'; Calls = 0; LastStatus = ''; LastPath = '' }
Set-Item -Path Function:Get-AuthenticodeSignature -Value ({
  param($LiteralPath, $ErrorAction)
  $signatureFixture.Calls = $signatureFixture.Calls + 1
  $signatureFixture.LastStatus = $signatureFixture.Status
  $signatureFixture.LastPath = $LiteralPath
  [pscustomobject]@{ Status = $signatureFixture.Status }
}.GetNewClosure())
function Reject([scriptblock] $Call, [string] $ExpectedCause = '') {
  $failure = $null
  try { & $Call } catch { $failure = $_.Exception.Message }
  if (-not $failure) { throw 'Expected Headless installer manifest validation failure' }
  if ($ExpectedCause -and -not $failure.Contains($ExpectedCause)) { throw 'Headless installer rejected for an unexpected cause' }
}
try {
  $setup = Join-Path $scratch 'edr_agent_setup.exe'
  [byte[]]$pe = New-Object byte[] 512
  $pe[0] = 0x4d; $pe[1] = 0x5a
  [BitConverter]::GetBytes([int]128).CopyTo($pe, 60)
  [BitConverter]::GetBytes([uint32]0x4550).CopyTo($pe, 128)
  [BitConverter]::GetBytes([uint16]0x014c).CopyTo($pe, 132)
  [IO.File]::WriteAllBytes($setup, $pe)
  [IO.File]::WriteAllText($setup + '.arch', 'arm64')
  $caps = Join-Path $scratch 'package-capabilities.json'
  [IO.File]::WriteAllText($caps, '{"schema":"edr.windows.package-capabilities.v1","target_arch":"arm64","signature_status":"unsigned","windows_firewall_isolation":true}')
  $fixtureParameters = @{ SetupExe = $setup; AppVersion = '3.2.688'; TargetArch = 'arm64';
    AgentBinarySha256 = ('A' * 64); RuntimeIdentitySha256 = ('B' * 64); PackageCapabilitiesPath = $caps }
  $out = Join-Path $scratch 'full-installer-manifest.json'
  & $writer @fixtureParameters -OutputPath $out
  if ($signatureFixture.Calls -ne 1 -or $signatureFixture.LastStatus -cne 'NotSigned' -or
      $signatureFixture.LastPath -cne $setup) {
    throw 'Child writer did not use the captured Authenticode fixture'
  }
  $actual = [IO.File]::ReadAllText($out) | ConvertFrom-Json
  if ($actual.version -cne '3.2.688' -or $actual.target_arch -cne 'arm64' -or $actual.setup_target_arch -cne 'arm64' -or
      $actual.agent_binary_sha256 -cne ('a' * 64) -or $actual.runtime_identity_sha256 -cne ('b' * 64) -or
      $actual.setup_exe_sha256 -cne (Get-FileHash -LiteralPath $setup -Algorithm SHA256).Hash.ToLowerInvariant() -or
      $actual.upgrade_protocol -cne 'edr.windows.full-installer-upgrade.v1' -or
      -not $actual.preserves_existing_identity -or -not $actual.preserves_offline_queue -or -not $actual.preserves_evidence_cache -or
      $actual.capabilities.signature_status -cne 'unsigned' -or -not $actual.capabilities.windows_firewall_isolation -or $actual.setup_exe_signed) {
    throw 'Headless installer manifest binding or preservation contract mismatch'
  }
  foreach ($name in @('ui_exe', 'ui_exe_sha256', 'ui_exe_signed', 'runtime_mode', 'dotnet_runtime', 'webview2_runtime')) {
    if ($actual.PSObject.Properties[$name]) { throw 'Headless manifest contains an invented UI field' }
  }
  $savedHash = (Get-FileHash -LiteralPath $out -Algorithm SHA256).Hash
  Reject { & $writer @fixtureParameters -OutputPath $out }
  if ((Get-FileHash -LiteralPath $out -Algorithm SHA256).Hash -cne $savedHash) { throw 'Existing manifest was overwritten' }
  $bad = Join-Path $scratch 'bad.json'
  foreach ($status in @('Valid', 'UnknownError', 'HashMismatch')) {
    $signatureFixture.Status = $status
    $callsBefore = $signatureFixture.Calls
    Reject { & $writer @fixtureParameters -OutputPath $bad } 'explicitly NotSigned Authenticode result'
    if ($signatureFixture.Calls -ne ($callsBefore + 1) -or $signatureFixture.LastStatus -cne $status) {
      throw 'Child writer did not observe the updated Authenticode fixture status'
    }
    if (Test-Path -LiteralPath $bad) { throw 'Rejected signature produced a manifest' }
  }
  $signatureFixture.Status = 'NotSigned'
  [IO.File]::WriteAllText($setup + '.arch', ('x' * 33))
  Reject { & $writer @fixtureParameters -OutputPath $bad } 'metadata exceeds its bound'
  [IO.File]::WriteAllText($setup + '.arch', 'arm64')
  [IO.File]::WriteAllText($caps, ('{"schema":"edr.windows.package-capabilities.v1","target_arch":"arm64","signature_status":"unsigned","padding":"' + ('x' * 1MB) + '"}'))
  Reject { & $writer @fixtureParameters -OutputPath $bad } 'metadata exceeds its bound'
  [IO.File]::WriteAllText($caps, '{"schema":"edr.windows.package-capabilities.v1","target_arch":"arm64","signature_status":"unsigned"}')
  [IO.File]::WriteAllText($setup + '.arch', 'amd64')
  Reject { & $writer @fixtureParameters -OutputPath $bad }
  [IO.File]::WriteAllText($setup + '.arch', 'arm64')
  [IO.File]::WriteAllText($caps, '{"schema":"edr.windows.package-capabilities.v1","target_arch":"arm64","signature_status":"signed"}')
  Reject { & $writer @fixtureParameters -OutputPath $bad }
  [IO.File]::WriteAllText($caps, '{"schema":"edr.windows.package-capabilities.v1","target_arch":"amd64","signature_status":"unsigned"}')
  Reject { & $writer @fixtureParameters -OutputPath $bad }
  [IO.File]::WriteAllText($caps, '{"schema":"edr.windows.package-capabilities.v1","target_arch":"arm64","signature_status":"unsigned"}')
  $fixtureParameters.AgentBinarySha256 = 'invalid'
  Reject { & $writer @fixtureParameters -OutputPath $bad }
  $fixtureParameters.AgentBinarySha256 = 'a' * 64
  $fixtureParameters.AppVersion = '3.2.688-extra'
  Reject { & $writer @fixtureParameters -OutputPath $bad }
  $fixtureParameters.AppVersion = '3.2.688'
  [BitConverter]::GetBytes([uint16]0xaa64).CopyTo($pe, 132)
  [IO.File]::WriteAllBytes($setup, $pe)
  Reject { & $writer @fixtureParameters -OutputPath $bad }
  if (Test-Path -LiteralPath $bad) { throw 'Rejected installer input produced a manifest' }
  [BitConverter]::GetBytes([uint16]0x014c).CopyTo($pe, 132)
  [IO.File]::WriteAllBytes($setup, $pe)
  [IO.File]::WriteAllText($setup + '.arch', 'amd64')
  [IO.File]::WriteAllText($caps, '{"schema":"edr.windows.package-capabilities.v1","target_arch":"amd64","signature_status":"unsigned"}')
  $fixtureParameters.TargetArch = 'amd64'
  $amdOutput = Join-Path $scratch 'amd64-manifest.json'
  $callsBefore = $signatureFixture.Calls
  & $writer @fixtureParameters -OutputPath $amdOutput
  if ($signatureFixture.Calls -ne ($callsBefore + 1) -or $signatureFixture.LastStatus -cne 'NotSigned') {
    throw 'AMD64 child writer did not use the restored Authenticode fixture status'
  }
  $amd = [IO.File]::ReadAllText($amdOutput) | ConvertFrom-Json
  if ($amd.target_arch -cne 'amd64' -or $amd.setup_target_arch -cne 'amd64' -or
      $amd.capabilities.target_arch -cne 'amd64' -or $amd.setup_exe_signed -or
      $amd.setup_exe_sha256 -cne (Get-FileHash -LiteralPath $setup -Algorithm SHA256).Hash.ToLowerInvariant()) {
    throw 'AMD64 Headless manifest binding mismatch'
  }
  Write-Host 'PASS: unsigned Headless manifest bindings on both architectures, preservation, no UI fields, exclusive output, signature/architecture/hash/version/bounds rejection (Authenticode fixture isolated)'
} finally {
  Remove-Item -LiteralPath $scratch -Recurse -Force
}
