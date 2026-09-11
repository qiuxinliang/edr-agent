#Requires -Version 5.1
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$RepositoryRoot
)

$ErrorActionPreference = "Stop"
$RepositoryRoot = [IO.Path]::GetFullPath($RepositoryRoot)

function Assert-InstallTest {
  param([bool]$Condition, [string]$Message)
  if (-not $Condition) { throw "Windows install compatibility test failed: $Message" }
}

function Assert-InstallTestEqual {
  param([object]$Actual, [object]$Expected, [string]$Message)
  if ([string]$Actual -ne [string]$Expected) {
    throw "Windows install compatibility test failed: $Message; actual='$Actual' expected='$Expected'"
  }
}

function Ensure-TestCertificateProvider {
  $certDrive = Get-PSDrive -Name Cert -ErrorAction SilentlyContinue
  if ($certDrive) {
    if ($certDrive.Provider.Name -ne "Certificate") {
      throw "The Cert drive is already mapped to an unexpected provider: $($certDrive.Provider.Name)"
    }
    return
  }

  $provider = Get-PSProvider -PSProvider Certificate -ErrorAction SilentlyContinue
  if (-not $provider -and -not (Get-Module -Name Microsoft.PowerShell.Security)) {
    # -NoProfile runners can have the provider type data partially registered
    # by another built-in module. A terminating import can then fail with
    # FormatXmlUpdateException for duplicate members, even though the provider
    # can still be used. Preserve the import error and allow only that known
    # condition after verifying the actual provider below.
    $importFailure = $null
    try {
      Import-Module Microsoft.PowerShell.Security -ErrorAction Stop | Out-Null
    } catch {
      $importFailure = $_
    }
    $provider = Get-PSProvider -PSProvider Certificate -ErrorAction SilentlyContinue
    $importMessage = if ($importFailure) { [string]$importFailure.Exception.Message } else { "" }
    $duplicateTypeData = $importFailure -and
      ([string]$importFailure.FullyQualifiedErrorId -match "FormatXmlUpdateException") -and
      ($importMessage -match "(?s)Error in TypeData.*System.Security.AccessControl.ObjectSecurity") -and
      ($importMessage -match "(?s)member .*already present")
    if ($importFailure -and (-not $duplicateTypeData -or -not $provider)) {
      throw ("Microsoft.PowerShell.Security import failed: " + $importFailure.Exception.Message)
    }
  }
  if (-not $provider) {
    throw "Windows certificate compatibility test requires the Microsoft.PowerShell.Security Certificate provider"
  }

  $certDrive = Get-PSDrive -Name Cert -ErrorAction SilentlyContinue
  if ($certDrive) {
    if ($certDrive.Provider.Name -ne "Certificate") {
      throw "The Cert drive is already mapped to an unexpected provider: $($certDrive.Provider.Name)"
    }
    return
  }
  New-PSDrive -Name Cert -PSProvider Certificate -Root "\" -Scope Script -ErrorAction Stop | Out-Null
  Get-PSDrive -Name Cert -PSProvider Certificate -ErrorAction Stop | Out-Null
}

if ([string]$PSVersionTable.PSEdition -ne "Desktop") {
  throw "Windows install compatibility test must run under Windows PowerShell 5.1 Desktop; actual edition=$($PSVersionTable.PSEdition)"
}

$installerPath = Join-Path $RepositoryRoot "scripts\edr_agent_install.ps1"
$tokens = $null
$parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($installerPath, [ref]$tokens, [ref]$parseErrors)
if (@($parseErrors).Count -gt 0) {
  throw "installer script has $(@($parseErrors).Count) PowerShell parser error(s)"
}

# Load production functions without invoking the enrollment entrypoint.
foreach ($functionAst in @($ast.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] }, $true))) {
  Invoke-Expression $functionAst.Extent.Text
}

$diagnosticRoot = Join-Path ([IO.Path]::GetTempPath()) ("fds-install-compat-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $diagnosticRoot -Force | Out-Null
$oldDiagnosticRoot = $env:EDR_INSTALL_DIAGNOSTICS_DIR
$env:EDR_INSTALL_DIAGNOSTICS_DIR = $diagnosticRoot
$root = $null
$server = $null
$wrongEku = $null
$wrongIp = $null
$expired = $null
$unrestricted = $null
$intermediate = $null
$restrictedLeaf = $null
$oldTls = [Net.ServicePointManager]::SecurityProtocol
$oldCallback = [Net.ServicePointManager]::ServerCertificateValidationCallback
$caPath = Join-Path $diagnosticRoot "bootstrap-ca.cer"
$caBundlePath = Join-Path $diagnosticRoot "bootstrap-ca-bundle.cer"
$emptyCaPath = Join-Path $diagnosticRoot "empty-ca.cer"
$nativeOutputPath = Join-Path $diagnosticRoot "certreq-output.bin"
$primaryError = $null
$cleanupFailure = $null

try {
  $snapshot = Get-WindowsInstallCompatibilitySnapshot
  Assert-InstallTestEqual $snapshot.powershell.edition "Desktop" "runtime snapshot records Desktop PowerShell"
  Assert-InstallTest ($snapshot.powershell.executable -match '(?i)powerShell\.exe$') "runtime snapshot records the actual powershell.exe"
  Assert-InstallTest ([int]$snapshot.dotnet_framework_release -ge 0) "runtime snapshot records .NET Framework Release"
  [void](Assert-WindowsInstallCompatibility -RequestedProvider "pem")

  # Scoped input substitution tests capability decisions, not API availability
  # on this runner. The real CSR branches run separately below.
  & {
    $script:testSnapshot = $snapshot
    $savedCapabilities = [ordered]@{}
    foreach ($key in $snapshot.capabilities.Keys) { $savedCapabilities[$key] = $snapshot.capabilities[$key] }
    $savedTools = [ordered]@{}
    foreach ($key in $snapshot.tools.Keys) { $savedTools[$key] = $snapshot.tools[$key] }
    $savedPs = [ordered]@{}
    foreach ($key in $snapshot.powershell.Keys) { $savedPs[$key] = $snapshot.powershell[$key] }
    function Get-WindowsInstallCompatibilitySnapshot { return $script:testSnapshot }
    try {
      foreach ($key in @($snapshot.capabilities.Keys)) { $snapshot.capabilities[$key] = $true }
      $snapshot.tools["certreq.exe"] = "missing"
      [void](Assert-WindowsInstallCompatibility -RequestedProvider "cng")
      foreach ($missing in @("certificate_request", "copy_with_private_key")) {
        $snapshot.capabilities[$missing] = $false
        $failed = $false
        try { [void](Assert-WindowsInstallCompatibility -RequestedProvider "cng") }
        catch { $failed = $_.Exception.Message -match 'certreq.exe is required' }
        Assert-InstallTest $failed "$missing absent requires certreq"
        $snapshot.tools["certreq.exe"] = $savedTools["certreq.exe"]
        [void](Assert-WindowsInstallCompatibility -RequestedProvider "cng")
        $snapshot.capabilities[$missing] = $true
        $snapshot.tools["certreq.exe"] = "missing"
      }
      $snapshot.tools["certutil.exe"] = "missing"
      [void](Assert-WindowsInstallCompatibility -RequestedProvider "tpm" -ExternalTpmKeyUri $true)
      $snapshot.powershell.edition = "Core"
      $failed = $false
      try { [void](Assert-WindowsInstallCompatibility -RequestedProvider "pem") }
      catch { $failed = $_.Exception.Message -match 'PowerShell 5.1 Desktop' }
      Assert-InstallTest $failed "direct Core PowerShell is rejected"
    } finally {
      $snapshot.capabilities = $savedCapabilities
      $snapshot.tools = $savedTools
      $snapshot.powershell = $savedPs
    }
  }
  & {
    function Get-RegistryValueOrNull { return $script:testFrameworkRelease }
    foreach ($release in @(394802, 461808)) {
      $script:testFrameworkRelease = $release
      [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls
      Set-WindowsInstallTlsCompatibility
      $hasSystemDefault = [Enum]::IsDefined([Net.SecurityProtocolType], "SystemDefault")
      $expected = if ($release -lt 461808 -or -not $hasSystemDefault) { 3072 } else { 0 }
      Assert-InstallTestEqual ([int][Net.ServicePointManager]::SecurityProtocol) $expected "TLS policy for Framework Release $release"
    }
  }

  Set-WindowsInstallTlsCompatibility
  $tlsAfter = [string][Net.ServicePointManager]::SecurityProtocol
  if ([int]$snapshot.dotnet_framework_release -ge 461808 -and [Enum]::IsDefined([Net.SecurityProtocolType], "SystemDefault")) {
    Assert-InstallTest ($tlsAfter -match "SystemDefault") "modern .NET uses process-local SystemDefault"
  } else {
    Assert-InstallTest ($tlsAfter -match "Tls12") "old .NET uses process-local TLS 1.2"
    Assert-InstallTest (-not ($tlsAfter -match "Tls$|Tls11")) "old .NET does not enable TLS 1.0 or TLS 1.1"
  }

  $defaultEncoding = [Text.Encoding]::Default
  $nativeFixtureText = "certreq: caf$([char]0xE9)"
  [IO.File]::WriteAllBytes($nativeOutputPath, $defaultEncoding.GetBytes($nativeFixtureText))
  $decodedNativeOutput = Read-NativeProcessOutput -Path $nativeOutputPath
  $expectedNativeOutput = $defaultEncoding.GetString($defaultEncoding.GetBytes($nativeFixtureText))
  Assert-InstallTestEqual $decodedNativeOutput $expectedNativeOutput "native code-page output is decoded from captured bytes"
  # An actual child writes code-page bytes to both pipes, exits nonzero, or
  # sleeps. This covers the full capture path rather than just file decoding.
  $fixtureExe = Join-Path $diagnosticRoot "NativeOutputFixture.exe"
  Add-Type -OutputAssembly $fixtureExe -OutputType ConsoleApplication -TypeDefinition @'
using System;
using System.Text;
public class NativeOutputFixture {
    public static int Main(string[] args) {
        if (args[0] == "sleep") { System.Threading.Thread.Sleep(30000); return 0; }
        byte[] data = Encoding.Default.GetBytes("certreq: caf\u00e9 \u4e2d\u6587");
        using (var stdout = Console.OpenStandardOutput()) stdout.Write(data, 0, data.Length);
        using (var stderr = Console.OpenStandardError()) stderr.Write(data, 0, data.Length);
        return 37;
    }
}
'@
  $nativeResult = Invoke-CapturedProcess -Exe $fixtureExe -ArgList @("output") -TimeoutSeconds 5
  $expectedPipe = [Text.Encoding]::Default.GetString([Text.Encoding]::Default.GetBytes("certreq: caf$([char]0xe9) $([char]0x4e2d)$([char]0x6587)"))
  Assert-InstallTestEqual $nativeResult.Stdout $expectedPipe "raw stdout code-page capture"
  Assert-InstallTestEqual $nativeResult.Stderr $expectedPipe "raw stderr code-page capture"
  Assert-InstallTestEqual $nativeResult.ExitCode 37 "native exit is distinct from PowerShell exit"
  $watch = [Diagnostics.Stopwatch]::StartNew()
  $timedOut = $false
  try { [void](Invoke-CapturedProcess -Exe $fixtureExe -ArgList @("sleep") -TimeoutSeconds 1) }
  catch { $timedOut = $_.Exception.Message -match 'native process timed out' }
  Assert-InstallTest ($timedOut -and $watch.Elapsed.TotalSeconds -lt 10) "child timeout and termination are bounded"

  Ensure-BootstrapTlsValidatorType
  Ensure-TestCertificateProvider
  $newSelfSigned = Get-Command New-SelfSignedCertificate -ErrorAction SilentlyContinue
  if (-not $newSelfSigned) { throw "New-SelfSignedCertificate is required by the certificate validator behavior test" }
  $storePath = "Cert:\CurrentUser\My"
  $root = New-SelfSignedCertificate -Type Custom -Subject "CN=FDS Compatibility Test Root" -KeyAlgorithm RSA -KeyLength 2048 `
    -HashAlgorithm SHA256 -KeyUsage CertSign, CRLSign, DigitalSignature -TextExtension @("2.5.29.19={critical}{text}CA=true") `
    -CertStoreLocation $storePath -NotBefore (Get-Date).AddDays(-10)
  $server = New-SelfSignedCertificate -Type Custom -Subject "CN=server.example" -Signer $root -KeyAlgorithm RSA -KeyLength 2048 `
    -HashAlgorithm SHA256 -KeyUsage DigitalSignature, KeyEncipherment `
    -TextExtension @("2.5.29.17={text}DNS=server.example&IPAddress=127.0.0.1", "2.5.29.37={critical}{text}1.3.6.1.5.5.7.3.1") `
    -CertStoreLocation $storePath -NotAfter (Get-Date).AddDays(30)
  $wrongEku = New-SelfSignedCertificate -Type Custom -Subject "CN=wrong-eku.example" -Signer $root -KeyAlgorithm RSA -KeyLength 2048 `
    -HashAlgorithm SHA256 -KeyUsage DigitalSignature, KeyEncipherment `
    -TextExtension @("2.5.29.17={text}DNS=wrong-eku.example", "2.5.29.37={critical}{text}1.3.6.1.5.5.7.3.2") `
    -CertStoreLocation $storePath -NotAfter (Get-Date).AddDays(30)
  $expired = New-SelfSignedCertificate -Type Custom -Subject "CN=expired.example" -Signer $root -KeyAlgorithm RSA -KeyLength 2048 `
    -HashAlgorithm SHA256 -KeyUsage DigitalSignature, KeyEncipherment `
    -TextExtension @("2.5.29.17={text}DNS=expired.example", "2.5.29.37={critical}{text}1.3.6.1.5.5.7.3.1") `
    -CertStoreLocation $storePath -NotBefore (Get-Date).AddDays(-3) -NotAfter (Get-Date).AddDays(-1)
  $wrongIp = New-SelfSignedCertificate -Type Custom -Subject "CN=wrong-ip.example" -Signer $root -KeyAlgorithm RSA -KeyLength 2048 `
    -HashAlgorithm SHA256 -KeyUsage DigitalSignature, KeyEncipherment `
    -TextExtension @("2.5.29.17={text}DNS=wrong-ip.example", "2.5.29.37={critical}{text}1.3.6.1.5.5.7.3.1") `
    -CertStoreLocation $storePath -NotAfter (Get-Date).AddDays(30)
  $unrestricted = New-SelfSignedCertificate -Type Custom -Subject "CN=unrestricted.example" -Signer $root -KeyAlgorithm RSA -KeyLength 2048 `
    -HashAlgorithm SHA256 -KeyUsage DigitalSignature, KeyEncipherment -CertStoreLocation $storePath -NotAfter (Get-Date).AddDays(30)
  $intermediate = New-SelfSignedCertificate -Type Custom -Subject "CN=Restricted Intermediate" -Signer $root -KeyAlgorithm RSA -KeyLength 2048 `
    -HashAlgorithm SHA256 -KeyUsage CertSign, CRLSign -TextExtension @("2.5.29.19={critical}{text}CA=true", "2.5.29.37={text}1.3.6.1.5.5.7.3.2") -CertStoreLocation $storePath
  $restrictedLeaf = New-SelfSignedCertificate -Type Custom -Subject "CN=restricted.example" -Signer $intermediate -KeyAlgorithm RSA -KeyLength 2048 `
    -HashAlgorithm SHA256 -KeyUsage DigitalSignature -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.1") -CertStoreLocation $storePath -NotAfter (Get-Date).AddDays(30)
  [IO.File]::WriteAllText($caPath, (ConvertTo-Pem "CERTIFICATE" $root.RawData), [Text.Encoding]::ASCII)
  [IO.File]::WriteAllBytes($emptyCaPath, [byte[]]@())
  [IO.File]::WriteAllBytes($caBundlePath, [IO.File]::ReadAllBytes($caPath) + [IO.File]::ReadAllBytes($caPath))

  $singleCa = Read-PemCertificates -Path $caPath
  $multiCa = Read-PemCertificates -Path $caBundlePath
  $emptyCa = Read-PemCertificates -Path $emptyCaPath
  Assert-InstallTest ($singleCa -is [Array] -and $singleCa.Count -eq 1) "single PEM CA is returned as a stable one element array"
  Assert-InstallTest ($multiCa -is [Array] -and $multiCa.Count -eq 2) "multiple PEM CAs are returned as a stable array"
  Assert-InstallTest ($emptyCa -is [Array] -and $emptyCa.Count -eq 0) "empty PEM input is returned as an empty array"

  Enable-BootstrapTlsValidation -CaPath $caPath -LeafSha256 ""
  $request = [Net.WebRequest]::Create("https://server.example")
  $chainErrors = [Net.Security.SslPolicyErrors]::RemoteCertificateChainErrors
  $nameMismatch = [Net.Security.SslPolicyErrors]::RemoteCertificateNameMismatch
  Assert-InstallTest ([FdsBootstrapTlsValidator]::Validate($request, $server, $null, $chainErrors)) "trusted CA accepts a valid server certificate"
  Assert-InstallTest (-not [FdsBootstrapTlsValidator]::Validate($request, $server, $null, $nameMismatch)) "hostname mismatch is rejected"

  $rootThumbprint = ($root.Thumbprint -replace '\s+', '').ToUpperInvariant()
  [FdsBootstrapTlsValidator]::Configure([System.Security.Cryptography.X509Certificates.X509Certificate2[]]@($root), [string[]]@($rootThumbprint), [string[]]@("00" * 32))
  Assert-InstallTest ([FdsBootstrapTlsValidator]::Validate($request, $server, $null, $chainErrors)) "CA and pin policies retain OR semantics"
  $hash = [Security.Cryptography.SHA256]::Create()
  try { $serverPin = ([BitConverter]::ToString($hash.ComputeHash($server.RawData)) -replace '-', '').ToLowerInvariant() } finally { $hash.Dispose() }
  [FdsBootstrapTlsValidator]::Configure([System.Security.Cryptography.X509Certificates.X509Certificate2[]]@(), [string[]]@(), [string[]]@($serverPin))
  Assert-InstallTest ([FdsBootstrapTlsValidator]::Validate($request, $server, $null, $chainErrors)) "matching leaf pin is an independent trust anchor"
  Assert-InstallTest (-not [FdsBootstrapTlsValidator]::Validate($request, $server, $null, $nameMismatch)) "leaf pin does not bypass hostname validation"
  [FdsBootstrapTlsValidator]::Configure([System.Security.Cryptography.X509Certificates.X509Certificate2[]]@(), [string[]]@(), [string[]]@("11" * 32))
  Assert-InstallTest (-not [FdsBootstrapTlsValidator]::Validate($request, $server, $null, $chainErrors)) "mismatched leaf pin is rejected"
  [FdsBootstrapTlsValidator]::Configure([System.Security.Cryptography.X509Certificates.X509Certificate2[]]@($root), [string[]]@("00" * 32), [string[]]@())
  Assert-InstallTest (-not [FdsBootstrapTlsValidator]::Validate($request, $server, $null, $chainErrors)) "wrong CA rejects otherwise valid server"
  Enable-BootstrapTlsValidation -CaPath $caPath -LeafSha256 ""
  Assert-InstallTest (-not [FdsBootstrapTlsValidator]::Validate($request, $wrongEku, $null, $chainErrors)) "wrong EKU is rejected"
  Assert-InstallTestEqual ([FdsBootstrapTlsValidator]::LastFailure) "certificate_missing_server_auth_eku" "EKU is the failure reason"
  Assert-InstallTest (-not [FdsBootstrapTlsValidator]::Validate($request, $expired, $null, $chainErrors)) "expired certificate is rejected"
  Assert-InstallTestEqual ([FdsBootstrapTlsValidator]::LastFailure) "certificate_not_time_valid" "expiry is the failure reason"
  Assert-InstallTest ([FdsBootstrapTlsValidator]::Validate($request, $unrestricted, $null, $chainErrors)) "missing EKU remains unrestricted"
  $peerChain = New-Object Security.Cryptography.X509Certificates.X509Chain
  try {
    [void]$peerChain.ChainPolicy.ExtraStore.Add($intermediate)
    Assert-InstallTest (-not [FdsBootstrapTlsValidator]::Validate($request, $restrictedLeaf, $peerChain, $chainErrors)) "intermediate client-only EKU restricts server leaf"
    Assert-InstallTest ([FdsBootstrapTlsValidator]::LastFailure -match 'NotValidForUsage') "intermediate EKU is the failure reason"
  } finally { $peerChain.Dispose() }
  $emptyCertificate = New-Object Security.Cryptography.X509Certificates.X509Certificate2
  try {
    Assert-InstallTest (-not [FdsBootstrapTlsValidator]::Validate($request, $emptyCertificate, $null, [Net.Security.SslPolicyErrors]::None)) "validation exception fails closed"
    Assert-InstallTest ([FdsBootstrapTlsValidator]::LastFailure -match '^validator_exception:') "exception diagnostic is retained"
  } finally { $emptyCertificate.Dispose() }

  # Actual Invoke-RestMethod -> Schannel -> CLR delegate callbacks over TLS1.2.
  Add-Type -Path (Join-Path $RepositoryRoot "tests\windows_install_tls_fixture.cs")
  foreach ($usePin in @($false, $true)) {
    if ($usePin) { Enable-BootstrapTlsValidation -CaPath "" -LeafSha256 $serverPin }
    else { Enable-BootstrapTlsValidation -CaPath $caPath -LeafSha256 "" }
    $listener = New-Object InstallTlsFixture -ArgumentList $server
    $clientFailure = $null
    $disposeFailure = $null
    try {
      try {
        $response = Invoke-RestMethod -Uri ("https://127.0.0.1:{0}/tls-test" -f $listener.Port) -Method Get -TimeoutSec 8 -Proxy $null
        Assert-InstallTest ($response.ok -eq $true) "real TLS1.2 GET with pin=$usePin (transport only, not enrollment POST)"
      } catch { $clientFailure = $_ }
    } finally {
      try { $listener.Dispose() } catch { $disposeFailure = $_ }
    }
    if ($clientFailure -or $disposeFailure -or $listener.Error) {
      $clientMessage = if ($clientFailure) { [string]$clientFailure.Exception.Message } else { "none" }
      $disposeMessage = if ($disposeFailure) { [string]$disposeFailure.Exception.Message } else { "none" }
      $serverMessage = if ($listener.Error) { [string]$listener.Error } else { "none" }
      throw ("TLS fixture failed for pin={0}; client={1}; server={2}; dispose={3}" -f $usePin, $clientMessage, $serverMessage, $disposeMessage)
    }
  }
  $hash = [Security.Cryptography.SHA256]::Create()
  try { $wrongIpPin = ([BitConverter]::ToString($hash.ComputeHash($wrongIp.RawData)) -replace '-', '').ToLowerInvariant() } finally { $hash.Dispose() }
  foreach ($usePin in @($false, $true)) {
    if ($usePin) { Enable-BootstrapTlsValidation -CaPath "" -LeafSha256 $wrongIpPin }
    else { Enable-BootstrapTlsValidation -CaPath $caPath -LeafSha256 "" }
    $listener = New-Object InstallTlsFixture -ArgumentList $wrongIp
    $disposeFailure = $null
    try {
      $rejected = $false
      try { [void](Invoke-RestMethod -Uri ("https://127.0.0.1:{0}" -f $listener.Port) -TimeoutSec 8 -Proxy $null) }
      catch { $rejected = $true }
    } finally {
      try { $listener.Dispose() } catch { $disposeFailure = $_ }
    }
    Assert-InstallTest $rejected "actual mismatched IP SAN TLS connection is rejected with pin=$usePin"
    Assert-InstallTest ([FdsBootstrapTlsValidator]::LastFailure -match 'certificate_name_mismatch') "Schannel supplied identity mismatch"
    if ($disposeFailure) { throw ("TLS fixture disposal failed for mismatched IP, pin={0}: {1}" -f $usePin, $disposeFailure.Exception.Message) }
  }

  $invalidPinFailed = $false
  try { Enable-BootstrapTlsValidation -CaPath $caPath -LeafSha256 "invalid-pin" } catch { $invalidPinFailed = $true }
  Assert-InstallTest $invalidPinFailed "invalid bootstrap pin is rejected before HTTP"
  . (Join-Path $RepositoryRoot "tests\test_windows_install_cng_behavior.ps1")
  Write-Host "Windows install compatibility behavior test passed under Windows PowerShell 5.1."
} catch {
  $primaryError = $_
} finally {
  [Net.ServicePointManager]::SecurityProtocol = $oldTls
  [Net.ServicePointManager]::ServerCertificateValidationCallback = $oldCallback
  $cleanupErrors = New-Object 'System.Collections.Generic.List[string]'
  foreach ($certificate in @($restrictedLeaf, $intermediate, $unrestricted, $expired, $wrongIp, $wrongEku, $server, $root)) {
    if ($certificate -and $certificate.Thumbprint) {
      try { Remove-Item -LiteralPath ("Cert:\CurrentUser\My\" + $certificate.Thumbprint) -DeleteKey -Force -ErrorAction Stop }
      catch { $cleanupErrors.Add($_.Exception.Message) }
      finally { $certificate.Dispose() }
    }
  }
  Remove-Item -LiteralPath $diagnosticRoot -Recurse -Force -ErrorAction SilentlyContinue
  if ($null -eq $oldDiagnosticRoot) { Remove-Item Env:\EDR_INSTALL_DIAGNOSTICS_DIR -ErrorAction SilentlyContinue }
  else { $env:EDR_INSTALL_DIAGNOSTICS_DIR = $oldDiagnosticRoot }
  if ($cleanupErrors.Count -gt 0) {
    $cleanupFailure = "Test certificate cleanup failed: " + ($cleanupErrors -join '; ')
  }
}
if ($primaryError) {
  $primaryMessage = [string]$primaryError.Exception.Message
  if ($cleanupFailure) {
    throw ("Windows install compatibility test failed: {0}; cleanup also failed: {1}" -f $primaryMessage, $cleanupFailure)
  }
  throw $primaryError
}
if ($cleanupFailure) { throw $cleanupFailure }
