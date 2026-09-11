#Requires -Version 5.1
# Dot-sourced by test_windows_install_compatibility.ps1 after loading installer
# functions. Uses only uniquely named test-owned machine keys; no service work.
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw "CNG installer behavior tests require an elevated Windows PowerShell 5.1 process"
}
$testProviderName = "Microsoft Software Key Storage Provider"
$testProvider = New-Object Security.Cryptography.CngProvider($testProviderName)
$machineKey = [Security.Cryptography.CngKeyOpenOptions]::MachineKey
$ownedTestKeys = New-Object 'System.Collections.Generic.List[string]'
$ownedPublicKeys = New-Object 'System.Collections.Generic.HashSet[string]'
$savedCompatibility = $script:EDR_INSTALL_COMPATIBILITY
$cngPrimaryError = $null
$cngCleanupFailure = $null

$newKeyInf = New-CngCertreqInfText -SubjectCN "compat-new" -ProviderName $testProviderName `
  -KeyName "FDS-Compat-New" -UseExistingKeySet $false
Assert-InstallTest ($newKeyInf -match '(?m)^KeyLength = 3072\r?$') "new certreq key requires 3072 bits"
Assert-InstallTest ($newKeyInf -match '(?m)^Exportable = FALSE\r?$') "new certreq key is non-exportable"
Assert-InstallTest (-not ($newKeyInf -match '(?m)^UseExistingKeySet\s*=')) "new certreq key does not request reuse"
$existingKeyInf = New-CngCertreqInfText -SubjectCN "compat-existing" -ProviderName $testProviderName `
  -KeyName "FDS-Compat-Existing" -UseExistingKeySet $true
Assert-InstallTest ($existingKeyInf -match '(?m)^UseExistingKeySet = TRUE\r?$') "existing certreq key explicitly requests reuse"
Assert-InstallTest (-not ($existingKeyInf -match '(?m)^KeyLength\s*=')) "existing certreq key length is not changed"
Assert-InstallTest (-not ($existingKeyInf -match '(?m)^Exportable\s*=')) "existing certreq key exportability is not changed"

function Get-TestRsaPublicIdentity {
  param([Security.Cryptography.RSA]$Rsa)
  $public = $Rsa.ExportParameters($false)
  return ([Convert]::ToBase64String($public.Modulus) + ":" + [Convert]::ToBase64String($public.Exponent))
}
function Remember-TestKeyPublicIdentity {
  param([string]$KeyName)
  if (-not $ownedTestKeys.Contains($KeyName)) { throw "refusing to track an unowned test key" }
  if (-not [Security.Cryptography.CngKey]::Exists($KeyName, $testProvider, $machineKey)) { return }
  $trackedKey = [Security.Cryptography.CngKey]::Open($KeyName, $testProvider, $machineKey)
  $trackedRsa = $null
  try {
    $trackedRsa = New-Object Security.Cryptography.RSACng($trackedKey)
    [void]$ownedPublicKeys.Add((Get-TestRsaPublicIdentity $trackedRsa))
  } finally {
    if ($trackedRsa) { $trackedRsa.Dispose() }
    $trackedKey.Dispose()
  }
}
function Reset-TestEnrollmentTransaction {
  $script:EDR_INSTALL_TRANSACTION_ACTIVE = $true
  $script:EDR_INSTALL_TRANSACTION_COMMITTED = $false
  $script:EDR_CNG_KEY_CONTAINER = ""
  $script:EDR_CNG_KEY_CREATED_BY_INSTALL = $false
  $script:EDR_CNG_PROVIDER_USED = $testProviderName
  $script:EDR_PROVISIONAL_CERT_THUMBPRINT = ""
  $script:EDR_PROVISIONAL_CERT_PREEXISTED = $false
}
function Read-TestRollback {
  return (Get-Content -Raw -LiteralPath (Join-Path $diagnosticRoot "install-enrollment-rollback-last.json") | ConvertFrom-Json)
}
try {
  foreach ($native in @($true, $false)) {
    $script:EDR_INSTALL_COMPATIBILITY = Get-WindowsInstallCompatibilitySnapshot
    if ($native -and -not ($script:EDR_INSTALL_COMPATIBILITY.capabilities.certificate_request -and
        $script:EDR_INSTALL_COMPATIBILITY.capabilities.copy_with_private_key)) {
      Write-Host "SKIP: native CSR APIs absent on this runtime; real certreq branch remains mandatory."
      continue
    }
    $script:EDR_INSTALL_COMPATIBILITY.capabilities.certificate_request = $native
    $script:EDR_INSTALL_COMPATIBILITY.capabilities.copy_with_private_key = $native
    Reset-TestEnrollmentTransaction
    try {
      $csrPath = Join-Path $diagnosticRoot ("cng-" + $native + ".csr")
      $csr = & {
        function Invoke-Checked {
          param([string]$Exe, [string[]]$ArgList, [int]$TimeoutSeconds)
          Assert-InstallTest (-not $native) "available native CSR must not fall back to certreq"
          $result = Invoke-CapturedProcess -Exe $Exe -ArgList $ArgList -TimeoutSeconds $TimeoutSeconds
          Assert-InstallTestEqual $result.ExitCode 0 "actual certreq CSR exit code"
        }
        Ensure-CngAgentCSR -CsrPath $csrPath -SubjectCN "compat-test" -ProviderName $testProviderName
      }
      Assert-InstallTest ($csr -match 'BEGIN (NEW )?CERTIFICATE REQUEST') "actual CSR native=$native"
      Assert-InstallTest $script:EDR_CNG_KEY_CREATED_BY_INSTALL "new key belongs to transaction native=$native"
      $key = [Security.Cryptography.CngKey]::Open($script:EDR_CNG_KEY_CONTAINER, $testProvider, $machineKey)
      try {
        Assert-InstallTest $key.IsMachineKey "CSR uses machine key"
        Assert-InstallTestEqual ([int]$key.ExportPolicy) 0 "CSR key is not exportable"
        Assert-InstallTestEqual $key.Provider.Provider $testProviderName "CSR retains requested KSP"
      } finally { $key.Dispose() }
      # Simulate the enrollment failure boundary after a real successful CSR.
      # This tests rollback, not a full enrollment network request.
    } finally {
      if ($script:EDR_CNG_KEY_CREATED_BY_INSTALL -and $script:EDR_CNG_KEY_CONTAINER) {
        $ownedTestKeys.Add($script:EDR_CNG_KEY_CONTAINER)
        Remember-TestKeyPublicIdentity $script:EDR_CNG_KEY_CONTAINER
      }
      Remove-ProvisionalEnrollmentMaterial -Reason "test: enrollment SecureChannelFailure after CSR"
    }
    Assert-InstallTest (-not [Security.Cryptography.CngKey]::Exists($script:EDR_CNG_KEY_CONTAINER, $testProvider, $machineKey)) "actual rollback removes native/certreq key"
    $receipt = Read-TestRollback
    Assert-InstallTestEqual $receipt.status "succeeded" "successful rollback receipt"
    Assert-InstallTest $receipt.cng_key_removed "receipt confirms actual key removal"
  }

  # Caller-owned key: certreq must reuse it, and rollback must not delete it.
  $existingName = "FDS-Compat-Existing-" + [guid]::NewGuid().ToString("N")
  $creation = New-Object Security.Cryptography.CngKeyCreationParameters
  $creation.Provider = $testProvider
  $creation.KeyCreationOptions = [Security.Cryptography.CngKeyCreationOptions]::MachineKey
  $creation.ExportPolicy = [Security.Cryptography.CngExportPolicies]::None
  $creation.Parameters.Add((New-Object Security.Cryptography.CngProperty("Length", [BitConverter]::GetBytes(3072), [Security.Cryptography.CngPropertyOptions]::None)))
  $key = [Security.Cryptography.CngKey]::Create([Security.Cryptography.CngAlgorithm]::Rsa, $existingName, $creation)
  $ownedTestKeys.Add($existingName)
  $existingUniqueName = $key.UniqueName
  $key.Dispose()
  Remember-TestKeyPublicIdentity $existingName
  Reset-TestEnrollmentTransaction
  [void](Ensure-CngAgentCSR -CsrPath (Join-Path $diagnosticRoot "existing.csr") -SubjectCN "compat-existing" -ProviderName $testProviderName -KeyName $existingName)
  Assert-InstallTest (-not $script:EDR_CNG_KEY_CREATED_BY_INSTALL) "explicit existing key stays caller-owned"
  $key = [Security.Cryptography.CngKey]::Open($existingName, $testProvider, $machineKey)
  try { Assert-InstallTestEqual $key.UniqueName $existingUniqueName "certreq reused the same underlying existing key" }
  finally { $key.Dispose() }
  Remove-ProvisionalEnrollmentMaterial -Reason "test: existing key"
  Assert-InstallTest ([Security.Cryptography.CngKey]::Exists($existingName, $testProvider, $machineKey)) "rollback preserves caller-owned key"
  Assert-InstallTest (-not (Read-TestRollback).cng_key_removed) "receipt does not claim existing key removed"
  $missingName = "FDS-Compat-Missing-" + [guid]::NewGuid().ToString("N")
  $failed = $false
  try { [void](Ensure-CngAgentCSR -CsrPath (Join-Path $diagnosticRoot "missing.csr") -SubjectCN "compat-missing" -ProviderName $testProviderName -KeyName $missingName) }
  catch { $failed = $_.Exception.Message -match 'will not be replaced by certreq' }
  Assert-InstallTest $failed "explicit nonexistent key fails before certreq"
  Assert-InstallTest (-not [Security.Cryptography.CngKey]::Exists($missingName, $testProvider, $machineKey)) "missing caller key is not created"
  foreach ($field in @("KeyName", "ProviderName")) {
    $arguments = @{ CsrPath = (Join-Path $diagnosticRoot "injection.csr"); SubjectCN = "compat"; ProviderName = $testProviderName }
    $arguments[$field] = "bad" + [char]10 + "Injected=TRUE"
    $failed = $false
    try { [void](Ensure-CngAgentCSR @arguments) } catch { $failed = $_.Exception.Message -match 'control character' }
    Assert-InstallTest $failed "$field cannot inject an INF line"
  }

  # Fault injection after real certreq created a key: ownership must already be
  # recorded, even if the native wrapper then reports timeout/failure.
  & {
    function Invoke-Checked {
      param([string]$Exe, [string[]]$ArgList, [int]$TimeoutSeconds)
      $result = Invoke-CapturedProcess -Exe $Exe -ArgList $ArgList -TimeoutSeconds $TimeoutSeconds
      Assert-InstallTestEqual $result.ExitCode 0 "fault fixture actually created certreq CSR"
      throw "test: native process timed out after key creation"
    }
    Reset-TestEnrollmentTransaction
    try {
      $failed = $false
      try { [void](Ensure-CngAgentCSR -CsrPath (Join-Path $diagnosticRoot "partial.csr") -SubjectCN "compat-partial" -ProviderName $testProviderName) }
      catch { $failed = $_.Exception.Message -match 'test: native process timed out' }
      Assert-InstallTest $failed "partial certreq failure is propagated"
      Assert-InstallTest $script:EDR_CNG_KEY_CREATED_BY_INSTALL "partial certreq key is still transaction-owned"
    } finally {
      if ($script:EDR_CNG_KEY_CREATED_BY_INSTALL) {
        $ownedTestKeys.Add($script:EDR_CNG_KEY_CONTAINER)
        Remember-TestKeyPublicIdentity $script:EDR_CNG_KEY_CONTAINER
      }
      Remove-ProvisionalEnrollmentMaterial -Reason "test: injected partial certreq timeout"
    }
    Assert-InstallTest (-not [Security.Cryptography.CngKey]::Exists($script:EDR_CNG_KEY_CONTAINER, $testProvider, $machineKey)) "partial certreq key is recovered"
  }

  # Exact rollback argument/budget contract plus failure receipt behavior.
  foreach ($timeout in @($false, $true)) {
    & {
      function Invoke-CapturedProcess {
        param([string]$Exe, [string[]]$ArgList, [int]$TimeoutSeconds)
        Assert-InstallTestEqual ([IO.Path]::GetFileName($Exe)) "certutil.exe" "rollback executable"
        Assert-InstallTestEqual ($ArgList -join '|') ("-csp|$testProviderName|-delkey|$existingName") "rollback exact arguments"
        Assert-InstallTestEqual $TimeoutSeconds 30 "rollback bounded timeout"
        if ($timeout) { throw "test: native process timed out" }
        return @{ ExitCode = 5; Stdout = ""; Stderr = "test access denied" }
      }
      Reset-TestEnrollmentTransaction
      # Only a fixture-owned key is marked here; the previous assertion already
      # proved normal caller-owned behavior. The mock never deletes anything.
      $script:EDR_CNG_KEY_CONTAINER = $existingName
      $script:EDR_CNG_KEY_CREATED_BY_INSTALL = $true
      Remove-ProvisionalEnrollmentMaterial -Reason "test: cleanup failure"
      $receipt = Read-TestRollback
      Assert-InstallTestEqual $receipt.status "partial_failed" "cleanup failure cannot claim success"
      Assert-InstallTest (-not $receipt.cng_key_removed) "failed removal is reported accurately"
      $expected = if ($timeout) { 'timed out' } else { 'exit=5' }
      Assert-InstallTest (($receipt.errors -join ' ') -match $expected) "numeric native error/timeout preserved"
    }
  }
  Write-Host "CNG actual CSR/key rollback and injected failure contracts passed."
} catch {
  $cngPrimaryError = $_
} finally {
  $keyCleanupErrors = New-Object 'System.Collections.Generic.List[string]'
  # certreq may leave pending REQUEST certificates after CSR/failed enrollment.
  # Match the complete RSA public key of a unique fixture-owned machine key,
  # never a subject/CN, and never clear the store. Public identities were saved
  # before production rollback deleted the private keys.
  $pendingStore = $null
  try {
    $pendingStore = New-Object Security.Cryptography.X509Certificates.X509Store -ArgumentList @(
      "REQUEST", [Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
    $openFlags = [Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite -bor
      [Security.Cryptography.X509Certificates.OpenFlags]::OpenExistingOnly
    $pendingStore.Open($openFlags)
    foreach ($pending in @($pendingStore.Certificates)) {
      $publicRsa = $null
      try {
        $publicRsa = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($pending)
        if ($publicRsa -and $ownedPublicKeys.Contains((Get-TestRsaPublicIdentity $publicRsa))) {
          $thumbprint = $pending.Thumbprint
          $pendingStore.Remove($pending)
          $remaining = $pendingStore.Certificates.Find(
            [Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint, $thumbprint, $false)
          try {
            if ($remaining.Count -ne 0) { throw "test-owned pending request remains: $thumbprint" }
          } finally {
            foreach ($remainingCertificate in @($remaining)) { $remainingCertificate.Dispose() }
          }
        }
      } catch { $keyCleanupErrors.Add("pending request: $($_.Exception.Message)") }
      finally {
        if ($publicRsa) { $publicRsa.Dispose() }
        $pending.Dispose()
      }
    }
  } catch { $keyCleanupErrors.Add("pending REQUEST store: $($_.Exception.Message)") }
  finally {
    if ($pendingStore) { $pendingStore.Close() }
  }
  foreach ($keyName in $ownedTestKeys) {
    $key = $null
    try {
      if ([Security.Cryptography.CngKey]::Exists($keyName, $testProvider, $machineKey)) {
        $key = [Security.Cryptography.CngKey]::Open($keyName, $testProvider, $machineKey)
        $key.Delete()
      }
    } catch { $keyCleanupErrors.Add("$keyName : $($_.Exception.Message)") }
    finally { if ($key) { $key.Dispose() } }
  }
  $script:EDR_INSTALL_COMPATIBILITY = $savedCompatibility
  $script:EDR_INSTALL_TRANSACTION_ACTIVE = $false
  if ($keyCleanupErrors.Count -gt 0) {
    $cngCleanupFailure = "CNG test-owned key cleanup failed: " + ($keyCleanupErrors -join '; ')
  }
}
if ($cngPrimaryError) {
  $primaryMessage = [string]$cngPrimaryError.Exception.Message
  if ($cngCleanupFailure) {
    throw ("CNG compatibility test failed: {0}; cleanup also failed: {1}" -f $primaryMessage, $cngCleanupFailure)
  }
  throw $cngPrimaryError
}
if ($cngCleanupFailure) { throw $cngCleanupFailure }
