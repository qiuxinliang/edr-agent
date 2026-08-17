#Requires -Version 5.1
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$BaselinePackageDir,
  [Parameter(Mandatory = $true)][string]$TargetPackageDir,
  [Parameter(Mandatory = $true)][string]$BaselineVersion,
  [Parameter(Mandatory = $true)][string]$TargetVersion,
  [Parameter(Mandatory = $true)][ValidateSet("amd64", "arm64")][string]$Architecture,
  [Parameter(Mandatory = $true)][string]$EvidenceDir
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$installDir = "C:\edr-agent-lifecycle-smoke"
$serviceName = "FDSecurityAgentCISmoke"
$configPath = Join-Path $installDir "agent.toml"
$programDataState = Join-Path $env:ProgramData "FDSecurity\state"
$programDataLogs = Join-Path $env:ProgramData "FDSecurity\logs"
$expectedUpdateArchitecture = if ($Architecture -eq "arm64") { "arm64" } else { "x64" }

function Find-OneFile {
  param([string]$Root, [string]$Name)
  $matches = @(Get-ChildItem -LiteralPath $Root -Recurse -File -Filter $Name)
  if ($matches.Count -ne 1) {
    throw "expected exactly one $Name under $Root; found $($matches.Count)"
  }
  return $matches[0].FullName
}

function Assert-Administrator {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($identity)
  if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Windows lifecycle smoke requires an elevated runner"
  }
}

function Get-AgentVersion {
  param([string]$Path)
  $value = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($Path).ProductVersion
  if ($value) {
    $value = ($value -split '[ +]')[0].Trim()
    if ($value -match '^((?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*))(?:\.0)?$') {
      $value = [string]$Matches[1]
    }
  }
  return $value
}

function Get-Publisher {
  param([string]$Path)
  $signature = Get-AuthenticodeSignature -LiteralPath $Path
  if ($signature.Status -eq [System.Management.Automation.SignatureStatus]::Valid -and $signature.SignerCertificate) {
    return @{
      Thumbprint = ($signature.SignerCertificate.Thumbprint -replace '\s','').ToUpperInvariant()
      Subject = $signature.SignerCertificate.Subject
    }
  }
  return @{
    Thumbprint = "SHA256_ONLY_UNSIGNED"
    Subject = "Unsigned release; SHA-256 integrity only"
  }
}

function Get-TextSha256 {
  param([Parameter(Mandatory = $true)][string]$Value)
  $sha = [Security.Cryptography.SHA256]::Create()
  try {
    $digest = [BitConverter]::ToString(
      $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value)))
    return $digest.Replace("-", "").ToLowerInvariant()
  } finally {
    $sha.Dispose()
  }
}

function Get-UninstallAttestationProof {
  param(
    [Parameter(Mandatory = $true)][string]$Token,
    [Parameter(Mandatory = $true)][string]$TaskID,
    [Parameter(Mandatory = $true)][string]$EndpointID
  )
  $key = [Text.Encoding]::UTF8.GetBytes($Token)
  $message = [Text.Encoding]::UTF8.GetBytes(
    "edr.endpoint.uninstall.attestation.v1`n$TaskID`n$EndpointID")
  $hmac = New-Object Security.Cryptography.HMACSHA256 -ArgumentList (,$key)
  try {
    $proof = [BitConverter]::ToString($hmac.ComputeHash($message))
    return $proof.Replace("-", "").ToLowerInvariant()
  } finally {
    $hmac.Dispose()
  }
}

function Wait-ServiceStable {
  param([int]$Seconds = 10)
  Start-Service -Name $serviceName
  for ($i = 0; $i -lt $Seconds; $i++) {
    Start-Sleep -Seconds 1
    $service = Get-CimInstance Win32_Service -Filter ("Name='{0}'" -f $serviceName) -ErrorAction Stop
    if ($service.State -ne "Running") {
      throw "service $serviceName stopped during stability window: $($service.State)"
    }
  }
}

function Wait-ServiceDeleted {
  param([int]$Seconds = 20)
  for ($i = 0; $i -lt $Seconds; $i++) {
    if (-not (Get-CimInstance Win32_Service -Filter ("Name='{0}'" -f $serviceName) -ErrorAction SilentlyContinue)) {
      return
    }
    Start-Sleep -Seconds 1
  }
  & sc.exe queryex $serviceName 2>&1 | Out-Host
  Get-CimInstance Win32_Service -Filter ("Name='{0}'" -f $serviceName) -ErrorAction SilentlyContinue |
    Format-List Name, State, Status, ProcessId, StartMode | Out-Host
  throw "service $serviceName still exists after waiting $Seconds seconds for deletion"
}

function Wait-ProcessDeleted {
  param([int]$ProcessId, [int]$Seconds = 20)
  if ($ProcessId -le 0) { throw "Agent service did not expose a process id before uninstall" }
  for ($i = 0; $i -lt $Seconds; $i++) {
    if (-not (Get-Process -Id $ProcessId -ErrorAction SilentlyContinue)) {
      return
    }
    Start-Sleep -Seconds 1
  }
  throw "Agent process still exists after waiting $Seconds seconds"
}

function Wait-InstallDirectoryDeleted {
  param([int]$Seconds = 120)
  for ($i = 0; $i -lt $Seconds; $i++) {
    if (-not (Test-Path -LiteralPath $installDir)) { return }
    Start-Sleep -Seconds 1
  }
  throw "install directory still exists after waiting $Seconds seconds: $installDir"
}

function Wait-CleanupReceipt {
  param([string]$Path, [int]$Seconds = 120)
  for ($i = 0; $i -lt $Seconds; $i++) {
    if (Test-Path -LiteralPath $Path -PathType Leaf) { return }
    Start-Sleep -Seconds 1
  }
  throw "deferred uninstall cleanup did not write its receipt within $Seconds seconds"
}

function Wait-AttestationListenerReady {
  param(
    [string]$Path,
    [System.Management.Automation.Job]$Job,
    [int]$Seconds = 15
  )
  $pollCount = $Seconds * 4
  for ($i = 0; $i -lt $pollCount; $i++) {
    if (Test-Path -LiteralPath $Path -PathType Leaf) { return }
    if ($Job.State -eq "Failed" -or $Job.State -eq "Stopped" -or $Job.State -eq "Completed") {
      $reason = ""
      if ($Job.ChildJobs.Count -gt 0 -and $Job.ChildJobs[0].JobStateInfo.Reason) {
        $reason = $Job.ChildJobs[0].JobStateInfo.Reason.Message
      }
      $output = ((Receive-Job -Job $Job -Keep -ErrorAction SilentlyContinue | Out-String).Trim())
      throw "uninstall attestation listener stopped before becoming ready: state=$($Job.State) reason=$reason output=$output"
    }
    Start-Sleep -Milliseconds 250
  }
  throw "uninstall attestation listener did not become ready within $Seconds seconds"
}

function Wait-EmbeddedUpdaterMaterialized {
  param(
    [string]$Version,
    [string]$ExpectedScript,
    [int]$Seconds = 45
  )
  $materialized = Join-Path $installDir ("edr_agent_inplace_update-{0}.ps1" -f $Version)
  $expectedHash = (Get-FileHash -LiteralPath $ExpectedScript -Algorithm SHA256).Hash
  for ($i = 0; $i -lt $Seconds; $i++) {
    if (Test-Path -LiteralPath $materialized -PathType Leaf) {
      $actualHash = (Get-FileHash -LiteralPath $materialized -Algorithm SHA256).Hash
      if ($actualHash -eq $expectedHash) { return $actualHash.ToLowerInvariant() }
      throw "materialized embedded updater hash mismatch: expected=$expectedHash actual=$actualHash"
    }
    Start-Sleep -Seconds 1
  }
  throw "target Agent did not materialize its embedded updater within $Seconds seconds: $materialized"
}

function Invoke-VersionTransition {
  param(
    [ValidateSet("upgrade", "rollback")][string]$Operation,
    [string]$Candidate,
    [string]$Version,
    [string]$ArtifactID,
    [string]$UpdateScript
  )
  $staged = Join-Path $installDir "FDSensor.next.exe"
  Copy-Item -LiteralPath $Candidate -Destination $staged -Force
  $publisher = Get-Publisher -Path $Candidate
  $issued = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
  $deadline = $issued + 900000
  & $UpdateScript `
    -InstallDir $installDir `
    -StagedBinary $staged `
    -ExpectedSha256 ((Get-FileHash -LiteralPath $Candidate -Algorithm SHA256).Hash) `
    -TargetVersion $Version `
    -ExpectedArchitecture $expectedUpdateArchitecture `
    -TrustedPublisherThumbprint $publisher.Thumbprint `
    -TrustedPublisherSubject $publisher.Subject `
    -DeploymentMode service `
    -ServiceName $serviceName `
    -CommandId ("ci-{0}-{1}" -f $Operation, $Version) `
    -TaskId ([Guid]::NewGuid().ToString("N")) `
    -Operation $Operation `
    -ArtifactId $ArtifactID `
    -UpgradeClass binary_hot `
    -IssuedAtUnixMs $issued `
    -DeadlineUnixMs $deadline `
    -HealthObserveMs 1000 `
    -DrainDelaySeconds 0 `
    -StartupTimeoutSeconds 45
  if ($LASTEXITCODE -ne 0) {
    throw "$Operation script failed with exit code $LASTEXITCODE"
  }
  $installedVersion = Get-AgentVersion -Path (Join-Path $installDir "FDSensor.exe")
  if ($installedVersion -ne $Version) {
    throw "$Operation version mismatch: expected=$Version actual=$installedVersion"
  }
  if ((Get-CimInstance Win32_Service -Filter ("Name='{0}'" -f $serviceName) -ErrorAction Stop).State -ne "Running") {
    throw "$Operation left service non-running"
  }
}

$EvidenceDir = [IO.Path]::GetFullPath($EvidenceDir)
New-Item -ItemType Directory -Path $EvidenceDir -Force | Out-Null
Assert-Administrator
$syntaxValidator = Join-Path $PSScriptRoot "validate_windows_powershell_syntax.ps1"
& $syntaxValidator -RepositoryRoot (Split-Path -Parent $PSScriptRoot)

$baselineBinary = Find-OneFile -Root $BaselinePackageDir -Name "FDSensor.exe"
$targetBinary = Find-OneFile -Root $TargetPackageDir -Name "FDSensor.exe"
$baselineRoot = Split-Path -Parent $baselineBinary
$targetRoot = Split-Path -Parent $targetBinary
$targetInstaller = Find-OneFile -Root $TargetPackageDir -Name "windows_service_install.ps1"
$targetUpdater = Find-OneFile -Root $TargetPackageDir -Name "edr_agent_inplace_update.ps1"
$targetLifecycleWorker = Find-OneFile -Root $TargetPackageDir -Name "FDSecurityInstallerWorker.exe"
$targetUninstaller = Find-OneFile -Root $TargetPackageDir -Name "uninstall.exe"
$targetUninstallScript = Find-OneFile -Root $TargetPackageDir -Name "uninstall.ps1"
$targetNativeIntegrity = Find-OneFile -Root $TargetPackageDir -Name "native-package-integrity.json"
$baselineTemplate = Find-OneFile -Root $BaselinePackageDir -Name "agent_windows_production.example.toml"
$sourceInstaller = Join-Path $PSScriptRoot "windows_service_install.ps1"
$sourceUninstallScript = Join-Path $PSScriptRoot "edr_agent_uninstall.ps1"

if (-not (Test-Path -LiteralPath $sourceInstaller)) {
  throw "current windows_service_install.ps1 is missing from the checked-out repository"
}
if (-not (Test-Path -LiteralPath $sourceUninstallScript)) {
  throw "current edr_agent_uninstall.ps1 is missing from the checked-out repository"
}
$targetInstallerHash = (Get-FileHash -LiteralPath $targetInstaller -Algorithm SHA256).Hash
$sourceInstallerHash = (Get-FileHash -LiteralPath $sourceInstaller -Algorithm SHA256).Hash
if ($targetInstallerHash -ne $sourceInstallerHash) {
  throw "target package service installer hash mismatch"
}
$targetUninstallScriptHash = (Get-FileHash -LiteralPath $targetUninstallScript -Algorithm SHA256).Hash
$sourceUninstallScriptHash = (Get-FileHash -LiteralPath $sourceUninstallScript -Algorithm SHA256).Hash
if ($targetUninstallScriptHash -ne $sourceUninstallScriptHash) {
  throw "target package uninstall script hash mismatch"
}
$nativeIntegrity = Get-Content -LiteralPath $targetNativeIntegrity -Raw | ConvertFrom-Json
if ($nativeIntegrity.schema -ne "edr.windows.native-package-integrity.v1") {
  throw "target package native integrity manifest schema mismatch"
}
foreach ($component in @(
    @{ Name = "FDSecurityInstallerWorker.exe"; Path = $targetLifecycleWorker },
    @{ Name = "uninstall.exe"; Path = $targetUninstaller },
    @{ Name = "uninstall.ps1"; Path = $targetUninstallScript }
  )) {
  $entry = @($nativeIntegrity.files | Where-Object { $_.name -eq $component.Name })
  if ($entry.Count -ne 1) {
    throw "target package native integrity manifest is missing $($component.Name)"
  }
  $actualHash = (Get-FileHash -LiteralPath $component.Path -Algorithm SHA256).Hash.ToLowerInvariant()
  $expectedHash = ([string]($entry[0].sha256)).ToLowerInvariant()
  if ($expectedHash -cne $actualHash) {
    throw "target package native integrity hash mismatch for $($component.Name)"
  }
}
$workerProbe = Join-Path $EvidenceDir "installer-worker-capabilities.json"
$uninstallerProbe = Join-Path $EvidenceDir "headless-uninstaller-capabilities.json"
$capabilityProbeRunner = Join-Path $PSScriptRoot "invoke_windows_native_capability_probe.ps1"
$workerCapabilities = & $capabilityProbeRunner `
  -ExecutablePath $targetLifecycleWorker `
  -ProbePath $workerProbe `
  -ComponentName "target installer worker"
$uninstallerCapabilities = & $capabilityProbeRunner `
  -ExecutablePath $targetUninstaller `
  -ProbePath $uninstallerProbe `
  -ComponentName "target headless uninstaller"
if ($workerCapabilities.uninstall_attestation -ne "v2" -or
    $workerCapabilities.token_handoff -ne $true) {
  throw "target installer worker lacks uninstall attestation v2 token handoff"
}
if ($uninstallerCapabilities.uninstall_attestation -ne "v2" -or
    $uninstallerCapabilities.powershell_token_handoff -ne $true) {
  throw "target headless uninstaller lacks uninstall attestation v2 PowerShell handoff"
}

if ((Get-AgentVersion -Path $baselineBinary) -ne $BaselineVersion) {
  throw "baseline binary ProductVersion does not match $BaselineVersion"
}
if ((Get-AgentVersion -Path $targetBinary) -ne $TargetVersion) {
  throw "target binary ProductVersion does not match $TargetVersion"
}

$stage = "prepare"
$attestationJob = $null
try {
  $existing = Get-CimInstance Win32_Service -Filter ("Name='{0}'" -f $serviceName) -ErrorAction SilentlyContinue
  if ($existing) {
    Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
    & sc.exe delete $serviceName | Out-Null
    if ($LASTEXITCODE -ne 0) {
      throw "failed to remove pre-existing lifecycle service: sc.exe exit code $LASTEXITCODE"
    }
    Wait-ServiceDeleted
  }
  Remove-Item -LiteralPath $installDir -Recurse -Force -ErrorAction SilentlyContinue
  New-Item -ItemType Directory -Path $installDir -Force | Out-Null
  Copy-Item -Path (Join-Path $baselineRoot "*") -Destination $installDir -Recurse -Force

  $template = [IO.File]::ReadAllText($baselineTemplate)
  $escapedInstallDir = $installDir.Replace("\", "\\")
  $template = $template.Replace("C:\\Program Files\\FDSecurity", $escapedInstallDir)
  $template = $template.Replace('endpoint_id          = "auto"', 'endpoint_id          = "ci-lifecycle-smoke"')
  $template = $template.Replace('tenant_id            = "tenant_default"', 'tenant_id            = "ci-lifecycle"')
  $template = $template.Replace('https://edr.example.com/api/v1', 'https://127.0.0.1:9/api/v1')
  [IO.File]::WriteAllText($configPath, $template, (New-Object Text.UTF8Encoding($false)))

  # Historical runtime packages remain immutable. Use the target package's
  # current installer to exercise the baseline binary without reviving an old
  # PowerShell/sc.exe compatibility bug from the baseline release.
  $stage = "baseline_install"
  & $targetInstaller -Action Install -ServiceName $serviceName `
    -DisplayName "FDSecurity Agent CI Lifecycle Smoke" `
    -ExePath (Join-Path $installDir "FDSensor.exe") `
    -ConfigPath $configPath -InstallDir $installDir -DataDir $installDir `
    -SkipPreflight -NoStart
  $stage = "baseline_stability"
  Wait-ServiceStable

  $stage = "upgrade"
  Invoke-VersionTransition -Operation upgrade -Candidate $targetBinary `
    -Version $TargetVersion -ArtifactID "ci-$TargetVersion-$Architecture" -UpdateScript $targetUpdater
  $stage = "embedded_updater"
  $embeddedUpdaterSha256 = Wait-EmbeddedUpdaterMaterialized -Version $TargetVersion `
    -ExpectedScript $targetUpdater
  $stage = "rollback"
  Invoke-VersionTransition -Operation rollback -Candidate $baselineBinary `
    -Version $BaselineVersion -ArtifactID "ci-$BaselineVersion-$Architecture" -UpdateScript $targetUpdater

  $stage = "uninstall"
  $agentProcessId = [int](Get-CimInstance Win32_Service -Filter ("Name='{0}'" -f $serviceName) -ErrorAction Stop).ProcessId
  $lifecycleCommandId = "cmd_lifecycle_uninstall_ci_$($TargetVersion.Replace('.', '_'))"
  $lifecycleTaskId = "ci-lifecycle-uninstall-$($TargetVersion.Replace('.', '-'))"
  $lifecycleJournal = Join-Path $programDataState "agent-lifecycle-$lifecycleCommandId.journal.json"
  $lifecycleLog = Join-Path $programDataState "agent-lifecycle-$lifecycleCommandId.worker.log"
  $cleanupReceipt = Join-Path $programDataState "uninstall-cleanup-$lifecycleTaskId.json"
  $cleanupStdout = Join-Path $programDataState "uninstall-cleanup-$lifecycleTaskId.stdout.log"
  $cleanupStderr = Join-Path $programDataState "uninstall-cleanup-$lifecycleTaskId.stderr.log"
  $uninstallScriptReceipt = Join-Path $programDataState "uninstall-script-$lifecycleTaskId.json"
  $uninstallPowerShellLog = Join-Path $programDataState "uninstall-powershell-$lifecycleTaskId.log"
  $attestationEvidence = Join-Path $EvidenceDir "uninstall-attestation-callback.json"
  $attestationAttempts = Join-Path $EvidenceDir "uninstall-attestation-attempts.json"
  $attestationReady = Join-Path $EvidenceDir "uninstall-attestation-listener-ready.json"
  $attestationPort = Get-Random -Minimum 32000 -Maximum 45000
  $attestationURL = "http://127.0.0.1:$attestationPort/uninstall-attest/"
  # A fresh token makes the smoke exercise the same one-time credential model
  # as production instead of relying on a predictable release-derived value.
  $attestationToken = ([Guid]::NewGuid().ToString("N") + [Guid]::NewGuid().ToString("N"))
  $attestationTokenSha256 = Get-TextSha256 -Value $attestationToken
  $attestationProof = Get-UninstallAttestationProof -Token $attestationToken `
    -TaskID $lifecycleTaskId -EndpointID "ci-lifecycle-smoke"
  New-Item -ItemType Directory -Path $programDataState -Force | Out-Null
  Remove-Item -LiteralPath $lifecycleJournal, $cleanupReceipt, $cleanupStdout, $cleanupStderr, `
    $uninstallScriptReceipt, $uninstallPowerShellLog, `
    $attestationEvidence, $attestationAttempts, $attestationReady -Force -ErrorAction SilentlyContinue
  $attestationJob = Start-Job -ScriptBlock {
    param(
      $Port,
      $EvidencePath,
      $AttemptsPath,
      $ReadyPath,
      $ExpectedTokenSha256,
      $ExpectedTokenLength,
      $ExpectedProof
    )
    function Normalize-AttestationToken {
      param([string]$Value)
      if ($null -eq $Value) { return "" }
      $normalized = $Value.Trim()
      if ($normalized.Length -ge 2 -and
          (($normalized[0] -eq [char]34 -and $normalized[$normalized.Length - 1] -eq [char]34) -or
           ($normalized[0] -eq [char]39 -and $normalized[$normalized.Length - 1] -eq [char]39))) {
        $normalized = $normalized.Substring(1, $normalized.Length - 2).Trim()
      }
      return $normalized
    }
    function Get-TokenFingerprint {
      param([string]$Value)
      if ([string]::IsNullOrEmpty($Value)) { return "" }
      $sha = [Security.Cryptography.SHA256]::Create()
      try {
        return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value)))).Replace("-", "").ToLowerInvariant()
      } finally {
        $sha.Dispose()
      }
    }
    $listener = New-Object Net.HttpListener
    $listener.Prefixes.Add("http://127.0.0.1:$Port/uninstall-attest/")
    $attemptRecords = @()
    $expectedTokenFingerprint = [string]$ExpectedTokenSha256
    try {
      $listener.Start()
      [ordered]@{
        ready_at = [DateTime]::UtcNow.ToString("o")
        port = $Port
      } | ConvertTo-Json | Set-Content -LiteralPath $ReadyPath -Encoding UTF8 -Force -ErrorAction Stop
      $accepted = $false
      while (-not $accepted) {
        $context = $listener.GetContext()
        $requestAccepted = $false
        $responseStatus = 500
        $responseJson = '{"success":false}'
        try {
          $reader = New-Object IO.StreamReader($context.Request.InputStream, $context.Request.ContentEncoding)
          $body = $reader.ReadToEnd()
          $reader.Dispose()
          $authorization = [string]$context.Request.Headers['Authorization']
          $parsedBody = $null
          $bodyError = ""
          try {
            $parsedBody = $body | ConvertFrom-Json -ErrorAction Stop
          } catch {
            $bodyError = $_.Exception.Message
          }
          $bearerToken = ""
          if ($authorization.StartsWith("Bearer ", [StringComparison]::OrdinalIgnoreCase)) {
            $bearerToken = Normalize-AttestationToken -Value $authorization.Substring(7)
          }
          $loopbackToken = Normalize-AttestationToken `
            -Value ([string]$context.Request.Headers['X-EDR-Uninstall-Token'])
          $bearerTokenFingerprint = Get-TokenFingerprint -Value $bearerToken
          $loopbackTokenFingerprint = Get-TokenFingerprint -Value $loopbackToken
          $authorizationValid = $bearerTokenFingerprint -and
            $bearerTokenFingerprint -ceq $expectedTokenFingerprint
          $loopbackTokenValid = $loopbackTokenFingerprint -and
            $loopbackTokenFingerprint -ceq $expectedTokenFingerprint
          $bodyTokenProofValid = ($null -ne $parsedBody -and
            [string]$parsedBody.token_proof_hmac_sha256 -ceq [string]$ExpectedProof)
          $tokenValid = $authorizationValid -or $loopbackTokenValid -or $bodyTokenProofValid
          $proofValid = ($null -ne $parsedBody -and
            $parsedBody.schema -eq "edr.endpoint.uninstall.attestation.v1" -and
            $parsedBody.service_removed -eq $true -and
            $parsedBody.process_stopped -eq $true -and
            $parsedBody.install_dir_removed -eq $true)
          $requestAccepted = $tokenValid -and $proofValid
          $attemptRecords += [ordered]@{
            received_at = [DateTime]::UtcNow.ToString("o")
            method = [string]$context.Request.HttpMethod
            remote_endpoint = [string]$context.Request.RemoteEndPoint
            content_type = [string]$context.Request.ContentType
            content_length = [long]$context.Request.ContentLength64
            body_utf8_length = [Text.Encoding]::UTF8.GetByteCount([string]$body)
            authorization_present = $authorization -like 'Bearer *'
            authorization_valid = $authorizationValid
            loopback_token_present = -not [string]::IsNullOrEmpty($loopbackToken)
            loopback_token_valid = $loopbackTokenValid
            body_token_proof_present = ($null -ne $parsedBody -and
              -not [string]::IsNullOrWhiteSpace([string]$parsedBody.token_proof_hmac_sha256))
            body_token_proof_valid = $bodyTokenProofValid
            accepted_token_transport = if ($authorizationValid) { "authorization" } elseif ($loopbackTokenValid) { "loopback_header" } elseif ($bodyTokenProofValid) { "body_hmac_sha256" } else { "none" }
            expected_token_length = [int]$ExpectedTokenLength
            expected_token_sha256 = $expectedTokenFingerprint
            bearer_token_length = $bearerToken.Length
            bearer_token_sha256 = $bearerTokenFingerprint
            loopback_token_length = $loopbackToken.Length
            loopback_token_sha256 = $loopbackTokenFingerprint
            expected_body_token_proof_sha256 = Get-TokenFingerprint -Value ([string]$ExpectedProof)
            received_body_token_proof_sha256 = if ($null -ne $parsedBody) {
              Get-TokenFingerprint -Value ([string]$parsedBody.token_proof_hmac_sha256)
            } else { "" }
            body_parse_error = $bodyError
            proof_valid = $proofValid
          }
          @($attemptRecords) | ConvertTo-Json -Depth 4 | Set-Content `
            -LiteralPath $AttemptsPath -Encoding UTF8 -Force -ErrorAction Stop
          if ($requestAccepted) {
            [ordered]@{
              authorization_present = $authorization -like 'Bearer *'
              authorization_valid = $authorizationValid
              token_valid = $tokenValid
              authorization_standard_valid = $authorizationValid
              loopback_token_valid = $loopbackTokenValid
              body_token_proof_valid = $bodyTokenProofValid
              accepted_token_transport = if ($authorizationValid) { "authorization" } elseif ($loopbackTokenValid) { "loopback_header" } else { "body_hmac_sha256" }
              body_parse_error = $bodyError
              body = $parsedBody
            } | ConvertTo-Json -Depth 4 | Set-Content `
              -LiteralPath $EvidencePath -Encoding UTF8 -Force -ErrorAction Stop
            $responseStatus = 200
            $responseJson = '{"success":true}'
          } elseif (-not $tokenValid) {
            $responseStatus = 401
          } else {
            $responseStatus = 400
          }
        } catch {
          $requestAccepted = $false
          Write-Output ("attestation_listener_request_failed: " + $_.Exception.Message)
        }
        try {
          $responseBody = [Text.Encoding]::UTF8.GetBytes($responseJson)
          $context.Response.StatusCode = $responseStatus
          $context.Response.ContentType = 'application/json'
          $context.Response.OutputStream.Write($responseBody, 0, $responseBody.Length)
          $context.Response.Close()
          if ($requestAccepted -and $responseStatus -eq 200) { $accepted = $true }
        } catch {
          Write-Output ("attestation_listener_response_failed: " + $_.Exception.Message)
          try { $context.Response.Abort() } catch {}
        }
      }
    } finally {
      $listener.Close()
    }
  } -ArgumentList $attestationPort, $attestationEvidence, $attestationAttempts, $attestationReady, `
    $attestationTokenSha256, $attestationToken.Length, $attestationProof
  Wait-AttestationListenerReady -Path $attestationReady -Job $attestationJob
  Copy-Item -LiteralPath $targetLifecycleWorker -Destination (Join-Path $installDir "FDSecurityInstallerWorker.exe") -Force
  Copy-Item -LiteralPath $targetUninstaller -Destination (Join-Path $installDir "uninstall.exe") -Force
  Copy-Item -LiteralPath $targetUninstallScript -Destination (Join-Path $installDir "uninstall.ps1") -Force
  $worker = Start-Process -FilePath (Join-Path $installDir "FDSecurityInstallerWorker.exe") `
    -ArgumentList @(
      "--stage", "lifecycle-uninstall",
      "--install-dir", $installDir,
      "--service-name", $serviceName,
      "--journal", $lifecycleJournal,
      "--log", $lifecycleLog,
      "--command-id", $lifecycleCommandId,
      "--task-id", $lifecycleTaskId,
      "--action", "uninstall",
      "--delay-ms", "5000",
      "--attestation-url", $attestationURL,
      "--attestation-token", $attestationToken,
      "--endpoint-id", "ci-lifecycle-smoke"
    ) -Wait -PassThru
  if ($worker.ExitCode -ne 0) {
    if (Test-Path -LiteralPath $lifecycleLog) { Get-Content -LiteralPath $lifecycleLog | Out-Host }
    $uninstallFailure = ""
    if (Test-Path -LiteralPath $uninstallScriptReceipt -PathType Leaf) {
      Copy-Item -LiteralPath $uninstallScriptReceipt -Destination $EvidenceDir -Force
      Get-Content -LiteralPath $uninstallScriptReceipt | Out-Host
      try {
        $uninstallResult = Get-Content -LiteralPath $uninstallScriptReceipt -Raw | ConvertFrom-Json
        $uninstallFailure = "; uninstall stage '$($uninstallResult.stage)': $($uninstallResult.error)"
      } catch {
        $uninstallFailure = "; uninstall diagnostic receipt was not valid JSON"
      }
    }
    if (Test-Path -LiteralPath $uninstallPowerShellLog -PathType Leaf) {
      Copy-Item -LiteralPath $uninstallPowerShellLog -Destination $EvidenceDir -Force
      Write-Host "--- uninstall PowerShell output ---"
      Get-Content -LiteralPath $uninstallPowerShellLog | Out-Host
    }
    if (Test-Path -LiteralPath $lifecycleJournal -PathType Leaf) {
      Copy-Item -LiteralPath $lifecycleJournal -Destination $EvidenceDir -Force
    }
    throw "lifecycle uninstall worker returned code $($worker.ExitCode)$uninstallFailure"
  }
  if (-not (Test-Path -LiteralPath $lifecycleJournal -PathType Leaf)) {
    throw "lifecycle uninstall worker did not write its terminal journal"
  }
  $lifecycleResult = Get-Content -LiteralPath $lifecycleJournal -Raw | ConvertFrom-Json
  if ($lifecycleResult.succeeded -ne $true -or [int]$lifecycleResult.exit_code -ne 0) {
    throw "lifecycle uninstall journal reported failure: $($lifecycleResult.detail)"
  }
  $stage = "verify_uninstall"
  Wait-ServiceDeleted
  Wait-ProcessDeleted -ProcessId $agentProcessId
  Wait-InstallDirectoryDeleted
  Wait-CleanupReceipt -Path $cleanupReceipt
  $cleanupResult = Get-Content -LiteralPath $cleanupReceipt -Raw | ConvertFrom-Json
  if ($cleanupResult.status -ne "succeeded" -or $cleanupResult.attestation_status -ne "succeeded") {
    Copy-Item -LiteralPath $cleanupReceipt -Destination $EvidenceDir -Force
    Write-Host "--- deferred uninstall cleanup receipt ---"
    Get-Content -LiteralPath $cleanupReceipt | Out-Host
    if (Test-Path -LiteralPath $attestationAttempts -PathType Leaf) {
      Write-Host "--- uninstall attestation listener attempts ---"
      Get-Content -LiteralPath $attestationAttempts | Out-Host
    }
    if (Test-Path -LiteralPath $attestationEvidence -PathType Leaf) {
      Write-Host "--- uninstall attestation callback evidence ---"
      Get-Content -LiteralPath $attestationEvidence | Out-Host
    }
    $listenerReason = ""
    if ($attestationJob.ChildJobs.Count -gt 0 -and $attestationJob.ChildJobs[0].JobStateInfo.Reason) {
      $listenerReason = $attestationJob.ChildJobs[0].JobStateInfo.Reason.Message
    }
    Write-Host "attestation_listener state=$($attestationJob.State) reason=$listenerReason"
    Receive-Job -Job $attestationJob -Keep -ErrorAction SilentlyContinue | Out-Host
    $attemptDetail = ""
    if (Test-Path -LiteralPath $attestationAttempts -PathType Leaf) {
      try {
        $attemptResult = @(Get-Content -LiteralPath $attestationAttempts -Raw | ConvertFrom-Json)[-1]
        $attemptDetail = " method=$($attemptResult.method) content_type=$($attemptResult.content_type) content_length=$($attemptResult.content_length) body_utf8_length=$($attemptResult.body_utf8_length) expected_token_sha256=$($attemptResult.expected_token_sha256) bearer_token_sha256=$($attemptResult.bearer_token_sha256) loopback_token_sha256=$($attemptResult.loopback_token_sha256) body_token_proof_present=$($attemptResult.body_token_proof_present) expected_body_token_proof_sha256=$($attemptResult.expected_body_token_proof_sha256) received_body_token_proof_sha256=$($attemptResult.received_body_token_proof_sha256) body_token_proof_valid=$($attemptResult.body_token_proof_valid) body_parse_error=$($attemptResult.body_parse_error) proof_valid=$($attemptResult.proof_valid) accepted_token_transport=$($attemptResult.accepted_token_transport)"
      } catch {
        $attemptDetail = " attestation_attempt_diagnostic=invalid_json"
      }
    }
    throw "deferred uninstall cleanup failed: status=$($cleanupResult.status) local_status=$($cleanupResult.local_status) service_removed=$($cleanupResult.service_removed) process_stopped=$($cleanupResult.process_stopped) install_dir_removed=$($cleanupResult.install_dir_removed) deletion_attempts=$($cleanupResult.deletion_attempts) deletion_last_error=$($cleanupResult.deletion_last_error) remaining_entries=$(@($cleanupResult.remaining_entries) -join '|') attestation_status=$($cleanupResult.attestation_status) attestation_token_present=$($cleanupResult.attestation_token_present) attestation_token_length=$($cleanupResult.attestation_token_length) attestation_attempts=$($cleanupResult.attestation_attempts) attestation_proxy_mode=$($cleanupResult.attestation_proxy_mode) attestation_transport=$($cleanupResult.attestation_transport) attestation_request_body_bytes=$($cleanupResult.attestation_request_body_bytes) attestation_http_status=$($cleanupResult.attestation_last_http_status) attestation_error=$($cleanupResult.attestation_error) attestation_errors=$(@($cleanupResult.attestation_errors) -join '|') failure_reasons=$(@($cleanupResult.failure_reasons) -join ',')$attemptDetail"
  }
  if (-not (Test-Path -LiteralPath $attestationEvidence -PathType Leaf)) {
    throw "uninstall attestation callback evidence is missing"
  }
  $attestationResult = Get-Content -LiteralPath $attestationEvidence -Raw | ConvertFrom-Json
  if ($attestationResult.token_valid -ne $true -or
      $attestationResult.body_token_proof_valid -ne $true -or
      $attestationResult.body_parse_error -or
      $attestationResult.body.schema -ne "edr.endpoint.uninstall.attestation.v1" -or
      $attestationResult.body.service_removed -ne $true -or
      $attestationResult.body.process_stopped -ne $true -or
      $attestationResult.body.install_dir_removed -ne $true) {
    throw "uninstall attestation callback did not contain complete local teardown proof"
  }
  Copy-Item -LiteralPath $lifecycleJournal, $cleanupReceipt, $uninstallScriptReceipt `
    -Destination $EvidenceDir -Force
  if (Test-Path -LiteralPath $uninstallPowerShellLog -PathType Leaf) {
    Copy-Item -LiteralPath $uninstallPowerShellLog -Destination $EvidenceDir -Force
  }

  $stage = "completed"
  [ordered]@{
    schema_version = 1
    baseline_version = $BaselineVersion
    target_version = $TargetVersion
    architecture = $Architecture
    install = "passed"
    upgrade = "passed"
    embedded_updater = "passed"
    embedded_updater_sha256 = $embeddedUpdaterSha256
    rollback = "passed"
    uninstall = "passed"
    uninstall_path = "agent_lifecycle_worker"
    completed_at = [DateTimeOffset]::UtcNow.ToString("o")
  } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $EvidenceDir "summary.json") -Encoding UTF8
} catch {
  [ordered]@{
    schema_version = 1
    baseline_version = $BaselineVersion
    target_version = $TargetVersion
    architecture = $Architecture
    status = "failed"
    failed_stage = $stage
    error = $_.Exception.Message
    completed_at = [DateTimeOffset]::UtcNow.ToString("o")
  } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $EvidenceDir "summary.json") -Encoding UTF8
  throw
} finally {
  if ($attestationJob) {
    try {
      $reason = ""
      if ($attestationJob.ChildJobs.Count -gt 0 -and $attestationJob.ChildJobs[0].JobStateInfo.Reason) {
        $reason = $attestationJob.ChildJobs[0].JobStateInfo.Reason.Message
      }
      [ordered]@{
        state = [string]$attestationJob.State
        reason = $reason
        output = ((Receive-Job -Job $attestationJob -Keep -ErrorAction SilentlyContinue | Out-String).Trim())
      } | ConvertTo-Json -Depth 3 | Set-Content `
        -LiteralPath (Join-Path $EvidenceDir "uninstall-attestation-listener-job.json") -Encoding UTF8 -Force
    } catch {}
    Stop-Job -Job $attestationJob -ErrorAction SilentlyContinue
    Remove-Job -Job $attestationJob -Force -ErrorAction SilentlyContinue
  }
  Get-CimInstance Win32_Service -Filter ("Name='{0}'" -f $serviceName) -ErrorAction SilentlyContinue |
    Format-List * | Out-File -FilePath (Join-Path $EvidenceDir "service-final.txt")
  foreach ($root in @($programDataState, $programDataLogs)) {
    if (Test-Path -LiteralPath $root) {
      Get-ChildItem -LiteralPath $root -File -ErrorAction SilentlyContinue |
        Where-Object Name -Match "agent-update-ci-|agent-lifecycle-|uninstall-(script|cleanup|powershell)-last" |
        Copy-Item -Destination $EvidenceDir -Force -ErrorAction SilentlyContinue
    }
  }
  Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
  & sc.exe delete $serviceName 2>$null | Out-Null
  Remove-Item -LiteralPath $installDir -Recurse -Force -ErrorAction SilentlyContinue
}

# GitHub's pwsh wrapper propagates a stale native-command LASTEXITCODE even
# when every lifecycle assertion passed. Make successful completion explicit.
exit 0
