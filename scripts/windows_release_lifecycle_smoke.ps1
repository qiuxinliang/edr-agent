#Requires -Version 5.1
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$BaselinePackageDir,
  [Parameter(Mandatory = $true)][string]$TargetPackageDir,
  [Parameter(Mandatory = $true)][string]$BaselineVersion,
  [Parameter(Mandatory = $true)][string]$TargetVersion,
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
  param([string]$Path, [int]$Seconds = 90)
  for ($i = 0; $i -lt $Seconds; $i++) {
    if (Test-Path -LiteralPath $Path -PathType Leaf) { return }
    Start-Sleep -Seconds 1
  }
  throw "deferred uninstall cleanup did not write its receipt within $Seconds seconds"
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
    -ExpectedArchitecture x64 `
    -TrustedPublisherThumbprint $publisher.Thumbprint `
    -TrustedPublisherSubject $publisher.Subject `
    -DeploymentMode service `
    -ServiceName $serviceName `
    -CommandId ("ci-{0}-{1}" -f $Operation, $Version) `
    -TaskId ([Guid]::NewGuid().ToString("N")) `
    -Operation $Operation `
    -ArtifactId $ArtifactID `
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

New-Item -ItemType Directory -Path $EvidenceDir -Force | Out-Null
Assert-Administrator

$baselineBinary = Find-OneFile -Root $BaselinePackageDir -Name "FDSensor.exe"
$targetBinary = Find-OneFile -Root $TargetPackageDir -Name "FDSensor.exe"
$baselineRoot = Split-Path -Parent $baselineBinary
$targetRoot = Split-Path -Parent $targetBinary
$targetInstaller = Find-OneFile -Root $TargetPackageDir -Name "windows_service_install.ps1"
$targetUpdater = Find-OneFile -Root $TargetPackageDir -Name "edr_agent_inplace_update.ps1"
$targetLifecycleWorker = Find-OneFile -Root $TargetPackageDir -Name "FDSecurityInstallerWorker.exe"
$targetUninstaller = Find-OneFile -Root $TargetPackageDir -Name "uninstall.exe"
$targetUninstallScript = Find-OneFile -Root $TargetPackageDir -Name "uninstall.ps1"
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
    -Version $TargetVersion -ArtifactID "ci-$TargetVersion-amd64" -UpdateScript $targetUpdater
  $stage = "embedded_updater"
  $embeddedUpdaterSha256 = Wait-EmbeddedUpdaterMaterialized -Version $TargetVersion `
    -ExpectedScript $targetUpdater
  $stage = "rollback"
  Invoke-VersionTransition -Operation rollback -Candidate $baselineBinary `
    -Version $BaselineVersion -ArtifactID "ci-$BaselineVersion-amd64" -UpdateScript $targetUpdater

  $stage = "uninstall"
  $agentProcessId = [int](Get-CimInstance Win32_Service -Filter ("Name='{0}'" -f $serviceName) -ErrorAction Stop).ProcessId
  $lifecycleCommandId = "cmd_lifecycle_uninstall_ci_$($TargetVersion.Replace('.', '_'))"
  $lifecycleTaskId = "ci-lifecycle-uninstall-$($TargetVersion.Replace('.', '-'))"
  $lifecycleJournal = Join-Path $programDataState "agent-lifecycle-$lifecycleCommandId.journal.json"
  $lifecycleLog = Join-Path $installDir "diagnostics\lifecycle-worker.log"
  $cleanupReceipt = Join-Path $programDataState "uninstall-cleanup-last.json"
  $attestationEvidence = Join-Path $EvidenceDir "uninstall-attestation-callback.json"
  $attestationPort = Get-Random -Minimum 32000 -Maximum 45000
  $attestationURL = "http://127.0.0.1:$attestationPort/uninstall-attest/"
  $attestationToken = "ci-lifecycle-uninstall-token-$($TargetVersion.Replace('.', '-'))"
  $attestationJob = Start-Job -ScriptBlock {
    param($Port, $EvidencePath)
    $listener = New-Object Net.HttpListener
    $listener.Prefixes.Add("http://127.0.0.1:$Port/uninstall-attest/")
    try {
      $listener.Start()
      $context = $listener.GetContext()
      $reader = New-Object IO.StreamReader($context.Request.InputStream, $context.Request.ContentEncoding)
      $body = $reader.ReadToEnd()
      $reader.Dispose()
      [ordered]@{
        authorization_present = $context.Request.Headers['Authorization'] -like 'Bearer *'
        body = ($body | ConvertFrom-Json)
      } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $EvidencePath -Encoding UTF8
      $responseBody = [Text.Encoding]::UTF8.GetBytes('{"success":true}')
      $context.Response.StatusCode = 200
      $context.Response.ContentType = 'application/json'
      $context.Response.OutputStream.Write($responseBody, 0, $responseBody.Length)
      $context.Response.Close()
    } finally {
      $listener.Close()
    }
  } -ArgumentList $attestationPort, $attestationEvidence
  New-Item -ItemType Directory -Path (Split-Path -Parent $lifecycleLog) -Force | Out-Null
  New-Item -ItemType Directory -Path $programDataState -Force | Out-Null
  Remove-Item -LiteralPath $lifecycleJournal, $cleanupReceipt -Force -ErrorAction SilentlyContinue
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
    throw "lifecycle uninstall worker returned code $($worker.ExitCode)"
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
    throw "deferred uninstall cleanup failed for $($cleanupResult.install_dir)"
  }
  if (-not (Test-Path -LiteralPath $attestationEvidence -PathType Leaf)) {
    throw "uninstall attestation callback evidence is missing"
  }
  $attestationResult = Get-Content -LiteralPath $attestationEvidence -Raw | ConvertFrom-Json
  if ($attestationResult.authorization_present -ne $true -or
      $attestationResult.body.schema -ne "edr.endpoint.uninstall.attestation.v1" -or
      $attestationResult.body.service_removed -ne $true -or
      $attestationResult.body.process_stopped -ne $true -or
      $attestationResult.body.install_dir_removed -ne $true) {
    throw "uninstall attestation callback did not contain complete local teardown proof"
  }
  Copy-Item -LiteralPath $lifecycleJournal, $cleanupReceipt -Destination $EvidenceDir -Force

  $stage = "completed"
  [ordered]@{
    schema_version = 1
    baseline_version = $BaselineVersion
    target_version = $TargetVersion
    architecture = "amd64"
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
    architecture = "amd64"
    status = "failed"
    failed_stage = $stage
    error = $_.Exception.Message
    completed_at = [DateTimeOffset]::UtcNow.ToString("o")
  } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $EvidenceDir "summary.json") -Encoding UTF8
  throw
} finally {
  if ($attestationJob) {
    Stop-Job -Job $attestationJob -ErrorAction SilentlyContinue
    Remove-Job -Job $attestationJob -Force -ErrorAction SilentlyContinue
  }
  Get-CimInstance Win32_Service -Filter ("Name='{0}'" -f $serviceName) -ErrorAction SilentlyContinue |
    Format-List * | Out-File -FilePath (Join-Path $EvidenceDir "service-final.txt")
  foreach ($root in @($programDataState, $programDataLogs)) {
    if (Test-Path -LiteralPath $root) {
      Get-ChildItem -LiteralPath $root -File -ErrorAction SilentlyContinue |
        Where-Object Name -Match "agent-update-ci-" |
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
