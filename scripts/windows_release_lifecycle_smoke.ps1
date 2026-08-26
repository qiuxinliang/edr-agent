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
$targetNativeIntegrity = Find-OneFile -Root $TargetPackageDir -Name "native-package-integrity.json"
$baselineTemplate = Find-OneFile -Root $BaselinePackageDir -Name "agent_windows_production.example.toml"
$sourceInstaller = Join-Path $PSScriptRoot "windows_service_install.ps1"

if (-not (Test-Path -LiteralPath $sourceInstaller)) {
  throw "current windows_service_install.ps1 is missing from the checked-out repository"
}
$targetInstallerHash = (Get-FileHash -LiteralPath $targetInstaller -Algorithm SHA256).Hash
$sourceInstallerHash = (Get-FileHash -LiteralPath $sourceInstaller -Algorithm SHA256).Hash
if ($targetInstallerHash -ne $sourceInstallerHash) {
  throw "target package service installer hash mismatch"
}
$nativeIntegrity = Get-Content -LiteralPath $targetNativeIntegrity -Raw | ConvertFrom-Json
if ($nativeIntegrity.schema -ne "edr.windows.native-package-integrity.v1") {
  throw "target package native integrity manifest schema mismatch"
}
$targetNativeHashes = @{}
foreach ($component in @(
    @{ Name = "FDSecurityInstallerWorker.exe"; Path = $targetLifecycleWorker },
    @{ Name = "uninstall.exe"; Path = $targetUninstaller }
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
  $targetNativeHashes[$component.Name] = $actualHash
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
if ($workerCapabilities.uninstall_attestation -ne "v3" -or
    $workerCapabilities.native_in_memory_token_handoff -ne $true) {
  throw "target installer worker lacks native uninstall attestation v3 handoff"
}
if ($uninstallerCapabilities.uninstall_attestation -ne "v3" -or
    $uninstallerCapabilities.native_in_memory_token_handoff -ne $true) {
  throw "target headless uninstaller lacks native uninstall attestation v3 handoff"
}

if ((Get-AgentVersion -Path $baselineBinary) -ne $BaselineVersion) {
  throw "baseline binary ProductVersion does not match $BaselineVersion"
}
if ((Get-AgentVersion -Path $targetBinary) -ne $TargetVersion) {
  throw "target binary ProductVersion does not match $TargetVersion"
}

$stage = "prepare"
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
  Copy-Item -LiteralPath $targetLifecycleWorker -Destination (Join-Path $installDir "FDSecurityInstallerWorker.exe") -Force
  Copy-Item -LiteralPath $targetUninstaller -Destination (Join-Path $installDir "uninstall.exe") -Force
  # Rollback restores the baseline runtime. Preserve its DLL hashes and update
  # only the two target lifecycle components copied into this test fixture.
  $installedNativeIntegrityPath = Join-Path $installDir "native-package-integrity.json"
  $installedNativeIntegrity = Get-Content -LiteralPath $installedNativeIntegrityPath -Raw | ConvertFrom-Json
  if ($installedNativeIntegrity.schema -ne "edr.windows.native-package-integrity.v1") {
    throw "installed baseline native integrity manifest schema mismatch"
  }
  foreach ($componentName in @("FDSecurityInstallerWorker.exe", "uninstall.exe")) {
    $installedEntry = @($installedNativeIntegrity.files | Where-Object { $_.name -eq $componentName })
    if ($installedEntry.Count -ne 1) {
      throw "installed baseline native integrity manifest is missing $componentName"
    }
    $installedEntry[0].sha256 = $targetNativeHashes[$componentName]
  }
  $installedNativeIntegrity | ConvertTo-Json -Depth 4 | Set-Content `
    -LiteralPath $installedNativeIntegrityPath -Encoding UTF8
  $uninstallerProcess = Start-Process -FilePath (Join-Path $installDir "uninstall.exe") -ArgumentList @(
    "--silent", "--install-dir", $installDir, "--service-name", $serviceName
  ) -Wait -PassThru
  if ($uninstallerProcess.ExitCode -ne 0) {
    $uninstallError = [ComponentModel.Win32Exception]::new([int]$uninstallerProcess.ExitCode).Message
    throw "native uninstall coordinator returned code $($uninstallerProcess.ExitCode): $uninstallError"
  }
  $stage = "verify_uninstall"
  Wait-ServiceDeleted
  Wait-ProcessDeleted -ProcessId $agentProcessId
  Wait-InstallDirectoryDeleted
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
    uninstall_path = "native_coordinator"
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
  Get-CimInstance Win32_Service -Filter ("Name='{0}'" -f $serviceName) -ErrorAction SilentlyContinue |
    Format-List * | Out-File -FilePath (Join-Path $EvidenceDir "service-final.txt")
  foreach ($root in @($programDataState, $programDataLogs)) {
    if (Test-Path -LiteralPath $root) {
      Get-ChildItem -LiteralPath $root -File -ErrorAction SilentlyContinue |
        Where-Object Name -Match "agent-update-ci-|agent-lifecycle-|last-native-uninstall-failure" |
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
