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

function Get-UninstallFinalizerSnapshot {
  if (-not (Test-Path -LiteralPath $programDataState)) { return @() }
  return @(Get-ChildItem -LiteralPath $programDataState -File -Filter "uninstall-finalizer-*.exe" -ErrorAction Stop |
    ForEach-Object { [pscustomobject]@{ Path = $_.FullName; CreationUtc = $_.CreationTimeUtc; LastWriteUtc = $_.LastWriteTimeUtc; Length = $_.Length } })
}

function Get-NewUninstallFinalizers {
  param([object[]]$Before)
  $beforePaths = @{}; foreach ($item in $Before) { $beforePaths[$item.Path] = $true }
  return @(Get-UninstallFinalizerSnapshot | Where-Object { -not $beforePaths.ContainsKey($_.Path) })
}

function Get-UninstallFinalizerProcesses {
  param([object[]]$Finalizers)
  if (-not $Finalizers -or $Finalizers.Count -eq 0) { return @() }
  $paths = @{}; foreach ($item in $Finalizers) { $paths[$item.Path] = $true }
  return @(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object {
    $_.ExecutablePath -and $paths.ContainsKey($_.ExecutablePath)
  } | Select-Object ProcessId, Name, ExecutablePath, CommandLine, CreationDate)
}

function Get-NativeUninstallFailureSnapshot {
  $snapshots = @()
  foreach ($name in @("last-native-uninstall-failure.receipt", "last-native-uninstall-failure.receipt.tmp")) {
    $path = Join-Path $programDataState $name
    $snapshot = [ordered]@{ Path = $path; Exists = $false; LastWriteUtc = $null; Length = 0; Sha256 = $null }
    if (Test-Path -LiteralPath $path -PathType Leaf) {
      $item = Get-Item -LiteralPath $path -ErrorAction Stop
      $snapshot.Exists = $true
      $snapshot.LastWriteUtc = $item.LastWriteTimeUtc
      $snapshot.Length = $item.Length
      $snapshot.Sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash
    }
    $snapshots += [pscustomobject]$snapshot
  }
  return @($snapshots)
}

function Get-NativeUninstallFailure {
  param([object[]]$Before)
  $beforeByPath = @{}
  foreach ($item in $Before) { $beforeByPath[$item.Path] = $item }
  foreach ($name in @("last-native-uninstall-failure.receipt", "last-native-uninstall-failure.receipt.tmp")) {
    $path = Join-Path $programDataState $name
    if (Test-Path -LiteralPath $path -PathType Leaf) {
      $item = Get-Item -LiteralPath $path -ErrorAction Stop
      $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash
      $before = $beforeByPath[$path]
      if (-not $before -or -not $before.Exists -or $before.LastWriteUtc -ne $item.LastWriteTimeUtc -or $before.Length -ne $item.Length -or $before.Sha256 -ne $hash) {
      $fields = @{}; Get-Content -LiteralPath $path -ErrorAction Stop | ForEach-Object {
        $pair = $_ -split "=", 2; if ($pair.Count -eq 2) { $fields[$pair[0]] = $pair[1] }
      }
        return [pscustomobject]@{ Path = $path; Stage = $fields["stage"]; Error = $fields["error"]; FailurePath = $fields["path"]; LastWriteUtc = $item.LastWriteTimeUtc; Length = $item.Length; Sha256 = $hash }
      }
    }
  }
  return $null
}

function Wait-NativeUninstallTerminal {
  param([int]$AgentProcessId, [object[]]$Finalizers, [DateTime]$DeadlineUtc, [object[]]$ReceiptBefore)
  $lastQueryError = $null
  while ([DateTime]::UtcNow -lt $DeadlineUtc) {
    try {
      $receipt = Get-NativeUninstallFailure -Before $ReceiptBefore
      if ($receipt) { throw "native finalizer failure: stage=$($receipt.Stage) error=$($receipt.Error) failure_path=$($receipt.FailurePath) receipt=$($receipt.Path)" }
      $rootGone = -not (Test-Path -LiteralPath $installDir -ErrorAction Stop)
      $service = @(Get-CimInstance Win32_Service -Filter ("Name='{0}'" -f $serviceName) -ErrorAction Stop)
      $processes = @(Get-CimInstance Win32_Process -ErrorAction Stop)
      $serviceGone = $service.Count -eq 0
      $agentGone = @($processes | Where-Object { $_.ProcessId -eq $AgentProcessId }).Count -eq 0
      $finalizerPaths = @{}; foreach ($finalizer in $Finalizers) { $finalizerPaths[$finalizer.Path] = $true }
      $finalizerRunning = @($processes | Where-Object { $_.ExecutablePath -and $finalizerPaths.ContainsKey($_.ExecutablePath) }).Count -gt 0
      # A finalizer can delete its own executable before the process table refreshes;
      # install-root removal is the terminal success condition once registration is gone.
      if ($rootGone -and $serviceGone -and $agentGone -and -not $finalizerRunning) { return }
    } catch {
      if ($_.Exception.Message -like "native finalizer failure:*") { throw }
      $lastQueryError = $_.Exception.Message
    }
    Start-Sleep -Seconds 1
  }
  $receipt = Get-NativeUninstallFailure -Before $ReceiptBefore
  if ($receipt) { throw "native finalizer failure: stage=$($receipt.Stage) error=$($receipt.Error) failure_path=$($receipt.FailurePath) receipt=$($receipt.Path)" }
  throw "native uninstall terminal state timed out within the shared 120 second budget; install_root=$installDir last_query_error=$lastQueryError"
}

function Write-UninstallDiagnostics {
  param([string]$Reason)
  $errors = [System.Collections.Generic.List[string]]::new()
  try {
    $items = @(); if (Test-Path -LiteralPath $installDir) {
      $items = @(Get-ChildItem -LiteralPath $installDir -Force -Recurse -ErrorAction Stop | ForEach-Object {
        $entry = $_
        try { $acl = Get-Acl -LiteralPath $entry.FullName -ErrorAction Stop; $owner = $acl.Owner; $access = @($acl.Access | ForEach-Object { "$($_.IdentityReference):$($_.FileSystemRights):$($_.AccessControlType)" }) -join ";" }
        catch { $owner = "<acl-error>"; $access = $_.Exception.Message; $errors.Add("ACL $($entry.FullName): $($_.Exception.Message)") }
        [pscustomobject]@{ relative_path = $entry.FullName.Substring($installDir.Length).TrimStart('\\'); type = if ($entry.PSIsContainer) { "directory" } else { "file" }; size = if ($entry.PSIsContainer) { 0 } else { $entry.Length }; attributes = [string]$entry.Attributes; creation_utc = $entry.CreationTimeUtc; lastwrite_utc = $entry.LastWriteTimeUtc; owner = $owner; acl = $access }
      })
    }
    ConvertTo-Json -InputObject @($items) -Depth 4 | Set-Content -LiteralPath (Join-Path $EvidenceDir "uninstall-install-root-residual.json") -Encoding UTF8
  } catch { $errors.Add("install-root inventory: $($_.Exception.Message)") }
  try { $processes = @(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object { $_.ExecutablePath -like "$installDir*" -or $_.CommandLine -like "*$installDir*" } | Select-Object ProcessId, Name, ExecutablePath, CommandLine); ConvertTo-Json -InputObject @($processes) -Depth 3 | Set-Content (Join-Path $EvidenceDir "uninstall-install-processes.json") -Encoding UTF8 } catch { $errors.Add("process inventory: $($_.Exception.Message)") }
  try { Get-CimInstance Win32_Service -Filter ("Name='{0}'" -f $serviceName) -ErrorAction Stop | Format-List * | Out-File (Join-Path $EvidenceDir "uninstall-service.txt") } catch { $errors.Add("service inventory: $($_.Exception.Message)") }
  try { Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.TaskName -match "FDSecurity|$serviceName" } | Format-List * | Out-File (Join-Path $EvidenceDir "uninstall-tasks.txt") } catch { $errors.Add("task inventory: $($_.Exception.Message)") }
  try { if (Test-Path -LiteralPath $programDataState) { $state = @(Get-ChildItem -LiteralPath $programDataState -Force -ErrorAction Stop | Where-Object { $_.Name -match "uninstall-finalizer-|last-native-uninstall-failure" } | Select-Object FullName, Length, CreationTimeUtc, LastWriteTimeUtc, Attributes); ConvertTo-Json -InputObject @($state) | Set-Content (Join-Path $EvidenceDir "uninstall-finalizer-state.json") -Encoding UTF8 } } catch { $errors.Add("finalizer inventory: $($_.Exception.Message)") }
  foreach ($receiptCopy in @(
      [pscustomobject]@{ Source = (Join-Path $programDataState "last-native-uninstall-failure.receipt"); Destination = "native-failure-receipt.txt" },
      [pscustomobject]@{ Source = (Join-Path $programDataState "last-native-uninstall-failure.receipt.tmp"); Destination = "native-failure-receipt-tmp.txt" }
    )) {
    try {
      $content = if (Test-Path -LiteralPath $receiptCopy.Source -PathType Leaf) { Get-Content -LiteralPath $receiptCopy.Source -Raw -ErrorAction Stop } else { "<absent>" }
      Set-Content -LiteralPath (Join-Path $EvidenceDir $receiptCopy.Destination) -Value $content -Encoding UTF8 -ErrorAction Stop
    } catch { $errors.Add("receipt diagnostic $($receiptCopy.Source): $($_.Exception.Message)") }
  }
  ConvertTo-Json -InputObject @([pscustomobject]@{ reason = $Reason; errors = @($errors) }) -Depth 3 | Set-Content -LiteralPath (Join-Path $EvidenceDir "uninstall-diagnostics-errors.json") -Encoding UTF8
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
  $transitionId = [Guid]::NewGuid().ToString("N")
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
    -CommandId ("ci-{0}-{1}-{2}" -f $Operation, $Version, $transitionId) `
    -TaskId $transitionId `
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
    $preexistingDeleteDeadline = [DateTime]::UtcNow.AddSeconds(20)
    while ((Get-CimInstance Win32_Service -Filter ("Name='{0}'" -f $serviceName) -ErrorAction SilentlyContinue) -and
           [DateTime]::UtcNow -lt $preexistingDeleteDeadline) { Start-Sleep -Seconds 1 }
    if (Get-CimInstance Win32_Service -Filter ("Name='{0}'" -f $serviceName) -ErrorAction SilentlyContinue) {
      throw "pre-existing lifecycle service still exists after deletion request"
    }
  }
  Remove-Item -LiteralPath $installDir -Recurse -Force -ErrorAction SilentlyContinue
  New-Item -ItemType Directory -Path $installDir -Force | Out-Null
  Copy-Item -Path (Join-Path $baselineRoot "*") -Destination $installDir -Recurse -Force
  # The runtime ZIP keeps package assets under config\, while the Windows
  # installer places protected detection assets under the installed
  # edr_config\ directory. Mirror that installer mapping for this direct-copy
  # lifecycle fixture before the Agent starts.
  $installedDetectionConfigDir = Join-Path $installDir "edr_config"
  New-Item -ItemType Directory -Path $installedDetectionConfigDir -Force | Out-Null
  foreach ($detectionAssetName in @("p0_rule_bundle_ir_v1.json.enc", "sensor_interest_manifest.json")) {
    $installedDetectionAsset = Join-Path $installedDetectionConfigDir $detectionAssetName
    if (Test-Path -LiteralPath $installedDetectionAsset -PathType Leaf) {
      continue
    }
    $packagedDetectionAsset = $null
    foreach ($packageRoot in @($baselineRoot, $targetRoot)) {
      foreach ($packageConfigDir in @("edr_config", "config")) {
        $candidateDetectionAsset = Join-Path (Join-Path $packageRoot $packageConfigDir) $detectionAssetName
        if (Test-Path -LiteralPath $candidateDetectionAsset -PathType Leaf) {
          $candidateDetectionAssetLength = (Get-Item -LiteralPath $candidateDetectionAsset).Length
          if ($candidateDetectionAssetLength -gt 0) {
            $packagedDetectionAsset = $candidateDetectionAsset
            break
          }
        }
      }
      if ($packagedDetectionAsset) { break }
    }
    if (-not $packagedDetectionAsset) {
      throw "target and baseline packages are missing required detection artifact: $detectionAssetName"
    }
    $packagedDetectionAssetFullPath = [IO.Path]::GetFullPath($packagedDetectionAsset)
    $targetRootFullPath = [IO.Path]::GetFullPath($targetRoot)
    if ($packagedDetectionAssetFullPath.StartsWith($targetRootFullPath, [StringComparison]::OrdinalIgnoreCase)) {
      Write-Warning "baseline package omitted $detectionAssetName; using the target package's verified detection asset for the installed lifecycle fixture"
    }
    Copy-Item -LiteralPath $packagedDetectionAsset -Destination $installedDetectionAsset -Force
  }

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
  Copy-Item -LiteralPath $targetLifecycleWorker -Destination (Join-Path $installDir "FDSecurityInstallerWorker.exe") -Force
  Copy-Item -LiteralPath $targetUninstaller -Destination (Join-Path $installDir "uninstall.exe") -Force
  # Rollback restores the baseline runtime. Preserve its DLL hashes and update
  # only the two target lifecycle components copied into this test fixture.
  $installedNativeIntegrityPath = Join-Path $installDir "native-package-integrity.json"
  $installedNativeIntegrity = Get-Content -LiteralPath $installedNativeIntegrityPath -Raw | ConvertFrom-Json
  if ($installedNativeIntegrity.schema -ne "edr.windows.native-package-integrity.v1") {
    throw "installed baseline native integrity manifest schema mismatch"
  }
  # Releases 3.2.383 and earlier could list the standalone PCRE2 contract in
  # this native-only manifest. Keep the legacy baseline package usable while
  # leaving production package generation and native validation strict.
  $installedNativeIntegrity.files = @($installedNativeIntegrity.files | Where-Object {
    $_.name -ne "p0_matcher_contract.json"
  })
  foreach ($componentName in @("FDSecurityInstallerWorker.exe", "uninstall.exe")) {
    $installedEntry = @($installedNativeIntegrity.files | Where-Object { $_.name -eq $componentName })
    if ($installedEntry.Count -ne 1) {
      throw "installed baseline native integrity manifest is missing $componentName"
    }
    $installedEntry[0].sha256 = $targetNativeHashes[$componentName]
  }
  $installedNativeIntegrity | ConvertTo-Json -Depth 4 | Set-Content `
    -LiteralPath $installedNativeIntegrityPath -Encoding UTF8
  $finalizersBefore = Get-UninstallFinalizerSnapshot
  $finalizerProcessesBefore = Get-UninstallFinalizerProcesses -Finalizers $finalizersBefore
  $nativeFailureBefore = Get-NativeUninstallFailureSnapshot
  $uninstallStartedUtc = [DateTime]::UtcNow
  $uninstallDeadlineUtc = $uninstallStartedUtc.AddSeconds(120)
  $uninstallerProcess = Start-Process -FilePath (Join-Path $installDir "uninstall.exe") -ArgumentList @(
    "--silent", "--install-dir", $installDir, "--service-name", $serviceName
  ) -Wait -PassThru
  if ($uninstallerProcess.ExitCode -ne 0) {
    $uninstallError = [ComponentModel.Win32Exception]::new([int]$uninstallerProcess.ExitCode).Message
    throw "native uninstall coordinator returned code $($uninstallerProcess.ExitCode): $uninstallError"
  }
  # Exit 0 is only a committed handoff to the detached finalizer, not proof of removal.
  $finalizersThisRun = Get-NewUninstallFinalizers -Before $finalizersBefore
  ConvertTo-Json -InputObject @([pscustomobject]@{ started_utc = $uninstallStartedUtc; before_finalizers = @($finalizersBefore); before_processes = @($finalizerProcessesBefore); receipt_before = @($nativeFailureBefore); this_run_finalizers = @($finalizersThisRun); this_run_processes = @(Get-UninstallFinalizerProcesses -Finalizers $finalizersThisRun); receipt_after_handoff = @(Get-NativeUninstallFailureSnapshot) }) -Depth 4 |
    Set-Content -LiteralPath (Join-Path $EvidenceDir "uninstall-finalizers-this-run.json") -Encoding UTF8
  $stage = "verify_uninstall"
  Wait-NativeUninstallTerminal -AgentProcessId $agentProcessId -Finalizers $finalizersThisRun -DeadlineUtc $uninstallDeadlineUtc -ReceiptBefore $nativeFailureBefore
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
  try { Write-UninstallDiagnostics -Reason $_.Exception.Message } catch {
    [pscustomobject]@{ reason = "diagnostic wrapper failure"; error = $_.Exception.Message } |
      ConvertTo-Json | Set-Content -LiteralPath (Join-Path $EvidenceDir "uninstall-diagnostics-errors.json") -Encoding UTF8
  }
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
