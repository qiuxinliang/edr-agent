#Requires -Version 5.1
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)] [string] $BaselineSetupExe,
  [Parameter(Mandatory = $true)] [string] $TargetSetupExe,
  [Parameter(Mandatory = $true)] [string] $BaselineVersion,
  [Parameter(Mandatory = $true)] [string] $TargetVersion,
  [Parameter(Mandatory = $true)]
  [ValidateSet("amd64", "arm64")]
  [string] $Architecture,
  [string] $InstallDir = "C:\edr-agent-setup-lifecycle-smoke",
  [string] $ServiceName = "FDSecurityAgent",
  [string] $EvidenceDir = "setup-exe-evidence",
  [Parameter(Mandatory = $true)] [string] $UpgradeInput,
  [Parameter(Mandatory = $true)] [string] $BaselineConfigTemplate,
  [switch] $ExerciseInstallerTimeout,
  [switch] $SkipSetupRollback
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'Start-LifecycleWindowsPowerShell.ps1')
$archVerifier = Join-Path $PSScriptRoot "Assert-WindowsPeArchitecture.ps1"
$bootstrapVerifier = Join-Path $PSScriptRoot "Assert-WindowsInstallerBootstrapArchitecture.ps1"
$BaselineSetupExe = (Resolve-Path -LiteralPath $BaselineSetupExe).Path
$TargetSetupExe = (Resolve-Path -LiteralPath $TargetSetupExe).Path
$InstallDir = [IO.Path]::GetFullPath($InstallDir)
$EvidenceDir = [IO.Path]::GetFullPath($EvidenceDir)
New-Item -ItemType Directory -Path $EvidenceDir -Force | Out-Null

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw "Setup EXE lifecycle smoke must run elevated"
}
if ($InstallDir -notmatch '^C:\\edr-agent-setup-lifecycle-[A-Za-z0-9._-]+$') {
  throw "Refusing unsafe lifecycle install directory: $InstallDir"
}
if (Test-Path -LiteralPath $InstallDir) {
  throw "Lifecycle install directory already exists; use a clean runner: $InstallDir"
}

& $bootstrapVerifier -Path $BaselineSetupExe -PayloadArchitecture $Architecture
& $bootstrapVerifier -Path $TargetSetupExe -PayloadArchitecture $Architecture

$events = New-Object System.Collections.Generic.List[object]
function Add-Evidence([string] $Stage, [string] $Status, [string] $Detail) {
  $events.Add([ordered]@{
    at = [DateTime]::UtcNow.ToString("o")
    stage = $Stage
    status = $Status
    detail = $Detail
  }) | Out-Null
}
function Copy-InstallerDiagnostics([string] $Stage, [string] $SetupLog) {
  # Evidence collection must never hide the original installer failure.
  try {
    if (Test-Path -LiteralPath $SetupLog -PathType Leaf) {
      Write-Host "--- $Stage Inno Setup log tail ---"
      Get-Content -LiteralPath $SetupLog -Tail 120 | ForEach-Object { Write-Host $_ }
    } else {
      Write-Warning "$Stage did not create its requested Inno Setup log: $SetupLog"
    }

    $diagnosticsRoot = Join-Path $env:ProgramData "FDSecurity\setup-ui\agent-diagnostics"
    if (Test-Path -LiteralPath $diagnosticsRoot -PathType Container) {
      $stageDiagnostics = Join-Path $EvidenceDir ($Stage + ".agent-diagnostics")
      New-Item -ItemType Directory -Path $stageDiagnostics -Force | Out-Null
      Get-ChildItem -LiteralPath $diagnosticsRoot -Force -ErrorAction SilentlyContinue | ForEach-Object {
        Copy-Item -LiteralPath $_.FullName -Destination $stageDiagnostics -Recurse -Force -ErrorAction SilentlyContinue
      }
      $stageLog = Join-Path $diagnosticsRoot "install-stage.log"
      if (Test-Path -LiteralPath $stageLog -PathType Leaf) {
        Write-Host "--- $Stage Agent install-stage.log ---"
        Get-Content -LiteralPath $stageLog -Tail 120 | ForEach-Object { Write-Host $_ }
      }
    } elseif ($Stage -like "uninstall-*") {
      # A successful uninstaller removes ProgramData setup diagnostics by
      # contract. The requested Inno log above remains the authoritative
      # failure evidence if a later residue assertion fails.
      Write-Host "$Stage removed Agent installer diagnostics as expected: $diagnosticsRoot"
    } else {
      Write-Warning "$Stage did not create Agent installer diagnostics: $diagnosticsRoot"
    }

    $diagnosticsBundle = Join-Path $env:ProgramData "FDSecurity\setup-ui\install-diagnostics.zip"
    if (Test-Path -LiteralPath $diagnosticsBundle -PathType Leaf) {
      Copy-Item -LiteralPath $diagnosticsBundle `
        -Destination (Join-Path $EvidenceDir ($Stage + ".install-diagnostics.zip")) -Force
    }
  } catch {
    Write-Warning ("Unable to collect diagnostics for {0}: {1}" -f $Stage, $_.Exception.Message)
  }
}
function Invoke-Installer([string] $Path, [string] $Stage, [bool] $UpgradeExisting) {
  $log = Join-Path $EvidenceDir ($Stage + ".setup.log")
  $script:LastLifecycleStage = $Stage
  $script:LastSetupLog = $log
  $arguments = @(
    "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/SP-",
    # Preserve the supported 673 caller contract: the new installer must derive
    # its local floor even when an old embedded updater sends no new argument.
    ('/DIR="{0}"' -f $InstallDir),
    '/TASKS="windowsservice"',
    ('/LOG="{0}"' -f $log)
  )
  if ($UpgradeExisting) { $arguments += "/EDR_UPGRADE_EXISTING=1" }
  Add-Evidence $Stage "started" $Path
  $process = Start-Process -FilePath $Path -ArgumentList $arguments -Wait -PassThru
  if ($process.ExitCode -ne 0) {
    throw "Setup EXE stage '$Stage' failed with exit code $($process.ExitCode); log=$log"
  }
  Add-Evidence $Stage "completed" "exit_code=0"
}
function Invoke-BaselineRepair([string] $Path, [string] $Stage, [string] $BackupDir) {
  $log = Join-Path $EvidenceDir ($Stage + ".setup.log")
  $script:LastLifecycleStage = $Stage
  $script:LastSetupLog = $log
  $arguments = @(
    "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/SP-",
    ('/DIR="{0}"' -f $InstallDir),
    '/TASKS="windowsservice"',
    '/EDR_REPAIR_BASELINE=1',
    ('/EDR_REPAIR_BACKUP_DIR="{0}"' -f $BackupDir),
    '/EDR_KEEP_OFFLINE_QUEUE=1', '/EDR_KEEP_EVIDENCE_CACHE=1',
    ('/LOG="{0}"' -f $log)
  )
  Add-Evidence $Stage "started" "repairing missing Inno lifecycle baseline"
  $process = Start-Process -FilePath $Path -ArgumentList $arguments -Wait -PassThru
  if ($process.ExitCode -ne 0) {
    throw "Setup EXE baseline repair '$Stage' failed with exit code $($process.ExitCode); log=$log"
  }
  Add-Evidence $Stage "completed" "exit_code=0"
}
function New-BaselineRepairBackup([string] $BackupDirectory) {
  if (Test-Path -LiteralPath $BackupDirectory) {
    Remove-Item -LiteralPath $BackupDirectory -Recurse -Force
  }
  New-Item -ItemType Directory -Path $BackupDirectory -Force | Out-Null

  # Repair authorization requires the protected Agent and its identity config.
  # Do not recursively read hardened runtime-data or collector directories from
  # the lifecycle harness; their ACL isolation is a separate security contract.
  foreach ($name in @("FDSensor.exe", "agent.toml")) {
    $source = Join-Path $InstallDir $name
    $backupPath = Join-Path $BackupDirectory $name
    $item = Get-Item -LiteralPath $source -Force -ErrorAction Stop
    if ($item.PSIsContainer -or
        (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
      throw "repair backup source is not a regular file: $source"
    }
    $expectedHash = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
    Copy-Item -LiteralPath $source -Destination $backupPath -Force
    if ((Get-FileHash -LiteralPath $backupPath -Algorithm SHA256).Hash -ne $expectedHash) {
      throw "repair backup hash mismatch: $name"
    }
  }
}
function Assert-BaselineRepair([string] $SetupPath) {
  $stage = "repair-baseline"
  $backupDir = Join-Path $EvidenceDir "repair-baseline-backup"
  # Use the legacy root-level database names that the cleanup stage also
  # manages.  The repair workflow intentionally hardens queue/ and evidence/
  # to SYSTEM/Administrators only, so reading arbitrary markers inside those
  # directories from the unelevated CI parent would test ACL enforcement, not
  # preservation.  These files still exercise the real keep-queue/evidence
  # branches and remain readable under the hardened install-root RX ACL.
  $queueMarker = Join-Path $InstallDir "edr_queue.db.baseline-repair-preserve"
  $evidenceMarker = Join-Path $InstallDir "local_evidence_cache.db.baseline-repair-preserve"
  [IO.File]::WriteAllText($queueMarker, "queue-preserve", [Text.UTF8Encoding]::new($false))
  [IO.File]::WriteAllText($evidenceMarker, "evidence-preserve", [Text.UTF8Encoding]::new($false))
  $configPath = Join-Path $InstallDir "agent.toml"
  $configHash = (Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash

  Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
  Get-Process -Name "FDSensor" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
  New-BaselineRepairBackup $backupDir
  foreach ($name in @("unins000.exe", "unins000.dat")) {
    Remove-Item -LiteralPath (Join-Path $InstallDir $name) -Force
    if (Test-Path -LiteralPath (Join-Path $InstallDir $name)) { throw "$stage could not remove $name from the repair fixture" }
  }

  Invoke-BaselineRepair $SetupPath $stage $backupDir
  Assert-InstalledRuntime $BaselineVersion $stage
  if ((Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash -ne $configHash) {
    throw "$stage modified protected agent.toml"
  }
  if ([IO.File]::ReadAllText($queueMarker) -ne "queue-preserve" -or
      [IO.File]::ReadAllText($evidenceMarker) -ne "evidence-preserve") {
    throw "$stage did not preserve queue/evidence data"
  }
  Add-Evidence $stage "verified" "uninstaller_restored=true identity_preserved=true queue_preserved=true evidence_preserved=true"
  Remove-Item -LiteralPath $backupDir -Recurse -Force
}
function Assert-InstalledRuntime(
  [string] $ExpectedVersion,
  [string] $Stage,
  [bool] $RequireModernLifecycleAssets = $true,
  [bool] $RequireBuiltinCollector = $false
) {
  $versionPath = Join-Path $InstallDir "VERSION"
  if (-not (Test-Path -LiteralPath $versionPath -PathType Leaf)) {
    throw "$Stage did not install VERSION"
  }
  $actualVersion = ([IO.File]::ReadAllText($versionPath)).Trim()
  if ($actualVersion -ne $ExpectedVersion) {
    throw "$Stage version mismatch: expected=$ExpectedVersion actual=$actualVersion"
  }
  foreach ($name in @("FDSensor.exe", "FDSecurityInstallerWorker.exe")) {
    $path = Join-Path $InstallDir $name
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "$Stage is missing $name" }
    & $archVerifier -Path $path -Architecture $Architecture
  }
  if ($RequireBuiltinCollector) {
    $builtinCollector = Join-Path $InstallDir "collector\forensic_collector_builtin.exe"
    if (-not (Test-Path -LiteralPath $builtinCollector -PathType Leaf)) {
      throw "$Stage is missing collector\forensic_collector_builtin.exe"
    }
    & $archVerifier -Path $builtinCollector -Architecture $Architecture
  }
  foreach ($name in @("package-capabilities.json", "unins000.exe")) {
    if (-not (Test-Path -LiteralPath (Join-Path $InstallDir $name) -PathType Leaf)) {
      throw "$Stage is missing $name"
    }
  }
  $capabilities = [IO.File]::ReadAllText((Join-Path $InstallDir "package-capabilities.json")) | ConvertFrom-Json
  if ([string]$capabilities.target_arch -ne $Architecture) {
    throw "$Stage package capability architecture mismatch: $($capabilities.target_arch)"
  }
  if ($RequireModernLifecycleAssets) {
    foreach ($name in @("uninstall.exe", "native-package-integrity.json")) {
      if (-not (Test-Path -LiteralPath (Join-Path $InstallDir $name) -PathType Leaf)) {
        throw "$Stage is missing modern lifecycle asset $name"
      }
    }
  }
  $deadline = (Get-Date).AddSeconds(60)
  do {
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    $runtime = Get-Process -Name "FDSensor" -ErrorAction SilentlyContinue
    if ($service -and $service.Status -eq "Running" -and $runtime) { break }
    Start-Sleep -Milliseconds 500
  } while ((Get-Date) -lt $deadline)
  if (-not $service -or $service.Status -ne "Running" -or -not $runtime) {
    throw "$Stage did not leave the Agent service and process healthy"
  }
  Add-Evidence $Stage "verified" "version=$actualVersion service=running process=running"
}
function Invoke-UninstallerAndAssertCleanup([string] $Stage) {
  $uninstaller = Join-Path $InstallDir "unins000.exe"
  $uninstallLog = Join-Path $EvidenceDir ($Stage + ".setup.log")
  $script:LastLifecycleStage = $Stage
  $script:LastSetupLog = $uninstallLog
  if (-not (Test-Path -LiteralPath $uninstaller -PathType Leaf)) {
    throw "$Stage is missing the Inno Setup uninstaller: $uninstaller"
  }
  Add-Evidence $Stage "started" $uninstaller
  $uninstallProcess = Start-Process -FilePath $uninstaller -ArgumentList @(
    "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", ('/LOG="{0}"' -f $uninstallLog)
  ) -Wait -PassThru
  if ($uninstallProcess.ExitCode -ne 0) {
    throw "$Stage failed with exit code $($uninstallProcess.ExitCode); log=$uninstallLog"
  }
  $deadline = (Get-Date).AddSeconds(120)
  do {
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    $runtime = Get-Process -Name "FDSensor" -ErrorAction SilentlyContinue
    $installEntries = @()
    if (Test-Path -LiteralPath $InstallDir -PathType Container) {
      $installEntries = @(Get-ChildItem -LiteralPath $InstallDir -Force -ErrorAction SilentlyContinue | Select-Object -First 1)
    }
    if (-not $service -and -not $runtime -and $installEntries.Count -eq 0) { break }
    Start-Sleep -Seconds 1
  } while ((Get-Date) -lt $deadline)
  if ($service -or $runtime -or (Test-Path -LiteralPath $InstallDir)) {
    $residue = @()
    if (Test-Path -LiteralPath $InstallDir -PathType Container) {
      $residue = @(Get-ChildItem -LiteralPath $InstallDir -Force -Recurse -ErrorAction SilentlyContinue |
        ForEach-Object {
          $relative = $_.FullName.Substring($InstallDir.TrimEnd('\').Length).TrimStart('\')
          if ($_.PSIsContainer) { $relative + '\' } else { $relative }
        })
      $residuePath = Join-Path $EvidenceDir ($Stage + ".install-dir-residue.txt")
      [IO.File]::WriteAllLines($residuePath, [string[]]$residue, [Text.UTF8Encoding]::new($false))
      Write-Host "--- $Stage install directory residue ---"
      $residue | ForEach-Object { Write-Host $_ }
    }
    if ($service -or $runtime -or $residue.Count -gt 0) {
      throw "$Stage residue: service=$([bool]$service) process=$([bool]$runtime) install_dir=$([bool](Test-Path -LiteralPath $InstallDir)) entries=$($residue -join '|')"
    }
    Write-Host "$Stage left an empty install directory; runtime removal is complete and the empty container is non-blocking: $InstallDir"
  }
  Add-Evidence $Stage "verified" "service_removed=true process_stopped=true product_residue=none"
}

function Initialize-LifecycleOfflineConfig([string] $TemplatePath) {
  # The baseline only materializes its embedded updater while building its
  # capability manifest or handling an update command. A configured loopback
  # HTTPS endpoint enables that normal local capability path without a backend.
  # Prepare this before Setup starts the Agent; transport is not hot-reloaded.
  $configPath = Join-Path $InstallDir 'agent.toml'
  if (Test-Path -LiteralPath $configPath) { throw 'offline lifecycle configuration already exists' }
  $template = Get-Item -LiteralPath $TemplatePath -ErrorAction Stop
  if ($template.PSIsContainer -or $template.Length -le 0 -or $template.Length -gt 131072) {
    throw 'offline lifecycle configuration template must be a bounded nonempty file'
  }
  $config = [IO.File]::ReadAllText($template.FullName)
  $templateHash = (Get-FileHash -LiteralPath $template.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
  foreach ($section in @('agent', 'platform')) {
    if ([regex]::Matches($config, ('(?m)^\[' + $section + '\]\s*(?:#.*)?$')).Count -ne 1) {
      throw "offline lifecycle configuration requires one active $section section"
    }
  }
  $endpoint = 'ci-setup-lifecycle-' + [Guid]::NewGuid().ToString('N')
  foreach ($pair in @(@('endpoint_id', $endpoint), @('tenant_id', 'ci-lifecycle'),
      @('rest_base_url', 'https://127.0.0.1:9/api/v1'), @('proxy_mode', 'off'),
      @('proxy_url', ''), @('relay_url', ''))) {
    $pattern = '(?m)^' + [regex]::Escape($pair[0]) + '\s*=\s*"[^"\r\n]*"'
    if ([regex]::Matches($config, $pattern).Count -ne 1) {
      throw "offline lifecycle configuration requires one active $($pair[0]) field"
    }
    $config = [regex]::Replace($config, $pattern, ($pair[0] + ' = "' + $pair[1] + '"'))
  }
  $config = $config.Replace('C:\\Program Files\\FDSecurity', $InstallDir.Replace('\', '\\'))
  New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
  $bytes = [Text.UTF8Encoding]::new($false).GetBytes($config)
  $stream = [IO.File]::Open($configPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
  try { $stream.Write($bytes, 0, $bytes.Length) } finally { $stream.Dispose() }
  $configHash = (Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash.ToLowerInvariant()
  Add-Evidence 'old-updater-offline-config' 'prepared' ("template_sha256={0} config_sha256={1} rest_base_url=https://127.0.0.1:9/api/v1 proxy_mode=off" -f $templateHash, $configHash)
  return $configHash
}

function Wait-LifecycleEmbeddedUpdater([string] $Version, [string] $ExpectedSha256) {
  $path = Join-Path $InstallDir ("edr_agent_inplace_update-{0}.ps1" -f $Version)
  $clock = [Diagnostics.Stopwatch]::StartNew()
  while ($clock.Elapsed.TotalSeconds -lt 60) {
    if (Test-Path -LiteralPath $path -PathType Leaf) {
      if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $ExpectedSha256) {
        throw "installed $Version embedded updater differs from its immutable release"
      }
      return $path
    }
    Start-Sleep -Milliseconds 500
  }
  throw "installed $Version did not materialize its original embedded updater within 60 seconds"
}

function Assert-LifecycleUpgradeResult($InputBinding, $Report) {
  if ($Report.status -cne 'succeeded' -or $Report.target_version -cne $InputBinding.target_version -or
      $Report.upgrade_class -cne $InputBinding.upgrade_class -or $Report.operation -cne 'upgrade' -or
      $Report.expected_sha256 -cne $InputBinding.binary_sha256 -or
      $Report.installed_sha256 -cne $InputBinding.binary_sha256) {
    throw 'old embedded updater did not report the exact target upgrade as succeeded'
  }
  foreach ($item in @(
      @{ Name = 'FDSensor.exe'; Sha256 = $InputBinding.binary_sha256 },
      @{ Name = 'native-package-integrity.json'; Sha256 = $InputBinding.runtime_identity_sha256 }
    )) {
    $actual = (Get-FileHash -LiteralPath (Join-Path $InstallDir $item.Name) -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -cne $item.Sha256) { throw "old updater installed an unexpected $($item.Name)" }
  }
  $native = Get-Content -LiteralPath (Join-Path $InstallDir 'native-package-integrity.json') -Raw | ConvertFrom-Json
  foreach ($item in $native.files) {
    $actual = (Get-FileHash -LiteralPath (Join-Path $InstallDir $item.name) -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -cne $item.sha256) { throw "old updater left a mixed native runtime: $($item.name)" }
  }
}

function Get-LifecycleTrustedPublisher($InputBinding) {
  if ($InputBinding.signature_status -cnotin @('unsigned','signed')) {
    throw 'lifecycle release signature policy is missing or unsupported'
  }
  if ($InputBinding.signature_status -ceq 'signed' -and
      ($InputBinding.publisher_thumbprint -cnotmatch '^[A-F0-9]{40}$' -or
       [string]::IsNullOrWhiteSpace($InputBinding.publisher_subject))) {
    throw 'signed lifecycle release is missing its pinned publisher identity'
  }
  if ($InputBinding.signature_status -ceq 'unsigned' -and
      ($InputBinding.publisher_thumbprint -or $InputBinding.publisher_subject)) {
    throw 'unsigned lifecycle release contains a publisher identity'
  }
  $paths = @([pscustomobject]@{Path=$InputBinding.binary_path;Sha256=$InputBinding.binary_sha256})
  if ($InputBinding.upgrade_class -ceq 'installer_required') {
    if (-not $InputBinding.installer_path) { throw 'full-installer lifecycle signature input is missing' }
    $paths += [pscustomobject]@{Path=$InputBinding.installer_path;Sha256=$InputBinding.installer_sha256}
  }
  foreach ($item in $paths) {
    if ((Get-FileHash -LiteralPath $item.Path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $item.Sha256) {
      throw 'lifecycle signature input no longer matches the release hash'
    }
    $signature = Get-AuthenticodeSignature -LiteralPath $item.Path -ErrorAction Stop
    if ($InputBinding.signature_status -ceq 'unsigned') {
      if ([string]$signature.Status -cne 'NotSigned' -or $signature.SignerCertificate) {
        throw "unsigned lifecycle release requires NotSigned, got $($signature.Status)"
      }
    } else {
      if ([string]$signature.Status -cne 'Valid' -or -not $signature.SignerCertificate) {
        throw "signed lifecycle release requires Valid, got $($signature.Status)"
      }
      $thumbprint = ($signature.SignerCertificate.Thumbprint -replace '\s','').ToUpperInvariant()
      if ($thumbprint -cne $InputBinding.publisher_thumbprint -or
          $signature.SignerCertificate.Subject -cne $InputBinding.publisher_subject) {
        throw 'lifecycle Authenticode publisher differs from the release publisher'
      }
    }
  }
  if ($InputBinding.signature_status -ceq 'unsigned') {
    return @{Thumbprint='SHA256_ONLY_UNSIGNED';Subject='Unsigned release; SHA-256 integrity only'}
  }
  return @{Thumbprint=$InputBinding.publisher_thumbprint;Subject=$InputBinding.publisher_subject}
}

function Invoke-BaselineUpdaterUpgrade($InputBinding) {
  $script:LastLifecycleStage = 'old-updater-upgrade'
  if ($InputBinding.schema -cne 'edr.windows.lifecycle-upgrade.v1' -or
      $InputBinding.baseline_version -cne $BaselineVersion -or $InputBinding.target_version -cne $TargetVersion -or
      $InputBinding.architecture -cne $Architecture -or $InputBinding.deployment_mode -cne 'service' -or
      $InputBinding.service_name -cne $ServiceName) { throw 'old updater lifecycle input identity/mode mismatch' }
  $updater = Wait-LifecycleEmbeddedUpdater $BaselineVersion $InputBinding.baseline_updater_sha256
  $publisher = Get-LifecycleTrustedPublisher $InputBinding
  $commandId = 'ci-old-updater-' + [Guid]::NewGuid().ToString('N')
  $issued = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
  $parameters = [ordered]@{
    InstallDir = $InstallDir; StagedBinary = $InputBinding.binary_path
    ExpectedSha256 = $InputBinding.binary_sha256; TargetVersion = $TargetVersion
    ExpectedArchitecture = $(if ($Architecture -eq 'amd64') { 'x64' } else { 'arm64' })
    TrustedPublisherThumbprint = $publisher.Thumbprint; TrustedPublisherSubject = $publisher.Subject
    DeploymentMode = $InputBinding.deployment_mode; ServiceName = $ServiceName
    CommandId = $commandId; TaskId = $commandId; ArtifactId = "ci-$TargetVersion-$Architecture"
    Operation = 'upgrade'; UpgradeClass = $InputBinding.upgrade_class
    IssuedAtUnixMs = $issued; DeadlineUnixMs = $issued + 900000
    HealthObserveMs = 30000; StartupTimeoutSeconds = 60
    MinCurrentVersion = $InputBinding.min_current_version; MaxCurrentVersion = $InputBinding.max_current_version
    MinFreeBytes = $InputBinding.min_free_bytes
  }
  if ($InputBinding.runtime_package) {
    $parameters.RuntimeManifest = $InputBinding.runtime_package
    $parameters.RuntimeManifestSha256 = $InputBinding.runtime_package_sha256
  }
  # Use Windows PowerShell 5.1, as the Agent's real detached updater does. No
  # current-source script or patched baseline script enters this invocation.
  $entries = @($parameters.GetEnumerator() | ForEach-Object {
    "'{0}'='{1}'" -f $_.Key, ([string]$_.Value).Replace("'", "''")
  })
  $source = "`$ErrorActionPreference='Stop'; `$parameters=@{" + ($entries -join ';') + "}; & '" + $updater.Replace("'", "''") + "' @parameters; exit `$LASTEXITCODE"
  $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($source))
  $reportPath = Join-Path $env:ProgramData ("FDSecurity\logs\agent-update-{0}-report.json" -f $commandId)
  Add-Evidence 'old-updater-upgrade' 'started' ("command_id={0} class={1} mode={2} baseline_updater_sha256={3}" -f $commandId, $InputBinding.upgrade_class, $InputBinding.deployment_mode, $InputBinding.baseline_updater_sha256)
  $process = Start-LifecycleWindowsPowerShell -EncodedCommand $encoded `
    -StandardOutput (Join-Path $EvidenceDir 'old-updater.stdout.log') `
    -StandardError (Join-Path $EvidenceDir 'old-updater.stderr.log')
  try {
    $null = $process.Handle
    if (-not $process.WaitForExit(600000)) {
      $process.Kill()
      [void]$process.WaitForExit(5000)
      throw 'old embedded updater exceeded the 600 second lifecycle budget'
    }
    $process.WaitForExit()
    if ($null -eq $process.ExitCode -or $process.ExitCode -ne 0) { throw "old embedded updater failed with exit code $($process.ExitCode)" }
    $report = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
    Assert-LifecycleUpgradeResult $InputBinding $report
    $null = Wait-LifecycleEmbeddedUpdater $TargetVersion $InputBinding.target_updater_sha256
    Add-Evidence 'old-updater-upgrade' 'verified' ("class={0} target_updater_sha256={1} native_runtime_verified=true" -f $InputBinding.upgrade_class, $InputBinding.target_updater_sha256)
  } finally {
    try {
      if (Test-Path -LiteralPath $reportPath -PathType Leaf) {
        Copy-Item -LiteralPath $reportPath -Destination (Join-Path $EvidenceDir 'old-updater-report.json')
      }
      $journalPath = Join-Path $env:ProgramData ("FDSecurity\state\agent-update-{0}.journal.json" -f $commandId)
      if (Test-Path -LiteralPath $journalPath -PathType Leaf) {
        Copy-Item -LiteralPath $journalPath -Destination (Join-Path $EvidenceDir 'old-updater-journal.json')
      }
    } catch { Write-Warning ("Unable to retain old updater report: " + $_.Exception.Message) }
    $process.Dispose()
  }
}

$status = "failed"
$script:LastLifecycleStage = "lifecycle"
$script:LastSetupLog = ""
try {
  # Validate the target independently first. A broken historical baseline must
  # not hide whether the candidate can install and uninstall on a clean host.
  Invoke-Installer $TargetSetupExe "install-target-fresh" $false
  Assert-InstalledRuntime $TargetVersion "install-target-fresh" $true $true
  Invoke-UninstallerAndAssertCleanup "uninstall-target-fresh"

  # Start with the immutable old Setup and the updater materialized by that
  # actual old Agent. Keep the separate direct-Setup path below unchanged.
  $upgradeBinding = Get-Content -LiteralPath $UpgradeInput -Raw | ConvertFrom-Json
  $offlineConfigHash = Initialize-LifecycleOfflineConfig $BaselineConfigTemplate
  Invoke-Installer $BaselineSetupExe 'install-old-updater-baseline' $false
  Assert-InstalledRuntime $BaselineVersion 'install-old-updater-baseline' (-not $SkipSetupRollback)
  if ((Get-FileHash -LiteralPath (Join-Path $InstallDir 'agent.toml') -Algorithm SHA256).Hash.ToLowerInvariant() -cne $offlineConfigHash) {
    throw 'baseline Setup changed the prepared offline lifecycle configuration'
  }
  Invoke-BaselineUpdaterUpgrade $upgradeBinding
  Assert-InstalledRuntime $TargetVersion 'old-updater-upgrade' $true $true
  if ($ExerciseInstallerTimeout) {
    $script:LastLifecycleStage = 'candidate-installer-timeout'
    Add-Evidence 'candidate-installer-timeout' 'started' 'same-version repair with original candidate updater and Setup bytes'
    $candidateUpdater = Wait-LifecycleEmbeddedUpdater $TargetVersion $upgradeBinding.target_updater_sha256
    $candidatePublisher = Get-LifecycleTrustedPublisher $upgradeBinding
    & (Join-Path $repoRoot 'tests\Invoke-RealInstallerTimeoutRecovery.ps1') -InputBinding $upgradeBinding `
      -InstallDir $InstallDir -EvidenceDir $EvidenceDir -Updater $candidateUpdater -Publisher $candidatePublisher
    Assert-InstalledRuntime $TargetVersion 'candidate-installer-timeout' $true $true
    Add-Evidence 'candidate-installer-timeout' 'verified' 'original Setup timed out; Job empty; runtime/config/service/uninstall identity restored; queue/evidence marker bytes preserved'
  }
  Invoke-UninstallerAndAssertCleanup 'uninstall-old-updater-target'

  # Then verify the cross-version compatibility path using a baseline that is
  # freshly installed and validated in this same native-runner job.
  Invoke-Installer $BaselineSetupExe "install-baseline" $false
  Assert-InstalledRuntime $BaselineVersion "install-baseline" (-not $SkipSetupRollback)
  Assert-BaselineRepair $BaselineSetupExe
  Invoke-Installer $TargetSetupExe "upgrade-target" $true
  Assert-InstalledRuntime $TargetVersion "upgrade-target" $true $true
  if ($SkipSetupRollback) {
    Add-Evidence "rollback-baseline" "skipped" "legacy baseline predates the immutable full-Setup rollback contract; native runtime rollback remains mandatory"
    Invoke-UninstallerAndAssertCleanup "uninstall-after-upgrade"
  } else {
    Invoke-Installer $BaselineSetupExe "rollback-baseline" $true
    Assert-InstalledRuntime $BaselineVersion "rollback-baseline"
    Invoke-UninstallerAndAssertCleanup "uninstall-after-rollback"
  }
  $status = "succeeded"
} catch {
  $lifecycleFailure = $_
  Copy-InstallerDiagnostics -Stage $script:LastLifecycleStage -SetupLog $script:LastSetupLog
  Add-Evidence "lifecycle" "failed" $lifecycleFailure.Exception.Message
  throw $lifecycleFailure
} finally {
  # PowerShell 7 can throw "Argument types do not match" when a generic
  # List[object] is expanded with @($list) inside an ordered hashtable. Convert
  # it explicitly so summary serialization cannot mask the lifecycle result.
  [object[]]$eventArray = $events.ToArray()
  $summary = [ordered]@{
    schema = "edr.agent.setup-exe.lifecycle.v1"
    completed_at = [DateTime]::UtcNow.ToString("o")
    status = $status
    architecture = $Architecture
    baseline_version = $BaselineVersion
    target_version = $TargetVersion
    setup_rollback_skipped = [bool]$SkipSetupRollback
    installer_timeout_requested = [bool]$ExerciseInstallerTimeout
    install_dir = $InstallDir
    events = $eventArray
  }
  [IO.File]::WriteAllText(
    (Join-Path $EvidenceDir "summary.json"),
    ($summary | ConvertTo-Json -Depth 8),
    (New-Object Text.UTF8Encoding($false))
  )
}
