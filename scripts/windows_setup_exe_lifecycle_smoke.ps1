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
  [ValidateSet('service','scheduled_task')] [string] $RuntimeMode = 'service',
  [string] $EvidenceDir = "setup-exe-evidence",
  [Parameter(Mandatory = $true)] [string] $UpgradeInput,
  [Parameter(Mandatory = $true)] [string] $BaselineConfigTemplate,
  [switch] $ExerciseInstallerTimeout,
  [switch] $SkipSetupRollback,
  [switch] $SignedPublisherValidation,
  [string] $LegacySetupExe = '',
  [string] $LegacyVersion = '',
  [string] $MigrationInput = '',
  [string] $StorageToolsInput = ''
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
if ($SignedPublisherValidation) {
  if ($env:GITHUB_ACTIONS -cne 'true' -or -not $LegacySetupExe -or -not $MigrationInput -or
      $LegacyVersion -cne '3.2.723' -or [version]$BaselineVersion -ge [version]$TargetVersion -or
      [version]$LegacyVersion -ge [version]$BaselineVersion -or $SkipSetupRollback -or -not $StorageToolsInput) {
    throw 'signed publisher validation requires disposable CI, original 3.2.723, two increasing candidates, storage consumer tools and full rollback'
  }
  $LegacySetupExe = (Resolve-Path -LiteralPath $LegacySetupExe).Path
  & $bootstrapVerifier -Path $LegacySetupExe -PayloadArchitecture $Architecture
  . (Join-Path $repoRoot 'tests\Invoke-LifecycleStorageCompatibility.ps1')
  $storageTools=Import-LifecycleStorageTools $StorageToolsInput $Architecture $archVerifier
} elseif ($LegacySetupExe -or $LegacyVersion -or $MigrationInput -or $StorageToolsInput) {
  throw 'legacy migration inputs require signed publisher validation'
}
if ($RuntimeMode -ceq 'scheduled_task' -and -not $SignedPublisherValidation) {
  throw 'scheduled-task lifecycle requires the explicitly bound signed validation path'
}

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
    ('/TASKS="{0}"' -f $(if($RuntimeMode -ceq 'scheduled_task'){'windowsautorun'}else{'windowsservice'})),
    ('/LOG="{0}"' -f $log)
  )
  if ($UpgradeExisting) { $arguments += "/EDR_UPGRADE_EXISTING=1" }
  Add-Evidence $Stage "started" $Path
  $process = Start-LifecycleWindowsProcess -ProcessParameters @{
    FilePath=$Path;ArgumentList=$arguments;Wait=$true;PassThru=$true
  }
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
    ('/TASKS="{0}"' -f $(if($RuntimeMode -ceq 'scheduled_task'){'windowsautorun'}else{'windowsservice'})),
    '/EDR_REPAIR_BASELINE=1',
    ('/EDR_REPAIR_BACKUP_DIR="{0}"' -f $BackupDir),
    '/EDR_KEEP_OFFLINE_QUEUE=1', '/EDR_KEEP_EVIDENCE_CACHE=1',
    ('/LOG="{0}"' -f $log)
  )
  Add-Evidence $Stage "started" "repairing missing Inno lifecycle baseline"
  $process = Start-LifecycleWindowsProcess -ProcessParameters @{
    FilePath=$Path;ArgumentList=$arguments;Wait=$true;PassThru=$true
  }
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

  if ($RuntimeMode -ceq 'scheduled_task') {
    Stop-ScheduledTask -TaskName $ServiceName -TaskPath '\' -ErrorAction Stop
  } else {
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
  }
  $stopReceipt=Stop-LifecycleAgentProcesses
  Add-Evidence $stage 'processes-stopped' ('generation_bound=true wait_budget_seconds='+$stopReceipt.wait_budget_seconds+' remaining=0')
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
    $runtime = Get-LifecycleRuntimeProcess
    if ($runtime.State -ceq 'Running' -and $runtime.ProcessId -gt 0) { break }
    Start-Sleep -Milliseconds 500
  } while ((Get-Date) -lt $deadline)
  if ($runtime.State -cne 'Running' -or $runtime.ProcessId -le 0) {
    throw "$Stage did not leave the expected Agent runtime owner and process healthy"
  }
  $null=Get-LifecycleRuntimeOwner
  Add-Evidence $Stage "verified" "version=$actualVersion mode=$RuntimeMode owner=running process=running"
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
  $uninstallProcess = Start-LifecycleWindowsProcess -ProcessParameters @{
    FilePath=$uninstaller;ArgumentList=@(
      "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", ('/LOG="{0}"' -f $uninstallLog)
    );Wait=$true;PassThru=$true
  }
  if ($uninstallProcess.ExitCode -ne 0) {
    throw "$Stage failed with exit code $($uninstallProcess.ExitCode); log=$uninstallLog"
  }
  $deadline = (Get-Date).AddSeconds(120)
  do {
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    $task = Get-ScheduledTask -TaskName $ServiceName -TaskPath '\' -ErrorAction SilentlyContinue
    $runtime = @(Get-LifecycleAgentProcesses)
    $installEntries = @()
    if (Test-Path -LiteralPath $InstallDir -PathType Container) {
      $installEntries = @(Get-ChildItem -LiteralPath $InstallDir -Force -ErrorAction SilentlyContinue | Select-Object -First 1)
    }
    if (-not $service -and -not $task -and $runtime.Count -eq 0 -and $installEntries.Count -eq 0) { break }
    Start-Sleep -Seconds 1
  } while ((Get-Date) -lt $deadline)
  if ($service -or $task -or $runtime.Count -gt 0 -or (Test-Path -LiteralPath $InstallDir)) {
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
    if ($service -or $task -or $runtime.Count -gt 0 -or $residue.Count -gt 0) {
      throw "$Stage residue: service=$([bool]$service) task=$([bool]$task) process_count=$($runtime.Count) install_dir=$([bool](Test-Path -LiteralPath $InstallDir)) entries=$($residue -join '|')"
    }
    Write-Host "$Stage left an empty install directory; runtime removal is complete and the empty container is non-blocking: $InstallDir"
  }
  Add-Evidence $Stage "verified" "service_removed=true task_removed=true process_stopped=true product_residue=none"
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
  # The original cache query contract stores endpoint IDs in 48 bytes including
  # the terminator. Keep this synthetic identity within that installed boundary.
  $endpoint = 'ci-lifecycle-' + [Guid]::NewGuid().ToString('N')
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

function Assert-LifecyclePublisherProtocol([string] $Updater, [string] $ExpectedSha256, $Publisher) {
  if (-not $Publisher.SubjectDerSha256) { return }
  if ((Get-FileHash -LiteralPath $Updater -Algorithm SHA256).Hash.ToLowerInvariant() -cne $ExpectedSha256) {
    throw 'publisher protocol inspection requires the immutable installed updater'
  }
  $tokens=$null; $errors=$null
  $ast=[Management.Automation.Language.Parser]::ParseFile($Updater,[ref]$tokens,[ref]$errors)
  $declarations=@($ast.EndBlock.Statements | Where-Object {
    $_ -is [Management.Automation.Language.AssignmentStatementAst] -and
    $_.Left -is [Management.Automation.Language.VariableExpressionAst] -and
    $_.Left.VariablePath.UserPath -ceq 'AgentUpdateUpdaterProtocolVersion'
  })
  $parameters=@($ast.ParamBlock.Parameters | Where-Object {
    $_.Name.VariablePath.UserPath -ceq 'TrustedPublisherSubjectDerSha256'
  })
  if ($errors.Count -ne 0 -or $declarations.Count -ne 1 -or $parameters.Count -ne 1 -or
      $declarations[0].Right.Extent.Text -cnotmatch '^[0-9]+$' -or [int]$declarations[0].Right.Extent.Text -lt 6) {
    throw 'installed original updater does not declare publisher identity protocol 6'
  }
}

function Get-LifecycleTrustedPublisher($InputBinding) {
  $subjectDer = ''
  $verification = $null
  if ($InputBinding.PSObject.Properties['publisher_subject_der_sha256']) {
    $subjectDer = [string]$InputBinding.publisher_subject_der_sha256
  }
  if ($InputBinding.PSObject.Properties['publisher_verification']) {
    $verification = $InputBinding.publisher_verification
  }
  if ($InputBinding.signature_status -cnotin @('unsigned','signed')) {
    throw 'lifecycle release signature policy is missing or unsupported'
  }
  if ($InputBinding.signature_status -ceq 'signed' -and
      ($InputBinding.publisher_thumbprint -cnotmatch '^[A-F0-9]{40}$' -or
       [string]::IsNullOrWhiteSpace($InputBinding.publisher_subject))) {
    throw 'signed lifecycle release is missing its pinned publisher identity'
  }
  if ($InputBinding.signature_status -ceq 'unsigned' -and
      ($InputBinding.publisher_thumbprint -or $InputBinding.publisher_subject -or $subjectDer -or $verification)) {
    throw 'unsigned lifecycle release contains a publisher identity'
  }
  if ($subjectDer -or $verification) {
    if ($subjectDer -cnotmatch '^[a-f0-9]{64}$' -or -not $verification -or
        $verification.schema -cne 'edr.windows.publisher-verification.v1' -or
        $verification.version -cne $InputBinding.target_version -or $verification.arch -cne $InputBinding.architecture -or
        $verification.subject -cne $InputBinding.publisher_subject -or
        $verification.thumbprint -cne $InputBinding.publisher_thumbprint -or
        $verification.subject_der_sha256 -cne $subjectDer -or
        $verification.manifest_sha256 -cne $InputBinding.target_manifest_sha256 -or
        $verification.signature_sha256 -cne $InputBinding.target_signature_sha256 -or
        $verification.artifact_sha256 -cne $InputBinding.binary_sha256 -or
        $verification.verifier_source_commit -cnotmatch '^[a-f0-9]{40}$' -or
        -not $InputBinding.target_manifest_path -or -not $InputBinding.target_signature_path) {
      throw 'lifecycle publisher proof is not bound to the verified release'
    }
    foreach ($item in @(
        @{Path=$InputBinding.target_manifest_path;Hash=$verification.manifest_sha256},
        @{Path=$InputBinding.target_signature_path;Hash=$verification.signature_sha256})) {
      if ($item.Hash -cnotmatch '^[a-f0-9]{64}$' -or
          (Get-FileHash -LiteralPath $item.Path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $item.Hash) {
        throw 'lifecycle manifest or CMS differs from the verified publisher proof'
      }
    }
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
      if ($thumbprint -cne $InputBinding.publisher_thumbprint) {
        throw 'lifecycle Authenticode publisher differs from the release publisher'
      }
      if ($subjectDer) {
        [byte[]]$rawSubject=$signature.SignerCertificate.SubjectName.RawData
        if (-not $rawSubject -or $rawSubject.Length -eq 0) { throw 'lifecycle publisher subject DER is missing' }
        $hasher=[Security.Cryptography.SHA256]::Create()
        try { $actual=([BitConverter]::ToString($hasher.ComputeHash($rawSubject))).Replace('-','').ToLowerInvariant() }
        finally { $hasher.Dispose() }
        if ($actual -cne $subjectDer) { throw 'lifecycle Authenticode subject DER differs from the verified release publisher' }
      } elseif ($signature.SignerCertificate.Subject -cne $InputBinding.publisher_subject) {
        throw 'lifecycle Authenticode publisher differs from the release publisher'
      }
    }
  }
  if ($InputBinding.signature_status -ceq 'unsigned') {
    return @{Thumbprint='SHA256_ONLY_UNSIGNED';Subject='Unsigned release; SHA-256 integrity only';SubjectDerSha256=''}
  }
  return @{Thumbprint=$InputBinding.publisher_thumbprint;Subject=$InputBinding.publisher_subject;SubjectDerSha256=$subjectDer}
}

function Invoke-BaselineUpdaterUpgrade($InputBinding) {
  $script:LastLifecycleStage = 'old-updater-upgrade'
  if ($InputBinding.schema -cne 'edr.windows.lifecycle-upgrade.v1' -or
      $InputBinding.baseline_version -cne $BaselineVersion -or $InputBinding.target_version -cne $TargetVersion -or
      $InputBinding.architecture -cne $Architecture -or $InputBinding.deployment_mode -cne 'service' -or
      $InputBinding.service_name -cne $ServiceName) { throw 'old updater lifecycle input identity/mode mismatch' }
  $updater = Wait-LifecycleEmbeddedUpdater $BaselineVersion $InputBinding.baseline_updater_sha256
  $publisher = Get-LifecycleTrustedPublisher $InputBinding
  Assert-LifecyclePublisherProtocol $updater $InputBinding.baseline_updater_sha256 $publisher
  $commandId = 'ci-old-updater-' + [Guid]::NewGuid().ToString('N')
  # The original updater consumes StagedBinary on success. Keep the immutable
  # transition input for subsequent repair checks, while preserving its parent
  # directory for runtime-package resolution and installer extraction.
  $stagedBinary = Join-Path (Split-Path -Parent $InputBinding.binary_path) ($commandId + '.exe')
  Copy-Item -LiteralPath $InputBinding.binary_path -Destination $stagedBinary -ErrorAction Stop
  if ((Get-FileHash -LiteralPath $stagedBinary -Algorithm SHA256).Hash.ToLowerInvariant() -cne $InputBinding.binary_sha256) {
    throw 'old updater staging copy differs from the immutable release'
  }
  $issued = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
  $parameters = [ordered]@{
    InstallDir = $InstallDir; StagedBinary = $stagedBinary
    ExpectedSha256 = $InputBinding.binary_sha256; TargetVersion = $TargetVersion
    ExpectedArchitecture = $(if ($Architecture -eq 'amd64') { 'x64' } else { 'arm64' })
    TrustedPublisherThumbprint = $publisher.Thumbprint; TrustedPublisherSubject = $publisher.Subject
    DeploymentMode = $(if($RuntimeMode -ceq 'scheduled_task'){'auto'}else{$InputBinding.deployment_mode}); ServiceName = $ServiceName
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
  if ($publisher.SubjectDerSha256) {
    $parameters.TrustedPublisherSubjectDerSha256=$publisher.SubjectDerSha256
  }
  # Use Windows PowerShell 5.1, as the Agent's real detached updater does. No
  # current-source script or patched baseline script enters this invocation.
  $entries = @($parameters.GetEnumerator() | ForEach-Object {
    "'{0}'='{1}'" -f $_.Key, ([string]$_.Value).Replace("'", "''")
  })
  # Match agent_update_command.c: a normal script return can retain robocopy's
  # successful nonzero code; preserve explicit failed exits and exceptions.
  $source = "`$ErrorActionPreference='Stop'; `$parameters=@{" + ($entries -join ';') + "}; & '" + $updater.Replace("'", "''") + "' @parameters; `$updaterSucceeded=`$?; if (`$updaterSucceeded) { exit 0 }; if ((Test-Path variable:LASTEXITCODE) -and `$LASTEXITCODE -is [int] -and `$LASTEXITCODE -ne 0) { exit `$LASTEXITCODE }; exit 1"
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
    if ($RuntimeMode -ceq 'scheduled_task') {
      $journal=Get-Content -LiteralPath (Join-Path $env:ProgramData ("FDSecurity\state\agent-update-{0}.journal.json" -f $commandId)) -Raw | ConvertFrom-Json
      if ($journal.resolved_deployment_mode -cne 'scheduled_task') { throw 'auto upgrade did not retain the scheduled-task deployment' }
    }
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

function Get-LifecycleAgentProcesses {
  $expected=[IO.Path]::GetFullPath((Join-Path $InstallDir 'FDSensor.exe'))
  return @(Get-CimInstance Win32_Process -Filter "Name='FDSensor.exe'" -ErrorAction Stop | Where-Object {
    $_.ExecutablePath -and [IO.Path]::GetFullPath($_.ExecutablePath) -ieq $expected
  })
}

function Open-LifecycleAgentProcess($Snapshot) {
  $expected=[IO.Path]::GetFullPath((Join-Path $InstallDir 'FDSensor.exe'))
  if($Snapshot.ProcessId -le 0 -or $Snapshot.CreationDate -isnot [DateTime] -or
      [string]$Snapshot.ExecutablePath -ine $expected){throw 'invalid scoped Agent process snapshot'}
  $process=$null;$retained=$false
  try {
    try {
      $process=Get-Process -Id $Snapshot.ProcessId -ErrorAction Stop
      $null=$process.Handle
    } catch {
      $failure=$_;$cause=$failure.Exception
      while($cause.InnerException){$cause=$cause.InnerException}
      $missing=($cause.GetType().FullName -ceq 'Microsoft.PowerShell.Commands.ProcessCommandException' -and
        $failure.FullyQualifiedErrorId -ceq 'NoProcessFoundForGivenId,Microsoft.PowerShell.Commands.GetProcessCommand') -or
        ($cause -is [ComponentModel.Win32Exception] -and $cause.NativeErrorCode -eq 87)
      if($missing -and @(Get-CimInstance Win32_Process -Filter ('ProcessId='+$Snapshot.ProcessId) -ErrorAction Stop).Count -eq 0){return $null}
      throw
    }
    if($process.HasExited){return $null}
    try {
      if($process.Id -ne $Snapshot.ProcessId -or $process.Path -ine $expected -or
          [Math]::Abs(($process.StartTime.ToUniversalTime()-$Snapshot.CreationDate.ToUniversalTime()).Ticks) -gt 10){
        throw 'scoped Agent process generation or image changed'
      }
    } catch [InvalidOperationException] {
      if($process.HasExited){return $null}
      throw
    }
    $retained=$true
    return $process
  } finally {if($process -and -not $retained){$process.Dispose()}}
}

function Stop-LifecycleAgentProcesses {
  $clock=[Diagnostics.Stopwatch]::StartNew();$budgetMs=30000
  foreach($snapshot in @(Get-LifecycleAgentProcesses)) {
    $process=Open-LifecycleAgentProcess $snapshot
    if(-not $process){continue}
    try {
      if(-not $process.HasExited) {
        try {$process.Kill()} catch [InvalidOperationException] {if(-not $process.HasExited){throw}}
      }
      $remaining=$budgetMs-[int]$clock.ElapsedMilliseconds
      if($remaining -le 0 -or -not $process.WaitForExit($remaining)){throw 'scoped Agent stop exceeded the 30 second test budget'}
    } finally {$process.Dispose()}
  }
  if(@(Get-LifecycleAgentProcesses).Count -ne 0){throw 'scoped Agent processes remain after stop'}
  return [pscustomobject]@{wait_budget_seconds=30;remaining=0}
}

function Get-LifecycleUpdaterIdentity($UpdaterProcess) {
  if($UpdaterProcess -isnot [Diagnostics.Process]){throw 'storage preflight requires the owned updater Process'}
  $null=$UpdaterProcess.Handle
  if($UpdaterProcess.HasExited){throw 'storage preflight updater is no longer live'}
  $rows=@(Get-CimInstance Win32_Process -Filter ('ProcessId='+$UpdaterProcess.Id) -ErrorAction Stop)
  if($rows.Count -ne 1 -or $rows[0].CreationDate -isnot [DateTime] -or
      $rows[0].ExecutablePath -ine $UpdaterProcess.Path -or
      [Math]::Abs(($rows[0].CreationDate.ToUniversalTime()-$UpdaterProcess.StartTime.ToUniversalTime()).Ticks) -gt 10 -or
      $UpdaterProcess.HasExited){throw 'storage preflight updater parent generation is unverified'}
  return [pscustomobject]@{pid=$UpdaterProcess.Id;created_utc=$UpdaterProcess.StartTime.ToUniversalTime();image=$UpdaterProcess.Path}
}

function Get-LifecycleStoragePreflight($Snapshot,$UpdaterProcess) {
  $executable=[IO.Path]::GetFullPath((Join-Path $InstallDir 'FDSensor.exe'))
  $config=Join-Path $InstallDir 'agent.toml'
  $exePattern='"'+[regex]::Escape($executable)+'"'
  if($executable -notmatch '\s'){$exePattern='(?:'+$exePattern+'|'+[regex]::Escape($executable)+')'}
  $pattern='^(?i:'+ $exePattern +') --storage-space-preflight --config "(?i:'+ [regex]::Escape($config) +')" --output "(?<output>(?i:'+ [regex]::Escape($InstallDir.TrimEnd('\')) +')\\\.storage-preflight-[a-f0-9]{32}\\floor)"$'
  $match=[regex]::Match([string]$Snapshot.CommandLine,$pattern)
  if(-not $match.Success){return $null}
  $parent=Get-LifecycleUpdaterIdentity $UpdaterProcess
  if($Snapshot.ParentProcessId -ne $parent.pid -or $Snapshot.CreationDate -isnot [DateTime] -or
      $Snapshot.CreationDate.ToUniversalTime() -lt $parent.created_utc){throw 'storage preflight child parent generation is unverified'}
  $child=Open-LifecycleAgentProcess $Snapshot
  try {
    return [pscustomobject]@{role='storage_space_preflight';pid=[uint32]$Snapshot.ProcessId;parent_pid=$parent.pid;
      created_utc=$Snapshot.CreationDate.ToUniversalTime().ToString('o');updater_created_utc=$parent.created_utc.ToString('o');
      image=$executable;config=$config;output=$match.Groups['output'].Value;
      observation=$(if($child){'live'}else{'observed_then_exited'})}
  } finally {if($child){$child.Dispose()}}
}

function Get-LifecycleRuntimeProcess($UpdaterProcess=$null) {
  $service=Get-CimInstance Win32_Service -Filter ("Name='{0}'" -f $ServiceName) -ErrorAction Stop
  $agents=@(Get-LifecycleAgentProcesses)
  $preflights=New-Object 'System.Collections.Generic.List[object]'
  if($null -ne $UpdaterProcess) {
    $runtime=New-Object 'System.Collections.Generic.List[object]'
    foreach($agent in $agents) {
      $probe=Get-LifecycleStoragePreflight $agent $UpdaterProcess
      if($probe){$preflights.Add($probe)}else{$runtime.Add($agent)}
    }
    $agents=@($runtime.ToArray())
  }
  if ($agents.Count -gt 1) {
    $failure=[InvalidOperationException]::new('multiple Agent processes own the isolated install directory')
    $details=@($agents|Select-Object -First 8|ForEach-Object {
      [ordered]@{pid=$_.ProcessId;parent_pid=$_.ParentProcessId;created=$_.CreationDate;
        image=([string]$_.ExecutablePath).Substring(0,[Math]::Min(512,([string]$_.ExecutablePath).Length));role='runtime_candidate'}
    })
    $failure.Data['lifecycle_process_snapshot']=$details|ConvertTo-Json -Depth 4 -Compress
    throw $failure
  }
  $pidValue=if($agents.Count -eq 1){[uint32]$agents[0].ProcessId}else{0}
  if ($RuntimeMode -ceq 'scheduled_task') {
    if ($service) { throw 'scheduled-task validation found an unexpected service owner' }
    $task=Get-ScheduledTask -TaskName $ServiceName -TaskPath '\' -ErrorAction SilentlyContinue
    return [pscustomobject]@{State=$(if($task){[string]$task.State}else{'Absent'});ProcessId=$pidValue;StoragePreflightProcesses=$preflights.ToArray()}
  }
  if ($service -and $service.State -ceq 'Running' -and $pidValue -gt 0 -and $service.ProcessId -ne $pidValue) {
    throw 'service process does not own the isolated install directory'
  }
  return [pscustomobject]@{State=$(if($service){[string]$service.State}else{'Absent'});ProcessId=$pidValue;StoragePreflightProcesses=$preflights.ToArray()}
}

function Get-LifecycleTaskDefinition {
  $scheduler=New-Object -ComObject 'Schedule.Service'
  $scheduler.Connect()
  $registered=$scheduler.GetFolder('\').GetTask($ServiceName)
  return [pscustomobject]@{xml=[string]$registered.Xml;sddl=[string]$registered.GetSecurityDescriptor(7)}
}

function Get-LifecycleRuntimeOwner {
  $service=Get-CimInstance Win32_Service -Filter ("Name='{0}'" -f $ServiceName) -ErrorAction Stop
  if ($RuntimeMode -ceq 'scheduled_task') {
    if ($service) { throw 'scheduled-task validation found an unexpected service owner' }
    $task=Get-ScheduledTask -TaskName $ServiceName -TaskPath '\' -ErrorAction Stop
    $actions=@($task.Actions)
    $launcher=Join-Path $InstallDir 'FDSensorTaskLaunch.ps1'
    $expectedArguments='-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "'+$launcher+'"'
    if (-not $task -or $task.State -cne 'Running' -or $task.TaskName -cne $ServiceName -or $task.TaskPath -cne '\' -or
        $task.Principal.UserId -notin @('SYSTEM','NT AUTHORITY\SYSTEM','S-1-5-18') -or
        [string]$task.Principal.LogonType -cne 'ServiceAccount' -or [string]$task.Principal.RunLevel -cne 'Highest' -or
        $actions.Count -ne 1 -or $actions[0].Execute -ine (Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe') -or
        $actions[0].Arguments -cne $expectedArguments -or $actions[0].WorkingDirectory -ine $InstallDir -or
        -not (Test-Path -LiteralPath $launcher -PathType Leaf)) {
      throw 'scheduled-task owner, principal or original launcher binding is invalid'
    }
    $definition=Get-LifecycleTaskDefinition
    [xml]$xml=$definition.xml
    $manager=New-Object Xml.XmlNamespaceManager($xml.NameTable)
    $manager.AddNamespace('t','http://schemas.microsoft.com/windows/2004/02/mit/task')
    $triggers=@($xml.SelectNodes('/t:Task/t:Triggers/*',$manager))
    if ($triggers.Count -ne 1 -or $triggers[0].LocalName -cne 'BootTrigger' -or
        $xml.SelectSingleNode('/t:Task/t:Settings/t:ExecutionTimeLimit',$manager).InnerText -cne 'PT0S' -or
        $xml.SelectSingleNode('/t:Task/t:Settings/t:MultipleInstancesPolicy',$manager).InnerText -cne 'IgnoreNew' -or
        [string]::IsNullOrWhiteSpace($definition.sddl)) {
      throw 'scheduled-task startup, unlimited lifetime or security definition is invalid'
    }
    # Registration time is metadata. All actions, principals, triggers, runtime
    # settings and the full owner/group/DACL stay in the preservation identity.
    foreach($date in @($xml.SelectNodes('/t:Task/t:RegistrationInfo/t:Date',$manager))) { [void]$date.ParentNode.RemoveChild($date) }
    return [ordered]@{mode='scheduled_task';name=$task.TaskName;path=$task.TaskPath;xml=$xml.OuterXml;sddl=$definition.sddl}
  }
  if (Get-ScheduledTask -TaskName $ServiceName -TaskPath '\' -ErrorAction SilentlyContinue) {
    throw 'service validation found an unexpected scheduled-task owner'
  }
  if (-not $service -or $service.PathName.IndexOf((Join-Path $InstallDir 'FDSensor.exe'),[StringComparison]::OrdinalIgnoreCase) -lt 0 -or
      $service.State -cne 'Running') { throw 'preservation snapshot requires the running lifecycle service' }
  return [ordered]@{mode='service';path=$service.PathName;account=$service.StartName;start_mode=$service.StartMode}
}

function New-LifecyclePreservationSnapshot([string] $Stage) {
  $owner=Get-LifecycleRuntimeOwner
  $files=@()
  foreach ($name in @('edr_queue.db.signed-lifecycle-preserve','local_evidence_cache.db.signed-lifecycle-preserve')) {
    $path=Join-Path $InstallDir $name
    if (Test-Path -LiteralPath $path) { throw 'preservation marker already exists' }
    [IO.File]::WriteAllText($path,('isolated preservation marker '+[Guid]::NewGuid().ToString('N')),[Text.UTF8Encoding]::new($false))
    $files+=@{name=$name;sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()}
  }
  $snapshot=[pscustomobject]@{
    config_sha256=(Get-FileHash -LiteralPath (Join-Path $InstallDir 'agent.toml') -Algorithm SHA256).Hash.ToLowerInvariant()
    deployment_mode=$RuntimeMode;runtime_owner=$owner
    markers=$files;scope='Actual configuration and runtime owner identity; synthetic queue/evidence marker bytes, not business database readback'
  }
  [IO.File]::WriteAllText((Join-Path $EvidenceDir ($Stage+'-preservation.json')),($snapshot|ConvertTo-Json -Depth 5),[Text.UTF8Encoding]::new($false))
  return $snapshot
}

function Assert-LifecyclePreservationSnapshot($Snapshot, [string] $Stage) {
  if ((Get-FileHash -LiteralPath (Join-Path $InstallDir 'agent.toml') -Algorithm SHA256).Hash.ToLowerInvariant() -cne $Snapshot.config_sha256) {
    throw "$Stage changed the original configuration or identity"
  }
  $owner=Get-LifecycleRuntimeOwner
  if ($Snapshot.deployment_mode -cne $RuntimeMode -or
      ($owner|ConvertTo-Json -Depth 10 -Compress) -cne ($Snapshot.runtime_owner|ConvertTo-Json -Depth 10 -Compress)) {
    throw "$Stage changed the original $RuntimeMode deployment identity"
  }
  foreach ($item in $Snapshot.markers) {
    if ((Get-FileHash -LiteralPath (Join-Path $InstallDir $item.name) -Algorithm SHA256).Hash.ToLowerInvariant() -cne $item.sha256) {
      throw "$Stage changed the original queue/evidence marker bytes"
    }
  }
  Add-Evidence $Stage 'preserved' "original_config=true mode=$RuntimeMode runtime_owner_identity=true synthetic_queue_evidence_markers=true business_database_readback=false"
}

$status = "failed"
$script:LastLifecycleStage = "lifecycle"
$script:LastSetupLog = ""
try {
  $upgradeBinding = Get-Content -LiteralPath $UpgradeInput -Raw | ConvertFrom-Json
  if ($SignedPublisherValidation) {
    $migrationBinding=Get-Content -LiteralPath $MigrationInput -Raw | ConvertFrom-Json
    foreach ($binding in @($migrationBinding,$upgradeBinding)) {
      if ($binding.signature_status -cne 'signed' -or -not $binding.publisher_subject_der_sha256 -or
          $binding.upgrade_class -cne 'installer_required' -or $binding.deployment_mode -cne 'service' -or
          $binding.architecture -cne $Architecture -or $binding.service_name -cne $ServiceName) {
        throw 'signed publisher validation requires two verified full-installer service inputs'
      }
      $null=Get-LifecycleTrustedPublisher $binding
    }
    if ($migrationBinding.baseline_version -cne $LegacyVersion -or $migrationBinding.target_version -cne $BaselineVersion -or
        $upgradeBinding.baseline_version -cne $BaselineVersion -or $upgradeBinding.target_version -cne $TargetVersion -or
        $migrationBinding.target_updater_sha256 -cne $upgradeBinding.baseline_updater_sha256 -or
        (Get-FileHash -LiteralPath $BaselineSetupExe -Algorithm SHA256).Hash.ToLowerInvariant() -cne $migrationBinding.installer_sha256 -or
        (Get-FileHash -LiteralPath $TargetSetupExe -Algorithm SHA256).Hash.ToLowerInvariant() -cne $upgradeBinding.installer_sha256 -or
        (Get-FileHash -LiteralPath $LegacySetupExe -Algorithm SHA256).Hash.ToLowerInvariant() -cne $migrationBinding.baseline_setup_sha256) {
      throw 'signed publisher migration and upgrade inputs do not form one immutable version chain'
    }
  }
  # Validate the target independently first. A broken historical baseline must
  # not hide whether the candidate can install and uninstall on a clean host.
  Invoke-Installer $TargetSetupExe "install-target-fresh" $false
  Assert-InstalledRuntime $TargetVersion "install-target-fresh" $true $true
  Invoke-UninstallerAndAssertCleanup "uninstall-target-fresh"

  # Start with the immutable old Setup and the updater materialized by that
  # actual old Agent. Keep the separate direct-Setup path below unchanged.
  $offlineConfigHash = Initialize-LifecycleOfflineConfig $BaselineConfigTemplate
  if ($SignedPublisherValidation) {
    Invoke-Installer $LegacySetupExe 'install-legacy-migration-baseline' $false
    Assert-InstalledRuntime $LegacyVersion 'install-legacy-migration-baseline' $true
    $null=Wait-LifecycleEmbeddedUpdater $LegacyVersion $migrationBinding.baseline_updater_sha256
    $chainStorage=New-LifecycleStorageChain $storageTools 'legacy-updater'
    Write-LifecycleStorageFixture $chainStorage 'seed' 'legacy-seed'
    Test-LifecycleStorageReadback $chainStorage 'legacy-installed'
    $chainSnapshot=New-LifecyclePreservationSnapshot 'legacy-migration'
    # This is the supported full-Setup migration. The old command contract
    # rejects this publisher before PS starts; do not bypass it with a patched
    # old updater, new fields, or a direct PS invocation counted as that hop.
    Invoke-Installer $BaselineSetupExe 'migrate-legacy-full-setup' $true
    Assert-InstalledRuntime $BaselineVersion 'migrate-legacy-full-setup' $true $true
    Assert-LifecyclePreservationSnapshot $chainSnapshot 'migrate-legacy-full-setup'
    Test-LifecycleStorageReadback $chainStorage 'migrated-baseline'
    $migratedUpdater=Wait-LifecycleEmbeddedUpdater $BaselineVersion $upgradeBinding.baseline_updater_sha256
    Assert-LifecyclePublisherProtocol $migratedUpdater $upgradeBinding.baseline_updater_sha256 (Get-LifecycleTrustedPublisher $migrationBinding)
  } else {
    Invoke-Installer $BaselineSetupExe 'install-old-updater-baseline' $false
  }
  Assert-InstalledRuntime $BaselineVersion 'install-old-updater-baseline' (-not $SkipSetupRollback)
  if ((Get-FileHash -LiteralPath (Join-Path $InstallDir 'agent.toml') -Algorithm SHA256).Hash.ToLowerInvariant() -cne $offlineConfigHash) {
    throw 'baseline Setup changed the prepared offline lifecycle configuration'
  }
  Invoke-BaselineUpdaterUpgrade $upgradeBinding
  Assert-InstalledRuntime $TargetVersion 'old-updater-upgrade' $true $true
  if ($SignedPublisherValidation) {
    Assert-LifecyclePreservationSnapshot $chainSnapshot 'signed-updater-upgrade'
    Test-LifecycleStorageReadback $chainStorage 'updater-target'
    Write-LifecycleStorageFixture $chainStorage 'append' 'updater-target-append'
    Test-LifecycleStorageReadback $chainStorage 'updater-target-new-data'
  }
  if ($ExerciseInstallerTimeout) {
    $script:LastLifecycleStage = 'candidate-installer-timeout'
    Add-Evidence 'candidate-installer-timeout' 'started' 'same-version repair with original candidate updater and Setup bytes'
    $candidateUpdater = Wait-LifecycleEmbeddedUpdater $TargetVersion $upgradeBinding.target_updater_sha256
    $candidatePublisher = Get-LifecycleTrustedPublisher $upgradeBinding
    & (Join-Path $repoRoot 'tests\Invoke-RealInstallerTimeoutRecovery.ps1') -InputBinding $upgradeBinding `
      -InstallDir $InstallDir -EvidenceDir $EvidenceDir -Updater $candidateUpdater -Publisher $candidatePublisher -RuntimeMode $RuntimeMode
    Assert-InstalledRuntime $TargetVersion 'candidate-installer-timeout' $true $true
    if ($SignedPublisherValidation) {
      Assert-LifecyclePreservationSnapshot $chainSnapshot 'signed-installer-timeout'
      Test-LifecycleStorageReadback $chainStorage 'timeout-recovered'
    }
    Add-Evidence 'candidate-installer-timeout' 'verified' 'original Setup timed out; Job empty; runtime/config/owner/uninstall identity restored; queue/evidence marker bytes preserved'
  }
  Invoke-UninstallerAndAssertCleanup 'uninstall-old-updater-target'

  # Then verify the cross-version compatibility path using a baseline that is
  # freshly installed and validated in this same native-runner job.
  if ($SignedPublisherValidation) { $null=Initialize-LifecycleOfflineConfig $BaselineConfigTemplate }
  Invoke-Installer $BaselineSetupExe "install-baseline" $false
  Assert-InstalledRuntime $BaselineVersion "install-baseline" (-not $SkipSetupRollback)
  Assert-BaselineRepair $BaselineSetupExe
  if ($SignedPublisherValidation) {
    $rollbackStorage=New-LifecycleStorageChain $storageTools 'setup-rollback'
    Write-LifecycleStorageFixture $rollbackStorage 'seed' 'rollback-baseline-seed'
    Test-LifecycleStorageReadback $rollbackStorage 'rollback-baseline'
    $rollbackSnapshot=New-LifecyclePreservationSnapshot 'signed-setup-rollback'
  }
  Invoke-Installer $TargetSetupExe "upgrade-target" $true
  Assert-InstalledRuntime $TargetVersion "upgrade-target" $true $true
  if ($SignedPublisherValidation) {
    Assert-LifecyclePreservationSnapshot $rollbackSnapshot 'signed-setup-upgrade'
    Test-LifecycleStorageReadback $rollbackStorage 'setup-target'
    Write-LifecycleStorageFixture $rollbackStorage 'append' 'setup-target-append'
    Test-LifecycleStorageReadback $rollbackStorage 'setup-target-new-data'
  }
  if ($SkipSetupRollback) {
    Add-Evidence "rollback-baseline" "skipped" "legacy baseline predates the immutable full-Setup rollback contract; native runtime rollback remains mandatory"
    Invoke-UninstallerAndAssertCleanup "uninstall-after-upgrade"
  } else {
    Invoke-Installer $BaselineSetupExe "rollback-baseline" $true
    Assert-InstalledRuntime $BaselineVersion "rollback-baseline"
    if ($SignedPublisherValidation) {
      Assert-LifecyclePreservationSnapshot $rollbackSnapshot 'signed-setup-rollback'
      Test-LifecycleStorageReadback $rollbackStorage 'setup-rollback-completed'
    }
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
    runtime_mode = $RuntimeMode
    baseline_version = $BaselineVersion
    target_version = $TargetVersion
    signed_publisher_validation = [bool]$SignedPublisherValidation
    legacy_migration_version = $LegacyVersion
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
