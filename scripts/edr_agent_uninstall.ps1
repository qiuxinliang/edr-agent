#Requires -Version 5.1
<#
.SYNOPSIS
  Remove a headless FDSecurity installation's runtime registration.

.DESCRIPTION
  Headless packages are ZIP/SFX bundles, not Inno Setup packages, so Windows
  does not create unins000.exe automatically. This script is copied into the
  install directory by edr_agent_install.ps1 and provides the equivalent
  elevated cleanup entry point for services, scheduled tasks, certificates,
  machine environment variables, runtime data and program files.

  The default action removes runtime registration and identity material but
  leaves program files for a recoverable administrator-driven cleanup.
  uninstall.exe always invokes this script with -RemoveProgramFiles. It either
  passes -RemoveData for a complete uninstall or -PreserveDiagnostics to archive
  logs and diagnostics outside the installation directory before removal.
#>
[CmdletBinding()]
param(
  [string]$InstallDir = "",
  [switch]$RemoveData,
  [switch]$RemoveProgramFiles,
  [switch]$PreserveDiagnostics,
  [string]$ServiceName = "FDSecurityAgent",
  [int]$ParentProcessId = 0,
  [string]$AttestationURL = "",
  [string]$AttestationToken = "",
  [string]$LifecycleTaskID = "",
  [string]$EndpointID = ""
)

$ErrorActionPreference = "Stop"
$script:CriticalErrors = @()
$script:DeferredRuntimePaths = @()
$script:TargetProcessIds = @()
$script:UninstallStage = "initialization"
$programData = if ($env:ProgramData) { $env:ProgramData } else { Join-Path $env:SystemDrive "ProgramData" }
$receiptRoot = Join-Path $programData "FDSecurity\state"
$safeLifecycleTaskID = ([string]$LifecycleTaskID) -replace '[^A-Za-z0-9_.-]', '_'
$script:UninstallReceiptLatestPath = Join-Path $receiptRoot "uninstall-script-last.json"
$script:UninstallReceiptPath = if ($safeLifecycleTaskID) {
  Join-Path $receiptRoot "uninstall-script-$safeLifecycleTaskID.json"
} else {
  $script:UninstallReceiptLatestPath
}
$ConfigPath = ""

function Add-CriticalFailure {
  param([string]$Message)
  if (-not [string]::IsNullOrWhiteSpace($Message)) {
    $script:CriticalErrors += $Message
    Write-Warning $Message
  }
}

function Add-TargetProcessId {
  param([int]$ProcessId)
  if ($ProcessId -gt 0 -and $script:TargetProcessIds -notcontains $ProcessId) {
    $script:TargetProcessIds += $ProcessId
  }
}

function Add-CleanupWarning {
  param([string]$Message)
  if (-not [string]::IsNullOrWhiteSpace($Message)) {
    Write-Warning $Message
  }
}

function Write-UninstallScriptReceipt {
  param(
    [string]$Status,
    [string]$ErrorMessage = "",
    [string]$ErrorType = "",
    [string]$ErrorPosition = ""
  )
  try {
    $parent = Split-Path -Parent $script:UninstallReceiptPath
    New-Item -ItemType Directory -Path $parent -Force -ErrorAction Stop | Out-Null
    $receiptJSON = [ordered]@{
      schema = "edr.agent.uninstall.script.v1"
      completed_at = [DateTime]::UtcNow.ToString("o")
      status = $Status
      stage = $script:UninstallStage
      install_dir = $InstallDir
      service_name = $ServiceName
      remove_data = [bool]$RemoveData
      remove_program_files = [bool]$RemoveProgramFiles
      attestation_url_configured = -not [string]::IsNullOrWhiteSpace($AttestationURL)
      attestation_token_present = -not [string]::IsNullOrWhiteSpace($AttestationToken)
      attestation_token_length = ([string]$AttestationToken).Length
      error = $ErrorMessage
      error_type = $ErrorType
      error_position = $ErrorPosition
      critical_errors = @($script:CriticalErrors)
      deferred_runtime_paths = @($script:DeferredRuntimePaths)
    } | ConvertTo-Json -Depth 3
    $receiptJSON | Set-Content -LiteralPath $script:UninstallReceiptPath `
      -Encoding UTF8 -Force -ErrorAction Stop
    if ($script:UninstallReceiptLatestPath -ne $script:UninstallReceiptPath) {
      $receiptJSON | Set-Content -LiteralPath $script:UninstallReceiptLatestPath `
        -Encoding UTF8 -Force -ErrorAction Stop
    }
  } catch {
    Write-Warning ("Unable to persist uninstall diagnostic receipt: " + $_.Exception.Message)
  }
}

function Set-UninstallStage {
  param([string]$Stage)
  $script:UninstallStage = $Stage
  Write-UninstallScriptReceipt -Status "running"
}

function Assert-Admin {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($identity)
  if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run uninstall.ps1 from an elevated PowerShell session."
  }
}

function Read-AgentTomlScalar {
  param([string]$Path, [string]$Key)
  if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return "" }
  $pattern = '^\s*' + [regex]::Escape($Key) + '\s*=\s*"([^"]*)"'
  try {
    foreach ($line in [System.IO.File]::ReadLines(([System.IO.Path]::GetFullPath($Path)))) {
      $match = [regex]::Match($line, $pattern)
      if ($match.Success) { return $match.Groups[1].Value }
    }
  } catch {}
  return ""
}

function Remove-AgentClientCertificate {
  $thumbprint = (Read-AgentTomlScalar -Path $ConfigPath -Key "client_cert_thumbprint") -replace '\s+', ''
  $store = Read-AgentTomlScalar -Path $ConfigPath -Key "client_cert_store"
  if (-not $thumbprint) {
    Write-Host "Client certificate cleanup skipped: thumbprint not found in agent.toml"
    return
  }
  $scope = if ($store -match "CurrentUser") { "CurrentUser" } else { "LocalMachine" }
  $certPath = "Cert:\$scope\My\$thumbprint"
  try {
    if (Test-Path -LiteralPath $certPath) {
      Remove-Item -LiteralPath $certPath -DeleteKey -Force -ErrorAction Stop
      Write-Host "Removed client certificate: $scope\My\$thumbprint"
    } else {
      Write-Host "Client certificate not found: $scope\My\$thumbprint"
    }
  } catch {
    Add-CriticalFailure ("Client certificate cleanup failed: " + $_.Exception.Message)
  }
}

function Invoke-AgentEtwUninstallCleanup {
  foreach ($name in @("FDSensor.exe", "edr_agent.exe")) {
    $exe = Join-Path $InstallDir $name
    if (-not (Test-Path -LiteralPath $exe)) { continue }
    $cleanupProcess = $null
    try {
      $cleanupProcess = Start-Process -FilePath $exe -ArgumentList "--etw-uninstall-cleanup" `
        -WorkingDirectory $InstallDir -WindowStyle Hidden -PassThru -ErrorAction Stop
      if (-not $cleanupProcess.WaitForExit(15000)) {
        try { $cleanupProcess.Kill() } catch {}
        Add-CleanupWarning "ETW cleanup exceeded 15 seconds and was terminated; continuing uninstall"
      } elseif ($cleanupProcess.ExitCode -ne 0) {
        Add-CleanupWarning "ETW cleanup returned exit code $($cleanupProcess.ExitCode); continuing uninstall"
      }
    } catch {
      Add-CleanupWarning ("ETW cleanup failed: " + $_.Exception.Message + "; continuing uninstall")
    } finally {
      if ($cleanupProcess) { try { $cleanupProcess.Dispose() } catch {} }
    }
    break
  }
}

function Stop-AgentProcesses {
  $installPrefix = $InstallDir.TrimEnd('\') + '\'
  foreach ($name in @("FDSensor.exe", "edr_agent.exe")) {
    Get-CimInstance Win32_Process -Filter ("Name='{0}'" -f $name) -ErrorAction SilentlyContinue | ForEach-Object {
      $processId = [int]$_.ProcessId
      $path = [string]$_.ExecutablePath
      $pathMatches = $path -and $path.StartsWith($installPrefix, [StringComparison]::OrdinalIgnoreCase)
      if (($script:TargetProcessIds -contains $processId) -or $pathMatches) {
        Add-TargetProcessId -ProcessId $processId
        try {
          Stop-Process -Id $processId -Force -ErrorAction Stop
        } catch {
          Add-CriticalFailure ("Failed to stop Agent process PID ${processId}: " + $_.Exception.Message)
        }
      } else {
        Write-Warning "Skipped unrelated $name process PID $processId outside $InstallDir"
      }
    }
  }
  foreach ($targetProcessId in @($script:TargetProcessIds)) {
    if (Get-Process -Id $targetProcessId -ErrorAction SilentlyContinue) {
      Add-CriticalFailure "Target Agent process PID $targetProcessId is still running after stop"
    }
  }
}

function Wait-AgentServiceDeleted {
  param(
    [string]$Name,
    [int]$TimeoutSeconds = 30
  )
  $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
  do {
    $escapedName = $Name.Replace("'", "''")
    if (-not (Get-CimInstance Win32_Service -Filter "Name='$escapedName'" -ErrorAction SilentlyContinue)) {
      return $true
    }
    Start-Sleep -Milliseconds 500
  } while ([DateTime]::UtcNow -lt $deadline)
  return $false
}

function Disable-AgentServiceRecovery {
  param([string]$Name)
  if (-not (Get-Service -Name $Name -ErrorAction SilentlyContinue)) { return }
  try {
    $failureArguments = @("failure", $Name, "reset=", "0", "actions=", "")
    $failureOutput = (& sc.exe @failureArguments 2>&1 | Out-String).Trim()
    $failureExitCode = $LASTEXITCODE
    if ($failureOutput) { Write-Host $failureOutput }
    if ($failureExitCode -ne 0) {
      throw "sc.exe failure returned exit code $failureExitCode"
    }
    $flagArguments = @("failureflag", $Name, "0")
    $flagOutput = (& sc.exe @flagArguments 2>&1 | Out-String).Trim()
    $flagExitCode = $LASTEXITCODE
    if ($flagOutput) { Write-Host $flagOutput }
    if ($flagExitCode -ne 0) {
      throw "sc.exe failureflag returned exit code $flagExitCode"
    }
    Write-Host "Disabled Windows service recovery: $Name"
  } catch {
    # The detached lifecycle worker disables recovery with the native SCM API
    # before it starts uninstall.exe.  Keep this script-level guard best effort:
    # Windows PowerShell 5.1 can drop the intentionally empty actions argument
    # while serializing native command lines, which must not abort teardown after
    # the authoritative native guard already succeeded.
    Add-CleanupWarning ("Failed to disable Windows service recovery for ${Name}: " + $_.Exception.Message)
  }
}

function Remove-AgentServices {
  $serviceNames = @($ServiceName, "FDSecurityAgent", "EdrAgent")
  if ($env:EDR_SERVICE_NAME) { $serviceNames += $env:EDR_SERVICE_NAME }
  foreach ($name in ($serviceNames | Select-Object -Unique)) {
    $escapedName = $name.Replace("'", "''")
    $serviceCim = Get-CimInstance Win32_Service -Filter "Name='$escapedName'" -ErrorAction SilentlyContinue
    if ($serviceCim -and [int]$serviceCim.ProcessId -gt 0) {
      Add-TargetProcessId -ProcessId ([int]$serviceCim.ProcessId)
    }
    $service = Get-Service -Name $name -ErrorAction SilentlyContinue
    if (-not $service) { continue }
    Disable-AgentServiceRecovery -Name $name
    Stop-Service -Name $name -Force -ErrorAction SilentlyContinue
    try {
      $service.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(20))
    } catch {
      Stop-AgentProcesses
      Start-Sleep -Milliseconds 500
    } finally {
      # A service remains DELETE_PENDING while a ServiceController handle is
      # open. Release this handle before asking SCM to delete the service.
      try { $service.Close() } catch {}
      try { $service.Dispose() } catch {}
      $service = $null
    }
    $deleteExitCode = 0
    for ($attempt = 0; $attempt -lt 3; $attempt++) {
      try {
        $deleteOutput = (& sc.exe delete $name 2>&1 | Out-String).Trim()
        $deleteExitCode = $LASTEXITCODE
      } catch {
        $deleteOutput = $_.Exception.Message
        $deleteExitCode = if ($LASTEXITCODE) { $LASTEXITCODE } else { 1 }
      }
      if ($deleteOutput) { Write-Host $deleteOutput }
      if (Wait-AgentServiceDeleted -Name $name -TimeoutSeconds 1) { break }
      Start-Sleep -Seconds 1
    }
    if (-not (Wait-AgentServiceDeleted -Name $name)) {
      Add-CriticalFailure "Windows service '$name' still exists after delete attempts; last sc.exe exit code $deleteExitCode."
      continue
    }
    Write-Host "Removed Windows service: $name"
  }
}

function Export-AgentDiagnostics {
  $programData = if ($env:ProgramData) { $env:ProgramData } else { Join-Path $env:SystemDrive "ProgramData" }
  $archiveRoot = Join-Path $programData "FDSecurity\UninstallArchive"
  $stamp = [DateTime]::UtcNow.ToString("yyyyMMddTHHmmssfffZ")
  $archiveDir = Join-Path $archiveRoot $stamp
  New-Item -ItemType Directory -Path $archiveDir -Force -ErrorAction Stop | Out-Null
  $copied = @()
  foreach ($relative in @("logs", "diagnostics")) {
    $source = Join-Path $InstallDir $relative
    if (-not (Test-Path -LiteralPath $source)) { continue }
    Copy-Item -LiteralPath $source -Destination (Join-Path $archiveDir $relative) `
      -Recurse -Force -ErrorAction Stop
    $copied += $relative
  }
  [ordered]@{
    schema = "edr.agent.uninstall.archive.v1"
    archived_at = [DateTime]::UtcNow.ToString("o")
    hostname = $env:COMPUTERNAME
    source_install_dir = $InstallDir
    contents = $copied
  } | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath (Join-Path $archiveDir "manifest.json") `
    -Encoding UTF8 -ErrorAction Stop
  Write-Host "Archived local diagnostics: $archiveDir"
  return $archiveDir
}

function Remove-AgentScheduledTasks {
  foreach ($name in (@($ServiceName, "FDSecurityAgent", "EdrAgent") | Select-Object -Unique)) {
    $task = Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
    if (-not $task) { continue }
    try {
      Stop-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
      Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction Stop
      Write-Host "Removed scheduled task: $name"
    } catch {
      Add-CriticalFailure ("Failed to remove scheduled task ${name}: " + $_.Exception.Message)
    }
    if (Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue) {
      Add-CriticalFailure "Scheduled task '$name' still exists after uninstall cleanup"
    }
  }
}

function Remove-MachineEnvironment {
  foreach ($name in @(
      "EDR_GRPC_REQUIRE_MTLS",
      "EDR_UPLOAD_FILE_RETRIES",
      "EDR_UPLOAD_FILE_RETRY_BACKOFF_MS",
      "EDR_FORENSIC_OUT",
      "EDR_FORENSIC_COLLECTOR",
      "EDR_FORENSIC_COLLECTOR_BIN",
      "EDR_FORENSIC_COLLECTOR_BUILTIN_BIN",
      "EDR_VELOCIRAPTOR_BIN",
      "EDR_FORENSIC_VERSION_CHECK_SEC",
      "EDR_FORENSIC_PREFETCH_RETRY_SEC",
      "EDR_FORENSIC_COLLECTOR_AUTOFETCH",
      "EDR_FORENSIC_ADAPTER_MANIFEST_URL",
      "EDR_FORENSIC_COLLECTOR_MANIFEST_URL",
      "EDR_CMD_AUDIT_PATH",
      "EDR_SELF_PROTECT_PIDFILE",
      "EDR_ISOLATE_STAMP_PATH",
      "EDR_ISOLATE_HOOK",
      "EDR_CMD_ENABLED"
    )) {
    try { [Environment]::SetEnvironmentVariable($name, $null, "Machine") } catch {
      Add-CriticalFailure ("Failed to remove machine environment variable " + $name + ": " + $_.Exception.Message)
    }
  }
}

function Remove-HeadlessUninstallRegistration {
  $key = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\FDSecurityAgentHeadless"
  try {
    if (Test-Path -LiteralPath $key) {
      Remove-Item -LiteralPath $key -Recurse -Force -ErrorAction Stop
    }
    if (Test-Path -LiteralPath $key) {
      throw "registry key still exists after removal"
    }
  } catch {
    Add-CriticalFailure ("Failed to remove uninstall registry entry: " + $_.Exception.Message)
  }
}

function Start-DeferredProgramFilesRemoval {
  if (-not $RemoveProgramFiles) { return }

  $quotedDir = $InstallDir.Replace("'", "''")
  $quotedService = $ServiceName.Replace("'", "''")
  $quotedAttestationURL = $AttestationURL.Replace("'", "''")
  $quotedAttestationToken = $AttestationToken.Replace("'", "''")
  $quotedLifecycleTaskID = $LifecycleTaskID.Replace("'", "''")
  $quotedEndpointID = $EndpointID.Replace("'", "''")
  $targetPidLiteral = (@($script:TargetProcessIds) | ForEach-Object { [string][int]$_ }) -join ','
  $programData = if ($env:ProgramData) { $env:ProgramData } else { Join-Path $env:SystemDrive "ProgramData" }
  $receiptDir = Join-Path $programData "FDSecurity\state"
  New-Item -ItemType Directory -Path $receiptDir -Force -ErrorAction Stop | Out-Null
  $cleanupReceiptName = if ($safeLifecycleTaskID) {
    "uninstall-cleanup-$safeLifecycleTaskID.json"
  } else {
    "uninstall-cleanup-last.json"
  }
  $quotedReceipt = (Join-Path $receiptDir $cleanupReceiptName).Replace("'", "''")
  $quotedLatestReceipt = (Join-Path $receiptDir "uninstall-cleanup-last.json").Replace("'", "''")
  $cleanup = @"
`$ErrorActionPreference = 'SilentlyContinue'
`$parentId = $ParentProcessId
if (`$parentId -gt 0) {
  `$parent = Get-Process -Id `$parentId -ErrorAction SilentlyContinue
  if (`$parent) { `$null = `$parent.WaitForExit(30000) }
}
Start-Sleep -Milliseconds 750
`$target = '$quotedDir'
`$receipt = '$quotedReceipt'
`$latestReceipt = '$quotedLatestReceipt'
`$serviceName = '$quotedService'
`$attestationURL = '$quotedAttestationURL'
`$attestationToken = '$quotedAttestationToken'
`$taskID = '$quotedLifecycleTaskID'
`$endpointID = '$quotedEndpointID'
`$targetPids = @($targetPidLiteral)
try { & takeown.exe /F `$target /A /R /D Y | Out-Null } catch {}
try {
  & icacls.exe `$target /inheritance:e /T /C /Q | Out-Null
  & icacls.exe `$target /reset /T /C /Q | Out-Null
  & icacls.exe `$target /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' /T /C /Q | Out-Null
} catch {}
Get-ChildItem -LiteralPath `$target -Force -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
  try { `$_.Attributes = [IO.FileAttributes]::Normal } catch {}
}
`$deleteAttemptCount = 0
`$deleteLastError = ''
for (`$attempt = 0; `$attempt -lt 120 -and (Test-Path -LiteralPath `$target); `$attempt++) {
  `$deleteAttemptCount = `$attempt + 1
  try {
    Remove-Item -LiteralPath `$target -Recurse -Force -ErrorAction Stop
  } catch {
    `$deleteLastError = `$_.Exception.Message
  }
  if (Test-Path -LiteralPath `$target) { Start-Sleep -Milliseconds 500 }
}
`$remaining = Test-Path -LiteralPath `$target
`$remainingEntries = @()
if (`$remaining) {
  `$remainingEntries = @(Get-ChildItem -LiteralPath `$target -Force -Recurse -ErrorAction SilentlyContinue |
    Select-Object -First 50 | ForEach-Object { `$_.FullName })
}
`$escapedService = `$serviceName.Replace("'", "''")
`$serviceRemoved = -not (Get-CimInstance Win32_Service -Filter "Name='`$escapedService'" -ErrorAction SilentlyContinue)
`$installPrefix = `$target.TrimEnd('\') + '\'
`$processStopped = `$true
foreach (`$imageName in @('FDSensor.exe', 'edr_agent.exe')) {
  foreach (`$candidate in @(Get-CimInstance Win32_Process -Filter "Name='`$imageName'" -ErrorAction SilentlyContinue)) {
    `$candidatePath = [string]`$candidate.ExecutablePath
    if (`$targetPids -contains [int]`$candidate.ProcessId -or
        (`$candidatePath -and `$candidatePath.StartsWith(`$installPrefix, [StringComparison]::OrdinalIgnoreCase))) {
      `$processStopped = `$false
    }
  }
}
`$teardownCompletedAt = [DateTime]::UtcNow.ToString('o')
`$localSucceeded = (-not `$remaining) -and `$serviceRemoved -and `$processStopped
`$attestationError = ''
`$attestationAttemptCount = 0
`$attestationLastHttpStatus = 0
`$attestationErrors = @()
`$attestationProxyMode = 'system'
`$attestationTransport = 'invoke_rest_method'
`$attestationRequestBodyBytes = 0
`$attestationStatus = if ([string]::IsNullOrWhiteSpace(`$attestationURL)) {
  'not_configured'
} elseif (`$localSucceeded) {
  'pending'
} else {
  'skipped_local_teardown_failed'
}
if (`$localSucceeded -and `$attestationStatus -eq 'pending') {
  `$normalizedAttestationToken = `$attestationToken.Trim()
  if (`$normalizedAttestationToken.Length -ge 2 -and
      ((`$normalizedAttestationToken[0] -eq [char]34 -and `$normalizedAttestationToken[`$normalizedAttestationToken.Length - 1] -eq [char]34) -or
       (`$normalizedAttestationToken[0] -eq [char]39 -and `$normalizedAttestationToken[`$normalizedAttestationToken.Length - 1] -eq [char]39))) {
    `$normalizedAttestationToken = `$normalizedAttestationToken.Substring(1, `$normalizedAttestationToken.Length - 2).Trim()
  }
  `$bypassProxy = ([Uri]`$attestationURL).IsLoopback
  `$bodyFields = [ordered]@{
    schema = 'edr.endpoint.uninstall.attestation.v1'
    task_id = `$taskID
    endpoint_id = `$endpointID
    service_removed = `$serviceRemoved
    process_stopped = `$processStopped
    install_dir_removed = (-not `$remaining)
    completed_at = `$teardownCompletedAt
  }
  if (`$bypassProxy) {
    `$proofKey = [Text.Encoding]::UTF8.GetBytes(`$normalizedAttestationToken)
    `$proofMessage = [Text.Encoding]::UTF8.GetBytes(
      "edr.endpoint.uninstall.attestation.v1``n`$taskID``n`$endpointID")
    `$proofHmac = New-Object Security.Cryptography.HMACSHA256 -ArgumentList (,`$proofKey)
    try {
      `$tokenProofRaw = [BitConverter]::ToString(`$proofHmac.ComputeHash(`$proofMessage))
      `$tokenProof = `$tokenProofRaw.Replace('-', '').ToLowerInvariant()
      `$bodyFields.token_proof_hmac_sha256 = `$tokenProof
    } finally {
      `$proofHmac.Dispose()
    }
  }
  `$body = `$bodyFields | ConvertTo-Json -Compress
  `$bodyBytes = [Text.Encoding]::UTF8.GetBytes(`$body)
  `$attestationRequestBodyBytes = `$bodyBytes.Length
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  `$originalDefaultProxy = [Net.WebRequest]::DefaultWebProxy
  if (`$bypassProxy) {
    [Net.WebRequest]::DefaultWebProxy = `$null
    `$attestationProxyMode = 'loopback_direct'
    `$attestationTransport = 'tcp_loopback_http11'
  }
  `$requestHeaders = @{ Authorization = "Bearer `$normalizedAttestationToken" }
  if (`$bypassProxy) { `$requestHeaders['X-EDR-Uninstall-Token'] = `$normalizedAttestationToken }
  try {
    for (`$postAttempt = 0; `$postAttempt -lt 8 -and `$attestationStatus -ne 'succeeded'; `$postAttempt++) {
      `$attestationAttemptCount = `$postAttempt + 1
      `$attestationLastHttpStatus = 0
      try {
        if (`$bypassProxy) {
          # Windows PowerShell 5.1 can silently suppress restricted headers and
          # request bodies through its loopback WebRequest path under LocalSystem.
          # The CI-only loopback listener needs a byte-exact HTTP request so it
          # can verify the same token that crossed both native process handoffs.
          `$attestationUri = [Uri]`$attestationURL
          `$requestPath = if ([string]::IsNullOrEmpty(`$attestationUri.PathAndQuery)) {
            '/'
          } else {
            `$attestationUri.PathAndQuery
          }
          `$requestAuthority = `$attestationUri.Authority
          `$requestHead = "POST `$requestPath HTTP/1.1``r``n" +
            "Host: `$requestAuthority``r``n" +
            "Authorization: Bearer `$normalizedAttestationToken``r``n" +
            "X-EDR-Uninstall-Token: `$normalizedAttestationToken``r``n" +
            "Content-Type: application/json; charset=utf-8``r``n" +
            "Content-Length: `$(`$bodyBytes.Length)``r``n" +
            "Connection: close``r``n``r``n"
          `$requestHeadBytes = [Text.Encoding]::ASCII.GetBytes(`$requestHead)
          `$tcpClient = New-Object Net.Sockets.TcpClient
          try {
            `$tcpClient.NoDelay = `$true
            `$tcpClient.ReceiveTimeout = 5000
            `$tcpClient.SendTimeout = 5000
            `$tcpClient.Connect(`$attestationUri.Host, `$attestationUri.Port)
            `$networkStream = `$tcpClient.GetStream()
            `$networkStream.Write(`$requestHeadBytes, 0, `$requestHeadBytes.Length)
            `$networkStream.Write(`$bodyBytes, 0, `$bodyBytes.Length)
            `$networkStream.Flush()
            `$responseBytes = New-Object byte[] 4096
            `$responseLength = 0
            `$statusLine = ''
            while (`$responseLength -lt `$responseBytes.Length -and -not `$statusLine) {
              `$readCount = `$networkStream.Read(
                `$responseBytes, `$responseLength, `$responseBytes.Length - `$responseLength)
              if (`$readCount -le 0) { break }
              `$responseLength += `$readCount
              `$responseText = [Text.Encoding]::ASCII.GetString(`$responseBytes, 0, `$responseLength)
              `$lineEnd = `$responseText.IndexOf("``r``n", [StringComparison]::Ordinal)
              if (`$lineEnd -ge 0) { `$statusLine = `$responseText.Substring(0, `$lineEnd) }
            }
            if (`$statusLine -notmatch '^HTTP/1\.[01] ([0-9]{3})(?: |$)') {
              throw "loopback attestation returned an invalid HTTP status line"
            }
            `$attestationLastHttpStatus = [int]`$Matches[1]
            if (`$attestationLastHttpStatus -ne 200) {
              throw "loopback attestation returned HTTP `$attestationLastHttpStatus"
            }
          } finally {
            if (`$tcpClient) { `$tcpClient.Dispose() }
          }
        } else {
          `$null = Invoke-RestMethod -Uri `$attestationURL -Method Post -ContentType 'application/json' `
            -Headers `$requestHeaders -Body `$body -TimeoutSec 5
          `$attestationLastHttpStatus = 200
        }
        `$attestationStatus = 'succeeded'
        `$attestationError = ''
      } catch {
        `$attestationStatus = 'failed'
        `$attestationError = `$_.Exception.Message
        if (`$attestationLastHttpStatus -eq 0 -and
            `$_.Exception.Response -and `$_.Exception.Response.StatusCode) {
          `$attestationLastHttpStatus = [int]`$_.Exception.Response.StatusCode
        }
        `$attestationErrors += ("attempt {0}: {1}" -f `$attestationAttemptCount, `$attestationError)
        if (`$attestationLastHttpStatus -in @(400, 401, 403)) { break }
        if (`$postAttempt -lt 7) { Start-Sleep -Seconds 4 }
      }
    }
  } finally {
    if (`$bypassProxy) { [Net.WebRequest]::DefaultWebProxy = `$originalDefaultProxy }
  }
}
`$failureReasons = @()
if (`$remaining) { `$failureReasons += 'install_dir_remaining' }
if (-not `$serviceRemoved) { `$failureReasons += 'service_remaining' }
if (-not `$processStopped) { `$failureReasons += 'process_remaining' }
if (`$attestationStatus -eq 'failed') {
  `$failureReasons += 'attestation_failed'
} elseif (`$attestationStatus -eq 'skipped_local_teardown_failed') {
  `$failureReasons += 'attestation_skipped_local_teardown_failed'
}
`$attestationRequired = -not [string]::IsNullOrWhiteSpace(`$attestationURL)
`$overallSucceeded = `$localSucceeded -and (-not `$attestationRequired -or `$attestationStatus -eq 'succeeded')
`$receiptJSON = [ordered]@{
  schema = 'edr.agent.uninstall.cleanup.v1'
  completed_at = [DateTime]::UtcNow.ToString('o')
  local_teardown_completed_at = `$teardownCompletedAt
  status = if (`$overallSucceeded) { 'succeeded' } else { 'failed' }
  local_status = if (`$localSucceeded) { 'succeeded' } else { 'failed' }
  install_dir = `$target
  service_removed = `$serviceRemoved
  process_stopped = `$processStopped
  install_dir_removed = (-not `$remaining)
  deletion_attempts = `$deleteAttemptCount
  deletion_last_error = `$deleteLastError
  remaining_entries = @(`$remainingEntries)
  attestation_status = `$attestationStatus
  attestation_token_present = -not [string]::IsNullOrWhiteSpace(`$normalizedAttestationToken)
  attestation_token_length = ([string]`$normalizedAttestationToken).Length
  attestation_error = `$attestationError
  attestation_attempts = `$attestationAttemptCount
  attestation_last_http_status = `$attestationLastHttpStatus
  attestation_errors = @(`$attestationErrors)
  attestation_proxy_mode = `$attestationProxyMode
  attestation_transport = `$attestationTransport
  attestation_request_body_bytes = `$attestationRequestBodyBytes
  failure_reasons = @(`$failureReasons)
  lifecycle_task_id = `$taskID
  endpoint_id = `$endpointID
} | ConvertTo-Json -Depth 2
`$receiptJSON | Set-Content -LiteralPath `$receipt -Encoding UTF8 -Force -ErrorAction Stop
if (`$latestReceipt -ne `$receipt) {
  `$receiptJSON | Set-Content -LiteralPath `$latestReceipt -Encoding UTF8 -Force -ErrorAction Stop
}
`$cleanupStatus = if (`$overallSucceeded) { 'succeeded' } else { 'failed' }
Write-Output ("deferred_cleanup status=" + `$cleanupStatus + " attestation_status=" +
  `$attestationStatus + " failure_reasons=" + (`$failureReasons -join ','))
if (-not `$overallSucceeded) { exit 1 }
"@
  try {
    $tokens = $null
    $parseErrors = $null
    [void][Management.Automation.Language.Parser]::ParseInput($cleanup, [ref]$tokens, [ref]$parseErrors)
    if (@($parseErrors).Count -gt 0) {
      $parseDetail = @($parseErrors | ForEach-Object {
        "line $($_.Extent.StartLineNumber), column $($_.Extent.StartColumnNumber): $($_.Message)"
      }) -join "; "
      throw "Generated deferred cleanup script failed syntax validation: $parseDetail"
    }
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cleanup))
    $powershell = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
    $cleanupStdout = Join-Path $receiptDir "uninstall-cleanup-last.stdout.log"
    $cleanupStderr = Join-Path $receiptDir "uninstall-cleanup-last.stderr.log"
    if ($safeLifecycleTaskID) {
      $cleanupStdout = Join-Path $receiptDir ("uninstall-cleanup-$safeLifecycleTaskID.stdout.log")
      $cleanupStderr = Join-Path $receiptDir ("uninstall-cleanup-$safeLifecycleTaskID.stderr.log")
    }
    Remove-Item -LiteralPath $cleanupStdout, $cleanupStderr -Force -ErrorAction SilentlyContinue
    Start-Process -FilePath $powershell -WorkingDirectory $env:SystemRoot -WindowStyle Hidden -ArgumentList @(
      "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", $encoded
    ) -RedirectStandardOutput $cleanupStdout -RedirectStandardError $cleanupStderr | Out-Null
    Write-Host "Scheduled program directory removal: $InstallDir"
  } catch {
    throw ("Failed to schedule program directory removal: " + $_.Exception.Message)
  }
}

function Remove-RuntimePathWithRetry {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Path,
    [int]$Attempts = 12,
    [int]$DelayMilliseconds = 250
  )
  $lastError = ""
  for ($attempt = 1; $attempt -le $Attempts; $attempt++) {
    try {
      if (Test-Path -LiteralPath $Path) {
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
        if ($item) {
          try { $item.Attributes = [IO.FileAttributes]::Normal } catch {}
        }
        Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
      }
    } catch {
      $lastError = $_.Exception.Message
    }
    if (-not (Test-Path -LiteralPath $Path)) {
      return [pscustomobject]@{ Removed = $true; Error = "" }
    }
    if ($attempt -lt $Attempts) {
      Start-Sleep -Milliseconds $DelayMilliseconds
    }
  }
  return [pscustomobject]@{ Removed = $false; Error = $lastError }
}

function Remove-AgentData {
  foreach ($relative in @(
      "agent.toml",
      "certs",
      "queue",
      "evidence",
      "state",
      "logs",
      "diagnostics",
      "upload_outbox",
      "forensic",
      "isolation",
      "FDSensor.pid"
    )) {
    $path = Join-Path $InstallDir $relative
    if (Test-Path -LiteralPath $path) {
      $result = Remove-RuntimePathWithRetry -Path $path
      if ($result.Removed) {
        Write-Host "Removed runtime data: $relative"
      } elseif ($RemoveProgramFiles) {
        $script:DeferredRuntimePaths += $path
        $detail = if ($result.Error) { "; last error: " + $result.Error } else { "" }
        Add-CleanupWarning ("Runtime data remains for verified deferred directory cleanup: " + $path + $detail)
      } else {
        $detail = if ($result.Error) { "; last error: " + $result.Error } else { "" }
        Add-CriticalFailure ("Failed to remove runtime data: " + $path + $detail)
      }
    }
  }
}

try {
  if ([string]::IsNullOrWhiteSpace($InstallDir)) {
    $InstallDir = Split-Path -Parent $MyInvocation.MyCommand.Path
  }
  $InstallDir = [System.IO.Path]::GetFullPath($InstallDir)
  $ConfigPath = Join-Path $InstallDir "agent.toml"
  Set-UninstallStage -Stage "admin_check"
  Assert-Admin
  Write-Host "Uninstalling FDSecurity runtime from $InstallDir"

  Set-UninstallStage -Stage "service_cleanup"
  Remove-AgentServices
  Set-UninstallStage -Stage "scheduled_task_cleanup"
  Remove-AgentScheduledTasks
  Set-UninstallStage -Stage "process_cleanup"
  Stop-AgentProcesses
  Set-UninstallStage -Stage "etw_cleanup"
  Invoke-AgentEtwUninstallCleanup
  Set-UninstallStage -Stage "identity_cleanup"
  Remove-AgentClientCertificate
  Set-UninstallStage -Stage "environment_cleanup"
  Remove-MachineEnvironment
  Set-UninstallStage -Stage "registration_cleanup"
  Remove-HeadlessUninstallRegistration

  $diagnosticArchive = ""
  if ($PreserveDiagnostics) {
    Set-UninstallStage -Stage "diagnostics_archive"
    $diagnosticArchive = Export-AgentDiagnostics
  }
  if ($RemoveData) {
    Set-UninstallStage -Stage "runtime_data_cleanup"
    Remove-AgentData
  } elseif ($PreserveDiagnostics) {
    Write-Host "Only logs and diagnostics were archived; credentials, configuration and runtime state will not be retained."
  } else {
    Write-Host "Runtime data preserved. Use -RemoveData to remove config, certificates, queue, evidence and logs."
  }
  if ($script:CriticalErrors.Count -gt 0) {
    throw ("Uninstall stopped after critical cleanup failures: " + ($script:CriticalErrors -join "; "))
  }
  if ($RemoveProgramFiles) {
    Set-UninstallStage -Stage "deferred_program_files_cleanup"
    Start-DeferredProgramFilesRemoval
    Set-UninstallStage -Stage "deferred_cleanup_scheduled"
    if ($diagnosticArchive) {
      Write-Host "FDSecurity Agent uninstalled successfully. Program files are scheduled for removal; diagnostics archive: $diagnosticArchive"
    } else {
      Write-Host "FDSecurity Agent uninstalled successfully. Program files are scheduled for removal."
    }
  } else {
    Set-UninstallStage -Stage "completed"
    Write-Host "FDSecurity runtime unregistered successfully. Program files remain in place for audit/recovery."
  }
  Write-UninstallScriptReceipt -Status "accepted"
} catch {
  $failure = $_
  $failureType = $failure.Exception.GetType().FullName
  $failurePosition = $failure.InvocationInfo.PositionMessage
  Write-UninstallScriptReceipt -Status "failed" `
    -ErrorMessage $failure.Exception.Message `
    -ErrorType $failureType `
    -ErrorPosition $failurePosition
  Write-Error -ErrorRecord $failure -ErrorAction Continue
  exit 1
}

# Do not let a handled best-effort native helper exit code leak through
# powershell.exe after all required teardown assertions were accepted.
exit 0
