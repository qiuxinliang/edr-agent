[CmdletBinding()]
param(
  [string]$InstallDir = "${env:ProgramFiles}\FDSecurity",
  [int]$LookbackMinutes = 30,
  [switch]$PrepareDumps,
  [string]$OutputDir = ""
)

$ErrorActionPreference = "Stop"

function Test-IsAdministrator {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($identity)
  return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Copy-IfPresent {
  param([string]$Path, [string]$Destination)
  if (Test-Path -LiteralPath $Path) {
    try {
      Copy-Item -LiteralPath $Path -Destination $Destination -Recurse -Force -ErrorAction Stop
    } catch {
      Add-Content -LiteralPath $script:CollectionErrors -Value ("copy failed: {0}: {1}" -f $Path, $_.Exception.Message)
    }
  }
}

function Write-CommandOutput {
  param([scriptblock]$Command, [string]$Path)
  try {
    & $Command 2>&1 | Out-String -Width 4096 | Set-Content -LiteralPath $Path -Encoding UTF8
  } catch {
    ("command failed: {0}" -f $_.Exception.Message) | Set-Content -LiteralPath $Path -Encoding UTF8
  }
}

if ($LookbackMinutes -lt 1 -or $LookbackMinutes -gt 1440) {
  throw "LookbackMinutes must be between 1 and 1440."
}

$isAdmin = Test-IsAdministrator
if ($PrepareDumps -and -not $isAdmin) {
  throw "PrepareDumps requires an elevated PowerShell session."
}

$dumpDir = Join-Path $env:ProgramData "FDSecurity\dumps"
if ($PrepareDumps) {
  New-Item -ItemType Directory -Force -Path $dumpDir | Out-Null
  $wer = "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\FDSensor.exe"
  New-Item -Force -Path $wer | Out-Null
  New-ItemProperty -Path $wer -Name DumpFolder -PropertyType ExpandString -Value $dumpDir -Force | Out-Null
  New-ItemProperty -Path $wer -Name DumpType -PropertyType DWord -Value 2 -Force | Out-Null
  New-ItemProperty -Path $wer -Name DumpCount -PropertyType DWord -Value 5 -Force | Out-Null
  & wevtutil.exe sl "Microsoft-Windows-TaskScheduler/Operational" /e:true | Out-Null
  Write-Host "WER full dumps enabled for FDSensor.exe: $dumpDir"
}

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
if ([string]::IsNullOrWhiteSpace($OutputDir)) {
  $OutputDir = Join-Path $env:ProgramData "FDSecurity\rtr-diagnostics-$stamp"
}
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
$script:CollectionErrors = Join-Path $OutputDir "collection-errors.txt"
New-Item -ItemType File -Force -Path $script:CollectionErrors | Out-Null

$summary = @(
  "collected_at=$((Get-Date).ToString('o'))"
  "computer=$env:COMPUTERNAME"
  "user=$env:USERNAME"
  "administrator=$isAdmin"
  "install_dir=$InstallDir"
  "lookback_minutes=$LookbackMinutes"
)
$summary | Set-Content -LiteralPath (Join-Path $OutputDir "summary.txt") -Encoding UTF8

$configPath = Join-Path $InstallDir "agent.toml"
if (Test-Path -LiteralPath $configPath) {
  $config = [IO.File]::ReadAllText($configPath)
  $secretKeys = "rest_bearer_token|secret|client_key|pkcs11_key_uri|tpm_key_uri"
  $config = [Text.RegularExpressions.Regex]::Replace(
    $config,
    "(?im)^(\s*(?:$secretKeys)\s*=\s*).*$",
    '$1"<redacted>"'
  )
  [IO.File]::WriteAllText(
    (Join-Path $OutputDir "agent.sanitized.toml"),
    $config,
    (New-Object Text.UTF8Encoding($false))
  )
}

$logsDir = Join-Path $InstallDir "logs"
if (Test-Path -LiteralPath $logsDir) {
  New-Item -ItemType Directory -Force -Path (Join-Path $OutputDir "logs") | Out-Null
  Get-ChildItem -LiteralPath $logsDir -File -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -like "*.log*" } |
    ForEach-Object { Copy-IfPresent $_.FullName (Join-Path $OutputDir "logs") }
}

$stateDir = Join-Path $InstallDir "state"
if (Test-Path -LiteralPath $stateDir) {
  Copy-IfPresent $stateDir (Join-Path $OutputDir "state")
}
Copy-IfPresent (Join-Path $InstallDir "diagnostics") (Join-Path $OutputDir "agent-diagnostics")
Copy-IfPresent (Join-Path $env:ProgramData "FDSecurity\setup-ui\agent-diagnostics") (Join-Path $OutputDir "installer-diagnostics")
Copy-IfPresent $dumpDir (Join-Path $OutputDir "dumps")

$sensorPath = Join-Path $InstallDir "FDSensor.exe"
if (Test-Path -LiteralPath $sensorPath) {
  Write-CommandOutput { Get-Item -LiteralPath $sensorPath | Format-List FullName,Length,CreationTimeUtc,LastWriteTimeUtc,VersionInfo } (Join-Path $OutputDir "fdsensor-file.txt")
  Write-CommandOutput { Get-FileHash -LiteralPath $sensorPath -Algorithm SHA256 | Format-List * } (Join-Path $OutputDir "fdsensor-sha256.txt")
}

Write-CommandOutput { Get-ScheduledTask -TaskName "FDSecurityAgent" | Format-List * } (Join-Path $OutputDir "scheduled-task.txt")
Write-CommandOutput { Get-ScheduledTaskInfo -TaskName "FDSecurityAgent" | Format-List * } (Join-Path $OutputDir "scheduled-task-info.txt")
Write-CommandOutput {
  Get-CimInstance Win32_Process -Filter "Name='FDSensor.exe'" | ForEach-Object {
    $owner = Invoke-CimMethod -InputObject $_ -MethodName GetOwner -ErrorAction SilentlyContinue
    [pscustomobject]@{
      ProcessId = $_.ProcessId
      ParentProcessId = $_.ParentProcessId
      CreationDate = $_.CreationDate
      ExecutablePath = $_.ExecutablePath
      CommandLine = $_.CommandLine
      Owner = if ($owner) { "$($owner.Domain)\$($owner.User)" } else { "" }
    }
  } | Format-List *
} (Join-Path $OutputDir "fdsensor-process.txt")

Write-CommandOutput {
  "EDR_CMD_ENABLED=" + [Environment]::GetEnvironmentVariable("EDR_CMD_ENABLED", "Machine")
  "EDR_CMD_DANGEROUS=" + [Environment]::GetEnvironmentVariable("EDR_CMD_DANGEROUS", "Machine")
  "EDR_COMMAND_SIGNING_PUBLIC_KEY_PATH=" + [Environment]::GetEnvironmentVariable("EDR_COMMAND_SIGNING_PUBLIC_KEY_PATH", "Machine")
  "EDR_COMMAND_STATE_DIR=" + [Environment]::GetEnvironmentVariable("EDR_COMMAND_STATE_DIR", "Machine")
} (Join-Path $OutputDir "machine-command-environment.txt")

Write-CommandOutput {
  "local_time=$((Get-Date).ToString('o'))"
  "utc_time=$([DateTime]::UtcNow.ToString('o'))"
  "unix_time_ms=$([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds())"
  "timezone=$(& tzutil.exe /g)"
  "--- w32time source ---"
  & w32tm.exe /query /source
  "--- w32time status ---"
  & w32tm.exe /query /status /verbose
  "--- w32time configuration ---"
  & w32tm.exe /query /configuration
} (Join-Path $OutputDir "time-sync.txt")

$caPath = Join-Path $InstallDir "certs\ca.pem"
$signingPath = Join-Path $InstallDir "certs\command-signing.pub.pem"
Write-CommandOutput {
  "ca_exists=$(Test-Path -LiteralPath $caPath)"
  "command_signing_key_exists=$(Test-Path -LiteralPath $signingPath)"
  if (Test-Path -LiteralPath $caPath) { & certutil.exe -dump $caPath }
  if (Test-Path -LiteralPath $signingPath) { & certutil.exe -dump $signingPath }
} (Join-Path $OutputDir "trust-and-signing.txt")

$startTime = (Get-Date).AddMinutes(-$LookbackMinutes)
$eventLogs = @(
  "Application",
  "System",
  "Microsoft-Windows-TaskScheduler/Operational",
  "Microsoft-Windows-Windows Defender/Operational"
)
foreach ($eventLog in $eventLogs) {
  $safeName = $eventLog -replace '[\\/]', '_'
  Write-CommandOutput {
    Get-WinEvent -FilterHashtable @{ LogName = $eventLog; StartTime = $startTime } -ErrorAction SilentlyContinue |
      Format-List TimeCreated,Id,ProviderName,LevelDisplayName,Message
  } (Join-Path $OutputDir ("events-{0}.txt" -f $safeName))
}

$archive = "$OutputDir.zip"
if (Test-Path -LiteralPath $archive) {
  Remove-Item -LiteralPath $archive -Force
}
Compress-Archive -Path (Join-Path $OutputDir "*") -DestinationPath $archive -Force
Write-Host "RTR diagnostic archive: $archive"
Write-Host "The archive contains a sanitized agent.toml; bearer and request-signing secrets are redacted."
