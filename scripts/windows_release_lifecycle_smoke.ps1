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
    $service = Get-Service -Name $serviceName -ErrorAction Stop
    if ($service.Status -ne "Running") {
      throw "service $serviceName stopped during stability window: $($service.Status)"
    }
  }
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
  if ((Get-Service -Name $serviceName).Status -ne "Running") {
    throw "$Operation left service non-running"
  }
}

New-Item -ItemType Directory -Path $EvidenceDir -Force | Out-Null
Assert-Administrator

$baselineBinary = Find-OneFile -Root $BaselinePackageDir -Name "FDSensor.exe"
$targetBinary = Find-OneFile -Root $TargetPackageDir -Name "FDSensor.exe"
$baselineRoot = Split-Path -Parent $baselineBinary
$targetRoot = Split-Path -Parent $targetBinary
$baselineInstaller = Find-OneFile -Root $BaselinePackageDir -Name "windows_service_install.ps1"
$targetUpdater = Find-OneFile -Root $TargetPackageDir -Name "edr_agent_inplace_update.ps1"
$baselineTemplate = Find-OneFile -Root $BaselinePackageDir -Name "agent_windows_production.example.toml"

if ((Get-AgentVersion -Path $baselineBinary) -ne $BaselineVersion) {
  throw "baseline binary ProductVersion does not match $BaselineVersion"
}
if ((Get-AgentVersion -Path $targetBinary) -ne $TargetVersion) {
  throw "target binary ProductVersion does not match $TargetVersion"
}

try {
  $existing = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
  if ($existing) {
    Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
    & sc.exe delete $serviceName | Out-Null
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

  & $baselineInstaller -Action Install -ServiceName $serviceName `
    -DisplayName "FDSecurity Agent CI Lifecycle Smoke" `
    -ExePath (Join-Path $installDir "FDSensor.exe") `
    -ConfigPath $configPath -InstallDir $installDir -DataDir $installDir `
    -SkipPreflight -NoStart
  if ($LASTEXITCODE -ne 0) { throw "headless install failed with exit code $LASTEXITCODE" }
  Wait-ServiceStable

  Invoke-VersionTransition -Operation upgrade -Candidate $targetBinary `
    -Version $TargetVersion -ArtifactID "ci-$TargetVersion-amd64" -UpdateScript $targetUpdater
  $embeddedUpdaterSha256 = Wait-EmbeddedUpdaterMaterialized -Version $TargetVersion `
    -ExpectedScript $targetUpdater
  Invoke-VersionTransition -Operation rollback -Candidate $baselineBinary `
    -Version $BaselineVersion -ArtifactID "ci-$BaselineVersion-amd64" -UpdateScript $targetUpdater

  & $baselineInstaller -Action Uninstall -ServiceName $serviceName `
    -ExePath (Join-Path $installDir "FDSensor.exe") `
    -ConfigPath $configPath -InstallDir $installDir -DataDir $installDir `
    -SkipPreflight
  if ($LASTEXITCODE -ne 0) { throw "headless uninstall failed with exit code $LASTEXITCODE" }
  if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
    throw "service still exists after uninstall"
  }

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
    completed_at = [DateTimeOffset]::UtcNow.ToString("o")
  } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $EvidenceDir "summary.json") -Encoding UTF8
} finally {
  Get-Service -Name $serviceName -ErrorAction SilentlyContinue |
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
