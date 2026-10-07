#Requires -Version 5.1
<#
.SYNOPSIS
  Post-install verification for the bundled Windows setup flow.

.DESCRIPTION
  Reads agent.toml, verifies required identity fields, performs a best-effort
  runtime policy pull, checks that the agent runtime is present, and writes a
  JSON report consumed by the Inno installer summary/diagnostics bundle.
#>
param(
  [string]$InstallDir = $(if ($env:EDR_INSTALL_DIR) { $env:EDR_INSTALL_DIR } else { "C:\Program Files\FDSecurity" }),
  [string]$ConfigPath = "",
  [string]$ReportPath = $(if ($env:EDR_VERIFY_REPORT_PATH) { $env:EDR_VERIFY_REPORT_PATH } else { "" }),
  [string]$LogPath = $(if ($env:EDR_VERIFY_LOG_PATH) { $env:EDR_VERIFY_LOG_PATH } else { "" }),
  [int]$PolicyTimeoutSec = 8,
  [ValidateSet("auto", "service", "scheduled_task", "manual")][string]$RuntimeMode = "auto",
  [string]$InstallationRunId = ""
)

$ErrorActionPreference = "Stop"
$checkId = [Guid]::NewGuid().ToString("N")

if (-not $ConfigPath) {
  $ConfigPath = Join-Path $InstallDir "agent.toml"
}
if (-not $ReportPath) {
  $ReportPath = Join-Path $InstallDir "install_runtime_verify.json"
}
if (-not $LogPath) {
  $reportDirForLog = Split-Path -Parent ([System.IO.Path]::GetFullPath($ReportPath))
  if (-not $reportDirForLog) { $reportDirForLog = $InstallDir }
  $LogPath = Join-Path $reportDirForLog "install_runtime_verify.log"
}

function Write-VerifyLog {
  param([string]$Message)
  try {
    $path = [System.IO.Path]::GetFullPath($LogPath)
    $dir = Split-Path -Parent $path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
      New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    Add-Content -LiteralPath $path -Value ("{0:o} {1}" -f (Get-Date).ToUniversalTime(), $Message) -Encoding UTF8
  } catch {
    Write-Warning ("postinstall verifier could not write log: " + $_.Exception.Message)
  }
}

function Read-TomlString {
  param([string]$Path, [string]$Key, [string]$Section = "")
  if (-not (Test-Path -LiteralPath $Path)) { return "" }
  $pattern = '^\s*' + [regex]::Escape($Key) + '\s*=\s*"([^"]*)"'
  $reader = [System.IO.File]::OpenText(([System.IO.Path]::GetFullPath($Path)))
  $currentSection = ""
  try {
    while ($null -ne ($line = $reader.ReadLine())) {
      if ($line -match '^\s*\[([^\]]+)\]\s*(?:#.*)?$') { $currentSection = $Matches[1].Trim(); continue }
      if ($Section -and $currentSection -cne $Section) { continue }
      $m = [regex]::Match($line, $pattern)
      if ($m.Success) { return $m.Groups[1].Value }
    }
  } finally {
    $reader.Dispose()
  }
  return ""
}

# This is the same bearer owner/precedence as edr_transport_init_from_config.
# Restrict the TOML read to [platform]; never select an identically named key
# from another section or put the credential in command arguments or reports.
function Read-AgentPolicyBearer {
  param([string]$Path)
  $bearer = [Environment]::GetEnvironmentVariable('EDR_PLATFORM_BEARER', 'Process')
  if (-not $bearer) {
    $bearer = ''; $section = ''; $found = $false
    $reader = [IO.File]::OpenText([IO.Path]::GetFullPath($Path))
    try {
      while ($null -ne ($line = $reader.ReadLine())) {
        if ($line -match '^\s*\[([^\]]+)\]\s*(?:#.*)?$') { $section = $Matches[1].Trim(); continue }
        if ($section -ceq 'platform' -and $line -match '^\s*rest_bearer_token\s*=') {
          if ($found) { throw 'policy_bearer_source_invalid' }
          $found = $true
          # Bearer token68 contains no TOML escapes; reject malformed or multiline
          # values instead of guessing a different credential than the Agent.
          $m = [regex]::Match($line, '^\s*rest_bearer_token\s*=\s*(["''])([A-Za-z0-9._~+/=-]*)\1\s*(?:#.*)?$')
          if (-not $m.Success) { throw 'policy_bearer_source_invalid' }
          $bearer = $m.Groups[2].Value
        }
      }
    } finally { $reader.Dispose() }
  }
  if (-not $bearer) { throw 'policy_bearer_missing' }
  if ($bearer.Length -gt 511 -or $bearer -cnotmatch '^[A-Za-z0-9._~+/-]+=*$') { throw 'policy_bearer_source_invalid' }
  return $bearer
}

function Invoke-AgentPolicyVerification {
  param([string]$Path, [string]$Url, [string]$RestBaseUrl, [string]$RelayUrl,
        [string]$EndpointId, [string]$TenantId, [int]$TimeoutSec, [hashtable]$ProxyOptions)
  $result = [ordered]@{ status = 'warning'; message = 'policy_request_failed'; version = '' }
  $headers = @{}; $bearer = $null
  try {
    $uri = $null
    if (-not [Uri]::TryCreate($Url, [UriKind]::Absolute, [ref]$uri) -or
        $uri.Scheme -cne 'https' -or $uri.UserInfo -or $uri.Fragment) { throw 'policy_url_invalid' }
    # A configured remote URL is not authority to disclose the platform token
    # to an arbitrary host. Redirects are disabled for the same reason.
    $trustedOrigin = $false
    foreach ($base in @($RestBaseUrl, $RelayUrl)) {
      $baseUri = $null
      if ([Uri]::TryCreate($base, [UriKind]::Absolute, [ref]$baseUri) -and
          $baseUri.Scheme -ceq 'https' -and -not $baseUri.UserInfo -and
          $baseUri.DnsSafeHost -ieq $uri.DnsSafeHost -and $baseUri.Port -eq $uri.Port) { $trustedOrigin = $true }
    }
    if (-not $trustedOrigin) { throw 'policy_url_origin_mismatch' }
    $bearer = Read-AgentPolicyBearer -Path $Path
    $headers['Authorization'] = 'Bearer ' + $bearer
    if ($EndpointId) { $headers['X-Endpoint-ID'] = $EndpointId }
    if ($TenantId) { $headers['X-Tenant-ID'] = $TenantId }
    $resp = Invoke-WebRequest -Uri $uri -Headers $headers -UseBasicParsing -TimeoutSec $TimeoutSec -MaximumRedirection 0 @ProxyOptions
    if ([int]$resp.StatusCode -ne 200) { throw 'policy_http_status_unexpected' }
    $result.status = 'ok'; $result.message = 'authenticated_policy_http_200'
    # This verifies an authenticated fetch only. Signature/application status
    # continues to belong to the running Agent's signed policy owner.
    $result.version = Read-PolicyVersionFromText -Text ([string]$resp.Content)
    if (-not $result.version) { $result.version = 'runtime-policy' }
  } catch {
    $result.status = 'warning'; $result.message = 'policy_request_failed'; $result.version = ''
    $known = @('policy_bearer_missing', 'policy_bearer_source_invalid', 'policy_url_invalid', 'policy_url_origin_mismatch', 'policy_http_status_unexpected')
    if ($known -ccontains $_.Exception.Message) { $result.message = $_.Exception.Message }
    elseif ($_.Exception.Response -and $_.Exception.Response.StatusCode) { $result.message = 'policy_http_' + [int]$_.Exception.Response.StatusCode }
    # Never include response bodies, request headers, or arbitrary exception text.
  } finally {
    $headers.Clear(); $bearer = $null
  }
  return $result
}

function Read-TextFile {
  param([string]$Path)
  if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return "" }
  try {
    return Get-Content -LiteralPath $Path -Raw -Encoding UTF8
  } catch {
    return ""
  }
}

function Read-AgentVersion {
  foreach ($candidate in @((Join-Path $InstallDir "VERSION"), (Join-Path (Split-Path -Parent $PSScriptRoot) "VERSION"))) {
    $text = Read-TextFile -Path $candidate
    if ($text.Trim()) {
      return $text.Trim()
    }
  }
  return ""
}

function Read-PolicyVersionFromText {
  param([string]$Text)
  if (-not $Text) { return "" }
  foreach ($pattern in @(
      '(?m)^\s*policy_version\s*=\s*"([^"]+)"',
      '(?m)^\s*version\s*=\s*"([^"]+)"',
      '(?m)^\s*name\s*=\s*"([^"]+)"'
    )) {
    $m = [regex]::Match($Text, $pattern)
    if ($m.Success) { return $m.Groups[1].Value }
  }
  return ""
}

function Read-P0BundleSummary {
  $summary = [ordered]@{ version = ""; count = "" }
  foreach ($candidate in @(
      (Join-Path $InstallDir "edr_config\sensor_interest_manifest.json"),
      (Join-Path $InstallDir "edr_config\p0_rule_bundle_manifest.json"),
      (Join-Path $InstallDir "p0_rule_bundle_manifest.json")
    )) {
    $raw = Read-TextFile -Path $candidate
    if (-not $raw) { continue }
    try {
      $j = $raw | ConvertFrom-Json
      if ($j.rules_bundle_version) { $summary.version = [string]$j.rules_bundle_version }
      if ($j.enabled_rules) { $summary.count = [string]$j.enabled_rules }
      elseif ($j.rules) { $summary.count = [string]@($j.rules).Count }
      if ($summary.version -or $summary.count) { return $summary }
    } catch {}
  }
  return $summary
}

function Normalize-ProxyModeValue {
  param([string]$Value)
  $v = if ($Value) { $Value.Trim().ToLowerInvariant() } else { "auto" }
  switch ($v) {
    "off" { return "off" }
    "direct" { return "off" }
    "none" { return "off" }
    "explicit" { return "explicit" }
    "manual" { return "explicit" }
    "proxy" { return "explicit" }
    default { return "auto" }
  }
}

function Get-WebRequestProxyOptions {
  param([string]$Mode, [string]$Url)
  $opts = @{}
  if ($Mode -ne "explicit") {
    return $opts
  }
  $raw = if ($Url) { $Url.Trim() } else { "" }
  if (-not $raw) {
    return $opts
  }
  try {
    $u = [System.Uri]$raw
  } catch {
    return $opts
  }
  if ($u.Scheme -ne "http" -and $u.Scheme -ne "https") {
    return $opts
  }
  $b = New-Object System.UriBuilder -ArgumentList $u
  if ($u.UserInfo) {
    $parts = $u.UserInfo.Split([char[]]@(':'), 2)
    $user = [System.Uri]::UnescapeDataString($parts[0])
    $pass = if ($parts.Count -gt 1) { [System.Uri]::UnescapeDataString($parts[1]) } else { "" }
    $secure = ConvertTo-SecureString $pass -AsPlainText -Force
    $opts["ProxyCredential"] = New-Object System.Management.Automation.PSCredential -ArgumentList $user, $secure
    $b.UserName = ""
    $b.Password = ""
  }
  $opts["Proxy"] = $b.Uri.AbsoluteUri
  return $opts
}

function Format-ProxySummary {
  param([string]$Mode, [string]$Url)
  if ($Mode -ne "explicit") {
    return $Mode
  }
  if (-not $Url) {
    return "explicit proxy_url missing"
  }
  try {
    $u = [System.Uri]$Url
    $b = New-Object System.UriBuilder -ArgumentList $u
    $b.UserName = ""
    $b.Password = ""
    return "explicit " + $b.Uri.GetLeftPart([System.UriPartial]::Authority)
  } catch {
    return "explicit proxy_url invalid"
  }
}

function New-Check {
  param([string]$Name, [string]$Status, [string]$Message)
  return [ordered]@{
    name = $Name
    status = $Status
    message = $Message
  }
}

function Write-Report {
  param([object]$Report)
  $path = [System.IO.Path]::GetFullPath($ReportPath)
  $dir = Split-Path -Parent $path
  if ($dir -and -not (Test-Path -LiteralPath $dir)) {
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
  }
  $json = $Report | ConvertTo-Json -Depth 8
  $temporary = $path + "." + $checkId + ".tmp"
  $utf8NoBom = New-Object System.Text.UTF8Encoding -ArgumentList $false
  try {
    [System.IO.File]::WriteAllText($temporary, $json, $utf8NoBom)
    if ([System.IO.File]::Exists($path)) {
      # Windows PowerShell converts $null to an empty string for this .NET
      # string parameter. NullString supplies the actual no-backup null value.
      [System.IO.File]::Replace($temporary, $path, [NullString]::Value)
    } else {
      [System.IO.File]::Move($temporary, $path)
    }
  } finally {
    if ([System.IO.File]::Exists($temporary)) { [System.IO.File]::Delete($temporary) }
  }
  Write-VerifyLog ("report=" + $path)
  Write-Host "postinstall_verify_report=$path"
}

trap {
  $err = $_
  $msg = if ($err -and $err.Exception) { $err.Exception.Message } else { [string]$err }
  Write-VerifyLog ("ERROR " + $msg)
  try {
    if (-not $script:checks) {
      $script:checks = New-Object System.Collections.Generic.List[object]
    }
    $script:checks.Add((New-Check -Name "script_exception" -Status "failed" -Message $msg)) | Out-Null
    $fallbackReport = [ordered]@{
      schema = "edr.installation-verification.v2"
      scope = "installation_runtime_snapshot"
      check_id = $checkId
      installation_run_id = $InstallationRunId
      created_at = (Get-Date).ToUniversalTime().ToString("o")
      status = "failed"
      install_dir = $(try { [System.IO.Path]::GetFullPath($InstallDir) } catch { $InstallDir })
      config_path = $(try { [System.IO.Path]::GetFullPath($ConfigPath) } catch { $ConfigPath })
      endpoint_id = $script:endpointId
      tenant_id = $script:tenantId
      rest_base_url = $script:restBase
      runtime_policy_url = $script:runtimePolicyUrl
      policy_version = ""
      p0_rule_version = ""
      p0_rule_count = ""
      agent_version = ""
      agent_process_running = $false
      scheduled_task_state = ""
      service_state = ""
      runtime_mode = "unknown"
      proxy_mode = ""
      proxy = ""
      checks = $script:checks
    }
    Write-Report -Report $fallbackReport
  } catch {
    Write-Warning ("postinstall verifier could not write failure report: " + $_.Exception.Message)
    Write-VerifyLog ("ERROR failure report write failed: " + $_.Exception.Message)
  }
  Write-Host ("post-install verification exception; report={0}; error={1}" -f $ReportPath, $msg)
  exit 1
}

Write-VerifyLog ("start install_dir={0} config={1} report={2}" -f $InstallDir, $ConfigPath, $ReportPath)
$checks = New-Object System.Collections.Generic.List[object]
$configExists = Test-Path -LiteralPath $ConfigPath
$configStatus = if ($configExists) { "ok" } else { "failed" }
$checks.Add((New-Check -Name "agent_toml" -Status $configStatus -Message $ConfigPath)) | Out-Null

$endpointId = Read-TomlString -Path $ConfigPath -Key "endpoint_id"
$tenantId = Read-TomlString -Path $ConfigPath -Key "tenant_id"
$restBase = Read-TomlString -Path $ConfigPath -Key "rest_base_url" -Section "platform"
$runtimePolicyUrl = Read-TomlString -Path $ConfigPath -Key "runtime_policy_url" -Section "remote"
$proxyMode = Normalize-ProxyModeValue (Read-TomlString -Path $ConfigPath -Key "proxy_mode")
$proxyUrl = Read-TomlString -Path $ConfigPath -Key "proxy_url"
$agentVersion = Read-AgentVersion
$p0Summary = Read-P0BundleSummary
if ($proxyMode -eq "off") {
  [System.Net.WebRequest]::DefaultWebProxy = New-Object System.Net.WebProxy
}
$webRequestProxyOptions = Get-WebRequestProxyOptions -Mode $proxyMode -Url $proxyUrl

$endpointStatus = if ($endpointId) { "ok" } else { "failed" }
$endpointMessage = if ($endpointId) { $endpointId } else { "missing endpoint_id" }
$tenantStatus = if ($tenantId) { "ok" } else { "failed" }
$tenantMessage = if ($tenantId) { $tenantId } else { "missing tenant_id" }
$restStatus = if ($restBase) { "ok" } else { "warning" }
$restMessage = if ($restBase) { $restBase } else { "missing rest_base_url" }
$checks.Add((New-Check -Name "endpoint_id" -Status $endpointStatus -Message $endpointMessage)) | Out-Null
$checks.Add((New-Check -Name "tenant_id" -Status $tenantStatus -Message $tenantMessage)) | Out-Null
$checks.Add((New-Check -Name "rest_base_url" -Status $restStatus -Message $restMessage)) | Out-Null
$checks.Add((New-Check -Name "proxy_config" -Status "ok" -Message (Format-ProxySummary -Mode $proxyMode -Url $proxyUrl))) | Out-Null

$policyStatus = "skipped"
$policyMessage = "runtime_policy_url missing"
$policyVersion = ""
if ($runtimePolicyUrl) {
  $policyCheck = Invoke-AgentPolicyVerification -Path $ConfigPath -Url $runtimePolicyUrl -RestBaseUrl $restBase -RelayUrl (Read-TomlString -Path $ConfigPath -Key "relay_url" -Section "platform") -EndpointId $endpointId -TenantId $tenantId -TimeoutSec $PolicyTimeoutSec -ProxyOptions $webRequestProxyOptions
  $policyStatus = $policyCheck.status
  $policyMessage = $policyCheck.message
  $policyVersion = $policyCheck.version
  Write-VerifyLog ("runtime_policy_pull " + $policyMessage)
}
$checks.Add((New-Check -Name "runtime_policy_pull" -Status $policyStatus -Message $policyMessage)) | Out-Null

# Observe the installed image, not another process with the same filename.
$procCount = 0
$processState = "missing"
$binaryState = "missing"
$expectedImages = @((Join-Path $InstallDir "FDSensor.exe"), (Join-Path $InstallDir "edr_agent.exe"))
try {
  foreach ($path in $expectedImages) {
    if (Test-Path -LiteralPath $path -PathType Leaf -ErrorAction Stop) { $binaryState = "present" }
  }
} catch { $binaryState = "unknown"; Write-VerifyLog ("binary query failed: " + $_.Exception.Message) }
try {
  $processes = @(Get-CimInstance -ClassName Win32_Process -Filter "Name='FDSensor.exe' OR Name='edr_agent.exe'" -ErrorAction Stop)
  foreach ($process in $processes) {
    if (-not $process.ExecutablePath) { $processState = "unknown"; continue }
    if ($expectedImages -contains $process.ExecutablePath) { $procCount++ }
  }
  if ($procCount -gt 0) { $processState = "running" }
} catch { $processState = "unknown"; Write-VerifyLog ("process query failed: " + $_.Exception.Message) }
$taskState = "missing"
$taskLastResult = ""
$serviceState = "missing"
try {
  $services = @(Get-Service -ErrorAction Stop | Where-Object { $_.Name -in @("FDSecurityAgent", "EdrAgent") })
  if ($services.Count -gt 0) { $serviceState = ([string]$services[0].Status).ToLowerInvariant() }
} catch { $serviceState = "unknown"; Write-VerifyLog ("service query failed: " + $_.Exception.Message) }
try {
  $tasks = @(Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.TaskName -in @("FDSecurityAgent", "EdrAgent") })
  if ($tasks.Count -gt 0) {
    $taskState = ([string]$tasks[0].State).ToLowerInvariant()
    $taskLastResult = [string](Get-ScheduledTaskInfo -InputObject $tasks[0] -ErrorAction Stop).LastTaskResult
  }
} catch { $taskState = "unknown"; Write-VerifyLog ("task query failed: " + $_.Exception.Message) }
$effectiveMode = $RuntimeMode
if ($effectiveMode -eq "auto") {
  $effectiveMode = if ($serviceState -notin @("missing", "unknown")) { "service" } elseif ($taskState -notin @("missing", "unknown")) { "scheduled_task" } else { "manual" }
}
$runtimeStatus = "ok"
if ($binaryState -eq "missing" -or $processState -eq "missing" -or
    ($effectiveMode -eq "service" -and $serviceState -in @("missing", "stopped")) -or
    ($effectiveMode -eq "scheduled_task" -and $taskState -in @("missing", "disabled", "ready"))) {
  $runtimeStatus = "failed"
} elseif ($binaryState -eq "unknown" -or $processState -eq "unknown" -or
    ($effectiveMode -eq "service" -and $serviceState -eq "unknown") -or
    ($effectiveMode -eq "scheduled_task" -and $taskState -eq "unknown") -or
    ($RuntimeMode -eq "auto" -and ($serviceState -eq "unknown" -or $taskState -eq "unknown"))) {
  $runtimeStatus = "unknown"
} elseif (($effectiveMode -eq "service" -and $serviceState -ne "running") -or
          ($effectiveMode -eq "scheduled_task" -and $taskState -ne "running")) {
  $runtimeStatus = "warning"
}
$runtimeMsg = "binary=$binaryState process=$processState process_count=$procCount service=$serviceState task=$taskState task_last_result=$taskLastResult mode=$effectiveMode"
$checks.Add((New-Check -Name "runtime_presence" -Status $runtimeStatus -Message $runtimeMsg)) | Out-Null

# Bootstrap installation history is a diagnostic reference, never a live check.
$healthReport = Join-Path $InstallDir "install_health_report.json"
$failed = @($checks | Where-Object { $_.status -eq "failed" }).Count
$unknown = @($checks | Where-Object { $_.status -eq "unknown" }).Count
$warnings = @($checks | Where-Object { $_.status -eq "warning" }).Count
$overallStatus = if ($failed -gt 0) { "failed" } elseif ($unknown -gt 0) { "unknown" } elseif ($warnings -gt 0) { "warning" } else { "ok" }
$report = [ordered]@{
  schema = "edr.installation-verification.v2"
  scope = "installation_runtime_snapshot"
  check_id = $checkId
  installation_run_id = $InstallationRunId
  historical_installation_report_path = $healthReport
  capability_health = "unknown"
  created_at = (Get-Date).ToUniversalTime().ToString("o")
  status = $overallStatus
  install_dir = [System.IO.Path]::GetFullPath($InstallDir)
  config_path = [System.IO.Path]::GetFullPath($ConfigPath)
  endpoint_id = $endpointId
  tenant_id = $tenantId
  rest_base_url = $restBase
  runtime_policy_url = $runtimePolicyUrl
  policy_version = $policyVersion
  p0_rule_version = [string]$p0Summary["version"]
  p0_rule_count = [string]$p0Summary["count"]
  agent_version = $agentVersion
  binary_state = $binaryState
  process_state = $processState
  agent_process_running = ($procCount -gt 0)
  scheduled_task_state = $taskState
  scheduled_task_last_result = $taskLastResult
  service_state = $serviceState
  runtime_mode = $effectiveMode
  proxy_mode = $proxyMode
  proxy = (Format-ProxySummary -Mode $proxyMode -Url $proxyUrl)
  checks = $checks
}

Write-Report -Report $report
if ($failed -gt 0) {
  Write-VerifyLog ("failed_checks=" + $failed)
  Write-Host "post-install verification failed; report=$ReportPath"
  exit 1
}
if ($overallStatus -ne "ok") {
  Write-VerifyLog ("verification_status=" + $overallStatus)
  exit 2
}
Write-VerifyLog "ok"
exit 0
