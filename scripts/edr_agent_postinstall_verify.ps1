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
  [string]$ReportPath = "",
  [int]$PolicyTimeoutSec = 8
)

$ErrorActionPreference = "Stop"

if (-not $ConfigPath) {
  $ConfigPath = Join-Path $InstallDir "agent.toml"
}
if (-not $ReportPath) {
  $ReportPath = Join-Path $InstallDir "install_runtime_verify.json"
}

function Read-TomlString {
  param([string]$Path, [string]$Key)
  if (-not (Test-Path -LiteralPath $Path)) { return "" }
  $pattern = '^\s*' + [regex]::Escape($Key) + '\s*=\s*"([^"]*)"'
  foreach ($line in [System.IO.File]::ReadLines(([System.IO.Path]::GetFullPath($Path)))) {
    $m = [regex]::Match($line, $pattern)
    if ($m.Success) { return $m.Groups[1].Value }
  }
  return ""
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
  $b = [System.UriBuilder]::new($u)
  if ($u.UserInfo) {
    $parts = $u.UserInfo.Split(":", 2)
    $user = [System.Uri]::UnescapeDataString($parts[0])
    $pass = if ($parts.Count -gt 1) { [System.Uri]::UnescapeDataString($parts[1]) } else { "" }
    $secure = ConvertTo-SecureString $pass -AsPlainText -Force
    $opts["ProxyCredential"] = [System.Management.Automation.PSCredential]::new($user, $secure)
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
    $b = [System.UriBuilder]::new($u)
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
  $Report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $path -Encoding UTF8
  Write-Host "postinstall_verify_report=$path"
}

$checks = New-Object System.Collections.Generic.List[object]
$configExists = Test-Path -LiteralPath $ConfigPath
$configStatus = if ($configExists) { "ok" } else { "failed" }
$checks.Add((New-Check -Name "agent_toml" -Status $configStatus -Message $ConfigPath)) | Out-Null

$endpointId = Read-TomlString -Path $ConfigPath -Key "endpoint_id"
$tenantId = Read-TomlString -Path $ConfigPath -Key "tenant_id"
$restBase = Read-TomlString -Path $ConfigPath -Key "rest_base_url"
$runtimePolicyUrl = Read-TomlString -Path $ConfigPath -Key "runtime_policy_url"
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
  try {
    $headers = @{}
    if ($endpointId) { $headers["X-Endpoint-ID"] = $endpointId }
    if ($tenantId) { $headers["X-Tenant-ID"] = $tenantId }
    $resp = Invoke-WebRequest -Uri $runtimePolicyUrl -Headers $headers -UseBasicParsing -TimeoutSec $PolicyTimeoutSec @webRequestProxyOptions
    $policyStatus = "ok"
    $policyMessage = "HTTP $($resp.StatusCode) $runtimePolicyUrl"
    $policyVersion = Read-PolicyVersionFromText -Text ([string]$resp.Content)
    if (-not $policyVersion) { $policyVersion = "runtime-policy" }
  } catch {
    $policyStatus = "warning"
    $policyMessage = "policy pull failed: $($_.Exception.Message)"
  }
}
$checks.Add((New-Check -Name "runtime_policy_pull" -Status $policyStatus -Message $policyMessage)) | Out-Null

$procCount = 0
foreach ($procName in @("FDSensor", "edr_agent")) {
  $procCount += @((Get-Process -Name $procName -ErrorAction SilentlyContinue)).Count
}
$taskState = ""
$serviceState = ""
try {
  foreach ($taskName in @("FDSecurityAgent", "EdrAgent")) {
    $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if ($task) { $taskState = [string]$task.State; break }
  }
} catch {}
try {
  foreach ($svcName in @("FDSecurityAgent", "EdrAgent")) {
    $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
    if ($svc) { $serviceState = [string]$svc.Status; break }
  }
} catch {}
$runtimeOk = ($procCount -gt 0 -or $taskState -or $serviceState)
$runtimeMsg = "process_count=$procCount"
if ($taskState) { $runtimeMsg += " scheduled_task=$taskState" }
if ($serviceState) { $runtimeMsg += " service=$serviceState" }
$runtimeStatus = if ($runtimeOk) { "ok" } else { "warning" }
$checks.Add((New-Check -Name "runtime_presence" -Status $runtimeStatus -Message $runtimeMsg)) | Out-Null

$reportDir = Split-Path -Parent ([System.IO.Path]::GetFullPath($ReportPath))
$healthReport = Join-Path $reportDir "install_health_report.json"
if (-not (Test-Path -LiteralPath $healthReport)) {
  $healthReport = Join-Path $InstallDir "install_health_report.json"
}
$healthOk = $false
if (Test-Path -LiteralPath $healthReport) {
  try {
    $raw = Get-Content -LiteralPath $healthReport -Raw -Encoding UTF8
    $healthOk = ($raw -match '"status"\s*:\s*"ok"')
  } catch {}
}
$healthStatus = if ($healthOk) { "ok" } else { "pending" }
$healthMessage = if ($healthOk) { $healthReport } else { "waiting for agent heartbeat or bootstrap report" }
$checks.Add((New-Check -Name "bootstrap_health" -Status $healthStatus -Message $healthMessage)) | Out-Null

$failed = @($checks | Where-Object { $_.status -eq "failed" }).Count
$overallStatus = if ($failed -eq 0) { "ok" } else { "failed" }
$report = [ordered]@{
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
  agent_process_running = ($procCount -gt 0)
  scheduled_task_state = $taskState
  service_state = $serviceState
  runtime_mode = $(if ($serviceState) { "windows_service" } elseif ($taskState) { "scheduled_task" } else { "manual" })
  proxy_mode = $proxyMode
  proxy = (Format-ProxySummary -Mode $proxyMode -Url $proxyUrl)
  checks = $checks
}

Write-Report -Report $report
if ($failed -gt 0) {
  Write-Error "post-install verification failed; report=$ReportPath"
}
