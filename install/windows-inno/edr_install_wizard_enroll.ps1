#Requires -Version 5.1
<#
  由 EDRAgentSetup.iss 的 [Run] 调用：读取向导写入的 JSON，调用同目录 edr_agent_install.ps1 完成 enroll。
  参数 1：JSON 路径（含 api_base、token、insecure_tls）
  参数 2：输出的 agent.toml 绝对路径（安装器传 {app}\agent.toml，与 edr_agent.exe 同目录）
#>
param(
  [Parameter(Mandatory = $true)][string]$ParamsFile,
  [Parameter(Mandatory = $true)][string]$OutToml
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $ParamsFile)) {
  Write-Error "Missing params file: $ParamsFile"
}

$raw = Get-Content -LiteralPath $ParamsFile -Raw -Encoding UTF8
$j = $raw | ConvertFrom-Json
if (-not $j.api_base -or -not $j.token) {
  Write-Error "Invalid enroll params (need api_base and token)"
}

$env:EDR_API_BASE = [string]$j.api_base
$env:EDR_ENROLL_TOKEN = [string]$j.token
if ($j.insecure_tls -eq $true) {
  $env:EDR_INSECURE_TLS = "1"
} else {
  Remove-Item Env:EDR_INSECURE_TLS -ErrorAction SilentlyContinue
}

$proxyMode = if ($j.proxy_mode) { [string]$j.proxy_mode } else { "auto" }
$proxyUrl = if ($j.proxy_url) { [string]$j.proxy_url } else { "" }
$relayUrl = if ($j.relay_url) { [string]$j.relay_url } else { "" }
$healthReport = if ($j.health_report) { [string]$j.health_report } else { "" }
$keepOfflineQueue = ($j.keep_offline_queue -eq $true)
$keepEvidenceCache = ($j.keep_evidence_cache -eq $true)
$strictHealthCheck = ($j.strict_health_check -eq $true)
$trustCa = ($j.trust_ca -eq $true)

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$installer = Join-Path $here "edr_agent_install.ps1"
if (-not (Test-Path -LiteralPath $installer)) {
  Write-Error "Missing bundled installer script: $installer"
}

$installDir = Split-Path -Parent ([System.IO.Path]::GetFullPath($OutToml))
$installerArgs = @(
  "-Output", $OutToml,
  "-UseTemplateToml",
  "-CaCertPath", (Join-Path $installDir "certs\ca.pem"),
  "-ClientCertPath", (Join-Path $installDir "certs\client.pem"),
  "-ClientKeyPath", (Join-Path $installDir "certs\client-key.pem"),
  "-ClientCsrPath", (Join-Path $installDir "certs\client.csr.pem"),
  "-ProxyMode", $proxyMode,
  "-ProxyUrl", $proxyUrl,
  "-RelayUrl", $relayUrl
)

if ($healthReport) {
  $installerArgs += @("-HealthReportPath", $healthReport)
} else {
  $installerArgs += @("-HealthReportPath", (Join-Path $installDir "install_health_report.json"))
}
if ($keepOfflineQueue) { $installerArgs += "-KeepOfflineQueue" }
if ($keepEvidenceCache) { $installerArgs += "-KeepEvidenceCache" }
if ($strictHealthCheck) { $installerArgs += "-StrictHealthCheck" }
if ($trustCa) { $installerArgs += "-TrustCa" }

& $installer @installerArgs

Remove-Item -LiteralPath $ParamsFile -Force -ErrorAction SilentlyContinue
