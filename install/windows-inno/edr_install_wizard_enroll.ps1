#Requires -Version 5.1
<#
  由 EDRAgentSetup.iss 的 [Run] 调用：读取向导写入的 JSON，调用同目录 edr_agent_install.ps1 完成 enroll。
  参数 1：JSON 路径（含 api_base、token、insecure_tls）
  参数 2：输出的 agent.toml 绝对路径（安装器传 {app}\agent.toml，与 FDSensor.exe 同目录）
  参数 3：诊断目录（可选；用于写 enroll-output.log）
#>
param(
  [Parameter(Mandatory = $true)][string]$ParamsFile,
  [Parameter(Mandatory = $true)][string]$OutToml,
  [string]$DiagnosticsDir = ""
)

$ErrorActionPreference = "Stop"

if (-not $DiagnosticsDir) {
  $outDir = Split-Path -Parent ([System.IO.Path]::GetFullPath($OutToml))
  $DiagnosticsDir = Join-Path $outDir "diagnostics"
}
New-Item -ItemType Directory -Path $DiagnosticsDir -Force | Out-Null
$EnrollLogPath = Join-Path $DiagnosticsDir "enroll-output.log"
[System.IO.File]::WriteAllText(
  ([System.IO.Path]::GetFullPath($EnrollLogPath)),
  ("FDSecurity enroll stage log`r`ncreated_at={0:o}`r`n" -f (Get-Date).ToUniversalTime())
)

function Write-EnrollLog {
  param([string]$Message)
  $line = ("{0:o} {1}" -f (Get-Date).ToUniversalTime(), $Message)
  Add-Content -LiteralPath $EnrollLogPath -Value $line -Encoding UTF8
}

function Get-RedactedUrl {
  param([string]$Value)
  if (-not $Value) { return "" }
  try {
    $u = [System.Uri]$Value
    $b = [System.UriBuilder]::new($u)
    if ($u.UserInfo) {
      $b.UserName = "***"
      $b.Password = "***"
    }
    return $b.Uri.AbsoluteUri
  } catch {
    return $Value
  }
}

function Format-ArgForLog {
  param([string]$Value)
  if ($null -eq $Value) { return "<null>" }
  $v = [string]$Value
  if ($v.Length -eq 0) { return '""' }
  if ($v -match '\s|["]') {
    return ('"{0}"' -f ($v -replace '"', '\"'))
  }
  return $v
}

function Format-ArgsForLog {
  param([string[]]$Args)
  $out = New-Object System.Collections.Generic.List[string]
  $redactNext = $false
  foreach ($arg in $Args) {
    if ($redactNext) {
      $out.Add((Format-ArgForLog (Get-RedactedUrl $arg))) | Out-Null
      $redactNext = $false
      continue
    }
    $out.Add((Format-ArgForLog $arg)) | Out-Null
    if ($arg -eq "-ProxyUrl" -or $arg -eq "-RelayUrl") {
      $redactNext = $true
    }
  }
  return ($out -join " ")
}

if (-not (Test-Path -LiteralPath $ParamsFile)) {
  Write-EnrollLog "ERROR missing params file: $ParamsFile"
  Write-Error "Missing params file: $ParamsFile"
}

$raw = Get-Content -LiteralPath $ParamsFile -Raw -Encoding UTF8
$j = $raw | ConvertFrom-Json
if (-not $j.api_base -or -not $j.token) {
  Write-EnrollLog "ERROR invalid enroll params: api_base/token missing"
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
$keyProvider = if ($j.key_provider) { [string]$j.key_provider } else { "cng" }
$bootstrapVerified = ($j.bootstrap_manifest_verified -eq $true)
$bootstrapCaPem = if ($j.bootstrap_ca_pem) { [string]$j.bootstrap_ca_pem } else { "" }
$bootstrapLeafSha256 = if ($j.bootstrap_tls_leaf_sha256) { [string]$j.bootstrap_tls_leaf_sha256 } else { "" }
$bootstrapKeyID = if ($j.bootstrap_manifest_key_id) { [string]$j.bootstrap_manifest_key_id } else { "" }
if (($bootstrapCaPem -or $bootstrapLeafSha256) -and -not $bootstrapVerified) {
  Write-EnrollLog "ERROR bootstrap TLS material was provided without verified manifest"
  Write-Error "bootstrap TLS material requires bootstrap_manifest_verified=true"
}

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$installer = Join-Path $here "edr_agent_install.ps1"
if (-not (Test-Path -LiteralPath $installer)) {
  Write-EnrollLog "ERROR missing bundled installer script: $installer"
  Write-Error "Missing bundled installer script: $installer"
}

$installDir = Split-Path -Parent ([System.IO.Path]::GetFullPath($OutToml))
$bootstrapCaPath = ""
if ($bootstrapCaPem) {
  $certDir = Join-Path $installDir "certs"
  New-Item -ItemType Directory -Path $certDir -Force | Out-Null
  $bootstrapCaPath = Join-Path $certDir "bootstrap-ca.pem"
  $bootstrapCaText = $bootstrapCaPem.Replace("`r`n", "`n").Replace("\r\n", "`n").Replace("\n", "`n")
  [System.IO.File]::WriteAllText(([System.IO.Path]::GetFullPath($bootstrapCaPath)), $bootstrapCaText)
}
$installerArgs = @(
  "-Output", $OutToml,
  "-UseTemplateToml",
  "-KeyProvider", $keyProvider,
  "-CaCertPath", (Join-Path $installDir "certs\ca.pem"),
  "-ClientCertPath", (Join-Path $installDir "certs\client.pem"),
  "-ClientKeyPath", (Join-Path $installDir "certs\client-key.pem"),
  "-ClientCsrPath", (Join-Path $installDir "certs\client.csr.pem"),
  "-ProxyMode", $proxyMode
)

$proxyUrl = if ($proxyUrl) { $proxyUrl.Trim() } else { "" }
$relayUrl = if ($relayUrl) { $relayUrl.Trim() } else { "" }
if ($proxyUrl) {
  $env:EDR_PROXY_URL = $proxyUrl
  $installerArgs += @("-ProxyUrl", $proxyUrl)
} else {
  Remove-Item Env:EDR_PROXY_URL -ErrorAction SilentlyContinue
}
if ($relayUrl) {
  $env:EDR_RELAY_URL = $relayUrl
  $installerArgs += @("-RelayUrl", $relayUrl)
} else {
  Remove-Item Env:EDR_RELAY_URL -ErrorAction SilentlyContinue
}
if ($bootstrapCaPath) {
  $env:EDR_BOOTSTRAP_CA_CERT = $bootstrapCaPath
  $installerArgs += @("-BootstrapCaCertPath", $bootstrapCaPath)
} else {
  Remove-Item Env:EDR_BOOTSTRAP_CA_CERT -ErrorAction SilentlyContinue
}
if ($bootstrapLeafSha256) {
  $env:EDR_BOOTSTRAP_TLS_LEAF_SHA256 = $bootstrapLeafSha256
  $installerArgs += @("-BootstrapTlsLeafSha256", $bootstrapLeafSha256)
} else {
  Remove-Item Env:EDR_BOOTSTRAP_TLS_LEAF_SHA256 -ErrorAction SilentlyContinue
}

if ($healthReport) {
  $installerArgs += @("-HealthReportPath", $healthReport)
} else {
  $installerArgs += @("-HealthReportPath", (Join-Path $installDir "install_health_report.json"))
}
if ($keepOfflineQueue) { $installerArgs += "-KeepOfflineQueue" }
if ($keepEvidenceCache) { $installerArgs += "-KeepEvidenceCache" }
if ($strictHealthCheck) { $installerArgs += "-StrictHealthCheck" }
if ($trustCa) { $installerArgs += "-TrustCa" }

Write-EnrollLog ("params_file={0}" -f $ParamsFile)
Write-EnrollLog ("output_toml={0}" -f $OutToml)
Write-EnrollLog ("api_base={0}" -f (Get-RedactedUrl $env:EDR_API_BASE))
Write-EnrollLog ("proxy_mode={0} proxy_url={1}" -f $proxyMode, (Get-RedactedUrl $proxyUrl))
Write-EnrollLog ("relay_url={0}" -f (Get-RedactedUrl $relayUrl))
Write-EnrollLog ("key_provider={0} trust_ca={1} insecure_tls={2}" -f $keyProvider, $trustCa, ($j.insecure_tls -eq $true))
if ($bootstrapVerified) {
  Write-EnrollLog ("bootstrap_manifest_verified=true key_id={0} ca_path={1} leaf_pin={2}" -f $bootstrapKeyID, $bootstrapCaPath, [bool]$bootstrapLeafSha256)
}

$ps = Get-Command "powershell.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
$psExe = if ($ps) { $ps.Source } else { "powershell.exe" }
$childArgs = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $installer) + $installerArgs
Write-EnrollLog ("invoking bundled installer script: {0}" -f $installer)
Write-EnrollLog ("child_command={0} {1}" -f (Format-ArgForLog $psExe), (Format-ArgsForLog $childArgs))

$exitCode = 0
try {
  & $psExe @childArgs *>&1 | ForEach-Object {
    $line = [string]$_
    Write-EnrollLog ("child: {0}" -f $line)
    Write-Host $line
  }
  $exitCode = if ($null -ne $LASTEXITCODE) { [int]$LASTEXITCODE } else { 0 }
} catch {
  $msg = $_.Exception.Message
  Write-EnrollLog ("ERROR child invocation failed: {0}" -f $msg)
  Write-Error ("bundled installer script invocation failed; log={0}; error={1}" -f $EnrollLogPath, $msg)
}
if ($exitCode -ne 0) {
  Write-EnrollLog ("ERROR bundled installer script failed exit_code={0}" -f $exitCode)
  Write-Error ("bundled installer script failed with exit code {0}; log={1}" -f $exitCode, $EnrollLogPath)
}

Remove-Item -LiteralPath $ParamsFile -Force -ErrorAction SilentlyContinue
Write-EnrollLog "enroll stage completed"
