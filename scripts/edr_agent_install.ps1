#Requires -Version 5.1
<#
.SYNOPSIS
  独立运行：调用 POST /api/v1/enroll，生成 agent.toml（不依赖 Python）。

.DESCRIPTION
  推荐：
    .\edr_agent_install.ps1 -ApiBase https://edr.example:8080 -EnrollToken <token>

  可选：
    EDR_API_BASE / EDR_ENROLL_TOKEN  兼容旧版环境变量传参
    EDR_OUTPUT              输出路径，Windows 默认 C:\Program Files\FDSecurity\agent.toml
    EDR_AGENT_VERSION       默认使用环境变量；否则读取包内 VERSION / 可执行文件版本；再否则 unknown
    EDR_FORCE_ENROLL=1      已存在 agent.toml 时仍强制重新 enroll
    EDR_OVERRIDE_SERVER_ADDR
    EDR_PROXY_MODE=auto|off|explicit
    EDR_PROXY_URL=http://proxy.corp:8080
    EDR_RELAY_URL=https://relay.corp:443/api/v1
    EDR_MAX_EVENT_QUEUE_SIZE=8192
    EDR_ENROLL_TIMEOUT_SEC=30
    EDR_AGENT_TEMPLATE      默认优先使用 config\agent_windows_production.example.toml
    EDR_CA_CERT / EDR_CLIENT_CERT / EDR_CLIENT_KEY / EDR_CLIENT_CSR
    EDR_KEY_PROVIDER=pem|cng|tpm|pkcs11（Windows 默认 cng，Linux/macOS 默认 pem）
    EDR_CNG_PROVIDER_NAME        默认 cng=Microsoft Software Key Storage Provider，tpm=Microsoft Platform Crypto Provider
    EDR_CNG_KEY_NAME             默认 FDSecurity-Agent-$COMPUTERNAME-<random>
    EDR_PKCS11_KEY_URI           PKCS#11 key URI；需本机 openssl engine/provider 可用
    EDR_TPM_KEY_URI              TPM/OpenSSL provider key URI；PowerShell 默认走 Windows Platform Crypto Provider
    EDR_TRUST_CA=1          enroll 前将 EDR_CA_CERT 导入 Windows Root（适合企业私有 CA / lab mkcert）
    EDR_INSECURE_TLS=1      [System.Net.ServicePointManager]::ServerCertificateValidationCallback（仅调试）
    EDR_CONFIGURE_SENSOR_POLICY=0  跳过 Windows 采集策略配置；默认安装时启用进程命令行审计和 PowerShell ScriptBlock。

.EXAMPLE
  $env:EDR_API_BASE="http://127.0.0.1:8080"
  $env:EDR_ENROLL_TOKEN="xxxxxxxx"
  .\edr_agent_install.ps1
#>
param(
  [string]$Output = $(if ($env:EDR_OUTPUT) { $env:EDR_OUTPUT } else { "C:\Program Files\FDSecurity\agent.toml" }),
  [string]$Template = $(if ($env:EDR_AGENT_TEMPLATE) { $env:EDR_AGENT_TEMPLATE } else { "" }),
  [string]$CaCertPath = $(if ($env:EDR_CA_CERT) { $env:EDR_CA_CERT } else { "C:\Program Files\FDSecurity\certs\ca.pem" }),
  [string]$ClientCertPath = $(if ($env:EDR_CLIENT_CERT) { $env:EDR_CLIENT_CERT } else { "C:\Program Files\FDSecurity\certs\client.pem" }),
  [string]$ClientKeyPath = $(if ($env:EDR_CLIENT_KEY) { $env:EDR_CLIENT_KEY } else { "C:\Program Files\FDSecurity\certs\client-key.pem" }),
  [string]$ClientCsrPath = $(if ($env:EDR_CLIENT_CSR) { $env:EDR_CLIENT_CSR } else { "C:\Program Files\FDSecurity\certs\client.csr.pem" }),
  [string]$KeyProvider = $(if ($env:EDR_KEY_PROVIDER) { $env:EDR_KEY_PROVIDER } else { "" }),
  [string]$ApiBase = $(if ($env:EDR_API_BASE) { $env:EDR_API_BASE } else { "" }),
  [string]$EnrollToken = $(if ($env:EDR_ENROLL_TOKEN) { $env:EDR_ENROLL_TOKEN } else { "" }),
  [string]$ProxyMode = $(if ($env:EDR_PROXY_MODE) { $env:EDR_PROXY_MODE } else { "auto" }),
  [string]$ProxyUrl = $(if ($env:EDR_PROXY_URL) { $env:EDR_PROXY_URL } else { "" }),
  [string]$RelayUrl = $(if ($env:EDR_RELAY_URL) { $env:EDR_RELAY_URL } else { "" }),
  [string]$BootstrapCaCertPath = $(if ($env:EDR_BOOTSTRAP_CA_CERT) { $env:EDR_BOOTSTRAP_CA_CERT } else { "" }),
  [string]$BootstrapTlsLeafSha256 = $(if ($env:EDR_BOOTSTRAP_TLS_LEAF_SHA256) { $env:EDR_BOOTSTRAP_TLS_LEAF_SHA256 } else { "" }),
  [int]$MaxEventQueueSize = 8192,
  [int]$EnrollTimeoutSec = 30,
  [string]$CngProviderName = $(if ($env:EDR_CNG_PROVIDER_NAME) { $env:EDR_CNG_PROVIDER_NAME } else { "" }),
  [string]$CngKeyName = $(if ($env:EDR_CNG_KEY_NAME) { $env:EDR_CNG_KEY_NAME } else { "" }),
  [string]$Pkcs11KeyUri = $(if ($env:EDR_PKCS11_KEY_URI) { $env:EDR_PKCS11_KEY_URI } else { "" }),
  [string]$Pkcs11Module = $(if ($env:EDR_PKCS11_MODULE) { $env:EDR_PKCS11_MODULE } else { "" }),
  [string]$TpmKeyUri = $(if ($env:EDR_TPM_KEY_URI) { $env:EDR_TPM_KEY_URI } else { "" }),
  [switch]$TrustCa = $($env:EDR_TRUST_CA -eq "1"),
  [switch]$InstallAutorun,
  [switch]$HardenAcl,
  [switch]$ConfigureSensorPolicy = $($env:EDR_CONFIGURE_SENSOR_POLICY -ne "0"),
  [switch]$SkipPreflight = $($env:EDR_SKIP_PREFLIGHT -eq "1"),
  [switch]$SkipHealthCheck = $($env:EDR_SKIP_HEALTH_CHECK -eq "1"),
  [switch]$StrictHealthCheck = $($env:EDR_INSTALL_HEALTH_STRICT -eq "1"),
  [string]$HealthReportPath = $(if ($env:EDR_INSTALL_HEALTH_REPORT) { $env:EDR_INSTALL_HEALTH_REPORT } else { "" }),
  [switch]$KeepOfflineQueue = $($env:EDR_KEEP_OFFLINE_QUEUE -eq "1"),
  [switch]$KeepEvidenceCache = $($env:EDR_KEEP_EVIDENCE_CACHE -eq "1"),
  [switch]$KeepTemplateComments = $($env:EDR_KEEP_TEMPLATE_COMMENTS -eq "1"),
  [switch]$UseTemplateToml = $($env:EDR_USE_TEMPLATE_TOML -eq "1"),
  [switch]$MinimalTomlOnly,
  [switch]$ForceEnroll = $($env:EDR_FORCE_ENROLL -eq "1"),
  [switch]$DryRun
)

$ErrorActionPreference = "Stop"
if ($env:OS -eq "Windows_NT") {
  if ($PSVersionTable.PSEdition -ne "Desktop" -or $PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -lt 1) {
    throw "Windows enrollment requires Windows PowerShell 5.1 Desktop. Run this script with %WINDIR%\System32\WindowsPowerShell\v1.0\powershell.exe; launching the installer EXE from PowerShell 7 is supported."
  }
  if ($ExecutionContext.SessionState.LanguageMode -ne "FullLanguage") {
    throw "Windows enrollment requires FullLanguage mode for signed-package .NET cryptography. Ask the administrator to authorize the installer under the existing application-control policy."
  }
}
try {
  $script:EDR_UTF8_OUTPUT = New-Object System.Text.UTF8Encoding -ArgumentList $false
  [Console]::OutputEncoding = $script:EDR_UTF8_OUTPUT
  $OutputEncoding = $script:EDR_UTF8_OUTPUT
} catch {
  # Diagnostics still carry numeric HRESULT/Win32 codes when console encoding
  # cannot be changed by a constrained PowerShell host.
}

function Get-EnrollOs {
  if ($env:OS -match "Windows_NT" -or $env:OS -like "*Windows*") { return "windows" }
  if ($IsMacOS) { return "darwin" }
  return "linux"
}

$Output = [System.IO.Path]::GetFullPath($Output)
$InstallDir = Split-Path -Parent $Output
if ((Get-EnrollOs) -eq "windows" -and $InstallDir) {
  if (-not $env:EDR_CA_CERT) { $CaCertPath = Join-Path $InstallDir "certs\ca.pem" }
  if (-not $env:EDR_CLIENT_CERT) { $ClientCertPath = Join-Path $InstallDir "certs\client.pem" }
  if (-not $env:EDR_CLIENT_KEY) { $ClientKeyPath = Join-Path $InstallDir "certs\client-key.pem" }
  if (-not $env:EDR_CLIENT_CSR) { $ClientCsrPath = Join-Path $InstallDir "certs\client.csr.pem" }
}

# Headless packages may carry a signed Bootstrap CA under certs/. Discover it
# automatically so scripted installs get the same TLS trust as Setup UI.
if (-not $BootstrapCaCertPath) {
  $bootstrapCaCandidates = New-Object System.Collections.Generic.List[string]
  if ($PSScriptRoot) {
    $bootstrapCaCandidates.Add((Join-Path $PSScriptRoot "certs\bootstrap-ca.pem")) | Out-Null
    $packageRoot = Split-Path -Parent $PSScriptRoot
    if ($packageRoot) {
      $bootstrapCaCandidates.Add((Join-Path $packageRoot "certs\bootstrap-ca.pem")) | Out-Null
    }
  }
  foreach ($candidate in $bootstrapCaCandidates) {
    if (Test-Path -LiteralPath $candidate) {
      $BootstrapCaCertPath = [System.IO.Path]::GetFullPath($candidate)
      break
    }
  }
}

$api = $ApiBase
$tok = $EnrollToken
if (-not $api -or -not $tok) {
  Write-Error "Provide -ApiBase and -EnrollToken, for example: .\edr_agent_install.ps1 -ApiBase https://edr.example:8080 -EnrollToken <token>"
}

function Normalize-ApiBaseForEnroll {
  param([Parameter(Mandatory = $true)][string]$Value)
  $v = $Value.Trim().TrimEnd("/")
  if (-not $v) {
    Write-Error "ApiBase is empty"
  }
  try {
    $u = [System.Uri]$v
  } catch {
    Write-Error "ApiBase must be an absolute http(s) URL: $Value"
  }
  if ($u.Scheme -ne "http" -and $u.Scheme -ne "https") {
    Write-Error "ApiBase must use http or https: $Value"
  }
  $path = $u.AbsolutePath.TrimEnd("/")
  $apiSuffix = "/api/v1"
  if ($path -match '(?i)/api/v1$') {
    $prefix = $path.Substring(0, $path.Length - $apiSuffix.Length)
    $b = [System.UriBuilder]::new($u)
    $b.Path = $prefix
    $b.Query = ""
    $b.Fragment = ""
    return $b.Uri.AbsoluteUri.TrimEnd("/")
  }
  return $v
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
    Write-Error "ProxyMode=explicit requires ProxyUrl"
  }
  try {
    $u = [System.Uri]$raw
  } catch {
    Write-Error "ProxyUrl must be an absolute http(s) URL: $Url"
  }
  if ($u.Scheme -ne "http" -and $u.Scheme -ne "https") {
    Write-Error "ProxyUrl must use http or https: $Url"
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

$api = Normalize-ApiBaseForEnroll $api
$uri = "$api/api/v1/enroll"
if ($RelayUrl -and $RelayUrl.Trim()) {
  $RelayUrl = (Normalize-ApiBaseForEnroll $RelayUrl) + "/api/v1"
}
$ProxyMode = Normalize-ProxyModeValue $ProxyMode
$ProxyUrl = if ($ProxyUrl) { $ProxyUrl.Trim() } else { "" }
if ($ProxyMode -eq "off") {
  [System.Net.WebRequest]::DefaultWebProxy = New-Object System.Net.WebProxy
}
$WebRequestProxyOptions = Get-WebRequestProxyOptions -Mode $ProxyMode -Url $ProxyUrl

function Resolve-AgentVersion {
  if ($env:EDR_AGENT_VERSION -and $env:EDR_AGENT_VERSION.Trim()) {
    return $env:EDR_AGENT_VERSION.Trim()
  }

  $dirs = @()
  if ($PSScriptRoot) {
    $dirs += $PSScriptRoot
    $parent = Split-Path -Parent $PSScriptRoot
    if ($parent) { $dirs += $parent }
  }
  if ($Output) {
    $outDir = Split-Path -Parent $Output
    if ($outDir) { $dirs += $outDir }
  }
  try {
    $cwd = (Get-Location).Path
    if ($cwd) { $dirs += $cwd }
  } catch {
  }

  foreach ($dir in ($dirs | Where-Object { $_ } | Select-Object -Unique)) {
    $vf = Join-Path $dir "VERSION"
    if (Test-Path -LiteralPath $vf) {
      $v = ([System.IO.File]::ReadAllText($vf)).Trim()
      if ($v) { return $v }
    }
  }

  foreach ($dir in ($dirs | Where-Object { $_ } | Select-Object -Unique)) {
    foreach ($exeName in @("FDSensor.exe", "edr_agent.exe")) {
      $exe = Join-Path $dir $exeName
      if (Test-Path -LiteralPath $exe) {
        try {
          $info = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($exe)
          foreach ($candidate in @($info.ProductVersion, $info.FileVersion)) {
            if ($candidate -and $candidate.Trim() -and $candidate.Trim() -ne "0.0.0.0") {
              return $candidate.Trim()
            }
          }
        } catch {
        }
      }
    }
  }

  return "unknown"
}

function Read-AgentTomlScalar {
  param([string]$Path, [string]$Key)
  if (-not $Path -or -not (Test-Path -LiteralPath $Path)) {
    return ""
  }
  $pattern = '^\s*' + [regex]::Escape($Key) + '\s*=\s*"([^"]*)"'
  foreach ($line in [System.IO.File]::ReadLines(([System.IO.Path]::GetFullPath($Path)))) {
    $m = [regex]::Match($line, $pattern)
    if ($m.Success) {
      return $m.Groups[1].Value
    }
  }
  return ""
}

function Get-ExistingAgentTomlSanityIssue {
  param([string]$Path)
  if (-not $Path -or -not (Test-Path -LiteralPath $Path)) {
    return "missing TOML"
  }
  try {
    $raw = [System.IO.File]::ReadAllText(([System.IO.Path]::GetFullPath($Path)))
  } catch {
    return ("unreadable TOML: " + $_.Exception.Message)
  }
  if ([string]::IsNullOrWhiteSpace($raw)) {
    return "empty TOML"
  }
  $lines = ($raw -replace "`r`n", "`n").Split([string[]]@("`n"), [System.StringSplitOptions]::None)
  for ($idx = 0; $idx -lt $lines.Count; $idx++) {
    $t = $lines[$idx].Trim()
    if ($idx -eq 0 -and $t.Length -gt 0 -and [int][char]$t[0] -eq 0xFEFF) {
      $t = $t.Substring(1).TrimStart()
    }
    if ($t -eq "" -or $t.StartsWith("#")) {
      continue
    }
    if ($t.StartsWith("[") -and $t.EndsWith("]")) {
      continue
    }
    if (-not $t.Contains("=")) {
      $near = ($t -replace '\s+', ' ').Trim()
      if ($near.Length -gt 120) {
        $near = $near.Substring(0, 120) + "..."
      }
      return ("line {0}: missing = near '{1}'" -f ($idx + 1), $near)
    }
  }
  return ""
}

function Get-ExistingAgentTomlMtlsIssue {
  param([string]$Path)
  if ((Get-EnrollOs) -ne "windows" -or -not $Path -or -not (Test-Path -LiteralPath $Path)) {
    return ""
  }
  $provider = (Read-AgentTomlScalar -Path $Path -Key "client_key_provider").Trim().ToLowerInvariant()
  $certPath = Read-AgentTomlScalar -Path $Path -Key "client_cert"
  $keyPath = Read-AgentTomlScalar -Path $Path -Key "client_key"
  $store = Read-AgentTomlScalar -Path $Path -Key "client_cert_store"
  $thumbprint = Read-AgentTomlScalar -Path $Path -Key "client_cert_thumbprint"
  if ($thumbprint -and -not $store) {
    return "client_cert_thumbprint is set without client_cert_store; Schannel will search CurrentUser\\MY and miss LocalMachine certificates"
  }
  if ($provider -eq "pem" -and ($certPath -or $keyPath)) {
    return "client_key_provider=pem is incompatible with the current Windows Schannel transport; re-enroll with CNG certificate store"
  }
  return ""
}

function Get-ExistingAgentTomlRequestSigningIssue {
  param([string]$Path)
  if (-not $Path -or -not (Test-Path -LiteralPath $Path)) {
    return "missing TOML"
  }
  try {
    $raw = [System.IO.File]::ReadAllText(([System.IO.Path]::GetFullPath($Path)))
  } catch {
    return ("unreadable TOML: " + $_.Exception.Message)
  }
  $sectionMatch = [regex]::Match(
    $raw,
    '(?ms)^\s*\[platform\.request_signing\]\s*$\s*(?<body>.*?)(?=^\s*\[|\z)'
  )
  if (-not $sectionMatch.Success) {
    return "missing [platform.request_signing] enrollment credentials"
  }
  $section = $sectionMatch.Groups['body'].Value
  if ($section -match '(?m)^\s*enabled\s*=\s*false\s*(?:#.*)?$') {
    return ""
  }
  if ($section -notmatch '(?m)^\s*enabled\s*=\s*true\s*(?:#.*)?$') {
    return "platform request signing state is missing"
  }
  if ($section -notmatch '(?m)^\s*key_id\s*=\s*"[^\"]+"\s*(?:#.*)?$' -or
      $section -notmatch '(?m)^\s*secret\s*=\s*"[^\"]+"\s*(?:#.*)?$') {
    return "platform request signing credentials are incomplete"
  }
  return ""
}

function Get-DurableInstallDiagnosticsDir {
  if ($env:EDR_INSTALL_DIAGNOSTICS_DIR) {
    return [System.IO.Path]::GetFullPath($env:EDR_INSTALL_DIAGNOSTICS_DIR)
  }
  $programData = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
  if (-not $programData) { $programData = "C:\ProgramData" }
  return (Join-Path $programData "FDSecurity\diagnostics")
}

function Write-DurableInstallDiagnostic {
  param([string]$Name, [object]$Report)
  try {
    $dir = Get-DurableInstallDiagnosticsDir
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    $path = Join-Path $dir $Name
    $json = $Report | ConvertTo-Json -Depth 8
    $utf8NoBom = New-Object System.Text.UTF8Encoding -ArgumentList $false
    [System.IO.File]::WriteAllText($path, $json, $utf8NoBom)
    return $path
  } catch {
    Write-Warning ("failed to persist install diagnostic: " + $_.Exception.Message)
    return ""
  }
}

function Write-Utf8NoBomFileWithRetry {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)][string]$Text,
    [int]$MaxAttempts = 40,
    [int]$DelayMilliseconds = 250
  )
  if ($MaxAttempts -lt 1) { throw "file write retry count must be positive" }
  if ($DelayMilliseconds -lt 0) { throw "file write retry delay must be non-negative" }

  $fullPath = [System.IO.Path]::GetFullPath($Path)
  $dir = Split-Path -Parent $fullPath
  if ($dir -and -not (Test-Path -LiteralPath $dir)) {
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
  }
  $stagedPath = $fullPath + ".write-" + [guid]::NewGuid().ToString("N") + ".tmp"
  # Windows PowerShell 5.1/.NET Framework rejects a null backup path for the
  # four-argument File.Replace overload. Keep the backup beside the target so
  # the swap remains atomic, then remove it after the replacement completes.
  $backupPath = $fullPath + ".replace-" + [guid]::NewGuid().ToString("N") + ".bak"
  $utf8NoBom = New-Object System.Text.UTF8Encoding -ArgumentList $false
  $lastFailure = $null
  try {
    [System.IO.File]::WriteAllText($stagedPath, $Text, $utf8NoBom)
    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
      try {
        if (Test-Path -LiteralPath $fullPath) {
          [System.IO.File]::Replace($stagedPath, $fullPath, $backupPath, $true)
        } else {
          [System.IO.File]::Move($stagedPath, $fullPath)
        }
        return
      } catch [System.IO.IOException] {
        $lastFailure = $_
      } catch [System.UnauthorizedAccessException] {
        $lastFailure = $_
      }
      if ($attempt -lt $MaxAttempts) {
        Start-Sleep -Milliseconds $DelayMilliseconds
      }
    }
    $reason = if ($lastFailure) { [string]$lastFailure.Exception.Message } else { "unknown file replacement failure" }
    throw ("failed to atomically write {0} after {1} attempts: {2}" -f $fullPath, $MaxAttempts, $reason)
  } finally {
    Remove-Item -LiteralPath $stagedPath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $backupPath -Force -ErrorAction SilentlyContinue
  }
}

function Get-NativeWindowsArchitecture {
  if ((Get-EnrollOs) -ne "windows") { return (Get-EnrollOs) }
  try {
    return [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToLowerInvariant()
  } catch {
    try {
      $osArch = (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).OSArchitecture
      if ($osArch -match "ARM") { return "arm64" }
      if ($osArch -match "64") { return "x64" }
      return [string]$osArch
    } catch {
      return "unknown"
    }
  }
}

function Get-PeMachineName {
  param([string]$Path)
  try {
    $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
    $reader = New-Object System.IO.BinaryReader -ArgumentList $stream
    try {
      if ($reader.ReadUInt16() -ne 0x5A4D) { return "not-pe" }
      $stream.Position = 0x3C
      $peOffset = $reader.ReadUInt32()
      $stream.Position = $peOffset
      if ($reader.ReadUInt32() -ne 0x00004550) { return "not-pe" }
      $machine = $reader.ReadUInt16()
      switch ($machine) {
        0x8664 { return "amd64" }
        0xAA64 { return "arm64" }
        0x014C { return "x86" }
        default { return ("0x{0:X4}" -f $machine) }
      }
    } finally {
      $reader.Dispose()
      $stream.Dispose()
    }
  } catch {
    return "unreadable"
  }
}

function Get-ExceptionNativeErrorCode {
  param([object]$Exception)
  $current = $Exception
  while ($current) {
    if ($current -is [System.ComponentModel.Win32Exception]) {
      return [int]$current.NativeErrorCode
    }
    $current = $current.InnerException
  }
  return $null
}

function Write-AgentProcessLaunchDiagnostic {
  param([string]$Exe, [string[]]$ArgList, [object]$Exception)
  $nativeErrorCode = Get-ExceptionNativeErrorCode $Exception
  $hresult = if ($Exception) { [int]$Exception.HResult } else { 0 }
  $sha256 = ""
  $signatureStatus = "unknown"
  try { $sha256 = (Get-FileHash -LiteralPath $Exe -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant() } catch {}
  try { $signatureStatus = [string](Get-AuthenticodeSignature -LiteralPath $Exe -ErrorAction Stop).Status } catch {}
  $report = [ordered]@{
    schema = "edr.agent.install.process_failure.v1"
    created_at = (Get-Date).ToUniversalTime().ToString("o")
    stage = "agent_config_test_launch"
    executable = $Exe
    executable_sha256 = $sha256
    executable_machine = Get-PeMachineName $Exe
    process_architecture = [string]$env:PROCESSOR_ARCHITECTURE
    native_os_architecture = Get-NativeWindowsArchitecture
    authenticode_status = $signatureStatus
    arguments = @($ArgList)
    exception_type = if ($Exception) { $Exception.GetType().FullName } else { "" }
    exception_message = if ($Exception) { [string]$Exception.Message } else { "" }
    hresult = $hresult
    hresult_hex = ("0x{0:X8}" -f ($hresult -band 0xffffffffL))
    native_error_code = $nativeErrorCode
  }
  return Write-DurableInstallDiagnostic -Name "install-process-failure-last.json" -Report $report
}

function Format-AgentProcessLaunchFailure {
  param([object]$Exception, [string]$DiagnosticPath)
  $nativeErrorCode = Get-ExceptionNativeErrorCode $Exception
  $hresult = if ($Exception) { [int]$Exception.HResult } else { 0 }
  $parts = New-Object System.Collections.Generic.List[string]
  $parts.Add(("type={0}" -f $(if ($Exception) { $Exception.GetType().FullName } else { "unknown" }))) | Out-Null
  $parts.Add(("hresult=0x{0:X8}" -f ($hresult -band 0xffffffffL))) | Out-Null
  if ($null -ne $nativeErrorCode) { $parts.Add(("win32={0}" -f $nativeErrorCode)) | Out-Null }
  $parts.Add(("native_os={0}" -f (Get-NativeWindowsArchitecture))) | Out-Null
  if ($DiagnosticPath) { $parts.Add(("diagnostic={0}" -f $DiagnosticPath)) | Out-Null }
  if ($Exception -and $Exception.Message) { $parts.Add(("message={0}" -f $Exception.Message)) | Out-Null }
  return ($parts -join "; ")
}

function Test-ExistingAgentTomlWithAgent {
  param([string]$InstallRoot, [string]$ConfigPath)
  if (-not $InstallRoot -or -not $ConfigPath) {
    return ""
  }
  foreach ($exeName in @("FDSensor.exe", "edr_agent.exe")) {
    $exe = Join-Path $InstallRoot $exeName
    if (-not (Test-Path -LiteralPath $exe)) {
      continue
    }
    $requiredRuntime = @(
      "vcruntime140.dll",
      "msvcp140.dll"
    )
    $exeMachine = Get-PeMachineName $exe
    if ($exeMachine -ne "arm64") {
      $requiredRuntime += "vcruntime140_1.dll"
    }
    $missingRuntime = @($requiredRuntime | Where-Object {
      -not (Test-Path -LiteralPath (Join-Path $InstallRoot $_) -PathType Leaf)
    })
    if ($missingRuntime.Count -gt 0) {
      return ("packaged MSVC runtime missing beside {0}: {1}" -f $exeName, ($missingRuntime -join ", "))
    }
    try {
      $result = Invoke-CapturedProcess -Exe $exe -ArgList @("--config", $ConfigPath, "--config-test")
      $out = (($result.Stdout, $result.Stderr | Where-Object { $_ }) -join "`n").Trim()
      if ($result.ExitCode -eq 0) {
        return ""
      }
      if ($out.Length -gt 240) {
        $out = $out.Substring(0, 240) + "..."
      }
      return ("agent parser rejected existing TOML with {0}: {1}" -f $exeName, $out)
    } catch {
      $diagnosticPath = Write-AgentProcessLaunchDiagnostic -Exe $exe -ArgList @("--config", $ConfigPath, "--config-test") -Exception $_.Exception
      return ("agent process launch failed with {0}: {1}" -f $exeName, (Format-AgentProcessLaunchFailure -Exception $_.Exception -DiagnosticPath $diagnosticPath))
    }
  }
  return ""
}

function Backup-InvalidAgentToml {
  param([string]$Path)
  if (-not $Path -or -not (Test-Path -LiteralPath $Path)) {
    return ""
  }
  try {
    $full = [System.IO.Path]::GetFullPath($Path)
    $dir = Split-Path -Parent $full
    $stamp = Get-Date -Format "yyyyMMddHHmmss"
    $backup = Join-Path $dir ("agent.toml.invalid." + $stamp)
    Move-Item -LiteralPath $full -Destination $backup -Force
    return $backup
  } catch {
    Write-Warning ("failed to backup invalid agent.toml: " + $_.Exception.Message)
    return ""
  }
}

function Repair-AgentTomlAcl {
  param([string]$Path)
  if ((Get-EnrollOs) -ne "windows") { return }
  if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return }
  try {
    $takeown = Get-Command "takeown.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($takeown) {
      & $takeown.Source /F $Path /A 2>$null | Out-Null
    }
  } catch {
    Write-Warning ("failed to take ownership of agent.toml: " + $_.Exception.Message)
  }
  $icacls = Get-Command "icacls.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
  if (-not $icacls) { return }
  try {
    & $icacls.Source $Path /inheritance:r /grant:r "*S-1-5-18:F" /grant:r "*S-1-5-32-544:F" /C /Q | Out-Null
  } catch {
    Write-Warning ("failed to repair agent.toml ACL: " + $_.Exception.Message)
  }
}

function Remove-StaleEnrollmentArtifact {
  param([string]$Path)
  if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return }
  try {
    Remove-Item -LiteralPath $Path -Force -ErrorAction Stop
    return
  } catch {
    if ((Get-EnrollOs) -ne "windows") { throw }
  }

  try { & takeown.exe /F $Path /A 2>$null | Out-Null } catch {}
  try {
    & icacls.exe $Path /inheritance:r /grant:r "*S-1-5-18:F" /grant:r "*S-1-5-32-544:F" /C /Q | Out-Null
  } catch {}
  Remove-Item -LiteralPath $Path -Force -ErrorAction Stop
}

function Repair-RuntimeFileAcls {
  param([string]$Path)
  if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return }
  $icacls = Get-Command "icacls.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
  if (-not $icacls) { throw "icacls.exe not found" }
  foreach ($item in @(Get-ChildItem -LiteralPath $Path -File -Force -Recurse -ErrorAction SilentlyContinue)) {
    try { & takeown.exe /F $item.FullName /A 2>$null | Out-Null } catch {}
    & $icacls.Source $item.FullName /inheritance:r /grant:r "*S-1-5-18:F" /grant:r "*S-1-5-32-544:F" /C /Q | Out-Null
    if ($LASTEXITCODE -ne 0) {
      throw "file ACL repair failed with exit code $LASTEXITCODE path=$($item.FullName)"
    }
  }
}

function Repair-InstallRuntimeAcls {
  param([string]$InstallRoot)
  if ((Get-EnrollOs) -ne "windows") { return }
  if (-not $InstallRoot -or -not (Test-Path -LiteralPath $InstallRoot)) { return }

  $icacls = Get-Command "icacls.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
  if (-not $icacls) { return }

  try {
    & $icacls.Source $InstallRoot /grant:r "*S-1-5-18:(OI)(CI)F" /grant:r "*S-1-5-32-544:(OI)(CI)F" /grant:r "*S-1-5-32-545:(OI)(CI)RX" /C /Q | Out-Null
  } catch {
    Write-Warning ("failed to grant runtime ACLs on install dir: " + $_.Exception.Message)
  }

  foreach ($sub in @("certs", "queue", "evidence", "state", "logs", "diagnostics", "upload_outbox", "forensic", "isolation")) {
    $path = Join-Path $InstallRoot $sub
    try {
      if (-not (Test-Path -LiteralPath $path)) {
        New-Item -ItemType Directory -Path $path -Force | Out-Null
      }
      try { & takeown.exe /F $path /A /R /D Y 2>$null | Out-Null } catch {}
      & $icacls.Source $path /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" /grant:r "*S-1-5-32-544:(OI)(CI)F" /T /C /Q | Out-Null
      if ($LASTEXITCODE -ne 0) {
        throw "directory ACL repair failed with exit code $LASTEXITCODE path=$path"
      }
      Repair-RuntimeFileAcls -Path $path
    } catch {
      Write-Warning ("failed to harden runtime path ACL: " + $path + " " + $_.Exception.Message)
      if ($sub -eq "queue") { throw }
    }
  }

  foreach ($sensitive in @((Join-Path $InstallRoot "agent.toml"), (Join-Path $InstallRoot "certs\*.pem"), (Join-Path $InstallRoot "certs\*.key"), (Join-Path $InstallRoot "certs\*.pfx"))) {
    try {
      Get-ChildItem -Path $sensitive -Force -ErrorAction SilentlyContinue |
        ForEach-Object {
          try { & takeown.exe /F $_.FullName /A 2>$null | Out-Null } catch {}
          try { & $icacls.Source $_.FullName /inheritance:r /grant:r "*S-1-5-18:F" /grant:r "*S-1-5-32-544:F" /C /Q | Out-Null } catch {}
        }
    } catch {}
  }

  foreach ($publicPattern in @("*.exe", "*.dll", "*.ps1", "*.json", "*.enc", "*.example", "*.txt", "edr_config\*")) {
    try {
      Get-ChildItem -Path (Join-Path $InstallRoot $publicPattern) -Force -Recurse -ErrorAction SilentlyContinue |
        ForEach-Object {
          try { & $icacls.Source $_.FullName /grant:r "*S-1-5-18:F" /grant:r "*S-1-5-32-544:F" /grant:r "*S-1-5-32-545:RX" /C /Q | Out-Null } catch {}
          try { Unblock-File -LiteralPath $_.FullName -ErrorAction SilentlyContinue } catch {}
        }
    } catch {}
  }

  foreach ($uninstaller in @(
    @{ Name = "unins000.exe"; Grant = "*S-1-5-32-545:RX" },
    @{ Name = "unins000.dat"; Grant = "*S-1-5-32-545:R" },
    @{ Name = "uninstall.exe"; Grant = "*S-1-5-32-545:RX" }
  )) {
    $path = Join-Path $InstallRoot $uninstaller.Name
    try {
      if (Test-Path -LiteralPath $path) {
        & $icacls.Source $path /grant:r "*S-1-5-18:F" /grant:r "*S-1-5-32-544:F" /grant:r $uninstaller.Grant /C /Q | Out-Null
        try { Unblock-File -LiteralPath $path -ErrorAction SilentlyContinue } catch {}
      }
    } catch {
      Write-Warning ("failed to repair uninstaller ACL: " + $path + " " + $_.Exception.Message)
    }
  }
}

$av = Resolve-AgentVersion
Write-Host "Resolved agent_version=$av"
if ($env:EDR_MAX_EVENT_QUEUE_SIZE) {
  try {
    $MaxEventQueueSize = [int]$env:EDR_MAX_EVENT_QUEUE_SIZE
  } catch {
    Write-Warning "Invalid EDR_MAX_EVENT_QUEUE_SIZE=$($env:EDR_MAX_EVENT_QUEUE_SIZE); using $MaxEventQueueSize"
  }
}
if ($env:EDR_ENROLL_TIMEOUT_SEC) {
  try {
    $EnrollTimeoutSec = [int]$env:EDR_ENROLL_TIMEOUT_SEC
  } catch {
    Write-Warning "Invalid EDR_ENROLL_TIMEOUT_SEC=$($env:EDR_ENROLL_TIMEOUT_SEC); using $EnrollTimeoutSec"
  }
}
$TomlMaxEventQueueSize = [Math]::Min(65536, [Math]::Max(1024, $MaxEventQueueSize))
$EnrollTimeoutSec = [Math]::Min(120, [Math]::Max(5, $EnrollTimeoutSec))

function Resolve-OpenSSL {
  $candidates = New-Object System.Collections.Generic.List[string]
  foreach ($name in @("openssl.exe", "openssl")) {
    $cmd = Get-Command $name -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($cmd) { return $cmd.Source }
  }
  $pf = [Environment]::GetEnvironmentVariable("ProgramFiles")
  $pf86 = [Environment]::GetEnvironmentVariable("ProgramFiles(x86)")
  $probe = New-Object System.Collections.Generic.List[string]
  foreach ($rel in @("openssl.exe", "tools\openssl.exe", "bin\openssl.exe", "OpenSSL-Win64\bin\openssl.exe")) {
    $probe.Add((Join-Path $PSScriptRoot $rel)) | Out-Null
  }
  if ($pf) {
    $probe.Add((Join-Path $pf "OpenSSL-Win64\bin\openssl.exe")) | Out-Null
    $probe.Add((Join-Path $pf "Git\usr\bin\openssl.exe")) | Out-Null
  }
  if ($pf86) {
    $probe.Add((Join-Path $pf86 "OpenSSL-Win32\bin\openssl.exe")) | Out-Null
  }
  $probe.Add("C:\OpenSSL-Win64\bin\openssl.exe") | Out-Null
  $probe.Add("C:\OpenSSL-Win32\bin\openssl.exe") | Out-Null
  foreach ($p in $probe) {
    if ($p -and (Test-Path -LiteralPath $p)) {
      return ([System.IO.Path]::GetFullPath($p))
    }
    if ($p) { $candidates.Add($p) | Out-Null }
  }
  Write-Error ("openssl not found. Native PowerShell CSR generation was unavailable, and these paths were checked: " + ($candidates -join "; "))
}

function Quote-ProcessArgument {
  param([string]$Value)
  if ($null -eq $Value) { return '""' }
  if ($Value.Length -gt 0 -and $Value -notmatch '[\s"]') {
    return $Value
  }
  $out = New-Object System.Text.StringBuilder
  [void]$out.Append('"')
  $slashes = 0
  foreach ($ch in $Value.ToCharArray()) {
    if ($ch -eq '\') {
      $slashes++
      continue
    }
    if ($ch -eq '"') {
      [void]$out.Append(('\' * (($slashes * 2) + 1)))
      [void]$out.Append('"')
      $slashes = 0
      continue
    }
    if ($slashes -gt 0) {
      [void]$out.Append(('\' * $slashes))
      $slashes = 0
    }
    [void]$out.Append($ch)
  }
  if ($slashes -gt 0) {
    [void]$out.Append(('\' * ($slashes * 2)))
  }
  [void]$out.Append('"')
  return $out.ToString()
}

function Join-ProcessArguments {
  param([string[]]$ArgList)
  if (-not $ArgList) { return "" }
  return (($ArgList | ForEach-Object { Quote-ProcessArgument ([string]$_) }) -join " ")
}

function Read-NativeProcessOutput {
  param([string]$Path)
  if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return "" }
  try {
    [byte[]]$bytes = [System.IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -eq 0) { return "" }
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
      return (New-Object System.Text.UTF8Encoding -ArgumentList $true).GetString($bytes, 3, $bytes.Length - 3)
    }
    if ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) {
      return [System.Text.Encoding]::Unicode.GetString($bytes, 2, $bytes.Length - 2)
    }
    try {
      return (New-Object System.Text.UTF8Encoding -ArgumentList @($false, $true)).GetString($bytes)
    } catch {
      # certreq/certutil use the active Windows code page for localized output
      # on older Server images. Preserve the numeric exit code separately.
      return [System.Text.Encoding]::Default.GetString($bytes)
    }
  } catch {
    return ("<native output read failed: {0}>" -f $_.Exception.Message)
  }
}

function Invoke-CapturedProcess {
  param([string]$Exe, [string[]]$ArgList, [int]$TimeoutSeconds = 0)
  if (-not $Exe) {
    throw "missing executable"
  }
  if ($TimeoutSeconds -lt 0) {
    throw "process timeout must be non-negative"
  }
  $tmpBase = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), ("fdproc-" + [guid]::NewGuid().ToString("N")))
  $stdoutPath = $tmpBase + ".out"
  $stderrPath = $tmpBase + ".err"
  $p = New-Object System.Diagnostics.Process
  $stdoutFile = $null
  $stderrFile = $null
  try {
    $p.StartInfo.FileName = $Exe
    $p.StartInfo.Arguments = Join-ProcessArguments $ArgList
    $p.StartInfo.UseShellExecute = $false
    $p.StartInfo.CreateNoWindow = $true
    $p.StartInfo.RedirectStandardOutput = $true
    $p.StartInfo.RedirectStandardError = $true
    $stdoutFile = [System.IO.File]::Create($stdoutPath)
    $stderrFile = [System.IO.File]::Create($stderrPath)
    [void]$p.Start()
    # Copy raw pipe bytes concurrently. Start-Process redirection may decode
    # localized bytes before writing its files, which cannot be repaired later.
    $stdoutCopy = $p.StandardOutput.BaseStream.CopyToAsync($stdoutFile)
    $stderrCopy = $p.StandardError.BaseStream.CopyToAsync($stderrFile)
    $budget = if ($TimeoutSeconds -gt 0) { $TimeoutSeconds } else { 120 }
    if (-not $p.WaitForExit($budget * 1000)) {
      $p.Kill()
      if (-not $p.WaitForExit(5000)) {
        throw ("native process termination not confirmed; pid={0}; executable={1}" -f $p.Id, $Exe)
      }
      throw ("native process timed out after {0}s; pid={1}; executable={2}" -f $budget, $p.Id, $Exe)
    }
    if (-not [System.Threading.Tasks.Task]::WaitAll([System.Threading.Tasks.Task[]]@($stdoutCopy, $stderrCopy), 5000)) {
      throw ("native process output drain timed out; executable={0}" -f $Exe)
    }
    $stdoutFile.Dispose()
    $stderrFile.Dispose()
    $stdout = Read-NativeProcessOutput -Path $stdoutPath
    $stderr = Read-NativeProcessOutput -Path $stderrPath
    return [pscustomobject]@{
      ExitCode = [int]$p.ExitCode
      Stdout = [string]$stdout
      Stderr = [string]$stderr
    }
  } finally {
    if ($stdoutFile) { $stdoutFile.Dispose() }
    if ($stderrFile) { $stderrFile.Dispose() }
    $p.Dispose()
    Remove-Item -LiteralPath $stdoutPath, $stderrPath -Force -ErrorAction SilentlyContinue
  }
}

function Invoke-Checked {
  param([string]$Exe, [string[]]$ArgList, [int]$TimeoutSeconds = 0)
  $result = Invoke-CapturedProcess -Exe $Exe -ArgList $ArgList -TimeoutSeconds $TimeoutSeconds
  $combined = @()
  if ($result.Stdout) { $combined += ($result.Stdout -split "`r?`n") }
  if ($result.Stderr) { $combined += ($result.Stderr -split "`r?`n") }
  foreach ($line in $combined) {
    if ($line) { Write-Host ([string]$line) }
  }
  if ($result.ExitCode -ne 0) {
    $detail = (($combined | Where-Object { $_ }) -join "`n").Trim()
    $cmd = $Exe + " " + ($ArgList -join " ")
    if ($detail) {
      throw ("native command failed exit_code={0}; executable={1}; args={2}`n{3}" -f $result.ExitCode, $Exe, ($ArgList -join " "), $detail)
    }
    throw ("native command failed exit_code={0}; executable={1}; args={2}" -f $result.ExitCode, $Exe, ($ArgList -join " "))
  }
}

function Test-IsElevated {
  if ((Get-EnrollOs) -ne "windows") { return $false }
  try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  } catch {
    return $false
  }
}

function Get-CurrentPowerShellExecutable {
  try {
    $path = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
    if ($path) { return [System.IO.Path]::GetFullPath($path) }
  } catch {
  }
  if ($PSHOME) {
    $candidate = Join-Path $PSHOME "powershell.exe"
    if (Test-Path -LiteralPath $candidate) { return [System.IO.Path]::GetFullPath($candidate) }
  }
  return "unknown"
}

function Get-RegistryValueOrNull {
  param([string]$Path, [string]$Name)
  try {
    $item = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop
    return $item.$Name
  } catch {
    return $null
  }
}

function Test-TypeAvailable {
  param([string]$TypeName)
  try {
    return [bool]([System.Management.Automation.PSTypeName]$TypeName).Type
  } catch {
    return $false
  }
}

function Test-CopyWithPrivateKeyAvailable {
  if (-not (Test-TypeAvailable "System.Security.Cryptography.X509Certificates.RSACertificateExtensions")) {
    return $false
  }
  try {
    $type = ([System.Management.Automation.PSTypeName]"System.Security.Cryptography.X509Certificates.RSACertificateExtensions").Type
    return [bool]$type.GetMethod("CopyWithPrivateKey", [System.Reflection.BindingFlags]"Public,Static")
  } catch {
    return $false
  }
}

function Get-WindowsInstallCompatibilitySnapshot {
  $os = $null
  try {
    $os = Get-ItemProperty -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction Stop
  } catch {
  }
  $release = Get-RegistryValueOrNull -Path "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" -Name "Release"
  $languageMode = "unknown"
  try { $languageMode = [string]$ExecutionContext.SessionState.LanguageMode } catch {}
  $psVersion = "unknown"
  $detectedPowerShellEdition = "unknown"
  try {
    $psVersion = [string]$PSVersionTable.PSVersion
    $detectedPowerShellEdition = [string]$PSVersionTable.PSEdition
  } catch {
  }
  $tools = [ordered]@{}
  foreach ($name in @("powershell.exe", "certreq.exe", "certutil.exe")) {
    $command = Get-Command $name -ErrorAction SilentlyContinue | Select-Object -First 1
    $tools[$name] = if ($command) { [string]$command.Source } else { "missing" }
  }
  $tlsRegistry = [ordered]@{}
  foreach ($path in @(
    "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319",
    "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319"
  )) {
    $tlsRegistry[$path] = [ordered]@{
      SystemDefaultTlsVersions = Get-RegistryValueOrNull -Path $path -Name "SystemDefaultTlsVersions"
      SchUseStrongCrypto = Get-RegistryValueOrNull -Path $path -Name "SchUseStrongCrypto"
    }
  }
  $securityProtocol = "unknown"
  try { $securityProtocol = [string][System.Net.ServicePointManager]::SecurityProtocol } catch {}
  return [ordered]@{
    os = [ordered]@{
      product_name = if ($os) { [string]$os.ProductName } else { "unknown" }
      edition = if ($os) { [string]$os.EditionID } else { "unknown" }
      installation_type = if ($os) { [string]$os.InstallationType } else { "unknown" }
      display_version = if ($os) { [string]$os.DisplayVersion } else { "unknown" }
      build = if ($os) { [string]$os.CurrentBuildNumber } else { "unknown" }
      ubr = if ($os) { [string]$os.UBR } else { "unknown" }
      architecture = [string](Get-NativeWindowsArchitecture)
    }
    powershell = [ordered]@{
      executable = Get-CurrentPowerShellExecutable
      version = $psVersion
      edition = $detectedPowerShellEdition
      language_mode = $languageMode
      is_64_bit_process = [bool][Environment]::Is64BitProcess
    }
    dotnet_framework_release = if ($null -eq $release) { $null } else { [int]$release }
    capabilities = [ordered]@{
      certificate_request = Test-TypeAvailable "System.Security.Cryptography.X509Certificates.CertificateRequest"
      copy_with_private_key = Test-CopyWithPrivateKeyAvailable
      cng_key = Test-TypeAvailable "System.Security.Cryptography.CngKey"
      cng_provider = Test-TypeAvailable "System.Security.Cryptography.CngProvider"
      rsa_cng = Test-TypeAvailable "System.Security.Cryptography.RSACng"
    }
    tools = $tools
    tls = [ordered]@{
      process_security_protocol = $securityProtocol
      registry = $tlsRegistry
    }
  }
}

function Write-WindowsInstallCompatibilityDiagnostic {
  param([object]$Snapshot, [string]$Failure = "")
  $report = [ordered]@{
    schema = "edr.agent.install.compatibility.v1"
    created_at = (Get-Date).ToUniversalTime().ToString("o")
    status = if ($Failure) { "failed" } else { "ok" }
    failure = $Failure
    snapshot = $Snapshot
  }
  return Write-DurableInstallDiagnostic -Name "install-compatibility-last.json" -Report $report
}

function Assert-WindowsInstallCompatibility {
  param(
    [string]$RequestedProvider,
    [bool]$ExternalTpmKeyUri = $false
  )
  if ((Get-EnrollOs) -ne "windows") { return $null }
  $snapshot = Get-WindowsInstallCompatibilitySnapshot
  $failures = New-Object System.Collections.Generic.List[string]
  $ps = $snapshot.powershell
  if ([string]$ps.edition -ne "Desktop" -or [version][string]$ps.version -lt [version]"5.1") {
    $failures.Add(("Windows enrollment requires Windows PowerShell 5.1 Desktop; executable={0}, version={1}, edition={2}" -f $ps.executable, $ps.version, $ps.edition)) | Out-Null
  }
  if ([string]$ps.language_mode -ne "FullLanguage") {
    $failures.Add(("Windows enrollment requires FullLanguage mode; language_mode={0}" -f $ps.language_mode)) | Out-Null
  }
  if (-not $snapshot.tools["powershell.exe"] -or $snapshot.tools["powershell.exe"] -eq "missing") {
    $failures.Add("Windows PowerShell executable was not found") | Out-Null
  }
  $needsNativeCng = ($RequestedProvider -eq "cng" -or ($RequestedProvider -eq "tpm" -and -not $ExternalTpmKeyUri))
  $nativeCsrAvailable = [bool]($snapshot.capabilities.certificate_request -and
    $snapshot.capabilities.cng_key -and $snapshot.capabilities.cng_provider -and $snapshot.capabilities.rsa_cng)
  $nativeBindingAvailable = [bool]($nativeCsrAvailable -and $snapshot.capabilities.copy_with_private_key)
  if ($needsNativeCng) {
    if (-not $snapshot.capabilities.cng_key -or -not $snapshot.capabilities.cng_provider -or -not $snapshot.capabilities.rsa_cng) {
      $failures.Add("Windows CNG APIs are required to verify machine key identity and rollback; repair the Windows/.NET installation") | Out-Null
    }
    if (-not (Test-IsElevated)) {
      $failures.Add("Run the installer as Administrator for LocalMachine private key and certificate enrollment") | Out-Null
    }
    if (-not $snapshot.tools["certutil.exe"] -or $snapshot.tools["certutil.exe"] -eq "missing") {
      $failures.Add("certutil.exe is required for Windows CNG rollback") | Out-Null
    }
    # certreq is a compatibility fallback only. A host with both native CSR
    # creation and native certificate binding does not need it to enroll.
    if (-not $nativeBindingAvailable -and (-not $snapshot.tools["certreq.exe"] -or $snapshot.tools["certreq.exe"] -eq "missing")) {
      $failures.Add("certreq.exe is required because native CNG CSR or certificate binding capability is unavailable") | Out-Null
    }
  }
  if ($TrustCa -and (-not $CaCertPath -or -not (Test-Path -LiteralPath $CaCertPath -PathType Leaf))) {
    $failures.Add(("TrustCa was requested but the CA file is missing: {0}" -f $CaCertPath)) | Out-Null
  }
  $failure = ($failures -join " | ")
  $diagnostic = Write-WindowsInstallCompatibilityDiagnostic -Snapshot $snapshot -Failure $failure
  if ($failure) {
    throw ("Windows install compatibility preflight failed: {0}; diagnostic={1}" -f $failure, $diagnostic)
  }
  Write-Host ("Windows install compatibility: OS={0} build={1} arch={2}; PowerShell={3} {4} ({5}); .NET Release={6}; CertificateRequest={7}; CopyWithPrivateKey={8}" -f `
    $snapshot.os.product_name, $snapshot.os.build, $snapshot.os.architecture, $snapshot.powershell.version, $snapshot.powershell.executable, $snapshot.powershell.edition, `
    $snapshot.dotnet_framework_release, $snapshot.capabilities.certificate_request, $snapshot.capabilities.copy_with_private_key)
  return $snapshot
}

function Set-WindowsInstallTlsCompatibility {
  if ((Get-EnrollOs) -ne "windows") { return }
  $release = Get-RegistryValueOrNull -Path "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" -Name "Release"
  $before = "unknown"
  try { $before = [string][System.Net.ServicePointManager]::SecurityProtocol } catch {}
  $mode = "system_default"
  if ($null -eq $release -or [int]$release -lt 461808) {
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
    $mode = "tls12_process_only"
  } else {
    try {
      $systemDefault = [System.Enum]::Parse([System.Net.SecurityProtocolType], "SystemDefault", $false)
      [System.Net.ServicePointManager]::SecurityProtocol = $systemDefault
    } catch {
      [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
      $mode = "tls12_process_only_enum_unavailable"
    }
  }
  $after = [string][System.Net.ServicePointManager]::SecurityProtocol
  $script:EDR_TLS_POLICY_MODE = $mode
  $script:EDR_TLS_POLICY_BEFORE = $before
  $script:EDR_TLS_POLICY_AFTER = $after
  Write-Host ("Enrollment TLS policy={0}; process_security_protocol={1}; previous={2}; machine TLS policy unchanged" -f $mode, $after, $before)
}

function Invoke-AgentPreflightIfNeeded {
  if ((Get-EnrollOs) -ne "windows") { return }
  if ($SkipPreflight) { return }
  if (-not $InstallAutorun -and $env:EDR_INSTALL_PREFLIGHT -ne "1") { return }
  $installDir = Split-Path -Parent $Output
  if (-not $installDir) { $installDir = "C:\Program Files\FDSecurity" }
  $preflight = Join-Path $PSScriptRoot "edr_agent_preflight.ps1"
  if (-not (Test-Path -LiteralPath $preflight)) {
    $preflight = Join-Path $installDir "edr_agent_preflight.ps1"
  }
  if (-not (Test-Path -LiteralPath $preflight)) {
    Write-Warning "edr_agent_preflight.ps1 not found; runtime cleanup skipped"
    return
  }
  $args = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $preflight, "-InstallDir", $installDir)
  if ($KeepOfflineQueue) { $args += "-KeepOfflineQueue" }
  if ($KeepEvidenceCache) { $args += "-KeepEvidenceCache" }
  Invoke-Checked -Exe "powershell.exe" -ArgList $args
}

function Enable-WindowsSensorPolicy {
  if ((Get-EnrollOs) -ne "windows") { return }
  if (-not (Test-IsElevated)) {
    Write-Warning "ConfigureSensorPolicy skipped: run the installer as Administrator to enable command line audit and PowerShell ScriptBlock telemetry"
    return
  }

  $auditpol = Get-Command "auditpol.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($auditpol) {
    try {
      Invoke-Checked -Exe $auditpol.Source -ArgList @("/set", "/subcategory:{0CCE922B-69AE-11D9-BED3-505054503030}", "/success:enable")
    } catch {
      Write-Warning ("failed to enable Process Creation audit policy: " + $_)
    }
  } else {
    Write-Warning "auditpol.exe not found; Security 4688 process creation audit was not enabled"
  }

  try {
    $auditKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
    New-Item -Path $auditKey -Force | Out-Null
    New-ItemProperty -Path $auditKey -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -PropertyType DWord -Force | Out-Null

    $psKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    New-Item -Path $psKey -Force | Out-Null
    New-ItemProperty -Path $psKey -Name "EnableScriptBlockLogging" -Value 1 -PropertyType DWord -Force | Out-Null

    Write-Host "Configured Windows sensor policy: Security 4688 command line + PowerShell ScriptBlock logging"
  } catch {
    Write-Warning ("failed to configure Windows sensor policy: " + $_)
  }
}

function Install-BootstrapCaTrust {
  param([string]$Path)
  if (-not $Path -or -not (Test-Path -LiteralPath $Path)) {
    Write-Warning "TrustCa requested, but CA file was not found: $Path"
    return
  }
  $certutil = Get-Command "certutil.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
  if (-not $certutil) {
    Write-Warning "TrustCa requested, but certutil.exe was not found"
    return
  }
  Invoke-Checked -Exe $certutil.Source -ArgList @("-addstore", "Root", $Path)
}

function Install-AgentAutorun {
  $autorun = Join-Path $PSScriptRoot "edr_windows_autorun.ps1"
  if (-not (Test-Path -LiteralPath $autorun)) {
    $autorun = Join-Path (Split-Path -Parent $PSScriptRoot) "install\windows-inno\edr_windows_autorun.ps1"
  }
  if (-not (Test-Path -LiteralPath $autorun)) {
    Write-Warning "InstallAutorun requested, but edr_windows_autorun.ps1 was not found next to the installer script"
    return
  }
  $autorunArgs = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $autorun, "-Action", "Install")
  if ($HardenAcl) {
    $autorunArgs += "-HardenAcl"
  }
  Invoke-Checked -Exe "powershell.exe" -ArgList $autorunArgs
  Write-Host "Installed FDSecurityAgent startup task"
}

function Install-HeadlessUninstaller {
  param([string]$InstallRoot)
  if ((Get-EnrollOs) -ne "windows" -or -not $InstallRoot) { return }

  $packageDirs = @($PSScriptRoot, (Split-Path -Parent $PSScriptRoot)) |
    Where-Object { $_ } | Select-Object -Unique
  $exeSource = $packageDirs | ForEach-Object { Join-Path $_ "uninstall.exe" } |
    Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1

  $installRootFull = [System.IO.Path]::GetFullPath($InstallRoot)
  if (-not $exeSource) {
    throw "Headless uninstall.exe was not found; a verified native Release artifact is required"
  }
  $exeDestination = Join-Path $installRootFull "uninstall.exe"
  if ([System.IO.Path]::GetFullPath($exeSource) -ne [System.IO.Path]::GetFullPath($exeDestination)) {
    Copy-Item -LiteralPath $exeSource -Destination $exeDestination -Force
  }
  try { Unblock-File -LiteralPath $exeDestination -ErrorAction SilentlyContinue } catch {}

  try {
    $uninstallKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\FDSecurityAgentHeadless"
    $version = ""
    foreach ($versionFile in @((Join-Path $installRootFull "VERSION"), (Join-Path $PSScriptRoot "VERSION"))) {
      if ($versionFile -and (Test-Path -LiteralPath $versionFile -PathType Leaf)) {
        $version = (Get-Content -LiteralPath $versionFile -Raw -ErrorAction SilentlyContinue).Trim()
        if ($version) { break }
      }
    }
    if (-not $version) { $version = "unknown" }
    New-Item -Path $uninstallKey -Force | Out-Null
    New-ItemProperty -Path $uninstallKey -Name "DisplayName" -Value "FDSecurity Endpoint Agent" -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $uninstallKey -Name "DisplayVersion" -Value $version -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $uninstallKey -Name "Publisher" -Value "FDSecurity" -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $uninstallKey -Name "InstallLocation" -Value $installRootFull -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $uninstallKey -Name "DisplayIcon" -Value $exeDestination -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $uninstallKey -Name "UninstallString" -Value ('"' + $exeDestination + '"') -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $uninstallKey -Name "QuietUninstallString" -Value ('"' + $exeDestination + '" /S') -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $uninstallKey -Name "NoModify" -Value 1 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path $uninstallKey -Name "NoRepair" -Value 1 -PropertyType DWord -Force | Out-Null
  } catch {
    Write-Warning ("Failed to register headless uninstaller: " + $_.Exception.Message)
  }
  Write-Host "Installed headless uninstall entry: $exeDestination"
}

function Normalize-KeyProvider([string]$Provider) {
  $p = if ($Provider) { $Provider.Trim().ToLowerInvariant() } else { "" }
  if (-not $p) {
    $p = if ((Get-EnrollOs) -eq "windows") { "cng" } else { "pem" }
  }
  if ($p -eq "file") { return "pem" }
  if (@("pem", "cng", "tpm", "pkcs11") -notcontains $p) {
    Write-Error "unsupported EDR_KEY_PROVIDER=$Provider (expected pem|cng|tpm|pkcs11)"
  }
  return $p
}

function Join-Bytes {
  param([object[]]$Parts)
  $ms = New-Object System.IO.MemoryStream
  foreach ($part in $Parts) {
    if ($null -eq [object]$part) {
      continue
    }
    $bytes = [byte[]]$part
    if ($bytes.Length -gt 0) {
      $ms.Write($bytes, 0, $bytes.Length)
    }
  }
  return ,$ms.ToArray()
}

function New-Asn1Length([int]$Length) {
  if ($Length -lt 128) {
    return ,[byte[]]@($Length)
  }
  $bytes = New-Object System.Collections.Generic.List[byte]
  $n = $Length
  while ($n -gt 0) {
    $bytes.Insert(0, [byte]($n -band 0xff))
    $n = $n -shr 8
  }
  return ,(Join-Bytes @([byte[]]@([byte](0x80 -bor $bytes.Count)), $bytes.ToArray()))
}

function New-Asn1Integer([byte[]]$Value) {
  if (-not $Value -or $Value.Length -eq 0) {
    $Value = [byte[]]@(0)
  }
  $offset = 0
  while (($Value.Length - $offset) -gt 1 -and $Value[$offset] -eq 0 -and (($Value[$offset + 1] -band 0x80) -eq 0)) {
    $offset++
  }
  if ($offset -gt 0) {
    $tmp = New-Object byte[] ($Value.Length - $offset)
    [Array]::Copy($Value, $offset, $tmp, 0, $tmp.Length)
    $Value = $tmp
  }
  if (($Value[0] -band 0x80) -ne 0) {
    $Value = Join-Bytes @([byte[]]@(0), $Value)
  }
  return ,(Join-Bytes @([byte[]]@(0x02), (New-Asn1Length $Value.Length), $Value))
}

function New-Asn1Sequence([byte[]]$Body) {
  return ,(Join-Bytes @([byte[]]@(0x30), (New-Asn1Length $Body.Length), $Body))
}

function ConvertTo-Pem([string]$Label, [byte[]]$DerBytes) {
  $b64 = [Convert]::ToBase64String($DerBytes)
  $lines = New-Object System.Collections.Generic.List[string]
  $lines.Add("-----BEGIN $Label-----") | Out-Null
  for ($i = 0; $i -lt $b64.Length; $i += 64) {
    $take = [Math]::Min(64, $b64.Length - $i)
    $lines.Add($b64.Substring($i, $take)) | Out-Null
  }
  $lines.Add("-----END $Label-----") | Out-Null
  return (($lines -join "`n") + "`n")
}

function Read-Asn1LengthValue {
  param([byte[]]$Data, [ref]$Offset)
  if ($Offset.Value -ge $Data.Length) {
    throw "ASN.1 length offset out of range"
  }
  $b = [int]$Data[$Offset.Value]
  $Offset.Value++
  if (($b -band 0x80) -eq 0) {
    return $b
  }
  $count = $b -band 0x7f
  if ($count -le 0 -or $count -gt 4 -or ($Offset.Value + $count) -gt $Data.Length) {
    throw "invalid ASN.1 long-form length"
  }
  $len = 0
  for ($i = 0; $i -lt $count; $i++) {
    $len = (($len -shl 8) -bor [int]$Data[$Offset.Value])
    $Offset.Value++
  }
  return $len
}

function Test-PemRsaPrivateKeyReadable {
  param([string]$Path)
  try {
    if (-not (Test-Path -LiteralPath $Path)) { return $false }
    $text = [System.IO.File]::ReadAllText(([System.IO.Path]::GetFullPath($Path)))
    $m = [regex]::Match($text, '-----BEGIN RSA PRIVATE KEY-----\s*(?<b64>.*?)\s*-----END RSA PRIVATE KEY-----', 'Singleline')
    if (-not $m.Success) { return $false }
    $der = [Convert]::FromBase64String(($m.Groups['b64'].Value -replace '\s+', ''))
    $offset = 0
    if ($der.Length -lt 16 -or $der[$offset] -ne [byte]0x30) { return $false }
    $offset++
    $seqLen = Read-Asn1LengthValue -Data $der -Offset ([ref]$offset)
    if ($seqLen -le 0 -or ($offset + $seqLen) -gt $der.Length) { return $false }
    if ($der[$offset] -ne [byte]0x02) { return $false }
    $offset++
    $versionLen = Read-Asn1LengthValue -Data $der -Offset ([ref]$offset)
    if ($versionLen -lt 1 -or ($offset + $versionLen) -gt $der.Length) { return $false }
    $versionOk = $true
    for ($i = 0; $i -lt $versionLen; $i++) {
      if ($der[$offset + $i] -ne [byte]0x00) {
        $versionOk = $false
        break
      }
    }
    if (-not $versionOk) { return $false }
    $offset += $versionLen
    $integerCount = 1
    while ($offset -lt $der.Length) {
      if ($der[$offset] -ne [byte]0x02) { break }
      $offset++
      $len = Read-Asn1LengthValue -Data $der -Offset ([ref]$offset)
      if ($len -le 0 -or ($offset + $len) -gt $der.Length) { return $false }
      $offset += $len
      $integerCount++
    }
    return ($integerCount -ge 9)
  } catch {
    return $false
  }
}

function Backup-InvalidPemMaterial {
  param([string]$KeyPath, [string]$CsrPath)
  $stamp = Get-Date -Format "yyyyMMddHHmmss"
  foreach ($p in @($KeyPath, $CsrPath)) {
    if ($p -and (Test-Path -LiteralPath $p)) {
      try {
        Move-Item -LiteralPath $p -Destination ($p + ".invalid-" + $stamp) -Force
      } catch {
        Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue
      }
    }
  }
}

function Convert-RsaParametersToPrivateKeyDer([System.Security.Cryptography.RSAParameters]$P) {
  $body = Join-Bytes @(
    (New-Asn1Integer ([byte[]]@(0))),
    (New-Asn1Integer $P.Modulus),
    (New-Asn1Integer $P.Exponent),
    (New-Asn1Integer $P.D),
    (New-Asn1Integer $P.P),
    (New-Asn1Integer $P.Q),
    (New-Asn1Integer $P.DP),
    (New-Asn1Integer $P.DQ),
    (New-Asn1Integer $P.InverseQ)
  )
  return ,(New-Asn1Sequence $body)
}

function Try-Ensure-NativePemAgentCSR {
  param([string]$KeyPath, [string]$CsrPath, [string]$SubjectCN)
  try {
    if ((Test-Path -LiteralPath $KeyPath) -and (Test-Path -LiteralPath $CsrPath)) {
      if (-not (Test-PemRsaPrivateKeyReadable -Path $KeyPath)) {
        Write-Warning "Existing PEM private key is invalid; backing it up and regenerating key material"
        Backup-InvalidPemMaterial -KeyPath $KeyPath -CsrPath $CsrPath
      } else {
        return [System.IO.File]::ReadAllText(([System.IO.Path]::GetFullPath($CsrPath)))
      }
    }
    if (Test-Path -LiteralPath $KeyPath) {
      if (-not (Test-PemRsaPrivateKeyReadable -Path $KeyPath)) {
        Write-Warning "Existing PEM private key is invalid; backing it up and regenerating key material"
        Backup-InvalidPemMaterial -KeyPath $KeyPath -CsrPath $CsrPath
      } else {
        return $null
      }
    }
    if ((Test-Path -LiteralPath $KeyPath) -and (Test-Path -LiteralPath $CsrPath)) {
      return [System.IO.File]::ReadAllText(([System.IO.Path]::GetFullPath($CsrPath)))
    }
    if (Test-Path -LiteralPath $KeyPath) {
      return $null
    }
    $csrDir = Split-Path -Parent $CsrPath
    if ($csrDir -and -not (Test-Path $csrDir)) {
      New-Item -ItemType Directory -Path $csrDir -Force | Out-Null
    }
    $keyDir = Split-Path -Parent $KeyPath
    if ($keyDir -and -not (Test-Path $keyDir)) {
      New-Item -ItemType Directory -Path $keyDir -Force | Out-Null
    }
    $safeCN = if ($SubjectCN) { $SubjectCN.Replace("/", "-").Replace("\", "-").Replace('"', '') } else { "edr-agent" }
    $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider -ArgumentList 3072
    $rsa.PersistKeyInCsp = $false
    $dn = New-Object System.Security.Cryptography.X509Certificates.X500DistinguishedName -ArgumentList "CN=$safeCN"
    $hash = [System.Security.Cryptography.HashAlgorithmName]::SHA256
    $padding = [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
    $req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new($dn, $rsa, $hash, $padding)
    $csrDer = $req.CreateSigningRequest()
    $keyDer = Convert-RsaParametersToPrivateKeyDer ($rsa.ExportParameters($true))
    [System.IO.File]::WriteAllText(([System.IO.Path]::GetFullPath($KeyPath)), (ConvertTo-Pem "RSA PRIVATE KEY" $keyDer))
    [System.IO.File]::WriteAllText(([System.IO.Path]::GetFullPath($CsrPath)), (ConvertTo-Pem "CERTIFICATE REQUEST" $csrDer))
    return [System.IO.File]::ReadAllText(([System.IO.Path]::GetFullPath($CsrPath)))
  } catch {
    Write-Verbose ("Native PEM CSR generation unavailable: " + $_)
    return $null
  }
}

function Ensure-CngAgentCSR {
  param([string]$CsrPath, [string]$SubjectCN, [string]$ProviderName, [string]$KeyName)
  foreach ($value in @(@{ Name = "ProviderName"; Value = $ProviderName }, @{ Name = "KeyName"; Value = $KeyName })) {
    if ($value.Value -and [regex]::IsMatch([string]$value.Value, '[\x00-\x1f\x7f"]')) {
      throw ("{0} contains a control character or quote and cannot be used in a certreq INF" -f $value.Name)
    }
  }
  if ($SubjectCN -match '[\x00-\x1f\x7f]') { throw "SubjectCN contains control characters" }
  $csrDir = Split-Path -Parent $CsrPath
  if ($csrDir -and -not (Test-Path $csrDir)) {
    New-Item -ItemType Directory -Path $csrDir -Force | Out-Null
  }
  $safeCN = if ($SubjectCN) { $SubjectCN.Replace("/", "-").Replace("\", "-").Replace('"', '') } else { "edr-agent" }
  $safeKeyName = if ($KeyName) {
    if (-not (Test-TypeAvailable "System.Security.Cryptography.CngKey")) {
      throw "an explicit CNG KeyName cannot be verified because the CNG API is unavailable"
    }
    try {
      $existingProvider = New-Object System.Security.Cryptography.CngProvider($ProviderName)
      $existingKey = [System.Security.Cryptography.CngKey]::Open(
        $KeyName,
        $existingProvider,
        [System.Security.Cryptography.CngKeyOpenOptions]::MachineKey
      )
      $existingKey.Dispose()
    } catch {
      throw ("specified machine CNG key '{0}' was not found and will not be replaced by certreq: {1}" -f $KeyName, $_.Exception.Message)
    }
    $KeyName
  } else {
    $suffix = ([guid]::NewGuid().ToString("N")).Substring(0, 12)
    "FDSecurity-Agent-$safeCN-$suffix"
  }
  $script:EDR_CNG_KEY_CONTAINER = $safeKeyName
  $script:EDR_CNG_KEY_CREATED_BY_INSTALL = $false
  $script:EDR_CNG_PROVIDER_USED = $ProviderName
  Write-Host "Using CNG key container: $safeKeyName"
  $infPath = [System.IO.Path]::ChangeExtension($CsrPath, ".inf")
  foreach ($stalePath in @($CsrPath, $infPath)) {
    Remove-StaleEnrollmentArtifact -Path $stalePath
  }
  $nativeKey = $null
  $nativeRsa = $null
  $nativeKeyCreated = $false
  $compatibility = $script:EDR_INSTALL_COMPATIBILITY
  if (-not $compatibility -and (Get-EnrollOs) -eq "windows") {
    $compatibility = Get-WindowsInstallCompatibilitySnapshot
  }
  $nativeCsrAvailable = [bool]($compatibility -and $compatibility.capabilities.certificate_request -and
    $compatibility.capabilities.copy_with_private_key -and $compatibility.capabilities.cng_key -and
    $compatibility.capabilities.cng_provider -and $compatibility.capabilities.rsa_cng)
  if ($nativeCsrAvailable) {
    try {
      $cngProvider = New-Object System.Security.Cryptography.CngProvider($ProviderName)
      if ($KeyName) {
        $nativeKey = [System.Security.Cryptography.CngKey]::Open(
          $safeKeyName,
          $cngProvider,
          [System.Security.Cryptography.CngKeyOpenOptions]::MachineKey
        )
      } else {
        $creation = New-Object System.Security.Cryptography.CngKeyCreationParameters
        $creation.Provider = $cngProvider
        $creation.KeyCreationOptions = [System.Security.Cryptography.CngKeyCreationOptions]::MachineKey
        $creation.ExportPolicy = [System.Security.Cryptography.CngExportPolicies]::None
        $creation.KeyUsage = [System.Security.Cryptography.CngKeyUsages]::Signing
        $creation.Parameters.Add((New-Object System.Security.Cryptography.CngProperty(
          "Length",
          [BitConverter]::GetBytes(3072),
          [System.Security.Cryptography.CngPropertyOptions]::None
        )))
        $nativeKey = [System.Security.Cryptography.CngKey]::Create(
          [System.Security.Cryptography.CngAlgorithm]::Rsa,
          $safeKeyName,
          $creation
        )
        $nativeKeyCreated = $true
        $script:EDR_CNG_KEY_CREATED_BY_INSTALL = $true
      }
      $nativeRsa = New-Object System.Security.Cryptography.RSACng($nativeKey)
      $dn = New-Object System.Security.Cryptography.X509Certificates.X500DistinguishedName("CN=$safeCN")
      $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        $dn,
        $nativeRsa,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
      )
      $oids = New-Object System.Security.Cryptography.OidCollection
      [void]$oids.Add((New-Object System.Security.Cryptography.Oid("1.3.6.1.5.5.7.3.2")))
      $request.CertificateExtensions.Add((New-Object System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension($oids, $false)))
      $csrDer = $request.CreateSigningRequest()
      [System.IO.File]::WriteAllText(
        ([System.IO.Path]::GetFullPath($CsrPath)),
        (ConvertTo-Pem "CERTIFICATE REQUEST" $csrDer)
      )
      return [System.IO.File]::ReadAllText(([System.IO.Path]::GetFullPath($CsrPath)))
    } catch {
      $nativeError = $_.Exception.Message
      if ($nativeKeyCreated -and $nativeKey) {
        try {
          $nativeKey.Delete()
        } catch {
          throw ("Native CNG CSR generation failed and provisional key cleanup failed: " + $_.Exception.Message)
        }
        $script:EDR_CNG_KEY_CREATED_BY_INSTALL = $false
      }
      Write-Warning ("Native CNG CSR generation unavailable; trying bounded certreq compatibility path: " + $nativeError)
    } finally {
      if ($nativeRsa) { $nativeRsa.Dispose() }
      if ($nativeKey) { $nativeKey.Dispose() }
    }
  } else {
    $nativeError = "CertificateRequest/CNG API is unavailable; selecting certreq without creating a provisional native key"
    Write-Warning $nativeError
  }

  $certreq = Get-Command "certreq.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
  if (-not $certreq) {
    Write-Error "Native CNG CSR generation failed and certreq.exe is unavailable"
  }
  $existingKeySetLine = if ($KeyName) { "UseExistingKeySet = TRUE" } else { "" }
  $inf = @"
[Version]
Signature="`$Windows NT`$"

[NewRequest]
Subject = "CN=$safeCN"
KeyAlgorithm = RSA
KeyLength = 3072
HashAlgorithm = SHA256
ProviderName = "$ProviderName"
KeyContainer = "$safeKeyName"
MachineKeySet = TRUE
$existingKeySetLine
Exportable = FALSE
KeySpec = 0
RequestType = PKCS10
Silent = TRUE

[EnhancedKeyUsageExtension]
OID=1.3.6.1.5.5.7.3.2
"@
  [System.IO.File]::WriteAllText(([System.IO.Path]::GetFullPath($infPath)), $inf)
  # A generated name is owned by this transaction. An explicitly supplied
  # name remains caller-owned even when certreq is the compatibility path.
  if (-not $KeyName -and [System.Security.Cryptography.CngKey]::Exists(
    $safeKeyName, (New-Object System.Security.Cryptography.CngProvider($ProviderName)),
    [System.Security.Cryptography.CngKeyOpenOptions]::MachineKey)) {
    throw "generated key name already exists; refusing to replace an unowned machine key"
  }
  $script:EDR_CNG_KEY_CREATED_BY_INSTALL = -not [bool]$KeyName
  Invoke-Checked -Exe $certreq.Source -ArgList @("-new", "-machine", $infPath, $CsrPath) -TimeoutSeconds 30
  return [System.IO.File]::ReadAllText(([System.IO.Path]::GetFullPath($CsrPath)))
}

function Ensure-ExternalKeyCSR {
  param([string]$CsrPath, [string]$SubjectCN, [string]$Provider, [string]$KeyUri, [string]$ModulePath)
  $openssl = Resolve-OpenSSL
  $csrDir = Split-Path -Parent $CsrPath
  if ($csrDir -and -not (Test-Path $csrDir)) {
    New-Item -ItemType Directory -Path $csrDir -Force | Out-Null
  }
  $safeCN = if ($SubjectCN) { $SubjectCN.Replace("/", "-").Replace("\", "-") } else { "edr-agent" }
  if ($Provider -eq "pkcs11") {
    if (-not $KeyUri) { Write-Error "EDR_PKCS11_KEY_URI is required for EDR_KEY_PROVIDER=pkcs11" }
    $mode = if ($env:EDR_PKCS11_OPENSSL_MODE) { $env:EDR_PKCS11_OPENSSL_MODE.Trim().ToLowerInvariant() } else { "engine" }
    if ($mode -eq "provider") {
      $args = @("req", "-new", "-provider", "default", "-provider", "pkcs11", "-key", $KeyUri, "-out", $CsrPath, "-subj", "/CN=$safeCN")
      if ($ModulePath) { $args = @("req", "-new", "-provider", "default", "-provider-path", $ModulePath, "-provider", "pkcs11", "-key", $KeyUri, "-out", $CsrPath, "-subj", "/CN=$safeCN") }
      Invoke-Checked -Exe $openssl -ArgList $args
    } else {
      Invoke-Checked -Exe $openssl -ArgList @("req", "-new", "-engine", "pkcs11", "-keyform", "engine", "-key", $KeyUri, "-out", $CsrPath, "-subj", "/CN=$safeCN")
    }
  } elseif ($Provider -eq "tpm") {
    if (-not $KeyUri) { Write-Error "EDR_TPM_KEY_URI is required when TPM OpenSSL provider mode is used" }
    $tpmProvider = if ($env:EDR_OPENSSL_TPM_PROVIDER) { $env:EDR_OPENSSL_TPM_PROVIDER } else { "tpm2" }
    Invoke-Checked -Exe $openssl -ArgList @("req", "-new", "-provider", "default", "-provider", $tpmProvider, "-key", $KeyUri, "-out", $CsrPath, "-subj", "/CN=$safeCN")
  }
  return [System.IO.File]::ReadAllText(([System.IO.Path]::GetFullPath($CsrPath)))
}

function Ensure-AgentCSR {
  param([string]$KeyPath, [string]$CsrPath, [string]$SubjectCN, [string]$Provider)
  $Provider = Normalize-KeyProvider $Provider
  $script:EDR_EFFECTIVE_KEY_PROVIDER = $Provider
  if ($Provider -eq "cng" -or ($Provider -eq "tpm" -and -not $TpmKeyUri)) {
    $pn = $CngProviderName
    if (-not $pn) {
      $pn = if ($Provider -eq "tpm") { "Microsoft Platform Crypto Provider" } else { "Microsoft Software Key Storage Provider" }
    }
    try {
      return Ensure-CngAgentCSR -CsrPath $CsrPath -SubjectCN $SubjectCN -ProviderName $pn -KeyName $CngKeyName
    } catch {
      if ($Provider -ne "cng") {
        throw
      }
      if ((Get-EnrollOs) -eq "windows" -and $env:EDR_ALLOW_WINDOWS_PEM_FALLBACK -ne "1") {
        throw ("CNG CSR generation failed; Windows Schannel transport requires a certificate-store backed client certificate. " +
          "Fix certreq/CNG enrollment or set EDR_ALLOW_WINDOWS_PEM_FALLBACK=1 only when using an OpenSSL libcurl build. " +
          "Cause: " + $_.Exception.Message)
      }
      Write-Warning ("CNG CSR generation failed, falling back to PEM key for install continuity: " + $_.Exception.Message)
      $Provider = "pem"
      $script:EDR_EFFECTIVE_KEY_PROVIDER = "pem"
    }
  }
  if ($Provider -eq "pkcs11" -or $Provider -eq "tpm") {
    $script:EDR_EFFECTIVE_KEY_PROVIDER = $Provider
    $uri = if ($Provider -eq "pkcs11") { $Pkcs11KeyUri } else { $TpmKeyUri }
    return Ensure-ExternalKeyCSR -CsrPath $CsrPath -SubjectCN $SubjectCN -Provider $Provider -KeyUri $uri -ModulePath $Pkcs11Module
  }
  $script:EDR_EFFECTIVE_KEY_PROVIDER = "pem"
  $nativeCsr = Try-Ensure-NativePemAgentCSR -KeyPath $KeyPath -CsrPath $CsrPath -SubjectCN $SubjectCN
  if ($nativeCsr) {
    return $nativeCsr
  }
  $openssl = Resolve-OpenSSL
  $keyDir = Split-Path -Parent $KeyPath
  if ($keyDir -and -not (Test-Path $keyDir)) {
    New-Item -ItemType Directory -Path $keyDir -Force | Out-Null
  }
  $csrDir = Split-Path -Parent $CsrPath
  if ($csrDir -and -not (Test-Path $csrDir)) {
    New-Item -ItemType Directory -Path $csrDir -Force | Out-Null
  }
  if (-not (Test-Path -LiteralPath $KeyPath)) {
    Invoke-Checked -Exe $openssl -ArgList @("genrsa", "-out", $KeyPath, "3072")
  }
  $safeCN = if ($SubjectCN) { $SubjectCN.Replace("/", "-").Replace("\", "-") } else { "edr-agent" }
  Invoke-Checked -Exe $openssl -ArgList @("req", "-new", "-key", $KeyPath, "-out", $CsrPath, "-subj", "/CN=$safeCN")
  return [System.IO.File]::ReadAllText(([System.IO.Path]::GetFullPath($CsrPath)))
}

$script:EDR_INSTALL_TRANSACTION_ACTIVE = $false
$script:EDR_INSTALL_TRANSACTION_COMMITTED = $false
$script:EDR_PROVISIONAL_CERT_THUMBPRINT = ""
$script:EDR_PROVISIONAL_CERT_STORE = ""
$script:EDR_PROVISIONAL_CERT_PREEXISTED = $false
$script:EDR_CNG_KEY_CREATED_BY_INSTALL = $false
$script:EDR_CNG_PROVIDER_USED = ""

function Remove-ProvisionalEnrollmentMaterial {
  param([string]$Reason)
  if (-not $script:EDR_INSTALL_TRANSACTION_ACTIVE -or $script:EDR_INSTALL_TRANSACTION_COMMITTED) { return }

  $certificateRemoved = $false
  $keyRemoved = $false
  $errors = New-Object System.Collections.Generic.List[string]
  if ((Get-EnrollOs) -eq "windows") {
    $thumbprint = ([string]$script:EDR_PROVISIONAL_CERT_THUMBPRINT -replace '\s+', '').ToUpperInvariant()
    if ($thumbprint -and -not $script:EDR_PROVISIONAL_CERT_PREEXISTED) {
      $store = if ($script:EDR_PROVISIONAL_CERT_STORE) { [string]$script:EDR_PROVISIONAL_CERT_STORE } else { "LocalMachine\My" }
      $store = ($store -replace '^Cert:\\?', '').Trim([char]0x5c)
      $certPath = "Cert:\$store\$thumbprint"
      try {
        if (Test-Path -LiteralPath $certPath) {
          Remove-Item -LiteralPath $certPath -Force -ErrorAction Stop
          $certificateRemoved = $true
        }
      } catch {
        $errors.Add(("client certificate cleanup failed: " + $_.Exception.Message)) | Out-Null
      }
    }

    if ($script:EDR_CNG_KEY_CREATED_BY_INSTALL -and $script:EDR_CNG_KEY_CONTAINER) {
      try {
        $certutil = Get-Command "certutil.exe" -ErrorAction Stop | Select-Object -First 1
        $provider = if ($script:EDR_CNG_PROVIDER_USED) { [string]$script:EDR_CNG_PROVIDER_USED } else { "Microsoft Software Key Storage Provider" }
        # Windows 11 certutil rejects -f for the -delkey verb. Keep the KSP
        # selection explicit, but use the verb's supported argument contract so
        # failed enrollment cannot accumulate orphaned machine keys.
        $result = Invoke-CapturedProcess -Exe $certutil.Source -ArgList @("-csp", $provider, "-delkey", [string]$script:EDR_CNG_KEY_CONTAINER) -TimeoutSeconds 30
        $output = @($result.Stdout, $result.Stderr) | Where-Object { $_ }
        if ($result.ExitCode -eq 0) {
          $keyRemoved = $true
        } else {
          $errors.Add(("CNG key cleanup failed exit={0}: {1}" -f $result.ExitCode, (($output | Out-String).Trim()))) | Out-Null
        }
      } catch {
        $errors.Add(("CNG key cleanup failed: " + $_.Exception.Message)) | Out-Null
      }
    }
  }

  $receipt = [ordered]@{
    schema = "edr.agent.install.rollback.v1"
    completed_at = (Get-Date).ToUniversalTime().ToString("o")
    status = if ($errors.Count -eq 0) { "succeeded" } else { "partial_failed" }
    reason = $Reason
    certificate_thumbprint = [string]$script:EDR_PROVISIONAL_CERT_THUMBPRINT
    certificate_preexisting = [bool]$script:EDR_PROVISIONAL_CERT_PREEXISTED
    certificate_removed = $certificateRemoved
    cng_key_container = [string]$script:EDR_CNG_KEY_CONTAINER
    cng_key_created_by_install = [bool]$script:EDR_CNG_KEY_CREATED_BY_INSTALL
    cng_key_removed = $keyRemoved
    errors = [string[]]$errors
  }
  $path = Write-DurableInstallDiagnostic -Name "install-enrollment-rollback-last.json" -Report $receipt
  if ($path) {
    if ($errors.Count -eq 0) {
      Write-Host ("Rolled back provisional enrollment material; receipt=" + $path)
    } else {
      Write-Warning ("Enrollment material rollback incomplete; receipt=" + $path)
    }
  }
  $script:EDR_INSTALL_TRANSACTION_ACTIVE = $false
}

function Get-NormalizedSha256List([string]$Value) {
  $out = New-Object System.Collections.Generic.List[string]
  if (-not $Value) { return $out.ToArray() }
  foreach ($part in ($Value -split '[,;\s]+')) {
    $p = ($part -replace '[:\-]', '').Trim().ToLowerInvariant()
    if ($p -match '^[0-9a-f]{64}$') {
      $out.Add($p) | Out-Null
    }
  }
  return $out.ToArray()
}

function Read-PemCertificates([string]$Path) {
  $certs = New-Object System.Collections.Generic.List[System.Security.Cryptography.X509Certificates.X509Certificate2]
  if (-not $Path -or -not (Test-Path -LiteralPath $Path)) {
    return ,([System.Security.Cryptography.X509Certificates.X509Certificate2[]]@())
  }
  $raw = [System.IO.File]::ReadAllText(([System.IO.Path]::GetFullPath($Path)))
  foreach ($m in [regex]::Matches($raw, '-----BEGIN CERTIFICATE-----\s*(?<b64>.*?)\s*-----END CERTIFICATE-----', 'Singleline')) {
    try {
      $bytes = [Convert]::FromBase64String(($m.Groups['b64'].Value -replace '\s+', ''))
      $certs.Add((New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @(,$bytes))) | Out-Null
    } catch {
      Write-Warning ("failed to parse bootstrap CA certificate: " + $_)
    }
  }
  return ,([System.Security.Cryptography.X509Certificates.X509Certificate2[]]$certs.ToArray())
}

function Ensure-BootstrapTlsValidatorType {
  if (([System.Management.Automation.PSTypeName]"FdsBootstrapTlsValidator").Type) { return }
  Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

public static class FdsBootstrapTlsValidator
{
    private static readonly object Sync = new object();
    private static X509Certificate2Collection CaCertificates = new X509Certificate2Collection();
    private static HashSet<string> CaThumbprints = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    private static HashSet<string> LeafPins = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    private static string LastFailureValue = "";
    private static string LastSuccessValue = "";

    public static readonly RemoteCertificateValidationCallback Callback = Validate;

    public static void Configure(X509Certificate2[] certificates, string[] caThumbprints, string[] leafPins)
    {
        lock (Sync)
        {
            foreach (X509Certificate2 oldCertificate in CaCertificates)
            {
                oldCertificate.Dispose();
            }
            CaCertificates = new X509Certificate2Collection();
            CaThumbprints = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            LeafPins = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (certificates != null)
            {
                foreach (X509Certificate2 certificate in certificates)
                {
                    CaCertificates.Add(new X509Certificate2(certificate));
                }
            }
            if (caThumbprints != null)
            {
                foreach (string thumbprint in caThumbprints)
                {
                    if (!String.IsNullOrEmpty(thumbprint)) CaThumbprints.Add(thumbprint);
                }
            }
            if (leafPins != null)
            {
                foreach (string pin in leafPins)
                {
                    if (!String.IsNullOrEmpty(pin)) LeafPins.Add(pin);
                }
            }
            LastFailureValue = "";
            LastSuccessValue = "";
        }
    }

    public static string LastFailure
    {
        get { lock (Sync) { return LastFailureValue; } }
    }

    public static string LastSuccess
    {
        get { lock (Sync) { return LastSuccessValue; } }
    }

    private static bool IsServerAuthenticationCertificate(X509Certificate2 certificate)
    {
        bool hasEku = false;
        bool hasServerAuth = false;
        bool hasAnyExtendedKeyUsage = false;
        foreach (X509Extension extension in certificate.Extensions)
        {
            if (extension.Oid == null || extension.Oid.Value != "2.5.29.37") continue;
            hasEku = true;
            X509EnhancedKeyUsageExtension eku = new X509EnhancedKeyUsageExtension(extension, false);
            foreach (Oid oid in eku.EnhancedKeyUsages)
            {
                if (oid != null && oid.Value == "1.3.6.1.5.5.7.3.1")
                {
                    hasServerAuth = true;
                }
                if (oid != null && oid.Value == "2.5.29.37.0")
                {
                    hasAnyExtendedKeyUsage = true;
                }
            }
        }
        // No EKU means unrestricted usage. anyExtendedKeyUsage is also an
        // explicit unrestricted usage marker; an explicit EKU list otherwise
        // must contain serverAuth for the bootstrap HTTPS server.
        return !hasEku || hasServerAuth || hasAnyExtendedKeyUsage;
    }

    private static bool HasOnlyPermittedTrustErrors(X509Chain chain, bool allowPartialChain, bool allowUntrustedRoot, out string status)
    {
        List<string> failures = new List<string>();
        foreach (X509ChainElement element in chain.ChainElements)
        {
            foreach (X509ChainStatus chainStatus in element.ChainElementStatus)
            {
                X509ChainStatusFlags flags = chainStatus.Status;
                if (flags != X509ChainStatusFlags.NoError &&
                    !(allowUntrustedRoot && flags == X509ChainStatusFlags.UntrustedRoot) &&
                    !(allowPartialChain && flags == X509ChainStatusFlags.PartialChain))
                {
                    failures.Add(flags.ToString());
                }
            }
        }
        status = String.Join(",", failures.ToArray());
        return failures.Count == 0;
    }

    private static bool HasConfiguredCaAnchor(X509Chain chain)
    {
        int lastIndex = chain.ChainElements.Count - 1;
        for (int index = 0; index < chain.ChainElements.Count; index++)
        {
            if (index != lastIndex) continue;
            X509ChainElement element = chain.ChainElements[index];
            string thumbprint = (element.Certificate.Thumbprint ?? "").Replace(" ", "").ToUpperInvariant();
            if (!CaThumbprints.Contains(thumbprint)) continue;
            foreach (X509Certificate2 configured in CaCertificates)
            {
                string configuredThumbprint = (configured.Thumbprint ?? "").Replace(" ", "").ToUpperInvariant();
                if (configuredThumbprint != thumbprint) continue;
                foreach (X509Extension extension in configured.Extensions)
                {
                    if (extension.Oid != null && extension.Oid.Value == "2.5.29.19")
                    {
                        X509BasicConstraintsExtension constraints = new X509BasicConstraintsExtension(extension, false);
                        if (constraints.CertificateAuthority) return true;
                    }
                }
            }
        }
        return false;
    }

    private static void SetFailure(string value)
    {
        lock (Sync)
        {
            LastFailureValue = value;
            LastSuccessValue = "";
        }
    }

    private static void SetSuccess(string value)
    {
        lock (Sync)
        {
            LastFailureValue = "";
            LastSuccessValue = value;
        }
    }

    public static bool Validate(object sender, X509Certificate certificate, X509Chain peerChain, SslPolicyErrors sslPolicyErrors)
    {
        try
        {
            if (certificate == null)
            {
                SetFailure("certificate_not_available");
                return false;
            }
            if ((sslPolicyErrors & SslPolicyErrors.RemoteCertificateNotAvailable) != 0)
            {
                SetFailure("certificate_not_available");
                return false;
            }
            if ((sslPolicyErrors & SslPolicyErrors.RemoteCertificateNameMismatch) != 0)
            {
                SetFailure("certificate_name_mismatch");
                return false;
            }
            X509Certificate2 leaf = new X509Certificate2(certificate);
            try
            {
                DateTime now = DateTime.UtcNow;
                if (leaf.NotBefore.ToUniversalTime() > now || leaf.NotAfter.ToUniversalTime() < now)
                {
                    SetFailure("certificate_not_time_valid");
                    return false;
                }
                if (!IsServerAuthenticationCertificate(leaf))
                {
                    SetFailure("certificate_missing_server_auth_eku");
                    return false;
                }
                X509Chain customChain = new X509Chain();
                try
                {
                    // Offline bootstrap policy: no online CRL/OCSP assertion.
                    // No other chain errors are ignored.
                    customChain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                    customChain.ChainPolicy.UrlRetrievalTimeout = TimeSpan.FromSeconds(5);
                    customChain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
                    customChain.ChainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.1"));
                    // Peer-supplied intermediates are candidates, never anchors.
                    if (peerChain != null)
                    {
                        foreach (X509ChainElement element in peerChain.ChainElements)
                            customChain.ChainPolicy.ExtraStore.Add(element.Certificate);
                        customChain.ChainPolicy.ExtraStore.AddRange(peerChain.ChainPolicy.ExtraStore);
                    }
                    lock (Sync)
                    {
                        foreach (X509Certificate2 ca in CaCertificates)
                        {
                            customChain.ChainPolicy.ExtraStore.Add(ca);
                        }
                    }
                    bool built = customChain.Build(leaf);
                    string chainStatus;
                    string pinStatus;
                    bool caStatuses = HasOnlyPermittedTrustErrors(customChain, false, true, out chainStatus);
                    bool pinStatuses = HasOnlyPermittedTrustErrors(customChain, true, true, out pinStatus);
                    bool caMatch;
                    bool pinMatch;
                    lock (Sync)
                    {
                        caMatch = built && caStatuses && HasConfiguredCaAnchor(customChain);
                        string leafHash = "";
                        using (System.Security.Cryptography.SHA256 sha = System.Security.Cryptography.SHA256.Create())
                        {
                            leafHash = BitConverter.ToString(sha.ComputeHash(leaf.RawData)).Replace("-", "").ToLowerInvariant();
                        }
                        pinMatch = LeafPins.Contains(leafHash) && pinStatuses;
                    }
                    if (caMatch)
                    {
                        SetSuccess("ca");
                        return true;
                    }
                    if (pinMatch)
                    {
                        SetSuccess("leaf_pin");
                        return true;
                    }
                    SetFailure((built ? "bootstrap_trust_anchor_or_pin_mismatch" : "bootstrap_chain_build_failed") +
                        (String.IsNullOrEmpty(chainStatus) ? "" : ":" + chainStatus));
                    return false;
                }
                finally
                {
                    customChain.Dispose();
                }
            }
            finally
            {
                leaf.Dispose();
            }
        }
        catch (Exception error)
        {
            SetFailure("validator_exception:" + error.GetType().FullName + ":" + error.Message);
            return false;
        }
    }
}
'@
}

$script:EDR_BOOTSTRAP_TLS_VALIDATION_ENABLED = $false
$script:EDR_BOOTSTRAP_TLS_LAST_FAILURE = ""

function Enable-BootstrapTlsValidation([string]$CaPath, [string]$LeafSha256) {
  $pins = @(Get-NormalizedSha256List $LeafSha256)
  if ($LeafSha256 -and $pins.Count -eq 0) {
    throw "bootstrap leaf pin is not a valid SHA-256 value"
  }
  if ($CaPath -and -not (Test-Path -LiteralPath $CaPath -PathType Leaf)) {
    throw ("bootstrap CA file was not found: {0}" -f $CaPath)
  }
  $certs = Read-PemCertificates $CaPath
  if ($pins.Count -eq 0 -and $certs.Count -eq 0) {
    throw "bootstrap TLS policy was requested but contained no valid CA certificate or leaf pin"
  }
  $thumbprints = New-Object System.Collections.Generic.List[string]
  foreach ($ca in $certs) {
    if ($ca.Thumbprint) {
      $thumbprints.Add(($ca.Thumbprint -replace '\s+', '').ToUpperInvariant()) | Out-Null
    }
  }
  $script:EDR_BOOTSTRAP_TLS_LEAF_SHA256 = @($pins)
  $script:EDR_BOOTSTRAP_TLS_CA_CERTS = @($certs)
  $script:EDR_BOOTSTRAP_TLS_CA_THUMBPRINTS = @($thumbprints)
  Ensure-BootstrapTlsValidatorType
  [System.Security.Cryptography.X509Certificates.X509Certificate2[]]$certArray = @($certs)
  [string[]]$thumbprintArray = @($thumbprints)
  [string[]]$pinArray = @($pins)
  [FdsBootstrapTlsValidator]::Configure($certArray, $thumbprintArray, $pinArray)
  $script:EDR_BOOTSTRAP_TLS_VALIDATION_ENABLED = $true
  [System.Net.ServicePointManager]::ServerCertificateValidationCallback = [FdsBootstrapTlsValidator]::Callback
  Write-Host "Enabled bootstrap TLS validation for enrollment"
}

if ((Get-EnrollOs) -eq "windows") {
  $compatibilityProvider = Normalize-KeyProvider $KeyProvider
  $script:EDR_INSTALL_COMPATIBILITY = Assert-WindowsInstallCompatibility -RequestedProvider $compatibilityProvider -ExternalTpmKeyUri ([bool]$TpmKeyUri)
  Set-WindowsInstallTlsCompatibility
  $script:EDR_INSTALL_COMPATIBILITY.tls["selected_policy"] = $script:EDR_TLS_POLICY_MODE
  $script:EDR_INSTALL_COMPATIBILITY.tls["effective_security_protocol"] = $script:EDR_TLS_POLICY_AFTER
  [void](Write-WindowsInstallCompatibilityDiagnostic -Snapshot $script:EDR_INSTALL_COMPATIBILITY)
  # Compile/parse bootstrap policy before preflight stops services or creates keys.
  if ($BootstrapCaCertPath -or $BootstrapTlsLeafSha256) {
    Enable-BootstrapTlsValidation -CaPath $BootstrapCaCertPath -LeafSha256 $BootstrapTlsLeafSha256
  }
}

Invoke-AgentPreflightIfNeeded

Repair-AgentTomlAcl -Path $Output
$existingEndpointId = Read-AgentTomlScalar -Path $Output -Key "endpoint_id"
$existingTenantId = Read-AgentTomlScalar -Path $Output -Key "tenant_id"
if ($existingEndpointId -and $existingTenantId -and -not $ForceEnroll) {
  $existingInstallRoot = Split-Path -Parent ([System.IO.Path]::GetFullPath($Output))
  Repair-InstallRuntimeAcls -InstallRoot $existingInstallRoot
  Repair-AgentTomlAcl -Path $Output
  $existingTomlIssue = Get-ExistingAgentTomlSanityIssue -Path $Output
  if (-not $existingTomlIssue) {
    $existingTomlIssue = Test-ExistingAgentTomlWithAgent -InstallRoot $existingInstallRoot -ConfigPath $Output
  }
  if (-not $existingTomlIssue) {
    $existingTomlIssue = Get-ExistingAgentTomlMtlsIssue -Path $Output
  }
  if (-not $existingTomlIssue -and $env:EDR_ALLOW_LEGACY_UNSIGNED_CONFIG -ne "1") {
    $existingTomlIssue = Get-ExistingAgentTomlRequestSigningIssue -Path $Output
  }
  if ($existingTomlIssue) {
    Write-Warning ("Existing agent.toml is invalid ({0}); backing it up and re-enrolling." -f $existingTomlIssue)
    $backupPath = Backup-InvalidAgentToml -Path $Output
    if ($backupPath) {
      Write-Warning ("Invalid agent.toml moved to " + $backupPath)
    }
  } else {
    if ($TrustCa) {
      Install-BootstrapCaTrust -Path $CaCertPath
    }
    if ($ConfigureSensorPolicy) {
      Enable-WindowsSensorPolicy
    }
    if ($InstallAutorun) {
      Install-AgentAutorun
    }
    Install-HeadlessUninstaller -InstallRoot $existingInstallRoot
    Write-Host "Existing agent.toml found (endpoint_id=$existingEndpointId tenant_id=$existingTenantId); skipped enroll. Use -ForceEnroll or EDR_FORCE_ENROLL=1 to re-enroll."
    exit 0
  }
}

try {
  $script:EDR_INSTALL_TRANSACTION_ACTIVE = $true
  $keyProviderNorm = Normalize-KeyProvider $KeyProvider
  $csrPem = Ensure-AgentCSR -KeyPath $ClientKeyPath -CsrPath $ClientCsrPath -SubjectCN $env:COMPUTERNAME -Provider $keyProviderNorm
  $effectiveKeyProvider = if ($script:EDR_EFFECTIVE_KEY_PROVIDER) { [string]$script:EDR_EFFECTIVE_KEY_PROVIDER } else { $keyProviderNorm }
if ($keyProviderNorm -eq "cng" -and $effectiveKeyProvider -eq "pem") {
  # CNG can fall back to a local PEM key on hosts where certreq/KSP enrollment is
  # unavailable. Keep the rest of the install path aligned with the key material
  # that was actually generated.
  Write-Warning "CNG key provider fell back to PEM; using file-based client certificate configuration"
}

$bodyObj = @{
  token         = $tok
  hostname      = $env:COMPUTERNAME
  os            = (Get-EnrollOs)
  arch          = $env:PROCESSOR_ARCHITECTURE
  agent_version = $av
  ip            = ""
  csr_pem       = $csrPem
}
$json = $bodyObj | ConvertTo-Json -Compress

function Write-BootstrapPemNoBom([string]$Path, [string]$Text) {
  if (-not $Path -or -not $Text) { return }
  $dir = Split-Path -Parent $Path
  if ($dir -and -not (Test-Path $dir)) {
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
  }
  [System.IO.File]::WriteAllText(([System.IO.Path]::GetFullPath($Path)), $Text)
}


if ($TrustCa) {
  Install-BootstrapCaTrust -Path $CaCertPath
}

if ($env:EDR_INSECURE_TLS -eq "1") {
  $script:EDR_BOOTSTRAP_TLS_VALIDATION_ENABLED = $false
  if (-not ([System.Management.Automation.PSTypeName]'TrustAllCertsPolicy').Type) {
    Add-Type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
  public bool CheckValidationResult(ServicePoint sp, X509Certificate cert, WebRequest req, int problem) { return true; }
}
"@
  }
  [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
}

function Get-RedactedUrlForDiagnostics {
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

function Get-ExceptionChainText {
  param([object]$Exception)
  $items = New-Object System.Collections.Generic.List[string]
  $e = $Exception
  while ($e) {
    $msg = ([string]$e.Message).Trim()
    if ($msg) {
      $items.Add(("{0}: {1}" -f $e.GetType().FullName, $msg)) | Out-Null
    }
    $e = $e.InnerException
  }
  return ($items -join " | ")
}

function ConvertTo-EnrollDiagnosticValue {
  param(
    [object]$Value,
    [int]$MaxLength = 800
  )
  $s = ([string]$Value).Trim()
  if (-not $s) {
    return ""
  }
  $s = $s -replace "[`r`n`t]+", " "
  if ($s.Length -gt $MaxLength) {
    return ($s.Substring(0, $MaxLength) + "...")
  }
  return $s
}

function Get-EnrollErrorResponseDiagnostics {
  param([object]$Response)
  $items = New-Object System.Collections.Generic.List[string]
  if (-not $Response) {
    return $items
  }
  try {
    $stream = $Response.GetResponseStream()
    if (-not $stream) {
      return $items
    }
    $reader = New-Object System.IO.StreamReader -ArgumentList @($stream, [System.Text.Encoding]::UTF8)
    try {
      $rawBody = $reader.ReadToEnd()
    } finally {
      $reader.Dispose()
    }
    $body = ConvertTo-EnrollDiagnosticValue $rawBody 2000
    if (-not $body) {
      return $items
    }
    $parsed = $null
    try {
      $parsed = $rawBody | ConvertFrom-Json -ErrorAction Stop
    } catch {
      $parsed = $null
    }
    if ($parsed) {
      if ($parsed.code) {
        $items.Add(("api_code={0}" -f (ConvertTo-EnrollDiagnosticValue $parsed.code 200))) | Out-Null
      }
      if ($parsed.message) {
        $items.Add(("api_message={0}" -f (ConvertTo-EnrollDiagnosticValue $parsed.message 800))) | Out-Null
      }
      if ($parsed.request_id) {
        $items.Add(("api_request_id={0}" -f (ConvertTo-EnrollDiagnosticValue $parsed.request_id 200))) | Out-Null
      }
    }
    $items.Add(("api_body={0}" -f $body)) | Out-Null
  } catch {
    $items.Add(("api_body_read_error={0}" -f (ConvertTo-EnrollDiagnosticValue $_.Exception.Message 400))) | Out-Null
  }
  return $items
}

function Get-EnrollFailureHint {
  param(
    [object]$Exception,
    [string]$ApiDiagnostics = ""
  )
  $text = ((Get-ExceptionChainText $Exception) + " " + $ApiDiagnostics).ToLowerInvariant()
  if ($text -match "token_expired|token expired|has expired|已过期|过期") {
    return "Enrollment token has expired; generate a new enrollment token in the platform and rerun the installer with the new token."
  }
  if ($text -match "token_exhausted|activation limit|limit reached|no longer activatable|激活次数|耗尽") {
    return "Enrollment token activation limit has been reached; generate a new token or increase the token activation limit, then rerun the installer."
  }
  if ($text -match "invalid_token|unknown or revoked|not active|missing token|无效|吊销|撤销") {
    return "Enrollment token is invalid, revoked, missing, or not active; copy the current plaintext token from the platform and rerun the installer."
  }
  if ($text -match "os_not_allowed|os_type|does not allow this platform|platform|操作系统") {
    return "Enrollment token does not allow this operating system; create or select a token whose osType matches this endpoint."
  }
  if ($text -match "quota_exceeded|endpoint quota|quota exceeded|配额") {
    return "Endpoint quota has been reached; free endpoint quota or expand the tenant license before enrolling this endpoint."
  }
  if ($text -match "license_blocked|license expired|license suspended|expired/suspended|过期许可|许可") {
    return "Tenant license blocks enrollment; renew or reactivate the tenant license before enrolling new endpoints."
  }
  if ($text -match "securechannelfailure|could not establish trust relationship|ssl/tls|tls handshake|certificate_name_mismatch|certificate_not_time_valid|missing_server_auth_eku|bootstrap_chain") {
    if ($BootstrapCaCertPath -or $BootstrapTlsLeafSha256) {
      return "TLS/bootstrap certificate validation failed under the supplied bootstrap policy; verify Schannel events, the server DNS/IP SAN, validity period, serverAuth EKU, CA chain, and configured leaf pin."
    }
    return "TLS/bootstrap certificate validation failed; provide a signed bootstrap manifest with tls_ca_pem or tls_leaf_sha256 and verify the server DNS/IP SAN, validity period, serverAuth EKU, and CA chain."
  }
  if ($text -match "trust|certificate|ssl|tls|认证|证书") {
    if ($BootstrapCaCertPath -or $BootstrapTlsLeafSha256) {
      return "TLS/bootstrap certificate validation failed under the supplied bootstrap policy; inspect Schannel and the bootstrap certificate metadata."
    }
    return "TLS/bootstrap certificate validation failed; provide a signed bootstrap manifest with tls_ca_pem or tls_leaf_sha256 and verify the certificate metadata."
  }
  if ($text -match "proxy|407") {
    return "Proxy failed; verify proxy mode, proxy URL, and optional proxy credentials."
  }
  if ($text -match "timed out|timeout|超时|canceled") {
    return "Enroll endpoint timed out; verify address, port, firewall/NAT, proxy, and that the backend is listening on the selected HTTPS port."
  }
  if ($text -match "refused|actively refused|无法连接|no connection|unreachable|name resolution|dns") {
    return "Enroll endpoint is unreachable; verify IP/port, backend bind address, firewall, routing, and proxy mode."
  }
  return "Enroll request failed; check backend /api/v1/enroll availability, TLS trust, proxy settings, and enroll token validity."
}

function Format-EnrollFailure {
  param([object]$ErrorRecord)
  $ex = $ErrorRecord.Exception
  $parts = New-Object System.Collections.Generic.List[string]
  $parts.Add("enroll failed") | Out-Null
  $parts.Add(("url={0}" -f (Get-RedactedUrlForDiagnostics $uri))) | Out-Null
  $parts.Add(("timeout_sec={0}" -f $EnrollTimeoutSec)) | Out-Null
  $parts.Add(("proxy_mode={0}" -f $ProxyMode)) | Out-Null
  $parts.Add(("proxy_url={0}" -f (Get-RedactedUrlForDiagnostics $ProxyUrl))) | Out-Null
  $parts.Add(("trust_ca={0}" -f [bool]$TrustCa)) | Out-Null
  $parts.Add(("insecure_tls={0}" -f ($env:EDR_INSECURE_TLS -eq "1"))) | Out-Null
  $parts.Add(("bootstrap_ca={0}" -f [bool]$BootstrapCaCertPath)) | Out-Null
  $parts.Add(("bootstrap_leaf_pin={0}" -f [bool]$BootstrapTlsLeafSha256)) | Out-Null
  $parts.Add(("tls_policy={0}" -f $(if ($script:EDR_TLS_POLICY_MODE) { $script:EDR_TLS_POLICY_MODE } else { "unknown" }))) | Out-Null
  if (([System.Management.Automation.PSTypeName]"FdsBootstrapTlsValidator").Type) {
    $parts.Add(("bootstrap_validator_failure={0}" -f [FdsBootstrapTlsValidator]::LastFailure)) | Out-Null
    $parts.Add(("bootstrap_validator_success={0}" -f [FdsBootstrapTlsValidator]::LastSuccess)) | Out-Null
  }
  $apiDetails = New-Object System.Collections.Generic.List[string]
  if ($ex -is [System.Net.WebException]) {
    $parts.Add(("web_status={0}" -f $ex.Status)) | Out-Null
    if ($ex.Response -is [System.Net.HttpWebResponse]) {
      $parts.Add(("http_status={0}" -f [int]$ex.Response.StatusCode)) | Out-Null
      foreach ($detail in (Get-EnrollErrorResponseDiagnostics $ex.Response)) {
        if ($detail) {
          $apiDetails.Add($detail) | Out-Null
          $parts.Add($detail) | Out-Null
        }
      }
    }
  }
  $parts.Add(("error_chain={0}" -f (Get-ExceptionChainText $ex))) | Out-Null
  $parts.Add(("hint={0}" -f (Get-EnrollFailureHint -Exception $ex -ApiDiagnostics ($apiDetails -join " ")))) | Out-Null
  return ($parts -join "; ")
}

try {
  $resp = Invoke-RestMethod -Uri $uri -Method Post -ContentType "application/json; charset=utf-8" -Body $json -TimeoutSec $EnrollTimeoutSec @WebRequestProxyOptions
} catch {
  Write-Error (Format-EnrollFailure $_)
}

if ($resp.code -and $resp.code -ne "OK") {
  Write-Error ("API error: " + ($resp | ConvertTo-Json -Compress))
}

$d = $resp.data
if (-not $d.endpoint_id -or -not $d.tenant_id -or -not $d.server_addr) {
  Write-Error "enroll response missing endpoint_id, tenant_id or server_addr"
}

$saddr = $d.server_addr
if ($env:EDR_OVERRIDE_SERVER_ADDR) {
  $saddr = $env:EDR_OVERRIDE_SERVER_ADDR.Trim()
}

$rest = if ($d.rest_base_url) { ([string]$d.rest_base_url).TrimEnd("/") } else { "$api/api/v1" }
$agentApiBase = if ($RelayUrl -and $RelayUrl.Trim()) { $RelayUrl.Trim().TrimEnd("/") } else { $rest }
$serverIssuedCert = ($d.ca_cert -and $d.client_cert)
$bootstrapCaAvailable = [bool]($BootstrapCaCertPath -and (Test-Path -LiteralPath $BootstrapCaCertPath))
$useCertPaths = [bool]($serverIssuedCert -or $bootstrapCaAvailable -or $env:EDR_CA_CERT -or $env:EDR_CLIENT_CERT -or $env:EDR_CLIENT_KEY)
$UseNativeWindowsStore = ((Get-EnrollOs) -eq "windows" -and ($effectiveKeyProvider -eq "cng" -or ($effectiveKeyProvider -eq "tpm" -and -not $TpmKeyUri)))
$EffectiveCaCertPath = if ($useCertPaths) { $CaCertPath } else { "" }
$EffectiveClientCertPath = if ($useCertPaths -and -not $UseNativeWindowsStore) { $ClientCertPath } else { "" }
$EffectiveClientKeyPath = if ($useCertPaths -and $effectiveKeyProvider -eq "pem") { $ClientKeyPath } else { "" }
$EffectiveCertStore = if ($UseNativeWindowsStore) { "LocalMachine\MY" } else { "" }
$EffectiveCertThumbprint = ""

$Http2Enabled = if ($null -ne $d.http2_enabled) { [bool]$d.http2_enabled } else { $false }
$Http2Require = if ($null -ne $d.http2_require) { [bool]$d.http2_require } else { $false }
$ControlHttp2Enabled = if ($null -ne $d.control_http2_enabled) { [bool]$d.control_http2_enabled } else { $Http2Enabled }
$ControlHttp2Require = if ($null -ne $d.control_http2_require) { [bool]$d.control_http2_require } else { $false }
$ControlHttp1Fallback = if ($null -ne $d.control_http1_fallback) { [bool]$d.control_http1_fallback } else { $true }
$ControlStreamEnabled = if ($null -ne $d.control_stream_enabled) { [bool]$d.control_stream_enabled } else { $true }
$LongPollFallback = if ($null -ne $d.long_poll_fallback) { [bool]$d.long_poll_fallback } else { $true }
$ReportEventsV2Enabled = if ($null -ne $d.report_events_v2_enabled) { [bool]$d.report_events_v2_enabled } else { $true }
$DataPlaneEncoding = if ($d.data_plane_encoding) { [string]$d.data_plane_encoding } else { "protobuf" }
$DataPlaneCompression = if ($d.data_plane_compression) { [string]$d.data_plane_compression } else { "identity" }
$ControlDictVersion = if ($d.control_dict_version) { [string]$d.control_dict_version } else { "edr-zstd-dict-v1" }
$ControlSchemaVersion = if ($d.control_schema_version) { [string]$d.control_schema_version } else { "edr-control-schema-v1" }
$ControlProfileID = if ($d.control_profile_id) { [string]$d.control_profile_id } else { "default-http1-protobuf" }
$ConfigSigningKeyID = if ($d.config_signing_key_id) { [string]$d.config_signing_key_id } else { "" }
$ConfigSigningPublicKeyPEM = if ($d.config_signing_public_key_pem) { [string]$d.config_signing_public_key_pem } else { "" }
$ConfigSignatureRequired = if ($null -ne $d.config_signature_required) { [bool]$d.config_signature_required } else { [bool]($ConfigSigningKeyID -and $ConfigSigningPublicKeyPEM) }
$CommandSigningPublicKeyPEM = if ($d.command_signing_public_key_pem) { [string]$d.command_signing_public_key_pem } else { "" }
$RequestSigningEnabled = if ($null -ne $d.request_signing_enabled) { [bool]$d.request_signing_enabled } else { $false }
$RequestSigningRequired = if ($null -ne $d.request_signing_required) { [bool]$d.request_signing_required } else { $false }
$RequestSigningKeyID = if ($d.request_signing_key_id) { [string]$d.request_signing_key_id } else { "" }
$RequestSigningSecret = if ($d.request_signing_secret) { [string]$d.request_signing_secret } else { "" }
if (($RequestSigningEnabled -or $RequestSigningRequired) -and
    (-not $RequestSigningKeyID -or -not $RequestSigningSecret)) {
  Write-Error "enroll response enabled request signing but did not include key_id and secret"
}
$RulesURL = if ($d.rules_url) { [string]$d.rules_url } else { "$agentApiBase/agent/rules.toml" }
$P0BundleURL = if ($d.p0_bundle_url) { [string]$d.p0_bundle_url } else { "$agentApiBase/agent/p0-bundle.enc" }
$SensorInterestURL = if ($d.sensor_interest_url) { [string]$d.sensor_interest_url } else { "$agentApiBase/agent/sensor-interest.json" }
$RuntimePolicyURL = if ($d.runtime_policy_url) { [string]$d.runtime_policy_url } else { "$agentApiBase/agent/runtime-policy.toml" }
$VersionURL = if ($d.version_url) { [string]$d.version_url } else { "$agentApiBase/agent/version/latest" }
$DownloadURL = if ($d.download_url) { [string]$d.download_url } else { "$agentApiBase/agent/download/latest" }

function Escape-Toml([string]$s) {
  return $s.Replace('\', '\\').Replace('"', '\"')
}

function Format-TomlBool([object]$v) {
  if ([bool]$v) { return "true" }
  return "false"
}

function Format-TomlInlinePem([string]$Value) {
  if (-not $Value) { return "" }
  return (($Value -replace "`r`n", "`n") -replace "`r", "`n") -replace "`n", "\n"
}

function Get-EnrollBearerToken([object]$Data) {
  if (-not $Data) { return "" }
  foreach ($name in @("platform_bearer_token", "agent_access_token", "access_token", "rest_bearer_token", "bearer_token")) {
    $prop = $Data.PSObject.Properties[$name]
    if (-not $prop -or $null -eq $prop.Value) { continue }
    $v = ([string]$prop.Value).Trim()
    if (-not $v) { continue }
    $v = [regex]::Replace($v, '(?i)^Bearer\s+', '').Trim()
    if (-not $v) { continue }
    if ($v.Length -gt 480) {
      Write-Error "enroll response bearer token exceeds Agent configuration limit"
    }
    if ([regex]::IsMatch($v, '[\x00-\x20\x7f]')) {
      Write-Error "enroll response bearer token contains whitespace or control characters"
    }
    return $v
  }
  return ""
}

$RestBearerToken = Get-EnrollBearerToken $d

$InstallDirForToml = if ($InstallDir) { $InstallDir } elseif ((Get-EnrollOs) -eq "windows") { "C:\Program Files\FDSecurity" } else { "." }
$TomlQueueDbPath = Join-Path $InstallDirForToml "queue\edr_queue.db"
$TomlEvidenceCachePath = Join-Path $InstallDirForToml "evidence\local_evidence_cache.db"
$TomlLogDir = Join-Path $InstallDirForToml "logs"
$TomlSigningPublicKeyPath = Join-Path $InstallDirForToml "certs\command-signing.pub.pem"
if (-not $HealthReportPath) {
  $HealthReportPath = Join-Path $TomlLogDir "install-bootstrap-report.json"
}

function Write-PemNoBom([string]$Path, [string]$Text) {
  if (-not $Text) { return }
  $dir = Split-Path -Parent $Path
  if ($dir -and -not (Test-Path $dir)) {
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
  }
  [System.IO.File]::WriteAllText(([System.IO.Path]::GetFullPath($Path)), $Text)
}

function Get-Ed25519PublicKeyDer([string]$PemText) {
  if ([string]::IsNullOrWhiteSpace($PemText)) {
    throw "enroll response did not include an Ed25519 command signing public key"
  }
  $match = [regex]::Match(
    $PemText.Trim(),
    '(?s)^-----BEGIN PUBLIC KEY-----\s*(?<body>[A-Za-z0-9+/=\s]+?)\s*-----END PUBLIC KEY-----$'
  )
  if (-not $match.Success) {
    throw "enroll response command signing public key is not a valid PUBLIC KEY PEM"
  }
  try {
    [byte[]]$der = [Convert]::FromBase64String(($match.Groups["body"].Value -replace '\s', ''))
  } catch {
    throw "enroll response command signing public key has invalid base64"
  }

  # RFC 8410 Ed25519 SubjectPublicKeyInfo prefix followed by the 32-byte key.
  [byte[]]$prefix = @(0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00)
  if ($der.Length -ne 44) {
    throw "enroll response command signing public key is not an Ed25519 SubjectPublicKeyInfo"
  }
  for ($i = 0; $i -lt $prefix.Length; $i++) {
    if ($der[$i] -ne $prefix[$i]) {
      throw "enroll response command signing public key algorithm is not Ed25519"
    }
  }
  return ,$der
}

function Get-ByteArraySha256Hex([byte[]]$Value) {
  $sha = [Security.Cryptography.SHA256]::Create()
  try {
    return ([BitConverter]::ToString($sha.ComputeHash($Value))).Replace("-", "").ToLowerInvariant()
  } finally {
    $sha.Dispose()
  }
}

[byte[]]$CommandSigningPublicKeyDer = Get-Ed25519PublicKeyDer $CommandSigningPublicKeyPEM
$CommandSigningPublicKeySha256 = Get-ByteArraySha256Hex $CommandSigningPublicKeyDer

function Get-PemCertificateThumbprint([string]$PemText) {
  if (-not $PemText) { return "" }
  $m = [regex]::Match($PemText, '-----BEGIN CERTIFICATE-----\s*(?<b64>.*?)\s*-----END CERTIFICATE-----', 'Singleline')
  if (-not $m.Success) { return "" }
  $b64 = ($m.Groups['b64'].Value -replace '\s+', '')
  try {
    $bytes = [Convert]::FromBase64String($b64)
    $cert = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @(,$bytes)
    return ($cert.Thumbprint -replace '\s+', '').ToUpperInvariant()
  } catch {
    return ""
  }
}

function Accept-CngIssuedCertificate([string]$CertPath, [string]$Provider) {
  if (($Provider -ne "cng" -and $Provider -ne "tpm") -or ($Provider -eq "tpm" -and $TpmKeyUri)) { return }
  $nativeKey = $null
  $nativeRsa = $null
  $issuedCert = $null
  $certWithKey = $null
  $store = $null
  $compatibility = $script:EDR_INSTALL_COMPATIBILITY
  $nativeBindingAvailable = [bool]($compatibility -and $compatibility.capabilities.copy_with_private_key -and
    $compatibility.capabilities.cng_key -and $compatibility.capabilities.cng_provider -and $compatibility.capabilities.rsa_cng)
  if ($nativeBindingAvailable) {
    try {
    if (-not $script:EDR_CNG_KEY_CONTAINER) {
      throw "CNG key container is unavailable"
    }
    $pem = [System.IO.File]::ReadAllText(([System.IO.Path]::GetFullPath($CertPath)))
    $match = [regex]::Match($pem, '-----BEGIN CERTIFICATE-----\s*(?<b64>.*?)\s*-----END CERTIFICATE-----', 'Singleline')
    if (-not $match.Success) {
      throw "issued client certificate is not valid PEM"
    }
    $certBytes = [Convert]::FromBase64String(($match.Groups['b64'].Value -replace '\s+', ''))
    $issuedCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @(,$certBytes)
    $providerName = if ($script:EDR_CNG_PROVIDER_USED) {
      [string]$script:EDR_CNG_PROVIDER_USED
    } elseif ($Provider -eq "tpm") {
      "Microsoft Platform Crypto Provider"
    } else {
      "Microsoft Software Key Storage Provider"
    }
    $nativeKey = [System.Security.Cryptography.CngKey]::Open(
      [string]$script:EDR_CNG_KEY_CONTAINER,
      (New-Object System.Security.Cryptography.CngProvider($providerName)),
      [System.Security.Cryptography.CngKeyOpenOptions]::MachineKey
    )
    $nativeRsa = New-Object System.Security.Cryptography.RSACng($nativeKey)
    $certWithKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::CopyWithPrivateKey($issuedCert, $nativeRsa)
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("My", "LocalMachine")
    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    $store.Add($certWithKey)
    return
    } catch {
      Write-Warning ("Native CNG certificate binding unavailable; trying bounded certreq compatibility path: " + $_.Exception.Message)
    } finally {
      if ($store) { $store.Close() }
      if ($certWithKey) { $certWithKey.Dispose() }
      if ($issuedCert) { $issuedCert.Dispose() }
      if ($nativeRsa) { $nativeRsa.Dispose() }
      if ($nativeKey) { $nativeKey.Dispose() }
    }
  } else {
    Write-Warning "Certificate binding API is unavailable; selecting certreq compatibility path without native binding"
  }

  $certreq = Get-Command "certreq.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
  if (-not $certreq) {
    throw "Native CNG certificate binding failed and certreq.exe is unavailable"
  }
  Invoke-Checked -Exe $certreq.Source -ArgList @("-accept", "-machine", $CertPath) -TimeoutSeconds 30
}

function Write-InstallDiagnosticReport {
  param([string]$Path, [object]$Report)
  if (-not $Path) { return }
  try {
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path $dir)) {
      New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    $json = $Report | ConvertTo-Json -Depth 8
    [System.IO.File]::WriteAllText(([System.IO.Path]::GetFullPath($Path)), $json)
  } catch {
    Write-Warning ("failed to write install diagnostic report: " + $_)
  }
}

function Test-EndpointCertStore {
  param([string]$StorePath, [string]$Thumbprint)
  if (-not $Thumbprint) {
    return @{ ok = $false; message = "missing client certificate thumbprint" }
  }
  if (-not $StorePath) {
    return @{ ok = $false; message = "missing client certificate store" }
  }
  if ((Get-EnrollOs) -ne "windows") {
    return @{ ok = $true; message = "certificate store check skipped on non-Windows" }
  }
  $store = $StorePath.Replace("\\", "\")
  $psPath = "Cert:\" + $store + "\" + ($Thumbprint -replace '\s+', '')
  try {
    $cert = Get-Item -LiteralPath $psPath -ErrorAction Stop
    if (-not $cert.HasPrivateKey) {
      return @{ ok = $false; message = ("client certificate has no private key in {0}" -f $StorePath) }
    }
    $hasClientAuth = $false
    foreach ($ext in $cert.Extensions) {
      if ($ext -is [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]) {
        foreach ($oid in $ext.EnhancedKeyUsages) {
          if ($oid.Value -eq "1.3.6.1.5.5.7.3.2") {
            $hasClientAuth = $true
          }
        }
      }
    }
    if (-not $hasClientAuth) {
      return @{ ok = $false; message = "client certificate missing Client Authentication EKU" }
    }
    $rsa = $null
    try {
      $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
      if (-not $rsa) {
        return @{ ok = $false; message = "client certificate private key cannot be opened" }
      }
      $probe = [System.Text.Encoding]::UTF8.GetBytes("fdsecurity-install-cert-probe")
      $null = $rsa.SignData($probe, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    } catch {
      return @{ ok = $false; message = ("client certificate private key probe failed: " + $_.Exception.Message) }
    } finally {
      if ($rsa -and ($rsa -is [System.IDisposable])) { $rsa.Dispose() }
    }
    return @{ ok = $true; message = ("found usable client certificate subject={0} not_after={1:o}" -f $cert.Subject, $cert.NotAfter.ToUniversalTime()) }
  } catch {
    return @{ ok = $false; message = ("client certificate not found in {0}: {1}" -f $StorePath, $_) }
  }
}

function Test-HttpBootstrapReachability {
  param([string]$RestBaseUrl)
  if (-not $RestBaseUrl) {
    return @{ ok = $false; message = "missing rest_base_url" }
  }
  try {
    $null = Invoke-WebRequest -Uri $RestBaseUrl -Method Head -UseBasicParsing -TimeoutSec 8 @WebRequestProxyOptions
    return @{ ok = $true; message = "HTTP/TLS reachable" }
  } catch {
    $resp = $null
    try { $resp = $_.Exception.Response } catch { $resp = $null }
    if ($resp) {
      return @{ ok = $true; message = ("HTTP/TLS reachable status={0}" -f [int]$resp.StatusCode) }
    }
    return @{ ok = $false; message = ("HTTP/TLS probe failed: " + $_.Exception.Message) }
  }
}

function Test-AgentBootstrapHealth {
  param(
    [string]$TomlPath,
    [string]$EndpointId,
    [string]$TenantId,
    [string]$RestBaseUrl,
    [string]$CaPath,
    [string]$Provider,
    [string]$CertPath,
    [string]$KeyPath,
    [string]$CertStore,
    [string]$CertThumbprint,
    [string]$ReportPath,
    [bool]$Strict
  )
  $checks = New-Object System.Collections.Generic.List[object]
  function Add-Check([string]$Name, [bool]$Ok, [string]$Message) {
    $checks.Add([ordered]@{ name = $Name; ok = $Ok; message = $Message }) | Out-Null
  }

  Add-Check "agent.toml" (Test-Path -LiteralPath $TomlPath) ("path=" + $TomlPath)
  Add-Check "identity" ([bool]($EndpointId -and $TenantId)) ("endpoint_id=" + $EndpointId + " tenant_id=" + $TenantId)
  if ($CaPath) {
    Add-Check "ca_cert_file" (Test-Path -LiteralPath $CaPath) ("path=" + $CaPath)
  }
  if ($Provider -eq "cng" -or $Provider -eq "tpm") {
    $storeCheck = Test-EndpointCertStore -StorePath $CertStore -Thumbprint $CertThumbprint
    Add-Check "client_cert_store" ([bool]$storeCheck.ok) ([string]$storeCheck.message)
  } elseif ($Provider -eq "pem") {
    if ($CertPath) {
      Add-Check "client_cert_file" (Test-Path -LiteralPath $CertPath) ("path=" + $CertPath)
    }
    if ($KeyPath) {
      $keyOk = Test-PemRsaPrivateKeyReadable -Path $KeyPath
      Add-Check "client_key_file" ([bool]$keyOk) ("path=" + $KeyPath)
    }
  }
  $httpCheck = Test-HttpBootstrapReachability -RestBaseUrl $RestBaseUrl
  Add-Check "rest_tls_reachability" ([bool]$httpCheck.ok) ([string]$httpCheck.message)

  $ok = $true
  foreach ($check in $checks) {
    if (-not $check.ok) {
      $ok = $false
      break
    }
  }
  $report = [ordered]@{
    created_at = (Get-Date).ToUniversalTime().ToString("o")
    status = if ($ok) { "ok" } else { "failed" }
    strict = $Strict
    endpoint_id = $EndpointId
    tenant_id = $TenantId
    rest_base_url = $RestBaseUrl
    key_provider = $Provider
    cng_key_container = if ($script:EDR_CNG_KEY_CONTAINER) { [string]$script:EDR_CNG_KEY_CONTAINER } else { "" }
    client_cert_path = $CertPath
    client_key_path = $KeyPath
    client_cert_store = $CertStore
    client_cert_thumbprint = $CertThumbprint
    checks = $checks
  }
  Write-InstallDiagnosticReport -Path $ReportPath -Report $report
  if ($ok) {
    Write-Host "Install bootstrap health OK (report=$ReportPath)"
    return
  }
  $msg = "Install bootstrap health check failed; report=" + $ReportPath
  if ($Strict) {
    Write-Error $msg
  }
  Write-Warning $msg
}

$issuedCertThumbprint = Get-PemCertificateThumbprint $d.client_cert
if ($UseNativeWindowsStore) {
  $EffectiveCertThumbprint = $issuedCertThumbprint
  $script:EDR_PROVISIONAL_CERT_THUMBPRINT = $EffectiveCertThumbprint
  $script:EDR_PROVISIONAL_CERT_STORE = $EffectiveCertStore
  $candidateStore = (([string]$EffectiveCertStore) -replace '^Cert:\\?', '').Trim([char]0x5c)
  $candidateCertPath = "Cert:\$candidateStore\" + ($EffectiveCertThumbprint -replace '\s+', '')
  $script:EDR_PROVISIONAL_CERT_PREEXISTED = [bool](Test-Path -LiteralPath $candidateCertPath)
}

function Merge-EnrollIntoAgentTomlExample {
  param(
    [Parameter(Mandatory = $true)][string]$ExamplePath,
    [AllowEmptyString()][string]$InstallDir,
    [Parameter(Mandatory = $true)][string]$ServerAddr,
    [Parameter(Mandatory = $true)][string]$EndpointId,
    [Parameter(Mandatory = $true)][string]$TenantId,
    [Parameter(Mandatory = $true)][string]$RestBaseUrl,
    [AllowEmptyString()][string]$RestBearerToken,
    [AllowEmptyString()][string]$CaPath,
    [AllowEmptyString()][string]$CertPath,
    [AllowEmptyString()][string]$KeyPath,
    [Parameter(Mandatory = $true)][string]$KeyProvider,
    [Parameter(Mandatory = $true)][string]$ProxyMode,
    [AllowEmptyString()][string]$ProxyUrl,
    [AllowEmptyString()][string]$RelayUrl,
    [Parameter(Mandatory = $true)][bool]$Http2Enabled,
    [Parameter(Mandatory = $true)][bool]$Http2Require,
    [Parameter(Mandatory = $true)][bool]$ControlStreamEnabled,
    [Parameter(Mandatory = $true)][bool]$LongPollFallback,
    [Parameter(Mandatory = $true)][bool]$ReportEventsV2Enabled,
    [Parameter(Mandatory = $true)][string]$DataPlaneEncoding,
    [Parameter(Mandatory = $true)][string]$DataPlaneCompression,
    [Parameter(Mandatory = $true)][string]$ControlDictVersion,
    [Parameter(Mandatory = $true)][string]$ControlSchemaVersion,
    [Parameter(Mandatory = $true)][string]$ControlProfileID,
    [Parameter(Mandatory = $true)][string]$RulesURL,
    [Parameter(Mandatory = $true)][string]$P0BundleURL,
    [Parameter(Mandatory = $true)][string]$SensorInterestURL,
    [Parameter(Mandatory = $true)][string]$RuntimePolicyURL,
    [Parameter(Mandatory = $true)][string]$VersionURL,
    [Parameter(Mandatory = $true)][string]$DownloadURL,
    [AllowEmptyString()][string]$ConfigSigningKeyID,
    [AllowEmptyString()][string]$ConfigSigningPublicKeyPEM,
    [Parameter(Mandatory = $true)][bool]$ConfigSignatureRequired,
    [Parameter(Mandatory = $true)][bool]$RequestSigningEnabled,
    [AllowEmptyString()][string]$RequestSigningKeyID,
    [AllowEmptyString()][string]$RequestSigningSecret,
    [AllowEmptyString()][string]$CertStore,
    [AllowEmptyString()][string]$CertThumbprint,
    [AllowEmptyString()][string]$Pkcs11ModulePath,
    [AllowEmptyString()][string]$Pkcs11Uri,
    [AllowEmptyString()][string]$TpmUri
  )
  $raw = [System.IO.File]::ReadAllText($ExamplePath)
  if ($raw.StartsWith([char]0xFEFF)) {
    $raw = $raw.Substring(1)
  }
  $AgentApiBase = if ($RelayUrl -and $RelayUrl.Trim()) { $RelayUrl.Trim().TrimEnd("/") } else { $RestBaseUrl.TrimEnd("/") }
  $installRoot = if ($InstallDir -and $InstallDir.Trim()) { $InstallDir.Trim() } elseif ($env:OS -match 'Windows') { 'C:\Program Files\FDSecurity' } else { Split-Path -Parent $ExamplePath }
  $queueDb = Join-Path $installRoot "queue\edr_queue.db"
  $evidenceDb = Join-Path $installRoot "evidence\local_evidence_cache.db"
  $logDir = Join-Path $installRoot "logs"
  $signingPub = Join-Path $installRoot "certs\command-signing.pub.pem"
  $raw = $raw -replace "`r`n", "`n"
  $lines = $raw.Split([string[]]@("`n"), [System.StringSplitOptions]::None)
  $out = New-Object System.Collections.Generic.List[string]
  $i = 0
  while ($i -lt $lines.Count) {
    $line = $lines[$i]
    if ($line -match '^\s*address\s*=') {
      $out.Add(('address              = "{0}"' -f (Escape-Toml $ServerAddr)))
      $i++
      continue
    }
    if ($line -match '^\s*grpc_enabled\s*=') {
      $i++
      continue
    }
    if ($line -match '^\s*grpc_insecure\s*=') {
      $i++
      continue
    }
    if ($line -match '^\s*ca_cert\s*=') {
      $out.Add(('ca_cert              = "{0}"' -f (Escape-Toml $CaPath)))
      $i++
      continue
    }
    if ($line -match '^\s*client_cert\s*=') {
      $out.Add(('client_cert          = "{0}"' -f (Escape-Toml $CertPath)))
      $i++
      continue
    }
    if ($line -match '^\s*client_key\s*=') {
      $out.Add(('client_key           = "{0}"' -f (Escape-Toml $KeyPath)))
      $i++
      continue
    }
    if ($line -match '^\s*client_key_provider\s*=') {
      $out.Add(('client_key_provider  = "{0}"' -f (Escape-Toml $KeyProvider)))
      $i++
      continue
    }
    if ($line -match '^\s*client_cert_store\s*=') {
      $out.Add(('client_cert_store    = "{0}"' -f (Escape-Toml $CertStore)))
      $i++
      continue
    }
    if ($line -match '^\s*client_cert_thumbprint\s*=') {
      $out.Add(('client_cert_thumbprint = "{0}"' -f (Escape-Toml $CertThumbprint)))
      $i++
      continue
    }
    if ($line -match '^\s*pkcs11_module\s*=') {
      $out.Add(('pkcs11_module        = "{0}"' -f (Escape-Toml $Pkcs11ModulePath)))
      $i++
      continue
    }
    if ($line -match '^\s*pkcs11_key_uri\s*=') {
      $out.Add(('pkcs11_key_uri       = "{0}"' -f (Escape-Toml $Pkcs11Uri)))
      $i++
      continue
    }
    if ($line -match '^\s*tpm_key_uri\s*=') {
      $out.Add(('tpm_key_uri          = "{0}"' -f (Escape-Toml $TpmUri)))
      $i++
      continue
    }
    if ($line -match '^\s*endpoint_id\s*=') {
      $out.Add(('endpoint_id          = "{0}"' -f (Escape-Toml $EndpointId)))
      $i++
      continue
    }
    if ($line -match '^\s*tenant_id\s*=') {
      $out.Add(('tenant_id            = "{0}"' -f (Escape-Toml $TenantId)))
      $i++
      continue
    }
    if ($line -match '^\s*max_event_queue_size\s*=') {
      $out.Add(('max_event_queue_size = {0}' -f $TomlMaxEventQueueSize))
      $i++
      continue
    }
    if ($line -match '^\s*(model_dir|static_model_enabled|static_infer_cache_max_entries|static_infer_cache_ttl_s|ave_infer_per_min|behavior_infer_per_min)\s*=') {
      $i++
      continue
    }
    if ($line -match '^\s*queue_db_path\s*=') {
      $out.Add(('queue_db_path        = "{0}"' -f (Escape-Toml $queueDb)))
      $i++
      continue
    }
    if ($line -match '^\s*evidence_cache_path\s*=') {
      $out.Add(('evidence_cache_path  = "{0}"' -f (Escape-Toml $evidenceDb)))
      $i++
      continue
    }
    if ($line -match '^\s*log_dir\s*=') {
      $out.Add(('log_dir              = "{0}"' -f (Escape-Toml $logDir)))
      $i++
      continue
    }
    if ($line -match '^\s*#?\s*signing_public_key_path\s*=') {
      $out.Add(('signing_public_key_path = "{0}"' -f (Escape-Toml $signingPub)))
      $i++
      continue
    }
    if ($line -match '^\s*rest_base_url\s*=') {
      $out.Add(('rest_base_url        = "{0}"' -f (Escape-Toml $RestBaseUrl)))
      $out.Add(('rest_bearer_token    = "{0}"' -f (Escape-Toml $RestBearerToken)))
      $out.Add(('http2_enabled        = {0}' -f (Format-TomlBool $Http2Enabled)))
      $out.Add(('http2_require        = {0}' -f (Format-TomlBool $Http2Require)))
      $out.Add(('control_http2_enabled = {0}' -f (Format-TomlBool $ControlHttp2Enabled)))
      $out.Add(('control_http2_require = {0}' -f (Format-TomlBool $ControlHttp2Require)))
      $out.Add(('control_http1_fallback = {0}' -f (Format-TomlBool $ControlHttp1Fallback)))
      $out.Add(('control_stream_enabled = {0}' -f (Format-TomlBool $ControlStreamEnabled)))
      $out.Add(('long_poll_fallback   = {0}' -f (Format-TomlBool $LongPollFallback)))
      $out.Add(('report_events_v2_enabled = {0}' -f (Format-TomlBool $ReportEventsV2Enabled)))
      $out.Add(('data_plane_encoding  = "{0}"' -f (Escape-Toml $DataPlaneEncoding)))
      $out.Add(('data_plane_compression = "{0}"' -f (Escape-Toml $DataPlaneCompression)))
      $out.Add(('control_dict_version = "{0}"' -f (Escape-Toml $ControlDictVersion)))
      $out.Add(('control_schema_version = "{0}"' -f (Escape-Toml $ControlSchemaVersion)))
      $out.Add(('control_profile_id   = "{0}"' -f (Escape-Toml $ControlProfileID)))
      $out.Add(('proxy_mode           = "{0}"' -f (Escape-Toml $ProxyMode)))
      $out.Add(('proxy_url            = "{0}"' -f (Escape-Toml $ProxyUrl)))
      $out.Add(('relay_url            = "{0}"' -f (Escape-Toml $RelayUrl)))
      $i++
      while ($i -lt $lines.Count -and ($lines[$i] -match '^\s*(rest_bearer_token|http2_enabled|http2_require|control_http2_enabled|control_http2_require|control_http1_fallback|control_stream_enabled|long_poll_fallback|report_events_v2_enabled|data_plane_encoding|data_plane_compression|control_dict_version|control_schema_version|control_profile_id|proxy_mode|proxy_url|relay_url)\s*=')) {
        $i++
      }
      continue
    }
    if ($line -match '^\s*rules_url\s*=') {
      $out.Add(('rules_url            = "{0}"' -f (Escape-Toml $RulesURL)))
      $i++
      continue
    }
    if ($line -match '^\s*p0_bundle_url\s*=') {
      $out.Add(('p0_bundle_url        = "{0}"' -f (Escape-Toml $P0BundleURL)))
      $i++
      continue
    }
    if ($line -match '^\s*sensor_interest_url\s*=') {
      $out.Add(('sensor_interest_url  = "{0}"' -f (Escape-Toml $SensorInterestURL)))
      $i++
      continue
    }
    if ($line -match '^\s*runtime_policy_url\s*=') {
      $out.Add(('runtime_policy_url   = "{0}"' -f (Escape-Toml $RuntimePolicyURL)))
      $i++
      continue
    }
    if ($line -match '^\s*version_url\s*=') {
      $out.Add(('version_url          = "{0}"' -f (Escape-Toml $VersionURL)))
      $i++
      continue
    }
    if ($line -match '^\s*download_url\s*=') {
      $out.Add(('download_url         = "{0}"' -f (Escape-Toml $DownloadURL)))
      $i++
      continue
    }
    if ($line -match '^\s*#\s*\[platform\]\s*$') {
      $out.Add('[platform]')
      $out.Add(('rest_base_url        = "{0}"' -f (Escape-Toml $RestBaseUrl)))
      $out.Add(('rest_bearer_token    = "{0}"' -f (Escape-Toml $RestBearerToken)))
      $out.Add(('http2_enabled        = {0}' -f (Format-TomlBool $Http2Enabled)))
      $out.Add(('http2_require        = {0}' -f (Format-TomlBool $Http2Require)))
      $out.Add(('control_http2_enabled = {0}' -f (Format-TomlBool $ControlHttp2Enabled)))
      $out.Add(('control_http2_require = {0}' -f (Format-TomlBool $ControlHttp2Require)))
      $out.Add(('control_http1_fallback = {0}' -f (Format-TomlBool $ControlHttp1Fallback)))
      $out.Add(('control_stream_enabled = {0}' -f (Format-TomlBool $ControlStreamEnabled)))
      $out.Add(('long_poll_fallback   = {0}' -f (Format-TomlBool $LongPollFallback)))
      $out.Add(('report_events_v2_enabled = {0}' -f (Format-TomlBool $ReportEventsV2Enabled)))
      $out.Add(('data_plane_encoding  = "{0}"' -f (Escape-Toml $DataPlaneEncoding)))
      $out.Add(('data_plane_compression = "{0}"' -f (Escape-Toml $DataPlaneCompression)))
      $out.Add(('control_dict_version = "{0}"' -f (Escape-Toml $ControlDictVersion)))
      $out.Add(('control_schema_version = "{0}"' -f (Escape-Toml $ControlSchemaVersion)))
      $out.Add(('control_profile_id   = "{0}"' -f (Escape-Toml $ControlProfileID)))
      $out.Add(('proxy_mode           = "{0}"' -f (Escape-Toml $ProxyMode)))
      $out.Add(('proxy_url            = "{0}"' -f (Escape-Toml $ProxyUrl)))
      $out.Add(('relay_url            = "{0}"' -f (Escape-Toml $RelayUrl)))
      $i++
      while ($i -lt $lines.Count -and ($lines[$i] -match '^\s*#\s*(rest_(base_url|user_id|bearer_token)|proxy_mode|proxy_url|relay_url)')) {
        $i++
      }
      continue
    }
    $out.Add($line)
    $i++
  }
  $merged = ($out -join "`n")
  if (-not $merged.EndsWith("`n")) {
    $merged += "`n"
  }
  if ($installRoot) {
    $escLog = (Escape-Toml $logDir)
    $merged = [regex]::Replace(
      $merged,
      '(?m)^(\s*log_dir\s+=\s*")[^"]*(")',
      {
        param($m)
        $m.Groups[1].Value + $escLog + $m.Groups[2].Value
      },
      1
    )
  }
  if (($ConfigSigningKeyID -or $ConfigSigningPublicKeyPEM -or $ConfigSignatureRequired) -and $merged -notmatch '(?m)^\s*\[config_signing\]\s*$') {
    $merged += "`n[config_signing]`n"
    $merged += ('signature_required = {0}' -f (Format-TomlBool $ConfigSignatureRequired)) + "`n"
    if ($ConfigSigningKeyID) {
      $merged += ('signing_key_id = "{0}"' -f (Escape-Toml $ConfigSigningKeyID)) + "`n"
    }
    if ($ConfigSigningPublicKeyPEM) {
      $merged += ('public_key_pem = "{0}"' -f (Escape-Toml (Format-TomlInlinePem $ConfigSigningPublicKeyPEM))) + "`n"
    }
  }
  if ($merged -notmatch '(?m)^\s*\[platform\.request_signing\]\s*$') {
    $merged += "`n[platform.request_signing]`n"
    $merged += ('enabled = {0}' -f (Format-TomlBool $RequestSigningEnabled)) + "`n"
    $merged += ('key_id = "{0}"' -f (Escape-Toml $RequestSigningKeyID)) + "`n"
    $merged += ('secret = "{0}"' -f (Escape-Toml $RequestSigningSecret)) + "`n"
  }
  if ($merged -notmatch '(?m)^\s*\[health_monitor\]\s*$') {
    $merged += "`n[health_monitor]`n"
    $merged += "enabled              = true`n"
    $merged += 'profile              = "basic"' + "`n"
    $merged += "interval_s           = 60`n"
    $merged += "expires_at_unix_ms   = 0`n"
    $merged += 'request_id           = "bootstrap-runtime"' + "`n"
  }
  return $merged
}

function Remove-TomlCommentSuffix([string]$Line) {
  $inQuote = $false
  $escape = $false
  for ($i = 0; $i -lt $Line.Length; $i++) {
    $ch = $Line[$i]
    if ($escape) {
      $escape = $false
      continue
    }
    if ($ch -eq '\') {
      $escape = $true
      continue
    }
    if ($ch -eq '"') {
      $inQuote = -not $inQuote
      continue
    }
    if (-not $inQuote -and $ch -eq '#') {
      return $Line.Substring(0, $i).TrimEnd()
    }
  }
  return $Line.TrimEnd()
}

function Optimize-GeneratedToml([string]$TomlText) {
  $raw = $TomlText -replace "`r`n", "`n"
  $lines = $raw.Split([string[]]@("`n"), [System.StringSplitOptions]::None)
  $out = New-Object System.Collections.Generic.List[string]
  $out.Add("# Generated by FDSecurity installer. Keep endpoint-specific values in this file.") | Out-Null
  $out.Add("") | Out-Null
  $blank = $true
  foreach ($line in $lines) {
    $trim = $line.Trim()
    if ($trim.StartsWith("#")) {
      continue
    }
    if ($trim -eq "") {
      if (-not $blank -and $out.Count -gt 0) {
        $out.Add("") | Out-Null
        $blank = $true
      }
      continue
    }
    $clean = Remove-TomlCommentSuffix $line
    $cleanTrim = $clean.Trim()
    if ($cleanTrim -eq "") {
      if (-not $blank -and $out.Count -gt 0) {
        $out.Add("") | Out-Null
        $blank = $true
      }
      continue
    }
    if (-not $cleanTrim.Contains("=") -and -not ($cleanTrim.StartsWith("[") -and $cleanTrim.EndsWith("]"))) {
      continue
    }
    $out.Add($clean) | Out-Null
    $blank = $false
  }
  while ($out.Count -gt 1 -and $out[$out.Count - 1] -eq "") {
    $out.RemoveAt($out.Count - 1)
  }
  return (($out -join "`n") + "`n")
}

function Get-SafeTomlSnippet([string]$Value) {
  if ($null -eq $Value) { return "" }
  $v = ($Value -replace '\s+', ' ').Trim()
  if ($v.Length -gt 120) {
    $v = $v.Substring(0, 120) + "..."
  }
  return $v
}

function Get-AgentTomlSanityIssue([string]$TomlText) {
  if ([string]::IsNullOrWhiteSpace($TomlText)) {
    return "empty TOML"
  }
  $raw = $TomlText -replace "`r`n", "`n"
  $lines = $raw.Split([string[]]@("`n"), [System.StringSplitOptions]::None)
  for ($idx = 0; $idx -lt $lines.Count; $idx++) {
    $t = $lines[$idx].Trim()
    if ($idx -eq 0 -and $t.Length -gt 0 -and [int][char]$t[0] -eq 0xFEFF) {
      $t = $t.Substring(1).TrimStart()
    }
    if ($t -eq "" -or $t.StartsWith("#")) {
      continue
    }
    if ($t.StartsWith("[") -and $t.EndsWith("]")) {
      continue
    }
    if (-not $t.Contains("=")) {
      return ("line {0}: missing = near '{1}'" -f ($idx + 1), (Get-SafeTomlSnippet $t))
    }
  }
  return ""
}

function Redact-AgentTomlLine([string]$Line) {
  if ($null -eq $Line) { return "" }
  if ($Line -match '(?i)^(\s*(endpoint_id|tenant_id|client_key|client_cert|client_cert_thumbprint|rest_bearer_token|secret|signing_public_key_path|signing_public_key_pem|public_key_pem)\s*=\s*).*$') {
    return ($Matches[1] + '"<redacted>"')
  }
  return $Line
}

function Write-AgentTomlSanityDiagnostic {
  param(
    [string]$TomlText,
    [string]$Issue,
    [string]$OutputPath,
    [string]$ReportPath
  )
  try {
    $dir = ""
    if ($ReportPath) {
      $dir = Split-Path -Parent ([System.IO.Path]::GetFullPath($ReportPath))
    }
    if (-not $dir -and $OutputPath) {
      $dir = Join-Path (Split-Path -Parent ([System.IO.Path]::GetFullPath($OutputPath))) "diagnostics"
    }
    if (-not $dir) { return }
    if (-not (Test-Path -LiteralPath $dir)) {
      New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    $raw = if ($TomlText) { $TomlText -replace "`r`n", "`n" } else { "" }
    $lines = $raw.Split([string[]]@("`n"), [System.StringSplitOptions]::None)
    $out = New-Object System.Collections.Generic.List[string]
    $out.Add(("issue={0}" -f $Issue)) | Out-Null
    $out.Add(("output={0}" -f $OutputPath)) | Out-Null
    $out.Add("head_redacted:") | Out-Null
    $limit = [Math]::Min(80, $lines.Count)
    for ($i = 0; $i -lt $limit; $i++) {
      $out.Add(("{0,4}: {1}" -f ($i + 1), (Redact-AgentTomlLine $lines[$i]))) | Out-Null
    }
    $utf8NoBom = New-Object System.Text.UTF8Encoding -ArgumentList $false
    [System.IO.File]::WriteAllText((Join-Path $dir "agent-toml-sanity.redacted.txt"), (($out -join "`r`n") + "`r`n"), $utf8NoBom)
  } catch {
    Write-Warning ("failed to write agent.toml sanity diagnostic: " + $_)
  }
}

$tomlMinimal = @"
# Generated by FDSecurity installer. Keep endpoint-specific values in this file.

[server]
address              = "$(Escape-Toml $saddr)"
ca_cert              = "$(Escape-Toml $EffectiveCaCertPath)"
client_cert          = "$(Escape-Toml $EffectiveClientCertPath)"
client_key           = "$(Escape-Toml $EffectiveClientKeyPath)"
client_key_provider  = "$(Escape-Toml $effectiveKeyProvider)"
client_cert_store    = "$(Escape-Toml $EffectiveCertStore)"
client_cert_thumbprint = "$(Escape-Toml $EffectiveCertThumbprint)"
pkcs11_module        = "$(Escape-Toml $Pkcs11Module)"
pkcs11_key_uri       = "$(Escape-Toml $Pkcs11KeyUri)"
tpm_key_uri          = "$(Escape-Toml $TpmKeyUri)"
connect_timeout_s    = 10
keepalive_interval_s = 30

[agent]
endpoint_id          = "$(Escape-Toml $d.endpoint_id)"
tenant_id            = "$(Escape-Toml $d.tenant_id)"

[platform]
rest_base_url        = "$(Escape-Toml $rest)"
rest_bearer_token    = "$(Escape-Toml $RestBearerToken)"
http2_enabled        = $(Format-TomlBool $Http2Enabled)
http2_require        = $(Format-TomlBool $Http2Require)
control_http2_enabled = $(Format-TomlBool $ControlHttp2Enabled)
control_http2_require = $(Format-TomlBool $ControlHttp2Require)
control_http1_fallback = $(Format-TomlBool $ControlHttp1Fallback)
control_stream_enabled = $(Format-TomlBool $ControlStreamEnabled)
long_poll_fallback   = $(Format-TomlBool $LongPollFallback)
report_events_v2_enabled = $(Format-TomlBool $ReportEventsV2Enabled)
data_plane_encoding  = "$(Escape-Toml $DataPlaneEncoding)"
data_plane_compression = "$(Escape-Toml $DataPlaneCompression)"
control_dict_version = "$(Escape-Toml $ControlDictVersion)"
control_schema_version = "$(Escape-Toml $ControlSchemaVersion)"
control_profile_id   = "$(Escape-Toml $ControlProfileID)"
proxy_mode           = "$(Escape-Toml $ProxyMode)"
proxy_url            = "$(Escape-Toml $ProxyUrl)"
relay_url            = "$(Escape-Toml $RelayUrl)"

[platform.request_signing]
enabled              = $(Format-TomlBool $RequestSigningEnabled)
key_id               = "$(Escape-Toml $RequestSigningKeyID)"
secret               = "$(Escape-Toml $RequestSigningSecret)"

[collection]
etw_enabled          = true
ebpf_enabled         = false
poll_interval_s      = 1
max_event_queue_size = $TomlMaxEventQueueSize
adaptive_enabled = true
adaptive_boost_seconds = 180
adaptive_min_severity = 3
etw_dns_client_provider = false
etw_powershell_provider = true
etw_security_audit_provider = true
etw_wmi_provider = false
etw_tcpip_provider = false
etw_firewall_provider = false

[preprocessing]
dedup_window_s       = 60
high_freq_threshold  = 40
sampling_rate_whitelist = 0.03
rules_version        = "edr-dynamic-rules-v1"

[ave]
scan_threads         = 1
max_file_size_mb     = 256
sensitivity          = "MEDIUM"
behavior_monitor_enabled = false

[forensic_auto]
enabled              = false
cooldown_s           = 30
trigger_on_p0        = true
collect_process_tree = true

[health_monitor]
enabled              = true
profile              = "basic"
interval_s           = 60
expires_at_unix_ms   = 0
request_id           = "bootstrap-runtime"

[upload]
batch_max_events     = 200
batch_max_size_mb    = 2
batch_timeout_s      = 2
max_upload_mbps      = 4

[offline]
queue_db_path        = "$(Escape-Toml $TomlQueueDbPath)"
max_queue_size_mb    = 512
retention_hours      = 72
evidence_cache_path  = "$(Escape-Toml $TomlEvidenceCachePath)"
evidence_cache_max_size_mb = 512
evidence_cache_retention_hours = 72

[resource_limit]
cpu_limit_percent    = 10
memory_limit_mb      = 512
emergency_cpu_limit  = 25

[logging]
level                = "info"
log_dir              = "$(Escape-Toml $TomlLogDir)"
max_log_size_mb      = 50
max_log_files        = 5

[command]
allow_dangerous      = false
allow_lifecycle_maintenance = true
allow_rtq_readonly   = true
signing_public_key_path = "$(Escape-Toml $TomlSigningPublicKeyPath)"

[config_signing]
signature_required = $(Format-TomlBool $ConfigSignatureRequired)
signing_key_id = "$(Escape-Toml $ConfigSigningKeyID)"
public_key_pem = "$(Escape-Toml (Format-TomlInlinePem $ConfigSigningPublicKeyPEM))"

[self_protect]
anti_debug           = true
job_object_windows   = true
watchdog_log_interval_s = 60
event_bus_pressure_warn_pct = 80

[attack_surface]
# 默认开启：安装/注册后 Agent 会执行一次 agent_start/agent_enrolled 攻击面检测，之后支持控制台按需刷新。
enabled              = true

[detection]
auto_profile         = true
shellcode_mode       = 0
webshell_mode        = 0
pmfe_mode            = 2

[pmfe]
idle_scan_enabled    = false
idle_scan_interval_min = 15
idle_scan_max_procs  = 8
idle_cpu_threshold   = 15.0
idle_skip_on_battery = true

[shellcode_detector]
enabled              = false

[webshell_detector]
enabled              = false

[remote]
rules_url            = "$(Escape-Toml $RulesURL)"
p0_bundle_url        = "$(Escape-Toml $P0BundleURL)"
sensor_interest_url  = "$(Escape-Toml $SensorInterestURL)"
runtime_policy_url   = "$(Escape-Toml $RuntimePolicyURL)"
poll_interval_s      = 1800
version_url          = "$(Escape-Toml $VersionURL)"
download_url         = "$(Escape-Toml $DownloadURL)"
auto_update          = false

"@

if ($Template) {
  $examplePath = $Template
} else {
  $examplePath = Join-Path $PSScriptRoot "agent.toml.example"
  $repoTemplate = Join-Path (Split-Path -Parent $PSScriptRoot) "config\agent_windows_production.example.toml"
  $bundledTemplate = Join-Path $PSScriptRoot "config\agent_windows_production.example.toml"
  if ((Get-EnrollOs) -eq "windows") {
    if (Test-Path -LiteralPath $bundledTemplate) {
      $examplePath = $bundledTemplate
    } elseif (Test-Path -LiteralPath $repoTemplate) {
      $examplePath = $repoTemplate
    }
  } elseif (-not (Test-Path -LiteralPath $examplePath)) {
    if (Test-Path -LiteralPath $repoTemplate) {
      $examplePath = $repoTemplate
    }
  }
}
$toml = $tomlMinimal
$tomlSource = "minimal"
if ($UseTemplateToml -and -not $MinimalTomlOnly -and (Test-Path -LiteralPath $examplePath)) {
  try {
    $toml = Merge-EnrollIntoAgentTomlExample -ExamplePath $examplePath -InstallDir $InstallDirForToml -ServerAddr $saddr `
      -EndpointId $d.endpoint_id -TenantId $d.tenant_id -RestBaseUrl $rest -RestBearerToken $RestBearerToken `
      -CaPath $EffectiveCaCertPath -CertPath $EffectiveClientCertPath -KeyPath $EffectiveClientKeyPath `
      -KeyProvider $effectiveKeyProvider -ProxyMode $ProxyMode -ProxyUrl $ProxyUrl -RelayUrl $RelayUrl `
      -Http2Enabled $Http2Enabled -Http2Require $Http2Require `
      -ControlStreamEnabled $ControlStreamEnabled -LongPollFallback $LongPollFallback `
      -ReportEventsV2Enabled $ReportEventsV2Enabled -DataPlaneEncoding $DataPlaneEncoding `
      -DataPlaneCompression $DataPlaneCompression -ControlDictVersion $ControlDictVersion `
      -ControlSchemaVersion $ControlSchemaVersion -ControlProfileID $ControlProfileID `
      -RulesURL $RulesURL -P0BundleURL $P0BundleURL -SensorInterestURL $SensorInterestURL `
      -RuntimePolicyURL $RuntimePolicyURL -VersionURL $VersionURL -DownloadURL $DownloadURL `
      -ConfigSigningKeyID $ConfigSigningKeyID -ConfigSigningPublicKeyPEM $ConfigSigningPublicKeyPEM `
      -ConfigSignatureRequired $ConfigSignatureRequired `
      -RequestSigningEnabled $RequestSigningEnabled -RequestSigningKeyID $RequestSigningKeyID `
      -RequestSigningSecret $RequestSigningSecret `
      -CertStore $EffectiveCertStore -CertThumbprint $EffectiveCertThumbprint `
      -Pkcs11ModulePath $Pkcs11Module -Pkcs11Uri $Pkcs11KeyUri -TpmUri $TpmKeyUri
    $tomlSource = "template:$examplePath"
  } catch {
    Write-Warning ("Merge with agent.toml.example failed, writing minimal TOML only: " + $_)
    $toml = $tomlMinimal
    $tomlSource = "minimal-merge-error"
  }
}
if (-not $KeepTemplateComments) {
  $toml = Optimize-GeneratedToml $toml
}

$tomlIssue = Get-AgentTomlSanityIssue $toml
if ($tomlIssue) {
  Write-AgentTomlSanityDiagnostic -TomlText $toml -Issue ("source={0}; {1}" -f $tomlSource, $tomlIssue) -OutputPath $Output -ReportPath $HealthReportPath
  if ($tomlSource -like "template:*") {
    Write-Warning ("Generated agent.toml from template failed sanity check ({0}); falling back to minimal TOML" -f $tomlIssue)
    $toml = $tomlMinimal
    $tomlSource = "minimal-fallback"
    if (-not $KeepTemplateComments) {
      $toml = Optimize-GeneratedToml $toml
    }
    $tomlIssue = Get-AgentTomlSanityIssue $toml
  }
}
if ($tomlIssue) {
  Write-AgentTomlSanityDiagnostic -TomlText $toml -Issue ("source={0}; {1}" -f $tomlSource, $tomlIssue) -OutputPath $Output -ReportPath $HealthReportPath
  Write-Error ("Generated agent.toml failed sanity check ({0}); source={1}" -f $tomlIssue, $tomlSource)
}

if ($DryRun) {
  $displayToml = [regex]::Replace($toml, '(?m)^(\s*rest_bearer_token\s*=\s*")[^"]*(")', '$1<redacted>$2')
  Write-Output $displayToml
  Remove-ProvisionalEnrollmentMaterial -Reason "dry_run"
  exit 0
}

if ($d.ca_cert -or $d.client_cert) {
  if (-not ($d.ca_cert -and $d.client_cert)) {
    Write-Error "enroll response returned an incomplete mTLS certificate bundle"
  }
  Write-PemNoBom -Path $CaCertPath -Text $d.ca_cert
  Write-PemNoBom -Path $ClientCertPath -Text $d.client_cert
  # certreq validates the issued chain against LocalMachine\Root. The enrollment
  # CA may be trusted automatically only when its response arrived over bootstrap-verified HTTPS.
  $enrollmentTransportAuthenticated = $false
  try {
    $enrollmentUri = [System.Uri]$uri
    $enrollmentTransportAuthenticated = ($script:EDR_BOOTSTRAP_TLS_VALIDATION_ENABLED -and $enrollmentUri.Scheme -eq "https" -and $env:EDR_INSECURE_TLS -ne "1")
  } catch {
  }
  $shouldInstallEnrollmentCaTrust = [bool]$TrustCa -or ($UseNativeWindowsStore -and $enrollmentTransportAuthenticated)
  if ($shouldInstallEnrollmentCaTrust) {
    Install-BootstrapCaTrust -Path $CaCertPath
  } elseif ($UseNativeWindowsStore) {
    throw "Windows certificate-store acceptance requires a trusted issuing CA; use verified HTTPS bootstrap or set -TrustCa explicitly"
  }
  Accept-CngIssuedCertificate -CertPath $ClientCertPath -Provider $effectiveKeyProvider
  if ($UseNativeWindowsStore) {
    $storeCheck = Test-EndpointCertStore -StorePath $EffectiveCertStore -Thumbprint $EffectiveCertThumbprint
    if (-not $storeCheck.ok) {
      throw ("client certificate was not accepted into Windows certificate store: " + [string]$storeCheck.message)
    }
  }
}
if ($d.client_key) {
  Write-Warning "enroll response included deprecated client_key; ignoring it because the endpoint private key is generated locally"
}
if (-not $d.ca_cert -and $bootstrapCaAvailable) {
  Write-PemNoBom -Path $CaCertPath -Text ([System.IO.File]::ReadAllText(([System.IO.Path]::GetFullPath($BootstrapCaCertPath))))
}
Write-PemNoBom -Path $TomlSigningPublicKeyPath -Text $CommandSigningPublicKeyPEM
$writtenCommandSigningPublicKeyPEM = [System.IO.File]::ReadAllText(
  [System.IO.Path]::GetFullPath($TomlSigningPublicKeyPath)
)
[byte[]]$WrittenCommandSigningPublicKeyDer = Get-Ed25519PublicKeyDer $writtenCommandSigningPublicKeyPEM
$WrittenCommandSigningPublicKeySha256 = Get-ByteArraySha256Hex $WrittenCommandSigningPublicKeyDer
if ($WrittenCommandSigningPublicKeySha256 -ne $CommandSigningPublicKeySha256) {
  throw "command signing public key integrity check failed after writing $TomlSigningPublicKeyPath"
}

$dir = Split-Path -Parent $Output
if ($dir -and -not (Test-Path $dir)) {
  New-Item -ItemType Directory -Path $dir -Force | Out-Null
}
$outFile = [System.IO.Path]::GetFullPath($Output)
Write-Utf8NoBomFileWithRetry -Path $outFile -Text $toml
$generatedTomlIssue = Test-ExistingAgentTomlWithAgent -InstallRoot $InstallDirForToml -ConfigPath $outFile
if ($generatedTomlIssue) {
  Write-AgentTomlSanityDiagnostic -TomlText $toml -Issue ("source={0}; {1}" -f $tomlSource, $generatedTomlIssue) -OutputPath $Output -ReportPath $HealthReportPath
  if ($tomlSource -like "template:*") {
    Write-Warning ("Agent rejected template-generated agent.toml ({0}); falling back to minimal TOML." -f $generatedTomlIssue)
    $toml = $tomlMinimal
    $tomlSource = "minimal-parser-fallback"
    if (-not $KeepTemplateComments) {
      $toml = Optimize-GeneratedToml $toml
    }
    Write-Utf8NoBomFileWithRetry -Path $outFile -Text $toml
    $generatedTomlIssue = Test-ExistingAgentTomlWithAgent -InstallRoot $InstallDirForToml -ConfigPath $outFile
  }
}
if ($generatedTomlIssue) {
  Write-AgentTomlSanityDiagnostic -TomlText $toml -Issue ("source={0}; {1}" -f $tomlSource, $generatedTomlIssue) -OutputPath $Output -ReportPath $HealthReportPath
  Write-Error ("Generated agent.toml failed Agent config validation ({0}); source={1}" -f $generatedTomlIssue, $tomlSource)
}
Repair-AgentTomlAcl -Path $outFile
Repair-InstallRuntimeAcls -InstallRoot $InstallDirForToml
Install-HeadlessUninstaller -InstallRoot $InstallDirForToml
Repair-AgentTomlAcl -Path $outFile
Write-Host "Wrote $outFile (endpoint_id=$($d.endpoint_id) tenant_id=$($d.tenant_id) server.address=$saddr)"

if (-not $SkipHealthCheck) {
  Test-AgentBootstrapHealth -TomlPath $outFile -EndpointId $d.endpoint_id -TenantId $d.tenant_id `
    -RestBaseUrl $rest -CaPath $EffectiveCaCertPath -Provider $effectiveKeyProvider `
    -CertPath $EffectiveClientCertPath -KeyPath $EffectiveClientKeyPath `
    -CertStore $EffectiveCertStore -CertThumbprint $EffectiveCertThumbprint `
    -ReportPath $HealthReportPath -Strict ([bool]$StrictHealthCheck)
}

if ($ConfigureSensorPolicy) {
  Enable-WindowsSensorPolicy
}

if ($InstallAutorun) {
  Install-AgentAutorun
}
$script:EDR_INSTALL_TRANSACTION_COMMITTED = $true
$script:EDR_INSTALL_TRANSACTION_ACTIVE = $false
} catch {
  $failure = $_
  Remove-ProvisionalEnrollmentMaterial -Reason ([string]$failure.Exception.Message)
  throw $failure
}
