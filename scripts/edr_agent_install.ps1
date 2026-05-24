#Requires -Version 5.1
<#
.SYNOPSIS
  独立运行：调用 POST /api/v1/enroll，生成 agent.toml（不依赖 Python）。

.DESCRIPTION
  环境变量（必填）：
    EDR_API_BASE      平台 REST 根，如 http://127.0.0.1:8080
    EDR_ENROLL_TOKEN  注册 Token

  可选：
    EDR_OUTPUT              输出路径，Windows 默认 C:\Program Files\EDR Agent\agent.toml
    EDR_AGENT_VERSION       默认 0.3.0
    EDR_OVERRIDE_SERVER_ADDR
    EDR_AGENT_TEMPLATE      默认优先使用 config\agent_windows_production.example.toml
    EDR_CA_CERT / EDR_CLIENT_CERT / EDR_CLIENT_KEY / EDR_CLIENT_CSR
    EDR_KEY_PROVIDER=pem|cng|tpm|pkcs11
    EDR_CNG_PROVIDER_NAME        默认 cng=Microsoft Software Key Storage Provider，tpm=Microsoft Platform Crypto Provider
    EDR_CNG_KEY_NAME             默认 EDR-Agent-$COMPUTERNAME
    EDR_PKCS11_KEY_URI           PKCS#11 key URI；需本机 openssl engine/provider 可用
    EDR_TPM_KEY_URI              TPM/OpenSSL provider key URI；PowerShell 默认走 Windows Platform Crypto Provider
    EDR_INSECURE_TLS=1      [System.Net.ServicePointManager]::ServerCertificateValidationCallback（仅调试）

.EXAMPLE
  $env:EDR_API_BASE="http://127.0.0.1:8080"
  $env:EDR_ENROLL_TOKEN="xxxxxxxx"
  .\edr_agent_install.ps1
#>
param(
  [string]$Output = $(if ($env:EDR_OUTPUT) { $env:EDR_OUTPUT } else { "C:\Program Files\EDR Agent\agent.toml" }),
  [string]$Template = $(if ($env:EDR_AGENT_TEMPLATE) { $env:EDR_AGENT_TEMPLATE } else { "" }),
  [string]$CaCertPath = $(if ($env:EDR_CA_CERT) { $env:EDR_CA_CERT } else { "C:\Program Files\EDR Agent\certs\ca.pem" }),
  [string]$ClientCertPath = $(if ($env:EDR_CLIENT_CERT) { $env:EDR_CLIENT_CERT } else { "C:\Program Files\EDR Agent\certs\client.pem" }),
  [string]$ClientKeyPath = $(if ($env:EDR_CLIENT_KEY) { $env:EDR_CLIENT_KEY } else { "C:\Program Files\EDR Agent\certs\client-key.pem" }),
  [string]$ClientCsrPath = $(if ($env:EDR_CLIENT_CSR) { $env:EDR_CLIENT_CSR } else { "C:\Program Files\EDR Agent\certs\client.csr.pem" }),
  [string]$KeyProvider = $(if ($env:EDR_KEY_PROVIDER) { $env:EDR_KEY_PROVIDER } else { "pem" }),
  [string]$CngProviderName = $(if ($env:EDR_CNG_PROVIDER_NAME) { $env:EDR_CNG_PROVIDER_NAME } else { "" }),
  [string]$CngKeyName = $(if ($env:EDR_CNG_KEY_NAME) { $env:EDR_CNG_KEY_NAME } else { "" }),
  [string]$Pkcs11KeyUri = $(if ($env:EDR_PKCS11_KEY_URI) { $env:EDR_PKCS11_KEY_URI } else { "" }),
  [string]$Pkcs11Module = $(if ($env:EDR_PKCS11_MODULE) { $env:EDR_PKCS11_MODULE } else { "" }),
  [string]$TpmKeyUri = $(if ($env:EDR_TPM_KEY_URI) { $env:EDR_TPM_KEY_URI } else { "" }),
  [switch]$DryRun,
  # 若同目录存在 agent.toml.example，注册成功后合并为「完整 agent.toml」（保留 collection/ave 等默认），仅覆盖 [server]/[agent]/[platform]。
  [switch]$MinimalTomlOnly
)

$ErrorActionPreference = "Stop"

function Get-EnrollOs {
  if ($env:OS -match "Windows_NT" -or $env:OS -like "*Windows*") { return "windows" }
  if ($IsMacOS) { return "darwin" }
  return "linux"
}

$api = $env:EDR_API_BASE
$tok = $env:EDR_ENROLL_TOKEN
if (-not $api -or -not $tok) {
  Write-Error "Set EDR_API_BASE and EDR_ENROLL_TOKEN"
}

$api = $api.TrimEnd("/")
$uri = "$api/api/v1/enroll"
$av = if ($env:EDR_AGENT_VERSION) { $env:EDR_AGENT_VERSION } else { "0.3.0" }

function Resolve-OpenSSL {
  foreach ($name in @("openssl.exe", "openssl")) {
    $cmd = Get-Command $name -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($cmd) { return $cmd.Source }
  }
  Write-Error "openssl is required to generate the endpoint private key and CSR"
}

function Invoke-Checked {
  param([string]$Exe, [string[]]$Args)
  & $Exe @Args
  if ($LASTEXITCODE -ne 0) {
    Write-Error ("command failed: " + $Exe + " " + ($Args -join " "))
  }
}

function Normalize-KeyProvider([string]$Provider) {
  $p = if ($Provider) { $Provider.Trim().ToLowerInvariant() } else { "pem" }
  if ($p -eq "file") { return "pem" }
  if (@("pem", "cng", "tpm", "pkcs11") -notcontains $p) {
    Write-Error "unsupported EDR_KEY_PROVIDER=$Provider (expected pem|cng|tpm|pkcs11)"
  }
  return $p
}

function Ensure-CngAgentCSR {
  param([string]$CsrPath, [string]$SubjectCN, [string]$ProviderName, [string]$KeyName)
  $certreq = Get-Command "certreq.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
  if (-not $certreq) {
    Write-Error "certreq.exe is required for Windows CNG/TPM non-exportable key CSR"
  }
  $csrDir = Split-Path -Parent $CsrPath
  if ($csrDir -and -not (Test-Path $csrDir)) {
    New-Item -ItemType Directory -Path $csrDir -Force | Out-Null
  }
  $safeCN = if ($SubjectCN) { $SubjectCN.Replace("/", "-").Replace("\", "-").Replace('"', '') } else { "edr-agent" }
  $safeKeyName = if ($KeyName) { $KeyName } else { "EDR-Agent-$safeCN" }
  $infPath = [System.IO.Path]::ChangeExtension($CsrPath, ".inf")
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
Exportable = FALSE
KeyExportPolicy = 0
KeySpec = 1
RequestType = PKCS10
Silent = TRUE

[EnhancedKeyUsageExtension]
OID=1.3.6.1.5.5.7.3.2
"@
  $utf8NoBom = New-Object System.Text.UTF8Encoding $false
  [System.IO.File]::WriteAllText(([System.IO.Path]::GetFullPath($infPath)), $inf, $utf8NoBom)
  Invoke-Checked -Exe $certreq.Source -Args @("-new", "-machine", $infPath, $CsrPath)
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
      Invoke-Checked -Exe $openssl -Args $args
    } else {
      Invoke-Checked -Exe $openssl -Args @("req", "-new", "-engine", "pkcs11", "-keyform", "engine", "-key", $KeyUri, "-out", $CsrPath, "-subj", "/CN=$safeCN")
    }
  } elseif ($Provider -eq "tpm") {
    if (-not $KeyUri) { Write-Error "EDR_TPM_KEY_URI is required when TPM OpenSSL provider mode is used" }
    $tpmProvider = if ($env:EDR_OPENSSL_TPM_PROVIDER) { $env:EDR_OPENSSL_TPM_PROVIDER } else { "tpm2" }
    Invoke-Checked -Exe $openssl -Args @("req", "-new", "-provider", "default", "-provider", $tpmProvider, "-key", $KeyUri, "-out", $CsrPath, "-subj", "/CN=$safeCN")
  }
  return [System.IO.File]::ReadAllText(([System.IO.Path]::GetFullPath($CsrPath)))
}

function Ensure-AgentCSR {
  param([string]$KeyPath, [string]$CsrPath, [string]$SubjectCN, [string]$Provider)
  $Provider = Normalize-KeyProvider $Provider
  if ($Provider -eq "cng" -or ($Provider -eq "tpm" -and -not $TpmKeyUri)) {
    $pn = $CngProviderName
    if (-not $pn) {
      $pn = if ($Provider -eq "tpm") { "Microsoft Platform Crypto Provider" } else { "Microsoft Software Key Storage Provider" }
    }
    return Ensure-CngAgentCSR -CsrPath $CsrPath -SubjectCN $SubjectCN -ProviderName $pn -KeyName $CngKeyName
  }
  if ($Provider -eq "pkcs11" -or $Provider -eq "tpm") {
    $uri = if ($Provider -eq "pkcs11") { $Pkcs11KeyUri } else { $TpmKeyUri }
    return Ensure-ExternalKeyCSR -CsrPath $CsrPath -SubjectCN $SubjectCN -Provider $Provider -KeyUri $uri -ModulePath $Pkcs11Module
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
    Invoke-Checked -Exe $openssl -Args @("genrsa", "-out", $KeyPath, "3072")
  }
  $safeCN = if ($SubjectCN) { $SubjectCN.Replace("/", "-").Replace("\", "-") } else { "edr-agent" }
  Invoke-Checked -Exe $openssl -Args @("req", "-new", "-key", $KeyPath, "-out", $CsrPath, "-subj", "/CN=$safeCN")
  return [System.IO.File]::ReadAllText(([System.IO.Path]::GetFullPath($CsrPath)))
}

$keyProviderNorm = Normalize-KeyProvider $KeyProvider
$csrPem = Ensure-AgentCSR -KeyPath $ClientKeyPath -CsrPath $ClientCsrPath -SubjectCN $env:COMPUTERNAME -Provider $keyProviderNorm

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

if ($env:EDR_INSECURE_TLS -eq "1") {
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

try {
  $resp = Invoke-RestMethod -Uri $uri -Method Post -ContentType "application/json; charset=utf-8" -Body $json
} catch {
  Write-Error ("enroll failed: " + $_)
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

$rest = "$api/api/v1"
$serverIssuedCert = ($d.ca_cert -and $d.client_cert)
$useCertPaths = [bool]($serverIssuedCert -or $env:EDR_CA_CERT -or $env:EDR_CLIENT_CERT -or $env:EDR_CLIENT_KEY)
$EffectiveCaCertPath = if ($useCertPaths) { $CaCertPath } else { "" }
$EffectiveClientCertPath = if ($useCertPaths) { $ClientCertPath } else { "" }
$EffectiveClientKeyPath = if ($useCertPaths -and $keyProviderNorm -eq "pem") { $ClientKeyPath } else { "" }
$EffectiveCertStore = if ($keyProviderNorm -eq "cng" -or $keyProviderNorm -eq "tpm") { "LocalMachine\\My" } else { "" }
$EffectiveCertThumbprint = ""

function Escape-Toml([string]$s) {
  return $s.Replace('\', '\\').Replace('"', '\"')
}

function Write-PemNoBom([string]$Path, [string]$Text) {
  if (-not $Text) { return }
  $dir = Split-Path -Parent $Path
  if ($dir -and -not (Test-Path $dir)) {
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
  }
  $utf8NoBom = New-Object System.Text.UTF8Encoding $false
  [System.IO.File]::WriteAllText(([System.IO.Path]::GetFullPath($Path)), $Text, $utf8NoBom)
}

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
  if ($Provider -ne "cng" -and $Provider -ne "tpm") { return }
  $certreq = Get-Command "certreq.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
  if (-not $certreq) {
    Write-Warning "certreq.exe not found; issued certificate was written but not accepted into LocalMachine\\My"
    return
  }
  Invoke-Checked -Exe $certreq.Source -Args @("-accept", "-machine", $CertPath)
}

$EffectiveCertThumbprint = Get-PemCertificateThumbprint $d.client_cert

function Merge-EnrollIntoAgentTomlExample {
  param(
    [Parameter(Mandatory = $true)][string]$ExamplePath,
    [Parameter(Mandatory = $true)][string]$ServerAddr,
    [Parameter(Mandatory = $true)][string]$EndpointId,
    [Parameter(Mandatory = $true)][string]$TenantId,
    [Parameter(Mandatory = $true)][string]$RestBaseUrl,
    [Parameter(Mandatory = $true)][string]$CaPath,
    [Parameter(Mandatory = $true)][string]$CertPath,
    [Parameter(Mandatory = $true)][string]$KeyPath,
    [Parameter(Mandatory = $true)][string]$KeyProvider,
    [Parameter(Mandatory = $true)][string]$CertStore,
    [Parameter(Mandatory = $true)][string]$CertThumbprint,
    [Parameter(Mandatory = $true)][string]$Pkcs11ModulePath,
    [Parameter(Mandatory = $true)][string]$Pkcs11Uri,
    [Parameter(Mandatory = $true)][string]$TpmUri
  )
  $raw = [System.IO.File]::ReadAllText($ExamplePath)
  if ($raw.StartsWith([char]0xFEFF)) {
    $raw = $raw.Substring(1)
  }
  $raw = $raw -replace "`r`n", "`n"
  $lines = $raw -split "`n", 0, "None"
  $out = New-Object System.Collections.Generic.List[string]
  $i = 0
  while ($i -lt $lines.Count) {
    $line = $lines[$i]
    if ($line -match '^\s*address\s*=') {
      $out.Add(('address              = "{0}"' -f (Escape-Toml $ServerAddr)))
      $i++
      continue
    }
    if ($line -match '^\s*grpc_insecure\s*=') {
      $out.Add('grpc_insecure        = false')
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
    if ($line -match '^\s*#\s*\[platform\]\s*$') {
      $out.Add('[platform]')
      $out.Add(('rest_base_url        = "{0}"' -f (Escape-Toml $RestBaseUrl)))
      # 省略 rest_user_id / rest_bearer_token：Agent 默认 X-User-ID=edr-agent；Bearer 用环境变量或后续手写。
      $i++
      while ($i -lt $lines.Count -and ($lines[$i] -match '^\s*#\s*rest_(base_url|user_id|bearer_token)')) {
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
  if ($env:OS -match 'Windows') {
    $logWin = 'C:\Program Files\EDR Agent\logs'
    $escLog = (Escape-Toml $logWin)
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
  return $merged
}

$tomlMinimal = @"
# Generated by edr_agent_install.ps1

[server]
address              = "$(Escape-Toml $saddr)"
grpc_insecure        = false
ca_cert              = "$(Escape-Toml $EffectiveCaCertPath)"
client_cert          = "$(Escape-Toml $EffectiveClientCertPath)"
client_key           = "$(Escape-Toml $EffectiveClientKeyPath)"
client_key_provider  = "$(Escape-Toml $keyProviderNorm)"
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

"@

$examplePath = Join-Path $PSScriptRoot "agent.toml.example"
if ($Template) {
  $examplePath = $Template
} elseif (-not (Test-Path -LiteralPath $examplePath)) {
  $repoTemplate = Join-Path (Split-Path -Parent $PSScriptRoot) "config\agent_windows_production.example.toml"
  if (Test-Path -LiteralPath $repoTemplate) {
    $examplePath = $repoTemplate
  }
}
$toml = $tomlMinimal
if (-not $MinimalTomlOnly -and (Test-Path -LiteralPath $examplePath)) {
  try {
    $toml = Merge-EnrollIntoAgentTomlExample -ExamplePath $examplePath -ServerAddr $saddr `
      -EndpointId $d.endpoint_id -TenantId $d.tenant_id -RestBaseUrl $rest `
      -CaPath $EffectiveCaCertPath -CertPath $EffectiveClientCertPath -KeyPath $EffectiveClientKeyPath `
      -KeyProvider $keyProviderNorm -CertStore $EffectiveCertStore -CertThumbprint $EffectiveCertThumbprint `
      -Pkcs11ModulePath $Pkcs11Module -Pkcs11Uri $Pkcs11KeyUri -TpmUri $TpmKeyUri
  } catch {
    Write-Warning ("Merge with agent.toml.example failed, writing minimal TOML only: " + $_)
    $toml = $tomlMinimal
  }
}

if ($DryRun) {
  Write-Output $toml
  exit 0
}

if ($d.ca_cert -or $d.client_cert) {
  if (-not ($d.ca_cert -and $d.client_cert)) {
    Write-Error "enroll response returned an incomplete mTLS certificate bundle"
  }
  Write-PemNoBom -Path $CaCertPath -Text $d.ca_cert
  Write-PemNoBom -Path $ClientCertPath -Text $d.client_cert
  Accept-CngIssuedCertificate -CertPath $ClientCertPath -Provider $keyProviderNorm
}
if ($d.client_key) {
  Write-Warning "enroll response included deprecated client_key; ignoring it because the endpoint private key is generated locally"
}

$dir = Split-Path -Parent $Output
if ($dir -and -not (Test-Path $dir)) {
  New-Item -ItemType Directory -Path $dir -Force | Out-Null
}
# 必须无 UTF-8 BOM：Set-Content -Encoding UTF8 在 Windows PowerShell 5.1 会写 BOM，tomlc99 解析报 line 1 missing =（EDR_ERR_CONFIG_PARSE=7002）
$utf8NoBom = New-Object System.Text.UTF8Encoding $false
$outFile = [System.IO.Path]::GetFullPath($Output)
[System.IO.File]::WriteAllText($outFile, $toml, $utf8NoBom)
Write-Host "Wrote $outFile (endpoint_id=$($d.endpoint_id) tenant_id=$($d.tenant_id) server.address=$saddr)"
