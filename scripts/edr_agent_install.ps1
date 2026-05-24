#Requires -Version 5.1
<#
.SYNOPSIS
  独立运行：调用 POST /api/v1/enroll，生成 agent.toml（不依赖 Python）。

.DESCRIPTION
  推荐：
    .\edr_agent_install.ps1 -ApiBase https://edr.example:8080 -EnrollToken <token>

  可选：
    EDR_API_BASE / EDR_ENROLL_TOKEN  兼容旧版环境变量传参
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
    EDR_TRUST_CA=1          enroll 前将 EDR_CA_CERT 导入 Windows Root（适合企业私有 CA / lab mkcert）
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
  [string]$ApiBase = $(if ($env:EDR_API_BASE) { $env:EDR_API_BASE } else { "" }),
  [string]$EnrollToken = $(if ($env:EDR_ENROLL_TOKEN) { $env:EDR_ENROLL_TOKEN } else { "" }),
  [string]$CngProviderName = $(if ($env:EDR_CNG_PROVIDER_NAME) { $env:EDR_CNG_PROVIDER_NAME } else { "" }),
  [string]$CngKeyName = $(if ($env:EDR_CNG_KEY_NAME) { $env:EDR_CNG_KEY_NAME } else { "" }),
  [string]$Pkcs11KeyUri = $(if ($env:EDR_PKCS11_KEY_URI) { $env:EDR_PKCS11_KEY_URI } else { "" }),
  [string]$Pkcs11Module = $(if ($env:EDR_PKCS11_MODULE) { $env:EDR_PKCS11_MODULE } else { "" }),
  [string]$TpmKeyUri = $(if ($env:EDR_TPM_KEY_URI) { $env:EDR_TPM_KEY_URI } else { "" }),
  [switch]$TrustCa = $($env:EDR_TRUST_CA -eq "1"),
  [switch]$InstallAutorun,
  [switch]$HardenAcl,
  [switch]$KeepTemplateComments = $($env:EDR_KEEP_TEMPLATE_COMMENTS -eq "1"),
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

$api = $ApiBase
$tok = $EnrollToken
if (-not $api -or -not $tok) {
  Write-Error "Provide -ApiBase and -EnrollToken, for example: .\edr_agent_install.ps1 -ApiBase https://edr.example:8080 -EnrollToken <token>"
}

$api = $api.TrimEnd("/")
$uri = "$api/api/v1/enroll"
$av = if ($env:EDR_AGENT_VERSION) { $env:EDR_AGENT_VERSION } else { "0.3.0" }

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

function Invoke-Checked {
  param([string]$Exe, [string[]]$ArgList)
  & $Exe @ArgList
  if ($LASTEXITCODE -ne 0) {
    Write-Error ("command failed: " + $Exe + " " + ($ArgList -join " "))
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

function Normalize-KeyProvider([string]$Provider) {
  $p = if ($Provider) { $Provider.Trim().ToLowerInvariant() } else { "pem" }
  if ($p -eq "file") { return "pem" }
  if (@("pem", "cng", "tpm", "pkcs11") -notcontains $p) {
    Write-Error "unsupported EDR_KEY_PROVIDER=$Provider (expected pem|cng|tpm|pkcs11)"
  }
  return $p
}

function Join-Bytes {
  param([byte[][]]$Parts)
  $ms = New-Object System.IO.MemoryStream
  foreach ($part in $Parts) {
    if ($part -and $part.Length -gt 0) {
      $ms.Write($part, 0, $part.Length)
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
    $utf8NoBom = New-Object System.Text.UTF8Encoding $false
    [System.IO.File]::WriteAllText(([System.IO.Path]::GetFullPath($KeyPath)), (ConvertTo-Pem "RSA PRIVATE KEY" $keyDer), $utf8NoBom)
    [System.IO.File]::WriteAllText(([System.IO.Path]::GetFullPath($CsrPath)), (ConvertTo-Pem "CERTIFICATE REQUEST" $csrDer), $utf8NoBom)
    return [System.IO.File]::ReadAllText(([System.IO.Path]::GetFullPath($CsrPath)))
  } catch {
    Write-Verbose ("Native PEM CSR generation unavailable: " + $_)
    return $null
  }
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
  Invoke-Checked -Exe $certreq.Source -ArgList @("-new", "-machine", $infPath, $CsrPath)
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

if ($TrustCa) {
  Install-BootstrapCaTrust -Path $CaCertPath
}

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
  Invoke-Checked -Exe $certreq.Source -ArgList @("-accept", "-machine", $CertPath)
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
    [AllowEmptyString()][string]$CertStore,
    [Parameter(Mandatory = $true)][string]$CertThumbprint,
    [AllowEmptyString()][string]$Pkcs11ModulePath,
    [AllowEmptyString()][string]$Pkcs11Uri,
    [AllowEmptyString()][string]$TpmUri
  )
  $raw = [System.IO.File]::ReadAllText($ExamplePath)
  if ($raw.StartsWith([char]0xFEFF)) {
    $raw = $raw.Substring(1)
  }
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
  $out.Add("# Generated by EDR Agent installer. Keep endpoint-specific values in this file.") | Out-Null
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
    if ($clean.Trim() -eq "") {
      if (-not $blank -and $out.Count -gt 0) {
        $out.Add("") | Out-Null
        $blank = $true
      }
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

$tomlMinimal = @"
# Generated by EDR Agent installer. Keep endpoint-specific values in this file.

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
if (-not $KeepTemplateComments) {
  $toml = Optimize-GeneratedToml $toml
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

if ($InstallAutorun) {
  $autorun = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) "edr_windows_autorun.ps1"
  if (-not (Test-Path -LiteralPath $autorun)) {
    $autorun = Join-Path (Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)) "install\windows-inno\edr_windows_autorun.ps1"
  }
  if (-not (Test-Path -LiteralPath $autorun)) {
    Write-Warning "InstallAutorun requested, but edr_windows_autorun.ps1 was not found next to the installer script"
  } else {
    $autorunArgs = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $autorun, "-Action", "Install")
    if ($HardenAcl) {
      $autorunArgs += "-HardenAcl"
    }
    Invoke-Checked -Exe "powershell.exe" -ArgList $autorunArgs
    Write-Host "Installed EdrAgent startup task"
  }
}
