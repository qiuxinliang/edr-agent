#Requires -Version 5.1
<#
.SYNOPSIS
  独立运行：调用 POST /api/v1/enroll，生成 agent.toml（不依赖 Python）。

.DESCRIPTION
  二选一提供平台地址与注册 Token（参数优先于环境变量）：
    -ApiBase          或  EDR_API_BASE       例如 http://192.168.1.35:8080（无尾斜杠）
    -Token            或  EDR_ENROLL_TOKEN   控制台下发的 enroll token（enr_...）

  可选：
    -Output / EDR_OUTPUT              输出路径，默认 agent.toml
    EDR_ENROLL_IP                     显式写入 enroll 请求体 ip（不设则本机尽力探测）
    -OverrideServerAddr / EDR_OVERRIDE_SERVER_ADDR   覆盖返回的 gRPC server_addr
    -InsecureTls / -k / EDR_INSECURE_TLS=1           跳过服务端 TLS 证书校验（仅调试）
    -DryRun                           只打印 TOML，不写文件
    EDR_AGENT_VERSION                 Agent 版本号上报字段，默认 0.3.0

  Windows 服务（与 **`--service`** / **`sc stop`** 对齐，见 **`docs/WINDOWS_SERVICE_SHUTDOWN.md`**）：
    -RegisterService                  在成功写出 agent.toml 后（或与 -SkipEnroll 联用）执行 **sc create**
    -AgentExe / EDR_AGENT_EXE          **edr_agent.exe** 绝对或可用路径（**-RegisterService** 必填）
    -ServiceName / EDR_SERVICE_NAME    服务名，须与 **binPath** 内 **--service** 一致，默认 **EdrAgent**
    -ServiceAccount                    **sc create obj=**，默认 **NT AUTHORITY\LocalService**（与 **`WINDOWS_DEPLOY`** 草案一致）
    -SkipEnroll                        跳过 enroll；须已有 **-Output** 配置文件，且通常与 **-RegisterService** 同用
    -UnregisterService                 **sc stop** + **sc delete**（仅删服务，不删 toml / 二进制）
    -ReplaceService                    若服务已存在则先 **UnregisterService** 再创建（需管理员）

  注意：请在「同一 PowerShell 会话」中设置环境变量后再执行脚本；双击运行通常拿不到你设的 $env:。

.EXAMPLE
  .\edr_agent_install.ps1 -ApiBase "http://192.168.1.35:8080" -Token "enr_xxxxxxxx" -Output "C:\ProgramData\EDR\agent.toml"

.EXAMPLE
  $env:EDR_API_BASE = "http://127.0.0.1:8080"
  $env:EDR_ENROLL_TOKEN = "enr_xxxxxxxx"
  .\edr_agent_install.ps1 -Output "C:\ProgramData\EDR\agent.toml"

.EXAMPLE
  HTTPS 自签证书调试：
  .\edr_agent_install.ps1 -ApiBase "https://edr.example.com" -Token "enr_..." -InsecureTls

.EXAMPLE
  平台 enroll 仍返回 127.0.0.1:8443，强制写入内网 gRPC 地址：
  .\edr_agent_install.ps1 -ApiBase "http://192.168.1.35:8080" -Token "enr_..." -OverrideServerAddr "192.168.1.35:8443"

.EXAMPLE
  Enroll 并注册 Windows 服务（管理员 PowerShell；**ServiceName** 须与 **--service** 一致）：
  .\edr_agent_install.ps1 -ApiBase "http://127.0.0.1:8080" -Token "enr_..." `
    -Output "C:\ProgramData\EDR\agent.toml" -AgentExe "C:\Program Files\EDR\edr_agent.exe" -RegisterService -ServiceName EdrAgent

.EXAMPLE
  已有 agent.toml，仅注册服务：
  .\edr_agent_install.ps1 -SkipEnroll -Output "C:\ProgramData\EDR\agent.toml" `
    -AgentExe "C:\Program Files\EDR\edr_agent.exe" -RegisterService -ServiceName EdrAgent

.EXAMPLE
  卸载服务（保留配置与二进制）：
  .\edr_agent_install.ps1 -UnregisterService -ServiceName EdrAgent

.NOTES
  若出现 PSSecurityException / about_Execution_Policies，任选其一（推荐前两种）：

  1) 仅当前用户放宽（一次即可，需新开窗口后 .\ 脚本）：
     Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned

  2) 不改策略，单次绕过执行：
     powershell -NoProfile -ExecutionPolicy Bypass -File .\edr_agent_install.ps1 -ApiBase "http://..." -Token "enr_..."

  3) 同目录下若有 edr_agent_install.cmd，可在 cmd 中：
     edr_agent_install.cmd -ApiBase "http://..." -Token "enr_..."

  【agent.toml 里 server.address（gRPC）】
  该值来自平台 POST /api/v1/enroll 的 server_addr，与 -ApiBase（REST，通常 :8080）不是同一地址。
  若得到 127.0.0.1:8443、但终端应连内网：运行脚本时加
    -OverrideServerAddr "192.168.1.35:8443"
  或在启动 edr-api 前设置环境变量 ENROLL_PUBLIC_SERVER_ADDR=192.168.1.35:8443（优先于租户 features）。
  使用 ./edr-backend/scripts/restart_local_edr_api.sh 且已设 LOCAL_DEV_HOST=192.168.1.35 时，会默认导出 ENROLL_PUBLIC_SERVER_ADDR 为该 IP 的 8443 端口。
#>
[CmdletBinding()]
param(
  [string]$ApiBase,
  [string]$Token,
  [string]$OverrideServerAddr,
  [Alias("k")]
  [switch]$InsecureTls,
  [string]$Output = $(if ($env:EDR_OUTPUT) { $env:EDR_OUTPUT } else { "agent.toml" }),
  [switch]$DryRun,
  [string]$AgentExe,
  [string]$ServiceName,
  [string]$ServiceAccount,
  [switch]$RegisterService,
  [switch]$SkipEnroll,
  [switch]$UnregisterService,
  [switch]$ReplaceService
)

$ErrorActionPreference = "Stop"

# Windows PowerShell 5.x：控制台 UTF-8，减少中文提示乱码（脚本文件请保存为 UTF-8 BOM）
if ($PSVersionTable.PSVersion.Major -lt 6) {
  try { [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false) } catch { }
  try { chcp 65001 | Out-Null } catch { }
}

function Test-EdrWindowsHost {
  if ($PSVersionTable.PSVersion.Major -ge 6 -and (Test-Path variable:global:IsWindows) -and $IsWindows) {
    return $true
  }
  if ($env:OS -match "Windows_NT") {
    return $true
  }
  return $false
}

function Remove-EdrScmService([string]$Name) {
  Write-Host "sc.exe stop $Name ..."
  $null = & sc.exe stop $Name 2>$null
  Start-Sleep -Seconds 2
  Write-Host "sc.exe delete $Name ..."
  $null = & sc.exe delete $Name 2>$null
  $c = $LASTEXITCODE
  if ($c -ne 0 -and $c -ne 1060) {
    Write-Warning "sc.exe delete returned $c (1060 = service did not exist)"
  }
  Write-Host "Service removal attempted: $Name"
}

function Add-EdrScmService {
  param(
    [Parameter(Mandatory)][string]$ExePath,
    [Parameter(Mandatory)][string]$CfgPath,
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][string]$RunAsObj
  )
  if (-not (Test-Path -LiteralPath $ExePath)) {
    throw "Agent exe not found: $ExePath"
  }
  if (-not (Test-Path -LiteralPath $CfgPath)) {
    throw "Config not found: $CfgPath"
  }
  $exeFull = (Resolve-Path -LiteralPath $ExePath).Path
  $cfgFull = (Resolve-Path -LiteralPath $CfgPath).Path
  $binPath = "`"$exeFull`" --service $Name --config `"$cfgFull`""
  Write-Host "sc.exe create $Name binPath= $binPath ..."
  & sc.exe create $Name binPath= $binPath start= auto DisplayName= EDRAgent obj= "$RunAsObj"
  if ($LASTEXITCODE -ne 0) {
    throw "sc.exe create failed (exit $LASTEXITCODE). Run as Administrator. If the service already exists, use -UnregisterService or -ReplaceService."
  }
  Write-Host "Created service '$Name'. Start with: sc.exe start $Name"
}

if (-not $PSBoundParameters.ContainsKey("ApiBase")) {
  $ApiBase = $env:EDR_API_BASE
}
if (-not $PSBoundParameters.ContainsKey("Token")) {
  $Token = $env:EDR_ENROLL_TOKEN
}
if (-not $PSBoundParameters.ContainsKey("OverrideServerAddr")) {
  $OverrideServerAddr = $env:EDR_OVERRIDE_SERVER_ADDR
}
if (-not $PSBoundParameters.ContainsKey("AgentExe")) {
  $AgentExe = $env:EDR_AGENT_EXE
}
if (-not $PSBoundParameters.ContainsKey("ServiceName")) {
  $ServiceName = if ($env:EDR_SERVICE_NAME -and $env:EDR_SERVICE_NAME.Trim()) { $env:EDR_SERVICE_NAME.Trim() } else { "EdrAgent" }
}
if (-not $PSBoundParameters.ContainsKey("ServiceAccount")) {
  $ServiceAccount = if ($env:EDR_SERVICE_ACCOUNT -and $env:EDR_SERVICE_ACCOUNT.Trim()) { $env:EDR_SERVICE_ACCOUNT.Trim() } else { "NT AUTHORITY\LocalService" }
}

$api = if ($null -ne $ApiBase -and $ApiBase.Trim().Length -gt 0) { $ApiBase.Trim() } else { "" }
$tok = if ($null -ne $Token -and $Token.Trim().Length -gt 0) { $Token.Trim() } else { "" }

if ($UnregisterService) {
  if (-not (Test-EdrWindowsHost)) {
    throw "-UnregisterService is only supported on Windows."
  }
  Remove-EdrScmService -Name $ServiceName
  exit 0
}

if ($SkipEnroll -and -not $RegisterService) {
  throw "-SkipEnroll is only valid together with -RegisterService."
}

if (-not $SkipEnroll) {
  if (-not $api -or -not $tok) {
    Write-Host "ERROR: Missing -ApiBase / -Token (or env EDR_API_BASE / EDR_ENROLL_TOKEN). Same PowerShell window required for env vars." -ForegroundColor Yellow
    Write-Host @"
缺少平台地址或 Token。请使用参数，或在「本窗口」先设置环境变量：

  .\edr_agent_install.ps1 -ApiBase <URL> -Token <TOKEN> [-Output <path>] [-DryRun] [-InsecureTls] [-RegisterService -AgentExe <path> ...]

或:

  `$env:EDR_API_BASE = 'http://192.168.1.35:8080'
  `$env:EDR_ENROLL_TOKEN = 'enr_...'
  .\edr_agent_install.ps1

仅注册服务（已有 agent.toml）:
  .\edr_agent_install.ps1 -SkipEnroll -Output "C:\ProgramData\EDR\agent.toml" -AgentExe "...\edr_agent.exe" -RegisterService

完整帮助: Get-Help .\$($MyInvocation.MyCommand.Name) -Full
"@ -ForegroundColor Yellow
    exit 2
  }
  if ($api -notmatch '^(https?://)') {
    throw "ApiBase must start with http:// or https:// (got: '$api')"
  }
} else {
  if (-not (Test-Path -LiteralPath $Output)) {
    throw "-SkipEnroll: config file not found at -Output: $Output"
  }
}

function Get-EnrollOs {
  if ($env:OS -match "Windows_NT" -or $env:OS -like "*Windows*") { return "windows" }
  if ((Test-Path variable:global:IsMacOS) -and $IsMacOS) { return "darwin" }
  if ((Test-Path variable:global:IsLinux) -and $IsLinux) { return "linux" }
  return "linux"
}

function Get-EnrollBodyIP {
  $envIp = $env:EDR_ENROLL_IP
  if ($null -ne $envIp -and $envIp.Trim().Length -gt 0) { return $envIp.Trim() }
  try {
    $udp = New-Object System.Net.Sockets.UdpClient
    try {
      $udp.Client.Connect('203.0.113.1', 53)
      $lep = $udp.Client.LocalEndPoint
      if ($lep -and $lep.Address) { return $lep.Address.IPAddressToString }
    } finally {
      $udp.Close()
    }
  } catch { }
  return ''
}

# 旧版 .NET / Windows 上 Invoke-RestMethod 常见需显式 TLS 1.2
try {
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
} catch {
  # 忽略：部分环境已默认 TLS 1.2+
}

if (-not $SkipEnroll) {
  $api = $api.TrimEnd("/")
  $uri = "$api/api/v1/enroll"
  $av = if ($env:EDR_AGENT_VERSION -and $env:EDR_AGENT_VERSION.Trim()) { $env:EDR_AGENT_VERSION.Trim() } else { "0.3.0" }

  $bodyObj = @{
    token         = $tok
    hostname      = if ($env:COMPUTERNAME) { $env:COMPUTERNAME } else { "unknown" }
    os            = (Get-EnrollOs)
    arch          = if ($env:PROCESSOR_ARCHITECTURE) { $env:PROCESSOR_ARCHITECTURE } else { "" }
    agent_version = $av
    ip            = (Get-EnrollBodyIP)
  }
  $json = $bodyObj | ConvertTo-Json -Compress

  if ($InsecureTls -or ($env:EDR_INSECURE_TLS -eq "1")) {
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

  Write-Verbose "POST $uri"
  try {
    $resp = Invoke-RestMethod -Uri $uri -Method Post -ContentType "application/json; charset=utf-8" -Body $json
  } catch {
    throw ("enroll failed: " + $_)
  }

  if ($resp.code -and $resp.code -ne "OK") {
    throw ("API error: " + ($resp | ConvertTo-Json -Compress))
  }

  $d = $resp.data
  if (-not $d -or -not $d.endpoint_id -or -not $d.tenant_id -or -not $d.server_addr) {
    throw "enroll response missing data or endpoint_id / tenant_id / server_addr"
  }

  $saddr = [string]$d.server_addr
  if ($OverrideServerAddr -and $OverrideServerAddr.Trim()) {
    $saddr = $OverrideServerAddr.Trim()
  }

  $rest = "$api/api/v1"

  function Escape-Toml([string]$s) {
    if ($null -eq $s) { return "" }
    return $s.Replace('\', '\\').Replace('"', '\"')
  }

  $toml = @"
# Generated by edr_agent_install.ps1

[server]
address              = "$(Escape-Toml $saddr)"
ca_cert              = ""
client_cert          = ""
client_key           = ""
connect_timeout_s    = 10
keepalive_interval_s = 30

[agent]
endpoint_id          = "$(Escape-Toml $d.endpoint_id)"
tenant_id            = "$(Escape-Toml $d.tenant_id)"

[platform]
rest_base_url        = "$(Escape-Toml $rest)"
rest_user_id         = ""
rest_bearer_token    = ""

"@

  if ($DryRun) {
    Write-Output $toml
    if ($RegisterService) {
      $ax = if ($AgentExe -and $AgentExe.Trim()) { $AgentExe.Trim() } else { "<set -AgentExe or EDR_AGENT_EXE>" }
      $cfgHint = try { [System.IO.Path]::GetFullPath($Output) } catch { $Output }
      Write-Host ""
      Write-Host "# DryRun: next step (Administrator): sc.exe create $ServiceName binPath= ..." -ForegroundColor Cyan
      Write-Host "#   exe=$ax" -ForegroundColor Cyan
      Write-Host "#   config=$cfgHint  service=$ServiceName  obj=$ServiceAccount" -ForegroundColor Cyan
    }
    exit 0
  }

  $dir = Split-Path -Parent $Output
  if ($dir -and -not (Test-Path -LiteralPath $dir)) {
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
  }
  Set-Content -LiteralPath $Output -Value $toml -Encoding UTF8
  Write-Host "Wrote $Output (endpoint_id=$($d.endpoint_id) tenant_id=$($d.tenant_id) server.address=$saddr)"
} elseif ($DryRun) {
  Write-Host "DryRun with -SkipEnroll: no TOML generated (use without -DryRun to register service only)." -ForegroundColor Yellow
  exit 0
}

if ($RegisterService) {
  if (-not (Test-EdrWindowsHost)) {
    throw "-RegisterService is only supported on Windows."
  }
  $ax = if ($AgentExe -and $AgentExe.Trim()) { $AgentExe.Trim() } else { "" }
  if (-not $ax) {
    throw "-RegisterService requires -AgentExe or environment variable EDR_AGENT_EXE (path to edr_agent.exe)."
  }
  if ($ReplaceService) {
    Remove-EdrScmService -Name $ServiceName
  } else {
    $null = & sc.exe query $ServiceName 2>$null
    if ($LASTEXITCODE -eq 0) {
      throw "Windows service '$ServiceName' already exists. Use -ReplaceService to recreate, or -UnregisterService to remove."
    }
  }
  Add-EdrScmService -ExePath $ax -CfgPath $Output -Name $ServiceName -RunAsObj $ServiceAccount
}
