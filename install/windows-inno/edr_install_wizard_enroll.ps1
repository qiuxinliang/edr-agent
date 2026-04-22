#Requires -Version 5.1
<#
  由 EDRAgentSetup.iss 的 [Run] 调用：读取向导写入的 JSON，调用同目录 edr_agent_install.ps1 完成 enroll。
  参数 1：JSON 路径（含 api_base、token、insecure_tls）
  参数 2：输出的 agent.toml 绝对路径
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

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$installer = Join-Path $here "edr_agent_install.ps1"
if (-not (Test-Path -LiteralPath $installer)) {
  Write-Error "Missing bundled installer script: $installer"
}

& $installer -Output $OutToml

Remove-Item -LiteralPath $ParamsFile -Force -ErrorAction SilentlyContinue
