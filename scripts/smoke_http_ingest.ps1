# 与 smoke_http_ingest.sh 等价（Windows）。需：Go 在 PATH。
# 若环境禁止执行 .ps1：用同目录 smoke_http_ingest.cmd + 预生成的 smoke_body.json（无需 Go、无需 PowerShell）。
# 脚本应放在 monorepo 的 edr-agent\scripts\ 下；若拷到「安装目录」等其它位置，必须设置 EDR_PLATFORM_ROOT 指向含 go.mod 的 edr-backend\platform。
# 示例：
#   $env:EDR_SMOKE_BASE = 'http://192.168.1.35:8080/api/v1'
#   $env:EDR_SMOKE_BEARER = 'eyJ...'
#   $env:EDR_SMOKE_ENDPOINT = '<endpoint_id>'
#   $env:EDR_PLATFORM_ROOT = 'D:\src\AI Agent\edr-backend\platform'   # 安装目录等非仓库路径时必填
#   .\scripts\smoke_http_ingest.ps1
$ErrorActionPreference = 'Stop'
foreach ($k in @('EDR_SMOKE_BASE', 'EDR_SMOKE_BEARER', 'EDR_SMOKE_ENDPOINT')) {
    $v = (Get-Item "Env:$k" -ErrorAction SilentlyContinue).Value
    if ([string]::IsNullOrWhiteSpace($v)) {
        Write-Error "Missing environment variable $k"
        exit 1
    }
}
$tenant = if ($env:EDR_SMOKE_TENANT) { $env:EDR_SMOKE_TENANT } else { 'demo-tenant' }
$user = if ($env:EDR_SMOKE_USER) { $env:EDR_SMOKE_USER } else { 'edr-agent' }

$platformRoot = $null
if (-not [string]::IsNullOrWhiteSpace($env:EDR_PLATFORM_ROOT)) {
    $platformRoot = $env:EDR_PLATFORM_ROOT.TrimEnd('\', '/')
}
if ([string]::IsNullOrWhiteSpace($platformRoot)) {
    $agentRoot = Split-Path -Parent $PSScriptRoot
    $candidate = [System.IO.Path]::GetFullPath((Join-Path $agentRoot '..\edr-backend\platform'))
    if (Test-Path -LiteralPath (Join-Path $candidate 'go.mod')) {
        $platformRoot = $candidate
    }
}
if ([string]::IsNullOrWhiteSpace($platformRoot) -or -not (Test-Path -LiteralPath (Join-Path $platformRoot 'go.mod'))) {
    Write-Error @"
Could not find edr-backend\platform (go.mod).

When the script is not under the monorepo (e.g. copied to 'C:\Program Files\EDR Agent'), set:
  `$env:EDR_PLATFORM_ROOT = '<full-path>\edr-backend\platform'

Script folder: $PSScriptRoot
"@
    exit 1
}
Push-Location $platformRoot
try {
    $json = & go run ./cmd/edr-ingest-sample -endpoint $env:EDR_SMOKE_ENDPOINT -tenant $tenant
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
} finally {
    Pop-Location
}
$url = "$($env:EDR_SMOKE_BASE.TrimEnd('/'))/ingest/report-events"
Write-Host "POST $url ..."
$headers = @{
    'Content-Type'      = 'application/json'
    'X-Tenant-ID'       = $tenant
    'X-User-ID'         = $user
    'X-Permission-Set'  = 'telemetry:write'
    'Authorization'     = "Bearer $($env:EDR_SMOKE_BEARER)"
}
Invoke-RestMethod -Uri $url -Method Post -Headers $headers -Body $json
