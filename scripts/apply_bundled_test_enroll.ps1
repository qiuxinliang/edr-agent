#Requires -Version 5.1
# 读取安装目录下的 enroll_test.env（由 CI 内网测试包生成），调用 enroll 并写入同目录 agent.toml。
$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
$envFile = Join-Path $root "enroll_test.env"
if (-not (Test-Path $envFile)) {
  Write-Host "未找到 enroll_test.env（正式包不含测试 Token）。请使用 edr-terminal-install.ps1 并传入 -ApiBase / -Token。" -ForegroundColor Yellow
  exit 1
}
Get-Content $envFile -Encoding UTF8 | ForEach-Object {
  $line = $_.Trim()
  if (-not $line -or $line.StartsWith("#")) { return }
  $i = $line.IndexOf("=")
  if ($i -lt 1) { return }
  $k = $line.Substring(0, $i).Trim()
  $v = $line.Substring($i + 1).Trim()
  if ($k) { Set-Item -Path "Env:$k" -Value $v }
}
$out = Join-Path $root "agent.toml"
& "$root\edr_agent_install.ps1" -Output $out
Write-Host "已生成: $out" -ForegroundColor Green
