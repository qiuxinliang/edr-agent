# 在「适用于 VS 的 x64 本机工具」等已执行 vcvars 的 PowerShell 中 source，便于本机 sccache 与 CI 行为一致。
# 不修改项目；只设置本会话环境变量。安装: winget install -e --id Mozilla.sccache 或 choco install sccache
$ErrorActionPreference = "Stop"
$root = Join-Path $env:LOCALAPPDATA "sccache-edr-agent"
New-Item -ItemType Directory -Force -Path $root | Out-Null
$env:SCCACHE_DIR = $root
$env:SCCACHE_CACHE_SIZE = "2G"
Write-Host "SCCACHE_DIR=$($env:SCCACHE_DIR) (sccache on PATH expected)"
Write-Host "Add to cmake configure:"
Write-Host '  -DCMAKE_C_COMPILER_LAUNCHER=sccache -DCMAKE_CXX_COMPILER_LAUNCHER=sccache'
