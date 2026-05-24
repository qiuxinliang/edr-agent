# 将 ONNX Runtime 的 DLL 复制到 build\Release\，供 Inno / 便携 zip 与 edr_agent.exe 同目录分发。
# 前提：已设置环境变量 ONNXRUNTIME_ROOT（官方 onnxruntime-win-x64-* 解压根目录）；在 edr-agent 仓库根执行。
$ErrorActionPreference = 'Stop'
if (-not $env:ONNXRUNTIME_ROOT) {
    Write-Error "ONNXRUNTIME_ROOT is not set"
    exit 1
}
$Root = Split-Path -Parent $PSScriptRoot
$releaseDir = Join-Path $Root 'build\Release'
$singleConfigDir = Join-Path $Root 'build'
$releaseExe = Join-Path $releaseDir 'edr_agent.exe'
$singleConfigExe = Join-Path $singleConfigDir 'edr_agent.exe'
if (-not (Test-Path -LiteralPath $releaseExe)) {
    if (Test-Path -LiteralPath $singleConfigExe) {
        New-Item -ItemType Directory -Force -Path $releaseDir | Out-Null
        Copy-Item -LiteralPath $singleConfigExe -Destination $releaseExe -Force
        Write-Host "Normalized Ninja single-config exe: $singleConfigExe -> $releaseExe"
    }
}
if (-not (Test-Path -LiteralPath $releaseExe)) {
    Write-Error "edr_agent.exe not found under build\Release or build (Ninja single-config). Build first."
    exit 1
}
$lib = Join-Path $env:ONNXRUNTIME_ROOT 'lib'
$candidates = @(
    (Join-Path $lib 'onnxruntime.dll'),
    (Join-Path $env:ONNXRUNTIME_ROOT 'onnxruntime.dll')
)
$dll = $candidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if (-not $dll) {
    Write-Error "onnxruntime.dll not found under ONNXRUNTIME_ROOT=$($env:ONNXRUNTIME_ROOT)"
    exit 1
}
Copy-Item -LiteralPath $dll -Destination $releaseDir -Force
$prov = Join-Path $lib 'onnxruntime_providers_shared.dll'
if (Test-Path -LiteralPath $prov) {
    Copy-Item -LiteralPath $prov -Destination $releaseDir -Force
}
Write-Host "Staged ORT DLL(s) into $releaseDir"
