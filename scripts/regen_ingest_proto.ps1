# 在 Windows 上由 proto/edr/v1/ingest.proto 生成 C++ gRPC 桩到 src/grpc_gen/edr/v1/。
# 须与最终链接的 libprotobuf 主版本一致：请传入与 CMake/vcpkg 同一 triplet 的 vcpkg_installed 根
#（例如 .../vcpkg_installed/x64-windows），脚本会选用 tools\protobuf\protoc.exe 与 tools\grpc\grpc_cpp_plugin.exe。
#
# 用法（在 edr-agent 目录）：
#   powershell -NoProfile -File scripts/regen_ingest_proto.ps1 -VcpkgInstalledX64 "C:\path\vcpkg_installed\x64-windows"
# 或设置环境变量 VCPKG_INSTALLED_X64 后无参执行。
param(
  [string]$VcpkgInstalledX64 = $env:VCPKG_INSTALLED_X64
)
$ErrorActionPreference = "Stop"
$EdrRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if (-not $VcpkgInstalledX64 -or -not (Test-Path -LiteralPath $VcpkgInstalledX64)) {
  Write-Error "VcpkgInstalledX64 未指到 x64 安装根（如 .../vcpkg_installed/x64-windows），或设环境变量 VCPKG_INSTALLED_X64"
  exit 1
}
$protoc = Join-Path $VcpkgInstalledX64 "tools\protobuf\protoc.exe"
$plugin = Join-Path $VcpkgInstalledX64 "tools\grpc\grpc_cpp_plugin.exe"
if (-not (Test-Path -LiteralPath $protoc)) {
  Write-Error "未找到: $protoc"
  exit 1
}
if (-not (Test-Path -LiteralPath $plugin)) {
  Write-Error "未找到: $plugin"
  exit 1
}
$ver = & $protoc --version 2>&1
Write-Host "protoc: $ver ($protoc)"
Write-Host "grpc_cpp_plugin: $plugin"
$proto = Join-Path $EdrRoot "proto\edr\v1\ingest.proto"
$out = Join-Path $EdrRoot "src\grpc_gen"
if (-not (Test-Path -LiteralPath $proto)) { Write-Error "Missing $proto" ; exit 1 }
New-Item -ItemType Directory -Force -Path (Join-Path $out "edr\v1") | Out-Null
& $protoc -I (Join-Path $EdrRoot "proto") $proto --cpp_out=$out --grpc_out=$out --plugin=protoc-gen-grpc=$plugin
Write-Host "OK: $out\edr\v1\ingest.pb.*, ingest.grpc.pb.*"
