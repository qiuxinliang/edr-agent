# 将 vcpkg x64-windows 的 bin\*.dll 复制到 build\Release\，与 edr_agent.exe 同目录分发（gRPC/protobuf/abseil 等）。
# 在 edr-agent 根目录、Release 已生成 edr_agent.exe 后执行。
# 由 CI 在链接 gRPC 后调用；VCPKG_INSTALLED_X64 为 .../vcpkg_installed/x64-windows
$ErrorActionPreference = "Stop"
$V = $env:VCPKG_INSTALLED_X64
if (-not $V) {
  Write-Error "Set VCPKG_INSTALLED_X64 to vcpkg_installed\x64-windows (e.g. under edr-agent)"
  exit 1
}
$bin = Join-Path $V "bin"
$EdrRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$rel = Join-Path $EdrRoot "build\Release"
if (-not (Test-Path -LiteralPath $bin)) {
  Write-Error "No bin: $bin"
  exit 1
}
if (-not (Test-Path -LiteralPath $rel)) {
  Write-Error "Missing $rel (build Release first)"
  exit 1
}
$n = 0
Get-ChildItem -Path $bin -Filter "*.dll" -File -ErrorAction SilentlyContinue | ForEach-Object {
  Copy-Item -LiteralPath $_.FullName -Destination $rel -Force
  $n++
}
Write-Host "Staged $n vcpkg DLL(s) from $bin into $rel"
