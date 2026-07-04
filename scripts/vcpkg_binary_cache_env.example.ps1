# 示例：在本机开启 vcpkg 二进制缓存（与 CI 的 VCPKG_BINARY_SOURCES 思路一致）。
# 使用：在「执行 vcpkg install 的」 PowerShell 会话中先点源或复制以下两行到 $PROFILE。
# 将 $HOME\.vcpkg-bincache 换为团队共享目录即团队缓存。

$dir = Join-Path $HOME ".vcpkg-bincache"
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$env:VCPKG_BINARY_SOURCES = "clear;files,$dir,readwrite"
Write-Host "VCPKG_BINARY_SOURCES=$($env:VCPKG_BINARY_SOURCES)"
