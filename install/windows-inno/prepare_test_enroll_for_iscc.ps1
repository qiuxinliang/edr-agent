#Requires -Version 5.1
# 从 compile-secrets.local.env 生成 ISCC 所需的 enroll_test 源文件（供 /DEDRCI_BUNDLE_TEST_ENROLL）。
# 用法：在 windows-inno 目录执行 .\prepare_test_enroll_for_iscc.ps1
$ErrorActionPreference = "Stop"
$here = $PSScriptRoot
$src = Join-Path $here "compile-secrets.local.env"
$dst = Join-Path $here "build-ci-test-enroll.env"
if (-not (Test-Path $src)) {
  Write-Host "未找到 $src — 请复制 compile-secrets.example.env 并填写 Token。" -ForegroundColor Yellow
  exit 1
}
Copy-Item -Path $src -Destination $dst -Force
Write-Host "已写入 $dst 。请使用 ISCC 并追加编译开关: /DEDRCI_BUNDLE_TEST_ENROLL" -ForegroundColor Green
