# 将 onnx-output\*.onnx 复制到 models\（与 sync_onnx_output_to_models.sh 行为一致）。
# 环境变量 EDR_BUNDLE_ONNX_REQUIRED=1 时，若 onnx-output 下无 .onnx 则退出码 1（发布 CI）。
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
$SrcDir = Join-Path $Root 'onnx-output'
$DstDir = Join-Path $Root 'models'
if (-not (Test-Path -LiteralPath $DstDir)) {
    New-Item -ItemType Directory -Path $DstDir | Out-Null
}
if (-not (Test-Path -LiteralPath $SrcDir)) {
    if ($env:EDR_BUNDLE_ONNX_REQUIRED -eq '1') {
        Write-Error "sync_onnx_output_to_models: missing directory $SrcDir"
        exit 1
    }
    Write-Warning "sync_onnx_output_to_models: missing $SrcDir"
    exit 0
}
$onnx = @(Get-ChildItem -LiteralPath $SrcDir -Filter '*.onnx' -File -ErrorAction SilentlyContinue)
if ($onnx.Count -eq 0) {
    if ($env:EDR_BUNDLE_ONNX_REQUIRED -eq '1') {
        Write-Error "sync_onnx_output_to_models: no *.onnx under $SrcDir — add static.onnx / behavior.onnx and commit for release bundle."
        exit 1
    }
    Write-Warning "sync_onnx_output_to_models: no *.onnx in $SrcDir; leaving models/ as-is."
    exit 0
}
foreach ($f in $onnx) {
    Copy-Item -LiteralPath $f.FullName -Destination (Join-Path $DstDir $f.Name) -Force
}
Write-Host "sync_onnx_output_to_models: copied $($onnx.Count) file(s) to $DstDir"
