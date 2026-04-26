#Requires -Version 5.1
<#
  Builds EDRAgentSetup-bundled.exe (full layout: staged exe/DLLs + models dir + preprocess TOML + scripts).
  Run on Windows from the monorepo root OR from this directory.

  Default staging folder (relative to this .iss file): ..\..\..\edr-agent-win_2-2

  Examples:
    .\edr-agent\install\windows-inno\Build-BundledInstaller.ps1
    .\Build-BundledInstaller.ps1 -AppVersion 2.2.0
    .\Build-BundledInstaller.ps1 -BinDir "D:\staged\edr-release" -Inno "C:\Program Files (x86)\Inno Setup 6\ISCC.exe"
#>
param(
    [string] $Inno = "",
    [string] $BinDir = "",
    [string] $AppVersion = "2.2.0"
)
if (-not $Inno) {
    $pf86 = [Environment]::GetFolderPath("ProgramFilesX86")
    $Inno = if ($pf86) { Join-Path $pf86 "Inno Setup 6\ISCC.exe" } else { "ISCC.exe" }
}

$ErrorActionPreference = "Stop"
$scriptDir = $PSScriptRoot
$iss = Join-Path $scriptDir "EDRAgentSetup.bundled.iss"
if (-not (Test-Path -LiteralPath $iss)) {
    throw "Missing $iss"
}

if (-not $BinDir) {
    $monorepoRoot = (Resolve-Path (Join-Path $scriptDir "..\..\..")).Path
    $BinDir = Join-Path $monorepoRoot "edr-agent-win_2-2"
}
$binExe = Join-Path $BinDir "edr_agent.exe"
if (-not (Test-Path -LiteralPath $binExe)) {
    throw "edr_agent.exe not found: $binExe. Pass -BinDir to your staging folder."
}

$modelsDir = Join-Path (Join-Path (Join-Path $scriptDir "..\..") "models")
if (Test-Path -LiteralPath $modelsDir) {
    $onnx = Get-ChildItem -Path $modelsDir -Filter "*.onnx" -File -Recurse -ErrorAction SilentlyContinue
    if (-not $onnx) {
        Write-Warning "No .onnx under $modelsDir — install will still include README; copy models before build for a full stack."
    }
}

$pre = Join-Path (Join-Path (Join-Path $scriptDir "..\..\..") "edr-backend\platform\config\agent_preprocess_rules_v1.toml")
if (-not (Test-Path -LiteralPath $pre)) {
    Write-Warning "Preprocess TOML missing: $pre — run edr-backend/platform/config/generate_agent_preprocess_rules.py first."
}

if (-not (Test-Path -LiteralPath $Inno)) {
    throw "Inno Setup compiler not found: $Inno. Install Inno Setup 6 or pass -Inno to ISCC.exe"
}

# ISCC: paths with spaces need /DNAME="C:\a b"
if ($BinDir -match "\s") { $binDef = '/DEDR_BIN_DIR="' + $BinDir + '"' } else { $binDef = "/DEDR_BIN_DIR=$BinDir" }
& $Inno $binDef "/DMyAppVersion=$AppVersion" $iss
if ($LASTEXITCODE -ne 0) {
    throw "ISCC failed with exit $LASTEXITCODE"
}
$outDir = Join-Path $scriptDir "Output"
$out = Join-Path $outDir "EDRAgentSetup-bundled.exe"
if (Test-Path -LiteralPath $out) {
    Write-Host "OK: $out"
} else {
    Write-Warning "ISCC reported success but $out not found; check ISCC log."
}
