# 将 vcpkg x64-windows 的 bin\*.dll 复制到 build\Release\，与 FDSensor.exe 同目录分发。
# 在 edr-agent 根目录、Release 已生成 FDSensor.exe 后执行。
# 由 CI 在构建后调用；VCPKG_INSTALLED_X64 为 .../vcpkg_installed/x64-windows
$ErrorActionPreference = "Stop"
$V = $env:VCPKG_INSTALLED_X64
if (-not $V) {
  Write-Error "Set VCPKG_INSTALLED_X64 to vcpkg_installed\x64-windows (e.g. under edr-agent)"
  exit 1
}
$bin = Join-Path $V "bin"
$EdrRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$releaseDir = Join-Path $EdrRoot "build\Release"
$singleConfigDir = Join-Path $EdrRoot "build"
$releaseExe = Join-Path $releaseDir "FDSensor.exe"
$singleConfigExe = Join-Path $singleConfigDir "FDSensor.exe"
$legacyReleaseExe = Join-Path $releaseDir "edr_agent.exe"
$legacySingleConfigExe = Join-Path $singleConfigDir "edr_agent.exe"
if (-not (Test-Path -LiteralPath $bin)) {
  Write-Error "No bin: $bin"
  exit 1
}
$yaraRuntimeDlls = @(Get-ChildItem -Path $bin -Filter "*.dll" -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '(?i)yara.*\.dll$' })
if (-not $yaraRuntimeDlls -or $yaraRuntimeDlls.Count -lt 1) {
  Write-Error "YARA runtime DLL missing from vcpkg bin: $bin. Install vcpkg manifest feature 'yara' for x64-windows before staging."
  exit 1
}
Write-Host "Found YARA runtime DLL(s) in vcpkg bin: $($yaraRuntimeDlls.Name -join ', ')"
if (-not (Test-Path -LiteralPath $releaseExe)) {
  if (Test-Path -LiteralPath $singleConfigExe) {
    New-Item -ItemType Directory -Force -Path $releaseDir | Out-Null
    Copy-Item -LiteralPath $singleConfigExe -Destination $releaseExe -Force
    Write-Host "Normalized Ninja single-config exe: $singleConfigExe -> $releaseExe"
  } elseif (Test-Path -LiteralPath $legacyReleaseExe) {
    Copy-Item -LiteralPath $legacyReleaseExe -Destination $releaseExe -Force
    Write-Host "Created compatibility product exe: $legacyReleaseExe -> $releaseExe"
  } elseif (Test-Path -LiteralPath $legacySingleConfigExe) {
    New-Item -ItemType Directory -Force -Path $releaseDir | Out-Null
    Copy-Item -LiteralPath $legacySingleConfigExe -Destination $releaseExe -Force
    Write-Host "Created compatibility product exe: $legacySingleConfigExe -> $releaseExe"
  }
}
if (-not (Test-Path -LiteralPath $releaseExe)) {
  Write-Error "FDSensor.exe not found under build\Release or build (Ninja). Build first."
  exit 1
}
$n = 0
Get-ChildItem -Path $bin -Filter "*.dll" -File -ErrorAction SilentlyContinue | ForEach-Object {
  Copy-Item -LiteralPath $_.FullName -Destination $releaseDir -Force
  $n++
}
Write-Host "Staged $n vcpkg DLL(s) from $bin into $releaseDir"
$stagedYaraRuntimeDlls = @(Get-ChildItem -Path $releaseDir -Filter "*.dll" -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '(?i)yara.*\.dll$' })
if (-not $stagedYaraRuntimeDlls -or $stagedYaraRuntimeDlls.Count -lt 1) {
  Write-Error "YARA runtime DLL was not staged into $releaseDir"
  exit 1
}
Write-Host "Verified staged YARA runtime DLL(s): $($stagedYaraRuntimeDlls.Name -join ', ')"
