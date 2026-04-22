# Native ARM64 Windows build (Snapdragon / WoA laptops, Windows 11 ARM VMs).
# Prerequisites: Visual Studio 2022 (or 2019) with "Desktop development with C++"
# and the ARM64 MSVC toolset / Windows 11 SDK (installer option for ARM64).
#
# Usage (from edr-agent repo root, in PowerShell):
#   .\scripts\build_windows_arm64.ps1
# Optional:
#   .\scripts\build_windows_arm64.ps1 -Generator "Visual Studio 16 2019" -BuildDir build-arm64

param(
    [string]$BuildDir = "build-arm64",
    [ValidateSet("Debug", "Release", "RelWithDebInfo", "MinSizeRel")]
    [string]$Config = "Release",
    [string]$Generator = "Visual Studio 17 2022",
    [int]$Parallel = 0
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $root

if ($Parallel -le 0) {
    $Parallel = [Math]::Max(1, [Environment]::ProcessorCount)
}

Write-Host "Configuring CMake: generator=$Generator, -A ARM64, EDR_WITH_GRPC=OFF" -ForegroundColor Cyan
cmake -B $BuildDir -G $Generator -A ARM64 -DEDR_WITH_GRPC=OFF

Write-Host "Building ($Config, -j $Parallel)..." -ForegroundColor Cyan
cmake --build $BuildDir --config $Config --parallel $Parallel

$exe = Join-Path $BuildDir "$Config\edr_agent.exe"
if (-not (Test-Path -LiteralPath $exe)) {
    Write-Warning "Expected output not found at $exe (check generator output layout)."
} else {
    Write-Host "OK: $exe" -ForegroundColor Green
    & $exe --help | Select-Object -First 5
}
