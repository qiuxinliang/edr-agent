#Requires -Version 5.1
# Run the real selection/installation script with isolated tool fakes.
# Windows uses native batch processes; other hosts stub only the tool boundary.
$ErrorActionPreference = 'Stop'
$owner = Join-Path $PSScriptRoot '../scripts/Ensure-WindowsBuildTools.ps1'
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('edr tool tests ' + [guid]::NewGuid().ToString('N'))
$savedRoot = $env:EDR_BUILD_TOOLS_TEST_ROOT
$windowsHost = $env:OS -eq 'Windows_NT'
$suffix = if ($windowsHost) { '.cmd' } else { '.ps1' }

function Assert-BuildToolTest([bool] $Condition, [string] $Message) {
  if (-not $Condition) { throw "Build tool regression: $Message" }
}
function Get-Command {
  param([string] $Name, [string] $CommandType, [string] $ErrorAction)
  # Never discover or install the test host's real build tools.
  $candidate = Join-Path $env:EDR_BUILD_TOOLS_TEST_ROOT ($Name + $suffix)
  if (Test-Path -LiteralPath $candidate -PathType Leaf) {
    [pscustomobject]@{ Source = $candidate }
  }
}
try {
  New-Item -ItemType Directory -Path $testRoot | Out-Null
  $templates = Join-Path $testRoot 'templates'
  New-Item -ItemType Directory -Path $templates | Out-Null
  if ($windowsHost) {
    $ninja = @'
@echo off
if exist "%EDR_BUILD_TOOLS_TEST_ROOT%\broken-ninja" exit /b 7
findstr /c:"ninja_required_version = 1.10" "%~2" >nul || exit /b 24
if not "%~3"=="-n" exit /b 25
echo [1/1] echo build-tool-probe
exit /b 0
'@
    $inno = @'
@echo off
if exist "%EDR_BUILD_TOOLS_TEST_ROOT%\broken-innosetup" exit /b 8
findstr /c:"ArchitecturesAllowed=x64os or arm64" "%~1" >nul || exit /b 26
findstr /c:"Output=no" "%~1" >nul || exit /b 27
if exist "%EDR_BUILD_TOOLS_TEST_ROOT%\wrong-inno" (echo Inno Setup 7 Command-Line Compiler) else (echo Inno Setup 6 Command-Line Compiler)
exit /b 0
'@
    $choco = @'
@echo off
echo %2>>"%EDR_BUILD_TOOLS_TEST_ROOT%\installed.txt"
if exist "%EDR_BUILD_TOOLS_TEST_ROOT%\install-fails" exit /b 13
if exist "%EDR_BUILD_TOOLS_TEST_ROOT%\install-ineffective" exit /b 0
copy /y "%EDR_BUILD_TOOLS_TEST_ROOT%\..\templates\%2.cmd" "%EDR_BUILD_TOOLS_TEST_ROOT%\%2.cmd" >nul
if exist "%EDR_BUILD_TOOLS_TEST_ROOT%\broken-%2" del "%EDR_BUILD_TOOLS_TEST_ROOT%\broken-%2"
if "%2"=="innosetup" if exist "%EDR_BUILD_TOOLS_TEST_ROOT%\wrong-inno" del "%EDR_BUILD_TOOLS_TEST_ROOT%\wrong-inno"
exit /b 0
'@
  } else {
    $ninja = @'
if (Test-Path (Join-Path $env:EDR_BUILD_TOOLS_TEST_ROOT 'broken-ninja')) { $global:LASTEXITCODE = 7; return }
if ([IO.File]::ReadAllText($args[1]) -notmatch 'ninja_required_version = 1.10') { $global:LASTEXITCODE = 24; return }
if ($args[2] -ne '-n') { $global:LASTEXITCODE = 25; return }
'[1/1] echo build-tool-probe'
$global:LASTEXITCODE = 0
'@
    $inno = @'
if (Test-Path (Join-Path $env:EDR_BUILD_TOOLS_TEST_ROOT 'broken-innosetup')) { $global:LASTEXITCODE = 8; return }
$source = [IO.File]::ReadAllText($args[0])
if ($source -notmatch 'ArchitecturesAllowed=x64os or arm64') { $global:LASTEXITCODE = 26; return }
if ($source -notmatch 'Output=no') { $global:LASTEXITCODE = 27; return }
if (Test-Path (Join-Path $env:EDR_BUILD_TOOLS_TEST_ROOT 'wrong-inno')) { 'Inno Setup 7 Command-Line Compiler' }
else { 'Inno Setup 6 Command-Line Compiler' }
$global:LASTEXITCODE = 0
'@
    $choco = @'
$root = $env:EDR_BUILD_TOOLS_TEST_ROOT
$package = $args[1]
[IO.File]::AppendAllText((Join-Path $root 'installed.txt'), $package + [Environment]::NewLine)
if (Test-Path (Join-Path $root 'install-fails')) { $global:LASTEXITCODE = 13; return }
if (Test-Path (Join-Path $root 'install-ineffective')) { $global:LASTEXITCODE = 0; return }
Copy-Item -LiteralPath (Join-Path $root "../templates/$package.ps1") -Destination $root -Force
$marker = Join-Path $root "broken-$package"
if (Test-Path $marker) { Remove-Item $marker }
$marker = Join-Path $root 'wrong-inno'
if ($package -eq 'innosetup' -and (Test-Path $marker)) { Remove-Item $marker }
$global:LASTEXITCODE = 0
'@
  }
  foreach ($entry in @{ ninja = $ninja; innosetup = $inno; choco = $choco }.GetEnumerator()) {
    $path = Join-Path $templates ($entry.Key + $suffix)
    [IO.File]::WriteAllText($path, $entry.Value, [Text.Encoding]::ASCII)
  }
  $cases = @(
    @{ Name = 'reuse-both'; Present = @('ninja', 'innosetup'); Installed = @() },
    @{ Name = 'install-ninja-only'; Present = @('innosetup'); Installed = @('ninja') },
    @{ Name = 'install-inno-only'; Present = @('ninja'); Installed = @('innosetup') },
    @{ Name = 'install-both'; Present = @(); Installed = @('ninja', 'innosetup') },
    @{ Name = 'broken-ninja'; Present = @('ninja', 'innosetup'); Marker = 'broken-ninja'; Installed = @('ninja') },
    @{ Name = 'broken-inno'; Present = @('ninja', 'innosetup'); Marker = 'broken-innosetup'; Installed = @('innosetup') },
    @{ Name = 'wrong-bootstrap'; Present = @('ninja', 'innosetup'); Marker = 'wrong-inno'; Installed = @('innosetup') },
    @{ Name = 'ninja-consumer-only'; Present = @('ninja'); NinjaOnly = $true; Installed = @() },
    @{ Name = 'installation-failed'; Present = @(); Marker = 'install-fails'; Installed = @('ninja'); Error = 'failed with exit 13' },
    @{ Name = 'installation-ineffective'; Present = @(); Marker = 'install-ineffective'; Installed = @('ninja'); Error = 'still unavailable' },
    @{ Name = 'no-package-manager'; Present = @(); NoChoco = $true; Installed = @(); Error = 'Chocolatey is not on PATH' }
  )
  foreach ($case in $cases) {
    $directory = Join-Path $testRoot $case.Name
    New-Item -ItemType Directory -Path $directory | Out-Null
    $env:EDR_BUILD_TOOLS_TEST_ROOT = $directory
    foreach ($package in @($case.Present) + $(if ($case.NoChoco) { @() } else { @('choco') })) {
      Copy-Item -LiteralPath (Join-Path $templates ($package + $suffix)) -Destination $directory
    }
    if ($case.Marker) { [IO.File]::WriteAllText((Join-Path $directory $case.Marker), '') }
    $arguments = @{ InnoCompiler = (Join-Path $directory ('innosetup' + $suffix)); NinjaOnly = [bool]$case.NinjaOnly }
    $failure = ''
    try { & $owner @arguments } catch { $failure = $_.Exception.Message }
    if ($case.Error) {
      Assert-BuildToolTest ($failure -match $case.Error) ($case.Name + ': expected failure, got ' + $failure)
    } else {
      Assert-BuildToolTest (-not $failure) ($case.Name + ': unexpected failure ' + $failure)
    }
    $installed = @()
    if (Test-Path -LiteralPath (Join-Path $directory 'installed.txt')) {
      $installed = @(Get-Content -LiteralPath (Join-Path $directory 'installed.txt'))
    }
    Assert-BuildToolTest (($installed -join ',') -ceq ($case.Installed -join ',')) ($case.Name + ': wrong install selection')
  }
  Write-Host "PASS: $($cases.Count) build tool reuse, selective install and failure cases"
} finally {
  [Environment]::SetEnvironmentVariable('EDR_BUILD_TOOLS_TEST_ROOT', $savedRoot, 'Process')
  if (Test-Path -LiteralPath $testRoot) { Remove-Item -LiteralPath $testRoot -Recurse -Force }
}
