#Requires -Version 5.1
[CmdletBinding()]
param(
  [switch] $NinjaOnly,
  # Test isolation only: production packaging uses this same default path.
  [Parameter(DontShow = $true)]
  [string] $InnoCompiler = ''
)

$ErrorActionPreference = 'Stop'
if (-not $InnoCompiler) {
  $programFilesX86 = [Environment]::GetFolderPath('ProgramFilesX86')
  $InnoCompiler = if ($programFilesX86) { Join-Path $programFilesX86 'Inno Setup 6\ISCC.exe' } else { 'ISCC.exe' }
}
$probeRoot = Join-Path ([IO.Path]::GetTempPath()) ('edr-build-tools-' + [guid]::NewGuid().ToString('N'))

function Test-ReleaseBuildTool {
  param([string] $Package)
  try {
    if ($Package -eq 'ninja') {
      $command = Get-Command ninja -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
      if (-not $command) { throw 'ninja executable is not on PATH' }
      # Ninja Multi-Config is exercised by the release gate dependency checks.
      # Dry-run the graph so an executable/version string alone cannot pass.
      $output = @(& $command.Source -f (Join-Path $probeRoot 'build.ninja') -n 2>&1)
    } else {
      if (-not (Test-Path -LiteralPath $InnoCompiler -PathType Leaf)) {
        throw "packaging compiler is missing: $InnoCompiler"
      }
      $output = @(& $InnoCompiler (Join-Path $probeRoot 'probe.iss') 2>&1)
    }
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) { throw "capability probe exited $exitCode`: $(($output | Select-Object -Last 4) -join ' ')" }
    if ($Package -eq 'innosetup' -and ($output -join "`n") -notmatch '(?m)^Inno Setup 6 Command-Line Compiler\s*$') {
      throw 'packaging requires the Inno Setup 6 bootstrap compiler'
    }
    Write-Host "Build tool ready: $Package (consumer capability probe passed)"
    return $true
  } catch {
    Write-Host "Build tool unavailable: $Package`: $($_.Exception.Message)"
    return $false
  }
}

try {
  New-Item -ItemType Directory -Path $probeRoot | Out-Null
  [IO.File]::WriteAllText((Join-Path $probeRoot 'build.ninja'), (@'
ninja_required_version = 1.10
rule probe
  command = echo build-tool-probe
build probe: probe
default probe
'@ + "`n"), [Text.Encoding]::ASCII)
  # Parse the architecture expressions and modern wizard used by the real
  # installer. Output=no compiles no installer and cannot install anything.
  [IO.File]::WriteAllText((Join-Path $probeRoot 'probe.iss'), @'
[Setup]
AppName=EDR build tool probe
AppVersion=0.0.0
DefaultDirName={tmp}\EDRBuildToolProbe
ArchitecturesAllowed=x64os or arm64
ArchitecturesInstallIn64BitMode=x64os or arm64
WizardStyle=modern
Uninstallable=no
CreateAppDir=no
Output=no
'@, [Text.Encoding]::ASCII)
  $packages = @('ninja')
  if (-not $NinjaOnly) { $packages += 'innosetup' }
  foreach ($package in $packages) {
    if (Test-ReleaseBuildTool $package) { continue }
    $choco = Get-Command choco -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $choco) { throw "Cannot install unavailable build tool '$package': Chocolatey is not on PATH" }
    & $choco.Source install $package -y --no-progress
    if ($LASTEXITCODE -ne 0) { throw "Chocolatey installation of '$package' failed with exit $LASTEXITCODE" }
    if (-not (Test-ReleaseBuildTool $package)) {
      throw "Build tool '$package' is still unavailable after Chocolatey install; inspect the capability probe above and repair the existing tool installation"
    }
  }
} finally {
  if (Test-Path -LiteralPath $probeRoot) { Remove-Item -LiteralPath $probeRoot -Recurse -Force }
}
