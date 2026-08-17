#Requires -Version 5.1
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [ValidateSet("x64", "arm64")]
  [string] $Architecture,
  [string] $GithubEnvPath = $env:GITHUB_ENV
)

$ErrorActionPreference = "Stop"
$repositoryRoot = Split-Path -Parent $PSScriptRoot
& (Join-Path $PSScriptRoot "Validate-DependencyLocks.ps1") -RepositoryRoot $repositoryRoot
$dependencyLock = [IO.File]::ReadAllText((Join-Path $repositoryRoot "dependencies.lock.json")) | ConvertFrom-Json
$visualStudioVersionRange = [string]$dependencyLock.visual_studio.version_range
$vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path -LiteralPath $vswhere -PathType Leaf)) {
  throw "vswhere.exe was not found: $vswhere"
}
$requiredComponents = @("Microsoft.VisualStudio.Component.VC.Tools.x86.x64")
if ($Architecture -eq "arm64") {
  $requiredComponents += "Microsoft.VisualStudio.Component.VC.Tools.ARM64"
}
$installationPath = (& $vswhere -products * -version $visualStudioVersionRange -requires $requiredComponents -property installationPath -latest | Select-Object -First 1)
if ([string]::IsNullOrWhiteSpace([string]$installationPath)) {
  throw "Visual Studio 2022 with the C++ toolchain is required"
}
$installationVersion = (& $vswhere -path $installationPath -property installationVersion | Select-Object -First 1)
if ([string]$installationVersion -notmatch '^17\.') {
  throw "Visual Studio generation mismatch: expected 17.x, actual=$installationVersion"
}
$devCmd = Join-Path $installationPath "Common7\Tools\VsDevCmd.bat"
if (-not (Test-Path -LiteralPath $devCmd -PathType Leaf)) {
  throw "VsDevCmd.bat was not found: $devCmd"
}

$environmentDump = Join-Path $env:RUNNER_TEMP ("vs2022-{0}-{1}.env" -f $Architecture, [Guid]::NewGuid().ToString("N"))
$command = 'call "{0}" -no_logo -arch={1} -host_arch=x64 && set > "{2}"' -f $devCmd, $Architecture, $environmentDump
& $env:ComSpec /d /s /c $command
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $environmentDump -PathType Leaf)) {
  throw "Visual Studio 2022 environment initialization failed for $Architecture"
}
try {
  foreach ($line in [IO.File]::ReadAllLines($environmentDump)) {
    $separator = $line.IndexOf('=')
    if ($separator -le 0) { continue }
    $name = $line.Substring(0, $separator)
    $value = $line.Substring($separator + 1)
    [Environment]::SetEnvironmentVariable($name, $value, 'Process')
    if (-not [string]::IsNullOrWhiteSpace($GithubEnvPath)) {
      Add-Content -LiteralPath $GithubEnvPath -Value ("{0}={1}" -f $name, $value) -Encoding UTF8
    }
  }
} finally {
  Remove-Item -LiteralPath $environmentDump -Force -ErrorAction SilentlyContinue
}

$compiler = (& where.exe cl.exe | Select-Object -First 1)
if ([string]::IsNullOrWhiteSpace([string]$compiler)) {
  throw "cl.exe was not found after Visual Studio 2022 initialization"
}
Write-Host "Visual Studio 2022 ready: version=$installationVersion target=$Architecture compiler=$compiler"
