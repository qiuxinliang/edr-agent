#Requires -Version 5.1
<#
  Builds FDSecuritySetup-bundled.exe (full layout: staged exe/DLLs + preprocess TOML + scripts).
  Run on Windows from the monorepo root OR from this directory.

  Default staging folder (relative to this .iss file): ..\..\..\edr-agent-win_2-2

  Examples:
    .\edr-agent\install\windows-inno\Build-BundledInstaller.ps1
    .\Build-BundledInstaller.ps1 -AppVersion 3.2.0
    .\Build-BundledInstaller.ps1 -BinDir "D:\staged\edr-release" -Inno "C:\Program Files (x86)\Inno Setup 6\ISCC.exe"
#>
param(
    [string] $Inno = "",
    [string] $BinDir = "",
    [string] $AppVersion = "",
    [ValidateSet("amd64", "arm64")]
    [string] $TargetArch = "amd64",
    [ValidateSet("signed", "unsigned")]
    [string] $SignatureStatus = "unsigned",
    [string] $CollectorArch = "",
    [switch] $SkipForensicCollectorBuild,
    [switch] $AllowPowerShellFallback
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

function Assert-YaraRuntimeDlls {
    param([string] $Dir)
    $dlls = @(Get-ChildItem -Path $Dir -Filter "*.dll" -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '(?i)yara.*\.dll$' })
    if (-not $dlls -or $dlls.Count -lt 1) {
        Write-Warning "No YARA runtime DLL found in $Dir; vcpkg libyara may be statically linked for this triplet."
        return
    }
    Write-Host "Verified YARA runtime DLL(s): $($dlls.Name -join ', ')"
}

function Assert-WinDivertRuntime {
    param([string] $AgentRoot)
    $runtimeDir = Join-Path $AgentRoot "third_party\windivert\runtime\amd64"
    $expected = @{
        "WinDivert.dll" = "c1e060ee19444a259b2162f8af0f3fe8c4428a1c6f694dce20de194ac8d7d9a2"
        "WinDivert64.sys" = "8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2"
    }
    foreach ($name in $expected.Keys) {
        $path = Join-Path $runtimeDir $name
        if (-not (Test-Path -LiteralPath $path)) {
            throw "Missing pinned WinDivert runtime: $path"
        }
        $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash.ToLowerInvariant()
        if ($actual -ne $expected[$name]) {
            throw "WinDivert hash mismatch for $name. expected=$($expected[$name]) actual=$actual"
        }
    }
    foreach ($path in @(
        (Join-Path $AgentRoot "third_party\windivert\LICENSE"),
        (Join-Path $AgentRoot "third_party\windivert\SOURCE.json")
    )) {
        if (-not (Test-Path -LiteralPath $path)) { throw "Missing WinDivert legal/provenance asset: $path" }
    }
    Write-Host "Verified pinned WinDivert 2.2.2 x64 runtime."
}

if (-not $BinDir) {
    $monorepoRoot = (Resolve-Path (Join-Path $scriptDir "..\..\..")).Path
    $BinDir = Join-Path $monorepoRoot "edr-agent-win_2-2"
}
$binExe = Join-Path $BinDir "FDSensor.exe"
$legacyBinExe = Join-Path $BinDir "edr_agent.exe"
if (-not (Test-Path -LiteralPath $binExe)) {
    if (Test-Path -LiteralPath $legacyBinExe) {
        Copy-Item -LiteralPath $legacyBinExe -Destination $binExe -Force
        Write-Warning "FDSensor.exe was not found; created compatibility alias from edr_agent.exe in staging folder."
    } else {
        throw "FDSensor.exe not found: $binExe. Pass -BinDir to your staging folder."
    }
}
Assert-YaraRuntimeDlls -Dir $BinDir

$agentRoot = (Resolve-Path (Join-Path $scriptDir "..\..")).Path
$repoRoot = (Resolve-Path (Join-Path $scriptDir "..\..\..")).Path
$forensicRulesDir = Join-Path $agentRoot "rules\forensic"
$requiredForensicRules = @(
    "VERSION",
    "credential_theft.yar",
    "injection.yar",
    "lateral_movement.yar",
    "packers.yar",
    "privilege_escalation.yar",
    "suspicious.yar"
)
foreach ($rule in $requiredForensicRules) {
    $rulePath = Join-Path $forensicRulesDir $rule
    if (-not (Test-Path -LiteralPath $rulePath -PathType Leaf)) {
        throw "Missing required forensic YARA rule asset: $rulePath"
    }
}
$forensicRuleFiles = @(Get-ChildItem -LiteralPath $forensicRulesDir -File -ErrorAction Stop | Where-Object {
    $_.Extension -eq ".yar" -or $_.Extension -eq ".yara"
})
if ($forensicRuleFiles.Count -lt 1) {
    throw "Forensic YARA rules directory has no .yar/.yara files: $forensicRulesDir"
}
Write-Host "Verified forensic YARA rules: $($forensicRuleFiles.Count) file(s)."
$archCheck = Join-Path $agentRoot "scripts\Assert-WindowsPeArchitecture.ps1"
if (-not (Test-Path -LiteralPath $archCheck)) { throw "Missing architecture verifier: $archCheck" }
$installerBootstrapArchCheck = Join-Path $agentRoot "scripts\Assert-WindowsInstallerBootstrapArchitecture.ps1"
if (-not (Test-Path -LiteralPath $installerBootstrapArchCheck)) {
    throw "Missing installer bootstrap architecture verifier: $installerBootstrapArchCheck"
}
& $archCheck -Path $binExe -Architecture $TargetArch
if ($TargetArch -eq "amd64") {
    Assert-WinDivertRuntime -AgentRoot $agentRoot
} else {
    Write-Host "ARM64 package: WinDivert x64 DLL/driver intentionally excluded."
}

function Resolve-CollectorArch {
    param([string] $Raw)
    $v = ""
    if ($Raw) { $v = $Raw.Trim().ToLowerInvariant() }
    if (-not $v -and $env:EDR_BUNDLE_ARCH) { $v = $env:EDR_BUNDLE_ARCH.Trim().ToLowerInvariant() }
    if (-not $v) { $v = "amd64" }
    switch ($v) {
        "x64" { return "amd64" }
        "x86_64" { return "amd64" }
        "amd64" { return "amd64" }
        "aarch64" { return "arm64" }
        "arm64" { return "arm64" }
        default { throw "Unsupported CollectorArch '$Raw' (allow: amd64|arm64)" }
    }
}

function Build-AndStageForensicCollector {
    param(
        [string] $RepoRoot,
        [string] $BinDir,
        [string] $Arch,
        [switch] $Skip
    )
    if ($Skip) {
        Write-Warning "SkipForensicCollectorBuild set; installer will use existing BinDir\collector content."
        return
    }
    $fcRoot = Join-Path $RepoRoot "forensic-collector"
    if (-not (Test-Path -LiteralPath $fcRoot)) {
        Write-Warning "forensic-collector source not found: $fcRoot. Installer will use existing BinDir\collector content."
        return
    }
    $go = Get-Command go -ErrorAction SilentlyContinue
    if (-not $go) {
        Write-Warning "go executable not found. Cannot rebuild forensic_collector.exe; installer will use existing BinDir\collector content."
        return
    }
    $distDir = Join-Path $fcRoot ("dist\win-" + $Arch)
    $outExe = Join-Path $distDir "forensic_collector.exe"
    New-Item -ItemType Directory -Force -Path $distDir | Out-Null
    Push-Location $fcRoot
    $oldGoos = $env:GOOS
    $oldGoarch = $env:GOARCH
    $oldCgo = $env:CGO_ENABLED
    try {
        $env:GOOS = "windows"
        $env:GOARCH = $Arch
        $env:CGO_ENABLED = "0"
        & $go.Source build -trimpath -ldflags "-s -w" -o $outExe .
        if ($LASTEXITCODE -ne 0) {
            throw "go build forensic_collector.exe failed with exit code $LASTEXITCODE"
        }
    } finally {
        $env:GOOS = $oldGoos
        $env:GOARCH = $oldGoarch
        $env:CGO_ENABLED = $oldCgo
        Pop-Location
    }
    $collectorDir = Join-Path $BinDir "collector"
    New-Item -ItemType Directory -Force -Path $collectorDir | Out-Null
    $dest = Join-Path $collectorDir "forensic_collector.exe"
    Copy-Item -LiteralPath $outExe -Destination $dest -Force
    $sha = (Get-FileHash -Algorithm SHA256 -LiteralPath $dest).Hash.ToLowerInvariant()
    Write-Host "Staged forensic_collector.exe: arch=$Arch sha256=$sha path=$dest"
}

$workerExe = Join-Path $BinDir "FDSecurityInstallerWorker.exe"
if (-not (Test-Path -LiteralPath $workerExe)) {
    $message = "FDSecurityInstallerWorker.exe not found in $BinDir. Release installers require the native worker; pass -AllowPowerShellFallback only for development/lab builds."
    if ($AllowPowerShellFallback) {
        Write-Warning $message
    } else {
        throw $message
    }
}
if (Test-Path -LiteralPath $workerExe) {
    & $archCheck -Path $workerExe -Architecture $TargetArch
}

$versionFile = Join-Path $BinDir "VERSION"
$sourceVersionFile = Join-Path $agentRoot "VERSION"
if (-not $AppVersion) {
    foreach ($candidate in @($versionFile, $sourceVersionFile)) {
        if (Test-Path -LiteralPath $candidate) {
            $candidateVersion = ([System.IO.File]::ReadAllText($candidate)).Trim()
            if ($candidateVersion) {
                $AppVersion = $candidateVersion
                break
            }
        }
    }
}
if (-not $AppVersion) {
    throw "AppVersion was not provided and no VERSION file was found. Pass -AppVersion or stage a VERSION file next to FDSensor.exe."
}
[System.IO.File]::WriteAllText($versionFile, $AppVersion + [Environment]::NewLine, [System.Text.Encoding]::ASCII)
Write-Host "Staged VERSION: $AppVersion"
$archFile = Join-Path $BinDir "ARCH"
[System.IO.File]::WriteAllText($archFile, $TargetArch + [Environment]::NewLine, [System.Text.Encoding]::ASCII)
$capabilityWriter = Join-Path $agentRoot "scripts\write_windows_package_capabilities.ps1"
if (-not (Test-Path -LiteralPath $capabilityWriter -PathType Leaf)) {
    throw "Missing package capability writer: $capabilityWriter"
}
& $capabilityWriter `
    -OutputPath (Join-Path $BinDir "package-capabilities.json") `
    -TargetArch $TargetArch `
    -SignatureStatus $SignatureStatus

$collectorArchInput = if ($CollectorArch) { $CollectorArch } else { $TargetArch }
$resolvedCollectorArch = Resolve-CollectorArch $collectorArchInput
if ($resolvedCollectorArch -ne $TargetArch) {
    throw "CollectorArch '$resolvedCollectorArch' must match TargetArch '$TargetArch'"
}
Build-AndStageForensicCollector -RepoRoot $repoRoot -BinDir $BinDir -Arch $resolvedCollectorArch -Skip:$SkipForensicCollectorBuild

$runtimePeFiles = @(Get-ChildItem -LiteralPath $BinDir -File -ErrorAction Stop | Where-Object {
    $_.Extension -ieq ".exe" -or $_.Extension -ieq ".dll"
})
if ($runtimePeFiles.Count -lt 1) { throw "No Runtime EXE/DLL files found for architecture validation: $BinDir" }
foreach ($runtimePeFile in $runtimePeFiles) {
    & $archCheck -Path $runtimePeFile.FullName -Architecture $TargetArch
}
Write-Host "Verified Runtime PE closure: arch=$TargetArch files=$($runtimePeFiles.Count)"

$pre = Join-Path $repoRoot "edr-backend\platform\config\agent_preprocess_rules_v1.toml"
if (-not (Test-Path -LiteralPath $pre)) {
    Write-Warning "Preprocess TOML missing: $pre — run edr-backend/platform/config/generate_agent_preprocess_rules.py first."
}

if (-not (Test-Path -LiteralPath $Inno)) {
    throw "Inno Setup compiler not found: $Inno. Install Inno Setup 6 or pass -Inno to ISCC.exe"
}

# ISCC: paths with spaces need /DNAME="C:\a b"
if ($BinDir -match "\s") { $binDef = '/DEDR_BIN_DIR="' + $BinDir + '"' } else { $binDef = "/DEDR_BIN_DIR=$BinDir" }
$archDefs = @("/DEDR_TARGET_ARCH=$TargetArch")
if ($TargetArch -eq "arm64") { $archDefs += "/DEDR_TARGET_ARM64=1" }
$fallbackDefs = @()
if ($AllowPowerShellFallback) {
    $fallbackDefs += "/DEDR_ALLOW_POWERSHELL_FALLBACK=1"
}
& $Inno $binDef "/DMyAppVersion=$AppVersion" @archDefs @fallbackDefs $iss
if ($LASTEXITCODE -ne 0) {
    throw "ISCC failed with exit $LASTEXITCODE"
}
$outDir = Join-Path $scriptDir "Output"
$out = Join-Path $outDir "FDSecuritySetup-bundled.exe"
if (Test-Path -LiteralPath $out) {
    & $installerBootstrapArchCheck -Path $out -PayloadArchitecture $TargetArch
    [System.IO.File]::WriteAllText($out + ".arch", $TargetArch + [Environment]::NewLine, [System.Text.Encoding]::ASCII)
    Write-Host "OK: $out"
    $legacyOut = Join-Path $outDir "EDRAgentSetup-bundled.exe"
    Copy-Item -LiteralPath $out -Destination $legacyOut -Force
    Copy-Item -LiteralPath ($out + ".arch") -Destination ($legacyOut + ".arch") -Force
    Write-Host "OK: legacy compatibility alias: $legacyOut"
} else {
    Write-Warning "ISCC reported success but $out not found; check ISCC log."
}
