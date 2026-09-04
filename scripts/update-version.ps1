<#
.SYNOPSIS
    更新 edr-agent 项目的发布版本，保持依赖闭包标识不变。

.DESCRIPTION
    接收 a.b.c 格式的版本号作为唯一参数，更新 CMakeLists.txt 中的
    project VERSION。vcpkg.json 描述的是锁定依赖闭包，必须在不同 Agent
    发布版本之间保持不变，否则会使预构建制品永远无法命中。
    EDR_AGENT_VERSION_STRING 运行时版本由 CMake/CI 注入；源码 fallback 必须保持 unknown，
    避免漏注入时伪装成真实旧版本。
    支持干跑模式（-DryRun），仅报告将会修改的内容而不实际修改文件。

.PARAMETER Version
    新版本号，格式为 a.b.c（如 1.2.3）。

.PARAMETER DryRun
    仅预览将要修改的内容，不实际写入文件。

.EXAMPLE
    ./scripts/update-version.ps1 1.2.3
    ./scripts/update-version.ps1 1.2.3 -DryRun
#>

param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidatePattern('^\d+\.\d+\.\d+$')]
    [string]$Version,

    [Parameter()]
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'

# ── 版本解析 ──────────────────────────────────────────────
$parts = $Version -split '\.'
$Major = [int]$parts[0]
$Minor = [int]$parts[1]
$Patch = [int]$parts[2]

# ── 更新规则定义 ──────────────────────────────────────────
# 每项包含: File (相对路径), Pattern (regex), Replacement (替换文本), Desc (描述)
$Rules = @(
    @{
        File        = 'CMakeLists.txt'
        Pattern     = '(?s)(project\(\s*edr_agent\b.*?\bVERSION\s+)[0-9]+\.[0-9]+\.[0-9]+(.*?\))'
        Replacement = '${1}' + $Version + '${2}'
        Desc        = 'CMake project() VERSION'
    }
)

# ── 执行更新 ──────────────────────────────────────────────
$UpdatedCount = 0
$SkippedCount = 0
$Report = @()

Push-Location $PSScriptRoot/..
try {
    $DependencyManifest = 'vcpkg.json'
    $DependencyManifestHashBefore = $null
    if (Test-Path -LiteralPath $DependencyManifest -PathType Leaf) {
        $DependencyManifestHashBefore = (Get-FileHash -LiteralPath $DependencyManifest -Algorithm SHA256).Hash
    }

    foreach ($Rule in $Rules) {
        $File = $Rule.File
        $Desc = $Rule.Desc

        if (-not (Test-Path -LiteralPath $File)) {
            $msg = "[SKIP] $File — file not found ($Desc)"
            Write-Warning $msg
            $Report += $msg
            $SkippedCount++
            continue
        }

        $Original = Get-Content -LiteralPath $File -Raw
        $Updated  = $Original -replace $Rule.Pattern, $Rule.Replacement

        if ($Original -ceq $Updated) {
            $msg = "[NOCHG] $File — pattern not matched ($Desc)"
            Write-Host $msg
            $Report += $msg
            $SkippedCount++
            continue
        }

        if ($DryRun) {
            Write-Host "[DRYRUN] Would update: $File ($Desc)"
            Write-Host "         → $Version"
            $Report += "[DRYRUN] $File ($Desc) → $Version"
            $UpdatedCount++
        }
        else {
            Set-Content -LiteralPath $File -Value $Updated -NoNewline
            Write-Host "[OK] $File ($Desc) → $Version"
            $Report += "[OK] $File ($Desc) → $Version"
            $UpdatedCount++
        }
    }

    $CMakeFile = 'CMakeLists.txt'
    if (Test-Path -LiteralPath $CMakeFile) {
        $CMakeText = Get-Content -LiteralPath $CMakeFile -Raw
        $EscapedVersion = [regex]::Escape($Version)
        if ($CMakeText -match '(?m)^\s*\$\d+\.\d+\.\d+') {
            Write-Error "CMakeLists.txt appears corrupted by a regex replacement (line starts with `$<version>)."
            exit 1
        }
        if ($CMakeText -notmatch "(?s)project\(\s*edr_agent\b.*?\bVERSION\s+$EscapedVersion\b") {
            Write-Error "CMakeLists.txt project() VERSION was not updated to $Version."
            exit 1
        }
    }

    foreach ($FallbackFile in @('include/edr/agent_update.h', 'src/core/agent.c', 'src/transport/ingest_http.c', 'src/transport/grpc_client_impl.cpp')) {
        if (-not (Test-Path -LiteralPath $FallbackFile)) {
            continue
        }
        $FallbackText = Get-Content -LiteralPath $FallbackFile -Raw
        if ($FallbackText -match '#define\s+EDR_AGENT_VERSION_STRING\s+"(?!unknown")[^"]+"') {
            Write-Error "$FallbackFile contains a concrete EDR_AGENT_VERSION_STRING fallback. Keep fallbacks as `"unknown`" and inject the real version from CMake/CI."
            exit 1
        }
    }

    if ($DependencyManifestHashBefore) {
        $DependencyManifestHashAfter = (Get-FileHash -LiteralPath $DependencyManifest -Algorithm SHA256).Hash
        if ($DependencyManifestHashAfter -ne $DependencyManifestHashBefore) {
            throw 'vcpkg.json changed while updating the Agent version; dependency closure identity must remain release-invariant'
        }
    }
}
finally {
    Pop-Location
}

# ── 输出报告 ──────────────────────────────────────────────
Write-Host ''
Write-Host '========================================'
Write-Host '  Version Update Report'
Write-Host "  New version : $Version"
Write-Host "  Major.Minor.Patch : $Major.$Minor.$Patch"
Write-Host "  Files updated : $UpdatedCount"
Write-Host "  Files skipped : $SkippedCount"
if ($DryRun) {
    Write-Host '  Mode : DRY RUN (no files modified)'
}
Write-Host '========================================'
foreach ($line in $Report) {
    Write-Host "  $line"
}
Write-Host ''

if ($UpdatedCount -eq 0 -and $SkippedCount -gt 0) {
    Write-Warning "No files were updated. Check the patterns or file paths."
}
elseif ($UpdatedCount -eq 0 -and $SkippedCount -eq 0) {
    Write-Error "No rules defined or no files scanned."
    exit 1
}

exit 0
