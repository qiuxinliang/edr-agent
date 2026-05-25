<#
.SYNOPSIS
    更新 edr-agent 项目中所有版本号引用为指定版本。

.DESCRIPTION
    接收 a.b.c 格式的版本号作为唯一参数，自动扫描并更新以下文件中的版本号：
      - vcpkg.json                  (version-string)
      - include/edr/agent_update.h (EDR_AGENT_VERSION_STRING fallback)
      - src/transport/ingest_http.c (EDR_AGENT_VERSION_STRING fallback)
      - CMakeLists.txt              (project VERSION)
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
        File        = 'vcpkg.json'
        Pattern     = '("version-string"\s*:\s*)"[^"]*"'
        Replacement = "`$1`"$Version`""
        Desc        = 'vcpkg manifest version-string'
    },
    @{
        File        = 'include/edr/agent_update.h'
        Pattern     = '(#define\s+EDR_AGENT_VERSION_STRING\s+)"[^"]*"'
        Replacement = "`$1`"$Version`""
        Desc        = 'EDR_AGENT_VERSION_STRING header fallback'
    },
    @{
        File        = 'src/transport/ingest_http.c'
        Pattern     = '(#define\s+EDR_AGENT_VERSION_STRING\s+)"[^"]*"'
        Replacement = "`$1`"$Version`""
        Desc        = 'EDR_AGENT_VERSION_STRING transport fallback'
    },
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
