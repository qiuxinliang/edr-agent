#Requires -Version 5.1
# Harmless EDR end-to-end smoke. Run only on lab/VM. Rule IDs: see edr-backend .../dynamic_rules_v1.json
# P0 直出联调：Agent 上设 EDR_P0_DIRECT_EMIT=1 且 EDR_BEHAVIOR_ENCODING=protobuf 后，平台 alerts 应出现
#   user_subject_json.subject_type=edr_dynamic_rule 或 Title 为 [规则] R-…（见 EDR_P0_DIRECT_EMIT_E2E.md）
# Do not use multiline <# #> help here: some hosts save UTF-8 without BOM; PS 5.1 may break parsing.
# Install copy: keep file as UTF-8 with BOM, or use ASCII-only. See README in repo.
param(
    [int] $Iterations = 5,
    [int] $StaggerMs = 150,
    [switch] $DryRun
)

if ($env:EDR_SMOKE_LOOPS -match '^\d+$') { $Iterations = [int]$env:EDR_SMOKE_LOOPS }
if ($env:EDR_SMOKE_STAGGER_MS -match '^\d+$') { $StaggerMs = [int]$env:EDR_SMOKE_STAGGER_MS }

$ErrorActionPreference = 'Continue'
Write-Host "edr_platform_stack_smoke.ps1: starting  Iterations=$Iterations  StaggerMs=${StaggerMs}ms  DryRun=$DryRun  (PID=$PID)" -ForegroundColor Cyan
$round = 0
$outDir = Join-Path $env:TEMP ("edr_smoke_{0:yyyyMMdd_HHmmss}" -f (Get-Date))
if (-not $DryRun) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }

function Invoke-SmokeStep {
    param(
        [string] $Name,
        [scriptblock] $Block
    )
    Write-Host ("  [{0:00}] {1}" -f $script:round, $Name) -ForegroundColor Yellow
    if ($DryRun) { return }
    try {
        & $Block
    } catch {
        Write-Host "    (warning) $Name : $_" -ForegroundColor DarkGray
    }
    Start-Sleep -Milliseconds $StaggerMs
}

function B64-EncCommand([string] $s) {
    $bytes = [Text.Encoding]::Unicode.GetBytes($s)
    return [Convert]::ToBase64String($bytes)
}

for ($g = 1; $g -le $Iterations; $g++) {
    $round = $g
    Write-Host "`n=== EDR platform stack smoke: round $g / $Iterations ===" -ForegroundColor Cyan
    if (-not $DryRun) { Start-Sleep -Milliseconds $StaggerMs }

    # R-EXEC-001 encoded command
    $enc1 = B64-EncCommand "Write-Output 'r-exec-001-smoke'"
    Invoke-SmokeStep "R-EXEC-001: powershell -encodedcommand" {
        Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
            -ArgumentList @('-NoLogo', '-EncodedCommand', $enc1) -NoNewWindow -Wait
    }
    # R-EXEC-001 frombase64string
    Invoke-SmokeStep "R-EXEC-001: frombase64string" {
        $b = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('edr-smoke-b64'))
        & powershell.exe -NoP -Command "[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('$b')) | Out-Null"
    }

    # R-EXEC-002 -WindowStyle hidden -NoProfile
    Invoke-SmokeStep "R-EXEC-002: -WindowStyle hidden + -NoProfile" {
        Start-Process -FilePath "powershell.exe" -ArgumentList '-NoProfile', '-WindowStyle', 'hidden', '-Command', 'hostname' -NoNewWindow -Wait
    }

    # R-EXEC-005 IWR/IRM + http URL
    Invoke-SmokeStep "R-EXEC-005: IWR+URL" {
        & powershell.exe -NoP -Command "try { Invoke-WebRequest 'https://example.com' -UseBasicParsing -TimeoutSec 5 } catch {}"
    }
    Invoke-SmokeStep "R-EXEC-005: IRM+URL" {
        & powershell.exe -NoP -Command "try { Invoke-RestMethod 'https://httpbin.org/get' -TimeoutSec 5 } catch {}"
    }

    # R-FILELESS-001
    Invoke-SmokeStep "R-FILELESS-001: IEX" {
        & powershell.exe -NoP -Command "IEX ('Write-Output ok')"
    }
    Invoke-SmokeStep "R-FILELESS-001: Invoke-Expression" {
        & powershell.exe -NoP -Command "Invoke-Expression '1+1' | Out-Null"
    }

    # R-DISC-001 discovery via cmd
    Invoke-SmokeStep "R-DISC-001: cmd /c discovery" {
        $exe = "$env:ComSpec"
        foreach ($line in @(
            'whoami', 'systeminfo', 'tasklist /FI "STATUS eq running"', 'hostname', 'ipconfig /all'
        )) {
            Start-Process -FilePath $exe -ArgumentList @('/c', $line) -NoNewWindow -Wait
        }
    }

    # R-LOLBIN-003 certutil
    $cuOut = Join-Path $outDir "smoke_ct_$g.bin"
    Invoke-SmokeStep "R-LOLBIN-003: certutil -urlcache" {
        if (Get-Command certutil.exe -ErrorAction SilentlyContinue) {
            & certutil.exe -urlcache -split -f "https://example.com" $cuOut 2>&1 | Out-Null
        }
    }

    # R-LOLBIN-004 mshta
    Invoke-SmokeStep "R-LOLBIN-004: mshta" {
        if (Get-Command mshta.exe -ErrorAction SilentlyContinue) {
            Start-Process "mshta.exe" -ArgumentList "https://example.com" -WindowStyle Hidden
            Start-Sleep 2
            try { Get-Process -Name 'mshta' -ErrorAction SilentlyContinue | Stop-Process -Force } catch {}
        }
    }
    Invoke-SmokeStep "R-LOLBIN-004: mshta javascript" {
        if (Get-Command mshta.exe -ErrorAction SilentlyContinue) {
            Start-Process "mshta.exe" -ArgumentList 'about:' -WindowStyle Hidden
            Start-Sleep 1
            try { Get-Process -Name 'mshta' -ErrorAction SilentlyContinue | Stop-Process -Force } catch {}
        }
    }

    # R-LOLBIN-002 rundll32 + https
    Invoke-SmokeStep "R-LOLBIN-002: rundll32 + https URL" {
        if (Get-Command rundll32.exe -ErrorAction SilentlyContinue) {
            Start-Process "rundll32.exe" -ArgumentList 'url.dll,FileProtocolHandler','https://example.com' -NoNewWindow -PassThru | ForEach-Object { try { $_.WaitForExit(5000) } catch {} } | Out-Null
        }
    }

    # R-LOLBIN-001 regsvr32
    Invoke-SmokeStep "R-LOLBIN-001: regsvr32 /i:https" {
        if (Get-Command regsvr32.exe -ErrorAction SilentlyContinue) {
            Start-Process "regsvr32.exe" -ArgumentList @(
                '/s', '/n', '/u', '/i:https://example.com/invalid.sct', 'scrobj.dll'
            ) -NoNewWindow -Wait
        }
    }

    # R-LOLBIN-005 wmic /node
    Invoke-SmokeStep "R-LOLBIN-005: wmic /node + process call create" {
        if (Get-Command wmic.exe -ErrorAction SilentlyContinue) {
            $hn = Join-Path $env:WinDir 'System32\HOSTNAME.EXE'
            $null = & wmic.exe /node:127.0.0.1 process call create "`"$hn`"" 2>&1
        }
    }

    # R-LOLBIN-009 bitsadmin
    Invoke-SmokeStep "R-LOLBIN-009: bitsadmin /transfer" {
        if (Get-Command bitsadmin.exe -ErrorAction SilentlyContinue) {
            $f = Join-Path $outDir "smoke_bit_$g.dat"
            $job = "edrSmk{0:0000}" -f (Get-Random)
            $null = & bitsadmin.exe /transfer $job /download /priority normal "https://example.com" $f 2>&1
        }
    }

    # R-LOLBIN-006 msiexec + https
    Invoke-SmokeStep "R-LOLBIN-006: msiexec+https" {
        if (Get-Command msiexec.exe -ErrorAction SilentlyContinue) {
            $msi = "https://example.com/not-a-real.msi"
            Start-Process "msiexec.exe" -ArgumentList @('/I', $msi) -NoNewWindow -PassThru | ForEach-Object { $_.WaitForExit(5000) | Out-Null }
        }
    }

    # R-CRED-005 cmdkey
    Invoke-SmokeStep "R-CRED-005: cmdkey /list" {
        if (Get-Command cmdkey.exe -ErrorAction SilentlyContinue) {
            & cmdkey.exe /list 1>$null
        }
    }

    # R-LMOVE-004/005 admin$ path in cmdline (no PsExec install)
    Invoke-SmokeStep 'R-LMOVE-004/005: admin$ echo' {
        & cmd.exe /c "echo psexec64.exe \\192.0.2.1\admin$"
        & cmd.exe /c "net use \\192.0.2.1\admin$" 2>$null
    }

    # bcdedit read only (not ransomware-style delete)
    Invoke-SmokeStep "bcdedit: enum current" {
        if (Get-Command bcdedit.exe -ErrorAction SilentlyContinue) {
            & bcdedit.exe /enum "{current}" 1>$null
        }
    }
}

# cleanup temp
if (-not $DryRun) {
    try {
        Get-ChildItem $outDir -Recurse -File -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
        Remove-Item $outDir -Recurse -Force -ErrorAction SilentlyContinue
    } catch {}
}

Write-Host "`nDone. Iterations=$Iterations  StaggerMs=$StaggerMs" -ForegroundColor Green
Write-Host "Check: endpoint_events, behavior alerts, alerts.dynamic_rule_hits_json (if ruleenrich is on)." -ForegroundColor Gray
Write-Host "If you see behavior_0 / missing cmdline: set Agent EDR_BEHAVIOR_ENCODING=protobuf to match platform pbwire." -ForegroundColor Gray
exit 0
