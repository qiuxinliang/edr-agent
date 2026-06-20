#Requires -Version 5.1
<#
  安装 / 卸载 FDSecurity 的「开机常驻」与可选安装目录 ACL 加固。
  - Install：注册计划任务（SYSTEM、开机触发、无执行时限）；默认立即启动一次，传 -NoStart 时只注册不启动。
  - Remove：停止任务、结束 FDSensor 进程、按名停止可能残留的 ETW 实时会话、重置 ACL、注销任务（供 Inno UninstallRun 调用）。

  说明：FDSensor 为控制台程序，未实现 SCM ServiceMain；以「计划任务 + SYSTEM」实现重启后仍在。
  管理员仍可强制删除文件；加固仅提高普通用户随意改删的成本。正式卸载应使用「程序和功能」中的卸载项（unins000.exe）。
#>
param(
  [Parameter(Mandatory = $true)]
  [ValidateSet("Install", "Remove")]
  [string]$Action,
  [switch]$HardenAcl,
  [switch]$NoStart
)

$ErrorActionPreference = "Stop"
$TaskName = "FDSecurityAgent"
$LegacyTaskName = "EdrAgent"
$instDir = $PSScriptRoot

function Stop-AgentProcess {
  Stop-Process -Name "FDSensor" -Force -ErrorAction SilentlyContinue
  Stop-Process -Name "edr_agent" -Force -ErrorAction SilentlyContinue
  Start-Sleep -Milliseconds 400
}

function Remove-ScheduledTaskIfPresent {
  foreach ($name in @($TaskName, $LegacyTaskName)) {
    try {
      Stop-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
    } catch {}
    Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction SilentlyContinue
  }
}

function Reset-InstallDirAcl {
  param([string]$Dir)
  if (-not (Test-Path -LiteralPath $Dir)) { return }
  & icacls.exe $Dir /inheritance:e /T /C /Q | Out-Null
}

function Set-InstallDirAclHarden {
  param([string]$Dir)
  if (-not (Test-Path -LiteralPath $Dir)) { return }
  # SID: SYSTEM / Administrators full control; Users read+execute for binaries.
  # agent.toml is tightened separately because it contains endpoint identity.
  & icacls.exe $Dir /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" /grant:r "*S-1-5-32-544:(OI)(CI)F" /grant:r "*S-1-5-32-545:(OI)(CI)RX" /T /C /Q | Out-Null
}

function Set-AgentTomlAcl {
  param([string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) { return }
  # agent.toml contains endpoint identity and policy URLs. Keep it readable by
  # SYSTEM and elevated administrators, but do not inherit broad Users read ACLs.
  try {
    & takeown.exe /F $Path /A 2>$null | Out-Null
  } catch {}
  & icacls.exe $Path /inheritance:r /grant:r "*S-1-5-18:F" /grant:r "*S-1-5-32-544:F" /C /Q | Out-Null
}

function Repair-ExecutableAcl {
  param([string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) { return }
  try {
    & takeown.exe /F $Path /A 2>$null | Out-Null
  } catch {}
  & icacls.exe $Path /grant:r "*S-1-5-18:F" /grant:r "*S-1-5-32-544:F" /grant:r "*S-1-5-32-545:RX" /C /Q | Out-Null
  try {
    Unblock-File -LiteralPath $Path -ErrorAction SilentlyContinue
  } catch {}
}

if ($Action -eq "Remove") {
  Remove-ScheduledTaskIfPresent
  Stop-AgentProcess
  $exeCleanup = Join-Path $instDir "FDSensor.exe"
  if (-not (Test-Path -LiteralPath $exeCleanup)) {
    $exeCleanup = Join-Path $instDir "edr_agent.exe"
  }
  if (Test-Path -LiteralPath $exeCleanup) {
    try {
      & $exeCleanup --etw-uninstall-cleanup
    } catch {}
  }
  Reset-InstallDirAcl -Dir $instDir
  exit 0
}

# --- Install ---
$exe = Join-Path $instDir "FDSensor.exe"
if (-not (Test-Path -LiteralPath $exe)) {
  $exe = Join-Path $instDir "edr_agent.exe"
}
$cfg = Join-Path $instDir "agent.toml"

if (-not (Test-Path -LiteralPath $exe)) {
  Write-Error "Missing $exe"
}
if (-not (Test-Path -LiteralPath $cfg)) {
  Write-Error "Missing $cfg (enroll or copy agent.toml.example before autorun install)"
}

Remove-ScheduledTaskIfPresent
Stop-AgentProcess

if ($HardenAcl) {
  Set-InstallDirAclHarden -Dir $instDir
  Set-AgentTomlAcl -Path $cfg
}
Repair-ExecutableAcl -Path $exe

$argLine = '--config "' + $cfg + '"'
$sta = New-ScheduledTaskAction -Execute $exe -Argument $argLine -WorkingDirectory $instDir
$trg = New-ScheduledTaskTrigger -AtStartup
$prc = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$set = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
  -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)

Register-ScheduledTask -TaskName $TaskName -Action $sta -Trigger $trg -Principal $prc -Settings $set -Force | Out-Null
if (-not $NoStart) {
  Start-ScheduledTask -TaskName $TaskName
}

exit 0
