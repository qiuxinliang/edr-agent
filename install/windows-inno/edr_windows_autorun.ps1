#Requires -Version 5.1
<#
  安装 / 卸载 EDR Agent 的「开机常驻」与可选安装目录 ACL 加固。
  - Install：注册计划任务（SYSTEM、开机触发、无执行时限），并立即启动一次；可选对安装目录做 icacls 加固。
  - Remove：停止任务、结束 edr_agent 进程、重置 ACL、注销任务（供 Inno UninstallRun 调用）。

  说明：edr_agent 为控制台程序，未实现 SCM ServiceMain；以「计划任务 + SYSTEM」实现重启后仍在。
  管理员仍可强制删除文件；加固仅提高普通用户随意改删的成本。正式卸载应使用「程序和功能」中的卸载项（unins000.exe）。
#>
param(
  [Parameter(Mandatory = $true)]
  [ValidateSet("Install", "Remove")]
  [string]$Action,
  [switch]$HardenAcl
)

$ErrorActionPreference = "Stop"
$TaskName = "EdrAgent"
$instDir = $PSScriptRoot

function Stop-AgentProcess {
  Stop-Process -Name "edr_agent" -Force -ErrorAction SilentlyContinue
  Start-Sleep -Milliseconds 400
}

function Remove-ScheduledTaskIfPresent {
  try {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
  } catch {}
  Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
}

function Reset-InstallDirAcl {
  param([string]$Dir)
  if (-not (Test-Path -LiteralPath $Dir)) { return }
  & icacls.exe $Dir /inheritance:e /T /C /Q | Out-Null
}

function Set-InstallDirAclHarden {
  param([string]$Dir)
  if (-not (Test-Path -LiteralPath $Dir)) { return }
  # SID：SYSTEM、Administrators（避免非英文系统上组名本地化问题）
  & icacls.exe $Dir /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" /grant:r "*S-1-5-32-544:(OI)(CI)F" /T /C /Q | Out-Null
}

if ($Action -eq "Remove") {
  Remove-ScheduledTaskIfPresent
  Stop-AgentProcess
  Reset-InstallDirAcl -Dir $instDir
  exit 0
}

# --- Install ---
$exe = Join-Path $instDir "edr_agent.exe"
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
}

$argLine = '--config "' + $cfg + '"'
$sta = New-ScheduledTaskAction -Execute $exe -Argument $argLine -WorkingDirectory $instDir
$trg = New-ScheduledTaskTrigger -AtStartup
$prc = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$set = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
  -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)

Register-ScheduledTask -TaskName $TaskName -Action $sta -Trigger $trg -Principal $prc -Settings $set -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName

exit 0
