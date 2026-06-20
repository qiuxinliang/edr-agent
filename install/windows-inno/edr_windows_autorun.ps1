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
  & icacls.exe $Dir /grant:r "*S-1-5-18:(OI)(CI)F" /grant:r "*S-1-5-32-544:(OI)(CI)F" /grant:r "*S-1-5-32-545:(OI)(CI)RX" /C /Q | Out-Null
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

function Repair-UninstallerAcls {
  param([string]$Dir)
  if (-not (Test-Path -LiteralPath $Dir)) { return }

  $entries = @(
    @{ Name = "unins000.exe"; Grant = "*S-1-5-32-545:RX" },
    @{ Name = "unins000.dat"; Grant = "*S-1-5-32-545:R" }
  )
  foreach ($entry in $entries) {
    $path = Join-Path $Dir $entry.Name
    try {
      if (Test-Path -LiteralPath $path) {
        & icacls.exe $path /grant:r "*S-1-5-18:F" /grant:r "*S-1-5-32-544:F" /grant:r $entry.Grant /C /Q | Out-Null
        try { Unblock-File -LiteralPath $path -ErrorAction SilentlyContinue } catch {}
      }
    } catch {}
  }
}

function Repair-RuntimeDependencyAcls {
  param([string]$Dir)
  if (-not (Test-Path -LiteralPath $Dir)) { return }
  try {
    & icacls.exe $Dir /grant:r "*S-1-5-18:(OI)(CI)F" /grant:r "*S-1-5-32-544:(OI)(CI)F" /grant:r "*S-1-5-32-545:(OI)(CI)RX" /C /Q | Out-Null
  } catch {}

  foreach ($pattern in @("*.exe", "*.dll", "*.ps1", "*.toml", "*.json", "*.enc", "models\*", "edr_config\*")) {
    try {
      Get-ChildItem -Path (Join-Path $Dir $pattern) -Force -Recurse -ErrorAction SilentlyContinue |
        ForEach-Object {
          try { Unblock-File -LiteralPath $_.FullName -ErrorAction SilentlyContinue } catch {}
        }
    } catch {}
  }
  Repair-UninstallerAcls -Dir $Dir
}

function Repair-SensitiveRuntimeAcls {
  param([string]$Dir)
  if (-not (Test-Path -LiteralPath $Dir)) { return }

  foreach ($sub in @("certs", "queue", "evidence", "state", "logs", "diagnostics", "upload_outbox")) {
    $path = Join-Path $Dir $sub
    try {
      if (-not (Test-Path -LiteralPath $path)) {
        New-Item -ItemType Directory -Path $path -Force | Out-Null
      }
      & icacls.exe $path /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" /grant:r "*S-1-5-32-544:(OI)(CI)F" /T /C /Q | Out-Null
    } catch {}
  }

  foreach ($path in @((Join-Path $Dir "agent.toml"), (Join-Path $Dir "certs\*.pem"), (Join-Path $Dir "certs\*.key"), (Join-Path $Dir "certs\*.pfx"))) {
    try {
      Get-ChildItem -Path $path -Force -ErrorAction SilentlyContinue |
        ForEach-Object {
          try { & takeown.exe /F $_.FullName /A 2>$null | Out-Null } catch {}
          try { & icacls.exe $_.FullName /inheritance:r /grant:r "*S-1-5-18:F" /grant:r "*S-1-5-32-544:F" /C /Q | Out-Null } catch {}
        }
    } catch {}
  }

  foreach ($pattern in @("*.exe", "*.dll", "*.ps1", "*.json", "*.enc", "*.example", "*.txt", "edr_config\*", "models\*")) {
    try {
      Get-ChildItem -Path (Join-Path $Dir $pattern) -Force -Recurse -ErrorAction SilentlyContinue |
        ForEach-Object {
          try { & icacls.exe $_.FullName /grant:r "*S-1-5-18:F" /grant:r "*S-1-5-32-544:F" /grant:r "*S-1-5-32-545:RX" /C /Q | Out-Null } catch {}
          try { Unblock-File -LiteralPath $_.FullName -ErrorAction SilentlyContinue } catch {}
        }
    } catch {}
  }
  Repair-UninstallerAcls -Dir $Dir
}

function Quote-ForSingleQuotedPowerShell {
  param([string]$Value)
  return "'" + ($Value -replace "'", "''") + "'"
}

function Write-TaskLauncher {
  param([string]$Exe, [string]$Config, [string]$Dir)
  $launcher = Join-Path $Dir "FDSensorTaskLaunch.ps1"
  $logDir = Join-Path $Dir "logs"
  $logPath = Join-Path $logDir "startup-task.log"
  $stdoutPath = Join-Path $logDir "startup-agent.stdout.log"
  $stderrPath = Join-Path $logDir "startup-agent.stderr.log"
  $exeLit = Quote-ForSingleQuotedPowerShell $Exe
  $cfgLit = Quote-ForSingleQuotedPowerShell $Config
  $dirLit = Quote-ForSingleQuotedPowerShell $Dir
  $logDirLit = Quote-ForSingleQuotedPowerShell $logDir
  $logPathLit = Quote-ForSingleQuotedPowerShell $logPath
  $stdoutPathLit = Quote-ForSingleQuotedPowerShell $stdoutPath
  $stderrPathLit = Quote-ForSingleQuotedPowerShell $stderrPath
  $body = @"
#Requires -Version 5.1
`$ErrorActionPreference = "SilentlyContinue"
`$exe = $exeLit
`$cfg = $cfgLit
`$wd = $dirLit
`$logDir = $logDirLit
`$logPath = $logPathLit
`$stdoutPath = $stdoutPathLit
`$stderrPath = $stderrPathLit
function Quote-FDNativeArg {
  param([string]`$Value)
  if (`$null -eq `$Value) { return '""' }
  return '"' + (`$Value -replace '"', '\"') + '"'
}
function Write-FDTaskLog {
  param([string]`$Message)
  try {
    if (-not (Test-Path -LiteralPath `$logDir)) {
      New-Item -ItemType Directory -Path `$logDir -Force | Out-Null
    }
    Add-Content -LiteralPath `$logPath -Value ((Get-Date).ToString("o") + " " + `$Message) -Encoding UTF8
  } catch {}
}
Write-FDTaskLog "launcher_start user=`$([Security.Principal.WindowsIdentity]::GetCurrent().Name)"
Write-FDTaskLog "exe=`$exe cfg=`$cfg wd=`$wd"
try {
  if (-not (Test-Path -LiteralPath `$exe)) { Write-FDTaskLog "missing_exe"; exit 2 }
  if (-not (Test-Path -LiteralPath `$cfg)) { Write-FDTaskLog "missing_config"; exit 3 }
  try { Unblock-File -LiteralPath `$exe -ErrorAction SilentlyContinue } catch {}
  try { Remove-Item -LiteralPath `$stdoutPath -Force -ErrorAction SilentlyContinue } catch {}
  try { Remove-Item -LiteralPath `$stderrPath -Force -ErrorAction SilentlyContinue } catch {}
  `$agentArgs = "--config " + (Quote-FDNativeArg `$cfg)
  Write-FDTaskLog ("args=`$agentArgs")
  `$p = Start-Process -FilePath `$exe -ArgumentList `$agentArgs -WorkingDirectory `$wd -WindowStyle Hidden -RedirectStandardOutput `$stdoutPath -RedirectStandardError `$stderrPath -PassThru -ErrorAction Stop
  Write-FDTaskLog ("started_pid=" + `$p.Id)
  Start-Sleep -Seconds 4
  `$alive = Get-Process -Id `$p.Id -ErrorAction SilentlyContinue
  if (-not `$alive) {
    try { `$p.Refresh(); Write-FDTaskLog ("process_exited_early exit_code=" + `$p.ExitCode) } catch { Write-FDTaskLog "process_exited_early" }
    try { if (Test-Path -LiteralPath `$stderrPath) { Get-Content -LiteralPath `$stderrPath -Tail 40 -ErrorAction SilentlyContinue | ForEach-Object { Write-FDTaskLog ("stderr " + `$_) } } } catch {}
    try { if (Test-Path -LiteralPath `$stdoutPath) { Get-Content -LiteralPath `$stdoutPath -Tail 40 -ErrorAction SilentlyContinue | ForEach-Object { Write-FDTaskLog ("stdout " + `$_) } } } catch {}
    exit 4
  }
  Write-FDTaskLog "process_alive"
  exit 0
} catch {
  Write-FDTaskLog ("launcher_error=" + `$_.Exception.Message)
  exit 1
}
"@
  Set-Content -LiteralPath $launcher -Value $body -Encoding UTF8
  try { Unblock-File -LiteralPath $launcher -ErrorAction SilentlyContinue } catch {}
  try {
    & icacls.exe $launcher /grant:r "*S-1-5-18:F" /grant:r "*S-1-5-32-544:F" /grant:r "*S-1-5-32-545:RX" /C /Q | Out-Null
  } catch {}
  return $launcher
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
Repair-RuntimeDependencyAcls -Dir $instDir
Repair-SensitiveRuntimeAcls -Dir $instDir
Set-AgentTomlAcl -Path $cfg
Repair-ExecutableAcl -Path $exe

$launcher = Write-TaskLauncher -Exe $exe -Config $cfg -Dir $instDir
$psExe = Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe"
if (-not (Test-Path -LiteralPath $psExe)) {
  $psExe = "powershell.exe"
}
$argLine = '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "' + $launcher + '"'
$sta = New-ScheduledTaskAction -Execute $psExe -Argument $argLine -WorkingDirectory $instDir
$trg = New-ScheduledTaskTrigger -AtStartup
$prc = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$set = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
  -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)

Register-ScheduledTask -TaskName $TaskName -Action $sta -Trigger $trg -Principal $prc -Settings $set -Force | Out-Null
if (-not $NoStart) {
  Start-ScheduledTask -TaskName $TaskName
}

exit 0
