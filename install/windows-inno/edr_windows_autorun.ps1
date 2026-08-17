#Requires -Version 5.1
<#
  Installs or removes the FDSecurity startup task and optional install-directory ACL hardening.
  - Install: registers an unlimited SYSTEM startup task and starts it unless -NoStart is set.
  - Remove: stops the task and Agent, cleans residual ETW sessions, resets ACLs, and unregisters the task.

  This script configures the scheduled-task runtime mode; the native-service mode is installed separately.
  ACL hardening limits ordinary users; administrators must use unins000.exe for normal removal.
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

function Remove-StaleQueueLock {
  param([string]$Dir)
  $path = Join-Path $Dir "queue\edr_queue.db.lock"
  if (-not (Test-Path -LiteralPath $path)) { return }
  try {
    Remove-Item -LiteralPath $path -Force -ErrorAction Stop
    return
  } catch {}

  try { & takeown.exe /F $path /A 2>$null | Out-Null } catch {}
  try {
    & icacls.exe $path /inheritance:r /grant:r "*S-1-5-18:F" /grant:r "*S-1-5-32-544:F" /C /Q | Out-Null
  } catch {}
  Remove-Item -LiteralPath $path -Force -ErrorAction Stop
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

function Get-FDWindowsArch {
  $raw = if ($env:EDR_BUNDLE_ARCH) { $env:EDR_BUNDLE_ARCH } elseif ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
  $v = if ($raw) { $raw.Trim().ToLowerInvariant() } else { "" }
  switch ($v) {
    "arm64" { return "arm64" }
    "aarch64" { return "arm64" }
    default { return "amd64" }
  }
}

function Read-AgentTomlString {
  param([string]$Path, [string]$Key)
  if (-not (Test-Path -LiteralPath $Path)) { return "" }
  try {
    foreach ($line in Get-Content -LiteralPath $Path -ErrorAction Stop) {
      if ($line -match ("^\s*" + [regex]::Escape($Key) + "\s*=\s*`"([^`"]*)`"")) {
        return [string]$Matches[1]
      }
      if ($line -match ("^\s*" + [regex]::Escape($Key) + "\s*=\s*'([^']*)'")) {
        return [string]$Matches[1]
      }
    }
  } catch {}
  return ""
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
    @{ Name = "unins000.dat"; Grant = "*S-1-5-32-545:R" },
    @{ Name = "uninstall.exe"; Grant = "*S-1-5-32-545:RX" },
    @{ Name = "uninstall.ps1"; Grant = "*S-1-5-32-545:R" }
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

function Repair-RuntimeFileAcls {
  param([string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) { return }
  foreach ($item in @(Get-ChildItem -LiteralPath $Path -File -Force -Recurse -ErrorAction SilentlyContinue)) {
    try { & takeown.exe /F $item.FullName /A 2>$null | Out-Null } catch {}
    & icacls.exe $item.FullName /inheritance:r /grant:r "*S-1-5-18:F" /grant:r "*S-1-5-32-544:F" /C /Q | Out-Null
    if ($LASTEXITCODE -ne 0) {
      throw "file ACL repair failed with exit code $LASTEXITCODE path=$($item.FullName)"
    }
  }
}

function Repair-RuntimeDependencyAcls {
  param([string]$Dir)
  if (-not (Test-Path -LiteralPath $Dir)) { return }
  try {
    & icacls.exe $Dir /grant:r "*S-1-5-18:(OI)(CI)F" /grant:r "*S-1-5-32-544:(OI)(CI)F" /grant:r "*S-1-5-32-545:(OI)(CI)RX" /C /Q | Out-Null
  } catch {}

  foreach ($pattern in @("*.exe", "*.dll", "*.ps1", "*.toml", "*.json", "*.enc", "edr_config\*")) {
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
      try { & takeown.exe /F $path /A /R /D Y 2>$null | Out-Null } catch {}
      & icacls.exe $path /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" /grant:r "*S-1-5-32-544:(OI)(CI)F" /T /C /Q | Out-Null
      $aclExit = $LASTEXITCODE
      if ($sub -eq "queue" -and $aclExit -ne 0) {
        throw "queue ACL repair failed with exit code $aclExit"
      }
      Repair-RuntimeFileAcls -Path $path
    } catch {
      if ($sub -eq "queue") { throw }
    }
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

  foreach ($pattern in @("*.exe", "*.dll", "*.ps1", "*.json", "*.enc", "*.example", "*.txt", "edr_config\*")) {
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
`$jobHandle = [IntPtr]::Zero
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
  if (-not ("FDSecurity.TaskJob" -as [type])) {
    Add-Type -ErrorAction Stop -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace FDSecurity {
  public static class TaskJob {
    private const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;
    private const int JobObjectExtendedLimitInformation = 9;

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_BASIC_LIMIT_INFORMATION {
      public long PerProcessUserTimeLimit;
      public long PerJobUserTimeLimit;
      public uint LimitFlags;
      public UIntPtr MinimumWorkingSetSize;
      public UIntPtr MaximumWorkingSetSize;
      public uint ActiveProcessLimit;
      public UIntPtr Affinity;
      public uint PriorityClass;
      public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IO_COUNTERS {
      public ulong ReadOperationCount;
      public ulong WriteOperationCount;
      public ulong OtherOperationCount;
      public ulong ReadTransferCount;
      public ulong WriteTransferCount;
      public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
      public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
      public IO_COUNTERS IoInfo;
      public UIntPtr ProcessMemoryLimit;
      public UIntPtr JobMemoryLimit;
      public UIntPtr PeakProcessMemoryUsed;
      public UIntPtr PeakJobMemoryUsed;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateJobObject(IntPtr securityAttributes, string name);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetInformationJobObject(
      IntPtr job,
      int infoClass,
      IntPtr info,
      uint infoLength);

    [DllImport("kernel32.dll", EntryPoint = "AssignProcessToJobObject", SetLastError = true)]
    private static extern bool AssignProcessToJobObjectNative(IntPtr job, IntPtr process);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    public static IntPtr CreateKillOnCloseJob() {
      IntPtr job = CreateJobObject(IntPtr.Zero, null);
      if (job == IntPtr.Zero) {
        throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateJobObject failed");
      }
      var limits = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
      limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
      int length = Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
      IntPtr buffer = Marshal.AllocHGlobal(length);
      try {
        Marshal.StructureToPtr(limits, buffer, false);
        if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, buffer, (uint)length)) {
          int error = Marshal.GetLastWin32Error();
          CloseHandle(job);
          throw new Win32Exception(error, "SetInformationJobObject failed");
        }
      } finally {
        Marshal.FreeHGlobal(buffer);
      }
      return job;
    }

    public static void AssignProcess(IntPtr job, IntPtr process) {
      if (!AssignProcessToJobObjectNative(job, process)) {
        throw new Win32Exception(Marshal.GetLastWin32Error(), "AssignProcessToJobObject failed");
      }
    }

    public static void Close(IntPtr job) {
      if (job != IntPtr.Zero) {
        CloseHandle(job);
      }
    }
  }
}
'@
  }
  `$jobHandle = [FDSecurity.TaskJob]::CreateKillOnCloseJob()
  try {
    [FDSecurity.TaskJob]::AssignProcess(`$jobHandle, [Diagnostics.Process]::GetCurrentProcess().Handle)
  } catch {
    [FDSecurity.TaskJob]::Close(`$jobHandle)
    `$jobHandle = [IntPtr]::Zero
    throw
  }
  Write-FDTaskLog "launcher_job_assigned kill_on_close=1"
  if (-not (Test-Path -LiteralPath `$exe)) { Write-FDTaskLog "missing_exe"; exit 2 }
  if (-not (Test-Path -LiteralPath `$cfg)) { Write-FDTaskLog "missing_config"; exit 3 }
  try { Unblock-File -LiteralPath `$exe -ErrorAction SilentlyContinue } catch {}
  try { Remove-Item -LiteralPath `$stdoutPath -Force -ErrorAction SilentlyContinue } catch {}
  try { Remove-Item -LiteralPath `$stderrPath -Force -ErrorAction SilentlyContinue } catch {}
  foreach (`$envName in @(
      "EDR_FORENSIC_COLLECTOR",
      "EDR_FORENSIC_COLLECTOR_BIN",
      "EDR_FORENSIC_COLLECTOR_BUILTIN_BIN",
      "EDR_VELOCIRAPTOR_BIN",
      "EDR_FORENSIC_VERSION_CHECK_SEC",
      "EDR_FORENSIC_PREFETCH_RETRY_SEC",
      "EDR_FORENSIC_COLLECTOR_AUTOFETCH",
      "EDR_FORENSIC_ADAPTER_MANIFEST_URL",
      "EDR_FORENSIC_COLLECTOR_MANIFEST_URL")) {
    `$machineValue = [Environment]::GetEnvironmentVariable(`$envName, "Machine")
    if (-not [string]::IsNullOrWhiteSpace(`$machineValue)) {
      [Environment]::SetEnvironmentVariable(`$envName, `$machineValue, "Process")
    }
  }
  `$agentArgs = "--config " + (Quote-FDNativeArg `$cfg)
  Write-FDTaskLog ("args=`$agentArgs")
  `$p = Start-Process -FilePath `$exe -ArgumentList `$agentArgs -WorkingDirectory `$wd -WindowStyle Hidden -RedirectStandardOutput `$stdoutPath -RedirectStandardError `$stderrPath -PassThru -ErrorAction Stop
  Write-FDTaskLog ("started_pid=" + `$p.Id + " inherited_kill_on_close_job=1")
  Start-Sleep -Seconds 4
  `$alive = Get-Process -Id `$p.Id -ErrorAction SilentlyContinue
  if (-not `$alive) {
    try { `$p.Refresh(); Write-FDTaskLog ("process_exited_early exit_code=" + `$p.ExitCode) } catch { Write-FDTaskLog "process_exited_early" }
    try { if (Test-Path -LiteralPath `$stderrPath) { Get-Content -LiteralPath `$stderrPath -Tail 40 -ErrorAction SilentlyContinue | ForEach-Object { Write-FDTaskLog ("stderr " + `$_) } } } catch {}
    try { if (Test-Path -LiteralPath `$stdoutPath) { Get-Content -LiteralPath `$stdoutPath -Tail 40 -ErrorAction SilentlyContinue | ForEach-Object { Write-FDTaskLog ("stdout " + `$_) } } } catch {}
    exit 4
  }
  Write-FDTaskLog "process_alive"
  try {
    `$p.WaitForExit()
    `$p.Refresh()
    `$exitCode = [int]`$p.ExitCode
    Write-FDTaskLog ("process_exit exit_code=" + `$exitCode)
    try { if (Test-Path -LiteralPath `$stderrPath) { Get-Content -LiteralPath `$stderrPath -Tail 40 -ErrorAction SilentlyContinue | ForEach-Object { Write-FDTaskLog ("stderr " + `$_) } } } catch {}
    try { if (Test-Path -LiteralPath `$stdoutPath) { Get-Content -LiteralPath `$stdoutPath -Tail 40 -ErrorAction SilentlyContinue | ForEach-Object { Write-FDTaskLog ("stdout " + `$_) } } } catch {}
    exit `$exitCode
  } catch {
    Write-FDTaskLog ("process_wait_error=" + `$_.Exception.Message)
    exit 5
  }
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
  foreach ($n in @(
      "EDR_FORENSIC_COLLECTOR",
      "EDR_FORENSIC_COLLECTOR_BIN",
      "EDR_FORENSIC_COLLECTOR_BUILTIN_BIN",
      "EDR_VELOCIRAPTOR_BIN",
      "EDR_FORENSIC_COLLECTOR_AUTOFETCH",
      "EDR_FORENSIC_ADAPTER_MANIFEST_URL",
      "EDR_FORENSIC_COLLECTOR_MANIFEST_URL")) {
    try { [Environment]::SetEnvironmentVariable($n, $null, "Machine") } catch {}
  }
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
Remove-StaleQueueLock -Dir $instDir

if ($HardenAcl) {
  Set-InstallDirAclHarden -Dir $instDir
  Set-AgentTomlAcl -Path $cfg
}
Repair-RuntimeDependencyAcls -Dir $instDir
Repair-SensitiveRuntimeAcls -Dir $instDir
Set-AgentTomlAcl -Path $cfg

# Keep autorun forensic collector settings aligned with the Windows service installer.
# Derive adapter and Velociraptor manifest URLs from rest_base_url.
try {
  [Environment]::SetEnvironmentVariable("EDR_FORENSIC_COLLECTOR", "1", "Machine")
  [Environment]::SetEnvironmentVariable("EDR_FORENSIC_COLLECTOR_BIN", (Join-Path $instDir "collector\forensic_collector.exe"), "Machine")
  [Environment]::SetEnvironmentVariable("EDR_FORENSIC_COLLECTOR_BUILTIN_BIN", (Join-Path $instDir "collector\forensic_collector_builtin.exe"), "Machine")
  [Environment]::SetEnvironmentVariable("EDR_VELOCIRAPTOR_BIN", (Join-Path $instDir "collector\velociraptor.exe"), "Machine")
  [Environment]::SetEnvironmentVariable("EDR_FORENSIC_VERSION_CHECK_SEC", "900", "Machine")
  [Environment]::SetEnvironmentVariable("EDR_FORENSIC_PREFETCH_RETRY_SEC", "900", "Machine")
  [Environment]::SetEnvironmentVariable("EDR_FORENSIC_COLLECTOR_AUTOFETCH", "1", "Machine")
  $restBase = (Read-AgentTomlString -Path $cfg -Key "rest_base_url").TrimEnd("/")
  if ($restBase) {
    $arch = Get-FDWindowsArch
    [Environment]::SetEnvironmentVariable("EDR_FORENSIC_ADAPTER_MANIFEST_URL", "$restBase/agent/forensic-collector/manifest?kind=adapter&os=windows&arch=$arch", "Machine")
    [Environment]::SetEnvironmentVariable("EDR_FORENSIC_COLLECTOR_MANIFEST_URL", "$restBase/agent/forensic-collector/manifest?kind=velociraptor&os=windows&arch=$arch", "Machine")
  }
} catch {
  Write-Warning "Failed to configure forensic collector environment variables (non-fatal): $_"
}
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
$set = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
  -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero) `
  -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)

Register-ScheduledTask -TaskName $TaskName -Action $sta -Trigger $trg -Principal $prc -Settings $set -Force | Out-Null
if (-not $NoStart) {
  Start-ScheduledTask -TaskName $TaskName
}

exit 0
