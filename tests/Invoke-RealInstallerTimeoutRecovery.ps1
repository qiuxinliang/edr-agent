#Requires -Version 5.1
# Disposable native CI only. Never patch a release or the installed updater.
[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)] $InputBinding,
  [Parameter(Mandatory=$true)] [string] $InstallDir,
  [Parameter(Mandatory=$true)] [string] $EvidenceDir,
  [Parameter(Mandatory=$true)] [string] $Updater,
  [Parameter(Mandatory=$true)] $Publisher
)
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -cne 'true' -or $env:OS -cne 'Windows_NT') {
  throw 'Real installer timeout recovery requires a disposable Windows Actions runner'
}
if ($InputBinding.upgrade_class -cne 'installer_required' -or $InputBinding.deployment_mode -cne 'service') {
  throw 'Real installer timeout recovery requires the release-declared installer_required service path'
}
$InstallDir = [IO.Path]::GetFullPath($InstallDir)
if ($InstallDir -notmatch '^C:\\edr-agent-setup-lifecycle-[A-Za-z0-9._-]+$') { throw 'Unsafe installer fault-test directory' }
if ((Get-FileHash -LiteralPath $Updater -Algorithm SHA256).Hash.ToLowerInvariant() -cne $InputBinding.target_updater_sha256) {
  throw 'Candidate embedded updater no longer matches the release'
}
Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
public static class LifecycleInstallerFault {
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern IntPtr OpenJobObjectW(uint access, bool inherit, string name);
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool QueryInformationJobObject(IntPtr job, int type, IntPtr data, uint length, out uint returned);
  [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool IsProcessInJob(IntPtr process, IntPtr job, out bool member);
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool QueryFullProcessImageNameW(IntPtr process, uint flags, StringBuilder path, ref uint size);
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetProcessTimes(IntPtr process, out long created, out long exited, out long kernel, out long user);
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool TerminateJobObject(IntPtr job, uint code);
  [DllImport("kernel32.dll", SetLastError=true)] static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
  [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr value);
  [DllImport("ntdll.dll")] static extern int NtSuspendProcess(IntPtr process);
  static void Check(bool result) { if (!result) throw new Win32Exception(Marshal.GetLastWin32Error()); }
  public static IntPtr OpenJob(string name) {
    IntPtr job = OpenJobObjectW(12, false, name); // QUERY | TERMINATE, scoped cleanup on test failure.
    if (job == IntPtr.Zero && Marshal.GetLastWin32Error()!=2) throw new Win32Exception(Marshal.GetLastWin32Error());
    return job;
  }
  public static uint[] Pids(IntPtr job) {
    const int size = 65536;
    IntPtr data = Marshal.AllocHGlobal(size);
    try {
      uint returned; Check(QueryInformationJobObject(job, 3, data, size, out returned));
      int assigned = Marshal.ReadInt32(data), count = Marshal.ReadInt32(data, 4);
      if (assigned != count || count < 0 || 8L + count * IntPtr.Size > size) throw new InvalidOperationException("Incomplete installer Job process inventory");
      uint[] pids = new uint[count];
      for (int i=0; i<count; i++) pids[i] = checked((uint)Marshal.ReadIntPtr(data, 8+i*IntPtr.Size).ToInt64());
      return pids;
    } finally { Marshal.FreeHGlobal(data); }
  }
  public static IntPtr Open(uint pid, bool suspend) {
    IntPtr process = OpenProcess(suspend ? 0x101800U : 0x101000U, false, pid); // QUERY | SYNCHRONIZE, plus SUSPEND_RESUME for injection only.
    if (process == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
    return process;
  }
  public static bool Member(IntPtr process, IntPtr job) { bool member; Check(IsProcessInJob(process, job, out member)); return member; }
  public static string Image(IntPtr process) { uint size=32768; var text=new StringBuilder((int)size); Check(QueryFullProcessImageNameW(process,0,text,ref size)); return text.ToString(); }
  public static long Created(IntPtr process) { long c,e,k,u; Check(GetProcessTimes(process,out c,out e,out k,out u)); return c; }
  public static bool Exited(IntPtr process) { uint result=WaitForSingleObject(process,0); if(result==0) return true; if(result==258) return false; throw new Win32Exception(Marshal.GetLastWin32Error()); }
  public static void Suspend(IntPtr process) { int status=NtSuspendProcess(process); if(status!=0) throw new InvalidOperationException("NtSuspendProcess failed: "+status); }
  public static void Terminate(IntPtr job) { Check(TerminateJobObject(job, 1460)); }
}
'@

function Get-RecoveryOwnerSnapshot {
  $service = Get-CimInstance Win32_Service -Filter ("Name='{0}'" -f $InputBinding.service_name)
  if (-not $service -or $service.PathName.IndexOf($InstallDir, [StringComparison]::OrdinalIgnoreCase) -lt 0) {
    throw 'Installed service is not bound to this lifecycle directory'
  }
  $uninstall = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
                 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*') |
    ForEach-Object { Get-ItemProperty -Path $_ -ErrorAction SilentlyContinue } |
    Where-Object { $_.InstallLocation -and ([string]$_.InstallLocation).TrimEnd('\') -ieq $InstallDir.TrimEnd('\') } |
    Sort-Object PSPath | ForEach-Object {
      [ordered]@{ key=$_.PSChildName; version=$_.DisplayVersion; location=$_.InstallLocation;
                  uninstall=$_.UninstallString; quiet_uninstall=$_.QuietUninstallString }
    }
  if (@($uninstall).Count -ne 1 -or @($uninstall)[0].version -cne $InputBinding.target_version) {
    throw 'Expected one actual Inno uninstall registration at the installed candidate version'
  }
  return [ordered]@{ service=[ordered]@{ path=$service.PathName; start_mode=$service.StartMode; account=$service.StartName };
                     uninstall=@($uninstall) }
}
function Read-RecoveryJournal([string]$Path) {
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
  # Atomic replacement can race the read; only its transient I/O error is retried.
  try { return [IO.File]::ReadAllText($Path) | ConvertFrom-Json }
  catch [IO.IOException] { return $null }
}
function Assert-RecoveryFiles($Expected) {
  foreach ($entry in $Expected.GetEnumerator()) {
    $path = Join-Path $InstallDir $entry.Key
    if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $entry.Value) {
      throw "Installer timeout recovery changed protected file: $($entry.Key)"
    }
  }
}
$stage = Join-Path $EvidenceDir 'candidate-installer-timeout'
New-Item -ItemType Directory -Path $stage -ErrorAction Stop | Out-Null
$stage = [IO.Path]::GetFullPath($stage)
$files = [ordered]@{}
foreach ($name in @('FDSensor.exe','native-package-integrity.json','agent.toml')) {
  $files[$name] = (Get-FileHash -LiteralPath (Join-Path $InstallDir $name) -Algorithm SHA256).Hash.ToLowerInvariant()
}
$native = Get-Content -LiteralPath (Join-Path $InstallDir 'native-package-integrity.json') -Raw | ConvertFrom-Json
foreach ($file in $native.files) { $files[$file.name] = $file.sha256 }
$certs = Join-Path $InstallDir 'certs'
if (Test-Path -LiteralPath $certs -PathType Container) {
  foreach ($file in Get-ChildItem -LiteralPath $certs -File -Recurse) {
    $files[$file.FullName.Substring($InstallDir.Length + 1)] = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
  }
}
# Markers establish file preservation only; they are not a database readability test.
foreach ($prefix in @('edr_queue.db','local_evidence_cache.db')) {
  # Reuse the lifecycle's legacy root-marker convention. The real queue and
  # evidence directories retain their protected ACLs; the runner cannot write them.
  $relative = $prefix + '.ci-installer-timeout-' + [Guid]::NewGuid().ToString('N')
  [IO.File]::WriteAllText((Join-Path $InstallDir $relative), [Guid]::NewGuid().ToString('N'))
  $files[$relative] = (Get-FileHash -LiteralPath (Join-Path $InstallDir $relative) -Algorithm SHA256).Hash.ToLowerInvariant()
}
Assert-RecoveryFiles $files
$beforeOwner = Get-RecoveryOwnerSnapshot | ConvertTo-Json -Depth 8 -Compress
$oldService = Get-CimInstance Win32_Service -Filter ("Name='{0}'" -f $InputBinding.service_name)
$binary = Join-Path $stage 'FDSensor.next.exe'
$package = Join-Path $stage 'full-installer.zip'
Copy-Item -LiteralPath $InputBinding.binary_path -Destination $binary
Copy-Item -LiteralPath $InputBinding.runtime_package -Destination $package
if ((Get-FileHash $binary -Algorithm SHA256).Hash.ToLowerInvariant() -cne $InputBinding.binary_sha256 -or
    (Get-FileHash $package -Algorithm SHA256).Hash.ToLowerInvariant() -cne $InputBinding.runtime_package_sha256) {
  throw 'Repair staging bytes differ from the immutable candidate'
}
$commandId = 'ci-installer-timeout-' + [Guid]::NewGuid().ToString('N')
$issued = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
$parameters = [ordered]@{
  InstallDir=$InstallDir; StagedBinary=$binary; ExpectedSha256=$InputBinding.binary_sha256
  TargetVersion=$InputBinding.target_version; ExpectedArchitecture=$(if ($InputBinding.architecture -eq 'amd64') {'x64'} else {'arm64'})
  TrustedPublisherThumbprint=$Publisher.Thumbprint; TrustedPublisherSubject=$Publisher.Subject
  DeploymentMode=$InputBinding.deployment_mode; ServiceName=$InputBinding.service_name
  CommandId=$commandId; TaskId=$commandId; ArtifactId=('ci-repair-' + $InputBinding.target_version)
  Operation='repair'; UpgradeClass=$InputBinding.upgrade_class
  IssuedAtUnixMs=$issued; DeadlineUnixMs=$issued+120000; HealthObserveMs=30000; StartupTimeoutSeconds=60
  MinFreeBytes=$InputBinding.min_free_bytes; RuntimeManifest=$package; RuntimeManifestSha256=$InputBinding.runtime_package_sha256
}
$entries = @($parameters.GetEnumerator() | ForEach-Object { "'{0}'='{1}'" -f $_.Key, ([string]$_.Value).Replace("'", "''") })
$source = "`$ErrorActionPreference='Stop'; `$parameters=@{" + ($entries -join ';') + "}; & '" + $Updater.Replace("'", "''") + "' @parameters; exit `$LASTEXITCODE"
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($source))
$journalPath = Join-Path $env:ProgramData ("FDSecurity\state\agent-update-{0}.journal.json" -f $commandId)
$reportPath = Join-Path $env:ProgramData ("FDSecurity\logs\agent-update-{0}-report.json" -f $commandId)
$expectedSetup = Join-Path $stage 'FDSecuritySetup.exe'
$job = [IntPtr]::Zero; $rootHandle = [IntPtr]::Zero; $oldRuntime = [IntPtr]::Zero
$delegatedRuntime = [IntPtr]::Zero; $process = $null
$suspended = $false; $stopped = $false; $delegatedRunning = $false; $passed = $false
$observations = New-Object System.Collections.Generic.List[object]
$receipt = [ordered]@{ schema='edr.windows.real-installer-timeout.v1'; command_id=$commandId; status='failed';
  architecture=$InputBinding.architecture; target_version=$InputBinding.target_version;
  updater_sha256=$InputBinding.target_updater_sha256; installer_sha256=$InputBinding.installer_sha256;
  protected_files=$files; owner_before=($beforeOwner | ConvertFrom-Json); data_check='legacy root marker bytes only; protected databases not modified or validated' }
try {
  $oldRuntime = [LifecycleInstallerFault]::Open([uint32]$oldService.ProcessId, $false)
  if ([LifecycleInstallerFault]::Image($oldRuntime) -ine (Join-Path $InstallDir 'FDSensor.exe')) {
    throw 'Initial installed service process is not the expected runtime'
  }
  $receipt.initial_service = [ordered]@{ pid=$oldService.ProcessId; created_filetime=[LifecycleInstallerFault]::Created($oldRuntime) }
  $process = Start-Process -FilePath (Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe') `
    -ArgumentList @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-EncodedCommand',$encoded) `
    -RedirectStandardOutput (Join-Path $stage 'updater.stdout.log') -RedirectStandardError (Join-Path $stage 'updater.stderr.log') -PassThru
  $null = $process.Handle
  $clock = [Diagnostics.Stopwatch]::StartNew()
  $lastState = ''
  while (-not $process.HasExited -and $clock.Elapsed.TotalSeconds -lt 240) {
    $journal = Read-RecoveryJournal $journalPath
    $service = Get-CimInstance Win32_Service -Filter ("Name='{0}'" -f $InputBinding.service_name)
    if ($journal -and $journal.stop_intent -and [LifecycleInstallerFault]::Exited($oldRuntime) -and -not $stopped) {
      $stopped = $true
      $receipt.runtime_stopped = [ordered]@{ at=[DateTime]::UtcNow.ToString('o'); state=$service.State;
        original_pid=$oldService.ProcessId; original_process_handle_signaled=$true }
    }
    # Launch intent is durable before both Stop and CreateJobObject. Wait for
    # the actual stopped owner and original process, never mistake intent for execution.
    if ($journal -and $journal.installer_job_name -and $job -eq [IntPtr]::Zero -and
        $journal.stage -ceq 'full_installer_upgrade' -and $journal.stop_intent -and $stopped) {
      $job = [LifecycleInstallerFault]::OpenJob($journal.installer_job_name)
      if ($job -ne [IntPtr]::Zero) { $receipt.installer_job_name = $journal.installer_job_name }
    }
    if ($job -ne [IntPtr]::Zero) {
      $members = @([LifecycleInstallerFault]::Pids($job))
      $state = "{0}/{1}/{2}" -f $journal.stage, $journal.installer_quiesced, $members.Count
      if ($state -cne $lastState) {
        $observations.Add([ordered]@{ at=[DateTime]::UtcNow.ToString('o'); elapsed_ms=$clock.ElapsedMilliseconds;
          stage=$journal.stage; quiesced=$journal.installer_quiesced; active_processes=$members.Count })
        $lastState = $state
      }
      if (($journal.installer_quiesced -eq $true -or $journal.stage -like 'rollback*') -and $members.Count -ne 0) {
        throw 'Installer rollback began while its Job still had writers'
      }
      if (-not $suspended) {
        $children = @(Get-CimInstance Win32_Process | Where-Object { [uint32]$_.ProcessId -in $members })
        foreach ($candidate in $children) {
          if ([string]$candidate.ExecutablePath -ine $expectedSetup) { continue }
          $actualChildren = @($children | Where-Object { $_.ParentProcessId -eq $candidate.ProcessId })
          if ($actualChildren.Count -lt 1) { continue }
          $rootHandle = [LifecycleInstallerFault]::Open([uint32]$candidate.ProcessId, $true)
          $created = [LifecycleInstallerFault]::Created($rootHandle)
          if (-not [LifecycleInstallerFault]::Member($rootHandle, $job) -or
              [LifecycleInstallerFault]::Image($rootHandle) -ine $expectedSetup -or
              [Math]::Abs(([DateTime]::FromFileTimeUtc($created) - $candidate.CreationDate.ToUniversalTime()).Ticks) -gt 10 -or
              (Get-FileHash -LiteralPath $expectedSetup -Algorithm SHA256).Hash.ToLowerInvariant() -cne $InputBinding.installer_sha256) {
            throw 'Real Setup process generation, Job membership, image path or hash mismatch'
          }
          [LifecycleInstallerFault]::Suspend($rootHandle)
          $suspended = $true
          $receipt.fault = [ordered]@{ at=[DateTime]::UtcNow.ToString('o'); root_pid=$candidate.ProcessId;
            root_created_filetime=$created; image=$expectedSetup; child_pids=@($actualChildren.ProcessId);
            action='suspend_verified_original_setup_root_after_child_creation' }
          break
        }
      }
      if ($suspended -and -not $delegatedRunning -and $members.Count -gt 0 -and $service.State -eq 'Running' -and
          $service.ProcessId -gt 0) {
        $serviceHandle = [LifecycleInstallerFault]::Open([uint32]$service.ProcessId, $false)
        try {
          if ([LifecycleInstallerFault]::Image($serviceHandle) -ine (Join-Path $InstallDir 'FDSensor.exe') -or
              [LifecycleInstallerFault]::Member($serviceHandle, $job)) { throw 'SCM runtime identity or external ownership mismatch' }
          if (-not $delegatedRunning -and $members.Count -gt 0) {
            $receipt.delegated_service = [ordered]@{ at=[DateTime]::UtcNow.ToString('o'); pid=$service.ProcessId;
              created_filetime=[LifecycleInstallerFault]::Created($serviceHandle); outside_installer_job=$true }
            $delegatedRuntime = $serviceHandle
            $serviceHandle = [IntPtr]::Zero
            $delegatedRunning = $true
          }
        } finally { if ($serviceHandle -ne [IntPtr]::Zero) { [void][LifecycleInstallerFault]::CloseHandle($serviceHandle) } }
      }
    }
    Start-Sleep -Milliseconds 100
    $process.Refresh()
  }
  if (-not $process.HasExited) { throw 'Candidate updater did not recover within the 240 second CI budget' }
  $process.WaitForExit()
  $report = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
  $journal = Get-Content -LiteralPath $journalPath -Raw | ConvertFrom-Json
  if (-not $suspended -or -not $delegatedRunning -or $process.ExitCode -eq 0 -or
      $report.operation -cne 'repair' -or $report.error_code -cne 'INSTALL_TIMEOUT' -or
      $report.failed_stage -cne 'full_installer_upgrade' -or $report.status -cne 'failed_rolled_back' -or
      $report.rollback -cne 'succeeded' -or $report.installed_sha256 -cne $InputBinding.binary_sha256 -or
      $journal.installer_quiesced -ne $true -or @([LifecycleInstallerFault]::Pids($job)).Count -ne 0) {
    throw 'Actual installer hang did not produce the required timeout, zero-writer receipt and successful rollback'
  }
  Assert-RecoveryFiles $files
  $afterOwner = Get-RecoveryOwnerSnapshot | ConvertTo-Json -Depth 8 -Compress
  if ($beforeOwner -cne $afterOwner) { throw 'Recovery changed service configuration or Inno uninstall registration' }
  $service = Get-CimInstance Win32_Service -Filter ("Name='{0}'" -f $InputBinding.service_name)
  if ($service.State -cne 'Running' -or -not [LifecycleInstallerFault]::Exited($delegatedRuntime)) {
    throw 'Recovery did not stop the installer-created SCM runtime and start a healthy recovered owner'
  }
  $receipt.status = 'succeeded'; $receipt.owner_after = ($afterOwner | ConvertFrom-Json)
  $receipt.recovered_service_pid = $service.ProcessId
  $receipt.installer_quiesced = $true
  $passed = $true
} catch {
  $receipt.failure = $_.Exception.Message
  throw
} finally {
  try {
    if (-not $passed -and $job -ne [IntPtr]::Zero) {
      # Failure does not continue into uninstall or RuntimeMirror. End only
      # this verified Job; preserve the original failure if cleanup also fails.
      try {
        if (@([LifecycleInstallerFault]::Pids($job)).Count -gt 0) { [LifecycleInstallerFault]::Terminate($job) }
        $cleanupClock = [Diagnostics.Stopwatch]::StartNew()
        while (@([LifecycleInstallerFault]::Pids($job)).Count -gt 0 -and $cleanupClock.Elapsed.TotalSeconds -lt 15) { Start-Sleep -Milliseconds 100 }
        $receipt.failure_cleanup_job_empty = @([LifecycleInstallerFault]::Pids($job)).Count -eq 0
      } catch {
        $receipt.failure_cleanup_job_empty = $false
        $receipt.failure_cleanup_error = $_.Exception.Message
      }
    }
    if ($process -and -not $process.HasExited -and -not $passed) {
      $receipt.failure_cleanup_updater_exited = $process.WaitForExit(90000)
    }
    foreach ($item in @(@{source=$reportPath;name='report.json'},@{source=$journalPath;name='journal.json'})) {
      try {
        if (Test-Path -LiteralPath $item.source -PathType Leaf) { Copy-Item -LiteralPath $item.source -Destination (Join-Path $stage $item.name) }
      } catch {
        $receipt.evidence_copy_error = $_.Exception.Message
        if ($passed) { throw }
      }
    }
  } finally {
    try {
      $receipt.observations = $observations.ToArray()
      [IO.File]::WriteAllText((Join-Path $stage 'receipt.json'), ($receipt | ConvertTo-Json -Depth 12), [Text.UTF8Encoding]::new($false))
    } finally {
      foreach ($handle in @($rootHandle, $oldRuntime, $delegatedRuntime, $job)) {
        if ($handle -ne [IntPtr]::Zero) { [void][LifecycleInstallerFault]::CloseHandle($handle) }
      }
      if ($process) { $process.Dispose() }
    }
  }
}
