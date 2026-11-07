using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
namespace FDSecurity {
  public sealed class InstallerJob : IDisposable {
    [StructLayout(LayoutKind.Sequential)] struct SECURITY_ATTRIBUTES {
      public int Length; public IntPtr Descriptor; public int Inherit;
    }
    [StructLayout(LayoutKind.Sequential)] struct BASIC_LIMIT {
      public long ProcessTime, JobTime; public uint Flags;
      public UIntPtr MinimumWorkingSet, MaximumWorkingSet;
      public uint ActiveLimit; public UIntPtr Affinity; public uint Priority, Scheduling;
    }
    [StructLayout(LayoutKind.Sequential)] struct IO_COUNTERS {
      public ulong ReadOps, WriteOps, OtherOps, ReadBytes, WriteBytes, OtherBytes;
    }
    [StructLayout(LayoutKind.Sequential)] struct EXTENDED_LIMIT {
      public BASIC_LIMIT Basic; public IO_COUNTERS Io;
      public UIntPtr ProcessMemory, JobMemory, PeakProcessMemory, PeakJobMemory;
    }
    [StructLayout(LayoutKind.Sequential)] struct ACCOUNTING {
      public long User, Kernel, PeriodUser, PeriodKernel;
      public uint Faults, Total, Active, Terminated;
    }
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] struct STARTUPINFO {
      public int Size; public string Reserved, Desktop, Title;
      public uint X, Y, XSize, YSize, XCount, YCount, Fill, Flags;
      public ushort Show, ReservedSize; public IntPtr ReservedBytes, Input, Output, Error;
    }
    [StructLayout(LayoutKind.Sequential)] struct STARTUPINFOEX {
      public STARTUPINFO Startup; public IntPtr Attributes;
    }
    [StructLayout(LayoutKind.Sequential)] struct PROCESS_INFORMATION {
      public IntPtr Process, Thread; public uint ProcessId, ThreadId;
    }
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string value, uint revision, out IntPtr descriptor, out uint size);
    [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr value);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern IntPtr CreateJobObject(ref SECURITY_ATTRIBUTES security, string name);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern IntPtr OpenJobObject(uint access, bool inherit, string name);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool SetInformationJobObject(IntPtr job, int kind, ref EXTENDED_LIMIT limits, uint size);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool QueryInformationJobObject(IntPtr job, int kind, out ACCOUNTING info, uint size, IntPtr returned);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool TerminateJobObject(IntPtr job, uint code);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool InitializeProcThreadAttributeList(IntPtr list, int count, uint flags, ref IntPtr size);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool UpdateProcThreadAttribute(IntPtr list, uint flags, IntPtr attribute, IntPtr value, IntPtr size, IntPtr previous, IntPtr returned);
    [DllImport("kernel32.dll")] static extern void DeleteProcThreadAttributeList(IntPtr list);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern bool CreateProcess(string application, StringBuilder command, IntPtr processSecurity, IntPtr threadSecurity,
      bool inherit, uint flags, IntPtr environment, string directory, ref STARTUPINFOEX startup, out PROCESS_INFORMATION process);
    [DllImport("kernel32.dll", SetLastError=true)] static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetExitCodeProcess(IntPtr process, out uint code);
    [DllImport("kernel32.dll")] public static extern ulong GetTickCount64();
    IntPtr job, process, attributes, jobList;
    bool attributesInitialized;
    public string Name { get; private set; }
    InstallerJob() { }
    static void Error(string operation) { throw new Win32Exception(Marshal.GetLastWin32Error(), operation); }
    public static InstallerJob Create(string name) {
      var owner = new InstallerJob(); owner.Name = name;
      IntPtr descriptor = IntPtr.Zero; uint size;
      try {
        if (!ConvertStringSecurityDescriptorToSecurityDescriptor("D:P(A;;GA;;;SY)(A;;GA;;;BA)", 1, out descriptor, out size)) Error("installer_job_acl");
        var security = new SECURITY_ATTRIBUTES { Length=Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES)), Descriptor=descriptor };
        owner.job = CreateJobObject(ref security, name);
        int error = Marshal.GetLastWin32Error();
        if (owner.job == IntPtr.Zero) throw new Win32Exception(error, "installer_job_create");
        // Never adopt or terminate an existing object, even on a GUID collision.
        if (error == 183) throw new InvalidOperationException("installer_job_name_collision");
        var limits = new EXTENDED_LIMIT(); limits.Basic.Flags = 0x2000; // KILL_ON_JOB_CLOSE; no breakaway
        if (!SetInformationJobObject(owner.job, 9, ref limits, (uint)Marshal.SizeOf(typeof(EXTENDED_LIMIT)))) Error("installer_job_limits");
        IntPtr length = IntPtr.Zero;
        InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref length);
        if (length == IntPtr.Zero) Error("installer_job_attribute_size");
        owner.attributes = Marshal.AllocHGlobal(length);
        if (!InitializeProcThreadAttributeList(owner.attributes, 1, 0, ref length)) Error("installer_job_attributes");
        owner.attributesInitialized = true;
        owner.jobList = Marshal.AllocHGlobal(IntPtr.Size); Marshal.WriteIntPtr(owner.jobList, owner.job);
        // Atomic creation in the job avoids the crash gap between suspended
        // CreateProcess and AssignProcessToJobObject. Probe before runtime stop.
        if (!UpdateProcThreadAttribute(owner.attributes, 0, new IntPtr(0x2000D), owner.jobList, new IntPtr(IntPtr.Size), IntPtr.Zero, IntPtr.Zero)) Error("installer_job_atomic_launch_unsupported");
        return owner;
      } catch { owner.Dispose(); throw; }
      finally { if (descriptor != IntPtr.Zero) LocalFree(descriptor); }
    }
    public static InstallerJob Open(string name) {
      IntPtr handle = OpenJobObject(0x0C, false, name); // QUERY | TERMINATE
      if (handle == IntPtr.Zero) {
        int error = Marshal.GetLastWin32Error();
        if (error == 2) return null; // Absence is NOT evidence that writers exited.
        throw new Win32Exception(error, "installer_job_open");
      }
      return new InstallerJob { job=handle, Name=name };
    }
    public void Launch(string executable, string arguments, string directory) {
      if (process != IntPtr.Zero || !attributesInitialized) throw new InvalidOperationException("installer_job_launch_state");
      var startup = new STARTUPINFOEX(); startup.Startup.Size = Marshal.SizeOf(typeof(STARTUPINFOEX)); startup.Attributes = attributes;
      PROCESS_INFORMATION created;
      if (!CreateProcess(executable, new StringBuilder("\"" + executable + "\" " + arguments), IntPtr.Zero, IntPtr.Zero, false,
          0x00080000, IntPtr.Zero, directory, ref startup, out created)) Error("installer_job_launch");
      process = created.Process; CloseHandle(created.Thread);
    }
    public uint ActiveProcesses() {
      ACCOUNTING info;
      if (!QueryInformationJobObject(job, 1, out info, (uint)Marshal.SizeOf(typeof(ACCOUNTING)), IntPtr.Zero)) Error("installer_job_query");
      return info.Active;
    }
    bool RootExited() {
      if (process == IntPtr.Zero) return true;
      uint result = WaitForSingleObject(process, 0);
      if (result == 0xFFFFFFFF) Error("installer_root_wait");
      return result == 0;
    }
    public bool WaitForEmpty(long timeoutMilliseconds) {
      var clock = Stopwatch.StartNew();
      do {
        if (ActiveProcesses() == 0 && RootExited()) return true;
        if (clock.ElapsedMilliseconds >= timeoutMilliseconds) return false;
        Thread.Sleep(50);
      } while (true);
    }
    public void StopAndDrain(int timeoutMilliseconds) {
      if (ActiveProcesses() == 0 && RootExited()) return;
      if (!TerminateJobObject(job, 1460)) Error("installer_job_terminate");
      if (!WaitForEmpty(timeoutMilliseconds)) throw new TimeoutException("installer_job_writers_unconfirmed");
    }
    public int ExitCode() {
      uint code;
      if (process == IntPtr.Zero || !RootExited()) throw new InvalidOperationException("installer_root_not_exited");
      if (!GetExitCodeProcess(process, out code)) Error("installer_root_exit_code");
      return unchecked((int)code);
    }
    public void Dispose() {
      if (attributesInitialized) { DeleteProcThreadAttributeList(attributes); attributesInitialized=false; }
      if (attributes != IntPtr.Zero) { Marshal.FreeHGlobal(attributes); attributes=IntPtr.Zero; }
      if (jobList != IntPtr.Zero) { Marshal.FreeHGlobal(jobList); jobList=IntPtr.Zero; }
      if (process != IntPtr.Zero) { CloseHandle(process); process=IntPtr.Zero; }
      if (job != IntPtr.Zero) { CloseHandle(job); job=IntPtr.Zero; }
    }
  }
}
