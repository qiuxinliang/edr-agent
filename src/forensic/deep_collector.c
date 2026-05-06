#include "edr/deep_collector.h"

#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>

static HANDLE g_collector_process = NULL;
static HANDLE g_collector_job = NULL;
static int g_running = 0;
static char g_detail[512];

int edr_deep_collector_launch(const EdrDeepCollectorParams *params) {
  if (!params) return EDR_DC_ERR_DISABLED;

  if (g_collector_process) {
    DWORD ec = 0;
    if (GetExitCodeProcess(g_collector_process, &ec) && ec == STILL_ACTIVE) {
      return EDR_DC_ERR_SPAWN;
    }
    CloseHandle(g_collector_process);
    g_collector_process = NULL;
  }
  if (g_collector_job) {
    CloseHandle(g_collector_job);
    g_collector_job = NULL;
  }
  g_running = 0;
  g_detail[0] = '\0';

  char collector_path[MAX_PATH];
  const char *progdata = getenv("ProgramData");
  if (!progdata) progdata = "C:\\ProgramData";
  snprintf(collector_path, sizeof(collector_path),
           "%s\\EDR Agent\\collector\\forensic_collector.exe", progdata);

  HANDLE job = CreateJobObject(NULL, NULL);
  if (job) {
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli = {0};
    jeli.BasicLimitInformation.LimitFlags =
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE |
        JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
    jeli.BasicLimitInformation.PerProcessUserTimeLimit.QuadPart =
        (int64_t)params->timeout_s * 10000000LL;
    SetInformationJobObject(job, JobObjectExtendedLimitInformation,
                            &jeli, sizeof(jeli));

    JOBOBJECT_CPU_RATE_CONTROL_INFORMATION cpu = {0};
    cpu.ControlFlags =
        JOB_OBJECT_CPU_RATE_CONTROL_ENABLE |
        JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP;
    cpu.CpuRate = 1000;
    SetInformationJobObject(job, JobObjectCpuRateControlInformation,
                            &cpu, sizeof(cpu));
  }

  char cmdline[2048];
  snprintf(cmdline, sizeof(cmdline),
           "\"%s\" --output-dir=\"%s\" --upload-url=\"%s\" --scope=\"%s\"",
           collector_path,
           params->output_dir ? params->output_dir : "",
           params->upload_url ? params->upload_url : "",
           params->scope ? params->scope : "standard");

  STARTUPINFO si = { sizeof(si) };
  si.dwFlags = STARTF_USESHOWWINDOW;
  si.wShowWindow = SW_HIDE;

  PROCESS_INFORMATION pi = {0};
  BOOL cr = CreateProcess(collector_path, cmdline,
                          NULL, NULL, FALSE,
                          CREATE_NEW_CONSOLE | CREATE_SUSPENDED,
                          NULL, NULL, &si, &pi);
  if (!cr) {
    snprintf(g_detail, sizeof(g_detail), "CreateProcess failed: %lu",
             (unsigned long)GetLastError());
    if (job) CloseHandle(job);
    return EDR_DC_ERR_SPAWN;
  }

  if (job) {
    AssignProcessToJobObject(job, pi.hProcess);
  }

  SetPriorityClass(pi.hProcess, IDLE_PRIORITY_CLASS);

  ResumeThread(pi.hThread);
  CloseHandle(pi.hThread);

  g_collector_process = pi.hProcess;
  g_collector_job = job;
  g_running = 1;
  return EDR_DC_OK;
}

int edr_deep_collector_poll(int *out_exit_code, char *out_detail,
                            size_t detail_cap) {
  if (!g_collector_process || !g_running) return 0;

  DWORD ec = 0;
  if (!GetExitCodeProcess(g_collector_process, &ec)) {
    if (out_exit_code) *out_exit_code = -1;
    if (out_detail) {
      snprintf(out_detail, detail_cap, "GetExitCodeProcess failed");
    }
    CloseHandle(g_collector_process);
    g_collector_process = NULL;
    g_running = 0;
    return EDR_DC_ERR_CRASH;
  }

  if (ec != STILL_ACTIVE) {
    if (out_exit_code) *out_exit_code = (int)ec;
    if (out_detail) {
      snprintf(out_detail, detail_cap, "%s", g_detail[0] ? g_detail : "completed");
    }
    CloseHandle(g_collector_process);
    g_collector_process = NULL;
    g_running = 0;
    return 0;
  }
  return 1;
}

void edr_deep_collector_kill(void) {
  if (g_collector_process) {
    TerminateProcess(g_collector_process, 9);
    CloseHandle(g_collector_process);
    g_collector_process = NULL;
  }
  if (g_collector_job) {
    CloseHandle(g_collector_job);
    g_collector_job = NULL;
  }
  g_running = 0;
}

int edr_deep_collector_is_running(void) {
  return g_running ? 1 : 0;
}

#else /* POSIX stub */

int edr_deep_collector_launch(const EdrDeepCollectorParams *params) {
  (void)params;
  return EDR_DC_ERR_DISABLED;
}

int edr_deep_collector_poll(int *out_exit_code, char *out_detail,
                            size_t detail_cap) {
  (void)out_exit_code;
  (void)out_detail;
  (void)detail_cap;
  return 0;
}

void edr_deep_collector_kill(void) {}

int edr_deep_collector_is_running(void) { return 0; }

#endif
