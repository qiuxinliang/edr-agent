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

#else /* POSIX */

#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

static pid_t g_collector_pid = 0;
static int g_running = 0;
static char g_detail[512];

static const char *find_collector_bin(void) {
  if (access("./forensic_collector", X_OK) == 0) return "./forensic_collector";
#ifdef __APPLE__
  const char *home = getenv("HOME");
  static char path[1024];
  snprintf(path, sizeof(path), "%s/.edr/collector/forensic_collector", home ? home : "/tmp");
  if (access(path, X_OK) == 0) return path;
#endif
  return "forensic_collector";
}

int edr_deep_collector_launch(const EdrDeepCollectorParams *params) {
  if (!params) return EDR_DC_ERR_DISABLED;

  if (g_collector_pid && g_running) {
    int st = 0;
    pid_t w = waitpid(g_collector_pid, &st, WNOHANG);
    if (w == 0) return EDR_DC_ERR_SPAWN;
    g_collector_pid = 0;
  }
  g_running = 0;
  g_detail[0] = '\0';

  const char *bin = find_collector_bin();

  pid_t pid = fork();
  if (pid < 0) {
    snprintf(g_detail, sizeof(g_detail), "fork failed");
    return EDR_DC_ERR_SPAWN;
  }

  if (pid == 0) {
    char scope_str[32];
    snprintf(scope_str, sizeof(scope_str), "%s", params->scope ? params->scope : "standard");

    char timeout_str[32];
    snprintf(timeout_str, sizeof(timeout_str), "%u",
             params->timeout_s > 0 ? (unsigned)params->timeout_s : 300u);

    const char *output_dir = params->output_dir ? params->output_dir : "/tmp/edr_forensic";

    execl(bin, bin,
          "--scope", scope_str,
          "--timeout", timeout_str,
          "--output-dir", output_dir,
          (char *)NULL);

    _exit(127);
  }

  g_collector_pid = pid;
  g_running = 1;
  snprintf(g_detail, sizeof(g_detail), "collector pid=%d started", (int)pid);
  return EDR_DC_OK;
}

int edr_deep_collector_poll(int *out_exit_code, char *out_detail,
                            size_t detail_cap) {
  if (!g_collector_pid || !g_running) return 0;

  int st = 0;
  pid_t w = waitpid(g_collector_pid, &st, WNOHANG);
  if (w == 0) return 1;
  if (w < 0) {
    if (out_exit_code) *out_exit_code = -1;
    if (out_detail) snprintf(out_detail, detail_cap, "waitpid error");
    g_collector_pid = 0;
    g_running = 0;
    return EDR_DC_ERR_CRASH;
  }

  int ec = 0;
  if (WIFEXITED(st)) ec = WEXITSTATUS(st);
  else if (WIFSIGNALED(st)) ec = 128 + WTERMSIG(st);

  if (out_exit_code) *out_exit_code = ec;
  if (out_detail) snprintf(out_detail, detail_cap, "%s",
                            ec == 0 ? "completed" : "exited with error");

  g_collector_pid = 0;
  g_running = 0;
  return 0;
}

void edr_deep_collector_kill(void) {
  if (g_collector_pid && g_running) {
    kill(g_collector_pid, SIGKILL);
    waitpid(g_collector_pid, NULL, 0);
  }
  g_collector_pid = 0;
  g_running = 0;
}

int edr_deep_collector_is_running(void) {
  return g_running ? 1 : 0;
}

#endif
