#include "edr/deep_collector.h"

#include "edr/sha256.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* P3:下载 + SHA256 验签的平台无关辅助(放在平台分支之前,两端共用)。 */

/* 计算文件 SHA256(十六进制,小写)。成功返回 0。大文件分块读。 */
static int dc_sha256_file(const char *path, char out65[65]) {
  out65[0] = '\0';
  FILE *f = fopen(path, "rb");
  if (!f) return -1;
  /* edr_sha256_hex 作用于完整缓冲;此处读全文件(collector 二进制,一次性验证)。 */
  if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
  long sz = ftell(f);
  if (sz < 0 || fseek(f, 0, SEEK_SET) != 0) { fclose(f); return -1; }
  uint8_t *buf = (uint8_t *)malloc((size_t)sz ? (size_t)sz : 1u);
  if (!buf) { fclose(f); return -1; }
  size_t rd = fread(buf, 1, (size_t)sz, f);
  fclose(f);
  if (rd != (size_t)sz) { free(buf); return -1; }
  int rc = edr_sha256_hex(buf, rd, out65);
  free(buf);
  return rc;
}

/* 文件是否存在。 */
static int dc_file_exists(const char *path) {
  FILE *f = fopen(path, "rb");
  if (f) { fclose(f); return 1; }
  return 0;
}

/* 经 curl 下载 url 到 dest(本地)。成功返回 0。仅在 collector 缺失且配置了 URL 时使用。 */
static int dc_download(const char *url, const char *dest) {
  if (!url || !url[0] || !dest || !dest[0]) return -1;
  char cmd[2600];
#ifdef _WIN32
  snprintf(cmd, sizeof(cmd), "curl -fsSL \"%s\" -o \"%s\" 1>nul 2>nul", url, dest);
#else
  snprintf(cmd, sizeof(cmd), "curl -fsSL '%s' -o '%s' 2>/dev/null", url, dest);
#endif
  return system(cmd) == 0 ? 0 : -1;
}

/* 从小型 manifest JSON 中提取字符串字段 "key":"value"(value 不含转义)。成功返回 0。
 * manifest 由本平台服务端产出且体量小,沿用 forensic_collector main.c 的手写扫描风格,不引 cJSON。 */
static int dc_json_str(const char *json, const char *key, char *out, size_t cap) {
  if (!json || !key || !out || cap == 0) return -1;
  out[0] = '\0';
  char needle[64];
  snprintf(needle, sizeof(needle), "\"%s\"", key);
  const char *p = strstr(json, needle);
  if (!p) return -1;
  p += strlen(needle);
  while (*p == ' ' || *p == ':' || *p == '\t') p++;
  if (*p != '"') return -1; /* 仅取字符串值 */
  p++;
  size_t i = 0;
  while (*p && *p != '"' && i + 1 < cap) {
    out[i++] = *p++;
  }
  out[i] = '\0';
  return out[0] ? 0 : -1;
}

/* manifest 是否标记 enabled:true(粗匹配,容忍空格)。 */
static int dc_json_enabled(const char *json) {
  if (!json) return 0;
  const char *p = strstr(json, "\"enabled\"");
  if (!p) return 0;
  p += 9;
  while (*p == ' ' || *p == ':' || *p == '\t') p++;
  return strncmp(p, "true", 4) == 0 ? 1 : 0;
}

/* 从平台固定地址拉取 manifest,解析出下载 url 与 sha256,下载到 dest。
 * 成功返回 0 并把期望 sha256 写入 out_sha(65);失败返回非 0。
 * manifest_url 由 EDR_FORENSIC_COLLECTOR_MANIFEST_URL 提供(installer 写入)。 */
static int dc_autofetch_via_manifest(const char *manifest_url, const char *dest,
                                     char out_sha[65], char *detail, size_t detail_cap) {
  if (!manifest_url || !manifest_url[0]) return -1;
  char mf_path[1100];
  snprintf(mf_path, sizeof(mf_path), "%s.mf.json", dest);
  if (dc_download(manifest_url, mf_path) != 0) {
    if (detail) snprintf(detail, detail_cap, "manifest fetch failed");
    return EDR_DC_ERR_DOWNLOAD;
  }
  FILE *f = fopen(mf_path, "rb");
  if (!f) {
    if (detail) snprintf(detail, detail_cap, "manifest read failed");
    return EDR_DC_ERR_DOWNLOAD;
  }
  char buf[4096];
  size_t n = fread(buf, 1, sizeof(buf) - 1, f);
  fclose(f);
  remove(mf_path);
  buf[n] = '\0';

  if (!dc_json_enabled(buf)) {
    if (detail) snprintf(detail, detail_cap, "manifest disabled (no active collector)");
    return EDR_DC_ERR_DISABLED;
  }
  char url[1024];
  if (dc_json_str(buf, "url", url, sizeof(url)) != 0) {
    if (detail) snprintf(detail, detail_cap, "manifest missing url");
    return EDR_DC_ERR_DOWNLOAD;
  }
  out_sha[0] = '\0';
  (void)dc_json_str(buf, "sha256", out_sha, 65); /* 缺 sha 则后续按 env 或无 pin 处理 */
  if (dc_download(url, dest) != 0) {
    if (detail) snprintf(detail, detail_cap, "collector download failed (manifest url)");
    return EDR_DC_ERR_DOWNLOAD;
  }
  return EDR_DC_OK;
}

/* 解析 collector 路径并(可选)下载+验签。返回 0 可执行;EDR_DC_ERR_DOWNLOAD/SIGNATURE 失败。
 * 来源:spec_bin > EDR_FORENSIC_COLLECTOR_BIN > platform_default(由调用方传入)。
 * 文件缺失时的拉取优先级:
 *   1) EDR_FORENSIC_COLLECTOR_URL(静态直链,向后兼容,最高优先);
 *   2) 否则若 autofetch 开启(EDR_FORENSIC_COLLECTOR_AUTOFETCH != "0")且配置了
 *      EDR_FORENSIC_COLLECTOR_MANIFEST_URL → 经平台固定地址 manifest 拉取(返回 sha256)。
 * 验签优先级:EDR_FORENSIC_COLLECTOR_SHA256(env pin) > manifest sha256;
 *   两者皆有则任一不匹配即拒绝执行。 */
static int dc_resolve_verify(const char *spec_bin, const char *platform_default, char *out_path,
                             size_t cap, char *detail, size_t detail_cap) {
  const char *bin = (spec_bin && spec_bin[0]) ? spec_bin : NULL;
  if (!bin) {
    const char *envb = getenv("EDR_FORENSIC_COLLECTOR_BIN");
    if (envb && envb[0]) bin = envb;
  }
  if (!bin) bin = platform_default;
  snprintf(out_path, cap, "%s", bin ? bin : "");

  char manifest_sha[65];
  manifest_sha[0] = '\0';

  if (!dc_file_exists(out_path)) {
    const char *url = getenv("EDR_FORENSIC_COLLECTOR_URL");
    if (url && url[0]) {
      if (dc_download(url, out_path) != 0) {
        if (detail) snprintf(detail, detail_cap, "collector download failed");
        return EDR_DC_ERR_DOWNLOAD;
      }
    } else {
      const char *af = getenv("EDR_FORENSIC_COLLECTOR_AUTOFETCH");
      int autofetch = !(af && af[0] == '0'); /* 默认开,显式 "0" 关闭 */
      const char *mf = getenv("EDR_FORENSIC_COLLECTOR_MANIFEST_URL");
      if (autofetch && mf && mf[0]) {
        int rc = dc_autofetch_via_manifest(mf, out_path, manifest_sha, detail, detail_cap);
        if (rc != EDR_DC_OK) return rc;
      }
    }
  }
  const char *want = getenv("EDR_FORENSIC_COLLECTOR_SHA256");
  if ((!want || !want[0]) && manifest_sha[0]) {
    want = manifest_sha; /* env 未 pin 时用 manifest 的 sha256(纵深防御:下载后本地再校验) */
  }
  if (want && want[0]) {
    char got[65];
    if (dc_sha256_file(out_path, got) != 0) {
      if (detail) snprintf(detail, detail_cap, "collector sha256 read failed");
      return EDR_DC_ERR_SIGNATURE;
    }
    /* 不区分大小写比较 */
    int mismatch = 0;
    for (int i = 0; i < 64; i++) {
      char a = got[i], b = want[i];
      if (a >= 'A' && a <= 'F') a = (char)(a - 'A' + 'a');
      if (b >= 'A' && b <= 'F') b = (char)(b - 'A' + 'a');
      if (a != b) { mismatch = 1; break; }
    }
    if (mismatch) {
      if (detail) snprintf(detail, detail_cap, "collector sha256 mismatch (got %.16s...)", got);
      return EDR_DC_ERR_SIGNATURE;
    }
  }
  return EDR_DC_OK;
}

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
  snprintf(collector_path, sizeof(collector_path),
           "%s", "C:\\Program Files\\FDSecurity\\collector\\forensic_collector.exe");

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
  /* 通信硬约束:不再传 --upload-url;产物只写本地 output-dir,上传由 agent 通道负责。 */
  snprintf(cmdline, sizeof(cmdline),
           "\"%s\" --output-dir=\"%s\" --scope=\"%s\"",
           collector_path,
           params->output_dir ? params->output_dir : "",
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

int edr_deep_collector_run_blocking(const EdrCollectorRunSpec *spec, char *out_detail,
                                    size_t detail_cap) {
  if (out_detail && detail_cap) out_detail[0] = '\0';
  if (!spec || !spec->scope || !spec->scope[0]) {
    return EDR_DC_ERR_DISABLED;
  }
  char binpath[1024];
  int vr = dc_resolve_verify(spec->collector_bin,
                             "C:\\Program Files\\FDSecurity\\collector\\forensic_collector.exe",
                             binpath, sizeof(binpath), out_detail, detail_cap);
  if (vr != EDR_DC_OK) return vr;
  const char *bin = binpath;
  uint32_t to = spec->timeout_s ? spec->timeout_s : 300u;

  /* NOTE: 通信硬约束 — 不拼 --upload-url;collector 只写本地 output-dir。 */
  char cmdline[2048];
  snprintf(cmdline, sizeof(cmdline),
           "\"%s\" --scope=\"%s\" --output-dir=\"%s\" --timeout=%u %s", bin, spec->scope,
           spec->output_dir ? spec->output_dir : ".", to, spec->extra_args ? spec->extra_args : "");

  HANDLE job = CreateJobObject(NULL, NULL);
  if (job) {
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli = {0};
    jeli.BasicLimitInformation.LimitFlags =
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
    SetInformationJobObject(job, JobObjectExtendedLimitInformation, &jeli, sizeof(jeli));
    JOBOBJECT_CPU_RATE_CONTROL_INFORMATION cpu = {0};
    cpu.ControlFlags = JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP;
    cpu.CpuRate = 1000; /* 10% */
    SetInformationJobObject(job, JobObjectCpuRateControlInformation, &cpu, sizeof(cpu));
  }

  STARTUPINFO si = {sizeof(si)};
  si.dwFlags = STARTF_USESHOWWINDOW;
  si.wShowWindow = SW_HIDE;
  PROCESS_INFORMATION pi = {0};
  BOOL cr = CreateProcess(bin, cmdline, NULL, NULL, FALSE,
                          CREATE_NEW_CONSOLE | CREATE_SUSPENDED, NULL, NULL, &si, &pi);
  if (!cr) {
    if (out_detail) {
      snprintf(out_detail, detail_cap, "CreateProcess failed: %lu", (unsigned long)GetLastError());
    }
    if (job) CloseHandle(job);
    return EDR_DC_ERR_SPAWN;
  }
  if (job) AssignProcessToJobObject(job, pi.hProcess);
  SetPriorityClass(pi.hProcess, IDLE_PRIORITY_CLASS);
  ResumeThread(pi.hThread);
  CloseHandle(pi.hThread);

  DWORD wr = WaitForSingleObject(pi.hProcess, to * 1000u);
  if (wr == WAIT_TIMEOUT) {
    if (job) {
      TerminateJobObject(job, 1);
    } else {
      TerminateProcess(pi.hProcess, 1);
    }
    if (out_detail) snprintf(out_detail, detail_cap, "collector timeout after %us", to);
    CloseHandle(pi.hProcess);
    if (job) CloseHandle(job);
    return EDR_DC_ERR_TIMEOUT;
  }
  DWORD ec = 0;
  GetExitCodeProcess(pi.hProcess, &ec);
  CloseHandle(pi.hProcess);
  if (job) CloseHandle(job);
  if (out_detail) snprintf(out_detail, detail_cap, "collector exit=%lu", (unsigned long)ec);
  return (int)ec; /* 0=成功;>0=collector 非0退出码 */
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

int edr_deep_collector_run_blocking(const EdrCollectorRunSpec *spec, char *out_detail,
                                    size_t detail_cap) {
  if (out_detail && detail_cap) out_detail[0] = '\0';
  if (!spec || !spec->scope || !spec->scope[0]) {
    return EDR_DC_ERR_DISABLED;
  }
  char binpath[1024];
  int vr = dc_resolve_verify(spec->collector_bin, find_collector_bin(), binpath, sizeof(binpath),
                             out_detail, detail_cap);
  if (vr != EDR_DC_OK) return vr;
  const char *bin = binpath;
  uint32_t to = spec->timeout_s ? spec->timeout_s : 300u;

  pid_t pid = fork();
  if (pid < 0) {
    if (out_detail) snprintf(out_detail, detail_cap, "fork failed");
    return EDR_DC_ERR_SPAWN;
  }
  if (pid == 0) {
    /* child:组装 argv(不含 --upload-url),透传 extra_args(空格分词) */
    char scope_buf[80], out_buf[1024], to_buf[40], extra[256];
    snprintf(scope_buf, sizeof(scope_buf), "--scope=%s", spec->scope);
    snprintf(out_buf, sizeof(out_buf), "--output-dir=%s", spec->output_dir ? spec->output_dir : ".");
    snprintf(to_buf, sizeof(to_buf), "--timeout=%u", to);
    extra[0] = '\0';
    if (spec->extra_args) snprintf(extra, sizeof(extra), "%s", spec->extra_args);
    char *argv[32];
    int ai = 0;
    argv[ai++] = (char *)bin;
    argv[ai++] = scope_buf;
    argv[ai++] = out_buf;
    argv[ai++] = to_buf;
    char *save = NULL;
    char *tok = strtok_r(extra, " ", &save);
    while (tok && ai < 31) {
      argv[ai++] = tok;
      tok = strtok_r(NULL, " ", &save);
    }
    argv[ai] = NULL;
    execv(bin, argv);
    _exit(127);
  }

  /* parent:带超时等待 */
  uint32_t waited_ms = 0;
  const uint32_t step_ms = 100;
  for (;;) {
    int st = 0;
    pid_t w = waitpid(pid, &st, WNOHANG);
    if (w == pid) {
      int ec = WIFEXITED(st) ? WEXITSTATUS(st) : (WIFSIGNALED(st) ? 128 + WTERMSIG(st) : -1);
      if (out_detail) snprintf(out_detail, detail_cap, "collector exit=%d", ec);
      return ec; /* 0=成功;>0=collector 失败/被信号 */
    }
    if (w < 0) {
      if (out_detail) snprintf(out_detail, detail_cap, "waitpid error");
      return EDR_DC_ERR_CRASH;
    }
    if (waited_ms >= to * 1000u) {
      kill(pid, SIGKILL);
      waitpid(pid, NULL, 0);
      if (out_detail) snprintf(out_detail, detail_cap, "collector timeout after %us", to);
      return EDR_DC_ERR_TIMEOUT;
    }
    usleep(step_ms * 1000u);
    waited_ms += step_ms;
  }
}

#endif
