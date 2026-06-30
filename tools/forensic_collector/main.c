/* ============================================================================
 * EDR Deep Forensic Collector (独立可执行，对标 CrowdStrike Falcon Forensics Collector)
 *
 * 由 agent 的 deep_collector.c fork/CreateProcess 调用；通信只走 agent：
 * collector 仅在本地落产物，由 agent 经 transport v2 上传（本程序不联网）。
 *
 * 契约（与 edr-agent/src/forensic/deep_collector.c 对齐）：
 *   forensic_collector --scope=<triage|standard|full|all> --output-dir=<dir> \
 *                      --timeout=<sec> [--request=<file>] [--out-file=<bundle>] [--reason=<str>]
 *   - 同时接受 --key=value 与 --key value 两种形式。
 *   - 所有产物写 --output-dir；若给了 --out-file，则把 output-dir 打包为该文件
 *     （agent 随后上传 --out-file）。out-file 不存在会导致 agent 上传失败。
 *   - 退出码 0=成功；非 0=失败（与 agent edr_deep_collector_run_blocking 的 ec 语义一致）。
 * ==========================================================================*/

#if defined(_MSC_VER)
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(_WIN32)
#include <direct.h>
#include <windows.h>
#define EDR_PATH_SEP '\\'
#else
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#define EDR_PATH_SEP '/'
#endif

#define MAXPATH 1024

static char g_scope[64] = "standard";
static char g_output_dir[MAXPATH] = "";
static char g_request[MAXPATH] = "";
static char g_out_file[MAXPATH] = "";
static char g_reason[256] = "";
static long g_timeout = 300;

static int has_prefix(const char *s, const char *pfx) {
  return strncmp(s, pfx, strlen(pfx)) == 0;
}

/* 设置 dst=value；支持 "--key=value"（value 在 eq 之后）或单独 value（next）。
 * 返回消费的额外 argv 数（0 或 1）。 */
static int take_kv(const char *arg, const char *key, char *dst, size_t cap, const char *next) {
  size_t klen = strlen(key);
  if (strncmp(arg, key, klen) != 0) {
    return -1; /* 不匹配 */
  }
  if (arg[klen] == '=') {
    snprintf(dst, cap, "%s", arg + klen + 1);
    return 0;
  }
  if (arg[klen] == '\0' && next) {
    snprintf(dst, cap, "%s", next);
    return 1;
  }
  return -1;
}

static void default_output_dir(char *out, size_t cap) {
#if defined(_WIN32)
  const char *tmp = getenv("TEMP");
  if (!tmp || !tmp[0]) tmp = getenv("TMP");
  if (!tmp || !tmp[0]) tmp = ".";
  snprintf(out, cap, "%s\\edr_forensic", tmp);
#else
  snprintf(out, cap, "%s", "/tmp/edr_forensic");
#endif
}

static int make_dir(const char *path) {
#if defined(_WIN32)
  return (_mkdir(path) == 0 || GetLastError() == ERROR_ALREADY_EXISTS) ? 0 : -1;
#else
  return (mkdir(path, 0700) == 0 || 1) ? 0 : -1; /* 已存在也算成功 */
#endif
}

static int file_exists(const char *path) {
  FILE *f = fopen(path, "rb");
  if (!f) return 0;
  fclose(f);
  return 1;
}

static void now_iso(char *out, size_t cap) {
  time_t t = time(NULL);
  struct tm tmv;
#if defined(_WIN32)
  gmtime_s(&tmv, &t);
#else
  gmtime_r(&t, &tmv);
#endif
  strftime(out, cap, "%Y-%m-%dT%H:%M:%SZ", &tmv);
}

/* 把命令 stdout 落到 output-dir/<name>。失败不致命（产物缺失即可）。 */
static void run_to_file(const char *cmd, const char *name) {
  char path[MAXPATH];
  snprintf(path, sizeof(path), "%s%c%s", g_output_dir, EDR_PATH_SEP, name);
  FILE *out = fopen(path, "wb");
  if (!out) return;
#if defined(_WIN32)
  FILE *p = _popen(cmd, "rb");
#else
  FILE *p = popen(cmd, "r");
#endif
  if (p) {
    char buf[8192];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), p)) > 0) {
      fwrite(buf, 1, n, out);
    }
#if defined(_WIN32)
    _pclose(p);
#else
    pclose(p);
#endif
  }
  fclose(out);
}

static void write_str_file(const char *name, const char *content) {
  char path[MAXPATH];
  snprintf(path, sizeof(path), "%s%c%s", g_output_dir, EDR_PATH_SEP, name);
  FILE *f = fopen(path, "wb");
  if (!f) return;
  fputs(content, f);
  fclose(f);
}

/* 从 --request 文件中尽力提取 "path":"..." 目标并拷贝到 output-dir（targeted/full）。 */
static void collect_request_targets(void) {
  if (!g_request[0] || !file_exists(g_request)) return;
  FILE *f = fopen(g_request, "rb");
  if (!f) return;
  char buf[16384];
  size_t n = fread(buf, 1, sizeof(buf) - 1, f);
  fclose(f);
  buf[n] = '\0';

  int idx = 0;
  const char *p = buf;
  while ((p = strstr(p, "\"path\"")) != NULL) {
    p += 6;
    while (*p == ' ' || *p == ':' || *p == '"') p++;
    char target[MAXPATH];
    size_t ti = 0;
    while (*p && *p != '"' && ti < sizeof(target) - 1) {
      if (*p == '\\' && p[1]) { /* 反转义 JSON \\ */
        p++;
      }
      target[ti++] = *p++;
    }
    target[ti] = '\0';
    if (target[0]) {
      char dst[MAXPATH];
      snprintf(dst, sizeof(dst), "copied_%02d", idx++);
      char cmd[MAXPATH * 2];
#if defined(_WIN32)
      snprintf(cmd, sizeof(cmd), "copy /Y \"%s\" \"%s%c%s\" >nul 2>&1", target, g_output_dir, EDR_PATH_SEP, dst);
      (void)system(cmd);
#else
      snprintf(cmd, sizeof(cmd), "cp -f \"%s\" \"%s/%s\" 2>/dev/null", target, g_output_dir, dst);
      (void)system(cmd);
#endif
    }
  }
}

static int is_scope(const char *s) { return strcmp(g_scope, s) == 0; }

static void collect(void) {
  char ts[64];
  now_iso(ts, sizeof(ts));
  char manifest[1024];
  snprintf(manifest, sizeof(manifest),
           "{\"collector\":\"edr-forensic-collector\",\"version\":\"1.0.0\",\"scope\":\"%s\","
           "\"reason\":\"%s\",\"started_at\":\"%s\"}\n",
           g_scope, g_reason, ts);
  write_str_file("manifest.json", manifest);

#if defined(_WIN32)
  run_to_file("systeminfo", "system_info.txt");
  run_to_file("hostname", "hostname.txt");
  run_to_file("tasklist /v /fo csv", "process_list.csv");
  run_to_file("netstat -ano", "network.txt");
  if (!is_scope("triage")) {
    run_to_file("schtasks /query /fo LIST /v", "scheduled_tasks.txt");
    run_to_file("reg query \"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\"", "run_keys.txt");
    run_to_file("reg query \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\"", "run_keys_user.txt");
    run_to_file("wmic startup get caption,command", "startup_items.txt");
  }
#else
  run_to_file("uname -a 2>/dev/null", "system_info.txt");
  run_to_file("hostname 2>/dev/null", "hostname.txt");
  run_to_file("uptime 2>/dev/null", "uptime.txt");
  run_to_file("ps aux 2>/dev/null", "process_list.txt");
  /* 网络：优先 ss（Linux），回退 netstat / lsof（macOS） */
  run_to_file("ss -tunap 2>/dev/null || netstat -an 2>/dev/null", "network.txt");
  run_to_file("lsof -i -nP 2>/dev/null | head -1000", "network_lsof.txt");
  if (!is_scope("triage")) {
    run_to_file("crontab -l 2>/dev/null", "cron.txt");
    run_to_file("ls -la /etc/cron.* 2>/dev/null; ls -la /etc/init.d 2>/dev/null; "
                "ls -la ~/Library/LaunchAgents /Library/LaunchAgents /Library/LaunchDaemons 2>/dev/null",
                "startup_items.txt");
    run_to_file("systemctl list-unit-files --type=service 2>/dev/null | head -500", "services.txt");
  }
#endif

  if (is_scope("full") || is_scope("targeted") || is_scope("all")) {
    collect_request_targets();
  }

  now_iso(ts, sizeof(ts));
  char done[256];
  snprintf(done, sizeof(done), "{\"finished_at\":\"%s\",\"status\":\"ok\"}\n", ts);
  write_str_file("collected.json", done);
}

/* 把 output-dir 打包为 out-file（tar.gz）。返回 0 成功。 */
static int make_bundle(void) {
  char cmd[MAXPATH * 3];
#if defined(_WIN32)
  /* Windows 10+ 自带 bsdtar（tar.exe）。 */
  snprintf(cmd, sizeof(cmd), "tar -czf \"%s\" -C \"%s\" . 2>nul", g_out_file, g_output_dir);
  if (system(cmd) == 0 && file_exists(g_out_file)) return 0;
  /* 回退 PowerShell Compress-Archive（产物为 .zip 语义，但路径按 out-file 给定）。 */
  snprintf(cmd, sizeof(cmd),
           "powershell -NoProfile -Command \"Compress-Archive -Path '%s\\*' -DestinationPath '%s' -Force\" >nul 2>&1",
           g_output_dir, g_out_file);
  (void)system(cmd);
#else
  snprintf(cmd, sizeof(cmd), "tar czf \"%s\" -C \"%s\" . 2>/dev/null", g_out_file, g_output_dir);
  (void)system(cmd);
#endif
  return file_exists(g_out_file) ? 0 : -1;
}

int main(int argc, char **argv) {
  for (int i = 1; i < argc; i++) {
    const char *a = argv[i];
    const char *next = (i + 1 < argc) ? argv[i + 1] : NULL;
    int adv;
    if ((adv = take_kv(a, "--scope", g_scope, sizeof(g_scope), next)) >= 0) { i += adv; continue; }
    if ((adv = take_kv(a, "--output-dir", g_output_dir, sizeof(g_output_dir), next)) >= 0) { i += adv; continue; }
    if ((adv = take_kv(a, "--request", g_request, sizeof(g_request), next)) >= 0) { i += adv; continue; }
    if ((adv = take_kv(a, "--out-file", g_out_file, sizeof(g_out_file), next)) >= 0) { i += adv; continue; }
    if ((adv = take_kv(a, "--reason", g_reason, sizeof(g_reason), next)) >= 0) { i += adv; continue; }
    if (has_prefix(a, "--timeout")) {
      char tbuf[32] = "";
      if ((adv = take_kv(a, "--timeout", tbuf, sizeof(tbuf), next)) >= 0) {
        g_timeout = strtol(tbuf, NULL, 10);
        if (g_timeout <= 0) g_timeout = 300;
        i += adv;
      }
      continue;
    }
    /* 未知参数忽略，保持前向兼容。 */
  }

  if (!g_output_dir[0]) {
    default_output_dir(g_output_dir, sizeof(g_output_dir));
  }
  if (make_dir(g_output_dir) != 0) {
    fprintf(stderr, "forensic_collector: cannot create output dir: %s\n", g_output_dir);
    return 2;
  }

  collect();

  if (g_out_file[0]) {
    if (make_bundle() != 0) {
      fprintf(stderr, "forensic_collector: bundle create failed: %s\n", g_out_file);
      return 3;
    }
  }
  return 0;
}
