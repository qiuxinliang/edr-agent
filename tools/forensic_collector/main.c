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
static unsigned g_partial_failures;

static int has_prefix(const char *s, const char *pfx) {
  return strncmp(s, pfx, strlen(pfx)) == 0;
}

static int copy_text_exact(char *dst, size_t cap, const char *value) {
  size_t len;
  if (!dst || cap == 0u || !value) return -1;
  len = strlen(value);
  if (len >= cap) {
    dst[0] = '\0';
    return -1;
  }
  memcpy(dst, value, len + 1u);
  return 0;
}

/* Form an output path only when every component fits.  A truncated output
 * path could make a collection appear to belong to a different case. */
static int join_path_exact(char *out, size_t cap, const char *dir, const char *name) {
  size_t dir_len;
  size_t name_len;
  int add_sep;
  if (!out || cap == 0u || !dir || !name || !dir[0] || !name[0]) return -1;
  dir_len = strlen(dir);
  name_len = strlen(name);
  if (dir_len >= cap) return -1;
  add_sep = dir[dir_len - 1u] != EDR_PATH_SEP;
  if (add_sep) {
    if (dir_len + 1u >= cap) return -1;
    out[dir_len++] = EDR_PATH_SEP;
  }
  if (name_len >= cap - dir_len) return -1;
  memcpy(out, dir, dir_len - (add_sep ? 1u : 0u));
  if (add_sep) out[dir_len - 1u] = EDR_PATH_SEP;
  memcpy(out + dir_len, name, name_len + 1u);
  return 0;
}

/* 设置 dst=value；支持 "--key=value"（value 在 eq 之后）或单独 value（next）。
 * 返回消费的额外 argv 数（0 或 1）；-2 表示匹配的值无法完整保存。 */
static int take_kv(const char *arg, const char *key, char *dst, size_t cap, const char *next) {
  size_t klen = strlen(key);
  if (strncmp(arg, key, klen) != 0) {
    return -1; /* 不匹配 */
  }
  if (arg[klen] == '=') {
    if (copy_text_exact(dst, cap, arg + klen + 1) != 0) return -2;
    return 0;
  }
  if (arg[klen] == '\0' && next) {
    if (copy_text_exact(dst, cap, next) != 0) return -2;
    return 1;
  }
  return -1;
}

static int default_output_dir(char *out, size_t cap) {
#if defined(_WIN32)
  const char *tmp = getenv("TEMP");
  if (!tmp || !tmp[0]) tmp = getenv("TMP");
  if (!tmp || !tmp[0]) tmp = ".";
  return join_path_exact(out, cap, tmp, "edr_forensic");
#else
  return copy_text_exact(out, cap, "/tmp/edr_forensic");
#endif
}

static int make_dir(const char *path) {
#if defined(_WIN32)
  if (_mkdir(path) == 0) return 0;
  {
    DWORD attributes = GetFileAttributesA(path);
    return attributes != INVALID_FILE_ATTRIBUTES &&
                   (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0
               ? 0
               : -1;
  }
#else
  struct stat st;
  if (mkdir(path, 0700) == 0) return 0;
  return stat(path, &st) == 0 && S_ISDIR(st.st_mode) ? 0 : -1;
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

/* 把命令 stdout 落到 output-dir/<name>。任何不完整的输出都不保留为完整产物，
 * 但收集可降级继续，最终由 manifest/collected.json 记录。 */
static int run_to_file(const char *cmd, const char *name) {
  char path[MAXPATH];
  int failed = 0;
  if (join_path_exact(path, sizeof(path), g_output_dir, name) != 0) {
    g_partial_failures++;
    return -1;
  }
  FILE *out = fopen(path, "wb");
  if (!out) {
    g_partial_failures++;
    return -1;
  }
#if defined(_WIN32)
  FILE *p = _popen(cmd, "rb");
#else
  FILE *p = popen(cmd, "r");
#endif
  if (!p) {
    failed = 1;
  } else {
    char buf[8192];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), p)) > 0) {
      if (fwrite(buf, 1, n, out) != n) {
        failed = 1;
        break;
      }
    }
    if (ferror(p)) failed = 1;
#if defined(_WIN32)
    if (_pclose(p) != 0) failed = 1;
#else
    if (pclose(p) != 0) failed = 1;
#endif
  }
  if (fclose(out) != 0) failed = 1;
  if (failed) {
    remove(path);
    g_partial_failures++;
    return -1;
  }
  return 0;
}

static int write_str_file(const char *name, const char *content) {
  char path[MAXPATH];
  size_t len;
  int failed = 0;
  if (!content || join_path_exact(path, sizeof(path), g_output_dir, name) != 0) return -1;
  len = strlen(content);
  FILE *f = fopen(path, "wb");
  if (!f) return -1;
  if (fwrite(content, 1, len, f) != len) failed = 1;
  if (fclose(f) != 0) failed = 1;
  if (failed) {
    remove(path);
    return -1;
  }
  return 0;
}

/* Copy targeted evidence without constructing a shell command from request
 * data.  A read/write failure removes the partial destination. */
static int copy_target_file(const char *source, const char *name) {
  char path[MAXPATH];
  char buf[8192];
  FILE *in;
  FILE *out;
  size_t n;
  int failed = 0;
  if (join_path_exact(path, sizeof(path), g_output_dir, name) != 0) return -1;
  in = fopen(source, "rb");
  if (!in) return -1;
  out = fopen(path, "wb");
  if (!out) {
    fclose(in);
    return -1;
  }
  while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
    if (fwrite(buf, 1, n, out) != n) {
      failed = 1;
      break;
    }
  }
  if (ferror(in)) failed = 1;
  if (fclose(in) != 0) failed = 1;
  if (fclose(out) != 0) failed = 1;
  if (failed) {
    remove(path);
    return -1;
  }
  return 0;
}

/* 从 --request 文件中尽力提取 "path":"..." 目标并拷贝到 output-dir（targeted/full）。 */
static void collect_request_targets(void) {
  if (!g_request[0] || !file_exists(g_request)) return;
  FILE *f = fopen(g_request, "rb");
  if (!f) {
    g_partial_failures++;
    return;
  }
  char buf[16384];
  size_t n = fread(buf, 1, sizeof(buf) - 1, f);
  int request_failed = ferror(f);
  if (!request_failed && n == sizeof(buf) - 1u) {
    if (fgetc(f) != EOF || ferror(f)) request_failed = 1;
  }
  if (fclose(f) != 0) request_failed = 1;
  if (request_failed) {
    g_partial_failures++;
    return;
  }
  buf[n] = '\0';

  int idx = 0;
  const char *p = buf;
  while ((p = strstr(p, "\"path\"")) != NULL) {
    p += 6;
    while (*p == ' ' || *p == ':' || *p == '\t') p++;
    if (*p != '"') {
      g_partial_failures++;
      continue;
    }
    p++;
    char target[MAXPATH];
    size_t ti = 0;
    int target_too_long = 0;
    while (*p && *p != '"') {
      if (*p == '\\') { /* 反转义 JSON \\ */
        if (!p[1]) break;
        p++;
      }
      if (ti + 1u >= sizeof(target)) {
        target_too_long = 1;
        while (*p && *p != '"') {
          if (*p == '\\' && p[1]) p++;
          p++;
        }
        break;
      }
      target[ti++] = *p++;
    }
    target[ti] = '\0';
    if (*p != '"') {
      g_partial_failures++;
      break;
    }
    p++;
    if (target_too_long) {
      g_partial_failures++;
      continue;
    }
    if (target[0]) {
      char dst[32];
      int written = snprintf(dst, sizeof(dst), "copied_%02d", idx++);
      if (written <= 0 || (size_t)written >= sizeof(dst) ||
          copy_target_file(target, dst) != 0) {
        g_partial_failures++;
      }
    }
  }
}

static int is_scope(const char *s) { return strcmp(g_scope, s) == 0; }

static int format_manifest(char *out, size_t cap, const char *started_at) {
  int written = snprintf(out, cap,
                         "{\"collector\":\"edr-forensic-collector\",\"version\":\"1.0.0\",\"scope\":\"%s\","
                         "\"reason\":\"%s\",\"started_at\":\"%s\",\"partial_failures\":%u}\n",
                         g_scope, g_reason, started_at, g_partial_failures);
  return written > 0 && (size_t)written < cap ? 0 : -1;
}

static int format_collected_status(char *out, size_t cap, const char *finished_at) {
  int written = snprintf(out, cap,
                         "{\"finished_at\":\"%s\",\"status\":\"%s\",\"partial_failures\":%u}\n",
                         finished_at, g_partial_failures ? "degraded" : "ok",
                         g_partial_failures);
  return written > 0 && (size_t)written < cap ? 0 : -1;
}

static int collect(void) {
  char ts[64];
  now_iso(ts, sizeof(ts));
  char manifest[1024];

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

  /* Target-copy failures are non-fatal collection degradation, but the
   * manifest must report their final count rather than the initial zero. */
  if (format_manifest(manifest, sizeof(manifest), ts) != 0 ||
      write_str_file("manifest.json", manifest) != 0) {
    return -1;
  }

  now_iso(ts, sizeof(ts));
  char done[256];
  if (format_collected_status(done, sizeof(done), ts) != 0 ||
      write_str_file("collected.json", done) != 0) {
    return -1;
  }
  return 0;
}

/* 把 output-dir 打包为 out-file（tar.gz）。返回 0 成功。 */
static int make_bundle(void) {
  char cmd[MAXPATH * 3];
  int written;
#if defined(_WIN32)
  /* Windows 10+ 自带 bsdtar（tar.exe）。 */
  written = snprintf(cmd, sizeof(cmd), "tar -czf \"%s\" -C \"%s\" . 2>nul", g_out_file, g_output_dir);
  if (written <= 0 || (size_t)written >= sizeof(cmd)) return -1;
  if (system(cmd) == 0 && file_exists(g_out_file)) return 0;
  /* 回退 PowerShell Compress-Archive（产物为 .zip 语义，但路径按 out-file 给定）。 */
  written = snprintf(cmd, sizeof(cmd),
                     "powershell -NoProfile -Command \"Compress-Archive -Path '%s\\*' -DestinationPath '%s' -Force\" >nul 2>&1",
                     g_output_dir, g_out_file);
  if (written <= 0 || (size_t)written >= sizeof(cmd)) return -1;
  (void)system(cmd);
#else
  written = snprintf(cmd, sizeof(cmd), "tar czf \"%s\" -C \"%s\" . 2>/dev/null", g_out_file, g_output_dir);
  if (written <= 0 || (size_t)written >= sizeof(cmd)) return -1;
  if (system(cmd) != 0) return -1;
#endif
  return file_exists(g_out_file) ? 0 : -1;
}

int main(int argc, char **argv) {
  for (int i = 1; i < argc; i++) {
    const char *a = argv[i];
    const char *next = (i + 1 < argc) ? argv[i + 1] : NULL;
    int adv;
    adv = take_kv(a, "--scope", g_scope, sizeof(g_scope), next);
    if (adv == -2) { fputs("forensic_collector: --scope value exceeds supported length\n", stderr); return 2; }
    if (adv >= 0) { i += adv; continue; }
    adv = take_kv(a, "--output-dir", g_output_dir, sizeof(g_output_dir), next);
    if (adv == -2) { fputs("forensic_collector: --output-dir value exceeds supported length\n", stderr); return 2; }
    if (adv >= 0) { i += adv; continue; }
    adv = take_kv(a, "--request", g_request, sizeof(g_request), next);
    if (adv == -2) { fputs("forensic_collector: --request value exceeds supported length\n", stderr); return 2; }
    if (adv >= 0) { i += adv; continue; }
    adv = take_kv(a, "--out-file", g_out_file, sizeof(g_out_file), next);
    if (adv == -2) { fputs("forensic_collector: --out-file value exceeds supported length\n", stderr); return 2; }
    if (adv >= 0) { i += adv; continue; }
    adv = take_kv(a, "--reason", g_reason, sizeof(g_reason), next);
    if (adv == -2) { fputs("forensic_collector: --reason value exceeds supported length\n", stderr); return 2; }
    if (adv >= 0) { i += adv; continue; }
    if (has_prefix(a, "--timeout")) {
      char tbuf[32] = "";
      adv = take_kv(a, "--timeout", tbuf, sizeof(tbuf), next);
      if (adv == -2) { fputs("forensic_collector: --timeout value exceeds supported length\n", stderr); return 2; }
      if (adv >= 0) {
        g_timeout = strtol(tbuf, NULL, 10);
        if (g_timeout <= 0) g_timeout = 300;
        i += adv;
      }
      continue;
    }
    /* 未知参数忽略，保持前向兼容。 */
  }

  if (!g_output_dir[0]) {
    if (default_output_dir(g_output_dir, sizeof(g_output_dir)) != 0) {
      fputs("forensic_collector: default output directory exceeds supported length\n", stderr);
      return 2;
    }
  }
  if (make_dir(g_output_dir) != 0) {
    fputs("forensic_collector: cannot create output directory\n", stderr);
    return 2;
  }

  if (collect() != 0) {
    fputs("forensic_collector: cannot record complete collection status\n", stderr);
    return 3;
  }

  if (g_out_file[0]) {
    if (make_bundle() != 0) {
      fputs("forensic_collector: bundle create failed\n", stderr);
      return 3;
    }
  }
  return 0;
}
