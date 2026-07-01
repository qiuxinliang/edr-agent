#include "edr/deep_collector.h"

#include "edr/ingest_http.h"
#include "edr/sha256.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 平台头(供下方共享段的 dc_download 直起 curl 用;平台分支后会重复 include,有头文件 guard 无碍)。 */
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

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

/* 文件大小(字节);不存在/不可读返回 -1。可移植(fseek/ftell),无平台分支。 */
static long dc_file_size(const char *path) {
  FILE *f = fopen(path, "rb");
  if (!f) return -1;
  if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
  long sz = ftell(f);
  fclose(f);
  return sz;
}

/* 非空文件视为"就绪"。下载失败/中断常留 0 字节坏件,若仅用 dc_file_exists 会被当成已装而永不自愈。 */
static int dc_file_nonempty(const char *path) { return dc_file_size(path) > 0; }

/* url 基本合法性:必须 http(s):// 开头,且不含控制字符/引号/shell 元字符(纵深防御)。 */
static int dc_url_ok(const char *url) {
  if (!url || !url[0]) return 0;
  if (strncmp(url, "http://", 7) != 0 && strncmp(url, "https://", 8) != 0) return 0;
  /* 注:dc_download 在 Win 走 CreateProcessA(无 cmd.exe)、*nix 走 execlp(argv),URL 不经 shell 解释，
   * 故查询串里的 '&' 是合法的(manifest URL 形如 ?kind=...&os=...&arch=...);只需拦真正会破坏
   * 引号包裹/参数切分的字符:引号、空格、反引号、控制字符、重定向符。 */
  for (const unsigned char *p = (const unsigned char *)url; *p; p++) {
    if (*p < 0x20 || *p == '"' || *p == '\'' || *p == '`' ||
        *p == '\\' || *p == ' ' || *p == '<' || *p == '>') {
      return 0;
    }
  }
  return 1;
}

/* dest 路径不得含引号/控制字符(Windows 命令行引号安全;路径可含空格故只禁引号与控制符)。 */
static int dc_path_ok(const char *p) {
  if (!p || !p[0]) return 0;
  for (const unsigned char *c = (const unsigned char *)p; *c; c++) {
    if (*c < 0x20 || *c == '"') return 0;
  }
  return 1;
}

/* 经 curl 下载 url 到 dest(本地)。成功返回 0。**不经 shell**(消除命令注入):
 * POSIX 用 fork+execlp 直传 argv;Windows 用 CreateProcess 直起 curl.exe(不经 cmd.exe)。 */
/* TLS 信任:平台多为私有 CA(企业自签/mkcert),裸 curl 默认只认系统信任库 → 校验失败。
 * 取 agent 配置导出的 EDR_FORENSIC_CA_CERT 作 --cacert;EDR_FORENSIC_COLLECTOR_INSECURE_TLS=1 时 -k(逃生口)。
 * ca 路径来源可信(agent 自身配置),仅做基本字符护栏避免破坏引号/参数切分。 */
static int dc_tls_ca_ok(const char *p) {
  if (!p || !p[0]) return 0;
  for (const unsigned char *c = (const unsigned char *)p; *c; c++) {
    if (*c < 0x20 || *c == '"' || *c == '`' || *c == '<' || *c == '>') return 0;
  }
  return 1;
}

static int dc_download(const char *url, const char *dest) {
  if (!dc_url_ok(url) || !dc_path_ok(dest)) return -1;
  /* 首选 Agent 自带的 OpenSSL HTTP 客户端:认 ca.pem(私有 CA 无碍)、带鉴权头、无 Schannel 吊销/
   * curl.exe PATH 依赖。256MiB 上限覆盖 velo(~80MB),客户端流式写文件内存安全。
   * 仅当它失败(如下载源在不同主机/未配置)时回退到 curl。EDR_FORENSIC_DOWNLOAD_NO_INPROC=1 可禁用此首选。 */
  {
    const char *noinproc = getenv("EDR_FORENSIC_DOWNLOAD_NO_INPROC");
    if (!(noinproc && noinproc[0] == '1')) {
      if (edr_ingest_http_get_url_to_file(url, dest, 256u * 1024u * 1024u) == 0 && dc_file_nonempty(dest)) {
        return 0;
      }
      (void)remove(dest); /* 客户端可能留半截/0 字节,清掉再让 curl 兜底重试 */
    }
  }
  const char *ca = getenv("EDR_FORENSIC_CA_CERT");
  const char *insec = getenv("EDR_FORENSIC_COLLECTOR_INSECURE_TLS");
  int use_insecure = insec && insec[0] == '1';
  int use_ca = !use_insecure && dc_tls_ca_ok(ca);
#ifdef _WIN32
  char cmd[4096];
  char tlsopt[1200];
  tlsopt[0] = '\0';
  if (use_insecure) {
    snprintf(tlsopt, sizeof(tlsopt), " -k");
  } else if (use_ca) {
    snprintf(tlsopt, sizeof(tlsopt), " --cacert \"%s\"", ca);
  }
  /* 直起 curl.exe(lpApplicationName=NULL → 按 PATH 解析首 token);不走 cmd.exe,故无 shell 解释。
   * url/dest/ca 已过字符护栏,引号包裹安全。
   * --ssl-no-revoke:Windows 自带 curl 用 Schannel 后端,对私有 CA(mkcert/企业自签,无 CRL/OCSP)会因
   * "revocation status unknown" 拒绝(curl: (60));跳过吊销检查(仍校验证书链),这是私有 CA 的标准做法。 */
  snprintf(cmd, sizeof(cmd), "curl.exe -fsSL --ssl-no-revoke%s \"%s\" -o \"%s\"", tlsopt, url, dest);
  STARTUPINFOA si = { sizeof(si) };
  si.dwFlags = STARTF_USESHOWWINDOW;
  si.wShowWindow = SW_HIDE;
  PROCESS_INFORMATION pi = {0};
  if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
    return -1;
  }
  WaitForSingleObject(pi.hProcess, 600000); /* 10min 上限 */
  DWORD ec = 1;
  GetExitCodeProcess(pi.hProcess, &ec);
  CloseHandle(pi.hThread);
  CloseHandle(pi.hProcess);
  return ec == 0 ? 0 : -1;
#else
  pid_t pid = fork();
  if (pid < 0) return -1;
  if (pid == 0) {
    /* 子进程:argv 直传,curl 永不经 shell 解释;`--` 阻断选项注入。 */
    const char *argv[12];
    int n = 0;
    argv[n++] = "curl";
    argv[n++] = "-fsSL";
    if (use_insecure) {
      argv[n++] = "-k";
    } else if (use_ca) {
      argv[n++] = "--cacert";
      argv[n++] = ca;
    }
    argv[n++] = "--";
    argv[n++] = url;
    argv[n++] = "-o";
    argv[n++] = dest;
    argv[n] = NULL;
    execvp("curl", (char *const *)argv);
    _exit(127);
  }
  int st = 0;
  if (waitpid(pid, &st, 0) != pid) return -1;
  return (WIFEXITED(st) && WEXITSTATUS(st) == 0) ? 0 : -1;
#endif
}

static int dc_hex64_ieq(const char *a, const char *b);

/* 从小型 manifest JSON 中提取字符串字段 "key":"value"，并做标准 JSON 反转义。成功返回 0。
 * 关键:Go 的 json 编码默认把 URL 里的 '&' 转义成 &(还有 </>),
 * 若按字面照抄会得到含反斜杠的坏 URL(下载失败)。这里解码 \"、\\、\/、\n\t\r\b\f 及 \uXXXX(ASCII 直出/UTF-8)。 */
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
    if (*p != '\\') {
      out[i++] = *p++;
      continue;
    }
    /* 转义序列 */
    p++;
    char e = *p;
    if (e == '\0') break;
    switch (e) {
      case '"': out[i++] = '"'; p++; break;
      case '\\': out[i++] = '\\'; p++; break;
      case '/': out[i++] = '/'; p++; break;
      case 'n': out[i++] = '\n'; p++; break;
      case 't': out[i++] = '\t'; p++; break;
      case 'r': out[i++] = '\r'; p++; break;
      case 'b': out[i++] = '\b'; p++; break;
      case 'f': out[i++] = '\f'; p++; break;
      case 'u': {
        p++; /* 跳过 'u' */
        int v = 0, ok = 1;
        for (int k = 0; k < 4; k++) {
          char h = p[k];
          int d;
          if (h >= '0' && h <= '9') d = h - '0';
          else if (h >= 'a' && h <= 'f') d = h - 'a' + 10;
          else if (h >= 'A' && h <= 'F') d = h - 'A' + 10;
          else { ok = 0; break; }
          v = v * 16 + d;
        }
        if (!ok) { out[i++] = 'u'; break; } /* 非法 \u,退化保留 */
        p += 4;
        if (v < 0x80) {
          out[i++] = (char)v;
        } else if (v < 0x800) {
          if (i + 2 < cap) { out[i++] = (char)(0xC0 | (v >> 6)); out[i++] = (char)(0x80 | (v & 0x3F)); }
        } else {
          if (i + 3 < cap) {
            out[i++] = (char)(0xE0 | (v >> 12));
            out[i++] = (char)(0x80 | ((v >> 6) & 0x3F));
            out[i++] = (char)(0x80 | (v & 0x3F));
          }
        }
        break;
      }
      default: out[i++] = e; p++; break;
    }
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

static int dc_replace_file(const char *tmp, const char *dest) {
  if (!tmp || !tmp[0] || !dest || !dest[0]) return -1;
#ifdef _WIN32
  return MoveFileExA(tmp, dest, MOVEFILE_REPLACE_EXISTING | MOVEFILE_COPY_ALLOWED) ? 0 : -1;
#else
  return rename(tmp, dest) == 0 ? 0 : -1;
#endif
}

/* 从平台固定地址拉取 manifest,解析出下载 url 与 sha256,下载到 dest.part,验签后原子替换 dest。
 * 失败只清理 .part/manifest,不删除已有可用 dest,避免瞬时网络/平台错误破坏本地好件。
 * pin_sha 非空时优先生效;否则使用 manifest sha256。 */
static int dc_autofetch_via_manifest(const char *manifest_url, const char *dest,
                                     const char *pin_sha, char *detail, size_t detail_cap) {
  if (!manifest_url || !manifest_url[0] || !dest || !dest[0]) return -1;
  char mf_path[1100];
  char part_path[1100];
  if (snprintf(mf_path, sizeof(mf_path), "%s.mf.json", dest) >= (int)sizeof(mf_path) ||
      snprintf(part_path, sizeof(part_path), "%s.part", dest) >= (int)sizeof(part_path)) {
    if (detail) snprintf(detail, detail_cap, "collector path too long");
    return EDR_DC_ERR_DOWNLOAD;
  }
  if (dc_download(manifest_url, mf_path) != 0) {
    (void)remove(mf_path); /* 失败可能留 0 字节坏件,清掉避免下次误读 */
    if (detail) snprintf(detail, detail_cap, "manifest fetch failed");
    return EDR_DC_ERR_DOWNLOAD;
  }
  FILE *f = fopen(mf_path, "rb");
  if (!f) {
    (void)remove(mf_path);
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
  char manifest_sha[65];
  manifest_sha[0] = '\0';
  (void)dc_json_str(buf, "sha256", manifest_sha, sizeof(manifest_sha));
  const char *want = (pin_sha && pin_sha[0]) ? pin_sha : (manifest_sha[0] ? manifest_sha : NULL);

  (void)remove(part_path); /* 只清旧临时件,不碰已有最终 exe */
  if (dc_download(url, part_path) != 0) {
    (void)remove(part_path);
    if (detail) snprintf(detail, detail_cap, "artifact download failed");
    return EDR_DC_ERR_DOWNLOAD;
  }
  if (!dc_file_nonempty(part_path)) {
    (void)remove(part_path); /* 成功但 0 字节(代理/截断) → 视为失败,不替换最终件 */
    if (detail) snprintf(detail, detail_cap, "downloaded artifact is empty");
    return EDR_DC_ERR_DOWNLOAD;
  }
  if (want && want[0]) {
    char got[65];
    if (dc_sha256_file(part_path, got) != 0 || !dc_hex64_ieq(got, want)) {
      (void)remove(part_path);
      if (detail) snprintf(detail, detail_cap, "artifact sha256 mismatch/read fail");
      return EDR_DC_ERR_SIGNATURE;
    }
  }
  if (dc_replace_file(part_path, dest) != 0) {
    (void)remove(part_path);
    if (detail) snprintf(detail, detail_cap, "artifact install failed");
    return EDR_DC_ERR_DOWNLOAD;
  }
  return EDR_DC_OK;
}

/* 64 位 hex 不区分大小写相等。 */
static int dc_hex64_ieq(const char *a, const char *b) {
  for (int i = 0; i < 64; i++) {
    char x = a[i], y = b[i];
    if (x >= 'A' && x <= 'F') x = (char)(x - 'A' + 'a');
    if (y >= 'A' && y <= 'F') y = (char)(y - 'A' + 'a');
    if (x != y || x == '\0') return 0;
  }
  return 1;
}

/* 尽力创建 path 的父目录(单层即可:安装目录通常已在,仅 collector 子目录可能缺)。 */
static void dc_make_parent_dir(const char *path) {
  char dir[1024];
  snprintf(dir, sizeof(dir), "%s", path ? path : "");
  size_t n = strlen(dir);
  while (n > 0 && dir[n - 1] != '/' && dir[n - 1] != '\\') {
    dir[--n] = '\0';
  }
  if (n == 0) return;
  dir[--n] = '\0'; /* 去掉尾部分隔符 */
  if (!dir[0]) return;
#ifdef _WIN32
  (void)CreateDirectoryA(dir, NULL); /* 已存在/父级缺失均忽略,best-effort */
#else
  (void)mkdir(dir, 0755);
#endif
}

/* 确保适配器(forensic_collector)就绪到 dest:缺失且 autofetch 开启时,
 * 经平台 manifest 固定地址(EDR_FORENSIC_ADAPTER_MANIFEST_URL, kind=forensic_collector)下载 + SHA256 校验
 * (EDR_FORENSIC_ADAPTER_SHA256 > legacy EDR_FORENSIC_COLLECTOR_SHA256 > manifest sha)。best-effort:失败返回非 0,调用方据此回退 builtin。
 * 与 dc_ensure_velociraptor 同构,但目标是适配器自身(小体积),走独立 manifest(kind=forensic_collector)。 */
static int dc_ensure_adapter(const char *dest, char *detail, size_t detail_cap) {
  if (!dest || !dest[0]) return EDR_DC_ERR_DOWNLOAD;
  if (dc_file_nonempty(dest)) return EDR_DC_OK;
  const char *af = getenv("EDR_FORENSIC_COLLECTOR_AUTOFETCH");
  int autofetch = !(af && af[0] == '0');
  const char *mf = getenv("EDR_FORENSIC_ADAPTER_MANIFEST_URL"); /* kind=forensic_collector */
  if (!autofetch || !mf || !mf[0]) {
    if (detail) snprintf(detail, detail_cap, "adapter missing; autofetch/manifest unavailable");
    return EDR_DC_ERR_DOWNLOAD;
  }
  dc_make_parent_dir(dest);
  const char *want = getenv("EDR_FORENSIC_ADAPTER_SHA256");
  if (!want || !want[0]) want = getenv("EDR_FORENSIC_COLLECTOR_SHA256"); /* legacy adapter pin */
  int rc = dc_autofetch_via_manifest(mf, dest, want, detail, detail_cap);
  if (rc != EDR_DC_OK) return rc;
#ifndef _WIN32
  (void)chmod(dest, 0755); /* 下载件需可执行位 */
#endif
  return EDR_DC_OK;
}

/* 解析适配器(forensic_collector)路径并校验。返回 0 可执行;否则 <0。
 * 路径来源:spec_bin > EDR_FORENSIC_COLLECTOR_BIN > platform_default(由调用方传入)。
 * 适配器为小体积件,随安装包内置:缺失即返回 EDR_DC_ERR_DOWNLOAD(调用方回退 builtin),
 *   **不**经 velo manifest 误下载(velo 由 dc_ensure_velociraptor 拉到独立槽位)。
 * 验签:EDR_FORENSIC_ADAPTER_SHA256 或 legacy EDR_FORENSIC_COLLECTOR_SHA256(env pin)配置时校验,不匹配拒绝执行。 */
static int dc_resolve_verify(const char *spec_bin, const char *platform_default, char *out_path,
                             size_t cap, char *detail, size_t detail_cap) {
  const char *bin = (spec_bin && spec_bin[0]) ? spec_bin : NULL;
  if (!bin) {
    const char *envb = getenv("EDR_FORENSIC_COLLECTOR_BIN");
    if (envb && envb[0]) bin = envb;
  }
  if (!bin) bin = platform_default;
  snprintf(out_path, cap, "%s", bin ? bin : "");

  if (!dc_file_nonempty(out_path)) {
    /* 适配器缺失/0 字节坏件 → 经平台 manifest(kind=forensic_collector)按需自动下发到该路径,再复检。 */
    char ad[256];
    ad[0] = '\0';
    (void)dc_ensure_adapter(out_path, ad, sizeof(ad));
    if (!dc_file_nonempty(out_path)) {
      if (detail) {
        snprintf(detail, detail_cap, "collector adapter missing: %.300s (%s)", out_path,
                 ad[0] ? ad : "平台未激活适配器制品或终端无法访问固定地址");
      }
      return EDR_DC_ERR_DOWNLOAD; /* 调用方据此回退 builtin */
    }
  }
  const char *want = getenv("EDR_FORENSIC_ADAPTER_SHA256");
  if (!want || !want[0]) want = getenv("EDR_FORENSIC_COLLECTOR_SHA256"); /* legacy adapter pin */
  if (want && want[0]) {
    char got[65];
    if (dc_sha256_file(out_path, got) != 0) {
      if (detail) snprintf(detail, detail_cap, "collector sha256 read failed");
      return EDR_DC_ERR_SIGNATURE;
    }
    if (!dc_hex64_ieq(got, want)) {
      if (detail) snprintf(detail, detail_cap, "collector sha256 mismatch (got %.16s...)", got);
      return EDR_DC_ERR_SIGNATURE;
    }
  }
  return EDR_DC_OK;
}

/* 确保 velociraptor 就绪到**它自己的槽位**(EDR_VELOCIRAPTOR_BIN,适配器经此定位 velo)。
 * 缺失且 autofetch 开启时,经平台 manifest 固定地址(EDR_FORENSIC_COLLECTOR_MANIFEST_URL,
 * kind=velociraptor)下载到该路径 + SHA256 校验(EDR_VELOCIRAPTOR_SHA256 > manifest sha)。
 * best-effort:返回非 0 时调用方不应中止(适配器找不到 velo 会 exit 5 → 由上层回退 builtin)。 */
static int dc_ensure_velociraptor(char *detail, size_t detail_cap) {
  char path[1024];
  const char *velo = getenv("EDR_VELOCIRAPTOR_BIN");
  if (velo && velo[0]) {
    snprintf(path, sizeof(path), "%s", velo);
  } else {
#ifdef _WIN32
    snprintf(path, sizeof(path), "%s", "C:\\Program Files\\FDSecurity\\collector\\velociraptor.exe");
#else
    snprintf(path, sizeof(path), "%s", "velociraptor");
#endif
  }
  if (dc_file_nonempty(path)) return EDR_DC_OK; /* 已就绪(非空) */

  const char *af = getenv("EDR_FORENSIC_COLLECTOR_AUTOFETCH");
  int autofetch = !(af && af[0] == '0');
  const char *mf = getenv("EDR_FORENSIC_COLLECTOR_MANIFEST_URL"); /* kind=velociraptor */
  if (!autofetch || !mf || !mf[0]) {
    if (detail) snprintf(detail, detail_cap, "velociraptor missing; autofetch/manifest unavailable");
    return EDR_DC_ERR_DOWNLOAD;
  }
  dc_make_parent_dir(path);
  const char *want = getenv("EDR_VELOCIRAPTOR_SHA256");
  int rc = dc_autofetch_via_manifest(mf, path, want, detail, detail_cap);
  if (rc != EDR_DC_OK) return rc;
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
  if (spec->needs_velociraptor) {
    char vd[256]; vd[0] = '\0';
    if (dc_ensure_velociraptor(vd, sizeof(vd)) != EDR_DC_OK) {
      fprintf(stderr, "[forensic] velociraptor ensure: %s\n", vd[0] ? vd : "unavailable");
    }
  }
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

/* 异步 spawn(Windows):同 run_blocking 的解析/Job/CreateProcess,但不等待——登记到单例后立即返回。 */
int edr_deep_collector_spawn(const EdrCollectorRunSpec *spec, char *out_detail, size_t detail_cap) {
  if (out_detail && detail_cap) out_detail[0] = '\0';
  if (!spec || !spec->scope || !spec->scope[0]) return EDR_DC_ERR_DISABLED;

  /* 单槽:已有采集在跑则忙。 */
  if (g_collector_process) {
    DWORD ec = 0;
    if (GetExitCodeProcess(g_collector_process, &ec) && ec == STILL_ACTIVE) {
      if (out_detail) snprintf(out_detail, detail_cap, "collector busy");
      return EDR_DC_ERR_SPAWN;
    }
    CloseHandle(g_collector_process);
    g_collector_process = NULL;
  }
  if (g_collector_job) { CloseHandle(g_collector_job); g_collector_job = NULL; }
  g_running = 0;
  g_detail[0] = '\0';

  char binpath[1024];
  int vr = dc_resolve_verify(spec->collector_bin,
                             "C:\\Program Files\\FDSecurity\\collector\\forensic_collector.exe",
                             binpath, sizeof(binpath), out_detail, detail_cap);
  if (vr != EDR_DC_OK) return vr;
  if (spec->needs_velociraptor) {
    char vd[256]; vd[0] = '\0';
    if (dc_ensure_velociraptor(vd, sizeof(vd)) != EDR_DC_OK) {
      fprintf(stderr, "[forensic] velociraptor ensure: %s\n", vd[0] ? vd : "unavailable");
    }
  }
  uint32_t to = spec->timeout_s ? spec->timeout_s : 300u;

  char cmdline[2048];
  snprintf(cmdline, sizeof(cmdline),
           "\"%s\" --scope=\"%s\" --output-dir=\"%s\" --timeout=%u %s", binpath, spec->scope,
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
  BOOL cr = CreateProcess(binpath, cmdline, NULL, NULL, FALSE,
                          CREATE_NEW_CONSOLE | CREATE_SUSPENDED, NULL, NULL, &si, &pi);
  if (!cr) {
    if (out_detail) snprintf(out_detail, detail_cap, "CreateProcess failed: %lu",
                             (unsigned long)GetLastError());
    if (job) CloseHandle(job);
    return EDR_DC_ERR_SPAWN;
  }
  if (job) AssignProcessToJobObject(job, pi.hProcess);
  SetPriorityClass(pi.hProcess, IDLE_PRIORITY_CLASS);
  ResumeThread(pi.hThread);
  CloseHandle(pi.hThread);
  g_collector_process = pi.hProcess;
  g_collector_job = job;
  g_running = 1;
  return EDR_DC_OK;
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
  if (spec->needs_velociraptor) {
    char vd[256]; vd[0] = '\0';
    if (dc_ensure_velociraptor(vd, sizeof(vd)) != EDR_DC_OK) {
      fprintf(stderr, "[forensic] velociraptor ensure: %s\n", vd[0] ? vd : "unavailable");
    }
  }
  const char *bin = binpath;
  uint32_t to = spec->timeout_s ? spec->timeout_s : 300u;

  pid_t pid = fork();
  if (pid < 0) {
    if (out_detail) snprintf(out_detail, detail_cap, "fork failed");
    return EDR_DC_ERR_SPAWN;
  }
  if (pid == 0) {
    /* child:组装 argv(不含 --upload-url),透传 extra_args(空格分词) */
    char scope_buf[80], out_buf[1024], to_buf[40], extra[2048];
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

/* 异步 spawn(POSIX):同 run_blocking 的解析/fork/execv,但不等待——登记到单例后立即返回。 */
int edr_deep_collector_spawn(const EdrCollectorRunSpec *spec, char *out_detail, size_t detail_cap) {
  if (out_detail && detail_cap) out_detail[0] = '\0';
  if (!spec || !spec->scope || !spec->scope[0]) return EDR_DC_ERR_DISABLED;

  /* 单槽:已有采集在跑则忙。 */
  if (g_collector_pid && g_running) {
    int st = 0;
    pid_t w = waitpid(g_collector_pid, &st, WNOHANG);
    if (w == 0) {
      if (out_detail) snprintf(out_detail, detail_cap, "collector busy");
      return EDR_DC_ERR_SPAWN;
    }
    g_collector_pid = 0;
  }
  g_running = 0;
  g_detail[0] = '\0';

  char binpath[1024];
  int vr = dc_resolve_verify(spec->collector_bin, find_collector_bin(), binpath, sizeof(binpath),
                             out_detail, detail_cap);
  if (vr != EDR_DC_OK) return vr;
  if (spec->needs_velociraptor) {
    char vd[256]; vd[0] = '\0';
    if (dc_ensure_velociraptor(vd, sizeof(vd)) != EDR_DC_OK) {
      fprintf(stderr, "[forensic] velociraptor ensure: %s\n", vd[0] ? vd : "unavailable");
    }
  }
  uint32_t to = spec->timeout_s ? spec->timeout_s : 300u;

  pid_t pid = fork();
  if (pid < 0) {
    if (out_detail) snprintf(out_detail, detail_cap, "fork failed");
    return EDR_DC_ERR_SPAWN;
  }
  if (pid == 0) {
    char scope_buf[80], out_buf[1024], to_buf[40], extra[2048];
    snprintf(scope_buf, sizeof(scope_buf), "--scope=%s", spec->scope);
    snprintf(out_buf, sizeof(out_buf), "--output-dir=%s", spec->output_dir ? spec->output_dir : ".");
    snprintf(to_buf, sizeof(to_buf), "--timeout=%u", to);
    extra[0] = '\0';
    if (spec->extra_args) snprintf(extra, sizeof(extra), "%s", spec->extra_args);
    char *argv[32];
    int ai = 0;
    argv[ai++] = (char *)binpath;
    argv[ai++] = scope_buf;
    argv[ai++] = out_buf;
    argv[ai++] = to_buf;
    char *save = NULL;
    char *tok = strtok_r(extra, " ", &save);
    while (tok && ai < 31) { argv[ai++] = tok; tok = strtok_r(NULL, " ", &save); }
    argv[ai] = NULL;
    execv(binpath, argv);
    _exit(127);
  }
  g_collector_pid = pid;
  g_running = 1;
  snprintf(g_detail, sizeof(g_detail), "collector pid=%d started(async)", (int)pid);
  return EDR_DC_OK;
}

#endif
