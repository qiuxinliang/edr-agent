#include "edr/response.h"
#include "edr/command_cancel.h"
#include "edr/command_util.h"
#include "edr/config.h"
#include "edr/deep_collector.h"
#include "edr/error.h"
#include "edr/ingest_http.h"
#include "edr/pmfe.h"
#include "edr/sha256.h"
#include "edr/shell_session.h"
#include "edr/edr_log.h"
#include "edr/pe_verify.h"
#include "edr/shell_exec.h"
#include "edr/transport_v2.h"
#include "cJSON.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <direct.h>
#include <process.h>
#include <windows.h>
#include <dbghelp.h>
#pragma comment(lib, "dbghelp.lib")
#else
#include <dirent.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#include "edr/response_utils.h"

static void response_json_escape(const char *in, char *out, size_t cap);

static int response_file_sha256(const char *path, char out65[65]) {
  FILE *f;
  EdrSha256Ctx ctx;
  uint8_t digest[EDR_SHA256_DIGEST_LEN];
  uint8_t buf[65536];
  size_t n;
  static const char hex[] = "0123456789abcdef";
  if (!path || !path[0] || !out65) return -1;
  out65[0] = '\0';
  f = fopen(path, "rb");
  if (!f) return -1;
  edr_sha256_init(&ctx);
  while ((n = fread(buf, 1, sizeof(buf), f)) > 0) edr_sha256_update(&ctx, buf, n);
  if (ferror(f)) { fclose(f); return -1; }
  fclose(f);
  edr_sha256_final(&ctx, digest);
  for (size_t i = 0; i < sizeof(digest); i++) {
    out65[i * 2] = hex[digest[i] >> 4];
    out65[i * 2 + 1] = hex[digest[i] & 0x0f];
  }
  out65[64] = '\0';
  return 0;
}

static void forensic_result_json(char *out, size_t out_cap, const char *status,
                                 const char *source, const char *artifact, const char *sha256,
                                 const char *object_key, int truncated, const char *upload_status,
                                 const char *error) {
  char source_esc[96], artifact_esc[1200], key_esc[1200], error_esc[600];
  response_json_escape(source ? source : "", source_esc, sizeof(source_esc));
  response_json_escape(artifact ? artifact : "", artifact_esc, sizeof(artifact_esc));
  response_json_escape(object_key ? object_key : "", key_esc, sizeof(key_esc));
  response_json_escape(error ? error : "", error_esc, sizeof(error_esc));
  snprintf(out, out_cap,
           "{\"schema\":\"edr.forensic.result.v1\",\"status\":\"%s\","
           "\"source\":\"%s\",\"artifact\":\"%s\",\"sha256\":\"%s\","
           "\"object_key\":\"%s\",\"truncated\":%s,\"upload_status\":\"%s\","
           "\"error\":\"%s\"}",
           status ? status : "failed", source_esc, artifact_esc, sha256 ? sha256 : "",
           key_esc, truncated ? "true" : "false",
           upload_status ? upload_status : "not_requested", error_esc);
}

static void yara_artifact_result_json(char *out, size_t out_cap, const char *status,
                                      const char *source, const char *artifact, const char *sha256,
                                      const char *object_key, const char *upload_status,
                                      const char *error, int partial) {
  char source_esc[96], artifact_esc[1200], key_esc[1200], error_esc[600];
  response_json_escape(source ? source : "", source_esc, sizeof(source_esc));
  response_json_escape(artifact ? artifact : "", artifact_esc, sizeof(artifact_esc));
  response_json_escape(object_key ? object_key : "", key_esc, sizeof(key_esc));
  response_json_escape(error ? error : "", error_esc, sizeof(error_esc));
  snprintf(out, out_cap,
           "{\"schema\":\"edr.yara_scan.result.v1\",\"status\":\"%s\","
           "\"source\":\"%s\",\"engine\":\"%s\",\"scan_status\":\"artifact_only\","
           "\"artifact\":\"%s\",\"sha256\":\"%s\",\"object_key\":\"%s\","
           "\"upload_status\":\"%s\",\"truncated\":false,\"error\":\"%s\","
           "\"warnings\":[\"%s\"]}",
           status ? status : "failed", source_esc, source_esc, artifact_esc,
           sha256 ? sha256 : "", key_esc,
           upload_status ? upload_status : "not_requested", error_esc,
           error_esc[0] ? error_esc :
           partial ? "collector completed with warnings; inspect the uploaded artifact for full results" :
                     "external collector returned an evidence artifact; inline match status is unavailable");
}

/* ── 取证 YARA 真引擎（libyara，构建启用 EDR_WITH_YARA 时可用） ──
 * 规则来源优先级:命令 payload 内联 rules > [command].forensic_yara_rules_dir >
 * EDR_YARA_RULES_DIR > rules/forensic。scan 回调收集命中规则名。
 * 不可用（未链接 libyara / 规则编译失败 / 扫描失败）时默认失败；仅在显式开启
 * EDR_YARA_ALLOW_BUILTIN_FALLBACK=1 时降级到内置子串启发式并在结果中标记 degraded。 */
#ifdef EDR_HAVE_YARA
#include <yara.h>

#define EDR_FY_RULE_NAME_MAX 128
#define EDR_FY_MAX_HITS 8

typedef struct {
  char rules[EDR_FY_MAX_HITS][EDR_FY_RULE_NAME_MAX];
  int count;
  const char *cancel_cmd_id;
  int cancelled;
} ForensicYaraResult;

static int s_fy_initialized;
#ifdef _WIN32
static INIT_ONCE s_fy_init_once = INIT_ONCE_STATIC_INIT;
static BOOL CALLBACK fy_initialize_once(PINIT_ONCE once, PVOID param, PVOID *ctx) {
  (void)once; (void)param; (void)ctx;
  s_fy_initialized = yr_initialize() == ERROR_SUCCESS ? 1 : -1;
  return TRUE;
}
#else
static pthread_once_t s_fy_init_once = PTHREAD_ONCE_INIT;
static void fy_initialize_once(void) {
  s_fy_initialized = yr_initialize() == ERROR_SUCCESS ? 1 : -1;
}
#endif

typedef struct {
  char msg[256];
} ForensicYaraCompileState;

static void fy_compiler_error_cb(int level, const char *fn, int line, const YR_RULE *rule,
                                 const char *msg, void *ud) {
  (void)rule;
  const char *lv = (level == YARA_ERROR_LEVEL_WARNING) ? "warning" : "error";
  fprintf(stderr, "[forensic-yara] compile %s file=%s line=%d msg=%s\n", lv, fn ? fn : "-", line,
          msg ? msg : "-");
  ForensicYaraCompileState *st = (ForensicYaraCompileState *)ud;
  if (st && level != YARA_ERROR_LEVEL_WARNING && st->msg[0] == '\0') {
    snprintf(st->msg, sizeof(st->msg), "compile error file=%s line=%d msg=%s", fn ? fn : "-", line,
             msg ? msg : "-");
  }
}

#if defined(YR_VERSION_HEX) && YR_VERSION_HEX >= 0x040500
static int fy_scan_cb(YR_SCAN_CONTEXT *ctx, int message, void *message_data, void *user_data) {
  (void)ctx;
#else
static int fy_scan_cb(int message, void *message_data, void *user_data) {
#endif
  ForensicYaraResult *res = (ForensicYaraResult *)user_data;
  if (!res) {
    return CALLBACK_CONTINUE;
  }
  if (res->cancel_cmd_id && edr_command_cancel_requested(res->cancel_cmd_id)) {
    res->cancelled = 1;
    return CALLBACK_ABORT;
  }
  if (message == CALLBACK_MSG_RULE_MATCHING) {
    const YR_RULE *rule = (const YR_RULE *)message_data;
    if (rule && rule->identifier && res->count < EDR_FY_MAX_HITS) {
      snprintf(res->rules[res->count], EDR_FY_RULE_NAME_MAX, "%s", rule->identifier);
      res->count++;
    }
  }
  return CALLBACK_CONTINUE;
}

static int fy_scan_rules(YR_RULES *rules, const char *cmd_id, const char *target_path, const uint8_t *buf, size_t len,
                         ForensicYaraResult *res, char *err, size_t err_cap) {
  if (!rules || !res) {
    if (err && err_cap) snprintf(err, err_cap, "libyara rules unavailable");
    return 0;
  }
  memset(res, 0, sizeof(*res));
  res->cancel_cmd_id = cmd_id;
  int rc = ERROR_INTERNAL_FATAL_ERROR;
  if (target_path && target_path[0]) {
    rc = yr_rules_scan_file(rules, target_path, 0, fy_scan_cb, res, 0);
  }
  if (rc != ERROR_SUCCESS && buf && len > 0u) {
    rc = yr_rules_scan_mem(rules, buf, len, 0, fy_scan_cb, res, 0);
  }
  if (res->cancelled) {
    if (err && err_cap) snprintf(err, err_cap, "libyara scan cancelled");
    return 0;
  }
  if (rc != ERROR_SUCCESS) {
    if (err && err_cap) snprintf(err, err_cap, "libyara scan failed rc=%d", rc);
    return 0;
  }
  return 1;
}

static int fy_ensure_initialized(char *err, size_t err_cap) {
#ifdef _WIN32
  (void)InitOnceExecuteOnce(&s_fy_init_once, fy_initialize_once, NULL, NULL);
#else
  (void)pthread_once(&s_fy_init_once, fy_initialize_once);
#endif
  if (s_fy_initialized != 1) {
    if (err && err_cap) snprintf(err, err_cap, "libyara initialize failed");
    return 0;
  }
  return 1;
}

static YR_RULES *fy_compile_inline_rules(const char *rules_text, char *err, size_t err_cap) {
  if (!rules_text || !rules_text[0]) {
    if (err && err_cap) snprintf(err, err_cap, "inline YARA rules required");
    return NULL;
  }
  if (!fy_ensure_initialized(err, err_cap)) return NULL;
  YR_COMPILER *c = NULL;
  if (yr_compiler_create(&c) != ERROR_SUCCESS || !c) {
    if (err && err_cap) snprintf(err, err_cap, "libyara compiler create failed");
    return NULL;
  }
  ForensicYaraCompileState cstate;
  memset(&cstate, 0, sizeof(cstate));
  yr_compiler_set_callback(c, fy_compiler_error_cb, &cstate);
  int nerr = yr_compiler_add_string(c, rules_text, "inline");
  if (nerr > 0) {
    if (err && err_cap) snprintf(err, err_cap, "%s", cstate.msg[0] ? cstate.msg : "inline YARA rule compile failed");
    yr_compiler_destroy(c);
    return NULL;
  }
  YR_RULES *rules = NULL;
  if (yr_compiler_get_rules(c, &rules) != ERROR_SUCCESS || !rules) {
    if (err && err_cap) snprintf(err, err_cap, "inline YARA rule finalize failed");
    yr_compiler_destroy(c);
    return NULL;
  }
  yr_compiler_destroy(c);
  return rules;
}

static int fy_rule_file_path(const char *path) {
  if (!path || !path[0]) return 0;
  const char *dot = strrchr(path, '.');
  if (!dot) return 0;
  char ext[8];
  size_t i = 0;
  for (; dot[i] && i < sizeof(ext) - 1; i++) ext[i] = (char)tolower((unsigned char)dot[i]);
  ext[i] = '\0';
  return strcmp(ext, ".yar") == 0 || strcmp(ext, ".yara") == 0;
}

static int fy_add_rule_file(YR_COMPILER *c, const char *path, int *loaded, char *err, size_t err_cap) {
  if (!c || !path || !path[0] || !fy_rule_file_path(path)) return 1;
  FILE *fp = fopen(path, "rb");
  if (!fp) {
    if (err && err_cap) snprintf(err, err_cap, "open YARA rule file failed: %s", path);
    return 0;
  }
  int nerr = yr_compiler_add_file(c, fp, NULL, path);
  fclose(fp);
  if (nerr > 0) {
    if (err && err_cap && !err[0]) snprintf(err, err_cap, "compile YARA rule file failed: %s", path);
    return 0;
  }
  if (loaded) (*loaded)++;
  return 1;
}

#ifdef _WIN32
static int fy_add_rules_from_dir(YR_COMPILER *c, const char *dir, int *loaded, char *err, size_t err_cap) {
  char pat[1100];
  snprintf(pat, sizeof(pat), "%s\\*", dir);
  WIN32_FIND_DATAA ffd;
  HANDLE h = FindFirstFileA(pat, &ffd);
  if (h == INVALID_HANDLE_VALUE) {
    if (err && err_cap) snprintf(err, err_cap, "open YARA rules dir failed: %s", dir ? dir : "");
    return 0;
  }
  int ok = 1;
  do {
    if ((ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) continue;
    char full[1200];
    snprintf(full, sizeof(full), "%s\\%s", dir, ffd.cFileName);
    if (!fy_add_rule_file(c, full, loaded, err, err_cap)) { ok = 0; break; }
  } while (FindNextFileA(h, &ffd));
  FindClose(h);
  return ok;
}
#else
static int fy_add_rules_from_dir(YR_COMPILER *c, const char *dir, int *loaded, char *err, size_t err_cap) {
  DIR *d = opendir(dir);
  if (!d) {
    if (err && err_cap) snprintf(err, err_cap, "open YARA rules dir failed: %s", dir ? dir : "");
    return 0;
  }
  int ok = 1;
  struct dirent *ent;
  while ((ent = readdir(d)) != NULL) {
    if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;
    char full[1200];
    snprintf(full, sizeof(full), "%s/%s", dir, ent->d_name);
    struct stat st;
    if (stat(full, &st) != 0 || !S_ISREG(st.st_mode)) continue;
    if (!fy_add_rule_file(c, full, loaded, err, err_cap)) { ok = 0; break; }
  }
  closedir(d);
  return ok;
}
#endif

static const char *fy_effective_rules_dir(char *buf, size_t cap) {
  const EdrConfig *cfg = edr_command_get_config();
  if (cfg && cfg->command.forensic_yara_rules_dir[0]) {
    snprintf(buf, cap, "%s", cfg->command.forensic_yara_rules_dir);
    return buf;
  }
  const char *env = getenv("EDR_YARA_RULES_DIR");
  if (env && env[0]) {
    snprintf(buf, cap, "%s", env);
    return buf;
  }
  snprintf(buf, cap, "%s", "rules/forensic");
  return buf;
}

static YR_RULES *fy_compile_rules_dir(const char *rules_dir, int *files_loaded, char *err, size_t err_cap) {
  if (!rules_dir || !rules_dir[0]) {
    if (err && err_cap) snprintf(err, err_cap, "forensic YARA rules dir is empty");
    return NULL;
  }
  if (files_loaded) *files_loaded = 0;
  if (!fy_ensure_initialized(err, err_cap)) return NULL;
  YR_COMPILER *c = NULL;
  if (yr_compiler_create(&c) != ERROR_SUCCESS || !c) {
    if (err && err_cap) snprintf(err, err_cap, "libyara compiler create failed");
    return NULL;
  }
  ForensicYaraCompileState cstate;
  memset(&cstate, 0, sizeof(cstate));
  yr_compiler_set_callback(c, fy_compiler_error_cb, &cstate);
  int loaded = 0;
  if (!fy_add_rules_from_dir(c, rules_dir, &loaded, err, err_cap)) {
    if (err && err_cap && !err[0]) snprintf(err, err_cap, "%s", cstate.msg[0] ? cstate.msg : "YARA rules dir compile failed");
    yr_compiler_destroy(c);
    return NULL;
  }
  if (loaded <= 0) {
    if (err && err_cap) snprintf(err, err_cap, "no .yar/.yara files loaded from %s", rules_dir);
    yr_compiler_destroy(c);
    return NULL;
  }
  YR_RULES *rules = NULL;
  if (yr_compiler_get_rules(c, &rules) != ERROR_SUCCESS || !rules) {
    if (err && err_cap) snprintf(err, err_cap, "%s", cstate.msg[0] ? cstate.msg : "YARA rules dir finalize failed");
    yr_compiler_destroy(c);
    return NULL;
  }
  yr_compiler_destroy(c);
  if (files_loaded) *files_loaded = loaded;
  return rules;
}

static YR_RULES *fy_compile_effective_rules(const char *rules_text, char *source, size_t source_cap,
                                            int *files_loaded, char *err, size_t err_cap) {
  if (files_loaded) *files_loaded = 0;
  if (rules_text && rules_text[0]) {
    if (source && source_cap) snprintf(source, source_cap, "inline");
    return fy_compile_inline_rules(rules_text, err, err_cap);
  }
  char dir[1024];
  const char *rules_dir = fy_effective_rules_dir(dir, sizeof(dir));
  if (source && source_cap) snprintf(source, source_cap, "rules_dir:%s", rules_dir);
  return fy_compile_rules_dir(rules_dir, files_loaded, err, err_cap);
}

#endif /* EDR_HAVE_YARA */

struct EdrForensicYaraSession {
#ifdef EDR_HAVE_YARA
  YR_RULES *rules;
#else
  int unavailable;
#endif
};

EdrForensicYaraSession *edr_response_yara_session_open(char *error, size_t error_cap) {
  if (error && error_cap) error[0] = '\0';
#ifdef EDR_HAVE_YARA
  char source[1100];
  char compile_error[256];
  int files_loaded = 0;
  source[0] = '\0';
  compile_error[0] = '\0';
  YR_RULES *rules = fy_compile_effective_rules(NULL, source, sizeof(source),
                                                &files_loaded, compile_error,
                                                sizeof(compile_error));
  if (!rules) {
    if (error && error_cap) snprintf(error, error_cap, "%s", compile_error);
    return NULL;
  }
  EdrForensicYaraSession *session = (EdrForensicYaraSession *)calloc(1u, sizeof(*session));
  if (!session) {
    yr_rules_destroy(rules);
    if (error && error_cap) snprintf(error, error_cap, "%s", "YARA session allocation failed");
    return NULL;
  }
  session->rules = rules;
  return session;
#else
  if (error && error_cap) snprintf(error, error_cap, "%s", "libyara unavailable in this build");
  return NULL;
#endif
}

int edr_response_yara_session_scan(EdrForensicYaraSession *session, const char *cmd_id,
                                   const uint8_t *buf, size_t len, char (*hits)[128],
                                   size_t hit_cap, size_t *hit_count,
                                   char *error, size_t error_cap) {
  if (hit_count) *hit_count = 0u;
  if (error && error_cap) error[0] = '\0';
  if (!session || !buf || len == 0u || !hits || hit_cap == 0u || !hit_count) return -1;
#ifdef EDR_HAVE_YARA
  ForensicYaraResult result;
  char scan_error[256];
  scan_error[0] = '\0';
  int ok = fy_scan_rules(session->rules, cmd_id, NULL, buf, len, &result,
                         scan_error, sizeof(scan_error));
  if (!ok) {
    if (error && error_cap) snprintf(error, error_cap, "%s", scan_error);
    return -1;
  }
  size_t count = (size_t)result.count < hit_cap ? (size_t)result.count : hit_cap;
  for (size_t i = 0; i < count; i++) snprintf(hits[i], 128u, "%s", result.rules[i]);
  *hit_count = count;
  return 0;
#else
  (void)cmd_id;
  if (error && error_cap) snprintf(error, error_cap, "%s", "libyara unavailable in this build");
  return 1;
#endif
}

void edr_response_yara_session_close(EdrForensicYaraSession *session) {
  if (!session) return;
#ifdef EDR_HAVE_YARA
  if (session->rules) yr_rules_destroy(session->rules);
#endif
  free(session);
}

int edr_response_yara_scan_memory(const char *cmd_id, const uint8_t *buf, size_t len,
                                  char (*hits)[128], size_t hit_cap, size_t *hit_count,
                                  char *error, size_t error_cap) {
  EdrForensicYaraSession *session = edr_response_yara_session_open(error, error_cap);
  if (!session) return 1;
  int rc = edr_response_yara_session_scan(session, cmd_id, buf, len, hits, hit_cap,
                                          hit_count, error, error_cap);
  edr_response_yara_session_close(session);
  return rc;
}

/* ── Forensic Actions ── */

/* Windows 产品包默认启用外移取证；manifest 由 Agent 从 REST base 自动推导，
 * collector/velo 缺失时仍会回退 builtin/in-process。显式 EDR_FORENSIC_COLLECTOR=0 可关闭。 */
static int forensic_external_enabled(void) {
  const char *e = getenv("EDR_FORENSIC_COLLECTOR");
  if (e && e[0]) {
    return e[0] == '1' || e[0] == 't' || e[0] == 'T' || e[0] == 'y' || e[0] == 'Y';
  }
#ifdef _WIN32
  return 1;
#else
  return 0;
#endif
}

static int yara_external_enabled(void) {
  const char *mode = getenv("EDR_YARA_EXECUTION");
  if (mode && mode[0]) {
    if (strcmp(mode, "external") == 0 || strcmp(mode, "collector") == 0) return 1;
    if (strcmp(mode, "local") == 0 || strcmp(mode, "libyara") == 0) return 0;
  }
#ifdef EDR_HAVE_YARA
  return 0;
#else
  return forensic_external_enabled();
#endif
}
static int forensic_external_required(void) {
  const char *e = getenv("EDR_FORENSIC_COLLECTOR_STRICT");
  return e && e[0] == '1';
}
static const char *forensic_output_dir(void) {
  const char *o = getenv("EDR_FORENSIC_OUT");
  if (o && o[0]) return o;
  const EdrConfig *cfg = edr_command_get_config();
  if (cfg && cfg->shellcode_detector.forensic_dir[0]) {
    return cfg->shellcode_detector.forensic_dir;
  }
#ifdef _WIN32
  return ".\\edr_forensic";
#else
  return "/tmp/edr_forensic";
#endif
}

static int forensic_cancel_check(void *user) {
  return edr_command_cancel_requested((const char *)user);
}

/* P1/P2 共享:跑外部 collector 生成产物,成功后由 agent 经 transport v2 上传(通信只走 agent)。
 * 统一契约:把命令 payload 写成 .req 文件交给 collector;collector 读 --request、落 --out-file;agent 上传 out-file。
 * 返回 0=成功(do_upload 时 minio_key 已填);>0=collector 非0退出;<0=启动/超时/崩溃;-100=本地准备失败。 */
static int forensic_external_run(const char *cmd_id, const char *scope, const uint8_t *payload,
                                 size_t payload_len, const char *artifact_ext, int do_upload,
                                 char *minio_key, size_t key_cap, char *detail, size_t detail_cap) {
  const char *outdir = forensic_output_dir();
  if (response_mkdir_p(outdir) != 0) {
    if (detail) snprintf(detail, detail_cap, "mkdir output dir failed");
    return -100;
  }
  char job[96];
  response_sanitize_job_name(cmd_id ? cmd_id : "job", job, sizeof(job));
  long long ts = (long long)time(NULL);
#ifdef _WIN32
  const char sep = '\\';
#else
  const char sep = '/';
#endif
  char reqpath[900];
  char artifact[900];
  snprintf(reqpath, sizeof(reqpath), "%s%c%s_%s_%lld.req", outdir, sep, scope, job, ts);
  snprintf(artifact, sizeof(artifact), "%s%c%s_%s_%lld.%s", outdir, sep, scope, job, ts,
           artifact_ext ? artifact_ext : "bin");

  FILE *rf = fopen(reqpath, "wb");
  if (!rf) {
    if (detail) snprintf(detail, detail_cap, "write request file failed");
    return -100;
  }
  if (payload && payload_len) {
    fwrite(payload, 1, payload_len, rf);
  }
  fclose(rf);

  /* 注意:路径不加引号,collector 参数走空格分词(POSIX)/cmdline(Windows);取证目录约定无空格。 */
  char extra[2048];
  snprintf(extra, sizeof(extra), "--request=%s --out-file=%s", reqpath, artifact);

  EdrCollectorRunSpec spec = {0};
  spec.scope = scope;
  spec.output_dir = outdir;
  spec.extra_args = extra;
  spec.timeout_s = 300u;
  spec.needs_velociraptor = 1; /* 第一级走 velo 适配器,运行前确保 velo 就绪到其槽位 */
  spec.cancel_requested = forensic_cancel_check;
  spec.cancel_user = (void *)cmd_id;

  /* 第一级:Go 适配器(默认路径 forensic_collector[.exe])→ 调官方 Velociraptor。 */
  int rc = edr_deep_collector_run_blocking(&spec, detail, detail_cap);
  const char *tier = "velo";

  /* 第二级兜底:velo 不可用(rc==5,collector exitNoVelo)或启动/超时/崩溃(rc<0),
   * 且非 STRICT 时,改调 C baseline(forensic_collector_builtin)。仍失败则由调用方回退 in-process。 */
  if ((rc == 5 || (rc < 0 && rc != EDR_DC_ERR_CANCELLED)) && !forensic_external_required()) {
    const char *bbin = getenv("EDR_FORENSIC_COLLECTOR_BUILTIN_BIN");
    if (!bbin || !bbin[0]) {
#ifdef _WIN32
      bbin = "C:\\Program Files\\FDSecurity\\collector\\forensic_collector_builtin.exe";
#else
      bbin = "forensic_collector_builtin";
#endif
    }
    spec.collector_bin = bbin;
    spec.needs_velociraptor = 0; /* builtin 兜底不依赖 velo,勿在其前拉取 */
    char bdetail[512];
    bdetail[0] = '\0';
    int rc2 = edr_deep_collector_run_blocking(&spec, bdetail, sizeof(bdetail));
    /* 采纳 builtin 结果(它就是兜底):成功直接用;失败也覆盖 rc,让调用方据此回退 in-process。 */
    rc = rc2;
    tier = "builtin";
    if (detail && detail_cap) snprintf(detail, detail_cap, "%s", bdetail);
  }

  (void)remove(reqpath);

  if (rc == 0 && do_upload) {
    if (minio_key && key_cap) minio_key[0] = '\0';
    (void)edr_transport_v2_upload_file(cmd_id, artifact, NULL, minio_key, key_cap);
  }

  /* 在 detail 末尾标注实际采集层级,便于审计/前端展示(velo|builtin)。 */
  if (detail && detail_cap) {
    size_t l = strlen(detail);
    if (l + 12 < detail_cap) {
      snprintf(detail + l, detail_cap - l, " [tier=%s]", tier);
    }
  }
  return rc;
}

/* 非静态包装:供 response_actions.c 的 deep_forensic 等复用同一外移路径(声明见 response.h)。 */
int edr_response_forensic_run_external(const char *cmd_id, const char *scope, const uint8_t *payload,
                                       size_t payload_len, const char *artifact_ext, int do_upload,
                                       char *minio_key, size_t key_cap, char *detail,
                                       size_t detail_cap) {
  return forensic_external_run(cmd_id, scope, payload, payload_len, artifact_ext, do_upload,
                               minio_key, key_cap, detail, detail_cap);
}

int edr_response_forensic_external_enabled(void) { return forensic_external_enabled(); }
int edr_response_yara_external_enabled(void) { return yara_external_enabled(); }

/* ════════════════════════ 取证异步生命周期(单槽 + 锁) ════════════════════════
 * 受理在命令线程、收割在主循环线程、取消在命令线程、关闭在主循环线程 → 跨线程共享 g_fx,加锁。
 * 单槽:同一时刻只允许一个 velo 采集(底层 deep_collector 本就是单例)。
 * 上报用 edr_command_emit_always(cmd_id+sm 自含,不依赖全局 command_type) → 可在 poll 线程安全调用。 */
#ifdef _WIN32
static CRITICAL_SECTION g_fx_lock;
static int g_fx_lock_init = 0;
static void fx_lock_ensure(void) { if (!g_fx_lock_init) { InitializeCriticalSection(&g_fx_lock); g_fx_lock_init = 1; } }
static void fx_lock(void) { fx_lock_ensure(); EnterCriticalSection(&g_fx_lock); }
static void fx_unlock(void) { LeaveCriticalSection(&g_fx_lock); }
#else
#include <pthread.h>
static pthread_mutex_t g_fx_lock = PTHREAD_MUTEX_INITIALIZER;
static void fx_lock(void) { pthread_mutex_lock(&g_fx_lock); }
static void fx_unlock(void) { pthread_mutex_unlock(&g_fx_lock); }
#endif

typedef struct {
  int active;
  int phase;            /* 0=velo, 1=builtin */
  int do_upload;
  int strict;
  int cancel_requested;
  char cmd_id[96];
  char command_type[64];
  EdrSoarCommandMeta sm; /* 值拷贝,供 poll 线程上报 */
  char scope[64];
  char reqpath[900];
  char artifact[900];
  char outdir[512];
  char extra[2048];
} ForensicAsyncJob;
static ForensicAsyncJob g_fx; /* 受 g_fx_lock 保护 */

#ifdef _WIN32
static DWORD WINAPI fx_monitor_thread(LPVOID unused) {
  (void)unused;
  while (edr_response_forensic_async_active()) {
    edr_response_forensic_async_poll();
    Sleep(100u);
  }
  return 0;
}
#else
static void *fx_monitor_thread(void *unused) {
  (void)unused;
  while (edr_response_forensic_async_active()) {
    edr_response_forensic_async_poll();
    usleep(100000u);
  }
  return NULL;
}
#endif

static int fx_start_monitor(void) {
#ifdef _WIN32
  HANDLE thread = CreateThread(NULL, 0u, fx_monitor_thread, NULL, 0u, NULL);
  if (!thread) return -1;
  CloseHandle(thread);
#else
  pthread_t thread;
  if (pthread_create(&thread, NULL, fx_monitor_thread, NULL) != 0) return -1;
  (void)pthread_detach(thread);
#endif
  return 0;
}

/* 构造 .req + extra_args,spawn velo(phase=0)。调用方持锁。返回 EDR_DC_OK/busy/err。 */
static int fx_spawn_locked(const char *scope, const uint8_t *payload, size_t payload_len,
                           const char *artifact_ext, char *detail, size_t detail_cap) {
  const char *outdir = forensic_output_dir();
  if (response_mkdir_p(outdir) != 0) {
    if (detail) snprintf(detail, detail_cap, "mkdir output dir failed");
    return -100;
  }
  char job[96];
  response_sanitize_job_name(g_fx.cmd_id[0] ? g_fx.cmd_id : "job", job, sizeof(job));
  long long ts = (long long)time(NULL);
#ifdef _WIN32
  const char sep = '\\';
#else
  const char sep = '/';
#endif
  snprintf(g_fx.outdir, sizeof(g_fx.outdir), "%s", outdir);
  snprintf(g_fx.reqpath, sizeof(g_fx.reqpath), "%s%c%s_%s_%lld.req", outdir, sep, scope, job, ts);
  snprintf(g_fx.artifact, sizeof(g_fx.artifact), "%s%c%s_%s_%lld.%s", outdir, sep, scope, job, ts,
           artifact_ext ? artifact_ext : "bin");
  FILE *rf = fopen(g_fx.reqpath, "wb");
  if (!rf) { if (detail) snprintf(detail, detail_cap, "write request file failed"); return -100; }
  if (payload && payload_len) fwrite(payload, 1, payload_len, rf);
  fclose(rf);
  snprintf(g_fx.extra, sizeof(g_fx.extra), "--request=%s --out-file=%s", g_fx.reqpath, g_fx.artifact);

  EdrCollectorRunSpec spec = {0};
  spec.scope = scope;
  spec.output_dir = g_fx.outdir;
  spec.extra_args = g_fx.extra;
  spec.timeout_s = 300u;
  spec.needs_velociraptor = (g_fx.phase == 0) ? 1 : 0; /* 仅 velo 层运行前确保 velo 就绪 */
  if (g_fx.phase == 1) {
    const char *bbin = getenv("EDR_FORENSIC_COLLECTOR_BUILTIN_BIN");
    if (!bbin || !bbin[0]) {
#ifdef _WIN32
      bbin = "C:\\Program Files\\FDSecurity\\collector\\forensic_collector_builtin.exe";
#else
      bbin = "forensic_collector_builtin";
#endif
    }
    spec.collector_bin = bbin;
  }
  return edr_deep_collector_spawn(&spec, detail, detail_cap);
}

int edr_response_forensic_async_accept(const char *cmd_id, const char *command_type,
                                       const EdrSoarCommandMeta *sm, const char *scope,
                                       const uint8_t *payload, size_t payload_len,
                                       const char *artifact_ext, int do_upload,
                                       char *detail, size_t detail_cap) {
  fx_lock();
  if (g_fx.active) { fx_unlock(); if (detail) snprintf(detail, detail_cap, "collector busy"); return 1; }
  (void)memset(&g_fx, 0, sizeof(g_fx));
  snprintf(g_fx.cmd_id, sizeof(g_fx.cmd_id), "%s", cmd_id ? cmd_id : "");
  snprintf(g_fx.command_type, sizeof(g_fx.command_type), "%s", command_type ? command_type : "collect_forensic");
  if (sm) g_fx.sm = *sm;
  snprintf(g_fx.scope, sizeof(g_fx.scope), "%s", scope ? scope : "standard");
  g_fx.do_upload = do_upload;
  g_fx.strict = forensic_external_required();
  g_fx.phase = 0; /* velo */
  snprintf(g_fx.artifact, sizeof(g_fx.artifact), "%s", ""); /* 由 fx_spawn_locked 填 */
  char art_ext[16];
  snprintf(art_ext, sizeof(art_ext), "%s", artifact_ext ? artifact_ext : "bin");
  /* spawn(含首次 manifest 下载,持锁;首跑较慢,后续即时) */
  int rc = fx_spawn_locked(g_fx.scope, payload, payload_len, art_ext, detail, detail_cap);
  if (rc != EDR_DC_OK) { (void)memset(&g_fx, 0, sizeof(g_fx)); fx_unlock(); return rc < 0 ? rc : -3; }
  /* 复用 artifact_ext 供 phase2 同名约定:重存 ext 到 scope 后缀不需要;artifact 路径已定 */
  g_fx.active = 1;
  fx_unlock();
  if (fx_start_monitor() != 0) {
    fx_lock();
    edr_deep_collector_kill();
    (void)memset(&g_fx, 0, sizeof(g_fx));
    fx_unlock();
    if (detail) snprintf(detail, detail_cap, "collector monitor thread start failed");
    return -4;
  }
  return 0;
}

/* 终态上报(poll 线程):成功/失败/已取消。do_upload 时先上传。 */
static void fx_report_terminal(const char *cmd_id, const EdrSoarCommandMeta *sm, int do_upload,
                               const char *command_type, const char *artifact, int rc, const char *tier,
                               int cancelled) {
  char minio_key[1024];
  minio_key[0] = '\0';
  if (cancelled) {
    char result[1200];
    if (command_type && strcmp(command_type, "yara_scan") == 0) {
      yara_artifact_result_json(result, sizeof(result), "cancelled", "external_collector", "", "", "",
                                "not_requested", "YARA scan cancelled by operator", 0);
    } else {
      forensic_result_json(result, sizeof(result), "cancelled", "external_collector", "", "", "",
                           0, "not_requested", "forensic cancelled by operator");
    }
    edr_cmd_inc_exec_fail();
    edr_command_emit_always_typed_status(cmd_id, command_type, sm, EdrCmdExecFailed, 130,
                                         result, "cancelled");
    return;
  }
  if (rc == 0 || rc == 2) {
    int upload_rc = 0;
    char sha[65];
    char result[2600];
    const char *source = (tier && strcmp(tier, "velo") == 0) ? "velociraptor" : "builtin";
    sha[0] = '\0';
    (void)response_file_sha256(artifact, sha);
    if (do_upload) upload_rc = edr_transport_v2_upload_file(cmd_id, artifact, sha, minio_key, sizeof(minio_key));
    if (do_upload && (upload_rc != 0 || !minio_key[0])) {
      if (edr_command_queue_forensic_upload(cmd_id, command_type, sm, artifact, sha,
                                            source, rc == 2) == 0) {
        edr_command_audit_both(cmd_id, "forensic artifact upload deferred to durable retry queue");
        return;
      }
      if (command_type && strcmp(command_type, "yara_scan") == 0) {
        yara_artifact_result_json(result, sizeof(result), "failed", source, artifact, sha, minio_key,
                                  "failed", "artifact collected but upload failed; no durable remote result",
                                  rc == 2);
      } else {
        forensic_result_json(result, sizeof(result), "failed", source, artifact, sha, minio_key, 0,
                             "failed", "artifact collected but upload failed; no durable remote result");
      }
      edr_cmd_inc_exec_fail();
      edr_command_emit_always_typed(cmd_id, command_type, sm, EdrCmdExecFailed, 9, result);
      return;
    }
    if (command_type && strcmp(command_type, "yara_scan") == 0) {
      yara_artifact_result_json(result, sizeof(result), rc == 2 ? "partial_success" : "success",
                                source, artifact, sha, minio_key,
                                do_upload ? "ok" : "not_requested", "", rc == 2);
    } else {
      forensic_result_json(result, sizeof(result), rc == 2 ? "partial_success" : "success",
                           source, artifact, sha, minio_key, 0,
                           do_upload ? "ok" : "not_requested", "");
    }
    edr_cmd_inc_handled();
    edr_cmd_inc_exec_ok();
    edr_command_emit_always_typed(cmd_id, command_type, sm, EdrCmdExecOk, 0, result);
  } else {
    edr_cmd_inc_exec_fail();
    char fail[1200], error[300];
    snprintf(error, sizeof(error), "forensic external failed(%s) rc=%d", tier ? tier : "unknown", rc);
    if (command_type && strcmp(command_type, "yara_scan") == 0) {
      yara_artifact_result_json(fail, sizeof(fail), "failed",
                                tier && strcmp(tier, "velo") == 0 ? "velociraptor" : "builtin",
                                artifact, "", "", "not_requested", error, 0);
    } else {
      forensic_result_json(fail, sizeof(fail), "failed",
                           tier && strcmp(tier, "velo") == 0 ? "velociraptor" : "builtin",
                           artifact, "", "", 0, "not_requested", error);
    }
    edr_command_emit_always_typed(cmd_id, command_type, sm, EdrCmdExecFailed, 6, fail);
  }
}

void edr_response_forensic_complete_queued_upload(
    const char *command_id, const char *command_type, const EdrSoarCommandMeta *soar_meta,
    const char *artifact_path, const char *sha256, const char *object_key,
    const char *source, int partial, int upload_ok, const char *upload_error) {
  char result[2600];
  const char *type = command_type && command_type[0] ? command_type : "collect_forensic";
  const char *actual_source = source && source[0] ? source : "builtin";
  if (upload_ok && object_key && object_key[0]) {
    if (strcmp(type, "yara_scan") == 0) {
      yara_artifact_result_json(result, sizeof(result), partial ? "partial_success" : "success",
                                actual_source, artifact_path, sha256, object_key, "ok", "", partial);
    } else {
      forensic_result_json(result, sizeof(result), partial ? "partial_success" : "success",
                           actual_source, artifact_path, sha256, object_key, 0, "ok", "");
    }
    edr_cmd_inc_handled();
    edr_cmd_inc_exec_ok();
    edr_command_emit_always_typed(command_id, type, soar_meta, EdrCmdExecOk, 0, result);
    return;
  }
  const char *error = upload_error && upload_error[0]
                          ? upload_error
                          : "artifact upload retry failed without a durable object key";
  if (strcmp(type, "yara_scan") == 0) {
    yara_artifact_result_json(result, sizeof(result), "failed", actual_source, artifact_path,
                              sha256, "", "failed", error, partial);
  } else {
    forensic_result_json(result, sizeof(result), "failed", actual_source, artifact_path,
                         sha256, "", 0, "failed", error);
  }
  edr_cmd_inc_exec_fail();
  edr_command_emit_always_typed(command_id, type, soar_meta, EdrCmdExecFailed, 9, result);
}

void edr_response_forensic_async_poll(void) {
  fx_lock();
  if (!g_fx.active) { fx_unlock(); return; }

  /* 取消优先:kill 由 poll 线程统一执行,避免与 spawn 跨线程争用句柄。 */
  if (g_fx.cancel_requested) {
    edr_deep_collector_kill();
    char cmd_id[96]; char command_type[64]; EdrSoarCommandMeta sm; char req[900];
    snprintf(cmd_id, sizeof(cmd_id), "%s", g_fx.cmd_id); sm = g_fx.sm;
    snprintf(command_type, sizeof(command_type), "%s", g_fx.command_type);
    snprintf(req, sizeof(req), "%s", g_fx.reqpath);
    (void)memset(&g_fx, 0, sizeof(g_fx));
    fx_unlock();
    (void)remove(req);
    fx_report_terminal(cmd_id, &sm, 0, command_type, "", 0, "cancelled", 1);
    return;
  }

  int exit_code = 0;
  char pd[256]; pd[0] = '\0';
  int pr = edr_deep_collector_poll(&exit_code, pd, sizeof(pd));
  if (pr > 0) { fx_unlock(); return; } /* 仍在跑 */

  /* 已结束(pr==0,exit_code 有效)或 poll 内部错误(pr<0) */
  int rc = (pr < 0) ? pr : exit_code;
  const char *tier = (g_fx.phase == 1) ? "builtin" : "velo";

  /* velo 段:无 velo(5)/启动崩溃(<0) 且非 strict → 切 builtin 第二段(单槽串行)。 */
  if (g_fx.phase == 0 && (rc == 5 || rc < 0) && !g_fx.strict) {
    g_fx.phase = 1;
    char bd[256]; bd[0] = '\0';
    /* 复用同一 req/artifact 路径(artifact_ext 已含在 artifact 名里);仅换 collector_bin。 */
    EdrCollectorRunSpec spec = {0};
    spec.scope = g_fx.scope;
    spec.output_dir = g_fx.outdir;
    spec.extra_args = g_fx.extra;
    spec.timeout_s = 300u;
    const char *bbin = getenv("EDR_FORENSIC_COLLECTOR_BUILTIN_BIN");
    if (!bbin || !bbin[0]) {
#ifdef _WIN32
      bbin = "C:\\Program Files\\FDSecurity\\collector\\forensic_collector_builtin.exe";
#else
      bbin = "forensic_collector_builtin";
#endif
    }
    spec.collector_bin = bbin;
    int sr = edr_deep_collector_spawn(&spec, bd, sizeof(bd));
    if (sr == EDR_DC_OK) { fx_unlock(); return; } /* builtin 已起,下轮 poll 收割 */
    rc = sr; tier = "builtin"; /* builtin 也起不来 → 失败终态 */
  }

  /* 终态:快照后出锁上报+上传 */
  char cmd_id[96]; char command_type[64]; EdrSoarCommandMeta sm; char artifact[900]; char req[900];
  int do_upload = g_fx.do_upload;
  snprintf(cmd_id, sizeof(cmd_id), "%s", g_fx.cmd_id); sm = g_fx.sm;
  snprintf(command_type, sizeof(command_type), "%s", g_fx.command_type);
  snprintf(artifact, sizeof(artifact), "%s", g_fx.artifact);
  snprintf(req, sizeof(req), "%s", g_fx.reqpath);
  const char *tier_final = tier;
  (void)memset(&g_fx, 0, sizeof(g_fx));
  fx_unlock();
  (void)remove(req);
  fx_report_terminal(cmd_id, &sm, do_upload, command_type, artifact, rc, tier_final, 0);
}

int edr_response_forensic_async_cancel(const char *target_cmd_id) {
  int hit = 0;
  fx_lock();
  if (g_fx.active) {
    if (!target_cmd_id || !target_cmd_id[0] || strcmp(target_cmd_id, g_fx.cmd_id) == 0) {
      g_fx.cancel_requested = 1; /* 实际 kill 由 poll 统一执行 */
      hit = 1;
    }
  }
  fx_unlock();
  return hit;
}

void edr_response_forensic_async_abort_shutdown(void) {
  fx_lock();
  if (!g_fx.active) { fx_unlock(); return; }
  edr_deep_collector_kill();
  char cmd_id[96]; char command_type[64]; EdrSoarCommandMeta sm; char req[900];
  snprintf(cmd_id, sizeof(cmd_id), "%s", g_fx.cmd_id); sm = g_fx.sm;
  snprintf(command_type, sizeof(command_type), "%s", g_fx.command_type);
  snprintf(req, sizeof(req), "%s", g_fx.reqpath);
  (void)memset(&g_fx, 0, sizeof(g_fx));
  fx_unlock();
  (void)remove(req);
  fx_report_terminal(cmd_id, &sm, 0, command_type, "", 0, "shutdown", 1);
}

int edr_response_forensic_async_active(void) {
  int a;
  fx_lock();
  a = g_fx.active;
  fx_unlock();
  return a;
}


void edr_response_collect_forensic(const char *cmd_id, const uint8_t *pl, size_t len,
                                    const EdrSoarCommandMeta *sm) {
  if (!edr_command_dangerous_enabled()) {
    edr_cmd_inc_rejected();
    edr_command_audit_both(cmd_id, "reject forensic: 设置 EDR_CMD_ENABLED=1 或 TOML [command] allow_dangerous=true");
    edr_command_emit_always(cmd_id, sm, EdrCmdExecRejected, 1, "policy disabled");
    return;
  }

  /* 外移:由独立 collector 异步生成 triage bundle,完成由主循环 poll 上传+上报。 */
  if (forensic_external_enabled()) {
    char dc_detail[512];
    dc_detail[0] = '\0';
    int ar = edr_response_forensic_async_accept(cmd_id, "collect_forensic", sm, "collect_forensic",
                                                pl, len, "tar.gz", 1, dc_detail, sizeof(dc_detail));
    if (ar == 0) {
      edr_command_audit_both(cmd_id, "collect_forensic: accepted(async velo); poll 上报终态");
      return;
    }
    if (ar == 1) {
      edr_cmd_inc_exec_fail();
      edr_command_emit_always(cmd_id, sm, EdrCmdExecFailed, 7, "forensic busy: another collection running");
      return;
    }
    if (forensic_external_required()) {
      edr_cmd_inc_exec_fail();
      char fail[600];
      snprintf(fail, sizeof(fail), "collect_forensic external failed rc=%d: %.460s", ar, dc_detail);
      edr_command_emit_always(cmd_id, sm, EdrCmdExecFailed, 6, fail);
      return;
    }
    edr_command_audit_both(cmd_id, "collect_forensic: external unavailable, fallback in-process");
  }

  char base[512];
  const char *o = getenv("EDR_FORENSIC_OUT");
  if (o && o[0]) {
    snprintf(base, sizeof(base), "%s", o);
  } else {
#ifdef _WIN32
    const char *tmp = getenv("TEMP");
    if (!tmp || !tmp[0]) {
      tmp = getenv("TMP");
    }
    if (!tmp || !tmp[0]) {
      tmp = ".";
    }
    snprintf(base, sizeof(base), "%s\\edr_forensic", tmp);
#else
    snprintf(base, sizeof(base), "%s", "/tmp/edr_forensic");
#endif
  }
  char job[96];
  response_sanitize_job_name(cmd_id, job, sizeof(job));
  char dir[700];
#ifdef _WIN32
  snprintf(dir, sizeof(dir), "%s\\%s", base, job);
#else
  snprintf(dir, sizeof(dir), "%s/%s", base, job);
#endif
  if (response_mkdir_p(dir) != 0) {
    edr_cmd_inc_exec_fail();
    edr_command_audit_both(cmd_id, "forensic: 创建输出目录失败");
    edr_command_emit_always(cmd_id, sm, EdrCmdExecFailed, 2, "mkdir failed");
    return;
  }
  char manifest[800];
#ifdef _WIN32
  snprintf(manifest, sizeof(manifest), "%s\\manifest.txt", dir);
#else
  snprintf(manifest, sizeof(manifest), "%s/manifest.txt", dir);
#endif
  FILE *f = fopen(manifest, "w");
  if (!f) {
    edr_cmd_inc_exec_fail();
    edr_command_audit_both(cmd_id, "forensic: 写 manifest 失败");
    edr_command_emit_always(cmd_id, sm, EdrCmdExecFailed, 2, "manifest write failed");
    return;
  }
  fprintf(f, "command_id=%s\npayload_len=%zu\n", cmd_id ? cmd_id : "", len);
  {
    char shahex[65];
    if (pl && len > 0u) {
      (void)edr_sha256_hex(pl, len, shahex);
      fprintf(f, "payload_sha256=%s\n", shahex);
    } else {
      fprintf(f, "payload_sha256=\n");
    }
  }
#ifdef _WIN32
  fprintf(f, "platform=windows\n");
  {
    char hn[256];
    DWORD hnl = sizeof(hn);
    if (GetComputerNameA(hn, &hnl)) {
      fprintf(f, "hostname=%s\n", hn);
    }
  }
#else
  fprintf(f, "platform=posix\n");
  {
    char hn[256];
    if (gethostname(hn, sizeof(hn)) == 0) {
      hn[sizeof(hn) - 1] = '\0';
      fprintf(f, "hostname=%s\n", hn);
    }
  }
#endif
  {
    const EdrConfig *cfg = edr_command_get_config();
    if (cfg) {
      fprintf(f, "endpoint_id=%s\ntenant_id=%s\n", cfg->agent.endpoint_id[0] ? cfg->agent.endpoint_id : "",
              cfg->agent.tenant_id[0] ? cfg->agent.tenant_id : "");
    }
  }
  fclose(f);
  response_forensic_copy_lines(dir, pl, len);
#ifdef _WIN32
  char bundle[1100];
  snprintf(bundle, sizeof(bundle), "%s\\bundle.tgz", dir);
#else
  char bundle[1000];
  snprintf(bundle, sizeof(bundle), "%s/bundle.tgz", dir);
#endif
  if (response_make_tar_bundle(dir, bundle) == 0) {
    edr_cmd_inc_exec_ok();
    edr_command_audit_both(cmd_id, "forensic: manifest + bundle.tgz");
    char minio_key[512];
    minio_key[0] = '\0';
    edr_transport_v2_upload_file(cmd_id, bundle, NULL, minio_key, sizeof(minio_key));
    char result[1024];
    if (minio_key[0]) {
      snprintf(result, sizeof(result), "forensic bundle ok minio_key=%s", minio_key);
    } else {
      snprintf(result, sizeof(result), "forensic bundle ok");
    }
    edr_command_emit_always(cmd_id, sm, EdrCmdExecOk, 0, result);
  } else {
    edr_cmd_inc_exec_fail();
    edr_command_audit_both(cmd_id, "forensic: tar bundle 失败");
    edr_command_emit_always(cmd_id, sm, EdrCmdExecFailed, 2, "tar bundle failed");
  }
}

void edr_response_pmfe_scan(const char *cmd_id, const uint8_t *pl, size_t len, const EdrSoarCommandMeta *sm) {
  if (!edr_command_dangerous_enabled()) {
    edr_cmd_inc_rejected();
    edr_command_audit_both(cmd_id, "reject pmfe_scan: enable EDR_CMD_ENABLED=1 or TOML [command] allow_dangerous=true");
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecRejected, 1, "policy disabled");
    return;
  }
  long pid = -1;
  if (edr_command_parse_pid_json(pl, len, &pid) != 0) {
    edr_cmd_inc_exec_fail();
    edr_command_audit_both(cmd_id, "pmfe_scan: payload missing valid pid (JSON requires \"pid\")");
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, 2, "invalid pid json");
    return;
  }
  EdrPmfeCommandContext context;
  memset(&context, 0, sizeof(context));
  char region_base[64];
  int region_size = 0;
  int extract_region = 0;
  int run_yara = 1;
  region_base[0] = '\0';
  (void)edr_parse_json_string(pl, len, "region_base", region_base, sizeof(region_base));
  (void)edr_parse_json_int(pl, len, "region_size", &region_size);
  (void)edr_parse_json_bool(pl, len, "extract_region", &extract_region);
  (void)edr_parse_json_bool(pl, len, "run_yara", &run_yara);
  if (region_base[0]) {
    char *end = NULL;
    unsigned long long base = strtoull(region_base, &end, 0);
    if (!end || end == region_base || *end != '\0') {
      edr_cmd_inc_exec_fail();
      edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, 2, "invalid region_base");
      return;
    }
    context.requested_region_base = (uint64_t)base;
    context.extract_region = 1u;
  } else if (extract_region) {
    edr_cmd_inc_exec_fail();
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, 2,
                          "extract_region requires region_base");
    return;
  }
  if (region_size > 0) context.requested_region_size = (uint64_t)region_size;
  context.yara_mode = run_yara ? 1u : 2u;
  if (sm) {
    snprintf(context.soar_correlation_id, sizeof(context.soar_correlation_id), "%s", sm->soar_correlation_id);
    snprintf(context.playbook_run_id, sizeof(context.playbook_run_id), "%s", sm->playbook_run_id);
    snprintf(context.playbook_step_id, sizeof(context.playbook_step_id), "%s", sm->playbook_step_id);
  }
  if (edr_pmfe_submit_server_scan_ex(cmd_id, (uint32_t)pid, &context) != 0) {
    edr_cmd_inc_exec_fail();
    edr_command_audit_both(cmd_id, "pmfe_scan: queue failed (PMFE not running or queue full)");
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, 3, "pmfe queue full or not running");
    return;
  }
  edr_cmd_inc_handled();
  edr_command_audit_both(cmd_id, "pmfe_scan: accepted (terminal result pending)");
}

void edr_response_rtr_shell(const char *cmd_id, const uint8_t *pl, size_t len, const EdrSoarCommandMeta *sm) {
  if (!edr_command_dangerous_enabled()) {
    edr_cmd_inc_rejected();
    edr_command_audit_both(cmd_id, "reject rtr_shell: 设置 EDR_CMD_ENABLED=1 或 TOML [command] allow_dangerous=true");
    edr_command_emit_always(cmd_id, sm, EdrCmdExecRejected, 1, "policy disabled");
    return;
  }
  char command[2048];
  int timeout_sec = 30;
  (void)edr_parse_json_string(pl, len, "command", command, sizeof(command));
  (void)edr_parse_json_int(pl, len, "timeout_sec", &timeout_sec);
  if (timeout_sec <= 0 || timeout_sec > 300) timeout_sec = 30;
  if (!command[0]) {
    edr_cmd_inc_exec_fail();
    edr_command_audit_both(cmd_id, "rtr_shell: 缺少 command");
    edr_command_emit_always(cmd_id, sm, EdrCmdExecFailed, 2, "missing command");
    return;
  }
  if (!edr_shell_is_allowed(command)) {
    edr_cmd_inc_rejected();
    edr_command_audit_both(cmd_id, "rtr_shell: 命令不在白名单或命中黑名单");
    edr_command_emit_always(cmd_id, sm, EdrCmdExecRejected, 3, "command blocked by policy");
    return;
  }
  char out[8192];
  int exit_code = 0;
  int r = edr_shell_exec(command, timeout_sec, out, sizeof(out), &exit_code);
  if (r != 0) {
    edr_cmd_inc_exec_fail();
    edr_command_audit_both(cmd_id, "rtr_shell: 执行失败");
    edr_command_emit_always(cmd_id, sm, EdrCmdExecFailed, exit_code, out[0] ? out : "exec failed");
    return;
  }
  edr_cmd_inc_handled();
  edr_cmd_inc_exec_ok();
  edr_command_audit_both(cmd_id, "rtr_shell: ok");
#ifdef _WIN32
  {
    int wlen = MultiByteToWideChar(CP_ACP, 0, out, -1, NULL, 0);
    if (wlen > 0) {
      wchar_t *wbuf = (wchar_t *)malloc((size_t)wlen * sizeof(wchar_t));
      if (wbuf) {
        MultiByteToWideChar(CP_ACP, 0, out, -1, wbuf, wlen);
        int u8len = WideCharToMultiByte(CP_UTF8, 0, wbuf, -1, NULL, 0, NULL, NULL);
        if (u8len > 0 && (size_t)u8len < sizeof(out)) {
          WideCharToMultiByte(CP_UTF8, 0, wbuf, -1, out, u8len, NULL, NULL);
        }
        free(wbuf);
      }
    }
  }
#endif
  edr_command_emit_always(cmd_id, sm, EdrCmdExecOk, exit_code, out);
}

void edr_response_targeted_forensic(const char *cmd_id, const uint8_t *pl, size_t len,
                                     const EdrSoarCommandMeta *sm) {
  if (!edr_command_dangerous_enabled()) {
    edr_cmd_inc_rejected();
    edr_command_audit_both(cmd_id, "reject targeted_forensic: policy");
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecRejected, 1, "policy disabled");
    return;
  }

  /* 外移:collector 按 request 中的 item 清单异步采集打包,完成由主循环 poll 上传+上报。 */
  if (forensic_external_enabled()) {
    char dc_detail[512];
    dc_detail[0] = '\0';
    int ar = edr_response_forensic_async_accept(cmd_id, "targeted_forensic", sm, "targeted_forensic",
                                                pl, len, "tar.gz", 1, dc_detail, sizeof(dc_detail));
    if (ar == 0) { edr_command_audit_both(cmd_id, "targeted_forensic: accepted(async)"); return; }
    if (ar == 1) {
      edr_cmd_inc_exec_fail();
      edr_command_emit_always(cmd_id, sm, EdrCmdExecFailed, 7, "forensic busy: another collection running");
      return;
    }
    if (forensic_external_required()) {
      edr_cmd_inc_exec_fail();
      char fail[600];
      snprintf(fail, sizeof(fail), "targeted_forensic external failed rc=%d: %.460s", ar, dc_detail);
      edr_command_emit_always(cmd_id, sm, EdrCmdExecFailed, 6, fail);
      return;
    }
    edr_command_audit_both(cmd_id, "targeted_forensic: external unavailable, fallback in-process");
  }

  char out[4096];
  int count = 0;
  int copy_failures = 0;
  out[0] = '\0';
  char *json = (char *)malloc(len + 1u);
  if (!json) {
    edr_cmd_inc_exec_fail();
    edr_command_emit_always(cmd_id, sm, EdrCmdExecFailed, 4,
                            "targeted_forensic payload allocation failed");
    return;
  }
  memcpy(json, pl, len);
  json[len] = '\0';
  const char *parse_end = NULL;
  cJSON *root = cJSON_ParseWithLengthOpts(json, len + 1u, &parse_end, 1);
  free(json);
  if (!cJSON_IsObject(root)) {
    cJSON_Delete(root);
    edr_cmd_inc_exec_fail();
    edr_command_emit_always(cmd_id, sm, EdrCmdExecFailed, 2,
                            "targeted_forensic payload is not a JSON object");
    return;
  }

  const cJSON *items = cJSON_GetObjectItemCaseSensitive(root, "items");
  const cJSON *item = NULL;
  cJSON_ArrayForEach(item, items) {
    if (count >= 20 || edr_command_cancel_requested(cmd_id)) {
      break;
    }
    const cJSON *type = cJSON_GetObjectItemCaseSensitive(item, "type");
    if (!cJSON_IsString(type) || !type->valuestring) {
      continue;
    }
    if (strcmp(type->valuestring, "file") == 0) {
      const cJSON *path = cJSON_GetObjectItemCaseSensitive(item, "path");
      if (!cJSON_IsString(path) || !path->valuestring || !path->valuestring[0]) {
        continue;
      }
      const char *fbname = strrchr(path->valuestring, '/');
      if (!fbname) fbname = strrchr(path->valuestring, '\\');
      if (!fbname) fbname = path->valuestring; else fbname++;
      char dest[800];
      snprintf(dest, sizeof(dest), "files/%s", fbname);
      if (response_forensic_copy_one_file(path->valuestring, dest) == 0) {
        count++;
      } else {
        copy_failures++;
      }
    }
    /* Registry/process/memory items require a dedicated platform backend.
     * The local fallback does not count unsupported targets as evidence. */
  }
  cJSON_Delete(root);
  if (edr_command_cancel_requested(cmd_id)) {
    edr_cmd_inc_exec_fail();
    edr_command_emit_always_typed_status(cmd_id, "targeted_forensic", sm,
                                         EdrCmdExecFailed, 130,
                                         "targeted_forensic cancelled at item checkpoint",
                                         "cancelled");
    return;
  }
  if (count == 0) {
    edr_cmd_inc_exec_fail();
    edr_command_audit_both(cmd_id, "targeted_forensic: no evidence collected");
    if (copy_failures > 0) {
      char fail[256];
      snprintf(fail, sizeof(fail), "targeted_forensic collected no evidence; file_copy_failures=%d", copy_failures);
      edr_command_emit_always(cmd_id, sm, EdrCmdExecFailed, 8, fail);
    } else {
      edr_command_emit_always(cmd_id, sm, EdrCmdExecFailed, 8, "targeted_forensic collected no evidence");
    }
    return;
  }
  snprintf(out, sizeof(out), "TARGETED_OK items=%d file_copy_failures=%d", count, copy_failures);
  edr_cmd_inc_handled(); edr_cmd_inc_exec_ok();
  edr_command_audit_both(cmd_id, "targeted_forensic: ok");
  edr_command_emit_always(cmd_id, sm, EdrCmdExecOk, 0, out);
}

#ifdef _WIN32
typedef struct MemoryDumpCancelContext {
  const char *command_id;
} MemoryDumpCancelContext;

static BOOL CALLBACK memory_dump_callback(PVOID param,
                                          const PMINIDUMP_CALLBACK_INPUT input,
                                          PMINIDUMP_CALLBACK_OUTPUT output) {
  MemoryDumpCancelContext *ctx = (MemoryDumpCancelContext *)param;
  if (!ctx || !input || !output) return TRUE;
  if (input->CallbackType == CancelCallback) {
    output->CheckCancel = TRUE;
    output->Cancel = edr_command_cancel_requested(ctx->command_id) ? TRUE : FALSE;
  }
  return TRUE;
}
#endif

void edr_response_memory_dump(const char *cmd_id, const uint8_t *pl, size_t len, const EdrSoarCommandMeta *sm) {
  if (!edr_command_dangerous_enabled()) {
    edr_cmd_inc_rejected();
    edr_command_audit_both(cmd_id, "reject memory_dump: policy");
    edr_command_emit_always(cmd_id, sm, EdrCmdExecRejected, 1, "policy disabled");
    return;
  }
  int pid = -1, full = 0;
  (void)edr_parse_json_int(pl, len, "pid", &pid);
  (void)edr_parse_json_int(pl, len, "full", &full);
  if (pid <= 0) {
    edr_cmd_inc_exec_fail();
    edr_command_emit_always(cmd_id, sm, EdrCmdExecFailed, 2, "invalid pid");
    return;
  }

  /* 重/危险取证外移:优先走独立 collector 进程;成功后 agent 经 transport v2 上传 .dmp(通信只走 agent)。
   * 失败时:STRICT 模式直接报错,否则回退 in-process(稳定优先)。 */
  if (forensic_external_enabled()) {
    char dc_detail[512];
    dc_detail[0] = '\0';
    int ar = edr_response_forensic_async_accept(cmd_id, "memory_dump", sm, "memory_dump",
                                                pl, len, "dmp", 1, dc_detail, sizeof(dc_detail));
    if (ar == 0) { edr_command_audit_both(cmd_id, "memory_dump: accepted(async)"); return; }
    if (ar == 1) {
      edr_cmd_inc_exec_fail();
      edr_command_emit_always(cmd_id, sm, EdrCmdExecFailed, 7, "forensic busy: another collection running");
      return;
    }
    if (forensic_external_required()) {
      edr_cmd_inc_exec_fail();
      char fail[600];
      snprintf(fail, sizeof(fail), "memory_dump external collector failed rc=%d: %.470s", ar, dc_detail);
      edr_command_emit_always(cmd_id, sm, EdrCmdExecFailed, 6, fail);
      return;
    }
    edr_command_audit_both(cmd_id, "memory_dump: external collector unavailable, fallback in-process");
    /* 继续走下方 in-process 兜底 */
  }

#ifdef _WIN32
  HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, (DWORD)pid);
  if (!h) {
    edr_cmd_inc_exec_fail();
    edr_command_emit_always(cmd_id, sm, EdrCmdExecFailed, 3, "OpenProcess failed");
    return;
  }
  char dmpPath[512];
  snprintf(dmpPath, sizeof(dmpPath), "memdump_%d_%lld.dmp", pid, (long long)time(NULL));
  HANDLE hFile = CreateFileA(dmpPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (hFile == INVALID_HANDLE_VALUE) {
    CloseHandle(h);
    edr_command_emit_always(cmd_id, sm, EdrCmdExecFailed, 4, "CreateFile failed");
    return;
  }
  MINIDUMP_TYPE dumpType = full ? MiniDumpWithFullMemory : MiniDumpNormal;
  MemoryDumpCancelContext cancel_ctx = {cmd_id};
  MINIDUMP_CALLBACK_INFORMATION callback_info;
  callback_info.CallbackRoutine = memory_dump_callback;
  callback_info.CallbackParam = &cancel_ctx;
  BOOL ok = MiniDumpWriteDump(h, (DWORD)pid, hFile, dumpType, NULL, NULL, &callback_info);
  CloseHandle(hFile);
  CloseHandle(h);
  if (!ok) {
    if (edr_command_cancel_requested(cmd_id)) {
      (void)remove(dmpPath);
      edr_cmd_inc_exec_fail();
      edr_command_emit_always_typed_status(cmd_id, "memory_dump", sm, EdrCmdExecFailed, 130,
                                           "memory dump cancelled during MiniDumpWriteDump", "cancelled");
      return;
    }
    edr_cmd_inc_exec_fail();
    edr_command_emit_always(cmd_id, sm, EdrCmdExecFailed, 5, "MiniDumpWriteDump failed");
    return;
  }
  char minio_key[1024];
  minio_key[0] = '\0';
  char sha[65];
  sha[0] = '\0';
  (void)response_file_sha256(dmpPath, sha);
  int up_rc = edr_transport_v2_upload_file(cmd_id, dmpPath, sha, minio_key, sizeof(minio_key));
  char result[2600];
  if (up_rc == 0) {
    forensic_result_json(result, sizeof(result), "success", "pmfe", dmpPath, sha, minio_key, 0,
                         "ok", "");
    edr_cmd_inc_handled(); edr_cmd_inc_exec_ok();
    edr_command_emit_always(cmd_id, sm, EdrCmdExecOk, 0, result);
  } else {
    forensic_result_json(result, sizeof(result), "failed", "pmfe", dmpPath, sha, "", 0,
                         "failed", "memory dump collected but upload failed");
    edr_cmd_inc_exec_fail();
    edr_command_emit_always(cmd_id, sm, EdrCmdExecFailed, 9, result);
  }
#else
  char procPath[128];
  snprintf(procPath, sizeof(procPath), "/proc/%d/mem", pid);
  FILE *src = fopen(procPath, "rb");
  if (!src) {
    edr_cmd_inc_exec_fail();
    edr_command_emit_always(cmd_id, sm, EdrCmdExecFailed, 3, "/proc/pid/mem open failed");
    return;
  }
  char dmpPath[512];
  snprintf(dmpPath, sizeof(dmpPath), "/tmp/memdump_%d_%lld.dmp", pid, (long long)time(NULL));
  FILE *dst = fopen(dmpPath, "wb");
  if (!dst) { fclose(src); edr_command_emit_always(cmd_id, sm, EdrCmdExecFailed, 4, "output create failed"); return; }
  char buf[65536];
  size_t total = 0;
  const size_t maxMem = 256ULL * 1024 * 1024;
  while (total < maxMem) {
    if (edr_command_cancel_requested(cmd_id)) {
      fclose(src); fclose(dst); (void)remove(dmpPath);
      edr_cmd_inc_exec_fail();
      edr_command_emit_always_typed_status(cmd_id, "memory_dump", sm, EdrCmdExecFailed, 130,
                                           "memory dump cancelled during read", "cancelled");
      return;
    }
    size_t nr = fread(buf, 1, sizeof(buf), src);
    if (nr == 0) break;
    fwrite(buf, 1, nr, dst);
    total += nr;
  }
  fclose(src); fclose(dst);
  char minio_key[1024];
  minio_key[0] = '\0';
  char sha[65];
  sha[0] = '\0';
  (void)response_file_sha256(dmpPath, sha);
  int up_rc = edr_transport_v2_upload_file(cmd_id, dmpPath, sha, minio_key, sizeof(minio_key));
  char result[2600];
  if (up_rc == 0) {
    forensic_result_json(result, sizeof(result), "success", "local_fallback", dmpPath, sha,
                         minio_key, total >= maxMem, "ok", "");
    edr_cmd_inc_handled(); edr_cmd_inc_exec_ok();
    edr_command_emit_always(cmd_id, sm, EdrCmdExecOk, 0, result);
  } else {
    forensic_result_json(result, sizeof(result), "failed", "local_fallback", dmpPath, sha, "",
                         total >= maxMem, "failed", "memory dump collected but upload failed");
    edr_cmd_inc_exec_fail();
    edr_command_emit_always(cmd_id, sm, EdrCmdExecFailed, 9, result);
  }
#endif
}

static void response_json_escape(const char *in, char *out, size_t cap) {
  if (!out || cap == 0) return;
  size_t oi = 0;
  out[0] = '\0';
  if (!in) return;
  for (const unsigned char *p = (const unsigned char *)in; *p && oi + 1 < cap; p++) {
    if (*p == '"' || *p == '\\') {
      if (oi + 2 >= cap) break;
      out[oi++] = '\\';
      out[oi++] = (char)*p;
    } else if (*p == '\n') {
      if (oi + 2 >= cap) break;
      out[oi++] = '\\';
      out[oi++] = 'n';
    } else if (*p == '\r') {
      if (oi + 2 >= cap) break;
      out[oi++] = '\\';
      out[oi++] = 'r';
    } else if (*p == '\t') {
      if (oi + 2 >= cap) break;
      out[oi++] = '\\';
      out[oi++] = 't';
    } else if (*p < 0x20) {
      continue;
    } else {
      out[oi++] = (char)*p;
    }
  }
  out[oi] = '\0';
}

static void yara_emit_json_result(const char *cmd_id, const EdrSoarCommandMeta *sm,
                                  EdrCommandExecutionStatus exec_status, int exit_code,
                                  const char *target_path, const char *engine, const char *status,
                                  int matched, long bytes_scanned, int files_scanned,
                                  int files_matched, int files_skipped, const char *rules_csv,
                                  const char *warning) {
  char path_esc[1100], engine_esc[96], status_esc[96], rules_esc[800], warning_esc[600];
  response_json_escape(target_path ? target_path : "", path_esc, sizeof(path_esc));
  response_json_escape(engine ? engine : "", engine_esc, sizeof(engine_esc));
  response_json_escape(status ? status : "", status_esc, sizeof(status_esc));
  response_json_escape(rules_csv ? rules_csv : "", rules_esc, sizeof(rules_esc));
  response_json_escape(warning ? warning : "", warning_esc, sizeof(warning_esc));

  char matches[1200];
  if (matched) {
    snprintf(matches, sizeof(matches), "[{\"path\":\"%s\",\"rules\":[", path_esc);
    const char *p = rules_esc;
    int first = 1;
    while (p && *p) {
      char rule_esc[180];
      size_t ri = 0;
      while (*p && *p != ',' && ri + 1 < sizeof(rule_esc)) {
        rule_esc[ri++] = *p++;
      }
      rule_esc[ri] = '\0';
      if (*p == ',') p++;
      if (!rule_esc[0]) continue;
      strncat(matches, first ? "\"" : ",\"", sizeof(matches) - strlen(matches) - 1);
      strncat(matches, rule_esc, sizeof(matches) - strlen(matches) - 1);
      strncat(matches, "\"", sizeof(matches) - strlen(matches) - 1);
      first = 0;
    }
    strncat(matches, "]}]", sizeof(matches) - strlen(matches) - 1);
  } else {
    snprintf(matches, sizeof(matches), "[]");
  }

  char warnings[700];
  if (warning_esc[0]) {
    snprintf(warnings, sizeof(warnings), "[\"%s\"]", warning_esc);
  } else {
    snprintf(warnings, sizeof(warnings), "[]");
  }

  char detail[4096];
  const char *contract_status = exec_status == EdrCmdExecOk
                                    ? (status && strcmp(status, "degraded") == 0
                                           ? "partial_success" : "success")
                                    : "failed";
  snprintf(detail, sizeof(detail),
           "{\"schema\":\"edr.yara_scan.result.v1\",\"status\":\"%s\",\"source\":\"%s\","
           "\"artifact\":\"%s\",\"sha256\":\"\",\"object_key\":\"\",\"truncated\":false,"
           "\"upload_status\":\"not_requested\",\"error\":\"%s\",\"scan_status\":\"%s\","
           "\"target_type\":\"file\",\"target_path\":\"%s\",\"engine\":\"%s\","
           "\"matched\":%s,\"files_scanned\":%d,\"files_matched\":%d,\"files_skipped\":%d,"
           "\"bytes_scanned\":%ld,\"matches\":%s,\"warnings\":%s}",
           contract_status, engine_esc, path_esc, exec_status == EdrCmdExecOk ? "" : warning_esc,
           status_esc, path_esc, engine_esc, matched ? "true" : "false", files_scanned,
           files_matched, files_skipped, bytes_scanned, matches, warnings);
  edr_command_emit_always(cmd_id, sm, exec_status, exit_code, detail);
}

static int yara_allow_builtin_fallback(void) {
  const char *e = getenv("EDR_YARA_ALLOW_BUILTIN_FALLBACK");
  return e && (e[0] == '1' || e[0] == 't' || e[0] == 'T' || e[0] == 'y' || e[0] == 'Y');
}

static int response_json_bool(const uint8_t *p, size_t len, const char *key) {
  int value = 0;
  return edr_parse_json_bool(p, len, key, &value) ? value : 0;
}

static void *response_memmem(const void *haystack, size_t haystack_len,
                             const void *needle, size_t needle_len) {
  if (!needle_len) return (void *)haystack;
  if (haystack_len < needle_len) return NULL;
  const char *h = (const char *)haystack;
  for (size_t i = 0; i <= haystack_len - needle_len; i++) {
    if (memcmp(h + i, needle, needle_len) == 0) return (void *)(h + i);
  }
  return NULL;
}

#ifdef EDR_HAVE_YARA
typedef struct {
  YR_RULES *rules;
  int max_files;
  int max_depth;
  long max_bytes;
  int recursive;
  int visited;
  int scanned;
  int matched_files;
  int skipped;
  int matches_returned;
  int matches_truncated;
  long bytes_scanned;
  int exclude_count;
  char exclude_paths[64][1024];
  char matches_json[4096];
  char warnings[512];
  const char *command_id;
  int cancelled;
  int max_files_reached;
  int max_depth_reached;
} YaraDirCtx;

static void yd_append_warning(YaraDirCtx *ctx, const char *msg) {
  if (!ctx || !msg || !msg[0]) return;
  if (ctx->warnings[0]) strncat(ctx->warnings, "; ", sizeof(ctx->warnings) - strlen(ctx->warnings) - 1);
  strncat(ctx->warnings, msg, sizeof(ctx->warnings) - strlen(ctx->warnings) - 1);
}

static void yd_normalize_path(const char *input, char *out, size_t cap) {
  size_t used = 0;
  if (!out || cap == 0u) return;
  out[0] = '\0';
  if (!input) return;
  for (const unsigned char *p = (const unsigned char *)input; *p && used + 1u < cap; p++) {
    unsigned char ch = *p == '\\' ? '/' : *p;
#ifdef _WIN32
    ch = (unsigned char)tolower(ch);
#endif
    if (ch == '/' && used > 0u && out[used - 1u] == '/') continue;
    out[used++] = (char)ch;
  }
  while (used > 1u && out[used - 1u] == '/') used--;
  out[used] = '\0';
}

static void yd_load_excludes(YaraDirCtx *ctx, const uint8_t *payload, size_t payload_len) {
  if (!ctx || !payload || payload_len == 0u) return;
  cJSON *root = cJSON_ParseWithLength((const char *)payload, payload_len);
  if (!root) {
    yd_append_warning(ctx, "exclude_paths could not be parsed");
    return;
  }
  cJSON *items = cJSON_GetObjectItemCaseSensitive(root, "exclude_paths");
  if (cJSON_IsArray(items)) {
    int count = cJSON_GetArraySize(items);
    for (int i = 0; i < count && ctx->exclude_count < 64; i++) {
      cJSON *item = cJSON_GetArrayItem(items, i);
      if (!cJSON_IsString(item) || !item->valuestring || !item->valuestring[0]) continue;
      yd_normalize_path(item->valuestring, ctx->exclude_paths[ctx->exclude_count],
                        sizeof(ctx->exclude_paths[ctx->exclude_count]));
      if (ctx->exclude_paths[ctx->exclude_count][0]) ctx->exclude_count++;
    }
    if (count > 64) yd_append_warning(ctx, "exclude_paths truncated to 64 entries");
  }
  cJSON_Delete(root);
}

static int yd_is_excluded(YaraDirCtx *ctx, const char *path) {
  if (!ctx || !path || !path[0] || ctx->exclude_count <= 0) return 0;
  char normalized[1200];
  yd_normalize_path(path, normalized, sizeof(normalized));
  for (int i = 0; i < ctx->exclude_count; i++) {
    const char *excluded = ctx->exclude_paths[i];
    size_t excluded_len = strlen(excluded);
    if (strcmp(normalized, excluded) == 0 ||
        (strncmp(normalized, excluded, excluded_len) == 0 && normalized[excluded_len] == '/')) {
      return 1;
    }
  }
  return 0;
}

static int yd_scan_file(YaraDirCtx *ctx, const char *path) {
  if (!ctx || !path || !path[0] || ctx->visited >= ctx->max_files) {
    if (ctx && ctx->visited >= ctx->max_files) ctx->max_files_reached = 1;
    return 0;
  }
  ctx->visited++;
  if (edr_command_cancel_requested(ctx->command_id)) { ctx->cancelled = 1; return 0; }
  if (yd_is_excluded(ctx, path)) { ctx->skipped++; return 0; }
  FILE *f = fopen(path, "rb");
  if (!f) { ctx->skipped++; return 0; }
  fseek(f, 0, SEEK_END);
  long fsz = ftell(f);
  fseek(f, 0, SEEK_SET);
  if (fsz <= 0 || fsz > ctx->max_bytes) { fclose(f); ctx->skipped++; return 0; }
  uint8_t *buf = (uint8_t *)malloc((size_t)fsz);
  if (!buf) { fclose(f); ctx->skipped++; return 0; }
  size_t nr = fread(buf, 1, (size_t)fsz, f);
  fclose(f);
  if (nr != (size_t)fsz) { free(buf); ctx->skipped++; return 0; }
  ForensicYaraResult res;
  char err[128]; err[0] = '\0';
  ctx->scanned++;
  ctx->bytes_scanned += fsz;
  int ok = fy_scan_rules(ctx->rules, ctx->command_id, path, buf, (size_t)fsz, &res, err, sizeof(err));
  if (res.cancelled) ctx->cancelled = 1;
  free(buf);
  if (!ok) { ctx->skipped++; yd_append_warning(ctx, err[0] ? err : "scan failed"); return 0; }
  if (res.count <= 0) return 1;
  ctx->matched_files++;
  if (ctx->matches_returned >= 100) { ctx->matches_truncated = 1; return 1; }
  char path_esc[1100]; response_json_escape(path, path_esc, sizeof(path_esc));
  if (ctx->matches_json[0]) strncat(ctx->matches_json, ",", sizeof(ctx->matches_json) - strlen(ctx->matches_json) - 1);
  strncat(ctx->matches_json, "{\"path\":\"", sizeof(ctx->matches_json) - strlen(ctx->matches_json) - 1);
  strncat(ctx->matches_json, path_esc, sizeof(ctx->matches_json) - strlen(ctx->matches_json) - 1);
  strncat(ctx->matches_json, "\",\"rules\":[", sizeof(ctx->matches_json) - strlen(ctx->matches_json) - 1);
  for (int i = 0; i < res.count; i++) {
    char rule_esc[180]; response_json_escape(res.rules[i], rule_esc, sizeof(rule_esc));
    strncat(ctx->matches_json, i == 0 ? "\"" : ",\"", sizeof(ctx->matches_json) - strlen(ctx->matches_json) - 1);
    strncat(ctx->matches_json, rule_esc, sizeof(ctx->matches_json) - strlen(ctx->matches_json) - 1);
    strncat(ctx->matches_json, "\"", sizeof(ctx->matches_json) - strlen(ctx->matches_json) - 1);
  }
  strncat(ctx->matches_json, "]}", sizeof(ctx->matches_json) - strlen(ctx->matches_json) - 1);
  ctx->matches_returned++;
  return 1;
}

static void yara_emit_dir_result(const char *cmd_id, const EdrSoarCommandMeta *sm, const char *target, YaraDirCtx *ctx) {
  char target_esc[1100], warn_esc[700];
  response_json_escape(target ? target : "", target_esc, sizeof(target_esc));
  response_json_escape(ctx && ctx->warnings[0] ? ctx->warnings : "", warn_esc, sizeof(warn_esc));
  char warnings[900];
  snprintf(warnings, sizeof(warnings), "%s%s%s", warn_esc[0] ? "[\"" : "[]", warn_esc[0] ? warn_esc : "", warn_esc[0] ? "\"]" : "");
  char detail[8192];
  snprintf(detail, sizeof(detail),
           "{\"schema\":\"edr.yara_scan.result.v1\",\"status\":\"success\",\"source\":\"libyara\","
           "\"artifact\":\"%s\",\"sha256\":\"\",\"object_key\":\"\","
           "\"truncated\":%s,\"upload_status\":\"not_requested\",\"error\":\"\","
           "\"scan_status\":\"completed\",\"target_type\":\"directory\",\"target_path\":\"%s\","
           "\"engine\":\"libyara\",\"matched\":%s,\"files_scanned\":%d,\"files_matched\":%d,"
           "\"files_skipped\":%d,\"bytes_scanned\":%ld,\"matches\":[%s],"
           "\"matches_returned\":%d,\"matches_truncated\":%s,\"warnings\":%s}",
           target_esc, ctx->matches_truncated ? "true" : "false", target_esc,
           ctx->matched_files > 0 ? "true" : "false", ctx->scanned, ctx->matched_files, ctx->skipped,
           ctx->bytes_scanned, ctx->matches_json, ctx->matches_returned, ctx->matches_truncated ? "true" : "false", warnings);
  edr_command_emit_always(cmd_id, sm, EdrCmdExecOk, 0, detail);
}

#ifdef _WIN32
static void yd_walk(YaraDirCtx *ctx, const char *dir, int depth) {
  if (!ctx || !dir || ctx->visited >= ctx->max_files || depth > ctx->max_depth) return;
  if (edr_command_cancel_requested(ctx->command_id)) { ctx->cancelled = 1; return; }
  char pat[1100]; snprintf(pat, sizeof(pat), "%s\\*", dir);
  WIN32_FIND_DATAA ffd; HANDLE h = FindFirstFileA(pat, &ffd);
  if (h == INVALID_HANDLE_VALUE) { ctx->skipped++; return; }
  do {
    if (strcmp(ffd.cFileName, ".") == 0 || strcmp(ffd.cFileName, "..") == 0) continue;
    char full[1200]; snprintf(full, sizeof(full), "%s\\%s", dir, ffd.cFileName);
    if ((ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
      if (ctx->recursive && depth < ctx->max_depth) yd_walk(ctx, full, depth + 1);
      else if (ctx->recursive) ctx->max_depth_reached = 1;
    }
    else yd_scan_file(ctx, full);
    if (ctx->cancelled) break;
    if (ctx->visited >= ctx->max_files) { ctx->max_files_reached = 1; break; }
  } while (FindNextFileA(h, &ffd));
  FindClose(h);
}
#else
static void yd_walk(YaraDirCtx *ctx, const char *dir, int depth) {
  if (!ctx || !dir || ctx->visited >= ctx->max_files || depth > ctx->max_depth) return;
  if (edr_command_cancel_requested(ctx->command_id)) { ctx->cancelled = 1; return; }
  DIR *d = opendir(dir);
  if (!d) { ctx->skipped++; return; }
  struct dirent *ent;
  while ((ent = readdir(d)) != NULL) {
    if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;
    char full[1200]; snprintf(full, sizeof(full), "%s/%s", dir, ent->d_name);
    struct stat st;
    if (lstat(full, &st) != 0) { ctx->skipped++; continue; }
    if (S_ISDIR(st.st_mode)) {
      if (ctx->recursive && depth < ctx->max_depth) yd_walk(ctx, full, depth + 1);
      else if (ctx->recursive) ctx->max_depth_reached = 1;
    }
    else if (S_ISREG(st.st_mode)) yd_scan_file(ctx, full);
    else ctx->skipped++;
    if (ctx->cancelled) break;
    if (ctx->visited >= ctx->max_files) { ctx->max_files_reached = 1; break; }
  }
  closedir(d);
}
#endif
#endif

void edr_response_yara_scan(const char *cmd_id, const uint8_t *pl, size_t len, const EdrSoarCommandMeta *sm) {
  /* yara_scan is a read-only scan. command_stub.c already applies the operator-only
   * gate before dispatching here, so do not require the global dangerous-command
   * switch that is reserved for destructive response actions. */

  /* 外移:collector 按 request(target_path/pid + 规则)异步扫描,完成由主循环 poll 上传+上报。 */
  if (yara_external_enabled()) {
    char dc_detail[512];
    dc_detail[0] = '\0';
    int ar = edr_response_forensic_async_accept(cmd_id, "yara_scan", sm, "yara_scan",
                                                pl, len, "tar.gz", 1, dc_detail, sizeof(dc_detail));
    if (ar == 0) { edr_command_audit_both(cmd_id, "yara_scan: accepted(async)"); return; }
    if (ar == 1) {
      edr_cmd_inc_exec_fail();
      edr_command_emit_always(cmd_id, sm, EdrCmdExecFailed, 7, "forensic busy: another collection running");
      return;
    }
    if (forensic_external_required()) {
      edr_cmd_inc_exec_fail();
      char fail[600];
      snprintf(fail, sizeof(fail), "yara_scan external failed rc=%d: %.460s", ar, dc_detail);
      edr_command_emit_always(cmd_id, sm, EdrCmdExecFailed, 6, fail);
      return;
    }
    edr_command_audit_both(cmd_id, "yara_scan: external unavailable, fallback in-process");
  }

  char target_path[520];
  char target_type[32];
  char rules_text[262144];
  int max_files = 0, max_depth = 0, max_file_mb = 0;
  (void)edr_parse_json_string(pl, len, "target_path", target_path, sizeof(target_path));
  (void)edr_parse_json_string(pl, len, "target_type", target_type, sizeof(target_type));
  (void)edr_parse_json_string(pl, len, "rules", rules_text, sizeof(rules_text));
  (void)edr_parse_json_int(pl, len, "max_files", &max_files);
  (void)edr_parse_json_int(pl, len, "max_depth", &max_depth);
  (void)edr_parse_json_int(pl, len, "max_file_mb", &max_file_mb);
  int recursive = response_json_bool(pl, len, "recursive");
  (void)recursive;
  if (!target_type[0]) snprintf(target_type, sizeof(target_type), "file");
  if (!target_path[0]) {
    edr_cmd_inc_exec_fail();
    yara_emit_json_result(cmd_id, sm, EdrCmdExecFailed, 2, "", "unavailable", "failed", 0, 0, 0, 0, 0,
                          NULL, "missing target_path");
    return;
  }
  if (strcmp(target_type, "directory") == 0) {
#ifdef EDR_HAVE_YARA
    if (max_files <= 0 || max_files > 10000) max_files = 1000;
    if (max_depth <= 0 || max_depth > 32) max_depth = 8;
    if (max_file_mb <= 0 || max_file_mb > 256) max_file_mb = 50;
    char yerr[256]; yerr[0] = '\0';
    char rules_source[1100]; rules_source[0] = '\0';
    int rules_files_loaded = 0;
    YR_RULES *rules = fy_compile_effective_rules(rules_text, rules_source, sizeof(rules_source),
                                                 &rules_files_loaded, yerr, sizeof(yerr));
    if (!rules) {
      edr_cmd_inc_exec_fail();
      yara_emit_json_result(cmd_id, sm, EdrCmdExecFailed, 6, target_path, "libyara", "failed", 0, 0, 0, 0,
                            0, NULL, yerr[0] ? yerr : "YARA rule compile failed");
      return;
    }
    YaraDirCtx yd;
    memset(&yd, 0, sizeof(yd));
    yd.rules = rules;
    yd.max_files = max_files;
    yd.max_depth = max_depth;
    yd.max_bytes = (long)max_file_mb * 1024L * 1024L;
    yd.recursive = recursive;
    yd_load_excludes(&yd, pl, len);
    yd.command_id = cmd_id;
    yd_walk(&yd, target_path, 0);
    if (yd.max_files_reached) yd_append_warning(&yd, "max_files limit reached");
    if (yd.max_depth_reached) yd_append_warning(&yd, "max_depth limit reached");
    yr_rules_destroy(rules);
    if (yd.cancelled || edr_command_cancel_requested(cmd_id)) {
      edr_cmd_inc_exec_fail();
      edr_command_emit_always_typed_status(cmd_id, "yara_scan", sm, EdrCmdExecFailed, 130,
                                           "YARA directory scan cancelled", "cancelled");
      return;
    }
    edr_cmd_inc_handled();
    edr_cmd_inc_exec_ok();
    char audit[1400];
    snprintf(audit, sizeof(audit), "yara_scan: ok (directory engine=libyara source=%s files_loaded=%d)",
             rules_source[0] ? rules_source : "unknown", rules_files_loaded);
    edr_command_audit_both(cmd_id, audit);
    yara_emit_dir_result(cmd_id, sm, target_path, &yd);
    return;
#else
    edr_cmd_inc_exec_fail();
    yara_emit_json_result(cmd_id, sm, EdrCmdExecFailed, 6, target_path, "unavailable", "failed", 0, 0, 0,
                          0, 0, NULL, "This Agent build does not include libyara-backed YARA support; upgrade to a YARA-enabled Agent build or route the request through the collector");
    return;
#endif
  }
#ifdef _WIN32
  DWORD attrs = GetFileAttributesA(target_path);
  if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY)) {
    edr_cmd_inc_exec_fail();
    yara_emit_json_result(cmd_id, sm, EdrCmdExecFailed, 3, target_path, "unavailable", "failed", 0, 0, 0,
                          0, 0, NULL, "target_path is a directory; current YARA scan supports single files only");
    return;
  }
#else
  struct stat st;
  if (stat(target_path, &st) == 0 && S_ISDIR(st.st_mode)) {
    edr_cmd_inc_exec_fail();
    yara_emit_json_result(cmd_id, sm, EdrCmdExecFailed, 3, target_path, "unavailable", "failed", 0, 0, 0,
                          0, 0, NULL, "target_path is a directory; current YARA scan supports single files only");
    return;
  }
#endif
  FILE *f = fopen(target_path, "rb");
  if (!f) {
    edr_cmd_inc_exec_fail();
    yara_emit_json_result(cmd_id, sm, EdrCmdExecFailed, 3, target_path, "unavailable", "failed", 0, 0, 0,
                          0, 0, NULL, "file not found");
    return;
  }
  fseek(f, 0, SEEK_END);
  long fsz = ftell(f);
  fseek(f, 0, SEEK_SET);
  if (fsz <= 0 || fsz > 50 * 1024 * 1024) {
    fclose(f);
    edr_cmd_inc_exec_fail();
    yara_emit_json_result(cmd_id, sm, EdrCmdExecFailed, 4, target_path, "unavailable", "failed", 0, 0, 0,
                          0, 1, NULL, "file empty or too large (>50MB)");
    return;
  }
  uint8_t *buf = (uint8_t *)malloc((size_t)fsz);
  if (!buf) {
    fclose(f);
    edr_cmd_inc_exec_fail();
    yara_emit_json_result(cmd_id, sm, EdrCmdExecFailed, 5, target_path, "unavailable", "failed", 0, 0, 0,
                          0, 0, NULL, "out of memory");
    return;
  }
  size_t nr = fread(buf, 1, (size_t)fsz, f);
  fclose(f);
  if (nr != (size_t)fsz) {
    free(buf);
    edr_cmd_inc_exec_fail();
    yara_emit_json_result(cmd_id, sm, EdrCmdExecFailed, 5, target_path, "unavailable", "failed", 0, 0, 0,
                          0, 1, NULL, "file read failed");
    return;
  }

#ifdef EDR_HAVE_YARA
  ForensicYaraResult yres;
  char yerr[256];
  char rules_source[1100];
  int rules_files_loaded = 0;
  yerr[0] = '\0';
  rules_source[0] = '\0';
  YR_RULES *rules = fy_compile_effective_rules(rules_text, rules_source, sizeof(rules_source),
                                               &rules_files_loaded, yerr, sizeof(yerr));
  if (rules) {
    int ok = fy_scan_rules(rules, cmd_id, target_path, buf, (size_t)fsz, &yres, yerr, sizeof(yerr));
    yr_rules_destroy(rules);
    if (yres.cancelled || edr_command_cancel_requested(cmd_id)) {
      free(buf);
      edr_cmd_inc_exec_fail();
      edr_command_emit_always_typed_status(cmd_id, "yara_scan", sm, EdrCmdExecFailed, 130,
                                           "YARA file scan cancelled", "cancelled");
      return;
    }
    if (ok) {
      char rules_csv[700];
      rules_csv[0] = '\0';
      for (int i = 0; i < yres.count; i++) {
        if (rules_csv[0]) strncat(rules_csv, ",", sizeof(rules_csv) - strlen(rules_csv) - 1);
        strncat(rules_csv, yres.rules[i], sizeof(rules_csv) - strlen(rules_csv) - 1);
      }
      free(buf);
      edr_cmd_inc_handled();
      edr_cmd_inc_exec_ok();
      char audit[1400];
      snprintf(audit, sizeof(audit), "yara_scan: ok (engine=libyara source=%s files_loaded=%d)",
               rules_source[0] ? rules_source : "unknown", rules_files_loaded);
      edr_command_audit_both(cmd_id, audit);
      yara_emit_json_result(cmd_id, sm, EdrCmdExecOk, 0, target_path, "libyara", "completed", yres.count > 0,
                            fsz, 1, yres.count > 0 ? 1 : 0, 0, rules_csv, NULL);
      return;
    }
  }
  if (!yara_allow_builtin_fallback()) {
    free(buf);
    edr_cmd_inc_exec_fail();
    char audit[1400];
    snprintf(audit, sizeof(audit), "yara_scan: failed (libyara source=%s)",
             rules_source[0] ? rules_source : "unknown");
    edr_command_audit_both(cmd_id, audit);
    yara_emit_json_result(cmd_id, sm, EdrCmdExecFailed, 6, target_path, "libyara", "failed", 0, 0, 0, 0,
                          0, NULL, yerr[0] ? yerr : "libyara scan failed");
    return;
  }
#else
  if (!yara_allow_builtin_fallback()) {
    free(buf);
    edr_cmd_inc_exec_fail();
    edr_command_audit_both(cmd_id, "yara_scan: failed (libyara unavailable)");
    yara_emit_json_result(cmd_id, sm, EdrCmdExecFailed, 6, target_path, "unavailable", "failed", 0, 0, 0,
                          0, 0, NULL, "This Agent build does not include libyara-backed YARA support; upgrade to a YARA-enabled Agent build or enable the collector/fallback path for this request");
    return;
  }
#endif

  int matches = 0;
  const char *patterns[] = {
    "MZ", "PE\0\0", "This program cannot be run",
    "powershell", "cmd.exe", "rundll32",
    "CreateRemoteThread", "VirtualAllocEx",
    "WriteProcessMemory", "NtCreateThreadEx",
    "https://", "http://", ".onion",
    "eval(", "base64_decode", "system(",
    NULL
  };
  char hitBuf[512];
  hitBuf[0] = '\0';
  for (int pi = 0; patterns[pi]; pi++) {
    if (response_memmem(buf, (size_t)fsz, patterns[pi], strlen(patterns[pi]))) {
      matches++;
      if (hitBuf[0]) strncat(hitBuf, ",", sizeof(hitBuf)-strlen(hitBuf)-1);
      strncat(hitBuf, patterns[pi], sizeof(hitBuf)-strlen(hitBuf)-1);
    }
  }
  free(buf);

  edr_cmd_inc_handled();
  edr_cmd_inc_exec_ok();
  edr_command_audit_both(cmd_id, "yara_scan: degraded (engine=builtin_substring_heuristic)");
  yara_emit_json_result(cmd_id, sm, EdrCmdExecOk, 0, target_path, "builtin_substring_heuristic", "degraded",
                        matches > 0, fsz, 1, matches > 0 ? 1 : 0, 0, hitBuf,
                        "YARA engine unavailable or rule compilation failed; used built-in substring heuristic, not YARA");
}
