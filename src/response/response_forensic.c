#include "edr/response.h"
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
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#include "edr/response_utils.h"

/* ── 取证 YARA 真引擎（libyara，构建启用 EDR_WITH_YARA 时可用） ──
 * 复用 shellcode_known.c 的成熟模式：懒加载 + 目录编译 + scan 回调收集命中规则名。
 * 规则目录优先级：EDR_YARA_RULES_DIR > [command].forensic_yara_rules_dir > 默认 rules/forensic。
 * 不可用（未链接 libyara / 无规则 / 加载失败）时由调用方回退内置子串匹配。 */
#ifdef EDR_HAVE_YARA
#include <yara.h>
#if !defined(_WIN32)
#include <dirent.h>
#endif

#define EDR_FY_RULE_NAME_MAX 128
#define EDR_FY_MAX_HITS 8

typedef struct {
  char rules[EDR_FY_MAX_HITS][EDR_FY_RULE_NAME_MAX];
  int count;
} ForensicYaraResult;

static YR_RULES *s_fy_rules;
static int s_fy_initialized;
static int s_fy_loaded;

static int fy_is_rule_file(const char *name) {
  const char *dot = name ? strrchr(name, '.') : NULL;
  if (!dot) {
    return 0;
  }
  return (strcmp(dot, ".yar") == 0 || strcmp(dot, ".yara") == 0) ? 1 : 0;
}

static void fy_compiler_error_cb(int level, const char *fn, int line, const YR_RULE *rule,
                                 const char *msg, void *ud) {
  (void)rule;
  (void)ud;
  const char *lv = (level == YARA_ERROR_LEVEL_WARNING) ? "warning" : "error";
  fprintf(stderr, "[forensic-yara] compile %s file=%s line=%d msg=%s\n", lv, fn ? fn : "-", line,
          msg ? msg : "-");
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
  if (message == CALLBACK_MSG_RULE_MATCHING) {
    const YR_RULE *rule = (const YR_RULE *)message_data;
    if (rule && rule->identifier && res->count < EDR_FY_MAX_HITS) {
      snprintf(res->rules[res->count], EDR_FY_RULE_NAME_MAX, "%s", rule->identifier);
      res->count++;
    }
  }
  return CALLBACK_CONTINUE;
}

static int fy_add_file(YR_COMPILER *c, const char *path) {
  FILE *fp = fopen(path, "rb");
  if (!fp) {
    return 0;
  }
  int nerr = yr_compiler_add_file(c, fp, NULL, path);
  fclose(fp);
  return nerr > 0 ? 0 : 1;
}

#if defined(_WIN32)
static int fy_add_dir(YR_COMPILER *c, const char *dir) {
  char pattern[1024];
  snprintf(pattern, sizeof(pattern), "%s\\*.*", dir);
  WIN32_FIND_DATAA ffd;
  HANDLE h = FindFirstFileA(pattern, &ffd);
  if (h == INVALID_HANDLE_VALUE) {
    return 0;
  }
  int loaded = 0;
  do {
    if ((ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
      continue;
    }
    if (!fy_is_rule_file(ffd.cFileName)) {
      continue;
    }
    char full[1024];
    snprintf(full, sizeof(full), "%s\\%s", dir, ffd.cFileName);
    loaded += fy_add_file(c, full);
  } while (FindNextFileA(h, &ffd));
  FindClose(h);
  return loaded;
}
#else
static int fy_add_dir(YR_COMPILER *c, const char *dir) {
  DIR *d = opendir(dir);
  if (!d) {
    return 0;
  }
  int loaded = 0;
  struct dirent *ent;
  while ((ent = readdir(d)) != NULL) {
    if (ent->d_name[0] == '.') {
      continue;
    }
    if (!fy_is_rule_file(ent->d_name)) {
      continue;
    }
    char full[1024];
    snprintf(full, sizeof(full), "%s/%s", dir, ent->d_name);
    loaded += fy_add_file(c, full);
  }
  closedir(d);
  return loaded;
}
#endif

static const char *fy_rules_dir(void) {
  const char *e = getenv("EDR_YARA_RULES_DIR");
  if (e && e[0]) {
    return e;
  }
  const EdrConfig *cfg = edr_command_get_config();
  if (cfg && cfg->command.forensic_yara_rules_dir[0]) {
    return cfg->command.forensic_yara_rules_dir;
  }
  return "rules/forensic";
}

/* 懒加载并编译规则。返回 1=规则可用，0=不可用（调用方回退子串匹配）。 */
static int fy_ensure_rules(void) {
  if (s_fy_loaded && s_fy_rules) {
    return 1;
  }
  if (!s_fy_initialized) {
    if (yr_initialize() != ERROR_SUCCESS) {
      return 0;
    }
    s_fy_initialized = 1;
  }
  YR_COMPILER *c = NULL;
  if (yr_compiler_create(&c) != ERROR_SUCCESS || !c) {
    return 0;
  }
  yr_compiler_set_callback(c, fy_compiler_error_cb, NULL);
  int loaded = fy_add_dir(c, fy_rules_dir());
  if (loaded <= 0) {
    yr_compiler_destroy(c);
    return 0;
  }
  YR_RULES *rules = NULL;
  if (yr_compiler_get_rules(c, &rules) != ERROR_SUCCESS || !rules) {
    yr_compiler_destroy(c);
    return 0;
  }
  yr_compiler_destroy(c);
  if (s_fy_rules) {
    yr_rules_destroy(s_fy_rules);
  }
  s_fy_rules = rules;
  s_fy_loaded = 1;
  return 1;
}

/* 用真引擎扫描文件（拿不到文件时回退内存缓冲）。
 * 返回 1=已用真引擎并将结果写入 out；0=引擎不可用，需回退子串匹配。 */
static int fy_scan(const char *target_path, const uint8_t *buf, size_t len, char *out, size_t cap) {
  if (!fy_ensure_rules()) {
    return 0;
  }
  ForensicYaraResult res;
  memset(&res, 0, sizeof(res));
  int rc = ERROR_INTERNAL_FATAL_ERROR;
  if (target_path && target_path[0]) {
    rc = yr_rules_scan_file(s_fy_rules, target_path, 0, fy_scan_cb, &res, 0);
  }
  if (rc != ERROR_SUCCESS && buf && len > 0u) {
    rc = yr_rules_scan_mem(s_fy_rules, buf, len, 0, fy_scan_cb, &res, 0);
  }
  if (rc != ERROR_SUCCESS) {
    return 0;
  }
  if (res.count > 0) {
    char rl[640];
    rl[0] = '\0';
    for (int i = 0; i < res.count; i++) {
      if (rl[0]) {
        strncat(rl, ",", sizeof(rl) - strlen(rl) - 1);
      }
      strncat(rl, res.rules[i], sizeof(rl) - strlen(rl) - 1);
    }
    snprintf(out, cap, "YARA_HIT path=%s engine=yara count=%d rules=[%s]",
             target_path ? target_path : "(mem)", res.count, rl);
  } else {
    snprintf(out, cap, "YARA_CLEAN path=%s engine=yara", target_path ? target_path : "(mem)");
  }
  return 1;
}
#endif /* EDR_HAVE_YARA */

/* ── Forensic Actions ── */

/* 取证外移门控:默认关闭(保持 in-process 现状,不破坏)。
 * EDR_FORENSIC_COLLECTOR=1 启用外部 collector;EDR_FORENSIC_COLLECTOR_STRICT=1 失败不回退。 */
static int forensic_external_enabled(void) {
  const char *e = getenv("EDR_FORENSIC_COLLECTOR");
  return e && (e[0] == '1' || e[0] == 't' || e[0] == 'T' || e[0] == 'y' || e[0] == 'Y');
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

  /* 第一级:Go 适配器(默认路径 forensic_collector[.exe])→ 调官方 Velociraptor。 */
  int rc = edr_deep_collector_run_blocking(&spec, detail, detail_cap);
  const char *tier = "velo";

  /* 第二级兜底:velo 不可用(rc==5,collector exitNoVelo)或启动/超时/崩溃(rc<0),
   * 且非 STRICT 时,改调 C baseline(forensic_collector_builtin)。仍失败则由调用方回退 in-process。 */
  if ((rc == 5 || rc < 0) && !forensic_external_required()) {
    const char *bbin = getenv("EDR_FORENSIC_COLLECTOR_BUILTIN_BIN");
    if (!bbin || !bbin[0]) {
#ifdef _WIN32
      bbin = "C:\\Program Files\\FDSecurity\\collector\\forensic_collector_builtin.exe";
#else
      bbin = "forensic_collector_builtin";
#endif
    }
    spec.collector_bin = bbin;
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

void edr_response_collect_forensic(const char *cmd_id, const uint8_t *pl, size_t len,
                                    const EdrSoarCommandMeta *sm) {
  if (!edr_command_dangerous_enabled()) {
    edr_cmd_inc_rejected();
    edr_command_audit_both(cmd_id, "reject forensic: 设置 EDR_CMD_ENABLED=1 或 TOML [command] allow_dangerous=true");
    edr_command_emit_always(cmd_id, sm, EdrCmdExecRejected, 1, "policy disabled");
    return;
  }

  /* 外移:由独立 collector 生成 triage bundle,agent 经 transport v2 上传(通信只走 agent)。 */
  if (forensic_external_enabled()) {
    char minio_key[1024];
    char dc_detail[512];
    minio_key[0] = '\0';
    int rc = forensic_external_run(cmd_id, "collect_forensic", pl, len, "tar.gz", 1, minio_key,
                                   sizeof(minio_key), dc_detail, sizeof(dc_detail));
    if (rc == 0) {
      char result[640];
      snprintf(result, sizeof(result), "forensic bundle ok(external) minio_key=%.480s",
               minio_key[0] ? minio_key : "(local)");
      edr_cmd_inc_handled();
      edr_cmd_inc_exec_ok();
      edr_command_emit_always(cmd_id, sm, EdrCmdExecOk, 0, result);
      return;
    }
    if (forensic_external_required()) {
      edr_cmd_inc_exec_fail();
      char fail[600];
      snprintf(fail, sizeof(fail), "collect_forensic external failed rc=%d: %.460s", rc, dc_detail);
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
  if (edr_pmfe_submit_server_scan(cmd_id, (uint32_t)pid) != 0) {
    edr_cmd_inc_exec_fail();
    edr_command_audit_both(cmd_id, "pmfe_scan: queue failed (PMFE not running or queue full)");
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, 3, "pmfe queue full or not running");
    return;
  }
  edr_cmd_inc_handled();
  edr_cmd_inc_exec_ok();
  edr_command_audit_both(cmd_id, "pmfe_scan: queued (async coarse scan)");
  edr_command_soar_emit(cmd_id, sm, EdrCmdExecOk, 0, "pmfe_scan queued");
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

  /* 外移:collector 按 request 中的 item 清单采集打包,agent 上传(通信只走 agent)。 */
  if (forensic_external_enabled()) {
    char minio_key[1024];
    char dc_detail[512];
    minio_key[0] = '\0';
    int rc = forensic_external_run(cmd_id, "targeted_forensic", pl, len, "tar.gz", 1, minio_key,
                                   sizeof(minio_key), dc_detail, sizeof(dc_detail));
    if (rc == 0) {
      char result[640];
      snprintf(result, sizeof(result), "TARGETED_OK(external) minio_key=%.480s",
               minio_key[0] ? minio_key : "(local)");
      edr_cmd_inc_handled();
      edr_cmd_inc_exec_ok();
      edr_command_emit_always(cmd_id, sm, EdrCmdExecOk, 0, result);
      return;
    }
    if (forensic_external_required()) {
      edr_cmd_inc_exec_fail();
      char fail[600];
      snprintf(fail, sizeof(fail), "targeted_forensic external failed rc=%d: %.460s", rc, dc_detail);
      edr_command_emit_always(cmd_id, sm, EdrCmdExecFailed, 6, fail);
      return;
    }
    edr_command_audit_both(cmd_id, "targeted_forensic: external unavailable, fallback in-process");
  }

  char out[4096];
  int count = 0;
  out[0] = '\0';

  const char *p = (const char *)pl;
  const char *end = p + len;

  while (p < end && count < 20) {
    const char *typePos = strstr(p, "\"type\"");
    if (!typePos || typePos >= end) break;
    typePos += 6;
    while (typePos < end && (*typePos == ' ' || *typePos == ':' || *typePos == '"')) typePos++;
    if (typePos >= end) break;

    if (strncmp(typePos, "file", 4) == 0) {
      const char *pathPos = strstr(typePos, "\"path\"");
      if (pathPos && pathPos < end) {
        pathPos += 6;
        while (pathPos < end && (*pathPos == ' ' || *pathPos == ':' || *pathPos == '"')) pathPos++;
        char fpath[520];
        size_t fi = 0;
        while (pathPos < end && *pathPos != '"' && fi < sizeof(fpath)-1) fpath[fi++] = *pathPos++;
        fpath[fi] = '\0';
        if (fpath[0]) {
          const char *fbname = strrchr(fpath, '/');
          if (!fbname) fbname = strrchr(fpath, '\\');
          if (!fbname) fbname = fpath; else fbname++;
          char dest[800];
          snprintf(dest, sizeof(dest), "files/%s", fbname);
          response_forensic_copy_one_file(fpath, dest);
          count++;
        }
      }
      p = pathPos ? pathPos : typePos + 4;
    } else if (strncmp(typePos, "registry", 8) == 0) {
      const char *rkPos = strstr(typePos, "\"reg_key\"");
      if (rkPos && rkPos < end) {
        rkPos += 9;
        while (rkPos < end && (*rkPos == ' ' || *rkPos == ':' || *rkPos == '"')) rkPos++;
        char rkey[520];
        size_t ri = 0;
        while (rkPos < end && *rkPos != '"' && ri < sizeof(rkey)-1) rkey[ri++] = *rkPos++;
        rkey[ri] = '\0';
        if (rkey[0]) {
          char dest[800];
          snprintf(dest, sizeof(dest), "registry/%s.reg", rkey); (void)dest;
          count++;
        }
      }
      p = rkPos ? rkPos : typePos + 8;
    } else {
      p = typePos + 4;
    }
    const char *next = strstr(p, "\"type\"");
    if (!next) break;
    p = next;
  }
  snprintf(out, sizeof(out), "TARGETED_OK items=%d", count);
  edr_cmd_inc_handled(); edr_cmd_inc_exec_ok();
  edr_command_audit_both(cmd_id, "targeted_forensic: ok");
  edr_command_emit_always(cmd_id, sm, EdrCmdExecOk, 0, out);
}

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
    char minio_key[1024];
    char dc_detail[512];
    minio_key[0] = '\0';
    int rc = forensic_external_run(cmd_id, "memory_dump", pl, len, "dmp", 1, minio_key,
                                   sizeof(minio_key), dc_detail, sizeof(dc_detail));
    if (rc == 0) {
      char result[640];
      snprintf(result, sizeof(result), "MEMDUMP_OK(external) pid=%d minio_key=%.480s", pid,
               minio_key[0] ? minio_key : "(local)");
      edr_cmd_inc_handled();
      edr_cmd_inc_exec_ok();
      edr_command_emit_always(cmd_id, sm, EdrCmdExecOk, 0, result);
      return;
    }
    if (forensic_external_required()) {
      edr_cmd_inc_exec_fail();
      char fail[600];
      snprintf(fail, sizeof(fail), "memory_dump external collector failed rc=%d: %.470s", rc,
               dc_detail);
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
  BOOL ok = MiniDumpWriteDump(h, (DWORD)pid, hFile, dumpType, NULL, NULL, NULL);
  CloseHandle(hFile);
  CloseHandle(h);
  if (!ok) {
    edr_cmd_inc_exec_fail();
    edr_command_emit_always(cmd_id, sm, EdrCmdExecFailed, 5, "MiniDumpWriteDump failed");
    return;
  }
  char minio_key[1024];
  minio_key[0] = '\0';
  int up_rc = edr_transport_v2_upload_file(cmd_id, dmpPath, NULL, minio_key, sizeof(minio_key));
  char result[700];
  if (up_rc == 0) {
    snprintf(result, sizeof(result), "MEMDUMP_OK pid=%d file=%s minio_key=%.400s", pid, dmpPath,
             minio_key[0] ? minio_key : "(ok)");
  } else {
    snprintf(result, sizeof(result), "MEMDUMP_OK pid=%d file=%s upload=failed", pid, dmpPath);
  }
  edr_cmd_inc_handled(); edr_cmd_inc_exec_ok();
  edr_command_emit_always(cmd_id, sm, EdrCmdExecOk, 0, result);
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
    size_t nr = fread(buf, 1, sizeof(buf), src);
    if (nr == 0) break;
    fwrite(buf, 1, nr, dst);
    total += nr;
  }
  fclose(src); fclose(dst);
  char minio_key[1024];
  minio_key[0] = '\0';
  int up_rc = edr_transport_v2_upload_file(cmd_id, dmpPath, NULL, minio_key, sizeof(minio_key));
  char result[700];
  if (up_rc == 0) {
    snprintf(result, sizeof(result), "MEMDUMP_OK pid=%d size=%zu file=%s minio_key=%.380s", pid,
             total, dmpPath, minio_key[0] ? minio_key : "(ok)");
  } else {
    snprintf(result, sizeof(result), "MEMDUMP_OK pid=%d size=%zu file=%s upload=failed", pid, total,
             dmpPath);
  }
  edr_cmd_inc_handled(); edr_cmd_inc_exec_ok();
  edr_command_emit_always(cmd_id, sm, EdrCmdExecOk, 0, result);
#endif
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

void edr_response_yara_scan(const char *cmd_id, const uint8_t *pl, size_t len, const EdrSoarCommandMeta *sm) {
  if (!edr_command_dangerous_enabled()) {
    edr_cmd_inc_rejected();
    edr_command_audit_both(cmd_id, "reject yara_scan: policy");
    edr_command_emit_always(cmd_id, sm, EdrCmdExecRejected, 1, "policy disabled");
    return;
  }

  /* 外移:collector 按 request(target_path/pid + 规则)扫描并落结果 json,agent 上传(通信只走 agent)。 */
  if (forensic_external_enabled()) {
    char minio_key[1024];
    char dc_detail[512];
    minio_key[0] = '\0';
    int rc = forensic_external_run(cmd_id, "yara_scan", pl, len, "json", 1, minio_key,
                                   sizeof(minio_key), dc_detail, sizeof(dc_detail));
    if (rc == 0) {
      char result[640];
      snprintf(result, sizeof(result), "YARA_OK(external) minio_key=%.480s",
               minio_key[0] ? minio_key : "(local)");
      edr_cmd_inc_handled();
      edr_cmd_inc_exec_ok();
      edr_command_emit_always(cmd_id, sm, EdrCmdExecOk, 0, result);
      return;
    }
    if (forensic_external_required()) {
      edr_cmd_inc_exec_fail();
      char fail[600];
      snprintf(fail, sizeof(fail), "yara_scan external failed rc=%d: %.460s", rc, dc_detail);
      edr_command_emit_always(cmd_id, sm, EdrCmdExecFailed, 6, fail);
      return;
    }
    edr_command_audit_both(cmd_id, "yara_scan: external unavailable, fallback in-process");
  }

  char target_path[520];
  (void)edr_parse_json_string(pl, len, "target_path", target_path, sizeof(target_path));
  if (!target_path[0]) {
    edr_cmd_inc_exec_fail();
    edr_command_emit_always(cmd_id, sm, EdrCmdExecFailed, 2, "missing target_path");
    return;
  }
  FILE *f = fopen(target_path, "rb");
  if (!f) {
    f = fopen(target_path, "r");
  }
  if (!f) {
    edr_cmd_inc_exec_fail();
    edr_command_emit_always(cmd_id, sm, EdrCmdExecFailed, 3, "file not found");
    return;
  }
  fseek(f, 0, SEEK_END);
  long fsz = ftell(f);
  fseek(f, 0, SEEK_SET);
  if (fsz <= 0 || fsz > 50 * 1024 * 1024) {
    fclose(f);
    edr_command_emit_always(cmd_id, sm, EdrCmdExecFailed, 4, "file too large (>50MB)");
    return;
  }
  uint8_t *buf = (uint8_t *)malloc((size_t)fsz);
  if (!buf) { fclose(f); edr_command_emit_always(cmd_id, sm, EdrCmdExecFailed, 5, "oom"); return; }
  fread(buf, 1, (size_t)fsz, f);
  fclose(f);

  char result[1024];
#ifdef EDR_HAVE_YARA
  /* 真引擎优先：libyara 编译 rules 目录并扫描；不可用（无规则/加载失败）则回退下方子串匹配。 */
  if (fy_scan(target_path, buf, (size_t)fsz, result, sizeof(result))) {
    free(buf);
    edr_cmd_inc_handled();
    edr_cmd_inc_exec_ok();
    edr_command_audit_both(cmd_id, "yara_scan: ok (engine=yara)");
    edr_command_emit_always(cmd_id, sm, EdrCmdExecOk, 0, result);
    return;
  }
#endif
  /* 降级：内置子串匹配（无 libyara 或无规则时）。结果标 engine=builtin 以便区分。 */
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

  if (matches > 0) {
    snprintf(result, sizeof(result), "YARA_HIT path=%s engine=builtin matches=%d patterns=[%s]", target_path, matches, hitBuf);
  } else {
    snprintf(result, sizeof(result), "YARA_CLEAN path=%s engine=builtin", target_path);
  }
  edr_cmd_inc_handled(); edr_cmd_inc_exec_ok();
  edr_command_audit_both(cmd_id, "yara_scan: ok (engine=builtin)");
  edr_command_emit_always(cmd_id, sm, EdrCmdExecOk, 0, result);
}
