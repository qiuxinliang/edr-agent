#include "edr/shellcode_known.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef EDR_HAVE_YARA
#include <yara.h>
#if defined(_WIN32)
#include <windows.h>
#else
#include <dirent.h>
#endif
#endif

#define EDR_RULE_NAME_MAX 96u

static EdrShellcodeRulesStatus s_rules_status = {
    "builtin", "builtin-embedded", "", 0u, 0u, 0, 0u, 0, 0, "", 0u, 0u, 0u, 0u, "", ""};

static unsigned long env_ulong(const char *name, unsigned long defv, unsigned long maxv) {
  const char *s = getenv(name);
  if (!s || !s[0]) {
    return defv;
  }
  char *end = NULL;
  unsigned long v = strtoul(s, &end, 10);
  if (end == s) {
    return defv;
  }
  return v > maxv ? maxv : v;
}

static void refresh_ops_policy(void) {
  s_rules_status.gray_percent = (uint32_t)env_ulong("EDR_SHELLCODE_RULES_GRAY_PERCENT", s_rules_status.gray_percent, 100u);
  const char *rb = getenv("EDR_SHELLCODE_RULES_ROLLBACK_VERSION");
  if (rb && rb[0]) {
    snprintf(s_rules_status.rollback_version, sizeof(s_rules_status.rollback_version), "%s", rb);
    s_rules_status.rollback_available = 1;
  }
  const char *ra = getenv("EDR_SHELLCODE_RULES_ROLLBACK");
  s_rules_status.rollback_active = (ra && ra[0] == '1') ? 1 : 0;
}

static uint32_t stable_bucket(const char *s) {
  uint32_t h = 2166136261u;
  if (!s) {
    s = "";
  }
  for (; *s; s++) {
    h ^= (unsigned char)*s;
    h *= 16777619u;
  }
  return h % 100u;
}

static void note_match(const char *source, const char *rule) {
  refresh_ops_policy();
  s_rules_status.matches_total++;
  if (source && strcmp(source, "yara") == 0) {
    s_rules_status.yara_matches++;
  } else {
    s_rules_status.builtin_matches++;
  }
  snprintf(s_rules_status.last_match_source, sizeof(s_rules_status.last_match_source), "%s", source ? source : "");
  snprintf(s_rules_status.last_match_rule, sizeof(s_rules_status.last_match_rule), "%s", rule ? rule : "");
  if (s_rules_status.gray_percent > 0u && stable_bucket(rule) < s_rules_status.gray_percent) {
    s_rules_status.gray_shadow_matches++;
  }
}

#ifdef EDR_HAVE_YARA
typedef struct {
  char first_rule[EDR_RULE_NAME_MAX];
  int matched;
} YaraScanResult;

static YR_RULES *s_yara_rules;
static int s_yara_initialized;
static uint64_t s_yara_last_reload_unix_s;
#endif

static bool has_subseq(const uint8_t *data, uint32_t len, const uint8_t *pat, size_t pat_len) {
  if (!data || !pat || pat_len == 0u || len < pat_len) {
    return false;
  }
  for (uint32_t i = 0; i + pat_len <= len; i++) {
    if (memcmp(data + i, pat, pat_len) == 0) {
      return true;
    }
  }
  return false;
}

static bool has_ascii(const uint8_t *data, uint32_t len, const char *s) {
  if (!s) {
    return false;
  }
  return has_subseq(data, len, (const uint8_t *)s, strlen(s));
}

static bool has_run(const uint8_t *data, uint32_t len, uint8_t v, uint32_t run_len) {
  if (!data || run_len == 0u || len < run_len) {
    return false;
  }
  uint32_t cur = 0;
  for (uint32_t i = 0; i < len; i++) {
    if (data[i] == v) {
      cur++;
      if (cur >= run_len) {
        return true;
      }
    } else {
      cur = 0;
    }
  }
  return false;
}

static void set_rule_name(char *out, size_t cap, const char *name) {
  if (!out || cap == 0u) {
    return;
  }
  snprintf(out, cap, "%s", name ? name : "");
}

static int match_smb1_eternalblue(const uint8_t *data, uint32_t len) {
  static const uint8_t kDoublePulsar[] = {0x81u, 0xF1u, 0x13u, 0x00u, 0x00u, 0x00u, 0x49u};
  static const uint8_t kTail0500[] = {0x05u, 0x00u};
  if (has_subseq(data, len, kDoublePulsar, sizeof(kDoublePulsar))) {
    return 1;
  }
  if (has_run(data, len, 0x00u, 32u) && has_subseq(data, len, kTail0500, sizeof(kTail0500))) {
    return 1;
  }
  return 0;
}

static int match_rdp_bluekeep(const uint8_t *data, uint32_t len) {
  static const uint8_t kAbnormalChan[] = {0x1Fu, 0x00u};
  return (has_ascii(data, len, "MS_T120") && has_subseq(data, len, kAbnormalChan, sizeof(kAbnormalChan)) &&
          has_run(data, len, 0x41u, 16u))
             ? 1
             : 0;
}

static int match_msrpc_printnightmare(const uint8_t *data, uint32_t len) {
  static const uint8_t kOpnum89[] = {0x59u, 0x00u, 0x00u, 0x00u};
  static const uint8_t kUncWide[] = {0x5Cu, 0x00u, 0x5Cu, 0x00u};
  static const uint8_t kRprnUuidLike[] = {
      0x12u, 0x34u, 0x56u, 0x78u, 0x12u, 0x34u, 0xABu, 0xCDu, 0xEFu, 0x00u, 0x01u, 0x23u, 0x45u, 0x67u, 0x89u,
      0xABu};
  return (has_subseq(data, len, kRprnUuidLike, sizeof(kRprnUuidLike)) &&
          has_subseq(data, len, kOpnum89, sizeof(kOpnum89)) && has_subseq(data, len, kUncWide, sizeof(kUncWide)))
             ? 1
             : 0;
}

static int match_smb3_smbghost(const uint8_t *data, uint32_t len) {
  static const uint8_t kCompressedSmb3[] = {0xFCu, 0x53u, 0x4Du, 0x42u};
  static const uint8_t kInvalidOriginalSize[] = {0xFFu, 0xFFu, 0xFFu, 0xFFu};
  static const uint8_t kLargeOffset[] = {0x00u, 0x10u, 0x00u, 0x00u};
  return (has_subseq(data, len, kCompressedSmb3, sizeof(kCompressedSmb3)) &&
          (has_subseq(data, len, kInvalidOriginalSize, sizeof(kInvalidOriginalSize)) ||
           has_subseq(data, len, kLargeOffset, sizeof(kLargeOffset))) &&
          (has_run(data, len, 0x41u, 24u) || has_run(data, len, 0x90u, 16u)))
             ? 1
             : 0;
}

static int match_http_reflective_loader_stager(const uint8_t *data, uint32_t len) {
  return ((has_ascii(data, len, "ReflectiveLoader") || has_ascii(data, len, "beacon.x64") ||
           has_ascii(data, len, "beacon.x86") || has_ascii(data, len, "metsrv.dll")) &&
          (has_ascii(data, len, "MZ") || has_run(data, len, 0x90u, 16u)))
             ? 1
             : 0;
}

static int match_ms17_010_doublepulsar_ping(const uint8_t *data, uint32_t len) {
  static const uint8_t kTrans2SessionSetup[] = {0x32u, 0x00u, 0x00u, 0x00u};
  static const uint8_t kMultiplexId[] = {0x51u, 0x00u};
  return (has_subseq(data, len, kTrans2SessionSetup, sizeof(kTrans2SessionSetup)) &&
          has_subseq(data, len, kMultiplexId, sizeof(kMultiplexId)) && has_run(data, len, 0x00u, 24u))
             ? 1
             : 0;
}

#ifdef EDR_HAVE_YARA
static void status_set_error(const char *msg) {
  snprintf(s_rules_status.last_error, sizeof(s_rules_status.last_error), "%s", msg ? msg : "");
}

static void read_rules_version(const char *rules_dir, char *out, size_t cap) {
  if (!out || cap == 0u) {
    return;
  }
  out[0] = '\0';
  const char *env = getenv("EDR_SHELLCODE_YARA_RULES_VERSION");
  if (env && env[0]) {
    snprintf(out, cap, "%s", env);
    return;
  }
  if (!rules_dir || !rules_dir[0]) {
    return;
  }
  char path[1024];
#if defined(_WIN32)
  snprintf(path, sizeof(path), "%s\\VERSION", rules_dir);
#else
  snprintf(path, sizeof(path), "%s/VERSION", rules_dir);
#endif
  FILE *fp = fopen(path, "rb");
  if (!fp) {
    return;
  }
  if (fgets(out, (int)cap, fp) == NULL) {
    out[0] = '\0';
  }
  fclose(fp);
  out[cap - 1u] = '\0';
  for (size_t i = 0; out[i]; i++) {
    if (out[i] == '\r' || out[i] == '\n') {
      out[i] = '\0';
      break;
    }
  }
}

static int is_rule_file_path(const char *path) {
  const char *dot = strrchr(path, '.');
  if (!dot) {
    return 0;
  }
  return (strcmp(dot, ".yar") == 0 || strcmp(dot, ".yara") == 0) ? 1 : 0;
}

static void compiler_error_cb(int err_level, const char *file_name, int line_number, const YR_RULE *rule,
                              const char *message, void *user_data) {
  (void)rule;
  (void)user_data;
  /* YARA 对短/低熵 atom 会发 WARNING（不影响加载），与真正的 ERROR 区分，避免误读为失败。 */
  const char *level = (err_level == YARA_ERROR_LEVEL_WARNING) ? "warning" : "error";
  fprintf(stderr, "[shellcode_detector] yara compile %s file=%s line=%d msg=%s\n", level,
          file_name ? file_name : "-", line_number, message ? message : "-");
}

#if defined(YR_VERSION_HEX) && YR_VERSION_HEX >= 0x040500
static int scan_cb(YR_SCAN_CONTEXT *context, int message, void *message_data, void *user_data) {
  (void)context;
#else
static int scan_cb(int message, void *message_data, void *user_data) {
#endif
  YaraScanResult *res = (YaraScanResult *)user_data;
  if (!res) {
    return CALLBACK_CONTINUE;
  }
  if (message == CALLBACK_MSG_RULE_MATCHING) {
    const YR_RULE *rule = (const YR_RULE *)message_data;
    if (rule && !res->matched) {
      set_rule_name(res->first_rule, sizeof(res->first_rule), rule->identifier);
      res->matched = 1;
    }
    return CALLBACK_ABORT;
  }
  return CALLBACK_CONTINUE;
}

static int add_rule_file(YR_COMPILER *c, const char *path) {
  FILE *fp = fopen(path, "rb");
  if (!fp) {
    fprintf(stderr, "[shellcode_detector] yara open failed: %s\n", path);
    return 0;
  }
  int nerr = yr_compiler_add_file(c, fp, NULL, path);
  fclose(fp);
  if (nerr > 0) {
    return 0;
  }
  return 1;
}

#if defined(_WIN32)
static int add_rules_from_dir(YR_COMPILER *c, const char *rules_dir) {
  char pattern[1024];
  snprintf(pattern, sizeof(pattern), "%s\\*.*", rules_dir);
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
    if (!is_rule_file_path(ffd.cFileName)) {
      continue;
    }
    char full[1024];
    snprintf(full, sizeof(full), "%s\\%s", rules_dir, ffd.cFileName);
    loaded += add_rule_file(c, full);
  } while (FindNextFileA(h, &ffd));
  FindClose(h);
  return loaded;
}
#else
static int add_rules_from_dir(YR_COMPILER *c, const char *rules_dir) {
  DIR *d = opendir(rules_dir);
  if (!d) {
    return 0;
  }
  int loaded = 0;
  for (;;) {
    struct dirent *ent = readdir(d);
    if (!ent) {
      break;
    }
    if (ent->d_name[0] == '.') {
      continue;
    }
    if (!is_rule_file_path(ent->d_name)) {
      continue;
    }
    char full[1024];
    snprintf(full, sizeof(full), "%s/%s", rules_dir, ent->d_name);
    loaded += add_rule_file(c, full);
  }
  closedir(d);
  return loaded;
}
#endif

/** 成功返回加载文件数；0=目录无有效规则（不替换已有）；-1=编译失败（保留旧规则） */
static int shellcode_yara_replace_rules(const char *rules_dir) {
  YR_COMPILER *c = NULL;
  if (yr_compiler_create(&c) != ERROR_SUCCESS || !c) {
    fprintf(stderr, "[shellcode_detector] yara compiler create failed\n");
    return -1;
  }
  yr_compiler_set_callback(c, compiler_error_cb, NULL);
  int loaded = add_rules_from_dir(c, rules_dir);
  if (loaded <= 0) {
    yr_compiler_destroy(c);
    return 0;
  }
  YR_RULES *rules = NULL;
  if (yr_compiler_get_rules(c, &rules) != ERROR_SUCCESS || !rules) {
    yr_compiler_destroy(c);
    fprintf(stderr, "[shellcode_detector] yara get rules failed, keeping previous rules if any\n");
    return -1;
  }
  yr_compiler_destroy(c);
  if (s_yara_rules) {
    yr_rules_destroy(s_yara_rules);
  }
  s_yara_rules = rules;
  return loaded;
}
#endif

int edr_shellcode_known_init(const char *rules_dir) {
  memset(&s_rules_status, 0, sizeof(s_rules_status));
  snprintf(s_rules_status.source, sizeof(s_rules_status.source), "%s", "builtin");
  snprintf(s_rules_status.version, sizeof(s_rules_status.version), "%s", "builtin-embedded");
  refresh_ops_policy();
  if (s_rules_status.rollback_active) {
    if (s_rules_status.rollback_version[0]) {
      snprintf(s_rules_status.version, sizeof(s_rules_status.version), "%s", s_rules_status.rollback_version);
    }
    snprintf(s_rules_status.last_error, sizeof(s_rules_status.last_error), "%s", "rules_rollback_active");
    return 0;
  }
#ifdef EDR_HAVE_YARA
  if (!rules_dir || !rules_dir[0]) {
    return 0;
  }
  s_rules_status.yara_enabled = 1;
  if (!s_yara_initialized) {
    if (yr_initialize() != ERROR_SUCCESS) {
      fprintf(stderr, "[shellcode_detector] yara initialize failed, fallback to builtin matcher\n");
      status_set_error("yara_initialize_failed");
      return -1;
    }
    s_yara_initialized = 1;
  }
  int loaded = shellcode_yara_replace_rules(rules_dir);
  if (loaded < 0) {
    status_set_error("yara_compile_failed");
    return -1;
  }
  if (loaded == 0) {
    fprintf(stderr, "[shellcode_detector] no yara rules loaded from %s, fallback to builtin matcher\n", rules_dir);
    status_set_error("no_yara_rules_loaded");
    return 0;
  }
  s_yara_last_reload_unix_s = (uint64_t)time(NULL);
  snprintf(s_rules_status.source, sizeof(s_rules_status.source), "%s", "yara");
  read_rules_version(rules_dir, s_rules_status.version, sizeof(s_rules_status.version));
  if (!s_rules_status.version[0]) {
    snprintf(s_rules_status.version, sizeof(s_rules_status.version), "yara-files-%d", loaded);
  }
  s_rules_status.files_loaded = (uint32_t)loaded;
  s_rules_status.last_reload_unix_s = s_yara_last_reload_unix_s;
  status_set_error("");
  fprintf(stderr, "[shellcode_detector] yara rules loaded=%d dir=%s\n", loaded, rules_dir);
#else
  (void)rules_dir;
#endif
  return 0;
}

void edr_shellcode_known_reload_periodic(const char *rules_dir, uint32_t interval_s) {
  refresh_ops_policy();
  if (s_rules_status.rollback_active) {
    return;
  }
#ifdef EDR_HAVE_YARA
  if (!rules_dir || !rules_dir[0] || interval_s == 0u || !s_yara_initialized) {
    return;
  }
  uint64_t now = (uint64_t)time(NULL);
  if (s_yara_last_reload_unix_s != 0u && (now - s_yara_last_reload_unix_s) < (uint64_t)interval_s) {
    return;
  }
  int loaded = shellcode_yara_replace_rules(rules_dir);
  if (loaded > 0) {
    s_yara_last_reload_unix_s = now;
    snprintf(s_rules_status.source, sizeof(s_rules_status.source), "%s", "yara");
    read_rules_version(rules_dir, s_rules_status.version, sizeof(s_rules_status.version));
    if (!s_rules_status.version[0]) {
      snprintf(s_rules_status.version, sizeof(s_rules_status.version), "yara-files-%d", loaded);
    }
    s_rules_status.files_loaded = (uint32_t)loaded;
    s_rules_status.last_reload_unix_s = now;
    status_set_error("");
    fprintf(stderr, "[shellcode_detector] yara rules hot-reloaded files=%d\n", loaded);
  } else if (loaded < 0) {
    status_set_error("hot_reload_compile_failed");
  }
#else
  (void)rules_dir;
  (void)interval_s;
#endif
}

void edr_shellcode_known_get_status(EdrShellcodeRulesStatus *out) {
  if (!out) {
    return;
  }
  refresh_ops_policy();
  *out = s_rules_status;
}

void edr_shellcode_known_shutdown(void) {
#ifdef EDR_HAVE_YARA
  if (s_yara_rules) {
    yr_rules_destroy(s_yara_rules);
    s_yara_rules = NULL;
  }
  if (s_yara_initialized) {
    yr_finalize();
    s_yara_initialized = 0;
  }
#endif
}

int edr_shellcode_match_known_exploit(const uint8_t *data, uint32_t len, EdrProtoKind kind, char *rule_name_out,
                                      size_t rule_name_cap) {
  if (!data || len == 0u || !rule_name_out || rule_name_cap == 0u) {
    return 0;
  }
  rule_name_out[0] = '\0';

#ifdef EDR_HAVE_YARA
  if (s_yara_rules) {
    YaraScanResult res;
    memset(&res, 0, sizeof(res));
    if (yr_rules_scan_mem(s_yara_rules, data, len, 0, scan_cb, &res, 0) == ERROR_SUCCESS && res.matched) {
      set_rule_name(rule_name_out, rule_name_cap, res.first_rule);
      note_match("yara", res.first_rule);
      return 1;
    }
  }
#endif

  if (kind == EDR_PROTO_KIND_SMB1 && match_smb1_eternalblue(data, len)) {
    set_rule_name(rule_name_out, rule_name_cap, "EternalBlue_MS17_010");
    note_match("builtin", rule_name_out);
    return 1;
  }
  if (kind == EDR_PROTO_KIND_SMB1 && match_ms17_010_doublepulsar_ping(data, len)) {
    set_rule_name(rule_name_out, rule_name_cap, "DoublePulsar_MS17_010_Ping");
    note_match("builtin", rule_name_out);
    return 1;
  }
  if ((kind == EDR_PROTO_KIND_UNKNOWN || kind == EDR_PROTO_KIND_SMB2) && match_smb3_smbghost(data, len)) {
    set_rule_name(rule_name_out, rule_name_cap, "SMBGhost_CVE_2020_0796");
    note_match("builtin", rule_name_out);
    return 1;
  }
  if (kind == EDR_PROTO_KIND_RDP && match_rdp_bluekeep(data, len)) {
    set_rule_name(rule_name_out, rule_name_cap, "BlueKeep_CVE_2019_0708");
    note_match("builtin", rule_name_out);
    return 1;
  }
  if ((kind == EDR_PROTO_KIND_UNKNOWN || kind == EDR_PROTO_KIND_SMB2) && match_msrpc_printnightmare(data, len)) {
    set_rule_name(rule_name_out, rule_name_cap, "PrintNightmare_CVE_2021_34527");
    note_match("builtin", rule_name_out);
    return 1;
  }
  if ((kind == EDR_PROTO_KIND_UNKNOWN || kind == EDR_PROTO_KIND_HTTP) && match_http_reflective_loader_stager(data, len)) {
    set_rule_name(rule_name_out, rule_name_cap, "ReflectiveLoader_HTTP_Stager");
    note_match("builtin", rule_name_out);
    return 1;
  }
  return 0;
}
