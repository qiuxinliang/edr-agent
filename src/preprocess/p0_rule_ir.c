#include "edr/p0_rule_ir.h"

#include "edr/behavior_record.h"
#include "cJSON.h"

/* pcre2.h 要求：在包含前设定宽度；本文件使用 8 位 API（与 PCRE2_UCHAR8 / char* 一致） */
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#include <ctype.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(EDR_P0_IR_HAS_EMBED) && EDR_P0_IR_HAS_EMBED
extern const unsigned char edr_p0_rule_ir_embed_bytes[];
extern const size_t edr_p0_rule_ir_embed_len;
#endif

#if defined(_WIN32)
#include <windows.h>
#else
#include <limits.h>
#include <unistd.h>
#if defined(__linux__)
#include <linux/limits.h>
#include <sys/stat.h>
#endif
#if !defined(_WIN32)
#include <unistd.h>
#endif
#endif

#define P0_IR_NAME_IN_MAX 24
#define P0_IR_PAT 40
#define P0_IR_ID_MAX 64
#define P0_IR_RULES_MAX 80
#define P0_IR_STR 512

struct p0_ir_one {
  char id[P0_IR_ID_MAX];
  char title[P0_IR_STR];
  char mitre_csv[P0_IR_STR];
  char event_type[48];
  int chain_gt; /* 0 = unset */
  int n_name_in;
  char name_in[P0_IR_NAME_IN_MAX][128];
  int n_parent_in;
  char parent_in[P0_IR_NAME_IN_MAX][128];
  pcre2_code *re_cmd_any[P0_IR_PAT];
  int n_cmd_any;
  pcre2_code *re_cmd_all[P0_IR_PAT];
  int n_cmd_all;
  pcre2_code *re_pn_rx[P0_IR_PAT];
  int n_pn_rx;
  pcre2_code *re_pr_rx[P0_IR_PAT];
  int n_pr_rx;
  pcre2_code *re_fpath[P0_IR_PAT];
  int n_fpath;
  int rport[64];
  int n_rport;
  pcre2_code *re_regpath[P0_IR_PAT];
  int n_regpath;
  char reg_name_in[P0_IR_NAME_IN_MAX][128];
  int n_reg_name;
  char reg_data_in[P0_IR_NAME_IN_MAX][256];
  int n_reg_data;
  int in_use;
};

static struct p0_ir_one s_rule[P0_IR_RULES_MAX];
static int s_n;
static int s_inited; /* 1 tried */
static int s_ready;

static void ascii_lower_truncate(char *dst, size_t cap, const char *src) {
  size_t i = 0;
  if (!dst || cap == 0) {
    return;
  }
  dst[0] = 0;
  if (!src) {
    return;
  }
  for (; *src && i + 1 < cap; src++) {
    char c = *src;
    if (c >= 'A' && c <= 'Z') {
      c = (char)(c - 'A' + 'a');
    }
    dst[i++] = c;
  }
  dst[i] = 0;
}

static const char *basename_slash(const char *lower_path) {
  if (!lower_path) {
    return "";
  }
  const char *s = lower_path;
  const char *last = s;
  for (; *s; s++) {
    if (*s == '/' || *s == '\\') {
      last = s + 1;
    }
  }
  return last;
}

static int name_in_list(const char *full_lower, const char (*list)[128], int n) {
  int i;
  for (i = 0; i < n; i++) {
    if (strcmp(full_lower, list[i]) == 0) {
      return 1;
    }
  }
  const char *base = basename_slash(full_lower);
  for (i = 0; i < n; i++) {
    if (strcmp(base, list[i]) == 0) {
      return 1;
    }
  }
  return 0;
}

static int pcre2_ok_one(const pcre2_code *re, const char *s) {
  PCRE2_SIZE sl = s ? strlen(s) : 0;
  pcre2_match_data *md = pcre2_match_data_create_from_pattern((pcre2_code *)re, NULL);
  if (!md) {
    return 0;
  }
  int rc = pcre2_match(
      (pcre2_code *)re, (PCRE2_SPTR) s, sl, 0, 0, md, NULL
  );
  pcre2_match_data_free(md);
  return (rc >= 0) ? 1 : 0;
}

static int any_pcre(pcre2_code *const *res, int n, const char *s) {
  int i;
  for (i = 0; i < n; i++) {
    if (res[i] && pcre2_ok_one(res[i], s)) {
      return 1;
    }
  }
  return 0;
}

static int all_pcre(pcre2_code *const *res, int n, const char *s) {
  int i;
  for (i = 0; i < n; i++) {
    if (!res[i] || !pcre2_ok_one(res[i], s)) {
      return 0;
    }
  }
  return 1;
}

static pcre2_code *compile_pat(const char *pat, char *err, size_t errcap) {
  if (!pat || !*pat) {
    return NULL;
  }
  int ecode;
  PCRE2_SIZE eoff;
  pcre2_code *re = pcre2_compile((PCRE2_SPTR) pat, PCRE2_ZERO_TERMINATED, PCRE2_UTF, &ecode, &eoff, NULL);
  if (!re) {
    PCRE2_UCHAR8 buf[256];
    pcre2_get_error_message(ecode, buf, sizeof(buf));
    if (err && errcap) {
      snprintf(err, errcap, "pcre2_compile: %s (offset %zu)", (char *)buf, (size_t)eoff);
    }
  }
  (void)err;
  (void)errcap;
  return re;
}

static void add_str_array(
    cJSON *cond, const char *key, char out[][128], int *pn, int maxn, int munge_lower) {
  cJSON *a = cJSON_GetObjectItemCaseSensitive(cond, key);
  if (!cJSON_IsArray(a)) {
    return;
  }
  cJSON *it;
  cJSON_ArrayForEach(it, a) {
    if (*pn >= maxn) {
      break;
    }
    if (cJSON_IsString(it) && it->valuestring) {
      if (munge_lower) {
        ascii_lower_truncate(out[*pn], 128, it->valuestring);
      } else {
        snprintf(out[*pn], 128, "%s", it->valuestring);
      }
      (*pn)++;
    }
  }
}

static void add_rx_array(
    cJSON *cond, const char *key, pcre2_code *out[], int *pn, int maxn, const char *ctx) {
  cJSON *a = cJSON_GetObjectItemCaseSensitive(cond, key);
  if (!cJSON_IsArray(a)) {
    return;
  }
  cJSON *it;
  cJSON_ArrayForEach(it, a) {
    if (*pn >= maxn) {
      break;
    }
    if (cJSON_IsString(it) && it->valuestring) {
      char emsg[200];
      pcre2_code *re = compile_pat(it->valuestring, emsg, sizeof(emsg));
      if (re) {
        out[(*pn)++] = re;
      } else {
        fprintf(
            stderr, "[p0_rule_ir] skip bad regex in %s: %s err=%s\n", ctx, it->valuestring, emsg
        );
      }
    }
  }
}

static void p0_ir_free_pcre_in_rule(struct p0_ir_one *r) {
  int i;
  if (!r) {
    return;
  }
  for (i = 0; i < P0_IR_PAT; i++) {
    if (r->re_cmd_any[i]) {
      pcre2_code_free((pcre2_code *)r->re_cmd_any[i]);
      r->re_cmd_any[i] = NULL;
    }
    if (r->re_cmd_all[i]) {
      pcre2_code_free((pcre2_code *)r->re_cmd_all[i]);
      r->re_cmd_all[i] = NULL;
    }
    if (r->re_pn_rx[i]) {
      pcre2_code_free((pcre2_code *)r->re_pn_rx[i]);
      r->re_pn_rx[i] = NULL;
    }
    if (r->re_pr_rx[i]) {
      pcre2_code_free((pcre2_code *)r->re_pr_rx[i]);
      r->re_pr_rx[i] = NULL;
    }
    if (r->re_fpath[i]) {
      pcre2_code_free((pcre2_code *)r->re_fpath[i]);
      r->re_fpath[i] = NULL;
    }
    if (r->re_regpath[i]) {
      pcre2_code_free((pcre2_code *)r->re_regpath[i]);
      r->re_regpath[i] = NULL;
    }
  }
}

static void add_int_array(cJSON *cond, const char *key, int *out, int *pn, int maxn) {
  cJSON *a = cJSON_GetObjectItemCaseSensitive(cond, key);
  if (!cJSON_IsArray(a)) {
    return;
  }
  cJSON *it;
  cJSON_ArrayForEach(it, a) {
    if (*pn >= maxn) {
      break;
    }
    if (cJSON_IsNumber(it)) {
      int v = (int)it->valuedouble;
      out[(*pn)++] = v;
    }
  }
}

static void add_reg_data_substrings_munge(
    cJSON *cond, const char *key, char out[][256], int *pn, int maxn) {
  cJSON *a = cJSON_GetObjectItemCaseSensitive(cond, key);
  if (!cJSON_IsArray(a)) {
    return;
  }
  cJSON *it;
  cJSON_ArrayForEach(it, a) {
    if (*pn >= maxn) {
      break;
    }
    if (cJSON_IsString(it) && it->valuestring) {
      ascii_lower_truncate(out[*pn], 256, it->valuestring);
      (*pn)++;
    }
  }
}

static int read_full_file(const char *path, char **out, size_t *out_len) {
  FILE *f = fopen(path, "rb");
  if (!f) {
    return 0;
  }
  if (fseek(f, 0, SEEK_END) != 0) {
    fclose(f);
    return 0;
  }
  long sz = ftell(f);
  if (sz < 0 || sz > 4 * 1024 * 1024) {
    fclose(f);
    return 0;
  }
  rewind(f);
  char *b = (char *)malloc((size_t)sz + 1u);
  if (!b) {
    fclose(f);
    return 0;
  }
  size_t n = fread(b, 1, (size_t)sz, f);
  fclose(f);
  b[n] = 0;
  *out = b;
  *out_len = n;
  return 1;
}

#if defined(_WIN32)
static int edr_win_exe_dir(char *out, size_t cap) {
  wchar_t wpath[MAX_PATH];
  DWORD n = GetModuleFileNameW(NULL, wpath, MAX_PATH);
  if (n == 0 || n >= MAX_PATH) {
    return 0;
  }
  wchar_t *slash = wcsrchr(wpath, L'\\');
  if (!slash) {
    slash = wcsrchr(wpath, L'/');
  }
  if (!slash) {
    return 0;
  }
  *slash = 0;
  if (WideCharToMultiByte(CP_UTF8, 0, wpath, -1, out, (int)cap, NULL, NULL) <= 1) {
    return 0;
  }
  return 1;
}
#endif

#if !defined(_WIN32)
static int try_linux_proc_exe(char *out, size_t cap) {
#if defined(__linux__)
  char buf[4096];
  ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf) - 1u);
  if (n <= 0) {
    return 0;
  }
  buf[n] = 0;
  char *sl = strrchr(buf, '/');
  if (!sl) {
    return 0;
  }
  *sl = 0;
  if ((size_t)snprintf(out, cap, "%s/edr_config/p0_rule_bundle_ir_v1.json", buf) >= cap) {
    return 0;
  }
  return access(out, R_OK) == 0 ? 1 : 0;
#else
  (void)out;
  (void)cap;
  return 0;
#endif
}
#endif

static int build_default_path(char *out, size_t cap) {
  const char *e = getenv("EDR_P0_IR_PATH");
  if (e && *e) {
    snprintf(out, cap, "%s", e);
    return 1;
  }
#if defined(_WIN32)
  char ex[1024];
  if (!edr_win_exe_dir(ex, sizeof(ex))) {
    return 0;
  }
  snprintf(out, cap, "%s\\edr_config\\p0_rule_bundle_ir_v1.json", ex);
  return 1;
#else
  if (try_linux_proc_exe(out, cap)) {
    return 1;
  }
  /* 开发/ctest：CWD 下 edr_config/ */
  if ((size_t)snprintf(out, cap, "edr_config/p0_rule_bundle_ir_v1.json") < cap &&
      access(out, R_OK) == 0) {
    return 1;
  }
  return 0;
#endif
}

static int one_rule_match_process(
    const struct p0_ir_one *r, const char *process_name, const char *cmdline, const char *parent_name, int pchain) {
  const char *cmd = cmdline ? cmdline : "";
  const char *par = parent_name ? parent_name : "";
  char pnlow[1024];
  char prlow[1024];
  ascii_lower_truncate(pnlow, sizeof(pnlow), process_name);
  ascii_lower_truncate(prlow, sizeof(prlow), par);

  if (r->chain_gt > 0) {
    if (pchain == 0 || pchain <= r->chain_gt) {
      return 0;
    }
  }
  if (r->n_name_in > 0) {
    if (!name_in_list(pnlow, (const char (*)[128])r->name_in, r->n_name_in)) {
      return 0;
    }
  }
  if (r->n_parent_in > 0) {
    if (!par[0] || !name_in_list(prlow, (const char (*)[128])r->parent_in, r->n_parent_in)) {
      return 0;
    }
  }
  if (r->n_pn_rx > 0) {
    if (!any_pcre((pcre2_code *const *)r->re_pn_rx, r->n_pn_rx, process_name ? process_name : "")) {
      return 0;
    }
  }
  if (r->n_pr_rx > 0) {
    if (!any_pcre((pcre2_code *const *)r->re_pr_rx, r->n_pr_rx, par)) {
      return 0;
    }
  }
  if (r->n_cmd_all > 0) {
    if (!all_pcre((pcre2_code *const *)r->re_cmd_all, r->n_cmd_all, cmd)) {
      return 0;
    }
  }
  if (r->n_cmd_any > 0) {
    if (!any_pcre((pcre2_code *const *)r->re_cmd_any, r->n_cmd_any, cmd)) {
      return 0;
    }
  }
  return 1;
}

static int one_rule_match_file(const struct p0_ir_one *r, const EdrBehaviorRecord *br) {
  const char *cmd = br->cmdline[0] ? br->cmdline : "";
  const char *par = br->parent_name[0] ? br->parent_name : "";
  char pnlow[1024];
  char prlow[1024];
  ascii_lower_truncate(pnlow, sizeof(pnlow), br->process_name);
  ascii_lower_truncate(prlow, sizeof(prlow), par);
  if (r->n_name_in > 0) {
    if (!name_in_list(pnlow, (const char (*)[128])r->name_in, r->n_name_in)) {
      return 0;
    }
  }
  if (r->n_parent_in > 0) {
    if (!par[0] || !name_in_list(prlow, (const char (*)[128])r->parent_in, r->n_parent_in)) {
      return 0;
    }
  }
  if (r->n_pr_rx > 0) {
    if (!any_pcre((pcre2_code *const *)r->re_pr_rx, r->n_pr_rx, br->parent_name)) {
      return 0;
    }
  }
  if (r->n_pn_rx > 0) {
    if (!any_pcre((pcre2_code *const *)r->re_pn_rx, r->n_pn_rx, br->process_name)) {
      return 0;
    }
  }
  if (r->n_cmd_all > 0) {
    if (!all_pcre((pcre2_code *const *)r->re_cmd_all, r->n_cmd_all, cmd)) {
      return 0;
    }
  }
  if (r->n_cmd_any > 0) {
    if (!any_pcre((pcre2_code *const *)r->re_cmd_any, r->n_cmd_any, cmd)) {
      return 0;
    }
  }
  if (r->n_fpath > 0) {
    if (!any_pcre(
            (pcre2_code *const *)r->re_fpath, r->n_fpath, br->file_path[0] ? br->file_path : ""
        )) {
      return 0;
    }
  }
  return 1;
}

static int one_rule_match_net(const struct p0_ir_one *r, const EdrBehaviorRecord *br) {
  if (r->n_rport > 0) {
    int ok = 0;
    int i;
    for (i = 0; i < r->n_rport; i++) {
      if ((uint32_t)r->rport[i] == br->net_dport) {
        ok = 1;
        break;
      }
    }
    if (!ok) {
      return 0;
    }
  }
  if (r->n_fpath > 0) {
    const char *aux = br->network_aux_path[0] ? br->network_aux_path : "";
    if (!any_pcre((pcre2_code *const *)r->re_fpath, r->n_fpath, aux)) {
      return 0;
    }
  }
  return 1;
}

static void lower_inplace_buf(char *buf, size_t cap) {
  size_t i;
  for (i = 0; i + 1 < cap && buf[i]; i++) {
    char c = buf[i];
    if (c >= 'A' && c <= 'Z') {
      buf[i] = (char)(c - 'A' + 'a');
    }
  }
}

static int reg_name_exact_fold(
    const char *name, const char name_in_list[][128], int n_name) {
  char low[512];
  ascii_lower_truncate(low, sizeof(low), name);
  int i;
  for (i = 0; i < n_name; i++) {
    if (strcmp(low, name_in_list[i]) == 0) {
      return 1;
    }
  }
  return 0;
}

static int reg_data_substring_any(
    const char *data, const char subs[][256], int n_sub) {
  char hay[10240];
  size_t l = 0;
  if (data) {
    l = strnlen(data, sizeof(hay) - 1u);
  }
  memcpy(hay, data ? data : "", l);
  hay[l] = 0;
  lower_inplace_buf(hay, sizeof(hay));
  int j;
  for (j = 0; j < n_sub; j++) {
    if (subs[j][0] && strstr(hay, subs[j]) != NULL) {
      return 1;
    }
  }
  return 0;
}

static int one_rule_match_registry(const struct p0_ir_one *r, const EdrBehaviorRecord *br) {
  const char *path = br->reg_key_path[0] ? br->reg_key_path : "";
  if (r->n_regpath > 0) {
    if (!any_pcre((pcre2_code *const *)r->re_regpath, r->n_regpath, path)) {
      return 0;
    }
  }
  if (r->n_reg_name > 0) {
    if (!reg_name_exact_fold(br->reg_value_name, r->reg_name_in, r->n_reg_name)) {
      return 0;
    }
  }
  if (r->n_reg_data > 0) {
    if (!reg_data_substring_any(br->reg_value_data, r->reg_data_in, r->n_reg_data)) {
      return 0;
    }
  }
  return 1;
}

static int p0_br_wants_event_type(EdrEventType t, const char *et) {
  if (!et) {
    return 0;
  }
  if (strcmp(et, "process_create") == 0) {
    return t == EDR_EVENT_PROCESS_CREATE ? 1 : 0;
  }
  if (strcmp(et, "file_read") == 0) {
    return t == EDR_EVENT_FILE_READ ? 1 : 0;
  }
  if (strcmp(et, "file_write") == 0) {
    return (t == EDR_EVENT_FILE_WRITE || t == EDR_EVENT_FILE_CREATE || t == EDR_EVENT_FILE_DELETE ||
            t == EDR_EVENT_FILE_RENAME || t == EDR_EVENT_FILE_PERMISSION_CHANGE)
               ? 1
               : 0;
  }
  if (strcmp(et, "network_connect") == 0) {
    /* 与平台 `network_connect` 同构：含出站连接与 **监听绑定**（TCPIP 等 → `NET_LISTEN`） */
    return (t == EDR_EVENT_NET_CONNECT || t == EDR_EVENT_NET_LISTEN) ? 1 : 0;
  }
  if (strcmp(et, "registry_set") == 0) {
    return (t == EDR_EVENT_REG_SET_VALUE || t == EDR_EVENT_REG_CREATE_KEY || t == EDR_EVENT_REG_DELETE_KEY)
               ? 1
               : 0;
  }
  return 0;
}

static int p0_rule_has_constraints(const char *et, const struct p0_ir_one *r) {
  if (!r || !et) {
    return 0;
  }
  if (strcmp(et, "process_create") == 0) {
    return r->n_name_in > 0 || r->n_parent_in > 0 || r->n_pn_rx > 0 || r->n_pr_rx > 0 || r->n_cmd_any > 0 ||
           r->n_cmd_all > 0 || r->chain_gt > 0;
  }
  if (strcmp(et, "file_read") == 0 || strcmp(et, "file_write") == 0) {
    return r->n_fpath > 0 || r->n_pn_rx > 0 || r->n_cmd_any > 0 || r->n_cmd_all > 0 || r->n_name_in > 0 ||
           r->n_parent_in > 0 || r->n_pr_rx > 0;
  }
  if (strcmp(et, "network_connect") == 0) {
    return r->n_rport > 0 || r->n_fpath > 0;
  }
  if (strcmp(et, "registry_set") == 0) {
    return r->n_regpath > 0 || r->n_reg_name > 0 || r->n_reg_data > 0;
  }
  return 0;
}

static int p0_ir_match_rule_to_br(const struct p0_ir_one *r, const EdrBehaviorRecord *br) {
  if (!r || !br) {
    return 0;
  }
  if (strcmp(r->event_type, "process_create") == 0) {
    return one_rule_match_process(
        r, br->process_name, br->cmdline, br->parent_name[0] ? br->parent_name : NULL, (int)br->process_chain_depth
    );
  }
  if (strcmp(r->event_type, "file_read") == 0 || strcmp(r->event_type, "file_write") == 0) {
    return one_rule_match_file(r, br);
  }
  if (strcmp(r->event_type, "network_connect") == 0) {
    return one_rule_match_net(r, br);
  }
  if (strcmp(r->event_type, "registry_set") == 0) {
    return one_rule_match_registry(r, br);
  }
  return 0;
}

/**
 * 从已解析的 JSON 文本加载；成功且至少一条可求值规则时 s_ready=1。每次入口清空 s_n。
 */
static int p0_ir_load_from_json_text(const char *source_label, const char *data, size_t data_len) {
  s_n = 0;
  s_ready = 0;
  cJSON *root = cJSON_ParseWithLength(data, data_len);
  if (!root) {
    fprintf(stderr, "[p0_rule_ir] JSON parse failed: %s\n", source_label);
    return 0;
  }
  cJSON *rules = cJSON_GetObjectItemCaseSensitive(root, "rules");
  if (!cJSON_IsArray(rules)) {
    cJSON_Delete(root);
    fprintf(stderr, "[p0_rule_ir] top-level 'rules' missing or not array: %s\n", source_label);
    return 0;
  }
  cJSON *rnode;
  cJSON_ArrayForEach(rnode, rules) {
    if (s_n >= P0_IR_RULES_MAX) {
      break;
    }
    if (!cJSON_IsObject(rnode)) {
      continue;
    }
    cJSON *jid = cJSON_GetObjectItemCaseSensitive(rnode, "id");
    cJSON *jet = cJSON_GetObjectItemCaseSensitive(rnode, "event_type");
    if (!cJSON_IsString(jid) || !jid->valuestring) {
      continue;
    }
    if (!cJSON_IsString(jet) || !jet->valuestring) {
      continue;
    }
    char etbuf[64];
    {
      const char *et = jet->valuestring;
      int k;
      for (k = 0; et[k] && k < (int)sizeof(etbuf) - 1; k++) {
        char c = (char)et[k];
        etbuf[k] = (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : c;
      }
      etbuf[k] = 0;
    }
    if (strcmp(etbuf, "process_create") != 0 && strcmp(etbuf, "file_read") != 0 &&
        strcmp(etbuf, "file_write") != 0 && strcmp(etbuf, "network_connect") != 0 &&
        strcmp(etbuf, "registry_set") != 0) {
      continue;
    }
    struct p0_ir_one t;
    memset(&t, 0, sizeof(t));
    snprintf(t.id, sizeof(t.id), "%s", jid->valuestring);
    snprintf(t.event_type, sizeof(t.event_type), "%s", etbuf);
    cJSON *jtit = cJSON_GetObjectItemCaseSensitive(rnode, "title");
    if (cJSON_IsString(jtit) && jtit->valuestring) {
      snprintf(t.title, sizeof(t.title), "%s", jtit->valuestring);
    }
    cJSON *jmit = cJSON_GetObjectItemCaseSensitive(rnode, "mitre_ttps");
    t.mitre_csv[0] = 0;
    if (cJSON_IsArray(jmit)) {
      size_t o = 0;
      cJSON *mit_it;
      cJSON_ArrayForEach(mit_it, jmit) {
        if (cJSON_IsString(mit_it) && mit_it->valuestring && o + 1 < sizeof(t.mitre_csv)) {
          if (o) {
            t.mitre_csv[o++] = ',';
          }
          size_t l = strnlen(mit_it->valuestring, 64);
          if (o + l < sizeof(t.mitre_csv)) {
            memcpy(t.mitre_csv + o, mit_it->valuestring, l);
            o += l;
            t.mitre_csv[o] = 0;
          }
        }
      }
    }
    cJSON *jcond = cJSON_GetObjectItemCaseSensitive(rnode, "condition");
    if (!cJSON_IsObject(jcond)) {
      continue;
    }
    if (strcmp(etbuf, "process_create") == 0) {
      add_str_array(
          jcond, "process_name_in", t.name_in, &t.n_name_in, P0_IR_NAME_IN_MAX, 1
      );
      add_str_array(
          jcond, "parent_name_in", t.parent_in, &t.n_parent_in, P0_IR_NAME_IN_MAX, 1
      );
      add_rx_array(
          jcond, "command_regex_any", t.re_cmd_any, &t.n_cmd_any, P0_IR_PAT, jid->valuestring
      );
      add_rx_array(
          jcond, "command_regex_all", t.re_cmd_all, &t.n_cmd_all, P0_IR_PAT, jid->valuestring
      );
      add_rx_array(
          jcond, "process_name_regex_any", t.re_pn_rx, &t.n_pn_rx, P0_IR_PAT, jid->valuestring
      );
      add_rx_array(
          jcond, "parent_name_regex_any", t.re_pr_rx, &t.n_pr_rx, P0_IR_PAT, jid->valuestring
      );
      cJSON *jdepth = cJSON_GetObjectItemCaseSensitive(jcond, "process_chain_depth_gt");
      if (cJSON_IsNumber(jdepth)) {
        int d = (int)jdepth->valuedouble;
        t.chain_gt = d > 0 ? d : 0;
      }
    } else if (strcmp(etbuf, "file_read") == 0 || strcmp(etbuf, "file_write") == 0) {
      add_str_array(
          jcond, "process_name_in", t.name_in, &t.n_name_in, P0_IR_NAME_IN_MAX, 1
      );
      add_str_array(
          jcond, "parent_name_in", t.parent_in, &t.n_parent_in, P0_IR_NAME_IN_MAX, 1
      );
      add_rx_array(
          jcond, "command_regex_any", t.re_cmd_any, &t.n_cmd_any, P0_IR_PAT, jid->valuestring
      );
      add_rx_array(
          jcond, "command_regex_all", t.re_cmd_all, &t.n_cmd_all, P0_IR_PAT, jid->valuestring
      );
      add_rx_array(
          jcond, "process_name_regex_any", t.re_pn_rx, &t.n_pn_rx, P0_IR_PAT, jid->valuestring
      );
      add_rx_array(
          jcond, "parent_name_regex_any", t.re_pr_rx, &t.n_pr_rx, P0_IR_PAT, jid->valuestring
      );
      add_rx_array(
          jcond, "file_path_regex_any", t.re_fpath, &t.n_fpath, P0_IR_PAT, jid->valuestring
      );
    } else if (strcmp(etbuf, "network_connect") == 0) {
      add_int_array(jcond, "remote_port_in", t.rport, &t.n_rport, 64);
      add_rx_array(
          jcond, "file_path_regex_any", t.re_fpath, &t.n_fpath, P0_IR_PAT, jid->valuestring
      );
    } else if (strcmp(etbuf, "registry_set") == 0) {
      add_rx_array(
          jcond, "registry_path_regex_any", t.re_regpath, &t.n_regpath, P0_IR_PAT, jid->valuestring
      );
      add_str_array(
          jcond, "registry_value_name_in", t.reg_name_in, &t.n_reg_name, P0_IR_NAME_IN_MAX, 1
      );
      add_reg_data_substrings_munge(
          jcond, "registry_value_data_in", t.reg_data_in, &t.n_reg_data, P0_IR_NAME_IN_MAX
      );
    }
    if (!p0_rule_has_constraints(etbuf, &t)) {
      p0_ir_free_pcre_in_rule(&t);
      continue;
    }
    t.in_use = 1;
    s_rule[s_n++] = t;
  }
  cJSON_Delete(root);
  if (s_n > 0) {
    s_ready = 1;
    fprintf(
        stderr, "[p0_rule_ir] loaded %d P0 rules (process/file/net/registry) from %s\n", s_n, source_label
    );
    return 1;
  }
  fprintf(stderr, "[p0_rule_ir] no loadable P0 rules in %s\n", source_label);
  return 0;
}

void edr_p0_rule_ir_lazy_init(void) {
  if (s_inited) {
    return;
  }
  s_inited = 1;
  int loaded = 0;
  char path[2048];
  char *buf = NULL;
  size_t blen = 0;
  if (build_default_path(path, sizeof(path))) {
    if (read_full_file(path, &buf, &blen)) {
      loaded = p0_ir_load_from_json_text(path, buf, blen) ? 1 : 0;
      free(buf);
    } else {
      fprintf(stderr, "[p0_rule_ir] cannot read %s\n", path);
    }
  } else {
    fprintf(
        stderr,
        "[p0_rule_ir] no file path (set EDR_P0_IR_PATH or place edr_config next to exe); trying "
        "fallback\n"
    );
  }
#if defined(EDR_P0_IR_HAS_EMBED) && EDR_P0_IR_HAS_EMBED
  if (!loaded) {
    loaded = p0_ir_load_from_json_text(
        "embedded: p0_rule_bundle_ir_v1.json", (const char *)edr_p0_rule_ir_embed_bytes,
        edr_p0_rule_ir_embed_len
    );
  }
#endif
  if (!loaded) {
    fprintf(
        stderr,
        "[p0_rule_ir] not loaded: no readable IR file and no embed (install edr_config JSON or build "
        "with EDR_P0_IR_EMBED)\n"
    );
  }
}

int edr_p0_rule_ir_is_ready(void) { return s_ready; }

int edr_p0_rule_ir_matches(const char *rule_id, const char *process_name, const char *cmdline,
                           const char *parent_name, int process_chain_depth) {
  int i;
  if (!rule_id || !s_ready) {
    return 0;
  }
  for (i = 0; i < s_n; i++) {
    if (strcmp(s_rule[i].id, rule_id) != 0) {
      continue;
    }
    if (!s_rule[i].in_use) {
      return 0;
    }
    if (strcmp(s_rule[i].event_type, "process_create") != 0) {
      return 0;
    }
    return one_rule_match_process(
               &s_rule[i], process_name, cmdline, parent_name, process_chain_depth
           )
             ? 1
             : 0;
  }
  return 0;
}

int edr_p0_rule_ir_get_meta(
    const char *rule_id, const char **out_title, const char **out_mitre) {
  int i;
  if (out_title) {
    *out_title = NULL;
  }
  if (out_mitre) {
    *out_mitre = NULL;
  }
  if (!rule_id || !s_ready) {
    return 0;
  }
  for (i = 0; i < s_n; i++) {
    if (strcmp(s_rule[i].id, rule_id) == 0 && s_rule[i].in_use) {
      if (out_title) {
        *out_title = s_rule[i].title[0] ? s_rule[i].title : s_rule[i].id;
      }
      if (out_mitre) {
        *out_mitre = s_rule[i].mitre_csv;
      }
      return 1;
    }
  }
  return 0;
}

int edr_p0_rule_ir_process_create_count(void) {
  int c = 0;
  int i;
  for (i = 0; i < s_n; i++) {
    if (strcmp(s_rule[i].event_type, "process_create") == 0) {
      c++;
    }
  }
  return c;
}

int edr_p0_rule_ir_process_create_id_at(int index, const char **out_id) {
  int k = 0;
  int i;
  if (index < 0 || !out_id) {
    return 0;
  }
  for (i = 0; i < s_n; i++) {
    if (strcmp(s_rule[i].event_type, "process_create") != 0) {
      continue;
    }
    if (k == index) {
      *out_id = s_rule[i].id;
      return 1;
    }
    k++;
  }
  return 0;
}

int edr_p0_rule_ir_rule_count(void) { return s_n; }

int edr_p0_rule_ir_rule_id_at(int index, const char **out_id) {
  if (index < 0 || index >= s_n || !out_id) {
    return 0;
  }
  *out_id = s_rule[index].id;
  return 1;
}

int edr_p0_rule_ir_br_matches_index(const EdrBehaviorRecord *br, int index) {
  if (!br || index < 0 || index >= s_n || !s_rule[index].in_use) {
    return 0;
  }
  if (!p0_br_wants_event_type(br->type, s_rule[index].event_type)) {
    return 0;
  }
  return p0_ir_match_rule_to_br(&s_rule[index], br) ? 1 : 0;
}
