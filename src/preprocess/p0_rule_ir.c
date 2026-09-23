#include "edr/p0_rule_ir.h"

#include "edr/preprocess.h"
#include "edr/behavior_record.h"
#include "edr/encrypt_p0_rules.h"
#include "edr/sha256.h"
#include "cJSON.h"

/* pcre2.h 要求：在包含前设定宽度；本文件使用 8 位 API（与 PCRE2_UCHAR8 / char* 一致） */
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#include <ctype.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <windows.h>
static SRWLOCK s_ir_snapshot_lock = SRWLOCK_INIT;
static void ir_write_lock(void) { AcquireSRWLockExclusive(&s_ir_snapshot_lock); }
static void ir_write_unlock(void) { ReleaseSRWLockExclusive(&s_ir_snapshot_lock); }
/* Candidate preparation mutates the parser's private target indirection.  It
 * deliberately is not the snapshot/pair lock: disk I/O, decrypt, JSON and
 * PCRE2 compilation must never hold the reader path used by ETW admission. */
static SRWLOCK s_ir_publication_lock = SRWLOCK_INIT;
static void p0_ir_publication_lock(void) { AcquireSRWLockExclusive(&s_ir_publication_lock); }
static void p0_ir_publication_unlock(void) { ReleaseSRWLockExclusive(&s_ir_publication_lock); }
static SRWLOCK s_ir_sensor_pair_lock = SRWLOCK_INIT;
static void p0_ir_sensor_pair_write_lock(void) { AcquireSRWLockExclusive(&s_ir_sensor_pair_lock); }
static void p0_ir_sensor_pair_write_unlock(void) { ReleaseSRWLockExclusive(&s_ir_sensor_pair_lock); }
void edr_p0_rule_ir_sensor_admission_lock(void) { AcquireSRWLockShared(&s_ir_sensor_pair_lock); }
void edr_p0_rule_ir_sensor_admission_unlock(void) { ReleaseSRWLockShared(&s_ir_sensor_pair_lock); }
#else
#include <pthread.h>
static pthread_rwlock_t s_ir_snapshot_lock = PTHREAD_RWLOCK_INITIALIZER;
static void ir_write_lock(void) { (void)pthread_rwlock_wrlock(&s_ir_snapshot_lock); }
static void ir_write_unlock(void) { (void)pthread_rwlock_unlock(&s_ir_snapshot_lock); }
static pthread_mutex_t s_ir_publication_lock = PTHREAD_MUTEX_INITIALIZER;
static void p0_ir_publication_lock(void) { (void)pthread_mutex_lock(&s_ir_publication_lock); }
static void p0_ir_publication_unlock(void) { (void)pthread_mutex_unlock(&s_ir_publication_lock); }
static pthread_rwlock_t s_ir_sensor_pair_lock = PTHREAD_RWLOCK_INITIALIZER;
static void p0_ir_sensor_pair_write_lock(void) { (void)pthread_rwlock_wrlock(&s_ir_sensor_pair_lock); }
static void p0_ir_sensor_pair_write_unlock(void) { (void)pthread_rwlock_unlock(&s_ir_sensor_pair_lock); }
void edr_p0_rule_ir_sensor_admission_lock(void) { (void)pthread_rwlock_rdlock(&s_ir_sensor_pair_lock); }
void edr_p0_rule_ir_sensor_admission_unlock(void) { (void)pthread_rwlock_unlock(&s_ir_sensor_pair_lock); }
#endif

#if defined(EDR_P0_IR_HAS_EMBED) && EDR_P0_IR_HAS_EMBED
extern const unsigned char edr_p0_rule_ir_embed_bytes[];
extern const size_t edr_p0_rule_ir_embed_len;
#endif

#if defined(_WIN32)
#include <windows.h>
#include <wchar.h>
#else
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>
#if defined(__linux__)
#include <linux/limits.h>
#include <sys/stat.h>
#endif
#if !defined(_WIN32)
#include <unistd.h>
#endif
#endif

#define P0_IR_REG_DWORD_MAX 8
#define P0_IR_NAME_IN_MAX 24
#define P0_IR_PAT 40
#define P0_IR_ID_MAX 64
#define P0_IR_STR 512
#define P0_IR_SENSOR_INTEREST_HASH_MODE "raw-json-v1-p0-artifact-sha256-zeroed"

struct p0_ir_registry_dword {
  pcre2_code *path;
  char name[128];
  uint32_t value;
};

struct p0_ir_one {
  char id[P0_IR_ID_MAX];
  char title[P0_IR_STR];
  char mitre_csv[P0_IR_STR];
  char event_type[48];
  int severity;
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
  pcre2_code *re_ppath_rx[P0_IR_PAT];
  int n_ppath_rx;
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
  struct p0_ir_registry_dword reg_dword[P0_IR_REG_DWORD_MAX];
  int n_reg_dword;
  int in_use;
};

typedef struct p0_ir_candidate {
  struct p0_ir_one rule[EDR_P0_RULE_IR_MAX_RULES];
  int n;
  int ready;
  char source_label[1024];
  size_t plain_size;
  char plain_sha256[65];
  char rules_bundle_version[128];
  uint32_t declared_rule_count;
  char sensor_interest_manifest_sha256[65];
  char sensor_interest_manifest_hash_mode[64];
  uint64_t epoch;
  /* Readers keep a counted reference after the active pointer is swapped. */
  unsigned int readers;
  int retired;
  uint64_t rule_evaluate_count[EDR_P0_RULE_IR_MAX_RULES];
  uint64_t rule_hit_count[EDR_P0_RULE_IR_MAX_RULES];
} p0_ir_candidate;

/* Candidate construction is performed while holding the writer lock.  This
 * keeps the parser's existing target indirection private to the writer while
 * readers use a counted immutable snapshot. */
static p0_ir_candidate *s_active_candidate;
static p0_ir_candidate *s_load_target;
static uint64_t s_next_snapshot_epoch;
#define s_rule (s_load_target->rule)
#define s_n (s_load_target->n)
#define s_ready (s_load_target->ready)
#define s_source_label (s_load_target->source_label)
#define s_plain_size (s_load_target->plain_size)
#define s_plain_sha256 (s_load_target->plain_sha256)
#define s_rules_bundle_version (s_load_target->rules_bundle_version)
#define s_declared_rule_count (s_load_target->declared_rule_count)
#define s_sensor_interest_manifest_sha256 (s_load_target->sensor_interest_manifest_sha256)
#define s_sensor_interest_manifest_hash_mode (s_load_target->sensor_interest_manifest_hash_mode)
static int s_inited; /* guarded by s_ir_snapshot_lock */
/* Set only when a durable artifact journal cannot establish either the old
 * generation or a committed new generation.  This is a capability failure,
 * not a transient parse error: active P0 authority is retired until a later
 * verified publication succeeds. */
enum {
  P0_IR_ARTIFACT_UNHEALTHY_IR = 1u << 0,
  P0_IR_ARTIFACT_UNHEALTHY_SENSOR = 1u << 1
};
static unsigned int s_artifact_terminal_unhealthy_mask; /* guarded by s_ir_snapshot_lock */
static char s_artifact_terminal_reason[96];
/* Only accessed under s_ir_publication_lock while a candidate is prepared. */
static int s_publication_recovery_failed;
/* Guarded by s_ir_sensor_pair_lock.  A valid SensorInterest snapshot records
 * this value; publishing any IR generation advances it before the pointer
 * swap so stale narrow admission can never overlap the new matcher. */
static uint64_t s_ir_sensor_pair_generation;

uint64_t edr_p0_rule_ir_sensor_admission_generation(void) {
  return s_ir_sensor_pair_generation;
}

static void p0_ir_sensor_pair_advance_locked(void) {
  s_ir_sensor_pair_generation++;
  if (s_ir_sensor_pair_generation == 0u) {
    s_ir_sensor_pair_generation++;
  }
}

#if defined(EDR_P0_RULE_IR_TESTING)
#include <stdatomic.h>
#ifndef ATOMIC_VAR_INIT
#define ATOMIC_VAR_INIT(value) (value)
#endif
static unsigned int s_test_fail_parent_sync_after;
static unsigned int s_test_fail_parent_sync_remaining;
static atomic_int s_test_preparation_pause = ATOMIC_VAR_INIT(0);
static atomic_int s_test_preparation_paused = ATOMIC_VAR_INIT(0);

void edr_p0_rule_ir_test_fail_parent_sync_after(unsigned int nth_call) {
  p0_ir_publication_lock();
  s_test_fail_parent_sync_after = nth_call ? nth_call : 1u;
  s_test_fail_parent_sync_remaining = 1u;
  p0_ir_publication_unlock();
}

void edr_p0_rule_ir_test_fail_parent_sync_after_count(unsigned int nth_call,
                                                       unsigned int count) {
  p0_ir_publication_lock();
  s_test_fail_parent_sync_after = nth_call ? nth_call : 1u;
  s_test_fail_parent_sync_remaining = count ? count : 1u;
  p0_ir_publication_unlock();
}

void edr_p0_rule_ir_test_pause_preparation(int pause) {
  atomic_store_explicit(&s_test_preparation_pause, pause ? 1 : 0, memory_order_release);
}

int edr_p0_rule_ir_test_preparation_paused(void) {
  return atomic_load_explicit(&s_test_preparation_paused, memory_order_acquire);
}

static void p0_ir_test_pause_preparation(void) {
  if (!atomic_load_explicit(&s_test_preparation_pause, memory_order_acquire)) {
    return;
  }
  atomic_store_explicit(&s_test_preparation_paused, 1, memory_order_release);
  while (atomic_load_explicit(&s_test_preparation_pause, memory_order_acquire)) {
#if defined(_WIN32)
    Sleep(1u);
#else
    usleep(1000u);
#endif
  }
  atomic_store_explicit(&s_test_preparation_paused, 0, memory_order_release);
}
#else
static void p0_ir_test_pause_preparation(void) {}
#endif

/* P0规则命中率统计 - 性能优化辅助数据 */
static int s_stats_enabled;

static int p0_ir_load_from_json_text(const char *source_label, const char *data, size_t data_len);
static int try_load_default_paths(void);
#if !defined(_WIN32)
static int p0_ir_journal_recover(const char *destination);
#endif

static void p0_ir_stats_init(void) {
  s_stats_enabled = edr_getenv_int_default("EDR_P0_STATS", 0);
  if (s_stats_enabled) {
    fprintf(stderr, "[p0_rule_ir] stats enabled (EDR_P0_STATS=1)\n");
  }
}

static p0_ir_candidate *p0_ir_snapshot_acquire(void);
static void p0_ir_snapshot_release(p0_ir_candidate *snapshot);

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

static int p0_ir_hex64(const char *value) {
  size_t i;
  if (!value || strlen(value) != 64u) {
    return 0;
  }
  for (i = 0u; i < 64u; ++i) {
    char c = value[i];
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
      return 0;
    }
  }
  return 1;
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
      /* The caller carries a 200-byte durable diagnostic. PCRE2 may return
       * a 255-byte message, so preserve a clearly marked bounded prefix and
       * the exact offset instead of relying on implicit snprintf truncation. */
      snprintf(err, errcap, "pcre2_compile: %.120s... (offset %zu)", (char *)buf, (size_t)eoff);
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
    cJSON *cond, const char *key, pcre2_code *out[], int *pn, int maxn, const char *ctx,
    int *parse_ok) {
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
            stderr, "[p0_rule_ir] invalid regex in %s: %s err=%s\n", ctx, it->valuestring, emsg
        );
        if (parse_ok) {
          *parse_ok = 0;
        }
        return;
      }
    }
  }
}

static void add_reg_dword(cJSON *condition, struct p0_ir_one *rule, int *parse_ok) {
  cJSON *branches = cJSON_GetObjectItemCaseSensitive(condition, "registry_dword_any");
  cJSON *branch;
  if (!branches) return;
  cJSON_ArrayForEach(branch, branches) {
    char error[200];
    cJSON *path = cJSON_GetObjectItemCaseSensitive(branch, "path_regex");
    cJSON *name = cJSON_GetObjectItemCaseSensitive(branch, "value_name");
    cJSON *value = cJSON_GetObjectItemCaseSensitive(branch, "value");
    struct p0_ir_registry_dword *predicate = &rule->reg_dword[rule->n_reg_dword];
    predicate->path = compile_pat(path->valuestring, error, sizeof(error));
    if (!predicate->path) {
      fprintf(stderr, "[p0_rule_ir] invalid registry_dword_any path in %s: %s\n", rule->id, error);
      *parse_ok = 0;
      return;
    }
    ascii_lower_truncate(predicate->name, sizeof(predicate->name), name->valuestring);
    predicate->value = (uint32_t)value->valuedouble;
    ++rule->n_reg_dword;
  }
}

static void p0_ir_free_pcre_in_rule(struct p0_ir_one *r) {
  int i;
  if (!r) {
    return;
  }
  for (i = 0; i < r->n_reg_dword; ++i) {
    pcre2_code_free(r->reg_dword[i].path);
    r->reg_dword[i].path = NULL;
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
    if (r->re_ppath_rx[i]) {
      pcre2_code_free((pcre2_code *)r->re_ppath_rx[i]);
      r->re_ppath_rx[i] = NULL;
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
  /* EDR1 input is bounded independently from its plaintext.  AES-GCM adds
   * exactly EDR_P0_ENCRYPT_OVERHEAD bytes, so the published plaintext limit
   * is deliberately lower than the 4 MiB envelope limit. */
  if (sz < 0 || (size_t)sz > EDR_P0_ENCRYPT_ENVELOPE_MAX_BYTES) {
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

  if (edr_p0_encrypt_is_edr1((const uint8_t *)b, n)) {
    uint8_t *plain = NULL;
    size_t plain_len = 0;
    int dr = edr_p0_encrypt_decrypt_edr1((const uint8_t *)b, n, &plain, &plain_len);
    free(b);
    if (dr != 0) {
      fprintf(stderr, "[p0_rule_ir] decrypt %s failed: %d\n", path, dr);
      return 0;
    }
    if (plain_len > EDR_P0_ENCRYPT_PLAINTEXT_MAX_BYTES) {
      free(plain);
      fprintf(stderr, "[p0_rule_ir] decrypt %s exceeds plaintext envelope contract\n", path);
      return 0;
    }
    *out = (char *)plain;
    *out_len = plain_len;
    return 1;
  }

  if (n > EDR_P0_ENCRYPT_PLAINTEXT_MAX_BYTES) {
    free(b);
    return 0;
  }

  b[n] = 0;
  *out = b;
  *out_len = n;
  return 1;
}

static int file_readable(const char *path) {
  if (!path || !path[0]) {
    return 0;
  }
  FILE *f = fopen(path, "rb");
  if (!f) {
    return 0;
  }
  fclose(f);
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
  if ((size_t)snprintf(out, cap, "%s/edr_config/p0_rule_bundle_ir_v1.json.enc", buf) >= cap) {
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

static int try_load_ir_path(const char *path) {
  if (!path || !path[0]) {
    return 0;
  }
#if !defined(_WIN32)
  if (p0_ir_journal_recover(path) < 0) {
    s_publication_recovery_failed = 1;
    fprintf(stderr, "[p0_rule_ir] artifact journal recovery failed for %s\n", path);
    return 0;
  }
#endif
  char *buf = NULL;
  size_t blen = 0;
  if (!read_full_file(path, &buf, &blen)) {
    fprintf(stderr, "[p0_rule_ir] cannot read %s\n", path);
    return 0;
  }
  int loaded = p0_ir_load_from_json_text(path, buf, blen) ? 1 : 0;
  free(buf);
  return loaded;
}

static int p0_ir_path_or_recovery_journal_present(const char *path) {
  if (file_readable(path)) return 1;
#if !defined(_WIN32)
  {
    char journal[PATH_MAX];
    int n;
    if (!path || !path[0]) return 0;
    n = snprintf(journal, sizeof(journal), "%s.p0txn", path);
    return n >= 0 && (size_t)n < sizeof(journal) && access(journal, F_OK) == 0;
  }
#else
  return 0;
#endif
}

static void p0_ir_candidate_destroy(p0_ir_candidate *candidate) {
  int i;
  if (!candidate) return;
  for (i = 0; i < candidate->n; ++i) {
    p0_ir_free_pcre_in_rule(&candidate->rule[i]);
  }
  memset(candidate, 0, sizeof(*candidate));
}

static p0_ir_candidate *p0_ir_snapshot_acquire(void) {
  p0_ir_candidate *snapshot;
  /* A writer lock makes incrementing the reader count portable even on
   * toolchains that do not provide C11 atomics.  It is held only long enough
   * to retain the immutable object. */
  ir_write_lock();
  snapshot = s_active_candidate;
  if (snapshot) {
    snapshot->readers++;
  }
  ir_write_unlock();
  return snapshot;
}

static void p0_ir_snapshot_release(p0_ir_candidate *snapshot) {
  int destroy = 0;
  if (!snapshot) {
    return;
  }
  ir_write_lock();
  if (snapshot->readers > 0) {
    snapshot->readers--;
  }
  if (snapshot->retired && snapshot->readers == 0) {
    destroy = 1;
  }
  ir_write_unlock();
  if (destroy) {
    p0_ir_candidate_destroy(snapshot);
    free(snapshot);
  }
}

static void p0_ir_snapshot_retire_locked(p0_ir_candidate *snapshot, int *destroy) {
  if (!snapshot) {
    return;
  }
  snapshot->retired = 1;
  if (snapshot->readers == 0) {
    *destroy = 1;
  }
}

static uint64_t p0_ir_next_epoch_locked(void) {
  s_next_snapshot_epoch++;
  if (s_next_snapshot_epoch == 0u) {
    s_next_snapshot_epoch++;
  }
  return s_next_snapshot_epoch;
}

/* Caller holds the publication mutex.  Advancing the pair generation before
 * retiring the active authority makes every SensorInterest reader fail-full
 * immediately; direct emission sees no active IR and cannot enforce. */
static void p0_ir_mark_artifact_terminal_unhealthy(const char *reason) {
  p0_ir_candidate *previous;
  int destroy_previous = 0;
  p0_ir_sensor_pair_write_lock();
  ir_write_lock();
  previous = s_active_candidate;
  p0_ir_sensor_pair_advance_locked();
  s_active_candidate = NULL;
  s_inited = 1;
  s_artifact_terminal_unhealthy_mask |= P0_IR_ARTIFACT_UNHEALTHY_IR;
  snprintf(s_artifact_terminal_reason, sizeof(s_artifact_terminal_reason), "%s",
           reason && reason[0] ? reason : "artifact_journal_recovery_failed");
  p0_ir_snapshot_retire_locked(previous, &destroy_previous);
  ir_write_unlock();
  p0_ir_sensor_pair_write_unlock();
  if (destroy_previous) {
    p0_ir_candidate_destroy(previous);
    free(previous);
  }
}

static void p0_ir_clear_ir_artifact_terminal_unhealthy_locked(void) {
  s_artifact_terminal_unhealthy_mask &= ~P0_IR_ARTIFACT_UNHEALTHY_IR;
  if (s_artifact_terminal_unhealthy_mask == 0u) {
    s_artifact_terminal_reason[0] = '\0';
  }
}

/* The following helpers require s_ir_publication_lock.  Parsing still uses
 * s_load_target for the long-standing field macros, but that target is now
 * private to publication work and never protected by the ETW reader locks. */
static int p0_ir_candidate_load_path_locked(p0_ir_candidate *candidate, const char *path) {
  p0_ir_candidate *previous;
  int loaded;
  if (!candidate || !path || !path[0]) return 0;
  p0_ir_test_pause_preparation();
  s_publication_recovery_failed = 0;
  p0_ir_candidate_destroy(candidate);
  previous = s_load_target;
  s_load_target = candidate;
  loaded = try_load_ir_path(path);
  s_load_target = previous;
  if (!loaded) p0_ir_candidate_destroy(candidate);
  return loaded;
}

static int p0_ir_candidate_load_default_paths_locked(p0_ir_candidate *candidate) {
  p0_ir_candidate *previous;
  int loaded;
  if (!candidate) return 0;
  p0_ir_test_pause_preparation();
  s_publication_recovery_failed = 0;
  p0_ir_candidate_destroy(candidate);
  previous = s_load_target;
  s_load_target = candidate;
  loaded = try_load_default_paths();
  s_load_target = previous;
  if (!loaded) p0_ir_candidate_destroy(candidate);
  return loaded;
}

#if defined(EDR_P0_IR_HAS_EMBED) && EDR_P0_IR_HAS_EMBED
static int p0_ir_candidate_load_json_locked(p0_ir_candidate *candidate,
                                             const char *source_label,
                                             const char *data,
                                             size_t data_len) {
  p0_ir_candidate *previous;
  int loaded;
  if (!candidate) return 0;
  p0_ir_candidate_destroy(candidate);
  previous = s_load_target;
  s_load_target = candidate;
  loaded = p0_ir_load_from_json_text(source_label, data, data_len);
  s_load_target = previous;
  if (!loaded) p0_ir_candidate_destroy(candidate);
  return loaded;
}
#endif

int edr_p0_rule_ir_validate_candidate_path(const char *path) {
  p0_ir_candidate *candidate = (p0_ir_candidate *)calloc(1, sizeof(*candidate));
  int ok;
  if (!candidate) {
    return 0;
  }
  p0_ir_publication_lock();
  ok = p0_ir_candidate_load_path_locked(candidate, path);
  p0_ir_publication_unlock();
  p0_ir_candidate_destroy(candidate);
  free(candidate);
  return ok;
}

static int p0_ir_sync_staged_file(const char *path) {
#ifdef _WIN32
  HANDLE file;
  DWORD error;
  if (!path || !path[0]) return 0;
  /* FlushFileBuffers requires a handle opened with GENERIC_WRITE.  A
   * read-only handle made every otherwise-valid Windows hot publication fail
   * before MoveFileExA could durably replace the active IR artifact. */
  file = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL,
                     OPEN_EXISTING, 0, NULL);
  if (file == INVALID_HANDLE_VALUE) {
    error = GetLastError();
    fprintf(stderr,
            "[p0_rule_ir] staged bundle durability open failed path=%s win32_error=%lu\n",
            path, (unsigned long)error);
    return 0;
  }
  if (!FlushFileBuffers(file)) {
    error = GetLastError();
    CloseHandle(file);
    fprintf(stderr,
            "[p0_rule_ir] staged bundle durability sync failed path=%s win32_error=%lu\n",
            path, (unsigned long)error);
    return 0;
  }
  if (!CloseHandle(file)) {
    error = GetLastError();
    fprintf(stderr,
            "[p0_rule_ir] staged bundle durability close failed path=%s win32_error=%lu\n",
            path, (unsigned long)error);
    return 0;
  }
  return 1;
#else
  int fd;
  if (!path || !path[0]) return 0;
  fd = open(path, O_RDONLY);
  if (fd < 0) return 0;
  if (fsync(fd) != 0) {
    (void)close(fd);
    return 0;
  }
  return close(fd) == 0 ? 1 : 0;
#endif
}

/* p0_ir_replace_file returns 1 only after the new bytes and a committed
 * recovery journal are durable.  0 means the old generation is confirmed
 * durable; -1 means neither generation can be proven and the caller must
 * fail closed instead of retaining an in-memory authority for a divergent
 * on-disk artifact. */
#ifdef _WIN32
static int p0_ir_replace_file(const char *staged_path, const char *destination_path) {
  return MoveFileExA(staged_path, destination_path,
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) ? 1 : 0;
}
#else
#define P0_IR_ARTIFACT_JOURNAL_VERSION "edr-p0-artifact-journal-v1"
#define P0_IR_ARTIFACT_JOURNAL_PREPARED "prepared"
#define P0_IR_ARTIFACT_JOURNAL_COMMITTED "committed"

typedef struct p0_ir_artifact_journal {
  int had_old;
  char phase[16];
  char old_sha256[65];
  char new_sha256[65];
} p0_ir_artifact_journal;

static int p0_ir_parent_dir(const char *path, char *out, size_t cap) {
  size_t len;
  if (!path || !path[0] || !out || cap == 0u) return 0;
  len = strlen(path);
  if (len + 1u > cap) return 0;
  memcpy(out, path, len + 1u);
  while (len > 0u && out[len - 1u] != '/') len--;
  if (len == 0u) return snprintf(out, cap, "%s", ".") > 0;
  if (len == 1u) {
    out[1] = '\0';
  } else {
    out[len - 1u] = '\0';
  }
  return 1;
}

static int p0_ir_sync_parent_dir(const char *parent) {
  int fd;
  int ok;
  if (!parent || !parent[0]) return 0;
#if defined(EDR_P0_RULE_IR_TESTING)
  if (s_test_fail_parent_sync_after > 0u && --s_test_fail_parent_sync_after == 0u) {
    if (s_test_fail_parent_sync_remaining > 1u) {
      s_test_fail_parent_sync_remaining--;
      s_test_fail_parent_sync_after = 1u;
    } else {
      s_test_fail_parent_sync_after = 0u;
      s_test_fail_parent_sync_remaining = 0u;
    }
    errno = EIO;
    return 0;
  }
#endif
  fd = open(parent, O_RDONLY);
  if (fd < 0) return 0;
  ok = fsync(fd) == 0;
  (void)close(fd);
  return ok;
}

static int p0_ir_file_sha256_raw(const char *path, char out[65], int *exists) {
  struct stat st;
  int fd = -1;
  char *buf = NULL;
  size_t offset = 0u;
  int ok = 0;
  if (!path || !path[0] || !out || !exists) return 0;
  *exists = 0;
  out[0] = '\0';
  if (stat(path, &st) != 0) {
    return errno == ENOENT ? 1 : 0;
  }
  if (!S_ISREG(st.st_mode) || st.st_size < 0 ||
      (uintmax_t)st.st_size > EDR_P0_ENCRYPT_ENVELOPE_MAX_BYTES) {
    return 0;
  }
  *exists = 1;
  fd = open(path, O_RDONLY);
  if (fd < 0) goto done;
  buf = (char *)malloc((size_t)st.st_size + 1u);
  if (!buf) goto done;
  while (offset < (size_t)st.st_size) {
    ssize_t got = read(fd, buf + offset, (size_t)st.st_size - offset);
    if (got <= 0) goto done;
    offset += (size_t)got;
  }
  ok = edr_sha256_hex((const uint8_t *)buf, offset, out) == 0;
done:
  if (fd >= 0) (void)close(fd);
  free(buf);
  return ok;
}

static int p0_ir_journal_paths(const char *destination, char *journal, size_t journal_cap,
                               char *backup, size_t backup_cap, char *temporary,
                               size_t temporary_cap) {
  int n;
  if (!destination || !destination[0]) return 0;
  n = snprintf(journal, journal_cap, "%s.p0txn", destination);
  if (n < 0 || (size_t)n >= journal_cap) return 0;
  n = snprintf(backup, backup_cap, "%s.backup", journal);
  if (n < 0 || (size_t)n >= backup_cap) return 0;
  n = snprintf(temporary, temporary_cap, "%s.tmp", journal);
  return n >= 0 && (size_t)n < temporary_cap;
}

static int p0_ir_journal_format(const p0_ir_artifact_journal *record, char *out, size_t cap) {
  int n;
  if (!record || !out || !record->phase[0] || !p0_ir_hex64(record->new_sha256) ||
      (record->had_old && !p0_ir_hex64(record->old_sha256))) {
    return 0;
  }
  n = snprintf(out, cap,
               P0_IR_ARTIFACT_JOURNAL_VERSION "\nphase=%s\nhad_old=%d\nold_sha256=%s\nnew_sha256=%s\n",
               record->phase, record->had_old ? 1 : 0,
               record->had_old ? record->old_sha256 : "none", record->new_sha256);
  return n >= 0 && (size_t)n < cap;
}

static int p0_ir_journal_write(const char *journal, const char *temporary, const char *parent,
                               const p0_ir_artifact_journal *record) {
  char data[256];
  size_t offset = 0u;
  int fd;
  if (!p0_ir_journal_format(record, data, sizeof(data)) || !journal || !temporary || !parent) {
    return 0;
  }
  (void)unlink(temporary);
  fd = open(temporary, O_CREAT | O_WRONLY | O_TRUNC, 0600);
  if (fd < 0) return 0;
  while (offset < strlen(data)) {
    ssize_t wrote = write(fd, data + offset, strlen(data) - offset);
    if (wrote <= 0) {
      (void)close(fd);
      (void)unlink(temporary);
      return 0;
    }
    offset += (size_t)wrote;
  }
  if (fsync(fd) != 0 || close(fd) != 0 || rename(temporary, journal) != 0 ||
      !p0_ir_sync_parent_dir(parent)) {
    (void)unlink(temporary);
    return 0;
  }
  return 1;
}

static int p0_ir_journal_read(const char *journal, p0_ir_artifact_journal *record) {
  char data[256];
  char expected[256];
  struct stat st;
  int fd;
  ssize_t got;
  int had_old = -1;
  if (!journal || !record) return -1;
  if (stat(journal, &st) != 0) return errno == ENOENT ? 0 : -1;
  if (!S_ISREG(st.st_mode) || st.st_size <= 0 || (size_t)st.st_size >= sizeof(data)) return -1;
  fd = open(journal, O_RDONLY);
  if (fd < 0) return -1;
  got = read(fd, data, (size_t)st.st_size);
  (void)close(fd);
  if (got != st.st_size) return -1;
  data[got] = '\0';
  memset(record, 0, sizeof(*record));
  if (sscanf(data, P0_IR_ARTIFACT_JOURNAL_VERSION "\nphase=%15[^\n]\nhad_old=%d\nold_sha256=%64[^\n]\nnew_sha256=%64[^\n]\n",
             record->phase, &had_old, record->old_sha256, record->new_sha256) != 4 ||
      (had_old != 0 && had_old != 1) ||
      (strcmp(record->phase, P0_IR_ARTIFACT_JOURNAL_PREPARED) != 0 &&
       strcmp(record->phase, P0_IR_ARTIFACT_JOURNAL_COMMITTED) != 0) ||
      !p0_ir_hex64(record->new_sha256) ||
      (had_old && !p0_ir_hex64(record->old_sha256)) ||
      (!had_old && strcmp(record->old_sha256, "none") != 0)) {
    return -1;
  }
  record->had_old = had_old;
  if (!p0_ir_journal_format(record, expected, sizeof(expected)) || strcmp(data, expected) != 0) {
    return -1;
  }
  return 1;
}

static int p0_ir_journal_cleanup(const char *journal, const char *backup, const char *parent) {
  int changed = 0;
  if (unlink(journal) == 0) changed = 1;
  else if (errno != ENOENT) return 0;
  if (unlink(backup) == 0) changed = 1;
  else if (errno != ENOENT) return 0;
  return !changed || p0_ir_sync_parent_dir(parent);
}

static int p0_ir_journal_restore_previous(const char *destination, const char *backup,
                                           const char *parent,
                                           const p0_ir_artifact_journal *record) {
  char restore[PATH_MAX];
  char backup_sha[65];
  int backup_exists;
  int destination_exists;
  if (!destination || !backup || !parent || !record) return 0;
  if (!record->had_old) {
    if (!p0_ir_file_sha256_raw(destination, backup_sha, &destination_exists)) return 0;
    if (!destination_exists) return 1;
    return unlink(destination) == 0 && p0_ir_sync_parent_dir(parent);
  }
  if (!p0_ir_file_sha256_raw(backup, backup_sha, &backup_exists) || !backup_exists ||
      strcmp(backup_sha, record->old_sha256) != 0 ||
      snprintf(restore, sizeof(restore), "%s.restore.%ld", backup, (long)getpid()) < 0) {
    return 0;
  }
  (void)unlink(restore);
  if (link(backup, restore) != 0 || rename(restore, destination) != 0) {
    (void)unlink(restore);
    return 0;
  }
  return p0_ir_sync_parent_dir(parent);
}

/* Return 1 if the disk is now a known legal state, 0 if no journal exists,
 * and -1 when neither old nor committed-new can be proven. */
static int p0_ir_journal_recover(const char *destination) {
  char journal[PATH_MAX];
  char backup[PATH_MAX];
  char temporary[PATH_MAX];
  char parent[PATH_MAX];
  char destination_sha[65];
  int destination_exists;
  int state;
  p0_ir_artifact_journal record;
  if (!p0_ir_parent_dir(destination, parent, sizeof(parent)) ||
      !p0_ir_journal_paths(destination, journal, sizeof(journal), backup, sizeof(backup),
                           temporary, sizeof(temporary))) {
    return -1;
  }
  (void)temporary;
  state = p0_ir_journal_read(journal, &record);
  if (state <= 0) return state;
  if (!p0_ir_file_sha256_raw(destination, destination_sha, &destination_exists)) return -1;
  if (strcmp(record.phase, P0_IR_ARTIFACT_JOURNAL_COMMITTED) == 0) {
    if (!destination_exists || strcmp(destination_sha, record.new_sha256) != 0) return -1;
    (void)p0_ir_journal_cleanup(journal, backup, parent);
    return 1;
  }
  if (record.had_old && destination_exists && strcmp(destination_sha, record.old_sha256) == 0) {
    (void)p0_ir_journal_cleanup(journal, backup, parent);
    return 1;
  }
  if (!record.had_old && !destination_exists) {
    (void)p0_ir_journal_cleanup(journal, backup, parent);
    return 1;
  }
  if ((!destination_exists && record.had_old) ||
      (destination_exists && strcmp(destination_sha, record.new_sha256) != 0)) {
    return -1;
  }
  if (!p0_ir_journal_restore_previous(destination, backup, parent, &record)) return -1;
  if (!p0_ir_journal_cleanup(journal, backup, parent)) return -1;
  return 1;
}

static int p0_ir_replace_file(const char *staged_path, const char *destination_path) {
  char journal[PATH_MAX];
  char backup[PATH_MAX];
  char temporary[PATH_MAX];
  char parent[PATH_MAX];
  char old_sha[65];
  char new_sha[65];
  int old_exists;
  int recovery;
  p0_ir_artifact_journal record;
  if (!staged_path || !destination_path || !destination_path[0] ||
      !p0_ir_parent_dir(destination_path, parent, sizeof(parent)) ||
      !p0_ir_journal_paths(destination_path, journal, sizeof(journal), backup, sizeof(backup),
                           temporary, sizeof(temporary))) {
    return 0;
  }
  recovery = p0_ir_journal_recover(destination_path);
  if (recovery < 0) return -1;
  if (access(journal, F_OK) == 0 || !p0_ir_file_sha256_raw(staged_path, new_sha, &old_exists) ||
      !old_exists || !p0_ir_file_sha256_raw(destination_path, old_sha, &old_exists)) {
    return 0;
  }
  memset(&record, 0, sizeof(record));
  record.had_old = old_exists;
  snprintf(record.phase, sizeof(record.phase), "%s", P0_IR_ARTIFACT_JOURNAL_PREPARED);
  if (old_exists) snprintf(record.old_sha256, sizeof(record.old_sha256), "%s", old_sha);
  snprintf(record.new_sha256, sizeof(record.new_sha256), "%s", new_sha);
  (void)unlink(backup);
  if (old_exists && (link(destination_path, backup) != 0 || !p0_ir_sync_parent_dir(parent))) {
    (void)unlink(backup);
    return 0;
  }
  if (!p0_ir_journal_write(journal, temporary, parent, &record)) {
    return 0;
  }
  if (rename(staged_path, destination_path) != 0 || !p0_ir_sync_parent_dir(parent)) {
    if (!p0_ir_journal_restore_previous(destination_path, backup, parent, &record) ||
        !p0_ir_journal_cleanup(journal, backup, parent)) {
      return -1;
    }
    return 0;
  }
  snprintf(record.phase, sizeof(record.phase), "%s", P0_IR_ARTIFACT_JOURNAL_COMMITTED);
  if (!p0_ir_journal_write(journal, temporary, parent, &record)) {
    /* The caller has not published the candidate.  Restore old bytes even if
     * the commit record may have reached disk, so memory and disk stay one
     * generation until a later fully-confirmed install. */
    if (!p0_ir_journal_restore_previous(destination_path, backup, parent, &record) ||
        !p0_ir_journal_cleanup(journal, backup, parent)) {
      return -1;
    }
    return 0;
  }
  (void)p0_ir_journal_cleanup(journal, backup, parent);
  return 1;
}
#endif

int edr_p0_rule_ir_install_staged_bundle(const char *staged_path, const char *destination_path) {
  p0_ir_candidate *next;
  p0_ir_candidate *previous;
  int destroy_previous = 0;
  int loaded;
  int replace_result = 0;
  if (!staged_path || !staged_path[0] || !destination_path || !destination_path[0]) {
    return 0;
  }
  /* Serialize publishers, not event admission.  Candidate parsing and the
   * durable replacement can take milliseconds (or much longer on a sick
   * filesystem), so neither is allowed under the paired reader/writer lock. */
  p0_ir_publication_lock();
  next = (p0_ir_candidate *)calloc(1, sizeof(*next));
  if (!next) {
    p0_ir_publication_unlock();
    return 0;
  }
  loaded = p0_ir_candidate_load_path_locked(next, staged_path);
  if (loaded && next->ready && p0_ir_sync_staged_file(staged_path)) {
    replace_result = p0_ir_replace_file(staged_path, destination_path);
  }
  if (replace_result != 1) {
    p0_ir_candidate_destroy(next);
    free(next);
    if (replace_result < 0 || s_publication_recovery_failed) {
      p0_ir_mark_artifact_terminal_unhealthy("artifact_journal_recovery_failed");
    }
    p0_ir_publication_unlock();
    return 0;
  }

  /* The only reader-visible critical section: invalidate the old
   * SensorInterest pairing and publish the already immutable candidate. */
  p0_ir_sensor_pair_write_lock();
  ir_write_lock();
  snprintf(next->source_label, sizeof(next->source_label), "%s", destination_path);
  if (!s_inited) {
    s_inited = 1;
    p0_ir_stats_init();
  }
  p0_ir_clear_ir_artifact_terminal_unhealthy_locked();
  p0_ir_sensor_pair_advance_locked();
  next->epoch = p0_ir_next_epoch_locked();
  previous = s_active_candidate;
  s_active_candidate = next;
  s_inited = 1;
  p0_ir_snapshot_retire_locked(previous, &destroy_previous);
  ir_write_unlock();
  p0_ir_sensor_pair_write_unlock();
  p0_ir_publication_unlock();
  if (destroy_previous) {
    p0_ir_candidate_destroy(previous);
    free(previous);
  }
  return 1;
}

static int try_load_default_paths(void) {
  const char *env_path = getenv("EDR_P0_IR_PATH");
  if (env_path && env_path[0]) {
    return try_load_ir_path(env_path);
  }
#if defined(_WIN32)
  char ex[1024];
  if (!edr_win_exe_dir(ex, sizeof(ex))) {
    return 0;
  }
  const char *suffixes[] = {
      "\\edr_config\\p0_rule_bundle_ir_v1.json.enc",
      "\\config\\p0_rule_bundle_ir_v1.json.enc",
  };
  for (size_t i = 0; i < sizeof(suffixes) / sizeof(suffixes[0]); i++) {
    char path[2048];
    if ((size_t)snprintf(path, sizeof(path), "%s%s", ex, suffixes[i]) >= sizeof(path)) {
      continue;
    }
    if (p0_ir_path_or_recovery_journal_present(path) && try_load_ir_path(path)) {
      return 1;
    }
    if (s_publication_recovery_failed) return 0;
  }
  return 0;
#else
  const char *paths[] = {
      "edr_config/p0_rule_bundle_ir_v1.json.enc",
      "config/p0_rule_bundle_ir_v1.json.enc",
      "edr_config/p0_rule_bundle_ir_v1.json",
      "config/p0_rule_bundle_ir_v1.json",
  };
  for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
    if (p0_ir_path_or_recovery_journal_present(paths[i]) && try_load_ir_path(paths[i])) {
      return 1;
    }
    if (s_publication_recovery_failed) return 0;
  }
  char proc_path[2048];
  if (try_linux_proc_exe(proc_path, sizeof(proc_path))) {
    if (try_load_ir_path(proc_path)) return 1;
    if (s_publication_recovery_failed) return 0;
  }
  return 0;
#endif
}

static int one_rule_match_process(
    const struct p0_ir_one *r, const char *process_name, const char *process_path,
    const char *cmdline, const char *parent_name, int pchain) {
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
  if (r->n_ppath_rx > 0) {
    if (!process_path || !process_path[0] ||
        !any_pcre((pcre2_code *const *)r->re_ppath_rx, r->n_ppath_rx, process_path)) {
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
  char pnlow[1024];
  const char *process_name;
  if (!r || !br) {
    return 0;
  }
  process_name = br->process_name[0] ? br->process_name : "";
  ascii_lower_truncate(pnlow, sizeof(pnlow), process_name);
  if (r->n_name_in > 0 &&
      !name_in_list(pnlow, (const char (*)[128])r->name_in, r->n_name_in)) {
    return 0;
  }
  if (r->n_pn_rx > 0 &&
      !any_pcre((pcre2_code *const *)r->re_pn_rx, r->n_pn_rx, process_name)) {
    return 0;
  }
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

static int reg_ascii_space(char c) {
  return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\v' || c == '\f';
}

static int reg_dword_atom(const char **cursor, unsigned base, uint32_t *out) {
  const char *p = *cursor;
  uint32_t value = 0u;
  int digits = 0;
  for (;;) {
    unsigned digit;
    if (*p >= '0' && *p <= '9') digit = (unsigned)(*p - '0');
    else if (base == 16u && *p >= 'a' && *p <= 'f') digit = (unsigned)(*p - 'a') + 10u;
    else if (base == 16u && *p >= 'A' && *p <= 'F') digit = (unsigned)(*p - 'A') + 10u;
    else break;
    if (value > (UINT32_MAX - digit) / base) return 0;
    value = value * base + digit;
    ++digits;
    ++p;
  }
  if (!digits) return 0;
  *cursor = p;
  *out = value;
  return 1;
}

/* collector_win renders DWORD as "decimal (0xHEX)". Require both values to
 * agree; numeric prefixes and conflicting display strings are not evidence. */
static int reg_parse_dword(const char *data, uint32_t *out) {
  const char *p = data;
  uint32_t value;
  int hex;
  if (!p) return 0;
  while (reg_ascii_space(*p)) ++p;
  hex = p[0] == '0' && (p[1] == 'x' || p[1] == 'X');
  if (hex) p += 2;
  if (!reg_dword_atom(&p, hex ? 16u : 10u, &value)) return 0;
  if (!hex && reg_ascii_space(*p)) {
    while (reg_ascii_space(*p)) ++p;
    if (*p == '(') {
      uint32_t second;
      ++p;
      if (p[0] != '0' || (p[1] != 'x' && p[1] != 'X')) return 0;
      p += 2;
      if (!reg_dword_atom(&p, 16u, &second) || second != value || *p++ != ')') return 0;
    }
  }
  while (reg_ascii_space(*p)) ++p;
  if (*p) return 0;
  *out = value;
  return 1;
}

static int reg_dword_any(const struct p0_ir_one *rule, const EdrBehaviorRecord *record) {
  uint32_t value;
  char name[sizeof(record->reg_value_name)];
  int i;
  if (!reg_parse_dword(record->reg_value_data, &value)) return 0;
  ascii_lower_truncate(name, sizeof(name), record->reg_value_name);
  for (i = 0; i < rule->n_reg_dword; ++i) {
    const struct p0_ir_registry_dword *predicate = &rule->reg_dword[i];
    if (value == predicate->value && strcmp(name, predicate->name) == 0 &&
        pcre2_ok_one(predicate->path, record->reg_key_path)) return 1;
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
  if (r->n_reg_dword > 0 && !reg_dword_any(r, br)) return 0;
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
  if (strcmp(et, "script_powershell") == 0 || strcmp(et, "powershell_script") == 0) {
    return t == EDR_EVENT_SCRIPT_POWERSHELL ? 1 : 0;
  }
  if (strcmp(et, "script_wmi") == 0 || strcmp(et, "wmi_script") == 0) {
    return t == EDR_EVENT_SCRIPT_WMI ? 1 : 0;
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
    /* registry_set is intentionally a write-only semantic.  Treating delete
     * notifications as a set made Run/RunOnce cleanup look like persistence. */
    return (t == EDR_EVENT_REG_SET_VALUE || t == EDR_EVENT_REG_CREATE_KEY) ? 1 : 0;
  }
  return 0;
}

static int p0_rule_has_constraints(const char *et, const struct p0_ir_one *r) {
  if (!r || !et) {
    return 0;
  }
  if (strcmp(et, "process_create") == 0 || strcmp(et, "script_powershell") == 0 ||
      strcmp(et, "powershell_script") == 0 || strcmp(et, "script_wmi") == 0 ||
      strcmp(et, "wmi_script") == 0) {
    return r->n_name_in > 0 || r->n_parent_in > 0 || r->n_pn_rx > 0 || r->n_ppath_rx > 0 ||
           r->n_pr_rx > 0 || r->n_cmd_any > 0 ||
           r->n_cmd_all > 0 || r->chain_gt > 0;
  }
  if (strcmp(et, "file_read") == 0 || strcmp(et, "file_write") == 0) {
    return r->n_fpath > 0 || r->n_pn_rx > 0 || r->n_cmd_any > 0 || r->n_cmd_all > 0 || r->n_name_in > 0 ||
           r->n_parent_in > 0 || r->n_pr_rx > 0;
  }
  if (strcmp(et, "network_connect") == 0) {
    return r->n_name_in > 0 || r->n_pn_rx > 0 || r->n_rport > 0 || r->n_fpath > 0;
  }
  if (strcmp(et, "registry_set") == 0) {
    return r->n_regpath > 0 || r->n_reg_name > 0 || r->n_reg_data > 0 || r->n_reg_dword > 0;
  }
  return 0;
}

static int p0_condition_string_array_valid(const cJSON *value) {
  cJSON *item;
  if (!cJSON_IsArray(value) || cJSON_GetArraySize(value) <= 0) {
    return 0;
  }
  cJSON_ArrayForEach(item, value) {
    if (!cJSON_IsString(item) || !item->valuestring || !item->valuestring[0]) {
      return 0;
    }
  }
  return 1;
}

static int p0_condition_port_array_valid(const cJSON *value) {
  cJSON *item;
  if (!cJSON_IsArray(value) || cJSON_GetArraySize(value) <= 0) {
    return 0;
  }
  cJSON_ArrayForEach(item, value) {
    int port;
    if (!cJSON_IsNumber(item)) {
      return 0;
    }
    port = (int)item->valuedouble;
    if (port < 1 || port > 65535 || item->valuedouble != (double)port) {
      return 0;
    }
  }
  return 1;
}

static int p0_condition_dword_array_valid(const cJSON *branches) {
  cJSON *branch;
  int count = cJSON_GetArraySize(branches);
  if (!cJSON_IsArray(branches) || count < 1 || count > P0_IR_REG_DWORD_MAX) return 0;
  cJSON_ArrayForEach(branch, branches) {
    cJSON *field;
    unsigned seen = 0u;
    if (!cJSON_IsObject(branch)) return 0;
    cJSON_ArrayForEach(field, branch) {
      unsigned bit;
      if (!field->string) return 0;
      if (strcmp(field->string, "path_regex") == 0) {
        bit = 1u;
        if (!cJSON_IsString(field) || !field->valuestring || !field->valuestring[0] ||
            strlen(field->valuestring) > 511u) return 0;
        {
          const char *p = field->valuestring;
          while (reg_ascii_space(*p)) ++p;
          if (!*p) return 0;
        }
      } else if (strcmp(field->string, "value_name") == 0) {
        size_t len;
        bit = 2u;
        if (!cJSON_IsString(field) || !field->valuestring) return 0;
        len = strlen(field->valuestring);
        if (len < 1u || len > 127u || reg_ascii_space(field->valuestring[0]) ||
            reg_ascii_space(field->valuestring[len - 1u])) return 0;
      } else if (strcmp(field->string, "value") == 0) {
        double value = field->valuedouble;
        bit = 4u;
        if (!cJSON_IsNumber(field) || !(value >= 0.0 && value <= 4294967295.0) ||
            value != (double)(uint32_t)value) return 0;
      } else return 0;
      if (seen & bit) return 0;
      seen |= bit;
    }
    if (seen != 7u) return 0;
  }
  return 1;
}

/* Conditions are a security contract, not an extensible bag of hints. A
 * field unknown to the event type must reject the entire candidate rather
 * than silently weakening a rule when an Agent parser has not implemented it.
 */
static int p0_condition_keys_supported(const char *event_type, const cJSON *condition) {
  cJSON *item;
  if (!event_type || !cJSON_IsObject(condition)) {
    return 0;
  }
  cJSON_ArrayForEach(item, condition) {
    const char *key = item->string;
    int allowed = 0;
    int string_array = 0;
    if (!key) {
      return 0;
    }
    for (cJSON *prior = condition->child; prior != item; prior = prior->next) {
      if (prior->string && strcmp(prior->string, key) == 0) return 0;
    }
    if (strcmp(event_type, "process_create") == 0 ||
        strcmp(event_type, "script_powershell") == 0 ||
        strcmp(event_type, "powershell_script") == 0 ||
        strcmp(event_type, "script_wmi") == 0 ||
        strcmp(event_type, "wmi_script") == 0) {
      allowed = strcmp(key, "process_chain_depth_gt") == 0 ||
                strcmp(key, "process_name_in") == 0 ||
                strcmp(key, "parent_name_in") == 0 ||
                strcmp(key, "command_regex_any") == 0 ||
                strcmp(key, "command_regex_all") == 0 ||
                strcmp(key, "process_name_regex_any") == 0 ||
                strcmp(key, "process_path_regex_any") == 0 ||
                strcmp(key, "parent_name_regex_any") == 0;
    } else if (strcmp(event_type, "file_read") == 0 || strcmp(event_type, "file_write") == 0) {
      allowed = strcmp(key, "process_name_in") == 0 ||
                strcmp(key, "parent_name_in") == 0 ||
                strcmp(key, "command_regex_any") == 0 ||
                strcmp(key, "command_regex_all") == 0 ||
                strcmp(key, "process_name_regex_any") == 0 ||
                strcmp(key, "parent_name_regex_any") == 0 ||
                strcmp(key, "file_path_regex_any") == 0;
    } else if (strcmp(event_type, "network_connect") == 0) {
      allowed = strcmp(key, "remote_port_in") == 0 ||
                strcmp(key, "file_path_regex_any") == 0 ||
                strcmp(key, "process_name_in") == 0 ||
                strcmp(key, "process_name_regex_any") == 0;
    } else if (strcmp(event_type, "registry_set") == 0) {
      allowed = strcmp(key, "registry_path_regex_any") == 0 ||
                strcmp(key, "registry_value_name_in") == 0 ||
                strcmp(key, "registry_value_data_in") == 0 ||
                strcmp(key, "registry_dword_any") == 0;
    }
    if (!allowed) {
      return 0;
    }
    if (strcmp(key, "process_chain_depth_gt") == 0) {
      int depth = cJSON_IsNumber(item) ? (int)item->valuedouble : 0;
      if (depth < 1 || !cJSON_IsNumber(item) || item->valuedouble != (double)depth) {
        return 0;
      }
    } else if (strcmp(key, "registry_dword_any") == 0) {
      if (!p0_condition_dword_array_valid(item)) return 0;
    } else if (strcmp(key, "remote_port_in") == 0) {
      if (!p0_condition_port_array_valid(item)) {
        return 0;
      }
    } else {
      string_array = 1;
    }
    if (string_array && !p0_condition_string_array_valid(item)) {
      return 0;
    }
  }
  return 1;
}

static int p0_ir_match_rule_to_br(const struct p0_ir_one *r, const EdrBehaviorRecord *br) {
  if (!r || !br) {
    return 0;
  }
  if (strcmp(r->event_type, "process_create") == 0 || strcmp(r->event_type, "script_powershell") == 0 ||
      strcmp(r->event_type, "powershell_script") == 0 || strcmp(r->event_type, "script_wmi") == 0 ||
      strcmp(r->event_type, "wmi_script") == 0) {
    const char *cmd = br->cmdline[0] ? br->cmdline : br->script_snippet;
    const char *pn = br->process_name[0] ? br->process_name : NULL;
    if (!pn && br->type == EDR_EVENT_SCRIPT_POWERSHELL) {
      pn = "powershell.exe";
    } else if (!pn && br->type == EDR_EVENT_SCRIPT_WMI) {
      pn = "wmiprvse.exe";
    }
    return one_rule_match_process(
        r, pn, br->exe_path[0] ? br->exe_path : NULL, cmd,
        br->parent_name[0] ? br->parent_name : NULL, (int)br->process_chain_depth
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
  if (!data || data_len > EDR_P0_ENCRYPT_PLAINTEXT_MAX_BYTES) {
    fprintf(stderr, "[p0_rule_ir] plaintext exceeds envelope contract: %s\n",
            source_label ? source_label : "unknown");
    return 0;
  }
  s_n = 0;
  s_ready = 0;
  s_source_label[0] = '\0';
  s_plain_size = 0u;
  s_plain_sha256[0] = '\0';
  s_rules_bundle_version[0] = '\0';
  s_declared_rule_count = 0u;
  s_sensor_interest_manifest_sha256[0] = '\0';
  s_sensor_interest_manifest_hash_mode[0] = '\0';
  fprintf(stderr, "[p0_rule_ir:%s/%s] loading %s (%zu bytes, %s)\n",
          EDR_P0_MATCHER_SOURCE_SCHEMA, EDR_P0_MATCHER_RULE_SCHEMA, source_label, data_len,
          (data_len >= 4 && memcmp(data, "EDR1", 4) == 0) ? "EDR1" : (data_len >= 1 && data[0] == '{') ? "JSON" : "unknown");
  /* cJSON exposes NUL-terminated strings; accepting an embedded NUL would
   * silently shorten a path or value-name constraint. */
  for (size_t i = 0; i < data_len; ++i) {
    if (!data[i]) return 0;
    if (data[i] == '\\' && i + 1u < data_len) {
      if (i + 5u < data_len && memcmp(data + i, "\\u0000", 6u) == 0) return 0;
      ++i;
    }
  }
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
  int legacy_schema = 0;
  {
    cJSON *kind = cJSON_GetObjectItemCaseSensitive(root, "kind");
    cJSON *schema_version = cJSON_GetObjectItemCaseSensitive(root, "ir_schema_version");
    cJSON *version = cJSON_GetObjectItemCaseSensitive(root, "rules_bundle_version");
    cJSON *declared_count = cJSON_GetObjectItemCaseSensitive(root, "rule_count");
    cJSON *sensor_sha = cJSON_GetObjectItemCaseSensitive(root, "sensor_interest_manifest_sha256");
    cJSON *sensor_mode = cJSON_GetObjectItemCaseSensitive(root, "sensor_interest_manifest_hash_mode");
    if (!cJSON_IsString(kind) || !kind->valuestring ||
        strcmp(kind->valuestring, EDR_P0_RULE_IR_BUNDLE_KIND) != 0 ||
        !cJSON_IsNumber(schema_version) ||
        (schema_version->valuedouble != (double)EDR_P0_RULE_IR_SCHEMA_VERSION &&
         schema_version->valuedouble != 2.0) ||
        !cJSON_IsString(version) || !version->valuestring || !version->valuestring[0] ||
        !cJSON_IsNumber(declared_count) || declared_count->valueint < 0 ||
        (uint32_t)declared_count->valueint != (uint32_t)cJSON_GetArraySize(rules) ||
        !cJSON_IsString(sensor_sha) || !p0_ir_hex64(sensor_sha->valuestring) ||
        !cJSON_IsString(sensor_mode) || !sensor_mode->valuestring ||
        strcmp(sensor_mode->valuestring, P0_IR_SENSOR_INTEREST_HASH_MODE) != 0) {
      cJSON_Delete(root);
      fprintf(stderr, "[p0_rule_ir] missing or inconsistent artifact binding: %s\n", source_label);
      return 0;
    }
    legacy_schema = schema_version->valuedouble == 2.0;
    snprintf(s_rules_bundle_version, sizeof(s_rules_bundle_version), "%s", version->valuestring);
    s_declared_rule_count = (uint32_t)declared_count->valueint;
    snprintf(s_sensor_interest_manifest_sha256, sizeof(s_sensor_interest_manifest_sha256), "%s",
             sensor_sha->valuestring);
    snprintf(s_sensor_interest_manifest_hash_mode, sizeof(s_sensor_interest_manifest_hash_mode), "%s",
             sensor_mode->valuestring);
  }
  cJSON *rnode;
  int parse_ok = 1;
  int semantic_ok = 1;
  cJSON_ArrayForEach(rnode, rules) {
    if (s_n >= (int)EDR_P0_RULE_IR_MAX_RULES) {
      break;
    }
    if (!cJSON_IsObject(rnode)) {
      semantic_ok = 0;
      break;
    }
    cJSON *jid = cJSON_GetObjectItemCaseSensitive(rnode, "id");
    cJSON *jet = cJSON_GetObjectItemCaseSensitive(rnode, "event_type");
    if (!cJSON_IsString(jid) || !jid->valuestring) {
      semantic_ok = 0;
      break;
    }
    if (!cJSON_IsString(jet) || !jet->valuestring) {
      semantic_ok = 0;
      break;
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
        strcmp(etbuf, "registry_set") != 0 && strcmp(etbuf, "script_powershell") != 0 &&
        strcmp(etbuf, "powershell_script") != 0 && strcmp(etbuf, "script_wmi") != 0 &&
        strcmp(etbuf, "wmi_script") != 0) {
      semantic_ok = 0;
      break;
    }
    struct p0_ir_one t;
    memset(&t, 0, sizeof(t));
    snprintf(t.id, sizeof(t.id), "%s", jid->valuestring);
    ascii_lower_truncate(t.event_type, sizeof(t.event_type), etbuf);
    t.severity = 3;
    cJSON *jsev = cJSON_GetObjectItemCaseSensitive(rnode, "severity");
    if (cJSON_IsNumber(jsev)) {
      t.severity = jsev->valueint;
      if (t.severity < 1) t.severity = 1;
      if (t.severity > 4) t.severity = 4;
    }
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
    if (!p0_condition_keys_supported(etbuf, jcond) ||
        (legacy_schema && cJSON_GetObjectItemCaseSensitive(jcond, "registry_dword_any"))) {
      semantic_ok = 0;
      break;
    }
    if (strcmp(etbuf, "process_create") == 0 || strcmp(etbuf, "script_powershell") == 0 ||
        strcmp(etbuf, "powershell_script") == 0 || strcmp(etbuf, "script_wmi") == 0 ||
        strcmp(etbuf, "wmi_script") == 0) {
      add_str_array(
          jcond, "process_name_in", t.name_in, &t.n_name_in, P0_IR_NAME_IN_MAX, 1
      );
      add_str_array(
          jcond, "parent_name_in", t.parent_in, &t.n_parent_in, P0_IR_NAME_IN_MAX, 1
      );
      add_rx_array(
          jcond, "command_regex_any", t.re_cmd_any, &t.n_cmd_any, P0_IR_PAT, jid->valuestring, &parse_ok
      );
      add_rx_array(
          jcond, "command_regex_all", t.re_cmd_all, &t.n_cmd_all, P0_IR_PAT, jid->valuestring, &parse_ok
      );
      add_rx_array(
          jcond, "process_name_regex_any", t.re_pn_rx, &t.n_pn_rx, P0_IR_PAT, jid->valuestring, &parse_ok
      );
      add_rx_array(
          jcond, "process_path_regex_any", t.re_ppath_rx, &t.n_ppath_rx, P0_IR_PAT, jid->valuestring, &parse_ok
      );
      add_rx_array(
          jcond, "parent_name_regex_any", t.re_pr_rx, &t.n_pr_rx, P0_IR_PAT, jid->valuestring, &parse_ok
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
          jcond, "command_regex_any", t.re_cmd_any, &t.n_cmd_any, P0_IR_PAT, jid->valuestring, &parse_ok
      );
      add_rx_array(
          jcond, "command_regex_all", t.re_cmd_all, &t.n_cmd_all, P0_IR_PAT, jid->valuestring, &parse_ok
      );
      add_rx_array(
          jcond, "process_name_regex_any", t.re_pn_rx, &t.n_pn_rx, P0_IR_PAT, jid->valuestring, &parse_ok
      );
      add_rx_array(
          jcond, "parent_name_regex_any", t.re_pr_rx, &t.n_pr_rx, P0_IR_PAT, jid->valuestring, &parse_ok
      );
      add_rx_array(
          jcond, "file_path_regex_any", t.re_fpath, &t.n_fpath, P0_IR_PAT, jid->valuestring, &parse_ok
      );
    } else if (strcmp(etbuf, "network_connect") == 0) {
      add_str_array(
          jcond, "process_name_in", t.name_in, &t.n_name_in, P0_IR_NAME_IN_MAX, 1
      );
      add_rx_array(
          jcond, "process_name_regex_any", t.re_pn_rx, &t.n_pn_rx, P0_IR_PAT,
          jid->valuestring, &parse_ok
      );
      add_int_array(jcond, "remote_port_in", t.rport, &t.n_rport, 64);
      add_rx_array(
          jcond, "file_path_regex_any", t.re_fpath, &t.n_fpath, P0_IR_PAT, jid->valuestring, &parse_ok
      );
    } else if (strcmp(etbuf, "registry_set") == 0) {
      add_reg_dword(jcond, &t, &parse_ok);
      add_rx_array(
          jcond, "registry_path_regex_any", t.re_regpath, &t.n_regpath, P0_IR_PAT, jid->valuestring, &parse_ok
      );
      add_str_array(
          jcond, "registry_value_name_in", t.reg_name_in, &t.n_reg_name, P0_IR_NAME_IN_MAX, 1
      );
      add_reg_data_substrings_munge(
          jcond, "registry_value_data_in", t.reg_data_in, &t.n_reg_data, P0_IR_NAME_IN_MAX
      );
    }
    if (!parse_ok) {
      p0_ir_free_pcre_in_rule(&t);
      cJSON_Delete(root);
      p0_ir_candidate_destroy(s_load_target);
      return 0;
    }
    if (!p0_rule_has_constraints(etbuf, &t)) {
      p0_ir_free_pcre_in_rule(&t);
      semantic_ok = 0;
      break;
    }
    for (int i = 0; i < s_n; ++i) {
      if (strcmp(s_rule[i].id, t.id) == 0) {
        p0_ir_free_pcre_in_rule(&t);
        semantic_ok = 0;
        break;
      }
    }
    if (!semantic_ok) {
      break;
    }
    t.in_use = 1;
    s_rule[s_n++] = t;
  }
  cJSON_Delete(root);
  if (!semantic_ok) {
    fprintf(stderr, "[p0_rule_ir] semantic validation failed: %s\n", source_label);
    p0_ir_candidate_destroy(s_load_target);
    return 0;
  }
  if (s_n > 0 && (uint32_t)s_n == s_declared_rule_count) {
    s_ready = 1;
    snprintf(s_source_label, sizeof(s_source_label), "%s", source_label ? source_label : "");
    s_plain_size = data_len;
    (void)edr_sha256_hex((const uint8_t *)data, data_len, s_plain_sha256);
    fprintf(
        stderr, "[p0_rule_ir] loaded %d P0 rules (process/file/net/registry) from %s sha256=%s\n", s_n,
        source_label, s_plain_sha256[0] ? s_plain_sha256 : "unknown"
    );
    return 1;
  }
  fprintf(stderr, "[p0_rule_ir] no loadable or count-consistent P0 rules in %s\n", source_label);
  return 0;
}

void edr_p0_rule_ir_lazy_init(void) {
  p0_ir_candidate *next;
  p0_ir_candidate *previous;
  int loaded = 0;
  int destroy_previous = 0;
  /* Avoid taking the paired writer lock on the common already-initialised
   * path: SensorInterest may call this while it holds the paired read guard. */
  ir_write_lock();
  if (s_inited) {
    ir_write_unlock();
    return;
  }
  ir_write_unlock();

  p0_ir_publication_lock();
  ir_write_lock();
  if (s_inited) {
    ir_write_unlock();
    p0_ir_publication_unlock();
    return;
  }
  /* Mark the load in progress before unlocking.  Callers then fail closed
   * while the potentially slow candidate preparation runs without blocking
   * the SensorInterest/ETW reader side of the paired lock. */
  s_inited = 1;
  p0_ir_stats_init();
  ir_write_unlock();

  next = (p0_ir_candidate *)calloc(1, sizeof(*next));
  if (!next) {
    p0_ir_publication_unlock();
    fprintf(stderr, "[p0_rule_ir] unable to allocate active snapshot\n");
    return;
  }
  loaded = p0_ir_candidate_load_default_paths_locked(next);
  if (!loaded && !s_publication_recovery_failed) {
    fprintf(
        stderr,
        "[p0_rule_ir] no loadable file path (set EDR_P0_IR_PATH or place edr_config next to exe); trying "
        "fallback\n"
    );
  }
#if defined(EDR_P0_IR_HAS_EMBED) && EDR_P0_IR_HAS_EMBED
  if (!loaded && !s_publication_recovery_failed) {
    const char *embed_data = (const char *)edr_p0_rule_ir_embed_bytes;
    size_t embed_len = edr_p0_rule_ir_embed_len;
    char *decrypted = NULL;
    if (embed_len > EDR_P0_ENCRYPT_ENVELOPE_MAX_BYTES) {
      fprintf(stderr, "[p0_rule_ir] embedded envelope exceeds contract\n");
      embed_len = 0u;
    } else if (edr_p0_encrypt_is_edr1((const uint8_t *)embed_data, embed_len)) {
      uint8_t *plain = NULL;
      size_t plain_len = 0;
      int dr = edr_p0_encrypt_decrypt_edr1((const uint8_t *)embed_data, embed_len, &plain, &plain_len);
      if (dr == 0 && plain_len <= EDR_P0_ENCRYPT_PLAINTEXT_MAX_BYTES) {
        decrypted = (char *)plain;
        embed_data = decrypted;
        embed_len = plain_len;
      } else if (plain) {
        free(plain);
        embed_len = 0u;
      }
    } else if (embed_len > EDR_P0_ENCRYPT_PLAINTEXT_MAX_BYTES) {
      fprintf(stderr, "[p0_rule_ir] embedded plaintext exceeds contract\n");
      embed_len = 0u;
    }
    loaded = p0_ir_candidate_load_json_locked(
        next, "embedded: p0_rule_bundle_ir_v1.json", embed_data, embed_len
    );
    if (decrypted) {
      free(decrypted);
    }
  }
#endif
  if (!loaded) {
    fprintf(
        stderr,
        "[p0_rule_ir] not loaded: no readable IR file and no embed (install edr_config JSON or build "
        "with EDR_P0_IR_EMBED)\n"
    );
    p0_ir_candidate_destroy(next);
    free(next);
    if (s_publication_recovery_failed) {
      p0_ir_mark_artifact_terminal_unhealthy("artifact_journal_recovery_failed");
    }
  } else {
    p0_ir_sensor_pair_write_lock();
    ir_write_lock();
    p0_ir_clear_ir_artifact_terminal_unhealthy_locked();
    p0_ir_sensor_pair_advance_locked();
    next->epoch = p0_ir_next_epoch_locked();
    previous = s_active_candidate;
    s_active_candidate = next;
    p0_ir_snapshot_retire_locked(previous, &destroy_previous);
    ir_write_unlock();
    p0_ir_sensor_pair_write_unlock();
  }
  p0_ir_publication_unlock();
  if (destroy_previous) {
    p0_ir_candidate_destroy(previous);
    free(previous);
  }
}

void edr_p0_rule_ir_reload(void) {
  p0_ir_candidate *next;
  p0_ir_candidate *previous;
  int destroy_previous = 0;
  int loaded;
  p0_ir_publication_lock();
  ir_write_lock();
  if (!s_inited) {
    s_inited = 1;
    p0_ir_stats_init();
  }
  ir_write_unlock();

  next = (p0_ir_candidate *)calloc(1, sizeof(*next));
  if (!next) {
    p0_ir_publication_unlock();
    fprintf(stderr, "[p0_rule_ir] unable to allocate reload snapshot\n");
    return;
  }
  loaded = p0_ir_candidate_load_default_paths_locked(next);
  if (!loaded) {
    p0_ir_candidate_destroy(next);
    free(next);
    if (s_publication_recovery_failed) {
      p0_ir_mark_artifact_terminal_unhealthy("artifact_journal_recovery_failed");
    }
    p0_ir_publication_unlock();
    return;
  }

  p0_ir_sensor_pair_write_lock();
  ir_write_lock();
  p0_ir_clear_ir_artifact_terminal_unhealthy_locked();
  previous = s_active_candidate;
  p0_ir_sensor_pair_advance_locked();
  next->epoch = p0_ir_next_epoch_locked();
  s_active_candidate = next;
  p0_ir_snapshot_retire_locked(previous, &destroy_previous);
  ir_write_unlock();
  p0_ir_sensor_pair_write_unlock();
  p0_ir_publication_unlock();
  if (destroy_previous) {
    p0_ir_candidate_destroy(previous);
    free(previous);
  }
}

int edr_p0_bundle_dst_path(char *out, size_t cap) {
  const char *e = getenv("EDR_P0_IR_PATH");
  if (e && *e) {
    snprintf(out, cap, "%s", e);
    return 0;
  }
#ifdef _WIN32
  char ex[1024];
  if (edr_win_exe_dir(ex, sizeof(ex))) {
    snprintf(out, cap, "%s\\edr_config\\p0_rule_bundle_ir_v1.json.enc", ex);
    return 0;
  }
#else
  char tmp[2048];
  if (try_linux_proc_exe(tmp, sizeof(tmp))) {
    snprintf(out, cap, "%s", tmp);
    return 0;
  }
#endif
  return -1;
}

int edr_p0_rule_ir_is_ready(void) {
  p0_ir_candidate *snapshot = p0_ir_snapshot_acquire();
  int unhealthy;
  int ready;
  ir_write_lock();
  unhealthy = s_artifact_terminal_unhealthy_mask != 0u;
  ir_write_unlock();
  ready = snapshot && snapshot->ready && !unhealthy;
  p0_ir_snapshot_release(snapshot);
  return ready;
}

int edr_p0_rule_ir_artifact_healthy(char *out_reason, size_t out_reason_cap) {
  int healthy;
  if (out_reason && out_reason_cap > 0u) out_reason[0] = '\0';
  ir_write_lock();
  healthy = s_artifact_terminal_unhealthy_mask == 0u;
  if (!healthy && out_reason && out_reason_cap > 0u) {
    snprintf(out_reason, out_reason_cap, "%s", s_artifact_terminal_reason);
  }
  ir_write_unlock();
  return healthy;
}

void edr_p0_rule_ir_set_sensor_artifact_terminal_unhealthy(const char *reason) {
  p0_ir_publication_lock();
  ir_write_lock();
  s_artifact_terminal_unhealthy_mask |= P0_IR_ARTIFACT_UNHEALTHY_SENSOR;
  if (!(s_artifact_terminal_unhealthy_mask & P0_IR_ARTIFACT_UNHEALTHY_IR)) {
    snprintf(s_artifact_terminal_reason, sizeof(s_artifact_terminal_reason), "%s",
             reason && reason[0] ? reason : "sensor_interest_journal_recovery_failed");
  }
  ir_write_unlock();
  p0_ir_publication_unlock();
}

void edr_p0_rule_ir_clear_sensor_artifact_terminal_unhealthy(void) {
  p0_ir_publication_lock();
  ir_write_lock();
  s_artifact_terminal_unhealthy_mask &= ~P0_IR_ARTIFACT_UNHEALTHY_SENSOR;
  if (s_artifact_terminal_unhealthy_mask == 0u) {
    s_artifact_terminal_reason[0] = '\0';
  }
  ir_write_unlock();
  p0_ir_publication_unlock();
}

int edr_p0_rule_ir_get_bundle_info(const char **out_source, size_t *out_plain_size, const char **out_plain_sha256) {
  static _Thread_local char source_copy[1024];
  static _Thread_local char sha_copy[65];
  p0_ir_candidate *snapshot = p0_ir_snapshot_acquire();
  int ready = snapshot && snapshot->ready;
  snprintf(source_copy, sizeof(source_copy), "%s", snapshot ? snapshot->source_label : "");
  snprintf(sha_copy, sizeof(sha_copy), "%s", snapshot ? snapshot->plain_sha256 : "");
  if (out_source) {
    *out_source = source_copy;
  }
  if (out_plain_size) {
    *out_plain_size = snapshot ? snapshot->plain_size : 0u;
  }
  if (out_plain_sha256) {
    *out_plain_sha256 = sha_copy;
  }
  p0_ir_snapshot_release(snapshot);
  return ready ? 1 : 0;
}

static int p0_ir_copy_binding_from_snapshot(const p0_ir_candidate *snapshot,
                                            EdrP0RuleIrBinding *out_binding) {
  if (!snapshot || !out_binding || !snapshot->ready || !snapshot->rules_bundle_version[0] ||
      !p0_ir_hex64(snapshot->plain_sha256) ||
      !p0_ir_hex64(snapshot->sensor_interest_manifest_sha256) ||
      !snapshot->sensor_interest_manifest_hash_mode[0] ||
      snapshot->declared_rule_count != (uint32_t)snapshot->n || snapshot->epoch == 0u) {
    return 0;
  }
  memset(out_binding, 0, sizeof(*out_binding));
  snprintf(out_binding->rules_bundle_version, sizeof(out_binding->rules_bundle_version), "%s",
           snapshot->rules_bundle_version);
  snprintf(out_binding->artifact_sha256, sizeof(out_binding->artifact_sha256), "%s",
           snapshot->plain_sha256);
  snprintf(out_binding->sensor_interest_manifest_sha256,
           sizeof(out_binding->sensor_interest_manifest_sha256), "%s",
           snapshot->sensor_interest_manifest_sha256);
  snprintf(out_binding->sensor_interest_manifest_hash_mode,
           sizeof(out_binding->sensor_interest_manifest_hash_mode), "%s",
           snapshot->sensor_interest_manifest_hash_mode);
  out_binding->rule_count = snapshot->declared_rule_count;
  out_binding->snapshot_epoch = snapshot->epoch;
  return 1;
}

static void p0_ir_stats_record_snapshot(p0_ir_candidate *snapshot, int rule_idx, int hit) {
  int stats_enabled;
  if (!snapshot || rule_idx < 0 || rule_idx >= snapshot->n) {
    return;
  }
  ir_write_lock();
  stats_enabled = s_stats_enabled;
  if (stats_enabled && snapshot->ready) {
    snapshot->rule_evaluate_count[rule_idx]++;
    if (hit) {
      snapshot->rule_hit_count[rule_idx]++;
    }
  }
  ir_write_unlock();
}

int edr_p0_rule_ir_get_binding(EdrP0RuleIrBinding *out_binding) {
  p0_ir_candidate *snapshot;
  int ok;
  if (!out_binding) {
    return 0;
  }
  memset(out_binding, 0, sizeof(*out_binding));
  /* Non-lazy by contract.  SensorInterest calls this while holding the
   * paired reader guard; attempting lazy initialization there would try to
   * upgrade that reader to the paired writer and can deadlock shutdown or a
   * first-load race.  Owners that need initialization call lazy_init before
   * entering the paired reader section. */
  snapshot = p0_ir_snapshot_acquire();
  ok = p0_ir_copy_binding_from_snapshot(snapshot, out_binding);
  p0_ir_snapshot_release(snapshot);
  return ok;
}

int edr_p0_rule_ir_evaluate_record(const EdrBehaviorRecord *br,
                                   EdrP0RuleIrEvaluation *out_evaluation) {
  p0_ir_candidate *snapshot;
  uint32_t match_count = 0u;
  int ok = 0;
  int artifact_healthy;
  int i;
  if (!br || !out_evaluation) {
    return 0;
  }
  memset(out_evaluation, 0, sizeof(*out_evaluation));
  edr_p0_rule_ir_lazy_init();
  /* A failed durable-artifact recovery retires the active authority.  Do not
   * let a retained pre-failure reader snapshot re-enter direct evaluation
   * while the endpoint is reporting the capability unavailable. */
  ir_write_lock();
  artifact_healthy = s_artifact_terminal_unhealthy_mask == 0u;
  ir_write_unlock();
  if (!artifact_healthy) {
    return 0;
  }
  snapshot = p0_ir_snapshot_acquire();
  if (!p0_ir_copy_binding_from_snapshot(snapshot, &out_evaluation->binding)) {
    goto done;
  }
  for (i = 0; i < snapshot->n; ++i) {
    const struct p0_ir_one *rule = &snapshot->rule[i];
    int hit;
    if (!rule->in_use) {
      continue;
    }
    hit = p0_br_wants_event_type(br->type, rule->event_type) &&
          p0_ir_match_rule_to_br(rule, br);
    p0_ir_stats_record_snapshot(snapshot, i, hit);
    if (!hit) {
      continue;
    }
    if (match_count >= EDR_P0_RULE_IR_MAX_MATCHES) {
      /* Parser capacity and evaluation capacity are deliberately the same;
       * this guards a future parser increase from silently truncating a P0
       * match set.  The caller fails closed and emits its registered
       * ruleset-evaluation disposition. */
      goto done;
    }
    out_evaluation->match_indices[match_count] = (uint16_t)i;
    match_count++;
  }
  out_evaluation->match_count = match_count;
  out_evaluation->snapshot = snapshot;
  snapshot = NULL;
  ok = 1;
done:
  if (!ok) {
    memset(out_evaluation, 0, sizeof(*out_evaluation));
  }
  p0_ir_snapshot_release(snapshot);
  return ok;
}

int edr_p0_rule_ir_evaluation_get_match(const EdrP0RuleIrEvaluation *evaluation,
                                        uint32_t index,
                                        EdrP0RuleIrMatch *out_match) {
  const p0_ir_candidate *snapshot;
  uint16_t rule_index;
  const struct p0_ir_one *rule;
  if (!evaluation || !out_match || index >= evaluation->match_count ||
      !evaluation->snapshot) {
    return 0;
  }
  snapshot = (const p0_ir_candidate *)evaluation->snapshot;
  rule_index = evaluation->match_indices[index];
  if (rule_index >= (uint16_t)snapshot->n || !snapshot->rule[rule_index].in_use) {
    return 0;
  }
  rule = &snapshot->rule[rule_index];
  memset(out_match, 0, sizeof(*out_match));
  snprintf(out_match->rule_id, sizeof(out_match->rule_id), "%s", rule->id);
  snprintf(out_match->title, sizeof(out_match->title), "%s",
           rule->title[0] ? rule->title : rule->id);
  snprintf(out_match->mitre_csv, sizeof(out_match->mitre_csv), "%s", rule->mitre_csv);
  out_match->severity = rule->severity > 0 ? rule->severity : 3;
  return 1;
}

void edr_p0_rule_ir_evaluation_free(EdrP0RuleIrEvaluation *evaluation) {
  p0_ir_candidate *snapshot;
  if (!evaluation) {
    return;
  }
  snapshot = (p0_ir_candidate *)evaluation->snapshot;
  memset(evaluation, 0, sizeof(*evaluation));
  p0_ir_snapshot_release(snapshot);
}

unsigned edr_p0_rule_ir_required_full_admission_mask(void) {
  p0_ir_candidate *snapshot;
  unsigned mask = EDR_P0_IR_FULL_ADMISSION_FILE_READ |
                  EDR_P0_IR_FULL_ADMISSION_FILE_WRITE |
                  EDR_P0_IR_FULL_ADMISSION_REGISTRY_SET;
  edr_p0_rule_ir_lazy_init();
  snapshot = p0_ir_snapshot_acquire();
  if (!snapshot || !snapshot->ready) {
    p0_ir_snapshot_release(snapshot);
    return mask;
  }
  mask = 0u;
  for (int i = 0; i < snapshot->n; ++i) {
    const struct p0_ir_one *rule = &snapshot->rule[i];
    if (!rule->in_use) {
      continue;
    }
    /* The current IR represents file/registry path constraints as PCRE2.
     * Any such predicate (or no predicate) is not safely reducible by the
     * raw collector, so admission must remain complete for that event type. */
    if (strcmp(rule->event_type, "file_read") == 0) {
      mask |= EDR_P0_IR_FULL_ADMISSION_FILE_READ;
    } else if (strcmp(rule->event_type, "file_write") == 0) {
      mask |= EDR_P0_IR_FULL_ADMISSION_FILE_WRITE;
    } else if (strcmp(rule->event_type, "registry_set") == 0) {
      mask |= EDR_P0_IR_FULL_ADMISSION_REGISTRY_SET;
    }
  }
  p0_ir_snapshot_release(snapshot);
  return mask;
}

int edr_p0_rule_ir_matches(const char *rule_id, const char *process_name, const char *cmdline,
                           const char *parent_name, int process_chain_depth) {
  p0_ir_candidate *snapshot;
  int result = 0;
  int i;
  if (!rule_id) {
    return 0;
  }
  edr_p0_rule_ir_lazy_init();
  snapshot = p0_ir_snapshot_acquire();
  if (!snapshot || !snapshot->ready) {
    p0_ir_snapshot_release(snapshot);
    return 0;
  }
  for (i = 0; i < snapshot->n; i++) {
    if (strcmp(snapshot->rule[i].id, rule_id) != 0) {
      continue;
    }
    if (!snapshot->rule[i].in_use || strcmp(snapshot->rule[i].event_type, "process_create") != 0) {
      break;
    }
    result = one_rule_match_process(
        &snapshot->rule[i], process_name, NULL, cmdline, parent_name, process_chain_depth) ? 1 : 0;
    break;
  }
  p0_ir_snapshot_release(snapshot);
  return result;
}

int edr_p0_rule_ir_get_meta(
    const char *rule_id, const char **out_title, const char **out_mitre) {
  static _Thread_local char title_copy[P0_IR_STR];
  static _Thread_local char mitre_copy[P0_IR_STR];
  p0_ir_candidate *snapshot;
  int result = 0;
  int i;
  if (out_title) {
    *out_title = NULL;
  }
  if (out_mitre) {
    *out_mitre = NULL;
  }
  if (!rule_id) {
    return 0;
  }
  edr_p0_rule_ir_lazy_init();
  snapshot = p0_ir_snapshot_acquire();
  if (!snapshot || !snapshot->ready) {
    p0_ir_snapshot_release(snapshot);
    return 0;
  }
  for (i = 0; i < snapshot->n; i++) {
    if (strcmp(snapshot->rule[i].id, rule_id) == 0 && snapshot->rule[i].in_use) {
      snprintf(title_copy, sizeof(title_copy), "%s",
               snapshot->rule[i].title[0] ? snapshot->rule[i].title : snapshot->rule[i].id);
      snprintf(mitre_copy, sizeof(mitre_copy), "%s", snapshot->rule[i].mitre_csv);
      if (out_title) {
        *out_title = title_copy;
      }
      if (out_mitre) {
        *out_mitre = mitre_copy;
      }
      result = 1;
      break;
    }
  }
  p0_ir_snapshot_release(snapshot);
  return result;
}

int edr_p0_rule_ir_get_severity(const char *rule_id) {
  p0_ir_candidate *snapshot;
  int severity = 3;
  int i;
  if (!rule_id) {
    return 3;
  }
  edr_p0_rule_ir_lazy_init();
  snapshot = p0_ir_snapshot_acquire();
  if (!snapshot || !snapshot->ready) {
    p0_ir_snapshot_release(snapshot);
    return severity;
  }
  for (i = 0; i < snapshot->n; i++) {
    if (strcmp(snapshot->rule[i].id, rule_id) == 0 && snapshot->rule[i].in_use) {
      severity = snapshot->rule[i].severity > 0 ? snapshot->rule[i].severity : 3;
      break;
    }
  }
  p0_ir_snapshot_release(snapshot);
  return severity;
}

int edr_p0_rule_ir_process_create_count(void) {
  p0_ir_candidate *snapshot;
  int c = 0;
  int i;
  edr_p0_rule_ir_lazy_init();
  snapshot = p0_ir_snapshot_acquire();
  if (!snapshot || !snapshot->ready) {
    p0_ir_snapshot_release(snapshot);
    return 0;
  }
  for (i = 0; i < snapshot->n; i++) {
    if (strcmp(snapshot->rule[i].event_type, "process_create") == 0) {
      c++;
    }
  }
  p0_ir_snapshot_release(snapshot);
  return c;
}

int edr_p0_rule_ir_process_create_id_at(int index, const char **out_id) {
  static _Thread_local char id_copy[P0_IR_ID_MAX];
  p0_ir_candidate *snapshot;
  int k = 0;
  int i;
  if (index < 0 || !out_id) {
    return 0;
  }
  *out_id = NULL;
  edr_p0_rule_ir_lazy_init();
  snapshot = p0_ir_snapshot_acquire();
  if (!snapshot || !snapshot->ready) {
    p0_ir_snapshot_release(snapshot);
    return 0;
  }
  for (i = 0; i < snapshot->n; i++) {
    if (strcmp(snapshot->rule[i].event_type, "process_create") != 0) {
      continue;
    }
    if (k == index) {
      snprintf(id_copy, sizeof(id_copy), "%s", snapshot->rule[i].id);
      *out_id = id_copy;
      p0_ir_snapshot_release(snapshot);
      return 1;
    }
    k++;
  }
  p0_ir_snapshot_release(snapshot);
  return 0;
}

int edr_p0_rule_ir_rule_count(void) {
  p0_ir_candidate *snapshot;
  int n;
  edr_p0_rule_ir_lazy_init();
  snapshot = p0_ir_snapshot_acquire();
  n = snapshot && snapshot->ready ? snapshot->n : 0;
  p0_ir_snapshot_release(snapshot);
  return n;
}

int edr_p0_rule_ir_rule_id_at(int index, const char **out_id) {
  static _Thread_local char id_copy[P0_IR_ID_MAX];
  p0_ir_candidate *snapshot;
  if (index < 0 || !out_id) {
    return 0;
  }
  *out_id = NULL;
  edr_p0_rule_ir_lazy_init();
  snapshot = p0_ir_snapshot_acquire();
  if (!snapshot || !snapshot->ready || index >= snapshot->n) {
    p0_ir_snapshot_release(snapshot);
    return 0;
  }
  snprintf(id_copy, sizeof(id_copy), "%s", snapshot->rule[index].id);
  *out_id = id_copy;
  p0_ir_snapshot_release(snapshot);
  return 1;
}

int edr_p0_rule_ir_br_matches_index(const EdrBehaviorRecord *br, int index) {
  p0_ir_candidate *snapshot;
  int result;
  if (!br || index < 0) {
    return 0;
  }
  edr_p0_rule_ir_lazy_init();
  snapshot = p0_ir_snapshot_acquire();
  if (!snapshot || !snapshot->ready || index >= snapshot->n || !snapshot->rule[index].in_use) {
    p0_ir_snapshot_release(snapshot);
    return 0;
  }
  result = p0_br_wants_event_type(br->type, snapshot->rule[index].event_type) &&
           p0_ir_match_rule_to_br(&snapshot->rule[index], br);
  p0_ir_snapshot_release(snapshot);
  return result ? 1 : 0;
}

int edr_p0_rule_ir_br_matches_any(const EdrBehaviorRecord *br) {
  if (!br) {
    return 0;
  }
  edr_p0_rule_ir_lazy_init();
  p0_ir_candidate *snapshot = p0_ir_snapshot_acquire();
  if (!snapshot || !snapshot->ready) {
    p0_ir_snapshot_release(snapshot);
    return 0;
  }
  for (int i = 0; i < snapshot->n; i++) {
    if (snapshot->rule[i].in_use && p0_br_wants_event_type(br->type, snapshot->rule[i].event_type) &&
        p0_ir_match_rule_to_br(&snapshot->rule[i], br)) {
      p0_ir_snapshot_release(snapshot);
      return 1;
    }
  }
  p0_ir_snapshot_release(snapshot);
  return 0;
}

int edr_p0_rule_ir_is_interesting_remote_port(uint32_t port) {
  p0_ir_candidate *snapshot;
  if (port == 0u) {
    return 0;
  }
  edr_p0_rule_ir_lazy_init();
  snapshot = p0_ir_snapshot_acquire();
  if (!snapshot || !snapshot->ready) {
    p0_ir_snapshot_release(snapshot);
    return 0;
  }
  for (int i = 0; i < snapshot->n; i++) {
    if (!snapshot->rule[i].in_use || strcmp(snapshot->rule[i].event_type, "network_connect") != 0) {
      continue;
    }
    for (int j = 0; j < snapshot->rule[i].n_rport; j++) {
      if ((uint32_t)snapshot->rule[i].rport[j] == port) {
        p0_ir_snapshot_release(snapshot);
        return 1;
      }
    }
  }
  p0_ir_snapshot_release(snapshot);
  return 0;
}

int edr_p0_rule_ir_is_interesting_process_name(const char *process_name) {
  p0_ir_candidate *snapshot;
  char lower[1024];
  if (!process_name || !process_name[0]) {
    return 0;
  }
  edr_p0_rule_ir_lazy_init();
  snapshot = p0_ir_snapshot_acquire();
  if (!snapshot || !snapshot->ready) {
    p0_ir_snapshot_release(snapshot);
    return 0;
  }
  ascii_lower_truncate(lower, sizeof(lower), process_name);
  for (int i = 0; i < snapshot->n; i++) {
    if (!snapshot->rule[i].in_use || snapshot->rule[i].n_name_in <= 0) {
      continue;
    }
    if (name_in_list(lower, (const char (*)[128])snapshot->rule[i].name_in, snapshot->rule[i].n_name_in)) {
      p0_ir_snapshot_release(snapshot);
      return 1;
    }
  }
  p0_ir_snapshot_release(snapshot);
  return 0;
}

int edr_p0_rule_ir_file_read_path_may_match(const char *path, uint64_t *out_snapshot_epoch) {
  p0_ir_candidate *snapshot;
  int result = 0;
  if (out_snapshot_epoch) {
    *out_snapshot_epoch = 0u;
  }
  edr_p0_rule_ir_lazy_init();
  snapshot = p0_ir_snapshot_acquire();
  if (!snapshot || !snapshot->ready || snapshot->epoch == 0u ||
      !edr_p0_rule_ir_artifact_healthy(NULL, 0u)) {
    p0_ir_snapshot_release(snapshot);
    return 1;
  }
  if (out_snapshot_epoch) {
    *out_snapshot_epoch = snapshot->epoch;
  }
  /* NameCreate without an exact, intact path is not a safe proof of a P0
   * miss. Keep it protected.  The optional epoch describes this evaluation
   * only; FileKey/path facts must never be invalidated merely by rule reload. */
  if (!path || !path[0]) {
    p0_ir_snapshot_release(snapshot);
    return 1;
  }
  for (int i = 0; i < snapshot->n; ++i) {
    const struct p0_ir_one *rule = &snapshot->rule[i];
    if (!rule->in_use || strcmp(rule->event_type, "file_read") != 0) {
      continue;
    }
    /* A file_read rule without a path predicate may match any NameCreate;
     * its process constraints are intentionally unknown at this stage. */
    if (rule->n_fpath == 0 ||
        any_pcre((pcre2_code *const *)rule->re_fpath, rule->n_fpath, path)) {
      result = 1;
      break;
    }
  }
  p0_ir_snapshot_release(snapshot);
  return result;
}

void edr_p0_rule_ir_stats_record(int rule_idx, int hit) {
  p0_ir_candidate *snapshot;
  int stats_enabled;
  if (rule_idx < 0) {
    return;
  }
  snapshot = p0_ir_snapshot_acquire();
  ir_write_lock();
  stats_enabled = s_stats_enabled;
  ir_write_unlock();
  if (!stats_enabled || !snapshot || !snapshot->ready || rule_idx >= snapshot->n) {
    p0_ir_snapshot_release(snapshot);
    return;
  }
  ir_write_lock();
  snapshot->rule_evaluate_count[rule_idx]++;
  if (hit) {
    snapshot->rule_hit_count[rule_idx]++;
  }
  ir_write_unlock();
  p0_ir_snapshot_release(snapshot);
}

void edr_p0_rule_ir_stats_dump(void) {
  p0_ir_candidate *snapshot;
  int stats_enabled;
  snapshot = p0_ir_snapshot_acquire();
  ir_write_lock();
  stats_enabled = s_stats_enabled;
  ir_write_unlock();
  if (!stats_enabled || !snapshot || !snapshot->ready) {
    p0_ir_snapshot_release(snapshot);
    return;
  }
  ir_write_lock();
  fprintf(stderr, "\n=== P0 Rule Statistics ===\n");
  fprintf(stderr, "%-12s %-10s %-10s %-8s %s\n", "Rule ID", "Evaluated", "Hits", "Hit Rate", "Event Type");
  fprintf(stderr, "----------------------------------------------------------------\n");
  for (int i = 0; i < snapshot->n; i++) {
    if (!snapshot->rule[i].in_use) continue;
    double hit_rate = snapshot->rule_evaluate_count[i] > 0
                          ? (double)snapshot->rule_hit_count[i] /
                                (double)snapshot->rule_evaluate_count[i] * 100.0
                          : 0.0;
    fprintf(stderr, "%-12s %-10llu %-10llu %-7.1f%% %s\n", snapshot->rule[i].id,
            (unsigned long long)snapshot->rule_evaluate_count[i],
            (unsigned long long)snapshot->rule_hit_count[i], hit_rate, snapshot->rule[i].event_type);
  }
  fprintf(stderr, "======================\n\n");
  ir_write_unlock();
  p0_ir_snapshot_release(snapshot);
}

void edr_p0_rule_ir_shutdown(void) {
  p0_ir_candidate *previous;
  int destroy_previous = 0;
  /* A concurrent staged candidate must not publish after shutdown.  This
   * serializes shutdown with preparation without holding the paired writer
   * across any I/O. */
  p0_ir_publication_lock();
  p0_ir_sensor_pair_write_lock();
  ir_write_lock();
  previous = s_active_candidate;
  p0_ir_sensor_pair_advance_locked();
  s_active_candidate = NULL;
  s_inited = 0;
  s_stats_enabled = 0;
  p0_ir_snapshot_retire_locked(previous, &destroy_previous);
  ir_write_unlock();
  p0_ir_sensor_pair_write_unlock();
  p0_ir_publication_unlock();
  if (destroy_previous) {
    p0_ir_candidate_destroy(previous);
    free(previous);
  }
}
