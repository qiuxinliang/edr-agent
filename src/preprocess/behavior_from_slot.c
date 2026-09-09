#include "edr/behavior_from_slot.h"

#include "edr/command.h"
#include "edr/policy_v2.h"
#include "edr/p0_source_only_contract.h"

#include <ctype.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <string.h>
#include <time.h>

#ifndef ATOMIC_VAR_INIT
#define ATOMIC_VAR_INIT(value) (value)
#endif

static atomic_uint_fast64_t g_event_seq = ATOMIC_VAR_INIT(0);
static atomic_uint_fast64_t g_event_boot_nonce = ATOMIC_VAR_INIT(0);

#define RANSOM_COUNTER_BUCKETS 128u
#define RANSOM_COUNTER_EXTS 24u
#define RANSOM_COUNTER_DIRS 16u
#define RANSOM_COUNTER_FILES 2048u
#define RANSOM_ADMISSION_BUCKETS 128u
#define RANSOM_ADMISSION_FILES 256u
#define RANSOM_ADMISSION_SAMPLE_FILES 64u
#define RANSOM_NOTE_BUCKETS 128u
#define RANSOM_NOTE_FILES 16u

typedef struct {
  uint64_t identity;
  uint16_t alias_index;
  int64_t last_sample_ns;
  float baseline_entropy;
  uint8_t sampled;
  uint8_t counted;
  uint8_t content_changed;
  uint8_t high_entropy;
} RansomFileObservation;

typedef struct {
  uint32_t pid;
  uint64_t process_start_key;
  uint64_t process_creation_time;
  char dir[256];
  int64_t window_start_ns;
  uint32_t file_events;
  uint32_t unique_files;
  uint32_t sampled_files;
  uint32_t content_changed_files;
  uint32_t high_entropy_events;
  char exts[RANSOM_COUNTER_EXTS][16];
  char dirs[RANSOM_COUNTER_DIRS][128];
  uint8_t ext_count;
  uint8_t dir_count;
  uint8_t emitted_level;
  int64_t last_signal_ns;
  uint32_t coalesced_events;
  RansomFileObservation files[RANSOM_COUNTER_FILES];
} RansomCounterBucket;

typedef struct {
  uint64_t identity;
  int64_t last_sample_ns;
  uint8_t sample_count;
  uint8_t sample_inflight;
  uint8_t sample_eligible;
} RansomAdmissionFile;

typedef struct {
  uint32_t pid;
  uint64_t process_start_key;
  int64_t window_start_ns;
  uint32_t file_events;
  uint32_t unique_files;
  uint16_t sample_files;
  uint8_t promoted;
  RansomAdmissionFile files[RANSOM_ADMISSION_FILES];
} RansomAdmissionBucket;

typedef struct {
  uint32_t pid;
  int64_t window_start_ns;
  uint32_t note_count;
  char files[RANSOM_NOTE_FILES][96];
} RansomNoteBucket;

static RansomCounterBucket g_ransom_buckets[RANSOM_COUNTER_BUCKETS];
static RansomAdmissionBucket g_ransom_admission_buckets[RANSOM_ADMISSION_BUCKETS];
static RansomNoteBucket g_ransom_note_buckets[RANSOM_NOTE_BUCKETS];
static atomic_flag g_ransom_admission_lock = ATOMIC_FLAG_INIT;

static int detail_token_value(const char *text, const char *key, char *out, size_t cap);

static int identity_value_present(const char *s) {
  if (!s) return 0;
  while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n') s++;
  if (*s == '-' && (s[1] == '\0' || s[1] == ' ' || s[1] == '\t' || s[1] == '\r' || s[1] == '\n')) return 0;
  return *s != '\0';
}

static int identity_sid_present(const char *s) {
  return identity_value_present(s) && strcmp(s, "S-1-0-0") != 0;
}

static int identity_logon_present(const char *s) {
  return identity_value_present(s) && strcmp(s, "0") != 0 &&
         strcmp(s, "0x0") != 0 && strcmp(s, "0X0") != 0;
}

static void edr_gen_event_id(char *out, size_t cap, int64_t time_ns) {
  uint64_t s = atomic_fetch_add_explicit(&g_event_seq, 1u, memory_order_relaxed) + 1u;
  uint64_t nonce = atomic_load_explicit(&g_event_boot_nonce, memory_order_acquire);
  if (nonce == 0u) {
    uint64_t candidate = ((uint64_t)clock() << 32u) ^ (uint64_t)(uintptr_t)&g_event_seq ^
                         ((uint64_t)time(NULL) << 17u);
    if (candidate == 0u) candidate = 1u;
    (void)atomic_compare_exchange_strong_explicit(&g_event_boot_nonce, &nonce, candidate,
                                                   memory_order_release, memory_order_acquire);
    nonce = atomic_load_explicit(&g_event_boot_nonce, memory_order_acquire);
  }
  snprintf(out, cap, "e-%llx-%llx-%llx", (unsigned long long)nonce,
           (unsigned long long)(uint64_t)time_ns, (unsigned long long)s);
}

static const char *basename_c(const char *path) {
  if (!path || !path[0]) {
    return "";
  }
  const char *p = path;
  for (const char *c = path; *c; c++) {
    if (*c == '\\' || *c == '/') {
      p = c + 1;
    }
  }
  return p;
}

static void first_cmd_token(const char *cmd, char *out, size_t cap) {
  if (!out || cap == 0u) {
    return;
  }
  out[0] = '\0';
  if (!cmd || !cmd[0]) {
    return;
  }
  while (*cmd == ' ' || *cmd == '\t') {
    cmd++;
  }
  char quote = 0;
  if (*cmd == '"' || *cmd == '\'') {
    quote = *cmd++;
  }
  size_t n = 0;
  while (*cmd && n + 1u < cap) {
    if (quote) {
      if (*cmd == quote) {
        break;
      }
    } else if (*cmd == ' ' || *cmd == '\t') {
      break;
    }
    out[n++] = *cmd++;
  }
  out[n] = '\0';
}

/* cmd.exe is the actor.  A batch file supplied to /c is a separate artifact;
 * never overwrite process_name/exe_path with it or P0 process identity drifts. */
static void cmd_script_artifact(const char *cmd, char *out, size_t cap) {
  const char *hit = NULL;
  if (!out || cap == 0u) return;
  out[0] = '\0';
  if (!cmd) return;
  for (const char *p = cmd; p[0] && p[1] && p[2] && p[3]; ++p) {
    if (p[0] == '.' && (p[1] == 'c' || p[1] == 'C') &&
        (p[2] == 'm' || p[2] == 'M') && (p[3] == 'd' || p[3] == 'D') &&
        (p[4] == '\0' || p[4] == ' ' || p[4] == '\t' || p[4] == '"')) { hit = p + 4; break; }
  }
  if (!hit) return;
  const char *begin = hit;
  while (begin > cmd && begin[-1] != ' ' && begin[-1] != '\t' && begin[-1] != '"') --begin;
  size_t n = (size_t)(hit - begin);
  if (n >= cap) n = cap - 1u;
  memcpy(out, begin, n); out[n] = '\0';
}

static int is_file_activity_event(EdrEventType t) {
  return t == EDR_EVENT_FILE_CREATE || t == EDR_EVENT_FILE_WRITE || t == EDR_EVENT_FILE_RENAME ||
         t == EDR_EVENT_FILE_DELETE;
}

static int has_ci_ascii(const char *hay, const char *needle);

static int file_path_has_root_or_separator(const char *path) {
  if (!path || !path[0]) {
    return 0;
  }
  if ((isalpha((unsigned char)path[0]) && path[1] == ':' && (path[2] == '\\' || path[2] == '/')) ||
      (path[0] == '\\' && path[1] == '\\') || (path[0] == '/' && path[1]) ||
      has_ci_ascii(path, "\\device\\") || has_ci_ascii(path, "\\??\\") ||
      has_ci_ascii(path, "\\global??\\")) {
    return 1;
  }
  return strchr(path, '\\') != NULL || strchr(path, '/') != NULL;
}

static int file_path_usable_for_ransom(const char *path) {
  if (!path || !path[0] || !file_path_has_root_or_separator(path)) {
    return 0;
  }
  const char *base = basename_c(path);
  if (!base || strlen(base) < 3u) {
    return 0;
  }
  size_t printable = 0u;
  size_t ascii = 0u;
  size_t len = 0u;
  for (const unsigned char *p = (const unsigned char *)path; *p && len < 512u; p++, len++) {
    if ((*p >= 0x20u && *p < 0x7fu) || *p >= 0x80u) {
      printable++;
    }
    if (*p < 0x80u) {
      ascii++;
    }
  }
  if (len == 0u || printable * 100u < len * 90u) {
    return 0;
  }
  return ascii > 0u;
}

static char fold_ascii(char c) {
  if (c == '/') {
    c = '\\';
  }
  return (char)tolower((unsigned char)c);
}

static int has_ci_ascii(const char *hay, const char *needle) {
  if (!needle || !needle[0]) {
    return 1;
  }
  if (!hay || !hay[0]) {
    return 0;
  }
  for (; *hay; hay++) {
    const char *a = hay;
    const char *b = needle;
    while (*a && *b && fold_ascii(*a) == fold_ascii(*b)) {
      a++;
      b++;
    }
    if (!*b) {
      return 1;
    }
  }
  return 0;
}

static int ransom_ci_equal(const char *a, const char *b) {
  if (!a || !b) {
    return 0;
  }
  while (*a && *b) {
    if (fold_ascii(*a) != fold_ascii(*b)) {
      return 0;
    }
    a++;
    b++;
  }
  return *a == '\0' && *b == '\0';
}

static int token_list_has_exact_ci_ascii(const char *list, const char *value) {
  if (!list || !list[0] || !value || !value[0]) {
    return 0;
  }
  const char *p = list;
  while (*p) {
    while (*p == ',' || *p == ';' || *p == '\n' || *p == '\r' || *p == '\t' || *p == ' ') {
      p++;
    }
    char tok[512];
    size_t n = 0u;
    while (*p && *p != ',' && *p != ';' && *p != '\n' && *p != '\r' && n + 1u < sizeof(tok)) {
      tok[n++] = *p++;
    }
    while (*p && *p != ',' && *p != ';' && *p != '\n' && *p != '\r') {
      p++;
    }
    while (n > 0u && (tok[n - 1u] == ' ' || tok[n - 1u] == '\t')) {
      n--;
    }
    tok[n] = '\0';
    if (tok[0] && ransom_ci_equal(tok, value)) {
      return 1;
    }
  }
  return 0;
}

static int policy_exact_value_match(const char *env_inline, const char *env_file, const char *value) {
  const char *list = getenv(env_inline);
  if (list && list[0] && token_list_has_exact_ci_ascii(list, value)) {
    return 1;
  }
  const char *file = getenv(env_file);
  if (file && file[0]) {
    FILE *f = fopen(file, "rb");
    if (f) {
      char buf[8192];
      size_t n = fread(buf, 1u, sizeof(buf) - 1u, f);
      fclose(f);
      buf[n] = '\0';
      if (token_list_has_exact_ci_ascii(buf, value)) {
        return 1;
      }
    }
  }
  return 0;
}

static int ransom_process_identity_match(const char *list, const EdrBehaviorRecord *r) {
  if (!list || !list[0] || !r) {
    return 0;
  }
  char first_cmd[EDR_BR_STR_LONG];
  first_cmd_token(r->cmdline, first_cmd, sizeof(first_cmd));
  const char *ids[] = {r->process_name, r->exe_path, basename_c(r->process_name), basename_c(r->exe_path),
                       basename_c(first_cmd), r->exe_hash};
  for (size_t i = 0; i < sizeof(ids) / sizeof(ids[0]); i++) {
    if (ids[i][0] && token_list_has_exact_ci_ascii(list, ids[i])) {
      return 1;
    }
  }
  return 0;
}

static int ransom_process_policy_match(const char *env_inline, const char *env_file, const char *fallback,
                                       const EdrBehaviorRecord *r) {
  const char *list = getenv(env_inline);
  if (ransom_process_identity_match(list, r)) {
    return 1;
  }
  const char *file = getenv(env_file);
  if (file && file[0]) {
    FILE *f = fopen(file, "rb");
    if (f) {
      char buf[8192];
      size_t n = fread(buf, 1u, sizeof(buf) - 1u, f);
      fclose(f);
      buf[n] = '\0';
      if (ransom_process_identity_match(buf, r)) {
        return 1;
      }
    }
  }
  return ransom_process_identity_match(fallback, r);
}

static int known_low_value_ransom_counter_process(const EdrBehaviorRecord *r) {
  const char *fallback =
      "taskmgr.exe,usoclient.exe,taskhostw.exe,ecagent.exe,checknetisolation.exe,conhost.exe,"
      "searchindexer.exe,searchprotocolhost.exe,searchfilterhost.exe";
  return ransom_process_policy_match("EDR_RANSOM_LOW_VALUE_PROCESSES",
                                    "EDR_RANSOM_LOW_VALUE_PROCESSES_FILE", fallback, r) ||
         ransom_process_policy_match("EDR_RANSOM_BULK_SAFE_PROCESSES",
                                    "EDR_RANSOM_BULK_SAFE_PROCESSES_FILE", "", r);
}

static int env_int_clamped(const char *name, int fallback, int lo, int hi) {
  const char *v = getenv(name);
  long n = v && v[0] ? strtol(v, NULL, 10) : (long)fallback;
  if (n < (long)lo) {
    n = (long)lo;
  }
  if (n > (long)hi) {
    n = (long)hi;
  }
  return (int)n;
}

static int ends_ci_ascii(const char *s, const char *suffix) {
  size_t a;
  size_t b;
  if (!s || !suffix) {
    return 0;
  }
  a = strlen(s);
  b = strlen(suffix);
  if (b == 0u || a < b) {
    return 0;
  }
  return has_ci_ascii(s + (a - b), suffix);
}

static uint32_t parse_token_elevation_type(const char *s) {
  if (!s || !s[0]) {
    return 0u;
  }
  if (strcmp(s, "%%1936") == 0) {
    return 1u; /* TokenElevationTypeDefault */
  }
  if (strcmp(s, "%%1937") == 0) {
    return 2u; /* TokenElevationTypeFull */
  }
  if (strcmp(s, "%%1938") == 0) {
    return 3u; /* TokenElevationTypeLimited */
  }
  if (has_ci_ascii(s, "default")) {
    return 1u;
  }
  if (has_ci_ascii(s, "full") || has_ci_ascii(s, "elevated")) {
    return 2u;
  }
  if (has_ci_ascii(s, "limited") || has_ci_ascii(s, "filtered")) {
    return 3u;
  }
  return (uint32_t)strtoul(s, NULL, 0);
}

static void dirname_c(const char *path, char *out, size_t cap) {
  if (!out || cap == 0u) {
    return;
  }
  out[0] = '\0';
  if (!path || !path[0]) {
    return;
  }
  const char *last = NULL;
  for (const char *p = path; *p; p++) {
    if (*p == '\\' || *p == '/') {
      last = p;
    }
  }
  if (!last) {
    snprintf(out, cap, "%s", ".");
    return;
  }
  size_t n = (size_t)(last - path);
  if (n >= cap) {
    n = cap - 1u;
  }
  memcpy(out, path, n);
  out[n] = '\0';
}

static void extension_c(const char *path, char *out, size_t cap) {
  if (!out || cap == 0u) {
    return;
  }
  out[0] = '\0';
  const char *b = basename_c(path);
  const char *dot = strrchr(b, '.');
  if (!dot || !dot[1]) {
    snprintf(out, cap, "%s", "<none>");
    return;
  }
  snprintf(out, cap, "%s", dot + 1);
}

static double path_entropy_score(const char *path) {
  const char *b = basename_c(path);
  if (!b || !b[0]) {
    return 0.0;
  }
  unsigned char seen[256];
  memset(seen, 0, sizeof(seen));
  size_t len = 0u;
  size_t uniq = 0u;
  for (const unsigned char *p = (const unsigned char *)b; *p && len < 160u; p++, len++) {
    if (!seen[*p]) {
      seen[*p] = 1u;
      uniq++;
    }
  }
  if (len == 0u) {
    return 0.0;
  }
  return ((double)uniq / (double)len) * 8.0;
}

static int file_content_entropy_sample(const char *path, double *out_entropy, size_t *out_bytes) {
  if (out_entropy) {
    *out_entropy = 0.0;
  }
  if (out_bytes) {
    *out_bytes = 0u;
  }
  if (!path || !path[0]) {
    return 0;
  }
  int cap = env_int_clamped("EDR_RANSOM_CONTENT_ENTROPY_SAMPLE_BYTES", 65536, 0, 1048576);
  if (cap <= 0) {
    return 0;
  }
  FILE *f = fopen(path, "rb");
  if (!f) {
    return 0;
  }
  unsigned long counts[256];
  memset(counts, 0, sizeof(counts));
  unsigned char buf[4096];
  size_t total = 0u;
  while (total < (size_t)cap) {
    size_t want = sizeof(buf);
    if ((size_t)cap - total < want) {
      want = (size_t)cap - total;
    }
    size_t n = fread(buf, 1u, want, f);
    if (n == 0u) {
      break;
    }
    for (size_t i = 0; i < n; i++) {
      counts[buf[i]]++;
    }
    total += n;
  }
  int read_failed = ferror(f);
  fclose(f);
  if (read_failed) {
    return 0;
  }
  if (out_bytes) {
    *out_bytes = total;
  }
  if (total == 0u) {
    return 0;
  }
  double entropy = 0.0;
  for (size_t i = 0; i < 256u; i++) {
    if (counts[i] == 0ul) {
      continue;
    }
    double p = (double)counts[i] / (double)total;
    entropy -= p * (log(p) / log(2.0));
  }
  if (out_entropy) {
    *out_entropy = entropy;
  }
  return 1;
}

static int should_sample_ransom_content_entropy(const RansomCounterBucket *b, int ext_changed, int canary) {
  if (canary) {
    return 1;
  }
  if (env_int_clamped("EDR_RANSOM_CONTENT_ENTROPY_ALWAYS", 0, 0, 1)) {
    return 1;
  }
  if (ext_changed && env_int_clamped("EDR_RANSOM_CONTENT_ENTROPY_ON_EXT_CHANGE", 1, 0, 1)) {
    return 1;
  }
  int min_events = env_int_clamped("EDR_RANSOM_CONTENT_ENTROPY_MIN_EVENTS", 6, 1, 200);
  return b && (int)b->file_events >= min_events;
}

static int64_t ransom_counter_summary_interval_ns(void) {
  return (int64_t)env_int_clamped("EDR_RANSOM_COUNTER_SUMMARY_S", 30, 5, 600) * 1000000000LL;
}

static RansomCounterBucket *ransom_bucket_for(const EdrBehaviorRecord *r, const char *dir, int64_t now_ns, int64_t window_ns) {
  RansomCounterBucket *empty = NULL;
  RansomCounterBucket *oldest = &g_ransom_buckets[0];
  uint32_t key_pid = r->pid ? r->pid : 1u;
  for (size_t i = 0; i < RANSOM_COUNTER_BUCKETS; i++) {
    RansomCounterBucket *b = &g_ransom_buckets[i];
    if (b->pid == key_pid) {
      if (b->window_start_ns <= 0 || now_ns < b->window_start_ns || now_ns - b->window_start_ns > window_ns ||
          b->process_start_key != r->process_start_key || b->process_creation_time != r->process_creation_filetime_100ns) {
        memset(b, 0, sizeof(*b));
        b->pid = key_pid;
        b->process_start_key = r->process_start_key;
        b->process_creation_time = r->process_creation_filetime_100ns;
        snprintf(b->dir, sizeof(b->dir), "%s", dir);
        b->window_start_ns = now_ns;
      }
      return b;
    }
    if (b->pid == 0u && !empty) {
      empty = b;
    }
    if (b->window_start_ns < oldest->window_start_ns) {
      oldest = b;
    }
  }
  RansomCounterBucket *b = empty ? empty : oldest;
  memset(b, 0, sizeof(*b));
  b->pid = key_pid;
  b->process_start_key = r->process_start_key;
  b->process_creation_time = r->process_creation_filetime_100ns;
  snprintf(b->dir, sizeof(b->dir), "%s", dir);
  b->window_start_ns = now_ns;
  return b;
}

static uint64_t ransom_path_identity(const char *path) {
  uint64_t hash = 1469598103934665603ULL;
  int windows_path = path[0] == '\\' || (path[0] && path[1] == ':');
  for (const unsigned char *p = (const unsigned char *)path; *p; ++p) {
    unsigned char c = *p;
    if (windows_path) {
      if (c == '/') c = '\\';
      if (c >= 'A' && c <= 'Z') c = (unsigned char)(c + ('a' - 'A'));
    }
    hash = (hash ^ c) * 1099511628211ULL;
  }
  return hash ? hash : 1u;
}

static void ransom_admission_lock(void) {
  while (atomic_flag_test_and_set_explicit(&g_ransom_admission_lock, memory_order_acquire)) {
  }
}

static void ransom_admission_unlock(void) {
  atomic_flag_clear_explicit(&g_ransom_admission_lock, memory_order_release);
}

static RansomAdmissionBucket *ransom_admission_bucket_for(const EdrBehaviorRecord *r,
                                                          int64_t now_ns,
                                                          int64_t window_ns) {
  RansomAdmissionBucket *empty = NULL;
  RansomAdmissionBucket *oldest = &g_ransom_admission_buckets[0];
  for (size_t i = 0; i < RANSOM_ADMISSION_BUCKETS; ++i) {
    RansomAdmissionBucket *b = &g_ransom_admission_buckets[i];
    if (b->pid == r->pid && b->process_start_key == r->process_start_key) {
      if (b->window_start_ns <= 0 || now_ns < b->window_start_ns ||
          now_ns - b->window_start_ns > window_ns) {
        memset(b, 0, sizeof(*b));
        b->pid = r->pid;
        b->process_start_key = r->process_start_key;
        b->window_start_ns = now_ns;
      }
      return b;
    }
    if (b->pid == 0u && !empty) empty = b;
    if (b->window_start_ns < oldest->window_start_ns) oldest = b;
  }
  RansomAdmissionBucket *b = empty ? empty : oldest;
  memset(b, 0, sizeof(*b));
  b->pid = r->pid;
  b->process_start_key = r->process_start_key;
  b->window_start_ns = now_ns;
  return b;
}

static RansomAdmissionFile *ransom_admission_file_for(RansomAdmissionBucket *b,
                                                      uint64_t identity,
                                                      int *added) {
  if (added) *added = 0;
  for (size_t i = 0; i < RANSOM_ADMISSION_FILES; ++i) {
    RansomAdmissionFile *f = &b->files[(identity + i) % RANSOM_ADMISSION_FILES];
    if (f->identity == identity) return f;
    if (!f->identity) {
      f->identity = identity;
      if (added) *added = 1;
      return f;
    }
  }
  return NULL;
}

static RansomAdmissionFile *ransom_admission_file_find(RansomAdmissionBucket *b,
                                                       uint64_t identity) {
  if (!b || !identity) return NULL;
  for (size_t i = 0; i < RANSOM_ADMISSION_FILES; ++i) {
    RansomAdmissionFile *f = &b->files[(identity + i) % RANSOM_ADMISSION_FILES];
    if (f->identity == identity) return f;
    if (!f->identity) return NULL;
  }
  return NULL;
}

static RansomFileObservation *ransom_file_observation(RansomCounterBucket *b, const EdrBehaviorRecord *r) {
  /* Create has no FileKey and the kernel can reuse a key after close. Only
   * an attributed Rename with a source path may join two path observations. */
  uint64_t hash = ransom_path_identity(r->file_path);
  for (size_t i = 0; i < RANSOM_COUNTER_FILES; ++i) {
    RansomFileObservation *f = &b->files[(hash + i) % RANSOM_COUNTER_FILES];
    if (!f->identity || f->identity == hash) {
      if (!f->identity && r->type == EDR_EVENT_FILE_RENAME && r->file_old_path[0]) {
        uint64_t old_hash = ransom_path_identity(r->file_old_path);
        for (size_t j = 0; j < RANSOM_COUNTER_FILES; ++j) {
          if (b->files[j].identity == old_hash) {
            f->alias_index = b->files[j].alias_index ? b->files[j].alias_index : (uint16_t)(j + 1u);
            break;
          }
        }
      }
      f->identity = hash;
      if (f->alias_index) f = &b->files[f->alias_index - 1u];
      return f;
    }
  }
  return NULL;
}

static int ext_seen_or_add(RansomCounterBucket *b, const char *ext) {
  if (!b || !ext || !ext[0]) {
    return 0;
  }
  for (uint8_t i = 0; i < b->ext_count; i++) {
    if (strcmp(b->exts[i], ext) == 0) {
      return 1;
    }
  }
  if (b->ext_count < RANSOM_COUNTER_EXTS) {
    snprintf(b->exts[b->ext_count], sizeof(b->exts[b->ext_count]), "%s", ext);
    b->ext_count++;
  }
  return 0;
}

static int dir_seen_or_add(RansomCounterBucket *b, const char *dir) {
  if (!b || !dir || !dir[0]) {
    return 0;
  }
  char compact[128];
  size_t n = 0u;
  while (*dir && n + 1u < sizeof(compact)) {
    char c = fold_ascii(*dir++);
    compact[n++] = c;
  }
  compact[n] = '\0';
  for (uint8_t i = 0; i < b->dir_count; i++) {
    if (strcmp(b->dirs[i], compact) == 0) {
      return 1;
    }
  }
  if (b->dir_count < RANSOM_COUNTER_DIRS) {
    snprintf(b->dirs[b->dir_count], sizeof(b->dirs[b->dir_count]), "%s", compact);
    b->dir_count++;
  }
  return 0;
}

static int note_file_seen_or_add(RansomNoteBucket *b, const char *path) {
  if (!b || !path || !path[0]) {
    return 0;
  }
  const char *base = basename_c(path);
  if (!base || !base[0]) {
    base = path;
  }
  char compact[96];
  size_t n = 0u;
  while (*base && n + 1u < sizeof(compact)) {
    char c = fold_ascii(*base++);
    if (c == ' ' || c == '\t' || c == '_' || c == '-') {
      c = '_';
    }
    compact[n++] = c;
  }
  compact[n] = '\0';
  for (uint32_t i = 0; i < b->note_count && i < RANSOM_NOTE_FILES; i++) {
    if (strcmp(b->files[i], compact) == 0) {
      return 1;
    }
  }
  if (b->note_count < RANSOM_NOTE_FILES) {
    snprintf(b->files[b->note_count], sizeof(b->files[b->note_count]), "%s", compact);
  }
  b->note_count++;
  return 0;
}

static int ransom_note_threshold(void) {
  const char *env = getenv("EDR_RANSOM_NOTE_MIN_FILES");
  long n = env && env[0] ? strtol(env, NULL, 10) : 2L;
  if (n < 2L) {
    n = 2L;
  }
  if (n > 10L) {
    n = 10L;
  }
  return (int)n;
}

static int64_t ransom_note_window_ns(void) {
  const char *env = getenv("EDR_RANSOM_NOTE_WINDOW_S");
  long sec = env && env[0] ? strtol(env, NULL, 10) : 300L;
  if (sec <= 0L) {
    sec = 300L;
  }
  if (sec > 3600L) {
    sec = 3600L;
  }
  return (int64_t)sec * 1000000000LL;
}

static int is_ransom_note_like_path(const char *path) {
  if (!path || !path[0]) {
    return 0;
  }
  const char *base = basename_c(path);
  int ext = ends_ci_ascii(base, ".txt") || ends_ci_ascii(base, ".hta") ||
            ends_ci_ascii(base, ".htm") || ends_ci_ascii(base, ".html");
  if (!ext) {
    return 0;
  }
  return has_ci_ascii(base, "readme") || has_ci_ascii(base, "read_me") ||
         has_ci_ascii(base, "read___me") || has_ci_ascii(base, "decrypt") ||
         has_ci_ascii(base, "encrypted") || has_ci_ascii(base, "recover") ||
         has_ci_ascii(base, "restore") || has_ci_ascii(base, "restore-files") ||
         has_ci_ascii(base, "restore_files") || has_ci_ascii(base, "get_your_files_back") ||
         has_ci_ascii(base, "help_instruction") || has_ci_ascii(base, "help_to_save_files") ||
         has_ci_ascii(base, "how_to_back") || has_ci_ascii(base, "how_to_restore") ||
         has_ci_ascii(base, "howtobackyourfiles") || has_ci_ascii(base, "howtorestoreyourfiles") ||
         has_ci_ascii(base, "return_files") || has_ci_ascii(base, "your_files_back") ||
         has_ci_ascii(base, "use_to_repair") || has_ci_ascii(base, "ransom");
}

static int is_ransom_canary_path(const char *path) {
  if (!path || !path[0]) {
    return 0;
  }
  /* Canary 必须由每台设备下发唯一完整路径；未配置时关闭确定性判定。 */
  return policy_exact_value_match("EDR_RANSOM_CANARY_PATH", "EDR_RANSOM_CANARY_PATH_FILE", path) ||
         policy_exact_value_match("EDR_RANSOM_CANARY_TOKENS", "EDR_RANSOM_CANARY_TOKENS_FILE", path);
}

static int ransom_signature_trusted(const EdrBehaviorRecord *r) {
  const char *s = r ? r->script_snippet : "";
  return has_ci_ascii(s, "signature_status=trusted") || has_ci_ascii(s, "signature_status=valid") ||
         has_ci_ascii(s, "signature_status=verified") || has_ci_ascii(s, "signature_status=ok") ||
         has_ci_ascii(s, "signed=1") || has_ci_ascii(s, "signed=true");
}

static int ransom_signer_allowlisted(const EdrBehaviorRecord *r) {
  if (!r) {
    return 0;
  }
  char signer[512];
  if (!detail_token_value(r->script_snippet, "signer", signer, sizeof(signer))) {
    return 0;
  }
  int signer_ok = policy_exact_value_match("EDR_RANSOM_SIGNER_ALLOWLIST",
                                           "EDR_RANSOM_SIGNER_ALLOWLIST_FILE", signer);
  if (!signer_ok) {
    return 0;
  }
  const char *path = r->exe_path[0] ? r->exe_path : r->process_name;
  int path_ok = policy_exact_value_match("EDR_RANSOM_SIGNED_PATH_ALLOWLIST",
                                         "EDR_RANSOM_SIGNED_PATH_ALLOWLIST_FILE", path);
  if (!path_ok) {
    return 0;
  }
  const char *require = getenv("EDR_RANSOM_REQUIRE_TRUSTED_SIGNATURE");
  if (require && require[0] && strcmp(require, "0") != 0 && !ransom_signature_trusted(r)) {
    return 0;
  }
  return 1;
}

static int ransom_counter_allowlisted(const EdrBehaviorRecord *r) {
  return ransom_process_policy_match("EDR_RANSOM_COUNTER_ALLOWLIST", "EDR_RANSOM_COUNTER_ALLOWLIST_FILE", "", r) ||
         ransom_signer_allowlisted(r);
}

static RansomNoteBucket *ransom_note_bucket_for(uint32_t pid, int64_t now_ns, int64_t window_ns) {
  RansomNoteBucket *empty = NULL;
  RansomNoteBucket *oldest = &g_ransom_note_buckets[0];
  for (size_t i = 0; i < RANSOM_NOTE_BUCKETS; i++) {
    RansomNoteBucket *b = &g_ransom_note_buckets[i];
    if (b->pid == pid) {
      if (b->window_start_ns <= 0 || now_ns - b->window_start_ns > window_ns) {
        memset(b, 0, sizeof(*b));
        b->pid = pid;
        b->window_start_ns = now_ns;
      }
      return b;
    }
    if (b->pid == 0u && !empty) {
      empty = b;
    }
    if (b->window_start_ns < oldest->window_start_ns) {
      oldest = b;
    }
  }
  RansomNoteBucket *b = empty ? empty : oldest;
  memset(b, 0, sizeof(*b));
  b->pid = pid ? pid : 1u;
  b->window_start_ns = now_ns;
  return b;
}

static void append_record_kv(EdrBehaviorRecord *r, const char *fmt, ...) {
  if (!r || !fmt) {
    return;
  }
  size_t l = strlen(r->script_snippet);
  if (l + 2u >= sizeof(r->script_snippet)) {
    return;
  }
  if (l > 0u) {
    r->script_snippet[l++] = ' ';
    r->script_snippet[l] = '\0';
  }
  va_list ap;
  va_start(ap, fmt);
  (void)vsnprintf(r->script_snippet + l, sizeof(r->script_snippet) - l, fmt, ap);
  va_end(ap);
}

int edr_behavior_file_activity_priority(EdrBehaviorRecord *r) {
  if (!r || !file_path_usable_for_ransom(r->file_path)) return -1;
  int mutation = r->type == EDR_EVENT_FILE_WRITE || r->type == EDR_EVENT_FILE_RENAME;
  if ((mutation || r->type == EDR_EVENT_FILE_DELETE) &&
      edr_policy_v2_ransomware_enabled("honey") &&
      (is_ransom_canary_path(r->file_path) ||
       (r->type == EDR_EVENT_FILE_RENAME && is_ransom_canary_path(r->file_old_path)))) {
    return 0;
  }
  if (!(mutation || r->type == EDR_EVENT_FILE_CREATE) ||
      !edr_policy_v2_ransomware_enabled("mass_write")) {
    return -1;
  }
  /* The real counter remains preprocess-owned. This small admission tracker
   * only protects a generation-bound candidate burst from the ordinary queue
   * reservation and captures bounded event-adjacent content snapshots. */
  if (!mutation || !r->pid || !r->process_start_key ||
      known_low_value_ransom_counter_process(r) || ransom_counter_allowlisted(r)) {
    return 1;
  }
  const char *window_value = getenv("EDR_RANSOM_COUNTER_WINDOW_S");
  long window_s = window_value && window_value[0] ? strtol(window_value, NULL, 10) : 60L;
  if (window_s <= 0L) window_s = 60L;
  if (window_s > 600L) window_s = 600L;
  int64_t now_ns = r->event_time_ns > 0 ? r->event_time_ns : 1;
  int64_t window_ns = (int64_t)window_s * 1000000000LL;
  uint64_t path_identity = ransom_path_identity(r->file_path);
  int should_sample = 0;
  int promoted = 0;

  ransom_admission_lock();
  RansomAdmissionBucket *b = ransom_admission_bucket_for(r, now_ns, window_ns);
  int added = 0;
  RansomAdmissionFile *file = ransom_admission_file_for(b, path_identity, &added);
  if (b->file_events < UINT32_MAX) b->file_events++;
  if (added) {
    if (b->unique_files < UINT32_MAX) b->unique_files++;
    if (file && b->sample_files < RANSOM_ADMISSION_SAMPLE_FILES) {
      file->sample_eligible = 1u;
      b->sample_files++;
    }
  }
  if (file && file->sample_eligible && !file->sample_inflight && file->sample_count < 4u &&
      (file->last_sample_ns <= 0 || now_ns < file->last_sample_ns ||
       now_ns - file->last_sample_ns >= 1000000000LL)) {
    file->sample_inflight = 1u;
    file->last_sample_ns = now_ns;
    should_sample = 1;
  }
  double elapsed_s = (double)(now_ns - b->window_start_ns) / 1000000000.0;
  if (elapsed_s < 1.0) elapsed_s = 1.0;
  if (!b->promoted && b->unique_files >= 20u &&
      ((double)b->unique_files * 60.0) / elapsed_s >= 120.0) {
    b->promoted = 1u;
  }
  promoted = b->promoted != 0u;
  ransom_admission_unlock();

  if (should_sample) {
    double entropy = 0.0;
    size_t sample_bytes = 0u;
    int sampled = file_content_entropy_sample(r->file_path, &entropy, &sample_bytes) &&
                  sample_bytes >= 512u;
    ransom_admission_lock();
    b = ransom_admission_bucket_for(r, now_ns, window_ns);
    file = ransom_admission_file_find(b, path_identity);
    if (file) {
      file->sample_inflight = 0u;
      if (sampled) {
        if (file->sample_count < UINT8_MAX) file->sample_count++;
      } else {
        file->last_sample_ns = 0;
      }
    }
    ransom_admission_unlock();
    if (sampled) {
      r->ransom_content_sampled = 1u;
      r->ransom_content_entropy = (float)entropy;
      r->ransom_content_sample_bytes = (uint32_t)sample_bytes;
      r->ransom_sample_process_start_key = r->process_start_key;
    }
  }
  return promoted ? 0 : 1;
}

void edr_behavior_enrich_file_activity(EdrBehaviorRecord *r) {
  int mass_write_enabled = edr_policy_v2_ransomware_enabled("mass_write");
  int honey_enabled = edr_policy_v2_ransomware_enabled("honey");
  if (!r || !is_file_activity_event(r->type) || !r->file_path[0]) {
    return;
  }
  if (r->file_activity_enriched) return;
  r->file_activity_enriched = 1u;
  if (r->kernel_file_activity &&
      (!r->file_actor_generation_validated || !r->pid || !r->process_start_key ||
       !r->process_creation_filetime_100ns || !r->exe_path[0])) {
    append_record_kv(r, "ransom_counter_suppressed=1 file_actor_unverified=1%s",
                     r->kernel_file_write ? " file_write_actor_unverified=1" : "");
    return;
  }
  if (!mass_write_enabled && !honey_enabled) {
    return;
  }
  if (!file_path_usable_for_ransom(r->file_path)) {
    append_record_kv(r, "invalid_file_path=1 ransom_counter_suppressed=1");
    return;
  }
  const char *env = getenv("EDR_RANSOM_COUNTER_WINDOW_S");
  long window_s = env && env[0] ? strtol(env, NULL, 10) : 60L;
  if (window_s <= 0L) {
    window_s = 60L;
  }
  if (window_s > 600L) {
    window_s = 600L;
  }
  int64_t now_ns = r->event_time_ns > 0 ? r->event_time_ns : 1;
  int64_t window_ns = (int64_t)window_s * 1000000000LL;
  char dir[256];
  char ext[16];
  dirname_c(r->file_path, dir, sizeof(dir));
  extension_c(r->file_path, ext, sizeof(ext));
  int ext_changed = has_ci_ascii(r->script_snippet, "ext_changed=1");
  int mutation = r->type == EDR_EVENT_FILE_WRITE || r->type == EDR_EVENT_FILE_RENAME;
  int canary = honey_enabled && (mutation || r->type == EDR_EVENT_FILE_DELETE) &&
      (is_ransom_canary_path(r->file_path) ||
       (r->type == EDR_EVENT_FILE_RENAME && is_ransom_canary_path(r->file_old_path)));
  if (canary) {
    append_record_kv(r, "ransom_canary=1 ransomware_kind=DETERMINISTIC_ENCRYPTION ransomware_severity=4");
  }
  if (!mass_write_enabled && !canary) {
    return;
  }
  if (!canary && known_low_value_ransom_counter_process(r)) {
    append_record_kv(r, "ransom_counter_suppressed=1 low_value_ransom_process=1");
    return;
  }
  if (!canary && ransom_counter_allowlisted(r)) {
    append_record_kv(r, "ransom_counter_allowlisted=1%s", ransom_signer_allowlisted(r) ? " ransom_signer_allowlisted=1" : "");
    return;
  }
  if ((mutation || r->type == EDR_EVENT_FILE_CREATE) && is_ransom_note_like_path(r->file_path)) {
    RansomNoteBucket *nb = ransom_note_bucket_for(r->pid ? r->pid : 1u, now_ns, ransom_note_window_ns());
    (void)note_file_seen_or_add(nb, r->file_path);
    append_record_kv(r, "ransom_note_count=%u%s", nb->note_count,
                     nb->note_count >= (uint32_t)ransom_note_threshold() ? " ransom_note_burst=1" : "");
  }
  if (r->type == EDR_EVENT_FILE_DELETE && !canary) {
    append_record_kv(r, "ransom_operation_context=1");
    return;
  }
  RansomCounterBucket *b = ransom_bucket_for(r, dir, now_ns, window_ns);
  RansomFileObservation *file = ransom_file_observation(b, r);
  if (!file && !canary) {
    append_record_kv(r, "ransom_tracking_saturated=1");
    return;
  }
  double content_entropy = 0.0;
  size_t content_sample = 0u;
  if (mutation) {
    if (b->file_events < UINT32_MAX) b->file_events++;
    if (file && !file->counted) {
      file->counted = 1;
      b->unique_files++;
      (void)ext_seen_or_add(b, ext);
      (void)dir_seen_or_add(b, dir);
    }
  }
  int admission_content_ok = r->ransom_content_sampled &&
      r->ransom_content_sample_bytes >= 512u && r->file_actor_generation_validated &&
      r->ransom_sample_process_start_key != 0u &&
      r->ransom_sample_process_start_key == r->process_start_key;
  int content_deferred = !file || r->type == EDR_EVENT_FILE_DELETE ||
      (!mutation && file->sampled) ||
      (!admission_content_ok && !should_sample_ransom_content_entropy(b, ext_changed, canary)) ||
      (!admission_content_ok && file->last_sample_ns > 0 &&
       now_ns - file->last_sample_ns < 1000000000LL && !ext_changed);
  int content_ok = 0;
  if (!content_deferred && admission_content_ok) {
    content_entropy = r->ransom_content_entropy;
    content_sample = r->ransom_content_sample_bytes;
    content_ok = 1;
  } else if (!content_deferred) {
    content_ok = file_content_entropy_sample(r->file_path, &content_entropy, &content_sample);
  }
  double entropy_delta = 0.0;
  int content_high = content_ok && content_entropy >= 7.20 && content_sample >= 512u;
  /* Create may arrive while overwrite has truncated the file to zero bytes.
   * An unusable baseline must not consume the following Write's sample slot.
   * Failed mutation reads still retain their per-file retry interval. */
  if (!content_deferred && (mutation || (content_ok && content_sample >= 512u)))
    file->last_sample_ns = now_ns;
  if (content_ok && content_sample >= 512u) {
    if (file->sampled) {
      /* Only a measured change of this same file is an entropy delta. */
      entropy_delta = content_entropy - file->baseline_entropy;
      if (entropy_delta < 0.0) entropy_delta = 0.0;
    } else {
      file->sampled = 1;
      file->baseline_entropy = (float)content_entropy;
      b->sampled_files++;
    }
    if (content_high && !file->high_entropy) {
      file->high_entropy = 1;
      b->high_entropy_events++;
    }
    if (mutation && content_high && entropy_delta >= 1.5 && !file->content_changed) {
      file->content_changed = 1;
      b->content_changed_files++;
    }
  }
  if (!mutation && !canary) {
    append_record_kv(r, "ransom_operation_context=1");
    return;
  }
  double elapsed_s = (double)(now_ns - b->window_start_ns) / 1000000000.0;
  if (elapsed_s < 1.0) {
    elapsed_s = 1.0;
  }
  double file_rate = ((double)b->unique_files * 60.0) / elapsed_s;
  int warn_files = env_int_clamped("EDR_RANSOM_RATE_WARN_FILES", 60, 8, 500);
  int confirm_files = env_int_clamped("EDR_RANSOM_RATE_CONFIRM_FILES", 200, 20, 2000);
  int warn_dirs = env_int_clamped("EDR_RANSOM_RATE_WARN_DIRS", 4, 1, 32);
  int confirm_dirs = env_int_clamped("EDR_RANSOM_RATE_CONFIRM_DIRS", 8, 1, 64);
  int enough_volume = b->unique_files >= 20u;
  int suspicious = (enough_volume && file_rate >= 120.0) ||
                   (b->unique_files >= 12u && b->ext_count >= 8u) ||
                   (b->unique_files >= 8u && entropy_delta >= 1.5) ||
                   (ext_changed && content_high) ||
                   ((int)b->unique_files >= warn_files &&
                    ((int)b->dir_count >= warn_dirs || b->ext_count >= 8u));
  double high_entropy_ratio = b->sampled_files > 0u ? (double)b->high_entropy_events / (double)b->sampled_files : 0.0;
  int content_changed = mutation && content_high && entropy_delta >= 1.5;
  int confirmed = canary ||
                  (content_changed && b->content_changed_files >= 20u &&
                   ((int)b->unique_files >= confirm_files || ext_changed || (int)b->dir_count >= confirm_dirs));
  uint8_t level = confirmed ? 2u : (suspicious ? 1u : 0u);
  /* Missing follow-up samples must not re-arm automatic response in the
   * same process-generation window after confirmation. */
  int state_changed = level > b->emitted_level;
  int periodic_summary = level > 0u && !state_changed && b->last_signal_ns > 0 &&
                         now_ns >= b->last_signal_ns &&
                         now_ns - b->last_signal_ns >= ransom_counter_summary_interval_ns();
  int emit_signal = state_changed || periodic_summary;
  if (emit_signal) {
    uint32_t coalesced = b->coalesced_events;
    if (level > b->emitted_level) b->emitted_level = level;
    b->last_signal_ns = now_ns;
    b->coalesced_events = 0u;
    append_record_kv(r,
                     "file_rate=%.0f ext_burst=%u dir_burst=%u entropy_delta=%.2f high_entropy_ratio=%.2f "
                     "path_entropy=%.2f content_entropy=%.2f content_sample_bytes=%u content_entropy_ok=%d "
                     "ransom_evidence_version=3 file_event_count=%u unique_file_count=%u sampled_file_count=%u "
                     "content_changed_file_count=%u confirmation_basis=%s "
                     "ransom_counter=1 ransom_counter_level=%u coalesced_events=%u%s%s%s%s",
                     file_rate, (unsigned)b->ext_count, (unsigned)b->dir_count, entropy_delta,
                     high_entropy_ratio, path_entropy_score(r->file_path), content_entropy, (unsigned)content_sample, content_ok ? 1 : 0,
                     b->file_events, b->unique_files, b->sampled_files, b->content_changed_files,
                     canary ? "canary_mutation" : (confirmed ? "content_change" : "none"),
                     (unsigned)level, (unsigned)coalesced,
                     content_deferred ? " content_entropy_deferred=1" : "",
                     state_changed ? " ransom_counter_transition=1" : "",
                     periodic_summary ? " ransom_counter_summary=1" : "",
                     confirmed ? " ransomware_kind=ENCRYPTION_CONFIRMED ransomware_severity=4" :
                     " ransomware_kind=ENCRYPTION_SUSPECTED ransomware_severity=3");
    if (admission_content_ok) {
      append_record_kv(r, "content_sample_source=collector_admission");
    }
    if (canary) {
      append_record_kv(r, "canary_counter_bypass=1");
    }
  } else if (level > 0u && b->coalesced_events < UINT32_MAX) {
    b->coalesced_events++;
  }

  if (confirmed && state_changed) {
    /* 确诊勒索:端侧处置(默认关,需显式启用自动隔离策略)。 */
    edr_isolate_auto_from_ransom_alarm(r);
  }
}

typedef struct {
  char prov[48];
  unsigned long eid;
  char img[EDR_BR_STR_LONG];
  char cmd[EDR_BR_STR_LONG];
  char file[EDR_BR_STR_LONG];
  char old_file[EDR_BR_STR_LONG];
  char signer[512];
  char signature_status[96];
  char qname[EDR_BR_STR_MID];
  char script[EDR_BR_STR_LONG];
  char url[EDR_BR_STR_MID];
  char sha256[80];
  char dst[64];
  char src[64];
  char score[32];
  char proto[48];
  char detector[32];
  char rule[96];
  char mitre[24];
  char forensic_kind[16];
  char pcap_stem[180];
  char pcap_status[24];
  char pcap_object_key[512];
  char preview_hex[256];
  char webshell_service[128];
  char webshell_action[64];
  char webshell_alert_id[96];
  char webshell_file_fp[80];
  char webshell_file_uploaded[16];
  char webshell_object_key[512];
  char webshell_local_path[1024];
  char webshell_ast_score[32];
  char webshell_token_score[32];
  char ring_trigger_slot[24];
  char ring_oldest_ns[28];
  char ring_newest_ns[28];
  char ring_span_ns[28];
  char shellcode_json[512];
  char attrib_schema[64];
  char attrib_cve[64];
  char attrib_family[96];
  char attrib_product[96];
  char attrib_vector[48];
  char attrib_confidence[24];
  char attrib_source[32];
  char attrib_basis[160];
  char sensor_detail[2048];
  char fw_id[96];
  char fw_rule[256];
  char fw_mod[512];
  char regkey[1024];
  char regname[512];
  char regdata[8192];
  char regold[2048];
  char regop[64];
  char regsource[48];
  char regattribution[32];
  char regstatus[48];
  char user[256];
  char domain[256];
  char user_sid[256];
  char logon_id[64];
  char creator_user[256];
  char creator_domain[256];
  char creator_sid[256];
  char creator_logon_id[64];
  char parent_img[EDR_BR_STR_LONG];
  char parent_cmdline[EDR_BR_STR_LONG];
  char cwd[EDR_BR_STR_LONG];
  char integrity[64];
  char token_elevation[64];
  char process_creation_time[96];
  uint64_t process_start_key;
  uint64_t process_creation_filetime_100ns;
  uint64_t file_key;
  char process_generation_source[64];
  char image_raw[EDR_BR_STR_LONG];
  char image_canonical[EDR_BR_STR_LONG];
  char image_namespace[32];
  char image_resolution_status[32];
  char image_resolution_source[32];
  char source_completeness[32];
  char collector_evidence_gate[64];
  char collector_evidence_reason[96];
  char collector_event_id[EDR_BR_ID_LEN];
  unsigned long evidence_revision;
  uint64_t truncation_mask;
  int has_fw;
  unsigned long forensic_frames;
  int has_forensic_frames;
  int has_ring_meta;
  uint8_t cert_revoked_ancestor;
  int has_cert_revoked_ancestor;
  unsigned long pid;
  unsigned long epid;
  unsigned long ppid;
  unsigned long dport;
  unsigned long sport;
  int has_img;
  int has_cmd;
  int has_dport;
  int has_sport;
  int has_parent_img;
  int has_parent_cmdline;
  int has_cwd;
  int has_integrity;
  int has_token_elevation;
  int has_process_creation_time;
  int has_process_start_key;
  int has_process_creation_filetime;
  int has_process_generation_source;
  int has_file_key;
} Etw1Fields;

static void etw1_clear(Etw1Fields *f) { memset(f, 0, sizeof(*f)); }

enum {
  EDR_ETW_TRUNC_IMAGE = 1ull << 0,
  EDR_ETW_TRUNC_IMAGE_RAW = 1ull << 1,
  EDR_ETW_TRUNC_IMAGE_CANONICAL = 1ull << 2,
  EDR_ETW_TRUNC_CMDLINE = 1ull << 3,
  EDR_ETW_TRUNC_USERNAME = 1ull << 4,
  EDR_ETW_TRUNC_DOMAIN = 1ull << 5,
  EDR_ETW_TRUNC_USER_SID = 1ull << 6,
  EDR_ETW_TRUNC_LOGON_ID = 1ull << 7,
  EDR_ETW_TRUNC_CREATOR_USERNAME = 1ull << 8,
  EDR_ETW_TRUNC_CREATOR_DOMAIN = 1ull << 9,
  EDR_ETW_TRUNC_CREATOR_SID = 1ull << 10,
  EDR_ETW_TRUNC_CREATOR_LOGON_ID = 1ull << 11,
  EDR_ETW_TRUNC_PARENT_IMAGE = 1ull << 12,
  EDR_ETW_TRUNC_PARENT_CMDLINE = 1ull << 13,
  EDR_ETW_TRUNC_CURRENT_DIRECTORY = 1ull << 14,
  EDR_ETW_TRUNC_INTEGRITY = 1ull << 15,
  EDR_ETW_TRUNC_TOKEN_ELEVATION = 1ull << 16,
  EDR_ETW_TRUNC_PROCESS_CREATION_TIME = 1ull << 17,
  EDR_ETW_TRUNC_PROCESS_GENERATION_SOURCE = 1ull << 18,
  EDR_ETW_TRUNC_SOURCE_COMPLETENESS = 1ull << 19,
  EDR_ETW_TRUNC_FILE_PATH = 1ull << 20,
  EDR_ETW_TRUNC_OLD_FILE_PATH = 1ull << 21,
  EDR_ETW_TRUNC_EXE_HASH = 1ull << 22,
  EDR_ETW_TRUNC_NET_PROTO = 1ull << 23,
  EDR_ETW_TRUNC_REG_OP = 1ull << 24,
  EDR_ETW_TRUNC_IMAGE_NAMESPACE = 1ull << 25,
  EDR_ETW_TRUNC_IMAGE_RESOLUTION_STATUS = 1ull << 26,
  EDR_ETW_TRUNC_IMAGE_RESOLUTION_SOURCE = 1ull << 27,
  EDR_ETW_TRUNC_REG_KEY_PATH = 1ull << 28,
  EDR_ETW_TRUNC_REG_VALUE_NAME = 1ull << 29,
  EDR_ETW_TRUNC_REG_OLD_VALUE_DATA = 1ull << 30,
  EDR_ETW_TRUNC_DNS_QUERY = 1ull << 31,
};

static int copy_text_exact(char *dst, size_t cap, const char *src) {
  size_t len;
  if (!dst || cap == 0u) {
    return 0;
  }
  dst[0] = '\0';
  if (!src) {
    return 1;
  }
  len = strlen(src);
  if (len >= cap) {
    return 0;
  }
  if (len > 0u) {
    memcpy(dst, src, len);
  }
  dst[len] = '\0';
  return 1;
}

static int etw1_copy_text(Etw1Fields *f, char *dst, size_t cap, const char *src,
                          uint64_t truncation_bit) {
  if (copy_text_exact(dst, cap, src)) {
    return 1;
  }
  if (f) {
    f->truncation_mask |= truncation_bit;
  }
  return 0;
}

static int comma_list_has_exact(const char *list, const char *item) {
  const char *start;
  size_t item_len;
  if (!list || !item || !item[0]) {
    return 0;
  }
  item_len = strlen(item);
  start = list;
  while (*start) {
    const char *end = strchr(start, ',');
    size_t len = end ? (size_t)(end - start) : strlen(start);
    if (len == item_len && memcmp(start, item, len) == 0) {
      return 1;
    }
    if (!end) {
      break;
    }
    start = end + 1;
  }
  return 0;
}

static void mark_source_truncation(EdrBehaviorRecord *r, const char *field) {
  static const char prefix[] = "source.";
  static const char overflow[] = "source.list_overflow";
  char item[64];
  size_t field_len;
  size_t item_len;
  size_t used;
  if (!r || !field || !field[0]) {
    return;
  }
  (void)copy_text_exact(r->source_completeness, sizeof(r->source_completeness), "TRUNCATED");
  field_len = strlen(field);
  if (field_len + sizeof(prefix) > sizeof(item)) {
    (void)copy_text_exact(r->source_truncated_fields,
                          sizeof(r->source_truncated_fields), overflow);
    return;
  }
  memcpy(item, prefix, sizeof(prefix) - 1u);
  memcpy(item + sizeof(prefix) - 1u, field, field_len + 1u);
  if (comma_list_has_exact(r->source_truncated_fields, item)) {
    return;
  }
  item_len = strlen(item);
  used = strlen(r->source_truncated_fields);
  if (used + (used ? 1u : 0u) + item_len < sizeof(r->source_truncated_fields)) {
    if (used > 0u) {
      r->source_truncated_fields[used++] = ',';
    }
    memcpy(r->source_truncated_fields + used, item, item_len + 1u);
    return;
  }
  if (comma_list_has_exact(r->source_truncated_fields, overflow)) {
    return;
  }
  item_len = sizeof(overflow) - 1u;
  if (used + (used ? 1u : 0u) + item_len < sizeof(r->source_truncated_fields)) {
    if (used > 0u) {
      r->source_truncated_fields[used++] = ',';
    }
    memcpy(r->source_truncated_fields + used, overflow, item_len + 1u);
  } else {
    /* A bounded list must never look complete after it runs out of room. */
    (void)copy_text_exact(r->source_truncated_fields,
                          sizeof(r->source_truncated_fields), overflow);
  }
}

static int copy_record_source_text(EdrBehaviorRecord *r, char *dst, size_t cap,
                                   const char *src, const char *field) {
  if (copy_text_exact(dst, cap, src)) {
    return 1;
  }
  mark_source_truncation(r, field);
  return 0;
}

static int copy_record_username(EdrBehaviorRecord *r, const char *domain, const char *user) {
  size_t domain_len;
  size_t user_len;
  if (!r || !user) {
    return 0;
  }
  if (!domain || !domain[0]) {
    return copy_record_source_text(r, r->username, sizeof(r->username), user, "username");
  }
  domain_len = strlen(domain);
  user_len = strlen(user);
  r->username[0] = '\0';
  if (domain_len + 1u >= sizeof(r->username) ||
      user_len >= sizeof(r->username) - domain_len - 1u) {
    mark_source_truncation(r, "username");
    return 0;
  }
  memcpy(r->username, domain, domain_len);
  r->username[domain_len] = '\\';
  memcpy(r->username + domain_len + 1u, user, user_len + 1u);
  return 1;
}

static void mark_etw1_input_truncations(EdrBehaviorRecord *r, uint64_t mask) {
  if (mask & EDR_ETW_TRUNC_IMAGE) {
    mark_source_truncation(r, "exe_path");
    mark_source_truncation(r, "process_name");
    mark_source_truncation(r, "image_path_raw");
  }
  if (mask & EDR_ETW_TRUNC_IMAGE_RAW) mark_source_truncation(r, "image_path_raw");
  if (mask & EDR_ETW_TRUNC_IMAGE_CANONICAL) mark_source_truncation(r, "image_path_canonical");
  if (mask & EDR_ETW_TRUNC_IMAGE_NAMESPACE) mark_source_truncation(r, "image_path_namespace");
  if (mask & EDR_ETW_TRUNC_IMAGE_RESOLUTION_STATUS) {
    mark_source_truncation(r, "image_path_resolution_status");
  }
  if (mask & EDR_ETW_TRUNC_IMAGE_RESOLUTION_SOURCE) {
    mark_source_truncation(r, "image_path_resolution_source");
  }
  if (mask & EDR_ETW_TRUNC_CMDLINE) mark_source_truncation(r, "cmdline");
  if (mask & EDR_ETW_TRUNC_USERNAME) mark_source_truncation(r, "username");
  if (mask & EDR_ETW_TRUNC_DOMAIN) mark_source_truncation(r, "domain");
  if (mask & EDR_ETW_TRUNC_USER_SID) mark_source_truncation(r, "user_sid");
  if (mask & EDR_ETW_TRUNC_LOGON_ID) mark_source_truncation(r, "logon_id");
  if (mask & EDR_ETW_TRUNC_CREATOR_USERNAME) mark_source_truncation(r, "creator_username");
  if (mask & EDR_ETW_TRUNC_CREATOR_DOMAIN) mark_source_truncation(r, "creator_domain");
  if (mask & EDR_ETW_TRUNC_CREATOR_SID) mark_source_truncation(r, "creator_sid");
  if (mask & EDR_ETW_TRUNC_CREATOR_LOGON_ID) mark_source_truncation(r, "creator_logon_id");
  if (mask & EDR_ETW_TRUNC_PARENT_IMAGE) {
    mark_source_truncation(r, "parent_path");
    mark_source_truncation(r, "parent_name");
  }
  if (mask & EDR_ETW_TRUNC_PARENT_CMDLINE) mark_source_truncation(r, "parent_cmdline");
  if (mask & EDR_ETW_TRUNC_CURRENT_DIRECTORY) mark_source_truncation(r, "current_directory");
  if (mask & EDR_ETW_TRUNC_INTEGRITY) mark_source_truncation(r, "integrity_level");
  if (mask & EDR_ETW_TRUNC_TOKEN_ELEVATION) mark_source_truncation(r, "token_elevation");
  if (mask & EDR_ETW_TRUNC_PROCESS_CREATION_TIME) {
    mark_source_truncation(r, "process_creation_time");
  }
  if (mask & EDR_ETW_TRUNC_PROCESS_GENERATION_SOURCE) {
    mark_source_truncation(r, "process_generation_source");
  }
  if (mask & EDR_ETW_TRUNC_SOURCE_COMPLETENESS) {
    mark_source_truncation(r, "source_completeness");
  }
  if (mask & EDR_ETW_TRUNC_FILE_PATH) mark_source_truncation(r, "file_path");
  if (mask & EDR_ETW_TRUNC_OLD_FILE_PATH) mark_source_truncation(r, "old_file_path");
  if (mask & EDR_ETW_TRUNC_EXE_HASH) mark_source_truncation(r, "exe_hash");
  if (mask & EDR_ETW_TRUNC_NET_PROTO) mark_source_truncation(r, "net_proto");
  if (mask & EDR_ETW_TRUNC_REG_OP) mark_source_truncation(r, "reg_op");
  if (mask & EDR_ETW_TRUNC_REG_KEY_PATH) mark_source_truncation(r, "reg_key_path");
  if (mask & EDR_ETW_TRUNC_REG_VALUE_NAME) mark_source_truncation(r, "reg_value_name");
  if (mask & EDR_ETW_TRUNC_REG_OLD_VALUE_DATA) {
    mark_source_truncation(r, "reg_old_value_data");
  }
  if (mask & EDR_ETW_TRUNC_DNS_QUERY) mark_source_truncation(r, "dns_query");
}

static void append_sensor_kv(Etw1Fields *f, const char *key, const char *val) {
  if (!f || !key || !key[0] || !val || !val[0]) {
    return;
  }
  size_t l = strlen(f->sensor_detail);
  if (l + 4u >= sizeof(f->sensor_detail)) {
    return;
  }
  if (l > 0u) {
    f->sensor_detail[l++] = ' ';
    f->sensor_detail[l] = '\0';
  }
  int n = snprintf(f->sensor_detail + l, sizeof(f->sensor_detail) - l, "%s=", key);
  if (n <= 0 || (size_t)n >= sizeof(f->sensor_detail) - l) {
    return;
  }
  l += (size_t)n;
  while (*val && l + 1u < sizeof(f->sensor_detail)) {
    char c = *val++;
    if (c == '\r' || c == '\n' || c == '\t' || c == ' ') {
      c = '_';
    }
    f->sensor_detail[l++] = c;
  }
  f->sensor_detail[l] = '\0';
}

static unsigned long parse_ulong_auto(const char *val) {
  if (!val) {
    return 0ul;
  }
  return strtoul(val, NULL, 0);
}

static int detail_token_value(const char *text, const char *key, char *out, size_t cap) {
  if (!text || !key || !out || cap == 0u) {
    return 0;
  }
  out[0] = '\0';
  size_t kl = strlen(key);
  for (const char *p = text; *p; p++) {
    if ((p == text || p[-1] == ' ' || p[-1] == '\n' || p[-1] == '|') && strncmp(p, key, kl) == 0 && p[kl] == '=') {
      const char *v = p + kl + 1u;
      size_t n = 0u;
      while (v[n] && v[n] != ' ' && v[n] != '\n' && v[n] != '\r' && v[n] != '|') {
        n++;
      }
      if (n >= cap) {
        n = cap - 1u;
      }
      memcpy(out, v, n);
      out[n] = '\0';
      return out[0] != '\0';
    }
  }
  return 0;
}

static int ipv4_decimal_to_dotted_le(const char *val, char *out, size_t cap) {
  if (!val || !val[0] || !out || cap == 0u) {
    return 0;
  }
  for (const unsigned char *p = (const unsigned char *)val; *p; p++) {
    if (!isdigit(*p)) {
      return 0;
    }
  }
  char *end = NULL;
  unsigned long n = strtoul(val, &end, 10);
  if (!end || *end != '\0' || n == 0ul || n > 0xfffffffful) {
    return 0;
  }
  unsigned int b0 = (unsigned int)(n & 0xfful);
  unsigned int b1 = (unsigned int)((n >> 8) & 0xfful);
  unsigned int b2 = (unsigned int)((n >> 16) & 0xfful);
  unsigned int b3 = (unsigned int)((n >> 24) & 0xfful);
  int w = snprintf(out, cap, "%u.%u.%u.%u", b0, b1, b2, b3);
  return w > 0 && (size_t)w < cap;
}

static void normalize_ip_field_copy(char *out, size_t cap, const char *val) {
  if (!out || cap == 0u) {
    return;
  }
  if (!val) {
    out[0] = '\0';
    return;
  }
  if (!ipv4_decimal_to_dotted_le(val, out, cap)) {
    snprintf(out, cap, "%s", val);
  }
}

static void append_snippet_kv(char *dst, size_t cap, const char *key, const char *val) {
  if (!dst || cap == 0u || !key || !key[0] || !val || !val[0]) {
    return;
  }
  if (strcmp(val, "-") == 0) {
    return;
  }
  size_t l = strlen(dst);
  if (l + 4u >= cap) {
    return;
  }
  int n = snprintf(dst + l, cap - l, "%s%s=", l > 0u ? " " : "", key);
  if (n <= 0 || (size_t)n >= cap - l) {
    return;
  }
  l += (size_t)n;
  for (const char *p = val; *p && l + 1u < cap; p++) {
    char c = *p;
    if (c == '\r' || c == '\n' || c == '\t' || c == ' ') {
      c = '_';
    }
    dst[l++] = c;
  }
  dst[l] = '\0';
}

static void apply_kv(Etw1Fields *f, const char *key, const char *val) {
  if (!key || !val) {
    return;
  }
  if (strcmp(key, "prov") == 0) {
    snprintf(f->prov, sizeof(f->prov), "%s", val);
  } else if (strcmp(key, "eid") == 0) {
    f->eid = parse_ulong_auto(val);
  } else if (strcmp(key, "pid") == 0) {
    f->pid = parse_ulong_auto(val);
  } else if (strcmp(key, "epid") == 0) {
    f->epid = parse_ulong_auto(val);
  } else if (strcmp(key, "hint_pid") == 0) {
    f->epid = parse_ulong_auto(val);
  } else if (strcmp(key, "ppid") == 0) {
    f->ppid = parse_ulong_auto(val);
  } else if (strcmp(key, "user") == 0 || strcmp(key, "username") == 0) {
    (void)etw1_copy_text(f, f->user, sizeof(f->user), val, EDR_ETW_TRUNC_USERNAME);
  } else if (strcmp(key, "user_sid") == 0 || strcmp(key, "target_user_sid") == 0) {
    (void)etw1_copy_text(f, f->user_sid, sizeof(f->user_sid), val, EDR_ETW_TRUNC_USER_SID);
  } else if (strcmp(key, "logon_id") == 0 || strcmp(key, "target_logon_id") == 0) {
    (void)etw1_copy_text(f, f->logon_id, sizeof(f->logon_id), val, EDR_ETW_TRUNC_LOGON_ID);
  } else if (strcmp(key, "user_domain") == 0 || strcmp(key, "subject_domain") == 0) {
    (void)etw1_copy_text(f, f->domain, sizeof(f->domain), val, EDR_ETW_TRUNC_DOMAIN);
  } else if (strcmp(key, "creator_user") == 0) {
    (void)etw1_copy_text(f, f->creator_user, sizeof(f->creator_user), val,
                         EDR_ETW_TRUNC_CREATOR_USERNAME);
  } else if (strcmp(key, "creator_domain") == 0) {
    (void)etw1_copy_text(f, f->creator_domain, sizeof(f->creator_domain), val,
                         EDR_ETW_TRUNC_CREATOR_DOMAIN);
  } else if (strcmp(key, "creator_sid") == 0) {
    (void)etw1_copy_text(f, f->creator_sid, sizeof(f->creator_sid), val,
                         EDR_ETW_TRUNC_CREATOR_SID);
  } else if (strcmp(key, "creator_logon_id") == 0) {
    (void)etw1_copy_text(f, f->creator_logon_id, sizeof(f->creator_logon_id), val,
                         EDR_ETW_TRUNC_CREATOR_LOGON_ID);
  } else if (strcmp(key, "parent_img") == 0 || strcmp(key, "parent_path") == 0) {
    f->has_parent_img = etw1_copy_text(f, f->parent_img, sizeof(f->parent_img), val,
                                       EDR_ETW_TRUNC_PARENT_IMAGE);
  } else if (strcmp(key, "parent_cmdline") == 0 || strcmp(key, "parent_cmd") == 0) {
    f->has_parent_cmdline = etw1_copy_text(f, f->parent_cmdline, sizeof(f->parent_cmdline), val,
                                           EDR_ETW_TRUNC_PARENT_CMDLINE);
  } else if (strcmp(key, "current_directory") == 0 || strcmp(key, "cwd") == 0) {
    f->has_cwd = etw1_copy_text(f, f->cwd, sizeof(f->cwd), val,
                                 EDR_ETW_TRUNC_CURRENT_DIRECTORY);
  } else if (strcmp(key, "integrity") == 0 || strcmp(key, "mandatory_label") == 0) {
    f->has_integrity = etw1_copy_text(f, f->integrity, sizeof(f->integrity), val,
                                       EDR_ETW_TRUNC_INTEGRITY);
  } else if (strcmp(key, "token_elevation") == 0 || strcmp(key, "token_elevation_type") == 0) {
    f->has_token_elevation = etw1_copy_text(f, f->token_elevation, sizeof(f->token_elevation), val,
                                             EDR_ETW_TRUNC_TOKEN_ELEVATION);
  } else if (strcmp(key, "process_start_key") == 0) {
    char *end = NULL;
    unsigned long long value = strtoull(val, &end, 0);
    if (end && *end == '\0' && value != 0u) {
      f->process_start_key = (uint64_t)value;
      f->has_process_start_key = 1;
    }
  } else if (strcmp(key, "process_creation_filetime_100ns") == 0 ||
             strcmp(key, "create_filetime_100ns") == 0) {
    char *end = NULL;
    unsigned long long value = strtoull(val, &end, 0);
    if (end && *end == '\0' && value != 0u) {
      f->process_creation_filetime_100ns = (uint64_t)value;
      f->has_process_creation_filetime = 1;
    }
  } else if (strcmp(key, "process_creation_time") == 0 || strcmp(key, "create_time") == 0) {
    f->has_process_creation_time = etw1_copy_text(
        f, f->process_creation_time, sizeof(f->process_creation_time), val,
        EDR_ETW_TRUNC_PROCESS_CREATION_TIME);
  } else if (strcmp(key, "process_generation_source") == 0) {
    f->has_process_generation_source = etw1_copy_text(
        f, f->process_generation_source, sizeof(f->process_generation_source), val,
        EDR_ETW_TRUNC_PROCESS_GENERATION_SOURCE);
  } else if (strcmp(key, "img") == 0) {
    f->has_img = etw1_copy_text(f, f->img, sizeof(f->img), val, EDR_ETW_TRUNC_IMAGE);
  } else if (strcmp(key, "img_raw") == 0) {
    (void)etw1_copy_text(f, f->image_raw, sizeof(f->image_raw), val, EDR_ETW_TRUNC_IMAGE_RAW);
  } else if (strcmp(key, "img_canonical") == 0) {
    (void)etw1_copy_text(f, f->image_canonical, sizeof(f->image_canonical), val,
                         EDR_ETW_TRUNC_IMAGE_CANONICAL);
  } else if (strcmp(key, "img_namespace") == 0) {
    (void)etw1_copy_text(f, f->image_namespace, sizeof(f->image_namespace), val,
                         EDR_ETW_TRUNC_IMAGE_NAMESPACE);
  } else if (strcmp(key, "img_resolution_status") == 0) {
    (void)etw1_copy_text(f, f->image_resolution_status, sizeof(f->image_resolution_status), val,
                         EDR_ETW_TRUNC_IMAGE_RESOLUTION_STATUS);
  } else if (strcmp(key, "img_resolution_source") == 0) {
    (void)etw1_copy_text(f, f->image_resolution_source, sizeof(f->image_resolution_source), val,
                         EDR_ETW_TRUNC_IMAGE_RESOLUTION_SOURCE);
  } else if (strcmp(key, "source_completeness") == 0) {
    (void)etw1_copy_text(f, f->source_completeness, sizeof(f->source_completeness), val,
                         EDR_ETW_TRUNC_SOURCE_COMPLETENESS);
  } else if (strcmp(key, "file_key") == 0) {
    char *end = NULL;
    unsigned long long value = strtoull(val, &end, 0);
    if (end && *end == '\0' && value != 0u) {
      f->file_key = (uint64_t)value;
      f->has_file_key = 1;
    }
  } else if (strcmp(key, "collector_evidence_gate") == 0) {
    snprintf(f->collector_evidence_gate, sizeof(f->collector_evidence_gate), "%s", val);
  } else if (strcmp(key, "collector_evidence_reason") == 0) {
    snprintf(f->collector_evidence_reason, sizeof(f->collector_evidence_reason), "%s", val);
  } else if (strcmp(key, "collector_event_id") == 0) {
    snprintf(f->collector_event_id, sizeof(f->collector_event_id), "%s", val);
  } else if (strcmp(key, "evidence_revision") == 0) {
    f->evidence_revision = parse_ulong_auto(val);
  } else if (strcmp(key, "cmd") == 0) {
    f->has_cmd = etw1_copy_text(f, f->cmd, sizeof(f->cmd), val, EDR_ETW_TRUNC_CMDLINE);
  } else if (strcmp(key, "cmd_id") == 0 || strcmp(key, "alert_id") == 0 ||
             strcmp(key, "pmfe_recommended") == 0 || strcmp(key, "pmfe_trigger") == 0 ||
             strcmp(key, "followup_only") == 0 ||
             strcmp(key, "source_alert_id") == 0 || strcmp(key, "pmfe_status") == 0 ||
             strcmp(key, "pmfe_verdict") == 0 || strcmp(key, "private_exec") == 0 ||
             strcmp(key, "mz_hits") == 0 || strcmp(key, "stomp_suspicious") == 0 ||
             strcmp(key, "thread_start_matches") == 0 || strcmp(key, "read_failures") == 0 ||
             strcmp(key, "injection_observed") == 0 || strcmp(key, "syscall") == 0 ||
             strcmp(key, "memfd_exec") == 0 || strcmp(key, "deleted_exec") == 0 ||
             strcmp(key, "target_pid") == 0 || strcmp(key, "memfd_name") == 0 ||
             strcmp(key, "sensor") == 0) {
    append_sensor_kv(f, key, val);
  } else if (strcmp(key, "path") == 0 && !f->file[0]) {
    (void)etw1_copy_text(f, f->file, sizeof(f->file), val, EDR_ETW_TRUNC_FILE_PATH);
  } else if (strcmp(key, "old_file") == 0 || strcmp(key, "old_path") == 0 ||
             strcmp(key, "source_file") == 0 || strcmp(key, "source_path") == 0 ||
             strcmp(key, "previous_file") == 0 || strcmp(key, "previous_path") == 0 ||
             strcmp(key, "rename_from") == 0) {
    (void)etw1_copy_text(f, f->old_file, sizeof(f->old_file), val,
                         EDR_ETW_TRUNC_OLD_FILE_PATH);
  } else if (strcmp(key, "new_file") == 0 || strcmp(key, "new_path") == 0 ||
             strcmp(key, "target_file") == 0 || strcmp(key, "target_path") == 0 ||
             strcmp(key, "rename_to") == 0) {
    (void)etw1_copy_text(f, f->file, sizeof(f->file), val, EDR_ETW_TRUNC_FILE_PATH);
  } else if (strcmp(key, "cert_revoked_ancestor") == 0 || strcmp(key, "cert_ra") == 0) {
    f->cert_revoked_ancestor = (strtoul(val, NULL, 10) != 0u) ? 1u : 0u;
    f->has_cert_revoked_ancestor = 1;
  } else if (strcmp(key, "file_write_binding_quality") == 0 ||
             strcmp(key, "file_write_file_object") == 0) {
    append_sensor_kv(f, key, val);
  } else if (strcmp(key, "file") == 0) {
    (void)etw1_copy_text(f, f->file, sizeof(f->file), val, EDR_ETW_TRUNC_FILE_PATH);
  } else if (strcmp(key, "signer") == 0 || strcmp(key, "publisher") == 0 ||
             strcmp(key, "signature_publisher") == 0 || strcmp(key, "cert_subject") == 0) {
    snprintf(f->signer, sizeof(f->signer), "%s", val);
    append_sensor_kv(f, "signer", val);
  } else if (strcmp(key, "signature_status") == 0 || strcmp(key, "signature_trust") == 0 ||
             strcmp(key, "signed") == 0 || strcmp(key, "verified") == 0) {
    snprintf(f->signature_status, sizeof(f->signature_status), "%s", val);
    append_sensor_kv(f, "signature_status", val);
  } else if (strcmp(key, "qname") == 0) {
    (void)etw1_copy_text(f, f->qname, sizeof(f->qname), val, EDR_ETW_TRUNC_DNS_QUERY);
  } else if ((strcmp(key, "ip") == 0 || strcmp(key, "dest_ip") == 0 ||
              strcmp(key, "dst_ip") == 0 || strcmp(key, "remote_ip") == 0 ||
              strcmp(key, "remote_addr") == 0) && !f->dst[0]) {
    normalize_ip_field_copy(f->dst, sizeof(f->dst), val);
  } else if ((strcmp(key, "source_ip") == 0 || strcmp(key, "src_ip") == 0 ||
              strcmp(key, "local_ip") == 0 || strcmp(key, "local_addr") == 0) && !f->src[0]) {
    normalize_ip_field_copy(f->src, sizeof(f->src), val);
  } else if (strcmp(key, "script") == 0) {
    snprintf(f->script, sizeof(f->script), "%s", val);
    detail_token_value(val, "service", f->webshell_service, sizeof(f->webshell_service));
    detail_token_value(val, "action", f->webshell_action, sizeof(f->webshell_action));
    detail_token_value(val, "alert_id", f->webshell_alert_id, sizeof(f->webshell_alert_id));
    detail_token_value(val, "file_fp", f->webshell_file_fp, sizeof(f->webshell_file_fp));
    detail_token_value(val, "file_uploaded", f->webshell_file_uploaded, sizeof(f->webshell_file_uploaded));
    detail_token_value(val, "object_key", f->webshell_object_key, sizeof(f->webshell_object_key));
    detail_token_value(val, "local_path", f->webshell_local_path, sizeof(f->webshell_local_path));
    detail_token_value(val, "ast_score", f->webshell_ast_score, sizeof(f->webshell_ast_score));
    detail_token_value(val, "token_score", f->webshell_token_score, sizeof(f->webshell_token_score));
  } else if (strcmp(key, "amsi_content") == 0 || strcmp(key, "script_content") == 0 ||
             strcmp(key, "script_text") == 0) {
    if (!f->script[0]) {
      snprintf(f->script, sizeof(f->script), "%s", val);
    }
    append_sensor_kv(f, key, val);
  } else if (strcmp(key, "app_name") == 0) {
    if (!f->has_img && val[0]) {
      f->has_img = etw1_copy_text(f, f->img, sizeof(f->img), val, EDR_ETW_TRUNC_IMAGE);
    }
    append_sensor_kv(f, key, val);
  } else if (strcmp(key, "url") == 0 || strcmp(key, "remote_url") == 0 || strcmp(key, "domain") == 0) {
    (void)etw1_copy_text(f, f->url, sizeof(f->url), val, EDR_ETW_TRUNC_DNS_QUERY);
    append_sensor_kv(f, key, val);
  } else if (strcmp(key, "sha256") == 0 || strcmp(key, "file_sha256") == 0 || strcmp(key, "file_hash") == 0) {
    (void)etw1_copy_text(f, f->sha256, sizeof(f->sha256), val, EDR_ETW_TRUNC_EXE_HASH);
    append_sensor_kv(f, key, val);
  } else if (strcmp(key, "sensor") == 0 || strcmp(key, "provider") == 0 || strcmp(key, "scriptblock_id") == 0 ||
             strcmp(key, "amsi_result") == 0 || strcmp(key, "script_hash") == 0 ||
             strcmp(key, "module") == 0 ||
             strcmp(key, "ja3") == 0 || strcmp(key, "ja3_hash") == 0 ||
             strcmp(key, "ja3_fingerprint") == 0 || strcmp(key, "ja3_rare") == 0 ||
             strcmp(key, "ja3_unknown") == 0 || strcmp(key, "sni") == 0 ||
             strcmp(key, "tls_sni") == 0 || strcmp(key, "sni_suspicious") == 0 ||
             strcmp(key, "sni_mismatch") == 0 || strcmp(key, "cert_self_signed") == 0 ||
             strcmp(key, "cert_expired") == 0 || strcmp(key, "cert_mismatch") == 0 ||
             strcmp(key, "cert_revoked") == 0 || strcmp(key, "cert_chain_anomaly") == 0 ||
             strcmp(key, "cert_untrusted") == 0 || strcmp(key, "cert_subject") == 0 ||
             strcmp(key, "cert_issuer") == 0 || strcmp(key, "cert_hash") == 0 ||
             strcmp(key, "tls_error") == 0 || strcmp(key, "tls_alert") == 0 ||
             strcmp(key, "amsi_session") == 0 || strcmp(key, "amsi_size") == 0 ||
             strcmp(key, "file_rate") == 0 || strcmp(key, "ext_burst") == 0 ||
             strcmp(key, "entropy_delta") == 0 || strcmp(key, "file_entropy_delta") == 0 ||
             strcmp(key, "ransom_counter") == 0 ||
             strcmp(key, "mass_rename") == 0 || strcmp(key, "extension_burst") == 0 ||
             strcmp(key, "rename_burst") == 0 || strcmp(key, "shadow_delete") == 0 ||
             strcmp(key, "shadowcopy_delete") == 0 || strcmp(key, "ast_score") == 0 ||
             strcmp(key, "token_score") == 0 || strcmp(key, "semantic_score") == 0 ||
             strcmp(key, "ast") == 0 || strcmp(key, "token") == 0 ||
             strcmp(key, "features") == 0 || strcmp(key, "ast_tokens") == 0 ||
             strcmp(key, "token_features") == 0) {
    if (strcmp(key, "ast_score") == 0 || strcmp(key, "ast") == 0) {
      snprintf(f->webshell_ast_score, sizeof(f->webshell_ast_score), "%s", val);
    } else if (strcmp(key, "token_score") == 0 || strcmp(key, "token") == 0) {
      snprintf(f->webshell_token_score, sizeof(f->webshell_token_score), "%s", val);
    }
    append_sensor_kv(f, key, val);
  } else if (strcmp(key, "dst") == 0) {
    normalize_ip_field_copy(f->dst, sizeof(f->dst), val);
  } else if (strcmp(key, "src") == 0) {
    normalize_ip_field_copy(f->src, sizeof(f->src), val);
  } else if (strcmp(key, "dpt") == 0) {
    f->dport = strtoul(val, NULL, 10);
    f->has_dport = 1;
  } else if (strcmp(key, "spt") == 0) {
    f->sport = strtoul(val, NULL, 10);
    f->has_sport = 1;
  } else if (strcmp(key, "laddr") == 0) {
    normalize_ip_field_copy(f->src, sizeof(f->src), val);
  } else if (strcmp(key, "raddr") == 0) {
    normalize_ip_field_copy(f->dst, sizeof(f->dst), val);
  } else if (strcmp(key, "lport") == 0) {
    f->sport = strtoul(val, NULL, 10);
    f->has_sport = 1;
  } else if (strcmp(key, "rport") == 0) {
    f->dport = strtoul(val, NULL, 10);
    f->has_dport = 1;
  } else if (strcmp(key, "fw_id") == 0) {
    snprintf(f->fw_id, sizeof(f->fw_id), "%s", val);
    f->has_fw = 1;
  } else if (strcmp(key, "fw_rule") == 0) {
    snprintf(f->fw_rule, sizeof(f->fw_rule), "%s", val);
    f->has_fw = 1;
  } else if (strcmp(key, "fw_mod") == 0) {
    snprintf(f->fw_mod, sizeof(f->fw_mod), "%s", val);
    f->has_fw = 1;
  } else if (strcmp(key, "fw_origin") == 0 || strcmp(key, "fw_remote") == 0 ||
             strcmp(key, "fw_lports") == 0) {
    f->has_fw = 1;
  } else if (strcmp(key, "score") == 0) {
    snprintf(f->score, sizeof(f->score), "%s", val);
  } else if (strcmp(key, "proto") == 0) {
    (void)etw1_copy_text(f, f->proto, sizeof(f->proto), val, EDR_ETW_TRUNC_NET_PROTO);
  } else if (strcmp(key, "detector") == 0) {
    snprintf(f->detector, sizeof(f->detector), "%s", val);
  } else if (strcmp(key, "rule") == 0) {
    snprintf(f->rule, sizeof(f->rule), "%s", val);
  } else if (strcmp(key, "mitre") == 0) {
    snprintf(f->mitre, sizeof(f->mitre), "%s", val);
  } else if (strcmp(key, "forensic_kind") == 0) {
    snprintf(f->forensic_kind, sizeof(f->forensic_kind), "%s", val);
  } else if (strcmp(key, "pcap_stem") == 0) {
    snprintf(f->pcap_stem, sizeof(f->pcap_stem), "%s", val);
  } else if (strcmp(key, "pcap_status") == 0) {
    snprintf(f->pcap_status, sizeof(f->pcap_status), "%s", val);
  } else if (strcmp(key, "pcap_object_key") == 0) {
    snprintf(f->pcap_object_key, sizeof(f->pcap_object_key), "%s", val);
  } else if (strcmp(key, "preview_hex") == 0) {
    snprintf(f->preview_hex, sizeof(f->preview_hex), "%s", val);
  } else if (strcmp(key, "service") == 0) {
    snprintf(f->webshell_service, sizeof(f->webshell_service), "%s", val);
  } else if (strcmp(key, "action") == 0) {
    snprintf(f->webshell_action, sizeof(f->webshell_action), "%s", val);
  } else if (strcmp(key, "alert_id") == 0) {
    snprintf(f->webshell_alert_id, sizeof(f->webshell_alert_id), "%s", val);
  } else if (strcmp(key, "file_fp") == 0) {
    snprintf(f->webshell_file_fp, sizeof(f->webshell_file_fp), "%s", val);
  } else if (strcmp(key, "file_uploaded") == 0) {
    snprintf(f->webshell_file_uploaded, sizeof(f->webshell_file_uploaded), "%s", val);
  } else if (strcmp(key, "object_key") == 0) {
    snprintf(f->webshell_object_key, sizeof(f->webshell_object_key), "%s", val);
  } else if (strcmp(key, "local_path") == 0) {
    snprintf(f->webshell_local_path, sizeof(f->webshell_local_path), "%s", val);
  } else if (strcmp(key, "forensic_frames") == 0) {
    f->forensic_frames = strtoul(val, NULL, 10);
    f->has_forensic_frames = 1;
  } else if (strcmp(key, "ring_trigger_slot") == 0) {
    snprintf(f->ring_trigger_slot, sizeof(f->ring_trigger_slot), "%s", val);
    f->has_ring_meta = 1;
  } else if (strcmp(key, "ring_oldest_ns") == 0) {
    snprintf(f->ring_oldest_ns, sizeof(f->ring_oldest_ns), "%s", val);
    f->has_ring_meta = 1;
  } else if (strcmp(key, "ring_newest_ns") == 0) {
    snprintf(f->ring_newest_ns, sizeof(f->ring_newest_ns), "%s", val);
    f->has_ring_meta = 1;
  } else if (strcmp(key, "ring_span_ns") == 0) {
    snprintf(f->ring_span_ns, sizeof(f->ring_span_ns), "%s", val);
    f->has_ring_meta = 1;
  } else if (strcmp(key, "attrib_schema") == 0) {
    snprintf(f->attrib_schema, sizeof(f->attrib_schema), "%s", val);
  } else if (strcmp(key, "attrib_cve") == 0) {
    snprintf(f->attrib_cve, sizeof(f->attrib_cve), "%s", val);
  } else if (strcmp(key, "attrib_family") == 0) {
    snprintf(f->attrib_family, sizeof(f->attrib_family), "%s", val);
  } else if (strcmp(key, "attrib_product") == 0) {
    snprintf(f->attrib_product, sizeof(f->attrib_product), "%s", val);
  } else if (strcmp(key, "attrib_vector") == 0) {
    snprintf(f->attrib_vector, sizeof(f->attrib_vector), "%s", val);
  } else if (strcmp(key, "attrib_confidence") == 0) {
    snprintf(f->attrib_confidence, sizeof(f->attrib_confidence), "%s", val);
  } else if (strcmp(key, "attrib_source") == 0) {
    snprintf(f->attrib_source, sizeof(f->attrib_source), "%s", val);
  } else if (strcmp(key, "attrib_basis") == 0) {
    snprintf(f->attrib_basis, sizeof(f->attrib_basis), "%s", val);
  } else if (strcmp(key, "shellcode_json") == 0) {
    snprintf(f->shellcode_json, sizeof(f->shellcode_json), "%s", val);
  } else if (strcmp(key, "regkey") == 0 || strcmp(key, "registry_key") == 0 ||
             strcmp(key, "registry_path") == 0 || strcmp(key, "target_object") == 0) {
    (void)etw1_copy_text(f, f->regkey, sizeof(f->regkey), val,
                         EDR_ETW_TRUNC_REG_KEY_PATH);
  } else if ((strcmp(key, "regpath") == 0 || strcmp(key, "key_path") == 0) && !f->regkey[0]) {
    (void)etw1_copy_text(f, f->regkey, sizeof(f->regkey), val,
                         EDR_ETW_TRUNC_REG_KEY_PATH);
  } else if (strcmp(key, "regname") == 0 || strcmp(key, "registry_value") == 0 ||
             strcmp(key, "value_name") == 0) {
    (void)etw1_copy_text(f, f->regname, sizeof(f->regname), val,
                         EDR_ETW_TRUNC_REG_VALUE_NAME);
  } else if (strcmp(key, "regdata") == 0 || strcmp(key, "registry_data") == 0 ||
             strcmp(key, "value_data") == 0 || strcmp(key, "details") == 0) {
    snprintf(f->regdata, sizeof(f->regdata), "%s", val);
  } else if (strcmp(key, "regold") == 0 || strcmp(key, "registry_old_data") == 0 ||
             strcmp(key, "old_value_data") == 0) {
    (void)etw1_copy_text(f, f->regold, sizeof(f->regold), val,
                         EDR_ETW_TRUNC_REG_OLD_VALUE_DATA);
  } else if (strcmp(key, "regop") == 0 || strcmp(key, "registry_op") == 0 ||
             strcmp(key, "operation") == 0) {
    (void)etw1_copy_text(f, f->regop, sizeof(f->regop), val, EDR_ETW_TRUNC_REG_OP);
  } else if (strcmp(key, "registry_source") == 0) {
    snprintf(f->regsource, sizeof(f->regsource), "%s", val);
  } else if (strcmp(key, "registry_attribution") == 0) {
    snprintf(f->regattribution, sizeof(f->regattribution), "%s", val);
  } else if (strcmp(key, "registry_detail_status") == 0) {
    snprintf(f->regstatus, sizeof(f->regstatus), "%s", val);
  }
}

/** 解析 ETW1\\n 文本块（collector TDH 输出） */
static int etw1_parse(const uint8_t *data, uint32_t len, Etw1Fields *f) {
  etw1_clear(f);
  if (!data || len < 5 || memcmp(data, "ETW1", 4) != 0) {
    return -1;
  }
  char *buf = (char *)malloc((size_t)len + 1u);
  if (!buf) {
    return -1;
  }
  memcpy(buf, data, len);
  buf[len] = '\0';

  char *p = buf;
  char *first_nl = strchr(p, '\n');
  if (!first_nl) {
    free(buf);
    return -1;
  }
  *first_nl = '\0';
  if (strcmp(p, "ETW1") != 0) {
    free(buf);
    return -1;
  }
  p = first_nl + 1;
  while (*p) {
    char *line_end = strchr(p, '\n');
    if (line_end) {
      *line_end = '\0';
    }
    char *eq = strchr(p, '=');
    if (eq) {
      *eq = '\0';
      apply_kv(f, p, eq + 1);
      *eq = '=';
    }
    if (!line_end) {
      break;
    }
    p = line_end + 1;
  }
  free(buf);
  return 0;
}

static void apply_mitre_hints(EdrBehaviorRecord *r) {
  r->mitre_ttp_count = 0;
  if (r->type == EDR_EVENT_PROTOCOL_SHELLCODE && r->mitre_ttp_count < (int)EDR_BR_MAX_MITRE) {
    snprintf(r->mitre_ttps[r->mitre_ttp_count], sizeof(r->mitre_ttps[0]), "%s", "T1210");
    r->mitre_ttp_count++;
  }
  if (r->type == EDR_EVENT_WEBSHELL_DETECTED && r->mitre_ttp_count < (int)EDR_BR_MAX_MITRE) {
    snprintf(r->mitre_ttps[r->mitre_ttp_count], sizeof(r->mitre_ttps[0]), "%s", "T1505.003");
    r->mitre_ttp_count++;
  }
  if (r->type == EDR_EVENT_FIREWALL_RULE_CHANGE && r->mitre_ttp_count < (int)EDR_BR_MAX_MITRE) {
    snprintf(r->mitre_ttps[r->mitre_ttp_count], sizeof(r->mitre_ttps[0]), "%s", "T1562.004");
    r->mitre_ttp_count++;
  }
  if (r->type == EDR_EVENT_PMFE_SCAN_RESULT &&
      strstr(r->script_snippet, "pmfe_verdict=suspicious") != NULL &&
      r->mitre_ttp_count < (int)EDR_BR_MAX_MITRE) {
    snprintf(r->mitre_ttps[r->mitre_ttp_count], sizeof(r->mitre_ttps[0]), "%s", "T1055");
    r->mitre_ttp_count++;
  }
  if ((r->type == EDR_EVENT_REG_CREATE_KEY || r->type == EDR_EVENT_REG_SET_VALUE ||
       r->type == EDR_EVENT_SERVICE_CREATE || r->type == EDR_EVENT_SCHEDULED_TASK_CREATE ||
       r->type == EDR_EVENT_DRIVER_LOAD) &&
      r->mitre_ttp_count < (int)EDR_BR_MAX_MITRE) {
    snprintf(r->mitre_ttps[r->mitre_ttp_count], sizeof(r->mitre_ttps[0]), "%s", "T1547.001");
    r->mitre_ttp_count++;
  }
  const char *hay = r->cmdline[0] ? r->cmdline : r->script_snippet;
  if (hay[0] && (strstr(hay, "EncodedCommand") != NULL || strstr(hay, "-Enc") != NULL) &&
      r->mitre_ttp_count < (int)EDR_BR_MAX_MITRE) {
    snprintf(r->mitre_ttps[r->mitre_ttp_count], sizeof(r->mitre_ttps[0]), "%s", "T1059.001");
    r->mitre_ttp_count++;
  }
}

void edr_behavior_from_slot(const EdrEventSlot *slot, EdrBehaviorRecord *r) {
  edr_behavior_record_init(r);
  if (!slot || !r) {
    return;
  }

  r->event_time_ns = (int64_t)slot->timestamp_ns;
  r->type = slot->type;
  r->priority = slot->priority;
  r->ransom_sample_process_start_key = slot->ransom_sample_process_start_key;
  r->ransom_content_entropy = slot->ransom_content_entropy;
  r->ransom_content_sample_bytes = slot->ransom_content_sample_bytes;
  r->ransom_content_sampled = slot->ransom_content_sampled;
  edr_gen_event_id(r->event_id, sizeof(r->event_id), r->event_time_ns);

  Etw1Fields ef;
  if (slot->size > 0 && etw1_parse(slot->data, slot->size, &ef) == 0) {
    r->kernel_file_write = slot->type == EDR_EVENT_FILE_WRITE &&
                           strcmp(ef.prov, "kfile") == 0;
    r->kernel_file_activity = is_file_activity_event(slot->type) &&
                              strcmp(ef.prov, "kfile") == 0;
    mark_etw1_input_truncations(r, ef.truncation_mask);
    if (strcmp(ef.prov, "sec") == 0 && ef.eid == 4688u) {
      r->is_security_4688 = 1u;
    }
    if (ef.pid) {
      r->pid = (uint32_t)ef.pid;
    }
    if (ef.epid) {
      r->pid = (uint32_t)ef.epid;
    }
    if (ef.ppid) {
      r->ppid = (uint32_t)ef.ppid;
    }
    if (ef.has_img) {
      (void)copy_record_source_text(r, r->exe_path, sizeof(r->exe_path), ef.img, "exe_path");
      (void)copy_record_source_text(r, r->process_name, sizeof(r->process_name),
                                    basename_c(ef.img), "process_name");
    }
    if (ef.image_raw[0]) {
      (void)copy_record_source_text(r, r->image_path_raw, sizeof(r->image_path_raw),
                                    ef.image_raw, "image_path_raw");
    } else if (ef.img[0]) {
      (void)copy_record_source_text(r, r->image_path_raw, sizeof(r->image_path_raw), ef.img,
                                    "image_path_raw");
    }
    (void)copy_record_source_text(r, r->image_path_canonical,
                                  sizeof(r->image_path_canonical), ef.image_canonical,
                                  "image_path_canonical");
    (void)copy_record_source_text(r, r->image_path_namespace,
                                  sizeof(r->image_path_namespace), ef.image_namespace,
                                  "image_path_namespace");
    (void)copy_record_source_text(r, r->image_path_resolution_status,
                                  sizeof(r->image_path_resolution_status),
                                  ef.image_resolution_status, "image_path_resolution_status");
    (void)copy_record_source_text(r, r->image_path_resolution_source,
                                  sizeof(r->image_path_resolution_source),
                                  ef.image_resolution_source, "image_path_resolution_source");
    (void)copy_record_source_text(r, r->source_completeness,
                                  sizeof(r->source_completeness), ef.source_completeness,
                                  "source_completeness");
    if (ef.has_file_key) {
      r->file_key = ef.file_key;
    }
    if (strcmp(ef.collector_evidence_gate, EDR_P0_FILE_READ_METADATA_GATE) == 0) {
      snprintf(r->collector_evidence_gate, sizeof(r->collector_evidence_gate), "%s",
               ef.collector_evidence_gate);
      snprintf(r->collector_evidence_reason, sizeof(r->collector_evidence_reason), "%s",
               ef.collector_evidence_reason);
      /* This identifier originates only in the collector's synthetic
       * NameCreate capacity gate.  Reusing it across retries lets the
       * existing durable queue apply its normal exact-idempotency behavior. */
      if (strncmp(ef.collector_event_id, "filemeta-", 9u) == 0) {
        snprintf(r->event_id, sizeof(r->event_id), "%s", ef.collector_event_id);
      }
    }
    r->evidence_revision = (uint32_t)ef.evidence_revision;
    if (ef.image_canonical[0] && strcmp(ef.image_resolution_status, "RESOLVED") == 0) {
      (void)copy_record_source_text(r, r->exe_path, sizeof(r->exe_path),
                                    ef.image_canonical, "exe_path");
      (void)copy_record_source_text(r, r->process_name, sizeof(r->process_name),
                                    basename_c(ef.image_canonical), "process_name");
    }
    if (ef.has_cmd) {
      (void)copy_record_source_text(r, r->cmdline, sizeof(r->cmdline), ef.cmd, "cmdline");
      if (!r->exe_path[0]) {
        char first[EDR_BR_STR_LONG];
        first_cmd_token(ef.cmd, first, sizeof(first));
        if (first[0]) {
          (void)copy_record_source_text(r, r->exe_path, sizeof(r->exe_path), first, "exe_path");
          (void)copy_record_source_text(r, r->process_name, sizeof(r->process_name),
                                        basename_c(first), "process_name");
        }
      }
    }
    if (has_ci_ascii(r->process_name, "cmd.exe") || has_ci_ascii(r->exe_path, "cmd.exe")) {
      char artifact[EDR_BR_STR_LONG];
      cmd_script_artifact(r->cmdline, artifact, sizeof(artifact));
      if (artifact[0]) snprintf(r->file_path, sizeof(r->file_path), "%s", artifact);
    }
    if (identity_value_present(ef.creator_user) || identity_value_present(ef.creator_domain) ||
        identity_value_present(ef.creator_sid) || identity_value_present(ef.creator_logon_id)) {
      (void)copy_record_source_text(r, r->creator_username, sizeof(r->creator_username),
                                    ef.creator_user, "creator_username");
      (void)copy_record_source_text(r, r->creator_domain, sizeof(r->creator_domain),
                                    ef.creator_domain, "creator_domain");
      (void)copy_record_source_text(r, r->creator_sid, sizeof(r->creator_sid),
                                    ef.creator_sid, "creator_sid");
      (void)copy_record_source_text(r, r->creator_logon_id, sizeof(r->creator_logon_id),
                                    ef.creator_logon_id, "creator_logon_id");
    }
    /* TargetUserSid=S-1-0-0 and TargetLogonId=0x0 are Security 4688
     * placeholders, not a created-process identity.  Only the complete
     * SID/logon tuple may request target-4688 validation; otherwise the live
     * token query remains the authority. */
    int target_present = identity_sid_present(ef.user_sid) &&
                         identity_logon_present(ef.logon_id);
    if (identity_value_present(ef.user)) {
      if (ef.domain[0]) {
        (void)copy_record_username(r, ef.domain, ef.user);
      } else {
        (void)copy_record_source_text(r, r->username, sizeof(r->username), ef.user, "username");
      }
    }
    if (identity_value_present(ef.domain)) {
      (void)copy_record_source_text(r, r->domain, sizeof(r->domain), ef.domain, "domain");
    }
    if (identity_sid_present(ef.user_sid)) {
      (void)copy_record_source_text(r, r->user_sid, sizeof(r->user_sid), ef.user_sid, "user_sid");
    }
    if (identity_logon_present(ef.logon_id)) {
      (void)copy_record_source_text(r, r->logon_id, sizeof(r->logon_id), ef.logon_id, "logon_id");
    }
    if (target_present) {
      snprintf(r->identity_source, sizeof(r->identity_source), "%s", "target_4688");
      snprintf(r->identity_quality, sizeof(r->identity_quality), "%s", "target_4688");
    } else if (identity_value_present(r->creator_username) || identity_value_present(r->creator_domain) ||
               identity_value_present(r->creator_sid) || identity_value_present(r->creator_logon_id)) {
      /* Security 4688 Creator Subject is the launching principal, not the
       * created process token.  Preserve it only in creator_* fields; never
       * promote it into the effective process identity. */
      snprintf(r->identity_source, sizeof(r->identity_source), "%s", "creator_fallback");
      snprintf(r->identity_quality, sizeof(r->identity_quality), "%s", "creator_fallback");
    }
    if (ef.has_parent_img) {
      (void)copy_record_source_text(r, r->parent_path, sizeof(r->parent_path),
                                    ef.parent_img, "parent_path");
      (void)copy_record_source_text(r, r->parent_name, sizeof(r->parent_name),
                                    basename_c(ef.parent_img), "parent_name");
    }
    if (ef.has_parent_cmdline) {
      (void)copy_record_source_text(r, r->parent_cmdline, sizeof(r->parent_cmdline),
                                    ef.parent_cmdline, "parent_cmdline");
    }
    if (ef.has_cwd) {
      (void)copy_record_source_text(r, r->current_directory, sizeof(r->current_directory),
                                    ef.cwd, "current_directory");
    }
    if (ef.has_integrity) {
      (void)copy_record_source_text(r, r->integrity_level, sizeof(r->integrity_level),
                                    ef.integrity, "integrity_level");
    }
    if (ef.has_token_elevation) {
      r->token_elevation = parse_token_elevation_type(ef.token_elevation);
    }
    if (ef.has_process_creation_time) {
      (void)copy_record_source_text(r, r->process_creation_time,
                                    sizeof(r->process_creation_time), ef.process_creation_time,
                                    "process_creation_time");
    }
    if (ef.has_process_start_key) {
      r->process_start_key = ef.process_start_key;
    }
    if (ef.has_process_creation_filetime) {
      r->process_creation_filetime_100ns = ef.process_creation_filetime_100ns;
    }
    if (ef.has_process_generation_source) {
      (void)copy_record_source_text(r, r->process_generation_source,
                                    sizeof(r->process_generation_source),
                                    ef.process_generation_source, "process_generation_source");
    }
    if (ef.file[0]) {
      (void)copy_record_source_text(r, r->file_path, sizeof(r->file_path), ef.file, "file_path");
      snprintf(r->file_op, sizeof(r->file_op), "%s",
               r->type == EDR_EVENT_FILE_READ ? "read" :
               r->type == EDR_EVENT_FILE_WRITE ? "write" :
               r->type == EDR_EVENT_FILE_CREATE ? "create" :
               r->type == EDR_EVENT_FILE_RENAME ? "rename" :
               r->type == EDR_EVENT_FILE_DELETE ? "delete" : "event");
    }
    if (ef.old_file[0]) {
      (void)copy_record_source_text(r, r->file_old_path, sizeof(r->file_old_path),
                                    ef.old_file, "file_old_path");
      char old_ext[16];
      char new_ext[16];
      extension_c(ef.old_file, old_ext, sizeof(old_ext));
      extension_c(r->file_path[0] ? r->file_path : ef.file, new_ext, sizeof(new_ext));
      append_record_kv(r, "old_ext=%s new_ext=%s ext_changed=%d",
                       old_ext, new_ext, strcmp(old_ext, new_ext) != 0 ? 1 : 0);
    }
    if (ef.qname[0]) {
      (void)copy_record_source_text(r, r->dns_query, sizeof(r->dns_query), ef.qname,
                                    "dns_query");
    }
    if (ef.url[0] && !r->dns_query[0]) {
      (void)copy_record_source_text(r, r->dns_query, sizeof(r->dns_query), ef.url,
                                    "dns_query");
    }
    if (ef.sha256[0]) {
      (void)copy_record_source_text(r, r->exe_hash, sizeof(r->exe_hash), ef.sha256,
                                    "exe_hash");
    }
    if (ef.script[0]) {
      snprintf(r->script_snippet, sizeof(r->script_snippet), "%s", ef.script);
    }
    if (ef.src[0]) {
      snprintf(r->net_src, sizeof(r->net_src), "%s", ef.src);
    }
    if (ef.dst[0]) {
      snprintf(r->net_dst, sizeof(r->net_dst), "%s", ef.dst);
    }
    if (ef.has_dport) {
      r->net_dport = (uint32_t)ef.dport;
    }
    if (ef.has_sport) {
      r->net_sport = (uint32_t)ef.sport;
    }
    if (ef.has_fw) {
      snprintf(r->file_path, sizeof(r->file_path), "WF rule=%s id=%s mod=%s",
               ef.fw_rule[0] ? ef.fw_rule : "-", ef.fw_id[0] ? ef.fw_id : "-",
               ef.fw_mod[0] ? ef.fw_mod : "-");
      snprintf(r->file_op, sizeof(r->file_op), "%s", "firewall_etw");
    }
    if (ef.proto[0]) {
      (void)copy_record_source_text(r, r->net_proto, sizeof(r->net_proto), ef.proto,
                                    "net_proto");
    }
    if (ef.has_cert_revoked_ancestor) {
      r->cert_revoked_ancestor = ef.cert_revoked_ancestor;
    }
    if (ef.regkey[0]) {
      (void)copy_record_source_text(r, r->reg_key_path, sizeof(r->reg_key_path), ef.regkey,
                                    "reg_key_path");
    }
    if (ef.regname[0]) {
      (void)copy_record_source_text(r, r->reg_value_name, sizeof(r->reg_value_name),
                                    ef.regname, "reg_value_name");
    }
    if (ef.regdata[0]) {
      snprintf(r->reg_value_data, sizeof(r->reg_value_data), "%s", ef.regdata);
    }
    if (ef.regold[0]) {
      (void)copy_record_source_text(r, r->reg_old_value_data,
                                    sizeof(r->reg_old_value_data), ef.regold,
                                    "reg_old_value_data");
    }
    if (ef.regop[0]) {
      (void)copy_record_source_text(r, r->reg_op, sizeof(r->reg_op), ef.regop,
                                    "reg_op");
    }
    snprintf(r->reg_source, sizeof(r->reg_source), "%s",
             ef.regsource[0] ? ef.regsource : ef.prov);
    snprintf(r->reg_attribution, sizeof(r->reg_attribution), "%s",
             ef.regattribution[0] ? ef.regattribution : (r->pid ? "process_id" : "unavailable"));
    if (ef.regstatus[0]) {
      snprintf(r->reg_detail_status, sizeof(r->reg_detail_status), "%s", ef.regstatus);
    }
    if (r->type == EDR_EVENT_REG_CREATE_KEY && !r->reg_op[0]) {
      snprintf(r->reg_op, sizeof(r->reg_op), "create_key");
    } else if (r->type == EDR_EVENT_REG_SET_VALUE && !r->reg_op[0]) {
      snprintf(r->reg_op, sizeof(r->reg_op), "set_value");
    } else if (r->type == EDR_EVENT_REG_DELETE_KEY && !r->reg_op[0]) {
      snprintf(r->reg_op, sizeof(r->reg_op), "delete_key");
    }
    if (ef.score[0] || ef.proto[0] || ef.detector[0] || ef.rule[0] || ef.mitre[0] || ef.forensic_kind[0] ||
        ef.pcap_stem[0] || ef.pcap_status[0] || ef.pcap_object_key[0] || ef.preview_hex[0] ||
        ef.has_forensic_frames || ef.has_ring_meta || ef.shellcode_json[0]) {
      if (ef.has_forensic_frames) {
        snprintf(r->script_snippet, sizeof(r->script_snippet),
                 "detector=%s rule=%s score=%s proto=%s mitre=%s forensic=%s stem=%s frames=%lu",
                 ef.detector[0] ? ef.detector : "-", ef.rule[0] ? ef.rule : "-", ef.score[0] ? ef.score : "-",
                 ef.proto[0] ? ef.proto : "-", ef.mitre[0] ? ef.mitre : "-", ef.forensic_kind[0] ? ef.forensic_kind : "-",
                 ef.pcap_stem[0] ? ef.pcap_stem : "-", (unsigned long)ef.forensic_frames);
      } else {
        snprintf(r->script_snippet, sizeof(r->script_snippet),
                 "detector=%s rule=%s score=%s proto=%s mitre=%s forensic=%s stem=%s",
                 ef.detector[0] ? ef.detector : "-", ef.rule[0] ? ef.rule : "-", ef.score[0] ? ef.score : "-",
                 ef.proto[0] ? ef.proto : "-", ef.mitre[0] ? ef.mitre : "-", ef.forensic_kind[0] ? ef.forensic_kind : "-",
                 ef.pcap_stem[0] ? ef.pcap_stem : "-");
      }
      append_snippet_kv(r->script_snippet, sizeof(r->script_snippet), "pcap_status", ef.pcap_status);
      append_snippet_kv(r->script_snippet, sizeof(r->script_snippet), "pcap_object_key", ef.pcap_object_key);
      append_snippet_kv(r->script_snippet, sizeof(r->script_snippet), "payload_sha256", ef.sha256);
      append_snippet_kv(r->script_snippet, sizeof(r->script_snippet), "preview_hex", ef.preview_hex);
      append_snippet_kv(r->script_snippet, sizeof(r->script_snippet), "attrib_schema", ef.attrib_schema);
      append_snippet_kv(r->script_snippet, sizeof(r->script_snippet), "attrib_cve", ef.attrib_cve);
      append_snippet_kv(r->script_snippet, sizeof(r->script_snippet), "attrib_family", ef.attrib_family);
      append_snippet_kv(r->script_snippet, sizeof(r->script_snippet), "attrib_product", ef.attrib_product);
      append_snippet_kv(r->script_snippet, sizeof(r->script_snippet), "attrib_vector", ef.attrib_vector);
      append_snippet_kv(r->script_snippet, sizeof(r->script_snippet), "attrib_confidence", ef.attrib_confidence);
      append_snippet_kv(r->script_snippet, sizeof(r->script_snippet), "attrib_source", ef.attrib_source);
      append_snippet_kv(r->script_snippet, sizeof(r->script_snippet), "attrib_basis", ef.attrib_basis);
      if (ef.has_ring_meta) {
        size_t L = strlen(r->script_snippet);
        snprintf(r->script_snippet + L, sizeof(r->script_snippet) - L, " ring_slot=%s span_ns=%s",
                 ef.ring_trigger_slot[0] ? ef.ring_trigger_slot : "-", ef.ring_span_ns[0] ? ef.ring_span_ns : "-");
      }
      if (ef.shellcode_json[0]) {
        size_t L = strlen(r->script_snippet);
        snprintf(r->script_snippet + L, sizeof(r->script_snippet) - L, " | %s", ef.shellcode_json);
      }
    }
    append_snippet_kv(r->script_snippet, sizeof(r->script_snippet), "service", ef.webshell_service);
    append_snippet_kv(r->script_snippet, sizeof(r->script_snippet), "action", ef.webshell_action);
    append_snippet_kv(r->script_snippet, sizeof(r->script_snippet), "url", ef.url);
    append_snippet_kv(r->script_snippet, sizeof(r->script_snippet), "alert_id", ef.webshell_alert_id);
    append_snippet_kv(r->script_snippet, sizeof(r->script_snippet), "file_fp", ef.webshell_file_fp);
    append_snippet_kv(r->script_snippet, sizeof(r->script_snippet), "file_uploaded", ef.webshell_file_uploaded);
    append_snippet_kv(r->script_snippet, sizeof(r->script_snippet), "object_key", ef.webshell_object_key);
    append_snippet_kv(r->script_snippet, sizeof(r->script_snippet), "local_path", ef.webshell_local_path);
    append_snippet_kv(r->script_snippet, sizeof(r->script_snippet), "ast_score", ef.webshell_ast_score);
    append_snippet_kv(r->script_snippet, sizeof(r->script_snippet), "token_score", ef.webshell_token_score);
    if (ef.sensor_detail[0]) {
      size_t L = strlen(r->script_snippet);
      snprintf(r->script_snippet + L, sizeof(r->script_snippet) - L, "%s%s",
               L > 0u ? " " : "", ef.sensor_detail);
    }
    if (r->kernel_file_write && r->file_key) {
      append_record_kv(r, "file_write_file_key=0x%llx", (unsigned long long)r->file_key);
    }
    /* Later ETW metadata can describe a normal source state, but it cannot
     * erase a field omission detected while parsing this same record. */
    if (ef.truncation_mask != 0u) {
      (void)copy_text_exact(r->source_completeness, sizeof(r->source_completeness),
                            "TRUNCATED");
    }
  } else if (slot->size > 0) {
    size_t n = slot->size;
    if (n >= sizeof(r->cmdline)) {
      n = sizeof(r->cmdline) - 1u;
    }
    memcpy(r->cmdline, slot->data, n);
    r->cmdline[n] = '\0';
  }

  apply_mitre_hints(r);
}
