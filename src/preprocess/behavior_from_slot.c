#include "edr/behavior_from_slot.h"

#include "edr/command.h"

#include <ctype.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

static uint64_t g_event_seq;

#define RANSOM_COUNTER_BUCKETS 128u
#define RANSOM_COUNTER_EXTS 24u
#define RANSOM_COUNTER_DIRS 16u
#define RANSOM_NOTE_BUCKETS 128u
#define RANSOM_NOTE_FILES 16u

typedef struct {
  uint32_t pid;
  char dir[256];
  int64_t window_start_ns;
  uint32_t file_events;
  uint32_t high_entropy_events;
  char exts[RANSOM_COUNTER_EXTS][16];
  char dirs[RANSOM_COUNTER_DIRS][128];
  uint8_t ext_count;
  uint8_t dir_count;
  double entropy_avg;
} RansomCounterBucket;

typedef struct {
  uint32_t pid;
  int64_t window_start_ns;
  uint32_t note_count;
  char files[RANSOM_NOTE_FILES][96];
} RansomNoteBucket;

static RansomCounterBucket g_ransom_buckets[RANSOM_COUNTER_BUCKETS];
static RansomNoteBucket g_ransom_note_buckets[RANSOM_NOTE_BUCKETS];

static void edr_gen_event_id(char *out, size_t cap, int64_t time_ns) {
  uint64_t s = ++g_event_seq;
  snprintf(out, cap, "e-%llx-%llx", (unsigned long long)(uint64_t)time_ns,
           (unsigned long long)s);
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

static int known_low_value_ransom_counter_process(const EdrBehaviorRecord *r) {
  if (!r) {
    return 0;
  }
  const char *s = r->process_name[0] ? r->process_name : r->exe_path;
  return has_ci_ascii(s, "taskmgr.exe") || has_ci_ascii(s, "usoclient.exe") ||
         has_ci_ascii(s, "taskhostw.exe") || has_ci_ascii(s, "ecagent.exe") ||
         has_ci_ascii(s, "checknetisolation.exe") || has_ci_ascii(s, "conhost.exe");
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

static int token_list_has_ci_ascii(const char *list, const char *value) {
  if (!list || !list[0] || !value || !value[0]) {
    return 0;
  }
  const char *p = list;
  while (*p) {
    while (*p == ',' || *p == ';' || *p == '\n' || *p == '\r' || *p == '\t' || *p == ' ') {
      p++;
    }
    char tok[256];
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
    if (tok[0] && has_ci_ascii(value, tok)) {
      return 1;
    }
  }
  return 0;
}

static int file_token_list_has_ci_ascii(const char *path, const char *value) {
  if (!path || !path[0] || !value || !value[0]) {
    return 0;
  }
  FILE *f = fopen(path, "rb");
  if (!f) {
    return 0;
  }
  char buf[4096];
  size_t n = fread(buf, 1u, sizeof(buf) - 1u, f);
  fclose(f);
  buf[n] = '\0';
  return token_list_has_ci_ascii(buf, value);
}

static int ransom_policy_token_match(const char *env_inline, const char *env_file, const char *fallback,
                                     const char *value) {
  const char *list = getenv(env_inline);
  if (list && list[0] && token_list_has_ci_ascii(list, value)) {
    return 1;
  }
  const char *file = getenv(env_file);
  if (file && file[0] && file_token_list_has_ci_ascii(file, value)) {
    return 1;
  }
  return fallback && fallback[0] && token_list_has_ci_ascii(fallback, value);
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
  fclose(f);
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

static RansomCounterBucket *ransom_bucket_for(uint32_t pid, const char *dir, int64_t now_ns, int64_t window_ns) {
  RansomCounterBucket *empty = NULL;
  RansomCounterBucket *oldest = &g_ransom_buckets[0];
  uint32_t key_pid = pid ? pid : 1u;
  for (size_t i = 0; i < RANSOM_COUNTER_BUCKETS; i++) {
    RansomCounterBucket *b = &g_ransom_buckets[i];
    if (b->pid == key_pid) {
      if (b->window_start_ns <= 0 || now_ns - b->window_start_ns > window_ns) {
        memset(b, 0, sizeof(*b));
        b->pid = key_pid;
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
  snprintf(b->dir, sizeof(b->dir), "%s", dir);
  b->window_start_ns = now_ns;
  return b;
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
  const char *fallback =
      "~$canary,edr_canary,.edr-canary,edr-canary,canary.doc,canary.docx,canary.xlsx,canary.txt,"
      "~edr_canary,~$edr_canary";
  return ransom_policy_token_match("EDR_RANSOM_CANARY_TOKENS", "EDR_RANSOM_CANARY_TOKENS_FILE",
                                   fallback, path);
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
  char subject[12288];
  snprintf(subject, sizeof(subject), "%s %s %s %s %s",
           r->process_name, r->exe_path, r->cmdline, r->file_path, r->script_snippet);
  int signer_ok = ransom_policy_token_match("EDR_RANSOM_SIGNER_ALLOWLIST",
                                             "EDR_RANSOM_SIGNER_ALLOWLIST_FILE", "", subject);
  if (!signer_ok) {
    return 0;
  }
  char path_subject[8192];
  snprintf(path_subject, sizeof(path_subject), "%s %s %s", r->exe_path, r->cmdline, r->process_name);
  int path_ok = ransom_policy_token_match("EDR_RANSOM_SIGNED_PATH_ALLOWLIST",
                                           "EDR_RANSOM_SIGNED_PATH_ALLOWLIST_FILE", "", path_subject);
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
  if (!r) {
    return 0;
  }
  char subject[8192];
  snprintf(subject, sizeof(subject), "%s %s %s %s",
           r->process_name, r->exe_path, r->cmdline, r->file_path);
  return ransom_policy_token_match("EDR_RANSOM_COUNTER_ALLOWLIST", "EDR_RANSOM_COUNTER_ALLOWLIST_FILE",
                                   "", subject) ||
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

static void enrich_ransom_file_counters(EdrBehaviorRecord *r) {
  if (!r || !is_file_activity_event(r->type) || !r->file_path[0]) {
    return;
  }
  if (!file_path_usable_for_ransom(r->file_path)) {
    append_record_kv(r, "invalid_file_path=1 ransom_counter_suppressed=1");
    return;
  }
  if (known_low_value_ransom_counter_process(r)) {
    append_record_kv(r, "ransom_counter_suppressed=1 low_value_ransom_process=1");
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
  int canary = is_ransom_canary_path(r->file_path);
  if (canary) {
    append_record_kv(r, "ransom_canary=1 ransomware_kind=DETERMINISTIC_ENCRYPTION ransomware_severity=4");
  }
  if (!canary && ransom_counter_allowlisted(r)) {
    append_record_kv(r, "ransom_counter_allowlisted=1%s", ransom_signer_allowlisted(r) ? " ransom_signer_allowlisted=1" : "");
    return;
  }
  RansomCounterBucket *b = ransom_bucket_for(r->pid ? r->pid : 1u, dir, now_ns, window_ns);
  double path_entropy = path_entropy_score(r->file_path);
  double content_entropy = 0.0;
  size_t content_sample = 0u;
  int content_ok = file_content_entropy_sample(r->file_path, &content_entropy, &content_sample);
  double entropy = content_ok ? content_entropy : path_entropy;
  double prev = b->entropy_avg;
  b->file_events++;
  (void)ext_seen_or_add(b, ext);
  (void)dir_seen_or_add(b, dir);
  if (b->file_events == 1u || prev <= 0.0) {
    b->entropy_avg = entropy;
  } else {
    b->entropy_avg = (prev * 0.85) + (entropy * 0.15);
  }
  double elapsed_s = (double)(now_ns - b->window_start_ns) / 1000000000.0;
  if (elapsed_s < 1.0) {
    elapsed_s = 1.0;
  }
  double file_rate = ((double)b->file_events * 60.0) / elapsed_s;
  double entropy_delta = entropy - prev;
  if (entropy_delta < 0.0) {
    entropy_delta = 0.0;
  }
  int content_high = content_ok && content_entropy >= 7.20 && content_sample >= 512u;
  if (content_high || entropy >= 4.0 || entropy_delta >= 1.5) {
    b->high_entropy_events++;
  }
  int warn_files = env_int_clamped("EDR_RANSOM_RATE_WARN_FILES", 60, 8, 500);
  int confirm_files = env_int_clamped("EDR_RANSOM_RATE_CONFIRM_FILES", 200, 20, 2000);
  int warn_dirs = env_int_clamped("EDR_RANSOM_RATE_WARN_DIRS", 4, 1, 32);
  int confirm_dirs = env_int_clamped("EDR_RANSOM_RATE_CONFIRM_DIRS", 8, 1, 64);
  int enough_volume = b->file_events >= 20u;
  int suspicious = (enough_volume && file_rate >= 120.0) ||
                   (b->file_events >= 12u && b->ext_count >= 8u) ||
                   (b->file_events >= 8u && entropy_delta >= 1.5) ||
                   (b->file_events >= 6u && ext_changed && content_high) ||
                   ((int)b->file_events >= warn_files &&
                    ((int)b->dir_count >= warn_dirs || b->ext_count >= 8u));
  double high_entropy_ratio = b->file_events > 0u ? (double)b->high_entropy_events / (double)b->file_events : 0.0;
  int confirmed = canary ||
                  ((int)b->file_events >= confirm_files &&
                   ((int)b->dir_count >= confirm_dirs || b->ext_count >= 12u || high_entropy_ratio >= 0.70)) ||
                  (suspicious && file_rate >= 300.0 && b->ext_count >= 12u) ||
                  (suspicious && ext_changed && content_high && b->file_events >= 20u);
  append_record_kv(r,
                   "file_rate=%.0f ext_burst=%u dir_burst=%u entropy_delta=%.2f high_entropy_ratio=%.2f "
                   "path_entropy=%.2f content_entropy=%.2f content_sample_bytes=%u content_entropy_ok=%d%s%s%s",
                   file_rate, (unsigned)b->ext_count, (unsigned)b->dir_count, entropy_delta,
                   high_entropy_ratio, path_entropy, content_entropy, (unsigned)content_sample, content_ok ? 1 : 0,
                   (suspicious || confirmed) ? " ransom_counter=1" : "",
                   confirmed ? " ransomware_kind=ENCRYPTION_CONFIRMED ransomware_severity=4" :
                   (suspicious ? " ransomware_kind=ENCRYPTION_SUSPECTED ransomware_severity=3" : ""),
                   canary ? " canary_counter_bypass=1" : "");

  if (confirmed) {
    /* 确诊勒索:端侧实时自隔离(默认关,需 EDR_RANSOM_AUTO_ISOLATE=1 + 高危策略;每进程一次)。 */
    edr_isolate_auto_from_ransom_alarm();
  }

  if (is_ransom_note_like_path(r->file_path)) {
    RansomNoteBucket *nb = ransom_note_bucket_for(r->pid ? r->pid : 1u, now_ns, ransom_note_window_ns());
    (void)note_file_seen_or_add(nb, r->file_path);
    append_record_kv(r, "ransom_note_count=%u%s", nb->note_count,
                     nb->note_count >= (uint32_t)ransom_note_threshold() ? " ransom_note_burst=1" : "");
  }
}

typedef struct {
  char prov[48];
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
  char ring_trigger_slot[24];
  char ring_oldest_ns[28];
  char ring_newest_ns[28];
  char ring_span_ns[28];
  char shellcode_json[512];
  char sensor_detail[2048];
  char fw_id[96];
  char fw_rule[256];
  char fw_mod[512];
  char regkey[1024];
  char regname[512];
  char regdata[8192];
  char regop[64];
  char user[256];
  char domain[256];
  char parent_img[EDR_BR_STR_LONG];
  char parent_cmdline[EDR_BR_STR_LONG];
  char cwd[EDR_BR_STR_LONG];
  char integrity[64];
  char token_elevation[64];
  char process_creation_time[96];
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
} Etw1Fields;

static void etw1_clear(Etw1Fields *f) { memset(f, 0, sizeof(*f)); }

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

static void apply_kv(Etw1Fields *f, const char *key, const char *val) {
  if (!key || !val) {
    return;
  }
  if (strcmp(key, "prov") == 0) {
    snprintf(f->prov, sizeof(f->prov), "%s", val);
  } else if (strcmp(key, "pid") == 0) {
    f->pid = parse_ulong_auto(val);
  } else if (strcmp(key, "epid") == 0) {
    f->epid = parse_ulong_auto(val);
  } else if (strcmp(key, "hint_pid") == 0) {
    f->epid = parse_ulong_auto(val);
  } else if (strcmp(key, "ppid") == 0) {
    f->ppid = parse_ulong_auto(val);
  } else if (strcmp(key, "user") == 0 || strcmp(key, "username") == 0) {
    snprintf(f->user, sizeof(f->user), "%s", val);
  } else if (strcmp(key, "user_domain") == 0 || strcmp(key, "subject_domain") == 0) {
    snprintf(f->domain, sizeof(f->domain), "%s", val);
  } else if (strcmp(key, "parent_img") == 0 || strcmp(key, "parent_path") == 0) {
    snprintf(f->parent_img, sizeof(f->parent_img), "%s", val);
    f->has_parent_img = 1;
  } else if (strcmp(key, "parent_cmdline") == 0 || strcmp(key, "parent_cmd") == 0) {
    snprintf(f->parent_cmdline, sizeof(f->parent_cmdline), "%s", val);
    f->has_parent_cmdline = 1;
  } else if (strcmp(key, "current_directory") == 0 || strcmp(key, "cwd") == 0) {
    snprintf(f->cwd, sizeof(f->cwd), "%s", val);
    f->has_cwd = 1;
  } else if (strcmp(key, "integrity") == 0 || strcmp(key, "mandatory_label") == 0) {
    snprintf(f->integrity, sizeof(f->integrity), "%s", val);
    f->has_integrity = 1;
  } else if (strcmp(key, "token_elevation") == 0 || strcmp(key, "token_elevation_type") == 0) {
    snprintf(f->token_elevation, sizeof(f->token_elevation), "%s", val);
    f->has_token_elevation = 1;
  } else if (strcmp(key, "process_creation_time") == 0 || strcmp(key, "create_time") == 0) {
    snprintf(f->process_creation_time, sizeof(f->process_creation_time), "%s", val);
    f->has_process_creation_time = 1;
  } else if (strcmp(key, "img") == 0) {
    snprintf(f->img, sizeof(f->img), "%s", val);
    f->has_img = 1;
  } else if (strcmp(key, "cmd") == 0) {
    snprintf(f->cmd, sizeof(f->cmd), "%s", val);
    f->has_cmd = 1;
  } else if (strcmp(key, "path") == 0 && !f->file[0]) {
    snprintf(f->file, sizeof(f->file), "%s", val);
  } else if (strcmp(key, "old_file") == 0 || strcmp(key, "old_path") == 0 ||
             strcmp(key, "source_file") == 0 || strcmp(key, "source_path") == 0 ||
             strcmp(key, "previous_file") == 0 || strcmp(key, "previous_path") == 0 ||
             strcmp(key, "rename_from") == 0) {
    snprintf(f->old_file, sizeof(f->old_file), "%s", val);
  } else if (strcmp(key, "new_file") == 0 || strcmp(key, "new_path") == 0 ||
             strcmp(key, "target_file") == 0 || strcmp(key, "target_path") == 0 ||
             strcmp(key, "rename_to") == 0) {
    snprintf(f->file, sizeof(f->file), "%s", val);
  } else if (strcmp(key, "cert_revoked_ancestor") == 0 || strcmp(key, "cert_ra") == 0) {
    f->cert_revoked_ancestor = (strtoul(val, NULL, 10) != 0u) ? 1u : 0u;
    f->has_cert_revoked_ancestor = 1;
  } else if (strcmp(key, "file") == 0) {
    snprintf(f->file, sizeof(f->file), "%s", val);
  } else if (strcmp(key, "signer") == 0 || strcmp(key, "publisher") == 0 ||
             strcmp(key, "signature_publisher") == 0 || strcmp(key, "cert_subject") == 0) {
    snprintf(f->signer, sizeof(f->signer), "%s", val);
    append_sensor_kv(f, "signer", val);
  } else if (strcmp(key, "signature_status") == 0 || strcmp(key, "signature_trust") == 0 ||
             strcmp(key, "signed") == 0 || strcmp(key, "verified") == 0) {
    snprintf(f->signature_status, sizeof(f->signature_status), "%s", val);
    append_sensor_kv(f, "signature_status", val);
  } else if (strcmp(key, "qname") == 0) {
    snprintf(f->qname, sizeof(f->qname), "%s", val);
  } else if (strcmp(key, "ip") == 0 && !f->dst[0]) {
    snprintf(f->dst, sizeof(f->dst), "%s", val);
  } else if (strcmp(key, "script") == 0) {
    snprintf(f->script, sizeof(f->script), "%s", val);
  } else if (strcmp(key, "amsi_content") == 0 || strcmp(key, "script_content") == 0 ||
             strcmp(key, "script_text") == 0) {
    if (!f->script[0]) {
      snprintf(f->script, sizeof(f->script), "%s", val);
    }
    append_sensor_kv(f, key, val);
  } else if (strcmp(key, "app_name") == 0) {
    if (!f->has_img && val[0]) {
      snprintf(f->img, sizeof(f->img), "%s", val);
      f->has_img = 1;
    }
    append_sensor_kv(f, key, val);
  } else if (strcmp(key, "url") == 0 || strcmp(key, "remote_url") == 0 || strcmp(key, "domain") == 0) {
    snprintf(f->url, sizeof(f->url), "%s", val);
    append_sensor_kv(f, key, val);
  } else if (strcmp(key, "sha256") == 0 || strcmp(key, "file_sha256") == 0 || strcmp(key, "file_hash") == 0) {
    snprintf(f->sha256, sizeof(f->sha256), "%s", val);
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
    append_sensor_kv(f, key, val);
  } else if (strcmp(key, "dst") == 0) {
    snprintf(f->dst, sizeof(f->dst), "%s", val);
  } else if (strcmp(key, "src") == 0) {
    snprintf(f->src, sizeof(f->src), "%s", val);
  } else if (strcmp(key, "dpt") == 0) {
    f->dport = strtoul(val, NULL, 10);
    f->has_dport = 1;
  } else if (strcmp(key, "spt") == 0) {
    f->sport = strtoul(val, NULL, 10);
    f->has_sport = 1;
  } else if (strcmp(key, "laddr") == 0) {
    snprintf(f->src, sizeof(f->src), "%s", val);
  } else if (strcmp(key, "raddr") == 0) {
    snprintf(f->dst, sizeof(f->dst), "%s", val);
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
    snprintf(f->proto, sizeof(f->proto), "%s", val);
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
  } else if (strcmp(key, "shellcode_json") == 0) {
    snprintf(f->shellcode_json, sizeof(f->shellcode_json), "%s", val);
  } else if (strcmp(key, "regkey") == 0 || strcmp(key, "registry_key") == 0 ||
             strcmp(key, "registry_path") == 0 || strcmp(key, "target_object") == 0) {
    snprintf(f->regkey, sizeof(f->regkey), "%s", val);
  } else if ((strcmp(key, "regpath") == 0 || strcmp(key, "key_path") == 0) && !f->regkey[0]) {
    snprintf(f->regkey, sizeof(f->regkey), "%s", val);
  } else if (strcmp(key, "regname") == 0 || strcmp(key, "registry_value") == 0 ||
             strcmp(key, "value_name") == 0) {
    snprintf(f->regname, sizeof(f->regname), "%s", val);
  } else if (strcmp(key, "regdata") == 0 || strcmp(key, "registry_data") == 0 ||
             strcmp(key, "value_data") == 0 || strcmp(key, "details") == 0) {
    snprintf(f->regdata, sizeof(f->regdata), "%s", val);
  } else if (strcmp(key, "regop") == 0 || strcmp(key, "registry_op") == 0 ||
             strcmp(key, "operation") == 0) {
    snprintf(f->regop, sizeof(f->regop), "%s", val);
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
  if (r->type == EDR_EVENT_PMFE_SCAN_RESULT && r->mitre_ttp_count < (int)EDR_BR_MAX_MITRE) {
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
  edr_gen_event_id(r->event_id, sizeof(r->event_id), r->event_time_ns);

  Etw1Fields ef;
  if (slot->size > 0 && etw1_parse(slot->data, slot->size, &ef) == 0) {
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
      snprintf(r->exe_path, sizeof(r->exe_path), "%s", ef.img);
      snprintf(r->process_name, sizeof(r->process_name), "%s", basename_c(ef.img));
    }
    if (ef.has_cmd) {
      snprintf(r->cmdline, sizeof(r->cmdline), "%s", ef.cmd);
      if (!r->exe_path[0]) {
        char first[EDR_BR_STR_LONG];
        first_cmd_token(ef.cmd, first, sizeof(first));
        if (first[0]) {
          snprintf(r->exe_path, sizeof(r->exe_path), "%s", first);
          snprintf(r->process_name, sizeof(r->process_name), "%s", basename_c(first));
        }
      }
    }
    if (ef.user[0]) {
      if (ef.domain[0]) {
        snprintf(r->username, sizeof(r->username), "%s\\%s", ef.domain, ef.user);
      } else {
        snprintf(r->username, sizeof(r->username), "%s", ef.user);
      }
    }
    if (ef.domain[0]) {
      snprintf(r->domain, sizeof(r->domain), "%s", ef.domain);
    }
    if (ef.has_parent_img) {
      snprintf(r->parent_path, sizeof(r->parent_path), "%s", ef.parent_img);
      snprintf(r->parent_name, sizeof(r->parent_name), "%s", basename_c(ef.parent_img));
    }
    if (ef.has_parent_cmdline) {
      snprintf(r->parent_cmdline, sizeof(r->parent_cmdline), "%s", ef.parent_cmdline);
    }
    if (ef.has_cwd) {
      snprintf(r->current_directory, sizeof(r->current_directory), "%s", ef.cwd);
    }
    if (ef.has_integrity) {
      snprintf(r->integrity_level, sizeof(r->integrity_level), "%s", ef.integrity);
    }
    if (ef.has_token_elevation) {
      r->token_elevation = parse_token_elevation_type(ef.token_elevation);
    }
    if (ef.has_process_creation_time) {
      snprintf(r->process_creation_time, sizeof(r->process_creation_time), "%s", ef.process_creation_time);
    }
    if (ef.file[0]) {
      snprintf(r->file_path, sizeof(r->file_path), "%s", ef.file);
      snprintf(r->file_op, sizeof(r->file_op), "event");
    }
    if (ef.old_file[0]) {
      char old_ext[16];
      char new_ext[16];
      extension_c(ef.old_file, old_ext, sizeof(old_ext));
      extension_c(r->file_path[0] ? r->file_path : ef.file, new_ext, sizeof(new_ext));
      append_record_kv(r, "old_ext=%s new_ext=%s ext_changed=%d",
                       old_ext, new_ext, strcmp(old_ext, new_ext) != 0 ? 1 : 0);
    }
    if (ef.qname[0]) {
      snprintf(r->dns_query, sizeof(r->dns_query), "%s", ef.qname);
    }
    if (ef.url[0] && !r->dns_query[0]) {
      snprintf(r->dns_query, sizeof(r->dns_query), "%s", ef.url);
    }
    if (ef.sha256[0]) {
      snprintf(r->exe_hash, sizeof(r->exe_hash), "%s", ef.sha256);
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
      snprintf(r->net_proto, sizeof(r->net_proto), "%s", ef.proto);
    }
    if (ef.has_cert_revoked_ancestor) {
      r->cert_revoked_ancestor = ef.cert_revoked_ancestor;
    }
    if (ef.regkey[0]) {
      snprintf(r->reg_key_path, sizeof(r->reg_key_path), "%s", ef.regkey);
    }
    if (ef.regname[0]) {
      snprintf(r->reg_value_name, sizeof(r->reg_value_name), "%s", ef.regname);
    }
    if (ef.regdata[0]) {
      snprintf(r->reg_value_data, sizeof(r->reg_value_data), "%s", ef.regdata);
    }
    if (ef.regop[0]) {
      snprintf(r->reg_op, sizeof(r->reg_op), "%s", ef.regop);
    }
    if (r->type == EDR_EVENT_REG_CREATE_KEY && !r->reg_op[0]) {
      snprintf(r->reg_op, sizeof(r->reg_op), "create_key");
    } else if (r->type == EDR_EVENT_REG_SET_VALUE && !r->reg_op[0]) {
      snprintf(r->reg_op, sizeof(r->reg_op), "set_value");
    } else if (r->type == EDR_EVENT_REG_DELETE_KEY && !r->reg_op[0]) {
      snprintf(r->reg_op, sizeof(r->reg_op), "delete_key");
    }
    if (ef.score[0] || ef.proto[0] || ef.detector[0] || ef.rule[0] || ef.mitre[0] || ef.forensic_kind[0] ||
        ef.pcap_stem[0] || ef.has_forensic_frames || ef.has_ring_meta || ef.shellcode_json[0]) {
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
    if (ef.sensor_detail[0]) {
      size_t L = strlen(r->script_snippet);
      snprintf(r->script_snippet + L, sizeof(r->script_snippet) - L, "%s%s",
               L > 0u ? " " : "", ef.sensor_detail);
    }
  } else if (slot->size > 0) {
    size_t n = slot->size;
    if (n >= sizeof(r->cmdline)) {
      n = sizeof(r->cmdline) - 1u;
    }
    memcpy(r->cmdline, slot->data, n);
    r->cmdline[n] = '\0';
  }

  enrich_ransom_file_counters(r);
  apply_mitre_hints(r);
}
