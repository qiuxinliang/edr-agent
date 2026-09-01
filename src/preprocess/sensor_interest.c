#include "edr/sensor_interest.h"

#include "edr/adaptive_collection.h"
#include "edr/correlation_engine.h"
#include "edr/p0_rule_ir.h"
#include "edr/sha256.h"

#include "cJSON.h"

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define EDR_SI_MAX_PROC 512u
#define EDR_SI_HASH_SIZE 1024u
#define EDR_SI_MAX_PREFIX 192u
#define EDR_SI_MAX_CONTAINS 256u
#define EDR_SI_MAX_TOKEN 256u
#define EDR_SI_MAX_ENTRY 384u
#define EDR_SI_MAX_PAIR 384u
#define EDR_SI_MAX_FIELD 512u
#define EDR_SI_MANIFEST_HASH_MODE "raw-json-v1-p0-artifact-sha256-zeroed"

typedef struct {
  char value[EDR_SI_MAX_ENTRY];
} EdrSIEntry;

typedef struct {
  char parent[128];
  char child[128];
} EdrSIPair;

typedef struct {
  char value[128];
  uint32_t hash;
  uint8_t used;
} EdrSIProcSlot;

typedef struct {
  int enabled;
  int loaded;
  /* A regular expression cannot be safely reduced to a finite set of
   * literals at the collector boundary.  The published manifest carries a
   * typed event list; these bits are its parsed, fixed vocabulary. */
  int file_read_full_admission;
  int file_write_full_admission;
  int registry_set_full_admission;
  int full_admission_contract_valid;
  int p0_binding_valid;
  char version[128];
  char rules_version[128];
  char p0_artifact_sha256[65];
  char p0_rule_coverage_sha256[65];
  char sensor_interest_manifest_sha256[65];
  char sensor_interest_manifest_hash_mode[64];
  uint32_t p0_artifact_rule_count;
  /* The manifest is only permitted to narrow collection while this exact
   * retained IR generation remains active.  A later IR reload can add an
   * otherwise-unrepresented admission condition, so readers fail full until
   * a manifest validated against that generation is published. */
  uint64_t bound_ir_snapshot_epoch;
  uint64_t bound_ir_pair_generation;
  uint64_t snapshot_epoch;
  uint8_t port_bits[65536u / 8u];
  EdrSIProcSlot proc_hash[EDR_SI_HASH_SIZE];
  EdrSIEntry proc_prefix[EDR_SI_MAX_PROC];
  uint32_t n_proc_hash;
  uint32_t n_proc_prefix;
  uint32_t n_ports;
  EdrSIEntry file_prefix[EDR_SI_MAX_PREFIX];
  EdrSIEntry file_contains[EDR_SI_MAX_CONTAINS];
  EdrSIEntry reg_prefix[EDR_SI_MAX_PREFIX];
  EdrSIEntry reg_contains[EDR_SI_MAX_CONTAINS];
  EdrSIEntry cmd_tokens[EDR_SI_MAX_TOKEN];
  EdrSIPair parent_child[EDR_SI_MAX_PAIR];
  EdrSIEntry required_fields[EDR_SI_MAX_FIELD];
  uint32_t n_file_prefix;
  uint32_t n_file_contains;
  uint32_t n_reg_prefix;
  uint32_t n_reg_contains;
  uint32_t n_cmd_tokens;
  uint32_t n_parent_child;
  uint32_t n_required_fields;
  /* Snapshot lifetime is protected by the publish lock; readers use an
   * immutable object after retaining this count. */
  unsigned int readers;
  int retired;
} EdrSensorInterestState;

typedef struct {
  volatile uint64_t checked;
  volatile uint64_t matched;
  volatile uint64_t dropped;
  volatile uint64_t provider_hits;
  volatile uint64_t adaptive_hits;
  volatile uint64_t process_hits;
  volatile uint64_t port_hits;
  volatile uint64_t path_hits;
  volatile uint64_t registry_hits;
  volatile uint64_t parent_child_hits;
} EdrSensorInterestMetrics;

#if defined(_MSC_VER)
#define EDR_SI_TLS __declspec(thread)
#elif defined(__GNUC__) || defined(__clang__)
#define EDR_SI_TLS __thread
#else
#define EDR_SI_TLS _Thread_local
#endif

static EdrSensorInterestState *s_si_active;
static EDR_SI_TLS EdrSensorInterestState *s_si_tls;
#define s_si (*s_si_tls)
static EdrSensorInterestMetrics s_si_metrics;
static volatile long s_inited;
static uint64_t s_next_snapshot_epoch;

#if defined(EDR_SENSOR_INTEREST_TESTING)
static unsigned int s_test_fail_parent_sync_after;

void edr_sensor_interest_test_fail_parent_sync_after(unsigned int nth_call) {
  s_test_fail_parent_sync_after = nth_call ? nth_call : 1u;
}
#endif

#if defined(_WIN32)
static SRWLOCK s_si_snapshot_lock = SRWLOCK_INIT;
static void edr_si_snapshot_lock(void) { AcquireSRWLockExclusive(&s_si_snapshot_lock); }
static void edr_si_snapshot_unlock(void) { ReleaseSRWLockExclusive(&s_si_snapshot_lock); }
#else
#include <pthread.h>
static pthread_rwlock_t s_si_snapshot_lock = PTHREAD_RWLOCK_INITIALIZER;
static void edr_si_snapshot_lock(void) { (void)pthread_rwlock_wrlock(&s_si_snapshot_lock); }
static void edr_si_snapshot_unlock(void) { (void)pthread_rwlock_unlock(&s_si_snapshot_lock); }
#endif

static uint64_t edr_si_load64(volatile uint64_t *p) {
#if defined(_WIN32)
  return (uint64_t)InterlockedCompareExchange64((volatile LONG64 *)p, 0, 0);
#elif defined(__GNUC__) || defined(__clang__)
  return __sync_add_and_fetch(p, 0);
#else
  return *p;
#endif
}

static void edr_si_inc64(volatile uint64_t *p) {
#if defined(_WIN32)
  (void)InterlockedIncrement64((volatile LONG64 *)p);
#elif defined(__GNUC__) || defined(__clang__)
  (void)__sync_add_and_fetch(p, 1);
#else
  (*p)++;
#endif
}

static EdrSensorInterestState *edr_si_snapshot_acquire(void) {
  EdrSensorInterestState *snapshot;
  edr_si_snapshot_lock();
  snapshot = s_si_active;
  if (snapshot) {
    snapshot->readers++;
  }
  edr_si_snapshot_unlock();
  return snapshot;
}

static void edr_si_snapshot_release(EdrSensorInterestState *snapshot) {
  int destroy = 0;
  if (!snapshot) {
    return;
  }
  edr_si_snapshot_lock();
  if (snapshot->readers > 0u) {
    snapshot->readers--;
  }
  if (snapshot->retired && snapshot->readers == 0u) {
    destroy = 1;
  }
  edr_si_snapshot_unlock();
  if (destroy) {
    free(snapshot);
  }
}

static void edr_si_publish_snapshot(EdrSensorInterestState *next) {
  EdrSensorInterestState *previous;
  int destroy_previous = 0;
  if (!next) {
    return;
  }
  edr_si_snapshot_lock();
  s_next_snapshot_epoch++;
  if (s_next_snapshot_epoch == 0u) {
    s_next_snapshot_epoch++;
  }
  next->snapshot_epoch = s_next_snapshot_epoch;
  previous = s_si_active;
  s_si_active = next;
  if (previous) {
    previous->retired = 1;
    if (previous->readers == 0u) {
      destroy_previous = 1;
    }
  }
  edr_si_snapshot_unlock();
  if (destroy_previous) {
    free(previous);
  }
}

static void edr_si_set_fail_full(EdrSensorInterestState *state) {
  if (!state) {
    return;
  }
  state->file_read_full_admission = 1;
  state->file_write_full_admission = 1;
  state->registry_set_full_admission = 1;
  state->full_admission_contract_valid = 0;
  state->p0_binding_valid = 0;
}

static int edr_si_env_bool(const char *name, int fallback) {
  const char *v = getenv(name);
  if (!v || !v[0]) {
    return fallback;
  }
  return !(v[0] == '0' || v[0] == 'n' || v[0] == 'N' || v[0] == 'f' || v[0] == 'F');
}

static char edr_si_fold(char c) {
  if (c == '/') {
    c = '\\';
  }
  if (c >= 'A' && c <= 'Z') {
    c = (char)(c - 'A' + 'a');
  }
  return c;
}

static void edr_si_norm(char *out, size_t cap, const char *in) {
  size_t o = 0;
  if (!out || cap == 0u) {
    return;
  }
  out[0] = '\0';
  if (!in) {
    return;
  }
  while (*in == ' ' || *in == '\t' || *in == '"' || *in == '\'') {
    in++;
  }
  for (; *in && o + 1u < cap; in++) {
    char c = edr_si_fold(*in);
    if (c == '\r' || c == '\n') {
      break;
    }
    out[o++] = c;
  }
  while (o > 0u && (out[o - 1u] == ' ' || out[o - 1u] == '\t' || out[o - 1u] == '"' ||
                    out[o - 1u] == '\'')) {
    o--;
  }
  out[o] = '\0';
}

static const char *edr_si_basename(const char *s) {
  const char *last = s;
  if (!s) {
    return "";
  }
  for (const char *p = s; *p; p++) {
    if (*p == '\\' || *p == '/') {
      last = p + 1;
    }
  }
  return last;
}

static uint32_t edr_si_fnv1a(const char *s) {
  uint32_t h = 2166136261u;
  if (!s) {
    return h;
  }
  while (*s) {
    h ^= (unsigned char)*s++;
    h *= 16777619u;
  }
  return h ? h : 1u;
}

static int edr_si_contains_ci(const char *hay, const char *needle) {
  char h[1024];
  char n[384];
  if (!needle || !needle[0]) {
    return 1;
  }
  if (!hay || !hay[0]) {
    return 0;
  }
  edr_si_norm(h, sizeof(h), hay);
  edr_si_norm(n, sizeof(n), needle);
  return strstr(h, n) != NULL;
}

static int edr_si_starts_ci(const char *hay, const char *prefix) {
  char h[1024];
  char p[384];
  if (!prefix || !prefix[0]) {
    return 1;
  }
  if (!hay || !hay[0]) {
    return 0;
  }
  edr_si_norm(h, sizeof(h), hay);
  edr_si_norm(p, sizeof(p), prefix);
  return strncmp(h, p, strlen(p)) == 0;
}

static int edr_si_ends_ci(const char *hay, const char *suffix) {
  char h[1024];
  char s[128];
  size_t hl;
  size_t sl;
  if (!hay || !suffix) {
    return 0;
  }
  edr_si_norm(h, sizeof(h), hay);
  edr_si_norm(s, sizeof(s), suffix);
  hl = strlen(h);
  sl = strlen(s);
  return sl > 0u && hl >= sl && strcmp(h + hl - sl, s) == 0;
}

static void edr_si_port_set(uint32_t port) {
  if (port > 65535u) {
    return;
  }
  if ((s_si.port_bits[port / 8u] & (uint8_t)(1u << (port % 8u))) == 0u) {
    s_si.n_ports++;
  }
  s_si.port_bits[port / 8u] |= (uint8_t)(1u << (port % 8u));
}

static int edr_si_port_has(uint32_t port) {
  if (port > 65535u) {
    return 0;
  }
  return (s_si.port_bits[port / 8u] & (uint8_t)(1u << (port % 8u))) != 0u;
}

static void edr_si_add_entry(EdrSIEntry *arr, uint32_t *count, uint32_t max_count,
                             const char *value, int basename_only) {
  char norm[EDR_SI_MAX_ENTRY];
  if (!arr || !count || !value || !value[0] || *count >= max_count) {
    return;
  }
  edr_si_norm(norm, sizeof(norm), basename_only ? edr_si_basename(value) : value);
  if (!norm[0]) {
    return;
  }
  for (uint32_t i = 0; i < *count; i++) {
    if (strcmp(arr[i].value, norm) == 0) {
      return;
    }
  }
  snprintf(arr[*count].value, sizeof(arr[*count].value), "%s", norm);
  (*count)++;
}

static void edr_si_add_parent_child_pair(const char *parent_name, const char *child_name) {
  char parent[128];
  char child[128];
  if (!parent_name || !parent_name[0] || !child_name || !child_name[0] ||
      s_si.n_parent_child >= EDR_SI_MAX_PAIR) {
    return;
  }
  edr_si_norm(parent, sizeof(parent), edr_si_basename(parent_name));
  edr_si_norm(child, sizeof(child), edr_si_basename(child_name));
  if (!parent[0] || !child[0]) {
    return;
  }
  for (uint32_t i = 0; i < s_si.n_parent_child; i++) {
    if (strcmp(s_si.parent_child[i].parent, parent) == 0 &&
        strcmp(s_si.parent_child[i].child, child) == 0) {
      return;
    }
  }
  snprintf(s_si.parent_child[s_si.n_parent_child].parent,
           sizeof(s_si.parent_child[s_si.n_parent_child].parent), "%s", parent);
  snprintf(s_si.parent_child[s_si.n_parent_child].child,
           sizeof(s_si.parent_child[s_si.n_parent_child].child), "%s", child);
  s_si.n_parent_child++;
}

static int edr_si_parent_child_matches(const char *parent_name, const char *child_name) {
  char parent[128];
  char child[128];
  if (!parent_name || !parent_name[0] || !child_name || !child_name[0]) {
    return 0;
  }
  edr_si_norm(parent, sizeof(parent), edr_si_basename(parent_name));
  edr_si_norm(child, sizeof(child), edr_si_basename(child_name));
  if (!parent[0] || !child[0]) {
    return 0;
  }
  for (uint32_t i = 0; i < s_si.n_parent_child; i++) {
    if (strcmp(s_si.parent_child[i].parent, parent) == 0 &&
        strcmp(s_si.parent_child[i].child, child) == 0) {
      return 1;
    }
  }
  return 0;
}

static void edr_si_add_process_name(const char *name) {
  char norm[128];
  uint32_t h;
  uint32_t idx;
  if (!name || !name[0]) {
    return;
  }
  edr_si_norm(norm, sizeof(norm), edr_si_basename(name));
  if (!norm[0]) {
    return;
  }
  h = edr_si_fnv1a(norm);
  idx = h % EDR_SI_HASH_SIZE;
  for (uint32_t probe = 0; probe < EDR_SI_HASH_SIZE; probe++) {
    EdrSIProcSlot *slot = &s_si.proc_hash[(idx + probe) % EDR_SI_HASH_SIZE];
    if (slot->used && strcmp(slot->value, norm) == 0) {
      return;
    }
    if (!slot->used) {
      slot->used = 1u;
      slot->hash = h;
      snprintf(slot->value, sizeof(slot->value), "%s", norm);
      s_si.n_proc_hash++;
      return;
    }
  }
}

static int edr_si_process_has(const char *name) {
  char norm[128];
  uint32_t h;
  uint32_t idx;
  if (!name || !name[0]) {
    return 0;
  }
  edr_si_norm(norm, sizeof(norm), edr_si_basename(name));
  if (!norm[0]) {
    return 0;
  }
  h = edr_si_fnv1a(norm);
  idx = h % EDR_SI_HASH_SIZE;
  for (uint32_t probe = 0; probe < EDR_SI_HASH_SIZE; probe++) {
    const EdrSIProcSlot *slot = &s_si.proc_hash[(idx + probe) % EDR_SI_HASH_SIZE];
    if (!slot->used) {
      return 0;
    }
    if (slot->hash == h && strcmp(slot->value, norm) == 0) {
      return 1;
    }
  }
  return 0;
}

static int edr_si_any_contains(EdrSIEntry *arr, uint32_t count, const char *value) {
  for (uint32_t i = 0; i < count; i++) {
    if (edr_si_contains_ci(value, arr[i].value)) {
      return 1;
    }
  }
  return 0;
}

static int edr_si_any_prefix(EdrSIEntry *arr, uint32_t count, const char *value) {
  for (uint32_t i = 0; i < count; i++) {
    if (edr_si_starts_ci(value, arr[i].value) || edr_si_contains_ci(value, arr[i].value)) {
      return 1;
    }
  }
  return 0;
}

static int edr_si_process_interesting(const char *process_name) {
  if (edr_si_process_has(process_name)) {
    return 1;
  }
  for (uint32_t i = 0; i < s_si.n_proc_prefix; i++) {
    if (edr_si_contains_ci(process_name, s_si.proc_prefix[i].value)) {
      return 1;
    }
  }
  return 0;
}

static void edr_si_add_json_string_array(cJSON *root, const char *name, EdrSIEntry *arr,
                                         uint32_t *count, uint32_t max_count,
                                         int basename_only) {
  cJSON *a = cJSON_GetObjectItemCaseSensitive(root, name);
  if (!cJSON_IsArray(a)) {
    return;
  }
  cJSON *it;
  cJSON_ArrayForEach(it, a) {
    if (cJSON_IsString(it) && it->valuestring) {
      edr_si_add_entry(arr, count, max_count, it->valuestring, basename_only);
    }
  }
}

static void edr_si_add_json_process_array(cJSON *root, const char *name) {
  cJSON *a = cJSON_GetObjectItemCaseSensitive(root, name);
  if (!cJSON_IsArray(a)) {
    return;
  }
  cJSON *it;
  cJSON_ArrayForEach(it, a) {
    if (cJSON_IsString(it) && it->valuestring) {
      edr_si_add_process_name(it->valuestring);
    }
  }
}

static void edr_si_add_json_port_array(cJSON *root, const char *name) {
  cJSON *a = cJSON_GetObjectItemCaseSensitive(root, name);
  if (!cJSON_IsArray(a)) {
    return;
  }
  cJSON *it;
  cJSON_ArrayForEach(it, a) {
    if (cJSON_IsNumber(it) && it->valuedouble > 0 && it->valuedouble <= 65535.0) {
      edr_si_port_set((uint32_t)it->valuedouble);
    }
  }
}

static void edr_si_add_json_parent_child_pairs(cJSON *root, const char *name) {
  cJSON *a = cJSON_GetObjectItemCaseSensitive(root, name);
  if (!cJSON_IsArray(a)) {
    return;
  }
  cJSON *it;
  cJSON_ArrayForEach(it, a) {
    cJSON *parent = cJSON_GetObjectItemCaseSensitive(it, "parent");
    cJSON *child = cJSON_GetObjectItemCaseSensitive(it, "child");
    if (cJSON_IsString(parent) && parent->valuestring &&
        cJSON_IsString(child) && child->valuestring) {
      edr_si_add_parent_child_pair(parent->valuestring, child->valuestring);
    }
  }
}

static void edr_si_add_json_required_fields(cJSON *root, const char *name) {
  cJSON *a = cJSON_GetObjectItemCaseSensitive(root, name);
  if (!cJSON_IsArray(a)) {
    return;
  }
  cJSON *it;
  cJSON_ArrayForEach(it, a) {
    cJSON *fields = cJSON_GetObjectItemCaseSensitive(it, "required_fields");
    if (!cJSON_IsArray(fields)) {
      fields = cJSON_GetObjectItemCaseSensitive(it, "fields");
    }
    if (!cJSON_IsArray(fields)) {
      continue;
    }
    cJSON *field;
    cJSON_ArrayForEach(field, fields) {
      if (cJSON_IsString(field) && field->valuestring) {
        edr_si_add_entry(s_si.required_fields, &s_si.n_required_fields, EDR_SI_MAX_FIELD,
                         field->valuestring, 0);
      }
    }
  }
}

static void edr_si_add_defaults(void) {
  static const uint16_t ports[] = {
      22, 53, 88, 135, 139, 389, 445, 464, 593, 636, 1080, 1433, 3128, 3306,
      3389, 5432, 5938, 5985, 5986, 6379, 7070, 8080, 8118, 8443, 9001, 9050,
      9200, 9300, 11211, 27017, 47001,
  };
  static const char *const proc[] = {
      "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe",
      "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "msiexec.exe",
      "wmic.exe", "odbcconf.exe", "msbuild.exe", "installutil.exe", "regasm.exe",
      "regsvcs.exe", "psexec.exe", "psexesvc.exe", "paexec.exe", "rclone.exe", "curl.exe",
      "wget.exe", "ngrok.exe", "frpc.exe", "chisel.exe", "plink.exe", "anydesk.exe",
      "teamviewer.exe",
  };
  static const char *const file_contains[] = {
      "\\ntds.dit", "\\config\\sam", "\\config\\system", "\\config\\security",
      "\\config\\software", "lsass.dmp", "\\sam.save", "\\system.save",
      "\\inetpub\\wwwroot\\", "\\wwwroot\\", "\\tomcat\\webapps\\", "\\nginx\\html\\",
      "\\apache\\htdocs\\", "\\phpstudy\\", "\\xampp\\htdocs\\",
      "\\microsoft\\windows\\start menu\\programs\\startup\\",
      "\\windows\\system32\\tasks\\", "\\windows\\tasks\\",
      "\\windows\\system32\\drivers\\", "\\windows\\system32\\spool\\drivers\\",
      "\\appdata\\local\\temp\\", "\\windows\\temp\\", "\\users\\public\\",
      "how_to_decrypt", "restore-files", "readme_to_decrypt", "decrypt_readme", "ransom",
  };
  static const char *const reg_contains[] = {
      "\\software\\microsoft\\windows\\currentversion\\run",
      "\\software\\microsoft\\windows\\currentversion\\runonce",
      "\\system\\currentcontrolset\\services\\",
      "\\windows nt\\currentversion\\winlogon",
      "\\image file execution options\\",
      "\\silentprocessexit\\",
      "\\windows nt\\currentversion\\windows",
      "\\control\\lsa",
      "\\securitypackages",
      "\\wdigest",
      "\\windows defender",
      "\\policies\\microsoft\\windows defender",
      "\\security center",
      "\\terminal server",
      "\\firewallpolicy\\",
      "\\sharedaccess\\parameters\\firewallpolicy",
      "\\software\\microsoft\\office\\",
      "\\software\\microsoft\\windows\\currentversion\\policies\\system",
  };
  static const char *const cmd_tokens[] = {
      "-enc", "encodedcommand", "frombase64string", "downloadstring", "iex", "invoke-expression",
      "bypass", "hidden", "http://", "https://", "ftp://", "javascript:", "vbscript:",
      "mimikatz", "sekurlsa", "procdump", "lsass", "vssadmin", "wmic shadowcopy",
      "delete shadows", "rundll32", "regsvr32", "mshta",
  };
  for (size_t i = 0; i < sizeof(ports) / sizeof(ports[0]); i++) {
    edr_si_port_set(ports[i]);
  }
  for (size_t i = 0; i < sizeof(proc) / sizeof(proc[0]); i++) {
    edr_si_add_process_name(proc[i]);
  }
  for (size_t i = 0; i < sizeof(file_contains) / sizeof(file_contains[0]); i++) {
    edr_si_add_entry(s_si.file_contains, &s_si.n_file_contains, EDR_SI_MAX_CONTAINS,
                     file_contains[i], 0);
  }
  for (size_t i = 0; i < sizeof(reg_contains) / sizeof(reg_contains[0]); i++) {
    edr_si_add_entry(s_si.reg_contains, &s_si.n_reg_contains, EDR_SI_MAX_CONTAINS,
                     reg_contains[i], 0);
  }
  for (size_t i = 0; i < sizeof(cmd_tokens) / sizeof(cmd_tokens[0]); i++) {
    edr_si_add_entry(s_si.cmd_tokens, &s_si.n_cmd_tokens, EDR_SI_MAX_TOKEN, cmd_tokens[i], 0);
  }
}

static char *edr_si_read_file(const char *path, size_t *out_len) {
  FILE *f;
  long n;
  char *buf;
  if (out_len) {
    *out_len = 0;
  }
  if (!path || !path[0]) {
    return NULL;
  }
  f = fopen(path, "rb");
  if (!f) {
    return NULL;
  }
  if (fseek(f, 0, SEEK_END) != 0) {
    fclose(f);
    return NULL;
  }
  n = ftell(f);
  if (n <= 0 || n > 4 * 1024 * 1024) {
    fclose(f);
    return NULL;
  }
  rewind(f);
  buf = (char *)malloc((size_t)n + 1u);
  if (!buf) {
    fclose(f);
    return NULL;
  }
  if (fread(buf, 1, (size_t)n, f) != (size_t)n) {
    free(buf);
    fclose(f);
    return NULL;
  }
  fclose(f);
  buf[n] = '\0';
  if (out_len) {
    *out_len = (size_t)n;
  }
  return buf;
}

static int edr_si_hex64(const char *value) {
  size_t i;
  if (!value || strlen(value) != 64u) {
    return 0;
  }
  for (i = 0; i < 64u; ++i) {
    char c = value[i];
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
      return 0;
    }
  }
  return 1;
}

static int edr_si_hex64_span(const char *value, size_t len) {
  size_t i;
  if (!value || len != 64u) {
    return 0;
  }
  for (i = 0u; i < len; ++i) {
    char c = value[i];
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
      return 0;
    }
  }
  return 1;
}

static int edr_si_manifest_keys_are_strict(cJSON *root) {
  static const char *const allowed[] = {
      "kind", "schema_version", "rules_bundle_version", "source_dynamic_rules", "enabled_rules",
      "process_names", "process_name_prefixes", "cmd_tokens", "remote_ports",
      "file_path_prefixes", "file_path_contains", "full_admission_event_types",
      "registry_path_prefixes", "registry_path_contains", "parent_child_pairs",
      "attack_stage_required_fields", "interest_version", "generated_at", "counts",
      "p0_artifact_sha256", "p0_artifact_rule_count", "p0_rule_ids",
      "p0_rule_coverage_sha256",
  };
  uint32_t seen = 0u;
  cJSON *item;
  if (!cJSON_IsObject(root)) {
    return 0;
  }
  for (item = root->child; item; item = item->next) {
    size_t index;
    int found = 0;
    if (!item->string) {
      return 0;
    }
    for (index = 0u; index < sizeof(allowed) / sizeof(allowed[0]); ++index) {
      if (strcmp(item->string, allowed[index]) == 0) {
        found = 1;
        break;
      }
    }
    if (!found || index >= 32u || (seen & (1u << index)) != 0u) {
      return 0;
    }
    seen |= 1u << index;
  }
  return 1;
}

static int edr_si_cmp_id(const void *left, const void *right) {
  return strcmp((const char *)left, (const char *)right);
}

static const char *edr_si_skip_ws(const char *cursor, const char *end) {
  while (cursor < end && (*cursor == ' ' || *cursor == '\t' || *cursor == '\r' || *cursor == '\n')) {
    cursor++;
  }
  return cursor;
}

static int edr_si_skip_json_string(const char **cursor, const char *end,
                                   const char **out_content, size_t *out_content_len) {
  const char *p = *cursor;
  const char *content;
  if (p >= end || *p != '"') {
    return 0;
  }
  content = ++p;
  while (p < end) {
    if (*p == '"') {
      if (out_content) {
        *out_content = content;
      }
      if (out_content_len) {
        *out_content_len = (size_t)(p - content);
      }
      *cursor = p + 1;
      return 1;
    }
    if ((unsigned char)*p < 0x20u) {
      return 0;
    }
    if (*p == '\\') {
      p++;
      if (p >= end) {
        return 0;
      }
      if (*p == 'u') {
        if (p + 4 >= end) {
          return 0;
        }
        p += 4;
      }
    }
    p++;
  }
  return 0;
}

static int edr_si_skip_json_value(const char **cursor, const char *end, unsigned depth) {
  const char *p = edr_si_skip_ws(*cursor, end);
  if (depth > 32u || p >= end) {
    return 0;
  }
  if (*p == '"') {
    if (!edr_si_skip_json_string(&p, end, NULL, NULL)) {
      return 0;
    }
    *cursor = p;
    return 1;
  }
  if (*p == '{') {
    p = edr_si_skip_ws(p + 1, end);
    if (p < end && *p == '}') {
      *cursor = p + 1;
      return 1;
    }
    while (p < end) {
      if (!edr_si_skip_json_string(&p, end, NULL, NULL)) {
        return 0;
      }
      p = edr_si_skip_ws(p, end);
      if (p >= end || *p++ != ':') {
        return 0;
      }
      if (!edr_si_skip_json_value(&p, end, depth + 1u)) {
        return 0;
      }
      p = edr_si_skip_ws(p, end);
      if (p < end && *p == '}') {
        *cursor = p + 1;
        return 1;
      }
      if (p >= end || *p++ != ',') {
        return 0;
      }
      p = edr_si_skip_ws(p, end);
    }
    return 0;
  }
  if (*p == '[') {
    p = edr_si_skip_ws(p + 1, end);
    if (p < end && *p == ']') {
      *cursor = p + 1;
      return 1;
    }
    while (p < end) {
      if (!edr_si_skip_json_value(&p, end, depth + 1u)) {
        return 0;
      }
      p = edr_si_skip_ws(p, end);
      if (p < end && *p == ']') {
        *cursor = p + 1;
        return 1;
      }
      if (p >= end || *p++ != ',') {
        return 0;
      }
      p = edr_si_skip_ws(p, end);
    }
    return 0;
  }
  {
    const char *start = p;
    while (p < end && *p != ',' && *p != '}' && *p != ']' &&
           *p != ' ' && *p != '\t' && *p != '\r' && *p != '\n') {
      p++;
    }
    if (p == start) {
      return 0;
    }
    *cursor = p;
    return 1;
  }
}

/* Find the only permitted recursive binding span without ever rewriting a
 * look-alike substring in a nested value.  cJSON subsequently validates the
 * full tree and rejects duplicate/unknown keys. */
static int edr_si_find_top_level_artifact_sha_span(const char *json, size_t len,
                                                   size_t *out_offset) {
  const char *p = json;
  const char *end = json ? json + len : NULL;
  unsigned found = 0u;
  if (!json || !out_offset) {
    return 0;
  }
  p = edr_si_skip_ws(p, end);
  if (p >= end || *p++ != '{') {
    return 0;
  }
  p = edr_si_skip_ws(p, end);
  if (p < end && *p == '}') {
    return 0;
  }
  while (p < end) {
    const char *key = NULL;
    const char *value = NULL;
    size_t key_len = 0u;
    size_t value_len = 0u;
    if (!edr_si_skip_json_string(&p, end, &key, &key_len)) {
      return 0;
    }
    p = edr_si_skip_ws(p, end);
    if (p >= end || *p++ != ':') {
      return 0;
    }
    p = edr_si_skip_ws(p, end);
    if (key_len == strlen("p0_artifact_sha256") &&
        memcmp(key, "p0_artifact_sha256", key_len) == 0) {
      if (!edr_si_skip_json_string(&p, end, &value, &value_len) ||
          !edr_si_hex64_span(value, value_len) || found != 0u) {
        return 0;
      }
      *out_offset = (size_t)(value - json);
      found = 1u;
    } else if (!edr_si_skip_json_value(&p, end, 0u)) {
      return 0;
    }
    p = edr_si_skip_ws(p, end);
    if (p < end && *p == '}') {
      p++;
      break;
    }
    if (p >= end || *p++ != ',') {
      return 0;
    }
    p = edr_si_skip_ws(p, end);
  }
  return found == 1u && edr_si_skip_ws(p, end) == end;
}

static int edr_si_constant_time_hex_equal(const char *left, const char *right) {
  unsigned diff = 0u;
  if (!left || !right || strlen(left) != 64u || strlen(right) != 64u) {
    return 0;
  }
  for (size_t i = 0u; i < 64u; ++i) {
    diff |= (unsigned)((unsigned char)left[i] ^ (unsigned char)right[i]);
  }
  return diff == 0u;
}

static int edr_si_active_ir_binding_matches_state(const EdrSensorInterestState *state) {
  EdrP0RuleIrBinding active;
  if (!state || !state->p0_binding_valid || state->bound_ir_snapshot_epoch == 0u ||
      state->bound_ir_pair_generation == 0u ||
      !edr_p0_rule_ir_get_binding(&active) ||
      edr_p0_rule_ir_sensor_admission_generation() != state->bound_ir_pair_generation ||
      active.snapshot_epoch != state->bound_ir_snapshot_epoch ||
      active.rule_count != state->p0_artifact_rule_count ||
      strcmp(active.rules_bundle_version, state->rules_version) != 0 ||
      strcmp(active.sensor_interest_manifest_hash_mode,
             state->sensor_interest_manifest_hash_mode) != 0 ||
      !edr_si_constant_time_hex_equal(active.artifact_sha256, state->p0_artifact_sha256) ||
      !edr_si_constant_time_hex_equal(active.sensor_interest_manifest_sha256,
                                      state->sensor_interest_manifest_sha256)) {
    return 0;
  }
  return 1;
}

static int edr_si_manifest_raw_hash_matches_p0(const char *json, size_t len,
                                                EdrP0RuleIrBinding *out_binding) {
  EdrP0RuleIrBinding binding;
  char *copy;
  char digest[65];
  size_t offset = 0u;
  if (!json || !out_binding || !edr_p0_rule_ir_get_binding(&binding) ||
      strcmp(binding.sensor_interest_manifest_hash_mode, EDR_SI_MANIFEST_HASH_MODE) != 0 ||
      !edr_si_hex64(binding.sensor_interest_manifest_sha256) ||
      !edr_si_find_top_level_artifact_sha_span(json, len, &offset) || offset + 64u > len) {
    return 0;
  }
  copy = (char *)malloc(len ? len : 1u);
  if (!copy) {
    return 0;
  }
  memcpy(copy, json, len);
  memset(copy + offset, '0', 64u);
  if (edr_sha256_hex((const uint8_t *)copy, len, digest) != 0) {
    free(copy);
    return 0;
  }
  free(copy);
  if (!edr_si_constant_time_hex_equal(digest, binding.sensor_interest_manifest_sha256)) {
    return 0;
  }
  *out_binding = binding;
  return 1;
}

/* The manifest's P0 ID vector is the coverage proof: the exact active
 * artifact hash binds every rule condition, while this sorted vector proves
 * no active rule was omitted from the collector-admission derivation. */
static int edr_si_manifest_p0_binding_valid(cJSON *root, unsigned declared_full_mask,
                                            const EdrP0RuleIrBinding *before) {
  EdrP0RuleIrBinding after;
  cJSON *kind;
  cJSON *schema;
  cJSON *bundle_version;
  cJSON *artifact_sha;
  cJSON *artifact_count;
  cJSON *coverage_sha;
  cJSON *ids;
  char expected[256][64];
  int expected_count;
  unsigned required_mask;
  if (!root || !before || before->rule_count == 0u || before->rule_count > 256u) {
    return 0;
  }
  kind = cJSON_GetObjectItemCaseSensitive(root, "kind");
  schema = cJSON_GetObjectItemCaseSensitive(root, "schema_version");
  bundle_version = cJSON_GetObjectItemCaseSensitive(root, "rules_bundle_version");
  artifact_sha = cJSON_GetObjectItemCaseSensitive(root, "p0_artifact_sha256");
  artifact_count = cJSON_GetObjectItemCaseSensitive(root, "p0_artifact_rule_count");
  coverage_sha = cJSON_GetObjectItemCaseSensitive(root, "p0_rule_coverage_sha256");
  ids = cJSON_GetObjectItemCaseSensitive(root, "p0_rule_ids");
  if (!cJSON_IsString(kind) || !kind->valuestring ||
      strcmp(kind->valuestring, "edr_sensor_interest_manifest") != 0 ||
      !cJSON_IsNumber(schema) || schema->valueint != 1 ||
      !cJSON_IsString(bundle_version) || !bundle_version->valuestring ||
      strcmp(bundle_version->valuestring, before->rules_bundle_version) != 0 ||
      !cJSON_IsString(artifact_sha) || !artifact_sha->valuestring ||
      !edr_si_constant_time_hex_equal(artifact_sha->valuestring, before->artifact_sha256) ||
      !cJSON_IsNumber(artifact_count) || artifact_count->valueint < 0 ||
      (uint32_t)artifact_count->valueint != before->rule_count ||
      !cJSON_IsString(coverage_sha) || !edr_si_hex64(coverage_sha->valuestring) ||
      !cJSON_IsArray(ids) || cJSON_GetArraySize(ids) != (int)before->rule_count) {
    return 0;
  }
  required_mask = edr_p0_rule_ir_required_full_admission_mask();
  if (required_mask != declared_full_mask) {
    return 0;
  }
  expected_count = edr_p0_rule_ir_rule_count();
  if (expected_count != (int)before->rule_count) {
    return 0;
  }
  for (int i = 0; i < expected_count; ++i) {
    const char *id = NULL;
    if (!edr_p0_rule_ir_rule_id_at(i, &id) || !id || !id[0]) {
      return 0;
    }
    snprintf(expected[i], sizeof(expected[i]), "%s", id);
  }
  qsort(expected, (size_t)expected_count, sizeof(expected[0]), edr_si_cmp_id);
  for (int i = 0; i < expected_count; ++i) {
    cJSON *id = cJSON_GetArrayItem(ids, i);
    if (!cJSON_IsString(id) || !id->valuestring || strcmp(id->valuestring, expected[i]) != 0) {
      return 0;
    }
  }
  if (!edr_p0_rule_ir_get_binding(&after) || after.snapshot_epoch != before->snapshot_epoch ||
      after.rule_count != before->rule_count ||
      !edr_si_constant_time_hex_equal(after.artifact_sha256, before->artifact_sha256) ||
      !edr_si_constant_time_hex_equal(after.sensor_interest_manifest_sha256,
                                      before->sensor_interest_manifest_sha256) ||
      strcmp(after.sensor_interest_manifest_hash_mode, before->sensor_interest_manifest_hash_mode) != 0 ||
      strcmp(after.rules_bundle_version, before->rules_bundle_version) != 0) {
    return 0;
  }
  snprintf(s_si.p0_artifact_sha256, sizeof(s_si.p0_artifact_sha256), "%s", before->artifact_sha256);
  snprintf(s_si.p0_rule_coverage_sha256, sizeof(s_si.p0_rule_coverage_sha256), "%s",
           coverage_sha->valuestring);
  snprintf(s_si.sensor_interest_manifest_sha256, sizeof(s_si.sensor_interest_manifest_sha256), "%s",
           before->sensor_interest_manifest_sha256);
  snprintf(s_si.sensor_interest_manifest_hash_mode,
           sizeof(s_si.sensor_interest_manifest_hash_mode), "%s",
           before->sensor_interest_manifest_hash_mode);
  s_si.p0_artifact_rule_count = before->rule_count;
  s_si.bound_ir_snapshot_epoch = before->snapshot_epoch;
  s_si.bound_ir_pair_generation = edr_p0_rule_ir_sensor_admission_generation();
  return 1;
}

static int edr_si_load_json_doc(const char *label, const char *json, size_t len) {
  cJSON *root;
  cJSON *v;
  EdrP0RuleIrBinding raw_binding;
  unsigned declared_full_mask = 0u;
  int full_list_valid = 0;
  if (!json || len == 0u) {
    return -1;
  }
  if (!edr_si_manifest_raw_hash_matches_p0(json, len, &raw_binding)) {
    fprintf(stderr, "[sensor_interest] raw manifest binding failed: %s\n", label ? label : "manifest");
    return -1;
  }
  root = cJSON_ParseWithLength(json, len);
  if (!root || !edr_si_manifest_keys_are_strict(root)) {
    fprintf(stderr, "[sensor_interest] JSON parse failed: %s\n", label ? label : "manifest");
    if (root) {
      cJSON_Delete(root);
    }
    return -1;
  }
  v = cJSON_GetObjectItemCaseSensitive(root, "interest_version");
  if (cJSON_IsString(v) && v->valuestring) {
    snprintf(s_si.version, sizeof(s_si.version), "%s", v->valuestring);
  }
  v = cJSON_GetObjectItemCaseSensitive(root, "rules_bundle_version");
  if (cJSON_IsString(v) && v->valuestring) {
    snprintf(s_si.rules_version, sizeof(s_si.rules_version), "%s", v->valuestring);
  }
  /* This list is an admission *superset* contract, not an optimisation hint.
   * It is valid only when it exactly matches the active verified P0 IR. */
  v = cJSON_GetObjectItemCaseSensitive(root, "full_admission_event_types");
  if (cJSON_IsArray(v)) {
    int valid = 1;
    unsigned seen = 0u;
    cJSON *item = NULL;
    cJSON_ArrayForEach(item, v) {
      if (!cJSON_IsString(item) || !item->valuestring) {
        valid = 0;
        break;
      }
      if (strcmp(item->valuestring, "file_read") == 0) {
        if ((seen & 1u) != 0u) { valid = 0; break; }
        seen |= 1u;
      } else if (strcmp(item->valuestring, "file_write") == 0) {
        if ((seen & 2u) != 0u) { valid = 0; break; }
        seen |= 2u;
      } else if (strcmp(item->valuestring, "registry_set") == 0) {
        if ((seen & 4u) != 0u) { valid = 0; break; }
        seen |= 4u;
      } else {
        valid = 0;
        break;
      }
    }
    if (valid) {
      declared_full_mask = seen;
      full_list_valid = 1;
    }
  }
  s_si.file_read_full_admission = 0;
  s_si.file_write_full_admission = 0;
  s_si.registry_set_full_admission = 0;
  s_si.full_admission_contract_valid =
      full_list_valid && edr_si_manifest_p0_binding_valid(root, declared_full_mask, &raw_binding);
  s_si.p0_binding_valid = s_si.full_admission_contract_valid;
  if (s_si.full_admission_contract_valid) {
    s_si.file_read_full_admission = (declared_full_mask & 1u) != 0u;
    s_si.file_write_full_admission = (declared_full_mask & 2u) != 0u;
    s_si.registry_set_full_admission = (declared_full_mask & 4u) != 0u;
  } else {
    edr_si_set_fail_full(&s_si);
    fprintf(stderr,
            "[sensor_interest] invalid full admission or P0 binding in %s; retaining all constrained event types\n",
            label ? label : "manifest");
  }
  edr_si_add_json_process_array(root, "process_names");
  edr_si_add_json_string_array(root, "process_name_prefixes", s_si.proc_prefix,
                               &s_si.n_proc_prefix, EDR_SI_MAX_PROC, 1);
  edr_si_add_json_string_array(root, "cmd_tokens", s_si.cmd_tokens, &s_si.n_cmd_tokens,
                               EDR_SI_MAX_TOKEN, 0);
  edr_si_add_json_port_array(root, "remote_ports");
  edr_si_add_json_string_array(root, "file_path_prefixes", s_si.file_prefix,
                               &s_si.n_file_prefix, EDR_SI_MAX_PREFIX, 0);
  edr_si_add_json_string_array(root, "file_path_contains", s_si.file_contains,
                               &s_si.n_file_contains, EDR_SI_MAX_CONTAINS, 0);
  edr_si_add_json_string_array(root, "registry_path_prefixes", s_si.reg_prefix,
                               &s_si.n_reg_prefix, EDR_SI_MAX_PREFIX, 0);
  edr_si_add_json_string_array(root, "registry_path_contains", s_si.reg_contains,
                               &s_si.n_reg_contains, EDR_SI_MAX_CONTAINS, 0);
  edr_si_add_json_parent_child_pairs(root, "parent_child_pairs");
  edr_si_add_json_required_fields(root, "attack_stage_required_fields");
  cJSON_Delete(root);
  s_si.loaded = 1;
  if (!s_si.version[0]) {
    snprintf(s_si.version, sizeof(s_si.version), "%s", "sensor-interest-v1-builtin");
  }
  fprintf(stderr,
          "[sensor_interest] loaded %s ports=%u proc=%u file=%u/%u full=%d/%d reg=%u/%u full=%d valid=%d pairs=%u fields=%u\n",
          s_si.version, s_si.n_ports, s_si.n_proc_hash, s_si.n_file_prefix,
          s_si.n_file_contains, s_si.file_read_full_admission,
          s_si.file_write_full_admission, s_si.n_reg_prefix, s_si.n_reg_contains,
          s_si.registry_set_full_admission, s_si.full_admission_contract_valid,
          s_si.n_parent_child, s_si.n_required_fields);
  return 0;
}

static int edr_si_file_present(const char *path) {
  if (!path || !path[0]) {
    return 0;
  }
#if defined(_WIN32)
  return GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES;
#else
  {
    struct stat st;
    return stat(path, &st) == 0;
  }
#endif
}

static int edr_si_exe_dir(char *out, size_t cap) {
  if (!out || cap == 0u) {
    return 0;
  }
  out[0] = '\0';
#if defined(_WIN32)
  DWORD n = GetModuleFileNameA(NULL, out, (DWORD)cap);
  if (n == 0 || n >= cap) {
    return 0;
  }
#else
  ssize_t n = readlink("/proc/self/exe", out, cap - 1u);
  if (n <= 0 || (size_t)n >= cap) {
    return 0;
  }
  out[n] = '\0';
#endif
  for (size_t i = strlen(out); i > 0u; i--) {
    if (out[i - 1u] == '\\' || out[i - 1u] == '/') {
      out[i - 1u] = '\0';
      return 1;
    }
  }
  return 0;
}

int edr_sensor_interest_default_path(char *out, size_t cap) {
  const char *env = getenv("EDR_SENSOR_INTEREST_PATH");
  char dir[1024];
  if (!out || cap == 0u) {
    return 0;
  }
  if (env && env[0]) {
    snprintf(out, cap, "%s", env);
    return 1;
  }
  if (edr_si_exe_dir(dir, sizeof(dir))) {
#if defined(_WIN32)
    snprintf(out, cap, "%s\\edr_config\\sensor_interest_manifest.json", dir);
#else
    snprintf(out, cap, "%s/edr_config/sensor_interest_manifest.json", dir);
#endif
    return 1;
  }
  snprintf(out, cap, "edr_config/sensor_interest_manifest.json");
  return 1;
}

static int edr_si_manifest_path_at(int idx, char *out, size_t cap) {
  char dir[1024];
  if (!out || cap == 0u) {
    return 0;
  }
  out[0] = '\0';
  if (idx == 0) {
    return edr_sensor_interest_default_path(out, cap);
  }
  if (edr_si_exe_dir(dir, sizeof(dir))) {
#if defined(_WIN32)
    if (idx == 1) {
      snprintf(out, cap, "%s\\config\\sensor_interest_manifest.json", dir);
      return 1;
    }
    if (idx == 2) {
      snprintf(out, cap, "%s\\sensor_interest_manifest.json", dir);
      return 1;
    }
#else
    if (idx == 1) {
      snprintf(out, cap, "%s/config/sensor_interest_manifest.json", dir);
      return 1;
    }
    if (idx == 2) {
      snprintf(out, cap, "%s/sensor_interest_manifest.json", dir);
      return 1;
    }
#endif
  }
  if (idx == 3) {
    snprintf(out, cap, "config/sensor_interest_manifest.json");
    return 1;
  }
  if (idx == 4) {
    snprintf(out, cap, "sensor_interest_manifest.json");
    return 1;
  }
  return 0;
}

static EdrSensorInterestState *edr_si_new_fail_full_candidate(void) {
  EdrSensorInterestState *candidate = (EdrSensorInterestState *)calloc(1, sizeof(*candidate));
  EdrSensorInterestState *previous_tls;
  if (!candidate) {
    return NULL;
  }
  previous_tls = s_si_tls;
  s_si_tls = candidate;
  s_si.enabled = edr_si_env_bool("EDR_SENSOR_INTEREST_ENABLED", 1);
  snprintf(s_si.version, sizeof(s_si.version), "%s", "sensor-interest-v1-builtin");
  snprintf(s_si.rules_version, sizeof(s_si.rules_version), "%s", "builtin");
  /* No readable, verified manifest is never permission to narrow raw file or
   * registry telemetry.  Defaults are full admission and explicitly invalid
   * until a binding to the active P0 IR proves the published projection. */
  edr_si_set_fail_full(&s_si);
  edr_si_add_defaults();
  s_si_tls = previous_tls;
  return candidate;
}

static int edr_si_load_manifest_into_candidate(EdrSensorInterestState *candidate, const char *path) {
  EdrSensorInterestState *previous_tls;
  char *buf;
  size_t len = 0u;
  int ok;
  if (!candidate || !path || !path[0]) {
    return 0;
  }
  buf = edr_si_read_file(path, &len);
  if (!buf) {
    return 0;
  }
  /* Hold the paired reader side across every IR-derived check.  The IR
   * publisher advances its generation under the writer side before swapping
   * snapshots, so this candidate cannot be authenticated to one matcher and
   * then published as a narrowing projection for another. */
  edr_p0_rule_ir_lazy_init();
  edr_p0_rule_ir_sensor_admission_lock();
  previous_tls = s_si_tls;
  s_si_tls = candidate;
  ok = edr_si_load_json_doc(path, buf, len) == 0 && s_si.loaded &&
       s_si.full_admission_contract_valid && s_si.p0_binding_valid;
  s_si_tls = previous_tls;
  edr_p0_rule_ir_sensor_admission_unlock();
  free(buf);
  return ok;
}

static void edr_si_publish_candidate(EdrSensorInterestState *candidate) {
  int binding_current = 0;
  if (!candidate) {
    return;
  }
  if (candidate->p0_binding_valid) {
    edr_p0_rule_ir_lazy_init();
    edr_p0_rule_ir_sensor_admission_lock();
    binding_current = edr_si_active_ir_binding_matches_state(candidate);
    if (!binding_current) {
      EdrSensorInterestState *previous_tls = s_si_tls;
      s_si_tls = candidate;
      edr_si_set_fail_full(&s_si);
      s_si.loaded = 0;
      s_si.bound_ir_snapshot_epoch = 0u;
      s_si.bound_ir_pair_generation = 0u;
      s_si_tls = previous_tls;
    }
    edr_si_publish_snapshot(candidate);
    edr_p0_rule_ir_sensor_admission_unlock();
    return;
  }
  edr_si_publish_snapshot(candidate);
}

static EdrSensorInterestState *edr_si_build_snapshot(void) {
  char path[1200];
  EdrSensorInterestState *candidate = edr_si_new_fail_full_candidate();
  if (!candidate) {
    return NULL;
  }
  for (int i = 0; i < 5; i++) {
    if (!edr_si_manifest_path_at(i, path, sizeof(path)) || !edr_si_file_present(path)) {
      continue;
    }
    if (!edr_si_load_manifest_into_candidate(candidate, path)) {
      /* A damaged or unverified higher-priority manifest remains fail-full.
       * Do not search a lower-priority path, which could narrow collection
       * during a torn or malicious replacement. */
      EdrSensorInterestState *previous_tls = s_si_tls;
      s_si_tls = candidate;
      edr_si_set_fail_full(&s_si);
      s_si.loaded = 0;
      s_si_tls = previous_tls;
      fprintf(stderr, "[sensor_interest] manifest %s is unavailable or unverified; using fail-full defaults\n", path);
    }
    return candidate;
  }
  fprintf(stderr, "[sensor_interest] using fail-full builtin defaults (no manifest)\n");
  return candidate;
}

void edr_sensor_interest_lazy_init(void) {
#if defined(_WIN32)
  if (InterlockedCompareExchange(&s_inited, 1, 0) == 0) {
    EdrSensorInterestState *candidate = edr_si_build_snapshot();
    if (candidate) {
      edr_si_publish_candidate(candidate);
    }
  }
#else
  if (__sync_bool_compare_and_swap(&s_inited, 0, 1)) {
    EdrSensorInterestState *candidate = edr_si_build_snapshot();
    if (candidate) {
      edr_si_publish_candidate(candidate);
    }
  }
#endif
}

void edr_sensor_interest_reload(void) {
  EdrSensorInterestState *candidate;
#if defined(_WIN32)
  InterlockedExchange(&s_inited, 1);
#else
  __sync_lock_test_and_set(&s_inited, 1);
#endif
  candidate = edr_si_build_snapshot();
  if (candidate) {
    edr_si_publish_candidate(candidate);
  }
}

static int edr_si_file_literal_candidate(const char *path) {
  static const char *const script_exts[] = {
      ".php", ".phtml", ".asp", ".aspx", ".ashx", ".asmx", ".jsp", ".jspx",
      ".js", ".jse", ".vbs", ".vbe", ".wsf", ".hta", ".ps1", ".psm1",
      ".sct", ".cmd", ".bat",
  };
  static const char *const exec_exts[] = {
      ".exe", ".dll", ".scr", ".com", ".msi", ".cpl", ".ocx", ".sys",
  };
  if (!path || !path[0]) {
    return 0;
  }
  if (edr_si_any_prefix(s_si.file_prefix, s_si.n_file_prefix, path) ||
      edr_si_any_contains(s_si.file_contains, s_si.n_file_contains, path)) {
    return 1;
  }
  if (edr_si_contains_ci(path, "\\appdata\\local\\temp\\") ||
      edr_si_contains_ci(path, "\\windows\\temp\\") ||
      edr_si_contains_ci(path, "\\users\\public\\")) {
    for (size_t i = 0; i < sizeof(script_exts) / sizeof(script_exts[0]); i++) {
      if (edr_si_ends_ci(path, script_exts[i])) {
        return 1;
      }
    }
    for (size_t i = 0; i < sizeof(exec_exts) / sizeof(exec_exts[0]); i++) {
      if (edr_si_ends_ci(path, exec_exts[i])) {
        return 1;
      }
    }
  }
  return 0;
}

static int edr_si_file_candidate(const char *path) {
  return (s_si.file_read_full_admission && path && path[0]) ||
         edr_si_file_literal_candidate(path);
}

int edr_sensor_interest_is_file_candidate_path(const char *path) {
  EdrSensorInterestState *snapshot;
  EdrSensorInterestState *previous_tls = s_si_tls;
  int result;
  edr_sensor_interest_lazy_init();
  edr_p0_rule_ir_lazy_init();
  edr_p0_rule_ir_sensor_admission_lock();
  snapshot = edr_si_snapshot_acquire();
  if (!snapshot) {
    edr_p0_rule_ir_sensor_admission_unlock();
    return 1;
  }
  s_si_tls = snapshot;
  result = !edr_si_active_ir_binding_matches_state(snapshot) || edr_si_file_candidate(path);
  s_si_tls = previous_tls;
  edr_si_snapshot_release(snapshot);
  edr_p0_rule_ir_sensor_admission_unlock();
  return result;
}

static int edr_si_registry_candidate(const char *path) {
  return (s_si.registry_set_full_admission && path && path[0]) ||
         (path && path[0] &&
          (edr_si_any_prefix(s_si.reg_prefix, s_si.n_reg_prefix, path) ||
           edr_si_any_contains(s_si.reg_contains, s_si.n_reg_contains, path)));
}

int edr_sensor_interest_should_admit(const EdrSensorInterestEvent *event) {
  EdrSensorInterestState *snapshot;
  EdrSensorInterestState *previous_tls;
  int matched = 0;
  if (!event) {
    return 0;
  }
  /* 集成点 A：在采集丢弃决策之前观测“全火喉”，供阈值/频率关联计数。
   * 个体事件的准入判定不受影响；总开关默认关时为 no-op。 */
  edr_correlation_observe_interest(event);
  edr_sensor_interest_lazy_init();
  edr_p0_rule_ir_lazy_init();
  edr_p0_rule_ir_sensor_admission_lock();
  snapshot = edr_si_snapshot_acquire();
  if (!snapshot) {
    /* A failed allocation/initialisation must not create a pre-IR blind
     * spot.  Retain the event and surface the failure through health. */
    edr_si_inc64(&s_si_metrics.checked);
    edr_si_inc64(&s_si_metrics.matched);
    edr_p0_rule_ir_sensor_admission_unlock();
    return 1;
  }
  previous_tls = s_si_tls;
  s_si_tls = snapshot;
  if (!edr_si_active_ir_binding_matches_state(snapshot)) {
    /* The IR may have changed after this manifest was authenticated.  Do not
     * let a stale narrow projection discard any provider event (notably
     * network events, which have no full-admission bitmap). */
    edr_si_inc64(&s_si_metrics.checked);
    edr_si_inc64(&s_si_metrics.matched);
    matched = 1;
    goto done;
  }
  if (!s_si.enabled || edr_si_env_bool("EDR_COLLECTOR_ADMIT_ALL", 0)) {
    edr_si_inc64(&s_si_metrics.checked);
    edr_si_inc64(&s_si_metrics.matched);
    matched = 1;
    goto done;
  }
  edr_si_inc64(&s_si_metrics.checked);
  if (edr_adaptive_collection_should_admit_interest(event)) {
    edr_si_inc64(&s_si_metrics.adaptive_hits);
    edr_si_inc64(&s_si_metrics.matched);
    matched = 1;
    goto done;
  }
  if (edr_si_parent_child_matches(event->parent_process_name, event->process_name)) {
    edr_si_inc64(&s_si_metrics.parent_child_hits);
    edr_si_inc64(&s_si_metrics.matched);
    matched = 1;
    goto done;
  }

  switch (event->type) {
  case EDR_EVENT_PROCESS_CREATE:
    matched = 1;
    edr_si_inc64(&s_si_metrics.provider_hits);
    break;
  case EDR_EVENT_PROCESS_TERMINATE:
  case EDR_EVENT_DLL_LOAD:
    matched = edr_si_env_bool("EDR_COLLECTOR_KEEP_LIFECYCLE", 0);
    break;
  case EDR_EVENT_AUTH_LOGIN:
  case EDR_EVENT_AUTH_LOGOUT:
  case EDR_EVENT_AUTH_FAILED:
    matched = edr_si_env_bool("EDR_COLLECTOR_KEEP_AUTH", 0);
    break;
  case EDR_EVENT_SCRIPT_POWERSHELL:
  case EDR_EVENT_SCRIPT_WMI:
  case EDR_EVENT_PROTOCOL_SHELLCODE:
  case EDR_EVENT_WEBSHELL_DETECTED:
  case EDR_EVENT_PMFE_SCAN_RESULT:
  case EDR_EVENT_BEHAVIOR_ONNX_ALERT:
  case EDR_EVENT_FIREWALL_RULE_CHANGE:
    matched = 1;
    edr_si_inc64(&s_si_metrics.provider_hits);
    break;
  case EDR_EVENT_NET_CONNECT:
  case EDR_EVENT_NET_LISTEN:
  case EDR_EVENT_NET_DNS_QUERY:
  case EDR_EVENT_NET_TLS_HANDSHAKE:
    if (event->remote_port && edr_si_port_has(event->remote_port)) {
      matched = 1;
      edr_si_inc64(&s_si_metrics.port_hits);
    } else if (edr_si_process_interesting(event->process_name)) {
      matched = 1;
      edr_si_inc64(&s_si_metrics.process_hits);
    } else if (edr_si_any_contains(s_si.cmd_tokens, s_si.n_cmd_tokens, event->path)) {
      matched = 1;
      edr_si_inc64(&s_si_metrics.path_hits);
    }
    break;
  case EDR_EVENT_FILE_CREATE:
  case EDR_EVENT_FILE_WRITE:
  case EDR_EVENT_FILE_DELETE:
  case EDR_EVENT_FILE_RENAME:
  case EDR_EVENT_FILE_PERMISSION_CHANGE:
    if (s_si.file_write_full_admission || edr_si_file_literal_candidate(event->path)) {
      matched = 1;
      edr_si_inc64(&s_si_metrics.path_hits);
    }
    break;
  case EDR_EVENT_FILE_READ:
    if (s_si.file_read_full_admission || edr_si_file_candidate(event->path)) {
      matched = 1;
      edr_si_inc64(&s_si_metrics.path_hits);
    }
    break;
  case EDR_EVENT_REG_CREATE_KEY:
  case EDR_EVENT_REG_SET_VALUE:
  case EDR_EVENT_REG_DELETE_KEY:
    if (edr_si_registry_candidate(event->registry_path[0] ? event->registry_path : event->path)) {
      matched = 1;
      edr_si_inc64(&s_si_metrics.registry_hits);
    }
    break;
  default:
    matched = edr_si_env_bool("EDR_COLLECTOR_KEEP_METADATA", 0);
    break;
  }

  /* A reload racing the ordinary miss must turn that miss into a retain. */
  if (!matched && !edr_si_active_ir_binding_matches_state(snapshot)) {
    edr_si_inc64(&s_si_metrics.matched);
    matched = 1;
    goto done;
  }
  if (matched) {
    edr_si_inc64(&s_si_metrics.matched);
    matched = 1;
    goto done;
  }
  edr_si_inc64(&s_si_metrics.dropped);
done:
  s_si_tls = previous_tls;
  edr_si_snapshot_release(snapshot);
  edr_p0_rule_ir_sensor_admission_unlock();
  return matched ? 1 : 0;
}

void edr_sensor_interest_get_status(EdrSensorInterestStatus *out_status) {
  EdrSensorInterestState *snapshot;
  EdrSensorInterestState *previous_tls;
  int active_binding_matches;
  if (!out_status) {
    return;
  }
  memset(out_status, 0, sizeof(*out_status));
  edr_sensor_interest_lazy_init();
  edr_p0_rule_ir_lazy_init();
  edr_p0_rule_ir_sensor_admission_lock();
  snapshot = edr_si_snapshot_acquire();
  if (!snapshot) {
    out_status->file_read_full_admission = 1;
    out_status->file_write_full_admission = 1;
    out_status->registry_set_full_admission = 1;
    edr_p0_rule_ir_sensor_admission_unlock();
    return;
  }
  previous_tls = s_si_tls;
  s_si_tls = snapshot;
  active_binding_matches = edr_si_active_ir_binding_matches_state(snapshot);
  out_status->enabled = s_si.enabled;
  out_status->loaded = s_si.loaded;
  out_status->file_read_full_admission = active_binding_matches ? s_si.file_read_full_admission : 1;
  out_status->file_write_full_admission = active_binding_matches ? s_si.file_write_full_admission : 1;
  out_status->registry_set_full_admission = active_binding_matches ? s_si.registry_set_full_admission : 1;
  out_status->full_admission_contract_valid = s_si.full_admission_contract_valid;
  out_status->p0_binding_valid = active_binding_matches;
  out_status->snapshot_epoch = s_si.snapshot_epoch;
  snprintf(out_status->version, sizeof(out_status->version), "%s", s_si.version);
  snprintf(out_status->rules_version, sizeof(out_status->rules_version), "%s", s_si.rules_version);
  snprintf(out_status->p0_artifact_sha256, sizeof(out_status->p0_artifact_sha256), "%s",
           s_si.p0_artifact_sha256);
  snprintf(out_status->p0_rule_coverage_sha256, sizeof(out_status->p0_rule_coverage_sha256), "%s",
           s_si.p0_rule_coverage_sha256);
  snprintf(out_status->sensor_interest_manifest_sha256,
           sizeof(out_status->sensor_interest_manifest_sha256), "%s",
           s_si.sensor_interest_manifest_sha256);
  snprintf(out_status->sensor_interest_manifest_hash_mode,
           sizeof(out_status->sensor_interest_manifest_hash_mode), "%s",
           s_si.sensor_interest_manifest_hash_mode);
  out_status->p0_artifact_rule_count = s_si.p0_artifact_rule_count;
  out_status->process_name_count = s_si.n_proc_hash;
  out_status->process_prefix_count = s_si.n_proc_prefix;
  out_status->port_count = s_si.n_ports;
  out_status->file_prefix_count = s_si.n_file_prefix;
  out_status->file_contains_count = s_si.n_file_contains;
  out_status->registry_prefix_count = s_si.n_reg_prefix;
  out_status->registry_contains_count = s_si.n_reg_contains;
  out_status->cmd_token_count = s_si.n_cmd_tokens;
  out_status->parent_child_pair_count = s_si.n_parent_child;
  out_status->attack_stage_required_field_count = s_si.n_required_fields;
  out_status->checked = edr_si_load64(&s_si_metrics.checked);
  out_status->matched = edr_si_load64(&s_si_metrics.matched);
  out_status->dropped = edr_si_load64(&s_si_metrics.dropped);
  out_status->provider_hits = edr_si_load64(&s_si_metrics.provider_hits);
  out_status->adaptive_hits = edr_si_load64(&s_si_metrics.adaptive_hits);
  out_status->process_hits = edr_si_load64(&s_si_metrics.process_hits);
  out_status->port_hits = edr_si_load64(&s_si_metrics.port_hits);
  out_status->path_hits = edr_si_load64(&s_si_metrics.path_hits);
  out_status->registry_hits = edr_si_load64(&s_si_metrics.registry_hits);
  out_status->parent_child_hits = edr_si_load64(&s_si_metrics.parent_child_hits);
  s_si_tls = previous_tls;
  edr_si_snapshot_release(snapshot);
  edr_p0_rule_ir_sensor_admission_unlock();
}

/* The downloaded manifest is a security boundary.  Never truncate the live
 * file while transport input is still arriving: materialise a same-directory
 * private stage, authenticate that exact byte sequence, durably install it,
 * and only then publish the matching immutable snapshot. */
static int edr_si_parent_dir(const char *path, char *out, size_t cap) {
  size_t len;
  if (!path || !path[0] || !out || cap == 0u) {
    return 0;
  }
  len = strlen(path);
  if (len + 1u > cap) {
    return 0;
  }
  memcpy(out, path, len + 1u);
  while (len > 0u) {
    if (out[len - 1u] == '\\' || out[len - 1u] == '/') {
      if (len == 1u) {
        out[1] = '\0';
      } else {
        out[len - 1u] = '\0';
      }
      return out[0] != '\0';
    }
    len--;
  }
  snprintf(out, cap, "%s", ".");
  return 1;
}

static int edr_si_ensure_parent_dir(const char *dir) {
  if (!dir || !dir[0]) {
    return 0;
  }
#if defined(_WIN32)
  if (CreateDirectoryA(dir, NULL) || GetLastError() == ERROR_ALREADY_EXISTS) {
    return 1;
  }
#else
  if (mkdir(dir, 0755) == 0 || errno == EEXIST) {
    return 1;
  }
#endif
  return 0;
}

static void edr_si_remove_stage(const char *path) {
  if (!path || !path[0]) {
    return;
  }
#if defined(_WIN32)
  (void)DeleteFileA(path);
#else
  (void)unlink(path);
#endif
}

#if defined(_WIN32)
static int edr_si_copy_to_stage(const char *src_path, const char *dst_path,
                                char *stage_path, size_t stage_cap) {
  HANDLE in = INVALID_HANDLE_VALUE;
  HANDLE out = INVALID_HANDLE_VALUE;
  DWORD got = 0u;
  DWORD wrote = 0u;
  char buffer[8192];
  unsigned int attempt;
  int ok = 0;
  if (!src_path || !dst_path || !stage_path || stage_cap == 0u) {
    return 0;
  }
  in = CreateFileA(src_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                   FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
  if (in == INVALID_HANDLE_VALUE) {
    return 0;
  }
  for (attempt = 0u; attempt < 32u; ++attempt) {
    int n = snprintf(stage_path, stage_cap, "%s.stage-%lu-%llu-%u", dst_path,
                     (unsigned long)GetCurrentProcessId(),
                     (unsigned long long)GetTickCount64(), attempt);
    if (n < 0 || (size_t)n >= stage_cap) {
      goto done;
    }
    out = CreateFileA(stage_path, GENERIC_WRITE, 0, NULL, CREATE_NEW,
                      FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_WRITE_THROUGH, NULL);
    if (out != INVALID_HANDLE_VALUE) {
      break;
    }
    if (GetLastError() != ERROR_FILE_EXISTS && GetLastError() != ERROR_ALREADY_EXISTS) {
      goto done;
    }
  }
  if (out == INVALID_HANDLE_VALUE) {
    goto done;
  }
  for (;;) {
    if (!ReadFile(in, buffer, (DWORD)sizeof(buffer), &got, NULL)) {
      goto done;
    }
    if (got == 0u) {
      break;
    }
    {
      DWORD offset = 0u;
      while (offset < got) {
        if (!WriteFile(out, buffer + offset, got - offset, &wrote, NULL) || wrote == 0u) {
          goto done;
        }
        offset += wrote;
      }
    }
  }
  if (!FlushFileBuffers(out)) {
    goto done;
  }
  ok = 1;
done:
  if (out != INVALID_HANDLE_VALUE) {
    CloseHandle(out);
  }
  CloseHandle(in);
  if (!ok) {
    edr_si_remove_stage(stage_path);
  }
  return ok;
}

static int edr_si_install_stage(const char *stage_path, const char *dst_path, const char *parent_dir) {
  (void)parent_dir;
  return MoveFileExA(stage_path, dst_path, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) ? 1 : 0;
}
#else
static int edr_si_copy_to_stage(const char *src_path, const char *dst_path,
                                char *stage_path, size_t stage_cap) {
  int in = -1;
  int out = -1;
  ssize_t got;
  char buffer[8192];
  int ok = 0;
  if (!src_path || !dst_path || !stage_path || stage_cap == 0u) {
    return 0;
  }
  if (snprintf(stage_path, stage_cap, "%s.stage.XXXXXX", dst_path) < 0 ||
      strlen(stage_path) + 1u > stage_cap) {
    return 0;
  }
  in = open(src_path, O_RDONLY);
  if (in < 0) {
    return 0;
  }
  out = mkstemp(stage_path);
  if (out < 0) {
    close(in);
    return 0;
  }
  if (fchmod(out, 0600) != 0) {
    goto done;
  }
  while ((got = read(in, buffer, sizeof(buffer))) != 0) {
    ssize_t offset = 0;
    if (got < 0) {
      if (errno == EINTR) {
        continue;
      }
      goto done;
    }
    while (offset < got) {
      ssize_t written = write(out, buffer + offset, (size_t)(got - offset));
      if (written < 0) {
        if (errno == EINTR) {
          continue;
        }
        goto done;
      }
      if (written == 0) {
        goto done;
      }
      offset += written;
    }
  }
  if (fsync(out) != 0) {
    goto done;
  }
  ok = 1;
done:
  if (out >= 0) {
    close(out);
  }
  close(in);
  if (!ok) {
    edr_si_remove_stage(stage_path);
  }
  return ok;
}

static int edr_si_sync_parent_dir(const char *parent_dir) {
  int parent_fd;
  int ok;
  if (!parent_dir || !parent_dir[0]) {
    return 0;
  }
#if defined(EDR_SENSOR_INTEREST_TESTING)
  if (s_test_fail_parent_sync_after > 0u && --s_test_fail_parent_sync_after == 0u) {
    errno = EIO;
    return 0;
  }
#endif
  parent_fd = open(parent_dir, O_RDONLY);
  if (parent_fd < 0) {
    return 0;
  }
  ok = fsync(parent_fd) == 0;
  close(parent_fd);
  return ok;
}

static int edr_si_install_stage(const char *stage_path, const char *dst_path, const char *parent_dir) {
  char backup[1400];
  char restore[1440];
  unsigned int attempt;
  int have_backup = 0;
  if (!stage_path || !dst_path || !parent_dir) {
    return 0;
  }
  /* Make the prior bytes durable under a second name before replacement. */
  for (attempt = 0u; attempt < 32u; ++attempt) {
    int n = snprintf(backup, sizeof(backup), "%s.rollback.%ld.%u", dst_path,
                     (long)getpid(), attempt);
    if (n < 0 || (size_t)n >= sizeof(backup)) {
      return 0;
    }
    if (link(dst_path, backup) == 0) {
      have_backup = 1;
      break;
    }
    if (errno == ENOENT) {
      backup[0] = '\0';
      break;
    }
    if (errno != EEXIST) {
      return 0;
    }
  }
  if (attempt == 32u) {
    return 0;
  }
  if (have_backup && !edr_si_sync_parent_dir(parent_dir)) {
    (void)unlink(backup);
    return 0;
  }
  if (rename(stage_path, dst_path) != 0) {
    if (have_backup) {
      (void)unlink(backup);
    }
    return 0;
  }
  if (!edr_si_sync_parent_dir(parent_dir)) {
    int restored = 0;
    if (have_backup) {
      int n = snprintf(restore, sizeof(restore), "%s.restore.%ld", backup, (long)getpid());
      if (n >= 0 && (size_t)n < sizeof(restore) && link(backup, restore) == 0 &&
          rename(restore, dst_path) == 0 && edr_si_sync_parent_dir(parent_dir)) {
        restored = 1;
        (void)unlink(backup);
        (void)edr_si_sync_parent_dir(parent_dir);
      }
    } else if (unlink(dst_path) == 0 && edr_si_sync_parent_dir(parent_dir)) {
      restored = 1;
    }
    if (!restored) {
      fprintf(stderr,
              "[sensor_interest] replacement rollback is not durably confirmed; retaining fail-full state\n");
    }
    return 0;
  }
  if (have_backup && unlink(backup) == 0) {
    (void)edr_si_sync_parent_dir(parent_dir);
  }
  return 1;
}
#endif

int edr_sensor_interest_replace_manifest_from_file(const char *src_path) {
  char dst[1200];
  char parent[1200];
  char stage[1400];
  EdrSensorInterestState *candidate = NULL;
  if (!src_path || !src_path[0] || !edr_sensor_interest_default_path(dst, sizeof(dst)) ||
      !edr_si_parent_dir(dst, parent, sizeof(parent)) || !edr_si_ensure_parent_dir(parent)) {
    return -1;
  }
  stage[0] = '\0';
  /* Establish a stable active snapshot before replacing its backing file. */
  edr_sensor_interest_lazy_init();
  if (!edr_si_copy_to_stage(src_path, dst, stage, sizeof(stage))) {
    return -1;
  }
  candidate = edr_si_new_fail_full_candidate();
  if (!candidate || !edr_si_load_manifest_into_candidate(candidate, stage)) {
    free(candidate);
    edr_si_remove_stage(stage);
    return -1;
  }
  /* Commit the disk bytes and matching immutable snapshot while the paired
   * IR reader guard is held.  An IR publisher cannot advance generation
   * between this revalidation and publication. */
  edr_p0_rule_ir_sensor_admission_lock();
  if (!edr_si_active_ir_binding_matches_state(candidate)) {
    edr_p0_rule_ir_sensor_admission_unlock();
    free(candidate);
    edr_si_remove_stage(stage);
    return -1;
  }
  if (!edr_si_install_stage(stage, dst, parent)) {
    /* A failed rename leaves the live file untouched.  A directory-sync
     * failure can occur after rename; do not publish an unconfirmed update. */
    free(candidate);
    edr_si_remove_stage(stage);
    edr_p0_rule_ir_sensor_admission_unlock();
    return -1;
  }
  edr_si_publish_snapshot(candidate);
  edr_p0_rule_ir_sensor_admission_unlock();
  return 0;
}
