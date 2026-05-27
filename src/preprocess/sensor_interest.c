#include "edr/sensor_interest.h"

#include "edr/adaptive_collection.h"

#include "cJSON.h"

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
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

typedef struct {
  char value[EDR_SI_MAX_ENTRY];
} EdrSIEntry;

typedef struct {
  char value[128];
  uint32_t hash;
  uint8_t used;
} EdrSIProcSlot;

typedef struct {
  int enabled;
  int loaded;
  char version[128];
  char rules_version[128];
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
  uint32_t n_file_prefix;
  uint32_t n_file_contains;
  uint32_t n_reg_prefix;
  uint32_t n_reg_contains;
  uint32_t n_cmd_tokens;
  volatile uint64_t checked;
  volatile uint64_t matched;
  volatile uint64_t dropped;
  volatile uint64_t provider_hits;
  volatile uint64_t adaptive_hits;
  volatile uint64_t process_hits;
  volatile uint64_t port_hits;
  volatile uint64_t path_hits;
  volatile uint64_t registry_hits;
} EdrSensorInterestState;

static EdrSensorInterestState s_si;
static volatile long s_inited;

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

static int edr_si_load_json_doc(const char *label, const char *json, size_t len) {
  cJSON *root;
  cJSON *v;
  if (!json || len == 0u) {
    return -1;
  }
  root = cJSON_ParseWithLength(json, len);
  if (!root) {
    fprintf(stderr, "[sensor_interest] JSON parse failed: %s\n", label ? label : "manifest");
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
  cJSON_Delete(root);
  s_si.loaded = 1;
  if (!s_si.version[0]) {
    snprintf(s_si.version, sizeof(s_si.version), "%s", "sensor-interest-v1-builtin");
  }
  fprintf(stderr,
          "[sensor_interest] loaded %s ports=%u proc=%u file=%u/%u reg=%u/%u\n",
          s_si.version, s_si.n_ports, s_si.n_proc_hash, s_si.n_file_prefix,
          s_si.n_file_contains, s_si.n_reg_prefix, s_si.n_reg_contains);
  return 0;
}

static int edr_si_file_exists(const char *path) {
  FILE *f;
  if (!path || !path[0]) {
    return 0;
  }
  f = fopen(path, "rb");
  if (!f) {
    return 0;
  }
  fclose(f);
  return 1;
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

static void edr_si_load(void) {
  char path[1200];
  char *buf = NULL;
  size_t len = 0;
  memset(&s_si, 0, sizeof(s_si));
  s_si.enabled = edr_si_env_bool("EDR_SENSOR_INTEREST_ENABLED", 1);
  snprintf(s_si.version, sizeof(s_si.version), "%s", "sensor-interest-v1-builtin");
  snprintf(s_si.rules_version, sizeof(s_si.rules_version), "%s", "builtin");
  edr_si_add_defaults();
  for (int i = 0; i < 5; i++) {
    if (!edr_si_manifest_path_at(i, path, sizeof(path)) || !edr_si_file_exists(path)) {
      continue;
    }
    buf = edr_si_read_file(path, &len);
    if (!buf) {
      continue;
    }
    if (edr_si_load_json_doc(path, buf, len) == 0) {
      free(buf);
      return;
    }
    free(buf);
  }
  s_si.loaded = 0;
  fprintf(stderr, "[sensor_interest] using builtin defaults (no manifest)\n");
}

void edr_sensor_interest_lazy_init(void) {
#if defined(_WIN32)
  if (InterlockedCompareExchange(&s_inited, 1, 0) == 0) {
    edr_si_load();
  }
#else
  if (__sync_bool_compare_and_swap(&s_inited, 0, 1)) {
    edr_si_load();
  }
#endif
}

void edr_sensor_interest_reload(void) {
#if defined(_WIN32)
  InterlockedExchange(&s_inited, 1);
#else
  __sync_lock_test_and_set(&s_inited, 1);
#endif
  edr_si_load();
}

static int edr_si_file_candidate(const char *path) {
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

static int edr_si_registry_candidate(const char *path) {
  return path && path[0] &&
         (edr_si_any_prefix(s_si.reg_prefix, s_si.n_reg_prefix, path) ||
          edr_si_any_contains(s_si.reg_contains, s_si.n_reg_contains, path));
}

int edr_sensor_interest_should_admit(const EdrSensorInterestEvent *event) {
  int matched = 0;
  if (!event) {
    return 0;
  }
  edr_sensor_interest_lazy_init();
  if (!s_si.enabled || edr_si_env_bool("EDR_COLLECTOR_ADMIT_ALL", 0)) {
    edr_si_inc64(&s_si.checked);
    edr_si_inc64(&s_si.matched);
    return 1;
  }
  edr_si_inc64(&s_si.checked);
  if (edr_adaptive_collection_should_admit_interest(event)) {
    edr_si_inc64(&s_si.adaptive_hits);
    edr_si_inc64(&s_si.matched);
    return 1;
  }

  switch (event->type) {
  case EDR_EVENT_PROCESS_CREATE:
    matched = 1;
    edr_si_inc64(&s_si.provider_hits);
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
    edr_si_inc64(&s_si.provider_hits);
    break;
  case EDR_EVENT_NET_CONNECT:
  case EDR_EVENT_NET_LISTEN:
  case EDR_EVENT_NET_DNS_QUERY:
  case EDR_EVENT_NET_TLS_HANDSHAKE:
    if (event->remote_port && edr_si_port_has(event->remote_port)) {
      matched = 1;
      edr_si_inc64(&s_si.port_hits);
    } else if (edr_si_process_interesting(event->process_name)) {
      matched = 1;
      edr_si_inc64(&s_si.process_hits);
    } else if (edr_si_any_contains(s_si.cmd_tokens, s_si.n_cmd_tokens, event->path)) {
      matched = 1;
      edr_si_inc64(&s_si.path_hits);
    }
    break;
  case EDR_EVENT_FILE_CREATE:
  case EDR_EVENT_FILE_WRITE:
  case EDR_EVENT_FILE_DELETE:
  case EDR_EVENT_FILE_RENAME:
  case EDR_EVENT_FILE_PERMISSION_CHANGE:
  case EDR_EVENT_FILE_READ:
    if (edr_si_file_candidate(event->path)) {
      matched = 1;
      edr_si_inc64(&s_si.path_hits);
    } else if (edr_si_process_interesting(event->process_name)) {
      matched = 1;
      edr_si_inc64(&s_si.process_hits);
    }
    break;
  case EDR_EVENT_REG_CREATE_KEY:
  case EDR_EVENT_REG_SET_VALUE:
  case EDR_EVENT_REG_DELETE_KEY:
    if (edr_si_registry_candidate(event->registry_path[0] ? event->registry_path : event->path)) {
      matched = 1;
      edr_si_inc64(&s_si.registry_hits);
    } else if (edr_si_process_interesting(event->process_name)) {
      matched = 1;
      edr_si_inc64(&s_si.process_hits);
    }
    break;
  default:
    matched = edr_si_env_bool("EDR_COLLECTOR_KEEP_METADATA", 0);
    break;
  }

  if (matched) {
    edr_si_inc64(&s_si.matched);
    return 1;
  }
  edr_si_inc64(&s_si.dropped);
  return 0;
}

void edr_sensor_interest_get_status(EdrSensorInterestStatus *out_status) {
  if (!out_status) {
    return;
  }
  edr_sensor_interest_lazy_init();
  memset(out_status, 0, sizeof(*out_status));
  out_status->enabled = s_si.enabled;
  out_status->loaded = s_si.loaded;
  snprintf(out_status->version, sizeof(out_status->version), "%s", s_si.version);
  snprintf(out_status->rules_version, sizeof(out_status->rules_version), "%s", s_si.rules_version);
  out_status->process_name_count = s_si.n_proc_hash;
  out_status->process_prefix_count = s_si.n_proc_prefix;
  out_status->port_count = s_si.n_ports;
  out_status->file_prefix_count = s_si.n_file_prefix;
  out_status->file_contains_count = s_si.n_file_contains;
  out_status->registry_prefix_count = s_si.n_reg_prefix;
  out_status->registry_contains_count = s_si.n_reg_contains;
  out_status->cmd_token_count = s_si.n_cmd_tokens;
  out_status->checked = edr_si_load64(&s_si.checked);
  out_status->matched = edr_si_load64(&s_si.matched);
  out_status->dropped = edr_si_load64(&s_si.dropped);
  out_status->provider_hits = edr_si_load64(&s_si.provider_hits);
  out_status->adaptive_hits = edr_si_load64(&s_si.adaptive_hits);
  out_status->process_hits = edr_si_load64(&s_si.process_hits);
  out_status->port_hits = edr_si_load64(&s_si.port_hits);
  out_status->path_hits = edr_si_load64(&s_si.path_hits);
  out_status->registry_hits = edr_si_load64(&s_si.registry_hits);
}

int edr_sensor_interest_replace_manifest_from_file(const char *src_path) {
  char dst[1200];
  FILE *in;
  FILE *out;
  char buf[8192];
  size_t n;
  if (!src_path || !src_path[0] || !edr_sensor_interest_default_path(dst, sizeof(dst))) {
    return -1;
  }
#if defined(_WIN32)
  {
    char dir[1200];
    snprintf(dir, sizeof(dir), "%s", dst);
    for (size_t i = strlen(dir); i > 0u; i--) {
      if (dir[i - 1u] == '\\' || dir[i - 1u] == '/') {
        dir[i - 1u] = '\0';
        CreateDirectoryA(dir, NULL);
        break;
      }
    }
  }
#else
  {
    char dir[1200];
    snprintf(dir, sizeof(dir), "%s", dst);
    for (size_t i = strlen(dir); i > 0u; i--) {
      if (dir[i - 1u] == '\\' || dir[i - 1u] == '/') {
        dir[i - 1u] = '\0';
        (void)mkdir(dir, 0755);
        break;
      }
    }
  }
#endif
  in = fopen(src_path, "rb");
  if (!in) {
    return -1;
  }
  out = fopen(dst, "wb");
  if (!out) {
    fclose(in);
    return -1;
  }
  while ((n = fread(buf, 1, sizeof(buf), in)) > 0u) {
    if (fwrite(buf, 1, n, out) != n) {
      fclose(in);
      fclose(out);
      return -1;
    }
  }
  fclose(in);
  fclose(out);
  edr_sensor_interest_reload();
  return 0;
}
