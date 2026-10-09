/* Exercise the production collector and result assembly. Only external command,
 * shell, parser and cache boundaries are isolated; file I/O and SHA256 are real. */
#include "cJSON.h"
#include "edr/command_util.h"
#include "edr/process_generation.h"
#include "edr/sha256.h"
#include "edr/shell_exec.h"
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include <process.h>
#define test_pid _getpid
#else
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#define test_pid getpid
#endif

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #x); exit(1); } } while (0)
static int cancel_after = -1, cancel_checks;
static int capture_exit, capture_count;
static EdrCommandExecutionStatus capture_execution;
static char capture_detail[32768], capture_response_status[32];
static const char *ps_fixture = "", *ss_fixture = "", *netstat_fixture = "";
static int ps_rc, ss_rc, netstat_rc, sampler_calls;
static const char *cache_fixture = "[]";
static uint32_t cache_returned, cache_scanned;
static int cache_rc, cache_truncated, cache_calls;
unsigned long g_cmd_handled, g_cmd_rejected, g_cmd_exec_ok, g_cmd_exec_fail;

/* Include the real owner so bounded scan behavior can be tested without
 * making test-only public collector APIs part of the runtime. */
#include "../src/command/rtq_exec.c"

int edr_command_rtq_readonly_enabled(void) { return 1; }
int edr_command_cancel_requested(const char *command_id) {
  CHECK(command_id != NULL);
  return cancel_after >= 0 && cancel_checks++ >= cancel_after;
}
void edr_command_audit_both(const char *id, const char *message) { (void)id; (void)message; }
void edr_command_emit_always_typed(const char *id, const char *type, const EdrSoarCommandMeta *meta,
    EdrCommandExecutionStatus execution, int code, const char *detail) {
  (void)meta; CHECK(id && !strcmp(type, "rtq_execute"));
  capture_count++; capture_execution = execution; capture_exit = code;
  CHECK(strlen(detail) < sizeof(capture_detail));
  snprintf(capture_detail, sizeof(capture_detail), "%s", detail);
}
int edr_command_emit_always_typed_status(const char *id, const char *type, const EdrSoarCommandMeta *meta,
    EdrCommandExecutionStatus execution, int code, const char *detail, const char *response_status) {
  edr_command_emit_always_typed(id, type, meta, execution, code, detail);
  snprintf(capture_response_status, sizeof(capture_response_status), "%s", response_status);
  return 0;
}
int edr_process_command_line_query_live(void *handle, char *out, size_t cap, char *reason, size_t reason_cap) {
  (void)handle; if (cap) out[0] = 0;
  if (reason_cap) snprintf(reason, reason_cap, "not sampled by collector test");
  return -1;
}
int edr_shell_exec(const char *command, int timeout, char *output, size_t cap, int *exit_code) {
  CHECK(timeout > 0 && cap > 0);
  sampler_calls++;
  const char *fixture;
  int rc;
  if (!strncmp(command, "ps ", 3)) { fixture = ps_fixture; rc = ps_rc; }
  else if (!strncmp(command, "ss ", 3)) { fixture = ss_fixture; rc = ss_rc; }
  else if (!strncmp(command, "netstat ", 8)) { fixture = netstat_fixture; rc = netstat_rc; }
  else { fprintf(stderr, "unexpected sampler command\n"); exit(1); }
  snprintf(output, cap, "%s", fixture);
  *exit_code = rc == 0 ? 0 : 1;
  return rc;
}
int edr_shell_exec_cancellable(const char *command, int timeout, char *output, size_t cap, int *exit_code,
    EdrShellCancelCheck cancel_check, void *cancel_user) {
  if (cancel_check && cancel_check(cancel_user)) { output[0] = 0; *exit_code = 130; return -1; }
  return edr_shell_exec(command, timeout, output, cap, exit_code);
}
static cJSON *payload_object(const uint8_t *payload, size_t length) {
  cJSON *root = cJSON_ParseWithLength((const char *)payload, length);
  CHECK(cJSON_IsObject(root)); return root;
}
int edr_parse_json_string(const uint8_t *payload, size_t length, const char *key, char *out, size_t cap) {
  cJSON *root = payload_object(payload, length);
  const cJSON *value = cJSON_GetObjectItemCaseSensitive(root, key);
  int ok = cJSON_IsString(value) && value->valuestring && strlen(value->valuestring) < cap;
  if (cap) out[0] = 0;
  if (ok) memcpy(out, value->valuestring, strlen(value->valuestring) + 1u);
  cJSON_Delete(root); return ok;
}
int edr_parse_json_int(const uint8_t *payload, size_t length, const char *key, int *out) {
  cJSON *root = payload_object(payload, length);
  const cJSON *value = cJSON_GetObjectItemCaseSensitive(root, key);
  int ok = cJSON_IsNumber(value) && value->valuedouble >= INT_MIN && value->valuedouble <= INT_MAX;
  if (ok) *out = (int)value->valuedouble;
  cJSON_Delete(root); return ok;
}
int edr_local_evidence_cache_query_file_hash_json(const char *sha, const char *path, const char *ext,
    uint32_t limit, char *out, size_t cap, uint32_t *returned, uint32_t *scanned, int *truncated) {
  CHECK(sha && strlen(sha) == 64 && path && ext && limit > 0);
  cache_calls++;
  CHECK(strlen(cache_fixture) < cap);
  snprintf(out, cap, "%s", cache_fixture);
  *returned = cache_returned; *scanned = cache_scanned; *truncated = cache_truncated;
  return cache_rc;
}

static const cJSON *member(const cJSON *value, const char *name) {
  return cJSON_GetObjectItemCaseSensitive(value, name);
}
static int integer(const cJSON *value, const char *name) {
  const cJSON *item = member(value, name); CHECK(cJSON_IsNumber(item)); return item->valueint;
}
static const char *text(const cJSON *value, const char *name) {
  const cJSON *item = member(value, name); CHECK(cJSON_IsString(item)); return item->valuestring;
}
static int has_diagnostic(const cJSON *result, const char *code, const char *severity) {
  const cJSON *errors = member(result, "errors"); CHECK(cJSON_IsArray(errors));
  for (const cJSON *error = errors->child; error; error = error->next) {
    if (!strcmp(text(error, "code"), code) && !strcmp(text(error, "severity"), severity)) return 1;
  }
  return 0;
}
static void reset_boundaries(void) {
  cancel_after = -1; cancel_checks = 0;
  capture_count = capture_exit = 0; capture_detail[0] = capture_response_status[0] = 0;
  ps_fixture = ss_fixture = netstat_fixture = ""; ps_rc = ss_rc = netstat_rc = sampler_calls = 0;
  cache_fixture = "[]"; cache_returned = cache_scanned = 0;
  cache_rc = cache_truncated = cache_calls = 0;
}
static cJSON *collect(cJSON *request) {
  char *payload = cJSON_PrintUnformatted(request); CHECK(payload);
  capture_count = 0; capture_detail[0] = capture_response_status[0] = 0;
  edr_response_rtq_execute("fixture-rtq", (const uint8_t *)payload, strlen(payload), NULL);
  free(payload); CHECK(capture_count == 1);
  cJSON *result = cJSON_Parse(capture_detail); CHECK(cJSON_IsObject(result));
  const cJSON *rows = member(result, "results"); CHECK(cJSON_IsArray(rows));
  CHECK(integer(result, "total") == cJSON_GetArraySize(rows));
  CHECK(strlen(capture_detail) < EDR_COMMAND_STATE_DETAIL_CAP);
  return result;
}
static cJSON *file_request(const char *path, const char *extension, const char *hash) {
  cJSON *q = cJSON_CreateObject(); CHECK(q);
  if (path) CHECK(cJSON_AddStringToObject(q, "file_path", path));
  if (extension) CHECK(cJSON_AddStringToObject(q, "file_ext", extension));
  if (hash) CHECK(cJSON_AddStringToObject(q, "file_sha256", hash));
  return q;
}
static void make_dir(const char *path) {
#ifdef _WIN32
  CHECK(CreateDirectoryA(path, NULL));
#else
  CHECK(mkdir(path, 0700) == 0);
#endif
}
static void path_join(char *out, size_t cap, const char *directory, const char *name) {
#ifdef _WIN32
  int count = snprintf(out, cap, "%s\\%s", directory, name);
#else
  int count = snprintf(out, cap, "%s/%s", directory, name);
#endif
  CHECK(count > 0 && (size_t)count < cap);
}
static void write_file(const char *path, const char *content) {
  FILE *file = fopen(path, "wb"); CHECK(file);
  CHECK(fwrite(content, 1, strlen(content), file) == strlen(content)); CHECK(fclose(file) == 0);
}
static void remove_tree(const char *path) {
#ifdef _WIN32
  char pattern[1100]; path_join(pattern, sizeof(pattern), path, "*");
  WIN32_FIND_DATAA entry; HANDLE find = FindFirstFileA(pattern, &entry);
  if (find != INVALID_HANDLE_VALUE) {
    do {
      if (!strcmp(entry.cFileName, ".") || !strcmp(entry.cFileName, "..")) continue;
      char child[1100]; path_join(child, sizeof(child), path, entry.cFileName);
      if (entry.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) remove_tree(child);
      else CHECK(DeleteFileA(child));
    } while (FindNextFileA(find, &entry));
    CHECK(FindClose(find));
  }
  CHECK(RemoveDirectoryA(path));
#else
  DIR *directory = opendir(path); CHECK(directory);
  struct dirent *entry;
  while ((entry = readdir(directory)) != NULL) {
    if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
    char child[1100]; path_join(child, sizeof(child), path, entry->d_name);
    struct stat st; CHECK(lstat(child, &st) == 0);
    if (S_ISDIR(st.st_mode)) remove_tree(child); else CHECK(unlink(child) == 0);
  }
  CHECK(closedir(directory) == 0); CHECK(rmdir(path) == 0);
#endif
}
static void fixture_root(char out[520]) {
#ifdef _WIN32
  char temporary[MAX_PATH]; CHECK(GetTempPathA(sizeof(temporary), temporary));
  CHECK(GetTempFileNameA(temporary, "rtq", 0, out)); CHECK(DeleteFileA(out)); make_dir(out);
#else
  snprintf(out, 520, "/tmp/edr-rtq-collectors-%d-XXXXXX", test_pid()); CHECK(mkdtemp(out));
#endif
}

static void file_semantics_tests(const char *root) {
  char directory[520], executable[520], longer_extension[520], missing[520];
  path_join(directory, sizeof(directory), root, "extensions"); make_dir(directory);
  path_join(executable, sizeof(executable), directory, "exact.EXE"); write_file(executable, "abc");
  path_join(longer_extension, sizeof(longer_extension), directory, "extra.exec"); write_file(longer_extension, "abc");
  path_join(missing, sizeof(missing), directory, "missing.exe");
  reset_boundaries(); cJSON *request = file_request(directory, ".exe", NULL), *result = collect(request);
  CHECK(integer(result, "total") == 1);
  CHECK(!strcmp(text(member(result, "results")->child, "path"), executable));
  CHECK(cJSON_IsFalse(member(result, "truncated")) && cJSON_IsNull(member(result, "error")));
  cJSON_Delete(result); cJSON_Delete(request);
  request = file_request(directory, "exe", NULL); result = collect(request);
  CHECK(integer(result, "total") == 1); cJSON_Delete(result); cJSON_Delete(request);
  request = file_request(directory, ".exe", NULL);
  CHECK(cJSON_AddNumberToObject(request, "process_pid_min", 0));
  CHECK(cJSON_AddNumberToObject(request, "process_pid_max", 0));
  CHECK(cJSON_AddNumberToObject(request, "network_remote_port", 0));
  result = collect(request); CHECK(integer(result, "total") == 1 && sampler_calls == 0);
  CHECK(!strcmp(text(member(result, "results")->child, "type"), "file"));
  cJSON_Delete(result); cJSON_Delete(request);

  request = file_request(missing, NULL, NULL); result = collect(request);
  CHECK(integer(result, "total") == 0 && has_diagnostic(result, "path_not_found", "error"));
  CHECK(cJSON_IsString(member(result, "error")) && cJSON_IsTrue(member(result, "partial")));
  cJSON_Delete(result); cJSON_Delete(request);
  char expected[65]; CHECK(edr_sha256_hex((const uint8_t *)"abc", 3, expected) == 0);
  request = file_request(executable, NULL, expected); result = collect(request);
  CHECK(integer(result, "total") == 1 && !strcmp(text(member(result, "results")->child, "sha256"), expected));
  CHECK(cache_calls == 1); cJSON_Delete(result); cJSON_Delete(request);
  expected[0] = expected[0] == '0' ? '1' : '0';
  request = file_request(executable, NULL, expected); result = collect(request);
  CHECK(integer(result, "total") == 0 && cJSON_GetArraySize(member(result, "errors")) == 0);
  CHECK(cJSON_IsFalse(member(result, "truncated")) && cJSON_IsNull(member(result, "error")));
  cJSON_Delete(result); cJSON_Delete(request);

  reset_boundaries(); cache_scanned = 7;
  request = file_request(NULL, NULL, expected); result = collect(request);
  const cJSON *hash = member(member(result, "meta"), "file_hash"); CHECK(cJSON_IsObject(hash));
  CHECK(!strcmp(text(hash, "scope"), "cache_only") && !strcmp(text(hash, "cache_status"), "miss"));
  CHECK(cJSON_IsTrue(member(hash, "cache_attempted")) && cJSON_IsFalse(member(hash, "path_scanned")));
  CHECK(integer(hash, "cache_candidates_scanned") == 7 && cache_calls == 1);
  CHECK(integer(result, "total") == 0); cJSON_Delete(result); cJSON_Delete(request);

  reset_boundaries(); char cache_row[1200];
  snprintf(cache_row, sizeof(cache_row), "[{\"type\":\"file\",\"path\":\"cache-synthetic.exe\",\"sha256\":\"%s\",\"size\":3}]", expected);
  cache_fixture = cache_row; cache_returned = 1; cache_scanned = 1;
  request = file_request(NULL, NULL, expected); result = collect(request);
  CHECK(integer(result, "total") == 1);
  hash = member(member(result, "meta"), "file_hash");
  CHECK(!strcmp(text(hash, "cache_status"), "hit") && integer(hash, "cache_hits") == 1);
  CHECK(cJSON_IsFalse(member(hash, "path_scanned"))); cJSON_Delete(result); cJSON_Delete(request);

  reset_boundaries(); cache_rc = -1;
  request = file_request(NULL, NULL, expected); result = collect(request);
  CHECK(has_diagnostic(result, "cache_query_failed", "error"));
  CHECK(!strcmp(text(member(member(result, "meta"), "file_hash"), "cache_status"), "unavailable"));
  cJSON_Delete(result); cJSON_Delete(request);
  puts("PASS: exact extension, path failure versus complete no-match, real SHA256 and explicit cache scope");
}

static void file_boundary_tests(const char *root) {
  char depth_root[520], directory[520], child[520], file_path[520];
  path_join(depth_root, sizeof(depth_root), root, "depth"); make_dir(depth_root);
  path_join(file_path, sizeof(file_path), depth_root, "shallow.exe"); write_file(file_path, "abc");
  snprintf(directory, sizeof(directory), "%s", depth_root);
  for (int i = 0; i < RTQ_FILE_SCAN_DEPTH + 1; i++) {
    path_join(child, sizeof(child), directory, "child"); make_dir(child); snprintf(directory, sizeof(directory), "%s", child);
  }
  path_join(file_path, sizeof(file_path), directory, "omitted.exe"); write_file(file_path, "abc");
  reset_boundaries(); cJSON *request = file_request(depth_root, ".exe", NULL), *result = collect(request);
  CHECK(integer(result, "total") == 1 && has_diagnostic(result, "scan_depth_limit", "warning"));
  CHECK(cJSON_IsTrue(member(result, "partial")) && cJSON_IsNull(member(result, "error")));
  cJSON_Delete(result); cJSON_Delete(request);

  char item_root[520]; path_join(item_root, sizeof(item_root), root, "items"); make_dir(item_root);
  for (int i = 0; i <= RTQ_FILE_SCAN_MAX; i++) {
    char name[64]; snprintf(name, sizeof(name), "ignored-%04d.txt", i); path_join(file_path, sizeof(file_path), item_root, name); write_file(file_path, "");
  }
  reset_boundaries(); request = file_request(item_root, ".never", NULL); result = collect(request);
  CHECK(integer(result, "total") == 0 && has_diagnostic(result, "scan_limit", "warning"));
  CHECK(cJSON_IsTrue(member(result, "partial"))); cJSON_Delete(result); cJSON_Delete(request);

  path_join(file_path, sizeof(file_path), root, "oversized.exe");
  FILE *large = fopen(file_path, "wb"); CHECK(large);
  CHECK(fseek(large, RTQ_FILE_HASH_MAX, SEEK_SET) == 0 && fputc('x', large) == 'x' && fclose(large) == 0);
  char expected[65]; CHECK(edr_sha256_hex((const uint8_t *)"abc", 3, expected) == 0);
  reset_boundaries(); request = file_request(file_path, NULL, expected); result = collect(request);
  CHECK(integer(result, "total") == 0 && has_diagnostic(result, "hash_size_limit", "warning"));
  CHECK(cJSON_IsTrue(member(result, "partial")) && cJSON_IsNull(member(result, "error")));
  cJSON_Delete(result); cJSON_Delete(request);
#ifndef _WIN32
  char links[520], outside[520]; path_join(links, sizeof(links), root, "links"); make_dir(links);
  path_join(outside, sizeof(outside), root, "outside.exe"); write_file(outside, "abc");
  path_join(file_path, sizeof(file_path), links, "link.exe"); CHECK(symlink(outside, file_path) == 0);
  reset_boundaries(); request = file_request(links, ".exe", NULL); result = collect(request);
  CHECK(integer(result, "total") == 0 && has_diagnostic(result, "field_unavailable", "warning"));
  cJSON_Delete(result); cJSON_Delete(request);
#endif
  puts("PASS: depth, scan-item and hash-size limits are partial; symlinks cannot escape the requested tree");
}

static void diagnostic_and_cache_budget_tests(void) {
  rtq_errors diagnostics; rtq_error_init(&diagnostics);
  const char *sources[] = {"process", "process_cmdline", "parent_cmdline", "network", "registry", "eventlog", "file", "file_hash_cache"};
  const char *codes[] = {"field_unavailable", "scan_limit", "scan_depth_limit", "hash_size_limit", "partial_access"};
  for (size_t i = 0; i < sizeof(sources) / sizeof(sources[0]); i++) {
    for (size_t j = 0; j < sizeof(codes) / sizeof(codes[0]); j++) {
      rtq_error_append(&diagnostics, sources[i], codes[j], "bounded diagnostic", 0);
    }
  }
  char detail[5000]; snprintf(detail, sizeof(detail), "{\"errors\":[%s]}", diagnostics.json);
  cJSON *result = cJSON_Parse(detail); CHECK(cJSON_IsObject(result));
  CHECK(cJSON_GetArraySize(member(result, "errors")) <= 32);
  CHECK(has_diagnostic(result, "collector_failed", "error")); cJSON_Delete(result);

  reset_boundaries(); char expected[65]; CHECK(edr_sha256_hex((const uint8_t *)"abc", 3, expected) == 0);
  char incomplete[1500]; snprintf(incomplete, sizeof(incomplete),
      "[{\"type\":\"file\",\"path\":\"complete-cached.exe\",\"sha256\":\"%s\",\"size\":3},{\"type\":\"file\",\"path\":\"incomplete", expected);
  cache_fixture = incomplete; cache_returned = 2; cache_scanned = 2; cache_truncated = 1;
  cJSON *request = file_request(NULL, NULL, expected); result = collect(request);
  CHECK(integer(result, "total") == 1 && cJSON_IsTrue(member(result, "truncated")));
  CHECK(!strcmp(text(member(result, "results")->child, "path"), "complete-cached.exe"));
  CHECK(has_diagnostic(result, "result_truncated", "warning")); cJSON_Delete(result); cJSON_Delete(request);
  puts("PASS: diagnostic budget exhaustion stays observable and partial cache arrays preserve complete rows only");
}

static void complete_row_and_cancellation_tests(const char *root) {
  char directory[520], path[520]; path_join(directory, sizeof(directory), root, "capacity"); make_dir(directory);
  for (int i = 0; i < 200; i++) {
    char name[96]; snprintf(name, sizeof(name), "complete-file-%04d-long-enough-to-fill-the-collector-budget.exe", i);
    path_join(path, sizeof(path), directory, name); write_file(path, "abc");
  }
  reset_boundaries(); cJSON *request = file_request(directory, ".exe", NULL), *result = collect(request);
  int total = integer(result, "total"); CHECK(total > 0 && total < 200);
  CHECK(cJSON_IsTrue(member(result, "truncated")) && has_diagnostic(result, "result_truncated", "warning"));
  CHECK(cJSON_IsNull(member(result, "error")) && capture_execution == EdrCmdExecOk && capture_exit == 0);
  for (const cJSON *row = member(result, "results")->child; row; row = row->next) {
    const char *name = text(row, "path"); CHECK(strstr(name, "complete-file-") && file_has_ext(name, ".exe"));
    CHECK(integer(row, "size") == 3);
  }
  cJSON_Delete(result);
  reset_boundaries(); cancel_after = 2;
  char *payload = cJSON_PrintUnformatted(request); CHECK(payload);
  edr_response_rtq_execute("fixture-cancel", (const uint8_t *)payload, strlen(payload), NULL); free(payload);
  CHECK(capture_count == 1 && capture_execution == EdrCmdExecFailed && capture_exit == 130);
  CHECK(!strcmp(capture_response_status, "cancelled")); cJSON_Delete(request);
  puts("PASS: bounded output preserves complete JSON rows and cooperative cancellation reports terminal failure");
}

#ifndef _WIN32
static void sampler_tests(void) {
  reset_boundaries();
  ss_fixture = "tcp ESTAB 0 0 [::1]:44444 [2001:db8::2]:443 users:((\"fixture\",pid=42,fd=3))\n";
  cJSON *request = cJSON_CreateObject(); CHECK(request);
  CHECK(cJSON_AddStringToObject(request, "network_proto", "TCP"));
  CHECK(cJSON_AddStringToObject(request, "network_state", "ESTABLISHED"));
  CHECK(cJSON_AddNumberToObject(request, "network_remote_port", 443));
  cJSON *result = collect(request); CHECK(integer(result, "total") == 1);
  const cJSON *row = member(result, "results")->child;
  CHECK(!strcmp(text(row, "state"), "ESTABLISHED") && !strcmp(text(row, "remote_ip"), "2001:db8::2"));
  CHECK(integer(row, "pid") == 42); cJSON_Delete(result); cJSON_Delete(request);

  reset_boundaries(); ps_fixture = "42 1 tester pwsh pwsh Write-Output fixture\n";
  request = cJSON_CreateObject(); CHECK(request); CHECK(cJSON_AddStringToObject(request, "script_engine", "pwsh"));
  CHECK(cJSON_AddStringToObject(request, "script_content", "Write-Output"));
  result = collect(request); CHECK(integer(result, "total") == 1);
  CHECK(!strcmp(text(member(result, "results")->child, "cmdline"), "pwsh Write-Output fixture"));
  cJSON_Delete(result); cJSON_Delete(request);

  reset_boundaries(); ss_rc = -1; ss_fixture = "ss failed";
  netstat_fixture = "tcp 0 0 127.0.0.1:44444 198.51.100.2:443 ESTABLISHED\n";
  request = cJSON_CreateObject(); CHECK(request); CHECK(cJSON_AddNumberToObject(request, "network_remote_port", 443));
  result = collect(request); CHECK(integer(result, "total") == 1 && cJSON_GetArraySize(member(result, "errors")) == 0);
  cJSON_Delete(result); cJSON_Delete(request);

  reset_boundaries(); ss_rc = netstat_rc = -1;
  request = cJSON_CreateObject(); CHECK(request); CHECK(cJSON_AddStringToObject(request, "network_proto", "TCP"));
  result = collect(request); CHECK(has_diagnostic(result, "sampler_failed", "error"));
  CHECK(integer(result, "total") == 0); cJSON_Delete(result); cJSON_Delete(request);

  reset_boundaries(); char *saturated = malloc(RTQ_SAMPLER_OUTPUT_MAX + 128u); CHECK(saturated);
  memset(saturated, 'x', RTQ_SAMPLER_OUTPUT_MAX + 127u); saturated[RTQ_SAMPLER_OUTPUT_MAX + 127u] = 0;
  const char *full_line = "tcp ESTAB 0 0 127.0.0.1:44444 198.51.100.2:443\n";
  memcpy(saturated, full_line, strlen(full_line));
  ss_fixture = saturated;
  request = cJSON_CreateObject(); CHECK(request); CHECK(cJSON_AddStringToObject(request, "network_proto", "TCP"));
  result = collect(request); CHECK(integer(result, "total") == 1 && cJSON_IsTrue(member(result, "partial")));
  CHECK(has_diagnostic(result, "scan_limit", "warning"));
  CHECK(!strcmp(text(member(result, "results")->child, "state"), "ESTABLISHED"));
  cJSON_Delete(result); cJSON_Delete(request); free(saturated);
  puts("PASS: production POSIX sampler parsing, IPv6 address fields, state normalization, fallback/failure and saturation diagnostics");
}
#else
static void windows_registry_tests(void) {
  char subkey[200], full[220]; snprintf(subkey, sizeof(subkey), "Software\\EDRRTQCollectorTest%u", (unsigned)test_pid());
  snprintf(full, sizeof(full), "HKCU\\%s", subkey);
  HKEY key; CHECK(RegCreateKeyExA(HKEY_CURRENT_USER, subkey, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &key, NULL) == ERROR_SUCCESS);
  BYTE oversized[4096]; memset(oversized, 'x', sizeof(oversized));
  CHECK(RegSetValueExA(key, "00Oversized", 0, REG_BINARY, oversized, sizeof(oversized)) == ERROR_SUCCESS);
  DWORD number = 1234; BYTE binary[] = {0, 255, 16};
  CHECK(RegSetValueExA(key, "01Number", 0, REG_DWORD, (BYTE *)&number, sizeof(number)) == ERROR_SUCCESS);
  CHECK(RegSetValueExA(key, "02Binary", 0, REG_BINARY, binary, sizeof(binary)) == ERROR_SUCCESS);
  CHECK(RegCloseKey(key) == ERROR_SUCCESS);
  reset_boundaries(); cJSON *request = cJSON_CreateObject(); CHECK(request); CHECK(cJSON_AddStringToObject(request, "registry_path", full));
  cJSON *result = collect(request); CHECK(integer(result, "total") == 2);
  CHECK(has_diagnostic(result, "field_unavailable", "warning"));
  int number_seen = 0, binary_seen = 0;
  for (const cJSON *row = member(result, "results")->child; row; row = row->next) {
    if (!strcmp(text(row, "value"), "01Number")) number_seen = !strcmp(text(row, "data"), "1234");
    if (!strcmp(text(row, "value"), "02Binary")) binary_seen = !strcmp(text(row, "data"), "00ff10");
  }
  CHECK(number_seen && binary_seen); cJSON_Delete(result); cJSON_Delete(request);
  char deep[350]; snprintf(deep, sizeof(deep), "%s\\a\\b\\c\\d\\e", subkey);
  CHECK(RegCreateKeyExA(HKEY_CURRENT_USER, deep, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &key, NULL) == ERROR_SUCCESS);
  CHECK(RegCloseKey(key) == ERROR_SUCCESS);
  request = cJSON_CreateObject(); CHECK(request); CHECK(cJSON_AddStringToObject(request, "registry_path", full));
  CHECK(cJSON_AddStringToObject(request, "registry_mode", "subtree")); result = collect(request);
  CHECK(has_diagnostic(result, "scan_depth_limit", "warning"));
  cJSON_Delete(result); cJSON_Delete(request);
  CHECK(RegDeleteTreeA(HKEY_CURRENT_USER, subkey) == ERROR_SUCCESS);
  LONG cleanup = RegDeleteKeyA(HKEY_CURRENT_USER, subkey);
  CHECK(cleanup == ERROR_SUCCESS || cleanup == ERROR_FILE_NOT_FOUND);
  puts("PASS: native registry continues after ERROR_MORE_DATA, preserves DWORD/binary and marks subtree depth boundaries");
}
static void windows_ipv6_test(void) {
  WSADATA startup; CHECK(WSAStartup(MAKEWORD(2, 2), &startup) == 0);
  SOCKET listener = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP); CHECK(listener != INVALID_SOCKET);
  struct sockaddr_in6 address; memset(&address, 0, sizeof(address));
  address.sin6_family = AF_INET6; address.sin6_addr = in6addr_loopback;
  CHECK(bind(listener, (struct sockaddr *)&address, sizeof(address)) == 0 && listen(listener, 1) == 0);
  int length = sizeof(address); CHECK(getsockname(listener, (struct sockaddr *)&address, &length) == 0);
  int port = ntohs(address.sin6_port);
  reset_boundaries(); cJSON *request = cJSON_CreateObject(); CHECK(request);
  CHECK(cJSON_AddStringToObject(request, "network_proto", "TCP")); CHECK(cJSON_AddStringToObject(request, "network_state", "LISTEN"));
  cJSON *result = collect(request); int seen = 0;
  for (const cJSON *row = member(result, "results")->child; row; row = row->next) {
    const cJSON *local_port = member(row, "local_port");
    if (cJSON_IsNumber(local_port) && local_port->valueint == port && !strcmp(text(row, "local_ip"), "::1")) seen = 1;
  }
  CHECK(seen); cJSON_Delete(result); cJSON_Delete(request); CHECK(closesocket(listener) == 0); CHECK(WSACleanup() == 0);
  puts("PASS: native Windows IPv6 loopback listener appears in real TCP table collection");
}
#endif

int main(void) {
  char root[520]; fixture_root(root);
  file_semantics_tests(root); file_boundary_tests(root); diagnostic_and_cache_budget_tests(); complete_row_and_cancellation_tests(root);
#ifndef _WIN32
  sampler_tests();
  puts("SKIP: Windows registry and native IPv6 fixtures require a Windows test host");
#else
  windows_registry_tests(); windows_ipv6_test();
#endif
  remove_tree(root);
  return 0;
}
