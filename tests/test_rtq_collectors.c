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
#include <winevt.h>
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
static const char *ps_fixture = "", *ps_args_fixture = "", *ss_fixture = "", *netstat_fixture = "";
static int ps_rc, ps_args_rc, ss_rc, netstat_rc, sampler_calls;
static char sampler_command[128];
static char sampler_commands[4][128];
static int commandline_calls;
static const char *cache_fixture = "[]";
static uint32_t cache_returned, cache_scanned;
static int cache_rc, cache_truncated, cache_calls;
unsigned long g_cmd_handled, g_cmd_rejected, g_cmd_exec_ok, g_cmd_exec_fail;

#ifdef _WIN32
/* Test the real event metadata assembler against bounded system-value replies.
 * Non-fixture handles still use the Windows API for the native System query. */
static EVT_VARIANT event_values[EvtSystemPropertyIdEND];
static DWORD event_render_size, event_render_count;
static int event_render_calls, event_xml_calls;
static BOOL WINAPI fixture_evt_render(EVT_HANDLE context, EVT_HANDLE fragment, DWORD flags,
    DWORD size, PVOID buffer, PDWORD used, PDWORD count);
#define EvtRender fixture_evt_render
#endif

/* Include the real owner so bounded scan behavior can be tested without
 * making test-only public collector APIs part of the runtime. */
#include "../src/command/rtq_exec.c"

#ifdef _WIN32
#undef EvtRender
static BOOL WINAPI fixture_evt_render(EVT_HANDLE context, EVT_HANDLE fragment, DWORD flags,
    DWORD size, PVOID buffer, PDWORD used, PDWORD count) {
  event_render_calls++;
  if (flags == EvtRenderEventXml) event_xml_calls++;
  if (context != (EVT_HANDLE)(uintptr_t)1u || fragment != (EVT_HANDLE)(uintptr_t)2u)
    return EvtRender(context, fragment, flags, size, buffer, used, count);
  CHECK(flags == EvtRenderEventValues);
  *used = event_render_size; *count = event_render_count;
  if (size < event_render_size) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
  CHECK(buffer && size >= sizeof(event_values));
  memcpy(buffer, event_values, sizeof(event_values));
  return TRUE;
}
#endif

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
  commandline_calls++;
  (void)handle; if (cap) out[0] = 0;
  if (reason_cap) snprintf(reason, reason_cap, "not sampled by collector test");
  return 0;
}
int edr_shell_exec(const char *command, int timeout, char *output, size_t cap, int *exit_code) {
  CHECK(timeout > 0 && cap > 0);
  sampler_calls++;
  snprintf(sampler_command, sizeof(sampler_command), "%s", command);
  if (sampler_calls <= 4) snprintf(sampler_commands[sampler_calls - 1], sizeof(sampler_commands[0]), "%s", command);
  const char *fixture;
  int rc;
  if (!strcmp(command, "ps -ww -eo pid,args")) { fixture = ps_args_fixture; rc = ps_args_rc; }
  else if (!strncmp(command, "ps ", 3)) { fixture = ps_fixture; rc = ps_rc; }
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
  ps_fixture = ps_args_fixture = ss_fixture = netstat_fixture = ""; ps_rc = ps_args_rc = ss_rc = netstat_rc = sampler_calls = 0;
  sampler_command[0] = 0; commandline_calls = 0;
  memset(sampler_commands, 0, sizeof(sampler_commands));
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

static void eventlog_batch_budget_tests(void) {
  rtq_filter filter; memset(&filter, 0, sizeof(filter));
  char metadata[4096], encoded[4200];
  CHECK(eventlog_batch_metadata(&filter, metadata, sizeof(metadata)) == 0 && !metadata[0]);
  filter.has_eventlog = 1;
  int metadata_len = eventlog_batch_metadata(&filter, metadata, sizeof(metadata));
  CHECK(metadata_len > 0);
  CHECK(snprintf(encoded, sizeof(encoded), "{%s\"fixture\":true}", metadata) < (int)sizeof(encoded));
  cJSON *object = cJSON_Parse(encoded); CHECK(object);
  const cJSON *batch = member(object, "eventlog");
  CHECK(!strcmp(text(batch, "schema"), EDR_RTQ_EVENTLOG_BATCH_SCHEMA));
  CHECK(!strcmp(text(batch, "channel"), "System") && !strcmp(text(batch, "query"), "*"));
  cJSON_Delete(object);
  CHECK(eventlog_batch_metadata(&filter, metadata, 32) < 0);

  snprintf(filter.eventlog_channel, sizeof(filter.eventlog_channel), "%s", "Security");
  snprintf(filter.eventlog_query, sizeof(filter.eventlog_query), "%s", "*[System[EventID=4624 or EventID=4625] and EventData[Data[@Name='TargetUserName']='Synthetic']]" );
  metadata_len = eventlog_batch_metadata(&filter, metadata, sizeof(metadata)); CHECK(metadata_len > 0);
  const char *row = "{\"type\":\"eventlog\",\"provider\":\"Synthetic\",\"timestamp\":\"2026-10-10T06:24:44.000Z\",\"event_id\":4624,\"record_id\":2998278,\"level\":0,\"process_id\":12,\"thread_id\":34}";
  char legacy_row[1200];
  int row_len = (int)strlen(row), legacy_len = row_len - 1;
  memcpy(legacy_row, row, (size_t)legacy_len); legacy_row[legacy_len] = 0;
  CHECK(append_json_kv_str(legacy_row, sizeof(legacy_row), &legacy_len, "channel", filter.eventlog_channel));
  CHECK(append_json_kv_str(legacy_row, sizeof(legacy_row), &legacy_len, "query", filter.eventlog_query));
  CHECK(rtq_appendf(legacy_row, sizeof(legacy_row), &legacy_len, "}"));
  char compact_result[RTQ_MAX_RESULT_STR], legacy_result[RTQ_MAX_RESULT_STR];
  int compact_offset=0, legacy_offset=0, compact_total=0, legacy_total=0, compact_truncated=0, legacy_truncated=0;
  CHECK(rtq_appendf(compact_result, sizeof(compact_result), &compact_offset, "{\"results\":["));
  CHECK(rtq_appendf(legacy_result, sizeof(legacy_result), &legacy_offset, "{\"results\":["));
  while(rtq_commit_row(compact_result, RTQ_COLLECTOR_RESULT_CAP-metadata_len, &compact_offset, &compact_total, row, row_len, &compact_truncated)) {}
  while(rtq_commit_row(legacy_result, RTQ_COLLECTOR_RESULT_CAP, &legacy_offset, &legacy_total, legacy_row, legacy_len, &legacy_truncated)) {}
  CHECK(compact_truncated && legacy_truncated && compact_total > legacy_total);
  CHECK(compact_offset+metadata_len < RTQ_COLLECTOR_RESULT_CAP);
  CHECK(rtq_appendf(compact_result, sizeof(compact_result), &compact_offset, "],\"meta\":{%s\"fixture\":true},\"truncated\":true}", metadata));
  CHECK(rtq_appendf(legacy_result, sizeof(legacy_result), &legacy_offset, "],\"truncated\":true}"));
  object=cJSON_Parse(compact_result); CHECK(object && cJSON_GetArraySize(member(object, "results"))==compact_total);
  CHECK(!member(member(object, "results")->child, "channel") && !member(member(object, "results")->child, "query")); cJSON_Delete(object);
  object=cJSON_Parse(legacy_result); CHECK(object && cJSON_GetArraySize(member(object, "results"))==legacy_total); cJSON_Delete(object);
  CHECK(compact_offset < RTQ_MAX_RESULT_STR);
  printf("PASS: the same fixed result budget retains %d compact rows versus %d legacy rows for the scoped fixture; complete rows and common query survive\n", compact_total, legacy_total);

  /* Worst-case JSON expansion is charged once, not multiplied by row count. */
  memset(filter.eventlog_channel, 1, sizeof(filter.eventlog_channel)-1);
  filter.eventlog_channel[sizeof(filter.eventlog_channel)-1]=0;
  memset(filter.eventlog_query, 1, sizeof(filter.eventlog_query)-1);
  filter.eventlog_query[sizeof(filter.eventlog_query)-1]=0;
  metadata_len=eventlog_batch_metadata(&filter, metadata, sizeof(metadata));
  CHECK(metadata_len > 6*((int)sizeof(filter.eventlog_channel)+(int)sizeof(filter.eventlog_query)-2));
  CHECK(snprintf(encoded, sizeof(encoded), "{%s\"fixture\":true}", metadata) < (int)sizeof(encoded));
  object=cJSON_Parse(encoded); CHECK(object);
  batch=member(object, "eventlog");
  CHECK(!strcmp(text(batch, "channel"), filter.eventlog_channel) && !strcmp(text(batch, "query"), filter.eventlog_query));
  cJSON_Delete(object);
  reset_boundaries();
  cJSON *request=cJSON_CreateObject(); CHECK(request);
  CHECK(cJSON_AddStringToObject(request, "eventlog_channel", filter.eventlog_channel));
  CHECK(cJSON_AddStringToObject(request, "eventlog_query", filter.eventlog_query));
  object=collect(request); CHECK(object && strlen(capture_detail)<RTQ_MAX_RESULT_STR);
  batch=member(member(object, "meta"), "eventlog");
  CHECK(!strcmp(text(batch, "channel"), filter.eventlog_channel) && !strcmp(text(batch, "query"), filter.eventlog_query));
  cJSON_Delete(object);cJSON_Delete(request);
  puts("PASS: absent/default/oversized/escaped batch scopes keep the existing footer and durable JSON budgets");
}

static void escaped_string_tests(void) {
  const char controls[] = {'f', 'i', 'x', 1, 2, 31, '\b', '\f', '\t', '\n', '\r', '"', '\\', (char)0xc3, (char)0xa9, 0};
  char buffer[256] = "{\"type\":\"process\""; int offset = (int)strlen(buffer);
  CHECK(append_json_kv_str(buffer, sizeof(buffer), &offset, "name", controls));
  CHECK(rtq_appendf(buffer, sizeof(buffer), &offset, "}"));
  cJSON *row = cJSON_Parse(buffer); CHECK(cJSON_IsObject(row));
  CHECK(!strcmp(text(row, "name"), controls)); cJSON_Delete(row);

  char incomplete[12] = "{"; int incomplete_offset = 1;
  CHECK(!append_json_kv_str(incomplete, sizeof(incomplete), &incomplete_offset, "name", controls));
  char committed[256] = ""; int committed_offset = 0, total = 0, truncated = 0;
  CHECK(rtq_commit_row(committed, sizeof(committed), &committed_offset, &total, buffer, offset, &truncated));
  CHECK(total == 1 && !truncated && !strcmp(committed, buffer));
  puts("PASS: JSON escaping round-trips control bytes, quotes, backslashes and UTF-8 without losing signed matching text");
}

#ifndef _WIN32
static cJSON *process_request(const char *name, const char *user, const char *cmdline) {
  cJSON *request = cJSON_CreateObject(); CHECK(request);
  if (name) CHECK(cJSON_AddStringToObject(request, "process_name", name));
  if (user) CHECK(cJSON_AddStringToObject(request, "process_user", user));
  if (cmdline) CHECK(cJSON_AddStringToObject(request, "process_cmdline", cmdline));
  return request;
}
static void process_field_tests(void) {
  reset_boundaries(); char fixture[256], args[256]; snprintf(fixture, sizeof(fixture), "%d fixture program\n", test_pid()); ps_fixture = fixture;
  cJSON *request = process_request("fixture", NULL, NULL), *result = collect(request);
  CHECK(integer(result, "total") == 1 && sampler_calls == 1 && !strcmp(sampler_command, "ps -eo pid,comm"));
  const cJSON *row = member(result, "results")->child;
  CHECK(!strcmp(text(row, "name"), "fixture program"));
  CHECK(!member(row, "cmdline") && !member(row, "user") && !member(row, "ppid"));
  CHECK(!member(row, "exe_hash") && !member(row, "signature") && !member(row, "network_by_pid"));
  cJSON_Delete(result); cJSON_Delete(request);

  reset_boundaries(); snprintf(fixture, sizeof(fixture), "%d tester fixture program\n", test_pid()); ps_fixture = fixture;
  request = process_request("fixture", "tester", NULL); result = collect(request);
  CHECK(integer(result, "total") == 1 && !strcmp(sampler_command, "ps -eo pid,user,comm"));
  row = member(result, "results")->child; CHECK(!strcmp(text(row, "user"), "tester") && !member(row, "cmdline"));
  CHECK(!strcmp(text(row, "name"), "fixture program"));
  cJSON_Delete(result); cJSON_Delete(request);

  reset_boundaries(); snprintf(fixture, sizeof(fixture), "%d tester fixture program\n", test_pid()); ps_fixture = fixture;
  snprintf(args, sizeof(args), "%d fixture --marker\n", test_pid()); ps_args_fixture = args;
  request = process_request("fixture program", "tester", "--marker"); result = collect(request);
  CHECK(integer(result, "total") == 1 && sampler_calls == 2);
  CHECK(!strcmp(sampler_commands[0], "ps -eo pid,user,comm") && !strcmp(sampler_commands[1], "ps -ww -eo pid,args"));
  row = member(result, "results")->child; CHECK(!strcmp(text(row, "user"), "tester"));
  CHECK(!strcmp(text(row, "name"), "fixture program"));
  CHECK(!strcmp(text(row, "cmdline"), "fixture --marker")); cJSON_Delete(result); cJSON_Delete(request);

  snprintf(args, sizeof(args), "%d unrelated --wrong\n%d fixture --marker\n", test_pid() + 1, test_pid());
  ps_args_fixture = args; request = process_request("fixture program", "tester", "--marker"); result = collect(request);
  CHECK(integer(result, "total") == 1 && !strcmp(text(member(result, "results")->child, "cmdline"), "fixture --marker"));
  cJSON_Delete(result); cJSON_Delete(request);

  request = process_request("fixture", "tester", "program"); result = collect(request);
  CHECK(integer(result, "total") == 0 && cJSON_GetArraySize(member(result, "errors")) == 0);
  cJSON_Delete(result); cJSON_Delete(request);

  char *long_fixture = malloc(8500); CHECK(long_fixture);
  reset_boundaries(); snprintf(fixture, sizeof(fixture), "%d fixture program\n", test_pid()); ps_fixture = fixture;
  int prefix = snprintf(long_fixture, 8500, "%d ", test_pid()); CHECK(prefix > 0);
  memset(long_fixture + prefix, 'm', 8192); long_fixture[prefix + 8192] = '\n'; long_fixture[prefix + 8193] = 0;
  ps_args_fixture = long_fixture; request = process_request("fixture program", NULL, "mmm"); result = collect(request);
  CHECK(integer(result, "total") == 1 && !strcmp(sampler_command, "ps -ww -eo pid,args"));
  row = member(result, "results")->child; CHECK(strlen(text(row, "cmdline")) == 8192 && !member(row, "user"));
  CHECK(cJSON_IsFalse(member(result, "truncated"))); cJSON_Delete(result);
  long_fixture[prefix + 8192] = 'm'; long_fixture[prefix + 8193] = '\n'; long_fixture[prefix + 8194] = 0;
  result = collect(request); CHECK(integer(result, "total") == 0);
  CHECK(has_diagnostic(result, "field_unavailable", "warning") && cJSON_IsTrue(member(result, "partial")));
  cJSON_Delete(result); cJSON_Delete(request); free(long_fixture);

  char *saturated_args = malloc(RTQ_SAMPLER_OUTPUT_MAX + 128u); CHECK(saturated_args);
  memset(saturated_args, 'x', RTQ_SAMPLER_OUTPUT_MAX + 127u); saturated_args[RTQ_SAMPLER_OUTPUT_MAX + 127u] = 0;
  snprintf(args, sizeof(args), "%d fixture --marker\n", test_pid()); memcpy(saturated_args, args, strlen(args));
  ps_args_fixture = saturated_args; request = process_request("fixture", NULL, "--marker"); result = collect(request);
  CHECK(integer(result, "total") == 1 && cJSON_IsFalse(member(result, "truncated")));
  CHECK(has_diagnostic(result, "scan_limit", "warning") && cJSON_IsTrue(member(result, "partial")));
  cJSON_Delete(result); cJSON_Delete(request); free(saturated_args);

  ps_args_fixture = "999999 unrelated --marker\n";
  request = process_request("fixture", NULL, "--marker"); result = collect(request);
  CHECK(integer(result, "total") == 0 && has_diagnostic(result, "field_unavailable", "warning"));
  cJSON_Delete(result); cJSON_Delete(request);

  snprintf(args, sizeof(args), "%d fixture --marker\n%d conflicting --marker\n", test_pid(), test_pid()); ps_args_fixture = args;
  request = process_request("fixture", NULL, "--marker"); result = collect(request);
  CHECK(integer(result, "total") == 0 && has_diagnostic(result, "field_unavailable", "warning"));
  cJSON_Delete(result); cJSON_Delete(request);

  ps_args_rc = -1; request = process_request("fixture", NULL, "--marker"); result = collect(request);
  CHECK(integer(result, "total") == 0 && has_diagnostic(result, "sampler_failed", "error"));
  cJSON_Delete(result); cJSON_Delete(request); ps_args_rc = 0;

  char malformed[512]; int used = snprintf(malformed, sizeof(malformed), "%d ", test_pid());
  memset(malformed + used, 'n', 256); malformed[used + 256] = '\n'; malformed[used + 257] = 0;
  ps_fixture = malformed; request = process_request("n", NULL, NULL); result = collect(request);
  CHECK(integer(result, "total") == 0 && has_diagnostic(result, "field_unavailable", "warning"));
  cJSON_Delete(result); cJSON_Delete(request);

  snprintf(fixture, sizeof(fixture), "%d fixture\001end\n", test_pid()); ps_fixture = fixture;
  request = process_request("fixture\001end", NULL, NULL); result = collect(request);
  CHECK(integer(result, "total") == 1 && !strcmp(text(member(result, "results")->child, "name"), "fixture\001end"));
  cJSON_Delete(result); cJSON_Delete(request);

  reset_boundaries(); snprintf(fixture, sizeof(fixture), "%d fixture program\n", test_pid()); ps_fixture = fixture;
  snprintf(args, sizeof(args), "%d fixture --marker\n", test_pid()); ps_args_fixture = args;
  request = process_request("fixture", NULL, "--marker"); char *payload = cJSON_PrintUnformatted(request); CHECK(payload);
  cancel_after = 1;
  edr_response_rtq_execute("fixture-cancel-second-process-sample", (const uint8_t *)payload, strlen(payload), NULL);
  free(payload); cJSON_Delete(request);
  CHECK(sampler_calls == 1 && capture_count == 1 && capture_execution == EdrCmdExecFailed && capture_exit == 130);
  CHECK(!strcmp(capture_response_status, "cancelled"));
  puts("PASS: process names with spaces stay intact; only separate PID-matched args can satisfy cmdline, with missing/oversized/failure diagnostics");
}
static cJSON *sample_process_rows(const char *fixture, const char *name, int *total, int *truncated, int *bytes) {
  reset_boundaries(); ps_fixture = fixture;
  rtq_filter filter; memset(&filter, 0, sizeof(filter)); filter.command_id = "fixture-process-boundary";
  snprintf(filter.process_name, sizeof(filter.process_name), "%s", name);
  char *buffer = calloc(131072, 1); CHECK(buffer); int offset = 1; buffer[0] = '[';
  rtq_errors errors; rtq_error_init(&errors); *total = *truncated = 0;
  int collected = match_processes(&filter, buffer, 131070, &offset, total, &errors, truncated);
  CHECK(collected == *total && offset < 131070); if (bytes) *bytes = offset - 1;
  buffer[offset++] = ']'; buffer[offset] = 0;
  cJSON *rows = cJSON_Parse(buffer); CHECK(cJSON_IsArray(rows) && cJSON_GetArraySize(rows) == *total);
  free(buffer); return rows;
}
static void process_capacity_tests(void) {
  char *fixture = calloc(RTQ_SAMPLER_OUTPUT_MAX, 1); CHECK(fixture); int used = 0;
  for (int i = 0; i < RTQ_MAX_RESULTS; i++) used += snprintf(fixture + used, RTQ_SAMPLER_OUTPUT_MAX - used, "%d fixture\n", 100000 + i);
  int total, truncated; cJSON *rows = sample_process_rows(fixture, "fixture", &total, &truncated, NULL);
  CHECK(total == RTQ_MAX_RESULTS && !truncated); cJSON_Delete(rows);
  snprintf(fixture + used, RTQ_SAMPLER_OUTPUT_MAX - used, "200000 unrelated\n");
  rows = sample_process_rows(fixture, "fixture", &total, &truncated, NULL);
  CHECK(total == RTQ_MAX_RESULTS && !truncated); cJSON_Delete(rows);
  snprintf(fixture + used, RTQ_SAMPLER_OUTPUT_MAX - used, "200000 fixture\n");
  rows = sample_process_rows(fixture, "fixture", &total, &truncated, NULL);
  CHECK(total == RTQ_MAX_RESULTS && truncated); cJSON_Delete(rows);

  /* Fill the inline byte budget closely without omitting a matching row. */
  char name[241]; memset(name, 'n', sizeof(name) - 1u); name[sizeof(name) - 1u] = 0;
  char one_line[300]; snprintf(one_line, sizeof(one_line), "%d %s\n", test_pid(), name);
  int row_bytes = 0; rows = sample_process_rows(one_line, "nnn", &total, &truncated, &row_bytes);
  CHECK(total == 1 && !truncated); cJSON_Delete(rows);
  int fitting = (RTQ_COLLECTOR_RESULT_CAP - (int)strlen("{\"results\":[\n")) / (row_bytes + 1);
  CHECK(fitting > 0 && fitting < RTQ_MAX_RESULTS);
  used = 0;
  for (int i = 0; i < fitting; i++) used += snprintf(fixture + used, RTQ_SAMPLER_OUTPUT_MAX - used, "%s", one_line);
  fixture[used] = 0; reset_boundaries(); ps_fixture = fixture;
  cJSON *request = process_request("nnn", NULL, NULL), *result = collect(request);
  CHECK(integer(result, "total") == fitting && cJSON_IsFalse(member(result, "truncated")));
  CHECK(!has_diagnostic(result, "result_truncated", "warning")); cJSON_Delete(result);
  snprintf(fixture + used, RTQ_SAMPLER_OUTPUT_MAX - used, "%s", one_line);
  result = collect(request); CHECK(integer(result, "total") == fitting);
  CHECK(cJSON_IsTrue(member(result, "truncated")) && has_diagnostic(result, "result_truncated", "warning"));
  cJSON_Delete(result); cJSON_Delete(request); free(fixture);
  puts("PASS: exactly 500 rows and unmatched lookahead stay complete; a 501st match or extra byte-budget row marks truncation");
}
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

  reset_boundaries(); ps_fixture = "42 pwsh\n"; ps_args_fixture = "42 pwsh Write-Output fixture\n";
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
static void windows_process_fields_test(void) {
  reset_boundaries(); cJSON *request = cJSON_CreateObject(); CHECK(request);
  CHECK(cJSON_AddNumberToObject(request, "process_pid_min", test_pid()));
  CHECK(cJSON_AddNumberToObject(request, "process_pid_max", test_pid()));
  cJSON *result = collect(request); CHECK(integer(result, "total") == 1 && commandline_calls == 0);
  const cJSON *row = member(result, "results")->child;
  CHECK(integer(row, "pid") == test_pid() && strlen(text(row, "name")) > 0 && strlen(text(row, "path")) > 0);
  const char *unrequested[] = {"ppid", "user", "cmdline", "integrity_level", "exe_hash", "signature",
      "parent_name", "parent_path", "parent_cmdline", "network_by_pid"};
  for (size_t i = 0; i < sizeof(unrequested) / sizeof(unrequested[0]); i++) CHECK(!member(row, unrequested[i]));
  cJSON_Delete(result); cJSON_Delete(request);
  puts("PASS: native PID-only process collection avoids command-line queries and unrequested enrichment");
}
static void windows_unicode_process_test(const char *root) {
  WCHAR executable[32768], wide_root[520], child_path[900], child_name[105], command[1000];
  CHECK(GetModuleFileNameW(NULL, executable, sizeof(executable) / sizeof(executable[0])) > 0);
  CHECK(MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, root, -1, wide_root, 520) > 0);
  for (int i = 0; i < 100; i++) child_name[i] = 0x6d4b;
  memcpy(child_name + 100, L".exe", 5u * sizeof(WCHAR));
  CHECK(swprintf(child_path, sizeof(child_path) / sizeof(child_path[0]), L"%ls\\%ls", wide_root, child_name) > 0);
  CHECK(swprintf(command, sizeof(command) / sizeof(command[0]), L"\"%ls\" --rtq-fixture-child", child_path) > 0);
  char expected_name[400]; CHECK(wide_to_utf8_str(child_name, expected_name, sizeof(expected_name)));
  CHECK(strlen(expected_name) > 260 && CopyFileW(executable, child_path, TRUE));
  STARTUPINFOW startup; PROCESS_INFORMATION process; memset(&startup, 0, sizeof(startup)); startup.cb = sizeof(startup);
  memset(&process, 0, sizeof(process));
  if (!CreateProcessW(child_path, command, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &startup, &process)) {
    CHECK(DeleteFileW(child_path)); CHECK(0);
  }
  reset_boundaries(); cancel_after = 10000; /* Detect an enumeration loop without waiting for the suite timeout. */
  char payload[200]; int length = snprintf(payload, sizeof(payload), "{\"process_pid_min\":%lu,\"process_pid_max\":%lu}",
      (unsigned long)process.dwProcessId, (unsigned long)process.dwProcessId);
  edr_response_rtq_execute("fixture-unicode-process", (const uint8_t *)payload, (size_t)length, NULL);
  /* The child also exits itself after 15 seconds if the test process is killed. */
  DWORD alive = WaitForSingleObject(process.hProcess, 0);
  if (alive == WAIT_TIMEOUT) (void)TerminateProcess(process.hProcess, 0);
  DWORD stopped = WaitForSingleObject(process.hProcess, 5000);
  BOOL thread_closed = CloseHandle(process.hThread), process_closed = CloseHandle(process.hProcess);
  BOOL file_removed = DeleteFileW(child_path);
  CHECK(thread_closed && process_closed && file_removed && stopped == WAIT_OBJECT_0);
  CHECK(capture_count == 1 && capture_execution == EdrCmdExecOk && capture_exit == 0 && commandline_calls == 0);
  cJSON *result = cJSON_Parse(capture_detail); CHECK(cJSON_IsObject(result) && integer(result, "total") == 1);
  const cJSON *row = member(result, "results")->child;
  CHECK(!strcmp(text(row, "name"), expected_name) && !member(row, "cmdline") && !member(row, "user"));
  cJSON_Delete(result);
  puts("PASS: native Unicode process names beyond 260 UTF-8 bytes remain complete and snapshot enumeration advances");
}
static void event_fixture_init(void) {
  memset(event_values, 0, sizeof(event_values));
  event_values[EvtSystemProviderName].Type = EvtVarTypeString;
  event_values[EvtSystemProviderName].StringVal = L"RTQFixture";
  event_values[EvtSystemEventID].Type = EvtVarTypeUInt16; event_values[EvtSystemEventID].UInt16Val = 123;
  event_values[EvtSystemEventRecordId].Type = EvtVarTypeUInt64; event_values[EvtSystemEventRecordId].UInt64Val = 7;
  SYSTEMTIME utc; memset(&utc, 0, sizeof(utc)); utc.wYear = 2026; utc.wMonth = 10; utc.wDay = 10;
  utc.wHour = 11; utc.wMinute = 22; utc.wSecond = 33; utc.wMilliseconds = 456;
  FILETIME time; CHECK(SystemTimeToFileTime(&utc, &time));
  event_values[EvtSystemTimeCreated].Type = EvtVarTypeFileTime;
  event_values[EvtSystemTimeCreated].FileTimeVal = ((ULONGLONG)time.dwHighDateTime << 32) | time.dwLowDateTime;
  event_values[EvtSystemLevel].Type = EvtVarTypeByte; event_values[EvtSystemLevel].ByteVal = 3;
  event_values[EvtSystemProcessID].Type = EvtVarTypeUInt32; event_values[EvtSystemProcessID].UInt32Val = 42;
  event_values[EvtSystemThreadID].Type = EvtVarTypeUInt32; event_values[EvtSystemThreadID].UInt32Val = 43;
  event_values[EvtSystemComputer].Type = EvtVarTypeString;
  event_values[EvtSystemComputer].StringVal = L"unrequested-computer";
  event_render_size = sizeof(event_values); event_render_count = EvtSystemPropertyIdEND;
  event_render_calls = event_xml_calls = 0;
}
static cJSON *event_fixture_evidence(int expected_valid, int capacity) {
  char buffer[2048] = "{\"type\":\"eventlog\""; int offset = (int)strlen(buffer);
  CHECK(capacity <= (int)sizeof(buffer));
  int valid = append_eventlog_evidence((EVT_HANDLE)(uintptr_t)1u, (EVT_HANDLE)(uintptr_t)2u, buffer, capacity, &offset);
  CHECK(valid == expected_valid && event_xml_calls == 0);
  if (!valid) return NULL;
  CHECK(rtq_appendf(buffer, capacity, &offset, "}"));
  cJSON *row = cJSON_Parse(buffer); CHECK(cJSON_IsObject(row));
  CHECK(!member(row, "xml") && !member(row, "xml_truncated") && !member(row, "computer"));
  return row;
}
static void windows_event_metadata_tests(void) {
  event_fixture_init(); cJSON *row = event_fixture_evidence(1, 2048);
  CHECK(event_render_calls == 2 && !strcmp(text(row, "provider"), "RTQFixture"));
  CHECK(integer(row, "event_id") == 123 && integer(row, "record_id") == 7);
  CHECK(!strcmp(text(row, "timestamp"), "2026-10-10T11:22:33.456Z"));
  CHECK(integer(row, "level") == 3 && integer(row, "process_id") == 42 && integer(row, "thread_id") == 43);
  cJSON_Delete(row);

  EVT_VARIANT variant; unsigned long long value; memset(&variant, 0, sizeof(variant));
  variant.Type = EvtVarTypeHexInt64; variant.UInt64Val = 9007199254740991ULL;
  CHECK(evt_variant_u64(&variant, &value) && value == 9007199254740991ULL);
  variant.Type |= EVT_VARIANT_TYPE_ARRAY; CHECK(!evt_variant_u64(&variant, &value));
  variant.Type = EvtVarTypeInt64; variant.Int64Val = -1; CHECK(!evt_variant_u64(&variant, &value));

  const EVT_SYSTEM_PROPERTY_ID required[] = {EvtSystemProviderName, EvtSystemEventID, EvtSystemEventRecordId, EvtSystemTimeCreated};
  for (size_t i = 0; i < sizeof(required) / sizeof(required[0]); i++) {
    event_fixture_init(); event_values[required[i]].Type = EvtVarTypeNull; CHECK(!event_fixture_evidence(0, 2048));
    event_fixture_init(); event_values[required[i]].Type |= EVT_VARIANT_TYPE_ARRAY; CHECK(!event_fixture_evidence(0, 2048));
    event_fixture_init(); event_render_count = required[i]; CHECK(!event_fixture_evidence(0, 2048));
  }
  event_fixture_init(); event_values[EvtSystemEventID].Type = EvtVarTypeUInt32;
  event_values[EvtSystemEventID].UInt32Val = 65536; CHECK(!event_fixture_evidence(0, 2048));
  event_fixture_init(); event_values[EvtSystemEventRecordId].UInt64Val = 0; CHECK(!event_fixture_evidence(0, 2048));
  event_fixture_init(); event_values[EvtSystemEventRecordId].UInt64Val = 9007199254740992ULL; CHECK(!event_fixture_evidence(0, 2048));
  event_fixture_init(); event_values[EvtSystemTimeCreated].FileTimeVal = ~(ULONGLONG)0; CHECK(!event_fixture_evidence(0, 2048));
  event_fixture_init(); event_values[EvtSystemProviderName].StringVal = L""; CHECK(!event_fixture_evidence(0, 2048));
  WCHAR oversized[513]; for (size_t i = 0; i < 512; i++) oversized[i] = L'n'; oversized[512] = 0;
  event_fixture_init(); event_values[EvtSystemProviderName].StringVal = oversized; CHECK(!event_fixture_evidence(0, 2048));
  WCHAR invalid_utf16[] = {0xd800, 0};
  event_fixture_init(); event_values[EvtSystemProviderName].StringVal = invalid_utf16; CHECK(!event_fixture_evidence(0, 2048));
  event_fixture_init(); event_render_size = 65537; CHECK(!event_fixture_evidence(0, 2048)); CHECK(event_render_calls == 1);
  event_fixture_init(); event_render_count = EvtSystemPropertyIdEND + 1; CHECK(!event_fixture_evidence(0, 2048));
  event_fixture_init(); CHECK(!event_fixture_evidence(0, 64));
  event_fixture_init(); event_values[EvtSystemLevel].Type = EvtVarTypeNull;
  row = event_fixture_evidence(1, 2048); CHECK(!member(row, "level")); cJSON_Delete(row);
  puts("PASS: event metadata rejects missing, array, oversized, invalid and unsafe-number fields; only complete metadata is emitted");
}
static void windows_system_event_test(void) {
  reset_boundaries(); event_render_calls = event_xml_calls = 0;
  cJSON *request = cJSON_CreateObject(); CHECK(request); CHECK(cJSON_AddStringToObject(request, "eventlog_channel", "System"));
  cJSON *result = collect(request); CHECK(integer(result, "total") > 0 && event_render_calls > 0 && event_xml_calls == 0);
  const cJSON *batch=member(member(result, "meta"), "eventlog");
  CHECK(!strcmp(text(batch, "schema"), EDR_RTQ_EVENTLOG_BATCH_SCHEMA));
  CHECK(!strcmp(text(batch, "channel"), "System") && !strcmp(text(batch, "query"), "*"));
  for (const cJSON *row = member(result, "results")->child; row; row = row->next) {
    CHECK(!strcmp(text(row, "type"), "eventlog") && !member(row, "channel") && !member(row, "query"));
    CHECK(strlen(text(row, "provider")) > 0 && strlen(text(row, "timestamp")) > 0);
    CHECK(integer(row, "event_id") >= 0 && integer(row, "event_id") <= 65535);
    CHECK(cJSON_IsNumber(member(row, "record_id")) && member(row, "record_id")->valuedouble >= 1);
    CHECK(!member(row, "xml") && !member(row, "xml_truncated") && !member(row, "computer"));
  }
  cJSON_Delete(result); cJSON_Delete(request);
  puts("PASS: native System event queries return complete system metadata without XML or computer collection");
}
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

int main(int argc, char **argv) {
#ifdef _WIN32
  if (argc == 2 && !strcmp(argv[1], "--rtq-fixture-child")) { Sleep(15000); return 0; }
#else
  (void)argc; (void)argv;
#endif
  char root[520]; fixture_root(root);
  file_semantics_tests(root); file_boundary_tests(root); diagnostic_and_cache_budget_tests(); complete_row_and_cancellation_tests(root); eventlog_batch_budget_tests(); escaped_string_tests();
#ifndef _WIN32
  process_field_tests(); process_capacity_tests(); sampler_tests();
  puts("SKIP: Windows native process, event metadata, System events, registry and IPv6 branches require a Windows test host");
#else
  windows_process_fields_test(); windows_unicode_process_test(root); windows_event_metadata_tests(); windows_system_event_test(); windows_registry_tests(); windows_ipv6_test();
#endif
  remove_tree(root);
  return 0;
}
