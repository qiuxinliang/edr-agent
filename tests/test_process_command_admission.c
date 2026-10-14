/* Exercise the production IR projection and coalescer together. No fixture
 * command is executed, and plaintext authority is test-build-only. */
#include "edr/p0_rule_ir.h"
#include "edr/process_create_coalescer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "command admission line %d: %s\n", __LINE__, #x); return 0; } } while (0)
#define DEADLINE 3000000000ULL
static EdrBehaviorRecord kernel, security, out;
static char fixture_path[1200];
static char archives[32][1400];
static unsigned archive_count;
static const char *command = "\"C:\\Windows\\System32\\icacls.exe\" \"C:\\probe.txt\" /grant *S-1-5-18:F /Q";

static int set_env(const char *key, const char *value) {
#ifdef _WIN32
  return _putenv_s(key, value) == 0;
#else
  return setenv(key, value, 1) == 0;
#endif
}
static int init_fixture(void) {
#ifdef _WIN32
  char directory[MAX_PATH];
  CHECK(GetTempPathA(sizeof(directory), directory));
  CHECK(GetTempFileNameA(directory, "pca", 0, fixture_path));
#else
  strcpy(fixture_path, "/tmp/edr-process-command-XXXXXX");
  int fd = mkstemp(fixture_path); CHECK(fd >= 0); close(fd);
#endif
  CHECK(set_env("EDR_P0_PURPOSE_ARCHIVE_BASE", fixture_path));
  return 1;
}
static int remember_archive(void) {
  const char *sha = NULL;
  CHECK(edr_p0_rule_ir_get_bundle_info(NULL, NULL, &sha));
  CHECK(archive_count < 32 && sha);
  snprintf(archives[archive_count++], sizeof(archives[0]), "%s.purpose-%s.edr1", fixture_path, sha);
  return 1;
}
static int load_rule(const char *condition) {
  FILE *f = fopen(fixture_path, "wb"); CHECK(f);
  int wrote = fprintf(f, "{\"kind\":\"" EDR_P0_RULE_IR_BUNDLE_KIND "\",\"ir_schema_version\":%u,"
      "\"rules_bundle_version\":\"command-admission-test\",\"rule_count\":1,"
      "\"sensor_interest_manifest_sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\","
      "\"sensor_interest_manifest_hash_mode\":\"raw-json-v1-p0-artifact-sha256-zeroed\","
      "\"rules\":[{\"id\":\"test\",\"effect\":\"security_alert\",\"event_type\":\"process_create\",\"condition\":%s}]}",
      EDR_P0_RULE_IR_SCHEMA_VERSION, condition);
  int closed = fclose(f); CHECK(wrote > 0 && closed == 0);
  CHECK(set_env("EDR_P0_IR_PATH", fixture_path));
  edr_p0_rule_ir_reload(); CHECK(edr_p0_rule_ir_is_ready());
  CHECK(edr_p0_rule_ir_rule_count() == 1); CHECK(remember_archive());
  return 1;
}
static void record(void) {
  memset(&kernel, 0, sizeof(kernel)); memset(&out, 0, sizeof(out));
  kernel.type = EDR_EVENT_PROCESS_CREATE; kernel.pid = 5808; kernel.ppid = 5112;
  kernel.process_start_key = 18295873486207052ULL;
  kernel.process_creation_filetime_100ns = 134364677423488195ULL;
  kernel.event_time_ns = 1791994142349105000LL;
  strcpy(kernel.process_name, "icacls.exe");
  strcpy(kernel.exe_path, "C:\\Windows\\System32\\icacls.exe");
  strcpy(kernel.image_path_canonical, kernel.exe_path);
  strcpy(kernel.image_path_resolution_status, "RESOLVED");
  strcpy(kernel.parent_name, "powershell.exe");
  security = kernel; security.is_security_4688 = 1;
  security.process_start_key = security.process_creation_filetime_100ns = 0;
  security.event_time_ns += 102100;
  strcpy(security.cmdline, command); strcpy(security.command_line_origin, "security_4688");
  strcpy(security.identity_source, "target_4688"); strcpy(security.identity_quality, "target_4688");
  strcpy(security.user_sid, "S-1-5-18");
  edr_process_coalescer_reset();
}
static int authoritative_match(const EdrBehaviorRecord *r, const char *id) {
  EdrP0RuleIrEvaluation eval;
  if (!edr_p0_rule_ir_evaluate_record(r, NULL, &eval)) return 0;
  int found = 0;
  for (uint32_t i = 0; i < eval.match_count; i++) {
    EdrP0RuleIrMatch match;
    if (edr_p0_rule_ir_evaluation_get_match(&eval, i, &match) && !strcmp(match.rule_id, id)) found = 1;
  }
  edr_p0_rule_ir_evaluation_free(&eval);
  return found;
}
static int current_bundle(void) {
  CHECK(edr_p0_rule_ir_is_ready()); CHECK(remember_archive());
  for (int mode = 0; mode < 3; mode++) for (int reverse = 0; reverse < 2; reverse++) {
    record();
    if (mode) {
      strcpy(kernel.cmdline, "icacls.exe C:\\probe.txt");
      strcpy(kernel.source_truncated_fields, mode == 1 ? "source.cmdline" : "source.cmdline_quality_unknown");
    }
    /* None of these newly retained inputs should itself start an optional
     * file scan through the original full-match/name-interest path. */
    CHECK(!edr_p0_rule_ir_br_matches_any(&kernel));
    CHECK(!edr_p0_rule_ir_is_interesting_process_name(kernel.process_name));
    int candidate = edr_p0_rule_ir_process_create_command_pending(&kernel); CHECK(candidate);
    if (reverse) CHECK(edr_process_coalescer_submit(&security, 1, 10, &out) == EDR_PROCESS_COALESCE_HOLD);
    CHECK(edr_process_coalescer_submit(&kernel, candidate, 20, &out) == EDR_PROCESS_COALESCE_HOLD);
    if (!reverse) CHECK(edr_process_coalescer_submit(&security, 1, 30, &out) == EDR_PROCESS_COALESCE_HOLD);
    CHECK(!edr_process_coalescer_poll(DEADLINE - 1, &out));
    CHECK(edr_process_coalescer_poll(DEADLINE + 40, &out));
    CHECK(!strcmp(out.source_completeness, "COALESCED"));
    CHECK(out.process_start_key == kernel.process_start_key && out.process_creation_filetime_100ns == kernel.process_creation_filetime_100ns);
    CHECK(!strcmp(out.cmdline, command) && !strcmp(out.command_line_origin, "security_4688"));
    CHECK(!edr_p0_rule_ir_process_create_command_pending(&out));
    CHECK(authoritative_match(&out, "R-MITRE-WIN-T1044"));
    CHECK(!edr_process_coalescer_poll(DEADLINE + 50, &out));
  }
  record(); strcpy(kernel.cmdline, "icacls.exe C:\\probe.txt");
  CHECK(!edr_p0_rule_ir_process_create_command_pending(&kernel)); CHECK(!edr_p0_rule_ir_br_matches_any(&kernel));
  CHECK(edr_process_coalescer_submit(&kernel, 0, 1, &out) == EDR_PROCESS_COALESCE_PASS);
  record(); CHECK(edr_process_coalescer_submit(&kernel, edr_p0_rule_ir_process_create_command_pending(&kernel), 1, &out) == EDR_PROCESS_COALESCE_HOLD);
  CHECK(edr_process_coalescer_poll(DEADLINE + 1, &out));
  CHECK(!strcmp(out.source_completeness, "CORRELATION_MISSING") && !out.cmdline[0]);
  CHECK(edr_p0_rule_ir_process_create_command_pending(&out)); CHECK(!authoritative_match(&out, "R-MITRE-WIN-T1044"));
  /* An incomplete audit must not promote a preview into a complete command. */
  record(); strcpy(security.source_truncated_fields, "source.cmdline_quality_unknown");
  CHECK(edr_process_coalescer_submit(&kernel, edr_p0_rule_ir_process_create_command_pending(&kernel), 1, &out) == EDR_PROCESS_COALESCE_HOLD);
  CHECK(edr_process_coalescer_submit(&security, 1, 2, &out) == EDR_PROCESS_COALESCE_HOLD);
  CHECK(edr_process_coalescer_poll(DEADLINE + 3, &out));
  CHECK(edr_p0_rule_ir_process_create_command_pending(&out)); CHECK(!authoritative_match(&out, "R-MITRE-WIN-T1044"));
  record(); kernel.process_start_key = 0;
  CHECK(edr_process_coalescer_submit(&kernel, edr_p0_rule_ir_process_create_command_pending(&kernel), 1, &out) == EDR_PROCESS_COALESCE_READY);
  CHECK(!strcmp(out.source_completeness, "NOT_EVALUABLE") && !out.process_start_key);
  record(); security.ppid++;
  CHECK(edr_process_coalescer_submit(&kernel, edr_p0_rule_ir_process_create_command_pending(&kernel), 1, &out) == EDR_PROCESS_COALESCE_HOLD);
  CHECK(edr_process_coalescer_submit(&security, 1, 2, &out) == EDR_PROCESS_COALESCE_HOLD);
  CHECK(edr_process_coalescer_poll(DEADLINE + 3, &out)); CHECK(!out.cmdline[0]);
  record();
  for (unsigned i = 0; i < 128; i++) {
    kernel.pid = i + 10000; kernel.process_start_key = i + 1;
    CHECK(edr_process_coalescer_submit(&kernel, edr_p0_rule_ir_process_create_command_pending(&kernel), i + 1, &out) == EDR_PROCESS_COALESCE_HOLD);
  }
  kernel.pid++; kernel.process_start_key++;
  CHECK(edr_process_coalescer_submit(&kernel, edr_p0_rule_ir_process_create_command_pending(&kernel), 200, &out) == EDR_PROCESS_COALESCE_READY);
  CHECK(!strcmp(out.source_completeness, "COALESCE_BACKPRESSURE"));
  EdrProcessCoalescerMetrics m; edr_process_coalescer_get_metrics(&m);
  CHECK(m.capacity == 128 && m.slots_used == 128 && m.kernel_backpressure == 1);
  unsigned drained = 0; while (edr_process_coalescer_drain_stopping(&out)) { CHECK(!out.cmdline[0]); drained++; }
  CHECK(drained == 128); edr_process_coalescer_get_metrics(&m); CHECK(m.slots_used == 0);
  return 1;
}
static int partial_fields(void) {
  record();
  CHECK(load_rule("{\"process_name_in\":[\"powershell.exe\"],\"command_regex_any\":[\"trigger\"]}"));
  CHECK(!edr_p0_rule_ir_process_create_command_pending(&kernel));
  strcpy(kernel.source_truncated_fields, "source.process_name"); CHECK(edr_p0_rule_ir_process_create_command_pending(&kernel));
  record(); CHECK(load_rule("{\"process_name_regex_any\":[\"^powershell\\\\.exe$\"],\"command_regex_all\":[\"trigger\"]}"));
  CHECK(!edr_p0_rule_ir_process_create_command_pending(&kernel));
  CHECK(load_rule("{\"process_name_regex_any\":[\"(*UTF)^powershell\\\\.exe$\"],\"command_regex_any\":[\"trigger\"]}"));
  strcpy(kernel.process_name, "\xff");
  CHECK(edr_p0_rule_ir_process_create_command_pending(&kernel)); /* Regex failure is not a proven miss. */
  record(); CHECK(load_rule("{\"process_name_not_in\":[\"icacls.exe\"],\"command_regex_any\":[\"trigger\"]}"));
  CHECK(!edr_p0_rule_ir_process_create_command_pending(&kernel));
  kernel.process_name[0] = 0; CHECK(edr_p0_rule_ir_process_create_command_pending(&kernel));
  record(); CHECK(load_rule("{\"process_path_regex_any\":[\"Trusted\"],\"command_regex_any\":[\"trigger\"]}"));
  CHECK(!edr_p0_rule_ir_process_create_command_pending(&kernel));
  strcpy(kernel.image_path_resolution_status, "NOT_EVALUABLE"); CHECK(edr_p0_rule_ir_process_create_command_pending(&kernel));
  record(); CHECK(load_rule("{\"parent_name_in\":[\"winword.exe\"],\"command_regex_any\":[\"trigger\"]}"));
  CHECK(edr_p0_rule_ir_process_create_command_pending(&kernel)); /* Display text alone is not bound parent evidence. */
  kernel.parent_process_start_key = 10; kernel.parent_process_creation_filetime_100ns = kernel.process_creation_filetime_100ns - 100;
  strcpy(kernel.parent_resolution_source, "process_tree_cache_verified"); edr_behavior_bind_parent_context(&kernel);
  CHECK(!edr_p0_rule_ir_process_create_command_pending(&kernel));
  strcpy(kernel.source_truncated_fields, "source.parent_name"); CHECK(edr_p0_rule_ir_process_create_command_pending(&kernel));
  record(); CHECK(load_rule("{\"process_name_in\":[\"icacls.exe\"]}"));
  CHECK(!edr_p0_rule_ir_process_create_command_pending(&kernel)); CHECK(edr_p0_rule_ir_br_matches_any(&kernel));
  kernel.type = EDR_EVENT_FILE_READ; CHECK(!edr_p0_rule_ir_process_create_command_pending(&kernel));
  CHECK(!edr_p0_rule_ir_process_create_command_pending(NULL));
  record(); strcpy(kernel.source_truncated_fields, "source.unknown_marker"); CHECK(edr_p0_rule_ir_process_create_command_pending(&kernel));
  edr_p0_rule_ir_shutdown(); remove(fixture_path); record();
  CHECK(edr_p0_rule_ir_process_create_command_pending(&kernel)); CHECK(!edr_p0_rule_ir_is_ready());
  return 1;
}
int main(void) {
  int ok = init_fixture();
  if (ok) { edr_p0_rule_ir_lazy_init(); ok = current_bundle(); }
  if (ok) ok = partial_fields();
  edr_p0_rule_ir_shutdown();
  for (unsigned i = 0; i < archive_count; i++) remove(archives[i]);
  if (fixture_path[0]) remove(fixture_path);
  if (ok) puts("process command admission: PASS (order, quality, correlation, bounds, partial predicates)");
  return ok ? 0 : 1;
}
