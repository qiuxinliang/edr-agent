#include "edr/p0_rule_ir.h"

#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

enum { WORKERS = 4, ITERATIONS = 200 };
static volatile int s_failed;

static int write_all(int fd, const char *text) {
  size_t left = strlen(text); const char *p = text;
  while (left) { ssize_t n = write(fd, p, left); if (n <= 0) return 0; p += n; left -= (size_t)n; }
  return 1;
}
static int copy_file(const char *from, const char *to) {
  char buf[8192]; int in = open(from, O_RDONLY), out = open(to, O_WRONLY | O_TRUNC);
  if (in < 0 || out < 0) { if (in >= 0) close(in); if (out >= 0) close(out); return 0; }
  for (;;) { ssize_t n = read(in, buf, sizeof(buf)); if (n < 0) goto fail; if (n == 0) break;
    if (write(out, buf, (size_t)n) != n) goto fail; }
  return close(in) == 0 && close(out) == 0;
fail: close(in); close(out); return 0;
}
static int append_space(const char *path) {
  int fd = open(path, O_WRONLY | O_APPEND);
  int ok = fd >= 0 && write(fd, " ", 1u) == 1;
  if (fd >= 0) close(fd);
  return ok;
}
static int files_equal(const char *a, const char *b) {
  char aa[4096], bb[4096]; int fa = open(a, O_RDONLY), fb = open(b, O_RDONLY);
  if (fa < 0 || fb < 0) { if (fa >= 0) close(fa); if (fb >= 0) close(fb); return 0; }
  for (;;) { ssize_t na = read(fa, aa, sizeof(aa)), nb = read(fb, bb, sizeof(bb));
    if (na != nb || na < 0 || (na > 0 && memcmp(aa, bb, (size_t)na) != 0)) { close(fa); close(fb); return 0; }
    if (na == 0) { close(fa); close(fb); return 1; } }
}
static int active_sha(char out[65]) {
  const char *sha = NULL;
  if (!edr_p0_rule_ir_get_bundle_info(NULL, NULL, &sha) || !sha || !sha[0]) return 0;
  snprintf(out, 65, "%s", sha); return 1;
}
static void *evaluate_rules(void *unused) {
  EdrBehaviorRecord record;
  (void)unused;
  memset(&record, 0, sizeof(record));
  record.type = EDR_EVENT_PROCESS_CREATE;
  snprintf(record.process_name, sizeof(record.process_name), "%s", "powershell.exe");
  snprintf(record.cmdline, sizeof(record.cmdline), "%s", "powershell.exe -enc AAAA");
  for (int i = 0; i < ITERATIONS; ++i) {
    EdrP0RuleIrEvaluation evaluation;
    int found = 0;
    memset(&evaluation, 0, sizeof(evaluation));
    if (!edr_p0_rule_ir_evaluate_record(&record, NULL, &evaluation) ||
        !evaluation.binding.rules_bundle_version[0] ||
        !evaluation.binding.artifact_sha256[0] || evaluation.binding.snapshot_epoch == 0u) {
      fprintf(stderr, "single-snapshot evaluation unavailable at iteration %d\n", i);
      s_failed = 1;
      return NULL;
    }
    for (uint32_t j = 0u; j < evaluation.match_count; ++j) {
      EdrP0RuleIrMatch match;
      if (!edr_p0_rule_ir_evaluation_get_match(&evaluation, j, &match)) {
        fprintf(stderr, "copied descriptor unavailable at iteration %d\n", i);
        edr_p0_rule_ir_evaluation_free(&evaluation);
        s_failed = 1;
        return NULL;
      }
      if (strcmp(match.rule_id, "R-EXEC-001") == 0) {
        if (!match.title[0] || !match.mitre_csv[0] || match.severity <= 0) {
          fprintf(stderr, "incomplete copied descriptor at iteration %d\n", i);
          edr_p0_rule_ir_evaluation_free(&evaluation);
          s_failed = 1;
          return NULL;
        }
        found = 1;
      }
    }
    edr_p0_rule_ir_evaluation_free(&evaluation);
    if (!found) {
      fprintf(stderr, "expected R-EXEC-001 disappeared at iteration %d\n", i);
      s_failed = 1;
      return NULL;
    }
  }
  return NULL;
}

static void *reload_rules(void *unused) {
  (void)unused;
  edr_p0_rule_ir_reload();
  return NULL;
}

static void *release_preparation_pause(void *unused) {
  (void)unused;
  usleep(500000u);
  edr_p0_rule_ir_test_pause_preparation(0);
  return NULL;
}

static unsigned long long monotonic_ms(void) {
  struct timespec now;
  if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
    return 0u;
  }
  return (unsigned long long)now.tv_sec * 1000u + (unsigned long long)now.tv_nsec / 1000000u;
}

/* Candidate preparation intentionally sleeps while holding only the
 * publication mutex.  The paired admission guard must still be immediately
 * available; the watchdog turns a historical writer-lock regression into a
 * bounded, observable test failure instead of a hung test process. */
static int reload_preparation_does_not_block_admission(void) {
  pthread_t reload_thread;
  pthread_t watchdog_thread;
  unsigned long long start;
  unsigned long long elapsed;
  int paused = 0;

  edr_p0_rule_ir_test_pause_preparation(1);
  if (pthread_create(&reload_thread, NULL, reload_rules, NULL) != 0) {
    edr_p0_rule_ir_test_pause_preparation(0);
    return 0;
  }
  for (int i = 0; i < 500; ++i) {
    if (edr_p0_rule_ir_test_preparation_paused()) {
      paused = 1;
      break;
    }
    usleep(1000u);
  }
  if (!paused || pthread_create(&watchdog_thread, NULL, release_preparation_pause, NULL) != 0) {
    edr_p0_rule_ir_test_pause_preparation(0);
    (void)pthread_join(reload_thread, NULL);
    return 0;
  }
  start = monotonic_ms();
  edr_p0_rule_ir_sensor_admission_lock();
  edr_p0_rule_ir_sensor_admission_unlock();
  elapsed = monotonic_ms() - start;
  (void)pthread_join(watchdog_thread, NULL);
  (void)pthread_join(reload_thread, NULL);
  return start != 0u && elapsed < 100u;
}

static int rejected_install_keeps_state(const char *staged, const char *dst, const char *before_sha) {
  char after_sha[65];
  return !edr_p0_rule_ir_install_staged_bundle(staged, dst) && active_sha(after_sha) &&
         strcmp(before_sha, after_sha) == 0;
}

/* Invalid typed constraints must reject the whole candidate and preserve the
 * active snapshot and destination bytes. Schema 2 stays readable during upgrade,
 * but cannot disguise schema 3 operators as an old bundle. */
static int registry_candidate_contract(const char *dst, const char *active, const char *source) {
  static const char branch[] = "{\"path_regex\":\"a\",\"value_name\":\"Start\",\"value\":4}";
  const char *bad_conditions[] = {
    "{\"registry_dword_any\":null}", "{\"registry_dword_any\":[]}",
    "{\"registry_dword_any\":[null]}", "{\"registry_dword_any\":[{}]}",
    "{\"registry_dword_any\":[{\"path_regex\":\"a\",\"value_name\":\"Start\"}]}",
    "{\"registry_dword_any\":[{\"path_regex\":\"a\",\"value_name\":\"Start\",\"value\":null}]}",
    "{\"registry_dword_any\":[{\"path_regex\":\"a\",\"value_name\":\"Start\",\"value\":false}]}",
    "{\"registry_dword_any\":[{\"path_regex\":\"a\",\"value_name\":\"Start\",\"value\":-1}]}",
    "{\"registry_dword_any\":[{\"path_regex\":\"a\",\"value_name\":\"Start\",\"value\":4294967296}]}",
    "{\"registry_dword_any\":[{\"path_regex\":\"a\",\"value_name\":\"Start\",\"value\":1.5}]}",
    "{\"registry_dword_any\":[{\"path_regex\":\"a\",\"value_name\":\"Start\",\"value\":\"4\"}]}",
    "{\"registry_dword_any\":[{\"path_regex\":\"a\",\"value_name\":\"Start\",\"value\":4,\"other\":1}]}",
    "{\"registry_dword_any\":[{\"path_regex\":\"a\",\"value_name\":\"Start\",\"value\":4,\"value\":0}]}",
    "{\"registry_dword_any\":[{\"path_regex\":\"[\",\"value_name\":\"Start\",\"value\":4}]}",
    "{\"registry_dword_any\":[{\"path_regex\":\" \",\"value_name\":\"Start\",\"value\":4}]}",
    "{\"registry_dword_any\":[{\"path_regex\":\"a\",\"value_name\":\" Start\",\"value\":4}]}",
    "{\"registry_dword_any\":[{\"path_regex\":\"a\",\"value_name\":\"Start\\u0000X\",\"value\":4}]}"
  };
  size_t negative_count = sizeof(bad_conditions) / sizeof(bad_conditions[0]);
  for (size_t i = 0; i < negative_count + 6u; ++i) {
    char path[] = "/tmp/edr-p0-registry-XXXXXX";
    char json[4096], condition[2048], long_value[513];
    unsigned schema = EDR_P0_RULE_IR_SCHEMA_VERSION;
    int expect_valid = 0;
    if (i < negative_count) snprintf(condition, sizeof(condition), "%s", bad_conditions[i]);
    else if (i == negative_count) {
      snprintf(condition, sizeof(condition), "{\"registry_dword_any\":[%s]}", branch);
      schema = 2u;
    } else if (i == negative_count + 1u) {
      snprintf(condition, sizeof(condition), "{\"registry_path_regex_any\":[\"a\"],\"registry_value_data_in\":[\"0\"]}");
      schema = 2u;
      expect_valid = 1;
    } else if (i == negative_count + 2u) {
      snprintf(condition, sizeof(condition), "{\"registry_dword_any\":[%s]}", branch);
      expect_valid = 1;
    } else if (i == negative_count + 3u) {
      snprintf(condition, sizeof(condition), "{\"registry_dword_any\":[%s,%s,%s,%s,%s,%s,%s,%s,%s]}",
               branch,branch,branch,branch,branch,branch,branch,branch,branch);
    } else {
      size_t length = i == negative_count + 4u ? 512u : 128u;
      memset(long_value, 'a', length); long_value[length] = 0;
      snprintf(condition, sizeof(condition), "{\"registry_dword_any\":[{\"path_regex\":\"%s\",\"value_name\":\"%s\",\"value\":4}]}",
               length == 512u ? long_value : "a", length == 128u ? long_value : "Start");
    }
    snprintf(json, sizeof(json),
      "{\"kind\":\"" EDR_P0_RULE_IR_BUNDLE_KIND "\",\"ir_schema_version\":%u,"
      "\"rules_bundle_version\":\"registry-contract\",\"rule_count\":1,"
      "\"sensor_interest_manifest_sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\","
      "\"sensor_interest_manifest_hash_mode\":\"raw-json-v1-p0-artifact-sha256-zeroed\","
      "\"rules\":[{\"id\":\"registry\",\"event_type\":\"registry_set\",\"condition\":%s}]}", schema, condition);
    int fd = mkstemp(path);
    if (fd < 0) return 0;
    int wrote = write_all(fd, json);
    close(fd);
    int okay = wrote && (expect_valid ? edr_p0_rule_ir_validate_candidate_path(path) :
                        rejected_install_keeps_state(path, dst, active)) && files_equal(source, dst);
    unlink(path);
    if (!okay) { fprintf(stderr, "registry candidate case %zu failed\n", i); return 0; }
  }
  return 1;
}

int main(void) {
  char before_sha[65], installed_sha[65], after_sha[65], staged[] = "/tmp/edr-p0-stage-XXXXXX";
  char source_path[PATH_MAX];
  const char staged_template[] = "/tmp/edr-p0-stage-XXXXXX";
  char dst[] = "/tmp/edr-p0-final-XXXXXX", bad[] = "/tmp/edr-p0-bad-XXXXXX";
  const char bad_template[] = "/tmp/edr-p0-bad-XXXXXX";
  const char *source = getenv("EDR_P0_IR_PATH"); pthread_t workers[WORKERS];
  int staged_fd = -1, dst_fd = -1, bad_fd = -1;
  const char *failed_stage = "initialization";
  const char *cases[] = { "EDR1wrong-key-material", "EDR1",
    "{\"rules\":[{\"id\":\"sem\",\"event_type\":\"process_create\",\"condition\":{}}]}",
    "{\"rules\":[{\"id\":\"pcre\",\"event_type\":\"process_create\",\"condition\":{\"command_regex_any\":[\"[\"]}}]}",
    "{\"rules\":[{\"id\":\"net-unsupported\",\"event_type\":\"network_connect\",\"condition\":{\"remote_port_in\":[1080],\"command_regex_any\":[\"(?i)x\"]}}]}",
    "{\"kind\":\"edr_p0_rule_bundle_ir_v1\",\"ir_schema_version\":4,\"rules_bundle_version\":\"wrong-schema\",\"rule_count\":1,\"sensor_interest_manifest_sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"sensor_interest_manifest_hash_mode\":\"raw-json-v1-p0-artifact-sha256-zeroed\",\"rules\":[{\"id\":\"schema\",\"event_type\":\"process_create\",\"condition\":{\"process_name_in\":[\"tool.exe\"]}}]}",
    "{\"kind\":\"wrong_ir_kind\",\"ir_schema_version\":3,\"rules_bundle_version\":\"wrong-kind\",\"rule_count\":1,\"sensor_interest_manifest_sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"sensor_interest_manifest_hash_mode\":\"raw-json-v1-p0-artifact-sha256-zeroed\",\"rules\":[{\"id\":\"kind\",\"event_type\":\"process_create\",\"condition\":{\"process_name_in\":[\"tool.exe\"]}}]}" };
  if (!source || !source[0] || snprintf(source_path, sizeof(source_path), "%s", source) >= (int)sizeof(source_path)) {
    fprintf(stderr, "snapshot test missing EDR_P0_IR_PATH\n"); return 1;
  }
  source = source_path;
  edr_p0_rule_ir_lazy_init(); if (!active_sha(before_sha)) { fprintf(stderr, "snapshot test no active SHA\n"); return 1; }
  failed_stage = "FileRead authenticated path projection";
  {
    const char *ordinary = "C:\\Users\\testpc\\AppData\\Local\\Temp\\MicrosoftEdge_ARM64_152.0.4191.66_152.0.4191.64.exe";
    uint64_t epoch = 0u;
    if (edr_p0_rule_ir_file_read_path_may_match(ordinary, &epoch) || epoch == 0u ||
        !edr_p0_rule_ir_file_read_path_may_match("C:\\Windows\\Temp\\Login Data", NULL) ||
        !edr_p0_rule_ir_file_read_path_may_match("", NULL) ||
        !edr_p0_rule_ir_file_read_path_may_match(NULL, NULL)) goto fail;
    edr_p0_rule_ir_set_sensor_artifact_terminal_unhealthy("test_sensor_identity_unavailable");
    if (!edr_p0_rule_ir_file_read_path_may_match(ordinary, &epoch) || epoch != 0u) goto fail;
    edr_p0_rule_ir_clear_sensor_artifact_terminal_unhealthy();
    if (edr_p0_rule_ir_file_read_path_may_match(ordinary, NULL)) goto fail;
  }
  for (int i = 0; i < WORKERS; ++i) if (pthread_create(&workers[i], NULL, evaluate_rules, NULL) != 0) { fprintf(stderr, "snapshot worker create failed\n"); return 1; }
  for (int i = 0; i < 20; ++i) edr_p0_rule_ir_reload();
  for (int i = 0; i < WORKERS; ++i) (void)pthread_join(workers[i], NULL);
  if (s_failed) { fprintf(stderr, "snapshot worker reported failure\n"); return 1; }
  failed_stage = "reload preparation admission latency";
  if (!reload_preparation_does_not_block_admission()) goto fail;
  failed_stage = "create staged files";
  staged_fd = mkstemp(staged); dst_fd = mkstemp(dst); if (staged_fd < 0 || dst_fd < 0) goto fail;
  close(staged_fd); staged_fd = -1; close(dst_fd); dst_fd = -1;
  failed_stage = "install valid staged bundle";
  if (!copy_file(source, staged) || !edr_p0_rule_ir_install_staged_bundle(staged, dst) || !files_equal(source, dst) ||
      !active_sha(installed_sha) || strcmp(before_sha, installed_sha) != 0) goto fail;
  /* A failure after the staged file is renamed must restore the previous
   * durable bytes and leave the active snapshot untouched.  Whitespace makes
   * the staged plaintext SHA distinct while retaining valid JSON. */
  snprintf(staged, sizeof(staged), "%s", staged_template);
  staged_fd = mkstemp(staged); if (staged_fd < 0) goto fail;
  close(staged_fd); staged_fd = -1;
  failed_stage = "rollback post-rename directory sync failure";
  /* backup link + prepared journal are durable barriers one and two; fail
   * the post-rename directory sync and require the journal to restore old
   * bytes before the candidate can be considered rejected. */
  edr_p0_rule_ir_test_fail_parent_sync_after(3u);
  if (!copy_file(source, staged) || !append_space(staged) ||
      edr_p0_rule_ir_install_staged_bundle(staged, dst) || !files_equal(source, dst) ||
      !active_sha(after_sha) || strcmp(after_sha, installed_sha) != 0) goto fail;
  /* If both the post-rename fsync and the immediate rollback fsync fail, the
   * active authority must be retired.  A later lifecycle start recovers the
   * prepared journal before it trusts the destination again. */
  snprintf(staged, sizeof(staged), "%s", staged_template);
  staged_fd = mkstemp(staged); if (staged_fd < 0) goto fail;
  close(staged_fd); staged_fd = -1;
  failed_stage = "journal recovery after rollback durability failure";
  edr_p0_rule_ir_test_fail_parent_sync_after_count(3u, 2u);
  if (!copy_file(source, staged) || !append_space(staged) ||
      edr_p0_rule_ir_install_staged_bundle(staged, dst) ||
      edr_p0_rule_ir_artifact_healthy(NULL, 0u) || edr_p0_rule_ir_is_ready()) goto fail;
  edr_p0_rule_ir_shutdown();
  if (setenv("EDR_P0_IR_PATH", dst, 1) != 0) goto fail;
  edr_p0_rule_ir_lazy_init();
  if (!edr_p0_rule_ir_is_ready() || !edr_p0_rule_ir_artifact_healthy(NULL, 0u) ||
      !files_equal(source, dst) || setenv("EDR_P0_IR_PATH", source, 1) != 0) goto fail;
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
    failed_stage = "reject malformed staged bundle";
    snprintf(bad, sizeof(bad), "%s", bad_template);
    bad_fd = mkstemp(bad); if (bad_fd < 0 || !write_all(bad_fd, cases[i])) goto fail;
    close(bad_fd); bad_fd = -1;
    if (!rejected_install_keeps_state(bad, dst, installed_sha) || !files_equal(source, dst)) goto fail;
    unlink(bad);
  }
  failed_stage = "registry DWORD and legacy schema candidate contract";
  if (!registry_candidate_contract(dst, installed_sha, source)) goto fail;
  snprintf(bad, sizeof(bad), "%s", bad_template);
  bad_fd = mkstemp(bad); if (bad_fd < 0 || !write_all(
      bad_fd,
      "{\"kind\":\"" EDR_P0_RULE_IR_BUNDLE_KIND "\",\"ir_schema_version\":3,"
      "\"rules_bundle_version\":\"snapshot-test-v1\",\"rule_count\":1,"
      "\"sensor_interest_manifest_sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\","
      "\"sensor_interest_manifest_hash_mode\":\"raw-json-v1-p0-artifact-sha256-zeroed\","
      "\"rules\":[{\"id\":\"net-name\",\"title\":\"net name\",\"mitre_ttps\":[\"T1090\"],"
      "\"event_type\":\"network_connect\",\"condition\":{\"process_name_in\":[\"tool.exe\"],\"remote_port_in\":[1080]}}]}")) goto fail;
  close(bad_fd); bad_fd = -1;
  failed_stage = "validate non-install candidate";
  if (!edr_p0_rule_ir_validate_candidate_path(bad) || !files_equal(source, dst)) goto fail;
  unlink(bad);
  snprintf(staged, sizeof(staged), "%s", staged_template);
  staged_fd = mkstemp(staged); if (staged_fd < 0) goto fail; close(staged_fd); staged_fd = -1;
  failed_stage = "reject unwriteable destination";
  if (!copy_file(source, staged) || !rejected_install_keeps_state(staged, "/no/such/p0-rule-final", installed_sha) ||
      !files_equal(source, dst)) goto fail;
  unlink(staged); edr_p0_rule_ir_shutdown(); failed_stage = "shutdown"; if (edr_p0_rule_ir_is_ready()) goto fail;
  edr_p0_rule_ir_lazy_init(); failed_stage = "reinitialize"; if (!edr_p0_rule_ir_is_ready()) goto fail;
  unlink(dst); return 0;
fail:
  fprintf(stderr, "snapshot test failed at %s\n", failed_stage);
  if (staged_fd >= 0) close(staged_fd);
  if (dst_fd >= 0) close(dst_fd);
  if (bad_fd >= 0) close(bad_fd);
  unlink(staged);
  unlink(dst);
  unlink(bad);
  return 1;
}
