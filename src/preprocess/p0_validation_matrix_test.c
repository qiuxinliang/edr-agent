#include "edr/behavior_record.h"
#include "edr/p0_rule_ir.h"
#include "edr/sensor_interest.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(_WIN32)
#include <windows.h>
#endif

typedef struct {
  const char *case_id;
  const char *rule_id;
  const char *case_kind;
  const char *case_class;
  const char *operational_expectation;
  const char *validation_status;
  int expect_hit;
  EdrEventType type;
  const char *process_name;
  const char *process_path;
  const char *parent_name;
  const char *cmdline;
  uint32_t chain_depth;
  const char *file_path;
  uint32_t dest_port;
  const char *registry_path;
  const char *registry_value_name;
  const char *registry_value_data;
} P0ValidationCase;

/* The standalone matrix binary links the same SensorInterest predicate as
 * the collector, but feeds it constructed records.  This is matcher/admission
 * replay only: it neither starts collection nor proves live event delivery.
 * It does not execute matrix actions; a runner must reject unknown actions
 * before execution. Correlation observation is deliberately inert for
 * deterministic coverage. */
void edr_correlation_observe_interest(const EdrSensorInterestEvent *event) {
  (void)event;
}

static const P0ValidationCase k_cases[] = {
#include "p0_validation_matrix_data.inc"
};

static int find_rule(const char *rule_id) {
  int count = edr_p0_rule_ir_rule_count();
  int i;
  for (i = 0; i < count; ++i) {
    const char *candidate = NULL;
    if (edr_p0_rule_ir_rule_id_at(i, &candidate) && candidate && strcmp(candidate, rule_id) == 0) {
      return i;
    }
  }
  return -1;
}

static void copy_text(char *dst, size_t cap, const char *src) {
  snprintf(dst, cap, "%s", src ? src : "");
}

static void set_env_value(const char *name, const char *value) {
#if defined(_WIN32)
  (void)_putenv_s(name, value ? value : "");
#else
  (void)setenv(name, value ? value : "", 1);
#endif
}

static char *read_text_file(const char *path, size_t *out_len) {
  FILE *f;
  long n;
  char *buf;
  if (out_len) *out_len = 0u;
  f = path ? fopen(path, "rb") : NULL;
  if (!f || fseek(f, 0, SEEK_END) != 0 || (n = ftell(f)) <= 0 ||
      (size_t)n > 4u * 1024u * 1024u || fseek(f, 0, SEEK_SET) != 0) {
    if (f) fclose(f);
    return NULL;
  }
  buf = (char *)malloc((size_t)n + 1u);
  if (!buf || fread(buf, 1u, (size_t)n, f) != (size_t)n) {
    free(buf);
    fclose(f);
    return NULL;
  }
  fclose(f);
  buf[n] = '\0';
  if (out_len) *out_len = (size_t)n;
  return buf;
}

static int sensor_interest_is_fail_full(void) {
  EdrSensorInterestStatus status;
  memset(&status, 0, sizeof(status));
  edr_sensor_interest_get_status(&status);
  return !status.full_admission_contract_valid && !status.p0_binding_valid &&
         status.file_read_full_admission && status.file_write_full_admission &&
         status.registry_set_full_admission;
}

static int check_sensor_interest_raw_contract(const char *production_path) {
  static const char *const mutation_path = "sensor_interest_raw_contract_mutation.json";
  char production_copy[1200];
  char *raw;
  size_t raw_len = 0u;
  int failures = 0;
  EdrSensorInterestStatus status;
  if (!production_path || !production_path[0] || !(raw = read_text_file(production_path, &raw_len))) {
    fprintf(stderr, "sensor-interest raw contract fixture unavailable\n");
    return 1;
  }
  snprintf(production_copy, sizeof(production_copy), "%s", production_path);
  memset(&status, 0, sizeof(status));
  edr_sensor_interest_get_status(&status);
  if (!status.loaded || !status.full_admission_contract_valid || !status.p0_binding_valid ||
      !status.sensor_interest_manifest_sha256[0]) {
    fprintf(stderr, "sensor-interest production raw binding is unavailable\n");
    failures++;
  }
  for (int mutation = 0; mutation < 8; ++mutation) {
    char *candidate = NULL;
    size_t candidate_len = raw_len;
    FILE *out;
    size_t written;
    int close_rc;
    if (mutation == 0) { /* P0 remote-port deletion/tamper */
      candidate = (char *)malloc(raw_len + 1u);
      if (candidate) {
        memcpy(candidate, raw, raw_len + 1u);
        {
          char *port = strstr(candidate, "445");
          if (port) *port = '9'; /* preserve a valid-looking integer but alter the raw bytes */
        }
      }
    } else if (mutation == 1) { /* raw whitespace changes are authenticated too */
      candidate = (char *)malloc(raw_len + 2u);
      if (candidate) {
        candidate[0] = ' ';
        memcpy(candidate + 1u, raw, raw_len + 1u);
        candidate_len = raw_len + 1u;
      }
    } else if (mutation == 2) { /* duplicate top-level binding member */
      const char *sha = strstr(raw, "\"p0_artifact_sha256\": \"");
      const char *value = sha ? sha + strlen("\"p0_artifact_sha256\": \"") : NULL;
      candidate = (char *)malloc(raw_len + 100u);
      if (candidate && value && raw_len > 2u) {
        memcpy(candidate, raw, raw_len - 2u);
        candidate_len = raw_len - 2u;
        candidate_len += (size_t)snprintf(candidate + candidate_len, 100u,
                                          ",\n  \"p0_artifact_sha256\": \"%.*s\"\n}\n", 64, value);
      }
    } else if (mutation == 3) { /* same-value nested lure must not be zeroed as top-level */
      const char *sha = strstr(raw, "\"p0_artifact_sha256\": \"");
      const char *value = sha ? sha + strlen("\"p0_artifact_sha256\": \"") : NULL;
      candidate = (char *)malloc(raw_len + 150u);
      if (candidate && value && raw_len > 2u) {
        memcpy(candidate, raw, raw_len - 2u);
        candidate_len = raw_len - 2u;
        candidate_len += (size_t)snprintf(candidate + candidate_len, 150u,
                                          ",\n  \"nested\": {\"p0_artifact_sha256\": \"%.*s\"}\n}\n",
                                          64, value);
      }
    } else if (mutation == 4) { /* escaped raw key is semantically equivalent but not byte-identical */
      static const char marker[] = "\"p0_artifact_sha256\"";
      static const char replacement[] = "\"p0\\u005fartifact_sha256\"";
      const char *field = strstr(raw, marker);
      if (field) {
        size_t prefix = (size_t)(field - raw);
        size_t suffix = raw_len - prefix - (sizeof(marker) - 1u);
        candidate_len = prefix + (sizeof(replacement) - 1u) + suffix;
        candidate = (char *)malloc(candidate_len + 1u);
        if (candidate) {
          memcpy(candidate, raw, prefix);
          memcpy(candidate + prefix, replacement, sizeof(replacement) - 1u);
          memcpy(candidate + prefix + sizeof(replacement) - 1u,
                 field + sizeof(marker) - 1u, suffix);
          candidate[candidate_len] = '\0';
        }
      }
    } else if (mutation == 5) { /* canonical JSON reordering changes authenticated raw bytes */
      const char *cmd_start = strstr(raw, "  \"cmd_tokens\": ");
      const char *counts_start = strstr(raw, "\n  \"counts\": ");
      const char *enabled_start = counts_start ? strstr(counts_start, "\n  \"enabled_rules\": ") : NULL;
      if (cmd_start && counts_start && enabled_start && cmd_start < counts_start) {
        size_t prefix = (size_t)(cmd_start - raw);
        size_t cmd_len = (size_t)((counts_start + 1) - cmd_start);
        size_t counts_len = (size_t)((enabled_start + 1) - (counts_start + 1));
        size_t suffix = raw_len - (size_t)(enabled_start + 1 - raw);
        candidate = (char *)malloc(raw_len + 1u);
        if (candidate) {
          memcpy(candidate, raw, prefix);
          memcpy(candidate + prefix, counts_start + 1, counts_len);
          memcpy(candidate + prefix + counts_len, cmd_start, cmd_len);
          memcpy(candidate + prefix + counts_len + cmd_len, enabled_start + 1, suffix);
          candidate_len = raw_len;
          candidate[candidate_len] = '\0';
        }
      }
    } else if (mutation == 6) { /* a syntactically valid extra whitespace change */
      const char *field = strstr(raw, "\"remote_ports\": [");
      if (field) {
        size_t prefix = (size_t)(field - raw) + strlen("\"remote_ports\": [");
        candidate_len = raw_len + 1u;
        candidate = (char *)malloc(candidate_len + 1u);
        if (candidate) {
          memcpy(candidate, raw, prefix);
          candidate[prefix] = ' ';
          memcpy(candidate + prefix + 1u, raw + prefix, raw_len - prefix);
          candidate[candidate_len] = '\0';
        }
      }
    } else { /* truncation */
      candidate_len = raw_len / 2u;
      candidate = (char *)malloc(candidate_len + 1u);
      if (candidate) {
        memcpy(candidate, raw, candidate_len);
        candidate[candidate_len] = '\0';
      }
    }
    if (!candidate) {
      fprintf(stderr, "sensor-interest mutation setup failed (%d)\n", mutation);
      free(candidate);
      failures++;
      continue;
    }
    out = fopen(mutation_path, "wb");
    if (!out) {
      free(candidate);
      failures++;
      continue;
    }
    written = fwrite(candidate, 1u, candidate_len, out);
    close_rc = fclose(out);
    if (written != candidate_len || close_rc != 0) {
      free(candidate);
      failures++;
      continue;
    }
    free(candidate);
    set_env_value("EDR_SENSOR_INTEREST_PATH", mutation_path);
    edr_sensor_interest_reload();
    if (!sensor_interest_is_fail_full()) {
      fprintf(stderr, "sensor-interest raw mutation %d did not fail full\n", mutation);
      failures++;
    }
  }
  remove(mutation_path);
  set_env_value("EDR_SENSOR_INTEREST_PATH", production_copy);
  edr_sensor_interest_reload();
  memset(&status, 0, sizeof(status));
  edr_sensor_interest_get_status(&status);
  if (!status.loaded || !status.full_admission_contract_valid || !status.p0_binding_valid) {
    fprintf(stderr, "sensor-interest production manifest did not recover after mutation test\n");
    failures++;
  }
  free(raw);
  return failures;
}

static int check_sensor_interest_staged_replace(const char *production_path) {
  static const char *const dst_path = "sensor_interest_staged_live.json";
  static const char *const bad_path = "sensor_interest_staged_truncated.json";
  char *raw = NULL;
  char *installed = NULL;
  char production_copy[1200];
  size_t raw_len = 0u;
  size_t installed_len = 0u;
  int failures = 0;
  EdrSensorInterestStatus before;
  EdrSensorInterestStatus after;
  if (!production_path || !production_path[0] || !(raw = read_text_file(production_path, &raw_len))) {
    return 1;
  }
  snprintf(production_copy, sizeof(production_copy), "%s", production_path);
  remove(dst_path);
  remove(bad_path);
  set_env_value("EDR_SENSOR_INTEREST_PATH", dst_path);
  if (edr_sensor_interest_replace_manifest_from_file(production_copy) != 0) {
    fprintf(stderr, "sensor-interest staged replacement rejected authenticated manifest\n");
    failures++;
    goto done;
  }
  installed = read_text_file(dst_path, &installed_len);
  if (!installed || installed_len != raw_len || memcmp(installed, raw, raw_len) != 0) {
    fprintf(stderr, "sensor-interest staged replacement did not preserve exact raw bytes\n");
    failures++;
    goto done;
  }
  memset(&before, 0, sizeof(before));
  edr_sensor_interest_get_status(&before);
  if (!before.loaded || !before.p0_binding_valid || !before.full_admission_contract_valid) {
    fprintf(stderr, "sensor-interest staged replacement did not publish a verified snapshot\n");
    failures++;
    goto done;
  }
#if defined(_WIN32)
  /* Windows commits through MoveFileExA, not the POSIX parent-fsync hook.
   * A real handle without FILE_SHARE_DELETE must deny that replacement. */
  {
    int result;
    HANDLE held = CreateFileA(dst_path, GENERIC_READ, FILE_SHARE_READ, NULL,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (held == INVALID_HANDLE_VALUE) {
      fprintf(stderr, "sensor-interest replacement sharing-denial setup failed: %lu\n",
              (unsigned long)GetLastError());
      failures++;
      goto done;
    }
    result = edr_sensor_interest_replace_manifest_from_file(production_copy);
    CloseHandle(held);
    if (result == 0) {
      fprintf(stderr, "sensor-interest staged replacement ignored Windows sharing denial\n");
      failures++;
      goto done;
    }
  }
#else
  /* Force the second durability barrier: the stage has been renamed, so the
   * installer must roll back the old bytes and must not publish its candidate. */
  edr_sensor_interest_test_fail_parent_sync_after(2u);
  if (edr_sensor_interest_replace_manifest_from_file(production_copy) == 0) {
    fprintf(stderr, "sensor-interest staged replacement accepted post-rename sync failure\n");
    failures++;
    goto done;
  }
#endif
  memset(&after, 0, sizeof(after));
  edr_sensor_interest_get_status(&after);
  free(installed);
  installed = read_text_file(dst_path, &installed_len);
  if (!installed || installed_len != raw_len || memcmp(installed, raw, raw_len) != 0 ||
      after.snapshot_epoch != before.snapshot_epoch || !after.p0_binding_valid) {
    fprintf(stderr, "sensor-interest failed replacement did not retain the old durable state\n");
    failures++;
    goto done;
  }
  {
    FILE *bad = fopen(bad_path, "wb");
    size_t truncated = raw_len / 2u;
    if (!bad || fwrite(raw, 1u, truncated, bad) != truncated || fclose(bad) != 0) {
      if (bad) fclose(bad);
      fprintf(stderr, "sensor-interest staged truncation setup failed\n");
      failures++;
      goto done;
    }
  }
  if (edr_sensor_interest_replace_manifest_from_file(bad_path) == 0) {
    fprintf(stderr, "sensor-interest staged replacement accepted truncation\n");
    failures++;
  }
  memset(&after, 0, sizeof(after));
  edr_sensor_interest_get_status(&after);
  free(installed);
  installed = read_text_file(dst_path, &installed_len);
  if (!installed || installed_len != raw_len || memcmp(installed, raw, raw_len) != 0 ||
      !after.loaded || !after.p0_binding_valid || !after.full_admission_contract_valid ||
      after.snapshot_epoch != before.snapshot_epoch) {
    fprintf(stderr, "sensor-interest failed staged update altered live bytes or snapshot\n");
    failures++;
  }
  if (edr_sensor_interest_replace_manifest_from_file(production_copy) != 0) {
    fprintf(stderr, "sensor-interest valid replacement did not recover after failure\n");
    failures++;
  } else {
    edr_sensor_interest_get_status(&after);
    if (!after.p0_binding_valid || after.snapshot_epoch <= before.snapshot_epoch) {
      fprintf(stderr, "sensor-interest replacement recovery did not publish verified state\n");
      failures++;
    }
  }
done:
  free(installed);
  free(raw);
  remove(dst_path);
  remove(bad_path);
  set_env_value("EDR_SENSOR_INTEREST_PATH", production_copy);
  edr_sensor_interest_reload();
  return failures;
}

static int check_sensor_interest_ir_pair(const char *production_path) {
  static const char *const bad_path = "sensor_interest_pair_truncated.json";
  EdrSensorInterestEvent ordinary_network;
  EdrSensorInterestStatus status;
  EdrP0RuleIrBinding before;
  EdrP0RuleIrBinding after;
  char *raw = NULL;
  size_t raw_len = 0u;
  int failures = 0;
  FILE *bad = NULL;
  memset(&ordinary_network, 0, sizeof(ordinary_network));
  ordinary_network.type = EDR_EVENT_NET_CONNECT;
  snprintf(ordinary_network.process_name, sizeof(ordinary_network.process_name), "%s", "ordinary.exe");
  remove(bad_path);
  if (!production_path || !production_path[0] ||
      !edr_p0_rule_ir_get_binding(&before) ||
      edr_sensor_interest_should_admit(&ordinary_network)) {
    fprintf(stderr, "sensor-interest pair precondition is not a verified narrow projection\n");
    return 1;
  }

  /* The IR replacement succeeds while the old SensorInterest snapshot remains
   * resident.  It must immediately become fail-full rather than keep using
   * its old network-port projection. */
  edr_p0_rule_ir_reload();
  if (!edr_p0_rule_ir_get_binding(&after) || after.snapshot_epoch == before.snapshot_epoch) {
    fprintf(stderr, "sensor-interest pair test did not advance the IR generation\n");
    return 1;
  }
  memset(&status, 0, sizeof(status));
  edr_sensor_interest_get_status(&status);
  if (status.p0_binding_valid || !status.file_read_full_admission ||
      !status.file_write_full_admission || !status.registry_set_full_admission ||
      !edr_sensor_interest_should_admit(&ordinary_network)) {
    fprintf(stderr, "sensor-interest did not fail full after IR generation swap\n");
    failures++;
  }

  /* A failed sensor update cannot reopen the narrowed window after the IR
   * changed.  The existing stale snapshot must remain conservative. */
  raw = read_text_file(production_path, &raw_len);
  bad = raw ? fopen(bad_path, "wb") : NULL;
  if (!raw || !bad) {
    fprintf(stderr, "sensor-interest pair truncation setup failed\n");
    failures++;
  } else {
    size_t written = fwrite(raw, 1u, raw_len / 2u, bad);
    int close_rc = fclose(bad);
    bad = NULL;
    if (written != raw_len / 2u || close_rc != 0) {
      fprintf(stderr, "sensor-interest pair truncation setup failed\n");
      failures++;
    } else if (edr_sensor_interest_replace_manifest_from_file(bad_path) == 0 ||
             !edr_sensor_interest_should_admit(&ordinary_network)) {
      fprintf(stderr, "sensor-interest accepted failed update after IR generation swap\n");
      failures++;
    }
  }
  free(raw);
  remove(bad_path);

  /* Re-reading the authenticated manifest against the active IR commits the
   * only allowed narrow pair again. */
  edr_sensor_interest_reload();
  memset(&status, 0, sizeof(status));
  edr_sensor_interest_get_status(&status);
  if (!status.loaded || !status.full_admission_contract_valid || !status.p0_binding_valid ||
      edr_sensor_interest_should_admit(&ordinary_network)) {
    fprintf(stderr, "sensor-interest did not recover a matching IR pair\n");
    failures++;
  }
  return failures;
}

int main(void) {
  size_t i;
  int failures = 0;
  int positives = 0;
  int missing = 0;
  int business_benign = 0;
  int rule_tuning_required = 0;
  int security_control = 0;
  int not_evaluable = 0;
  int sensor_dispatch_positives = 0;
  edr_p0_rule_ir_lazy_init();
  if (!edr_p0_rule_ir_is_ready()) {
    fprintf(stderr, "P0 IR is not ready\n");
    return 1;
  }
  edr_sensor_interest_reload();
  {
    EdrSensorInterestStatus interest_status;
    memset(&interest_status, 0, sizeof(interest_status));
    edr_sensor_interest_get_status(&interest_status);
    if (!interest_status.loaded || !interest_status.full_admission_contract_valid) {
      fprintf(stderr, "SensorInterest full-admission contract is unavailable (loaded=%d valid=%d binding=%d epoch=%llu)\n",
              interest_status.loaded, interest_status.full_admission_contract_valid,
              interest_status.p0_binding_valid, (unsigned long long)interest_status.snapshot_epoch);
      return 1;
    }
  }
  failures += check_sensor_interest_raw_contract(getenv("EDR_SENSOR_INTEREST_PATH"));
  failures += check_sensor_interest_staged_replace(getenv("EDR_SENSOR_INTEREST_PATH"));
  failures += check_sensor_interest_ir_pair(getenv("EDR_SENSOR_INTEREST_PATH"));
  int rule_count = edr_p0_rule_ir_rule_count();
  const size_t case_count = sizeof(k_cases) / sizeof(k_cases[0]);
  if (rule_count <= 0 || case_count != (size_t)rule_count * 3u) {
    fprintf(stderr, "P0 matcher replay case count=%zu, want=%d active rules * 3\n",
            case_count, rule_count);
    failures++;
  }
  for (i = 0; i < sizeof(k_cases) / sizeof(k_cases[0]); ++i) {
    const P0ValidationCase *tc = &k_cases[i];
    int idx = find_rule(tc->rule_id);
    EdrBehaviorRecord br;
    int got;
    if (idx < 0) {
      fprintf(stderr, "%s: missing rule %s\n", tc->case_id, tc->rule_id);
      failures++;
      continue;
    }
    edr_behavior_record_init(&br);
    br.type = tc->type;
    br.process_chain_depth = tc->chain_depth;
    br.net_dport = tc->dest_port;
    copy_text(br.process_name, sizeof(br.process_name), tc->process_name);
    copy_text(br.exe_path, sizeof(br.exe_path), tc->process_path);
    copy_text(br.parent_name, sizeof(br.parent_name), tc->parent_name);
    copy_text(br.cmdline, sizeof(br.cmdline), tc->cmdline);
    copy_text(br.file_path, sizeof(br.file_path), tc->file_path);
    copy_text(br.reg_key_path, sizeof(br.reg_key_path), tc->registry_path);
    copy_text(br.reg_value_name, sizeof(br.reg_value_name), tc->registry_value_name);
    copy_text(br.reg_value_data, sizeof(br.reg_value_data), tc->registry_value_data);
    got = edr_p0_rule_ir_br_matches_index(&br, idx) ? 1 : 0;
    if (got != tc->expect_hit) {
      fprintf(stderr, "%s: expected %d got %d\n", tc->case_id, tc->expect_hit, got);
      failures++;
    }
    if (strcmp(tc->case_kind, "POSITIVE_E2E") == 0) {
      positives++;
      if (strcmp(tc->case_class, "DETECTION_REQUIRED") != 0 ||
          strcmp(tc->operational_expectation, "TARGET_RULE_PRESENT") != 0 ||
          strcmp(tc->validation_status, "UNVERIFIED") != 0 || !tc->expect_hit) {
        fprintf(stderr, "%s: invalid positive replay contract\n", tc->case_id);
        failures++;
      }
      if (tc->type == EDR_EVENT_FILE_READ || tc->type == EDR_EVENT_FILE_WRITE ||
          tc->type == EDR_EVENT_REG_SET_VALUE) {
        EdrSensorInterestEvent interest;
        memset(&interest, 0, sizeof(interest));
        interest.type = tc->type;
        snprintf(interest.process_name, sizeof(interest.process_name), "%s",
                 tc->process_name ? tc->process_name : "");
        snprintf(interest.path, sizeof(interest.path), "%s",
                 tc->file_path && tc->file_path[0] ? tc->file_path : tc->registry_path);
        snprintf(interest.registry_path, sizeof(interest.registry_path), "%s",
                 tc->registry_path ? tc->registry_path : "");
        if (!edr_sensor_interest_should_admit(&interest)) {
          fprintf(stderr, "%s: collector SensorInterest dropped P0 positive\n", tc->case_id);
          failures++;
        }
        sensor_dispatch_positives++;
      }
    } else if (strcmp(tc->case_kind, "MISSING_FIELD_REPLAY") == 0) {
      missing++;
      if (strcmp(tc->case_class, "MATCHER_REPLAY_ONLY") != 0 ||
          strcmp(tc->operational_expectation, "REPLAY_ONLY_NOT_A_LIVE_RESULT") != 0 ||
          strcmp(tc->validation_status, "STATIC_REPLAY_ONLY") != 0) {
        fprintf(stderr, "%s: invalid missing-field replay contract\n", tc->case_id);
        failures++;
      }
    } else if (strcmp(tc->case_kind, "BUSINESS_BENIGN_E2E") == 0) {
      business_benign++;
      if (strcmp(tc->case_class, "BUSINESS_BENIGN_E2E") != 0 ||
          strcmp(tc->operational_expectation, "TARGET_RULE_ABSENT_AND_QUIET_WINDOW") != 0 ||
          strcmp(tc->validation_status, "UNVERIFIED") != 0 || tc->expect_hit) {
        fprintf(stderr, "%s: business-benign replay is not an unverified zero-alert candidate\n", tc->case_id);
        failures++;
      }
    } else if (strcmp(tc->case_kind, "RULE_TUNING_REQUIRED") == 0) {
      rule_tuning_required++;
      if (strcmp(tc->case_class, "RULE_TUNING_REQUIRED") != 0 ||
          strcmp(tc->operational_expectation, "NO_PASS_RULE_TUNING_REQUIRED") != 0 ||
          strcmp(tc->validation_status, "UNVERIFIED") != 0 || !tc->expect_hit) {
        fprintf(stderr, "%s: rule-tuning replay contract is inconsistent\n", tc->case_id);
        failures++;
      }
    } else if (strcmp(tc->case_kind, "SECURITY_CONTROL") == 0) {
      security_control++;
      if (strcmp(tc->case_class, "SECURITY_CONTROL") != 0 ||
          strcmp(tc->operational_expectation, "TARGET_RULE_PRESENT_SECURITY_CONTROL") != 0 ||
          strcmp(tc->validation_status, "UNVERIFIED") != 0 || !tc->expect_hit) {
        fprintf(stderr, "%s: security-control replay contract is inconsistent\n", tc->case_id);
        failures++;
      }
    } else if (strcmp(tc->case_kind, "NOT_EVALUABLE") == 0) {
      not_evaluable++;
      if (strcmp(tc->case_class, "NOT_EVALUABLE") != 0 ||
          strcmp(tc->operational_expectation, "NO_PASS_NOT_EVALUABLE") != 0 ||
          strcmp(tc->validation_status, "NOT_EVALUABLE") != 0) {
        fprintf(stderr, "%s: not-evaluable replay contract is inconsistent\n", tc->case_id);
        failures++;
      }
    } else {
      fprintf(stderr, "%s: unknown replay case kind %s\n", tc->case_id,
              tc->case_kind ? tc->case_kind : "(null)");
      failures++;
    }
    {
      size_t j;
      int same_rule = 0;
      for (j = 0; j < sizeof(k_cases) / sizeof(k_cases[0]); ++j) {
        if (strcmp(k_cases[j].rule_id, tc->rule_id) == 0) same_rule++;
        if (j < i && strcmp(k_cases[j].case_id, tc->case_id) == 0) {
          fprintf(stderr, "%s: duplicate replay case id\n", tc->case_id);
          failures++;
        }
      }
      if (same_rule != 3) {
        fprintf(stderr, "%s: rule %s has %d replay cases, want=3\n",
                tc->case_id, tc->rule_id, same_rule);
        failures++;
      }
    }
  }
  /* Coverage follows the active authority, not a stale historical 173-rule
   * count. Every rule must retain its positive, missing-field and operational
   * case; one duplicated rule cannot compensate for an uncovered new rule. */
  for (int rule_index = 0; rule_index < rule_count; ++rule_index) {
    const char *rule_id = NULL;
    int positive_cases = 0, missing_cases = 0, other_cases = 0;
    if (!edr_p0_rule_ir_rule_id_at(rule_index, &rule_id) || !rule_id) {
      failures++;
      continue;
    }
    for (size_t j = 0; j < case_count; ++j) {
      if (strcmp(k_cases[j].rule_id, rule_id) != 0) continue;
      if (strcmp(k_cases[j].case_kind, "POSITIVE_E2E") == 0) positive_cases++;
      else if (strcmp(k_cases[j].case_kind, "MISSING_FIELD_REPLAY") == 0) missing_cases++;
      else other_cases++;
    }
    if (positive_cases != 1 || missing_cases != 1 || other_cases != 1) {
      fprintf(stderr, "%s: coverage must contain exactly one positive, missing-field and operational case\n", rule_id);
      failures++;
    }
  }
  if (positives != rule_count || missing != rule_count ||
      (size_t)(positives + missing + business_benign + rule_tuning_required +
               security_control + not_evaluable) != case_count) {
    fprintf(stderr, "coverage mismatch: positive=%d missing=%d business_benign=%d tuning=%d security=%d not_evaluable=%d sensor_dispatch=%d\n",
            positives, missing, business_benign, rule_tuning_required, security_control,
            not_evaluable, sensor_dispatch_positives);
    failures++;
  }
  fprintf(stderr, "P0 Agent matcher replay matrix (not live collection): positive=%d missing=%d business_benign=%d tuning=%d security=%d not_evaluable=%d sensor_dispatch=%d failures=%d\n",
          positives, missing, business_benign, rule_tuning_required, security_control,
          not_evaluable, sensor_dispatch_positives, failures);
  return failures == 0 ? 0 : 1;
}
