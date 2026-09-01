/* 显式非生产 CTest 的 source-only 桩：无 PCRE2 时 fail-closed，不走 legacy 回退。 */
#include "edr/p0_rule_ir.h"

#include <stddef.h>
#include <string.h>

void edr_p0_rule_ir_lazy_init(void) {}

int edr_p0_rule_ir_is_ready(void) { return 0; }
int edr_p0_rule_ir_artifact_healthy(char *out_reason, size_t out_reason_cap) {
  static const char reason[] = "p0_rule_ir_unavailable_nonproduction_stub";
  if (out_reason && out_reason_cap > 0u) {
    size_t copy_len = strlen(reason);
    if (copy_len >= out_reason_cap) {
      copy_len = out_reason_cap - 1u;
    }
    memcpy(out_reason, reason, copy_len);
    out_reason[copy_len] = '\0';
  }
  return 0;
}
void edr_p0_rule_ir_set_sensor_artifact_terminal_unhealthy(const char *reason) {
  (void)reason;
}
void edr_p0_rule_ir_clear_sensor_artifact_terminal_unhealthy(void) {}
int edr_p0_rule_ir_get_bundle_info(const char **out_source, size_t *out_plain_size, const char **out_plain_sha256) {
  if (out_source) *out_source = "";
  if (out_plain_size) *out_plain_size = 0u;
  if (out_plain_sha256) *out_plain_sha256 = "";
  return 0;
}

int edr_p0_rule_ir_get_binding(EdrP0RuleIrBinding *out_binding) {
  if (out_binding) {
    memset(out_binding, 0, sizeof(*out_binding));
  }
  return 0;
}

void edr_p0_rule_ir_sensor_admission_lock(void) {}
void edr_p0_rule_ir_sensor_admission_unlock(void) {}
uint64_t edr_p0_rule_ir_sensor_admission_generation(void) { return 0u; }

int edr_p0_rule_ir_evaluate_record(const EdrBehaviorRecord *br,
                                   EdrP0RuleIrEvaluation *out_evaluation) {
  (void)br;
  if (out_evaluation) {
    memset(out_evaluation, 0, sizeof(*out_evaluation));
  }
  /* The no-PCRE2 build must never claim a verified IR match.  The direct
   * emitter records its explicit no-rules source-only gate instead of
   * fabricating an authority bundle. */
  return 0;
}

int edr_p0_rule_ir_evaluation_get_match(const EdrP0RuleIrEvaluation *evaluation,
                                        uint32_t index,
                                        EdrP0RuleIrMatch *out_match) {
  (void)evaluation;
  (void)index;
  if (out_match) {
    memset(out_match, 0, sizeof(*out_match));
  }
  return 0;
}

void edr_p0_rule_ir_evaluation_free(EdrP0RuleIrEvaluation *evaluation) {
  if (!evaluation) {
    return;
  }
  memset(evaluation, 0, sizeof(*evaluation));
}

unsigned edr_p0_rule_ir_required_full_admission_mask(void) {
  return EDR_P0_IR_FULL_ADMISSION_FILE_READ |
         EDR_P0_IR_FULL_ADMISSION_FILE_WRITE |
         EDR_P0_IR_FULL_ADMISSION_REGISTRY_SET;
}

int edr_p0_rule_ir_matches(
    const char *rule_id, const char *process_name, const char *cmdline, const char *parent_name, int process_chain_depth) {
  (void)rule_id;
  (void)process_name;
  (void)cmdline;
  (void)parent_name;
  (void)process_chain_depth;
  return 0;
}

int edr_p0_rule_ir_get_meta(
    const char *rule_id, const char **out_title, const char **out_mitre) {
  (void)rule_id;
  if (out_title) {
    *out_title = NULL;
  }
  if (out_mitre) {
    *out_mitre = NULL;
  }
  return 0;
}

int edr_p0_rule_ir_get_severity(const char *rule_id) {
  (void)rule_id;
  return 3;
}

int edr_p0_rule_ir_process_create_count(void) { return 0; }

int edr_p0_rule_ir_process_create_id_at(int index, const char **out_id) {
  (void)index;
  (void)out_id;
  return 0;
}

int edr_p0_rule_ir_rule_count(void) { return 0; }

int edr_p0_rule_ir_rule_id_at(int index, const char **out_id) {
  (void)index;
  (void)out_id;
  return 0;
}

int edr_p0_rule_ir_br_matches_index(const EdrBehaviorRecord *br, int index) {
  (void)br;
  (void)index;
  return 0;
}

int edr_p0_rule_ir_br_matches_any(const EdrBehaviorRecord *br) {
  (void)br;
  return 0;
}

int edr_p0_rule_ir_is_interesting_remote_port(uint32_t port) {
  (void)port;
  return 0;
}

int edr_p0_rule_ir_is_interesting_process_name(const char *process_name) {
  (void)process_name;
  return 0;
}

int edr_p0_rule_ir_file_read_path_may_match(const char *path, uint64_t *out_snapshot_epoch) {
  (void)path;
  if (out_snapshot_epoch) *out_snapshot_epoch = 0u;
  return 1;
}

void edr_p0_rule_ir_stats_record(int rule_idx, int hit) {
  (void)rule_idx;
  (void)hit;
}

void edr_p0_rule_ir_stats_dump(void) {
}

void edr_p0_rule_ir_stats_init(void) {
}

void edr_p0_rule_ir_reload(void) {}
void edr_p0_rule_ir_shutdown(void) {}
int edr_p0_rule_ir_validate_candidate_path(const char *path) { (void)path; return 0; }
int edr_p0_rule_ir_install_staged_bundle(const char *staged_path, const char *destination_path) {
  (void)staged_path; (void)destination_path; return 0;
}

int edr_p0_bundle_dst_path(char *out, size_t cap) {
  (void)cap;
  if (out) out[0] = '\0';
  return -1;
}
