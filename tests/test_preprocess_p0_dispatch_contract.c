#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *read_file(const char *path) {
  FILE *file = fopen(path, "rb");
  long size;
  char *contents;
  if (!file || fseek(file, 0, SEEK_END) != 0 || (size = ftell(file)) < 0 ||
      fseek(file, 0, SEEK_SET) != 0) {
    if (file) fclose(file);
    return NULL;
  }
  contents = calloc((size_t)size + 1u, 1u);
  if (!contents || fread(contents, 1u, (size_t)size, file) != (size_t)size) {
    free(contents);
    fclose(file);
    return NULL;
  }
  fclose(file);
  return contents;
}

int main(void) {
  const char *root = getenv("EDR_SOURCE_DIR");
  char path[1400];
  char *source;
  const char *p0_call;
  const char *decision;
  const char *local_only;
  const char *standalone;
  const char *p0_guard;
  const char *throttle_proven_miss;
  const char *throttle_gate;
  const char *p0_enrichment;
  const char *hard_quality;
  const char *fact_resolve;
  const char *fact_match;
  const char *source_only_gate;
  const char *fact_handoff;

  if (!root || !root[0]) root = ".";
  snprintf(path, sizeof(path), "%s/src/preprocess/preprocess_pipeline.c", root);
  source = read_file(path);
  if (!source) return 1;
  p0_call = strstr(source, "int p0_emitted = facts ? edr_p0_rule_try_emit_with_command_facts(&br, facts)");
  decision = strstr(source, "edr_detection_decision_evaluate(&br, &dd);");
  local_only = strstr(source, "edr_preprocess_admit_telemetry(&br, &dd)");
  p0_guard = strstr(source, "if (p0_emitted > 0) {\n    return;\n  }\n  emit_behavior_record(&br);");
  throttle_proven_miss = strstr(source, "static int p0_resource_throttle_proven_miss");
  throttle_gate = strstr(source, "p0_resource_throttle_proven_miss(&br)");
  p0_enrichment = strstr(source, "edr_pid_history_pmfe_fill_record(&br);");
  hard_quality = strstr(source, "int source_only = edr_p0_rule_process_create_hard_reject(&br);");
  fact_resolve = hard_quality ? strstr(hard_quality, "edr_local_evidence_cache_resolve_commands(") : NULL;
  fact_match = fact_resolve ? strstr(fact_resolve,
      "edr_p0_rule_ir_evaluate_record(&br, &command_facts, &evaluation)") : NULL;
  source_only_gate = fact_match ? strstr(fact_match,
      "edr_p0_rule_emit_pre_evaluation_gate(&br, not_evaluable_reason)") : NULL;
  fact_handoff = source_only_gate ? strstr(source_only_gate,
      "process_ready_record(br, slot, command_facts_resolved ? &command_facts : NULL)") : NULL;
  standalone = p0_call ? strstr(p0_call, "emit_behavior_record(&br);") : NULL;
  if (!p0_call || !decision || !local_only || !p0_guard || !standalone ||
      !throttle_proven_miss || !throttle_gate || !p0_enrichment ||
      !hard_quality || !fact_resolve || !fact_match || !source_only_gate || !fact_handoff ||
      hard_quality >= fact_resolve || fact_resolve >= fact_match ||
      fact_match >= source_only_gate || source_only_gate >= fact_handoff ||
      throttle_gate <= p0_enrichment || throttle_gate >= p0_call ||
      p0_call >= decision || p0_call >= local_only || p0_guard >= standalone) {
    fprintf(stderr, "P0 dispatch must precede local-only admission, and pressure may shed only verified IR misses\n");
    free(source);
    return 2;
  }
  if (strstr(source, "edr_storage_queue_poll_drain(") ||
      strstr(source, "edr_process_evidence_wait(")) {
    fprintf(stderr, "preprocessing must not synchronously wait for network or optional evidence\n");
    free(source);
    return 3;
  }
  free(source);
  return 0;
}
