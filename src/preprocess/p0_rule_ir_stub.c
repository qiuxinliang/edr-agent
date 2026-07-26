/* 未链 PCRE2 时的桩：P0 仍走 p0_rule_match 内 legacy 路径。 */
#include "edr/p0_rule_ir.h"

#include <stddef.h>

void edr_p0_rule_ir_lazy_init(void) {}

int edr_p0_rule_ir_is_ready(void) { return 0; }
int edr_p0_rule_ir_get_bundle_info(const char **out_source, size_t *out_plain_size, const char **out_plain_sha256) {
  if (out_source) *out_source = "";
  if (out_plain_size) *out_plain_size = 0u;
  if (out_plain_sha256) *out_plain_sha256 = "";
  return 0;
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

void edr_p0_rule_ir_stats_record(int rule_idx, int hit) {
  (void)rule_idx;
  (void)hit;
}

void edr_p0_rule_ir_stats_dump(void) {
}

void edr_p0_rule_ir_stats_init(void) {
}

void edr_p0_rule_ir_reload(void) {}

int edr_p0_bundle_dst_path(char *out, size_t cap) {
  (void)cap;
  if (out) out[0] = '\0';
  return -1;
}
