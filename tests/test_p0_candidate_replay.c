/* Matcher-only replay. Arguments are data, never executed as commands. */
#include "edr/behavior_record.h"
#include "edr/p0_rule_ir.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int copy_field(char *dst, size_t cap, const char *src) {
  if (strlen(src) >= cap) return 0;
  memcpy(dst, src, strlen(src) + 1u);
  return 1;
}

int main(int argc, char **argv) {
  EdrBehaviorRecord record;
  const char *id = NULL;
  int index = -1;
  if (argc != 8 && argc != 12) {
    fprintf(stderr, "usage: replay RULE EVENT PROCESS PARENT COMMAND FILE IMAGE [PORT REG_PATH REG_NAME REG_DATA]\n");
    return 2;
  }
  edr_behavior_record_init(&record);
  if (strcmp(argv[2], "process_create") == 0) record.type = EDR_EVENT_PROCESS_CREATE;
  else if (strcmp(argv[2], "file_read") == 0) record.type = EDR_EVENT_FILE_READ;
  else if (strcmp(argv[2], "file_write") == 0) record.type = EDR_EVENT_FILE_WRITE;
  else if (argc == 12 && strcmp(argv[2], "registry_set") == 0) record.type = EDR_EVENT_REG_SET_VALUE;
  else if (argc == 12 && strcmp(argv[2], "network_connect") == 0) record.type = EDR_EVENT_NET_CONNECT;
  else { fprintf(stderr, "unsupported replay event\n"); return 2; }
  if (!copy_field(record.process_name, sizeof(record.process_name), argv[3]) ||
      !copy_field(record.parent_name, sizeof(record.parent_name), argv[4]) ||
      !copy_field(record.cmdline, sizeof(record.cmdline), argv[5]) ||
      !copy_field(record.file_path, sizeof(record.file_path),
                  record.type == EDR_EVENT_PROCESS_CREATE && argv[7][0] ? argv[7] : argv[6])) {
    fprintf(stderr, "replay field exceeds actual Agent capacity\n"); return 2;
  }
  if (argc == 12) {
    char *end = NULL;
    unsigned long port = strtoul(argv[8], &end, 10);
    if (!argv[8][0] || *end || port > 65535u ||
        !copy_field(record.reg_key_path, sizeof(record.reg_key_path), argv[9]) ||
        !copy_field(record.reg_value_name, sizeof(record.reg_value_name), argv[10]) ||
        !copy_field(record.reg_value_data, sizeof(record.reg_value_data), argv[11])) {
      fprintf(stderr, "invalid port or registry field exceeds actual Agent capacity\n"); return 2;
    }
    record.net_dport = (uint32_t)port;
  }
  edr_p0_rule_ir_lazy_init();
  if (!edr_p0_rule_ir_is_ready()) {
    fprintf(stderr, "real PCRE2 IR unavailable\n"); return 2;
  }
  for (int i = 0; i < edr_p0_rule_ir_rule_count(); ++i) {
    if (edr_p0_rule_ir_rule_id_at(i, &id) && id && strcmp(id, argv[1]) == 0) { index = i; break; }
  }
  if (index < 0) { fprintf(stderr, "rule absent from loaded IR\n"); return 2; }
  printf("%d\n", edr_p0_rule_ir_br_matches_index(&record, index) ? 1 : 0);
  edr_p0_rule_ir_shutdown();
  return 0;
}
