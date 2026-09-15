#include "edr/behavior_from_slot.h"

#include <stdio.h>
#include <string.h>

/* Link seam required by behavior_from_slot's ransomware policy path. */
void edr_isolate_auto_from_ransom_alarm(const EdrBehaviorRecord *record) { (void)record; }

static int test_etw1_high_truncation_bits(EdrBehaviorRecord *r) {
  const struct {
    const char *key;
    size_t capacity;
    const char *marker;
  } cases[] = {
    {"qname", EDR_BR_STR_MID, "source.dns_query"},
    {"source_truncated_fields", EDR_BR_SOURCE_TRUNCATED_FIELDS_LEN, "source.list_overflow"},
    {"command_line_origin", sizeof(r->command_line_origin), "source.command_line_origin"},
  };
  EdrEventSlot slot;
  char value[EDR_BR_STR_MID + 2u];
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
    /* A malformed over-capacity list must itself be reported as lost, not
     * discarded as if the producer supplied no loss metadata. */
    size_t first = strcmp(cases[i].key, "source_truncated_fields") == 0
                       ? cases[i].capacity : cases[i].capacity - 1u;
    for (size_t length = first; length <= cases[i].capacity + 1u; ++length) {
      memset(value, 'x', length);
      value[length] = '\0';
      memset(&slot, 0, sizeof(slot));
      slot.type = EDR_EVENT_NET_DNS_QUERY;
      slot.timestamp_ns = 1u;
      int n = snprintf((char *)slot.data, sizeof(slot.data),
          "ETW1\nprov=dns\npid=77\ncmd=actor.exe\n%s=%s\nsource_completeness=COMPLETE\n",
          cases[i].key, value);
      if (n <= 0 || (size_t)n >= sizeof(slot.data)) return 1;
      slot.size = (uint32_t)n + 1u;
      edr_behavior_from_slot(&slot, r);
      const char *expected = length < cases[i].capacity ? "" : cases[i].marker;
      if (strcmp(r->source_truncated_fields, expected) != 0 ||
          strcmp(r->source_completeness, expected[0] ? "TRUNCATED" : "COMPLETE") != 0) {
        fprintf(stderr, "ETW1 loss metadata key=%s length=%zu expected=%s actual=%s state=%s\n",
                cases[i].key, length, expected, r->source_truncated_fields, r->source_completeness);
        return 1;
      }
      if (strcmp(cases[i].key, "qname") == 0 &&
          strcmp(r->dns_query, expected[0] ? "" : value) != 0) return 1;
      if (strcmp(cases[i].key, "command_line_origin") == 0 &&
          strcmp(r->command_line_origin, expected[0] ? "" : value) != 0) return 1;
    }
  }

  /* Bits 31 and 33 must coexist without aliasing the list-overflow bit.
   * Compare membership and cardinality, not the order of the two markers. */
  memset(value, 'x', EDR_BR_STR_MID);
  value[EDR_BR_STR_MID] = '\0';
  memset(&slot, 0, sizeof(slot));
  slot.type = EDR_EVENT_NET_DNS_QUERY;
  slot.timestamp_ns = 1u;
  int n = snprintf((char *)slot.data, sizeof(slot.data),
      "ETW1\nprov=dns\npid=77\ncmd=actor.exe\nqname=%s\ncommand_line_origin=%s\n",
      value, value);
  if (n <= 0 || (size_t)n >= sizeof(slot.data)) return 1;
  slot.size = (uint32_t)n + 1u;
  edr_behavior_from_slot(&slot, r);
  const char *comma = strchr(r->source_truncated_fields, ',');
  if (!edr_behavior_source_field_truncated(r, "source.dns_query") ||
      !edr_behavior_source_field_truncated(r, "source.command_line_origin") ||
      edr_behavior_source_field_truncated(r, "source.list_overflow") ||
      !comma || strchr(comma + 1, ',') || r->dns_query[0] || r->command_line_origin[0]) {
    fprintf(stderr, "ETW1 combined loss bits mismatch: %s\n", r->source_truncated_fields);
    return 1;
  }
  return 0;
}

int main(void) {
  EdrEventSlot slot; EdrBehaviorRecord r;
  char precise[64], tiny[20];
  if (test_etw1_high_truncation_bits(&r) != 0) return 1;
  edr_behavior_format_time_ns(INT64_C(1789371253913980400), precise, sizeof(precise));
  if (strcmp(precise, "2026-09-14T07:34:13.913980400Z") != 0) return 1;
  edr_behavior_format_time_ns(INT64_C(1789371253913980400), tiny, sizeof(tiny));
  if (tiny[0]) return 1;
  edr_behavior_format_time_ns(0, precise, sizeof(precise));
  if (precise[0]) return 1;
  memset(&r, 0, sizeof(r));
  edr_behavior_mark_source_truncated(&r, "source.cmdline");
  edr_behavior_mark_source_truncated(&r, "source.cmdline");
  edr_behavior_mark_source_truncated(&r, "source.parent_path");
  if (strcmp(r.source_truncated_fields, "source.cmdline,source.parent_path") != 0 ||
      strcmp(r.source_completeness, "TRUNCATED") != 0 ||
      edr_behavior_source_field_truncated(&r, "source.cmd") ||
      !edr_behavior_source_field_truncated(&r, "source.parent_path")) return 1;
  snprintf(r.source_completeness, sizeof(r.source_completeness), "%s", "NOT_EVALUABLE");
  edr_behavior_mark_source_truncated(&r, "source.exe_path");
  if (strcmp(r.source_completeness, "NOT_EVALUABLE") != 0) return 1;
  memset(r.source_truncated_fields, 'x', sizeof(r.source_truncated_fields) - 1u);
  r.source_truncated_fields[sizeof(r.source_truncated_fields) - 1u] = '\0';
  edr_behavior_mark_source_truncated(&r, "source.cmdline");
  if (strcmp(r.source_truncated_fields, "source.list_overflow") != 0 ||
      !edr_behavior_source_field_truncated(&r, "source.exe_path")) return 1;
  memset(&r, 0, sizeof(r));
  const EdrEventType actors[] = { EDR_EVENT_PROCESS_CREATE, EDR_EVENT_FILE_READ,
      EDR_EVENT_NET_CONNECT, EDR_EVENT_NET_LISTEN };
  for (size_t i = 0u; i < sizeof(actors) / sizeof(actors[0]); i++) {
    r.type = actors[i];
    if (!edr_behavior_has_process_actor(&r)) return 1;
    r.is_security_4688 = 1u;
    if (edr_behavior_has_process_actor(&r)) return 1;
    r.is_security_4688 = 0u;
  }
  r.type = EDR_EVENT_CAPABILITY_AUDIT;
  if (edr_behavior_has_process_actor(&r)) return 1;
  r.type = EDR_EVENT_FILE_WRITE;
  r.kernel_file_activity = 1u;
  if (!edr_behavior_has_process_actor(&r) || edr_behavior_has_process_actor(NULL)) return 1;
  memset(&slot, 0, sizeof(slot)); slot.type = EDR_EVENT_PROCESS_CREATE; slot.timestamp_ns = 1u;
  snprintf((char *)slot.data, sizeof(slot.data),
           "ETW1\nprov=kproc\npid=77\nimg=C:\\Windows\\System32\\cmd.exe\n"
           "cmd=cmd.exe /c \"C:\\Temp\\payload.cmd\"\n");
  slot.size = (uint32_t)strlen((const char *)slot.data);
  edr_behavior_from_slot(&slot, &r);
  if (strcmp(r.process_name, "cmd.exe") != 0 ||
      strcmp(r.exe_path, "C:\\Windows\\System32\\cmd.exe") != 0 ||
      strcmp(r.file_path, "C:\\Temp\\payload.cmd") != 0) {
    fprintf(stderr, "cmd actor/artifact attribution failed: actor=%s path=%s artifact=%s\n",
            r.process_name, r.exe_path, r.file_path);
    return 1;
  }

  memset(&slot, 0, sizeof(slot));
  slot.type = EDR_EVENT_PROCESS_CREATE;
  slot.timestamp_ns = 2u;
  snprintf((char *)slot.data, sizeof(slot.data),
           "ETW1\nprov=sec\neid=4688\nepid=88\nppid=4\n"
           "img=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\n"
           "integrity=S-1-16-16384\ntoken_elevation=%%%%1936\n"
           "source_completeness=TRUNCATED\n"
           "source_truncated_fields=source.cmdline\ncmd=powershell.exe -EncodedCommand AAAA\n");
  slot.size = (uint32_t)strlen((const char *)slot.data);
  edr_behavior_from_slot(&slot, &r);
  if (!r.is_security_4688 || strcmp(r.source_completeness, "TRUNCATED") != 0 ||
      strcmp(r.source_truncated_fields, "source.cmdline") != 0 ||
      strcmp(r.integrity_level, "S-1-16-16384") != 0 || r.token_elevation != 1u) {
    fprintf(stderr,
            "4688 provenance mismatch: security=%u source=%s fields=%s integrity=%s elevation=%u\n",
            (unsigned)r.is_security_4688, r.source_completeness,
            r.source_truncated_fields, r.integrity_level, r.token_elevation);
    return 1;
  }
  return 0;
}
