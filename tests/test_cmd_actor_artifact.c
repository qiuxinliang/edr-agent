#include "edr/behavior_from_slot.h"

#include <stdio.h>
#include <string.h>

/* Link seam required by behavior_from_slot's ransomware policy path. */
void edr_isolate_auto_from_ransom_alarm(const EdrBehaviorRecord *record) { (void)record; }

int main(void) {
  EdrEventSlot slot; EdrBehaviorRecord r;
  char precise[64], tiny[20];
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
