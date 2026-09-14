#include "edr/behavior_from_slot.h"

#include <stdio.h>
#include <string.h>

/* Link seam required by behavior_from_slot's ransomware policy path. */
void edr_isolate_auto_from_ransom_alarm(const EdrBehaviorRecord *record) { (void)record; }

int main(void) {
  EdrEventSlot slot; EdrBehaviorRecord r;
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
