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
  return 0;
}
