/* Exercise the actual audit/eBPF text boundary without starting collectors or
 * attaching probes. Link-time section GC removes unrelated lifecycle I/O. */
#include "../src/collector/collector_linux.c"
#include "edr/behavior_from_slot.h"
#include "edr/detection_decision.h"
#include "cJSON.h"

#include <assert.h>

static EdrEventSlot captured;
static unsigned captured_count;
struct EdrEventBus { int unused; };

bool edr_event_bus_try_push(EdrEventBus *bus, const EdrEventSlot *slot) {
  assert(bus == s_bus);
  captured = *slot;
  captured_count++;
  return true;
}

void edr_isolate_auto_from_ransom_alarm(const EdrBehaviorRecord *record) { (void)record; }

static void check_event(const char *line, int ebpf, const char *name, int known,
                         int success, int64_t result, uint32_t target) {
  unsigned before = captured_count;
  if (ebpf) push_ebpf_trace_event(line);
  else push_audit_event(line);
  assert(captured_count == before + 1u);
  EdrBehaviorRecord record;
  EdrDetectionDecision decision;
  edr_behavior_from_slot(&captured, &record);
  assert(record.pid == 501u);
  assert(record.syscall_target_pid == target);
  assert(strcmp(record.syscall_name, name) == 0);
  assert(record.syscall_result_known == known);
  assert(record.syscall_success_known == known);
  if (known) {
    assert(record.syscall_result == result);
    assert(record.syscall_success == success);
  }
  assert(record.process_start_key == 0u); /* Source supplied no generation. */
  edr_detection_decision_evaluate(&record, &decision);
  int injection = strcmp(name, "process_vm_writev") == 0 && known && success && result > 0;
  assert(edr_behavior_is_injection_evidence(&record) == injection);
  assert((strstr(decision.reason, "process_injection_signal") != NULL) == injection);
  cJSON *context = cJSON_Parse(record.detection_context);
  assert(context);
  cJSON *event_type = cJSON_GetObjectItemCaseSensitive(context, "event_type");
  assert(cJSON_IsString(event_type) && strcmp(event_type->valuestring, "process_inject") == 0);
  cJSON *syscall = cJSON_GetObjectItemCaseSensitive(
      cJSON_GetObjectItemCaseSensitive(context, "engine_evidence"), "linux_syscall");
  assert(cJSON_IsObject(syscall));
  cJSON *outcome = cJSON_GetObjectItemCaseSensitive(syscall, "success");
  cJSON *returned = cJSON_GetObjectItemCaseSensitive(syscall, "result");
  if (known) {
    char expected[32];
    snprintf(expected, sizeof(expected), "%" PRId64, result);
    assert(cJSON_IsBool(outcome) && cJSON_IsTrue(outcome) == success);
    assert(cJSON_IsString(returned) && strcmp(expected, returned->valuestring) == 0);
  } else {
    assert(!outcome && !returned);
  }
  if (captured_count == 1u) {
    cJSON *payload = cJSON_CreateObject();
    cJSON *dc = cJSON_AddObjectToObject(payload, "detection_context");
    cJSON *engine = cJSON_AddObjectToObject(dc, "engine_evidence");
    cJSON_AddItemToObject(dc, "event_type", cJSON_Duplicate(event_type, 1));
    cJSON_AddItemToObject(engine, "linux_syscall", cJSON_Duplicate(syscall, 1));
    char *text = cJSON_PrintUnformatted(payload);
    assert(text);
    printf("collector consumer fixture: %s\n", text);
    free(text);
    cJSON_Delete(payload);
  }
  cJSON_Delete(context);
}

int main(void) {
  EdrEventBus bus;
  memset(&bus, 0, sizeof(bus));
  s_bus = &bus;
  check_event("type=SYSCALL arch=c000003e syscall=311 success=yes exit=4294967297 "
              "a0=309 ppid=900 pid=501 uid=42 auid=1000 comm=\"fixture\" exe=\"/usr/bin/fixture\"",
              0, "process_vm_writev", 1, 1, INT64_C(4294967297), 777);
  check_event("type=SYSCALL arch=c00000b7 syscall=271 success=no exit=-13 "
              "a0=309 ppid=900 pid=501 comm=\"fixture\"", 0, "process_vm_writev", 1, 0, -13, 777);
  check_event("type=SYSCALL arch=c000003e syscall=319 success=yes exit=0 pid=501",
              0, "memfd_create", 1, 1, 0, 0);
  check_event("type=SYSCALL syscall=process_vm_writev a0=309 pid=501 "
              "comm=\"ignored success=yes exit=42 pid=999\"", 0, "process_vm_writev", 0, 0, 0, 777);
  check_event("type=SYSCALL syscall=memfd_create pid=501 exit=9223372036854775808",
              0, "memfd_create", 0, 0, 0, 0);
  check_event("edr syscall=process_vm_writev target_pid=777 pid=501 exit=4096 comm_hex=\"66 69 78 74 75 72 65 00\"",
              1, "process_vm_writev", 1, 1, 4096, 777);
  check_event("edr syscall=process_vm_writev pid=501 exit=-1 target_pid=777",
              1, "process_vm_writev", 1, 0, -1, 777);
  check_event("edr syscall=process_vm_writev pid=501 target_pid=777", 1, "process_vm_writev", 0, 0, 0, 777);
  check_event("edr syscall=memfd_create pid=501 exit=0 name_hex=\"66 64 0a 73 79 73 63 61 6c 6c 5f 73 75 63 63 65 73 73 3d 74 72 75 65\"",
              1, "memfd_create", 1, 1, 0, 0);
  assert(strstr((char *)captured.data, "memfd_name=fd_syscall_success=true\n"));
  check_event("edr syscall=memfd_create pid=501 ret=27 comm=\"connect process_vm_writev\"",
              1, "memfd_create", 1, 1, 27, 0);
  unsigned before = captured_count;
  push_ebpf_trace_event("edr comm=\"process_vm_writev\" pid=501");
  assert(captured_count == before);
  puts("linux_syscall_evidence ok");
  return 0;
}
