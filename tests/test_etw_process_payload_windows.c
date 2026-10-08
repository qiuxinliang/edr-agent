#include "edr/etw_guids_win.h"
#include "edr/etw_tdh_win.h"
#include "edr/behavior_from_slot.h"

#include <tdh.h>
#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

/* Only the OS property lookup is replaced. UTF-16 conversion, production
 * payload building and delayed behavior normalization run unchanged. */
typedef struct { PCWSTR name; const void *data; ULONG bytes; } Property;
static Property s_properties[16];
static size_t s_count;
static PEVENT_RECORD s_record;

void edr_isolate_auto_from_ransom_alarm(const EdrBehaviorRecord *record) { (void)record; }

static Property *find_property(PCWSTR name) {
  for (size_t i = 0; i < s_count; ++i)
    if (wcscmp(name, s_properties[i].name) == 0) return &s_properties[i];
  return NULL;
}

static void add(PCWSTR name, const void *data, size_t bytes) {
  assert(s_count < sizeof(s_properties) / sizeof(s_properties[0]));
  assert(bytes <= ULONG_MAX);
  s_properties[s_count++] = (Property){name, data, (ULONG)bytes};
}

ULONG WINAPI edr_test_tdh_get_property_size(PEVENT_RECORD record, ULONG count,
    PTDH_CONTEXT context, ULONG property_count, PPROPERTY_DATA_DESCRIPTOR descriptors,
    PULONG size) {
  (void)count; (void)context;
  assert(record == s_record && property_count == 1u && descriptors && size);
  Property *p = find_property((PCWSTR)(ULONG_PTR)descriptors[0].PropertyName);
  if (!p) return ERROR_NOT_FOUND;
  *size = p->bytes;
  return ERROR_SUCCESS;
}

ULONG WINAPI edr_test_tdh_get_property(PEVENT_RECORD record, ULONG count,
    PTDH_CONTEXT context, ULONG property_count, PPROPERTY_DATA_DESCRIPTOR descriptors,
    ULONG bytes, PBYTE buffer) {
  (void)count; (void)context;
  assert(record == s_record && property_count == 1u && descriptors && buffer);
  Property *p = find_property((PCWSTR)(ULONG_PTR)descriptors[0].PropertyName);
  if (!p) return ERROR_NOT_FOUND;
  if (bytes < p->bytes) return ERROR_INSUFFICIENT_BUFFER;
  memcpy(buffer, p->data, p->bytes);
  return ERROR_SUCCESS;
}

static void test_payload(size_t command_chars, int duplicate_alias, WCHAR character,
                           int security_audit) {
  EVENT_RECORD event = {0};
  EdrEventSlot slot = {0};
  EdrBehaviorRecord record;
  WCHAR command[9001];
  const WCHAR image[] = L"C:\\Fixture\\child.exe";
  const WCHAR parent_image[] = L"C:\\Fixture\\parent.exe";
  const WCHAR cwd[] = L"C:\\Fixture";
  const uint32_t parent_pid = 4242u, actor_pid = 9001u, zero = 0u;
  const uint64_t key = 900u, creation = UINT64_C(134359259706010050);
  assert(command_chars < sizeof(command) / sizeof(command[0]));
  for (size_t i = 0u; i < command_chars; ++i) command[i] = character;
  command[command_chars] = L'\0';
  event.EventHeader.ProviderId = security_audit ? EDR_ETW_GUID_SECURITY_AUDIT
                                               : EDR_ETW_GUID_KERNEL_PROCESS;
  event.EventHeader.ProcessId = 4u; /* Logger is not the target process. */
  event.EventHeader.EventDescriptor.Id = security_audit ? 4688u : 1u;
  s_record = &event;
  s_count = 0u;
  add(security_audit ? L"CreatorProcessId" : L"ParentProcessId", &parent_pid, sizeof(parent_pid));
  add(security_audit ? L"NewProcessId" : L"ProcessId", &actor_pid, sizeof(actor_pid));
  if (duplicate_alias) {
    add(security_audit ? L"ParentProcessId" : L"ParentProcessID", &zero, sizeof(zero));
    add(security_audit ? L"ProcessId" : L"ProcessID", &zero, sizeof(zero));
  }
  add(L"ProcessStartKey", &key, sizeof(key));
  add(L"CreateTime", &creation, sizeof(creation));
  add(security_audit ? L"NewProcessName" : L"ImageFileName", image, sizeof(image));
  add(L"CommandLine", command, (command_chars + 1u) * sizeof(command[0]));
  add(L"ParentProcessName", parent_image, sizeof(parent_image));
  add(L"CurrentDirectory", cwd, sizeof(cwd));
  slot.type = EDR_EVENT_PROCESS_CREATE;
  slot.timestamp_ns = UINT64_C(1791454000000000000);
  slot.size = (uint32_t)edr_tdh_build_slot_payload(&event, security_audit ? "sec" : "kproc",
                                                   slot.data, sizeof(slot.data));
  assert(slot.size && slot.size <= sizeof(slot.data));
  edr_behavior_from_slot(&slot, &record);
  printf("{\"provider\":\"%s\",\"command_chars\":%zu,\"unicode\":%d,\"duplicate_alias\":%d,"
         "\"payload_bytes\":%u,\"pid\":%u,\"ppid\":%u,\"start_key\":%llu,"
         "\"command_bytes\":%zu,\"source_completeness\":\"%s\",\"truncated_fields\":\"%s\"}\n",
         security_audit ? "sec" : "kproc", command_chars, character != L'x', duplicate_alias, slot.size, record.pid,
         record.ppid, (unsigned long long)record.process_start_key, strlen(record.cmdline),
         record.source_completeness, record.source_truncated_fields);
  assert(record.pid == actor_pid && record.ppid == parent_pid);
  if (!security_audit)
    assert(record.process_start_key == key && record.process_creation_filetime_100ns == creation);
  else
    /* Security-Audit has no trusted target StartKey contract here. Identity
     * must not be invented from the logger's extended item or fixture text. */
    assert(record.process_start_key == 0u && record.process_creation_filetime_100ns == 0u);
  const char *parent = strstr((const char *)slot.data, "\nppid=");
  const char *actor = strstr((const char *)slot.data, "\nepid=");
  assert(parent && actor && !strstr(parent + 1, "\nppid=") && !strstr(actor + 1, "\nepid="));
  assert(strcmp(record.parent_path, "C:\\Fixture\\parent.exe") == 0);
  if (command_chars == 16u) {
    assert(strlen(record.cmdline) == command_chars && !record.source_truncated_fields[0]);
    const char *cmd = strstr((const char *)slot.data, "\ncmd=");
    assert(cmd && parent < cmd && actor < cmd);
  } else {
    assert(!record.cmdline[0]);
    assert(edr_behavior_source_field_truncated(&record, "source.cmdline"));
    assert(strcmp(record.source_completeness, "TRUNCATED") == 0);
    assert(!strstr((const char *)slot.data, "\ncmd="));
  }
  assert(edr_tdh_build_slot_payload(&event, security_audit ? "sec" : "kproc", slot.data, 32u) == 0u);
}

int main(void) {
  for (int security_audit = 0; security_audit <= 1; ++security_audit) {
    test_payload(16u, 0, L'x', security_audit);
    test_payload(4050u, 0, L'x', security_audit);
    test_payload(5000u, 0, L'x', security_audit);
    test_payload(16u, 1, L'x', security_audit);
    test_payload(9000u, 0, L'x', security_audit);
    test_payload(4050u, 0, L'\x4e2d', security_audit);
  }
  return 0;
}
