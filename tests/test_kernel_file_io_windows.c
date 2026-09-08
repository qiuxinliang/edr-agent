#include "edr/etw_guids_win.h"
#include "edr/etw_tdh_win.h"
#include "edr/process_generation.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void number(BYTE *buffer, size_t *offset, uint64_t value, size_t bytes) {
  memcpy(buffer + *offset, &value, bytes);
  *offset += bytes;
}

static void test_file_schema(unsigned version, size_t pointer_bytes) {
  BYTE data[256] = {0};
  EVENT_RECORD record = {0};
  EdrSensorInterestEvent interest;
  uint64_t key = 0u;
  const uint64_t expected = pointer_bytes == 8u ? 0xffffba876f41a180ULL : 0x6f41a180u;
  const uint64_t object = pointer_bytes == 8u ? 0xffff848901b137c0ULL : 0x01b137c0u;
  size_t used = 0u;
  char path[256];
  BYTE payload[4096];
  const WCHAR filename[] = L"C:\\Fixture\\write-canary.txt";
  record.EventHeader.ProviderId = EDR_ETW_GUID_KERNEL_FILE;
  record.EventHeader.Flags = pointer_bytes == 8u ? EVENT_HEADER_FLAG_64_BIT_HEADER
                                                 : EVENT_HEADER_FLAG_32_BIT_HEADER;
  record.EventHeader.ProcessId = 9416u;
  record.EventHeader.EventDescriptor.Id = 16u;
  record.EventHeader.EventDescriptor.Task = 16u;
  record.EventHeader.EventDescriptor.Version = (BYTE)version;
  record.EventHeader.EventDescriptor.Keyword = 0x220u;
  record.EventHeader.EventDescriptor.Level = 4u;
  /* Actual Kernel-File Write v0/v1 manifest order, not C struct alignment. */
  number(data, &used, 0u, 8u);       /* ByteOffset */
  number(data, &used, 1u, pointer_bytes); /* Irp */
  if (version == 0u) number(data, &used, 7u, pointer_bytes); /* ThreadId */
  number(data, &used, object, pointer_bytes);
  number(data, &used, expected, pointer_bytes);
  if (version == 1u) number(data, &used, 7u, 4u); /* IssuingThreadId */
  number(data, &used, 512u, 4u);     /* IOSize */
  number(data, &used, 0u, 4u);       /* IOFlags */
  if (version == 1u) number(data, &used, 0u, 4u); /* ExtraFlags */
  record.UserData = data;
  record.UserDataLength = (USHORT)used;
  assert(edr_tdh_kernel_file_extract_file_key(&record, &key));
  assert(key == expected && key != object);
  assert(edr_tdh_build_sensor_interest_event(&record, EDR_EVENT_FILE_WRITE, "kfile", &interest));
  assert(interest.pid == 9416u && interest.path[0] == '\0');
  /* A Write has no generic text properties. Its zero result is why the
   * collector must use the compact FileKey-bound payload builder. */
  assert(edr_tdh_build_slot_payload(&record, "kfile", payload, sizeof(payload)) == 0u);
  assert(payload[0] == '\0');

  /* NameCreate belongs to another actor. Only its FileKey/name is shared. */
  record.EventHeader.ProcessId = 2048u;
  record.EventHeader.EventDescriptor.Id = 10u;
  record.EventHeader.EventDescriptor.Task = 10u;
  record.EventHeader.EventDescriptor.Version = 0u;
  record.EventHeader.EventDescriptor.Keyword = 0x10u;
  memset(data, 0, sizeof(data));
  used = 0u;
  number(data, &used, expected, pointer_bytes);
  memcpy(data + used, filename, sizeof(filename));
  used += sizeof(filename);
  record.UserDataLength = (USHORT)used;
  assert(edr_tdh_kernel_file_extract_name_binding(&record, &key, path, sizeof(path)));
  assert(key == expected && strcmp(path, "C:\\Fixture\\write-canary.txt") == 0);
  assert(!edr_tdh_kernel_file_extract_name_binding(&record, &key, path, 4u));
  memset(data, 0, pointer_bytes);
  assert(!edr_tdh_kernel_file_extract_file_key(&record, &key) && key == 0u);
}

static void test_actor_handle(void) {
  EdrLiveProcessGeneration generation;
  FILETIME created, exited, kernel, user, now;
  char reason[64];
  uint64_t verified_creation = 0u;
  assert(edr_process_generation_query_live(GetCurrentProcess(), &generation, reason, sizeof(reason)));
  assert(generation.pid == GetCurrentProcessId() && generation.process_start_key != 0u);
  assert(GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user));
  uint64_t creation = ((uint64_t)created.dwHighDateTime << 32u) | created.dwLowDateTime;
  assert(creation == generation.creation_filetime_100ns);
  assert(edr_process_generation_validate_live(GetCurrentProcess(), generation.pid,
      generation.process_start_key, &verified_creation, reason, sizeof(reason)));
  assert(verified_creation == creation);
  assert(!edr_process_generation_validate_live(GetCurrentProcess(), generation.pid,
      generation.process_start_key + 1u, &verified_creation, reason, sizeof(reason)));
  GetSystemTimeAsFileTime(&now);
  uint64_t now_value = ((uint64_t)now.dwHighDateTime << 32u) | now.dwLowDateTime;
  uint64_t event_ns = (now_value - 116444736000000000ULL) * 100u;
  assert(edr_process_generation_contains_event(creation, event_ns));
  assert(!edr_process_generation_contains_event(now_value + 1u, event_ns));
}

int main(void) {
  for (unsigned version = 0u; version <= 1u; ++version) {
    test_file_schema(version, 4u);
    test_file_schema(version, 8u);
  }
  test_actor_handle();
  puts("kernel_file_io_windows: v0/v1, 32/64-bit FileKey and same-handle identity passed");
  return 0;
}
