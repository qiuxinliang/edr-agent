#include "edr/etw_guids_win.h"
#include "edr/etw_tdh_win.h"
#include "edr/process_generation.h"
#include "edr/file_object_binding.h"
#include "edr/kernel_file_semantics.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

void edr_test_file_object_binding_contract(void);

static void number(BYTE *buffer, size_t *offset, uint64_t value, size_t bytes) {
  memcpy(buffer + *offset, &value, bytes);
  *offset += bytes;
}

static void test_file_schema(unsigned version, size_t pointer_bytes) {
  BYTE data[256] = {0};
  EVENT_RECORD record = {0};
  EdrSensorInterestEvent interest;
  uint64_t key = 0u;
  uint64_t extracted_object = 0u;
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
  assert(edr_tdh_kernel_file_extract_file_object(&record, &extracted_object));
  assert(extracted_object == object && extracted_object != key);
  const uint64_t writer_object = extracted_object;
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

  /* Existing-file Create carries FileObject/name, but no FileKey. It may
   * belong to another process that shares the handle with the actual writer. */
  record.EventHeader.EventDescriptor.Id = 12u;
  record.EventHeader.EventDescriptor.Task = 12u;
  record.EventHeader.EventDescriptor.Version = (BYTE)version;
  record.EventHeader.EventDescriptor.Keyword = 0xa0u;
  memset(data, 0, sizeof(data)); used = 0u;
  number(data, &used, 1u, pointer_bytes); /* Irp */
  if (version == 0u) number(data, &used, 7u, pointer_bytes);
  number(data, &used, object, pointer_bytes);
  if (version == 1u) number(data, &used, 7u, 4u);
  number(data, &used, 0u, 4u); /* CreateOptions */
  number(data, &used, 0u, 4u); /* CreateAttributes */
  number(data, &used, 3u, 4u); /* ShareAccess */
  memcpy(data + used, filename, sizeof(filename)); used += sizeof(filename);
  record.UserDataLength = (USHORT)used;
  assert(edr_tdh_kernel_file_extract_create_binding(&record, &extracted_object, path, sizeof(path)));
  assert(extracted_object == object && strcmp(path, "C:\\Fixture\\write-canary.txt") == 0);
  assert(edr_kernel_file_descriptor_is_create_new(30u, 30u, 0u, 1u, UINT64_C(0x1000)));
  assert(!edr_kernel_file_descriptor_is_create_new(12u, 12u, 0u, 1u, UINT64_C(0xa0)));
  assert(!edr_kernel_file_descriptor_is_create_new(30u, 12u, 0u, 1u, UINT64_C(0x1000)));
  assert(!edr_kernel_file_descriptor_is_create_new(30u, 30u, 1u, 1u, UINT64_C(0x1000)));
  assert(!edr_kernel_file_descriptor_is_create_new(30u, 30u, 0u, 2u, UINT64_C(0x1000)));
  assert(!edr_kernel_file_descriptor_is_create_new(30u, 30u, 0u, 1u, UINT64_C(0xa0)));
  /* A real overwrite emits 12 -> 30 -> 16. CreateNewFile has the same typed
   * layout but only the CREATE_NEW_FILE keyword; it is not another lifetime. */
  record.EventHeader.EventDescriptor.Id = 30u;
  record.EventHeader.EventDescriptor.Task = 30u;
  record.EventHeader.EventDescriptor.Keyword = 0x1000u;
  assert(edr_tdh_kernel_file_extract_create_binding(&record, &extracted_object, path, sizeof(path)));
  assert(extracted_object == object && strcmp(path, "C:\\Fixture\\write-canary.txt") == 0);
  record.EventHeader.EventDescriptor.Id = 12u;
  record.EventHeader.EventDescriptor.Task = 12u;
  record.EventHeader.EventDescriptor.Keyword = 0xa0u;
  EdrFileObjectBinding bindings[8] = {{0}};
  EdrFileObjectHistory history = {0};
  edr_file_object_binding_open(bindings, 8, &history, extracted_object, 100, path);
  assert(strcmp(edr_file_object_binding_resolve(bindings, 8, &history, writer_object, 150),
                "C:\\Fixture\\write-canary.txt") == 0);
  assert(!edr_file_object_binding_resolve(bindings, 8, &history, expected, 150));
  assert(!edr_tdh_kernel_file_extract_file_key(&record, &key));
  assert(!edr_tdh_kernel_file_extract_create_binding(&record, &extracted_object, path, 4u));
  /* Invalid names must still expose the typed object so the collector can
   * quarantine that object's new generation instead of keeping an old path. */
  assert(extracted_object == object);
  record.UserDataLength = 0u;
  assert(!edr_tdh_kernel_file_extract_create_binding(&record, &extracted_object, path, sizeof(path)));
  assert(extracted_object == 0u);

  for (unsigned event_id = 13u; event_id <= 14u; ++event_id) {
    record.EventHeader.EventDescriptor.Id = (USHORT)event_id;
    record.EventHeader.EventDescriptor.Task = (USHORT)event_id;
    record.EventHeader.EventDescriptor.Keyword = 0x20u;
    memset(data, 0, sizeof(data)); used = 0u;
    number(data, &used, 1u, pointer_bytes);
    if (version == 0u) number(data, &used, 7u, pointer_bytes);
    number(data, &used, object, pointer_bytes);
    number(data, &used, expected, pointer_bytes);
    if (version == 1u) number(data, &used, 7u, 4u);
    record.UserDataLength = (USHORT)used;
    assert(edr_tdh_kernel_file_extract_file_object(&record, &extracted_object));
    assert(extracted_object == object);
    edr_file_object_binding_close(bindings, 8, &history, extracted_object, 200 + event_id);
    assert(edr_file_object_binding_resolve(bindings, 8, &history, writer_object, 150));
    assert(!edr_file_object_binding_resolve(bindings, 8, &history, writer_object, 215));
  }
}

static void test_mutation_schema(unsigned version, size_t pointer_bytes) {
  for (unsigned id = 26u; id <= 27u; ++id) {
    BYTE data[512] = {0};
    EVENT_RECORD record = {0};
    const WCHAR filename[] = L"\\Device\\HarddiskVolume3\\Fixture\\canary.txt";
    char path[256];
    uint64_t key = 0u, object = 0u;
    size_t used = 0u;
    record.EventHeader.ProviderId = EDR_ETW_GUID_KERNEL_FILE;
    record.EventHeader.Flags = pointer_bytes == 8u ? EVENT_HEADER_FLAG_64_BIT_HEADER
                                                  : EVENT_HEADER_FLAG_32_BIT_HEADER;
    record.EventHeader.EventDescriptor.Id = (USHORT)id;
    record.EventHeader.EventDescriptor.Task = (USHORT)id;
    record.EventHeader.EventDescriptor.Version = (BYTE)version;
    record.EventHeader.EventDescriptor.Level = 4u;
    record.EventHeader.EventDescriptor.Keyword = id == 26u ? 0x400u : 0x800u;
    number(data, &used, 1u, pointer_bytes);
    if (version == 0u) number(data, &used, 7u, pointer_bytes);
    number(data, &used, 0x1234u, pointer_bytes);
    number(data, &used, 0x5678u, pointer_bytes);
    number(data, &used, 0u, pointer_bytes);
    if (version == 1u) number(data, &used, 7u, 4u);
    number(data, &used, 0u, 4u);
    memcpy(data + used, filename, sizeof(filename));
    used += sizeof(filename);
    record.UserData = data;
    record.UserDataLength = (USHORT)used;
    assert(edr_tdh_kernel_file_extract_mutation_path(&record, path, sizeof(path)));
    assert(strcmp(path, "\\Device\\HarddiskVolume3\\Fixture\\canary.txt") == 0);
    assert(edr_tdh_kernel_file_extract_file_key(&record, &key) && key == 0x5678u);
    assert(edr_tdh_kernel_file_extract_file_object(&record, &object) && object == 0x1234u);
    assert(!edr_tdh_kernel_file_extract_mutation_path(&record, path, 4u));
    record.EventHeader.EventDescriptor.Opcode = 1u;
    assert(!edr_tdh_kernel_file_extract_mutation_path(&record, path, sizeof(path)));
    record.EventHeader.EventDescriptor.Opcode = 0u;
    record.EventHeader.EventDescriptor.Version = 2u;
    assert(!edr_tdh_kernel_file_extract_mutation_path(&record, path, sizeof(path)));
    record.EventHeader.EventDescriptor.Version = (BYTE)version;
    record.UserDataLength = 0u;
    assert(!edr_tdh_kernel_file_extract_mutation_path(&record, path, sizeof(path)));
  }
}

static void test_actor_event_boundary(uint64_t creation) {
  const uint64_t epoch = 116444736000000000ULL;
  assert(creation > epoch && creation - epoch < UINT64_MAX / 100u);
  const uint64_t created_ns = (creation - epoch) * 100u;

  /* Anchor event fixtures to the verified creation time. A coarse wall-clock
   * sample can predate it on fast startup; clock adjustments can do so too. */
  assert(!edr_process_generation_contains_event(creation, created_ns - 1u));
  assert(edr_process_generation_contains_event(creation, created_ns));
  assert(edr_process_generation_contains_event(creation, created_ns + 1u));
  assert(edr_process_generation_contains_event(creation, created_ns + 100u));
  assert(!edr_process_generation_contains_event(creation + 1u, created_ns));
  assert(!edr_process_generation_contains_event(creation + 2u, created_ns + 100u));
  assert(!edr_process_generation_contains_event(creation, 0u));
  assert(!edr_process_generation_contains_event(0u, created_ns));
  assert(!edr_process_generation_contains_event(epoch, created_ns));
  assert(!edr_process_generation_contains_event(UINT64_MAX, created_ns));
}

static void test_actor_handle(void) {
  EdrLiveProcessGeneration generation;
  FILETIME created, exited, kernel, user;
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
  test_actor_event_boundary(creation);
}

int main(void) {
  for (unsigned version = 0u; version <= 1u; ++version) {
    test_file_schema(version, 4u);
    test_file_schema(version, 8u);
    test_mutation_schema(version, 4u);
    test_mutation_schema(version, 8u);
  }
  test_actor_handle();
  edr_test_file_object_binding_contract();
  puts("kernel_file_io_windows: v0/v1, 32/64-bit FileKey/FileObject, lifetimes and same-handle identity passed");
  return 0;
}
