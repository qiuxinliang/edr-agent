#include "collector_file_io_test.h"
#include "edr/behavior_from_slot.h"
#include "edr/etw_guids_win.h"
#include "edr/etw_tdh_win.h"
#include "edr/file_object_binding.h"
#include "edr/p0_source_only_contract.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

/* Capture the actual publication boundary; no resolver or slot logic lives
 * in this sink. Metadata and rejected Reads must never reach it. */
struct EdrEventBus {
  unsigned published;
  EdrEventSlot last;
};
static struct EdrEventBus bus;
static size_t binding_space = SIZE_MAX;
static const char *case_name = "initialization";
static unsigned case_version;
static size_t case_width;
static const uint32_t reader_pid = 7211u;
static const uint32_t opener_pid = 2048u;
static const WCHAR old_name[] = L"C:\\Fixture\\existing.txt";
static const WCHAR new_name[] = L"C:\\Fixture\\reused.txt";
static const char old_path[] = "C:\\Fixture\\existing.txt";
static const char new_path[] = "C:\\Fixture\\reused.txt";

bool edr_event_bus_try_push(EdrEventBus *target, const EdrEventSlot *slot) {
  assert(target == &bus && slot && slot->type == EDR_EVENT_FILE_READ);
  assert(slot->size && slot->size <= sizeof(slot->data));
  bus.last = *slot;
  ++bus.published;
  return true;
}

void edr_collector_file_io_test_before_binding(EdrEventSlot *slot) {
  if (binding_space == SIZE_MAX) return;
  assert(slot->type == EDR_EVENT_FILE_READ);
  size_t used = strlen((const char *)slot->data);
  size_t target = sizeof(slot->data) - 1u - binding_space;
  assert(target > used + 10u && target < sizeof(slot->data));
  /* A valid, otherwise ignored ETW1 line consumes the requested space. The
   * production appender, not this hook, decides whether each field fits. */
  memcpy(slot->data + used, "padding=", 8u);
  memset(slot->data + used + 8u, 'x', target - used - 8u);
  slot->data[target - 1u] = '\n';
  slot->data[target] = '\0';
  slot->size = (uint32_t)(target + 1u);
}

typedef struct {
  EVENT_RECORD record;
  BYTE data[8192];
} Fixture;

static void number(Fixture *f, size_t *used, uint64_t value, size_t bytes) {
  assert(*used + bytes <= sizeof(f->data));
  memcpy(f->data + *used, &value, bytes);
  *used += bytes;
}

/* Real manifest layouts, also exercised by test_kernel_file_io_windows.
 * TDH performs the property extraction; fixtures never supply resolved paths
 * to the collector or substitute FileObject for FileKey. */
static void make_event(Fixture *f, unsigned id, unsigned version, size_t width,
                       uint64_t object, uint64_t key, const WCHAR *name) {
  size_t used = 0u;
  memset(f, 0, sizeof(*f));
  f->record.EventHeader.ProviderId = EDR_ETW_GUID_KERNEL_FILE;
  f->record.EventHeader.Flags = width == 8u ? EVENT_HEADER_FLAG_64_BIT_HEADER
                                           : EVENT_HEADER_FLAG_32_BIT_HEADER;
  f->record.EventHeader.ProcessId = id == 15u ? reader_pid : opener_pid;
  f->record.EventHeader.EventDescriptor.Id = (USHORT)id;
  f->record.EventHeader.EventDescriptor.Task = (USHORT)id;
  f->record.EventHeader.EventDescriptor.Version = (BYTE)(id <= 11u ? 0u : version);
  f->record.EventHeader.EventDescriptor.Level = 4u;
  f->record.EventHeader.EventDescriptor.Keyword = id <= 11u ? 0x10u
      : id == 12u ? 0xa0u : id == 15u ? 0x120u : 0x20u;
  if (id <= 11u) {
    number(f, &used, key, width);
  } else {
    if (id == 15u) number(f, &used, 0u, 8u); /* ByteOffset */
    number(f, &used, 1u, width); /* Irp */
    if (version == 0u) number(f, &used, 7u, width); /* ThreadId */
    number(f, &used, object, width);
    if (id != 12u) number(f, &used, key, width);
    if (version == 1u) number(f, &used, 7u, 4u); /* IssuingThreadId */
    if (id == 12u) {
      number(f, &used, 0u, 4u); /* CreateOptions */
      number(f, &used, 0u, 4u); /* CreateAttributes */
      number(f, &used, 3u, 4u); /* ShareAccess */
    } else if (id == 15u) {
      number(f, &used, 512u, 4u); /* IOSize */
      number(f, &used, 0u, 4u); /* IOFlags */
      if (version == 1u) number(f, &used, 0u, 4u); /* ExtraFlags */
    }
  }
  if (name) {
    size_t bytes = (wcslen(name) + 1u) * sizeof(WCHAR);
    assert(used + bytes <= sizeof(f->data));
    memcpy(f->data + used, name, bytes);
    used += bytes;
  }
  f->record.UserData = f->data;
  f->record.UserDataLength = (USHORT)used;
}

static void begin_case(const char *name) {
  case_name = name;
  fprintf(stderr, "[fixture] CASE %s version=%u width=%zu collector_pid=%lu\n",
          case_name, case_version, case_width * 8u, (unsigned long)GetCurrentProcessId());
}

static void reset(const char *name) {
  memset(&bus, 0, sizeof(bus));
  binding_space = SIZE_MAX;
  edr_collector_file_io_test_reset(&bus);
  begin_case(name);
}

static void diagnose(void) {
  EdrCollectorHealth health;
  EdrEventSlot pending;
  EdrBehaviorRecord record;
  edr_collector_file_io_test_health(&health);
  fprintf(stderr,
          "[fixture] health published=%u dropped=%llu metadata_dropped=%llu queue_dropped=%llu "
          "self_interest=%llu self_record=%llu name_bindings=%llu name_misses=%llu "
          "key_ambiguities=%llu gate_staged=%llu gate_paused=%llu gate_durable_failures=%llu "
          "capability_healthy=%d capability_reason=%s\n",
          bus.published, (unsigned long long)health.collector_dropped,
          (unsigned long long)health.metadata_dropped, (unsigned long long)health.queue_dropped,
          (unsigned long long)health.agent_self_interest_suppressed,
          (unsigned long long)health.agent_self_record_suppressed,
          (unsigned long long)health.file_read_name_bindings,
          (unsigned long long)health.file_read_name_cache_misses,
          (unsigned long long)health.file_read_file_key_ambiguities,
          (unsigned long long)health.file_read_metadata_gate_staged,
          (unsigned long long)health.file_read_metadata_gate_paused_events,
          (unsigned long long)health.file_read_metadata_gate_durable_failures,
          health.file_read_p0_capability_healthy, health.file_read_p0_capability_reason);
  if (edr_collector_file_io_test_pending(&pending)) {
    edr_behavior_from_slot(&pending, &record);
    fprintf(stderr, "[fixture] pending reason=%s completeness=%s pid=%u at=%lld key=0x%llx path=%s\n",
            record.collector_evidence_reason, record.source_completeness, record.pid,
            (long long)record.event_time_ns, (unsigned long long)record.file_key, record.file_path);
  } else {
    fprintf(stderr, "[fixture] pending=none\n");
  }
}

static void diagnose_tdh_after_failure(Fixture *f, uint64_t at) {
  uint64_t object = 0u, key = 0u;
  char path[EDR_BR_STR_LONG] = {0};
  unsigned id = f->record.EventHeader.EventDescriptor.Id;
  int object_ok = id >= 12u && edr_tdh_kernel_file_extract_file_object(&f->record, &object);
  int key_ok = id != 12u && edr_tdh_kernel_file_extract_file_key(&f->record, &key);
  int path_ok = id == 12u
      ? edr_tdh_kernel_file_extract_create_binding(&f->record, &object, path, sizeof(path))
      : id == 10u && edr_tdh_kernel_file_extract_name_binding(&f->record, &key, path, sizeof(path));
  diagnose();
  /* Only reached after the expected publication/gate outcome has already
   * failed. Never prewarm TDH on the production feed or on successful cases;
   * these probes cannot change the outcome checked by the following assert. */
  fprintf(stderr,
          "[fixture] POST-FAILURE TDH case=%s version=%u width=%zu id=%u pid=%lu at=%llu bytes=%u "
          "tdh_object_ok=%d object=0x%llx tdh_key_ok=%d key=0x%llx path_ok=%d path_bytes=%zu\n",
          case_name, case_version, case_width * 8u, id,
          (unsigned long)f->record.EventHeader.ProcessId, (unsigned long long)at,
          (unsigned)f->record.UserDataLength, object_ok, (unsigned long long)object,
          key_ok, (unsigned long long)key, path_ok, strlen(path));
  if (id == 15u) {
    EdrSensorInterestEvent interest;
    int ok = edr_tdh_build_sensor_interest_event(&f->record, EDR_EVENT_FILE_READ, "kfile", &interest);
    fprintf(stderr, "[fixture] POST-FAILURE raw_interest ok=%d pid=%u parent_pid=%u path_bytes=%zu\n",
            ok, ok ? interest.pid : 0u, ok ? interest.parent_pid : 0u,
            ok ? strlen(interest.path) : 0u);
  }
}

static void feed(Fixture *f, uint64_t at) {
  edr_collector_file_io_test_feed(&f->record, at);
}

static void expect_read(Fixture *read, uint64_t at, const char *path,
                         uint64_t key, uint64_t object, const char *quality) {
  unsigned before = bus.published;
  EdrBehaviorRecord record;
  char object_kv[80];
  feed(read, at);
  if (bus.published != before + 1u) diagnose_tdh_after_failure(read, at);
  assert(bus.published == before + 1u);
  edr_behavior_from_slot(&bus.last, &record);
  assert(record.type == EDR_EVENT_FILE_READ && strcmp(record.file_op, "read") == 0);
  assert(record.pid == reader_pid && record.pid != opener_pid);
  assert(record.event_time_ns == (int64_t)at);
  assert(strcmp(record.file_path, path) == 0 && record.file_key == key);
  assert(record.process_start_key == 0u && record.process_creation_filetime_100ns == 0u);
  assert(!record.file_actor_generation_validated);
  assert(!record.collector_evidence_gate[0]);
  assert(strstr(record.script_snippet, quality));
  snprintf(object_kv, sizeof(object_kv), "file_read_file_object=0x%llx",
           (unsigned long long)object);
  assert(strstr(record.script_snippet, object_kv));
}

static void expect_rejected(Fixture *read, uint64_t at, const char *reason) {
  unsigned before = bus.published;
  EdrEventSlot pending;
  EdrBehaviorRecord record;
  feed(read, at);
  if (bus.published != before || !edr_collector_file_io_test_pending(&pending))
    diagnose_tdh_after_failure(read, at);
  assert(bus.published == before);
  assert(edr_collector_file_io_test_pending(&pending));
  edr_behavior_from_slot(&pending, &record);
  assert(strcmp(record.source_completeness, "NOT_EVALUABLE") == 0);
  assert(strcmp(record.collector_evidence_gate, EDR_P0_FILE_READ_METADATA_GATE) == 0);
  assert(strcmp(record.collector_evidence_reason, reason) == 0);
  assert(record.pid == reader_pid && record.event_time_ns == (int64_t)at);
  assert(pending.p0_critical && pending.type == EDR_EVENT_FILE_READ);
}

static void test_sequence(unsigned version, size_t width) {
  case_version = version;
  case_width = width;
  const uint64_t object = width == 8u ? UINT64_C(0xffff848901b137c0) : 0x01b137c0u;
  const uint64_t key = width == 8u ? UINT64_C(0xffffba876f41a180) : 0x6f41a180u;
  Fixture create, read, close, name;
  make_event(&create, 12u, version, width, object, 0u, old_name);
  make_event(&read, 15u, version, width, object, key, NULL);
  make_event(&close, 14u, version, width, object, key, NULL);

  /* Fill the production 4096-slot object cache using real typed metadata.
   * Evict a different object's Close after the target's earlier Create;
   * the complete target Read must still cross the publication boundary. */
  reset("unrelated_object_eviction_preserves_read");
  Fixture pressure;
  make_event(&pressure, 14u, version, width, object + 1u, key + 1u, NULL);
  feed(&pressure, 400u);
  feed(&create, 200u);
  for (unsigned i = 2u; i < 4096u; ++i) {
    make_event(&pressure, 12u, version, width, object + i, 0u, new_name);
    feed(&pressure, 500u + i);
  }
  make_event(&pressure, 12u, version, width, object + 5000u, 0u, new_name);
  feed(&pressure, 9000u);
  expect_read(&read, 10000u, old_path, key, object,
              "file_read_binding_quality=etw_fileobject_create");
  begin_case("unidentified_boundary_still_rejects_read");
  make_event(&pressure, 14u, version, width, 0u, 0u, NULL);
  feed(&pressure, 11000u);
  expect_rejected(&read, 11500u, EDR_P0_FILE_READ_REASON_CANONICAL_PATH_UNRESOLVED);

  reset("no_namecreate_read");
  feed(&create, 100u);
  assert(!bus.published); /* Open metadata is not a Read. */
  expect_read(&read, 150u, old_path, key, object,
              "file_read_binding_quality=etw_fileobject_create");
  feed(&close, 200u);
  begin_case("delayed_read_before_close");
  /* Decode after Close uses event time, and cannot cross the close boundary. */
  expect_read(&read, 150u, old_path, key, object,
              "file_read_binding_quality=etw_fileobject_create");
  begin_case("read_at_close_rejected");
  expect_rejected(&read, 200u, EDR_P0_FILE_READ_REASON_CANONICAL_PATH_UNRESOLVED);
  begin_case("reuse_delayed_duplicate_close");
  make_event(&create, 12u, version, width, object, 0u, new_name);
  feed(&create, 300u);
  feed(&close, 200u); /* Delayed duplicate Close must not close the reuse. */
  expect_read(&read, 150u, old_path, key, object,
              "file_read_binding_quality=etw_fileobject_create");
  begin_case("read_reused_object");
  expect_read(&read, 350u, new_path, key, object,
              "file_read_binding_quality=etw_fileobject_create");

  /* Close can arrive before Create; the retained boundary still applies. */
  reset("close_delivered_before_create");
  feed(&close, 400u);
  feed(&create, 300u);
  expect_read(&read, 350u, new_path, key, object,
              "file_read_binding_quality=etw_fileobject_create");
  begin_case("read_after_close_rejected");
  expect_rejected(&read, 401u, EDR_P0_FILE_READ_REASON_CANONICAL_PATH_UNRESOLVED);

  /* A live conflicting FileKey must block the otherwise usable object. */
  reset("live_key_object_conflict");
  make_event(&name, 10u, version, width, 0u, key, old_name);
  feed(&name, 100u);
  feed(&create, 110u);
  expect_rejected(&read, 150u, EDR_P0_FILE_READ_REASON_CANONICAL_PATH_UNRESOLVED);
  /* The conflict has no authoritative path; staging normalizes the reason
   * to the contract's nullable-path reason. No guessed path is published. */

  reset("live_key_object_agreement");
  make_event(&create, 12u, version, width, object, 0u, old_name);
  feed(&name, 100u);
  feed(&create, 110u);
  expect_read(&read, 150u, old_path, key, object,
              "file_read_binding_quality=etw_filekey_namecreate");

  /* A closed key cannot shadow a fresh, independently timed object. */
  reset("expired_key_fresh_object");
  feed(&name, 100u);
  make_event(&name, 11u, version, width, 0u, key, NULL);
  feed(&name, 200u);
  make_event(&create, 12u, version, width, object, 0u, new_name);
  feed(&create, 300u);
  expect_read(&read, 350u, new_path, key, object,
              "file_read_binding_quality=etw_fileobject_create");

  /* Same-time conflicting Create stays quarantined after an exact duplicate. */
  reset("same_time_create_conflict");
  feed(&create, 100u);
  make_event(&create, 12u, version, width, object, 0u, old_name);
  feed(&create, 100u);
  make_event(&create, 12u, version, width, object, 0u, new_name);
  feed(&create, 100u);
  expect_rejected(&read, 150u, EDR_P0_FILE_READ_REASON_CANONICAL_PATH_UNRESOLVED);

  /* Both name and object history must be cleared at the real reset seam. */
  reset("epoch_reset_clears_both_caches");
  make_event(&name, 10u, version, width, 0u, key, new_name);
  feed(&name, 100u);
  feed(&create, 110u);
  uint64_t epoch = edr_collector_file_io_test_new_epoch();
  assert(edr_collector_file_io_test_new_epoch() != epoch);
  expect_rejected(&read, 150u, EDR_P0_FILE_READ_REASON_CANONICAL_PATH_UNRESOLVED);
  begin_case("new_epoch_create_read");
  feed(&create, 300u);
  expect_read(&read, 350u, new_path, key, object,
              "file_read_binding_quality=etw_fileobject_create");

  /* Missing typed key/object, zero PID, and overlong Create cannot recover. */
  for (unsigned invalid = 0u; invalid < 4u; ++invalid) {
    static const char *const invalid_cases[] = {
      "missing_key", "missing_object", "zero_pid", "overlong_create_path"
    };
    WCHAR long_name[EDR_FILE_OBJECT_PATH_CAP + 1u];
    reset(invalid_cases[invalid]);
    for (size_t i = 0u; i < EDR_FILE_OBJECT_PATH_CAP; ++i) long_name[i] = L'x';
    long_name[EDR_FILE_OBJECT_PATH_CAP] = L'\0';
    make_event(&create, 12u, version, width, object, 0u,
                invalid == 3u ? long_name : old_name);
    feed(&create, 100u);
    make_event(&read, 15u, version, width, invalid == 1u ? 0u : object,
                invalid == 0u ? 0u : key, NULL);
    if (invalid == 2u) read.record.EventHeader.ProcessId = 0u;
    if (invalid == 2u) {
      feed(&read, 150u);
      assert(!bus.published);
      EdrEventSlot pending;
      assert(edr_collector_file_io_test_pending(&pending));
    } else {
      expect_rejected(&read, 150u, EDR_P0_FILE_READ_REASON_CANONICAL_PATH_UNRESOLVED);
    }
  }

  /* Capacity failures at first field, after the object/path, and at the last
   * provenance field must stage a complete source-only subject, never publish
   * the partial normal slot. Exact fit is a separate positive control. */
  char object_line[80], key_line[80];
  snprintf(object_line, sizeof(object_line), "file_read_file_object=0x%llx\n",
           (unsigned long long)object);
  snprintf(key_line, sizeof(key_line), "file_key=0x%llx\n", (unsigned long long)key);
  size_t path_bytes = strlen("file=\n") + strlen(old_path);
  size_t total = strlen(object_line) + path_bytes + strlen(key_line) +
      strlen("file_read_binding_quality=etw_fileobject_create\n");
  const size_t spaces[] = {0u, strlen(object_line) + path_bytes, total - 1u, total};
  for (size_t i = 0u; i < sizeof(spaces) / sizeof(spaces[0]); ++i) {
    static const char *const capacity_cases[] = {
      "capacity_first_field", "capacity_after_object_path", "capacity_last_field", "capacity_exact_fit"
    };
    reset(capacity_cases[i]);
    make_event(&create, 12u, version, width, object, 0u, old_name);
    make_event(&read, 15u, version, width, object, key, NULL);
    feed(&create, 100u);
    binding_space = spaces[i];
    if (spaces[i] == total) {
      expect_read(&read, 150u, old_path, key, object,
                  "file_read_binding_quality=etw_fileobject_create");
      assert(bus.last.size == sizeof(bus.last.data));
    } else {
      expect_rejected(&read, 150u, EDR_P0_FILE_READ_REASON_PAYLOAD_UNAVAILABLE);
      EdrEventSlot pending;
      EdrBehaviorRecord record;
      assert(edr_collector_file_io_test_pending(&pending));
      edr_behavior_from_slot(&pending, &record);
      assert(strcmp(record.file_path, old_path) == 0 && record.file_key == key);
    }
  }
}

int main(void) {
  setvbuf(stderr, NULL, _IONBF, 0);
  fprintf(stderr, "[fixture] native collector diagnostic build; no ETW consumer is started, "
                  "so capability_healthy=0 is expected independently of Read publication\n");
  /* Do not inherit bypass/admission or debug settings from a developer shell. */
  assert(_putenv_s("EDR_COLLECTOR_ADMIT_ALL", "0") == 0);
  assert(_putenv_s("EDR_COLLECTOR_KEEP_AGENT_SELF", "0") == 0);
  assert(_putenv_s("EDR_TDH_DEBUG", "0") == 0);
  for (unsigned version = 0u; version <= 1u; ++version) {
    test_sequence(version, 4u);
    test_sequence(version, 8u);
  }
  /* A long-lived Agent handle can have no retained Create or NameCreate.
   * Suppress only the proven live Agent generation before it opens a P0 gate. */
  reset("self_unbound_read_does_not_open_gate");
  EdrLiveProcessGeneration self = {
      reader_pid, UINT64_C(0x7211), UINT64_C(116444736000000001)};
  edr_collector_file_io_test_self_identity(&self);
  Fixture self_read;
  make_event(&self_read, 15u, 1u, 8u, UINT64_C(0x721100), UINT64_C(0x721101), NULL);
  feed(&self_read, 150u);
  EdrCollectorHealth health;
  EdrEventSlot pending;
  edr_collector_file_io_test_health(&health);
  assert(bus.published == 0u && !edr_collector_file_io_test_pending(&pending));
  assert(health.agent_self_direct_pid_suppressed == 1u);
  assert(health.file_read_name_cache_misses == 0u &&
         health.file_read_metadata_gate_staged == 0u);

  reset("explicit_self_diagnostics_retains_source_only");
  edr_collector_file_io_test_self_identity(&self);
  assert(_putenv_s("EDR_COLLECTOR_KEEP_AGENT_SELF", "1") == 0);
  expect_rejected(&self_read, 150u,
                  EDR_P0_FILE_READ_REASON_CANONICAL_PATH_UNRESOLVED);
  assert(_putenv_s("EDR_COLLECTOR_KEEP_AGENT_SELF", "0") == 0);

  reset("precreation_pid_reuse_remains_source_only");
  self.creation_filetime_100ns = UINT64_C(116444736000000002);
  edr_collector_file_io_test_self_identity(&self);
  expect_rejected(&self_read, 150u, EDR_P0_FILE_READ_REASON_CANONICAL_PATH_UNRESOLVED);
  edr_collector_file_io_test_health(&health);
  assert(health.agent_self_direct_pid_suppressed == 0u);

  reset("canary_marked_agent_read_remains_source_only");
  self.creation_filetime_100ns = UINT64_C(116444736000000001);
  edr_collector_file_io_test_self_identity(&self);
  edr_collector_register_policy_canary_process(reader_pid,
                                               "EDR_POLICY_CANARY_collector_fixture");
  FILETIME now;
  GetSystemTimePreciseAsFileTime(&now);
  uint64_t now_filetime = ((uint64_t)now.dwHighDateTime << 32u) | now.dwLowDateTime;
  assert(now_filetime > UINT64_C(116444736000000000));
  expect_rejected(&self_read,
                  (now_filetime - UINT64_C(116444736000000000)) * 100u,
                  EDR_P0_FILE_READ_REASON_CANONICAL_PATH_UNRESOLVED);
  edr_collector_file_io_test_health(&health);
  assert(health.agent_self_direct_pid_suppressed == 0u);

  puts("collector_file_read_windows: real metadata/resolver/slot/gate cases passed (v0/v1, 32/64-bit)");
  return 0;
}
