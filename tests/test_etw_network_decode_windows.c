#include "edr/etw_guids_win.h"
#include "edr/etw_tdh_win.h"
#include "collector_network_test.h"
#include "edr/adaptive_collection.h"
#include "edr/behavior_from_slot.h"
#include "edr/config.h"
#include "edr/p0_rule_ir.h"
#include "edr/windows_event_policy.h"
#include "edr/windows_file_identity.h"

#include <tdh.h>

#include <assert.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>
#include <stdlib.h>

typedef struct {
  const WCHAR *name;
  BYTE data[128];
  ULONG size;
  ULONG status;
} TestProperty;

static TestProperty s_properties[16];
static size_t s_property_count;
static PEVENT_RECORD s_expected_record;

static TestProperty *find_property(PCWSTR name) {
  for (size_t i = 0u; i < s_property_count; ++i) {
    if (wcscmp(s_properties[i].name, name) == 0) {
      return &s_properties[i];
    }
  }
  return NULL;
}

static TestProperty *add_property(PCWSTR name, const void *data, ULONG size) {
  TestProperty *property;
  assert(s_property_count < sizeof(s_properties) / sizeof(s_properties[0]));
  assert(size <= sizeof(s_properties[0].data));
  property = &s_properties[s_property_count++];
  memset(property, 0, sizeof(*property));
  property->name = name;
  property->size = size;
  property->status = ERROR_SUCCESS;
  if (size != 0u) {
    assert(data != NULL);
    memcpy(property->data, data, size);
  }
  return property;
}

static void add_u32(PCWSTR name, uint32_t value) {
  (void)add_property(name, &value, (ULONG)sizeof(value));
}

static void add_wide(PCWSTR name, const WCHAR *value) {
  size_t bytes = (wcslen(value) + 1u) * sizeof(*value);
  assert(bytes <= ULONG_MAX);
  (void)add_property(name, value, (ULONG)bytes);
}

static void reset_properties(PEVENT_RECORD record) {
  memset(s_properties, 0, sizeof(s_properties));
  s_property_count = 0u;
  s_expected_record = record;
}

ULONG WINAPI edr_test_tdh_get_property_size(
    PEVENT_RECORD record, ULONG context_count, PTDH_CONTEXT context,
    ULONG property_count, PPROPERTY_DATA_DESCRIPTOR descriptors,
    PULONG property_size) {
  TestProperty *property;
  (void)context_count;
  (void)context;
  if (record != s_expected_record || property_count != 1u || !descriptors ||
      !property_size) {
    return ERROR_INVALID_PARAMETER;
  }
  property = find_property((PCWSTR)(ULONG_PTR)descriptors[0].PropertyName);
  if (!property) {
    return ERROR_NOT_FOUND;
  }
  if (property->status != ERROR_SUCCESS) {
    return property->status;
  }
  *property_size = property->size;
  return ERROR_SUCCESS;
}

ULONG WINAPI edr_test_tdh_get_property(
    PEVENT_RECORD record, ULONG context_count, PTDH_CONTEXT context,
    ULONG property_count, PPROPERTY_DATA_DESCRIPTOR descriptors,
    ULONG buffer_size, PBYTE buffer) {
  TestProperty *property;
  (void)context_count;
  (void)context;
  if (record != s_expected_record || property_count != 1u || !descriptors ||
      !buffer) {
    return ERROR_INVALID_PARAMETER;
  }
  property = find_property((PCWSTR)(ULONG_PTR)descriptors[0].PropertyName);
  if (!property) {
    return ERROR_NOT_FOUND;
  }
  if (property->status != ERROR_SUCCESS) {
    return property->status;
  }
  if (buffer_size < property->size) {
    return ERROR_INSUFFICIENT_BUFFER;
  }
  memcpy(buffer, property->data, property->size);
  return ERROR_SUCCESS;
}

static EVENT_RECORD make_record(const GUID *provider, ULONG header_pid) {
  EVENT_RECORD record;
  memset(&record, 0, sizeof(record));
  record.EventHeader.ProviderId = *provider;
  record.EventHeader.ProcessId = header_pid;
  record.EventHeader.EventDescriptor.Id = 12u;
  record.EventHeader.EventDescriptor.Task = 10u;
  record.EventHeader.EventDescriptor.Opcode = 12u;
  record.EventHeader.EventDescriptor.Level = 4u;
  return record;
}

static void expect_contains(const char *payload, const char *expected) {
  if (!strstr(payload, expected)) {
    fprintf(stderr, "missing '%s' in payload:\n%s\n", expected, payload);
    assert(0);
  }
}

static void expect_absent(const char *payload, const char *unexpected) {
  if (strstr(payload, unexpected)) {
    fprintf(stderr, "unexpected '%s' in payload:\n%s\n", unexpected, payload);
    assert(0);
  }
}

static void test_kernel_network_raw_ports(void) {
  EVENT_RECORD record = make_record(&EDR_ETW_GUID_KERNEL_NETWORK, 7u);
  EdrSensorInterestEvent interest;
  BYTE payload[2048];
  const BYTE dport[] = {0x01u, 0xbdu}; /* 445 in network byte order. */
  const BYTE sport[] = {0x1fu, 0x90u}; /* 8080 in network byte order. */
  uint32_t daddr = 16777343u;
  uint32_t saddr = 16777343u;
  uint32_t payload_pid = 9840u;
  size_t size;

  reset_properties(&record);
  (void)add_property(L"dport", dport, (ULONG)sizeof(dport));
  (void)add_property(L"sport", sport, (ULONG)sizeof(sport));
  (void)add_property(L"daddr", &daddr, (ULONG)sizeof(daddr));
  (void)add_property(L"saddr", &saddr, (ULONG)sizeof(saddr));
  add_u32(L"PID", payload_pid);

  assert(edr_tdh_build_sensor_interest_event(
      &record, EDR_EVENT_NET_CONNECT, "knet", &interest));
  assert(interest.remote_port == 445u);
  assert(interest.pid == payload_pid);

  memset(payload, 0, sizeof(payload));
  size = edr_tdh_build_slot_payload(&record, "knet", payload,
                                    sizeof(payload));
  assert(size > 0u);
  expect_contains((const char *)payload, "pid=7\n");
  expect_contains((const char *)payload, "epid=9840\n");
  expect_contains((const char *)payload, "dst=16777343\n");
  expect_contains((const char *)payload, "src=16777343\n");
  expect_contains((const char *)payload, "dpt=445\n");
  expect_contains((const char *)payload, "spt=8080\n");
}

static void test_kernel_network_malformed_port_sizes(void) {
  EVENT_RECORD record = make_record(&EDR_ETW_GUID_KERNEL_NETWORK, 11u);
  EdrSensorInterestEvent interest;
  BYTE payload[1024];
  const BYTE malformed_dport[] = {0x01u};
  const BYTE malformed_sport[] = {0x1fu, 0x90u, 0x00u};
  uint32_t daddr = 16777343u;
  size_t size;

  reset_properties(&record);
  (void)add_property(L"dport", malformed_dport,
                     (ULONG)sizeof(malformed_dport));
  (void)add_property(L"sport", malformed_sport,
                     (ULONG)sizeof(malformed_sport));
  (void)add_property(L"daddr", &daddr, (ULONG)sizeof(daddr));

  assert(edr_tdh_build_sensor_interest_event(
      &record, EDR_EVENT_NET_CONNECT, "knet", &interest));
  assert(interest.remote_port == 0u);
  memset(payload, 0, sizeof(payload));
  size = edr_tdh_build_slot_payload(&record, "knet", payload,
                                    sizeof(payload));
  assert(size > 0u);
  expect_contains((const char *)payload, "dst=16777343\n");
  expect_absent((const char *)payload, "dpt=");
  expect_absent((const char *)payload, "spt=");
}

static void test_kernel_network_ipv6_text_unchanged(void) {
  EVENT_RECORD record = make_record(&EDR_ETW_GUID_KERNEL_NETWORK, 13u);
  BYTE payload[1024];
  const BYTE dport[] = {0x1fu, 0x90u};
  size_t size;

  reset_properties(&record);
  (void)add_property(L"dport", dport, (ULONG)sizeof(dport));
  add_wide(L"daddr", L"fe80::1");
  add_wide(L"saddr", L"::1");
  memset(payload, 0, sizeof(payload));
  size = edr_tdh_build_slot_payload(&record, "knet", payload,
                                    sizeof(payload));
  assert(size > 0u);
  expect_contains((const char *)payload, "dst=fe80::1\n");
  expect_contains((const char *)payload, "src=::1\n");
  expect_contains((const char *)payload, "dpt=8080\n");
}

static void test_other_provider_host_order_and_text_ports(void) {
  EVENT_RECORD record = make_record(&EDR_ETW_GUID_MICROSOFT_TCPIP, 17u);
  EdrSensorInterestEvent interest;
  BYTE payload[2048];
  uint32_t dport = 445u;
  uint32_t sport = 8080u;
  size_t size;

  reset_properties(&record);
  add_u32(L"Dport", dport);
  add_u32(L"Sport", sport);
  add_wide(L"DAddr", L"192.0.2.10");
  add_wide(L"SAddr", L"192.0.2.20");
  assert(edr_tdh_build_sensor_interest_event(
      &record, EDR_EVENT_NET_CONNECT, "tcpip", &interest));
  assert(interest.remote_port == 445u);
  memset(payload, 0, sizeof(payload));
  size = edr_tdh_build_slot_payload(&record, "tcpip", payload,
                                    sizeof(payload));
  assert(size > 0u);
  expect_contains((const char *)payload, "dpt=445\n");
  expect_contains((const char *)payload, "spt=8080\n");
  expect_contains((const char *)payload, "dst=192.0.2.10\n");
  expect_contains((const char *)payload, "src=192.0.2.20\n");

  reset_properties(&record);
  add_wide(L"RemotePort", L"8443");
  assert(edr_tdh_build_sensor_interest_event(
      &record, EDR_EVENT_NET_CONNECT, "tcpip", &interest));
  assert(interest.remote_port == 8443u);
  memset(payload, 0, sizeof(payload));
  size = edr_tdh_build_slot_payload(&record, "tcpip", payload,
                                    sizeof(payload));
  assert(size > 0u);
  expect_contains((const char *)payload, "rport=8443\n");
}

struct EdrEventBus { unsigned published; EdrEventSlot last; };
static struct EdrEventBus bus;
static EdrLiveProcessGeneration live_actor;
static const char *actor_path;
static uint64_t os_birth, os_exit;
static unsigned opens, closes, image_queries;
static int deny_open, deny_image, deny_times;
static DWORD actor_state;
static unsigned state_queries, time_queries;
static int use_real_process_io;
static const uint32_t actor_pid = 9840u;
static const uint64_t event_ns = 1700000000000000000ULL;

bool edr_event_bus_try_push(EdrEventBus *target, const EdrEventSlot *slot) {
  assert(target == &bus && slot->type == EDR_EVENT_NET_CONNECT);
  bus.last = *slot;
  ++bus.published;
  return true;
}
HANDLE WINAPI edr_network_test_open_process(DWORD access, BOOL inherit, DWORD pid) {
  if (use_real_process_io) return OpenProcess(access, inherit, pid);
  assert(access == (PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE) && !inherit && pid == actor_pid);
  ++opens;
  return deny_open ? NULL : (HANDLE)&live_actor;
}
BOOL WINAPI edr_network_test_close_handle(HANDLE process) {
  if (use_real_process_io) return CloseHandle(process);
  assert(process == (HANDLE)&live_actor);
  ++closes;
  return TRUE;
}
DWORD WINAPI edr_network_test_wait_process(HANDLE process, DWORD milliseconds) {
  if (use_real_process_io) return WaitForSingleObject(process, milliseconds);
  assert(process == (HANDLE)&live_actor && milliseconds == 0u);
  ++state_queries;
  return actor_state;
}
static void set_filetime(LPFILETIME out, uint64_t value) {
  out->dwHighDateTime = (DWORD)(value >> 32u);
  out->dwLowDateTime = (DWORD)value;
}
BOOL WINAPI edr_network_test_process_times(HANDLE process, LPFILETIME created,
                                          LPFILETIME exited, LPFILETIME kernel, LPFILETIME user) {
  if (use_real_process_io || process == GetCurrentProcess())
    return GetProcessTimes(process, created, exited, kernel, user);
  assert(process == (HANDLE)&live_actor);
  assert(state_queries == 1u); /* State must precede potentially undefined ExitTime. */
  ++time_queries;
  if (deny_times) return FALSE;
  set_filetime(created, os_birth); set_filetime(exited, os_exit);
  set_filetime(kernel, 0u); set_filetime(user, 0u);
  return TRUE;
}
int edr_network_test_query_generation(void *process, EdrLiveProcessGeneration *out,
                                       char *reason, size_t cap) {
  if (use_real_process_io || process == GetCurrentProcess())
    return edr_process_generation_query_live(process, out, reason, cap);
  assert(process == &live_actor);
  *out = live_actor;
  snprintf(reason, cap, "ok");
  return 1;
}
int edr_network_test_image_path(void *process, char *out, size_t cap) {
  if (use_real_process_io) return edr_windows_process_image_path_utf8(process, out, cap);
  assert(process == &live_actor);
  ++image_queries;
  if (deny_image) return 0;
  assert(strlen(actor_path) < cap);
  snprintf(out, cap, "%s", actor_path);
  return 1;
}

static EVENT_RECORD network_case(const char *name, uint16_t port) {
  EVENT_RECORD record = make_record(&EDR_ETW_GUID_KERNEL_NETWORK, 4u);
  fprintf(stderr, "[collector-network] %s\n", name);
  memset(&bus, 0, sizeof(bus));
  edr_collector_network_test_reset(&bus);
  opens = closes = image_queries = state_queries = time_queries = 0u;
  deny_open = deny_image = deny_times = 0;
  actor_state = WAIT_TIMEOUT;
  live_actor.pid = actor_pid;
  live_actor.process_start_key = 0x12345678u;
  live_actor.creation_filetime_100ns = 116444736000000000ULL + event_ns / 100u - 10000000u;
  os_birth = live_actor.creation_filetime_100ns;
  os_exit = 0u;
  actor_path = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
  /* The returned record has a different address: bind the TDH external-I/O
   * fixture to the caller's record immediately before feeding it. */
  reset_properties(NULL);
  add_u32(L"PID", actor_pid);
  BYTE dport[2] = {(BYTE)(port >> 8u), (BYTE)(port & 255u)};
  BYTE sport[2] = {0xd5u, 0xf2u};
  add_property(L"dport", dport, sizeof(dport));
  add_property(L"sport", sport, sizeof(sport));
  add_wide(L"daddr", L"127.0.0.1");
  add_wide(L"saddr", L"127.0.0.1");
  return record;
}

static void feed_network(EVENT_RECORD *record, uint64_t at, unsigned expected) {
  s_expected_record = record;
  edr_collector_network_test_feed(record, at);
  if (bus.published != expected) {
    fprintf(stderr, "publication mismatch: expected=%u actual=%u\n", expected, bus.published);
    exit(EXIT_FAILURE);
  }
  assert(closes == opens - (deny_open ? opens : 0u));
}

static void test_collector_network_admission(void) {
  EdrSensorInterestStatus status;
  EdrConfig *config = calloc(1u, sizeof(*config));
  assert(config);
  edr_adaptive_collection_configure(config); free(config);
  _putenv_s("EDR_COLLECTOR_ADMIT_ALL", "0");
  _putenv_s("EDR_COLLECTOR_KEEP_ALL_NET", "0");
  _putenv_s("EDR_SENSOR_INTEREST_ENABLED", "1");
  edr_p0_rule_ir_lazy_init(); edr_sensor_interest_reload();
  edr_sensor_interest_get_status(&status);
  assert(status.p0_binding_valid && status.full_admission_contract_valid);

  EVENT_RECORD record = network_case("unnamed ordinary port, exact live actor", 54760u);
  EdrSensorInterestEvent raw;
  s_expected_record = &record;
  assert(edr_tdh_build_sensor_interest_event(&record, EDR_EVENT_NET_CONNECT, "knet", &raw));
  assert(raw.pid == actor_pid && !raw.process_name[0]);
  assert(!edr_sensor_interest_should_admit(&raw)); /* old ordering loses this event */
  /* Deliberately different logger key: it must never become the payload owner's key. */
  uint64_t logger_key = 0x99999999u;
  EVENT_HEADER_EXTENDED_DATA_ITEM extended = {0};
  extended.ExtType = 13u; /* EVENT_HEADER_EXT_TYPE_PROCESS_START_KEY */
  extended.DataSize = sizeof(logger_key);
  extended.DataPtr = (ULONGLONG)(ULONG_PTR)&logger_key;
  record.ExtendedData = &extended; record.ExtendedDataCount = 1u;
  feed_network(&record, event_ns, 1u);
  EdrBehaviorRecord decoded;
  edr_behavior_from_slot(&bus.last, &decoded);
  assert(decoded.pid == actor_pid && decoded.process_start_key == live_actor.process_start_key);
  assert(decoded.process_creation_filetime_100ns == os_birth);
  assert(!strcmp(decoded.process_name, "powershell.exe") && !strcmp(decoded.exe_path, actor_path));
  assert(!strcmp(decoded.process_generation_source, "network_pid_event_time_live_telemetry"));
  assert(!strcmp(decoded.image_path_resolution_source, "live_same_generation"));
  assert(decoded.net_dport == 54760u && !strcmp(decoded.net_dst, "127.0.0.1"));
  assert(opens == 1u && image_queries == 1u);

  record = network_case("running actor with undefined nonzero exit time", 54760u);
  /* GetProcessTimes does not define ExitTime until the process has exited. */
  os_exit = 116444736000000000ULL + event_ns / 100u - 1u;
  feed_network(&record, event_ns, 1u);
  assert(state_queries == 1u && time_queries == 1u && image_queries == 1u);

  record = network_case("process state query fails closed", 54760u);
  actor_state = WAIT_FAILED;
  feed_network(&record, event_ns, 0u);
  assert(state_queries == 1u && time_queries == 0u && image_queries == 0u);
  record = network_case("interesting port survives unavailable process state", 445u);
  actor_state = WAIT_FAILED;
  feed_network(&record, event_ns, 1u);
  edr_behavior_from_slot(&bus.last, &decoded);
  assert(!decoded.process_start_key && !decoded.exe_path[0]);
  assert(!strcmp(decoded.process_generation_source, "network_actor_state_unavailable"));
  record = network_case("process time query fails closed", 54760u);
  deny_times = 1;
  feed_network(&record, event_ns, 0u);
  assert(image_queries == 0u);

  record = network_case("uninteresting process remains filtered", 54760u);
  actor_path = "C:\\Windows\\System32\\notepad.exe";
  feed_network(&record, event_ns, 0u);
  record = network_case("late event predates reused PID", 54760u);
  live_actor.creation_filetime_100ns = os_birth = 116444736000000000ULL + event_ns / 100u + 1u;
  feed_network(&record, event_ns, 0u);
  assert(image_queries == 0u);
  EdrCollectorHealth health;
  edr_collector_network_test_health(&health);
  assert(health.process_start_key_missing_events == 1u);
  record = network_case("telemetry and OS birth disagree", 54760u);
  ++os_birth;
  feed_network(&record, event_ns, 0u);
  assert(image_queries == 0u);
  record = network_case("queried PID disagrees", 54760u);
  ++live_actor.pid;
  feed_network(&record, event_ns, 0u);
  record = network_case("source event time unavailable", 54760u);
  /* Calling feed with zero exercises the collector's callback-time fallback:
   * a missing source time must not become authority to bind a current PID. */
  feed_network(&record, 0u, 0u);
  record = network_case("exited after source event still uses same handle", 54760u);
  actor_state = WAIT_OBJECT_0;
  os_exit = 116444736000000000ULL + event_ns / 100u + 1u;
  feed_network(&record, event_ns, 1u);
  record = network_case("event after process exit", 54760u);
  actor_state = WAIT_OBJECT_0;
  os_exit = 116444736000000000ULL + event_ns / 100u - 1u;
  feed_network(&record, event_ns, 0u);
  record = network_case("event at process exit", 54760u);
  actor_state = WAIT_OBJECT_0;
  os_exit = 116444736000000000ULL + event_ns / 100u;
  feed_network(&record, event_ns, 0u);
  record = network_case("exited process without valid exit time", 54760u);
  actor_state = WAIT_OBJECT_0;
  feed_network(&record, event_ns, 0u);
  record = network_case("exit time predates birth", 54760u);
  actor_state = WAIT_OBJECT_0;
  os_exit = os_birth - 1u;
  feed_network(&record, event_ns, 0u);
  record = network_case("process unavailable is not ordinary", 54760u);
  deny_open = 1;
  feed_network(&record, event_ns, 0u);
  record = network_case("interesting port survives unavailable actor", 445u);
  deny_open = 1;
  feed_network(&record, event_ns, 1u);
  edr_behavior_from_slot(&bus.last, &decoded);
  assert(!decoded.process_start_key && !decoded.exe_path[0]);
  assert(!strcmp(decoded.process_generation_source, "network_actor_open_failed"));
  record = network_case("image unavailable", 54760u);
  deny_image = 1;
  feed_network(&record, event_ns, 0u);
  record = network_case("missing payload PID cannot use logger", 445u);
  find_property(L"PID")->status = ERROR_NOT_FOUND;
  feed_network(&record, event_ns, 0u);
  assert(opens == 0u);
  record = network_case("IPv6 connect has same unnamed-owner contract", 54760u);
  record.EventHeader.EventDescriptor.Id = 28u;
  feed_network(&record, event_ns, 1u);
}

static void test_file_control_policy_preconditions(void) {
  static const char *paths[] = {
      "C:\\Windows\\Temp\\EDR-FILE-CONTROL\\A.txt",
      "C:\\Windows\\Temp\\EDR-FILE-CONTROL\\B.txt",
      "C:\\Windows\\Temp\\EDR-FILE-CONTROL\\A\\Login Data",
      "C:\\Windows\\Temp\\EDR-FILE-CONTROL\\B\\Network\\Cookies"};
  EdrBehaviorRecord *br = calloc(1u, sizeof(*br));
  assert(br);
  edr_windows_event_policy_configure(NULL);
  br->type = EDR_EVENT_FILE_READ;
  br->priority = 2u;
  snprintf(br->process_name, sizeof(br->process_name), "powershell.exe");
  for (size_t i = 0u; i < sizeof(paths) / sizeof(paths[0]); ++i) {
    EdrSensorInterestEvent interest = {0};
    EdrWindowsEventPolicy policy;
    interest.type = EDR_EVENT_FILE_READ;
    snprintf(interest.path, sizeof(interest.path), "%s", paths[i]);
    snprintf(br->file_path, sizeof(br->file_path), "%s", paths[i]);
    int path_keep = edr_p0_rule_ir_file_read_path_may_match(paths[i], NULL);
    edr_windows_event_policy_evaluate(br, &policy);
    fprintf(stderr, "[file-control] target=%zu path_keep=%d noise_emit=%u\n",
            i, path_keep, policy.should_emit);
    assert(edr_sensor_interest_should_admit(&interest));
    assert(!policy.should_emit); /* All four are inside the same noise directory. */
    assert(path_keep == (i >= 2u)); /* Positive targets take the existing P0 exception. */
  }
  free(br);
}

static void test_real_same_handle_actor_binding(void) {
  EdrBehaviorRecord *br = calloc(1u, sizeof(*br));
  FILETIME created, exited, kernel, user;
  wchar_t executable_wide[4096];
  char executable[EDR_BR_STR_LONG];
  assert(br);
  assert(GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user));
  DWORD chars = GetModuleFileNameW(NULL, executable_wide,
                                   sizeof(executable_wide) / sizeof(executable_wide[0]));
  assert(chars && chars < sizeof(executable_wide) / sizeof(executable_wide[0]));
  assert(WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, executable_wide, -1,
                            executable, sizeof(executable), NULL, NULL));
  br->type = EDR_EVENT_NET_CONNECT;
  br->pid = GetCurrentProcessId();
  FILETIME observed;
  /* Match the collector's clock; do not compare a coarse wall-clock sample
   * against an exact process creation timestamp. No lifetime slack is added. */
  GetSystemTimePreciseAsFileTime(&observed);
  uint64_t now_filetime = ((uint64_t)observed.dwHighDateTime << 32u) | observed.dwLowDateTime;
  br->event_time_ns = (int64_t)((now_filetime - 116444736000000000ULL) * 100u);
  use_real_process_io = 1;
  int bound = edr_collector_network_test_bind_actor(br);
  if (!bound) {
    fprintf(stderr, "[collector-network] real binding failed: reason=%s pid=%lu event_ns=%llu creation_filetime=%llu\n",
            br->process_generation_source, (unsigned long)br->pid,
            (unsigned long long)br->event_time_ns,
            (unsigned long long)(((uint64_t)created.dwHighDateTime << 32u) | created.dwLowDateTime));
  }
  assert(bound);
  assert(br->process_start_key && br->process_creation_filetime_100ns ==
      (((uint64_t)created.dwHighDateTime << 32u) | created.dwLowDateTime));
  assert(!strcmp(br->exe_path, executable));
  br->event_time_ns = 1; /* The same real process cannot own a pre-birth event. */
  assert(!edr_collector_network_test_bind_actor(br));
  assert(!strcmp(br->process_generation_source, "network_actor_event_time_mismatch"));
  use_real_process_io = 0;
  free(br);
  fprintf(stderr, "[collector-network] real Windows same-handle binding passed\n");
}

static void test_self_noise_uses_immutable_actor_identity(void) {
  EdrLiveProcessGeneration self = {9100u, UINT64_C(0x91000001), UINT64_C(132000000000000000)};
  EdrBehaviorRecord br;
  EdrSensorInterestEvent interest;
  static const char *const names[] = {"powershell.exe", "FDSensor.exe", "edr_agent.exe"};
  assert(_putenv_s("EDR_COLLECTOR_KEEP_AGENT_SELF", "0") == 0);
  edr_collector_network_test_self_identity(&self);
  memset(&br, 0, sizeof(br));
  memset(&interest, 0, sizeof(interest));
  br.pid = interest.pid = 9200u;
  br.ppid = interest.parent_pid = self.pid;
  br.process_start_key = interest.process_start_key = 0x92000001u;
  snprintf(br.cmdline, sizeof(br.cmdline), "%s", "powershell.exe cmd_forensic_1 edr_remote_1");
  snprintf(br.file_path, sizeof(br.file_path), "%s", "C:\\edr_forensic\\payload.ps1");
  snprintf(br.exe_path, sizeof(br.exe_path), "%s", "C:\\FDSecurity\\FDSensor.exe");
  snprintf(br.reg_key_path, sizeof(br.reg_key_path), "%s", "HKCU\\edr_remote_");
  snprintf(interest.path, sizeof(interest.path), "%s", br.file_path);
  snprintf(interest.registry_path, sizeof(interest.registry_path), "%s", br.reg_key_path);
  for (size_t i = 0u; i < sizeof(names) / sizeof(names[0]); ++i) {
    snprintf(br.process_name, sizeof(br.process_name), "%s", names[i]);
    snprintf(interest.process_name, sizeof(interest.process_name), "%s", names[i]);
    assert(!edr_collector_network_test_self_record(&br));
    assert(!edr_collector_network_test_self_interest(&interest));
  }
  /* Text or a parent match cannot leave behind a descendant cache exemption. */
  br.ppid = interest.parent_pid = 0u;
  br.cmdline[0] = br.file_path[0] = interest.path[0] = '\0';
  assert(!edr_collector_network_test_self_record(&br));
  assert(!edr_collector_network_test_self_interest(&interest));
  br.pid = interest.pid = self.pid;
  assert(!edr_collector_network_test_self_record(&br));
  assert(!edr_collector_network_test_self_interest(&interest));
  br.process_start_key = interest.process_start_key = 0u;
  assert(!edr_collector_network_test_self_record(&br));
  assert(!edr_collector_network_test_self_interest(&interest));
  br.process_start_key = interest.process_start_key = self.process_start_key;
  assert(edr_collector_network_test_self_record(&br));
  assert(edr_collector_network_test_self_interest(&interest));
  assert(_putenv_s("EDR_COLLECTOR_KEEP_AGENT_SELF", "1") == 0);
  assert(!edr_collector_network_test_self_record(&br));
  assert(!edr_collector_network_test_self_interest(&interest));
  assert(_putenv_s("EDR_COLLECTOR_KEEP_AGENT_SELF", "0") == 0);
  edr_collector_network_test_self_identity(NULL);
  assert(!edr_collector_network_test_self_record(&br));
  assert(!edr_collector_network_test_self_interest(&interest));
}

int main(int argc, char **argv) {
  /* Standalone native replay uses literal argv, not a shell which can
   * reinterpret paths or environment assignments. CTest supplies these by env. */
  if (argc == 3) {
    assert(_putenv_s("EDR_P0_IR_PATH", argv[1]) == 0);
    assert(_putenv_s("EDR_SENSOR_INTEREST_PATH", argv[2]) == 0);
  } else {
    assert(argc == 1);
  }
  test_kernel_network_raw_ports();
  test_kernel_network_malformed_port_sizes();
  test_kernel_network_ipv6_text_unchanged();
  test_other_provider_host_order_and_text_ports();
  test_collector_network_admission();
  test_file_control_policy_preconditions();
  test_self_noise_uses_immutable_actor_identity();
  test_real_same_handle_actor_binding();
  puts("Windows ETW network decoding tests passed");
  return 0;
}
