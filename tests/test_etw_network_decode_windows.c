#include "edr/etw_guids_win.h"
#include "edr/etw_tdh_win.h"

#include <tdh.h>

#include <assert.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

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

int main(void) {
  test_kernel_network_raw_ports();
  test_kernel_network_malformed_port_sizes();
  test_kernel_network_ipv6_text_unchanged();
  test_other_provider_host_order_and_text_ports();
  puts("Windows ETW network decoding tests passed");
  return 0;
}
