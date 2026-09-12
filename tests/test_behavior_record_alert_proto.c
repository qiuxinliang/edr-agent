#include "edr/ave_sdk.h"
#include "edr/behavior_proto.h"
#include "edr/behavior_proto_c.h"
#include "edr/event_batch.h"

#include "edr/v1/event.pb.h"
#include <pb_decode.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void init_transport_record(EdrBehaviorRecord *record) {
  memset(record, 0, sizeof(*record));
  record->type = EDR_EVENT_PROCESS_CREATE;
  snprintf(record->event_id, sizeof(record->event_id), "transport-boundary");
  snprintf(record->endpoint_id, sizeof(record->endpoint_id), "endpoint-transport");
  snprintf(record->tenant_id, sizeof(record->tenant_id), "tenant-transport");
}

static void fill_boundary_ascii(char *dst, size_t cap, char value) {
  if (!dst || cap == 0u) return;
  memset(dst, value, cap - 1u);
  dst[cap - 1u] = '\0';
}

static void fill_common_process_context(EdrBehaviorRecord *record, const char *label) {
  snprintf(record->parent_name, sizeof(record->parent_name), "parent-%s.exe", label);
  snprintf(record->parent_path, sizeof(record->parent_path), "C:/parent/%s.exe", label);
  snprintf(record->integrity_level, sizeof(record->integrity_level), "high");
  snprintf(record->parent_cmdline, sizeof(record->parent_cmdline),
           "parent-%s.exe --captured", label);
  snprintf(record->current_directory, sizeof(record->current_directory), "C:/work/%s", label);
  snprintf(record->process_creation_time, sizeof(record->process_creation_time),
           "2026-09-12T01:02:03Z");
  record->token_elevation = 2u;
  record->grandparent_pid = 77u;
  snprintf(record->grandparent_name, sizeof(record->grandparent_name), "grandparent.exe");
  snprintf(record->grandparent_path, sizeof(record->grandparent_path),
           "C:/parent/grandparent.exe");
}

typedef size_t (*EdrBehaviorRecordEncoder)(const EdrBehaviorRecord *record, uint8_t *wire,
                                           size_t wire_cap);

static int encode_decode_record_with(EdrBehaviorRecordEncoder encoder,
                                     const EdrBehaviorRecord *record, uint8_t *wire,
                                     size_t wire_cap, edr_v1_BehaviorEvent *decoded) {
  const size_t wire_len = encoder(record, wire, wire_cap);
  pb_istream_t stream;
  if (wire_len == 0u) return 0;
  memset(decoded, 0, sizeof(*decoded));
  stream = pb_istream_from_buffer(wire, wire_len);
  return pb_decode(&stream, edr_v1_BehaviorEvent_fields, decoded);
}

static int encode_decode_record(const EdrBehaviorRecord *record, uint8_t *wire,
                                size_t wire_cap, edr_v1_BehaviorEvent *decoded) {
  return encode_decode_record_with(edr_behavior_record_encode_protobuf, record, wire, wire_cap,
                                   decoded);
}

static int verify_parent_identity_across_detail_oneofs(uint8_t *wire, size_t wire_cap) {
  static const struct {
    const char *name;
    uint32_t expected_detail;
  } cases[] = {
      {"process", edr_v1_BehaviorEvent_process_tag},
      {"file", edr_v1_BehaviorEvent_file_tag},
      {"network", edr_v1_BehaviorEvent_network_tag},
      {"registry", edr_v1_BehaviorEvent_registry_tag},
      {"dns", edr_v1_BehaviorEvent_dns_tag},
      {"script", edr_v1_BehaviorEvent_script_tag},
  };

  for (size_t i = 0u; i < sizeof(cases) / sizeof(cases[0]); ++i) {
    EdrBehaviorRecord record;
    edr_v1_BehaviorEvent decoded = edr_v1_BehaviorEvent_init_zero;

    init_transport_record(&record);
    fill_common_process_context(&record, cases[i].name);
    switch (cases[i].expected_detail) {
      case edr_v1_BehaviorEvent_file_tag:
        snprintf(record.file_op, sizeof(record.file_op), "write");
        snprintf(record.file_path, sizeof(record.file_path), "C:/detail/file.bin");
        break;
      case edr_v1_BehaviorEvent_network_tag:
        snprintf(record.net_dst, sizeof(record.net_dst), "198.51.100.10");
        snprintf(record.net_proto, sizeof(record.net_proto), "tcp");
        break;
      case edr_v1_BehaviorEvent_registry_tag:
        snprintf(record.reg_key_path, sizeof(record.reg_key_path), "HKCU/Software/EDR");
        snprintf(record.reg_op, sizeof(record.reg_op), "set_value");
        break;
      case edr_v1_BehaviorEvent_dns_tag:
        snprintf(record.dns_query, sizeof(record.dns_query), "example.invalid");
        break;
      case edr_v1_BehaviorEvent_script_tag:
        snprintf(record.script_snippet, sizeof(record.script_snippet), "Write-Output benign");
        break;
      default:
        break;
    }
    if (!encode_decode_record(&record, wire, wire_cap, &decoded) ||
        decoded.which_detail != cases[i].expected_detail ||
        strcmp(decoded.parent_name, record.parent_name) != 0 ||
        strcmp(decoded.parent_path, record.parent_path) != 0 ||
        !decoded.has_process_context ||
        !decoded.process_context.has_parent_name ||
        strcmp(decoded.process_context.parent_name, record.parent_name) != 0 ||
        !decoded.process_context.has_parent_path ||
        strcmp(decoded.process_context.parent_path, record.parent_path) != 0 ||
        !decoded.process_context.has_integrity_level ||
        strcmp(decoded.process_context.integrity_level, record.integrity_level) != 0 ||
        !decoded.process_context.has_parent_cmdline ||
        strcmp(decoded.process_context.parent_cmdline, record.parent_cmdline) != 0 ||
        !decoded.process_context.has_current_directory ||
        strcmp(decoded.process_context.current_directory, record.current_directory) != 0 ||
        !decoded.process_context.has_process_creation_time ||
        strcmp(decoded.process_context.process_creation_time, record.process_creation_time) != 0 ||
        !decoded.process_context.has_token_elevation ||
        decoded.process_context.token_elevation != record.token_elevation ||
        !decoded.process_context.has_grandparent_pid ||
        decoded.process_context.grandparent_pid != record.grandparent_pid ||
        !decoded.process_context.has_grandparent_name ||
        strcmp(decoded.process_context.grandparent_name, record.grandparent_name) != 0 ||
        !decoded.process_context.has_grandparent_path ||
        strcmp(decoded.process_context.grandparent_path, record.grandparent_path) != 0 ||
        strcmp(decoded.transport_completeness, "COMPLETE") != 0 ||
        decoded.truncated_fields[0] != '\0') {
      fprintf(stderr, "top-level parent identity lost for %s detail\n", cases[i].name);
      return 0;
    }
  }

  /* `protobuf_c` currently delegates to nanopb, so exercise that supported
   * encoding path with a non-process oneof rather than assuming compatibility. */
  {
    EdrBehaviorRecord record;
    edr_v1_BehaviorEvent decoded = edr_v1_BehaviorEvent_init_zero;
    init_transport_record(&record);
    snprintf(record.parent_name, sizeof(record.parent_name), "parent-protobuf-c.exe");
    snprintf(record.parent_path, sizeof(record.parent_path), "C:/parent/protobuf-c.exe");
    snprintf(record.parent_cmdline, sizeof(record.parent_cmdline),
             "parent-protobuf-c.exe --captured");
    snprintf(record.net_dst, sizeof(record.net_dst), "198.51.100.11");
    snprintf(record.net_proto, sizeof(record.net_proto), "tcp");
    if (!encode_decode_record_with(edr_behavior_record_encode_protobuf_c, &record, wire,
                                   wire_cap, &decoded) ||
        decoded.which_detail != edr_v1_BehaviorEvent_network_tag ||
        strcmp(decoded.parent_name, record.parent_name) != 0 ||
        strcmp(decoded.parent_path, record.parent_path) != 0 ||
        !decoded.has_process_context ||
        strcmp(decoded.process_context.parent_cmdline, record.parent_cmdline) != 0) {
      fprintf(stderr, "protobuf_c parent identity projection failed\n");
      return 0;
    }
  }

  /* Missing input stays missing even when a non-process detail is present. */
  {
    EdrBehaviorRecord record;
    edr_v1_BehaviorEvent decoded = edr_v1_BehaviorEvent_init_zero;
    init_transport_record(&record);
    snprintf(record.file_op, sizeof(record.file_op), "create");
    snprintf(record.file_path, sizeof(record.file_path), "E:/removable/marker.txt");
    if (!encode_decode_record(&record, wire, wire_cap, &decoded) ||
        decoded.which_detail != edr_v1_BehaviorEvent_file_tag ||
        decoded.has_process_context) {
      fprintf(stderr, "absent process context was fabricated\n");
      return 0;
    }
  }

  /* A non-terminated fixed-width source must be explicitly reported rather
   * than copied past its record boundary or silently treated as complete. */
  {
    EdrBehaviorRecord record;
    edr_v1_BehaviorEvent decoded = edr_v1_BehaviorEvent_init_zero;
    init_transport_record(&record);
    memset(record.parent_name, 'n', sizeof(record.parent_name));
    memset(record.parent_path, 'p', sizeof(record.parent_path));
    if (!encode_decode_record(&record, wire, wire_cap, &decoded) ||
        decoded.which_detail != edr_v1_BehaviorEvent_process_tag ||
        strlen(decoded.parent_name) != sizeof(record.parent_name) - 1u ||
        strlen(decoded.parent_path) != sizeof(record.parent_path) - 1u ||
        strcmp(decoded.transport_completeness, "TRUNCATED") != 0 ||
        strcmp(decoded.truncated_fields, "parent_name,parent_path") != 0) {
      fprintf(stderr, "parent identity truncation was not explicit\n");
      return 0;
    }
  }
  return 1;
}

static int verify_transport_boundaries(uint8_t *wire, size_t wire_cap) {
  EdrBehaviorRecord record;
  edr_v1_BehaviorEvent decoded = edr_v1_BehaviorEvent_init_zero;
  char expected[EDR_BR_STR_LONG];

  /* Every aligned 4 KiB record string survives exactly at the boundary. */
  init_transport_record(&record);
  fill_boundary_ascii(record.cmdline, sizeof(record.cmdline), 'c');
  fill_boundary_ascii(record.exe_path, sizeof(record.exe_path), 'e');
  fill_boundary_ascii(record.file_path, sizeof(record.file_path), 'f');
  snprintf(record.file_op, sizeof(record.file_op), "write");
  if (!encode_decode_record(&record, wire, wire_cap, &decoded) ||
      strlen(decoded.cmdline) != sizeof(record.cmdline) - 1u ||
      strlen(decoded.exe_path) != sizeof(record.exe_path) - 1u ||
      !decoded.which_detail ||
      strlen(decoded.detail.file.target_path) != sizeof(record.file_path) - 1u ||
      strcmp(decoded.transport_completeness, "COMPLETE") != 0 ||
      decoded.truncated_fields[0] != '\0') {
    return 0;
  }

  init_transport_record(&record);
  snprintf(record.parent_name, sizeof(record.parent_name), "parent.exe");
  fill_boundary_ascii(record.parent_cmdline, sizeof(record.parent_cmdline), 'p');
  fill_boundary_ascii(record.current_directory, sizeof(record.current_directory), 'd');
  if (!encode_decode_record(&record, wire, wire_cap, &decoded) ||
      decoded.which_detail != edr_v1_BehaviorEvent_process_tag ||
      strlen(decoded.detail.process.parent_cmdline) != sizeof(record.parent_cmdline) - 1u ||
      strlen(decoded.detail.process.current_directory) != sizeof(record.current_directory) - 1u ||
      !decoded.has_process_context ||
      strlen(decoded.process_context.parent_cmdline) != sizeof(record.parent_cmdline) - 1u ||
      strlen(decoded.process_context.current_directory) != sizeof(record.current_directory) - 1u ||
      strcmp(decoded.transport_completeness, "COMPLETE") != 0) {
    return 0;
  }

  init_transport_record(&record);
  fill_boundary_ascii(record.network_aux_path, sizeof(record.network_aux_path), 'n');
  if (!encode_decode_record(&record, wire, wire_cap, &decoded) ||
      decoded.which_detail != edr_v1_BehaviorEvent_network_tag ||
      strlen(decoded.detail.network.network_aux_path) != sizeof(record.network_aux_path) - 1u ||
      strcmp(decoded.transport_completeness, "COMPLETE") != 0) {
    return 0;
  }

  init_transport_record(&record);
  fill_boundary_ascii(record.script_snippet, sizeof(record.script_snippet), 's');
  if (!encode_decode_record(&record, wire, wire_cap, &decoded) ||
      decoded.which_detail != edr_v1_BehaviorEvent_script_tag ||
      strlen(decoded.detail.script.snippet) != sizeof(record.script_snippet) - 1u ||
      strcmp(decoded.transport_completeness, "COMPLETE") != 0) {
    return 0;
  }

  /* A capacity+1 non-terminated UTF-8 input is tagged as truncated, and the
   * final two-byte character is discarded as a unit rather than split. */
  init_transport_record(&record);
  memset(record.cmdline, 'x', sizeof(record.cmdline) - 2u);
  record.cmdline[sizeof(record.cmdline) - 2u] = (char)0xc3;
  record.cmdline[sizeof(record.cmdline) - 1u] = (char)0xa9;
  memset(expected, 'x', sizeof(expected) - 2u);
  expected[sizeof(expected) - 2u] = '\0';
  if (!encode_decode_record(&record, wire, wire_cap, &decoded) ||
      strcmp(decoded.transport_completeness, "TRUNCATED") != 0 ||
      strcmp(decoded.truncated_fields, "cmdline") != 0 ||
      strcmp(decoded.cmdline, expected) != 0 ||
      strlen(decoded.cmdline) != sizeof(record.cmdline) - 2u) {
    return 0;
  }
  return 1;
}

static int verify_source_truncation_projection(uint8_t *wire, size_t wire_cap) {
  EdrBehaviorRecord record;
  edr_v1_BehaviorEvent decoded = edr_v1_BehaviorEvent_init_zero;
  size_t used = 0u;

  /* The encoder accepts a production-created source list verbatim, but still
   * de-duplicates defensively so a later copy/retry can never create two
   * claims for one withheld field. */
  init_transport_record(&record);
  snprintf(record.source_completeness, sizeof(record.source_completeness), "TRUNCATED");
  snprintf(record.source_truncated_fields, sizeof(record.source_truncated_fields),
           "source.process_name,source.process_name,source.exe_hash");
  if (!encode_decode_record(&record, wire, wire_cap, &decoded) ||
      strcmp(decoded.source_completeness, "TRUNCATED") != 0 ||
      strcmp(decoded.transport_completeness, "COMPLETE") != 0 ||
      strcmp(decoded.truncated_fields, "source.process_name,source.exe_hash") != 0) {
    fprintf(stderr, "source list merge mismatch: source=%s transport=%s fields=%s\n",
            decoded.source_completeness, decoded.transport_completeness,
            decoded.truncated_fields);
    return 0;
  }

  /* A full source list plus a real encoder omission must not be silently
   * prefix-truncated.  The stable combined overflow token remains parseable
   * and tells the backend that named omissions are incomplete. */
  init_transport_record(&record);
  snprintf(record.source_completeness, sizeof(record.source_completeness), "TRUNCATED");
  record.source_truncated_fields[0] = '\0';
  for (unsigned i = 0u; i < 32u; ++i) {
    const int n = snprintf(record.source_truncated_fields + used,
                           sizeof(record.source_truncated_fields) - used,
                           "%ssource.x%03u", used ? "," : "", i);
    if (n < 0 || (size_t)n >= sizeof(record.source_truncated_fields) - used) {
      return 0;
    }
    used += (size_t)n;
  }
  if (used != sizeof(record.source_truncated_fields) - 1u) {
    return 0;
  }
  memset(record.cmdline, 'x', sizeof(record.cmdline));
  memset(record.exe_path, 'x', sizeof(record.exe_path));
  memset(record.image_path_raw, 'x', sizeof(record.image_path_raw));
  memset(record.image_path_canonical, 'x', sizeof(record.image_path_canonical));
  memset(record.parent_creation_time, 'x', sizeof(record.parent_creation_time));
  memset(record.detection_context, 'x', sizeof(record.detection_context));
  memset(record.file_path, 'x', sizeof(record.file_path));
  memset(record.reg_key_path, 'x', sizeof(record.reg_key_path));
  memset(record.reg_value_data, 'x', sizeof(record.reg_value_data));
  if (!encode_decode_record(&record, wire, wire_cap, &decoded) ||
      strcmp(decoded.source_completeness, "TRUNCATED") != 0 ||
      strcmp(decoded.transport_completeness, "TRUNCATED") != 0 ||
      strcmp(decoded.truncated_fields, "truncated_fields.list_overflow") != 0) {
    fprintf(stderr, "source list overflow mismatch: source=%s transport=%s fields=%s\n",
            decoded.source_completeness, decoded.transport_completeness,
            decoded.truncated_fields);
    return 0;
  }
  return 1;
}

static void print_base64(const uint8_t *input, size_t input_len) {
  static const char alphabet[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  size_t i;
  for (i = 0u; i < input_len; i += 3u) {
    uint32_t value = (uint32_t)input[i] << 16u;
    const size_t remaining = input_len - i;
    if (remaining > 1u) value |= (uint32_t)input[i + 1u] << 8u;
    if (remaining > 2u) value |= input[i + 2u];
    putchar(alphabet[(value >> 18u) & 0x3fu]);
    putchar(alphabet[(value >> 12u) & 0x3fu]);
    putchar(remaining > 1u ? alphabet[(value >> 6u) & 0x3fu] : '=');
    putchar(remaining > 2u ? alphabet[value & 0x3fu] : '=');
  }
}

static int emit_common_process_context_fixtures(void) {
  static const struct {
    const char *name;
    EdrEventType type;
    uint32_t detail_tag;
  } cases[] = {
      {"process", EDR_EVENT_PROCESS_CREATE, edr_v1_BehaviorEvent_process_tag},
      {"file", EDR_EVENT_FILE_CREATE, edr_v1_BehaviorEvent_file_tag},
      {"network", EDR_EVENT_NET_CONNECT, edr_v1_BehaviorEvent_network_tag},
      {"registry", EDR_EVENT_REG_SET_VALUE, edr_v1_BehaviorEvent_registry_tag},
      {"dns", EDR_EVENT_NET_DNS_QUERY, edr_v1_BehaviorEvent_dns_tag},
      {"script", EDR_EVENT_SCRIPT_POWERSHELL, edr_v1_BehaviorEvent_script_tag},
  };
  uint8_t wire[edr_v1_BehaviorEvent_size];

  for (size_t i = 0u; i < sizeof(cases) / sizeof(cases[0]); ++i) {
    EdrBehaviorRecord record;
    edr_v1_BehaviorEvent decoded = edr_v1_BehaviorEvent_init_zero;
    pb_istream_t stream;
    size_t wire_len;

    init_transport_record(&record);
    record.type = cases[i].type;
    snprintf(record.event_id, sizeof(record.event_id), "c-wire-context-%s", cases[i].name);
    snprintf(record.process_name, sizeof(record.process_name), "actor-%s.exe", cases[i].name);
    snprintf(record.cmdline, sizeof(record.cmdline), "actor-%s.exe --captured", cases[i].name);
    fill_common_process_context(&record, cases[i].name);
    switch (cases[i].detail_tag) {
      case edr_v1_BehaviorEvent_file_tag:
        snprintf(record.file_op, sizeof(record.file_op), "create");
        snprintf(record.file_path, sizeof(record.file_path), "E:/fixture/autorun.inf");
        break;
      case edr_v1_BehaviorEvent_network_tag:
        snprintf(record.net_dst, sizeof(record.net_dst), "203.0.113.20");
        record.net_dport = 443u;
        snprintf(record.net_proto, sizeof(record.net_proto), "tcp");
        break;
      case edr_v1_BehaviorEvent_registry_tag:
        snprintf(record.reg_key_path, sizeof(record.reg_key_path), "HKCU/Software/Fixture");
        snprintf(record.reg_op, sizeof(record.reg_op), "set_value");
        break;
      case edr_v1_BehaviorEvent_dns_tag:
        snprintf(record.dns_query, sizeof(record.dns_query), "fixture.example.invalid");
        break;
      case edr_v1_BehaviorEvent_script_tag:
        snprintf(record.script_snippet, sizeof(record.script_snippet), "Write-Output fixture");
        break;
      default:
        break;
    }

    wire_len = edr_behavior_record_encode_protobuf(&record, wire, sizeof(wire));
    stream = pb_istream_from_buffer(wire, wire_len);
    if (wire_len == 0u ||
        !pb_decode(&stream, edr_v1_BehaviorEvent_fields, &decoded) ||
        decoded.which_detail != cases[i].detail_tag || !decoded.has_process_context ||
        strcmp(decoded.process_context.parent_cmdline, record.parent_cmdline) != 0 ||
        !decoded.process_context.has_token_elevation ||
        decoded.process_context.token_elevation != record.token_elevation) {
      fprintf(stderr, "cannot produce deterministic %s process-context fixture\n", cases[i].name);
      return 0;
    }
    printf("%s\t", cases[i].name);
    print_base64(wire, wire_len);
    putchar('\n');
  }
  return 1;
}

int main(int argc, char **argv) {
  EdrBehaviorRecord record;
  AVEBehaviorAlert alert;
  uint8_t wire[edr_v1_BehaviorEvent_size];
  uint8_t combined_wire[edr_v1_BehaviorEvent_size];
  edr_v1_BehaviorEvent decoded = edr_v1_BehaviorEvent_init_zero;
  size_t combined_wire_len = 0u;
  const int emit_combined_frame =
      argc == 2 && strcmp(argv[1], "--emit-combined-frame-base64") == 0;
  const int emit_process_context_fixtures =
      argc == 2 && strcmp(argv[1], "--emit-process-context-fixtures") == 0;

  if (argc > 1 && !emit_combined_frame && !emit_process_context_fixtures) return 2;

  if (edr_v1_BehaviorEvent_size >= EDR_EVENT_BATCH_CAP) {
    fprintf(stderr, "maximum protobuf event no longer fits one event batch\n");
    return 1;
  }

  memset(&record, 0, sizeof(record));
  snprintf(record.event_id, sizeof(record.event_id), "record-event-123");
  snprintf(record.endpoint_id, sizeof(record.endpoint_id), "endpoint-record");
  snprintf(record.tenant_id, sizeof(record.tenant_id), "tenant-record");
  record.type = EDR_EVENT_PROCESS_CREATE;
  record.event_time_ns = 1720000000123456789LL;
  record.pid = 4242u;
  record.ppid = 3131u;
  snprintf(record.process_name, sizeof(record.process_name), "record.exe");
  snprintf(record.cmdline, sizeof(record.cmdline), "record.exe --from-record");
  snprintf(record.exe_path, sizeof(record.exe_path), "C:/record/record.exe");
  snprintf(record.file_op, sizeof(record.file_op), "write");
  snprintf(record.file_path, sizeof(record.file_path), "C:/record/record.bin");
  snprintf(record.username, sizeof(record.username), "alice");
  snprintf(record.domain, sizeof(record.domain), "EXAMPLE");
  snprintf(record.user_sid, sizeof(record.user_sid), "S-1-5-21-record");
  snprintf(record.identity_source, sizeof(record.identity_source), "target_4688");
  snprintf(record.identity_quality, sizeof(record.identity_quality), "high");
  record.process_start_key = UINT64_C(0x1020304050607080);
  record.process_creation_filetime_100ns = UINT64_C(133444555666777888);
  snprintf(record.process_generation_source, sizeof(record.process_generation_source),
           "live_process_identity");
  snprintf(record.image_path_raw, sizeof(record.image_path_raw),
           "\\\\Device\\\\HarddiskVolume3\\\\record\\\\record.exe");
  snprintf(record.image_path_canonical, sizeof(record.image_path_canonical),
           "C:\\record\\record.exe");
  snprintf(record.image_path_namespace, sizeof(record.image_path_namespace), "win32");
  snprintf(record.image_path_resolution_status, sizeof(record.image_path_resolution_status),
           "RESOLVED");
  snprintf(record.image_path_resolution_source, sizeof(record.image_path_resolution_source),
           "volume_mapping");
  snprintf(record.source_completeness, sizeof(record.source_completeness), "COMPLETE");
  record.evidence_revision = 7u;
  snprintf(record.parent_resolution_status, sizeof(record.parent_resolution_status),
           "RESOLVED");
  snprintf(record.parent_resolution_source, sizeof(record.parent_resolution_source),
           "generation_cache");
  snprintf(record.parent_creation_time, sizeof(record.parent_creation_time),
           "2026-08-31T01:02:03.456Z");
  fill_common_process_context(&record, "record");
  snprintf(record.detection_context, sizeof(record.detection_context),
           "{\"engine\":\"agent\",\"evidence\":{\"hash\":{\"quality\":\"captured\"},"
           "\"signature\":{\"status\":\"verified\",\"source\":\"WinVerifyTrust\","
           "\"signer\":\"Example\",\"thumbprint\":\"abc\",\"revocation\":\"checked\",\"quality\":\"verified_chain\",\"reason\":\"verified\"}}}");

  memset(&alert, 0, sizeof(alert));
  alert.pid = 9999u;
  alert.ppid = 8888u;
  alert.timestamp_ns = 1720000000999999999LL;
  alert.anomaly_score = 0.91f;
  snprintf(alert.process_name, sizeof(alert.process_name), "alert.exe");
  snprintf(alert.process_path, sizeof(alert.process_path), "C:/alert/alert.exe");
  snprintf(alert.user_subject_json, sizeof(alert.user_subject_json),
           "{\"subject_type\":\"ad_sid\",\"value\":\"S-1-5-21-alert\"}");

  const size_t wire_len =
      edr_behavior_record_alert_encode_protobuf(&record, &alert, wire, sizeof(wire));
  if (wire_len == 0u) {
    fprintf(stderr, "combined record/alert encoding failed\n");
    return 1;
  }
  memcpy(combined_wire, wire, wire_len);
  combined_wire_len = wire_len;

  pb_istream_t stream = pb_istream_from_buffer(wire, wire_len);
  if (!pb_decode(&stream, edr_v1_BehaviorEvent_fields, &decoded)) {
    fprintf(stderr, "combined record/alert decoding failed\n");
    return 2;
  }

  if (strcmp(decoded.event_id, record.event_id) != 0 || decoded.pid != record.pid ||
      strcmp(decoded.exe_path, record.exe_path) != 0 ||
      strcmp(decoded.username, record.username) != 0 || strcmp(decoded.domain, record.domain) != 0 ||
      strcmp(decoded.user_sid, record.user_sid) != 0 ||
      strcmp(decoded.identity_source, record.identity_source) != 0 ||
      strcmp(decoded.identity_quality, record.identity_quality) != 0 ||
      decoded.process_start_key != record.process_start_key ||
      decoded.process_creation_filetime_100ns != record.process_creation_filetime_100ns ||
      strcmp(decoded.process_generation_source, record.process_generation_source) != 0 ||
      strcmp(decoded.image_path_raw, record.image_path_raw) != 0 ||
      strcmp(decoded.image_path_canonical, record.image_path_canonical) != 0 ||
      strcmp(decoded.image_path_namespace, record.image_path_namespace) != 0 ||
      strcmp(decoded.image_path_resolution_status, record.image_path_resolution_status) != 0 ||
      strcmp(decoded.image_path_resolution_source, record.image_path_resolution_source) != 0 ||
      strcmp(decoded.source_completeness, record.source_completeness) != 0 ||
      decoded.evidence_revision != record.evidence_revision ||
      strcmp(decoded.parent_resolution_status, record.parent_resolution_status) != 0 ||
      strcmp(decoded.parent_resolution_source, record.parent_resolution_source) != 0 ||
      strcmp(decoded.parent_creation_time, record.parent_creation_time) != 0 ||
      !decoded.has_process_context ||
      strcmp(decoded.process_context.parent_cmdline, record.parent_cmdline) != 0 ||
      strcmp(decoded.process_context.current_directory, record.current_directory) != 0 ||
      strcmp(decoded.process_context.integrity_level, record.integrity_level) != 0 ||
      !decoded.process_context.has_token_elevation ||
      decoded.process_context.token_elevation != record.token_elevation ||
      strcmp(decoded.transport_completeness, "COMPLETE") != 0 ||
      decoded.truncated_fields[0] != '\0') {
    fprintf(stderr, "top-level record fields were not preserved\n");
    return 3;
  }
  if (!decoded.has_behavior_alert ||
      strcmp(decoded.behavior_alert.user_subject_json, alert.user_subject_json) != 0 ||
      strcmp(decoded.behavior_alert.user_subject_status, "present") != 0 ||
      decoded.behavior_alert.user_subject_withheld_reason[0] != '\0') {
    fprintf(stderr, "nested behavior alert user subject was not preserved\n");
    return 4;
  }
  if (!strstr(decoded.ave_result_json, "\"engine\":\"agent\"") ||
      !strstr(decoded.ave_result_json, "\"signer\":\"Example\"") ||
      !strstr(decoded.ave_result_json, "\"revocation\":\"checked\"")) {
    fprintf(stderr, "evidence fields were not serialized\n");
    return 5;
  }

  memset(&alert, 0, sizeof(alert));
  alert.pid = 9999u;
  alert.timestamp_ns = 1720000000999999999LL;
  snprintf(alert.process_name, sizeof(alert.process_name), "alert.exe");
  const size_t pure_wire_len = edr_behavior_alert_encode_protobuf(
      &alert, "endpoint-record", "tenant-record", wire, sizeof(wire));
  if (pure_wire_len == 0u) {
    fprintf(stderr, "pure alert encoding failed\n");
    return 6;
  }
  memset(&decoded, 0, sizeof(decoded));
  stream = pb_istream_from_buffer(wire, pure_wire_len);
  if (!pb_decode(&stream, edr_v1_BehaviorEvent_fields, &decoded) ||
      !decoded.has_behavior_alert ||
      strcmp(decoded.behavior_alert.user_subject_status, "withheld") != 0 ||
      strcmp(decoded.behavior_alert.user_subject_withheld_reason, "not_provided_by_agent") != 0 ||
      decoded.behavior_alert.user_subject_json[0] != '\0') {
    fprintf(stderr, "pure alert user subject withholding was not explicit\n");
    return 7;
  }
  if (!verify_transport_boundaries(wire, sizeof(wire))) {
    fprintf(stderr, "transport boundary or UTF-8 truncation contract failed\n");
    return 8;
  }
  if (!verify_parent_identity_across_detail_oneofs(wire, sizeof(wire))) {
    return 9;
  }
  if (!verify_source_truncation_projection(wire, sizeof(wire))) {
    fprintf(stderr, "source truncation projection contract failed\n");
    return 10;
  }
  if (emit_combined_frame) {
    print_base64(combined_wire, combined_wire_len);
    putchar('\n');
  }
  if (emit_process_context_fixtures && !emit_common_process_context_fixtures()) {
    return 11;
  }
  return 0;
}
