/**
 * Transport protocol v2 abstraction.
 *
 * This is the stable Agent-side boundary for the HTTPS/TLS v2 transport.  The
 * first implementation delegates to the existing HTTP/2-capable ingest stack,
 * while exposing openStream / send / onControl / ack / resume semantics so the
 * lower layer can later move to a single CURLM/nghttp2 dispatcher without
 * touching collectors, command handlers, or upload code.
 */
#ifndef EDR_TRANSPORT_V2_H
#define EDR_TRANSPORT_V2_H

#include <stddef.h>
#include <stdint.h>

struct EdrConfig;
struct EdrSoarCommandMeta;

typedef enum {
  EDR_TV2_CHANNEL_CONTROL = 1,
  EDR_TV2_CHANNEL_HIGH_SEV_TELEMETRY = 2,
  EDR_TV2_CHANNEL_NORMAL_TELEMETRY = 3,
  EDR_TV2_CHANNEL_BACKFILL = 4,
  EDR_TV2_CHANNEL_UPLOAD = 5,
  EDR_TV2_CHANNEL_COMMAND_RESULT = 6
} EdrTransportV2Channel;

typedef enum {
  EDR_TV2_OP_REPORT_EVENTS = 1,
  EDR_TV2_OP_COMMAND_RESULT = 2,
  EDR_TV2_OP_UPLOAD_FILE = 3,
  EDR_TV2_OP_CONTROL_STREAM = 4,
  EDR_TV2_OP_CONTROL_ACK = 5,
  EDR_TV2_OP_RESUME = 6
} EdrTransportV2Operation;

typedef struct {
  int enabled;
  int h2_enabled;
  int h2_required;
  int control_stream_enabled;
  int long_poll_fallback;
  int report_events_v2_enabled;
  int zstd_requested;
  int backpressure_enabled;
  unsigned telemetry_sampling_pct;
  char data_plane_encoding[32];
  char data_plane_compression[32];
  char dict_ver[64];
  char schema_ver[64];
  char profile_id[64];
  char qos_dscp[32];
  char threshold[32];
} EdrTransportV2Config;

typedef struct {
  int configured;
  int enabled;
  int h2_enabled;
  int h2_required;
  int control_stream_enabled;
  int long_poll_fallback;
  int report_events_v2_enabled;
  int zstd_requested;
  int backpressure_enabled;
  unsigned telemetry_sampling_pct;
  unsigned long opened_streams;
  unsigned long send_ok;
  unsigned long send_fail;
  unsigned long ack_ok;
  unsigned long ack_fail;
  unsigned long resume_count;
  unsigned long control_frames;
  unsigned long channel_control;
  unsigned long channel_high_sev;
  unsigned long channel_normal;
  unsigned long channel_backfill;
  unsigned long channel_upload;
  unsigned long channel_command_result;
  char active_channel[32];
  char last_operation[32];
  char last_error[160];
  char data_plane_encoding[32];
  char data_plane_compression[32];
  char envelope_format[32];
  char dict_ver[64];
  char schema_ver[64];
  char profile_id[64];
  char qos_dscp[32];
  char threshold[32];
} EdrTransportV2Runtime;

void edr_transport_v2_init_from_config(const struct EdrConfig *cfg);
void edr_transport_v2_get_config(EdrTransportV2Config *out);
void edr_transport_v2_get_runtime(EdrTransportV2Runtime *out);
void edr_transport_v2_apply_profile(const char *dict_ver, const char *schema_ver,
                                    const char *profile_id, int h2, int zstd,
                                    const char *qos_dscp, unsigned sampling_pct,
                                    const char *threshold, int backpressure_enabled);

int edr_transport_v2_open_stream(EdrTransportV2Channel channel, EdrTransportV2Operation op);
int edr_transport_v2_send(int stream_id, const void *data, size_t len);
void edr_transport_v2_on_control(const char *frame_type);
void edr_transport_v2_ack(const char *command_id, int ok);
void edr_transport_v2_resume(const char *cursor);

int edr_transport_v2_report_events(const char *batch_id, const uint8_t *header12,
                                   size_t header_len, const uint8_t *payload,
                                   size_t payload_len);
int edr_transport_v2_command_result(const char *command_id,
                                    const struct EdrSoarCommandMeta *meta,
                                    int execution_status, int exit_code,
                                    const char *detail_utf8);
int edr_transport_v2_command_result_typed(const char *command_id, const char *command_type,
                                          const struct EdrSoarCommandMeta *meta,
                                          int execution_status, int exit_code,
                                          const char *detail_utf8);
int edr_transport_v2_upload_file(const char *upload_id, const char *file_path,
                                 const char *sha256_hex, char *out_minio_key,
                                 size_t out_minio_key_cap);

#endif
