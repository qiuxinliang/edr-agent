#include "edr/behavior_alert_emit.h"

#include "edr/alert_governor.h"
#include "edr/behavior_proto.h"
#include "edr/event_batch.h"
#include "edr/preprocess.h"
#include "edr/policy_v2.h"
#include "edr/process_tree_cache.h"
#include "edr/p0_source_only_contract.h"
#include "edr/sha256.h"
#include "edr/storage_queue.h"
#include "edr/transport_sink.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

#ifndef EDR_HAVE_NANOPB
#pragma message("WARNING: EDR_HAVE_NANOPB not defined; ALL P0 and AVE behavior alerts will be silently dropped. Build with nanopb support for production use.")
#endif

static void warn_encoding_once(void) {
  static int s_done;
  const char *enc = getenv("EDR_BEHAVIOR_ENCODING");
  if (s_done) {
    return;
  }
  if (enc && strcmp(enc, "protobuf") != 0 && strcmp(enc, "protobuf_c") != 0) {
    fprintf(stderr,
            "[edr] behavior alert frames use protobuf; for platform ingest use "
            "EDR_BEHAVIOR_ENCODING=protobuf (or protobuf_c) so batches are uniformly decodable.\n");
  }
  s_done = 1;
}

#ifdef EDR_HAVE_NANOPB
static int process_name_is_placeholder(const char *name) {
  if (!name || !name[0]) return 1;
  if (strncmp(name, "pid:", 4) != 0) return 0;
  const char *p = name + 4;
  if (!*p) return 0;
  while (*p >= '0' && *p <= '9') p++;
  return *p == '\0';
}

static void enrich_alert_process_snapshot(AVEBehaviorAlert *alert) {
  if (!alert || alert->pid == 0u) return;
  ProcessTreeEntry snapshot;
  uint64_t event_time_ns = alert->timestamp_ns > 0 ? (uint64_t)alert->timestamp_ns : 0u;
  if (edr_pt_cache_snapshot_at(alert->pid, event_time_ns, &snapshot) != 0) return;
  if (process_name_is_placeholder(alert->process_name) && snapshot.process_name[0]) {
    snprintf(alert->process_name, sizeof(alert->process_name), "%s", snapshot.process_name);
  }
  if (!alert->process_path[0] && snapshot.exe_path[0]) {
    snprintf(alert->process_path, sizeof(alert->process_path), "%s", snapshot.exe_path);
  }
  if (alert->ppid == 0u) alert->ppid = snapshot.ppid;
  if (!alert->cmdline[0] && snapshot.cmdline[0]) {
    snprintf(alert->cmdline, sizeof(alert->cmdline), "%s", snapshot.cmdline);
  }
}

static int emit_raw(const AVEBehaviorAlert *a, const char *ep, const char *te) {
  uint8_t buf[65536];
  size_t n = edr_behavior_alert_encode_protobuf(a, ep, te, buf, sizeof(buf));
  if (n > 0) {
    return edr_event_batch_push(buf, n) == 0;
  } else {
    static int s_logged_once = 0;
    if (!s_logged_once) {
      fprintf(stderr, "[P0 WARN] Alert encode failed: endpoint=%s tenant=%s\n", ep, te);
      s_logged_once = 1;
    }
  }
  return 0;
}

static size_t behavior_frame_encode_durable_wire(const uint8_t *frame, size_t frame_len,
                                                 uint8_t *wire, size_t wire_cap) {
  size_t body_len;
  size_t wire_len;
  if (!frame || frame_len == 0u || !wire || frame_len > UINT32_MAX - 4u) {
    return 0u;
  }
  body_len = 4u + frame_len;
  wire_len = 12u + body_len;
  if (wire_len > wire_cap) {
    return 0u;
  }
  /* BAT1 header + exactly one length-prefixed protobuf frame. */
  wire[0] = (uint8_t)(EDR_TRANSPORT_BATCH_MAGIC_RAW & 0xffu);
  wire[1] = (uint8_t)((EDR_TRANSPORT_BATCH_MAGIC_RAW >> 8) & 0xffu);
  wire[2] = (uint8_t)((EDR_TRANSPORT_BATCH_MAGIC_RAW >> 16) & 0xffu);
  wire[3] = (uint8_t)((EDR_TRANSPORT_BATCH_MAGIC_RAW >> 24) & 0xffu);
  wire[4] = 1u; wire[5] = 0u; wire[6] = 0u; wire[7] = 0u;
  wire[8] = (uint8_t)(body_len & 0xffu);
  wire[9] = (uint8_t)((body_len >> 8) & 0xffu);
  wire[10] = (uint8_t)((body_len >> 16) & 0xffu);
  wire[11] = (uint8_t)((body_len >> 24) & 0xffu);
  wire[12] = (uint8_t)(frame_len & 0xffu);
  wire[13] = (uint8_t)((frame_len >> 8) & 0xffu);
  wire[14] = (uint8_t)((frame_len >> 16) & 0xffu);
  wire[15] = (uint8_t)((frame_len >> 24) & 0xffu);
  memcpy(wire + 16u, frame, frame_len);
  return wire_len;
}

int edr_behavior_durable_wire_batch_id(const char *kind, const uint8_t *wire, size_t wire_len,
                                       char *out, size_t out_cap) {
  char sha256[65];
  if (!kind || !wire || wire_len == 0u || !out || out_cap == 0u ||
      edr_sha256_hex(wire, wire_len, sha256) != 0) {
    if (out && out_cap > 0u) out[0] = '\0';
    return 0;
  }
  snprintf(out, out_cap, "%s-%s", kind, sha256);
  return out[0] != '\0';
}

size_t edr_behavior_record_alert_encode_durable_wire(const EdrBehaviorRecord *record,
                                                      const AVEBehaviorAlert *alert,
                                                      uint8_t *wire, size_t wire_cap) {
#ifdef EDR_HAVE_NANOPB
  uint8_t frame[65536];
  size_t n = edr_behavior_record_alert_encode_protobuf(record, alert, frame, sizeof(frame));
  return behavior_frame_encode_durable_wire(frame, n, wire, wire_cap);
#else
  (void)record;
  (void)alert;
  (void)wire;
  (void)wire_cap;
  return 0u;
#endif
}

size_t edr_behavior_record_encode_durable_wire(const EdrBehaviorRecord *record,
                                               uint8_t *wire, size_t wire_cap) {
#ifdef EDR_HAVE_NANOPB
  uint8_t frame[65536];
  size_t n = edr_behavior_record_encode_protobuf(record, frame, sizeof(frame));
  return behavior_frame_encode_durable_wire(frame, n, wire, wire_cap);
#else
  (void)record;
  (void)wire;
  (void)wire_cap;
  return 0u;
#endif
}

static int enqueue_durable_p0_wire(const char *batch_id, const uint8_t *wire, size_t wire_len,
                                   int severity) {
  if (!batch_id || !batch_id[0] || !wire || wire_len == 0u || !edr_storage_queue_is_open()) {
    return 0;
  }
  return edr_storage_queue_enqueue(batch_id, wire, wire_len, 0, severity) == EDR_OK;
}

static int emit_record_alert_raw(const EdrBehaviorRecord *record, const AVEBehaviorAlert *alert) {
  uint8_t wire[65536 + 16u];
  char batch_id[128];
  size_t wire_len = edr_behavior_record_alert_encode_durable_wire(record, alert, wire, sizeof(wire));
  if (wire_len == 0u ||
      !edr_behavior_durable_wire_batch_id("p0", wire, wire_len, batch_id, sizeof(batch_id))) {
    return 0;
  }
  return enqueue_durable_p0_wire(batch_id, wire, wire_len,
                                 EDR_STORAGE_QUEUE_SEVERITY_TERMINAL);
}

typedef struct CombinedEmitContext {
  const EdrBehaviorRecord *record;
  const AVEBehaviorAlert *alert;
  EdrBehaviorRecordAlertPrepareFn prepare;
  void *prepare_context;
} CombinedEmitContext;

static int emit_record_alert_callback(void *context) {
  CombinedEmitContext *combined = context;
  if (!combined) return 0;
  if (combined->prepare && !combined->prepare(combined->prepare_context)) return 0;
  return emit_record_alert_raw(combined->record, combined->alert);
}

static void emit_volume_summary(uint64_t suppressed_count, uint64_t timestamp_ns,
                                const char *ep, const char *te) {
  AVEBehaviorAlert summary;
  memset(&summary, 0, sizeof(summary));
  summary.timestamp_ns = timestamp_ns;
  summary.anomaly_score = 0.1f;
  summary.skip_ai_analysis = true;
  snprintf(summary.process_name, sizeof(summary.process_name), "edr-agent");
  snprintf(summary.triggered_tactics, sizeof(summary.triggered_tactics), "alert_volume_control");
  snprintf(summary.user_subject_json, sizeof(summary.user_subject_json),
           "{\"rule_id\":\"alert_cardinality_summary\",\"suppressed_count\":%llu,"
           "\"period_seconds\":60,\"source\":\"agent_alert_governor\"}",
           (unsigned long long)suppressed_count);
  emit_raw(&summary, ep, te);
}
#else
size_t edr_behavior_record_alert_encode_durable_wire(const EdrBehaviorRecord *record,
                                                      const AVEBehaviorAlert *alert,
                                                      uint8_t *wire, size_t wire_cap) {
  (void)record;
  (void)alert;
  (void)wire;
  (void)wire_cap;
  return 0u;
}

size_t edr_behavior_record_encode_durable_wire(const EdrBehaviorRecord *record,
                                               uint8_t *wire, size_t wire_cap) {
  (void)record;
  (void)wire;
  (void)wire_cap;
  return 0u;
}

int edr_behavior_durable_wire_batch_id(const char *kind, const uint8_t *wire, size_t wire_len,
                                       char *out, size_t out_cap) {
  char sha256[65];
  if (!kind || !wire || wire_len == 0u || !out || out_cap == 0u ||
      edr_sha256_hex(wire, wire_len, sha256) != 0) {
    if (out && out_cap > 0u) out[0] = '\0';
    return 0;
  }
  snprintf(out, out_cap, "%s-%s", kind, sha256);
  return out[0] != '\0';
}
#endif

void edr_behavior_alert_emit_to_batch(const AVEBehaviorAlert *a) {
  if (!a) {
    return;
  }
  if (!edr_policy_v2_alert_allowed(a->triggered_tactics, a->user_subject_json)) {
    return;
  }
#ifdef EDR_HAVE_NANOPB
  EdrAlertGovernorDecision decision;
  warn_encoding_once();
  char ep[128];
  char te[128];
  edr_preprocess_copy_agent_ids(ep, sizeof(ep), te, sizeof(te));
  edr_alert_governor_admit(a, 0, &decision);
  if (decision.emit_summary) {
    emit_volume_summary(decision.summary_suppressed, a->timestamp_ns, ep, te);
  }
  if (decision.allow_original) {
    AVEBehaviorAlert enriched = *a;
    enrich_alert_process_snapshot(&enriched);
    emit_raw(&enriched, ep, te);
    static int s_debug_enabled = -1;
    if (s_debug_enabled < 0) {
      s_debug_enabled = (getenv("EDR_P0_DEBUG") != NULL) ? 1 : 0;
    }
    if (s_debug_enabled) {
      fprintf(stderr, "[P0 DEBUG] Alert emitted: endpoint=%s tenant=%s\n", ep, te);
    }
  }
#else
  {
    static int s_no_nanopb_logged = 0;
    if (!s_no_nanopb_logged) {
      fprintf(stderr,
              "[edr] FATAL: EDR_HAVE_NANOPB is not defined; ALL behavior alerts "
              "(P0 direct emit + AVE behavior heuristic) are being SILENTLY DISCARDED. "
              "Rebuild with nanopb support enabled.\n");
      s_no_nanopb_logged = 1;
    }
  }
  (void)a;
#endif
}

EdrBehaviorRecordAlertEmitOutcome edr_behavior_record_alert_emit_to_batch_with_prepare_outcome(
    const EdrBehaviorRecord *record, const AVEBehaviorAlert *alert,
    EdrBehaviorRecordAlertPrepareFn prepare, void *prepare_context) {
  if (!record || !alert) {
    return EDR_BEHAVIOR_RECORD_ALERT_EMIT_PREPARE_OR_QUEUE_FAILED;
  }
  if (!edr_policy_v2_alert_allowed(alert->triggered_tactics, alert->user_subject_json)) {
    return EDR_BEHAVIOR_RECORD_ALERT_EMIT_POLICY_DENIED;
  }
#ifdef EDR_HAVE_NANOPB
  EdrAlertGovernorDecision decision;
  EdrAlertGovernorEmitOutcome governor_outcome;
  CombinedEmitContext combined;
  warn_encoding_once();
  AVEBehaviorAlert enriched = *alert;
  enrich_alert_process_snapshot(&enriched);
  combined.record = record;
  combined.alert = &enriched;
  combined.prepare = prepare;
  combined.prepare_context = prepare_context;
  governor_outcome = edr_alert_governor_admit_and_emit(
      alert, 0, emit_record_alert_callback, &combined, &decision);
  if (decision.emit_summary) {
    char ep[128];
    char te[128];
    edr_preprocess_copy_agent_ids(ep, sizeof(ep), te, sizeof(te));
    emit_volume_summary(decision.summary_suppressed, alert->timestamp_ns, ep, te);
  }
  if (governor_outcome == EDR_ALERT_GOVERNOR_EMIT_ACCEPTED) {
    return EDR_BEHAVIOR_RECORD_ALERT_EMIT_ACCEPTED;
  }
  if (governor_outcome == EDR_ALERT_GOVERNOR_EMIT_SUPPRESSED) {
    return EDR_BEHAVIOR_RECORD_ALERT_EMIT_GOVERNOR_SUPPRESSED;
  }
  return EDR_BEHAVIOR_RECORD_ALERT_EMIT_PREPARE_OR_QUEUE_FAILED;
#else
  (void)prepare;
  (void)prepare_context;
  return EDR_BEHAVIOR_RECORD_ALERT_EMIT_PREPARE_OR_QUEUE_FAILED;
#endif
}

int edr_behavior_record_alert_emit_to_batch_with_prepare(
    const EdrBehaviorRecord *record, const AVEBehaviorAlert *alert,
    EdrBehaviorRecordAlertPrepareFn prepare, void *prepare_context) {
  return edr_behavior_record_alert_emit_to_batch_with_prepare_outcome(
             record, alert, prepare, prepare_context) ==
         EDR_BEHAVIOR_RECORD_ALERT_EMIT_ACCEPTED;
}

int edr_behavior_record_alert_emit_to_batch(const EdrBehaviorRecord *record,
                                            const AVEBehaviorAlert *alert) {
  return edr_behavior_record_alert_emit_to_batch_with_prepare(record, alert, NULL, NULL);
}

int edr_behavior_record_emit_durable(const EdrBehaviorRecord *record) {
#ifdef EDR_HAVE_NANOPB
  uint8_t wire[65536 + 16u];
  char batch_id[128];
  if (!record || !edr_p0_source_only_validate_record(record)) {
    return 0;
  }
  size_t wire_len = edr_behavior_record_encode_durable_wire(record, wire, sizeof(wire));
  if (wire_len == 0u ||
      !edr_behavior_durable_wire_batch_id("p0-source", wire, wire_len,
                                          batch_id, sizeof(batch_id))) {
    return 0;
  }
  return enqueue_durable_p0_wire(batch_id, wire, wire_len,
                                 EDR_STORAGE_QUEUE_SEVERITY_P0_SOURCE_ONLY);
#else
  (void)record;
  return 0;
#endif
}

void edr_behavior_alert_emit_periodic_summary(void) {
#ifdef EDR_HAVE_NANOPB
  uint64_t suppressed_count = 0;
  static int64_t s_last_poll_second;
  int64_t now_s = (int64_t)time(NULL);
  char ep[128];
  char te[128];
  if (now_s == s_last_poll_second) return;
  s_last_poll_second = now_s;
  if (!edr_alert_governor_poll_summary(now_s, &suppressed_count)) return;
  edr_preprocess_copy_agent_ids(ep, sizeof(ep), te, sizeof(te));
  emit_volume_summary(suppressed_count, (uint64_t)now_s * 1000000000ULL, ep, te);
#endif
}
