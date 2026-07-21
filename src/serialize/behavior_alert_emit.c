#include "edr/behavior_alert_emit.h"

#include "edr/alert_governor.h"
#include "edr/behavior_proto.h"
#include "edr/event_batch.h"
#include "edr/preprocess.h"
#include "edr/policy_v2.h"
#include "edr/process_tree_cache.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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

static void emit_raw(const AVEBehaviorAlert *a, const char *ep, const char *te) {
  uint8_t buf[65536];
  size_t n = edr_behavior_alert_encode_protobuf(a, ep, te, buf, sizeof(buf));
  if (n > 0) {
    (void)edr_event_batch_push(buf, n);
  } else {
    static int s_logged_once = 0;
    if (!s_logged_once) {
      fprintf(stderr, "[P0 WARN] Alert encode failed: endpoint=%s tenant=%s\n", ep, te);
      s_logged_once = 1;
    }
  }
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
              "(P0 direct emit + AVE ONNX) are being SILENTLY DISCARDED. "
              "Rebuild with nanopb support enabled.\n");
      s_no_nanopb_logged = 1;
    }
  }
  (void)a;
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
