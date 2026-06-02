#include "edr/agent.h"

#include "edr/adaptive_collection.h"
#include "edr/ave_sdk.h"
#include "edr/behavior_alert_emit.h"
#include "edr/config.h"
#include "edr/event_bus.h"
#include "edr/preprocess.h"
#include "edr/resource.h"
#include "edr/self_protect.h"
#include "edr/sensor_interest.h"
#include "edr/shell_session.h"
#include "edr/shellcode_known.h"
#include "edr/time_util.h"

#if defined(EDR_WITH_FL_TRAINER)
#include "edr/fl_trainer.h"
#endif

#include "edr/attack_surface_report.h"
#include "edr/collector.h"
#include "edr/command.h"
#include "edr/grpc_client.h"
#include "edr/ingest_http.h"
#include "edr/local_evidence_cache.h"
#include "edr/p0_rule_ir.h"
#include "edr/pmfe.h"
#include "edr/storage_queue.h"
#include "edr/transport_sink.h"
#include "edr/windows_event_policy.h"
#ifdef _WIN32
#include <windows.h>
static void edr_ms_sleep(unsigned ms) { Sleep(ms); }
#else
#include <unistd.h>
static void edr_ms_sleep(unsigned ms) { usleep(ms * 1000u); }
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sys/stat.h>

#ifdef _WIN32
#define EDR_AGENT_STRDUP _strdup
#else
#define EDR_AGENT_STRDUP strdup
#endif

#ifndef EDR_AGENT_VERSION_STRING
#define EDR_AGENT_VERSION_STRING "0.3.0"
#endif

#define EDR_REMOTE_POLICY_COLLECTION_CHANGED 0x01

static int edr_agent_download_text_file(const char *url, const char *tmp, size_t max_bytes,
                                        const char *label) {
  if (!url || !url[0] || !tmp || !tmp[0]) {
    return -1;
  }
  if (edr_ingest_http_get_url_to_file(url, tmp, max_bytes) == 0) {
    return 0;
  }
  fprintf(stderr, "[config] %s pull failed via native HTTPS client\n",
          label && label[0] ? label : "remote config");
  return -1;
}

static int edr_agent_file_has_magic(const char *path, const char *magic, size_t magic_len) {
  char buf[8];
  FILE *f;
  size_t n;
  if (!path || !path[0] || !magic || magic_len == 0u || magic_len > sizeof(buf)) {
    return 0;
  }
  f = fopen(path, "rb");
  if (!f) {
    return 0;
  }
  n = fread(buf, 1u, magic_len, f);
  fclose(f);
  return n == magic_len && memcmp(buf, magic, magic_len) == 0 ? 1 : 0;
}

static int edr_agent_files_equal(const char *a, const char *b) {
  FILE *fa;
  FILE *fb;
  unsigned char ba[8192];
  unsigned char bb[8192];
  int equal = 0;
  if (!a || !a[0] || !b || !b[0]) {
    return 0;
  }
  fa = fopen(a, "rb");
  if (!fa) {
    return 0;
  }
  fb = fopen(b, "rb");
  if (!fb) {
    fclose(fa);
    return 0;
  }
  equal = 1;
  for (;;) {
    size_t na = fread(ba, 1u, sizeof(ba), fa);
    size_t nb = fread(bb, 1u, sizeof(bb), fb);
    if (na != nb || (na > 0u && memcmp(ba, bb, na) != 0)) {
      equal = 0;
      break;
    }
    if (na == 0u) {
      if (ferror(fa) || ferror(fb)) {
        equal = 0;
      }
      break;
    }
  }
  fclose(fa);
  fclose(fb);
  return equal;
}

static int edr_agent_replace_file(const char *src, const char *dst) {
  if (!src || !src[0] || !dst || !dst[0]) {
    return -1;
  }
#ifdef _WIN32
  if (MoveFileExA(src, dst, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
    return 0;
  }
  return -1;
#else
  return rename(src, dst);
#endif
}

struct EdrAgent {
  EdrEventBus *event_bus;
  char *config_path;
  EdrConfig cfg;
  time_t config_mtime;
  int shutdown;
  int collector_started;
  /** §19.8 周期快照：上次全量定时采集单调时钟（ns） */
  uint64_t asurf_last_post_ns;
  /** §19.6 上次轮询 refresh-request 的时间（ns） */
  uint64_t asurf_last_pending_check_ns;
};

static void AVE_CALL edr_agent_on_behavior_alert(const AVEBehaviorAlert *alert, void *user_data) {
  (void)user_data;
  edr_behavior_alert_emit_to_batch(alert);
}

static void edr_agent_register_ave_behavior_callbacks(EdrAgent *agent) {
  AVECallbacks callbacks;
  memset(&callbacks, 0, sizeof(callbacks));
  callbacks.on_behavior_alert = edr_agent_on_behavior_alert;
  callbacks.user_data = agent;

  int cr = AVE_RegisterCallbacks(&callbacks);
  if (cr != AVE_OK) {
    fprintf(stderr, "[ave] AVE_RegisterCallbacks failed: %d\n", cr);
    return;
  }
  int mr = AVE_StartBehaviorMonitor();
  if (mr != AVE_OK) {
    fprintf(stderr, "[ave] AVE_StartBehaviorMonitor failed: %d\n", mr);
  }
  AVEStatus st;
  memset(&st, 0, sizeof(st));
  (void)AVE_GetStatus(&st);
  fprintf(stderr,
          "[ave] on_behavior_alert=1 behavior_monitor=%d model_dir=%s "
          "static_model=%s behavior_model=%s l4_th=%.2f\n",
          st.behavior_monitor_running ? 1 : 0,
          agent ? agent->cfg.ave.model_dir : "",
          st.static_model_version,
          st.behavior_model_version,
          agent ? (double)agent->cfg.ave.l4_realtime_anomaly_threshold : 0.0);
}

static void edr_agent_apply_event_filter_config(const EdrConfig *cfg) {
  EdrWindowsEventFilterConfig fc;
  memset(&fc, 0, sizeof(fc));
  if (!cfg) {
    edr_windows_event_policy_configure(NULL);
    return;
  }
  fc.enabled = cfg->event_filter.enabled ? 1u : 0u;
  fc.agent_internal_forensic = cfg->event_filter.agent_internal_forensic ? 1u : 0u;
  fc.low_value_file_process = cfg->event_filter.low_value_file_process ? 1u : 0u;
  fc.low_value_file_suffix = cfg->event_filter.low_value_file_suffix ? 1u : 0u;
  fc.temp_xml = cfg->event_filter.temp_xml ? 1u : 0u;
  snprintf(fc.version, sizeof(fc.version), "%s", cfg->event_filter.version);
  edr_windows_event_policy_configure(&fc);
}

EdrAgent *edr_agent_create(void) {
  return (EdrAgent *)calloc(1, sizeof(EdrAgent));
}

void edr_agent_destroy(EdrAgent *agent) {
  if (!agent) {
    return;
  }
  edr_preprocess_stop();
  edr_self_protect_shutdown();
  edr_resource_shutdown();
#if defined(EDR_WITH_FL_TRAINER)
  FLT_Shutdown();
#endif
  AVE_Shutdown();
  edr_event_bus_destroy(agent->event_bus);
  edr_config_free_heap(&agent->cfg);
  free(agent->config_path);
  free(agent);
}

EdrError edr_agent_init(EdrAgent *agent, const char *config_path) {
  if (!agent) {
    return EDR_ERR_INVALID_ARG;
  }
  if (config_path && config_path[0]) {
    agent->config_path = EDR_AGENT_STRDUP(config_path);
    if (!agent->config_path) {
      return EDR_ERR_INTERNAL;
    }
  }
  {
    const char *load_path =
        (config_path && config_path[0]) ? config_path : NULL;
    EdrError ce = edr_config_load(load_path, &agent->cfg);
    if (ce != EDR_OK) {
      return ce;
    }
    agent->config_mtime = (time_t)0;
    if (load_path) {
      struct stat st;
      if (stat(load_path, &st) == 0) {
        agent->config_mtime = st.st_mtime;
      }
      char fp[80];
      edr_config_fingerprint(load_path, fp, sizeof(fp));
      if (fp[0]) {
        fprintf(stderr, "[config] fingerprint=%s path=%s\n", fp, load_path);
      }
    }
  }
  edr_self_protect_init();
  edr_adaptive_collection_configure(&agent->cfg);
  edr_agent_apply_event_filter_config(&agent->cfg);
  edr_resource_init(&agent->cfg);
  {
    int ar = AVE_InitFromEdrConfig(&agent->cfg);
    if (ar != AVE_OK) {
      fprintf(stderr, "[ave] AVE_InitFromEdrConfig failed: %d\n", ar);
    } else {
      edr_agent_register_ave_behavior_callbacks(agent);
    }
  }
#if defined(EDR_WITH_FL_TRAINER)
  if (agent->cfg.fl.enabled) {
    int fr = FLT_InitFromEdrConfig(&agent->cfg);
    if (fr != FLT_OK) {
      fprintf(stderr, "[fl] FLT_InitFromEdrConfig failed: %d\n", fr);
    } else {
      fr = FLT_Start();
      if (fr != FLT_OK) {
        fprintf(stderr, "[fl] FLT_Start failed: %d\n", fr);
        FLT_Shutdown();
      }
    }
  }
#endif
  agent->event_bus =
      edr_event_bus_create(agent->cfg.collection.max_event_queue_size);
  if (!agent->event_bus) {
#if defined(EDR_WITH_FL_TRAINER)
    FLT_Shutdown();
#endif
    AVE_Shutdown();
    edr_resource_shutdown();
    edr_self_protect_shutdown();
    return EDR_ERR_INTERNAL;
  }
  edr_self_protect_apply_config(&agent->cfg);
  edr_self_protect_set_event_bus(agent->event_bus);
  return EDR_OK;
}

static void edr_agent_poll_config_reload(EdrAgent *agent, uint64_t *last_reload_ns);
static void edr_agent_poll_remote_config(EdrAgent *agent, uint64_t *last_remote_ns);
static void edr_agent_poll_p0_bundle(EdrAgent *agent, uint64_t *last_p0_bundle_ns);
static void edr_agent_poll_sensor_interest(EdrAgent *agent, uint64_t *last_sensor_interest_ns);
static void edr_agent_poll_attack_surface(EdrAgent *agent);
static void edr_agent_poll_engine_health(EdrAgent *agent, uint64_t *last_health_ns);

static int edr_agent_collection_enabled(const EdrConfig *cfg) {
  if (!cfg) {
    return 0;
  }
  return cfg->collection.etw_enabled || cfg->collection.ebpf_enabled || cfg->collection.auditd_enabled;
}

EdrError edr_agent_run(EdrAgent *agent) {
  if (!agent || !agent->event_bus) {
    return EDR_ERR_INVALID_ARG;
  }
  {
    EdrError pe = edr_preprocess_start(agent->event_bus, &agent->cfg);
    if (pe != EDR_OK) {
      return pe;
    }
  }
  {
    uint64_t last_reload_ns = 0;
    uint64_t last_remote_ns = 0;
    uint64_t last_p0_bundle_ns = 0;
    uint64_t last_sensor_interest_ns = 0;
    uint64_t last_health_ns = 0;
    {
      EdrError e = edr_collector_start(agent->event_bus, edr_agent_get_config(agent));
      if (e != EDR_OK) {
        fprintf(stderr, "[collector] start failed: %d; continuing in degraded mode\n", (int)e);
      } else if (edr_agent_collection_enabled(&agent->cfg)) {
        agent->collector_started = 1;
      }
      if (agent->cfg.attack_surface.enabled && agent->cfg.agent.endpoint_id[0] &&
          strcmp(agent->cfg.agent.endpoint_id, "auto") != 0) {
        char d[256];
        int sr = edr_attack_surface_execute("agent_start", &agent->cfg, d, sizeof(d));
        if (sr != 0) {
          fprintf(stderr, "[attack_surface] startup snapshot failed: %s\n", d);
        } else if (strncmp(d, "uploaded_", 9) == 0) {
          fprintf(stderr, "[attack_surface] startup %s\n", d);
        }
      }
      {
        uint64_t t0 = edr_monotonic_ns();
        agent->asurf_last_post_ns = t0;
        agent->asurf_last_pending_check_ns = t0;
      }
      while (!agent->shutdown) {
        edr_ms_sleep(200u);
        edr_resource_poll();
        edr_self_protect_poll();
        edr_agent_poll_config_reload(agent, &last_reload_ns);
        edr_agent_poll_remote_config(agent, &last_remote_ns);
        edr_agent_poll_p0_bundle(agent, &last_p0_bundle_ns);
        edr_agent_poll_sensor_interest(agent, &last_sensor_interest_ns);
        edr_agent_poll_attack_surface(agent);
        edr_agent_poll_engine_health(agent, &last_health_ns);
        edr_shell_session_poll();
        edr_command_poll_reliable_delivery();
      }
      if (agent->collector_started) {
        edr_collector_stop();
        agent->collector_started = 0;
      }
    }
  }
  edr_preprocess_stop();
  return EDR_OK;
}

static void json_escape_small(const char *in, char *out, size_t cap) {
  size_t o = 0;
  if (!out || cap == 0u) {
    return;
  }
  out[0] = '\0';
  if (!in) {
    return;
  }
  for (size_t i = 0; in[i] && o + 2u < cap; i++) {
    unsigned char c = (unsigned char)in[i];
    if (c == '"' || c == '\\') {
      if (o + 3u >= cap) {
        break;
      }
      out[o++] = '\\';
      out[o++] = (char)c;
    } else if (c >= 0x20u && c < 0x7fu) {
      out[o++] = (char)c;
    }
  }
  out[o] = '\0';
}

static void edr_agent_poll_engine_health(EdrAgent *agent, uint64_t *last_health_ns) {
  if (!agent || !last_health_ns || !edr_ingest_http_configured()) {
    return;
  }
  int interval = 60;
  const char *iv = getenv("EDR_ENGINE_HEALTH_INTERVAL_S");
  if (iv && iv[0]) {
    int v = atoi(iv);
    if (v >= 10 && v <= 3600) {
      interval = v;
    }
  }
  uint64_t now = edr_monotonic_ns();
  if (now - *last_health_ns < (uint64_t)interval * 1000000000ULL) {
    return;
  }
  *last_health_ns = now;

  unsigned long pmfe_sub = 0, pmfe_done = 0, pmfe_drop = 0;
  edr_pmfe_get_stats(&pmfe_sub, &pmfe_done, &pmfe_drop);
  unsigned long pmfe_q = edr_pmfe_queue_depth();

  AVEStatus avst;
  memset(&avst, 0, sizeof(avst));
  int ave_ok = (AVE_GetStatus(&avst) == AVE_OK);

  char rules_ver[96], static_ver[48], behavior_ver[48], ioc_ver[48];
  char det_policy_source[64], det_policy_version[96], det_policy_rollback[96], det_policy_audit[160];
  char grpc_err[192], http_err[192], evidence_json[1600], sensor_interest_ver[160], sensor_interest_rules[160];
  char event_filter_ver[96];
  char adaptive_last_rule[96];
  char http_conn_mode[48], http_base_url[640], http_relay_url[640], http_proxy_mode[48];
  char http_proxy_url[640], http_proxy_status[128], http_circuit_reason[160];
  char http_mtls_status[128], http_key_provider[48];
  char resource_pressure_reason[96];
  EdrGrpcClientRuntime grpc_rt;
  EdrIngestHttpRuntime http_rt;
  EdrResourceSample rs;
  EdrCollectorHealth ch;
  EdrWindowsEventFilterStatus event_filter_status;
  memset(&grpc_rt, 0, sizeof(grpc_rt));
  memset(&http_rt, 0, sizeof(http_rt));
  memset(&rs, 0, sizeof(rs));
  memset(&ch, 0, sizeof(ch));
  memset(&event_filter_status, 0, sizeof(event_filter_status));
  edr_grpc_client_get_runtime(&grpc_rt);
  edr_ingest_http_get_runtime(&http_rt);
  edr_resource_get_sample(&rs);
  (void)edr_collector_get_health(&ch);
  edr_windows_event_policy_get_status(&event_filter_status);
  edr_local_evidence_cache_status_json(evidence_json, sizeof(evidence_json));
  EdrShellcodeRulesStatus shell_rules;
  memset(&shell_rules, 0, sizeof(shell_rules));
  edr_shellcode_known_get_status(&shell_rules);
  char shell_source[48], shell_version[128], shell_error[192], shell_rb[128], shell_last_rule[128], shell_last_src[48];
  char audit_err[192], ebpf_err[192];
  json_escape_small(agent->cfg.preprocessing.rules_version, rules_ver, sizeof(rules_ver));
  json_escape_small(agent->cfg.detection_policy.source, det_policy_source, sizeof(det_policy_source));
  json_escape_small(agent->cfg.detection_policy.policy_version, det_policy_version, sizeof(det_policy_version));
  json_escape_small(agent->cfg.detection_policy.rollback_version, det_policy_rollback, sizeof(det_policy_rollback));
  json_escape_small(agent->cfg.detection_policy.audit_id, det_policy_audit, sizeof(det_policy_audit));
  json_escape_small(ave_ok ? avst.static_model_version : "", static_ver, sizeof(static_ver));
  json_escape_small(ave_ok ? avst.behavior_model_version : "", behavior_ver, sizeof(behavior_ver));
  json_escape_small(ave_ok ? avst.ioc_rules_version : "", ioc_ver, sizeof(ioc_ver));
  json_escape_small(shell_rules.source, shell_source, sizeof(shell_source));
  json_escape_small(shell_rules.version, shell_version, sizeof(shell_version));
  json_escape_small(shell_rules.last_error, shell_error, sizeof(shell_error));
  json_escape_small(shell_rules.rollback_version, shell_rb, sizeof(shell_rb));
  json_escape_small(shell_rules.last_match_rule, shell_last_rule, sizeof(shell_last_rule));
  json_escape_small(shell_rules.last_match_source, shell_last_src, sizeof(shell_last_src));
  json_escape_small(grpc_rt.last_error, grpc_err, sizeof(grpc_err));
  json_escape_small(http_rt.last_error, http_err, sizeof(http_err));
  json_escape_small(http_rt.connection_mode, http_conn_mode, sizeof(http_conn_mode));
  json_escape_small(http_rt.effective_base_url, http_base_url, sizeof(http_base_url));
  json_escape_small(http_rt.relay_url, http_relay_url, sizeof(http_relay_url));
  json_escape_small(http_rt.proxy_mode, http_proxy_mode, sizeof(http_proxy_mode));
  json_escape_small(http_rt.proxy_url, http_proxy_url, sizeof(http_proxy_url));
  json_escape_small(http_rt.proxy_status, http_proxy_status, sizeof(http_proxy_status));
  json_escape_small(http_rt.circuit_reason, http_circuit_reason, sizeof(http_circuit_reason));
  json_escape_small(http_rt.mtls_status, http_mtls_status, sizeof(http_mtls_status));
  json_escape_small(http_rt.client_key_provider, http_key_provider, sizeof(http_key_provider));
  json_escape_small(rs.pressure_reason, resource_pressure_reason, sizeof(resource_pressure_reason));
  json_escape_small(ch.auditd_last_error, audit_err, sizeof(audit_err));
  json_escape_small(ch.ebpf_last_error, ebpf_err, sizeof(ebpf_err));
  json_escape_small(ch.sensor_interest_version, sensor_interest_ver, sizeof(sensor_interest_ver));
  json_escape_small(ch.sensor_interest_rules_version, sensor_interest_rules, sizeof(sensor_interest_rules));
  json_escape_small(ch.adaptive_collection_last_rule_id, adaptive_last_rule, sizeof(adaptive_last_rule));
  json_escape_small(event_filter_status.version, event_filter_ver, sizeof(event_filter_ver));

  char body[16384];
  int n = snprintf(
      body, sizeof(body),
      "{\"endpoint_id\":\"%s\",\"agent_version\":\"%s\",\"policy_version\":\"%s\","
      "\"engine_health\":{"
      "\"reported_at_unix_ms\":%llu,"
      "\"communication\":{\"grpc_ready\":%s,\"grpc_insecure\":%s,\"http_fallback\":%s,"
      "\"http_insecure\":%s,\"grpc_rpc_ok\":%lu,\"grpc_rpc_fail\":%lu,"
      "\"grpc_consecutive_failures\":%d,\"http_ok\":%lu,\"http_fail\":%lu,"
      "\"send_queue_depth\":%llu,\"send_queue_capacity\":%llu,"
      "\"queue_full_total\":%lu,\"queue_full_persisted\":%lu,"
      "\"queue_full_sampled\":%lu,\"queue_full_dropped\":%lu,"
      "\"offline_queue_pending\":%llu,\"last_success_unix_ms\":%lld,"
      "\"last_failure_unix_ms\":%lld,\"last_failure_reason\":\"%s%s%s\","
      "\"enterprise\":{\"connection_mode\":\"%s\",\"effective_base_url\":\"%s\","
      "\"relay_url\":\"%s\",\"mtls_configured\":%s,\"websocket_ready\":%s,"
      "\"mtls_status\":\"%s\",\"client_key_provider\":\"%s\","
      "\"proxy_mode\":\"%s\",\"proxy_url\":\"%s\",\"proxy_status\":\"%s\","
      "\"last_success_unix_ms\":%lld,\"last_failure_unix_ms\":%lld,"
      "\"failure_reason\":\"%s%s%s\",\"poll_backoff_ms\":%d,\"ws_backoff_ms\":%d,"
      "\"circuit_open\":%s,\"circuit_until_unix_ms\":%lld,\"circuit_reason\":\"%s\","
      "\"pending_upload_queue\":%llu,"
      "\"budget\":{\"requests_this_minute\":%lu,\"request_limit_per_minute\":%lu,"
      "\"bytes_this_minute\":%llu,\"byte_limit_per_minute\":%llu,"
      "\"tls_handshakes_this_minute\":%lu,\"tls_handshake_limit_per_minute\":%lu,"
      "\"budget_drops\":%lu},"
      "\"slo\":{\"success_rate_pct\":%u}}},"
      "\"resource\":{\"cpu_budget_percent\":%u,\"memory_budget_mb\":%u,"
      "\"ave_infer_per_min\":%u,\"behavior_infer_per_min\":%u,"
      "\"pmfe_scans_per_min\":%u,\"webshell_scan_mb_per_min\":%u,"
      "\"shellcode_packets_per_sec\":%u,\"low_priority_keep_percent_under_pressure\":%u,"
      "\"cpu_percent\":%u,\"rss_mb\":%llu,\"current_rss_mb\":%llu,"
      "\"thread_count\":%u,\"handle_count\":%u,"
      "\"throttle_active\":%s,\"pressure\":%s,\"pressure_level\":%u,"
      "\"pressure_reason\":\"%s\",\"sample_count\":%llu},"
      "\"p0_rule\":{\"enabled\":true,\"mode\":\"resident\",\"rule_version\":\"%s\","
      "\"rules_count\":%u,\"last_degrade_reason\":\"%s\"},"
      "\"suppression_policy\":{\"source\":\"%s\",\"policy_version\":\"%s\","
      "\"rollback_version\":\"%s\",\"audit_id\":\"%s\"},"
      "\"sensor_health\":{\"etw_or_inotify_enabled\":%s,\"powershell_visible\":%s,"
      "\"amsi_visible\":%s,\"security_audit_visible\":%s,"
      "\"auditd_enabled\":%s,\"auditd_running\":%s,\"auditd_events\":%llu,"
      "\"ebpf_enabled\":%s,\"ebpf_loaded\":%s,\"ebpf_events\":%llu,"
      "\"collector_dropped\":%llu,\"queue_dropped\":%llu,"
      "\"agent_self_fuse\":{\"active\":%s,\"until_unix_ms\":%llu,"
      "\"trips\":%llu,\"suppressed\":%llu},"
      "\"drop_breakdown\":{\"agent_self\":%llu,\"lifecycle\":%llu,"
      "\"auth\":%llu,\"invalid_process\":%llu,\"ordinary_file\":%llu,"
      "\"ordinary_registry\":%llu,\"ordinary_network\":%llu,\"metadata\":%llu},"
      "\"auditd_last_error\":\"%s\",\"ebpf_last_error\":\"%s\","
      "\"event_filter\":{\"enabled\":%s,\"version\":\"%s\","
      "\"evaluated\":%llu,\"dropped\":%llu,"
      "\"agent_internal_forensic\":%llu,\"low_value_file_process\":%llu,"
      "\"low_value_file_suffix\":%llu,\"temp_xml\":%llu},"
      "\"adaptive_collection\":{\"enabled\":%s,\"active\":%s,\"ttl_s\":%u,"
      "\"remaining_s\":%u,\"min_severity\":%u,\"level\":%d,"
      "\"boosts\":%llu,\"last_boost_unix_ms\":%llu,\"last_rule_id\":\"%s\"},"
      "\"sensor_interest\":{\"enabled\":%s,\"loaded\":%s,\"version\":\"%s\","
      "\"rules_version\":\"%s\",\"process_names\":%u,\"process_prefixes\":%u,"
      "\"ports\":%u,\"file_prefixes\":%u,\"file_contains\":%u,"
      "\"registry_prefixes\":%u,\"registry_contains\":%u,\"cmd_tokens\":%u,"
      "\"parent_child_pairs\":%u,\"required_fields\":%u,"
      "\"checked\":%llu,\"matched\":%llu,\"dropped\":%llu,"
      "\"provider_hits\":%llu,\"adaptive_hits\":%llu,\"process_hits\":%llu,\"port_hits\":%llu,"
      "\"path_hits\":%llu,\"registry_hits\":%llu,\"parent_child_hits\":%llu}},"
      "\"ave\":{\"enabled\":%s,\"mode\":\"triggered\",\"static_model_version\":\"%s\","
      "\"behavior_model_version\":\"%s\",\"ioc_rules_version\":\"%s\","
      "\"queue_depth\":%d,\"queue_capacity\":%u,\"active_scans\":%d,"
      "\"feed_total\":%llu,\"queue_enqueued\":%llu,\"queue_full_dropped\":%llu,"
      "\"queue_full_sync_fallback\":%llu,\"feed_sync_bypass\":%llu,"
      "\"worker_dequeued\":%llu,\"infer_ok\":%llu,\"infer_fail\":%llu,"
      "\"infer_budget_per_min\":%u,\"infer_budget_dropped\":%llu,"
      "\"infer_effective_budget_per_min\":%u,\"pressure_active\":%s,"
      "\"pressure_feed_dropped\":%llu,\"pressure_infer_dropped\":%llu,"
      "\"infer_latency_last_ms\":%u,\"infer_latency_p95_ms\":%u,"
      "\"last_degrade_reason\":\"%s\"},"
      "\"pmfe\":{\"enabled\":true,\"mode\":\"alert_single_process\",\"queue_depth\":%lu,"
      "\"submitted\":%lu,\"completed\":%lu,\"dropped\":%lu,"
      "\"last_degrade_reason\":\"%s\"},"
      "\"shellcode\":{\"enabled\":%s,\"mode\":\"%s\",\"watch_count\":%zu,"
      "\"threads\":%u,\"max_payload_inspect\":%u,\"rule_version\":\"%s\","
      "\"rules_source\":\"%s\",\"rules_loaded\":%u,\"last_reload_unix_s\":%llu,"
      "\"gray_percent\":%u,\"rollback_available\":%s,\"rollback_active\":%s,"
      "\"rollback_version\":\"%s\",\"matches_total\":%llu,\"yara_matches\":%llu,"
      "\"builtin_matches\":%llu,\"gray_shadow_matches\":%llu,"
      "\"last_match_rule\":\"%s\",\"last_match_source\":\"%s\","
      "\"last_error\":\"%s\",\"last_degrade_reason\":\"%s\"},"
      "\"webshell\":{\"enabled\":%s,\"mode\":\"web_roots_only\",\"watch_count\":%u,"
      "\"max_file_size_mb\":%u,\"scan_threads\":%u,\"last_degrade_reason\":\"%s\"},"
      "%s"
      "}}",
      agent->cfg.agent.endpoint_id, EDR_AGENT_VERSION_STRING, rules_ver[0] ? rules_ver : "local",
      (unsigned long long)(time(NULL) * 1000LL),
	      grpc_rt.ready ? "true" : "false", grpc_rt.insecure ? "true" : "false",
	      http_rt.http_fallback_available ? "true" : "false", http_rt.insecure_http ? "true" : "false",
	      grpc_rt.rpc_ok, grpc_rt.rpc_fail, grpc_rt.report_fail_streak, http_rt.ok_count, http_rt.fail_count,
	      (unsigned long long)edr_transport_send_queue_depth(),
	      (unsigned long long)edr_transport_send_queue_capacity(),
	      edr_transport_queue_full_count(), edr_transport_queue_full_persisted_count(),
	      edr_transport_queue_full_sampled_count(), edr_transport_queue_full_dropped_count(),
	      (unsigned long long)edr_storage_queue_pending_count(),
      (long long)((grpc_rt.last_success_unix_ms > http_rt.last_success_unix_ms) ? grpc_rt.last_success_unix_ms
                                                                                : http_rt.last_success_unix_ms),
      (long long)((grpc_rt.last_failure_unix_ms > http_rt.last_failure_unix_ms) ? grpc_rt.last_failure_unix_ms
                                                                                : http_rt.last_failure_unix_ms),
      grpc_err, (grpc_err[0] && http_err[0]) ? "|" : "", http_err,
	      http_conn_mode[0] ? http_conn_mode : "direct", http_base_url, http_relay_url,
	      http_rt.mtls_configured ? "true" : "false", http_rt.websocket_ready ? "true" : "false",
	      http_mtls_status[0] ? http_mtls_status : "not_configured",
	      http_key_provider[0] ? http_key_provider : "pem",
	      http_proxy_mode[0] ? http_proxy_mode : "auto", http_proxy_url, http_proxy_status,
      (long long)((grpc_rt.last_success_unix_ms > http_rt.last_success_unix_ms) ? grpc_rt.last_success_unix_ms
                                                                                : http_rt.last_success_unix_ms),
      (long long)((grpc_rt.last_failure_unix_ms > http_rt.last_failure_unix_ms) ? grpc_rt.last_failure_unix_ms
                                                                                : http_rt.last_failure_unix_ms),
	      grpc_err, (grpc_err[0] && http_err[0]) ? "|" : "", http_err,
	      http_rt.poll_backoff_ms, http_rt.ws_backoff_ms,
	      http_rt.circuit_open ? "true" : "false", (long long)http_rt.circuit_until_unix_ms,
	      http_circuit_reason,
	      (unsigned long long)edr_storage_queue_pending_count(),
	      http_rt.requests_this_minute, http_rt.request_limit_per_minute,
	      (unsigned long long)http_rt.bytes_this_minute,
	      (unsigned long long)http_rt.byte_limit_per_minute,
	      http_rt.tls_handshakes_this_minute, http_rt.tls_handshake_limit_per_minute,
      http_rt.budget_drop_count, http_rt.slo_success_rate_pct,
      agent->cfg.resource_limit.cpu_limit_percent, agent->cfg.resource_limit.memory_limit_mb,
      agent->cfg.resource_limit.ave_infer_per_min,
      agent->cfg.resource_limit.behavior_infer_per_min,
      agent->cfg.resource_limit.pmfe_scans_per_min,
      agent->cfg.resource_limit.webshell_scan_mb_per_min,
      agent->cfg.resource_limit.shellcode_packets_per_sec,
      agent->cfg.resource_limit.low_priority_keep_percent_under_pressure,
      rs.cpu_percent, (unsigned long long)rs.rss_mb, (unsigned long long)rs.rss_mb,
      rs.thread_count, rs.handle_count,
      rs.throttle_active ? "true" : "false", rs.throttle_active ? "true" : "false",
      rs.pressure_level, resource_pressure_reason[0] ? resource_pressure_reason : "ok",
      (unsigned long long)rs.sample_count,
      rules_ver, agent->cfg.preprocessing.rules_count,
      rs.throttle_active ? "resource_throttle" : "",
      det_policy_source, det_policy_version, det_policy_rollback, det_policy_audit,
      ch.etw_or_inotify_enabled ? "true" : "false", ch.powershell_visible ? "true" : "false",
      ch.amsi_visible ? "true" : "false", ch.security_audit_visible ? "true" : "false",
      ch.auditd_enabled ? "true" : "false", ch.auditd_running ? "true" : "false",
      (unsigned long long)ch.auditd_events,
      ch.ebpf_enabled ? "true" : "false", ch.ebpf_loaded ? "true" : "false",
      (unsigned long long)ch.ebpf_events, (unsigned long long)ch.collector_dropped,
      (unsigned long long)ch.queue_dropped,
      ch.agent_self_fuse_active ? "true" : "false",
      (unsigned long long)ch.agent_self_fuse_until_unix_ms,
      (unsigned long long)ch.agent_self_fuse_trips,
      (unsigned long long)ch.agent_self_fuse_suppressed,
      (unsigned long long)ch.agent_self_suppressed,
      (unsigned long long)ch.lifecycle_dropped,
      (unsigned long long)ch.auth_dropped,
      (unsigned long long)ch.invalid_process_dropped,
      (unsigned long long)ch.ordinary_file_dropped,
      (unsigned long long)ch.ordinary_registry_dropped,
      (unsigned long long)ch.ordinary_network_dropped,
      (unsigned long long)ch.metadata_dropped,
      audit_err, ebpf_err,
      event_filter_status.enabled ? "true" : "false",
      event_filter_ver[0] ? event_filter_ver : "agent-event-filter-v1",
      (unsigned long long)event_filter_status.evaluated,
      (unsigned long long)event_filter_status.dropped,
      (unsigned long long)event_filter_status.agent_internal_forensic,
      (unsigned long long)event_filter_status.low_value_file_process,
      (unsigned long long)event_filter_status.low_value_file_suffix,
      (unsigned long long)event_filter_status.temp_xml,
      ch.adaptive_collection_enabled ? "true" : "false",
      ch.adaptive_collection_active ? "true" : "false",
      ch.adaptive_collection_ttl_s,
      ch.adaptive_collection_remaining_s,
      ch.adaptive_collection_min_severity,
      ch.adaptive_collection_level,
      (unsigned long long)ch.adaptive_collection_boosts,
      (unsigned long long)ch.adaptive_collection_last_boost_unix_ms,
      adaptive_last_rule,
      ch.sensor_interest_enabled ? "true" : "false",
      ch.sensor_interest_loaded ? "true" : "false",
      sensor_interest_ver[0] ? sensor_interest_ver : "builtin",
      sensor_interest_rules[0] ? sensor_interest_rules : rules_ver,
      ch.sensor_interest_process_names, ch.sensor_interest_process_prefixes,
      ch.sensor_interest_ports, ch.sensor_interest_file_prefixes, ch.sensor_interest_file_contains,
      ch.sensor_interest_registry_prefixes, ch.sensor_interest_registry_contains,
      ch.sensor_interest_cmd_tokens, ch.sensor_interest_parent_child_pairs,
      ch.sensor_interest_required_fields, (unsigned long long)ch.sensor_interest_checked,
      (unsigned long long)ch.sensor_interest_matched, (unsigned long long)ch.sensor_interest_dropped,
      (unsigned long long)ch.sensor_interest_provider_hits,
      (unsigned long long)ch.sensor_interest_adaptive_hits,
      (unsigned long long)ch.sensor_interest_process_hits,
      (unsigned long long)ch.sensor_interest_port_hits,
      (unsigned long long)ch.sensor_interest_path_hits,
      (unsigned long long)ch.sensor_interest_registry_hits,
      (unsigned long long)ch.sensor_interest_parent_child_hits,
      ave_ok && avst.initialized ? "true" : "false", static_ver, behavior_ver, ioc_ver,
      ave_ok ? avst.behavior_event_queue_size : 0, ave_ok ? avst.behavior_queue_capacity : 0u,
      ave_ok ? avst.active_scan_count : 0,
      (unsigned long long)(ave_ok ? avst.behavior_feed_total : 0u),
      (unsigned long long)(ave_ok ? avst.behavior_queue_enqueued : 0u),
      (unsigned long long)(ave_ok ? avst.behavior_queue_full_dropped : 0u),
      (unsigned long long)(ave_ok ? avst.behavior_queue_full_sync_fallback : 0u),
      (unsigned long long)(ave_ok ? avst.behavior_feed_sync_bypass : 0u),
      (unsigned long long)(ave_ok ? avst.behavior_worker_dequeued : 0u),
      (unsigned long long)(ave_ok ? avst.behavior_infer_ok : 0u),
      (unsigned long long)(ave_ok ? avst.behavior_infer_fail : 0u),
      ave_ok ? avst.behavior_infer_budget_per_min : 0u,
      (unsigned long long)(ave_ok ? avst.behavior_infer_budget_dropped : 0u),
      ave_ok ? avst.behavior_infer_effective_budget_per_min : 0u,
      (ave_ok && avst.behavior_pressure_active) ? "true" : "false",
      (unsigned long long)(ave_ok ? avst.behavior_pressure_feed_dropped : 0u),
      (unsigned long long)(ave_ok ? avst.behavior_pressure_infer_dropped : 0u),
      ave_ok ? avst.behavior_infer_latency_last_ms : 0u,
      ave_ok ? avst.behavior_infer_latency_p95_ms : 0u,
      (ave_ok && avst.behavior_queue_capacity > 0u &&
       avst.behavior_event_queue_size >= (int)avst.behavior_queue_capacity) ? "queue_full" : "",
      pmfe_q, pmfe_sub, pmfe_done, pmfe_drop,
      pmfe_drop ? "queue_drop" : "",
      agent->cfg.shellcode_detector.enabled ? "true" : "false",
      agent->cfg.shellcode_detector.windivert_ports_is_custom ? "custom_ports" : "lateral_movement_ports",
      agent->cfg.shellcode_detector.windivert_ports_is_custom
          ? agent->cfg.shellcode_detector.windivert_tcp_ports_parsed_count
          : (size_t)((agent->cfg.shellcode_detector.monitor_smb ? 1 : 0) +
                     (agent->cfg.shellcode_detector.monitor_rdp ? 1 : 0) +
                     (agent->cfg.shellcode_detector.monitor_winrm ? 1 : 0) +
                     (agent->cfg.shellcode_detector.monitor_msrpc ? 1 : 0) +
                     (agent->cfg.shellcode_detector.monitor_ldap ? 1 : 0) +
                     (agent->cfg.shellcode_detector.monitor_tls ? 1 : 0)),
      agent->cfg.shellcode_detector.detector_threads, agent->cfg.shellcode_detector.max_payload_inspect,
      shell_version[0] ? shell_version : "builtin-embedded", shell_source[0] ? shell_source : "builtin",
      shell_rules.files_loaded, (unsigned long long)shell_rules.last_reload_unix_s,
      shell_rules.gray_percent, shell_rules.rollback_available ? "true" : "false",
      shell_rules.rollback_active ? "true" : "false", shell_rb,
      (unsigned long long)shell_rules.matches_total, (unsigned long long)shell_rules.yara_matches,
      (unsigned long long)shell_rules.builtin_matches, (unsigned long long)shell_rules.gray_shadow_matches,
      shell_last_rule, shell_last_src, shell_error,
      shell_error[0] ? "rules_error" : "",
      agent->cfg.webshell_detector.enabled ? "true" : "false", agent->cfg.webshell_detector.max_watch_dirs,
      agent->cfg.webshell_detector.max_file_size_mb, agent->cfg.webshell_detector.scan_threads,
      "", evidence_json);
  if (n > 0 && (size_t)n < sizeof(body)) {
    (void)edr_ingest_http_post_engine_health_json(body);
  }
}

void edr_agent_shutdown(EdrAgent *agent) {
  if (!agent) {
    return;
  }
  agent->shutdown = 1;
}

const EdrConfig *edr_agent_get_config(const EdrAgent *agent) {
  if (!agent) {
    return NULL;
  }
  return &agent->cfg;
}

EdrEventBus *edr_agent_event_bus(EdrAgent *agent) {
  if (!agent) {
    return NULL;
  }
  return agent->event_bus;
}

static void edr_agent_poll_config_reload(EdrAgent *agent, uint64_t *last_reload_ns) {
  const char *rs = getenv("EDR_CONFIG_RELOAD_S");
  if (!agent->config_path || !agent->config_path[0] || !rs || rs[0] == '0') {
    return;
  }
  int interval = atoi(rs);
  if (interval < 1) {
    interval = 2;
  }
  uint64_t now = edr_monotonic_ns();
  if (now - *last_reload_ns < (uint64_t)interval * 1000000000ULL) {
    return;
  }
  *last_reload_ns = now;
  int rel = 0;
  EdrError cr =
      edr_config_reload_if_modified(agent->config_path, &agent->cfg, &agent->config_mtime, &rel);
  if (cr == EDR_OK && rel) {
    edr_preprocess_apply_config(&agent->cfg);
    edr_adaptive_collection_configure(&agent->cfg);
    edr_agent_apply_event_filter_config(&agent->cfg);
    edr_resource_init(&agent->cfg);
    edr_self_protect_apply_config(&agent->cfg);
    agent->asurf_last_post_ns = 0;
    {
      const char *post_reload = getenv("EDR_ATTACK_SURFACE_POST_ON_CONFIG_RELOAD");
      if (post_reload && post_reload[0] == '1' && agent->cfg.attack_surface.enabled &&
          agent->cfg.agent.endpoint_id[0] && strcmp(agent->cfg.agent.endpoint_id, "auto") != 0) {
        char d[256];
        int sr = edr_attack_surface_execute("config_reload", &agent->cfg, d, sizeof(d));
        if (sr != 0) {
          fprintf(stderr, "[attack_surface] config_reload POST failed: %s\n", d);
        } else if (strncmp(d, "uploaded_", 9) == 0) {
          fprintf(stderr, "[attack_surface] config_reload %s\n", d);
        }
      }
    }
    {
      int av = AVE_SyncFromEdrConfig(&agent->cfg);
      if (av != AVE_OK && av != AVE_ERR_NOT_INITIALIZED) {
        fprintf(stderr, "[ave] AVE_SyncFromEdrConfig 失败: %d\n", av);
      }
    }
    fprintf(stderr,
            "[config] 热重载: preprocessing + event_filter + resource_limit + self_protect + attack_surface tick + ave\n");
    char fp[80];
    edr_config_fingerprint(agent->config_path, fp, sizeof(fp));
    if (fp[0]) {
      fprintf(stderr, "[config] 热重载 fingerprint=%s\n", fp);
    }
  }
}

static int edr_agent_toml_has_section(const char *path, const char *section) {
  FILE *fp;
  char line[256];
  char needle[96];
  size_t nlen;
  if (!path || !path[0] || !section || !section[0]) {
    return 0;
  }
  snprintf(needle, sizeof(needle), "[%s]", section);
  nlen = strlen(needle);
  fp = fopen(path, "r");
  if (!fp) {
    return 0;
  }
  while (fgets(line, sizeof(line), fp)) {
    char *p = line;
    while (*p == ' ' || *p == '\t') {
      p++;
    }
    if (*p == '#' || *p == '\0' || p[0] != '[' || p[1] == '[') {
      continue;
    }
    if (strncmp(p, needle, nlen) == 0) {
      char tail = p[nlen];
      if (tail == '\0' || tail == '\r' || tail == '\n' || tail == ' ' || tail == '\t' || tail == '#') {
        fclose(fp);
        return 1;
      }
    }
  }
  fclose(fp);
  return 0;
}

static int edr_collection_policy_changed(const EdrConfig *current, const EdrConfig *remote) {
  if (!current || !remote) {
    return 0;
  }
  return current->collection.etw_enabled != remote->collection.etw_enabled ||
         current->collection.etw_dns_client_provider != remote->collection.etw_dns_client_provider ||
         current->collection.etw_powershell_provider != remote->collection.etw_powershell_provider ||
         current->collection.etw_amsi_provider != remote->collection.etw_amsi_provider ||
         current->collection.etw_schannel_provider != remote->collection.etw_schannel_provider ||
         current->collection.etw_security_audit_provider != remote->collection.etw_security_audit_provider ||
         current->collection.etw_wmi_provider != remote->collection.etw_wmi_provider ||
         current->collection.etw_tcpip_provider != remote->collection.etw_tcpip_provider ||
         current->collection.etw_firewall_provider != remote->collection.etw_firewall_provider;
}

static void edr_agent_restart_collector(EdrAgent *agent) {
  if (!agent || !agent->event_bus) {
    return;
  }
  if (agent->collector_started) {
    edr_collector_stop();
    agent->collector_started = 0;
  }
  if (!edr_agent_collection_enabled(&agent->cfg)) {
    fprintf(stderr, "[collector] remote policy disabled collection; collector stopped\n");
    return;
  }
  {
    EdrError e = edr_collector_start(agent->event_bus, &agent->cfg);
    if (e != EDR_OK) {
      fprintf(stderr, "[collector] remote policy restart failed: %d; continuing in degraded mode\n", (int)e);
      return;
    }
    agent->collector_started = 1;
    fprintf(stderr, "[collector] remote policy applied; collector restarted\n");
  }
}

static int edr_agent_apply_remote_policy(EdrAgent *agent, const EdrConfig *remote, const char *tmp) {
  int changed = 0;
  if (!agent || !remote || !tmp || !tmp[0]) {
    return 0;
  }
  if (edr_agent_toml_has_section(tmp, "preprocessing")) {
    snprintf(agent->cfg.preprocessing.rules_version, sizeof(agent->cfg.preprocessing.rules_version), "%s",
             remote->preprocessing.rules_version);
  }
  if (edr_agent_toml_has_section(tmp, "collection")) {
    if (edr_collection_policy_changed(&agent->cfg, remote)) {
      changed |= EDR_REMOTE_POLICY_COLLECTION_CHANGED;
    }
    if (agent->cfg.collection.max_event_queue_size != remote->collection.max_event_queue_size) {
      fprintf(stderr, "[config] remote max_event_queue_size changed; applies after agent restart\n");
    }
    agent->cfg.collection.etw_enabled = remote->collection.etw_enabled;
    agent->cfg.collection.etw_dns_client_provider = remote->collection.etw_dns_client_provider;
    agent->cfg.collection.etw_powershell_provider = remote->collection.etw_powershell_provider;
    agent->cfg.collection.etw_amsi_provider = remote->collection.etw_amsi_provider;
    agent->cfg.collection.etw_schannel_provider = remote->collection.etw_schannel_provider;
    agent->cfg.collection.etw_security_audit_provider = remote->collection.etw_security_audit_provider;
    agent->cfg.collection.etw_wmi_provider = remote->collection.etw_wmi_provider;
    agent->cfg.collection.etw_tcpip_provider = remote->collection.etw_tcpip_provider;
    agent->cfg.collection.etw_firewall_provider = remote->collection.etw_firewall_provider;
    agent->cfg.collection.max_event_queue_size = remote->collection.max_event_queue_size;
    agent->cfg.collection.adaptive_enabled = remote->collection.adaptive_enabled;
    agent->cfg.collection.adaptive_boost_seconds = remote->collection.adaptive_boost_seconds;
    agent->cfg.collection.adaptive_min_severity = remote->collection.adaptive_min_severity;
    edr_adaptive_collection_configure(&agent->cfg);
  }
  if (edr_agent_toml_has_section(tmp, "event_filter")) {
    agent->cfg.event_filter = remote->event_filter;
    edr_agent_apply_event_filter_config(&agent->cfg);
  }
  if (edr_agent_toml_has_section(tmp, "upload")) {
    agent->cfg.upload = remote->upload;
  }
  if (edr_agent_toml_has_section(tmp, "resource_limit")) {
    agent->cfg.resource_limit = remote->resource_limit;
  }
  if (edr_agent_toml_has_section(tmp, "command")) {
    agent->cfg.command = remote->command;
  }
  if (edr_agent_toml_has_section(tmp, "forensic_auto")) {
    agent->cfg.forensic_auto = remote->forensic_auto;
  }
  if (edr_agent_toml_has_section(tmp, "platform")) {
    snprintf(agent->cfg.platform.proxy_mode, sizeof(agent->cfg.platform.proxy_mode), "%s",
             remote->platform.proxy_mode);
    snprintf(agent->cfg.platform.proxy_url, sizeof(agent->cfg.platform.proxy_url), "%s",
             remote->platform.proxy_url);
    snprintf(agent->cfg.platform.relay_url, sizeof(agent->cfg.platform.relay_url), "%s",
             remote->platform.relay_url);
  }
  if (edr_agent_toml_has_section(tmp, "ave")) {
    agent->cfg.ave.behavior_monitor_enabled = remote->ave.behavior_monitor_enabled;
    agent->cfg.ave.scan_threads = remote->ave.scan_threads;
    agent->cfg.ave.max_file_size_mb = remote->ave.max_file_size_mb;
    snprintf(agent->cfg.ave.sensitivity, sizeof(agent->cfg.ave.sensitivity), "%s", remote->ave.sensitivity);
  }
  if (edr_agent_toml_has_section(tmp, "attack_surface")) {
    agent->cfg.attack_surface.enabled = remote->attack_surface.enabled;
  }
  if (edr_agent_toml_has_section(tmp, "self_protect")) {
    agent->cfg.self_protect.event_bus_pressure_warn_pct = remote->self_protect.event_bus_pressure_warn_pct;
  }
  return changed;
}

static void edr_agent_poll_remote_config(EdrAgent *agent, uint64_t *last_remote_ns) {
  const char *url = getenv("EDR_REMOTE_CONFIG_URL");
  const char *auto_pull = getenv("EDR_REMOTE_CONFIG_AUTO_PULL");
  const char *ps = getenv("EDR_REMOTE_CONFIG_POLL_S");
  char derived[768];
  int interval = 1800;
  if (!agent) {
    return;
  }
  if (auto_pull && (auto_pull[0] == '0' || auto_pull[0] == 'n' || auto_pull[0] == 'N')) {
    return;
  }
  if (!url || !url[0]) {
    const char *base = agent->cfg.platform.relay_url[0]
                           ? agent->cfg.platform.relay_url
                           : agent->cfg.platform.rest_base_url;
    if (!base[0]) {
      return;
    }
    snprintf(derived, sizeof(derived), "%s/agent/runtime-policy.toml", base);
    url = derived;
  }
  if (ps && ps[0]) {
    int v = atoi(ps);
    if (v >= 60 && v <= 86400) {
      interval = v;
    }
  }
  uint64_t now = edr_monotonic_ns();
  if (*last_remote_ns != 0u &&
      now - *last_remote_ns < (uint64_t)interval * 1000000000ULL) {
    return;
  }
  *last_remote_ns = now;

  char tmp[520];
#ifdef _WIN32
  const char *t = getenv("TEMP");
  if (!t || !t[0]) {
    t = ".";
  }
  snprintf(tmp, sizeof(tmp), "%s\\edr_remote_%lu.toml", t, (unsigned long)GetCurrentProcessId());
#else
  snprintf(tmp, sizeof(tmp), "/tmp/edr_remote_%d.toml", (int)getpid());
#endif
  if (edr_agent_download_text_file(url, tmp, 1024u * 1024u, "remote TOML") != 0) {
    return;
  }

  EdrConfig remote;
  memset(&remote, 0, sizeof(remote));
  EdrError ce = edr_config_load(tmp, &remote);
  char fp[80];
  int changed = 0;
  edr_config_fingerprint(tmp, fp, sizeof(fp));
  if (ce != EDR_OK) {
    fprintf(stderr, "[config] remote TOML parse failed: %d\n", (int)ce);
    (void)remove(tmp);
    return;
  }
  changed = edr_agent_apply_remote_policy(agent, &remote, tmp);
  edr_config_free_heap(&remote);
  (void)remove(tmp);
  if ((changed & EDR_REMOTE_POLICY_COLLECTION_CHANGED) != 0) {
    edr_agent_restart_collector(agent);
  }
  edr_preprocess_apply_config(&agent->cfg);
  edr_resource_init(&agent->cfg);
  edr_self_protect_apply_config(&agent->cfg);
  edr_ingest_http_set_policy_version(agent->cfg.preprocessing.rules_version);
  {
    const char *post_reload = getenv("EDR_ATTACK_SURFACE_POST_ON_CONFIG_RELOAD");
    if (post_reload && post_reload[0] == '1' && agent->cfg.attack_surface.enabled &&
        agent->cfg.agent.endpoint_id[0] && strcmp(agent->cfg.agent.endpoint_id, "auto") != 0) {
      char d[256];
      int sr = edr_attack_surface_execute("config_reload", &agent->cfg, d, sizeof(d));
      if (sr != 0) {
        fprintf(stderr, "[attack_surface] remote config_reload POST failed: %s\n", d);
      } else if (strncmp(d, "uploaded_", 9) == 0) {
        fprintf(stderr, "[attack_surface] remote config_reload %s\n", d);
      }
    }
  }
  {
    uint64_t t0 = edr_monotonic_ns();
    agent->asurf_last_post_ns = t0;
    agent->asurf_last_pending_check_ns = t0;
  }
  {
    int av = AVE_SyncFromEdrConfig(&agent->cfg);
    if (av != AVE_OK && av != AVE_ERR_NOT_INITIALIZED) {
      fprintf(stderr, "[ave] AVE_SyncFromEdrConfig(remote) failed: %d\n", av);
    }
  }
  fprintf(stderr,
          "[config] remote policy applied: preprocessing + event_filter + resource_limit + self_protect + attack_surface tick + ave");
  if (fp[0]) {
    fprintf(stderr, " fingerprint=%s", fp);
  }
  fprintf(stderr, "\n");
}

static void edr_agent_poll_p0_bundle(EdrAgent *agent, uint64_t *last_p0_bundle_ns) {
  const char *url = getenv("EDR_P0_BUNDLE_URL");
  const char *auto_pull = getenv("EDR_P0_BUNDLE_AUTO_PULL");
  const char *iv = getenv("EDR_P0_BUNDLE_POLL_S");
  int interval = 1800;
  uint64_t now;
  char derived[768];
  char tmp[520];
  char dst[2048];
  const char *base;
  if (!agent || !last_p0_bundle_ns) {
    return;
  }
  if (auto_pull && (auto_pull[0] == '0' || auto_pull[0] == 'n' || auto_pull[0] == 'N')) {
    return;
  }
  if (!url || !url[0]) {
    base = agent->cfg.platform.relay_url[0]
               ? agent->cfg.platform.relay_url
               : agent->cfg.platform.rest_base_url;
    if (!base[0]) {
      return;
    }
    snprintf(derived, sizeof(derived), "%s/agent/p0-bundle.enc", base);
    url = derived;
  }
  if (iv && iv[0]) {
    int v = atoi(iv);
    if (v >= 60 && v <= 86400) {
      interval = v;
    }
  }
  now = edr_monotonic_ns();
  if (*last_p0_bundle_ns != 0u &&
      now - *last_p0_bundle_ns < (uint64_t)interval * 1000000000ULL) {
    return;
  }
  *last_p0_bundle_ns = now;

#ifdef _WIN32
  {
    const char *t = getenv("TEMP");
    if (!t || !t[0]) {
      t = ".";
    }
    snprintf(tmp, sizeof(tmp), "%s\\edr_p0_bundle_%lu.enc", t, (unsigned long)GetCurrentProcessId());
  }
#else
  snprintf(tmp, sizeof(tmp), "/tmp/edr_p0_bundle_%d.enc", (int)getpid());
#endif

  if (edr_agent_download_text_file(url, tmp, 4u * 1024u * 1024u, "P0 bundle") != 0) {
    return;
  }
  if (!edr_agent_file_has_magic(tmp, "EDR1", 4u)) {
    fprintf(stderr, "[p0_rule_ir] remote bundle rejected: missing EDR1 header\n");
    (void)remove(tmp);
    return;
  }
  if (edr_p0_bundle_dst_path(dst, sizeof(dst)) != 0 || !dst[0]) {
    fprintf(stderr, "[p0_rule_ir] remote bundle rejected: cannot resolve destination path\n");
    (void)remove(tmp);
    return;
  }
  if (edr_agent_files_equal(tmp, dst)) {
    (void)remove(tmp);
    return;
  }
  if (edr_agent_replace_file(tmp, dst) != 0) {
    fprintf(stderr, "[p0_rule_ir] remote bundle install failed: %s\n", dst);
    (void)remove(tmp);
    return;
  }
  edr_p0_rule_ir_reload();
  {
    const char *source = "";
    const char *sha = "";
    size_t plain_size = 0u;
    (void)edr_p0_rule_ir_get_bundle_info(&source, &plain_size, &sha);
    fprintf(stderr, "[p0_rule_ir] remote bundle applied: rules=%d sha256=%s source=%s\n",
            edr_p0_rule_ir_rule_count(), sha && sha[0] ? sha : "unknown",
            source && source[0] ? source : dst);
    (void)plain_size;
  }
}

static void edr_agent_poll_sensor_interest(EdrAgent *agent, uint64_t *last_sensor_interest_ns) {
  const char *url = getenv("EDR_SENSOR_INTEREST_URL");
  const char *auto_pull = getenv("EDR_SENSOR_INTEREST_AUTO_PULL");
  int interval = 1800;
  const char *iv = getenv("EDR_SENSOR_INTEREST_POLL_S");
  uint64_t now;
  char derived[768];
  char tmp[520];
  if (!agent || !last_sensor_interest_ns) {
    return;
  }
  if (auto_pull && (auto_pull[0] == '0' || auto_pull[0] == 'n' || auto_pull[0] == 'N')) {
    return;
  }
  if (!url || !url[0]) {
    const char *base = agent->cfg.platform.relay_url[0]
                           ? agent->cfg.platform.relay_url
                           : agent->cfg.platform.rest_base_url;
    if (!base[0]) {
      return;
    }
    snprintf(derived, sizeof(derived), "%s/agent/sensor-interest.json", base);
    url = derived;
  }
  if (iv && iv[0]) {
    int v = atoi(iv);
    if (v >= 60 && v <= 86400) {
      interval = v;
    }
  }
  now = edr_monotonic_ns();
  if (*last_sensor_interest_ns != 0u &&
      now - *last_sensor_interest_ns < (uint64_t)interval * 1000000000ULL) {
    return;
  }
  *last_sensor_interest_ns = now;

#ifdef _WIN32
  {
    const char *t = getenv("TEMP");
    if (!t || !t[0]) {
      t = ".";
    }
    snprintf(tmp, sizeof(tmp), "%s\\edr_sensor_interest_%lu.json", t, (unsigned long)GetCurrentProcessId());
    if (edr_agent_download_text_file(url, tmp, 1024u * 1024u, "sensor interest") != 0) {
      return;
    }
  }
#else
  {
    snprintf(tmp, sizeof(tmp), "/tmp/edr_sensor_interest_%d.json", (int)getpid());
    if (edr_agent_download_text_file(url, tmp, 1024u * 1024u, "sensor interest") != 0) {
      return;
    }
  }
#endif
  if (edr_sensor_interest_replace_manifest_from_file(tmp) == 0) {
    fprintf(stderr, "[sensor_interest] remote manifest applied\n");
  }
  (void)remove(tmp);
}

/**
 * §19.8 周期快照：仅当 `[attack_surface].enabled=true` 时，按
 * `edr_attack_surface_effective_periodic_interval_s`（`min(port, service, policy, full)`，钳 60～604800s）
 * 调用 `edr_attack_surface_execute`（与 Subscribe 指令路径共用实现）。
 * 按需刷新：按 `conn_interval_s`（钳 15～120s）轮询 GET .../attack-surface/refresh-request。
 */
static void edr_agent_poll_attack_surface(EdrAgent *agent) {
  if (!agent || agent->shutdown) {
    return;
  }
  const EdrConfig *cfg = &agent->cfg;
  if (!cfg->attack_surface.enabled) {
    return;
  }
  if (!cfg->agent.endpoint_id[0] || strcmp(cfg->agent.endpoint_id, "auto") == 0) {
    return;
  }

  uint64_t now = edr_monotonic_ns();

  if (cfg->attack_surface.etw_refresh_triggers_snapshot) {
    uint32_t ds = cfg->attack_surface.etw_refresh_debounce_s;
    if (ds < 1u) {
      ds = 1u;
    }
    if (ds > 300u) {
      ds = 300u;
    }
    uint64_t debounce_ns = (uint64_t)ds * 1000000000ULL;
    if (edr_attack_surface_take_etw_flush(now, debounce_ns)) {
      char detail[256];
      int r = edr_attack_surface_execute("etw_tcpip_wf", cfg, detail, sizeof(detail));
      if (r != 0) {
        fprintf(stderr, "[attack_surface] etw_tcpip_wf failed: %s\n", detail);
      } else if (strncmp(detail, "uploaded_", 9) == 0) {
        fprintf(stderr, "[attack_surface] etw_tcpip_wf %s\n", detail);
      }
    }
  }

  uint32_t pend_iv = cfg->attack_surface.conn_interval_s;
  if (pend_iv < 15u) {
    pend_iv = 15u;
  }
  if (pend_iv > 120u) {
    pend_iv = 120u;
  }
  const uint64_t pend_iv_ns = (uint64_t)pend_iv * 1000000000ULL;
  if (now - agent->asurf_last_pending_check_ns >= pend_iv_ns) {
    agent->asurf_last_pending_check_ns = now;
    int pr = edr_attack_surface_refresh_pending(cfg);
    if (pr == 1) {
      char detail[256];
      int r = edr_attack_surface_execute("refresh_request", cfg, detail, sizeof(detail));
      if (r != 0) {
        fprintf(stderr, "[attack_surface] refresh_request failed: %s\n", detail);
      } else if (strncmp(detail, "uploaded_", 9) == 0) {
        fprintf(stderr, "[attack_surface] refresh_request %s\n", detail);
      }
    }
  }

  uint32_t sec = edr_attack_surface_effective_periodic_interval_s(cfg);
  const uint64_t interval_ns = (uint64_t)sec * 1000000000ULL;

  if (now - agent->asurf_last_post_ns < interval_ns) {
    return;
  }
  agent->asurf_last_post_ns = now;

  char detail[256];
  int r = edr_attack_surface_execute("periodic_attack_surface", cfg, detail, sizeof(detail));
  if (r != 0) {
    fprintf(stderr, "[attack_surface] periodic failed: %s\n", detail);
    return;
  }
  if (strncmp(detail, "uploaded_", 9) == 0) {
    fprintf(stderr, "[attack_surface] periodic %s\n", detail);
  }
}
