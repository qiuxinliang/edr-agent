#include "edr/agent.h"

#include "edr/ave_sdk.h"
#include "edr/config.h"
#include "edr/event_bus.h"
#include "edr/preprocess.h"
#include "edr/resource.h"
#include "edr/self_protect.h"
#include "edr/time_util.h"

#if defined(EDR_WITH_FL_TRAINER)
#include "edr/fl_trainer.h"
#endif

#include "edr/attack_surface_report.h"
#include "edr/collector.h"
#include "edr/p0_rule_match.h"
#ifdef _WIN32
#include "edr/etw_observability_win.h"
#include "edr/edr_a44_split_path_win.h"
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

#include "edr/ave.h"
#include "edr/grpc_client.h"
#include "edr/ingest_http.h"
#include "edr/transport_sink.h"
#include "edr/edr_log.h"

#include "ave_onnx_infer.h"

#ifdef EDR_HAVE_LIBCURL
#include <curl/curl.h>
#endif

/** Non-NULL required: behavior pipeline only emits protobuf alerts when on_behavior_alert is set. */
static void edr_agent_on_behavior_alert(const AVEBehaviorAlert *alert, void *user_data) {
  (void)alert;
  (void)user_data;
}

struct EdrAgent {
  EdrEventBus *event_bus;
  char *config_path;
  EdrConfig cfg;
  time_t config_mtime;
  int shutdown;
  /** §19.8 周期快照：上次全量定时采集单调时钟（ns） */
  uint64_t asurf_last_post_ns;
  /** §19.6 上次轮询 refresh-request 的时间（ns） */
  uint64_t asurf_last_pending_check_ns;
};

/** 0 = disabled; unset = use clamped server.keepalive_interval_s. */
static int edr_agent_console_heartbeat_interval_s(const EdrAgent *agent) {
  const char *e = getenv("EDR_CONSOLE_HEARTBEAT_SEC");
  if (e && e[0]) {
    return atoi(e);
  }
  int k = agent->cfg.server.keepalive_interval_s;
  if (k < 10) {
    k = 10;
  }
  if (k > 600) {
    k = 600;
  }
  return k;
}

static void edr_agent_log_collection_profile(const EdrConfig *cfg) {
  if (!cfg) {
    return;
  }
  fprintf(stderr,
          "[collection] etw_on=%d tcpip=%d fw=%d dns=%d ps=%d secaudit=%d wmi=%d "
          "ebpf=%d poll_s=%d queue_size=%u etw_buf_kb=%u etw_flush_s=%u (P0: "
          "Cauld Design/EDR_P0_Field_Matrix_Signoff.md; WP-8: "
          "edr-agent/docs/WP8_ETW_COLLECTION_PROFILE.md)\n",
          (int)cfg->collection.etw_enabled, (int)cfg->collection.etw_tcpip_provider,
          (int)cfg->collection.etw_firewall_provider, (int)cfg->collection.etw_dns_client_provider,
          (int)cfg->collection.etw_powershell_provider, (int)cfg->collection.etw_security_audit_provider,
          (int)cfg->collection.etw_wmi_provider, (int)cfg->collection.ebpf_enabled,
          cfg->collection.poll_interval_s, (unsigned)cfg->collection.max_event_queue_size,
          (unsigned)cfg->collection.etw_buffer_kb, (unsigned)cfg->collection.etw_flush_timer_s);
}

/** 与 agent.toml 对表，便于对照 WP-9 行为/AVE 数据链。Monitor：1=起线程成功 0=失败 na=未试（如 Register 失败） */
static void edr_agent_log_ave_profile(const EdrConfig *cfg, int on_behavior_alert_registered, int start_monitor) {
  if (!cfg) {
    return;
  }
  const char *mon = "na";
  if (start_monitor == 1) {
    mon = "1";
  } else if (start_monitor < 0) {
    mon = "0";
  }
  fprintf(
      stderr,
      "[ave] on_behavior_alert=%d behavior_monitor_toml=%d behavior_monitor=%s model_dir=%.300s "
      "onnx_static=%d onnx_behavior=%d l4_th=%.3f (WP-9: edr-agent/docs/WP9_BEHAVIOR_AVE.md)\n",
      (int)on_behavior_alert_registered, (int)cfg->ave.behavior_monitor_enabled, mon,
      (cfg->ave.model_dir[0] ? cfg->ave.model_dir : "-"), edr_onnx_runtime_ready(), edr_onnx_behavior_ready(),
      (double)cfg->ave.l4_realtime_anomaly_threshold);
}

static void edr_agent_print_console_heartbeat_line(const EdrAgent *agent) {
  char grpc_diag[200];
  int ave_mf = 0, ave_nf = 0, ave_dir = 0;
  edr_grpc_client_diag(grpc_diag, sizeof(grpc_diag));
  if (!grpc_diag[0]) {
    snprintf(grpc_diag, sizeof(grpc_diag), "%s", "-");
  }
  edr_ave_get_scan_counts(&ave_mf, &ave_nf, &ave_dir);
  if (edr_log_verbose()) {
    fprintf(stderr,
            "[heartbeat] grpc_ready=%d grpc_diag=%s http_ingest=%d batches=%lu target=%s rpc_ok=%lu "
            "rpc_fail=%lu wire_events=%lu wire_bytes=%lu "
            "ave_model_files=%d ave_dir_ready=%d onnx_static_ready=%d onnx_behavior_ready=%d\n",
            edr_grpc_client_ready(), grpc_diag, edr_ingest_http_configured(),
            edr_transport_batch_count(), agent->cfg.server.address, edr_grpc_client_rpc_ok(),
            edr_grpc_client_rpc_fail(), edr_transport_wire_events_count(),
            edr_transport_wire_bytes_count(), ave_mf, ave_dir, edr_onnx_runtime_ready(),
            edr_onnx_behavior_ready());
  } else {
    fprintf(stderr,
            "[heartbeat] grpc=%d http=%d batches=%lu\n", edr_grpc_client_ready(), edr_ingest_http_configured(),
            edr_transport_batch_count());
  }
#if defined(_WIN32)
  {
    const char *e = getenv("EDR_ETW_OBS");
    if (e && (e[0] == '1' || (e[0] == 'y' && e[1] == '\0') || (e[0] == 'Y' && e[1] == '\0'))) {
      edr_etw_observability_print_line(agent->event_bus);
    }
  }
  EdrA44Stats a44_stats;
  if (edr_a44_get_stats(&a44_stats) == 0 && a44_stats.active_threads > 0) {
    fprintf(stderr,
            "[a44] threads=%u cap=%u depth=%u(%.1f%%) avg=%.2f drop=%lu backoff=%lu rps=%.1f\n",
            (unsigned)a44_stats.active_threads,
            (unsigned)a44_stats.queue_capacity,
            (unsigned)a44_stats.current_depth,
            a44_stats.queue_utilization_pct,
            a44_stats.queue_depth_avg,
            (unsigned long)a44_stats.dropped_total,
            (unsigned long)a44_stats.backoff_sync_total,
            a44_stats.throughput_rps);
    (void)edr_a44_adjust_threads_dynamically();
  }
  {
    EdrP0RuleStats p0_stats;
    if (edr_p0_rule_get_stats(&p0_stats) == 0) {
      fprintf(stderr,
              "[p0] total=%lu env_skip=%lu ir_match=%lu fb_match=%lu "
              "r_exec=%lu r_cred=%lu r_filess=%lu\n",
              (unsigned long)p0_stats.total_calls,
              (unsigned long)p0_stats.env_not_set_skip,
              (unsigned long)p0_stats.ir_mode_matches,
              (unsigned long)p0_stats.fallback_mode_matches,
              (unsigned long)p0_stats.rule_r_exec_001_hits,
              (unsigned long)p0_stats.rule_r_cred_001_hits,
              (unsigned long)p0_stats.rule_r_fileless_001_hits);
    }
  }
#endif
  fflush(stderr);
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
    agent->config_path = strdup(config_path);
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
        EDR_LOGV("[config] fingerprint=%s path=%s\n", fp, load_path);
      }
    }
  }
  edr_self_protect_init();
  edr_resource_init(&agent->cfg);
  {
    int ar = AVE_InitFromEdrConfig(&agent->cfg);
    if (ar != AVE_OK) {
      fprintf(stderr, "[ave] AVE_InitFromEdrConfig failed: %d\n", ar);
    } else {
      int start_monitor = 0;
      int on_reg = 0;
      AVECallbacks acb;
      memset(&acb, 0, sizeof(acb));
      acb.on_behavior_alert = edr_agent_on_behavior_alert;
      int reg = AVE_RegisterCallbacks(&acb);
      if (reg != AVE_OK) {
        fprintf(stderr, "[ave] AVE_RegisterCallbacks failed: %d (behavior alerts will not be emitted)\n", reg);
      } else {
        on_reg = 1;
        int sm = AVE_StartBehaviorMonitor();
        start_monitor = (sm == AVE_OK) ? 1 : -1;
        if (sm != AVE_OK) {
          fprintf(stderr, "[ave] AVE_StartBehaviorMonitor failed: %d (behavior queue may run sync-only)\n", sm);
        }
      }
      edr_agent_log_ave_profile(&agent->cfg, on_reg, start_monitor);
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
static void edr_agent_poll_attack_surface(EdrAgent *agent);

#ifdef EDR_HAVE_LIBCURL
static int edr_remote_curl_init(void) {
  static int done = 0;
  if (!done) {
    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
      return -1;
    }
    done = 1;
  }
  return 0;
}
#endif

static int edr_remote_tmp_path(char *out, size_t cap) {
  if (!out || cap < 16u) {
    return -1;
  }
#ifdef _WIN32
  char td[MAX_PATH];
  DWORD nn = GetTempPathA((DWORD)sizeof(td), td);
  if (nn == 0 || nn >= sizeof(td)) {
    snprintf(td, sizeof(td), ".\\");
  }
  UINT rc = GetTempFileNameA(td, "edr", 0, out);
  if (rc == 0) {
    return -1;
  }
  return 0;
#else
  snprintf(out, cap, "%s", "/tmp/edr_remote_XXXXXX.toml");
  int fd = mkstemps(out, 5);
  if (fd < 0) {
    return -1;
  }
  close(fd);
  return 0;
#endif
}

static int edr_remote_fetch_toml(const char *url, const char *out_path) {
  if (!url || !url[0] || !out_path || !out_path[0]) {
    return -1;
  }
#ifndef EDR_HAVE_LIBCURL
  (void)url;
  (void)out_path;
  return -1;
#else
  if (edr_remote_curl_init() != 0) {
    return -1;
  }
  CURL *curl = curl_easy_init();
  if (!curl) {
    return -1;
  }
  FILE *f = fopen(out_path, "wb");
  if (!f) {
    curl_easy_cleanup(curl);
    return -1;
  }
  char errbuf[CURL_ERROR_SIZE];
  errbuf[0] = 0;
  curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);
  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
  curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)f);
  CURLcode cc = curl_easy_perform(curl);
  fclose(f);
  curl_easy_cleanup(curl);
  if (cc != CURLE_OK) {
    (void)remove(out_path);
    const char *em = errbuf[0] ? errbuf : curl_easy_strerror(cc);
    EDR_LOGE("[config] 远程 TOML 拉取失败: %s\n", em);
    return -1;
  }
  return 0;
#endif
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
  edr_agent_log_collection_profile(&agent->cfg);
  {
    uint64_t last_reload_ns = 0;
    uint64_t last_remote_ns = 0;
    {
      EdrError e = edr_collector_start(agent->event_bus, edr_agent_get_config(agent));
      if (e != EDR_OK) {
        fprintf(stderr,
                "[agent] edr_collector_start failed (%d); staying up without live ETW (run as admin for "
                "ETW, or set [collection] etw_enabled=false in agent.toml).\n",
                (int)e);
      }
      if (agent->cfg.attack_surface.enabled && agent->cfg.agent.endpoint_id[0] &&
          strcmp(agent->cfg.agent.endpoint_id, "auto") != 0) {
        char d[256];
        int sr = edr_attack_surface_execute("agent_start", &agent->cfg, d, sizeof(d));
        if (sr != 0) {
          EDR_LOGE("[attack_surface] startup snapshot failed: %s\n", d);
        } else if (strncmp(d, "uploaded_", 9) == 0) {
          EDR_LOGV("[attack_surface] startup %s\n", d);
        }
      }
      {
        uint64_t t0 = edr_monotonic_ns();
        agent->asurf_last_post_ns = t0;
        agent->asurf_last_pending_check_ns = t0;
      }
      int hb_sec = edr_agent_console_heartbeat_interval_s(agent);
      uint64_t hb_period_ns =
          hb_sec > 0 ? (uint64_t)hb_sec * 1000000000ULL : (uint64_t)0ULL;
      uint64_t last_hb_ns = 0;
      if (hb_sec > 0) {
        edr_agent_print_console_heartbeat_line(agent);
        last_hb_ns = edr_monotonic_ns();
      }
      while (!agent->shutdown) {
        edr_ms_sleep(200u);
        if (hb_period_ns > 0) {
          uint64_t now = edr_monotonic_ns();
          if (now - last_hb_ns >= hb_period_ns) {
            edr_agent_print_console_heartbeat_line(agent);
            last_hb_ns = now;
          }
        }
        edr_resource_poll();
        edr_self_protect_poll();
        edr_agent_poll_config_reload(agent, &last_reload_ns);
        edr_agent_poll_remote_config(agent, &last_remote_ns);
        edr_agent_poll_attack_surface(agent);
      }
      edr_collector_stop();
    }
  }
  edr_preprocess_stop();
  return EDR_OK;
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
          EDR_LOGE("[attack_surface] config_reload POST failed: %s\n", d);
        } else if (strncmp(d, "uploaded_", 9) == 0) {
          EDR_LOGV("[attack_surface] config_reload %s\n", d);
        }
      }
    }
    {
      int av = AVE_SyncFromEdrConfig(&agent->cfg);
      if (av != AVE_OK && av != AVE_ERR_NOT_INITIALIZED) {
        fprintf(stderr, "[ave] AVE_SyncFromEdrConfig 失败: %d\n", av);
      }
    }
    EDR_LOGV("%s", "[config] 热重载: preprocessing + resource_limit + self_protect + attack_surface tick + ave\n");
    char fp[80];
    edr_config_fingerprint(agent->config_path, fp, sizeof(fp));
    if (fp[0]) {
      EDR_LOGV("[config] 热重载 fingerprint=%s\n", fp);
    }
  }
}

static void edr_agent_poll_remote_config(EdrAgent *agent, uint64_t *last_remote_ns) {
  const char *url = getenv("EDR_REMOTE_CONFIG_URL");
  const char *ps = getenv("EDR_REMOTE_CONFIG_POLL_S");
  if (!agent || !url || !url[0] || !ps || !ps[0]) {
    return;
  }
  int interval = atoi(ps);
  if (interval < 1) {
    return;
  }
  uint64_t now = edr_monotonic_ns();
  if (*last_remote_ns != 0u &&
      now - *last_remote_ns < (uint64_t)interval * 1000000000ULL) {
    return;
  }
  *last_remote_ns = now;

  char tmp[520];
  if (edr_remote_tmp_path(tmp, sizeof(tmp)) != 0) {
    EDR_LOGE("%s", "[config] 远程 TOML 临时文件创建失败\n");
    return;
  }
  if (edr_remote_fetch_toml(url, tmp) != 0) {
    return;
  }

  EdrError ce = edr_config_load(tmp, &agent->cfg);
  char fp[80];
  edr_config_fingerprint(tmp, fp, sizeof(fp));
  (void)remove(tmp);
  if (ce != EDR_OK) {
    fprintf(stderr, "[config] 远程 TOML 解析失败: %d\n", (int)ce);
    return;
  }
  edr_preprocess_apply_config(&agent->cfg);
  edr_resource_init(&agent->cfg);
  edr_self_protect_apply_config(&agent->cfg);
  {
    const char *post_reload = getenv("EDR_ATTACK_SURFACE_POST_ON_CONFIG_RELOAD");
    if (post_reload && post_reload[0] == '1' && agent->cfg.attack_surface.enabled &&
        agent->cfg.agent.endpoint_id[0] && strcmp(agent->cfg.agent.endpoint_id, "auto") != 0) {
      char d[256];
      int sr = edr_attack_surface_execute("config_reload", &agent->cfg, d, sizeof(d));
      if (sr != 0) {
        EDR_LOGE("[attack_surface] remote config_reload POST failed: %s\n", d);
      } else if (strncmp(d, "uploaded_", 9) == 0) {
        EDR_LOGV("[attack_surface] remote config_reload %s\n", d);
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
      fprintf(stderr, "[ave] AVE_SyncFromEdrConfig(远程) 失败: %d\n", av);
    }
  }
  EDR_LOGV("[config] 远程配置已应用: preprocessing + resource_limit + self_protect + attack_surface tick + ave%s%s\n",
           fp[0] ? " fingerprint=" : "", fp[0] ? fp : "");

  /* 远程 P0 规则包热加载 (B1.1) */
  {
    const char *p0_url = getenv("EDR_REMOTE_P0_BUNDLE_URL");
    if (p0_url && p0_url[0]) {
      char p0_tmp[520];
      if (edr_remote_tmp_path(p0_tmp, sizeof(p0_tmp)) == 0) {
        if (edr_remote_fetch_toml(p0_url, p0_tmp) == 0) {
          char p0_dst[1024];
          if (edr_p0_bundle_dst_path(p0_dst, sizeof(p0_dst)) == 0) {
            if (rename(p0_tmp, p0_dst) != 0) {
              (void)remove(p0_tmp);
              EDR_LOGE("[config] P0 bundle 写入失败: %s\n", p0_dst);
            } else {
              EDR_LOGV("[config] P0 bundle 热加载成功 (%s)\n", p0_dst);
              edr_p0_rule_ir_reload();
            }
          } else {
            (void)remove(p0_tmp);
          }
        } else {
          (void)remove(p0_tmp);
        }
      }
    }
  }
}

/**
 * §19.8 周期快照：仅当 `[attack_surface].enabled=true` 时，按
 * `edr_attack_surface_effective_periodic_interval_s`（`min(port, service, policy, full)`，钳 60～604800s）
 * 且 **ETW/按需刷新 POST 与周期 POST 共享同一间隔**：避免 etw_tcpip_wf 单独打满带宽。
 * 按需轮询：按 `conn_interval_s`（钳 15～120s）GET .../attack-surface/refresh-request；仅当
 * 距上次成功 POST 已满间隔且平台 refreshPending 时 POST。
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
  const uint32_t post_iv_sec = edr_attack_surface_effective_periodic_interval_s(cfg);
  const uint64_t post_iv_ns = (uint64_t)post_iv_sec * 1000000000ULL;
  int asurf_may_post = (now - agent->asurf_last_post_ns) >= post_iv_ns;

  if (cfg->attack_surface.etw_refresh_triggers_snapshot && asurf_may_post) {
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
        EDR_LOGE("[attack_surface] etw_tcpip_wf failed: %s\n", detail);
      } else if (strncmp(detail, "uploaded_", 9) == 0) {
        agent->asurf_last_post_ns = now;
        asurf_may_post = 0;
        EDR_LOGV("[attack_surface] etw_tcpip_wf %s\n", detail);
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
    asurf_may_post = (now - agent->asurf_last_post_ns) >= post_iv_ns;
    if (pr == 1 && asurf_may_post) {
      char detail[256];
      int r = edr_attack_surface_execute("refresh_request", cfg, detail, sizeof(detail));
      if (r != 0) {
        EDR_LOGE("[attack_surface] refresh_request failed: %s\n", detail);
      } else if (strncmp(detail, "uploaded_", 9) == 0) {
        agent->asurf_last_post_ns = now;
        asurf_may_post = 0;
        EDR_LOGV("[attack_surface] refresh_request %s\n", detail);
      }
    }
  }

  if ((now - agent->asurf_last_post_ns) < post_iv_ns) {
    return;
  }
  agent->asurf_last_post_ns = now;

  char detail[256];
  int r = edr_attack_surface_execute("periodic_attack_surface", cfg, detail, sizeof(detail));
  if (r != 0) {
    EDR_LOGE("[attack_surface] periodic failed: %s\n", detail);
    return;
  }
  if (strncmp(detail, "uploaded_", 9) == 0) {
    EDR_LOGV("[attack_surface] periodic %s\n", detail);
  }
}
