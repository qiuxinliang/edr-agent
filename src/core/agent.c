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

#include "edr/ave.h"
#include "edr/grpc_client.h"
#include "edr/ingest_http.h"
#include "edr/transport_sink.h"

#include "ave_onnx_infer.h"

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

static void edr_agent_print_console_heartbeat_line(const EdrAgent *agent) {
  char grpc_diag[200];
  int ave_mf = 0, ave_nf = 0, ave_dir = 0;
  edr_grpc_client_diag(grpc_diag, sizeof(grpc_diag));
  if (!grpc_diag[0]) {
    snprintf(grpc_diag, sizeof(grpc_diag), "%s", "-");
  }
  edr_ave_get_scan_counts(&ave_mf, &ave_nf, &ave_dir);
  fprintf(stderr,
          "[heartbeat] grpc_ready=%d grpc_diag=%s http_ingest=%d batches=%lu target=%s rpc_ok=%lu "
          "rpc_fail=%lu wire_events=%lu wire_bytes=%lu "
          "ave_model_files=%d ave_dir_ready=%d onnx_static_ready=%d onnx_behavior_ready=%d\n",
          edr_grpc_client_ready(), grpc_diag, edr_ingest_http_configured(),
          edr_transport_batch_count(), agent->cfg.server.address, edr_grpc_client_rpc_ok(),
          edr_grpc_client_rpc_fail(), edr_transport_wire_events_count(),
          edr_transport_wire_bytes_count(), ave_mf, ave_dir, edr_onnx_runtime_ready(),
          edr_onnx_behavior_ready());
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
        fprintf(stderr, "[config] fingerprint=%s path=%s\n", fp, load_path);
      }
    }
  }
  edr_self_protect_init();
  edr_resource_init(&agent->cfg);
  {
    int ar = AVE_InitFromEdrConfig(&agent->cfg);
    if (ar != AVE_OK) {
      fprintf(stderr, "[ave] AVE_InitFromEdrConfig failed: %d\n", ar);
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
    fprintf(stderr, "[config] 热重载: preprocessing + resource_limit + self_protect + attack_surface tick + ave\n");
    char fp[80];
    edr_config_fingerprint(agent->config_path, fp, sizeof(fp));
    if (fp[0]) {
      fprintf(stderr, "[config] 热重载 fingerprint=%s\n", fp);
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
#ifdef _WIN32
  const char *t = getenv("TEMP");
  if (!t || !t[0]) {
    t = ".";
  }
  snprintf(tmp, sizeof(tmp), "%s\\edr_remote_%lu.toml", t, (unsigned long)GetCurrentProcessId());
  {
    char cmd[2048];
    snprintf(cmd, sizeof(cmd), "curl -fsSL \"%s\" -o \"%s\" 1>nul 2>nul", url, tmp);
    if (system(cmd) != 0) {
      fprintf(stderr, "[config] 远程 TOML 拉取失败（需系统 PATH 中有 curl）\n");
      return;
    }
  }
#else
  snprintf(tmp, sizeof(tmp), "/tmp/edr_remote_%d.toml", (int)getpid());
  {
    char cmd[2048];
    snprintf(cmd, sizeof(cmd), "curl -fsSL '%s' -o '%s' 2>/dev/null", url, tmp);
    if (system(cmd) != 0) {
      fprintf(stderr, "[config] 远程 TOML 拉取失败（curl 非零退出）\n");
      return;
    }
  }
#endif

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
      fprintf(stderr, "[ave] AVE_SyncFromEdrConfig(远程) 失败: %d\n", av);
    }
  }
  fprintf(stderr, "[config] 远程配置已应用: preprocessing + resource_limit + self_protect + attack_surface tick + ave");
  if (fp[0]) {
    fprintf(stderr, " fingerprint=%s", fp);
  }
  fprintf(stderr, "\n");
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
