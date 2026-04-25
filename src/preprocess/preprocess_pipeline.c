#include "edr/preprocess.h"

#include "edr/resource.h"
#include "edr/attack_surface_report.h"
#include "edr/config.h"
#include "edr/behavior_from_slot.h"
#include "edr/behavior_proto.h"
#include "edr/behavior_proto_c.h"
#include "edr/behavior_wire.h"
#include "edr/dedup.h"
#include "edr/emit_rules.h"
#include "edr/event_batch.h"
#include "edr/event_bus.h"
#include "edr/ave_cross_engine_feed.h"
#include "edr/pid_history_pmfe.h"
#include "edr/pmfe.h"
#include "edr/process_chain_depth.h"
#include "edr/storage_queue.h"
#include "edr/transport_sink.h"
#include "edr/types.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
static HANDLE s_thread;
static volatile LONG s_stop_preprocess;
#else
#include <pthread.h>
#include <unistd.h>
static pthread_t s_thread;
static volatile int s_stop_preprocess;
#endif

static int s_preprocess_active;
enum { EDR_PREPROCESS_POP_BURST = 32 };

static EdrEventBus *s_bus;
static int s_l2_split_enabled;
static double s_l2_unmatched_keep_ratio;
static int s_l3_pressure_enabled;
static uint32_t s_l3_pressure_high_pct;
static uint32_t s_l3_pressure_recover_pct;
static uint32_t s_l3_drop_permille;
static int s_l3_pressure_active;
static uint32_t s_drop_l2_unmatched;
static uint32_t s_drop_l3_pressure;
static int s_strict_behavior_gate_enabled;
static uint32_t s_drop_strict_behavior_gate;
static uint32_t s_rng_state = 0x12345678u;

/** 与 [agent] 对齐，写入每条 BehaviorRecord（线格式 / nanopb 与 gRPC endpoint_id 一致） */
static char s_cfg_endpoint_id[128];
static char s_cfg_tenant_id[128];

static void sync_agent_ids_from_cfg(const EdrConfig *cfg) {
  if (!cfg) {
    return;
  }
  snprintf(s_cfg_endpoint_id, sizeof(s_cfg_endpoint_id), "%s", cfg->agent.endpoint_id);
  snprintf(s_cfg_tenant_id, sizeof(s_cfg_tenant_id), "%s", cfg->agent.tenant_id);
}

static void apply_agent_ids_to_record(EdrBehaviorRecord *br) {
  if (!br) {
    return;
  }
  if (s_cfg_tenant_id[0]) {
    snprintf(br->tenant_id, sizeof(br->tenant_id), "%s", s_cfg_tenant_id);
  }
  if (s_cfg_endpoint_id[0] && strcmp(s_cfg_endpoint_id, "auto") != 0) {
    snprintf(br->endpoint_id, sizeof(br->endpoint_id), "%s", s_cfg_endpoint_id);
  }
}

static int slot_is_high_value(const EdrEventSlot *slot) {
  if (!slot) {
    return 0;
  }
  if (slot->priority == 0u || slot->attack_surface_hint != 0u) {
    return 1;
  }
  switch (slot->type) {
    case EDR_EVENT_PROCESS_INJECT:
    case EDR_EVENT_THREAD_CREATE_REMOTE:
    case EDR_EVENT_PROTOCOL_SHELLCODE:
    case EDR_EVENT_WEBSHELL_DETECTED:
    case EDR_EVENT_FIREWALL_RULE_CHANGE:
      return 1;
    default:
      return 0;
  }
}

static int slot_is_behavior_engine_process_event(const EdrEventSlot *slot) {
  if (!slot) {
    return 0;
  }
  switch (slot->type) {
    case EDR_EVENT_PROCESS_CREATE:
    case EDR_EVENT_PROCESS_INJECT:
      return 1;
    default:
      return 0;
  }
}

static uint32_t rng_next_u32(void) {
  s_rng_state = s_rng_state * 1664525u + 1013904223u;
  return s_rng_state;
}

static int rng_hit_permille(uint32_t p) {
  if (p == 0u) {
    return 0;
  }
  if (p >= 1000u) {
    return 1;
  }
  return (rng_next_u32() % 1000u) < p;
}

static uint32_t clamp_u32(uint32_t v, uint32_t lo, uint32_t hi) {
  if (v < lo) {
    return lo;
  }
  if (v > hi) {
    return hi;
  }
  return v;
}

static int getenv_int_default(const char *key, int defv) {
  const char *v = getenv(key);
  if (!v || !v[0]) {
    return defv;
  }
  return atoi(v);
}

static double getenv_double_default(const char *key, double defv) {
  const char *v = getenv(key);
  if (!v || !v[0]) {
    return defv;
  }
  return atof(v);
}

static void preprocess_init_l2_l3_controls(const EdrConfig *cfg) {
  s_l2_split_enabled = getenv_int_default("EDR_PREPROCESS_L2_SPLIT", 0) == 1 ? 1 : 0;
  s_l2_unmatched_keep_ratio = cfg ? cfg->preprocessing.sampling_rate_whitelist : 0.1;
  s_l2_unmatched_keep_ratio =
      getenv_double_default("EDR_PREPROCESS_L2_KEEP_RATIO", s_l2_unmatched_keep_ratio);
  if (s_l2_unmatched_keep_ratio < 0.0) {
    s_l2_unmatched_keep_ratio = 0.0;
  }
  if (s_l2_unmatched_keep_ratio > 0.10) {
    s_l2_unmatched_keep_ratio = 0.10;
  }

  s_l3_pressure_enabled = getenv_int_default("EDR_PREPROCESS_L3_PRESSURE", 0) == 1 ? 1 : 0;
  s_l3_pressure_high_pct = (uint32_t)getenv_int_default("EDR_PREPROCESS_L3_HIGH_PCT", 90);
  s_l3_pressure_recover_pct = (uint32_t)getenv_int_default("EDR_PREPROCESS_L3_RECOVER_PCT", 70);
  s_l3_drop_permille = (uint32_t)getenv_int_default("EDR_PREPROCESS_L3_DROP_PERMILLE", 800);
  s_l3_pressure_high_pct = clamp_u32(s_l3_pressure_high_pct, 50u, 99u);
  s_l3_pressure_recover_pct = clamp_u32(s_l3_pressure_recover_pct, 10u, s_l3_pressure_high_pct);
  s_l3_drop_permille = clamp_u32(s_l3_drop_permille, 0u, 1000u);
  s_l3_pressure_active = 0;
  s_drop_l2_unmatched = 0u;
  s_drop_l3_pressure = 0u;
  s_strict_behavior_gate_enabled =
      getenv_int_default("EDR_PREPROCESS_STRICT_BEHAVIOR_GATE", 0) == 1 ? 1 : 0;
  s_drop_strict_behavior_gate = 0u;
  if (cfg) {
    s_rng_state ^= cfg->collection.max_event_queue_size;
    s_rng_state ^= cfg->upload.batch_max_events << 1;
  }
}

static void process_one_slot(const EdrEventSlot *slot) {
  /* AGT-010：资源压力下跳过低优先级槽位；保留 priority==0 与 §19.10 attack_surface_hint */
  if (edr_resource_preprocess_throttle_active() && slot && slot->priority != 0u &&
      slot->attack_surface_hint == 0u) {
    return;
  }
  if (slot && slot->attack_surface_hint) {
    edr_attack_surface_etw_signal();
  }
#if defined(__linux__) && !defined(_WIN32)
  /* Windows 在 ETW 回调中调用；Linux 行为事件（含未来 audit/eBPF 注入）在此对齐 */
  if (slot && (slot->type == EDR_EVENT_PROCESS_CREATE || slot->type == EDR_EVENT_PROCESS_TERMINATE)) {
    edr_pmfe_on_process_lifecycle_hint();
  }
#endif
  uint8_t buf[16384];
  EdrBehaviorRecord br;
  edr_behavior_from_slot(slot, &br);
  edr_behavior_record_fill_process_chain_depth(&br);
  apply_agent_ids_to_record(&br);
  edr_pid_history_pmfe_fill_record(&br);
  edr_pmfe_on_preprocess_slot(slot, &br);
  if (s_l2_split_enabled && br.priority != 0u &&
      slot_is_behavior_engine_process_event(slot)) {
    int rr = edr_emit_rules_evaluate(&br);
    if (rr < 0) {
      uint32_t keep_permille = (uint32_t)(s_l2_unmatched_keep_ratio * 1000.0 + 0.5);
      if (!rng_hit_permille(keep_permille)) {
        s_drop_l2_unmatched++;
        return;
      }
    }
  }
  /* P2 T9：Shellcode / Webshell / PMFE → AVE 行为槽（E 组 46–47、53–54） */
  edr_ave_cross_engine_feed_from_record(&br);
  if (!edr_preprocess_should_emit(&br)) {
    return;
  }
  size_t n = 0;
  const char *enc = getenv("EDR_BEHAVIOR_ENCODING");
  if (enc && strcmp(enc, "protobuf") == 0) {
#ifdef EDR_HAVE_NANOPB
    n = edr_behavior_record_encode_protobuf(&br, buf, sizeof(buf));
#endif
    if (n == 0) {
      n = edr_behavior_wire_encode(&br, buf, sizeof(buf));
    }
  } else if (enc && strcmp(enc, "protobuf_c") == 0) {
    n = edr_behavior_record_encode_protobuf_c(&br, buf, sizeof(buf));
    if (n == 0) {
      n = edr_behavior_wire_encode(&br, buf, sizeof(buf));
    }
  } else {
    n = edr_behavior_wire_encode(&br, buf, sizeof(buf));
  }
  if (n > 0) {
    (void)edr_event_batch_push(buf, n);
  }
}

#ifdef _WIN32
static DWORD WINAPI preprocess_main(void *arg) {
#else
static void *preprocess_main(void *arg) {
#endif
  (void)arg;
  for (;;) {
    EdrEventSlot slots[EDR_PREPROCESS_POP_BURST];
    if (s_l3_pressure_enabled && s_bus) {
      uint32_t cap = edr_event_bus_capacity(s_bus);
      if (cap > 0u) {
        uint32_t used = edr_event_bus_used_approx(s_bus);
        uint32_t pct = (used * 100u) / cap;
        if (!s_l3_pressure_active && pct >= s_l3_pressure_high_pct) {
          s_l3_pressure_active = 1;
        } else if (s_l3_pressure_active && pct <= s_l3_pressure_recover_pct) {
          s_l3_pressure_active = 0;
        }
      }
    }
    uint32_t n = edr_event_bus_try_pop_many(s_bus, slots, EDR_PREPROCESS_POP_BURST);
    if (n > 0u) {
      for (uint32_t i = 0; i < n; i++) {
        if (s_strict_behavior_gate_enabled &&
            !slot_is_behavior_engine_process_event(&slots[i])) {
          s_drop_strict_behavior_gate++;
          continue;
        }
        if (s_l3_pressure_active && !slot_is_high_value(&slots[i])) {
          if (!rng_hit_permille(1000u - s_l3_drop_permille)) {
            s_drop_l3_pressure++;
            continue;
          }
        }
        process_one_slot(&slots[i]);
      }
      edr_event_batch_poll_timeout();
      edr_storage_queue_poll_drain();
      continue;
    }
    edr_event_batch_poll_timeout();
    edr_storage_queue_poll_drain();
#ifdef _WIN32
    if (s_stop_preprocess) {
      for (;;) {
        uint32_t rn = edr_event_bus_try_pop_many(s_bus, slots, EDR_PREPROCESS_POP_BURST);
        if (rn == 0u) {
          break;
        }
        for (uint32_t i = 0; i < rn; i++) {
          process_one_slot(&slots[i]);
        }
      }
      edr_storage_queue_poll_drain();
      break;
    }
    Sleep(1);
#else
    if (s_stop_preprocess) {
      for (;;) {
        uint32_t rn = edr_event_bus_try_pop_many(s_bus, slots, EDR_PREPROCESS_POP_BURST);
        if (rn == 0u) {
          break;
        }
        for (uint32_t i = 0; i < rn; i++) {
          process_one_slot(&slots[i]);
        }
      }
      edr_storage_queue_poll_drain();
      break;
    }
    usleep(1000);
#endif
  }
#ifdef _WIN32
  return 0;
#else
  return NULL;
#endif
}

EdrError edr_preprocess_start(EdrEventBus *bus, const EdrConfig *cfg) {
  EdrConfig defaults;
  if (!bus) {
    return EDR_ERR_INVALID_ARG;
  }
  if (s_preprocess_active) {
    return EDR_OK;
  }
  if (!cfg) {
    edr_config_apply_defaults(&defaults);
    cfg = &defaults;
  }
  {
    size_t max_bytes = (size_t)cfg->upload.batch_max_size_mb * 1024u * 1024u;
    if (max_bytes == 0) {
      max_bytes = EDR_EVENT_BATCH_CAP;
    }
    EdrError be = edr_event_batch_init(max_bytes, cfg->upload.batch_max_events,
                                       cfg->upload.batch_timeout_s);
    if (be != EDR_OK) {
      return be;
    }
  }
  edr_dedup_configure(cfg->preprocessing.dedup_window_s,
                      cfg->preprocessing.high_freq_threshold);
  edr_emit_rules_configure(cfg);
  edr_dedup_init();
  preprocess_init_l2_l3_controls(cfg);
  sync_agent_ids_from_cfg(cfg);
  s_bus = bus;
#ifdef _WIN32
  s_stop_preprocess = 0;
  s_thread = CreateThread(NULL, 0, preprocess_main, NULL, 0, NULL);
  if (!s_thread) {
    s_bus = NULL;
    edr_event_batch_shutdown();
    return EDR_ERR_INTERNAL;
  }
#else
  s_stop_preprocess = 0;
  if (pthread_create(&s_thread, NULL, preprocess_main, NULL) != 0) {
    s_bus = NULL;
    edr_event_batch_shutdown();
    return EDR_ERR_INTERNAL;
  }
#endif
  s_preprocess_active = 1;
  return EDR_OK;
}

void edr_preprocess_apply_config(const EdrConfig *cfg) {
  if (!s_preprocess_active || !cfg) {
    return;
  }
  edr_dedup_configure(cfg->preprocessing.dedup_window_s, cfg->preprocessing.high_freq_threshold);
  edr_emit_rules_configure(cfg);
  preprocess_init_l2_l3_controls(cfg);
  sync_agent_ids_from_cfg(cfg);
}

void edr_preprocess_copy_agent_ids(char *endpoint_id, size_t endpoint_cap, char *tenant_id, size_t tenant_cap) {
  if (endpoint_id && endpoint_cap > 0) {
    snprintf(endpoint_id, endpoint_cap, "%s", s_cfg_endpoint_id);
  }
  if (tenant_id && tenant_cap > 0) {
    snprintf(tenant_id, tenant_cap, "%s", s_cfg_tenant_id);
  }
}

void edr_preprocess_stop(void) {
  if (!s_preprocess_active) {
    return;
  }
#ifdef _WIN32
  InterlockedExchange(&s_stop_preprocess, 1);
  if (s_thread) {
    WaitForSingleObject(s_thread, 60000);
    CloseHandle(s_thread);
    s_thread = NULL;
  }
#else
  s_stop_preprocess = 1;
  pthread_join(s_thread, NULL);
#endif
  s_bus = NULL;
  s_preprocess_active = 0;
  if (s_drop_l2_unmatched > 0u || s_drop_l3_pressure > 0u ||
      s_drop_strict_behavior_gate > 0u) {
    fprintf(stderr,
            "[preprocess/l2l3] strict_behavior_gate_drop=%u l2_unmatched_drop=%u l3_pressure_drop=%u\n",
            s_drop_strict_behavior_gate, s_drop_l2_unmatched, s_drop_l3_pressure);
  }
  edr_event_batch_shutdown();
  edr_emit_rules_configure(NULL);
  edr_dedup_reset();
}
