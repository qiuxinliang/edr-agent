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
    uint32_t n = edr_event_bus_try_pop_many(s_bus, slots, EDR_PREPROCESS_POP_BURST);
    if (n > 0u) {
      for (uint32_t i = 0; i < n; i++) {
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
  edr_event_batch_shutdown();
  edr_emit_rules_configure(NULL);
  edr_dedup_reset();
}
