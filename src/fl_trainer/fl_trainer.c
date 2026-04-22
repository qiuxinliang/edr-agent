#include "edr/fl_trainer.h"

#include "edr/fl_crypto.h"

#include "fl_frozen_layers.h"
#include "fl_round_internal.h"

#include "edr/fl_round.h"

#include "fl_samples_db.h"

#include "edr/fl_privacy_budget.h"

#include <stddef.h>
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
static HANDLE s_thr_protocol;
static HANDLE s_thr_local;
#else
#include <pthread.h>
static pthread_t s_thr_protocol;
static pthread_t s_thr_local;
#endif
static volatile int s_stop;

static FLTConfig s_cfg;
static int s_inited;
static int s_started;

#ifdef _WIN32
static DWORD WINAPI fl_protocol_thread_main(void *arg) {
#else
static void *fl_protocol_thread_main(void *arg) {
#endif
  (void)arg;
  fl_round_protocol_thread_loop((volatile int *)&s_stop, s_cfg.mock_round_interval_s);
#ifdef _WIN32
  return 0;
#else
  return NULL;
#endif
}

#ifdef _WIN32
static DWORD WINAPI fllocal_trainer_thread_main(void *arg) {
#else
static void *fllocal_trainer_thread_main(void *arg) {
#endif
  (void)arg;
  fl_round_trainer_thread_loop((volatile int *)&s_stop);
#ifdef _WIN32
  return 0;
#else
  return NULL;
#endif
}

int FLT_Init(const FLTConfig *cfg) {
  if (!cfg) {
    return FLT_ERR_INVALID_ARG;
  }
  if (s_inited) {
    return FLT_OK;
  }
  s_cfg = *cfg;
  fl_round_init();
  fl_round_set_config(&s_cfg);
  fl_frozen_layers_log_once(&s_cfg);
  fl_privacy_budget_open(s_cfg.privacy_budget_db_path[0] ? s_cfg.privacy_budget_db_path : NULL);
  if (s_cfg.fl_samples_db_path[0]) {
    if (fl_samples_db_open(s_cfg.fl_samples_db_path) == 0) {
      fl_samples_db_register_ave_bridge();
    }
  }
  s_inited = 1;
  return FLT_OK;
}

int FLT_InitFromEdrConfig(const EdrConfig *cfg) {
  FLTConfig fc;

  if (!cfg) {
    return FLT_ERR_INVALID_ARG;
  }
  memset(&fc, 0, sizeof(fc));
  snprintf(fc.agent_endpoint_id, sizeof(fc.agent_endpoint_id), "%s", cfg->agent.endpoint_id);
  snprintf(fc.tenant_id, sizeof(fc.tenant_id), "%s", cfg->agent.tenant_id);
  snprintf(fc.coordinator_grpc_addr, sizeof(fc.coordinator_grpc_addr), "%s",
           cfg->fl.coordinator_grpc_addr);
  snprintf(fc.coordinator_http_url, sizeof(fc.coordinator_http_url), "%s",
           cfg->fl.coordinator_http_url);
  snprintf(fc.privacy_budget_db_path, sizeof(fc.privacy_budget_db_path), "%s",
           cfg->fl.privacy_budget_db_path);
  snprintf(fc.fl_samples_db_path, sizeof(fc.fl_samples_db_path), "%s", cfg->fl.fl_samples_db_path);
  fc.min_new_samples = cfg->fl.min_new_samples;
  fc.idle_cpu_threshold = cfg->fl.idle_cpu_threshold;
  fc.local_epochs = cfg->fl.local_epochs;
  fc.dp_epsilon = cfg->fl.dp_epsilon;
  fc.dp_clip_norm = cfg->fl.dp_clip_norm;
  fc.max_participated_rounds = cfg->fl.max_participated_rounds;
  fc.gradient_chunk_size_kb = cfg->fl.gradient_chunk_size_kb;
  fc.mock_round_interval_s = cfg->fl.mock_round_interval_s;
  snprintf(fc.model_target, sizeof(fc.model_target), "%s", cfg->fl.model_target);
  fc.frozen_layer_count_static = cfg->fl.frozen_layer_count_static;
  memcpy(fc.frozen_layer_static, cfg->fl.frozen_layer_static, sizeof(fc.frozen_layer_static));
  fc.frozen_layer_count_behavior = cfg->fl.frozen_layer_count_behavior;
  memcpy(fc.frozen_layer_behavior, cfg->fl.frozen_layer_behavior, sizeof(fc.frozen_layer_behavior));
  fc.ave_ctx = NULL;
  fc.coordinator_secp256r1_pub_len = cfg->fl.coordinator_secp256r1_pub_len;
  if (fc.coordinator_secp256r1_pub_len > 0u) {
    memcpy(fc.coordinator_secp256r1_pub, cfg->fl.coordinator_secp256r1_pub,
           (size_t)fc.coordinator_secp256r1_pub_len);
  }
  return FLT_Init(&fc);
}

int FLT_Start(void) {
  if (!s_inited) {
    return FLT_ERR_NOT_INITIALIZED;
  }
  if (s_started) {
    return FLT_OK;
  }
#ifdef _WIN32
  s_stop = 0;
  s_thr_protocol = CreateThread(NULL, 0, fl_protocol_thread_main, NULL, 0, NULL);
  s_thr_local = CreateThread(NULL, 0, fllocal_trainer_thread_main, NULL, 0, NULL);
  if (!s_thr_protocol || !s_thr_local) {
    InterlockedExchange((LONG *)&s_stop, 1);
    if (s_thr_protocol) {
      WaitForSingleObject(s_thr_protocol, 60000);
      CloseHandle(s_thr_protocol);
      s_thr_protocol = NULL;
    }
    if (s_thr_local) {
      WaitForSingleObject(s_thr_local, 60000);
      CloseHandle(s_thr_local);
      s_thr_local = NULL;
    }
    return FLT_ERR_INTERNAL;
  }
#else
  s_stop = 0;
  if (pthread_create(&s_thr_protocol, NULL, fl_protocol_thread_main, NULL) != 0) {
    return FLT_ERR_INTERNAL;
  }
  if (pthread_create(&s_thr_local, NULL, fllocal_trainer_thread_main, NULL) != 0) {
    s_stop = 1;
    pthread_join(s_thr_protocol, NULL);
    return FLT_ERR_INTERNAL;
  }
#endif
  s_started = 1;
  return FLT_OK;
}

void FLT_Shutdown(void) {
  if (!s_started) {
    fl_samples_db_unregister_ave_bridge();
    fl_samples_db_close();
    fl_privacy_budget_close();
    fl_round_shutdown();
    s_inited = 0;
    memset(&s_cfg, 0, sizeof(s_cfg));
    return;
  }
#ifdef _WIN32
  InterlockedExchange((LONG *)&s_stop, 1);
  if (s_thr_protocol) {
    WaitForSingleObject(s_thr_protocol, 60000);
    CloseHandle(s_thr_protocol);
    s_thr_protocol = NULL;
  }
  if (s_thr_local) {
    WaitForSingleObject(s_thr_local, 60000);
    CloseHandle(s_thr_local);
    s_thr_local = NULL;
  }
#else
  s_stop = 1;
  pthread_join(s_thr_protocol, NULL);
  pthread_join(s_thr_local, NULL);
#endif
  fl_samples_db_unregister_ave_bridge();
  fl_samples_db_close();
  fl_privacy_budget_close();
  fl_round_shutdown();
  s_started = 0;
  s_inited = 0;
  memset(&s_cfg, 0, sizeof(s_cfg));
}

FLTStatus FLT_GetStatus(void) {
  if (!s_inited || !s_started) {
    return FLT_STATUS_DISABLED;
  }
  return (FLTStatus)fl_round_get_phase();
}

int FLT_GetPrivacyBudget(int *participated_out, int *max_rounds_out) {
  if (!participated_out || !max_rounds_out) {
    return FLT_ERR_INVALID_ARG;
  }
  if (!s_inited) {
    return FLT_ERR_NOT_INITIALIZED;
  }
  *max_rounds_out = s_cfg.max_participated_rounds;
  return fl_privacy_budget_get(participated_out, *max_rounds_out);
}
