#include "edr/fl_round.h"
#include "fl_round_internal.h"

#include "edr/ave_sdk.h"
#include "edr/fl_crypto.h"
#include "edr/fl_dp.h"
#include "edr/fl_kafka_stub.h"
#include "edr/fl_privacy_budget.h"
#include "edr/local_train_core.h"

#include "fl_frozen_layers.h"
#include "fl_gradient_upload.h"
#include "fl_samples_db.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
static void fl_ms_sleep(unsigned ms) {
  Sleep(ms);
}
#else
#include <unistd.h>
static void fl_ms_sleep(unsigned ms) {
  usleep(ms * 1000u);
}
#endif

/** 最大训练维度（`static` 512；`behavior` 使用前缀 256） */
#define FL_VEC_DIM_MAX 512u

static size_t fl_vec_dim_for_model_target(const FLTConfig *cfg) {
  if (cfg && strncmp(cfg->model_target, "behavior", 8) == 0) {
    return (size_t)AVE_FL_FEATURE_DIM_BEHAVIOR_DEFAULT;
  }
  return (size_t)AVE_FL_FEATURE_DIM_STATIC;
}

static FLTConfig s_cfg;
static int s_cfg_ok;
static volatile int s_has_round;
static volatile uint64_t s_round_id;
static FLRoundPhase s_trainer_phase;

void fl_round_set_config(const FLTConfig *cfg) {
  if (!cfg) {
    s_cfg_ok = 0;
    fl_crypto_set_coordinator_pubkey(NULL, 0);
    return;
  }
  s_cfg = *cfg;
  s_cfg_ok = 1;
  if (cfg->coordinator_secp256r1_pub_len > 0u) {
    fl_crypto_set_coordinator_pubkey(cfg->coordinator_secp256r1_pub,
                                     (size_t)cfg->coordinator_secp256r1_pub_len);
  } else {
    fl_crypto_set_coordinator_pubkey(NULL, 0);
  }
}

static void fl_round_kafka_cb(const FLRoundInfoKafka *info, void *user) {
  static uint64_t s_last_dup;
  (void)user;
  if (!info || info->round_id == 0u) {
    return;
  }
  if (info->round_id == s_last_dup) {
    return;
  }
  s_last_dup = info->round_id;
  s_round_id = info->round_id;
  s_has_round = 1;
}

void fl_round_init(void) {
  s_has_round = 0;
  s_round_id = 0;
  s_trainer_phase = FL_ROUND_IDLE;
  (void)fl_kafka_register_round_consumer(fl_round_kafka_cb, NULL);
}

void fl_round_shutdown(void) {
  fl_kafka_round_consumer_shutdown();
  s_has_round = 0;
  s_cfg_ok = 0;
}

FLRoundPhase fl_round_get_phase(void) {
  return s_trainer_phase;
}

void fl_round_mock_inject(uint64_t round_id) {
  s_round_id = round_id;
  s_has_round = 1;
}

void fl_round_protocol_thread_loop(volatile int *stop_flag, uint32_t mock_interval_s) {
  time_t last_inject = 0;

  while (!*stop_flag) {
    (void)fl_kafka_poll_round_stub();
    if (mock_interval_s > 0u) {
      time_t now = time(NULL);
      if (last_inject == 0 ||
          (uint64_t)(now - last_inject) >= (uint64_t)mock_interval_s) {
        fl_round_mock_inject((uint64_t)now);
        last_inject = now;
      }
    }
    fl_ms_sleep(200u);
  }
}

void fl_round_trainer_thread_loop(volatile int *stop_flag) {
  float grad[FL_VEC_DIM_MAX];
  uint8_t sealed[65536];
  size_t sealed_len = 0;
  uint64_t rng = 0xC0FFEEu;
  char rowbuf[65 * 256];
  size_t n_samples = 0;
  size_t vec_dim = (size_t)AVE_FL_FEATURE_DIM_STATIC;

  while (!*stop_flag) {
    if (!s_has_round) {
      fl_ms_sleep(200u);
      continue;
    }
    s_has_round = 0;
    if (!s_cfg_ok) {
      s_trainer_phase = FL_ROUND_ERROR;
      continue;
    }
    vec_dim = fl_vec_dim_for_model_target(&s_cfg);
    if (vec_dim > FL_VEC_DIM_MAX) {
      vec_dim = FL_VEC_DIM_MAX;
    }

    s_trainer_phase = FL_ROUND_ANNOUNCED;

    n_samples = 0;
    if (fl_samples_db_list_static_sha256(rowbuf, 65u, 256u, &n_samples) != 0) {
      fprintf(stderr,
              "[fl] round skipped: fl_samples_db_list_static_sha256 failed (check fl_samples_db_path / "
              "SQLite / schema)\n");
      s_trainer_phase = FL_ROUND_SKIPPED;
      continue;
    }
    if (n_samples < (size_t)s_cfg.min_new_samples) {
      fprintf(stderr,
              "[fl] round skipped: static sample rows=%zu < min_new_samples=%d (configured model_target=%s; "
              "enumeration uses only model_target='static'; behavior-only rows do not count)\n",
              n_samples, s_cfg.min_new_samples,
              s_cfg.model_target[0] ? s_cfg.model_target : "static");
      s_trainer_phase = FL_ROUND_SKIPPED;
      continue;
    }
    {
      int participated = 0;
      if (fl_privacy_budget_get(&participated, s_cfg.max_participated_rounds) == 0 &&
          participated >= s_cfg.max_participated_rounds) {
        fprintf(stderr, "[fl] round skipped: privacy budget exhausted (participated=%d >= max=%d)\n",
                participated, s_cfg.max_participated_rounds);
        s_trainer_phase = FL_ROUND_SKIPPED;
        continue;
      }
    }

    s_trainer_phase = FL_ROUND_TRAINING;
    memset(grad, 0, sizeof(grad));
    if (fl_local_train_mean_feature_delta(grad, vec_dim, n_samples) != 0) {
      fprintf(stderr, "[fl] round skipped: fl_local_train_mean_feature_delta failed (vec_dim=%zu n_samples=%zu)\n",
              vec_dim, n_samples);
      s_trainer_phase = FL_ROUND_SKIPPED;
      continue;
    }
    fl_frozen_layers_apply_feature_delta(&s_cfg, grad, vec_dim);

    fl_dp_clip_l2(grad, vec_dim, s_cfg.dp_clip_norm);
    {
      float scale = s_cfg.dp_clip_norm;
      if (s_cfg.dp_epsilon > 1e-6f) {
        scale /= s_cfg.dp_epsilon;
      }
      fl_dp_add_laplace(grad, vec_dim, scale, &rng);
    }

    s_trainer_phase = FL_ROUND_UPLOADING;
    sealed_len = 0;
    if (fl_crypto_seal_gradient((const uint8_t *)grad, vec_dim * sizeof(float), sealed, sizeof(sealed),
                                &sealed_len) != 0) {
      s_trainer_phase = FL_ROUND_ERROR;
      continue;
    }
    if (fl_gradient_upload_bytes(sealed, sealed_len, s_cfg.coordinator_http_url,
                                 s_cfg.coordinator_grpc_addr[0] ? s_cfg.coordinator_grpc_addr : NULL,
                                 s_cfg.agent_endpoint_id[0] ? s_cfg.agent_endpoint_id : NULL,
                                 s_cfg.tenant_id[0] ? s_cfg.tenant_id : NULL, s_round_id,
                                 (size_t)s_cfg.gradient_chunk_size_kb * 1024u, &s_cfg) != 0) {
      s_trainer_phase = FL_ROUND_ERROR;
      continue;
    }

    if (fl_privacy_budget_try_consume_one(s_cfg.max_participated_rounds) != 0) {
      s_trainer_phase = FL_ROUND_ERROR;
      continue;
    }

    s_trainer_phase = FL_ROUND_DONE;
    (void)s_round_id;
    s_trainer_phase = FL_ROUND_IDLE;
  }
}
