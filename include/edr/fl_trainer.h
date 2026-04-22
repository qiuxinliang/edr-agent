/**
 * 联邦学习本地训练（FL §10）：Round 协议线程与 FLLocalTrainer。
 * 仅在 CMake `EDR_WITH_FL_TRAINER=ON` 时编译进 `edr_agent`。
 */
#ifndef EDR_FL_TRAINER_H
#define EDR_FL_TRAINER_H

#include "edr/config.h"

#define FLT_OK 0
#define FLT_ERR_INVALID_ARG -1
#define FLT_ERR_NOT_INITIALIZED -2
#define FLT_ERR_INTERNAL -3

typedef enum FLTStatus {
  FLT_STATUS_IDLE = 0,
  FLT_STATUS_ANNOUNCED = 1,
  FLT_STATUS_TRAINING = 2,
  FLT_STATUS_UPLOADING = 3,
  FLT_STATUS_DONE = 4,
  FLT_STATUS_SKIPPED = 5,
  FLT_STATUS_ERROR = 6,
  FLT_STATUS_DISABLED = 7,
} FLTStatus;

/**
 * 与 FL 组件设计对齐的运行时参数；`ave_ctx` 预留为后续绑定 AVEngine。
 */
typedef struct FLTConfig {
  void *ave_ctx;
  /** 与 `[agent] endpoint_id` / `tenant_id` 对齐，供上传与 gRPC 元数据 */
  char agent_endpoint_id[128];
  char tenant_id[128];
  char coordinator_grpc_addr[256];
  char coordinator_http_url[512];
  char privacy_budget_db_path[1024];
  char fl_samples_db_path[1024];
  int min_new_samples;
  float idle_cpu_threshold;
  int local_epochs;
  float dp_epsilon;
  float dp_clip_norm;
  int max_participated_rounds;
  int gradient_chunk_size_kb;
  uint32_t mock_round_interval_s;
  /** 与 `[fl] model_target` 一致；决定 `fl_round` 梯度向量维数（512 vs 256） */
  char model_target[32];
  /** T-015：与 `EdrConfig.fl.frozen_layer_*` 一致 */
  size_t frozen_layer_count_static;
  char frozen_layer_static[EDR_FL_FROZEN_MAX][EDR_FL_FROZEN_NAME_MAX];
  size_t frozen_layer_count_behavior;
  char frozen_layer_behavior[EDR_FL_FROZEN_MAX][EDR_FL_FROZEN_NAME_MAX];
  /** 与 `EdrConfig.fl.coordinator_secp256r1_pub*` 一致；供 FL3 封装 */
  uint8_t coordinator_secp256r1_pub[96];
  uint32_t coordinator_secp256r1_pub_len;
} FLTConfig;

int FLT_Init(const FLTConfig *cfg);
int FLT_InitFromEdrConfig(const EdrConfig *cfg);
int FLT_Start(void);
void FLT_Shutdown(void);
FLTStatus FLT_GetStatus(void);
int FLT_GetPrivacyBudget(int *participated_out, int *max_rounds_out);

#endif
