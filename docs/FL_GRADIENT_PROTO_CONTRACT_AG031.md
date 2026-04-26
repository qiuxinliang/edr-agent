# AG-031：端侧载荷与 `edr/v1/fl.proto` 对齐说明

**目的**：明确 **`UploadGradientsRequest`** 中 **`sealed_gradient` 字节** 与 Agent 内其它「导出」API 的边界，避免将 **整模型 ONNX 导出** 误当作联邦上传载荷。

**权威 proto**：`edr-agent/proto/edr/v1/fl.proto`（与协调器 `FLService` 一致）。

---

## 1. 联邦上传主路径（`fl_trainer` → 协调器）

| 步骤 | 代码 / 说明 |
|------|-------------|
| 本地梯度 | `fl_round.c`：`fl_local_train_mean_feature_delta` 得到 **`float` 向量**（维数由 `model_target` 与 `FLTConfig` 决定，与 `fl_samples` / 特征维一致）。 |
| DP | `fl_dp_clip_l2`、`fl_dp_add_laplace` 作用于上述向量。 |
| 密封 | `fl_crypto_seal_gradient(plain, plain_len, ...)` → **FL3** 二进制（魔数 **`FL3`**、版本字节 **`0x02`**，见 `fl_crypto.c` / `tests/test_fl_crypto_fl3.c`）。 |
| 上传 | `fl_gradient_upload_bytes` → **HTTP JSON**（`sealed_gradient` Base64）或 **gRPC** `UploadGradients`，载荷为 **`UploadGradientsRequest`**。 |
| 分块 | 当梯度字节大于 `[fl] gradient_chunk_size_kb` 时，同一逻辑 ID 下多片上传，proto 字段 **`gradient_upload_id` / `chunk_index` / `chunk_count`**。 |
| 样本加权 | **`sample_count`**（proto field 8）：与 `fl_participants.sample_count`、FedAvg 权重一致；≤0 时协调器按 1 处理。 |

**结论**：**`UploadGradientsRequest.sealed_gradient` = FL3 封装后的「梯度向量」密文**，**不是** ONNX 文件，**不是** `AVE_ExportModelWeights` 的输出。

---

## 2. 与 `UploadGradientsRequest` 字段逐项对照

| 字段 | 端侧来源 |
|------|----------|
| `endpoint_id` | `agent.toml` / `[fl]` → `agent_endpoint_id`（或等价配置）。 |
| `round_id` | Round 状态机当前轮（Kafka 公告 / 轮询 / 本地缓存）。 |
| `tenant_id` | `[fl]` `tenant_id`，与 `fl_rounds.tenant_id` 对齐。 |
| `sealed_gradient` | 见 §1。 |
| `gradient_upload_id` / `chunk_*` | 分块上传时由 `fl_gradient_upload.c` 生成。 |
| `sample_count` | 本地参与该轮训练的样本数（与 `fl_samples` 枚举计数等一致时由训练路径填入；当前 C 路径以实际实现为准）。 |

---

## 3. 易混淆 API（**不**填入 `UploadGradientsRequest.sealed_gradient`）

| API | 内容 | 用途 |
|-----|------|------|
| **`AVE_ExportModelWeights("static"\|"behavior")`** | **整模型权重/ONNX 字节**（如 `behavior.onnx` 文件内容） | P3 模型运维、联邦**整包**导出路线（与「梯度密封上传」不同产品线）。 |
| **`AVE_ExportBehaviorFlTrainableTensors`** | 可训练张量 float + manifest JSON | 行为侧 FL 张量导出；与 **FL3 梯度上传** 为不同封装，需单独约定若要走 gRPC 上传。 |
| **`AVE_ImportModelWeights`** | 显式 **拒绝** 前缀 **`FL3`** 的缓冲区 | 防止把 FL3 梯度误当权重导入（见 `ave_sdk.c`）。 |

---

## 4. HTTP 与 gRPC 等价性

- **HTTP**：`fl_gradient_upload_http_one` 发送 JSON，含 `sealed_gradient`（Base64）、`endpoint_id`、`round_id`、`tenant_id` 等（见 `fl_gradient_upload.c`）。
- **gRPC**：`fl_pb_encode_upload_gradients*` 生成 **`UploadGradientsRequest`** wire，由 `fl_grpc_upload_gradient_call` 发送。

二者与协调器 **`/v1/fl/...` HTTP** 及 **`FLService.UploadGradients`** 解析同一 proto 语义。

---

## 5. 维护

- 若 proto 增字段（如压缩算法、模型目标），同步更新本文件与 **`FL_TRACEABILITY_DESIGN10.md`**。
- 评审记录：AG-031 关单以本文件路径 **`edr-agent/docs/FL_GRADIENT_PROTO_CONTRACT_AG031.md`** 为准。
