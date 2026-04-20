# FL Round 本地训练语义（`model_target`）

## 配置

TOML `[fl]`：

```toml
model_target = "static"    # 或 "behavior"
```

- 默认值：`static`（由 `edr_config_apply_defaults` / `edr_config_clamp` 规范化）。
- 非法值回退为 `static`。
- 与 `FLTConfig.model_target` / `fl_round` 梯度向量维数一致。

## 向量维数

| `model_target` | 梯度 float 维数 | 与头文件 |
|----------------|-----------------|----------|
| `static` | 512 | `AVE_FL_FEATURE_DIM_STATIC` |
| `behavior` | 256 | `AVE_FL_FEATURE_DIM_BEHAVIOR_DEFAULT` |

## 数据与样本

- **`fl_samples.db` / `AVE_ExportFeatureVector`**：当前仍以 **static** 样本枚举与 512 维路径为主；`behavior` 时训练维数与 `ExportFeatureVectorEx` / behavior ONNX 设计对齐，但 **DB 命中行为** 以 `FL_SAMPLES_SCHEMA.md` 与实现为准。
- 若 `model_target=behavior` 但样本侧仍仅 static，Round 可能因 `min_new_samples` 等条件跳过；属预期联调阶段行为。端上 **`fl_round_trainer_thread_loop`** 在跳过时会向 **stderr** 输出 **`[fl] round skipped:`** 及原因（含「仅统计 `model_target='static'` 行」）。

## 上传

`fl_gradient_upload` 仍发送 **FL3**（或占位）封装后的梯度；协调端用 `edr-backend/platform/cmd/fl-coordinator` 与 `FL_COORDINATOR_MINIMAL.md` 所述私钥解密。

## `frozen_layers`（T-015）

TOML 子表 **`[fl.frozen_layers]`**（与《10》§5 示例一致）：

```toml
[fl.frozen_layers]
static   = ["head_b", "head_c"]
behavior = ["head_b"]
```

- **解析**：`edr_config_load` 读入字符串数组（最多 `EDR_FL_FROZEN_MAX` 条，单条长度 `EDR_FL_FROZEN_NAME_MAX`）；非法字符规范为 `_`。
- **与 `model_target` 的关系**：HTTP JSON 仅附带 **当前目标** 对应列表：`*model_target=static*` → `static` 数组；`*behavior*` → `behavior` 数组。字段名为 **`frozen_layer_names`**（与 `sealed_gradient` 等同一条 POST）。
- **训练语义（当前实现）**：本地 Round 使用 **特征向量均值** 作为伪梯度（512/256 维），**无法**将 ONNX 逻辑名映射到嵌入向量的切片；`fl_frozen_layers_apply_feature_delta` 为占位（不改变数值）。名称仍随上传 JSON 供协调端/审计/后续张量级联邦使用。
- **LibTorch**：若将来在本仓库对 `torch::nn::Module` 做完整 backward，应在对应模块上对 `frozen_layers` 名称做 `requires_grad_(false)`；`local_train_torch.cpp` 当前仅 `reduce_mean`。
