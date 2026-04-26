# AVE / ONNX：本地首次真推理联调（AGT-005）

目标：在**本机**用 **ONNX Runtime** 加载 **`[ave].model_dir`** 下模型，跑通 **`edr_ave_infer_file`** / **`test_ave_infer`**，并与 **`edr-backend/docs/LOCAL_STACK_INTEGRATION.md`** 的租户、endpoint 约定一致（若还要连平台）。

**与「行为全链 / ingest」Runbook 的分工**：本页解决 **ORT 能加载**、`static.onnx` / **`behavior.onnx`** 就绪、**`edr_onnx_runtime_ready` / `edr_onnx_behavior_ready`** 为真时**在测试里**能跑通推理与 **`test_ave_e2e_full`** 等；**不**单独保证**生产路径**上一定出现**可解码**的 **行为批次** —— 那依赖 **预处理 → 跨引擎喂入 → 行为队列 → 非空 `on_behavior_alert` → `edr_behavior_alert_emit_to_batch` → `EDR_BEHAVIOR_ENCODING`**，见 **[WP-9 行为全链](WP9_BEHAVIOR_AVE.md)** 与 P0/静态 的**边界**（**WP-5**）。**CI 锚点**（无模型）：`edr-agent/scripts/verify_ave_behavior_chain_invariants.sh`。

---

## 1. 依赖

- **CMake** 构建的 **edr-agent**。
- **ONNX Runtime** 预编译包（含 `include/onnxruntime_c_api.h` 与 `libonnxruntime`）。
- 可选：仓库内 **`./scripts/install_static_onnx.sh`** 将 **`static.onnx`** 安装到 **`model_dir`**（与 `agent.toml.example` 注释一致）。

---

## 2. 配置 CMake

```bash
cd edr-agent
export ONNXRUNTIME_ROOT="/path/to/onnxruntime"   # 根目录，含 include/ 与 lib/
cmake -B build -DCMAKE_BUILD_TYPE=Debug \
  -DEDR_WITH_ONNXRUNTIME=ON \
  -DONNXRUNTIME_ROOT="$ONNXRUNTIME_ROOT"
cmake --build build -j4
```

未设置 **`ONNXRUNTIME_ROOT`** 时，CMake 会尝试常见路径（Homebrew 等）；找不到则 **`EDR_HAVE_ONNXRUNTIME`** 未定义，推理仍为占位实现。

---

## 3. 准备 `model_dir`

- TOML **`[ave].model_dir`** 指向目录（如从 **`agent.toml.example`** 拷贝为 **`agent.toml`** 后改为本机路径）。
- 目录内 **`*.onnx`**：构建时约定 **首个非 `behavior.onnx` 的文件**为**静态扫描模型**（见 `ave_onnx_infer.c` 与 README）；**`behavior.onnx`** 单独用于行为管线。

### 3.1 本仓库根目录 `model/releases/...`（训练产物）

若已在**本仓库根目录** `model/` 下生成 release（`model/releases/<release_id>/` 内含 `static.onnx`、`behavior.onnx` 等，清单见该目录 `manifest.json`；当前 release 指针见 **`model/releases/current.json`**），本地测试时直接将 **`model_dir`** 设为**该 release 目录的绝对路径**（不要用相对路径），例如：

```text
# 示例（按本机路径与 current.json 中的 release_id 修改）
/Users/you/…/AI Agent/model/releases/20260418_053704_UTC
```

Windows 可使用 `C:/…/AI Agent/model/releases/<release_id>` 形式。详见仓库根目录 **`model/README.md`**。

### 3.2 全流程一次跑通（static 扫描 + behavior 推理）

目标：同一进程内 **`AVE_Init`** → 加载 **`static.onnx`** 与 **`behavior.onnx`** → **`AVE_ScanFile`**（静态 ONNX）→ **`edr_onnx_behavior_infer`**（行为 ONNX，探针特征）。

- 构建目标：**`test_ave_e2e_full`**（需 **`-DEDR_WITH_ONNXRUNTIME=ON`**）。
- 脚本：**`edr-agent/scripts/ave_e2e_release_smoke.sh`**（自动根据仓库根 **`model/releases/current.json`** 推导 `MODEL_DIR`，或传入绝对路径）。

```bash
cd edr-agent
bash ./scripts/ave_e2e_release_smoke.sh /abs/path/to/model/releases/<release_id> /bin/ls
```

勿设置 **`EDR_AVE_INFER_DRY_RUN=1`**。源码：**`tests/test_ave_e2e_full.c`**。

---

## 4. 一键冒烟（推荐）

```bash
cd edr-agent
bash ./scripts/onnx_local_stack_smoke.sh
```

脚本在检测到 **`EDR_HAVE_ONNXRUNTIME`** 时会用 **`test_ave_infer`** 验证；默认仍为 **dry-run**（与 CI 一致）。要对**真实 ONNX**跑 **`test_ave_infer`**：

```bash
export EDR_AVE_INFER_DRY_RUN=0
# 可选：export EDR_AVE_ONNX_IN_LEN=4096   # 与模型输入动态轴一致
./build/test_ave_infer
```

若未设置 **`EDR_AVE_INFER_DRY_RUN`**，测试程序会默认设为 **`1`**（占位推理，避免无模型时失败）。

---

## 5. 与联调栈、Subscribe 的关系

- **平台 HTTP + 种子库**：按 **`edr-backend/docs/LOCAL_STACK_INTEGRATION.md`** 启动 **edr-api**，**`tenant_id` / `endpoint_id`** 与 **`agent.integration.toml`** 对齐。
- **gRPC**：Agent **`[server].address`** 指向 ingest；开发可用 **`EDR_GRPC_INSECURE=1`**（仅调试）。**`ave_infer`** 等指令经 **Subscribe** 下发时，需进程已 **`AVE_InitFromEdrConfig`**（**`edr_agent`** 主程序路径已初始化）。
- **行为 ONNX**：真机 E2E 见 **`docs/REAL_DEVICE_BEHAVIOR_E2E.md`**；实现计划见 **`docs/BEHAVIOR_ONNX_IMPLEMENTATION_PLAN.md`**。  
- **全链可运营**（回调、跨引擎喂入、**`EDR_BEHAVIOR_ENCODING`**、与 P0 不混谈）：**[`docs/WP9_BEHAVIOR_AVE.md`](WP9_BEHAVIOR_AVE.md)**。

---

## 6. CI / 无 ONNX 环境

不设 **`EDR_WITH_ONNXRUNTIME`** 时仍可编译；**`test_ave_infer`** 依赖 dry-run，**ctest** 与 **`scripts/ci_build.sh`** 保持绿色。

---

## 7. 性能与环境变量基线（P2-3）

同机对比回归时，请固定下列变量并记录硬件/OS；Python 集成测试见仓库根 **`T-integration-test/README.md`**。

| 类别 | 变量 | 含义 |
|------|------|------|
| Agent static 推理 | `EDR_AVE_INFER_DRY_RUN` | `=1` 跳过 ORT（占位）。 |
| | `EDR_AVE_STATIC_LEGACY512` | `=1` 强制 Legacy 字节填充（即使输入 512 维）。 |
| | `EDR_AVE_ONNX_IN_LEN` / `EDR_AVE_STATIC_INPUT_NELEM_MAX` | 大图/上限，见 `ave_onnx_infer.c`。 |
| **P2 结果缓存** | `[ave].static_infer_cache_max_entries` | 进程内 LRU 条数上限（默认 **0**=关闭）；实际上限 **256**。 |
| | `[ave].static_infer_cache_ttl_s` | TTL（秒）；**0**=仅 LRU。 |
| | `EDR_AVE_STATIC_INFER_CACHE_MAX` | 覆盖配置条数。 |
| | `EDR_AVE_STATIC_INFER_CACHE_TTL_S` | 覆盖 TTL（秒）。 |
| Python `test_ave_pipeline` | `ITEST_RELAX_PERF` | 放宽 P99 延迟阈值。 |
| | `ITEST_SEMANTIC_SEED` | 固定 numpy 种子（非 stub 回归）。 |
| | `ITEST_STATIC_P99_MS` / `ITEST_BEHAVIOR_P99_MS` / `ITEST_BEHAVIOR_512_P99_MS` | 毫秒上限覆盖。 |

**CI**：`.github/workflows/edr-agent-ci.yml` 中 **`ort-e2e-ubuntu`** 在固定 ONNX Runtime 版本下跑 **ctest**；若需记录 P50/P99，可在本机对同一 `model_dir` 执行 **`test_ave_e2e_full`** / **`T-integration-test`** 并保存日志。

