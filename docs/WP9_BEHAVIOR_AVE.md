# WP-9：行为回调与 AVE

> **目标**：说清 **预处理 → 跨引擎喂入 → 行为队列 → ONNX/启发式 → `on_behavior_alert` → `edr_behavior_alert_emit_to_batch`** 的**一条链**；**不是** P0 规则直出（**WP-5**）或纯 ETW 开关（**WP-8**）；与 **`AVE_OnDisk` 静态扫** 解耦可单独讨论。

> **相关**：`docs/AVE_ENGINE_IMPLEMENTATION_PLAN.md`、**WP-2**（总线/预处理在 **AVE 之前** 与 **跨引擎 `edr_ave_cross_engine_feed_from_record` 之后** 的分工）、**WP-4/6**（编码与批次）、`include/edr/ave_sdk.h`（`AVECallbacks`）、`include/edr/ave_cross_engine_feed.h`。

## 1. 总览（与实现对齐）

| 阶段 | 行为 |
|------|------|
| 预处理主路径 | 组 **`EdrBehaviorRecord`*** |
| 跨引擎（T9 等） | `edr_ave_cross_engine_feed_from_record` → 把 **Shellcode / Webshell / PMFE** 等**标量**与 ETW1 同 PID 的序列写入 **`edr_ave` / PidHistory** 视角（与 `ave_cross_engine_*.c` 一致） |
| 行为管线 | `ave_behavior_pipeline`：MPMC 入队、消费线程；**`behavior.onnx` 就绪** 则 ORT 推理，否则**启发式** 路径 |
| 回调 | 异常分/策略满足时调 **`on_behavior_alert`**；**在 agent 里必须注册非 NULL 回调**，否则管线**不**出 protobuf 告警帧（见 `edr_agent_on_behavior_alert` 注释 + `ave_behavior_pipeline.c`） |
| 入批 | `edr_behavior_alert_emit_to_batch` → `edr_event_batch_push`（`behavior_alert_emit.c`） |
| 平台 | 与 **`EDR_BEHAVIOR_ENCODING=protobuf`** 及 ingest 契约对齐（`warn_encoding_once`） |

\* **注意**：`edr_agent_on_behavior_alert` 在默认集成里**可为空实现**（不占业务侧逻辑），但**指针需非空** 以**解锁** `edr_behavior_alert_emit_to_batch` 的调用链（`ave_behavior_pipeline` 在回调前后编码）。

## 2. 配置与开关（TOML / 环境，摘要）

| 项 | 说明 |
|----|------|
| `[ave].model_dir` | 静态/行为 **ONNX** 与元数据**根**（与 README 模型目录说明一致） |
| `[ave].behavior_monitor_enabled` | **true** 时**尝试**起 `AVE_StartBehaviorMonitor` 消费线程；失败则 stderr 提示、可能**同步/降级** |
| `[ave].l4_realtime_anomaly_threshold` 等 | 与 `EDR_AVE_BEH_SCORE_HIGH` 等产品阈值对齐，见 `ave_behavior_gates.h` |
| **`EDR_AVE_BEH_INFER_MIN_EVENTS`** 等 | 与「每 N 事件推理」legacy 模式互斥/覆盖，见 `ave_behavior_pipeline.c` 内注释 |
| **`EDR_BEHAVIOR_ENCODING`** | 上送/批次侧建议 `protobuf` / `protobuf_c`；否则 stderr 有**一次**提醒 |

**启动**会打一行（见 `agent.c`）**`[ave] on_behavior_alert=1 … model_dir=… onnx_static=… onnx_behavior=… l4_th=…`** 便于与 **`agent.toml`** 对表。

### 2.1 运行与可观测（stderr、管道、macOS）

- **构建目录**：仓库**根** `.gitignore` 已含 `edr-agent/build-*/`；仅维护 **`edr-agent/`** 子目录时，其内 `.gitignore` 也忽略 **`/build-*/`**，避免把本机 `build-wp9` 等实验输出提交。  
- **行缓冲**：`main.c` 在 **POSIX** 上对 **`stderr` 行缓冲**（`setvbuf`），`edr_agent_init` 等打出的、以换行结束的行在**接管道/重定向**时也会较快出现，便于与 **`| head`**、日志采集对表。  
- **仍看不到首行时**（工具链极老或特殊包装）：**Linux** 可试 `stdbuf -eL ./edr_agent --config ...`；**macOS** 常无 `stdbuf`，可 **`2>&1 | cat`** 强刷一行、或**先写文件再读**，例如：  
  `./edr_agent --config agent.toml 2> /tmp/e.log & pid=$!; sleep 0.3; head -20 /tmp/e.log; kill $pid`  
- **Windows**：控制台下通常**即打即见**；与计划任务/重定向联调时同样找 **`[ave]`**、**`[collection]`** 等前缀。  
- 验收时 **macOS / Linux** 均可在 **stderr** 看到含 **`[ave] on_behavior_alert=…`** 的启动行（与 **§4** 一致，不限于 Windows）。

### 2.2 与「ONNX 真推理 / AGT-005」的分工

| 主题 | 入口 | 说明 |
|------|------|------|
| **ORT + `model_dir` 里 `static.onnx` / `behavior.onnx` 能加载** | **`docs/AVE_ONNX_LOCAL_STACK.md`** | **AGT-005**：解决 **无模型 / dry-run** 时测试行为、**`edr_onnx_*_ready()`** 与 e2e 探针；**不**写 ingest 业务契约。 |
| **本 WP（行为链）** | 本文 | **有 `EdrBehaviorRecord` 之后** 的喂入、队列、**`on_behavior_alert` 已注册**、**`edr_behavior_alert_emit_to_batch`** 与 **`EDR_BEHAVIOR_ENCODING`**；**不**替代 **P0 直出（WP-5）**。 |

**CI**（不跑 ORT、不拉模型）用 **`edr-agent/scripts/verify_ave_behavior_chain_invariants.sh`** 锚住 `agent.c` 回调、**`behavior_alert_emit.c`** 编码提醒、**`ave_cross_engine_feed` / `ave_behavior_pipeline`** 等符号，防无意删改。  
**GHA**：`edr-agent-ci.yml` 的 **precheck**；以及 **`edr-agent-build-grpc-ort.yml`**、**`edr-agent-client-build.yml`**、**`edr-agent-client-release.yml`** 在**编译/装 vcpkg 之前**各跑同一脚本。独立 **edr-agent** 子仓 **`.github/workflows/*`** 同步。本地：`bash edr-agent/scripts/verify_ave_behavior_chain_invariants.sh`（monorepo 根）或 `bash ./scripts/...`（子仓根）。

## 3. 与 P0/规则、ETW 的边界

| 主题 | 关系 |
|------|------|
| **P0 直出** | **不依赖** `behavior.onnx`；经 **IR/预处理直出** `BehaviorAlert`（**WP-5**） |
| **AVE 行为告警** | 依赖**管线+回调+编码**；**漏配编码** 或 **回调未注册** → **无** protobuf 行为告警帧（仍可有 P0/静态扫） |
| **WP-8** | ETW/采集**少**事件时，**两侧** 行为分与 P0 命中都会**变少** |
| **WP-2** | 总线满/预处理丢 → **到不了** `edr_ave_cross_engine_feed_from_record` / 或喂入**稀疏** |

### 3.1 与平台 ingest、**WP-1**（不重复排障）

| 侧 | 说明 |
|----|------|
| **平台** | **`POST /api/v1/ingest/report-events`** 解 **BAT1**、落 **`alerts`** 的**最短验证**见 **`edr-backend/docs/WP1_ALERT_INGEST_E2E.md`** 与 **`verify_ingest_alert_e2e.sh`**；`edr-ingest-sample` 与真机**同一 HTTP 契约**，验 **DB / 租户 / `endpoint_id`**。 |
| **本 WP** | 真机 **Agent** 上 **是否** 产生可解码的 **行为** 批次：依赖 **采集 → 预处理 → 跨引擎 → 行为队列 → 回调 → 编码**；**`verify_ingest` 绿** 只说明**平台**侧正常，**不**证明 **AVE 行为链** 已走通。 |
| **排障顺序** | 先 **WP-1 绿**（排除 404/403/库），再查 **本 WP** 与 **WP-2/5/8**；勿把 **ingest 404** 与 **`on_behavior_alert` 未注册** 混成同一因。 |

## 4. 完成标准（验收）

- [ ] 能按 §1 顺序**口述** 从 `EdrBehaviorRecord` 到 **ingest 批次** 的路径。  
- [ ] 能解释**为何** `on_behavior_alert` 必须**注册**非空**函数指针** 才会出 **batch 内 protobuf 行为告警**（与「回调体可空」不矛盾）。  
- [ ] 在 **Windows 或** **macOS/Linux** 上启动一次 Agent，**stderr** 有 **`[ave] on_behavior_alert=1 …`**，且与 **`[ave]`** 段配置一致（管道排障见 **§2.1**）。  
- [ ] 能区分本 WP 的 **ONNX/启发式 行为** 与 **P0 规则**（**WP-5**）。

## 5. 参考

- **`docs/AVE_ONNX_LOCAL_STACK.md`（AGT-005）** — `model_dir` 与 **ORT** 首次真推理，与全链**分工**见 **§2.2**  
- `edr-agent/src/serialize/behavior_alert_emit.c`  
- `edr-agent/src/ave/ave_behavior_pipeline.c` / `edr_ave_bp_set_callbacks`  
- `edr-agent/src/core/agent.c` — `edr_agent_on_behavior_alert` / `AVE_RegisterCallbacks`  
- `edr-agent/include/edr/ave_cross_engine_feed.h`  
- `edr-agent/scripts/verify_ave_behavior_chain_invariants.sh` — CI/本地 无模型 锚点检查  
