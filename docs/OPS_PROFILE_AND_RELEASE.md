# Events-only 瘦配置对表（B3.1）与 P0 发版前检查（D1.1）

**GHA `win_*` 客户端 tag**：`edr-agent-client-release` 在 **同一 Release** 上发布 **两枚** Windows zip — `…-windows-amd64-exe.zip`（**no-gRPC**+ONNX，与历史一致）与 `…-windows-amd64-grpc-exe.zip`（**gRPC**+ONNX）。选用与平台 **gRPC** 联调/ **Subscribe** 时取后者。

## B3.1：「先事件、后开 ONNX/重模块」对表

目标：以 **ETW → 总线 → 预处理 → 上送** 为主，弱化或关闭 **ONNX/攻击面/联邦** 等加重路径。以下为**建议**组合，产品请按会签的 P0/字段矩阵裁剪。

| 能力域 | 配置或环境 | events-only 建议 | 说明 |
|--------|------------|------------------|------|
| 采集/ETW | `[collection] etw_enabled = true` | **开** | 核心事件源 |
| | `[collection] max_event_queue_size` | 视内存保留默认或略降 | 与总线丢事件预算联动 |
| | `[collection] etw_buffer_kb` / `etw_flush_timer_s`；或 `EDR_ETW_BUFFER_KB` / `EDR_ETW_FLUSH_TIMER_S` | 默认 64 KB / 1 s | A4.2：调 ETW 实时会话缓冲与刷写；不当值可能增丢或内存占用 |
| | `[collection] etw_dns_client_provider` / `etw_powershell_provider` / `etw_security_audit_provider` / `etw_wmi_provider` 及 `etw_tcpip_provider` / `etw_firewall_provider` | **P0 全路径**：默认全 **true**；**缩流** 仅在与 `EDR_P0_Field_Matrix_Signoff` 会签/测试对表后逐个关 | A4.3 + §19.10；关 Provider 会少一类事件源，非「性能 profile」默认可动项 |
| | `EDR_AVE_ETW_ASYNC=1` | **默认不设置**（同线程 `AVE_FeedEvent`）。压测/减负时可选开，见 README；`terminate` 不走路径，队列满时同线程同步回退 | A3.2 大全套，与 `EDR_AVE_ETW_FEED_EVERY_N` 可叠 |
| 总线 A4.1 | `ctest -R test_event_bus_mpmc_stress` 或 `bash scripts/run_event_bus_mpmc_stress.sh` / **`bash scripts/run_event_bus_mpmc_soak.sh`** | CI 同参 250ms；**P2** 小时级默认 3600s | MPMC 无锁环表短时/长时压；长 soak 可 `DURATION_MS=…` 或手传如 `.../build 600000 8 256` |
| AVE / ONNX | CMake `EDR_WITH_ONNXRUNTIME=OFF` 构建 | 构建期关 ORT 即无真推理 | 与「未部署模型」环境一致 |
| | `[ave] model_dir` | 可指向空目录（无 .onnx） | 无模型则不走静态推理 |
| | `[ave] behavior_monitor_enabled = false` | **关** | 不拉行为消费线程，事件仍可入队/上送（见 README `[ave]`） |
| | `EDR_AVE_ETW_FEED=0` | 可选关 | 关 ETW→`AVE_FeedEvent`，**不**动 TDH/总线（见 README） |
| 预处理 / P0 | `preprocessing.rules` / P0 bundle | 与平台 manifest 同版本 | 与 `verify_p0_bundle_version_alignment.sh` 对账 |
| 攻击面 | `[attack_surface] enabled` | **关** 或不配置 `[platform]` | 避免周期 POST/额外采集 |
| 联邦/FL | `[fl] …` / `fl_samples.db_path` | 空或默认关 | 见 `config.h` 中 FL 节 |
| 上送 | `[upload]` + gRPC / HTTP | 按联调开 | 事件上报仍需要传输通道 |

> **注意**：`events-only` 不是单一只读开关，而是**模块级**关闭；以 `agent.toml.example` 与 `include/edr/config.h` 为真源做走读。  
> **P2 一键模板**：`config/agent_profile_events_only.example.toml`（复制后改 `server` / `tenant` / 路径）；`model_dir` 指向**无** `.onnx` 的目录且 `behavior_monitor_enabled = false` 时，与「只跑事件/预处理/上送」一致。

---

## P2：SRE/运维可选项（A1.1 落盘、A4.1 长 soak、B0.2 对表、C1.2 新路由）

| 项 | 交付/用法 |
|----|------------|
| **A1.1 行镜像** | Windows 设 `EDR_ETW_OBS=1` 且 `EDR_ETW_OBS_EXPORT_PATH=<可写文件>`，在 `[etw_obs]` 行同时**追加**到该路径（与 stderr 同文；**首次** `fopen` 失败则只打一次提示并关镜像）。由现有 shipper/日志代理采集即可，无需改二进制协议。 |
| **A1.2 长基线** | 同机 ≥10 分钟、同负载，仍用 `scripts/etw_observability_baseline.sh` 清单；P2 建议叠加 `EXPORT_PATH` 或重定向 `2> file` 做前后 diff。 |
| **A4.1 小时级 soak** | `bash edr-agent/scripts/run_event_bus_mpmc_soak.sh`；默认 3600000 ms、4 产线、槽深 64。覆盖：`DURATION_MS=… ./scripts/run_event_bus_mpmc_soak.sh [builddir] [ms] [prods] [cap]`（底层同 `run_event_bus_mpmc_stress.sh` / `test_event_bus_mpmc_stress`）。 |
| **B0.2 产品灰度** | 端上**不**读；平台默认用 **`p0_rule_gray_tiers_v1.json`** + 只读 API `GET /api/v1/admin/p0-gray/tiers` / `.../resolve?phase_id=…` 对表；租户的 phase 与 **`PATCH /admin/tenants/:id/features`** 中策略对接（见 `platform/config/README_dynamic_rules_v1.md`）。与 `dynamic_rules` 根 `version` 发版单对表。 |
| **B3.1 模板** | 见上表与 `config/agent_profile_events_only.example.toml`。 |
| **D1.1 大页** | 本文 **§D1.1** 与 P2 上表可一并贴进发版/运维单；B2.4 证据链仍以 `EVIDENCE_B24_CHECKLIST.md` 等为准。 |
| **C1.2 新 ingest 入队** | 若将来新增**旁路**路由：须复用现有「直出 + `UserSubjectIsEdrDynamicRule` + ruleenrich 幂等」契约；`IngestHandler.shouldEnqueueRuleEnrichOnIngestC12` 为**唯一** ingester 内判定。 |

---

## P1：A4.4 收/解路径 — 现网/灰度建议

与 [ADR A4.4 `ADR_A4.4_ETW_Receive_Path_Decouple.md`](../../Cauld%20Design/ADR_A4.4_ETW_Receive_Path_Decouple.md) 一致，**`EDR_A44_SPLIT_PATH=1`** 打开后建议：

- **观测**：与 **`EDR_ETW_OBS=1`** 同用；需要 TDH/回调分段时叠加 **`EDR_A44_CB_PHASE_MEAS=1`**。关注 `[etw_obs]` 中 `a44_q_drops` 与总线 `drop`。
- **基线/Soak**：`scripts/run_event_bus_mpmc_soak.sh` 做总线长时；A4.4 大负载须 **Windows 真机或 windows-latest 构建** 上跑，与本文件 **A4.1** 行不互相替代。
- **门闩**：动过 `etw_tdh_win` / 收/解 路径时，合并前 `recommended_p0_pr_gates` / precheck 全绿；P0/会签 若涉及 TCPIP/监听 语义，和 **`EDR_TDH_LIGHT_PATH_TCPIP`** 对表同 PR 或附对比说明。

---

## D1.1：P0 直出 / 规则包 发版前检查（简版）

1. **版本四方对齐**（阻断错版）  
   `bash edr-backend/scripts/verify_p0_bundle_version_alignment.sh`

2. **金线与门闩**（**P0 机读一键** + 落盘 `EVIDENCE.md`：`bash edr-backend/scripts/p0_pack_machine_gates.sh`；说明见 `Cauld Design/EDR_P0_Pack_P0_Execution.md`）  
   或分步： `bash edr-backend/scripts/recommended_p0_pr_gates.sh` / `bash edr-backend/scripts/p0_engine_continuous_gates.sh`（等价）  
   （含 TDH try-order、ETW1、UserData hex 金体、Go P0 manifest 等，与 `edr-agent-ci` precheck 对齐。）

3. **Agent 行为**（变更说明中须写清）  
   - `rules_bundle_version` / `EDR_P0_RULES_BUNDLE_VERSION` 与 `edr_config/p0_rule_bundle_manifest.json` 一致。  
   - 若发版动 ETW 映射/opcode/字段，注明对 **P0 字段矩阵** 的影响。  
   - 若引入或默认开启 **A4.3** 某 optional Provider=**false**、**`EDR_AVE_ETW_ASYNC=1`**、或关 **`EDR_AVE_ETW_FEED`** 类开关，发版单须写**依据**（会签/门闩/对比测试）。

4. **必提环境变量（若用）**（摘自 README，以实际发版说明为准）  
   `EDR_P0_IR_PATH`、`EDR_P0_*` 直出/限频、Windows `EDR_AVE_ETW_FEED` / `EDR_AVE_ETW_FEED_EVERY_N` / **`EDR_AVE_ETW_ASYNC`**（A3.2、默认关）、`EDR_ETW_OBS` / **`EDR_ETW_OBS_EXPORT_PATH`**（P2 可观测落盘，非生产必开）等。  
   **B0.2 产品灰度**（平台/运维）：端上**不**读；`p0_rule_gray_tiers_v1.json` + `/admin/p0-gray/*` 与 `dynamic_rules` 根 `version` 及租户 `features` 策略一致（见上 **§P2**）。

5. **E2E 证据**（B2.4，按需；机读部分可与 §2 一键同跑）  
   `docs/EDR_P0_DIRECT_EMIT_E2E.md`、**`docs/EVIDENCE_B24_CHECKLIST.md` §0+**；`p0_pack_machine_gates.sh` 或单跑 `collect_p0_b24_evidence.sh`（`artifacts/.../EVIDENCE.md`）。

更细的 Windows 真机/Staging 步骤仍以 **`docs/EDR_P0_DIRECT_EMIT_E2E.md` §3** 与 **`Sprint-Gates-Runbook.md`** 为准。
