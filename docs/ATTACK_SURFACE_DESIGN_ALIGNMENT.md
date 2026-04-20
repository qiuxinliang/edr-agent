# §19 攻击面：详设（调度 / 上报）与实现对照

本文档对照《EDR_端点详细设计_v1.0》**§19.4（快照采集调度）**、**§19.5（上报协议）** 与当前 `edr-agent` 行为，便于评审与迭代。**不包含** §19.2 字段级 JSON 与采集维度细节。

**权威代码路径**：`src/core/agent.c`（`edr_agent_poll_attack_surface`）、`src/attack_surface/attack_surface_report.c`（`edr_attack_surface_execute`、`edr_attack_surface_effective_periodic_interval_s`、出站/策略**并行采集**、`snapshotKind` **full / listenersOnly**、ETW 去抖）、`src/command/command_stub.c`（`GET_ATTACK_SURFACE`）。gRPC 演进见 **`docs/ATTACK_SURFACE_GRPC.md`**。

---

## 0. 产品策略（已确认）

1. **上报通道**：生产环境以 **REST JSON（`curl` POST）** 为**唯一权威**；详设 §19.5 的 **gRPC `ReportSnapshot`** 保留为**后续可选**能力（见 **`ATTACK_SURFACE_GRPC.md`**），不默认双写。
2. **`listenersOnly` / ETW 轻量**：**默认不启用** `EDR_ATTACK_SURFACE_ETW_LIGHT`；仅在**平台侧已约定**对 `snapshotKind=listenersOnly` 的合并或展示规则后，再在生产环境按需开启。

---

## 1. 调度（§19.4）

| 详设 §19.4 | 当前实现 | 备注 |
|------------|----------|------|
| 多轨间隔：`port_interval_s`、`conn_interval_s`、`service_interval_s`、`policy_interval_s`、`full_snapshot_interval_s` | 周期 **`POST`** 使用 **`edr_attack_surface_effective_periodic_interval_s`** = **`min(port, service, policy, full)`**（钳 60～604800s）。**`conn_interval_s`** 仍仅用于 **GET `.../refresh-request`** 轮询（钳 15～120s） | 整包快照下用「最短间隔」驱动刷新；**未**实现各维度独立线程/独立 JSON 片段 |
| 启动立即全量 | **`[attack_surface].enabled=true`** 且 **`endpoint_id` ≠ `auto`** 时 **`agent_start`** 一次 | 详设未写 `enabled` 门控 |
| Subscribe **`GET_ATTACK_SURFACE`** | **`edr_attack_surface_execute`**，**不检查 `enabled`** | 与周期开关解耦（见 `README`） |
| ETW 新监听：增量 / 高风险 **partial** 上报 | 预处理 **`edr_attack_surface_etw_signal`** → 主线程去抖后 **`etw_tcpip_wf`**；可选 **`EDR_ATTACK_SURFACE_ETW_LIGHT=1`** 生成 **`snapshotKind=listenersOnly`**（跳过出站/系统策略采集，仍 POST 整份 JSON） | 非独立 RPC，仍为 REST |
| 策略变更 / 防火墙变更触发 | **无**专用钩子；配置热重载/远程 TOML 会重置攻击面计时。可选 **`EDR_ATTACK_SURFACE_POST_ON_CONFIG_RELOAD=1`** 在配置应用后 **`POST`**（`config_reload`） | **可选**对齐「策略变更」 |
| 线程池并行采集四维度 | 监听仍顺序；**出站摘要与策略摘要**在整包快照路径上 **并行**（`pthread` / `CreateThread`）；与详设「四任务线程池」仍不等价 | **部分**对齐 |

---

## 2. 上报（§19.5）

| 详设 §19.5 | 当前实现 | 备注 |
|------------|----------|------|
| gRPC **`AttackSurfaceService.ReportSnapshot`** | **HTTP `POST`** `{rest_base}/endpoints/{endpoint_id}/attack-surface`**，**`curl`**，`Content-Type: application/json` | 与 Proto 示例不一致；**以 REST 为端点实现准** |
| **`RequestSnapshot`**（服务端 → Agent） | 控制台路径：**GET `refresh-request`** + 轮询 + 条件 **POST** 全量快照 | 产品流程可等价，**协议不同** |
| **`SnapshotRequest.full`**（全量 / 增量） | **无**该语义；每次 POST 均为当前实现的**整份 JSON** | 无「仅增量 diff」模式 |

---

## 3. 结论（仅调度 / 上报）

- **已实现**：周期全量（按四间隔最小值）、refresh-request 轮询、ETW 去抖触发、（条件）启动快照、Subscribe 按需 POST；可选配置重载后 POST；上报 **REST JSON** 稳定可用。
- **与详设差异**：分维度并行采集、partial 上报、gRPC/增量请求——**未按 §19.4/19.5 示例实现**；若产品以 REST 为准，建议在《端点详细设计》或平台 API 文档中**显式声明**与 §19.5 Proto 示例的关系，避免读者混用。

---

*文档版本：与仓库 `edr-agent` 同步维护。*
