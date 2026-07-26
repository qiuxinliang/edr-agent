# EDR 行为 / 平台 / 发布 — 详细任务清单（跨仓库）

> **维护**：关单时在对应行更新 **状态**；大项拆 PR 时在 **依赖** 中写 PR 号。  
> **状态图例**：`[ ]` 未开始 · `[~]` 进行中 · `[x]` 已完成 · `[-]` 取消/不由本仓做  
> **优先级**：**P0** 阻塞演示或生产安全 · **P1** 契约/可观测/试点必备 · **P2** 增强与长期债  
> **粗估**：人天（pd），含自测与文档；并行时 **wall-clock** 可缩短。

---

## 索引与权威文档

| 主题 | 文档 / 代码入口 |
|------|-----------------|
| 行为 ONNX 总跟踪 | `edr-agent/docs/BEHAVIOR_ONNX_IMPLEMENTATION_PLAN.md` |
| Proto ↔《11》§4 映射（DOC-001） | **`edr-agent/docs/BEHAVIOR_PROTO_DESIGN_MAPPING.md`** |
| 设计权威 | `Cauld Design/11_behavior.onnx详细设计.md` |
| BAT1 / ingest | `edr-backend/docs/BAT1_EVENT_INGEST.md` |
| 真机 E2E（若已存在） | `edr-agent/docs/REAL_DEVICE_BEHAVIOR_E2E.md`（见实施计划 B2 引用） |
| TLS / 安装包 / §22 发布 | `edr-backend/docs/RELEASE_PUBLISH_CHECKLIST.md` |
| §22 规划 | `edr-backend/docs/PLAN_SECTION22_LICENSE_ENROLLMENT_V15.md` |
| 安装包 INS | `edr-backend/docs/INSTALLER_IMPLEMENTATION_TASKS.md` |
| L2 LLM / T14 脚本 | `edr-backend/docs/L2_LLM_AND_BEHAVIOR_SERVER.md` |

---

## A. Agent（edr-agent）— 行为 ONNX · 特征 · 管线

### A1. 契约与代码生成

| ID | 状态 | P | 任务 | 验收标准 | 依赖 | 估(pd) |
|----|------|---|------|----------|------|--------|
| AG-001 | [x] | P0 | `event.proto`：`BehaviorAlert`、`behavior_alert`、`AveBehaviorEventFeed`（§4.1）与《11》对齐 | 平台 `pbwire` 可解析；Agent `behavior_proto.c` 编码一致 | — | 0 |
| AG-002 | [~] | P1 | 本机 **protobuf≥7** 时跑通 **`scripts/regen_event_proto.sh`**，必要时提交 `event.pb.*` | CI/同事机可重现生成 | AG-001 | 0.5–1 |
| AG-003 | [ ] | P1 | `nanopb` 与 `pbwire` 对 **field 41**（若有）做 golden 字节或往返测试 | 单测或脚本比对 | AG-002 | 1–2 |

### A2. 特征 M3b / B3c（《11》§5）

| ID | 状态 | P | 任务 | 验收标准 | 依赖 | 估(pd) |
|----|------|---|------|----------|------|--------|
| AG-010 | [x] | P0 | `encode_c_group` C24–C35 与 **`test_ave_behavior_features_m3b`** / **`behavior_encode_m3b.py`** 对拍 | `go test` + `python3 scripts/behavior_encode_m3b.py` | — | 0 |
| AG-011 | [ ] | P1 | 《11》§5.3 **C24–C34** 剩余边界（高熵路径数值、更多扩展名/注册表变体） | 新增 golden，不静默改既有向量 | AG-010 | 2–4 |
| AG-012 | [~] | P1 | **B/C/D 维 8–43** 与设计表逐维对照，缺的在 `ave_behavior_features.c` 补或文档标「刻意简化」 | **`BEHAVIOR_DIM_BCD_AUDIT_AG012.md`** 签字表 + 既有 `test_ave_behavior_features_m3b` | AG-011 | 5–15 |
| AG-013 | [~] | P2 | **§7** 触发/步长：命名宏与《11》阈值表一致；门禁脚本或单测覆盖「立即触发 / 步长 16/8」 | **`BEHAVIOR_GATES_AG013.md`**；**`test_ave_behavior_gates`** 已校验步长宏 | 《11》§7 | 2–5 |
| AG-014 | [ ] | P2 | **ORT 失败 metrics**（对外）+ 队列深度指标 | 与 §6 文档一致可观测 | — | 2–4 |

### A3. B3b 数据面（PidHistory · IOC · 跨引擎）

| ID | 状态 | P | 任务 | 验收标准 | 依赖 | 估(pd) |
|----|------|---|------|----------|------|--------|
| AG-020 | [~] | P1 | 各子系统稳定 **`AVE_FeedEvent`** → E 组标量与设计逐维对齐 | **`BEHAVIOR_E_GROUP_FEED_AG020.md`** + 真机 **AG-040** | AG-012 部分 | 5–12 |
| AG-021 | [ ] | P1 | **维 56** 等与《11》逐维 diff；`ph_reset`/PID 复用边界 | m3b 或管线测试 | — | 2–4 |
| AG-022 | [ ] | P2 | **§5.3 维 35 MOTW** 等 C 组细项与 ETW/预处理对齐 | 端到端字段非 0 样例 | — | 2–6 |

### A4. 联邦与导出

| ID | 状态 | P | 任务 | 验收标准 | 依赖 | 估(pd) |
|----|------|---|------|----------|------|--------|
| AG-030 | [x] | P1 | **`AVE_ExportModelWeights("behavior")`** 整文件字节 | `test_ave_fl_abi` | — | 0 |
| AG-031 | [x] | P2 | 与 **`fl.proto` / 平台 FL** 约定同一字节对象；文档闭环 | **`docs/FL_GRADIENT_PROTO_CONTRACT_AG031.md`** + **`FL_JOINT_DEBUG_CHECKLIST.md`** | AG-030 | 2–5 |
| AG-032 | [ ] | P2 | 若需 **张量级** FL：新 API/proto（与 AG-030 并存） | 不与现 Export 混用 | 产品决策 | 8–20 |

### A5. 真机与配置

| ID | 状态 | P | 任务 | 验收标准 | 依赖 | 估(pd) |
|----|------|---|------|----------|------|--------|
| AG-040 | [ ] | P1 | 真机 **E2E**：`EDR_BEHAVIOR_ENCODING=protobuf`、告警、DB 字段 | 按 **`REAL_DEVICE_BEHAVIOR_E2E.md`** 或等价清单勾选 | PL-010 | 1–3 |
| AG-041 | [ ] | P2 | **Windows** 安装包路径下 ORT/模型路径回归 | 安装文档更新 | REL 系列 | 1–2 |

---

## B. 平台后端（edr-backend/platform）

### B1. Ingest 与告警

| ID | 状态 | P | 任务 | 验收标准 | 依赖 | 估(pd) |
|----|------|---|------|----------|------|--------|
| PL-001 | [x] | P0 | HTTP **`POST .../ingest/report-events`** + BAT1 + pbwire + `InsertBehavior` | `smoke_behavior_ingest.sh` | — | 0 |
| PL-002 | [ ] | P1 | **gRPC `ReportEvents`** 与 HTTP **共用**解码/入库（或独立进程同包） | 同 payload 双路径单测 | PL-001 | 2–5 |
| PL-003 | [ ] | P2 | 进程历史 **>512** 或过滤参数 | API 契约 + 迁移若需 | 产品 | 2–6 |

### B2. L2 复核

| ID | 状态 | P | 任务 | 验收标准 | 依赖 | 估(pd) |
|----|------|---|------|----------|------|--------|
| PL-010 | [x] | P1 | **`l2review` Worker** + `ListEventsByPID` + 占位 Markdown | `EDR_L2_REVIEW_INTERVAL_SEC` | — | 0 |
| PL-011 | [x] | P1 | **OpenAI 兼容 LLM**（`EDR_L2_LLM_*`）+ `GetL2AlertContext` | `go test ./internal/l2review` | PL-010 | 0 |
| PL-012 | [ ] | P2 | 提示词版本化、审计（tenant、model、token 用量）、重试/退避 | 运维文档 + 日志字段 | PL-011 | 2–5 |
| PL-013 | [ ] | P2 | RAG / 工具调用（可选） | 产品规格 | PL-012 | 5–15 |

### B3. T14 behavior_server

| ID | 状态 | P | 任务 | 验收标准 | 依赖 | 估(pd) |
|----|------|---|------|----------|------|--------|
| PL-020 | [x] | P2 | **`behavior_server_infer.py`** 参考服务 | `POST /infer` 文档 | — | 0 |
| PL-021 | [x] | P2 | 服务进 **edr-api**：`/admin/behavior-server/health`、`/infer` + **`BEHAVIOR_SERVER_HTTP_URL`** | `L2_LLM_AND_BEHAVIOR_SERVER` §2.1 | PL-020 | 5–15 |

### B4. §22 · License · Enroll · Installer

| ID | 状态 | P | 任务 | 验收标准 | 依赖 | 估(pd) |
|----|------|---|------|----------|------|--------|
| PL-030 | [x] | P0 | Phase A–D+F + Phase E stub（见 §22 规划文） | 规划文勾选 | — | 0 |
| PL-031 | [~] | P1 | **INS-03～04**：`expires_at`、匿名下载路由 | `INSTALLER_IMPLEMENTATION_TASKS`；**`000023`** + **`public_installer.go`** | PL-030 | 5–12 |
| PL-032 | [x] | P1 | **INS-06**：`expiresIn` 真实剩余秒 | 与 DB 一致 | PL-031 | 0.5–1 |
| PL-033 | [x] | P2 | **INS-09**：S3 兼容预签名 **`download_url`**（`INSTALLER_MINIO_*`） | `INSTALLER_IMPLEMENTATION_TASKS` INS-09 | PL-031 | 3–8 |
| PL-034 | [~] | P2 | **INS-10**：**`INSTALLER_EMBED_AGENT_BINARY`** 打入 zip；矩阵/失败策略在 CI | 流水线 + 同表 INS-10 | PL-033 | 5–15 |
| PL-035 | [ ] | P2 | **INS-07/08** 权限与租户列表入口 | 前端联调 | PL-031 | 2–4 |

---

## C. 前端（edr-frontend）

| ID | 状态 | P | 任务 | 验收标准 | 依赖 | 估(pd) |
|----|------|---|------|----------|------|--------|
| FE-001 | [x] | P1 | 行为告警详情：**`anomaly_score` / `tactic_probs` / `triggered_tactics` / L2 字段** | 实施计划 T13 | PL-001 | 0 |
| FE-002 | [ ] | P1 | 与 **`EDR_前端详细设计`** 告警 DTO 全文对齐 | 设计评审 tick | FE-001 | 2–5 |
| FE-003 | [ ] | P2 | 十四战术可视化（热力/条形）与 MITRE 链 | 产品稿 | FE-001 | 3–8 |
| FE-004 | [~] | P1 | **HTTPS**：`VITE_API_BASE_URL`、`ws.ts` wss | `RELEASE_PUBLISH_CHECKLIST` §2；仓库：**`I1_DEMO_STAGING.md`**、`build:staging`、**`apiRoot`/`ws`** | REL-010 | 0.5–1 |
| FE-005 | [~] | P2 | **Agent 下载 / 租户列表** 与 INS-08 一致 | 列表入口 **`/admin/agent-download?tenantId=`** + `AgentDownloadPage` 解析 query（`INSTALLER_AND_DOWNLOAD_DESIGN`）；**INS-07** 权限细化仍待 **PL-035** | PL-035 | 1–2 |

---

## D. 发布 / 运维 / 安全（跨仓）

| ID | 状态 | P | 任务 | 验收标准 | 依赖 | 估(pd) |
|----|------|---|------|----------|------|--------|
| REL-001 | [x] | P1 | **`RELEASE_PUBLISH_CHECKLIST.md`** 合并 TLS+安装包+§22 | 团队采用 | — | 0 |
| REL-010 | [~] | P0 | **Staging 生产形态**：网关 TLS、CORS、`WS_*`、`ENROLL_*` https | `HTTPS_TLS_INTEGRATION_CHECKLIST` 全勾；仓库：**`REL010_FE004_RUNBOOK.md`**、`deploy/staging-edr-api.env.example`、网关脚本 | — | 2–4 |
| REL-011 | [ ] | P0 | **每版 platform**：`make sync-agent-installer-embedded` + `go test ./internal/installer` | `RELEASE_AGENT_INSTALLER_BUNDLE.md` | — | 0.2/版 |
| REL-012 | [ ] | P1 | **生产**关闭 Agent 不安全 TLS；**`PLATFORM_SKIP_LICENSE_GATE`** 勿长期开启 | 发布说明 | REL-010 | 0.5 |
| REL-013 | [~] | P2 | **`INSTALLER_IMPLEMENTATION_TASKS`** 非代码项：安全评审、运维手册 | **`INSTALLER_OPS_AND_SECURITY.md`**（运维手册已归档；安全评审仍待会议勾选） | PL-031 | 2–4 |

---

## E. 设计文与索引债

| ID | 状态 | P | 任务 | 验收标准 | 依赖 | 估(pd) |
|----|------|---|------|----------|------|--------|
| DOC-001 | [x] | P1 | 《11》与 **`BehaviorEvent` proto** 字段映射表（§4） | **`BEHAVIOR_PROTO_DESIGN_MAPPING.md`** | — | 1–3 |
| DOC-002 | [ ] | P2 | 《11》里程碑 M7–M9 与仓库任务 ID 映射 | 本文件互链 | — | 0.5–1 |

---

## F. 建议排期（迭代切片）

### F0. I1 仓库交付物（已实现，2026-04-18）

| 项 | 说明 |
|----|------|
| **`edr-backend/scripts/smoke_i1_demo_ready.sh`** | **`/healthz`** + **`/ready`** + 调用 **`smoke_behavior_ingest.sh`**（PL-001 回归）；支持 **`API_ROOT`/`BASE`** 指向 **https** 网关 |
| **`edr-backend/scripts/dev_i1_execute.sh`** + **`make dev-i1-execute`** | 开发顺序：嵌入同步 → installer / l2review / pbwire 单测 →（可选）live smoke；无 API 时 **`SKIP_LIVE=1`** |
| **`edr-frontend/docs/I1_DEMO_STAGING.md`** | **FE-004** + **REL-010** 的环境变量与验收勾选说明 |
| **`edr-backend/docs/REL010_FE004_RUNBOOK.md`** | **REL-010** / **FE-004** 运维执行索引（链到模板与脚本） |
| **`edr-backend/deploy/staging-edr-api.env.example`** | **REL-010**：`edr-api` 侧 CORS / WS / JWT / Enroll 变量模板 |

**I1 环境侧**（须在目标 Staging 由运维/开发勾选，不在仓库内自动化）：**REL-010**（网关 TLS、CORS、`WS_*`、`ENROLL_*`）、**AG-040**（真机 **`REAL_DEVICE_BEHAVIOR_E2E.md`**）。

| 切片 | 包含任务（示例） | 粗估 wall-clock（2 人并行） |
|------|------------------|----------------------------|
| **I1 演示就绪** | 先跑 **`smoke_i1_demo_ready.sh`**；再 **REL-010、FE-004、AG-040**（环境与真机） | **1–2 周**（其中仓库脚本部分 **<1h**） |
| **I2 试点分发** | PL-031、PL-032、FE-005、REL-013 | **2–4 周**（仓库：**`000023`**、匿名 **`GET /public/installer-artifacts`**、**`INSTALLER_OPS_AND_SECURITY.md`**、租户列表 **Agent 安装** 入口） |
| **I3 行为设计闭环** | AG-012、AG-013、AG-020、DOC-001 | **4–10 周**（仓库：**`BEHAVIOR_PROTO_DESIGN_MAPPING.md`**、**`BEHAVIOR_DIM_BCD_AUDIT_AG012.md`**、**`BEHAVIOR_GATES_AG013.md`**、**`BEHAVIOR_E_GROUP_FEED_AG020.md`** + **`test_ave_behavior_gates`** 扩展） |
| **I4 平台推理产品化** | PL-021、PL-033、PL-034 | **3–8 周** |

---

## G. 依赖关系简图（文字）

```
AG-001 → AG-002 → AG-003
AG-010 → AG-011 → AG-012 → AG-013
AG-012 + AG-020 → B3c 收口

PL-001 → PL-002（可选）
PL-010 → PL-011 → PL-012（可选）
PL-020 → PL-021（可选）

PL-030 → PL-031 → PL-032 → PL-033 → PL-034
                └→ PL-035 → FE-005

REL-010 → REL-012；REL-011 与每版 platform 并行
```

---

*版本：2026-04-18（I1 + REL-010/FE-004；I2 试点；**I3**：**DOC-001** 已关，**AG-012/013/020** 文档与门禁单测已落地，评审/真机仍待勾选）· 随仓库关单更新 **状态** 列；粗估仅作排期参考。*
