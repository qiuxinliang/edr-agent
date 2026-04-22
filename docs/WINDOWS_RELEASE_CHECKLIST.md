# Windows 发版核对清单（仅 Windows）

**范围**：本文件只覆盖 **Windows x64 / ARM64** 上的 **`edr_agent.exe`** 发版与现场验收；**不含** Linux。  
**详细预检与排障**：**`docs/WINDOWS_DEPLOY.md`**（§3 起）、**`README.md`** §17/§19。  
**相对设计全图（含 Linux 列）**：**`docs/EDR_AGENT_DESIGN_COVERAGE_CHECKLIST.md`**。

---

## 0. 发版类型与架构

| 勾 | 项 | 说明 |
|----|----|------|
| ☐ | **目标架构与 CI 一致** | 发版物与 **`edr-agent-ci.yml`** 中 **`windows-latest`**（x64）或 **`windows-11-arm`**（ARM64）之一一致；勿混用 MinGW x64 PE 与 MSVC 现场包。 |
| ☐ | **配置：`Release`** | `cmake --build build --config Release`；符号与 PDB 策略按安全团队要求。 |

---

## 1. 构建与自动化测试

| 勾 | 项 | 说明 |
|----|----|------|
| ☐ | **本机或 CI：`ctest` 通过** | 至少 **`ctest --test-dir build -C Release --output-on-failure`**（与 workflow 对齐）。 |
| ☐ | **（可选）Shellcode 语料** | **`cmake --build build --target shellcode_t_sc_000_verify`** 或 **`bash scripts/shellcode_corpus/t_sc_000_verify.sh build`**（含 pipeline **`--strict`**）。 |
| ☐ | **gRPC 栈发版** | 若发版包需 **真实 Subscribe / ReportEvents**，确认 **非** `EDR_WITH_GRPC=OFF` 的构建；stub 构建仅用于窄场景。 |

---

## 2. 配置与身份（最小可运行）

| 勾 | 项 | 说明 |
|----|----|------|
| ☐ | **`agent.toml` 三件套** | **`[server].address`**、**`[agent].endpoint_id`**、租户相关字段与 **`agent.toml.example`** / 安装器输出一致。 |
| ☐ | **TLS / mTLS** | `ca_cert`、可选 `client_cert`/`client_key` 与平台 ingest 一致；调试 **`EDR_GRPC_INSECURE=1`** 不得进生产。 |
| ☐ | **ingest 与 UploadFile** | 取证 / Webshell 上传地址须为 **已实现 `UploadFile` 的 EventIngest**；见 **`docs/AGT009_FORENSIC_UPLOAD_E2E.md` §2.1**。 |
| ☐ | **运行账户策略已签字** | **LOCAL SERVICE 收窄** vs **LocalSystem/管理员全功能**：见 **`WINDOWS_DEPLOY.md` §2**。 |

---

## 3. 采集与总线（核心路径）

| 勾 | 项 | 说明 |
|----|----|------|
| ☐ | **ETW 会话成功** | 启动后无持续 **`edr_collector_start` 失败**；Kernel Provider 失败则不可发「全采集」版。 |
| ☐ | **扩展 Provider 行为符合预期** | 可选 Provider 跳过时有 stderr 说明；**§19.10** TCPIP/WF 与攻击面联动策略与 **`[attack_surface]`** 一致。 |
| ☐ | **注册表 → 平台**（若产品需要） | 按 **`docs/REGISTRY_ETW_ACCEPTANCE.md`** 做过至少一条实机或预发验证。 |
| ☐ | **总线背压可观测** | 高负载场景下关注退出日志 **`bus_dropped` / `bus_hw80`**；见 **`docs/EVENT_BUS_BACKPRESSURE.md`**。必要时压测 stderr：**ETW** / **PMFE** 约 **5s** 节流一行、**Webshell** 与 **WinDivert** 为即时一行。 |

---

## 4. 可选模块（按产品开关勾选）

| 勾 | 项 | 说明 |
|----|----|------|
| ☐ | **`[shellcode_detector].enabled=true`** | **WinDivert** 驱动/服务已装；**`windivert_tcp_ports`** 与监控范围评审通过；默认 **false** 发版可跳过整行。 |
| ☐ | **§17 取证目录** | **`forensic_dir` / `EDR_FORENSIC_OUT`** 可写；PCAP 与 **`EDR_SHELLCODE_WD_STATS`** 策略已告知运维。 |
| ☐ | **`[webshell_detector]`** | 站点路径、YARA 目录、上传开关与 **`EDR_FORENSIC_UPLOAD`** 一致。 |
| ☐ | **`EDR_PMFE_ETW_AUTO` 等** | 若启用 shellcode→PMFE 自动入队，确认 **`SOAR_CONTRACT.md` §1** 与冷却环境变量。 |
| ☐ | **`[ave]` + ONNX** | 发版若带 ONNX：**`EDR_WITH_ONNXRUNTIME`** 构建 + **`[ave].model_dir`** 现场路径；见 **`docs/AVE_ONNX_LOCAL_STACK.md`**。 |

---

## 5. 指令、自保护与服务

| 勾 | 项 | 说明 |
|----|----|------|
| ☐ | **高危指令策略** | **`EDR_CMD_ENABLED` / `[command] allow_dangerous`** 与运维 playbook 一致；**`EDR_CMD_AUDIT_PATH`** 可写。 |
| ☐ | **`forensic` / `isolate` / `kill`** | 至少抽样一条 **`forensic`**（含 **`UploadFile`** 或明确关闭上传）；**`kill`** 不误杀自身（已实现保护）。 |
| ☐ | **Windows 服务路径** | 若走 SCM：**`--service`** 与 **`sc stop`** 行为见 **`docs/WINDOWS_SERVICE_SHUTDOWN.md`**。 |
| ☐ | **自保护回归（按需）** | Job Object / anti_debug 等见 **`docs/SELF_PROTECT_REGRESSION.md`**（默认关项须显式开启才测）。 |

---

## 6. 攻击面（§19，若启用）

| 勾 | 项 | 说明 |
|----|----|------|
| ☐ | **`[platform].rest_base_url` + Bearer** | **`POST .../attack-surface`** 成功或失败原因可解释；**`endpoint_id`≠`auto`**。 |
| ☐ | **ETW 触发快照** | **`etw_refresh_triggers_snapshot`** 与 **`etw_refresh_debounce_s`** 与现场负载匹配。 |

---

## 7. 签出

| 角色 | 姓名 | 日期 | 备注（架构 / 账户模式 / 版本号） |
|------|------|------|----------------------------------|
| 研发 | | | |
| 安全 | | | |
| 运维 | | | |

---

## 修订记录

| 日期 | 变更 |
|------|------|
| 2026-04-20 | 首版：从 **`EDR_AGENT_DESIGN_COVERAGE_CHECKLIST.md`** 抽出仅 Windows 发版项，并引用 **`WINDOWS_DEPLOY.md`** |
