# EDR Agent（端点）

本目录按 [Cauld Design/EDR_端点详细设计_v1.0.md](../Cauld%20Design/EDR_端点详细设计_v1.0.md) 拆分模块，用于从设计落地到实现的起点。

**改进任务单（按 AGT-xxx 编号，可拆 issue）**：[docs/CLIENT_IMPROVEMENT_TASKS.md](docs/CLIENT_IMPROVEMENT_TASKS.md)。

**线程模型（M2）**：[docs/AGENT_THREAD_MODEL.md](docs/AGENT_THREAD_MODEL.md)（**AGT-003**）。**取证 UploadFile 联调**：[docs/AGT009_FORENSIC_UPLOAD_E2E.md](docs/AGT009_FORENSIC_UPLOAD_E2E.md)。**Linux P7 eBPF 路线图**：[docs/AGT012_LINUX_EBPF_P7.md](docs/AGT012_LINUX_EBPF_P7.md)。

### 工程文档与 Windows / Linux 能力对齐（AGT-011）

- **可交付行为变更须随文档**：仓库级约定见根目录 [docs/ENGINEERING_PRINCIPLES.md](../docs/ENGINEERING_PRINCIPLES.md)。
- **能力矩阵（避免「设计有、本分支无」的静默误预期）**：

| 能力 | Windows | Linux（默认 `EDR_WITH_LINUX_COLLECTOR=ON`） | 其它 POSIX |
|------|---------|-----------------------------------------------|------------|
| 采集主路径 | ETW（内核三通道 + TDH + 扩展 Provider，见下文「ETW 增强」） | **M1**：inotify 文件事件（`collector_linux.c`）；进程/网络等 **§3.2** 见路线图 **P7** | `collector_stub` |
| 预处理 / 批次 / gRPC 客户端 / Subscribe 指令 | 是 | 是 | 是 |
| §19 攻击面 HTTP `POST` | 是（监听/出站路径最完整） | 是（依赖 `ss`/`curl` 等，见 §19 长段） | 同 Linux |
| §17 WinDivert Shellcode | 是 | 否 | 否 |
| §1.2 API / IAT 用户态 Hook | **本期不做**（**`docs/AGT004_API_MONITOR_DESCope.md`**，AGT-004 descope） | — | — |

**AVE / ONNX 首次真推理（AGT-005）**：**[docs/AVE_ONNX_LOCAL_STACK.md](docs/AVE_ONNX_LOCAL_STACK.md)**；一键脚本 **`scripts/onnx_local_stack_smoke.sh`**（`bash ./scripts/onnx_local_stack_smoke.sh`）。与平台 + 前端的租户约定仍见 **edr-backend/docs/LOCAL_STACK_INTEGRATION.md**。**管控指令与控制台展示边界**见 **[docs/AVE_PLATFORM_FRONTEND.md](docs/AVE_PLATFORM_FRONTEND.md)**（与 **`docs/SOAR_CONTRACT.md`** 配套）。

## 目录与 DDD 章节对应

| 代码路径 | 设计文档章节 |
|---------|-------------|
| `include/edr/types.h`, `event_bus.h` | §1.2、§2.3、附录 16 |
| `src/collector/` | §3 ETW / eBPF / 轮询 |
| `src/preprocess/` | §4 本地预处理引擎（ETW1→`EdrBehaviorRecord`、MITRE 初标） |
| `src/serialize/behavior_wire.c` | §6 紧凑线格式 v1（BER1，默认批次帧） |
| `proto/edr/v1/event.proto`、`src/proto/edr/v1/event.pb.*` | §6.1 `BehaviorEvent` — **nanopb** 生成 + `behavior_proto.c` 编码 |
| `src/serialize/behavior_proto_c.c` | 同 wire 的 `edr_behavior_record_encode_protobuf_c`；可选 **protobuf-c** `event.pb-c.*`（见 `third_party/protobuf-c/`） |
| `src/transport/event_batch.c` | §6.2 批次：`BAT1` 头 + 多帧 `u32le` 长度前缀 + wire 体；字节/条数上限见 §11 `upload` |
| `src/ave/`、`include/edr/ave_sdk.h` | §5 AV Engine：`edr_ave_*` 与 09 文档对齐的 **`AVE_*` SDK**；`AVE_ScanFile` 含 **L1** 证书 Stage0、**L2/L3** 哈希白名单与 IOC（见 `docs/AVE_ENGINE_IMPLEMENTATION_PLAN.md`） |
| `src/serialize/` | §6 事件序列化 |
| `proto/edr/v1/ingest.proto`、`src/grpc_gen/edr/v1/*` | §7 `EventIngest`（`ReportEvents` / `Subscribe`）— **protobuf + grpc_cpp_plugin** 生成 |
| `src/transport/grpc_client_impl.cpp` | §7 gRPC++ 客户端：mTLS、`ReportEvents`、后台 `Subscribe` |
| `src/transport/` | §6.2 批次、`transport_stub` 统计与 gRPC 发送 |
| `src/command/` | §8 响应指令执行器 |
| `src/attack_surface/` | §19 `GET_ATTACK_SURFACE`：采集监听并 `POST` 平台 REST |
| `src/self_protect/` | §9 自保护 |
| `src/storage/queue_sqlite.c` | §10 SQLite `event_queue`（可选 `EDR_HAVE_SQLITE`） |
| `src/config/` | §11 配置管理 |
| `tools/edr_monitor.c`（`edr_monitor`） | §1.2 / §14 终端联调：读 `agent.toml`，对 gRPC 目标 TCP、REST `healthz`、`[ave]` 模型目录、`[offline]` 队列与 **edr_agent** 进程做黑盒探针（非进程内观测） |
| `src/resource/` | §12 资源限制 |
| `src/shellcode_detector/` | §17 协议层 Shellcode 检测（Windows：WinDivert + 可选 libyara；协议解析含 SMB/RDP/明文 HTTP） |
| `src/webshell_detector/` | §18 Webshell 检测引擎（站点目录监控、专项规则匹配、告警入总线） |

## 构建

```bash
cd edr-agent
cmake -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build
./build/edr_agent --help
./build/edr_agent --config agent.toml.example
./build/edr_monitor --config agent.toml.example
./build/edr_monitor --config agent.toml.example --json
```

**终端监测小工具 `edr_monitor`**：与主程序独立，用于联调阶段快速核对「管控地址是否可达、REST 根是否健康、模型目录与离线库文件是否存在、本机是否已有 Agent 进程」。详见源码头注释；Windows 安装包/zip 在构建出 `edr_monitor.exe` 时会一并带上（可选）。

**首次部署 / 租户注册**：使用独立安装器调用 **`POST /api/v1/enroll`** 并生成 **`agent.toml`**（`[server].address`、`endpoint_id`、`tenant_id`、`[platform].rest_base_url`）。脚本见 **`scripts/edr_agent_install.py`**（跨平台，标准库）、**`scripts/edr_agent_install.ps1`**（Windows 无 Python）、**`scripts/edr_agent_install.sh`**（调用前者）；说明见 **`docs/AGENT_INSTALLER.md`**。从 **GitHub Release** 下载安装时，优先用 **`EDRAgentSetup-*.exe`（Windows）** 或 zip 内 **`install.sh`（Linux）**，见 **`docs/AGENT_INSTALLER.md`** 中「Release 一键安装」。

**Windows 生产部署（服务账户、ETW/WinDivert 预检、`sc` 示例草案）**：见 **`docs/WINDOWS_DEPLOY.md`**（**AGT-006 已关闭**）；索引见 **`deploy/README.md`**。管理端 zip / MSI 流水线以 **edr-backend** 文档为准。

**无 MSVC、仅验证 Windows 目标能否编过**：在仓库内执行 **`./scripts/build_windows_mingw.sh`**（需 `x86_64-w64-mingw32-gcc` 在 `PATH` 中，或设置 **`MINGW_PREFIX`** 指向工具链根目录；来源可为 **MacPorts / 任意解压的 MinGW**，或 **docker / podman** 可用时自动执行 **`./scripts/build_windows_mingw_docker.sh`**（Ubuntu `apt` 安装 MinGW，**不经 Homebrew ghcr**；**Docker Desktop 异常**时可用 **Colima / Podman Machine** 等，见文档）。**Homebrew ghcr 超时或容器不可用**，见 **`docs/WINDOWS_CROSS_COMPILE.md`**（含 **终端编译注意要点**：保留 **`build-mingw/`** 等中间文件便于后查、**gRPC/protobuf/vcpkg** 维护）。产物在 **`build-mingw/`**，与 MSVC 二进制 ABI 不同，仅作编译期检查）。

**本机无 CMake / 沙箱或 CI 中编 Linux 版**：在 **`docker`/`podman` 可用**时执行 **`./scripts/build_linux_native_docker.sh`**，在 Ubuntu 容器内 **`apt` 安装 CMake + Ninja + 依赖** 并生成 **`build-linux/edr_agent`**（与 Trae 等沙箱内「干净环境装依赖再编译」同思路）。说明见 **`docs/SANDBOX_LINUX_BUILD.md`**；仅需 CMake 链路冒烟时可设 **`EDR_WITH_GRPC=OFF`**。

### CMake 与 gRPC 可选依赖

| 选项 | 含义 |
|------|------|
| `EDR_WITH_GRPC`（默认 `ON`） | 为 `ON` 且系统能 `find_package(gRPC CONFIG)` 时，链接 **gRPC++** 与 **protobuf**，编译真实 `grpc_client_impl.cpp` 与 `src/grpc_gen/edr/v1/*.cc`。 |
| `EDR_WITH_GRPC=OFF` | 不依赖 gRPC，改用 `grpc_client_stub.c`，进程仍可运行，上报与补传 RPC 恒为失败（返回码 `-1`）。 |
| `EDR_WITH_LINUX_COLLECTOR`（默认 `ON`，**仅 Linux**） | 为 `ON` 时编入 `src/collector/collector_linux.c`；为 `OFF` 时在 Linux 上退回 `collector_stub.c`（与其它 POSIX 一致）。**Windows 不受影响**（始终使用 `collector_win.c`）。 |
| `EDR_WITH_ONNXRUNTIME`（默认 `OFF`） | 为 `ON` 且能 `find_path`/`find_library` 找到 **ONNX Runtime**（头文件 `onnxruntime_c_api.h` 与 `libonnxruntime`）时，定义 **`EDR_HAVE_ONNXRUNTIME`**；主进程在 **`edr_agent_init`** 中通过 **`AVE_InitFromEdrConfig(&cfg)`**（见 `ave_sdk.h`）在 **`[ave] model_dir`** 下加载**首个** `.onnx` 做真推理；未找到库时 CMake **告警**并仍按无 ONNX 编译。可通过 **`ONNXRUNTIME_ROOT`** 指向解压的预编译包。**联调步骤**见 **[docs/AVE_ONNX_LOCAL_STACK.md](docs/AVE_ONNX_LOCAL_STACK.md)**。 |

#### Linux：inotify（M1）

在 **Linux** 且 `collector_linux.c` 启用时，`[collection] etw_enabled = true`（默认）会启动 **inotify** 后台线程，将目录下文件事件以 **`ETW1`** 文本格式写入事件总线，供预处理与 Windows ETW 路径一致。

| 环境变量 | 说明 |
|---------|------|
| `EDR_INOTIFY_PATHS` | 可选。逗号分隔的**已存在目录**列表（首尾空格会被修剪）；未设置时默认只监视 **`/tmp`**。 |

若 `etw_enabled = false`，不创建 inotify 线程（与 Windows 下不启 ETW 会话一致）。监视目录不存在或不可读时，启动会失败并打印 `[collector_linux]` 提示。

若已安装 gRPC（如 macOS `brew install grpc`），CMake 会搜索 `/usr/local` 与 `/opt/homebrew`。**不要**在工程中再单独 `find_package(Protobuf)`，以免与 gRPC 自带的 Protobuf 目标冲突。

### §17 Shellcode 检测引擎（Windows）

- 配置节 **`[shellcode_detector]`**（见 `agent.toml.example`），默认 **`enabled = false`**，不改变既有部署行为。
- 已编译：**熵 / 启发式 / SMB2·SMB1·RDP·明文 HTTP 载荷区定位**（`proto_parse.c`；HTTPS/TLS 仍按原始字节启发式），单测 `test_shellcode`。
- **WinDivert 闭环（初版）**：`windivert_capture.c` 从 **`%SystemRoot%\System32\WinDivert.dll`** **动态加载**（无需链接 `WinDivert.lib`），`SNIFF | RECV_ONLY` 捕获 TCP 端口集合；**`windivert_tcp_ports`** 为空时使用内置端口（SMB/RDP/WinRM/MSRPC/LDAP 等）；**非空**时为逗号分隔列表（如 `80,443,8443`），据此生成过滤器，且 **`monitor_smb` 等按类开关不再生效**（仅按列表匹配）。TCP 载荷经协议区段提取与启发式打分，**≥ `alert_threshold`** 时投递 **`EDR_EVENT_PROTOCOL_SHELLCODE`**（ETW1，`prov=windivert`），预处理映射 **T1210**。
- **已实现（Phase 2）**：优先使用 **libyara** 扫描已知漏洞规则（`yara_rules_dir` 指向规则目录，加载 `.yar/.yara`）；命中时以 `detector=yara` 和 `rule=<规则名>` 上报。若未安装 libyara 或目录未加载到规则，自动降级为内置匹配器（规则名保持一致：`EternalBlue_MS17_010` / `BlueKeep_CVE_2019_0708` / `PrintNightmare_CVE_2021_34527`）。默认规则文件见 `src/shellcode_detector/rules/known_exploits.yar`。
- **P0（持续迭代）**：IPv6 五元组；**`windivert_tcp_ports`**；**单包或环形 PCAP**（`shellcode_ring_*.pcap`，EN10MB）；**SHA256 + 可选 preview_hex**；环形告警附 **`ring_*_ns` / `ring_trigger_slot`** 与 **`shellcode_json`** 行；**`heuristic_score_scale`** 调启发式灵敏度；**`yara_rules_reload_interval_s`** 热重载规则（libyara）；**`auto_isolate_threshold`** 仍为高优先级标记；**可选端上隔离**：`EDR_SHELLCODE_AUTO_ISOLATE=1` 或 **`auto_isolate_execute`** + 高危策略，与 **`isolate`** 同路径（每进程最多一次）。WinDivert 过滤器在**启动时**固定。**pcapng / 纯服务端编排隔离**等见 **`docs/WINDOWS_SHELLCODE_FORENSIC_TODO.md`**。

### §18 Webshell 检测引擎（Web 服务目录监控）

- 入口：`edr_webshell_detector_init()` / `edr_webshell_detector_shutdown()`（`src/main.c` 已接入）。
- Linux 当前实现：`inotify` 递归监控站点目录的新增/写入完成/移入事件，预过滤后执行 Webshell 专项规则扫描。
- 规则目录：`src/webshell_detector/rules/`（`php_webshell.yar`、`jsp_aspx_webshell.yar`），可通过 `[webshell_detector].webshell_rules_dir` 覆盖。
- 若编译时找到 `libyara` 则优先用 YARA 引擎扫描；否则自动回退到内置关键模式匹配（保证功能可用）。
- 命中后写入事件总线事件类型 `EDR_EVENT_WEBSHELL_DETECTED`，预处理映射 MITRE `T1505.003`。
- 取证上传：`ingest.proto` 已扩展 `UploadFile(stream FileChunk)`；agent 命中后优先走 gRPC 流式上传（256KB 分片，首片携带 `sha256/file_size`），失败时自动回退到本地分层落盘（`webshell/{tenant}/{date}/{alert_id}/{filename}`）。

**WinDivert 路径约定（本环境）**

| 用途 | 路径 |
|------|------|
| 用户态 DLL（部署） | **`%SystemRoot%\System32\WinDivert.dll`**（例如 `C:\Windows\System32\WinDivert.dll`） |
| 内核驱动（安装后） | 通常在 **`%SystemRoot%\System32\drivers\`** 下，名称形如 `WinDivert*.sys`（以实际安装为准） |
| 开发编译 | **`windivert.h` / `WinDivert.lib`** 仍来自官方 SDK 解压目录；CMake 可用 **`WINDIVERT_ROOT`** 指向该目录；**不要**指望 System32 里带有头文件与导入库 |

运行期若从固定路径加载 DLL，可使用上述 System32 路径；需管理员权限与已正确安装的 WinDivert 服务/驱动。

---

## 配置说明（§11 TOML + 环境变量）

### 命令行

| 参数 | 说明 |
|------|------|
| （无参数） | 打印用法说明后退出。 |
| `--config <path>` | 加载 TOML 配置文件；启动 Agent 时须指定（或依赖安装包/计划任务已写入的带 `--config` 的启动方式）。 |
| `--help` / `-h` / `-help` / `/?` | 打印用法说明后退出。 |

`edr_agent` 在 Windows 上执行 **`--help`** 或**无参数**时，帮助文本中会顺带说明 **Inno 安装包 `EDRAgentSetup.exe` 静默安装**时如何通过 **`/EDR_API_BASE=`**、**`/EDR_ENROLL_TOKEN=`**（或 **`/API=`**、**`/TOK=`**）传入平台与注册信息；细则见 **`docs/AGENT_INSTALLER.md`**（Release 一键安装 · Windows）。

解析器为 **tomlc99**（`third_party/tomlc99`）。参考模板：**`agent.toml.example`**，可复制为 `agent.toml` 后修改。与 **platform + 前端 + 种子库** 对齐的联调示例见 **`agent.integration.toml`** 与仓库 **`edr-backend/docs/LOCAL_STACK_INTEGRATION.md`**。**Windows 真机行为 ONNX 端到端验收**见 **`docs/REAL_DEVICE_BEHAVIOR_E2E.md`**。

### `[server]` — gRPC 接入与 TLS

| 字段 | 说明 |
|------|------|
| `address` | gRPC 服务端地址，如 `host:50051`。为空则跳过 gRPC 初始化（仅本地统计/队列仍可用）。 |
| `ca_cert` | PEM 路径：服务端/链校验用根或中间 CA。 |
| `client_cert` / `client_key` | 客户端证书与私钥 PEM 路径；与 `ca_cert` 同时配置时走 **mTLS**。 |
| `connect_timeout_s` | `ReportEvents` 单次 RPC 截止时间（秒），默认 10。 |
| `keepalive_interval_s` | 通道 keepalive 间隔（秒），映射为 gRPC `GRPC_ARG_KEEPALIVE_TIME_MS`，默认 30。与平台「在线」判定见 **`docs/SOAR_CONTRACT.md` §4**（**§4.1** 终端；**§4.2** 平台契约与 **`T_offline`**；**后端实现见 §4.2.3**）。 |

仅配置 `ca_cert`、不配客户端证书时，为**单向 TLS**（校验服务端），与完整 mTLS 不同。

`POST /api/v1/enroll` 返回的 `server_addr` 语义应与 `server.address` 一致（即 **Agent gRPC 接入地址**，不是 REST 基址）。平台当前解析优先级为：

1. 租户 `features.grpcServerAddress`
2. `ENROLL_PUBLIC_SERVER_ADDR`
3. `PUBLIC_API_BASE`（URL 会规范化为 `host[:port]`）
4. `127.0.0.1:8443`（兜底）

### `[agent]`

| 字段 | 说明 |
|------|------|
| `endpoint_id` | 上报与 `Subscribe` 使用的端点标识。 |
| `tenant_id` | 租户标识（预留，随配置传给后续逻辑）。 |

### `[ave]` — ONNX、L1 证书 Stage0、L2/L3 哈希抑制

| 字段 | 说明 |
|------|------|
| `model_dir` / `scan_threads` / `max_file_size_mb` / `sensitivity` | 见上文构建说明与端点设计 §5。 |
| `cert_whitelist_enabled` | **Windows** 默认 `true`：`AVE_ScanFile` 在 ONNX 前走 **L1**（`WinVerifyTrust`、可选内置链/SQL 白名单/厂商路径等；见 `docs/AVE_ENGINE_IMPLEMENTATION_PLAN.md`）。非 Windows忽略。 |
| `cert_whitelist_db_path` | 可选 SQLite；表 **`sign_blacklist`**（`cert_thumbprint` BLOB 32B）命中则 ONNX 后 **+0.30** 置信度；另有 **`sign_whitelist`** / **`sign_cache`** 等供 L1（需 **`EDR_HAVE_SQLITE`**）。 |
| `file_whitelist_db_path` | 可选 SQLite；表 **`file_hash_whitelist`**（`sha256` TEXT 64 位小写 hex，`is_active`）命中则 **`VERDICT_WHITELISTED`**，`verification_layer=L2`，**跳过 ONNX**。 |
| `ioc_db_path` | 可选 SQLite；表 **`ioc_file_hash`**（同上 + 可选 `severity`）与 **`ave_db_meta`**（键 **`rules_version`** 等）。预检命中可跳过 ONNX；**ONNX 后**仍会二次核对（`ioc_file_hash_post`），**保留** `raw_ai_*`。 |
| `ioc_precheck_enabled` | 默认 `true`；为 `false` 时**不**在 ONNX 前拦截 IOC（便于先跑模型再以后检为准）。 |
| `behavior_policy_db_path` | 可选 SQLite；表 **`file_behavior_non_exempt`**（`escalate` 等）用于 **L4**（ONNX 之后），见实施计划。 |
| `behavior_monitor_enabled` | 默认 `true`：在已 **`AVE_RegisterCallbacks`**（含 `on_behavior_alert`）时，**`AVE_StartBehaviorMonitor`** 可拉起行为消费线程；为 `false` 时不拉起（事件仍可 **`AVE_FeedEvent`** 入队）。 |

完整扫描顺序、元数据表、P2 行为管线与单元测试说明见 **`docs/AVE_ENGINE_IMPLEMENTATION_PLAN.md`**。

### `[upload]` — 与 §6.2 批次相关

| 字段 | 说明 |
|------|------|
| `batch_max_events` | 单批最大事件条数（帧数），触顶则刷批。 |
| `batch_max_size_mb` | 单批缓冲区最大字节（内部换算为字节上限）。 |
| `batch_timeout_s` | 空闲超时刷批（秒）。 |

### `[offline]` — SQLite 队列库路径

| 字段 | 说明 |
|------|------|
| `queue_db_path` | 离线队列 SQLite 文件路径（见下文「SQLite 离线队列」）。 |

### 其它表（摘录）

- `collection.max_event_queue_size`：事件总线槽数。
- `preprocessing.*`：去重窗口、高频阈值、白名单采样等；**`[[preprocessing.rules]]`** 可配置路径/命令行等 **子串规则**（`drop` / `emit_always`），在 dedup 之前匹配，**条数无 64 条硬顶**（堆分配），详见 **`docs/PREPROCESS_RULES.md`**。
- `collection.etw_enabled`（仅 Windows）：是否启用 ETW 采集；`false` 可关闭 ETW。

### 环境变量索引（运行时）

| 变量 | 说明（详情见下文对应章节） |
|------|---------------------------|
| `EDR_GRPC_INSECURE` | `=1` 时使用非加密 gRPC（仅调试）。 |
| `EDR_QUEUE_PATH` | 覆盖 TOML 中的 `offline.queue_db_path`。 |
| `EDR_PERSIST_QUEUE` | `=1` 且策略为 **always** 时，flush 同时将批次写入 SQLite。 |
| `EDR_PERSIST_STRATEGY` | `always`（默认）或 `on_fail`：见「SQLite」与「gRPC」小节。 |
| `EDR_QUEUE_MAX_RETRIES` | 单条补传最大重试次数，默认 `100`；`0` 表示不限制。 |
| `EDR_QUEUE_MAX_DB_MB` | 队列库文件大小上限（MB，粗粒度 `stat`），超出则拒绝新入队；未设置则不限制。（当前非 Windows 生效） |
| `EDR_BEHAVIOR_ENCODING` | 见「Protobuf（nanopb）」：`protobuf` / `protobuf_c` / 默认 BER1。 |
| `EDR_CMD_ENABLED` / `EDR_CMD_DANGEROUS` | 任一为 `1` 时允许 **kill / isolate / forensic**；亦可由 TOML **`[command] allow_dangerous = true`** 固定策略（环境变量优先于未设置项）。 |
| `EDR_CMD_KILL_ALLOWLIST` | 若设置（逗号分隔 PID 列表），**kill** 仅允许终止列表内进程（仍须先满足高危策略）；未设置则不限制 PID。 |
| `EDR_CMD_AUDIT_PATH` | 若设置，高危指令审计**追加**写入该文件（带时间戳）；stderr 仍会打印 `[command][audit]`。 |
| `EDR_SOAR_REPORT_ALWAYS` | `=1` 时对**每条**指令尝试 gRPC **`ReportCommandResult`**（即使无 `soar_correlation_id`）；默认仅在下发含编排字段时上报。 |
| `EDR_ISOLATE_HOOK` | 若设置，`isolate` 在写标记后执行 `system(hook)`（POSIX 下会 `setenv("EDR_CMD_ID", …)`）。 |
| `EDR_SHELLCODE_AUTO_ISOLATE` | `=1` 时，若已允许高危指令且 WinDivert 分数 ≥ **`auto_isolate_threshold`**，执行与 **`isolate`** 相同的标记 + **`EDR_ISOLATE_HOOK`**（每进程最多一次）。亦可由 TOML **`[shellcode_detector] auto_isolate_execute = true`** 开启（仍须高危策略）。 |
| `EDR_CONFIG_RELOAD_S` | 非 `0` 时每隔 N 秒检测配置文件 mtime，变更则热更 **preprocessing + resource_limit + self_protect**（见 §11.2 初版）。 |
| `EDR_REMOTE_CONFIG_URL` | 若与 **`EDR_REMOTE_CONFIG_POLL_S`**（秒，≥1）同时设置，则周期性用 **`curl`** 下载 TOML 到临时文件并 **`edr_config_load`**，再应用 **preprocessing + resource_limit + self_protect**（**不**重连 gRPC / 不重初始化传输层，需重启进程才能对齐证书与批次参数）。URL 勿含未转义引号（Windows `cmd` 限制）。 |
| `EDR_REMOTE_CONFIG_POLL_S` | 与上一项配合：轮询间隔秒数；未设置或 `0` 则禁用远程拉取。 |
| `EDR_AVE_INFER_DRY_RUN` | `=1` 时 **`edr_ave_infer_file`** 不调用真实后端，返回占位 **`EdrAveInferResult`**（集成测试/联调；生产应启用 **`EDR_WITH_ONNXRUNTIME`** 并勿依赖此项）。 |
| `EDR_AVE_ONNX_IN_LEN` | （可选）ONNX 输入含**动态长度**轴时，用作该轴默认元素个数（默认 **4096**）；需与模型一致。 |
| `EDR_RESOURCE_STRICT` | `=1` 时即使 `cpu_limit_percent` &lt; 5 也做 CPU 监控（否则跳过以免默认 1% 刷屏）。 |
| `EDR_SELF_PROTECT_WATCHDOG` | `=1` 时周期性 stderr 心跳（极粗看门狗）；与 TOML **`[self_protect] watchdog_log_interval_s`** 可并存。 |
| `EDR_SELF_PROTECT_PIDFILE` | 若设置，启动时写入当前 PID（退出时尝试 `remove`）；便于外部进程管理。 |
| `EDR_FORENSIC_OUT` | 取证输出根目录；未设置时 **POSIX** 默认 `/tmp/edr_forensic`，**Windows** 默认 **`%TEMP%\\edr_forensic`**。 |
| `EDR_FORENSIC_COPY_PATHS` | `=1` 时按 payload **每行一个路径**复制到作业目录（POSIX：**`open`/`read`/`write`**；Windows：**`CopyFileA`**；`#` 行与空行忽略）。 |
| `EDR_ISOLATE_STAMP_PATH` | 隔离标记文件路径；未设置时 POSIX 默认 `/tmp/edr_isolated_<command_id>`，Windows 默认 **`%TEMP%\\edr_isolated_<command_id>`**。 |
| `EDR_PLATFORM_REST_BASE` | 覆盖 **`[platform].rest_base_url`**；攻击面 **`POST`** 的 API 前缀（无尾斜杠）。未设置且 TOML 未配时，指令仍成功结束但不发起 HTTP（结果 detail 含 `skip_no_rest_base`）。 |
| `EDR_PLATFORM_BEARER` | 可选 JWT，作为 **`Authorization: Bearer …`**（优先于 **`[platform].rest_bearer_token`**）。 |
| `EDR_WIN_LISTEN_CACHE_TTL_MS` | **（Windows）** 覆盖 **`[attack_surface].win_listen_cache_ttl_ms`**：监听表 **`edr_win_listen_collect_rows`** 进程内缓存 TTL（毫秒）。`0` 表示关闭缓存；未设置则沿用 TOML/默认。 |
| `EDR_ATTACK_SURFACE_POST_ON_CONFIG_RELOAD` | `=1` 时，**本地 TOML 热重载**或**远程 TOML** 成功应用后，若 **`[attack_surface].enabled=true`** 且 **`endpoint_id`** 有效，额外 **`POST`** 一次快照（`command_id` **`config_reload`**）。默认不 POST，避免配置抖动连打平台。 |
| `EDR_ATTACK_SURFACE_ETW_LIGHT` | `=1` 且 **`etw_tcpip_wf`** 触发时，快照 **`snapshotKind=listenersOnly`**（不采集出站 `ss`/系统策略查询，缩短 ETW 洪峰路径延迟）。 |
| `EDR_ATTACK_SURFACE_LISTENERS_ONLY` | `=1` 时，任意 **`edr_attack_surface_execute`** 均使用 **`listenersOnly`** 快照（调试用）。 |

**系统级网络隔离（nft / 防火墙）**：客户端不内置 nft 规则；将运维脚本路径设为 **`EDR_ISOLATE_HOOK`**（如对某接口 `nft add rule … drop`），由 **`isolate`** 在写标记后调用；配合 **`EDR_CMD_AUDIT_PATH`** 留痕。

**SOAR 协议契约**：编排字段（`soar_correlation_id`、`playbook_run_id` 等）在 **`CommandEnvelope`** 中下发；执行结束后终端调用 **`ReportCommandResult`** 回传状态。详见 **`docs/SOAR_CONTRACT.md`**。**§19 攻击面** 详设 §19.4/§19.5（调度 / gRPC 示例）与当前 **REST + `curl` POST** 的差异见 **`docs/ATTACK_SURFACE_DESIGN_ALIGNMENT.md`**；gRPC **`ReportSnapshot`** 后续接入步骤见 **`docs/ATTACK_SURFACE_GRPC.md`**。

**§19 攻击面快照（`GET_ATTACK_SURFACE`）**：Subscribe 指令类型 **`GET_ATTACK_SURFACE`** / `get_attack_surface` / `REFRESH_ATTACK_SURFACE` 时，Agent 组装与控制台 **GET** `/api/v1/endpoints/:id/attack-surface` 同形的 **camelCase JSON**，通过 **`curl`** 执行 **`POST`** `{rest_base}/endpoints/{endpoint_id}/attack-surface`。**Linux**：监听来自 **`ss -ltnp`**（含 **tcp6** 行；解析同时支持「`LISTEN` 起头」与「`tcp/tcp6 LISTEN`」两种列布局），出站 **`ss -tanp state established`**（**含 IPv6**，不再使用 `-4`）；IPv6 私网/链路本地与 v4 一致参与 **`suspiciousEgressCount`/`riskTag`** 启发式。**Windows**：监听枚举在 **`listen_table_win.c`**（**`edr_win_listen_collect_rows`**），底层 **`GetExtendedTcpTable` / `GetExtendedUdpTable`**（**IPv4+IPv6** / `TCP_TABLE_OWNER_PID_LISTENER` / `UDP_TABLE_OWNER_PID`），进程内 **TTL 缓存**（默认 **2000 ms**，**`[attack_surface].win_listen_cache_ttl_ms`** / **`EDR_WIN_LISTEN_CACHE_TTL_MS`**；`0` 关闭缓存）供 §19 与 §21 PMFE 共用；出站来自 **`GetExtendedTcpTable`**（**IPv4+IPv6** `TCP_TABLE_OWNER_PID_CONNECTIONS`，ESTAB=**5**）；IPv6 见 **`edr_asurf_win_ipv6_to_string` / `edr_asurf_win_bind_scope_v6`**；进程短名由 **`QueryFullProcessImageNameA`**；共享辅助见 **`attack_surface_win_util.c`**；协议字段 **`tcp`/`udp`/`tcp6`/`udp6`**。另：**`edr_attack_surface_refresh_pending`** 对 **`GET {rest_base}/endpoints/{id}/attack-surface/refresh-request`** 轮询（同权限头），与控制台 **POST …/attack-surface/refresh** 排队联动。需 **`[platform].rest_base_url`**（无尾斜杠，如 `http://127.0.0.1:8080/api/v1`）或环境变量 **`EDR_PLATFORM_REST_BASE`** 覆盖；可选 **`EDR_PLATFORM_BEARER`** 或 TOML **`rest_bearer_token`**。请求携带 **`X-Tenant-ID`**（`[agent].tenant_id`）、**`X-User-ID`**（默认 `edr-agent`）、**`X-Permission-Set: endpoint:attack_surface_report`**。`[agent].endpoint_id` 为 **`auto`** 时拒绝上报（避免写错路径）。链接 **`ws2_32` `iphlpapi`**（CMake 已加）。

**监听端口 `riskLevel` / `riskReason`（启发式）**：`attack_surface_report.c` 按 **`scope`**（`public` / `lan` / `loopback`）、绑定是否为全网卡（`0.0.0.0`、`::`、`*`、`[::]`）、端口是否命中内置敏感端口表或 **`[attack_surface].high_risk_immediate_ports`**，为 **`listeners.items[]`** 可选写入 **`riskLevel`（1–3）** 与英文 **`riskReason`**（与控制台 UI 字段对齐）；**`loopback`** 默认不写入风险字段。

**§19.8 TOML `[attack_surface]`**（与《EDR_端点详细设计》§19.8 对齐）：已在 **`EdrConfig`** 中解析 **`enabled`**、各 **`_interval_s`**、**`outbound_top_n`**、**`outbound_exclude_loopback`**、**`geoip_db_path`**、**`high_risk_immediate_ports`**（**内联整型数组**，最多 256 项）、**`firewall_rule_detail_max`**、**`win_listen_cache_ttl_ms`**（**Windows**，监听表进程内缓存毫秒，`0` 关闭；钳 **≤300000**）；默认值见 **`edr_config_apply_defaults`**，钳位见 **`edr_config_clamp`**。**`high_risk_immediate_ports` 为堆数组**，由 **`edr_config_free_heap`** 释放。**周期 POST 与 JSON `ttlSeconds`**：使用 **`edr_attack_surface_effective_periodic_interval_s`**，即 **`min(port_interval_s, service_interval_s, policy_interval_s, full_snapshot_interval_s)`**（钳 60～604800；**`conn_interval_s`** 仅用于 **`refresh-request`** 轮询，不参与）。默认 **`port_interval_s`=300** 时周期约 **300s**；若希望接近「仅按全量间隔」可把这四项都设为相同较大值（如 1800）。**`outbound_top_n`** 暂作写入 JSON 的**监听条数上限**（出站 TOP 采集落地后改为仅约束 egress）；**`outbound_exclude_loopback`** 为 true 时丢弃 **`scope=loopback`** 监听行；端口命中 **`high_risk_immediate_ports`** 时写入 **`processHighlights`**；**`firewall_rule_detail_max`** 与 **`geoip_db_path`** 可读性写入 **`firewall.notes`**；常见 Web 端口启发式写入 **`webServices`**。指令 **`GET_ATTACK_SURFACE`** 仍**不**检查 **`enabled`**（与周期开关解耦）。**`edr_agent_run`**：collector 启动后 **`enabled=true`** 时先 **`agent_start`** 全量上报一次；主循环内按 **`conn_interval_s`**（钳 15～120s）轮询 **`refresh-request`** 并在 **`refreshPending`** 时 **`refresh_request`** 上报；再按上述有效间隔 **`periodic_attack_surface`**。整包快照尚未按维度拆分并行采集线程（见 **`docs/ATTACK_SURFACE_DESIGN_ALIGNMENT.md`**）。配置**热重载**或**远程 TOML** 成功应用后会将攻击面周期与待轮询计时**重置为当前时刻**（避免旧计时导致突发连打）；可选 **`EDR_ATTACK_SURFACE_POST_ON_CONFIG_RELOAD=1`** 立即 **`POST`** 一次。

---

## gRPC / mTLS 使用说明（§7）

### 行为概要

- **`ReportEvents`**：每次批次 flush 时，将 **12 字节批次头 + 载荷**（BAT1 或 BLZ4，见 §6.2）作为 `payload` 上报，并带 `batch_id`（幂等）、`endpoint_id`、`agent_version`。
- **`upload.max_upload_mbps`**：在 `ReportEvents` 发送前对**本批 wire 字节数**（头+体）做**令牌桶**节流（`0` = 不限制；默认 `1` Mbps）；与失败退避独立，二者可能叠加等待。
- **`Subscribe`**：独立后台线程向服务端发起**服务端流**；流断开后按 **500ms 起指数退避（上限 60s）** 自动重连。收到 `CommandEnvelope` 时调用 **`edr_command_on_envelope`**（`src/command/command_stub.c`），并传入 **SOAR 扩展字段**（`EdrSoarCommandMeta`）。指令类型含 `noop` / `ping` / `echo`；`isolate` / `kill` / `forensic` 在启用高危策略时执行（见环境变量与 **`[command] allow_dangerous`**）。**健康/自保护（只读）**：`self_protect_status` / `agent_health` / `health_status`，返回调试器与事件总线占用等。**AVE（§5）联动**：`ave_status` / `ave_fingerprint`（`ave_fp`）/ `ave_infer`，payload 为 `{"path":"..."}`（`ave_status` 可空）；`main` 在 **`edr_agent_init`** 后调用 **`edr_command_bind_config`**，供 `ave_infer` 使用当前 `EdrConfig`。详见 **`docs/SOAR_CONTRACT.md`**（**§5.2** 平台 gRPC 注册现状与 mock）。执行结束后，若含编排关联或 **`EDR_SOAR_REPORT_ALWAYS=1`**，则 **`ReportCommandResult`** 回传。**`forensic`** 在 Windows 上同样写 manifest、可选 `copy`、`tar` 打 **`bundle.tgz`**（依赖 **`tar.exe`**）。
- **`ReportCommandResult`**： unary，上报 **`CommandExecutionResult`**（状态、exit_code、detail、完成时间等）；与 **`ReportEvents` 事件批次**相互独立。详见 **`docs/SOAR_CONTRACT.md`**。
- **`ReportEvents` 失败退避**：连续失败后，下一次 RPC 前在持锁侧做 **50ms～5s** 的指数退避（减轻对不可用服务端的冲击）。
- 通道参数：`GRPC_ARG_INITIAL_RECONNECT_BACKOFF_MS` / `MAX_RECONNECT_BACKOFF_MS` 已设置，便于底层重连。
- 进程退出前会关闭通道并打印 **`[grpc] rpc_ok=… rpc_fail=…`**，以及 **`[command] handled=… unknown=…`**。

### 环境变量

| 变量 | 说明 |
|------|------|
| `EDR_GRPC_INSECURE=1` | **仅用于开发/内网调试**：在缺少有效 PEM 路径时使用 **非加密** gRPC 通道；生产环境应配置证书并勿设置此项。 |

未配置任何证书且未设置 `EDR_GRPC_INSECURE=1` 时，客户端会跳过 gRPC 连接并打印提示（仍可运行进程）。

### 重新生成 `ingest` 桩代码

若修改了 `proto/edr/v1/ingest.proto`，执行 **`./scripts/regen_ingest_proto.sh`**（或手动用 `protoc` + `grpc_cpp_plugin` 生成至 `src/grpc_gen/edr/v1/`）。**protobuf 主版本**须与链接的 `libprotobuf` 一致。

---

## SQLite 离线队列（§10）— 落盘与出队补传

SRE 口径（磁盘上限、重试丢弃、平台 4xx/5xx 解读、**`enqueue_wire_on_fail`**）：**`edr-backend/docs/AGENT_EVENT_QUEUE_SRE.md`**。

依赖：编译时 `find_package(SQLite3)` 成功，定义 **`EDR_HAVE_SQLITE`**，并链接 `queue_sqlite.c`。

### 配置与环境变量

| 来源 | 说明 |
|------|------|
| `EDR_QUEUE_PATH` | 若设置且非空，**优先于** TOML 中的 `offline.queue_db_path`，作为队列库文件路径。 |
| `offline.queue_db_path` | 未设置 `EDR_QUEUE_PATH` 时使用；均未设置时 `edr_storage_queue_open` 默认打开当前目录下 **`edr_queue.db`**。 |
| `EDR_PERSIST_QUEUE=1` | 与 **`EDR_PERSIST_STRATEGY=always`**（或未设置策略）配合：每次 flush 将完整 wire **INSERT**（与当次 gRPC 成败无关）。 |
| `EDR_PERSIST_STRATEGY` | **`always`**（默认）：见上，需 `EDR_PERSIST_QUEUE=1`。**`on_fail`**：flush 时**不写**库；仅在 **`ReportEvents` 失败**且队列已打开时，由传输层把该批写入队列（适合「平时不落盘、失败才缓存」）。 |

### 库内数据格式

- 表中 `payload` 存 **§6.2 完整 wire：`12` 字节头 + 体**（与 `ReportEvents` 的 `payload` 一致），便于 **`edr_storage_queue_poll_drain`** 直接调用 `edr_grpc_client_send_batch` 补传。
- 字段 `compressed` 仅作记录；`retry_count` 在补传失败时递增。

### 出队补传行为

- 在**预处理线程**中周期性调用 `edr_storage_queue_poll_drain()`（与入队同线程，无需额外线程锁）。
- 约 **每 200ms** 最多尝试一轮；单轮内连续成功最多 **32** 条；若某次 **gRPC 失败**，则对该行 `retry_count++` 并**结束本轮**（避免在不可用通道上狂重试）。
- 成功上传后删除对应行；**`retry_count` 达到 `EDR_QUEUE_MAX_RETRIES`（默认 100，`0` 表示不限制）** 时丢弃该条并打日志（死信式处理）。
- **无法识别魔数**的旧数据（仅历史 body、无 12 字节头）会打日志后删除，避免堵塞队列。

### 无 SQLite 或未链接

`edr_storage_queue_*` 为空实现：不落盘、不补传，`edr_storage_queue_pending_count()` 恒为 0。

---

## 运行与日志

- 退出时 stderr 汇总含：`wire_events`、`batches`、`batch_lz4`、`batch_timeout_flushes`、`bus_hw80`、`bus_dropped`、去重丢弃、`queue_pending` 等；若启用 gRPC，另有 **`[grpc] rpc_ok` / `rpc_fail`** 与 **`[command] handled` / `unknown`**。
- 启动时若配置了 `server.address`，`[transport] gRPC target: …` 会打印目标地址；随后由 gRPC 客户端按证书或 `EDR_GRPC_INSECURE` 建立通道。
- 成功加载配置文件路径时，stderr 会打印 **`[config] fingerprint=…`**（FNV-1a 十六进制）；热重载成功后再打一行 **`热重载 fingerprint=…`**。

**Linux**（且 `EDR_WITH_LINUX_COLLECTOR=ON`，默认）编入 `collector_linux.c`：**inotify** 监视目录（默认 `/tmp` 或 `EDR_INOTIFY_PATHS`），产出**文件侧**事件（`ETW1\nprov=inotify…`），**无**进程创建/网络等内核级等价流。**其它非 Windows**（如 macOS）仍为 **`collector_stub`**。在 **Windows** 上构建时自动编译 `src/collector/collector_win.c`：创建实时 ETW 会话、启用 **Kernel-Process / Kernel-File / Kernel-Network** 三通道（§3.1.1），并按配置启用 **§19.10** 的 **Microsoft-Windows-TCPIP** / **WFAS 防火墙** Provider（见「ETW 增强」）；独立线程 `OpenTrace` + `ProcessTrace`，回调中过滤本进程 PID 并写入事件总线。

运行 `edr_agent` 后将以 200ms 周期等待直至 Ctrl+C（控制台）触发关闭。**内核 Provider 通常需要提升权限**（管理员或具备相应 ETW 权限），否则 `StartTrace` / `EnableTraceEx2` 可能返回 `EDR_ERR_ETW_SESSION_CREATE` 或 `EDR_ERR_ETW_PROVIDER_ENABLE`。

### Protobuf（nanopb，§6.1）

- 运行时库：`third_party/nanopb`（`pb_encode.c`、`pb_common.c`），定义 `EDR_HAVE_NANOPB`。
- 生成文件：`src/proto/edr/v1/event.pb.h`、`event.pb.c`（由 `proto/edr/v1/event.proto` + `event.options` 生成）。
- 重新生成：`chmod +x scripts/regen_event_proto.sh && ./scripts/regen_event_proto.sh`（需 Python3，且建议 `pip install protobuf` 与系统 `protoc` 主版本一致，否则 nanopb 生成器可能报错）。
- 编码 API：`edr_behavior_record_encode_protobuf()`（`include/edr/behavior_proto.h`）。
- 默认预处理仍输出 **BER1 线格式**；设置环境变量 `EDR_BEHAVIOR_ENCODING=protobuf` 时尝试 nanopb；`protobuf_c` 时调用 `edr_behavior_record_encode_protobuf_c()`（当前与 nanopb **同一套 protobuf 二进制**，可与 `libprotobuf-c` 解包兼容；若需原生 `*_pack`，见 `third_party/protobuf-c/README_EDR.txt` 与 `scripts/regen_event_proto_c.sh`）；失败则回退 BER1。

### LZ4（可选）

将官方 `lz4.c` / `lz4.h`（v1.9.4）放入 `third_party/lz4/` 后重新 CMake，即定义 `EDR_HAVE_LZ4`：单批原始载荷 ≥1KB 且压缩后更小则使用魔数 **BLZ4**（`EDR_TRANSPORT_BATCH_MAGIC_LZ4`）上传输层；队列落盘与补传行为见上文「SQLite 离线队列（§10）」。

### ETW 增强（Windows）

- **TDH**（`etw_tdh_win.c`）：`TdhGetPropertySize` / `TdhGetProperty` 按 Provider 尝试多组字段名，将事件整理为 UTF-8 文本载荷 `ETW1\nprov=...\npid=...\nimg=...\ncmd=...\n`（见 §3.1.3）。
- **Provider**：在 Kernel 三通道之外，尽力启用 **DNS-Client、PowerShell、Security-Auditing、WMI-Activity**；后四类若因权限或策略失败会**跳过**（内核三通道仍失败则整段启动失败）。
- **§19.10（AGT-001）**：`[collection]` 中 **`etw_tcpip_provider`**（默认 `true`）启用 **Microsoft-Windows-TCPIP**；**`etw_firewall_provider`**（默认 `true`）启用 **Windows Firewall With Advanced Security**。二者启用失败时**仅 stderr 提示并继续**（不导致 `edr_collector_start` 失败）。事件映射：`prov=tcpip`，事件 ID **1002** → `EDR_EVENT_NET_LISTEN`，其余常见 ID → `EDR_EVENT_NET_CONNECT`；`prov=wf` → `EDR_EVENT_FIREWALL_RULE_CHANGE`（MITRE 初标 **T1562.004**）。TDH 对 TCPIP/WF 补充常见属性名（如 `LocalPort` / `RuleName` 等），解析不到时仍可能回退 **UserData 原始字节**。
- **§19.10 → 攻击面联动**：上述 Provider 产生的事件在入总线时置 **`attack_surface_hint`**；预处理线程消费时调用 **`edr_attack_surface_etw_signal()`**；主循环在 **`[attack_surface].enabled=true`** 且 **`etw_refresh_triggers_snapshot=true`（默认）** 时，按 **`etw_refresh_debounce_s`（默认 8，范围 1～300 秒）** 去抖后执行 **`edr_attack_surface_execute("etw_tcpip_wf", …)`**（与周期快照、refresh-request 共用采集与 POST 路径）。关闭联动：将 `etw_refresh_triggers_snapshot` 设为 `false`。
- **优先级**：载荷中出现 `EncodedCommand` / `-Enc` 时置 `priority=0`（对齐 §4 高危特征初筛）；`tcpip` 连接类默认低优先级，`wf` 规则变更默认高优先级。

## 实现阶段建议

1. **核心**：事件总线背压策略（§2.3；**AGT-002 已关闭**：`event_bus.h` 说明当前为互斥环形队列，stderr 汇总 `bus_hw80`/`bus_dropped`）；配置加载（§11）已有 TOML 子集与运行时接入。
2. **采集**：Windows ETW Provider 表（§3.1.1）；Linux eBPF CO-RE 与降级（§3.2）。
3. **预处理 → 上报**：与 protobuf / gRPC 对齐 §6–§7（**Subscribe→指令分发**、队列策略与补传、RPC 退避已具备初版）。
4. **指令与自保护**：见下方「P1–P6 落地」；**P7 Linux 采集**仍排期在最后。

---

## 实现状态快照（相对设计文档）

| 模块 | 状态 |
|------|------|
| §6–§7 批次上报、gRPC、mTLS、Subscribe 重连、指令入口 | 已接通初版 |
| §10 队列 always/on_fail、补传、重试上限、库大小上限 | 已接通初版（Windows 下 MSVC 用 `_stat64` 检查库大小） |
| **P1 §8** | **深化**：`kill` / `isolate` / `forensic`（POSIX/Windows 路径与产物、**`EDR_FORENSIC_COPY_PATHS`**、**`EDR_CMD_AUDIT_PATH`**、**`EDR_ISOLATE_HOOK`**）；TOML **`[command] allow_dangerous`**；**`EDR_CMD_KILL_ALLOWLIST`**；**Windows** 下 **kill** 拒绝本进程；**`self_protect_status` / `agent_health` / `health_status`**。 |
| **P2 §9** | **深化**：**`SIGTERM` / `SIGINT`**、**`EDR_SELF_PROTECT_PIDFILE`**、**`EDR_SELF_PROTECT_WATCHDOG`**；**防调试**（`[self_protect] anti_debug`）、**事件总线背压**告警（`event_bus_pressure_warn_pct`）、可选 **Windows Job Object**（`job_object_windows`）、**`watchdog_log_interval_s`**、**`edr_self_protect_format_status`**。 |
| **P3 §12** | **初版**：`getrusage` 粗算 CPU%、RSS 与 `resource_limit` 比对；`cpu_limit<5%` 且未设 **`EDR_RESOURCE_STRICT=1`** 时不刷屏。**AGT-010**：**`edr_resource_preprocess_throttle_active()`** — 超限时预处理 **跳过低优先级**（`priority!=0`，且非 `attack_surface_hint`）；**Windows** 无 rusage 时可设 **`EDR_PREPROCESS_THROTTLE=1`** 联调。 |
| **P4 §5** | **深化**：模型目录统计 + **`edr_ave_file_fingerprint`**；**`edr_ave_infer_file`** 占位（未接 ONNX 时返回 **`EDR_ERR_NOT_IMPL`**；**`EDR_AVE_INFER_DRY_RUN=1`** 可走通联调）；**gRPC Subscribe** 指令类型 **`ave_status` / `ave_fingerprint` / `ave_infer`** 与 **`edr_command_bind_config`** 联动。 |
| **P5 §11.2** | **深化**：本地 mtime 热重载 + **`EDR_REMOTE_CONFIG_URL` / `EDR_REMOTE_CONFIG_POLL_S`** 心跳拉 TOML（依赖 **curl**）；指纹日志；**未**热更 gRPC 证书/批次参数。 |
| **P6** | **ctest**：`edr_agent --help`、**`ave_file_fingerprint`**、**`ave_infer_dry_run`**、**`config_fingerprint`**、**`shellcode_modules`**、**`edr_agent_smoke`**（`scripts/agent_smoke.sh` 启动进程后 SIGINT）；**`scripts/ci_build.sh`**、**`.github/workflows/edr-agent-ci.yml`**（**macOS / Ubuntu / Windows**）。 |
| §3 采集 | **Windows**：ETW 内核三通道 + TDH + 扩展 Provider（见上文「ETW 增强」）。**Linux**：**M1 inotify** 文件事件（`collector_linux.c`）；**进程/网络等 §3.2 级采集** 仍属 **P7（eBPF CO-RE）**。**其它 POSIX**：`collector_stub`。 |
| §1.2 API / IAT 监控层 | **本期 descope**（**`docs/AGT004_API_MONITOR_DESCope.md`**）；主路径为 **ETW → 总线 → 预处理**。 |
| Windows 服务 / 权限预检（§1.1 / §13） | **已关闭 AGT-006**（**`docs/WINDOWS_DEPLOY.md`**、**`deploy/README.md`**）；MSI/平台打包见 **edr-backend**。 |
| §7 连接保活 / 控制台「在线」 | **已关闭 AGT-007**：终端 **gRPC keepalive**（**`docs/SOAR_CONTRACT.md` §4.1**）；平台 **`T_offline` 与在线语义**（**§4.2**）；**落库与控制台 API** 在 **edr-backend**（**§4.2.3**）。 |
| §2.1 线程 / 主循环 | **已关闭 AGT-003**（**`docs/AGENT_THREAD_MODEL.md`**）。 |
| §12 资源 / 预处理降载 | **已关闭 AGT-010**（预处理 **`priority`** 降载 + **`resource.h`**）；**`README`** 本表 **P3 §12**。 |
| 取证 UploadFile E2E | **已关闭 AGT-009**（**`docs/AGT009_FORENSIC_UPLOAD_E2E.md`**；`forensic` bundle 上传续见 **WINDOWS_SHELLCODE_FORENSIC_TODO**）。 |
| §3.2 Linux P7 eBPF | **已关闭 AGT-012**（路线图 **`docs/AGT012_LINUX_EBPF_P7.md`**；**实现** 按 P7.x PR）。 |

---

## 后续排期（路线图）

| 阶段 | 内容 | 说明 |
|------|------|------|
| **深化 P1–P6** | 系统级网络隔离（nft 等）、更多测试用例 | **SOAR**：终端已实现 **`ReportCommandResult`** 调用（见 **`docs/SOAR_CONTRACT.md`** §5 **平台侧**）；远程配置见 **`EDR_REMOTE_CONFIG_*`** |
| **P7（末段）** | **§3.2 Linux 内核态采集** | 路线图：**`docs/AGT012_LINUX_EBPF_P7.md`**（**AGT-012** 已关闭文档交付；**探针代码** 按 P7.x PR）。当前 Linux 主路径仍为 **inotify M1**。 |

**原则**：**Linux 内核态采集（P7）最后投入**；其余在 `edr-agent/README.md` 与实现保持同步迭代。
