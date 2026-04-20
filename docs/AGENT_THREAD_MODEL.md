# Agent 线程模型与主循环（M2 冻结 / AGT-003）

**关联**：[CLIENT_IMPROVEMENT_TASKS.md §AGT-003](CLIENT_IMPROVEMENT_TASKS.md)、[Cauld Design/EDR_端点详细设计_v1.0.md](../../Cauld%20Design/EDR_端点详细设计_v1.0.md) §2.1  

本文冻结 **当前 edr-agent 实现** 中的线程与职责边界，便于评审与排障；**不**替代设计稿中的理想架构图，但标出与「主线程轮询即上报」等易混表述的差异。

---

## 1. 总览：三条主路径

| 路径 | 承担者 | 说明 |
|------|--------|------|
| **控制面循环** | **主线程** `edr_agent_run` | 约 **200ms** 睡眠周期：`resource`、`self_protect`、配置热重载/远程拉取、`attack_surface` 周期与 ETW 去抖触发等。 |
| **数据面：采集 → 预处理 → 批次** | **采集线程(们)** + **预处理线程** | 采集 **push** `EdrEventBus`；预处理 **pop** → 编码 → `event_batch` → **flush 时 `ReportEvents`**（与预处理**同线程**）。 |
| **指令面** | **gRPC `Subscribe` 独立线程** | 读 `CommandEnvelope` → `edr_command_on_envelope`；与主线程、预处理 **并发**。 |

**纠偏**：**批次 flush / `ReportEvents`** 在 **预处理线程** 触发，**不在**主线程。

---

## 2. 线程对照表（代码锚点）

| 线程 / 上下文 | 职责 | 主要文件 |
|---------------|------|----------|
| **主线程** | 控制面循环（见上） | `src/core/agent.c` |
| **预处理线程** | `event_bus` 消费 → BER1/protobuf → `event_batch` → `edr_transport_on_event_batch` → gRPC **`ReportEvents`**；`edr_storage_queue_poll_drain` | `src/preprocess/preprocess_pipeline.c`、`src/transport/event_batch.c`、`transport_stub.c` |
| **Windows ETW** | 单线程 `OpenTrace`/`ProcessTrace`，回调 **`edr_event_bus_try_push`** | `src/collector/collector_win.c` |
| **Linux inotify** | 监视目录，push 总线 | `src/collector/collector_linux.c` |
| **gRPC Subscribe** | `std::thread`，服务端流 | `src/transport/grpc_client_impl.cpp` |
| **PMFE** | 监听表轮询 + worker 池 | `src/pmfe/pmfe_engine.c` |
| **AVE 行为** | 可选 worker | `src/ave/ave_behavior_pipeline.c` |
| **Webshell / WinDivert** | 各模块独立监视/捕获线程 | `webshell_detector_*.c`、`windivert_capture.c` |
| **攻击面** | 主路径同步 + 部分 **临时** `pthread_create` 并行 | `src/attack_surface/attack_surface_report.c` |
| **联邦学习（可选）** | `fl_trainer` 协议 / 本地线程 | `src/fl_trainer/fl_trainer.c` |

---

## 3. 锁与并发

- **事件总线**：互斥环形队列；多生产者（采集、Shellcode、Webshell 等）、**单消费者**（预处理）。见 `src/core/event_bus.c`。
- **gRPC**：**同一 `Channel`** 上并发 **unary**（`ReportEvents`、`UploadFile` 等）与 **Subscribe 流**；指令回调避免长时间持锁与预处理路径交叉。见 `grpc_client_impl.cpp`。
- **SQLite 队列**：预处理线程内 `poll_drain`，与文档 §10 一致。

---

## 4. 与设计 §2.1 的关系

设计中的「上报 / Subscribe / watchdog 分离」在实现上已分为 **预处理线程（含上报）**、**Subscribe 线程**、**主线程（含自保护 watchdog 配置）**。若设计图仍画「独立上报线程」，请以 **本文** 为准标注 **M2 实现差异**。

---

**维护**：模块或线程模型变更时同步更新本文与 **README**「实现状态快照」交叉引用。
