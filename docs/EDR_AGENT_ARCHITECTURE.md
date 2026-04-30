# EDR Agent 系统架构全景

## 一、总体架构

```
┌────────────────────────────────────────────────────────────────────────────┐
│                               edr_agent.exe 进程                           │
│                                                                            │
│  ┌─────────────────────────────────────────────────────────────────────┐  │
│  │                         main.c (入口)                                │  │
│  │  edr_agent_create → edr_agent_init → edr_agent_run → ... → destroy  │  │
│  └─────────────────────────────────────────────────────────────────────┘  │
│                                    │                                       │
│  ┌─────────────────────────────────┴───────────────────────────────────┐  │
│  │                    agent.c (核心生命周期)                            │  │
│  │  · 初始化各模块  · 主循环 (200ms tick)  · 配置热重载  · 心跳输出     │  │
│  └───────┬───────────────────────────────────────────────┬─────────────┘  │
│          │                                               │                │
│    采集层 (L1)                                    预处理层 (L2)           │
│  ┌───────┴──────────┐                         ┌────────┴──────────┐      │
│  │ collector_win.c  │  ETW 实时会话            │ preprocess_       │      │
│  │ collector_linux.c│  inotify/eBPF(规划)      │ pipeline.c        │      │
│  │ collector_stub.c │  其他POSIX stub          │ (独立线程)        │      │
│  │                  │                         │                   │      │
│  │ etw_tdh_win.c    │  TDH属性提取→ETW1文本    │ dedup.c           │      │
│  │ etw_observability│  可观测性统计            │ emit_rules.c      │      │
│  │ _win.c           │                         │ behavior_from_    │      │
│  │ ave_etw_feed_    │  ETW→AVE 事件喂入        │ slot.c            │      │
│  │ win.c            │                         │ p0_rule_direct_   │      │
│  │ edr_a44_split_   │  A4.4 解线程分流         │ emit.c            │      │
│  │ path_win.c       │                         │ p0_rule_ir.c      │      │
│  └───────┬──────────┘                         │ p0_rule_match.c   │      │
│          │                                    └────────┬──────────┘      │
│          │ EdrEventSlot (4096B)                          │                 │
│          ▼                                               │                 │
│  ┌──────────────────────────────────────────┐            │                 │
│  │         event_bus.c (MPMC 无锁环)         │◄───────────┘                 │
│  │   capacity: max_event_queue_size (4096)   │                              │
│  │   双总线模式: EDR_DUAL_BUS_ENABLED        │                              │
│  │   · 高优先级总线                          │                              │
│  │   · 低优先级总线                          │     序列化层 (L2)             │
│  └──────────────────────────────────────────┘  ┌─────────────────┐          │
│                                                │ behavior_wire.c  │          │
│   AVE 引擎层 (L3)                               │ behavior_proto.c │          │
│  ┌──────────────────────────────┐              │ behavior_alert_  │          │
│  │ ave_behavior_pipeline.c     │  MPMC入队    │ emit.c           │          │
│  │  (独立线程)                  │  单消费线程   └────────┬────────┘          │
│  │ · PID 状态维护 (512 slots)   │                       │                   │
│  │ · 特征提取 (64维)            │                       │                   │
│  │ · ONNX 推理 → 行为告警      │                       ▼                   │
│  │ ave_engine.c / ave_onnx_    │              ┌─────────────────┐          │
│  │ infer.c                     │              │ event_batch.c   │          │
│  │ ave_sdk.c / ave_suppression │              │ 批次累积/LZ4压缩 │          │
│  │ ave_cross_engine_feed.c     │              └────────┬────────┘          │
│  └──────────────────────────────┘                       │                   │
│                                                         ▼                   │
│  专项引擎层                                         传输层 (L4)             │
│  ┌──────────────────────────┐              ┌─────────────────────────┐     │
│  │ shellcode_detector_win.c │              │ transport_stub.c        │     │
│  │  (WinDivert 协议层检测)   │              │  · 异步发送队列 (256)    │     │
│  ├──────────────────────────┤              │  · 工作线程              │     │
│  │ webshell_detector_win/   │              │  · gRPC ReportEvents    │     │
│  │ linux.c                  │              │  · HTTP POST fallback   │     │
│  │  (inotify 目录监控)      │              └────────┬────────────────┘     │
│  ├──────────────────────────┤                       │                      │
│  │ pmfe_engine.c            │                       ▼                      │
│  │  (进程内存取证)           │              ┌─────────────────────────┐     │
│  └──────────────────────────┘              │ queue_sqlite.c          │     │
│                                            │  · 离线持久化            │     │
│  辅助模块                                   │  · 指数退避重试          │     │
│  ┌──────────────────────────┐              │  · WAL模式 (已启用)      │     │
│  │ config.c (TOML解析)      │              │  · 按severity自动裁剪    │     │
│  │ resource.c (资源限制)     │              └─────────────────────────┘     │
│  │ self_protect.c (自保护)  │                                                │
│  │ command_stub.c (高危指令)│                                                │
│  │ attack_surface_report.c  │                      ┌──────────────┐         │
│  │ fl_trainer (联邦学习)    │                      │ 平台 Ingest  │         │
│  └──────────────────────────┘                      │ gRPC / HTTP  │         │
│                                                    └──────────────┘         │
└────────────────────────────────────────────────────────────────────────────┘
```

---

## 二、数据总线 (Event Bus)

### 2.1 物理结构

位于 `src/core/event_bus.c`：无锁 MPMC 环形缓冲区（LMAX/Disruptor 风格）。

```c
struct EdrEventBus {
  EdrEventBusCell *cells;    // 环形槽数组
  uint32_t cap;              // 容量 (默认4096, 可配 max_event_queue_size)
  _Atomic uint64_t head;     // 入队位标 (生产者共享)
  _Atomic uint64_t tail;     // 出队位标 (消费者共享)
  _Atomic uint64_t dropped;  // 丢弃计数
  _Atomic uint64_t pushed;   // 入队计数
  _Atomic uint64_t high_water_hits;  // 高水位命中 (≥80%)
};

struct EdrEventBusCell {
  _Alignas(64) _Atomic uint64_t turn;  // 世代号 (防ABA)
  EdrEventSlot data;                   // 4096+32B 事件槽
};
```

**核心机制**：
- `turn` 世代号：每槽 `lap*2`(可写) → `lap*2+1`(可读) → `lap*2+2`(可写)... 循环
- 每槽 64 字节对齐 (`_Alignas(64)`)，防 CPU 伪共享
- `try_push` 满时直接返回 false，递增 `dropped` 计数（不阻塞）
- `try_pop_many` 每次最多取 32 条

### 2.2 双总线优先级 (可选)

通过 `EDR_DUAL_BUS_ENABLED=1` 启用：

```
高优先级总线 ──── 入站: PROCESS_INJECT, THREAD_CREATE_REMOTE,
                         PROTOCOL_SHELLCODE, WEBSHELL_DETECTED,
                         FIREWALL_RULE_CHANGE, priority==0 事件

低优先级总线 ──── 入站: 所有其他事件 (FILE_WRITE, REG_SET_VALUE...)
```

双总线模式下，预处理线程优先消费高优先级总线。

### 2.3 接口一览

| 函数 | 说明 |
|------|------|
| `edr_event_bus_create(slot_count)` | 创建总线 |
| `edr_event_bus_try_push(bus, slot)` | 非阻塞推 (生产者) |
| `edr_event_bus_try_pop_many(bus, slots, max)` | 批量弹出 (消费者，最多32条) |
| `edr_event_bus_capacity(bus)` | 总容量 |
| `edr_event_bus_used_approx(bus)` | 近似占用 (用于L3高压判断) |
| `edr_event_bus_dropped_total(bus)` | 丢弃总数 |
| `edr_event_bus_high_water_hits(bus)` | 80%高水位命中次数 |

---

## 三、事件类型全集 (EdrEventType)

定义于 `include/edr/types.h`。

### 进程类 (1-5, 62)

| 值 | 枚举 | ETW 来源 | 说明 |
|:---:|------|------|------|
| 1 | `PROCESS_CREATE` | KP op=1, SEC 4688 | 进程创建 |
| 2 | `PROCESS_TERMINATE` | KP op=2 | 进程终止 |
| 3 | `PROCESS_INJECT` | — | 进程注入 |
| 4 | `DLL_LOAD` | KP op=3-5,32-36 | DLL/模块加载 |
| 5 | `THREAD_CREATE_REMOTE` | — | 远程线程创建 |
| 62 | `DRIVER_LOAD` | — | 驱动加载 |

### 文件类 (6, 10-14)

| 值 | 枚举 | ETW 来源 |
|:---:|------|------|
| 6 | `FILE_READ` | KF op=15 |
| 10 | `FILE_CREATE` | KF op=12 |
| 11 | `FILE_WRITE` | KF op=14 |
| 12 | `FILE_DELETE` | KF op=16 |
| 13 | `FILE_RENAME` | — |
| 14 | `FILE_PERMISSION_CHANGE` | — |

### 网络类 (20-23)

| 值 | 枚举 | ETW 来源 |
|:---:|------|------|
| 20 | `NET_CONNECT` | KN (默认), TCPIP≠1002 |
| 21 | `NET_LISTEN` | TCPIP 1002 |
| 22 | `NET_DNS_QUERY` | KN op=15, DNS Client |
| 23 | `NET_TLS_HANDSHAKE` | — |

### 注册表类 (30-32)

| 值 | 枚举 | ETW 来源 |
|:---:|------|------|
| 30 | `REG_CREATE_KEY` | KR op=1,2 |
| 31 | `REG_SET_VALUE` | KR op=6 |
| 32 | `REG_DELETE_KEY` | KR op=3,7 |

### 脚本类 (40-43)

| 值 | 枚举 | ETW 来源 |
|:---:|------|------|
| 40 | `SCRIPT_POWERSHELL` | PowerShell Provider |
| 43 | `SCRIPT_WMI` | WMI Activity |

### 认证类 (50-53)

| 值 | 枚举 | ETW 来源 |
|:---:|------|------|
| 50 | `AUTH_LOGIN` | SEC 4624 |
| 52 | `AUTH_FAILED` | — |
| 53 | `AUTH_PRIVILEGE_ESC` | — |

### 安全事件类 (60-61, 63-66, 70)

| 值 | 枚举 | 来源 |
|:---:|------|------|
| 60 | `SERVICE_CREATE` | — |
| 61 | `SCHEDULED_TASK_CREATE` | — |
| 63 | `PROTOCOL_SHELLCODE` | WinDivert |
| 64 | `WEBSHELL_DETECTED` | inotify + YARA |
| 65 | `FIREWALL_RULE_CHANGE` | WFAS ETW |
| 66 | `PMFE_SCAN_RESULT` | 进程内存取证 |
| 70 | `BEHAVIOR_ONNX_ALERT` | AVE behavior.onnx |

---

## 四、采集层 (Collector)

### 4.1 Windows ETW 采集

位于 `src/collector/collector_win.c` + `src/collector/etw_tdh_win.c`。

```
ETW 内核事件
    │
    ▼
EventRecordCallback()
    ├─ edr_map_type_and_tag()     → EdrEventType + tag 字符串
    │   ├─ Kernel-Process (kp)     op1=CREATE op2=TERM op3-5=DLL_LOAD op32-36=DLL_LOAD
    │   ├─ Kernel-File (kf)        op12=FCREATE op14=FWRITE op15=FREAD op16=FDELETE
    │   ├─ Kernel-Network (kn)     op15=DNS 其他=NET_CONNECT
    │   ├─ Kernel-Registry (kr)    op1-2=CREATE op3,7=DELETE op6=SET_VALUE
    │   ├─ DNS-Client (dns)        → NET_DNS_QUERY
    │   ├─ PowerShell (ps)         → SCRIPT_POWERSHELL
    │   ├─ Security-Audit (sec)    4624=AUTH_LOGIN 4688=PROCESS_CREATE
    │   ├─ WMI-Activity (wmi)      → SCRIPT_WMI
    │   ├─ TCPIP (tcpip)          1002=NET_LISTEN 其他=NET_CONNECT
    │   └─ WFAS (wf)              → FIREWALL_RULE_CHANGE
    │
    ├─ [A4.4分流] → edr_a44_try_push() → 解码线程 → edr_collector_tdh_to_bus()
    │   └─ 满队 → 同线程回退
    │
    └─ edr_collector_tdh_to_bus()
        ├─ edr_ave_etw_feed_from_event()   → AVE 行为管线 (A3分频/异步可选)
        ├─ edr_tdh_build_slot_payload()    → TDH属性提取 → ETW1\n文本
        │   ├─ proc_try[]: ImageFileName→img, CommandLine→cmd, ParentProcessId→ppid...
        │   ├─ file_try[]: FileName→file...
        │   ├─ net_try[]: daddr→dst, dport→dpt...
        │   ├─ reg_try[]:  KeyName→reg, ValueName→regname...
        │   ├─ sec_try[]:  NewProcessName→img, CommandLine→cmd...
        │   └─ ... (DNS/PS/WMI/TCPIP/WFAS 各有专用 try 表)
        └─ edr_event_bus_try_push()        → 入总线
```

**关键配置**：

| 配置项 | 说明 | 默认值 |
|--------|------|:---:|
| `etw_enabled` | 总开关 | true |
| `etw_dns_client_provider` | DNS Client | **false**(已优化) |
| `etw_wmi_provider` | WMI Activity | **false**(已优化) |
| `etw_tcpip_provider` | TCPIP | **false**(已优化) |
| `etw_firewall_provider` | WFAS防火墙 | **false**(已优化) |
| `etw_powershell_provider` | PowerShell | true |
| `etw_security_audit_provider` | Security Audit | true |
| `etw_buffer_kb` | ETW 缓冲KB | 64 |
| `etw_flush_timer_s` | 刷新间隔(秒) | **3**(已优化) |
| `max_event_queue_size` | 总线容量 | 4096 |

### 4.2 Linux 采集

位于 `src/collector/collector_linux.c`：inotify 文件系统监控（非 Windows 平台另有 stub 实现）。

---

## 五、预处理管线 (Preprocess)

### 5.1 处理流程

位于 `src/preprocess/preprocess_pipeline.c`：**独立线程**，批量从总线取槽 (每次最多32条)，逐条处理。

```
edr_event_bus_try_pop_many()  →  32 条 EdrEventSlot
                                    │
    ┌───────────────────────────────┘
    │  [1] edr_behavior_from_slot()   ETW1文本 → EdrBehaviorRecord
    │       · etw1_parse() 解析 key=value 行
    │       · img= → exe_path + process_name
    │       · cmd= → cmdline
    │       · file= → file_path
    │       · reg= → reg_key_path 等
    │
    ├─ [2] 丢弃非exe进程名 (process_name_looks_like_exe)
    │
    ├─ [3] 空事件过滤 (behavior_record_has_meaningful_data)
    │       · PROCESS_TERMINATE 无数据 → 跳过
    │       · NET_CONNECT/LISTEN  无数据 → 跳过
    │       · SCRIPT 无脚本内容    → 跳过
    │       · PROCESS_CREATE 无进程名 → 跳过
    │
    ├─ [4] P0 规则检测 (slot_is_p0_eligible)
    │       · edr_p0_rule_try_emit()    IR 模式: 80条JSON规则
    │       · 命中 → emit_for_rule() → 去重/限流 → Alert 入批次
    │
    ├─ [5] 进程名门控 (procname_gate)
    │       · 仅 hot 进程 (powershell/cmd/certutil...) 全量保留
    │       · 其他进程: 千分比随机保留
    │       · 扩展到 FILE_WRITE/REG_SET 等所有类型
    │
    ├─ [6] L2 未命中规则抽样
    │       · 命中 emit 规则 → 全留
    │       · 未命中 → KEEP_RATIO 比例保留
    │
    ├─ [7] L3 总线高压丢弃
    │       · bus_used ≥ HIGH_PCT → 低价值事件丢 DROP_PERMILLE
    │
    ├─ [8] edr_preprocess_should_emit()
    │       · priority==0 → 直接通过 (高优先级)
    │       · 规则评估 (drop规则 → 丢弃)
    │       · 去重 (FNV-1a指纹, 8192槽, 90s窗口)
    │       · 限流 (512槽, 30/秒/PID)
    │
    ├─ [9] 序列化
    │       · EDR_BEHAVIOR_ENCODING=protobuf  → nanopb编码
    │       · 默认                          → behavior_wire编码
    │
    └─ [10] edr_event_batch_push()  → 入批次缓冲区
```

### 5.2 降载三防体系

| 层级 | 机制 | 环境变量 | 效果 |
|:---:|------|------|------|
| **L1** | 进程名门控 | `EDR_PREPROCESS_PROCNAME_GATE=1` | 仅保留白名单进程事件，-90% |
| **L2** | 未命中规则抽样 | `EDR_PREPROCESS_L2_SPLIT=1` | 未命中规则仅保留 KEEP_RATIO，-97% |
| **L3** | 总线高压丢弃 | `EDR_PREPROCESS_L3_PRESSURE=1` | bus≥80%时丢低价值事件 |

### 5.3 接入模块

| 模块 | 函数 | 说明 |
|------|------|------|
| 去重 | `edr_dedup_configure / edr_preprocess_should_emit` | FNV-1a指纹, 8192槽, 90s窗口 |
| 限流 | `rate_allow` | 512槽, 30/秒/PID |
| 规则评估 | `edr_emit_rules_evaluate` | TOML 配置 drop/emit 规则 |
| P0 直出 | `edr_p0_rule_try_emit → emit_for_rule` | 80条IR规则 → Alert 直接入批次 |
| AVE 跨引擎喂入 | `edr_ave_cross_engine_feed_from_record` | Shellcode/Webshell/PMFE → AVE 行为槽 |
| PMFE | `edr_pmfe_on_preprocess_slot` | 进程内存取证联动 |
| 进程链深度 | `edr_behavior_record_fill_process_chain_depth` | 父链跳数 |

---

## 六、AVE 引擎层

### 6.1 行为管线

位于 `src/ave/ave_behavior_pipeline.c`：

```
ETW回调 → AVE_FeedEvent()
              │
    ┌─────────┴──────────┐
    │ A3分频: EVERY_N=4   │  仅 1/N 事件喂入
    │ A3.2异步: 入队+线程  │  队列满时回退同步
    └─────────┬──────────┘
              ▼
    ave_mpmc_try_push()  → MPMC环形队列 (4096槽)
              │
              ▼
    worker_main (独立线程)
      ├─ PID查找/创建 (512槽, 线性探测 → LRU淘汰)
      ├─ 进程退出300s后GC
      ├─ 父进程链深度追踪
      ├─ 特征提取 (64维浮点, 含进程快照+事件属性)
      ├─ ONNX 推理
      │   ├─ 立即触发: PROCESS_INJECT/LSASS_ACCESS/SHELLCODE等
      │   ├─ 自适应步长: 16 → 低分动态2x步长, 高分紧缩步长
      │   ├─ 序列填充: 128步×64维 → ORT输入
      │   └─ 指数平滑: anomaly = 0.35*old + 0.65*new
      ├─ 无ONNX时: 启发式 bump (severity_hint + behavior_flags)
      └─ anomaly ≥ THRESH(0.70) → 触发告警
           ├─ edr_behavior_alert_emit_to_batch()  ← 先入批次
           └─ cb(&al, ud)                          ← 回调 (当前空实现)
```

**关键配置**：

| 环境变量 | 说明 | 推荐值 |
|------|------|:---:|
| `EDR_AVE_ETW_FEED_EVERY_N` | AVE 分频 | **4** |
| `EDR_AVE_ETW_ASYNC` | 异步喂入 | 1 |
| `EDR_AVE_ETW_FEED` | 完全关闭 | 0 (仅非交互场景) |
| `EDR_AVE_BEH_SCORE_HIGH` | 告警阈值 | 0.70 |

### 6.2 静态引擎

位于 `src/ave/ave_engine.c` + `src/ave/ave_onnx_infer.c`：

- 文件 SHA256 → 静态 ONNX 推理 → 判定 (MALICIOUS/SUSPICIOUS/CLEAN)
- 结果缓存 (LRU + TTL)
- L1: 证书验证 (Windows Authenticode)
- L2: 哈希白名单 (SQLite)
- L3: IOC 检测 (SQLite)
- L4: 行为联动 (ONNX行为分≥阈值 → 叠加L4)

### 6.3 AVE SDK 层

位于 `src/ave/ave_sdk.c`：

| 函数 | 说明 |
|------|------|
| `AVE_InitFromEdrConfig` | 从配置初始化 |
| `AVE_RegisterCallbacks` | 注册行为告警回调 |
| `AVE_StartBehaviorMonitor` | 启动行为管线 (需 `on_behavior_alert` 非空) |
| `AVE_FeedEvent` | 喂入行为事件 |
| `AVE_NotifyProcessExit` | 进程退出通知 |
| `AVE_ScanFileWithSubject` | 静态文件扫描 |
| `AVE_SyncFromEdrConfig` | 热重载模型 |
| `AVE_GetStatus` | 获取运行状态统计 |

---

## 七、序列化与传输层

### 7.1 事件批次

位于 `src/transport/event_batch.c`：

```
edr_event_batch_push(frame)
    │
    ├─ append_frame()  → 4B LE长度 + payload → 批次缓冲区
    │
    ├─ 触发 flush:
    │   ├─ 批次数 ≥ batch_max_events (200)
    │   ├─ 总大小 ≥ batch_max_size_mb (2MB)
    │   └─ 超时 ≥ batch_timeout_s (2s)
    │
    └─ flush_locked()
        ├─ [可选] ingest_split: frame_prefers_grpc_path() → pb_decode 检测 behavior_alert字段
        │   ├─ BehaviorAlert → gRPC 通道
        │   └─ 其他 → HTTP 通道
        │
        ├─ [可选] LZ4压缩 (≥1024B, 级别可配 EDR_LZ4_COMPRESSION_LEVEL)
        │
        └─ edr_transport_send_ingest_batch()
            └─ transport_queue → 异步发送线程
```

### 7.2 传输队列

位于 `src/transport/transport_stub.c`：

```
┌───────────────────────────┐
│  异步发送队列 (默认256槽)  │
│  · 生产: push batch       │
│  · 消费: 工作线程 pop     │
└───────────────────────────┘
              │
    ┌─────────┴──────────┐
    │ 发送路径             │
    │ · gRPC 就绪 → gRPC  │
    │ · gRPC 未就绪 → HTTP│
    │ · gRPC 失败 → HTTP  │
    │   fallback           │
    └─────────┬──────────┘
              │
              ▼ 失败
    ┌───────────────────┐
    │ SQLite 离线队列    │
    │ · batch_id UNIQUE  │
    │ · 指数退避重试      │
    │ · 最大重试:100次    │
    │ · 按severity裁剪   │
    └───────────────────┘
```

---

## 八、专项检测引擎

### 8.1 Shellcode 检测

位置：`src/shellcode_detector/`

| 文件 | 功能 |
|------|------|
| `shellcode_detector_win.c` | Windows WinDivert 入口 |
| `windivert_capture.c` | 网络包捕获 |
| `proto_parse.c` | SMB/RDP/HTTP 协议解析 |
| `shellcode_entropy.c` | 熵分析 |
| `shellcode_heuristic.c` | 启发式检测 |
| `shellcode_known.c` | 已知漏洞规则 (YARA) |

### 8.2 Webshell 检测

位置：`src/webshell_detector/`

| 文件 | 功能 |
|------|------|
| `webshell_detector_linux.c` | Linux inotify 监控 |
| `webshell_detector_win.c` | Windows IIS 目录监控 |
| `webshell_forensic.c` | 取证文件上传 |
| `rules/*.yar` | YARA 规则库 |

### 8.3 PMFE (进程内存取证)

位置：`src/pmfe/`

| 文件 | 功能 |
|------|------|
| `pmfe_engine.c` | 内存扫描引擎 |
| `pmfe_etw_preprocess.c` | ETW 事件预处理 |
| `pid_history_pmfe.c` | PID 历史 |

---

## 九、辅助模块

### 9.1 配置管理

位于 `src/config/config.c`：tomlc99 TOML 解析，支持：
- `edr_config_load(path)` — 首次加载
- `edr_config_reload_if_modified(path, mtime, out_reloaded)` — 热重载 (mtime 检测)
- `EDR_CONFIG_RELOAD_S` 定时热重载
- `EDR_REMOTE_CONFIG_URL` + `EDR_REMOTE_CONFIG_POLL_S` 远程拉取

### 9.2 资源限制

位于 `src/resource/resource.c`：POSIX `getrusage` CPU/RSS 监控，超限时设置预处理节流标志。

### 9.3 自保护

位于 `src/self_protect/self_protect.c`：防调试、总线背压告警、可选 Windows Job Object。

### 9.4 命令执行

位置：`src/command/` — 处理平台下发的 kill / isolate / forensic 高危指令。

### 9.5 攻击面报告

位置：`src/attack_surface/` — 采集监听端口、出站连接、服务、防火墙规则，通过 curl HTTP POST 上报。

---

## 十、完整数据流路径速查

```
┌──────────────────────┐
│ 1. ETW 内核事件        │  Windows ETW 实时会话
│    (Kernel-* + 可选    │  Linux inotify
│     Provider)         │
└────────┬─────────────┘
         │ EventRecordCallback()
         │ edr_map_type_and_tag()  → EdrEventType + tag
         │   未知 opcode/eventid  → 直接跳过
         ▼
┌──────────────────────┐
│ 2. TDH 属性提取        │  edr_tdh_build_slot_payload()
│    按 Provider 分发:   │    → ETW1\n文本 (img=/cmd=/file=...)
│    proc/file/net/reg/  │
│    dns/ps/sec/wmi/tcpip│
└────────┬─────────────┘
         │ edr_event_bus_try_push()
         ▼
┌──────────────────────┐
│ 3. 事件总线 (MPMC)     │  4096 槽, 无锁环
│    · try_push 满→丢    │  etw_obs 可观测
│    · high_water ≥80%   │
└────────┬─────────────┘
         │ 预处理线程 try_pop_many(32)
         ▼
┌──────────────────────┐
│ 4. 预处理管线          │  process_one_slot()
│    · ETW1→BehaviorRec │  behavior_from_slot.c
│    · 非exe进程 → 跳过  │
│    · 空事件 → 跳过      │
│    · P0 规则 → Alert   │  p0_rule_direct_emit.c (80条IR规则)
│    · 进程名门控 → 抽样  │
│    · L2/L3 降载        │
│    · 去重/限流         │  dedup.c (90s窗, 30/秒/PID)
│    · wire/proto 编码   │  behavior_wire.c / behavior_proto.c
└────────┬─────────────┘
         │ edr_event_batch_push()
         ▼
┌──────────────────────┐
│ 5. 事件批次            │  event_batch.c
│    · 累积帧             │  4B LE长度 + payload
│    · LZ4 压缩 (>=1024B) │
│    · 200帧/2MB/2s 触发  │
│    · ingest_split       │  BehaviorAlert→gRPC, 其他→HTTP
└────────┬─────────────┘
         │ 同步
┌──────────────────────┐     ┌──────────────────┐
│ 6. 异步发送队列 (256) │ ──→ │ gRPC ReportEvents │
│    工作线程            │     │ 失败→HTTP fallback│
│    满→SQLite离线      │     │ SQLite queue_sqlite│
└──────────────────────┘     └──────────────────┘
                                      │
                                      ▼
                              ┌──────────────┐
                              │ 平台 Ingest   │
                              │ alerts /      │
                              │ endpoint_     │
                              │ events 表     │
                              └──────────────┘
```

---

## 十一、源码模块划分

| 模块 | 路径 | 说明 |
|------|------|------|
| 入口 | `src/main.c` | 主函数 |
| 核心框架 | `src/core/` | agent.c, edr_log.c, event_bus.c, time_util.c |
| 配置 | `src/config/` | config.c (tomlc99 TOML 解析) |
| 预处理 | `src/preprocess/` | pipeline, dedup, emit_rules, p0_rule_*, behavior_from_slot |
| 序列化 | `src/serialize/` | behavior_wire.c, behavior_proto.c, behavior_alert_emit.c |
| Protobuf | `src/proto/` + `third_party/nanopb/` | event.pb.c, pb_encode/decode |
| 传输 | `src/transport/` | event_batch.c, ingest_http.c, transport_stub.c, grpc_client |
| 存储 | `src/storage/` | queue_sqlite.c (离线队列) |
| 指令 | `src/command/` | command_stub.c, sha256.c |
| PMFE | `src/pmfe/` | pmfe_engine.c, pid_history_pmfe.c |
| 攻击面 | `src/attack_surface/` | attack_surface_report.c, security_policy_collect.c |
| 自保护 | `src/self_protect/` | self_protect.c |
| 资源限制 | `src/resource/` | resource.c |
| AVE 引擎 | `src/ave/` | behavior_pipeline, onnx_infer, sdk, cross_engine_feed, suppression |
| Shellcode | `src/shellcode_detector/` | windivert_capture, proto_parse, entropy, heuristic, known |
| Webshell | `src/webshell_detector/` | webshell_detector_*, forensic, YARA rules |
| FL 训练 | `src/fl_trainer/` | fl_trainer, fl_round, fl_crypto, fl_dp, local_train |
| 采集层 | `src/collector/` | collector_win/linux/stub, etw_tdh_win, etw_observability_win, ave_etw_feed_win |

---

## 十二、第三方依赖

| 依赖 | 用途 | 条件编译宏 |
|------|------|------|
| gRPC++ | 平台通信 | `EDR_HAVE_GRPC=1` (`EDR_WITH_GRPC`) |
| ONNX Runtime | ML推理 | `EDR_HAVE_ONNXRUNTIME=1` (`EDR_WITH_ONNXRUNTIME`) |
| LibTorch | FL训练 | `EDR_HAVE_LIBTORCH=1` (`EDR_WITH_LIBTORCH`) |
| libyara | 规则匹配 | `EDR_HAVE_YARA=1` (`EDR_WITH_YARA`) |
| libcurl | HTTP通信 | `EDR_HAVE_LIBCURL=1` (auto) |
| SQLite3 | 离线队列+白名单 | `EDR_HAVE_SQLITE=1` (auto) |
| LZ4 | 批次压缩 | `EDR_HAVE_LZ4=1` (bundled) |
| PCRE2 | P0 IR正则 | `EDR_HAVE_PCRE2=1` (auto) |
| librdkafka | FL Kafka | `EDR_WITH_FL_KAFKA` |
| nanopb | Protobuf序列化 | `EDR_HAVE_NANOPB` (bundled) |
