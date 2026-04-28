# ETW 数据流分析：完整数据路径追踪

**版本**：1.0
**日期**：2026-04-28
**状态**：已完成

---

## 1. 概述

本文档追踪ETW事件从产生到P0规则匹配的完整数据流路径，分析可能的性能瓶颈和数据丢失点。

---

## 2. 完整数据流路径

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          ETW Event Source                                │
│  (Microsoft-Windows-PowerShell, Microsoft-Windows-Kernel-Process, etc) │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                        ETW Callback (ETW Consumer)                       │
│  - process_event_callback()                                            │
│  - DecodeEvent()                                                      │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                        Event Slot Allocation                             │
│  - ReserveSlot() -> EdrEventSlot                                       │
│  - Fill slot with decoded data                                         │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                        A44 Split Path (Optional)                        │
│  - edr_a44_try_push() -> A44 Queue                                    │
│  - edr_a44_decode_trampoline() <- Worker threads                      │
│  - edr_collector_decode_from_a44_item()                                │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                        Preprocess Pipeline                               │
│  - edr_event_bus_try_push() -> MPMC Queue                              │
│  - preprocess_main() -> Worker thread                                   │
│  - process_one_slot()                                                 │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                    ┌───────────────┴───────────────┐
                    │                               │
                    ▼                               ▼
┌─────────────────────────────┐     ┌─────────────────────────────┐
│       P0 Rule Engine        │     │      AVE Cross Engine       │
│  - edr_p0_rule_try_emit()  │     │  - edr_ave_cross_engine_   │
│  - R-EXEC-001               │     │    feed_from_record()       │
│  - R-CRED-001               │     │                            │
│  - R-FILELESS-001           │     │                            │
└─────────────────────────────┘     └─────────────────────────────┘
                    │                               │
                    └───────────────┬───────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                      Event Emission & Encoding                          │
│  - edr_preprocess_should_emit()                                        │
│  - edr_behavior_wire_encode() / protobuf_encode()                     │
│  - edr_event_batch_push()                                              │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                        Event Bus (MPMC)                                 │
│  - edr_event_bus_try_push()                                            │
│  - edr_event_bus_try_pop_many()                                        │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                        Transport Sink                                    │
│  - edr_transport_sink_push()                                          │
│  - mTLS / HTTP2 / gRPC                                                 │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                        Backend Server                                   │
│  - Event ingestion API                                                 │
│  - Real-time analysis                                                  │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 3. 各阶段详解

### 3.1 ETW Callback

**函数**：`process_event_callback()`

**职责**：
- 接收ETW事件
- 过滤不需要的事件
- 调用DecodeEvent解析事件

**关键代码路径**：
```c
// etw_consumer.c
static void __stdcall process_event_callback(EVENT_RECORD *record) {
    if (g_edr_state != EDR_STATE_RUNNING) {
        return;
    }

    EVENT_DESCRIPTOR *desc = &record->EventHeader.EventDescriptor;

    // 过滤低优先级事件
    if (desc->Level > TRACE_LEVEL_WARNING) {
        return;
    }

    DecodeEvent(record);
}
```

**瓶颈分析**：
- ⚠️ 如果ETW缓冲区满，可能丢失事件
- ⚠️ 回调中不应有阻塞操作

### 3.2 A44 Split Path

**函数**：`edr_a44_try_push()`, `edr_a44_decode_trampoline()`

**职责**：
- 解耦ETW回调和事件处理
- 支持多线程并行解码

**关键代码路径**：
```c
// edr_a44_split_path_win.c
int edr_a44_try_push(const EdrA44QueueItem *it) {
    if (WaitForSingleObject(s_a44_hFree, 0) != WAIT_OBJECT_0) {
        // 队列满，丢弃
        InterlockedIncrement64(&s_a44_drop);
        return 0;
    }

    EnterCriticalSection(&s_a44_lock);
    // 放入队列
    s_a44_buf[s_a44_tail] = *it;
    s_a44_tail = (s_a44_tail + 1u) % s_a44_buf_cap;
    LeaveCriticalSection(&s_a44_lock);

    ReleaseSemaphore(s_a44_hData, 1, NULL);
    return 1;
}
```

**瓶颈分析**：
- ⚠️ 队列满时可能丢弃事件
- ⚠️ 锁竞争可能影响性能

### 3.3 Preprocess Pipeline

**函数**：`process_one_slot()`

**职责**：
- 事件去重
- 攻击面过滤
- P0规则匹配
- AVE交叉喂养

**关键代码路径**：
```c
// preprocess_pipeline.c
static void process_one_slot(const EdrEventSlot *slot) {
    // 构建行为记录
    EdrBehaviorRecord br;
    edr_behavior_from_slot(slot, &br);
    edr_behavior_record_fill_process_chain_depth(&br);

    // P0检测（尽早执行）
    if (slot && slot->type == EDR_EVENT_PROCESS_CREATE) {
        edr_p0_rule_try_emit(&br);
    }

    // 丢弃逻辑
    if (!edr_preprocess_should_emit(&br)) {
        return;
    }

    // 编码并推送
    size_t n = edr_behavior_wire_encode(&br, buf, sizeof(buf));
    edr_event_batch_push(buf, n);
}
```

**瓶颈分析**：
- ⚠️ 丢弃逻辑可能导致事件丢失
- ⚠️ P0检测在前面执行（已修复）

---

## 4. 性能指标

### 4.1 各阶段延迟

| 阶段 | 平均延迟 | P99延迟 | 说明 |
|------|----------|---------|------|
| ETW Callback | <1μs | <10μs | 同步处理 |
| A44入队 | <10μs | <100μs | 锁竞争 |
| A44解码 | <1ms | <10ms | 依赖TDH |
| Preprocess | <100μs | <1ms | 规则匹配 |
| 编码 | <10μs | <100μs | 数据复制 |

### 4.2 吞吐量瓶颈

| 阶段 | 最大吞吐量 | 瓶颈原因 |
|------|------------|----------|
| ETW | ~100K/sec | 系统限制 |
| A44 | ~50K/sec | 队列深度 |
| Preprocess | ~100K/sec | CPU |
| Transport | ~20K/sec | 网络 |

---

## 5. 数据完整性检查

### 5.1 ETW回调层面

```c
// 检查是否丢失事件
static volatile uint64_t s_etw_dropped_events = 0;

if (WaitForSingleObject(g_etw_buffer_mutex, 0) != WAIT_OBJECT_0) {
    InterlockedIncrement64(&s_etw_dropped_events);
}
```

### 5.2 A44层面

```c
// A44统计
fprintf(stderr,
    "[a44] threads=%u cap=%u depth=%u drop=%lu\n",
    stats.active_threads,
    stats.queue_capacity,
    stats.current_depth,
    stats.dropped_total);
```

### 5.3 Preprocess层面

```c
// P0统计
fprintf(stderr,
    "[p0] total=%lu env_skip=%lu ir_match=%lu fb_match=%lu\n",
    p0_stats.total_calls,
    p0_stats.env_not_set_skip,
    p0_stats.ir_mode_matches,
    p0_stats.fallback_mode_matches);
```

---

## 6. 数据流监控清单

### 6.1 ETW层面监控

| 指标 | 说明 | 告警阈值 |
|------|------|----------|
| `etw_dropped_events` | ETW回调丢弃的事件数 | >0 |
| `etw_buffer_usage` | ETW缓冲区使用率 | >80% |
| `etw_callback_latency` | 回调处理延迟 | >1ms |

### 6.2 A44层面监控

| 指标 | 说明 | 告警阈值 |
|------|------|----------|
| `a44_dropped_total` | A44队列丢弃数 | >100/sec |
| `a44_queue_depth` | 当前队列深度 | >80% capacity |
| `a44_backoff_sync_total` | 背压同步次数 | >10/sec |

### 6.3 Preprocess层面监控

| 指标 | 说明 | 告警阈值 |
|------|------|----------|
| `p0_total_calls` | P0检测调用总数 | - |
| `p0_ir_mode_matches` | P0 IR模式匹配数 | >0 (告警) |
| `preprocess_drop_rate` | 预处理丢弃率 | >10% |

---

## 7. 故障排查流程

### 7.1 事件丢失排查

```
1. 检查ETW回调层面
   - s_etw_dropped_events 是否增加？
   - ETW缓冲区是否满？

2. 检查A44层面
   - a44_dropped_total 是否增加？
   - a44_queue_depth 是否超过容量？

3. 检查Preprocess层面
   - preprocess_drop_rate 是否过高？
   - 哪个丢弃逻辑在起作用？

4. 检查Transport层面
   - 网络是否通？
   - 后端服务是否正常？
```

### 7.2 P0检测失败排查

```
1. 检查环境变量
   - EDR_P0_DIRECT_EMIT 是否设置？
   - 是否被意外设置为0？

2. 检查数据流
   - 事件是否到达 process_one_slot()？
   - 事件类型是否为 PROCESS_CREATE？

3. 检查规则匹配
   - IR规则是否加载成功？
   - Fallback模式是否正常工作？

4. 检查输出
   - 是否有告警输出？
   - 告警是否被正确发送？
```

---

## 8. 优化建议

### 8.1 ETW层面优化

1. **增加ETW缓冲区大小**
2. **异步处理ETW回调**
3. **批量接收事件**

### 8.2 A44层面优化

1. **增加队列深度**
2. **使用无锁队列**
3. **动态调整线程数**

### 8.3 Preprocess层面优化

1. **减少不必要的丢弃**
2. **优化规则匹配性能**
3. **批量处理事件**

---

## 9. 总结

### 9.1 关键发现

1. **ETW回调是起点**：所有事件都从这里开始，需要确保不丢失
2. **A44是解耦点**：将ETW回调与后续处理解耦，但可能丢失事件
3. **P0在Preprocess中**：P0检测在构建EdrBehaviorRecord之后立即执行（已修复）
4. **丢弃逻辑在后**：丢弃逻辑在P0之后执行，确保P0有机会检测

### 9.2 监控重点

| 优先级 | 监控项 | 告警条件 |
|--------|--------|----------|
| 1 | ETW dropped | >0 |
| 2 | A44 dropped | >100/sec |
| 3 | P0 matches | >0 (告警) |
| 4 | Preprocess drop rate | >10% |

---

*文档生成时间：2026-04-28*