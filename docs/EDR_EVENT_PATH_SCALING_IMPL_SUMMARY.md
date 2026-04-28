# EDR Agent 事件路径扩展性实现总结

**版本**：6.0
**日期**：2026-04-28
**状态**：已完成

---

## 1. 概述

本文档记录了EDR Agent事件路径扩展性方案的实现细节，包括短期方案（C1、C2）和中期方案（D1、B1）以及后续优化（v2.0、v3.0、v4.0）的代码修改和配置说明。

---

## 2. 已完成的修改

### 2.1 短期C1：A4.4线程池化

#### 2.1.1 修改文件

| 文件 | 修改类型 | 说明 |
|------|----------|------|
| `include/edr/edr_a44_split_path_win.h` | 修改 | 新增`EdrA44Stats`结构体和`edr_a44_get_stats()`接口 |
| `src/collector/edr_a44_split_path_win.c` | 重写 | 实现多线程解码池（1-4线程可配置） |

#### 2.1.2 新增配置项

| 环境变量 | 默认值 | 范围 | 说明 |
|----------|--------|------|------|
| `EDR_A44_DECODE_THREADS` | 1 | 1-4 | 解码线程池大小 |
| `EDR_A44_QUEUE_CAP` | 512 | 128-2048 | 队列容量 |

#### 2.1.3 新增统计指标

```c
typedef struct {
    uint64_t dropped_total;          // 队列满导致的丢弃总数
    uint64_t backoff_sync_total;    // 回退到同步解码的次数
    double queue_depth_avg;          // 平均队列深度
    uint32_t queue_depth_max;       // 最大队列深度
    uint64_t thread_busy_time[4];   // 各线程忙碌时间
    uint32_t active_threads;        // 当前活跃线程数
    uint64_t total_processed;       // 总处理数量
    uint64_t total_pushed;          // 总入队数量
    uint32_t queue_capacity;        // 队列容量
    uint32_t current_depth;         // 当前队列深度
} EdrA44Stats;
```

#### 2.1.4 架构图

```
ETW回调 → A44有界队列 → [线程1] → TDH解析 → 总线push
                        → [线程2] → TDH解析 → 总线push
                        → [线程3] → TDH解析 → 总线push
                        → [线程4] → TDH解析 → 总线push
```

### 2.2 短期C2：完善A44统计指标

#### 2.2.1 修改文件

| 文件 | 修改类型 | 说明 |
|------|----------|------|
| `include/edr/edr_a44_split_path_win.h` | 修改 | 新增`edr_a44_get_stats()`和`edr_a44_get_drop_reason_stats()`接口 |
| `src/collector/edr_a44_split_path_win.c` | 修改 | 实现统计收集逻辑 |
| `src/core/agent.c` | 修改 | 在heartbeat中输出A44统计 |

#### 2.2.2 Heartbeat输出示例

```
[a44] threads=2 cap=512 depth=128 avg=85.30 drop=0 backoff=0
```

---

### 2.3 中期D1：可配置EventId过滤

#### 2.3.1 修改文件

| 文件 | 修改类型 | 说明 |
|------|----------|------|
| `include/edr/collector.h` | 修改 | 新增`EdrEventIdFilter`和`EdrCollectorEventFilterConfig`结构体 |
| `src/collector/collector_win.c` | 修改 | 实现EventId过滤逻辑 |

#### 2.3.2 新增类型

```c
typedef enum {
    EDR_EVENT_FILTER_MODE_NONE = 0,
    EDR_EVENT_FILTER_MODE_WHITELIST = 1,
    EDR_EVENT_FILTER_MODE_BLACKLIST = 2,
} EdrEventFilterMode;

typedef struct {
    EdrEventFilterMode mode;
    uint16_t event_ids[EDR_COLLECTOR_MAX_EVENTID_FILTER];
    uint32_t event_id_count;
} EdrEventIdFilter;

typedef struct {
    EdrEventIdFilter dns_client;
    EdrEventIdFilter powershell;
    EdrEventIdFilter tcpip;
    EdrEventIdFilter wmi_activity;
    int filtering_enabled;
} EdrCollectorEventFilterConfig;
```

#### 2.3.3 新增配置项

| 环境变量 | 说明 |
|----------|------|
| `EDR_COLLECTOR_EVENTID_FILTER_MODE` | `whitelist`或`blacklist` |
| `EDR_COLLECTOR_EVENTID_DNS_CLIENT_LIST` | DNS Client EventId列表 |
| `EDR_COLLECTOR_EVENTID_POWERSHELL_LIST` | PowerShell EventId列表 |
| `EDR_COLLECTOR_EVENTID_TCPIP_LIST` | TCPIP EventId列表 |
| `EDR_COLLECTOR_EVENTID_WMI_LIST` | WMI Activity EventId列表 |

#### 2.3.4 使用示例

```bash
# 仅记录DNS查询事件（白名单模式）
export EDR_COLLECTOR_EVENTID_FILTER_MODE=whitelist
export EDR_COLLECTOR_EVENTID_DNS_CLIENT_LIST=1,2,3

# 忽略PowerShell详细脚本块（黑名单模式）
export EDR_COLLECTOR_EVENTID_FILTER_MODE=blacklist
export EDR_COLLECTOR_EVENTID_POWERSHELL_LIST=100,200
```

#### 2.3.5 重要特性

- **内核四通道不受影响**：Process、File、Network、Registry事件始终通过
- **可选Provider可配置**：DNS Client、PowerShell、TCPIP、WMI Activity

---

### 2.4 中期B1：双总线架构原型

#### 2.4.1 修改文件

| 文件 | 修改类型 | 说明 |
|------|----------|------|
| `include/edr/event_bus.h` | 修改 | 新增双总线管理接口 |
| `src/core/event_bus.c` | 修改 | 实现双总线分发逻辑 |

#### 2.4.2 新增接口

```c
typedef enum {
    EDR_BUS_TYPE_NORMAL = 0,
    EDR_BUS_TYPE_HIGH_PRIORITY = 1,
    EDR_BUS_TYPE_LOW_PRIORITY = 2,
} EdrBusType;

int edr_dual_bus_enabled(void);
EdrEventBus *edr_event_bus_create_dual(uint32_t high_priority_slot_count, uint32_t low_priority_slot_count);
int edr_event_bus_try_push_dual(EdrBusType bus_type, const EdrEventSlot *slot);
bool edr_event_bus_try_pop_high_priority(EdrEventBus *bus, EdrEventSlot *out_slot);
bool edr_event_bus_try_pop_low_priority(EdrEventBus *bus, EdrEventSlot *out_slot);
uint32_t edr_event_bus_used_approx_high_priority(EdrEventBus *bus);
uint32_t edr_event_bus_used_approx_low_priority(EdrEventBus *bus);
uint64_t edr_event_bus_dropped_total_high_priority(EdrEventBus *bus);
uint64_t edr_event_bus_dropped_total_low_priority(EdrEventBus *bus);
```

#### 2.4.3 高优先级事件判定

```c
static int edr_is_high_value_event(const EdrEventSlot *slot) {
    if (slot->priority == 0) return 1;
    if (slot->attack_surface_hint != 0) return 1;
    switch (slot->type) {
        case EDR_EVENT_PROCESS_INJECT:
        case EDR_EVENT_THREAD_CREATE_REMOTE:
        case EDR_EVENT_PROTOCOL_SHELLCODE:
        case EDR_EVENT_WEBSHELL_DETECTED:
        case EDR_EVENT_FIREWALL_RULE_CHANGE:
            return 1;
        default:
            return 0;
    }
}
```

#### 2.4.4 新增配置项

| 环境变量 | 默认值 | 说明 |
|----------|--------|------|
| `EDR_DUAL_BUS_ENABLED` | 0 | 1=启用双总线 |

---

## 3. 配置汇总

### 3.1 短期方案配置

```bash
# A4.4线程池化（C1）
export EDR_A44_SPLIT_PATH=1
export EDR_A44_DECODE_THREADS=2
export EDR_A44_QUEUE_CAP=512
```

```bash
# 观察A44统计（C2）
export EDR_ETW_OBS=1
```

### 3.2 中期方案配置

```bash
# EventId过滤（D1）
export EDR_COLLECTOR_EVENTID_FILTER_MODE=blacklist
export EDR_COLLECTOR_EVENTID_POWERSHELL_LIST=100,200
export EDR_COLLECTOR_EVENTID_DNS_CLIENT_LIST=1,2,3
```

```bash
# 双总线架构（B1）
export EDR_DUAL_BUS_ENABLED=1
```

---

## 4. 部署指南

### 4.1 灰度策略

| 阶段 | 功能 | 默认状态 | 建议 |
|------|------|----------|------|
| C1 | A4.4线程池化 | 关闭 | 逐步增加线程数，观察性能 |
| C2 | A44统计指标 | 开启 | 始终开启，用于监控 |
| D1 | EventId过滤 | 关闭 | 谨慎配置，与P0矩阵会签 |
| B1 | 双总线架构 | 关闭 | 验证高优先保活能力 |

### 4.2 监控指标

部署后需重点监控：

| 指标 | 说明 | 告警阈值 |
|------|------|----------|
| `a44_drop_total` | A44队列丢弃数 | > 0 |
| `bus_dropped` | 事件总线丢弃数 | 持续增长 |
| `a44_backoff_sync_total` | 同步解码回退数 | > 100/分钟 |
| `a44_q_avg` | 平均队列深度 | > 80%容量 |
| `a44_threads` | 活跃线程数 | 应等于配置值 |

### 4.3 回滚方案

| 功能 | 回滚方法 |
|------|----------|
| C1 | 设置 `EDR_A44_DECODE_THREADS=1` 或 `EDR_A44_SPLIT_PATH=0` |
| D1 | 设置 `EDR_COLLECTOR_EVENTID_FILTER_MODE` 为空 |
| B1 | 设置 `EDR_DUAL_BUS_ENABLED=0` |

---

## 5. 测试用例

### 5.1 C1测试

| 用例 | 操作 | 预期结果 |
|------|------|----------|
| 单线程回退 | `EDR_A44_DECODE_THREADS=1` | 行为与原有单线程一致 |
| 双线程正常 | `EDR_A44_DECODE_THREADS=2` | 吞吐提升约80-100% |
| 队列满回退 | 高压注入 | 回退计数增加，同步解码生效 |
| 线程安全 | 并发压测 | 无数据竞争，无事件丢失 |

### 5.2 D1测试

| 用例 | 操作 | 预期结果 |
|------|------|----------|
| whitelist模式 | 配置EventId列表 | 仅列表中的EventId通过 |
| blacklist模式 | 配置EventId列表 | 列表中的EventId被过滤 |
| 内核四通道 | 任意过滤配置 | 内核事件不受影响 |

### 5.3 B1测试

| 用例 | 操作 | 预期结果 |
|------|------|----------|
| 高优先保活 | 高优+低优混合注入 | 高优先队列不丢事件 |
| 低优先丢弃 | 极端高压 | 低优先事件按L3策略丢弃 |
| 自动分类 | 普通事件注入 | 自动根据priority/type分类 |

---

## 6. 文件清单

### 6.1 新增文件

| 文件 | 说明 |
|------|------|
| `docs/EDR_EVENT_PATH_SCALING_IMPL_PLAN.md` | 实施方案文档 |

### 6.2 修改文件

| 文件 | 修改类型 |
|------|----------|
| `include/edr/edr_a44_split_path_win.h` | 修改 |
| `src/collector/edr_a44_split_path_win.c` | 重写 |
| `include/edr/collector.h` | 修改 |
| `src/collector/collector_win.c` | 修改 |
| `include/edr/event_bus.h` | 修改 |
| `src/core/event_bus.c` | 修改 |
| `src/core/agent.c` | 修改 |

---

## 7. 已知限制

1. **C1**: 当前实现不支持动态调整线程数，需要重启
2. **D1**: 过滤规则不支持正则表达式，仅支持精确EventId匹配
3. **B1**: 双总线原型未与预处理管道集成，仅提供API接口

---

## 8. 下一步工作

1. **C1稳定化**：
   - 增加动态线程数调整
   - 增加线程负载均衡监控

2. **D1增强**：
   - 支持基于EventId范围的过滤
   - 增加过滤统计（被过滤事件数量）

3. **B1集成**：
   - 与预处理管道集成
   - 实现跨总线关联机制

4. **长期A1储备**：
   - 多消费者预处理架构设计
   - 去重逻辑分片方案

---

## 8. 进一步优化（v2.0 新增）

### 8.1 A1：性能优化 - 无锁化统计收集

**修改文件**：`edr_a44_split_path_win.c`

**优化内容**：
- 将`s_a44_current_depth`改为原子变量
- 统计操作（`s_a44_q_depth_sum`、`s_a44_q_depth_samples`）移出锁保护范围
- 减少锁竞争，提高并发性能

### 8.2 A2：性能优化 - 批量事件处理

**修改文件**：`edr_a44_split_path_win.c`

**优化内容**：
- 解码线程每次从队列中批量取出最多`EDR_A44_BATCH_SIZE`（默认8）个事件
- 减少锁获取次数，提高吞吐量
- 配置项：`EDR_A44_BATCH_SIZE`

### 8.3 A3：性能优化 - CPU缓存友好

**优化内容**：
- 批量处理时使用栈上数组，减少堆分配
- 统计变量对齐到缓存行大小

### 8.4 B1：功能增强 - 完善监控指标体系

**修改文件**：`edr_a44_split_path_win.h`、`edr_a44_split_path_win.c`

**新增指标**：
```c
typedef struct {
    // ... 原有字段 ...
    double throughput_rps;        // 每秒处理速率
    uint64_t start_time_ns;      // 启动时间（纳秒）
    uint64_t last_update_ns;     // 最后更新时间（纳秒）
    uint32_t batch_size;         // 批处理大小
    double queue_utilization_pct; // 队列利用率（百分比）
} EdrA44Stats;
```

**Heartbeat输出**：
```
[a44] threads=2 cap=512 depth=128(50.0%) avg=85.30 drop=0 backoff=0 rps=1234.5
```

### 8.5 B2：功能增强 - 健康检查接口

**修改文件**：`edr_a44_split_path_win.h`、`edr_a44_split_path_win.c`

**新增类型**：
```c
typedef enum {
    EDR_A44_HEALTH_OK = 0,
    EDR_A44_HEALTH_WARNING = 1,
    EDR_A44_HEALTH_ERROR = 2,
    EDR_A44_HEALTH_CRITICAL = 3
} EdrA44HealthStatus;

typedef struct {
    EdrA44HealthStatus status;
    int active_threads;
    uint32_t queue_capacity;
    uint32_t current_depth;
    double queue_utilization_pct;
    uint64_t dropped_total;
    uint64_t total_processed;
    double throughput_rps;
    int is_dropping;
    int is_backing_off;
    int dynamic_adjustment_enabled;
} EdrA44HealthReport;
```

**健康状态判定**：
| 状态 | 条件 |
|------|------|
| CRITICAL | 队列利用率≥95% 或 丢弃数>1000 |
| ERROR | 队列利用率≥80% 或 丢弃数>100 |
| WARNING | 队列利用率≥60% 或 丢弃数>10 |
| OK | 其他情况 |

### 8.6 C1+C2：稳定性提升

**优化内容**：
- 动态线程调整机制（冷却期保护）
- 超时控制和熔断机制（基于健康状态）
- 增强错误处理和重试机制

### 8.7 D1+D2：代码质量

**优化内容**：
- 清理未使用的变量
- 添加关键函数注释
- 代码格式规范化

---

## 9. v3.0 进一步优化（2026-04-27）

### 9.1 A. 内存优化

**修改文件**：`edr_a44_split_path_win.h`、`edr_a44_split_path_win.c`

**新增配置项**：
| 配置项 | 类型 | 说明 |
|--------|------|------|
| `total_alloc_bytes` | uint64 | 累计内存分配字节数 |
| `total_free_bytes` | uint64 | 累计内存释放字节数 |
| `active_alloc_count` | uint32 | 当前活跃分配数 |
| `peak_alloc_count` | uint32 | 峰值分配数 |

**优化内容**：
- 添加内存分配统计，跟踪内存使用情况
- 监控活跃分配数和峰值分配数

### 9.2 B. CPU计算优化

**优化内容**：
- 批量处理减少系统调用
- 栈上数组存储批量事件，减少堆分配
- CPU缓存友好的数据结构设计

### 9.3 C. 容错容灾

**修改文件**：`edr_a44_split_path_win.h`、`edr_a44_split_path_win.c`

**新增接口**：
```c
int edr_a44_circuit_breaker_set_threshold(uint64_t drop_threshold, uint64_t recovery_timeout_ms);
int edr_a44_rate_limit_set(uint32_t max_qps);
int edr_a44_try_acquire_rate_limit(void);
```

**熔断器配置**：
| 环境变量 | 默认值 | 说明 |
|----------|--------|------|
| `EDR_A44_CIRCUIT_DROP_THRESHOLD` | 100 | 触发熔断的丢弃数阈值 |
| `EDR_A44_CIRCUIT_RECOVERY_TIMEOUT_MS` | 5000 | 熔断恢复超时（毫秒） |

**限流器配置**：
| 环境变量 | 默认值 | 说明 |
|----------|--------|------|
| `EDR_A44_RATE_LIMIT_QPS` | 0 | 限流QPS（0表示不限流） |

**熔断器工作原理**：
- 当丢弃数达到阈值时，熔断器打开，拒绝新事件
- 超过恢复超时后，熔断器自动关闭，恢复正常处理
- 熔断期间记录状态变化到日志

### 9.4 D. 可观测性增强

**修改文件**：`edr_a44_split_path_win.h`、`edr_a44_split_path_win.c`

**新增性能剖析接口**：
```c
typedef struct {
    uint64_t total_callback_ns;
    uint64_t callback_count;
    uint64_t avg_callback_ns;
    uint64_t max_callback_ns;
    uint64_t min_callback_ns;
    uint64_t total_tdh_ns;
    uint64_t tdh_count;
    uint64_t avg_tdh_ns;
    uint64_t max_tdh_ns;
    uint64_t total_bus_push_ns;
    uint64_t bus_push_count;
    uint64_t avg_bus_push_ns;
} EdrA44PerfProfile;

int edr_a44_get_perf_profile(EdrA44PerfProfile *out_profile);
int edr_a44_enable_perf_measurement(int enable);
```

**性能指标**：
| 指标 | 说明 |
|------|------|
| `total_callback_ns` | ETW回调总耗时（纳秒） |
| `avg_callback_ns` | ETW回调平均耗时 |
| `max_callback_ns` | ETW回调最大耗时 |
| `total_tdh_ns` | TDH解析总耗时 |
| `avg_tdh_ns` | TDH解析平均耗时 |
| `avg_bus_push_ns` | 总线push平均耗时 |

### 9.5 E. 集成优化

**修改文件**：`edr_a44_split_path_win.h`、`edr_a44_split_path_win.c`

**新增事件聚合接口**：
```c
typedef struct {
    uint64_t aggregated_count;
    uint64_t flush_count;
    uint32_t pending_count;
    uint32_t max_pending;
    uint64_t last_flush_ns;
} EdrA44AggStats;

int edr_a44_aggr_init(uint32_t max_pending);
int edr_a44_aggr_add(const EdrEventSlot *slot);
int edr_a44_aggr_flush(void);
int edr_a44_aggr_get_stats(EdrA44AggStats *out_stats);
```

**聚合器功能**：
- 支持事件批量聚合，减少传输次数
- 可配置的pending队列大小
- 定时flush机制

---

## 10. v4.0 深度优化（2026-04-27）

### 10.1 A. 深度内存优化

**修改文件**：`edr_a44_split_path_win.h`、`edr_a44_split_path_win.c`

**新增接口**：
```c
int edr_a44_memory_pool_init(uint32_t item_size, uint32_t capacity);
int edr_a44_memory_pool_set_prealloc(uint32_t prealloc_count);
void *edr_a44_memory_pool_alloc(void);
void edr_a44_memory_pool_free(void *ptr);
int edr_a44_memory_pool_get_stats(EdrA44MemoryPoolStats *out_stats);
int edr_a44_memory_pool_trim(uint32_t target_free_count);
void edr_a44_memory_pool_shutdown(void);
```

**内存池统计**：
```c
typedef struct {
    uint32_t pool_item_size;
    uint32_t pool_capacity;
    uint32_t total_blocks;
    uint32_t used_blocks;
    uint32_t peak_used_blocks;
    uint64_t total_alloc_bytes;
    uint64_t total_free_bytes;
    uint32_t alloc_count;
    uint32_t free_count;
    uint32_t alloc_fail_count;
    double hit_rate_pct;
} EdrA44MemoryPoolStats;
```

**优化内容**：
- 预分配内存块，减少运行时分配
- 对象池模式，减少内存碎片
- 内存分配统计和命中率追踪
- 支持内存池收缩和清理

### 10.2 B. 深度并发优化

**新增接口**：
```c
int edr_a44_lockfree_queue_init(uint32_t capacity);
int edr_a44_lockfree_queue_try_push(const void *item, uint32_t item_size);
int edr_a44_lockfree_queue_try_pop(void *out_item, uint32_t *out_item_size);
int edr_a44_lockfree_queue_get_stats(EdrA44ConcurrencyStats *out_stats);
int edr_a44_enable_cache_friendly_mode(int enable);
```

**并发统计**：
```c
typedef struct {
    uint64_t lockfree_try_push_count;
    uint64_t lockfree_push_success_count;
    uint64_t lockfree_pop_count;
    uint64_t lockfree_pop_success_count;
    uint64_t lockfree_empty_count;
    uint64_t cacheline_false_sharing_hits;
    uint32_t padding_bytes;
} EdrA44ConcurrencyStats;
```

**优化内容**：
- 无锁队列实现，减少锁竞争
- 伪共享避免（64字节缓存行对齐）
- CAS操作替代互斥锁
- 独立的push/pop统计

### 10.3 C. 智能化自适应

**新增接口**：
```c
typedef enum {
    EDR_A44_ADAPTIVE_MODE_FIXED = 0,
    EDR_A44_ADAPTIVE_MODE_REACTIVE = 1,
    EDR_A44_ADAPTIVE_MODE_PREDICTIVE = 2
} EdrA44AdaptiveMode;

int edr_a44_adaptive_init(EdrA44AdaptiveMode mode);
int edr_a44_adaptive_get_config(EdrA44AdaptiveConfig *out_config);
int edr_a44_adaptive_set_thresholds(double scale_up, double scale_down);
int edr_a44_adaptive_get_recommendation(EdrA44ScalingRecommendation *out_rec);
int edr_a44_adaptive_execute_scale(int target_threads);
int edr_a44_adaptive_update_throughput(double throughput);
```

**自适应模式**：
| 模式 | 说明 |
|------|------|
| FIXED | 固定线程数，不自动调整 |
| REACTIVE | 基于当前指标的反应式调整 |
| PREDICTIVE | 基于历史趋势的预测性调整 |

**预测算法**：
- 滑动窗口（1分钟、5分钟、15分钟）
- 线性回归计算趋势斜率
- 预测1分钟后的吞吐量
- 置信度评估（1/2/3级）

### 10.4 D. 可观测性增强

**优化内容**：
- 内存池命中率追踪
- 无锁队列操作统计
- 自适应调参历史记录
- 缓存行伪共享检测

### 10.5 E. 系统级集成

**优化内容**：
- A44与预处理模块的协同优化
- 事件聚合器与传输模块的接口优化
- 统一的内存管理和统计接口

---

## 11. v5.0 综合优化（2026-04-28）

### 11.1 A. 编译优化

**修改文件**：`CMakeLists.txt`

**新增编译选项**：

| 选项 | 默认值 | 说明 |
|------|--------|------|
| `EDR_ENABLE_OPTIMIZATION` | ON | 启用激进编译器优化 |
| `EDR_ENABLE_ARCH_OPTIMIZATION` | ON | 启用架构特定优化 |

**MSVC优化选项**：
- `/O2` - 最大化优化
- `/Oi` - 启用内联函数
- `/Ot` - 优先优化速度
- `/GL` - 全程序优化
- `/Gy` - 函数级链接
- `/fp:fast` - 快速浮点运算
- `/LTCG` - 链接时代码生成
- `/OPT:REF` - 消除未引用代码
- `/OPT:ICF` - 跨函数重复数据消除

**GCC/Clang优化选项**：
- `-O3` - 最高级别优化
- `-ffast-math` - 快速浮点运算
- `-funroll-loops` - 循环展开
- `-fomit-frame-pointer` - 省略帧指针
- `-fstrict-aliasing` - 严格别名规则
- `-flto` - 链接时优化
- `-march=native` - 本机架构优化
- `-mtune=native` - 本机CPU调优

### 11.2 B. 模块深度优化

**优化内容**：
- AVE引擎：模型加载优化、推理缓存
- 事件总线：MPMC无锁队列优化、批量操作
- 传输模块：批量压缩、连接复用

### 11.3 C. 测试与验证

**新增测试脚本**：

| 文件 | 说明 |
|------|------|
| `scripts/benchmark_performance.sh` | 性能基准测试脚本 |
| `scripts/run_regression.sh` | 回归测试脚本 |

**测试覆盖**：
- Event Bus MPMC压力测试
- A44解码性能测试
- 预处理管道测试
- P0规则匹配测试
- 配置解析测试

### 11.4 D. 架构重构

**优化内容**：
- 设计模式应用（策略模式、观察者模式）
- 代码模块化重构
- 接口抽象与解耦

### 11.5 E. 部署优化

**新增文件**：

| 文件 | 说明 |
|------|------|
| `docker/Dockerfile` | Docker镜像构建文件 |
| `docker/docker-compose.yml` | Docker Compose配置 |

**资源限制**：
| 资源 | 限制 |
|------|------|
| CPU | 最大2核，保留0.5核 |
| 内存 | 最大512MB，保留128MB |

**安全配置**：
- 非特权用户运行
- 禁止新权限提升
- 网络模式host

---

**版本历史**：

| 版本 | 日期 | 修改内容 |
|------|------|----------|
| 1.0 | 2026-04-27 | 初始版本，包含C1、C2、D1、B1实现 |
| 2.0 | 2026-04-27 | 短期C1/C2稳定化，D1增强，B1集成 |
| 3.0 | 2026-04-27 | 内存优化、CPU优化、容错容灾、可观测性增强、集成优化 |
| 4.0 | 2026-04-27 | 深度内存池、无锁队列、智能化自适应 |
| 5.0 | 2026-04-28 | 编译优化、测试验证、容器化部署 |
| 6.0 | 2026-04-28 | 端到端性能优化、可观测性增强、稳定性增强、安全性增强 |

---

## 12. v6.0 端到端性能优化（2026-04-28）

### 12.1 A. 端到端性能优化

**修改文件**：`edr_a44_split_path_win.h`、`edr_a44_split_path_win.c`

**新增接口**：
```c
typedef struct {
    uint64_t total_events;
    uint64_t dropped_events;
    uint64_t queue_depth_max;
    uint64_t latency_min_ns;
    uint64_t latency_max_ns;
    uint64_t latency_avg_ns;
    uint64_t latency_p50_ns;
    uint64_t latency_p95_ns;
    uint64_t latency_p99_ns;
    double throughput_avg_rps;
    double queue_util_avg_pct;
} EdrA44EndToEndStats;

int edr_a44_e2e_enable_tracking(int enable);
int edr_a44_e2e_record_event(uint64_t timestamp_ns);
int edr_a44_e2e_get_stats(EdrA44EndToEndStats *out_stats);
int edr_a44_e2e_reset_stats(void);
```

**延迟追踪特性**：
- 端到端延迟追踪（事件产生到处理的完整路径）
- 百分位数统计（P50/P95/P99）
- 最小/最大/平均延迟
- 事件计数和丢弃统计

**管道配置**：
```c
typedef struct {
    int prefetch_enabled;
    int pipeline_parallel_enabled;
    int batch_timeout_ms;
    int max_batch_size;
} EdrA44PipelineConfig;

int edr_a44_pipeline_get_config(EdrA44PipelineConfig *out_config);
int edr_a44_pipeline_set_config(const EdrA44PipelineConfig *config);
int edr_a44_pipeline_prefetch_start(int lookahead_count);
void edr_a44_pipeline_prefetch_stop(void);
```

**性能剖析跨度**：
```c
typedef struct {
    uint64_t callback_enter_ns;
    uint64_t tdh_start_ns;
    uint64_t tdh_end_ns;
    uint64_t bus_push_start_ns;
    uint64_t bus_push_end_ns;
    uint32_t event_size_bytes;
} EdrA44PipelineSpan;

int edr_a44_pipeline_span_begin(EdrA44PipelineSpan *span);
int edr_a44_pipeline_span_end(EdrA44PipelineSpan *span);
int edr_a44_pipeline_span_record(const EdrA44PipelineSpan *span);
```

### 12.2 B. 可观测性增强

**优化内容**：
- 延迟百分位数实时计算
- 吞吐量滑动窗口
- 队列深度历史追踪
- 管道跨度记录

### 12.3 C. 稳定性增强

**优化内容**：
- 熔断器与限流器联动
- 健康状态自动上报
- 故障恢复自动化

### 12.4 D. 安全性增强

**优化内容**：
- 安全编译选项（DEP、ASLR）
- 安全函数使用
- 权限最小化

### 12.5 E. 代码质量提升

**优化内容**：
- 模块化设计
- 接口抽象
- 统一错误处理

---

*文档与代码实现同步更新*