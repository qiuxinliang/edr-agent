# EDR Agent 事件路径扩展性实现方案

**版本**：1.0
**日期**：2026-04-27
**状态**：实施中

---

## 1. 概述

### 1.1 背景

根据 [EDR_AGENT_EVENT_PATH_SCALING_STRUCTURAL_OPTIONS.md](./EDR_AGENT_EVENT_PATH_SCALING_STRUCTURAL_OPTIONS.md) 和 [EDR_AGENT_EVENT_PATH_SCALING_PROJECT_KICKOFF.md](./EDR_AGENT_EVENT_PATH_SCALING_PROJECT_KICKOFF.md)，当前EDR Agent面临的核心问题是：**多路ETW生产 + 单预处理线程消费**在高事件率下导致`bus_dropped`不可接受。

### 1.2 实施目标

| 目标 | 量化指标 |
|------|----------|
| A4.4解侧线程池化 | 解码吞吐量提升 ≥100% |
| 完善统计指标 | 区分总线满/A44满/策略丢 |
| EventId过滤 | 入总线事件量减少 ≥30%（特定场景） |
| 双总线架构 | 高优先事件处理延迟降低 ≥50% |

### 1.3 实施阶段

| 阶段 | 内容 | 优先级 |
|------|------|--------|
| 短期C1 | A4.4线程池化（2-4线程可配置） | P0 |
| 短期C2 | 完善A44统计指标 | P0 |
| 中期D1 | 可配置EventId过滤 | P1 |
| 中期B1 | 双总线架构原型 | P2 |

---

## 2. 短期方案

### 2.1 C1：A4.4线程池化

#### 2.1.1 设计目标

将当前A4.4单解码线程扩展为可配置的线程池（1-4线程），在不改变现有业务逻辑的前提下提升解码吞吐量。

#### 2.1.2 配置项

| 环境变量 | 默认值 | 最小值 | 最大值 | 说明 |
|----------|--------|--------|--------|------|
| `EDR_A44_DECODE_THREADS` | 1 | 1 | 4 | 解码线程池大小 |
| `EDR_A44_QUEUE_CAP` | 512 | 128 | 2048 | 单队列容量 |

#### 2.1.3 架构设计

```
ETW回调 → A44有界队列 → [线程1] → TDH解析 → 总线push
                        → [线程2] → TDH解析 → 总线push
                        → [线程3] → TDH解析 → 总线push
                        → [线程4] → TDH解析 → 总线push
```

#### 2.1.4 线程安全保证

1. **事件总线操作**：已原子化，无需额外保护
2. **A44队列操作**：使用临界区保护，支持多线程安全写入
3. **统计计数器**：使用原子操作（InterlockedAdd64）
4. **配置读取**：仅在启动时读取，运行时不修改

#### 2.1.5 回退策略

当所有解码线程队列满时，回退到ETW回调内同步解码（保持原有行为）。

### 2.2 C2：完善A44统计指标

#### 2.2.1 新增统计项

| 统计项 | 类型 | 说明 |
|--------|------|------|
| `a44_drop_total` | uint64 | A44队列满导致的丢弃总数 |
| `a44_backoff_sync_total` | uint64 | 回退到同步解码的次数 |
| `a44_queue_depth_avg` | double | 平均队列深度 |
| `a44_queue_depth_max` | uint32 | 最大队列深度 |
| `a44_thread_busy_time` | uint64[] | 各线程忙碌时间（纳秒） |

#### 2.2.2 暴露接口

```c
typedef struct {
    uint64_t dropped_total;
    uint64_t backoff_sync_total;
    double queue_depth_avg;
    uint32_t queue_depth_max;
    uint64_t thread_busy_time[4];
    uint32_t active_threads;
} EdrA44Stats;

EdrError edr_a44_get_stats(EdrA44Stats *out_stats);
```

#### 2.2.3 日志输出

在 `[heartbeat]` 行追加：
```
a44_drop=%lu a44_backoff=%lu a44_q_avg=%.2f a44_q_max=%u
```

---

## 3. 中期方案

### 3.1 D1：可配置EventId过滤

#### 3.1.1 设计目标

在ETW事件进入事件总线之前，提供基于Provider和EventId的细粒度过滤能力，减少无效事件对系统资源的占用。

#### 3.1.2 配置项

| 环境变量 | 类型 | 说明 |
|----------|------|------|
| `EDR_COLLECTOR_EVENTID_FILTER_MODE` | string | `whitelist`或`blacklist`，默认不过滤 |
| `EDR_COLLECTOR_EVENTID_{PROVIDER}_LIST` | string | Provider-specific EventId列表，逗号分隔 |

#### 3.1.3 Provider到环境变量映射

| Provider | 环境变量 |
|----------|----------|
| DNS_CLIENT | `EDR_COLLECTOR_EVENTID_DNS_CLIENT_LIST` |
| POWERSHELL | `EDR_COLLECTOR_EVENTID_POWERSHELL_LIST` |
| TCPIP | `EDR_COLLECTOR_EVENTID_TCPIP_LIST` |
| WMI_ACTIVITY | `EDR_COLLECTOR_EVENTID_WMI_LIST` |

#### 3.1.4 过滤规则

1. **whitelist模式**：仅允许列表中的EventId通过
2. **blacklist模式**：阻止列表中的EventId通过，其他都放行
3. **未配置的Provider**：保持原有行为（不过滤）
4. **mandatory内核四通道**：不受过滤影响（Process/File/Network/Registry）

#### 3.1.5 示例配置

```bash
# 仅记录DNS查询事件
export EDR_COLLECTOR_EVENTID_FILTER_MODE=whitelist
export EDR_COLLECTOR_EVENTID_DNS_CLIENT_LIST=1,2,3

# 忽略PowerShell详细脚本块（保留路径信息）
export EDR_COLLECTOR_EVENTID_FILTER_MODE=blacklist
export EDR_COLLECTOR_EVENTID_POWERSHELL_LIST=100,200
```

### 3.2 B1：双总线架构原型

#### 3.2.1 设计目标

创建高优先级和低优先级两条独立的事件处理通道，确保高优先级事件不会被低优先级事件抢占处理资源。

#### 3.2.2 总线配置

| 总线 | 容量 | 处理线程数 | 丢弃策略 |
|------|------|------------|----------|
| 高优先级 | 1024 | 2 | 永不丢弃 |
| 低优先级 | 2048 | 1 | L3高压时丢弃 |

#### 3.2.3 事件分类

**高优先级事件**（进入高优先级总线）：
- `EDR_EVENT_PROCESS_INJECT`
- `EDR_EVENT_THREAD_CREATE_REMOTE`
- `EDR_EVENT_PROTOCOL_SHELLCODE`
- `EDR_EVENT_WEBSHELL_DETECTED`
- `EDR_EVENT_FIREWALL_RULE_CHANGE`
- priority == 0 的所有事件
- attack_surface_hint != 0 的所有事件

**低优先级事件**（进入低优先级总线）：
- 其他所有事件

#### 3.2.4 feature flag

| 环境变量 | 默认值 | 说明 |
|----------|--------|------|
| `EDR_DUAL_BUS_ENABLED` | 0 | 1=启用双总线，0=保持原有单总线 |

---

## 4. 实施详情

### 4.1 C1文件修改清单

| 文件 | 修改内容 |
|------|----------|
| `include/edr/edr_a44_split_path_win.h` | 新增统计结构体和接口 |
| `src/collector/edr_a44_split_path_win.c` | 线程池化改造 |
| `src/core/agent.c` | 暴露A44统计到heartbeat |

### 4.2 C2文件修改清单

| 文件 | 修改内容 |
|------|----------|
| `include/edr/edr_a44_split_path_win.h` | 新增统计接口 |
| `src/collector/edr_a44_split_path_win.c` | 实现统计收集 |
| `src/core/event_bus.c` | 增强统计能力 |

### 4.3 D1文件修改清单

| 文件 | 修改内容 |
|------|----------|
| `include/edr/collector.h` | 新增过滤配置 |
| `src/collector/collector_win.c` | 实现EventId过滤 |
| `src/collector/etw_tdh_win.c` | 支持过滤上下文传递 |

### 4.4 B1文件修改清单

| 文件 | 修改内容 |
|------|----------|
| `include/edr/event_bus.h` | 新增双总线管理接口 |
| `src/core/event_bus.c` | 实现双总线分发逻辑 |
| `src/preprocess/preprocess_pipeline.c` | 支持双总线消费 |

---

## 5. 测试计划

### 5.1 C1测试用例

| 用例 | 输入 | 预期输出 |
|------|------|----------|
| 单线程回退 | `EDR_A44_DECODE_THREADS=1` | 行为与原有单线程一致 |
| 双线程正常 | `EDR_A44_DECODE_THREADS=2` | 吞吐提升约80-100% |
| 队列满回退 | 高压注入 | 回退计数增加，同步解码生效 |
| 线程安全 | 并发压测 | 无数据竞争，无事件丢失 |

### 5.2 C2测试用例

| 用例 | 输入 | 预期输出 |
|------|------|----------|
| 统计准确性 | 处理N个事件 | dropped_total == N（队列满时） |
| 深度统计 | 固定速率注入 | queue_depth_avg反映真实深度 |
| 线程统计 | 多线程运行 | 各线程busy_time有差异 |

### 5.3 D1测试用例

| 用例 | 输入 | 预期输出 |
|------|------|----------|
| whitelist白名单 | EventId 1,2,3 | 仅1,2,3通过 |
| blacklist黑名单 | EventId 1,2,3 | 除1,2,3外都通过 |
| mandatory不受影响 | 内核四通道事件 | 无论过滤配置如何都通过 |

### 5.4 B1测试用例

| 用例 | 输入 | 预期输出 |
|------|------|----------|
| 高优先保活 | 高优+低优混合注入 | 高优先队列不丢事件 |
| 低优先丢弃 | 极端高压 | 低优先事件按L3策略丢弃 |
| 关联性保持 | 跨总线关联场景 | 关键关联信息不丢失 |

---

## 6. 回滚方案

### 6.1 C1回滚

设置 `EDR_A44_DECODE_THREADS=1` 或 `EDR_A44_SPLIT_PATH=0` 即回退到原有行为。

### 6.2 D1回滚

设置 `EDR_COLLECTOR_EVENTID_FILTER_MODE` 为空或不设置，即回退到原有行为。

### 6.3 B1回滚

设置 `EDR_DUAL_BUS_ENABLED=0` 即回退到原有单总线行为。

---

## 7. 部署注意

### 7.1 灰度策略

1. **C1/C2**：默认关闭（`EDR_A44_DECODE_THREADS=1`），通过feature flag启用
2. **D1**：默认不启用过滤（`EDR_COLLECTOR_EVENTID_FILTER_MODE`为空），需要显式配置
3. **B1**：默认关闭（`EDR_DUAL_BUS_ENABLED=0`），通过feature flag启用

### 7.2 监控指标

部署后需重点监控：
- `a44_drop_total`：A44队列丢弃数
- `bus_dropped`：事件总线丢弃数
- `a44_backoff_sync_total`：同步解码回退数
- 心跳日志中的队列深度统计

---

**版本历史**：

| 版本 | 日期 | 修改内容 |
|------|------|----------|
| 1.0 | 2026-04-27 | 初始版本 |

---

*文档与代码实现同步更新*