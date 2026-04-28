# P0 与 AVE 引擎集成分析

**版本**：1.0
**日期**：2026-04-28
**状态**：已完成

---

## 1. 概述

本文档分析P0动态行为引擎与AVE（Advanced Visibility Engine）引擎之间的集成关系和数据流。

---

## 2. 引擎职责对比

| 特性 | P0引擎 | AVE引擎 |
|------|--------|---------|
| **职责** | 动态规则匹配（Rule-based） | 高级威胁检测（ML/Score-based） |
| **规则来源** | JSON规则包 + 硬编码 | 启发式评分 |
| **事件类型** | PROCESS_CREATE | SHELLCODE, WEBSHELL, PMFE |
| **处理方式** | 即时匹配 | 跨事件关联评分 |
| **延迟** | 极低（同步） | 较高（可能需要积累） |

---

## 3. 数据流分析

### 3.1 当前数据流

```
ETW事件
    │
    ▼
process_one_slot()
    │
    ├─► EdrBehaviorRecord 构建
    │
    ├─► P0检测 (PROCESS_CREATE事件)
    │       │
    │       └─► R-EXEC-001 / R-CRED-001 / R-FILELESS-001
    │
    ├─► procname_gate丢弃检查
    │
    ├─► L2 split丢弃检查
    │
    ├─► edr_preprocess_should_emit()检查
    │
    ├─► AVE交叉引擎喂养
    │       │
    │       └─► SHELLCODE / WEBSHELL / PMFE 事件
    │
    └─► 编码并推送
```

### 3.2 AVE事件类型

```c
// ave_cross_engine_feed.c
void edr_ave_cross_engine_feed_from_record(const EdrBehaviorRecord *br) {
    // 只处理以下事件类型
    switch (br->type) {
    case EDR_EVENT_PROTOCOL_SHELLCODE:    // Shellcode检测
    case EDR_EVENT_WEBSHELL_DETECTED:     // Webshell检测
    case EDR_EVENT_PMFE_SCAN_RESULT:      // PMFE扫描结果
        // 喂养AVE引擎
        break;
    }
}
```

---

## 4. 潜在问题分析

### 4.1 问题1：事件类型分离

**描述**：P0和AVE处理不同的事件类型，可能导致某些攻击场景被遗漏。

**场景**：
1. 攻击者使用PowerShell编码命令执行shellcode
2. 这会触发 `EDR_EVENT_PROCESS_CREATE`（P0会检测）
3. 但不会触发 `EDR_EVENT_PROTOCOL_SHELLCODE`（AVE不会检测）

**结论**：这可能是预期行为，因为P0负责检测恶意命令执行，AVE负责检测恶意行为模式。

### 4.2 问题2：重复告警风险

**描述**：如果同一事件同时匹配P0规则和AVE评分，可能产生重复告警。

**当前实现**：
- P0通过 `emit_for_rule()` 直接发送告警
- AVE通过 `edr_ave_cross_engine_feed()` 喂养引擎
- 两者独立，不会有重复

### 4.3 问题3：AVE评分可能受丢弃逻辑影响

**描述**：如果事件在到达AVE之前被丢弃，AVE可能无法看到完整的行为链。

**当前实现**：
```c
// preprocess_pipeline.c
edr_p0_rule_try_emit(&br);  // P0先检测

// ... 丢弃逻辑 ...

edr_ave_cross_engine_feed_from_record(&br);  // AVE后检测
```

**问题**：如果事件被 `procname_gate` 或 `L2 split` 丢弃，AVE也看不到。

**建议**：AVE应该在丢弃逻辑之前被喂养，或者AVE的输入应该基于原始slot而非构建后的br。

---

## 5. 集成优化建议

### 5.1 建议1：AVE提前喂养

将AVE喂养移到丢弃逻辑之前：

```c
EdrBehaviorRecord br;
edr_behavior_from_slot(slot, &br);
edr_behavior_record_fill_process_chain_depth(&br);
apply_agent_ids_to_record(&br);

// P0检测：尽早执行
if (slot && slot->type == EDR_EVENT_PROCESS_CREATE) {
    edr_p0_rule_try_emit(&br);
}

// AVE喂养：在丢弃逻辑之前
if (slot && (slot->type == EDR_EVENT_PROTOCOL_SHELLCODE ||
             slot->type == EDR_EVENT_WEBSHELL_DETECTED ||
             slot->type == EDR_EVENT_PMFE_SCAN_RESULT)) {
    edr_ave_cross_engine_feed_from_record(&br);
}

// ... 丢弃逻辑 ...
```

### 5.2 建议2：AVE与P0结果关联

当P0匹配成功时，可以将AVE的评分作为上下文附加：

```c
if (edr_p0_rule_matches(...)) {
    // P0匹配成功
    float ave_score = edr_ave_cross_engine_get_score(br->pid);
    emit_p0_alert(rule_id, br, ave_score);  // 包含AVE评分
}
```

### 5.3 建议3：共享行为链深度

AVE和P0都需要 `process_chain_depth`：

```c
// 当前实现中，chain_depth在P0之后才填充
edr_behavior_record_fill_process_chain_depth(&br);

// 建议：在P0和AVE之前都填充
edr_behavior_record_fill_process_chain_depth(&br);
edr_p0_rule_try_emit(&br);
edr_ave_cross_engine_feed_from_record(&br);
```

---

## 6. 配置接口

### 6.1 AVE交叉引擎喂养控制

```bash
# 启用AVE交叉引擎喂养（默认启用）
export EDR_AVE_CROSS_ENGINE_FEED=1

# 禁用AVE交叉引擎喂养
export EDR_AVE_CROSS_ENGINE_FEED=0
```

### 6.2 P0直接发射控制

```bash
# 启用P0直接发射（默认启用，v2.0+）
export EDR_P0_DIRECT_EMIT=1

# 禁用P0直接发射
export EDR_P0_DIRECT_EMIT=0
```

---

## 7. 监控指标

### 7.1 P0统计

```bash
[p0] total=12345 env_skip=0 ir_match=5 fb_match=10 r_exec=3 r_cred=2 r_filess=0
```

### 7.2 AVE统计（待实现）

建议添加AVE的统计输出：

```bash
[ave] cross_feed=1234 shellcode=100 webshell=50 pmfe=200 avg_score=0.75
```

---

## 8. 总结

### 8.1 当前架构

| 组件 | 职责 | 触发条件 |
|------|------|----------|
| P0 | 规则匹配 | PROCESS_CREATE事件 |
| AVE | 评分检测 | SHELLCODE/WEBSHELL/PMFE事件 |
| L2 | 发射规则 | 所有事件 |
| Dedup | 去重 | 所有事件 |

### 8.2 优化建议优先级

| 优先级 | 建议 | 影响 |
|--------|------|------|
| 高 | AVE提前到丢弃逻辑之前 | 减少AVE遗漏 |
| 中 | AVE与P0结果关联 | 增强告警上下文 |
| 低 | 共享chain_depth计算 | 性能优化 |

---

*文档生成时间：2026-04-28*