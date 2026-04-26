# E 组标量与 `AVE_FeedEvent` 路径（AG-020）

> **目标**：各子系统稳定 **`AVE_FeedEvent`** → **`edr_ave_bp_feed`** → 特征 **§5.5 E(44–57)** 与《11》对齐。  
> **编码**：`ave_behavior_features.c` 中 **`encode_e_group`**（含维 **57** `is_real_event` 语义）。

## 1. 统一入口

| 步骤 | 文件 | 说明 |
|------|------|------|
| 1 | `include/edr/ave_sdk.h` | **`AVE_FeedEvent(const AVEBehaviorEvent *)`** 声明 |
| 2 | `src/ave/ave_sdk.c` | IOC 应用 **`edr_ave_behavior_event_apply_ioc`** → **`edr_ave_bp_feed`** |
| 3 | `src/ave/ave_behavior_pipeline.c` | **`edr_ave_bp_feed`**：入队 / 同步处理 → **`edr_ave_behavior_encode_m3b`** → **`encode_e_group`** |

## 2. 并行数据源（跨引擎）

| 路径 | 文件 | 说明 |
|------|------|------|
| 预处理记录 | `src/ave/ave_cross_engine_feed.c` | **`edr_ave_cross_engine_feed_from_record`**：Shellcode / Webshell / PMFE → 填 **`AVEBehaviorEvent`** → **`AVE_FeedEvent`** |
| ETW | `src/collector/ave_etw_feed_win.c` | 实时事件 **`AVE_FeedEvent`** |

环境变量 **`EDR_AVE_CROSS_ENGINE_FEED=0`** 可关闭跨引擎写回（调试）。

## 3. E 维与 `AVEBehaviorEvent` 字段

| 维 | 主要来源 |
|----|-----------|
| 44 | `static_max_conf` / `ave_confidence`（`EdrAveBehaviorFeatExtra`） |
| 45–47 | 静态 verdict、shellcode、webshell 分 |
| 48–50 | `ioc_*_hit` |
| 51–52 | 父静态置信、兄弟 anomaly 均值（PidHistory 扩展） |
| 53–55 | PMFE 置信、PE 标志、`behavior_flags` popcount |
| 56 | `cert_revoked_ancestor` 事件步 **OR** `FeatExtra` |
| 57 | 真实事件步 = 1（PAD 在 ORT 输入侧置零） |

## 4. 缺口与后续

- **维 56**：`EdrPidHistory` 粘性路径与证书子系统需与设计 §5.5 完整对拍（见 **AG-021**）。  
- **稳定性**：生产环境观测 **`AVEStatus.behavior_feed_*`** 与队列满降级。

## 5. 验收勾选

- [ ] 设计表 E 维与 `encode_e_group` 一致（本表已映射）  
- [ ] 关键路径集成测试或真机 E2E（**AG-040** / **`REAL_DEVICE_BEHAVIOR_E2E.md`**）
