# §7 触发 / 步长与源码对照（AG-013）

> **设计**：《11》§7 推理触发与分数带、§8.1 形状  
> **头文件**：`include/edr/ave_behavior_gates.h`  
> **管线**：`src/ave/ave_behavior_pipeline.c`

## 1. 命名宏（阈值与形状）

| 宏 | 值 | 《11》章节 |
|----|-----|------------|
| `EDR_AVE_BEH_SCORE_MEDIUM_LOW` | 0.40f | §7.2 |
| `EDR_AVE_BEH_SCORE_HIGH` | 0.65f | §7.3 |
| `EDR_AVE_BEH_INFER_STEP_DEFAULT` | 16 | §7.1 默认步长 |
| `EDR_AVE_BEH_INFER_STEP_TIGHT` | 8 | §7.1 步长减半 |
| `EDR_AVE_BEH_MEDIUM_RUN_LEN_FOR_STEP_TIGHT` | 3 | 连续中等次数 |
| `EDR_AVE_BEH_ONNX_SEQ_LEN` | 128 | §8.1 |
| `EDR_AVE_BEH_ONNX_FEAT_DIM` | 64 | §8.1 |

单测：`tests/test_ave_behavior_gates.c`（扩展后与头文件一致）。

## 2. 「立即触发」OR 推理（§7.1 P0）

实现为 **`bp_infer_immediate`**（`ave_behavior_pipeline.c`），满足以下任一即 **步长阈值 = 1**（与 `events_since_last_inference` 解耦）：

- 事件类型：`PROCESS_INJECT`、`MEM_ALLOC_EXEC`、`LSASS_ACCESS`、`SHELLCODE_SIGNAL`、`PMFE_RESULT`、`WEBSHELL_SIGNAL`
- IOC：`ioc_ip_hit` / `ioc_domain_hit`
- `behavior_flags` 命中高危子集（`AVE_BEH_*` 注入/ hollow / LSASS 等）

**未抽成独立宏**：避免与设计表逐字命名分叉；若后续产品冻结事件清单，可再提 **`EDR_AVE_BEH_IMMEDIATE_EVT_MASK`** 类宏。

## 3. 验收

- [ ] 阈值与步长与《11》打印版一致（本表已对齐）  
- [ ] `test_ave_behavior_gates` CI 通过
