# behavior.onnx：设计目标 vs 端侧现状（差距表）

**设计权威**：《Cauld Design/11_behavior.onnx详细设计.md》  
**实现入口**：`src/ave/ave_onnx_infer.c`、`src/ave/ave_behavior_pipeline.c`

| 主题 | 设计目标 | 当前 edr-agent | 备注 |
|------|----------|----------------|------|
| 输入形状 | `(1, 128, 64)` Transformer 序列等 | **已对齐**：`refine_behavior_input_dims` 解析 `(batch,seq,feat)`、`(seq,feat)`、**单轴展平 `seq×feat`**；`ph_build_ort_input` 从 `PidHistory.feat_chrono` 左 PAD 右对齐写入 ORT；`EDR_AVE_BEH_SEQ_LEN` / `EDR_AVE_BEH_IN_LEN` 调动态默认 | 4D 变体、非 64 feat 维需另行扩展 |
| 输出 | `anomaly_score` + `tactic_probs` (14) | 已支持 **双输出绑定 + 一次 Run**；单输出兼容 | 见 `AVE_ONNX_CONTRACT.md` §2 |
| 战术字符串 | `triggered_tactics`：概率 **>0.5** 的战术名 | 告警路径已按 §6.3 顺序生成逗号分隔英文名 | 与 proto 上报字段对齐见 `BEHAVIOR_ONNX_IMPLEMENTATION_PLAN.md` |
| 触发步长 / P0 | §7 立即推理与自适应步长 | **`bp_infer_immediate` / `bp_infer_events_threshold_design7`**（**`ave_behavior_pipeline.c`**）与 **`EDR_AVE_BEH_*`**；对照表见 **`docs/AVE_P3_TRACEABILITY.md`** | P3 可追溯 |
| 集成测试 | — | **`ctest -R ave_behavior_onnx_dual`**：`(1,64)` + **`(1,128,64)`** 两 fixture | `scripts/gen_minimal_behavior_dual_onnx.py`、`scripts/gen_behavior_seq128_dual_onnx.py` |
