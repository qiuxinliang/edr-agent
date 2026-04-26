# B2.4 实机 E2E 闭环保底清单

## 0. P0 机读门闩（**先跑**，与任务包 §7 **P0-验收** 对齐）

在 monorepo 根**一键**（= `recommended_p0_pr_gates` + 生成 `EVIDENCE.md`）：

```bash
bash edr-backend/scripts/p0_pack_machine_gates.sh
```

- **通过**：`exit 0`；`artifacts/p0_b24_evidence/EVIDENCE.md` 可随 MR/发版附。说明见 [`Cauld Design/EDR_P0_Pack_P0_Execution.md`](../../Cauld%20Design/EDR_P0_Pack_P0_Execution.md)。  
- **不替代**：下文 §1～3 **人测**；**会签实名** 见 `EDR_P0_Field_Matrix_Signoff.md` §4。

---

与 **`edr-backend/scripts/collect_p0_b24_evidence.sh`**（仓库内自动化证据）**互补**：脚本覆盖 **P0 版本/金线/可选 Staging GET alerts**；本文档为 **人测** 在 **实机/Staging** 的勾选项，便于发版 or MR 留档（可与 `Sprint-Gates-Runbook.md` G-01 对齐）。

## 1. 前置

- [ ] 已读 **`docs/EDR_P0_DIRECT_EMIT_E2E.md`**：`EDR_P0_DIRECT_EMIT=1`、平台 URL/Token 与**预期命中**条目的规则 ID 一致。  
- [ ] Agent **CMake/嵌入** 与 `verify_p0_bundle_version_alignment.sh` 一致（发版前 gate）。  
- [ ] 本地或 CI 已跑通 `collect_p0_b24_evidence.sh`，产物 `artifacts/.../EVIDENCE.md` 附 MR。

## 2. 实机/Win（规则源 alerts）

- [ ] 触发一条 **P0 可命中的行为**（与 E2E 文档一致，如可复制的 **process_create** 用例）。  
- [ ] **`GET /api/v1/alerts`** 或产品列表可见 **`user_subject_json`** / `edr_dynamic_rule` / 或 **`display_title` 回退**（与 C1.3 一致）可区分 **规则源** vs ONNX。  
- [ ] 无 **同一条** alert 的 **双份** `dynamic_rule_hits`（C1.2 幂等，若有富化段）。

## 3. Staging（可选）

- [ ] 设 `B24_STAGING_API_BASE` + `B24_STAGING_BEARER` 后重跑 `collect_p0_b24_evidence.sh`，`EVIDENCE.md` 中 **http_code=200** 且样例体含 `alerts` 数组。  
- [ ] Token **不** 提交到 git；证据截屏/脱敏。

## 4. 与 ETW/减负 并行时的注意

若启 **`EDR_AVE_ETW_FEED=0` / `EVERY_N>1` / `EDR_AVE_ETW_ASYNC=1` / 关 A4.3 某 Provider**：P0 若依赖对应字段/事件，须已在 **`EDR_P0_Field_Matrix_Signoff.md`** 有依据，且本条 E2E **仍绿**。
