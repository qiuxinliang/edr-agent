# P0 直出（`EDR_P0_DIRECT_EMIT=1`）联调与 Staging 留证

> 与 `Cauld Design/EDR_Task_Package_ETW_Rule_Engine_Sprints.md` **B2.4**、**D1.1** 及 `Sprint-Gates-Runbook.md` **G-01** 对应。

## 1. 端上条件（Windows Agent）

- **编译**：`pcre2` 可用时运行期从 `edr_config/p0_rule_bundle_ir_v1.json` 读 IR；否则 legacy 子集。发版前跑 `bash edr-backend/scripts/verify_p0_bundle_version_alignment.sh`（四处 `version` 一致）。
- **环境变量**（示例）  
  - `EDR_P0_DIRECT_EMIT=1`  
  - `EDR_BEHAVIOR_ENCODING=protobuf`（与平台 ingest 一致时）  
  - 去重/限流：`EDR_P0_DEDUP_SEC`（默认 2）、`EDR_P0_MAX_EMITS_PER_MIN`（0=不限制）  
- **本机/实验室**：`edr-agent/scripts/edr_platform_stack_smoke.ps1` 辅助确认平台 **alerts** 侧可见规则源（`user_subject_json.subject_type=edr_dynamic_rule` 或 Title / 展示字段，依前端版本为准）。

## 2. 自动化证据包（不连实机 DB）

在 monorepo 根执行：

```bash
bash edr-backend/scripts/collect_p0_b24_evidence.sh
```

输出默认：`artifacts/p0_b24_evidence/EVIDENCE.md`（可随 MR 附上）。

**人工实机/Staging 勾选项**与脚本互补：见本目录下 **`EVIDENCE_B24_CHECKLIST.md`**。

## 3. Staging 可选：拉取 `alerts` 列表片段

若可对 Staging 的 `edr-api` 使用 JWT：

```bash
export B24_STAGING_API_BASE="https://edr-staging.example.com"   # 无尾斜杠
export B24_STAGING_BEARER="eyJ..."   # 平台用户 JWT
bash edr-backend/scripts/collect_p0_b24_evidence.sh
```

证据中会追加 `GET ${B24_STAGING_API_BASE}/api/v1/alerts?limit=5` 的 HTTP 状态与响应体前若干 KB（**不要**在日志中粘贴全 token；脚本**不**将 Bearer 原文写入 EVIDENCE）。

**人工 DB 留证**（G-01）：仍由联调方对 `alerts` 表执行 `user_subject_json` 含 `edr_dynamic_rule` 的 `SELECT` 并截屏/导出，附发布纪要。

## 4. 回归脚本索引

| 项 | 命令 |
|----|------|
| P0 版本四方对账 | `bash edr-backend/scripts/verify_p0_bundle_version_alignment.sh` |
| Go/C P0 金线 | 见 `Sprint-Backend-Tasks`「P0 金线」 |
| TDH 属性名顺序 | `python3 edr-agent/scripts/verify_tdh_property_try_order.py` |
| ETW1 槽文本字节金体 | `python3 edr-agent/scripts/verify_tdh_etw1_payload_golden.py` |

## 5. 与「Windows 录制 EVENT_RECORD 十六进制 diff」的关系

- **Linux / macOS CI 与 Cursor 沙箱**一般**不能**运行真实 ETW 或持有与 Windows 内核一致的 `EVENT_RECORD.UserData` 布局，因此**不做**原始事件字节的跨平台回归。
- **ETW1 文本槽**（`edr_tdh_build_slot_payload` 输出、`verify_tdh_etw1_payload_golden.py`）可在任意 OS 上锚定**代理层**契约。
- 若要对**单条录制**做 `UserData` **十六进制级** diff，请在 **Windows** 上执行（本机或 **`windows-latest` GitHub Actions**），将 `.bin` / hex 与 golden 比对；该步骤**不**放入 Linux precheck。
