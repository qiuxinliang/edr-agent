# Agent 环境 profile 示例

| 文件 | 用途 |
|------|------|
| `wp2_lab_e2e.env.example` | 实验室 / E2E：减轻 L2/L3/进程门控，便于**先跑通**告警链（`set` 语法，适用 Windows **cmd**） |
| `wp2_prod_default.env.example` | 高噪/生产**示例**（`set` 语法） |
| `wp8_compliance_baseline.env.example` | **WP-8**（ETW 可观测 + P0 对表）：`EDR_ETW_OBS=1` 等，**不**替代 `[collection]` 全量策略（见 **`edr-agent/docs/WP8_ETW_COLLECTION_PROFILE.md`**） |
| `wp9_behavior_ave.env.example` | **WP-9**（`on_behavior_alert` / 行为管线 / `EDR_BEHAVIOR_ENCODING` 与 **agent.toml** `[ave]` 对表；与 **WP-5** 直出 P0 **路径不同**；见 **`edr-agent/docs/WP9_BEHAVIOR_AVE.md`**） |

Bash 下等价为 `export EDR_PREPROCESS_L2_SPLIT=0` 等，或手抄变量名。

**批次/上送**（`[upload]`、shutdown 行）**先量化**再调，见 **WP-6** `edr-agent/docs/WP6_TRANSPORT_BATCH_QUANTIFIED_OPS.md`。**说明**见 **`edr-agent/docs/WP2_EVENT_BUS_PREPROCESS.md`**（与 **WP-1** `edr-backend/docs/WP1_ALERT_INGEST_E2E.md` 搭配使用）。**传输/ingest 排障**见 **`edr-agent/docs/WP4_HTTP_TRANSPORT_OPS.md`**（WP-4）；**联调身份 WARN** 见 **WP-3** `edr-agent/docs/WP3_CONFIG_VALIDATION.md`；**规则母版与版本对账** 见 **WP-5** `edr-agent/docs/WP5_RULES_ENGINEERING.md`；**发送失败/离线** 见 **WP-7** `edr-agent/docs/WP7_OFFLINE_QUEUE_RETRY.md`。**ETW/采集** 与 **P0 合规** 见 **WP-8** `edr-agent/docs/WP8_ETW_COLLECTION_PROFILE.md`（**`wp8_compliance_baseline.env.example`**）。**行为管线 / AVE 回调** 与 **P0/静态** 解耦 见 **WP-9** `edr-agent/docs/WP9_BEHAVIOR_AVE.md`（**`wp9_behavior_ave.env.example`**）。
