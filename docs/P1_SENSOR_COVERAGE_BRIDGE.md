# P1 Sensor Coverage Bridge

本文记录 P1 最新攻击覆盖的传感器闭环。目标不是新增大引擎，而是把真实采集字段稳定映射到 `BehaviorRecord.script_snippet`，再由 `detection_decision` 统一评分并写入 `detection_context`。

P2 运维闭环见 `P2_ENGINE_HEALTH_COVERAGE.md`：Agent `engine_health` 上报、平台检测覆盖矩阵、引擎最近命中和资源预算展示。

## ETW1 字段契约

预处理支持以下 ETW1 键，值会被合并到 `script_snippet`，供检测决策消费：

| 能力 | ETW1 键 |
| --- | --- |
| PowerShell / AMSI / ScriptBlock | `sensor`、`provider`、`scriptblock_id`、`amsi_content`、`script_hash` |
| JA3 / SNI / 证书异常 | `ja3`、`ja3_rare`、`ja3_unknown`、`sni`、`sni_suspicious`、`sni_mismatch`、`cert_self_signed`、`cert_expired`、`cert_mismatch`、`cert_revoked`、`cert_revoked_ancestor` |
| 勒索行为计数 | `ransom_counter`、`file_rate`、`ext_burst`、`entropy_delta`、`mass_rename`、`extension_burst`、`shadow_delete` |
| WebShell 语义 | `ast_score`、`token_score`、`ast`、`token`、`features` |
| 持久化变化 | `regkey`、`regpath`、`registry_key`、`registry_path`、`target_object`、`regname`、`registry_value`、`value_name`、`regdata`、`registry_data`、`value_data`、`operation` |

为适配真实传感器差异，预处理同时接受以下别名：

- 脚本内容：`amsi_result`、`script_content`、`script_text`
- 通用网络/文件：`url`、`remote_url`、`domain`、`sha256`、`file_sha256`、`file_hash`
- TLS：`ja3_hash`、`ja3_fingerprint`、`tls_sni`、`cert_chain_anomaly`、`cert_untrusted`、`cert_subject`、`cert_issuer`
- 勒索行为：`file_entropy_delta`、`rename_burst`、`shadowcopy_delete`
- WebShell 语义：`semantic_score`、`ast_tokens`、`token_features`
- 注册表持久化：`registry_key`、`registry_path`、`target_object`、`registry_value`、`value_name`、`registry_data`、`value_data`、`registry_op`

Windows TDH PowerShell Provider 会自动补充：

```text
sensor=scriptblock
provider=Microsoft-Windows-PowerShell
```

并尝试提取 `ScriptBlockId`。其他采集器或平台测试夹具只要输出同一 ETW1 键，即可复用统一评分。

文件事件预处理器会对 `create/write/rename/delete` 做轻量滑窗聚合：

- 以 `pid + 目录` 为桶，最多保留 128 个桶，默认窗口 60 秒。
- 记录文件事件速率、扩展名多样性和文件名熵变化，并写入 `file_rate`、`ext_burst`、`entropy_delta`。
- 当 `file_rate >= 80/min`、`ext_burst >= 20` 或 `entropy_delta >= 1.5` 时，自动追加 `ransom_counter=1`。
- 窗口可通过 `EDR_RANSOM_COUNTER_WINDOW_S` 调整，最大 600 秒。

## 进程上下文窗口

检测决策会维护一个轻量 `pid` 时间窗，用于关联同一进程的脚本、网络、TLS、PMFE、Shellcode、WebShell、凭据与勒索信号：

- 默认窗口 900 秒，可通过 `EDR_DETECTION_CONTEXT_WINDOW_S` 调整，最大 3600 秒。
- 当同一进程先后出现远程连接 + 脚本内容、TLS 异常 + 远程连接、WebShell + 网络、凭据/注入/PMFE 等组合时，会追加 `process_window_*` 原因并提升置信度。
- 当子进程继承了父进程的脚本、远程连接、WebShell、勒索或内存证据时，会追加 `process_tree_parent_*` 原因，补足 ISO/LNK、Office、脚本解释器拉起 LOLBin 的链式检测。
- 父进程远程脚本证据关联到子进程 LOLBin 时，不再按“单独 LOLBin 无组合条件”降噪；达到阈值后触发 `process_context_high_signal` 的单进程 PMFE 扫描建议，仍避免直接扩大到整机内存 dump。
- `detection_context.signals.process_context=true` 表示该告警命中了进程窗口关联。

## 策略文件

除环境变量内联列表外，Agent 侧检测决策还支持小型策略文件，便于运维中心下发后由本地配置或服务包装注入：

- `EDR_DETECTION_RMM_ALLOWLIST_FILE`
- `EDR_DETECTION_MGMT_TOOLS_FILE`
- `EDR_DETECTION_ALLOW_PATHS_FILE`
- `EDR_DETECTION_SCRIPT_DIRS_FILE`
- `EDR_DETECTION_FP_FEEDBACK_FILE`

文件内容可用逗号、分号或换行分隔，读取上限为 4 KiB；RMM 版本通过 `EDR_DETECTION_RMM_POLICY_VERSION` 写入 `detection_context.detection_profile.rmm_policy_version`，误报反馈版本通过 `EDR_DETECTION_FP_POLICY_VERSION` 写入 `detection_context.detection_profile.false_positive_policy_version`。

降噪闭环字段：

- `detection_context.suppression.hit_count`：当前 Agent 进程内按 `reason + policy_version` 统计的命中次数，用于运维中心观察策略噪声收益。
- `detection_context.suppression.rollback_available` / `rollback_version`：由 `EDR_DETECTION_RMM_ROLLBACK_VERSION`、`EDR_DETECTION_FP_ROLLBACK_VERSION` 或通用 `EDR_DETECTION_ROLLBACK_VERSION` 注入，供服务端展示一键回滚候选版本。
- `detection_context.signals.false_positive_feedback`：命中误报反馈策略。该策略不会压制 Shellcode、WebShell、PMFE、凭据、勒索、注入、持久化等高风险多源证据。

## 检测输出

命中后会进入 `detection_context.signals`：

- `script_sensor`
- `tls_anomaly`
- `ransom_behavior`
- `webshell_semantic`
- `persistence_change`
- `rmm_policy_match`
- `false_positive_feedback`
- `process_context`

推荐取证动作会追加：

- `script_content`
- `tls_certificate`
- `ransom_activity`
- `webshell_semantics`
- `persistence_changes`

## 验证

```bash
cd edr-agent
ctest --test-dir /private/tmp/edr-agent-decision-build -R 'detection_(decision_combo|regression_scenarios|sensor_bridge)' --output-on-failure
```

`detection_sensor_bridge` 覆盖 `ETW1 -> BehaviorRecord -> detection_decision -> detection_context` 的端到端映射。

真实 Windows 传感器 P0 验证见 `P0_REAL_SENSOR_E2E.md`。它使用 `scripts/windows_sensor_e2e.ps1` 在安装了 Agent 的终端上触发低风险 ScriptBlock/AMSI 和文件速率场景，并可按实验室策略显式启用持久化、WebShell、TLS 和 LSASS 命令行场景。
