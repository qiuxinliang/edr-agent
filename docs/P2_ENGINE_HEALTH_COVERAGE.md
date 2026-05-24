# P2 Engine Health And Coverage

本文记录检测能力 P2 运维闭环：Agent 低频上报 `engine_health`，平台运维总览展示真实启用状态、版本、队列、水位、最近命中与资源预算。

## Agent 上报

当 `[platform].rest_base_url` 已配置且 `[agent].endpoint_id` 不是 `auto` 时，Agent 主循环每 60 秒上报一次：

```http
POST /api/v1/ingest/engine-health
```

可用 `EDR_ENGINE_HEALTH_INTERVAL_S` 调整周期，范围 10～3600 秒。

载荷结构：

```json
{
  "endpoint_id": "ep-1",
  "agent_version": "0.3.0",
  "policy_version": "rules-2026.05",
  "engine_health": {
    "resource": {
      "cpu_budget_percent": 10,
      "memory_budget_mb": 512
    },
    "p0_rule": {
      "enabled": true,
      "mode": "resident",
      "rule_version": "rules-2026.05",
      "rules_count": 12
    },
    "ave": {
      "enabled": true,
      "mode": "triggered",
      "static_model_version": "ave-static-2.1",
      "behavior_model_version": "ave-behavior-3.2",
      "ioc_rules_version": "ioc-2026.05",
      "queue_depth": 1,
      "queue_capacity": 1024,
      "active_scans": 0
    },
    "pmfe": {
      "enabled": true,
      "mode": "alert_single_process",
      "queue_depth": 0,
      "submitted": 8,
      "completed": 8,
      "dropped": 0
    },
    "shellcode": {
      "enabled": false,
      "mode": "lateral_movement_ports",
      "watch_count": 5,
      "threads": 2,
      "max_payload_inspect": 16384
    },
    "webshell": {
      "enabled": false,
      "mode": "web_roots_only",
      "watch_count": 64,
      "max_file_size_mb": 10,
      "scan_threads": 2
    }
  }
}
```

## 平台聚合

- `POST /api/v1/ingest/engine-health` 将原始 JSON 写入 `endpoint_events(type='engine_health')`，并刷新终端在线、Agent 版本和策略版本。
- `GET /admin/ops/engine-health` 返回每个终端最近一条上报。
- `GET /admin/ops/detection-coverage` 按 ATT&CK 技术聚合覆盖状态：
  - 引擎启用状态来自最近 `engine_health`。
  - 规则版本、模型版本、队列深度、watch 数量来自最近 `engine_health`。
  - 技术近 7 天命中来自 `alerts.mitre_ttps`。
  - 引擎近 7 天命中来自 `endpoint_events.payload_json.detection_context.engine`，缺失时回退 `engine_evidence.detector`。

## 运维解释

- `enabled`：所有上报终端都启用该引擎。
- `adaptive`：部分终端启用，适合 Shellcode、WebShell、PMFE 这类按资产或告警触发的能力。
- `disabled`：有遥测但未启用。
- `no_telemetry`：尚无上报，通常表示 Agent 版本未升级、未配置 REST 上报，或终端离线。

P2 的目标是让覆盖矩阵不再是静态能力表，而是可支撑 MTTR、检测缺口、资源预算和策略回滚判断的运行态视图。

## 最新攻击覆盖增强

- WebShell fallback 检测已补充 AST/token 风格的轻量语义组合：输入源（`$_POST`、`request.getParameter`、`Request.Form` 等）+ 危险执行点（`eval/assert/system/shell_exec/Runtime.exec/Process.Start` 等）+ 解码/动态调用/上传写文件特征。该逻辑仍只在 Web 根目录文件变更后触发，并受 `max_file_size_mb`、`scan_threads`、`enabled` 策略约束。
- Shellcode 内置规则库在 YARA 外新增 SMBGhost、DoublePulsar ping、ReflectiveLoader HTTP stager 等低成本匹配。默认 `shellcode_detector.enabled=false` 不变，仍建议仅在服务器、高价值资产、横向移动高风险策略或特定端口监控策略下启用。
- 更大规模或更高成本的语义规则继续放在 YARA/策略目录中热加载，避免把默认 Agent 变成全量深扫。
