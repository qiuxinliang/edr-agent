# Windows 注册表（Kernel-Registry）— 实机验收清单（P0）

**关联**：`README.md`「ETW 增强」、`include/edr/etw_guids_win.h`（**Microsoft-Windows-Kernel-Registry**）、`collector_win.c` / `etw_tdh_win.c` / `behavior_from_slot.c` / `serialize/behavior_proto.c`；平台 ingest 将 `BehaviorEvent.detail.registry` 解析为 **`payload_json` `category=registry`**（与 `dynamic_rules` 的 `registry_set` 等对齐）。

**前置**：Agent **管理员**（或具备等效 ETW 权限）；`[collection].etw_enabled = true`（默认）；本机可连平台或至少能抓批次/日志。

---

## 1. 采集是否生效

- [ ] 启动后 stderr **无** `EDR_ERR_ETW_PROVIDER_ENABLE` / `KERNEL_REGISTRY` 相关持续失败（可选 Provider 跳过逻辑不适用于 **mandatory** 中的 Registry；若失败需查权限/策略）。
- [ ] 在注册表编辑器中执行一次 **新建键 / 改值 / 删键** 等操作后，预处理或调试日志中能看到 **`prov=kreg`** 的 ETW1 载荷（或总线中有类型 **`REG_CREATE_KEY` / `REG_SET_VALUE` / `REG_DELETE_KEY`** 的记录，见 `types.h` 30–32）。

---

## 2. 字段与载荷（端上）

- [ ] **`regkey` / `regname` / `regdata`**：在 ETW1 文本中是否出现（取决于 TDH 是否返回 `KeyName`、`ValueName`、`ValueData` 等；**二进制 `ValueData`** 在无法按 UTF-16/ULONG 转成可读 UTF-8 时应为 **`hex:` + 十六进制** 前缀形式，而非长期为空）。
- [ ] **`regop`**：未从 ETW1 解析到时，是否按事件类型默认 **`create_key` / `set_value` / `delete_key`**（小写，与平台 `registry_operation` 约定一致）。

---

## 3. 上报与平台（Protobuf）

- [ ] 设置 **`EDR_BEHAVIOR_ENCODING=protobuf`**（或 TOML/部署中等价方式）后，批次中行为帧为 **protobuf**（非仅 BER1）。
- [ ] 平台 **ingest** 解析后 **`payload_json`** 中含 **`"category":"registry"`**，且含 **`registry_key_path` / `registry_value_name` / `registry_value_data` / `registry_operation`** 等字段（与后端 `endpoint_event` 契约一致；空字段可省略由平台处理）。
- [ ] 动态规则（若有 **`registry_set`** 且匹配路径/值）是否在控制台或规则引擎侧按预期命中（可选，依赖平台配置）。

---

## 4. 回归注意

- [ ] **Opcode / Event ID 映射**：以 **Opcode** 为主（Create/Open/Delete/SetValue 等）；若 **Opcode 恒为 0** 等变体，客户端会按 **Event ID（常见 12–17）** 回退；若仍不一致，请抓 ETW1 头中的 **eid/op** 并提 issue / 补丁。
- [ ] **噪声**：注册表事件量极大时，关注 **`dedup`** 与 **`preprocessing`** 限流是否可接受；必要时加 **`[[preprocessing.rules]]`** 丢弃或采样（见 `docs/PREPROCESS_RULES.md`）。

---

**结论**：以上项在 **至少一台 Windows 10/11 真机** 上打勾，即可认为 **P0「注册表 ETW → 行为记录 → protobuf → 平台 category=registry」** 闭环已验收。
