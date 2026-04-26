# TDH 属性小表：A2.2 / A2.3 回归说明

- **A2.2 实现位置**：`src/collector/etw_tdh_win.c` 中 `edr_tdh_build_slot_payload` 按 **Provider GUID** 选用 `proc_try` / `file_try` 等表，**先试高频 Win32 属性名**，减少无效 `TdhGetProperty`；未命中时仍走后续分支（不删语义）。
- **A2.3 回归（无 Windows）**：`fixtures/tdh/*.txt` 与 `edr_tdh_win.c` 内 `L"..."` **顺序**由 `edr-agent/scripts/verify_tdh_property_try_order.py` 校验；`edr-agent` CI precheck 已跑。**调序**须同步更新对应 fixture 并在 MR 说明原因（仅 perf/兼容，不改为减少 P0 所需字段可用性不经评审）。

| Fixture | 对应 C 表 |
|---------|-----------|
| `fixtures/tdh/kernel_process_prop_try_v1.txt` | `proc_try[]`（Microsoft-Windows-Kernel-Process；命中 `ParentImage` / `ParentFileName` 时输出 `pimg=`，供 `behavior_from_slot` 填 `EdrBehaviorRecord.parent_name` / `parent_path`） |
| `fixtures/tdh/kernel_file_prop_try_v1.txt` | `file_try[]`（Kernel-File） |
