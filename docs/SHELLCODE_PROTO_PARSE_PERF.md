# `proto_parse` / `max_payload_inspect` — 性能回归说明（T-SC-013）

## 1. 目的

扩展 **SMB2 Command** 白名单（**T-SC-011**）后，WinDivert 路径上 **`edr_proto_find_shellcode_region`** 仍对每个截断后的 TCP 载荷最多调用一次；主要成本来自 **允许的 Command 变多** 时 **更少** 的 **`NOT_INTERESTING`** 早退，以及随后 **`edr_shellcode_match_known_exploit`** / 启发式。本页约定**如何**在专机做前后对比，而非在 CI 中硬编码耗时阈值。

## 2. 与 P2-PERF-4 的关系

合规压测与 **`wd_stats`** 模板见 **`docs/P2_PERF4_SYNTHETIC_TRAFFIC_REPORT.md`**。建议在 **P-B**（合成 SMB/HTTP 突发）Profile 中：

1. 记录 **`[shellcode_detector].max_payload_inspect`**（及 **`windivert_tcp_ports`**）配置。  
2. 设置 **`EDR_SHELLCODE_WD_STATS=1`**，在 **`edr_windivert_capture_stop`** 时保存 **`wd_stats`** 整行（含 **`recv` / `skip` / `pushed` / `bus_drop` / `alert_dedup`**）。  
3. 在 **变更 `proto_parse.c` 前后** 各跑一轮同 Profile，对比 **Agent 进程 CPU%**、**`pushed`** 是否异常升高、**`bus_drop`** 是否恶化。

## 3. 可选：纯解析微基准（本地）

不纳入默认 CI。可在开发机将 **`proto_parse.c`** 与极小 **`main`** 链成临时二进制，对 **固定 64+N 字节 SMB2 缓冲** 循环调用 **`edr_proto_find_shellcode_region`**（例如 **10^6** 次），用 **`clock_gettime`** / **`QueryPerformanceCounter`** 估计单次纳秒级耗时；对比扩展 Command 列表前后的差值，写入 **P2-PERF-4** §4 或本页修订记录。

## 4. 修订记录

| 日期 | 说明 |
|------|------|
| 2026-04-20 | T-SC-013：初版，与 **T-SC-011** 同步引入 |
