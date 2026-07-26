# Windows Shellcode / 取证 — 按模块 TODO（优先）

本文档相对 `edr-agent` 当前实现整理后续工作，**优先级：Windows §17 Shellcode 与远程取证链路**，其次为与 SOAR/平台的衔接。实现状态基线见仓库根目录 `README.md` §17 与 `command_stub.c` 中 `forensic`。

**Webshell `UploadFile` 联调步骤**见 **`docs/AGT009_FORENSIC_UPLOAD_E2E.md`**（**AGT-009**）。

---

## P0 — Shellcode 检测与证据留存（Windows）

### `src/shellcode_detector/windivert_capture.c`

- [x] **IPv6**：已支持 `ipv6` 头分支 + `InetNtopA`；`WSAStartup` 配对清理。
- [x] **PCAP（初版）**：`forensic_save_pcap` + 非空 `forensic_dir` 时，无环形则 **单包** raw IP（228/229）；**`forensic_ring_slots`>0** 时维护环形缓冲，告警写 **`shellcode_ring_*.pcap`（多帧，DLT=EN10MB 以太封装）**。
- [x] **环形增强（部分）**：告警 ETW1 增加 **`ring_trigger_slot`**、**`ring_oldest_ns` / `ring_newest_ns` / `ring_span_ns`**（触发帧槽位与缓冲内时间跨度）；**`shellcode_json=`** 单行结构化字段（score、dpt、spt、proto、det、rule）。**pcapng**、按时间窗 UI 高亮仍属后续。
- [x] **载荷摘要**：告警 ETW1 增加 **SHA256(证据区)**；可选 **preview_hex**（`evidence_preview_bytes`，默认 0 关闭）。
- [x] **驱动/DLL 健康**：`OpenSCManager` / `OpenService` 查询 `WinDivert` / `WinDivert1.4` 状态一行日志。

### `src/shellcode_detector/proto_parse.c` / `shellcode_heuristic.c` / `shellcode_known.c`

- [x] **WinDivert 端口配置化**：`[shellcode_detector].windivert_tcp_ports` 逗号列表；空 = 内置 `kWdFilter`；非空 = 自定义过滤器 + `monitor_allows` 仅按列表匹配。
- [x] **协议覆盖扩展（部分）**：**明文 HTTP/1.x** 任意端口：识别请求/状态行 + 头部后的 body 区再扫描（`EDR_PROTO_KIND_HTTP`）。**HTTPS/TLS** 仍为密文，仅整体启发式（依赖样本与端口列表）。
- [x] **误报调优（部分）**：TOML **`heuristic_score_scale`**（默认 1.0）缩放启发式分数；**`yara_rules_reload_interval_s`**（秒，0=关闭）周期性重编译规则目录。现网权重与 YARA 规则内容仍依赖运营迭代。

### `src/preprocess/behavior_from_slot.c`（及与总线联动）

- [x] **高优告警 → 自动处置（可选端上）**：分数 ≥ **`auto_isolate_threshold`** 时仍为 **`priority=0`**；若 **`EDR_SHELLCODE_AUTO_ISOLATE=1`** 或 TOML **`auto_isolate_execute`**，且 **`EDR_CMD_ENABLED`/`allow_dangerous`**，则执行与 **`isolate`** 相同的标记 + **`EDR_ISOLATE_HOOK`**（**每进程最多一次**）。服务端 playbook / 人工确认仍推荐并行使用。
- [x] **告警字段（部分）**：ETW1 增补 `mitre=T1210`、`forensic_kind`、`pcap_stem`、`forensic_frames`（环形）；`behavior_from_slot` 将上述与 detector/rule/score 一并写入 `script_snippet` 摘要；`apply_mitre_hints` 仍写入 **T1210**。

---

## P1 — 远程取证指令与打包（Windows 为主，POSIX 对齐）

### `src/command/command_stub.c` — `do_forensic` / `forensic_copy_lines`

- [x] **`forensic_copy_lines` 去 `system(copy)`**：Windows **`CopyFileA`**、POSIX **`open`/`read`/`write`** 逐文件复制（`EDR_FORENSIC_COPY_PATHS=1`）。
- [ ] **打包去 `system(tar ...)`**：`bundle.tgz` 仍通过 **`cmd /c tar`** / **`tar`**；后续可改为 **CreateProcess** 调 **`tar.exe`**、或 **libarchive**/miniz，减少注入面并改进错误码。
- [x] **清单增强（部分）**：`manifest.txt` 已写 **hostname**、**endpoint_id** / **tenant_id**、**`payload_sha256`**（完整指令载荷，小写 hex）；**不再**把原始 payload 二进制写入 manifest。**用户、卷序列号** 仍待做。
- [ ] **结构化 payload**：支持 JSON 路径列表 + **可选内存/注册表键**（仅文档化范围，分阶段实现）。
- [ ] **上传**：对齐 `ingest.proto` `UploadFile`，取证完成后 **可选自动上传 bundle**（与 webshell 取证同一 RPC），失败保留本地 `bundle.tgz`。

### `include/edr/config.h` / `src/config/config.c` — `[shellcode_detector].forensic_dir`

- [ ] **Shellcode 命中落盘**：当前 **webshell** 使用 `forensic_dir`；**WinDivert 路径**尚未统一写入该目录。完成 P0「PCAP/载荷」后，与 **统一根目录**（`EDR_FORENSIC_OUT` vs `forensic_dir`）语义在文档与代码中划清。

---

## P2 — 平台、SOAR 与运维

- [ ] **Playbook 模板**：Shellcode 高优 → 自动 **collect_forensic**（限定路径）→ **人工确认** → 隔离；文档写入 `docs/SOAR_CONTRACT.md` 示例。
- [ ] **控制台**：告警详情展示 **是否已上传 PCAP/样本**、存储 **MinIO key**（若已实现 gRPC 上传）。
- [ ] **性能**：WinDivert 队列参数与 `max_payload_inspect` 在生产环境压测；背压时丢弃策略与 metrics。

---

## 非目标（本清单不展开）

- Linux 侧 §17（无 WinDivert）；见路线图 **P7 eBPF** 与 `README.md`。
- 纯内核无载荷攻击（需驱动/ETW 其它通道）。

---

## 参考路径

| 模块 | 路径 |
|------|------|
| WinDivert 捕获 | `src/shellcode_detector/windivert_capture.c` |
| 协议/启发式/YARA | `proto_parse.c`, `shellcode_heuristic.c`, `shellcode_known.c` |
| 远程取证指令 | `src/command/command_stub.c` (`do_forensic`) |
| Webshell 取证上传 | `src/webshell_detector/webshell_forensic.c`, `grpc_client` |
| 配置 | `agent.toml.example` `[shellcode_detector]` |
