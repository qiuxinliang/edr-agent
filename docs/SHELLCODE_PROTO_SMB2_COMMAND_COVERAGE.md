# SMB2 / SMB1 — `proto_parse` 载荷区与 Command 覆盖（T-SC-010 / T-SC-011 / T-SC-012）

**实现**：`edr-agent/src/shellcode_detector/proto_parse.c`（`edr_proto_find_shellcode_region`）。**权威协议**：**[MS-SMB2]** 2.2.1.1 SMB2 Header — `Command` 为 **UINT16 LE** 位于 SMB2 头偏移 **12**。

## 1. WinDivert 默认端口（与 Command 归纳的关系）

**`windivert_capture.c`** 内置过滤器 **`kWdFilter`** 监视的 TCP 端口包括 **445 / 139**（SMB）、**3389**（RDP）、**5985–5986**（WinRM）、**135**（RPC）、**389 / 636 / 3268 / 3269**（LDAP）及对称 **SrcPort**；与 **`[shellcode_detector].windivert_tcp_ports`** 可覆盖。 exploit 相关明文载荷多出现在 **445（SMB2）** 与 **139（SMB1 + NetBIOS）** 上，故扩展 **SMB2 Command** 白名单主要服务 **445** 场景。

## 2. SMB2 — 当前「可扫描」Command 列表

对下列 **`Command` 值**（LE），在 **NetBIOS 偏移（`data[0]==0` → `off=4`）** 之后识别 **`\xfeSMB`**，且长度 ≥ **64** 字节头时，将 **`payload_off = off + 64`**，其后至包尾视为 **扫描子区间**（与 Write/IOCTL 历史行为一致；**Negotiate** 仍标记 **`is_negotiate=true`**）。

| Command (hex) | 名称（MS-SMB2） | 纳入理由（摘要） |
|---------------|-----------------|------------------|
| 0x0000 | NEGOTIATE | 已有；握手后常跟异常协商利用链 |
| 0x0001 | SESSION_SETUP | 会话建立阶段可携带大块交换数据 |
| 0x0003 | TREE_CONNECT | 树连接请求体可含异常路径/载荷 |
| 0x0005 | CREATE | 打开文件/管道，常见利用载体 |
| 0x0008 | READ | 读响应/请求体可含返回数据 |
| 0x0009 | WRITE | 已有；写管道/文件 |
| 0x000B | IOCTL | 已有；RPC 风格 IOCTL 常见 |
| 0x000C | CANCEL | 低量；为简化实现与测试一致性纳入 |
| 0x000D | ECHO | 低量；同上 |
| 0x000E | QUERY_DIRECTORY | 目录查询缓冲区 |
| 0x000F | CHANGE_NOTIFY | 通知缓冲区 |
| 0x0011 | QUERY_INFO | 元数据查询 |
| 0x0012 | SET_INFO | 元数据设置 |

**明确不解析为 SMB2 载荷区**（返回 **`EDR_PROTO_PARSE_NOT_INTERESTING`**）的示例：**LOCK (0x000A)**、**LOGOFF (0x0002)**、**CLOSE (0x0006)** 等控制型 PDU；后续若情报指向具体族，再按 **T-SC-011** 模式加单测 + 合成 carrier。

## 3. SMB1 — Command 白名单（32 字节头后扫描）

| `cmd`（偏移 `off+4`） | 说明 |
|----------------------|------|
| 0x25 | SMB_COM_TRANSACTION（EternalBlue 等） |
| 0x32 | SMB_COM_TRANSACTION2 |
| 0x71 | SMB_COM_TREE_CONNECT_ANDX |
| 0xA2 | SMB_COM_NT_CREATE_ANDX |

**注意**：**EternalBlue** 内置匹配仍要求 **`EdrProtoKind_SMB1`**；扩展 cmd **仅**影响 `proto_parse` 是否给出 **payload 子区间**，不改变 **`shellcode_known.c`** 中 SMB1 签名逻辑。

## 4. 相关文档与测试

- **单测**：`tests/test_shellcode.c`（SMB2 扩展命令、SMB2 Lock 负例、SMB1 `0xA2`）。  
- **语料**：`petitpotam_smb2_sess01.bin` / `petitpotam_smb2_create05.bin`、`eternalblue_smb1_cmd71_v00.bin` 等见 **`emit_baseline_variants.py`**。  
- **性能对比**：**T-SC-013** → **`docs/SHELLCODE_PROTO_PARSE_PERF.md`**、**`docs/P2_PERF4_SYNTHETIC_TRAFFIC_REPORT.md`**。
