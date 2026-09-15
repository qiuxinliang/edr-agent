# Agent 3.2.501 UTM 实测

2026-09-15，时间均为 UTC。目标 WIN-FAC3AC1PS5O。
结论：**FileRead 历史进程代际关联修复通过本次小样本实机验证；上下文完整性整体仍未通过。**
本轮只执行一个无害标记文件写入/读取案例及只读诊断，没有修改运行代码、策略、隔离状态或发布资产。

## 发布与实际进程

- `win_3.2.501` 标签准确指向 `94d41e8f02459ab83881f3b1898d43ceedeb897e`。
- Release 非草稿，published_at=`2026-09-15T11:53:13Z`。
- ARM64 官方 FDSensor SHA256 与实机均为
  `7d09d8c898920168593c1d156ebd463acf0db9bdbed40b2525fc77fd2d3e688c`。
- Agent PID=8408，启动时间 12:12:43.518135Z；12:14:16 实机校验版本为 3.2.501。
- 实机隔离规则为 0，取证进程为空；服务端 online/normal。

发布核验纠正：先前只查询 `/releases/latest` 不足以认定没有包含修复的发布。
3.2.500 在 11:53:36Z 发布，比 3.2.501 晚 23 秒；Latest 指针不等于最高语义版本。
应直接核验目标 tag、commit、发布状态和资产摘要，而非仅用 Latest 判断修复可用性。

## 操作真值与本地缓存

案例时间 12:15:44.3497873–12:15:44.5561976。
PID=2696，实际进程 creation FILETIME=`134339481430542295`。
创建并读取 `C:\Windows\Temp\EDR501-Uh0KGY\script-fact.ps1`，内容为 58 字节无害注释，
文件不执行；读取内容与写入内容一致。测试文件保留供复核，不涉及凭据、敏感文件或外部网络。

12:22:24 以 SQLite OPEN_READONLY 查询本次时间窗与唯一文件标记，12:25:09 补查截断字段：

| 记录 | 数量 | StartKey | creation FILETIME | 命令行长度 | source_truncated_fields |
| --- | ---: | --- | --- | ---: | --- |
| ProcessCreate | 1 | 11821949021855555 | 134339481430542295 | 1308 | 空 |
| 文件创建 type 10 | 1 | 同上 | 同上 | 1308 | 空 |
| 文件写入 type 11 | 1 | 同上 | 同上 | 1308 | 空 |
| 文件读取 type 6 | 2 | 同上 | 同上 | 各 1023 | 均为空 |

两条 FileRead 的 `process_generation_source` 均为
`file_read_process_tree_cache_generation`，对象路径正确，creation 与操作真值一致。
与 3.2.499 同类案例两条读取 StartKey/creation 均为 0 相比，**本次为 2/2 正确关联**。
这不是总体召回率或全部 Windows 平台通过率，也不能把两条 ETW 记录当作两个独立人工读取动作。

可追踪本地 candidate ID 后缀（共同前缀为端点的 `p0-...-e-`）：

- ProcessCreate：`e127b2b76fd35dc541ea13688aa16c80a3048921c04db61363034b426e1435a9`
- create：`d67965620b76c8dfe037529b23fc1ad092a78af7b067cb35f5e3d968e7237076`
- write：`9aa11c4a997e46476023b272e23c01e4ebe3b79f8d19620e07954a51cb6d6ca9`
- read：`db3f1e9db81c7272cc6053a7f01d5c0c1ec22bc9a6ba3307209a684c59f916e0`
- read：`8ce93d34d4c831a8047e50da033109b66a56cf6dbf79ebdc161c9331dd11d901`

## 尚未解决的保真问题

### 命令行短值未被完整事实替换

同一代际的 ProcessCreate、create、write 命令行为 1308 字符，两条 read 为 1023，
且 read 的 `source_completeness` 和 `source_truncated_fields` 均为空。
因此不能把 read 当前命令行视为已验证完整，也不能通过身份修复成功掩盖这项差异。

当前源码显示一条与实测吻合的具体路径：

1. `collector_win.c` 中 `EdrCollectorPidCacheEntry.cmdline[1024]` 会用 `edr_copy_trunc` 保存命令行，未携带相应截断标记。
2. collector 的 enrich/writeback 将该短值写入 FileRead。
3. `process_cached_generation.h` 仅在 `br->cmdline` 为空时从历史进程缓存补命令行；已存在的短值不会被替换。

这是字段来源优先级与截断来源传播问题，不是必须继续加大采集量。
本轮没有修改它。后续修复需验证：已知预览不冒充完整事实、同代际精确来源可正确消费、
冲突来源不被按长度盲目覆盖，以及带非空短命令行的回归案例。

read 用户名为空；代际绑定函数并不声称恢复读取时 token。是否需要用户上下文应按具体规则谓词评估，
不能以所有字段填满为目的伪造用户名或自动启动整机补证。

### 服务端可见性尚未闭环

本次按唯一标记找到的服务端记录是 create：
`epev_8ad0ec9a8e_1789474549772784000`，时间 12:15:44.528，
StartKey/creation 正确，命令行 1307 字符。

本地 write 和两条 read 在服务端尚未找到对应标记记录。
read 的规则不相关分支设计上只本地保留并 return，不能仅因没有上传就判定丢包；
但必须说明相应消费者如何按需回查，不能宣称端到端证据已可用。
write 的实际上传/聚合处置原因本轮未定位；1308 与 1307 的表示差异也尚未逐字节归因。
同 PID 的其他文件与无路径 metadata 不纳入该标记案例分母。

## 补证、隔离与通信

- 12:22:46 的新 Agent 健康快照：report_events_v2_ok=101、fail=0，控制租约有效；
  candidate_rejected=0、queue_dropped=0。这是当前进程快照，不代表历史全链路无损。
- Worker 45225 更新起点 11:48:33.800，到 12:26:36 查询，**约 38 分钟没有新增终端命令**，
  包括没有新增取证或隔离命令。
- 同窗口预算阻止 131 条、其他门禁阻止 119 条、状态暂空 2 条，不能将后两类冒充预算效果。
- 收尾时 Agent 3.2.501 online/normal，last_seen=12:26:21.771；没有为了测试关闭自动隔离。

## 验收边界与下一步

- 本次通过：官方发布/运行版本一致、FileRead 精确历史进程代际关联、预算部署后的持续收敛。
- 尚未通过：命令行精确保真、文件写入上传处置追踪、完整读取上下文的消费链。
- 未测试：新网络案例、文件并发/PID 重用压力、Windows Server/AMD64、LLM 消费、历史 220 条及四组回放。
- 下一步先修复并测试短值/完整来源选择，再核对保留与上传契约；不扩大采集、取消身份边界或调整全局评分来掩盖缺口。
