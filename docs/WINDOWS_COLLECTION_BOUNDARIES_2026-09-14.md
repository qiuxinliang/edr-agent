# Windows 采集边界与 3.2.481 完整性修复

## 采用的原则

参考 CrowdStrike 公开架构说明中“优先使用 Windows 正式接口、能安全迁移的处理放到用户态”的原则；不是照搬未公开实现，也不是把全部采集改成用户态。该说明同时明确保留内核能力及安全、可靠性前提。[CrowdStrike 官方架构说明](https://www.crowdstrike.com/en-us/blog/tech-analysis-kernel-access-security-architecture/)

本项目首先修复已有证据来源的绑定、保留和部署契约；不通过内核补丁、未文档化 Hook、关闭证书校验、取消进程代际检查来获得表面完整率。

## 能力放置不能混淆

| 能力 | 边界 | 对本次问题的帮助与限制 |
|---|---|---|
| Process callbacks | 驱动注册回调 | 创建通知能提供进程可执行文件的 FileObject；为创建时映像绑定提供更强来源，但不是普通用户态回调 |
| Registry filtering | 注册表过滤驱动 | 可观察/干预注册表操作；不能直接修复文件元数据或上下文落库预算 |
| Filter Manager | 文件系统 minifilter 框架 | 支持文件操作/对象生命周期证据；采用它需要独立驱动工程和发布验证 |
| Image verification callbacks | 内核安全扩展 | 可补充映像验证相关证据；不等于用户态 WinVerifyTrust 对一个事后路径的签名检查 |
| ETW | 操作系统事件源，用户态可消费 | 当前可落地：按实际 provider/schema 解码，关联 NameCreate/FileKey 与 Create/FileObject 的生命周期 |
| Secure ETW | 受保护的 ETW 能力 | 必须验证具体 provider、权限和部署条件；普通 ETW 会话打开成功不能宣称已获得受保护通道 |
| AMSI | 应用与反恶意软件集成接口 | 有助于脚本内容可见性；订阅 AMSI ETW 事件不等于实现并注册 AMSI provider，更不保证所有脚本均可见 |
| Protected Process Light | 受保护用户态服务 | 解决防篡改边界，不自动补出缺少的事件；反恶意软件受保护服务有 ELAM 和签名要求 |

依据：[PS_CREATE_NOTIFY_INFO](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_ps_create_notify_info)、[注册表过滤](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/filtering-registry-calls)、[Filter Manager](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/filter-manager-concepts)、[SeRegisterImageVerificationCallback](https://microsoft.github.io/windows-docs-rs/doc/windows/Wdk/System/SystemServices/fn.SeRegisterImageVerificationCallback.html)、[AMSI](https://learn.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal)、[反恶意软件受保护服务要求](https://learn.microsoft.com/en-us/windows/win32/services/protecting-anti-malware-services-)。

Windows 版本、架构、provider schema、权限和签名资质应分别验证。不能用“Win11/Server”一个标签替代能力实测，也不能把一个 provider 启用成功当作所有数据已采齐。

## 已验证问题及修复边界

### 文件读路径：复用已经存在的正式 ETW 对象关联

3.2.481 固定窗口中有 154 条 file_read_canonical_path_unresolved 凭据。这是源端明确报告不可评估，不是 154 条完整访问事件，也不是能直接归因于一个代码缺陷的漏采总数。

代码检查发现 `edr_collector_kernel_file_io_resolve` 对 Write 使用 FileObject/Create 历史，而 Read 被 `!is_read` 条件排除。仅观察 NameCreate 不足以覆盖当前会话内打开已有文件的路径。

修复 Read 复用现有 FileObject 历史，并保留：

- FileKey 和 FileObject 是两个不同标识，禁止相互强制转换或借用 opener PID。
- 路径只来自已解码的 NameCreate 或 Create，不能把内核指针当路径。
- Create/Close、事件时间、复用冲突、历史淘汰水位及 provider epoch 仍是边界。
- 两种有效绑定路径冲突时不可评估；已有歧义不能被后备路径掩盖。
- 读操作的实际 actor 仍由原有 StartKey/creation FILETIME 逻辑验证。
- 把 file_read_binding_quality 与 file_read_file_object 保留进类型化记录的来源字段。

Windows Read/Write 都携带 FileObject/FileKey，但经典 FileIo 文档与 manifest provider 的布局不能直接互换；实际解码继续走对应 provider 的 TDH。依据：[FileIo_ReadWrite](https://learn.microsoft.com/en-us/windows/win32/etw/fileio-readwrite)、[Microsoft Kernel-File manifest 示例](https://github.com/microsoft/Tx/blob/master/Generated/Microsoft_Windows_Kernel_File.cs)。

### 对“35 条本地文件读缺代际”的更准确解释

它们有路径、但 generation=0。代码中的 `verified_path_miss` 分支在签名 IR 的路径投影确认不匹配文件读规则后直接保留本地记录，不继续进行 live actor 查询。该集合不能当成 35 条失败的 P0 告警，也不能与 154 条 metadata 凭据逐条等同。

后续若要保留更完整的一般取证上下文，应复用已有的确切代际缓存，明确历史身份与操作时 token 的差异；不能为了字段覆盖率，在每个普通读事件上重复昂贵查询，或借用 PID 当前占用者的数据。

### 映像哈希：缺少的是绑定证明，不是哈希算法

3.2.481 现场 R-SIGN-001 告警已采到文件快照哈希与签名；`exe_hash` 为空，因为来源是 post_event_path_snapshot，而非经过绑定的执行映像。

本次不把快照质量强行升级。Windows 创建通知的 FileObject 可作为后续驱动设计的候选依据，但还需处理对象生命期、异步计算、可写映射、文件变化和进程映像语义；拿到 FileObject 本身也不是无限期不可变字节证明。

若要引入驱动/ELAM/PPL，需先确定支持系统矩阵、签名/认证渠道、驱动与用户态协议、HVCI/ARM64、安装升级回滚及性能验证。这不是把一个配置设为 true 就能完成的修复，本轮不新增驱动或假报这些能力。

### 关键上下文：容量约束不能混成固定事件计数

现场诊断的 `write_budget_context_dropped=15883` 是被拒绝的上下文写入尝试数，不是独立事件或告警数。固定 160 次/分钟的关键上下文限额，在有效关联窗口内仍可能拒绝动作和祖先进程证据。

取消该固定限额，继续复用现有 SQLite fact/ref 原子事务。普通 FILE_READ 的 best-effort 预算不变；关键上下文仍受数据库容量、保留期、有限关联窗口、进程代际及租户边界限制。磁盘容量不足与事务失败仍明确报错，不能承诺无条件无限保留。

本地诊断与心跳均以 `critical_context.mode=capacity_bound` 标注新语义；兼容计数字段 used/limit/dropped 为 0，而不是“允许 0 条”。总 used/limit 仅代表普通上下文限额。废弃 `EDR_EVIDENCE_CACHE_CRITICAL_CONTEXT_WRITE_BUDGET_PER_MIN`；不增加替代配置开关。

扩大保留范围不能扩大证据归属：内存前后窗口关联增加租户匹配，禁止同 PID/代际但不同租户的上下文混入。

### 取证组件：统一构建产物、发布目录和升级组件身份

现场取证回执报告固定路径 `collector/forensic_collector_builtin.exe` 缺失。代码检查发现独立 C 采集器虽有构建目标，但普通发布 ZIP 未把它加入该目录和原生组件身份清单；原地升级也仅接受平铺目录组件。这是已经证实的发布/升级契约缺口，不能仅据此还原现场此前每次部署所走的入口。

另核对 [win_3.2.481 正式发布](https://github.com/qiuxinliang/edr-agent/releases/tag/win_3.2.481) 的 AMD64 runtime ZIP：51 个条目中固定路径及任意目录同名 collector 均为 0；原生完整性清单的 24 项中 collector 为 0。资产 SHA-256 为 c68a21c8cec4cb77404e98e1bcf46a593169f600f6d7342f690968841df77ad2。该实证针对 AMD64 资产，不把它当成 ARM64 现场安装入口的证明。

修复让现有发布流程将该产物放入固定子目录、校验架构并绑定 SHA-256；ZIP 部署确认复制后的内容。USB 重打包刷新同一身份清单；原地升级只新增这个确切子路径的支持，沿用候选文件、提交、备份与回滚。

二进制热升级必须比较取证组件身份。旧包之间原有比较仍可执行；从不含组件的旧包升级到新增组件的包，不能伪装成仅替换 FDSensor 的 binary_hot，需要发布已有 runtime_bundle 或 installer_required 升级类型。旧安装基线不能被要求拥有尚未发布的文件，而新目标安装和升级必须验证该文件。

## 验证与上线验收

文件关联定向验证包括无 NameCreate 的打开/读取、关闭后延迟解码、指针复用、冲突及历史淘汰，以及 Read/Write v0/v1、32/64 位指针布局。

本轮已有的验证结果：

- 本地 file_object_binding、detection_sensor_bridge、windows_a44_collector_contract：3/3。
- amd64/arm64 collector_win.c 翻译单元交叉编译通过；两架构 kernel_file_io_windows 完整测试目标链接通过。
- UTM Windows ARM64 原生运行交叉生成的 kernel_file_io_windows：exit 0，2026-09-14T11:23:58Z。
  运行 EXE SHA-256：9c314c9f7adee000a46270a504d426b065d4c285be6037d9b223d5f9dc14f4a1。

- 完整 `edr_agent` 与运行时测试目标本地构建通过；`agent-runtime-gate` 30/30 通过。本地构建使用真实 SQLite/OpenSSL/Curl，但 PCRE2 为显式非生产 stub，不能验证生产签名规则匹配链路。
- ASan/UBSan：file_object_binding、detection_sensor_bridge、local_evidence_cache_candidate，3/3 通过。
- 关键上下文回归：161 个不同事件形成 161 facts / 161 refs，精确重放无新增；20 个候选共享 4 facts / 80 refs；提交失败无部分事实/关联，恢复后可完整重试。容量和保留期清理、跨租户隔离测试通过。
- 真实 collector Windows 测试目标 amd64/arm64 交叉链接通过；UTM 原生 ARM64 运行最终无 TDH 预热版：exit 0，2026-09-14T11:51:01Z，21 场景 × 4 种版本/指针布局通过。EXE SHA-256：a3a43ab3475360aea1f67298e0f293c31edaf09757054c3f4388e17f107231ef。
  首版夹具失败来自漏初始化 Agent owner PID，触发了 self-filter；按生产启动合同补齐，不改断言或放宽生产自过滤。
- 热升级兼容性 Python 测试 7/7，包装 C 契约 1/1 通过。
- 两项发布/升级 PowerShell 夹具在 UTM Windows PowerShell 5.1.26100.9444 原生通过，2026-09-14T11:54:20Z：有效包在三种升级类型通过、缺 collector 包明确拒绝；确切子路径校验、新增/替换/回滚及错误哈希拒绝。只使用临时夹具目录，没有操作实际安装目录、服务或安全策略；其中日志持久化为测试隔离点，不能宣称已验证进程崩溃后的升级恢复。
- Windows 构建依赖回归 17/17 通过；加入两项 PowerShell 测试后，再验证双生成器依赖完整性、失败阻断和共享构建/运行入口，3/3 通过。两个工作流 YAML 语法解析通过。新增 C/PowerShell 用例均接入现有 Windows 发布测试集合。

这些是代码回归与真实 Windows API/解析夹具验证，不是 MSVC 原生编译证明，也不是替换 Agent 后的真实攻击采集验收。不能据此宣称原 154 条缺失已全部消除。

新安装包部署后仍需对相同终端、同一事件窗口和代际元组验证：源日志→本地候选/可物化工件→服务端源事件→告警→取证回执。长字段验证需实际长命令行/路径样本；历史 393 字符样本一致不能替代边界测试。保持自动隔离等安全策略，不以停用防护换取测试通过。
