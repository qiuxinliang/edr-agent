# 短网络事件内部准入观测

## 当前问题与边界

2026-09-23，3.2.521 的两次短进程回环连接均到达服务端，源/目的 IP、
端口、TCP 协议及进程代际保持一致。其中一次有独立 Kernel-Network ETW
源记录，但独立会话不能证明 Agent 私有回调中的准入决定。历史缺失尚未
复现；不能宣布 actor 查询、兴趣过滤或队列拥塞中的某一项就是历史根因。

本改动仅增加本地诊断，不改变 actor 校验、sensor-interest、P0、普通网络
过滤、队列优先级、遥测上传、LLM 预算或自动处置。默认关闭。

## 明确的输出位置与启用条件

在**包含本改动的新 Agent 进程**启动环境中设置：

```text
EDR_NETWORK_ADMISSION_TRACE_PATH=C:\ProgramData\FDSecurity\diagnostics\network-admission-<本次唯一标记>.jsonl
EDR_NETWORK_ADMISSION_TRACE_PORT=<本次测试预先保留的回环监听端口>
```

- 必须使用现有部署/服务启动 owner 配置该进程的环境；在另外一个交互式
  PowerShell 中设置 `$env:` 不会改变已运行的 Windows 服务环境。
- PATH 是明确的 JSONL 输出文件，而不是目录；父目录须已存在，使用唯一文件名。
  只接受本地盘符绝对路径，拒绝 UNC、相对路径及 ADS；不覆盖、追加或删除已有文件。
  文件采用受保护 DACL，仅 SYSTEM、管理员及文件所有者可访问。
- 诊断仅选取源、目的均为 `127.0.0.1` 或 `::1`、且目的端口匹配的事件。
  同端口不等于同进程，核对时仍必须使用 PID、源事件时间、代际及五元组。
- 从 collector 启动开始最多 **120 秒**，保留前 **128 条完成事件**；这只是
  临时观测边界，不是生产事件采集或缓存限制。内存固定128条，不循环覆盖；
  文件每行最多4096字节，总上限小于526000字节。未写出的诊断有独立计数。
- 启动立即写 `session` 行。事件在回调/解码线程只写有界内存，不做文件 I/O；
  既有 `edr_collector_get_health` 健康采样负责写盘，正常停止且 decoder 全部
  join 后最终排空。默认健康周期通常60秒，以实际配置为准；采样周期较长或
  健康上报未配置时，不能承诺120秒内文件已经完整。不要为了取诊断擅自重启 Agent。
- 截止后不再选取新事件；下一次健康采样等待已进入的事件完成后写 `summary`
  并关文件。不新建线程、定时服务、表、上传通道或在线命令。
- 文件创建/写入/序列化失败只停诊断，不能改变生产准入或发布结果。创建失败
  会输出带 Win32 错误的 stderr；文件不存在、只有头或缺少有效尾行都不能算
  采样成功。写盘错误时不会伪造成功尾行。

该开关为本次间歇性准入调查服务；定位结束移除部署环境中的两项设置，归档后
按现有运维流程清理本次文件。不得把它长期全量开启或当成新的证据缓存。

## 每条事件如何对账

生产 decoder 只解析一次，诊断读取原有 `EdrBehaviorRecord`，不额外调用
`edr_behavior_from_slot`，避免额外分配事件 ID 或影响既有解析副作用。
一条 JSON 记录包含准入前事实、实际执行结果及发布结果：

| 字段 | 含义 |
| --- | --- |
| sequence | 本次诊断关联序号，不是服务端 event_id |
| provider、event_id、opcode | ETW 来源及事件描述符 |
| event_ns、observed_filetime | 源 UTC 纳秒时间、诊断观察时刻 Windows FILETIME |
| header_pid、payload_pid、decoded_pid | 分别为 logger、兴趣解析的 payload actor、准入解析的 PID；不能相互冒充 |
| src_ip/src_port、dst_ip/dst_port、protocol | 准入前已解码五元组 |
| input_start_key、input_birth_filetime | live actor 查询前的身份；0为未提供，不能借用 logger 代际 |
| actor_bound、actor_reason、actor_win32_error | 同句柄绑定结果；Win32错误仅在直接API失败时取值，0不等于绑定成功 |
| actor_start_key、actor_birth_filetime | actor 查询后身份 |
| process_start_key、process_creation_filetime_100ns、process_name | 既有缓存补全后、兴趣判断前身份 |
| interest_admitted | 兴趣清单是否放行 |
| identity_writeback | slot 身份及必要命令写回是否完整 |
| collector_admitted、reason | 最终 collector 准入及实际返回分支 |
| bus_published | 已准入 slot 是否成功进入事件总线 |

阶段值 `1=成功/允许`，`0=失败/拒绝`，`-1=未执行`。
所有64位时间、代际和序号使用十进制字符串，避免JSON浮点精度损失。
不输出命令正文、镜像完整路径、认证材料或网络内容。

例如 `actor_reason=network_actor_open_failed`、`interest_admitted=0`、
`reason=sensor_interest_rejected`、`bus_published=-1` 才证明该样本在
actor 不可用后被兴趣过滤；`collector_admitted=1` 且 `bus_published=0`
则是队列发布失败，不可归为源头未采集。

`summary` 的 selected 应等于 written + diagnostic_contention_dropped +
diagnostic_limit_dropped（完整结束、inflight=0、write_error=0时）。诊断
容量/锁竞争丢样不是生产丢包。缺少完整尾行、计数不对账或未观测区间仍为未知。

### 不得扩大的结论

- 覆盖从 `edr_collector_decode_mapped_event` 中成功构造 slot 并进入
  `edr_collector_should_admit_slot` 到总线发布。同步与A4.4解码都使用此路径。
- 不是原始provider全量抓包。零时间戳、未映射类型、TDH无法构造slot、
  解码不出目标端口/回环地址的事件不在采样内；也不覆盖开启
  `EDR_COLLECTOR_ADMIT_ALL` 后绕过正常解析的路径。禁止为诊断启用该绕过开关。
- 文件里没有某事件不能单独证明源头未采集，须先验证窗口、范围、尾行、
  丢样计数，再与同时间窗的独立provider记录对照。
- 总线发布成功不证明后续缓存、上传、告警或LLM收到。仍须沿原事件继续对账。

## 验证契约与下一次现场取证

既有 `etw_network_decode_native` 测试扩展覆盖：开关前后slot逐字节相同、
actor失败、代际拒绝、兴趣过滤、payload/logger PID区分、队列失败、文件即时
读回、JSON转义、64位精度、范围排除、128条上限、并发计数对账、期限、拒绝
覆盖历史文件及模拟磁盘写入失败。文件采集器测试同时链接该诊断模块，防止
共用collector路径的新链接缺口。测试替身只隔离外部进程/总线/写盘等I/O，
准入与诊断序列化均为生产代码。

下一次部署核验包含本改动的实际二进制后，预留唯一回环目的端口及文件名，
在120秒窗口内运行一例短连接。取回JSONL及独立ETW记录，以事件时间、PID、
代际和五元组对账；先看首次拒绝位置，再决定修复。保持现有检测/隔离策略；
隔离或通道失效立即停止，不自行解除。不把离线回归通过称为旧缺失样本已修复。

## 本次实现验证（2026-09-23）

| 检查 | 结果与限制 |
| --- | --- |
| 实际CMake网络/文件测试目标 | MinGW x64交叉编译、链接通过，非MSVC/ARM64原生构建 |
| UTM Windows执行网络测试 | exit=0；上述准入、落盘、并发、容量、期限、错误场景通过；未启动ETW会话或真实网络流量 |
| UTM Windows执行文件测试 | exit=0；真实metadata/resolver/slot/gate路径，v0/v1及32/64位fixture通过 |
| 宿主发布依赖回归 | `test_windows_release_gate.py` 18项通过；不代替Windows发布构建 |
| collector/A4.4接线契约 | 宿主执行通过；只证明静态调用接线 |
| 新诊断模块编译告警 | MinGW `-Wall -Wextra -Werror`语法检查通过 |

运行中的3.2.521未替换或重启，PID4852及启动时间保持不变；策略v470、规则
r283-245523c2、normal/online保持。4个唯一命名测试上传文件在哈希核验后删除，
宿主保留产物及回执。该结果证明离线生产路径回归，不证明新诊断已在在线Agent生效，
也不证明历史间歇性网络缺失已修复。
