# AVE 端点检测实现说明

## 当前边界

端点 AVE 使用规则、签名/哈希信任、IOC、租户误报抑制及行为启发式。它不包含 ONNX Runtime、端侧模型、模型热更新、FP32 训练或联邦学习。

保留的安全边界包括：TLS/mTLS、签名化远程命令、策略真实性、队列耐久性、证据完整性、安装回滚和审计；它们不是本次简化目标。

## 文件扫描顺序

1. 对目标文件计算 SHA-256，并记录 `edr_ave_file_fingerprint`。
2. Windows 上执行 L1 证书信任检查（`WinVerifyTrust`、企业白名单和吊销策略）。可信系统或厂商文件得到 `VERDICT_TRUSTED_CERT`。
3. 使用 L2 文件哈希白名单抑制已确认的良性项。
4. 使用 L3 IOC 哈希库识别已知恶意文件；关闭预检时仍会在规则阶段后复核，避免漏报。
5. 对未命中的文件保留 clean 基线，并由 L4 不可豁免策略和实时行为证据决定是否升级风险。
6. 最后执行租户级误报抑制；审计信息保留原始判定、最终判定、规则层和文件指纹。

## 行为检测

`AVE_FeedEvent` 将经过采集和预处理质量门禁的行为送入有界 MPMC 队列。后台消费者维护按 PID 聚合的特征、MITRE 相关标志和时间窗口计数，并结合 PMFE、Shellcode、WebShell 与 IOC 信号生成行为异常分。

事件量过大时可使用 `EDR_AVE_ETW_FEED_EVERY_N` 分频，或使用 `EDR_AVE_ETW_ASYNC` 让 ETW 回调与行为处理解耦；这两个开关不改变 P0 规则、证据和命令审计路径。

## 验收

- 本地：`cmake --preset any-ninja-smoke -DEDR_BUILD_TESTS=ON`，随后构建并执行 `ctest`。
- Windows 发布前：执行 PowerShell 语法验证、安装包架构/能力清单合同测试，以及 Setup EXE 的安装、升级、回滚、卸载测试。
- 平台联调：验证 HTTPS 升级、命令签名、端点健康上报和卸载回执闭环。
