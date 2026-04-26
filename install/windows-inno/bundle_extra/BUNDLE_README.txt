EDR Agent — 本 zip / Inno 完整负载说明（与 package_bundled_layout.sh / EDRAgentSetup.bundled.iss 一致）
================================================================================

一、本包意图：覆盖「标准 Windows 端点」全部核心能力
------------------------------------------------
在已正确配置 agent.toml 并完成与平台注册的前提下，本目录应足以支撑：

  • 进程 / ETW 等采集与事件总线、预处理、去重与 L2/L3/进程名门控（环境变量可调）
  • 动态前置规则：同目录 agent_preprocess_rules_v1.toml（未在 agent.toml 内写满 [[preprocessing.rules]] 时自动加载）
  • AVE：静态 ONNX + 行为 ONNX（models\ 下，与 agent.toml [ave].model_dir 一致；Windows 默认同目录\models）
  • 证书 Stage0：WinVerifyTrust + 内置信任链/厂商规则；可选 SQLite 见 data\README_OPTIONAL_DBS.txt
  • 上云：gRPC 或 HTTP 入站（由配置与构建决定）
  • 离线缓存队列：首次运行在配置路径生成 edr_queue.db（不必随包提供空库）
  • 安装/注册/开机任务：edr_*.ps1、edr_agent_install.ps1

二、本包不随包部署、需平台或单独交付的部分（非「缺件」而是约定）
--------------------------------------------------------------
  • 证书 / IOC / 行为策略等可选 SQLite 库：由平台下发或你们基建放入 data\ 并在 agent.toml 中配置路径
  • 攻击面 GeoIP：GeoLite2-City.mmdb 等需自行放置并配置 geoip_db_path
  • 若编译开启 YARA/webshell/专项规则：规则目录需按版本另发（本仓库默认未必含生产规则包）
  • §17 Shellcode/WinDivert：依赖系统侧 WinDivert 驱动与 DLL，不在本 zip 内
  • 联邦学习热修、模型热更新 blob：由平台 / FL 流程下发
  • 真实 endpoint/tenant、API 地址、Token：由 enroll 或手工写入 agent.toml

三、打包容器自检（发布前在构建机执行）
------------------------------------
  • models\ 下应至少包含 behavior.onnx 及用于静态推理的另一 .onnx（常见名 static.onnx；以引擎逻辑为准）
  • 与 edr_agent.exe 同目录应含完整运行时 DLL（与 CMake/vcpkg 实际链接一致，不仅 onnxruntime/libcurl）
  • 从 agent.toml.example 复制为 agent.toml 后按环境填写 [server] / 平台相关段

四、与「仅 GitHub Release exe+DLL zip」的区别
------------------------------------------
本包额外包含：models、agent_preprocess_rules_v1.toml、示例配置与安装脚本，用于性能与检测路径可对标的完整端形态。

(BUNDLE_README — keep in sync with package_bundled_layout.sh and EDRAgentSetup.bundled.iss)
