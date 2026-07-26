# EDR Agent 环境变量配置模板
# 用法: . .\edr_env_template.ps1
# 或: Import-Module .\edr_env_template.ps1

# ============================================
# P0 动态行为引擎配置
# ============================================

# P0引擎开关 (1=启用, 0=禁用)
# 默认: 1 (启用)
$env:EDR_P0_DIRECT_EMIT = "1"

# P0调试日志 (1=启用, 0=禁用)
# 默认: 0 (禁用)
# 生产环境建议保持禁用
$env:EDR_P0_DEBUG = "0"

# P0去重窗口（秒）
# 默认: 10
# 相同规则+相同PID在此时长内只告警一次
$env:EDR_P0_DEDUP_SEC = "10"

# P0全局速率限制（每分钟）
# 默认: 0 (不限)
# 设置为正数启用限制
$env:EDR_P0_MAX_EMITS_PER_MIN = "0"

# ============================================
# 预处理模块配置
# ============================================

# procname_gate白名单（逗号分隔）
# 默认: powershell.exe,pwsh.exe,cmd.exe (严格模式，仅3个最高风险进程)
# 生产环境稳定后可逐步添加: mshta.exe,rundll32.exe,regsvr32.exe,certutil.exe,cmstp.exe
$env:EDR_PROCNAME_GATE_WHITELIST = "powershell.exe,pwsh.exe,cmd.exe"

# procname_gate开关 (1=启用, 0=禁用)
$env:EDR_PROCNAME_GATE_ENABLED = "1"

# procname_gate非白名单进程保留比例 (permille, 1/1000)
# 默认: 1 (0.1%)
$env:EDR_PROCNAME_GATE_KEEP_UNKNOWN_PERMILLE = "1"

# 去重窗口（秒）
# 默认: 5 (严格模式)
$env:EDR_DEDUP_WINDOW_SECONDS = "5"

# 每PID每秒速率限制
# 默认: 20 (严格模式)
$env:EDR_RATE_LIMIT_PER_SEC = "20"

# L2 Split开关 (1=启用, 0=禁用)
$env:EDR_PREPROCESS_L2_SPLIT = "0"

# ============================================
# A44 分叉路径配置
# ============================================

# A44开关 (1=启用, 0=禁用)
$env:EDR_A44_ENABLED = "1"

# A44线程数
# 默认: 4
$env:EDR_A44_NUM_THREADS = "4"

# A44无锁队列开关 (1=启用, 0=禁用)
$env:EDR_A44_LOCKFREE_ENABLED = "0"

# A44无锁队列容量
$env:EDR_A44_LOCKFREE_CAP = "4096"

# ============================================
# 事件编码和传输配置
# ============================================

# 事件编码格式: wire, protobuf, protobuf_c
$env:EDR_BEHAVIOR_ENCODING = "protobuf_c"

# LZ4压缩级别 (1-12)
# 默认: 6
$env:EDR_LZ4_COMPRESSION_LEVEL = "6"

# 批量刷新超时（秒）
$env:EDR_BATCH_FLUSH_TIMEOUT_S = "5"

# ============================================
# 配置完成提示
# ============================================

Write-Host "[EDR] Environment configuration loaded successfully" -ForegroundColor Green
Write-Host "[EDR] P0 Direct Emit: $($env:EDR_P0_DIRECT_EMIT)"
Write-Host "[EDR] Dedup Window: $($env:EDR_P0_DEDUP_SEC)s"
Write-Host "[EDR] Behavior Encoding: $($env:EDR_BEHAVIOR_ENCODING)"