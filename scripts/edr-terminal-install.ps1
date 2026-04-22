#Requires -Version 5.1
# EDR Agent Windows 终端安装入口：参数全部转交给 edr_agent_install.ps1。
$ErrorActionPreference = "Stop"
$here = $PSScriptRoot
$core = Join-Path $here "edr_agent_install.ps1"
if (-not (Test-Path $core)) {
  Write-Error "edr-terminal-install.ps1: missing $core"
}

$first = if ($args.Count -gt 0) { $args[0] } else { $null }
if (-not $first -or $first -in @("-h", "/h", "/?", "help")) {
  Write-Host @'
EDR Agent Windows 终端安装器

用法:
  .\edr-terminal-install.ps1 -ApiBase <平台HTTP根> -Token <注册Token> [其他参数]

常用参数:
  -Output PATH           输出 agent.toml
  -DryRun                仅打印 TOML
  -InsecureTls / -k      调试：跳过 HTTPS 证书校验
  -OverrideServerAddr    覆盖 enroll 返回的 gRPC 地址

环境变量（与参数二选一，参数优先）:
  EDR_API_BASE  EDR_ENROLL_TOKEN

示例:
  .\edr-terminal-install.ps1 -ApiBase "http://192.168.1.35:8080" -Token "YOUR_TOKEN" -Output "C:\ProgramData\EDR\agent.toml"

cmd.exe:
  edr_agent_install.cmd -ApiBase http://192.168.1.35:8080 -Token YOUR_TOKEN

完整参数: Get-Help .\edr_agent_install.ps1 -Full
文档: edr-agent\docs\AGENT_INSTALLER.md
'@
  exit 0
}

if ($first -eq "--help") {
  Get-Help $core -Full
  exit 0
}

& $core @args
exit $LASTEXITCODE
