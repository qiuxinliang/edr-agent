#Requires -Version 5.1
# Deliberately opt-in: changes the firewall only on an authorized lab endpoint.
param(
  [Parameter(Mandatory=$true)][string]$ManagementAddress,
  [Parameter(Mandatory=$true)][ValidateRange(1,65535)][int]$ManagementPort,
  [Parameter(Mandatory=$true)][string]$ProbeAddress,
  [Parameter(Mandatory=$true)][ValidateRange(1,65535)][int]$ProbePort,
  [Parameter(Mandatory=$true)][string]$Workspace,
  [string]$IsolationScript = 'C:\Program Files\FDSecurity\windows_isolate_host.ps1',
  [switch]$AllowFirewallMutation
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
if (-not $AllowFirewallMutation) { throw 'Explicit lab firewall mutation opt-in required' }
[void][Net.IPAddress]::Parse($ManagementAddress)
[void][Net.IPAddress]::Parse($ProbeAddress)
if ($ManagementPort -eq $ProbePort) { throw 'Probe must use a non-management port' }
if (Test-Path -LiteralPath $Workspace) { throw 'Use a fresh test workspace; preserve previous evidence' }
if (-not (Test-Path -LiteralPath $IsolationScript -PathType Leaf)) { throw 'Isolation script missing' }
if ($env:EDR_ISOLATE_STATE_PATH -or $env:EDR_ISOLATE_RULE_PREFIX -or $env:EDR_ISOLATE_DRY_RUN) {
  throw 'Start in a clean process without inherited isolation overrides'
}
$before = & $IsolationScript -Action Observe | ConvertFrom-Json
if ($before.state -ne 'normal') { throw 'Endpoint is not normal; preserve existing containment' }

function Test-Tcp([string]$Address, [int]$Port) {
  $c = New-Object Net.Sockets.TcpClient
  try {
    $task = $c.ConnectAsync($Address, $Port)
    return [bool]($task.Wait(2000) -and $c.Connected)
  } catch [AggregateException] { return $false }
  finally { $c.Dispose() }
}
function Get-Baseline {
  $profiles = @(Get-NetFirewallProfile -PolicyStore PersistentStore | Sort-Object Name | ForEach-Object {
    [ordered]@{ name=[string]$_.Name; enabled=[string]$_.Enabled; inbound=[string]$_.DefaultInboundAction; outbound=[string]$_.DefaultOutboundAction }
  })
  $allows = @(Get-NetFirewallRule -PolicyStore PersistentStore -Enabled True -Action Allow | Select-Object -ExpandProperty Name | Sort-Object)
  return ([ordered]@{ profiles=$profiles; enabled_allow_rules=$allows } | ConvertTo-Json -Depth 5 -Compress)
}
function Quote-PS([string]$Text) { return "'" + $Text.Replace("'", "''") + "'" }

if (-not (Test-Tcp $ManagementAddress $ManagementPort)) { throw 'Management probe failed before test' }
if (-not (Test-Tcp $ProbeAddress $ProbePort)) { throw 'Controlled probe listener must be reachable before test' }
$baseline = Get-Baseline
[void](New-Item -ItemType Directory -Path $Workspace)
$baseline | Set-Content -LiteralPath (Join-Path $Workspace 'baseline.json') -Encoding UTF8
$prefix = 'EDR-Lab-' + [Guid]::NewGuid().ToString('N')
$taskName = $prefix + '-Restore'
$statePath = Join-Path $Workspace 'state.json'
$restorePath = Join-Path $Workspace 'restore.ps1'
$restoreLog = Join-Path $Workspace 'restore.log'
$restore = @(
  "`$ErrorActionPreference = 'Stop'",
  "`$env:EDR_ISOLATE_RULE_PREFIX = $(Quote-PS $prefix)",
  "`$env:EDR_ISOLATE_STATE_PATH = $(Quote-PS $statePath)",
  "if (Test-Path -LiteralPath $(Quote-PS $statePath)) {",
  "  `$result = & $(Quote-PS $IsolationScript) -Action Remove | ConvertFrom-Json",
  "  `$result | ConvertTo-Json -Compress | Set-Content -LiteralPath $(Quote-PS $restoreLog)",
  "  if (-not (`$result.restored -and `$result.enforcement_verified)) { throw 'Emergency restore unverified' }",
  '}',
  "Unregister-ScheduledTask -TaskName $(Quote-PS $taskName) -Confirm:`$false"
)
$restore | Set-Content -LiteralPath $restorePath -Encoding UTF8
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -ExecutionPolicy Bypass -File "' + $restorePath + '"')
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(3)
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 3)
[void](Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -User SYSTEM -RunLevel Highest)
$env:EDR_ISOLATE_RULE_PREFIX = $prefix
$env:EDR_ISOLATE_STATE_PATH = $statePath
$env:EDR_ISOLATE_ALLOW_REMOTE_ADDRS = $ManagementAddress
$env:EDR_ISOLATE_ALLOW_REMOTE_PORTS = [string]$ManagementPort
$report = [ordered]@{ schema='edr.lab.isolation.v1'; isolated=$false; management_reachable=$false; probe_blocked=$false; restored=$false; baseline_restored=$false; probe_restored=$false }
try {
  $isolated = & $IsolationScript -Action Enable | ConvertFrom-Json
  $report.isolated = [bool]($isolated.isolated -and $isolated.enforcement_verified)
  $report.management_reachable = Test-Tcp $ManagementAddress $ManagementPort
  $report.probe_blocked = -not (Test-Tcp $ProbeAddress $ProbePort)
  if (-not ($report.isolated -and $report.management_reachable -and $report.probe_blocked)) {
    throw 'Isolation did not satisfy controlled connectivity checks'
  }
} finally {
  if (Test-Path -LiteralPath $statePath) {
    $restored = & $IsolationScript -Action Remove | ConvertFrom-Json
    $report.restored = [bool]($restored.restored -and $restored.enforcement_verified)
  }
  $report.baseline_restored = (Get-Baseline) -ceq $baseline
  $report.probe_restored = Test-Tcp $ProbeAddress $ProbePort
  $report | ConvertTo-Json -Compress | Set-Content -LiteralPath (Join-Path $Workspace 'result.json') -Encoding UTF8
  $report | ConvertTo-Json -Compress
  if ($report.baseline_restored -and ($report.restored -or -not (Test-Path -LiteralPath $statePath))) {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
  } else { throw "Restore unverified; emergency task retained: $taskName" }
}
if (-not ($report.restored -and $report.baseline_restored -and $report.probe_restored)) { throw 'Restoration acceptance failed' }
