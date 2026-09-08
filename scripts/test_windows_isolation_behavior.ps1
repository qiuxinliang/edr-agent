# No production entrypoint or Windows firewall cmdlet is invoked. Load only the
# function ASTs, then provide an in-memory firewall and a real temporary journal.
$ErrorActionPreference = 'Stop'
$tokens = $null
$parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'windows_isolate_host.ps1'), [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw ($parseErrors | Out-String) }
foreach ($node in $ast.FindAll({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] }, $false)) {
  Invoke-Expression $node.Extent.Text
}
$Prefix = 'EDR-Test-Isolate'
$testDir = Join-Path ([IO.Path]::GetTempPath()) ('edr-isolation-test-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $testDir | Out-Null
$StatePath = Join-Path $testDir 'state.json'
$env:EDR_ISOLATE_DRY_RUN = '0'
function Assert-Admin {}
function Get-ManagementTargets { [pscustomobject]@{addresses=@('192.0.2.1');ports=@(443)} }
function Test-ManagementReachable($Targets) { return $script:reachable }
function Get-DnsClientServerAddress { [pscustomobject]@{ServerAddresses=@('192.0.2.53')} }
function Get-NetFirewallProfile { param($PolicyStore,$ErrorAction) $script:profiles }
function Get-NetFirewallRule {
  param($PolicyStore,$Name,$Enabled,$Action,$ErrorAction)
  $script:ruleReads++
  @($script:rules | Where-Object { (-not $Name -or $_.Name -in @($Name)) -and (-not $Enabled -or $_.Enabled -eq [string]$Enabled) -and (-not $Action -or $_.Action -eq $Action) })
}
function Get-NetFirewallAddressFilter {
  [CmdletBinding()]param([Parameter(ValueFromPipeline=$true)]$InputObject)
  process { [pscustomobject]@{RemoteAddress=$InputObject.RemoteAddress} }
}
function Get-NetFirewallPortFilter {
  [CmdletBinding()]param([Parameter(ValueFromPipeline=$true)]$InputObject)
  process { [pscustomobject]@{RemotePort=$InputObject.RemotePort;Protocol=$InputObject.Protocol} }
}
function New-NetFirewallRule {
  param($PolicyStore,$Name,$DisplayName,$Direction,$Action,$Enabled,$Profile,$RemoteAddress,$Protocol,$RemotePort,$ErrorAction)
  $script:rules += [pscustomobject]@{Name=$Name;DisplayName=$DisplayName;Direction=$Direction;Action=$Action;Enabled=[string]$Enabled;RemoteAddress=$RemoteAddress;RemotePort=$RemotePort;Protocol=$Protocol;PolicyStoreSourceType='Local'}
}
function Disable-NetFirewallRule { param($PolicyStore,$Name,$ErrorAction) ($script:rules | Where-Object Name -eq $Name).Enabled = 'False' }
function Enable-NetFirewallRule {
  param($PolicyStore,$Name,$ErrorAction)
  $script:enableCalls++
  if (@($Name).Count -gt 32) { throw 'firewall_query_quota_exceeded' }
  foreach ($n in @($Name)) {
    $matched = @($script:rules | Where-Object Name -eq $n)
    if ($matched.Count -ne 1) { throw 'firewall_rule_missing' }
    $matched[0].Enabled = 'True'
  }
}
function Remove-NetFirewallRule { param($PolicyStore,$Name,$ErrorAction) $script:rules = @($script:rules | Where-Object Name -ne $Name) }
function Set-NetFirewallProfile {
  param($PolicyStore,$Profile,$Enabled,$DefaultInboundAction,$DefaultOutboundAction,$ErrorAction)
  if ($script:failProfile -gt 0) { $script:failProfile--; throw 'injected_profile_failure' }
  foreach ($p in $script:profiles) {
    if ($p.Name -in @($Profile)) {
      $p.DefaultInboundAction = [string]$DefaultInboundAction
      $p.DefaultOutboundAction = [string]$DefaultOutboundAction
      if ($null -ne $Enabled) { $p.Enabled = [string]$Enabled }
    }
  }
}
function Assert($Condition, $Message) { if (-not $Condition) { throw $Message } }
function Expect-Failure($Block, $Pattern) {
  $caught = $false
  try { & $Block } catch { $caught = $true; Assert ($_.Exception.Message -match $Pattern) "unexpected failure: $_" }
  Assert $caught "expected failure: $Pattern"
}
function Reset-TestState {
  if (Test-Path -LiteralPath $StatePath) { Remove-Item -LiteralPath $StatePath }
  $script:reachable = $true
  $script:failProfile = 0
  $script:ruleReads = 0
  $script:enableCalls = 0
  $script:profiles = @('Domain','Private','Public' | ForEach-Object {
    [pscustomobject]@{Name=$_;Enabled='True';DefaultInboundAction='Block';DefaultOutboundAction='Allow'}
  })
  $script:rules = @([pscustomobject]@{Name='existing-allow';DisplayName='Existing';Action='Allow';Enabled='True';PolicyStoreSourceType='Local'})
}
try {
  Reset-TestState
  Enable-Isolation
  $first = Get-Content -LiteralPath $StatePath -Raw
  Assert (Test-Isolation (Read-State)) 'isolation must verify actual rules'
  Assert (($script:rules | Where-Object Name -eq 'existing-allow').Enabled -eq 'False') 'explicit allow must be disabled'
  Enable-Isolation
  Assert ((Get-Content -LiteralPath $StatePath -Raw) -ceq $first) 'repeat enable must preserve initial baseline byte-for-byte'
  ($script:rules | Where-Object Name -eq 'existing-allow').Enabled = 'True'
  Assert (-not (Test-Isolation (Read-State))) 'stale journal cannot prove isolation'
  Expect-Failure { Enable-Isolation } 'requires_restore'
  Remove-Isolation
  Remove-Isolation
  $status = Show-Status | ConvertFrom-Json
  Assert ($status.restored -and $status.enforcement_verified -and -not $status.isolated) 'restore must be verified and idempotent'
  Reset-TestState
  $script:rules[0].PolicyStoreSourceType = 'GroupPolicy'
  Expect-Failure { Enable-Isolation } 'nonlocal_allow_rule'
  Assert (-not (Test-Path -LiteralPath $StatePath)) 'GPO rejection precedes mutation/journal'
  Reset-TestState
  $script:failProfile = 1
  Expect-Failure { Enable-Isolation } 'rollback_verified'
  Assert (Test-Restored (Read-State)) 'failed isolation restores initial allow rules and profiles'
  Reset-TestState
  $script:failProfile = 2
  Expect-Failure { Enable-Isolation } 'rollback_failed'
  Assert ((Read-State).phase -eq 'prepared') 'rollback failure retains prepared baseline'
  Remove-Isolation
  Reset-TestState
  $legacy = [pscustomobject]@{profiles=$script:profiles}
  Save-State $legacy
  Remove-Isolation
  Remove-Isolation
  Assert ((Read-State).schema -eq 'edr.isolation.legacy') 'legacy baseline supports repeat restore, never verified isolation'
  Reset-TestState
  Add-Type 'public enum IsolationTestAction { NotConfigured=0, Allow=7, Block=3 }'
  foreach ($p in $script:profiles) { $p.DefaultInboundAction = [IsolationTestAction]::Block; $p.DefaultOutboundAction = [IsolationTestAction]::Allow }
  Save-State ([pscustomobject]@{profiles=$script:profiles})
  $legacy = Read-State
  Assert ($legacy.profiles[0].DefaultOutboundAction -eq 'Allow') 'legacy numbers use actual runtime enum mapping'
  Remove-Isolation
  Reset-TestState
  $script:rules = @(1..300 | ForEach-Object {
    [pscustomobject]@{Name="allow-$_";DisplayName="Existing $_";Action='Allow';Enabled='False';PolicyStoreSourceType='Local'}
  })
  $large = [pscustomobject]@{schema='edr.isolation.v2';phase='prepared';profiles=$script:profiles;disabled_rules=@($script:rules.Name)}
  Save-State $large
  Remove-Isolation
  Assert (@($script:rules | Where-Object Enabled -ne 'True').Count -eq 0) 'all baseline rules must be restored'
  Assert ($script:ruleReads -le 4 -and $script:enableCalls -le 10) 'restoration must bound firewall I/O and provider query size for 300 rules'
  $script:rules[0].Enabled = 'False'
  Assert (-not (Test-Restored (Read-State))) 'bulk verification must reject a disabled baseline rule'
  $script:rules = @($script:rules | Select-Object -Skip 1)
  Assert (-not (Test-Restored (Read-State))) 'bulk verification must reject a missing baseline rule'
  Expect-Failure { Remove-Isolation } 'firewall_rule_missing'
  Reset-TestState
  $script:reachable = $false
  Expect-Failure { Enable-Isolation } 'management_unreachable'
  Assert (-not (Test-Path -LiteralPath $StatePath)) 'unreachable management must not change firewall'
  Write-Output 'PASS: isolation mock behavior and durable recovery journal'
} finally {
  if ($testDir -and (Split-Path -Leaf $testDir) -like 'edr-isolation-test-*') { Remove-Item -LiteralPath $testDir -Recurse -Force }
}
