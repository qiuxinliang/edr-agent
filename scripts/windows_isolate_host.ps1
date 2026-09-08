#Requires -Version 5.1
param(
  [ValidateSet("Enable", "Remove", "Status")]
  [string]$Action = "Enable"
)

$ErrorActionPreference = "Stop"
$Prefix = if ($env:EDR_ISOLATE_RULE_PREFIX) { $env:EDR_ISOLATE_RULE_PREFIX } else { "EDR-Isolate" }
$StatePath = if ($env:EDR_ISOLATE_STATE_PATH) { $env:EDR_ISOLATE_STATE_PATH } else { "C:\Program Files\FDSecurity\isolation\state.json" }
if ($Prefix -notmatch '^[A-Za-z0-9_-]{1,64}$') { throw "isolation_rule_prefix_invalid" }

function Assert-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  if (-not (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "isolation_requires_administrator"
  }
}

function Get-OwnedRules {
  @(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop | Where-Object { $_.DisplayName -like "$Prefix *" })
}

function Save-State($State) {
  $dir = Split-Path -Parent $StatePath
  if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -ErrorAction Stop | Out-Null }
  if ((Get-Item -LiteralPath $dir).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "isolation_state_directory_is_reparse" }
  if ((Test-Path -LiteralPath $StatePath) -and ((Get-Item -LiteralPath $StatePath).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw "isolation_state_is_reparse" }
  $tmp = "$StatePath.$PID.tmp"
  $stream = $null
  try {
    $bytes = [Text.Encoding]::UTF8.GetBytes(($State | ConvertTo-Json -Depth 8 -Compress))
    $stream = [IO.File]::Open($tmp, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    $stream.Write($bytes, 0, $bytes.Length)
    $stream.Flush($true)
    $stream.Dispose()
    $stream = $null
    if (Test-Path -LiteralPath $StatePath) { [IO.File]::Replace($tmp, $StatePath, [NullString]::Value) }
    else { [IO.File]::Move($tmp, $StatePath) }
  } finally {
    if ($null -ne $stream) { $stream.Dispose() }
    if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -ErrorAction Stop }
  }
}

function Read-State {
  if (-not (Test-Path -LiteralPath $StatePath)) { return $null }
  if ((Get-Item -LiteralPath $StatePath).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "isolation_state_is_reparse" }
  $s = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
  if (@($s.profiles).Count -ne 3 -or (@($s.profiles.Name | Sort-Object -Unique) -join ',') -ne 'Domain,Private,Public') {
    throw "isolation_recovery_baseline_invalid"
  }
  foreach ($p in $s.profiles) {
    # Windows PowerShell 5.1 serialized the old CIM enums as integers. Resolve
    # using the installed NetSecurity enum, never a hand-written numeric map.
    foreach ($field in @('DefaultInboundAction','DefaultOutboundAction')) {
      if ([string]$p.$field -match '^\d+$') {
        $live = @(Get-NetFirewallProfile -PolicyStore PersistentStore -ErrorAction Stop | Where-Object Name -eq $p.Name)
        if ($live.Count -ne 1 -or -not $live[0].$field.GetType().IsEnum) { throw "legacy_firewall_enum_unavailable" }
        $enum = [Enum]::ToObject($live[0].$field.GetType(), [int]$p.$field)
        if (-not [Enum]::IsDefined($enum.GetType(), $enum)) { throw "legacy_firewall_enum_invalid" }
        $p.$field = $enum.ToString()
      }
    }
    if ([string]$p.DefaultInboundAction -notin @('Allow','Block','NotConfigured') -or [string]$p.DefaultOutboundAction -notin @('Allow','Block','NotConfigured')) { throw "isolation_recovery_profile_invalid" }
  }
  # 3.2.409 persisted only profile defaults. It is accepted for restore, never
  # reused as a new isolation baseline or declared verified isolation.
  if (-not $s.PSObject.Properties['schema']) {
    $s | Add-Member schema 'edr.isolation.legacy'
    $s | Add-Member phase 'prepared'
    $s | Add-Member disabled_rules @()
  } elseif ($s.schema -notin @('edr.isolation.v2','edr.isolation.legacy') -or $s.phase -notin @('prepared','isolated','restored')) {
    throw "isolation_state_schema_invalid"
  }
  return $s
}

function Get-ManagementTargets {
  $addresses = @()
  foreach ($value in @($env:EDR_ISOLATE_ALLOW_REMOTE_ADDRS -split ',')) {
    $value = $value.Trim()
    if (-not $value) { continue }
    $ip = $null
    if ([Net.IPAddress]::TryParse($value, [ref]$ip)) { $addresses += $ip.IPAddressToString }
    else { $addresses += @([Net.Dns]::GetHostAddresses($value) | ForEach-Object { $_.IPAddressToString }) }
  }
  $addresses = @($addresses | Sort-Object -Unique)
  $ports = @()
  foreach ($value in @($env:EDR_ISOLATE_ALLOW_REMOTE_PORTS -split ',')) {
    $port = 0
    if (-not [int]::TryParse($value, [ref]$port) -or $port -lt 1 -or $port -gt 65535) { throw "management_port_invalid" }
    $ports += $port
  }
  if ($addresses.Count -lt 1 -or $addresses.Count -gt 16 -or $ports.Count -lt 1 -or $ports.Count -gt 8) { throw "management_targets_missing_or_unbounded" }
  return [pscustomobject]@{ addresses=$addresses; ports=@($ports | Sort-Object -Unique) }
}

function Test-ManagementReachable($Targets) {
  # Bounded TCP reachability, not a claim that mTLS or Agent ACK succeeded.
  $deadline = [Diagnostics.Stopwatch]::StartNew()
  foreach ($addr in $Targets.addresses) {
    foreach ($port in $Targets.ports) {
      if ($deadline.ElapsedMilliseconds -ge 3000) { return $false }
      $client = New-Object Net.Sockets.TcpClient
      try {
        $task = $client.ConnectAsync([string]$addr, [int]$port)
        if ($task.Wait(250) -and $client.Connected) { return $true }
      } catch [AggregateException] {
        # A connection refusal/timeout is a failed probe; try the bounded next target.
      } finally { $client.Dispose() }
    }
  }
  return $false
}

function Test-Isolation($State) {
  if ($null -eq $State -or $State.schema -ne 'edr.isolation.v2' -or $State.phase -ne 'isolated') { return $false }
  $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)
  if ($profiles.Count -ne 3) { return $false }
  foreach ($p in $profiles) {
    if ([string]$p.Enabled -ne 'True' -or [string]$p.DefaultInboundAction -ne 'Block' -or [string]$p.DefaultOutboundAction -ne 'Block') { return $false }
  }
  $rules = @(Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True -Action Allow -ErrorAction Stop)
  $expected = @($State.allow_rules)
  if ($expected.Count -lt 1 -or $rules.Count -ne $expected.Count) { return $false }
  foreach ($r in $rules) {
    if ($r.Name -notin $expected) { return $false }
  }
  foreach ($name in $expected) {
    $r = @($rules | Where-Object Name -eq $name)
    if ($r.Count -ne 1) { return $false }
    $addressFilter = $r[0] | Get-NetFirewallAddressFilter -ErrorAction Stop
    $portFilter = $r[0] | Get-NetFirewallPortFilter -ErrorAction Stop
    $spec = @($State.allow_specs | Where-Object name -eq $name)
    if ($spec.Count -ne 1 -or [string]$r[0].Direction -ne 'Outbound' -or
        (@($addressFilter.RemoteAddress | Sort-Object) -join ',') -ne (@($spec[0].addresses | Sort-Object) -join ',') -or
        (@($portFilter.RemotePort | ForEach-Object { [string]$_ } | Sort-Object) -join ',') -ne (@($spec[0].ports | ForEach-Object { [string]$_ } | Sort-Object) -join ',') -or
        ([string]$portFilter.Protocol -replace '^6$','TCP' -replace '^17$','UDP') -ne [string]$spec[0].protocol) { return $false }
  }
  return (Test-ManagementReachable $State.management)
}

function Test-Restored($State) {
  if ($null -eq $State) { return $false }
  if (@(Get-OwnedRules).Count -ne 0) { return $false }
  $profiles = @(Get-NetFirewallProfile -PolicyStore PersistentStore -ErrorAction Stop)
  foreach ($saved in $State.profiles) {
    $p = @($profiles | Where-Object Name -eq $saved.Name)
    if ($p.Count -ne 1 -or [string]$p[0].DefaultInboundAction -ne [string]$saved.DefaultInboundAction -or [string]$p[0].DefaultOutboundAction -ne [string]$saved.DefaultOutboundAction) { return $false }
    if ($saved.PSObject.Properties['Enabled'] -and [string]$p[0].Enabled -ne [string]$saved.Enabled) { return $false }
  }
  # A CIM round trip per rule makes repeated restore/status checks exceed the
  # command deadline on ordinary Windows hosts with hundreds of allow rules.
  $rulesByName = @{}
  foreach ($r in @(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop)) {
    if ($rulesByName.ContainsKey($r.Name)) { return $false }
    $rulesByName[$r.Name] = $r
  }
  foreach ($name in @($State.disabled_rules)) {
    if (-not $rulesByName.ContainsKey($name) -or [string]$rulesByName[$name].Enabled -ne 'True') { return $false }
  }
  return $true
}

function Restore-Baseline($State) {
  # Restore defaults/rules before removing the management exceptions.
  foreach ($p in $State.profiles) {
    $args = @{ Profile=[string]$p.Name; PolicyStore='PersistentStore'; DefaultInboundAction=[string]$p.DefaultInboundAction; DefaultOutboundAction=[string]$p.DefaultOutboundAction; ErrorAction='Stop' }
    if ($p.PSObject.Properties['Enabled']) { $args.Enabled = [string]$p.Enabled }
    Set-NetFirewallProfile @args
  }
  # Name[] becomes a WQL filter; cap each batch below provider query quotas.
  $names = @($State.disabled_rules)
  for ($offset = 0; $offset -lt $names.Count; $offset += 32) {
    $last = [Math]::Min($offset + 31, $names.Count - 1)
    Enable-NetFirewallRule -PolicyStore PersistentStore -Name $names[$offset..$last] -ErrorAction Stop | Out-Null
  }
  foreach ($r in @(Get-OwnedRules)) { Remove-NetFirewallRule -PolicyStore PersistentStore -Name $r.Name -ErrorAction Stop }
  if (-not (Test-Restored $State)) { throw "restore_verification_failed" }
  if ($State.PSObject.Properties['management'] -and -not (Test-ManagementReachable $State.management)) { throw "restore_management_unreachable" }
  $State.phase = 'restored'
  Save-State $State
}

function Enable-Isolation {
  Assert-Admin
  if ($env:EDR_ISOLATE_DRY_RUN -eq '1') { throw "dry_run_is_not_enforcement" }
  $old = Read-State
  if ($null -ne $old -and $old.phase -ne 'restored') {
    if (Test-Isolation $old) { return }
    throw "existing_isolation_requires_restore; recovery baseline retained"
  }
  if (@(Get-OwnedRules).Count -ne 0) { throw "orphan_isolation_rules; recovery baseline required" }
  $management = Get-ManagementTargets
  if (-not (Test-ManagementReachable $management)) { throw "management_unreachable_before_isolation" }
  $rules = @(Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True -Action Allow -ErrorAction Stop)
  foreach ($r in $rules) {
    if ([string]$r.PolicyStoreSourceType -ne 'Local') { throw "nonlocal_allow_rule_prevents_verified_isolation" }
  }
  $profiles = @(Get-NetFirewallProfile -PolicyStore PersistentStore -ErrorAction Stop | ForEach-Object {
    [pscustomobject]@{ Name=[string]$_.Name; Enabled=[string]$_.Enabled; DefaultInboundAction=[string]$_.DefaultInboundAction; DefaultOutboundAction=[string]$_.DefaultOutboundAction }
  })
  $dns = @(Get-DnsClientServerAddress -ErrorAction Stop | ForEach-Object { $_.ServerAddresses } | Where-Object { $_ } | Sort-Object -Unique)
  $specs = @([pscustomobject]@{ name="$Prefix Mgmt"; addresses=@($management.addresses); ports=@($management.ports); protocol='TCP' })
  if ($dns.Count -gt 0) {
    $specs += [pscustomobject]@{ name="$Prefix DNS UDP"; addresses=$dns; ports=@(53); protocol='UDP' }
    $specs += [pscustomobject]@{ name="$Prefix DNS TCP"; addresses=$dns; ports=@(53); protocol='TCP' }
  }
  $state = [pscustomobject]@{ schema='edr.isolation.v2'; phase='prepared'; profiles=$profiles; disabled_rules=@($rules.Name); management=$management; allow_rules=@($specs.name); allow_specs=$specs }
  Save-State $state
  try {
    foreach ($s in $specs) {
      New-NetFirewallRule -PolicyStore PersistentStore -Name $s.name -DisplayName $s.name -Direction Outbound -Action Allow -Enabled True -Profile Any -RemoteAddress $s.addresses -Protocol $s.protocol -RemotePort $s.ports -ErrorAction Stop | Out-Null
    }
    foreach ($r in $rules) { Disable-NetFirewallRule -PolicyStore PersistentStore -Name $r.Name -ErrorAction Stop | Out-Null }
    Set-NetFirewallProfile -PolicyStore PersistentStore -Profile Domain,Private,Public -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Block -ErrorAction Stop
    $state.phase = 'isolated'
    if (-not (Test-Isolation $state)) { throw "isolation_effect_not_verified" }
    Save-State $state
  } catch {
    $cause = $_.Exception.Message
    try { Restore-Baseline $state } catch { throw "isolation_failed: $cause; rollback_failed: $($_.Exception.Message); baseline retained at $StatePath" }
    throw "isolation_failed: $cause; rollback_verified"
  }
}

function Remove-Isolation {
  Assert-Admin
  if ($env:EDR_ISOLATE_DRY_RUN -eq '1') { throw "dry_run_is_not_enforcement" }
  $state = Read-State
  if ($null -eq $state) { throw "recovery_baseline_missing" }
  Restore-Baseline $state
}

function Show-Status {
  $state = Read-State
  $isolated = Test-Isolation $state
  $restored = $null -ne $state -and $state.phase -eq 'restored' -and (Test-Restored $state)
  [ordered]@{ schema='edr.isolation.status.v1'; isolated=[bool]$isolated; restored=[bool]$restored; enforcement_verified=[bool]($isolated -or $restored) } | ConvertTo-Json -Compress
}

$mutex = New-Object Threading.Mutex($false, 'Global\FDSecurity.Isolation')
$locked = $false
try {
  try { $locked = $mutex.WaitOne(5000) } catch [Threading.AbandonedMutexException] { $locked = $true }
  if (-not $locked) { throw "isolation_operation_busy" }
  switch ($Action) {
    'Enable' { Enable-Isolation }
    'Remove' { Remove-Isolation }
    'Status' { }
  }
  Show-Status
} finally {
  if ($locked) { $mutex.ReleaseMutex() }
  $mutex.Dispose()
}
