#Requires -Version 5.1
<#
.SYNOPSIS
  Standard Windows host isolation hook for FDSecurity.

.DESCRIPTION
  The agent invokes this script through EDR_ISOLATE_HOOK. Enable mode switches
  Windows Defender Firewall profiles to default deny and optionally adds allow
  rules for management servers from EDR_ISOLATE_ALLOW_REMOTE_ADDRS.

  Environment:
    EDR_CMD_ID                         command id written by the agent
    EDR_ISOLATE_RULE_PREFIX            default: EDR-Isolate
    EDR_ISOLATE_STATE_PATH             default: C:\Program Files\FDSecurity\isolation\state.json
    EDR_ISOLATE_ALLOW_REMOTE_ADDRS     comma-separated IP/CIDR list
    EDR_ISOLATE_ALLOW_REMOTE_PORTS     comma-separated ports, default 443,50051
    EDR_ISOLATE_DRY_RUN=1              print actions only
#>
param(
  [ValidateSet("Enable", "Remove", "Status")]
  [string]$Action = "Enable"
)

$ErrorActionPreference = "Stop"

$Prefix = if ($env:EDR_ISOLATE_RULE_PREFIX) { $env:EDR_ISOLATE_RULE_PREFIX } else { "EDR-Isolate" }
$StatePath = if ($env:EDR_ISOLATE_STATE_PATH) {
  $env:EDR_ISOLATE_STATE_PATH
} else {
  "C:\Program Files\FDSecurity\isolation\state.json"
}
$DryRun = $env:EDR_ISOLATE_DRY_RUN -eq "1"

function Assert-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p = New-Object Security.Principal.WindowsPrincipal($id)
  if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Host isolation requires an elevated service or PowerShell session."
  }
}

function Invoke-Step([string]$Text, [scriptblock]$Block) {
  Write-Host $Text
  if (-not $DryRun) {
    & $Block
  }
}

function Ensure-StateDir {
  $dir = Split-Path -Parent $StatePath
  if ($dir -and -not (Test-Path -LiteralPath $dir)) {
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
  }
}

function Remove-IsolationRules {
  $rules = Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object {
    $_.DisplayName -like "$Prefix*"
  }
  foreach ($r in $rules) {
    Invoke-Step "Remove firewall rule $($r.DisplayName)" {
      Remove-NetFirewallRule -Name $r.Name -ErrorAction SilentlyContinue
    }
  }
}

function Enable-Isolation {
  Assert-Admin
  Ensure-StateDir
  $profiles = Get-NetFirewallProfile | Select-Object Name, DefaultInboundAction, DefaultOutboundAction
  $state = [ordered]@{
    command_id = if ($env:EDR_CMD_ID) { $env:EDR_CMD_ID } else { "" }
    enabled_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    profiles = $profiles
  }
  if (-not $DryRun) {
    $state | ConvertTo-Json -Depth 5 | Set-Content -Path $StatePath -Encoding UTF8
  }

  Remove-IsolationRules

  $ports = if ($env:EDR_ISOLATE_ALLOW_REMOTE_PORTS) {
    $env:EDR_ISOLATE_ALLOW_REMOTE_PORTS
  } else {
    "443,50051"
  }
  $addrs = @()
  if ($env:EDR_ISOLATE_ALLOW_REMOTE_ADDRS) {
    $addrs = $env:EDR_ISOLATE_ALLOW_REMOTE_ADDRS.Split(",") | ForEach-Object { $_.Trim() } | Where-Object { $_ }
  }
  # New-NetFirewallRule -RemoteAddress 只接受 IP/CIDR/range,不接受主机名:
  # 把任何非 IP 条目通过 DNS 解析成 IP(agent 在 Windows 上可能传入后端主机名)。
  $resolved = @()
  foreach ($a in $addrs) {
    if ($a -match '/' -or $a -match '^\d{1,3}(\.\d{1,3}){3}$' -or $a -match ':') {
      $resolved += $a   # 已是 IPv4 / CIDR / IPv6
    } else {
      try {
        [System.Net.Dns]::GetHostAddresses($a) | ForEach-Object { $resolved += $_.IPAddressToString }
      } catch {
        Write-Host "warn: cannot resolve management host '$a'; skipping (set EDR_ISOLATE_ALLOW_REMOTE_ADDRS to explicit IPs)"
      }
    }
  }
  $addrs = $resolved | Select-Object -Unique
  foreach ($addr in $addrs) {
    Invoke-Step "Allow outbound management traffic to $addr ports $ports" {
      New-NetFirewallRule -DisplayName "$Prefix Allow Mgmt $addr" -Direction Outbound `
        -Action Allow -Enabled True -Profile Any -RemoteAddress $addr -Protocol TCP `
        -RemotePort $ports | Out-Null
    }
  }

  Invoke-Step "Set firewall profiles to default inbound/outbound block" {
    Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block -DefaultOutboundAction Block
  }
  Write-Host "Isolation enabled. State: $StatePath"
}

function Remove-Isolation {
  Assert-Admin
  Remove-IsolationRules
  if (Test-Path -LiteralPath $StatePath) {
    $state = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
    foreach ($p in $state.profiles) {
      $name = [string]$p.Name
      $in = [string]$p.DefaultInboundAction
      $out = [string]$p.DefaultOutboundAction
      Invoke-Step "Restore firewall profile $name inbound=$in outbound=$out" {
        Set-NetFirewallProfile -Profile $name -DefaultInboundAction $in -DefaultOutboundAction $out
      }
    }
    if (-not $DryRun) {
      Remove-Item -LiteralPath $StatePath -Force -ErrorAction SilentlyContinue
    }
  }
  Write-Host "Isolation removed."
}

function Show-Status {
  Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction
  Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object {
    $_.DisplayName -like "$Prefix*"
  } | Select-Object DisplayName, Direction, Action, Enabled
  if (Test-Path -LiteralPath $StatePath) {
    Write-Host "State file: $StatePath"
  }
}

switch ($Action) {
  "Enable" { Enable-Isolation }
  "Remove" { Remove-Isolation }
  "Status" { Show-Status }
}
