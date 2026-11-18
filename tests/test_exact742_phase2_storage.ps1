#Requires -Version 5.1
# Pure event/cohort and synthetic receipt-summary boundaries. No product or DB operation.
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Exact742FirstHopRecovery.Common.ps1')
. Import-Exact742TestDefinitions
. (Join-Path $PSScriptRoot 'Exact742MaintenanceRecovery.Common.ps1')
$count=0
function Need($Value,$Message){if(!$Value){throw $Message};$script:count++}
function Reject([scriptblock]$Action){try{& $Action|Out-Null}catch{$script:count++;return};throw 'Expected Phase2 refusal absent'}
$events=New-Object 'System.Collections.Generic.List[object]'
Add-Evidence 'storage-pure-boundary' 'verified' 'real imported event owner; no storage operation'
Need ($events.Count -eq 1 -and $events.ToArray()[0].stage -ceq 'storage-pure-boundary') 'Imported storage ancestor/event owner is missing'
$root=Join-Path ([IO.Path]::GetTempPath()) ('edr-phase2-pure-'+[Guid]::NewGuid().ToString('N'));$completed=$false
try{
 New-Item -ItemType Directory $root|Out-Null
 $path=Join-Path $root 'tools.json'
 $pins=@{legacy='b307daa7a4e60a141d344fcb10bded19d97b436d';candidate='388d69438781d93cd36871354439585feb1ebc07'}
 $tools=@{schema='edr.windows.storage-compat-tools.v1';architecture='arm64';cohort='legacy-publisher';source_commits=$pins}
 $tools|ConvertTo-Json -Depth 6|Set-Content $path -Encoding UTF8
 Reject {Import-LifecycleStorageTools $path arm64 'must-not-execute.ps1' installed742-to747}
 $tools.cohort='installed742-to747';$tools.source_commits=@{legacy='b51bc3d825e6d5666535463b34eb708201e6fda7';candidate=$pins.candidate}
 $tools|ConvertTo-Json -Depth 6|Set-Content $path -Encoding UTF8
 Reject {Import-LifecycleStorageTools $path arm64 'must-not-execute.ps1' installed742-to747}
 $tools.source_commits=$pins;$tools.architecture='amd64';$tools|ConvertTo-Json -Depth 6|Set-Content $path -Encoding UTF8
 Reject {Import-LifecycleStorageTools $path amd64 'must-not-execute.ps1' installed742-to747}
 $tools.architecture='arm64';$tools|ConvertTo-Json -Depth 6|Set-Content $path -Encoding UTF8
 Reject {Import-LifecycleStorageTools $path arm64 'must-not-execute.ps1'}
 # Only summarize synthetic post-validation receipts, not pretend native DB proof.
 $context=@{root=$root;generation=1;tools=@{legacy=@{source_commit=$pins.legacy};candidate=@{source_commit=$pins.candidate}}}
 foreach($kind in @('cache','queue')){
  $proof=@{database_kind=$kind;source_journal_mode='wal';snapshot_scope='single_database_committed_read_view';cross_database_atomic=$false;wal_resolution='sqlite_read_transaction_resolves_committed_wal_if_present';sha256=('a'*64);size=4096;source_readonly=$true;wal_before=@{exists=$false;bytes=0};wal_after=@{exists=$true;bytes=24}}
  $proof|ConvertTo-Json -Depth 6|Set-Content (Join-Path $root ('pure-'+$kind+'-snapshot.stdout.json')) -Encoding UTF8
  foreach($role in @('legacy','candidate')){@{source_commit=$pins[$role];action='read';records=@('synthetic1','synthetic2')}|ConvertTo-Json -Depth 6|Set-Content (Join-Path $root ('pure-'+$kind+'-'+$role+'-read.stdout.json')) -Encoding UTF8}
 }
 $summary=Get-ExactMaintenanceStorageStage $context 'pure'
 Need ($summary.databases.Count -eq 2) 'Per-database evidence was merged/lost'
 foreach($field in @('cross_database_atomic','outbox_tested','server_ack_tested','shared_owner_ref_tested','protection_deadline_tested','queue_retry_metadata_preservation_tested','wal_only_frozen_rows_proven')){Need ($summary[$field] -eq $false) 'Untested data scope was promoted'}
 $proofPath=Join-Path $root 'pure-queue-snapshot.stdout.json';$changed=Get-Content $proofPath -Raw -Encoding UTF8|ConvertFrom-Json;$changed.source_journal_mode='delete';$changed|ConvertTo-Json -Depth 6|Set-Content $proofPath -Encoding UTF8
 Reject {Get-ExactMaintenanceStorageStage $context 'pure'}
 $completed=$true
 Write-Host "PASS: $count Phase2 event/cohort/receipt boundary assertions; no native storage/product/DB proof claimed"
}finally{if($completed){Remove-Item -LiteralPath $root -Recurse -Force}else{Write-Warning "Retained failed pure fixture: $root"}}
