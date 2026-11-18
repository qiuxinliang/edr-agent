#Requires -Version 5.1
# Pure contract/Job boundary doubles. No Setup, Agent, registry or task operation.
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '../scripts/Exact-Installed742Qualification.ps1')
. (Join-Path $PSScriptRoot 'Invoke-LifecycleStorageCompatibility.ps1')
. (Join-Path $PSScriptRoot 'Exact742MaintenanceRecovery.Common.ps1')
$count=0
function Need($Value,$Message){if(!$Value){throw $Message};$script:count++}
function Reject([scriptblock]$Action){try{& $Action|Out-Null}catch{$script:count++;return};throw 'Expected maintenance refusal absent'}
$old=@{};foreach($key in @('GITHUB_ACTIONS','RUNNER_ENVIRONMENT','RUNNER_ARCH','GITHUB_SHA','GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT','GITHUB_JOB','PSModulePath')){$old[$key]=[Environment]::GetEnvironmentVariable($key,'Process')}
$root=Join-Path ([IO.Path]::GetTempPath()) ('edr-maintenance-test-'+[Guid]::NewGuid().ToString('N'));$completed=$false
try{
 $env:GITHUB_ACTIONS='true';$env:RUNNER_ENVIRONMENT='github-hosted';$env:RUNNER_ARCH='ARM64';$env:GITHUB_SHA='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';$env:GITHUB_RUN_ID='123';$env:GITHUB_RUN_ATTEMPT='1';$env:GITHUB_JOB='maintenance'
 $fixtureInput=@{schema='edr.exact-installed-742-to-747.inputs.v1';source_version='3.2.742';target_version='3.2.747';architecture='arm64';runtime_mode='scheduled_task';old_full_setup_rollback_supported=$false;first_hop_inputs_staged=$false;upgrade_input=$null;storage_tools_input=$null;source_installed_agent_sha256='e6ea9736829d0c0be5284c570f198ec888bcaad1845a074ea8838ebf6b326dbe';source_installed_updater_sha256='cae170855648559201c20b62d2d72d1bf2f030b61f5fda8ba27aa7534bd7a183';source_installed_launcher_sha256='656d349640d5403af0881bb5db7a4811074450cb93b6602c1322f03edfafd8c3'}
 $source=@{schema='edr.exact-installed742.qualification-result.v1';complete=$true;qualification_only=$true;full_gate_passed=$false;deployment_authorized=$false;source_version='3.2.742';runner_environment='github-hosted';architecture='arm64';target_version='3.2.747';source_setup_sha256='6122591c151953e0416ca70815f4c437e62425cd1f5f48676087b25e32783c92';harness_commit=$env:GITHUB_SHA;run_id='123';run_attempt='1';job='maintenance';consumer_identity=@{install_dir='C:\Program Files\FDSecurity';runtime_mode='scheduled_task';agent_sha256=$fixtureInput.source_installed_agent_sha256;updater_sha256=$fixtureInput.source_installed_updater_sha256;launcher_sha256=$fixtureInput.source_installed_launcher_sha256;native_integrity_sha256='5399c68ef8860199c2efccc4ece6b8e489b01cd7e6f89cfe582df3332e4f37f9'}}
 Assert-Exact742MaintenanceContext $fixtureInput $source
 foreach($pair in @(@('source_version','3.2.747'),@('runtime_mode','service'),@('old_full_setup_rollback_supported',$true),@('first_hop_inputs_staged',$true))){$bad=$fixtureInput.Clone();$bad[$pair[0]]=$pair[1];Reject {Assert-Exact742MaintenanceContext $bad $source}}
 $bad=$source.Clone();$bad.job='other-job';Reject {Assert-Exact742MaintenanceContext $fixtureInput $bad}
 $bad=$source.Clone();$bad.complete=$false;Reject {Assert-Exact742MaintenanceContext $fixtureInput $bad}
 $env:RUNNER_ENVIRONMENT='self-hosted';Reject {Assert-Exact742MaintenanceContext $fixtureInput $source};$env:RUNNER_ENVIRONMENT='github-hosted'
 New-Item -ItemType Directory $root|Out-Null
 $fixture=Join-Path $root 'not-a-product.exe';[IO.File]::WriteAllText($fixture,'unexecuted boundary fixture')
 $digest=(Get-FileHash $fixture).Hash.ToLowerInvariant()
 function Get-AuthenticodeSignature {param($LiteralPath) return [pscustomobject]@{Status='NotSigned';TimeStamperCertificate=$null;SignerCertificate=$null}}
 Reject {Assert-ExactMaintenanceSetup $fixture $digest}
 Remove-Item Function:\Get-AuthenticodeSignature
 # Signature validation above is separate. Remaining tests isolate only Job I/O.
 function Assert-ExactMaintenanceSetup([string]$Path,[string]$ExpectedHash){Assert-Exact742ProgramHash $Path $ExpectedHash}
 Add-Type @'
using System;
namespace FDSecurity {
 public sealed class InstallerJob : IDisposable {
  public static string Mode;
  public static int WaitMs,DrainMs;
  public static string LaunchModulePath;
  public static InstallerJob Create(string name){return new InstallerJob();}
  public void Launch(string exe,string args,string dir){LaunchModulePath=Environment.GetEnvironmentVariable("PSModulePath");}
  public bool WaitForEmpty(int ms){WaitMs=ms;if(ms>0 && Mode.Contains("wait"))throw new TimeoutException("fixture-wait-limit");return true;}
  public int ExitCode(){return Mode.Contains("child")?9:0;}
  public void StopAndDrain(int ms){DrainMs=ms;if(Mode.Contains("drain"))throw new InvalidOperationException("fixture-drain-failure");}
  public void Dispose(){if(Mode.Contains("dispose"))throw new InvalidOperationException("fixture-dispose-failure");}
 }
}
'@
 $InstallDir='C:\Program Files\FDSecurity'
 foreach($case in @(@('success',$null,$null),@('child-drain','exit=9','fixture-drain-failure'),@('wait-drain','fixture-wait-limit','fixture-drain-failure'),@('child-dispose','exit=9','fixture-dispose-failure'),@('drain','fixture-drain-failure','fixture-drain-failure'),@('dispose','fixture-dispose-failure','fixture-dispose-failure'))){
  $EvidenceDir=Join-Path $root $case[0];New-Item -ItemType Directory $EvidenceDir|Out-Null
  [FDSecurity.InstallerJob]::Mode=$case[0]
  $modulePath=[Environment]::GetEnvironmentVariable('PSModulePath','Process')
  if($case[0] -eq 'success'){$result=Invoke-ExactMaintenanceSetupJob $fixture 'direct747-maintenance' 2147483648 $digest;Need ($result.job_empty -and $result.exit_code -eq 0) 'Successful bounded Job was not confirmed'}else{Reject {Invoke-ExactMaintenanceSetupJob $fixture 'direct747-maintenance' 2147483648 $digest}}
  $receipt=Get-Content (Join-Path $EvidenceDir 'direct747-maintenance.result.json') -Raw -Encoding UTF8|ConvertFrom-Json
  if($case[1]){Need ($receipt.first_failure -like ('*'+$case[1]+'*')) 'Cleanup replaced original failure';Need ($receipt.cleanup_failure -like ('*'+$case[2]+'*')) 'Cleanup failure lost'}
  Need ([FDSecurity.InstallerJob]::DrainMs -eq 5000 -and $receipt.limit_ms -eq 300000) 'Bounded existing Job contract changed'
  Need ([string]::IsNullOrEmpty([FDSecurity.InstallerJob]::LaunchModulePath)) 'Child inherited incompatible PowerShell module path'
  Need ([Environment]::GetEnvironmentVariable('PSModulePath','Process') -ceq $modulePath) 'Parent module path was not restored'
 }
 Reject {Invoke-ExactMaintenanceSetupJob $fixture 'unknown-stage' 2147483648 $digest}
 $completed=$true
 Write-Host "PASS: $count direct maintenance contract and bounded Job boundary assertions; no product execution"
}finally{foreach($key in $old.Keys){[Environment]::SetEnvironmentVariable($key,$old[$key],'Process')};if($completed){Remove-Item -LiteralPath $root -Recurse -Force}else{Write-Warning "Retained failed pure fixture: $root"}}
