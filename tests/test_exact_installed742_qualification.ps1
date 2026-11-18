#Requires -Version 5.1
# Pure boundary and copy-integrity tests. No Setup, task control or product execution.
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '../scripts/Exact-Installed742Qualification.ps1')
$count=0
function Need($value,$message){if(!$value){throw $message};$script:count++}
function Reject([scriptblock]$code){$caught=$false;try{& $code}catch{$caught=$true};Need $caught 'Expected refusal absent'}
$old=@{actions=$env:GITHUB_ACTIONS;environment=$env:RUNNER_ENVIRONMENT;arch=$env:RUNNER_ARCH}
$root=Join-Path ([IO.Path]::GetTempPath()) ('edr-exact742-test-'+[guid]::NewGuid().ToString('N'))
try{
 $env:GITHUB_ACTIONS='true';$env:RUNNER_ENVIRONMENT='github-hosted';$env:RUNNER_ARCH='ARM64'
 $good=@{schema='edr.exact-installed-742-to-747.inputs.v1';source_version='3.2.742';target_version='3.2.747';architecture='arm64';runtime_mode='scheduled_task';old_full_setup_rollback_supported=$false;source_installed_agent_sha256='e6ea9736829d0c0be5284c570f198ec888bcaad1845a074ea8838ebf6b326dbe';source_installed_updater_sha256='cae170855648559201c20b62d2d72d1bf2f030b61f5fda8ba27aa7534bd7a183';source_installed_launcher_sha256='656d349640d5403af0881bb5db7a4811074450cb93b6602c1322f03edfafd8c3'}
 Assert-Exact742QualificationContract ([pscustomobject]$good) 'C:\Program Files\FDSecurity' arm64 scheduled_task FDSecurityAgent
 foreach($pair in @(@('source_version','3.2.687'),@('target_version','3.2.748'),@('architecture','amd64'),@('runtime_mode','service'),@('old_full_setup_rollback_supported',$true),@('source_installed_updater_sha256','88912072d0e842bb07c1ee730b91233f39e0e8dad57e403990c702bda58edc2a'))){$bad=$good.Clone();$bad[$pair[0]]=$pair[1];Reject {Assert-Exact742QualificationContract ([pscustomobject]$bad) 'C:\Program Files\FDSecurity' arm64 scheduled_task FDSecurityAgent}}
 Reject {Assert-Exact742QualificationContract ([pscustomobject]$good) 'C:\Program Files\FDSecurity' arm64 scheduled_task WrongAgent}
 Reject {Assert-Exact742QualificationContract ([pscustomobject]$good) 'C:\edr-agent-setup-lifecycle-exact' arm64 scheduled_task FDSecurityAgent}
 $env:RUNNER_ENVIRONMENT='self-hosted';Reject {Assert-Exact742QualificationContract ([pscustomobject]$good) 'C:\Program Files\FDSecurity' arm64 scheduled_task FDSecurityAgent};$env:RUNNER_ENVIRONMENT='github-hosted'
 # Observe that metadata and native bytes are checked, never rewritten.
 . (Join-Path $PSScriptRoot 'Invoke-LifecycleStorageCompatibility.ps1')
 New-Item -ItemType Directory $root|Out-Null
 $roles=@('source_setup','target_setup','source_fixture_updater','source_fixture_task_owner','source_manifest','source_cms','source_proof','target_manifest','target_cms','target_proof','source_runtime_archive')
 $bindings=@();$byRole=@{}
 foreach($role in $roles){$path=Join-Path $root ($role+'.bin');[IO.File]::WriteAllText($path,$role);$byRole[$role]=$path;$bindings+=@{role=$role;path=$path;sha256=(Get-FileHash $path).Hash.ToLowerInvariant()}}
 $fixture=[pscustomobject]@{file_bindings=$bindings;source_setup_exe=$byRole.source_setup;target_setup_exe=$byRole.target_setup;source_fixture_updater=$byRole.source_fixture_updater;source_fixture_task_owner=$byRole.source_fixture_task_owner;source_publisher_proof=$byRole.source_proof;target_publisher_proof=$byRole.target_proof}
 Assert-Exact742FileBindings $fixture
 $fixture.file_bindings=@($bindings[0..9]);Reject {Assert-Exact742FileBindings $fixture}
 $fixture.file_bindings=@($bindings)+@($bindings[0]);Reject {Assert-Exact742FileBindings $fixture}
 $fixture.file_bindings=$bindings;$fixture.source_setup_exe=$byRole.target_setup;Reject {Assert-Exact742FileBindings $fixture}
 $fixture.source_setup_exe=$byRole.source_setup;[IO.File]::AppendAllText($byRole.source_setup,'changed');Reject {Assert-Exact742FileBindings $fixture}
 $native=Join-Path $root 'fixture.dll';[IO.File]::WriteAllBytes($native,[byte[]]@(1,2,3))
 $metadata=Join-Path $root 'native-package-integrity.json';@{files=@(@{name='fixture.dll';sha256=(Get-FileHash $native).Hash.ToLowerInvariant()})}|ConvertTo-Json -Depth 5|Set-Content $metadata -Encoding UTF8
 $hash=(Get-FileHash $metadata).Hash.ToLowerInvariant();$original=[IO.File]::ReadAllBytes($metadata)
 Assert-Exact742Integrity $root $hash
 [IO.File]::WriteAllBytes($native,[byte[]]@(1,2,4));Reject {Assert-Exact742Integrity $root $hash}
 Need ([Convert]::ToBase64String($original) -ceq [Convert]::ToBase64String([IO.File]::ReadAllBytes($metadata))) 'Integrity validator rewrote metadata'
 [IO.File]::AppendAllText($metadata,' ');Reject {Assert-Exact742Integrity $root $hash}
 # Isolated process-tree boundary double: no process is created or terminated.
 Add-Type @'
using System;
namespace FDSecurity {
 public sealed class InstallerJob : IDisposable {
  public static string Mode;
  public static InstallerJob Create(string name){return new InstallerJob();}
  public void Launch(string exe,string args,string directory){}
  public bool WaitForEmpty(int ms){return ms==0 || !Mode.Contains("timeout");}
  public int ExitCode(){return Mode.Contains("child")?9:0;}
  public void StopAndDrain(int ms){if(Mode.Contains("drain"))throw new InvalidOperationException("fixture-drain-failed");}
  public void Dispose(){if(Mode.Contains("dispose"))throw new InvalidOperationException("fixture-dispose-failed");}
 }
}
'@
 $fakeSource=Join-Path $root 'fake-owner.ps1';[IO.File]::WriteAllText($fakeSource,'function Initialize-InstallerJobType {}')
 foreach($case in @(
  @('child-drain','materialization failed','fixture-drain-failed'),
  @('timeout-drain','exceeded20s','fixture-drain-failed'),
  @('child-dispose','materialization failed','fixture-dispose-failed'),
  @('drain','fixture-drain-failed','fixture-drain-failed'),
  @('dispose','fixture-dispose-failed','fixture-dispose-failed')
 )){
  [FDSecurity.InstallerJob]::Mode=$case[0]
  $caseRoot=Join-Path $root $case[0];New-Item -ItemType Directory $caseRoot|Out-Null
  Reject {Invoke-Exact742Materialization $fakeSource 'not-executed.ps1' $caseRoot}
  $receipt=Get-Content (Join-Path $caseRoot 'exact742-materialization-result.json') -Raw -Encoding UTF8|ConvertFrom-Json
  Need ($receipt.first_failure -like ('*'+$case[1]+'*')) 'Cleanup replaced the materialization first cause'
  Need ($receipt.cleanup_failure -like ('*'+$case[2]+'*')) 'Cleanup failure evidence absent'
 }
 $parameterFile=Join-Path $root 'parameters.json';[IO.File]::WriteAllText($parameterFile,'{}')
 $pin=(Get-FileHash $parameterFile).Hash.ToLowerInvariant();Assert-Exact742ParametersUnchanged $parameterFile $pin
 [IO.File]::AppendAllText($parameterFile,' ');Reject {Assert-Exact742ParametersUnchanged $parameterFile $pin}
 Write-Host "PASS: $count exact installed qualification boundary assertions; no Setup/task execution"
}finally{$env:GITHUB_ACTIONS=$old.actions;$env:RUNNER_ENVIRONMENT=$old.environment;$env:RUNNER_ARCH=$old.arch;if(Test-Path $root){Remove-Item -LiteralPath $root -Recurse -Force}}
