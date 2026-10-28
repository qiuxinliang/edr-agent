#Requires -Version 5.1
[CmdletBinding()]
param([string]$RepoRoot = (Split-Path -Parent $PSScriptRoot))

# Run the real lifecycle orchestration functions; synthetic child updaters are
# the only external boundary. No service, task, installed Agent or real package
# is used by this regression.
$ErrorActionPreference = 'Stop'
$root = Join-Path ([IO.Path]::GetTempPath()) ('edr-upgrade-stability-ci-' + [Guid]::NewGuid().ToString('N'))
$savedProgramData = $env:ProgramData
New-Item -ItemType Directory -Path $root | Out-Null
function Check([bool]$Condition, [string]$Name) { if (-not $Condition) { throw "failed: $Name" } }
function Hash([string]$Path) { return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
function Put([string]$Path, [string]$Text) { [IO.File]::WriteAllText($Path, $Text, [Text.UTF8Encoding]::new($false)) }
function Must-Fail([scriptblock]$Action, [string]$Expected) {
  $caught = $false
  try { & $Action } catch { $caught = $true; Check ($_.Exception.Message -like $Expected) ('cause: '+$Expected) }
  Check $caught ('must reject: '+$Expected)
}
try {
  $tokens=$null; $errors=$null
  $ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $RepoRoot 'scripts/windows_setup_exe_lifecycle_smoke.ps1'),[ref]$tokens,[ref]$errors)
  Check ($errors.Count -eq 0) 'native parser'
  foreach ($name in @('Wait-LifecycleEmbeddedUpdater','Assert-LifecycleUpgradeResult','Get-LifecycleTrustedPublisher','Invoke-BaselineUpdaterUpgrade')) {
    $functions=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name},$true))
    Check ($functions.Count -eq 1) ('unique owner '+$name)
    . ([scriptblock]::Create($functions[0].Extent.Text))
  }
  $BaselineVersion='3.2.673'; $TargetVersion='3.2.725'; $Architecture='arm64'; $ServiceName='FDSecurityAgent'
  $InstallDir=Join-Path $root 'installed'; $EvidenceDir=Join-Path $root 'evidence'
  $env:ProgramData=Join-Path $root 'program-data'
  foreach($path in @($InstallDir,$EvidenceDir,(Join-Path $env:ProgramData 'FDSecurity\logs'))) {
    New-Item -ItemType Directory -Path $path -Force | Out-Null
  }
  $script:events=@()
  function Add-Evidence([string]$Stage,[string]$Status,[string]$Detail) { $script:events+=@{stage=$Stage;status=$Status;detail=$Detail} }
  $target=Join-Path $root 'FDSensor.next.exe'
  # An unsigned PE library is data for hash, copy and native NotSigned checks;
  # it is never executed as an Agent. Library output works in the workflow's
  # PowerShell 7 host, which cannot emit ConsoleApplication assemblies.
  # Invalid/trust outcomes below isolate only the Authenticode OS boundary.
  Add-Type -TypeDefinition 'public static class LifecycleUnsignedFixture { public static int Main() { return 0; } }' `
    -OutputAssembly $target -OutputType Library
  $setup=Join-Path $root 'FDSecuritySetup.exe';Copy-Item -LiteralPath $target -Destination $setup
  $newUpdater='throw "candidate updater must never execute the first hop"'
  Put (Join-Path $root 'new-updater.txt') $newUpdater
  Put (Join-Path $InstallDir 'uninstall.exe') 'synthetic uninstaller'
  $native=@{schema='edr.windows.native-package-integrity.v1';files=@(@{name='uninstall.exe';sha256=(Hash (Join-Path $InstallDir 'uninstall.exe'))})}
  Put (Join-Path $InstallDir 'native-package-integrity.json') ($native|ConvertTo-Json -Depth 5)
  $oldScript=@'
param($InstallDir,$StagedBinary,$ExpectedSha256,$TargetVersion,$ExpectedArchitecture,
  $TrustedPublisherThumbprint,$TrustedPublisherSubject,$DeploymentMode,$ServiceName,
  $CommandId,$TaskId,$ArtifactId,$Operation,$UpgradeClass,$IssuedAtUnixMs,$DeadlineUnixMs,
  $HealthObserveMs,$StartupTimeoutSeconds,$MinCurrentVersion,$MaxCurrentVersion,$MinFreeBytes,
  $RuntimeManifest,$RuntimeManifestSha256)
$ErrorActionPreference='Stop'
Copy-Item -LiteralPath $StagedBinary -Destination (Join-Path $InstallDir 'FDSensor.exe') -Force
Copy-Item -LiteralPath (Join-Path (Split-Path $StagedBinary -Parent) 'new-updater.txt') -Destination (Join-Path $InstallDir ("edr_agent_inplace_update-{0}.ps1" -f $TargetVersion)) -Force
$report=@{status='succeeded';target_version=$TargetVersion;upgrade_class=$UpgradeClass;operation=$Operation;
 expected_sha256=$ExpectedSha256;installed_sha256=$ExpectedSha256}
[IO.File]::WriteAllText((Join-Path $env:ProgramData ("FDSecurity\logs\agent-update-{0}-report.json" -f $CommandId)),($report|ConvertTo-Json))
[IO.File]::WriteAllText((Join-Path (Split-Path $StagedBinary -Parent) 'actual-arguments.json'),(@{class=$UpgradeClass;
 mode=$DeploymentMode;floor=$MinFreeBytes;health_ms=$HealthObserveMs;package=$RuntimeManifest;
 package_sha=$RuntimeManifestSha256;caller=$PSCommandPath}|ConvertTo-Json))
exit 0
'@
  $oldPath=Join-Path $InstallDir ('edr_agent_inplace_update-'+$BaselineVersion+'.ps1'); Put $oldPath $oldScript
  $inputBinding=[pscustomobject]@{schema='edr.windows.lifecycle-upgrade.v1';baseline_version=$BaselineVersion;
    target_version=$TargetVersion;architecture=$Architecture;deployment_mode='service';service_name=$ServiceName;
    upgrade_class='runtime_bundle';binary_path=$target;binary_sha256=(Hash $target);
    runtime_identity_sha256=(Hash (Join-Path $InstallDir 'native-package-integrity.json'));
    signature_status='unsigned';publisher_thumbprint='';publisher_subject='';installer_path=$setup;installer_sha256=(Hash $setup);
    baseline_updater_sha256=(Hash $oldPath);target_updater_sha256=(Hash (Join-Path $root 'new-updater.txt'));
    runtime_package=(Join-Path $root 'original-runtime.zip');runtime_package_sha256=('a'*64);
    min_current_version='0.0.0';max_current_version=$TargetVersion;min_free_bytes=268435456}
  foreach($class in @('binary_hot','runtime_bundle','installer_required')) {
    $inputBinding.upgrade_class=$class
    $inputBinding.runtime_package=if($class -eq 'binary_hot'){''}else{Join-Path $root 'original-runtime.zip'}
    Invoke-BaselineUpdaterUpgrade $inputBinding
    $actual=Get-Content -LiteralPath (Join-Path $root 'actual-arguments.json') -Raw|ConvertFrom-Json
    Check ($actual.class -ceq $class -and $actual.mode -ceq 'service') ('manifest class/mode '+$class)
    Check ($actual.caller -ceq $oldPath) ('old script actually invoked '+$class)
    Check ([uint64]$actual.floor -eq 268435456 -and [uint64]$actual.health_ms -eq 30000) 'floor/observation preserved'
    Check ([string]$actual.package -ceq $inputBinding.runtime_package) ('package forwarding '+$class)
    Check ((Hash $oldPath) -ceq $inputBinding.baseline_updater_sha256) 'old script unchanged'
  }
  function Get-AuthenticodeSignature {
    [CmdletBinding()]param([string]$LiteralPath)
    if($LiteralPath -ceq $script:rejectedInstaller){return [pscustomobject]@{Status='NotTrusted';SignerCertificate=$null}}
    return $script:authResult
  }
  try {
    $script:rejectedInstaller=''
    foreach($status in @('HashMismatch','NotTrusted','UnknownError','Valid')) {
      $script:authResult=[pscustomobject]@{Status=$status;SignerCertificate=$null}
      Must-Fail {Get-LifecycleTrustedPublisher $inputBinding} '*requires NotSigned*'
    }
    $inputBinding.signature_status='signed';$inputBinding.publisher_thumbprint='A'*40;$inputBinding.publisher_subject='CN=Release Publisher'
    foreach($status in @('NotSigned','HashMismatch','NotTrusted','UnknownError','Valid')) {
      $script:authResult=[pscustomobject]@{Status=$status;SignerCertificate=$null}
      Must-Fail {Get-LifecycleTrustedPublisher $inputBinding} '*requires Valid*'
    }
    $script:authResult=[pscustomobject]@{Status='Valid';SignerCertificate=[pscustomobject]@{Thumbprint=('B'*40);Subject='CN=Release Publisher'}}
    Must-Fail {Get-LifecycleTrustedPublisher $inputBinding} '*publisher differs*'
    $script:authResult.SignerCertificate.Thumbprint='A'*40;$script:authResult.SignerCertificate.Subject='CN=Other Publisher'
    Must-Fail {Get-LifecycleTrustedPublisher $inputBinding} '*publisher differs*'
    $script:authResult.SignerCertificate.Subject='CN=Release Publisher'
    $trusted=Get-LifecycleTrustedPublisher $inputBinding
    Check ($trusted.Thumbprint -ceq $inputBinding.publisher_thumbprint -and $trusted.Subject -ceq $inputBinding.publisher_subject) 'manifest owns signed publisher'
    $inputBinding.signature_status='unsigned';$inputBinding.publisher_thumbprint='';$inputBinding.publisher_subject=''
    $script:authResult=[pscustomobject]@{Status='NotSigned';SignerCertificate=$null};$script:rejectedInstaller=$setup
    Must-Fail {Get-LifecycleTrustedPublisher $inputBinding} '*requires NotSigned*'
  } finally { Remove-Item -LiteralPath Function:Get-AuthenticodeSignature }
  $inputBinding.deployment_mode='scheduled_task'
  Must-Fail {Invoke-BaselineUpdaterUpgrade $inputBinding} '*input identity/mode mismatch*'
  $inputBinding.deployment_mode='service'
  $savedHash=$inputBinding.baseline_updater_sha256; $inputBinding.baseline_updater_sha256='b'*64
  Must-Fail {Invoke-BaselineUpdaterUpgrade $inputBinding} '*differs from its immutable release*'
  $inputBinding.baseline_updater_sha256=$savedHash
  $goodReport=Get-Content -LiteralPath (Join-Path $EvidenceDir 'old-updater-report.json') -Raw|ConvertFrom-Json
  $goodReport.status='failed_rolled_back'
  Must-Fail {Assert-LifecycleUpgradeResult $inputBinding $goodReport} '*did not report*'
  $goodReport.status='succeeded'
  Put (Join-Path $InstallDir 'uninstall.exe') 'wrong runtime bytes'
  Must-Fail {Assert-LifecycleUpgradeResult $inputBinding $goodReport} '*mixed native runtime*'
  Put $oldPath "exit 7"; $inputBinding.baseline_updater_sha256=Hash $oldPath
  Must-Fail {Invoke-BaselineUpdaterUpgrade $inputBinding} '*failed with exit code 7*'
  Check (@($script:events|Where-Object{$_.status -eq 'verified'}).Count -eq 3) 'failures never counted as passed'
  Write-Output 'old updater lifecycle orchestration: 3 class executions, signed publisher binding and 17 negative controls passed'
} finally {
  $env:ProgramData=$savedProgramData
  Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction Stop
}
