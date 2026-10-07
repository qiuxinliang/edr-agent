#Requires -Version 5.1
param([string]$InstallerWorker, [string]$RepoRoot)
$ErrorActionPreference = 'Stop'
$root = Join-Path ([IO.Path]::GetTempPath()) ('edr-installer-health-' + [Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($root) | Out-Null
$report = Join-Path $root 'runtime.json'
$config = Join-Path $root 'agent.toml'
$binary = Join-Path $root 'FDSensor.exe'
function Assert-True([bool]$Condition, [string]$Message) { if (-not $Condition) { throw $Message } }
function Assert-FileReleased([string]$Path) {
  $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
  try { Assert-True ($stream.Length -ge 0) 'Config must allow immediate exclusive access' }
  finally { $stream.Dispose() }
}
try {
  # Extract only the real reader functions, never installation/service entrypoints.
  # FileShare.None checks early returns immediately without relying on GC.
  $readerConfig = Join-Path $root 'reader.toml'
  foreach ($reader in @(
      @('scripts/edr_agent_postinstall_verify.ps1', 'Read-TomlString'),
      @('scripts/edr_agent_install.ps1', 'Read-AgentTomlScalar'),
      @('scripts/windows_service_install.ps1', 'Read-AgentTomlScalar'))) {
    $tokens = $null; $parseErrors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $RepoRoot $reader[0]), [ref]$tokens, [ref]$parseErrors)
    Assert-True (@($parseErrors).Count -eq 0) ('Reader source must parse: ' + $reader[0])
    $readerName = $reader[1]
    $node = @($ast.EndBlock.Statements | Where-Object { $_ -is [Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -eq $readerName })
    Assert-True ($node.Count -eq 1) ('Missing unique production reader: ' + $readerName)
    . ([scriptblock]::Create($node[0].Extent.Text))
    [IO.File]::WriteAllText($readerConfig, "first = `"first-value`"`nliteral.key = `"middle-value`"`nempty = `"`"`nlast = `"last-value`"")
    foreach ($sample in @(@('first','first-value'), @('literal.key','middle-value'), @('empty',''), @('last','last-value'), @('absent',''))) {
      $value = & $readerName -Path $readerConfig -Key $sample[0]
      Assert-True ([string]$value -ceq $sample[1]) ('Unexpected TOML scalar from ' + $reader[0] + ': ' + $sample[0])
      Assert-FileReleased $readerConfig
    }
    $value = & $readerName -Path (Join-Path $root 'missing-reader.toml') -Key first
    Assert-True ([string]$value -eq '') 'Missing TOML must return an empty scalar'
  }

  # Exercise the production atomic writer directly, including its failure path.
  $verifier = Join-Path $RepoRoot 'scripts/edr_agent_postinstall_verify.ps1'
  $tokens = $null; $parseErrors = $null
  $ast = [Management.Automation.Language.Parser]::ParseFile($verifier, [ref]$tokens, [ref]$parseErrors)
  Assert-True (@($parseErrors).Count -eq 0) 'Verifier source must parse'
  foreach ($name in @('Write-VerifyLog', 'Write-Report')) {
    $node = @($ast.EndBlock.Statements | Where-Object { $_ -is [Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -eq $name })
    Assert-True ($node.Count -eq 1) ('Missing unique production writer: ' + $name)
    . ([scriptblock]::Create($node[0].Extent.Text))
  }
  $ReportPath = Join-Path $root 'atomic-runtime.json'
  $LogPath = Join-Path $root 'atomic-runtime.log'
  foreach ($round in 1..3) {
    $checkId = [Guid]::NewGuid().ToString('N')
    Write-Report -Report ([ordered]@{status='ok'; check_id=$checkId; round=$round})
    $written = [IO.File]::ReadAllText($ReportPath) | ConvertFrom-Json
    Assert-True ($written.check_id -eq $checkId -and $written.round -eq $round) 'Atomic creation/replacement must publish the complete current report'
    Assert-True (@(Get-ChildItem -LiteralPath $root -Filter 'atomic-runtime.json.*.tmp').Count -eq 0) 'Successful report publication must remove its temporary file'
  }
  $previousBytes = [Convert]::ToBase64String([IO.File]::ReadAllBytes($ReportPath))
  $lockedReport = [IO.File]::Open($ReportPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None)
  $writeFailure = $null
  try {
    try { Write-Report -Report ([ordered]@{status='failed'; check_id='must-not-publish'}) }
    catch { $writeFailure = $_.Exception }
  } finally { $lockedReport.Dispose() }
  Assert-True ($null -ne $writeFailure -and $writeFailure.GetBaseException() -is [IO.IOException]) 'Locked destination must fail explicitly with an I/O cause'
  Assert-True ([Convert]::ToBase64String([IO.File]::ReadAllBytes($ReportPath)) -eq $previousBytes) 'Failed replacement must preserve the previous complete report'
  Assert-True (@(Get-ChildItem -LiteralPath $root -Filter 'atomic-runtime.json.*.tmp').Count -eq 0) 'Failed replacement must remove its temporary file'

  [IO.File]::WriteAllText($config, "endpoint_id = `"test`"`ntenant_id = `"test`"`n[platform]`nrest_base_url = `"https://example.invalid`"")
  [IO.File]::WriteAllText((Join-Path $root 'VERSION'), 'test-version')
  [IO.File]::WriteAllText($report, '{"status":"ok","check_id":"old"}')
  [IO.File]::WriteAllText((Join-Path $root 'install_health_report.json'), '{"status":"ok"}')
  # Native worker only queries a nonexistent fixture service and this fixture path.
  $service = 'edr-health-fixture-' + [Guid]::NewGuid().ToString('N')
  $oldId = 'old'
  foreach ($round in 1..2) {
    & $InstallerWorker --stage write-health-summary --install-dir $root --config $config --report $report --log (Join-Path $root 'native.log') --runtime-mode service --service-name $service --run-id native-test
    Assert-True ($LASTEXITCODE -ne 0) 'Absent runtime must fail even with an old successful report'
    $r = Get-Content -LiteralPath $report -Raw | ConvertFrom-Json
    Assert-True ($r.check_id -and $r.check_id -ne $oldId -and $r.created_at -and $r.worker_version) 'Native checks must have fresh identity, time and version'
    Assert-True ($r.binary_state -eq 'missing' -and $r.service_state -eq 'missing' -and $r.status -eq 'failed') 'Native absence states must be explicit'
    $oldId = $r.check_id
  }

  # Execute the real verifier with only OS query boundaries replaced. No service,
  # scheduled task, remote host or running Agent on this machine is modified.
  [IO.File]::WriteAllText($binary, 'fixture')
  # Let query boundaries find the fixture in their parent scope. The verifier
  # runs as a child .ps1, whose script scope does not own these test variables.
  $fixtureProcess = 'running'
  $fixtureService = 'Running'
  $fixtureTask = 'Ready'
  function Get-CimInstance {
    [CmdletBinding()]param($ClassName, $Filter)
    if ($fixtureProcess -eq 'unknown') { throw 'fixture query denied' }
    if ($fixtureProcess -eq 'running') { [pscustomobject]@{ ExecutablePath = $binary } }
    if ($fixtureProcess -eq 'unrelated') { [pscustomobject]@{ ExecutablePath = 'C:\unrelated\FDSensor.exe' } }
  }
  function Get-Service {
    [CmdletBinding()]param()
    if ($fixtureService -eq 'unknown') { throw 'fixture query denied' }
    if ($fixtureService -ne 'missing') { [pscustomobject]@{Name='FDSecurityAgent'; Status=$fixtureService} }
  }
  function Get-ScheduledTask {
    [CmdletBinding()]param()
    [pscustomobject]@{TaskName='FDSecurityAgent'; State=$fixtureTask}
  }
  function Get-ScheduledTaskInfo { [CmdletBinding()]param($InputObject) [pscustomobject]@{LastTaskResult=0} }
  foreach ($case in @(
      @('running','Running','service','ok'), @('running','Stopped','service','failed'),
      @('running','missing','service','failed'), @('running','unknown','service','unknown'),
      @('missing','Running','service','failed'), @('unrelated','Running','service','failed'),
      @('unknown','Running','service','unknown'), @('running','missing','scheduled_task','failed'),
      @('running','missing','manual','ok'))) {
    $fixtureProcess=$case[0]; $fixtureService=$case[1]
    & $verifier -InstallDir $root -ConfigPath $config -ReportPath $report -LogPath (Join-Path $root 'verify.log') -RuntimeMode $case[2] -InstallationRunId ps-test
    $code = $LASTEXITCODE
    $r = Get-Content -LiteralPath $report -Raw | ConvertFrom-Json
    $expectedProcess = if ($case[0] -eq 'unrelated') { 'missing' } else { $case[0] }
    Assert-True ($r.process_state -eq $expectedProcess) ('Verifier must observe the process fixture for ' + ($case -join ','))
    Assert-True ($r.service_state -eq $case[1].ToLowerInvariant()) ('Verifier must observe the service fixture for ' + ($case -join ','))
    Assert-True ($r.scheduled_task_state -eq $fixtureTask.ToLowerInvariant()) ('Verifier must observe the task fixture for ' + ($case -join ','))
    Assert-True ($r.status -eq $case[3]) ('Unexpected verification result for ' + ($case -join ','))
    Assert-True (($code -eq 0) -eq ($case[3] -eq 'ok')) 'Only current successful verification may return zero'
    Assert-True ($r.check_id -ne $oldId -and $r.installation_run_id -eq 'ps-test') 'Verifier must replace historical results'
    Assert-FileReleased $config
    $oldId=$r.check_id
  }
  Remove-Item -LiteralPath $binary
  & $verifier -InstallDir $root -ConfigPath $config -ReportPath $report -LogPath (Join-Path $root 'verify.log') -RuntimeMode manual
  $r = Get-Content -LiteralPath $report -Raw | ConvertFrom-Json
  Assert-True ($r.binary_state -eq 'missing' -and $r.status -eq 'failed') 'Removed binary must fail current health'
  Assert-FileReleased $config
  & (Join-Path $RepoRoot 'tests/test_windows_policy_verifier_auth.ps1') -RepoRoot $RepoRoot
  Write-Host 'PASS: released TOML readers, atomic reports and fresh native/verifier health states'
} catch {
  $testFailure = $_
  # Preserve the synthetic fixture report in CTest output before strict cleanup.
  # This includes the first failed check without retaining temporary test files.
  try {
    if (Test-Path -LiteralPath $report -PathType Leaf) {
      Write-Host ('installer_health_failure_report=' + [IO.File]::ReadAllText($report))
    }
  } catch { Write-Warning ('Could not read the synthetic failure report: ' + $_.Exception.Message) }
  throw $testFailure
} finally { Remove-Item -LiteralPath $root -Recurse -Force }
