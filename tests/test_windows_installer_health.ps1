#Requires -Version 5.1
param([string]$InstallerWorker, [string]$RepoRoot)
$ErrorActionPreference = 'Stop'
$root = Join-Path ([IO.Path]::GetTempPath()) ('edr-installer-health-' + [Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($root) | Out-Null
$report = Join-Path $root 'runtime.json'
$config = Join-Path $root 'agent.toml'
$binary = Join-Path $root 'FDSensor.exe'
function Assert-True([bool]$Condition, [string]$Message) { if (-not $Condition) { throw $Message } }
try {
  [IO.File]::WriteAllText($config, "endpoint_id = `"test`"`ntenant_id = `"test`"`nrest_base_url = `"https://example.invalid`"")
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
  $script:fixtureProcess = 'running'
  $script:fixtureService = 'Running'
  $script:fixtureTask = 'Ready'
  function Get-CimInstance {
    [CmdletBinding()]param($ClassName, $Filter)
    if ($script:fixtureProcess -eq 'unknown') { throw 'fixture query denied' }
    if ($script:fixtureProcess -eq 'running') { [pscustomobject]@{ ExecutablePath = $binary } }
    if ($script:fixtureProcess -eq 'unrelated') { [pscustomobject]@{ ExecutablePath = 'C:\unrelated\FDSensor.exe' } }
  }
  function Get-Service {
    [CmdletBinding()]param()
    if ($script:fixtureService -eq 'unknown') { throw 'fixture query denied' }
    if ($script:fixtureService -ne 'missing') { [pscustomobject]@{Name='FDSecurityAgent'; Status=$script:fixtureService} }
  }
  function Get-ScheduledTask {
    [CmdletBinding()]param()
    [pscustomobject]@{TaskName='FDSecurityAgent'; State=$script:fixtureTask}
  }
  function Get-ScheduledTaskInfo { [CmdletBinding()]param($InputObject) [pscustomobject]@{LastTaskResult=0} }
  $verifier = Join-Path $RepoRoot 'scripts/edr_agent_postinstall_verify.ps1'
  foreach ($case in @(
      @('running','Running','service','ok'), @('running','Stopped','service','failed'),
      @('running','missing','service','failed'), @('running','unknown','service','unknown'),
      @('missing','Running','service','failed'), @('unrelated','Running','service','failed'),
      @('unknown','Running','service','unknown'), @('running','missing','scheduled_task','failed'),
      @('running','missing','manual','ok'))) {
    $script:fixtureProcess=$case[0]; $script:fixtureService=$case[1]
    & $verifier -InstallDir $root -ConfigPath $config -ReportPath $report -RuntimeMode $case[2] -InstallationRunId ps-test
    $code = $LASTEXITCODE
    $r = Get-Content -LiteralPath $report -Raw | ConvertFrom-Json
    Assert-True ($r.status -eq $case[3]) ('Unexpected verification result for ' + ($case -join ','))
    Assert-True (($code -eq 0) -eq ($case[3] -eq 'ok')) 'Only current successful verification may return zero'
    Assert-True ($r.check_id -ne $oldId -and $r.installation_run_id -eq 'ps-test') 'Verifier must replace historical results'
    $oldId=$r.check_id
  }
  Remove-Item -LiteralPath $binary
  & $verifier -InstallDir $root -ConfigPath $config -ReportPath $report -RuntimeMode manual
  $r = Get-Content -LiteralPath $report -Raw | ConvertFrom-Json
  Assert-True ($r.binary_state -eq 'missing' -and $r.status -eq 'failed') 'Removed binary must fail current health'
  Write-Host 'PASS: fresh native reports and verifier running/stopped/absent/unknown/path identity behavior'
} finally { Remove-Item -LiteralPath $root -Recurse -Force }
