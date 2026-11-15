#Requires -Version 5.1
[CmdletBinding()]
param([Parameter(Mandatory=$true)][ValidateSet('prepare','run')][string]$Mode)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Set-Location -LiteralPath $repo
$source = '984b955a64f5513377c465426faf45f9a0e9bf72'
$baselineSource = 'b51bc3d825e6d5666535463b34eb708201e6fda7'
$originalRun = '43672863753'
$evidence = Join-Path $repo 'preflight-diagnostic-evidence'
$probeRoot = Join-Path $env:RUNNER_TEMP 'preflight-diagnostic-probe'
$install = 'C:\edr-agent-setup-lifecycle-smoke'
$utf8 = [Text.UTF8Encoding]::new($false)

function Write-NewJson([string]$Path, $Value) {
  $bytes = $utf8.GetBytes(($Value | ConvertTo-Json -Depth 12))
  $file = [IO.File]::Open($Path, 'CreateNew', 'Write', 'None')
  try { $file.Write($bytes, 0, $bytes.Length); $file.Flush($true) } finally { $file.Dispose() }
}

if ($env:GITHUB_ACTIONS -cne 'true' -or $env:GITHUB_REPOSITORY -cne 'qiuxinliang/edr-agent' -or
    [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString() -cne 'X64') {
  throw 'Fixed diagnostic requires the disposable native AMD64 Actions host'
}

if ($Mode -ceq 'prepare') {
  New-Item -ItemType Directory -Path $evidence -ErrorAction Stop | Out-Null
  New-Item -ItemType Directory -Path 'release-metadata','downloads/target','downloads/baseline' -Force | Out-Null
  # Reuse the existing tested four-attempt downloader, including TLS, redirect,
  # partial-file, size and digest checks. No alternate download owner is added.
  $workflow = [IO.File]::ReadAllText((Join-Path $repo '.github/workflows/windows-install-upgrade-rollback.yml'))
  $download = [regex]::Match($workflow, '(?ms)^          function Get-ImmutableRelease\(.*?(?=^          \$targetRuntime = )')
  $resolve = [regex]::Match($workflow, '(?ms)^            function Resolve-ReleaseTagCommit\(.*?(?=^            \$targetRelease = )')
  if (-not $download.Success -or -not $resolve.Success) { throw 'Original immutable download owner is unavailable' }
  . ([scriptblock]::Create(($download.Value -replace '(?m)^          ', '')))
  . ([scriptblock]::Create(($resolve.Value -replace '(?m)^            ', '')))
  $script:immutableReleases = @{}
  $run = & gh api "repos/qiuxinliang/edr-agent/actions/runs/$originalRun/attempts/1" | ConvertFrom-Json
  if ($LASTEXITCODE -ne 0 -or [string]$run.id -cne $originalRun -or $run.run_attempt -ne 1 -or
      $run.head_sha -cne $source -or $run.head_branch -cne 'codex/upgrade-installer-stability' -or
      $run.event -cne 'workflow_dispatch' -or $run.status -cne 'completed' -or $run.conclusion -cne 'failure' -or
      $run.path -cne '.github/workflows/edr-agent-client-release.yml') {
    throw 'Original failed 746 run identity differs'
  }
  $target = Get-ImmutableRelease 'win_3.2.746'
  $baseline = Get-ImmutableRelease 'win_3.2.723'
  if (-not $target.draft -or $target.target_commitish -cne $source -or $baseline.draft -or
      (Resolve-ReleaseTagCommit 'win_3.2.746' $target) -cne $source -or
      (Resolve-ReleaseTagCommit 'win_3.2.723' $baseline) -cne $baselineSource) {
    throw 'Fixed target draft or published 723 identity differs'
  }
  foreach ($pair in @(@('win_3.2.746','target'),@('win_3.2.723','baseline'))) {
    foreach ($suffix in @('exe.zip','artifact-manifest.json')) {
      Download-ImmutableAsset $pair[0] ('edr-agent-'+$pair[0]+'-windows-amd64-'+$suffix) ('downloads/'+$pair[1])
    }
  }
  Write-NewJson 'release-metadata/target.json' $target
  Write-NewJson 'release-metadata/baseline.json' $baseline
  # This independent diagnostic binds the original failed source/run explicitly.
  # The production lifecycle's current-run checks remain authoritative there.
  $staged = & python scripts/windows_release_checkpoint.py stage-headless `
    --tag win_3.2.746 --arch amd64 --directory downloads/target --destination packages/target `
    --release-metadata release-metadata/target.json --tag-commit $source `
    --expected-source-commit $source --expected-run-id $originalRun
  if ($LASTEXITCODE -ne 0) { throw 'Original 746 Headless bytes failed admission' }
  Write-NewJson 'release-metadata/target-stage.json' ($staged | ConvertFrom-Json)
  $staged = & python scripts/windows_release_checkpoint.py stage-headless `
    --tag win_3.2.723 --arch amd64 --directory downloads/baseline --destination packages/baseline `
    --release-metadata release-metadata/baseline.json --tag-commit $baselineSource `
    --published-baseline --target-tag win_3.2.746
  if ($LASTEXITCODE -ne 0) { throw 'Original published 723 bytes failed admission' }
  Write-NewJson 'release-metadata/baseline-stage.json' ($staged | ConvertFrom-Json)
  $binding = & python scripts/windows_release_checkpoint.py prepare-lifecycle-upgrade `
    --directory downloads/target --baseline-directory downloads/baseline `
    --tag win_3.2.746 --baseline-tag win_3.2.723 --arch amd64 --destination release-metadata/lifecycle-upgrade
  if ($LASTEXITCODE -ne 0) { throw 'Original updater transition failed admission' }
  Write-NewJson (Join-Path $evidence 'inputs.json') @{
    schema='edr.test.preflight-diagnostic-inputs.v1'; diagnostic_only=$true;
    harness_commit=$env:GITHUB_SHA; source_commit=$source; source_run=$originalRun; source_attempt=1;
    baseline_source=$baselineSource; baseline_release=$baseline.id; target_release=$target.id;
    transition=($binding | ConvertFrom-Json)
  }
  return
}

function Invoke-PreflightCollector([string]$Stage, [string]$Failure='') {
  $arguments = @('-I','-B',(Join-Path $repo 'tests/preflight_diagnostic/capture.py'),$Stage,
    '--install-dir',$install,'--probe-root',$probeRoot,'--output-root',(Join-Path $evidence 'capture'),'--synthetic-ci')
  if ($Stage -ceq 'after') {
    $arguments += @('--baseline-exe',(Join-Path $repo 'packages/baseline/FDSensor.exe'),'--failure',$Failure,
      '--stable-copy-on-change')
  }
  $quoted = @($arguments | ForEach-Object { "'" + $_.Replace("'", "''") + "'" }) -join ' '
  $python = (Get-Command python.exe -ErrorAction Stop).Source
  $stdout = Join-Path $evidence ('collector-'+$Stage+'.stdout')
  $stderr = Join-Path $evidence ('collector-'+$Stage+'.stderr')
  if ((Test-Path $stdout) -or (Test-Path $stderr)) { throw 'Collector output already exists' }
  $child = "`$ErrorActionPreference='Stop';& '"+$python.Replace("'","''")+"' "+$quoted+
    " 1> '"+$stdout.Replace("'","''")+"' 2> '"+$stderr.Replace("'","''")+"';exit `$LASTEXITCODE"
  $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($child))
  $shell = (Get-Process -Id $PID).Path
  $job = [FDSecurity.InstallerJob]::Create('Local\EDR.PreflightDiagnostic.'+[Guid]::NewGuid().ToString('N'))
  try {
    $clock = [Diagnostics.Stopwatch]::StartNew()
    $job.Launch($shell, ('-NoProfile -NonInteractive -EncodedCommand '+$encoded), $repo)
    while ($true) {
      $empty = $job.WaitForEmpty(100)
      $large = @($stdout,$stderr | Where-Object { (Test-Path $_) -and (Get-Item $_).Length -gt 262144 })
      if ($large.Count) {
        $job.StopAndDrain(5000)
        foreach ($path in $large) {
          $file = [IO.File]::Open($path, 'Open', 'Write', 'None')
          try { $file.SetLength(262144) } finally { $file.Dispose() }
        }
        throw 'Collector output exceeded 256 KiB; process tree stopped and retained output bounded'
      }
      if ($clock.ElapsedMilliseconds -ge 90000) {
        $job.StopAndDrain(5000)
        throw 'Collector exceeded the 90-second outer deadline; process tree stopped'
      }
      if ($empty) { break }
    }
    if ($job.ExitCode() -ne 0) { throw 'Collector failed; inspect its bounded diagnostic files' }
  } finally {
    try { $job.StopAndDrain(5000) } finally { $job.Dispose() }
  }
}

$harness = Join-Path $repo 'scripts/windows_setup_exe_lifecycle_smoke.ps1'
$body = [IO.File]::ReadAllText($harness).Replace("`r`n", "`n")
$hasher = [Security.Cryptography.SHA256]::Create()
try { $hash = ([BitConverter]::ToString($hasher.ComputeHash($utf8.GetBytes($body)))).Replace('-','').ToLowerInvariant() }
finally { $hasher.Dispose() }
if ($hash -cne 'cab5d85fa748c98ca4e06a759774b61c5ff505114332dd86c56b8a6edc158cb0') {
  throw 'Original 984 lifecycle harness changed'
}
$before = '    Invoke-Installer $BaselineSetupExe "rollback-baseline" $true'
$failed = '  $lifecycleFailure = $_'
if (($body.Split(@($before),[StringSplitOptions]::None).Length -ne 2) -or
    ($body.Split(@($failed),[StringSplitOptions]::None).Length -ne 2)) {
  throw 'Original rollback/catch boundary is ambiguous'
}
$captureBefore = @'
    try { Invoke-PreflightCollector 'before' }
    catch {
      Write-NewJson (Join-Path $evidence 'before-error.json') @{
        status='diagnostic_unavailable'; original_rollback_executed=$false; cause=$_.Exception.GetType().Name
      }
      Write-Warning 'Before sampling failed; original rollback will still execute'
    }
'@
$body = $body.Replace($before, $captureBefore+"`n"+$before)
$after = @'
  if ($script:LastLifecycleStage -ceq 'rollback-baseline' -and
      -not (Test-Path (Join-Path $evidence 'before-error.json'))) {
    try { Invoke-PreflightCollector 'after' $lifecycleFailure.Exception.Message }
    catch { Write-Warning ('Collector incomplete: '+$_.Exception.GetType().Name+'; original lifecycle failure retained') }
  }
'@
$body = $body.Replace($failed, $failed+"`n"+$after)
$temporary = Join-Path (Split-Path -Parent $harness) '.preflight-diagnostic-746.ps1'
$jobSource = Join-Path $repo 'scripts/installer_job/InstallerJob.cs'
if (-not ('FDSecurity.InstallerJob' -as [type])) { Add-Type -Path $jobSource }
$targetStage = Get-Content -Raw 'release-metadata/target-stage.json' | ConvertFrom-Json
$baselineStage = Get-Content -Raw 'release-metadata/baseline-stage.json' | ConvertFrom-Json
$inputBinding = Get-Content -Raw (Join-Path $evidence 'inputs.json') | ConvertFrom-Json
if ($inputBinding.source_commit -cne $source -or $inputBinding.source_run -cne $originalRun -or $inputBinding.source_attempt -ne 1) {
  throw 'Prepared original transition identity differs'
}
if (Test-Path -LiteralPath $temporary) { throw 'Diagnostic harness destination already exists' }
[IO.File]::WriteAllText($temporary, $body, $utf8)
try {
  & $temporary -BaselineSetupExe $baselineStage.setup_exe -TargetSetupExe $targetStage.setup_exe `
    -BaselineVersion '3.2.723' -TargetVersion '3.2.746' -Architecture amd64 -InstallDir $install `
    -EvidenceDir setup-exe-evidence -UpgradeInput release-metadata/lifecycle-upgrade/transition.json `
    -BaselineConfigTemplate packages/baseline/agent_windows_production.example.toml -ExerciseInstallerTimeout
  Write-NewJson (Join-Path $evidence 'outcome.json') @{
    schema='edr.test.preflight-diagnostic-outcome.v1'; status='not_reproduced'; cause='unknown'; diagnostic_only=$true
  }
} catch {
  Write-NewJson (Join-Path $evidence 'outcome.json') @{
    schema='edr.test.preflight-diagnostic-outcome.v1'; status='original_lifecycle_failed';
    diagnostic_only=$true; after_recorded=(Test-Path (Join-Path $evidence 'capture/after.json'));
    before_unavailable=(Test-Path (Join-Path $evidence 'before-error.json'))
  }
  throw
} finally { [IO.File]::Delete($temporary) }
throw 'The rollback failure did not reproduce; cause remains unknown; stop this diagnostic round'
