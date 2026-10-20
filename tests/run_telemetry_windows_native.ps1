# Test-only runner: already configured native Windows build with real dependencies.
# No service, installer, production URL or persistent endpoint queue is started.
param(
  [Parameter(Mandatory = $true)][string]$BuildDir,
  [ValidateSet('Debug','RelWithDebInfo','Release')][string]$Configuration = 'Debug',
  [string]$OpenSslBin = '',
  [switch]$IncludeReleaseGate
)
$ErrorActionPreference = 'Stop'
$build = (Resolve-Path -LiteralPath $BuildDir).Path
# Like the existing JUnit output, this fixed log describes only this invocation.
# Invalidate a previous release copy even if this run fails before reaching CTest.
if ($IncludeReleaseGate) {
  $previousReleaseLog = Join-Path $build 'native-release-LastTest.log'
  if (Test-Path -LiteralPath $previousReleaseLog) { Remove-Item -LiteralPath $previousReleaseLog -Force }
}
if (!(Test-Path -LiteralPath (Join-Path $build 'CMakeCache.txt'))) { throw 'Configure a native Windows EDR build with real SQLite, OpenSSL and verified PCRE2 first.' }
if ($OpenSslBin) {
  $openssl = Join-Path $OpenSslBin 'openssl.exe'
  if (!(Test-Path -LiteralPath $openssl)) { throw 'OpenSslBin must contain openssl.exe for temporary synthetic certificates.' }
}
# Preserve complete successful release output before telemetry rewrites LastTest.
# This is this invocation's synthetic build log, not an endpoint evidence export.
function Save-NativeReleaseLog([string]$BuildPath) {
  $sourcePath = Join-Path $BuildPath 'Testing/Temporary/LastTest.log'
  $savedPath = Join-Path $BuildPath 'native-release-LastTest.log'
  if (!(Test-Path -LiteralPath $sourcePath -PathType Leaf) -or
      ((Get-Item -LiteralPath $sourcePath).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
    throw 'Native release LastTest log is missing or is not a regular file.'
  }
  $limit = 8 * 1024 * 1024
  $temporaryPath = $savedPath + '.tmp-' + [Guid]::NewGuid().ToString('N')
  $sourceStream = $null
  $savedStream = $null
  try {
    $sourceStream = [IO.File]::Open($sourcePath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    $initialLength = $sourceStream.Length
    if ($initialLength -gt $limit) { throw 'Native release LastTest exceeds the 8MiB preservation bound.' }
    $savedStream = [IO.File]::Open($temporaryPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    $copyBuffer = New-Object byte[] 65536
    $copiedBytes = 0
    while ($true) {
      $readLimit = [int][Math]::Min($copyBuffer.Length, $limit - $copiedBytes + 1)
      $readBytes = $sourceStream.Read($copyBuffer, 0, $readLimit)
      if ($readBytes -eq 0) { break }
      if ($copiedBytes + $readBytes -gt $limit) { throw 'Native release LastTest exceeds the 8MiB preservation bound.' }
      $savedStream.Write($copyBuffer, 0, $readBytes)
      $copiedBytes += $readBytes
    }
    if ($copiedBytes -ne $initialLength -or $sourceStream.Length -ne $initialLength) { throw 'Native release LastTest changed during preservation.' }
    $savedStream.Flush($true)
    $savedStream.Dispose(); $savedStream = $null
    $sourceStream.Dispose(); $sourceStream = $null
    [IO.File]::Move($temporaryPath, $savedPath)
  } finally {
    if ($null -ne $savedStream) { $savedStream.Dispose() }
    if ($null -ne $sourceStream) { $sourceStream.Dispose() }
    if (Test-Path -LiteralPath $temporaryPath) { Remove-Item -LiteralPath $temporaryPath -Force }
  }
}

$oldPath = $env:PATH
$edrOverrides = @{}
Get-ChildItem Env: | Where-Object Name -Like 'EDR_*' | ForEach-Object { $edrOverrides[$_.Name] = $_.Value }
try {
  # Prevent inherited endpoint configuration from changing an isolated fixture.
  foreach ($name in $edrOverrides.Keys) { [Environment]::SetEnvironmentVariable($name, $null, 'Process') }
  if ($OpenSslBin) { $env:PATH = "$OpenSslBin;$oldPath" }
  if (!(Get-Command openssl -ErrorAction SilentlyContinue)) { throw 'OpenSSL executable required for loopback fixture certificates.' }
  $listing = & ctest --test-dir $build -C $Configuration -N --show-only=json-v1
  if ($LASTEXITCODE -ne 0) { throw 'CTest inventory failed.' }
  $inventory = ($listing -join "`n") | ConvertFrom-Json
  $telemetryTests = @($inventory.tests | Where-Object {
    'telemetry-minimization' -in @($_.properties | Where-Object name -EQ 'LABELS' | ForEach-Object value)
  })
  $releaseTests = @($inventory.tests | Where-Object {
    'windows-release-gate' -in @($_.properties | Where-Object name -EQ 'LABELS' | ForEach-Object value)
  })
  $required = @('egress_batch_policy','egress_request_policy','command_result_egress','command_result_compaction','egress_receiver_resources','queue_recovery_real_codec',
    'local_evidence_cache_candidate','local_evidence_cache_migration','local_evidence_cache_retention','local_evidence_cache_context_layout',
    'local_evidence_cache_pressure_continuation',
    'storage_queue_sqlite_contract','deep_collector_manifest',
    'etw_process_payload_identity_native','collector_file_read_windows','process_tree_cache','parent_context_binding','process_create_coalescer_state_machine',
    'p0_source_only_durable_contract','p0_operation','p0_rule_ir_purpose_archive','p0_observation_semantics','ave_sdk_smoke','egress_loopback_mtls','egress_command_delivery_mtls','egress_update_download_mtls','report_events_ack_contract',
    'pmfe_lifecycle_policy_switch')
  foreach ($name in $required) {
    if ($name -notin @($telemetryTests.name)) { throw "Required native telemetry test missing or unlabelled: $name. A stub or incomplete dependency build cannot pass this runner." }
  }
  $buildTargets = @('telemetry_minimization_tests')
  $telemetryExclusions = @()
  if ($IncludeReleaseGate) {
    if ($releaseTests.Count -eq 0) { throw 'Required Windows release gate is empty.' }
    $buildTargets += 'windows_release_gate_tests'
    $telemetryExclusions = @('--label-exclude', '^windows-release-gate$')
  }
  & cmake --build $build --config $Configuration --target $buildTargets --parallel 4
  if ($LASTEXITCODE -ne 0) { throw 'Native contract executables failed to build.' }
  if ($IncludeReleaseGate) {
    # Keep the original per-test release deadlines and sequential execution.
    # Only a successful release gate permits excluding its tests below.
    & ctest --test-dir $build -C $Configuration --output-on-failure --no-tests=error --label-regex '^windows-release-gate$' --output-junit (Join-Path $build 'native-release-results.xml')
    if ($LASTEXITCODE -ne 0) { throw 'Native Windows release gate failed.' }
    Save-NativeReleaseLog $build
  }
  $remaining = @($telemetryTests | Where-Object { -not $IncludeReleaseGate -or $_.name -notin @($releaseTests.name) })
  Write-Host ("Native gate selection: release={0} telemetry={1} telemetry_remaining={2}" -f $releaseTests.Count, $telemetryTests.Count, $remaining.Count)
  # An empty remainder is legitimate only after all telemetry tests passed in
  # the release gate. Standalone telemetry still runs its complete label.
  if ($remaining.Count -gt 0) {
    & ctest --test-dir $build -C $Configuration -L '^telemetry-minimization$' @telemetryExclusions --output-on-failure --no-tests=error --timeout 150 --output-junit (Join-Path $build 'native-telemetry-results.xml')
    if ($LASTEXITCODE -ne 0) { throw 'Native telemetry contract failed; no release or deployment performed.' }
  }
  Write-Output 'PASS: native synthetic contracts and loopback mTLS. This does not certify native sensor collection or execute real queue migration.'
} finally {
  $env:PATH = $oldPath
  foreach ($name in $edrOverrides.Keys) { [Environment]::SetEnvironmentVariable($name, $edrOverrides[$name], 'Process') }
}
