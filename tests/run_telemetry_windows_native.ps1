# Test-only runner: already configured native Windows build with real dependencies.
# No service, installer, production URL or persistent endpoint queue is started.
param(
  [Parameter(Mandatory = $true)][string]$BuildDir,
  [ValidateSet('Debug','RelWithDebInfo','Release')][string]$Configuration = 'Debug',
  [string]$OpenSslBin = ''
)
$ErrorActionPreference = 'Stop'
$build = (Resolve-Path -LiteralPath $BuildDir).Path
if (!(Test-Path -LiteralPath (Join-Path $build 'CMakeCache.txt'))) { throw 'Configure a native Windows EDR build with real SQLite, OpenSSL and verified PCRE2 first.' }
if ($OpenSslBin) {
  $openssl = Join-Path $OpenSslBin 'openssl.exe'
  if (!(Test-Path -LiteralPath $openssl)) { throw 'OpenSslBin must contain openssl.exe for temporary synthetic certificates.' }
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
  $required = @('egress_batch_policy','egress_request_policy','command_result_egress','command_result_compaction','egress_receiver_resources','queue_recovery_real_codec',
    'local_evidence_cache_candidate','storage_queue_sqlite_contract','deep_collector_manifest',
    'p0_source_only_durable_contract','p0_operation','p0_rule_ir_purpose_archive','p0_observation_semantics','ave_sdk_smoke','egress_loopback_mtls','egress_update_download_mtls','report_events_ack_contract',
    'pmfe_lifecycle_policy_switch')
  foreach ($name in $required) {
    if ($name -notin @($inventory.tests.name)) { throw "Required native test missing: $name. A stub or incomplete dependency build cannot pass this runner." }
  }
  & cmake --build $build --config $Configuration --target telemetry_minimization_tests --parallel 4
  if ($LASTEXITCODE -ne 0) { throw 'Native contract executables failed to build.' }
  & ctest --test-dir $build -C $Configuration -L '^telemetry-minimization$' --output-on-failure --timeout 150
  if ($LASTEXITCODE -ne 0) { throw 'Native telemetry contract failed; no release or deployment performed.' }
  Write-Output 'PASS: native synthetic contracts and loopback mTLS. This does not certify native sensor collection or execute real queue migration.'
} finally {
  $env:PATH = $oldPath
  foreach ($name in $edrOverrides.Keys) { [Environment]::SetEnvironmentVariable($name, $edrOverrides[$name], 'Process') }
}
