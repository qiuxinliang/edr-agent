#Requires -Version 7.0
param(
    [Parameter(Mandatory=$true)][ValidateSet('amd64','arm64')][string]$Architecture,
    [Parameter(Mandatory=$true)][string]$Root
)
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_REF -cne 'refs/heads/codex/verify-687-752-753-maintenance' -or $env:GITHUB_ACTIONS -cne 'true') {
    throw 'Formal native storage consumers must be compiled on the disposable validation branch'
}
$repo = Split-Path -Parent $PSScriptRoot
$processor = if ($Architecture -ceq 'amd64') { 'AMD64' } else { 'ARM64' }
$prefix = Join-Path $repo "vcpkg_installed/$env:EDR_VCPKG_TRIPLET"
$toolchain = Join-Path $repo 'vcpkg/scripts/buildsystems/vcpkg.cmake'
New-Item -ItemType Directory -Path $Root | Out-Null
foreach ($role in @('legacy','baseline','candidate')) {
    $source = Join-Path $Root ('source-'+$role)
    $build = Join-Path $Root ('build-'+$role)
    python -B tests/storage_compat/prepare.py --repo $repo --output $source --role $role --formal-maintenance
    if ($LASTEXITCODE -ne 0) { throw "Pinned storage source export failed for role $role" }
    $configure = @(
        '-S', $source, '-B', $build, '-G', 'Ninja', '-DCMAKE_BUILD_TYPE:STRING=StorageCompat',
        '-DCMAKE_MAP_IMPORTED_CONFIG_STORAGECOMPAT:STRING=Release;', '-DCMAKE_MSVC_RUNTIME_LIBRARY:STRING=MultiThreadedDLL',
        "-DCMAKE_TOOLCHAIN_FILE=$toolchain", "-DCMAKE_PREFIX_PATH=$prefix",
        "-DVCPKG_INSTALLED_DIR=$repo/vcpkg_installed", '-DVCPKG_MANIFEST_INSTALL=OFF',
        "-DCMAKE_SYSTEM_PROCESSOR=$processor", "-DEDR_WINDOWS_TARGET_ARCH=$Architecture",
        '-DEDR_BUILD_TESTS=ON', '-DEDR_REQUIRE_SQLITE=ON', '-DEDR_REQUIRE_PCRE2=ON',
        '-DEDR_P0_RULE_IR_ALLOW_TEST_STUB=OFF', "-DEDR_PCRE2_PRODUCER_TARGET=windows/$Architecture",
        "-DEDR_PCRE2_VCPKG_ROOT=$repo/vcpkg", '-DEDR_WITH_YARA=OFF', '-DEDR_REQUIRE_YARA=OFF',
        "-DEDR_P0_TEST_CONFIG_DIR=$env:EDR_BACKEND_CONFIG_DIR",
        '-DEDR_WITH_FORENSIC_COLLECTOR=OFF', '-DEDR_WITH_HTTP2_CURL=OFF'
    )
    cmake @configure
    if ($LASTEXITCODE -ne 0) { throw "Native storage owner configuration failed for role $role" }
    cmake --build $build --target storage_compat_cache storage_compat_queue --parallel 4
    if ($LASTEXITCODE -ne 0) { throw "Native storage consumer compilation failed for role $role" }
}
$compiler = (Get-Command cl.exe -ErrorAction Stop).Source
$dumpbin = Join-Path (Split-Path $compiler) 'dumpbin.exe'
$options = @('--repo', $repo, '--architecture', $Architecture, '--harness-commit', $env:GITHUB_SHA,
             '--run-id', $env:GITHUB_RUN_ID, '--run-attempt', $env:GITHUB_RUN_ATTEMPT, '--formal-maintenance')
$builds = @('--legacy-build', "$Root/build-legacy", '--baseline-build', "$Root/build-baseline", '--candidate-build', "$Root/build-candidate")
python -B tests/storage_compat/stage_native.py stage @options @builds --source-manifests $Root --dependency-prefix $prefix --msvc-redist-root $env:VCToolsRedistDir --compiler $compiler --dumpbin $dumpbin --output "$Root/bundle"
if ($LASTEXITCODE -ne 0) { throw 'Native per-source cache and queue consumers failed readback or dependency closure' }
$python = (Get-Command python -ErrorAction Stop).Source
python -B tests/storage_compat/stage_native.py bind @options --bundle "$Root/bundle" --python-path $python --output "$Root/input.json"
if ($LASTEXITCODE -ne 0) { throw 'Same-job native storage binding failed' }
