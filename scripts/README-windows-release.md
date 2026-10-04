# Windows release flow

The release workflow is restored to the path before commit `cd8c25eb` introduced
USB signing. Later Agent fixes and built-in collector runtime/hash checks remain.

The job graph is prepare draft, native AMD64/ARM64 build and tests, native
install/upgrade/rollback validation, then combined Release publication. There is
no private-repository dispatch, self-hosted USB job, hosted signed-file repackaging,
or candidate/release-purpose selector in the public workflow.

Manual runs support the original `unsigned` and `signed` modes. Tag runs use
`WINDOWS_RELEASE_MODE`, falling back to `unsigned`. `signed` is the original
GitHub-hosted PFX path, not USB. Unsigned output must remain explicitly labelled;
restoring this workflow does not relax platform/Agent trust policy or guarantee
that a platform requiring signatures will accept the unsigned bundle. Native
lifecycle tests, package hashes, policy/rule verification and published-release
immutability are unchanged.

Existing runs and tags keep their workflow snapshot. Use a new version/ref that
contains the restoration; rerunning an old tag still shows the old jobs.

Private signing repository, runner registration, certificate and secrets are not
deleted. They are no longer referenced by this public release pipeline and can
be revisited separately if hardware signing is needed later.

## Daily release and failure recovery

The ARM64 dependency triplet overrides OpenSSL 3.6.3's `/Gs0` with the compiler
default `/Gs4096`, following OpenSSL commit
`e9344b082ffa78cb1d68f6446c1b6417c4244a00`. This avoids ARM64 prologue corruption;
`/GS`, large-frame stack probes, certificate validation and dependency versions
remain enabled/unchanged. Remove the override when the pinned port contains that
fix. The configuration and triplet participate in cache identity and vcpkg ABI
validation. Release gates now exercise the linked TLS 1.2/1.3 libraries with
trusted mutual authentication, untrusted certificates, wrong hostnames and missing
client certificates. Task launcher tests also require the real native exit code
before and after the startup observation period.

Choose one entry point: push `win_M.m.p`, **or** manually run the release workflow
with that version. Both now share a version-level concurrency group, without
cancelling a running release. A completed release with the same commit/mode is
reused without rebuilding. A different commit/mode cannot take over a version.

Draft notes retain a source binding (repository, commit, version, signing mode,
upgrade override and originating run ID). Do not remove it. Each architecture's
existing artifact manifest also carries this provenance. Unbound legacy drafts
are not silently adopted: use a new version. Existing tags/runs still use their
old workflow snapshot; this change cannot protect uploads from an older workflow.

Draft discovery resolves the release ID using GraphQL, then reads release metadata
and paginated assets through REST by ID. REST's published-release tag endpoint can
return 404 for an existing draft; that is not proof that creation failed. After
creation the workflow checks visibility at most three times, without creating a
second draft; permission/transport errors remain explicit failures.

If a run fails, use **Re-run failed jobs** on that original run, not a new manual
release. After all native build/test, packaging and integrity steps succeed,
the complete `dist` directory is retained as `release-checkpoint-amd64/arm64`
for one day. A rerun verifies the exact source, run, architecture and every file
SHA-256 before skipping rebuild/sign/package and resuming upload. There is no
cross-run or cross-commit product cache. A missing checkpoint takes the complete
build path; an expired, malformed or corrupt checkpoint fails explicitly. If
rebuilding encounters different bytes already uploaded to the draft, use a new
version rather than overwrite those bytes.

Release upload reconciles existing names, sizes and SHA-256 values (downloads
bytes if GitHub does not supply a digest). It only uploads missing files, never
uses `--clobber`, verifies the remote set, and retries transient failure at most
three times with backoff. It tolerates a lost reply after a successful upload.
The local checkpoint receipt is an Actions artifact only, not a release asset.
Install/upgrade/rollback/uninstall and embedded-updater validation remain required
before publication, including after a build checkpoint is reused.

After publication, the publish job removes only that run's large CI checkpoints;
the immutable Release assets remain the installation and rollback source. Draft
or failed runs keep their recovery checkpoints until the one-day expiry. Rule
validation and native lifecycle evidence are retained for seven days. Cleanup
checks the exact release source/run and artifact ownership, and is idempotent;
it cannot remove another run's checkpoints or diagnostic evidence.

## Build preparation and timing

The prepare job runs checkpoint behavior, workflow wiring, and the portable
`agent_update_packaging_contract` source test before starting native builds.
The same packaging contract remains in the Windows CTest gate. This catches
workflow/helper contract drift early without replacing native validation.

The pinned x64 Python 3.12.10 tool directory is cached on ARM64 hosts; version,
architecture and binary-only P0 cryptography dependency requirements are unchanged.
The existing **Build Pre-built vcpkg Packages** workflow seeds this cache on the
default branch (`main`) so new release tags can read it. Run that existing workflow
once on the default branch after merging these changes; a tag-only cache is only
useful to reruns of that tag. Cache eviction/miss still uses the normal pinned
Python installer. No new runner, service or signing system is needed.

Release gate fixture tests run with at most two independent workers, with per-case
logs and timings. All discovered cases and negative controls remain selected;
native product CTest and lifecycle jobs are not removed or parallelized by this
change. The fixture driver fails on an empty selection or any failed case. Measure
the next Windows CI runs before claiming a wall-clock improvement; local contract
tests do not establish hosted Python cache hit rate or native release performance.

## Windows rule validation

Use the release workflow's locked Visual Studio/vcpkg configuration for the
machine's native architecture. From an Agent checkout with that configured
`build` directory, run in Windows PowerShell 5.1 or PowerShell 7:

```powershell
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File scripts/validate_windows_powershell_syntax.ps1
if ($LASTEXITCODE -ne 0) { throw 'PowerShell 5.1 syntax validation failed' }
cmake --build build --config Release --target windows_release_gate_tests
if ($LASTEXITCODE -ne 0) { throw 'Native gate build failed' }
ctest --test-dir build -C Release --output-on-failure --no-tests=error --label-regex '^windows-release-gate$' --timeout 180
if ($LASTEXITCODE -ne 0) { throw 'Native Windows release gate failed' }
```

The gate builds `test_p0_candidate_replay` with the same build-owned static
PCRE2 producer as the Agent. `windows_rule_semantic_audit` replays the independent
Windows corpus and writes `build/windows-rule-audit-result.json` with the bundle
version, SHA-256, native architecture, and each expected/actual match. On Windows
it queries the kernel's native architecture and invokes the existing PE verifier,
so an x64 executable emulated on ARM64 cannot pass as native ARM64 evidence.
Case command lines are data and are never executed. The same test can run on
Linux/macOS with its result explicitly marked as non-native Windows replay.

The existing release matrix executes this gate on `windows-2022` (AMD64) and
`windows-11-arm` (ARM64) and retains the result as an Actions artifact. A passing
constructed-event matcher test does not prove ETW collection, installed endpoint
behavior, Server Core, or every PC/Server version. Use the existing native
install/upgrade/rollback workflow for lifecycle coverage; record any additional
PC/Server environments separately.
