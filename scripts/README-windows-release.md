# Windows release flow

The job graph is prepare draft, native AMD64/ARM64 build and tests, optional
USB finalization, native install/upgrade/rollback validation, then combined
Release publication. Manual runs support `unsigned` (default), `signed` and
`usb`; tag runs use `WINDOWS_RELEASE_MODE`, falling back to `unsigned`.
`signed` uses the GitHub-hosted PFX path. `usb` uses one private signing handoff
and validates the returned signatures before lifecycle testing and publication.

Unsigned output remains explicitly labelled. It does not relax platform/Agent
trust policy or guarantee that a platform requiring signatures will accept the
bundle. A manual candidate run publishes a prerelease with `--latest=false`.
Native lifecycle tests, package hashes, policy/rule verification and
published-release immutability remain required. Existing runs and tags retain
their workflow snapshot; use a new version/ref for a changed release workflow.

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

Release and client builds use `scripts/Ensure-WindowsBuildTools.ps1` to reuse
working runner tools. It dry-runs a Ninja 1.10 graph and compiles an output-free
Inno Setup 6 probe with the installer's `x64os`/`arm64` architecture expressions
and modern wizard. Inno is checked at the same default path used by the packaging
script. CI uses `-NinjaOnly` because it does not package an installer. Each failed
probe permits one Chocolatey install of that tool, followed by the same probe;
installation failure or an unusable result terminates with a diagnostic. There
is no upgrade command, unconditional reinstall, or unbounded repair loop.

The release **Test** step invokes
`tests/run_telemetry_windows_native.ps1 -BuildDir build -Configuration Release -IncludeReleaseGate`
on each native architecture. The runner builds both gate targets, clears inherited
endpoint overrides, and runs `windows-release-gate` first. Only after that succeeds
does it run `telemetry-minimization` excluding the already-passed release label.
Required telemetry contracts must be present in the labelled inventory; an empty
release gate fails. Without `-IncludeReleaseGate`, the standalone runner still
executes the entire telemetry group. Both phases remain sequential with their
original deadlines, including the isolated loopback mTLS receiver. The runner
uses the configured vcpkg `tools/openssl` executable
when available, otherwise the installed OpenSSL executable. Missing dependencies
or failed tests stop packaging and checkpoint sealing; a source-bound checkpoint
can only be reused after these gates passed in that same run. These tests use
synthetic data and temporary certificates, and do not migrate endpoint queues or
prove native sensor collection.

The pinned x64 Python 3.12.10 tool directory is cached on ARM64 hosts; version,
architecture and binary-only P0 cryptography dependency requirements are unchanged.
The existing **Build Pre-built vcpkg Packages** workflow seeds this cache on the
default branch (`main`) so new release tags can read it. Run that existing workflow
once on the default branch after merging these changes; a tag-only cache is only
useful to reruns of that tag. Cache eviction/miss still uses the normal pinned
Python installer. No new runner, service or signing system is needed.

Release gate fixture tests run with at most two independent workers, with per-case
logs and timings. All discovered cases and negative controls remain selected;
native product CTest and lifecycle jobs remain mandatory and sequential. The
fixture driver fails on an empty selection or any failed case.

## Build performance investigation (2026-10-15)

Successful GitHub job/step metadata and CTest logs show that the recent increase
is primarily validation work, rather than dependency downloads or packaging:

| Successful run | Total release | ARM64 gate self-tests | ARM64 Ninja build | ARM64 Test | ARM64 lifecycle |
| --- | ---: | ---: | ---: | ---: | ---: |
| [2026-10-04](https://github.com/qiuxinliang/edr-agent/actions/runs/37208653818) | 23m08s | 4m04s | 1m15s | 3m13s | 5m41s |
| [2026-10-11](https://github.com/qiuxinliang/edr-agent/actions/runs/38117339774) | 39m47s | 5m52s | 2m38s | 8m50s | 14m31s |
| [2026-10-15](https://github.com/qiuxinliang/edr-agent/actions/runs/38742901613) | 50m53s | 6m55s | 2m36s | 16m34s | 15m50s |

The latest run installed vcpkg dependencies in 5s/9s and packaged in 17s/19s
(AMD64/ARM64). Its Test step ran 99 release tests followed by 38 telemetry tests:
137 executions for 112 distinct tests. The second execution of the 25 shared tests
took 211.95s/212.48s. These are observed redundant costs in the old workflow,
not a measured end-to-end improvement from the new workflow. The unsigned run
does not establish USB or hosted certificate signing performance.

Three changes remove repeated work while retaining the existing contracts:

- Gate self-tests share the identical fixture body as an OBJECT library while
  keeping every executable as a separate build dependency. Failure-injection
  cases select the exact failing labelled test and require one failure with no
  missing executable. Complete graph, missing-target, real executable failure,
  and both Ninja generator checks remain. The two affected groups (17 host
  subcases) passed in 543.218s before and 5.508s after on macOS; these local
  samples ran alongside other checks and are not a hosted-run benchmark.
- The four full-runtime fixtures share assertion-enabled production objects.
  `agent.c` remains separate for fixtures that embed and substitute it;
  `pmfe_engine.c` remains separate for lifecycle-only test hooks. The verified
  macOS build graph reduced their compile units from 522 to 138 (384 fewer).
  Product objects, feature definitions, dependency verification, and native
  installer CRT settings are unchanged.
- Native release and telemetry execution uses the two-phase selection above.
  The telemetry-only path remains available and complete. Runtime tests are
  not broadly parallelized: existing fixtures can share build-directory state.

Validation: full fixture dependency/negative-control checks; real CTest execution
counts and failure propagation for both labels; nine orchestration cases executed
against the real PowerShell runner with only external commands substituted;
workflow/packaging contracts; and eight existing runtime behavior tests, including
mTLS, conditional policy, local query, startup, and PMFE lifecycle. Local runtime
checks used macOS Debug and the explicitly non-production PCRE2 stub. PowerShell
validation used 7.6.6 on macOS. The release now runs the orchestration regression
on both Windows architectures and parses both runner scripts with Windows
PowerShell 5.1 before building. A new Windows run is still required to measure
the actual MSVC build and end-to-end improvement. Native installer lifecycle,
trust, signatures, immutable checkpoints, and publication gates remain required.

Follow-up (2026-10-16): four small test-only object groups reuse identical cJSON,
SHA256, detection, and AVE codec compile variants across 23 consumers. Comparing
compiler, definitions, ordered includes, and options against the previous graph
verified 47 fewer compilations overall and 31 fewer in the runtime/telemetry gate
union. Product and P0/mutex/injected variants remain separate. The new socket
contract adds one compilation, making that host gate union 578 -> 548.

The four packaging CTests now receive a deliberately foreign `PSModulePath`
before their existing launcher removes it. The launcher regression verifies the
configured environment and both isolation controls; Windows runs each real
packaging test once in its native gate. Logger failure fixtures build and select
only the two logger owners; complete dependency closure still runs with both
Ninja generators.

The HTTP socket owner also monitors `exceptfds`: Winsock signals refused
nonblocking connections there, so a refused address no longer needs to consume
the full connection timeout before trying the next address. Success still
requires write readiness and a zero `SO_ERROR`. The same private implementation
is exercised by deterministic socket error/timeout controls and real loopback
success/refusal tests, now included in the runtime and Windows release gates.

Follow-up validation: all 23 affected object-consumer tests, the complete fixture
dependency checks for both generators, packaging/logger regressions, and all
three real mTLS fixtures passed locally. Removing exception monitoring again
fails the socket regression. Its Windows branch compiles and links with MinGW
under `-Wall -Wextra -Werror`. These checks used macOS Debug/non-production P0
stub, not native Windows/MSVC; the Windows timing benefit remains unmeasured.

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
