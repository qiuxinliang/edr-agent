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
