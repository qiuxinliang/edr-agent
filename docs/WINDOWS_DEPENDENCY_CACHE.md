# Windows dependency reuse and download recovery

The build, release, PR CI and dependency-prebuild workflows share
`scripts/vcpkg_cache_key.py` and `scripts/vcpkg_release_cache.py`.
This is a build-time cache only; it does not change Agent runtime dependencies,
installer trust, TLS verification, or the locked vcpkg baseline.

## Why the previous path was slow and fragile

GitHub Actions cache access is scoped by ref. Saving the same key on one release
tag does not make it readable on a different tag. The old Release fallback was
keyed only by manifest hash and contained `vcpkg_installed`, not ABI-keyed binary
packages and original tool downloads. A changed compiler could rebuild packages,
and even an installed dependency set could still require downloading CMake.

The reported 3.2.472 failure is a CMake download TLS-connect failure (curl 35),
before Agent compilation. The previous wrapper retried only HTTP 429. Error 35
alone does not prove whether the underlying cause is transient connectivity or
a persistent proxy/TLS configuration problem.

## Current ownership and sequence

1. Initialize the supported VS2022 toolchain using `IsWow64Process2`'s native
   host architecture, independently of the target architecture. Environment
   variables and older .NET APIs can report x64 on ARM64 Windows. Reject a
   mismatched compiler before exporting the environment. This build-host probe
   requires Windows 10/Server version 1709 or later; Agent install targets are
   unchanged.
2. Compute an `edr-vcpkg-v3-<triplet>-<digest>` identity from dependency inputs,
   compiler contents, SDK, CMake and host/image family. Agent version, release
   ref and runner image publication date are not cache identity inputs.
3. Restore the ref-scoped Actions cache first. Unless this is an exact hit,
   look for a dependency Release with the same identity.
4. Restore only `vcpkg-bincache/<abi-prefix>/<abi>.zip` and completed original
   files in `vcpkg-downloads`. Never restore installed state or extracted tools
   from the shared Release. Validate the manifest, SHA-256, ZIP CRC, paths and
   size before writing into the workspace cache.
5. Always run pinned vcpkg install. It validates package ABI and source/tool
   hashes; cache presence is not installation success.
6. Prebuild publishes the shared dependency Release. Product release jobs also
   seed it immediately after dependency installation, before product gates can
   fail. A completed identity is never deleted or overwritten by these helpers.
   Dependency Releases are prereleases and are not marked as the latest product.

The first build for a new dependency/toolchain identity can still compile from
source. Future tags can reuse it if ABI inputs remain compatible. Old prebuilt
Releases are left intact for historical workflow consumers.

Create-only is a helper policy, not a claim that GitHub's repository-level
immutable-release setting is enabled. Trust remains in the repository and its
authorized publishers; the archive manifest detects corruption, not a malicious
publisher that can replace both files. PR CI and client-build use read-only
repository tokens. Only the existing release/prebuild paths can publish.

## Failure behavior and verification

- Only a missing shared Release is an ordinary source-build fallback. Invalid
  archives and unexpected access/download errors fail visibly; they are not
  consumed or mistaken for cache misses.
- A failed shared-cache publication is a warning in the product release job;
  Actions cache saving remains its fallback, and normal build gates still run.
  Successful publication skips the duplicate ref-local Actions upload. It is fatal in the
  prebuild job, whose purpose is to publish dependencies. An incomplete/draft
  Release requires producer investigation; consumers refuse it. Inspect the
  exact cache tag and producer run first. A live producer must be allowed to
  finish; cleanup of an abandoned draft requires an authorized operator, then
  rerunning prebuild. These helpers never automatically delete releases/tags.
- vcpkg install retries only explicitly classified download failures. Attempts
  are bounded, with exponential backoff and jitter capped at 300 seconds per
  wait. Persistent failures terminate. Certificate, hash and concrete compiler
  errors take priority over retryable text. No insecure TLS flags or proxy
  changes are applied.
- `test_vcpkg_*cache*.py`, `test_vcpkg_install_retry.ps1`, and
  `test_vs2022_host_architecture.ps1` run before dependency downloads. Release
  scheduling and packaging contracts still cover the normal product gates.
- Product workflows compile the actual P0 suppression test with the initialized
  MSVC toolchain before dependency installation. This uses VS's NMake and needs
  no vcpkg/SQLite or Ninja download. It catches native compiler incompatibilities
  such as chained atomic assignments early; it does not replace the later
  SQLite-enabled compile probes or runtime tests. Host Clang success alone does
  not qualify MSVC compatibility.
- Validate performance using each job's dependency-install, native-build and
  test durations separately. A fault-injection pass is not evidence that a real
  GitHub TLS problem has disappeared or that a warm-cache speedup was measured.

## 3.2.473 C2095 and AMD64 timing verification

The two failing lines in `test_p0_direct_emit_suppression.c` were introduced by
`52796059`: `g_emit_count = g_durable_count = 0`, with both counters declared as
`atomic_int`. MSVC 19.44 rejects use of the inner atomic assignment's value.
Separate `atomic_store` calls preserve sequential consistency and the original
store order (durable counter first). Removing atomics, disabling assertions or
weakening the gate is not the fix.

Minimal independent reproduction on Compiler Explorer, using
`/TC /std:c11 /experimental:c11atomics /O2 /W4`:

```c
#include <stdatomic.h>
atomic_int a = 0, b = 0;
int main(void) {
    /* Before: a = b = 0; */
    atomic_store(&b, 0);
    atomic_store(&a, 0);
    return atomic_load(&a) + atomic_load(&b);
}
```

Both `vc_v19_44_VS17_14_x64` and `vc_v19_44_VS17_14_arm64` returned exit 2/C2095
for the old expression and exit 0 for the explicit stores. Only this generic
example was submitted, not Agent sources. This is compiler-behavior evidence,
not full product build/link/runtime qualification or a match of every MSVC
servicing revision used by GitHub.

GitHub job metadata read on 2026-09-14:

| AMD64 version | Job total | vcpkg install | Configure | Gate dependency regression | Product build / tests |
|---|---:|---:|---:|---:|---|
| [3.2.471](https://github.com/qiuxinliang/edr-agent/actions/runs/34771232439/job/103761104056) | 5m34s | 11s | 57s | 59s | 53s / 23s |
| [3.2.472](https://github.com/qiuxinliang/edr-agent/actions/runs/34799942067/job/103840424379) | 3m14s, failed | 3s, download failure | skipped | skipped | skipped |
| [3.2.473](https://github.com/qiuxinliang/edr-agent/actions/runs/34802647100/job/103848266247) | 11m14s, failed | 7m26s | 47s | 49s, C2095 | skipped |

The v3 cache migration had no matching shared Release at restore time; 3.2.473
seeded it after installation. Its x64 cache publication took 21s, followed by a
redundant 12s Actions upload. Both architecture caches now exist. This compiler
fix deliberately leaves all cache-key inputs unchanged; the release workflow
skips that second upload when shared publication succeeds. A future run must
still verify actual shared-cache consumption and warm install time. Unavailable
full logs mean the 7m26s cannot be partitioned into source compilation versus
any network backoff from metadata alone.
