# Windows upgrade storage compatibility tools

These are isolated test executables, never Agent payloads or production APIs.
`prepare.py` exports immutable original 3.2.723 source `b51bc3d825e6d5666535463b34eb708201e6fda7`
and candidate source `d4e837790c53861c99d31ee127c55a5ef1f06f4a`. It preserves the
original storage, codec and test-owner sources and appends only the two test
targets to the exported root CMake file. Production sources are hash-bound again
before native tools are staged. Old and new dependency manifests/locks match.

The adapters reuse the actual `test_queue_recovery` and
`test_local_evidence_cache_candidate` build owners and their existing external
I/O/test rule boundaries. They do not run those tests' SQL fixture helpers.
All representative records are written through the original storage APIs.
The queue fixture passes the actual producer projector and final egress gate;
ordinary telemetry is not made eligible for delivery. No network or server ACK
is fabricated. P0 matching, collection and a live server are outside this test.

## Build and stage

Run `prepare.py --repo CHECKOUT --role legacy --output NEW_SOURCE_OLD` and the
corresponding `--role candidate` export into the same parent directory. The
parent receives `legacy-source.json` and `candidate-source.json`.

Configure both exports with the existing Windows MSVC/Ninja/pinned vcpkg owner.
Use the explicit non-production configuration `CMAKE_BUILD_TYPE=StorageCompat`,
`CMAKE_MAP_IMPORTED_CONFIG_STORAGECOMPAT=Release;` and
`CMAKE_MSVC_RUNTIME_LIBRARY=MultiThreadedDLL`. This selects the same locked
Release dependencies and CRT while preserving the original production gate.
The trailing empty mapping element permits configuration-less imported targets
such as FindSQLite3's `IMPORTED_LOCATION`, using the same locked dependency
prefix; it does not select Debug libraries. Without that empty element CMake
rejects those targets at generation time.

Configure with the unchanged production matcher owner: `EDR_REQUIRE_PCRE2=ON`,
`EDR_P0_RULE_IR_ALLOW_TEST_STUB=OFF`, `EDR_PCRE2_PRODUCER_TARGET=windows/ARCH`
and `EDR_PCRE2_VCPKG_ROOT` pointing to the existing pinned vcpkg checkout.
Original 723's Windows test-link loop requires the real PCRE2-dependent test
targets to exist even when only the two storage targets are selected. The
producer performs its normal fresh static PCRE2 build for each source export;
no production gate or frozen CMake file is patched, and no placeholder target
is introduced. The selected storage test owners retain their existing external
I/O/rule stubs; this does not claim P0 integration coverage. Set
`EDR_BUILD_TESTS=ON`, `EDR_REQUIRE_SQLITE=ON`, the correct Windows
architecture/triplet and the same locked dependency prefix. Build only
`storage_compat_cache` and `storage_compat_queue`. These root-level test targets
use their original test owners' source, defines, includes and link dependencies.
They do not rebuild, rewrite or replace the signed product artifacts.

`stage_native.py stage` takes `--repo`, `--legacy-build`, `--candidate-build`,
`--source-manifests`, `--dependency-prefix`, `--msvc-redist-root`, `--compiler`,
`--dumpbin`, `--architecture`, `--harness-commit`, `--run-id`, `--run-attempt`,
and a new `--output`. It reuses `scripts/stage_retention_native_tools.py` for
strict native PE and complete DLL closure inspection. It checks the three exact
test configuration/dependency/CRT values above, records them in provenance,
verifies exported sources and adapter hashes, and runs the staged
executables through the native two-way compatibility check before producing a
manifest. A failed check does not produce a successful manifest.

The resulting directory contains `manifest.json`, `legacy/`, `candidate/` and
`evidence/`. Each role has both executables, all non-OS DLL dependencies and its
source provenance. Evidence includes receipts and the native comparison summary,
never database files. `verify(repo, bundle, architecture, harness_commit, run_id,
run_attempt)` checks this bundle after transport. Transport integrity must bind
the archive to the expected run before verification; this is not a code-signing
or authorization interface.

`stage_native.py bind --repo CHECKOUT --bundle BUNDLE --architecture ARCH
--harness-commit COMMIT --run-id ID --run-attempt ATTEMPT --python-path PYTHON
--output NEW_INPUT.json` verifies the bundle and produces the existing lifecycle
helper's `edr.windows.storage-compat-tools.v1` input with absolute tool paths.
The selected Python must provide `sqlite3` and `tomllib`.

## Native tool contract

Both executables take these positional arguments:

```
ACTION DB EPOCH GENERATIONS TENANT ENDPOINT MAX_MB RETENTION_HOURS SELECTED_RETENTION_HOURS
```

`create` requires a nonexistent database and writes generation 1; `seed` appends
generation 1 to an existing database; `append` writes generation 2 to an existing
database; `read` consumes one or both generations. Existing fixture identities
are rejected, never overwritten. Epoch is the fixture's real UTC creation time
in seconds, accepted within one hour. Tenant and endpoint are taken from the
isolated installation's actual config. Positive budget/retention values must
likewise be copied from that config, with default selected retention resolved by
the existing config contract. Queue passes its retention twice. The adapter
rejects relevant environment overrides rather than silently using another policy.

`seed` and `append` may operate on the verified disposable installation only
after its exact runtime owner is stopped and all its processes have exited.
The storage owner performs its normal open/maintenance/close. Production/live
endpoint paths are not inputs to these tools. The lifecycle helper owns this
path, identity and runtime-quiescence boundary.

`read` must run on a new SQLite backup snapshot, separately for every reader.
Never copy an active DB file without its WAL, use `immutable=1`, or open the same
copy with successive readers. Owner open and queue retry bookkeeping can change
the copy. The cache reader starts in a fresh process and requires each exact
record to come from `p0_candidates`, so an in-memory ring cannot satisfy it.
It checks generation, identity, UTF-8 content and the exact persisted nanosecond
timestamp. The queue reader uses real `poll_drain`, RAW/LZ4 and protobuf decoding,
and compares exact immutable wire bytes. It returns a transport failure so no
server ACK is claimed. Existing unrelated Agent records are left unacknowledged.

Both pinned versions have a 300-second retry cap with second-based persisted
eligibility. On the disposable reader copy only, the existing test clock seam
advances delivery eligibility by 301 seconds. The receipt marks
`virtual_retry_eligibility_only=true`. This proves persisted content is readable,
not real elapsed retry timing. It never rewrites a retry field directly or
disables the production validator. Polling is bounded and missing records fail.

Exit zero emits one `edr.test.storage-compat.v1` JSON receipt. Failure emits an
actionable cause on stderr and no success receipt. The lifecycle consumer must
bind source, action, config identity/policy, count and actual records against the
writer receipts. Cache and queue have additional explicit query/codec fields.
Windows tools reject emulated execution before touching a database.

## Scope of evidence

`run_cross_version.py` checks old writes with both readers, then candidate
additional writes with candidate and intended old rollback readers, always in
fresh processes and independent SQLite snapshots. It also rejects duplicate
seeding, absent generations/databases, expired fixture metadata and corruption.
This standalone result is explicitly not an installed Agent lifecycle result.
The signed lifecycle helper must still seed the actual installed DBs, start the
original runtime and validate snapshots after upgrade and timeout/rollback.
Host POSIX runs and Windows native runs are separately labeled; a host pass does
not count as Windows acceptance.
