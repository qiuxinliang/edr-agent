# Cache reliability remediation

## 2026-10-15 candidate 679: native gates passed, client upgrade rolled back

Current candidate source is `d0c49a193bb14d42e76bd0bb0412a6241c181044`,
branch `codex/rtq-result-delivery-pressure` (16 commits ahead of audit 662,
seven ahead of comparison `3de0dc680c78c335f8ab6ba37eef0d0f5d8f46e2`).
The sections below retain preparation and failed-candidate history; their
pending-release statements describe those earlier checkpoints.

Run `38701907504` completed all seven jobs successfully. AMD64 runtime gates
passed 99/99 in 278.42 s and standalone telemetry 38/38 in 442.28 s; ARM64
passed 99/99 in 462.75 s and 38/38 in 465.98 s. The labels overlap in 25 tests
and must not be added as independent coverage. Actual Inno fixtures passed
in 10.00 s / 61.42 s. Both native lifecycle jobs verified fresh installation,
baseline 673 installation, repair, upgrade to 679, embedded updater, rollback
and uninstall; `setup_rollback_skipped=false`. Fresh-install runtime-policy
pull warned with exit 2 on both architectures, so this CI success does not
certify online signed-policy synchronization.

Raw logs are `/tmp/edr-679-ci-all.zip` (SHA-256
`2c76a1da2847ca4496b1e701ba47209eaeaeca7514a02034c7a147b5e7006a7a`),
`/tmp/edr-679-ci-summary.json` and
`/tmp/edr-679-ci-lifecycle-{amd64,arm64}.zip`. The immutable build input is
P0 commit `896eb2f06c9ffa608085217d4d1e84494b43e564`. Release `win_3.2.679`
is a prerelease; GitHub latest remains `win_3.2.591`. The workflow pins source
and assets; GitHub platform Immutable Releases is not enabled.

The verified ARM64 full Bundle was imported through the existing client as
`artifact_1792054540294394000`. Its binary SHA-256 is
`17d58fe456c94670e562f8ec73d0cda972a59a9615518bb301854c7cacf4fc2b`.
The UI then queued only the authorized UTM endpoint at 09:03:35 UTC:
task `agent_upgrade_1792055015959878000`, command
`agent_update_1792055018219079000`. Download, verification and installation
events have matching task/artifact/version identities. At 09:04:31 UTC the
task failed with `full_installer_rollback_completed`. This is a recovery
outcome, not the initial failure cause. The same command's local journal is
`failed_rolled_back`, sequence 5, and `acked.seq=5` with no policy hold; its
failure event was acknowledged, not converted into a successful upgrade.

The actual process checked at 09:04:44 UTC was PID 9152, started 09:03:55 UTC,
running the original 673 binary SHA-256
`9641df3791f7c1f42fe98ecdce75e44f664ca94e60eb97f3d18a7882054163ca`.
The UI shows online 673 and failed upgrade. A fresh exact-endpoint policy
sample confirms signed v528 applied and current P0 healthy on that old
process. Deployment of 679 and its new storage behavior are **not verified**.
Failure diagnosis must precede another upgrade attempt; no cache was cleared
and the planned post-upgrade evidence comparison has not been run.

Bounded local evidence is under `/private/tmp/edr-678-client-acceptance/`:
`upgrade-679-identity.json`, `upgrade-679-state-after-old-binary.json`,
`upgrade-679-local-after.json`, `upgrade-679-local-invocation.json`,
`postupgrade-679-path-identity.json` and `upgrade-679-rolled-back.jpg`.
The directory name reflects its creation before the final candidate, not the
version actually tested. The authorized two-candidate baseline is explicitly
a partial association sample; both selected full-command keys were absent,
so it cannot establish live full-command preservation.

Subsequent bounded diagnosis identified installer exit 7 and the exact guard
refusal `local_storage_preflight_failed`. The updater's
`INSTALL_BASELINE_UNSUPPORTED` code is a broad classifier for exit 7 plus
`PrepareToInstall`/baseline/uninstall text; it does not prove an unsupported
baseline or insufficient space. See `upgrade-679-failure-selected.json` and
`upgrade-679-installer-rejection.json` in the same evidence directory.
The verified release EXE plus all 20 root DLLs then passed the existing
preflight entry point in an independent temporary directory: exit 0, 343 ms,
floor 143,479,824 bytes. Owner bytes, owner/parent ACL and configuration hash/ACL
were unchanged. This direct diagnostic cached the process Handle and redirected
output, unlike the original Inno launcher; it is not a reproduction of that
launcher. `release-679-isolated-preflight.json` retains the exact boundary.

The rollback verification did **not** establish preservation of the two old
candidate samples: both original row IDs were absent, and the bounded sampler
returned `no_candidate_sample_not_proof`. No replacement candidates were chosen.
The first failed call's stdout was not saved because a host assertion preceded
the save; this diagnostic defect and observed exit 3 are explicitly recorded in
`evidence-subset-rollback-first-read-failure.json`. One identical bounded read
then saved the refusal as `evidence-subset-after-679-rollback-diagnostic.json`.
Neither call passed the comparison. The 673 source contains both age retirement
and pressure deletion of oldest candidates, but the available evidence does not
identify which path removed these specific rows or establish deletion timing.
The three previously frozen queue samples did retain all sampled immutable bytes
and identities (`postrollback-679-queue-compare.json`). The command owner probe
returned a bounded read/parse failure, not an ACK. These distinct outcomes must
not be summarized as complete old-evidence preservation.

A diagnostic installer containing the exact 679 EXE and 20 DLLs also ran the
original Inno preflight command successfully (`launch=1`, `code=0`, floor
143,479,824 bytes, 3,430 ms). It always refuses before copying files, even when
preflight succeeds. Its exit 7 is that intentional fixture refusal, not the
production failure. The owner/configuration hashes and ACLs were unchanged;
the normal inventory lock may be created/hardened. See
`679-inno-original-launcher.json`. This result did not establish a fix.

One controlled retry through the client at 09:48:50 UTC used the same verified
artifact: task `agent_upgrade_1792057730709453000`, command
`agent_update_1792057733222511000`. It again failed at
`local_storage_preflight_failed`, installer exit 7, and rolled back. The exact
4,096-byte diagnostic log SHA-256 is
`3f9568c352eec2eed9cde6cf55c2daea942f94261f189c9729edcbb2bddc9136`.
The task's sequence-5 failed-rollback event was acknowledged; this is neither
a successful deployment nor proof of the separate command-result ACK.
The numeric child-preflight exit code was not retained by the production log,
so the initial cause remains unresolved. No speculative launcher change or
additional real upgrade retry has been made.

A temporary process observer bound the same Setup hash and captured only its
two start events. It then rejected a Stop event whose name or parent identity
did not match, before saving that event's fields. It exited without timeout
and removed both subscriptions. Its two starts and zero exits do not establish
the preflight cause or a complete process history. Original results remain at
`/tmp/edr-679-process-observer-ma99grty/`; the diagnostic gap is not hidden by
the installer result.

At 09:50:11 UTC the actual process was PID 6228, started 09:49:09.517875 UTC,
still 673 with the original binary hash. Two fresh endpoint samples show
ordinary health timestamps advancing from 09:54:14 to 09:56:14 UTC on that
same process; management is online, control stream connected/ready with a
valid lease, and no circuit/fallback. Signed v528 was verified/applied after
rollback and P0 is ready/healthy. Both samples report `resource.pressure=true`:
management recovered, but overall healthy operation and 679 deployment are
not established. Retry evidence uses `retry-679-*` and
`postretry-679-path-identity.json` in the same bounded evidence directory;
`retry-679-rolled-back.jpg` shows the actual client result.

The same frozen, always-refuse diagnostic installer was then invoked once by
an isolated SYSTEM/Highest scheduled task, without startup triggers or retries.
It returned `launch=1;code=4;guard=1;floor=0` in 3,712 ms, localizing this
diagnostic failure to the Agent preflight's owner-accounting/policy path rather
than failure to launch PowerShell. The task was removed and actual Agent PID
6228/generation, owner/configuration bytes and ACLs remained unchanged. Current
direct guest execution is also SYSTEM, ARM64, session 0; the historical direct
success used a different owner-file snapshot. These observations alone do not
prove a scheduler or identity cause. Evidence is
`/tmp/edr-679-scheduled-fixture-sb9ftict/fixture-result.json` and `task-result.json`.

An adjacent direct invocation of that same diagnostic installer succeeded
(`code=0`, 1,983 ms), as did one direct invocation of the actual 679 EXE with
bounded stderr classification (exit 0, 173 ms, empty stderr). Their owner-file
snapshots differ from the scheduled invocation, so neither success eliminates
the previously observed failure or establishes its cause. No direct probe was
repeated to obtain a desired result. Results are
`/tmp/edr-679-adjacent-direct-wabhxl49/comparison.json` and
`/tmp/edr-679-reason-preflight-6dy33i78/result.json`.

## Follow-up: bounded maintenance selection and Windows concurrency coverage

The additional full UTM queue test exposed an actual read-amplification path
in the shared capacity-cost expressions: `length(CAST(blob AS BLOB))` loads
the payload before the maintenance time check. A real SQLite VFS that adds
1 ms to each main-file read, without replacing I/O or its result, measured
3,078 reads / 12,607,072 bytes / 3.878 s and no dispositions in the first slice.
The minimal fix uses `length(column)` only when SQLite reports BLOB storage;
all other types retain the original CAST expression. The same experiment then
needed 521 reads / 2,134,008 bytes / 0.651 s and retired one eligible journal.
No frozen payload, identity, retention condition, capacity limit or schema
changed. Startup already recreates the accounting triggers and recalibrates
the nine-category ledger; their accounting semantics remain equal.

The regression adds one 30 ms delay after the first 128 KiB of real main-file
reads in each maintenance slice. With identical fixture input and the original
40-turn bound, the old production source fails (2.699 s, 44 deferred rows and
eight eligible journals remain); the fixed source passes (0.937 s, eight
delayed slices). Final payload/oversize protection, complete eligible cleanup
and independent ledger checks are unchanged. Type-equivalence tests exercise
real INSERT/UPDATE triggers and reopen calibration for BLOB, UTF-8 TEXT with
embedded NUL, NULL and numeric storage. A single indivisible SQLite delete can
still exceed 20 ms: that is a cooperative scheduling budget, not a hard lock
duration guarantee. Raw red/green, commands and source identities are in
`/private/tmp/edr-680-queue-case-gates/`; the per-read experiment is in
`/private/tmp/edr-680-queue-blob-cost/`.

Previously POSIX-only cache lifecycle/query and mutex tests now also use
Win32 threads and bounded waits. The unchanged context group passed 78/78 on
the host (3.798 s) and the UTM diagnostic build (10.625 s). This adds Windows
execution coverage; the lifecycle stress test alone does not prove every
concurrent record survived. Queue competing drain, stale connection ACK and
concurrent deferred-retain cases likewise execute on Windows. These UTM builds
use MinGW AMD64 under ARM64 emulation and do not replace native MSVC CI.
The dead-letter storm's 1,024 attempts / 91 admissions / 933 explicit refusals
and finite critical-reserve behavior are recorded in the acceptance table.

The current host build completed `edr_agent`, `agent_runtime_gate_tests` and
`telemetry_minimization_tests`. CTest selected 66 distinct tests: 61 passed and
five loopback server tests failed solely at sandbox socket binding (72.13 s).
Those five were rerun with local-listener permission and passed 5/5 (54.39 s);
the original failures remain recorded. Thus all 66 selected contracts passed
across the two runs, not 71 independent tests. Commands, source SHA-256 values
and results are `/tmp/edr-680-local-gate-provenance.json`,
`/tmp/edr-680-local-final-gates.log` and
`/tmp/edr-680-local-network-gates.log`. The host still uses the explicitly
documented P0 stub; it is not native Windows field acceptance.

The final fixed queue executable also passed the complete UTM suite once in
30.219 s (exit 0, no timeout), including the unchanged 40-turn fixture, slow
VFS, type accounting, dead-letter storm and all Windows thread cases. EXE
SHA-256 is `780d9419be09cb10f8fa36249831ca59a2e0b3ce7a81c531fa2425b9793d9eb0`;
source identities and full results are retained under
`/private/tmp/edr-680-queue-case-gates/` and
`/private/tmp/edr-680-queue-case-native/`. The earlier failed full run is not
reclassified as passed; this is the verified result after the production
cost-expression repair. Native MSVC AMD64/ARM64 CI remains required.

## 2026-10-15 fourth batch: value retention, bounded owners and physical admission

This section describes the development patch prepared from
`6bedb86bf9811bc304f4c97fdd62212ef437423f`, branch
`codex/rtq-result-delivery-pressure`. It supersedes the third batch's list of
unfinished features only where implementation and evidence are explicitly stated
below. HEAD remains 10 commits ahead of audit 662 and one ahead of the comparison
SHA at preparation. Earlier batch results below remain historical evidence, not current gates.

The user has now authorized completing the implementation and deploying through
the client for verification. The selected endpoint is the existing UTM Windows
lab VM. The user subsequently explicitly authorized committing/pushing the
66 task files and publishing candidate 3.2.674 without changing latest, followed
by this single-client validation. Native CI and deployment results are pending
at the source freeze. Permanent historical-data disposal is still a separate
authorization. Additive metadata classifies new writes; it does not silently
convert old payloads into disposable inventory.

### Candidate release verification

The reviewed 66-file implementation was committed and pushed as
`caa4c4ad9b9f94a80600028d38f88f44d7786384`. Candidate 3.2.674 run
`38680417809` stopped at the native Windows release build-dependency gate:
MSVC rejected the queue test's local identifier `small`, which collides with
the Windows SDK `rpcndr.h` type macro. No client deployment occurred. The fix
only renames the two test locals and adds the SDK macro to the existing
non-Windows declaration fixture; production behavior is unchanged. The focused
cross-platform compile check passes, and queue storage / real-codec recovery
tests pass 2/2 (13.90 s). Raw results are
`/tmp/edr-675-windows-macro-check.log` and `/tmp/edr-675-queue-gates.log`.

The immutable release owner binds 3.2.674 to the previous source/run, so the
corrected source proceeds as candidate 3.2.675, without promoting GitHub latest.
The failed draft and CI evidence remain intact. Native gate and single-client
deployment results will be appended after they actually complete.

Candidate 3.2.675, source `5b461f9146ee2994b3dde6e8e6740105dea8f5db`, run
`38681945395`, passed the native compilation gates on both architectures but
failed runtime gates: AMD64 92/97 (266.36 s), ARM64 91/97 (459.15 s). Neither
package, full installer lifecycle nor final publication ran. The subsequent
standalone telemetry label runner was also skipped; overlapping labels within
the 97 tests must not be counted as an additional run. The client remains 673.

Four common failures were test portability defects: Python's Windows default
encoding when reading UTF-8 source, an LF-only installer order assertion, a
superseded literal Source assertion after actual expanded-size accounting, and
case-sensitive removal of `PSModulePath` from Windows Python's uppercase
environment keys. The fixes preserve the actual preflight-before-runtime-stop,
mandatory uninstaller, ACL, and original source-path contracts. Static installer
mutations cover missing refusal exits, reordered checks/stops, wrong uninstaller
and changed size-macro return values. Native Windows Python / PowerShell 5.1
reproduced the old module-autoload failure and passed with the corrected launcher;
the parent environment remains unchanged.

The candidate pressure test also exposed a real slow-I/O starvation path:
checkpointing before the pressure loop can consume every 20 ms maintenance
slice. Retirement now checks live pages before checkpointing. The existing
post-work and bounded reclamation checkpoints remain; free pages alone never
authorize evidence retirement. A real SQLite VFS adds 30 ms only to main-DB
sync, without replacing I/O results. The unchanged 800-group / two-round /
32-retry admission and referential-integrity assertions fail against 675's
production source (1.952 s) and pass after the change (1.257 s). Raw red/green
results: `/tmp/edr-676-slow-cache/{red,green}.log`. A separate MinGW/SQLite 3.53.4
UTM diagnostic initially showed productive but insufficient work in 32 turns;
that diagnostic is not the MSVC Release gate and is not proof of one common
root cause for every native failure.

The same native diagnostic also captured a partial-cycle boundary: DB
1,036,288 bytes, WAL 0, below the 1 MiB admission limit but above the existing
960 KiB WAL working target. Later turns used only the hard limit and stopped
pressure retirement prematurely. An in-memory pending-pressure bit now retains
the interrupted cycle until the live-page target is met; each later transaction
rechecks ownership, pins and physical space. It stores no row payload or pending
transaction, resets on close, and grants no additional deletion authority.
The convergence tests now allow one turn per classified fixture group plus the
16 existing physical-reclaim continuations, and fail early after 32 turns with
no new retired groups or lower physical minimum. The WAL test allows multiple
bounded maintenance cycles, still proving each physical drain does not rerun
retirement, the original working target is recovered, and the next candidate
needs no further maintenance. No budget, retention dependency or successful
admission assertion was relaxed.

ARM64 additionally timed out in the Inno synthetic fixture, whose old failure
output omitted the case and installer log. The follow-up adds bounded per-case
logs and owned-process-tree cleanup, retaining its 30 s / 45 s bounds and the
product's 15 s preflight bound. It does not claim to resolve the unknown timeout
cause. AMD64's actual Inno fixture passed (17.07 s), and the actual Agent's native
preflight fixture passed on AMD64 (1.36 s) and ARM64 (3.13 s). These are distinct
from the Python launcher failure. Complete 675 logs are retained in
`/tmp/edr-675-ci-all.zip` and `/tmp/edr-675-ci-{amd64,arm64}.log`.

The final follow-up source passes all 64 local gate tests in one run (122.88 s),
including real loopback TLS/codec checks. The build and test commands are:

```sh
cmake --build /tmp/edr-cache-assessment-egress-build --target edr_agent agent_runtime_gate_tests telemetry_minimization_tests -j4
PATH=/opt/homebrew/opt/openssl@3/bin:$PATH ctest --test-dir /tmp/edr-cache-assessment-egress-build --output-on-failure --no-tests=error -L 'agent-runtime-gate|telemetry-minimization'
```

Raw logs: `/tmp/edr-676-final2-{build,gates}.log`. The local P0 sensor stub
boundary described below remains unchanged. The exact current cache/test
source also passes UTM native `--candidate-retention-pressure` (4,924 ms) and
`--slow-checkpoint-retention` (3,241 ms), with real SQLite 3.53.4 and no surviving
synthetic database files. This MinGW x64 process on Windows ARM64 is additional
Windows I/O evidence, not a replacement for MSVC's two-architecture CI. Complete
compile/link inputs and source hashes are in
`/tmp/edr-676-native-candidate-latest/provenance.json`, and the two `*.runner.log`
files in that directory retain process exit/timeout results. Source advances
to candidate 3.2.676; publication and deployment remain conditional on the
native gates. GitHub latest was verified unchanged at `win_3.2.591`.

Candidate 3.2.676, source `114755d033aa00140d37c2f019d2f091a326b3d9`,
run `38685993380`, passed both native compilation gates. AMD64 passed 96/97
runtime tests (292.96 s); its only failure was the incremental-reclaim fixture
requiring exactly 256 pages reclaimed during open. Actual Inno (19.37 s), native
Agent preflight (1.51 s) and Python preflight (6.06 s) passed. The standalone
telemetry invocation was skipped after the CTest failure. No package was deployed.
Raw log: `/tmp/edr-676-ci-amd64.log`.

ARM64 passed all 97 release-gate tests (462.28 s), including the complete cache
fixture (94.32 s) and the actual 12-case Inno fixture (63.40 s). The earlier ARM64
Inno timeout did not recur; its historical cause is not established by this pass.
The subsequent independent telemetry run passed 35/36 (455.37 s). Its sole failure
was `p0_rule_ir_purpose_archive`: the test hardcoded a wider evidence mask than
the exact frozen private input authorized. The frozen 183-rule JSON is 162,946
bytes, SHA-256 `7a2aed69535960e643cd85614fee677949e179c7d8abe823a041b6b4be8c392d`,
from private input commit `896eb2f06c9ffa608085217d4d1e84494b43e564`.
Package, full installer lifecycle and publication did not run. Complete logs are
preserved in `/tmp/edr-676-ci-all.zip` (CRC checked); the exact ARM64 Test step is
`/tmp/edr-676-ci-arm64-test.log`. The next run must retain this explicit input
commit, rather than implicitly follow a changed repository variable.

The four-rule purpose fixture now derives optional fields independently from the
decrypted frozen input's three explicitly reviewed purposes, plus fixed predicate
requirements per case. Missing actor attribution, duplicate or unknown purposes
fail for review. It checks both authorized text restoration and unauthorized text
omission, retaining generation/gap/frozen-byte checks and rejecting forged command
or parent-field masks at the real final egress gate. No rule, production matcher
or upload permission changed. The former test fails with the exact CI input
(0.825 s) but passes unchanged with the newer workspace input
`6b7390644145ba56439a7554ffce57fc2bf5657e80c64d3e90fb75d1da9506e6`
(0.310 s). The corrected test passes both (1.067 s / 0.307 s). Five related real
P0 operation, golden, exclusion, snapshot and command-admission tests also pass.
These local builds use real PCRE2, OpenSSL, protobuf/LZ4 and egress code, without
the P0 stub; they are test-only macOS builds and do not replace the verified
native Windows producer. Exact sources, compiler/link arguments, input hashes
and raw results are in `/tmp/edr-677-purpose-real-build/`.

The incremental-reclaim fixture assumed immediate work which the deadline does not
promise. With the real slow-sync VFS, its original assertion fails with 8,201
free pages both before and after open (1.255 s). The test now allows 0..256 pages
at open; if zero, the very next poll, without advancing time, must reclaim exactly
256 pages without another retirement run. All original per-slice/per-cycle bounds,
no-work-after-drain, two-cycle convergence, zero evidence eviction and retained
fact assertions remain. The slow-sync case passes (3.191 s), and the complete
local cache fixture passes (12.50 s). Production code is unchanged. These results
prove the deferred-work contract; the original native failure did not record the
page delta and does not independently establish this as its only cause.
Raw evidence: `/tmp/edr-677-reclaim-{red,green}.log` and
`/tmp/edr-677-cache-full.log`. On the UTM guest, the same updated fixture passes
both the slow-checkpoint case (5.875 s) and the complete candidate test (44.656 s),
each once with exit 0 and no timeout. This is MinGW x64 under Windows ARM64 with
real SQLite, in an exclusive synthetic directory; the installed client, services
and real cache were not changed. The test object was rebuilt; all 28 production
C files and 219 headers were checked against `114755d0`, and the 29 reused object
hashes and exact link inputs are recorded in
`/tmp/edr-677-native-candidate/provenance.json`. Its predecessor's provenance HEAD
label was stale; source hashes, rather than that label, establish the production
source identity. Raw `slow.result.json` / `full.result.json` and their hashed
stdout/stderr remain in the same directory. Formal release closure is pending.

Candidate 3.2.677, source `525b782e5868b9e9dac0b745ac11ef5c9827a26b`,
run `38689930815`, passed both 97-test release gates: AMD64 308.49 s and
ARM64 548.15 s. AMD64 also passed standalone telemetry 36/36 (441.82 s),
compiled the complete Inno package and uploaded its candidate bundle. ARM64
standalone telemetry passed 35/36 (552.84 s): its sole failure was the aggregate
`local_evidence_cache_candidate` executable being killed at 150.04 s. The same
executable had already passed the first ARM64 invocation in 174.20 s; AMD64's
two invocations passed in 127.65/121.12 s. No assertion failed in the timed-out
invocation. It reported two completed near-full migrations (34.765/29.094 s),
then entered bounded reclamation. The first release invocation had no individual
CTest timeout; the standalone runner imposed 150 s on every test. These facts
establish an aggregate-fixture/deadline mismatch, not a cache deadlock or a
claim that any arbitrarily slow disk must finish in that time.

The actual Inno preflight fixture passed on both architectures (20.67/61.76 s),
and the corrected P0 purpose fixture passed (1.11/0.99 s). ARM64 package, the
separate complete installer/upgrade/rollback lifecycle, and combined publication
were skipped. No client was upgraded. Complete evidence is
`/tmp/edr-677-ci-all.zip` (CRC checked), `/tmp/edr-677-ci-summary.json` and the
architecture-specific `*-test.log` files. The ZIP SHA-256 is
`f83e7c514aae83624ac7ef514960643079c6097119a70045dd906d719e7e2d4e`.

The follow-up keeps every original fixture body, assertion, conditional branch
and default execution order, using one case list filtered into context,
migration and retention CTests. The existing executable and manual full run
remain. All three groups retain a 150 s deadline and share a CTest resource lock;
runtime, telemetry and Windows release labels require all three. An unknown or
empty selector fails instead of running no cases successfully. Begin/end case
markers with diagnostic wall time identify the active operation on timeout;
they do not change simulated clocks, admission or product deadlines. POSIX
coverage remains 126 call expressions (78 context, 10 migration, 38 retention),
Windows 124 (76/10/38); the two distinct 119/121 MiB WAL fixtures both remain.
CTest totals grow by two through partitioning, not additional behavior coverage.

The three host processes passed in 4.296/1.984/7.475 s and the unchanged-order
full run in 12.164 s. Their executed call lists match the original list exactly,
with no omission or duplication; five invalid-argument cases refuse before any
case starts. Raw progress and digest evidence are in
`/tmp/edr-678-host-suites/` and `/tmp/edr-678-cache-suite-plan.json`. Current CTest
inventory confirms all three selectors, labels, deadlines and resource lock.
Independent review found every original test function and pre-existing child
command dispatch byte-identical. Production source is unchanged from
`114755d0`; candidate 3.2.678 still requires release CI and actual deployment.

The isolated UTM Windows runs also pass, with the same 150 s per-process limit:
context 76 cases / 9.203 s, migration 10 / 11.141 s, retention 38 / 25.985 s,
and the default full run 124 / 41.531 s. Their begin/end lists were compared
directly with the original `525b782e` Windows call list, including both WAL
tail sizes. Original production sources and linked objects remain unchanged.
The test-source SHA-256 is
`30b24da8e09b772bcbda6471c59a16bb2b2cd04f475da9e0a348a3193b794dc1`;
the isolated executable SHA-256 is
`74185ad7005619c558468ef44b59aded4a3f4642fa5323bc8e2491eb0f155820`.
Commands, per-case raw logs and build provenance are retained in
`/tmp/edr-678-native-suites-eq_rk90d/`. This uses MinGW AMD64 under UTM,
real SQLite 3.53.4 and the existing P0 stub; it is not an MSVC ARM64 or actual
P0 release certification. Only an exclusive synthetic guest directory was used.

Four registration/failure-propagation regressions passed (475.872 s), including
both generators and 14 injected failure classes across runtime/Windows labels.
Two native-telemetry release-workflow checks and the Windows SQLite compile
contract also passed. Removing any of the three suite registrations causes
configuration to fail. The executed commands and tool-output transcripts are
retained in `/private/tmp/edr-678-registration-checks/`; these are transcripts,
not independently redirected complete raw logs. `git diff --check` passes.

Candidate 3.2.678, source `58b1f175d0cc1ebd1c8d36d3f9795d23f9633547`,
run `38695879937`, passed AMD64 runtime 99/99 (311.77 s) and standalone
telemetry 38/38 (440.16 s), including actual package compilation (4.547 s).
ARM64 passed 98/99 runtime tests (473.59 s). All three cache groups passed:
context 15.42 s, migration 47.72 s and retention 50.42 s. AMD64's corresponding
groups passed in 14.58/62.91/61.31 s, then 14.37/60.42/58.68 s in standalone
telemetry. The partitioned fixtures retained their 150 s deadlines.

The sole failure was ARM64 `windows_inno_evidence_space`: actual ISCC compilation
passed (1.256 s), but the first `first-install-default` synthetic installer
exceeded its 30 s process deadline (30.240 s). Its real log reached
`InitializeSetup`, passed parser/native directory checks and entered
`PrepareToInstall`, then logged temporary executable/DLL extraction. No later
preflight-return marker appeared. Exact owned-process-tree cleanup succeeded.
ARM64 standalone telemetry, package, both full install/upgrade/rollback lifecycle
jobs and combined publication did not run. The installed UTM client remains 673.

Complete evidence is `/tmp/edr-678-ci-all.zip` (1,163,712 bytes, CRC verified,
SHA-256 `8df5a22e73851a5297f88556f0b82867a80ef50fbdf4f16f7c1f3ac7afff8074`),
`/tmp/edr-678-ci-summary.json` and `/tmp/edr-678-ci-arm64-inno-failure.log`.
The log establishes the stalled interval, not a specific stalled subprocess:
cleanup lists PID parentage without image names or creation timestamps. The
34.25 s Python preflight test is cumulative across multiple processes, not a
single preflight duration. The synthetic installer reports 32-bit install mode;
the actual installers configure architecture-specific 64-bit mode. Separately,
the production launcher's 15 s wait starts only after PowerShell and
`Start-Process` return, so it does not bound that earlier interval. These are
distinct candidate mechanisms under investigation, not a basis to increase
timeouts or claim the real installer necessarily fails.

A UTM single-factor experiment held the production includes, diagnostic probe
and 30 s fixture / 15 s child wait constant. The old first-install fixture used
32-bit mode and launched SysWOW64 PowerShell (x86); adding native install mode
launched System32 PowerShell (ARM64). An external observer recorded owned process
images and creation times. Both cases succeeded: 6.052 s versus 2.621 s; the
observed PowerShell-to-probe interval was about 4.343 s versus 1.656 s. This proves
the test/production architecture mismatch, not the historical timeout's unique
cause. Raw evidence: `/tmp/edr-678-inno-bitness-o3_qv1m2/evidence/`.

The shared fixture now uses `x64os arm64` for both architecture directives, the
union of the two native production packages' respective settings. It asserts
64-bit install mode and logs the effective system PowerShell path. Production
package restrictions, preflight code, all 12 case expectations and every deadline
remain unchanged. Independent review found no changed product admission contract.
The host installer/configuration and packaging checks pass 2/2 (0.24 s), with
raw output `/tmp/edr-679-installer-contracts.log`. Full native closure still
requires the next candidate's actual release executables and lifecycle jobs.

The corrected complete fixture passes all 12 cases on UTM: six expected successes
and six expected refusals. A separate synthetic probe sleeping for 60 s was
terminated by the unchanged production 15 s child wait: the observer captured
PowerShell exit 124, the installer refused with exit 7 after 17.396 s, neither
the before-copy marker nor `one.bin` existed, and no owned process survived.
The fixture's 30 s outer cleanup was not invoked. Evidence and exact source hashes
are under `/tmp/edr-678-inno-sleep-full-c4ojop21/`. These experiments use the
real production includes and a preflight-only diagnostic executable, not the full
release Agent; the sleep probe is deliberately synthetic. They validate the child
deadline and fixture correction, not a bound on PowerShell startup before that
wait or a reconstruction of the historical CI timeout. Source advances to
candidate 3.2.679 with the same frozen P0 inputs and without changing latest.

### Effective policy and ownership

| Data / actual owner | Retention and protection | Delivery obligation |
| --- | --- | --- |
| New typed non-DIRECT local-v3 diagnostic / `p0_source_only_enqueue_record` and `edr_storage_queue_p0_source_only_commit_local_typed` | Policy 2 with exact endpoint, tenant, event time, subject and parent generation metadata. Both insertion time and event time must pass the queue retention target. Recheck payload/owner hashes, journal, deferred, lineage, projection and recovery/loss ownership in the writer transaction. | No default transmission. Retirement is not an ACK. |
| Old/untyped local-v3, DIRECT or unknown owner | Protected and separately counted. No inference from `local_evidence` status. Opaque unresolved recovery owners conservatively hold retirement. | Existing obligation remains authoritative. |
| New local candidate group / `edr_local_evidence_cache_record_behavior` | Recent detail first; selected value comes from supported detector evidence or known generation with actual causal context. Severity alone is insufficient. Retire the candidate, canonical bundle, both reference layouts and exclusive facts together; shared references survive. | Alert projection does not release the original group. |
| Full command context fact / context store | Shared content with exact scope and process generation. A retained subject/parent reference, RAM process/window or current DB process owner prevents retirement. Legacy or unknown command owners remain protected. | Full local command is returned only under the existing purpose/field contract. |
| New terminal journal / enforcement precreate and typed result freeze | Reserve intent, both final frames and 2,048 bytes of local owner/index metadata before authorizing the action. Missing scope or generation rejects before execution. The journal is the only full source owner; the former ordinary source duplicate is no longer created. | Policy 3 has no source upload/ACK obligation. Intent and minimal combined projection require their own real ACKs; only then does the independent local retention window begin. Old policy-0 owners stay protected. |
| Command JSONL / command state | Incremental byte and record-slot accounting; reserve queued/running/terminal/receipt completion. Unknown or corrupt inventory refuses new owners. Existing final/idempotency/policy-held records are not TTL-erased. | Real result/receipt owners remain separate from query copies. |
| Command result SQLite copy | Inserts, growth and concurrent writes use the same capacity check. Bounded TTL may reclaim copies. Failure is returned and counted. | Failure of an optional query copy never fabricates success for the authoritative JSONL owner. |
| PMFE action, open context window, investigation snapshot | Existing action/window ownership protects its dependencies. An authorized query has one bounded in-flight snapshot, command identity and expiry; lock refusal is explicit and the snapshot releases on every exit. | No new remote command or permanent remote-control permission. |
| Reconstructible process/file/network/registry indexes and diagnostic metrics | Existing TTL, now bounded row/byte slices; fixed retirement reason counters have bounded keys and are included in the database budget. | Health contains fixed numeric counters, not evidence content. |

Retained -> retirement_eligible is transient within the retirement transaction;
a rollback restores retained. Successful deletion increments finite policy/reason
statistics rather than accumulating one tombstone per event. Pending, ACK, local
retention and recovery ownership remain distinct dimensions.

### Configuration and budget coverage

All new TOML keys belong to `[offline]` and require controlled restart to change
the storage instances. Failed config reload now parses into a temporary object:
a failed new-field validation preserves the entire active configuration, heap
ownership and accepted file timestamp. Config tests cover this before/after
contract, including command safety settings.

| Setting | Default / derivation | Scope |
| --- | --- | --- |
| `max_queue_size_mb` | Existing compiled default 512 MiB remains; explicit sample/deployed values override it. | Queue logical owner payload/metadata ledger. Not an Agent directory limit. |
| `retention_hours` | Existing 72 h default | Queue typed diagnostic target; protected owner/legacy data may outlive it. |
| `evidence_cache_retention_hours` | Existing 24 h compiled default | Recent local evidence target. Pressure can shorten it through whole-group retirement. |
| `evidence_cache_selected_retention_hours` | New 0 resolves to the existing queue retention window, at least the recent window. Explicit 1..87600 h must not be shorter than recent. | Selected candidate target, not a guaranteed retention duration under every load. |
| `command_state_owner_budget_mb` | New 0 derives 39,438,000 bytes from the existing 300-record compaction working window, two maximal 65,730-byte records per owner. | Independent bounded JSONL owner inventory. The existing 1 MiB `EDR_COMMAND_STATE_MAX_BYTES` remains a soft compaction trigger. |
| `storage_min_free_mb` | New 0 derives `3 * max(owner_budget, startup_protected_floor) + 24 MiB`; a positive value can raise this floor. | Actual containing-volume free-space admission. With the default owner budget: 143,479,824 bytes. |

The physical derivation covers owner plus atomic-compaction copies, two 4 MiB
SQLite checkpoint double-writes and the existing 4 MiB terminal reserve twice.
Each writer adds its own peak growth estimate. Health reports `policy_restart_required` when accepted configuration differs from the startup policy. It is a conservative admission
check, not filesystem block reservation: another process or an I/O failure can
still consume the volume. Unknown owner accounting holds ordinary writes;
already durable queue completion checks its actual growth independently. Invalid
configuration and failed volume queries fail closed.

DB pages include indexes and freelist allocation. Queue logical counters do not
include SQLite physical overhead; DB/WAL/SHM are reported separately. Evidence
cache admission retains its existing DB+WAL sizing semantics, reports SHM and
checks volume headroom. Command JSONL and temporary compaction copies use their
own guard. Updater download, extraction, runtime staging and rollback copies
check the actual destination volume, including mounted NTFS volumes; their
bytes are not charged to the queue's 512 MiB setting. The full installer now
measures its existing `[Files]` Source expressions before compression. New
updaters pass `/EDR_MIN_FREE_BYTES`, but the installed 673 updater does not. The
installer therefore always executes the package's own explicit local
`--storage-space-preflight` command, before stopping the old client or replacing
files. It uses the installed TOML and the same locked command-owner accounting
and physical formula as startup, taking the greater of the local and supplied
floor. Missing/malformed configuration, corrupt owner inventory, probe failure or
15-second child timeout refuses installation. A supplied zero cannot lower the
local floor. First installation uses `--defaults` without opening a state file.
This CLI starts no Agent workers, collection, maintenance or networking. Its
separate read-only owner-inventory entry point validates existing ACLs/reparse
boundaries without repairing them, does not create a missing state directory,
and takes the normal owner lock. That lock file may be created and its ACL
secured; the JSONL and its ACL are never rewritten. “Read-only inventory” does
not mean zero filesystem writes for acquiring the owner lock.
Its output file is created exclusively and contains only decimal bytes. Host
synthetic cases use both the complete built Agent and the isolated test client.
Thirteen native UTM cases pass with unchanged owner SHA-256, creation/write
timestamps and owner/parent SDDL; unsafe ACL, parent junction and busy lock are
rejected. The native helper links real Windows/config/owner implementations;
only the unused config listener callback and query-copy abort boundary are
stubs. The Windows release gate runs the same PowerShell fixture against the
actual full Agent. Raw output: `/tmp/edr-native-preflight-readonly-final.log`.

The preflight executable and its existing app-local DLL closure are extracted
into the installer's private temporary directory after an initial expanded-size
check. Final admission checks expanded new files and lifecycle overlap on the
actual application and temporary volumes. The compile-and-execute Inno fixture
uses the actual built Agent, includes old-673 upgrade/repair calls without the
new argument, and remains a native Windows release requirement. PowerShell 5.1
parsed the fixture, lifecycle script and expanded launcher with zero errors;
syntax checks do not establish successful Inno compilation/execution. Inno's
bootstrap temporary files precede this hook; exact uninstaller metadata and
concurrent disk consumption are not a hard quota. Existing log rotation owns
log files separately (configured size/count, checked once per second); it is not
a per-write hard quota and burst overshoot is possible. The patch does not claim
an atomic whole-directory hard limit or zero temporary-file overhead.

### Bounded maintenance and degradation

Terminal status refresh now reads five singleton counters in `queue_meta`,
maintained by journal INSERT/UPDATE/DELETE triggers and calibrated once at open.
New precreate refuses unavailable accounting. The test used a second legacy SQL
writer, rollback, corrupt counters and reopen; refresh uses 13 SQLite VM steps
with both a small inventory and 5,000 retained journal rows. Thus terminal
admission no longer SUMs the journal on each event.

Queue old-owner maintenance rotates five stages with a shared 128 examined rows,
4 MiB owner cost and 20 ms cooperative deadline. A single oversized indivisible
legacy owner stays protected and increments `maintenance_oversize_holds`. New
typed retirement has a bounded selector and rechecks obligations in the same
transaction. Evidence maintenance rotates stages and bounds group/ref/fact work;
reclamation is incremental, not full VACUUM on a full disk. SQLite busy, a single
SQL statement or fsync can exceed a cooperative deadline; this is not a hard
20 ms latency guarantee.

All evidence maintenance write slices, incremental vacuum and checkpoints now
perform ordinary physical admission. A long reader and an unreachable floor
leave expired copies, candidate groups, command facts and independent reclaim
unchanged, with zero test-VFS writes. Closing does not implicitly checkpoint;
committed WAL remains recoverable. The guarded automatic checkpoint runs after
commit and returns success even when checkpoint is deferred, preserving the
already successful transaction. A test raises the existing physical floor during
a real VFS write and proves STORED plus readable WAL after that refusal.
Startup measures existing DB/WAL pages and the source-table inventory for missing
indexes, under a ten-second cooperative probe deadline. The index-cost manifest
is checked against every actual CREATE INDEX declaration. Full old payloads are
not re-encoded; insufficient headroom holds startup instead of clearing the cache.
Focused complete-cache, authorized-query and index-manifest checks pass 3/3 in
12.11 seconds: `/tmp/edr-physical-maint-final-tests.log`.

Queue startup separately accounts for missing indexes and old-owner backfills;
already complete schemas avoid a whole-database rewrite allowance. Main and
recovery opens also cover reconstructing SHM from an existing WAL before any
SQLite open can create that index. Runtime retry/latch/maintenance writes use
ordinary admission. Existing ACK/freeze/completion can use reserved headroom,
but must cover the exact owner, matching projection/original and actual free
space. Finalization updates only its current journal owner. A pinned 6,324,232
byte WAL test records zero growth during refused retries, zero receipts when
actual space is zero, and successful reserved completion after space recovers.
Automatic/close checkpoints cannot bypass the floor. Refusal diagnostics report
the first event, changed causes and power-of-two cumulative counts. Final unit
and real-codec logs: `/tmp/edr-evidence-phase4-20261015/queue-runtime-final.log`
and `queue-recovery-runtime-final.log`.

Capacity exhaustion rejects new ordinary owners, retains required dependencies
and emits fixed counters. Critical reserves are finite. If they fill too,
necessary delivery/action admission fails explicitly; no unlimited acceptance
promise is made. Unknown legacy stock can prevent recovery of usable capacity.
This is reported as protected inventory, not disguised as a successful upgrade.

### Executed comparison and Windows checks

The checked-in queue comparison runner is
`tests/run_queue_retention_comparison.py`, with
`tests/queue_retention_comparison.c`. Both builds receive the same real protobuf
BAT1 stream: 1 MiB queue budget, 1 h retention target, 48 unique 128 KiB records
across 12 simulated windows; each includes a 90 KiB synthetic command and a
subject/parent tuple. Old source is exported from audit 662 without changing the
checkout. Time substitution is identical; total_changes instrumentation is
explicit and does not change queue policy.

| Observation | Audit 662 | Current patch |
| --- | ---: | ---: |
| Inputs admitted / rejected | 7 / 41 | 36 / 12 |
| Last window admits | 0 | 3 |
| Age of newest retained evidence | 36,070 s | 60 s |
| 20-byte terminal admitted | No | Yes; exact SQLite bytes verified |
| Completeness of retained decoded parent/subject tuple and command | 100% | 100% |
| Source-only full-fact uploads | 0 | 0 |
| Sampled DB+WAL+SHM peak | 1,890,896 B | 4,956,096 B |
| SQLite total_changes | 106 | 347 |

This proves rotation and preserved retained payloads for this workload, at an
increased sampled physical peak and more logical SQLite changes. total_changes
is not a byte write-amplification measurement. macOS block I/O counters returned
zero and are unavailable as useful I/O evidence. CPU measurements are single-run
observations, not proof of improvement. Raw results and exact compilation argv:
`/tmp/edr-queue-physical-final-20261015/`. The final run uses queue source SHA-256
`a9423f6f4a41293e9c9301b21fb1da7ccf5d797c9489d4b7564687ca3e9f8c4b`;
measured user/system CPU is 0.105780/0.018998 seconds for audit 662 and
0.273389/0.039594 seconds for the current patch.

The checked-in evidence comparison is `tests/run_evidence_retention_comparison.py`
and `tests/evidence_retention_comparison.c`. It exports untouched HEAD
`6bedb86b`, verifies every baseline source/header against Git, and compares the
same 8 MiB budget, 8 simulated hours, 192 candidates and 48 low-severity causal
facts. Five runs per variant use the same 63,064 encoded input bytes, SHA-256
`11ff7f03c2ee274b9127d9510f45afe0df5e7dec3d40d938cb1d57f7371efa64`.
The final candidate source `114755d0` was remeasured after the slow-disk fixes.
The following are medians; the old 1 h versus current 1 h columns isolate code
changes, while current 4 h also changes the selected retention policy.

| Observation | Original HEAD, 1 h | Current, 1 h | Current, selected 4 h |
| --- | ---: | ---: | ---: |
| Retained recent / selected candidates | 18 / 6 | 18 / 6 | 18 / 24 |
| Self-contained complete parent chains | 0 | 6 | 24 |
| Chains reconstructible including exact-generation process cache | 6 | 6 | 24 |
| Oldest retained selected evidence at final sample | 59 min | 59 min | 3 h 59 min |
| Sampled DB+WAL+SHM peak bytes | 2,305,312 | 3,272,648 | 3,379,192 |
| Final DB+WAL+SHM before close | 2,251,752 | 677,048 | 791,832 |
| CPU seconds | 0.163813 | 0.285384 | 0.306514 |
| SQLite VFS read bytes | 2,928,796 | 4,555,532 | 7,951,116 |
| SQLite VFS write bytes | 17,364,348 | 31,429,500 | 28,981,320 |
| SQLite VFS sync calls | 32 | 53 | 53 |

Old evidence was not wholly absent: six chains were reconstructible through the
process cache. The new self-contained owner removes that dependency for retained
chains. The workload is sparse hourly bursts, not a promise of continuous
four-hour visibility. Compared with original HEAD, the selected-4 h case costs
66.9% more VFS write bytes and 87.1% more CPU in this fixture. VFS issued writes
are measured, not physical-device writes. This is a value/cost tradeoff, not a
performance-improvement claim. Raw runs, exact compiler argv and source hashes:
`/tmp/edr-evidence-676-20261015/`. Earlier results in
`/tmp/edr-evidence-physical-final-20261015/` and the initial frozen comparison
remain historical evidence. CPU/read counts vary with the host and OS cache;
these medians do not establish device I/O or production throughput.

The terminal size regression uses two 98,300-byte synthetic commands. Required
outbound fields omit them: intent is 1,128 bytes while the measured full local
intent is 197,812 bytes. The former intent-based reservation (135,918 bytes)
cannot cover the 202,463-byte final owner cost. Pre-action sizing now reserves
526,846 bytes, and typed freeze refuses expansion beyond its promise. The
production codec round trip preserves both commands; only minimized intent and
combined projection enter normal transmission. Matcher/action/storage are
explicit stubs in this producer fixture; separate queue tests use real SQLite,
codec and ACK parsing. The 98,300-byte input is a stress case, not an assumed
per-event size.

### Durable command result backpressure

Shell streaming now consumes the result-persistence return value. A refused
chunk keeps its exact sequence, bytes and authority in one fixed 2,048-byte
buffer per existing bounded session; pipe reads and new input pause. Retry delay
is capped at four seconds. Process timeout still terminates the child, but exit
output drains and the close marker must be accepted before the slot is released.
This pending buffer is volatile: a process crash cannot promise preservation of
bytes that were never durably accepted. Explicit close/shutdown reports an
undurable discard rather than silently claiming delivery.

A Windows pipe failure alone no longer synthesizes exit code zero or releases a
still-running process's Job. The regression uses a real child that closes its
stdout/stderr and remains alive behind a named event. On the UTM guest, the
negative-control binary with the former condition fails the owner-preservation
assertion (exit 1); the corrected binary preserves it, then observes actual exit
7 or timeout exit 1. The same corrected run retains the complete 3,000-byte
pressure test, stable sequence retries and failed-close recovery (exit 0).
Raw logs: `/tmp/edr-shell-pipe-native-red.log` and
`/tmp/edr-shell-pipe-native-green.log`. This is an x64 fixture executing under
ARM64 emulation, not a native ARM64 Agent deployment.

### Authorized lookup and rollback boundaries

The existing signed `rtq_query` route now consumes its frozen purpose contract,
not an independently truncated payload. It checks tenant/endpoint, command/task,
purpose, issue/expiry, event window, requested fields and actual encoded output
bytes. A finite query slot owns a copied snapshot; queue locks/SQLite reads end
before projection callbacks. Busy, expired, oversized and corrupt reads fail
with a cause. There is no automatic permanent severity pin. One in-flight query,
1,000 result rows, 4 MiB copied queue bytes and the existing final result byte
limit bound this operation; release/cancellation ends the pin.

Real RAW/LZ4 decoding, scope checks, result projection, command-state persistence,
HTTP JSON and final egress assertions pass in `authorized_local_query_contract`.
Default queries omit complete commands. Explicitly authorized fields can match
and restore a 6,000-byte command. Terminal journal originals use the same path
with exact integer generation validation. Query absence returns one of
`outside_retention_window` or `not_collected_or_expired` and
`absence_is_evidence=false`; it never proves the behavior did not occur.
Materialized full context/parent chains remain queryable through local SQL views
and are verified by projection tests. The existing remote result contract does
not expose entire artifacts or a process tree; this patch adds no such permission.

An actual unmodified HEAD binary opened and maintained new databases in formats
0, 1 and 2 after aging them beyond the old recent window. New durable deletion
guards preserved candidate/context rows, full command facts, references and
materialized projection hashes exactly. Old cleanup returned constraint
`candidate retirement owner required`, not success at eviction. This supersedes
the third-batch rollback data-loss warning for this tested inventory. It does
not give an old binary the new budgets or query policy: protected stock can
exhaust its capacity. Raw evidence:
`/tmp/edr-retention-head-benchmark/guarded*-rollback*.{log,json}`.
Rollback must preserve the additive schema/guards and exact frozen payloads;
never drop guards, re-encode originals or use cleanup as a downgrade step.

An unmodified original-HEAD queue binary also opened synthetic policy-3 journal
inventories in precreated, ready and local_retained states. After eight
maintenance/drain rounds, all 30 frozen payload/hash/identity/owner fields were
identical and full-source ACK/policy-held remained zero. However, the old ready
path repeatedly selects the forbidden full source and cannot advance to combined
delivery. This is data-preserving degraded operation, not a supported routine
downgrade. Reopening with the new queue completes the minimized combined receipt
and reaches local_retained, without changing any frozen field or source flags.
Precreated unknown outcomes remained non-executable and wrong-generation replay
conflicted. The transport is a local stub; synthetic receipts exercise the real
ACK parser, and are not server or installed-client ACK evidence. All three
inventories passed SQLite integrity_check. Reproducer and raw evidence:
`/tmp/edr-terminal-rollback-head/run.py` and its `results.jsonl`.

Current UTM identity was read from the running process: Windows client 3.2.673,
SHA-256 `9641DF3791F7C1F42FE98ECDCE75E44F664CA94E60EB97F3D18A7882054163CA`,
process start `2026-10-14T18:58:41.8491942Z`. The earlier 670 snapshot is stale.
Before deployment, the console changed this existing 3.2.673 endpoint from
online to management-degraded while its engine report remained current, queue
was zero and pressure was false. A read-only UTM process check still found PID
4652 with the same start time and installed path (65,798,144-byte working set).
This is an unresolved pre-upgrade observation, not a result of the new patch;
the client has not been replaced. Recheck the concrete runtime-health reason
before judging the candidate upgrade.
The new standalone physical-guard test passed as Windows x64 on the existing
ARM64 guest's emulation; this is not native ARM64 Agent release evidence. The
current updater parsed with Windows PowerShell 5.1.26100.9711; the real volume
helper allowed normal/missing-parent cases and rejected arithmetic overflow and
an unreachable floor. No installer or installed-client replacement was run.
A separate opt-in NTFS test created and verified a new 64 MiB VHD on this UTM
guest, filled only that volume and observed an actual Windows disk-full error.
At 2,052,096 bytes free, ordinary admission refused, a 4 KiB reserved completion
was allowed, and a request larger than actual free space was refused. After
removing only the fixture's fill file, free space recovered to 54,611,968 bytes
and ordinary admission resumed. The VHD was detached and removed. No system
volume was filled and no real Agent cache was read or changed. Reproducer:
`tests/test_storage_physical_volume.ps1 -GuardExe <test_storage_physical_guard.exe>`;
raw output: `/tmp/edr-native-isolated-volume.log`. This validates the real mounted
volume API and guard decisions; it is not a claim that a running Agent can
commit after physical allocation has failed.

The reproducible helper test is now `tests/test_update_physical_guard.ps1`, bound
to the Windows release gate. No execution-policy or signature requirement was
relaxed. Logs: `/tmp/edr-phase4-native-guards-final.log` and
`/tmp/edr-phase4-native-updater-repo-test.log`.

Focused host checks passed for config preservation, physical guard, owner
compaction, inbox recovery, process identity/receipts, updater contract/packaging
and final health projection. These use real SQLite where linked and the existing
non-production macOS P0 stub; they are not Windows sensor validation. Raw logs:
`/tmp/edr-phase4-review-fixes-{build,tests}.log`,
`/tmp/edr-phase4-owner-updater-tests.log` (initial stale packaging assertion fails),
and `/tmp/edr-phase4-native-contract-{build,tests}.log` (corrected packaging and
egress assertions pass). No failing initial run is counted as a pass.

The final frozen-source integrated runtime/telemetry run passed **64/64** tests
(51 runtime and 29 telemetry tests with overlap) in 121.24 seconds. This run
includes the last queue startup/SHM correction, real loopback mTLS 429/503,
physical maintenance/checkpoint guards, read-only owner preflight and shell
backpressure. Exact commands:

```sh
cmake --build /tmp/edr-cache-assessment-egress-build --target edr_agent agent_runtime_gate_tests telemetry_minimization_tests -j4
PATH=/opt/homebrew/opt/openssl@3/bin:$PATH ctest --test-dir /tmp/edr-cache-assessment-egress-build --output-on-failure --no-tests=error -L 'agent-runtime-gate|telemetry-minimization'
python3 tests/test_storage_space_preflight.py --client /tmp/edr-cache-assessment-egress-build/edr_agent
python3 tests/run_queue_retention_comparison.py --output /tmp/edr-queue-physical-final-20261015 --codec-build /tmp/edr-cache-assessment-egress-build
python3 tests/run_evidence_retention_comparison.py --output /tmp/edr-evidence-676-20261015 --baseline 6bedb86bf9811bc304f4c97fdd62212ef437423f --runs 5
```

Final build and test logs: `/tmp/edr-cache-completion-queue-final-build.log`,
`/tmp/edr-cache-completion-final-gates.log`,
`/tmp/edr-cache-completion-final-raw.log`, and
`/tmp/edr-cache-completion-agent-preflight.log`. The mTLS delivery fixture observes
exactly two attempts each for 429 and 503 owners, one fresh result attempt,
three committed receipts, zero duplicate receipt observations and zero failed
business assertions. No 429/503 response is treated as an ACK. Prior runs and
corrected failures remain separately recorded. Release ownership/workflow Python
contracts passed 48 and 21 cases. Modified Python syntax, control-character
scan and `git diff --check` passed for all 66 task files.

Remaining release closure is native AMD64/ARM64 release builds and actual ISCC
lifecycle plus client upgrade/health/outbound verification. Until those run,
this section does not certify deployment or all ten acceptance items. The old
reader maintenance result above covers synthetic formats 0/1/2; routine downgrade
with policy-3 journals is unsupported because the old binary cannot finish the
new delivery sequence. Installed real cache cleanup or permanent legacy-data
migration is not part of the authorized deployment.

### Acceptance evidence and release closure

| Required acceptance | Implemented and exercised contract | Remaining consumer closure |
| --- | --- | --- |
| 1. Sustainable rotation, retained causality | Queue comparison covers 12 windows without full-fact delivery; cache comparison covers 8 virtual hours with exact parent generations and complete selected groups. Protected or oversized old owners cause explicit refusal. | Windows new-client sustained operation; no claim of guaranteed days at arbitrary input rates. |
| 2. Same-budget comparison | Frozen old/current sources, identical encoded inputs, retained event ranges, complete chains, sampled DB/WAL/SHM, CPU and VFS issued writes are recorded above. | Device-level I/O and a production workload are not represented by the host fixture. |
| 3. Critical reserve | Ordinary full stock cannot consume terminal/action completion reserve; finite critical exhaustion refuses before action. Both 679 native gates passed. | Installed new-client admission and health. |
| 4. 20-byte terminal | Exact 20-byte payload admitted with full ordinary local stock, zero source uploads and zero fabricated ACKs. Final production source passed both 679 native gates. | No promise of unlimited critical admission. |
| 5. Result budget | Real insert, growth, 1,000 serial copies and four concurrent writers; busy and commit failure preserve existing bytes; owner JSONL and optional copy failure are separate. Both 679 native gates passed. | Installed new-client necessary result and durable server receipt. |
| 6. Pressure/network cases | Candidate dedupe/aggregation, unique and high-priority capacity, long commands, pin refusal, offline/ACK loss and policy refusal; real loopback mTLS 429/503 with exact successful receipts. Additional fixed-budget dead-letter storm: 1,024 attempts, 91 admits, 933 explicit refusals, 59 saturated waves, 420,693-byte logical plateau; reserved terminal and precreated result remain usable; source uploads/ACKs zero. | Storm uses this queue fixture's transport/codec stubs; it does not replace actual wire tests. Installed-client reconnect/delivery remains separate. |
| 7. Concurrency/restart | 679 native child-process migration/reclaim crash cases passed. Previously POSIX-only cache lifecycle/query and mutex tests now execute on UTM, as do queue competing drains, stale event/journal connections and concurrent deferred retain. | New Windows test bridges still require native MSVC CI. MinGW AMD64 on ARM64 emulation is additional evidence. A killed process is not hardware power loss. The additional full UTM queue run failed its old 40-slice fixture; retain this failure separately from focused passes. |
| 8. Time/physical pressure | Wall/monotonic window rules, SQLite busy, pinned readers, zero-space ACK refusal, guarded checkpoint and isolated native NTFS disk-full/recovery. | 679 real upgrade refused preflight and rolled back; isolated original release preflight passes do not certify installed new-client startup. Physical admission is not an atomic directory quota. |
| 9. Frozen identity | Exact payload/hash/batch/owner, known PPID, PID reuse, uint64 generation and guarded old-reader tests passed both native gates. Three sampled old queue owners remain unchanged after the failed upgrade. | Two original evidence candidate samples are missing after rollback: preservation is unverified and deletion timing/cause unknown. New installed-client checks remain pending; old policy-3 delivery downgrade remains unsupported. |
| 10. Minimal egress | Real protobuf/RAW/LZ4 round trips, bounded authorized query and final HTTP field assertions; source facts stay local after ordinary delivery; both 679 native gates passed. | Actual client/server consumers and unenumerated wire routes must not be inferred from server-filtered rows or empty completed-batch payloads. |

The Windows release must compile AMD64 and ARM64, run its native gate and actual
ISCC install/repair/rollback fixture, and retain immutable source/artifact
identity. UTM standalone helpers and macOS sensor stubs cannot replace those
steps. After the candidate release passes, the existing client upgrade command
must select only the named lab endpoint; verify installed path/version/hash,
new process start, health, protected inventory and real result/receipt behavior.
No migration/verification step may clear the real cache, relabel an unknown old
owner, synthesize an ACK or expand the normal upload projection. Keep any failed
run as failed evidence and repair the cause before continuing.

## 2026-10-15 third batch: retire complete candidate evidence groups

This batch continues on HEAD `6bedb86bf9811bc304f4c97fdd62212ef437423f`,
branch `codex/rtq-result-delivery-pressure`, preserving the earlier uncommitted
patches. HEAD is 10 commits ahead of audit `0ae3fb28e553223358db1a83ebd26432336af9e7`
and one ahead of comparison `3de0dc680c78c335f8ab6ba37eef0d0f5d8f46e2`
(`git rev-list --left-right --count`: `0 10` and `0 1`).
It changes development code and synthetic fixtures only. No commit,
UTM connection, deployment, production migration or real-cache cleanup occurred.
The second-batch queue rollback result below does **not** establish safe rollback
of this newer evidence-cache behavior.

### Verified defect and bounded scope

The former `sqlite_maintenance` expired candidate rows, bundles, reference rows
and facts independently. A younger surviving candidate could therefore lose an
older, low-severity shared context fact. The frozen before binary fails the
consumer-level shared-fact assertion; the changed implementation must preserve
its materialized projection until the last owning group can retire. Pending
reference delivery, an unknown artifact or a raw legacy `post_context` artifact
is not authority to discard the group.

The unit in this batch is a new P0 candidate with its canonical local
`p0_context_bundle`, both supported reference layouts and their shared facts.
`process_cache` remains a latest-PID lookup, not a historical generation graph.
The bundle embeds pre-context subject and parent generations. Existing
post-context templates preserve subject generation, PPID and parent PID state,
but do not contain a full parent generation tuple. This patch preserves the
causal detail already stored; it does not reconstruct missing parent evidence.

This is not completion of sustainable whole-Agent storage. Queue local-v3
originals still have no retirement policy: event/parent/deferred owner indexes
are incomplete. Full command objects and unknown/orphan evidence remain
protected, including newly written command objects. They can still exhaust
capacity. General authorized investigation pins, selected long-term value tiers,
a global physical disk guard and a complete maintenance time budget remain
subsequent work. No remote permission or upload route was added.

### Lifecycle and transaction ownership

| Owner | Current retention rule | Delivery relationship |
| --- | --- | --- |
| Existing candidate, or an old writer omitting metadata | Policy 0, retained; counted at open; no automatic promotion on replay | No inferred ACK or disposal permission |
| Newly inserted candidate | Policy 1, retained; only the complete group can become eligible in a writer transaction | Local bundle/ref owners must be `local_manifest`, with empty upload key |
| Shared context fact / compact dictionary | Retained while either reference layout still needs it | Pending/unknown ref state protects its group |
| Open post-context window | Protected until both event-time end and monotonic residence permit closure | Independent of alert delivery |
| Unfinished PMFE action | Verified wire/hash, tenant, endpoint, source identity and full process generation protect related groups | `scheduled`, `running`, `result_bound`, and `result_acked` remain protected; ACK alone does not end ownership |
| Unknown artifact or legacy raw post-context | Protected; no independent capacity or TTL delete | Unknown obligation is not treated as local disposal permission |
| Complete command object | Protected in this batch until a decoder/reference-aware policy exists | Never retired as a side effect of candidate cleanup |
| Command result query copy | Existing bounded optional-copy TTL; earlier batch enforces insert/growth budget | Authoritative command state and result delivery owners remain separate |
| PMFE terminal owner | Existing terminal TTL for `completed`, `expired`, `conflict` | Existing terminal transition contract remains authoritative |

`sqlite_retention_metadata_open` adds two columns, guards and five indexes.
New writes set policy 1; conflict/enrichment never changes policy. Unknown
persistent policy/state fails open with a diagnostic. A replay of policy-0
inventory stays protected. No frozen payload, hash, batch ID, lineage or process
binding is re-encoded by this change.

`sqlite_retire_candidate_groups` owns `BEGIN IMMEDIATE`. Inside it, the cache
mutex and SQLite writer transaction cover window and PMFE protection,
eligibility, canonical group validation, reference deletion, last-reference fact
collection, disposition counters and commit. `retirement_eligible` is temporary
inside that transaction; failed work restores `retained`. Successful retirement
removes the group. There is no per-record `retired` tombstone and no ACK mutation.
A private helper savepoint also prevents a failed group's partial deletion.

`edr_context_store_retire_candidate` validates the candidate scope, exact
canonical bundle identity, all artifact owners, legacy/compact reference
identity and delivery state, and referenced fact scope before deleting any
payload. It retains facts used by another candidate. Missing or corrupt required
structure stops the transaction with a cause. Oversized or unclassified groups
are protected. Exact candidate IDs of committed retirements alone are removed
from RAM windows and dedup slots. Context writes recheck their retained owner
inside their own transaction: capacity maintenance cannot leave stale saved IDs
that recreate orphan facts/references later in the same call.

### Retention targets, capacity and observability

The existing `[offline].evidence_cache_retention_hours` source default remains
24 hours, with a 128 MiB evidence-cache default. Normal group retirement requires
both event and local creation time to predate the configured cutoff, and the
post-context window to be closed. Under physical pressure, closed, classified,
unprotected complete groups may retire earlier, oldest first. Severity does
not determine whether a dependency survives. This is a recent-evidence policy;
it does not yet implement a separately selected long-term evidence tier or
promise 24 hours under every load. Repeated and unique event floods still depend
on existing dedup/admission plus the boundaries stated here.

The queue's separate 512 MiB logical budget has not changed. Evidence admission
continues to use its existing DB/WAL accounting and headroom. Indexes, dictionary,
metadata and fixed disposition rows consume SQLite pages under that accounting;
SHM remains reported. Logs, upgrade directories, filesystem free space and all
product-directory physical usage are not converted into a hard cap here.

Each transaction selects at most 1,000 indexed candidate metadata rows, then
charges at most 4,096 processing rows and
`min(page_size * checkpoint_pages, 4 MiB)` group field bytes. The initial bounded
metadata selection is separate from that processing budget; no total physical
read-byte limit is inferred. Checkpoint pages are bounded by SQLite's existing 1,000-page default,
including when auto-checkpoint is disabled. The 4 MiB ceiling is four existing
1 MiB manifest envelopes, not a new storage partition. These are traversal
bounds, not a physical I/O or memory guarantee: SQLite may materialize one
oversized row before its byte count is known. Protected inspections consume the
same slice. Two small in-memory keyset cursors advance only after commit and
wrap at the end, so permanently protected old groups cannot starve later ones.
An empty indexed seek may wrap once within a transaction without raising the
1,000-row selector bound. Pressure can continue past a protected tail within the
existing four-pass limit, allowing rapidly refilled older timestamps to be seen.
Restart may repeat safe inspection but does not grant retirement authority.

One normal expiry slice and up to four existing pressure passes can run per
maintenance call. The cache mutex still spans that call. Existing synchronous
startup/admission reclamation, SQLite busy waits, non-group index TTL cleanup and
checkpoint work are not a proven wall-time bound. Existing incremental page
reclamation is retained; full `VACUUM` is not used as a full-disk remedy.

PMFE protection reuses the existing 64-action bound, caps generation traversal
and protected IDs at 4,096, and fails closed on unknown identities or exhaustion.
Two partial indexes prevent completed actions or old PID generations from making
those owner checks scan the entire inventory. Protected action lifetime is based
on its explicit completion protocol, never an age-based unpin.

Six exact fixed rows in the existing metrics table accumulate policy-1
`expired`/`capacity` group counts, deleted payload-row counts and examined bytes
of retired groups, in the deletion transaction. They survive ordinary metric
expiry, do not contain identities and cannot grow in row count. Integer overflow
or metric persistence failure prevents retirement. Examined bytes are not freed
physical bytes. Process health adds retired groups, held decisions, retirement
failures and legacy candidate count at open; it sends no commands or raw facts.
Held decisions are repeatable decisions, not unique protected-record counts.
Backend/UI consumption of these new numeric fields is not yet verified.

### Migration, rollback and outstanding acceptance

Upgrade adds side metadata/indexes and leaves policy-0 inventory intact. Existing
compact-format migration and its resumability are reused. New/old/mixed reference
layouts are checked by synthetic tests. An interrupted additive ALTER is retried
by column discovery; candidate state/disposition mutations are one transaction.
No production migration has been executed.

**Do not directly downgrade this evidence database to the old binary.** Its
independent table cleanup ignores the new group ownership rules. A safe rollback
plan is to stop the Agent, preserve DB/WAL/SHM and the new side metadata as a
coherent snapshot, then use a compatibility build that understands group
protection, or inspect a read-only copy. Do not drop metadata, restore an old
snapshot over newly admitted evidence, or treat a successful old-version open
as proof of safe cleanup. Building and testing that compatibility rollback is a
separate release gate; the second-batch queue-only probe is not that gate.

Windows/UTM installation and disk behavior are untested in this batch. Before a
production gate can close, run Windows SQLite busy/long-reader/disk-full and
crash-during-migration/retirement tests; measure collection lock latency, physical
peaks, CPU/I/O and write amplification on equal before/after workloads; verify
authorized local query/export protection and unavailable-evidence reasons; finish
general pins and value tiers; and prove queue local-v3 dependency-aware rotation.
The existing native tests cannot establish universal fixed retention duration,
all clock-jump cases, or sustainable capacity for protected command/legacy stock.

### Local verification

The existing macOS Debug CMake builds were reused. The candidate suite links
real SQLite, cache, context store, migration and materialized projections, with
`EDR_LOCAL_EVIDENCE_CACHE_TESTING` fault/clock hooks and the existing P0 rule IR
stub. The command-state tests include their existing cache/transport test doubles;
they do not represent a combined live endpoint/server. The separate five-test
transport group uses real encoding/final gates and recovery ACK handling. No
production backend or native Windows consumer was executed.

Commands (all test executions used a temporary directory, not the repository):

```sh
cmake --build /private/tmp/edr-parent-dup-recheck-20261014/build --target \
  test_local_evidence_cache_candidate test_command_inbox test_command_process \
  test_command_upload_outbox test_command_result_compaction -j4
# Working directory: /tmp
/usr/bin/time -p /private/tmp/edr-parent-dup-recheck-20261014/build/tests/test_local_evidence_cache_candidate --candidate-retention
/usr/bin/time -p /private/tmp/edr-parent-dup-recheck-20261014/build/tests/test_local_evidence_cache_candidate --candidate-retention-pressure
/usr/bin/time -p /private/tmp/edr-parent-dup-recheck-20261014/build/tests/test_local_evidence_cache_candidate
ctest --test-dir /private/tmp/edr-parent-dup-recheck-20261014/build \
  -R '^(command_inbox_persistence|command_process_identity_and_receipts|command_upload_outbox_recovery|command_result_compaction)$' \
  --output-on-failure
cmake --build /tmp/edr-cache-assessment-egress-build --target \
  test_egress_batch_policy test_egress_request_policy test_command_result_egress \
  test_command_fact_transport test_queue_recovery \
  CMakeFiles/edr_agent.dir/src/core/agent.c.o -j4
ctest --test-dir /tmp/edr-cache-assessment-egress-build \
  -R '^(egress_batch_policy|egress_request_policy|command_result_egress|command_fact_transport|queue_recovery_real_codec)$' \
  --output-on-failure
git diff --check
```

| Executed check | Result |
| --- | --- |
| Candidate retention focus | 8 test functions pass; real 1.00 s / user 0.08 s / sys 0.08 s |
| Candidate pressure focus | 5 test functions pass; real 0.60 s / user 0.17 s / sys 0.32 s |
| Complete candidate/cache executable | 120 calls to 119 distinct test functions on this build; exit 0; real 7.97 s / user 3.26 s / sys 2.26 s |
| Command state/result regression | 4/4 pass, 3.96 s |
| Real encoding/gate/recovery regression | 5/5 pass, 2.07 s |
| Agent health producer object | Compiles |
| Diff whitespace | Pass |

Raw candidate output is in
`/tmp/edr-evidence-phase3-candidate-tests/final-{build,focused,pressure,full}.txt`.
The frozen pre-integration binary and red result are `before-retirement` and
`before-retirement.txt` there. The before run fails because the retained young
group loses `low-severity-parent`; the after test checks exact two-way `EXCEPT`
equality of every surviving materialized artifact and the retained candidates,
not just a lower record count. The test spans legacy, partially migrated and
compact reference layouts. Unknown/pending owners, recent imports and future
windows remain present; retired groups leave no references or exclusive facts.
DELETE-trigger and COMMIT fault injection preserve full projections and counters.

Other final raw logs are `/tmp/edr-phase3-command-{build,tests}.log`,
`/tmp/edr-phase3-egress-{build,tests}.log` and
`/tmp/edr-phase3-agent-object-build.log`. Early development failures are not
counted as passes. They exposed held-work accounting, cursor starvation/refill,
independent-reference deletion and same-call post-context resurrection; focused
regressions exercise the fixes. Existing tests whose fixtures previously relied
on clearing unknown owners now verify protected bytes and capacity refusal, or
construct explicit new local groups when testing successful reclamation.

The complete suite also ran its existing synthetic migration/crash, SQLite busy,
query/lifecycle concurrency, command growth/concurrency, generation/PPID and
reopen checks. Its two near-full migration subtests observed peaks of 15,859,584
and 14,883,928 bytes against a 16 MiB fixture budget (4,099 rows / 68 batches / 392
ms and 3,203 rows / 52 batches / 306 ms). These measurements are not whole-Agent
physical maxima. New group retirement has DELETE/COMMIT failure rollback tests;
these must not be described as a native Windows power-loss test of the new path.
Maximum-width numeric retention accounting is 1,456 bytes within the existing
2,048-byte internal buffer, valid JSON with no raw evidence. The full status
consumer test uses the production Agent's existing 16 KiB buffer and keeps the
small-buffer truncated-JSON contract.

Independent in-memory SQLite probes provide narrower evidence:

| Query / invariant | Observed result |
| --- | --- |
| Entirely protected selector, 1k / 10k / 100k background candidates | Always 1,000 rows, zero eligible, 48,986 VM steps |
| PMFE active selection, 1k / 10k / 100k terminal rows | Always 64 rows, 596 VM steps |
| Unknown-generation miss before explicit partial index | 12,079 / 120,079 / 1,200,079 VM steps |
| Same miss with owned partial index | 42 VM steps at all sizes |
| Exact generation lookup | 57 VM steps at all sizes |
| Helper deletes one of two shared-fact groups | Deletes 1 candidate, 1 bundle, 2 refs and 1 exclusive fact; other group/shared fact survive |

Query probes use Python SQLite 3.51.0 and synthetic memory databases, not the
Windows SQLite build. Logs are in `/tmp/edr-evidence-phase3-20261015/`:
`pmfe-retention-index-probe.jsonl`, `pmfe-retention-index-forced-probe.jsonl`,
`bounded-selector-index-probe.jsonl` and `refill-cursor-sql-model.jsonl`.
The cursor model also checks a protected tail with refilled older records,
all-held bounded exit and continuation beyond a 5,000-record protected prefix;
it simplifies the C group validator and physical checks. The native pressure
regression independently exercises the actual refill/admission path.
The four corresponding `.py` files and a runner are retained beside the logs.
Reproduce with `python3 /tmp/edr-evidence-phase3-20261015/run-final-synthetic-probes.py`;
its final captured output is `final-synthetic-probes-summary.jsonl` in that
directory (15 results, all four subprocesses exit 0).

The standalone helper probe and ASan/UBSan run both pass; source/logs are
`/tmp/edr-context-retirement-probe.c`, `/tmp/edr-context-retirement-probe.log` and
`/tmp/edr-context-retirement-probe-sanitized.log`. Changed helper/probe sources
compiled with `-Wall -Wextra -Werror`; only existing vendor cJSON compilation
needed Apple's deprecated-`sprintf` warning exemption. Existing unused-function
and duplicate-library warnings in the larger build remain disclosed.

This evidence establishes the changed group-integrity and bounded-selection
contracts. It does not supply equal-load, before/after whole-Agent CPU/I/O,
write-amplification, investigation-time-range or native Windows acceptance.
Those are explicitly open release gates, not inferred from the reduced row
counts or the passing synthetic suite.

## 2026-10-15 second batch: retention identity and transactional queue accounting

This continues the first batch below on the same uncommitted development
baseline, `6bedb86bf9811bc304f4c97fdd62212ef437423f` / branch
`codex/rtq-result-delivery-pressure`. Existing first-batch changes are preserved.
No commit, deployment, live UTM access, production migration or real-cache
deletion is part of this batch. The evidence-diagnosis workflow is used to
separate implemented mechanisms from the remaining retention acceptance.

### Implemented state and owner contract

`queue_retention_metadata_ensure_locked` adds three columns without rewriting
payloads: `retention_class`, `local_retention_state`, and
`retention_policy_version`. Current producers set the class only on insertion:

| Creation class | Current writer | Retention policy |
| --- | --- | --- |
| 0, legacy/unclassified | Existing rows and older writers that omit the new columns | Version 0, protected and separately counted |
| 1, new local-v3 fact | `source_only_enqueue` local commit | Version 1, retain only |
| 2, new delivery record | `edr_storage_queue_enqueue`, remote-v2 source-only and deferred terminal handoff | Version 1, retain only; existing exact receipt ownership remains authoritative |
| 3, new recovery projection | `edr_storage_queue_recovery_apply` projection insertion | Version 1, retain only; its receipt releases its own delivery relationship |

These are immutable **creation classes**, independent of current delivery status.
A recovered original keeps its creation class. Recovery of an old row does not
promote it out of class 0. A `local_evidence` delivery status alone never proves
that a row is a disposable local-v3 fact.

All currently supported rows have `local_retention_state='retained'`. Here that
means payload is present and no local retirement has taken place; it does not
create an infinite local duty for every delivery copy. Existing exact ACK cleanup
of the corresponding delivery record still operates. Projection ACK does not
retire its original. The schema reserves the vocabulary `retirement_eligible`
and `retired`, but current guard triggers reject both: policy 1 authorizes no
local retirement. Class/policy mutation is also rejected. Unknown policy/state
on open fails with a diagnostic and preserves the database.

This deliberately does not introduce an age-only retirement candidate scanner.
The complete entity/parent/delta dependency index and bounded investigation pins
are not yet present. A future eligibility transition must check those owners,
pending delivery, journal and recovery lineage in the same transaction that
releases bytes. The added metadata alone does not prove those conditions.

### Accounting and admission changes

`queue_capacity_ledger_v1` contains exactly nine rows: the four event creation
classes, terminal journal, active deferred records, completed deferred records,
projection relationships and recovery metadata. SQL triggers update bytes and
row counts with each owning insert, growth/shrink, delete and rollback. The
ledger has no per-event tombstones. Startup and explicit recovery application
recalibrate it from actual owner tables in a writer transaction; malformed costs,
unsupported schema and missing ledger rows fail closed. Runtime missing-row
detection refuses admission instead of treating the absent category as zero.
Out-of-band DDL or manually changing the ledger to internally valid but false
numbers is not a supported writer: the nine-row read does not detect those
changes at runtime. Reopen reinstalls triggers and recalibrates from the owners.

`queue_capacity_admit_locked` now reads only these nine rows, inside the same
`BEGIN IMMEDIATE` transaction as the admitted write. Ordinary enqueue and deferred
retain have been moved into that boundary; ordinary durability remains NORMAL,
and the existing executor-owned FULL durability boundaries are preserved.
Startup calibration and some health, maintenance and recovery queries still scan
inventory. The bounded admission query is not a claim that every queue operation
is constant-time or that maintenance is fully sliced.

The existing `[offline].max_queue_size_mb` meaning and 512 MiB source default are
unchanged: it is a logical retained queue budget, separate from the evidence DB
and product-directory physical usage. Existing reserve derivation is reused;
there is no new percentage partition, database, configuration option or service.
Fixed ledger/schema/trigger storage is covered by DB/WAL/SHM physical reporting,
as with existing fixed schema and bounded receipt metadata. Per-record metadata
continues to use the existing fixed logical allowances. These allowances are not
measurements of exact allocated pages or a physical hard cap.

Two accounting corrections are explicit:

- Text costs use `length(CAST(value AS BLOB))`, matching producer UTF-8 byte
  lengths instead of SQLite character counts or its text NUL terminator behavior.
  Calibration can therefore report more logical usage for old non-ASCII or
  embedded-NUL identifiers, without changing their stored bytes.
- Journal state text receives a fixed 15-byte reservation covering the longest
  supported state, `outcome_unknown`; `pending_intent` is 14 bytes. The same cost
  is included before action precreation and in actual ledger accounting,
  preventing state transition growth from consuming unreserved bytes. Calibration
  increases an existing supported journal's charge by at most 10 bytes relative
  to its prior state-text charge. Unsupported oversized/NULL state costs fail
  closed. This changes no frozen intent/result frame.

Already over-budget legacy inventory remains present and can still block new
admission. This batch adds visibility, not an automatic legacy disposition.
The queue still shares its existing SQLite lock/WAL and disk fault domain.
Command JSONL owner reservation, the global physical guard, and evidence-store
class accounting remain separate unfinished work.

`queue_local_retention` adds a bounded numeric health object to the existing basic
and diagnostic profiles: class rows/bytes, journal/deferred/recovery bytes,
ledger availability, and `retirement_enabled:false`. The private shared serializer
has no identity, command, payload or user-controlled string fields. No new alert
projection, detail-upload route, permission or local-fact bulk upload is added.
Backend persistence/UI consumption of these new health fields is not yet verified.

### Migration and rollback boundary

Migration is additive. Legacy rows receive default class 0/policy 0/retained;
new columns are discovered before ALTER so partial additive schemas can resume.
Metadata guards and ledger reconstruction are transactional. Existing frozen
payload bytes, hashes, batch IDs, recovery ownership and process-instance bindings
are not rewritten. Metadata migration and ledger calibration are separate restartable
steps; failure of either prevents successful queue open rather than clearing rows.

For rollback, preserve the database and side metadata. The known previous binary
omits the new columns on insert, so new rows become protected class 0 and triggers
continue maintaining the ledger. Reopening with this version recalibrates it.
Do not drop side metadata or restore an old database copy over newly admitted
evidence. Downgrading code restores earlier admission defects and cannot recover
details previously refused. Arbitrary older/future schemas and operators that
replace rows are not supported rollback consumers.

SQLite replacement can skip implicit DELETE triggers when recursive triggers are
off. Identity guards therefore reject destructive replacement. The known older
recovery backfill is allowed only an exact immutable projection-tuple no-op; it
cannot overwrite receipt state, timestamps or hashes. This preserves its existing
`ON CONFLICT DO NOTHING` behavior without charging a second relation or fabricating
an ACK. Production rollout/rollback remains a plan requiring separate authorization.

### Validation and remaining closure

All databases are synthetic and final test execution uses temporary working
directories. The first batch's complete lifecycle inventory and remaining
implementation order below continue to apply; its statements about full-scan
admission describe that earlier batch, superseded for queue admission above.

The complete queue regression passed with exit 0. Its independent full-table test
oracle agrees with the nine-row production ledger after enqueue, local commit,
deferred handoff, journal freeze, state transition, growth/shrink, rollback, ACK,
dead-letter retention and reopen. It also checks:

- Legacy/partial-column upgrades keep exact frozen bytes, IDs, hashes and
  protected class 0, including recovery originals carrying `local_evidence`.
- Unsupported retirement or creation-class mutation, NULL/invalid/overflow costs
  and destructive identity replacement are rejected without losing the owner.
- A damaged ledger recalibrates on reopen; a missing category during operation
  makes accounting unavailable and blocks new admission.
- UTF-8 and embedded-NUL legacy identifiers are charged as stored bytes.
- Fixed-field health JSON parses, hides unavailable class counters, rejects a
  short output buffer and fits 1,024 bytes at maximum integer widths.
- The capacity-read query uses **53 SQLite VM steps** both before and after
  inserting 5,000 synthetic 1 KiB retained payloads. This measures only the
  capacity query, not whole enqueue CPU/I/O, triggers or maintenance.

Actual queue build command, from the Agent repository:

```sh
cc -std=c11 -D_DEFAULT_SOURCE -DEDR_HAVE_SQLITE=1 \
  -DEDR_STORAGE_QUEUE_TESTING=1 -Iinclude -Ithird_party/cjson \
  tests/test_storage_queue_sqlite.c src/storage/queue_sqlite.c \
  src/command/sha256.c src/core/time_util.c src/transport/report_events_ack.c \
  third_party/cjson/cJSON.c -lsqlite3 -lpthread \
  -o /tmp/edr-queue-phase2-ledger-tests
# Execution working directory: /tmp
/tmp/edr-queue-phase2-ledger-tests > /tmp/edr-queue-phase2-ledger-tests-final-v4.log 2>&1
```

Raw queue output: `/tmp/edr-queue-phase2-ledger-tests-final-v4.log`.
Injected failure diagnostics in that log are expected assertions, not ignored
test failures. Early development runs exposed and corrected a SQLite `GROUP BY`
constant being parsed as a column ordinal and a test expectation that incorrectly
treated released journal reservation bytes as permanently charged. Neither run
is counted as passing final validation.

The real encoding/gate/recovery group was rebuilt after the final source change:

```sh
cmake --build /tmp/edr-cache-assessment-egress-build --target \
  test_egress_batch_policy test_egress_request_policy test_command_result_egress \
  test_command_fact_transport test_queue_recovery \
  CMakeFiles/edr_agent.dir/src/core/agent.c.o -j4
ctest --test-dir /tmp/edr-cache-assessment-egress-build \
  -R '^(egress_batch_policy|egress_request_policy|command_result_egress|command_fact_transport|queue_recovery_real_codec)$' \
  --output-on-failure \
  --output-log /tmp/edr-evidence-phase2-20261015/egress-test-final.txt
git diff --check
```

Result: **5/5 passed**, 1.97 seconds. Build and test output are
`egress-build-final.txt` and `egress-test-final.txt` in
`/tmp/edr-evidence-phase2-20261015/`; the health producer object also compiled.
The added real recovery test covers raw and LZ4 original frames, verifies that
new projection rows are class 3 while the original class stays unchanged, and
checks that the parsed projection ACK removes only that delivery row. Original
bytes, class and logical cost remain; the projection receipt relation is retained.
The existing final egress gates remain active. The build uses the nonproduction
P0 IR stub described in the first-batch setup, not a native Windows release.

An independent rollback probe compiles both the actual HEAD queue implementation
and this implementation with their respective headers. It creates a new-format
fixture with a local original, an ACKed projection relationship and a journal;
the old implementation opens, reads, enqueues, commits local evidence and creates
a journal; the new implementation then reopens and recalibrates. Raw result:

```text
seed logical_bytes=134928 sends=0
old  logical_bytes=268833 sends=0
new  logical_bytes=268835 sends=0
frozen_events_relations_journal_equal=true
ledger=268835 independent_inventory=268835 PASS
```

The two-byte old/new difference is the two journal states changing from a
14-byte charge to the fixed 15-byte reservation. The two rows written by the old
binary are class 0, never inferred to be newly classifiable. Artifacts are in
`/tmp/edr-phase2-rollback-final-20261015/`: `raw_result.txt`, `run.py`,
`compile_commands.txt`, both source/header snapshots and `frozen_before.json`.
Actual execution was `python3 /tmp/edr-phase2-rollback-final-20261015/run.py`;
reproduction requires a fresh temporary fixture directory. The tested new queue
source SHA-256 is `60e48102e60dfc7bcbc3b11d60725dd40147ac9205c72db1be4714d2dcb0fcfe`.
The rollback probe uses codec/network stubs and a synthetic relationship, so it
does not establish real signed-request authorization or Windows downgrade safety.

The health serializer is behavior-tested and the producer compiles; a complete
maximal engine-health message through the deployed backend/UI is unverified.
Partial-schema fixtures model restartable migration steps but are not process
kill/power-loss tests. Whole-operation CPU/I/O, write amplification, startup lock
duration and physical migration peaks have not been benchmarked in this batch.

Automatic local retirement, selected-chain retention, indexed investigation
coverage, bounded pin exhaustion, sustainable rotation, global disk protection,
and native Windows crash/full-disk/long-reader behavior remain unimplemented or
unverified. No fixed number of days of useful investigation coverage is claimed.
This batch preserves existing accepted bytes and delivery relationships while
making their classification and logical cost explicit; it does not yet establish
that arbitrary sustained traffic can rotate safely within the configured budget.

## 2026-10-15 local evidence storage first batch (development only)

Scope: local development and disposable synthetic databases. No automatic Git
commit, deployment, UTM configuration change, live migration, or deletion of
existing endpoint evidence is authorized by this work. This document separates
implemented admission repairs from the remaining retention design. It does not
claim that the full retention system is complete.

### Baseline and evidence

Development baseline: `6bedb86bf9811bc304f4c97fdd62212ef437423f`, branch
`codex/rtq-result-delivery-pressure`, initially clean. It is ten commits after
`0ae3fb28e553223358db1a83ebd26432336af9e7` (46 files, +2336/-226), and one commit
after `3de0dc680c78c335f8ab6ba37eef0d0f5d8f46e2` (only the Windows release-gate
test, +3/-1).

The earlier read-only UTM observation identified running release `3.2.670`,
source `5072c2871bf49beaf05a9c51fc25f1ad62b8d605`, with installed executable
SHA-256 `e8536c45c45c26edf328102d43b4a46daba719947c011695ced796fe29fce418`.
The queue, evidence-cache, command-state, configuration, and direct-emission
source files matched the development baseline. This identifies the relevant
mechanisms; it does not establish that different detector versions produce the
same workload.

Observed on 2026-10-14 18:10–18:18 UTC:

- Queue: 62,104 strictly identified local-v3 rows, 71,392,885 payload bytes;
  42,721 were older than the configured 72 hours. Queue logical usage was about
  103.23 MiB of 512 MiB. This endpoint was **not** at the queue admission limit.
- Evidence cache: close to its separate 512 MiB target; compact references and
  allocated pages decreased during observation. The evidence cache does reclaim
  data. Its behavior must not be conflated with local-v3 queue retention.
- Command results: 2,148 rows, 680,340 detail bytes. This was not the dominant
  observed space consumer. The write-budget bypass is independently reproducible.
- Two databases plus sidecars used about 616 MiB, excluding command-state files,
  logs, upgrades, and other product files. The 512 MiB queue setting is not a
  product-directory physical cap.

These are bounded snapshots, not a passive workload benchmark or proof of the
cause of every endpoint failure. Diagnostic processes can themselves generate
events. No conclusion uses the 98,301-byte interface capacity as average event
size.

### Durable inventory and lifecycle ownership

The table covers the evidence pipeline and its execution/delivery owners. Trust
material, signed policy, updater rollback state, and executable files remain with
their existing owners; they are not evidence eviction candidates.

| Category and data | Actual writer / purpose | Delivery and dependency constraints | Current lifecycle and intended rule |
| --- | --- | --- | --- |
| A: recent candidate details, `p0_candidates` | `edr_local_evidence_cache_record_behavior` → candidate transaction; detection explanation and candidate lookup | Candidate IDs bind context references and bundles; severity alone cannot determine value | Current evidence TTL and oldest-first pressure eviction. Target: recent-detail tier, promoting selected chains before dependency-aware retirement |
| A/B: `context_facts`, legacy and compact context refs, fact/candidate key dictionaries | `evidence_context_store` writer, called by candidate/context persistence; shared before/after context | Shared facts must survive while any retained ref needs them; candidate and fact identities must remain resolvable | Existing ref expiry/eviction and orphan collection are reusable; target checks selection/pin/owner and performs ref/fact changes atomically |
| B: local-v3 `event_queue` facts | `edr_storage_queue_p0_source_only_commit_local` → `source_only_enqueue`; capability/source evidence | Exact local-v3 owner and reason required; local commit is not remote ACK; recovery rows can also use `local_evidence` | No automatic expiry today. First batch changes admission only. Target: independently classified retention with dependency-safe retirement |
| B: command facts and `p0_context_bundle` artifacts | `edr_local_evidence_cache_save_command_fact`, `insert_artifact_sqlite`; complete command/generation evidence and context | Command fact key includes endpoint/process generation; facts may be fuller than projected output | Existing artifact TTL/pressure rules; target content sharing and references must precede dependency-safe deletion. Existing frozen wires are never rewritten |
| A/E: `process_cache`, `file_evidence`, `network_ioc`, `registry_evidence` | Candidate transaction calls `upsert_process_sqlite`, `upsert_file_sqlite`, `upsert_network_sqlite`, `upsert_registry_sqlite`; lookup and summaries | Current process cache is not a historical process-generation registry; PID alone is insufficient for preserved chains | Current TTL and aggregate updates. Target preserves needed historical entity/generation definitions separately from replaceable lookup copies |
| C: necessary outbound `event_queue` records | `edr_storage_queue_enqueue` and remote-v2 source-only enqueue; immutable needed delivery | Exact receipt binds batch ID and payload; `pending`, `policy_held`, corrupt/unknown and unacknowledged owners do not imply safe retirement | Current retention/retry transitions may retain dead-letter payload. Target explicit delivery obligation and disposition, with a bounded quarantine; no status-only deletion |
| D: `enforcement_terminal_journal` | Terminal precreate/update APIs, called before/after direct action; durable intent and frozen result | Reserve before action; preserve intent, source, combined frame and true receipt relationships. `outcome_unknown` and `local_retained` are protected | Existing completion cleanup requires owner conditions; target accounts reservations and dependencies without changing frozen bytes or ACK semantics |
| D: `p0_deferred_match` | Retain/complete/fail/retry APIs from P0 deferred owner; unresolved matching/action retry | Pending/failed records protect their payload; completed records retain bounded dedup identity | Existing completed-payload release and metadata TTL; target retains the same safety boundary and charges metadata |
| D: `queue_meta`, recovery originals, `queue_projection_relations`, corruption latch | Queue open/recovery/projection/receipt transactions; loss and recovery ownership | Unknown legacy lineage stays protected. Projection ACK releases only that projection relation, not the original evidence | Target additive classification; unresolved historical data measured separately and never silently reclassified as disposable local-v3 |
| C/D: `delivery_receipts_v1` | Exact successful queue ACK transaction; bounded duplicate-delivery evidence | Not synthetic receipts for local retirement | Existing 1,024-row bound; keep finite receipt lifecycle separate from retirement statistics |
| D: PMFE follow-up artifacts | `edr_local_evidence_cache_pmfe_prepare` / bind / take / ACK APIs; asynchronous recovery and result ownership | Active association/result owner must survive; ordinary artifact cleanup exception already exists | Existing cap/lease/expiry and terminal-state rules remain authoritative; selection/pin must not bypass them |
| D: command JSONL, inbox, quarantine, upload outbox | `command_state_finish`, inbox APIs and existing upload-outbox owner; execution state, idempotency, authorized delivery | Successful durable final state prevents re-execution. ACK/expiry/authentication remain owner-specific | Not optional query copies. Current JSONL compaction target is not a hard byte cap. Needs separate owner budget and pre-action reservation work |
| E: `command_results` | `edr_local_evidence_cache_record_command_result`, after authoritative command-state append; local detailed copy | May retain unique pre-projection detail, so not generally reconstructible. It does not own execution or delivery | First batch checks writes and reports rejection; current TTL unchanged. Future pressure retirement requires local-value and investigation protection |
| E: evidence `metrics`, diagnostics and logs | `sqlite_flush_metrics` and existing diagnostic/log owners | No complete commands or raw facts in new health diagnostics | Existing metric TTL/log rotation; future disposition statistics aggregate by bounded reason/policy/time buckets, not unbounded per-row tombstones |
| Schema-only `event_cache`, `forensic_jobs` | Schema creation found; no current source writer/reader established in this audit | Not evidence that the feature is implemented or data reconstructible | Unknown historical rows remain protected until classified |

The in-memory hot ring and candidate windows are not durable history. Existing
candidate deduplication and shared context facts are the starting point; a second
parallel evidence architecture or a remote LLM retention decision is unnecessary.

### Independent retention and delivery contract (next stage)

Delivery state continues to express receipt obligations. Retention state will
express `retained`, `retirement_eligible`, or `retired`, plus policy version and
bounded reason. Legacy-unclassified is a protected classification, not an
eligibility shortcut. A true ACK may release a delivery edge; it cannot by itself
retire another local original. A normal local expiry never creates an ACK.

Before removing payload, the same write transaction must recheck record type and
owner, incomplete deliveries, frozen journals, recovery/projection lineage,
investigation pins, retained entities and process generations, and any decoding
baseline. Eligibility discovered by a scan is advisory until that recheck. Unknown
outcome and `policy_held` remain protected. SQLite foreign-key declarations alone
are insufficient where enforcement is not enabled; verify all writer paths and
explicit checks.

Use recent detailed retention plus selected longer-lived chains. Promotion must
include needed ordinary parents and earlier connections. Deduplication may merge
only equivalent identities/semantics, preserving count, first/last time and links.
Content sharing must retain an immutable hash and all active references; delta
encoding is deferred until baseline lifetime and decode tests exist. These changes
apply to new records; no recompression of old frozen frames.

An investigation pin must identify its authorized task, scope, expiry, byte cost,
and release condition. Pin capacity is finite and separately observable. Exhaustion
rejects/degrades the additional protection request explicitly; severity is never a
permanent pin. Selected evidence also needs an explicit bounded quota and expiry.
Neither tier promises fixed retention days for arbitrary load.

Successful retirement updates bounded aggregate reason/policy/time counters in
the same transaction. Per-record dispositions needed for query explanations need
a finite byte/age bound; after that bound, a query must report coverage unknown,
not infer that an event never happened. Detailed retrieval remains on the existing
authorized path; missing tenant/endpoint/task/purpose/time/field/byte/expiry
validation must be closed before exposing a new retrieval consumer.

### Budget semantics and first admission repairs

No configuration default changes in this batch:

- `[offline].max_queue_size_mb`: retained queue **logical** allocation, including
  frozen bodies, deferred records, recovery metadata and journal reservations.
  Source default remains 512 MiB, retention 72 hours. This does not cover the
  evidence database or the entire installation directory.
- `[offline].evidence_cache_max_size_mb`: separate evidence DB/WAL admission
  target. Source defaults are 128 MiB / 24 hours; the audited UTM overrides both
  stores to 512 MiB / 72 hours. Example configurations can differ.
- Existing terminal reserve derives a minimum from intent and two final frame
  bounds, with the existing fraction/cap; the source-only reserve derives from
  bounded retry slots. This batch reuses these rules and introduces no new fixed
  percentage partition. Their production sizing still needs workload validation.
- New local-v3 facts use ordinary queue admission, so they cannot consume the
  current critical reserves. Remote-v2 source-only behavior remains unchanged.
  Already over-limit data is preserved and can still prevent new admissions.
- Command-result copy failures must be visible independently from the authoritative
  command-state result. Capacity pressure cannot cause a completed side effect to
  be re-executed. Conversely, an authoritative append/flush failure must still
  fail and preserve recovery ownership.

The command copy repair uses SQLite active-page accounting (including indexes)
and the old row's UTF-8 byte length, rather than a per-write table sum. Under the
cache mutex and `BEGIN IMMEDIATE`, it checks the current DB+WAL guard, rejects
excess growth before writing, checks every binding, and rechecks actual live pages
before commit. Rejection rolls back the update and preserves the previous row.
No cleanup is invoked to make space for the copy. This is not yet a per-category
incremental ledger for every evidence writer. A current physical overage rejects
copies conservatively, including shrinking updates, until existing maintenance
recovers space.

The API returns stored, unavailable, capacity, storage or invalid outcomes.
Local status and diagnostic-profile health expose process-lifetime `written`,
`capacity_rejected` and `failed` counters; the basic health profile is unchanged.
The caller emits only numeric, exponentially sampled diagnostics for
copy failures and retains the durable command final state. Counter reset on
restart does not imply that previously rejected details were recovered. No
command identity or detail is added to these diagnostics.

Categories within each database still share its SQLite locks and WAL; the queue
and evidence databases already have separate WAL files but share the process and
disk failure domain. No new database is introduced. Full per-class accounting and startup
calibration are a later stage. Queue admission currently scans retained totals;
this batch does not claim the required per-event constant-time ledger.

Global physical protection is a separate pending contract: DB allocated pages,
indexes and freelist; WAL and SHM; transaction/rebuild temporary files; logs;
command state/inbox/outbox/quarantine; update downloads/staging/rollback assets;
and free disk must all be measured without double-counting. It needs a disk
watermark and owner-specific refusal/recovery actions. Optional evidence admits
must stop before protected action durability is lost. A logical budget is not a
physical guarantee, and a full-disk `VACUUM` is not a recovery policy.

### Implementation order and migration/rollback

1. This batch: verified inventory, ordinary local-v3 admission, command-result
   copy budget and caller diagnostics, isolated regressions and egress tests.
2. Add independent retention metadata for new records and startup-calibrated,
   transactional class ledgers. Audit every growth/shrink/delete/rollback path.
   Unknown old rows receive protected classification and explicit usage metrics.
3. Add value selection, dependency closure and bounded pins using existing facts,
   refs, candidate deduplication and process-instance identities. Build indexed
   local query coverage and explicit missing-evidence reasons before retirement.
4. Enable sliced, same-transaction retirement only after concurrent query/export,
   new projection, ACK and crash/reopen tests prove reference and owner safety.
   Validate unique/duplicate/high-severity storms and sustainable evidence value,
   not only lower row counts. No pressure-triggered bulk upload.
5. Close command-owner reservations, global physical protection and scoped retrieval
   gaps; run native Windows and real encoded egress acceptance before deployment.

The first batch performs no evidence schema migration or payload rewrite. Local
rollback restores the previous code and rebuilds; it cannot recover evidence
never admitted by either version. A rollback restores the old admission defects
and is not an operational pressure remedy. No live rollback is performed here.

Future metadata migrations must be additive, deterministic and restart-safe.
Do not alter hashes, batch IDs, owner/lineage or parent-generation bindings.
Rollback readers must tolerate new side metadata without deleting it. If an old
consumer cannot safely preserve the metadata, block downgrade with a precise
compatibility diagnosis. Production migration/deletion remains separately
authorized; unclassifiable legacy bytes may keep the store over budget indefinitely
until an explicit owner-safe disposition is chosen.

### Validation record

Local raw logs and disposable databases are kept outside the repository under
`/tmp/edr-evidence-first-batch-20261015/`. They contain only synthetic data. The
initial queue reproduction compiles real queue/receipt code with transport stubs;
the evidence reproduction uses the real cache/SQLite and existing test clock,
resource and P0 IR stubs.

Baseline rerun at the SHA above, 1 MiB per store:

```text
queue: 7 x 131072-byte local-v3, used=921200, terminal20=5003 (QUEUE_FULL),
       journal_precreate=0 (ERROR), local_after_reopen=7, sends=0
command: 1000 x 2048-byte details, after maintenance rows=1000,
         DB=4296704 WAL=0 SHM=32768 physical=4329472, dropped=0
command: expand one existing detail to65536 + four concurrent writers x250,
         rows=2000 physical=9946864, dropped=0
```

`/usr/bin/time -lp` reported queue 1.07 s wall / 0.01 s user / 0.01 s system and
command 0.15 s / 0.03 s / 0.07 s, but its additional kernel metrics were denied by
the host sandbox. These microbenchmarks do not establish workload throughput,
write amplification, I/O cost or an effective investigation window.

Post-change commands, executed from the Agent directory unless otherwise noted:

```sh
cc -std=c11 -D_DEFAULT_SOURCE -DEDR_HAVE_SQLITE=1 \
  -DEDR_STORAGE_QUEUE_TESTING=1 -Iinclude -Ithird_party/cjson \
  tests/test_storage_queue_sqlite.c src/storage/queue_sqlite.c \
  src/command/sha256.c src/core/time_util.c src/transport/report_events_ack.c \
  third_party/cjson/cJSON.c -lsqlite3 -lpthread \
  -o /tmp/edr-queue-first-batch-20261015/test_storage_queue_sqlite
# Executed with /tmp/edr-queue-first-batch-20261015 as working directory:
/tmp/edr-queue-first-batch-20261015/test_storage_queue_sqlite

cmake --build /private/tmp/edr-parent-dup-recheck-20261014/build --target \
  test_command_inbox test_command_process test_command_upload_outbox \
  test_command_result_compaction -j4
cmake --build /private/tmp/edr-parent-dup-recheck-20261014/build --target \
  test_local_evidence_cache_candidate -j4
ctest --test-dir /private/tmp/edr-parent-dup-recheck-20261014/build \
  -R '^(local_evidence_cache_candidate|command_inbox_persistence|command_process_identity_and_receipts|command_upload_outbox_recovery|command_result_compaction)$' \
  --output-on-failure --output-log /tmp/edr-evidence-first-batch-20261015/command-budget-tests.txt

cmake --build /tmp/edr-cache-assessment-egress-build --target \
  test_egress_batch_policy test_egress_request_policy test_command_result_egress \
  test_command_fact_transport test_queue_recovery -j4
ctest --test-dir /tmp/edr-cache-assessment-egress-build \
  -R '^(egress_batch_policy|egress_request_policy|command_result_egress|command_fact_transport|queue_recovery_real_codec)$' \
  --output-on-failure
git diff --check
```

The two existing temporary CMake builds use the same source tree, a nonproduction
P0 IR test stub, and production encoding/gate code. The egress build was configured
with `EDR_BUILD_TESTS=ON`, `EDR_P0_RULE_IR_ALLOW_TEST_STUB=ON`,
`EDR_REQUIRE_PCRE2=OFF`, `EDR_REQUIRE_YARA=OFF`, `EDR_WITH_YARA=OFF`,
`EDR_REQUIRE_SQLITE=ON`, `EDR_WITH_HTTP2_CURL=OFF`,
`EDR_WITH_INGEST_HTTPS_OPENSSL=ON`, `OPENSSL_ROOT_DIR=/opt/homebrew/opt/openssl@3`,
`EDR_BUILD_AVE_SHARED_LIB=OFF`, `EDR_WITH_FORENSIC_COLLECTOR=ON` and
`EDR_WITH_ZSTD=ON`, using Ninja and Debug. This is not a Windows release build.

Results: queue suite exit 0; command/cache group **5/5 passed** (8.15 s);
encoding/gate/recovery group **5/5 passed** (2.95 s); diff whitespace check passed.
Raw suite logs: `/tmp/edr-queue-first-batch-20261015/test-result.log`,
`command-budget-tests.txt` and `egress-test.txt` in the first-batch temporary
directory. Existing compiler warnings about test signedness, unused helper and
duplicate `-lm` were not treated as new defects or suppressed.

The queue regression exactly fills ordinary capacity before admitting the
20-byte terminal and a journal. It then fills critical capacity, refuses a new
journal, and successfully freezes the previously reserved result. All original
local bytes survive age, maintenance and reopen, without local sends or receipts.
Lowering a limit preserves 1,315,980 bytes of existing inventory and explicitly
rejects new local facts. The queue suite uses semantic/transport stubs; the five
separate egress/recovery tests exercise real serialization, final request gates,
long command preservation and immutable recovery behavior.

The real cache test covers serial and four-thread concurrent writes with both
successful and rejected admissions, 2 MiB insert/update refusals without physical
growth, a 64-to-128 KiB rejected expansion near capacity, shrinking updates,
UTF-8 byte preservation, reopen, SQLite busy, and commit failure rollback. The
command-inbox test uses a cache refusal stub to verify the real command-state
owner still yields duplicate-final rather than repeat execution. This is a
consumer contract test, not a combined live cache/command/remote-service test.
SQL binding failures are checked by the implementation; NOMEM/TOOBIG were not
fault-injected and are not counted as tested failures.

A repeatable same-input comparison submits twelve 128 KiB local facts plus the
same terminal/journal request; the command comparison submits 1,000 x 2 KiB,
maintenance/reopen, one 64 KiB update and four writers x 250 x 2 KiB. Each binary
exited 0. Raw measurements are `baseline-queue-comparison.txt`,
`after-queue-comparison.txt`, `baseline-command-comparison.txt` and
`after-command-comparison.txt` in the temporary directory. The probe sources and
command compilation arguments are saved there too.

| Measurement | Baseline | First batch |
| --- | ---: | ---: |
| Queue local 128 KiB admissions / 12 requests | 7 | 3 |
| Queue local bytes charged before terminal | 921,200 | 394,800 |
| 20-byte terminal / journal precreate | both refused | both admitted |
| Queue local records after maintenance/reopen | 7 | 3 |
| Queue DB+WAL+SHM at final sample | 1,175,552 | 651,264 |
| Command rows after first 1,000 requests | 1,000 | 44 (956 explicit refusals) |
| Command physical bytes after maintenance | 4,329,472 | 376,832 |
| Command rows after update and concurrent requests | 2,000 | 75 |
| Command final DB+WAL+SHM | 9,955,152 | 1,093,744 |
| Queue wall / user / system seconds | 0.737 / 0.012 / 0.017 | 0.697 / 0.008 / 0.008 |
| Command wall / user / system seconds | 0.130 / 0.027 / 0.057 | 0.787 / 0.014 / 0.036 |

The repeat uses direct subprocess exit status and child CPU accounting because
the earlier `time -lp` wrapper itself returned an error for unavailable kernel
statistics. Concurrent physical page allocation can vary slightly between runs.
These are single synthetic runs, not statistical throughput or I/O benchmarks.
The smaller store comes partly from earlier explicit refusal, not improved
investigative coverage; the command probe's wall time increased. At its peak
sample the command DB+WAL was 1,062,032 bytes, already above 1,048,576; SHM adds
32,768. Preflight plus bounded writes does **not** provide a physical hard cap.

No normal outbound field, endpoint, permission or data selector was expanded.
The local-v3 probe observes zero local payload sends; its one post-change send
belongs to the newly admissible terminal. Real codec/gate tests remain necessary
because the queue probe itself uses transport and semantic stubs. Backend storage,
investigation UI consumers and deployed Windows behavior are not verified here.

Unrun acceptance remains unrun: long-running value/chain retention, investigation
pin exhaustion, reclamation concurrency/crash migration, true full disk and
Windows long-reader/antivirus/ACL behavior. Closing those requires isolated native
Windows fixtures, bounded fault injection, exact immutable byte/identity checks,
and same-input before/after measurements of coverage, chain completeness,
physical peaks, CPU/I/O and write amplification. Current UTM data is not a test
target and no production validation is implied.

## Earlier cache reliability work (historical)

Latest result: the single Windows ARM64 UTM endpoint now runs `3.2.591`.
See [591 deployment and runtime evaluation](#2026-10-04-agent-591-deployment-and-runtime-evaluation)
for the completed checks, the retained installer policy-probe warning, and the
remaining verification limits. Earlier pending statements below record prior phases.

Baseline: `8e1e591229c2d83fbbfbf604c95e18e544a77af3` (tested release baseline:
`f708d6bd7a2ee1eb7be26cb593a4b79957a9746b`). The intervening change only
limits evidence-cache page reclamation per preprocess turn.

Initial scope: local code changes and isolated regression tests. No cloud deployment,
production data changes, or changes to endpoint protection were performed during remediation.
Windows-native installation, power loss and live backend acceptance require
separate environment verification. User-supplied Windows observations remain
historical evidence, not results of these local tests.

Order: R04, R02, R03, R08, R05, R06, R01, R07.

| Item | Change and acceptance | Verification |
| --- | --- | --- |
| R04 | Atomic primary + LKG persistence; preserve parsed local fields and never serialize runtime credentials. Persist policy identity and use its sequence as an additional rollback floor. | Local Agent build; config restart/LKG/long-string/secret/signature-override regression; installer config and remote status contracts passed. |
| R02 | Unconfigured polling only performs normal retention maintenance; event and terminal retry counters require an attempted send. | SQLite contract passed: severities 0/1/2 remain pending with zero attempts/retries across reopen, then acknowledge after configuration; terminal frames and budget deferral also covered. |
| R03 | Durable exponential backoff (1–300 seconds); every eighth event selection uses oldest eligible ID. Terminal journals defer failed rows using persisted error/time/counters. | SQLite contract: legacy schema upgrade and reopen, poison severity-2 retained, lower priority progresses within eight selections, independent journals progress. |
| R08 | Versioned whole-batch receipt binds endpoint, batch ID and SHA-256. Backend rejects volatile-only async operation; any alert persistence failure retries. | Agent receipt + SQLite response-loss tests; Go partial-failure/idempotency tests; isolated MySQL worker and actual server restart preserve acknowledged payload. |
| R05 | Event batch-ID/payload allocation failures and SQLite NOMEM defer selection without retry consumption or corruption disposition; terminal selection failures no longer increment send retries. | SQLite fault injection passed for both allocations at severities 0/1/2, exact payload replay after recovery, all three terminal allocations, and existing real corruption isolation cases. |
| R06 | Charge every retained event state to logical admission; report nonpending bytes and DB/WAL/SHM physical usage; run TTL cleanup even while transport is deferred. | Agent build, storage_queue_sqlite_contract and local_evidence_cache_candidate passed, including pinned-WAL visibility and circuit-open retention. |
| R01 | Always regenerate a timestamped presence snapshot; distinguish missing/stopped/unknown and the installed image path. Installer UI consumes current stage outcomes; bootstrap history is separate. | Portable classification, packaging/headless contracts and MinGW Windows worker compile/link passed. Native Windows/PowerShell behavior test registered in the Windows release gate, not executed on this Mac. |
| R07 | Retain aggregate counters; persist disjoint ordinary dispositions and typed candidate/context failure counters in the existing metrics table. Basic and diagnostic health share these definitions. | Cache regression passed: all four dispositions, atomic metric rollback/retry/reopen, real manifest allocation failure, SQL commit failure, quota/capacity refusal and invalid UTF-8. |

## R04 authority and limits

The primary TOML is the durable effective configuration. A verified remote update
changes only the fields already owned by remote policy; other parsed values are
retained, including unknown tables, certificate references, signing controls,
retention settings and independent rules. Comments/formatting are normalized.
LKG is an atomic copy of that complete primary. A persistence error is reported
and retried without an applied acknowledgement; the live policy can already be
active. If both primary and LKG are invalid, a valid local recovery source must
be restored before acknowledging a remote repair.

The persisted policy sequence supplements the existing separate anti-rollback
state. Environment-enforced signing remains stronger than the file setting.
Tests execute the real parser, serializer and atomic copy on macOS. Native
Windows ACL/replace behavior and abrupt-power-loss durability are not proven by
these tests. The local build uses the existing P0 rule test stub and does not
represent production Windows detector validation.

R02 retry_count means a failed transport submission while not locally deferred;
it is not a count of HTTP requests (the transport can reject locally or retry
internally). Unconfigured and budget/circuit-deferred states do not consume that
budget. Existing counters are retained for compatibility; historical inflated
values are not silently reset because genuine failures cannot be distinguished.

R03 scheduling: priority applies among due rows. A failed event becomes due after
1, 2, 4, ... seconds, capped at 300 seconds. Reopen preserves the deadline;
clock rollback beyond the cap permits a fresh attempt. A fair selection after
seven priority selections serves the oldest eligible ID. With transport available,
one poison source cannot monopolize subsequent polls. End-to-end latency still
depends on HTTP timeout, circuit backoff and the number of older eligible rows.
A non-acknowledgement is retained/retried under the existing severity policy;
no permanent HTTP rejection is interpreted as permission to delete protected
source evidence. Backend contract rejection handling is covered under R08.

## R08 receipt contract and rollout

Deploy the backend before these clients. Responses retain the existing envelope
and add `data.ack` version 1: `state` is `durable` after database queue insertion,
or `processed` after complete synchronous processing; endpoint ID, batch ID and
SHA-256 bind the decoded BAT1 bytes. The client requires the receipt and business
acceptance before deleting local pending data. Older servers without this receipt
will leave new clients retrying with a visible receipt error. No insecure fallback
or interpretation of arbitrary HTTP 2xx remains. Synchronous invalid-frame batches
return 422 even when valid frames persisted; asynchronous workers retain rejected
payloads in quarantine. A durable receipt transfers ownership of the original
bytes, not a promise that every frame will create an alert.

Validation used the production Agent queue/receipt parser with injected transport
outcomes; production Go handlers/repos with a fault-injecting SQL driver; and a
localhost-only disposable MySQL 8.4 container. The real DB was restarted between
seed and verify invocations: replay retained the same job identity and exact
payload, and a worker failure retained its bytes. The container and its anonymous
volume were removed. This does not establish end-to-end exactly-once effects or
power-loss guarantees of a deployed database.

Backend MySQL validation used an isolated snapshot of root
`980e414e4306740de3fd548ae26729a54e94c66d` plus this task's handler changes.
Final handler integration also passed against root `4f9d6cc7` (the concurrent
source-identity change), with the shared SQL fixture updated to read/update its
stored source rows. Receipt retry assertions now verify both alert and source-row
cardinality; original command-fact persistence, invalid-frame quarantine and
projection assertions remain intact.

Existing `TestReportEventBatchClaimFencingMySQL` could not execute migration
000157 through its SQL-driver harness because the migration contains mysql-client
`DELIMITER` commands. Claim-fencing unit tests passed; that separate migration
harness remains a validation gap. The real queue/worker/restart tests described
above passed in the disposable MySQL instance.

## R06 capacity and retention contract

`max_queue_size_mb` now bounds estimated retained logical record allocation,
including dead-letter/corrupt payloads, journal reservations and deferred records.
Changing a record status no longer creates free admission budget. On upgrade,
already retained records can exceed the configured budget; they are preserved,
new admissions receive a counted capacity refusal, and existing deliveries continue.
`retained_nonpending_bytes` explains this usage. Physical DB/WAL/SHM totals are
reported separately; SQLite free pages and a reader-pinned WAL can exceed the
logical limit even with zero pending records. No physical file hard limit is
claimed or silently imposed by deleting unacknowledged evidence. A strict physical
quota requires an explicit storage/deployment policy and remains outside this change.

| Data/state | Retention disposition |
| --- | --- |
| Ordinary event rows | Removed after configured age, including ordinary dead letters |
| Severity 1 pending | Moves to retained dead letter at TTL or retry exhaustion |
| Severity 2 pending/corrupt | No TTL/retry deletion; valid pending payload waits for ACK |
| Completed terminal/deferred rows | Removed by the existing bounded maintenance owner after retention |
| Unresolved/failed terminal/deferred rows | Retained and charged; no automatic evidence deletion |
| Evidence cache | Its own TTL/capacity policy; DB+WAL target, now with SHM/total diagnostics |

TTL is an eligibility rule, not a promise that every event is retained for exactly
that duration or that offline backlog will later be fully delivered. Capacity
refusal and ordinary retention eviction have separate counters. This change does
not invent an automatic archive/purge destination for unresolved audit evidence.

## R01 current checks and installation history

`install_health_report.json` remains bootstrap installation history. The native
worker always generates a new `install_runtime_health.json` (Inno path), with
check ID, installation-run ID, UTC time, worker version, individual probe states
and Win32 errors. It checks the configured installation's actual process image
path and requires a running service when service mode is selected. Missing
files/services, stopped services and access/query errors are distinct. Writes
are checked and replaced atomically; nonhealthy checks return nonzero.

The PowerShell verifier records its own check/run IDs and Agent version, requires
actual running states and image identity, and never consults historical success
to determine health. Unknown and warning states cannot return a successful
verification exit code. Inno clears only previous current-check reports and bases
its finished heading on the two current stage exit codes. A report is a snapshot
at installation, not continuing monitoring or proof of detector/TLS/backend
health; capability health is explicitly unknown.

The portable decision tests cover individual probe absence and query failure,
service stopped/pending and service-optional modes. The complete native worker
compiled and linked for Windows with MinGW `-Wall -Wextra -Werror`. The registered
Windows test executes the native worker against an isolated absent runtime, then
executes the actual PowerShell verifier with OS-query fixtures for running,
stopped, missing, unknown, unrelated same-name processes and removed files. It
never modifies host services/tasks. PowerShell, Inno compilation and real Windows
API execution are unavailable on this Mac and remain required release validation.

## R07 metric definitions and reconciliation

The existing `file_drops`, `registry_drops`, `network_drops`, `other_drops` names
remain compatible. Each counts a `record_behavior` invocation that did not request
candidate or context persistence. Exactly one reason is added to the same minute /
endpoint metric transaction:

| Reason | Meaning and remaining evidence |
| --- | --- |
| `ordinary_policy_filtered` | Existing low-value noise policy matched; this cache does not retain the raw record |
| `ordinary_pressure_skipped` | Resource throttle skipped an ordinary record with no active candidate/context request |
| `ordinary_coalesced` | Record contributed to the existing bounded aggregate; summary emission has its own threshold/lifetime |
| `ordinary_hot_ring_only` | Record captured in the bounded memory ring; related future candidates may promote its context |

Candidate/context failures are separate persistence operations. Each has one
reason: no database, capacity refusal, write budget refusal, resource allocation,
invalid content, storage operation failure, or unclassified failure. Ambiguous
serialization failures remain explicitly unclassified rather than being called
corruption or OOM. Candidate write-budget refusal remains zero because that path
is exempt. Failed post-context fanout counts one operation even if it would have
created several references. A committed candidate can coexist with a later failed
context operation. The previously uncounted no-database context branch now
increments `records_dropped` and its explicit reason.

Within one cache lifecycle, after each completed call (before counter overflow):

- `records_skipped = sum(legacy classified drops) = sum(ordinary reasons)`.
- `candidate_rejected = sum(candidate failure reasons)`.
- `records_dropped = candidate_rejected + sum(context failure reasons)`.
- `candidate_requests = records_written + candidate_rejected`; `records_written`
  means successful candidate insert/update transactions, not unique evidence rows.

Reuse, first-admission attempts and first-admission successes are additional
views; they do not form a separate conservation equation across replay/update
failures. The old header comment claiming that equality has been corrected.
These relations start at this module's input boundary and cannot account for
collector filtering, upstream losses, command-result mirrors or later eviction.

Health counters have current-process scope. Durable metric rows accumulate by
minute/endpoint, share the existing transactional committed watermark, and retain
the existing TTL. No schema migration/table or background worker was added. The
fixed 180 metric slots grow by about 51 KiB. Metric failure/retention and
`metric_unrecorded` remain visible; an ordinary event's type/reason pair counts
only once when reporting uncommitted diagnostic observations at close.

Older rows have no reason labels. Reconcile persisted type/reason totals only in
buckets wholly produced by the new version, after pending metrics commit. No
historical backfill or inference about the value of the supplied 4,336 classified
observations is made. Both basic and diagnostic health expose the same accounting
object; the diagnostic buffer was enlarged so the new fields do not turn a normal
report into a truncated fragment.

## Final local verification

Agent build and these 10 CTests passed together on the final implementation:
`config_fingerprint`, `remote_config_status_contract`,
`python_installer_config_contract`, `storage_queue_sqlite_contract`,
`local_evidence_cache_candidate`, `report_events_ack_contract`,
`installer_runtime_health_classification`, `http_retry_contract`,
`windows_headless_runtime_contract`, `agent_update_packaging_contract`.
The cache test retains two pre-existing signed/unsigned fixture warnings; the
Windows installer worker compiled/linked with warnings treated as errors.

Final Go handler checks passed for receipts, partial alert failure/retry,
async disposition, storage failures, batch finalization, command-fact persistence
and projection, invalid-frame quarantine, provenance and alert cardinality.
These complement the earlier isolated MySQL worker and real server restart tests.
`git diff --check` passed in the Agent and parent repository.

Release order: deploy the backend receipt contract before these clients. Older
backends without the receipt cause clients to retain and retry batches. No cloud
host, production database or endpoint protection setting was changed. Windows
PowerShell/Inno/native execution, production detector behavior, deployed-server
acceptance and sudden power loss remain explicitly unverified.


## 2026-10-02 rollout in progress

The user authorized deployment in backend-before-client order. The local API and
independent worker were upgraded through their existing launchd and Screen owners.
Both use the binary built from root `c957a670`, SHA-256
`165fc05a195c04a35f13be3fd13a9d558b373c899c6eebe687df2df4c2381f06`.
Old binary, launch configuration and local address configuration are retained in
the ignored, restricted `artifacts/cache-upgrade-20261002/rollback/` directory.

Preflight found that the host network had changed while the running API retained
the previous bind address. Local address configuration and the worker public URL
were updated to the active interface; the existing frontend owner reloaded its
matching API/WS addresses. The existing certificate covers the active address;
CA and hostname verification and API/worker `/ready` returned HTTP 200. API PID
95744 and worker PID 96074 were bound to the installed executable; frontend PID
96230 returned HTTP 200. The binary embeds `vcs.modified=true` because the root
has an unrelated untracked signing directory; tracked backend source was clean.

A controlled authenticated empty-BAT1 probe returned HTTP 202 twice with version-1
`durable` receipts, the exact submitted payload hash, the same job ID, and a
duplicate flag on replay. A separate read-only MySQL query found one durable row
with the exact original bytes; the worker rejected the empty batch as `dead` and
retained those bytes. No endpoint event rows were created. This proves deployed
receipt binding, duplicate-job identity and rejected-payload retention for this
probe; normal event delivery still requires the Windows upgrade verification.
The Windows upgrade remains pending. UTM guest execution and file reads returned RPC timeouts,
including after the user reported normal restart. A concurrent task also owns
network/release work for this guest; coordination was requested. No client setup
has been launched by this task.

Existing candidate run 36957844115 targets Agent `8c066365` / `3.2.584`; its AMD64
job failed at release-gate dependency verification. This task cancelled its own
duplicate pending run 36958055306. The native failure and local self-test show
missing expectations for the added health/receipt tests; the fixture also needs
to register the shared installer executable once. The corrective self-test work
retains all production gate labels and adds explicit failure-blocking assertions.
The local 19-test gate self-check completed with 18 passes and one failure in
the host-only Windows-SDK declaration fixture. The fixture lacked `WINAPI` and
`CreateThread`, which the already existing sliced-cache regression uses. Adding
those declarations made the failed SQLite-enabled Windows-branch compile probe
pass in a separate rerun. All 19 self-check cases therefore have passing results;
this is not a native Windows run. The added injected failures prove that health
and receipt failures block the applicable release labels. Native candidate
rebuild, installation and normal event delivery remain pending coordination
with the concurrent rollout task and restoration of the guest control channel.

## 2026-10-02 Windows upgrade acceptance

### Artifact and execution boundary

The tested artifact is `win_3.2.589`, built from Agent
`03d78b39b2c4f180b6acf41390e45946a2996b53` by
[run 37014901459](https://github.com/qiuxinliang/edr-agent/actions/runs/37014901459).
All seven jobs passed. AMD64 and ARM64 each passed 71/71 native CTests and the
actual Setup upgrade/rollback/uninstall and native runtime lifecycle gates,
using the published `win_3.2.583` baseline.

Only the ARM64 UTM endpoint was upgraded in this phase. The Setup SHA-256 is
`809e44b086d492b9f43beb3eabd5ba749880234bb8a4005465e0dd781ba1d3c6`;
the installed FDSensor SHA-256 is
`136f0eb3fac875eb047dfc1df74782ea695870d034a626216d93c53d852cf81f`.
The verified 583 rollback installer, runtime, configuration, task definition and
stopped cache copies remain in an ACL-restricted guest directory. Host diagnostic
artifacts and configuration copies are private and ignored by Git.

Exclusive guest ownership was handed over before execution. The original 583
process, PID 1652 / creation FILETIME `134354182747581310`, received the normal
console shutdown signal and exited with code 0 in 2.203 seconds. No forced
termination was used. Both SQLite databases were copied after exit and their
source/copy hashes matched; WAL and SHM were absent after the normal close.
Setup ran once, from 14:55:47 UTC, and returned 0. No rollback was used.

The launch RPC timed out before returning its receipt. Read-only job state
confirmed that the original job had advanced, so the command was not replayed.
The new scheduled-task process, PID 9688 / creation FILETIME
`134354265902246381`, started at 14:56:30.224 UTC. At 15:08:49.566 UTC the same
process remained Running, with the expected binary and 739.342 seconds of
uptime. The CA, final primary/LKG hashes and independent sequence remained
unchanged throughout that observation.

### Observed results

| Area | Result and scope |
| --- | --- |
| R01 current health | Both reports were generated at 14:56:33 UTC, with distinct check IDs, the same installation run ID `20261002225551341`, and version 589. Native presence was `ok`: config/binary present, process running, service missing but not required for scheduled-task mode. Capability health remained `unknown`. The policy probe correctly retained `warning`; see below. |
| R04 configuration | The verified remote policy identity was persisted in the complete primary; primary and LKG had identical bytes, SHA-256 `3b1db8ad836ec31c011e6363711aee6e580dfdd402ba56e7cad11b9878e9013f`. Typed local fields and non-policy table presence were preserved, with no existing owned field removed. Both snapshots passed the candidate's native `--config-test`. The separate anti-rollback state remained 524; TOML version/hash/sequence matched v524 and the endpoint's applied policy report. |
| Cache preservation | All 20 selected pre-upgrade candidate rows and their complete reference/fact sets had identical typed-value hashes after upgrade. This proves preservation of those selected rows and sets, not all cache contents. |
| SQLite structure | `quick_check=ok` for both stopped database copies and both live upgraded databases. Checks ran on a separate working copy of the frozen evidence; all original frozen hashes remained unchanged. Structure checks do not establish business completeness or remote durability. |
| R07 accounting | Basic health exposed `p0_acceptance.evidence_cache.accounting` with current-process scope and explicit units. All seven candidate-failure and seven context-failure counters were present and zero. Ordinary coalescing, hot-ring-only storage, policy filtering and pressure skipping had separate nonzero counts; they are not counts of lost important evidence. |
| R08 normal delivery | Two post-upgrade snapshots found 20 ordinary 589 batches with matching endpoint/batch/SHA-256 in durable jobs and accepted batch records. Jobs were `done`. Three selected batches also had 1, 2 and 1 persisted endpoint-event rows, matching their accepted counts. This does not prove exactly-once effects or every downstream consumer. |
| Observation | Backend health reported version 589 and PID 9688, online state and connected control stream. Between the two snapshots, successful report-events submissions grew from 403 to 564 while failure count stayed 2. Final health reported no pending offline rows. Instantaneous client SQLite snapshots had one pending row with retry count 0; these are different observation times, not a contradiction or a conservation equation. |

At 15:10 UTC the existing API PID 21204 on `192.168.3.101:8080`, worker PID
21598 on `127.0.0.1:8081`, and frontend PID 21763 on port 5173 remained live.
API and worker readiness returned 200 with CA and hostname verification, and the
frontend returned 200. The backend receipt binary was deployed before this client;
concurrent backend edits were not rebuilt or deployed during this acceptance.
Cross-machine timestamps can differ; process identity, version and independently
captured receipts bind these observations, rather than ordering guest and database
timestamps as if they shared an exact clock.

### Retained warning and corrected diagnostic failures

The installer's PowerShell runtime-policy probe returned HTTP 401. In the tested
script it sends endpoint/tenant headers without bearer authentication, while the
backend route requires authentication. This request also existed in 583. Version
589 correctly aggregates its warning into overall `warning` and exit 2; the
noncritical installer stage retains the warning while Setup completes. The native
Agent has a separate authenticated transport, and its applied/verified v524 report
and persisted configuration were observed separately. Neither the PowerShell
warning nor native presence was relabeled as full capability success. A later
probe fix should reuse native authentication or an authenticated application
receipt without placing credentials in installer command lines or stage logs.

Three diagnostic failures are preserved with their successful corrections:

- The first cache query assumed the new `event_queue.next_retry_at` column on
  583. The corrected read-only probe inspected `PRAGMA table_info`, explicitly
  reported the missing column, and omitted unavailable metrics instead of using
  zero. The upgraded schema then included the column.
- The first acceptance script compared a UTC file timestamp with a local
  `DateTime.Parse` result and incorrectly marked fresh reports stale. A separate
  receipt normalized both to UTC and verified both current reports. Explicit
  UTF-8 reading also avoided PowerShell's legacy-codepage decoding of Chinese
  warning text. The original failed receipt remains intact.
- The first integrity probe was interrupted by its eight-second SQLite progress
  deadline (`SQLITE_INTERRUPT`, code 9). A bounded rerun allowed 30 seconds per
  statement. All four checks completed; the longest took 8.179 seconds. This was
  a diagnostic timeout, not evidence of corruption.

### Remaining limits and evidence

This phase did not inject disk exhaustion, power loss, memory failure, permanent
backend rejection, signature-enforcement overrides, offline restart, or damaged
primary/LKG recovery into the UTM endpoint. Earlier isolated regression evidence
for those covered code paths remains separate from this live upgrade. Exact raw
signed v524 response bytes were unavailable, so the full policy-content comparison
was not claimed; the backend `verified` flag is the Agent's report, not an
independent cryptographic verification by this audit. The basic profile does not
expose the diagnostic delivery counters, which remain unavailable rather than zero.

The evidence manifest is the ignored parent-workspace artifact
`artifacts/cache-upgrade-20261002/install-589/acceptance-summary.json`, with the
raw install result, UTC report correction, configuration checks, fixed-selector
cache comparison, structural checks, backend snapshots and consumer-row receipt.
Historical rollout state was archived before the status journal was updated.

Concurrent Agent commit `7b282749` changes telemetry admission and is not part of
the tested 589 artifact. This documentation update does not validate or deploy
that change. Its parent-repository gitlink integration remains with its owning
task; no unrelated source changes or diagnostic secrets are included here.


## 2026-10-04 Agent 591 deployment and runtime evaluation

The user authorized deployment of the latest published Agent and continued
assessment against the alert-related-only upload requirement and 10,000-terminal
target. `win_3.2.591` was deployed to the existing Windows ARM64 UTM endpoint;
this phase performed one real endpoint's 30-minute observation and two bounded
90-second outbound outages. It did not rerun or pass 10,000-terminal mixed-load
acceptance. Existing [server capacity results](../../edr-backend/docs/database-capacity-20261002.md)
remain applicable, including the failed mixed-load cases.

### Published artifact and running identity

The [591 release](https://github.com/qiuxinliang/edr-agent/releases/tag/win_3.2.591)
was built from `bfb20a9afdb9889ea4c12aef1c648efc47724d87` by
[run 37208653818](https://github.com/qiuxinliang/edr-agent/actions/runs/37208653818).
Its manifest declares `unsigned`; the existing lab installation mode was retained,
and no signature-enforcement or TLS setting was overridden. The release contains
`7b282749` baseline admission changes and the queue ACK/CI recovery patch; later
strict egress commits `26a7ca91`, `64b923bf`, and `8fed2f9a`, and concurrent working
changes, are not part of this executable.

- Setup SHA-256: `2137bf5c1a52cc1eb18190bb736255b8a4493528e576562b8726aef43a44d6e5`.
- Published runtime ZIP SHA-256: `3c26f68b2076d911883f6b8224d2c9067c8aa74ef4d19786de8042f4837ec8c9`.
- Installed FDSensor SHA-256: `097e9a99ff9d2e2beab22789e272d0057104d7978f3f9d68ce05000ac9ab6bed`.
- Agent PID `3652`, creation FILETIME `134356002055865571`, started
  `2026-10-04T15:10:05.5865571Z`; the same generation remained Running in the
  SYSTEM `FDSecurityAgent` scheduled task at the final guest check, 15:40:13 UTC.

The original 589 PID `9688` exited normally with code 0 in 2.328 seconds, without
forced termination. Setup started at 15:09:22 UTC and returned 0. Stopped queue
and evidence databases were copied with identical source/copy hashes; WAL/SHM
were absent after normal close. The verified 589 installer, runtime, task and
configuration remain in the ACL-restricted guest rollback directory.

All 181 existing typed configuration fields were unchanged; primary and LKG
bytes matched each other. Both passed native `--config-test`. The CA hash and
independent sequence 524 were unchanged. Native status reported v524 `applied`,
matching desired/reported hashes and `verified=1`; this is the Agent's report,
not a new independent signature audit. All 20 selected candidate/reference/fact
sets were unchanged. Stopped working copies and live databases each returned
`quick_check=ok`; frozen original hashes remained unchanged. These checks prove
selected evidence preservation and structure, not completeness of every cache row.

Both fresh installer reports were bound to run ID `20261004230926402`. Runtime
presence was `ok`; capability health was `unknown`. The aggregate report retained
`warning` for `runtime_policy_pull`, as in 589. Missing service is expected in
scheduled-task mode. Full capability success was not claimed; ARM64's published
manifest also declares the unavailable WinDivert shellcode-network driver.

API PID `74137` and Worker PID `83159` remained the same during this phase, and
CA/hostname-verified readiness returned 200 for both before and after testing.
The API disk executable identified root revision `926c1d76` with modified-tree
metadata. The existing Worker was not restarted; this check does not re-identify
its in-memory binary by reading the newly replaced file. No backend deployment
or MySQL/ClickHouse setting change was performed in this phase.

### Thirty-minute observation and upload admission

The UTC window was 15:10:29.946–15:40:30.029 (1,800.083 seconds), with 31 successful
read-only samples and no sampling error. All samples reported version 591 and
online state; the largest observed `last_seen` age was 79 seconds. The window
includes installation acceptance probes and the two outages; it is not a quiet
idle baseline or a population-representative endpoint sample.

| Observed data | Records | Logical JSON bytes |
| --- | ---: | ---: |
| Unresolved FileRead, `NOT_EVALUABLE` source-only metadata | 427 | 764,087 |
| Security 4688 enrichment | 53 | 176,221 |
| Process decisions: persistence / script / uncombined LOLBin | 14 / 20 / 16 | 121,854 / 246,554 / 180,548 |
| AVE process evidence | 17 | 191,416 |
| Other Agent event | 1 | 831 |
| All version-591 Agent events | 548 | 1,681,511 |
| Separate health-history records | 17 | 77,539 |

There were 18 new stored atomic alerts with 607,667 logical process-context bytes.
These are stored alert rows, not 18 independently verified attacks. Selected
health reports showed minute-average CPU mean 4.58%, maximum minute average
21.36%, and reported RSS 52–124 MiB, including warmup and diagnostic workloads.

Current-process telemetry counters advanced by 619 successful event posts,
685,587 successful request-body bytes and 778,106 attempted
request-body bytes. Health counters advanced by 4 full and 22 delta reports,
389,772 attempted bytes against 477,148 equivalent-full bytes. These are
application body counters sampled at health-report times, not packet capture,
TLS/HTTP overhead, heartbeat totals or an exact byte total for the host-clock
window. Health remains `basic`, interval 60 seconds; request and history-archive
counts have different contracts. Local upload-skipped counters increased by
143 process and 6 file baselines.

**The strict upload requirement failed.** Unresolved FileRead accounts for
427/548 (77.9%) of new Agent event rows. Sample
`epev_f60c4d9cbd_1791127234415504000` has source completeness and disposition
`NOT_EVALUABLE`, null canonical path, no matched rule, and a `p0` source-only
context. In the immutable 591 source, collector evidence gates use the durable
source-only emit/retry path; the ordinary baseline admission change does not
turn those diagnostics into local-only records. The collector assertion is
explicitly prohibited from matching, correlation and action. Thus the `p0`
source label is not proof of a rule hit. Unknown contexts are also deliberately
kept on the ordinary upload path. Later strict egress code must be released and
validated before its contract can be attributed to this running endpoint.

### Outage, reconnect and queue recovery

Each outage added one named Windows Firewall rule scoped to FDSensor, the existing
API address and TCP port 8080. Profiles remained enabled; a separate bounded guard
removed the rule if the test job failed. Agent, policy, trust and caches were not
reset. Rule removal, process generation and guard exit were checked independently.

| Test | First outage | Second outage |
| --- | --- | --- |
| Block interval UTC | 15:27:19–15:28:50 | 15:36:09–15:37:40 |
| Peak sampled pending batches | 36 | 11 |
| Distinct sampled batch identities | 45 | 11 |
| Two consecutive empty queue samples after unblock | 115.324 s | 31.836 s |
| Exact receipt and durable-job SHA-256 matches | 45/45 | 11/11 |
| Final durable jobs | All done | All done, 14 accepted records |
| Test guard exit | 1; test marked failed | 0; test passed |

The first test's data recovered, but its guard used an unconditional removal of
an already absent rule. PowerShell returned 1, so the original terminal result
remains failed. The guard was corrected to explicitly handle the absent-rule
case while failing real lookup/removal errors; the same 90-second recovery test
was repeated and passed. A syntax error in the retry script was rejected before
launch. No failed receipt was rewritten. Both test rules and both guards were
absent at final acceptance.

Control-report recovery was slower than event/heartbeat recovery. Fresh reports
showed `h2_unavailable` after each outage with long-poll available. The first fresh
`connected` report after the first removal was 15:33:04 UTC; after the second it
was 2026-10-04 15:42:05.657000 UTC, sampled at 2026-10-04 15:42:29.196628 UTC. These are roughly
four-minute report delays, not precise socket reconnect latencies. At the latter
sample, PID 3652, version 591, long-poll ready and zero reported pending queue
were confirmed. This real-client behavior must remain separate from the earlier
synthetic 2,500-connection reconnect timing.

The 93 pre-existing `dead_letter/max_retries` batches all retained retry count 100
and originated at 2026-10-02 23:15:13–2026-10-03 00:41:53 UTC. None of their exact
batch IDs were found in this endpoint's retained accepted receipts or durable
jobs. Some retained receipts date back to September 16; this alone does not prove
that every historical receipt was retained. The absence of these batch IDs
cannot distinguish non-delivery from historical cleanup without further evidence.
Their historical failure cause and delivery remain unconfirmed. They were preserved, not cleared or automatically requeued;
success of today's pending-batch test does not resolve those historical batches.

### Storage and 10,000-terminal assessment

At the collector's 15:41 UTC sample, `storage-mysql-v4` measured
8,569,917,789 B (7.98 GiB), including
7,831,846,912 B allocated business space and
738,070,877 B infrastructure. `storage-clickhouse-v2` measured
603,948,302 B (575.97 MiB), of which
499,334,078 B (82.7%) was system logs.
A separate tablespace snapshot measured endpoint_events 1,958,739,968 B, alerts
1,283,457,024 B and purification history 587,202,560 B. These allocation snapshots
are not event JSON lengths or a reclaimable-garbage estimate.

The low-load shared MySQL window averaged 99.7 Questions/s, with
0.506% buffer-pool read misses, zero new log waits and zero new
buffer-pool-free waits; row-lock waits increased by 1,233 with 6,152 ms cumulative
wait time. Background services and the measurement queries contribute to these
counters. The 2 GiB buffer pool and synchronous redo/binlog durability settings
remained active. This is not a throughput limit or isolated database benchmark.

MySQL remains a candidate for authoritative business state, but 10,000-terminal
capacity is **not accepted**. First release and verify the strict egress boundary
while preserving local diagnostics, evidence and replay guarantees; investigate
the historical unreceived dead letters and the real control reconnect delay.
Then repeat mixed sustained/reconnect/recovery acceptance with the measured
request bodies and fixed release/configuration on dedicated resources. The prior
100/1,000 EPS mixed failures are not overturned by this single endpoint run.

Raw receipts, hashed metadata, private configuration copies and failed diagnostic
attempts are retained in the ignored, restricted
`artifacts/agent-591-evaluation-20261004/` directory. The guest rollback and frozen
copies are under `C:\ProgramData\EDR-AGENT-UPGRADE-20261004-591-attempt2`.
Initial upgrade digest and stale-generation diagnostic checks failed before their
respective protected actions; they were corrected with current identities, and
the original results remain available. This documentation-only change contains
no secrets, deployment scripts, binaries or concurrent source changes.
