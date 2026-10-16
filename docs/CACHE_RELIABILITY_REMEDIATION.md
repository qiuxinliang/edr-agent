# Cache reliability remediation

## 2026-10-16 native measurements accepted; Headless-only release path prepared

Native comparison run **38829816969**, source
`21b7e4d4c278448e628f5e1ddd6a3d26dfb6078f`, passed on real AMD64 and ARM64.
The two exact synthetic artifacts contain 30 evidence executions (three
variants, five samples, two architectures), 16 queue executions and 192 queue
window inventories. Input digests match before/after and across architectures.
All child exits, native-machine checks, payload readbacks, integrity/orphan and
nine-category ledger checks passed. Each architecture's current 1,072 source
files and baseline 1,067 Git blobs/four link closures were verified against the
immutable revisions, including Windows checkout line endings.

| Evidence workload, same 8 MiB budget / 192 candidates | Old 1 h | Current 1 h | Current 4 h |
| --- | ---: | ---: | ---: |
| Embedded complete parent chains | 0 | 6 | 24 |
| Reconstructable with process cache | 6 | 6 | 24 |
| Selected first/last event span, seconds | 20 | 20 | 10,820 |
| Sampled DB/WAL/SHM peak, bytes | 2,305,312 | 3,272,648 | 3,379,192 |
| SQLite VFS issued writes, bytes | 17,364,348 | 41,859,900 | 39,641,320 |
| AMD64 median process CPU, seconds | 0.515625 | 1.328125 | 1.328125 |
| ARM64 median process CPU, seconds | 0.515625 | 1.390625 | 1.359375 |

At the same 1 MiB logical queue budget, unique-input pressure changed the
freshest retained age from 36,070 to 120 seconds, successful exact retries from
0 to 33, and the 20-byte terminal from refusal to admission with exact readback.
Its sampled physical peak rose from 1,557,176 to 5,166,168 bytes; VFS writes
rose from 1,524,932 to 20,038,348 bytes (13.14 times). CPU rose from 0.203125 to
0.484375 seconds on AMD64 and 0.125 to 0.5625 seconds on ARM64. The historical
queue stalls while current code continues retry/maintenance work; these are
whole-workload costs, including encoding and forensic inventory, rather than
normalized per-event overhead. The existing logical budget remains distinct
from DB/WAL/SHM and global disk protection.

These costs are material. Issued VFS/process I/O is not device write
amplification; the windows use simulated event time, not an eight-hour wall
clock soak. Four hourly selected cohorts span 3 h 20 s, not continuous or
arbitrary-load four-hour retention. Historical embedded-chain count zero does
not mean all old evidence is unreconstructable. The intentional missing-RAM
`owner_loss` negative control remains recovery-held; the real eight-slot
producer/audit fix is verified by its separate regression and release gates.
The comparison sender is an isolated aborting/stub boundary, not a whole-client
packet capture or proof about every production consumer.

The complete raw synthetic artifacts, per-file hashes, recomputed sample
medians and bounded source bindings are indexed by
`/private/tmp/edr-native21b7-monitor/RESULTS.json`, SHA-256
`c7fad575af6bcb018dd7dfee879c84d89e6fc93b3930fdd455f8ac8a1868a7c2`.
The root also independently checked both artifact ZIP digests/CRC and all 46
execution exit codes before release preflight. Earlier failed runs and their
partial samples remain preserved and excluded from the accepted comparison.

### Release scope and preserved installer boundaries

Automatic approval review rejected the original full-688 workflow dispatch
before process creation: that workflow additionally builds/downloads Setup UI
and standalone Setup assets beyond the explicit Headless-only instruction.
No dispatch intent, workflow run, tag, release or deployment was created.
The rejected command has not been retried through another interface.

The prepared replacement changes the existing release owner, without creating
a parallel build/release implementation. Build-only `package_scope` defaults to
`full`. Its `headless` choice currently requires **unsigned + candidate=true**;
unsupported combinations fail before release operations. This limited mode
has a current consumer: the authorized single-UTM Headless candidate validation.
Signed/USB and existing full consumers retain their supported path.

Headless skips Setup UI/.NET restore and build, does not prepare/upload UI or
standalone Setup assets, and requires exactly three assets per architecture:
Agent, Headless ZIP and artifact manifest. Combined publication requires the
six exact assets. The installer remains inside Headless and receives a real
`full-installer-manifest.json`: version, native payload architecture, original
component hashes, unsigned capabilities and preservation protocol. The writer
checks bounded regular inputs before reading, the existing x86 Inno bootstrap
rule separately from native payload architecture, a real **NotSigned** result,
unchanged installer bytes and exclusive bounded manifest creation. It does not
invent a UI hash or fall back to synthesized legacy metadata.

Scope belongs to a separate release HTML ownership marker and Headless
checkpoint metadata. The canonical `build_provenance` schema is unchanged,
because the deployed backend rejects unknown provenance fields. Existing full
checkpoint shapes and source markers remain compatible; scope cannot be
borrowed in either direction.

The lifecycle job downloads only the target/baseline Headless ZIP and artifact
manifest. Its existing checkpoint owner validates immutable release/tag/source/
run bindings, native Agent and runtime hashes, the embedded installer, bounded
ZIP extraction/CRC and actual preservation manifest before a fresh atomic
stage. It feeds the verified embedded installers to the unchanged real Setup
install/repair/upgrade/rollback/uninstall script. Baseline 687 cannot skip Setup
rollback. The existing runtime lifecycle remains required. A full baseline's
Headless subset does not certify its unrelated UI or standalone Setup bytes.

No updater or backend implementation change is required for this package
format. Existing `BuildHeadlessFullInstaller` maps the verified Headless
installer/manifest to the existing protocol-5 wire filenames, without a UI
executable. It preserves supplied manifest bytes rather than using the legacy
missing-manifest fallback. Backend late-health-event patch `f8f5d4a2` remains
separately undeployed, pending its earlier API update/restart approval.

### Current verification checkpoint, not a release success claim

The composed host contracts passed **117/117**: checkpoint 67 (48 existing tests
unchanged, 19 additions), USB 9, binary compatibility 7, release workflow 25 and
lifecycle workflow 9. Both YAML owners and the host C asset contract passed.
Independent reviews checked scope isolation, closed provenance, typed external
JSON, strict Inno bootstrap rejection, actual ZIP/hash validation and atomic
staging. Raw host commands/results are in
`/private/tmp/edr-headless-checkpoint-final-oac3qlvm/RESULTS.json`, SHA-256
`86d7d5dfb6a5a51f5b16e2f65176f5a641af56cb986a93f6dd18dbf175417722`.
The root reran the final composed 117 tests, C compile/contract and diff check
with zero source drift; command/log index
`/private/tmp/edr-headless-composed-gates-j4j0y92m/RESULTS.json`, SHA-256
`5dd6c1e52c7a9f6dab4edc0e007cb7a7bcce3cdd44a94621903535999a0bfb5f`.
Existing backend `TestHeadlessFullInstaller*` tests also passed 2/2 locally,
covering protocol-5 transport, supplied-manifest byte preservation and invalid
inputs. Those use synthetic PE/CMS fixtures, not a new installed consumer.

On the single UTM, the initial synthetic unit invocation via `-File` was blocked
by its existing execution policy and remains **failed**, not passed or skipped.
No policy was changed, and script content was not re-executed inline to evade
that denial. Only three task source files and inert JSON data were staged in a
new owned temporary directory, without Agent/cache/installer access. A separate
data-only AST check passed for the final ten modified PowerShell workflow/source
bodies; it executes no content and is not a unit or lifecycle acceptance result.
Its proof is
`/private/tmp/edr-headless-manifest-native-hy6q2feo/FINAL_AST_RESULTS.json`, SHA-256
`378465eec01d29b651660d3dff648587ade680f39b9c08648352f996f1eb8fd8`.
The mandatory isolated CI unit step uses an explicit Authenticode fixture;
the actual package writer subsequently calls the real cmdlet on the real
installer. Windows unit execution, final-source native comparison, all 114
release gates per architecture, real lifecycle and single-client deployment
remain required at this checkpoint. The earlier runtime 68-test host gate is
unchanged by these release/build-only edits. No Setup UI product package was
downloaded, no real cache was cleaned, and no new historical evidence sample
was substituted. The two unavailable old candidates and 7,950 unclassified
owners remain the separately recorded limitations.

## 2026-10-16 source-owner recovery repair: host acceptance complete, native validation pending

The real eight-slot P0 producer regression described below now has a production
repair. `p0_rule_direct_emit.c` serializes source-owner I/O with a separate mutex;
the short state mutex never spans SQLite. Different pending sources share the
known prepared handoff rather than preparing it repeatedly. Exact deduplication,
eight RAM slots, round-robin retry and the existing 250 ms retry boundary remain.
Ordinary capacity refusal therefore does not manufacture a restart-loss claim.

A genuine overflow or lost handoff still requires a durable local gap audit.
The audit is written directly, without a ninth RAM slot. Only a successful FULL
commit of the canonical audit grants durable-loss status. Remaining RAM owners
receive a fresh prepared successor atomically with the committed payload; clean
close or a crash between audit commit and RAM drain cannot erase that recovery
obligation. A recreated queue must establish strict recovery before clearing a
known loss. Repeated strict-loss retries are bounded and do not rewrite the
same latch indefinitely. Legacy remote-v2 recovery ownership remains protected.

### Finite capacity and ownership

`queue_sqlite.c` gives only the canonical local recovery audit access to the
existing finite source reserve. The codec re-encodes and byte-compares a single
minimal RAW/BAT1 proof, binding scope, nonce, counter, epoch, domain commitment,
event ID and batch identity. Extra JSON/protobuf fields, commands, false flags,
wrong tuples and malformed markers do not gain this ownership. This local
classification grants no upload permission: the existing final egress gate
continues to reject these source-only audit records.

Let M be the existing queue logical budget, T its existing terminal reserve,
and S its existing source reserve. Ordinary admission stays within M-T-S.
New local audits must fit both their S-byte sublimit and total M-T. Terminal
admission excludes only the actual canonical audit bytes, capped at S, from
its M-S charge, and always checks total M. Repeated terminal records cannot
borrow S; audit exhaustion explicitly refuses and preserves the recovery fuse.
No configured budget, default retention window, percentage, or physical-disk
claim is introduced. Existing reserve derivation remains in
`queue_terminal_reserve_bytes` / `queue_p0_source_only_reserve_bytes`.

Admission reads the original nine-row ledger plus one fixed metadata row, not
an event-table SUM. Two new primitive counters in `queue_meta` are calibrated
transactionally at startup and maintained by triggers. Measured SQLite VM
steps remain 63 with both small and 5,000-row inventories. The original
three-column ledger schema is unchanged. Canonical audit rows retain supported
class 1 / policy 2, using a new controlled terminal-reason marker. Only the
verified current writer creates it; query and TTL retirement verify the bytes
again. Existing unclassified or malformed records remain protected.

The replay path rechecks the frozen row inside the FULL transaction. A second
SQLite connection deleting that row before BEGIN cannot clear the latch or
return a successor. Calibration/commit failure rolls back both payload and
counters. These protections do not reserve physical blocks or separate the
shared database, lock, WAL, index and disk fault domains.

### Verification and rollback boundary

The final host build of `edr_agent`, `agent_runtime_gate_tests` and
`telemetry_minimization_tests` passed. The combined labels selected 68 tests:
62 passed in the sandbox; six loopback-listener tests were blocked by sandbox
bind permission. The unchanged six tests passed after the scoped loopback
rerun, 6/6 in 55.14 s. Both manifests report zero source drift across 697
C/header/CMake entries. Original sandbox failures remain failures in their log.

```sh
cmake --build /private/tmp/edr-cache-assessment-egress-build --target edr_agent agent_runtime_gate_tests telemetry_minimization_tests -j4
PATH=/opt/homebrew/opt/openssl@3/bin:$PATH ctest --test-dir /private/tmp/edr-cache-assessment-egress-build --output-on-failure --no-tests=error -L 'agent-runtime-gate|telemetry-minimization'
```

Raw commands, exit codes and hashes are in
`/private/tmp/edr-source-recovery-integrated-20261016/RESULTS.json` and
`LOOPBACK_RESULTS.json`. Focused producer tests cover two failed sources,
in-flight concurrent submission, eight-slot overflow, FULL failure/backoff,
queue recreation, clean close, child `_Exit(95)`, V2 ownership and exact payload
preservation. Their network/action adapters are explicitly isolated; they do
not certify an installed Windows consumer. Queue/codec tests additionally cover
hostile proofs, critical exhaustion, a 20-byte terminal and journal under local
pressure, calibration rollback, external-writer replay deletion and exact
ledger agreement.

The old-687 storage owner (`97064865`) opened the new synthetic database,
performed expired cleanup and a terminal write, and reopened it successfully;
the original new-audit bytes, prepared successor and ledger identity survived.
The new reader then verified it again: 4/4 round-trip steps passed. Manifest:
`/private/tmp/edr-audit-687-compat-fczsy341/manifest.json`, SHA-256
`efcac7e9faf90a829d192355add28fe867fcb713d15c42d22dfb314585a8ebef`.
This executes the actual old queue owner with current shared codec/support,
not the complete old binary or a real-client rollback. Old readers conservatively
hold the unfamiliar marker; rollback does not authorize deleting it. No old
payload is re-encoded or reclassified by this change.

Native comparison runs 38825102163 and 38827617869 failed before measurement:
first Git autocrlf changed baseline bytes; then Windows tarfile produced an
unreadable nanopb symlink (Errno 22) on both architectures. Their failures are
preserved. The archive invocation now fixes LF locally, validates every Git
blob/link closure, and on Windows materializes verified target bytes. Eleven
export/failure boundaries plus complete host runner smoke protocols pass;
manifest `/private/tmp/edr-native-b783-symlink-zw3yw1k2/RESULTS.json`, SHA-256
`688c516821b8f0eb0fb01f06014fdb275cb6a4d5a7a220aee5371a15606fe716`.
Run 38828995933 at repaired runtime source `9547f675` passed the Windows
baseline export and completed five old-variant AMD64 samples, but the current
variant did not compile: MSVC C5102 ignored a function-style `/D BENCH_OPEN`
and C4013 then rejected its call. The same macro now lives in the existing
current-variant C branch; policy hours and workload assertions are unchanged.
Fifteen fresh host samples (three variants, five each) and three MSVC argv
branch checks passed; this is not native execution. Original partial measurements
remain partial. A new source-pinned native AMD64/ARM64 run remains required
before interpreting Windows CPU/I/O or publishing the repaired client candidate. Simulated windows,
issued I/O and sampled file peaks do not prove elapsed soak duration or device
write amplification.

Separately, parent commit `f8f5d4a256899f8ee4d4c525b4bef299470acdfd`
fixes late upgrade progress during the existing health observation and moves
the installer-log gate into the same row-lock transaction as journal advance.
Real isolated MySQL barrier tests and handler regressions passed; deployed-schema
EXPLAIN remains skipped. The local API binary is prepared but **not deployed**,
pending the separately requested backend update/restart approval. The installed
UTM client remains 687 at this checkpoint. No Setup UI download, real cache
cleanup, replacement evidence sample, fake ACK or expanded routine upload was
performed. The 7,950 unknown legacy owners and the two unavailable historical
candidate samples remain the separately recorded limitations below.

## 2026-10-16 native comparison preparation and a new producer recovery regression

The comparison runners now support native Windows MSVC with the existing locked
VS/vcpkg owners. Their dedicated CI builds synthetic test executables only,
checks PE architecture and `IsWow64Process2` (emulation is rejected), and records
`GetProcessTimes`, QPC, process-issued I/O and forwarded SQLite VFS I/O. It uses
`contents:read`, has no installer/release/client operation and uploads only
synthetic JSON/JSONL/logs. Narrow test/workflow push paths allow its first run on
the development branch without changing the default branch. The installed 687
Agent and routine upload projection are unaffected by these test-only changes.

Independent review found a defect in the historical queue comparison: after
each refused input it additionally committed the previous successful wire.
Those extra writes differed between implementations and were absent from the
reported input count/hash. Historical queue CPU/I/O and rotation results must
therefore not be treated as a strict equal-total-input comparison or complete
producer recovery proof. Original results remain preserved. The evidence-store
comparison did not contain that fallback.

The corrected queue comparison separately records the identical externally
offered stream and the implementation-dependent actual commit/retry streams,
with counts, bytes and SHA-256. It retains one exact failed snapshot/latch,
retries it before accepting another input and explicitly counts deferred inputs.
This is a queue model, not the real eight-slot/250 ms P0 producer. A separate
`owner_loss` case deliberately drops that handoff and preserves the resulting
recovery hold. No unrelated previous wire clears a failed owner. Every retained
128 KiB wire is compared exactly, including a 90 KiB command, parent command and
parent process generation; current windows verify all nine ledger categories
against actual tables plus SQLite integrity/FK checks.

Fresh macOS preflight results, with equal 1 MiB logical budgets, a one-hour target
and 12 simulated windows, are:

| Unique-input model | Old 662 queue | Current queue |
| --- | ---: | ---: |
| Offered new inputs | 48 | 48 |
| Initial success / refusal / deferred | 7 / 1 / 40 | 3 / 34 / 11 |
| Exact retry calls / successes | 40 / 0 | 44 / 33 |
| Final retained rows / freshest age | 7 / 36,070 s | 3 / 120 s |
| Retained timestamp span | 3,721 s | 3,541 s |
| CPU user + system | 0.297385 s | 0.555719 s |
| SQLite-issued write bytes | 1,524,932 | 20,017,796 |
| Sampled DB/WAL/SHM peak bytes | 1,557,176 | 4,745,976 |
| 20-byte terminal | Refused | Admitted and exact bytes read back |

Replay (384 offered inputs), priority-3 and owner-loss cases also ran. Source
sender calls remained zero under the declared sender stub. Queue CPU/I/O includes
encoding, retries, per-window forensic inventory and terminal readback, before
final close. The focused baseline pairs historical queue C/header with shared
current codec/support; it is not a whole historical Agent build. Costs include
different measured retry counts, not equal actual storage-call streams.

The unchanged 8 MiB evidence workload was rerun five times per variant. Old 1 h,
current 1 h and current 4 h retain 6/6/24 selected owners; self-contained parent
chains are 0/6/24 and reconstruction with process cache is 6/6/24. All admit 192
candidates, have identical protobuf input SHA, zero orphan references and valid
SQLite structure. Current 4 h selected span is 10,820 s, not continuous four-hour
coverage. Its median CPU is 0.300911 s, VFS writes 28,981,320 B, sampled peak
3,379,192 B and final DB/WAL/SHM 791,832 B. This workload does not fill 8 MiB;
the queue model supplies actual pressure. VFS/process-issued bytes are not
physical-device write amplification. Simulated time is not a Windows soak.

Commands and original outputs:

```sh
python3 -B tests/run_queue_retention_comparison.py --output /private/tmp/edr-windows-queue-frozen-20261016d --codec-build /private/tmp/edr-cache-assessment-egress-build --scenarios unique replay high_severity owner_loss
python3 -B tests/run_evidence_retention_comparison.py --output /private/tmp/edr-windows-evidence-frozen-20261016d --runs 5
```

Seven frozen test/workflow file hashes and all execution manifests are indexed by
`/private/tmp/edr-retention-comparison-handoff-2qczi__k/MANIFEST.json`, SHA-256
`fa96dd953cf15498fca6b072eaae12ef80df051232cb17a92f2576966d17b7ee`.
Queue summary SHA is
`bccd94e08f6c3e0881af1b39a37f13ef8eae8de2c0268dd94a3c0ba08620a5dc`;
evidence summary SHA is
`b1c29affda9f203a387b2271d2011226188a593dfca5f81016ef2a999c21e16c`.
Actual exit-17 and timeout subprocess output preservation passed 2/2; Windows
MinGW branch compile-only checks passed 2/2. These are not native Windows runtime
measurements; CI execution is pending at this preparation checkpoint.

Tracing the new owner-loss counterexample also exposed a separate real-producer
regression. A true SQLite/producer fixture fills the 1 MiB queue with 42 local
records, then submits two different sources before their 250 ms retry deadline.
Both remain in RAM, but repeated prepare converts the global latch to
`recovery_required`. After two simulated hours and 16 real cleanup/recovery/retry
turns, both are still pending and the original 42 rows cannot retire. The RED
assertion aborts; it is not a successful degradation acceptance. Original proof:
`/private/tmp/edr-p0-capacity-recovery-red-g43bpl63/RESULTS.json`.
The serial comparison above does not close this real eight-slot producer path.
Production repair, overflow/concurrency/restart regression and release/client
validation remain required. This queue defect is distinct from the live
evidence-store candidate-capacity refusal category below; no claim is made that
it caused those 484 refusals.

## 2026-10-16 follow-up: classify real admission refusals without disposing of evidence

This follow-up starts at Agent HEAD
`cddb191e836a882f7b1e2d252db14b874fc51104`; the installed 687 runtime remains
`97064865522c6aebd050fab9675c7eb34697ece6`. The single UTM process is still PID
8400 with the published Agent SHA recorded in the final 687 section below.
Native `GetProcessTimes` returns exact
creation FILETIME `134365780065939722`; CIM's displayed timestamp loses the
last two 100 ns ticks. Two initial probes refused that mismatched generation
before opening SQLite. Their original failures remain preserved. The corrected
probe binds the independently verified native value and retains exact identity,
path, sidecar/reparse and before/after generation checks.

### Observed capacity and refusal category

At the `23:20:40.250` UTC health report, this generation records 509 candidate
requests, 25 new admissions and 484 refusals. The bounded read at guest
`23:15:28.348` found 484 `candidate_capacity_refused` metric increments in five
event-time minute buckets, for the configured endpoint and fixed
`22:47 <= event time < 23:20` interval. This supports the capacity-gate category
for this batch; it does not prove the specific DB/WAL/physical subcause of every
attempt. Metrics use event timestamps, are not process-scoped and can omit
unflushed, old-timestamp or unrecorded failures. Absent metric groups are not
zero. Requests can update an existing owner; 484 is not a unique-lost-event count.

The separate read-only page/retention aggregate at `23:20:43.797` measured:

| Measurement | Bytes / count |
| --- | ---: |
| Main DB: 131,070 pages x 4,096 bytes | 536,862,720 B |
| Free pages / freelist bytes | 0 / 0 B |
| WAL / SHM | 12,392 / 32,768 B |
| DB + WAL versus configured 536,870,912 B budget | 4,200 B over |
| Policy 0, class 0, retained candidate owners | 7,950 |
| Policy 1 retained recent / selected owners | 1 / 12 |

File sizes matched before/after the 125 ms read. The 94 ms metric read and the
geometry read use SQLite `mode=ro`, query-only, an eight-second deadline and
1.5-second busy timeout. They export fixed aggregate fields, not candidate,
fact, event or command rows. No checkpoint, migration, VACUUM, fake ACK or cache
cleanup was performed. This page geometry does not attribute all bytes to the
7,950 unknown owners or identify a historical WAL blocker. Zero reported physical
refusals/retirement failures also does not prove every logical-budget write fits.

`sqlite_size_budget_allow_mode` accounts DB plus WAL; a small WAL can cross
the configured threshold even when the main DB is slightly below it. Existing
owner growth must pass this gate too. A long reader or reusable-WAL failure can
therefore reject a write. `candidate_pressure` instead reports a closed store
or resource throttle. It is not a summary of all capacity refusals. Ordinary
noncandidate/noncontext telemetry has a rate limit; candidates are exempt from
that particular throttle. These are source-verified distinctions, not a claim
that this live snapshot reproduced a particular SQLite reader failure.

The existing host retention suite was rerun after this diagnosis: **1/1 CTest,
39 retention cases passed in 7.26 s**. It includes existing-owner expansion
under a real reader-pinned WAL, recovery after reader release, unclassified
owner/shared-context protection, bounded reclaim, rollback/restart and result
copy budgets. The command and immutable copied original output, test-binary and
source hashes are in
`/private/tmp/edr-687-capacity-followup-20261016/RESULTS.json`, SHA-256
`d38551e6cc735cc1595febb4aa8a2cec9fc3d743d11ec98c046c6659bae14d84`.

```sh
ctest --test-dir /private/tmp/edr-cache-assessment-egress-build --output-on-failure --no-tests=error -R '^local_evidence_cache_retention$'
```

The aggregate metric proof SHA-256 is
`90d3dbe203d33917af778a1d265f8c71bc3b33609b9fa91fac1826d6daa063a5`;
page/retention proof SHA-256 is
`3faa72549877bef6ec1e8624d7e97292c8c1dd3954374d0cbca9cdad003b8460`.
The refusal category does not justify changing retention policy to delete
unknown old evidence, enlarging the budget or expanding routine uploads.

### Legacy inventory disposition: proposal, no real-data migration

The 7,950 owners remain separately measured and protected. Their aggregate
policy/class label is insufficient to establish original purpose, delivery or
recovery ownership. An eventual authorized disposition must use this sequence:

1. Work from a consistent, integrity-checked copy with a capacity/physical-peak
   estimate and immutable original-byte/identity manifest. Classify only owners
   whose record format, writer and original lifecycle can be established.
   Inspect complete linked delivery, frozen journal, recovery/projection,
   investigation-pin, lineage, exact process-generation, entity and delta-base
   dependencies. An absent ACK alone cannot decide local value or retirement.
2. Produce a reviewable dry-run plan for complete causal groups, showing owner
   class, policy version, byte estimates, protection reasons and proposed local
   retention outcome. Unknown, conflicting, busy or incomplete groups stay
   protected. Do not infer all 7,950 owners are disposable or promise enough
   capacity will become available.
3. After separate migration authorization, add bounded classification metadata;
   preserve old frozen bytes, hashes, batch IDs and owner/lineage/generation
   bindings. Recheck all protection and dependency predicates within the same
   transaction before changing an owner. Use deterministic checkpoints and
   bounded rows/time/bytes; verify restart and concurrent ACK/query behavior on
   a synthetic copy first. Projection ACK only releases its own delivery edge.
4. Treat permanent retirement as a separately authorized operation. Re-evaluate
   the complete group in its transaction, record bounded policy/reason/stats
   without inventing ACKs, and retain dependencies needed by surviving groups.
   Before deletion, rollback can restore classification metadata. After a
   committed deletion, recovery requires the authorized verified backup; metadata
   rollback cannot recreate payload. Routine downgrade across unsupported
   policy-3 delivery owners remains unsupported.

If the plan cannot legally release enough stock, expose the protected-byte risk
and continue finite, observable admission refusal. No fixed retention duration
is guaranteed in that condition. A future disk-budget change or evidence export
requires a separate concrete operational decision; routine full-fact upload is
not a capacity remedy. The original two missing candidate samples remain an
unclosed preservation gap; aggregate counts and replacement samples cannot
close it. The cached-evidence consumer remains an interface/test proposal below,
not a newly exposed remote-control route.

## 2026-10-16 final 687 Headless deployment and evidence acceptance

Runtime source is `97064865522c6aebd050fab9675c7eb34697ece6` on
`codex/rtq-result-delivery-pressure`. The final documentation commit is not a
different runtime build. This source is 32 commits after audit baseline
`0ae3fb28e553223358db1a83ebd26432336af9e7` and 23 after comparison
`3de0dc680c78c335f8ab6ba37eef0d0f5d8f46e2`. The implementation, configuration,
lifecycle, migration and measured comparisons below remain applicable; this
section records the final delivery and its limits, rather than certifying all
ten requirements as field passes.

### Release and actual single-client upgrade

Run [38814603184](https://github.com/qiuxinliang/edr-agent/actions/runs/38814603184)
completed all seven jobs successfully. Each native architecture executed and
passed 100 release and 13 remaining telemetry tests, 113 unique tests. Both
real Setup and binary-hot lifecycle jobs exercised 685 -> 687 -> 685. Setup
asserts version, PE architecture, files and runtime health; the independent
installed-Agent SHA assertions belong to binary-hot verification. The final
host regression passed 67/67 as recorded below. Mode-specific skipped steps
remain skips. Candidate 686 also completed CI, but was never downloaded or
installed on the client.

Release `414318483` is the source/run/P0-bound `win_3.2.687` prerelease.
GitHub latest remained `win_3.2.591`. Only these three ARM64 assets were
downloaded and imported through the client UI:

| Input | Bytes | SHA-256 |
| --- | ---: | --- |
| Artifact manifest | 2,367 | `f07603196a8dbae270260049af339227dbee4e1dc3d31609ac14d5dfc83247fe` |
| Agent | 3,215,872 | `6c33f6233b8355d6b30d4bd94082be13ee7d139e2b8b7bd425c1e5214dab8740` |
| Headless ZIP | 14,216,191 | `125825d514a8463d67d6260e6b67b9c70db821f59f1a34c864f1bd3dc2d40498` |

No Setup UI package or separate Setup executable was downloaded. The complete
Headless ZIP contains its required installer; member paths, CRC, runtime
closure, manifest identity and embedded installer hashes were verified.
`headless-artifact-pin.json` SHA-256 is
`30cb49702d25f189c6408d8663a0635f7b26149d74237fb6550c9b0cfa5f8639`.
The release proof directory is
`/private/tmp/edr-687-release-draft-60k9gvk5/`. Its four CI logs contain only
environment/credential-sanitized text with protected execution records checked
unchanged in memory before persistence. Full raw logs were not preserved.
Final log provenance SHA-256:
`ea622761a32cfbf9c3cd681869fe5a24cb4776c1417b597293bf69c5d782f564`.

The UI imported `artifact_1792104251397459000` and submitted exactly one task,
`agent_upgrade_1792104294189391000`, for WIN-FAC3AC1PS5O. Its command is
`agent_update_1792104295100925000`, runtime package 246 SHA-256
`26f8345c2b063073534956d7cad34e79917bba10cb82b7f0c5298250f17ac845`.
Actual installed version is 3.2.687, with the Agent hash above, PID 8400 and
guest CIM birth `2026-10-15T22:46:46.5939720Z`. The same identity remained at
guest `23:00:24.5353277Z`. The existing scheduled-task owner and explicit
512 MiB/72-hour queue/evidence overrides remain. No Machine/User path override
was observed; this is not a full process-environment inspection. No manual
restart or real-cache cleanup was performed in this deployment.

Backend health observation ran from `22:46:40.087` to `22:51:40.087` UTC;
the task completed at `22:51:40.088`. This is the configured 300-second
observation interval, not proof of uninterrupted physical sampling. Backend
and guest clock values are not interchangeable. Initially the local succeeded
journal had sequence 6 while ACK was 4. Bounded guest-side log classification
found HTTP 409 / `INVALID_UPGRADE_TRANSITION`, specifically
`health_check -> restarting`. The matching 4,096-byte redacted installer log
was already durably indexed; its local/server SHA is
`1569cdb7dd8e09c495b2aa62276d3273dddf428da38864de098fee946165ba9f`.

After backend completion, the normal retry path accepted late events 5 and 6
at `22:51:40.892` and `.987`; local ACK advanced to 6. No checkpoint, event or
server row was manually changed. Exact task/command/artifact pins, continuous
events 1..6, terminal journal, absent policy hold and ACK 6 then passed the
unchanged `--require-complete` verifier. Its result SHA-256 is
`ce7f6488d54ca1a3346baefa59daeb24c03680b1a121e22537db8330478378e0`.
The initial incomplete check is retained, not relabeled as success. The
observation/event ordering still causes avoidable temporary 409 retries in
this existing backend flow; this Agent delivery does not claim to repair it.
At two later same-PID reports, HTTP success increased 239 -> 242 while the
cumulative failure count remained 208; control ACK pending was 0 and h2
control remained connected and leased. These observations do not erase the
208 historical failures or prove an independent wire ACK capture.

An actual UI live query targeted only PID 8400 on this endpoint. Session
`rtq_1792104472196503000`, run `rtqrun_1792104472258614000`, returned one
FDSensor row with exactly `type`, `name`, `path`, `pid`. The command is
`cmd_rtq_ep-ff84e69e4_1792104472258618000`. Its stable local owner and actual
backend result matched type/status/exit/390-byte length/SHA
`216cc77e8aa43e24d2175a91ba4cf5ec95bf6bdb8c5f5a1b3b1c3c800789b096`;
both `accepted` and `execution_succeeded` are true, with no pending/held error.
Receipt SHA-256:
`126692a2e406e5e9c53db864ad469da187a336697cff112c86f61d83046288e3`.
This verifies the live consumer and necessary result delivery, not the absent
cached-query producer described below.

An additional generic-result lookup for the upgrade command returned no row;
its original exit 3 is preserved. That is not a generic-result ACK. The actual
upgrade owner has one successful terminal, no pending/held/error state and
empty SOAR/playbook correlation fields. `command_stub.c:command_should_report`
reports the `cmd_`/SOAR route; this ordinary `agent_update_` command uses the
dedicated upgrade-event consumer above. Its 92-byte local final is therefore
not certified as an `endpoint_command_results` receipt. The offline route
classification is `upgrade-687-delivery-consumer-classified.json` in the same
acceptance directory. The separate RTQ receipt proves the generic result path.

### Real capacity degradation remains visible

The last pre-upgrade 685 generation must not be replaced by post-restart zero
counters. At backend report `22:38:07.561`, PID 8432 reported 1,735 candidate
requests, 37 new admissions and 1,698 refusals. At `22:44:09.194` the same
generation had 1,741/43/1,698. Candidate requests can include owner updates;
these are not counts of unique lost events. The aggregate does not identify
every refusal as capacity, CPU, SQLite or transaction failure. CPU throttle
directly skips ordinary noncandidate/noncontext facts, not all candidates.

The 687 generation later reported 12 requests, 4 new admissions and 8 refusals
at `22:58:38.150`, with four retired groups, 241 held decisions and zero
recorded retirement/physical-guard failures. Ordinary candidate admission is
still degraded; an upgrade success and a false pressure boolean do not mean
all writes succeed. The boolean means closed evidence store or resource
throttle, not all logical-budget refusals. Rejection counters remain the
existing minimal-health evidence of those refusals.

The bounded before/after SQLite aggregates show the same 7,950 policy-0/class-0
legacy candidate count and earliest/latest times. They do not prove per-row
identity, content or hash preservation. Policy-1/class-2 retained candidates
changed 7 -> 14. Durable retirement counters changed 30 -> 41 groups,
784 -> 1,041 rows, and 1,306,985 -> 1,720,215 work bytes. These cross-generation
deltas prove some actual retirement, not equivalent disk bytes freed or work
attributable solely to 687. Held decisions can repeat and are not unique pins.
Unknown legacy owners remain protected instead of being silently classified
or deleted. Their occupancy can limit new retention.

The final sampled DB was 536,829,952 bytes and WAL 45,352 bytes: together
536,875,304, 4,392 bytes above the 512 MiB setting. Including SHM gave
536,908,072 bytes. These pre-write admission checks and bounded maintenance
are not an atomic post-transaction physical cap or Agent-directory quota.
Free-space guards remained available with about 20.95 GB free. Near-budget
occupancy alone is not failure; the observed refusals are a distinct fact.
No capacity increase, bulk upload, fake ACK or real-cache deletion was used.

All nine queue ledger categories matched. The three original queue owners
still matched their immutable bytes, identities and ACK flags after the
upgrade. This does not replace the two original candidate samples missing
after the earlier 679 rollback; that preservation gap remains unclosed within
the authorized evidence scope. No replacement samples were taken. P0 r289
was ready/healthy with 183 rules; the new-generation v528 configuration
receipt was verified/applied with matching desired/reported hashes and no
restart required.

The supported investigation value is recent detail plus selected candidates,
full command objects and protected process-generation/causal dependencies,
with independently owned necessary deliveries. Defaults target 24-hour recent
detail and 72-hour selected retention; this UTM explicitly targets 72/72 hours.
These are workload-dependent goals. Under pressure, eligible complete groups
retire and shared content deduplicates; protected/unknown owners and finite
critical reserves can force explicit refusal. A fixed retained duration under
all loads is not promised. The measured eight-hour synthetic comparison below
records retained timestamp span, parent reconstruction, physical peaks, writes
and increased CPU cost, not a Windows 72-hour field guarantee.

Actual acceptance commands and original JSON results are under
`/private/tmp/edr-678-client-acceptance/`. The 26-file
`final-687-evidence-index.json` has SHA-256
`ddce675c98f3218edd95c5335e84eb3f27f5184a27d7dec13f6d51bd9d4204d0`.
Relevant commands:

```sh
python3 -B /private/tmp/edr-687-release-draft-60k9gvk5/verify_headless_from_job_logs.v4.py
python3 -B /tmp/edr-678-run-live-probe.py --output /private/tmp/edr-678-client-acceptance/postdeploy-687-cache-final.json
python3 -B /tmp/edr-674-probe-compare.py /private/tmp/edr-678-client-acceptance/predeploy-687-cache.json /private/tmp/edr-678-client-acceptance/postdeploy-687-cache-final.json
python3 -B /private/tmp/edr-678-client-acceptance/run_687_upgrade_receipt_after_observation.py
python3 -B /private/tmp/edr-687-acceptance-prep-48o12l8r/upgrade_task_readonly.py --task-id agent_upgrade_1792104294189391000 --baseline /private/tmp/edr-678-client-acceptance/upgrade-687-baseline.json --upgrade-probe /private/tmp/edr-678-client-acceptance/upgrade-687-local-journal-after-observation.json --upgrade-invocation /private/tmp/edr-678-client-acceptance/upgrade-687-local-journal-after-observation-invocation.json --require-complete --output /private/tmp/edr-678-client-acceptance/upgrade-687-final-verified.json
python3 -B /private/tmp/edr-678-client-acceptance/command_result_verify_readonly.py --command-id cmd_rtq_ep-ff84e69e4_1792104472258618000 --version 3.2.687 --local-probe /private/tmp/edr-678-client-acceptance/rtq-687-pid8400-command-owner-byte.json --output /private/tmp/edr-678-client-acceptance/rtq-687-pid8400-command-result-verified.json
```

These exclusive-output commands are a record of execution, not instructions
to rerun mutations or overwrite evidence. Final cache JSON SHA-256:
`3412525df4543446e2875c08ad5faba56fc530a41a95331a08a5f57044d1e2b9`.
The final UI screenshot is
`/private/tmp/edr-678-client-acceptance/deployment-687-headless-completed.png`.
The Windows sustained-load/device-I/O/power-loss and actual wire-body closure
conditions below remain explicit. No absent cached-query consumer or historical
candidate preservation gap is certified by the successful Headless deployment.

## 2026-10-16 historical 687 preparation: final retrieval boundary review

The existing client UI and backend implement live `rtq_execute`, not a callable
cached-evidence `rtq_query` producer. The successful PID 8432 operation below
therefore proves only its live query and durable result owner. The backend's
permission/catalog aliases are not an executable cached-query route. No generic
command API, new remote-control authority or backend database insertion was added.

An Agent-only ingress mismatch was found at source `1b3fb19f`: the cached parser
and final result gate support exact process generations, but
`k_cached_query_rules` rejected `endpoint_id`, `process_start_key` and
`process_creation_filetime_100ns` before reaching them. Existing deeper-layer
tests did not establish compatibility with the real command-contract entrance.
The scoped follow-up aligns that existing entrance and tests it; it does not
create a backend producer or change routine uploads. At this preparation
checkpoint candidate 686 was still in CI. It was not downloaded or installed;
the final 687 candidate subsequently passed its own native gates above.

### Interface proposal for a future authorized cached-query consumer

This is an interface and acceptance proposal, not an exposed HTTP API. The
current internal contract derives result purpose from command type and binds
tenant/endpoint through authenticated delivery plus the local configuration.
Signature canonical bytes bind command ID/type, idempotency key, issue/deadline
and payload digest; tenant and endpoint are not separate canonical fields.
Neither a signature nor a syntactically accepted field proves business necessity.

| Required boundary | Current implementation and condition before exposing a consumer |
| --- | --- |
| Tenant, endpoint and task | Preserve authenticated tenant/endpoint routing, local configuration and signed command/task ownership; reject cross-scope requests and result receipts. Any future producer must derive these identities from its authorized investigation task, never an arbitrary UI payload. |
| Business purpose and fields | Require an authorized investigation purpose and a necessary returned-field allowlist. Current cached queries have a fixed projection, with complete command text omitted unless explicitly requested by their existing filter contract; there is no request `fields` key. A future producer must not infer necessity merely from authorization. |
| Time and process generation | Bound the requested event interval and exact process instance. Current internal queries use issue time minus `time_window_s` with an existing 300-second future tolerance, not a caller-specified closed interval. Exact generation fields are decimal uint64 strings; PID alone is not a generation. |
| Bytes, lifetime and pins | Intersect caller limits with server/local limits, include JSON encoding overhead, and reject expiry, cancellation or pin exhaustion. Current internal result authority is fixed at 16,383 bytes and `do_rtq_query` further limits detail to 11,999 bytes; request `max_bytes` is unsupported. |
| Missing evidence | Preserve `outside_retention_window` / `not_collected_or_expired` and `absence_is_evidence=false`; lack of a row is not lack of behavior. |
| End-to-end acceptance | Before exposing a producer, exercise its actual signature verification, receive validation, local SQLite query, real result encoding/final gate and durable consumer receipt. Cover wrong scope/task/generation, extra fields, expiry, byte/pin exhaustion and absence. Existing local tests start no network and do not certify this absent producer. |

The source audit is `/private/tmp/edr-cached-rtq-producer-audit-1b3fb19f.md`,
SHA-256 `b8960a6ab2e0086640a0f1fef500a9ccd35afdfcb9013f5eb34fedd3cbc22621`.
The old-source regression actually fails at the entrance with the new exact
endpoint/generation request (CTest exit 8); after the correction, all three
focused contract/result/local-query tests pass. Their raw commands, RED/GREEN
outputs and source digests are under
`/private/tmp/edr-cached-rtq-ingress-pceb67m5/`; manifest SHA-256 is
`9f5492b6ffbe3e73d2745a6cca16aedeecefca3eb40d86ad4ecc81e92a55b25a`.
The local-query fixture first invokes the production ingress validator, then
uses real SQLite and RAW/LZ4 encoding, a reused PID with two process generations,
the durable result owner, HTTP JSON and final gate. It rejects wrong endpoint,
mixed generations and individually forged scope fields. It explicitly reports
`signature_verified=false` and `network_started=false`; separate signature/TLS
tests do not turn this fixture into a signed cached-query end-to-end test.
The complete host runtime/telemetry regression then passed **67/67** in 131.33 s
(54 runtime and 31 telemetry cases with overlap). It includes the existing
cross-language signature and real loopback mTLS tests. All 1,068 tracked C/header
file bytes stayed unchanged throughout the build and run. Commands:

```sh
cmake --build /private/tmp/edr-cache-assessment-egress-build --target edr_agent agent_runtime_gate_tests telemetry_minimization_tests -j4
PATH=/opt/homebrew/opt/openssl@3/bin:$PATH ctest --test-dir /private/tmp/edr-cache-assessment-egress-build --output-on-failure --no-tests=error -L 'agent-runtime-gate|telemetry-minimization'
```

Raw build/test logs, source digests and actual command results:
`/private/tmp/edr-687-final-gates-wm455m_6/`; `RESULTS.json` SHA-256 is
`ca9c60bf0e6efe0455fd46222b2649bdda69708c327d0a45fbf22ab6c6b240e9`.
These host checks retain the documented macOS sensor/P0 stub limits. Windows
gates and the single-client Headless upgrade were pending at this checkpoint
and are recorded in the final section above. Storage/codec
implementation bytes are unchanged from the measured 3e8 benchmark below;
that benchmark is not relabeled as a new measurement of this contract correction.
The older aggregate acceptance table below is the historical 684 checkpoint;
subsequent source, CI and client sections record later observations without
turning the original missing two candidate samples into preservation passes.

### Windows conditions that remain separate from this delivery

An installed-client quiet interval cannot prove a 72-hour retained history.
Native Windows performance closure requires the same measured unique/repeated/
high-severity inputs and encoded sizes, running beyond the configured windows,
with CPU, issued and device I/O, sampled and continuous physical peaks, retained
event times and exact-generation dependency reconstruction recorded together.
That load must use disposable synthetic stores, not delete real endpoint caches.
Hardware power-loss closure requires interruption during real filesystem commit
and restart with ledger, frozen identity, idempotency and receipt verification;
child-process crash tests are narrower evidence. Final routine-upload assurance
uses real encoders/final gates and the synthetic TLS consumer; a claim about
actual endpoint wire bodies additionally requires an authorized scoped capture
and comparison of received fields. No such capture is claimed here. The two
historically missing candidate samples remain unclosed preservation gaps within
the authorized evidence scope;
new samples or a successful upgrade cannot close them retroactively.

## 2026-10-16 candidate 686 preparation: 685 reopening recovered, health fix verified locally

The local runtime change is `3e8e73c7e01bfee8f90bdd682db07202194392bc`.
It restores only the existing evidence-pressure health boolean and its closed
store meaning; it does not change retention, upload or startup deadlines.
The four focused host checks and actual mTLS producer/projection checks passed.
Windows CI and deployment were pending at this historical checkpoint and
subsequently completed in 687 above. Only Headless
client artifacts will be downloaded; no Setup UI package is a client input.

The first 685 startup failure below remains preserved. One controlled restart
of the same installed 685 bytes subsequently recovered actual native opening.
The first restart helper refused in preflight because an unnecessary historical
journal enumeration exceeded its diagnostic count limit; it issued no stop or
start. That original result SHA-256 is
`0b81ae587ce3389cc8bf60cd624dbe9af623457199d36b7ae457e26efd45ce6a`.
The replacement removed historical journal reads instead of increasing that
limit. It checked the exact completed 685 journal/checkpoint, current task and
process generation, no running local updater, and a fresh backend count of zero
unfinished upgrades for this endpoint. It did not classify or delete history.

The actual restart issued one stop and one start through the existing
`FDSecurityAgent` task. No fallback kill, timeout or recovery start was needed.
The Agent, launcher, configuration and task definition hashes stayed unchanged.
New PID 8432 has guest CIM birth `2026-10-15T21:24:10.7171330Z`, version 3.2.685,
and the same installed Agent SHA `1bccb92f...c1307`. Restart result SHA-256:
`b974081ae2582a65d4c9881153b1bad9fa84a8964cc6d9c74937ec9879b93e06`.
Guest creation time and health report time remain separate clocks.

The first new-generation health report has `db_open=true`, physical guard
failures 0, cause 0, and connected/leased control stream. It reports 7,950
legacy candidates at opening. DB bytes are 530,051,072 and sampled physical
DB/WAL/SHM bytes 535,942,512; near-budget occupancy is not itself a failure.
This first report also has resource pressure during initialization and zero
candidate admissions/rejections, so it is not sustained-write acceptance.
Health result SHA-256:
`37ce315f4aeddc80a5f5b4f9eaff48254890d56faa55e8c9a050451013bc7671`.
The bounded post-restart cache probe now reads all supported components,
matches all nine queue ledger categories and preserves the three original
sampled owners' immutable bytes/identities/ACK flags. Its SHA-256 is
`080cafe42e1f30e5b1d742f89ebd2059ecbf8412b66550656a15b2a8ef0c6f85`.
No real cache cleanup or manual migration was performed. This proves current
native reopening recovered; the original transient cause is still unknown.
A later fresh 8432 report at backend report time 21:34:01.162 remains open,
with zero guard failures and resource pressure cleared. Control stream is
connected/leased, P0 is ready with the same r289 artifact hash, and policy v528
has a new-generation verified/applied receipt with matching hashes. Candidate
requests/admissions/rejections still read zero in this quiet interval; this
does not establish sustained field writing or a seventy-two-hour window.

An actual client RTQ query targeted only this endpoint and `pid = 8432`.
Session `rtq_1792099754845833000`, run `rtqrun_1792099754918708000` completed
with one success, zero errors, and one FDSensor row. The durable run has
`status=success`, PID range 8432..8432, and exactly four row keys:
`type`, `name`, `path`, `pid`. No command line, user or process tree was requested
or returned. The initial metadata verifier mistakenly expected `completed`,
which is not `rtqRunStatus()`'s success value; its original failure is retained.
The original snapshot was reclassified offline using the authoritative success
contract, without repeating the query. The exact command is
`cmd_rtq_ep-ff84e69e4_1792099754918710000`; its stable local final is success,
exit 0, PID 8432, pending 0 and no held/error state. Local/server result length
390 and SHA `de6441e50dbf6f1bc0165efbcd71746d5b4e0e8c8221e8deb6c13ad6f136b789`
match, and the actual durable result verifier reports both `accepted=true`
and `execution_succeeded=true`. Receipt result SHA-256:
`48970b7f2aa9e4f5747e16ae6e227814ade708da8a993fa7cb5998278e9a0feb`.
The combined offline reclassification SHA-256 is
`160e90cb7bf212d7f14be5866096f29b295c6337739ca87358020a468fd595a4`.
This closes the sampled live-process `rtq_execute` consumer/result-owner check;
it does not certify cached-evidence `rtq_query` or independently captured
network application ACKs.
Screenshot: `/private/tmp/edr-678-client-acceptance/rtq-685-pid8432-completed.png`.

A fresh same-protocol benchmark binds all 1,068 tracked source/header bytes to
3e8 before and after execution, including the actual current codec objects.
Three original commands passed once; evidence variants use five fresh runs
each and queue variants one run each. Full results and commands are under
`/private/tmp/edr-evidence-health-3e8e73c7-kdw6tlbd/`; `RESULTS.json` SHA-256 is
`cce60dacad007def38bef3b0d484a08e38db3e2a56148493c3c038f478c42e84`,
`SUMMARY.txt` SHA-256 is
`1ce0f5b2ee1a8c37417e626e94a71d03ae94e0cfbafcfab0b22ddff61596fa61`.

| Evidence case: 8 MiB, 192 candidates + 48 facts over eight simulated hours | Old 673 / 1 h | Current / 1 h | Current / 4 h |
| --- | ---: | ---: | ---: |
| Selected candidates | 6 | 6 | 24 |
| Self-contained parent bindings | 0 | 6 | 24 |
| Reconstructable with process cache | 6 | 6 | 24 |
| Actual selected timestamp span, seconds | 20 | 20 | 10,820 |
| Median process CPU, seconds | 0.171884 | 0.303208 | 0.288581 |
| Sampled physical peak, bytes | 2,305,312 | 3,272,648 | 3,379,192 |
| Final physical bytes | 2,251,752 | 677,048 | 791,832 |
| VFS issued write bytes | 17,364,348 | 31,429,500 | 28,981,320 |

With the identical 1 MiB logical queue and 48 unique 128 KiB real BAT1 inputs,
old 662/current admit 7/36 and refuse 41/12; latest retained age is 36,070/60 s.
The 20-byte terminal is refused/accepted with exact readback and zero ordinary
source uploads in the sender-stub scope. CPU is 0.148379/0.316862 s and sampled
physical peak 1,890,896/4,956,096 bytes. SQLite total changes are 106/347.
Current four-hour evidence CPU (+67.893%) and queue CPU (+113.549%) cost more in this
synthetic comparison; there is no performance-improvement claim. Retention,
binding, physical samples and issued writes match the earlier 1ba experiment;
CPU/read differences are separately recorded and not attributed to this health
change. These remain macOS debug/synthetic measurements, VFS rather than device
I/O, sampled peaks rather than a directory hard cap, one parent generation per
candidate rather than arbitrary chain completeness, and 3 h 20 s of timestamp
span rather than a continuous four-hour or UTM 72-hour retention guarantee.

## 2026-10-16 candidate 685: installed, evidence-store startup not accepted

Runtime source is `1ba4e34cc0b656c7cc1d7d31fa19db20f5d84c2d`, branch
`codex/rtq-result-delivery-pressure`, 28 commits after audit 662 and 19 after
the requested comparison SHA. [CI run 38794126996](https://github.com/qiuxinliang/edr-agent/actions/runs/38794126996)
completed successfully at 20:11:26 UTC on October 15. All seven jobs succeeded.
The actual native Test-step intervals, excluding runner self-tests, contain
100 release and 13 remaining telemetry cases per architecture, 113 unique:

| Architecture | Release / remaining | CTest group durations |
| --- | --- | --- |
| AMD64 | 100/100, 13/13 | 334.09 s, 191.77 s |
| ARM64 | 100/100, 13/13 | 480.54 s, 214.15 s |

Both real Setup and separate runtime lifecycles passed 684 -> 685 -> 684.
Conditional unsigned/USB skips remain skips. The Setup assertions do not
independently measure its installed Agent SHA; the binary-hot lifecycle's
installed hash is evidence for that separate path only. Complete decoded-LF
job logs and step/skip audit are under
`/private/tmp/edr-685-release-draft-5aw5euur/monitor/`; final audit SHA-256 is
`cd06663b890bf9ab5abf206bb1f48a9994e0e53c74887ba9c7c68dce87af00c1`.

Release `414191493`, tag `win_3.2.685`, is a candidate; GitHub latest remains
591. Only the manifest, raw ARM64 Agent and Headless ZIP were downloaded and
imported through the actual client. No Setup UI or separate Setup download was
used. Headless pin `headless-artifact-pin.json`, SHA-256
`6dfe4b85857d6f4ec74cbabf6f52768d656c4272f3696db75812a55948c666c8`,
binds source, run, release, actual native gates, runtime closure and these files:

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| Manifest | 2,367 | `19d737aea7862b408026fe76c8d5338de6d57b5390a25be98dc0f25db104f3f8` |
| ARM64 Agent | 3,213,824 | `1bccb92f01b8aaafebb2803e74f1f6b73c472de213367ba60839f0b34c2c1307` |
| Headless ZIP | 14,215,708 | `6944daa8204dafb064a4ba5aba9917cf44abce45e239bd23966ace65aa29c151` |

The ZIP's embedded installer hash is
`d0afeb21150bb122498cf364c1f5a14b4c8d4dc9298dec89c75002f47e020804`.
The existing client created artifact `artifact_1792095336606925000` with no
Setup UI binding. Exactly one UTM upgrade was submitted:
task `agent_upgrade_1792095442526674000`, command
`agent_update_1792095443218661000`, runtime package 244/hash
`36db0124269b7fab0119b0dbc3d72f54718cf6768c89dfe0c03d0a06fa259a09`.
It entered installation at 20:17:32.237 UTC and the backend task completed
at 20:24:18.211 UTC, with no failure code. The observation configuration is
300 seconds; recorded health_check_at 20:19:46.836 and deadline 20:24:16.836
span 270 seconds. These fields do not independently attest 300 continuous
healthy seconds.

The installed `C:\Program Files\FDSecurity\FDSensor.exe` reports 3.2.685 and
matches the exact raw Agent hash. Its new process is PID 3272, with guest CIM
creation time `2026-10-15T20:19:16.9830310Z`. The existing scheduled-task owner
and 512 MiB/72-hour queue and evidence overrides remain. Selected retention
therefore also derives to 72 hours; this deployment did not shorten the recent
window or promise a longer interval under arbitrary load. Guest creation,
source-health clocks and backend receipt timestamps are distinct observations.

The exact local journal is succeeded, scope-matched and stable during read;
last event 6 has checkpoint ACK 6 with no policy hold. The task verifier ran
with `--require-complete`, the fresh exact baseline, journal and invocation:
`backend_and_local_upgrade_completion_verified=true`. Its result SHA-256 is
`adb6128371094c65a287bc937d8258b07b6960456870f895988697063d804399`.
This proves successful upgrade/event delivery, not every evidence capability.
The earlier 684 failure's cause remains unresolved: one later success after
diagnostic changes, prelaunch hash I/O and a different load/time is not a
controlled causal repair of that historical failure.

Two new 685/PID3272 health reports have increasing backend receipt times
20:20:17.277 -> 20:24:17.829 UTC, connected/leased control stream, P0 ready and
artifact healthy. The signed policy receipt is verified/applied at version
528 with matching desired/reported hash. Original three queue owners retain
identical sampled immutable fields and ACK flags. Ledger categories are
exactly 0..8, each matching recomputed bytes/rows, with zero invalid costs;
the sampled sum is 122,552,867 bytes / 70,167 rows. Independent summary SHA-256:
`53abe48e95a4b7722d1c657df7b48be27f6e27a24f45746f14dfb91a54ba2d0b`.
The original two missing candidate samples are not replaced or certified.

**Overall evidence-store acceptance is still false.** Both health reports
show `db_open=false`, `physical_guard_failures=1`, cause 2, and all five
observed candidate admissions refused. The main evidence file is 523,784,192
bytes, sampled DB/WAL/SHM total 529,275,992 bytes. Near-budget occupancy alone
does not explain or excuse failed opening; retention counters initialized
before successful opening do not prove an empty legacy inventory.

The launcher's inherited startup stderr was read within bounds and was empty.
Current source redirects diagnostics to configured `logs/agent.log` before
subsystem initialization. A second exact-path/new-process check read only its
first/last 64 KiB and emitted fixed classifications, no raw lines: one
`physical startup index accounting failed or exceeded 10s; existing cache preserved`.
The log was stable during that read; result SHA-256 is
`5e4fe09d19aa733fa320845cabf7214d76257f243de95e7a8a17252994877522`.
That combined error does not distinguish prepare/bind/step/type/allocation
failure from the ten-second progress deadline. No timeout increase, real-cache
cleanup or speculative runtime patch follows from it.

A separate 8-second read-only schema/EXPLAIN diagnostic found 16 missing
declared indexes; all generated inventory SELECTs prepared successfully with
guest Python SQLite 3.49.1, without executing any row-data query. It completed
in 46 ms internally and preserved the DB's identity/size/mtime; result SHA-256
`c35a6a5e81109f19cf0156db087f164cf06e7fdd26268d65e2f4ce55205f1adc`.
This does not certify the Agent's linked SQLite or actual aggregate execution.
An isolated replay of the production startup inventory remains required.

The attempt to use that installed Agent DLL from the diagnostic PowerShell
host did not reach SQLite. The second, explicitly loaded attempt returned
Win32 193 in 13 ms, with the DLL digest unchanged and no database opened.
Its original result SHA-256 is
`eb70f125c795c43bf9f8bc01b1bab5358d33de10c6121b2334fe53c2c809197f`.
`IsWow64Process2` returning process-machine 0 / native-machine ARM64 does not
establish the CLR host's compatibility with a pure ARM64 DLL. This is a
diagnostic-host loading failure, not evidence of an Agent SQL failure or of
the ten-second inventory deadline. The earlier generic loading failure is
also retained; neither attempt read evidence rows.

One subsequent read-only execution of all seven exact inventory aggregates
completed in 1,421 ms with guest Python SQLite 3.49.1. Every result had integer
type and rc 0; artifacts took 1,015 ms and p0_candidates 281 ms. No aggregate
value or individual row was exported, and DB identity/size/mtime remained
unchanged. Result SHA-256:
`74485ddc8f79d59cd996eaf969116dbb4664d5e4f4d766f67cac40501c53e7eb`.
This read used a 200 ms busy timeout and the current, potentially warm state.
The Agent's owner has no busy handler here and uses SQLite 3.53.4 in its
startup connection. This rules out a reproducible failure of these scans in
the diagnostic's conditions, without identifying the earlier startup cause.

A separate, not-yet-released health correction restores the existing
`evidence_cache.pressure_active` boolean to both real health producers and
the final minimal projection. The status snapshot treats an unavailable
durable store as degraded; the ingestion throttle predicate is unchanged.
The existing backend consumes this boolean and the existing frontend derives
degraded display status from it. No backend deployment, additional evidence
fields, error text, paths or commands are required. Four focused host checks
passed, including actual mTLS basic/diagnostic requests for closed/open
synthetic caches and full/delta field gates. The first sandbox loopback bind
failure is preserved, followed by a successful run of only that affected
test. Result SHA-256:
`09366f1efdd993976f80128ee165fce458e029a117123b8d97e4e80f4833fe91`.
The oversize capability-only fallback has source review, not a new exercised
oversize case. Windows and endpoint validation are pending. This correction
does not repair the evidence store's startup failure.

The old C# command probe returned a generic parse/read failure. Its strict
UTF-8 decoder runs before command filtering, so unrelated old invalid UTF-8
can abort it; that output alone cannot prove the actual exception. A new
fixed-command diagnostic, tested with 27 synthetic cases, reads bytes first
and strictly validates matching JSON only. One 15 ms read found the exact
upgrade final, success/exit0/PID3272, pending0/held0 and stable owner metadata;
only status, lengths and hashes were exported. It neither repairs nor
certifies unrelated legacy rows. The existing generic backend-result verifier
found zero rows for this command; its original `accepted=false` result remains.
Source review of both 673 and 1ba confirms that this direct-UI agent_update
task uses the dedicated journal/event consumer. `command_should_report()`
requires SOAR/playbook association, an explicit environment opt-in or a cmd_
prefix; ordinary agent_update_ dispatch does not request generic reporting.
After terminal journal/checkpoint recovery, `soar_emit_ex_policy()` may write
the local final with pending0 directly, without mark_reported. Backend
`PostAgentUpgradeEvent()` / `ApplyEvent()` commits the corresponding
agent_upgrade_events/task transaction before accepted=true and does not write
endpoint_command_results. Thus the generic-table verifier is inapplicable to
this task; its zero rows are not evidence of false ACK or loss. The specialized
require-complete correlation above is the applicable successful consumer
boundary. General RTQ/result delivery remains a separate acceptance item.

The closed backend-receipt metadata window 20:20:17.277 -> 20:29:00 UTC
contains zero batches/jobs/events and one unrelated isolate_status result,
without truncation or hash mismatch. No payload/detail was retrieved; wire
verification and negative-wire claims remain false. Admission generation is
unclassified and may represent old frozen backlog. This is not proof of
current encoding, useful event delivery or actual wire minimization. Its raw
metadata summary SHA-256 is
`b4655068c477a3e720ab591aa042c7480d1c3577f136cc882f0e96b6d8156ad9`.
All scoped client evidence and first diagnostic failures remain under
`/private/tmp/edr-678-client-acceptance/`. No RTQ or second upgrade has been
issued after this 685 deployment; evidence-store startup is the active blocker.

## 2026-10-16 inventory failure classification: diagnostic change

The direct native CLI, Guard launcher, current SYSTEM-task and isolated
old-scanner/six-worker checks below did not reproduce the actual installation
failure. The remaining live boundary is the active installer context. Historical
child exit 7 combines distinct admission outcomes and cannot identify which
occurred. This change makes the existing failure useful to the existing Inno
consumer; it is **not a root-cause repair or a completed deployment**.

Only the original expired-return branch is classified. The original success
condition, one queued byte lock, one-second admission, cancellation/completion,
unlock error precedence and 15-second CLI watchdog remain unchanged. No new
configuration, output file, table, thread, retry, upload or authorization was
added. Ordinary runtime locking and STARTUP policy behavior
are unchanged; the new mappings are restricted to READ_ONLY inventory.

| Observed admission outcome | Child exit / fixed reason |
| --- | --- |
| Other existing expiration without an acquired lock | `7 / owner_lock_timeout` (unchanged; not proof of continuous contention) |
| Acquired lock present, final admission check expired | `9 / owner_lock_granted_expired` |
| Initial deadline check expired before LockFileEx submission | `10 / owner_lock_deadline_before_request` |

Exit 9 does not establish when the kernel granted the lock: caller scheduling
after an earlier grant also satisfies it. An unlock failure still overrides
expiration classification and yields accounting failure. Expired admission
never authorizes an owner scan, and every nonzero result prohibits successful
floor output as before. The Inno process can
itself return outer installer exit 7 after any rejected child; diagnosis must
read the existing log's `stage=child_exit` code and fixed reason, not confuse
that outer installer code with the preflight child's code.

The existing installer log also gains a SHA-256 of the extracted preflight
executable immediately before invocation. It reads only that already extracted
binary and logs a fixed hash field, with no temporary path, environment or owner
content. This one additional binary read occurs before the native CLI starts;
it does not extend CLI admission/watchdog limits. The existing exception handler
rejects hash/read failures. This supplies the missing prelaunch-image identity
for the next attempt, rather than inferring it from an installed VERSION or
another test's binary-hot replacement. It does not retrospectively attest the
684 child or independently measure the loaded image after launch. The supported
Inno [built-in hash function](https://jrsoftware.org/ishelp/topic_isxfunc_getsha256offile.htm)
requires no added dependency.

The permanent Windows fixture uses real kernel pending/completion events for
7/9, a test-only 1,100 ms monotonic delay after event creation for 10, and an
immediate-acquisition/completion-delay case for 9. A combined expired-grant plus
failed-unlock case requires exit 4, no scan/floor and handle-close release while
the child remains alive; it does not claim a successful Unlock. Inno tests
exercise refusal for 9/10 and compare the actual extracted image hash with the
supplied executable. Bounded-redaction tests preserve both reasons and the hash
after a long prefix. Production builds contain no environment-selected test
mode. No further actual upgrade has been issued.

Local validation at this source checkpoint:

- Built `edr_agent` and `storage_space_preflight_client`, then ran
  `ctest --test-dir /private/tmp/edr-cache-assessment-egress-build --output-on-failure -R '^storage_space_preflight$'`:
  pass, 0.78 s. The host build retains its previously declared nonproduction
  PCRE2/P0 boundary; this diagnostic does not claim host P0 enforcement.
- The first packaging-contract execution used a stale test executable and
  failed an assertion absent from current source. After building the specific
  `test_agent_update_assets` target, its case passed in 0.74 s; after the final
  Guard/hash edit it passed again in 0.01 s. No assertion or workflow was
  weakened. Original failed and corrected logs remain under
  `/private/tmp/edr-preflight-classification-host-48pnqoof/`.
- Fresh MinGW AMD64 compilation (18 translation-unit invocations, two links,
  no reused objects) and all input digests passed. In the single isolated UTM
  run, the permanent Python fixture with `--client fixture.exe` completed in
  22.703 s, exit 0, with all 11 classification/failure cases and zero stderr.
  Pending cancellation remained 7 (1.047 s); late/completion/immediate-completion
  expiration returned 9 (1.031 / 1.125 / 1.125 s); the expired-grant/unlock failure
  returned 4 with no scan (1.125 s); before-request expiration returned 10 with
  no lock request/scan (1.140 s); the actual CLI watchdog self-exited 124 at
  15.031 s. No parent timeout or forced termination was needed.
- Each non-watchdog case proved a third-party handle could reacquire the byte
  while the test child was alive. Both injected unlock failures rely on final
  handle close, not successful Unlock. The watchdog case has no live-child
  reacquisition assertion. Every case checks the synthetic owner SHA, and the
  whole suite checks owner/parent owner-group-DACL preservation; this is not a
  claim about SACL, config, lock hash/ACL or hardware power-loss behavior.
- Three current PowerShell files parsed in Windows PowerShell 5.1, and the real
  updater's bounded redactor passed all 30 synthetic cases, including 9/10 and
  the prelaunch image digest. This UTM has no Inno compiler at the standard
  installed path, so the new Inno includes/hash assertions remain pending CI;
  no compiler/package was downloaded.

Raw fixture results, original rejected execution plans and corrected plan are
under `/private/tmp/edr-preflight-classification-fixture-x0v9_bas/`.
Corrected plan SHA-256 is
`4bc5263d7ae6fad8a6de58ec43c64df0e36ed5dda12e577a3235835c0d6a8a0c`;
result SHA-256 is
`baf166a94f054f3bd756cd5ec0dadc316944fbf1ee7ca09cd4fb672e8b865d85`,
stdout SHA-256 is
`03fc991da8f1741f5c7e6cf324e4374e834e33f765bc06b39a1306409413a4ba`.
The PowerShell result is `ps-run.json`, SHA-256
`b067ce2f5df509ab87af32e4ad8a867f36af7e0789790a453f9e4c9a0df2365a`.
Independent review verified the source/cleanup boundaries and raw result
identities. These are emulated AMD64 diagnostics on ARM64 Windows, separate
from the forthcoming native MSVC gates and installed-client acceptance.

## 2026-10-16 final-source retention comparison

The original comparison predates later queue/evidence edits. Both existing
protocols were therefore executed once again against clean source
`1ba4e34cc0b656c7cc1d7d31fa19db20f5d84c2d`, without changing inputs, budgets,
assertions or older artifacts. All 1,068 tracked source/header files in the
current snapshot matched that commit and the working tree byte-for-byte;
actual linked C inputs and the freshly checked codec dependency set matched.
One copied, untracked generated Python file was unused by C compilation.

The evidence comparison uses the same 8 MiB budget, one-hour recent target,
192 candidates and 48 low-severity context facts over eight simulated hourly
bursts. Each variant has five fresh samples; medians are:

| Metric | Old 673, selected 1 h | Current, selected 1 h | Current, selected 4 h |
| --- | ---: | ---: | ---: |
| Selected evidence | 6 | 6 | 24 |
| Parent chain complete inside retained manifest | 0/6 | 6/6 | 24/24 |
| Reconstructable with manifest or process cache | 6/6 | 6/6 | 24/24 |
| Actual selected-event timestamp span | 20 s | 20 s | 10,820 s |
| Sampled DB + WAL + SHM peak | 2,305,312 B | 3,272,648 B | 3,379,192 B |
| Final pre-close DB + WAL + SHM | 2,251,752 B | 677,048 B | 791,832 B |
| Process CPU | 0.159455 s | 0.285535 s | 0.279193 s |
| SQLite VFS issued writes | 17,364,348 B | 31,429,500 B | 28,981,320 B |

The old version's missing manifest links do not mean all chains were lost:
the process cache could reconstruct its six retained parent bindings. The new
four-hour selection retains 24 self-contained bindings and measured timestamps
span three hours and 20 seconds under the hourly-burst input. This is one known
parent generation/name per candidate, not proof of arbitrary attack-chain
completeness or continuous sampling. Four hours is an explicit test setting,
not an unbounded-load promise or a change to the UTM's 72-hour overrides.

The increased value has measured cost. Current four-hour CPU is 75.092% higher,
issued VFS writes 66.901% higher and sampled physical peak 46.583% higher than
old one-hour retention; final pre-close physical sum is 64.835% lower. The
current one-hour costs are also recorded above. These regressions are not
presented as a storage/CPU optimization.

The queue comparison uses the same real protobuf BAT1 input stream: 48 unique
128 KiB records over 12 simulated windows, a one-hour target and a 1 MiB logical
budget. The old queue implementation is audit 662, sharing the current codec,
time utility, ACK parser and other headers; this is not an old-Agent binary
performance comparison.

| Queue metric | Audit 662 | Current |
| --- | ---: | ---: |
| Total admitted / refused | 7 / 41 | 36 / 12 |
| Final-window admitted / refused | 0 / 4 | 3 / 1 |
| Retained rows / valid embedded parent fields | 7 / 7 | 3 / 3 |
| Retained event timestamp span | 3,721 s | 120 s |
| Latest retained event age | 36,070 s | 60 s |
| Sampled DB + WAL + SHM peak | 1,890,896 B | 4,956,096 B |
| User + system CPU | 0.140968 s | 0.314808 s |
| SQLite total_changes proxy | 106 | 347 |
| 20-byte terminal admitted / exact readback | no / no | yes / yes |
| Source upload calls | 0 | 0 |

Current rotation sustains three admissions and one explicit refusal per window;
it retains a shorter but fresh interval rather than old frozen inventory.
Critical reserve admits the exact 20-byte terminal without sending local facts
or fabricating ACK. This embedded-parent-field check is not a traversal of
separate parent entities. CPU is 123.319% higher and sampled physical peak
162.103% higher. The 1 MiB logical budget is plainly not a physical hard cap.

Commands, compiler flags, complete source snapshots, library identities,
per-run raw stdout/stderr and checksum index are under
`/private/tmp/edr-evidence-685-33286iba/`, with `SUMMARY.txt` SHA-256
`8b79eadb23355b8c9393e0a3bbf2c3390f395e0e0352ef4db8bc0daef85f5a54`
and `RESULTS.json` SHA-256
`2020c633c4a2a430466eb8b6359b389034c3438da40468764515aecc6d5966f3`.
Actual commands were:

```sh
cmake --build /private/tmp/edr-cache-assessment-egress-build --target edr_egress_policy --verbose
python3 tests/run_evidence_retention_comparison.py --output /private/tmp/edr-evidence-685-33286iba/evidence --baseline 6bedb86bf9811bc304f4c97fdd62212ef437423f --runs 5
python3 tests/run_queue_retention_comparison.py --output /private/tmp/edr-evidence-685-33286iba/queue --codec-build /private/tmp/edr-cache-assessment-egress-build
```

All exited zero; the protocols ran sequentially. These are macOS test/debug
compilations without release optimization, synthetic clocks/inputs and real
storage/codec code with declared unrelated action/network substitutes. The
unchanged harness version macro is 3.2.642, not the source/release identity.
VFS bytes measure issued SQLite I/O, not device writes; queue OS block counters
are zero/unavailable and total_changes is a mutation-count proxy. Evidence
CPU excludes later reconstruction queries; queue CPU includes fixture queries.
Physical sums are samples, not continuous peaks, allocated blocks or the whole
Agent directory. The evidence fixture records the DB/WAL/SHM sum rather than
separate component values; queue endpoint components and total_changes are
sampled before the terminal insertion. No Windows production-performance claim
follows.

## 2026-10-16 candidate 684: queued inventory release acceptance

Runtime source is `b7c8bd4b279d79fb72ae9db377df50e8f2981a91`, branch
`codex/rtq-result-delivery-pressure`: 25 commits after audit 662 and 16 after
comparison `3de0dc680c78c335f8ab6ba37eef0d0f5d8f46e2`. This task commit changes
only the eight inventory/diagnostic regression files and this report. It
preserves the already-committed build/transport work in parents `3c5eb039` and
`5d12b3c5`. The shared worktree was clean after the task commit.

Candidate 683 was already owned by another run/source, so this repair uses
`win_3.2.684`, [run 38771099974](https://github.com/qiuxinliang/edr-agent/actions/runs/38771099974),
draft release 414041732, dispatched once at 2026-10-15 16:41:24 UTC. Its exact
source/run/P0 owner marker was verified. Fixed P0 remains
`896eb2f06c9ffa608085217d4d1e84494b43e564`, aggregate
`4fe0f9d1d199c95c1e6ce33ce4422d5352c0653369a1b5cc8e875cc678c7a62b`.
The pre-publication snapshot is
`/private/tmp/edr-684-release-run-84zk8mn4/before-publication.json`, SHA-256
`1c2e2dca7afabd63615e588f9ad8da7463c93ebb49699a76314ca2d9421238d1`;
GitHub latest was 591 / 403052409. Normal Git transport failed with HTTP/2
framing and then a bounded HTTP/1.1 low-speed timeout. The existing Git Data
API transport verified all nine blob identities, the exact tree and exact
original commit SHA before a `force=false` fast-forward from 5d12 to b7c8.
No replacement commit, history rewrite or repeated dispatch was used.

Both native build/package jobs succeeded. AMD64's complete original job log
verified actual release 100/100 in 336.78 seconds and telemetry remainder
13/13 in 192.54 seconds. The current runner inventory is release=100,
telemetry=38, telemetry_remaining=13; 25 telemetry cases already passed in the
release group. Earlier virtual runner self-test selections in other steps do
not count as native execution. The permanent `storage_space_preflight` passed
in 18.42 seconds, real Windows CLI in 2.48 seconds, Inno evidence-space test
in 35.25 seconds, and installer redaction in 1.67 seconds. Original AMD64 log
SHA-256 is `3c09b673eb26da17be1ee7f15722ca5eed21b807b3947dc18d04f4a1a38493d8`.
ARM64's decoded job log verified release 100/100 in 483.70 seconds and telemetry
remainder 13/13 in 216.07 seconds. Its permanent preflight, real CLI, Inno and
redaction cases passed in 18.73, 6.64, 88.86 and 22.84 seconds respectively.
All seven jobs completed successfully at 17:17:26 UTC. Both real Setup/runtime
lifecycle jobs exercised 682 -> 684 -> 682 once; they do not cover this live
673 baseline. Setup rollback was enabled and its step succeeded; its separate
stage JSON was not downloaded. The baseline service bootstrap uses
`-SkipPreflight`, distinct from the new Inno preflight. Mode-specific unsigned
USB/signing steps were skipped, not passed tests.

Interrupted log/ZIP transports remain preserved as partials. Complete decoded
job logs were obtained through the GitHub job-log connector instead, with exact
run/source/job IDs and normalized-LF hashes in
`/private/tmp/edr-684-release-run-84zk8mn4/monitor/complete-job-logs-provenance.json`
(SHA-256 `e3f23fce146e7718a34b408b21039d5d41dc0d4a1bd653fc128a84b4a9fd4f0f`).
Actual Test step intervals, all per-case names/ordinals and 100+13 completions
were checked; earlier runner self-test selections were excluded. ARM64's two
CTest summaries omit an explicit failed-count phrase, so only those summaries
were normalized; the 113 individual Passed results remained mandatory. No
complete CI archive or archive CRC was claimed. Independent audit is
`monitor/final-ci-job-audit.json`, SHA-256
`a46effdb616296580d373ec7232fc54d6c96a40e47d6f057767ee1f6ff3ba62c`.

The Headless verifier completed with exit 0 in 19.069 seconds using those job
logs. Only the manifest, ARM64 Agent and Headless ZIP were downloaded, with
SHA-256 `45f56dd1b040f13d0f546a5e75ef1987b31c4f58a4a314810625bd77cd0b2f43`,
`b29b73477d67136257821839993b677c05fe8cf27da885574583ec7caa1322bc`, and
`0d7144b279c0179751a352d319ac2a910a52f59da4be390fa521c32eec5b73b1`.
Runtime closure, ZIP CRC, embedded installer, source/P0 identity and unchanged
latest were verified. No separate Setup or Setup UI asset was downloaded.
The pin is `/private/tmp/edr-684-release-verification/headless-artifact-pin.json`,
SHA-256 `8a15722280ff6468fa14fd7f609e2959a8f1cc88545e6fc0b48a9fc998d0bcc1`.
The revised verifier `verify_headless_from_job_logs.py` has SHA-256
`22d30567f667e9b53fbcc3f50586817191cc0fd52593a5e528d356f78121a2b7`;
the original verifier and its failed transport executions remain preserved.

### Actual single-client attempt: refused and rolled back

The client UI imported exactly those three Headless assets as
`artifact_1792085918951790000`, leaving Setup UI unbound, then submitted one
upgrade for WIN-FAC3AC1PS5O. Task `agent_upgrade_1792086016008146000` and command
`agent_update_1792086018219530000` bind version 684, ARM64, the Agent hash above,
runtime package 242 and package hash
`7076e290bf8532986e307347979ac9cacec75c3fc231657e88f5eb7d5e46bc58`.
Events 1 through 5 match all task pins. The actual terminal event at
2026-10-15 17:41:08.608 UTC is `failed/full_installer_rollback_completed`.
No health-observation phase completed and no further upgrade retry or RTQ was
issued. The redacted installer log again identifies
`stage=child_exit; exit_code=7; reason=owner_lock_timeout` (line 32), followed by
local-storage-preflight failure. Log length is 4,096 bytes, SHA-256
`a31383c758e6043d7c9a61c8c2663f2e155af28c8ebf55a526276b9771acbe41`.
The journal is `failed_rolled_back`, SHA-256
`62df71ecfc24b6983a43bc7d909c37c81579912e39940440cbfbc1944f44a4d8`;
the bounded selected-field reader verified exact task/command/artifact/hash
identity before interpreting it. The coarse report code
`INSTALL_BASELINE_UNSUPPORTED` does not supersede the specific installer cause.

Post-failure identity at guest 17:53:36.5399761 UTC is 673, PID 8316, created
17:40:41.9017470 guest UTC, using the original installed binary hash
`9641df3791f7c1f42fe98ecdce75e44f664ca94e60eb97f3d18a7882054163ca` and existing
scheduled-task owner/configuration. These guest timestamps are not assumed
synchronized with backend UTC. Queue/evidence overrides remain 512 MiB/72 h.
All three original frozen queue owners still match the pre-679 baseline with
no immutable-field changes or ACK transitions. Unsupported old-schema ledger
queries remain unverified, not passed. The two earlier missing local candidates
remain missing and have not been replaced or resampled. Local checkpoint 5
matches the exact failure journal's last event; this proves failure-event ACK,
not deployment success or command-result ACK.

The backend's actual package 242 archive was independently read with exact-ID
scope. Its two members are the original Headless embedded installer and its
unchanged protocol manifest, renamed for the existing full-installer protocol;
there is no graphical Setup UI executable. The actual installer SHA-256 is
`dcd20d5348c466deba8bee0247d1c87a648fbb1e64356eb80cc083145da0579b`, identical
to the Headless member. The endpoint's exact journal-derived staging directory
still contained `runtime-package.zip`, `FDSecuritySetup.exe` and
`FDSensor.next.exe`; all three matched the pinned package/installer/Agent hashes.
This excludes a wrong stored or staged installer. The historical extracted
preflight child's own image hash was not captured, so it is not independently
attested by these staging reads. No broad temporary-directory search was used.

Raw bounded results are in `/private/tmp/edr-678-client-acceptance/`:
`upgrade-684-task-current-01.json`, `upgrade-684-failure-selected.json`,
`upgrade-684-installer-rejection.json`, `postfailure-684-path-identity.json`,
`postfailure-684-cache.json`, `upgrade-684-failure-event-ack.json` and
`upgrade-684-staging-selected.json`. UI rollback proof is
`upgrade-684-rolled-back.png`. Backend package audit is
`/private/tmp/edr-684-package-242-audit-xs_bvt1r/result.json`, SHA-256
`d19635c9771b6aa99aee29bcaae2cd0a82422b0e20b7c9fe3cf4e9d8af0fa933`.

**The live failure remains unresolved.** Exit 7 covers a pending request that
expires, an immediately successful request whose caller resumes after the
one-second deadline, and expiration before submission. It identifies neither
a historical holder nor continuous contention. Existing 673/current owner
paths can perform whole-file scans, sorting and repeated full-line JSON parsing
inside the lock, but their actual live hold times were not measured. No
updater self-lock path was found. The configured 10% resource threshold is not
a Job CPU hard cap; Agent self-protection sets only `BREAKAWAY_OK`, and the
updater is launched through a SYSTEM scheduled task. Those source facts do not
establish a scheduling cause. The subsequent bounded direct, launcher and
SYSTEM-task discriminators below all passed; none reproduces the real active
installation context. Another behavior repair or timeout increase is not
justified by this unexplained aggregate exit code alone.

The exact 673 tag (`6bedb86bf9811bc304f4c97fdd62212ef437423f`) was also traced,
rather than assuming the current updater describes the old one. Its
`installer_required` branch verifies the package, backs up runtime/configuration
while excluding mutable stores, then invokes Setup while the old Agent remains
running. Only its failure handler stops, restores and restarts the old runtime.
Six default executor lanes can each call `has_final` before lane filtering for
the still-retained update inbox, producing independent whole-owner scans.
These are verified possible contention paths, not measured live holders.
The source-bound trace is
`/private/tmp/edr-684-673-owner-trace-efs1okcy/manifest.json`, SHA-256
`6ccd280059e9ba0b844ac1157d04ed568ca6878779a7b913c4f07a5b77ae0a87`.
Its synthetic scan benchmark was deliberately not implemented because a host
timing result would not discriminate this Windows admission failure.

### Bounded direct stock-CLI discriminator

A single direct invocation of the published 684 ARM64 executable completed at
guest 18:08:07.277984 UTC: child 10476 returned 0 in 0.140 seconds with a valid
new floor file containing `143479824`. No timeout, forced termination, output
overflow or incomplete cleanup occurred; both output streams were completely
empty. The original Headless ZIP was verified again, and only its actual
FDSensor plus 20 root DLLs (21 files) were copied into a newly created directory
whose protected inheritable DACL permits only SYSTEM and Administrators.
All member hashes were checked before execution. No Setup or installer was
executed, no configuration was copied, and no Agent initialization, network,
cache migration/maintenance or service/task operation was performed.

The operation used the installed config and explicitly fixed the existing
owner path in a six-variable child environment. The 1,000 ms admission and
15-second stock CLI watchdog were unchanged; an outer 20-second limit targets
only its owned child handle. Output drains are bounded to 64 KiB each and
export only fixed reasons, byte counts and hashes. The wrapper's 32 offline
checks cover input/member digests, unsafe paths, existing/invalid output,
output overflow and exact-child termination with a surviving unrelated
sentinel. Those host tests do not prove Windows ACL/termination APIs; the
actual run verified directory creation/ACL and normal native completion, not
the Windows forced-termination branch.

The owner was 6,379,595 bytes; its size/mtime and the existing lock's size/mtime
were unchanged during this sample. The stock CLI can normalize the lock DACL
and holds the owner lock while scanning; metadata equality is not proof of
zero filesystem writes. Before/after identity reads both identify PID 8316,
the same 673 binary and process creation time. The Agent was not stopped or
replaced by this diagnostic. This does not prove every owner byte unchanged
or reproduce the installation-time load.

Frozen inputs and the actual result are under
`/private/tmp/edr-684-direct-preflight-bx9n96e0/`; result SHA-256 is
`56237552407ff7e5b98915c9449c881eb373a7a9a33d463d8c6e15d75af1a5de`.
Its closure ZIP SHA-256 is
`c369522a9f40c7f179f76e45f9832e31c0134c426c42489ed957c5072815682c`,
containing no Setup/configuration. The independent review confirmed these
results. This proves the pinned CLI can calibrate the current owner in this
controlled launch context, not that the actual upgrade succeeds. Inno's
PowerShell launcher inherits its environment, whereas this diagnostic fixed
six variables; empty Machine/User overrides do not attest historical process
environment. Installation-time contention and inherited context remain open.

A second, separately marked single execution retained the same verified
closure, six-variable environment, config/owner paths and working directory,
but used the exact Guard PowerShell `Start-Process` / `WaitForExit(15000)` /
exit-code path without executing an installer. It returned 0 with the same
valid floor in 1.407 seconds, including PowerShell startup/wait. Both streams
were completely empty, with no forced termination or incomplete cleanup.
The live owner was then 6,381,669 bytes and unchanged within that sample; it
was not frozen to the first sample, so this is not a historical single-factor
replay. It excludes that launcher hop being inherently unable to run the
current pinned CLI under the controlled environment. It does not attest the
historical inherited environment, lock pressure or scheduling. The exact
summary is
`/private/tmp/edr-678-client-acceptance/direct-preflight-684-guard-hop.json`.
The wrapper source SHA-256 is
`ec6ff777016178069fe44be97c7e17a4e99426432282d3e9d398d5f7c607c725`.
If its outer PowerShell process had been killed, descendant exit would have
been explicitly unverified and further experiments stopped; this branch was
not exercised. No further client upgrade was issued.

### Isolated old-scanner overlap: timeout not reproduced

One no-holder control and one concurrent old-scanner case ran in fresh private
UTM directories, with no installed paths or real owner contents read. Both used
the same generated 6,379,595 bytes: 4,096 unique final IDs, half held and half
future not-due, 1,557–1,558 bytes per line and 766–770 detail bytes. This is a
fixed invented distribution, not the endpoint's unknown row count or contents.
The input SHA-256 is
`b6d85f9167e05fbf2c918ccdf4af7924a95571dcac60be194c623aed63922940`.

The 673 scanner and b7 inventory diagnostic were compiled fresh from their exact
commits in 32 translation-unit invocations and two successful links (12.57 s).
Original source/header hashes were independently checked. The old business
code differs only by two row counters and an API observation bridge; lock
parameters/return semantics are preserved. Timing includes the counter and
grant-event observation overhead. Both executables are MinGW AMD64 on ARM64
Windows emulation, not the native ARM64 release or an ARM64 timing guarantee.
The new diagnostic uses existing observe-only test hooks, with no fault,
retry or completion-delay injection. Its preload wait is outside the original
CLI; the unchanged operation still has one-second admission and 15-second
watchdog. The old holder never waits for the controller while holding its lock.

The no-holder control returned 0 in 47 ms. The single real
`collect_pending(..., 16)` scanned and restored all 4,096 rows, returned zero
due results with empty stderr, and held the actual byte lock for 580.486958 ms,
measured after acquisition through successful Unlock return. Concurrent b7
observed real `ERROR_IO_PENDING` (997), completed the lock at 578 ms and returned
0 with a valid floor in 641 ms. Thus overlap was proven, but this fixed
single-scanner load **did not reproduce exit 7**. It does not justify raising
the timeout or declaring the historical failure explained. No workload/row-count
increase or repeated run was used to seek a failure.

Both cases preserved owner/config/lock content hashes and DACL hashes, plus
their directory DACL. Every child exited normally, every event handle closed,
and no forced cleanup occurred. An independent review found a failure-cleanup
short circuit before execution; the driver was corrected to attempt each owned
process and handle independently and fail on incomplete cleanup. The original
driver and exact correction remain preserved, not passed as runtime results.

Build, input validation, independent-review source and actual results are under
`/private/tmp/edr-684-active-inbox-n5saczo3/`. Reviewed manifest SHA-256 is
`3ebf1eafc4e85b115d82dbc44123a99b6f3540e5703986f9c183bb438e13ff20`;
executables are pinned as `d999be9a98f55f55169a04bb79e5969a3655816ab899d304a2c801142c17afd6`
and `6bd1c593772dfe7df7b79beee44eb83ab0dd22523689a80dd503aa11660b715c`.
The host transport completed in 5.493 seconds. Independent review verified the
v2 cleanup, host transport and actual result identities: guest result SHA-256
`2232c19e5ffe5678e5d0357ff3c1851afdaf416b1c987a5a9c87fd755d6f88ec`,
host result SHA-256
`6274d523a3f2d9522a711cd8a82691c394818e3682d5a4389b5b0e454ea4032d`.
The six-lane active-inbox scenario is not implemented by this probe and is not
claimed as tested here.

### Operational owner format: aggregate discriminator only

A bounded read of the installed owner returned only physical-format and
semantic counts, with no IDs, commands, row hashes, file hash or raw data
exported. It used the existing selected-field reader (16 MiB total, 65,536 rows,
1 MiB per row and eight-second deadline), verified stable file identity during
the read and performed no lock/ACL mutation. This was not a replacement sample
of the two missing original evidence candidates.

The first aggregate was 6,394,043 bytes / 5,637 physical lines. A second read was
needed because the first combined decoding and JSON failures. That read was
6,396,117 bytes / 5,639 lines: 5,616 strictly decoded final rows with distinct
IDs, no decoded nonfinal rows, one pending/currently held result and no decoded
future-not-due result. All 23 excluded rows failed UTF-8 decoding; none reached
a JSON-syntax failure. Line lengths were 865..13,404 bytes, with 2,825 / 2,781 /
33 lines in the <=1 KiB / <=4 KiB / <=16 KiB buckets. Parsed detail values totalled
1,410,226 bytes. These parsed-subset counts do not classify the 23 excluded rows
or prove that the owner's protected inventory consists only of those rows.

The whole input contained 4,952 bytes >=0x80. Source inspection explains why a
strict Python decoder and the production inventory can disagree: old JSON
escaping copies bytes >=0x20 without validating UTF-8, while cJSON's string
parser copies ordinary non-backslash bytes without requiring UTF-8. Therefore
the 23 strict-decoder exclusions are not established JSON-syntax corruption or
an inventory-classification failure. No old frozen bytes were reencoded,
reclassified, removed or uploaded. The two reads are separate changing live
snapshots, not a frozen before/after workload comparison.

Results and bounded scripts are under `/private/tmp/edr-678-client-acceptance/`:
`owner-format-684-aggregate.json`, `owner-format-684-aggregate-v2.json`,
`run_684_owner_format_aggregate.py` and `run_684_owner_format_aggregate_v2.py`.
Their physical-size/line-count distribution can inform an explicitly generated
fixture; it cannot reconstruct the endpoint contents, encoding, identity or
causal workload. No native ARM64 compiler is installed in this UTM, so isolated
MinGW diagnostics remain AMD64 emulation and are reported separately from the
published native ARM64 executable and CI gates.

### Current SYSTEM task context, selected fields only

One new temporary SYSTEM/Highest task, with no trigger or restart and a
60-second execution limit, sampled only the two command-owner environment
variables as fixed classifications plus its own process attributes. It did not
open an owner/config path, execute an installer or enumerate another process.
Both `EDR_COMMAND_STATE_DB` and `EDR_COMMAND_STATE_DIR` were `unset`; SYSTEM was
true, priority was `below_normal`, and job membership was true. Membership
alone establishes no Job CPU limit. This samples a new task's current context,
not the failed historical installer or the current Agent's private environment.

The sample exited zero, the exact new diagnostic task was removed, and the
separate host-finally cleanup independently found it absent. No task restart or
retry occurred. The frozen source/plan and actual result are in
`/private/tmp/edr-684-task-context-fj1a21xa/`; manifest SHA-256 is
`428c0a50b38691fdfee4f40d286e269d276ca3e1e5b3e13a73382fdc84ab7628`,
result SHA-256 is
`b7d100b4ca33751adcfd8dc2b7a4a9a2dcf5e4f0d2e4731d869e7360d5847b64`.
The 13 offline input/classification/hash checks are separate from this actual
Windows API/task execution. No current wrong inherited owner-path override was
observed; installation-time contention and the historical context remain open.

### Natural six-worker inbox pair: timeout still not reproduced

The next isolated pair used the exact 673 executor/registry/cancel translation
units, unchanged default 1/2/2/1 workers and normal 1,000 ms idle wait. Its
diagnostic callback allocates 16 records, calls the real lane-filtered inbox
collector, frees the records and returns zero. It does not recover, dispatch or
execute a command; no delivery collector, repeated wake, worker barrier or
injected delay is present. The active inbox is written by real `store_inbox`
against a private synthetic identity before timing. The b7 observe-only
inventory executable is byte-identical to the prior probe, with unchanged
one-second admission and 15-second watchdog.

Both cases use entirely generated 6,396,117 bytes / 5,639 unique ASCII final
rows, matching the physical length buckets above but not the real contents,
encoding, detail/escape distribution or the 23 excluded rows' unknown semantics.
Input SHA-256 is
`3623783e1c672793e4239d8952bfd8b739fbed72cc8247649535548ee0df4d00`.
The first host invocation was refused by the private-directory name guard
before directory creation or fixture upload. That failed record is preserved.
A separate v2 host corrects only the fresh guest path and independent output
names, and evaluates the actual bootstrap/driver path predicates offline.
Neither workload nor binary was changed in response to a runtime result.

The empty-inbox control returned zero in 63 ms; the active-inbox case observed
real `ERROR_IO_PENDING` (997), acquired at 62 ms and completed/unlocked with a
valid floor and exit zero at 109 ms. All six distinct workers each scanned the
full 5,639 lines in the active case; actual acquired-through-successful-Unlock
hold intervals were 19.984375..25.236750 ms. Both cases preserved owner, config,
lock and active-inbox bytes/ACLs and directory ACLs. All processes exited
normally, all handles closed, no forced cleanup or observation overflow occurred.
Independent review verified source provenance, concurrency/measurement boundaries,
the path correction and raw result identity. This natural six-worker synthetic
scenario also **did not reproduce exit 7**, and provides no basis to preselect an
installer/timeout change. Its simplified callback and emulated AMD64 diagnostic
binaries do not represent complete native ARM64 upgrade recovery or the real
installation-time workload.

Frozen source, the successful 19-TU/one-link build (7.178 s), manifest and both
host attempts are under `/private/tmp/edr-684-active-inbox-six-lwgr6op6/`.
Manifest SHA-256 is
`d5ac458d844d7a815018df41a24231e7d1447c17ecdc2c4bbbdd6ba8133dfbb1`;
guest result SHA-256 is
`333621b17feb681f4d13d364da47d25d7fadee3948b9ada0a657b2c52edb80f2`,
host v2 result SHA-256 is
`de288a2a33fd513d64afdba35e697d5bcbfd14e00484649a1d509003042942cc`.

### Native stock preflight inside a current SYSTEM task

One separate temporary SYSTEM/Highest task ran the same published ARM64
executable through the original Guard PowerShell launcher. Its inherited
environment was not cleaned or overridden: before touching config/owner
metadata, the helper classified both owner variables and rejected any unknown
path. Both were `unset`, SYSTEM was true, priority was `below_normal` and job
membership was true. The original 21-file Headless closure was reverified; no
installer/config was copied and no Setup or Agent lifecycle action ran.

The Guard returned zero in 1.703 seconds with a new valid floor `143479824`.
No forced termination, timeout, stream overflow or incomplete cleanup occurred.
Owner size 6,407,603 bytes and owner/lock mtime/size were stable within this
read; the existing production lock DACL normalizer still prevents a claim of
zero filesystem writes. The exact diagnostic task was removed; host-finally
independently found it absent. The native one-second admission and 15-second
watchdog/Guard wait were unchanged. The wrapper's 20-second launcher bound and
30-second task-observation limit do not extend native lock admission.

The wrapper owns the PowerShell launcher, so its empty captured streams are
not independent attestation of all native stderr. The native exit is propagated
by the Guard; its completion plus the verified numeric floor establish this
single successful preflight. On forced launcher termination, native cleanup
would be explicitly unconfirmed; that path was not exercised. Task/host exit
zero by itself only means summary capture and cleanup, not upgrade acceptance.

Frozen inputs and actual result are under
`/private/tmp/edr-684-task-preflight-sh17692n/`. Manifest SHA-256 is
`2f068aff69150a41b46e64f13e3a8d6600c42d01be5d31d5c1f50cb1bc083d5e`,
result SHA-256 is
`dc0a1d5d6eafe31ea6f2d823653a5efc1be7a45b379d2f10b12909f5874732f0`.
This excludes a new SYSTEM task with inherited context and the launcher being
inherently unable to calibrate the current owner. It does not reproduce the
historical active update or attest its environment/lock holder. No further
actual upgrade, cache cleanup, ACK mutation or Setup UI download was performed.

## 2026-10-16 queued inventory: mechanism and cancellation validation

At this pre-684 checkpoint, the 682 live refusal was `owner_lock_timeout` and
no further upgrade had yet been attempted. The following results establish a synthetic mechanism
and its failure boundaries, not the identity of the historical live holder.
No Setup UI package was downloaded or used during this work.

The frozen prototype changes only inventory locking: one overlapped exclusive
request on the existing byte-0/length-1 lock, with the unchanged 1,000 ms
monotonic admission deadline. Cancellation is followed by real completion;
`ERROR_NOT_FOUND` is not treated as cancellation success. A late grant is
explicitly released and cannot authorize owner scanning. Inventory unlock or
close failure propagates through policy and prevents a successful floor file.
Ordinary runtime locks, POSIX locking, installer stop order and rollback are
unchanged. The standalone preflight CLI now owns a short-lived 15-second
watchdog thread, since cancellation completion itself cannot be assumed to
finish within the admission deadline. It joins on normal completion, terminates
the preflight process on expiry, and uses fail-fast only if self-termination
unexpectedly returns. It adds no Agent-service thread or configuration. Child
8 means `deadline_unavailable`; the installer still consumes a floor only after
child exit 0. This is not a hard real-time guarantee about kernel or scheduling
failure.

The first paired experiment preserved the old executable, owner/configuration,
two blocking workers targeting 20 ms holds, one-second admission and all test
deadlines. Old polling observed 32 actual conflicts and exited 7; the queued
request observed real `ERROR_IO_PENDING` and returned successfully in 47 ms.
Independent review then found that the worker's hold statistic was sampled
before calling UnlockFileEx. That original result remains intact and does not
bound unlock-call latency. A measurement-only revision moved the statistic
after successful unlock, leaving both executables, workload and deadlines
unchanged. Its single run again observed old 32-conflict timeout and new queued
success, this time in 78 ms. Old complete hold bounds were 32/47 ms; new were
32/46 ms. Both sides' uncontended controls passed. The new child remained alive
while a third process acquired and released the same lock, ruling out process
exit as the explanation for release. All synthetic owner hashes matched and
no parent-forced process cleanup was needed. This does not establish Windows
FIFO fairness or an unconditional admission guarantee.

Nine separately selected native cases passed: short-holder release, continuous
hold timeout, late grant, delayed completion observation, event-creation
failure, thread-creation failure, unlock failure, cleanup-stall release and
cleanup-stall timeout. Continuous hold completed cancellation with Win32 995;
late grant observed cancel 1168, real successful completion and explicit unlock,
then returned 7 with zero inventory scans. The resource-failure cases returned
8 before any lock request; injected unlock failure returned 4 without a floor.
The controlled native wait was terminated by the CLI watchdog with exit 124 at
15.093 seconds, measured before any post-exit probe. Its release control returned
7 after actual cancellation. These injection cases do not claim reproduced
kernel failures. Native asynchronous-unlock pending and a precisely simultaneous
15-second completion/deadline race have not been forced or claimed as tested.

Raw results and exact invocations are under
`/private/tmp/edr-683-lock-contention-4y4xiv5c/queued-harness/`:
`paired-frozen-v2/execution-a24cae354eac/`,
`paired-measurement-v3/execution-e8daab22e49f/`, and the nine
`race-frozen-v1/execution-*/` records. The measurement-corrected result SHA-256
is `f9737ad9a053a89171e09d805bfd6fee08e408e8a288126e40d3f4a977e2c97e`;
watchdog raw result SHA-256 is
`f26f5e9e657684f17ed5f1b18dc1ee914b636187f61b9168db9e2e13a9e0e305`.
Commands were the frozen `execute_paired_once.py` and
`execute_selected_case_once.py --case <case>`, each with recorded executable,
script and output hashes. These are MinGW AMD64 helpers under ARM64 Windows
emulation, not the MSVC ARM64 release. The permanent fixture retains the existing
non-lock cases and 60-second suite bound. The final permanent fixture was then
freshly built from all 18 translation-unit compilations (plain and fixture
variants) and run once in an exclusive UTM temporary directory. It passed in
19.25 seconds, exit 0, with no timeout, forced termination or stderr. The
original ACL, legacy-owner, corruption, configuration and exclusive-output
cases remained enabled; owner bytes and ACLs remained unchanged. The dedicated
watchdog case exited 124 at 15.031 seconds. Its eight case observations and
final suite result are preserved in
`/private/tmp/edr-683-inventory-full-fixture-vhbj7qxs/results/`;
`result.json` SHA-256 is
`59dd1238d10fb21862fd40a1d9e78d9441d5f964949bb2800db8192d604a0338`.
The host executed the frozen `plan.json` prepare/start/poll/collect commands,
with a 60-second guest test deadline and a separate 75-second transport bound.
An initial local collection attempt found the already-created empty results
directory; no test rerun occurred. Collection then verified output hashes.
The eight-file permanent patch matches frozen-v2 manifest
`372477ba6a4afb0331df7c7482ab15d3e4c8e137b3e12e642661c2c7d2b47150`.
After integration, the host built `storage_space_preflight_client` and
`test_command_result_compaction` and ran
`ctest --test-dir /private/tmp/edr-cache-assessment-egress-build --output-on-failure -R '^(storage_space_preflight|command_result_compaction)$'`:
2/2 passed in 21.25 seconds (20.71 and 0.54 seconds). The existing host build
uses a non-production PCRE2 stub; these focused storage tests do not establish
P0 rule enforcement. Native MSVC builds, new release and client acceptance
remain pending at this checkpoint.

## 2026-10-15 candidate 682: Headless validation, live inventory-lock refusal

Source `4aee784a6bcbe8d1f309e1c3b4d662f5eb9cea0a` was committed and pushed to
`codex/rtq-result-delivery-pressure`: 21 commits after audit 662, 12 after
comparison `3de0dc680c78c335f8ab6ba37eef0d0f5d8f46e2`. Native release
[run 38742901613](https://github.com/qiuxinliang/edr-agent/actions/runs/38742901613)
passed all seven jobs on its first attempt. AMD64 runtime passed 99/99 in
317.97 s and standalone telemetry 38/38 in 451.19 s; ARM64 passed 99/99 in
480.58 s and 38/38 in 477.75 s. These labels overlap. Both native installer
and embedded-updater lifecycle jobs passed, but their upgrade/rollback
baseline was 679, not the live endpoint's 673. Optional signing and formal
non-candidate publication were skipped, not passed. Synthetic telemetry and
loopback mTLS do not prove real sensor coverage or endpoint queue migration.
More specifically, the direct Setup lifecycle upgraded 679 to 682; the other
runtime lifecycle used the candidate updater with `binary_hot` and checked
embedded-script materialization. Neither exercised the live 673 embedded
updater's `installer_required` route with its active command owner. Changing
only the candidate updater would not change that old updater's first hop.

Release `win_3.2.682` (413844804) is a candidate prerelease, pinned to that
source and P0 `896eb2f06c9ffa608085217d4d1e84494b43e564`. GitHub latest remained
`win_3.2.591` (403052409) before and after artifact verification. Full CI logs
are `/private/tmp/edr-682-release-run-nnqsguly/raw-logs.zip`, CRC verified,
SHA-256 `16ba674adbea5a2871a20717837b6a4df933b4f5e6a31b0b44d6a85ce292697d`.

At the user's instruction the optional Setup UI transfer was stopped; its
incomplete bytes and failed-transfer records remain separate. It was not
resumed or imported. The completed acceptance verified only the ARM64 binary,
artifact manifest and Headless ZIP, including ZIP CRC/path checks, native PE,
23 runtime components, runtime identity and the embedded full installer.
Headless still legitimately contains the installer required for this upgrade
class; it does not require the separate Setup UI package. Binary SHA-256 is
`560d28d01a3c38bbb48fe3faf0c38b43f3633d2a8918b0cd660898d3b0d20302`;
Headless ZIP SHA-256 is
`8356f0f7fca37ebe845b5914e2c05c62d78fd871e3f4c5b928feec458688dafc`.
`/private/tmp/edr-682-release-verification/headless-artifact-pin.json` records
the exact scope; it is not a successful five-asset verification.

The client imported those three files as `artifact_1792076398357833000`, with
Setup UI unbound, and queued only the authorized UTM endpoint at 15:04:24 UTC.
Task `agent_upgrade_1792076664225887000` / command
`agent_update_1792076665090123000` reached verified and installing, then failed
at 15:05:16.726 UTC with `full_installer_rollback_completed`. All five event
identity pins match; no new-version health observation occurred. No retry was
made. The exact task-bound 4,096-byte redacted diagnostic contains
`stage=child_exit; exit_code=7; reason=owner_lock_timeout`, followed by the
storage-preflight refusal. This directly identifies the child inventory lock
timeout for this attempt. The outer Setup exit 7 and coarse
`INSTALL_BASELINE_UNSUPPORTED` classifier are different facts; neither proves
a damaged baseline. The bounded classifier exported fixed codes and hashes,
not raw log lines, configuration or owner contents.

At 15:14:31 UTC the actual process was PID 7600, started 15:04:49.361294 UTC,
running 673 at the original installation path with binary SHA-256
`9641df3791f7c1f42fe98ecdce75e44f664ca94e60eb97f3d18a7882054163ca`.
Its exact upgrade journal is `failed_rolled_back`, `succeeded=false`, with
`last_event_seq=acked.seq=5` and no policy hold. This is acknowledged delivery
of the failed-upgrade event, not upgrade success or command-result ACK.
One post-failure cache probe retained all three sampled frozen queue owners
against both the immediate 682 baseline and the original 679 baseline, with
no changed bytes, dropped owner or ACK transition. Nine-category accounting
remains unverified because the running 673 schema does not support it. The
two missing old candidate samples were not replaced or resampled.

Evidence is under `/private/tmp/edr-678-client-acceptance/`:
`upgrade-682-task-current-01.json`, `upgrade-682-failure-selected.json`,
`upgrade-682-installer-rejection.json`, `postfailure-682-summary.json` and
`upgrade-682-rolled-back.png`. The 682 diagnostic log SHA-256 is
`268bdaf369f6e34b78387d63a017231a0d75e3960c5eeb27af73e8c2c93675fa`.
Source review finds identical 673/682 runtime lock open/release logic and the
same exclusive byte range as inventory. The timeout alone cannot distinguish
a long critical section, repeated competition or an unreleased lock, and
does not identify the holder. Runtime full-owner scans and installer/runtime
coordination remain under investigation. Raising the timeout or repeating
the deployment is not an established repair.

The next observation was one bounded three-second check of the existing lock,
with the exact PID 7600 generation and lock-file identity checked before/after.
All 116 nonblocking attempts acquired and immediately released it, with zero
conflicts. The owner remained 6,302,598 bytes with unchanged modification time;
Agent CPU increased by 0.640625 user seconds and 0.984375 kernel seconds. No
owner contents or ACLs were read/changed. Four native synthetic checks first
verified the observer's missing-file refusal, availability, real Win32 33,
release-after-conflict and reacquisition. These results establish availability
in that later window, not availability during the failed upgrade or a known
historical lock holder. Evidence is `owner-lock-682-{selftest,live}.json` and
their invocation records in the same acceptance directory.

One independent synthetic Windows experiment then used the actual preflight
test client and two runtime-style blocking byte-lock workers, all on the same
new synthetic owner/config/lock. Uncontended before/after calls succeeded on
their first attempt (0.110 s / 0.031 s). With two workers targeting 20 ms holds,
the existing preflight timed out in 1.046 s: 32 attempts, 32 actual Win32 33
conflicts and 32 sleeps. Workers acquired 21/18 times, with maximum observed
holds of only 47/31 ms. All owner bytes were unchanged and every process exited
normally. This proves that short, repeated lock competition can exhaust the
polling admission window without any single one-second holder. It does not
prove the historical holder, Windows fairness or a repaired implementation.
The original result and all 14 hashed raw outputs are under
`/private/tmp/edr-683-lock-contention-4y4xiv5c/execution-124bd4acf302/`;
`raw/result.json` SHA-256 is
`f60a5f08e4e4bdcaf8b14f91ff9c21af1c0bd7fcd1408b909ca52f5de24980a2`.
No live upgrade retry, timeout increase or production lock change followed
this experiment. A queued-lock prototype and its cancellation/CLI deadline
contract are being evaluated separately before any production patch.

## 2026-10-15 post-681 validation: exact boundary and existing-owner updates

An independent synthetic fixture reproduced the 681 strict-boundary assertion
at exactly 240 live 4,096-byte pages (983,040 bytes). The inclusive target then
passed the original next-candidate admission, retained owner/shared fact,
reference integrity and reopen checks. A 241-page control required actual
retirement before admission. The permanent regression preserves the original
pressure input and bounded maintenance loops, then fills only a separate
synthetic padding table to force the exact boundary. Host retention passed all
38 cases in 8.39 s with its unchanged 150-second deadline. Evidence and source
hashes are in `/private/tmp/edr-681-exact-capacity/`.

This result does not establish a hard physical cap: the next candidate's
transaction produced a 90,672-byte WAL, temporarily taking DB+WAL to 1,073,712
bytes, 25,136 bytes above the 1 MiB admission budget. A subsequent distinct
candidate reset/reused the WAL. The headroom is a cleanup target; it is not a
reservation covering every possible transaction or the whole Agent directory.

The follow-up same-ID experiment found a separate real admission bypass.
`edr_local_evidence_cache_record_behavior` checked `sqlite_size_budget_allow`
only for a new candidate. With a real pinned reader, 200 identical updates to
one candidate all committed: DB stayed 237,568 bytes while WAL grew to
13,937,992 bytes. There were no capacity rejections or physical-floor failures.
Changing only the next event ID caused the expected WAL-reset rejection.
The original owner and fact/reference digests stayed intact, so the defect is
unbounded repeated WAL admission, not evidence corruption in this experiment.
This is a synthetic mechanism proof, not the cause of any particular UTM cache
size. Original results, counters and object hashes are retained in
`/private/tmp/edr-681-same-id-8ci6diie/`; no endpoint evidence was sampled.

The repair makes existing-owner updates use the same physical and DB+WAL
admission check. They may reset a reusable WAL, but cannot run retirement to
delete their own owner/dependencies and recreate them through an upsert. New
candidate and context admission keep their existing retirement policy; updates
still do not consume the new-candidate admission count. The identical 200-call
experiment, replacing only the cache object, committed 11 updates then rejected
189: DB+WAL stayed at 1,106,920 bytes from the twelfth attempt onward. Original
owner/fact/reference hashes matched, materialized context remained readable,
and reopen passed. This is bounded refusal after one admitted transaction's
overshoot, not an exact physical quota. Raw results and compile provenance are
in `/private/tmp/edr-682-same-id-green-cdm60i54/` (1.767 s, original 45 s limit).

The same owner decision now treats candidate lookup bind/step errors as unknown
state rather than absence. A real SQLite trace-triggered interrupt at that
SELECT made the old code incorrectly admit/write once; the repaired code wrote
nothing and reported one storage rejection with an unknown-owner cause, with
no maintenance. The host fixture uses a temporary `sqlite3_open` passthrough
interposer solely to obtain the connection handle; it is not a production API.
Evidence is in
`/var/folders/gv/5p7lbk210d7c1nnzqvn2cfvc0000gn/T/edr-682-lookup-final-7_46uc0n/`.
Its first two fixture attempts are retained separately: this host's auto-extension
API was unavailable, then the initial fixture lacked the network port needed to
qualify as a candidate. Neither fixture failure is counted as a product pass.

The permanent `test_existing_candidate_update_honors_capacity` fails against
the frozen old object at its first required rejection and passes with the new
object. It verifies two consecutive refusals without WAL growth or retirement,
full owner/fact/reference/materialized-row preservation, an unchanged imported
policy-0 owner, successful same-ID enrichment after the reader closes, and
query/reference integrity after reopen. The initial fixture's attempted policy
downgrade was correctly rejected by the existing trigger; that failed fixture
is retained, and the final fixture creates a separate default-policy-0 owner.
No trigger or timeout was weakened.

Final host commands:

```sh
cmake --build /private/tmp/edr-cache-assessment-egress-build --target test_local_evidence_cache_candidate -j4
ctest --test-dir /private/tmp/edr-cache-assessment-egress-build --output-on-failure --no-tests=error -R '^local_evidence_cache_(candidate|migration|retention)$'
```

The three cache suites passed 3/3 in 13.11 s: context 78 cases, migration 10,
retention 39 (127 total). Exact executed commands, logs and source hashes are
recorded in `/private/tmp/edr-682-existing-capacity-regression/host-results.json`.
The cache source SHA-256 is
`42a96d03b8d3243371a208c89d4b818ae49762629c6b16690aa3989a3d4d40f9`;
the test SHA-256 is
`ed880fb83def7d6aa899a41946f51afc4a968f0422d4884447bbe67abff328f4`.

Fresh Windows synthetic validation also passed once per suite: retention 39
cases in 27.828 s and context 78 in 8.860 s, both exit 0, no timeout, unchanged
150-second limits. The exact-boundary case took 272 ms and the existing-owner
capacity/recovery case 99 ms. All 30 C inputs (including SQLite), 219 project
headers and two SQLite headers were hashed before compilation and checked
afterward; no earlier objects were reused. Host and guest EXE SHA-256 matched
`21b836f7f5d92735b8e9e1dd3b98bec095b85a23c46c9c5f456031c63eda12f0`.
Results, raw logs and precompile provenance are under
`/private/tmp/edr-682-native-retention-43da53c2b7/`; downloaded log hashes matched
the guest runner's result. This is MinGW x64 under UTM ARM64 emulation, with
the existing P0 IR test stub and historical diagnostic version string. It is
not a native ARM64 release or a client upgrade. Only an exclusive synthetic
temporary directory was used; the installed Agent and its real cache were
untouched. Native release/lifecycle gates and deployment remain separate.

## 2026-10-15 candidate 681: retained ARM64 boundary failure, no deployment

Candidate source `8fb522b0d32725e4d1bd8d65f80efb10e920796c` is on
`codex/rtq-result-delivery-pressure`, 20 commits ahead of audit 662 and 11 ahead
of comparison `3de0dc680c78c335f8ab6ba37eef0d0f5d8f46e2`.
[Run 38730044427](https://github.com/qiuxinliang/edr-agent/actions/runs/38730044427)
finished **failed**. AMD64 passed 99/99 runtime gates in 332.88 s and 38/38
standalone telemetry gates in 466.13 s, then packaged successfully. ARM64 passed
99/99 runtime gates in 563.85 s, but standalone telemetry passed only 37/38 in
576.06 s. Overlapping labels are not independent coverage. Finalization,
installer lifecycle and publication were skipped; no 681 client deployment ran.
Draft release `413746983` remains bound to this source and run, with five AMD64
assets only. Its tag does not exist and latest remains `win_3.2.591` (release
`403052409`). The draft is preserved, not reused for a different source.

The first ARM64 failure is
`test_capacity_reserves_wal_room_below_live_limit`, in the retention suite:
`db=983040 wal=0 retired=43`, followed by the assertion
`db_bytes + wal_bytes < 960 * 1024`. The suite failed after 64.22 s, not its
150-second deadline. The same suite had passed in the earlier runtime gate on
that runner. Production's 1 MiB cleanup target is 960 KiB inclusive; this exact
boundary already leaves 64 KiB headroom. This source observation alone does not
prove that the next candidate transaction fits: a deterministic boundary fixture
must exercise the real write, reopen and reference-integrity assertions before
changing the test contract. No timeout, retry count or production retention rule
has been relaxed to turn this run green.

Full logs: `/private/tmp/edr-681-release-run-9fa6mv19/raw-logs.zip`, 1,189,083 bytes,
CRC verified, SHA-256
`1a2049f5d7d357d1a64d25c264d879b3003a29aae8b49ebaf7970500af4cf9e5`.
The same directory contains `edr-681-ci-summary.json` and
`arm64-first-failure-excerpt.log`. Initial timed-out downloads remain partial;
the complete ARM64 entry extracted from the partial archive matches the final
CRC-verified archive. Prior failures and skipped stages remain failures/skips.

## 2026-10-15 candidate 679: native gates passed, client upgrade rolled back

The historical 679 checkpoint source was `d0c49a193bb14d42e76bd0bb0412a6241c181044`,
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

One subsequent SYSTEM scheduled invocation of that bounded stderr wrapper also
passed: actual 679 preflight exit 0 in 120 ms, floor 143,479,824 bytes, empty
stderr. Its owner snapshot again differed from the prior failure. The temporary
task was removed; the installed Agent remained the same PID 6228 generation.
See `/tmp/edr-679-scheduled-reason-rcut0d6_/`. This does not explain the earlier
code 4 or justify another upgrade retry. Source inspection confirms that the
full-installer updater does not stop the Agent before Setup; after a Setup
failure its rollback branch does stop and restart the old runtime. The guard's
"existing runtime was not stopped" message describes its own preflight stage,
not the subsequent updater recovery.

A temporary diagnostic executable records a fixed first-observed inventory
branch and typed numeric error only after the real preflight returns. It is a
MinGW AMD64 diagnostic build, not the published ARM64 679 binary. Its baseline
and instrumented forms passed six isolated Windows cases / 12 calls in
137.484 s: clean and absent-parent inventories succeed, an externally held
lock returns 4 with Win32 33, unsafe parent ACL returns 4 with a policy reason,
and a torn owner returns 4 with the existing unclassified-record reason. An
existing diagnostic sidecar is preserved and makes diagnostic success return
6 instead of overwriting it. All calls had no timeout and left their synthetic
owner bytes and owner/parent ACL unchanged. A first setup attempt failed while
reading the schema after changing the staging-directory ACL, before any of the
12 calls; that failure is retained. Removing only that unrelated staging ACL
operation allowed the unchanged cases to run. Raw results and the failed-setup
record are in `/private/tmp/edr-680-inventory-oracles-fixed-2bfd37a90618/`.
These results validate diagnostic discrimination, not a historical failure
cause; an observed missing parent can legitimately accompany preflight exit 0.

The single subsequent SYSTEM always-refuse Inno probe captured a specific
failure at 10:51:37 UTC: preflight exit 4, phase
`lock_exclusive_nonblocking`, valid Win32 `ERROR_LOCK_VIOLATION` (33).
The original Inno launch command was unchanged; only the tested diagnostic
executable supplied the bounded sidecar. The fixture refused before copying
files (exit 7, 2,759 ms, no timeout, dummy destination absent), removed its
temporary task, and left Agent PID 6228/generation and the 6,152,971-byte
command owner, configuration and checked ACLs unchanged. See
`/private/tmp/edr-680-inventory-inno-rct_r0tr/fixture-result.json` (SHA-256
`f2cdd7c93ed22dfe6435ecc462d82c2fbe8263cd3c07a276fcde465b63f28ff9`).
This establishes lock contention as the cause of this diagnostic failure.
It does not identify the lock holder or prove that both historical ARM64
679 upgrade failures had the same cause; their child error was not retained.

### Follow-up: bounded inventory lock contention and installer diagnostics

The pending repair changes only the Windows read-only inventory lock: retry
actual `ERROR_LOCK_VIOLATION` on the same validated handle, with a 1,000 ms
monotonic budget, sleeps of at most 25 ms and an independent 41-attempt cap.
Other errors fail immediately. The ordinary runtime lock, owner/parent ACL and
reparse checks, parser, protected bytes and existing 15-second installer child
watchdog remain unchanged. The contention budget leaves room for normal
calibration observed at 120/173 ms; it is not a hard bound on arbitrary disk I/O
or scheduling and does not guarantee every owner will complete in 15 seconds.
Exhaustion propagates a typed status through policy to preflight exit 7. It
does not read an unlocked owner or replace an unavailable inventory with zero.

Inno logs one fixed diagnostic line separating launcher failure (numeric
Win32 code) from child exit (numeric exit and fixed reason). It does not collect
raw child output, command text or paths. The existing updater still redacts and
retains at most 4,096 bytes; the coarse updater error classifier is unchanged.
The original PowerShell command and watchdog are preserved byte-for-byte.

Host build and the seven focused CTest contracts passed in 20.56 seconds:
preflight, command inbox/process/outbox/result/compaction and update packaging.
Commands and build-source hashes are in `/tmp/edr-680-lock-host-provenance.json`;
logs are `/tmp/edr-680-lock-host-{build,tests}.log`. This does not execute the
Windows retry branch. The Windows test client alone receives private clock,
sleep and observation hooks; LockFileEx and owner I/O remain real. The product
does not contain the test environment controls or event names.

The first UTM fixture run establishes a narrow red/green result. An old-source
observer build failed after an observed real lock conflict (one attempt, zero
sleeps, exit 4). The repaired build passed all four new lock assertions:
release-after-conflict succeeded (2 attempts), a held lock timed out (exit 7,
1.047 seconds), reaching the deadline prevented a second attempt, and a frozen
test clock still stopped at 41 attempts / 40 sleeps. However, the complete
Python fixture exceeded its original 60-second bound during later checks.
Its original result remains **timeout**, not a passing gate. The retained logs
show repeated PowerShell ACL-query process initialization; batching paired
owner/parent ACL reads preserves both SDDL comparisons and the original bound.
Raw old/new stdout, stderr and timing are under
`/private/tmp/edr-680-inventory-lock-fix/native/`.

The first independent installer test run likewise remains failed: its original
12 real preflight cases passed, then the synthetic child compilation used an
Add-Type option unsupported by Windows PowerShell 5.1. The fixture correction
uses its existing default AnyCPU compiler mode. The redaction run separately
failed at the existing snapshot Move-Item with a sharing violation; the writer
was disposed before the move, but the available log cannot identify the holder
or case. Fixed case labels are added for diagnosis without production retries
or expanded collection. These failures and subsequent results must be reported
separately. No additional real upgrade has been attempted for this repair.

After removing only the unsupported compiler option, the real Inno fixture
passed 19/19 in 58.375 seconds, including the original 12 cases and seven
failure-diagnostic cases. The real child watchdog case took 17.229 seconds
including launch/installer overhead; the original child limit remains 15
seconds. Every injected failure refused before the marker and payload copy.
The one labeled redaction rerun passed 26/26 in 6.235 seconds with the original
4,096-byte UTF-8/hash/size checks. Its prior sharing violation did not recur;
the holder/cause remains unknown and no production fix is claimed for it.
Source hashes, exact commands and raw logs are in
`/private/tmp/edr-680-inno-diag-fixed-a0d5_t1c/handoff.json`.

The paired-ACL Python fixture still exceeded 60 seconds (63.078 seconds after
cleanup), after all four lock cases passed again; stderr contains the 15
PowerShell module initializations and no assertion/traceback. That full result
also remains failed, at
`/private/tmp/edr-680-inventory-lock-fixed-3a8c734eece4/result.json`.
The existing one-process native PowerShell preflight fixture separately passed
13/13 in 9.016 seconds using the same plain helper and original 90-second bound;
see `/private/tmp/edr-680-preflight-ps13-85cd1a426e26/result.json`. These helpers
are MinGW AMD64 on ARM64 emulation, not the pending official MSVC release.

The final Python fixture replaces only its independent Windows ACL test I/O
with ctypes calls to Get/SetFileSecurityW and the system SDDL converters. The
same protected DACL and unsafe Everyone ACE are applied; every owner/group/DACL
comparison still performs a fresh OS read. No production security helper,
cache, extra dependency or test timeout is introduced. The complete fixture
then passed once in 2.062 seconds, exit 0 with no stderr, including all original
checks and the four real lock cases, under the unchanged 60-second limit.
Original command owner bytes and ACL assertions remain intact. Results and
source hashes are in
`/private/tmp/edr-680-inventory-native-acl-40a2f4cbc00c/result.json`;
the same final Python source also passed the host POSIX path, recorded in
`/tmp/edr-680-native-acl-host-check.json`. The removed PowerShell startup cost
was a fixture problem; it does not change the installed Agent or explain the
two historical 679 upgrade failures. Official native release gates and actual
new-client deployment are still required.

The repair was committed and pushed as
`c07ebb942205200e4f942e2ab7580a4c164aaf3d`, after the strict synthetic-CA
fixture repair `508b915b275efd893024069482955a861cba6390`. A subsequent
cross-consumer check found a stale test in `test_windows_release_gate.py`
which AST-extracted the removed `windows_ps` helper. Its focused invocation
reproduced StopIteration; it is not a runtime lock or ACL failure. The obsolete
test is removed with that absent consumer; the separate packaging PowerShell
environment-isolation tests remain, and real Windows ACL behavior is covered
by the complete preflight fixtures above. No unused helper is restored merely
to satisfy an obsolete test.

Candidate 680 run `38728352109` had already started against c07ebb94. It was
cancelled at 11:36:42 UTC before native runtime/telemetry gates completed.
Preparation had bound draft release `413734807` to that source and run; it has
no assets or publication time. It is retained unchanged, not reused for a
different source. The next candidate is 681. Cancelled is not a passing gate;
the original run logs are
`/private/tmp/edr-680-release-run-y83yo3c7/raw-logs.zip` (SHA-256
`705af759e2ab614ff4125055ad6cbb4ce1cedf9bb2763b9ede89c0d4435c453b`).
No additional installed-client upgrade was attempted.

The complete host release-contract entry point ran all 25 fixtures in
448.808 seconds: 24 passed and one exposed another stale test adapter. Its
compile-only simulated Windows header lacked the SRWLOCK/CONDITION_VARIABLE
types and declarations now used by the real cache concurrency tests. Nine
lines add only those SDK-compatible declarations/initializers, with no runtime
stub or production change. Both consumers of that temporary header (with and
without SQLite) then passed in 2.893 seconds. Thus all 25 distinct contracts
have passing results across the original run and two focused rechecks; the
original full run remains failed, not 26 independent tests or a rewritten
success. Raw results are
`/private/tmp/edr-680-gate-acl-consumer-g74hy48y/{full.log,result.json,two-consumers-green.log,two-consumers-result.json}`.

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

Commit `e6130ee3f227a6013128f761143042a87fe97308` contains this follow-up
(17 ahead of audit 662, eight ahead of the comparison SHA). Its nonpublishing
Windows CI run `38719364108` built with MSVC 14.44.35207 on native AMD64 and
passed 98/99 selected tests in 294.31 s, including the new storage cases.
The remaining `egress_receiver_resources` test failed the real TLS handshake:
Python 3.14.8 rejected the synthetic CA because it lacks a key usage extension.
The later zero-receipts assertion is a consequence of those 16 handshake
failures. The run is failed, not a release gate pass. Full original output is
`/private/tmp/edr-680-native-ci/native-ci.log`; strict TLS verification remains
enabled in the certificate fixture repair below.

The minimal fixture repair explicitly gives both synthetic CAs critical
`basicConstraints=CA:TRUE` and `keyUsage=keyCertSign,cRLSign`. The existing
resource test now also enables `VERIFY_X509_STRICT` on older Python versions;
no production verification option or expected receipt count changes. With
OpenSSL 3.6.2, the old generator reproduced strict error 92 (exit 2), while
the fixed server/client chains passed and wrong-CA/wrong-host chains still
failed. The resource suite passed 9/9 in 0.838 s and its four direct real mTLS
consumers passed in 52.91 s. An initial sandbox-only loopback bind refusal is
retained separately; the successful run used local-listener permission.
Commands, source hashes and red/green results are in
`/private/tmp/edr-680-native-ci/tls-fix-result.json`. Native validation of this
fixture repair remains pending. The Windows run's 99 tests are the actual
expected conditional set: `p0_runtime_delivery` is registered only on
non-Windows, not a missing test from the 100-name static candidate list.

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
| `evidence_cache_max_size_mb` | Existing compiled default 128 MiB; explicit deployed values override it. | Independent evidence DB+WAL admission target; SHM reporting and containing-volume headroom remain separate. |
| `evidence_cache_retention_hours` | Existing 24 h compiled default | Recent local evidence target. Pressure can shorten it through whole-group retirement. |
| `evidence_cache_selected_retention_hours` | New 0 resolves to the existing queue retention window, at least the recent window. Explicit 1..87600 h must not be shorter than recent. | Selected candidate target, not a guaranteed retention duration under every load. |
| `command_state_owner_budget_mb` | New 0 derives 39,438,000 bytes from the existing 300-record compaction working window, two maximal 65,730-byte records per owner. | Independent bounded JSONL owner inventory. The existing 1 MiB `EDR_COMMAND_STATE_MAX_BYTES` remains a soft compaction trigger. |
| `storage_min_free_mb` | New 0 derives `3 * max(owner_budget, startup_protected_floor) + 24 MiB`; a positive value can raise this floor. | Actual containing-volume free-space admission. With the default owner budget: 143,479,824 bytes. |

Existing reserve formulas are retained, not newly established production sizing.
Terminal reserve starts at `Q/8`, is raised to the bounded intent/final-frame/owner
minimum, capped at 4 MiB, and falls back to `Q/2` if it reaches the queue budget.
The source-only lane derives from eight bounded retry slots and is capped at
half the post-terminal space. Evidence live-page headroom is `min(E/16, 8 MiB)`.
These formulas and the synthetic workload checks do not establish an optimal
production partition or a guaranteed retention window. Deployed effective values
must be recorded separately from compiled defaults and earlier UTM snapshots.

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

The internal `rtq_query` handler consumes its frozen purpose contract rather
than an independently truncated payload. It checks tenant/endpoint, command/task,
derived purpose, issue/expiry, event window, fixed result projection and actual
encoded output bytes. The final retrieval review above distinguishes this
internal implementation from the absent backend/UI producer and identifies the
ingress correction. Request `fields` and `max_bytes` controls are not implemented.
A finite query slot owns a copied snapshot; queue locks/SQLite reads end
before projection callbacks. Busy, expired, oversized and corrupt reads fail
with a cause. There is no automatic permanent severity pin. One in-flight query,
1,000 result rows, 4 MiB copied queue bytes and the existing final result byte
limit bound this operation; release/cancellation ends the pin.

Real RAW/LZ4 decoding, scope checks, result projection, command-state persistence,
HTTP JSON and final egress assertions pass in `authorized_local_query_contract`.
Default queries omit complete commands. The existing command-line filter scope
in the local fixture can match and restore a 6,000-byte command. This does not
establish a remote field-selection API or business necessity. Terminal journal originals use the same path
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

Current release closure is recorded in the 684 section above: native AMD64/ARM64
gates and actual ISCC lifecycle passed for runtime source b7c8bd4, but the single
UTM upgrade failed and rolled back to 673. Installed new-client health/outbound
verification remains incomplete. This does not certify all ten acceptance items. The old
reader maintenance result above covers synthetic formats 0/1/2; routine downgrade
with policy-3 journals is unsupported because the old binary cannot finish the
new delivery sequence. Installed real cache cleanup or permanent legacy-data
migration is not part of the authorized deployment.

### Historical 684 acceptance checkpoint

This historical aggregate status includes the completed 684 gates; earlier failed
releases and benchmark revisions remain historical evidence, not overwritten passes.
References to current or remaining verification in this table are specific to
that checkpoint. Later observations and final status are recorded at the top.

| Required acceptance | Implemented and exercised contract | Remaining consumer closure / limits |
| --- | --- | --- |
| 1. Sustainable rotation, retained causality | Same-input queue comparison covers 12 virtual windows without full-fact delivery; evidence comparison covers 8 virtual hours with exact-generation causal groups. Current retention contracts passed native AMD64 and ARM64 in 684. | Sustained operation of the installed new client remains unverified. Retention targets depend on workload and protected inventory. |
| 2. Same-budget comparison | The final-source 1ba4e34 comparison above reruns the unchanged protocols and identical encoded inputs, measuring retained time ranges, chain completeness, sampled DB/WAL/SHM, CPU and issued VFS writes. Increased CPU, issued writes and physical peaks are explicit. | These are macOS synthetic/debug measurements. Native Windows performance, physical-device I/O and production throughput are unverified. |
| 3. Critical reserve | Real queue/SQLite tests fill ordinary local inventory exactly, admit terminal/journal owners, reject finite critical exhaustion and freeze previously reserved results. Both 684 native gates passed. | Queue fixture codec/transport are stubs; installed new-client admission/health remains unverified. This is a logical reserve, not physical block reservation. |
| 4. 20-byte terminal | The original 20-byte regression passes with ordinary inventory exactly full, original local bytes retained, no source uploads and no fabricated ACKs. Both 684 native gates passed. | Critical capacity remains finite. No real-cache pressure experiment is claimed. |
| 5. Result budget | Real evidence SQLite tests cover insert, expansion, 1,000 serial attempts, four writer threads, busy and COMMIT failure; rejection returns explicit outcomes. Separate authoritative-owner tests cover reserved completion and capacity refusal. Both 684 native gates passed. | These are separate fixtures: command-state/egress tests stub the optional SQLite query copy. Installed-client necessary-result persistence and server receipt remain unverified. |
| 6. Pressure/network cases | Repeated/unique/high-priority input, long commands, pin exhaustion, offline/ACK loss, policy refusal and bounded dead-letter storms are covered. Real loopback mTLS exercises 429/503 and exact receipts. Both 684 native gates passed. | Storm codec/transport are stubs. The TLS receiver is a synthetic business consumer; installed-client reconnect/delivery remains separate. |
| 7. Concurrency/restart | Real SQLite lifecycle/query concurrency, competing drains, stale connections, deferred retain and child-process migration/reclaim recovery run on both Windows architectures in 684. | Earlier failed runs remain history. Abrupt process termination is not hardware power loss; installed real-cache migration was not performed. MinGW AMD64 emulation is separate additional evidence. |
| 8. Time/physical pressure | Clock movement, busy, long readers, zero-space receipt refusal, guarded checkpoints and isolated NTFS disk-full/recovery are covered. Both 684 native gates passed. | Actual 684 upgrade still refused preflight and rolled back. Standalone successful preflight does not certify the installer context. Physical protection is admission checking, not an atomic directory quota. |
| 9. Frozen identity | Native tests cover frozen payload/hash/batch/owner, PPID, PID reuse and exact uint64 generation. Three sampled original queue owners remained unchanged after the actual failed 684 attempt. | The original two candidate samples remain missing; preservation and deletion timing/cause are unverified. New samples or a later successful upgrade cannot retroactively close that historical gap. Old policy-3 delivery downgrade remains unsupported. |
| 10. Minimal egress | Production protobuf/RAW/LZ4 encoding and final frame/request gates reject local source facts and unnecessary fields. Real loopback mTLS checks the received synthetic requests. These suites passed both 684 architectures. | Authorized-query contract opens no network; queue recovery uses synthetic transport receipts. Current installed-client/backend consumers remain unverified. Application-body counters and filtered server rows are not wire capture. |

684 compiled AMD64 and ARM64, passed its native gates and actual ISCC lifecycle,
and retained immutable source/artifact identity. Those results do not replace
installed-client acceptance. UTM standalone helpers and macOS sensor stubs cannot
replace native release gates. A further justified client upgrade command
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
