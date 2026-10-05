# Windows minimization candidate validation

This continuation follows the actual Windows build, native contracts and lab
deployment. The earlier host/cross-build evidence is in
[the development ledger](minimization_verification_2026-10-04.md). Neither that
ledger nor a successful build certifies installed sensor behavior.

Current verified checkpoint: 600 has passed both native architecture groups and
the installer/updater lifecycle gates, been published as a prerelease, and been
installed on the ARM64 lab endpoint. The stopped queue and fixed evidence subset
are preserved. The original baseline cache comparison remains failed, and
installed-600 field acceptance is FAILED with resource pressure and increasing
eventbus drops. Guarded field cases remain NOT EXECUTED; strict field minimization
acceptance is incomplete.

## Scope and starting runtime

The user authorized candidate prerelease publication with `latest=false` and
deployment to the existing UTM Windows test machine. Real queue migration,
production deployment and merging remain outside this task. The candidate must
pass both architecture jobs and the installer lifecycle job before deployment.

The initial published/runtime version was `win_3.2.591`, source
`bfb20a9afdb9889ea4c12aef1c648efc47724d87`; it predates minimization commit
`75a397d89353df7b3a7d36ff8807a00941411da2`. The test machine's OS and installed
executable are ARM64. Emulated PowerShell's architecture variable does not
establish the kernel or executable architecture. Read-only preflight bound the
running process to its creation time, binary SHA, SYSTEM scheduled task,
configuration/LKG and CA hashes, and policy sequence 524. No existing queue was
cleared or rewritten during preflight.

## Failed candidates and verified causes

Each row names an immutable source/run. Failed versions are retained as drafts;
the same version is not republished from another commit.

| Candidate | Source/run | Actual first failure | Repair and evidence |
| --- | --- | --- | --- |
| 592 | `130924b7`; [37247437746](https://github.com/qiuxinliang/edr-agent/actions/runs/37247437746) | Both dependency fixtures link `edr_egress_policy.lib` without declaring the library | `0fa5761e`: PCRE2 fixture consumes the real policy library sources/public includes/defines; exact host regression passes with its poisoned-header negative control |
| 593 | `0fa5761e`; [37248302237](https://github.com/qiuxinliang/edr-agent/actions/runs/37248302237) | MSVC C1189: fixture omitted existing production C11 atomic options | `793f6a07`: inherit the production common warnings/options and C11 configuration; no product option is weakened |
| 594 | `793f6a07`; [37248974243](https://github.com/qiuxinliang/edr-agent/actions/runs/37248974243) | Both dependency gates pass; sole failed build target is `test_windows_native_uninstall`, LNK2019 for `edr_egress_request_validate` | `b07a4629`: link the real policy library in the native test. Exact Windows source closure cross-link fails without it and passes with it; 595 native build verifies the repair |
| 595 | `b07a4629`; [37250513381](https://github.com/qiuxinliang/edr-agent/actions/runs/37250513381) | Both actual product builds pass; `command_fact_transport` fails; each original native release group is 70/71 | `40649221`: replace the synthetic label-only positive with the real IR rule producer. Native 596 original AMD64 group subsequently passes 71/71; the guard and production behavior remain unchanged |

The new `run_telemetry_windows_native.ps1` invocation is a required prepackaging
step from `130924b7`. In 592–595, later native minimization, installer lifecycle and publication
were not executed. A passing dependency
probe or the original release group cannot be reported as that new group
passing. The native uninstall behavior itself passed in 595 (AMD64 7.82 seconds).

`b07a4629` also repairs the host Windows admission fixture's real policy/public
protobuf dependency. The initial full host release-gate Python run had 18 passes
and this one failure in 551.069 seconds. The affected case passed after repair
in 3.339 seconds, retaining its full behavior assertions and suite-completion
check. The other 18 cases were not needlessly repeated. This is host OS-adapter
evidence, distinct from native Windows execution.

## Native gate continuation

596 ([37252872108](https://github.com/qiuxinliang/edr-agent/actions/runs/37252872108)),
source `4064922101269d3602348d305c548d8ea4e134d9`, builds successfully on both architectures.
Both original native release groups pass **71/71**, including the real P0 command
fact producer fixture. The new minimization runner then fails *before test
execution*: PowerShell array splatting binds literal flag strings as positional
values and supplies `build` as Configuration. This is an invocation failure,
not evidence that the minimization tests pass or fail. ARM64 independently confirms the same binding failure after 71/71 passes.

`da0d78f1b3e8364044f09a0fb59e75aad671de90` uses named hashtable splatting for
BuildDir, Configuration and optional OpenSslBin. Workflow contracts pass 15/15,
checkpoint contracts 40/40, YAML parsing and `git diff --check` pass. Restoring
either positional argument array makes the regression fail. The native runner,
all test selections, exit-code checks and publication dependencies are retained.
597 ([37253796936](https://github.com/qiuxinliang/edr-agent/actions/runs/37253796936))
is a separate immutable candidate from this commit. AMD64 compiles and passes
its original 71-test group, then correctly enters the new runner. Building the
new target stops at `test_deep_collector_manifest.c` because its Windows branch
uses `_mktemp_s` without including the declaring `<io.h>` header (C4013,
retaining `/we4013`). The test helper and its guard are executing; native
minimization test bodies have not passed. ARM64 independently passes its 71-test group and fails at the same missing
declaration. The new minimization tests themselves have not executed.

The corrected command fixture uses actual `R-CRED-003` matching and the real P0
producer, encoder and SQLite queue, rather than treating a score or label as a
valid detection. UTF-8 command and parent facts of 8,191, 8,192, 12,717 and
98,301 bytes remain exact after reopen and deferred replay. Positive wire lengths
are 17,622, 17,624, 26,674 and 197,845 bytes. Bare alert labels are denied. The
unproven terminal journal retains all three original IDs, bodies and SHA values
under policy hold, with zero ACKs/retries/transport calls. The host OS-adapter and
stub-only negative path pass; these transport callbacks are not real HTTP or
server receipts. Actual loopback HTTPS evidence must come from the native group.

## Consumer boundary under verification

A new real-producer 12,717-byte synthetic command frame was independently decoded
by the current backend. Its typed child/parent commands are complete, while its
embedded compatibility alert preview is nine bytes. Before repair, pure production
consumer regressions demonstrate that the first-class process column and baseline
choose nine bytes; a nonempty subject preview can also override the complete
same-event typed child command. Exact-source enrichment restores the full command
for model consumption, but the UI prefers the short first-class column. No existing
server row has been changed. Root commit `7616b21c` repairs only new ingestion. It builds normalized JSON and
first-class process fields through one owner. A complete, valid UTF-8 typed
same-process command takes precedence over a bounded preview; incomplete,
mismatched, empty or command-truncated/list-overflow inputs do not receive that
precedence. Coalescing remains compatible with a complete retained command.

Fifteen unique focused top-level tests pass (root independently reran the group),
including four positive and ten negative new-producer subcases. JSON, relational
input, baseline and model now keep 12,717 bytes, including exact Unicode and
whitespace. The new fixture is synthetic, independently named, SHA-bound and
produced by actual Agent IR matching; the older test fixture is unchanged.
No schema, historical-row update, service deployment, full MySQL or full HTTP
consumer execution is claimed. Historical shortened columns remain a known gap.

## Deployment and observation boundary

600 installation actually completes at 03:41:10.9911706 UTC with Setup exit 0.
The installed ARM64 process is PID 2608, creation FILETIME
`134356452523762683`, under the Running SYSTEM task; its binary SHA is
`2dc27d87500eac6c35493459642f34c70ec8dbf752ffde780266a50be4fccb5e`.
Configuration/LKG, CA and sequence 524 are preserved. Before this installation,
the six private owner templates passed the actual Windows PowerShell parser,
and the verified normal-stop receipt bound the original 591 process to its
exact creation time. The stopped read-only gate proves clear legacy source
ownership; its database remains unchanged and it does not infer an ACK.

The installer preserves queue/cache and retains verified stopped backups. A
subsequent read-only comparison proves all 95 original queue record IDs, batch
IDs and payloads unchanged. A separate fixed-20 evidence comparison proves the
stopped backup's candidate/reference/fact values unchanged in the live 600
cache. These bounded results do not establish whole-cache preservation or
server ACK completion. The earlier baseline-to-after cache comparison actually
exits 2 and remains FAILED; its differing reference/fact sets already differ in
the stopped backup before 600 installation. Details and receipt hashes are
recorded below. No queue recovery `--apply`, replacement under an old batch ID,
forced stop or concurrent rollback was performed.

The first passive 591 baseline was the separate 180-second development-server
window 00:25:25.803802–00:28:25.803802 UTC:
29 durable ingestion frames, 29 exact server batch/SHA receipt matches,
28 stored source events and two business alert rows with context. The 28/29
difference remains unattributed, and these rows are not independently verified
attacks. Server durability is not proof the Agent received its ACK. Cumulative
HTTP body counters are not a fixed-window byte comparison.

Prepared field probes use the existing bounded ARM64 truth/observer owners,
three synthetic process actions or three local loopback actions per 45-second
owned ETW session. Their tool hashes, PE architecture and protected ACLs were
read-only verified, and the wrapper parsed natively. No current field probe has
run: all three post-install resource snapshots reject the field precondition.
The new private basic-accounting wrapper has not been parsed or executed and
does not relax the pressure/eventbus guards. Complete raw artifacts remain
private; only counts, hashes, field presence and fixed causes may be returned.

Individual ordinary facts can be retained in a bounded memory ring. An empty
SQLite ordinary table, a sampled empty queue or a server count of zero cannot
prove uncollected data or successful minimization. Deterministic negative and
positive wire/body/receiver/ACK cases must be recorded independently of passive
sensor observations. No health-field exception or remote query is added to
compensate for a retired test driver's process-ID assumption.

## Further native-fixture repairs

`c58a667a` includes `<io.h>` in the Windows manifest fixture, leaving MSVC
implicit-function errors enabled. The failing 597 evidence is actual MSVC on
both architectures. MinGW can compile the old and new header sets because its
CRT also declares the function elsewhere; it is **not** a failing-before
cross-compiler regression. The repaired object compiles with implicit-function
errors and the host manifest behavior passes in 5.32 seconds.

The same review finds SQLite handles still open as receiver `main` enters
TemporaryDirectory cleanup. A deterministic resource ownership regression fails
before (three open connections), passes after, and keeps its deliberately failed
baseline client a failure. Seven receiver/inspection connection scopes now close
explicitly *after* normal transaction completion. No receipt or business oracle
is weakened. Native required inventory includes the new `egress_receiver_resources`
case; the full minimization group now has 18 cases.

The actual host nine-scenario loopback HTTPS/mTLS matrix passes again after this
resource fix; 49 observed connections close. Wrong CA/SAN receive zero requests;
P0 journal receipts produce one synthetic business alert; crash restart preserves
the original pending SHA and yields two distinct genuine queue ACKs. This is
synthetic host evidence, distinct from future native Windows execution.

598 ([37255415333](https://github.com/qiuxinliang/edr-agent/actions/runs/37255415333))
was mistakenly dispatched while the push still ran and therefore binds the older
`da0d78f1`, not `c58a667a`. It is cancelled before publication. The push subsequently
fails with an HTTP/2 framing error. A bounded HTTP/1.1 retry preserves normal TLS;
this version is not reused or silently rebound.

The additional passive 591 baseline has a fixed 180-second server window
(02:10:27.489893–02:13:27.489893 UTC): five durable done batches, five exact
batch/SHA matches, five stored source events, zero new business alerts. The
health snapshots actually span 300.211 seconds because the first ending SQL
sample reaches the eight-second deadline; its failed receipt is retained and
only one bounded retry is made. Over that actual health span, successful event
POSTs increase by 11 and body bytes by 12,233; health body bytes increase by
48,601, HTTP failures and eventbus drops by zero. Native process birth, binary,
SYSTEM task and trust/configuration remain identical across the observation.
Local ACK counters are absent in 591, so this window proves server durability,
not local ACK completion or an exact 180-second request-byte comparison.

## 599 native execution

599 ([37255678624](https://github.com/qiuxinliang/edr-agent/actions/runs/37255678624))
is independently bound to `c58a667ab0b1e15a5308b03725be5f8a788c7481` after
the bounded HTTP/1.1 push succeeds. AMD64 compiles the product and all new
minimization targets, passes the old **71/71**, then executes **17/18** new
contracts successfully. `egress_receiver_resources` passes natively (0.23 s).
The only failure is `egress_loopback_mtls` (111.65 s): its ninth, crash-restart
scenario does not reach the expected child checkpoint within the harness deadline.
The first eight scenarios have run but their overall result JSON is not emitted
before this exception; they are not declared independently passing yet.

ARM64 independently passes 71/71 and 17/18, with the same crash checkpoint
failure (113.16 s); its resource case passes (0.40 s). No lifecycle,
publication, real queue operation or installation has occurred. Investigation
keeps the deadline and TLS/business assertions unchanged while adding bounded
child diagnostics and a TEST ONLY Windows loopback probe to distinguish
connection readiness delay from an actual child assertion failure.

## 600 fixture isolation and bounded diagnostics

`2754870ecb840b09022882eaf1fc854b34c9b681` changes only the test receiver and
its resource/diagnostic regression. The ninth scenario connects to the receiver's
actual IPv4 loopback address using its existing IP SAN. DNS hostname verification
and lost-ACK/reopen/duplicate coverage remain in the other scenarios. Nine scenes,
ten-second checkpoint deadline, positive detector counters, immutable pending
payload comparison, real kill/reopen and genuine ACK assertions are unchanged.
No production connection function or detection owner is changed.

The new failure path records a fixed stage, child status, assertion names and
private log hash while preserving the earlier eight reports; errors remain
failures, and unavailable receive counts remain null. Diagnostic regressions fail
before and pass after (3/3); workflow 15/15 and diff check pass. The actual host
matrix passes nine scenarios with 49 SQLite connections closed after this change.

A TEST ONLY UTM Winsock probe measures IPv6 refusal under write-only select at
3,015 ms (SO_ERROR 10061), write/exception select at 2,032 ms, and normal IPv4
readiness at zero ms. Its conservative exception-readiness threshold does not
pass, so the probe is **not** counted as a passing suite or proof of the exact CI
child cause. The native acceptance run remains decisive.

600 ([37257803958](https://github.com/qiuxinliang/edr-agent/actions/runs/37257803958))
is independently source-bound after a completed push and remote branch SHA
check. At that build checkpoint its native tests, lifecycle, candidate publication
and field effect were pending; the live 591 service and original queues were
unchanged. The subsequent completed gates and installation are recorded below.


## 600 readiness and measured host request evidence

Fresh read-only preflight at 03:10:39.9863903 UTC confirms the exact unchanged
591 process generation, binary, primary/LKG configuration, CA, sequence 524,
SYSTEM task XML and protected ARM64 field tools. Six 600 owner templates parse
on Windows with zero errors; inverse mechanical retargeting is byte-exact and
all 44 prior SHA literals remain unchanged. No deployment template had executed
at that preinstallation checkpoint.
At 03:12:16 UTC the configured development `/ready` returns HTTP 200 using
CERT_REQUIRED and hostname/IP SAN verification under the same CA as the guest.

The host mTLS receiver report is a measurement of real synthetic HTTPS requests,
independent of the native Windows reports:

| Host scenario | Receiver requests / body bytes | Durable batches | Duplicate observations | Additional measured result |
| --- | ---: | ---: | ---: | --- |
| Valid DNS alert and required control | 8 / 11,329 | 3 | 2 | collected 2, detector inputs 1, detected 1, enqueued 3 |
| Valid IP SAN | 8 / 11,329 | 3 | 2 | same positive collection/detection/queue counts |
| Dictionary codec | 8 / 9,174 | 3 | 2 | same positive collection/detection/queue counts |
| Wrong CA | 0 / 0 | unavailable | unavailable | TLS rejected |
| Wrong SAN | 0 / 0 | unavailable | unavailable | TLS rejected |
| PMFE result bound to retained alert | 3 / 3,230 | 2 | 1 | actual worker results 1, distinct genuine queue ACKs 2 |
| Independent terminal journal | 1 / 2,017 | 1 | 0 | combined ACK 1, source ACK 0; detected 1 |
| Paired P0 journal | 3 / 5,928 | 2 | 1 | business alert 1, intent ACK 1, combined ACK 1, source ACK 0 |
| Crash/lost ACK and restart | 4 / 6,118 | 2 | 1 | checkpoint detected 1/enqueued 3; resumed collector 0 |

The paired P0 journal uses a production-schema fixture (`detector_executed=false`);
its business association result is distinct from the separately executed real IR
producer regression. Received bytes include genuine retries and minimal control
messages, not just alert payload size. All nine host scenarios pass and none
connects to production. Native counters are not inferred from these host numbers.
The ordinary 191-byte synthetic event is retained under policy hold rather than
sent; the valid alert remains eligible. Complete receiver body decoding and the
queue/receipt oracles establish purpose and ACK identity rather than treating an
empty queue as acceptance.


## 600 confirmed AMD64 native acceptance

The completed AMD64 job's original log confirms 71/71 original native tests
(147.98 seconds) and 18/18 minimization tests (221.09 seconds), including actual
`egress_loopback_mtls` success (105.22 seconds) and receiver resource/diagnostic
contracts (0.65 seconds). This is native fixture execution, not host adaptation.
The ninth crash checkpoint, immutable pending SHA, kill/reopen and genuine ACK
oracles remain required; none was removed or given a longer deadline.

CTest uses `--output-on-failure`; the successful native receiver JSON is not
present in this job log. Exact native per-scene byte/request/ACK values therefore
remain unavailable, rather than being copied from the host table above.
Product/package completion is verified for AMD64; ARM64 and complete candidate
publication are still pending at this point. No installation has begun.


ARM64's `Test` step also completes successfully and proceeds to package upload.
Both architectures therefore pass the required native invocation; exact ARM64
counts/timings await its completed original log. The subsequent real Setup EXE
install/upgrade/rollback and embedded updater jobs are still required before
published candidate selection. This intermediate state is not deployment success.


ARM64's completed original log independently confirms 71/71 (256.00 seconds)
and 18/18 (226.74 seconds), with real loopback mTLS success in 105.86 seconds
and receiver resource/diagnostic contracts in 0.73 seconds. As for AMD64,
successful per-scene JSON is unavailable in the native CTest output.
Both 599 native mTLS failures become 600 passes while production socket code
is unchanged. This verifies the isolated fixture repair; the previous child
cause was not independently observed and remains outside that conclusion.

The AMD64 real Setup EXE install, upgrade, rollback, uninstall and embedded
runtime updater lifecycle job completes successfully. At that intermediate
checkpoint, ARM64 lifecycle and combined publication were pending and UTM
installation had not executed. Their completed results follow.


## 600 complete native gates and candidate publication

Run 37257803958 completes successfully with all seven jobs successful. Both
architectures execute the real Setup EXE install, upgrade, rollback and uninstall
step and the native embedded updater step successfully. The architecture-only
Python cache skip on AMD64 does not substitute for a lifecycle step. The
lifecycle logs independently report actual 600 upgrade and 591 rollback success;
ARM64's installed native hash is
`2dc27d87500eac6c35493459642f34c70ec8dbf752ffde780266a50be4fccb5e`.

Release 403329514 is published, `draft=false`, `prerelease=true`; its lightweight
tag and target source are exactly `2754870ecb840b09022882eaf1fc854b34c9b681`.
`latest` remains `win_3.2.591`. Both independent artifact manifests match their
GitHub asset digests and bind the same exact run/source/tag and unsigned mode.
This unsigned mode is the explicitly authorized lab candidate, not a signing or
TLS exception for endpoint traffic. ARM64's complete five-file package download
and local SHA/ZIP/PE verification subsequently complete successfully. The
verified ARM64 Setup SHA is
`10d264c33320fd190356dc562d2fc5a8fd82354ac882340b15795501a032e2f9`;
the ZIP's executable matches the installed binary SHA above and is PE ARM64
(`0xaa64`). This artifact verification is distinct from the completed UTM
installation and the resource/field acceptance below.

## 600 stopped ownership and data preservation

The 591 process PID 3652, creation FILETIME `134356002055865571`, exits through
the normal stop owner in 2,422 ms: signal sent, wait status 0, exit code 0,
`forced_termination=false`. The immutable read-only gate at 03:40:09.2528213 UTC
is eligible, with legacy owner 2, state `clear`, epoch 0, loss flag 0 and session
`clean`. The old schema has no owner column; owner 2 is its established legacy
contract, not a newly written value. Recovery IDs and diagnostic text are absent.
The gate does not modify the database, perform ownership migration or infer
server ACKs. The stopped queue has 95 records and 285,738 payload bytes, with
neither WAL nor SHM sidecar present.

Both actual stopped database copies match the frozen backup manifest: queue
32,448,512 bytes, SHA
`97ce9d08c589255ae9ae351d61dc4d438d6d3f01bc9487a0fc2f941a15fa3f21`;
evidence cache 529,121,280 bytes, SHA
`54f5ca31a24a7b31459cca088f96864b9eb858e4cc52af37709cdf92611a983d`.
All four backup WAL/SHM paths remain absent. The later queue comparison uses an
immutable backup and one live read-only transaction: **95/95 original record
IDs, batch IDs, payload lengths and payload SHA values match**, with zero
missing, identity-changed or body-changed records. It completes in 64 ms at
03:50:11.2551392 UTC. This is storage preservation, not delivery or an ACK.

The original fixed-20 cache baseline is sampled at 03:38:06–03:38:07 UTC. Its
one after-install compare executes the existing SHA-bound read-only probe with
that exact selector and completes at 03:45:30.6903960 UTC: **FAILED, exit 2,
`selected_samples_differ`**, 20 changed sets, zero absent candidates. Candidate
hashes are equal for all 20; reference and fact set hashes differ for all 20.
Scoped reference/fact row occurrences increase from 190 to 5,120. These are
actual counts, not proof that each original row was appended without changes.
The complete failed receipt and empty stderr are retained; the probe is not
rerun or relabelled as passing.

A separate bounded investigation compares the same selectors with the complete
stopped evidence backup and the live 600 cache. Actual columns match for all
three tables/views, and both user versions are 2. The original reference/fact
set hashes already differ in the stopped backup before 600 installation; this
locates the changes to the **591 baseline-to-stopped-backup interval, including
normal shutdown**. Neither a schema change nor a particular 591 update cause is
established by that observation.

Stopped backup to live 600 is **PASS for this fixed subset**: all 20 complete
candidate rows, 5,120 scoped reference row occurrences and 5,120 scoped fact row
occurrences have identical original columns, SQLite types and value SHA values;
all 5,120 fact `manifest_template_json` bodies match exactly. There are zero
missing rows, new scoped rows, changed columns or changed bodies in this
comparison. All 20 reference/fact set hashes also match. SQL completes in
2,123 ms at 03:56:12.2513742 UTC, reading 24,795,760 canonical/value bytes under
64 MiB, 4,096 rows per set, eight-second statements and a 90-second total bound.
Live reading uses one read-only transaction; the backup is immutable. Runtime
generation and backup identity remain unchanged.

These counts are scoped occurrences across 20 selectors; shared facts can be
counted more than once. The original baseline receipt contains aggregate hashes,
not individual pre-shutdown reference/fact bodies, so exact preservation of its
earlier 190-row sets is not established. The new result proves upgrade
preservation of the stopped snapshot's fixed subset; it does not make the
original comparison pass, prove entire-cache preservation, or establish an ACK.

## 600 resource precondition and field status

Three existing server health snapshots are received from 600, without new field
workloads. Each reports CPU pressure and rejects the field precondition:

| Health reported UTC | CPU 60-second average | CPU budget | Pressure / throttle | Eventbus used / capacity | Dropped / queue pending |
| --- | ---: | ---: | --- | --- | --- |
| 03:52:49.318000 | 29.43% | 10% | 1 / true | 5,283 / 8,192 | 0 / 0 |
| 03:54:49.559000 | 30.72% | 10% | 1 / true | 4,571 / 8,192 | 0 / 0 |
| 03:57:49.794000 | 30.61% | 10% | 1 / true | 6,011 / 8,192 | 0 / 0 |

The unchanged field guards require pressure 0, no throttle and eventbus used
below 100. Resource/field readiness is therefore **FAILED** and both prepared
three-action native-short and loopback field cases are **NOT EXECUTED**. Zero
drops or pending rows do not override that gate or prove minimization/ACKs.
The older 591 30-sample resource series is from a different time window; it
contains ten pressure-1 observations and lacks the current throttle/eventbus
fields. It is not a causal control for attributing the current pressure to 600.
Guest SQL/probes pause after this investigation; no collection, detector,
validation or budget is weakened to permit field execution.

The subsequent passive server beginning receipt at 04:09:11.939688 UTC uses
600 health reported at 04:08:51.354 UTC: CPU 33%, 60-second average 30.86%,
pressure 1 and eventbus 6,706/8,192. Its eventbus dropped counter is **403**;
the three earlier zero-drop snapshots are historical and do not describe this
later state. Cumulative successful event POSTs are 34/53,946 body bytes, HTTP
success/failure 133/0, and attempted health body bytes 140,237. These cumulative
values are not a fixed-window comparison or delivery/ACK proof.

The final receipt now completes the fixed **04:09–04:12 UTC server window,
180 seconds**: received ingestion records, durable accepted frames, stored source
events and business alerts are all zero. Local ACK observation is unavailable
(`NULL`). The earlier file named `passive-server-600-end.json` was actually
sampled at 04:11:48.801 UTC, before the window ended; it is retained as an
intermediate observation and is not the final receipt.

The actual health report span is separately **04:08:51.354–04:11:51.719 UTC,
180.365 seconds**. Eventbus pushed increases by 2,752 and dropped by **61**, to
a cumulative **464**. Successful event POST body bytes increase by zero; HTTP
success/failure increase by 14/0 and attempted health body bytes by 17,167.
Sensor callback counts increase by 87,764,873; callbacks are not unique collected
inputs. Unique collector inputs, detector inputs, evaluated events, enqueued
events and local ACK counts are unavailable (`NULL`), rather than assumed zero.
The ending health sample reports CPU 29%, 60-second average 31.62%, throttle
active and eventbus 7,583/8,192. Zero server events while local drops increase
cannot demonstrate semantic minimization, absence of attacks or detection/data
preservation. Installed-600 field acceptance remains **FAILED**, and the guarded
field actions remain NOT EXECUTED. A PMFE index repair has host mechanism
evidence but has not been deployed to this runtime.

A separate private `field-case-basic-accounting.ps1` changes only the consumer
path to the real basic-accounting health field. Its SHA is
`4b2027c735e5ecb48c1579540062ffd184c0a7c0b5680cdd7434f29b78c32895`.
The original reviewed wrapper SHA
`f57312123aa581caa344db56d7427017753e9404a05297d1b0e76310d985067c`
is unchanged. Pressure 0/eventbus-below-100 guards are retained. The new wrapper
is **NOT PARSED / NOT EXECUTED**; this consumer repair supplies no field evidence
and adds no health whitelist exception.

## 600 resource investigation and verified local mechanism

Three two-second read-only CPU-counter windows bind the same 600 PID/creation
time, with five logical processors and 24 threads. Process CPU is 29.670%,
25.852% and 32.059%. One continuously busy thread consumes 60.95–67.88% of
process CPU, with 91.60–96.88% kernel time. Its role is unknown. The private
probe's hashtable sorting does not establish top-five ordering; the identified
thread nevertheless consumes more CPU than all remaining process time combined.
No ETW session, profiler, memory/stack read or database operation is performed.

Separate `GetProcessIoCounters` windows observe 383,291–527,569 read operations
and 1,569,929,354–2,160,922,624 read bytes per approximately two seconds, about
4 KiB per operation. Write operations are 0/1 with 0/108 bytes. A single bounded
immutable read-only statement on the stopped backup counts 13,229 artifact rows,
zero PMFE rows and zero legacy `post_context` rows in 222 ms. The backup SHA and
runtime identity remain unchanged. Zero PMFE rows do not mean an empty artifact
table. These observations support sustained read scanning, but do not identify
the hot thread or independently prove field causality.

The 600 source calls `poll_pmfe_followup_recovery` every preprocess turn. Both
`edr_local_evidence_cache_pmfe_take_task` and
`edr_local_evidence_cache_pmfe_replay_result` select by artifact type/status and
creation time under the evidence-owner mutex; only an endpoint/time index exists.
Busy event processing repeats both queries without the idle wait. A deterministic
synthetic database with 10,000 unrelated artifacts and zero tasks invokes the
real owner selector 16 times: the task selector executes 159,984 full-scan steps
and 480,224 VM steps. Its new zero-full-scan assertion fails on the unchanged
600 mechanism. This proves a local query-cost defect, separately from installed
sensor causality. The correction is being implemented as one matching partial
index in the existing schema owner; no recovery frequency, collection, detector,
lease, retry budget, wire bytes or ACK contract is relaxed. It is not yet a
deployed repair or a passed field result.

## Private receipt commitments

The following complete evidence stays private; only SHA commitments and bounded
results are recorded here. No raw event commands, candidate IDs, user data or
credentials are included. Successful native CTest output still does not provide
per-scene native request-byte/ACK JSON, so the earlier host table is not promoted
to native measurements.

| Private receipt | SHA-256 |
| --- | --- |
| `edr-600-amd64-full.log` (71/71, 18/18, actual mTLS) | `cf0ba8cbdc3b4960dfce7e27962d962d1c43a1a9f8d80834a09740a0f74276cf` |
| `edr-600-arm64-full.log` (71/71, 18/18, actual mTLS) | `31b7212fc138db03c49527eee72e77dd84104df20e97e6a1bc7ada5494888c1f` |
| `edr-600-amd64-lifecycle.log` | `b729ae45bb25383233d672153d01989a0c58fdb73409bfbb2e5cb22eeb40d915` |
| `edr-600-arm64-lifecycle.log` | `b9fe1352dec0ef9938a25ffe27b57b471f1f05801c6a392f72f76d4769926ba4` |
| `arm64-assets-c4z7ba78-verified.json` | `a8c956d311ef220509fe0c986d16e6f2a9a51a3d97059623ceb3672b7344142a` |
| `install-result.private.json` | `83f53c23d33b68f8993b1448797db4a2d5b1086b47aa6e11df103a7791a44cf4` |
| `stopped-queue-gate.private.json` | `717b5d3430394489bdc13efb6a538f40d8411ea06824734f3ea1f06e0395f925` |
| `stopped-backup-actual-hash.json` | `a006786395fcf46608f01adfdd92c20dd6aa496a21b9e5801f0165e68bb6602a` |
| `edr-600-queue-retention-readonly.json` | `1c86df7410be6748d4fee8528cb49c7d790d7f1d5d3a789bfc3ea69bf299af70` |
| `cache-before.private.json` | `69ce07fe87978a1a3740998c3fab948c7499c9495910d4fd2a0874a10b404a87` |
| `cache-after.private.json` (original FAILED comparison) | `8b3ff81883d5693cd4331906f056133af77cdb4fb8155b4d8695267f562e848f` |
| `fixed20-diff-owner.json` (stopped subset comparison) | `d84c0ff6df4d52398db8d2c8d1f9c77ae07f6fab293a62445f03252066c47620` |
| `cache-post-install-summary.json` | `62f2f3e7b8b006b9c5a9bf31501c8c7050d0fd4c2a353eb10b7306943c3169cb` |
| `pressure-baseline-comparison-600.json` (three actual snapshots) | `196d57b154f6e52f9050ed83324c9b0a29669e2982d78fbd6f96d4f7556fc0fe` |
| `passive-server-600-begin.json` (later pressure / 403 drops) | `e4c94cd7414ddffc85d827f662398ea9cddf954b89a9bf14f348124c55363638` |
| `edr-600-thread-cpu-readonly.json` | `14a9869f451ce16b96125b7d3e4fef38ce5f3a7d73d34ea2c66416e1517be2ae` |
| `edr-600-process-io-readonly.json` | `2445a1d17cc04da256f32f86e758445791a7a9a8c2aa602521e5cc1cc815f016` |
| `edr-600-artifacts-count-readonly.json` | `4e9de3b9103eec7eb9a2df0839d56f018b0b0678740654811a7900492097b090` |
| `passive-server-600-end.json` (intermediate before window end) | `5f6b653b0a1fb6f793802e0489b5e29eb53bb3a1f04b6e275816b59530324367` |
| `passive-server-600-final.json` (completed 180-second server window) | `564af8a475defa1cf7c96cabd4f793d3256fa88c2e3d0c9e179f55ec77781947` |
| `passive-delta-summary-600.json` (actual health span and unavailable counters) | `1e1df6bf7f91077c0f5119c8b6e81b53ef14376589e7d790b1a3a61e06ecaaf3` |

The completed CI/lifecycle gates, actual lab installation and limited storage
preservation are passed within the stated scopes. The original cache comparison
is failed, field execution is not performed, and installed-600 field acceptance
is FAILED. Strict field minimization has not been declared complete.
