# Windows minimization candidate validation

This continuation follows the actual Windows build, native contracts and lab
deployment. The earlier host/cross-build evidence is in
[the development ledger](minimization_verification_2026-10-04.md). Neither that
ledger nor a successful build certifies installed sensor behavior.

Current verified checkpoint: 601 passes the host regressions, both native
architecture groups, both CI installer/updater lifecycle groups and published
ARM64 asset verification. The second protected lab attempt installs the exact
601 binary successfully. A bound post-install sample reports CPU 60-second
average 2.41%, current CPU 6.90%, budget 10%, pressure/throttle zero and eventbus
used/dropped zero. All 507 original stopped queue identities/payloads and the
fixed evidence subset are preserved in separate bounded read-only comparisons.
Both bounded synthetic field captures and their private consumer analysis
complete. The later 60-second CPU average is 2.21%, with no eventbus drops.
Per-action local/detection/wire/server/ACK evidence still has UNKNOWN gaps.
Strict field minimization is not declared complete.

The first 601 stop attempt remains FAILED with verified 600 recovery. The
installed-600 resource/field result and original baseline cache comparison
remain FAILED. The queue comparison launcher's unknown child exit and the first
two cache invocation parse failures remain separate failed executions; later
semantic preservation evidence does not convert those failures into passes.

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
600 mechanism. This earlier failure is retained separately from the stronger
completed-row regression below. It proves a local query-cost defect, separately
from installed sensor causality.

Commit `3e5ddeb80a8d1d178002a2d6ea74b436d0eccfd9` adds one matching partial
index through three production schema-owner string literals in
`src/storage/local_evidence_cache.c`: `idx_artifacts_pmfe_state_created` indexes
`(upload_status,created_ns,artifact_id)` only for
`artifact_type='pmfe_followup_local_v1'`. There is no new table, worker or runtime
option. Actual `SQLITE_STMTSTATUS_FULLSCAN_STEP` and `SQLITE_STMTSTATUS_VM_STEP`
counters are compiled only under `EDR_LOCAL_EVIDENCE_CACHE_TESTING`; they measure
the two real owner statements rather than a substitute query or elapsed-time
oracle. No recovery frequency, collection, detector, lease, retry budget, wire
bytes or ACK contract is relaxed.

The final deterministic synthetic owner fixture contains 10,000 ordinary
artifacts, 1,024 completed PMFE-shaped rows and zero active tasks. Completed rows
carry no claimed detection facts. Each real selector is called 16 times:

| Real owner query | Unindexed full-scan / VM steps | Indexed full-scan / VM steps |
| --- | ---: | ---: |
| `edr_local_evidence_cache_pmfe_take_task` | 176,368 / 578,528 | 0 / 512 |
| `edr_local_evidence_cache_pmfe_replay_result` | 176,368 / 578,528 | 0 / 512 |

The unindexed new assertion terminates with SIGABRT (subprocess exit -6); the
indexed regression exits 0 and passes. The same fixture verifies exact ordinary
and completed rows, original/result wire hashes and bytes, existing scan lease
exclusion, two reopen/replay cycles, and observable initialization failure while
another writer holds the database. Index creation resumes after that writer
releases its lock; retained rows and unacknowledged result state remain intact.
The full `local_evidence_cache_candidate` test passes 1/1 in 7.59 seconds and
`pmfe_lifecycle_policy_switch` passes 1/1 in 1.23 seconds. Independent review,
narrow checks and `git diff --check` pass. This is host synthetic evidence with
the explicit debug rule-IR stub; the fixture opens no production or guest
database. It does not establish native Windows behavior or installed CPU/drop
recovery. At that host-verification checkpoint, installed 600 remains unchanged
and its field result remains FAILED; the later native and 601 lab results follow.

## 601 host verification and native workflow checkpoint

601 [run 37263506416](https://github.com/qiuxinliang/edr-agent/actions/runs/37263506416)
is dispatched from exact source
`3e5ddeb80a8d1d178002a2d6ea74b436d0eccfd9` using `workflow_dispatch`.
The source/run binding is verified and all seven workflow jobs complete with
SUCCESS. Both product builds and their actual native Test steps pass. The old
release gate runs before the separate native minimization runner on each
architecture:

| Native architecture | Existing release gate | Minimization gate | Actual loopback mTLS test |
| --- | --- | --- | --- |
| AMD64 | 71/71 PASS, 154.57 s | 18/18 PASS, 228.86 s | PASS, 105.60 s |
| ARM64 | 71/71 PASS, 240.92 s | 18/18 PASS, 215.34 s | PASS, 106.01 s |

The new receiver-resource test also passes on both architectures. Successful
CTest stdout does not retain the receiver's per-scene request/body/ACK JSON or
the query-cost numbers; those native values remain unavailable and are not
replaced with host measurements.

The actual CI lifecycle steps execute successfully rather than being skipped.
AMD64 Setup install/upgrade/rollback/uninstall runs from 04:48:04 to 04:49:27 UTC,
then native runtime update lifecycle from 04:49:27 to 04:50:29 UTC. ARM64 runs
those steps from 04:48:25 to 04:51:27 and from 04:51:27 to 04:52:47 UTC,
respectively. Publication completes as prerelease `win_3.2.601`, release
403365668, at 04:53:06 UTC with ten assets and the exact source/tag commit above.
`latest` remains `win_3.2.591` (release 403052409). ARM64 asset-content
verification subsequently passes as recorded below. CI lifecycle success does
not itself establish a lab upgrade or installed resource recovery. The first
lab normal-stop attempt subsequently fails before Setup; the second attempt's
actual stop, installation and bounded post-install results are recorded below.

After the index change, the actual host loopback HTTPS/mTLS receiver passes all
nine synthetic scenes with normal TLS verification and zero production
connections. Their measured request/body, durable-batch, duplicate and ACK counts
match the separate 600 host table above: DNS and IP SAN each 8/11,329, dictionary
8/9,174, associated PMFE 3/3,230, terminal journal 1/2,017, paired P0 journal
3/5,928 and crash/restart 4/6,118 requests/bytes; wrong CA and SAN each receive
0/0. The associated PMFE scene executes one actual worker result and records two
distinct queue ACKs. The crash scene preserves the original pending hash, then
records two distinct queue ACKs after restart; resumed collection/detection are
zero. Receiver business failures are zero throughout, and reported client
failed-check counters are zero.
The paired P0 scene remains a production-schema fixture with
`detector_executed=false`; host measurements are not native Windows facts.

The first sandbox attempt exits 1 on `PermissionError` while binding the local
listener, before any scene executes. That execution limitation is retained in
its own receipt; it is not a production-transport test failure. The separately
completed unrestricted host run supplies the nine-scene result above.

All six mechanically retargeted 601 private owner scripts pass actual Windows
`Parser.ParseFile` AST parsing at 04:27:50.0154461 UTC, with zero parse errors and
matching frozen SHA/lengths. That particular operation only parses syntax:
no prepare, stop, cache, install or field owner executes, no protected 601 job
is created and no queue is modified during it. The runtime at that historical
parser checkpoint is still 600; subsequent owner executions follow below.

The original frozen stopped-queue gate remains unchanged at SHA
`16b8cad374f525356dc2aaa27bbecd0a3b1e26f3136595d9a71b7ef0584a534e`.
Its decision rejects even a valid retained local-v3 severity-2 fixture; that
historical refusal is reproduced, with `historical_gate_passed=false`. A new
private gate, `stopped-owner-compat-601-local-v3-v2`, changes only that
compatibility classification for the unchanged queue-owner implementation from
600 (`2754870ecb840b09022882eaf1fc854b34c9b681`) to 601. It permits severity-2
rows only when the source-owner column exists, fully validated owner is 3, the
owner is clear with epoch/loss zero, the session is clean, no diagnostics or
recovery bindings remain, and every such row is exactly
`status=local_evidence` and `terminal_reason=source_only_local_v3`. It reports
retained local-v3 and unresolved legacy counts separately, with no inferred
server ACK or established alert identity. Owner-2 local tags, pending/dead
source rows, unknown state and any unmet existing owner guard remain refused.

At 04:44:21.8131136 UTC, actual Windows compilation and execution of the gate's
C# decision function passes all 20 isolated synthetic contracts, including the
old-gate refusal control and the rejection cases above. Both scripts parse
with zero errors and match their frozen hashes. This test opens no database
and executes no stop/install owner. The normal-stop requirement, read-only
immutable access, file/row/byte/time bounds, quick-check and before/after SHA
guards are preserved in source. The actual stopped-database gate remains
pending at that synthetic-test checkpoint and subsequently passes in the second
lab attempt below. The new gate does not migrate, send or acknowledge retained
data, and the original failure receipt remains separate.

The strengthened private field wrapper checks its child owner exit code as
well as the existing completion, ETW-loss, health, throttle, eventbus and queue
guards. Actual Windows AST parsing and an extracted exact-source condition
test pass at 04:49:59.2787392 UTC: otherwise valid observations accept exit 0
and reject exit 1. This is a pure guard test, with no field owner executed;
`observations_collected_not_acceptance` and the unassigned quality result are
preserved.

Revision 3 keeps the earlier files and manifests unchanged. Its new
prepare/install/launch copies pin the new gate SHA and a separate
`stopped-queue-gate-601-v2.json` receipt. Install additionally verifies the
exact gate version, source/target commits, eligibility, read-only/immutable
flags, zero legacy/unknown counts and explicit false ACK/alert-identity flags.
The existing candidate, normal-stop, backup, rollback and hash guards remain.
All four new files pass actual Windows `Parser.ParseFile` AST/hash validation
at 04:51:43.0413500 UTC, with zero errors; mechanical review accounts for every
changed byte. The root agent has adopted the revision for the planned upgrade.
Template upload and that parsing operation do not execute these owners or
inspect an actual live/stopped database; they precede the later lab attempts.

## 601 asset adoption and failed lab stop

All five ARM64 published assets pass independent size and GitHub digest checks,
the release manifest and bundle inspection, ZIP/raw-binary agreement, and ARM64
PE architecture validation. The exact source/tag/run identity and prerelease
with `latest=false` are rechecked after download. The 7,285,601-byte official
Setup has SHA `6312d3108e541179965cc5250badcc429330daa08f6db38efc50e022d075d7bd`;
the 2,848,256-byte Agent binary has SHA
`ca71ab98f8a9b6da404a305311da34748a1d4ed91c51f1857ba8b78ec049312c`.
The initial download fails its 300-second deadline for the 75,035,330-byte UI
asset and is retained as FAILED. One separately recorded bounded fallback
completes verification; it does not overwrite the failed receipt or partial
downloads. The release owner classifies 600 to 601 as `installer_required`;
only official Setup is prepared, with queue and evidence retention enabled.

The first protected 601 lab owner starts at 05:33:55 UTC and fails before Setup
at 05:34:58 UTC. Its original 600 PID/creation-time binding is verified. The
unchanged normal-stop helper actually exits 9: the stop signal succeeds, the
process wait succeeds, but the Agent exits 1 after 61,531 ms without forced
termination. The current stderr contains both preprocessing shutdown timeout
and dependency-retention markers. In the exact installed source this is the
60-second preprocessing join followed by `main` returning 1; later drain,
transport shutdown and normal queue-close success are not reached. This
identifies the failed shutdown stage, not the particular operation that stalls
inside the worker. No all-collected-event retention claim follows from a
process exit or durable-file copy.

Before restarting 600, all nine stopped queue/cache DB, WAL/SHM and current
startup-log files are copied to a separate protected failure-evidence directory.
Source and destination byte lengths, SHA digests and write times are verified
individually and the complete source set is rechecked while the Agent remains
absent. The preserved files total 572,304,705 bytes. No SQLite checkpoint,
recovery apply, database replacement, queue clearing or inferred ACK occurs.
The failed owner and stop receipts remain unchanged. Only after preservation
and unchanged binary/configuration/CA/sequence/SYSTEM-task verification does
the existing task start once. At 05:55:58 UTC, 600 is verified Running as one
new generation; a scoped server sample confirms online heartbeat and verified
v524 policy. This is recovery from failed stopping, not successful upgrade.

After recovery, CPU still exceeds the 10 percent budget and the event bus
has backlog; this remains a failed field-readiness condition. A full sample at
06:05:44 UTC confirms P0/artifact readiness and the open evidence cache, with
zero retry/family/terminal-unhealthy flags, but the process-local sticky
`source_only.loss_detected` is 1. This RAM history is distinct from the durable
queue latch checked by the stopped gate. The existing local-v3 durable audit can
clear the persistent latch without clearing history in the current process;
only an actual clean stop and unchanged persistent state can establish the
next-generation recovery result. No historical loss is cleared manually. Any second
upgrade attempt must have its own identity and receipts, require an actual
exit-0 normal stop, and leave the original failure intact. The 601 stopped gate,
Setup, retention comparisons and field cases remain NOT EXECUTED at this stage.


Read-only shutdown review also identifies conditional liveness gaps unchanged
from 600 to 601. The preprocessing loop checks stopping only after an empty bus;
a producer that keeps replenishing it can prevent that check. PMFE, WinDivert
and Webshell bus producers are stopped later in `main`, and a full PMFE
unassociated-submit queue can wait for admission shutdown that follows the
preprocessing join. These conditions are not established for the failed lab
attempt. A deterministic real-owner harness plan is recorded, but no new
shutdown regression or lifecycle fix executes in this investigation. An
eventually successful second stop would establish only that actual attempt,
not close these conditional risks.

Second-attempt templates use a new protected job and the recovered 600
generation. They leave the failed original owner untouched and reuse its 20
selector IDs only; no fresh live baseline is claimed. A separate CMD wrapper
captures the actual unchanged helper process exit immediately, copies its raw
receipt and refuses replay. Launch/install require strict PID/birth, actual
helper exit, Agent exit, signal, wait, no force, fresh file times and exact
receipt hashes before any stopped backup or Setup. Windows AST parsing and
execution of 24 exact extracted-function contracts plus five synthetic CMD
exit/missing/stale/replay cases pass at 06:23:47 UTC. Only a synthetic helper
is invoked; no Agent stop, production helper, real database or installer runs.

At 06:25:50 UTC, the independent protected second job is prepared with eleven
verified copies and the original configuration, trust, sequence and SYSTEM-task
contract. Both mechanically retargeted retention probes also pass actual native
AST and C# compilation, returning before any SQLite or process comparison.
The completed preparation is not a successful second stop or install. After
all guest preparation ceases, read-only snapshots show old-generation bus
backlog 5,280 at 06:27:47, then 4,328 at 06:32:47, with dropped count still zero.
At this preparation checkpoint the low-interference normal stop remains
pending; neither sampling nor detectors nor collection are reduced. The later
second stop and installation result follows below.

The private completed-case consumer is separately strengthened to require
integer-zero owner/probe/observer/cache exits and an explicitly true trace-stop
flag, in addition to the existing exact actor/runtime/scope checks. The original
consumer accepts a same-status owner-exit-1 synthetic receipt; that failure is
retained. The new consumer passes 11 deterministic host contracts including
failed, missing and mistyped exit/trace fields. This is a private guard test;
no completed field case, decoder, guest workload or backend collection executes.

## 601 second lab installation and bounded retention

After preparation has ceased and the original bus has drained, the unchanged
normal-stop helper targets recovered 600 PID 7224 / creation filetime
`134356533455526833`. Its separately captured actual process exit is 0. The raw
stop receipt reports signal sent, wait status 0, Agent exit 0, 2,437 ms elapsed
and no forced termination. The independent protected attempt-2 owner verifies
both fresh receipt hashes, the absent Agent and Ready SYSTEM task before
backup or Setup. This successful stop does not supersede the first failed
stop or close the unchanged conditional shutdown risks above.

The actual stopped read-only v2 gate passes at 06:48:44 UTC. It verifies queue
owner 3, clear latch, epoch/loss zero, a clean session, no diagnostic/recovery
binding and quick-check success. The immutable inventory contains 507 rows:
412 retained local-v3 source rows, 93 pre-existing severity-1 dead-letter rows
and two severity-1 policy-held rows; there are zero unresolved legacy-source or
unknown-severity rows. The local-v3 count establishes compatible retention,
with explicitly false inferred server ACK and alert identity. Semantic event
decoding is not performed by this gate. The stopped queue SHA is
`5ad561ca4a66a876dcccc6d441abb2549eb8235a5b55f492e2a3984033c9a8ab`.

The installation owner starts at 06:48:27.6302525 UTC, starts official Setup at
06:48:46.6930910 UTC and completes at 06:49:43.0907237 UTC. Setup actually exits
0; the owner is completed with no installer pending. The resulting one Running
SYSTEM-task generation is 601 PID 4464 / creation filetime
`134356565652927026`, binary SHA
`ca71ab98f8a9b6da404a305311da34748a1d4ed91c51f1857ba8b78ec049312c`.
Primary/LKG configuration and the CA remain unchanged; independent policy
sequence remains 524. Current installer verification/health reports are
freshly bound to this Setup execution. No separate index-bootstrap operation
is executed.

The bound health sample reported at 06:54:21 UTC has current CPU 6.90%,
10-second average 3.18% and 60-second average 2.41%, with the unchanged 10%
budget, pressure/throttle zero, eventbus used/dropped zero and current
source-only loss flag zero. The recovered 600 sample at 06:42:48 UTC already
has eventbus used zero while its current CPU is 20.25%, 60-second average
24.98% and pressure/throttle remain active. Thus the new-generation resource
observation is favorable, but bus clearance cannot be attributed to the index
change. Restarted cumulative counters are not subtracted across generations;
the earlier process-local sticky loss history and 600 failures remain intact.
This sample does not prove complete collection, detection or ACK behavior.

At 07:07:15.4365873 UTC, the bounded queue comparison reads the immutable
stopped backup and a consistent read-only live transaction while verifying the
601 identity. All 507/507 original record IDs, batch IDs, payload SHA values and
lengths are present and equal, covering 948,210 original payload bytes. Missing,
identity-changed and payload-changed counts are all zero; both sides read
1,896,420 payload bytes in 89 ms. The probe retains the 4,096-row / 128-MiB,
8-second statement / 90-second total bounds. Its full report establishes exact
preservation of that original inventory; `server_ack=not_inferred` and per-row
status reporting is not an admission/ACK assertion.

That comparison's launcher separately fails with outer exit 1 after its
`Start-Process` child exit is returned as NULL. The comparison stdout and
exclusive full report are complete, with child stderr zero, but actual child
exit remains UNKNOWN. The exclusive queue comparison is not rerun.
Semantic preservation PASS and launcher-exit failure are
recorded separately.

The cache invocation receipts `actual01` and `actual02` retain real
`ParserError` / `UnexpectedToken` failures, outer exit 1 and empty stdout,
before SQL executes. The separate `actual03` invocation captures the actual
native child exit 0 through `$LASTEXITCODE`, with child stderr zero. Its
07:13:02.3007061 UTC report compares the fixed 20 selector IDs against the
later stopped cache backup and a read-only live cache. All common columns are
equal for 20 candidates, 5,120 scoped reference occurrences and 5,120 scoped
fact occurrences; all 5,120 fact bodies are byte-identical. There are zero
missing, changed-common-column or changed-body occurrences. Schema columns
and cache user version 2 are equal on both sides. The bounded comparison reads
24,980,880 canonical/value bytes in 1,616 ms, with no database modification or
server ACK inference. Counts are scoped occurrences; shared facts can repeat.

The old baseline is used only to select those IDs. All 20 candidate hashes are
equal from that baseline to the stopped backup, while all 20 reference/fact
set hashes differ before this upgrade. Stopped-backup-to-601-live hashes are
equal for every selected set. This proves the stated subset survived this
upgrade; it does not erase the original failed baseline comparison, establish
whole-cache preservation or infer confirmation of any retained source payload.

The first installed-601 native-short capture runs from 07:18:07.7509603 to
07:18:54.4892207 UTC. Probe, observer, cache and trace start/stop exits are 0,
and trace stop is explicitly true. The trace reports 90 records read, 12 matched,
zero parse errors and zero reported ETW events/buffers lost. Circular-file
completeness and API-truth/per-action joins remain separate checks. This is
completed capture evidence, not final collection/detection/alert/context/ACK
acceptance. At that capture checkpoint analysis is pending; the completed cases and
consumer results are recorded in the following section.

## Installed 601 field observations and remaining acceptance boundaries

Two new bounded synthetic cases actually execute, each with three children,
concurrency one, 45 seconds of observation and no policy change or business
command. Each uses a separately fresh full server preflight, the pinned wrapper
and exact installed PID/birth/binary/configuration/CA. Pressure, throttle,
source-only loss/retry/degraded masks and eventbus drops are zero before both
cases. Native-short holds each child for 100 ms; network-loopback holds it for
3,000 ms and uses loopback only. Their outer 20-second transport waits expire
without restarting the owners. Subsequent exact completed receipts capture
real native exit 0, not a timeout interpreted as success.

| Measurement | Native-short | Network-loopback |
| --- | --- | --- |
| Wrapper UTC window | 07:18:06.2492491–07:18:55.1279719 | 07:22:52.6653503–07:23:40.7586028 |
| Requested / completed children | 3 / 3 | 3 / 3 |
| Owner, probe, observer, cache exit | all integer 0 | all integer 0 |
| Trace stopped / reported ETW loss | true / 0 | true / 0 |
| Distinct truth generations / ETW lifetime matches | 3 / 3 | 3 / 3 |
| Scoped raw ETW rows | 12 | 33 |
| Truth action count, including exit/network actions | 6 | 12 |
| Original strict per-action raw observation | 6 OBSERVED | 6 OBSERVED, 6 UNKNOWN |
| Strict local / sampled wire / exact child server actions | each 6 UNKNOWN | each 12 UNKNOWN |
| Captured queue batches / decoded frames | 723 / 870 | 747 / 894 |
| Fetched actor-PID-or-marker server subset | 30 rows | 0 rows |
| Server rows with exact child PID/birth/scope | 0 | 0 |

The capture and execution checks pass. They do not establish field collection,
rule evaluation, expected filtering, complete local retention or ACK for each
action. Historic held records are included in the sampled queue counts; these
are not newly enqueued/sent/received counts. The server subset uses the existing
source-time window expanded by 120 seconds and actor PID or case marker. It is
not the full endpoint receive window. The native subset's 30 records are outside
the three exact child generations; their independent durable ingest timestamps
are 07:19:54–07:19:58, after that trace ends. A parent/collector command carrying
the marker can fall into this subset. Its normalized rows do not preserve
sufficient structured rule/trigger evidence to verify alert identity, necessity
or exact original protobuf association. Alert/source status remains UNKNOWN;
a `p0` envelope, severity, score or record count is not accepted as proof.

The verification owner `outer scripts/telemetry_quality/analyze_actions.py`
initially compares native decimal UInt32 IPv4 addresses and UInt16 PORT values
with formatted truth tuples. This creates three false UNKNOWN connect results.
The repair in outer commit `72d7a922` follows the
[Microsoft TDH IPv4/PORT contract](https://learn.microsoft.com/en-us/windows/win32/etw/using-tdhgetproperty-to-consume-event-data),
accepts only bounded canonical unsigned facts for supported provider/event
schemas, and preserves formatted addresses and generic host-order port aliases.
The new same-shape three-tuple regression fails before the fix; the complete
focused analyzer suite passes 41/41 afterward, including wrong provider/schema,
PID/birth/time/tuple and malformed-value negatives. Independent saved-data
reanalysis, with no guest operation or decoder rerun, changes network raw results
to 9 OBSERVED / 3 UNKNOWN. All three connects match; the three listens still lack
explicit provider evidence. Every local/wire/server action remains UNKNOWN.
Original traces and reports are immutable; the new derived report records the
new parser source. This repair changes verification tooling only, not the
published Agent or any runtime collection behavior.

Exact follow-up read-only metadata verifies all 30 native-subset batches against
the same tenant/endpoint and saved batch set. Every queue job reports 601,
`done`, a matching accepted batch SHA and server completion. All 30 stored
`payload_b64` lengths are zero. This agrees with the current backend's normal
`ReportEventQueueSQL.MarkDone` cleanup after completion; it does not establish
that the running backend has the current source build. The original decoded
batch cannot be recovered from this table for retrospective rule/context/body
verification. No body or options JSON is exported, no real record is modified,
and no local ACK is inferred. Structured alert identity and necessary-context
acceptance for these unrelated records therefore remain UNKNOWN.

The first V2 completed-case consumer fails before its backend query because the
native producer serializes its five counts as canonical decimal strings, whereas
the prepared fixture checked integer literals. Its failed capture is retained.
A separate private V3 consumer accepts only integers or canonical unsigned decimal
strings for these five counters; boolean/float/negative/noncanonical/overflow
values are rejected. Owner/child exit checks remain strict integer zero and all
identity/trace/byte/provenance guards remain unchanged. The original 11 offline
tests and three added tests pass (14/14), including 105 invalid-count subcases;
the identical real-owner string-count fixture fails before the repair. Both
completed cases then collect successfully into a fresh private directory with
the pinned current decoder and immutable original-frame byte/count checks. No
workload is rerun and the failed V2 evidence is not overwritten.

A combined historical receive window triggers MySQL error 3024 under the existing
8-second statement / 12-second client bounds; that failed receipt is retained.
Two first attempts using Windows seven-digit fractional timestamps fail host
argument parsing before sampling. Converting timestamps to supported UTC
microseconds and querying each actual approximately 49-second case separately
passes without increasing either deadline. Each exact receive window has zero
ingest jobs, processed events or business alerts. These zeros do not prove
intentional filtering or no missed detection; source-time marker queries and
server receive-time counts measure different boundaries.

The later full samples at 07:46:52 UTC still report 601 online with verified
applied policy, 60-second CPU average 2.21%, current CPU 2.98%, pressure/throttle
zero, eventbus used/dropped zero and source-only loss/retry zero. Eventbus pushed
is 35,034 versus 19,021 before the first case, with no within-generation drop
increase. These counters cover the whole interval and background activity;
collector callbacks and bus pushes are not distinct case-event counts. The
runtime reports 68 successful event POSTs / 163,114 actual request-body bytes
cumulatively, versus 35 / 72,845 before the first case, and health attempt-body
bytes 291,378 versus 148,531. Neither delta is assigned to the three child
actors. Detection-evaluation and exact case enqueue/ACK counts remain unavailable
rather than being reported as zero. A final independent read-only runtime check
confirms the original 601 PID/birth/binary, Running SYSTEM task and unchanged
configuration/CA after both cases. The strict field no-miss/necessary-context/ACK
acceptance remains incomplete; normal collection and detectors were not reduced
to obtain these results.

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
| `pmfe-recovery-query-ckh5ehf9/owner-verification.json` (host indexed-owner regression) | `c6757c42653a8b819a9d8ff6f0ed007fdb1bbe66ac7e47c3a0662a0cc262cdc0` |
| `edr-601-host-mtls-receiver.log` (sandbox bind limitation; no scenes executed) | `c3d5912af546b91c01c473f56aed517a0719a3a6dbcd01a3afaab44c18aad790` |
| `edr-601-host-mtls-receiver-unrestricted.log` (actual nine-scene host PASS) | `45d6cda4faae7bfbd8669a0e549579144c365b9e0593d480fce9367662ee7ec2` |
| `601/template-manifest-v2.json` (six frozen private owners) | `318e84dcda3a6e6d7be7cecd8fd1714d18ccd89c8a87299a52e0fa4463319ba8` |
| `601/mechanical-adaptation-review.json` | `048de63bcd84d43fb70cd839343822b58968871b24f8b80c925bf7ca53f3f92b` |
| `601/windows-parser-receipt.json` (AST only; owners NOT EXECUTED) | `7b6a338bac717c4039d5d6dce051efe1d0a986da64a195b171a60f4716b65298` |
| `601/windows-parser-freeze.json` | `14a71ea1d6de0b6835c8c7d8c7cbf48ae7cc332a450e3cad216c1caec32b0c02` |
| `601-ci/amd64.log` (71/71, 18/18, actual mTLS) | `3e599837c3732d05f46653cae04fa6894608b8cbc33a8800e5ed2eece789f43e` |
| `601-ci/arm64.log` (71/71, 18/18, actual mTLS) | `81e1b00bc78d685ce899139303468f8b08cc16f1ac6516ba165b478329dab64a` |
| `601-ci/lifecycle-amd64.log` (actual Setup/runtime steps) | `3bcb24d222983e7eb99570d384bb838fe4483f3ee2cd1edfacc861c433ad63f2` |
| `601-ci/lifecycle-arm64.log` (actual Setup/runtime steps) | `5d126c1db6fbd0e9b9eb892b89d55bf8ec2c5c615c33d7ee9ed0e654c59be064` |
| `601-ci/ci-release-summary.json` (all seven jobs and source/tag/latest binding) | `918c1d2f17ecdef3e6602887f1cdf5e5bfeae47efa13a9e411ac9dd46073cf98` |
| `compat601/stopped-queue-gate-601-v2.ps1` (new private gate source) | `a1833f65d957179b23af1ec8d2c68a035348dfd268a884ed16ab78550e158141` |
| `compat601/compat601-synthetic-v2.private.json` (20 native pure-decision contracts) | `7c681816e505ca0a8e6b98fe79209e38cf19d49fa7e48df5b06e7015afc293b6` |
| `compat601/compat601-review-verification.json` | `585642da037623ecf0fab0ccffe62835631feba5756f55e46a64d7871f1c2816` |
| `601/owner-exit-parser-guard-receipt.json` (AST/exact condition only) | `d3c29550609eabdec6dbf4e02f2f111b5b360f56a12bd52abebdebf52383240c` |
| `601/owner-exit-parse-freeze.json` | `8183f1f4cb079b9b30364fb7685459edfcca74d7fe03c8abfdddb742c4db47a5` |
| `601/revision3/template-manifest-v3.json` | `2c8bb946dbd4b0133db4f132ec249fe59f609817a1647be9cf0bc3334321ac79` |
| `601/revision3/revision3-validation.json` | `2c87698890761967e3538b4b3a3660f90083a40189b49515e86066b4db65a088` |
| `601/revision3/windows-ast-hash-validation.private.json` (four AST/hash checks only) | `8ae02e017a46944ec4f02cae573acd41e0c0e82a76c9cc30b8293c4dca79ea23` |
| `601/arm64-download-attempt1-failed.json` | `316e5498d502714b750321630a8e4f1ab10338719af5d49155e6a1b4aad11cb7` |
| `601/arm64-assets-fallback-verified.json` | `ae677e11a202fb0025e909cc9c452b75f2205eea010f6d48abb3e15a48a8b8bd` |
| `601/prepare-execution.json` | `5f7b5fc2f6fc1aa93cd85336b3746f7a00347ac94d91f1458d5da370bcff77d2` |
| `601/install-result-failed.private.json` | `5a8d9ef35ae095f84739fd0f953ac085497104a232ee89849f4fab2ded0113c2` |
| `601/failed-stop-inventory01.json` | `0ddeaa46da3a5377a7434bbdee1c2021ceadbb95ced614e8a4312fd9f6578423` |
| `601/restore600-poll01.json` | `b83dfc3f1310e270aa1407cfa61aca8832ddb9f9554713f937a3bb82b26256c8` |
| `601/recovery-adoption.json` | `5c520d43971ab75cae95ec65904009ce89d860e60ba9413833b0d42e7d81d8b5` |
| `601/server-600-restored-full04.json` | `b6c0896d92adf1721f2e605f0af6fa4f23aec35c3a187f83cab4742fead0a2db` |
| `601/field-consumer/prepared-owner-exit-v2.json` | `e797f089579c6a1ccaa3a689dd070979de1233770256e2f292ad927051ff410d` |
| `601/decoder-current/decoder-validation.json` | `3849d6e0e32222876e9130b41ee89294e692376b856a24a710acbfb4642dd415` |
| `601/source-only-loss-semantics.private.json` | `9c627235b1b200e5eacac0699ed4c93c4d0fc7d63877bb41de0a85e3efef81c0` |
| `601/shutdown-600-owner-harness-plan.private.json` | `317ed47a142dff970cb939477db435155c98eb39336ab0a3b2167c481d859430` |
| `601/failed-stop-preserved-manifest.private.json` | `22af262d7c393e0eb429e205c9e2e1c663fa238d52919b76c82bf29e47e54e88` |
| `601/attempt2-native-fixture-launch.json` | `f19ea0e6f7f6e8477642ea689a69b01783d666b159e89f0a33780219ccbdbc23` |
| `601/attempt2-prepare-execution.json` | `0f3a3d9b4d334d7d7df9244976c14e4693460ff65d044c9b87e3ebe6eeed2e3f` |
| `601/attempt2-probe-compile-execution.json` | `066d2bcdd37c5616ce5998e8e6459173bac35029fa5ff501ab14aba9e82b47af` |
| `601/attempt2-install-result.json.private.json` (actual Setup exit 0 / bound 601 generation) | `fd1c5b11ec28fb3bb16bfc58f229703b0b63af2c6d99a792f42af322f2c9f1c1` |
| `601/attempt2-stopped-cache-manifest.json.private.json` | `b30837000ac944474004eb361bc97856baec82a640e7b59af50a1d307ffc27ea` |
| `601/attempt2-stopped-queue-gate-601-v2.json.private.json` (actual compatible retention gate) | `96f0bef8afc032ffc0008c840e0864f8d6d91530ef70185d16d909c8f419afc0` |
| `601/server-601-installed-full01.json` (bound resource sample) | `cb864b853985bcd899eddd6ccda5be8e419128ec3e68f12cb775c239fb785d8d` |
| `601/actual-queue-retention-readonly.json` (complete 507-row preservation report) | `3c67b7ba3a3e006f3fbd7f16f504bfa7c8d2b89244f1aac6a3d952b9b6e5eda9` |
| `601/actual-queue-compare-actual-stdout.json` (semantic preservation summary) | `6ccfe04779a87c8c31a6efab3db147213e43f9d91ac19ef00f5598b4ad1adec4` |
| `601/queue-compare-operation-actual01.json` (outer exit 1 / child exit UNKNOWN) | `1b340f8bbf1dbcc7806fd7626083e26dc8f8e51d968d89931d5b495b1e3d3724` |
| `601/cache-compare-operation-actual01.json` (pre-SQL parse failure retained) | `e22194bc09e9efde0b28f41801cfc2739d633be9db3ea48b768b895b5a014fcf` |
| `601/cache-compare-operation-actual02.json` (pre-SQL parse failure retained) | `e22194bc09e9efde0b28f41801cfc2739d633be9db3ea48b768b895b5a014fcf` |
| `601/cache-compare-operation-actual03.json` (separate completed invocation) | `d65b5a270464a120915655f3afd2af46366c06182b1f40e829fe32a016040769` |
| `601/actual-cache-compare-actual-stdout.json` (20 / 5,120 / 5,120 subset comparison) | `a47b18cec7112d7caf977ec030939a3cf030cc6001a220bda71e75edddf988d9` |
| `601/actual-cache-compare-actual-exit.json` (actual native child exit 0) | `d4f98e8ced45b9993b90ca75cbb566a771450cb3a31b523f47fed09154ca11e2` |
| `601/field-native-short/trace-result.json` (completed capture; acceptance pending) | `28ed6c4121b0adf67e494d93cdbd79656ae7014ef25216981999d0e916ecc347` |
| `601/field-native-preflight.json` | `efb17b2df6db4865d81ab378979b93d0ef3ea5c5a89f33cc5eb4c2fa3ff5b647` |
| `601/field-network-preflight.json` | `48c6435ba36d33bcc0aa7da02c47f7310e6ca965e8b7750b5a763e54eb3e881a` |
| `601/field-native-summary.json` | `f4b02e631cab1758aee54b9eedf102c3a209c4c8b09c9abaf2717465b9a178e3` |
| `601/field-native-outer-exit.json` | `711c208db1b9fd8692be55c9f40c3274107c11a42fa5ff2c7b0fa7452bdbadc6` |
| `601/field-network-summary.json` | `060eead4c74ba965a60a26998ad2d7915248d4bf79c395f6bc4bcc6525d62e53` |
| `601/field-network-outer-exit.json` | `101769042f2be76bf31d4afcf4417bb961d7702dc7edce490d2e6e169a667630` |
| `601/field-consumer-v3-validation.json` | `cff53a09bd188325d7d49df84b5da5235149ef7945e1e90ba405a04c2b720414` |
| `601/field-native-analysis-summary.json` | `d48447ca59cb1f4e8928aa766bdc243e63190cba8361d2cb8719407924033929` |
| `601/field-network-original-analysis-summary.json` | `750b8dda65c3fe07ef8b365e1aa1ee3674275197986439a58d02ff81e31ebf21` |
| `601/field-network-corrected-analysis-summary.json` | `90dd9b175ff50ce894efa309d1099cf0c029def9ca872b2527405bb747568f4c` |
| `601/raw-network-codec-validation-summary.json` | `9eaefc88a995b6135510cdae31db3c9e4f222e0a03ae9e6aaa918e236f031aeb` |
| `601/native-exact-batch-metadata-receipt.json` | `83cf780f60c00c4bbd881fb2e890feb2c765ed12320d5026a030ccf1276ef884` |
| `601/server-field-combined-failed.json` | `b308c64bafa577fad01289c88a135ae42c6ded5c03ba9b1b11389e87d861b45f` |
| `601/server-field-native-receive-counts.json` | `e4dddbed1871c307958bcdd77f9a3872829628c5beae16339a5222a98f2673a3` |
| `601/server-field-network-receive-counts.json` | `1e8e9e0a2bc1d2e255ed1583e07c85280867bd3547d973e76132b9e17a2f2f03` |
| `601/runtime-final-identity.json` | `3024020e7d45e5a38943bb159e4c996a6015c6174efa1fc64eb2d79746c649d5` |

The completed CI/lifecycle gates, verified 601 assets, second lab installation
and stated bounded preservation comparisons pass within their scopes. The
first 601 lab stop, installed-600 field result and original cache comparison
remain FAILED. Queue launcher child exit remains UNKNOWN with outer failure;
the first two cache parse failures remain failed executions. Both 601 field captures and bounded collection/analysis execute. Exact
per-action local/detection/wire/server/ACK acceptance remains UNKNOWN where
evidence is absent; successful observation does not turn these gaps into PASS.
Strict field minimization has not been declared complete.

## Detailed UNKNOWN investigation, 2026-10-05

This continuation is a read-only investigation of the installed 601 and the
two saved cases. It does not change detection policy, restart the runtime,
rewrite queues, migrate retained data, or publish a candidate. Only this ledger
is changed in the repository. Private bounded probes and receipts remain under
`/private/tmp/edr-agent-601-evaluation/unknown-investigation/`; raw commands,
user identities, credentials and payloads are not included here.

The nested repository started clean at `45a0f76e` on
`codex/release-workflow-convergence`; product code is unchanged from `3e5ddeb8`.
The outer repository was at `fd30c157`; its existing Agent pointer, signing
directory and concurrent frontend edits are outside this change. At 08:57:52
UTC, the guest still runs the original installed 601 process generation, with
binary SHA `ca71ab98f8a9b6da404a305311da34748a1d4ed91c51f1857ba8b78ec049312c`
and configuration SHA
`d6e73872e47d71ee88702ed42a5a8a48ccf662bbb9195e7cba154f17ce17f229`.
Later probes require the same exact `Get-Process` creation FILETIME. The local
API/second listener map to `edr-backend/bin/edr-api`; its file build information
says revision `6cdb5a97`, modified=true. This does not establish the exact source
of both running backend roles. Live database facts below stand independently
of the current backend source explanations.

### Per-action evidence: first unobserved boundary

| Saved case | Truth actions | Independently observed actions | Local / wire / server per-action result |
| --- | ---: | ---: | --- |
| Native short process | 6 | 6 | 6 UNKNOWN at each boundary |
| Loopback network | 12 | 9 | 12 UNKNOWN at each boundary; 3 listen actions also raw UNKNOWN |

These are action counts, not total ETW or queued record counts. Re-reading all
870 native-case and 894 network-case decoded queue records without an action
time filter finds respectively 1 and 8 same-PID records, but zero exact child
generation matches. Six network records have no generation, and their event
times predate the child lifetimes. The same-PID process rows belong to older
generations. Widening the join window cannot convert these into case evidence.
Both saved local exports contain zero event/candidate/context records.

The first unobserved boundary is between the independent OS observer and the
Agent's per-event admission/evaluation disposition. Independent ETW observation
does not prove the Agent decoded or evaluated the same action. Conversely, the
current observer cannot prove a normal local disposition:

- `local_evidence_cache.c` records ordinary context in its in-memory ring;
  durable process upsert is part of candidate recording. The SQLite observer
  does not read that ring or prove each detector's input. Its absence is not a
  detection failure or proof of successful local retention.
- `sensor_interest.c` and `collector_win.c` have lifecycle/network admission
  branches. Process-exit cache/AVE notification precedes some event admission
  gates. These are possible explanations, not historical per-action receipts.
- `run_case.ps1` enables Kernel-Network for the independent observer. The
  Agent's separate TCPIP mapping includes listen handling; the current raw
  consumer does not establish equivalent listen coverage. Three missing listen
  observations cannot be classified as Agent loss from this capture.
- `analyze_actions.py` uses UNKNOWN when no matching record and no authoritative
  per-action expectation exist. It has raw/local/wire/server stages, not an
  instrumented detector or ACK stage. Assigning every action a required-upload
  expectation would contradict minimization; assigning expected-filter without
  actual disposition evidence would conceal loss.

### Necessary alert context: exact associations exist, but for the exporter

The fixed 30 source IDs from the native-case export join to **30 alerts and 30
emitted P0 dispositions**, all `R-EXFIL-006`. This resolves the earlier lack of
an alert-table association for this set. All 30 persisted process contexts are
valid JSON. Prior exact field checks also bind source/rule/bundle and actor
generation; the new bounded aggregate receipt independently rechecks counts,
rule identity and context status.

They are **not the six native-short target actions**. Saved source comparison
finds one actor generation, zero truth-child generation matches and zero
truth-parent PID matches. All 30 target the native case's evidence export ZIP;
all 30 privately decoded script suffixes exactly match the current
`collect_case.py` export template after root/case substitution. They consist of
one file-create and 29 file-write events caused by test evidence packaging.
The case marker and extended source-time query included the exporter. Rule
association does not make it a successful per-action test, nor does this archive
activity alone prove actual exfiltration.

The context conclusion remains narrower than full sufficiency:

- `decision_completeness` is 0.6 (3/5), with no generic critical missing fields.
  Earlier field inspection found command, parent chain and process path
  available; executable hash/signature were not reported. This generic score
  does not prove rule-specific investigation sufficiency.
- All 30 additional server predicates are `not_evaluated`. The current
  `p0RulePredicateAssessment` only implements the extra check for R-LOLBIN-010;
  this value alone does not invalidate the separately established R-EXFIL-006
  endpoint match.
- Persisted, enriched context sizes are 158,681–161,585 bytes. These are backend
  JSON sizes, **not outbound HTTP body sizes**. Original protobuf bodies for
  the 30 done server jobs are no longer stored, and the saved queue capture did
  not establish their original bodies. Field-by-field outbound minimality
  remains unverified for this set.

The exporter creates real detector input and therefore contaminates a test
whose backend query relies on marker/time alone. Future evaluation must join
the intended actor generation and separately account for the export process.
Suppressing all PowerShell/archive activity would be an unsafe substitute.
Whether repeated writes to one archive should aggregate belongs to the rule's
alert contract, with evidence preservation and dedup regression coverage.

### Local ACK: receipt, queue commit and retained evidence are distinct

The earlier exact server query confirms 30 accepted/done batches with matching
batch identity and payload SHA. At 09:02:50 UTC, a bounded read-only live SQLite
transaction finds none of these 30 IDs in `event_queue` or the terminal journal.
The entire current terminal journal is empty. This is an absence observation,
**not a local ACK receipt**.

The production path is:

```text
immutable queued body + batch ID
  -> request -> server durable/processed receipt
  -> validate endpoint + batch + exact body SHA + acceptance
  -> exact selected row/generation deletion transaction
  -> local delivery counter / severity-1 diagnostic
```

`report_events_ack.c` validates the receipt; `ingest_http.c` returns transport
success after validation; `queue_sqlite.c` separately verifies the selected
database generation/row/body before deletion and increments the in-memory ACK
counter. Standard queue removal leaves no general per-batch durable ACK
receipt. `p0_deferred_match=completed` records queue handoff, not server ACK;
the current 375 completed entries cannot fill this gap. The enforcement journal
is a separate owner, not a universal receipt ledger.

Two supplemental evidence paths were checked:

1. **Health profile omission is confirmed.** The fixed installed config has
   basic profile, disabled diagnostic monitoring, 60-second interval and expiry
   zero. `agent.c` emits queue delivery counters only in the diagnostic branch;
   its normal basic branch emits smaller `p0_acceptance.offline_queue` metrics.
   The live server record at 09:09:36 has that smaller object but no
   `p0_offline_queue_capacity`. The transport whitelist allows the missing
   counter paths, so it is not the cause of their absence. It does omit
   `monitor.profile`, explaining why the server cannot directly identify this
   profile from that field. Missing counters are NULL, not zero; even aggregate
   counts would not establish ACK of these exact batches.
2. **The current launch path does redirect logs.** The live parent, scheduled
   task and bounded startup-log markers identify the PowerShell task launcher
   and this exact Agent PID. Its installed script redirects stdout/stderr.
   The competing native-worker-without-redirection explanation is excluded
   for this process. Both redirected files are zero bytes. The exact ARM64
   binary is a console-subsystem PE and retains queue diagnostic literals.
   Why this live process's expected diagnostics are unavailable is unresolved;
   empty files do not prove an ACK error. No process injection, handle rewrite,
   verbose-policy change or restart was used to force a result.

Current queue health also requires separate treatment: the snapshot contains
933 local-evidence rows, 2 policy-held rows (`alert_provenance_unavailable`) and
93 dead letters (`max_retries`). The source-only owner is v3, clear, loss=0,
session=open. These describe current retained state; they do not identify which
version created the dead letters or prove uninterrupted detection during the
earlier action windows. No retained row was deleted or migrated.

### Checks, rejected explanations and remaining acceptance

| Check | Result and limit |
| --- | --- |
| Exact installed generation/binary/config refresh | PASS; unchanged 601 identity |
| Saved-data generation reassociation without time filter | PASS; no exact child-generation wire matches; this preserves per-action UNKNOWN |
| Exact 30-source alert/disposition and exporter comparison | PASS; valid associations, wrong workload actor for target-action acceptance |
| Bounded live queue/journal read | PASS, native exit 0; 48 ms read; absence is not ACK |
| Basic-profile/config and server field-presence check | PASS; optional counter/profile visibility gap identified |
| Task/parent/log-owner read | PASS after correcting diagnostic time precision; missing output remains unexplained |
| Initial long encoded SQLite probe | FAILED to launch; compact bounded probe executed separately |
| Initial log-owner probe | FAILED its guard: a separate same-process check confirms CIM differs from Get-Process by six 100-ns ticks; replacement retains the exact original Get-Process FILETIME guard |
| Initial health-query result adapter | FAILED on list/string mismatch after the read; corrected adapter obtained the same bounded query successfully |
| Initial private saved-data import | FAILED before analysis due to missing module search path; corrected import replay passed |
| New detector workload, real request-body capture, ACK-loss/crash trial | NOT EXECUTED in this read-only continuation |

The next discriminating test needs one bounded, generation-bound disposition
trace spanning Agent admission, detector evaluation and local retention, plus
one known rule-positive action and its necessary context. The receiver must
capture the immutable body/hash and issue real receipts; the local owner must
expose receipt validation separately from committed removal. Reusing the
existing queue/transport test owners is preferable to adding a second sender or
inventing ACKs. Health-counter availability can support this trace but cannot
replace it. A capture covering the required listen provider is also needed.
No historical action can be upgraded from UNKNOWN by a later synthetic replay.

This investigation confirms measurement/consumer gaps and a diagnostic profile
visibility gap. It does not establish that all 18 actions were evaluated or
lost, that complete minimal wire context was retained, or that local ACK
committed for the 30 batches. No speculative runtime patch or release is made.

Private receipt identities for reproducibility:

| Receipt under `unknown-investigation/` | SHA-256 |
| --- | --- |
| `inventory-receipt.json` | `4760ae9cea567f9ee8a1ffdc18405953d0e8a059ba3f6035f318d2693025ad71` |
| `saved-generation-recheck-receipt.json` | `772a1a2f5f92cee6fdbc8fddc4f9f5df9e936d5ca87892c9ab35591af8d0e585` |
| `exact-alert-summary-receipt.json` | `570ed157d48faff965a36798d915b2c8c7a5a057ec9f07dfb5a3962d59ddc689` |
| `queue-ack-compact-receipt.json` | `edf0da9e18e556dcf9f98edf463e642955f00c96436ff7a04a6710da7b20c9d5` |
| `health-profile-v2-receipt.json` | `f6b966d09224c0a4ac9eef393ca75f2d7bd304a4d363d2be33b7dd1b572b3e32` |
| `health-config-receipt.json` | `b145797ff524582b3ad733b83df7e81345a19c7203bcd214efd66f4149ec6502` |
| `log-owner-v2-receipt.json` | `f670e81b52400ba6700c7cfc7c9395d530ee781ccff349fc7d115ded76bdfe6f` |
| `generation-precision-receipt.json` | `8ae5d3e2870c1d47507f8d2008004ceb64dd68c8b0045fa41e48959b52b694ea` |

## Follow-up implementation: bounded observation and ACK witnesses

Baseline: clean nested `codex/release-workflow-convergence` at `2b0e52fd`;
product baseline `3e5ddeb8` / candidate 601. Existing outer frontend changes,
Agent pointer and signing directory are excluded from this implementation.

The preceding investigation established two product observability defects and
one experiment attribution defect, not proof that all missing ordinary events
were lost. This change preserves detection/admission decisions:

- `queue_sqlite.c`: every actual accepted delivery now commits a hash-only
  `delivery_receipts_v1` witness in the same FULL transaction as ordinary row
  deletion or independent terminal-journal acknowledgement. Batch-ID SHA256,
  immutable wire SHA256, byte count and local ACK time are the only facts.
  At most 1024 witnesses remain. Eviction or absence is UNKNOWN, never a NACK
  or an ACK. Reopen of an old database adds an empty table and never backfills
  historical deliveries or rewrites existing payloads. Local persistence or
  commit failure rolls back queue/journal acknowledgement for retry. The table
  is not read by detection, sending or server acknowledgement validation.
- `agent.c` / `egress_request_policy.c`: basic health exposes the existing
  selected/sent/acked/requeued/failed/resource-deferred counters and receipt
  write failures. Both basic and diagnostic profiles admit the explicit
  `monitor.profile` enum. No source event is relabelled health.
- `validation_trace.c`: a disabled-by-default local observer records actual
  collector interest, preprocessing rule/disposition and evidence-retention
  boundaries. Only an explicit executable basename and its direct children
  enter scope; subsequent matching requires a non-conflicting process
  generation. Unresolved generation stays unresolved. Combined alert encoding
  binds source event to immutable batch/wire hashes; the HTTP owner can then
  capture that batch's actual JSON/protobuf request body (not headers).
  These observations neither emit an alert nor acknowledge a batch.

The temporary observer's current consumer is the controlled Windows action
experiment. Administrators opt in with `EDR_VALIDATION_TRACE_PATH` (new file in
an owned protected directory) and `EDR_VALIDATION_TRACE_IMAGE` (exact basename).
The task launcher refreshes just these two values from machine environment,
including clearing stale inherited values. The operator removes them after
launch. One session is limited to 300 seconds, 8 MiB including body hex, 128
process generations and 128 batch IDs. No overwrite, rotation or upload exists.
Metadata excludes command lines/user names; captured scoped alert bodies stay
private. Main-loop flush owns disk I/O; producers never wait for it and record
observation loss instead. The consumer must account for an incomplete/truncated
session and dropped observations, and never infer an absent event from them.
After this investigation the opt-in is removed; default production operation
allocates no trace buffer and opens no trace file. This is a temporary diagnostic
facility, not a new telemetry purpose or policy exception.

Validation before candidate publication:

- FAIL-before/PASS-after: exact durable ACK witness test, including write fault
  preserving original row; health projection preserves profile and ACK count.
- PASS: reopen/old-schema empty addition, transaction commit rollback, bounded
  1024-witness eviction, foreign batch/mutated wire rejection, lost/missing
  remote receipt, independent intent/source/combined journal ACK witnesses.
- PASS: trace scope rejects PID reuse/conflicting key/unrelated actor; preserves
  same generation/direct child; captures exact scoped JSON/protobuf bytes;
  rejects overwrite/invalid scope, enforces TTL/generation/byte bounds, reports
  drops, redacts invalid diagnostic tokens. POSIX output is mode 0600.
- PASS: host 45 selected runtime/minimization contracts; separate loopback mTLS
  real-request/receiver/ACK matrix (22.43 s). The first mTLS attempt could not
  bind a loopback port in the sandbox; authorized rerun passed with ordinary
  TLS verification. That environmental failure is not counted as a pass.
- PASS: MinGW builds the trace contract with warnings as errors; host Agent
  builds; release checkpoint 40 tests, workflow 15 tests, USB bundle checks and
  AVE chain invariant check. Native Windows gates and deployment acceptance
  are pending at this checkpoint.
- NOT EXECUTED: full old MinGW build directory regeneration fails because its
  nonproduction dependency configuration lacks required OpenSSL gate targets.
  It is not a release build and does not replace native AMD64/ARM64 gates.

The trace can prove observed per-event edges, not recover the missing 601
historical trace. A validated HTTP response proves durable ingest admission;
backend asynchronous rule/alert completion is a separate join. Witness table
creation is additive local observation, not permission to migrate real retained
source-only or legacy mixed batches. Existing payloads/identities and gates
remain subject to the prior compatibility boundary.

### Candidate gate correction and native listen boundary

Candidate 602, run `37292990915`, was blocked before publication/deployment.
The new `validation_trace_contract` was registered in the CMake release gate,
but the dependency fixture's independent expected set was not updated. The
fixture now expects it and the isolated P0 compiler probe links the actual
new trace library. No failed gate is bypassed. On the host, the full 19-case
fixture run also encountered two 90-second CTest timeouts under parallel dummy
binary execution; those are reported separately from the fixed expected-set
failure. Both timed-out cases passed in the focused sequential rerun (163.14 s).
Native CI remains the release gate.

A read-only query of the lab Windows TCPIP provider established another concrete
cause of listen UNKNOWN: event 1002 is a connection request; 1123 v0/v1 is a
successful listener activation, with binary `SocketAddress`, payload ProcessId,
and a v1 ProcessStartKey. The old map called 1002 NET_LISTEN and 1123 NET_CONNECT;
the generic UTF-16 property formatter also did not decode the sockaddr. The
collector now maps 1123 to NET_LISTEN and reads typed status/actor/family/length,
network-byte-order port and IPv4/IPv6 address. It never invents a remote peer for
a listening socket. Unsupported versions, missing identity, failed status,
family/length conflicts, zero port and truncated output do not become valid
listen evidence. Existing provider collection and detector policy are retained.

The native TDH replay uses the existing test suite's external-I/O fixture with
the actual pre-change and post-change `etw_tdh_win.c` (ARM64 binaries): old exit
41, new exit 0 on the same v1 IPv4 input; new code also rejects failed status.
Receipt: `fixtures-native.json` under private 602 evaluation artifacts. The full
native network test now covers mapping, v0/v1 typed fields, IPv6 loopback,
malformed variants, same-handle generation admission and real mapping before
publication. Its future CI execution is not claimed by the focused TDH replay.
The independent observer includes TCPIP 1123 and validates its typed successful
payload; its original Kernel-Network capture still covers connect events.

The additive receipt observer was also executed against the unchanged 601:
exit 0, complete read, schema available=false (no table). This explicitly
means no historical ACK evidence, and does not fabricate confirmation from the
current queue contents. The live Agent remained PID 4464, exact birth
134356565652927026, version 3.2.601, with the unchanged baseline binary/config
hashes throughout these isolated fixture checks.

Candidate 603, run `37295416212`, exposed a second isolated build-fixture
dependency omission: the PCRE2 header-order probe preserved the network target's
new trace link but did not define that library in its temporary CMake project.
AMD64 stopped with LNK1181 before the product build. The same fixture fails on
the host before correction (`library edr_validation_trace not found`) and passes
after importing the actual trace target's sources and usage requirements
(9.98 s), including its deliberately poisoned-header negative control. The
production gate is unchanged. Neither failed candidate is deployed or retargeted.

### Full collector listener admission regression

Candidate 604 (`37296796013`, source `0afb14fc`) compiled on AMD64 and ARM64;
both native gates passed 71/72 tests and rejected `etw_network_decode_native`.
The first deviation was downstream of successful typed decoding and actor
binding: the shared network admission branch required a nonzero remote port
even for NET_LISTEN. A listener has none. It now retains listener context only
after sensor interest and same-generation actor verification, with a nonzero
local port and an already suspicious actor. It does not create a remote peer,
reinterpret local ports as remote evidence, or establish alert identity.

The full native test now resets each listener fixture's actor counters, makes
its event-bus/AVE observation stubs explicitly accept valid listener output,
and counts empty-payload observations for malformed inputs. It checks v0/v1,
IPv4/IPv6, ordinary-actor filtering, unavailable actor with local port 3389,
seven malformed inputs and exact local-only decoded endpoints. The first
isolated after-run caught a pre-existing connect-only bus stub assertion; this
failed run is retained and is not counted as passing.

An ARM64 executable built from the complete native test's actual production
source list and PCRE2 10.47 ran on the existing Windows lab: identical final
fixtures with the old collector exited 1 at listener publication; with the
corrected collector the entire test exited 0. It includes real same-handle
Windows generation binding and diagnostic failure/boundary tests. Private
evidence: `network-replay-result-v2.json`, `network-replay-build.json`, and
`replay-v2-*.stderr/stdout` in the 604 evaluation directory. This isolated replay
uses a separately cross-built PCRE2 archive and is not the hosted release
dependency proof. Native production build gates remain mandatory before deploy.


### Candidate 605 publication and deployed acceptance

Candidate `win_3.2.605` is bound to `c5a3d27812c002d8f9bd3d101fcfd3bc61bfeffa`,
run `37299295683`. All seven jobs completed successfully, including both native
builds, both actual installer/updater lifecycle jobs and candidate publication.
AMD64 passed 72/72 native tests (143.63 s) and 19/19 minimization gates
(215.13 s); ARM64 passed 72/72 (299.09 s) and 19/19 (268.92 s). The
`etw_network_decode_native`, `validation_trace_contract`, SQLite ACK contract
and real loopback mTLS receiver gates passed on both architectures. This is
native CI evidence, separate from the controlled lab acceptance below.

Before upgrading, the actual lab ETW session contained seven providers and
**did not subscribe to the TCPIP provider**. Both the primary and LKG signed
configuration had `etw_tcpip_provider=false` while ETW and PowerShell were
enabled. Consequently ordinary listen actions cannot establish an Agent TCPIP
collector result under that unchanged policy. The typed listener fix is proved
by the native collector replay and CI; a live TCPIP-enabled acceptance would
require a separately authorized policy change. The experiment does not alter
that policy to make coverage appear complete. The independent observer can
still capture successful TCPIP 1123 listener events.

The pre-stop backend sample was online at 3.2.601, with rule/artifact/cache
ready, no source-only unhealthy/loss/retry flags, no resource throttle or
pressure, event-bus used=0 and pending sends=0. Its cumulative event-bus dropped
counter was 1114, already present before this candidate experiment; it is not
attributed to the new build. The guest was still PID 4464 with exact birth
134356565652927026 and the unchanged baseline configuration, trust anchor and
rollback installer. No trace opt-in was present at this checkpoint.


#### Actual candidate install and retained data

The published candidate remained prerelease and `latest` remained `win_3.2.591`
at the post-download identity check. Four deployment-consumed files were byte
verified against both GitHub asset digests and the immutable manifest: the
manifest, ARM64 runtime ZIP, independent Agent EXE and official Setup EXE. The
75 MB graphical Setup UI ZIP was not used or fully downloaded on this host;
its published identity was verified and full bundle/lifecycle validation had
already passed in CI. This is not described as a complete local bundle download.

ARM64 Agent SHA-256:
`abd161c69dca01a0b157273103db898a7989b1bc0a3f4130b7fac822da6d810a`.
Official installer SHA-256:
`bbcd2e173d528b7fd85c392a86cb6752a9819ec463221a54b5ec8032e5ea0bd6`.

The first preparation was refused with only 1.47 GiB free. Reversible NTFS
compression of closed experiment files preserved all contents and paths, with
SHA-256 comparisons before and after; no file or diagnostic was deleted. The
initial added space was too close to the 2 GiB gate: a second check after
protected copies refused before launching Setup and the recovery branch
restarted the unchanged 601. Four additional cold maintenance snapshots were
then compressed with identical hashes, bringing available space to 3,275,534,336
bytes. Fourteen cold files were compressed in total; active Agent queue/evidence
files and the required rollback installer were not compressed or changed by
these operations. Both space refusals remain failed receipts, not passes.

A separate attempt bound the restored 601 process generation and preserved the
first job. Native operation fixtures caught an escaped CMD receipt path still
pointing to the first job; correcting that unused script was followed by all
24 strict receipt checks and five actual CMD/replay checks passing. The second
normal stop, frozen backup and read-only historical queue gate passed. Official
Setup exited 0 and produced stable 605 PID 9552, birth 134356756862003710.
Primary/LKG configuration hashes remained
`d6e73872e47d71ee88702ed42a5a8a48ccf662bbb9195e7cba154f17ce17f229`, CA hash remained
`f1ea357ee8f28d7184f8bc1b9b4c85f5f75587b5466ae9a491d9ed5dd3f75efe`, and signed
sequence remained 524. No existing queue payload migration was executed.

Read-only comparison against that actual stopped backup found all **2,292
original queue records / 2,640,275 payload bytes** preserved, with zero missing
rows, changed batch identities or changed payloads. A first read-only probe
failed because its URI still named the first job's nonexistent backup; the
corrected URI completed the same comparison, preserving the failed receipt.
For exactly 20 historical candidate selectors, all 20 candidates, 5,120 scoped
reference occurrences and 5,120 scoped fact occurrences matched the stopped
backup; no fact body changed or disappeared. Shared facts may occur under more
than one selector, so these occurrence counts are not unique-fact counts.
Neither comparison infers any server ACK from retained or missing rows.

#### Controlled sampling: incomplete first window retained

The first installed-run experiment successfully executed 6 native process
actions, 12 loopback process/network actions and 4 encoded PowerShell process
actions, with no raw parse errors. Backend association used exact child birth
and source pairs. Ordinary cases had zero matching server events; both positive
children had an `R-EXEC-001` alert under signed bundle
`edr-dynamic-rules-v1-r283-e2008650`. Source and alert command lines, decoded
commands, process paths, parent PID and parent path matched the independent
truth (Windows path normalization only). Parent command lines were present;
the independent truth does not contain a parent command-line oracle, so their
byte equality is not claimed.

This first local trace is **incomplete acceptance evidence**: readiness waiting
consumed much of the 300-second window, only 5/22 actions had local observed
edges, 17/22 remained UNKNOWN, and the closed trace recorded 20 diagnostic
contention drops. It captured no request body for the two positive children;
zero captured deliveries is not zero delivery. Thirty-six durable local receipt
rows were observable, but unassociated rows are not counted as those children's
ACKs. Original input clocks and receipts were retained; the host Python 3.9
query-window parser required fractional-second normalization for a coarse
120-second search margin, without changing FILETIME generation identities.

Startup CPU throttling and a transient FILE-family source-only health mask
(2) were observed, with loss_detected=0 and event-bus dropped=0. Both states
recovered under the unchanged policy before sampling. They are not suppressed
or reclassified as healthy by the acceptance tools.

A second bounded sampling run retained the first evidence. Its first normal
restart stopped 605 successfully but did not establish a stable new generation;
no sampling was launched from that failed state. Read-only inspection found the
scheduled task Ready, last result 0, IgnoreNew configured, no Agent and no new
trace file. A separate start from that verified Ready state restored stable
605 PID 3008, birth 134356772078459664, with the same binary, policy and CA.
The exact cause of the earlier no-generation start is not established by these
receipts alone. Automatic readiness polling then started all three cases within
the fresh trace window; all case owners exited 0, no raw parse errors occurred,
and post-case health had rules/cache ready, no source-only unhealthy flag,
no resource pressure/throttle and event-bus dropped=0.


#### Second 605 window: request, alert and ACK join

The closed second trace contains 1,910 event observations, two encoded records
and two actual HTTP request bodies (443,845 bytes total trace; 30 diagnostic
contention drops). The eight child generations executed 22 truth actions with
zero raw parse errors. Eleven actions have explicit local observed edges:
eight process creates and three loopback connects. Eight process exits and
three listens remain UNKNOWN in this trace; its drops prohibit absence claims.
The ordinary native and loopback cases have zero exact-generation backend rows.
Three ordinary short process creates have explicit generation-unavailable /
resource-throttle-proven-miss dispositions. Two loopback-case creates have the
same throttle disposition; the third has a proven miss and local-only retention.
All three ordinary connects have exact-generation sensor-interest rejection.
These are observed decisions, not evidence that every detector evaluated every
ordinary action. Rule/cache health recovered without changing policy.

For the two positive children, the trace records `R-EXEC-001` emitted and queued,
with local candidate/context retention. Exactly two captured compressed protobuf
requests decode to two records: each immutable payload is 3,710 bytes, and the
actual HTTP bodies are 1,749 and 1,752 bytes (3,501 combined). Each exact batch
and payload hash agrees with server durable ingest (`done`, accepted=1,
attempts=1), the accepted batch owner, and the local committed ACK witness.
There are two exact-source backend alerts, with no excluded alert associations.
Independent truth confirms source/alert command lines, decoded commands, child
image, parent PID and parent image; the rule predicate is present. Parent command
line presence is verified, but equality is not claimed without an independent
parent-command oracle. No raw command or request body is committed here.

The initial host analysis failed because macOS system Python could not discover
the installed zstd library. Resumption explicitly resolves the existing
`libzstd.1.5.7.dylib`, keeps the same decoder and 8 MiB output bound, checks saved
inputs byte-for-byte, and performs read-only backend joins. It executes no new
actions and does not rewrite request/ACK evidence. The failed receipt remains.
All 36 witnesses from the preceding runtime are present unchanged among the
92 post-restart witnesses; no eviction occurred. This proves persistence of those
witnesses, not an ACK for unmatched historical payloads.

At final 605 runtime readback (2026-10-05 12:44 UTC), PID 3008 and its exact birth
remain unchanged, the scheduled task is Running, and binary hash/version match
the installed release. Both Machine trace opt-in variables are absent and the
trace is closed. The actual session still has seven providers without TCPIP.
No live TCPIP-enabled listen acceptance is claimed under the unchanged policy.

### Exit diagnostic follow-up after 605 acceptance

The remaining eight exit UNKNOWNs expose a diagnostic identity omission:
Kernel-Process exit has typed target ProcessID/CreateTime but no target StartKey;
the interest observation retained only StartKey. The event-header extended key
belongs to the logger and is not a valid replacement. The interest structure now
carries the typed eight-byte target birth only with a matching nonzero typed
four-byte payload PID from Kernel-Process lifecycle events. The local trace uses
that birth to join an already observed generation even when the exit name is
truncated or absent. Rule admission, collection volume and the ACK protocol are
unchanged. Missing/malformed identity remains unjoinable; PID reuse and PID-only
exit observations never close a different generation in the diagnostic join.

The same new trace regression fails against the 605 trace implementation (abort)
and passes against the change, including wrong-birth and PID-only negative cases.
The full native ARM64 collector fixture fails at the exact target-birth assertion
against the old TDH implementation and passes against the new one; missing PID,
truncated birth and a different provider cannot create a target birth. The replay
wrapper expected failure exit 1, but Windows returned -1073740791 for the old
assertion; the original child receipt and assertion text establish the intended
counterfactual without rerunning it. The new child exited 0. This is isolated
fixture evidence; publication and live acceptance of the follow-up remain pending.

Private evidence hashes (paths relative to `/private/tmp`):

| Evidence | SHA-256 |
| --- | --- |
| `edr-agent-605-evaluation/attempt2/replay/field-evidence/acceptance-summary.json` | `9bc7cda06f2c7f650a32006b43e8ba49ef4452e5696642aa7219edf45245c6fb` |
| `edr-agent-605-evaluation/attempt2/replay/field-evidence/server-batch-receipts.json` | `192cd5f66cbd47ced434d53d799cf6b8f3476518db06d109f8a8a8d7d6c459ac` |
| `edr-agent-605-evaluation/attempt2/replay/field-evidence/context-quality.json` | `ccbc8bde0f77213e20ff16deac605ca61b518e78921a0a951b6836fb55a3f5f1` |
| `edr-agent-605-evaluation/attempt2/replay/field-evidence/agent-validation.jsonl` | `a60639115eac3354cff84165de4443cbc8c0f0affb95b5834de9338fce2dd73e` |
| `edr-agent-605-evaluation/attempt2/replay/field-evidence/receipts.json` | `25a00f6370f00c146bf698644f8616e3789ae24d32abf62b227ae9c1b8ddc909` |
| `edr-agent-605-evaluation/attempt2/replay/receipt-restart-persistence.json` | `854956820162f054e66a720e6380fca41a769bfbf6f09b0b225db6e7a693a636` |
| `edr-agent-606-evaluation/trace-counterfactual.json` | `246713de32667a6cb1e3f52b4cd66336fa13a8c495f0224f2c5a9c2c41477ace` |
| `edr-agent-606-evaluation/network-replay-result.json` | `257c8f09e8ba4c0bba708e35ae04ef1217a5e65967fe369d530b72a713ca1444` |


### Candidate 606: native release and deployed acceptance

Source `4a9507389bae6cd4d4811cca31ed2b661ae7da7a` was published as
[win_3.2.606](https://github.com/qiuxinliang/edr-agent/releases/tag/win_3.2.606).
[Run 37312878137](https://github.com/qiuxinliang/edr-agent/actions/runs/37312878137)
completed all seven jobs, including both real installer/updater lifecycle jobs.
AMD64 passed 72/72 native tests (146.78 s) and 19/19 minimization gates
(218.38 s); ARM64 passed 72/72 (249.70 s) and 19/19 (220.86 s).
This is an unsigned candidate prerelease; `latest` remained win_3.2.591.
The first ARM64 log download reached its deadline; a second bounded download
retrieved the full successful log. Its CTest summary omits the optional
“0 tests failed” phrase; both 100-percent summaries and their test counts were
validated without rerunning or changing tests.

The four deployment inputs (binary, manifest, runtime ZIP and unattended setup)
were fully downloaded and checked against GitHub digests and the manifest.
The original download reached its 600-second limit before any Agent lifecycle
operation. A bounded HTTP 206/Content-Range resume retained the original partial
file and verified the complete resulting bytes. GUI ZIP bytes were not downloaded
or used; its release metadata and the successful bundle CI are separate evidence.

| ARM64 deployment artifact | SHA-256 |
| --- | --- |
| FDSensor.exe | `e792e7cdcebf52dfdb1c007778a68174a50e8dbe8f1e9b352b44cd0ddd863d2e` |
| Official setup.exe | `e108be2a06cd8788047a08185638878af4dc4f99513c2100d2617f3b6f100fe1` |
| Runtime ZIP | `e6ffaa48ca23d135abc3574697b944b0244c975b2bbf4e06998033ba3c39ad65` |

The verified 605 process stopped normally (875 ms, exit 0, no force). The official
606 installer exited 0 and started PID 4708, birth `134356819428736092`.
Primary/LKG configuration, CA and policy sequence 524 were preserved. The UTM
20-second launch wait returned before installation ended; the actual installer
receipt, rather than the transport timeout, established success. No installer
or synthetic case was blindly replayed.

The first 606 acceptance controller exhausted its 180-second readiness budget
with resource pressure/throttle present in reported samples. Rules/cache were
ready, source-only flags and event-bus drops were zero. It executed no cases,
removed its Machine opt-in and retained the closed trace (three diagnostic drops).
CPU snapshots exceeded the unchanged 10-percent budget; a later readback recovered
to pressure=0/throttle=0. Neither collection nor the budget was changed to pass.

A separately owned normal restart preserved that failed window, confirmed the
prior scheduled task Ready for three samples, and started PID 5028 with birth
`134356825692407918`. The stop exited 0 in 1,578 ms without force. The original
readiness predicates then passed before one execution of the three cases.
All case owners exited 0; all eight children and 22 truth actions succeeded;
independent raw ETW parsing reported zero errors. Raw matching still leaves the
three listener actions unresolved; zero parse errors alone is not full coverage.

#### 606 action, context, delivery and persistence results

| Observable contract | 605 second window | 606 window | Result boundary |
| --- | --- | --- | --- |
| Explicit local action observations | 11/22 | 19/22 | Observation is not proof that every detector evaluated every action. |
| Process creates | 8/8 observed | 8/8 observed | Two real positive rule emissions; ordinary outcomes remain locally explained. |
| Process exits | 0/8, UNKNOWN | 8/8 observed | Exact target birth joins; eight AVE notifications and interest rejections. No claim of eight alerts. |
| Ordinary loopback connects | 3/3 observed | 3/3 observed | Two interest rejections, one admitted event with explicit throttle/proven-miss disposition. |
| Listens | 3 UNKNOWN | 3 UNKNOWN | The unchanged Agent session does not enable TCPIP; live listen acceptance remains unexecuted. |
| Positive alerts | 2 | 2 | Exact source/generation links, R-EXEC-001, signed bundle r283-e2008650. |
| Parent command truth | Presence only | Exact equality, 2/2 | Independent GetCommandLineW truth, verified by live OS readback in native smoke. |
| Actual HTTP bodies | 3,501 bytes | 3,500 bytes | Two decoded immutable payloads of 3,710 bytes each; not whole-machine traffic totals. |
| Exact request/server/local ACK joins | 2/2 | 2/2 | Server ingest done/accepted=1/attempts=1, accepted batch owner, local COMMITTED witness. |
| Ordinary exact-generation backend records | 0 | 0 | Applies to these ordinary native/loopback synthetic children only. |

Five ordinary process creates have explicit resource-throttle/proven-miss outcomes;
one has P0 proven miss and local-only retention. Three short-process creates also
record generation/correlation unavailable. These diagnostic outcomes remain
visible; no claim is made that every ordinary event received complete rule
analysis or durable context retention. Necessary positive context, source/alert
command lines, decoded commands, image paths, parent PID/image/command and the
rule predicate all match independent truth. The trace is closed at 456,362 bytes
with 18 diagnostic contention drops, so absence is never used as proof of filtering.

Parent-command oracle tooling is root-workspace commit
`15c6a5b1a4fba8c2defcf70db8d757c06dbf8937`. ARM64 cross-build passed; the native
smoke fails against the old producer (missing parent command) and passes all three
checks with the new producer, including child/parent failure propagation. An
initial test that reconstructed Start-Process argument quoting did not establish
exact command equality. Its failure is retained; the final oracle reads the actual
OS command of the same PID/birth and does not reconstruct it. No Agent command
text was changed to satisfy the comparison.

Upgrade preservation inspected all 3,315 original queue rows / 3,584,521 bytes.
3,314 retained rows have identical identity and payload; the single absent row
has its original 6,374-byte payload and exact hash in a real committed local ACK,
a server accepted batch and completed ingest (accepted=1, attempts=1). Thus the
strict all-rows-present comparison correctly exited 2, and a separate exact
receipt join explains normal delivery without excusing changed data or inventing
ACKs. Changed retained identities/payloads=0. Fixed-20 cache comparison passed:
20 candidates, 5,120 scoped reference occurrences and 5,120 scoped fact-body
occurrences remained equal to the stopped backup. Shared facts may repeat.

All 182 pre-upgrade ACK witnesses and all 240 pre-restart witnesses are unchanged
among 260 post-window witnesses, including their original confirmation times.
No real queue migration, clearing, rewriting or local ACK synthesis occurred.
Final readback at 14:10 UTC confirms PID 5028/birth above, binary/version/config/CA
unchanged, task Running, sequence 524 and both Machine trace opt-ins absent.
The actual ETW session has seven providers and no TCPIP provider. Post-case
health confirms rules/cache ready, source-only flags=0 and event-bus drops=0;
resource pressure can recur under the unchanged budget, so sustained pressure-free
operation is not asserted.

Private evidence follows; raw commands, event bodies, credentials and files are
not committed. Collection uses bounded read-only backend queries and the existing
normal TLS path. Coarse SQL time windows normalize Windows seven-digit fractions
for host Python 3.9; exact decimal FILETIME identities and payload bytes do not.

| Evidence relative to `/private/tmp` | SHA-256 |
| --- | --- |
| `edr-agent-606-evaluation/workflow-completed.json` | `5e0ee3fc2ba8ae41c4954ffdd77cdbc5d7ef47486703359316ad005ed1033505` |
| `edr-agent-606-evaluation/deployment-assets-verified.json` | `926011e3d95b13fb34bbd9d7739c07c79b67ac535a54c898f793d272105d3ace` |
| `edr-agent-606-evaluation/install-terminal-private.json` | `c7781ff9cb2b59b78553eaeb474c4d7abf3f81f784d38353e8325e803b337281` |
| `edr-agent-606-evaluation/auto-acceptance-result.json` | `1d77d55786908edd04e386ac9593a67427ad36e888734d3420b23932453a8ade` |
| `edr-agent-606-evaluation/queue-final-verdict.json` | `b23b5fcc5788dd95b4e49bf6695b5284fc45b015916624af613d72decbe3f010` |
| `edr-agent-606-evaluation/cache-compare-actual-stdout.json` | `c14a5e67975948c626bfe51d49143d3966313f6d4c9d568ed6daf862b7511a36` |
| `edr-agent-606-evaluation/parent-smoke-result.json` | `f7aeb1fb28582960e2891ea21c03900e2f186412e6f94ad396e4190ef206c851` |
| `edr-agent-606-evaluation/replay/runtime-result.json` | `7447a65e53806eacb90cf3c6516201a15d5532b20c0c84b318bd5f46d90ac43a` |
| `edr-agent-606-evaluation/replay/field-evidence/exact-delivery-verdict.json` | `d7400c7f42b7cc097a9d092771e70b80ac9cf17b0ef973f4b6c589948afd9366` |
| `edr-agent-606-evaluation/replay/field-evidence/context-quality.json` | `edaa47096ccce7da5e5645a6ddad6d41c537a226a78041495276db257f1efed3` |
| `edr-agent-606-evaluation/replay/field-evidence/server-batch-receipts.json` | `a089c88ab7385044e04f57bcd934a38fe78a5e9c0f4fe0878d5f9ca93e8e5e6f` |
| `edr-agent-606-evaluation/replay/field-evidence/agent-validation.jsonl` | `48a3ecee5f1642a3f9013b88bab7af5f158f59afa6a92564526c768323614f6e` |
| `edr-agent-606-evaluation/replay/receipt-upgrade-restart-persistence.json` | `f2a0d1c031c90f98f012f34cf5a26fc6591fdc955d177834a07e3aafc4ed09ec` |
| `edr-agent-606-evaluation/replay/final-runtime.json` | `648a222b3e3b2f4adacf1b069a5e734be08f440f7acca1672ebf6f68f24e7a63` |
| `edr-agent-606-evaluation/replay/final-provider.json` | `f0fd9b948428183e76a42753fdc8fec6674e817a25d537f97c652aecde80f682` |


### Control protocol compatibility defect found during 606 acceptance

Event-batch local ACKs above pass. A separate control-delivery ACK check found
201 durable pending records with `transport=https_h2_server_stream`, nonnegative
sequence and bounded command ID. The current server owner
`platform/internal/handler/ingest_http_extensions.go` produces
`https_h2_server_stream`, `https_http1_stream`, `https_h2_long_poll` and
`https_http1_long_poll`; `ingest.go` also produces `https_transport_v2`.
`poll_dispatch_one` preserves that transport in receipt and durable retry state.
The egress control whitelist only allowed three Agent fallback names, so these
valid current protocol ACKs were refused before sending. This is a confirmed
producer/consumer enum mismatch, not an event-batch ACK failure.

The fix adds exactly those five existing producer enum values in
`control_leaf_valid`. It adds no route, field, arbitrary text, command result,
query result or attachment exception and changes no signature/TLS checks. Existing
retry state remains owned by the normal ACK sender; production data is not migrated.
Regression covers all eight exact names, each name with a forbidden result field,
and seven invalid/near-match enum values. The same new test aborts on the old
production owner (host -6; native ARM64 -1073740791) and passes on the fixed owner
(host/native 0). The native wrapper's initial postcheck wrongly expected the
function name in assertion output; the preserved assertion instead identifies the
exact acceptance expression and test line 34. The child failure/pass evidence was
validated without replay. Full release gates and deployed control-ACK recovery
are pending for this fix; strict overall minimization is not declared complete.

- `edr-agent-606-evaluation/replay/control-ack-owner-enums.json` SHA-256 `37699175a81b5930c045e22d4ec35e3f0910a02c5d5a1a6a3b4046a9b68181d4`.

- `edr-agent-607-evaluation/policy-before.json` SHA-256 `cedac72c9d68080329dca77d77d7e87a451023063d172ed514d6df458577d32e`.

- `edr-agent-607-evaluation/policy-after.json` SHA-256 `dd359d7caeb88c1b490ce9555e340570b6b60ddfc298e5e7c564b193d55b5074`.

- `edr-agent-607-evaluation/native-policy-verdict.json` SHA-256 `48e7a5e11bcae43597458ac852407ebe10ee2d725e4ee978435925bb9eb6ed8c`.
