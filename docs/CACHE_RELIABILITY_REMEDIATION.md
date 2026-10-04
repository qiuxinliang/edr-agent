# Cache reliability remediation

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
