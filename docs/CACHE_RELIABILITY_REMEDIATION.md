# Cache reliability remediation

Baseline: `8e1e591229c2d83fbbfbf604c95e18e544a77af3` (tested release baseline:
`f708d6bd7a2ee1eb7be26cb593a4b79957a9746b`). The intervening change only
limits evidence-cache page reclamation per preprocess turn.

Scope: local code changes and isolated regression tests. No cloud deployment,
production data changes, or changes to endpoint protection are authorized.
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
