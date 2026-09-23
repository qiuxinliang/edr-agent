# P0 matched-event recovery at a source-health boundary

## Verified failure

The same FILE-family gate covers reads, creates and writes. A source-only
assertion awaiting central acknowledgement previously made the direct emitter
free an already-successful rule evaluation and return without retaining it.
Acknowledgement recovered health but did not replay those matches.

A paired live test on 3.2.467 used one process generation and one persistent
file handle: three cold-state matches were blocked and produced no alerts;
five subsequent matches after health recovery all reached the server. The
three cold matches were still absent more than nine minutes later, with an
empty upload queue and recovered health. This established an admission/recovery
defect, not a failed trigger or a disconnected upload path.

## Durable owner

`p0_deferred_match` resides in the existing offline queue database. There is no
new database, background process, thread, transport endpoint or configuration.
Each owner is a SHA-256 commitment to a versioned, field-based record snapshot,
the rule ID and the verified bundle identity. It includes the complete bounded
source record; it never persists a compiler-specific C struct image.

The existing preprocess loop selects at most one due, healthy-family owner
per 100 ms. It re-evaluates the retained source under the same authenticated
rule bundle. A changed bundle, changed endpoint identity or invalid snapshot
is explicitly quarantined as `failed`, with the original payload retained.
Neither an unknown generation nor a later live PID lookup is substituted for
the recorded source. The health gate remains enforced.

For ordinary alerts, one FULL SQLite transaction inserts the normal high-
priority BAT1 wire and changes the owner to `completed`. That tombstone remains
after the upload ACK deletes the wire, preventing repeated source delivery or
a restart from emitting it again within the configured retention period.
Policy rejection and governor suppression retain an explicit terminal reason.

Block actions still use the existing terminal journal: durable intent before
execution, live target-generation validation, then durable result. The deferred
owner is completed only after ownership has crossed to that journal. A restart
cannot claim the action a second time.

## Bounds and failure behavior

- Pending and failed snapshots share at most 1,024 retained-payload owners;
  each payload is at most 512 KiB. Moving a record to failed cannot release a
  slot and create an unbounded quarantine backlog.
- A worst-case test fills every bounded string with characters requiring the
  largest JSON escaping expansion: 443,937 bytes fit the 524,288-byte ceiling.
- 64-bit generation keys and nanosecond timestamps are decimal strings, avoiding
  JSON's 53-bit integer precision limit. Long paths and command lines are not
  shortened by this local codec.
- Pending, failed and completed metadata count against existing logical queue
  capacity. Deferred admission uses the terminal lane, not the source-only
  emergency reserve. Atomic handoff releases the snapshot allocation within the
  same transaction before checking room for the resulting wire.
- Pending/failed snapshots are never TTL-evicted to make room. Completed
  tombstones follow existing configured retention (default 72 hours).
- Transient retries use durable exponential backoff capped at 60 seconds.
  If the retry/failure state itself cannot be written, process-level backoff
  (1 to 60 seconds) prevents a 100 ms hot loop; storage failure counts and
  degraded state are included in the same health report. Corrupt rows are
  isolated so they do not starve later records.
- An admission/storage failure is an observable fail-closed loss boundary, not
  a successful retention claim. Existing owners are never overwritten.
- `p0_acceptance.offline_queue.deferred_pending` and `deferred_failed` expose
  durable backlog and quarantine counts in the existing health report.

## Parent-generation repair

### Complete command facts and rollback boundary

The 8 KiB behavior/process-tree command field is a UTF-8 preview, not the
complete-fact limit. Longer same-handle observations use the existing evidence
artifact store, keyed by tenant, endpoint, PID, StartKey and creation FILETIME,
with a full-content hash. Conflicting same-generation observations invalidate
the reference rather than selecting an earlier tail. Failed retention remains
explicitly incomplete. The artifact store retains its existing capacity and
retention owner.

Schema 3 snapshots bind the parent generation and embed resolved subject and
parent command bodies, so replay does not depend on the evidence cache or a
live process. The new reader accepts schema 1 and 2 without inventing missing
fields. Encoding still fails explicitly above the existing 512 KiB limit.
Final BAT1 messages remain within the existing 256 KiB event-batch limit.
Terminal action space is reserved from immutable intent facts before execution,
without increasing the global queue budget or short-event lane minimum.

Older Agents do not understand schema 3 or the larger terminal frames. **Do
not downgrade with pending new-format owners.** Quiesce/drain them under the
new Agent first, or retain the database for explicit recovery with the new
version. An old reader quarantines unsupported snapshots as `failed`; merely
upgrading again does not automatically retry those failed rows. Do not delete
the queue to force rollback. These source changes are not a proof of binary-hot
rollback compatibility. Deploy the matching server command-capacity/projection
changes before publishing the Agent.

`test_command_fact_transport` checks exact parent identity, cache/queue reopen,
cache-independent deferred handoff, conflicts and wire content at 8191, 8192,
12717 and 98301 UTF-8 bytes. The Windows same-handle test queries an actual
12717-byte inert child. Neither replaces post-deployment sensor-to-model
acceptance, especially for a process that exits before live enrichment.

A separate read-only snapshot showed child PID 6316 bound to parent PID 3404
with generation `11540474045138450`, while the corresponding actual parent
generation was `11540474045138506`. The difference is not a missing display
name: filling from the old persisted tuple would produce a wrong parent edge.

The process-tree cache previously overwrote birth time and cleared exit time
on a later update of the same exact generation. A late update could move the
real parent's interval after child birth and make a historical lookup select
an older still-open PID occupant. The repair derives immutable birth from
FILETIME, keeps observation recency separate, preserves known exits, and bounds
old intervals when a newer exact generation of that PID is learned.

Parent selection now uses child birth, not the time of a later file event.
An authoritative parent lifecycle event arriving late can repair a child edge
only when an exact snapshot at child birth selects that parent generation.
Generation, name and path move together, in memory and in the process-cache
database. Durable repair runs on the authoritative identity-observation path,
even when the parent is an ordinary non-candidate event; an endpoint/PPID index
bounds the lookup to its children. No parent is promoted into a P0 candidate
just to perform this repair. A two-child SQLite fault test aborts the second
update, verifies rollback of the first, retries, and checks both edges after
close/reopen. A parent generation born after the child cannot replace its parent.
This does not rewrite historic server alerts or promote path-based hash and
signature snapshots to action-authoritative evidence.

## Verification boundaries

`p0_direct_emit_suppression` covers cold/healthy transitions, preserved source
identity and parent fields, restart ownership, retry, rule-bundle changes,
admission failure and no duplicate action after a journal handoff. The snapshot
test covers all registered record fields, maximum escaping, exact 64-bit values
and rejected malformed/unsupported input. `storage_queue_sqlite_contract` covers
real transactions, reopen/upgrade, commit rollback, atomic capacity handoff,
concurrent exact replay, ACK deletion, corruption, retry bounds and retention.
The parent tests use the captured StartKey/FILETIME values to cover same-PID
reuse, late metadata, preserved exits and late parent-edge repair. Script
matches also obey the PROCESS-family health gate. The pre-existing no-IR
source-only contract does not include script event types; extending that
separate Agent/server contract is not part of this matched-event recovery.

Local verification on this change: product target built; 22/22 runtime gate
tests and 13/13 gate dependency checks passed. The codec/direct/serializer and
parent tests also passed AddressSanitizer and UndefinedBehaviorSanitizer. This local
configuration explicitly uses the non-production PCRE2 stub, not the release
matcher.

These tests are bound to both Agent runtime and Windows release gate build
dependencies. Passing a local non-production build is not proof of native
Windows/MSVC compatibility or a deployed endpoint's behavior. Release validation
must run the same cold/warm marked scenario on the new Windows binary, check
original source IDs after health recovery/restart, and independently inspect
context completeness. A successful alert does not imply every context field
is collected or action-authoritative.
