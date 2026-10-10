# Parent PID contract for projection v3

This contract supplements the `win_3.2.629` implementation at
`edf0340fcb038c4ceffae57b5beff74704ad3e9f`. It applies to newly generated
v3 frames and paired backend/frontend consumers. It does not reconstruct
information removed from historical payloads.

## Canonical relationship

`Event.ppid` is canonical. `Event.parent_pid_state` must be present in v3.
The nested `BehaviorAlert.ppid` is a legacy display duplicate, not a v3
relationship source. Process predicates and confirmed tree edges require
`KNOWN`. A retained candidate with `CONFLICT` is audit evidence, not a
confirmed edge.

| State | Canonical PPID | Meaning |
| --- | --- | --- |
| UNKNOWN (0) | 0 | No usable source parent identity |
| KNOWN (1) | Positive uint32 | Confirmed source parent identity |
| EXPLICIT_ZERO (2) | 0 | Source explicitly reported zero |
| INVALID (3) | 0 | Source value was invalid |
| CONFLICT (4) | 0 or retained uint32 | Contradictory parent evidence |

Proto3 omission of the nonoptional PPID integer and its explicit wire zero
decode to the same numeric value. The optional state distinguishes unknown,
explicit zero and invalid; field omission is not itself a state.

An event-local JSON parent alias may be absent. When present it must be a
uint32 integer equal to the canonical PPID, including zero. No side is chosen
to repair a contradiction. The closed AVE schema admits `parent_pid` in
`detection_context.process`; supported dynamic consumers also validate their
existing aliases in `context`. Agent gate, test receiver and backend must
apply this equality to v3. v2 validation and parsing remain unchanged.

The required-evidence mask does not authorize extra parent command lines,
paths, names or other identity text. Retaining the minimal relationship must
not disclose those details without a separate predicate and purpose.

## AVE capture and safe enrichment

The private AVE feed and queue own a copy of the source PID, PPID/state,
ProcessStartKey, creation FILETIME and source event ID. The public SDK ABI is
unchanged. A non-KNOWN parent is zero in model input; its original value/state
remains in the private capture for evidence encoding. Conflicting retained
values never become parent model features.

The internal `captured_process` JSON object carries this copy between the
existing callback and encoder. It is not authorization and is removed by
the existing outbound projector. Decimal strings preserve exact 64-bit
identity values. A nonempty JSON parse failure, including allocation failure,
cannot be interpreted as absence of a legacy capture.

Enrichment requires independently captured start key and creation time,
matching historical generation, event inside its lifetime, no truncated cache
path and no contradictory known image path. A legacy SDK event without that
tuple is not supplemented using PID/time alone. Existing known source values
survive a cache unknown; known disagreement becomes CONFLICT. The tree owner
remembers a conflict for that exact lifetime before another sparse event can
use it. Failure to rebuild the updated JSON stops the new emission instead of
encoding the original KNOWN state.

The private atomic and mutex queues preserve FIFO captures and refuse a full
push using the existing queue-full status/counter. They do not overwrite an
already owned event. A captured changed process generation resets AVE history
even when the first event is a file/network event. Missing source generation
does not acquire historical identity from AVE history.

Kernel/4688 correlation guards are not relaxed: a source that lacks independent
child-instance proof remains UNKNOWN. Startup snapshots, collector restarts,
short-lived processes and cache eviction may still leave unavailable evidence.
Do not infer historical parents from a currently live process with the same PID.

## Consumers and local diagnosis

The backend persists state beside the canonical value and restores that state
before generic SQL/display aliases. Conflict updates are written even when
completeness does not increase. Repeated enrichment cannot downgrade a stored
CONFLICT. API snapshots and alert UI use the same state priority. UNKNOWN,
EXPLICIT_ZERO, INVALID and CONFLICT do not create confirmed parent nodes or
inherit fallback parent names/PIDs. Supported v2 consumers retain legacy
fallback behavior when no state was declared.

The existing protected local trace can select the explicit purpose
`EDR_VALIDATION_TRACE_PURPOSE=parent_identity`. It keeps the existing 300-second,
8-MiB and 128-identity bounds and protected file owner. It records event ID,
version, type/time, PID/start key/birth, PPID/state, projection version/mask,
rule ID and closed change reason at normalization, enrichment and projected
wire boundaries. AVE source and aggregate wire event IDs are linked locally;
business event IDs are unchanged. This purpose excludes request bodies,
commands, usernames and arbitrary diagnostic text. The existing default
egress-validation purpose is unchanged. Unavailable binary SHA is explicitly
`unknown`; source checkout SHA is not binary provenance.

Wire observations occur after projection and before encoding/freezing/hash;
they do not prove successful encoding, HTTP delivery or server receipt.

## Frozen data and acceptance

Frozen queue/journal bytes, hashes, event/batch identity and receipt owners are
not rewritten. A previously accepted inconsistent v3 frame can now fail the
stricter gate. It must remain retained/policy-held under the existing queue
owner; local hold is not a remote ACK. Correct v2 frames and independent old
version receipts keep their existing contracts. Do not clear a family-health
latch or invent a new receipt to repair old content.

Focused regression covers the 72 state/value/alias combinations in the real C
gate and Python receiver, plus comparison of the same frames in Go; real AVE
feed/queue/detector callbacks; exact-cache positive and negative cases; JSON
failure; queue ownership/full behavior; consumer states; frozen v2, durable
queue recovery and ACK/latch invariants. Test replacements and commands belong
in the accompanying acceptance evidence, not product success claims.

Native Windows collection/queue/trace execution, actual HTTP and database
durability, and a newly generated UTM event traced to API/page remain separate
acceptance requirements. Offline tests cannot establish those effects or
recover previously deleted historical PPIDs.
