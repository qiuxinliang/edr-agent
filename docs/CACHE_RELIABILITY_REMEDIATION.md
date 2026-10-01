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
| R08 | Local acknowledgement must match durable backend acceptance. | Pending |
| R05 | Resource exhaustion must preserve valid pending records. | Pending |
| R06 | Define and observe logical capacity, physical usage and retention separately. | Pending |
| R01 | Installation history must not substitute for current runtime health. | Pending |
| R07 | Preserve compatible aggregate counters and add reason-specific accounting. | Pending |

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
