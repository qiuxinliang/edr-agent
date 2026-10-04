# Agent upload minimization: development evidence

The current continuation results are in the final validation ledger below:
34 individually passed selected contracts, nine isolated mTLS scenarios and
19 Windows objects plus three linked contract programs. Earlier sections record
the original three commits; their timestamps and limitations remain historical.

## Fixed baseline and continuation

- Repository: `https://github.com/qiuxinliang/edr-agent.git` (nested Git repository).
- Branch: `codex/release-workflow-convergence`.
- Starting HEAD: `7c43dc2d30f9c05292ca5cce6dfe893d2dc39528`; nested worktree clean.
- Historical reference: `03d78b39b2c4f180b6acf41390e45946a2996b53`, Windows `win_3.2.589`.
- Subsequent agent commits: `7b282749` (proven baseline upload filtering),
  `7c43dc2d` (verified 589 cache reliability documentation).
- Outer workspace HEAD: `7c9e5429d2dfa0c775c345ba57f08b91d94adb07`;
  pre-existing untracked `edr-agent-signing/` preserved. The outer index is not
  part of these agent commits.

At final verification the outer repository had independently advanced to
`fa83be1cdc921a26bc0568e79070e8b85ff56495` (`perf(alert-workbench): defer evidence
reads for AI priority sorting`), changing two backend repository files. This
task did not alter or include that concurrent change. Its outer status remains
the changed nested-agent attachment and the pre-existing signing directory;
the nested agent worktree is clean after its three task commits.

The supplied historical 30-record/29,103-byte observation establishes enqueue,
not HTTP delivery or receipt. Its original database is unavailable in this
task. All new replay inputs are synthetic, not a historical endpoint replay.
CodeGraph's outer index differs from the nested checkout; findings below were
checked against current source.

| Historical observation | Current-source baseline finding | Evidence limit |
| --- | --- | --- |
| Loopback counted remote, negative PMFE context became a candidate | Both predicates were still present in the starting decision/cache owners | Reproduced with deterministic synthetic input; original record not replayed |
| Priority-0 ordinary process became `emit_alert` | Collector interest reservation supplies priority 0; copy/encoder preserve it and decision treated it as alert quality | Verified production chain, not a claim that every original record used that branch |
| Process source-only with unavailable correlation | Current pre-evaluation producer still retains full captured source and uses the durable recovery owner | Source-only is diagnostic evidence; absence of an embedded alert does not establish a verified miss |
| Unresolved FILE_READ source-only | Current collector evidence gate still emits not-evaluable source diagnostics and affects capability health | No filename or source identity inferred from the unavailable historical fixture |

## Stage 1: verified signal and scheduling defects

`detection_decision.c:has_remote_indicator` treated any destination/port as an
off-host signal. The numeric address parser now distinguishes `loopback`,
`local_host`, `local_network`, `external` and `unknown`; private off-host peers
retain lateral-attack scoring. Script fetch intent has its own reason and score,
so repairing endpoint classification does not suppress real script detection.
No loopback event is discarded merely because of its address.

`collector_win.c:edr_collector_should_admit_slot` reserves priority 0 for process
interest candidates before exact enriched rule matching. `behavior_from_slot`
copies the scheduling value and both encoders serialize it. This verified
producer is not a demonstrated zero-initialization bug. Scheduling and collector
interest remain intact; `compute_event_quality` no longer converts priority 0
into alert identity. Its score/action remains a local selection hint, not final
egress authorization.

`local_evidence_cache.c:evidence_text_has_high_signal` searched all detection
context text, including negative `pmfe_scan` keys. Context eligibility now reads
recognized structured values and positive completed suspicious engine evidence.
False values, empty snapshots, field names, unrelated prose and string booleans
do not create PMFE evidence. Existing local command/script collection heuristics
and generation-bound retention continue to run.

The dependent `telemetry_admission.c:is_uncombined_tool_file` accepts the new
local-only disposition under its existing complete-facts/verified-miss guards.
It does not use priority as an alert proof.

Deterministic tests added before implementation aborted on the original HEAD:
ordinary priority-0 process expected `local_only`; negative PMFE context expected
noncandidate. With the fix, the synthetic loopback LOLBin score is 34 rather
than 56; priority-0 baseline remains 20/`local_only`; script hint remains
52/`emit_context`. A real loopback attack and remote script detection retain
their positive evidence. These are synthetic differences, not recalculated
historical endpoint totals.

Focused native checks: `detection_decision_combo`, `detection_regression_scenarios`
(14 scenarios), `detection_sensor_bridge`, `telemetry_admission`, and the complete
SQLite `local_evidence_cache_candidate` suite. Windows native collector execution
is not implied by native Clang tests; Windows test targets link `ws2_32` for the
same numeric address parser.

## Reproducible host checks

Use a disposable build directory:

```sh
cmake -S . -B /tmp/edr-min-egress -G Ninja -DCMAKE_BUILD_TYPE=Debug \
  -DEDR_BUILD_TESTS=ON -DEDR_REQUIRE_PCRE2=OFF \
  -DEDR_P0_RULE_IR_ALLOW_TEST_STUB=ON -DEDR_WITH_YARA=OFF \
  -DEDR_WITH_HTTP2_CURL=OFF
cmake --build /tmp/edr-min-egress --target test_detection_decision \
  test_detection_regression test_detection_sensor_bridge \
  test_telemetry_admission test_local_evidence_cache_candidate
ctest --test-dir /tmp/edr-min-egress --output-on-failure \
  -R '^(detection_decision_combo|detection_regression_scenarios|detection_sensor_bridge|telemetry_admission|local_evidence_cache_candidate)$'
```

This explicit nonproduction build cannot publish or enforce authenticated P0
rules. It is a portable regression environment, not a production acceptance
substitute. Native Windows/authenticated-rule and end-to-end results must be
reported separately. No detector configuration or collection is weakened on an
endpoint by running this disposable build.

## Stage 2: final request purpose and field boundaries

The authoritative owners are `egress_batch_policy.c` and
`egress_request_policy.c`. Preprocessing uses the same frame contract before
batch assembly, and HTTP validates the final immutable envelope before native
or libcurl I/O. Independent multipart, stream, updater, collector bootstrap and
uninstall attestation paths are covered. The approved minimum control messages
have separate exact route, query and field contracts. Command/query results,
inventory, attachments, update logs and unknown purposes are denied.

See [the complete egress inventory](egress_policy_v1.md) for each caller, purpose,
field group, size, scheduling/dedup owner and receipt semantics. Alerts require
actual detector-owned triggering facts and source identity. AVE/correlation/
fanout produce their basis only at the detector's actual emit point; this is
distinct from priority, score or labels. A real accumulated AVE detection is not
lost when the latest PMFE hint is zero. Standalone positive PMFE/shellcode/webshell
verdicts can qualify without an embedded BehaviorAlert. The actual PMFE context
builder is tested; a clean follow-up ID alone is insufficient.

Known protobuf descriptors reject unknown tags, duplicate singular/oneof fields,
embedded NUL strings, invalid encoding and unsupported types. JSON parsers reject
duplicate members, incomplete input and decoded NUL suffixes. Detector subjects,
basis and source bindings have explicit current-member lists; arbitrary extra
subject members and opaque unrelated IOC objects are rejected. General context
subtrees and per-rule necessity still require narrower contracts; this is not a
claim that every retained field is minimal for every rule.

Health projection uses one exact path/type whitelist for full and delta uploads.
Known bounded cause codes remain distinguishable; free text and raw process/user/
path/command details stay local. Allocation failure refuses the projection rather
than acknowledging a partial summary. Removal-only deltas remain compatible.
Health revision ACKs never acknowledge diagnostic evidence or event batches.

Detector context overflow originally either truncated source identity or emitted
invalid JSON. P0 now preserves the complete required rule/bundle/source tuple in
its bounded fallback; AVE omits only duplicate process display projections and
retains the original alert ABI fields plus unique file/network/detection facts.
The governor's aggregate counter is health data, rather than a pid-zero pseudo
alert that could contaminate a real-alert batch. TLS now verifies the peer's DNS
or IP identity in addition to its CA chain. Fresh envelopes use identity encoding
when an optional outbound zstd dictionary cannot be inspected by the validator.

New regression suites include actual encoding/decoding, ordinary and valid
loopback events, false/empty/prose PMFE, priority-only events, source-only,
mixed/raw/LZ4 batches, unknown versions/tags, false predicates, contradictory
verdicts, and unsupported channels. The actual AVE SDK produced 21 alerts,
including a forced capacity fallback, all accepted by the production codec and
policy. A maximum rule/bundle/tenant identity fixture preserves its exact source
binding through both preview failures.

The first broadened build exposed a missing policy link on the collector test;
it is repaired. A broadened run exposed the AVE fixture that did not actually
overflow and outdated arbitrary-download expectations. Deterministic quoted
input now exercises the real capacity path. Collector replacement, hashes,
refresh and fallback still pass through approved bootstrap routes, while
unapproved native/subprocess downloads are explicitly rejected. These were
development failures, not passes attributed to the original code.

Stage 2 was also exported from its own Git index into a disposable directory,
without the Stage 3 owner/schema/queue changes or TLS fixture. Its full native
build (685 Ninja steps) and 16 focused CTest cases passed. This verifies that
the second commit is independently buildable and reviewable. Windows binaries
were not built. The separate headless policy target preserves its static CRT
while using the same authoritative policy sources.

## Stage 3: local ownership, historical isolation and receipt evidence

The transition diagrams and compatibility proposal are in
[source-only ownership](source_only_local_v3_compatibility.md). The owning
functions are `queue_meta_ensure_open_locked`, the `p0_source_only_*` paths in
`p0_rule_direct_emit.c`, and the source-only prepare/commit/drain functions in
`queue_sqlite.c`. Previously every full source-only diagnostic required remote
delivery to clear its capability latch. Holding it at egress without changing
that owner would permanently fuse detection. The new explicit local-v3 owner
commits its original full wire and resolves its exact tuple in one SQLite FULL
transaction. It then requires the existing healthy IR, durable probe and retry
checks before recovery. This is local durability, not remote receipt.

Old owner-v2 rows remain under their original remote ACK contract. Immediately
before ordinary queue transport, a forbidden immutable batch becomes
`policy_held`; no frames are changed or deleted, and no delivery/retry/ACK counter
is fabricated. Mixed batches retain their eligible alerts as well. A failed hold
commit rolls back, leaving the original pending row intact. Unknown encodings,
expiry and exhausted retries retain the original body instead of deleting it.
All retained bodies consume the existing logical capacity. A zero/invalid limit
uses a finite 512 MiB default with an observable cause; a lowered limit leaves
old bytes intact and refuses new writes. This is not a physical WAL disk ceiling.

The final read-only review found and repaired a metadata-loss recovery defect:
a missing `queue_meta` singleton beside retained old source-only evidence could
look like a fresh clear local-v3 database. Its new regression failed before the
repair (exit 134) and passed after it. Opening now inventories all retained
severity-2 rows, including pending, held and corrupt rows. Old/unknown sources
keep remote-v2 and require recovery; proven local-v3 evidence still requires a
local loss audit. Inventory failure refuses open without changing retained
bodies. The complete SQLite suite and its CMake CTest target passed again after
this repair; recovering an old owner is never replaced by local ACK.

Health includes only whitelisted counters, owner/recovery status and fixed cause
codes. Its revision receipt does not confirm or dispose of any original wire.
No real endpoint database was opened, converted, drained or migrated.

### Final native verification

The full final native build passed. All **31 selected CTest cases passed**, with
zero failures. There are other registered tests; this does not claim that the
entire repository suite or Windows runtime was executed. The explicit build
uses nonproduction PCRE2 stubs. Separately,
`bash tests/run_p0_source_only_real_ir.sh` passed with the production matcher,
system PCRE2/OpenSSL, the current 180-rule plaintext bundle and a TEST ONLY
AES-GCM EDR1 envelope. Its tampered authentication tag was rejected with -3.
That test isolates persistence with a capture stub and does not establish a
publisher signature, production dependency provenance, SQLite receipt or HTTP.

Reproduce the selected checks after the full build:

```sh
ctest --test-dir /tmp/edr-min-egress --output-on-failure \
  -R '^(transport_v2_status_capacity|transport_durable_owner|telemetry_admission|storage_queue_sqlite_contract|detection_decision_combo|detection_regression_scenarios|detection_sensor_bridge|p0_direct_emit_suppression|p0_deferred_snapshot|preprocess_p0_dispatch_contract|local_evidence_cache_candidate|deep_collector_manifest|pmfe_injection_generation|ave_sdk_smoke|net_fanout|health_upload|egress_batch_policy|egress_request_policy|report_events_ack_contract|command_signature_cross_language|command_inbox_persistence|command_upload_outbox_recovery|agent_update_event_outbox|request_signing|control_stream_lease_contract|mtls_upload_transport_contract|behavior_record_alert_proto_contract|behavior_record_alert_emit_contract|alert_cardinality_release_gate|endpoint_policy_v2_modes|collector_health_disposition_json)$'
bash tests/run_p0_source_only_real_ir.sh
python3 -B tests/test_egress_tls_receiver.py \
  --client /tmp/edr-min-egress/tests/test_egress_tls_client
# Expected exit 1: preserved historical regression FAIL, not a passing sender.
bash tests/run_egress_baseline_regression.sh
```

On this macOS host CMake used `-DOPENSSL_ROOT_DIR=/opt/homebrew/opt/openssl@3`.
The receiver requires permission to bind a loopback socket. The first final
invocation in the filesystem/network sandbox failed before any request with
`PermissionError`; the same fixture then passed with loopback execution allowed.
No TLS validation was disabled and it connected to zero production servers.

| Requirement | Test evidence | Status and boundary |
| --- | --- | --- |
| Negative/empty/text-only PMFE, ordinary priority 0, ordinary and attacking loopback | Decision/cache/batch regressions; valid source context bytes unchanged | Passed native; negative regression failed on starting HEAD |
| Real alert and necessary explanation | Actual AVE callback, 21 SDK alerts including capacity fallback, production codec and receiver | Passed; per-rule necessity of every field is still incomplete |
| Missing process association, unresolved file path, unavailable IR | Source-only owner/suppression, actual IR/codec fixture, health cause whitelist | Passed synthetic; original 30 endpoint records unavailable |
| Rate suppression and queue failure | Governor token/rollback, deferred ownership, bounded RAM handoff, loss audit and FULL rollback | Passed; suppression is distinguishable from queue failure |
| Ordinary/mixed/BLZ4, old/unknown wire | Real batch decoder plus production SQLite retained-body assertions | Passed; mixed valid alert remains held pending compatible extraction |
| Restart, crash gap, ACK loss/replay, duplicates | SQLite reopen/session-marker tests and actual receiver lost ACK/exact duplicate/wrong-hash cases | Passed logical fault injection and reopen; real process kill/power loss unexecuted |
| Backpressure and policy mode changes | Finite/default/lowered-limit cases, exact hold bytes, unchanged old owner and existing endpoint policy mode tests | Passed within those contracts; switching to a new egress policy version or releasing held rows is unexecuted |
| Results, queries, inventory, attachments, upgrade and diagnostics bypass | Request whitelist; production native/multipart calls against receiver; independent collector native/subprocess denial | Passed native; Windows Schannel/headless and libcurl HTTP2 runtime unexecuted |
| Health/control integrity | Full/delta projection, allocation failure, fixed causes, closed route/member/type/query tests; command/signing/outbox regressions | Passed; approved minimum control whitelist is separate |

### Actual request and receipt counts

The final fixture records two synthetic collected inputs, one accepted detector
input, one real detector callback and three successful queue inserts. It does
not claim that native endpoint sensors were run. The ordinary 191-byte batch is
held; the real 1,564-byte alert is preserved. A receiver SQLite FULL commit
precedes each receipt.

| Current fixture | HTTP requests | Body bytes | Receiver business failures | Client assertion failures |
| --- | ---: | ---: | ---: | ---: |
| DNS mTLS, lost ACK/reopen, exact duplicates, health full/delta | 8 | 12,229 | 0 | 0 |
| IP SAN mTLS, same scenario | 8 | 12,229 | 0 | 0 |
| Protobuf envelope, optional outbound dictionary configured | 8 | 9,844 | 0 | 0 |
| Wrong CA | 0 | 0 | 0 | 0 |
| Wrong SAN | 0 | 0 | 0 | 0 |

Each positive receiver retains three distinct durable batch identities and two
duplicate observations. Only **two distinct queue batches** get an accepted
queue-owned receipt. The third ID belongs to the deliberate wrong-hash receipt
probe: the server stored it, but the agent rejects that receipt. Receipt loss and
duplicate observations therefore are not counted as extra distinct confirmations.
Heartbeat and health have their own protocol confirmation. Every denied data
channel contributes zero HTTP requests in the corrected build.

Against the exact starting archive, the unchanged final callback test failed as
expected: DNS/IP each sent 14 requests and about 86.9 KiB, with nine client and
thirteen receiver failures. The old real AVE callback still fired, but its alert
lacked the new detector-owned basis, so the strict receiver rejected it. This is
not proof that the old detector missed the attack. An earlier equal-payload
experiment recorded 16/83,092 versus 8/5,909 DNS requests/body bytes, preserving
the same 618-byte synthetic alert. Both experiments and their different fixture
boundaries are detailed in [egress policy](egress_policy_v1.md). The old
dictionary codec failing receiver decode is not a codec compatibility success.

The checked-in `run_egress_baseline_regression.sh` was executed after the final
metadata repair. It exports exactly `7c43dc2`, builds the unchanged current
callback fixture against those archived production sources and confines runtime
configuration/state to temporary directories. It reproduced the historical
**FAIL**, preserving exit 1: 14 DNS requests / 86,915 bytes, 13 receiver failures
and actual observations of each denied result/attachment/inventory/upgrade/
unknown category. Infrastructure or incomplete evidence returns 2. No failure is
renamed a passing historical sender. The final rebuilt current binary then
passed all five mTLS scenarios again, with the counts above unchanged. The
four focused transport-owner/P0/batch/request tests also passed after the repair.

## Blocker resolution continuation

The continuation began with a clean nested worktree at
`8fed2f9ae7dc018804e56d4ca747078727d41156`. The three staged changes above are
`26a7ca91`, `64b923bf` and `8fed2f9a`. During the continuation, another authorized
session committed `efe99ffdf649816488074d73d7d68a80d67267e0` (release cleanup and
terminal ACK error/clock recovery). Its ACK fixes and regression assertions are
preserved. A later concurrent documentation-only commit,
`9368e9593df192e2bd199613ea7870a460796c21`, was also preserved and is the parent
checkout for this task commit; it changes no production source. This task does
not include either commit's workflow/release/runtime-assessment files or the
outer workspace's separately committed frontend work/signing directory. The
final observed outer HEAD is `0a1736eb150c80192f3c5d128eb1d659d592e5bd`; its
pre-existing signing directory remains outside this nested task commit.

The owner authorized minimum control messages under a separate closed protocol
whitelist and selected Windows cross compilation plus a repeatable native entry.
No service, publisher, cloud deployment, merge or real queue migration is part
of this continuation.

| Previous blocker and root cause | Current owner and implementation | Verification and remaining boundary |
| --- | --- | --- |
| Nested explanation JSON and child arguments could carry unrelated facts or create another sending path | `egress_batch_policy.c` owns recursive typed `alert-fields-v1`; fresh outbound encoding and immutable final admission share it. Full-facts local encoding remains separate. `deep_collector.c` validates a closed local argument contract before binary resolution/download/spawn on both platforms and legacy entry points. | Unknown/nested/wrong-type/duplicate fields denied; actual 21-alert SDK ABI preserved; quoted local query paths executed. Archived `8fed2f9a` collector regression genuinely fails with exit 1, not a missing-API compile failure. Arbitrary substituted programs/VQL are not an OS network sandbox. |
| PMFE clean/inconclusive or weak suspicious could not be safely linked to a true alert | `local_evidence_cache.c` reuses existing artifacts, stores original wire/SHA and exact scoped generation, and binds final result wire/SHA before queue handoff. `pmfe_engine.c` checks the same opened process handle's generation before memory reads. `preprocess_pipeline.c` consumes leased jobs/replays bound results with deterministic batch identity. | Original/result tuple, corruption, storage failure, policy switch, retries, expiry, capacity and crash/ACK/delete boundaries tested. A real worker failure remains inconclusive for the expected generation. Crash before final result binding uses bounded rescan; it does not guarantee preservation of an uncaptured memory snapshot. |
| Denied journal source frames shared retry/backoff and could block a true combined alert or exhaust the pending-action cap | `queue_sqlite.c` has separate per-frame held reason/retry deadline and FULL ACK transactions. Source frames remain immutable and unacknowledged. `local_retained` releases a completed action's pending slot only after actual necessary intent and combined receipts; retained bytes still consume capacity. | Real-codec SQLite regression, 1024 retained-action capacity case and mTLS journal receipts. Ordinary manufactured intent cannot receive permission or falsely release an action slot. |
| P0 combined HTTP acceptance alone did not create the server alert | Existing backend `ingest_p0_batch_mysql_test.go:1218-1246` shows combined Accepted=1/alerts=0 until the matched intent arrives. Strict schema/terminal SHA plus the queue's exact committed intent/combined pair authorize both necessary alert frames. An orphaned combined is also denied. Held pre-action intent is rechecked automatically after FULL combined commit. | Strict real-IR builder contract and independent synthetic receiver business reconciliation, lost intent ACK and replay. Source result is still denied. Backend MySQL integration is source evidence, not a newly executed production-server test. |
| Historical remote-v2 latch and mixed payloads had no restart-safe explicit recovery path | `main.c` invokes `queue_maintenance.c` before service startup. Default read-only check binds configured scope, exact owner tuple, cursor/limit, original hashes and projected proof. Explicit apply uses FULL transaction, new deterministic projected batch ID, retained parent hash/body and bounded unacknowledged old-owner lineage; current local-v3 recovery still requires healthy IR/probe/loss audit. | Clean/upgrade synthetic DBs, raw/LZ4/mixed/old/unknown input, stale authorization, wrong/lost ACK, immutable lineage, three actual SIGKILL commit boundaries, capacity and proof changes. Unknown or incomplete context remains unresolved with a bounded observable reason; a summary never ACKs the original. No real queue migrated. |
| Windows execution environment unavailable | `run_telemetry_windows_cross.py` compiles actual changed Windows owners and links policy contracts. `run_telemetry_windows_native.ps1` requires a configured real-dependency native build and executes a shared CMake test target/label, including loopback mTLS and crash cases. | Cross compilation is distinct from full production agent dependency/link acceptance and native runtime. The owner's selected cross/native-entry scope does not certify native sensors, Schannel or headless finalizer operation. |

The original artifact/health owners remain bounded. PMFE associations are limited
to 64 active entries (including ACKed results awaiting queue deletion), three
attempts and a one-hour task deadline, with a five-minute running lease. A new
fixed numeric health summary reports scheduled/running/bound/ACKed-awaiting-queue,
capacity/failures and closed cause codes. No association ID, original command,
username, path, raw context or receipt secret appears in that summary.

Historical recovery is an operator tool, not an automatic migration. At most 32
batches/frames and 128 MiB are inspected per pass; cursor advancement avoids
unsupported first rows starving later inventory. Retained unresolved rows can
be explicitly rechecked after decoder/proof upgrades. A linked projection
retains its existing body/ID/hash across capped service-lifetime backoff rather
than being deleted at TTL/retry exhaustion. Policy-held projections require
fresh scoped snapshot authorization to resume. Logical retention remains bounded
by the existing configured queue limit; SQLite WAL is not a physical disk quota.

### Continuation validation ledger

Final checkout validation: full incremental native build **PASS**. The broadened
34-case run initially had **33 PASS / 1 FAIL**, with the P0 TLS fixture failure
recorded. After respecting the existing 1000 ms drain cadence, correcting its
protocol oracle and completing the historical terminal-state recovery, the five
affected contracts were rebuilt and rerun: **5/5 PASS**, zero failures, 38.84 s.
They are `storage_queue_sqlite_contract`, `queue_recovery_real_codec`,
`local_evidence_cache_candidate`, `egress_loopback_mtls` and
`pmfe_lifecycle_policy_switch`. The remaining 29 contracts were unchanged after
their PASS. This gives 34 individually passed selected contracts, not a claim
that one final full-repository run occurred or that every registered test ran.

| Final validation | Status | Evidence |
| --- | --- | --- |
| Native selected contracts | PASS | 34 selected contract names below; final five affected cases all pass |
| Actual PCRE2/source/terminal builder | PASS | Plaintext current 180-rule bundle and TEST ONLY AES-GCM EDR1; tampered tag rejects -3; immutable intent/source/combined and paired owner restrictions verified |
| Windows cross compilation | PASS | 19 AMD64 objects, including main/agent health, real SQLite queue/cache/recovery, PMFE, preprocessing, HTTP and test entries; three AMD64 policy/collector test executables linked; output architecture checked |
| Native Windows entry | CREATED, NOT EXECUTED | CMake real-dependency target/label plus PowerShell runner refuses missing actual IR/SQLite/TLS contracts; no Windows host available |
| Original Windows 30 records / 29,103 bytes | NOT EXECUTED | Original queue not provided; synthetic tests are not a reconstruction |
| Backend MySQL business consumer | NOT EXECUTED | Existing combined-first regression/implementation read; independent synthetic receiver checks matching intent/combined business reconciliation |
| Full Windows production dependency/link gate, Schannel/finalizer, HTTP2 runtime, publisher provenance, hardware power loss | NOT EXECUTED | Cross objects, host OpenSSL, system-library fixtures and SIGKILL do not establish these runtime guarantees |
| Syntax and Git whitespace checks | PASS | Python parse; shell syntax; final `git diff --check` |

The final TLS report separates actual requests, independently durable receipts
and distinct queue-owned ACKs. Body counts exclude TLS and HTTP headers.

| Scenario | Requests / body bytes | Durable receiver batches / duplicate observations | Business/ACK result |
| --- | --- | --- | --- |
| Actual AVE callback + DNS TLS | 8 / 11,329 | 3 / 2 | One detector input/callback, two synthetic collected records, three enqueued batches, two distinct genuine queue ACKs; ordinary 191-byte record stays held |
| Actual AVE callback + IP SAN | 8 / 11,329 | 3 / 2 | Same actual provenance/command/ACK assertions |
| Protobuf + optional dictionary | 8 / 9,174 | 3 / 2 | Existing identity envelope remains inspectable; alert body is unchanged |
| Wrong CA | 0 / 0 | 0 / 0 | TLS refused before HTTP |
| Wrong SAN | 0 / 0 | 0 / 0 | TLS refused before HTTP |
| Associated PMFE actual worker | 3 / 3,230 | 2 / 1 | One original synthetic proven alert and one real worker failure/inconclusive result, two enqueues/two distinct ACKs; first result ACK lost, exact replay completes cache only after queue deletion |
| Ordinary manufactured journal intent/source plus real AVE alert | 1 / 2,017 | 1 / 0 | Combined genuinely ACKed; ordinary intent/source remain unacknowledged and the action slot remains pending |
| Matched P0 pair (production-schema fixture) | 3 / 5,928 | 2 / 1 | Exactly one synthetic business alert, intent ACK=1, source ACK=0, combined ACK=1; lost intent receipt replay causes no duplicate business alert |
| Abrupt child kill after lost ACK | 4 / 6,118 | 2 / 1 | Original pending payload/hash unchanged across kill/reopen; no recollection, redetection or re-encoding on resume; genuine replay ACK removes exact queue row |

All nine final scenarios have client exit 0, zero failed assertions and zero
receiver business failures. The current actual AVE batch is 1,430 bytes, compared
with the previous three-commit 1,564-byte fixture; DNS/IP aggregate falls from
12,229 to 11,329 bytes while the canonical required command/provenance is
preserved. The rejected ordinary batch remains 191 bytes locally and transmits
zero bytes. This is synthetic measured data, not a recalculation of the supplied
historical endpoint's 29,103 bytes.

Reproduce in a disposable host build using the explicit nonproduction settings
above. The exact broadened selection adds `queue_recovery_real_codec`,
`pmfe_lifecycle_policy_switch` and `egress_loopback_mtls` to the original 31-case
expression; real-IR and Windows probes are separate evidence levels:

```sh
cmake --build /tmp/edr-min-egress -j 4
ctest --test-dir /tmp/edr-min-egress --output-on-failure \
  -R '^(transport_v2_status_capacity|transport_durable_owner|telemetry_admission|storage_queue_sqlite_contract|queue_recovery_real_codec|detection_decision_combo|detection_regression_scenarios|detection_sensor_bridge|p0_direct_emit_suppression|p0_deferred_snapshot|preprocess_p0_dispatch_contract|local_evidence_cache_candidate|deep_collector_manifest|pmfe_injection_generation|pmfe_lifecycle_policy_switch|ave_sdk_smoke|net_fanout|health_upload|egress_batch_policy|egress_request_policy|report_events_ack_contract|command_signature_cross_language|command_inbox_persistence|command_upload_outbox_recovery|agent_update_event_outbox|request_signing|control_stream_lease_contract|mtls_upload_transport_contract|behavior_record_alert_proto_contract|behavior_record_alert_emit_contract|alert_cardinality_release_gate|endpoint_policy_v2_modes|collector_health_disposition_json|egress_loopback_mtls)$'
bash tests/run_p0_source_only_real_ir.sh
python3 -B tests/run_telemetry_windows_cross.py \
  --build-dir /tmp/edr-min-egress-windows-owners \
  --sqlite-include /absolute/portable-sqlite-headers \
  --openssl-include /absolute/openssl-headers \
  --pcre2-include /absolute/pcre2-headers
```

The cross probe copies only the portable SQLite declaration header into its
isolated build root; it never includes a host SDK ahead of Windows stdlib or
links host-platform libraries into a PE executable. There is no new production
service/thread/table or permissive runtime flag. The offline maintenance CLI,
existing bounded artifact subtype, durable ownership columns/lineage, closed
field contracts and lifecycle synchronization each have an actual consumer and
failure-path coverage. Ordinary logical retention still has a finite capacity
and recoverable, observable state; no queue is cleared to obtain a test pass.

- Completed deterministic before experiments: collector archive `8fed2f9a` FAIL
  exit 1; historical transport archive `7c43dc2d` FAIL exit 1 (14 requests,
  86,915 bytes, 13 receiver business failures); weak suspicious PMFE exact-bound
  fixture FAIL before guard repair, PASS after (9.92 seconds); PMFE worker ready/disabled-policy timing tests FAIL exit 1 before lock repair and PASS after; same required P0 pair contract with old queue implementation FAIL exit 134, current implementation PASS exit 0.
- Iteration failures were fixed without weakening behavior: legacy artifact NULL
  cleanup, exact AVE 255-byte target-domain ABI, independent journal retry fixture
  timing, and synthetic TLS journal SQL-column/protocol-field mistakes. The final P0 fixture also now respects the unchanged 1000 ms drain cadence and bounded retry instead of asserting completion after a suppressed poll. A sandbox socket-bind
  refusal was infrastructure failure; isolated loopback verification used approved
  sandbox escalation with normal certificate checks.
- Native Windows runtime, full Windows production dependency/link gates,
  libcurl HTTP2 runtime, hardware power loss, production publisher signature,
  original historical 30-record database and production server/queue operation
  remain unexecuted. POSIX process-kill tests do not prove hardware power-loss
  survival; system-library real-IR fixtures do not certify production provenance.
