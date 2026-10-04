# Agent upload minimization: development evidence

## Fixed baseline

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

### Unfinished requirements and release blockers

These commits do **not** establish strict upload minimization as complete:

1. Historical remote-v2 capability ownership cannot be safely cleared by a
   local-v3 commit or health receipt. Old mixed-batch alerts need a reviewed
   projection protocol with new ID, original hash lineage and separate ACK.
   No automatic production migration or operator disposition API is included.
2. The independent enforcement journal still retries denied source frames with
   shared backoff and source-before-combined selection. Its HTTP guard prevents
   raw egress, but it lacks per-frame held/recovery state and can delay a valid
   combined alert. No action audit, payload or ACK is invented to hide this.
3. Clean/inconclusive PMFE follow-ups need durable original-alert, endpoint and
   process-generation association. A string ID alone is denied; this can
   withhold useful true-alert context until that association owner exists.
4. Supported alert fields and bounded nested explanation JSON are not yet
   proven minimal for every rule and server consumer. Native Windows collectors,
   Schannel/headless finalizer, libcurl HTTP2, production publisher signatures,
   genuine crash/power loss, and all historical onsite fixtures remain unexecuted.
   Scripts/installers or arbitrary child program network behavior are outside
   this C transport boundary and need their own audit before a whole-endpoint
   strict claim.

The compatibility proposal names the required server negotiation, new projection
identity and restart-safe local handoff. These are decision/blocking items for a
later authorized implementation; none is an expanded egress exception here.
