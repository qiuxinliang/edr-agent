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

The supplied historical 30-record/29,103-byte observation establishes enqueue,
not HTTP delivery or receipt. Its original database is unavailable in this
task. All new replay inputs are synthetic, not a historical endpoint replay.
CodeGraph's outer index differs from the nested checkout; findings below were
checked against current source.

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
