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
