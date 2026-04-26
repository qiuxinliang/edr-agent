#!/usr/bin/env bash
# 不跑 Agent、不拉模型：用 grep 锚住「行为链」关键符号，防回归改断回调/编码 却无人知。
# 在 monorepo 根目录执行: ./edr-agent/scripts/verify_ave_behavior_chain_invariants.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# ROOT = edr-agent

fail() { echo "verify_ave_behavior_chain_invariants: $*" >&2; exit 1; }

test -f "${ROOT}/docs/WP9_BEHAVIOR_AVE.md" || fail "missing docs/WP9_BEHAVIOR_AVE.md"
test -f "${ROOT}/src/core/agent.c" || fail "missing src/core/agent.c"
test -f "${ROOT}/src/serialize/behavior_alert_emit.c" || fail "missing behavior_alert_emit.c"
test -f "${ROOT}/src/ave/ave_cross_engine_feed.c" || fail "missing ave_cross_engine_feed.c"
test -f "${ROOT}/src/ave/ave_behavior_pipeline.c" || fail "missing ave_behavior_pipeline.c"

grep -q "edr_agent_on_behavior_alert" "${ROOT}/src/core/agent.c" || fail "agent.c must register edr_agent_on_behavior_alert"
grep -q "on_behavior_alert" "${ROOT}/src/core/agent.c" || fail "agent.c must set ave callback on_behavior_alert"
grep -q "warn_encoding_once" "${ROOT}/src/serialize/behavior_alert_emit.c" || fail "behavior_alert_emit.c must keep warn_encoding_once"
grep -q "EDR_BEHAVIOR_ENCODING" "${ROOT}/src/serialize/behavior_alert_emit.c" || fail "behavior_alert_emit.c must reference EDR_BEHAVIOR_ENCODING"
grep -q "edr_behavior_alert_emit_to_batch" "${ROOT}/src/serialize/behavior_alert_emit.c" || fail "behavior_alert_emit.c must keep edr_behavior_alert_emit_to_batch"
grep -q "edr_ave_cross_engine_feed" "${ROOT}/src/ave/ave_cross_engine_feed.c" || fail "cross_engine_feed must keep feed entry points"
grep -q "on_behavior_alert" "${ROOT}/src/ave/ave_behavior_pipeline.c" || fail "ave_behavior_pipeline.c must reference on_behavior_alert"

echo "ok: ave/behavior chain doc + source anchors present"
