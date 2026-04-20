#!/usr/bin/env bash
# 《11_behavior.onnx详细设计》§6.1 与端侧头文件 / ORT 默认序列长 文实一致门禁（无编译）。
# 用法：在 edr-agent 仓库根目录执行 ./scripts/check_behavior_onnx_contract.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

die() { echo "check_behavior_onnx_contract: $*" >&2; exit 1; }

test -f include/edr/pid_history.h || die "include/edr/pid_history.h missing (run from edr-agent root)"
test -f include/edr/ave_behavior_gates.h || die "include/edr/ave_behavior_gates.h missing (《11》§7/§8)"
test -f src/ave/ave_onnx_infer.c || die "src/ave/ave_onnx_infer.c missing"

grep -q 'EDR_AVE_BEH_SCORE_MEDIUM_LOW' include/edr/ave_behavior_gates.h \
  || die "§7: EDR_AVE_BEH_SCORE_MEDIUM_LOW (0.40) missing"
grep -q 'EDR_AVE_BEH_SCORE_HIGH' include/edr/ave_behavior_gates.h \
  || die "§7: EDR_AVE_BEH_SCORE_HIGH (0.65) missing"
grep -q 'EDR_AVE_BEH_INFER_STEP_DEFAULT' include/edr/ave_behavior_gates.h \
  || die "§7: EDR_AVE_BEH_INFER_STEP_DEFAULT (16) missing"
grep -q 'EDR_AVE_BEH_ONNX_SEQ_LEN' include/edr/ave_behavior_gates.h \
  || die "§8.1: EDR_AVE_BEH_ONNX_SEQ_LEN missing"
grep -q 'bp_infer_immediate' src/ave/ave_behavior_pipeline.c \
  || die "§7.1: bp_infer_immediate missing in ave_behavior_pipeline.c"
grep -q 'ave_behavior_gates.h' src/ave/ave_behavior_pipeline.c \
  || die "pipeline must include ave_behavior_gates.h"

grep -q '#define EDR_PID_HISTORY_MAX_SEQ 128' include/edr/pid_history.h \
  || die "EDR_PID_HISTORY_MAX_SEQ must be 128 (《11》§6.1 seq_len)"
grep -q '#define EDR_PID_HISTORY_FEAT_DIM 64' include/edr/pid_history.h \
  || die "EDR_PID_HISTORY_FEAT_DIM must be 64 (《11》§6.1 feature_dim)"

# ORT 分支默认 seq（与 env_behavior_seq_len 一致）；stub 分支 seq=1 为预期
if grep -q 'EDR_HAVE_ONNXRUNTIME' src/ave/ave_onnx_infer.c; then
  grep -q 'return 128' src/ave/ave_onnx_infer.c \
    || die "env_behavior_seq_len default 128 missing in ave_onnx_infer.c"
fi

grep -q 'encode_c_group' src/ave/ave_behavior_features.c \
  || die "encode_c_group missing (§5.3 C 组入口)"

grep -q 'feat\[57\] = 1.f' src/ave/ave_behavior_features.c \
  || die "§5.6 is_real_event: feat[57]=1 for real steps must remain in encode_e_group"

grep -q '§5.6 PAD' src/ave/ave_behavior_pipeline.c \
  || die "ph_build_ort_input must document §5.6 PAD (all-zero steps incl. dim 57)"

grep -q 'target_has_motw' include/edr/ave_sdk.h \
  || die "P0 T01: AVEBehaviorEvent.target_has_motw (§5.3 dim 35)"
grep -q 'cert_revoked_ancestor' include/edr/ave_sdk.h \
  || die "P0 T02b: AVEBehaviorEvent.cert_revoked_ancestor (§5.5 dim 56 event OR ex)"
grep -q 'cert_revoked_ancestor' include/edr/behavior_record.h \
  || die "EdrBehaviorRecord.cert_revoked_ancestor (wire → AveBehaviorEventFeed)"
grep -q 'cert_revoked_ancestor' src/serialize/behavior_proto.c \
  || die "behavior_proto.c fills AveBehaviorEventFeed.cert_revoked_ancestor"

grep -q 'sticky_cert_revoked_ancestor' include/edr/pid_history.h \
  || die "P0 T02: EdrPidHistory.sticky_cert_revoked_ancestor"

grep -q 'ph_reset_lifecycle_for_pid_reuse' src/ave/ave_behavior_pipeline.c \
  || die "P0 T03: PROCESS_CREATE PID reuse reset"

grep -q 'EDR_AVE_BEH_INFER_MIN_EVENTS' src/ave/ave_behavior_pipeline.c \
  || die "P1 T06: ORT infer throttle env EDR_AVE_BEH_INFER_MIN_EVENTS"

grep -q 's_bp_ort_scratch' src/ave/ave_behavior_pipeline.c \
  || die "P1 T04: fixed ORT scratch buffer"

grep -q 'edr_onnx_static_export_weights' src/ave/ave_onnx_infer.c \
  || die "P3 T10: static onnx export"
grep -q 'edr_onnx_behavior_export_fl_trainable_floats' src/ave/edr_onnx_behavior_fl_tensor_export.c \
  || die "behavior FL tensor export (§9.4)"
grep -q 'AVE_ExportBehaviorFlTrainableTensors' include/edr/ave_sdk.h \
  || die "AVE_ExportBehaviorFlTrainableTensors in ave_sdk.h"

grep -q 'target_has_motw' proto/edr/v1/event.proto \
  || die "FileDetail.target_has_motw in proto"
grep -q 'AveBehaviorEventFeed' proto/edr/v1/event.proto \
  || die "《11》§4.1: AveBehaviorEventFeed in event.proto"
grep -q 'ave_behavior_feed' proto/edr/v1/event.proto \
  || die "BehaviorEvent.ave_behavior_feed (field 41)"
grep -q 'edr_v1_AveBehaviorEventFeed' src/proto/edr/v1/event.pb.h \
  || die "nanopb: edr_v1_AveBehaviorEventFeed in event.pb.h"

grep -q 'edr_ave_cross_engine_feed_from_record' src/preprocess/preprocess_pipeline.c \
  || die "P2 T9: cross-engine feed from preprocess"

test -f scripts/behavior_encode_m3b.py || die "P5 T17: scripts/behavior_encode_m3b.py missing"
grep -q 'encode_m3b' scripts/behavior_encode_m3b.py \
  || die "P5 T17: behavior_encode_m3b.py must export encode_m3b"

echo "check_behavior_onnx_contract: ok"
