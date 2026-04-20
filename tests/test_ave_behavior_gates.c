/**
 * 《11》§7/§8 与 `pid_history.h` 常量对齐的轻量门禁（无 ORT）。
 * P3：与 `onnxtraining/.../feature_config.BEHAVIOR_THRESHOLDS` 及 **`docs/AVE_P3_TRACEABILITY.md`** 对齐。
 */
#include "edr/ave_behavior_gates.h"
#include "edr/pid_history.h"

#include <math.h>

int main(void) {
#if EDR_AVE_BEH_ONNX_SEQ_LEN != EDR_PID_HISTORY_MAX_SEQ
  return 1;
#endif
#if EDR_AVE_BEH_ONNX_FEAT_DIM != EDR_PID_HISTORY_FEAT_DIM
  return 1;
#endif
  if (EDR_AVE_BEH_SCORE_HIGH <= EDR_AVE_BEH_SCORE_MEDIUM_LOW) {
    return 2;
  }
  if (fabsf(EDR_AVE_BEH_SCORE_MEDIUM_LOW - 0.40f) > 1e-5f) {
    return 10;
  }
  if (fabsf(EDR_AVE_BEH_SCORE_HIGH - 0.65f) > 1e-5f) {
    return 11;
  }
  if (fabsf(EDR_AVE_PMFE_TRIGGER_SCORE - 0.45f) > 1e-5f) {
    return 12;
  }
  /* 《11》§7.1：步长 16 / 8 与连续中等次数 3（见 ave_behavior_gates.h、BEHAVIOR_GATES_AG013.md） */
  if (EDR_AVE_BEH_INFER_STEP_DEFAULT != 16u) {
    return 3;
  }
  if (EDR_AVE_BEH_INFER_STEP_TIGHT != 8u) {
    return 4;
  }
  if (EDR_AVE_BEH_MEDIUM_RUN_LEN_FOR_STEP_TIGHT != 3u) {
    return 5;
  }
  return 0;
}
