/**
 * 将 §12.4 行为告警推入 EventBatch（与 gRPC ReportEvents payload 同源）。
 */
#ifndef EDR_BEHAVIOR_ALERT_EMIT_H
#define EDR_BEHAVIOR_ALERT_EMIT_H

#include "ave_sdk.h"

void edr_behavior_alert_emit_to_batch(const AVEBehaviorAlert *a);

#endif
