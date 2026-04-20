/**
 * EdrBehaviorRecord → edr.v1.BehaviorEvent（nanopb）二进制编码（§6.1）。
 */
#ifndef EDR_BEHAVIOR_PROTO_H
#define EDR_BEHAVIOR_PROTO_H

#include "behavior_record.h"

#include <stddef.h>
#include <stdint.h>

/**
 * 将 r 编码为 protobuf 字节；成功返回写入长度，失败或空间不足返回 0。
 * 最大编码长度见 `edr_v1_BehaviorEvent_size`（event.pb.h）。
 */
size_t edr_behavior_record_encode_protobuf(const EdrBehaviorRecord *r, uint8_t *out,
                                           size_t out_cap);

struct AVEBehaviorAlert;
/**
 * 将 behavior.onnx 告警编码为带 `behavior_alert` 的 BehaviorEvent（§12.4）。
 * endpoint_id / tenant_id 可为空串（由调用方从配置填入）。
 */
size_t edr_behavior_alert_encode_protobuf(const struct AVEBehaviorAlert *a, const char *endpoint_id,
                                            const char *tenant_id, uint8_t *out, size_t out_cap);

#endif
