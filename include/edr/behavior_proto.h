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

typedef struct AVEBehaviorAlert AVEBehaviorAlert;
/**
 * 将主机行为告警编码为带 `behavior_alert` 的 BehaviorEvent。
 * endpoint_id / tenant_id 可为空串（由调用方从配置填入）。
 */
size_t edr_behavior_alert_encode_protobuf(const AVEBehaviorAlert *a, const char *endpoint_id,
                                          const char *tenant_id, uint8_t *out, size_t out_cap);

/**
 * 将行为记录与主机行为告警编码到同一个 BehaviorEvent 中。
 * 顶层字段全部来自 r；behavior_alert 嵌套字段全部来自 a。
 */
size_t edr_behavior_record_alert_encode_protobuf(const EdrBehaviorRecord *r,
                                                 const AVEBehaviorAlert *a, uint8_t *out,
                                                 size_t out_cap);

#endif
