/**
 * BehaviorEvent 紧凑线格式 v1（§6 的中间层，非完整 protobuf，字段顺序与 proto 顶部对齐便于后续替换）。
 * Magic: 0x31424542 即 ASCII "BER1" 小端。
 */
#ifndef EDR_BEHAVIOR_WIRE_H
#define EDR_BEHAVIOR_WIRE_H

#include "behavior_record.h"

#include <stddef.h>
#include <stdint.h>

#define EDR_BEHAVIOR_WIRE_MAGIC 0x31424542u
#define EDR_BEHAVIOR_WIRE_VER 2u

/**
 * 将 r 编码到 out；返回写入字节数；空间不足返回 0。
 */
size_t edr_behavior_wire_encode(const EdrBehaviorRecord *r, uint8_t *out, size_t out_cap);

#endif
