/**
 * EdrBehaviorRecord → protobuf 二进制（§6.1，与 edr.v1.BehaviorEvent 一致）。
 * 默认实现委托 nanopb 编码（与 libprotobuf-c 解包兼容）；若生成 event.pb-c.* 并改用
 * *_pack，见 third_party/protobuf-c/README_EDR.txt。
 */
#ifndef EDR_BEHAVIOR_PROTO_C_H
#define EDR_BEHAVIOR_PROTO_C_H

#include "behavior_record.h"

#include <stddef.h>
#include <stdint.h>

/**
 * 将 r 打包为 protobuf 二进制；成功返回字节数，失败或不可用返回 0。
 */
size_t edr_behavior_record_encode_protobuf_c(const EdrBehaviorRecord *r, uint8_t *out,
                                             size_t out_cap);

#endif
