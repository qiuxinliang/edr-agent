#include "edr/behavior_proto_c.h"

#include "edr/behavior_proto.h"

#include <stddef.h>

/*
 * Protobuf 二进制与具体实现无关：nanopb 编码与 libprotobuf-c 解包兼容。
 *
 * 若需使用 protobuf-c 生成的 *_pack（malloc 字符串等），请：
 *   1. 安装 protobuf-c 与 protoc-gen-c，运行 scripts/regen_event_proto_c.sh
 *   2. 根据 src/proto_c/edr/v1/event.pb-c.h 中的 oneof / 字段名，
 *      将 scripts/behavior_proto_c_pack.c.in 拷贝为 behavior_proto_c_pack.c 并补全，
 *      或在 CMake 中启用 EDR_PROTOBUF_C_USE_GENERATED 并链接实现文件。
 */

size_t edr_behavior_record_encode_protobuf_c(const EdrBehaviorRecord *r, uint8_t *out,
                                             size_t out_cap) {
  return edr_behavior_record_encode_protobuf(r, out, out_cap);
}
