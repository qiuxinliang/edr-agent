#ifndef EDR_FL_PB_WIRE_H
#define EDR_FL_PB_WIRE_H

#include <stddef.h>
#include <stdint.h>

/**
 * 编码 `edr.v1.UploadGradientsRequest`（proto3）；返回写入长度，失败返回 0。
 * `gradient_upload_id == NULL` 或空：整包上传（字段 1–4），兼容旧协调端。
 * 否则：字段 5–7 与分片数据（字段 3 为当前片字节）。
 */
size_t fl_pb_encode_upload_gradients(uint8_t *out, size_t out_cap, const char *endpoint_id,
                                     uint64_t round_id, const uint8_t *sealed, size_t sealed_len,
                                     const char *tenant_id);
size_t fl_pb_encode_upload_gradients_chunked(uint8_t *out, size_t out_cap, const char *endpoint_id,
                                           uint64_t round_id, const uint8_t *chunk, size_t chunk_len,
                                           const char *tenant_id, const char *gradient_upload_id,
                                           uint32_t chunk_index, uint32_t chunk_count);

#endif
