#ifndef EDR_FL_GRADIENT_UPLOAD_H
#define EDR_FL_GRADIENT_UPLOAD_H

#include <stddef.h>
#include <stdint.h>

struct FLTConfig;

/**
 * 上传梯度：`http_url` 非空则 JSON+Base64 POST；否则若 `grpc_target` 非空则 gRPC Unary（需 CMake 启用）。
 * 二者皆空则占位成功（仅 `EDR_FL_UPLOAD_TRACE` 落盘）。
 * `max_chunk_size`：单块最大字节数（通常 `[fl] gradient_chunk_size_kb * 1024`）；`0` 或 `len` 不超过该值时
 * 单次请求（无 `gradient_upload_id` / chunk 字段，兼容旧协调端）；否则按片顺序上传，片间共用 `gradient_upload_id`。
 * `fl_cfg`：可选；非空且配置了 `[fl.frozen_layers]` 时 HTTP JSON 附带 `frozen_layer_names`（T-015）。
 */
int fl_gradient_upload_bytes(const unsigned char *data, size_t len, const char *http_url,
                             const char *grpc_target, const char *endpoint_id, const char *tenant_id,
                             uint64_t round_id, size_t max_chunk_size, const struct FLTConfig *fl_cfg);

#endif
