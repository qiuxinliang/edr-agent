/**
 * §17.5.2 协议解析层 — TCP 载荷内定位待检测缓冲区（首版：SMB2/SMB1/RDP 启发式边界）。
 */
#ifndef EDR_PROTO_PARSE_H
#define EDR_PROTO_PARSE_H

#include <stdbool.h>
#include <stdint.h>

typedef enum {
  EDR_PROTO_PARSE_OK = 0,
  EDR_PROTO_PARSE_TOO_SHORT = 1,
  EDR_PROTO_PARSE_NOT_INTERESTING = 2,
  EDR_PROTO_PARSE_UNKNOWN = 3,
} EdrProtoParseResult;

typedef enum {
  EDR_PROTO_KIND_UNKNOWN = 0,
  EDR_PROTO_KIND_SMB2 = 1,
  EDR_PROTO_KIND_SMB1 = 2,
  EDR_PROTO_KIND_RDP = 3,
  /** 明文 HTTP/1.x（首行 + 头部后的 body 区；HTTPS/TLS 仍走 UNKNOWN） */
  EDR_PROTO_KIND_HTTP = 4,
} EdrProtoKind;

typedef struct {
  EdrProtoKind kind;
  uint32_t payload_off;
  uint32_t payload_len;
  bool is_negotiate;
} EdrProtoShellcodeRegion;

/**
 * 在一段已截断的 TCP payload 中查找用于 shellcode 检测的字节区间。
 * 未识别协议时返回 EDR_PROTO_PARSE_UNKNOWN。
 */
EdrProtoParseResult edr_proto_find_shellcode_region(const uint8_t *data, uint32_t len,
                                                    EdrProtoShellcodeRegion *out);

#endif
