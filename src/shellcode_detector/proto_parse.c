#include "edr/proto_parse.h"

#include <string.h>

#define SMB2_MAGIC "\xfeSMB"
#define SMB1_MAGIC "\xffSMB"
#define SMB2_HEADER_SIZE 64u
#define SMB1_HEADER_SIZE 32u

static uint16_t rd16le(const uint8_t *p) {
  return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

EdrProtoParseResult edr_proto_find_shellcode_region(const uint8_t *data, uint32_t len,
                                                    EdrProtoShellcodeRegion *out) {
  if (!out) {
    return EDR_PROTO_PARSE_TOO_SHORT;
  }
  memset(out, 0, sizeof(*out));
  if (!data || len < 4u) {
    return EDR_PROTO_PARSE_TOO_SHORT;
  }

  uint32_t off = 0;
  if (data[0] == 0x00u) {
    off = 4u;
    if (len < off + 4u) {
      return EDR_PROTO_PARSE_TOO_SHORT;
    }
  }

  if (off + 4u > len) {
    return EDR_PROTO_PARSE_UNKNOWN;
  }

  /* SMB2 */
  if (memcmp(data + off, SMB2_MAGIC, 4u) == 0) {
    if (len < off + SMB2_HEADER_SIZE) {
      return EDR_PROTO_PARSE_TOO_SHORT;
    }
    uint16_t command = rd16le(data + off + 12u);
    out->kind = EDR_PROTO_KIND_SMB2;
    if (command == 0x0000u) {
      out->is_negotiate = true;
      out->payload_off = off + SMB2_HEADER_SIZE;
      out->payload_len = len - off - SMB2_HEADER_SIZE;
      return EDR_PROTO_PARSE_OK;
    }
    if (command == 0x0009u || command == 0x000Bu) {
      out->is_negotiate = false;
      out->payload_off = off + SMB2_HEADER_SIZE;
      out->payload_len = len - off - SMB2_HEADER_SIZE;
      return EDR_PROTO_PARSE_OK;
    }
    return EDR_PROTO_PARSE_NOT_INTERESTING;
  }

  /* SMBv1 */
  if (memcmp(data + off, SMB1_MAGIC, 4u) == 0) {
    if (off + 5u > len) {
      return EDR_PROTO_PARSE_TOO_SHORT;
    }
    uint8_t cmd = data[off + 4u];
    if (cmd == 0x25u || cmd == 0x32u) {
      if (len < off + SMB1_HEADER_SIZE) {
        return EDR_PROTO_PARSE_TOO_SHORT;
      }
      out->kind = EDR_PROTO_KIND_SMB1;
      out->is_negotiate = false;
      out->payload_off = off + SMB1_HEADER_SIZE;
      out->payload_len = len - off - SMB1_HEADER_SIZE;
      return EDR_PROTO_PARSE_OK;
    }
    return EDR_PROTO_PARSE_NOT_INTERESTING;
  }

  /* TPKT + X.224 粗判 RDP */
  if (len >= 7u && data[0] == 0x03u && data[1] == 0x00u && data[4] == 0x02u) {
    out->kind = EDR_PROTO_KIND_RDP;
    out->payload_off = 7u;
    out->payload_len = (len > 7u) ? (len - 7u) : 0u;
    out->is_negotiate = false;
    return EDR_PROTO_PARSE_OK;
  }

  /* 明文 HTTP/1.x：请求行或状态行 + \r\n\r\n 后为 body（任意端口） */
  if (len >= 16u) {
    int req = (memcmp(data, "GET ", 4u) == 0 || memcmp(data, "PUT ", 4u) == 0 ||
               memcmp(data, "POST ", 5u) == 0 || memcmp(data, "HEAD ", 5u) == 0);
    int resp = (len >= 8u && memcmp(data, "HTTP/1.", 7u) == 0);
    if (req || resp) {
      uint32_t body_off = len;
      for (uint32_t i = 0; i + 3u < len; i++) {
        if (data[i] == '\r' && data[i + 1u] == '\n' && data[i + 2u] == '\r' && data[i + 3u] == '\n') {
          body_off = i + 4u;
          break;
        }
      }
      if (body_off < len) {
        out->kind = EDR_PROTO_KIND_HTTP;
        out->is_negotiate = false;
        out->payload_off = body_off;
        out->payload_len = len - body_off;
        return EDR_PROTO_PARSE_OK;
      }
      /* 无完整头部时仍扫描首行之后，避免漏报极短片段 */
      uint32_t line_end = len;
      for (uint32_t i = 0; i < len; i++) {
        if (data[i] == '\n') {
          line_end = i + 1u;
          break;
        }
      }
      if (line_end < len) {
        out->kind = EDR_PROTO_KIND_HTTP;
        out->is_negotiate = false;
        out->payload_off = line_end;
        out->payload_len = len - line_end;
        return EDR_PROTO_PARSE_OK;
      }
    }
  }

  return EDR_PROTO_PARSE_UNKNOWN;
}
