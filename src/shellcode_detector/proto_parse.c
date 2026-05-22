#include "edr/proto_parse.h"

#include <stdio.h>
#include <string.h>

#define SMB2_MAGIC "\xfeSMB"
#define SMB1_MAGIC "\xffSMB"
#define SMB2_HEADER_SIZE 64u
#define SMB1_HEADER_SIZE 32u

static uint16_t rd16le(const uint8_t *p) {
  return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint16_t rd16be(const uint8_t *p) {
  return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static uint32_t rd24be(const uint8_t *p) {
  return ((uint32_t)p[0] << 16) | ((uint32_t)p[1] << 8) | (uint32_t)p[2];
}

static int is_grease(uint16_t v) {
  return ((v & 0x0f0fu) == 0x0a0au && ((v >> 8) == (v & 0xffu))) ? 1 : 0;
}

static int append_u16_dec(char *out, size_t cap, size_t *off, uint16_t v, int *first) {
  int n;
  if (!out || !off || *off >= cap) {
    return -1;
  }
  n = snprintf(out + *off, cap - *off, "%s%u", (*first) ? "" : "-", (unsigned)v);
  if (n < 0 || (size_t)n >= cap - *off) {
    return -1;
  }
  *off += (size_t)n;
  *first = 0;
  return 0;
}

static int sni_is_suspicious(const char *s) {
  if (!s || !s[0]) {
    return 0;
  }
  int dot = 0;
  int alpha = 0;
  int digit = 0;
  int dash = 0;
  for (const char *p = s; *p; p++) {
    if (*p == '.') {
      dot = 1;
    } else if ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z')) {
      alpha = 1;
    } else if (*p >= '0' && *p <= '9') {
      digit++;
    } else if (*p == '-') {
      dash++;
    } else {
      return 1;
    }
  }
  if (!dot || !alpha) {
    return 1;
  }
  return (digit >= 10 || dash >= 5) ? 1 : 0;
}

int edr_proto_parse_tls_client_hello(const uint8_t *data, uint32_t len,
                                     EdrTlsClientHelloInfo *out) {
  if (!out) {
    return 0;
  }
  memset(out, 0, sizeof(*out));
  if (!data || len < 11u || data[0] != 0x16u || data[1] != 0x03u) {
    return 0;
  }
  uint32_t rec_len = rd16be(data + 3u);
  if (rec_len + 5u > len) {
    return 0;
  }
  const uint8_t *hs = data + 5u;
  if (hs[0] != 0x01u) {
    return 0;
  }
  uint32_t hs_len = rd24be(hs + 1u);
  if (hs_len + 4u > rec_len || hs_len < 38u) {
    return 0;
  }
  uint32_t p = 9u;
  uint32_t end = 5u + 4u + hs_len;
  if (p + 34u > end) {
    return 0;
  }
  uint16_t ver = rd16be(data + p);
  out->tls_version = ver;
  p += 2u + 32u;
  if (p + 1u > end) {
    return 0;
  }
  uint32_t sid_len = data[p++];
  if (p + sid_len + 2u > end) {
    return 0;
  }
  p += sid_len;
  uint32_t cipher_len = rd16be(data + p);
  p += 2u;
  if (cipher_len < 2u || (cipher_len & 1u) || p + cipher_len + 1u > end) {
    return 0;
  }
  char ciphers[220] = "";
  size_t co = 0u;
  int first = 1;
  for (uint32_t i = 0; i + 1u < cipher_len; i += 2u) {
    uint16_t c = rd16be(data + p + i);
    if (!is_grease(c)) {
      (void)append_u16_dec(ciphers, sizeof(ciphers), &co, c, &first);
      out->cipher_count++;
    }
  }
  p += cipher_len;
  uint32_t comp_len = data[p++];
  if (p + comp_len > end) {
    return 0;
  }
  p += comp_len;
  char exts[180] = "";
  char groups[180] = "";
  char points[80] = "";
  if (p + 2u <= end) {
    uint32_t ext_len = rd16be(data + p);
    p += 2u;
    if (p + ext_len > end) {
      return 0;
    }
    uint32_t ext_end = p + ext_len;
    size_t eo = 0u, go = 0u, po = 0u;
    int first_ext = 1, first_group = 1, first_point = 1;
    while (p + 4u <= ext_end) {
      uint16_t et = rd16be(data + p);
      uint16_t el = rd16be(data + p + 2u);
      p += 4u;
      if (p + el > ext_end) {
        return 0;
      }
      if (!is_grease(et)) {
        (void)append_u16_dec(exts, sizeof(exts), &eo, et, &first_ext);
        out->extension_count++;
      }
      if (et == 0u && el >= 5u) {
        uint32_t q = p;
        uint32_t list_len = rd16be(data + q);
        q += 2u;
        uint32_t list_end = q + list_len;
        while (q + 3u <= p + el && q + 3u <= list_end) {
          uint8_t name_type = data[q++];
          uint16_t name_len = rd16be(data + q);
          q += 2u;
          if (q + name_len > p + el) {
            break;
          }
          if (name_type == 0u && name_len > 0u) {
            uint32_t n = name_len;
            if (n >= sizeof(out->sni)) {
              n = sizeof(out->sni) - 1u;
            }
            memcpy(out->sni, data + q, n);
            out->sni[n] = '\0';
          }
          q += name_len;
        }
      } else if (et == 10u && el >= 2u) {
        uint32_t q = p;
        uint32_t glen = rd16be(data + q);
        q += 2u;
        uint32_t gend = q + glen;
        while (q + 1u < p + el && q + 1u < gend) {
          uint16_t g = rd16be(data + q);
          if (!is_grease(g)) {
            (void)append_u16_dec(groups, sizeof(groups), &go, g, &first_group);
          }
          q += 2u;
        }
      } else if (et == 11u && el >= 1u) {
        uint32_t q = p;
        uint32_t plen = data[q++];
        uint32_t pend = q + plen;
        while (q < p + el && q < pend) {
          (void)append_u16_dec(points, sizeof(points), &po, (uint16_t)data[q], &first_point);
          q++;
        }
      }
      p += el;
    }
  }
  (void)snprintf(out->ja3, sizeof(out->ja3), "%u,%s,%s,%s,%s", (unsigned)ver, ciphers, exts, groups, points);
  out->sni_suspicious = (uint8_t)sni_is_suspicious(out->sni);
  return 1;
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
