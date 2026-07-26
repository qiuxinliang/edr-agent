#include "edr/proto_parse.h"
#include "edr/shellcode_known.h"
#include "edr/shellcode_detector.h"

#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>

static int fail(const char *msg) {
  fprintf(stderr, "fail: %s\n", msg);
  return 1;
}

int main(void) {
  {
    EdrShellcodeRulesStatus st;
    memset(&st, 0, sizeof(st));
    edr_shellcode_known_init(NULL);
    edr_shellcode_known_get_status(&st);
    if (strcmp(st.source, "builtin") != 0 || strcmp(st.version, "builtin-embedded") != 0) {
      return fail("shellcode rules builtin status");
    }
  }
  {
    uint8_t uniform[256];
    memset(uniform, 0x42, sizeof(uniform));
    double e = edr_shellcode_shannon_entropy_bits(uniform, sizeof(uniform));
    if (fabs(e - 0.0) > 0.01) {
      return fail("entropy uniform");
    }
  }
  {
    uint8_t buf[64];
    memset(buf, 0x90, sizeof(buf));
    double s = edr_shellcode_heuristic_score(buf, sizeof(buf));
    if (s < 0.2) {
      return fail("heuristic nop sled");
    }
  }
  {
    uint8_t smb2[96];
    memset(smb2, 0, sizeof(smb2));
    memcpy(smb2, "\xfeSMB", 4);
    smb2[12] = 0x09;
    smb2[13] = 0x00;
    for (int i = 64; i < 96; i++) {
      smb2[i] = (uint8_t)(0x41 + (i & 0xf));
    }
    EdrProtoShellcodeRegion r;
    EdrProtoParseResult pr = edr_proto_find_shellcode_region(smb2, (uint32_t)sizeof(smb2), &r);
    if (pr != EDR_PROTO_PARSE_OK || r.kind != EDR_PROTO_KIND_SMB2) {
      return fail("smb2 parse");
    }
    if (r.payload_off != 64u || r.payload_len != (uint32_t)(sizeof(smb2) - 64u)) {
      return fail("smb2 region");
    }
  }
  {
    uint8_t smb1_payload[80];
    memset(smb1_payload, 0, sizeof(smb1_payload));
    smb1_payload[40] = 0x81;
    smb1_payload[41] = 0xF1;
    smb1_payload[42] = 0x13;
    smb1_payload[43] = 0x00;
    smb1_payload[44] = 0x00;
    smb1_payload[45] = 0x00;
    smb1_payload[46] = 0x49;
    char rule[96];
    if (!edr_shellcode_match_known_exploit(smb1_payload, (uint32_t)sizeof(smb1_payload), EDR_PROTO_KIND_SMB1, rule,
                                           sizeof(rule))) {
      return fail("known smb1 match");
    }
    if (strcmp(rule, "EternalBlue_MS17_010") != 0) {
      return fail("known smb1 rule name");
    }
    EdrShellcodeRulesStatus st;
    memset(&st, 0, sizeof(st));
    edr_shellcode_known_get_status(&st);
    if (st.matches_total == 0u || st.builtin_matches == 0u || strcmp(st.last_match_rule, "EternalBlue_MS17_010") != 0) {
      return fail("shellcode match stats");
    }
  }
  {
    const uint8_t rdp_bluekeep[] = {
        0x4Du, 0x53u, 0x5Fu, 0x54u, 0x31u, 0x32u, 0x30u, 0x00u, 0x1Fu, 0x00u, 0x41u, 0x41u, 0x41u, 0x41u, 0x41u,
        0x41u, 0x41u, 0x41u, 0x41u, 0x41u, 0x41u, 0x41u, 0x41u, 0x41u, 0x41u, 0x41u};
    char rule[96];
    if (!edr_shellcode_match_known_exploit(rdp_bluekeep, (uint32_t)sizeof(rdp_bluekeep), EDR_PROTO_KIND_RDP, rule,
                                           sizeof(rule))) {
      return fail("known rdp match");
    }
    if (strcmp(rule, "BlueKeep_CVE_2019_0708") != 0) {
      return fail("known rdp rule name");
    }
  }
  {
    uint8_t smbghost[96];
    memset(smbghost, 0, sizeof(smbghost));
    memcpy(smbghost, "\xfcSMB", 4);
    smbghost[16] = 0xFFu;
    smbghost[17] = 0xFFu;
    smbghost[18] = 0xFFu;
    smbghost[19] = 0xFFu;
    memset(smbghost + 48, 0x90, 32);
    char rule[96];
    if (!edr_shellcode_match_known_exploit(smbghost, (uint32_t)sizeof(smbghost), EDR_PROTO_KIND_SMB2, rule,
                                           sizeof(rule))) {
      return fail("known smbghost match");
    }
    if (strcmp(rule, "SMBGhost_CVE_2020_0796") != 0) {
      return fail("known smbghost rule name");
    }
  }
  {
    uint8_t http_stage[160];
    memset(http_stage, 0, sizeof(http_stage));
    const char *body = "HTTP/1.1 200 OK\r\nContent-Length: 72\r\n\r\nMZ........ReflectiveLoader........beacon.x64";
    memcpy(http_stage, body, strlen(body));
    char rule[96];
    if (!edr_shellcode_match_known_exploit(http_stage, (uint32_t)sizeof(http_stage), EDR_PROTO_KIND_HTTP, rule,
                                           sizeof(rule))) {
      return fail("known reflective loader match");
    }
    if (strcmp(rule, "ReflectiveLoader_HTTP_Stager") != 0) {
      return fail("known reflective loader rule name");
    }
  }
  {
    const uint8_t ch[] = {
        0x16,0x03,0x01,0x00,0x66, 0x01,0x00,0x00,0x62, 0x03,0x03,
        0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,
        0x00, 0x00,0x04, 0x13,0x01, 0xc0,0x2f, 0x01,0x00, 0x00,0x35,
        0x00,0x00,0x00,0x12, 0x00,0x10,0x00,0x00,0x0d,
        'l','o','g','i','n','.','e','x','a','m','p','l','e',
        0x00,0x0a,0x00,0x08, 0x00,0x06,0x00,0x1d,0x00,0x17,0x00,0x18,
        0x00,0x0b,0x00,0x02, 0x01,0x00,
        0x00,0x0d,0x00,0x09, 0x00,0x07,0x04,0x03,0x08,0x04,0x04,0x01,0x05
    };
    EdrTlsClientHelloInfo ti;
    if (!edr_proto_parse_tls_client_hello(ch, (uint32_t)sizeof(ch), &ti)) {
      return fail("tls clienthello parse");
    }
    if (strcmp(ti.sni, "login.example") != 0) {
      return fail("tls sni parse");
    }
    if (strstr(ti.ja3, "771,4865-49199,0-10-11-13,29-23-24,0") == NULL) {
      return fail("tls ja3 string");
    }
  }
  {
    uint8_t http[128];
    memset(http, 0, sizeof(http));
    const char *hdr = "POST /api HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\n\r\n";
    size_t hlen = strlen(hdr);
    memcpy(http, hdr, hlen);
    memcpy(http + hlen, "ABCD", 4);
    for (size_t i = hlen + 4; i < 96; i++) {
      http[i] = (uint8_t)(0x41 + (i & 0xf));
    }
    EdrProtoShellcodeRegion r;
    EdrProtoParseResult pr = edr_proto_find_shellcode_region(http, 96u, &r);
    if (pr != EDR_PROTO_PARSE_OK || r.kind != EDR_PROTO_KIND_HTTP) {
      return fail("http parse kind");
    }
    if (r.payload_off != (uint32_t)hlen || r.payload_len < 8u) {
      return fail("http region");
    }
  }
  return 0;
}
