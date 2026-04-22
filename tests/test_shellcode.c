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
    /* T-SC-011: additional SMB2 commands share the same post-header scan region. */
    const uint16_t cmds[] = {0x0001u, 0x0003u, 0x0005u, 0x0008u, 0x000Bu, 0x0011u};
    for (size_t c = 0; c < sizeof(cmds) / sizeof(cmds[0]); c++) {
      uint8_t smb2b[80];
      memset(smb2b, 0, sizeof(smb2b));
      memcpy(smb2b, "\xfeSMB", 4u);
      smb2b[12] = (uint8_t)(cmds[c] & 0xFFu);
      smb2b[13] = (uint8_t)((cmds[c] >> 8) & 0xFFu);
      smb2b[70] = 0x37u;
      EdrProtoShellcodeRegion r;
      EdrProtoParseResult pr = edr_proto_find_shellcode_region(smb2b, (uint32_t)sizeof(smb2b), &r);
      if (pr != EDR_PROTO_PARSE_OK || r.kind != EDR_PROTO_KIND_SMB2) {
        return fail("smb2 extended command parse");
      }
      if (r.payload_off != 64u || r.payload_len != (uint32_t)sizeof(smb2b) - 64u) {
        return fail("smb2 extended command region");
      }
    }
  }
  {
    uint8_t smb2lock[70];
    memset(smb2lock, 0, sizeof(smb2lock));
    memcpy(smb2lock, "\xfeSMB", 4u);
    smb2lock[12] = 0x0Au;
    smb2lock[13] = 0x00u;
    EdrProtoShellcodeRegion r;
    EdrProtoParseResult pr = edr_proto_find_shellcode_region(smb2lock, (uint32_t)sizeof(smb2lock), &r);
    if (pr != EDR_PROTO_PARSE_NOT_INTERESTING) {
      return fail("smb2 lock not interesting");
    }
  }
  {
    /* T-SC-012: SMB1 NT Create AndX (0xA2) uses same 32-byte header skip as Trans. */
    uint8_t inner[80];
    memset(inner, 0, sizeof(inner));
    inner[40] = 0x81;
    inner[41] = 0xF1;
    inner[42] = 0x13;
    inner[43] = 0x00;
    inner[44] = 0x00;
    inner[45] = 0x00;
    inner[46] = 0x49;
    uint8_t framed[112];
    memset(framed, 0, sizeof(framed));
    memcpy(framed, "\xffSMB", 4u);
    framed[4] = 0xa2u;
    memcpy(framed + 32u, inner, sizeof(inner));
    EdrProtoShellcodeRegion r;
    EdrProtoParseResult pr = edr_proto_find_shellcode_region(framed, (uint32_t)sizeof(framed), &r);
    if (pr != EDR_PROTO_PARSE_OK || r.kind != EDR_PROTO_KIND_SMB1) {
      return fail("smb1 cmd a2 parse");
    }
    char rule[96];
    if (!edr_shellcode_match_known_exploit(framed + r.payload_off, r.payload_len, EDR_PROTO_KIND_SMB1, rule,
                                           sizeof(rule))) {
      return fail("known smb1 cmd a2 payload match");
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
  }
  {
    /* Corpus pipeline alignment: SMB1 Trans + 32-byte header + payload (see emit_baseline_variants.py). */
    uint8_t inner[80];
    memset(inner, 0, sizeof(inner));
    inner[40] = 0x81;
    inner[41] = 0xF1;
    inner[42] = 0x13;
    inner[43] = 0x00;
    inner[44] = 0x00;
    inner[45] = 0x00;
    inner[46] = 0x49;
    uint8_t framed[112];
    memset(framed, 0, sizeof(framed));
    memcpy(framed, "\xffSMB", 4u);
    framed[4] = 0x25u;
    memcpy(framed + 32u, inner, sizeof(inner));
    EdrProtoShellcodeRegion r;
    EdrProtoParseResult pr =
        edr_proto_find_shellcode_region(framed, (uint32_t)sizeof(framed), &r);
    if (pr != EDR_PROTO_PARSE_OK || r.kind != EDR_PROTO_KIND_SMB1) {
      return fail("smb1 framed parse");
    }
    if (r.payload_off != 32u || r.payload_len != sizeof(inner)) {
      return fail("smb1 framed region");
    }
    char rule[96];
    if (!edr_shellcode_match_known_exploit(framed + r.payload_off, r.payload_len, EDR_PROTO_KIND_SMB1, rule,
                                           sizeof(rule))) {
      return fail("known smb1 framed payload match");
    }
    if (strcmp(rule, "EternalBlue_MS17_010") != 0) {
      return fail("known smb1 framed rule name");
    }
  }
  {
    /* NetBIOS session message (0x00 + BE length) then same SMB1 PDU; proto_parse uses off=4. */
    uint8_t inner[80];
    memset(inner, 0, sizeof(inner));
    inner[40] = 0x81;
    inner[41] = 0xF1;
    inner[42] = 0x13;
    inner[43] = 0x00;
    inner[44] = 0x00;
    inner[45] = 0x00;
    inner[46] = 0x49;
    uint8_t smb[112];
    memset(smb, 0, sizeof(smb));
    memcpy(smb, "\xffSMB", 4u);
    smb[4] = 0x25u;
    memcpy(smb + 32u, inner, sizeof(inner));
    uint32_t smb_len = (uint32_t)sizeof(smb);
    uint8_t nb[4u + 112u];
    nb[0] = 0x00u;
    nb[1] = (uint8_t)((smb_len >> 16) & 0xFFu);
    nb[2] = (uint8_t)((smb_len >> 8) & 0xFFu);
    nb[3] = (uint8_t)(smb_len & 0xFFu);
    memcpy(nb + 4u, smb, smb_len);
    EdrProtoShellcodeRegion r;
    EdrProtoParseResult pr = edr_proto_find_shellcode_region(nb, (uint32_t)sizeof(nb), &r);
    if (pr != EDR_PROTO_PARSE_OK || r.kind != EDR_PROTO_KIND_SMB1) {
      return fail("smb1 netbios parse");
    }
    if (r.payload_off != 36u || r.payload_len != sizeof(inner)) {
      return fail("smb1 netbios region");
    }
    char rule[96];
    if (!edr_shellcode_match_known_exploit(nb + r.payload_off, r.payload_len, EDR_PROTO_KIND_SMB1, rule,
                                           sizeof(rule))) {
      return fail("known smb1 netbios payload match");
    }
    if (strcmp(rule, "EternalBlue_MS17_010") != 0) {
      return fail("known smb1 netbios rule name");
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
    const uint8_t rdp_inner[] = {
        0x4Du, 0x53u, 0x5Fu, 0x54u, 0x31u, 0x32u, 0x30u, 0x00u, 0x1Fu, 0x00u, 0x41u, 0x41u, 0x41u, 0x41u, 0x41u,
        0x41u, 0x41u, 0x41u, 0x41u, 0x41u, 0x41u, 0x41u, 0x41u, 0x41u, 0x41u, 0x41u};
    uint32_t ilen = (uint32_t)sizeof(rdp_inner);
    uint8_t framed[40];
    uint16_t tot = (uint16_t)(7u + ilen);
    framed[0] = 0x03u;
    framed[1] = 0x00u;
    framed[2] = (uint8_t)((tot >> 8) & 0xFFu);
    framed[3] = (uint8_t)(tot & 0xFFu);
    framed[4] = 0x02u;
    framed[5] = 0x00u;
    framed[6] = 0x00u;
    memcpy(framed + 7u, rdp_inner, ilen);
    uint32_t flen = 7u + ilen;
    EdrProtoShellcodeRegion r;
    EdrProtoParseResult pr = edr_proto_find_shellcode_region(framed, flen, &r);
    if (pr != EDR_PROTO_PARSE_OK || r.kind != EDR_PROTO_KIND_RDP) {
      return fail("rdp framed parse");
    }
    if (r.payload_off != 7u || r.payload_len != ilen) {
      return fail("rdp framed region");
    }
    char rule[96];
    if (!edr_shellcode_match_known_exploit(framed + r.payload_off, r.payload_len, EDR_PROTO_KIND_RDP, rule,
                                           sizeof(rule))) {
      return fail("known rdp framed payload match");
    }
    if (strcmp(rule, "BlueKeep_CVE_2019_0708") != 0) {
      return fail("known rdp framed rule name");
    }
  }
  {
    uint8_t http_lc[96];
    memset(http_lc, 0, sizeof(http_lc));
    const char *hdr_lc = "post /api HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\n\r\n";
    size_t hl = strlen(hdr_lc);
    memcpy(http_lc, hdr_lc, hl);
    memcpy(http_lc + hl, "abcd", 4);
    EdrProtoShellcodeRegion r;
    EdrProtoParseResult pr = edr_proto_find_shellcode_region(http_lc, (uint32_t)(hl + 4u), &r);
    if (pr != EDR_PROTO_PARSE_OK || r.kind != EDR_PROTO_KIND_HTTP) {
      return fail("http lowercase method parse");
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
  {
    static const uint8_t k_efsr[] = {0xC6u, 0x81u, 0xD4u, 0x88u, 0xD8u, 0x50u, 0x11u, 0xD0u,
                                     0x8Cu, 0x52u, 0x00u, 0xC0u, 0x4Fu, 0xD9u, 0x0Fu, 0x7Eu};
    uint8_t smb2_efsr[64];
    memset(smb2_efsr, 0x11, sizeof(smb2_efsr));
    memcpy(smb2_efsr + 10, k_efsr, sizeof(k_efsr));
    char rule[96];
    if (!edr_shellcode_match_known_exploit(smb2_efsr, (uint32_t)sizeof(smb2_efsr), EDR_PROTO_KIND_SMB2, rule,
                                           sizeof(rule))) {
      return fail("known petitpotam efsr uuid");
    }
    if (strcmp(rule, "PetitPotam_MS_EFSR") != 0) {
      return fail("known petitpotam rule name");
    }
  }
  {
    const char *http_follina =
        "POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 24\r\n\r\n"
        "https://q?ms-msdt:/x";
    char rule[96];
    if (!edr_shellcode_match_known_exploit((const uint8_t *)http_follina,
                                           (uint32_t)strlen(http_follina), EDR_PROTO_KIND_HTTP, rule, sizeof(rule))) {
      return fail("known follina match");
    }
    if (strcmp(rule, "Follina_CVE_2022_30190") != 0) {
      return fail("known follina rule name");
    }
  }
  {
    const char *http_log4 =
        "POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 28\r\n\r\n"
        "${jndi:ldap://127.0.0.1/a}";
    char rule[96];
    if (!edr_shellcode_match_known_exploit((const uint8_t *)http_log4, (uint32_t)strlen(http_log4),
                                           EDR_PROTO_KIND_HTTP, rule, sizeof(rule))) {
      return fail("known log4shell match");
    }
    if (strcmp(rule, "Log4Shell_CVE_2021_44228") != 0) {
      return fail("known log4shell rule name");
    }
  }
  {
    /* T-SC-030: wrong last byte of MS-EFSR UUID — must not hit PetitPotam. */
    static const uint8_t k_efsr[] = {0xC6u, 0x81u, 0xD4u, 0x88u, 0xD8u, 0x50u, 0x11u, 0xD0u,
                                     0x8Cu, 0x52u, 0x00u, 0xC0u, 0x4Fu, 0xD9u, 0x0Fu, 0x7Eu};
    uint8_t bad[16];
    memcpy(bad, k_efsr, 16u);
    bad[15] = 0x00u;
    char rule[96];
    if (edr_shellcode_match_known_exploit(bad, 16u, EDR_PROTO_KIND_SMB2, rule, sizeof(rule))) {
      return fail("negative petitpotam uuid tail");
    }
  }
  {
    const char *http_no_jndi = "POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 12\r\n\r\njndi:ldap://x";
    char rule[96];
    rule[0] = '\0';
    if (edr_shellcode_match_known_exploit((const uint8_t *)http_no_jndi, (uint32_t)strlen(http_no_jndi),
                                          EDR_PROTO_KIND_HTTP, rule, sizeof(rule))) {
      return fail("negative log4shell without dollar");
    }
  }
  return 0;
}
