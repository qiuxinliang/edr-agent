/**
 * §17 WinDivert：从 %SystemRoot%\System32\WinDivert.dll 动态加载，SNIFF+RECV_ONLY，
 * TCP payload → proto_parse + 启发式，达阈值则写入事件总线（ETW1 载荷）。
 */
#if !defined(_WIN32)
#error windivert_capture.c is Windows-only
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <wincrypt.h>

#include "edr/command.h"
#include "edr/config.h"
#include "edr/error.h"
#include "edr/event_bus.h"
#include "edr/proto_parse.h"
#include "edr/shellcode_known.h"
#include "edr/shellcode_detector.h"
#include "edr/types.h"
#include "edr/edr_log.h"

#include "windivert_abi.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#ifndef CALG_SHA_256
#define CALG_SHA_256 0x0000800c
#endif

/** libpcap LINKTYPE (per tcpdump.org linktypes) */
#define EDR_PCAP_LT_IPV4 228u
#define EDR_PCAP_LT_IPV6 229u
#define EDR_PCAP_LT_EN10MB 1u

/** 环形槽：ts_ns(8) + stored_len(4) + is_v6(4) + payload[max] */
#define EDR_RING_SLOT_HDR 16u

static const char kWdDllPath[] = "%SystemRoot%\\System32\\WinDivert.dll";

static const char kWdFilter[] =
    "tcp and ("
    "tcp.DstPort == 445 or tcp.DstPort == 139 or "
    "tcp.DstPort == 3389 or "
    "tcp.DstPort == 5985 or tcp.DstPort == 5986 or "
    "tcp.DstPort == 135 or "
    "tcp.DstPort == 389 or tcp.DstPort == 636 or tcp.DstPort == 3268 or tcp.DstPort == 3269 or "
    "tcp.SrcPort == 445 or tcp.SrcPort == 139 or "
    "tcp.SrcPort == 3389 or "
    "tcp.SrcPort == 5985 or tcp.SrcPort == 5986 or "
    "tcp.SrcPort == 389 or tcp.SrcPort == 636 or tcp.SrcPort == 3268 or tcp.SrcPort == 3269"
    ")";

typedef HANDLE(WINAPI *PFN_WinDivertOpen)(const char *, WINDIVERT_LAYER, INT16, UINT64);
typedef BOOL(WINAPI *PFN_WinDivertRecv)(HANDLE, PVOID, UINT, UINT *, WINDIVERT_ADDRESS *);
typedef BOOL(WINAPI *PFN_WinDivertClose)(HANDLE);
typedef BOOL(WINAPI *PFN_WinDivertSetParam)(HANDLE, WINDIVERT_PARAM, UINT64);
typedef BOOL(WINAPI *PFN_WinDivertHelperParsePacket)(
    const VOID *, UINT, WINDIVERT_IPHDR **, VOID **, UINT8 *, WINDIVERT_ICMPHDR **, WINDIVERT_ICMPV6HDR **,
    WINDIVERT_TCPHDR **, WINDIVERT_UDPHDR **, PVOID *, UINT *, PVOID *, UINT *);
static HMODULE s_wd_dll;
static PFN_WinDivertOpen s_open;
static PFN_WinDivertRecv s_recv;
static PFN_WinDivertClose s_close;
static PFN_WinDivertSetParam s_setparam;
static PFN_WinDivertHelperParsePacket s_parse;

static HANDLE s_handle = INVALID_HANDLE_VALUE;
static HANDLE s_thread;
static volatile LONG s_capture_stop;
static const EdrConfig *s_cfg;
static EdrEventBus *s_bus;
static int s_wsa_started;

/** 环形缓冲（仅捕获线程写；告警同线程读） */
static uint8_t *s_ring_mem;
static uint32_t s_ring_slots;
static uint32_t s_ring_stride;
static uint32_t s_ring_w;
static uint32_t s_ring_r;
static uint32_t s_ring_count;

static uint64_t edr_win_now_ns(void) {
  FILETIME ft;
  GetSystemTimePreciseAsFileTime(&ft);
  ULARGE_INTEGER u;
  u.LowPart = ft.dwLowDateTime;
  u.HighPart = ft.dwHighDateTime;
  const uint64_t epoch_100ns = 116444736000000000ULL;
  if (u.QuadPart < epoch_100ns) {
    return 0;
  }
  return (u.QuadPart - epoch_100ns) * 100ULL;
}

static void ipv4_ntoa(uint32_t addr_le, char *out, size_t cap) {
  const unsigned char *b = (const unsigned char *)&addr_le;
  snprintf(out, cap, "%u.%u.%u.%u", (unsigned)b[0], (unsigned)b[1], (unsigned)b[2], (unsigned)b[3]);
}

static int ipv6_addrs_to_str(const WINDIVERT_IPV6HDR *h, char *src, size_t src_cap, char *dst, size_t dst_cap) {
  if (!h) {
    return -1;
  }
  const IN6_ADDR *sa = (const IN6_ADDR *)h->SrcAddr;
  const IN6_ADDR *da = (const IN6_ADDR *)h->DstAddr;
  if (!InetNtopA(AF_INET6, sa, src, (DWORD)src_cap)) {
    snprintf(src, src_cap, "?");
  }
  if (!InetNtopA(AF_INET6, da, dst, (DWORD)dst_cap)) {
    snprintf(dst, dst_cap, "?");
  }
  return 0;
}

static int sha256_hex_buf(const uint8_t *data, size_t len, char out65[65]) {
  HCRYPTPROV hProv = 0;
  HCRYPTHASH hHash = 0;
  if (!CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
    return -1;
  }
  if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
    CryptReleaseContext(hProv, 0);
    return -1;
  }
  if (!CryptHashData(hHash, data, (DWORD)len, 0)) {
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    return -1;
  }
  DWORD cb = 32;
  uint8_t hash[32];
  if (!CryptGetHashParam(hHash, HP_HASHVAL, hash, &cb, 0)) {
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    return -1;
  }
  CryptDestroyHash(hHash);
  CryptReleaseContext(hProv, 0);
  static const char *hx = "0123456789abcdef";
  for (DWORD i = 0; i < 32; i++) {
    out65[i * 2] = hx[hash[i] >> 4];
    out65[i * 2 + 1] = hx[hash[i] & 15];
  }
  out65[64] = '\0';
  return 0;
}

static void mkdir_p_win(const char *dir) {
  if (!dir || !dir[0]) {
    return;
  }
  char tmp[1024];
  size_t n = strlen(dir);
  if (n >= sizeof(tmp)) {
    return;
  }
  memcpy(tmp, dir, n + 1u);
  for (char *p = tmp + 1; *p; p++) {
    if (*p == '\\' || *p == '/') {
      char bak = *p;
      *p = '\0';
      (void)CreateDirectoryA(tmp, NULL);
      *p = bak;
    }
  }
  (void)CreateDirectoryA(tmp, NULL);
}

static void pcap_write_global_header(FILE *f, uint32_t linktype) {
  uint8_t gh[24];
  memset(gh, 0, sizeof(gh));
  gh[0] = 0xd4;
  gh[1] = 0xc3;
  gh[2] = 0xb2;
  gh[3] = 0xa1;
  gh[4] = 2;
  gh[5] = 4;
  gh[8] = 0xff;
  gh[9] = 0xff;
  gh[10] = 0xff;
  gh[11] = 0xff;
  gh[16] = 0xff;
  gh[17] = 0xff;
  gh[18] = 0;
  gh[19] = 0;
  memcpy(gh + 20, &linktype, 4);
  (void)fwrite(gh, 1, sizeof(gh), f);
}

static void pcap_write_record_raw_ip(FILE *f, const uint8_t *ip_pkt, uint32_t ip_len, uint32_t tv_sec,
                                     uint32_t tv_usec) {
  uint32_t incl = ip_len;
  uint32_t orig = ip_len;
  (void)fwrite(&tv_sec, 4, 1, f);
  (void)fwrite(&tv_usec, 4, 1, f);
  (void)fwrite(&incl, 4, 1, f);
  (void)fwrite(&orig, 4, 1, f);
  (void)fwrite(ip_pkt, 1, (size_t)ip_len, f);
}

/** 以太网封装（混合 IPv4/IPv6 于同一文件，LINKTYPE=EN10MB） */
static void pcap_write_record_en10mb(FILE *f, const uint8_t *ip_pkt, uint32_t ip_len, int is_v6, uint64_t ts_ns) {
  uint8_t eth[14];
  memset(eth, 0, sizeof(eth));
  eth[12] = is_v6 ? 0x86 : 0x08;
  eth[13] = is_v6 ? 0xdd : 0x00;
  uint32_t tv_sec = (uint32_t)(ts_ns / 1000000000ULL);
  uint32_t tv_usec = (uint32_t)((ts_ns % 1000000000ULL) / 1000ULL);
  uint32_t incl = 14u + ip_len;
  uint32_t orig = incl;
  (void)fwrite(&tv_sec, 4, 1, f);
  (void)fwrite(&tv_usec, 4, 1, f);
  (void)fwrite(&incl, 4, 1, f);
  (void)fwrite(&orig, 4, 1, f);
  (void)fwrite(eth, 1, sizeof(eth), f);
  (void)fwrite(ip_pkt, 1, (size_t)ip_len, f);
}

static void ring_snapshot_meta(uint32_t *trigger_slot, uint64_t *oldest_ns, uint64_t *newest_ns, uint64_t *span_ns) {
  *trigger_slot = 0u;
  *oldest_ns = *newest_ns = *span_ns = 0u;
  if (!s_ring_mem || s_ring_slots == 0u || s_ring_count == 0u) {
    return;
  }
  uint32_t trig = (s_ring_w + s_ring_slots - 1u) % s_ring_slots;
  *trigger_slot = trig;
  uint64_t min_ts = UINT64_MAX;
  uint64_t max_ts = 0u;
  for (uint32_t i = 0; i < s_ring_count; i++) {
    uint32_t idx = (s_ring_r + i) % s_ring_slots;
    const uint8_t *slot = s_ring_mem + (size_t)idx * (size_t)s_ring_stride;
    uint64_t ts;
    memcpy(&ts, slot, sizeof(ts));
    if (ts < min_ts) {
      min_ts = ts;
    }
    if (ts > max_ts) {
      max_ts = ts;
    }
  }
  if (min_ts != UINT64_MAX) {
    *oldest_ns = min_ts;
    *newest_ns = max_ts;
    if (max_ts >= min_ts) {
      *span_ns = max_ts - min_ts;
    }
  }
}

static void ring_packet_push(const uint8_t *ip_pkt, UINT ip_len, int is_v6) {
  if (!s_ring_mem || s_ring_slots == 0u || !ip_pkt || ip_len == 0u || !s_cfg) {
    return;
  }
  uint32_t maxp = s_cfg->shellcode_detector.forensic_ring_max_packet_bytes;
  uint32_t copy = (uint32_t)ip_len;
  if (copy > maxp) {
    copy = maxp;
  }
  uint64_t ts = edr_win_now_ns();
  uint8_t *slot = s_ring_mem + (size_t)s_ring_w * (size_t)s_ring_stride;
  memcpy(slot, &ts, sizeof(ts));
  memcpy(slot + 8, &copy, 4);
  uint32_t fl = is_v6 ? 1u : 0u;
  memcpy(slot + 12, &fl, 4);
  memcpy(slot + EDR_RING_SLOT_HDR, ip_pkt, copy);
  s_ring_w = (s_ring_w + 1u) % s_ring_slots;
  if (s_ring_count < s_ring_slots) {
    s_ring_count++;
  } else {
    s_ring_r = (s_ring_r + 1u) % s_ring_slots;
  }
}

static int write_ring_pcap(const char *path) {
  if (!s_ring_mem || s_ring_count == 0u) {
    return -1;
  }
  FILE *f = fopen(path, "wb");
  if (!f) {
    return -1;
  }
  pcap_write_global_header(f, EDR_PCAP_LT_EN10MB);
  for (uint32_t i = 0; i < s_ring_count; i++) {
    uint32_t idx = (s_ring_r + i) % s_ring_slots;
    const uint8_t *slot = s_ring_mem + (size_t)idx * (size_t)s_ring_stride;
    uint64_t ts_ns;
    uint32_t slen;
    uint32_t fl;
    memcpy(&ts_ns, slot, sizeof(ts_ns));
    memcpy(&slen, slot + 8, 4);
    memcpy(&fl, slot + 12, 4);
    if (slen == 0u || slen > s_ring_stride - EDR_RING_SLOT_HDR) {
      continue;
    }
    pcap_write_record_en10mb(f, slot + EDR_RING_SLOT_HDR, slen, fl != 0u, ts_ns);
  }
  (void)fclose(f);
  return 0;
}

static int write_single_pcap(const char *path, const uint8_t *ip_pkt, UINT ip_len, int is_ipv6) {
  FILE *f = fopen(path, "wb");
  if (!f) {
    return -1;
  }
  uint32_t lt = is_ipv6 ? EDR_PCAP_LT_IPV6 : EDR_PCAP_LT_IPV4;
  pcap_write_global_header(f, lt);

  FILETIME ftw;
  GetSystemTimeAsFileTime(&ftw);
  ULARGE_INTEGER u;
  u.LowPart = ftw.dwLowDateTime;
  u.HighPart = ftw.dwHighDateTime;
  const uint64_t epoch_100ns = 116444736000000000ULL;
  uint64_t t100ns = u.QuadPart > epoch_100ns ? u.QuadPart - epoch_100ns : 0ULL;
  uint32_t tv_sec = (uint32_t)(t100ns / 10000000ULL);
  uint32_t tv_usec = (uint32_t)((t100ns % 10000000ULL) / 10ULL);
  pcap_write_record_raw_ip(f, ip_pkt, ip_len, tv_sec, tv_usec);
  (void)fclose(f);
  return 0;
}

static char s_wd_filter_dyn[8192];

static int build_windivert_filter_string(const EdrConfig *cfg, char *out, size_t cap) {
  if (!cfg) {
    return -1;
  }
  if (!cfg->shellcode_detector.windivert_ports_is_custom || cfg->shellcode_detector.windivert_tcp_ports_parsed_count == 0u) {
    size_t n = strlen(kWdFilter);
    if (n + 1u > cap) {
      return -1;
    }
    memcpy(out, kWdFilter, n + 1u);
    return 0;
  }
  size_t w = 0;
  int nw = snprintf(out + w, cap - w, "tcp and (");
  if (nw < 0 || (size_t)nw >= cap - w) {
    return -1;
  }
  w += (size_t)nw;
  int first = 1;
  for (size_t i = 0; i < cfg->shellcode_detector.windivert_tcp_ports_parsed_count; i++) {
    uint16_t p = cfg->shellcode_detector.windivert_tcp_ports_parsed[i];
    if (!first) {
      nw = snprintf(out + w, cap - w, " or ");
      if (nw < 0 || (size_t)nw >= cap - w) {
        return -1;
      }
      w += (size_t)nw;
    }
    first = 0;
    nw = snprintf(out + w, cap - w, "tcp.DstPort == %u or tcp.SrcPort == %u", (unsigned)p, (unsigned)p);
    if (nw < 0 || (size_t)nw >= cap - w) {
      return -1;
    }
    w += (size_t)nw;
  }
  nw = snprintf(out + w, cap - w, ")");
  if (nw < 0 || (size_t)nw >= cap - w) {
    return -1;
  }
  return 0;
}

static void log_windivert_service_hint(void) {
  SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
  if (!scm) {
    fprintf(stderr, "[shellcode_detector] OpenSCManager failed err=%lu\n", GetLastError());
    return;
  }
  static const char *names[] = {"WinDivert", "WinDivert1.4"};
  for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
    SC_HANDLE svc = OpenServiceA(scm, names[i], SERVICE_QUERY_STATUS);
    if (!svc) {
      continue;
    }
    SERVICE_STATUS ss;
    if (QueryServiceStatus(svc, &ss)) {
      EDR_LOGV_SHEL("[shellcode_detector] SCM service '%s' state=%lu (RUNNING=4)\n", names[i],
                    (unsigned long)ss.dwCurrentState);
      CloseServiceHandle(svc);
      CloseServiceHandle(scm);
      return;
    }
    CloseServiceHandle(svc);
  }
  EDR_LOGV_SHEL("%s", "[shellcode_detector] no WinDivert service in SCM (driver may still load; WinDivertOpen will "
                      "confirm)\n");
  CloseServiceHandle(scm);
}

static int monitor_allows(const EdrConfig *c, uint16_t dp, uint16_t sp) {
  if (!c) {
    return 0;
  }
  if (c->shellcode_detector.windivert_ports_is_custom && c->shellcode_detector.windivert_tcp_ports_parsed_count > 0u) {
    for (size_t i = 0; i < c->shellcode_detector.windivert_tcp_ports_parsed_count; i++) {
      uint16_t x = c->shellcode_detector.windivert_tcp_ports_parsed[i];
      if (dp == x || sp == x) {
        return 1;
      }
    }
    return 0;
  }
  if ((dp == 445u || dp == 139u || sp == 445u || sp == 139u) && !c->shellcode_detector.monitor_smb) {
    return 0;
  }
  if ((dp == 3389u || sp == 3389u) && !c->shellcode_detector.monitor_rdp) {
    return 0;
  }
  if ((dp == 5985u || dp == 5986u || sp == 5985u || sp == 5986u) && !c->shellcode_detector.monitor_winrm) {
    return 0;
  }
  if ((dp == 135u || sp == 135u) && !c->shellcode_detector.monitor_msrpc) {
    return 0;
  }
  if ((dp == 389u || dp == 636u || dp == 3268u || dp == 3269u || sp == 389u || sp == 636u || sp == 3268u ||
       sp == 3269u) &&
      !c->shellcode_detector.monitor_ldap) {
    return 0;
  }
  return 1;
}

static const char *kind_name(EdrProtoKind k) {
  switch (k) {
    case EDR_PROTO_KIND_SMB2:
      return "smb2";
    case EDR_PROTO_KIND_SMB1:
      return "smb1";
    case EDR_PROTO_KIND_RDP:
      return "rdp";
    case EDR_PROTO_KIND_HTTP:
      return "http";
    default:
      return "raw";
  }
}

static int push_alert(double score, const char *detector_label, const char *rule_name, const char *proto_label,
                      uint16_t dpt, uint16_t spt, const char *src, const char *dst, const uint8_t *evidence,
                      uint32_t evidence_len, const uint8_t *ip_packet, UINT ip_len, int is_v6) {
  if (!s_bus) {
    EDR_LOGV_SHEL("[shellcode_detector] score=%.3f proto=%s %s:%u -> %s:%u (no event bus)\n", score, proto_label, src,
                  (unsigned)spt, dst, (unsigned)dpt);
    return 0;
  }
  int wrote_pcap_ok = 0;
  char forensic_stem[192];
  forensic_stem[0] = '\0';
  unsigned forensic_frames = 0u;
  const char *forensic_kind = "";

  if (s_cfg && s_cfg->shellcode_detector.forensic_save_pcap && s_cfg->shellcode_detector.forensic_dir[0]) {
    mkdir_p_win(s_cfg->shellcode_detector.forensic_dir);
    char pcap_path[1200];
    unsigned long long tsn = (unsigned long long)edr_win_now_ns();
    unsigned long pid = (unsigned long)GetCurrentProcessId();
    if (s_ring_mem && s_cfg->shellcode_detector.forensic_ring_slots > 0u && s_ring_count > 0u) {
      snprintf(pcap_path, sizeof(pcap_path), "%s\\shellcode_ring_%llu_%lu.pcap", s_cfg->shellcode_detector.forensic_dir,
               tsn, pid);
      if (write_ring_pcap(pcap_path) == 0) {
        wrote_pcap_ok = 1;
        forensic_kind = "ring";
        forensic_frames = s_ring_count;
        snprintf(forensic_stem, sizeof(forensic_stem), "shellcode_ring_%llu_%lu", tsn, pid);
        EDR_LOGV_SHEL("[shellcode_detector] wrote ring pcap %s (frames=%u link=EN10MB)\n", pcap_path,
                    (unsigned)s_ring_count);
      }
    } else if (ip_packet && ip_len > 0u) {
      snprintf(pcap_path, sizeof(pcap_path), "%s\\shellcode_%llu_%lu.pcap", s_cfg->shellcode_detector.forensic_dir, tsn,
               pid);
      if (write_single_pcap(pcap_path, ip_packet, ip_len, is_v6) == 0) {
        wrote_pcap_ok = 1;
        forensic_kind = "single";
        snprintf(forensic_stem, sizeof(forensic_stem), "shellcode_%llu_%lu", tsn, pid);
        EDR_LOGV_SHEL("[shellcode_detector] wrote pcap %s\n", pcap_path);
      }
    }
  }

  EdrEventSlot slot;
  memset(&slot, 0, sizeof(slot));
  slot.timestamp_ns = edr_win_now_ns();
  slot.type = EDR_EVENT_PROTOCOL_SHELLCODE;
  slot.consumed = false;
  if (s_cfg && score >= s_cfg->shellcode_detector.auto_isolate_threshold) {
    slot.priority = 0;
  } else {
    slot.priority = 1;
  }

  char wx[EDR_MAX_EVENT_PAYLOAD];
  int base = snprintf(wx, sizeof(wx),
                      "ETW1\nprov=windivert\ndetector=%s\nrule=%s\nscore=%.6f\nproto=%s\ndpt=%u\nspt=%u\nsrc=%s\ndst=%s\n",
                      detector_label ? detector_label : "heuristic", rule_name ? rule_name : "-", score, proto_label,
                      (unsigned)dpt, (unsigned)spt, src, dst);
  if (base < 0 || (size_t)base >= sizeof(wx)) {
    return -1;
  }
  size_t off = (size_t)base;
  if (wrote_pcap_ok && forensic_kind[0]) {
    int fm = snprintf(wx + off, sizeof(wx) - off,
                      "mitre=T1210\nforensic_kind=%s\npcap_stem=%s\n", forensic_kind, forensic_stem[0] ? forensic_stem : "-");
    if (fm > 0 && (size_t)fm < sizeof(wx) - off) {
      off += (size_t)fm;
    }
    if (strcmp(forensic_kind, "ring") == 0 && forensic_frames > 0u) {
      fm = snprintf(wx + off, sizeof(wx) - off, "forensic_frames=%u\n", forensic_frames);
      if (fm > 0 && (size_t)fm < sizeof(wx) - off) {
        off += (size_t)fm;
      }
    }
  }
  char hx[65];
  if (evidence && evidence_len > 0u && sha256_hex_buf(evidence, (size_t)evidence_len, hx) == 0) {
    int m = snprintf(wx + off, sizeof(wx) - off, "sha256=%s\n", hx);
    if (m > 0 && (size_t)m < sizeof(wx) - off) {
      off += (size_t)m;
    }
  }
  uint32_t prev = s_cfg ? s_cfg->shellcode_detector.evidence_preview_bytes : 0u;
  if (prev > 0u && evidence && evidence_len > 0u && off + 32u < sizeof(wx)) {
    uint32_t n = evidence_len;
    if (n > prev) {
      n = prev;
    }
    int m = snprintf(wx + off, sizeof(wx) - off, "preview_hex=");
    if (m > 0 && (size_t)m < sizeof(wx) - off) {
      off += (size_t)m;
    }
    static const char *H = "0123456789abcdef";
    for (uint32_t i = 0; i < n && off + 2u < sizeof(wx); i++) {
      wx[off++] = H[evidence[i] >> 4];
      wx[off++] = H[evidence[i] & 15];
    }
    if (off < sizeof(wx)) {
      wx[off++] = '\n';
    }
  }
  if (s_ring_mem && s_ring_slots > 0u && s_ring_count > 0u) {
    uint32_t trig_slot = 0;
    uint64_t oldest_ns = 0, newest_ns = 0, span_ns = 0;
    ring_snapshot_meta(&trig_slot, &oldest_ns, &newest_ns, &span_ns);
    int rm = snprintf(wx + off, sizeof(wx) - off,
                      "ring_trigger_slot=%u\nring_oldest_ns=%llu\nring_newest_ns=%llu\nring_span_ns=%llu\n",
                      (unsigned)trig_slot, (unsigned long long)oldest_ns, (unsigned long long)newest_ns,
                      (unsigned long long)span_ns);
    if (rm > 0 && (size_t)rm < sizeof(wx) - off) {
      off += (size_t)rm;
    }
  }
  {
    char erule[96];
    char eproto[40];
    snprintf(erule, sizeof(erule), "%s", rule_name ? rule_name : "-");
    snprintf(eproto, sizeof(eproto), "%s", proto_label ? proto_label : "raw");
    for (size_t z = 0; z < sizeof(erule) && erule[z]; z++) {
      if (erule[z] == '"' || erule[z] == '\\' || erule[z] == '\n' || erule[z] == '\r') {
        erule[z] = '_';
      }
    }
    for (size_t z = 0; z < sizeof(eproto) && eproto[z]; z++) {
      if (eproto[z] == '"' || eproto[z] == '\\' || eproto[z] == '\n' || eproto[z] == '\r') {
        eproto[z] = '_';
      }
    }
    const char *det = detector_label ? detector_label : "heuristic";
    int jn = snprintf(wx + off, sizeof(wx) - off,
                      "shellcode_json={\"score\":%.6f,\"dpt\":%u,\"spt\":%u,\"proto\":\"%s\",\"det\":\"%s\","
                      "\"rule\":\"%s\"}\n",
                      score, (unsigned)dpt, (unsigned)spt, eproto, det, erule);
    if (jn > 0 && (size_t)jn < sizeof(wx) - off) {
      off += (size_t)jn;
    }
  }
  if (off >= sizeof(wx)) {
    off = sizeof(wx) - 1u;
  }
  memcpy(slot.data, wx, off);
  slot.size = (uint32_t)off;
  if (!edr_event_bus_try_push(s_bus, &slot)) {
    fprintf(stderr, "[shellcode_detector] event bus full, drop shellcode alert\n");
  }
  if (s_cfg && score >= s_cfg->shellcode_detector.auto_isolate_threshold) {
    edr_isolate_auto_from_shellcode_alarm();
  }
  return 0;
}

static void inspect_tcp_payload(const uint8_t *ip_packet, UINT ip_len, int is_v6_pkt, const uint8_t *pl,
                                uint32_t plen, uint16_t dpt, uint16_t spt, const char *src, const char *dst) {
  if (!s_cfg || plen == 0u) {
    return;
  }
  uint32_t cap = s_cfg->shellcode_detector.max_payload_inspect;
  if (cap == 0u) {
    cap = 16384u;
  }
  uint32_t n = plen;
  if (n > cap) {
    n = cap;
  }
  EdrProtoShellcodeRegion reg;
  EdrProtoParseResult pr = edr_proto_find_shellcode_region(pl, n, &reg);
  const uint8_t *scan = pl;
  uint32_t slen = n;
  char proto_l[32] = "raw";
  if (pr == EDR_PROTO_PARSE_OK && reg.payload_len > 0u) {
    scan = pl + reg.payload_off;
    slen = reg.payload_len;
    snprintf(proto_l, sizeof(proto_l), "%s", kind_name(reg.kind));
  }
  char rule_name[96];
  EdrProtoKind k = (pr == EDR_PROTO_PARSE_OK) ? reg.kind : EDR_PROTO_KIND_UNKNOWN;
  if (edr_shellcode_match_known_exploit(scan, slen, k, rule_name, sizeof(rule_name))) {
    (void)push_alert(1.0, "yara", rule_name, proto_l, dpt, spt, src, dst, scan, slen, ip_packet, ip_len, is_v6_pkt);
    return;
  }
  double sc = edr_shellcode_heuristic_score(scan, slen);
  sc *= s_cfg->shellcode_detector.heuristic_score_scale;
  if (sc > 1.0) {
    sc = 1.0;
  }
  if (sc < s_cfg->shellcode_detector.alert_threshold) {
    return;
  }
  (void)push_alert(sc, "heuristic", "-", proto_l, dpt, spt, src, dst, scan, slen, ip_packet, ip_len, is_v6_pkt);
}

static DWORD WINAPI wd_thread_main(void *arg) {
  (void)arg;
  uint8_t buf[0xFFFF];
  while (InterlockedCompareExchange(&s_capture_stop, 0, 0) == 0) {
    if (s_cfg && s_cfg->shellcode_detector.yara_rules_reload_interval_s > 0u && s_cfg->shellcode_detector.yara_rules_dir[0]) {
      edr_shellcode_known_reload_periodic(s_cfg->shellcode_detector.yara_rules_dir,
                                          s_cfg->shellcode_detector.yara_rules_reload_interval_s);
    }
    WINDIVERT_ADDRESS addr;
    UINT recvlen = 0;
    memset(&addr, 0, sizeof(addr));
    if (!s_recv(s_handle, buf, (UINT)sizeof(buf), &recvlen, &addr)) {
      DWORD e = GetLastError();
      if (e == ERROR_INVALID_HANDLE || InterlockedCompareExchange(&s_capture_stop, 0, 0) != 0) {
        break;
      }
      continue;
    }
    if (recvlen == 0u || !s_cfg) {
      continue;
    }
    WINDIVERT_IPHDR *ip = NULL;
    void *ipv6 = NULL;
    UINT8 proto = 0;
    WINDIVERT_ICMPHDR *ic = NULL;
    WINDIVERT_ICMPV6HDR *ic6 = NULL;
    WINDIVERT_TCPHDR *tcp = NULL;
    WINDIVERT_UDPHDR *udp = NULL;
    PVOID data = NULL;
    UINT datalen = 0;
    PVOID next = NULL;
    UINT nextlen = 0;
    if (!s_parse(buf, recvlen, &ip, (VOID **)&ipv6, &proto, &ic, &ic6, &tcp, &udp, &data, &datalen, &next,
                 &nextlen)) {
      continue;
    }
    if (!tcp || !data || datalen == 0) {
      continue;
    }
    uint16_t sp = tcp->SrcPort;
    uint16_t dp = tcp->DstPort;
    if (!monitor_allows(s_cfg, dp, sp)) {
      continue;
    }
    char src[64], dst[64];
    int is_v6 = 0;
    if (ip) {
      ipv4_ntoa(ip->SrcAddr, src, sizeof(src));
      ipv4_ntoa(ip->DstAddr, dst, sizeof(dst));
    } else if (ipv6) {
      is_v6 = 1;
      (void)ipv6_addrs_to_str((const WINDIVERT_IPV6HDR *)ipv6, src, sizeof(src), dst, sizeof(dst));
    } else {
      continue;
    }
    ring_packet_push(buf, recvlen, is_v6);
    inspect_tcp_payload(buf, recvlen, is_v6, (const uint8_t *)data, (uint32_t)datalen, dp, sp, src, dst);
  }
  return 0;
}

static int load_windivert(void) {
  wchar_t wpath[512];
  if (ExpandEnvironmentStringsW(L"%SystemRoot%\\System32\\WinDivert.dll", wpath,
                                (DWORD)(sizeof(wpath) / sizeof(wpath[0]))) == 0u) {
    return -1;
  }
  s_wd_dll = LoadLibraryW(wpath);
  if (!s_wd_dll) {
    fprintf(stderr, "[shellcode_detector] LoadLibrary WinDivert.dll failed err=%lu (path=%ls)\n", GetLastError(),
            wpath);
    return -1;
  }
#define LOAD(sym, dst, T)                                                                         \
  dst = (T)(void *)GetProcAddress(s_wd_dll, #sym);                                               \
  if (!(dst)) {                                                                                   \
    fprintf(stderr, "[shellcode_detector] GetProcAddress %s failed\n", #sym);                    \
    return -1;                                                                                    \
  }
  LOAD(WinDivertOpen, s_open, PFN_WinDivertOpen);
  LOAD(WinDivertRecv, s_recv, PFN_WinDivertRecv);
  LOAD(WinDivertClose, s_close, PFN_WinDivertClose);
  LOAD(WinDivertSetParam, s_setparam, PFN_WinDivertSetParam);
  LOAD(WinDivertHelperParsePacket, s_parse, PFN_WinDivertHelperParsePacket);
#undef LOAD
  (void)kWdDllPath;
  return 0;
}

EdrError edr_windivert_capture_start(const EdrConfig *cfg, EdrEventBus *bus) {
  s_cfg = cfg;
  s_bus = bus;
  InterlockedExchange(&s_capture_stop, 0);
  if (!cfg || !cfg->shellcode_detector.enabled) {
    return EDR_OK;
  }
  (void)edr_shellcode_known_init(cfg->shellcode_detector.yara_rules_dir);
  if (load_windivert() != 0) {
    fprintf(stderr, "[shellcode_detector] WinDivert 不可用，跳过捕获（安装 DLL/驱动至 System32）\n");
    return EDR_OK;
  }
  log_windivert_service_hint();
  if (!s_wsa_started) {
    WSADATA wd;
    if (WSAStartup(MAKEWORD(2, 2), &wd) == 0) {
      s_wsa_started = 1;
    } else {
      EDR_LOGE("[shellcode_detector] WSAStartup failed (IPv6 地址显示可能异常)\n");
    }
  }
  UINT64 flags = (UINT64)(WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY);
  INT16 pri = (INT16)cfg->shellcode_detector.windivert_priority;
  if (pri > 30000) {
    pri = 30000;
  }
  if (pri < -30000) {
    pri = -30000;
  }
  const char *wd_filter = kWdFilter;
  if (cfg->shellcode_detector.windivert_ports_is_custom && cfg->shellcode_detector.windivert_tcp_ports_parsed_count > 0u) {
    if (build_windivert_filter_string(cfg, s_wd_filter_dyn, sizeof(s_wd_filter_dyn)) != 0) {
      EDR_LOGV_SHEL("%s", "[shellcode_detector] WinDivert 过滤器字符串过长，回退内置端口表\n");
    } else {
      wd_filter = s_wd_filter_dyn;
      EDR_LOGV_SHEL("[shellcode_detector] WinDivert 自定义 TCP 端口数=%zu\n",
                    cfg->shellcode_detector.windivert_tcp_ports_parsed_count);
    }
  }
  s_handle = s_open(wd_filter, (WINDIVERT_LAYER)0, pri, flags);
  if (s_handle == INVALID_HANDLE_VALUE) {
    fprintf(stderr, "[shellcode_detector] WinDivertOpen 失败 err=%lu（常见：非管理员/驱动未装），继续运行但不捕获\n",
            GetLastError());
    if (s_wsa_started) {
      (void)WSACleanup();
      s_wsa_started = 0;
    }
    FreeLibrary(s_wd_dll);
    s_wd_dll = NULL;
    return EDR_OK;
  }
  (void)s_setparam(s_handle, WINDIVERT_PARAM_QUEUE_LENGTH, 8192ull);
  (void)s_setparam(s_handle, WINDIVERT_PARAM_QUEUE_SIZE, 8ull * 1024ull * 1024ull);
  (void)s_setparam(s_handle, WINDIVERT_PARAM_QUEUE_TIME, 2000ull);

  if (cfg->shellcode_detector.forensic_save_pcap && cfg->shellcode_detector.forensic_ring_slots > 0u) {
    uint32_t slots = cfg->shellcode_detector.forensic_ring_slots;
    uint32_t maxp = cfg->shellcode_detector.forensic_ring_max_packet_bytes;
    s_ring_stride = EDR_RING_SLOT_HDR + maxp;
    size_t need = (size_t)slots * (size_t)s_ring_stride;
    s_ring_mem = (uint8_t *)calloc(1, need);
    if (!s_ring_mem) {
      EDR_LOGE("[shellcode_detector] ring buffer alloc failed (need %zu bytes), ring disabled\n", need);
    } else {
      s_ring_slots = slots;
      s_ring_w = 0;
      s_ring_r = 0;
      s_ring_count = 0;
      EDR_LOGV_SHEL("[shellcode_detector] ring buffer: slots=%u max_pkt=%u (~%zu KiB)\n", slots, maxp,
                    (need + 1023u) / 1024u);
    }
  }

  s_thread = CreateThread(NULL, 0, wd_thread_main, NULL, 0, NULL);
  if (!s_thread) {
    s_close(s_handle);
    s_handle = INVALID_HANDLE_VALUE;
    if (s_wsa_started) {
      (void)WSACleanup();
      s_wsa_started = 0;
    }
    FreeLibrary(s_wd_dll);
    s_wd_dll = NULL;
    return EDR_ERR_INTERNAL;
  }
  EDR_LOGV_SHEL("%s", "[shellcode_detector] WinDivert 捕获线程已启动（SNIFF+RECV_ONLY）\n");
  return EDR_OK;
}

void edr_windivert_capture_stop(void) {
  InterlockedExchange(&s_capture_stop, 1);
  if (s_ring_mem) {
    free(s_ring_mem);
    s_ring_mem = NULL;
    s_ring_slots = 0;
    s_ring_stride = 0;
    s_ring_w = s_ring_r = s_ring_count = 0;
  }
  if (s_handle != INVALID_HANDLE_VALUE && s_close) {
    s_close(s_handle);
    s_handle = INVALID_HANDLE_VALUE;
  }
  if (s_thread) {
    WaitForSingleObject(s_thread, 15000);
    CloseHandle(s_thread);
    s_thread = NULL;
  }
  if (s_wd_dll) {
    FreeLibrary(s_wd_dll);
    s_wd_dll = NULL;
  }
  s_open = NULL;
  s_recv = NULL;
  s_close = NULL;
  s_setparam = NULL;
  s_parse = NULL;
  edr_shellcode_known_shutdown();
  s_cfg = NULL;
  s_bus = NULL;
  if (s_wsa_started) {
    (void)WSACleanup();
    s_wsa_started = 0;
  }
  InterlockedExchange(&s_capture_stop, 0);
}
