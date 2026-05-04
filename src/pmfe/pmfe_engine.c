/* §21 PMFE — 队列 + 双扫描线程；Windows：模块基线 + VAD 粗筛 + PE peek + §6 DNS 路径（ASCII 分块）；Linux：maps 粗筛 + process_vm_readv peek + ELF/熵（§9）+ 可选 DNS ASCII */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "edr/pmfe.h"
#include "edr/pid_history_pmfe.h"

#include "edr/event_bus.h"
#include "edr/types.h"

#if defined(_WIN32) || defined(__linux__)
extern void edr_pmfe_host_policy_init(void);
extern void edr_pmfe_host_policy_shutdown(void);
#endif
#include "edr/ave_sdk.h"
#include "edr/config.h"
#include "edr/edr_log.h"
#include "edr/error.h"
#include "edr/sha256.h"

#if defined(__linux__)
#include "pmfe_linux_scan_util.h"
#endif

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include "edr/pmfe_idle_scanner.h"
#ifdef _WIN32
static const EdrConfig *s_pmfe_cfg;
#endif

void edr_pmfe_bind_config(const EdrConfig *cfg) {
#ifdef _WIN32
  s_pmfe_cfg = cfg;
#else
  (void)cfg;
#endif
}

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#else
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <unistd.h>
#endif

#define PMFE_TASK_CAP 64
#define PMFE_NUM_WORKERS 2

typedef struct {
  uint32_t pid;
  char cmd_id[64];
  uint8_t priority;
  uint8_t band;
  uint8_t force_deep;
  uint8_t full_vad;
  uint8_t module_integrity;
  uint8_t dns_path;
  uint8_t peek_cap;
  /** Windows：`VirtualQueryEx` 精扫窗口中心（用户态 VA）；0 表示未指定（全空间候选逻辑不变）。 */
  uint64_t vad_hint_va;
} EdrPmfeTask;

static EdrPmfeTask s_task_buf[PMFE_TASK_CAP];
static unsigned s_task_head;
static unsigned s_task_tail;
static unsigned s_task_count;

#ifdef _WIN32
static volatile LONG s_stat_submitted;
static volatile LONG s_stat_completed;
static volatile LONG s_stat_dropped;
#else
static volatile unsigned long s_stat_submitted;
static volatile unsigned long s_stat_completed;
static volatile unsigned long s_stat_dropped;
#endif

#ifdef _WIN32
static CRITICAL_SECTION s_q_mu;
static CRITICAL_SECTION s_etw_cd_mu;
static CONDITION_VARIABLE s_q_nonempty;
static CONDITION_VARIABLE s_q_nonfull;
static HANDLE s_workers[PMFE_NUM_WORKERS];
static HANDLE s_listen_thread;
static volatile LONG s_listen_stop; /* 1 = exit listen poller */
static volatile LONG s_shutdown;
static volatile LONG s_inited;
#else
static pthread_mutex_t s_q_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t s_etw_cd_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t s_q_nonempty = PTHREAD_COND_INITIALIZER;
static pthread_cond_t s_q_nonfull = PTHREAD_COND_INITIALIZER;
static pthread_t s_workers[PMFE_NUM_WORKERS];
static int s_shutdown;
static int s_inited;
#if defined(__linux__) && !defined(_WIN32)
static pthread_t s_linux_listen_thread;
static volatile int s_linux_listen_stop;
static volatile uint64_t s_defer_listen_refresh_at_ms_linux;
#endif
#endif

static EdrEventBus *s_pmfe_bus;

#define PMFE_ETW_CD_CAP 16u
static uint32_t s_etw_cd_pid[PMFE_ETW_CD_CAP];
static uint64_t s_etw_cd_ms[PMFE_ETW_CD_CAP];

static void audit_pmfe_line(const char *cmd_id, const char *msg) {
  EDR_LOGV("[pmfe][audit] id=%s %s\n", cmd_id ? cmd_id : "", msg);
  const char *ap = getenv("EDR_CMD_AUDIT_PATH");
  if (!ap || !ap[0]) {
    return;
  }
  FILE *f = fopen(ap, "a");
  if (!f) {
    return;
  }
  time_t t = time(NULL);
#ifdef _WIN32
  struct tm tmst;
  localtime_s(&tmst, &t);
#else
  struct tm tmst;
  localtime_r(&t, &tmst);
#endif
  char ts[40];
  strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S", &tmst);
  fprintf(f, "%s [pmfe] id=%s %s\n", ts, cmd_id ? cmd_id : "", msg);
  fclose(f);
}

#if defined(_WIN32) || defined(__linux__)
static void pmfe_digest_to_hex(const uint8_t d[EDR_SHA256_DIGEST_LEN], char out65[65]) {
  static const char *hx = "0123456789abcdef";
  for (int i = 0; i < 32; i++) {
    out65[i * 2] = hx[d[i] >> 4];
    out65[i * 2 + 1] = hx[d[i] & 15];
  }
  out65[64] = '\0';
}

static int pmfe_sha256_file_prefix(const char *path, size_t max_read, char out65[65]) {
  FILE *fp = fopen(path, "rb");
  if (!fp) {
    return -1;
  }
  EdrSha256Ctx ctx;
  edr_sha256_init(&ctx);
  uint8_t buf[65536];
  size_t total = 0;
  for (;;) {
    size_t want = sizeof(buf);
    if (max_read > 0u && total + want > max_read) {
      want = max_read - total;
    }
    if (want == 0u) {
      break;
    }
    size_t nr = fread(buf, 1, want, fp);
    if (nr == 0u) {
      break;
    }
    edr_sha256_update(&ctx, buf, nr);
    total += nr;
    if (nr < want) {
      break;
    }
  }
  fclose(fp);
  if (total == 0u) {
    return -1;
  }
  uint8_t digest[EDR_SHA256_DIGEST_LEN];
  edr_sha256_final(&ctx, digest);
  pmfe_digest_to_hex(digest, out65);
  return 0;
}

static size_t pmfe_read_file_prefix(const char *path, uint8_t *buf, size_t cap) {
  FILE *fp = fopen(path, "rb");
  if (!fp) {
    return 0;
  }
  size_t n = fread(buf, 1, cap, fp);
  fclose(fp);
  return n;
}
#endif /* _WIN32 || __linux__ digest/hash/file prefix */

#ifdef _WIN32
typedef struct {
  unsigned module_count;
  unsigned stomp_suspicious;
  unsigned disk_hash_ok;
  unsigned enum_failed;
  char first_stomp_path[260];
} PmfeBaselineWin;

/** §6.5 / §3：模块区间，用于 DNS 命中地址反查归属 */
typedef struct {
  uint8_t *base;
  SIZE_T size;
  char path[MAX_PATH];
} PmfeModuleRange;

static int pmfe_module_map_build(HANDLE proc, PmfeModuleRange *out, int max, int *count_out) {
  HMODULE mods[512];
  DWORD cb_needed = 0;
  if (!EnumProcessModulesEx(proc, mods, sizeof(mods), &cb_needed, LIST_MODULES_ALL)) {
    if (count_out) {
      *count_out = 0;
    }
    return -1;
  }
  unsigned nmod = cb_needed / (DWORD)sizeof(HMODULE);
  if (nmod > 512u) {
    nmod = 512u;
  }
  int n = 0;
  for (unsigned i = 0; i < nmod && n < max; i++) {
    MODULEINFO mi;
    memset(&mi, 0, sizeof(mi));
    if (!GetModuleInformation(proc, mods[i], &mi, sizeof(mi))) {
      continue;
    }
    uint8_t *base = (uint8_t *)mi.lpBaseOfDll;
    if (!base || mi.SizeOfImage == 0) {
      continue;
    }
    out[n].base = base;
    out[n].size = mi.SizeOfImage;
    if (!GetModuleFileNameExA(proc, mods[i], out[n].path, MAX_PATH)) {
      out[n].path[0] = '\0';
    }
    n++;
  }
  if (count_out) {
    *count_out = n;
  }
  return 0;
}

static void pmfe_owner_for_va(const PmfeModuleRange *mods, int nmod, const void *va, char *out, size_t cap) {
  out[0] = '\0';
  if (!va || !out || cap == 0u) {
    return;
  }
  const uint8_t *p = (const uint8_t *)va;
  for (int i = 0; i < nmod; i++) {
    if (p >= mods[i].base && p < mods[i].base + mods[i].size) {
      const char *bn = mods[i].path;
      for (const char *s = mods[i].path; *s; s++) {
        if (*s == '\\' || *s == '/') {
          bn = s + 1;
        }
      }
      snprintf(out, cap, "%s", bn[0] ? bn : mods[i].path);
      return;
    }
  }
  snprintf(out, cap, "[ANONYMOUS_PRIVATE@%p]", (void *)p);
}

static int pmfe_baseline_windows(HANDLE proc, PmfeBaselineWin *out, int do_integrity) {
  memset(out, 0, sizeof(*out));
  HMODULE mods[512];
  DWORD cb_needed = 0;
  if (!EnumProcessModulesEx(proc, mods, sizeof(mods), &cb_needed, LIST_MODULES_ALL)) {
    out->enum_failed = 1;
    return -1;
  }
  unsigned nmod = cb_needed / (DWORD)sizeof(HMODULE);
  if (nmod > 512u) {
    nmod = 512u;
  }
  out->module_count = nmod;
  if (!do_integrity) {
    return 0;
  }

  size_t cmp_bytes = 64u;
  const char *ev = getenv("EDR_PMFE_STOMP_BYTES");
  if (ev && ev[0]) {
    unsigned long v = strtoul(ev, NULL, 10);
    if (v >= 16u && v <= 4096u) {
      cmp_bytes = (size_t)v;
    }
  }

  size_t max_hash = (size_t)256 * 1024u;
  const char *mh = getenv("EDR_PMFE_DISK_HASH_MAX");
  if (mh && mh[0]) {
    unsigned long v = strtoul(mh, NULL, 10);
    if (v >= 4096ul && v <= 16ul * 1024ul * 1024ul) {
      max_hash = (size_t)v;
    }
  }

  for (unsigned i = 0; i < nmod; i++) {
    MODULEINFO mi;
    memset(&mi, 0, sizeof(mi));
    if (!GetModuleInformation(proc, mods[i], &mi, sizeof(mi))) {
      continue;
    }
    char modpath[MAX_PATH];
    if (!GetModuleFileNameExA(proc, mods[i], modpath, (DWORD)sizeof(modpath))) {
      modpath[0] = '\0';
    }
    uint8_t *base = (uint8_t *)mi.lpBaseOfDll;
    if (!base || mi.SizeOfImage == 0) {
      continue;
    }

    uint8_t mem_head[4096];
    SIZE_T br = 0;
    size_t want_read = cmp_bytes;
    if (want_read > sizeof(mem_head)) {
      want_read = sizeof(mem_head);
    }
    if (!ReadProcessMemory(proc, base, mem_head, want_read, &br) || br < 2u) {
      continue;
    }

    uint8_t disk_head[4096];
    size_t dr = 0;
    if (modpath[0]) {
      dr = pmfe_read_file_prefix(modpath, disk_head, want_read);
    }
    if (dr >= 2u && mem_head[0] == 'M' && mem_head[1] == 'Z' && disk_head[0] == 'M' && disk_head[1] == 'Z') {
      size_t cmp = br < dr ? br : dr;
      if (cmp > want_read) {
        cmp = want_read;
      }
      if (memcmp(mem_head, disk_head, cmp) != 0) {
        out->stomp_suspicious++;
        if (!out->first_stomp_path[0]) {
          snprintf(out->first_stomp_path, sizeof(out->first_stomp_path), "%s", modpath);
        }
      }
    }

    if (modpath[0]) {
      char hex65[65];
      if (pmfe_sha256_file_prefix(modpath, max_hash, hex65) == 0) {
        (void)hex65;
        out->disk_hash_ok++;
      }
    }
  }
  return 0;
}

static int pmfe_coarse_vad_windows_handle(HANDLE h, unsigned *regions_out, unsigned *candidates_out) {
  unsigned regions = 0;
  unsigned candidates = 0;
  uint8_t *addr = (uint8_t *)(uintptr_t)0x10000u;
  MEMORY_BASIC_INFORMATION mbi;
  while (VirtualQueryEx(h, addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
    regions++;
    if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_GUARD) == 0 &&
        (mbi.Protect & PAGE_NOACCESS) == 0) {
      int exec = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                                 PAGE_EXECUTE_WRITECOPY)) != 0;
      if (mbi.Type == MEM_PRIVATE && exec) {
        candidates++;
      }
    }
    uint8_t *next = (uint8_t *)mbi.BaseAddress + mbi.RegionSize;
    if (next <= addr) {
      break;
    }
    addr = next;
  }
  *regions_out = regions;
  *candidates_out = candidates;
  return 0;
}

typedef struct {
  uint8_t *base;
  SIZE_T size;
  DWORD protect;
  DWORD type;
  float score;
} PmfeVadCand;

/** 任意长度字节串 Shannon 熵（DNS 等短串亦可用） */
static float pmfe_shannon_entropy_bytes(const uint8_t *b, size_t n) {
  if (n == 0u) {
    return 0.f;
  }
  unsigned long c[256];
  for (int i = 0; i < 256; i++) {
    c[i] = 0;
  }
  for (size_t i = 0; i < n; i++) {
    c[(unsigned)b[i]]++;
  }
  float ent = 0.f;
  float nf = (float)n;
  for (int i = 0; i < 256; i++) {
    if (!c[i]) {
      continue;
    }
    float p = (float)c[i] / nf;
    ent -= p * (logf(p) / logf(2.f));
  }
  return ent;
}

static float pmfe_shannon_bits(const uint8_t *b, size_t n) {
  if (n < 32u) {
    return 0.f;
  }
  return pmfe_shannon_entropy_bytes(b, n);
}

static float pmfe_win_vad_score(const MEMORY_BASIC_INFORMATION *m) {
  if (m->State != MEM_COMMIT) {
    return 0.f;
  }
  if (m->Protect & PAGE_GUARD || m->Protect & PAGE_NOACCESS) {
    return 0.f;
  }
  int ex = (m->Protect &
            (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
  float s = 0.f;
  if (m->Type == MEM_PRIVATE && ex) {
    s += 60.f;
  }
  if (m->Protect == PAGE_EXECUTE_READWRITE || m->Protect == PAGE_EXECUTE_WRITECOPY) {
    s += 25.f;
  }
  if (m->Type == MEM_PRIVATE && !ex && m->RegionSize >= 4096u && m->RegionSize <= 256ull * 1024u * 1024u) {
    s += 15.f;
  }
  return s;
}

static int pmfe_vad_cand_cmp(const void *a, const void *b) {
  const PmfeVadCand *x = (const PmfeVadCand *)a;
  const PmfeVadCand *y = (const PmfeVadCand *)b;
  if (x->score > y->score) {
    return -1;
  }
  if (x->score < y->score) {
    return 1;
  }
  return 0;
}

/** §6.3：ASCII 域名字符 [a-zA-Z0-9.-] */
static int pmfe_ascii_domain_byte(uint8_t c) {
  if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '.') {
    return 1;
  }
  return 0;
}

static int pmfe_tld_is_known(const char *tld, size_t tld_len) {
  if (tld_len < 2u || tld_len > 24u) {
    return 0;
  }
  static const char *const k[] = {"com",  "net",   "org",  "edu",    "gov",  "mil",  "int",  "cn",   "io",
                                  "co",   "uk",    "de",   "jp",     "ru",   "fr",   "au",   "in",   "br",
                                  "info", "biz",   "name", "mobi",   "app",  "dev",  "xyz",  "top",  "site",
                                  "online", "tech", "cloud", "arpa", "local", "internal", NULL};
  char tmp[32];
  if (tld_len >= sizeof(tmp)) {
    return 0;
  }
  for (size_t i = 0; i < tld_len; i++) {
    char c = tld[i];
    if (c >= 'A' && c <= 'Z') {
      c = (char)(c - 'A' + 'a');
    }
    tmp[i] = c;
  }
  tmp[tld_len] = '\0';
  for (unsigned i = 0; k[i]; i++) {
    if (strcmp(tmp, k[i]) == 0) {
      return 1;
    }
  }
  return 0;
}

static int pmfe_domain_has_known_tld(const char *s, size_t len) {
  size_t i = len;
  while (i > 0u && s[i - 1] != '.') {
    i--;
  }
  if (i == 0u || i == len) {
    return 0;
  }
  return pmfe_tld_is_known(s + i, len - i);
}

/** §6.4 简化版 suspicion_score（无 TIP / 工具特征），阈值与设计一致 ≥0.30 */
static float pmfe_dns_score_ascii_domain(const char *s, size_t len) {
  if (len < 4u || len > 253u) {
    return 0.f;
  }
  float score = 0.f;
  float ent = pmfe_shannon_entropy_bytes((const uint8_t *)s, len);
  if (ent > 4.5f) {
    score += 0.30f;
  }
  if (ent > 5.5f) {
    score += 0.20f;
  }
  const char *dot = strchr(s, '.');
  if (dot) {
    size_t first = (size_t)(dot - s);
    if (first > 40u) {
      score += 0.25f;
    }
    if (first > 60u) {
      score += 0.15f;
    }
  }
  if (score > 1.f) {
    score = 1.f;
  }
  return score;
}

static void pmfe_scan_dns_ascii_in_buf(const uint8_t *buf, size_t len, unsigned *hits, float *best_score,
                                       char *best_dom, size_t best_cap, char *best_owner, size_t owner_cap,
                                       const PmfeModuleRange *mods, int nmod, uint8_t *region_base,
                                       SIZE_T region_off) {
  size_t i = 0;
  while (i < len) {
    if (!pmfe_ascii_domain_byte(buf[i])) {
      i++;
      continue;
    }
    size_t start = i;
    while (i < len && pmfe_ascii_domain_byte(buf[i])) {
      i++;
    }
    size_t dlen = i - start;
    if (dlen < 4u || dlen > 253u) {
      continue;
    }
    char tmp[256];
    if (dlen >= sizeof(tmp)) {
      continue;
    }
    memcpy(tmp, buf + start, dlen);
    tmp[dlen] = '\0';
    if (strchr(tmp, '.') == NULL) {
      continue;
    }
    if (!pmfe_domain_has_known_tld(tmp, dlen)) {
      continue;
    }
    float sc = pmfe_dns_score_ascii_domain(tmp, dlen);
    if (sc < 0.30f) {
      continue;
    }
    (*hits)++;
    if (sc > *best_score) {
      *best_score = sc;
      snprintf(best_dom, best_cap, "%s", tmp);
      if (best_owner && owner_cap > 0u) {
        void *hit_va = (void *)(region_base + region_off + start);
        pmfe_owner_for_va(mods, nmod, hit_va, best_owner, owner_cap);
      }
    }
  }
}

/**
 * RFC 1035 QNAME 解码（支持压缩指针）；成功返回 0。
 */
static int pmfe_decode_dns_qname(const uint8_t *buf, size_t len, size_t start, char *out, size_t out_cap) {
  size_t pos = start;
  size_t o = 0;
  int first = 1;
  unsigned jumps = 0;
  while (jumps < 64u) {
    if (pos >= len) {
      return -1;
    }
    uint8_t lab = buf[pos];
    if (lab == 0) {
      if (o == 0u) {
        return -1;
      }
      out[o] = '\0';
      return 0;
    }
    if ((lab & 0xC0u) == 0xC0u) {
      if (pos + 1u >= len) {
        return -1;
      }
      uint16_t ptr = (((uint16_t)(lab & 0x3Fu)) << 8) | (uint16_t)buf[pos + 1u];
      if ((size_t)ptr >= len) {
        return -1;
      }
      pos = (size_t)ptr;
      if (o > 0u) {
        first = 0;
      }
      jumps++;
      continue;
    }
    if (lab > 63u) {
      return -1;
    }
    if (pos + 1u + (size_t)lab > len) {
      return -1;
    }
    if (!first) {
      if (o + 1u >= out_cap) {
        return -1;
      }
      out[o++] = '.';
    }
    first = 0;
    for (uint8_t k = 0; k < lab; k++) {
      char c = (char)buf[pos + 1u + k];
      if (c < 0x21 || c > 0x7e || c == ' ') {
        return -1;
      }
      if (o + 1u >= out_cap) {
        return -1;
      }
      out[o++] = c;
    }
    pos += 1u + (size_t)lab;
  }
  return -1;
}

/** §6.3：DNS Wire（UDP 报文形态，大端头 + QNAME） */
static void pmfe_scan_dns_wire_in_buf(const uint8_t *buf, size_t len, unsigned *hits, float *best_score,
                                      char *best_dom, size_t best_cap, char *best_owner, size_t owner_cap,
                                      const PmfeModuleRange *mods, int nmod, uint8_t *region_base,
                                      SIZE_T region_off) {
  if (len < 16u) {
    return;
  }
  for (size_t i = 0; i + 12u <= len; i++) {
    uint16_t flags = ((uint16_t)buf[i + 2u] << 8) | (uint16_t)buf[i + 3u];
    uint16_t qdcount = ((uint16_t)buf[i + 4u] << 8) | (uint16_t)buf[i + 5u];
    uint16_t ancount = ((uint16_t)buf[i + 6u] << 8) | (uint16_t)buf[i + 7u];

    int is_query =
        ((flags & 0x8000u) == 0) && (qdcount == 1u) && (ancount == 0u) && ((flags & 0x7800u) <= 0x0800u);
    int is_response = ((flags & 0x8000u) != 0) && (qdcount <= 4u) && (ancount >= 1u && ancount <= 16u);

    if (!is_query && !is_response) {
      continue;
    }

    size_t qname_start = i + 12u;
    if (qname_start >= len) {
      continue;
    }

    char qname[256];
    if (pmfe_decode_dns_qname(buf, len, qname_start, qname, sizeof(qname)) != 0) {
      continue;
    }
    size_t qlen = strlen(qname);
    if (qlen < 4u || qlen > 253u) {
      continue;
    }
    if (strchr(qname, '.') == NULL) {
      continue;
    }
    if (!pmfe_domain_has_known_tld(qname, qlen)) {
      continue;
    }

    float sc = pmfe_dns_score_ascii_domain(qname, qlen);
    if (sc < 0.50f) {
      sc = 0.50f;
    }

    (*hits)++;
    if (sc > *best_score) {
      *best_score = sc;
      snprintf(best_dom, best_cap, "%s", qname);
      if (best_owner && owner_cap > 0u) {
        void *hit_va = (void *)(region_base + region_off + i);
        pmfe_owner_for_va(mods, nmod, hit_va, best_owner, owner_cap);
      }
    }
  }
}

/** §6.3：UTF-16LE 宽字符域名（DnsQueryW 等路径） */
static void pmfe_scan_dns_utf16_in_buf(const uint8_t *buf, size_t len, unsigned *hits, float *best_score,
                                       char *best_dom, size_t best_cap, char *best_owner, size_t owner_cap,
                                       const PmfeModuleRange *mods, int nmod, uint8_t *region_base,
                                       SIZE_T region_off) {
  size_t bi = 0;
  while (bi + 8u <= len) {
    if (bi % 2u != 0u) {
      bi++;
      continue;
    }
    if (buf[bi + 1u] != 0) {
      bi += 2u;
      continue;
    }
    if (!pmfe_ascii_domain_byte(buf[bi])) {
      bi += 2u;
      continue;
    }
    size_t start = bi;
    size_t j = bi;
    while (j + 1u < len && buf[j + 1u] == 0 && pmfe_ascii_domain_byte(buf[j])) {
      j += 2u;
    }
    size_t wchar_count = (j - start) / 2u;
    if (wchar_count < 4u || wchar_count > 253u) {
      bi = j;
      continue;
    }
    char tmp[256];
    if (wchar_count >= sizeof(tmp)) {
      bi = j;
      continue;
    }
    for (size_t w = 0; w < wchar_count; w++) {
      tmp[w] = buf[start + w * 2u];
    }
    tmp[wchar_count] = '\0';
    if (strchr(tmp, '.') == NULL) {
      bi = j;
      continue;
    }
    if (!pmfe_domain_has_known_tld(tmp, wchar_count)) {
      bi = j;
      continue;
    }
    float sc = pmfe_dns_score_ascii_domain(tmp, wchar_count);
    if (sc < 0.30f) {
      bi = j;
      continue;
    }
    (*hits)++;
    if (sc > *best_score) {
      *best_score = sc;
      snprintf(best_dom, best_cap, "%s", tmp);
      if (best_owner && owner_cap > 0u) {
        void *hit_va = (void *)(region_base + region_off + start);
        pmfe_owner_for_va(mods, nmod, hit_va, best_owner, owner_cap);
      }
    }
    bi = j;
  }
}

static void pmfe_dns_region_scan(HANDLE proc, uint8_t *base, SIZE_T region_size, unsigned *ascii_hits,
                                 unsigned *utf16_hits, unsigned *wire_hits, float *best_score, char *best_dom,
                                 size_t best_dom_cap, char *best_owner, size_t owner_cap,
                                 const PmfeModuleRange *mods, int nmod) {
  const SIZE_T CHUNK = 65536;
  SIZE_T max_region = (SIZE_T)256 * 1024u;
  const char *ev = getenv("EDR_PMFE_DNS_MAX_REGION");
  if (ev && ev[0]) {
    unsigned long v = strtoul(ev, NULL, 10);
    if (v >= 4096ul && v <= 16ul * 1024ul * 1024ul) {
      max_region = (SIZE_T)v;
    }
  }
  SIZE_T cap = region_size < max_region ? region_size : max_region;
  uint8_t *chunk_buf = (uint8_t *)malloc(CHUNK);
  if (!chunk_buf) {
    return;
  }
  const char *u16 = getenv("EDR_PMFE_DNS_UTF16");
  int do_u16 = !(u16 && u16[0] == '0');
  const char *wir = getenv("EDR_PMFE_DNS_WIRE");
  int do_wire = !(wir && wir[0] == '0');
  for (SIZE_T off = 0; off < cap; off += CHUNK) {
    SIZE_T to_read = cap - off;
    if (to_read > CHUNK) {
      to_read = CHUNK;
    }
    SIZE_T br = 0;
    if (!ReadProcessMemory(proc, base + off, chunk_buf, to_read, &br) || br < 4u) {
      continue;
    }
    pmfe_scan_dns_ascii_in_buf(chunk_buf, (size_t)br, ascii_hits, best_score, best_dom, best_dom_cap, best_owner,
                               owner_cap, mods, nmod, base, off);
    if (do_u16) {
      pmfe_scan_dns_utf16_in_buf(chunk_buf, (size_t)br, utf16_hits, best_score, best_dom, best_dom_cap, best_owner,
                                 owner_cap, mods, nmod, base, off);
    }
    if (do_wire) {
      pmfe_scan_dns_wire_in_buf(chunk_buf, (size_t)br, wire_hits, best_score, best_dom, best_dom_cap, best_owner,
                                owner_cap, mods, nmod, base, off);
    }
  }
  free(chunk_buf);
}

/** `full_vad=0` 且提供 hint 时，仅保留与该 VA 窗口相交的 VAD 候选（设计 §2.2.5「hint 周围」）。 */
#define PMFE_VAD_HINT_RADIUS (64ull * 1024ull * 1024ull)

static int pmfe_vad_region_in_hint_window(uint8_t *base, SIZE_T sz, uint64_t hint_va, int use_focus) {
  if (!use_focus || hint_va == 0ull) {
    return 1;
  }
  uint64_t lo = hint_va > PMFE_VAD_HINT_RADIUS ? hint_va - PMFE_VAD_HINT_RADIUS : 0ull;
  uint64_t hi = hint_va + PMFE_VAD_HINT_RADIUS;
  uintptr_t b = (uintptr_t)base;
  uintptr_t e = b + (uintptr_t)sz;
  if (e <= (uintptr_t)lo || b >= (uintptr_t)hi) {
    return 0;
  }
  return 1;
}

static void pmfe_win_vad_deep_scan(HANDLE proc, uint32_t pid, unsigned peek_cap_req, int full_vad, int dns_path,
                                   uint64_t vad_hint_va, char *extra, size_t extra_cap) {
  extra[0] = '\0';
  const char *peek_ev = getenv("EDR_PMFE_VAD_PEEK");
  int peek_n = (int)peek_cap_req;
  if (peek_ev && peek_ev[0]) {
    int v = atoi(peek_ev);
    if (v >= 0 && v <= 64) {
      peek_n = (peek_n > v) ? v : peek_n;
    }
  }
  if (peek_n <= 0) {
    return;
  }

  const int pool_max = full_vad ? 64 : 16;
  const unsigned max_vad_steps = full_vad ? 200000u : 4000u;
  const int use_hint_focus = (vad_hint_va != 0ull && !full_vad);

#define PMFE_VAD_POOL 64
  PmfeVadCand pool[PMFE_VAD_POOL];
  int np = 0;
  uint8_t *addr = (uint8_t *)(uintptr_t)0x10000u;
  MEMORY_BASIC_INFORMATION mbi;
  unsigned steps = 0;
  while (VirtualQueryEx(proc, addr, &mbi, sizeof(mbi)) == sizeof(mbi) && steps < max_vad_steps) {
    steps++;
    float sc = pmfe_win_vad_score(&mbi);
    if (sc >= 20.f && np < pool_max && np < PMFE_VAD_POOL) {
      uint8_t *rb = (uint8_t *)mbi.BaseAddress;
      if (!pmfe_vad_region_in_hint_window(rb, mbi.RegionSize, vad_hint_va, use_hint_focus)) {
        uint8_t *next = (uint8_t *)mbi.BaseAddress + mbi.RegionSize;
        if (next <= addr) {
          break;
        }
        addr = next;
        continue;
      }
      pool[np].base = rb;
      pool[np].size = mbi.RegionSize;
      pool[np].protect = mbi.Protect;
      pool[np].type = mbi.Type;
      pool[np].score = sc;
      np++;
    }
    uint8_t *next = (uint8_t *)mbi.BaseAddress + mbi.RegionSize;
    if (next <= addr) {
      break;
    }
    addr = next;
  }
  if (np == 0 && use_hint_focus && vad_hint_va != 0ull) {
    if (VirtualQueryEx(proc, (void *)(uintptr_t)vad_hint_va, &mbi, sizeof(mbi)) == sizeof(mbi) &&
        mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_GUARD) == 0 && (mbi.Protect & PAGE_NOACCESS) == 0) {
      pool[0].base = (uint8_t *)mbi.BaseAddress;
      pool[0].size = mbi.RegionSize;
      pool[0].protect = mbi.Protect;
      pool[0].type = mbi.Type;
      pool[0].score = 1000.f;
      np = 1;
    }
  }
  if (np == 0) {
    return;
  }
  qsort(pool, (size_t)np, sizeof(PmfeVadCand), pmfe_vad_cand_cmp);
  if (peek_n > np) {
    peek_n = np;
  }

  int mz = 0;
  float ent_max = 0.f;
  int ave_probes = 0;
  float ave_max_score = 0.f;
  const char *ave_tmp = getenv("EDR_PMFE_AVE_TEMPFILE");
  int do_ave = (ave_tmp && ave_tmp[0] == '1' && s_pmfe_cfg);

  for (int i = 0; i < peek_n; i++) {
    uint8_t buf[512];
    SIZE_T to_read = pool[i].size < sizeof(buf) ? pool[i].size : sizeof(buf);
    if (to_read == 0u) {
      continue;
    }
    SIZE_T br = 0;
    if (!ReadProcessMemory(proc, pool[i].base, buf, to_read, &br) || br < 2u) {
      continue;
    }
    float ent = pmfe_shannon_bits(buf, (size_t)br);
    if (ent > ent_max) {
      ent_max = ent;
    }
    if (buf[0] == 'M' && buf[1] == 'Z') {
      mz++;
    }
    if (do_ave && buf[0] == 'M' && buf[1] == 'Z' && ave_probes < 3) {
      char td[MAX_PATH];
      char tp[MAX_PATH + 80];
      DWORD tdl = GetTempPathA((DWORD)sizeof(td), td);
      if (tdl == 0u || tdl >= sizeof(td)) {
        snprintf(td, sizeof(td), ".\\");
      }
      snprintf(tp, sizeof(tp), "%sedr_pmfe_%u_%llx.bin", td, pid, (unsigned long long)(uintptr_t)pool[i].base);
      FILE *wf = fopen(tp, "wb");
      if (wf) {
        size_t wr = fwrite(buf, 1, (size_t)br, wf);
        fclose(wf);
        if (wr == (size_t)br) {
          AVEScanResult avr;
          memset(&avr, 0, sizeof(avr));
          int ar = AVE_ScanFile(tp, &avr);
          (void)remove(tp);
          ave_probes++;
          if (ar == AVE_OK && avr.final_confidence > ave_max_score) {
            ave_max_score = avr.final_confidence;
          }
        }
      }
    }
  }

  unsigned dns_ascii_hits = 0;
  unsigned dns_utf16_hits = 0;
  unsigned dns_wire_hits = 0;
  float dns_best_score = 0.f;
  char dns_sample[200];
  char dns_owner[200];
  dns_sample[0] = '\0';
  dns_owner[0] = '\0';
  const char *dns_dis = getenv("EDR_PMFE_DNS_DISABLED");
  if (dns_path && !(dns_dis && dns_dis[0] == '1')) {
    PmfeModuleRange modmap[512];
    int nmod = 0;
    (void)pmfe_module_map_build(proc, modmap, 512, &nmod);
    for (int i = 0; i < peek_n; i++) {
      pmfe_dns_region_scan(proc, pool[i].base, pool[i].size, &dns_ascii_hits, &dns_utf16_hits, &dns_wire_hits,
                           &dns_best_score, dns_sample, sizeof(dns_sample), dns_owner, sizeof(dns_owner), modmap,
                           nmod);
    }
  }

  if (dns_path && !(dns_dis && dns_dis[0] == '1')) {
    snprintf(extra, extra_cap,
             "vad_peek=%d mz_hits=%d ent_max=%.2f ave_probes=%d ave_max_score=%.3f full_vad=%d | "
             "dns_ascii_hits=%u dns_utf16_hits=%u dns_wire_hits=%u dns_best=%.2f dns_sample=%.80s dns_owner=%.80s",
             peek_n, mz, (double)ent_max, ave_probes, (double)ave_max_score, full_vad ? 1 : 0, dns_ascii_hits,
             dns_utf16_hits, dns_wire_hits, (double)dns_best_score, dns_sample[0] ? dns_sample : "-",
             dns_owner[0] ? dns_owner : "-");
  } else {
    snprintf(extra, extra_cap, "vad_peek=%d mz_hits=%d ent_max=%.2f ave_probes=%d ave_max_score=%.3f full_vad=%d", peek_n, mz,
             (double)ent_max, ave_probes, (double)ave_max_score, full_vad ? 1 : 0);
  }
#undef PMFE_VAD_POOL
}

static int pmfe_scan_windows(const EdrPmfeTask *task, char *detail, size_t detail_cap) {
  uint32_t pid = task->pid;
  int do_mod = task->module_integrity != 0u;
  unsigned peek_cap = task->peek_cap == 0u ? 4u : (unsigned)task->peek_cap;
  int full_vad = task->full_vad != 0u;
  HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, (DWORD)pid);
  if (!h) {
    snprintf(detail, detail_cap, "pid=%u open_process=failed err=%lu", pid, (unsigned long)GetLastError());
    return -1;
  }
  PmfeBaselineWin bm;
  (void)pmfe_baseline_windows(h, &bm, do_mod);
  unsigned regions = 0, cand = 0;
  (void)pmfe_coarse_vad_windows_handle(h, &regions, &cand);
  char vad_extra[896];
  pmfe_win_vad_deep_scan(h, pid, peek_cap, full_vad, task->dns_path != 0u ? 1 : 0, task->vad_hint_va, vad_extra,
                         sizeof(vad_extra));
  CloseHandle(h);

  char vh[28];
  if (task->vad_hint_va != 0ull) {
    snprintf(vh, sizeof(vh), "0x%llx", (unsigned long long)task->vad_hint_va);
  } else {
    snprintf(vh, sizeof(vh), "-");
  }

  if (bm.enum_failed) {
    snprintf(detail, detail_cap,
             "pid=%u prio=%u band=%u baseline=enum_failed regions=%u private_exec=%u vad_hint=%s%s%s", pid,
             (unsigned)task->priority, (unsigned)task->band, regions, cand, vh, vad_extra[0] ? " | " : "",
             vad_extra[0] ? vad_extra : "");
  } else {
    const char *stomp_path = bm.first_stomp_path[0] ? bm.first_stomp_path : "-";
    snprintf(detail, detail_cap,
             "pid=%u prio=%u band=%u baseline_mods=%u stomp_suspicious=%u disk_hash_ok=%u regions=%u private_exec=%u "
             "first_stomp=%.200s vad_hint=%s%s%s",
             pid, (unsigned)task->priority, (unsigned)task->band, bm.module_count, bm.stomp_suspicious, bm.disk_hash_ok,
             regions, cand, stomp_path, vh, vad_extra[0] ? " | " : "", vad_extra[0] ? vad_extra : "");
  }
  return 0;
}
#elif defined(__linux__)
typedef struct {
  uint64_t lo;
  uint64_t hi;
  float score;
} PmfeLinuxMapCand;

typedef struct {
  char path[512];
  uint64_t lo;
  uint64_t hi;
} PmfeLinuxImod;

static float pmfe_linux_entropy_bytes(const uint8_t *b, size_t n) {
  if (n == 0u) {
    return 0.f;
  }
  unsigned long c[256];
  for (int i = 0; i < 256; i++) {
    c[i] = 0;
  }
  for (size_t i = 0; i < n; i++) {
    c[(unsigned)b[i]]++;
  }
  float ent = 0.f;
  float nf = (float)n;
  for (int i = 0; i < 256; i++) {
    if (!c[i]) {
      continue;
    }
    float p = (float)c[i] / nf;
    ent -= p * (logf(p) / logf(2.f));
  }
  return ent;
}

static int pmfe_linux_ascii_domain_byte(uint8_t ch) {
  if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '.') {
    return 1;
  }
  return 0;
}

static int pmfe_linux_tld_is_known(const char *tld, size_t tld_len) {
  if (tld_len < 2u || tld_len > 24u) {
    return 0;
  }
  static const char *const k[] = {"com",  "net",   "org",  "edu",    "gov",  "mil",  "int",  "cn",   "io",
                                  "co",   "uk",    "de",   "jp",     "ru",   "fr",   "au",   "in",   "br",
                                  "info", "biz",   "name", "mobi",   "app",  "dev",  "xyz",  "top",  "site",
                                  "online", "tech", "cloud", "arpa", "local", "internal", NULL};
  char tmp[32];
  if (tld_len >= sizeof(tmp)) {
    return 0;
  }
  for (size_t i = 0; i < tld_len; i++) {
    char c = tld[i];
    if (c >= 'A' && c <= 'Z') {
      c = (char)(c - 'A' + 'a');
    }
    tmp[i] = c;
  }
  tmp[tld_len] = '\0';
  for (unsigned i = 0; k[i]; i++) {
    if (strcmp(tmp, k[i]) == 0) {
      return 1;
    }
  }
  return 0;
}

static int pmfe_linux_domain_has_known_tld(const char *s, size_t len) {
  size_t i = len;
  while (i > 0u && s[i - 1] != '.') {
    i--;
  }
  if (i == 0u || i == len) {
    return 0;
  }
  return pmfe_linux_tld_is_known(s + i, len - i);
}

static float pmfe_linux_dns_score_ascii_domain(const char *s, size_t len) {
  if (len < 4u || len > 253u) {
    return 0.f;
  }
  float score = 0.f;
  float ent = pmfe_linux_entropy_bytes((const uint8_t *)s, len);
  if (ent > 4.5f) {
    score += 0.30f;
  }
  if (ent > 5.5f) {
    score += 0.20f;
  }
  const char *dot = strchr(s, '.');
  if (dot) {
    size_t first = (size_t)(dot - s);
    if (first > 40u) {
      score += 0.25f;
    }
    if (first > 60u) {
      score += 0.15f;
    }
  }
  if (score > 1.f) {
    score = 1.f;
  }
  return score;
}

static void pmfe_linux_scan_dns_ascii_buf(const uint8_t *buf, size_t len, unsigned *hits, float *best_score,
                                            char *best_dom, size_t best_cap) {
  size_t i = 0;
  while (i < len) {
    if (!pmfe_linux_ascii_domain_byte(buf[i])) {
      i++;
      continue;
    }
    size_t start = i;
    while (i < len && pmfe_linux_ascii_domain_byte(buf[i])) {
      i++;
    }
    size_t dlen = i - start;
    if (dlen < 4u || dlen > 253u) {
      continue;
    }
    char tmp[256];
    if (dlen >= sizeof(tmp)) {
      continue;
    }
    memcpy(tmp, buf + start, dlen);
    tmp[dlen] = '\0';
    if (strchr(tmp, '.') == NULL) {
      continue;
    }
    if (!pmfe_linux_domain_has_known_tld(tmp, dlen)) {
      continue;
    }
    float sc = pmfe_linux_dns_score_ascii_domain(tmp, dlen);
    if (sc < 0.30f) {
      continue;
    }
    (*hits)++;
    if (sc > *best_score) {
      *best_score = sc;
      snprintf(best_dom, best_cap, "%s", tmp);
    }
  }
}

#define PMFE_LINUX_MAP_POOL 64
#define PMFE_LINUX_PEEK_BYTES 512u
#define PMFE_LINUX_DNS_CHUNK (64u * 1024u)
#define PMFE_LINUX_DNS_CAP 256u
#define PMFE_LINUX_DNS_CAP_FULL 512u

static int pmfe_linux_map_cand_cmp(const void *a, const void *b) {
  const PmfeLinuxMapCand *x = (const PmfeLinuxMapCand *)a;
  const PmfeLinuxMapCand *y = (const PmfeLinuxMapCand *)b;
  if (x->score > y->score) {
    return -1;
  }
  if (x->score < y->score) {
    return 1;
  }
  return 0;
}

static ssize_t pmfe_linux_read_vm(pid_t pid, uint64_t addr, void *buf, size_t len, unsigned *vm_read_failures) {
  struct iovec local = {.iov_base = buf, .iov_len = len};
  struct iovec remote = {.iov_base = (void *)(uintptr_t)addr, .iov_len = len};
  ssize_t r = process_vm_readv(pid, &local, 1, &remote, 1, 0);
  if (r >= 0) {
    return r;
  }
  char mempath[64];
  snprintf(mempath, sizeof(mempath), "/proc/%d/mem", (int)pid);
  int fd = open(mempath, O_RDONLY);
  if (fd < 0) {
    if (vm_read_failures) {
      (*vm_read_failures)++;
    }
    return -1;
  }
  ssize_t pr = pread(fd, buf, len, (off_t)addr);
  close(fd);
  if (pr < 0) {
    if (vm_read_failures) {
      (*vm_read_failures)++;
    }
    return -1;
  }
  return pr;
}

static void pmfe_linux_dns_scan_region(pid_t pid, uint64_t base, uint64_t region_sz, int full_vad,
                                       unsigned *ascii_hits, float *dns_best, char *dns_sample, size_t dns_sample_cap,
                                       unsigned *vm_read_failures) {
  size_t cap_kb = full_vad ? PMFE_LINUX_DNS_CAP_FULL : PMFE_LINUX_DNS_CAP;
  size_t max_total = cap_kb * 1024u;
  size_t off = 0;
  uint8_t chunk[PMFE_LINUX_DNS_CHUNK];
  while (off < max_total && off < region_sz) {
    size_t want = PMFE_LINUX_DNS_CHUNK;
    if (want > region_sz - off) {
      want = (size_t)(region_sz - off);
    }
    ssize_t r = pmfe_linux_read_vm(pid, base + (uint64_t)off, chunk, want, vm_read_failures);
    if (r <= 0) {
      break;
    }
    pmfe_linux_scan_dns_ascii_buf(chunk, (size_t)r, ascii_hits, dns_best, dns_sample, dns_sample_cap);
    off += (size_t)r;
    if ((size_t)r < want) {
      break;
    }
  }
}

static void pmfe_linux_run_module_integrity(pid_t pid, const PmfeLinuxImod *mods, int nmods, unsigned *stomp_out,
                                            unsigned *disk_ok_out, char *first_stomp, size_t first_cap,
                                            unsigned *vm_read_failures) {
  *stomp_out = 0;
  *disk_ok_out = 0;
  first_stomp[0] = '\0';
  size_t cmp_bytes = 64u;
  const char *ev = getenv("EDR_PMFE_STOMP_BYTES");
  if (ev && ev[0]) {
    unsigned long v = strtoul(ev, NULL, 10);
    if (v >= 16u && v <= 4096u) {
      cmp_bytes = (size_t)v;
    }
  }
  size_t max_hash = (size_t)256 * 1024u;
  const char *mh = getenv("EDR_PMFE_DISK_HASH_MAX");
  if (mh && mh[0]) {
    unsigned long v = strtoul(mh, NULL, 10);
    if (v >= 4096ul && v <= 16ul * 1024ul * 1024ul) {
      max_hash = (size_t)v;
    }
  }

  for (int i = 0; i < nmods; i++) {
    uint64_t lo = mods[i].lo;
    const char *modpath = mods[i].path;
    size_t want_read = cmp_bytes;
    if (want_read > 4096u) {
      want_read = 4096u;
    }
    uint8_t mem_head[4096];
    uint8_t disk_head[4096];
    ssize_t br = pmfe_linux_read_vm(pid, lo, mem_head, want_read, vm_read_failures);
    if (br < 4) {
      continue;
    }
    size_t dr = pmfe_read_file_prefix(modpath, disk_head, want_read);
    int mel = (br >= 4 && (unsigned char)mem_head[0] == 0x7fu && mem_head[1] == 'E' && mem_head[2] == 'L' &&
               mem_head[3] == 'F');
    int del = (dr >= 4u && (unsigned char)disk_head[0] == 0x7fu && disk_head[1] == 'E' && disk_head[2] == 'L' &&
               disk_head[3] == 'F');
    if (mel && del) {
      size_t cmp = (size_t)br < dr ? (size_t)br : dr;
      if (cmp > want_read) {
        cmp = want_read;
      }
      if (memcmp(mem_head, disk_head, cmp) != 0) {
        (*stomp_out)++;
        if (!first_stomp[0]) {
          snprintf(first_stomp, first_cap, "%s", modpath);
        }
      }
    }
    char hex65[65];
    if (pmfe_sha256_file_prefix(modpath, max_hash, hex65) == 0) {
      (void)hex65;
      (*disk_ok_out)++;
    }
  }
}

static int pmfe_scan_linux(const EdrPmfeTask *task, char *detail, size_t detail_cap) {
  uint32_t pid_u = task->pid;
  pid_t pid = (pid_t)pid_u;
  unsigned peek_cap_req = task->peek_cap == 0u ? 4u : (unsigned)task->peek_cap;
  int full_vad = task->full_vad != 0u;
  int dns_path = task->dns_path != 0u;
  int do_integrity = task->module_integrity != 0u;
  const char *anon_env = getenv("EDR_PMFE_LINUX_ANON_EXEC_ONLY");
  int anon_exec_only = (anon_env && anon_env[0] == '1') ? 1 : 0;

  char mpath[64];
  snprintf(mpath, sizeof(mpath), "/proc/%u/maps", pid_u);
  FILE *f = fopen(mpath, "r");
  if (!f) {
    snprintf(detail, detail_cap, "pid=%u maps_open_failed", pid_u);
    return -1;
  }
  unsigned regions = 0u;
  unsigned private_exec = 0u;
  unsigned file_exec_maps = 0u;
  unsigned vm_read_failures = 0u;
  PmfeLinuxMapCand pool[PMFE_LINUX_MAP_POOL];
  int np = 0;
  PmfeLinuxImod imods[64];
  int nimods = 0;
  char line[768];
  while (fgets(line, sizeof(line), f)) {
    regions++;
    uint64_t lo = 0, hi = 0;
    char perms[8];
    char mpathline[512];
    memset(perms, 0, sizeof(perms));
    mpathline[0] = '\0';
    if (edr_pmfe_linux_parse_maps_line(line, &lo, &hi, perms, mpathline, sizeof(mpathline)) != 0) {
      continue;
    }
    if (strlen(perms) >= 4u && perms[2] == 'x' && perms[3] == 'p') {
      private_exec++;
      if (strchr(mpathline, '/') != NULL) {
        file_exec_maps++;
      }
    }
    float sc = edr_pmfe_linux_map_candidate_score(perms, lo, hi, mpathline, anon_exec_only);
    if (sc >= 20.f && np < PMFE_LINUX_MAP_POOL) {
      pool[np].lo = lo;
      pool[np].hi = hi;
      pool[np].score = sc;
      np++;
    }
    if (do_integrity && strlen(perms) >= 4u && perms[2] == 'x' && perms[3] == 'p' && strchr(mpathline, '/') != NULL &&
        nimods < 64) {
      int dup = 0;
      for (int j = 0; j < nimods; j++) {
        if (strcmp(imods[j].path, mpathline) == 0) {
          dup = 1;
          break;
        }
      }
      if (!dup) {
        snprintf(imods[nimods].path, sizeof(imods[nimods].path), "%s", mpathline);
        imods[nimods].lo = lo;
        imods[nimods].hi = hi;
        nimods++;
      }
    }
  }
  fclose(f);

  unsigned stomp = 0u;
  unsigned disk_ok = 0u;
  char first_stomp[260];
  first_stomp[0] = '\0';
  if (do_integrity && nimods > 0) {
    pmfe_linux_run_module_integrity(pid, imods, nimods, &stomp, &disk_ok, first_stomp, sizeof(first_stomp),
                                    &vm_read_failures);
  }

  if (np > 1) {
    qsort(pool, (size_t)np, sizeof(PmfeLinuxMapCand), pmfe_linux_map_cand_cmp);
  }

  int peek_n = (int)peek_cap_req;
  if (peek_n > np) {
    peek_n = np;
  }
  if (peek_n <= 0) {
    peek_n = 0;
  }
  int elf = 0;
  float ent_max = 0.f;
  unsigned dns_ascii_hits = 0u;
  float dns_best_score = 0.f;
  char dns_sample[160];
  dns_sample[0] = '\0';
  const char *dns_dis = getenv("EDR_PMFE_DNS_DISABLED");

  for (int i = 0; i < peek_n; i++) {
    uint8_t buf[PMFE_LINUX_PEEK_BYTES];
    uint64_t base = pool[i].lo;
    size_t want = PMFE_LINUX_PEEK_BYTES;
    uint64_t rsz = pool[i].hi > pool[i].lo ? pool[i].hi - pool[i].lo : 0u;
    if (rsz > 0u && rsz < want) {
      want = (size_t)rsz;
    }
    ssize_t nr = pmfe_linux_read_vm(pid, base, buf, want, &vm_read_failures);
    if (nr <= 0) {
      continue;
    }
    if ((size_t)nr >= 4u && buf[0] == 0x7f && buf[1] == 'E' && buf[2] == 'L' && buf[3] == 'F') {
      elf++;
    }
    if ((size_t)nr >= 32u) {
      float e = pmfe_linux_entropy_bytes(buf, (size_t)nr);
      if (e > ent_max) {
        ent_max = e;
      }
    }
    if (dns_path && !(dns_dis && dns_dis[0] == '1')) {
      pmfe_linux_dns_scan_region(pid, base, rsz, full_vad, &dns_ascii_hits, &dns_best_score, dns_sample,
                                 sizeof(dns_sample), &vm_read_failures);
    }
  }

  unsigned baseline_mods_u = do_integrity ? (unsigned)nimods : file_exec_maps;
  const char *stomp_disp = first_stomp[0] ? first_stomp : "-";

  char extra[720];
  extra[0] = '\0';
  if (dns_path && !(dns_dis && dns_dis[0] == '1')) {
    snprintf(extra, sizeof(extra),
             "maps_peek=%d elf_hits=%d ent_max=%.2f ave_probes=0 ave_max_score=0.000 full_vad=%d vm_read_failures=%u | "
             "dns_ascii_hits=%u dns_utf16_hits=0 dns_wire_hits=0 dns_best=%.2f dns_sample=%.80s dns_owner=-",
             peek_n, elf, (double)ent_max, full_vad ? 1 : 0, vm_read_failures, dns_ascii_hits, (double)dns_best_score,
             dns_sample[0] ? dns_sample : "-");
  } else {
    snprintf(extra, sizeof(extra),
             "maps_peek=%d elf_hits=%d ent_max=%.2f ave_probes=0 ave_max_score=0.000 full_vad=%d vm_read_failures=%u",
             peek_n, elf, (double)ent_max, full_vad ? 1 : 0, vm_read_failures);
  }

  snprintf(detail, detail_cap,
           "pid=%u prio=%u band=%u baseline_mods=%u stomp_suspicious=%u disk_hash_ok=%u regions=%u private_exec=%u "
           "file_exec_maps=%u first_stomp=%.200s | %s",
           pid_u, (unsigned)task->priority, (unsigned)task->band, baseline_mods_u, stomp, disk_ok, regions,
           private_exec, file_exec_maps, stomp_disp, extra);
  return 0;
}

#else
static int pmfe_scan_stub(uint32_t pid, char *detail, size_t detail_cap) {
  (void)pid;
  snprintf(detail, detail_cap, "pid=%u baseline=unsupported_platform", pid);
  return -1;
}
#endif

static int pmfe_run_scan(const EdrPmfeTask *task, char *detail, size_t detail_cap) {
#ifdef _WIN32
  return pmfe_scan_windows(task, detail, detail_cap);
#elif defined(__linux__)
  return pmfe_scan_linux(task, detail, detail_cap);
#else
  return pmfe_scan_stub(task->pid, detail, detail_cap);
#endif
}

void edr_pmfe_set_event_bus(EdrEventBus *bus) { s_pmfe_bus = bus; }

static unsigned pmfe_detail_u(const char *d, const char *key) {
  const char *p = strstr(d, key);
  if (!p) {
    return 0u;
  }
  p += strlen(key);
  return (unsigned)strtoul(p, NULL, 10);
}

static int pmfe_detail_i(const char *d, const char *key) {
  const char *p = strstr(d, key);
  if (!p) {
    return 0;
  }
  p += strlen(key);
  return (int)strtol(p, NULL, 10);
}

static float pmfe_detail_f(const char *d, const char *key) {
  const char *p = strstr(d, key);
  if (!p) {
    return 0.f;
  }
  p += strlen(key);
  return strtof(p, NULL);
}

static void pmfe_detail_copy_token(const char *d, const char *key, char *out, size_t cap) {
  out[0] = '\0';
  const char *p = strstr(d, key);
  if (!p) {
    return;
  }
  p += strlen(key);
  size_t i = 0;
  while (p[i] && p[i] != ' ' && p[i] != '|' && i + 1 < cap) {
    out[i] = p[i];
    i++;
  }
  out[i] = '\0';
  if (strcmp(out, "-") == 0) {
    out[0] = '\0';
  }
}

static uint64_t pmfe_wall_time_ns(void) {
#ifdef _WIN32
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
#else
  struct timeval tv;
  if (gettimeofday(&tv, NULL) != 0) {
    return 0;
  }
  return (uint64_t)tv.tv_sec * 1000000000ULL + (uint64_t)tv.tv_usec * 1000ULL;
#endif
}

static void pmfe_query_target_image(uint32_t pid, char *out, size_t cap) {
  out[0] = '\0';
#ifdef _WIN32
  HANDLE ph = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)pid);
  if (!ph) {
    return;
  }
  wchar_t w[1024];
  DWORD n = 1024u;
  if (QueryFullProcessImageNameW(ph, 0, w, &n)) {
    WideCharToMultiByte(CP_UTF8, 0, w, -1, out, (int)cap, NULL, NULL);
  }
  CloseHandle(ph);
#elif defined(__linux__)
  char path[64];
  snprintf(path, sizeof(path), "/proc/%u/exe", pid);
  ssize_t nr = readlink(path, out, cap - 1u);
  if (nr > 0) {
    out[nr] = '\0';
  }
#else
  (void)pid;
#endif
}

static uint8_t pmfe_emit_priority(unsigned stomp, unsigned dns_hits, float ave_max) {
  if (stomp > 0u || dns_hits > 0u || ave_max >= 0.65f) {
    return 0u;
  }
  return 1u;
}

/**
 * 经 `edr_event_bus_try_push` → 预处理 → `EdrBehaviorRecord` → `edr_event_batch_push` → gRPC（与 ETW 同源）。
 * `EDR_PMFE_EMIT_ALERTS=0` 关闭；`EDR_PMFE_EMIT_MZ=1` 时在无 stomp/dns/ave 信号下仍上报「仅 MZ 命中」类结果。
 * Linux：`elf_hits=` 仅由 `EDR_PMFE_EMIT_ELF=1` 控制上报，与 `EDR_PMFE_EMIT_MZ` 无关。
 */
static void pmfe_try_emit_scan_result(const EdrPmfeTask *task, const char *detail) {
  if (!task || !detail || !detail[0]) {
    return;
  }
  const char *dis = getenv("EDR_PMFE_EMIT_ALERTS");
  if (dis && dis[0] == '0') {
    return;
  }
  if (!s_pmfe_bus) {
    return;
  }
  if (strstr(detail, "open_process=failed")) {
    return;
  }
  if (strstr(detail, "maps_open_failed")) {
    return;
  }
  unsigned stomp = pmfe_detail_u(detail, "stomp_suspicious=");
  unsigned dns_hits = pmfe_detail_u(detail, "dns_ascii_hits=") + pmfe_detail_u(detail, "dns_utf16_hits=") +
                      pmfe_detail_u(detail, "dns_wire_hits=");
  int mz = pmfe_detail_i(detail, "mz_hits=");
  int elf = pmfe_detail_i(detail, "elf_hits=");
  float ave_max = pmfe_detail_f(detail, "ave_max_score=");
  float dns_best = pmfe_detail_f(detail, "dns_best=");
  char dns_sample[256];
  pmfe_detail_copy_token(detail, "dns_sample=", dns_sample, sizeof(dns_sample));

  int want = 0;
  if (stomp > 0u) {
    want = 1;
  }
  if (dns_hits > 0u) {
    want = 1;
  }
  if (ave_max >= 0.5f) {
    want = 1;
  }
  const char *mz_env = getenv("EDR_PMFE_EMIT_MZ");
  const char *elf_env = getenv("EDR_PMFE_EMIT_ELF");
  if (mz >= 1 && mz_env && mz_env[0] == '1') {
    want = 1;
  }
  if (elf >= 1 && elf_env && elf_env[0] == '1') {
    want = 1;
  }
  if (!want) {
    return;
  }

  char img[1024];
  pmfe_query_target_image(task->pid, img, sizeof(img));

  /* 长摘要走 `cmd=` → `cmdline`；`detector`/`score` 仍写入 script_snippet（见 behavior_from_slot 合并逻辑） */
  char cmdline_buf[832];
  size_t dl = strlen(detail);
  if (dl > sizeof(cmdline_buf) - 1u) {
    dl = sizeof(cmdline_buf) - 1u;
  }
  memcpy(cmdline_buf, detail, dl);
  cmdline_buf[dl] = '\0';
  for (size_t i = 0; i < dl; i++) {
    if (cmdline_buf[i] == '\n' || cmdline_buf[i] == '\r') {
      cmdline_buf[i] = ' ';
    }
  }

  float score = 0.f;
  if (stomp > 0u) {
    score = 0.92f;
  }
  if (dns_hits > 0u) {
    float s = 0.55f + 0.08f * (float)dns_hits;
    if (s > score) {
      score = s;
    }
    if (dns_best > score) {
      score = dns_best;
    }
  }
  if (ave_max > score) {
    score = ave_max;
  }
  if (score < 0.35f) {
    score = 0.35f;
  }
  if (score > 1.f) {
    score = 1.f;
  }

  EdrEventSlot slot;
  memset(&slot, 0, sizeof(slot));
  slot.timestamp_ns = pmfe_wall_time_ns();
  slot.type = EDR_EVENT_PMFE_SCAN_RESULT;
  slot.priority = pmfe_emit_priority(stomp, dns_hits, ave_max);
  slot.consumed = false;
  slot.attack_surface_hint = 0u;

  const char *cid = task->cmd_id[0] ? task->cmd_id : "-";
  int n = snprintf((char *)slot.data, sizeof(slot.data),
                   "ETW1\nprov=pmfe\npid=%u\ncmd_id=%.63s\nimg=%s\ncmd=%s\nqname=%s\nscore=%.4f\nmitre=T1055\n"
                   "detector=pmfe\n",
                   task->pid, cid, img[0] ? img : "-", cmdline_buf, dns_sample[0] ? dns_sample : "-", score);
  if (n < 0 || (size_t)n >= sizeof(slot.data)) {
    return;
  }
  slot.size = (uint32_t)n;
  (void)edr_event_bus_try_push(s_pmfe_bus, &slot);
}

static void pmfe_worker_body(void) {
  for (;;) {
    EdrPmfeTask task;
    memset(&task, 0, sizeof(task));
#ifdef _WIN32
    EnterCriticalSection(&s_q_mu);
    while (s_task_count == 0u && !s_shutdown) {
      SleepConditionVariableCS(&s_q_nonempty, &s_q_mu, INFINITE);
    }
    if (s_shutdown && s_task_count == 0u) {
      LeaveCriticalSection(&s_q_mu);
      break;
    }
    task = s_task_buf[s_task_head];
    s_task_head = (s_task_head + 1u) % PMFE_TASK_CAP;
    s_task_count--;
    WakeConditionVariable(&s_q_nonfull);
    LeaveCriticalSection(&s_q_mu);
#else
    pthread_mutex_lock(&s_q_mu);
    while (s_task_count == 0u && !s_shutdown) {
      pthread_cond_wait(&s_q_nonempty, &s_q_mu);
    }
    if (s_shutdown && s_task_count == 0u) {
      pthread_mutex_unlock(&s_q_mu);
      break;
    }
    task = s_task_buf[s_task_head];
    s_task_head = (s_task_head + 1u) % PMFE_TASK_CAP;
    s_task_count--;
    pthread_cond_signal(&s_q_nonfull);
    pthread_mutex_unlock(&s_q_mu);
#endif

    char detail[1024];
    int sr = pmfe_run_scan(&task, detail, sizeof(detail));
    (void)sr;
    if (detail[0] == '\0') {
      snprintf(detail, sizeof(detail), "pid=%u scan_failed", task.pid);
    }
    EDR_LOGV("[pmfe] scan_done %s\n", detail);
    audit_pmfe_line(task.cmd_id[0] ? task.cmd_id : "-", detail);
    edr_pid_history_pmfe_ingest_scan_detail(task.pid, detail);
    pmfe_try_emit_scan_result(&task, detail);

#ifdef _WIN32
    InterlockedIncrement(&s_stat_completed);
#else
    (void)__atomic_add_fetch(&s_stat_completed, 1ul, __ATOMIC_RELAXED);
#endif
  }
}

#ifdef _WIN32
static DWORD WINAPI pmfe_worker_main(void *arg) {
  (void)arg;
  pmfe_worker_body();
  return 0;
}
#else
static void *pmfe_worker_main(void *arg) {
  (void)arg;
  pmfe_worker_body();
  return NULL;
}
#endif

#ifdef _WIN32
static volatile LONG64 s_defer_listen_refresh_at_ms;

void edr_pmfe_on_process_lifecycle_hint(void) {
  const char *dis = getenv("EDR_PMFE_DISABLED");
  if (dis && dis[0] == '1') {
    return;
  }
  const char *e = getenv("EDR_PMFE_LISTEN_REFRESH_ON_PROCESS");
  if (e && e[0] == '0') {
    return;
  }
  uint64_t deadline = GetTickCount64() + 1000ull;
  InterlockedExchange64(&s_defer_listen_refresh_at_ms, (LONG64)deadline);
}

static void pmfe_try_deferred_listen_refresh(void) {
  LONG64 w = s_defer_listen_refresh_at_ms;
  if (w == 0) {
    return;
  }
  uint64_t now = GetTickCount64();
  if (now < (uint64_t)w) {
    return;
  }
  if (InterlockedCompareExchange64(&s_defer_listen_refresh_at_ms, 0, w) != w) {
    return;
  }
  edr_pmfe_listen_table_refresh();
}

static DWORD WINAPI pmfe_listen_poll_main(void *arg) {
  (void)arg;
  InterlockedExchange64(&s_defer_listen_refresh_at_ms, 0);
  for (;;) {
    for (int i = 0; i < 60; i++) {
      if (s_listen_stop) {
        return 0;
      }
      pmfe_try_deferred_listen_refresh();
      Sleep(1000);
    }
    if (s_listen_stop) {
      break;
    }
    edr_pmfe_listen_table_refresh();
    pmfe_idle_scanner_tick();
  }
  return 0;
}
#elif defined(__linux__) && !defined(_WIN32)
static uint64_t pmfe_linux_monotonic_ms(void) {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
    return 0;
  }
  return (uint64_t)ts.tv_sec * 1000ull + (uint64_t)ts.tv_nsec / 1000000ull;
}

static void pmfe_linux_try_deferred_listen_refresh(void) {
  uint64_t w = __atomic_load_n(&s_defer_listen_refresh_at_ms_linux, __ATOMIC_ACQUIRE);
  if (w == 0) {
    return;
  }
  uint64_t now = pmfe_linux_monotonic_ms();
  if (now < w) {
    return;
  }
  uint64_t expected = w;
  if (!__atomic_compare_exchange_n(&s_defer_listen_refresh_at_ms_linux, &expected, 0, 0, __ATOMIC_ACQ_REL,
                                   __ATOMIC_RELAXED)) {
    return;
  }
  edr_pmfe_listen_table_refresh();
}

static void *pmfe_linux_listen_poll_main(void *arg) {
  (void)arg;
  __atomic_store_n(&s_defer_listen_refresh_at_ms_linux, 0, __ATOMIC_RELEASE);
  for (;;) {
    for (int i = 0; i < 60; i++) {
      if (s_linux_listen_stop) {
        return NULL;
      }
      pmfe_linux_try_deferred_listen_refresh();
      sleep(1);
    }
    if (s_linux_listen_stop) {
      break;
    }
    edr_pmfe_listen_table_refresh();
  }
  return NULL;
}

void edr_pmfe_on_process_lifecycle_hint(void) {
  const char *dis = getenv("EDR_PMFE_DISABLED");
  if (dis && dis[0] == '1') {
    return;
  }
  const char *e = getenv("EDR_PMFE_LISTEN_REFRESH_ON_PROCESS");
  if (e && e[0] == '0') {
    return;
  }
  uint64_t deadline = pmfe_linux_monotonic_ms() + 1000ull;
  __atomic_store_n(&s_defer_listen_refresh_at_ms_linux, deadline, __ATOMIC_RELEASE);
}
#else
void edr_pmfe_on_process_lifecycle_hint(void) {}
#endif

EdrError edr_pmfe_init(void) {
  const char *en = getenv("EDR_PMFE_ENABLED");
  if (en && en[0] == '0') {
    EDR_LOGV("%s", "[pmfe] disabled (EDR_PMFE_ENABLED=0)\n");
    return EDR_OK;
  }
  if (en && en[0] != '1') {
    EDR_LOGV("%s", "[pmfe] disabled by default, set EDR_PMFE_ENABLED=1 to enable\n");
    return EDR_OK;
  }
  if (!en) {
    EDR_LOGV("%s", "[pmfe] disabled by default, set EDR_PMFE_ENABLED=1 to enable\n");
    return EDR_OK;
  }
#ifdef _WIN32
  if (InterlockedCompareExchange(&s_inited, 1, 0) != 0) {
    return EDR_OK;
  }
  edr_pmfe_host_policy_init();
  edr_pmfe_listen_table_refresh();
  InterlockedExchange(&s_listen_stop, 0);
  s_listen_thread = CreateThread(NULL, 0, pmfe_listen_poll_main, NULL, 0, NULL);
  if (!s_listen_thread) {
    edr_pmfe_host_policy_shutdown();
    InterlockedExchange(&s_inited, 0);
    return EDR_ERR_INTERNAL;
  }
  InitializeCriticalSection(&s_q_mu);
  InitializeCriticalSection(&s_etw_cd_mu);
  InitializeConditionVariable(&s_q_nonempty);
  InitializeConditionVariable(&s_q_nonfull);
  s_shutdown = 0;
  s_task_head = s_task_tail = s_task_count = 0;
  memset(s_etw_cd_pid, 0, sizeof(s_etw_cd_pid));
  memset(s_etw_cd_ms, 0, sizeof(s_etw_cd_ms));
  for (int i = 0; i < PMFE_NUM_WORKERS; i++) {
    s_workers[i] = CreateThread(NULL, 0, pmfe_worker_main, NULL, 0, NULL);
    if (!s_workers[i]) {
      s_shutdown = 1;
      InterlockedExchange(&s_listen_stop, 1);
      if (s_listen_thread) {
        WaitForSingleObject(s_listen_thread, 120000);
        CloseHandle(s_listen_thread);
        s_listen_thread = NULL;
      }
      edr_pmfe_host_policy_shutdown();
      WakeAllConditionVariable(&s_q_nonempty);
      for (int j = 0; j < i; j++) {
        WaitForSingleObject(s_workers[j], INFINITE);
        CloseHandle(s_workers[j]);
        s_workers[j] = NULL;
      }
      DeleteCriticalSection(&s_etw_cd_mu);
      DeleteCriticalSection(&s_q_mu);
      InterlockedExchange(&s_inited, 0);
      return EDR_ERR_INTERNAL;
    }
  }
#else
  {
    int expected = 0;
    if (!__atomic_compare_exchange_n(&s_inited, &expected, 1, 0, __ATOMIC_ACQ_REL, __ATOMIC_RELAXED)) {
      return EDR_OK;
    }
  }
#if defined(__linux__)
  edr_pmfe_host_policy_init();
  edr_pmfe_listen_table_refresh();
  s_linux_listen_stop = 0;
  __atomic_store_n(&s_defer_listen_refresh_at_ms_linux, 0, __ATOMIC_RELEASE);
  if (pthread_create(&s_linux_listen_thread, NULL, pmfe_linux_listen_poll_main, NULL) != 0) {
    edr_pmfe_host_policy_shutdown();
    __atomic_store_n(&s_inited, 0, __ATOMIC_RELEASE);
    return EDR_ERR_INTERNAL;
  }
#endif
  s_shutdown = 0;
  s_task_head = s_task_tail = s_task_count = 0;
  memset(s_etw_cd_pid, 0, sizeof(s_etw_cd_pid));
  memset(s_etw_cd_ms, 0, sizeof(s_etw_cd_ms));
  for (int i = 0; i < PMFE_NUM_WORKERS; i++) {
    int pr = pthread_create(&s_workers[i], NULL, pmfe_worker_main, NULL);
    if (pr != 0) {
      s_shutdown = 1;
      pthread_cond_broadcast(&s_q_nonempty);
      for (int j = 0; j < i; j++) {
        pthread_join(s_workers[j], NULL);
      }
#if defined(__linux__)
      s_linux_listen_stop = 1;
      pthread_join(s_linux_listen_thread, NULL);
      edr_pmfe_host_policy_shutdown();
#endif
      __atomic_store_n(&s_inited, 0, __ATOMIC_RELEASE);
      (void)pr;
      return EDR_ERR_INTERNAL;
    }
  }
#endif
  edr_pid_history_pmfe_init();
  EDR_LOGV("[pmfe] init workers=%d queue=%d (listen_table: 60s + deferred; Windows/Linux)\n", PMFE_NUM_WORKERS,
           PMFE_TASK_CAP);
  return EDR_OK;
}

void edr_pmfe_shutdown(void) {
#ifdef _WIN32
  if (!s_inited) {
    return;
  }
  EnterCriticalSection(&s_q_mu);
  s_shutdown = 1;
  WakeAllConditionVariable(&s_q_nonempty);
  WakeAllConditionVariable(&s_q_nonfull);
  LeaveCriticalSection(&s_q_mu);
  for (int i = 0; i < PMFE_NUM_WORKERS; i++) {
    if (s_workers[i]) {
      WaitForSingleObject(s_workers[i], INFINITE);
      CloseHandle(s_workers[i]);
      s_workers[i] = NULL;
    }
  }
  InterlockedExchange(&s_listen_stop, 1);
  if (s_listen_thread) {
    WaitForSingleObject(s_listen_thread, 120000);
    CloseHandle(s_listen_thread);
    s_listen_thread = NULL;
  }
  edr_pmfe_host_policy_shutdown();
  DeleteCriticalSection(&s_etw_cd_mu);
  DeleteCriticalSection(&s_q_mu);
  InterlockedExchange(&s_inited, 0);
#else
  if (!__atomic_load_n(&s_inited, __ATOMIC_ACQUIRE)) {
    return;
  }
  pthread_mutex_lock(&s_q_mu);
  s_shutdown = 1;
  pthread_cond_broadcast(&s_q_nonempty);
  pthread_cond_broadcast(&s_q_nonfull);
  pthread_mutex_unlock(&s_q_mu);
  for (int i = 0; i < PMFE_NUM_WORKERS; i++) {
    pthread_join(s_workers[i], NULL);
  }
#if defined(__linux__)
  s_linux_listen_stop = 1;
  pthread_join(s_linux_listen_thread, NULL);
  edr_pmfe_host_policy_shutdown();
#endif
  __atomic_store_n(&s_inited, 0, __ATOMIC_RELEASE);
#endif
#ifdef _WIN32
  EDR_LOGV("[pmfe] shutdown submitted=%ld completed=%ld dropped=%ld\n", (long)s_stat_submitted,
          (long)s_stat_completed, (long)s_stat_dropped);
#else
  EDR_LOGV("[pmfe] shutdown submitted=%lu completed=%lu dropped=%lu\n", (unsigned long)s_stat_submitted,
           (unsigned long)s_stat_completed, (unsigned long)s_stat_dropped);
#endif
  edr_pid_history_pmfe_shutdown();
}

static uint64_t pmfe_now_ms(void) {
#ifdef _WIN32
  return (uint64_t)GetTickCount64();
#else
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
    return 0;
  }
  return (uint64_t)ts.tv_sec * 1000ull + (uint64_t)ts.tv_nsec / 1000000ull;
#endif
}

/** @return 1 允许入队；0 冷却期内跳过 */
static int pmfe_etw_cooldown_pass(uint32_t pid, uint32_t cd_ms) {
  if (cd_ms == 0u) {
    return 1;
  }
  uint64_t now = pmfe_now_ms();
#ifdef _WIN32
  EnterCriticalSection(&s_etw_cd_mu);
#else
  pthread_mutex_lock(&s_etw_cd_mu);
#endif
  int empty_slot = -1;
  for (unsigned i = 0; i < PMFE_ETW_CD_CAP; i++) {
    if (s_etw_cd_pid[i] == 0u) {
      if (empty_slot < 0) {
        empty_slot = (int)i;
      }
      continue;
    }
    if (s_etw_cd_pid[i] == pid) {
      if (now - s_etw_cd_ms[i] < (uint64_t)cd_ms) {
#ifdef _WIN32
        LeaveCriticalSection(&s_etw_cd_mu);
#else
        pthread_mutex_unlock(&s_etw_cd_mu);
#endif
        return 0;
      }
      s_etw_cd_ms[i] = now;
#ifdef _WIN32
      LeaveCriticalSection(&s_etw_cd_mu);
#else
      pthread_mutex_unlock(&s_etw_cd_mu);
#endif
      return 1;
    }
  }
  unsigned slot = empty_slot >= 0 ? (unsigned)empty_slot : (unsigned)(now % PMFE_ETW_CD_CAP);
  s_etw_cd_pid[slot] = pid;
  s_etw_cd_ms[slot] = now;
#ifdef _WIN32
  LeaveCriticalSection(&s_etw_cd_mu);
#else
  pthread_mutex_unlock(&s_etw_cd_mu);
#endif
  return 1;
}

static void pmfe_task_fill_scope(EdrPmfeTask *t) {
  if (t->force_deep) {
    t->full_vad = 1u;
    t->module_integrity = 1u;
    t->dns_path = 0u;
    t->peek_cap = 24u;
    return;
  }
  EdrPmfeScanPriority p = (EdrPmfeScanPriority)t->priority;
  EdrPmfeTriggerBand b = (EdrPmfeTriggerBand)t->band;
  t->dns_path = 0u;
  switch (p) {
  case EDR_PMFE_PRIO_CRITICAL:
    t->full_vad = 1u;
    t->module_integrity = 1u;
    t->dns_path = 1u;
    t->peek_cap = 32u;
    break;
  case EDR_PMFE_PRIO_HIGH:
    t->module_integrity = 1u;
    t->dns_path = 1u;
    t->full_vad = (b <= EDR_PMFE_BAND_P1) ? 1u : 0u;
    t->peek_cap = 16u;
    break;
  case EDR_PMFE_PRIO_MED:
    t->module_integrity = 0u;
    t->dns_path = (b <= EDR_PMFE_BAND_P1) ? 1u : 0u;
    t->full_vad = (b <= EDR_PMFE_BAND_P1) ? 1u : 0u;
    t->peek_cap = 8u;
    break;
  case EDR_PMFE_PRIO_LOW:
  default:
    t->module_integrity = 0u;
    t->dns_path = 0u;
    t->full_vad = 0u;
    t->peek_cap = (b == EDR_PMFE_BAND_P0) ? 4u : 1u;
    break;
  case EDR_PMFE_PRIO_IGNORE:
    t->peek_cap = 0u;
    break;
  }
}

static int pmfe_enqueue_task(const EdrPmfeTask *src) {
  if (!src || src->pid == 0u) {
    return -1;
  }
#ifdef _WIN32
  if (!s_inited) {
    return -1;
  }
  EnterCriticalSection(&s_q_mu);
  while (s_task_count >= PMFE_TASK_CAP && !s_shutdown) {
    SleepConditionVariableCS(&s_q_nonfull, &s_q_mu, 2000);
  }
  if (s_shutdown || s_task_count >= PMFE_TASK_CAP) {
    LeaveCriticalSection(&s_q_mu);
    InterlockedIncrement(&s_stat_dropped);
    return -1;
  }
  s_task_buf[s_task_tail] = *src;
  s_task_tail = (s_task_tail + 1u) % PMFE_TASK_CAP;
  s_task_count++;
  InterlockedIncrement(&s_stat_submitted);
  WakeAllConditionVariable(&s_q_nonempty);
  LeaveCriticalSection(&s_q_mu);
#else
  if (!__atomic_load_n(&s_inited, __ATOMIC_ACQUIRE)) {
    return -1;
  }
  pthread_mutex_lock(&s_q_mu);
  while (s_task_count >= PMFE_TASK_CAP && !s_shutdown) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += 2;
    (void)pthread_cond_timedwait(&s_q_nonfull, &s_q_mu, &ts);
  }
  if (s_shutdown || s_task_count >= PMFE_TASK_CAP) {
    pthread_mutex_unlock(&s_q_mu);
    (void)__atomic_add_fetch(&s_stat_dropped, 1ul, __ATOMIC_RELAXED);
    return -1;
  }
  s_task_buf[s_task_tail] = *src;
  s_task_tail = (s_task_tail + 1u) % PMFE_TASK_CAP;
  s_task_count++;
  (void)__atomic_add_fetch(&s_stat_submitted, 1ul, __ATOMIC_RELAXED);
  pthread_cond_broadcast(&s_q_nonempty);
  pthread_mutex_unlock(&s_q_mu);
#endif
  return 0;
}

int edr_pmfe_submit_server_scan(const char *command_id, uint32_t pid) {
  if (pid == 0u) {
    return -1;
  }
#ifdef _WIN32
  if (!s_inited) {
    return -1;
  }
#else
  if (!__atomic_load_n(&s_inited, __ATOMIC_ACQUIRE)) {
    return -1;
  }
#endif
  EdrPmfeScanPriority pr = edr_pmfe_compute_priority(pid);
  if (pr == EDR_PMFE_PRIO_IGNORE) {
    return -1;
  }
  EdrPmfeTask t;
  memset(&t, 0, sizeof(t));
  t.pid = pid;
  if (command_id && command_id[0]) {
    snprintf(t.cmd_id, sizeof(t.cmd_id), "%s", command_id);
  }
  t.priority = (uint8_t)pr;
  t.band = (uint8_t)EDR_PMFE_BAND_P0;
  t.force_deep = 1u;
  pmfe_task_fill_scope(&t);
  return pmfe_enqueue_task(&t);
}

int edr_pmfe_submit_etw_scan_ex(const char *reason, uint32_t pid, EdrPmfeTriggerBand band, uint64_t vad_hint_va) {
  if (pid == 0u) {
    return -1;
  }
#ifdef _WIN32
  if (!s_inited) {
    return -1;
  }
#else
  if (!__atomic_load_n(&s_inited, __ATOMIC_ACQUIRE)) {
    return -1;
  }
#endif
  uint32_t cd_ms = 30000u;
  const char *e = getenv("EDR_PMFE_ETW_COOLDOWN_MS");
  if (e && e[0]) {
    unsigned long v = strtoul(e, NULL, 10);
    if (v > 0ul && v < 86400000ul) {
      cd_ms = (uint32_t)v;
    }
  }
  if (!pmfe_etw_cooldown_pass(pid, cd_ms)) {
    return 1;
  }
  EdrPmfeScanPriority pr = edr_pmfe_compute_priority(pid);
  if (pr == EDR_PMFE_PRIO_IGNORE) {
    return -1;
  }
  EdrPmfeTask t;
  memset(&t, 0, sizeof(t));
  t.pid = pid;
  {
    const char *r = reason && reason[0] ? reason : "evt";
    snprintf(t.cmd_id, sizeof(t.cmd_id), "etw:%.48s", r);
  }
  t.priority = (uint8_t)pr;
  t.band = (uint8_t)band;
  if ((unsigned)band > (unsigned)EDR_PMFE_BAND_P2) {
    t.band = (uint8_t)EDR_PMFE_BAND_P0;
  }
  t.force_deep = 0u;
  t.vad_hint_va = vad_hint_va;
  pmfe_task_fill_scope(&t);
  return pmfe_enqueue_task(&t);
}

int edr_pmfe_submit_etw_scan(const char *reason, uint32_t pid) {
  return edr_pmfe_submit_etw_scan_ex(reason, pid, EDR_PMFE_BAND_P0, 0ull);
}

void edr_pmfe_get_stats(unsigned long *out_submitted, unsigned long *out_completed, unsigned long *out_dropped) {
#ifdef _WIN32
  if (out_submitted) {
    *out_submitted = (unsigned long)(ULONG_PTR)s_stat_submitted;
  }
  if (out_completed) {
    *out_completed = (unsigned long)(ULONG_PTR)s_stat_completed;
  }
  if (out_dropped) {
    *out_dropped = (unsigned long)(ULONG_PTR)s_stat_dropped;
  }
#else
  if (out_submitted) {
    *out_submitted = s_stat_submitted;
  }
  if (out_completed) {
    *out_completed = s_stat_completed;
  }
  if (out_dropped) {
    *out_dropped = s_stat_dropped;
  }
#endif
}
