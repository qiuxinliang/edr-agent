#include "edr/pid_history_pmfe.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/** 与 `EdrBehaviorRecord.pmfe_snapshot` 同宽，避免中间缓冲与槽位不一致 */
#define PMFE_PID_JSON_BYTES (sizeof(((EdrBehaviorRecord *)0)->pmfe_snapshot))

#ifdef _WIN32
#include <windows.h>
#else
#include <pthread.h>
#include <sys/time.h>
#endif

#define EDR_PID_PMFE_SLOTS 512

typedef struct {
  uint32_t pid;
  uint64_t last_ns;
  char json[PMFE_PID_JSON_BYTES];
  int valid;
} PmfePidSlot;

static PmfePidSlot s_slots[EDR_PID_PMFE_SLOTS];
static int s_ph_ready;

#ifdef _WIN32
static CRITICAL_SECTION s_mu;
#else
static pthread_mutex_t s_mu = PTHREAD_MUTEX_INITIALIZER;
#endif

static void lock(void) {
#ifdef _WIN32
  if (s_ph_ready) {
    EnterCriticalSection(&s_mu);
  }
#else
  pthread_mutex_lock(&s_mu);
#endif
}

static void unlock(void) {
#ifdef _WIN32
  if (s_ph_ready) {
    LeaveCriticalSection(&s_mu);
  }
#else
  pthread_mutex_unlock(&s_mu);
#endif
}

static uint64_t wall_ns(void) {
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

static unsigned detail_u(const char *d, const char *key) {
  const char *p = strstr(d, key);
  if (!p) {
    return 0u;
  }
  p += strlen(key);
  return (unsigned)strtoul(p, NULL, 10);
}

static int detail_i(const char *d, const char *key) {
  const char *p = strstr(d, key);
  if (!p) {
    return 0;
  }
  p += strlen(key);
  return (int)strtol(p, NULL, 10);
}

static float detail_f(const char *d, const char *key) {
  const char *p = strstr(d, key);
  if (!p) {
    return 0.f;
  }
  p += strlen(key);
  return strtof(p, NULL);
}

static void detail_token(const char *d, const char *key, char *out, size_t cap) {
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

static void json_escape_short(const char *in, char *out, size_t cap) {
  size_t j = 0;
  for (size_t i = 0; in[i] && j + 2 < cap; i++) {
    char c = in[i];
    if (c == '"' || c == '\\') {
      continue;
    }
    if ((unsigned char)c < 0x20) {
      continue;
    }
    out[j++] = c;
  }
  out[j] = '\0';
}

void edr_pid_history_pmfe_init(void) {
  if (s_ph_ready) {
    return;
  }
#ifdef _WIN32
  InitializeCriticalSection(&s_mu);
#endif
  memset(s_slots, 0, sizeof(s_slots));
  s_ph_ready = 1;
}

void edr_pid_history_pmfe_shutdown(void) {
  if (!s_ph_ready) {
    return;
  }
  lock();
  memset(s_slots, 0, sizeof(s_slots));
  unlock();
#ifdef _WIN32
  DeleteCriticalSection(&s_mu);
#endif
  s_ph_ready = 0;
}

void edr_pid_history_pmfe_ingest_scan_detail(uint32_t pid, const char *detail) {
  const char *e = getenv("EDR_PMFE_PID_HISTORY");
  if (e && e[0] == '0') {
    return;
  }
  if (!s_ph_ready || pid == 0u || !detail || !detail[0]) {
    return;
  }
  if (strstr(detail, "open_process=failed")) {
    return;
  }
  if (strstr(detail, "maps_open_failed")) {
    return;
  }

  unsigned stomp = detail_u(detail, "stomp_suspicious=");
  unsigned dns = detail_u(detail, "dns_ascii_hits=") + detail_u(detail, "dns_utf16_hits=") +
                 detail_u(detail, "dns_wire_hits=");
  int mz = detail_i(detail, "mz_hits=");
  int elf = detail_i(detail, "elf_hits=");
  float ave = detail_f(detail, "ave_max_score=");
  float dns_best = detail_f(detail, "dns_best=");
  char sample[140];
  char owner[140];
  detail_token(detail, "dns_sample=", sample, sizeof(sample));
  detail_token(detail, "dns_owner=", owner, sizeof(owner));
  char esample[160];
  char eowner[160];
  json_escape_short(sample, esample, sizeof(esample));
  json_escape_short(owner, eowner, sizeof(eowner));

  uint64_t now = wall_ns();
  lock();
  int idx = -1;
  int empty = -1;
  int oldest = -1;
  uint64_t oldest_t = UINT64_MAX;
  for (int i = 0; i < EDR_PID_PMFE_SLOTS; i++) {
    if (s_slots[i].valid && s_slots[i].pid == pid) {
      idx = i;
      break;
    }
    if (!s_slots[i].valid && empty < 0) {
      empty = i;
    }
    if (s_slots[i].valid && s_slots[i].last_ns < oldest_t) {
      oldest_t = s_slots[i].last_ns;
      oldest = i;
    }
  }
  if (idx < 0) {
    idx = empty >= 0 ? empty : oldest;
  }
  if (idx >= 0) {
    s_slots[idx].valid = 1;
    s_slots[idx].pid = pid;
    s_slots[idx].last_ns = now;
    (void)snprintf(
        s_slots[idx].json, sizeof(s_slots[idx].json),
        "{\"stomp\":%u,\"dns\":%u,\"mz\":%d,\"elf\":%d,\"ave\":%.4f,\"dns_best\":%.4f,\"sample\":\"%.120s\","
        "\"owner\":\"%.120s\"}",
        stomp, dns, mz, elf, (double)ave, (double)dns_best, esample, eowner);
  }
  unlock();
}

void edr_pid_history_pmfe_fill_record(EdrBehaviorRecord *br) {
  const char *e = getenv("EDR_PMFE_PID_HISTORY");
  if (e && e[0] == '0') {
    return;
  }
  if (!s_ph_ready || !br || br->pid == 0u) {
    return;
  }
  br->pmfe_snapshot[0] = '\0';
  lock();
  for (int i = 0; i < EDR_PID_PMFE_SLOTS; i++) {
    if (s_slots[i].valid && s_slots[i].pid == br->pid) {
      snprintf(br->pmfe_snapshot, sizeof(br->pmfe_snapshot), "%s", s_slots[i].json);
      break;
    }
  }
  unlock();
}
