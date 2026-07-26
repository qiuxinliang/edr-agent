/* §18.3.5.4 P2：egressTop 采集 */

#include "edr/attack_surface_egress.h"

#include "edr/config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __linux__

#include <sys/wait.h>
#include <unistd.h>

#define EDR_ASURF_EG_BUCKETS 2048

typedef struct {
  char rip[64];
  int rport;
  int pid;
  char proc[160];
  int cnt;
} EgBucket;

static void trim_crlf(char *s) {
  size_t n = strlen(s);
  while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r')) {
    s[--n] = 0;
  }
}

static int parse_host_port(const char *tok, char *host, size_t hc, int *port_out) {
  const char *colon = strrchr(tok, ':');
  if (!colon || colon == tok) {
    return -1;
  }
  size_t hn = (size_t)(colon - tok);
  if (hn >= hc) {
    hn = hc - 1u;
  }
  memcpy(host, tok, hn);
  host[hn] = 0;
  return sscanf(colon + 1, "%d", port_out) == 1 ? 0 : -1;
}

/** 远端为回环（用于 `outbound_exclude_loopback`）：127/8、::1、::ffff:127.x */
static int rip_is_loopback_remote(const char *ip) {
  if (!ip || !ip[0]) {
    return 0;
  }
  if (strcmp(ip, "::1") == 0) {
    return 1;
  }
  if (strncmp(ip, "::ffff:", 7) == 0) {
    return rip_is_loopback_remote(ip + 7);
  }
  int a = 0, b = 0, c = 0, d = 0;
  if (sscanf(ip, "%d.%d.%d.%d", &a, &b, &c, &d) == 4 && a == 127) {
    return 1;
  }
  return 0;
}

static int rip_is_private_or_loopback(const char *ip) {
  if (ip && strchr(ip, ':') != NULL) {
    if (strcmp(ip, "::1") == 0) {
      return 1;
    }
    if (strncmp(ip, "fe80:", 5) == 0 || strncmp(ip, "FE80:", 5) == 0) {
      return 1;
    }
    if ((ip[0] == 'f' || ip[0] == 'F') && (ip[1] == 'c' || ip[1] == 'C')) {
      return 1;
    }
    if ((ip[0] == 'f' || ip[0] == 'F') && (ip[1] == 'd' || ip[1] == 'D')) {
      return 1;
    }
    return 0;
  }
  int a = 0, b = 0, c = 0, d = 0;
  if (sscanf(ip, "%d.%d.%d.%d", &a, &b, &c, &d) != 4) {
    return 0;
  }
  if (a == 127) {
    return 1;
  }
  if (a == 10) {
    return 1;
  }
  if (a == 172 && b >= 16 && b <= 31) {
    return 1;
  }
  if (a == 192 && b == 168) {
    return 1;
  }
  if (a == 169 && b == 254) {
    return 1;
  }
  if (a == 0 && b == 0 && c == 0 && d == 0) {
    return 1;
  }
  return 0;
}

static int is_infra_port(int p) {
  return p == 53 || p == 80 || p == 443 || p == 123 || p == 853;
}

static void proc_from_users(const char *line, char *name, size_t cap) {
  name[0] = 0;
  const char *q = strstr(line, "((\"");
  if (!q) {
    return;
  }
  q += 3;
  const char *end = strchr(q, '"');
  if (!end || end <= q) {
    return;
  }
  size_t n = (size_t)(end - q);
  if (n >= cap) {
    n = cap - 1u;
  }
  memcpy(name, q, n);
  name[n] = 0;
}

static int find_or_add(EgBucket *B, int *nb, const char *rip, int rp, int pid, const char *proc, int *trunc) {
  for (int i = 0; i < *nb; i++) {
    if (B[i].rport == rp && B[i].pid == pid && strcmp(B[i].rip, rip) == 0) {
      return i;
    }
  }
  if (*nb >= EDR_ASURF_EG_BUCKETS) {
    *trunc = 1;
    return -1;
  }
  int j = *nb;
  (*nb)++;
  snprintf(B[j].rip, sizeof(B[j].rip), "%s", rip);
  B[j].rport = rp;
  B[j].pid = pid;
  snprintf(B[j].proc, sizeof(B[j].proc), "%s", proc ? proc : "");
  B[j].cnt = 0;
  return j;
}

static int cmp_bucket_desc(const void *a, const void *b) {
  const EgBucket *x = (const EgBucket *)a;
  const EgBucket *y = (const EgBucket *)b;
  return (y->cnt > x->cnt) - (x->cnt > y->cnt);
}

static FILE *open_ss_established_reader(pid_t *child_out) {
  if (child_out) {
    *child_out = -1;
  }
  int pfd[2];
  if (pipe(pfd) != 0) {
    return NULL;
  }
  pid_t pid = fork();
  if (pid < 0) {
    close(pfd[0]);
    close(pfd[1]);
    return NULL;
  }
  if (pid == 0) {
    close(pfd[0]);
    (void)dup2(pfd[1], STDOUT_FILENO);
    close(pfd[1]);
    execlp("ss", "ss", "-tanp", "state", "established", (char *)NULL);
    _exit(127);
  }
  close(pfd[1]);
  FILE *pf = fdopen(pfd[0], "r");
  if (!pf) {
    close(pfd[0]);
    (void)waitpid(pid, NULL, 0);
    return NULL;
  }
  if (child_out) {
    *child_out = pid;
  }
  return pf;
}

void edr_asurf_collect_egress(const EdrConfig *cfg, EdrAsurfEgressRow *out, int max_out, int *n_out,
                              int *suspicious_conn_total, int *truncated) {
  *n_out = 0;
  *suspicious_conn_total = 0;
  *truncated = 0;
  if (!cfg || !out || max_out <= 0) {
    return;
  }
  int cap = (int)cfg->attack_surface.egress_top_n;
  if (cap > max_out) {
    cap = max_out;
  }
  if (cap < 1) {
    cap = 1;
  }

  EgBucket *B = (EgBucket *)calloc((size_t)EDR_ASURF_EG_BUCKETS, sizeof(EgBucket));
  if (!B) {
    return;
  }
  int nb = 0;

  pid_t child = -1;
  FILE *pf = open_ss_established_reader(&child);
  if (!pf) {
    free(B);
    return;
  }
  char line[2048];
  while (fgets(line, sizeof(line), pf)) {
    trim_crlf(line);
    if (strncmp(line, "ESTAB", 5) != 0 && strncmp(line, "ESTABLISHED", 11) != 0) {
      continue;
    }
    char work[1536];
    const char *u = strstr(line, " users:(");
    if (u) {
      size_t wn = (size_t)(u - line);
      if (wn >= sizeof(work)) {
        wn = sizeof(work) - 1u;
      }
      memcpy(work, line, wn);
      work[wn] = 0;
    } else {
      snprintf(work, sizeof(work), "%s", line);
    }
    char st[16], rq[16], sq[16], loc[192], peer[192];
    if (sscanf(work, "%15s %15s %15s %191s %191s", st, rq, sq, loc, peer) != 5) {
      continue;
    }
    if (strchr(peer, '*') != NULL) {
      continue;
    }
    char rip[64];
    int rp = 0;
    if (parse_host_port(peer, rip, sizeof(rip), &rp) != 0 || rp <= 0) {
      continue;
    }
    if (cfg->attack_surface.outbound_exclude_loopback && rip_is_loopback_remote(rip)) {
      continue;
    }
    int pid = -1;
    const char *pp = strstr(line, "pid=");
    if (pp) {
      (void)sscanf(pp + 4, "%d", &pid);
    }
    char proc[160];
    proc_from_users(line, proc, sizeof(proc));

    if (!rip_is_private_or_loopback(rip) && !is_infra_port(rp)) {
      (*suspicious_conn_total)++;
    }

    int idx = find_or_add(B, &nb, rip, rp, pid, proc, truncated);
    if (idx < 0) {
      continue;
    }
    B[idx].cnt++;
  }
  (void)fclose(pf);
  if (child > 0) {
    (void)waitpid(child, NULL, 0);
  }

  if (nb == 0) {
    free(B);
    return;
  }
  qsort(B, (size_t)nb, sizeof(B[0]), cmp_bucket_desc);

  int emit = nb < cap ? nb : cap;
  if (emit > max_out) {
    emit = max_out;
  }
  for (int i = 0; i < emit; i++) {
    EdrAsurfEgressRow *r = &out[i];
    memset(r, 0, sizeof(*r));
    snprintf(r->remote_ip, sizeof(r->remote_ip), "%s", B[i].rip);
    r->remote_port = B[i].rport;
    r->pid = B[i].pid;
    snprintf(r->proc_name, sizeof(r->proc_name), "%s", B[i].proc);
    r->connection_count = B[i].cnt;
    r->mark_risk = (!rip_is_private_or_loopback(B[i].rip) && !is_infra_port(B[i].rport)) ? 1 : 0;
  }
  *n_out = emit;
  free(B);
}

#elif defined(_WIN32)

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>

#include "edr/attack_surface_win_util.h"

#define EDR_ASURF_EG_BUCKETS 2048

typedef struct {
  char rip[64];
  int rport;
  int pid;
  char proc[160];
  int cnt;
} EgBucket;

static int rip_is_loopback_remote(const char *ip) {
  if (!ip || !ip[0]) {
    return 0;
  }
  if (strcmp(ip, "::1") == 0) {
    return 1;
  }
  if (strncmp(ip, "::ffff:", 7) == 0) {
    return rip_is_loopback_remote(ip + 7);
  }
  int a = 0, b = 0, c = 0, d = 0;
  if (sscanf(ip, "%d.%d.%d.%d", &a, &b, &c, &d) == 4 && a == 127) {
    return 1;
  }
  return 0;
}

static int rip_is_private_or_loopback(const char *ip) {
  if (ip && strchr(ip, ':') != NULL) {
    if (strcmp(ip, "::1") == 0) {
      return 1;
    }
    if (strncmp(ip, "fe80:", 5) == 0 || strncmp(ip, "FE80:", 5) == 0) {
      return 1;
    }
    if ((ip[0] == 'f' || ip[0] == 'F') && (ip[1] == 'c' || ip[1] == 'C')) {
      return 1;
    }
    if ((ip[0] == 'f' || ip[0] == 'F') && (ip[1] == 'd' || ip[1] == 'D')) {
      return 1;
    }
    return 0;
  }
  int a = 0, b = 0, c = 0, d = 0;
  if (sscanf(ip, "%d.%d.%d.%d", &a, &b, &c, &d) != 4) {
    return 0;
  }
  if (a == 127) {
    return 1;
  }
  if (a == 10) {
    return 1;
  }
  if (a == 172 && b >= 16 && b <= 31) {
    return 1;
  }
  if (a == 192 && b == 168) {
    return 1;
  }
  if (a == 169 && b == 254) {
    return 1;
  }
  if (a == 0 && b == 0 && c == 0 && d == 0) {
    return 1;
  }
  return 0;
}

static int is_infra_port(int p) {
  return p == 53 || p == 80 || p == 443 || p == 123 || p == 853;
}

static int find_or_add(EgBucket *B, int *nb, const char *rip, int rp, int pid, const char *proc, int *trunc) {
  for (int i = 0; i < *nb; i++) {
    if (B[i].rport == rp && B[i].pid == pid && strcmp(B[i].rip, rip) == 0) {
      return i;
    }
  }
  if (*nb >= EDR_ASURF_EG_BUCKETS) {
    *trunc = 1;
    return -1;
  }
  int j = *nb;
  (*nb)++;
  snprintf(B[j].rip, sizeof(B[j].rip), "%s", rip);
  B[j].rport = rp;
  B[j].pid = pid;
  snprintf(B[j].proc, sizeof(B[j].proc), "%s", proc ? proc : "");
  B[j].cnt = 0;
  return j;
}

static int cmp_bucket_desc(const void *a, const void *b) {
  const EgBucket *x = (const EgBucket *)a;
  const EgBucket *y = (const EgBucket *)b;
  return (y->cnt > x->cnt) - (x->cnt > y->cnt);
}

void edr_asurf_collect_egress(const EdrConfig *cfg, EdrAsurfEgressRow *out, int max_out, int *n_out,
                              int *suspicious_conn_total, int *truncated) {
  *n_out = 0;
  *suspicious_conn_total = 0;
  *truncated = 0;
  if (!cfg || !out || max_out <= 0) {
    return;
  }
  int cap = (int)cfg->attack_surface.egress_top_n;
  if (cap > max_out) {
    cap = max_out;
  }
  if (cap < 1) {
    cap = 1;
  }

  EgBucket *B = (EgBucket *)calloc((size_t)EDR_ASURF_EG_BUCKETS, sizeof(EgBucket));
  if (!B) {
    return;
  }
  int nb = 0;

  edr_asurf_win_ensure_wsa();

  DWORD sz = 0;
  PMIB_TCPTABLE_OWNER_PID tbl = NULL;
  if (GetExtendedTcpTable(NULL, &sz, FALSE, AF_INET, TCP_TABLE_OWNER_PID_CONNECTIONS, 0) ==
          ERROR_INSUFFICIENT_BUFFER &&
      sz > 0) {
    tbl = (PMIB_TCPTABLE_OWNER_PID)malloc((size_t)sz);
    if (tbl) {
      DWORD req = sz;
      if (GetExtendedTcpTable((PVOID)tbl, &req, FALSE, AF_INET, TCP_TABLE_OWNER_PID_CONNECTIONS, 0) !=
          NO_ERROR) {
        free(tbl);
        tbl = NULL;
      }
    }
  }

  if (tbl) {
    for (DWORD i = 0; i < tbl->dwNumEntries; i++) {
      MIB_TCPROW_OWNER_PID *row = &tbl->table[i];
      /* MIB_TCP_STATE_ESTAB == 5（见 Windows SDK iphlpapi.h） */
      if ((int)row->dwState != 5) {
        continue;
      }
      char rip[64];
      edr_asurf_win_ipv4_to_string(row->dwRemoteAddr, rip, sizeof(rip));
      int rp = (int)ntohs((u_short)row->dwRemotePort);
      if (rp <= 0 || rip[0] == 0) {
        continue;
      }
      if (cfg->attack_surface.outbound_exclude_loopback && rip_is_loopback_remote(rip)) {
        continue;
      }
      int pid = (int)row->dwOwningPid;
      char proc[160];
      edr_asurf_win_pid_exe_name(row->dwOwningPid, proc, sizeof(proc));

      if (!rip_is_private_or_loopback(rip) && !is_infra_port(rp)) {
        (*suspicious_conn_total)++;
      }

      int idx = find_or_add(B, &nb, rip, rp, pid, proc, truncated);
      if (idx < 0) {
        continue;
      }
      B[idx].cnt++;
    }
    free(tbl);
  }

  /* IPv6 ESTABLISHED（与 IPv4 共用聚合桶） */
  sz = 0;
  PMIB_TCP6TABLE_OWNER_PID tbl6 = NULL;
  if (GetExtendedTcpTable(NULL, &sz, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_CONNECTIONS, 0) ==
          ERROR_INSUFFICIENT_BUFFER &&
      sz > 0) {
    tbl6 = (PMIB_TCP6TABLE_OWNER_PID)malloc((size_t)sz);
    if (tbl6) {
      DWORD req6 = sz;
      if (GetExtendedTcpTable((PVOID)tbl6, &req6, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_CONNECTIONS, 0) !=
          NO_ERROR) {
        free(tbl6);
        tbl6 = NULL;
      }
    }
  }
  if (tbl6) {
    for (DWORD i = 0; i < tbl6->dwNumEntries; i++) {
      MIB_TCP6ROW_OWNER_PID *row = &tbl6->table[i];
      if ((int)row->dwState != 5) {
        continue;
      }
      char rip[64];
      edr_asurf_win_ipv6_to_string(row->ucRemoteAddr, rip, sizeof(rip));
      int rp = (int)ntohs((u_short)row->dwRemotePort);
      if (rp <= 0 || rip[0] == 0) {
        continue;
      }
      if (cfg->attack_surface.outbound_exclude_loopback && rip_is_loopback_remote(rip)) {
        continue;
      }
      int pid = (int)row->dwOwningPid;
      char proc[160];
      edr_asurf_win_pid_exe_name(row->dwOwningPid, proc, sizeof(proc));

      if (!rip_is_private_or_loopback(rip) && !is_infra_port(rp)) {
        (*suspicious_conn_total)++;
      }

      int idx = find_or_add(B, &nb, rip, rp, pid, proc, truncated);
      if (idx < 0) {
        continue;
      }
      B[idx].cnt++;
    }
    free(tbl6);
  }

  if (nb == 0) {
    free(B);
    return;
  }
  qsort(B, (size_t)nb, sizeof(B[0]), cmp_bucket_desc);

  int emit = nb < cap ? nb : cap;
  if (emit > max_out) {
    emit = max_out;
  }
  for (int i = 0; i < emit; i++) {
    EdrAsurfEgressRow *r = &out[i];
    memset(r, 0, sizeof(*r));
    snprintf(r->remote_ip, sizeof(r->remote_ip), "%s", B[i].rip);
    r->remote_port = B[i].rport;
    r->pid = B[i].pid;
    snprintf(r->proc_name, sizeof(r->proc_name), "%s", B[i].proc);
    r->connection_count = B[i].cnt;
    r->mark_risk = (!rip_is_private_or_loopback(B[i].rip) && !is_infra_port(B[i].rport)) ? 1 : 0;
  }
  *n_out = emit;
  free(B);
}

#else

void edr_asurf_collect_egress(const EdrConfig *cfg, EdrAsurfEgressRow *out, int max_out, int *n_out,
                              int *suspicious_conn_total, int *truncated) {
  (void)cfg;
  (void)out;
  (void)max_out;
  *n_out = 0;
  *suspicious_conn_total = 0;
  *truncated = 0;
}

#endif
