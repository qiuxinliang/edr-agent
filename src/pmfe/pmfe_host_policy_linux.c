/* §21 PMFE（Linux）：`ss -ltnp` 监听聚合 + `/proc` 有效用户 + 关键进程名 — 对齐 §2.2.4（无 Windows 服务规则） */

#include "edr/pmfe.h"
#include "edr/edr_log.h"

#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdint.h>
#include <sys/wait.h>
#include <unistd.h>

#define PMFE_LISTEN_CAP 512
#define PMFE_PORTS_PER_PID 64

typedef struct {
  uint32_t pid;
  uint16_t ports[PMFE_PORTS_PER_PID];
  uint8_t nports;
  uint8_t has_external;
  uint8_t has_inaddr_any;
  uint8_t has_privileged;
} PmfeListenAgg;

static PmfeListenAgg s_agg[PMFE_LISTEN_CAP];
static int s_nagg;
static pthread_mutex_t s_listen_mu = PTHREAD_MUTEX_INITIALIZER;

/* —— 以下解析逻辑与 `attack_surface_report.c` 中 `collect_listeners_linux` 同源（避免链接 static 符号）—— */

static void trim_crlf(char *s) {
  size_t n = strlen(s);
  while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r')) {
    s[--n] = 0;
  }
}

static const char *skip_ws(const char *p) {
  while (*p == ' ' || *p == '\t') {
    p++;
  }
  return p;
}

static const char *next_tok_end(const char *p) {
  while (*p && *p != ' ' && *p != '\t') {
    p++;
  }
  return p;
}

static const char *skip_fields(const char *p, int n) {
  p = skip_ws(p);
  for (int i = 0; i < n; i++) {
    p = next_tok_end(p);
    p = skip_ws(p);
    if (!*p) {
      return p;
    }
  }
  return p;
}

static int parse_local_addr(const char *tok, char *bind_out, size_t bind_cap, int *port_out) {
  const char *colon = strrchr(tok, ':');
  if (!colon || colon == tok) {
    return -1;
  }
  if (tok[0] == '[') {
    const char *br = strchr(tok + 1, ']');
    if (!br || br >= colon) {
      return -1;
    }
    size_t n = (size_t)(br - (tok + 1));
    if (n >= bind_cap) {
      n = bind_cap - 1u;
    }
    memcpy(bind_out, tok + 1, n);
    bind_out[n] = 0;
  } else {
    size_t n = (size_t)(colon - tok);
    if (n >= bind_cap) {
      n = bind_cap - 1u;
    }
    memcpy(bind_out, tok, n);
    bind_out[n] = 0;
  }
  return sscanf(colon + 1, "%d", port_out) == 1 ? 0 : -1;
}

static void scope_for_bind(const char *bind, char *scope, size_t cap) {
  if (!bind[0]) {
    snprintf(scope, cap, "lan");
    return;
  }
  if (strcmp(bind, "127.0.0.1") == 0 || strcmp(bind, "::1") == 0) {
    snprintf(scope, cap, "loopback");
    return;
  }
  if (strcmp(bind, "0.0.0.0") == 0 || strcmp(bind, "*") == 0 || strcmp(bind, "::") == 0 || strcmp(bind, "[::]") == 0) {
    snprintf(scope, cap, "public");
    return;
  }
  snprintf(scope, cap, "lan");
}

static int parse_pid_users(const char *proc, int *pid_out) {
  const char *p = strstr(proc, "pid=");
  if (!p) {
    *pid_out = -1;
    return -1;
  }
  return sscanf(p + 4, "%d", pid_out) == 1 ? 0 : -1;
}

static PmfeListenAgg *pmfe_find_or_add_agg(uint32_t pid) {
  for (int i = 0; i < s_nagg; i++) {
    if (s_agg[i].pid == pid) {
      return &s_agg[i];
    }
  }
  if (s_nagg >= PMFE_LISTEN_CAP) {
    return NULL;
  }
  PmfeListenAgg *a = &s_agg[s_nagg++];
  memset(a, 0, sizeof(*a));
  a->pid = pid;
  return a;
}

static void pmfe_linux_agg_note(PmfeListenAgg *a, const char *bind, int port) {
  if (port <= 0 || port > 65535) {
    return;
  }
  uint16_t p16 = (uint16_t)port;
  if (a->nports < PMFE_PORTS_PER_PID) {
    a->ports[a->nports++] = p16;
  }
  if (p16 < 1024u) {
    a->has_privileged = 1u;
  }
  if (strcmp(bind, "0.0.0.0") == 0 || strcmp(bind, "::") == 0 || strcmp(bind, "*") == 0 || strcmp(bind, "[::]") == 0) {
    a->has_inaddr_any = 1u;
    a->has_external = 1u;
  } else {
    char scope[40];
    scope_for_bind(bind, scope, sizeof(scope));
    if (strcmp(scope, "loopback") != 0) {
      a->has_external = 1u;
    }
  }
}

static FILE *open_ss_ltnp_reader(pid_t *child_out) {
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
    execlp("ss", "ss", "-ltnp", (char *)NULL);
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

void edr_pmfe_listen_table_refresh(void) {
  pid_t child = -1;
  FILE *pf = open_ss_ltnp_reader(&child);
  if (!pf) {
    return;
  }
  char line[2048];
  int truncated = 0;
  pthread_mutex_lock(&s_listen_mu);
  s_nagg = 0;
  memset(s_agg, 0, sizeof(s_agg));
  while (fgets(line, sizeof(line), pf)) {
    trim_crlf(line);
    if (strstr(line, "LISTEN") == NULL) {
      continue;
    }
    const char *p;
    if (line[0] == 't' || line[0] == 'u') {
      p = skip_fields(line, 4);
    } else {
      p = skip_fields(line, 3);
    }
    if (!*p) {
      continue;
    }
    char local[256];
    const char *e = next_tok_end(p);
    size_t ln = (size_t)(e - p);
    if (ln >= sizeof(local)) {
      ln = sizeof(local) - 1u;
    }
    memcpy(local, p, ln);
    local[ln] = 0;
    p = skip_ws(e);
    char proc[512];
    proc[0] = 0;
    if (*p) {
      snprintf(proc, sizeof(proc), "%s", p);
    }
    char bind[256];
    int port = 0;
    if (parse_local_addr(local, bind, sizeof(bind), &port) != 0) {
      continue;
    }
    int pid_i = -1;
    if (parse_pid_users(proc, &pid_i) != 0 || pid_i <= 0) {
      continue;
    }
    uint32_t pid_u = (uint32_t)pid_i;
    PmfeListenAgg *a = pmfe_find_or_add_agg(pid_u);
    if (!a) {
      truncated = 1;
      break;
    }
    pmfe_linux_agg_note(a, bind, port);
  }
  pthread_mutex_unlock(&s_listen_mu);
  (void)fclose(pf);
  if (child > 0) {
    (void)waitpid(child, NULL, 0);
  }
  if (truncated) {
    const char *q = getenv("EDR_PMFE_LISTEN_TRUNC_QUIET");
    if (!q || q[0] != '1') {
      EDR_LOGE("[pmfe][listen] linux agg truncated (cap=%d), priority table may miss listeners\n", PMFE_LISTEN_CAP);
    }
  }
}

static const PmfeListenAgg *pmfe_listen_lookup_locked(uint32_t pid) {
  for (int i = 0; i < s_nagg; i++) {
    if (s_agg[i].pid == pid) {
      return &s_agg[i];
    }
  }
  return NULL;
}

static int pmfe_linux_pid_euid_root(uint32_t pid) {
  char path[64];
  snprintf(path, sizeof(path), "/proc/%u/status", pid);
  FILE *f = fopen(path, "r");
  if (!f) {
    return 0;
  }
  char line[256];
  while (fgets(line, sizeof(line), f)) {
    if (strncmp(line, "Uid:", 4) == 0) {
      unsigned r = 0, e = 0, s = 0, fs = 0;
      if (sscanf(line, "Uid: %u %u %u %u", &r, &e, &s, &fs) >= 2) {
        fclose(f);
        return e == 0u;
      }
    }
  }
  fclose(f);
  return 0;
}

static int pmfe_linux_pid_image_base(uint32_t pid, char *out, size_t out_cap) {
  char path[64];
  char buf[512];
  snprintf(path, sizeof(path), "/proc/%u/exe", pid);
  ssize_t n = readlink(path, buf, sizeof(buf) - 1u);
  if (n > 0) {
    buf[n] = '\0';
    const char *base = buf;
    for (const char *p = buf; *p; p++) {
      if (*p == '/') {
        base = p + 1;
      }
    }
    snprintf(out, out_cap, "%s", base);
    return 0;
  }
  snprintf(path, sizeof(path), "/proc/%u/comm", pid);
  FILE *f = fopen(path, "r");
  if (!f) {
    return -1;
  }
  if (!fgets(buf, sizeof(buf), f)) {
    fclose(f);
    return -1;
  }
  fclose(f);
  trim_crlf(buf);
  if (!buf[0]) {
    return -1;
  }
  snprintf(out, out_cap, "%s", buf);
  return 0;
}

typedef struct {
  const char *name;
  EdrPmfeScanPriority pr;
} PmfeCritProc;

/** Linux 关键进程/服务名（basename），与 Windows 表同档位意图 */
static const PmfeCritProc s_crit[] = {
    {"sshd", EDR_PMFE_PRIO_HIGH},       {"nginx", EDR_PMFE_PRIO_HIGH},
    {"mysqld", EDR_PMFE_PRIO_HIGH},      {"postgres", EDR_PMFE_PRIO_HIGH},
    {"dockerd", EDR_PMFE_PRIO_HIGH},     {"containerd", EDR_PMFE_PRIO_HIGH},
    {"httpd", EDR_PMFE_PRIO_MED},       {"apache2", EDR_PMFE_PRIO_MED},
    {"java", EDR_PMFE_PRIO_MED},        {NULL, EDR_PMFE_PRIO_LOW}};

static EdrPmfeScanPriority pmfe_match_crit(const char *base) {
  for (unsigned i = 0; s_crit[i].name; i++) {
    if (strcasecmp(base, s_crit[i].name) == 0) {
      return s_crit[i].pr;
    }
  }
  return EDR_PMFE_PRIO_LOW;
}

EdrPmfeScanPriority edr_pmfe_compute_priority(uint32_t pid) {
  if (pid == 0u) {
    return EDR_PMFE_PRIO_IGNORE;
  }
  if (pid == (uint32_t)getpid()) {
    return EDR_PMFE_PRIO_IGNORE;
  }

  pthread_mutex_lock(&s_listen_mu);
  const PmfeListenAgg *lp = pmfe_listen_lookup_locked(pid);
  int has_listen = lp && lp->nports > 0;
  uint8_t hex = lp ? lp->has_external : 0u;
  uint8_t h0 = lp ? lp->has_inaddr_any : 0u;
  uint8_t hp = lp ? lp->has_privileged : 0u;
  pthread_mutex_unlock(&s_listen_mu);

  if (has_listen) {
    int sys = pmfe_linux_pid_euid_root(pid);
    if (hex && sys && hp) {
      return EDR_PMFE_PRIO_CRITICAL;
    }
    if (hex && sys) {
      return EDR_PMFE_PRIO_HIGH;
    }
    if (hex && hp) {
      return EDR_PMFE_PRIO_HIGH;
    }
    if (h0) {
      return EDR_PMFE_PRIO_MED;
    }
    if (!hex) {
      return EDR_PMFE_PRIO_LOW;
    }
    return EDR_PMFE_PRIO_MED;
  }

  char base[260];
  if (pmfe_linux_pid_image_base(pid, base, sizeof(base)) == 0) {
    return pmfe_match_crit(base);
  }
  return EDR_PMFE_PRIO_LOW;
}

void edr_pmfe_host_policy_init(void) {}

void edr_pmfe_host_policy_shutdown(void) {}
