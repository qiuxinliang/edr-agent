/* §19 攻击面：GET_ATTACK_SURFACE — 轻量采集 + 复用内置 HTTP 传输栈 POST 平台 */

#include "edr/attack_surface_report.h"
#include "edr/attack_surface_egress.h"
#include "edr/attack_surface_inventory.h"
#include "edr/security_policy_collect.h"
#include "edr/ingest_http.h"
#include "cJSON.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <process.h>
#include "edr/attack_surface_win_util.h"
#include "edr/listen_table_win.h"
#define EDR_GETPID() ((int)GetCurrentProcessId())
#else
#include <pthread.h>
#include <sys/wait.h>
#include <unistd.h>
#define EDR_GETPID() ((int)getpid())
#endif

#ifdef _WIN32
/** Windows 临时路径统一转为正斜杠，避免后续文件读取/日志中的反斜杠转义歧义。 */
static void win_path_fwd_slashes(char *p) {
  if (!p) {
    return;
  }
  for (; *p; ++p) {
    if (*p == '\\') {
      *p = '/';
    }
  }
}
#endif

/** 与 `[attack_surface]` 对齐：单次 ss 解析与快照序列化上限 */
#define EDR_ASURF_LISTENERS_MAX 256
#define EDR_ASURF_EGRESS_OUT_MAX 256

typedef struct {
  char bind[160];
  int port;
  char proto[8];
  char scope[20];
  char id[40];
  int pid;
  char proc[160];
} AsListener;

static void json_escape_str(FILE *f, const char *s) {
  fputc('"', f);
  for (; s && *s; s++) {
    unsigned char c = (unsigned char)*s;
    if (c == '"' || c == '\\') {
      fputc('\\', f);
      fputc((int)c, f);
    } else if (c < 32u) {
      fprintf(f, "\\u%04x", (unsigned)c);
    } else {
      fputc((int)c, f);
    }
  }
  fputc('"', f);
}

static void copy_text_file_to_stream(FILE *out, const char *path) {
  FILE *in = fopen(path, "rb");
  if (!in) {
    return;
  }
  char buf[4096];
  for (;;) {
    size_t n = fread(buf, 1u, sizeof(buf), in);
    if (n > 0u) {
      (void)fwrite(buf, 1u, n, out);
    }
    if (n < sizeof(buf)) {
      break;
    }
  }
  fclose(in);
}

#ifdef __linux__
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
  if (strcmp(bind, "0.0.0.0") == 0 || strcmp(bind, "*") == 0 || strcmp(bind, "::") == 0 ||
      strcmp(bind, "[::]") == 0) {
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

static void proc_name_from_users(const char *proc, char *name, size_t cap) {
  name[0] = 0;
  const char *q = strstr(proc, "((\"");
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

static int collect_listeners_linux(AsListener *out, int max_out, int *truncated) {
  pid_t child = -1;
  FILE *pf = open_ss_ltnp_reader(&child);
  if (!pf) {
    return -1;
  }
  char line[2048];
  int n = 0;
  *truncated = 0;
  while (fgets(line, sizeof(line), pf)) {
    trim_crlf(line);
    /* `ss`：可能是 `LISTEN ...` 或 `tcp/tcp6 LISTEN ...` */
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
    if (n >= max_out) {
      *truncated = 1;
      break;
    }
    AsListener *L = &out[n];
    memset(L, 0, sizeof(*L));
    if (strncmp(line, "tcp6", 4) == 0) {
      snprintf(L->proto, sizeof(L->proto), "%s", "tcp6");
    } else {
      snprintf(L->proto, sizeof(L->proto), "%s", "tcp");
    }
    if (parse_local_addr(local, L->bind, sizeof(L->bind), &L->port) != 0) {
      continue;
    }
    scope_for_bind(L->bind, L->scope, sizeof(L->scope));
    if (parse_pid_users(proc, &L->pid) != 0) {
      L->pid = -1;
    }
    proc_name_from_users(proc, L->proc, sizeof(L->proc));
    snprintf(L->id, sizeof(L->id), "l-%d", n);
    n++;
  }
  int close_rc = fclose(pf);
  if (child > 0) {
    int child_status = 0;
    if (waitpid(child, &child_status, 0) < 0 || !WIFEXITED(child_status) ||
        WEXITSTATUS(child_status) != 0) {
      return -1;
    }
  }
  if (close_rc != 0) return -1;
  return n;
}
#elif defined(_WIN32)

static int collect_listeners_win32(AsListener *out, int max_out, int *truncated) {
  EdrWinListenRow *tmp = (EdrWinListenRow *)malloc((size_t)max_out * sizeof(EdrWinListenRow));
  if (!tmp) {
    *truncated = 0;
    return 0;
  }
  int n = edr_win_listen_collect_rows(tmp, max_out, truncated);
  for (int i = 0; i < n; i++) {
    AsListener *L = &out[i];
    memset(L, 0, sizeof(*L));
    L->pid = tmp[i].pid;
    L->port = tmp[i].port;
    snprintf(L->bind, sizeof(L->bind), "%s", tmp[i].bind);
    snprintf(L->scope, sizeof(L->scope), "%s", tmp[i].scope);
    snprintf(L->proto, sizeof(L->proto), "%s", tmp[i].proto);
    edr_asurf_win_pid_exe_name((DWORD)L->pid, L->proc, sizeof(L->proc));
    snprintf(L->id, sizeof(L->id), "l-%d", i);
  }
  free(tmp);
  return n;
}
#else
static int collect_listeners_none(AsListener *out, int max_out, int *truncated) {
  (void)out;
  (void)max_out;
  *truncated = 0;
  return 0;
}
#endif

#if defined(__linux__)
static int collect_listeners_platform(AsListener *out, int max_out, int *truncated) {
  return collect_listeners_linux(out, max_out, truncated);
}
#elif defined(_WIN32)
static int collect_listeners_platform(AsListener *out, int max_out, int *truncated) {
  return collect_listeners_win32(out, max_out, truncated);
}
#else
static int collect_listeners_platform(AsListener *out, int max_out, int *truncated) {
  return collect_listeners_none(out, max_out, truncated);
}
#endif

uint32_t edr_attack_surface_effective_periodic_interval_s(const EdrConfig *cfg) {
  if (!cfg) {
    return 7200u;
  }
  uint32_t m = cfg->attack_surface.port_interval_s;
  if (cfg->attack_surface.service_interval_s < m) {
    m = cfg->attack_surface.service_interval_s;
  }
  if (cfg->attack_surface.policy_interval_s < m) {
    m = cfg->attack_surface.policy_interval_s;
  }
  if (cfg->attack_surface.full_snapshot_interval_s < m) {
    m = cfg->attack_surface.full_snapshot_interval_s;
  }
  if (m < 60u) {
    m = 60u;
  }
  if (m > 604800u) {
    m = 604800u;
  }
  return m;
}

static int ttl_seconds_from_cfg(const EdrConfig *cfg) {
  if (!cfg) {
    return 1800;
  }
  uint32_t t = edr_attack_surface_effective_periodic_interval_s(cfg);
  if (t > 86400u) {
    t = 86400u;
  }
  return (int)t;
}

static int geoip_db_readable(const EdrConfig *cfg) {
  const char *p = cfg->attack_surface.geoip_db_path;
  if (!p || !p[0]) {
    return 0;
  }
#ifdef _WIN32
  return GetFileAttributesA(p) != INVALID_FILE_ATTRIBUTES ? 1 : 0;
#else
  return access(p, R_OK) == 0 ? 1 : 0;
#endif
}

static int port_in_high_risk_list(const EdrConfig *cfg, int port) {
  if (!cfg->attack_surface.high_risk_immediate_ports || cfg->attack_surface.high_risk_immediate_ports_count == 0) {
    return 0;
  }
  for (size_t i = 0; i < cfg->attack_surface.high_risk_immediate_ports_count; i++) {
    if ((int)cfg->attack_surface.high_risk_immediate_ports[i] == port) {
      return 1;
    }
  }
  return 0;
}

static int bind_is_all_interfaces(const char *b) {
  if (!b || !b[0]) {
    return 0;
  }
  return strcmp(b, "0.0.0.0") == 0 || strcmp(b, "*") == 0 || strcmp(b, "::") == 0 || strcmp(b, "[::]") == 0;
}

/** 常见高危/管理面端口（与控制台演示种子对齐的启发式子集） */
static int port_builtin_sensitive(int port) {
  static const int pts[] = {20,  21,  22,  23,  25,  53,   69,  80,  110, 111, 135,  137, 138, 139, 143, 161, 445,
                            993, 995, 1433, 1521, 1723, 3306, 3389, 5432, 5900, 5985, 5986, 6379, 8080, 8443,
                            9200, 11211, 27017};
  for (size_t i = 0; i < sizeof(pts) / sizeof(pts[0]); i++) {
    if (pts[i] == port) {
      return 1;
    }
  }
  return 0;
}

/** §19.2 对齐的 1–3 级启发式；回环默认不标注 */
static void emit_listener_risk_fields(FILE *f, const EdrConfig *cfg, const AsListener *L) {
  const int crit = port_builtin_sensitive(L->port) || port_in_high_risk_list(cfg, L->port);
  const int all = bind_is_all_interfaces(L->bind);
  int level = 0;
  char rs[300];
  rs[0] = 0;

  if (strcmp(L->scope, "public") == 0) {
    level = crit ? 3 : 2;
    snprintf(rs, sizeof(rs), "%s",
             crit ? "Public bind: port is sensitive or listed in high_risk_immediate_ports; prioritize review"
                  : "Public bind: tighten bind address, source ACLs, or edge firewall");
  } else if (strcmp(L->scope, "lan") == 0) {
    if (all && crit) {
      level = 2;
      snprintf(rs, sizeof(rs), "%s",
               "All-interfaces bind (0.0.0.0/::) with sensitive port; split interface or disable unused service");
    } else if (crit) {
      level = 1;
      snprintf(rs, sizeof(rs), "%s", "LAN listener on sensitive port; review lateral movement and ACLs");
    } else if (all) {
      level = 1;
      snprintf(rs, sizeof(rs), "%s", "All-interfaces bind; confirm exposure on every interface is intended");
    }
  }

  if (level <= 0 || !rs[0]) {
    return;
  }
  fprintf(f, ",\"riskLevel\":%d", level);
  fprintf(f, ",\"riskReason\":");
  json_escape_str(f, rs);
}

/**
 * 按 `[attack_surface]`：`outbound_top_n` 暂作快照内监听条数上限（出站采集落地后改为仅约束 egress）；
 * `outbound_exclude_loopback` 为 true 时丢弃 scope=loopback 的监听行。
 */
static int build_emit_listeners(const EdrConfig *cfg, const AsListener *L, int nL, AsListener *E, int maxE,
                                int *trunc_emit) {
  *trunc_emit = 0;
  int cap = (int)cfg->attack_surface.outbound_top_n;
  if (cap < 1) {
    cap = 1;
  }
  if (cap > maxE) {
    cap = maxE;
  }
  int eligible = 0;
  for (int i = 0; i < nL; i++) {
    if (cfg->attack_surface.outbound_exclude_loopback && strcmp(L[i].scope, "loopback") == 0) {
      continue;
    }
    eligible++;
  }
  if (eligible > cap) {
    *trunc_emit = 1;
  }
  int n = 0;
  for (int i = 0; i < nL; i++) {
    if (cfg->attack_surface.outbound_exclude_loopback && strcmp(L[i].scope, "loopback") == 0) {
      continue;
    }
    if (n >= cap) {
      *trunc_emit = 1;
      break;
    }
    E[n++] = L[i];
  }
  return n;
}

/** §19 关键对外服务：由常见 Web 端口 + 进程名启发式推导（完整 §18 Web 缓存后续再接）。 */
static int web_listener_heuristic(const AsListener *L) {
  int p = L->port;
  if (p != 80 && p != 443 && p != 8080 && p != 8443 && p != 8000 && p != 8888) {
    return 0;
  }
  if (strcmp(L->scope, "loopback") == 0) {
    return 0;
  }
  return 1;
}

static void infer_web_label(const AsListener *L, char *svc, size_t cap) {
  const char *p = L->proc;
  if (strstr(p, "nginx") || strstr(p, "Nginx")) {
    snprintf(svc, cap, "nginx");
    return;
  }
  if (strstr(p, "apache") || strstr(p, "httpd") || strstr(p, "Apache")) {
    snprintf(svc, cap, "apache");
    return;
  }
  if (strstr(p, "node")) {
    snprintf(svc, cap, "node");
    return;
  }
  if (strstr(p, "java")) {
    snprintf(svc, cap, "java");
    return;
  }
  snprintf(svc, cap, "http");
}

static void emit_web_services_array(FILE *f, const AsListener *E, int nE) {
  fprintf(f, "\"webServices\":[");
  int first = 1;
  for (int i = 0; i < nE; i++) {
    if (!web_listener_heuristic(&E[i])) {
      continue;
    }
    if (!first) {
      fputc(',', f);
    }
    first = 0;
    char svc[48];
    infer_web_label(&E[i], svc, sizeof(svc));
    char wid[72];
    snprintf(wid, sizeof(wid), "ws-%d-%d", E[i].port, i);
    fprintf(f, "{\"id\":");
    json_escape_str(f, wid);
    fprintf(f, ",\"serviceName\":");
    json_escape_str(f, svc);
    fprintf(f, ",\"listenPort\":%d,\"pid\":", E[i].port);
    if (E[i].pid >= 0) {
      fprintf(f, "%d", E[i].pid);
    } else {
      fprintf(f, "null");
    }
    fprintf(f, ",\"rootDirs\":[],\"configPath\":null}");
  }
  fprintf(f, "],");
}

typedef struct {
  const EdrConfig *cfg;
  EdrSecurityPolicySnap *sp;
  EdrAsurfEgressRow *eg;
  int eg_max;
  int *n_eg;
  int *susp;
  int *eg_trunc;
} AsurfGatherParallel;

#ifdef _WIN32
static DWORD WINAPI asurf_thread_policy(void *arg) {
  AsurfGatherParallel *g = (AsurfGatherParallel *)arg;
  edr_security_policy_snap_collect(g->cfg, g->sp);
  return 0;
}

static DWORD WINAPI asurf_thread_egress(void *arg) {
  AsurfGatherParallel *g = (AsurfGatherParallel *)arg;
  edr_asurf_collect_egress(g->cfg, g->eg, g->eg_max, g->n_eg, g->susp, g->eg_trunc);
  return 0;
}
#else
static void *asurf_thread_policy(void *arg) {
  AsurfGatherParallel *g = (AsurfGatherParallel *)arg;
  edr_security_policy_snap_collect(g->cfg, g->sp);
  return NULL;
}

static void *asurf_thread_egress(void *arg) {
  AsurfGatherParallel *g = (AsurfGatherParallel *)arg;
  edr_asurf_collect_egress(g->cfg, g->eg, g->eg_max, g->n_eg, g->susp, g->eg_trunc);
  return NULL;
}
#endif

/** §19.4：出站与策略摘要互不依赖，并行采集以缩短快照延迟（失败则退回顺序）。 */
static void asurf_gather_policy_and_egress(const EdrConfig *cfg, EdrSecurityPolicySnap *sp,
                                           EdrAsurfEgressRow *eg, int eg_max, int *n_eg, int *susp,
                                           int *eg_trunc) {
  AsurfGatherParallel ctx;
  memset(&ctx, 0, sizeof(ctx));
  ctx.cfg = cfg;
  ctx.sp = sp;
  ctx.eg = eg;
  ctx.eg_max = eg_max;
  ctx.n_eg = n_eg;
  ctx.susp = susp;
  ctx.eg_trunc = eg_trunc;
#ifdef _WIN32
  HANDLE tp = CreateThread(NULL, 0, asurf_thread_policy, &ctx, 0, NULL);
  HANDLE te = CreateThread(NULL, 0, asurf_thread_egress, &ctx, 0, NULL);
  if (tp && te) {
    HANDLE arr[2] = {tp, te};
    (void)WaitForMultipleObjects(2, arr, TRUE, INFINITE);
  } else if (tp) {
    edr_asurf_collect_egress(cfg, eg, eg_max, n_eg, susp, eg_trunc);
    (void)WaitForSingleObject(tp, INFINITE);
  } else if (te) {
    edr_security_policy_snap_collect(cfg, sp);
    (void)WaitForSingleObject(te, INFINITE);
  } else {
    edr_security_policy_snap_collect(cfg, sp);
    edr_asurf_collect_egress(cfg, eg, eg_max, n_eg, susp, eg_trunc);
  }
  if (tp) {
    CloseHandle(tp);
  }
  if (te) {
    CloseHandle(te);
  }
#else
  pthread_t tpol = 0;
  pthread_t tegr = 0;
  int have_policy = pthread_create(&tpol, NULL, asurf_thread_policy, &ctx) == 0;
  int have_egress = pthread_create(&tegr, NULL, asurf_thread_egress, &ctx) == 0;
  if (!have_policy) {
    edr_security_policy_snap_collect(cfg, sp);
  }
  if (!have_egress) {
    edr_asurf_collect_egress(cfg, eg, eg_max, n_eg, susp, eg_trunc);
  }
  if (have_policy) {
    (void)pthread_join(tpol, NULL);
  }
  if (have_egress) {
    (void)pthread_join(tegr, NULL);
  }
#endif
}

static int asurf_listeners_only_mode(const char *command_id, const uint8_t *payload,
                                     size_t payload_len) {
  const char *lo = getenv("EDR_ATTACK_SURFACE_LISTENERS_ONLY");
  if (lo && lo[0] == '1') {
    return 1;
  }
  int etw_trigger = command_id && strcmp(command_id, "etw_tcpip_wf") == 0;
  if (payload && payload_len > 0u && payload_len <= 4096u) {
    cJSON *root = cJSON_ParseWithLength((const char *)payload, payload_len);
    if (root) {
      cJSON *reason = cJSON_GetObjectItemCaseSensitive(root, "reason");
      cJSON *light = cJSON_GetObjectItemCaseSensitive(root, "listeners_only");
      if (cJSON_IsString(reason) && reason->valuestring &&
          strcmp(reason->valuestring, "etw_tcpip_wf") == 0) etw_trigger = 1;
      if (cJSON_IsTrue(light)) etw_trigger = 1;
      cJSON_Delete(root);
    }
  }
  if (etw_trigger) {
    const char *el = getenv("EDR_ATTACK_SURFACE_ETW_LIGHT");
    if (!el || el[0] != '0') return 1;
  }
  return 0;
}

static uint64_t asurf_monotonic_ms(void) {
#ifdef _WIN32
  return (uint64_t)GetTickCount64();
#else
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0u;
  return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
#endif
}

#ifdef _WIN32
static volatile LONG s_asurf_execute_running;
static int asurf_execute_try_lock(void) {
  return InterlockedCompareExchange(&s_asurf_execute_running, 1, 0) == 0;
}
static void asurf_execute_unlock(void) { InterlockedExchange(&s_asurf_execute_running, 0); }
#else
static volatile unsigned s_asurf_execute_running;
static int asurf_execute_try_lock(void) {
  unsigned expected = 0u;
  return __atomic_compare_exchange_n(&s_asurf_execute_running, &expected, 1u, 0,
                                     __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
}
static void asurf_execute_unlock(void) {
  __atomic_store_n(&s_asurf_execute_running, 0u, __ATOMIC_RELEASE);
}
#endif

static int write_snapshot_json(const char *path, const EdrConfig *cfg, const AsListener *L, int nL,
                               int truncated_ss, int listeners_only) {
  FILE *f = fopen(path, "wb");
  if (!f) {
    return -1;
  }
  /* collectedAt: UTC (trailing Z). Compare with local OS clock by converting local -> UTC. */
  time_t now = time(NULL);
#ifdef _WIN32
  struct tm tmb;
  gmtime_s(&tmb, &now);
  struct tm *tmv = &tmb;
#else
  struct tm tmb;
  struct tm *tmv = gmtime_r(&now, &tmb);
#endif
  char ts[40];
  strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", tmv);

  AsListener E[EDR_ASURF_LISTENERS_MAX];
  int trunc_cap = 0;
  int nE = build_emit_listeners(cfg, L, nL, E, EDR_ASURF_LISTENERS_MAX, &trunc_cap);
  int truncated = truncated_ss || trunc_cap;

  EdrSecurityPolicySnap sp;
  EdrAsurfEgressRow Eg[EDR_ASURF_EGRESS_OUT_MAX];
  int nEg = 0;
  int suspEg = 0;
  int egTrunc = 0;
  if (listeners_only) {
    memset(&sp, 0, sizeof(sp));
    nEg = 0;
    suspEg = 0;
    egTrunc = 0;
  } else {
    asurf_gather_policy_and_egress(cfg, &sp, Eg, EDR_ASURF_EGRESS_OUT_MAX, &nEg, &suspEg, &egTrunc);
    if (!cfg->attack_surface.egress_enabled) { nEg = 0; suspEg = 0; egTrunc = 0; }
    if (!cfg->attack_surface.defender_enabled) memset(&sp, 0, sizeof(sp));
  }

  EdrAsurfInventorySummary inv;
  memset(&inv, 0, sizeof(inv));
  char inv_path[1100];
  snprintf(inv_path, sizeof(inv_path), "%s.inv", path);
  FILE *invf = fopen(inv_path, "wb");
  if (invf) {
    edr_asurf_inventory_write_json(invf, cfg, listeners_only, &inv);
    fclose(invf);
  }

  int pub = 0;
  int webInst = 0;
  for (int i = 0; i < nE; i++) {
    if (cfg->attack_surface.public_service_enabled && strcmp(E[i].scope, "public") == 0) {
      pub++;
    }
    if (web_listener_heuristic(&E[i])) {
      webInst++;
    }
  }

  const int ttl = ttl_seconds_from_cfg(cfg);

  fprintf(f, "{\"endpointId\":");
  json_escape_str(f, cfg->agent.endpoint_id);
  fprintf(f, ",\"collectedAt\":");
  json_escape_str(f, ts);
  fprintf(f, ",\"snapshotKind\":");
  if (listeners_only) {
    fprintf(f, "\"listenersOnly\"");
  } else {
    fprintf(f, "\"full\"");
  }
  fprintf(f, ",\"stale\":false,\"ttlSeconds\":%d,", ttl);

  fprintf(f, "\"summary\":{\"listenerCount\":%d,\"publicListenerCount\":%d,\"webInstanceCount\":%d,"
          "\"suspiciousEgressCount\":%d,"
          "\"serviceCount\":%d,\"autoStartServiceCount\":%d,\"scheduledTaskCount\":%d,"
          "\"enabledScheduledTaskCount\":%d,\"startupItemCount\":%d,\"privilegedAccountCount\":%d,"
          "\"adminGroupMemberCount\":%d,\"shareCount\":%d,\"riskyShareCount\":%d,"
          "\"persistenceFindingCount\":%d,\"browserExtensionCount\":%d,\"installedSoftwareCount\":%d},",
          nE, pub, webInst, suspEg, inv.service_count, inv.auto_start_service_count, inv.scheduled_task_count,
          inv.enabled_scheduled_task_count, inv.startup_item_count, inv.privileged_account_count,
          inv.admin_group_member_count, inv.share_count, inv.risky_share_count, inv.persistence_finding_count,
          inv.browser_extension_count, inv.installed_software_count);

  fprintf(f, "\"listeners\":{\"items\":[");
  for (int i = 0; i < nE; i++) {
    if (i) {
      fputc(',', f);
    }
    fprintf(f, "{");
    fprintf(f, "\"id\":");
    json_escape_str(f, E[i].id);
    fprintf(f, ",\"protocol\":");
    json_escape_str(f, E[i].proto);
    fprintf(f, ",\"bindAddr\":");
    json_escape_str(f, E[i].bind);
    fprintf(f, ",\"port\":%d,", E[i].port);
    fprintf(f, "\"pid\":");
    if (E[i].pid >= 0) {
      fprintf(f, "%d", E[i].pid);
    } else {
      fprintf(f, "null");
    }
    fprintf(f, ",\"processName\":");
    if (E[i].proc[0]) {
      json_escape_str(f, E[i].proc);
    } else {
      fprintf(f, "null");
    }
    fprintf(f, ",\"processPath\":null,\"serviceName\":null,\"scope\":");
    json_escape_str(f, E[i].scope);
    emit_listener_risk_fields(f, cfg, &E[i]);
    fprintf(f, "}");
  }
  fprintf(f, "],\"truncated\":%s},", truncated ? "true" : "false");

  emit_web_services_array(f, E, nE);
  fprintf(f, "\"egressTop\":[");
  for (int i = 0; i < nEg; i++) {
    if (i) {
      fputc(',', f);
    }
    char eid[32];
    snprintf(eid, sizeof(eid), "e-%d", i);
    fprintf(f, "{\"id\":");
    json_escape_str(f, eid);
    fprintf(f, ",\"remoteIp\":");
    json_escape_str(f, Eg[i].remote_ip);
    fprintf(f, ",\"remotePort\":%d,\"protocol\":", Eg[i].remote_port);
    json_escape_str(f, "tcp");
    fprintf(f, ",\"pid\":");
    if (Eg[i].pid >= 0) {
      fprintf(f, "%d", Eg[i].pid);
    } else {
      fprintf(f, "null");
    }
    fprintf(f, ",\"processName\":");
    if (Eg[i].proc_name[0]) {
      json_escape_str(f, Eg[i].proc_name);
    } else {
      fprintf(f, "null");
    }
    fprintf(f, ",\"lastSeen\":");
    json_escape_str(f, ts);
    fprintf(f, ",\"connectionCount\":%d", Eg[i].connection_count);
    if (Eg[i].mark_risk) {
      fprintf(f, ",\"riskTag\":");
      json_escape_str(f, "non_rfc1918");
    }
    fprintf(f, "}");
  }
  fprintf(f, "],");
  fprintf(f, "\"processHighlights\":[");
  {
    int nh = 0;
    const int nh_max = 32;
    for (int i = 0; i < nE && nh < nh_max; i++) {
      if (!port_in_high_risk_list(cfg, E[i].port)) {
        continue;
      }
      if (nh) {
        fputc(',', f);
      }
      fprintf(f, "{\"id\":");
      json_escape_str(f, E[i].id);
      fprintf(f, ",\"pid\":%d,", E[i].pid >= 0 ? E[i].pid : 0);
      fprintf(f, "\"name\":");
      if (E[i].proc[0]) {
        json_escape_str(f, E[i].proc);
      } else {
        json_escape_str(f, "unknown");
      }
      fprintf(f, ",\"path\":null,\"reason\":");
      json_escape_str(f, "监听端口命中 high_risk_immediate_ports 配置列表");
      fprintf(f, ",\"severity\":\"high\",\"observedAt\":");
      json_escape_str(f, ts);
      fprintf(f, "}");
      nh++;
    }
    for (int i = 0; i < nE && nh < nh_max; i++) {
      if (strcmp(E[i].scope, "public") != 0) {
        continue;
      }
      if (port_in_high_risk_list(cfg, E[i].port)) {
        continue;
      }
      if (nh) {
        fputc(',', f);
      }
      char hid[48];
      snprintf(hid, sizeof(hid), "ph-pub-%s", E[i].id);
      fprintf(f, "{\"id\":");
      json_escape_str(f, hid);
      fprintf(f, ",\"pid\":%d,", E[i].pid >= 0 ? E[i].pid : 0);
      fprintf(f, "\"name\":");
      if (E[i].proc[0]) {
        json_escape_str(f, E[i].proc);
      } else {
        json_escape_str(f, "unknown");
      }
      fprintf(f, ",\"path\":null,\"reason\":");
      json_escape_str(f, "公网暴露监听（非回环/内网绑定）");
      fprintf(f, ",\"severity\":\"medium\",\"observedAt\":");
      json_escape_str(f, ts);
      fprintf(f, "}");
      nh++;
    }
  }
  fprintf(f, "],");
  if (invf) {
    copy_text_file_to_stream(f, inv_path);
    (void)remove(inv_path);
    fprintf(f, ",");
  } else {
    edr_asurf_inventory_write_json(f, cfg, listeners_only, &inv);
    fprintf(f, ",");
  }

  fprintf(f, "\"policy\":{},\"firewall\":{");
  fprintf(f, "\"enabled\":");
  if (sp.top_fw_enabled_known) {
    fprintf(f, "%s", sp.top_fw_enabled ? "true" : "false");
  } else {
    fprintf(f, "null");
  }
  fprintf(f, ",\"profile\":");
  if (sp.top_fw_profile[0]) {
    json_escape_str(f, sp.top_fw_profile);
  } else {
    fprintf(f, "null");
  }
  fprintf(f, ",\"approximateRuleCount\":");
  if (sp.top_rule_count_known) {
    fprintf(f, "%d", sp.top_rule_count);
  } else {
    fprintf(f, "null");
  }
  fprintf(f, ",\"notes\":[");
  json_escape_str(f, "edr-agent GET_ATTACK_SURFACE：§18.3.5.4 P2 egressTop(ss)+processHighlights；§19.3.3 P1 securityPolicy");
  if (listeners_only) {
    fprintf(f, ",");
    json_escape_str(f, "snapshotKind=listenersOnly：未采集 egressTop 与 securityPolicy 系统查询");
  }
  {
    char note_fw[160];
    snprintf(note_fw, sizeof(note_fw), "firewall_rule_detail_max(config_limit)=%u",
             cfg->attack_surface.firewall_rule_detail_max);
    fprintf(f, ",");
    json_escape_str(f, note_fw);
  }
  if (egTrunc) {
    fprintf(f, ",");
    json_escape_str(f, "egressTop 聚合达到桶上限，已截断");
  }
  {
    const char *gp = cfg->attack_surface.geoip_db_path;
    if (gp && gp[0]) {
      char note_geo[768];
      if (geoip_db_readable(cfg)) {
        snprintf(note_geo, sizeof(note_geo), "geoip_db_path readable: %.680s", gp);
      } else {
        snprintf(note_geo, sizeof(note_geo), "geoip_db_path not ready (skipped): %.680s", gp);
      }
      fprintf(f, ",");
      json_escape_str(f, note_geo);
    }
  }
  fprintf(f, "]}");
  fprintf(f, ",\"securityPolicy\":");
  edr_security_policy_snap_write_policy_object(f, cfg, &sp);
  fprintf(f, "}");
  fclose(f);
  return 0;
}

static char *read_text_file_alloc(const char *path, size_t max_bytes, size_t *out_len) {
  if (out_len) {
    *out_len = 0u;
  }
  FILE *f = fopen(path, "rb");
  if (!f) {
    return NULL;
  }
  if (fseek(f, 0, SEEK_END) != 0) {
    fclose(f);
    return NULL;
  }
  long sz = ftell(f);
  if (sz < 0 || (size_t)sz > max_bytes) {
    fclose(f);
    return NULL;
  }
  rewind(f);
  char *buf = (char *)malloc((size_t)sz + 1u);
  if (!buf) {
    fclose(f);
    return NULL;
  }
  size_t n = fread(buf, 1u, (size_t)sz, f);
  fclose(f);
  buf[n] = 0;
  if (out_len) {
    *out_len = n;
  }
  return buf;
}

static int response_json_refresh_pending_buf(const char *buf) {
  if (!buf) {
    return 0;
  }
  return (strstr(buf, "\"refreshPending\":true") != NULL || strstr(buf, "\"refreshPending\": true") != NULL) ? 1 : 0;
}

int edr_attack_surface_refresh_pending(const EdrConfig *cfg) {
  if (!cfg || !cfg->agent.endpoint_id[0] || strcmp(cfg->agent.endpoint_id, "auto") == 0) {
    return 0;
  }
  char suffix[512];
  snprintf(suffix, sizeof(suffix), "endpoints/%s/attack-surface/refresh-request", cfg->agent.endpoint_id);
  char resp[16384];
  resp[0] = 0;
  if (edr_ingest_http_get_suffix(suffix, resp, sizeof(resp)) != 0) {
    return -1;
  }
  return response_json_refresh_pending_buf(resp);
}

static int edr_attack_surface_execute_impl(const char *command_id, const uint8_t *payload,
                                           size_t payload_len, const EdrConfig *cfg,
                                           char *detail, size_t detail_cap) {
  if (!detail || detail_cap == 0) {
    return 3;
  }
  detail[0] = 0;
  if (!cfg || !cfg->agent.endpoint_id[0] || strcmp(cfg->agent.endpoint_id, "auto") == 0) {
    snprintf(detail, detail_cap, "bad_endpoint_id");
    return 2;
  }

  uint64_t started_ms = asurf_monotonic_ms();
  AsListener L[EDR_ASURF_LISTENERS_MAX];
  int truncated = 0;
  int nL = (cfg->attack_surface.listeners_enabled || cfg->attack_surface.public_service_enabled)
             ? collect_listeners_platform(L, EDR_ASURF_LISTENERS_MAX, &truncated) : 0;
  if (nL < 0) {
    snprintf(detail, detail_cap, "listener_collection_failed");
    return 3;
  }
  uint64_t listeners_done_ms = asurf_monotonic_ms();
  int listeners_only = asurf_listeners_only_mode(command_id, payload, payload_len);

  char jsonpath[512];
  snprintf(jsonpath, sizeof(jsonpath), "/tmp/edr_asurf_%d_%lld.json", EDR_GETPID(),
           (long long)time(NULL) * 1000LL);
#ifdef _WIN32
  {
    char td[MAX_PATH];
    DWORD n = GetTempPathA(sizeof(td), td);
    if (n == 0 || n >= sizeof(td)) {
      snprintf(td, sizeof(td), ".\\");
    }
    win_path_fwd_slashes(td);
    snprintf(jsonpath, sizeof(jsonpath), "%sedr_asurf_%d_%lld.json", td, EDR_GETPID(),
             (long long)time(NULL) * 1000LL);
    win_path_fwd_slashes(jsonpath);
  }
#endif
  if (write_snapshot_json(jsonpath, cfg, L, nL, truncated, listeners_only) != 0) {
    snprintf(detail, detail_cap, "write_json_failed");
    return 3;
  }

  size_t body_len = 0u;
  char *body = read_text_file_alloc(jsonpath, 4u * 1024u * 1024u, &body_len);
  (void)remove(jsonpath);
  if (!body || body_len == 0u) {
    free(body);
    snprintf(detail, detail_cap, "read_json_failed");
    return 3;
  }
  uint64_t snapshot_done_ms = asurf_monotonic_ms();

  char suffix[512];
  snprintf(suffix, sizeof(suffix), "endpoints/%s/attack-surface", cfg->agent.endpoint_id);
  int ur = edr_ingest_http_post_json_suffix(suffix, body, NULL, 0u);
  free(body);
  if (ur != 0) {
    snprintf(detail, detail_cap, "http_post_failed");
    return 3;
  }
  uint64_t uploaded_ms = asurf_monotonic_ms();
  snprintf(detail, detail_cap,
           "uploaded_http_ok mode=%s listeners_ms=%llu snapshot_ms=%llu upload_ms=%llu total_ms=%llu",
           listeners_only ? "listeners_only" : "full",
           (unsigned long long)(listeners_done_ms - started_ms),
           (unsigned long long)(snapshot_done_ms - listeners_done_ms),
           (unsigned long long)(uploaded_ms - snapshot_done_ms),
           (unsigned long long)(uploaded_ms - started_ms));
  return 0;
}

int edr_attack_surface_execute(const char *command_id, const uint8_t *payload,
                               size_t payload_len, const EdrConfig *cfg,
                               char *detail, size_t detail_cap) {
  if (!detail || detail_cap == 0u) return 3;
  if (!asurf_execute_try_lock()) {
    snprintf(detail, detail_cap, "%s", "coalesced_inflight");
    return 0;
  }
  int rc = edr_attack_surface_execute_impl(command_id, payload, payload_len,
                                           cfg, detail, detail_cap);
  asurf_execute_unlock();
  return rc;
}

/* §19.10 ETW → 攻击面增量：预处理线程 signal，主线程 take + execute（去抖） */
#ifdef _WIN32
static volatile LONG s_asurf_etw_pending;
#else
static volatile unsigned s_asurf_etw_pending;
#endif
static uint64_t s_asurf_etw_last_flush_ns;

void edr_attack_surface_etw_signal(void) {
#ifdef _WIN32
  InterlockedExchange(&s_asurf_etw_pending, 1);
#else
  __atomic_store_n(&s_asurf_etw_pending, 1u, __ATOMIC_RELEASE);
#endif
}

int edr_attack_surface_take_etw_flush(uint64_t now_monotonic_ns, uint64_t debounce_ns) {
#ifdef _WIN32
  if (InterlockedCompareExchange(&s_asurf_etw_pending, 0, 0) == 0) {
#else
  if (__atomic_load_n(&s_asurf_etw_pending, __ATOMIC_ACQUIRE) == 0u) {
#endif
    return 0;
  }
  if (s_asurf_etw_last_flush_ns != 0u &&
      (now_monotonic_ns - s_asurf_etw_last_flush_ns) < debounce_ns) {
    return 0;
  }
#ifdef _WIN32
  InterlockedExchange(&s_asurf_etw_pending, 0);
#else
  __atomic_store_n(&s_asurf_etw_pending, 0u, __ATOMIC_RELEASE);
#endif
  s_asurf_etw_last_flush_ns = now_monotonic_ns;
  return 1;
}
