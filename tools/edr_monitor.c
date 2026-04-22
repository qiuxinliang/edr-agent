/*
 * edr_monitor — 终端联调工具（独立 exe，不嵌入 edr_agent 进程）。
 * 对齐《EDR_端点详细设计_v1.0》§1.2 / §14 的黑盒视角：通信（gRPC 目标 TCP、REST 根 HTTP 探针）、
 * AVE（model_dir / .onnx 数量）、离线队列（queue_db 文件）、本机 edr_agent 进程。
 *
 * 用法:
 *   edr_monitor --config <agent.toml> [--json] [--no-probe]
 *
 * 说明: 不读取也不打印 rest_bearer_token 明文；JSON 模式下 bearer 仅输出是否已配置。
 */
#include "toml.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winhttp.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <tlhelp32.h>
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "ws2_32.lib")
#else
#include <arpa/inet.h>
#include <dirent.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#define EDR_MON_STR_CAP 2048
#define EDR_MON_HOST_CAP 512
#define EDR_MON_HTTP_BUF 4096

typedef struct {
  char server_addr[EDR_MON_STR_CAP];
  char endpoint_id[256];
  char tenant_id[256];
  char rest_base[EDR_MON_STR_CAP];
  char bearer_set; /* 0/1 */
  char model_dir[EDR_MON_STR_CAP];
  char queue_db[512];
} EdrMonSnapshot;

static void edr_strcpy(char *dst, size_t cap, const char *src) {
  if (!dst || cap == 0) {
    return;
  }
  dst[0] = '\0';
  if (!src) {
    return;
  }
  strncpy(dst, src, cap - 1);
  dst[cap - 1] = '\0';
}

static int edr_toml_str(toml_table_t *t, const char *key, char *out, size_t cap) {
  toml_datum_t d = toml_string_in(t, key);
  if (!d.ok) {
    return 0;
  }
  edr_strcpy(out, cap, d.u.s);
  free(d.u.s);
  return out[0] != '\0';
}

static void edr_api_origin_from_rest_base(const char *rest, char *out, size_t cap) {
  edr_strcpy(out, cap, rest);
  if (!out[0]) {
    return;
  }
  {
    char *p = strstr(out, "/api/v1");
    if (p) {
      *p = '\0';
    }
  }
  {
    size_t n = strlen(out);
    while (n > 0 && out[n - 1] == '/') {
      out[--n] = '\0';
    }
  }
}

static int edr_parse_host_port(const char *addr, char *host, size_t host_cap, char *port, size_t port_cap) {
  const char *colon = strrchr(addr, ':');
  if (!colon || colon == addr) {
    return 0;
  }
  size_t hl = (size_t)(colon - addr);
  if (hl >= host_cap) {
    return 0;
  }
  memcpy(host, addr, hl);
  host[hl] = '\0';
  edr_strcpy(port, port_cap, colon + 1);
  return host[0] && port[0];
}

#ifdef _WIN32
static int edr_tcp_probe_win(const char *host, const char *port) {
  WSADATA wsa;
  if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
    return -1;
  }
  struct addrinfo hints;
  struct addrinfo *res = NULL;
  memset(&hints, 0, sizeof(hints));
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_family = AF_UNSPEC;
  int gai = getaddrinfo(host, port, &hints, &res);
  if (gai != 0 || !res) {
    WSACleanup();
    return 0;
  }
  SOCKET s = INVALID_SOCKET;
  struct addrinfo *p;
  for (p = res; p; p = p->ai_next) {
    s = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
    if (s == INVALID_SOCKET) {
      continue;
    }
    unsigned long nb = 1;
    ioctlsocket(s, FIONBIO, &nb);
    int cr = connect(s, p->ai_addr, (int)p->ai_addrlen);
    if (cr == 0) {
      closesocket(s);
      freeaddrinfo(res);
      WSACleanup();
      return 1;
    }
    int werr = WSAGetLastError();
    if (werr != WSAEWOULDBLOCK) {
      closesocket(s);
      s = INVALID_SOCKET;
      continue;
    }
    fd_set wf;
    FD_ZERO(&wf);
    FD_SET(s, &wf);
    struct timeval tv;
    tv.tv_sec = 3;
    tv.tv_usec = 0;
    int sel = select(0, NULL, &wf, NULL, &tv);
    closesocket(s);
    s = INVALID_SOCKET;
    if (sel == 1) {
      freeaddrinfo(res);
      WSACleanup();
      return 1;
    }
    if (p->ai_next == NULL) {
      break;
    }
  }
  freeaddrinfo(res);
  WSACleanup();
  return 0;
}

static int edr_http_get_status_win(const char *url_utf8, char *err, size_t errcap) {
  if (err && errcap) {
    err[0] = '\0';
  }
  int wlen = MultiByteToWideChar(CP_UTF8, 0, url_utf8, -1, NULL, 0);
  if (wlen <= 0) {
    edr_strcpy(err, errcap, "utf8 url");
    return -1;
  }
  wchar_t *wurl = (wchar_t *)malloc((size_t)wlen * sizeof(wchar_t));
  if (!wurl) {
    return -1;
  }
  MultiByteToWideChar(CP_UTF8, 0, url_utf8, -1, wurl, wlen);
  URL_COMPONENTS uc;
  memset(&uc, 0, sizeof(uc));
  uc.dwStructSize = sizeof(uc);
  wchar_t host[256];
  wchar_t path[1024];
  uc.lpszHostName = host;
  uc.dwHostNameLength = (DWORD)(sizeof(host) / sizeof(host[0]));
  uc.lpszUrlPath = path;
  uc.dwUrlPathLength = (DWORD)(sizeof(path) / sizeof(path[0]));
  if (!WinHttpCrackUrl(wurl, 0, 0, &uc)) {
    free(wurl);
    edr_strcpy(err, errcap, "WinHttpCrackUrl");
    return -1;
  }
  HINTERNET ses =
      WinHttpOpen(L"edr_monitor/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME,
                  WINHTTP_NO_PROXY_BYPASS, 0);
  if (!ses) {
    free(wurl);
    edr_strcpy(err, errcap, "WinHttpOpen");
    return -1;
  }
  unsigned long flags = 0;
  if (uc.nScheme == INTERNET_SCHEME_HTTPS) {
    flags |= WINHTTP_FLAG_SECURE;
  }
  HINTERNET con = WinHttpConnect(ses, uc.lpszHostName, uc.nPort, 0);
  if (!con) {
    WinHttpCloseHandle(ses);
    free(wurl);
    edr_strcpy(err, errcap, "WinHttpConnect");
    return -1;
  }
  HINTERNET req = WinHttpOpenRequest(con, L"GET", uc.lpszUrlPath, NULL, WINHTTP_NO_REFERER,
                                     WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
  if (!req) {
    WinHttpCloseHandle(con);
    WinHttpCloseHandle(ses);
    free(wurl);
    edr_strcpy(err, errcap, "WinHttpOpenRequest");
    return -1;
  }
  BOOL ok = WinHttpSendRequest(req, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
  if (!ok || !WinHttpReceiveResponse(req, NULL)) {
    WinHttpCloseHandle(req);
    WinHttpCloseHandle(con);
    WinHttpCloseHandle(ses);
    free(wurl);
    edr_strcpy(err, errcap, "WinHttpSend/Receive");
    return -1;
  }
  DWORD status = 0;
  DWORD sz = sizeof(status);
  if (!WinHttpQueryHeaders(req, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX,
                           &status, &sz, WINHTTP_NO_HEADER_INDEX)) {
    status = 0;
  }
  WinHttpCloseHandle(req);
  WinHttpCloseHandle(con);
  WinHttpCloseHandle(ses);
  free(wurl);
  return (int)status;
}

static int edr_count_onnx_in_dir_win(const wchar_t *wdir) {
  wchar_t pat[MAX_PATH];
  _snwprintf_s(pat, MAX_PATH, _TRUNCATE, L"%s\\*.onnx", wdir);
  WIN32_FIND_DATAW fd;
  HANDLE h = FindFirstFileW(pat, &fd);
  if (h == INVALID_HANDLE_VALUE) {
    return 0;
  }
  int n = 0;
  do {
    if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
      n++;
    }
  } while (FindNextFileW(h, &fd));
  FindClose(h);
  return n;
}

static int edr_agent_process_running_win(void) {
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snap == INVALID_HANDLE_VALUE) {
    return 0;
  }
  PROCESSENTRY32W pe;
  pe.dwSize = sizeof(pe);
  int found = 0;
  if (Process32FirstW(snap, &pe)) {
    do {
      if (_wcsicmp(pe.szExeFile, L"edr_agent.exe") == 0) {
        found = 1;
        break;
      }
    } while (Process32NextW(snap, &pe));
  }
  CloseHandle(snap);
  return found;
}

static int edr_utf8_to_wide(const char *u8, wchar_t *wout, int wcap) {
  return MultiByteToWideChar(CP_UTF8, 0, u8, -1, wout, wcap);
}
#else
static int edr_tcp_probe_posix(const char *host, const char *port) {
  struct addrinfo hints;
  struct addrinfo *res = NULL;
  memset(&hints, 0, sizeof(hints));
  hints.ai_socktype = SOCK_STREAM;
  int gai = getaddrinfo(host, port, &hints, &res);
  if (gai != 0 || !res) {
    return 0;
  }
  int fd = -1;
  struct addrinfo *p;
  for (p = res; p; p = p->ai_next) {
    fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
    if (fd < 0) {
      continue;
    }
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl >= 0) {
      (void)fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    }
    int cr = connect(fd, p->ai_addr, p->ai_addrlen);
    if (cr == 0) {
      close(fd);
      freeaddrinfo(res);
      return 1;
    }
    if (errno == EINPROGRESS) {
      fd_set wf;
      FD_ZERO(&wf);
      FD_SET(fd, &wf);
      struct timeval tv;
      tv.tv_sec = 3;
      tv.tv_usec = 0;
      if (select(fd + 1, NULL, &wf, NULL, &tv) == 1) {
        int soe = 0;
        socklen_t sl = sizeof(soe);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soe, &sl) == 0 && soe == 0) {
          close(fd);
          freeaddrinfo(res);
          return 1;
        }
      }
    }
    close(fd);
    fd = -1;
  }
  freeaddrinfo(res);
  return 0;
}

static int edr_http_probe_posix(const char *host, const char *port_num, const char *path) {
  struct addrinfo hints;
  struct addrinfo *res = NULL;
  memset(&hints, 0, sizeof(hints));
  hints.ai_socktype = SOCK_STREAM;
  if (getaddrinfo(host, port_num, &hints, &res) != 0 || !res) {
    return 0;
  }
  int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
  if (fd < 0) {
    freeaddrinfo(res);
    return 0;
  }
  if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
    close(fd);
    freeaddrinfo(res);
    return 0;
  }
  freeaddrinfo(res);
  char req[512];
  snprintf(req, sizeof(req),
           "GET %s HTTP/1.0\r\n"
           "Host: %s\r\n"
           "Connection: close\r\n"
           "\r\n",
           path, host);
  if (send(fd, req, strlen(req), 0) < 0) {
    close(fd);
    return 0;
  }
  char buf[256];
  int n = (int)recv(fd, buf, sizeof(buf) - 1, 0);
  close(fd);
  if (n <= 0) {
    return 0;
  }
  buf[n] = '\0';
  /* first line: HTTP/1.x 200 */
  if (strstr(buf, " 200") != NULL) {
    return 200;
  }
  if (strstr(buf, " 204") != NULL) {
    return 204;
  }
  return 0;
}

static int edr_parse_http_host_port_path(const char *origin, char *host, size_t hc, char *port, size_t pc,
                                          char *path, size_t ptc) {
  edr_strcpy(host, hc, "");
  edr_strcpy(port, pc, "80");
  edr_strcpy(path, ptc, "/healthz");
  if (strncmp(origin, "http://", 7) != 0) {
    return 0;
  }
  const char *p = origin + 7;
  const char *slash = strchr(p, '/');
  char hp[EDR_MON_HOST_CAP];
  if (slash) {
    size_t l = (size_t)(slash - p);
    if (l >= sizeof(hp)) {
      return 0;
    }
    memcpy(hp, p, l);
    hp[l] = '\0';
    edr_strcpy(path, ptc, slash);
  } else {
    edr_strcpy(hp, sizeof(hp), p);
  }
  const char *colon = strrchr(hp, ':');
  if (colon) {
    size_t hl = (size_t)(colon - hp);
    if (hl >= hc) {
      return 0;
    }
    memcpy(host, hp, hl);
    host[hl] = '\0';
    edr_strcpy(port, pc, colon + 1);
  } else {
    edr_strcpy(host, hc, hp);
  }
  return host[0] != '\0';
}

static int edr_count_onnx_posix(const char *dir) {
  DIR *d = opendir(dir);
  if (!d) {
    return 0;
  }
  int n = 0;
  struct dirent *e;
  while ((e = readdir(d)) != NULL) {
    size_t len = strlen(e->d_name);
    if (len > 5 && strcmp(e->d_name + len - 5, ".onnx") == 0) {
      n++;
    }
  }
  closedir(d);
  return n;
}

static int edr_agent_process_running_posix(void) {
  DIR *d = opendir("/proc");
  if (!d) {
    return 0;
  }
  struct dirent *e;
  int found = 0;
  while ((e = readdir(d)) != NULL) {
    if (e->d_name[0] < '0' || e->d_name[0] > '9') {
      continue;
    }
    char path[256];
    snprintf(path, sizeof(path), "/proc/%s/comm", e->d_name);
    FILE *fp = fopen(path, "r");
    if (!fp) {
      continue;
    }
    char comm[64];
    if (fgets(comm, sizeof(comm), fp)) {
      size_t n = strcspn(comm, "\n\r");
      comm[n] = '\0';
      if (strcmp(comm, "edr_agent") == 0) {
        found = 1;
        fclose(fp);
        break;
      }
    }
    fclose(fp);
  }
  closedir(d);
  return found;
}
#endif

static long edr_file_size(const char *path) {
#ifdef _WIN32
  wchar_t w[MAX_PATH];
  if (MultiByteToWideChar(CP_UTF8, 0, path, -1, w, MAX_PATH) <= 0) {
    return -1;
  }
  WIN32_FILE_ATTRIBUTE_DATA fa;
  if (!GetFileAttributesExW(w, GetFileExInfoStandard, &fa)) {
    return -1;
  }
  LARGE_INTEGER li;
  li.HighPart = fa.nFileSizeHigh;
  li.LowPart = fa.nFileSizeLow;
  return (long)li.QuadPart;
#else
  struct stat st;
  if (stat(path, &st) != 0) {
    return -1;
  }
  return (long)st.st_size;
#endif
}

static int edr_load_snapshot(const char *path, EdrMonSnapshot *out, char *err, size_t errcap) {
  memset(out, 0, sizeof(*out));
  FILE *fp = fopen(path, "rb");
  if (!fp) {
    snprintf(err, errcap, "open %s: %s", path, strerror(errno));
    return -1;
  }
  char ebuf[256];
  toml_table_t *root = toml_parse_file(fp, ebuf, sizeof(ebuf));
  fclose(fp);
  if (!root) {
    snprintf(err, errcap, "toml: %s", ebuf);
    return -1;
  }
  toml_table_t *srv = toml_table_in(root, "server");
  toml_table_t *ag = toml_table_in(root, "agent");
  toml_table_t *pl = toml_table_in(root, "platform");
  toml_table_t *av = toml_table_in(root, "ave");
  toml_table_t *off = toml_table_in(root, "offline");
  if (srv) {
    (void)edr_toml_str(srv, "address", out->server_addr, sizeof(out->server_addr));
  }
  if (ag) {
    (void)edr_toml_str(ag, "endpoint_id", out->endpoint_id, sizeof(out->endpoint_id));
    (void)edr_toml_str(ag, "tenant_id", out->tenant_id, sizeof(out->tenant_id));
  }
  if (pl) {
    (void)edr_toml_str(pl, "rest_base_url", out->rest_base, sizeof(out->rest_base));
    {
      toml_datum_t b = toml_string_in(pl, "rest_bearer_token");
      out->bearer_set = (char)((b.ok && b.u.s && b.u.s[0]) ? 1 : 0);
      if (b.ok) {
        free(b.u.s);
      }
    }
  }
  if (av) {
    (void)edr_toml_str(av, "model_dir", out->model_dir, sizeof(out->model_dir));
  }
  if (off) {
    (void)edr_toml_str(off, "queue_db_path", out->queue_db, sizeof(out->queue_db));
  }
  toml_free(root);
  return 0;
}

static void print_usage(const char *p) {
  fprintf(stderr,
          "%s — EDR Agent terminal monitor (read-only probes; see EDR_端点详细设计 §1.2 / §14)\n"
          "\n"
          "Usage:\n"
          "  %s --config <agent.toml> [--json] [--no-probe]\n"
          "\n",
          p, p);
}

int main(int argc, char **argv) {
  const char *cfg = NULL;
  int json = 0;
  int probe = 1;
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
      cfg = argv[++i];
    } else if (strcmp(argv[i], "--json") == 0) {
      json = 1;
    } else if (strcmp(argv[i], "--no-probe") == 0) {
      probe = 0;
    } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
      print_usage(argv[0]);
      return 0;
    }
  }
  if (!cfg) {
    print_usage(argv[0]);
    return 2;
  }

  EdrMonSnapshot s;
  char err[512];
  if (edr_load_snapshot(cfg, &s, err, sizeof(err)) != 0) {
    fprintf(stderr, "%s\n", err);
    return 1;
  }

  char origin[EDR_MON_STR_CAP];
  edr_api_origin_from_rest_base(s.rest_base, origin, sizeof(origin));

  int tcp_ok = -1;
  int http_st = -1;
  char http_err[128];
  http_err[0] = '\0';
  int onnx_n = 0;
  long qbytes = -1;
  int agent_run = 0;

  char gh[EDR_MON_HOST_CAP];
  char gp[64];
  if (probe && s.server_addr[0] && edr_parse_host_port(s.server_addr, gh, sizeof(gh), gp, sizeof(gp))) {
#ifdef _WIN32
    tcp_ok = edr_tcp_probe_win(gh, gp);
#else
    tcp_ok = edr_tcp_probe_posix(gh, gp);
#endif
  }

  if (probe && origin[0]) {
#ifdef _WIN32
    {
      char url[EDR_MON_STR_CAP];
      snprintf(url, sizeof(url), "%s/healthz", origin);
      http_st = edr_http_get_status_win(url, http_err, sizeof(http_err));
    }
#else
    {
      char h[256], po[16], path[256];
      if (edr_parse_http_host_port_path(origin, h, sizeof(h), po, sizeof(po), path, sizeof(path))) {
        http_st = edr_http_probe_posix(h, po, path);
      } else {
        edr_strcpy(http_err, sizeof(http_err), "non-http origin");
        http_st = 0;
      }
    }
#endif
  }

  if (s.model_dir[0]) {
#ifdef _WIN32
    wchar_t wdir[MAX_PATH];
    if (edr_utf8_to_wide(s.model_dir, wdir, MAX_PATH) > 0) {
      onnx_n = edr_count_onnx_in_dir_win(wdir);
    }
#else
    onnx_n = edr_count_onnx_posix(s.model_dir);
#endif
  }

  if (s.queue_db[0]) {
    qbytes = edr_file_size(s.queue_db);
  }

#ifdef _WIN32
  agent_run = edr_agent_process_running_win();
#else
  agent_run = edr_agent_process_running_posix();
#endif

  if (json) {
    printf("{\n");
    printf("  \"config\": \"%s\",\n", cfg);
    printf("  \"server_address\": \"%s\",\n", s.server_addr);
    printf("  \"endpoint_id\": \"%s\",\n", s.endpoint_id);
    printf("  \"tenant_id\": \"%s\",\n", s.tenant_id);
    printf("  \"rest_base_url\": \"%s\",\n", s.rest_base);
    printf("  \"rest_bearer_configured\": %s,\n", s.bearer_set ? "true" : "false");
    printf("  \"model_dir\": \"%s\",\n", s.model_dir);
    printf("  \"onnx_files\": %d,\n", onnx_n);
    printf("  \"queue_db_path\": \"%s\",\n", s.queue_db);
    printf("  \"queue_db_bytes\": %ld,\n", qbytes);
    printf("  \"tcp_grpc_target_ok\": ");
    if (tcp_ok < 0) {
      printf("null");
    } else {
      printf("%s", tcp_ok ? "true" : "false");
    }
    printf(",\n");
    printf("  \"http_healthz_status\": %d,\n", http_st);
    printf("  \"edr_agent_process_running\": %s\n", agent_run ? "true" : "false");
    printf("}\n");
    return 0;
  }

  printf("=== EDR Monitor (design view: transport / engine / offline) ===\n");
  printf("config: %s\n\n", cfg);

  printf("[7 gRPC target — TCP connect to server.address]\n");
  if (!probe) {
    printf("  (probe disabled)\n");
  } else if (!s.server_addr[0]) {
    printf("  (missing [server].address)\n");
  } else {
    printf("  address=%s\n", s.server_addr);
    if (tcp_ok < 0) {
      printf("  probe: skipped (host:port parse error)\n");
    } else {
      printf("  tcp_connect: %s\n", tcp_ok ? "OK (port accepting)" : "FAIL");
    }
  }

  printf("\n[6 REST / platform — healthz on API origin]\n");
  printf("  rest_base_url=%s\n", s.rest_base[0] ? s.rest_base : "(unset)");
  printf("  api_origin=%s\n", origin[0] ? origin : "(n/a)");
  printf("  rest_bearer_token: %s\n", s.bearer_set ? "configured (value hidden)" : "(empty)");
  if (!probe) {
    printf("  GET .../healthz: (probe disabled)\n");
  } else if (!origin[0]) {
    printf("  GET .../healthz: (no rest_base_url — cannot derive API origin)\n");
  } else if (http_st >= 200 && http_st < 300) {
    printf("  GET .../healthz: HTTP %d OK\n", http_st);
  } else if (http_st > 0) {
    printf("  GET .../healthz: HTTP %d\n", http_st);
  } else {
#ifdef _WIN32
    printf("  GET .../healthz: fail (%s)\n", http_err[0] ? http_err : "no HTTP status");
#else
    if (strncmp(origin, "http://", 7) != 0) {
      printf("  GET .../healthz: (https origin — use Windows build of edr_monitor or curl)\n");
    } else {
      printf("  GET .../healthz: FAIL or unreachable (plain HTTP probe)\n");
    }
#endif
  }

  printf("\n[5 AVE — model_dir]\n");
  printf("  model_dir=%s\n", s.model_dir[0] ? s.model_dir : "(unset)");
  printf("  *.onnx count: %d\n", onnx_n);

  printf("\n[10 offline queue]\n");
  printf("  queue_db_path=%s\n", s.queue_db[0] ? s.queue_db : "(unset)");
  if (qbytes >= 0) {
    printf("  file size: %ld bytes\n", qbytes);
  } else if (s.queue_db[0]) {
    printf("  file: not found or unreadable\n");
  }

  printf("\n[process]\n");
  printf("  edr_agent running: %s\n", agent_run ? "yes" : "no");

  printf("\nNote: in-process event bus / preprocess counters require future agent IPC or logs.\n");
  return 0;
}
