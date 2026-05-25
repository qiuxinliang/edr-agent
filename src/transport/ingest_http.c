#include "edr/ingest_http.h"

#include "edr/command.h"
#include "edr/grpc_client.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <process.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#endif

#ifdef EDR_HAVE_OPENSSL_HTTP
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#endif

#ifdef _WIN32
typedef SOCKET EdrSocket;
#define EDR_SOCKET_INVALID INVALID_SOCKET
#else
typedef int EdrSocket;
#define EDR_SOCKET_INVALID (-1)
#endif

#ifndef EDR_AGENT_VERSION_STRING
#define EDR_AGENT_VERSION_STRING "0.3.0"
#endif

static char s_rest[512];
static char s_tenant[128];
static char s_user[128];
static char s_bearer[512];
static char s_endpoint[128];
static char s_agent_ver[64];
static char s_policy_version[64];
static char s_ca_file[1024];
static char s_client_cert_file[1024];
static char s_client_key_file[1024];
static char s_relay_url[512];
static char s_proxy_mode[32];
static char s_proxy_url_cfg[512];
static char s_proxy_url_active[512];
static char s_proxy_status[96];
static char s_connection_mode[32];
static unsigned long s_http_ok;
static unsigned long s_http_fail;
static int64_t s_last_success_ms;
static int64_t s_last_failure_ms;
static char s_last_error[160];
static int s_insecure_http;
static volatile int s_poll_backoff_ms;
static volatile int s_ws_backoff_ms;
static volatile int s_poll_run;
static int s_poll_started;
static volatile int s_ws_ready;
static int s_ws_started;
#ifdef _WIN32
static HANDLE s_poll_thread;
static HANDLE s_ws_thread;
static CRITICAL_SECTION s_ws_mu;
static int s_ws_mu_init;
#else
static pthread_t s_poll_thread;
static pthread_t s_ws_thread;
static pthread_mutex_t s_ws_mu = PTHREAD_MUTEX_INITIALIZER;
#endif

typedef struct EdrWsConn {
  EdrSocket fd;
#ifdef EDR_HAVE_OPENSSL_HTTP
  SSL_CTX *ctx;
  SSL *ssl;
#endif
} EdrWsConn;

static EdrWsConn *s_ws_conn;

static int64_t unix_ms_now(void) {
  return (int64_t)time(NULL) * 1000LL;
}

static void runtime_success(void) {
  s_http_ok++;
  s_last_success_ms = unix_ms_now();
  s_last_error[0] = '\0';
}

static void runtime_failure(const char *msg) {
  s_http_fail++;
  s_last_failure_ms = unix_ms_now();
  snprintf(s_last_error, sizeof(s_last_error), "%s", msg ? msg : "");
}

static void ws_mu_init_once(void) {
#ifdef _WIN32
  if (!s_ws_mu_init) {
    InitializeCriticalSection(&s_ws_mu);
    s_ws_mu_init = 1;
  }
#endif
}

static void ws_lock(void) {
  ws_mu_init_once();
#ifdef _WIN32
  EnterCriticalSection(&s_ws_mu);
#else
  pthread_mutex_lock(&s_ws_mu);
#endif
}

static void ws_unlock(void) {
#ifdef _WIN32
  LeaveCriticalSection(&s_ws_mu);
#else
  pthread_mutex_unlock(&s_ws_mu);
#endif
}

#ifdef EDR_HAVE_OPENSSL_HTTP
static void runtime_failure_openssl(const char *prefix) {
  unsigned long err = ERR_get_error();
  char msg[160];
  if (err != 0ul) {
    char detail[96];
    ERR_error_string_n(err, detail, sizeof(detail));
    snprintf(msg, sizeof(msg), "%s: %s", prefix ? prefix : "openssl failed", detail);
  } else {
    snprintf(msg, sizeof(msg), "%s", prefix ? prefix : "openssl failed");
  }
  runtime_failure(msg);
}
#endif

static void copy_base_url(char *dst, size_t cap, const char *url) {
  size_t n;
  if (!dst || cap == 0u) {
    return;
  }
  dst[0] = '\0';
  if (!url || !url[0]) {
    return;
  }
  snprintf(dst, cap, "%s", url);
  n = strlen(dst);
  while (n > 1u && dst[n - 1u] == '/') {
    dst[n - 1u] = '\0';
    n--;
  }
}

void edr_ingest_http_configure(const char *rest_base, const char *tenant_id, const char *user_id,
                                const char *bearer, const char *endpoint_id, const char *agent_version,
                                const char *ca_file, const char *client_cert_file,
                                const char *client_key_file, const char *proxy_mode,
                                const char *proxy_url, const char *relay_url) {
  const char *relay_effective = getenv("EDR_RELAY_URL");
  const char *proxy_mode_effective = getenv("EDR_PROXY_MODE");
  const char *proxy_url_effective = getenv("EDR_PROXY_URL");
  memset(s_rest, 0, sizeof(s_rest));
  memset(s_tenant, 0, sizeof(s_tenant));
  memset(s_user, 0, sizeof(s_user));
  memset(s_bearer, 0, sizeof(s_bearer));
  memset(s_endpoint, 0, sizeof(s_endpoint));
  memset(s_agent_ver, 0, sizeof(s_agent_ver));
  memset(s_ca_file, 0, sizeof(s_ca_file));
  memset(s_client_cert_file, 0, sizeof(s_client_cert_file));
  memset(s_client_key_file, 0, sizeof(s_client_key_file));
  memset(s_relay_url, 0, sizeof(s_relay_url));
  memset(s_proxy_mode, 0, sizeof(s_proxy_mode));
  memset(s_proxy_url_cfg, 0, sizeof(s_proxy_url_cfg));
  memset(s_proxy_url_active, 0, sizeof(s_proxy_url_active));
  memset(s_proxy_status, 0, sizeof(s_proxy_status));
  memset(s_connection_mode, 0, sizeof(s_connection_mode));
  if (!relay_effective || !relay_effective[0]) {
    relay_effective = relay_url;
  }
  if (!proxy_mode_effective || !proxy_mode_effective[0]) {
    proxy_mode_effective = proxy_mode;
  }
  if (!proxy_url_effective || !proxy_url_effective[0]) {
    proxy_url_effective = proxy_url;
  }
  copy_base_url(s_relay_url, sizeof(s_relay_url), relay_effective);
  copy_base_url(s_rest, sizeof(s_rest), s_relay_url[0] ? s_relay_url : rest_base);
  snprintf(s_connection_mode, sizeof(s_connection_mode), "%s", s_relay_url[0] ? "relay" : "direct");
  if (tenant_id && tenant_id[0]) {
    snprintf(s_tenant, sizeof(s_tenant), "%s", tenant_id);
  }
  if (user_id && user_id[0]) {
    snprintf(s_user, sizeof(s_user), "%s", user_id);
  }
  if (bearer && bearer[0]) {
    snprintf(s_bearer, sizeof(s_bearer), "%s", bearer);
  }
  if (endpoint_id && endpoint_id[0]) {
    snprintf(s_endpoint, sizeof(s_endpoint), "%s", endpoint_id);
  }
  if (agent_version && agent_version[0]) {
    snprintf(s_agent_ver, sizeof(s_agent_ver), "%s", agent_version);
  } else {
    snprintf(s_agent_ver, sizeof(s_agent_ver), "%s", EDR_AGENT_VERSION_STRING);
  }
  if (ca_file && ca_file[0]) {
    snprintf(s_ca_file, sizeof(s_ca_file), "%s", ca_file);
  }
  if (client_cert_file && client_cert_file[0]) {
    snprintf(s_client_cert_file, sizeof(s_client_cert_file), "%s", client_cert_file);
  }
  if (client_key_file && client_key_file[0]) {
    snprintf(s_client_key_file, sizeof(s_client_key_file), "%s", client_key_file);
  }
  snprintf(s_proxy_mode, sizeof(s_proxy_mode), "%s",
           (proxy_mode_effective && proxy_mode_effective[0]) ? proxy_mode_effective : "auto");
  copy_base_url(s_proxy_url_cfg, sizeof(s_proxy_url_cfg), proxy_url_effective);
  snprintf(s_proxy_status, sizeof(s_proxy_status), "%s", "not_used");
  s_insecure_http = (strncmp(s_rest, "http://", 7u) == 0) ? 1 : 0;
}

int edr_ingest_http_configured(void) { return s_rest[0] != 0 && s_endpoint[0] != 0; }

void edr_ingest_http_get_runtime(EdrIngestHttpRuntime *out) {
  if (!out) {
    return;
  }
  memset(out, 0, sizeof(*out));
  out->configured = edr_ingest_http_configured();
  out->http_fallback_available = out->configured;
  out->insecure_http = s_insecure_http;
  out->mtls_configured = (s_client_cert_file[0] && s_client_key_file[0]) ? 1 : 0;
  out->websocket_ready = s_ws_ready ? 1 : 0;
  out->poll_backoff_ms = s_poll_backoff_ms;
  out->ws_backoff_ms = s_ws_backoff_ms;
  out->ok_count = s_http_ok;
  out->fail_count = s_http_fail;
  out->last_success_unix_ms = s_last_success_ms;
  out->last_failure_unix_ms = s_last_failure_ms;
  snprintf(out->last_error, sizeof(out->last_error), "%s", s_last_error);
  snprintf(out->connection_mode, sizeof(out->connection_mode), "%s",
           s_connection_mode[0] ? s_connection_mode : "direct");
  snprintf(out->effective_base_url, sizeof(out->effective_base_url), "%s", s_rest);
  snprintf(out->relay_url, sizeof(out->relay_url), "%s", s_relay_url);
  snprintf(out->proxy_mode, sizeof(out->proxy_mode), "%s", s_proxy_mode[0] ? s_proxy_mode : "auto");
  snprintf(out->proxy_url, sizeof(out->proxy_url), "%s", s_proxy_url_active);
  snprintf(out->proxy_status, sizeof(out->proxy_status), "%s",
           s_proxy_status[0] ? s_proxy_status : "not_used");
}

void edr_ingest_http_set_policy_version(const char *policy_version) {
  memset(s_policy_version, 0, sizeof(s_policy_version));
  if (policy_version && policy_version[0]) {
    snprintf(s_policy_version, sizeof(s_policy_version), "%s", policy_version);
  }
}

void edr_ingest_http_copy_policy_version(char *out, size_t out_cap) {
  if (!out || out_cap == 0u) {
    return;
  }
  snprintf(out, out_cap, "%s", s_policy_version[0] ? s_policy_version : "local");
}

static int b64_encode(const uint8_t *in, size_t len, char *out, size_t cap) {
  static const char tbl[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  size_t o = 0;
  for (size_t i = 0; i < len; i += 3u) {
    size_t rem = len - i;
    uint32_t b = (uint32_t)in[i] << 16;
    if (rem >= 2u) {
      b |= (uint32_t)in[i + 1u] << 8;
    }
    if (rem >= 3u) {
      b |= (uint32_t)in[i + 2u];
    }
    if (o + 4u >= cap) {
      return -1;
    }
    out[o++] = tbl[(b >> 18) & 63u];
    out[o++] = tbl[(b >> 12) & 63u];
    if (rem >= 2u) {
      out[o++] = tbl[(b >> 6) & 63u];
    } else {
      out[o++] = '=';
    }
    if (rem >= 3u) {
      out[o++] = tbl[b & 63u];
    } else {
      out[o++] = '=';
    }
  }
  if (o >= cap) {
    return -1;
  }
  out[o] = 0;
  return (int)o;
}

static int b64_value(unsigned char c) {
  if (c >= 'A' && c <= 'Z') return (int)(c - 'A');
  if (c >= 'a' && c <= 'z') return (int)(c - 'a') + 26;
  if (c >= '0' && c <= '9') return (int)(c - '0') + 52;
  if (c == '+') return 62;
  if (c == '/') return 63;
  if (c == '=') return -2;
  return -1;
}

static int b64_decode_alloc(const char *in, uint8_t **out, size_t *out_len) {
  size_t len;
  size_t cap;
  uint8_t *buf;
  size_t o = 0;
  int vals[4];
  int vi = 0;
  if (!in || !out || !out_len) {
    return -1;
  }
  *out = NULL;
  *out_len = 0;
  len = strlen(in);
  cap = (len / 4u + 1u) * 3u + 8u;
  buf = (uint8_t *)malloc(cap);
  if (!buf) {
    return -1;
  }
  for (size_t i = 0; i < len; i++) {
    int v;
    unsigned char c = (unsigned char)in[i];
    if (c == '\r' || c == '\n' || c == ' ' || c == '\t') {
      continue;
    }
    v = b64_value(c);
    if (v < -1) {
      vals[vi++] = v;
    } else if (v >= 0) {
      vals[vi++] = v;
    } else {
      free(buf);
      return -1;
    }
    if (vi == 4) {
      if (o + 3u > cap) {
        free(buf);
        return -1;
      }
      buf[o++] = (uint8_t)((vals[0] << 2) | ((vals[1] & 0x30) >> 4));
      if (vals[2] != -2) {
        buf[o++] = (uint8_t)(((vals[1] & 0x0f) << 4) | ((vals[2] & 0x3c) >> 2));
      }
      if (vals[3] != -2) {
        buf[o++] = (uint8_t)(((vals[2] & 0x03) << 6) | vals[3]);
      }
      vi = 0;
    }
  }
  if (vi != 0) {
    free(buf);
    return -1;
  }
  *out = buf;
  *out_len = o;
  return 0;
}

static void json_escape_buf(char *dst, size_t cap, const char *s) {
  size_t o = 0;
  if (!dst || cap == 0u) {
    return;
  }
  if (!s) {
    s = "";
  }
  for (; *s && o + 2u < cap; s++) {
    unsigned char c = (unsigned char)*s;
    if (c == '"' || c == '\\') {
      dst[o++] = '\\';
      dst[o++] = (char)c;
    } else if (c == '\n') {
      dst[o++] = '\\';
      dst[o++] = 'n';
    } else if (c == '\r') {
      dst[o++] = '\\';
      dst[o++] = 'r';
    } else if (c == '\t') {
      dst[o++] = '\\';
      dst[o++] = 't';
    } else if (c < 0x20u) {
      dst[o++] = ' ';
    } else {
      dst[o++] = (char)c;
    }
  }
  dst[o < cap ? o : cap - 1u] = '\0';
}

static char *json_escape_alloc(const char *s) {
  size_t len = s ? strlen(s) : 0u;
  size_t cap = len * 2u + 32u;
  char *out = (char *)malloc(cap);
  if (!out) {
    return NULL;
  }
  json_escape_buf(out, cap, s ? s : "");
  return out;
}

static int json_get_string(const char *obj, const char *key, char *out, size_t cap) {
  char needle[96];
  const char *p;
  const char *q;
  size_t o = 0;
  if (!obj || !key || !out || cap == 0u) {
    return -1;
  }
  out[0] = '\0';
  snprintf(needle, sizeof(needle), "\"%s\"", key);
  p = strstr(obj, needle);
  if (!p) {
    return -1;
  }
  p += strlen(needle);
  while (*p && isspace((unsigned char)*p)) p++;
  if (*p != ':') {
    return -1;
  }
  p++;
  while (*p && isspace((unsigned char)*p)) p++;
  if (*p != '"') {
    return -1;
  }
  q = p + 1;
  while (*q && o + 1u < cap) {
    char c = *q++;
    if (c == '\\' && *q) {
      char e = *q++;
      if (e == 'n') c = '\n';
      else if (e == 'r') c = '\r';
      else if (e == 't') c = '\t';
      else c = e;
    } else if (c == '"') {
      out[o] = '\0';
      return 0;
    }
    out[o++] = c;
  }
  out[o] = '\0';
  return (*q == '"') ? 0 : -1;
}

static int json_get_int64(const char *obj, const char *key, int64_t *out) {
  char needle[96];
  const char *p;
  char *endp = NULL;
  if (!obj || !key || !out) {
    return -1;
  }
  snprintf(needle, sizeof(needle), "\"%s\"", key);
  p = strstr(obj, needle);
  if (!p) {
    return -1;
  }
  p += strlen(needle);
  while (*p && isspace((unsigned char)*p)) p++;
  if (*p != ':') {
    return -1;
  }
  p++;
  while (*p && (isspace((unsigned char)*p) || *p == '"')) p++;
  *out = (int64_t)strtoll(p, &endp, 10);
  return (endp && endp != p) ? 0 : -1;
}

static int is_local_or_private_host(const char *host) {
  if (!host || !host[0]) {
    return 0;
  }
  if (strcmp(host, "localhost") == 0 || strcmp(host, "127.0.0.1") == 0 || strcmp(host, "::1") == 0) {
    return 1;
  }
  if (strncmp(host, "10.", 3u) == 0 || strncmp(host, "192.168.", 8u) == 0) {
    return 1;
  }
  if (strncmp(host, "172.", 4u) == 0) {
    int b = atoi(host + 4);
    if (b >= 16 && b <= 31) {
      return 1;
    }
  }
  return 0;
}

static int parse_url(const char *url, char *host, size_t host_cap, char *path, size_t path_cap,
                     int *out_port, int *out_https) {
  const char *p = NULL;
  const char *slash = NULL;
  const char *colon = NULL;
  size_t host_len = 0;
  if (!url || !host || !path || !out_port || !out_https) {
    return -1;
  }
  *out_https = 0;
  *out_port = 80;
  if (strncmp(url, "https://", 8u) == 0) {
    p = url + 8u;
    *out_https = 1;
    *out_port = 443;
  } else if (strncmp(url, "http://", 7u) == 0) {
    p = url + 7u;
  } else {
    return -1;
  }
  slash = strchr(p, '/');
  colon = strchr(p, ':');
  if (colon && (!slash || colon < slash)) {
    host_len = (size_t)(colon - p);
    if (host_len == 0u || host_len >= host_cap) {
      return -1;
    }
    memcpy(host, p, host_len);
    host[host_len] = '\0';
    *out_port = atoi(colon + 1);
  } else {
    host_len = slash ? (size_t)(slash - p) : strlen(p);
    if (host_len == 0u || host_len >= host_cap) {
      return -1;
    }
    memcpy(host, p, host_len);
    host[host_len] = '\0';
  }
  snprintf(path, path_cap, "%s", slash ? slash : "/");
  if (*out_port <= 0 || *out_port > 65535) {
    return -1;
  }
  return 0;
}

typedef struct {
  int active;
  char url[512];
  char host[256];
  int port;
} EdrProxyRoute;

static int ascii_eq_ci(const char *a, const char *b) {
  if (!a || !b) {
    return 0;
  }
  while (*a && *b) {
    if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) {
      return 0;
    }
    a++;
    b++;
  }
  return *a == 0 && *b == 0;
}

static void set_proxy_status(const char *status, const char *active_url) {
  snprintf(s_proxy_status, sizeof(s_proxy_status), "%s", status ? status : "");
  if (active_url && active_url[0]) {
    snprintf(s_proxy_url_active, sizeof(s_proxy_url_active), "%s", active_url);
  } else {
    s_proxy_url_active[0] = '\0';
  }
}

static int host_suffix_match_ci(const char *host, const char *suffix) {
  size_t hl;
  size_t sl;
  if (!host || !suffix || !host[0] || !suffix[0]) {
    return 0;
  }
  while (*suffix == '.') {
    suffix++;
  }
  hl = strlen(host);
  sl = strlen(suffix);
  if (sl == 0u || sl > hl) {
    return 0;
  }
  if (!ascii_eq_ci(host + hl - sl, suffix)) {
    return 0;
  }
  return hl == sl || host[hl - sl - 1u] == '.';
}

static int no_proxy_matches(const char *host) {
  const char *np = getenv("NO_PROXY");
  char buf[1024];
  char *p;
  if (!np || !np[0]) {
    np = getenv("no_proxy");
  }
  if (!np || !np[0] || !host || !host[0]) {
    return 0;
  }
  snprintf(buf, sizeof(buf), "%s", np);
  p = buf;
  while (*p) {
    char *tok = p;
    char *end;
    while (*p && *p != ',') {
      p++;
    }
    if (*p == ',') {
      *p++ = '\0';
    }
    while (*tok && isspace((unsigned char)*tok)) {
      tok++;
    }
    end = tok + strlen(tok);
    {
      while (end > tok && isspace((unsigned char)end[-1])) {
        *--end = '\0';
      }
    }
    if (strcmp(tok, "*") == 0 || ascii_eq_ci(tok, host) || host_suffix_match_ci(host, tok)) {
      return 1;
    }
  }
  return 0;
}

static const char *proxy_env_for_scheme(int https) {
  const char *v = NULL;
  if (https) {
    v = getenv("EDR_HTTPS_PROXY");
    if (!v || !v[0]) v = getenv("HTTPS_PROXY");
    if (!v || !v[0]) v = getenv("https_proxy");
  }
  if (!v || !v[0]) v = getenv("EDR_HTTP_PROXY");
  if (!v || !v[0]) v = getenv("HTTP_PROXY");
  if (!v || !v[0]) v = getenv("http_proxy");
  if (!v || !v[0]) v = getenv("ALL_PROXY");
  if (!v || !v[0]) v = getenv("all_proxy");
  return (v && v[0]) ? v : NULL;
}

static int parse_proxy_url(const char *url, EdrProxyRoute *out) {
  const char *p;
  const char *slash;
  const char *at;
  const char *colon;
  size_t host_len;
  if (!url || !url[0] || !out) {
    return -1;
  }
  memset(out, 0, sizeof(*out));
  if (strncmp(url, "http://", 7u) == 0) {
    p = url + 7u;
    out->port = 80;
  } else {
    return -1;
  }
  slash = strchr(p, '/');
  at = strchr(p, '@');
  if (at && (!slash || at < slash)) {
    p = at + 1;
  }
  slash = strchr(p, '/');
  colon = strchr(p, ':');
  if (colon && (!slash || colon < slash)) {
    host_len = (size_t)(colon - p);
    out->port = atoi(colon + 1);
  } else {
    host_len = slash ? (size_t)(slash - p) : strlen(p);
  }
  if (host_len == 0u || host_len >= sizeof(out->host) || out->port <= 0 || out->port > 65535) {
    return -1;
  }
  memcpy(out->host, p, host_len);
  out->host[host_len] = '\0';
  snprintf(out->url, sizeof(out->url), "http://%s:%d", out->host, out->port);
  out->active = 1;
  return 0;
}

static int resolve_proxy_route(int https, const char *host, EdrProxyRoute *out) {
  const char *mode = s_proxy_mode[0] ? s_proxy_mode : "auto";
  const char *url = NULL;
  if (!out) {
    return 0;
  }
  memset(out, 0, sizeof(*out));
  if (ascii_eq_ci(mode, "off") || ascii_eq_ci(mode, "none") || ascii_eq_ci(mode, "direct")) {
    set_proxy_status("disabled", NULL);
    return 0;
  }
  if (host && no_proxy_matches(host)) {
    set_proxy_status("bypass:no_proxy", NULL);
    return 0;
  }
  if (s_proxy_url_cfg[0]) {
    url = s_proxy_url_cfg;
  } else if (ascii_eq_ci(mode, "auto") || ascii_eq_ci(mode, "wpad")) {
    url = proxy_env_for_scheme(https);
  }
  if (!url || !url[0]) {
    set_proxy_status(ascii_eq_ci(mode, "explicit") ? "explicit:missing" : "auto:none", NULL);
    return 0;
  }
  if (parse_proxy_url(url, out) != 0) {
    set_proxy_status("invalid", NULL);
    return ascii_eq_ci(mode, "explicit") ? -1 : 0;
  }
  set_proxy_status(s_proxy_url_cfg[0] ? "explicit" : "auto:env", out->url);
  return 0;
}

static int net_init(void) {
#ifdef _WIN32
  WSADATA w;
  return WSAStartup(MAKEWORD(2, 2), &w);
#else
  return 0;
#endif
}

static void net_done(void) {
#ifdef _WIN32
  WSACleanup();
#endif
}

static void close_fd(EdrSocket fd) {
#ifdef _WIN32
  closesocket(fd);
#else
  close(fd);
#endif
}

static int tcp_connect_host(const char *host, int port, EdrSocket *out_fd) {
  struct addrinfo hints;
  struct addrinfo *res = NULL;
  struct addrinfo *rp = NULL;
  char portstr[16];
  EdrSocket fd = EDR_SOCKET_INVALID;
  memset(&hints, 0, sizeof(hints));
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_family = AF_UNSPEC;
  snprintf(portstr, sizeof(portstr), "%d", port);
  if (getaddrinfo(host, portstr, &hints, &res) != 0 || !res) {
    return -1;
  }
  for (rp = res; rp; rp = rp->ai_next) {
#ifdef _WIN32
    fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
#else
    fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
#endif
    if (fd == EDR_SOCKET_INVALID) {
      continue;
    }
    if (connect(fd, rp->ai_addr, (int)rp->ai_addrlen) == 0) {
      break;
    }
    close_fd(fd);
    fd = EDR_SOCKET_INVALID;
  }
  freeaddrinfo(res);
  if (fd == EDR_SOCKET_INVALID) {
    return -1;
  }
  *out_fd = fd;
  return 0;
}

static void socket_set_timeout_ms(EdrSocket fd, int ms) {
  if (fd == EDR_SOCKET_INVALID || ms <= 0) {
    return;
  }
#ifdef _WIN32
  DWORD tv = (DWORD)ms;
  (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
  (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char *)&tv, sizeof(tv));
#else
  struct timeval tv;
  tv.tv_sec = ms / 1000;
  tv.tv_usec = (ms % 1000) * 1000;
  (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif
}

static int write_all_plain(EdrSocket fd, const char *p, size_t n) {
  size_t off = 0;
  while (off < n) {
#ifdef _WIN32
    int w = send(fd, p + off, (int)(n - off), 0);
#else
    ssize_t w = send(fd, p + off, n - off, 0);
#endif
    if (w <= 0) {
      return -1;
    }
    off += (size_t)w;
  }
  return 0;
}

static int read_status_plain(EdrSocket fd) {
  char buf[256];
#ifdef _WIN32
  int n = recv(fd, buf, (int)sizeof(buf) - 1, 0);
#else
  ssize_t n = recv(fd, buf, sizeof(buf) - 1, 0);
#endif
  if (n <= 0) {
    return -1;
  }
  buf[n] = '\0';
  return (strncmp(buf, "HTTP/1.1 2", 10u) == 0 || strncmp(buf, "HTTP/1.0 2", 10u) == 0) ? 0 : -1;
}

static int tcp_connect_http_route(const char *host, int port, int https, EdrSocket *out_fd) {
  EdrProxyRoute proxy;
  char req[512];
  int rn;
  if (!out_fd) {
    return -1;
  }
  *out_fd = EDR_SOCKET_INVALID;
  if (resolve_proxy_route(https, host, &proxy) != 0) {
    runtime_failure("proxy configuration invalid");
    return -1;
  }
  if (!proxy.active) {
    return tcp_connect_host(host, port, out_fd);
  }
  if (!https) {
    runtime_failure("http proxy only supports HTTPS CONNECT in this build");
    return -1;
  }
  if (tcp_connect_host(proxy.host, proxy.port, out_fd) != 0) {
    runtime_failure("proxy tcp connect failed");
    return -1;
  }
  rn = snprintf(req, sizeof(req),
                "CONNECT %s:%d HTTP/1.1\r\n"
                "Host: %s:%d\r\n"
                "Proxy-Connection: Keep-Alive\r\n\r\n",
                host, port, host, port);
  if (rn <= 0 || (size_t)rn >= sizeof(req) ||
      write_all_plain(*out_fd, req, (size_t)rn) != 0 ||
      read_status_plain(*out_fd) != 0) {
    runtime_failure("proxy CONNECT failed");
    close_fd(*out_fd);
    *out_fd = EDR_SOCKET_INVALID;
    return -1;
  }
  return 0;
}

static int append_common_headers(char *req, size_t cap, size_t used) {
  int n;
  if (used >= cap) {
    return -1;
  }
  n = snprintf(req + used, cap - used,
               "X-Tenant-ID: %s\r\n"
               "X-User-ID: %s\r\n"
               "X-Permission-Set: telemetry:write\r\n",
               s_tenant[0] ? s_tenant : "demo-tenant",
               s_user[0] ? s_user : "edr-agent");
  if (n <= 0 || (size_t)n >= cap - used) {
    return -1;
  }
  used += (size_t)n;
  if (s_bearer[0]) {
    n = snprintf(req + used, cap - used, "Authorization: Bearer %s\r\n", s_bearer);
    if (n <= 0 || (size_t)n >= cap - used) {
      return -1;
    }
    used += (size_t)n;
  }
  return (int)used;
}

static int append_request_headers(char *req, size_t cap, const char *method, const char *path,
                                  const char *host, const char *content_type, size_t body_len) {
  int n;
  size_t used;
  n = snprintf(req, cap, "%s %s HTTP/1.1\r\nHost: %s\r\n", method, path, host);
  if (n <= 0 || (size_t)n >= cap) {
    return -1;
  }
  used = (size_t)n;
  if (content_type && content_type[0]) {
    n = snprintf(req + used, cap - used, "Content-Type: %s\r\n", content_type);
    if (n <= 0 || (size_t)n >= cap - used) {
      return -1;
    }
    used += (size_t)n;
  }
  if (body_len > 0u || strcmp(method, "POST") == 0) {
    n = snprintf(req + used, cap - used, "Content-Length: %zu\r\n", body_len);
    if (n <= 0 || (size_t)n >= cap - used) {
      return -1;
    }
    used += (size_t)n;
  }
  n = append_common_headers(req, cap, used);
  if (n <= 0) {
    return -1;
  }
  used = (size_t)n;
  n = snprintf(req + used, cap - used, "Connection: close\r\n\r\n");
  if (n <= 0 || (size_t)n >= cap - used) {
    return -1;
  }
  return (int)(used + (size_t)n);
}

static int read_http_response_from_recv(int (*recvfn)(void *ctx, char *buf, int cap), void *ctx,
                                        char *body, size_t body_cap) {
  char resp[8192];
  size_t used = 0;
  int status_ok = 0;
  int saw_header = 0;
  size_t body_used = 0;
  if (body && body_cap > 0u) {
    body[0] = '\0';
  }
  for (;;) {
    int n = recvfn(ctx, resp + used, (int)(sizeof(resp) - 1u - used));
    char *hdr;
    char *body_start;
    size_t chunk_body_len;
    if (n <= 0) {
      break;
    }
    used += (size_t)n;
    resp[used] = '\0';
    if (!saw_header) {
      hdr = strstr(resp, "\r\n\r\n");
      if (!hdr) {
        if (used >= sizeof(resp) - 1u) {
          return -1;
        }
        continue;
      }
      status_ok = (strncmp(resp, "HTTP/1.1 2", 10u) == 0 || strncmp(resp, "HTTP/1.0 2", 10u) == 0);
      saw_header = 1;
      body_start = hdr + 4;
      chunk_body_len = used - (size_t)(body_start - resp);
      if (body && body_cap > 0u && chunk_body_len > 0u) {
        size_t copy = chunk_body_len;
        if (copy > body_cap - 1u - body_used) {
          copy = body_cap - 1u - body_used;
        }
        memcpy(body + body_used, body_start, copy);
        body_used += copy;
        body[body_used] = '\0';
      }
      used = 0;
    } else if (body && body_cap > 0u) {
      size_t copy = (size_t)n;
      if (copy > body_cap - 1u - body_used) {
        copy = body_cap - 1u - body_used;
      }
      if (copy > 0u) {
        memcpy(body + body_used, resp, copy);
        body_used += copy;
        body[body_used] = '\0';
      }
      used = 0;
    } else {
      used = 0;
    }
  }
  return saw_header && status_ok ? 0 : -1;
}

static int plain_recv_adapter(void *ctx, char *buf, int cap) {
#ifdef _WIN32
  return recv(*(EdrSocket *)ctx, buf, cap, 0);
#else
  return (int)recv(*(EdrSocket *)ctx, buf, (size_t)cap, 0);
#endif
}

#ifdef EDR_HAVE_OPENSSL_HTTP
static int ssl_recv_adapter(void *ctx, char *buf, int cap) {
  return SSL_read((SSL *)ctx, buf, cap);
}

static int write_all_ssl(SSL *ssl, const char *p, size_t n) {
  size_t off = 0;
  while (off < n) {
    int w = SSL_write(ssl, p + off, (int)(n - off));
    if (w <= 0) {
      return -1;
    }
    off += (size_t)w;
  }
  return 0;
}

static SSL_CTX *new_https_ctx(char *active_cafile, size_t active_cafile_cap) {
  SSL_CTX *ctx;
  if (active_cafile && active_cafile_cap > 0u) {
    active_cafile[0] = '\0';
  }
  OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
  ctx = SSL_CTX_new(TLS_client_method());
  if (!ctx) {
    runtime_failure_openssl("https ssl ctx failed");
    return NULL;
  }
  {
    const char *cafile = getenv("EDR_INGEST_HTTPS_CA_FILE");
    if (!cafile || !cafile[0]) {
      cafile = s_ca_file;
    }
    if (cafile && cafile[0]) {
      if (active_cafile && active_cafile_cap > 0u) {
        snprintf(active_cafile, active_cafile_cap, "%s", cafile);
      }
      if (SSL_CTX_load_verify_locations(ctx, cafile, NULL) != 1) {
        char msg[160];
        snprintf(msg, sizeof(msg), "https ca load failed: %s", cafile);
        runtime_failure(msg);
        SSL_CTX_free(ctx);
        return NULL;
      }
    } else if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
      runtime_failure_openssl("https default ca load failed");
      SSL_CTX_free(ctx);
      return NULL;
    }
  }
  if (s_client_cert_file[0] && s_client_key_file[0]) {
    if (SSL_CTX_use_certificate_file(ctx, s_client_cert_file, SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_use_PrivateKey_file(ctx, s_client_key_file, SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_check_private_key(ctx) != 1) {
      runtime_failure("https client certificate load failed");
      SSL_CTX_free(ctx);
      return NULL;
    }
  }
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
  return ctx;
}
#endif

static int append_headers(char *req, size_t cap, const char *path, const char *host,
                          const char *body, size_t body_len) {
  int n = snprintf(req, cap,
                   "POST %s HTTP/1.1\r\n"
                   "Host: %s\r\n"
                   "Content-Type: application/json\r\n"
                   "Content-Length: %zu\r\n"
                   "X-Tenant-ID: %s\r\n"
                   "X-User-ID: %s\r\n"
                   "X-Permission-Set: telemetry:write\r\n",
                   path, host, body_len, s_tenant[0] ? s_tenant : "demo-tenant",
                   s_user[0] ? s_user : "edr-agent");
  if (n <= 0 || (size_t)n >= cap) {
    return -1;
  }
  if (s_bearer[0]) {
    size_t used = (size_t)n;
    int m = snprintf(req + used, cap - used, "Authorization: Bearer %s\r\n", s_bearer);
    if (m <= 0 || (size_t)m >= cap - used) {
      return -1;
    }
    n += m;
  }
  {
    size_t used = (size_t)n;
    int m = snprintf(req + used, cap - used, "Connection: close\r\n\r\n");
    if (m <= 0 || (size_t)m >= cap - used) {
      return -1;
    }
    n += m;
  }
  (void)body;
  return n;
}

#ifdef EDR_HAVE_OPENSSL_HTTP
static int post_https_openssl(const char *host, int port, const char *path, const char *body, size_t body_len) {
  EdrSocket fd = EDR_SOCKET_INVALID;
  int ret = -1;
  SSL_CTX *ctx = NULL;
  SSL *ssl = NULL;
  char req[8192];
  char active_cafile[1024];
  int rn = append_headers(req, sizeof(req), path, host, body, body_len);
  if (rn <= 0) {
    return -1;
  }
  ctx = new_https_ctx(active_cafile, sizeof(active_cafile));
  if (!ctx) {
    return -1;
  }
  if (tcp_connect_http_route(host, port, 1, &fd) != 0) {
    runtime_failure("https tcp connect failed");
    goto done;
  }
  ssl = SSL_new(ctx);
  if (!ssl) {
    runtime_failure_openssl("https ssl new failed");
    goto done;
  }
#ifdef _WIN32
  SSL_set_fd(ssl, (int)fd);
#else
  SSL_set_fd(ssl, fd);
#endif
  (void)SSL_set_tlsext_host_name(ssl, host);
  if (SSL_connect(ssl) != 1) {
    long verify = SSL_get_verify_result(ssl);
    if (verify != X509_V_OK) {
      char msg[160];
      snprintf(msg, sizeof(msg), "https tls verify failed: %s ca=%s",
               X509_verify_cert_error_string(verify),
               active_cafile[0] ? active_cafile : "<default>");
      runtime_failure(msg);
    } else {
      runtime_failure_openssl("https tls connect failed");
    }
    goto done;
  }
  if (write_all_ssl(ssl, req, (size_t)rn) != 0 ||
      (body_len > 0u && write_all_ssl(ssl, body, body_len) != 0)) {
    runtime_failure_openssl("https write failed");
    goto done;
  }
  {
    char resp[256];
    int n = SSL_read(ssl, resp, (int)sizeof(resp) - 1);
    if (n > 0) {
      resp[n] = '\0';
      ret = (strncmp(resp, "HTTP/1.1 2", 10u) == 0 || strncmp(resp, "HTTP/1.0 2", 10u) == 0) ? 0 : -1;
      if (ret != 0) {
        char *eol = strstr(resp, "\r\n");
        if (eol) {
          *eol = '\0';
        }
        {
          char msg[160];
          snprintf(msg, sizeof(msg), "https http status: %s", resp);
          runtime_failure(msg);
        }
      }
    } else {
      runtime_failure_openssl("https read failed");
    }
  }
done:
  if (ssl) {
    SSL_shutdown(ssl);
    SSL_free(ssl);
  }
  if (fd != EDR_SOCKET_INVALID) {
    close_fd(fd);
  }
  if (ctx) {
    SSL_CTX_free(ctx);
  }
  return ret;
}
#endif

static int native_post_json(const char *url, const char *body, size_t body_len) {
  char host[256];
  char path[1024];
  int port = 0;
  int https = 0;
  EdrSocket fd = EDR_SOCKET_INVALID;
  int rc = -1;
  char req[8192];
  if (parse_url(url, host, sizeof(host), path, sizeof(path), &port, &https) != 0) {
    runtime_failure("invalid ingest url");
    return -1;
  }
  if (!https) {
    const char *allow = getenv("EDR_ALLOW_INSECURE_HTTP");
    if ((!allow || allow[0] != '1') && !is_local_or_private_host(host)) {
      runtime_failure("plain http denied for non-local host");
      return -1;
    }
  }
  if (net_init() != 0) {
    runtime_failure("network init failed");
    return -1;
  }
  if (https) {
#ifdef EDR_HAVE_OPENSSL_HTTP
    rc = post_https_openssl(host, port, path, body, body_len);
#else
    runtime_failure("https requested but OpenSSL disabled");
    rc = -1;
#endif
    net_done();
    return rc;
  }
  {
    int rn = append_headers(req, sizeof(req), path, host, body, body_len);
    if (rn <= 0 || tcp_connect_host(host, port, &fd) != 0) {
      runtime_failure("http connect failed");
      net_done();
      return -1;
    }
    if (write_all_plain(fd, req, (size_t)rn) == 0 &&
        (body_len == 0u || write_all_plain(fd, body, body_len) == 0) &&
        read_status_plain(fd) == 0) {
      rc = 0;
    }
    close_fd(fd);
  }
  net_done();
  if (rc != 0) {
    runtime_failure("http post failed");
  }
  return rc;
}

static int native_request(const char *method, const char *url, const char *content_type,
                          const char *body, size_t body_len, char *resp_body,
                          size_t resp_body_cap) {
  char host[256];
  char path[1024];
  int port = 0;
  int https = 0;
  EdrSocket fd = EDR_SOCKET_INVALID;
  int rc = -1;
  char req[8192];
  int rn;
  if (parse_url(url, host, sizeof(host), path, sizeof(path), &port, &https) != 0) {
    runtime_failure("invalid ingest url");
    return -1;
  }
  if (!https) {
    const char *allow = getenv("EDR_ALLOW_INSECURE_HTTP");
    if ((!allow || allow[0] != '1') && !is_local_or_private_host(host)) {
      runtime_failure("plain http denied for non-local host");
      return -1;
    }
  }
  if (net_init() != 0) {
    runtime_failure("network init failed");
    return -1;
  }
  rn = append_request_headers(req, sizeof(req), method, path, host, content_type, body_len);
  if (rn <= 0) {
    runtime_failure("http request build failed");
    net_done();
    return -1;
  }
  if (https) {
#ifdef EDR_HAVE_OPENSSL_HTTP
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    char active_cafile[1024];
    ctx = new_https_ctx(active_cafile, sizeof(active_cafile));
    if (!ctx) {
      net_done();
      return -1;
    }
    if (tcp_connect_http_route(host, port, 1, &fd) != 0) {
      runtime_failure("https tcp connect failed");
      SSL_CTX_free(ctx);
      net_done();
      return -1;
    }
    ssl = SSL_new(ctx);
    if (!ssl) {
      runtime_failure_openssl("https ssl new failed");
      close_fd(fd);
      SSL_CTX_free(ctx);
      net_done();
      return -1;
    }
#ifdef _WIN32
    SSL_set_fd(ssl, (int)fd);
#else
    SSL_set_fd(ssl, fd);
#endif
    (void)SSL_set_tlsext_host_name(ssl, host);
    if (SSL_connect(ssl) == 1 &&
        write_all_ssl(ssl, req, (size_t)rn) == 0 &&
        (body_len == 0u || write_all_ssl(ssl, body, body_len) == 0) &&
        read_http_response_from_recv(ssl_recv_adapter, ssl, resp_body, resp_body_cap) == 0) {
      rc = 0;
    } else if (!s_last_error[0]) {
      long verify = SSL_get_verify_result(ssl);
      if (verify != X509_V_OK) {
        char msg[160];
        snprintf(msg, sizeof(msg), "https tls verify failed: %s ca=%s",
                 X509_verify_cert_error_string(verify),
                 active_cafile[0] ? active_cafile : "<default>");
        runtime_failure(msg);
      } else {
        runtime_failure_openssl("https request failed");
      }
    }
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close_fd(fd);
    SSL_CTX_free(ctx);
#else
    runtime_failure("https requested but OpenSSL disabled");
    rc = -1;
#endif
    net_done();
    return rc;
  }
  if (tcp_connect_host(host, port, &fd) != 0) {
    runtime_failure("http connect failed");
    net_done();
    return -1;
  }
  if (write_all_plain(fd, req, (size_t)rn) == 0 &&
      (body_len == 0u || write_all_plain(fd, body, body_len) == 0) &&
      read_http_response_from_recv(plain_recv_adapter, &fd, resp_body, resp_body_cap) == 0) {
    rc = 0;
  }
  close_fd(fd);
  net_done();
  if (rc != 0 && !s_last_error[0]) {
    runtime_failure("http request failed");
  }
  return rc;
}

static int request_to_suffix(const char *method, const char *suffix, const char *content_type,
                             const char *body, size_t body_len, char *resp_body,
                             size_t resp_body_cap) {
  char url[1400];
  size_t rb = strlen(s_rest);
  snprintf(url, sizeof(url), "%s%s%s", s_rest, (rb > 0u && s_rest[rb - 1u] == '/') ? "" : "/", suffix);
  return native_request(method, url, content_type, body, body_len, resp_body, resp_body_cap);
}

static int ws_recv_some(EdrWsConn *c, char *buf, int cap) {
  if (!c || cap <= 0) {
    return -1;
  }
#ifdef EDR_HAVE_OPENSSL_HTTP
  if (c->ssl) {
    int n = SSL_read(c->ssl, buf, cap);
    if (n > 0) {
      return n;
    }
    {
      int e = SSL_get_error(c->ssl, n);
      if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) {
        return -2;
      }
    }
    return -1;
  }
#endif
#ifdef _WIN32
  {
    int n = recv(c->fd, buf, cap, 0);
    if (n < 0) {
      int e = WSAGetLastError();
      if (e == WSAETIMEDOUT || e == WSAEWOULDBLOCK) {
        return -2;
      }
    }
    return n;
  }
#else
  {
    ssize_t n = recv(c->fd, buf, (size_t)cap, 0);
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      return -2;
    }
    return (int)n;
  }
#endif
}

static int ws_read_exact(EdrWsConn *c, uint8_t *buf, size_t len) {
  size_t off = 0;
  while (off < len && s_poll_run) {
    int n = ws_recv_some(c, (char *)buf + off, (int)(len - off));
    if (n == -2) {
      if (off == 0u) {
        return -2;
      }
      continue;
    }
    if (n <= 0) {
      return -1;
    }
    off += (size_t)n;
  }
  return off == len ? 0 : -1;
}

static int ws_write_all(EdrWsConn *c, const uint8_t *buf, size_t len) {
  size_t off = 0;
  if (!c || !buf) {
    return -1;
  }
  while (off < len && s_poll_run) {
#ifdef EDR_HAVE_OPENSSL_HTTP
    if (c->ssl) {
      int n = SSL_write(c->ssl, buf + off, (int)(len - off));
      if (n <= 0) {
        int e = SSL_get_error(c->ssl, n);
        if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) {
          continue;
        }
        return -1;
      }
      off += (size_t)n;
      continue;
    }
#endif
#ifdef _WIN32
    {
      int n = send(c->fd, (const char *)buf + off, (int)(len - off), 0);
      if (n <= 0) {
        return -1;
      }
      off += (size_t)n;
    }
#else
    {
      ssize_t n = send(c->fd, (const char *)buf + off, len - off, 0);
      if (n <= 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
          continue;
        }
        return -1;
      }
      off += (size_t)n;
    }
#endif
  }
  return off == len ? 0 : -1;
}

static void ws_close_conn(EdrWsConn *c) {
  if (!c) {
    return;
  }
#ifdef EDR_HAVE_OPENSSL_HTTP
  if (c->ssl) {
    SSL_shutdown(c->ssl);
    SSL_free(c->ssl);
    c->ssl = NULL;
  }
  if (c->ctx) {
    SSL_CTX_free(c->ctx);
    c->ctx = NULL;
  }
#endif
  if (c->fd != EDR_SOCKET_INVALID) {
    close_fd(c->fd);
    c->fd = EDR_SOCKET_INVALID;
  }
}

static void ws_random_bytes(uint8_t *out, size_t n) {
  static int seeded;
  if (!seeded) {
    srand((unsigned)time(NULL) ^ (unsigned)(uintptr_t)out);
    seeded = 1;
  }
#ifdef EDR_HAVE_OPENSSL_HTTP
  if (RAND_bytes(out, (int)n) == 1) {
    return;
  }
#endif
  for (size_t i = 0; i < n; i++) {
    out[i] = (uint8_t)(rand() & 0xff);
  }
}

static int ws_send_frame(EdrWsConn *c, int opcode, const uint8_t *payload, size_t len) {
  uint8_t hdr[14];
  uint8_t mask[4];
  uint8_t *masked = NULL;
  size_t h = 0;
  if (!c || (len > 0u && !payload)) {
    return -1;
  }
  hdr[h++] = (uint8_t)(0x80u | (opcode & 0x0f));
  if (len < 126u) {
    hdr[h++] = (uint8_t)(0x80u | len);
  } else if (len <= 0xffffu) {
    hdr[h++] = 0x80u | 126u;
    hdr[h++] = (uint8_t)((len >> 8) & 0xffu);
    hdr[h++] = (uint8_t)(len & 0xffu);
  } else {
    hdr[h++] = 0x80u | 127u;
    for (int i = 7; i >= 0; i--) {
      hdr[h++] = (uint8_t)(((uint64_t)len >> (unsigned)(i * 8)) & 0xffu);
    }
  }
  ws_random_bytes(mask, sizeof(mask));
  memcpy(hdr + h, mask, sizeof(mask));
  h += sizeof(mask);
  if (ws_write_all(c, hdr, h) != 0) {
    return -1;
  }
  if (len == 0u) {
    return 0;
  }
  masked = (uint8_t *)malloc(len);
  if (!masked) {
    return -1;
  }
  for (size_t i = 0; i < len; i++) {
    masked[i] = payload[i] ^ mask[i & 3u];
  }
  {
    int rc = ws_write_all(c, masked, len);
    free(masked);
    return rc;
  }
}

static int ws_send_text_conn(EdrWsConn *c, const char *text) {
  return ws_send_frame(c, 1, (const uint8_t *)(text ? text : ""), text ? strlen(text) : 0u);
}

static int ws_send_text_active(const char *text) {
  int rc = -1;
  ws_lock();
  if (s_ws_ready && s_ws_conn) {
    rc = ws_send_text_conn(s_ws_conn, text);
    if (rc != 0) {
      s_ws_ready = 0;
    }
  }
  ws_unlock();
  return rc;
}

static int ws_read_frame(EdrWsConn *c, int *opcode, char **payload, size_t *payload_len) {
  uint8_t h[2];
  uint64_t len;
  int masked;
  uint8_t mask[4] = {0, 0, 0, 0};
  char *buf = NULL;
  int rc;
  if (!opcode || !payload || !payload_len) {
    return -1;
  }
  *opcode = 0;
  *payload = NULL;
  *payload_len = 0;
  rc = ws_read_exact(c, h, sizeof(h));
  if (rc != 0) {
    return rc;
  }
  *opcode = h[0] & 0x0f;
  masked = (h[1] & 0x80u) != 0;
  len = (uint64_t)(h[1] & 0x7fu);
  if (len == 126u) {
    uint8_t ext[2];
    if (ws_read_exact(c, ext, sizeof(ext)) != 0) {
      return -1;
    }
    len = ((uint64_t)ext[0] << 8) | ext[1];
  } else if (len == 127u) {
    uint8_t ext[8];
    if (ws_read_exact(c, ext, sizeof(ext)) != 0) {
      return -1;
    }
    len = 0;
    for (size_t i = 0; i < sizeof(ext); i++) {
      len = (len << 8) | ext[i];
    }
  }
  if (len > 1024u * 1024u) {
    return -1;
  }
  if (masked && ws_read_exact(c, mask, sizeof(mask)) != 0) {
    return -1;
  }
  buf = (char *)malloc((size_t)len + 1u);
  if (!buf) {
    return -1;
  }
  if (len > 0u && ws_read_exact(c, (uint8_t *)buf, (size_t)len) != 0) {
    free(buf);
    return -1;
  }
  if (masked) {
    for (size_t i = 0; i < (size_t)len; i++) {
      buf[i] = (char)((uint8_t)buf[i] ^ mask[i & 3u]);
    }
  }
  buf[len] = '\0';
  *payload = buf;
  *payload_len = (size_t)len;
  return 0;
}

static int ws_read_handshake(EdrWsConn *c) {
  char buf[4096];
  size_t used = 0;
  while (used + 1u < sizeof(buf)) {
    int n = ws_recv_some(c, buf + used, (int)(sizeof(buf) - 1u - used));
    if (n == -2) {
      continue;
    }
    if (n <= 0) {
      return -1;
    }
    used += (size_t)n;
    buf[used] = '\0';
    if (strstr(buf, "\r\n\r\n")) {
      return (strncmp(buf, "HTTP/1.1 101", 12u) == 0 || strncmp(buf, "HTTP/1.0 101", 12u) == 0) ? 0 : -1;
    }
  }
  return -1;
}

static int ws_connect_once(EdrWsConn *out) {
  char url[1400];
  char host[256];
  char path[1024];
  char req[4096];
  uint8_t nonce[16];
  char key[64];
  int port = 0;
  int https = 0;
  int rn;
  size_t rb;
  if (!out || !edr_ingest_http_configured()) {
    return -1;
  }
  memset(out, 0, sizeof(*out));
  out->fd = EDR_SOCKET_INVALID;
  rb = strlen(s_rest);
  snprintf(url, sizeof(url), "%s%singest/control/ws?endpoint_id=%s",
           s_rest, (rb > 0u && s_rest[rb - 1u] == '/') ? "" : "/", s_endpoint);
  if (parse_url(url, host, sizeof(host), path, sizeof(path), &port, &https) != 0) {
    return -1;
  }
  if (net_init() != 0) {
    return -1;
  }
  if (tcp_connect_http_route(host, port, https, &out->fd) != 0) {
    net_done();
    return -1;
  }
  socket_set_timeout_ms(out->fd, 1000);
  if (https) {
#ifdef EDR_HAVE_OPENSSL_HTTP
    char active_cafile[1024];
    out->ctx = new_https_ctx(active_cafile, sizeof(active_cafile));
    if (!out->ctx) {
      ws_close_conn(out);
      net_done();
      return -1;
    }
    out->ssl = SSL_new(out->ctx);
    if (!out->ssl) {
      ws_close_conn(out);
      net_done();
      return -1;
    }
#ifdef _WIN32
    SSL_set_fd(out->ssl, (int)out->fd);
#else
    SSL_set_fd(out->ssl, out->fd);
#endif
    (void)SSL_set_tlsext_host_name(out->ssl, host);
    if (SSL_connect(out->ssl) != 1) {
      runtime_failure_openssl("control ws tls connect failed");
      ws_close_conn(out);
      net_done();
      return -1;
    }
#else
    runtime_failure("control ws https requested but OpenSSL disabled");
    ws_close_conn(out);
    net_done();
    return -1;
#endif
  }
  ws_random_bytes(nonce, sizeof(nonce));
  if (b64_encode(nonce, sizeof(nonce), key, sizeof(key)) < 0) {
    ws_close_conn(out);
    net_done();
    return -1;
  }
  rn = snprintf(req, sizeof(req),
                "GET %s HTTP/1.1\r\n"
                "Host: %s\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                "Sec-WebSocket-Key: %s\r\n"
                "Sec-WebSocket-Version: 13\r\n",
                path, host, key);
  if (rn <= 0 || (size_t)rn >= sizeof(req)) {
    ws_close_conn(out);
    net_done();
    return -1;
  }
  rn = append_common_headers(req, sizeof(req), (size_t)rn);
  if (rn <= 0) {
    ws_close_conn(out);
    net_done();
    return -1;
  }
  {
    size_t used = (size_t)rn;
    int m = snprintf(req + used, sizeof(req) - used, "\r\n");
    if (m <= 0 || (size_t)m >= sizeof(req) - used ||
        ws_write_all(out, (const uint8_t *)req, used + (size_t)m) != 0 ||
        ws_read_handshake(out) != 0) {
      ws_close_conn(out);
      net_done();
      return -1;
    }
  }
  return 0;
}

static int ws_send_agent_message(EdrWsConn *c, const char *command_type) {
  char payload[512];
  char payload_b64[1024];
  char env[1600];
  int hb = 45;
  const char *hbe = getenv("EDR_WS_HEARTBEAT_S");
  if (hbe && hbe[0]) {
    int v = atoi(hbe);
    if (v >= 30 && v <= 60) {
      hb = v;
    }
  }
  snprintf(payload, sizeof(payload),
           "{\"endpoint_id\":\"%s\",\"agent_version\":\"%s\",\"policy_version\":\"%s\","
           "\"transport\":\"websocket\",\"heartbeat_sec\":%d,"
           "\"supports_rtr\":true,\"supports_rtq\":true,\"supports_results\":true}",
           s_endpoint, s_agent_ver, s_policy_version[0] ? s_policy_version : "local", hb);
  if (b64_encode((const uint8_t *)payload, strlen(payload), payload_b64, sizeof(payload_b64)) < 0) {
    return -1;
  }
  snprintf(env, sizeof(env),
           "{\"command_id\":\"agent-%s\",\"command_type\":\"%s\","
           "\"issued_at_unix_ms\":%lld,\"payload_b64\":\"%s\"}",
           strcmp(command_type, "agent_hello") == 0 ? "hello" : "heartbeat",
           command_type, (long long)unix_ms_now(), payload_b64);
  return ws_send_text_conn(c, env);
}

static int ws_send_command_result(const char *command_id, const struct EdrSoarCommandMeta *meta,
                                  int execution_status, int exit_code, const char *detail_utf8) {
  char *cmd = NULL;
  char *detail = NULL;
  char *soar = NULL;
  char *run = NULL;
  char *step = NULL;
  char *payload = NULL;
  char *payload_b64 = NULL;
  char *env = NULL;
  size_t payload_cap;
  size_t b64_cap;
  size_t env_cap;
  int rc = -1;
  if (!s_ws_ready || !command_id || !command_id[0]) {
    return -1;
  }
  cmd = json_escape_alloc(command_id);
  detail = json_escape_alloc(detail_utf8 ? detail_utf8 : "");
  soar = json_escape_alloc(meta ? meta->soar_correlation_id : "");
  run = json_escape_alloc(meta ? meta->playbook_run_id : "");
  step = json_escape_alloc(meta ? meta->playbook_step_id : "");
  if (!cmd || !detail || !soar || !run || !step) {
    goto done;
  }
  payload_cap = strlen(cmd) + strlen(detail) + strlen(soar) + strlen(run) + strlen(step) +
                strlen(s_agent_ver) + 512u;
  payload = (char *)malloc(payload_cap);
  if (!payload) {
    goto done;
  }
  snprintf(payload, payload_cap,
           "{\"command_id\":\"%s\",\"status\":%d,\"exit_code\":%d,"
           "\"detail_utf8\":\"%s\",\"agent_version\":\"%s\","
           "\"soar_correlation_id\":\"%s\",\"playbook_run_id\":\"%s\","
           "\"playbook_step_id\":\"%s\",\"finished_unix_ms\":%lld}",
           cmd, execution_status, exit_code, detail, s_agent_ver, soar, run, step,
           (long long)unix_ms_now());
  b64_cap = (strlen(payload) / 3u + 2u) * 4u + 16u;
  payload_b64 = (char *)malloc(b64_cap);
  if (!payload_b64 || b64_encode((const uint8_t *)payload, strlen(payload), payload_b64, b64_cap) < 0) {
    goto done;
  }
  env_cap = strlen(cmd) + strlen(payload_b64) + strlen(soar) + strlen(run) + strlen(step) + 512u;
  env = (char *)malloc(env_cap);
  if (!env) {
    goto done;
  }
  snprintf(env, env_cap,
           "{\"command_id\":\"%s\",\"command_type\":\"command_result\","
           "\"issued_at_unix_ms\":%lld,\"payload_b64\":\"%s\","
           "\"soar_correlation_id\":\"%s\",\"playbook_run_id\":\"%s\","
           "\"playbook_step_id\":\"%s\"}",
           cmd, (long long)unix_ms_now(), payload_b64, soar, run, step);
  rc = ws_send_text_active(env);
done:
  free(cmd);
  free(detail);
  free(soar);
  free(run);
  free(step);
  free(payload);
  free(payload_b64);
  free(env);
  return rc;
}

static int post_to_suffix(const char *suffix, const char *body) {
  char url[1024];
  size_t rb = strlen(s_rest);
  snprintf(url, sizeof(url), "%s%s%s", s_rest, (rb > 0u && s_rest[rb - 1u] == '/') ? "" : "/", suffix);
  int rc = native_post_json(url, body, strlen(body));
  if (rc == 0) {
    runtime_success();
  } else if (!s_last_error[0]) {
    runtime_failure("native post failed");
  }
  return rc;
}

int edr_ingest_http_post_report_events(const char *batch_id, const uint8_t *header12, size_t header_len,
                                       const uint8_t *payload, size_t payload_len) {
  if (!edr_ingest_http_configured() || !batch_id || !header12 || header_len < 12u || !payload ||
      payload_len == 0u) {
    return -1;
  }
  size_t raw_len = header_len + payload_len;
  size_t b64_cap = (raw_len / 3u + 2u) * 4u + 16u;
  char *b64 = (char *)malloc(b64_cap);
  if (!b64) {
    return -1;
  }
  uint8_t *raw = (uint8_t *)malloc(raw_len);
  if (!raw) {
    free(b64);
    return -1;
  }
  memcpy(raw, header12, header_len);
  memcpy(raw + header_len, payload, payload_len);
  if (b64_encode(raw, raw_len, b64, b64_cap) < 0) {
    free(b64);
    free(raw);
    return -1;
  }
  free(raw);

  size_t body_cap = strlen(b64) + strlen(s_endpoint) + strlen(batch_id) + strlen(s_agent_ver) + 128u;
  char *body = (char *)malloc(body_cap);
  if (!body) {
    free(b64);
    return -1;
  }
  snprintf(body, body_cap,
           "{\"endpoint_id\":\"%s\",\"batch_id\":\"%s\",\"agent_version\":\"%s\",\"payload\":\"%s\"}",
           s_endpoint, batch_id, s_agent_ver, b64);
  free(b64);
  int rc = post_to_suffix("ingest/report-events", body);
  free(body);
  if (rc != 0) {
    fprintf(stderr, "[ingest-http] native post failed rc=%d (rest=%s err=%s)\n", rc, s_rest, s_last_error);
    return -1;
  }
  return 0;
}

int edr_ingest_http_post_engine_health_json(const char *body_json) {
  if (!edr_ingest_http_configured() || !body_json || !body_json[0]) {
    return -1;
  }

  int rc = post_to_suffix("ingest/engine-health", body_json);
  if (rc != 0) {
    fprintf(stderr, "[ingest-http] engine_health native post failed rc=%d (rest=%s err=%s)\n", rc, s_rest,
            s_last_error);
    return -1;
  }
  return 0;
}

int edr_ingest_http_post_command_result(const char *command_id,
                                        const struct EdrSoarCommandMeta *meta,
                                        int execution_status,
                                        int exit_code,
                                        const char *detail_utf8) {
  char *detail = NULL;
  char *cmd = NULL;
  char *soar = NULL;
  char *run = NULL;
  char *step = NULL;
  char *body = NULL;
  size_t body_cap;
  int rc;
  if (!edr_ingest_http_configured() || !command_id || !command_id[0]) {
    return -1;
  }
  if (ws_send_command_result(command_id, meta, execution_status, exit_code, detail_utf8) == 0) {
    runtime_success();
    return 0;
  }
  cmd = json_escape_alloc(command_id);
  detail = json_escape_alloc(detail_utf8 ? detail_utf8 : "");
  soar = json_escape_alloc(meta ? meta->soar_correlation_id : "");
  run = json_escape_alloc(meta ? meta->playbook_run_id : "");
  step = json_escape_alloc(meta ? meta->playbook_step_id : "");
  if (!cmd || !detail || !soar || !run || !step) {
    free(cmd);
    free(detail);
    free(soar);
    free(run);
    free(step);
    return -1;
  }
  body_cap = strlen(cmd) + strlen(detail) + strlen(soar) + strlen(run) + strlen(step) +
             strlen(s_endpoint) + strlen(s_agent_ver) + 512u;
  body = (char *)malloc(body_cap);
  if (!body) {
    free(cmd);
    free(detail);
    free(soar);
    free(run);
    free(step);
    return -1;
  }
  snprintf(body, body_cap,
           "{\"endpoint_id\":\"%s\",\"result\":{"
           "\"command_id\":\"%s\",\"endpoint_id\":\"%s\",\"agent_version\":\"%s\","
           "\"status\":\"%d\",\"exit_code\":\"%d\",\"detail_utf8\":\"%s\","
           "\"finished_unix_ms\":\"%lld\",\"soar_correlation_id\":\"%s\","
           "\"playbook_run_id\":\"%s\",\"playbook_step_id\":\"%s\"}}",
           s_endpoint, cmd, s_endpoint, s_agent_ver, execution_status, exit_code, detail,
           (long long)unix_ms_now(), soar, run, step);
  rc = request_to_suffix("POST", "ingest/report-command-result", "application/json",
                         body, strlen(body), NULL, 0u);
  if (rc == 0) {
    runtime_success();
  } else if (!s_last_error[0]) {
    runtime_failure("command result http post failed");
  }
  free(cmd);
  free(detail);
  free(soar);
  free(run);
  free(step);
  free(body);
  return rc;
}

static const char *base_name_ptr(const char *path) {
  const char *b1;
  const char *b2;
  if (!path || !path[0]) {
    return "upload.bin";
  }
  b1 = strrchr(path, '/');
  b2 = strrchr(path, '\\');
  if (b2 && (!b1 || b2 > b1)) {
    b1 = b2;
  }
  return b1 ? b1 + 1 : path;
}

static int read_file_alloc(const char *path, uint8_t **out, size_t *out_len) {
  FILE *f;
  long sz;
  uint8_t *buf;
  const char *max_mb_env = getenv("EDR_HTTP_UPLOAD_MAX_MB");
  long max_mb = max_mb_env && max_mb_env[0] ? strtol(max_mb_env, NULL, 10) : 256L;
  if (!path || !out || !out_len) {
    return -1;
  }
  if (max_mb < 1) max_mb = 1;
  if (max_mb > 2048) max_mb = 2048;
  *out = NULL;
  *out_len = 0;
  f = fopen(path, "rb");
  if (!f) {
    return -1;
  }
  if (fseek(f, 0, SEEK_END) != 0) {
    fclose(f);
    return -1;
  }
  sz = ftell(f);
  if (sz < 0 || (unsigned long)sz > (unsigned long)max_mb * 1024ul * 1024ul) {
    fclose(f);
    return -1;
  }
  if (fseek(f, 0, SEEK_SET) != 0) {
    fclose(f);
    return -1;
  }
  buf = (uint8_t *)malloc((size_t)sz + 1u);
  if (!buf) {
    fclose(f);
    return -1;
  }
  if (sz > 0 && fread(buf, 1u, (size_t)sz, f) != (size_t)sz) {
    free(buf);
    fclose(f);
    return -1;
  }
  fclose(f);
  *out = buf;
  *out_len = (size_t)sz;
  return 0;
}

int edr_ingest_http_upload_file_multipart(const char *upload_id, const char *file_path,
                                          const char *sha256_hex, char *out_minio_key,
                                          size_t out_minio_key_cap) {
  const char *boundary = "----edr-agent-upload-boundary-v1";
  const char *filename;
  uint8_t *file_buf = NULL;
  size_t file_len = 0;
  char *uid = NULL;
  char *sha = NULL;
  char *fname = NULL;
  char content_type[160];
  char resp[4096];
  char pre[2048];
  char post[96];
  char *body = NULL;
  size_t body_len;
  int rc;
  if (out_minio_key && out_minio_key_cap > 0u) {
    out_minio_key[0] = '\0';
  }
  if (!edr_ingest_http_configured() || !upload_id || !upload_id[0] || !file_path || !file_path[0]) {
    return -1;
  }
  if (read_file_alloc(file_path, &file_buf, &file_len) != 0) {
    runtime_failure("http upload file read failed");
    return -1;
  }
  filename = base_name_ptr(file_path);
  uid = json_escape_alloc(upload_id);
  sha = json_escape_alloc(sha256_hex ? sha256_hex : "");
  fname = json_escape_alloc(filename);
  if (!uid || !sha || !fname) {
    free(file_buf);
    free(uid);
    free(sha);
    free(fname);
    return -1;
  }
  snprintf(pre, sizeof(pre),
           "--%s\r\nContent-Disposition: form-data; name=\"upload_id\"\r\n\r\n%s\r\n"
           "--%s\r\nContent-Disposition: form-data; name=\"sha256\"\r\n\r\n%s\r\n"
           "--%s\r\nContent-Disposition: form-data; name=\"file_name\"\r\n\r\n%s\r\n"
           "--%s\r\nContent-Disposition: form-data; name=\"file\"; filename=\"%s\"\r\n"
           "Content-Type: application/octet-stream\r\n\r\n",
           boundary, uid, boundary, sha, boundary, fname, boundary, fname);
  snprintf(post, sizeof(post), "\r\n--%s--\r\n", boundary);
  body_len = strlen(pre) + file_len + strlen(post);
  body = (char *)malloc(body_len + 1u);
  if (!body) {
    free(file_buf);
    free(uid);
    free(sha);
    free(fname);
    return -1;
  }
  memcpy(body, pre, strlen(pre));
  memcpy(body + strlen(pre), file_buf, file_len);
  memcpy(body + strlen(pre) + file_len, post, strlen(post));
  body[body_len] = '\0';
  snprintf(content_type, sizeof(content_type), "multipart/form-data; boundary=%s", boundary);
  resp[0] = '\0';
  rc = request_to_suffix("POST", "ingest/upload-file", content_type, body, body_len, resp, sizeof(resp));
  if (rc == 0) {
    runtime_success();
    if (out_minio_key && out_minio_key_cap > 0u) {
      (void)json_get_string(resp, "minio_key", out_minio_key, out_minio_key_cap);
    }
  } else if (!s_last_error[0]) {
    runtime_failure("http upload failed");
  }
  free(file_buf);
  free(uid);
  free(sha);
  free(fname);
  free(body);
  return rc;
}

static int poll_dispatch_one(const char *obj) {
  char command_id[160];
  char command_type[96];
  char *payload_b64 = NULL;
  EdrSoarCommandMeta sm;
  uint8_t *payload = NULL;
  size_t payload_len = 0;
  int64_t v;
  memset(&sm, 0, sizeof(sm));
  if (json_get_string(obj, "command_id", command_id, sizeof(command_id)) != 0 ||
      json_get_string(obj, "command_type", command_type, sizeof(command_type)) != 0) {
    return -1;
  }
  payload_b64 = (char *)malloc(strlen(obj) + 1u);
  if (!payload_b64) {
    return -1;
  }
  if (json_get_string(obj, "payload_b64", payload_b64, strlen(obj) + 1u) == 0 && payload_b64[0]) {
    if (b64_decode_alloc(payload_b64, &payload, &payload_len) != 0) {
      free(payload_b64);
      return -1;
    }
  }
  (void)json_get_string(obj, "soar_correlation_id", sm.soar_correlation_id, sizeof(sm.soar_correlation_id));
  (void)json_get_string(obj, "playbook_run_id", sm.playbook_run_id, sizeof(sm.playbook_run_id));
  (void)json_get_string(obj, "playbook_step_id", sm.playbook_step_id, sizeof(sm.playbook_step_id));
  (void)json_get_string(obj, "idempotency_key", sm.idempotency_key, sizeof(sm.idempotency_key));
  if (json_get_int64(obj, "issued_at_unix_ms", &v) == 0) {
    sm.issued_at_unix_ms = v;
  }
  if (json_get_int64(obj, "deadline_ms", &v) == 0 && v > 0 && v <= 0xffffffffLL) {
    sm.deadline_ms = (uint32_t)v;
  }
  edr_command_on_envelope(command_id, command_type, payload, payload_len, &sm);
  free(payload_b64);
  free(payload);
  return 0;
}

static int poll_dispatch_commands(const char *resp) {
  const char *arr;
  int count = 0;
  if (!resp) {
    return -1;
  }
  arr = strstr(resp, "\"commands\"");
  if (!arr) {
    return 0;
  }
  arr = strchr(arr, '[');
  if (!arr) {
    return 0;
  }
  arr++;
  while (*arr) {
    const char *start;
    const char *p;
    int depth = 0;
    int in_string = 0;
    int esc = 0;
    while (*arr && *arr != '{' && *arr != ']') arr++;
    if (*arr == ']' || !*arr) {
      break;
    }
    start = arr;
    for (p = arr; *p; p++) {
      char c = *p;
      if (in_string) {
        if (esc) {
          esc = 0;
        } else if (c == '\\') {
          esc = 1;
        } else if (c == '"') {
          in_string = 0;
        }
        continue;
      }
      if (c == '"') {
        in_string = 1;
      } else if (c == '{') {
        depth++;
      } else if (c == '}') {
        depth--;
        if (depth == 0) {
          size_t n = (size_t)(p - start + 1);
          char *obj = (char *)malloc(n + 1u);
          if (obj) {
            memcpy(obj, start, n);
            obj[n] = '\0';
            if (poll_dispatch_one(obj) == 0) {
              count++;
            }
            free(obj);
          }
          arr = p + 1;
          break;
        }
      }
    }
    if (!*p) {
      break;
    }
  }
  return count;
}

static int ws_heartbeat_seconds(void) {
  int hb = 45;
  const char *e = getenv("EDR_WS_HEARTBEAT_S");
  if (e && e[0]) {
    int v = atoi(e);
    if (v >= 30 && v <= 60) {
      hb = v;
    }
  }
  return hb;
}

static void sleep_poll_ms(int ms);

#ifdef _WIN32
static unsigned __stdcall control_ws_thread(void *arg)
#else
static void *control_ws_thread(void *arg)
#endif
{
  int backoff_ms = 5000;
  (void)arg;
  s_ws_backoff_ms = backoff_ms;
  while (s_poll_run) {
    EdrWsConn conn;
    int64_t next_hb;
    if (!edr_ingest_http_configured()) {
      sleep_poll_ms(5000);
      continue;
    }
    if (edr_grpc_client_ready() || s_ws_ready) {
      sleep_poll_ms(5000);
      continue;
    }
    if (ws_connect_once(&conn) != 0) {
      s_ws_backoff_ms = backoff_ms;
      sleep_poll_ms(backoff_ms);
      if (backoff_ms < 60000) {
        backoff_ms *= 2;
        if (backoff_ms > 60000) {
          backoff_ms = 60000;
        }
      }
      s_ws_backoff_ms = backoff_ms;
      continue;
    }
    ws_lock();
    s_ws_conn = &conn;
    s_ws_ready = 1;
    ws_unlock();
    if (ws_send_agent_message(&conn, "agent_hello") == 0) {
      runtime_success();
      backoff_ms = 5000;
      s_ws_backoff_ms = 0;
      fprintf(stderr, "[ingest-ws] control connected endpoint=%s\n", s_endpoint);
    } else {
      runtime_failure("control ws hello failed");
    }
    next_hb = unix_ms_now() + (int64_t)ws_heartbeat_seconds() * 1000LL;
    while (s_poll_run && s_ws_ready) {
      int opcode = 0;
      char *payload = NULL;
      size_t payload_len = 0;
      int rc;
      if (unix_ms_now() >= next_hb) {
        if (ws_send_agent_message(&conn, "agent_heartbeat") != 0) {
          break;
        }
        next_hb = unix_ms_now() + (int64_t)ws_heartbeat_seconds() * 1000LL;
      }
      rc = ws_read_frame(&conn, &opcode, &payload, &payload_len);
      if (rc == -2) {
        continue;
      }
      if (rc != 0) {
        break;
      }
      if (opcode == 1 || opcode == 2) {
        (void)payload_len;
        (void)poll_dispatch_one(payload);
      } else if (opcode == 8) {
        free(payload);
        break;
      } else if (opcode == 9) {
        ws_lock();
        if (s_ws_conn == &conn) {
          (void)ws_send_frame(&conn, 10, (const uint8_t *)payload, payload_len);
        }
        ws_unlock();
      }
      free(payload);
    }
    ws_lock();
    if (s_ws_conn == &conn) {
      s_ws_conn = NULL;
    }
    s_ws_ready = 0;
    ws_unlock();
    ws_close_conn(&conn);
    net_done();
    if (s_poll_run) {
      fprintf(stderr, "[ingest-ws] control disconnected; HTTP long-poll fallback remains active\n");
      s_ws_backoff_ms = backoff_ms;
      sleep_poll_ms(backoff_ms);
    }
  }
#ifdef _WIN32
  return 0;
#else
  return NULL;
#endif
}

static int edr_ingest_http_poll_once(void) {
  char suffix[512];
  char resp[262144];
  int wait_s = 25;
  const char *w = getenv("EDR_HTTP_COMMAND_POLL_WAIT_S");
  int n;
  if (w && w[0]) {
    int v = atoi(w);
    if (v >= 1 && v <= 30) {
      wait_s = v;
    }
  }
  snprintf(suffix, sizeof(suffix), "ingest/poll-commands?endpoint_id=%s&limit=8&wait_s=%d",
           s_endpoint, wait_s);
  resp[0] = '\0';
  if (request_to_suffix("GET", suffix, NULL, NULL, 0u, resp, sizeof(resp)) != 0) {
    return -1;
  }
  runtime_success();
  n = poll_dispatch_commands(resp);
  return n < 0 ? -1 : n;
}

static void sleep_poll_ms(int ms) {
  int step = 100;
  if (ms < step) {
    step = ms;
  }
  while (s_poll_run && ms > 0) {
#ifdef _WIN32
    Sleep((DWORD)step);
#else
    usleep((useconds_t)step * 1000u);
#endif
    ms -= step;
    if (ms < step) {
      step = ms;
    }
  }
}

static unsigned poll_jitter_ms(void) {
  unsigned h = 2166136261u;
  for (const char *p = s_endpoint; p && *p; p++) {
    h ^= (unsigned char)*p;
    h *= 16777619u;
  }
  h ^= (unsigned)time(NULL);
  return 2000u + (h % 3000u);
}

#ifdef _WIN32
static unsigned __stdcall command_poll_thread(void *arg)
#else
static void *command_poll_thread(void *arg)
#endif
{
  int backoff_ms = 5000;
  (void)arg;
  s_poll_backoff_ms = backoff_ms;
  while (s_poll_run) {
    int rc;
    if (!edr_ingest_http_configured()) {
      sleep_poll_ms(5000);
      continue;
    }
    if (edr_grpc_client_ready()) {
      sleep_poll_ms(5000);
      continue;
    }
    rc = edr_ingest_http_poll_once();
    if (rc >= 0) {
      backoff_ms = 5000;
      s_poll_backoff_ms = 0;
      if (rc == 0) {
        sleep_poll_ms((int)poll_jitter_ms());
      }
      continue;
    }
    sleep_poll_ms(backoff_ms);
    if (backoff_ms < 300000) {
      backoff_ms *= 2;
      if (backoff_ms > 300000) {
        backoff_ms = 300000;
      }
    }
    s_poll_backoff_ms = backoff_ms;
  }
#ifdef _WIN32
  return 0;
#else
  return NULL;
#endif
}

void edr_ingest_http_start_command_poll(void) {
  const char *off = getenv("EDR_HTTP_COMMAND_POLL");
  const char *wsoff = getenv("EDR_HTTP_CONTROL_WS");
  if (off && strcmp(off, "0") == 0) {
    return;
  }
  if (s_poll_started || !edr_ingest_http_configured()) {
    return;
  }
  s_poll_run = 1;
  ws_mu_init_once();
  if (!wsoff || strcmp(wsoff, "0") != 0) {
#ifdef _WIN32
    s_ws_thread = (HANDLE)_beginthreadex(NULL, 0, control_ws_thread, NULL, 0, NULL);
    if (s_ws_thread) {
      s_ws_started = 1;
    } else {
      runtime_failure("control ws thread create failed");
    }
#else
    if (pthread_create(&s_ws_thread, NULL, control_ws_thread, NULL) == 0) {
      s_ws_started = 1;
    } else {
      runtime_failure("control ws thread create failed");
    }
#endif
  }
#ifdef _WIN32
  s_poll_thread = (HANDLE)_beginthreadex(NULL, 0, command_poll_thread, NULL, 0, NULL);
  if (!s_poll_thread) {
    s_poll_run = 0;
    runtime_failure("http command poll thread create failed");
    return;
  }
#else
  if (pthread_create(&s_poll_thread, NULL, command_poll_thread, NULL) != 0) {
    s_poll_run = 0;
    runtime_failure("http command poll thread create failed");
    return;
  }
#endif
  s_poll_started = 1;
}

void edr_ingest_http_stop_command_poll(void) {
  if (!s_poll_started) {
    return;
  }
  s_poll_run = 0;
  ws_lock();
  if (s_ws_conn) {
    if (s_ws_conn->fd != EDR_SOCKET_INVALID) {
      close_fd(s_ws_conn->fd);
      s_ws_conn->fd = EDR_SOCKET_INVALID;
    }
  }
  s_ws_ready = 0;
  ws_unlock();
#ifdef _WIN32
  WaitForSingleObject(s_poll_thread, 3000);
  CloseHandle(s_poll_thread);
  s_poll_thread = NULL;
  if (s_ws_started) {
    WaitForSingleObject(s_ws_thread, 3000);
    CloseHandle(s_ws_thread);
    s_ws_thread = NULL;
    s_ws_started = 0;
  }
#else
  pthread_join(s_poll_thread, NULL);
  if (s_ws_started) {
    pthread_join(s_ws_thread, NULL);
    s_ws_started = 0;
  }
#endif
  s_poll_started = 0;
}
