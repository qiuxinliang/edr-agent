#include "edr/ingest_http.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#ifdef EDR_HAVE_OPENSSL_HTTP
#include <openssl/ssl.h>
#include <openssl/err.h>
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
static unsigned long s_http_ok;
static unsigned long s_http_fail;
static int64_t s_last_success_ms;
static int64_t s_last_failure_ms;
static char s_last_error[160];
static int s_insecure_http;

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

void edr_ingest_http_configure(const char *rest_base, const char *tenant_id, const char *user_id,
                                const char *bearer, const char *endpoint_id, const char *agent_version,
                                const char *ca_file) {
  memset(s_rest, 0, sizeof(s_rest));
  memset(s_tenant, 0, sizeof(s_tenant));
  memset(s_user, 0, sizeof(s_user));
  memset(s_bearer, 0, sizeof(s_bearer));
  memset(s_endpoint, 0, sizeof(s_endpoint));
  memset(s_agent_ver, 0, sizeof(s_agent_ver));
  memset(s_ca_file, 0, sizeof(s_ca_file));
  if (rest_base && rest_base[0]) {
    snprintf(s_rest, sizeof(s_rest), "%s", rest_base);
  }
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
  out->ok_count = s_http_ok;
  out->fail_count = s_http_fail;
  out->last_success_unix_ms = s_last_success_ms;
  out->last_failure_unix_ms = s_last_failure_ms;
  snprintf(out->last_error, sizeof(out->last_error), "%s", s_last_error);
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
  int rn = append_headers(req, sizeof(req), path, host, body, body_len);
  if (rn <= 0) {
    return -1;
  }
  OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
  ctx = SSL_CTX_new(TLS_client_method());
  if (!ctx) {
    runtime_failure_openssl("https ssl ctx failed");
    return -1;
  }
  {
    const char *cafile = getenv("EDR_INGEST_HTTPS_CA_FILE");
    if (!cafile || !cafile[0]) {
      cafile = s_ca_file;
    }
    if (cafile && cafile[0]) {
      if (SSL_CTX_load_verify_locations(ctx, cafile, NULL) != 1) {
        char msg[160];
        snprintf(msg, sizeof(msg), "https ca load failed: %s", cafile);
        runtime_failure(msg);
        goto done;
      }
    } else if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
      runtime_failure_openssl("https default ca load failed");
      goto done;
    }
  }
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
  if (tcp_connect_host(host, port, &fd) != 0) {
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
      snprintf(msg, sizeof(msg), "https tls verify failed: %s", X509_verify_cert_error_string(verify));
      runtime_failure(msg);
    } else {
      runtime_failure_openssl("https tls connect failed");
    }
    goto done;
  }
  if (SSL_write(ssl, req, rn) <= 0 || (body_len > 0u && SSL_write(ssl, body, (int)body_len) <= 0)) {
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

void edr_ingest_http_start_command_poll(void) {
  /* HTTP command polling is optional; gRPC ControlStream remains the primary command path. */
}

void edr_ingest_http_stop_command_poll(void) {}
