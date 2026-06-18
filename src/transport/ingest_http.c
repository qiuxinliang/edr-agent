#include "edr/ingest_http.h"

#include "edr/command.h"
#include "edr/event_batch.h"
#include "edr/grpc_client.h"
#include "edr/transport_v2.h"

#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <io.h>
#include <process.h>
#include <winreg.h>
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

#ifdef EDR_HAVE_CURL_HTTP2
#include <curl/curl.h>
#endif

#ifdef EDR_HAVE_ZSTD
#include <zstd.h>
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
static char s_client_key_provider[32];
static char s_client_cert_store[256];
static char s_client_cert_thumbprint[128];
static char s_mtls_status[96];
static char s_relay_url[512];
static char s_proxy_mode[32];
static char s_proxy_url_cfg[512];
static char s_proxy_url_active[512];
static char s_proxy_status[96];
static char s_connection_mode[32];
static char s_control_dict_ver[64];
static char s_control_schema_ver[64];
static char s_control_profile_id[64];
static char s_control_qos_dscp[32];
static char s_control_threshold[32];
static char s_data_plane_encoding[32] = "protobuf";
static char s_data_plane_compression[32] = "identity";
static unsigned s_control_sampling_pct;
static int s_control_backpressure_enabled;
static int s_http2_enabled_cfg = 1;
static int s_http2_required_cfg;
static int s_control_stream_enabled_cfg = 1;
static int s_long_poll_fallback_cfg = 1;
static int s_report_events_v2_enabled_cfg = 1;
static unsigned long s_report_events_v2_ok;
static unsigned long s_report_events_v2_fail;

static int ascii_eq_ci(const char *a, const char *b);
static int ascii_contains_ci(const char *s, const char *needle);

static unsigned long s_zstd_compress_ok;
static unsigned long s_zstd_compress_fail;
static uint64_t s_zstd_raw_bytes;
static uint64_t s_zstd_wire_bytes;
static uint64_t s_zstd_dict_bytes;
static volatile int s_zstd_dict_loaded;
static char s_zstd_dict_path[512];
#ifdef EDR_HAVE_ZSTD
static uint8_t *s_zstd_dict;
static size_t s_zstd_dict_len;
static int s_zstd_dict_load_attempted;
#endif
static char s_control_stream_status[32] = "idle";
static char s_upload_status[32] = "idle";
static unsigned long s_http_ok;
static unsigned long s_http_fail;
static unsigned long s_http_request_ok;
static unsigned long s_http_request_fail;
static unsigned long s_ws_message_ok;
static unsigned long s_ws_message_fail;
static unsigned long s_ws_pong;
static unsigned long s_command_result_ok;
static unsigned long s_command_result_fail;
static unsigned long s_upload_ok;
static unsigned long s_upload_fail;
static unsigned long s_long_poll_ok;
static unsigned long s_long_poll_fail;
static unsigned long s_control_stream_ok;
static unsigned long s_control_stream_fail;
static unsigned long s_control_stream_heartbeat;
static unsigned long s_control_ack_ok;
static unsigned long s_control_ack_fail;
static unsigned long s_http2_request_ok;
static unsigned long s_http2_request_fail;
static unsigned long s_http2_negotiated_count;
static unsigned long s_http2_fallback_count;
static unsigned long s_http2_multiplex_ok;
static unsigned long s_http2_multiplex_fail;
static volatile int s_http2_multiplex_active;
static volatile int s_http2_negotiated;
static char s_negotiated_protocol[16];
static int s_transport_capability_logged;
static int s_schannel_pem_warned;
static int s_alpn_log_state;
static int64_t s_native_post_fail_log_until_ms;
static unsigned long s_native_post_fail_log_suppressed;
static int64_t s_last_success_ms;
static int64_t s_last_failure_ms;
static char s_last_error[160];
static int s_insecure_http;
static volatile int s_circuit_open;
static int64_t s_circuit_until_ms;
static char s_circuit_reason[128];
static unsigned s_consecutive_failures;
static unsigned long s_budget_drop_count;
static int64_t s_budget_window_minute;
static unsigned long s_budget_requests;
static uint64_t s_budget_bytes;
static unsigned long s_budget_tls_handshakes;
static volatile int s_poll_backoff_ms;
static volatile int s_ws_backoff_ms;
static volatile int s_poll_run;
static int s_poll_started;
static volatile int s_ws_ready;
static volatile int s_stream_ready;
static int s_ws_started;
static volatile int s_control_hello_ok;
static int64_t s_control_hello_last_ms;
static int s_control_h2;
static int s_control_zstd;
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

typedef struct EdrHttpConn {
  int active;
  int https;
  int port;
  char host[256];
  EdrSocket fd;
#ifdef EDR_HAVE_OPENSSL_HTTP
  SSL_CTX *ctx;
  SSL *ssl;
#endif
  int64_t last_used_ms;
} EdrHttpConn;

static EdrHttpConn s_http_conn;
#ifdef _WIN32
static CRITICAL_SECTION s_http_mu;
static int s_http_mu_init;
#else
static pthread_mutex_t s_http_mu = PTHREAD_MUTEX_INITIALIZER;
#endif

static int64_t unix_ms_now(void) {
  return (int64_t)time(NULL) * 1000LL;
}

static unsigned long env_ul_clamped(const char *name, unsigned long fallback,
                                    unsigned long min_v, unsigned long max_v) {
  const char *e = getenv(name);
  unsigned long v = fallback;
  if (e && e[0]) {
    char *endp = NULL;
    v = strtoul(e, &endp, 10);
    if (!endp || endp == e) {
      v = fallback;
    }
  }
  if (v < min_v) v = min_v;
  if (v > max_v) v = max_v;
  return v;
}

static int env_bool_default(const char *name, int fallback) {
  const char *e = getenv(name);
  if (!e || !e[0]) {
    return fallback ? 1 : 0;
  }
  if (strcmp(e, "1") == 0 || strcmp(e, "true") == 0 || strcmp(e, "TRUE") == 0 ||
      strcmp(e, "yes") == 0 || strcmp(e, "YES") == 0 || strcmp(e, "on") == 0 ||
      strcmp(e, "ON") == 0) {
    return 1;
  }
  if (strcmp(e, "0") == 0 || strcmp(e, "false") == 0 || strcmp(e, "FALSE") == 0 ||
      strcmp(e, "no") == 0 || strcmp(e, "NO") == 0 || strcmp(e, "off") == 0 ||
      strcmp(e, "OFF") == 0) {
    return 0;
  }
  return fallback ? 1 : 0;
}

static const char *env_str_default(const char *name, const char *fallback) {
  const char *e = getenv(name);
  return (e && e[0]) ? e : fallback;
}

static int http2_client_enabled(void) {
#ifdef EDR_HAVE_CURL_HTTP2
  return s_http2_enabled_cfg &&
         env_bool_default("EDR_HTTP2_CLIENT", 1) &&
         env_bool_default("EDR_DATA_PLANE_HTTP2", 1);
#else
  return 0;
#endif
}

static int http2_required(void) {
  return s_http2_required_cfg || env_bool_default("EDR_HTTP2_REQUIRE", 0);
}

static int curl_ssl_backend_is_schannel(void) {
#ifdef EDR_HAVE_CURL_HTTP2
  curl_version_info_data *info = curl_version_info(CURLVERSION_NOW);
  const char *ssl = (info && info->ssl_version) ? info->ssl_version : "";
  return ascii_contains_ci(ssl, "schannel");
#else
  return 0;
#endif
}

static int str_ends_with_ci(const char *s, const char *suffix) {
  size_t slen, tlen;
  if (!s || !suffix) {
    return 0;
  }
  slen = strlen(s);
  tlen = strlen(suffix);
  if (tlen > slen) {
    return 0;
  }
  return ascii_eq_ci(s + slen - tlen, suffix);
}

static void compact_thumbprint(char *dst, size_t cap, const char *src) {
  size_t n = 0u;
  if (!dst || cap == 0u) {
    return;
  }
  dst[0] = '\0';
  if (!src) {
    return;
  }
  for (; *src && n + 1u < cap; ++src) {
    if (isxdigit((unsigned char)*src)) {
      dst[n++] = (char)toupper((unsigned char)*src);
    }
  }
  dst[n] = '\0';
}

static int build_schannel_cert_selector(char *dst, size_t cap) {
  char thumb[128];
  const char *store = s_client_cert_store[0] ? s_client_cert_store : "CurrentUser\\MY";
  compact_thumbprint(thumb, sizeof(thumb), s_client_cert_thumbprint);
  if (!dst || cap == 0u || !thumb[0]) {
    return 0;
  }
  if (str_ends_with_ci(store, thumb)) {
    snprintf(dst, cap, "%s", store);
  } else {
    snprintf(dst, cap, "%s\\%s", store, thumb);
  }
  return dst[0] != '\0';
}

static void log_transport_capabilities_once(void) {
  if (s_transport_capability_logged) {
    return;
  }
  s_transport_capability_logged = 1;
#ifdef EDR_HAVE_CURL_HTTP2
  {
    curl_version_info_data *info = curl_version_info(CURLVERSION_NOW);
    long features = info ? (long)info->features : 0L;
    int feature_http2 = 0;
#ifdef CURL_VERSION_HTTP2
    feature_http2 = (features & CURL_VERSION_HTTP2) ? 1 : 0;
#endif
    fprintf(stderr,
            "[transport] EDR_HAVE_CURL_HTTP2=1 libcurl=%s ssl=%s features_http2=%d "
            "http2_enabled=%d http2_required=%d control_stream_enabled=%d long_poll_fallback=%d "
            "data_encoding=%s data_compression=%s mtls_status=%s cert_store=%s thumbprint=%s\n",
            info && info->version ? info->version : "unknown",
            info && info->ssl_version ? info->ssl_version : "unknown",
            feature_http2,
            http2_client_enabled(),
            http2_required(),
            s_control_stream_enabled_cfg,
            s_long_poll_fallback_cfg,
            s_data_plane_encoding[0] ? s_data_plane_encoding : "protobuf",
            s_data_plane_compression[0] ? s_data_plane_compression : "identity",
            s_mtls_status[0] ? s_mtls_status : "not_configured",
            s_client_cert_store[0] ? s_client_cert_store : "-",
            s_client_cert_thumbprint[0] ? s_client_cert_thumbprint : "-");
    if (!feature_http2) {
      fprintf(stderr,
              "[transport] warning: EDR_HAVE_CURL_HTTP2=1 but runtime libcurl does not advertise "
              "CURL_VERSION_HTTP2; install libcurl built with nghttp2\n");
    }
  }
#else
  fprintf(stderr,
          "[transport] EDR_HAVE_CURL_HTTP2=0 http2_enabled=0 http2_required=%d "
          "control_stream_enabled=%d long_poll_fallback=%d data_encoding=%s data_compression=%s mtls_status=%s\n",
          http2_required(),
          s_control_stream_enabled_cfg,
          s_long_poll_fallback_cfg,
          s_data_plane_encoding[0] ? s_data_plane_encoding : "protobuf",
          s_data_plane_compression[0] ? s_data_plane_compression : "identity",
          s_mtls_status[0] ? s_mtls_status : "not_configured");
#endif
}

static unsigned long request_limit_per_minute(void) {
  return env_ul_clamped("EDR_HTTP_REQUEST_BUDGET_PER_MIN", 600ul, 30ul, 60000ul);
}

static uint64_t byte_limit_per_minute(void) {
  unsigned long mb = env_ul_clamped("EDR_HTTP_BYTE_BUDGET_MB_PER_MIN", 64ul, 1ul, 4096ul);
  return (uint64_t)mb * 1024ULL * 1024ULL;
}

static unsigned long tls_handshake_limit_per_minute(void) {
  return env_ul_clamped("EDR_HTTP_TLS_HANDSHAKE_BUDGET_PER_MIN", 120ul, 5ul, 60000ul);
}

static void comm_open_circuit(const char *reason);

static void budget_refresh_window(void) {
  int64_t minute = unix_ms_now() / 60000LL;
  if (minute != s_budget_window_minute) {
    s_budget_window_minute = minute;
    s_budget_requests = 0;
    s_budget_bytes = 0;
    s_budget_tls_handshakes = 0;
  }
}

static int comm_budget_try(size_t bytes, int tls_handshake) {
  unsigned long req_lim;
  uint64_t byte_lim;
  unsigned long tls_lim;
  budget_refresh_window();
  req_lim = request_limit_per_minute();
  byte_lim = byte_limit_per_minute();
  tls_lim = tls_handshake_limit_per_minute();
  if (s_budget_requests + 1ul > req_lim ||
      s_budget_bytes + (uint64_t)bytes > byte_lim ||
      (tls_handshake && s_budget_tls_handshakes + 1ul > tls_lim)) {
    s_budget_drop_count++;
    snprintf(s_last_error, sizeof(s_last_error), "%s", "communication budget exceeded");
    s_last_failure_ms = unix_ms_now();
    comm_open_circuit(s_last_error);
    return 0;
  }
  s_budget_requests++;
  s_budget_bytes += (uint64_t)bytes;
  if (tls_handshake) {
    s_budget_tls_handshakes++;
  }
  return 1;
}

static int comm_tls_handshake_budget_try(void) {
  unsigned long tls_lim;
  budget_refresh_window();
  tls_lim = tls_handshake_limit_per_minute();
  if (s_budget_tls_handshakes + 1ul > tls_lim) {
    s_budget_drop_count++;
    snprintf(s_last_error, sizeof(s_last_error), "%s", "tls handshake budget exceeded");
    s_last_failure_ms = unix_ms_now();
    comm_open_circuit(s_last_error);
    return 0;
  }
  s_budget_tls_handshakes++;
  return 1;
}

static int failure_should_open_circuit(const char *msg) {
  if (!msg || !msg[0]) {
    return 0;
  }
  return strstr(msg, "tls verify") || strstr(msg, "certificate") ||
         strstr(msg, "proxy") || strstr(msg, "connect failed") ||
         strstr(msg, "tcp connect") || strstr(msg, "network init") ||
         strstr(msg, "OpenSSL disabled") || strstr(msg, "ca load failed");
}

static void comm_open_circuit(const char *reason) {
  int sec = (int)env_ul_clamped("EDR_HTTP_CIRCUIT_OPEN_S", 60ul, 10ul, 3600ul);
  s_circuit_open = 1;
  s_circuit_until_ms = unix_ms_now() + (int64_t)sec * 1000LL;
  snprintf(s_circuit_reason, sizeof(s_circuit_reason), "%s", reason ? reason : "transport failures");
}

int edr_ingest_http_circuit_open(void) {
  int64_t now;
  if (!s_circuit_open) {
    return 0;
  }
  now = unix_ms_now();
  if (now >= s_circuit_until_ms) {
    s_circuit_open = 0;
    s_circuit_until_ms = 0;
    s_circuit_reason[0] = '\0';
    s_consecutive_failures = 0;
    return 0;
  }
  return 1;
}

static int comm_circuit_allows(void) {
  int64_t now;
  if (!edr_ingest_http_circuit_open()) {
    return 1;
  }
  now = unix_ms_now();
  snprintf(s_last_error, sizeof(s_last_error), "circuit open: %s", s_circuit_reason);
  s_last_failure_ms = now;
  return 0;
}

static void runtime_success(void) {
  s_http_ok++;
  s_last_success_ms = unix_ms_now();
  s_last_error[0] = '\0';
  s_consecutive_failures = 0;
  s_circuit_open = 0;
  s_circuit_until_ms = 0;
  s_circuit_reason[0] = '\0';
}

static void runtime_failure(const char *msg) {
  unsigned threshold;
  s_http_fail++;
  s_last_failure_ms = unix_ms_now();
  snprintf(s_last_error, sizeof(s_last_error), "%s", msg ? msg : "");
  s_consecutive_failures++;
  threshold = (unsigned)env_ul_clamped("EDR_HTTP_CIRCUIT_FAILURES", 3ul, 1ul, 100ul);
  if (!s_circuit_open && s_consecutive_failures >= threshold && failure_should_open_circuit(msg)) {
    comm_open_circuit(msg);
  }
}

static void note_http_request_success(void) {
  s_http_request_ok++;
  runtime_success();
}

static void note_http_request_failure(void) {
  s_http_request_fail++;
}

static void note_ws_message_success(void) {
  s_ws_message_ok++;
  runtime_success();
}

static void note_ws_message_failure(const char *msg) {
  s_ws_message_fail++;
  runtime_failure(msg);
}

static void note_command_result_success(void) {
  s_command_result_ok++;
}

static void note_command_result_failure(void) {
  s_command_result_fail++;
}

static void note_upload_success(void) {
  s_upload_ok++;
}

static void note_upload_failure(void) {
  s_upload_fail++;
}

static void note_long_poll_success(void) {
  s_long_poll_ok++;
}

static void note_long_poll_failure(void) {
  s_long_poll_fail++;
}

static void note_control_stream_success(void) {
  s_control_stream_ok++;
}

static void note_control_stream_failure(void) {
  s_control_stream_fail++;
}

static void note_control_stream_heartbeat(void) {
  s_control_stream_heartbeat++;
}

static void note_control_ack_success(void) {
  s_control_ack_ok++;
}

static void note_control_ack_failure(void) {
  s_control_ack_fail++;
}

static void log_native_post_failure(const char *label, int rc) {
  int64_t now = unix_ms_now();
  if (s_native_post_fail_log_until_ms > now) {
    s_native_post_fail_log_suppressed++;
    return;
  }
  unsigned long suppressed = s_native_post_fail_log_suppressed;
  s_native_post_fail_log_suppressed = 0;
  s_native_post_fail_log_until_ms =
      now + (int64_t)env_ul_clamped("EDR_HTTP_FAILURE_LOG_INTERVAL_MS", 60000ul, 1000ul, 600000ul);
  if (suppressed > 0ul) {
    fprintf(stderr, "[ingest-http] %s native post failed rc=%d (rest=%s err=%s suppressed=%lu)\n",
            label ? label : "request", rc, s_rest, s_last_error, suppressed);
    return;
  }
  fprintf(stderr, "[ingest-http] %s native post failed rc=%d (rest=%s err=%s)\n",
          label ? label : "request", rc, s_rest, s_last_error);
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

static void http_mu_init_once(void) {
#ifdef _WIN32
  if (!s_http_mu_init) {
    InitializeCriticalSection(&s_http_mu);
    s_http_mu_init = 1;
  }
#endif
}

static void http_lock(void) {
  http_mu_init_once();
#ifdef _WIN32
  EnterCriticalSection(&s_http_mu);
#else
  pthread_mutex_lock(&s_http_mu);
#endif
}

static void http_unlock(void) {
#ifdef _WIN32
  LeaveCriticalSection(&s_http_mu);
#else
  pthread_mutex_unlock(&s_http_mu);
#endif
}

static int http_keepalive_enabled(void) {
  const char *e = getenv("EDR_HTTP_KEEPALIVE");
  return !(e && e[0] == '0');
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
                                const char *client_key_file, const char *client_key_provider,
                                const char *client_cert_store,
                                const char *client_cert_thumbprint,
                                const char *proxy_mode,
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
  memset(s_client_key_provider, 0, sizeof(s_client_key_provider));
  memset(s_client_cert_store, 0, sizeof(s_client_cert_store));
  memset(s_client_cert_thumbprint, 0, sizeof(s_client_cert_thumbprint));
  memset(s_mtls_status, 0, sizeof(s_mtls_status));
  memset(s_relay_url, 0, sizeof(s_relay_url));
  memset(s_proxy_mode, 0, sizeof(s_proxy_mode));
  memset(s_proxy_url_cfg, 0, sizeof(s_proxy_url_cfg));
  memset(s_proxy_url_active, 0, sizeof(s_proxy_url_active));
  memset(s_proxy_status, 0, sizeof(s_proxy_status));
  memset(s_connection_mode, 0, sizeof(s_connection_mode));
  memset(s_control_dict_ver, 0, sizeof(s_control_dict_ver));
  memset(s_control_schema_ver, 0, sizeof(s_control_schema_ver));
  memset(s_control_profile_id, 0, sizeof(s_control_profile_id));
  memset(s_control_qos_dscp, 0, sizeof(s_control_qos_dscp));
  memset(s_control_threshold, 0, sizeof(s_control_threshold));
  snprintf(s_data_plane_encoding, sizeof(s_data_plane_encoding), "%s",
           env_str_default("EDR_DATA_PLANE_ENCODING", "protobuf"));
  snprintf(s_data_plane_compression, sizeof(s_data_plane_compression), "%s",
           env_str_default("EDR_DATA_PLANE_COMPRESSION", "identity"));
  s_circuit_open = 0;
  s_circuit_until_ms = 0;
  s_circuit_reason[0] = '\0';
  s_consecutive_failures = 0;
  s_control_hello_ok = 0;
  s_control_hello_last_ms = 0;
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
  if (client_cert_store && client_cert_store[0]) {
    snprintf(s_client_cert_store, sizeof(s_client_cert_store), "%s", client_cert_store);
  }
  if (client_cert_thumbprint && client_cert_thumbprint[0]) {
    compact_thumbprint(s_client_cert_thumbprint, sizeof(s_client_cert_thumbprint),
                       client_cert_thumbprint);
  }
  {
    const char *kp = getenv("EDR_CLIENT_KEY_PROVIDER");
    if (!kp || !kp[0]) {
      kp = client_key_provider;
    }
    snprintf(s_client_key_provider, sizeof(s_client_key_provider), "%s",
             (kp && kp[0]) ? kp : "pem");
  }
  if (s_client_cert_thumbprint[0]) {
    snprintf(s_mtls_status, sizeof(s_mtls_status), "%s", "schannel_store_ready");
  } else if (s_client_cert_file[0] && s_client_key_file[0]) {
    snprintf(s_mtls_status, sizeof(s_mtls_status), "%s", "pem_ready");
  } else if (s_client_cert_file[0] && strcmp(s_client_key_provider, "pem") != 0) {
    snprintf(s_mtls_status, sizeof(s_mtls_status), "native_http_%s_pending_adapter",
             s_client_key_provider);
  } else {
    snprintf(s_mtls_status, sizeof(s_mtls_status), "%s", "not_configured");
  }
  snprintf(s_proxy_mode, sizeof(s_proxy_mode), "%s",
           (proxy_mode_effective && proxy_mode_effective[0]) ? proxy_mode_effective : "auto");
  copy_base_url(s_proxy_url_cfg, sizeof(s_proxy_url_cfg), proxy_url_effective);
  snprintf(s_proxy_status, sizeof(s_proxy_status), "%s", "not_used");
  snprintf(s_control_dict_ver, sizeof(s_control_dict_ver), "%s",
           env_str_default("EDR_CONTROL_DICT_VERSION", "edr-zstd-dict-v1"));
  snprintf(s_control_schema_ver, sizeof(s_control_schema_ver), "%s",
           env_str_default("EDR_CONTROL_SCHEMA_VERSION", "edr-control-schema-v1"));
  snprintf(s_control_profile_id, sizeof(s_control_profile_id), "%s",
           env_str_default("EDR_CONTROL_PROFILE_ID", "default-h2-zstd"));
  snprintf(s_control_qos_dscp, sizeof(s_control_qos_dscp), "%s",
           env_str_default("EDR_NET_QOS_DSCP", "AF21"));
  snprintf(s_control_threshold, sizeof(s_control_threshold), "%s",
           env_str_default("EDR_TELEMETRY_PROFILE_THRESHOLD", "medium"));
  s_control_sampling_pct = (unsigned)env_ul_clamped("EDR_TELEMETRY_PROFILE_SAMPLING_PCT", 100ul, 1ul, 100ul);
  s_control_backpressure_enabled = env_bool_default("EDR_BACKPRESSURE_PUSH_PROFILE_THROTTLE", 1);
  s_control_h2 = env_bool_default("EDR_CONTROL_CAP_H2", 1);
  s_control_zstd = env_bool_default("EDR_CONTROL_CAP_ZSTD", 0);
  s_http2_enabled_cfg = env_bool_default("EDR_DATA_PLANE_HTTP2", 1);
  s_http2_required_cfg = env_bool_default("EDR_HTTP2_REQUIRE", 0);
  s_control_stream_enabled_cfg = env_bool_default("EDR_HTTP_CONTROL_STREAM", 1);
  s_long_poll_fallback_cfg = env_bool_default("EDR_CONTROL_LONG_POLL_FALLBACK", 1);
  s_report_events_v2_enabled_cfg = env_bool_default("EDR_REPORT_EVENTS_V2", 1);
  s_insecure_http = (strncmp(s_rest, "http://", 7u) == 0) ? 1 : 0;
}

int edr_ingest_http_configured(void) { return s_rest[0] != 0 && s_endpoint[0] != 0; }

void edr_ingest_http_configure_transport_options(int http2_enabled, int http2_required,
                                                 int control_stream_enabled,
                                                 int long_poll_fallback,
                                                 int report_events_v2_enabled,
                                                 const char *data_plane_encoding,
                                                 const char *data_plane_compression) {
  s_http2_enabled_cfg = http2_enabled ? 1 : 0;
  s_http2_required_cfg = http2_required ? 1 : 0;
  s_control_stream_enabled_cfg = control_stream_enabled ? 1 : 0;
  s_long_poll_fallback_cfg = long_poll_fallback ? 1 : 0;
  s_report_events_v2_enabled_cfg = report_events_v2_enabled ? 1 : 0;
  s_control_h2 = s_http2_enabled_cfg;
  if (data_plane_encoding && data_plane_encoding[0]) {
    snprintf(s_data_plane_encoding, sizeof(s_data_plane_encoding), "%s", data_plane_encoding);
  }
  if (data_plane_compression && data_plane_compression[0]) {
    snprintf(s_data_plane_compression, sizeof(s_data_plane_compression), "%s", data_plane_compression);
  }
  s_control_zstd = strcmp(s_data_plane_compression, "zstd") == 0 ? 1 : s_control_zstd;
  log_transport_capabilities_once();
}

void edr_ingest_http_apply_transport_flags(int http2_required, int control_stream_enabled,
                                           int long_poll_fallback,
                                           int report_events_v2_enabled) {
  if (http2_required >= 0) {
    s_http2_required_cfg = http2_required ? 1 : 0;
  }
  if (control_stream_enabled >= 0) {
    s_control_stream_enabled_cfg = control_stream_enabled ? 1 : 0;
  }
  if (long_poll_fallback >= 0) {
    s_long_poll_fallback_cfg = long_poll_fallback ? 1 : 0;
  }
  if (report_events_v2_enabled >= 0) {
    s_report_events_v2_enabled_cfg = report_events_v2_enabled ? 1 : 0;
  }
}

void edr_ingest_http_get_runtime(EdrIngestHttpRuntime *out) {
  if (!out) {
    return;
  }
  memset(out, 0, sizeof(*out));
  out->configured = edr_ingest_http_configured();
  out->http_fallback_available = out->configured;
  out->insecure_http = s_insecure_http;
  out->mtls_configured = (s_client_cert_file[0] && s_client_key_file[0]) ? 1 : 0;
  out->websocket_ready = (s_ws_ready || s_stream_ready) ? 1 : 0;
  out->http2_enabled = http2_client_enabled();
  out->http2_required = http2_required();
  out->http2_negotiated = s_http2_negotiated ? 1 : 0;
  out->control_stream_enabled = s_control_stream_enabled_cfg;
  out->control_stream_ready = s_stream_ready ? 1 : 0;
  out->long_poll_fallback = s_long_poll_fallback_cfg;
  out->report_events_v2_enabled = s_report_events_v2_enabled_cfg;
  out->zstd_requested = strcmp(s_data_plane_compression, "zstd") == 0 || s_control_zstd;
#ifdef EDR_HAVE_ZSTD
  out->zstd_available = 1;
#else
  out->zstd_available = 0;
#endif
  out->zstd_dict_loaded = s_zstd_dict_loaded ? 1 : 0;
  out->http2_multiplex_enabled = env_bool_default("EDR_HTTP2_MULTIPLEX", 1);
  out->http2_multiplex_active = s_http2_multiplex_active ? 1 : 0;
  out->poll_backoff_ms = s_poll_backoff_ms;
  out->ws_backoff_ms = s_ws_backoff_ms;
  out->circuit_open = s_circuit_open ? 1 : 0;
  out->circuit_until_unix_ms = s_circuit_until_ms;
  out->ok_count = s_http_ok;
  out->fail_count = s_http_fail;
  out->http_request_ok_count = s_http_request_ok;
  out->http_request_fail_count = s_http_request_fail;
  out->ws_message_ok_count = s_ws_message_ok;
  out->ws_message_fail_count = s_ws_message_fail;
  out->ws_pong_count = s_ws_pong;
  out->command_result_ok_count = s_command_result_ok;
  out->command_result_fail_count = s_command_result_fail;
  out->upload_ok_count = s_upload_ok;
  out->upload_fail_count = s_upload_fail;
  out->long_poll_ok_count = s_long_poll_ok;
  out->long_poll_fail_count = s_long_poll_fail;
  out->control_stream_ok_count = s_control_stream_ok;
  out->control_stream_fail_count = s_control_stream_fail;
  out->control_stream_heartbeat_count = s_control_stream_heartbeat;
  out->control_ack_ok_count = s_control_ack_ok;
  out->control_ack_fail_count = s_control_ack_fail;
  out->http2_request_ok_count = s_http2_request_ok;
  out->http2_request_fail_count = s_http2_request_fail;
  out->http2_negotiated_count = s_http2_negotiated_count;
  out->http2_fallback_count = s_http2_fallback_count;
  out->report_events_v2_ok_count = s_report_events_v2_ok;
  out->report_events_v2_fail_count = s_report_events_v2_fail;
  out->zstd_compress_ok_count = s_zstd_compress_ok;
  out->zstd_compress_fail_count = s_zstd_compress_fail;
  out->http2_multiplex_ok_count = s_http2_multiplex_ok;
  out->http2_multiplex_fail_count = s_http2_multiplex_fail;
  out->budget_drop_count = s_budget_drop_count;
  out->last_success_unix_ms = s_last_success_ms;
  out->last_failure_unix_ms = s_last_failure_ms;
  snprintf(out->last_error, sizeof(out->last_error), "%s", s_last_error);
  snprintf(out->circuit_reason, sizeof(out->circuit_reason), "%s", s_circuit_reason);
  snprintf(out->connection_mode, sizeof(out->connection_mode), "%s",
           s_connection_mode[0] ? s_connection_mode : "direct");
  snprintf(out->effective_base_url, sizeof(out->effective_base_url), "%s", s_rest);
  snprintf(out->relay_url, sizeof(out->relay_url), "%s", s_relay_url);
  snprintf(out->proxy_mode, sizeof(out->proxy_mode), "%s", s_proxy_mode[0] ? s_proxy_mode : "auto");
  snprintf(out->proxy_url, sizeof(out->proxy_url), "%s", s_proxy_url_active);
  snprintf(out->proxy_status, sizeof(out->proxy_status), "%s",
           s_proxy_status[0] ? s_proxy_status : "not_used");
  snprintf(out->client_key_provider, sizeof(out->client_key_provider), "%s",
           s_client_key_provider[0] ? s_client_key_provider : "pem");
  snprintf(out->mtls_status, sizeof(out->mtls_status), "%s",
           s_mtls_status[0] ? s_mtls_status : "not_configured");
  snprintf(out->negotiated_protocol, sizeof(out->negotiated_protocol), "%s",
           s_negotiated_protocol[0] ? s_negotiated_protocol : (s_http2_negotiated ? "h2" : "http/1.1"));
  snprintf(out->control_stream_status, sizeof(out->control_stream_status), "%s",
           s_control_stream_status[0] ? s_control_stream_status : "idle");
  snprintf(out->upload_status, sizeof(out->upload_status), "%s",
           s_upload_status[0] ? s_upload_status : "idle");
  snprintf(out->data_plane_encoding, sizeof(out->data_plane_encoding), "%s",
           s_data_plane_encoding[0] ? s_data_plane_encoding : "protobuf");
  snprintf(out->data_plane_compression, sizeof(out->data_plane_compression), "%s",
           s_data_plane_compression[0] ? s_data_plane_compression : "identity");
  snprintf(out->envelope_format, sizeof(out->envelope_format), "%s",
           s_report_events_v2_enabled_cfg ? "protobuf:edr.transport.envelope.v1" : "legacy_json_b64");
  snprintf(out->dict_ver, sizeof(out->dict_ver), "%s",
           s_control_dict_ver[0] ? s_control_dict_ver : "edr-zstd-dict-v1");
  snprintf(out->schema_ver, sizeof(out->schema_ver), "%s",
           s_control_schema_ver[0] ? s_control_schema_ver : "edr-control-schema-v1");
  snprintf(out->profile_id, sizeof(out->profile_id), "%s",
           s_control_profile_id[0] ? s_control_profile_id : "default-h2-zstd");
  snprintf(out->zstd_dict_path, sizeof(out->zstd_dict_path), "%s", s_zstd_dict_path);
  snprintf(out->qos_dscp, sizeof(out->qos_dscp), "%s",
           s_control_qos_dscp[0] ? s_control_qos_dscp : "AF21");
  snprintf(out->telemetry_threshold, sizeof(out->telemetry_threshold), "%s",
           s_control_threshold[0] ? s_control_threshold : "medium");
  out->telemetry_sampling_pct = s_control_sampling_pct;
  out->zstd_raw_bytes = s_zstd_raw_bytes;
  out->zstd_wire_bytes = s_zstd_wire_bytes;
  out->zstd_dict_bytes = s_zstd_dict_bytes;
  budget_refresh_window();
  out->requests_this_minute = s_budget_requests;
  out->request_limit_per_minute = request_limit_per_minute();
  out->bytes_this_minute = s_budget_bytes;
  out->byte_limit_per_minute = byte_limit_per_minute();
  out->tls_handshakes_this_minute = s_budget_tls_handshakes;
  out->tls_handshake_limit_per_minute = tls_handshake_limit_per_minute();
  {
    unsigned long total = s_http_ok + s_http_fail;
    out->slo_success_rate_pct = total ? (unsigned int)((s_http_ok * 100ul) / total) : 100u;
  }
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

void edr_ingest_http_apply_telemetry_profile(const char *dict_ver, const char *schema_ver,
                                             const char *profile_id, int h2, int zstd,
                                             const char *qos_dscp, unsigned sampling_pct,
                                             const char *threshold, int backpressure_enabled) {
  if (dict_ver && dict_ver[0]) {
    snprintf(s_control_dict_ver, sizeof(s_control_dict_ver), "%s", dict_ver);
  }
  if (schema_ver && schema_ver[0]) {
    snprintf(s_control_schema_ver, sizeof(s_control_schema_ver), "%s", schema_ver);
  }
  if (profile_id && profile_id[0]) {
    snprintf(s_control_profile_id, sizeof(s_control_profile_id), "%s", profile_id);
  }
  if (qos_dscp && qos_dscp[0]) {
    snprintf(s_control_qos_dscp, sizeof(s_control_qos_dscp), "%s", qos_dscp);
  }
  if (threshold && threshold[0]) {
    snprintf(s_control_threshold, sizeof(s_control_threshold), "%s", threshold);
  }
  if (sampling_pct > 0u) {
    if (sampling_pct > 100u) {
      sampling_pct = 100u;
    }
    s_control_sampling_pct = sampling_pct;
  }
  if (h2 >= 0) {
    s_control_h2 = h2 ? 1 : 0;
  }
  if (zstd >= 0) {
    s_control_zstd = zstd ? 1 : 0;
  }
  if (backpressure_enabled >= 0) {
    s_control_backpressure_enabled = backpressure_enabled ? 1 : 0;
  }
  s_control_hello_ok = 1;
  s_control_hello_last_ms = unix_ms_now();
  edr_transport_v2_apply_profile(dict_ver, schema_ver, profile_id, h2, zstd, qos_dscp,
                                 s_control_sampling_pct, threshold, backpressure_enabled);
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

static void proxy_auth_b64_from_config(const char *url_userinfo, size_t url_userinfo_len,
                                       char *out, size_t out_cap) {
  const char *auth_b64 = getenv("EDR_PROXY_AUTH_B64");
  const char *auth = getenv("EDR_PROXY_AUTH_BASIC");
  if (!out || out_cap == 0u) {
    return;
  }
  out[0] = '\0';
  if (auth_b64 && auth_b64[0]) {
    snprintf(out, out_cap, "%s", auth_b64);
    return;
  }
  if (auth && auth[0]) {
    (void)b64_encode((const uint8_t *)auth, strlen(auth), out, out_cap);
    return;
  }
  if (url_userinfo && url_userinfo_len > 0u && url_userinfo_len < 192u) {
    (void)b64_encode((const uint8_t *)url_userinfo, url_userinfo_len, out, out_cap);
  }
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

static size_t pb_varint_len(uint64_t v) {
  size_t n = 1u;
  while (v >= 0x80u) {
    v >>= 7;
    n++;
  }
  return n;
}

static size_t pb_write_varint(uint8_t *out, uint64_t v) {
  size_t n = 0u;
  while (v >= 0x80u) {
    out[n++] = (uint8_t)(v | 0x80u);
    v >>= 7;
  }
  out[n++] = (uint8_t)v;
  return n;
}

static size_t pb_field_len(int field_no, size_t len) {
  return pb_varint_len((uint64_t)((field_no << 3) | 2)) + pb_varint_len((uint64_t)len) + len;
}

static size_t pb_write_bytes(uint8_t *out, int field_no, const void *data, size_t len) {
  size_t n = 0u;
  n += pb_write_varint(out + n, (uint64_t)((field_no << 3) | 2));
  n += pb_write_varint(out + n, (uint64_t)len);
  if (len > 0u && data) {
    memcpy(out + n, data, len);
    n += len;
  }
  return n;
}

static int ci_equals(const char *a, const char *b) {
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
  return *a == '\0' && *b == '\0';
}

static int report_events_v2_should_use(void) {
  if (!s_report_events_v2_enabled_cfg) {
    return 0;
  }
  if (ci_equals(s_data_plane_encoding, "json")) {
    return 0;
  }
  return 1;
}

#ifdef EDR_HAVE_ZSTD
static int zstd_read_dict_file(const char *path, uint8_t **out, size_t *out_len) {
  FILE *f;
  long sz;
  uint8_t *buf;
  if (!path || !path[0] || !out || !out_len) {
    return -1;
  }
  *out = NULL;
  *out_len = 0u;
  f = fopen(path, "rb");
  if (!f) {
    return -1;
  }
  if (fseek(f, 0L, SEEK_END) != 0) {
    fclose(f);
    return -1;
  }
  sz = ftell(f);
  if (sz <= 0L || sz > 4L * 1024L * 1024L) {
    fclose(f);
    return -1;
  }
  if (fseek(f, 0L, SEEK_SET) != 0) {
    fclose(f);
    return -1;
  }
  buf = (uint8_t *)malloc((size_t)sz);
  if (!buf) {
    fclose(f);
    return -1;
  }
  if (fread(buf, 1u, (size_t)sz, f) != (size_t)sz) {
    free(buf);
    fclose(f);
    return -1;
  }
  fclose(f);
  *out = buf;
  *out_len = (size_t)sz;
  return 0;
}

static void zstd_load_dict_once(void) {
  const char *path;
  if (s_zstd_dict_load_attempted) {
    return;
  }
  s_zstd_dict_load_attempted = 1;
  path = getenv("EDR_ZSTD_DICT_PATH");
  if (!path || !path[0]) {
    path = getenv("EDR_CONTROL_DICT_PATH");
  }
  if (!path || !path[0]) {
    return;
  }
  snprintf(s_zstd_dict_path, sizeof(s_zstd_dict_path), "%s", path);
  if (zstd_read_dict_file(path, &s_zstd_dict, &s_zstd_dict_len) == 0) {
    s_zstd_dict_loaded = 1;
    s_zstd_dict_bytes = (uint64_t)s_zstd_dict_len;
  }
}
#endif

static int zstd_requested_for_data_plane(void) {
  return ci_equals(s_data_plane_compression, "zstd") || s_control_zstd;
}

static int maybe_zstd_compress_payload(const uint8_t *raw, size_t raw_len,
                                       uint8_t **out, size_t *out_len,
                                       const char **codec) {
  if (!out || !out_len || !codec) {
    return -1;
  }
  *out = NULL;
  *out_len = 0u;
  *codec = "identity";
  if (!zstd_requested_for_data_plane()) {
    return 0;
  }
#ifdef EDR_HAVE_ZSTD
  {
    size_t bound;
    uint8_t *dst;
    size_t n;
    int level = (int)env_ul_clamped("EDR_ZSTD_LEVEL", 3ul, 1ul, 19ul);
    ZSTD_CCtx *cctx;
    zstd_load_dict_once();
    bound = ZSTD_compressBound(raw_len);
    dst = (uint8_t *)malloc(bound);
    if (!dst) {
      s_zstd_compress_fail++;
      return 0;
    }
    cctx = ZSTD_createCCtx();
    if (!cctx) {
      free(dst);
      s_zstd_compress_fail++;
      return 0;
    }
    if (s_zstd_dict && s_zstd_dict_len > 0u) {
      n = ZSTD_compress_usingDict(cctx, dst, bound, raw, raw_len,
                                  s_zstd_dict, s_zstd_dict_len, level);
    } else {
      n = ZSTD_compressCCtx(cctx, dst, bound, raw, raw_len, level);
    }
    ZSTD_freeCCtx(cctx);
    if (ZSTD_isError(n)) {
      free(dst);
      s_zstd_compress_fail++;
      return 0;
    }
    *out = dst;
    *out_len = n;
    *codec = "zstd";
    s_zstd_compress_ok++;
    s_zstd_raw_bytes += (uint64_t)raw_len;
    s_zstd_wire_bytes += (uint64_t)n;
    return 0;
  }
#else
  s_zstd_compress_fail++;
  return 0;
#endif
}

static int build_report_events_v2_envelope(const char *batch_id,
                                           const uint8_t *header12, size_t header_len,
                                           const uint8_t *payload, size_t payload_len,
                                           uint8_t **out, size_t *out_len) {
  const char *version = "edr.transport.envelope.v1";
  const char *codec = "identity";
  size_t raw_len = header_len + payload_len;
  const uint8_t *wire_payload;
  size_t wire_payload_len;
  uint8_t *compressed = NULL;
  size_t compressed_len = 0u;
  size_t cap;
  uint8_t *buf;
  uint8_t *raw;
  size_t n = 0u;
  if (!out || !out_len || !batch_id || !header12 || header_len == 0u || !payload || payload_len == 0u) {
    return -1;
  }
  raw = (uint8_t *)malloc(raw_len);
  if (!raw) {
    return -1;
  }
  memcpy(raw, header12, header_len);
  memcpy(raw + header_len, payload, payload_len);
  if (maybe_zstd_compress_payload(raw, raw_len, &compressed, &compressed_len, &codec) != 0) {
    free(raw);
    return -1;
  }
  wire_payload = compressed ? compressed : raw;
  wire_payload_len = compressed ? compressed_len : raw_len;
  cap = pb_field_len(1, strlen(version)) +
        pb_field_len(2, strlen(s_endpoint)) +
        pb_field_len(3, strlen(batch_id)) +
        pb_field_len(4, strlen(s_agent_ver)) +
        pb_field_len(5, strlen(s_control_dict_ver)) +
        pb_field_len(6, strlen(s_control_schema_ver)) +
        pb_field_len(7, strlen(s_control_profile_id)) +
        pb_field_len(8, strlen(codec)) +
        pb_field_len(9, wire_payload_len) + 32u;
  buf = (uint8_t *)malloc(cap);
  if (!buf) {
    free(compressed);
    free(raw);
    return -1;
  }
  n += pb_write_bytes(buf + n, 1, version, strlen(version));
  n += pb_write_bytes(buf + n, 2, s_endpoint, strlen(s_endpoint));
  n += pb_write_bytes(buf + n, 3, batch_id, strlen(batch_id));
  n += pb_write_bytes(buf + n, 4, s_agent_ver, strlen(s_agent_ver));
  n += pb_write_bytes(buf + n, 5, s_control_dict_ver, strlen(s_control_dict_ver));
  n += pb_write_bytes(buf + n, 6, s_control_schema_ver, strlen(s_control_schema_ver));
  n += pb_write_bytes(buf + n, 7, s_control_profile_id, strlen(s_control_profile_id));
  n += pb_write_bytes(buf + n, 8, codec, strlen(codec));
  n += pb_write_bytes(buf + n, 9, wire_payload, wire_payload_len);
  free(compressed);
  free(raw);
  *out = buf;
  *out_len = n;
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

static int json_get_bool(const char *obj, const char *key, int *out) {
  char needle[96];
  const char *p;
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
  while (*p && isspace((unsigned char)*p)) p++;
  if (strncmp(p, "true", 4u) == 0) {
    *out = 1;
    return 0;
  }
  if (strncmp(p, "false", 5u) == 0) {
    *out = 0;
    return 0;
  }
  return -1;
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
  char auth_b64[256];
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

static int ascii_contains_ci(const char *s, const char *needle) {
  size_t nlen;
  if (!s || !needle) {
    return 0;
  }
  nlen = strlen(needle);
  if (nlen == 0u) {
    return 1;
  }
  for (; *s; ++s) {
    size_t i;
    for (i = 0u; i < nlen; ++i) {
      if (!s[i] || tolower((unsigned char)s[i]) != tolower((unsigned char)needle[i])) {
        break;
      }
    }
    if (i == nlen) {
      return 1;
    }
  }
  return 0;
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

#ifdef _WIN32
static int proxy_server_pick(const char *server, int https, char *out, size_t cap) {
  char buf[1024];
  char *p;
  const char *want = https ? "https=" : "http=";
  if (!server || !server[0] || !out || cap == 0u) {
    return -1;
  }
  snprintf(buf, sizeof(buf), "%s", server);
  p = buf;
  while (*p) {
    char *tok = p;
    char *end;
    while (*p && *p != ';') p++;
    if (*p == ';') *p++ = '\0';
    while (*tok && isspace((unsigned char)*tok)) tok++;
    end = tok + strlen(tok);
    while (end > tok && isspace((unsigned char)end[-1])) *--end = '\0';
    if (strncmp(tok, want, strlen(want)) == 0) {
      tok += strlen(want);
      snprintf(out, cap, "%s%s", strstr(tok, "://") ? "" : "http://", tok);
      return 0;
    }
  }
  if (!strchr(server, '=')) {
    snprintf(out, cap, "%s%s", strstr(server, "://") ? "" : "http://", server);
    return 0;
  }
  return -1;
}

static int wininet_proxy_for_scheme(int https, char *out, size_t cap) {
  DWORD enable = 0;
  DWORD enable_sz = sizeof(enable);
  char proxy_server[1024];
  DWORD proxy_sz = sizeof(proxy_server);
  char auto_config[1024];
  DWORD auto_sz = sizeof(auto_config);
  if (!out || cap == 0u) {
    return -1;
  }
  out[0] = '\0';
  proxy_server[0] = '\0';
  auto_config[0] = '\0';
  if (RegGetValueA(HKEY_CURRENT_USER,
                   "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
                   "ProxyEnable", RRF_RT_REG_DWORD, NULL, &enable, &enable_sz) != ERROR_SUCCESS ||
      enable == 0) {
    if (RegGetValueA(HKEY_CURRENT_USER,
                     "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
                     "AutoConfigURL", RRF_RT_REG_SZ, NULL, auto_config, &auto_sz) == ERROR_SUCCESS &&
        auto_config[0]) {
      return -2;
    }
    return -1;
  }
  if (RegGetValueA(HKEY_CURRENT_USER,
                   "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
                   "ProxyServer", RRF_RT_REG_SZ, NULL, proxy_server, &proxy_sz) != ERROR_SUCCESS ||
      !proxy_server[0]) {
    return -1;
  }
  return proxy_server_pick(proxy_server, https, out, cap);
}
#endif

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
    size_t cred_len = (size_t)(at - p);
    proxy_auth_b64_from_config(p, cred_len, out->auth_b64, sizeof(out->auth_b64));
    p = at + 1;
  } else {
    proxy_auth_b64_from_config(NULL, 0u, out->auth_b64, sizeof(out->auth_b64));
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
#ifdef _WIN32
    if (!url || !url[0]) {
      static char win_proxy_url[512];
      int wr = wininet_proxy_for_scheme(https, win_proxy_url, sizeof(win_proxy_url));
      if (wr == 0) {
        url = win_proxy_url;
      } else if (wr == -2) {
        set_proxy_status("auto:pac_unsupported", NULL);
        return 0;
      }
    }
#endif
  }
  if (!url || !url[0]) {
    set_proxy_status(ascii_eq_ci(mode, "explicit") ? "explicit:missing" : "auto:none", NULL);
    return 0;
  }
  if (parse_proxy_url(url, out) != 0) {
    set_proxy_status("invalid", NULL);
    return ascii_eq_ci(mode, "explicit") ? -1 : 0;
  }
  set_proxy_status(s_proxy_url_cfg[0] ? "explicit" :
#ifdef _WIN32
                   (url && strstr(url, "://") ? "auto" : "auto:wininet"),
#else
                   "auto:env",
#endif
                   out->url);
  return 0;
}

static int net_init(void) {
#ifdef _WIN32
  static int started = 0;
  WSADATA w;
  if (started) {
    return 0;
  }
  {
    int rc = WSAStartup(MAKEWORD(2, 2), &w);
    if (rc == 0) {
      started = 1;
    }
    return rc;
  }
#else
  return 0;
#endif
}

static void net_done(void) {
#ifdef _WIN32
  /* Keep Winsock initialized for persistent HTTP/WebSocket connections. */
#endif
}

static void close_fd(EdrSocket fd) {
#ifdef _WIN32
  closesocket(fd);
#else
  close(fd);
#endif
}

static void socket_enable_keepalive(EdrSocket fd);

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
  socket_enable_keepalive(fd);
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

static void socket_enable_keepalive(EdrSocket fd) {
  if (fd == EDR_SOCKET_INVALID) {
    return;
  }
#ifdef _WIN32
  {
    BOOL on = TRUE;
    (void)setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (const char *)&on, sizeof(on));
  }
#else
  {
    int on = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on));
  }
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
                "Proxy-Connection: Keep-Alive\r\n",
                host, port, host, port);
  if (rn <= 0 || (size_t)rn >= sizeof(req)) {
    runtime_failure("proxy CONNECT request build failed");
    close_fd(*out_fd);
    *out_fd = EDR_SOCKET_INVALID;
    return -1;
  }
  if (proxy.auth_b64[0]) {
    size_t used = (size_t)rn;
    int an = snprintf(req + used, sizeof(req) - used,
                      "Proxy-Authorization: Basic %s\r\n", proxy.auth_b64);
    if (an <= 0 || (size_t)an >= sizeof(req) - used) {
      runtime_failure("proxy auth header build failed");
      close_fd(*out_fd);
      *out_fd = EDR_SOCKET_INVALID;
      return -1;
    }
    rn += an;
  }
  {
    size_t used = (size_t)rn;
    int en = snprintf(req + used, sizeof(req) - used, "\r\n");
    if (en <= 0 || (size_t)en >= sizeof(req) - used) {
      runtime_failure("proxy CONNECT request build failed");
      close_fd(*out_fd);
      *out_fd = EDR_SOCKET_INVALID;
      return -1;
    }
    rn += en;
  }
  if (write_all_plain(*out_fd, req, (size_t)rn) != 0 ||
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
		               "X-Endpoint-ID: %s\r\n"
		               "X-User-ID: %s\r\n"
		               "X-Permission-Set: telemetry:write,endpoint:attack_surface_report\r\n",
	               s_tenant[0] ? s_tenant : "demo-tenant",
	               s_endpoint[0] ? s_endpoint : "",
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
  n = snprintf(req + used, cap - used, "Connection: %s\r\n\r\n",
               http_keepalive_enabled() ? "keep-alive" : "close");
  if (n <= 0 || (size_t)n >= cap - used) {
    return -1;
  }
  return (int)(used + (size_t)n);
}

static int ascii_starts_ci(const char *s, const char *prefix) {
  if (!s || !prefix) return 0;
  while (*prefix) {
    if (tolower((unsigned char)*s) != tolower((unsigned char)*prefix)) return 0;
    s++;
    prefix++;
  }
  return 1;
}

static const char *ascii_find_ci(const char *hay, const char *needle) {
  size_t nl;
  if (!hay || !needle || !needle[0]) return NULL;
  nl = strlen(needle);
  for (const char *p = hay; *p; p++) {
    size_t i;
    for (i = 0; i < nl; i++) {
      if (!p[i] || tolower((unsigned char)p[i]) != tolower((unsigned char)needle[i])) break;
    }
    if (i == nl) return p;
  }
  return NULL;
}

static long parse_content_length_header(const char *headers) {
  const char *p = ascii_find_ci(headers, "\r\ncontent-length:");
  char *endp = NULL;
  if (!p && ascii_starts_ci(headers, "content-length:")) {
    p = headers;
  }
  if (!p) return -1;
  p = strchr(p, ':');
  if (!p) return -1;
  p++;
  while (*p && isspace((unsigned char)*p)) p++;
  {
    long v = strtol(p, &endp, 10);
    return (endp && endp != p && v >= 0) ? v : -1;
  }
}

static int headers_connection_close(const char *headers) {
  const char *p = ascii_find_ci(headers, "\r\nconnection:");
  if (!p && ascii_starts_ci(headers, "connection:")) p = headers;
  if (!p) return 0;
  return ascii_find_ci(p, "close") != NULL;
}

static int headers_chunked(const char *headers) {
  const char *p = ascii_find_ci(headers, "\r\ntransfer-encoding:");
  if (!p && ascii_starts_ci(headers, "transfer-encoding:")) p = headers;
  if (!p) return 0;
  return ascii_find_ci(p, "chunked") != NULL;
}

static void append_body_copy(char *body, size_t body_cap, size_t *body_used,
                             const char *src, size_t src_len) {
  size_t copy;
  if (!body || body_cap == 0u || !body_used || !src || src_len == 0u) return;
  if (*body_used >= body_cap - 1u) return;
  copy = src_len;
  if (copy > body_cap - 1u - *body_used) copy = body_cap - 1u - *body_used;
  memcpy(body + *body_used, src, copy);
  *body_used += copy;
  body[*body_used] = '\0';
}

static int read_http_response_from_recv(int (*recvfn)(void *ctx, char *buf, int cap), void *ctx,
                                        char *body, size_t body_cap, int *out_reusable) {
  char buf[8192];
  size_t used = 0;
  size_t header_len = 0;
  size_t body_used = 0;
  long content_len = -1;
  int status_ok = 0;
  int reusable = 0;
  if (body && body_cap > 0u) body[0] = '\0';
  if (out_reusable) *out_reusable = 0;
  for (;;) {
    int n;
    if (used >= sizeof(buf) - 1u) return -1;
    n = recvfn(ctx, buf + used, (int)(sizeof(buf) - 1u - used));
    if (n <= 0) return -1;
    used += (size_t)n;
    buf[used] = '\0';
    {
      char *hdr = strstr(buf, "\r\n\r\n");
      if (!hdr) continue;
      header_len = (size_t)(hdr + 4 - buf);
      status_ok = (strncmp(buf, "HTTP/1.1 2", 10u) == 0 || strncmp(buf, "HTTP/1.0 2", 10u) == 0);
      content_len = parse_content_length_header(buf);
      reusable = status_ok && content_len >= 0 && !headers_connection_close(buf) && !headers_chunked(buf);
      if (used > header_len) {
        append_body_copy(body, body_cap, &body_used, buf + header_len, used - header_len);
      }
      break;
    }
  }
  if (content_len >= 0) {
    while ((long)(used - header_len) < content_len) {
      char tmp[4096];
      size_t got = used - header_len;
      long remain = content_len - (long)got;
      int want = remain > (long)sizeof(tmp) ? (int)sizeof(tmp) : (int)remain;
      int n = recvfn(ctx, tmp, want);
      if (n <= 0) return -1;
      used += (size_t)n;
      append_body_copy(body, body_cap, &body_used, tmp, (size_t)n);
    }
  } else {
    reusable = 0;
  }
  if (out_reusable) *out_reusable = reusable;
  return status_ok ? 0 : -1;
}

static int write_response_chunk_to_file(FILE *f, size_t *written, size_t max_bytes,
                                        const char *src, size_t src_len) {
  if (!f || !written || !src || src_len == 0u) {
    return 0;
  }
  if (*written > max_bytes || src_len > max_bytes - *written) {
    runtime_failure("http get response too large");
    return -1;
  }
  if (fwrite(src, 1u, src_len, f) != src_len) {
    runtime_failure("http get output write failed");
    return -1;
  }
  *written += src_len;
  return 0;
}

static int read_http_response_to_file_from_recv(int (*recvfn)(void *ctx, char *buf, int cap), void *ctx,
                                                FILE *out, size_t max_bytes, int *out_reusable) {
  char buf[8192];
  size_t used = 0;
  size_t header_len = 0;
  size_t written = 0;
  long content_len = -1;
  int status_ok = 0;
  int reusable = 0;
  if (out_reusable) *out_reusable = 0;
  if (!out || max_bytes == 0u) return -1;
  for (;;) {
    int n;
    if (used >= sizeof(buf) - 1u) return -1;
    n = recvfn(ctx, buf + used, (int)(sizeof(buf) - 1u - used));
    if (n <= 0) return -1;
    used += (size_t)n;
    buf[used] = '\0';
    {
      char *hdr = strstr(buf, "\r\n\r\n");
      if (!hdr) continue;
      header_len = (size_t)(hdr + 4 - buf);
      status_ok = (strncmp(buf, "HTTP/1.1 2", 10u) == 0 || strncmp(buf, "HTTP/1.0 2", 10u) == 0);
      content_len = parse_content_length_header(buf);
      reusable = status_ok && content_len >= 0 && !headers_connection_close(buf) && !headers_chunked(buf);
      if (!status_ok || content_len < 0 || headers_chunked(buf)) {
        return -1;
      }
      if ((unsigned long)content_len > (unsigned long)max_bytes) {
        runtime_failure("http get response too large");
        return -1;
      }
      if (used > header_len &&
          write_response_chunk_to_file(out, &written, max_bytes, buf + header_len, used - header_len) != 0) {
        return -1;
      }
      break;
    }
  }
  while ((long)written < content_len) {
    char tmp[4096];
    long remain = content_len - (long)written;
    int want = remain > (long)sizeof(tmp) ? (int)sizeof(tmp) : (int)remain;
    int n = recvfn(ctx, tmp, want);
    if (n <= 0) return -1;
    if (write_response_chunk_to_file(out, &written, max_bytes, tmp, (size_t)n) != 0) {
      return -1;
    }
  }
  if (out_reusable) *out_reusable = reusable;
  return 0;
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

static int http_socket_recv_adapter(void *ctx, char *buf, int cap) {
  EdrHttpConn *c = (EdrHttpConn *)ctx;
#ifdef EDR_HAVE_OPENSSL_HTTP
  if (c && c->ssl) {
    return SSL_read(c->ssl, buf, cap);
  }
#endif
  if (!c) return -1;
#ifdef _WIN32
  return recv(c->fd, buf, cap, 0);
#else
  return (int)recv(c->fd, buf, (size_t)cap, 0);
#endif
}

static int http_conn_write_all(EdrHttpConn *c, const char *p, size_t n) {
  if (!c || !c->active || !p) return -1;
#ifdef EDR_HAVE_OPENSSL_HTTP
  if (c->ssl) {
    return write_all_ssl(c->ssl, p, n);
  }
#endif
  return write_all_plain(c->fd, p, n);
}

static void http_conn_close_locked(void) {
  if (!s_http_conn.active) {
    return;
  }
#ifdef EDR_HAVE_OPENSSL_HTTP
  if (s_http_conn.ssl) {
    SSL_shutdown(s_http_conn.ssl);
    SSL_free(s_http_conn.ssl);
    s_http_conn.ssl = NULL;
  }
  if (s_http_conn.ctx) {
    SSL_CTX_free(s_http_conn.ctx);
    s_http_conn.ctx = NULL;
  }
#endif
  if (s_http_conn.fd != EDR_SOCKET_INVALID) {
    close_fd(s_http_conn.fd);
  }
  memset(&s_http_conn, 0, sizeof(s_http_conn));
  s_http_conn.fd = EDR_SOCKET_INVALID;
}

static int http_conn_matches_locked(const char *host, int port, int https) {
  int64_t idle_ms;
  if (!http_keepalive_enabled()) {
    http_conn_close_locked();
    return 0;
  }
  if (!s_http_conn.active || s_http_conn.fd == EDR_SOCKET_INVALID) return 0;
  idle_ms = unix_ms_now() - s_http_conn.last_used_ms;
  if (idle_ms > (int64_t)env_ul_clamped("EDR_HTTP_KEEPALIVE_IDLE_MS", 30000ul, 1000ul, 300000ul)) {
    http_conn_close_locked();
    return 0;
  }
  return s_http_conn.https == https && s_http_conn.port == port &&
         strcmp(s_http_conn.host, host ? host : "") == 0;
}

static EdrHttpConn *http_conn_get_locked(const char *host, int port, int https) {
  if (http_conn_matches_locked(host, port, https)) {
    return &s_http_conn;
  }
  http_conn_close_locked();
  memset(&s_http_conn, 0, sizeof(s_http_conn));
  s_http_conn.fd = EDR_SOCKET_INVALID;
  if (https && !comm_tls_handshake_budget_try()) {
    return NULL;
  }
  if (tcp_connect_http_route(host, port, https, &s_http_conn.fd) != 0) {
    runtime_failure(https ? "https tcp connect failed" : "http connect failed");
    return NULL;
  }
  socket_set_timeout_ms(s_http_conn.fd, (int)env_ul_clamped("EDR_HTTP_SOCKET_TIMEOUT_MS", 10000ul, 1000ul, 120000ul));
  snprintf(s_http_conn.host, sizeof(s_http_conn.host), "%s", host ? host : "");
  s_http_conn.port = port;
  s_http_conn.https = https;
#ifdef EDR_HAVE_OPENSSL_HTTP
  if (https) {
    char active_cafile[1024];
    s_http_conn.ctx = new_https_ctx(active_cafile, sizeof(active_cafile));
    if (!s_http_conn.ctx) {
      http_conn_close_locked();
      return NULL;
    }
    s_http_conn.ssl = SSL_new(s_http_conn.ctx);
    if (!s_http_conn.ssl) {
      runtime_failure_openssl("https ssl new failed");
      http_conn_close_locked();
      return NULL;
    }
#ifdef _WIN32
    SSL_set_fd(s_http_conn.ssl, (int)s_http_conn.fd);
#else
    SSL_set_fd(s_http_conn.ssl, s_http_conn.fd);
#endif
    (void)SSL_set_tlsext_host_name(s_http_conn.ssl, host);
    if (SSL_connect(s_http_conn.ssl) != 1) {
      long verify = SSL_get_verify_result(s_http_conn.ssl);
      if (verify != X509_V_OK) {
        char msg[160];
        snprintf(msg, sizeof(msg), "https tls verify failed: %s ca=%s",
                 X509_verify_cert_error_string(verify),
                 active_cafile[0] ? active_cafile : "<default>");
        runtime_failure(msg);
      } else {
        runtime_failure_openssl("https tls connect failed");
      }
      http_conn_close_locked();
      return NULL;
    }
  }
#else
  if (https) {
    runtime_failure("https requested but OpenSSL disabled");
    http_conn_close_locked();
    return NULL;
  }
#endif
  s_http_conn.active = 1;
  s_http_conn.last_used_ms = unix_ms_now();
  return &s_http_conn;
}

static int append_headers(char *req, size_t cap, const char *path, const char *host,
                          const char *body, size_t body_len) {
  int n = snprintf(req, cap,
                   "POST %s HTTP/1.1\r\n"
                   "Host: %s\r\n"
                   "Content-Type: application/json\r\n"
                   "Content-Length: %zu\r\n"
		                   "X-Tenant-ID: %s\r\n"
		                   "X-Endpoint-ID: %s\r\n"
		                   "X-User-ID: %s\r\n"
		                   "X-Permission-Set: telemetry:write,endpoint:attack_surface_report\r\n",
	                   path, host, body_len, s_tenant[0] ? s_tenant : "demo-tenant",
	                   s_endpoint[0] ? s_endpoint : "",
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
	    int m = snprintf(req + used, cap - used, "Connection: %s\r\n\r\n",
	                     http_keepalive_enabled() ? "keep-alive" : "close");
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

static int native_request(const char *method, const char *url, const char *content_type,
                          const char *body, size_t body_len, char *resp_body,
                          size_t resp_body_cap);
static int stream_consume_bytes(char *line, size_t line_cap, size_t *line_len,
                                const char *buf, size_t len);
static const char *base_name_ptr(const char *path);

static int native_post_json(const char *url, const char *body, size_t body_len) {
  return native_request("POST", url, "application/json", body, body_len, NULL, 0u);
}

#ifdef EDR_HAVE_CURL_HTTP2
typedef struct {
  char *buf;
  size_t cap;
  size_t len;
} EdrCurlBuffer;

typedef struct {
  char line[262144];
  size_t line_len;
  int failed;
} EdrCurlStreamCtx;

typedef struct EdrCurlMultiJob {
  CURL *easy;
  int done;
  int status;
  CURLcode result;
  long response_code;
  int h2;
  EdrCurlStreamCtx *stream_ctx;
  struct EdrCurlMultiJob *next;
} EdrCurlMultiJob;

static int curl_note_http_version(CURL *curl);

#ifdef _WIN32
static CRITICAL_SECTION s_curl_multi_mu;
static CONDITION_VARIABLE s_curl_multi_cv;
static HANDLE s_curl_multi_thread;
static int s_curl_multi_mu_init;
#else
static pthread_mutex_t s_curl_multi_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t s_curl_multi_cv = PTHREAD_COND_INITIALIZER;
static pthread_t s_curl_multi_thread;
#endif
static int s_curl_multi_started;
static CURLM *s_curl_multi;
static EdrCurlMultiJob *s_curl_multi_pending_head;
static EdrCurlMultiJob *s_curl_multi_pending_tail;
static unsigned s_curl_multi_active_count;

static int curl_global_ready(void) {
  static int ready = 0;
  if (ready) {
    return 1;
  }
  if (curl_global_init(CURL_GLOBAL_DEFAULT) == 0) {
    ready = 1;
  }
  return ready;
}

static int curl_h2_multiplex_enabled(void) {
  return env_bool_default("EDR_HTTP2_MULTIPLEX", 1);
}

static void curl_multi_sync_init(void) {
#ifdef _WIN32
  if (!s_curl_multi_mu_init) {
    InitializeCriticalSection(&s_curl_multi_mu);
    InitializeConditionVariable(&s_curl_multi_cv);
    s_curl_multi_mu_init = 1;
  }
#endif
}

static void curl_multi_lock(void) {
  curl_multi_sync_init();
#ifdef _WIN32
  EnterCriticalSection(&s_curl_multi_mu);
#else
  pthread_mutex_lock(&s_curl_multi_mu);
#endif
}

static void curl_multi_unlock(void) {
#ifdef _WIN32
  LeaveCriticalSection(&s_curl_multi_mu);
#else
  pthread_mutex_unlock(&s_curl_multi_mu);
#endif
}

static void curl_multi_signal(void) {
#ifdef _WIN32
  WakeAllConditionVariable(&s_curl_multi_cv);
#else
  pthread_cond_broadcast(&s_curl_multi_cv);
#endif
}

static void curl_multi_wait_cv(void) {
#ifdef _WIN32
  SleepConditionVariableCS(&s_curl_multi_cv, &s_curl_multi_mu, INFINITE);
#else
  pthread_cond_wait(&s_curl_multi_cv, &s_curl_multi_mu);
#endif
}

static void curl_multi_complete_job(CURLM *multi, EdrCurlMultiJob *job, CURLcode result) {
  int ok = 0;
  if (!job) {
    return;
  }
  if (multi && job->easy) {
    curl_multi_remove_handle(multi, job->easy);
  }
  job->result = result;
  job->h2 = job->easy ? curl_note_http_version(job->easy) : 0;
  if (job->easy) {
    (void)curl_easy_getinfo(job->easy, CURLINFO_RESPONSE_CODE, &job->response_code);
  }
  ok = result == CURLE_OK && job->response_code >= 200 && job->response_code < 300 &&
       (!job->stream_ctx || !job->stream_ctx->failed) && (job->h2 || !http2_required());
  job->status = ok ? 0 : -1;
  if (ok) {
    s_http2_request_ok++;
    s_http2_multiplex_ok++;
  } else {
    s_http2_request_fail++;
    s_http2_multiplex_fail++;
    fprintf(stderr,
            "[transport] HTTP/2 request failed result=%d(%s) http_status=%ld h2=%d "
            "http2_required=%d stream=%d\n",
            (int)result, curl_easy_strerror(result), job->response_code, job->h2,
            http2_required(), job->stream_ctx ? 1 : 0);
  }
  curl_multi_lock();
  if (s_curl_multi_active_count > 0u) {
    s_curl_multi_active_count--;
  }
  s_http2_multiplex_active = s_curl_multi_active_count > 0u ? 1 : 0;
  job->done = 1;
  curl_multi_signal();
  curl_multi_unlock();
}

#ifdef _WIN32
static DWORD WINAPI curl_multi_worker_main(LPVOID arg)
#else
static void *curl_multi_worker_main(void *arg)
#endif
{
  int running = 0;
  (void)arg;
  for (;;) {
    EdrCurlMultiJob *pending;
    curl_multi_lock();
    while (!s_curl_multi_pending_head && s_curl_multi_active_count == 0u) {
      s_http2_multiplex_active = 0;
      curl_multi_wait_cv();
    }
    pending = s_curl_multi_pending_head;
    s_curl_multi_pending_head = NULL;
    s_curl_multi_pending_tail = NULL;
    curl_multi_unlock();

    while (pending) {
      EdrCurlMultiJob *next = pending->next;
      pending->next = NULL;
      if (curl_multi_add_handle(s_curl_multi, pending->easy) == CURLM_OK) {
        curl_multi_lock();
        s_curl_multi_active_count++;
        s_http2_multiplex_active = 1;
        curl_multi_unlock();
      } else {
        curl_multi_complete_job(NULL, pending, CURLE_FAILED_INIT);
      }
      pending = next;
    }

    (void)curl_multi_perform(s_curl_multi, &running);

    for (;;) {
      int msgs_left = 0;
      CURLMsg *msg = curl_multi_info_read(s_curl_multi, &msgs_left);
      if (!msg) {
        break;
      }
      if (msg->msg == CURLMSG_DONE) {
        EdrCurlMultiJob *job = NULL;
        (void)curl_easy_getinfo(msg->easy_handle, CURLINFO_PRIVATE, &job);
        curl_multi_complete_job(s_curl_multi, job, msg->data.result);
      }
    }

    if (s_curl_multi_active_count > 0u || s_curl_multi_pending_head) {
      int numfds = 0;
      (void)curl_multi_wait(s_curl_multi, NULL, 0u, 250, &numfds);
    }
  }
#ifdef _WIN32
  return 0;
#else
  return NULL;
#endif
}

static int curl_multi_worker_start(void) {
  if (!curl_h2_multiplex_enabled() || !curl_global_ready()) {
    return 0;
  }
  curl_multi_sync_init();
  curl_multi_lock();
  if (s_curl_multi_started) {
    curl_multi_unlock();
    return 1;
  }
  s_curl_multi = curl_multi_init();
  if (!s_curl_multi) {
    curl_multi_unlock();
    return 0;
  }
#ifdef CURLMOPT_PIPELINING
#ifdef CURLPIPE_MULTIPLEX
  curl_multi_setopt(s_curl_multi, CURLMOPT_PIPELINING, (long)CURLPIPE_MULTIPLEX);
#endif
#endif
#ifdef CURLMOPT_MAX_HOST_CONNECTIONS
  curl_multi_setopt(s_curl_multi, CURLMOPT_MAX_HOST_CONNECTIONS, 1L);
#endif
#ifdef CURLMOPT_MAX_TOTAL_CONNECTIONS
  curl_multi_setopt(s_curl_multi, CURLMOPT_MAX_TOTAL_CONNECTIONS, 1L);
#endif
#ifdef _WIN32
  s_curl_multi_thread = CreateThread(NULL, 0, curl_multi_worker_main, NULL, 0, NULL);
  if (!s_curl_multi_thread) {
    curl_multi_cleanup(s_curl_multi);
    s_curl_multi = NULL;
    curl_multi_unlock();
    return 0;
  }
  CloseHandle(s_curl_multi_thread);
#else
  if (pthread_create(&s_curl_multi_thread, NULL, curl_multi_worker_main, NULL) != 0) {
    curl_multi_cleanup(s_curl_multi);
    s_curl_multi = NULL;
    curl_multi_unlock();
    return 0;
  }
  pthread_detach(s_curl_multi_thread);
#endif
  s_curl_multi_started = 1;
  curl_multi_unlock();
  return 1;
}

static int curl_h2_multi_perform(CURL *curl, EdrCurlStreamCtx *stream_ctx) {
  EdrCurlMultiJob job;
  if (!curl || !curl_h2_multiplex_enabled() || !curl_multi_worker_start()) {
    return -2;
  }
  memset(&job, 0, sizeof(job));
  job.easy = curl;
  job.stream_ctx = stream_ctx;
  curl_easy_setopt(curl, CURLOPT_PRIVATE, &job);
  curl_multi_lock();
  if (s_curl_multi_pending_tail) {
    s_curl_multi_pending_tail->next = &job;
  } else {
    s_curl_multi_pending_head = &job;
  }
  s_curl_multi_pending_tail = &job;
  curl_multi_signal();
  while (!job.done) {
    curl_multi_wait_cv();
  }
  curl_multi_unlock();
  return job.status;
}

static size_t curl_write_buffer_cb(char *ptr, size_t size, size_t nmemb, void *userdata) {
  size_t n = size * nmemb;
  EdrCurlBuffer *b = (EdrCurlBuffer *)userdata;
  if (!b || !b->buf || b->cap == 0u || !ptr || n == 0u) {
    return n;
  }
  if (b->len < b->cap - 1u) {
    size_t copy = n;
    if (copy > b->cap - 1u - b->len) {
      copy = b->cap - 1u - b->len;
    }
    memcpy(b->buf + b->len, ptr, copy);
    b->len += copy;
    b->buf[b->len] = '\0';
  }
  return n;
}

static size_t curl_stream_write_cb(char *ptr, size_t size, size_t nmemb, void *userdata) {
  size_t n = size * nmemb;
  EdrCurlStreamCtx *ctx = (EdrCurlStreamCtx *)userdata;
  if (!ctx || !ptr || n == 0u) {
    return n;
  }
  if (stream_consume_bytes(ctx->line, sizeof(ctx->line), &ctx->line_len, ptr, n) != 0) {
    ctx->failed = 1;
    return 0;
  }
  return n;
}

static struct curl_slist *curl_common_headers(const char *content_type) {
  char h[1024];
  struct curl_slist *headers = NULL;
  snprintf(h, sizeof(h), "X-Tenant-ID: %s", s_tenant[0] ? s_tenant : "demo-tenant");
  headers = curl_slist_append(headers, h);
  snprintf(h, sizeof(h), "X-Endpoint-ID: %s", s_endpoint[0] ? s_endpoint : "");
  headers = curl_slist_append(headers, h);
  snprintf(h, sizeof(h), "X-User-ID: %s", s_user[0] ? s_user : "edr-agent");
  headers = curl_slist_append(headers, h);
  headers = curl_slist_append(headers, "X-Permission-Set: telemetry:write,endpoint:attack_surface_report");
  if (content_type && content_type[0]) {
    snprintf(h, sizeof(h), "Content-Type: %s", content_type);
    headers = curl_slist_append(headers, h);
  }
  if (s_bearer[0]) {
    snprintf(h, sizeof(h), "Authorization: Bearer %s", s_bearer);
    headers = curl_slist_append(headers, h);
  }
  return headers;
}

static void curl_apply_common_options(CURL *curl, const char *url, struct curl_slist *headers, long timeout_s) {
  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
#ifdef CURL_HTTP_VERSION_2TLS
  curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, (long)CURL_HTTP_VERSION_2TLS);
#else
  curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, (long)CURL_HTTP_VERSION_2_0);
#endif
#ifdef CURLOPT_SSL_ENABLE_ALPN
  curl_easy_setopt(curl, CURLOPT_SSL_ENABLE_ALPN, 1L);
#endif
#ifdef CURLOPT_PIPEWAIT
  curl_easy_setopt(curl, CURLOPT_PIPEWAIT, 1L);
#endif
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
  curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);
  curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
  if (timeout_s > 0) {
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout_s);
  }
  if (s_ca_file[0]) {
    curl_easy_setopt(curl, CURLOPT_CAINFO, s_ca_file);
  }
  if (curl_ssl_backend_is_schannel()) {
    char selector[512];
    if (build_schannel_cert_selector(selector, sizeof(selector))) {
      curl_easy_setopt(curl, CURLOPT_SSLCERT, selector);
    } else if (s_client_cert_file[0] && s_client_key_file[0] && !s_schannel_pem_warned) {
      s_schannel_pem_warned = 1;
      snprintf(s_mtls_status, sizeof(s_mtls_status), "%s", "schannel_needs_store_cert");
      fprintf(stderr,
              "[transport] Schannel libcurl cannot use PEM client_cert/client_key reliably; "
              "import client cert with private key into Windows cert store and set "
              "client_cert_thumbprint/client_cert_store, or use OpenSSL libcurl\n");
    }
  } else if (s_client_cert_file[0] && s_client_key_file[0]) {
    curl_easy_setopt(curl, CURLOPT_SSLCERT, s_client_cert_file);
    curl_easy_setopt(curl, CURLOPT_SSLKEY, s_client_key_file);
  }
  if (ascii_eq_ci(s_proxy_mode, "off") || ascii_eq_ci(s_proxy_mode, "none") ||
      ascii_eq_ci(s_proxy_mode, "direct")) {
    curl_easy_setopt(curl, CURLOPT_NOPROXY, "*");
  } else if (s_proxy_url_cfg[0]) {
    curl_easy_setopt(curl, CURLOPT_PROXY, s_proxy_url_cfg);
  }
}

static int curl_note_http_version(CURL *curl) {
#ifdef CURLINFO_HTTP_VERSION
  long version = 0;
  if (curl_easy_getinfo(curl, CURLINFO_HTTP_VERSION, &version) == CURLE_OK) {
#ifdef CURL_HTTP_VERSION_2_0
    if (version == CURL_HTTP_VERSION_2_0) {
      s_http2_negotiated = 1;
      s_http2_negotiated_count++;
      snprintf(s_negotiated_protocol, sizeof(s_negotiated_protocol), "%s", "h2");
      if (s_alpn_log_state != 1) {
        s_alpn_log_state = 1;
        fprintf(stderr, "[transport] ALPN negotiated h2 control_stream_status=%s endpoint=%s\n",
                s_control_stream_status[0] ? s_control_stream_status : "idle",
                s_endpoint[0] ? s_endpoint : "-");
      }
      return 1;
    }
#endif
  }
#else
  (void)curl;
#endif
  s_http2_fallback_count++;
  if (!s_negotiated_protocol[0]) {
    snprintf(s_negotiated_protocol, sizeof(s_negotiated_protocol), "%s", "http/1.1");
  }
  if (s_alpn_log_state != 2) {
    s_alpn_log_state = 2;
    fprintf(stderr,
            "[transport] ALPN did not negotiate h2; negotiated_protocol=%s "
            "http2_required=%d control_stream_status=%s fallback_count=%lu\n",
            s_negotiated_protocol[0] ? s_negotiated_protocol : "http/1.1",
            http2_required(),
            s_control_stream_status[0] ? s_control_stream_status : "idle",
            s_http2_fallback_count);
  }
  return 0;
}

static int curl_h2_allowed_for_url(const char *url) {
  if (!http2_client_enabled() || !url || strncmp(url, "https://", 8u) != 0) {
    return 0;
  }
  return 1;
}

static int curl_h2_request(const char *method, const char *url, const char *content_type,
                           const char *body, size_t body_len, char *resp_body,
                           size_t resp_body_cap) {
  CURL *curl = NULL;
  struct curl_slist *headers = NULL;
  EdrCurlBuffer rb;
  long code = 0;
  CURLcode cc;
  int h2;
  char errbuf[CURL_ERROR_SIZE];
  if (!curl_h2_allowed_for_url(url) || !curl_global_ready()) {
    return -2;
  }
  if (!comm_circuit_allows() || !comm_budget_try(body_len + 512u, 0)) {
    return -1;
  }
  curl = curl_easy_init();
  if (!curl) {
    return -2;
  }
  if (resp_body && resp_body_cap > 0u) {
    resp_body[0] = '\0';
  }
  errbuf[0] = '\0';
  memset(&rb, 0, sizeof(rb));
  rb.buf = resp_body;
  rb.cap = resp_body_cap;
  headers = curl_common_headers(content_type);
  curl_apply_common_options(curl, url, headers,
                            (long)env_ul_clamped("EDR_HTTP_SOCKET_TIMEOUT_MS", 10000ul, 1000ul, 120000ul) / 1000L);
  curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_buffer_cb);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &rb);
  if (strcmp(method, "GET") == 0) {
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
  } else if (strcmp(method, "POST") == 0) {
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body ? body : "");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)body_len);
  } else {
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method);
    if (body_len > 0u) {
      curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body ? body : "");
      curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)body_len);
    }
  }
  {
    int mrc = curl_h2_multi_perform(curl, NULL);
    if (mrc != -2) {
      curl_slist_free_all(headers);
      curl_easy_cleanup(curl);
      return mrc;
    }
  }
  cc = curl_easy_perform(curl);
  h2 = curl_note_http_version(curl);
  (void)curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
  curl_slist_free_all(headers);
  curl_easy_cleanup(curl);
  if (cc == CURLE_OK && code >= 200 && code < 300 &&
      (h2 || !http2_required())) {
    s_http2_request_ok++;
    return 0;
  }
  s_http2_request_fail++;
  fprintf(stderr,
          "[transport] HTTP/2 request failed method=%s result=%d(%s) http_status=%ld h2=%d "
          "http2_required=%d err=%s\n",
          method ? method : "-", (int)cc, curl_easy_strerror(cc), code, h2,
          http2_required(), errbuf[0] ? errbuf : "-");
  return -1;
}

static int curl_h2_stream_loop(const char *url) {
  CURL *curl = NULL;
  struct curl_slist *headers = NULL;
  EdrCurlStreamCtx ctx;
  long code = 0;
  CURLcode cc;
  int h2;
  char errbuf[CURL_ERROR_SIZE];
  if (!curl_h2_allowed_for_url(url) || !curl_global_ready()) {
    return -2;
  }
  if (!comm_circuit_allows() || !comm_budget_try(2048u, 0)) {
    return -1;
  }
  memset(&ctx, 0, sizeof(ctx));
  curl = curl_easy_init();
  if (!curl) {
    return -2;
  }
  errbuf[0] = '\0';
  headers = curl_common_headers(NULL);
  headers = curl_slist_append(headers, "Accept: application/x-ndjson");
  headers = curl_slist_append(headers, "Cache-Control: no-cache");
  curl_apply_common_options(curl, url, headers, 0L);
  curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_stream_write_cb);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &ctx);
  curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT, 1L);
  curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME, (long)env_ul_clamped("EDR_HTTP2_STREAM_LOW_SPEED_S", 120ul, 30ul, 3600ul));
  {
    int mrc = curl_h2_multi_perform(curl, &ctx);
    if (mrc != -2) {
      curl_slist_free_all(headers);
      curl_easy_cleanup(curl);
      return mrc;
    }
  }
  cc = curl_easy_perform(curl);
  h2 = curl_note_http_version(curl);
  (void)curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
  curl_slist_free_all(headers);
  curl_easy_cleanup(curl);
  if (cc == CURLE_OK && code >= 200 && code < 300 && !ctx.failed &&
      (h2 || !http2_required())) {
    s_http2_request_ok++;
    return 0;
  }
  s_http2_request_fail++;
  fprintf(stderr,
          "[ingest-stream] HTTP/2 control stream failed result=%d(%s) http_status=%ld "
          "h2=%d http2_required=%d parser_failed=%d err=%s\n",
          (int)cc, curl_easy_strerror(cc), code, h2, http2_required(), ctx.failed,
          errbuf[0] ? errbuf : "-");
  return -1;
}
#endif

static int native_post_json_legacy(const char *url, const char *body, size_t body_len) {
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
  if (!comm_circuit_allows()) {
    return -1;
  }
  if (!comm_budget_try(body_len + 512u, https)) {
    return -1;
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
  int rc = -1;
  char req[8192];
  int rn;
  if (parse_url(url, host, sizeof(host), path, sizeof(path), &port, &https) != 0) {
    runtime_failure("invalid ingest url");
    return -1;
  }
  if (https && http2_client_enabled()) {
#ifdef EDR_HAVE_CURL_HTTP2
    int h2rc = curl_h2_request(method, url, content_type, body, body_len, resp_body, resp_body_cap);
    if (h2rc == 0) {
      return 0;
    }
    if (h2rc != -2) {
      s_http2_fallback_count++;
    }
#endif
  }
  if (!https) {
    const char *allow = getenv("EDR_ALLOW_INSECURE_HTTP");
    if ((!allow || allow[0] != '1') && !is_local_or_private_host(host)) {
      runtime_failure("plain http denied for non-local host");
      return -1;
    }
  }
  if (!comm_circuit_allows()) {
    return -1;
  }
  if (!comm_budget_try(body_len + 512u, 0)) {
    return -1;
  }
  if (net_init() != 0) {
    runtime_failure("network init failed");
    return -1;
  }
  rn = append_request_headers(req, sizeof(req), method, path, host, content_type, body_len);
  if (rn <= 0) {
    runtime_failure("http request build failed");
    return -1;
  }
  http_lock();
  for (int attempt = 0; attempt < 2; attempt++) {
    int reusable = 0;
    EdrHttpConn *conn = http_conn_get_locked(host, port, https);
    if (!conn) {
      break;
    }
    if (http_conn_write_all(conn, req, (size_t)rn) == 0 &&
        (body_len == 0u || (body && http_conn_write_all(conn, body, body_len) == 0)) &&
        read_http_response_from_recv(http_socket_recv_adapter, conn, resp_body, resp_body_cap, &reusable) == 0) {
      rc = 0;
      conn->last_used_ms = unix_ms_now();
      if (!reusable || !http_keepalive_enabled()) {
        http_conn_close_locked();
      }
      break;
    }
    http_conn_close_locked();
  }
  http_unlock();
  if (rc != 0 && !s_last_error[0]) {
    runtime_failure(https ? "https request failed" : "http request failed");
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

static int native_get_to_file(const char *url, FILE *out, size_t max_bytes) {
  char host[256];
  char path[1024];
  int port = 0;
  int https = 0;
  int rc = -1;
  char req[8192];
  int rn;
  if (!out || parse_url(url, host, sizeof(host), path, sizeof(path), &port, &https) != 0) {
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
  if (!comm_circuit_allows()) {
    return -1;
  }
  if (!comm_budget_try(512u, 0)) {
    return -1;
  }
  if (net_init() != 0) {
    runtime_failure("network init failed");
    return -1;
  }
  rn = append_request_headers(req, sizeof(req), "GET", path, host, NULL, 0u);
  if (rn <= 0) {
    runtime_failure("http request build failed");
    net_done();
    return -1;
  }
  http_lock();
  for (int attempt = 0; attempt < 2; attempt++) {
    int reusable = 0;
    EdrHttpConn *conn = http_conn_get_locked(host, port, https);
    if (!conn) {
      break;
    }
    if (http_conn_write_all(conn, req, (size_t)rn) == 0 &&
        read_http_response_to_file_from_recv(http_socket_recv_adapter, conn, out, max_bytes, &reusable) == 0) {
      rc = 0;
      conn->last_used_ms = unix_ms_now();
      if (!reusable || !http_keepalive_enabled()) {
        http_conn_close_locked();
      }
      break;
    }
    http_conn_close_locked();
    if (fseek(out, 0L, SEEK_SET) == 0) {
#if defined(_WIN32)
      (void)_chsize(_fileno(out), 0);
#else
      (void)ftruncate(fileno(out), 0);
#endif
    }
  }
  http_unlock();
  net_done();
  if (rc != 0 && !s_last_error[0]) {
    runtime_failure(https ? "https get failed" : "http get failed");
  }
  return rc;
}

int edr_ingest_http_get_url_to_file(const char *url, const char *file_path, size_t max_bytes) {
  FILE *f;
  size_t cap;
  int rc;
  if (!url || !url[0] || !file_path || !file_path[0] || !edr_ingest_http_configured()) {
    return -1;
  }
  cap = max_bytes;
  if (cap < 4096u) {
    cap = 4096u;
  }
  if (cap > 4u * 1024u * 1024u) {
    cap = 4u * 1024u * 1024u;
  }
  f = fopen(file_path, "wb");
  if (!f) {
    runtime_failure("http get output open failed");
    return -1;
  }
  rc = native_get_to_file(url, f, cap);
  fclose(f);
  if (rc != 0) {
    (void)remove(file_path);
    note_http_request_failure();
    return -1;
  }
  note_http_request_success();
  return 0;
}

static void sleep_poll_ms(int ms);
static int poll_dispatch_one(const char *obj);

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
#ifdef _WIN32
      if (e == SSL_ERROR_SYSCALL) {
        int se = WSAGetLastError();
        if (se == WSAETIMEDOUT || se == WSAEWOULDBLOCK) {
          return -2;
        }
        if (n < 0 && se == 0 && ERR_peek_error() == 0) {
          return -2;
        }
      }
#else
      if (e == SSL_ERROR_SYSCALL && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        return -2;
      }
      if (e == SSL_ERROR_SYSCALL && n < 0 && errno == 0 && ERR_peek_error() == 0) {
        return -2;
      }
#endif
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
      sleep_poll_ms(10);
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
          sleep_poll_ms(10);
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
          sleep_poll_ms(10);
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
  snprintf(url, sizeof(url),
           "%s%singest/control/ws?endpoint_id=%s&agent_version=%s&dict_ver=%s&schema_ver=%s&profile_id=%s&h2=%d&zstd=%d",
           s_rest, (rb > 0u && s_rest[rb - 1u] == '/') ? "" : "/", s_endpoint,
           s_agent_ver, s_control_dict_ver, s_control_schema_ver, s_control_profile_id,
           s_control_h2 ? 1 : 0, s_control_zstd ? 1 : 0);
  if (parse_url(url, host, sizeof(host), path, sizeof(path), &port, &https) != 0) {
    return -1;
  }
  if (!comm_circuit_allows()) {
    return -1;
  }
  if (!comm_budget_try(2048u, https)) {
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

static void build_control_stream_url(char *url, size_t cap) {
  size_t rb = strlen(s_rest);
  if (!url || cap == 0u) {
    return;
  }
  snprintf(url, cap,
           "%s%singest/control/stream?endpoint_id=%s&agent_version=%s&policy_version=%s&dict_ver=%s&schema_ver=%s&profile_id=%s&h2=%d&zstd=%d",
           s_rest, (rb > 0u && s_rest[rb - 1u] == '/') ? "" : "/", s_endpoint,
           s_agent_ver, s_policy_version[0] ? s_policy_version : "local",
           s_control_dict_ver, s_control_schema_ver, s_control_profile_id,
           s_control_h2 ? 1 : 0, s_control_zstd ? 1 : 0);
}

static int stream_connect_once(EdrWsConn *out) {
  char url[1400];
  char host[256];
  char path[1024];
  char req[4096];
  int port = 0;
  int https = 0;
  int rn;
  if (!out || !edr_ingest_http_configured()) {
    return -1;
  }
  memset(out, 0, sizeof(*out));
  out->fd = EDR_SOCKET_INVALID;
  build_control_stream_url(url, sizeof(url));
  if (parse_url(url, host, sizeof(host), path, sizeof(path), &port, &https) != 0) {
    return -1;
  }
  if (!comm_circuit_allows() || !comm_budget_try(2048u, https) || net_init() != 0) {
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
      runtime_failure_openssl("control stream tls connect failed");
      ws_close_conn(out);
      net_done();
      return -1;
    }
#else
    runtime_failure("control stream https requested but OpenSSL disabled");
    ws_close_conn(out);
    net_done();
    return -1;
#endif
  }
  rn = snprintf(req, sizeof(req),
                "GET %s HTTP/1.1\r\n"
                "Host: %s\r\n"
                "Accept: application/x-ndjson\r\n"
                "Cache-Control: no-cache\r\n",
                path, host);
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
    int m = snprintf(req + used, sizeof(req) - used, "Connection: keep-alive\r\n\r\n");
    if (m <= 0 || (size_t)m >= sizeof(req) - used ||
        ws_write_all(out, (const uint8_t *)req, used + (size_t)m) != 0) {
      ws_close_conn(out);
      net_done();
      return -1;
    }
  }
  return 0;
}

static void stream_process_line(const char *line) {
  if (!line || !line[0]) {
    return;
  }
  if (!strchr(line, '{')) {
    return;
  }
  if (strstr(line, "\"type\":\"command_envelope\"") || strstr(line, "\"command_id\"")) {
    edr_transport_v2_on_control("command_envelope");
    (void)poll_dispatch_one(line);
  } else if (strstr(line, "\"type\":\"server_hello\"")) {
    int64_t batch_events = 0;
    int64_t flush_s = 0;
    int64_t sampling_pct = 0;
    (void)json_get_string(line, "dict_ver", s_control_dict_ver, sizeof(s_control_dict_ver));
    (void)json_get_string(line, "schema_ver", s_control_schema_ver, sizeof(s_control_schema_ver));
    (void)json_get_string(line, "profile_id", s_control_profile_id, sizeof(s_control_profile_id));
    (void)json_get_string(line, "qos_dscp", s_control_qos_dscp, sizeof(s_control_qos_dscp));
    (void)json_get_string(line, "threshold", s_control_threshold, sizeof(s_control_threshold));
    (void)json_get_bool(line, "h2", &s_control_h2);
    (void)json_get_bool(line, "zstd", &s_control_zstd);
    if (json_get_int64(line, "batch_events", &batch_events) == 0 ||
        json_get_int64(line, "flush_interval_s", &flush_s) == 0) {
      if (batch_events < 0) batch_events = 0;
      if (batch_events > 50000) batch_events = 50000;
      if (flush_s < 0) flush_s = 0;
      if (flush_s > 300) flush_s = 300;
      edr_event_batch_apply_profile((uint32_t)batch_events, (int)flush_s);
    }
    if (json_get_int64(line, "sampling_pct", &sampling_pct) == 0 && sampling_pct > 0) {
      if (sampling_pct > 100) sampling_pct = 100;
      s_control_sampling_pct = (unsigned)sampling_pct;
    }
    s_control_hello_ok = 1;
    edr_transport_v2_apply_profile(s_control_dict_ver, s_control_schema_ver, s_control_profile_id,
                                   s_control_h2, s_control_zstd, s_control_qos_dscp,
                                   s_control_sampling_pct, s_control_threshold,
                                   s_control_backpressure_enabled);
    edr_transport_v2_on_control("server_hello");
  } else if (strstr(line, "\"type\":\"heartbeat\"")) {
    note_control_stream_heartbeat();
    edr_transport_v2_on_control("heartbeat");
  }
}

static int stream_consume_bytes(char *line, size_t line_cap, size_t *line_len,
                                const char *buf, size_t len) {
  size_t i;
  if (!line || !line_len || !buf || line_cap == 0u) {
    return -1;
  }
  for (i = 0; i < len; i++) {
    char c = buf[i];
    if (c == '\r') {
      continue;
    }
    if (c == '\n') {
      line[*line_len] = '\0';
      stream_process_line(line);
      *line_len = 0;
      continue;
    }
    if (*line_len + 1u < line_cap) {
      line[(*line_len)++] = c;
    } else {
      *line_len = 0;
      runtime_failure("control stream line too large");
      return -1;
    }
  }
  return 0;
}

static int stream_read_loop(EdrWsConn *conn) {
  char buf[8192];
  size_t used = 0;
  char line[262144];
  size_t line_len = 0;
  int status_ok = 0;
  if (!conn) {
    return -1;
  }
  for (;;) {
    int n;
    if (used >= sizeof(buf) - 1u) {
      return -1;
    }
    n = ws_recv_some(conn, buf + used, (int)(sizeof(buf) - 1u - used));
    if (n == -2) {
      if (!s_poll_run) {
        return -1;
      }
      continue;
    }
    if (n <= 0) {
      return -1;
    }
    used += (size_t)n;
    buf[used] = '\0';
    {
      char *hdr = strstr(buf, "\r\n\r\n");
      if (!hdr) {
        continue;
      }
      status_ok = (strncmp(buf, "HTTP/1.1 2", 10u) == 0 || strncmp(buf, "HTTP/1.0 2", 10u) == 0);
      if (!status_ok) {
        return -1;
      }
      if (used > (size_t)(hdr + 4 - buf)) {
        if (stream_consume_bytes(line, sizeof(line), &line_len, hdr + 4,
                                 used - (size_t)(hdr + 4 - buf)) != 0) {
          return -1;
        }
      }
      break;
    }
  }
  while (s_poll_run) {
    int n = ws_recv_some(conn, buf, (int)(sizeof(buf) - 1u));
    if (n == -2) {
      continue;
    }
    if (n <= 0) {
      return -1;
    }
    if (stream_consume_bytes(line, sizeof(line), &line_len, buf, (size_t)n) != 0) {
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
    note_http_request_success();
  } else if (!s_last_error[0]) {
    note_http_request_failure();
    runtime_failure("native post failed");
  } else {
    note_http_request_failure();
  }
  return rc;
}

int edr_ingest_http_post_report_events(const char *batch_id, const uint8_t *header12, size_t header_len,
                                       const uint8_t *payload, size_t payload_len) {
  if (!edr_ingest_http_configured() || !batch_id || !header12 || header_len < 12u || !payload ||
      payload_len == 0u) {
    return -1;
  }
  if (report_events_v2_should_use()) {
    uint8_t *env = NULL;
    size_t env_len = 0u;
    int v2rc;
    if (build_report_events_v2_envelope(batch_id, header12, header_len, payload, payload_len,
                                        &env, &env_len) == 0) {
      v2rc = request_to_suffix("POST", "ingest/report-events", "application/x-protobuf",
                               (const char *)env, env_len, NULL, 0u);
      free(env);
      if (v2rc == 0) {
        s_report_events_v2_ok++;
        note_http_request_success();
        return 0;
      }
      s_report_events_v2_fail++;
      note_http_request_failure();
      if (!env_bool_default("EDR_REPORT_EVENTS_V2_FALLBACK_JSON", 1)) {
        log_native_post_failure("report-events-v2", v2rc);
        return -1;
      }
    } else {
      s_report_events_v2_fail++;
      if (!env_bool_default("EDR_REPORT_EVENTS_V2_FALLBACK_JSON", 1)) {
        runtime_failure("report-events-v2 envelope build failed");
        return -1;
      }
    }
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
    log_native_post_failure("report-events", rc);
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
    log_native_post_failure("engine_health", rc);
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
  int ws_was_ready;
  if (!edr_ingest_http_configured() || !command_id || !command_id[0]) {
    return -1;
  }
  ws_was_ready = s_ws_ready ? 1 : 0;
  if (ws_send_command_result(command_id, meta, execution_status, exit_code, detail_utf8) == 0) {
    note_ws_message_success();
    note_command_result_success();
    return 0;
  }
  if (ws_was_ready) {
    s_ws_message_fail++;
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
    note_http_request_success();
    note_command_result_success();
  } else if (!s_last_error[0]) {
    note_http_request_failure();
    note_command_result_failure();
    runtime_failure("command result http post failed");
  } else {
    note_http_request_failure();
    note_command_result_failure();
  }
  free(cmd);
  free(detail);
  free(soar);
  free(run);
  free(step);
  free(body);
  return rc;
}

static int edr_ingest_http_post_control_ack(const char *command_id, const char *transport, int64_t last_seq) {
  char *cmd = NULL;
  char *tr = NULL;
  char *body = NULL;
  size_t body_cap;
  int rc;
  if (!edr_ingest_http_configured() || !command_id || !command_id[0]) {
    return -1;
  }
  cmd = json_escape_alloc(command_id);
  tr = json_escape_alloc((transport && transport[0]) ? transport : "https_control");
  if (!cmd || !tr) {
    free(cmd);
    free(tr);
    return -1;
  }
  body_cap = strlen(s_endpoint) + strlen(cmd) + strlen(tr) + 256u;
  body = (char *)malloc(body_cap);
  if (!body) {
    free(cmd);
    free(tr);
    return -1;
  }
  snprintf(body, body_cap,
           "{\"endpoint_id\":\"%s\",\"command_id\":\"%s\",\"status\":\"processed\","
           "\"transport\":\"%s\",\"last_seq\":%lld}",
           s_endpoint, cmd, tr, (long long)last_seq);
  rc = request_to_suffix("POST", "ingest/control/ack", "application/json", body, strlen(body), NULL, 0u);
  if (rc == 0) {
    note_http_request_success();
    note_control_ack_success();
    edr_transport_v2_ack(command_id, 1);
  } else {
    note_http_request_failure();
    note_control_ack_failure();
    edr_transport_v2_ack(command_id, 0);
    if (!s_last_error[0]) {
      runtime_failure("control ack http post failed");
    }
  }
  free(cmd);
  free(tr);
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

static long upload_max_mb(void) {
  const char *max_mb_env = getenv("EDR_HTTP_UPLOAD_MAX_MB");
  long max_mb = max_mb_env && max_mb_env[0] ? strtol(max_mb_env, NULL, 10) : 256L;
  if (max_mb < 1) max_mb = 1;
  if (max_mb > 65536) max_mb = 65536;
  return max_mb;
}

#ifdef EDR_HAVE_CURL_HTTP2
static int curl_h2_upload_multipart_file(const char *upload_id, const char *file_path,
                                         const char *sha256_hex, char *resp_body,
                                         size_t resp_body_cap) {
  char url[1400];
  size_t rb;
  CURL *curl = NULL;
  curl_mime *mime = NULL;
  curl_mimepart *part = NULL;
  struct curl_slist *headers = NULL;
  EdrCurlBuffer out;
  long code = 0;
  CURLcode cc;
  int h2;
  const char *filename;
  if (!edr_ingest_http_configured() || !upload_id || !upload_id[0] || !file_path || !file_path[0] ||
      !http2_client_enabled() || strncmp(s_rest, "https://", 8u) != 0 || !curl_global_ready()) {
    return -2;
  }
  if (!comm_circuit_allows() || !comm_budget_try(4096u, 0)) {
    return -1;
  }
  curl = curl_easy_init();
  if (!curl) {
    return -2;
  }
  if (resp_body && resp_body_cap > 0u) {
    resp_body[0] = '\0';
  }
  memset(&out, 0, sizeof(out));
  out.buf = resp_body;
  out.cap = resp_body_cap;
  rb = strlen(s_rest);
  snprintf(url, sizeof(url), "%s%singest/upload-file",
           s_rest, (rb > 0u && s_rest[rb - 1u] == '/') ? "" : "/");
  filename = base_name_ptr(file_path);
  mime = curl_mime_init(curl);
  if (!mime) {
    curl_easy_cleanup(curl);
    return -2;
  }
  part = curl_mime_addpart(mime);
  curl_mime_name(part, "upload_id");
  curl_mime_data(part, upload_id, CURL_ZERO_TERMINATED);
  part = curl_mime_addpart(mime);
  curl_mime_name(part, "sha256");
  curl_mime_data(part, sha256_hex ? sha256_hex : "", CURL_ZERO_TERMINATED);
  part = curl_mime_addpart(mime);
  curl_mime_name(part, "file_name");
  curl_mime_data(part, filename, CURL_ZERO_TERMINATED);
  part = curl_mime_addpart(mime);
  curl_mime_name(part, "file");
  curl_mime_filename(part, filename);
  curl_mime_type(part, "application/octet-stream");
  if (curl_mime_filedata(part, file_path) != CURLE_OK) {
    curl_mime_free(mime);
    curl_easy_cleanup(curl);
    return -2;
  }
  headers = curl_common_headers(NULL);
  curl_apply_common_options(curl, url, headers,
                            (long)env_ul_clamped("EDR_HTTP_UPLOAD_TIMEOUT_S", 600ul, 30ul, 86400ul));
  curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_buffer_cb);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &out);
  {
    int mrc = curl_h2_multi_perform(curl, NULL);
    if (mrc != -2) {
      curl_slist_free_all(headers);
      curl_mime_free(mime);
      curl_easy_cleanup(curl);
      return mrc;
    }
  }
  cc = curl_easy_perform(curl);
  h2 = curl_note_http_version(curl);
  (void)curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
  curl_slist_free_all(headers);
  curl_mime_free(mime);
  curl_easy_cleanup(curl);
  if (cc == CURLE_OK && code >= 200 && code < 300 &&
      (h2 || !http2_required())) {
    s_http2_request_ok++;
    return 0;
  }
  s_http2_request_fail++;
  return -1;
}
#endif

static int http_conn_write_file(EdrHttpConn *conn, FILE *f, size_t file_len) {
  char chunk[65536];
  size_t remaining = file_len;
  if (!conn || !f) {
    return -1;
  }
  while (remaining > 0u) {
    size_t want = remaining > sizeof(chunk) ? sizeof(chunk) : remaining;
    size_t got = fread(chunk, 1u, want, f);
    if (got == 0u) {
      return -1;
    }
    if (http_conn_write_all(conn, chunk, got) != 0) {
      return -1;
    }
    remaining -= got;
  }
  return 0;
}

static int request_to_suffix_multipart_file(const char *suffix, const char *content_type,
                                            const char *pre, size_t pre_len,
                                            FILE *file, size_t file_len,
                                            const char *post, size_t post_len,
                                            char *resp_body, size_t resp_body_cap) {
  char url[1400];
  char host[256];
  char path[1024];
  int port = 0;
  int https = 0;
  int rc = -1;
  char req[8192];
  int rn;
  size_t rb = strlen(s_rest);
  size_t body_len = pre_len + file_len + post_len;
  snprintf(url, sizeof(url), "%s%s%s", s_rest, (rb > 0u && s_rest[rb - 1u] == '/') ? "" : "/", suffix);
  if (parse_url(url, host, sizeof(host), path, sizeof(path), &port, &https) != 0) {
    runtime_failure("invalid upload url");
    return -1;
  }
  if (!https) {
    const char *allow = getenv("EDR_ALLOW_INSECURE_HTTP");
    if ((!allow || allow[0] != '1') && !is_local_or_private_host(host)) {
      runtime_failure("plain http denied for non-local host");
      return -1;
    }
  }
  if (!comm_circuit_allows()) {
    return -1;
  }
  if (!comm_budget_try(4096u, 0)) {
    return -1;
  }
  if (net_init() != 0) {
    runtime_failure("network init failed");
    return -1;
  }
  rn = append_request_headers(req, sizeof(req), "POST", path, host, content_type, body_len);
  if (rn <= 0) {
    runtime_failure("http upload request build failed");
    return -1;
  }
  http_lock();
  for (int attempt = 0; attempt < 2; attempt++) {
    int reusable = 0;
    EdrHttpConn *conn;
    if (fseek(file, 0, SEEK_SET) != 0) {
      break;
    }
    conn = http_conn_get_locked(host, port, https);
    if (!conn) {
      break;
    }
    if (http_conn_write_all(conn, req, (size_t)rn) == 0 &&
        http_conn_write_all(conn, pre, pre_len) == 0 &&
        http_conn_write_file(conn, file, file_len) == 0 &&
        http_conn_write_all(conn, post, post_len) == 0 &&
        read_http_response_from_recv(http_socket_recv_adapter, conn, resp_body, resp_body_cap, &reusable) == 0) {
      rc = 0;
      conn->last_used_ms = unix_ms_now();
      if (!reusable || !http_keepalive_enabled()) {
        http_conn_close_locked();
      }
      break;
    }
    http_conn_close_locked();
  }
  http_unlock();
  if (rc != 0 && !s_last_error[0]) {
    runtime_failure(https ? "https upload failed" : "http upload failed");
  }
  return rc;
}

int edr_ingest_http_upload_file_multipart(const char *upload_id, const char *file_path,
                                          const char *sha256_hex, char *out_minio_key,
                                          size_t out_minio_key_cap) {
  const char *boundary = "----edr-agent-upload-boundary-v1";
  const char *filename;
  FILE *file = NULL;
  size_t file_len = 0;
  char *uid = NULL;
  char *sha = NULL;
  char *fname = NULL;
  char content_type[160];
  char resp[4096];
  char pre[2048];
  char post[96];
  int rc;
  long sz;
  long max_mb;
  if (out_minio_key && out_minio_key_cap > 0u) {
    out_minio_key[0] = '\0';
  }
  if (!edr_ingest_http_configured() || !upload_id || !upload_id[0] || !file_path || !file_path[0]) {
    return -1;
  }
  snprintf(s_upload_status, sizeof(s_upload_status), "%s", "opening");
  file = fopen(file_path, "rb");
  if (!file) {
    snprintf(s_upload_status, sizeof(s_upload_status), "%s", "failed_open");
    runtime_failure("http upload file read failed");
    return -1;
  }
  if (fseek(file, 0, SEEK_END) != 0) {
    fclose(file);
    runtime_failure("http upload file seek failed");
    return -1;
  }
  sz = ftell(file);
  max_mb = upload_max_mb();
  if (sz < 0 || (unsigned long)sz > (unsigned long)max_mb * 1024ul * 1024ul) {
    fclose(file);
    snprintf(s_upload_status, sizeof(s_upload_status), "%s", "failed_too_large");
    runtime_failure("http upload file too large");
    return -1;
  }
  file_len = (size_t)sz;
  if (fseek(file, 0, SEEK_SET) != 0) {
    fclose(file);
    snprintf(s_upload_status, sizeof(s_upload_status), "%s", "failed_seek");
    runtime_failure("http upload file seek failed");
    return -1;
  }
#ifdef EDR_HAVE_CURL_HTTP2
  if (http2_client_enabled()) {
    snprintf(s_upload_status, sizeof(s_upload_status), "%s", "uploading_h2");
    resp[0] = '\0';
    rc = curl_h2_upload_multipart_file(upload_id, file_path, sha256_hex ? sha256_hex : "", resp, sizeof(resp));
    if (rc == 0) {
      note_http_request_success();
      note_upload_success();
      snprintf(s_upload_status, sizeof(s_upload_status), "%s", "ok_h2");
      if (out_minio_key && out_minio_key_cap > 0u) {
        (void)json_get_string(resp, "minio_key", out_minio_key, out_minio_key_cap);
      }
      fclose(file);
      return 0;
    }
    if (rc != -2) {
      s_http2_fallback_count++;
      if (fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        runtime_failure("http upload file seek failed");
        return -1;
      }
    }
  }
#endif
  filename = base_name_ptr(file_path);
  uid = json_escape_alloc(upload_id);
  sha = json_escape_alloc(sha256_hex ? sha256_hex : "");
  fname = json_escape_alloc(filename);
  if (!uid || !sha || !fname) {
    fclose(file);
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
  snprintf(content_type, sizeof(content_type), "multipart/form-data; boundary=%s", boundary);
  resp[0] = '\0';
  snprintf(s_upload_status, sizeof(s_upload_status), "%s", "uploading_http");
  rc = request_to_suffix_multipart_file("ingest/upload-file", content_type,
                                        pre, strlen(pre), file, file_len,
                                        post, strlen(post), resp, sizeof(resp));
  if (rc == 0) {
    note_http_request_success();
    note_upload_success();
    snprintf(s_upload_status, sizeof(s_upload_status), "%s", "ok_http");
    if (out_minio_key && out_minio_key_cap > 0u) {
      (void)json_get_string(resp, "minio_key", out_minio_key, out_minio_key_cap);
    }
  } else if (!s_last_error[0]) {
    note_http_request_failure();
    note_upload_failure();
    runtime_failure("http upload failed");
  } else {
    note_http_request_failure();
    note_upload_failure();
    snprintf(s_upload_status, sizeof(s_upload_status), "%s", "failed");
  }
  fclose(file);
  free(uid);
  free(sha);
  free(fname);
  return rc;
}

static int poll_dispatch_one(const char *obj) {
  char command_id[160];
  char command_type[96];
  char transport[96];
  char *payload_b64 = NULL;
  EdrSoarCommandMeta sm;
  uint8_t *payload = NULL;
  size_t payload_len = 0;
  int64_t v;
  int64_t seq = 0;
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
  if (json_get_int64(obj, "seq", &seq) != 0) {
    seq = sm.issued_at_unix_ms;
  }
  if (json_get_string(obj, "transport", transport, sizeof(transport)) != 0 || !transport[0]) {
    snprintf(transport, sizeof(transport), "%s", s_stream_ready ? "https_control_stream" : "https_long_poll");
  }
  if (json_get_int64(obj, "deadline_ms", &v) == 0 && v > 0 && v <= 0xffffffffLL) {
    sm.deadline_ms = (uint32_t)v;
  }
  edr_command_on_envelope(command_id, command_type, payload, payload_len, &sm);
  (void)edr_ingest_http_post_control_ack(command_id, transport, seq);
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

static int edr_ingest_http_control_hello_once(void) {
  char resp[8192];
  char *endpoint = NULL;
  char *agent = NULL;
  char *policy = NULL;
  char *dict = NULL;
  char *schema = NULL;
  char *profile = NULL;
  char *body = NULL;
  size_t body_cap;
  int rc = -1;
  int64_t now = unix_ms_now();
  int retry_ms = (int)env_ul_clamped("EDR_CONTROL_HELLO_RETRY_MS", 30000ul, 5000ul, 300000ul);
  if (!edr_ingest_http_configured()) {
    return -1;
  }
  if (s_control_hello_ok) {
    return 0;
  }
  if (s_control_hello_last_ms > 0 && now - s_control_hello_last_ms < (int64_t)retry_ms) {
    return -1;
  }
  s_control_hello_last_ms = now;
  endpoint = json_escape_alloc(s_endpoint);
  agent = json_escape_alloc(s_agent_ver);
  policy = json_escape_alloc(s_policy_version[0] ? s_policy_version : "local");
  dict = json_escape_alloc(s_control_dict_ver[0] ? s_control_dict_ver : "edr-zstd-dict-v1");
  schema = json_escape_alloc(s_control_schema_ver[0] ? s_control_schema_ver : "edr-control-schema-v1");
  profile = json_escape_alloc(s_control_profile_id[0] ? s_control_profile_id : "default-h2-zstd");
  if (!endpoint || !agent || !policy || !dict || !schema || !profile) {
    goto done;
  }
  body_cap = strlen(endpoint) + strlen(agent) + strlen(policy) + strlen(dict) +
             strlen(schema) + strlen(profile) + 1024u;
  body = (char *)malloc(body_cap);
  if (!body) {
    goto done;
  }
  snprintf(body, body_cap,
           "{\"type\":\"client_hello\",\"endpoint_id\":\"%s\",\"agent_version\":\"%s\","
           "\"policy_version\":\"%s\",\"h2\":%s,\"zstd\":%s,"
           "\"dict_ver\":\"%s\",\"schema_ver\":\"%s\",\"profile_id\":\"%s\","
           "\"capabilities\":{\"h2\":%s,\"zstd\":%s,\"dict_ver\":\"%s\","
           "\"schema_ver\":\"%s\",\"profile_id\":\"%s\"},"
           "\"supported_schema\":[\"%s\"],\"supported_dicts\":[\"%s\"],\"profiles\":[\"%s\"]}",
           endpoint, agent, policy,
           s_control_h2 ? "true" : "false",
           s_control_zstd ? "true" : "false",
           dict, schema, profile,
           s_control_h2 ? "true" : "false",
           s_control_zstd ? "true" : "false",
           dict, schema, profile,
           schema, dict, profile);
  resp[0] = '\0';
  if (request_to_suffix("POST", "ingest/control/hello", "application/json",
                        body, strlen(body), resp, sizeof(resp)) != 0) {
    note_http_request_failure();
    goto done;
  }
  note_http_request_success();
  (void)json_get_string(resp, "dict_ver", s_control_dict_ver, sizeof(s_control_dict_ver));
  (void)json_get_string(resp, "schema_ver", s_control_schema_ver, sizeof(s_control_schema_ver));
  (void)json_get_string(resp, "profile_id", s_control_profile_id, sizeof(s_control_profile_id));
  (void)json_get_string(resp, "qos_dscp", s_control_qos_dscp, sizeof(s_control_qos_dscp));
  (void)json_get_string(resp, "threshold", s_control_threshold, sizeof(s_control_threshold));
  (void)json_get_bool(resp, "h2", &s_control_h2);
  (void)json_get_bool(resp, "zstd", &s_control_zstd);
  {
    int64_t batch_events = 0;
    int64_t flush_s = 0;
    int64_t sampling_pct = 0;
    if (json_get_int64(resp, "batch_events", &batch_events) == 0 ||
        json_get_int64(resp, "flush_interval_s", &flush_s) == 0) {
      if (batch_events < 0) batch_events = 0;
      if (batch_events > 50000) batch_events = 50000;
      if (flush_s < 0) flush_s = 0;
      if (flush_s > 300) flush_s = 300;
      edr_event_batch_apply_profile((uint32_t)batch_events, (int)flush_s);
    }
    if (json_get_int64(resp, "sampling_pct", &sampling_pct) == 0 && sampling_pct > 0) {
      if (sampling_pct > 100) sampling_pct = 100;
      s_control_sampling_pct = (unsigned)sampling_pct;
    }
  }
  edr_transport_v2_apply_profile(s_control_dict_ver, s_control_schema_ver, s_control_profile_id,
                                 s_control_h2, s_control_zstd, s_control_qos_dscp,
                                 s_control_sampling_pct, s_control_threshold,
                                 s_control_backpressure_enabled);
  s_control_hello_ok = 1;
  rc = 0;
done:
  free(endpoint);
  free(agent);
  free(policy);
  free(dict);
  free(schema);
  free(profile);
  free(body);
  return rc;
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
    if (!edr_ingest_http_configured()) {
      sleep_poll_ms(5000);
      continue;
    }
    if (!s_long_poll_fallback_cfg && s_control_stream_enabled_cfg) {
      s_poll_backoff_ms = 0;
      sleep_poll_ms(5000);
      continue;
    }
    if (!s_control_stream_enabled_cfg) {
      snprintf(s_control_stream_status, sizeof(s_control_stream_status), "%s", "disabled");
      sleep_poll_ms(5000);
      continue;
    }
    if (s_stream_ready || s_ws_ready) {
      sleep_poll_ms(5000);
      continue;
    }
    (void)edr_ingest_http_control_hello_once();
#ifdef EDR_HAVE_CURL_HTTP2
    if (http2_client_enabled()) {
      char stream_url[1400];
      int h2rc;
      build_control_stream_url(stream_url, sizeof(stream_url));
      s_stream_ready = 1;
      snprintf(s_control_stream_status, sizeof(s_control_stream_status), "%s", "connecting_h2");
      note_control_stream_success();
      backoff_ms = 5000;
      s_ws_backoff_ms = 0;
      fprintf(stderr, "[ingest-stream] HTTP/2 control stream connecting endpoint=%s\n", s_endpoint);
      h2rc = curl_h2_stream_loop(stream_url);
      s_stream_ready = 0;
      if (h2rc == 0) {
        continue;
      }
      note_control_stream_failure();
      snprintf(s_control_stream_status, sizeof(s_control_stream_status), "%s", "h2_failed");
      if (h2rc != -2 && s_long_poll_fallback_cfg && env_bool_default("EDR_HTTP2_STREAM_FALLBACK_HTTP1", 1)) {
        fprintf(stderr,
                "[ingest-stream] HTTP/2 control stream unavailable; falling back to HTTP/1.1 stream\n");
      } else if (h2rc != -2) {
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
    }
#endif
    if (stream_connect_once(&conn) != 0) {
      note_control_stream_failure();
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
    s_stream_ready = 1;
    snprintf(s_control_stream_status, sizeof(s_control_stream_status), "%s", "connected");
    note_http_request_success();
    note_control_stream_success();
    backoff_ms = 5000;
    s_ws_backoff_ms = 0;
    fprintf(stderr, "[ingest-stream] control stream connected endpoint=%s\n", s_endpoint);
    if (stream_read_loop(&conn) != 0) {
      note_control_stream_failure();
    }
    s_stream_ready = 0;
    snprintf(s_control_stream_status, sizeof(s_control_stream_status), "%s", "disconnected");
    ws_close_conn(&conn);
    net_done();
    if (s_poll_run) {
      fprintf(stderr,
              "[ingest-stream] control stream disconnected; HTTP long-poll fallback remains active\n");
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
  (void)edr_ingest_http_control_hello_once();
  snprintf(suffix, sizeof(suffix),
           "ingest/poll-commands?endpoint_id=%s&limit=8&wait_s=%d&agent_version=%s&dict_ver=%s&schema_ver=%s&profile_id=%s&h2=%d&zstd=%d",
           s_endpoint, wait_s, s_agent_ver, s_control_dict_ver, s_control_schema_ver,
           s_control_profile_id, s_control_h2 ? 1 : 0, s_control_zstd ? 1 : 0);
  resp[0] = '\0';
  if (request_to_suffix("GET", suffix, NULL, NULL, 0u, resp, sizeof(resp)) != 0) {
    note_http_request_failure();
    note_long_poll_failure();
    return -1;
  }
  note_http_request_success();
  note_long_poll_success();
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
    if (s_stream_ready || s_ws_ready) {
      s_poll_backoff_ms = 0;
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
  const char *streamoff = getenv("EDR_HTTP_CONTROL_STREAM");
  if (off && strcmp(off, "0") == 0) {
    return;
  }
  if (s_poll_started || !edr_ingest_http_configured()) {
    return;
  }
  s_poll_run = 1;
  ws_mu_init_once();
  if (s_control_stream_enabled_cfg && (!streamoff || strcmp(streamoff, "0") != 0)) {
#ifdef _WIN32
    s_ws_thread = (HANDLE)_beginthreadex(NULL, 0, control_ws_thread, NULL, 0, NULL);
    if (s_ws_thread) {
      s_ws_started = 1;
    } else {
      runtime_failure("control stream thread create failed");
    }
#else
    if (pthread_create(&s_ws_thread, NULL, control_ws_thread, NULL) == 0) {
      s_ws_started = 1;
    } else {
      runtime_failure("control stream thread create failed");
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
  s_stream_ready = 0;
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
