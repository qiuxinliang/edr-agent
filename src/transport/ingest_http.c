#include "edr/ingest_http.h"

#include "edr/command.h"
#include "edr/edr_log.h"
#include "edr/grpc_client.h"

/* CMake：EDR_NO_GRPC_CLIENT=1 时必须 EDR_HAVE_LIBCURL=1，否则不生成此翻译单元。 */
#if defined(EDR_NO_GRPC_CLIENT) && !defined(EDR_HAVE_LIBCURL)
#error "EDR：无 gRPC 客户端时必须以 libcurl 内嵌实现 ingest HTTP，请用 CMake 正确 find CURL::libcurl（如 vcpkg 安装 curl）"
#endif

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#ifdef _WIN32
#include <process.h>
#include <windows.h>
#else
#include <pthread.h>
#include <unistd.h>
#endif

#ifdef EDR_HAVE_LIBCURL
#include <curl/curl.h>
#endif

#ifndef _WIN32
#include <sys/time.h>
#endif

#ifdef _WIN32
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

static int64_t edr_ingest_wall_time_ms(void) {
#ifdef _WIN32
  FILETIME ft;
  GetSystemTimeAsFileTime(&ft);
  uint64_t t = ((uint64_t)ft.dwHighDateTime << 32) | (uint32_t)ft.dwLowDateTime;
  t = t / 10000ULL;
  if (t < 11644473600000ULL) {
    return 0;
  }
  return (int64_t)(t - 11644473600000ULL);
#else
  struct timeval tv;
  if (gettimeofday(&tv, NULL) != 0) {
    return (int64_t)time(NULL) * 1000;
  }
  return (int64_t)tv.tv_sec * 1000 + (int64_t)tv.tv_usec / 1000;
#endif
}

static size_t json_escaped_size(const char *s) {
  if (!s) {
    return 0;
  }
  size_t tot = 0;
  for (; *s; ++s) {
    unsigned char c = (unsigned char)*s;
    switch (c) {
      case '"':
      case '\\':
        tot += 2u;
        break;
      case '\b':
      case '\f':
      case '\n':
      case '\r':
      case '\t':
        tot += 2u;
        break;
      default:
        if (c < 0x20u) {
          tot += 6u; /* \uXXXX */
        } else {
          tot += 1u;
        }
        break;
    }
  }
  return tot;
}

static int json_escape_to_buf(const char *s, char *out, size_t cap) {
  if (!s || !out || cap < 2u) {
    return 0;
  }
  size_t w = 0;
  for (; *s; ++s) {
    if (w + 8u >= cap) {
      return 0;
    }
    unsigned char c = (unsigned char)*s;
    switch (c) {
      case '"':
        out[w++] = '\\';
        out[w++] = '"';
        break;
      case '\\':
        out[w++] = '\\';
        out[w++] = '\\';
        break;
      case '\b':
        memcpy(out + w, "\\b", 2u);
        w += 2u;
        break;
      case '\f':
        memcpy(out + w, "\\f", 2u);
        w += 2u;
        break;
      case '\n':
        memcpy(out + w, "\\n", 2u);
        w += 2u;
        break;
      case '\r':
        memcpy(out + w, "\\r", 2u);
        w += 2u;
        break;
      case '\t':
        memcpy(out + w, "\\t", 2u);
        w += 2u;
        break;
      default:
        if (c < 0x20u) {
          w += (size_t)snprintf((char *)out + w, cap - w, "\\u%04x", (unsigned)c);
        } else {
          out[w++] = (char)c;
        }
        break;
    }
  }
  if (w >= cap) {
    return 0;
  }
  out[w] = 0;
  return (int)w;
}

static void fprint_curl_cfg_dquoted_body(FILE *f, const char *s) {
  if (!f || !s) {
    return;
  }
  for (; *s; ++s) {
    if (*s == '\\' || *s == '"') {
      fputc('\\', f);
    }
    fputc(*s, f);
  }
}

#ifndef EDR_AGENT_VERSION_STRING
#define EDR_AGENT_VERSION_STRING "0.3.0"
#endif

static char s_rest[512];
static char s_tenant[128];
static char s_user[128];
static char s_bearer[512];
static char s_endpoint[128];
static char s_agent_ver[64];

void edr_ingest_http_configure(const char *rest_base, const char *tenant_id, const char *user_id,
                               const char *bearer, const char *endpoint_id, const char *agent_version) {
  memset(s_rest, 0, sizeof(s_rest));
  memset(s_tenant, 0, sizeof(s_tenant));
  memset(s_user, 0, sizeof(s_user));
  memset(s_bearer, 0, sizeof(s_bearer));
  memset(s_endpoint, 0, sizeof(s_endpoint));
  memset(s_agent_ver, 0, sizeof(s_agent_ver));
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
}

int edr_ingest_http_configured(void) { return s_rest[0] != 0 && s_endpoint[0] != 0; }

#ifdef EDR_HAVE_LIBCURL
static size_t ingest_curl_discard_cb(char *p, size_t s, size_t n, void *u) {
  (void)p;
  (void)u;
  return s * n;
}

static int curl_ensure_init(void) {
  static int done;
  if (!done) {
    if (curl_global_init(CURL_GLOBAL_DEFAULT) != 0) {
      return -1;
    }
    done = 1;
  }
  return 0;
}
#endif

/**
 * 成功返回 0（HTTP 2xx），失败 -1。relpath 为 ingest/report-events 等（无前导/）。
 */
static int ingest_post_json_relpath(const char *relpath, const char *json_body, const char *json_path_for_log) {
  if (!relpath || !relpath[0] || !json_body) {
    return -1;
  }
  size_t body_len = strlen(json_body);

#ifdef EDR_HAVE_LIBCURL
  if (curl_ensure_init() == 0) {
    CURL *curl = curl_easy_init();
    if (curl) {
      char errbuf[CURL_ERROR_SIZE];
      errbuf[0] = 0;
      char url[768];
      if ((size_t)snprintf(url, sizeof(url), "%s/%s", s_rest, relpath) >= sizeof(url)) {
        curl_easy_cleanup(curl);
      } else {
        struct curl_slist *hdrs = NULL;
    hdrs = curl_slist_append(hdrs, "Content-Type: application/json");
    char tbuf[160];
    snprintf(tbuf, sizeof(tbuf), "X-Tenant-ID: %s", s_tenant[0] ? s_tenant : "demo-tenant");
    hdrs = curl_slist_append(hdrs, tbuf);
    snprintf(tbuf, sizeof(tbuf), "X-User-ID: %s", s_user[0] ? s_user : "edr-agent");
    hdrs = curl_slist_append(hdrs, tbuf);
    hdrs = curl_slist_append(hdrs, "X-Permission-Set: telemetry:write");
    if (s_bearer[0]) {
      char abuf[640];
      if ((size_t)snprintf(abuf, sizeof(abuf), "Authorization: Bearer %s", s_bearer) < sizeof(abuf)) {
        hdrs = curl_slist_append(hdrs, abuf);
      }
    }

    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_body);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)body_len);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 120L);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, NULL);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, ingest_curl_discard_cb);
    (void)curl_easy_setopt(curl, CURLOPT_USERAGENT, "edr-agent/ingest");

    CURLcode cres = curl_easy_perform(curl);
    long code = 0;
    if (cres == CURLE_OK) {
      curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    }
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);

    if (cres != CURLE_OK) {
      const char *em = errbuf[0] ? errbuf : curl_easy_strerror(cres);
      EDR_LOGE("[ingest-http] POST %s: %s\n", relpath, em);
      EDR_LOGV("[ingest-http] (verbose) rest=%s path=%s\n", s_rest, relpath);
    } else if (code < 200 || code >= 300) {
      EDR_LOGE("[ingest-http] POST %s: HTTP %ld\n", relpath, code);
      EDR_LOGV("[ingest-http] (verbose) rest=%s path=%s extra=%s\n", s_rest, relpath,
               json_path_for_log ? json_path_for_log : "-");
    } else {
      return 0;
    }
    }
  }
  }
#endif

  (void)body_len;
  char jsonpath[512];
  char cfgpath[512];
  char resp_path[512];
#ifdef _WIN32
  char td[MAX_PATH];
  DWORD nn = GetTempPathA((DWORD)sizeof(td), td);
  if (nn == 0 || nn >= sizeof(td)) {
    snprintf(td, sizeof(td), ".\\");
  }
  win_path_fwd_slashes(td);
  snprintf(jsonpath, sizeof(jsonpath), "%sedr_ingest_%lu.json", td, (unsigned long)GetCurrentProcessId());
  snprintf(cfgpath, sizeof(cfgpath), "%sedr_ingest_%lu.cfg", td, (unsigned long)GetCurrentProcessId());
  snprintf(resp_path, sizeof(resp_path), "%sedr_ingest_%lu.http", td, (unsigned long)GetCurrentProcessId());
#else
  {
    int pid = (int)getpid();
    snprintf(jsonpath, sizeof(jsonpath), "/tmp/edr_ingest_%d.json", pid);
    snprintf(cfgpath, sizeof(cfgpath), "/tmp/edr_ingest_%d.cfg", pid);
    snprintf(resp_path, sizeof(resp_path), "/tmp/edr_ingest_%d.http", pid);
  }
#endif

  FILE *jf = fopen(jsonpath, "wb");
  if (!jf) {
    return -1;
  }
  (void)fwrite(json_body, 1, strlen(json_body), jf);
  fputc('\n', jf);
  fclose(jf);

  FILE *cf = fopen(cfgpath, "wb");
  if (!cf) {
    (void)remove(jsonpath);
    return -1;
  }
  fprintf(cf, "url = \"%s/%s\"\n", s_rest, relpath);
  fprintf(cf, "header = \"Content-Type: application/json\"\n");
  fputs("header = \"X-Tenant-ID: ", cf);
  fprint_curl_cfg_dquoted_body(cf, s_tenant[0] ? s_tenant : "demo-tenant");
  fputs("\"\n", cf);
  fputs("header = \"X-User-ID: ", cf);
  fprint_curl_cfg_dquoted_body(cf, s_user[0] ? s_user : "edr-agent");
  fputs("\"\n", cf);
  fprintf(cf, "header = \"X-Permission-Set: telemetry:write\"\n");
  if (s_bearer[0]) {
    fputs("header = \"Authorization: Bearer ", cf);
    fprint_curl_cfg_dquoted_body(cf, s_bearer);
    fputs("\"\n", cf);
  }
  fprintf(cf, "data = @%s\n", jsonpath);
  fprintf(cf, "silent\n");
  fclose(cf);

  char cmd[2048];
#ifdef _WIN32
  snprintf(cmd, sizeof(cmd), "curl -sS -o \"%s\" -w \"%%{http_code}\" --config \"%s\"", resp_path, cfgpath);
#else
  snprintf(cmd, sizeof(cmd), "curl -sS -o '%s' -w '%%{http_code}' --config '%s'", resp_path, cfgpath);
#endif

  char codebuf[32];
  size_t code_n = 0;
  memset(codebuf, 0, sizeof(codebuf));
#ifdef _WIN32
  FILE *pf = _popen(cmd, "r");
#else
  FILE *pf = popen(cmd, "r");
#endif
  if (!pf) {
    (void)remove(jsonpath);
    (void)remove(cfgpath);
    EDR_LOGE("[ingest-http] curl popen failed (rest=%s)\n", s_rest);
    return -1;
  }
  code_n = fread(codebuf, 1, sizeof(codebuf) - 1u, pf);
#ifdef _WIN32
  (void)_pclose(pf);
#else
  (void)pclose(pf);
#endif

  int http_code = 0;
  if (code_n > 0u) {
    codebuf[code_n] = 0;
    http_code = (int)strtol(codebuf, NULL, 10);
  }

  int ok = (http_code >= 200 && http_code < 300);
  if (!ok) {
    char snippet[640];
    size_t sn = 0;
    FILE *rf = fopen(resp_path, "rb");
    if (rf) {
      sn = fread(snippet, 1, sizeof(snippet) - 1u, rf);
      snippet[sn] = 0;
      fclose(rf);
    } else {
      snippet[0] = 0;
    }
    EDR_LOGE("[ingest-http] HTTP %d path=%s (rest=%s)\n", http_code, relpath, s_rest);
    if (sn > 0u) {
      EDR_LOGV("[ingest-http] (verbose) body_snippet=%.*s\n", (int)sn, snippet);
    }
  }

  (void)remove(jsonpath);
  (void)remove(cfgpath);
  (void)remove(resp_path);

  return ok ? 0 : -1;
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

  const size_t cap = 128u + json_escaped_size(s_endpoint) + json_escaped_size(batch_id) + json_escaped_size(s_agent_ver) +
                    strlen(b64) + 32u;
  char *json = (char *)malloc(cap);
  if (!json) {
    free(b64);
    return -1;
  }
  char *ept = (char *)malloc(256u + json_escaped_size(s_endpoint));
  char *bid = (char *)malloc(256u + json_escaped_size(batch_id));
  char *agv = (char *)malloc(256u + json_escaped_size(s_agent_ver));
  if (!ept || !bid || !agv) {
    free(b64);
    free(json);
    free(ept);
    free(bid);
    free(agv);
    return -1;
  }
  (void)json_escape_to_buf(s_endpoint, ept, 256u + json_escaped_size(s_endpoint));
  (void)json_escape_to_buf(batch_id, bid, 256u + json_escaped_size(batch_id));
  (void)json_escape_to_buf(s_agent_ver, agv, 256u + json_escaped_size(s_agent_ver));

  int w = snprintf(json, cap, "{\"endpoint_id\":\"%s\",\"batch_id\":\"%s\",\"agent_version\":\"%s\",\"payload\":\"%s\"}\n", ept,
          bid, agv, b64);
  if (w < 0 || (size_t)w >= cap) {
    free(b64);
    free(json);
    free(ept);
    free(bid);
    free(agv);
    return -1;
  }
  free(b64);
  free(ept);
  free(bid);
  free(agv);

  int rc = ingest_post_json_relpath("ingest/report-events", json, "report-events");
  free(json);
  return rc;
}

int edr_ingest_http_post_command_result(const char *command_id, const EdrSoarCommandMeta *meta,
                                        int execution_status, int exit_code, const char *detail_utf8) {
  if (!edr_ingest_http_configured() || !command_id || !command_id[0]) {
    return -1;
  }
  const char *d = detail_utf8 ? detail_utf8 : "";
  const size_t dmax = 64u * 1024u;
  size_t dlen = strlen(d);
  char *det = (char *)malloc(dmax + 1u);
  if (!det) {
    return -1;
  }
  if (dlen > dmax) {
    if (dmax > 3u) {
      memcpy(det, d, dmax - 3u);
      memcpy(det + dmax - 3u, "...", 3u);
      det[dmax] = 0;
    } else {
      det[0] = 0;
    }
  } else {
    memcpy(det, d, dlen);
    det[dlen] = 0;
  }

  const char *sc = meta && meta->soar_correlation_id[0] ? meta->soar_correlation_id : "";
  const char *pr = meta && meta->playbook_run_id[0] ? meta->playbook_run_id : "";
  const char *ps = meta && meta->playbook_step_id[0] ? meta->playbook_step_id : "";

  const size_t cap = 400u + json_escaped_size(s_endpoint) * 2u + json_escaped_size(command_id) + json_escaped_size(s_agent_ver) +
                    json_escaped_size(sc) + json_escaped_size(pr) + json_escaped_size(ps) + json_escaped_size(det) + 32u;
  char *e_ep0 = (char *)malloc(4u + json_escaped_size(s_endpoint));
  char *e_cid = (char *)malloc(4u + json_escaped_size(command_id));
  char *e_ep1 = (char *)malloc(4u + json_escaped_size(s_endpoint));
  char *e_agv = (char *)malloc(4u + json_escaped_size(s_agent_ver));
  char *e_sc = (char *)malloc(4u + json_escaped_size(sc));
  char *e_pr = (char *)malloc(4u + json_escaped_size(pr));
  char *e_ps = (char *)malloc(4u + json_escaped_size(ps));
  char *e_det = (char *)malloc(4u + json_escaped_size(det));
  char *j = (char *)malloc(cap);
  if (!e_ep0 || !e_cid || !e_ep1 || !e_agv || !e_sc || !e_pr || !e_ps || !e_det || !j) {
    free(det);
    free(e_ep0);
    free(e_cid);
    free(e_ep1);
    free(e_agv);
    free(e_sc);
    free(e_pr);
    free(e_ps);
    free(e_det);
    free(j);
    return -1;
  }
  (void)json_escape_to_buf(s_endpoint, e_ep0, 4u + json_escaped_size(s_endpoint));
  (void)json_escape_to_buf(command_id, e_cid, 4u + json_escaped_size(command_id));
  (void)json_escape_to_buf(s_endpoint, e_ep1, 4u + json_escaped_size(s_endpoint));
  (void)json_escape_to_buf(s_agent_ver, e_agv, 4u + json_escaped_size(s_agent_ver));
  (void)json_escape_to_buf(sc, e_sc, 4u + json_escaped_size(sc));
  (void)json_escape_to_buf(pr, e_pr, 4u + json_escaped_size(pr));
  (void)json_escape_to_buf(ps, e_ps, 4u + json_escaped_size(ps));
  (void)json_escape_to_buf(det, e_det, 4u + json_escaped_size(det));

  int64_t fin = edr_ingest_wall_time_ms();
  int w = snprintf(
      j, cap,
      "{\"endpoint_id\":\"%s\",\"command_type\":\"\",\"result\":{"
      "\"command_id\":\"%s\","
      "\"endpoint_id\":\"%s\","
      "\"agent_version\":\"%s\","
      "\"soar_correlation_id\":\"%s\","
      "\"playbook_run_id\":\"%s\","
      "\"playbook_step_id\":\"%s\","
      "\"status\":%d,\"exit_code\":%d,"
      "\"detail_utf8\":\"%s\","
      "\"finished_unix_ms\":%" PRId64 "}}",
      e_ep0, e_cid, e_ep1, e_agv, e_sc, e_pr, e_ps, execution_status, exit_code, e_det, fin);
  free(det);
  free(e_ep0);
  free(e_cid);
  free(e_ep1);
  free(e_agv);
  free(e_sc);
  free(e_pr);
  free(e_ps);
  free(e_det);
  if (w < 0 || (size_t)w >= cap) {
    free(j);
    return -1;
  }
  int rc = ingest_post_json_relpath("ingest/report-command-result", j, "report-command-result");
  free(j);
  return rc;
}

/* --- HTTP poll-commands 与 upload-file，与 gRPC 对等，见 /api/v1/ingest/... --- */

static int transport_env_cmd_poll_disabled(void) {
  const char *e = getenv("EDR_CMD_HTTP_POLL");
  return e && (strcmp(e, "0") == 0 || strcmp(e, "false") == 0);
}

static int transport_env_cmd_poll_forced(void) {
  const char *e = getenv("EDR_CMD_HTTP_POLL");
  return e && (strcmp(e, "1") == 0 || strcmp(e, "true") == 0 || strcmp(e, "TRUE") == 0);
}

static int want_http_command_poll(void) {
  if (transport_env_cmd_poll_disabled() || !edr_ingest_http_configured()) {
    return 0;
  }
  if (transport_env_cmd_poll_forced()) {
    return 1;
  }
  return !edr_grpc_client_ready();
}

static int b64_value(int c) {
  if (c >= 'A' && c <= 'Z') {
    return c - 'A';
  }
  if (c >= 'a' && c <= 'z') {
    return c - 'a' + 26;
  }
  if (c >= '0' && c <= '9') {
    return c - '0' + 52;
  }
  if (c == '+') {
    return 62;
  }
  if (c == '/') {
    return 63;
  }
  return -1;
}

static int b64_decode_in(const char *in, size_t in_len, uint8_t *out, size_t out_cap) {
  const uint8_t *p = (const uint8_t *)in;
  size_t o = 0;
  size_t i = 0u;
  while (i < in_len && p[i] && p[i] != '"') {
    while (i < in_len && (p[i] == ' ' || p[i] == '\n' || p[i] == '\r' || p[i] == '\t')) {
      i++;
    }
    if (i + 1u >= in_len || p[i] == 0) {
      break;
    }
    if (i + 3u >= in_len) {
      break;
    }
    int a = b64_value((int)p[i]);
    int b = b64_value((int)p[i + 1u]);
    if (a < 0 || b < 0) {
      break;
    }
    int c = b64_value((int)p[i + 2u]);
    int d4 = b64_value((int)p[i + 3u]);
    if (c >= 0 && d4 >= 0) {
      if (o + 3u > out_cap) {
        return -1;
      }
      out[o++] = (uint8_t)((a << 2) | (b >> 4));
      out[o++] = (uint8_t)(((b & 15) << 4) | (c >> 2));
      out[o++] = (uint8_t)(((c & 3) << 6) | d4);
    } else if (p[i + 2u] == '=') {
      if (o + 1u > out_cap) {
        return -1;
      }
      out[o++] = (uint8_t)((a << 2) | (b >> 4));
    } else if (p[i + 3u] == '=') {
      if (c < 0) {
        break;
      }
      if (o + 2u > out_cap) {
        return -1;
      }
      out[o++] = (uint8_t)((a << 2) | (b >> 4));
      out[o++] = (uint8_t)(((b & 15) << 4) | (c >> 2));
    } else {
      break;
    }
    i += 4u;
  }
  return (int)(o);
}

static int copy_json_string_val(const char *j, const char *key, char *out, size_t cap) {
  char kbuf[64];
  size_t n = 0u;
  while (key && key[n] && n + 6u < sizeof(kbuf) - 1u) {
    kbuf[n] = (char)key[n];
    n++;
  }
  if (n == 0u) {
    return -1;
  }
  kbuf[n] = 0;
  char need[80];
  if (snprintf(need, sizeof(need), "\"%s\":\"", kbuf) >= (int)sizeof(need) || need[0] == 0) {
    return -1;
  }
  const char *p = strstr(j, need);
  if (!p) {
    return -1;
  }
  p += strlen(need);
  size_t o = 0u;
  for (; p[0] && p[0] != '"';) {
    if (p[0] == '\\' && p[1] != 0) {
      p++;
    }
    if (o + 1u < cap) {
      out[o++] = *p;
    } else {
      return -1;
    }
    p++;
  }
  if (o < cap) {
    out[o] = 0;
  }
  return 0;
}

static int int32_str_10(const char *s) {
  long n = 0L;
  char *endp = NULL;
  if (!s || !s[0]) {
    return 0;
  }
  errno = 0;
  n = strtol(s, &endp, 10);
  if (errno != 0 || (endp && *endp != 0)) {
    return 0;
  }
  if (n > 2147483647L) {
    n = 2147483647L;
  }
  if (n < -2147483647L) {
    n = -2147483647L;
  }
  return (int)n;
}

static const char *find_json_object_end(const char *o) {
  int d = 0;
  for (const char *p = o; *p; p++) {
    if (*p == '{') {
      d++;
    } else if (*p == '}') {
      d--;
      if (d == 0) {
        return p + 1u;
      }
    }
  }
  return o;
}

static void try_dispatch_one_object(const char *ojson) {
  if (!ojson || ojson[0] != '{') {
    return;
  }
  char eid[128], cty[128];
  const size_t p64_cap = 2u * 1024u * 1024u;
  char *p64 = (char *)malloc(p64_cap);
  eid[0] = 0;
  cty[0] = 0;
  if (!p64) {
    return;
  }
  p64[0] = 0;
  (void)copy_json_string_val(ojson, "command_id", eid, sizeof(eid));
  (void)copy_json_string_val(ojson, "command_type", cty, sizeof(cty));
  (void)copy_json_string_val(ojson, "payload_b64", p64, p64_cap);
  if (eid[0] == 0 || cty[0] == 0) {
    free(p64);
    return;
  }
  EdrSoarCommandMeta m;
  memset(&m, 0, sizeof(m));
  char sc[200], pr[200], ps[200], ikey[200];
  sc[0] = 0;
  if (copy_json_string_val(ojson, "soar_correlation_id", sc, sizeof(sc)) == 0) {
    snprintf(m.soar_correlation_id, sizeof(m.soar_correlation_id), "%s", sc);
  }
  if (copy_json_string_val(ojson, "playbook_run_id", pr, sizeof(pr)) == 0) {
    snprintf(m.playbook_run_id, sizeof(m.playbook_run_id), "%s", pr);
  }
  if (copy_json_string_val(ojson, "playbook_step_id", ps, sizeof(ps)) == 0) {
    snprintf(m.playbook_step_id, sizeof(m.playbook_step_id), "%s", ps);
  }
  if (copy_json_string_val(ojson, "idempotency_key", ikey, sizeof(ikey)) == 0) {
    snprintf(m.idempotency_key, sizeof(m.idempotency_key), "%s", ikey);
  }
  {
    char tmp[32];
    if (copy_json_string_val(ojson, "issued_at_unix_ms", tmp, sizeof(tmp)) == 0) {
      m.issued_at_unix_ms = (int64_t)strtoll(tmp, NULL, 10);
    }
  }
  {
    char t[32];
    if (copy_json_string_val(ojson, "deadline_ms", t, sizeof(t)) == 0) {
      m.deadline_ms = (uint32_t)int32_str_10(t);
    }
  }
  {
    const size_t dec_cap = 1u * 1024u * 1024u;
    uint8_t *pbuf = (uint8_t *)malloc(dec_cap);
    if (pbuf) {
      int n = 0;
      if (p64[0]) {
        n = b64_decode_in(p64, strlen(p64), pbuf, dec_cap);
      }
      if (n < 0) {
        n = 0;
      }
      edr_command_on_envelope(eid, cty, n > 0 ? pbuf : NULL, (size_t)(unsigned)n, &m);
      free(pbuf);
    }
  }
  free(p64);
}

static void poll_dispatch_body(const char *body) {
  if (!body) {
    return;
  }
  const char *cstart = strstr(body, "\"commands\"");
  if (!cstart) {
    return;
  }
  const char *lb = strchr(cstart, '[');
  if (!lb) {
    return;
  }
  const char *p = lb;
  for (;;) {
    p = strchr(p, '{');
    if (!p) {
      return;
    }
    const char *e = find_json_object_end(p);
    if (!e || e == p) {
      return;
    }
    {
      char *s = (char *)malloc((size_t)(e - p) + 1u);
      if (s) {
        memcpy(s, p, (size_t)(e - p));
        s[(size_t)(e - p)] = 0;
        try_dispatch_one_object(s);
        free(s);
      }
    }
    p = e;
    for (;;) {
      if (!*p) {
        return;
      }
      if (*p == ']') {
        return;
      }
      if (isspace((unsigned char)*p) || *p == ',') {
        p++;
        continue;
      }
      if (*p == '{' || *p == '}') {
        break;
      }
      p++;
    }
  }
}

#ifdef EDR_HAVE_LIBCURL
struct edr_ingest_membuf {
  char *p;
  size_t len;
  size_t cap;
};

static size_t ingest_curl_grow_write(char *ptr, size_t sz, size_t nmemb, void *u) {
  size_t a = sz * nmemb;
  struct edr_ingest_membuf *b = (struct edr_ingest_membuf *)u;
  if (a == 0u) {
    return 0u;
  }
  if (b->len + a + 1u > b->cap) {
    size_t nc = (b->cap < 1024u ? 2048u : b->cap * 2u) + a;
    char *np = (char *)realloc(b->p, nc);
    if (!np) {
      return 0u;
    }
    b->p = np;
    b->cap = nc;
  }
  memcpy(b->p + b->len, ptr, a);
  b->len += a;
  b->p[b->len] = 0;
  return a;
}

static int ingest_get_json_relpath_curl(const char *relpath, char **out_body, int *out_http) {
  if (curl_ensure_init() != 0 || !relpath || !out_body || !out_http) {
    return -1;
  }
  *out_body = NULL;
  *out_http = 0;
  char url[1024];
  if (snprintf(url, sizeof(url), "%s/%s", s_rest, relpath) >= (int)sizeof(url)) {
    return -1;
  }
  struct edr_ingest_membuf mb;
  memset(&mb, 0, sizeof(mb));
  CURL *curl = curl_easy_init();
  if (!curl) {
    return -1;
  }
  struct curl_slist *hdrs = NULL;
  {
    char tbuf[200];
    hdrs = curl_slist_append(hdrs, "Content-Type: application/json");
    snprintf(tbuf, sizeof(tbuf), "X-Tenant-ID: %s", s_tenant[0] ? s_tenant : "demo-tenant");
    hdrs = curl_slist_append(hdrs, tbuf);
    snprintf(tbuf, sizeof(tbuf), "X-User-ID: %s", s_user[0] ? s_user : "edr-agent");
    hdrs = curl_slist_append(hdrs, tbuf);
    hdrs = curl_slist_append(hdrs, "X-Permission-Set: telemetry:write");
    if (s_bearer[0] && (size_t)snprintf(tbuf, sizeof(tbuf), "Authorization: Bearer %s", s_bearer) < sizeof(tbuf)) {
      hdrs = curl_slist_append(hdrs, tbuf);
    }
  }
  char errbuf[CURL_ERROR_SIZE];
  errbuf[0] = 0;
  curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);
  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, 60L);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, ingest_curl_grow_write);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&mb);
  (void)curl_easy_setopt(curl, CURLOPT_USERAGENT, "edr-agent/ingest");
  CURLcode cres = curl_easy_perform(curl);
  long code = 0;
  if (cres == CURLE_OK) {
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
  }
  curl_slist_free_all(hdrs);
  curl_easy_cleanup(curl);
  if (cres != CURLE_OK) {
    const char *em = errbuf[0] ? errbuf : curl_easy_strerror(cres);
    EDR_LOGE("[ingest-http] GET %s: %s\n", relpath, em);
    free(mb.p);
    return -1;
  }
  *out_body = mb.p;
  *out_http = (int)code;
  if (!mb.p) {
    *out_body = (char *)malloc(1);
    if (*out_body) {
      (*out_body)[0] = 0;
    }
  }
  return 0;
}
#endif

static int ingest_get_json_relpath_shell(const char *relpath, char **out_body, int *out_http) {
  if (!s_rest[0] || !relpath || !out_body || !out_http) {
    return -1;
  }
  *out_body = NULL;
  *out_http = 0;
  char jsonpath[512], cfgpath[512], resp_path[512];
#ifdef _WIN32
  char td[MAX_PATH];
  DWORD nn = GetTempPathA((DWORD)sizeof(td), td);
  if (nn == 0 || nn >= sizeof(td)) {
    snprintf(td, sizeof(td), ".\\");
  }
  win_path_fwd_slashes(td);
  {
    unsigned long pp = (unsigned long)GetCurrentProcessId();
    unsigned long t = (unsigned long)GetTickCount() ^ (pp << 1);
    _snprintf(cfgpath, sizeof(cfgpath) - 1, "%sedr_getcfg_%lu_%lu.curl", td, t, pp);
    _snprintf(resp_path, sizeof(resp_path) - 1, "%sedr_getresp_%lu_%lu.http", td, t, pp);
  }
  (void)jsonpath;
  jsonpath[0] = 0;
#else
  (void)jsonpath;
  {
    int pp = (int)getpid();
    (void)snprintf(cfgpath, sizeof(cfgpath), "/tmp/edr_getcfg_%d.curl", pp);
    (void)snprintf(resp_path, sizeof(resp_path), "/tmp/edr_getresp_%d.http", pp);
  }
#endif
  {
    char url[1024];
    if (snprintf(url, sizeof(url), "%s/%s", s_rest, relpath) >= (int)sizeof(url)) {
      return -1;
    }
    FILE *cf = fopen(cfgpath, "wb");
    if (!cf) {
      return -1;
    }
    fprintf(cf, "url = \"%s\"\n", url);
    fprintf(cf, "header = \"X-Tenant-ID: ");
    fprint_curl_cfg_dquoted_body(cf, s_tenant[0] ? s_tenant : "demo-tenant");
    fputs("\"\n", cf);
    fprintf(cf, "header = \"X-User-ID: ");
    fprint_curl_cfg_dquoted_body(cf, s_user[0] ? s_user : "edr-agent");
    fputs("\"\n", cf);
    fprintf(cf, "header = \"X-Permission-Set: telemetry:write\"\n");
    if (s_bearer[0]) {
      fputs("header = \"Authorization: Bearer ", cf);
      fprint_curl_cfg_dquoted_body(cf, s_bearer);
      fputs("\"\n", cf);
    }
    fprintf(cf, "output = \"%s\"\n", resp_path);
    fprintf(cf, "silent\n");
    fclose(cf);
  }
  char cmd[2560];
#ifdef _WIN32
  snprintf(cmd, sizeof(cmd), "curl -sS -o \"%s\" -w \"%%{http_code}\" --config \"%s\"", resp_path, cfgpath);
#else
  snprintf(cmd, sizeof(cmd), "curl -sS -o '%s' -w '%%{http_code}' --config '%s'", resp_path, cfgpath);
#endif
  char codebuf[32];
  size_t code_n = 0;
  memset(codebuf, 0, sizeof(codebuf));
#ifdef _WIN32
  FILE *pf = _popen(cmd, "r");
#else
  FILE *pf = popen(cmd, "r");
#endif
  if (!pf) {
    (void)remove(cfgpath);
    EDR_LOGE("%s", "[ingest-http] GET curl popen failed\n");
    return -1;
  }
  code_n = fread(codebuf, 1, sizeof(codebuf) - 1u, pf);
#ifdef _WIN32
  (void)_pclose(pf);
#else
  (void)pclose(pf);
#endif
  int http_code = 0;
  if (code_n > 0u) {
    codebuf[code_n] = 0;
    http_code = (int)strtol(codebuf, NULL, 10);
  }
  (void)remove(cfgpath);
  *out_http = http_code;
  {
    FILE *rf = fopen(resp_path, "rb");
    if (!rf) {
      (void)remove(resp_path);
      return -1;
    }
    if (fseek(rf, 0, SEEK_END) != 0) {
      fclose(rf);
      (void)remove(resp_path);
      return -1;
    }
    long fsz = ftell(rf);
    if (fsz < 0) {
      fclose(rf);
      (void)remove(resp_path);
      return -1;
    }
    rewind(rf);
    *out_body = (char *)malloc((size_t)fsz + 1u);
    if (!*out_body) {
      fclose(rf);
      (void)remove(resp_path);
      return -1;
    }
    (void)fread(*out_body, 1, (size_t)fsz, rf);
    (*out_body)[(size_t)fsz] = 0;
    fclose(rf);
  }
  (void)remove(resp_path);
  if (http_code < 200 || http_code >= 300) {
    free(*out_body);
    *out_body = NULL;
    return -1;
  }
  return 0;
}

static int ingest_get_json_relpath(const char *relpath, char **out_body) {
  int h = 0;
  char *body = NULL;
  if (!relpath || !out_body) {
    return -1;
  }
  *out_body = NULL;
#ifdef EDR_HAVE_LIBCURL
  {
    int hc = 0;
    if (ingest_get_json_relpath_curl(relpath, &body, &hc) == 0) {
      if (hc >= 200 && hc < 300) {
        *out_body = body;
        return 0;
      }
      EDR_LOGE("[ingest-http] GET %s: HTTP %d (libcurl)\n", relpath, hc);
      free(body);
      body = NULL;
    }
  }
#endif
  if (ingest_get_json_relpath_shell(relpath, &body, &h) == 0 && body) {
    *out_body = body;
    return 0;
  }
  return -1;
}

static int append_pct_encode(const char *in, char *out, size_t cap) {
  size_t w = 0;
  const char *p = in;
  for (; p && p[0]; p++) {
    unsigned char c = (unsigned char)p[0];
    if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '-' || c == '_' || c == '.'
        || c == '~') {
      if (w + 2u >= cap) {
        return -1;
      }
      out[w++] = (char)c;
    } else {
      if (w + 4u >= cap) {
        return -1;
      }
      (void)snprintf(out + w, cap - w, "%%%.2X", (unsigned)c);
      w += 3u;
    }
  }
  if (w < cap) {
    out[w] = 0;
  }
  return 0;
}

static void http_poll_once(void) {
  char relp[640];
  char eenc[500];
  eenc[0] = 0;
  if (append_pct_encode(s_endpoint, eenc, sizeof(eenc)) != 0) {
    return;
  }
  if (snprintf(relp, sizeof(relp), "ingest/poll-commands?endpoint_id=%s&limit=16", eenc) >= (int)sizeof(relp)) {
    return;
  }
  char *body = NULL;
  if (ingest_get_json_relpath(relp, &body) != 0) {
    return;
  }
  if (body) {
    poll_dispatch_body(body);
    free(body);
  }
}

static volatile int s_cmd_poll_run;
static volatile int s_cmd_poll_thread_started;
#ifdef _WIN32
static HANDLE s_cmd_poll_thr;
#else
static pthread_t s_cmd_poll_thr;
#endif

static void my_sleep_ms(unsigned n) {
#ifdef _WIN32
  if (n > 0u) {
    Sleep((DWORD)(n < 0xffffffffu ? n : 0xffffffffu));
  }
#else
  (void)usleep((n > 0u) ? n * 1000u : 0u);
#endif
}

static unsigned poll_interval_ms(void) {
  return 8000u;
}

static void *cmd_poll_thread(void *a) {
  (void)a;
  while (s_cmd_poll_run) {
    if (want_http_command_poll() && edr_ingest_http_configured()) {
      http_poll_once();
    }
    for (unsigned i = 0; i < poll_interval_ms() && s_cmd_poll_run; i += 200u) {
      my_sleep_ms(200u);
    }
  }
  return NULL;
}

#ifdef _WIN32
static unsigned __stdcall win_cmd_poll(void *p) {
  (void)cmd_poll_thread(p);
  return 0U;
}
#endif

void edr_ingest_http_start_command_poll(void) {
  if (s_cmd_poll_thread_started) {
    return;
  }
  if (!want_http_command_poll() || !edr_ingest_http_configured()) {
    return;
  }
  s_cmd_poll_run = 1;
  s_cmd_poll_thread_started = 1;
#ifdef _WIN32
  s_cmd_poll_thr = (HANDLE)_beginthreadex(NULL, 0, win_cmd_poll, NULL, 0, NULL);
  if (s_cmd_poll_thr == 0) {
    s_cmd_poll_thread_started = 0;
    s_cmd_poll_run = 0;
  }
#else
  if (pthread_create(&s_cmd_poll_thr, NULL, cmd_poll_thread, NULL) != 0) {
    s_cmd_poll_thread_started = 0;
    s_cmd_poll_run = 0;
  }
#endif
}

void edr_ingest_http_stop_command_poll(void) {
  s_cmd_poll_run = 0;
  if (s_cmd_poll_thread_started) {
#ifdef _WIN32
    if (s_cmd_poll_thr) {
      WaitForSingleObject(s_cmd_poll_thr, 15000);
      CloseHandle(s_cmd_poll_thr);
      s_cmd_poll_thr = 0;
    }
#else
    (void)pthread_join(s_cmd_poll_thr, NULL);
#endif
  }
  s_cmd_poll_thread_started = 0;
}

static int copy_minio_key_from_json(const char *json, char *out, size_t out_cap) {
  if (!out || out_cap < 2u) {
    return -1;
  }
  out[0] = 0;
  const char *k = (json && json[0]) ? strstr(json, "\"minio_key\":\"") : NULL;
  if (!k) {
    return -1;
  }
  k += 14; /* past "minio_key":" */
  {
    const char *e = k;
    for (; *e && *e != '"'; e++) {
      if (*e == '\\' && e[1] != 0) {
        e++;
      }
    }
    if (*e != '"') {
      return -1;
    }
    size_t n = (size_t)(e - k);
    if (n + 1u > out_cap) {
      n = out_cap - 1u;
    }
    memcpy(out, k, n);
    out[n] = 0;
  }
  return 0;
}

static int file_base_name_to_buf(const char *p, char *b, size_t cap) {
  if (!p) {
    return -1;
  }
  const char *s = p, *d = s;
  for (; *d; d++) {
#ifdef _WIN32
    if (*d == '/' || *d == '\\') {
      s = d + 1;
    }
#else
    if (*d == '/') {
      s = d + 1;
    }
#endif
  }
  (void)snprintf(b, cap, "%s", s);
  return 0;
}

int edr_ingest_http_upload_file_multipart(const char *upload_id, const char *file_path, const char *sha256_hex,
                                         char *out_minio_key, size_t out_minio_key_cap) {
  if (!edr_ingest_http_configured() || !file_path || !file_path[0]) {
    return -1;
  }
  char ubuf[160];
  ubuf[0] = 0;
  if (upload_id && upload_id[0]) {
    snprintf(ubuf, sizeof(ubuf), "%s", upload_id);
  } else {
    (void)snprintf(ubuf, sizeof(ubuf), "up-c-%" PRId64, (int64_t)edr_ingest_wall_time_ms());
  }
  if (out_minio_key && out_minio_key_cap > 0u) {
    out_minio_key[0] = 0;
  }
  char bname[260];
  bname[0] = 0;
  (void)file_base_name_to_buf(file_path, bname, sizeof(bname));
  if (bname[0] == 0) {
    snprintf(bname, sizeof(bname), "%s", "upload.bin");
  }
#ifdef EDR_HAVE_LIBCURL
  if (curl_ensure_init() == 0) {
    CURL *curl = curl_easy_init();
    if (curl) {
      char errbuf[CURL_ERROR_SIZE], url[800];
      errbuf[0] = 0;
      if (snprintf(url, sizeof(url), "%s/ingest/upload-file", s_rest) >= (int)sizeof(url)) {
        curl_easy_cleanup(curl);
        return -1;
      }
      struct curl_slist *hdrs = NULL;
      {
        char tbuf[200];
        snprintf(tbuf, sizeof(tbuf), "X-Tenant-ID: %s", s_tenant[0] ? s_tenant : "demo-tenant");
        hdrs = curl_slist_append(hdrs, tbuf);
        snprintf(tbuf, sizeof(tbuf), "X-User-ID: %s", s_user[0] ? s_user : "edr-agent");
        hdrs = curl_slist_append(hdrs, tbuf);
        hdrs = curl_slist_append(hdrs, "X-Permission-Set: telemetry:write");
        if (s_bearer[0] && (size_t)snprintf(tbuf, sizeof(tbuf), "Authorization: Bearer %s", s_bearer) < sizeof(tbuf)) {
          hdrs = curl_slist_append(hdrs, tbuf);
        }
      }
      struct edr_ingest_membuf mb;
      memset(&mb, 0, sizeof(mb));
      curl_mime *mime = curl_mime_init(curl);
      if (mime) {
        curl_mimepart *part;
        part = curl_mime_addpart(mime);
        curl_mime_name(part, "upload_id");
        curl_mime_data(part, ubuf, CURL_ZERO_TERMINATED);
        part = curl_mime_addpart(mime);
        curl_mime_name(part, "file");
        (void)curl_mime_filedata(part, file_path);
        (void)curl_mime_filename(part, bname);
        part = curl_mime_addpart(mime);
        curl_mime_name(part, "file_name");
        curl_mime_data(part, bname, CURL_ZERO_TERMINATED);
        if (sha256_hex && sha256_hex[0]) {
          part = curl_mime_addpart(mime);
          curl_mime_name(part, "sha256");
          curl_mime_data(part, sha256_hex, CURL_ZERO_TERMINATED);
        }
        curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 300L);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, ingest_curl_grow_write);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&mb);
        (void)curl_easy_setopt(curl, CURLOPT_USERAGENT, "edr-agent/ingest");
        CURLcode cres = curl_easy_perform(curl);
        long code = 0;
        if (cres == CURLE_OK) {
          curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
        }
        curl_mime_free(mime);
        curl_slist_free_all(hdrs);
        curl_easy_cleanup(curl);
        if (cres == CURLE_OK && code >= 200 && code < 300) {
          if (mb.p && out_minio_key) {
            (void)copy_minio_key_from_json(mb.p, out_minio_key, out_minio_key_cap);
          }
          free(mb.p);
          return 0;
        }
        if (cres != CURLE_OK) {
          EDR_LOGE("[ingest-http] upload: %s\n", errbuf[0] ? errbuf : curl_easy_strerror(cres));
        } else {
          EDR_LOGE("[ingest-http] upload HTTP %ld (libcurl)\n", code);
        }
        free(mb.p);
      } else {
        curl_slist_free_all(hdrs);
        curl_easy_cleanup(curl);
      }
    }
  }
#endif
  {
    char rpath[512], cfg2[800];
    char tbuf2[8];
    (void)memset(tbuf2, 0, sizeof(tbuf2));
#ifdef _WIN32
    char td[MAX_PATH];
    DWORD nn = GetTempPathA((DWORD)sizeof(td), td);
    if (nn == 0 || nn >= sizeof(td)) {
      snprintf(td, sizeof(td), ".\\");
    }
    win_path_fwd_slashes(td);
    (void)snprintf(rpath, sizeof(rpath), "%sedr_upr_%lu.http", td, (unsigned long)GetCurrentProcessId());
    (void)snprintf(cfg2, sizeof(cfg2), "%sedr_upc_%lu.curl", td, (unsigned long)GetCurrentProcessId());
#else
    (void)snprintf(rpath, sizeof(rpath), "/tmp/edr_upr_%d.http", (int)getpid());
    (void)snprintf(cfg2, sizeof(cfg2), "/tmp/edr_upc_%d.curl", (int)getpid());
#endif
    {
      char url0[800];
      if (snprintf(url0, sizeof(url0), "%s/ingest/upload-file", s_rest) >= (int)sizeof(url0)) {
        return -1;
      }
      FILE *cfx = fopen(cfg2, "wb");
      if (!cfx) {
        return -1;
      }
      fprintf(cfx, "url = \"%s\"\n", url0);
      fprintf(cfx, "form = \"upload_id=");
      fprint_curl_cfg_dquoted_body(cfx, ubuf);
      fputs("\"\n", cfx);
      fprintf(cfx, "form = \"file_name=");
      fprint_curl_cfg_dquoted_body(cfx, bname);
      fputs("\"\n", cfx);
      fprintf(cfx, "form = \"file=@");
      fprint_curl_cfg_dquoted_body(cfx, file_path);
      fputs("\"\n", cfx);
      if (sha256_hex && sha256_hex[0]) {
        fprintf(cfx, "form = \"sha256=");
        fprint_curl_cfg_dquoted_body(cfx, sha256_hex);
        fputs("\"\n", cfx);
      }
      fprintf(cfx, "header = \"X-Tenant-ID: ");
      fprint_curl_cfg_dquoted_body(cfx, s_tenant[0] ? s_tenant : "demo-tenant");
      fputs("\"\n", cfx);
      fprintf(cfx, "header = \"X-User-ID: ");
      fprint_curl_cfg_dquoted_body(cfx, s_user[0] ? s_user : "edr-agent");
      fputs("\"\n", cfx);
      fprintf(cfx, "header = \"X-Permission-Set: telemetry:write\"\n");
      if (s_bearer[0]) {
        fputs("header = \"Authorization: Bearer ", cfx);
        fprint_curl_cfg_dquoted_body(cfx, s_bearer);
        fputs("\"\n", cfx);
      }
      fprintf(cfx, "output = \"%s\"\n", rpath);
      fprintf(cfx, "silent\n");
      fclose(cfx);
    }
    char cmd2[3000];
#ifdef _WIN32
    snprintf(cmd2, sizeof(cmd2), "curl -sS -o \"%s\" -w \"%%{http_code}\" --config \"%s\"", rpath, cfg2);
#else
    snprintf(cmd2, sizeof(cmd2), "curl -sS -o '%s' -w '%%{http_code}' --config '%s'", rpath, cfg2);
#endif
    char cbuf2[12];
    memset(cbuf2, 0, sizeof(cbuf2));
#ifdef _WIN32
    {
      FILE *p2 = _popen(cmd2, "r");
      if (p2) {
        (void)fread(cbuf2, 1, sizeof(cbuf2) - 1u, p2);
        (void)_pclose(p2);
      }
    }
#else
    {
      FILE *p2 = popen(cmd2, "r");
      if (p2) {
        (void)fread(cbuf2, 1, sizeof(cbuf2) - 1u, p2);
        (void)pclose(p2);
      }
    }
#endif
    (void)remove(cfg2);
    int h2 = (int)strtol(cbuf2, NULL, 10);
    if (h2 < 200 || h2 >= 300) {
      (void)remove(rpath);
      return -1;
    }
    {
      FILE *rf2 = fopen(rpath, "rb");
      if (!rf2) {
        return -1;
      }
      if (fseek(rf2, 0, SEEK_END) != 0) {
        fclose(rf2);
        (void)remove(rpath);
        return -1;
      }
      long fs2 = ftell(rf2);
      if (fs2 < 0) {
        fclose(rf2);
        (void)remove(rpath);
        return -1;
      }
      rewind(rf2);
      char *jbuf = (char *)malloc((size_t)fs2 + 1u);
      if (!jbuf) {
        fclose(rf2);
        (void)remove(rpath);
        return -1;
      }
      (void)fread(jbuf, 1, (size_t)fs2, rf2);
      jbuf[(size_t)fs2] = 0;
      fclose(rf2);
      (void)remove(rpath);
      if (out_minio_key) {
        (void)copy_minio_key_from_json(jbuf, out_minio_key, out_minio_key_cap);
      }
      free(jbuf);
    }
    return 0;
  }
}