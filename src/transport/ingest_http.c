#include "edr/ingest_http.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
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

  char jsonpath[512];
  char cfgpath[512];
#ifdef _WIN32
  char td[MAX_PATH];
  DWORD nn = GetTempPathA(sizeof(td), td);
  if (nn == 0 || nn >= sizeof(td)) {
    snprintf(td, sizeof(td), ".\\");
  }
  snprintf(jsonpath, sizeof(jsonpath), "%sedr_ingest_%lu.json", td,
           (unsigned long)GetCurrentProcessId());
  snprintf(cfgpath, sizeof(cfgpath), "%sedr_ingest_%lu.cfg", td, (unsigned long)GetCurrentProcessId());
#else
  snprintf(jsonpath, sizeof(jsonpath), "/tmp/edr_ingest_%d.json", (int)getpid());
  snprintf(cfgpath, sizeof(cfgpath), "/tmp/edr_ingest_%d.cfg", (int)getpid());
#endif

  FILE *jf = fopen(jsonpath, "wb");
  if (!jf) {
    free(b64);
    return -1;
  }
  fprintf(jf,
          "{\"endpoint_id\":\"%s\",\"batch_id\":\"%s\",\"agent_version\":\"%s\",\"payload\":\"%s\"}\n",
          s_endpoint, batch_id, s_agent_ver, b64);
  fclose(jf);
  free(b64);

  FILE *cf = fopen(cfgpath, "wb");
  if (!cf) {
    (void)remove(jsonpath);
    return -1;
  }
  fprintf(cf, "url = \"%s/ingest/report-events\"\n", s_rest);
  fprintf(cf, "header = \"Content-Type: application/json\"\n");
  fprintf(cf, "header = \"X-Tenant-ID: %s\"\n", s_tenant[0] ? s_tenant : "demo-tenant");
  fprintf(cf, "header = \"X-User-ID: %s\"\n", s_user[0] ? s_user : "edr-agent");
  fprintf(cf, "header = \"X-Permission-Set: telemetry:write\"\n");
  if (s_bearer[0]) {
    fprintf(cf, "header = \"Authorization: Bearer %s\"\n", s_bearer);
  }
  fprintf(cf, "data = '@%s'\n", jsonpath);
  fprintf(cf, "silent\n");
  fclose(cf);

  char cmd[700];
  snprintf(cmd, sizeof(cmd), "curl -fsS --config '%s'", cfgpath);
  int rc = system(cmd);
  (void)remove(jsonpath);
  (void)remove(cfgpath);
  if (rc != 0) {
    fprintf(stderr, "[ingest-http] curl failed rc=%d (rest=%s)\n", rc, s_rest);
    return -1;
  }
  return 0;
}
