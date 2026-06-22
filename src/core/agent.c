#include "edr/agent.h"

#include "edr/adaptive_collection.h"
#include "edr/ave_sdk.h"
#include "edr/behavior_alert_emit.h"
#include "edr/config.h"
#include "edr/event_bus.h"
#include "edr/preprocess.h"
#include "edr/resource.h"
#include "edr/self_protect.h"
#include "edr/sensor_interest.h"
#include "edr/sha256.h"
#include "edr/shell_session.h"
#include "edr/shellcode_known.h"
#include "edr/time_util.h"

#if defined(EDR_WITH_FL_TRAINER)
#include "edr/fl_trainer.h"
#endif

#include "edr/attack_surface_report.h"
#include "edr/collector.h"
#include "edr/command.h"
#include "edr/grpc_client.h"
#include "edr/ingest_http.h"
#include "edr/local_evidence_cache.h"
#include "edr/p0_rule_ir.h"
#include "edr/pmfe.h"
#include "edr/storage_queue.h"
#include "edr/transport_sink.h"
#include "edr/transport_v2.h"
#include "edr/windows_event_policy.h"
#ifdef _WIN32
#include <windows.h>
static void edr_ms_sleep(unsigned ms) { Sleep(ms); }
#else
#include <unistd.h>
static void edr_ms_sleep(unsigned ms) { usleep(ms * 1000u); }
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sys/stat.h>

#ifdef EDR_HAVE_OPENSSL_HTTP
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#endif

#ifdef _WIN32
#define EDR_AGENT_STRDUP _strdup
#else
#define EDR_AGENT_STRDUP strdup
#endif

#ifndef EDR_AGENT_VERSION_STRING
#define EDR_AGENT_VERSION_STRING "unknown"
#endif

#define EDR_REMOTE_POLICY_COLLECTION_CHANGED 0x01

typedef enum {
  EDR_AGENT_POLL_RESOURCE = 0,
  EDR_AGENT_POLL_SELF_PROTECT,
  EDR_AGENT_POLL_CONFIG_RELOAD,
  EDR_AGENT_POLL_REMOTE_CONFIG,
  EDR_AGENT_POLL_P0_BUNDLE,
  EDR_AGENT_POLL_SENSOR_INTEREST,
  EDR_AGENT_POLL_ATTACK_SURFACE,
  EDR_AGENT_POLL_ENGINE_HEALTH,
  EDR_AGENT_POLL_SHELL_SESSION,
  EDR_AGENT_POLL_COMMAND_DELIVERY,
  EDR_AGENT_POLL_COUNT
} EdrAgentPollProbeId;

typedef struct {
  uint64_t calls;
  uint64_t last_us;
  uint64_t max_us;
  uint64_t total_us;
} EdrAgentPollProbe;

static EdrAgentPollProbe s_agent_poll_probe[EDR_AGENT_POLL_COUNT];
static uint64_t s_agent_loop_count;
static uint64_t s_agent_loop_last_start_ns;
static uint64_t s_agent_loop_interval_last_ms;
static uint64_t s_agent_loop_interval_max_ms;
static uint64_t s_agent_loop_elapsed_last_us;
static uint64_t s_agent_loop_elapsed_max_us;
#ifdef _WIN32
static uint32_t s_agent_main_thread_id;
#endif

static uint64_t edr_ns_to_ms(uint64_t ns) { return ns / 1000000ULL; }

static void edr_agent_poll_probe_done(EdrAgentPollProbeId id, uint64_t started_ns) {
  if ((int)id < 0 || id >= EDR_AGENT_POLL_COUNT || started_ns == 0u) {
    return;
  }
  uint64_t now_ns = edr_monotonic_ns();
  uint64_t elapsed_us = now_ns > started_ns ? (now_ns - started_ns) / 1000ULL : 0u;
  s_agent_poll_probe[id].calls++;
  s_agent_poll_probe[id].last_us = elapsed_us;
  s_agent_poll_probe[id].total_us += elapsed_us;
  if (elapsed_us > s_agent_poll_probe[id].max_us) {
    s_agent_poll_probe[id].max_us = elapsed_us;
  }
}

static uint64_t edr_agent_loop_probe_begin(void) {
  uint64_t now_ns = edr_monotonic_ns();
  if (s_agent_loop_last_start_ns != 0u && now_ns > s_agent_loop_last_start_ns) {
    uint64_t interval_ms = edr_ns_to_ms(now_ns - s_agent_loop_last_start_ns);
    s_agent_loop_interval_last_ms = interval_ms;
    if (interval_ms > s_agent_loop_interval_max_ms) {
      s_agent_loop_interval_max_ms = interval_ms;
    }
  }
  s_agent_loop_last_start_ns = now_ns;
  s_agent_loop_count++;
  return now_ns;
}

static void edr_agent_loop_probe_end(uint64_t started_ns) {
  if (started_ns == 0u) {
    return;
  }
  uint64_t now_ns = edr_monotonic_ns();
  uint64_t elapsed_us = now_ns > started_ns ? (now_ns - started_ns) / 1000ULL : 0u;
  s_agent_loop_elapsed_last_us = elapsed_us;
  if (elapsed_us > s_agent_loop_elapsed_max_us) {
    s_agent_loop_elapsed_max_us = elapsed_us;
  }
}

#define EDR_AGENT_TIMED_POLL(id, expr)      \
  do {                                      \
    uint64_t edr_poll_started_ns__ = edr_monotonic_ns(); \
    expr;                                  \
    edr_agent_poll_probe_done((id), edr_poll_started_ns__); \
  } while (0)

static int edr_agent_download_text_file(const char *url, const char *tmp, size_t max_bytes,
                                        const char *label, EdrAgentConfigHeaders *headers) {
  int rc;
  if (!url || !url[0] || !tmp || !tmp[0]) {
    return -1;
  }
  rc = headers
           ? edr_ingest_http_get_url_to_file_meta(url, tmp, max_bytes, headers)
           : edr_ingest_http_get_url_to_file(url, tmp, max_bytes);
  if (rc == 0) {
    return 0;
  }
  fprintf(stderr, "[config] %s pull failed via native HTTPS client\n",
          label && label[0] ? label : "remote config");
  return -1;
}

static int edr_agent_config_signature_required(const EdrConfig *cfg) {
  const char *v = getenv("EDR_AGENT_CONFIG_SIGNATURE_REQUIRED");
  if (v && (v[0] == '1' || v[0] == 't' || v[0] == 'T' || v[0] == 'y' || v[0] == 'Y')) {
    return 1;
  }
  return cfg && cfg->config_signing.signature_required;
}

static const char *edr_agent_config_signing_key_id(const EdrConfig *cfg) {
  const char *v = getenv("EDR_AGENT_CONFIG_SIGNING_KEY_ID");
  if (v && v[0]) {
    return v;
  }
  if (cfg && cfg->config_signing.signing_key_id[0]) {
    return cfg->config_signing.signing_key_id;
  }
  return "";
}

#ifdef EDR_HAVE_OPENSSL_HTTP
static const char *edr_agent_config_signing_secret(void) {
  const char *v = getenv("EDR_AGENT_CONFIG_SIGNING_SECRET");
  if (v && v[0]) {
    return v;
  }
  return "dev-agent-config-signing-secret";
}

static const char *edr_agent_config_public_key_pem(const EdrConfig *cfg) {
  const char *v = getenv("EDR_AGENT_CONFIG_SIGNING_PUBLIC_KEY_PEM");
  if (v && v[0]) {
    return v;
  }
  if (cfg && cfg->config_signing.public_key_pem[0]) {
    return cfg->config_signing.public_key_pem;
  }
  return "";
}

static int b64url_val(char c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '-' || c == '+') return 62;
  if (c == '_' || c == '/') return 63;
  return -1;
}

static int b64url_decode(const char *in, unsigned char *out, size_t out_cap, size_t *out_len) {
  int val = 0;
  int valb = -8;
  size_t n = 0;
  if (!in || !out || !out_len) {
    return -1;
  }
  for (; *in; in++) {
    if (*in == '=') break;
    int d = b64url_val(*in);
    if (d < 0) {
      if (*in == '\r' || *in == '\n' || *in == ' ' || *in == '\t') continue;
      return -1;
    }
    val = (val << 6) | d;
    valb += 6;
    if (valb >= 0) {
      if (n >= out_cap) return -1;
      out[n++] = (unsigned char)((val >> valb) & 0xFF);
      valb -= 8;
    }
  }
  *out_len = n;
  return 0;
}

static void b64url_encode(const unsigned char *in, size_t in_len, char *out, size_t out_cap) {
  static const char *tab = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  size_t o = 0;
  unsigned int val = 0;
  int valb = -6;
  if (!out || out_cap == 0u) return;
  for (size_t i = 0; i < in_len; i++) {
    val = (val << 8) | in[i];
    valb += 8;
    while (valb >= 0) {
      if (o + 1u >= out_cap) {
        out[o] = '\0';
        return;
      }
      out[o++] = tab[(val >> valb) & 0x3F];
      valb -= 6;
    }
  }
  if (valb > -6 && o + 1u < out_cap) {
    out[o++] = tab[((val << 8) >> (valb + 8)) & 0x3F];
  }
  out[o < out_cap ? o : out_cap - 1u] = '\0';
}
#endif

static time_t edr_agent_timegm_utc(struct tm *tmv) {
#ifdef _WIN32
  return _mkgmtime(tmv);
#else
  return timegm(tmv);
#endif
}

static int edr_agent_rfc3339_expired(const char *raw) {
  int y = 0, mo = 0, d = 0, h = 0, mi = 0, s = 0;
  struct tm tmv;
  time_t t;
  if (!raw || !raw[0]) {
    return 0;
  }
  if (sscanf(raw, "%d-%d-%dT%d:%d:%d", &y, &mo, &d, &h, &mi, &s) != 6) {
    return 0;
  }
  memset(&tmv, 0, sizeof(tmv));
  tmv.tm_year = y - 1900;
  tmv.tm_mon = mo - 1;
  tmv.tm_mday = d;
  tmv.tm_hour = h;
  tmv.tm_min = mi;
  tmv.tm_sec = s;
  t = edr_agent_timegm_utc(&tmv);
  if (t <= 0) {
    return 0;
  }
  return time(NULL) > t ? 1 : 0;
}

#ifdef EDR_HAVE_OPENSSL_HTTP
static int edr_agent_verify_ed25519_signature(const char *public_key_pem,
                                              const unsigned char *payload, size_t payload_len,
                                              const unsigned char *sig, size_t sig_len) {
  BIO *bio = NULL;
  EVP_PKEY *pkey = NULL;
  EVP_MD_CTX *ctx = NULL;
  int ok = 0;
  if (!public_key_pem || !public_key_pem[0] || !payload || !sig || sig_len == 0u) {
    return -1;
  }
  bio = BIO_new_mem_buf(public_key_pem, -1);
  if (!bio) {
    return -1;
  }
  pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
  BIO_free(bio);
  if (!pkey) {
    return -1;
  }
  ctx = EVP_MD_CTX_new();
  if (ctx && EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pkey) == 1 &&
      EVP_DigestVerify(ctx, sig, sig_len, payload, payload_len) == 1) {
    ok = 1;
  }
  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(pkey);
  return ok ? 0 : -1;
}
#endif

static int edr_agent_file_sha256_hex(const char *path, char out65[65]) {
  FILE *fp;
  unsigned char buf[8192];
  EdrSha256Ctx ctx;
  size_t n;
  uint8_t d[EDR_SHA256_DIGEST_LEN];
  static const char *hx = "0123456789abcdef";
  if (!path || !out65) return -1;
  fp = fopen(path, "rb");
  if (!fp) return -1;
  edr_sha256_init(&ctx);
  while ((n = fread(buf, 1u, sizeof(buf), fp)) > 0u) {
    edr_sha256_update(&ctx, buf, n);
  }
  fclose(fp);
  edr_sha256_final(&ctx, d);
  for (int i = 0; i < 32; i++) {
    out65[i * 2] = hx[d[i] >> 4];
    out65[i * 2 + 1] = hx[d[i] & 15];
  }
  out65[64] = '\0';
  return 0;
}

static void edr_agent_config_state_path(const char *queue_db_path, char *out, size_t cap) {
  const char *base = queue_db_path && queue_db_path[0] ? queue_db_path : "edr_queue.db";
  size_t len;
  if (!out || cap == 0u) return;
  snprintf(out, cap, "%s", base);
  len = strlen(out);
  while (len > 0u && out[len - 1u] != '/' && out[len - 1u] != '\\') {
    out[--len] = '\0';
  }
  if (len == 0u) {
    snprintf(out, cap, "agent_config_sequence.state");
  } else {
    snprintf(out + len, cap - len, "agent_config_sequence.state");
  }
}

static long long edr_agent_read_config_sequence_state(const char *queue_db_path) {
  char path[1024];
  FILE *fp;
  long long v = 0;
  edr_agent_config_state_path(queue_db_path, path, sizeof(path));
  fp = fopen(path, "r");
  if (!fp) return 0;
  if (fscanf(fp, "%lld", &v) != 1) v = 0;
  fclose(fp);
  return v;
}

static void edr_agent_write_config_sequence_state(const char *queue_db_path, long long seq) {
  char path[1024];
  FILE *fp;
  if (seq <= 0) return;
  edr_agent_config_state_path(queue_db_path, path, sizeof(path));
  fp = fopen(path, "w");
  if (!fp) return;
  fprintf(fp, "%lld\n", seq);
  fclose(fp);
}

static int edr_agent_verify_config_headers(const EdrConfig *cfg, const char *queue_db_path, const char *tmp,
                                           const EdrAgentConfigHeaders *headers,
                                           char *reason, size_t reason_cap) {
  char actual_hash[65];
  long long seq;
  long long seen;
  const char *trusted_key_id;
#ifdef EDR_HAVE_OPENSSL_HTTP
  const char *public_key_pem;
#endif
  if (reason && reason_cap) reason[0] = '\0';
  if (!headers || !headers->signature[0] || !headers->signed_payload_b64[0] || !headers->sequence[0] || !headers->config_hash[0]) {
    if (edr_agent_config_signature_required(cfg)) {
      snprintf(reason, reason_cap, "missing signed config headers");
      return -1;
    }
    return 0;
  }
  trusted_key_id = edr_agent_config_signing_key_id(cfg);
  if (trusted_key_id && trusted_key_id[0] && strcmp(trusted_key_id, headers->signing_key_id) != 0) {
    snprintf(reason, reason_cap, "untrusted signing key id expected=%s got=%s", trusted_key_id, headers->signing_key_id);
    return -1;
  }
  if (edr_agent_rfc3339_expired(headers->expires_at)) {
    snprintf(reason, reason_cap, "signed config expired at %s", headers->expires_at);
    return -1;
  }
  if (edr_agent_file_sha256_hex(tmp, actual_hash) != 0 || strcmp(actual_hash, headers->config_hash) != 0) {
    snprintf(reason, reason_cap, "config hash mismatch");
    return -1;
  }
  seq = atoll(headers->sequence);
  seen = edr_agent_read_config_sequence_state(queue_db_path);
  if (seq > 0 && seen > 0 && seq < seen) {
    snprintf(reason, reason_cap, "config rollback detected sequence=%lld seen=%lld", seq, seen);
    return -1;
  }
#ifdef EDR_HAVE_OPENSSL_HTTP
  public_key_pem = edr_agent_config_public_key_pem(cfg);
  if (public_key_pem && public_key_pem[0]) {
    unsigned char payload[2048];
    size_t payload_len = 0u;
    unsigned char sig[128];
    size_t sig_len = 0u;
    if (b64url_decode(headers->signed_payload_b64, payload, sizeof(payload), &payload_len) != 0) {
      snprintf(reason, reason_cap, "signed payload decode failed");
      return -1;
    }
    if (b64url_decode(headers->signature, sig, sizeof(sig), &sig_len) != 0) {
      snprintf(reason, reason_cap, "signature decode failed");
      return -1;
    }
    if (edr_agent_verify_ed25519_signature(public_key_pem, payload, payload_len, sig, sig_len) != 0) {
      snprintf(reason, reason_cap, "ed25519 signature mismatch");
      return -1;
    }
    return 0;
  }
  {
    unsigned char payload[2048];
    size_t payload_len = 0u;
    unsigned char mac[EVP_MAX_MD_SIZE];
    unsigned int mac_len = 0u;
    char encoded[192];
    const char *secret = edr_agent_config_signing_secret();
    if (b64url_decode(headers->signed_payload_b64, payload, sizeof(payload), &payload_len) != 0) {
      snprintf(reason, reason_cap, "signed payload decode failed");
      return -1;
    }
    if (!HMAC(EVP_sha256(), secret, (int)strlen(secret), payload, payload_len, mac, &mac_len)) {
      snprintf(reason, reason_cap, "hmac failed");
      return -1;
    }
    b64url_encode(mac, mac_len, encoded, sizeof(encoded));
    if (strcmp(encoded, headers->signature) != 0) {
      snprintf(reason, reason_cap, "signature mismatch");
      return -1;
    }
  }
#else
  if (edr_agent_config_signature_required(cfg)) {
    snprintf(reason, reason_cap, "OpenSSL signature verification unavailable");
    return -1;
  }
#endif
  return 0;
}

static int edr_agent_file_has_magic(const char *path, const char *magic, size_t magic_len) {
  char buf[8];
  FILE *f;
  size_t n;
  if (!path || !path[0] || !magic || magic_len == 0u || magic_len > sizeof(buf)) {
    return 0;
  }
  f = fopen(path, "rb");
  if (!f) {
    return 0;
  }
  n = fread(buf, 1u, magic_len, f);
  fclose(f);
  return n == magic_len && memcmp(buf, magic, magic_len) == 0 ? 1 : 0;
}

static int edr_agent_files_equal(const char *a, const char *b) {
  FILE *fa;
  FILE *fb;
  unsigned char ba[8192];
  unsigned char bb[8192];
  int equal = 0;
  if (!a || !a[0] || !b || !b[0]) {
    return 0;
  }
  fa = fopen(a, "rb");
  if (!fa) {
    return 0;
  }
  fb = fopen(b, "rb");
  if (!fb) {
    fclose(fa);
    return 0;
  }
  equal = 1;
  for (;;) {
    size_t na = fread(ba, 1u, sizeof(ba), fa);
    size_t nb = fread(bb, 1u, sizeof(bb), fb);
    if (na != nb || (na > 0u && memcmp(ba, bb, na) != 0)) {
      equal = 0;
      break;
    }
    if (na == 0u) {
      if (ferror(fa) || ferror(fb)) {
        equal = 0;
      }
      break;
    }
  }
  fclose(fa);
  fclose(fb);
  return equal;
}

static int edr_agent_replace_file(const char *src, const char *dst) {
  if (!src || !src[0] || !dst || !dst[0]) {
    return -1;
  }
#ifdef _WIN32
  if (MoveFileExA(src, dst, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
    return 0;
  }
  return -1;
#else
  return rename(src, dst);
#endif
}

struct EdrAgent {
  EdrEventBus *event_bus;
  char *config_path;
  EdrConfig cfg;
  time_t config_mtime;
  int shutdown;
  int collector_started;
  int config_recovery_active;
  int config_recovery_safe_mode;
  int config_recovery_last_good_used;
  int config_recovery_fields_extracted;
  int config_recovery_auto_repaired;
  char config_recovery_mode[48];
  char config_recovery_reason[256];
  char config_recovery_source[1024];
  char config_recovery_recovered_path[1024];
  char config_recovery_backup_path[1024];
  /** §19.8 周期快照：上次全量定时采集单调时钟（ns） */
  uint64_t asurf_last_post_ns;
  /** §19.6 上次轮询 refresh-request 的时间（ns） */
  uint64_t asurf_last_pending_check_ns;
};

static void edr_agent_clear_config_recovery(EdrAgent *agent) {
  if (!agent) {
    return;
  }
  agent->config_recovery_active = 0;
  agent->config_recovery_safe_mode = 0;
  agent->config_recovery_last_good_used = 0;
  agent->config_recovery_fields_extracted = 0;
  agent->config_recovery_auto_repaired = 0;
  snprintf(agent->config_recovery_mode, sizeof(agent->config_recovery_mode), "%s", "normal");
  agent->config_recovery_reason[0] = '\0';
  agent->config_recovery_source[0] = '\0';
  agent->config_recovery_recovered_path[0] = '\0';
  agent->config_recovery_backup_path[0] = '\0';
}

static void edr_agent_copy_string(char *dst, size_t cap, const char *src) {
  if (!dst || cap == 0u) {
    return;
  }
  snprintf(dst, cap, "%s", src ? src : "");
}

static const char *edr_agent_path_sep_for(const char *path) {
  return (path && strchr(path, '\\')) ? "\\" : "/";
}

static void edr_agent_config_dir(const char *config_path, char *out, size_t cap) {
  const char *last1;
  const char *last2;
  const char *last;
  size_t n;
  if (!out || cap == 0u) {
    return;
  }
  out[0] = '\0';
  if (!config_path || !config_path[0]) {
    snprintf(out, cap, "%s", ".");
    return;
  }
  last1 = strrchr(config_path, '/');
  last2 = strrchr(config_path, '\\');
  last = last1;
  if (last2 && (!last || last2 > last)) {
    last = last2;
  }
  if (!last) {
    snprintf(out, cap, "%s", ".");
    return;
  }
  n = (size_t)(last - config_path);
  if (n == 0u) {
    n = 1u;
  }
  if (n >= cap) {
    n = cap - 1u;
  }
  memcpy(out, config_path, n);
  out[n] = '\0';
}

static void edr_agent_join_path(const char *dir, const char *name, char *out, size_t cap) {
  const char *sep;
  size_t len;
  if (!out || cap == 0u) {
    return;
  }
  if (!dir || !dir[0]) {
    snprintf(out, cap, "%s", name ? name : "");
    return;
  }
  sep = edr_agent_path_sep_for(dir);
  len = strlen(dir);
  if (len > 0u && (dir[len - 1u] == '/' || dir[len - 1u] == '\\')) {
    snprintf(out, cap, "%s%s", dir, name ? name : "");
  } else {
    snprintf(out, cap, "%s%s%s", dir, sep, name ? name : "");
  }
}

static int edr_agent_ensure_dir(const char *path) {
  struct stat st;
  if (!path || !path[0]) {
    return -1;
  }
  if (stat(path, &st) == 0) {
    return 0;
  }
#ifdef _WIN32
  return CreateDirectoryA(path, NULL) ? 0 : -1;
#else
  return mkdir(path, 0700);
#endif
}

static void edr_agent_state_file_path(const char *config_path, const char *name, char *out, size_t cap) {
  char dir[1024];
  char state_dir[1024];
  edr_agent_config_dir(config_path, dir, sizeof(dir));
  edr_agent_join_path(dir, "state", state_dir, sizeof(state_dir));
  (void)edr_agent_ensure_dir(state_dir);
  edr_agent_join_path(state_dir, name, out, cap);
}

static void edr_agent_neighbor_file_path(const char *config_path, const char *suffix, char *out, size_t cap) {
  if (!out || cap == 0u) {
    return;
  }
  if (!config_path || !config_path[0]) {
    snprintf(out, cap, "%s", suffix ? suffix : "");
    return;
  }
  snprintf(out, cap, "%s%s", config_path, suffix ? suffix : "");
}

static int edr_agent_copy_file(const char *src, const char *dst) {
  FILE *in;
  FILE *out;
  unsigned char buf[8192];
  if (!src || !src[0] || !dst || !dst[0]) {
    return -1;
  }
  in = fopen(src, "rb");
  if (!in) {
    return -1;
  }
  out = fopen(dst, "wb");
  if (!out) {
    fclose(in);
    return -1;
  }
  for (;;) {
    size_t n = fread(buf, 1u, sizeof(buf), in);
    if (n > 0u && fwrite(buf, 1u, n, out) != n) {
      fclose(in);
      fclose(out);
      return -1;
    }
    if (n < sizeof(buf)) {
      if (ferror(in)) {
        fclose(in);
        fclose(out);
        return -1;
      }
      break;
    }
  }
  fclose(in);
  fclose(out);
  return 0;
}

static void edr_agent_toml_escape(const char *in, char *out, size_t cap) {
  size_t o = 0u;
  if (!out || cap == 0u) {
    return;
  }
  if (!in) {
    out[0] = '\0';
    return;
  }
  for (const unsigned char *p = (const unsigned char *)in; *p && o + 1u < cap; p++) {
    if (*p == '\\' || *p == '"') {
      if (o + 2u >= cap) {
        break;
      }
      out[o++] = '\\';
      out[o++] = (char)*p;
    } else if (*p == '\r' || *p == '\n') {
      if (o + 2u >= cap) {
        break;
      }
      out[o++] = '\\';
      out[o++] = 'n';
    } else {
      out[o++] = (char)*p;
    }
  }
  out[o] = '\0';
}

static void edr_agent_write_toml_string(FILE *fp, const char *key, const char *value) {
  char esc[2048];
  edr_agent_toml_escape(value, esc, sizeof(esc));
  fprintf(fp, "%s = \"%s\"\n", key, esc);
}

static int edr_agent_write_config_snapshot(const char *path, const EdrConfig *cfg) {
  char tmp_path[1100];
  FILE *fp;
  EdrConfig check;
  EdrError ce;
  if (!path || !path[0] || !cfg) {
    return -1;
  }
  snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", path);
  fp = fopen(tmp_path, "wb");
  if (!fp) {
    return -1;
  }
  fprintf(fp, "# Generated by FDSensor config recovery. Do not edit while Agent is running.\n");
  fprintf(fp, "\n[server]\n");
  edr_agent_write_toml_string(fp, "address", cfg->server.address);
  fprintf(fp, "grpc_enabled = %s\n", cfg->server.grpc_enabled ? "true" : "false");
  fprintf(fp, "grpc_insecure = %s\n", cfg->server.grpc_insecure ? "true" : "false");
  edr_agent_write_toml_string(fp, "ca_cert", cfg->server.ca_cert);
  edr_agent_write_toml_string(fp, "client_cert", cfg->server.client_cert);
  edr_agent_write_toml_string(fp, "client_key", cfg->server.client_key);
  edr_agent_write_toml_string(fp, "client_key_provider", cfg->server.client_key_provider);
  fprintf(fp, "\n[agent]\n");
  edr_agent_write_toml_string(fp, "endpoint_id", cfg->agent.endpoint_id);
  edr_agent_write_toml_string(fp, "tenant_id", cfg->agent.tenant_id);
  fprintf(fp, "\n[platform]\n");
  edr_agent_write_toml_string(fp, "rest_base_url", cfg->platform.rest_base_url);
  edr_agent_write_toml_string(fp, "relay_url", cfg->platform.relay_url);
  edr_agent_write_toml_string(fp, "proxy_mode", cfg->platform.proxy_mode);
  edr_agent_write_toml_string(fp, "proxy_url", cfg->platform.proxy_url);
  edr_agent_write_toml_string(fp, "rest_bearer_token", cfg->platform.rest_bearer_token);
  fprintf(fp, "http2_enabled = %s\n", cfg->platform.http2_enabled ? "true" : "false");
  fprintf(fp, "control_stream_enabled = %s\n", cfg->platform.control_stream_enabled ? "true" : "false");
  fprintf(fp, "long_poll_fallback = %s\n", cfg->platform.long_poll_fallback ? "true" : "false");
  fprintf(fp, "report_events_v2_enabled = %s\n", cfg->platform.report_events_v2_enabled ? "true" : "false");
  fprintf(fp, "\n[collection]\n");
  fprintf(fp, "etw_enabled = %s\n", cfg->collection.etw_enabled ? "true" : "false");
  fprintf(fp, "etw_powershell_provider = %s\n", cfg->collection.etw_powershell_provider ? "true" : "false");
  fprintf(fp, "etw_amsi_provider = %s\n", cfg->collection.etw_amsi_provider ? "true" : "false");
  fprintf(fp, "etw_security_audit_provider = %s\n", cfg->collection.etw_security_audit_provider ? "true" : "false");
  fprintf(fp, "max_event_queue_size = %u\n", cfg->collection.max_event_queue_size);
  fprintf(fp, "adaptive_enabled = %s\n", cfg->collection.adaptive_enabled ? "true" : "false");
  fprintf(fp, "\n[offline]\n");
  edr_agent_write_toml_string(fp, "queue_db_path", cfg->offline.queue_db_path);
  edr_agent_write_toml_string(fp, "evidence_cache_path", cfg->offline.evidence_cache_path);
  fprintf(fp, "max_queue_size_mb = %u\n", cfg->offline.max_queue_size_mb);
  fprintf(fp, "evidence_cache_max_size_mb = %u\n", cfg->offline.evidence_cache_max_size_mb);
  fprintf(fp, "\n[resource_limit]\n");
  fprintf(fp, "cpu_limit_percent = %u\n", cfg->resource_limit.cpu_limit_percent);
  fprintf(fp, "memory_limit_mb = %u\n", cfg->resource_limit.memory_limit_mb);
  fprintf(fp, "behavior_infer_per_min = %u\n", cfg->resource_limit.behavior_infer_per_min);
  fprintf(fp, "pmfe_scans_per_min = %u\n", cfg->resource_limit.pmfe_scans_per_min);
  fprintf(fp, "\n[health_monitor]\n");
  fprintf(fp, "enabled = %s\n", cfg->health_monitor.enabled ? "true" : "false");
  edr_agent_write_toml_string(fp, "profile", cfg->health_monitor.profile);
  fprintf(fp, "interval_s = %u\n", cfg->health_monitor.interval_s);
  fprintf(fp, "expires_at_unix_ms = %llu\n", (unsigned long long)cfg->health_monitor.expires_at_unix_ms);
  edr_agent_write_toml_string(fp, "request_id", cfg->health_monitor.request_id);
  fprintf(fp, "\n[command]\n");
  fprintf(fp, "allow_dangerous = %s\n", cfg->command.allow_dangerous ? "true" : "false");
  fprintf(fp, "allow_rtq_readonly = %s\n", cfg->command.allow_rtq_readonly ? "true" : "false");
  edr_agent_write_toml_string(fp, "signing_public_key_path", cfg->command.signing_public_key_path);
  fprintf(fp, "\n[ave]\n");
  fprintf(fp, "enabled = %s\n", cfg->ave.enabled ? "true" : "false");
  edr_agent_write_toml_string(fp, "model_dir", cfg->ave.model_dir);
  fprintf(fp, "static_model_enabled = %s\n", cfg->ave.static_model_enabled ? "true" : "false");
  fprintf(fp, "behavior_monitor_enabled = %s\n", cfg->ave.behavior_monitor_enabled ? "true" : "false");
  fprintf(fp, "\n[attack_surface]\n");
  fprintf(fp, "enabled = %s\n", cfg->attack_surface.enabled ? "true" : "false");
  fprintf(fp, "\n[shellcode_detector]\n");
  fprintf(fp, "enabled = %s\n", cfg->shellcode_detector.enabled ? "true" : "false");
  fprintf(fp, "\n[webshell_detector]\n");
  fprintf(fp, "enabled = %s\n", cfg->webshell_detector.enabled ? "true" : "false");
  fprintf(fp, "\n[fl]\n");
  fprintf(fp, "enabled = %s\n", cfg->fl.enabled ? "true" : "false");
  fclose(fp);

  memset(&check, 0, sizeof(check));
  ce = edr_config_load(tmp_path, &check);
  edr_config_free_heap(&check);
  if (ce != EDR_OK) {
    (void)remove(tmp_path);
    return -1;
  }
  return edr_agent_replace_file(tmp_path, path);
}

static void edr_agent_apply_config_recovery_safe_mode(EdrConfig *cfg) {
  if (!cfg) {
    return;
  }
  cfg->collection.etw_enabled = false;
  cfg->collection.etw_dns_client_provider = false;
  cfg->collection.etw_powershell_provider = false;
  cfg->collection.etw_amsi_provider = false;
  cfg->collection.etw_schannel_provider = false;
  cfg->collection.etw_security_audit_provider = false;
  cfg->collection.etw_wmi_provider = false;
  cfg->collection.etw_tcpip_provider = false;
  cfg->collection.etw_firewall_provider = false;
  cfg->collection.ebpf_enabled = false;
  cfg->collection.auditd_enabled = false;
  cfg->collection.max_event_queue_size = 512u;
  cfg->collection.adaptive_enabled = false;
  cfg->ave.enabled = false;
  cfg->ave.static_model_enabled = false;
  cfg->ave.behavior_monitor_enabled = false;
  cfg->command.allow_dangerous = false;
  cfg->command.allow_rtq_readonly = true;
  cfg->forensic_auto.enabled = false;
  cfg->attack_surface.enabled = false;
  cfg->shellcode_detector.enabled = false;
  cfg->webshell_detector.enabled = false;
  cfg->fl.enabled = false;
  cfg->resource_limit.cpu_limit_percent = 1u;
  cfg->resource_limit.memory_limit_mb = 100u;
  cfg->resource_limit.ave_infer_per_min = 0u;
  cfg->resource_limit.behavior_infer_per_min = 0u;
  cfg->resource_limit.pmfe_scans_per_min = 0u;
  cfg->resource_limit.webshell_scan_mb_per_min = 0u;
  cfg->resource_limit.shellcode_packets_per_sec = 0u;
  cfg->health_monitor.enabled = true;
  snprintf(cfg->health_monitor.profile, sizeof(cfg->health_monitor.profile), "%s", "basic");
  cfg->health_monitor.interval_s = 60u;
  cfg->health_monitor.expires_at_unix_ms = 0u;
  snprintf(cfg->health_monitor.request_id, sizeof(cfg->health_monitor.request_id), "%s", "config-recovery");
}

static char *edr_agent_trim(char *s) {
  char *e;
  if (!s) {
    return s;
  }
  while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n') {
    s++;
  }
  e = s + strlen(s);
  while (e > s && (e[-1] == ' ' || e[-1] == '\t' || e[-1] == '\r' || e[-1] == '\n')) {
    *--e = '\0';
  }
  return s;
}

static void edr_agent_strip_toml_value(char *raw, char *out, size_t cap) {
  char *p;
  size_t o = 0u;
  if (!out || cap == 0u) {
    return;
  }
  out[0] = '\0';
  p = edr_agent_trim(raw);
  if (!p || !p[0]) {
    return;
  }
  if (*p == '"') {
    p++;
    while (*p && o + 1u < cap) {
      if (*p == '"' && (p == raw || p[-1] != '\\')) {
        break;
      }
      if (*p == '\\' && p[1]) {
        p++;
      }
      out[o++] = *p++;
    }
    out[o] = '\0';
    return;
  }
  while (*p && *p != '#' && o + 1u < cap) {
    out[o++] = *p++;
  }
  out[o] = '\0';
  p = edr_agent_trim(out);
  if (p != out) {
    memmove(out, p, strlen(p) + 1u);
  }
}

static int edr_agent_parse_bool_value(const char *v, bool *out) {
  if (!v || !out) {
    return 0;
  }
  if (strcmp(v, "true") == 0 || strcmp(v, "1") == 0 || strcmp(v, "yes") == 0) {
    *out = true;
    return 1;
  }
  if (strcmp(v, "false") == 0 || strcmp(v, "0") == 0 || strcmp(v, "no") == 0) {
    *out = false;
    return 1;
  }
  return 0;
}

static int edr_agent_extract_scalar_from_broken_toml(const char *path, EdrConfig *cfg) {
  FILE *fp;
  char line[4096];
  char section[64] = "";
  int count = 0;
  if (!path || !path[0] || !cfg) {
    return 0;
  }
  fp = fopen(path, "r");
  if (!fp) {
    return 0;
  }
  while (fgets(line, sizeof(line), fp)) {
    char *p = edr_agent_trim(line);
    char *eq;
    char key[128];
    char val[2048];
    size_t key_len;
    if (!p || !p[0] || *p == '#') {
      continue;
    }
    if (*p == '[' && p[1] != '[') {
      char *end = strchr(p, ']');
      if (end) {
        size_t n = (size_t)(end - p - 1);
        if (n >= sizeof(section)) {
          n = sizeof(section) - 1u;
        }
        memcpy(section, p + 1, n);
        section[n] = '\0';
      }
      continue;
    }
    eq = strchr(p, '=');
    if (!eq) {
      continue;
    }
    key_len = (size_t)(eq - p);
    while (key_len > 0u && (p[key_len - 1u] == ' ' || p[key_len - 1u] == '\t')) {
      key_len--;
    }
    if (key_len == 0u || key_len >= sizeof(key)) {
      continue;
    }
    memcpy(key, p, key_len);
    key[key_len] = '\0';
    edr_agent_strip_toml_value(eq + 1, val, sizeof(val));
    if (!val[0]) {
      continue;
    }
#define EDR_REC_STR(sec, name, dst)                         \
    if (strcmp(section, (sec)) == 0 && strcmp(key, (name)) == 0) { \
      edr_agent_copy_string((dst), sizeof(dst), val);       \
      count++;                                              \
      continue;                                             \
    }
    EDR_REC_STR("server", "address", cfg->server.address)
    EDR_REC_STR("server", "ca_cert", cfg->server.ca_cert)
    EDR_REC_STR("server", "client_cert", cfg->server.client_cert)
    EDR_REC_STR("server", "client_key", cfg->server.client_key)
    EDR_REC_STR("server", "client_key_provider", cfg->server.client_key_provider)
    EDR_REC_STR("agent", "endpoint_id", cfg->agent.endpoint_id)
    EDR_REC_STR("agent", "tenant_id", cfg->agent.tenant_id)
    EDR_REC_STR("platform", "rest_base_url", cfg->platform.rest_base_url)
    EDR_REC_STR("platform", "relay_url", cfg->platform.relay_url)
    EDR_REC_STR("platform", "proxy_mode", cfg->platform.proxy_mode)
    EDR_REC_STR("platform", "proxy_url", cfg->platform.proxy_url)
    EDR_REC_STR("platform", "rest_bearer_token", cfg->platform.rest_bearer_token)
    EDR_REC_STR("offline", "queue_db_path", cfg->offline.queue_db_path)
    EDR_REC_STR("offline", "evidence_cache_path", cfg->offline.evidence_cache_path)
    EDR_REC_STR("logging", "log_dir", cfg->logging.log_dir)
    EDR_REC_STR("command", "signing_public_key_path", cfg->command.signing_public_key_path)
#undef EDR_REC_STR
    if (strcmp(section, "server") == 0 && strcmp(key, "grpc_enabled") == 0) {
      if (edr_agent_parse_bool_value(val, &cfg->server.grpc_enabled)) count++;
    } else if (strcmp(section, "server") == 0 && strcmp(key, "grpc_insecure") == 0) {
      if (edr_agent_parse_bool_value(val, &cfg->server.grpc_insecure)) count++;
    } else if (strcmp(section, "health_monitor") == 0 && strcmp(key, "enabled") == 0) {
      if (edr_agent_parse_bool_value(val, &cfg->health_monitor.enabled)) count++;
    } else if (strcmp(section, "health_monitor") == 0 && strcmp(key, "profile") == 0) {
      edr_agent_copy_string(cfg->health_monitor.profile, sizeof(cfg->health_monitor.profile), val);
      count++;
    } else if (strcmp(section, "health_monitor") == 0 && strcmp(key, "interval_s") == 0) {
      long v = atol(val);
      if (v >= 30 && v <= 3600) {
        cfg->health_monitor.interval_s = (uint32_t)v;
        count++;
      }
    }
  }
  fclose(fp);
  return count;
}

static int edr_agent_save_last_good_config(EdrAgent *agent, const char *source_path) {
  char lkg[1100];
  if (!agent || !source_path || !source_path[0]) {
    return -1;
  }
  edr_agent_state_file_path(source_path, "last_good_agent.toml", lkg, sizeof(lkg));
  return edr_agent_copy_file(source_path, lkg);
}

static int edr_agent_save_last_good_snapshot(EdrAgent *agent) {
  char lkg[1100];
  const char *base;
  if (!agent) {
    return -1;
  }
  base = agent->config_path && agent->config_path[0] ? agent->config_path : "agent.toml";
  edr_agent_state_file_path(base, "last_good_agent.toml", lkg, sizeof(lkg));
  return edr_agent_write_config_snapshot(lkg, &agent->cfg);
}

static EdrError edr_agent_try_last_good_config(EdrAgent *agent, const char *load_path, const char *reason) {
  char lkg[1100];
  EdrError ce;
  if (!agent || !load_path || !load_path[0]) {
    return EDR_ERR_CONFIG_PARSE;
  }
  edr_agent_state_file_path(load_path, "last_good_agent.toml", lkg, sizeof(lkg));
  ce = edr_config_load(lkg, &agent->cfg);
  if (ce != EDR_OK) {
    return ce;
  }
  agent->config_recovery_active = 1;
  agent->config_recovery_safe_mode = 0;
  agent->config_recovery_last_good_used = 1;
  agent->config_recovery_auto_repaired = 0;
  snprintf(agent->config_recovery_mode, sizeof(agent->config_recovery_mode), "%s", "last_good");
  edr_agent_copy_string(agent->config_recovery_reason, sizeof(agent->config_recovery_reason), reason);
  edr_agent_copy_string(agent->config_recovery_source, sizeof(agent->config_recovery_source), lkg);
  fprintf(stderr, "[config] strict load failed; using last-known-good config: %s\n", lkg);
  return EDR_OK;
}

static EdrError edr_agent_recover_config(EdrAgent *agent, const char *load_path, EdrError strict_error) {
  char reason[256];
  char recovered[1100];
  char backup[1100];
  int fields;
  snprintf(reason, sizeof(reason), "strict TOML load failed: %d", (int)strict_error);
  if (!agent) {
    return EDR_ERR_INVALID_ARG;
  }
  if (edr_agent_try_last_good_config(agent, load_path, reason) == EDR_OK) {
    return EDR_OK;
  }
  (void)edr_config_load(NULL, &agent->cfg);
  edr_agent_apply_config_recovery_safe_mode(&agent->cfg);
  fields = edr_agent_extract_scalar_from_broken_toml(load_path, &agent->cfg);
  if (agent->cfg.health_monitor.interval_s < 30u) {
    agent->cfg.health_monitor.interval_s = 60u;
  }
  agent->cfg.health_monitor.enabled = true;
  agent->config_recovery_active = 1;
  agent->config_recovery_safe_mode = 1;
  agent->config_recovery_last_good_used = 0;
  agent->config_recovery_fields_extracted = fields;
  snprintf(agent->config_recovery_mode, sizeof(agent->config_recovery_mode), "%s",
           fields > 0 ? "safe_extracted" : "safe_defaults");
  edr_agent_copy_string(agent->config_recovery_reason, sizeof(agent->config_recovery_reason), reason);
  edr_agent_copy_string(agent->config_recovery_source, sizeof(agent->config_recovery_source),
                        load_path ? load_path : "");
  if (load_path && load_path[0]) {
    char invalid_suffix[80];
    edr_agent_neighbor_file_path(load_path, ".recovered", recovered, sizeof(recovered));
    if (edr_agent_write_config_snapshot(recovered, &agent->cfg) == 0) {
      agent->config_recovery_auto_repaired = 1;
      edr_agent_copy_string(agent->config_recovery_recovered_path,
                            sizeof(agent->config_recovery_recovered_path), recovered);
    }
    snprintf(invalid_suffix, sizeof(invalid_suffix), ".invalid.%llu",
             (unsigned long long)time(NULL));
    edr_agent_neighbor_file_path(load_path, invalid_suffix, backup, sizeof(backup));
    if (edr_agent_copy_file(load_path, backup) == 0) {
      edr_agent_copy_string(agent->config_recovery_backup_path,
                            sizeof(agent->config_recovery_backup_path), backup);
    }
  }
  fprintf(stderr,
          "[config] strict load failed; recovery mode=%s extracted_fields=%d recovered=%s\n",
          agent->config_recovery_mode, fields,
          agent->config_recovery_recovered_path[0] ? agent->config_recovery_recovered_path : "-");
  return EDR_OK;
}

static void AVE_CALL edr_agent_on_behavior_alert(const AVEBehaviorAlert *alert, void *user_data) {
  (void)user_data;
  edr_behavior_alert_emit_to_batch(alert);
}

static void edr_agent_register_ave_behavior_callbacks(EdrAgent *agent) {
  if (!agent || !agent->cfg.ave.behavior_monitor_enabled) {
    AVEStatus st;
    memset(&st, 0, sizeof(st));
    (void)AVE_GetStatus(&st);
    fprintf(stderr,
            "[ave] behavior_monitor=0 static_model=%s behavior_model=%s l4_th=%.2f\n",
            st.static_model_version,
            st.behavior_model_version,
            agent ? (double)agent->cfg.ave.l4_realtime_anomaly_threshold : 0.0);
    return;
  }
  AVECallbacks callbacks;
  memset(&callbacks, 0, sizeof(callbacks));
  callbacks.on_behavior_alert = edr_agent_on_behavior_alert;
  callbacks.user_data = agent;

  int cr = AVE_RegisterCallbacks(&callbacks);
  if (cr != AVE_OK) {
    fprintf(stderr, "[ave] AVE_RegisterCallbacks failed: %d\n", cr);
    return;
  }
  int mr = AVE_StartBehaviorMonitor();
  if (mr != AVE_OK) {
    fprintf(stderr, "[ave] AVE_StartBehaviorMonitor failed: %d\n", mr);
  }
  AVEStatus st;
  memset(&st, 0, sizeof(st));
  (void)AVE_GetStatus(&st);
  fprintf(stderr,
          "[ave] on_behavior_alert=1 behavior_monitor=%d model_dir=%s "
          "static_model=%s behavior_model=%s l4_th=%.2f\n",
          st.behavior_monitor_running ? 1 : 0,
          agent ? agent->cfg.ave.model_dir : "",
          st.static_model_version,
          st.behavior_model_version,
          agent ? (double)agent->cfg.ave.l4_realtime_anomaly_threshold : 0.0);
}

static void edr_agent_apply_event_filter_config(const EdrConfig *cfg) {
  EdrWindowsEventFilterConfig fc;
  memset(&fc, 0, sizeof(fc));
  if (!cfg) {
    edr_windows_event_policy_configure(NULL);
    return;
  }
  fc.enabled = cfg->event_filter.enabled ? 1u : 0u;
  fc.agent_internal_forensic = cfg->event_filter.agent_internal_forensic ? 1u : 0u;
  fc.low_value_file_process = cfg->event_filter.low_value_file_process ? 1u : 0u;
  fc.low_value_file_suffix = cfg->event_filter.low_value_file_suffix ? 1u : 0u;
  fc.temp_xml = cfg->event_filter.temp_xml ? 1u : 0u;
  snprintf(fc.version, sizeof(fc.version), "%s", cfg->event_filter.version);
  edr_windows_event_policy_configure(&fc);
}

EdrAgent *edr_agent_create(void) {
  return (EdrAgent *)calloc(1, sizeof(EdrAgent));
}

void edr_agent_destroy(EdrAgent *agent) {
  if (!agent) {
    return;
  }
  edr_preprocess_stop();
  edr_self_protect_shutdown();
  edr_resource_shutdown();
#if defined(EDR_WITH_FL_TRAINER)
  FLT_Shutdown();
#endif
  AVE_Shutdown();
  edr_event_bus_destroy(agent->event_bus);
  edr_config_free_heap(&agent->cfg);
  free(agent->config_path);
  free(agent);
}

EdrError edr_agent_init(EdrAgent *agent, const char *config_path) {
  if (!agent) {
    return EDR_ERR_INVALID_ARG;
  }
  if (config_path && config_path[0]) {
    agent->config_path = EDR_AGENT_STRDUP(config_path);
    if (!agent->config_path) {
      return EDR_ERR_INTERNAL;
    }
  }
  {
    const char *load_path =
        (config_path && config_path[0]) ? config_path : NULL;
    EdrError ce = edr_config_load(load_path, &agent->cfg);
    if (ce != EDR_OK) {
      EdrError re = edr_agent_recover_config(agent, load_path, ce);
      if (re != EDR_OK) {
        return ce;
      }
    } else {
      edr_agent_clear_config_recovery(agent);
      (void)edr_agent_save_last_good_config(agent, load_path);
    }
    agent->config_mtime = (time_t)0;
    if (load_path) {
      struct stat st;
      if (stat(load_path, &st) == 0) {
        agent->config_mtime = st.st_mtime;
      }
      char fp[80];
      edr_config_fingerprint(load_path, fp, sizeof(fp));
      if (fp[0]) {
        fprintf(stderr, "[config] fingerprint=%s path=%s\n", fp, load_path);
      }
    }
  }
  edr_self_protect_init();
  edr_adaptive_collection_configure(&agent->cfg);
  edr_agent_apply_event_filter_config(&agent->cfg);
  edr_resource_init(&agent->cfg);
  {
    int ar = AVE_InitFromEdrConfig(&agent->cfg);
    if (ar != AVE_OK) {
      fprintf(stderr, "[ave] AVE_InitFromEdrConfig failed: %d\n", ar);
    } else {
      edr_agent_register_ave_behavior_callbacks(agent);
    }
  }
#if defined(EDR_WITH_FL_TRAINER)
  if (agent->cfg.fl.enabled) {
    int fr = FLT_InitFromEdrConfig(&agent->cfg);
    if (fr != FLT_OK) {
      fprintf(stderr, "[fl] FLT_InitFromEdrConfig failed: %d\n", fr);
    } else {
      fr = FLT_Start();
      if (fr != FLT_OK) {
        fprintf(stderr, "[fl] FLT_Start failed: %d\n", fr);
        FLT_Shutdown();
      }
    }
  }
#endif
  agent->event_bus =
      edr_event_bus_create(agent->cfg.collection.max_event_queue_size);
  if (!agent->event_bus) {
#if defined(EDR_WITH_FL_TRAINER)
    FLT_Shutdown();
#endif
    AVE_Shutdown();
    edr_resource_shutdown();
    edr_self_protect_shutdown();
    return EDR_ERR_INTERNAL;
  }
  edr_self_protect_apply_config(&agent->cfg);
  edr_self_protect_set_event_bus(agent->event_bus);
  return EDR_OK;
}

static void edr_agent_poll_config_reload(EdrAgent *agent, uint64_t *last_reload_ns);
static void edr_agent_poll_remote_config(EdrAgent *agent, uint64_t *last_remote_ns);
static void edr_agent_poll_p0_bundle(EdrAgent *agent, uint64_t *last_p0_bundle_ns);
static void edr_agent_poll_sensor_interest(EdrAgent *agent, uint64_t *last_sensor_interest_ns);
static void edr_agent_poll_attack_surface(EdrAgent *agent);
static void edr_agent_poll_heartbeat(uint64_t *last_heartbeat_ns);
static void edr_agent_poll_engine_health(EdrAgent *agent, uint64_t *last_health_ns);

static int edr_agent_collection_enabled(const EdrConfig *cfg) {
  if (!cfg) {
    return 0;
  }
  return cfg->collection.etw_enabled || cfg->collection.ebpf_enabled || cfg->collection.auditd_enabled;
}

EdrError edr_agent_run(EdrAgent *agent) {
  if (!agent || !agent->event_bus) {
    return EDR_ERR_INVALID_ARG;
  }
#ifdef _WIN32
  s_agent_main_thread_id = (uint32_t)GetCurrentThreadId();
#endif
  {
    EdrError pe = edr_preprocess_start(agent->event_bus, &agent->cfg);
    if (pe != EDR_OK) {
      return pe;
    }
  }
  {
    uint64_t last_reload_ns = 0;
    uint64_t last_remote_ns = 0;
    uint64_t last_p0_bundle_ns = 0;
    uint64_t last_sensor_interest_ns = 0;
    uint64_t last_heartbeat_ns = 0;
    uint64_t last_health_ns = 0;
    {
      EdrError e = edr_collector_start(agent->event_bus, edr_agent_get_config(agent));
      if (e != EDR_OK) {
        fprintf(stderr, "[collector] start failed: %d; continuing in degraded mode\n", (int)e);
      } else if (edr_agent_collection_enabled(&agent->cfg)) {
        agent->collector_started = 1;
      }
      if (agent->cfg.attack_surface.enabled && agent->cfg.agent.endpoint_id[0] &&
          strcmp(agent->cfg.agent.endpoint_id, "auto") != 0) {
        char d[256];
        int sr = edr_attack_surface_execute("agent_start", &agent->cfg, d, sizeof(d));
        if (sr != 0) {
          fprintf(stderr, "[attack_surface] startup snapshot failed: %s\n", d);
        } else if (strncmp(d, "uploaded_", 9) == 0) {
          fprintf(stderr, "[attack_surface] startup %s\n", d);
        }
      }
      {
        uint64_t t0 = edr_monotonic_ns();
        agent->asurf_last_post_ns = t0;
        agent->asurf_last_pending_check_ns = t0;
      }
      while (!agent->shutdown) {
        uint64_t edr_loop_started_ns = edr_agent_loop_probe_begin();
        edr_ms_sleep(200u);
        EDR_AGENT_TIMED_POLL(EDR_AGENT_POLL_RESOURCE, edr_resource_poll());
        EDR_AGENT_TIMED_POLL(EDR_AGENT_POLL_SELF_PROTECT, edr_self_protect_poll());
        EDR_AGENT_TIMED_POLL(EDR_AGENT_POLL_CONFIG_RELOAD,
                             edr_agent_poll_config_reload(agent, &last_reload_ns));
        EDR_AGENT_TIMED_POLL(EDR_AGENT_POLL_REMOTE_CONFIG,
                             edr_agent_poll_remote_config(agent, &last_remote_ns));
        EDR_AGENT_TIMED_POLL(EDR_AGENT_POLL_P0_BUNDLE,
                             edr_agent_poll_p0_bundle(agent, &last_p0_bundle_ns));
        EDR_AGENT_TIMED_POLL(EDR_AGENT_POLL_SENSOR_INTEREST,
                             edr_agent_poll_sensor_interest(agent, &last_sensor_interest_ns));
        EDR_AGENT_TIMED_POLL(EDR_AGENT_POLL_ATTACK_SURFACE, edr_agent_poll_attack_surface(agent));
        edr_agent_poll_heartbeat(&last_heartbeat_ns);
        EDR_AGENT_TIMED_POLL(EDR_AGENT_POLL_ENGINE_HEALTH,
                             edr_agent_poll_engine_health(agent, &last_health_ns));
        EDR_AGENT_TIMED_POLL(EDR_AGENT_POLL_SHELL_SESSION, edr_shell_session_poll());
        EDR_AGENT_TIMED_POLL(EDR_AGENT_POLL_COMMAND_DELIVERY, edr_command_poll_reliable_delivery());
        edr_agent_loop_probe_end(edr_loop_started_ns);
      }
      if (agent->collector_started) {
        edr_collector_stop();
        agent->collector_started = 0;
      }
    }
  }
  edr_preprocess_stop();
  return EDR_OK;
}

static void json_escape_small(const char *in, char *out, size_t cap) {
  size_t o = 0;
  if (!out || cap == 0u) {
    return;
  }
  out[0] = '\0';
  if (!in) {
    return;
  }
  for (size_t i = 0; in[i] && o + 2u < cap; i++) {
    unsigned char c = (unsigned char)in[i];
    if (c == '"' || c == '\\') {
      if (o + 3u >= cap) {
        break;
      }
      out[o++] = '\\';
      out[o++] = (char)c;
    } else if (c >= 0x20u && c < 0x7fu) {
      out[o++] = (char)c;
    }
  }
  out[o] = '\0';
}

static void edr_agent_config_recovery_json(const EdrAgent *agent, char *out, size_t cap) {
  char mode[80];
  char reason[320];
  char source[1200];
  char recovered[1200];
  char backup[1200];
  if (!out || cap == 0u) {
    return;
  }
  if (!agent) {
    snprintf(out, cap, "{\"active\":false}");
    return;
  }
  json_escape_small(agent->config_recovery_mode, mode, sizeof(mode));
  json_escape_small(agent->config_recovery_reason, reason, sizeof(reason));
  json_escape_small(agent->config_recovery_source, source, sizeof(source));
  json_escape_small(agent->config_recovery_recovered_path, recovered, sizeof(recovered));
  json_escape_small(agent->config_recovery_backup_path, backup, sizeof(backup));
  snprintf(out, cap,
           "{\"active\":%s,\"safe_mode\":%s,\"mode\":\"%s\",\"source\":\"%s\","
           "\"reason\":\"%s\",\"last_good_used\":%s,\"fields_extracted\":%d,"
           "\"recovered_path\":\"%s\",\"backup_path\":\"%s\",\"auto_repaired\":%s}",
           agent->config_recovery_active ? "true" : "false",
           agent->config_recovery_safe_mode ? "true" : "false",
           mode[0] ? mode : "normal", source, reason,
           agent->config_recovery_last_good_used ? "true" : "false",
           agent->config_recovery_fields_extracted,
           recovered, backup,
           agent->config_recovery_auto_repaired ? "true" : "false");
}

static void edr_agent_poll_heartbeat(uint64_t *last_heartbeat_ns) {
  int interval = 60;
  const char *iv;
  uint64_t now;
  if (!last_heartbeat_ns || !edr_ingest_http_configured()) {
    return;
  }
  iv = getenv("EDR_AGENT_HEARTBEAT_INTERVAL_S");
  if (iv && iv[0]) {
    int v = atoi(iv);
    if (v >= 30 && v <= 600) {
      interval = v;
    }
  }
  now = edr_monotonic_ns();
  if (now - *last_heartbeat_ns < (uint64_t)interval * 1000000000ULL) {
    return;
  }
  *last_heartbeat_ns = now;
  (void)edr_ingest_http_post_heartbeat();
}

static void edr_agent_poll_probe_json(char *out, size_t cap) {
  if (!out || cap == 0u) {
    return;
  }
  snprintf(
      out, cap,
      "\"poll_latency_us\":{\"resource\":%llu,\"self_protect\":%llu,"
      "\"config_reload\":%llu,\"remote_config\":%llu,\"p0_bundle\":%llu,"
      "\"sensor_interest\":%llu,\"attack_surface\":%llu,\"engine_health\":%llu,"
      "\"shell_session\":%llu,\"command_delivery\":%llu},"
      "\"poll_latency_max_us\":{\"resource\":%llu,\"self_protect\":%llu,"
      "\"config_reload\":%llu,\"remote_config\":%llu,\"p0_bundle\":%llu,"
      "\"sensor_interest\":%llu,\"attack_surface\":%llu,\"engine_health\":%llu,"
      "\"shell_session\":%llu,\"command_delivery\":%llu},"
      "\"poll_calls\":{\"resource\":%llu,\"self_protect\":%llu,"
      "\"config_reload\":%llu,\"remote_config\":%llu,\"p0_bundle\":%llu,"
      "\"sensor_interest\":%llu,\"attack_surface\":%llu,\"engine_health\":%llu,"
      "\"shell_session\":%llu,\"command_delivery\":%llu},",
      (unsigned long long)s_agent_poll_probe[EDR_AGENT_POLL_RESOURCE].last_us,
      (unsigned long long)s_agent_poll_probe[EDR_AGENT_POLL_SELF_PROTECT].last_us,
      (unsigned long long)s_agent_poll_probe[EDR_AGENT_POLL_CONFIG_RELOAD].last_us,
      (unsigned long long)s_agent_poll_probe[EDR_AGENT_POLL_REMOTE_CONFIG].last_us,
      (unsigned long long)s_agent_poll_probe[EDR_AGENT_POLL_P0_BUNDLE].last_us,
      (unsigned long long)s_agent_poll_probe[EDR_AGENT_POLL_SENSOR_INTEREST].last_us,
      (unsigned long long)s_agent_poll_probe[EDR_AGENT_POLL_ATTACK_SURFACE].last_us,
      (unsigned long long)s_agent_poll_probe[EDR_AGENT_POLL_ENGINE_HEALTH].last_us,
      (unsigned long long)s_agent_poll_probe[EDR_AGENT_POLL_SHELL_SESSION].last_us,
      (unsigned long long)s_agent_poll_probe[EDR_AGENT_POLL_COMMAND_DELIVERY].last_us,
      (unsigned long long)s_agent_poll_probe[EDR_AGENT_POLL_RESOURCE].max_us,
      (unsigned long long)s_agent_poll_probe[EDR_AGENT_POLL_SELF_PROTECT].max_us,
      (unsigned long long)s_agent_poll_probe[EDR_AGENT_POLL_CONFIG_RELOAD].max_us,
      (unsigned long long)s_agent_poll_probe[EDR_AGENT_POLL_REMOTE_CONFIG].max_us,
      (unsigned long long)s_agent_poll_probe[EDR_AGENT_POLL_P0_BUNDLE].max_us,
      (unsigned long long)s_agent_poll_probe[EDR_AGENT_POLL_SENSOR_INTEREST].max_us,
      (unsigned long long)s_agent_poll_probe[EDR_AGENT_POLL_ATTACK_SURFACE].max_us,
      (unsigned long long)s_agent_poll_probe[EDR_AGENT_POLL_ENGINE_HEALTH].max_us,
      (unsigned long long)s_agent_poll_probe[EDR_AGENT_POLL_SHELL_SESSION].max_us,
      (unsigned long long)s_agent_poll_probe[EDR_AGENT_POLL_COMMAND_DELIVERY].max_us,
      (unsigned long long)s_agent_poll_probe[EDR_AGENT_POLL_RESOURCE].calls,
      (unsigned long long)s_agent_poll_probe[EDR_AGENT_POLL_SELF_PROTECT].calls,
      (unsigned long long)s_agent_poll_probe[EDR_AGENT_POLL_CONFIG_RELOAD].calls,
      (unsigned long long)s_agent_poll_probe[EDR_AGENT_POLL_REMOTE_CONFIG].calls,
      (unsigned long long)s_agent_poll_probe[EDR_AGENT_POLL_P0_BUNDLE].calls,
      (unsigned long long)s_agent_poll_probe[EDR_AGENT_POLL_SENSOR_INTEREST].calls,
      (unsigned long long)s_agent_poll_probe[EDR_AGENT_POLL_ATTACK_SURFACE].calls,
      (unsigned long long)s_agent_poll_probe[EDR_AGENT_POLL_ENGINE_HEALTH].calls,
      (unsigned long long)s_agent_poll_probe[EDR_AGENT_POLL_SHELL_SESSION].calls,
      (unsigned long long)s_agent_poll_probe[EDR_AGENT_POLL_COMMAND_DELIVERY].calls);
}

static void edr_agent_poll_engine_health(EdrAgent *agent, uint64_t *last_health_ns) {
  if (!agent || !last_health_ns || !edr_ingest_http_configured()) {
    return;
  }
  if (!agent->cfg.health_monitor.enabled) {
    return;
  }
  uint64_t wall_ms = (uint64_t)time(NULL) * 1000ULL;
  if (agent->cfg.health_monitor.expires_at_unix_ms > 0u &&
      wall_ms >= agent->cfg.health_monitor.expires_at_unix_ms) {
    return;
  }
  int interval = (int)agent->cfg.health_monitor.interval_s;
  if (interval < 30 || interval > 3600) {
    interval = 60;
  }
  const char *iv = getenv("EDR_ENGINE_HEALTH_INTERVAL_S");
  if (iv && iv[0]) {
    int v = atoi(iv);
    if (v >= 30 && v <= 3600) {
      interval = v;
    }
  }
  uint64_t now = edr_monotonic_ns();
  if (now - *last_health_ns < (uint64_t)interval * 1000000000ULL) {
    return;
  }
  *last_health_ns = now;

  unsigned long pmfe_sub = 0, pmfe_done = 0, pmfe_drop = 0;
  unsigned long pmfe_q = 0;

  AVEStatus avst;
  memset(&avst, 0, sizeof(avst));
  int ave_ok = 0;

  char rules_ver[96], runtime_policy_raw[96], runtime_policy_ver[96];
  char static_ver[48], behavior_ver[48], ioc_ver[48];
  char health_profile[48], health_request_id[160];
  char det_policy_source[64], det_policy_version[96], det_policy_rollback[96], det_policy_audit[160];
  char grpc_err[192], http_err[192], evidence_json[1600], sensor_interest_ver[160], sensor_interest_rules[160];
  char event_filter_ver[96];
  char event_filter_last_reason[128], event_filter_last_process[128];
  char event_filter_last_path[320], event_filter_last_cmdline[320];
  char adaptive_last_rule[96];
  char http_conn_mode[48], http_base_url[640], http_relay_url[640], http_proxy_mode[48];
  char http_proxy_url[640], http_proxy_status[128], http_circuit_reason[160];
  char http_mtls_status[128], http_key_provider[48];
  char http_negotiated_protocol[32], http_control_status[48], http_upload_status[48];
  char http2_last_error[192];
  char http_data_encoding[48], http_data_compression[48], http_envelope_format[64];
  char http_dict_ver[96], http_schema_ver[96], http_profile_id[96];
  char http_zstd_dict_path[640];
  char http_qos_dscp[48], http_threshold[48];
  char tv2_active_channel[48], tv2_last_operation[48], tv2_last_error[192];
  char tv2_envelope_format[64];
  char resource_pressure_reason[96];
  char poll_probe_json[1600];
  char config_recovery_json[1600];
  const char *hot_thread_role = "unknown";
  EdrGrpcClientRuntime grpc_rt;
  EdrIngestHttpRuntime http_rt;
  EdrTransportV2Runtime tv2_rt;
  EdrResourceSample rs;
  EdrCollectorHealth ch;
  EdrCommandDeliveryHealth cdh;
  EdrWindowsEventFilterStatus event_filter_status;
  memset(&grpc_rt, 0, sizeof(grpc_rt));
  memset(&http_rt, 0, sizeof(http_rt));
  memset(&tv2_rt, 0, sizeof(tv2_rt));
  memset(&rs, 0, sizeof(rs));
  memset(&ch, 0, sizeof(ch));
  memset(&cdh, 0, sizeof(cdh));
  memset(&event_filter_status, 0, sizeof(event_filter_status));
  edr_grpc_client_get_runtime(&grpc_rt);
  edr_ingest_http_get_runtime(&http_rt);
  edr_transport_v2_get_runtime(&tv2_rt);
  edr_resource_get_sample(&rs);
  (void)edr_collector_get_health(&ch);
  edr_command_get_delivery_health(&cdh);
#ifdef _WIN32
  if (rs.hot_thread_id != 0u && ch.collector_thread_id != 0u &&
      rs.hot_thread_id == ch.collector_thread_id) {
    hot_thread_role = "collector_etw";
  } else if (rs.hot_thread_id != 0u && s_agent_main_thread_id != 0u &&
             rs.hot_thread_id == s_agent_main_thread_id) {
    hot_thread_role = "agent_main_loop";
  } else if (rs.hot_thread_id != 0u) {
    hot_thread_role = "background_worker";
  }
#endif
  json_escape_small(agent->cfg.health_monitor.profile, health_profile, sizeof(health_profile));
  json_escape_small(agent->cfg.health_monitor.request_id, health_request_id, sizeof(health_request_id));
  json_escape_small(agent->cfg.preprocessing.rules_version, rules_ver, sizeof(rules_ver));
  runtime_policy_raw[0] = '\0';
  edr_ingest_http_copy_policy_version(runtime_policy_raw, sizeof(runtime_policy_raw));
  json_escape_small(runtime_policy_raw, runtime_policy_ver, sizeof(runtime_policy_ver));
  json_escape_small(grpc_rt.last_error, grpc_err, sizeof(grpc_err));
  json_escape_small(http_rt.last_error, http_err, sizeof(http_err));
  json_escape_small(http_rt.connection_mode, http_conn_mode, sizeof(http_conn_mode));
  json_escape_small(http_rt.effective_base_url, http_base_url, sizeof(http_base_url));
  char http_route_profile[128];
  char http_active_route_url[640];
  json_escape_small(http_rt.route_profile_version, http_route_profile, sizeof(http_route_profile));
  json_escape_small(http_rt.active_route_url, http_active_route_url, sizeof(http_active_route_url));
  json_escape_small(http_rt.relay_url, http_relay_url, sizeof(http_relay_url));
  json_escape_small(http_rt.proxy_mode, http_proxy_mode, sizeof(http_proxy_mode));
  json_escape_small(http_rt.proxy_url, http_proxy_url, sizeof(http_proxy_url));
  json_escape_small(http_rt.proxy_status, http_proxy_status, sizeof(http_proxy_status));
  json_escape_small(http_rt.circuit_reason, http_circuit_reason, sizeof(http_circuit_reason));
  json_escape_small(http_rt.mtls_status, http_mtls_status, sizeof(http_mtls_status));
  json_escape_small(http_rt.client_key_provider, http_key_provider, sizeof(http_key_provider));
  json_escape_small(http_rt.negotiated_protocol, http_negotiated_protocol, sizeof(http_negotiated_protocol));
  json_escape_small(http_rt.http2_last_error, http2_last_error, sizeof(http2_last_error));
  json_escape_small(http_rt.control_stream_status, http_control_status, sizeof(http_control_status));
  json_escape_small(http_rt.upload_status, http_upload_status, sizeof(http_upload_status));
  json_escape_small(http_rt.data_plane_encoding, http_data_encoding, sizeof(http_data_encoding));
  json_escape_small(http_rt.data_plane_compression, http_data_compression, sizeof(http_data_compression));
  json_escape_small(http_rt.envelope_format, http_envelope_format, sizeof(http_envelope_format));
  json_escape_small(http_rt.dict_ver, http_dict_ver, sizeof(http_dict_ver));
  json_escape_small(http_rt.schema_ver, http_schema_ver, sizeof(http_schema_ver));
  json_escape_small(http_rt.profile_id, http_profile_id, sizeof(http_profile_id));
  json_escape_small(http_rt.zstd_dict_path, http_zstd_dict_path, sizeof(http_zstd_dict_path));
  json_escape_small(http_rt.qos_dscp, http_qos_dscp, sizeof(http_qos_dscp));
  json_escape_small(http_rt.telemetry_threshold, http_threshold, sizeof(http_threshold));
  json_escape_small(tv2_rt.active_channel, tv2_active_channel, sizeof(tv2_active_channel));
  json_escape_small(tv2_rt.last_operation, tv2_last_operation, sizeof(tv2_last_operation));
  json_escape_small(tv2_rt.last_error, tv2_last_error, sizeof(tv2_last_error));
  json_escape_small(tv2_rt.envelope_format, tv2_envelope_format, sizeof(tv2_envelope_format));
  json_escape_small(rs.pressure_reason, resource_pressure_reason, sizeof(resource_pressure_reason));
  edr_agent_config_recovery_json(agent, config_recovery_json, sizeof(config_recovery_json));
  if (strcmp(health_profile, "diagnostic") != 0) {
    char body_basic[12288];
    int n_basic = snprintf(
        body_basic, sizeof(body_basic),
        "{\"endpoint_id\":\"%s\",\"agent_version\":\"%s\",\"policy_version\":\"%s\","
        "\"engine_health\":{"
        "\"reported_at_unix_ms\":%llu,"
        "\"config_recovery\":%s,"
        "\"monitor\":{\"enabled\":true,\"profile\":\"%s\","
        "\"interval_s\":%u,\"expires_at_unix_ms\":%llu,\"request_id\":\"%s\"},"
        "\"communication\":{\"grpc_ready\":%s,\"http_fallback\":%s,"
        "\"http_ok\":%lu,\"http_fail\":%lu,"
        "\"offline_queue_pending\":%llu,"
        "\"last_success_unix_ms\":%lld,\"last_failure_unix_ms\":%lld,"
        "\"last_failure_reason\":\"%s%s%s\","
        "\"enterprise\":{\"connection_mode\":\"%s\",\"effective_base_url\":\"%s\","
        "\"relay_url\":\"%s\",\"mtls_configured\":%s,\"websocket_ready\":%s,"
        "\"mtls_status\":\"%s\",\"client_key_provider\":\"%s\","
        "\"proxy_mode\":\"%s\",\"proxy_url\":\"%s\",\"proxy_status\":\"%s\","
        "\"last_success_unix_ms\":%lld,\"last_failure_unix_ms\":%lld,"
        "\"failure_reason\":\"%s%s%s\",\"poll_backoff_ms\":%d,\"ws_backoff_ms\":%d,"
        "\"circuit_open\":%s,\"circuit_until_unix_ms\":%lld,"
        "\"circuit_reason\":\"%s\",\"pending_upload_queue\":%llu,"
        "\"route\":{\"profile_version\":\"%s\",\"active_base_url\":\"%s\","
        "\"route_count\":%d,\"active_index\":%d,\"failover_count\":%lu},"
        "\"budget\":{\"requests_this_minute\":%lu,\"request_limit_per_minute\":%lu,"
        "\"bytes_this_minute\":%llu,\"byte_limit_per_minute\":%llu,"
        "\"tls_handshakes_this_minute\":%lu,\"tls_handshake_limit_per_minute\":%lu,"
        "\"budget_drops\":%lu},\"slo\":{\"success_rate_pct\":%u},"
        "\"protocol\":{\"http2_enabled\":%s,\"http2_required\":%s,"
        "\"http2_negotiated\":%s,\"negotiated_protocol\":\"%s\","
        "\"http2_last_error\":\"%s\",\"http2_cert_error_count\":%lu,"
        "\"control_stream_enabled\":%s,\"control_stream_ready\":%s,"
        "\"control_stream_status\":\"%s\",\"long_poll_fallback\":%s,"
        "\"upload_status\":\"%s\",\"report_events_v2_enabled\":%s,"
        "\"report_events_v2_ok\":%lu,\"report_events_v2_fail\":%lu,"
        "\"data_plane_encoding\":\"%s\",\"data_plane_compression\":\"%s\","
        "\"envelope_format\":\"%s\",\"dict_ver\":\"%s\",\"schema_ver\":\"%s\","
        "\"profile_id\":\"%s\",\"qos_dscp\":\"%s\",\"telemetry_threshold\":\"%s\","
        "\"telemetry_sampling_pct\":%u,"
        "\"zstd_runtime\":{\"available\":%s,\"dict_loaded\":%s,"
        "\"dict_path\":\"%s\",\"raw_bytes\":%llu,\"wire_bytes\":%llu,"
        "\"dict_bytes\":%llu,\"compress_ok\":%lu,\"compress_fail\":%lu},"
        "\"http2_multiplex\":{\"enabled\":%s,\"active\":%s,"
        "\"ok\":%lu,\"fail\":%lu},"
        "\"transport_v2\":{\"enabled\":%s,\"opened_streams\":%lu,"
        "\"send_ok\":%lu,\"send_fail\":%lu,\"ack_ok\":%lu,\"ack_fail\":%lu,"
        "\"resume_count\":%lu,\"control_frames\":%lu,"
        "\"active_channel\":\"%s\",\"last_operation\":\"%s\","
        "\"envelope_format\":\"%s\",\"last_error\":\"%s\"}}}},"
        "\"event_bus\":{\"capacity\":%u,\"used\":%u,\"pushed\":%llu,"
        "\"dropped\":%llu,\"high_water_hits\":%llu,\"static_bytes\":%llu},"
        "\"main_loop\":{\"count\":%llu,\"interval_last_ms\":%llu,"
        "\"interval_max_ms\":%llu,\"elapsed_last_us\":%llu,\"elapsed_max_us\":%llu},"
        "\"resource\":{\"cpu_budget_percent\":%u,\"memory_budget_mb\":%u,"
        "\"behavior_infer_per_min\":%u,\"pmfe_scans_per_min\":%u,"
        "\"cpu_percent\":%u,\"rss_mb\":%llu,\"current_rss_mb\":%llu,"
        "\"working_set_mb\":%llu,\"private_bytes_mb\":%llu,\"pagefile_mb\":%llu,"
        "\"thread_count\":%u,\"handle_count\":%u,"
        "\"hot_thread_id\":%u,\"hot_thread_cpu_percent\":%u,"
        "\"hot_thread_role\":\"%s\","
        "\"throttle_active\":%s,\"pressure\":%s,\"pressure_level\":%u,"
        "\"pressure_reason\":\"%s\",\"sample_count\":%llu},"
        "\"p0_rule\":{\"enabled\":true,\"mode\":\"resident\","
        "\"rule_version\":\"%s\",\"rules_count\":%u,"
        "\"last_degrade_reason\":\"%s\"},"
        "\"sensor_health\":{\"etw_or_inotify_enabled\":%s,"
        "\"powershell_visible\":%s,\"amsi_visible\":%s,"
        "\"security_audit_visible\":%s,\"collector_thread_id\":%u,"
        "\"collector_dropped\":%llu,\"queue_dropped\":%llu,"
        "\"agent_self_fuse\":{\"active\":%s,\"provider_degraded\":%s,"
        "\"until_unix_ms\":%llu,\"trips\":%llu,\"suppressed\":%llu,"
        "\"current_minute_count\":%llu,\"threshold_per_min\":%llu,"
        "\"cooldown_s\":%llu},"
        "\"drop_breakdown\":{\"agent_self\":%llu,\"lifecycle\":%llu,"
        "\"auth\":%llu,\"invalid_process\":%llu,\"ordinary_file\":%llu,"
        "\"ordinary_registry\":%llu,\"ordinary_network\":%llu,"
        "\"metadata\":%llu}}"
        "}}",
        agent->cfg.agent.endpoint_id, EDR_AGENT_VERSION_STRING,
        runtime_policy_ver[0] ? runtime_policy_ver : (rules_ver[0] ? rules_ver : "local"),
        (unsigned long long)wall_ms, config_recovery_json,
        health_profile[0] ? health_profile : "basic",
        agent->cfg.health_monitor.interval_s,
        (unsigned long long)agent->cfg.health_monitor.expires_at_unix_ms, health_request_id,
        grpc_rt.ready ? "true" : "false",
        http_rt.http_fallback_available ? "true" : "false", http_rt.ok_count, http_rt.fail_count,
        (unsigned long long)edr_storage_queue_pending_count(),
        (long long)((grpc_rt.last_success_unix_ms > http_rt.last_success_unix_ms) ? grpc_rt.last_success_unix_ms
                                                                                  : http_rt.last_success_unix_ms),
        (long long)((grpc_rt.last_failure_unix_ms > http_rt.last_failure_unix_ms) ? grpc_rt.last_failure_unix_ms
                                                                                  : http_rt.last_failure_unix_ms),
        grpc_err, (grpc_err[0] && http_err[0]) ? "|" : "", http_err,
        http_conn_mode[0] ? http_conn_mode : "direct", http_base_url, http_relay_url,
        http_rt.mtls_configured ? "true" : "false", http_rt.websocket_ready ? "true" : "false",
        http_mtls_status[0] ? http_mtls_status : "not_configured",
        http_key_provider[0] ? http_key_provider : "pem",
        http_proxy_mode[0] ? http_proxy_mode : "auto", http_proxy_url, http_proxy_status,
        (long long)((grpc_rt.last_success_unix_ms > http_rt.last_success_unix_ms) ? grpc_rt.last_success_unix_ms
                                                                                  : http_rt.last_success_unix_ms),
        (long long)((grpc_rt.last_failure_unix_ms > http_rt.last_failure_unix_ms) ? grpc_rt.last_failure_unix_ms
                                                                                  : http_rt.last_failure_unix_ms),
        grpc_err, (grpc_err[0] && http_err[0]) ? "|" : "", http_err,
        http_rt.poll_backoff_ms, http_rt.ws_backoff_ms,
        http_rt.circuit_open ? "true" : "false", (long long)http_rt.circuit_until_unix_ms,
        http_circuit_reason, (unsigned long long)edr_storage_queue_pending_count(),
        http_route_profile, http_active_route_url, http_rt.route_count,
        http_rt.active_route_index, http_rt.route_failover_count,
        http_rt.requests_this_minute, http_rt.request_limit_per_minute,
        (unsigned long long)http_rt.bytes_this_minute,
        (unsigned long long)http_rt.byte_limit_per_minute,
        http_rt.tls_handshakes_this_minute, http_rt.tls_handshake_limit_per_minute,
        http_rt.budget_drop_count, http_rt.slo_success_rate_pct,
        http_rt.http2_enabled ? "true" : "false", http_rt.http2_required ? "true" : "false",
        http_rt.http2_negotiated ? "true" : "false", http_negotiated_protocol,
        http2_last_error, http_rt.http2_cert_error_count,
        http_rt.control_stream_enabled ? "true" : "false",
        http_rt.control_stream_ready ? "true" : "false", http_control_status,
        http_rt.long_poll_fallback ? "true" : "false", http_upload_status,
        http_rt.report_events_v2_enabled ? "true" : "false",
        http_rt.report_events_v2_ok_count, http_rt.report_events_v2_fail_count,
        http_data_encoding, http_data_compression, http_envelope_format,
        http_dict_ver, http_schema_ver, http_profile_id, http_qos_dscp, http_threshold,
        http_rt.telemetry_sampling_pct,
        http_rt.zstd_available ? "true" : "false", http_rt.zstd_dict_loaded ? "true" : "false",
        http_zstd_dict_path,
        (unsigned long long)http_rt.zstd_raw_bytes,
        (unsigned long long)http_rt.zstd_wire_bytes,
        (unsigned long long)http_rt.zstd_dict_bytes,
        http_rt.zstd_compress_ok_count, http_rt.zstd_compress_fail_count,
        http_rt.http2_multiplex_enabled ? "true" : "false",
        http_rt.http2_multiplex_active ? "true" : "false",
        http_rt.http2_multiplex_ok_count, http_rt.http2_multiplex_fail_count,
        tv2_rt.enabled ? "true" : "false", tv2_rt.opened_streams,
        tv2_rt.send_ok, tv2_rt.send_fail, tv2_rt.ack_ok, tv2_rt.ack_fail,
        tv2_rt.resume_count, tv2_rt.control_frames,
        tv2_active_channel, tv2_last_operation, tv2_envelope_format, tv2_last_error,
        edr_event_bus_capacity(agent->event_bus),
        edr_event_bus_used_approx(agent->event_bus),
        (unsigned long long)edr_event_bus_pushed_total(agent->event_bus),
        (unsigned long long)edr_event_bus_dropped_total(agent->event_bus),
        (unsigned long long)edr_event_bus_high_water_hits(agent->event_bus),
        (unsigned long long)edr_event_bus_static_bytes(agent->event_bus),
        (unsigned long long)s_agent_loop_count,
        (unsigned long long)s_agent_loop_interval_last_ms,
        (unsigned long long)s_agent_loop_interval_max_ms,
        (unsigned long long)s_agent_loop_elapsed_last_us,
        (unsigned long long)s_agent_loop_elapsed_max_us,
        agent->cfg.resource_limit.cpu_limit_percent, agent->cfg.resource_limit.memory_limit_mb,
        agent->cfg.resource_limit.behavior_infer_per_min,
        agent->cfg.resource_limit.pmfe_scans_per_min,
        rs.cpu_percent, (unsigned long long)rs.rss_mb, (unsigned long long)rs.rss_mb,
        (unsigned long long)rs.working_set_mb,
        (unsigned long long)rs.private_bytes_mb,
        (unsigned long long)rs.pagefile_mb,
        rs.thread_count, rs.handle_count,
        rs.hot_thread_id, rs.hot_thread_cpu_percent, hot_thread_role,
        rs.throttle_active ? "true" : "false", rs.throttle_active ? "true" : "false",
        rs.pressure_level, resource_pressure_reason[0] ? resource_pressure_reason : "ok",
        (unsigned long long)rs.sample_count, rules_ver, agent->cfg.preprocessing.rules_count,
        rs.throttle_active ? "resource_throttle" : "",
        ch.etw_or_inotify_enabled ? "true" : "false", ch.powershell_visible ? "true" : "false",
        ch.amsi_visible ? "true" : "false", ch.security_audit_visible ? "true" : "false",
        ch.collector_thread_id,
        (unsigned long long)ch.collector_dropped,
        (unsigned long long)ch.queue_dropped,
        ch.agent_self_fuse_active ? "true" : "false",
        ch.agent_self_fuse_provider_degraded ? "true" : "false",
        (unsigned long long)ch.agent_self_fuse_until_unix_ms,
        (unsigned long long)ch.agent_self_fuse_trips,
        (unsigned long long)ch.agent_self_fuse_suppressed,
        (unsigned long long)ch.agent_self_fuse_current_minute_count,
        (unsigned long long)ch.agent_self_fuse_threshold_per_min,
        (unsigned long long)ch.agent_self_fuse_cooldown_s,
        (unsigned long long)ch.agent_self_suppressed,
        (unsigned long long)ch.lifecycle_dropped,
        (unsigned long long)ch.auth_dropped,
        (unsigned long long)ch.invalid_process_dropped,
        (unsigned long long)ch.ordinary_file_dropped,
        (unsigned long long)ch.ordinary_registry_dropped,
        (unsigned long long)ch.ordinary_network_dropped,
        (unsigned long long)ch.metadata_dropped);
    if (n_basic > 0 && (size_t)n_basic < sizeof(body_basic)) {
      (void)edr_ingest_http_post_engine_health_json(body_basic);
    }
    return;
  }

  edr_pmfe_get_stats(&pmfe_sub, &pmfe_done, &pmfe_drop);
  pmfe_q = edr_pmfe_queue_depth();
  ave_ok = (AVE_GetStatus(&avst) == AVE_OK);
  edr_windows_event_policy_get_status(&event_filter_status);
  edr_local_evidence_cache_status_json(evidence_json, sizeof(evidence_json));
  EdrShellcodeRulesStatus shell_rules;
  memset(&shell_rules, 0, sizeof(shell_rules));
  edr_shellcode_known_get_status(&shell_rules);
  char shell_source[48], shell_version[128], shell_error[192], shell_rb[128], shell_last_rule[128], shell_last_src[48];
  char audit_err[192], ebpf_err[192];
  json_escape_small(agent->cfg.health_monitor.profile, health_profile, sizeof(health_profile));
  json_escape_small(agent->cfg.health_monitor.request_id, health_request_id, sizeof(health_request_id));
  json_escape_small(agent->cfg.preprocessing.rules_version, rules_ver, sizeof(rules_ver));
  runtime_policy_raw[0] = '\0';
  edr_ingest_http_copy_policy_version(runtime_policy_raw, sizeof(runtime_policy_raw));
  json_escape_small(runtime_policy_raw, runtime_policy_ver, sizeof(runtime_policy_ver));
  json_escape_small(agent->cfg.detection_policy.source, det_policy_source, sizeof(det_policy_source));
  json_escape_small(agent->cfg.detection_policy.policy_version, det_policy_version, sizeof(det_policy_version));
  json_escape_small(agent->cfg.detection_policy.rollback_version, det_policy_rollback, sizeof(det_policy_rollback));
  json_escape_small(agent->cfg.detection_policy.audit_id, det_policy_audit, sizeof(det_policy_audit));
  json_escape_small(ave_ok ? avst.static_model_version : "", static_ver, sizeof(static_ver));
  json_escape_small(ave_ok ? avst.behavior_model_version : "", behavior_ver, sizeof(behavior_ver));
  json_escape_small(ave_ok ? avst.ioc_rules_version : "", ioc_ver, sizeof(ioc_ver));
  json_escape_small(shell_rules.source, shell_source, sizeof(shell_source));
  json_escape_small(shell_rules.version, shell_version, sizeof(shell_version));
  json_escape_small(shell_rules.last_error, shell_error, sizeof(shell_error));
  json_escape_small(shell_rules.rollback_version, shell_rb, sizeof(shell_rb));
  json_escape_small(shell_rules.last_match_rule, shell_last_rule, sizeof(shell_last_rule));
  json_escape_small(shell_rules.last_match_source, shell_last_src, sizeof(shell_last_src));
  json_escape_small(grpc_rt.last_error, grpc_err, sizeof(grpc_err));
  json_escape_small(http_rt.last_error, http_err, sizeof(http_err));
  json_escape_small(http_rt.connection_mode, http_conn_mode, sizeof(http_conn_mode));
  json_escape_small(http_rt.effective_base_url, http_base_url, sizeof(http_base_url));
  json_escape_small(http_rt.relay_url, http_relay_url, sizeof(http_relay_url));
  json_escape_small(http_rt.proxy_mode, http_proxy_mode, sizeof(http_proxy_mode));
  json_escape_small(http_rt.proxy_url, http_proxy_url, sizeof(http_proxy_url));
  json_escape_small(http_rt.proxy_status, http_proxy_status, sizeof(http_proxy_status));
  json_escape_small(http_rt.circuit_reason, http_circuit_reason, sizeof(http_circuit_reason));
  json_escape_small(http_rt.mtls_status, http_mtls_status, sizeof(http_mtls_status));
  json_escape_small(http_rt.client_key_provider, http_key_provider, sizeof(http_key_provider));
  json_escape_small(rs.pressure_reason, resource_pressure_reason, sizeof(resource_pressure_reason));
  edr_agent_poll_probe_json(poll_probe_json, sizeof(poll_probe_json));
  json_escape_small(ch.auditd_last_error, audit_err, sizeof(audit_err));
  json_escape_small(ch.ebpf_last_error, ebpf_err, sizeof(ebpf_err));
  json_escape_small(ch.sensor_interest_version, sensor_interest_ver, sizeof(sensor_interest_ver));
  json_escape_small(ch.sensor_interest_rules_version, sensor_interest_rules, sizeof(sensor_interest_rules));
  json_escape_small(ch.adaptive_collection_last_rule_id, adaptive_last_rule, sizeof(adaptive_last_rule));
  json_escape_small(event_filter_status.version, event_filter_ver, sizeof(event_filter_ver));
  json_escape_small(event_filter_status.last_drop_reason, event_filter_last_reason,
                    sizeof(event_filter_last_reason));
  json_escape_small(event_filter_status.last_drop_process, event_filter_last_process,
                    sizeof(event_filter_last_process));
  json_escape_small(event_filter_status.last_drop_path, event_filter_last_path,
                    sizeof(event_filter_last_path));
  json_escape_small(event_filter_status.last_drop_cmdline, event_filter_last_cmdline,
                    sizeof(event_filter_last_cmdline));
  edr_agent_config_recovery_json(agent, config_recovery_json, sizeof(config_recovery_json));

  char body[24576];
  int n = snprintf(
      body, sizeof(body),
      "{\"endpoint_id\":\"%s\",\"agent_version\":\"%s\",\"policy_version\":\"%s\","
      "\"engine_health\":{"
      "\"reported_at_unix_ms\":%llu,"
      "\"config_recovery\":%s,"
      "\"monitor\":{\"enabled\":true,\"profile\":\"%s\","
      "\"interval_s\":%u,\"expires_at_unix_ms\":%llu,\"request_id\":\"%s\"},"
      "\"communication\":{\"grpc_ready\":%s,\"grpc_insecure\":%s,\"http_fallback\":%s,"
      "\"http_insecure\":%s,\"grpc_rpc_ok\":%lu,\"grpc_rpc_fail\":%lu,"
      "\"grpc_consecutive_failures\":%d,\"http_ok\":%lu,\"http_fail\":%lu,"
      "\"counters\":{\"legacy_ok\":%lu,\"legacy_fail\":%lu,"
      "\"http_request_ok\":%lu,\"http_request_fail\":%lu,"
      "\"ws_message_ok\":%lu,\"ws_message_fail\":%lu,\"ws_pong\":%lu,"
      "\"command_result_ok\":%lu,\"command_result_fail\":%lu,"
      "\"upload_ok\":%lu,\"upload_fail\":%lu,"
      "\"long_poll_ok\":%lu,\"long_poll_fail\":%lu,"
      "\"control_stream_ok\":%lu,\"control_stream_fail\":%lu,"
      "\"control_stream_heartbeat\":%lu,"
      "\"control_ack_ok\":%lu,\"control_ack_fail\":%lu,"
      "\"http2_request_ok\":%lu,\"http2_request_fail\":%lu,"
      "\"http2_negotiated\":%lu,\"http2_fallback\":%lu,"
      "\"http2_cert_error\":%lu},"
      "\"send_queue_depth\":%llu,\"send_queue_capacity\":%llu,"
      "\"queue_full_total\":%lu,\"queue_full_persisted\":%lu,"
      "\"queue_full_sampled\":%lu,\"queue_full_dropped\":%lu,"
      "\"offline_queue_pending\":%llu,\"last_success_unix_ms\":%lld,"
      "\"last_failure_unix_ms\":%lld,\"last_failure_reason\":\"%s%s%s\","
      "\"enterprise\":{\"connection_mode\":\"%s\",\"effective_base_url\":\"%s\","
      "\"relay_url\":\"%s\",\"mtls_configured\":%s,\"websocket_ready\":%s,"
      "\"mtls_status\":\"%s\",\"client_key_provider\":\"%s\","
      "\"proxy_mode\":\"%s\",\"proxy_url\":\"%s\",\"proxy_status\":\"%s\","
      "\"last_success_unix_ms\":%lld,\"last_failure_unix_ms\":%lld,"
      "\"failure_reason\":\"%s%s%s\",\"poll_backoff_ms\":%d,\"ws_backoff_ms\":%d,"
      "\"circuit_open\":%s,\"circuit_until_unix_ms\":%lld,\"circuit_reason\":\"%s\","
      "\"pending_upload_queue\":%llu,"
      "\"budget\":{\"requests_this_minute\":%lu,\"request_limit_per_minute\":%lu,"
      "\"bytes_this_minute\":%llu,\"byte_limit_per_minute\":%llu,"
      "\"tls_handshakes_this_minute\":%lu,\"tls_handshake_limit_per_minute\":%lu,"
      "\"budget_drops\":%lu},"
      "\"slo\":{\"success_rate_pct\":%u},"
      "\"protocol\":{\"http2_enabled\":%s,\"http2_required\":%s,"
      "\"http2_negotiated\":%s,\"negotiated_protocol\":\"%s\","
      "\"http2_last_error\":\"%s\",\"http2_cert_error_count\":%lu,"
      "\"control_stream_enabled\":%s,\"control_stream_ready\":%s,"
      "\"control_stream_status\":\"%s\",\"long_poll_fallback\":%s,"
      "\"upload_status\":\"%s\",\"report_events_v2_enabled\":%s,"
      "\"report_events_v2_ok\":%lu,\"report_events_v2_fail\":%lu,"
      "\"data_plane_encoding\":\"%s\",\"data_plane_compression\":\"%s\","
      "\"envelope_format\":\"%s\",\"dict_ver\":\"%s\",\"schema_ver\":\"%s\","
      "\"profile_id\":\"%s\",\"qos_dscp\":\"%s\",\"telemetry_threshold\":\"%s\","
      "\"telemetry_sampling_pct\":%u,"
      "\"zstd_runtime\":{\"available\":%s,\"dict_loaded\":%s,"
      "\"dict_path\":\"%s\",\"raw_bytes\":%llu,\"wire_bytes\":%llu,"
      "\"dict_bytes\":%llu,\"compress_ok\":%lu,\"compress_fail\":%lu},"
      "\"http2_multiplex\":{\"enabled\":%s,\"active\":%s,"
      "\"ok\":%lu,\"fail\":%lu},"
      "\"transport_v2\":{\"enabled\":%s,\"opened_streams\":%lu,"
      "\"send_ok\":%lu,\"send_fail\":%lu,\"ack_ok\":%lu,\"ack_fail\":%lu,"
      "\"resume_count\":%lu,\"control_frames\":%lu,"
      "\"channel_control\":%lu,\"channel_high_sev\":%lu,"
      "\"channel_normal\":%lu,\"channel_backfill\":%lu,"
      "\"channel_upload\":%lu,\"channel_command_result\":%lu,"
      "\"active_channel\":\"%s\",\"last_operation\":\"%s\","
      "\"envelope_format\":\"%s\",\"last_error\":\"%s\"}}}},"
      "%s"
      "\"event_bus\":{\"capacity\":%u,\"used\":%u,\"pushed\":%llu,"
      "\"dropped\":%llu,\"high_water_hits\":%llu,\"static_bytes\":%llu},"
      "\"main_loop\":{\"count\":%llu,\"interval_last_ms\":%llu,"
      "\"interval_max_ms\":%llu,\"elapsed_last_us\":%llu,\"elapsed_max_us\":%llu},"
      "\"command_delivery\":{\"poll_count\":%llu,\"last_poll_unix_ms\":%lld,"
      "\"last_total_ms\":%u,\"max_total_ms\":%u,"
      "\"last_upload_ms\":%u,\"max_upload_ms\":%u,"
      "\"last_result_ms\":%u,\"max_result_ms\":%u,"
      "\"last_compact_ms\":%u,\"max_compact_ms\":%u,"
      "\"upload_pending_seen\":%u,\"upload_attempted\":%u,"
      "\"upload_succeeded\":%u,\"upload_failed\":%u,"
      "\"upload_skipped_backoff\":%u,\"upload_fail_streak\":%u,"
      "\"upload_next_retry_unix_ms\":%lld},"
      "\"resource\":{\"cpu_budget_percent\":%u,\"memory_budget_mb\":%u,"
      "\"ave_infer_per_min\":%u,\"behavior_infer_per_min\":%u,"
      "\"pmfe_scans_per_min\":%u,\"webshell_scan_mb_per_min\":%u,"
      "\"shellcode_packets_per_sec\":%u,\"low_priority_keep_percent_under_pressure\":%u,"
      "\"cpu_percent\":%u,\"rss_mb\":%llu,\"current_rss_mb\":%llu,"
      "\"working_set_mb\":%llu,\"private_bytes_mb\":%llu,\"pagefile_mb\":%llu,"
      "\"thread_count\":%u,\"handle_count\":%u,"
      "\"hot_thread_id\":%u,\"hot_thread_cpu_percent\":%u,"
      "\"hot_thread_role\":\"%s\","
      "\"hot_thread_kernel_delta_100ns\":%llu,\"hot_thread_user_delta_100ns\":%llu,"
      "\"hot_thread_total_delta_100ns\":%llu,"
      "\"throttle_active\":%s,\"pressure\":%s,\"pressure_level\":%u,"
      "\"pressure_reason\":\"%s\",\"sample_count\":%llu},"
      "\"p0_rule\":{\"enabled\":true,\"mode\":\"resident\",\"rule_version\":\"%s\","
      "\"rules_count\":%u,\"last_degrade_reason\":\"%s\"},"
      "\"suppression_policy\":{\"source\":\"%s\",\"policy_version\":\"%s\","
      "\"rollback_version\":\"%s\",\"audit_id\":\"%s\"},"
      "\"sensor_health\":{\"etw_or_inotify_enabled\":%s,\"powershell_visible\":%s,"
      "\"amsi_visible\":%s,\"security_audit_visible\":%s,"
      "\"auditd_enabled\":%s,\"auditd_running\":%s,\"auditd_events\":%llu,"
      "\"ebpf_enabled\":%s,\"ebpf_loaded\":%s,\"ebpf_events\":%llu,"
      "\"collector_thread_id\":%u,"
      "\"collector_dropped\":%llu,\"queue_dropped\":%llu,"
      "\"agent_self_fuse\":{\"active\":%s,\"provider_degraded\":%s,"
      "\"until_unix_ms\":%llu,\"trips\":%llu,\"suppressed\":%llu,"
      "\"current_minute_count\":%llu,\"threshold_per_min\":%llu,"
      "\"cooldown_s\":%llu},"
      "\"agent_self_sources\":{\"direct_pid\":%llu,\"security_event\":%llu,"
      "\"record\":%llu,\"interest\":%llu,\"fuse_provider\":%llu},"
      "\"drop_breakdown\":{\"agent_self\":%llu,\"lifecycle\":%llu,"
      "\"auth\":%llu,\"invalid_process\":%llu,\"ordinary_file\":%llu,"
      "\"ordinary_registry\":%llu,\"ordinary_network\":%llu,\"metadata\":%llu},"
      "\"auditd_last_error\":\"%s\",\"ebpf_last_error\":\"%s\","
      "\"event_filter\":{\"enabled\":%s,\"version\":\"%s\","
      "\"evaluated\":%llu,\"dropped\":%llu,"
      "\"agent_internal_forensic\":%llu,\"low_value_file_process\":%llu,"
      "\"low_value_file_suffix\":%llu,\"temp_xml\":%llu,"
      "\"windows_noise_path\":%llu,\"metadata_only\":%llu,"
      "\"last_drop\":{\"reason\":\"%s\",\"process\":\"%s\","
      "\"path\":\"%s\",\"cmdline\":\"%s\"}},"
      "\"adaptive_collection\":{\"enabled\":%s,\"active\":%s,\"ttl_s\":%u,"
      "\"remaining_s\":%u,\"min_severity\":%u,\"level\":%d,"
      "\"boosts\":%llu,\"last_boost_unix_ms\":%llu,\"last_rule_id\":\"%s\"},"
      "\"sensor_interest\":{\"enabled\":%s,\"loaded\":%s,\"version\":\"%s\","
      "\"rules_version\":\"%s\",\"process_names\":%u,\"process_prefixes\":%u,"
      "\"ports\":%u,\"file_prefixes\":%u,\"file_contains\":%u,"
      "\"registry_prefixes\":%u,\"registry_contains\":%u,\"cmd_tokens\":%u,"
      "\"parent_child_pairs\":%u,\"required_fields\":%u,"
      "\"checked\":%llu,\"matched\":%llu,\"dropped\":%llu,"
      "\"provider_hits\":%llu,\"adaptive_hits\":%llu,\"process_hits\":%llu,\"port_hits\":%llu,"
      "\"path_hits\":%llu,\"registry_hits\":%llu,\"parent_child_hits\":%llu}},"
      "\"ave\":{\"enabled\":%s,\"mode\":\"triggered\",\"static_model_version\":\"%s\","
      "\"behavior_model_version\":\"%s\",\"ioc_rules_version\":\"%s\","
      "\"queue_depth\":%d,\"queue_capacity\":%u,\"active_scans\":%d,"
      "\"feed_total\":%llu,\"queue_enqueued\":%llu,\"queue_full_dropped\":%llu,"
      "\"queue_full_sync_fallback\":%llu,\"feed_sync_bypass\":%llu,"
      "\"worker_dequeued\":%llu,\"infer_ok\":%llu,\"infer_fail\":%llu,"
      "\"infer_budget_per_min\":%u,\"infer_budget_dropped\":%llu,"
      "\"infer_effective_budget_per_min\":%u,\"pressure_active\":%s,"
      "\"pressure_feed_dropped\":%llu,\"pressure_infer_dropped\":%llu,"
      "\"infer_latency_last_ms\":%u,\"infer_latency_p95_ms\":%u,"
      "\"pid_history_used\":%u,\"pid_history_capacity\":%u,"
      "\"pid_history_static_bytes\":%llu,"
      "\"last_degrade_reason\":\"%s\"},"
      "\"pmfe\":{\"enabled\":true,\"mode\":\"alert_single_process\",\"queue_depth\":%lu,"
      "\"submitted\":%lu,\"completed\":%lu,\"dropped\":%lu,"
      "\"last_degrade_reason\":\"%s\"},"
      "\"shellcode\":{\"enabled\":%s,\"mode\":\"%s\",\"watch_count\":%zu,"
      "\"threads\":%u,\"max_payload_inspect\":%u,\"rule_version\":\"%s\","
      "\"rules_source\":\"%s\",\"rules_loaded\":%u,\"last_reload_unix_s\":%llu,"
      "\"gray_percent\":%u,\"rollback_available\":%s,\"rollback_active\":%s,"
      "\"rollback_version\":\"%s\",\"matches_total\":%llu,\"yara_matches\":%llu,"
      "\"builtin_matches\":%llu,\"gray_shadow_matches\":%llu,"
      "\"last_match_rule\":\"%s\",\"last_match_source\":\"%s\","
      "\"last_error\":\"%s\",\"last_degrade_reason\":\"%s\"},"
      "\"webshell\":{\"enabled\":%s,\"mode\":\"web_roots_only\",\"watch_count\":%u,"
      "\"max_file_size_mb\":%u,\"scan_threads\":%u,\"last_degrade_reason\":\"%s\"},"
      "%s"
      "}}",
      agent->cfg.agent.endpoint_id, EDR_AGENT_VERSION_STRING,
      runtime_policy_ver[0] ? runtime_policy_ver : (rules_ver[0] ? rules_ver : "local"),
      (unsigned long long)wall_ms, config_recovery_json,
      health_profile[0] ? health_profile : "basic", agent->cfg.health_monitor.interval_s,
      (unsigned long long)agent->cfg.health_monitor.expires_at_unix_ms, health_request_id,
	      grpc_rt.ready ? "true" : "false", grpc_rt.insecure ? "true" : "false",
	      http_rt.http_fallback_available ? "true" : "false", http_rt.insecure_http ? "true" : "false",
	      grpc_rt.rpc_ok, grpc_rt.rpc_fail, grpc_rt.report_fail_streak, http_rt.ok_count, http_rt.fail_count,
	      http_rt.ok_count, http_rt.fail_count,
	      http_rt.http_request_ok_count, http_rt.http_request_fail_count,
	      http_rt.ws_message_ok_count, http_rt.ws_message_fail_count, http_rt.ws_pong_count,
	      http_rt.command_result_ok_count, http_rt.command_result_fail_count,
	      http_rt.upload_ok_count, http_rt.upload_fail_count,
	      http_rt.long_poll_ok_count, http_rt.long_poll_fail_count,
	      http_rt.control_stream_ok_count, http_rt.control_stream_fail_count,
	      http_rt.control_stream_heartbeat_count,
	      http_rt.control_ack_ok_count, http_rt.control_ack_fail_count,
	      http_rt.http2_request_ok_count, http_rt.http2_request_fail_count,
	      http_rt.http2_negotiated_count, http_rt.http2_fallback_count,
	      http_rt.http2_cert_error_count,
	      (unsigned long long)edr_transport_send_queue_depth(),
	      (unsigned long long)edr_transport_send_queue_capacity(),
	      edr_transport_queue_full_count(), edr_transport_queue_full_persisted_count(),
	      edr_transport_queue_full_sampled_count(), edr_transport_queue_full_dropped_count(),
	      (unsigned long long)edr_storage_queue_pending_count(),
      (long long)((grpc_rt.last_success_unix_ms > http_rt.last_success_unix_ms) ? grpc_rt.last_success_unix_ms
                                                                                : http_rt.last_success_unix_ms),
      (long long)((grpc_rt.last_failure_unix_ms > http_rt.last_failure_unix_ms) ? grpc_rt.last_failure_unix_ms
                                                                                : http_rt.last_failure_unix_ms),
      grpc_err, (grpc_err[0] && http_err[0]) ? "|" : "", http_err,
	      http_conn_mode[0] ? http_conn_mode : "direct", http_base_url, http_relay_url,
	      http_rt.mtls_configured ? "true" : "false", http_rt.websocket_ready ? "true" : "false",
	      http_mtls_status[0] ? http_mtls_status : "not_configured",
	      http_key_provider[0] ? http_key_provider : "pem",
	      http_proxy_mode[0] ? http_proxy_mode : "auto", http_proxy_url, http_proxy_status,
      (long long)((grpc_rt.last_success_unix_ms > http_rt.last_success_unix_ms) ? grpc_rt.last_success_unix_ms
                                                                                : http_rt.last_success_unix_ms),
      (long long)((grpc_rt.last_failure_unix_ms > http_rt.last_failure_unix_ms) ? grpc_rt.last_failure_unix_ms
                                                                                : http_rt.last_failure_unix_ms),
	      grpc_err, (grpc_err[0] && http_err[0]) ? "|" : "", http_err,
	      http_rt.poll_backoff_ms, http_rt.ws_backoff_ms,
	      http_rt.circuit_open ? "true" : "false", (long long)http_rt.circuit_until_unix_ms,
	      http_circuit_reason,
	      (unsigned long long)edr_storage_queue_pending_count(),
	      http_rt.requests_this_minute, http_rt.request_limit_per_minute,
	      (unsigned long long)http_rt.bytes_this_minute,
	      (unsigned long long)http_rt.byte_limit_per_minute,
	      http_rt.tls_handshakes_this_minute, http_rt.tls_handshake_limit_per_minute,
      http_rt.budget_drop_count, http_rt.slo_success_rate_pct,
      http_rt.http2_enabled ? "true" : "false", http_rt.http2_required ? "true" : "false",
      http_rt.http2_negotiated ? "true" : "false", http_negotiated_protocol,
      http2_last_error, http_rt.http2_cert_error_count,
      http_rt.control_stream_enabled ? "true" : "false",
      http_rt.control_stream_ready ? "true" : "false", http_control_status,
      http_rt.long_poll_fallback ? "true" : "false", http_upload_status,
      http_rt.report_events_v2_enabled ? "true" : "false",
      http_rt.report_events_v2_ok_count, http_rt.report_events_v2_fail_count,
      http_data_encoding, http_data_compression, http_envelope_format,
      http_dict_ver, http_schema_ver, http_profile_id, http_qos_dscp, http_threshold,
      http_rt.telemetry_sampling_pct,
      http_rt.zstd_available ? "true" : "false", http_rt.zstd_dict_loaded ? "true" : "false",
      http_zstd_dict_path,
      (unsigned long long)http_rt.zstd_raw_bytes,
      (unsigned long long)http_rt.zstd_wire_bytes,
      (unsigned long long)http_rt.zstd_dict_bytes,
      http_rt.zstd_compress_ok_count, http_rt.zstd_compress_fail_count,
      http_rt.http2_multiplex_enabled ? "true" : "false",
      http_rt.http2_multiplex_active ? "true" : "false",
      http_rt.http2_multiplex_ok_count, http_rt.http2_multiplex_fail_count,
      tv2_rt.enabled ? "true" : "false", tv2_rt.opened_streams,
      tv2_rt.send_ok, tv2_rt.send_fail, tv2_rt.ack_ok, tv2_rt.ack_fail,
      tv2_rt.resume_count, tv2_rt.control_frames,
      tv2_rt.channel_control, tv2_rt.channel_high_sev, tv2_rt.channel_normal,
      tv2_rt.channel_backfill, tv2_rt.channel_upload, tv2_rt.channel_command_result,
      tv2_active_channel, tv2_last_operation, tv2_envelope_format, tv2_last_error,
      poll_probe_json,
      edr_event_bus_capacity(agent->event_bus),
      edr_event_bus_used_approx(agent->event_bus),
      (unsigned long long)edr_event_bus_pushed_total(agent->event_bus),
      (unsigned long long)edr_event_bus_dropped_total(agent->event_bus),
      (unsigned long long)edr_event_bus_high_water_hits(agent->event_bus),
      (unsigned long long)edr_event_bus_static_bytes(agent->event_bus),
      (unsigned long long)s_agent_loop_count,
      (unsigned long long)s_agent_loop_interval_last_ms,
      (unsigned long long)s_agent_loop_interval_max_ms,
      (unsigned long long)s_agent_loop_elapsed_last_us,
      (unsigned long long)s_agent_loop_elapsed_max_us,
      (unsigned long long)cdh.poll_count, (long long)cdh.last_poll_unix_ms,
      cdh.last_total_ms, cdh.max_total_ms,
      cdh.last_upload_ms, cdh.max_upload_ms,
      cdh.last_result_ms, cdh.max_result_ms,
      cdh.last_compact_ms, cdh.max_compact_ms,
      cdh.upload_pending_seen, cdh.upload_attempted,
      cdh.upload_succeeded, cdh.upload_failed,
      cdh.upload_skipped_backoff, cdh.upload_fail_streak,
      (long long)cdh.upload_next_retry_unix_ms,
      agent->cfg.resource_limit.cpu_limit_percent, agent->cfg.resource_limit.memory_limit_mb,
      agent->cfg.resource_limit.ave_infer_per_min,
      agent->cfg.resource_limit.behavior_infer_per_min,
      agent->cfg.resource_limit.pmfe_scans_per_min,
      agent->cfg.resource_limit.webshell_scan_mb_per_min,
      agent->cfg.resource_limit.shellcode_packets_per_sec,
      agent->cfg.resource_limit.low_priority_keep_percent_under_pressure,
      rs.cpu_percent, (unsigned long long)rs.rss_mb, (unsigned long long)rs.rss_mb,
      (unsigned long long)rs.working_set_mb,
      (unsigned long long)rs.private_bytes_mb,
      (unsigned long long)rs.pagefile_mb,
      rs.thread_count, rs.handle_count,
      rs.hot_thread_id, rs.hot_thread_cpu_percent, hot_thread_role,
      (unsigned long long)rs.hot_thread_kernel_delta_100ns,
      (unsigned long long)rs.hot_thread_user_delta_100ns,
      (unsigned long long)rs.hot_thread_total_delta_100ns,
      rs.throttle_active ? "true" : "false", rs.throttle_active ? "true" : "false",
      rs.pressure_level, resource_pressure_reason[0] ? resource_pressure_reason : "ok",
      (unsigned long long)rs.sample_count,
      rules_ver, agent->cfg.preprocessing.rules_count,
      rs.throttle_active ? "resource_throttle" : "",
      det_policy_source, det_policy_version, det_policy_rollback, det_policy_audit,
      ch.etw_or_inotify_enabled ? "true" : "false", ch.powershell_visible ? "true" : "false",
      ch.amsi_visible ? "true" : "false", ch.security_audit_visible ? "true" : "false",
      ch.auditd_enabled ? "true" : "false", ch.auditd_running ? "true" : "false",
      (unsigned long long)ch.auditd_events,
      ch.ebpf_enabled ? "true" : "false", ch.ebpf_loaded ? "true" : "false",
      (unsigned long long)ch.ebpf_events, ch.collector_thread_id,
      (unsigned long long)ch.collector_dropped,
      (unsigned long long)ch.queue_dropped,
      ch.agent_self_fuse_active ? "true" : "false",
      ch.agent_self_fuse_provider_degraded ? "true" : "false",
      (unsigned long long)ch.agent_self_fuse_until_unix_ms,
      (unsigned long long)ch.agent_self_fuse_trips,
      (unsigned long long)ch.agent_self_fuse_suppressed,
      (unsigned long long)ch.agent_self_fuse_current_minute_count,
      (unsigned long long)ch.agent_self_fuse_threshold_per_min,
      (unsigned long long)ch.agent_self_fuse_cooldown_s,
      (unsigned long long)ch.agent_self_direct_pid_suppressed,
      (unsigned long long)ch.agent_self_security_event_suppressed,
      (unsigned long long)ch.agent_self_record_suppressed,
      (unsigned long long)ch.agent_self_interest_suppressed,
      (unsigned long long)ch.agent_self_fuse_provider_suppressed,
      (unsigned long long)ch.agent_self_suppressed,
      (unsigned long long)ch.lifecycle_dropped,
      (unsigned long long)ch.auth_dropped,
      (unsigned long long)ch.invalid_process_dropped,
      (unsigned long long)ch.ordinary_file_dropped,
      (unsigned long long)ch.ordinary_registry_dropped,
      (unsigned long long)ch.ordinary_network_dropped,
      (unsigned long long)ch.metadata_dropped,
      audit_err, ebpf_err,
      event_filter_status.enabled ? "true" : "false",
      event_filter_ver[0] ? event_filter_ver : "agent-event-filter-v1",
      (unsigned long long)event_filter_status.evaluated,
      (unsigned long long)event_filter_status.dropped,
      (unsigned long long)event_filter_status.agent_internal_forensic,
      (unsigned long long)event_filter_status.low_value_file_process,
      (unsigned long long)event_filter_status.low_value_file_suffix,
      (unsigned long long)event_filter_status.temp_xml,
      (unsigned long long)event_filter_status.windows_noise_path,
      (unsigned long long)event_filter_status.metadata_only,
      event_filter_last_reason,
      event_filter_last_process,
      event_filter_last_path,
      event_filter_last_cmdline,
      ch.adaptive_collection_enabled ? "true" : "false",
      ch.adaptive_collection_active ? "true" : "false",
      ch.adaptive_collection_ttl_s,
      ch.adaptive_collection_remaining_s,
      ch.adaptive_collection_min_severity,
      ch.adaptive_collection_level,
      (unsigned long long)ch.adaptive_collection_boosts,
      (unsigned long long)ch.adaptive_collection_last_boost_unix_ms,
      adaptive_last_rule,
      ch.sensor_interest_enabled ? "true" : "false",
      ch.sensor_interest_loaded ? "true" : "false",
      sensor_interest_ver[0] ? sensor_interest_ver : "builtin",
      sensor_interest_rules[0] ? sensor_interest_rules : rules_ver,
      ch.sensor_interest_process_names, ch.sensor_interest_process_prefixes,
      ch.sensor_interest_ports, ch.sensor_interest_file_prefixes, ch.sensor_interest_file_contains,
      ch.sensor_interest_registry_prefixes, ch.sensor_interest_registry_contains,
      ch.sensor_interest_cmd_tokens, ch.sensor_interest_parent_child_pairs,
      ch.sensor_interest_required_fields, (unsigned long long)ch.sensor_interest_checked,
      (unsigned long long)ch.sensor_interest_matched, (unsigned long long)ch.sensor_interest_dropped,
      (unsigned long long)ch.sensor_interest_provider_hits,
      (unsigned long long)ch.sensor_interest_adaptive_hits,
      (unsigned long long)ch.sensor_interest_process_hits,
      (unsigned long long)ch.sensor_interest_port_hits,
      (unsigned long long)ch.sensor_interest_path_hits,
      (unsigned long long)ch.sensor_interest_registry_hits,
      (unsigned long long)ch.sensor_interest_parent_child_hits,
      ave_ok && avst.initialized ? "true" : "false", static_ver, behavior_ver, ioc_ver,
      ave_ok ? avst.behavior_event_queue_size : 0, ave_ok ? avst.behavior_queue_capacity : 0u,
      ave_ok ? avst.active_scan_count : 0,
      (unsigned long long)(ave_ok ? avst.behavior_feed_total : 0u),
      (unsigned long long)(ave_ok ? avst.behavior_queue_enqueued : 0u),
      (unsigned long long)(ave_ok ? avst.behavior_queue_full_dropped : 0u),
      (unsigned long long)(ave_ok ? avst.behavior_queue_full_sync_fallback : 0u),
      (unsigned long long)(ave_ok ? avst.behavior_feed_sync_bypass : 0u),
      (unsigned long long)(ave_ok ? avst.behavior_worker_dequeued : 0u),
      (unsigned long long)(ave_ok ? avst.behavior_infer_ok : 0u),
      (unsigned long long)(ave_ok ? avst.behavior_infer_fail : 0u),
      ave_ok ? avst.behavior_infer_budget_per_min : 0u,
      (unsigned long long)(ave_ok ? avst.behavior_infer_budget_dropped : 0u),
      ave_ok ? avst.behavior_infer_effective_budget_per_min : 0u,
      (ave_ok && avst.behavior_pressure_active) ? "true" : "false",
      (unsigned long long)(ave_ok ? avst.behavior_pressure_feed_dropped : 0u),
      (unsigned long long)(ave_ok ? avst.behavior_pressure_infer_dropped : 0u),
      ave_ok ? avst.behavior_infer_latency_last_ms : 0u,
      ave_ok ? avst.behavior_infer_latency_p95_ms : 0u,
      ave_ok ? avst.behavior_pid_history_used : 0u,
      ave_ok ? avst.behavior_pid_history_capacity : 0u,
      (unsigned long long)(ave_ok ? avst.behavior_pid_history_static_bytes : 0u),
      (ave_ok && avst.behavior_queue_capacity > 0u &&
       avst.behavior_event_queue_size >= (int)avst.behavior_queue_capacity) ? "queue_full" : "",
      pmfe_q, pmfe_sub, pmfe_done, pmfe_drop,
      pmfe_drop ? "queue_drop" : "",
      agent->cfg.shellcode_detector.enabled ? "true" : "false",
      agent->cfg.shellcode_detector.windivert_ports_is_custom ? "custom_ports" : "lateral_movement_ports",
      agent->cfg.shellcode_detector.windivert_ports_is_custom
          ? agent->cfg.shellcode_detector.windivert_tcp_ports_parsed_count
          : (size_t)((agent->cfg.shellcode_detector.monitor_smb ? 1 : 0) +
                     (agent->cfg.shellcode_detector.monitor_rdp ? 1 : 0) +
                     (agent->cfg.shellcode_detector.monitor_winrm ? 1 : 0) +
                     (agent->cfg.shellcode_detector.monitor_msrpc ? 1 : 0) +
                     (agent->cfg.shellcode_detector.monitor_ldap ? 1 : 0) +
                     (agent->cfg.shellcode_detector.monitor_tls ? 1 : 0)),
      agent->cfg.shellcode_detector.detector_threads, agent->cfg.shellcode_detector.max_payload_inspect,
      shell_version[0] ? shell_version : "builtin-embedded", shell_source[0] ? shell_source : "builtin",
      shell_rules.files_loaded, (unsigned long long)shell_rules.last_reload_unix_s,
      shell_rules.gray_percent, shell_rules.rollback_available ? "true" : "false",
      shell_rules.rollback_active ? "true" : "false", shell_rb,
      (unsigned long long)shell_rules.matches_total, (unsigned long long)shell_rules.yara_matches,
      (unsigned long long)shell_rules.builtin_matches, (unsigned long long)shell_rules.gray_shadow_matches,
      shell_last_rule, shell_last_src, shell_error,
      shell_error[0] ? "rules_error" : "",
      agent->cfg.webshell_detector.enabled ? "true" : "false", agent->cfg.webshell_detector.max_watch_dirs,
      agent->cfg.webshell_detector.max_file_size_mb, agent->cfg.webshell_detector.scan_threads,
      "", evidence_json);
  if (n > 0 && (size_t)n < sizeof(body)) {
    (void)edr_ingest_http_post_engine_health_json(body);
  }
}

void edr_agent_shutdown(EdrAgent *agent) {
  if (!agent) {
    return;
  }
  agent->shutdown = 1;
}

const EdrConfig *edr_agent_get_config(const EdrAgent *agent) {
  if (!agent) {
    return NULL;
  }
  return &agent->cfg;
}

EdrEventBus *edr_agent_event_bus(EdrAgent *agent) {
  if (!agent) {
    return NULL;
  }
  return agent->event_bus;
}

static void edr_agent_poll_config_reload(EdrAgent *agent, uint64_t *last_reload_ns) {
  const char *rs = getenv("EDR_CONFIG_RELOAD_S");
  if (!agent->config_path || !agent->config_path[0] || !rs || rs[0] == '0') {
    return;
  }
  int interval = atoi(rs);
  if (interval < 1) {
    interval = 2;
  }
  uint64_t now = edr_monotonic_ns();
  if (now - *last_reload_ns < (uint64_t)interval * 1000000000ULL) {
    return;
  }
  *last_reload_ns = now;
  int rel = 0;
  EdrError cr =
      edr_config_reload_if_modified(agent->config_path, &agent->cfg, &agent->config_mtime, &rel);
  if (cr == EDR_OK && rel) {
    edr_agent_clear_config_recovery(agent);
    (void)edr_agent_save_last_good_config(agent, agent->config_path);
    edr_preprocess_apply_config(&agent->cfg);
    edr_adaptive_collection_configure(&agent->cfg);
    edr_agent_apply_event_filter_config(&agent->cfg);
    edr_resource_init(&agent->cfg);
    edr_self_protect_apply_config(&agent->cfg);
    agent->asurf_last_post_ns = 0;
    {
      const char *post_reload = getenv("EDR_ATTACK_SURFACE_POST_ON_CONFIG_RELOAD");
      if (post_reload && post_reload[0] == '1' && agent->cfg.attack_surface.enabled &&
          agent->cfg.agent.endpoint_id[0] && strcmp(agent->cfg.agent.endpoint_id, "auto") != 0) {
        char d[256];
        int sr = edr_attack_surface_execute("config_reload", &agent->cfg, d, sizeof(d));
        if (sr != 0) {
          fprintf(stderr, "[attack_surface] config_reload POST failed: %s\n", d);
        } else if (strncmp(d, "uploaded_", 9) == 0) {
          fprintf(stderr, "[attack_surface] config_reload %s\n", d);
        }
      }
    }
    {
      int av = AVE_SyncFromEdrConfig(&agent->cfg);
      if (av != AVE_OK && av != AVE_ERR_NOT_INITIALIZED) {
        fprintf(stderr, "[ave] AVE_SyncFromEdrConfig failed: %d\n", av);
      }
    }
    fprintf(stderr,
            "[config] hot reload applied: preprocessing + event_filter + resource_limit + self_protect + attack_surface tick + ave\n");
    char fp[80];
    edr_config_fingerprint(agent->config_path, fp, sizeof(fp));
    if (fp[0]) {
      fprintf(stderr, "[config] hot reload fingerprint=%s\n", fp);
    }
  }
}

static int edr_agent_toml_has_section(const char *path, const char *section) {
  FILE *fp;
  char line[256];
  char needle[96];
  size_t nlen;
  if (!path || !path[0] || !section || !section[0]) {
    return 0;
  }
  snprintf(needle, sizeof(needle), "[%s]", section);
  nlen = strlen(needle);
  fp = fopen(path, "r");
  if (!fp) {
    return 0;
  }
  while (fgets(line, sizeof(line), fp)) {
    char *p = line;
    while (*p == ' ' || *p == '\t') {
      p++;
    }
    if (*p == '#' || *p == '\0' || p[0] != '[' || p[1] == '[') {
      continue;
    }
    if (strncmp(p, needle, nlen) == 0) {
      char tail = p[nlen];
      if (tail == '\0' || tail == '\r' || tail == '\n' || tail == ' ' || tail == '\t' || tail == '#') {
        fclose(fp);
        return 1;
      }
    }
  }
  fclose(fp);
  return 0;
}

static int edr_collection_policy_changed(const EdrConfig *current, const EdrConfig *remote) {
  if (!current || !remote) {
    return 0;
  }
  return current->collection.etw_enabled != remote->collection.etw_enabled ||
         current->collection.etw_dns_client_provider != remote->collection.etw_dns_client_provider ||
         current->collection.etw_powershell_provider != remote->collection.etw_powershell_provider ||
         current->collection.etw_amsi_provider != remote->collection.etw_amsi_provider ||
         current->collection.etw_schannel_provider != remote->collection.etw_schannel_provider ||
         current->collection.etw_security_audit_provider != remote->collection.etw_security_audit_provider ||
         current->collection.etw_wmi_provider != remote->collection.etw_wmi_provider ||
         current->collection.etw_tcpip_provider != remote->collection.etw_tcpip_provider ||
         current->collection.etw_firewall_provider != remote->collection.etw_firewall_provider;
}

static void edr_agent_restart_collector(EdrAgent *agent) {
  if (!agent || !agent->event_bus) {
    return;
  }
  if (agent->collector_started) {
    edr_collector_stop();
    agent->collector_started = 0;
  }
  if (!edr_agent_collection_enabled(&agent->cfg)) {
    fprintf(stderr, "[collector] remote policy disabled collection; collector stopped\n");
    return;
  }
  {
    EdrError e = edr_collector_start(agent->event_bus, &agent->cfg);
    if (e != EDR_OK) {
      fprintf(stderr, "[collector] remote policy restart failed: %d; continuing in degraded mode\n", (int)e);
      return;
    }
    agent->collector_started = 1;
    fprintf(stderr, "[collector] remote policy applied; collector restarted\n");
  }
}

static int edr_agent_apply_remote_policy(EdrAgent *agent, const EdrConfig *remote, const char *tmp) {
  int changed = 0;
  if (!agent || !remote || !tmp || !tmp[0]) {
    return 0;
  }
  if (edr_agent_toml_has_section(tmp, "preprocessing")) {
    snprintf(agent->cfg.preprocessing.rules_version, sizeof(agent->cfg.preprocessing.rules_version), "%s",
             remote->preprocessing.rules_version);
  }
  if (edr_agent_toml_has_section(tmp, "collection")) {
    if (edr_collection_policy_changed(&agent->cfg, remote)) {
      changed |= EDR_REMOTE_POLICY_COLLECTION_CHANGED;
    }
    if (agent->cfg.collection.max_event_queue_size != remote->collection.max_event_queue_size) {
      fprintf(stderr, "[config] remote max_event_queue_size changed; applies after agent restart\n");
    }
    agent->cfg.collection.etw_enabled = remote->collection.etw_enabled;
    agent->cfg.collection.etw_dns_client_provider = remote->collection.etw_dns_client_provider;
    agent->cfg.collection.etw_powershell_provider = remote->collection.etw_powershell_provider;
    agent->cfg.collection.etw_amsi_provider = remote->collection.etw_amsi_provider;
    agent->cfg.collection.etw_schannel_provider = remote->collection.etw_schannel_provider;
    agent->cfg.collection.etw_security_audit_provider = remote->collection.etw_security_audit_provider;
    agent->cfg.collection.etw_wmi_provider = remote->collection.etw_wmi_provider;
    agent->cfg.collection.etw_tcpip_provider = remote->collection.etw_tcpip_provider;
    agent->cfg.collection.etw_firewall_provider = remote->collection.etw_firewall_provider;
    agent->cfg.collection.max_event_queue_size = remote->collection.max_event_queue_size;
    agent->cfg.collection.adaptive_enabled = remote->collection.adaptive_enabled;
    agent->cfg.collection.adaptive_boost_seconds = remote->collection.adaptive_boost_seconds;
    agent->cfg.collection.adaptive_min_severity = remote->collection.adaptive_min_severity;
    edr_adaptive_collection_configure(&agent->cfg);
  }
  if (edr_agent_toml_has_section(tmp, "event_filter")) {
    agent->cfg.event_filter = remote->event_filter;
    edr_agent_apply_event_filter_config(&agent->cfg);
  }
  if (edr_agent_toml_has_section(tmp, "upload")) {
    agent->cfg.upload = remote->upload;
  }
  if (edr_agent_toml_has_section(tmp, "resource_limit")) {
    agent->cfg.resource_limit = remote->resource_limit;
  }
  if (edr_agent_toml_has_section(tmp, "health_monitor")) {
    agent->cfg.health_monitor = remote->health_monitor;
  }
  if (edr_agent_toml_has_section(tmp, "command")) {
    char local_command_signing_public_key_path[sizeof(agent->cfg.command.signing_public_key_path)];
    char local_command_signing_public_key_pem[sizeof(agent->cfg.command.signing_public_key_pem)];
    snprintf(local_command_signing_public_key_path, sizeof(local_command_signing_public_key_path), "%s",
             agent->cfg.command.signing_public_key_path);
    snprintf(local_command_signing_public_key_pem, sizeof(local_command_signing_public_key_pem), "%s",
             agent->cfg.command.signing_public_key_pem);
    agent->cfg.command = remote->command;
    if (!agent->cfg.command.signing_public_key_path[0] && !agent->cfg.command.signing_public_key_pem[0]) {
      snprintf(agent->cfg.command.signing_public_key_path, sizeof(agent->cfg.command.signing_public_key_path), "%s",
               local_command_signing_public_key_path);
      snprintf(agent->cfg.command.signing_public_key_pem, sizeof(agent->cfg.command.signing_public_key_pem), "%s",
               local_command_signing_public_key_pem);
      if (agent->cfg.command.signing_public_key_path[0] || agent->cfg.command.signing_public_key_pem[0]) {
        fprintf(stderr, "[config] remote command policy omitted signing public key; preserved local command key material\n");
      }
    }
  }
  if (edr_agent_toml_has_section(tmp, "forensic_auto")) {
    agent->cfg.forensic_auto = remote->forensic_auto;
  }
  if (edr_agent_toml_has_section(tmp, "platform")) {
    snprintf(agent->cfg.platform.proxy_mode, sizeof(agent->cfg.platform.proxy_mode), "%s",
             remote->platform.proxy_mode);
    snprintf(agent->cfg.platform.proxy_url, sizeof(agent->cfg.platform.proxy_url), "%s",
             remote->platform.proxy_url);
    snprintf(agent->cfg.platform.relay_url, sizeof(agent->cfg.platform.relay_url), "%s",
             remote->platform.relay_url);
  }
  if (edr_agent_toml_has_section(tmp, "ave")) {
    agent->cfg.ave.behavior_monitor_enabled = false;
    agent->cfg.ave.static_model_enabled = remote->ave.static_model_enabled;
    agent->cfg.ave.scan_threads = remote->ave.scan_threads;
    agent->cfg.ave.max_file_size_mb = remote->ave.max_file_size_mb;
    snprintf(agent->cfg.ave.sensitivity, sizeof(agent->cfg.ave.sensitivity), "%s", remote->ave.sensitivity);
  }
  if (edr_agent_toml_has_section(tmp, "attack_surface")) {
    agent->cfg.attack_surface.enabled = remote->attack_surface.enabled;
  }
  if (edr_agent_toml_has_section(tmp, "self_protect")) {
    agent->cfg.self_protect.event_bus_pressure_warn_pct = remote->self_protect.event_bus_pressure_warn_pct;
  }
  return changed;
}

static void edr_agent_poll_remote_config(EdrAgent *agent, uint64_t *last_remote_ns) {
  const char *url = getenv("EDR_REMOTE_CONFIG_URL");
  const char *auto_pull = getenv("EDR_REMOTE_CONFIG_AUTO_PULL");
  const char *ps = getenv("EDR_REMOTE_CONFIG_POLL_S");
  char derived[768];
  int interval = 1800;
  if (!agent) {
    return;
  }
  if (auto_pull && (auto_pull[0] == '0' || auto_pull[0] == 'n' || auto_pull[0] == 'N')) {
    return;
  }
  if (!url || !url[0]) {
    const char *base = agent->cfg.platform.relay_url[0]
                           ? agent->cfg.platform.relay_url
                           : agent->cfg.platform.rest_base_url;
    if (!base[0]) {
      return;
    }
    snprintf(derived, sizeof(derived), "%s/agent/runtime-policy.toml", base);
    url = derived;
  }
  if (ps && ps[0]) {
    int v = atoi(ps);
    if (v >= 60 && v <= 86400) {
      interval = v;
    }
  }
  uint64_t now = edr_monotonic_ns();
  if (*last_remote_ns != 0u &&
      now - *last_remote_ns < (uint64_t)interval * 1000000000ULL) {
    return;
  }
  *last_remote_ns = now;

  char tmp[520];
#ifdef _WIN32
  const char *t = getenv("TEMP");
  if (!t || !t[0]) {
    t = ".";
  }
  snprintf(tmp, sizeof(tmp), "%s\\edr_remote_%lu.toml", t, (unsigned long)GetCurrentProcessId());
#else
  snprintf(tmp, sizeof(tmp), "/tmp/edr_remote_%d.toml", (int)getpid());
#endif
  EdrAgentConfigHeaders config_headers;
  memset(&config_headers, 0, sizeof(config_headers));
  if (edr_agent_download_text_file(url, tmp, 1024u * 1024u, "remote TOML", &config_headers) != 0) {
    return;
  }
  {
    char verify_reason[192];
    if (edr_agent_verify_config_headers(&agent->cfg, agent->cfg.offline.queue_db_path, tmp, &config_headers, verify_reason, sizeof(verify_reason)) != 0) {
      fprintf(stderr, "[config] remote TOML signature rejected: %s\n", verify_reason);
      (void)edr_ingest_http_post_config_status(agent->cfg.agent.tenant_id,
                                               agent->cfg.agent.endpoint_id,
                                               EDR_AGENT_VERSION_STRING,
                                               config_headers.sequence[0] ? agent->cfg.preprocessing.rules_version : "local",
                                               config_headers.config_hash,
                                               config_headers.sequence,
                                               config_headers.nonce,
                                               config_headers.signature,
                                               config_headers.signing_key_id,
                                               0,
                                               verify_reason,
                                               agent->cfg.preprocessing.rules_version,
                                               config_headers.config_hash,
                                               "failed",
                                               0);
      (void)remove(tmp);
      return;
    }
  }

  EdrConfig remote;
  memset(&remote, 0, sizeof(remote));
  EdrError ce = edr_config_load(tmp, &remote);
  char fp[80];
  int changed = 0;
  int was_recovering = agent->config_recovery_active;
  char repaired_local_config[1100];
  repaired_local_config[0] = '\0';
  edr_config_fingerprint(tmp, fp, sizeof(fp));
  if (ce != EDR_OK) {
    fprintf(stderr, "[config] remote TOML parse failed: %d\n", (int)ce);
    (void)remove(tmp);
    return;
  }
  changed = edr_agent_apply_remote_policy(agent, &remote, tmp);
  edr_config_free_heap(&remote);
  (void)remove(tmp);
  if ((changed & EDR_REMOTE_POLICY_COLLECTION_CHANGED) != 0) {
    edr_agent_restart_collector(agent);
  }
  edr_preprocess_apply_config(&agent->cfg);
  edr_resource_init(&agent->cfg);
  edr_self_protect_apply_config(&agent->cfg);
  edr_ingest_http_set_policy_version(agent->cfg.preprocessing.rules_version);
  if (was_recovering && agent->config_path && agent->config_path[0] &&
      edr_agent_write_config_snapshot(agent->config_path, &agent->cfg) == 0) {
    snprintf(repaired_local_config, sizeof(repaired_local_config), "%s", agent->config_path);
  }
  edr_agent_clear_config_recovery(agent);
  if (edr_agent_save_last_good_snapshot(agent) == 0) {
    agent->config_recovery_auto_repaired = 1;
    snprintf(agent->config_recovery_mode, sizeof(agent->config_recovery_mode), "%s", "remote_repaired");
    if (repaired_local_config[0]) {
      snprintf(agent->config_recovery_recovered_path, sizeof(agent->config_recovery_recovered_path),
               "%s", repaired_local_config);
    }
  }
  if (config_headers.sequence[0] || config_headers.config_hash[0]) {
    long long seq = atoll(config_headers.sequence);
    if (seq > 0) {
      edr_agent_write_config_sequence_state(agent->cfg.offline.queue_db_path, seq);
    }
    (void)edr_ingest_http_post_config_status(agent->cfg.agent.tenant_id,
                                             agent->cfg.agent.endpoint_id,
                                             EDR_AGENT_VERSION_STRING,
                                             agent->cfg.preprocessing.rules_version,
                                             config_headers.config_hash,
                                             config_headers.sequence,
                                             config_headers.nonce,
                                             config_headers.signature,
                                             config_headers.signing_key_id,
                                             1,
                                             "",
                                             agent->cfg.preprocessing.rules_version,
                                             config_headers.config_hash,
                                             "applied",
                                             (changed & EDR_REMOTE_POLICY_COLLECTION_CHANGED) != 0);
    fprintf(stderr, "[config] signed remote policy applied sequence=%s hash=%s rollout=%s/%s\n",
            config_headers.sequence[0] ? config_headers.sequence : "0",
            config_headers.config_hash[0] ? config_headers.config_hash : "-",
            config_headers.rollout_id[0] ? config_headers.rollout_id : "-",
            config_headers.rollout_bucket[0] ? config_headers.rollout_bucket : "-");
  }
  {
    const char *post_reload = getenv("EDR_ATTACK_SURFACE_POST_ON_CONFIG_RELOAD");
    if (post_reload && post_reload[0] == '1' && agent->cfg.attack_surface.enabled &&
        agent->cfg.agent.endpoint_id[0] && strcmp(agent->cfg.agent.endpoint_id, "auto") != 0) {
      char d[256];
      int sr = edr_attack_surface_execute("config_reload", &agent->cfg, d, sizeof(d));
      if (sr != 0) {
        fprintf(stderr, "[attack_surface] remote config_reload POST failed: %s\n", d);
      } else if (strncmp(d, "uploaded_", 9) == 0) {
        fprintf(stderr, "[attack_surface] remote config_reload %s\n", d);
      }
    }
  }
  {
    uint64_t t0 = edr_monotonic_ns();
    agent->asurf_last_post_ns = t0;
    agent->asurf_last_pending_check_ns = t0;
  }
  {
    int av = AVE_SyncFromEdrConfig(&agent->cfg);
    if (av != AVE_OK && av != AVE_ERR_NOT_INITIALIZED) {
      fprintf(stderr, "[ave] AVE_SyncFromEdrConfig(remote) failed: %d\n", av);
    }
  }
  fprintf(stderr,
          "[config] remote policy applied: preprocessing + event_filter + resource_limit + self_protect + attack_surface tick + ave");
  if (fp[0]) {
    fprintf(stderr, " fingerprint=%s", fp);
  }
  fprintf(stderr, "\n");
}

static void edr_agent_poll_p0_bundle(EdrAgent *agent, uint64_t *last_p0_bundle_ns) {
  const char *url = getenv("EDR_P0_BUNDLE_URL");
  const char *auto_pull = getenv("EDR_P0_BUNDLE_AUTO_PULL");
  const char *iv = getenv("EDR_P0_BUNDLE_POLL_S");
  int interval = 1800;
  uint64_t now;
  char derived[768];
  char tmp[520];
  char dst[2048];
  const char *base;
  if (!agent || !last_p0_bundle_ns) {
    return;
  }
  if (auto_pull && (auto_pull[0] == '0' || auto_pull[0] == 'n' || auto_pull[0] == 'N')) {
    return;
  }
  if (!url || !url[0]) {
    base = agent->cfg.platform.relay_url[0]
               ? agent->cfg.platform.relay_url
               : agent->cfg.platform.rest_base_url;
    if (!base[0]) {
      return;
    }
    snprintf(derived, sizeof(derived), "%s/agent/p0-bundle.enc", base);
    url = derived;
  }
  if (iv && iv[0]) {
    int v = atoi(iv);
    if (v >= 60 && v <= 86400) {
      interval = v;
    }
  }
  now = edr_monotonic_ns();
  if (*last_p0_bundle_ns != 0u &&
      now - *last_p0_bundle_ns < (uint64_t)interval * 1000000000ULL) {
    return;
  }
  *last_p0_bundle_ns = now;

#ifdef _WIN32
  {
    const char *t = getenv("TEMP");
    if (!t || !t[0]) {
      t = ".";
    }
    snprintf(tmp, sizeof(tmp), "%s\\edr_p0_bundle_%lu.enc", t, (unsigned long)GetCurrentProcessId());
  }
#else
  snprintf(tmp, sizeof(tmp), "/tmp/edr_p0_bundle_%d.enc", (int)getpid());
#endif

  if (edr_agent_download_text_file(url, tmp, 4u * 1024u * 1024u, "P0 bundle", NULL) != 0) {
    return;
  }
  if (!edr_agent_file_has_magic(tmp, "EDR1", 4u)) {
    fprintf(stderr, "[p0_rule_ir] remote bundle rejected: missing EDR1 header\n");
    (void)remove(tmp);
    return;
  }
  if (edr_p0_bundle_dst_path(dst, sizeof(dst)) != 0 || !dst[0]) {
    fprintf(stderr, "[p0_rule_ir] remote bundle rejected: cannot resolve destination path\n");
    (void)remove(tmp);
    return;
  }
  if (edr_agent_files_equal(tmp, dst)) {
    (void)remove(tmp);
    return;
  }
  if (edr_agent_replace_file(tmp, dst) != 0) {
    fprintf(stderr, "[p0_rule_ir] remote bundle install failed: %s\n", dst);
    (void)remove(tmp);
    return;
  }
  edr_p0_rule_ir_reload();
  {
    const char *source = "";
    const char *sha = "";
    size_t plain_size = 0u;
    (void)edr_p0_rule_ir_get_bundle_info(&source, &plain_size, &sha);
    fprintf(stderr, "[p0_rule_ir] remote bundle applied: rules=%d sha256=%s source=%s\n",
            edr_p0_rule_ir_rule_count(), sha && sha[0] ? sha : "unknown",
            source && source[0] ? source : dst);
    (void)plain_size;
  }
}

static void edr_agent_poll_sensor_interest(EdrAgent *agent, uint64_t *last_sensor_interest_ns) {
  const char *url = getenv("EDR_SENSOR_INTEREST_URL");
  const char *auto_pull = getenv("EDR_SENSOR_INTEREST_AUTO_PULL");
  int interval = 1800;
  const char *iv = getenv("EDR_SENSOR_INTEREST_POLL_S");
  uint64_t now;
  char derived[768];
  char tmp[520];
  if (!agent || !last_sensor_interest_ns) {
    return;
  }
  if (auto_pull && (auto_pull[0] == '0' || auto_pull[0] == 'n' || auto_pull[0] == 'N')) {
    return;
  }
  if (!url || !url[0]) {
    const char *base = agent->cfg.platform.relay_url[0]
                           ? agent->cfg.platform.relay_url
                           : agent->cfg.platform.rest_base_url;
    if (!base[0]) {
      return;
    }
    snprintf(derived, sizeof(derived), "%s/agent/sensor-interest.json", base);
    url = derived;
  }
  if (iv && iv[0]) {
    int v = atoi(iv);
    if (v >= 60 && v <= 86400) {
      interval = v;
    }
  }
  now = edr_monotonic_ns();
  if (*last_sensor_interest_ns != 0u &&
      now - *last_sensor_interest_ns < (uint64_t)interval * 1000000000ULL) {
    return;
  }
  *last_sensor_interest_ns = now;

#ifdef _WIN32
  {
    const char *t = getenv("TEMP");
    if (!t || !t[0]) {
      t = ".";
    }
    snprintf(tmp, sizeof(tmp), "%s\\edr_sensor_interest_%lu.json", t, (unsigned long)GetCurrentProcessId());
    if (edr_agent_download_text_file(url, tmp, 1024u * 1024u, "sensor interest", NULL) != 0) {
      return;
    }
  }
#else
  {
    snprintf(tmp, sizeof(tmp), "/tmp/edr_sensor_interest_%d.json", (int)getpid());
    if (edr_agent_download_text_file(url, tmp, 1024u * 1024u, "sensor interest", NULL) != 0) {
      return;
    }
  }
#endif
  if (edr_sensor_interest_replace_manifest_from_file(tmp) == 0) {
    fprintf(stderr, "[sensor_interest] remote manifest applied\n");
  }
  (void)remove(tmp);
}

/**
 * §19.8 周期快照：仅当 `[attack_surface].enabled=true` 时，按
 * `edr_attack_surface_effective_periodic_interval_s`（`min(port, service, policy, full)`，钳 60～604800s）
 * 调用 `edr_attack_surface_execute`（与 Subscribe 指令路径共用实现）。
 * 按需刷新：按 `conn_interval_s`（钳 15～120s）轮询 GET .../attack-surface/refresh-request。
 */
static void edr_agent_poll_attack_surface(EdrAgent *agent) {
  if (!agent || agent->shutdown) {
    return;
  }
  const EdrConfig *cfg = &agent->cfg;
  if (!cfg->attack_surface.enabled) {
    return;
  }
  if (!cfg->agent.endpoint_id[0] || strcmp(cfg->agent.endpoint_id, "auto") == 0) {
    return;
  }

  uint64_t now = edr_monotonic_ns();

  if (cfg->attack_surface.etw_refresh_triggers_snapshot) {
    uint32_t ds = cfg->attack_surface.etw_refresh_debounce_s;
    if (ds < 1u) {
      ds = 1u;
    }
    if (ds > 300u) {
      ds = 300u;
    }
    uint64_t debounce_ns = (uint64_t)ds * 1000000000ULL;
    if (edr_attack_surface_take_etw_flush(now, debounce_ns)) {
      char detail[256];
      int r = edr_attack_surface_execute("etw_tcpip_wf", cfg, detail, sizeof(detail));
      if (r != 0) {
        fprintf(stderr, "[attack_surface] etw_tcpip_wf failed: %s\n", detail);
      } else if (strncmp(detail, "uploaded_", 9) == 0) {
        fprintf(stderr, "[attack_surface] etw_tcpip_wf %s\n", detail);
      }
    }
  }

  uint32_t pend_iv = cfg->attack_surface.conn_interval_s;
  if (pend_iv < 15u) {
    pend_iv = 15u;
  }
  if (pend_iv > 120u) {
    pend_iv = 120u;
  }
  const uint64_t pend_iv_ns = (uint64_t)pend_iv * 1000000000ULL;
  if (now - agent->asurf_last_pending_check_ns >= pend_iv_ns) {
    agent->asurf_last_pending_check_ns = now;
    int pr = edr_attack_surface_refresh_pending(cfg);
    if (pr == 1) {
      char detail[256];
      int r = edr_attack_surface_execute("refresh_request", cfg, detail, sizeof(detail));
      if (r != 0) {
        fprintf(stderr, "[attack_surface] refresh_request failed: %s\n", detail);
      } else if (strncmp(detail, "uploaded_", 9) == 0) {
        fprintf(stderr, "[attack_surface] refresh_request %s\n", detail);
      }
    }
  }

  uint32_t sec = edr_attack_surface_effective_periodic_interval_s(cfg);
  const uint64_t interval_ns = (uint64_t)sec * 1000000000ULL;

  if (now - agent->asurf_last_post_ns < interval_ns) {
    return;
  }
  agent->asurf_last_post_ns = now;

  char detail[256];
  int r = edr_attack_surface_execute("periodic_attack_surface", cfg, detail, sizeof(detail));
  if (r != 0) {
    fprintf(stderr, "[attack_surface] periodic failed: %s\n", detail);
    return;
  }
  if (strncmp(detail, "uploaded_", 9) == 0) {
    fprintf(stderr, "[attack_surface] periodic %s\n", detail);
  }
}
