#include "edr/alert_governor.h"
#include "edr/sha256.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
static SRWLOCK s_governor_lock = SRWLOCK_INIT;
static void governor_lock(void) { AcquireSRWLockExclusive(&s_governor_lock); }
static void governor_unlock(void) { ReleaseSRWLockExclusive(&s_governor_lock); }
#else
#include <pthread.h>
static pthread_mutex_t s_governor_lock = PTHREAD_MUTEX_INITIALIZER;
static void governor_lock(void) { pthread_mutex_lock(&s_governor_lock); }
static void governor_unlock(void) { pthread_mutex_unlock(&s_governor_lock); }
#endif

enum { EDR_ALERT_RULE_SLOTS = 256 };

typedef struct EdrAlertRuleBudget {
  char rule_id[96];
  uint32_t count;
} EdrAlertRuleBudget;

typedef struct EdrAlertGovernorState {
  int initialized;
  uint32_t endpoint_limit;
  uint32_t rule_limit;
  int64_t minute_bucket;
  uint32_t endpoint_count;
  uint64_t pending_suppressed;
  EdrAlertRuleBudget rules[EDR_ALERT_RULE_SLOTS];
  EdrAlertGovernorStats stats;
} EdrAlertGovernorState;

static EdrAlertGovernorState s_governor;

typedef struct EdrAlertGovernorReservation {
  int active;
  int critical;
  int64_t bucket;
  char rule_id[96];
} EdrAlertGovernorReservation;

static uint32_t env_limit(const char *name, uint32_t fallback) {
  const char *raw = getenv(name);
  char *end = NULL;
  unsigned long value;
  if (!raw || !raw[0]) return fallback;
  value = strtoul(raw, &end, 10);
  if (!end || *end != '\0' || value == 0 || value > 100000UL) return fallback;
  return (uint32_t)value;
}

static int contains_case_insensitive(const char *text, const char *needle) {
  size_t needle_len;
  if (!text || !needle || !needle[0]) return 0;
  needle_len = strlen(needle);
  for (; *text; text++) {
    size_t i = 0;
    while (i < needle_len && text[i] &&
           tolower((unsigned char)text[i]) == tolower((unsigned char)needle[i])) {
      i++;
    }
    if (i == needle_len) return 1;
  }
  return 0;
}

static int copy_rule_id_literal(char *out, size_t out_cap, const char *value) {
  size_t value_len;
  if (!out || out_cap == 0u || !value) return 0;
  value_len = strlen(value);
  if (value_len + 1u > out_cap) return 0;
  memcpy(out, value, value_len + 1u);
  return value_len > 0u;
}

static int copy_rule_id_digest(char *out, size_t out_cap, const char *prefix,
                               const uint8_t *value, size_t value_len) {
  char digest[65];
  size_t prefix_len;
  if (!out || out_cap == 0u || !prefix || !value) return 0;
  prefix_len = strlen(prefix);
  if (prefix_len + sizeof(digest) > out_cap ||
      edr_sha256_hex(value, value_len, digest) != 0) {
    return 0;
  }
  memcpy(out, prefix, prefix_len);
  memcpy(out + prefix_len, digest, sizeof(digest));
  return 1;
}

static int copy_rule_id_digest_context(char *out, size_t out_cap, const char *prefix,
                                       EdrSha256Ctx *context) {
  static const char hex[] = "0123456789abcdef";
  uint8_t digest[EDR_SHA256_DIGEST_LEN];
  size_t prefix_len;
  if (!out || out_cap == 0u || !prefix || !context) return 0;
  prefix_len = strlen(prefix);
  if (prefix_len + 65u > out_cap) return 0;
  edr_sha256_final(context, digest);
  memcpy(out, prefix, prefix_len);
  for (size_t i = 0u; i < sizeof(digest); ++i) {
    out[prefix_len + i * 2u] = hex[digest[i] >> 4u];
    out[prefix_len + i * 2u + 1u] = hex[digest[i] & 0x0fu];
  }
  out[prefix_len + 64u] = '\0';
  return 1;
}

static int copy_prefixed_rule_id(char *out, size_t out_cap, const char *literal_prefix,
                                 const char *digest_prefix,
                                 const char *critical_digest_prefix,
                                 const char *value) {
  size_t prefix_len;
  size_t value_len;
  if (!out || out_cap == 0u || !literal_prefix || !digest_prefix || !value || !value[0]) {
    return 0;
  }
  prefix_len = strlen(literal_prefix);
  value_len = strlen(value);
  if (prefix_len + value_len + 1u <= out_cap) {
    memcpy(out, literal_prefix, prefix_len);
    memcpy(out + prefix_len, value, value_len + 1u);
    return 1;
  }
  if (critical_digest_prefix && contains_case_insensitive(value, "canary")) {
    digest_prefix = critical_digest_prefix;
  }
  return copy_rule_id_digest(out, out_cap, digest_prefix, (const uint8_t *)value, value_len);
}

typedef struct EdrRuleIdBuilder {
  char *out;
  size_t out_cap;
  size_t length;
  size_t canary_prefix_length;
  int contains_canary;
  EdrSha256Ctx sha256;
} EdrRuleIdBuilder;

static unsigned char ascii_lower(unsigned char value) {
  return value >= 'A' && value <= 'Z' ? (unsigned char)(value + ('a' - 'A')) : value;
}

static int rule_id_builder_append_byte(EdrRuleIdBuilder *builder, unsigned char value) {
  static const char canary[] = "canary";
  unsigned char lower;
  if (!builder || value == 0u || value < 0x20u) return 0;
  edr_sha256_update(&builder->sha256, &value, 1u);
  if (builder->length + 1u < builder->out_cap) {
    builder->out[builder->length] = (char)value;
  }
  builder->length++;
  if (builder->contains_canary) return 1;
  lower = ascii_lower(value);
  if (lower == (unsigned char)canary[builder->canary_prefix_length]) {
    builder->canary_prefix_length++;
    if (builder->canary_prefix_length == sizeof(canary) - 1u) {
      builder->contains_canary = 1;
    }
  } else {
    builder->canary_prefix_length = lower == (unsigned char)canary[0] ? 1u : 0u;
  }
  return 1;
}

static int rule_id_builder_append_codepoint(EdrRuleIdBuilder *builder, uint32_t codepoint) {
  unsigned char encoded[4];
  size_t encoded_len;
  if (codepoint == 0u || codepoint < 0x20u || codepoint > 0x10ffffu ||
      (codepoint >= 0xd800u && codepoint <= 0xdfffu)) {
    return 0;
  }
  if (codepoint <= 0x7fu) {
    encoded[0] = (unsigned char)codepoint;
    encoded_len = 1u;
  } else if (codepoint <= 0x7ffu) {
    encoded[0] = (unsigned char)(0xc0u | (codepoint >> 6u));
    encoded[1] = (unsigned char)(0x80u | (codepoint & 0x3fu));
    encoded_len = 2u;
  } else if (codepoint <= 0xffffu) {
    encoded[0] = (unsigned char)(0xe0u | (codepoint >> 12u));
    encoded[1] = (unsigned char)(0x80u | ((codepoint >> 6u) & 0x3fu));
    encoded[2] = (unsigned char)(0x80u | (codepoint & 0x3fu));
    encoded_len = 3u;
  } else {
    encoded[0] = (unsigned char)(0xf0u | (codepoint >> 18u));
    encoded[1] = (unsigned char)(0x80u | ((codepoint >> 12u) & 0x3fu));
    encoded[2] = (unsigned char)(0x80u | ((codepoint >> 6u) & 0x3fu));
    encoded[3] = (unsigned char)(0x80u | (codepoint & 0x3fu));
    encoded_len = 4u;
  }
  for (size_t i = 0u; i < encoded_len; ++i) {
    if (!rule_id_builder_append_byte(builder, encoded[i])) return 0;
  }
  return 1;
}

static int json_hex4(const unsigned char *input, const unsigned char *end, uint32_t *value) {
  uint32_t result = 0u;
  if (!input || !end || !value || (size_t)(end - input) < 4u) return 0;
  for (size_t i = 0u; i < 4u; ++i) {
    unsigned char ch = input[i];
    if (ch >= '0' && ch <= '9') {
      result = (result << 4u) | (uint32_t)(ch - '0');
    } else if (ch >= 'a' && ch <= 'f') {
      result = (result << 4u) | (uint32_t)(ch - 'a' + 10u);
    } else if (ch >= 'A' && ch <= 'F') {
      result = (result << 4u) | (uint32_t)(ch - 'A' + 10u);
    } else {
      return 0;
    }
  }
  *value = result;
  return 1;
}

static int json_utf8_codepoint(const unsigned char *input, const unsigned char *end,
                               uint32_t *codepoint, size_t *consumed) {
  unsigned char first;
  size_t available;
  if (!input || !end || !codepoint || !consumed || input >= end) return 0;
  first = input[0];
  available = (size_t)(end - input);
  if (first >= 0xc2u && first <= 0xdfu && available >= 2u &&
      (input[1] & 0xc0u) == 0x80u) {
    *codepoint = ((uint32_t)(first & 0x1fu) << 6u) | (uint32_t)(input[1] & 0x3fu);
    *consumed = 2u;
    return 1;
  }
  if (first >= 0xe0u && first <= 0xefu && available >= 3u &&
      (input[1] & 0xc0u) == 0x80u && (input[2] & 0xc0u) == 0x80u &&
      !(first == 0xe0u && input[1] < 0xa0u) &&
      !(first == 0xedu && input[1] >= 0xa0u)) {
    *codepoint = ((uint32_t)(first & 0x0fu) << 12u) |
                 ((uint32_t)(input[1] & 0x3fu) << 6u) | (uint32_t)(input[2] & 0x3fu);
    *consumed = 3u;
    return 1;
  }
  if (first >= 0xf0u && first <= 0xf4u && available >= 4u &&
      (input[1] & 0xc0u) == 0x80u && (input[2] & 0xc0u) == 0x80u &&
      (input[3] & 0xc0u) == 0x80u && !(first == 0xf0u && input[1] < 0x90u) &&
      !(first == 0xf4u && input[1] > 0x8fu)) {
    *codepoint = ((uint32_t)(first & 0x07u) << 18u) |
                 ((uint32_t)(input[1] & 0x3fu) << 12u) |
                 ((uint32_t)(input[2] & 0x3fu) << 6u) | (uint32_t)(input[3] & 0x3fu);
    *consumed = 4u;
    return 1;
  }
  return 0;
}

static int copy_json_rule_id(char *out, size_t out_cap, const char *value) {
  const unsigned char *cursor;
  const unsigned char *end;
  EdrRuleIdBuilder builder;
  int complete = 0;
  if (!out || out_cap == 0u || !value) return 0;
  out[0] = '\0';
  cursor = (const unsigned char *)value;
  end = cursor + strlen(value);
  memset(&builder, 0, sizeof(builder));
  builder.out = out;
  builder.out_cap = out_cap;
  edr_sha256_init(&builder.sha256);
  while (cursor < end) {
    unsigned char ch = *cursor++;
    uint32_t codepoint;
    size_t consumed;
    if (ch == '"') {
      complete = 1;
      break;
    }
    if (ch < 0x20u) goto invalid;
    if (ch == '\\') {
      if (cursor >= end) goto invalid;
      ch = *cursor++;
      switch (ch) {
      case '"':
      case '\\':
      case '/':
        if (!rule_id_builder_append_byte(&builder, ch)) goto invalid;
        break;
      case 'b':
        if (!rule_id_builder_append_byte(&builder, '\b')) goto invalid;
        break;
      case 'f':
        if (!rule_id_builder_append_byte(&builder, '\f')) goto invalid;
        break;
      case 'n':
        if (!rule_id_builder_append_byte(&builder, '\n')) goto invalid;
        break;
      case 'r':
        if (!rule_id_builder_append_byte(&builder, '\r')) goto invalid;
        break;
      case 't':
        if (!rule_id_builder_append_byte(&builder, '\t')) goto invalid;
        break;
      case 'u':
        if (!json_hex4(cursor, end, &codepoint)) goto invalid;
        cursor += 4u;
        if (codepoint >= 0xd800u && codepoint <= 0xdbffu) {
          uint32_t low_surrogate;
          if ((size_t)(end - cursor) < 6u || cursor[0] != '\\' || cursor[1] != 'u' ||
              !json_hex4(cursor + 2u, end, &low_surrogate) || low_surrogate < 0xdc00u ||
              low_surrogate > 0xdfffu) {
            goto invalid;
          }
          codepoint = 0x10000u + ((codepoint - 0xd800u) << 10u) +
                      (low_surrogate - 0xdc00u);
          cursor += 6u;
        } else if (codepoint >= 0xdc00u && codepoint <= 0xdfffu) {
          goto invalid;
        }
        if (!rule_id_builder_append_codepoint(&builder, codepoint)) goto invalid;
        break;
      default:
        goto invalid;
      }
    } else if (ch < 0x80u) {
      if (!rule_id_builder_append_byte(&builder, ch)) goto invalid;
    } else {
      cursor--;
      if (!json_utf8_codepoint(cursor, end, &codepoint, &consumed) ||
          !rule_id_builder_append_codepoint(&builder, codepoint)) {
        goto invalid;
      }
      cursor += consumed;
    }
  }
  if (!complete || builder.length == 0u) goto invalid;
  if (builder.length + 1u <= out_cap) {
    out[builder.length] = '\0';
    return 1;
  }
  if (copy_rule_id_digest_context(
          out, out_cap, builder.contains_canary ? "canary-rule-sha256:" : "rule-sha256:",
          &builder.sha256)) {
    return 1;
  }

invalid:
  out[0] = '\0';
  return 0;
}

static void extract_rule_id(const AVEBehaviorAlert *alert, char *out, size_t out_cap) {
  const char *key = "\"rule_id\"";
  const char *p;
  if (!out || out_cap == 0) return;
  out[0] = '\0';
  if (!alert) return;
  p = strstr(alert->user_subject_json, key);
  if (p) {
    p += strlen(key);
    while (*p && (isspace((unsigned char)*p) || *p == ':')) p++;
    if (*p == '"') {
      p++;
      (void)copy_json_rule_id(out, out_cap, p);
    }
  }
  if (!out[0] && alert->triggered_tactics[0]) {
    (void)copy_prefixed_rule_id(out, out_cap, "tactic:", "tactic-sha256:",
                                 "canary-tactic-sha256:", alert->triggered_tactics);
  }
  if (!out[0] && alert->process_name[0]) {
    (void)copy_prefixed_rule_id(out, out_cap, "process:", "process-sha256:",
                                 "canary-process-sha256:", alert->process_name);
  }
  if (!out[0]) (void)copy_rule_id_literal(out, out_cap, "unclassified");
}

static int is_critical(const AVEBehaviorAlert *alert, const char *rule_id) {
  const char *iocs;
  if (!alert) return 0;
  if (contains_case_insensitive(rule_id, "canary")) return 1;
  iocs = alert->related_iocs_json;
  return contains_case_insensitive(iocs, "\"verdict\":\"malicious\"") ||
         contains_case_insensitive(iocs, "\"known_bad\":true") ||
         contains_case_insensitive(iocs, "\"malicious\":true");
}

static EdrAlertRuleBudget *rule_budget(const char *rule_id) {
  EdrAlertRuleBudget *empty = NULL;
  for (size_t i = 0; i < EDR_ALERT_RULE_SLOTS; i++) {
    if (!s_governor.rules[i].rule_id[0]) {
      if (!empty) empty = &s_governor.rules[i];
      continue;
    }
    if (strcmp(s_governor.rules[i].rule_id, rule_id) == 0) return &s_governor.rules[i];
  }
  if (empty) {
    snprintf(empty->rule_id, sizeof(empty->rule_id), "%s", rule_id);
    return empty;
  }
  return NULL;
}

static uint64_t rollover_bucket_locked(int64_t bucket) {
  uint64_t prior_suppressed;
  if (!s_governor.initialized || bucket == s_governor.minute_bucket) return 0;
  prior_suppressed = s_governor.pending_suppressed;
  memset(s_governor.rules, 0, sizeof(s_governor.rules));
  s_governor.endpoint_count = 0;
  s_governor.pending_suppressed = 0;
  s_governor.minute_bucket = bucket;
  if (prior_suppressed > 0) {
    s_governor.endpoint_count++;
    s_governor.stats.summaries++;
  }
  return prior_suppressed;
}

static void governor_admit_locked(const AVEBehaviorAlert *alert, int64_t now_s,
                                  EdrAlertGovernorDecision *decision) {
  char rule_id[96];
  EdrAlertRuleBudget *rule;
  int64_t bucket;
  if (!decision) return;
  memset(decision, 0, sizeof(*decision));
  if (!alert) return;
  if (now_s <= 0) now_s = (int64_t)time(NULL);
  bucket = now_s / 60;
  extract_rule_id(alert, rule_id, sizeof(rule_id));
  snprintf(decision->rule_id, sizeof(decision->rule_id), "%s", rule_id);

  if (!s_governor.initialized) {
    s_governor.endpoint_limit = env_limit("EDR_ALERT_MAX_PER_ENDPOINT_PER_MINUTE", 120);
    s_governor.rule_limit = env_limit("EDR_ALERT_MAX_PER_RULE_PER_MINUTE", 30);
    s_governor.minute_bucket = bucket;
    s_governor.initialized = 1;
  }
  if (bucket != s_governor.minute_bucket) {
    uint64_t prior_suppressed = rollover_bucket_locked(bucket);
    if (prior_suppressed > 0) {
      decision->emit_summary = 1;
      decision->summary_suppressed = prior_suppressed;
    }
  }

  if (is_critical(alert, rule_id)) {
    decision->allow_original = 1;
    s_governor.stats.admitted++;
    s_governor.stats.critical_bypassed++;
    return;
  }

  rule = rule_budget(rule_id);
  if (s_governor.endpoint_count >= s_governor.endpoint_limit || !rule ||
      rule->count >= s_governor.rule_limit) {
    s_governor.pending_suppressed++;
    s_governor.stats.suppressed++;
    return;
  }
  s_governor.endpoint_count++;
  rule->count++;
  s_governor.stats.admitted++;
  decision->allow_original = 1;
}

void edr_alert_governor_admit(const AVEBehaviorAlert *alert, int64_t now_s,
                              EdrAlertGovernorDecision *decision) {
  if (!decision) return;
  governor_lock();
  governor_admit_locked(alert, now_s, decision);
  governor_unlock();
}

EdrAlertGovernorEmitOutcome edr_alert_governor_admit_and_emit(
    const AVEBehaviorAlert *alert, int64_t now_s, EdrAlertGovernorEmitFn emit,
    void *context, EdrAlertGovernorDecision *decision) {
  EdrAlertGovernorReservation reservation;
  EdrAlertRuleBudget *rule;
  char rule_id[96];
  int64_t bucket;
  if (!decision || !emit) return EDR_ALERT_GOVERNOR_EMIT_INVALID;
  memset(&reservation, 0, sizeof(reservation));
  governor_lock();
  memset(decision, 0, sizeof(*decision));
  if (!alert) {
    governor_unlock();
    return EDR_ALERT_GOVERNOR_EMIT_INVALID;
  }
  if (now_s <= 0) now_s = (int64_t)time(NULL);
  bucket = now_s / 60;
  extract_rule_id(alert, rule_id, sizeof(rule_id));
  snprintf(decision->rule_id, sizeof(decision->rule_id), "%s", rule_id);
  if (!s_governor.initialized) {
    s_governor.endpoint_limit = env_limit("EDR_ALERT_MAX_PER_ENDPOINT_PER_MINUTE", 120);
    s_governor.rule_limit = env_limit("EDR_ALERT_MAX_PER_RULE_PER_MINUTE", 30);
    s_governor.minute_bucket = bucket;
    s_governor.initialized = 1;
  }
  if (bucket != s_governor.minute_bucket) {
    uint64_t prior_suppressed = rollover_bucket_locked(bucket);
    if (prior_suppressed > 0u) {
      decision->emit_summary = 1;
      decision->summary_suppressed = prior_suppressed;
    }
  }
  reservation.bucket = s_governor.minute_bucket;
  snprintf(reservation.rule_id, sizeof(reservation.rule_id), "%s", rule_id);
  reservation.critical = is_critical(alert, rule_id);
  if (reservation.critical) {
    decision->allow_original = 1;
    reservation.active = 1;
  } else {
    rule = rule_budget(rule_id);
    if (s_governor.endpoint_count >= s_governor.endpoint_limit || !rule ||
        rule->count >= s_governor.rule_limit) {
      s_governor.pending_suppressed++;
      s_governor.stats.suppressed++;
    } else {
      /* Counts are a reservation while the callback runs unlocked. They are
       * released on failure and therefore cannot leak capacity or allow a
       * concurrent caller to over-admit the same endpoint/rule budget. */
      s_governor.endpoint_count++;
      rule->count++;
      decision->allow_original = 1;
      reservation.active = 1;
    }
  }
  if (!decision->allow_original) {
    governor_unlock();
    return EDR_ALERT_GOVERNOR_EMIT_SUPPRESSED;
  }
  governor_unlock();
  /* Encoding and SQLite handoff may allocate or block; never hold governor
   * state across that I/O boundary. */
  if (!emit(context)) {
    governor_lock();
    if (reservation.active && !reservation.critical &&
        s_governor.initialized && s_governor.minute_bucket == reservation.bucket) {
      rule = rule_budget(reservation.rule_id);
      if (s_governor.endpoint_count > 0u) s_governor.endpoint_count--;
      if (rule && rule->count > 0u) rule->count--;
    }
    governor_unlock();
    return EDR_ALERT_GOVERNOR_EMIT_CALLBACK_FAILED;
  }
  governor_lock();
  if (reservation.active) {
    s_governor.stats.admitted++;
    if (reservation.critical) s_governor.stats.critical_bypassed++;
  }
  governor_unlock();
  return EDR_ALERT_GOVERNOR_EMIT_ACCEPTED;
}

int edr_alert_governor_poll_summary(int64_t now_s, uint64_t *suppressed_count) {
  uint64_t suppressed = 0;
  int64_t bucket;
  if (suppressed_count) *suppressed_count = 0;
  if (now_s <= 0) now_s = (int64_t)time(NULL);
  bucket = now_s / 60;

  governor_lock();
  if (s_governor.initialized) suppressed = rollover_bucket_locked(bucket);
  governor_unlock();

  if (suppressed_count) *suppressed_count = suppressed;
  return suppressed > 0 ? 1 : 0;
}

void edr_alert_governor_get_stats(EdrAlertGovernorStats *stats) {
  if (!stats) return;
  governor_lock();
  *stats = s_governor.stats;
  governor_unlock();
}

void edr_alert_governor_reset_for_test(void) {
  governor_lock();
  memset(&s_governor, 0, sizeof(s_governor));
  governor_unlock();
}
