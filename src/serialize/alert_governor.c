#include "edr/alert_governor.h"

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

static struct {
  int initialized;
  uint32_t endpoint_limit;
  uint32_t rule_limit;
  int64_t minute_bucket;
  uint32_t endpoint_count;
  uint64_t pending_suppressed;
  EdrAlertRuleBudget rules[EDR_ALERT_RULE_SLOTS];
  EdrAlertGovernorStats stats;
} s_governor;

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

static void extract_rule_id(const AVEBehaviorAlert *alert, char *out, size_t out_cap) {
  const char *key = "\"rule_id\"";
  const char *p;
  size_t n = 0;
  if (!out || out_cap == 0) return;
  out[0] = '\0';
  if (!alert) return;
  p = strstr(alert->user_subject_json, key);
  if (p) {
    p += strlen(key);
    while (*p && (isspace((unsigned char)*p) || *p == ':')) p++;
    if (*p == '"') {
      p++;
      while (*p && *p != '"' && n + 1 < out_cap) {
        if (*p == '\\' && p[1]) p++;
        out[n++] = *p++;
      }
      out[n] = '\0';
    }
  }
  if (!out[0] && alert->triggered_tactics[0]) {
    snprintf(out, out_cap, "tactic:%s", alert->triggered_tactics);
  }
  if (!out[0] && alert->process_name[0]) {
    snprintf(out, out_cap, "process:%s", alert->process_name);
  }
  if (!out[0]) snprintf(out, out_cap, "unclassified");
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

void edr_alert_governor_admit(const AVEBehaviorAlert *alert, int64_t now_s,
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

  governor_lock();
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
    governor_unlock();
    return;
  }

  rule = rule_budget(rule_id);
  if (s_governor.endpoint_count >= s_governor.endpoint_limit || !rule ||
      rule->count >= s_governor.rule_limit) {
    s_governor.pending_suppressed++;
    s_governor.stats.suppressed++;
    governor_unlock();
    return;
  }
  s_governor.endpoint_count++;
  rule->count++;
  s_governor.stats.admitted++;
  decision->allow_original = 1;
  governor_unlock();
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
