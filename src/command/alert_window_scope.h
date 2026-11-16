#ifndef EDR_COMMAND_ALERT_WINDOW_SCOPE_H
#define EDR_COMMAND_ALERT_WINDOW_SCOPE_H

#include "cJSON.h"
#include "edr/local_evidence_cache.h"
#include "edr/alert_window_page.h"
#include "edr/rtq_contract.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "edr/command_result_json.h"
#define ALERT_WINDOW_COMMAND EDR_ALERT_WINDOW_COMMAND
#define ALERT_WINDOW_MAX_BYTES EDR_ALERT_WINDOW_RESULT_LIMIT
#define ALERT_WINDOW_RADIUS_NS UINT64_C(120000000000)

/* All numeric JSON tokens in either window schema are unsigned integers.
 * Reject fractional/exponent spellings before cJSON rounds to a double. */
static inline int window_wire_valid(const uint8_t *wire, size_t size) {
  if (!rtq_payload_text_valid(wire, size)) return 0;
  int quoted = 0;
  for (size_t i = 0; i < size; ++i) {
    uint8_t c = wire[i];
    if (quoted && c == '\\') {
      ++i;
      continue;
    }
    if (c == '"') {
      quoted = !quoted;
      continue;
    }
    if (quoted) continue;
    if (c == '-' || c == '+' || c == '.') return 0;
    if (c >= '0' && c <= '9') {
      size_t start = i;
      while (i + 1u < size && wire[i + 1u] >= '0' && wire[i + 1u] <= '9')
        ++i;
      if ((wire[start] == '0' && i != start) || i - start >= 10u ||
          (i + 1u < size && (wire[i + 1u] == 'e' || wire[i + 1u] == 'E')))
        return 0;
    }
  }
  return !quoted;
}

static inline const char *window_string(const cJSON *object, const char *key) {
  return cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(object, key));
}

static inline int window_decimal(const cJSON *object, const char *key, uint64_t max, uint64_t *result) {
  const char *s = window_string(object, key);
  if (!s || *s < '1' || *s > '9' || strlen(s) > 20 || s[strspn(s, "0123456789")]) return 0;
  errno = 0;
  unsigned long long value = strtoull(s, NULL, 10);
  if (errno || value > max) return 0;
  *result = (uint64_t)value;
  return 1;
}

static inline int window_uint(const cJSON *object, const char *key, uint32_t min, uint32_t max, uint32_t *result) {
  const cJSON *item = cJSON_GetObjectItemCaseSensitive(object, key);
  if (!cJSON_IsNumber(item) || !(item->valuedouble >= min && item->valuedouble <= max) ||
      item->valuedouble != (double)(uint32_t)item->valuedouble)
    return 0;
  *result = (uint32_t)item->valuedouble;
  return 1;
}

static inline int window_identifier(const char *s, size_t max) {
  if (!s || !*s) return 0;
  size_t n = strlen(s);
  return n <= max && strspn(s, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.:-") == n;
}

/* All pointers borrow the parsed purpose. Both supported shapes are closed. */
static inline int window_scope(const cJSON *request, EdrAlertWindowQuery *q) {
  uint64_t from, anchor, until;
  const cJSON *page = cJSON_GetObjectItemCaseSensitive(request, "pre_page");
  if (!cJSON_IsObject(request)) return 0;
  q->tenant_id = window_string(request, "tenant_id");
  q->endpoint_id = window_string(request, "endpoint_id");
  q->alert_id = window_string(request, "alert_id");
  q->source_event_id = window_string(request, "source_event_id");
  q->kind = window_string(request, "kind");
  int port_query = q->kind && !strcmp(q->kind, "network_port");
  q->remote_port = 0;
  if (cJSON_GetArraySize(request) != 13 + (page != NULL) + port_query ||
      (port_query ? page || !window_uint(request, "remote_port", 1, 65535, &q->remote_port)
                  : cJSON_GetObjectItemCaseSensitive(request, "remote_port") != NULL)) return 0;
  if (!window_identifier(q->tenant_id, sizeof(((EdrBehaviorRecord *)0)->tenant_id) - 1u) ||
      !window_identifier(q->endpoint_id, EDR_BR_ID_LEN - 1u) || !window_identifier(q->alert_id, 127) ||
      !window_identifier(q->source_event_id, EDR_BR_ID_LEN - 1u) || !q->kind ||
      (strcmp(q->kind, "network") && strcmp(q->kind, "registry") && !port_query) ||
      !window_uint(request, "pid", 1, UINT32_MAX, &q->pid) || !window_uint(request, "limit", 1, 50, &q->limit) ||
      !window_uint(request, "max_bytes", 512, ALERT_WINDOW_MAX_BYTES, &q->max_bytes) ||
      !window_decimal(request, "process_start_key", UINT64_MAX, &q->process_start_key) ||
      !window_decimal(request, "process_creation_filetime_100ns", UINT64_MAX, &q->process_creation_filetime_100ns) ||
      !window_decimal(request, "from_ns", INT64_MAX, &from) ||
      !window_decimal(request, "source_time_ns", INT64_MAX, &anchor) ||
      !window_decimal(request, "until_ns", INT64_MAX, &until) || from > anchor || until < anchor ||
      anchor - from > ALERT_WINDOW_RADIUS_NS || until - anchor > ALERT_WINDOW_RADIUS_NS)
    return 0;
  q->from_ns = (int64_t)from;
  q->source_time_ns = (int64_t)anchor;
  q->until_ns = (int64_t)until;
  q->pre_start_slot = 0;
  q->pre_snapshot_sha256 = q->previous_task_id = q->previous_result_sha256 = NULL;
  if (page) {
    if (!cJSON_IsObject(page) || cJSON_GetArraySize(page) != 4 ||
        !window_uint(page, "start_slot", 0, 31, &q->pre_start_slot) ||
        !(q->pre_snapshot_sha256 = window_string(page, "snapshot_sha256")) ||
        !(q->previous_task_id = window_string(page, "previous_task_id")) ||
        !(q->previous_result_sha256 = window_string(page, "previous_result_sha256"))) return 0;
  }
  return edr_window_page_valid(q);
}
/* Both objects must have passed window_scope, including canonical decimal parsing. */
static inline int window_same_scope(const EdrAlertWindowQuery *a, const EdrAlertWindowQuery *b) {
  return (a->pre_snapshot_sha256 ? b->pre_snapshot_sha256 && a->pre_start_slot == b->pre_start_slot &&
             !strcmp(a->pre_snapshot_sha256, b->pre_snapshot_sha256) && !strcmp(a->previous_task_id, b->previous_task_id) &&
             !strcmp(a->previous_result_sha256, b->previous_result_sha256) : !b->pre_snapshot_sha256) &&
         !strcmp(a->tenant_id, b->tenant_id) && !strcmp(a->endpoint_id, b->endpoint_id) &&
         !strcmp(a->alert_id, b->alert_id) && !strcmp(a->source_event_id, b->source_event_id) &&
         !strcmp(a->kind, b->kind) && a->remote_port == b->remote_port && a->pid == b->pid && a->limit == b->limit && a->max_bytes == b->max_bytes &&
         a->from_ns == b->from_ns && a->until_ns == b->until_ns && a->source_time_ns == b->source_time_ns &&
         a->process_start_key == b->process_start_key &&
         a->process_creation_filetime_100ns == b->process_creation_filetime_100ns;
}
#endif
