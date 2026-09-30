#include "../src/core/collector_health_json.h"
#include "cJSON.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static uint64_t number(const cJSON *object, const char *key) {
  const cJSON *item = cJSON_GetObjectItemCaseSensitive(object, key);
  assert(cJSON_IsNumber(item) && item->valuedouble >= 0.0);
  uint64_t value = (uint64_t)item->valuedouble;
  assert((double)value == item->valuedouble);
  return value;
}

static uint64_t reasons(const cJSON *accounting, int available, const char *unit,
                        const char *const *names, size_t count) {
  const cJSON *field = cJSON_GetObjectItemCaseSensitive(accounting, "available");
  assert(cJSON_IsBool(field) && cJSON_IsTrue(field) == available);
  field = cJSON_GetObjectItemCaseSensitive(accounting, "unit");
  assert(cJSON_IsString(field) && strcmp(field->valuestring, unit) == 0);
  const cJSON *values = cJSON_GetObjectItemCaseSensitive(accounting, "reasons");
  assert(cJSON_IsObject(values) && cJSON_GetArraySize(values) == (int)count);
  uint64_t total = 0u;
  for (size_t i = 0; i < count; ++i) total += number(values, names[i]);
  return total;
}

static void test_snapshot(int available) {
  static const char *const drops[] = {
      "slot_admission_rejected", "sensor_interest_rejected", "security_render_failed",
      "security_event_unsupported", "security_required_overflow"};
  static const char *const failures[] = {
      "invalid_event", "missing_file_key_or_schema", "actor_unavailable",
      "file_key_ambiguous", "binding_conflict", "history_discarded", "lifetime_ended",
      "path_unavailable", "object_conflict", "unknown_boundary", "no_retained_lifetime"};
  EdrCollectorHealth health = {0};
  health.disposition_accounting_available = available;
  health.queue_dropped = 7u;
  health.file_write_path_resolved = 17u;
  health.file_write_payload_incomplete = 2u;
  for (size_t i = 0u; i < EDR_COLLECTOR_DROP_REASON_COUNT; ++i) {
    health.collector_drop_reasons[i] = available ? i + 1u : 0u;
    health.collector_dropped += health.collector_drop_reasons[i];
  }
  for (size_t i = 0u; i < EDR_FILE_WRITE_UNRESOLVED_REASON_COUNT; ++i) {
    health.file_write_unresolved_reasons[i] = available ? i + 11u : 0u;
    health.file_write_path_unresolved += health.file_write_unresolved_reasons[i];
  }
  /* Platforms without these reasons preserve their existing totals and
   * explicitly refuse the complete-reason-accounting interpretation. */
  if (!available) health.collector_dropped = 31u;
  char fragment[2048], document[2100];
  assert(edr_collector_health_json(&health, fragment, sizeof(fragment)) == 0);
  assert(snprintf(document, sizeof(document), "{%s\"end\":true}", fragment) > 0);
  cJSON *parsed = cJSON_Parse(document);
  assert(parsed && cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(parsed, "end")));
  assert(number(parsed, "collector_dropped") == health.collector_dropped);
  assert(number(parsed, "queue_dropped") == 7u);
  uint64_t total = reasons(cJSON_GetObjectItemCaseSensitive(parsed, "collector_drop_accounting"),
      available, "collector_rejections", drops, sizeof(drops) / sizeof(drops[0]));
  assert(total == (available ? health.collector_dropped : 0u));
  const cJSON *writes = cJSON_GetObjectItemCaseSensitive(parsed, "file_write_collection");
  assert(number(writes, "path_resolved") == 17u);
  assert(number(writes, "payload_incomplete") == 2u);
  assert(number(writes, "path_unresolved") == health.file_write_path_unresolved);
  total = reasons(cJSON_GetObjectItemCaseSensitive(writes, "unresolved_accounting"),
      available, "file_write_callbacks", failures, sizeof(failures) / sizeof(failures[0]));
  assert(total == health.file_write_path_unresolved);
  cJSON_Delete(parsed);
  char small[16];
  assert(edr_collector_health_json(&health, small, sizeof(small)) == -1 && !small[0]);
  /* Counter width cannot overflow the shared production fragment buffer. */
  for (size_t i = 0u; i < EDR_COLLECTOR_DROP_REASON_COUNT; ++i)
    health.collector_drop_reasons[i] = UINT64_MAX;
  for (size_t i = 0u; i < EDR_FILE_WRITE_UNRESOLVED_REASON_COUNT; ++i)
    health.file_write_unresolved_reasons[i] = UINT64_MAX;
  assert(edr_collector_health_json(&health, fragment, sizeof(fragment)) == 0);
}

int main(void) {
  test_snapshot(1);
  test_snapshot(0);
  puts("collector health disposition JSON contract passed");
  return 0;
}
