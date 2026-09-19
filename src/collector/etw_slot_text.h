#ifndef EDR_ETW_SLOT_TEXT_H
#define EDR_ETW_SLOT_TEXT_H

#include "edr/types.h"
#include <stdio.h>
#include <string.h>

typedef enum { EDR_SLOT_KV_APPENDED, EDR_SLOT_KV_EMPTY, EDR_SLOT_KV_NO_SPACE,
               EDR_SLOT_KV_VALUE_TOO_LONG } EdrSlotKvResult;

/* Shared production ETW1 boundary, also exercised without a Windows session. */
static inline void edr_etw1_sanitize_value(char *dst, size_t cap, const char *src) {
  size_t off = 0u;
  if (!dst || !cap) return;
  dst[0] = '\0';
  if (!src) return;
  while (*src && off + 1u < cap) {
    unsigned char c = (unsigned char)*src++;
    dst[off++] = (c == '\r' || c == '\n') ? ' ' : (char)c;
  }
  dst[off] = '\0';
}

static inline EdrSlotKvResult edr_collector_slot_append_kv(
    EdrEventSlot *slot, const char *key, const char *value) {
  /* The event envelope is the capacity authority. An unrelated 2 KiB
   * scratch limit rejected commands that fit both the envelope and record. */
  char safe[EDR_MAX_EVENT_PAYLOAD];
  size_t used;
  int n;
  if (!slot || !key || !key[0] || !value || !value[0]) return EDR_SLOT_KV_EMPTY;
  used = strnlen((const char *)slot->data, sizeof(slot->data));
  if (used >= sizeof(slot->data) - 4u) return EDR_SLOT_KV_NO_SPACE;
  if (strlen(value) >= sizeof(safe)) return EDR_SLOT_KV_VALUE_TOO_LONG;
  edr_etw1_sanitize_value(safe, sizeof(safe), value);
  n = snprintf(NULL, 0, "%s%s=%s\n",
               (used && slot->data[used - 1u] != '\n') ? "\n" : "", key, safe);
  if (n <= 0 || used + (size_t)n >= sizeof(slot->data)) return EDR_SLOT_KV_NO_SPACE;
  n = snprintf((char *)slot->data + used, sizeof(slot->data) - used, "%s%s=%s\n",
               (used && slot->data[used - 1u] != '\n') ? "\n" : "", key, safe);
  slot->size = (uint32_t)(used + (size_t)n + 1u);
  return EDR_SLOT_KV_APPENDED;
}

#endif
