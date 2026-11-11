#ifndef EDR_ALERT_WINDOW_PAGE_H
#define EDR_ALERT_WINDOW_PAGE_H

#include "edr/local_evidence_cache.h"
#include <string.h>

#define EDR_WINDOW_PRE_PAGE_SCHEMA "edr.alert-window.pre-page.v1"

static inline int edr_window_hex(const char *s, size_t bytes) {
  return s && strlen(s) == bytes && strspn(s, "0123456789abcdef") == bytes;
}

static inline int edr_window_page_valid(const EdrAlertWindowQuery *q) {
  if (!q->pre_snapshot_sha256)
    return !q->pre_start_slot && !q->previous_task_id && !q->previous_result_sha256;
  if (q->pre_start_slot >= 32 || !q->kind || strcmp(q->kind, "registry") ||
      !q->previous_task_id || !q->previous_result_sha256) return 0;
  if (!q->pre_start_slot)
    return !*q->pre_snapshot_sha256 && !*q->previous_task_id && !*q->previous_result_sha256;
  return edr_window_hex(q->pre_snapshot_sha256, 64) && edr_window_hex(q->previous_result_sha256, 64) &&
         !strncmp(q->previous_task_id, "lcq-", 4) && edr_window_hex(q->previous_task_id + 4, 48);
}
#endif
