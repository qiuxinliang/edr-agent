#include "edr/behavior_record.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

void edr_behavior_record_init(EdrBehaviorRecord *r) {
  if (!r) {
    return;
  }
  memset(r, 0, sizeof(*r));
  snprintf(r->tenant_id, sizeof(r->tenant_id), "tenant_default");
  snprintf(r->endpoint_id, sizeof(r->endpoint_id), "ep-local");
}

int edr_behavior_is_injection_evidence(const EdrBehaviorRecord *r) {
  if (!r || (r->type != EDR_EVENT_PROCESS_INJECT && r->type != EDR_EVENT_THREAD_CREATE_REMOTE))
    return 0;
  if (strcmp(r->syscall_sensor, "auditd") != 0 && strcmp(r->syscall_sensor, "ebpf") != 0)
    return 1;
  if (!r->syscall_success_known || !r->syscall_success || !r->syscall_result_known)
    return 0;
  if (strcmp(r->syscall_name, "process_vm_writev") == 0) return r->syscall_result > 0;
  /* The ptrace request is not captured: successful ATTACH/GETREGS is not
   * evidence of a memory write. Retain the event without upgrading it. */
  return 0;
}

int edr_behavior_source_field_truncated(const EdrBehaviorRecord *r, const char *field) {
  const char *cursor;
  size_t len;
  if (!r || !field || !field[0]) return 0;
  len = strlen(field);
  cursor = r->source_truncated_fields;
  while (*cursor) {
    const char *end = strchr(cursor, ',');
    size_t item_len = end ? (size_t)(end - cursor) : strlen(cursor);
    if ((item_len == len && memcmp(cursor, field, len) == 0) ||
        (item_len == sizeof("source.list_overflow") - 1u &&
         memcmp(cursor, "source.list_overflow", item_len) == 0)) return 1;
    if (!end) break;
    cursor = end + 1u;
  }
  return 0;
}

void edr_behavior_mark_source_truncated(EdrBehaviorRecord *r, const char *field) {
  size_t used, len;
  if (!r || !field || !field[0]) return;
  if (!edr_behavior_source_field_truncated(r, field)) {
    used = strlen(r->source_truncated_fields);
    len = strlen(field);
    if (used + (used ? 1u : 0u) + len < sizeof(r->source_truncated_fields)) {
      if (used) r->source_truncated_fields[used++] = ',';
      memcpy(r->source_truncated_fields + used, field, len + 1u);
    } else {
      snprintf(r->source_truncated_fields, sizeof(r->source_truncated_fields), "%s",
               "source.list_overflow");
    }
  }
  if (strcmp(r->source_completeness, "NOT_EVALUABLE") != 0)
    snprintf(r->source_completeness, sizeof(r->source_completeness), "%s", "TRUNCATED");
}

void edr_behavior_resolve_source_truncated(EdrBehaviorRecord *r, const char *field) {
  char *cursor;
  size_t len;
  int removed = 0;
  if (!r || !field || !field[0]) return;
  len = strlen(field);
  cursor = r->source_truncated_fields;
  while (*cursor) {
    char *end = strchr(cursor, ',');
    size_t item_len = end ? (size_t)(end - cursor) : strlen(cursor);
    if (item_len == len && memcmp(cursor, field, len) == 0) {
      removed = 1;
      if (end) memmove(cursor, end + 1u, strlen(end + 1u) + 1u);
      else {
        if (cursor > r->source_truncated_fields) --cursor;
        *cursor = '\0';
        break;
      }
    } else {
      if (!end) break;
      cursor = end + 1u;
    }
  }
  if (removed && !r->source_truncated_fields[0] && strcmp(r->source_completeness, "TRUNCATED") == 0)
    snprintf(r->source_completeness, sizeof(r->source_completeness), "%s", "COALESCED");
}

void edr_behavior_record_enrich_system_context(EdrBehaviorRecord *r) {
  if (!r) {
    return;
  }
  if (!r->hostname[0]) {
#ifdef _WIN32
    DWORD n = sizeof(r->hostname);
    if (!GetComputerNameA(r->hostname, &n)) {
      r->hostname[0] = '\0';
    }
#else
    if (gethostname(r->hostname, sizeof(r->hostname)) != 0) {
      r->hostname[0] = '\0';
    }
#endif
  }
  /* USERDOMAIN belongs to the Agent service, not necessarily the observed process.
   * Leave an unknown process domain empty instead of manufacturing attribution. */
}

int edr_process_create_is_lifecycle_authoritative(const EdrBehaviorRecord *r) {
  return r && r->type == EDR_EVENT_PROCESS_CREATE && !r->is_security_4688;
}

int edr_behavior_has_process_actor(const EdrBehaviorRecord *r) {
  return r && !r->is_security_4688 &&
      (r->type == EDR_EVENT_PROCESS_CREATE || r->type == EDR_EVENT_FILE_READ ||
       r->kernel_file_activity || r->type == EDR_EVENT_NET_CONNECT ||
       r->type == EDR_EVENT_NET_LISTEN);
}

void edr_behavior_format_time_ns(int64_t ns, char *out, size_t cap) {
  struct tm tmv;
  char date[24];
  time_t sec;
  int written;
  if (!out || !cap) return;
  out[0] = '\0';
  if (ns <= 0) return;
  sec = (time_t)(ns / INT64_C(1000000000));
#ifdef _WIN32
  if (gmtime_s(&tmv, &sec) != 0) return;
#else
  if (!gmtime_r(&sec, &tmv)) return;
#endif
  if (!strftime(date, sizeof(date), "%Y-%m-%dT%H:%M:%S", &tmv)) return;
  written = snprintf(out, cap, "%s.%09luZ", date,
                     (unsigned long)(ns % INT64_C(1000000000)));
  if (written < 0 || (size_t)written >= cap) out[0] = '\0';
}
