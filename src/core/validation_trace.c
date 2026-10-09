#include "edr/validation_trace.h"
#include "edr/sha256.h"
#include "edr/agent_update.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#ifdef _WIN32
#include <windows.h>
#include <sddl.h>
static HANDLE s_file = INVALID_HANDLE_VALUE;
static uint64_t now_ms(void) { return GetTickCount64(); }
#else
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
static int s_file = -1;
static uint64_t now_ms(void) {
  struct timespec t; if (clock_gettime(CLOCK_MONOTONIC, &t)) return 0;
  return (uint64_t)t.tv_sec * 1000u + (uint64_t)t.tv_nsec / 1000000u;
}
#endif

#define TRACE_CAP (8u * 1024u * 1024u)
#define TRACE_IDENTITIES 128u
#define TRACE_FOOTER_RESERVE 512u
static atomic_flag s_lock = ATOMIC_FLAG_INIT;
static atomic_int s_enabled;
static atomic_uint s_drop_capacity, s_drop_lock, s_drop_identity, s_drop_batch, s_drop_format;
static char *s_buffer;
static size_t s_used, s_written;
static unsigned s_events, s_buffered_events, s_persisted_events, s_generations, s_batches;
static uint64_t s_deadline;
static atomic_int s_parent_identity_only;
static char s_image[128], s_batch_sha[TRACE_IDENTITIES][65];
static struct { uint32_t pid; uint64_t birth, key; } s_actors[TRACE_IDENTITIES];

static int token(const char *s, size_t cap) {
  if (!s || strlen(s) >= cap) return 0;
  for (; *s; ++s) if (!((*s >= 'a' && *s <= 'z') || (*s >= 'A' && *s <= 'Z') ||
      (*s >= '0' && *s <= '9') || *s == '_' || *s == '-' || *s == '.' || *s == ':')) return 0;
  return 1;
}
static int equal_image(const char *s) {
  if (!s) return 0;
  const char *leaf = s;
  for (const char *p = s; *p; ++p) if (*p == '/' || *p == '\\') leaf = p + 1;
  const char *a = leaf, *b = s_image;
  while (*a && *b) {
    char x = *a++, y = *b++;
    if (x >= 'A' && x <= 'Z') x += 'a' - 'A';
    if (y >= 'A' && y <= 'Z') y += 'a' - 'A';
    if (x != y) return 0;
  }
  return !*a && !*b;
}
static void dropped(atomic_uint *cause) {
  atomic_fetch_add(cause, 1u);
}
static int parent_stage(const char *stage) {
  return stage && (!strcmp(stage, "normalized") || !strcmp(stage, "identity_enriched") ||
      !strcmp(stage, "enriched") || !strcmp(stage, "wire") ||
      !strcmp(stage, "actor_binding") || !strcmp(stage, "cached_generation") ||
      !strcmp(stage, "parent_cache"));
}
static int selected_stage(const char *stage) {
  if (atomic_load(&s_parent_identity_only)) return parent_stage(stage);
  /* These new owner diagnostics belong only to parent diagnosis. */
  return !stage || (strcmp(stage, "actor_binding") && strcmp(stage, "cached_generation") &&
      strcmp(stage, "parent_cache"));
}
static const char *parent_reason(const char *reason) {
  /* Owning components supply fixed diagnostic causes, never identity text. */
  static const char *const allowed[] = {
    "parent_identity", "decoded", "ok", "reason_unavailable",
    "live_process_pid_unavailable", "live_process_open_failed", "telemetry_pid_mismatch",
    "process_start_key_mismatch", "live_generation_query_failed", "invalid_process_handle",
    "telemetry_id_api_unavailable", "telemetry_id_buffer_unavailable",
    "telemetry_id_query_unsupported", "telemetry_id_incomplete",
    "live_creation_filetime_mismatch", "live_generation_event_time_mismatch",
    "file_activity_live_generation_event_time_mismatch", "file_read_live_generation_event_time_mismatch",
    "network_live_generation_event_time_mismatch", "actor_image_unresolved",
    "kernel_payload_live_telemetry", "target_live_telemetry", "etw_start_key_live_telemetry",
    "file_activity_pid_event_time_live_telemetry", "file_read_pid_event_time_live_telemetry",
    "network_pid_event_time_live_telemetry", "file_activity_process_tree_cache_generation",
    "file_read_process_tree_cache_generation", "network_process_tree_cache_generation",
    "cache_actor_ineligible", "cache_actor_unbound", "cache_miss", "cache_lookup_rejected",
    "cache_generation_incomplete", "cache_record_generation_unproven", "cache_image_unavailable",
    "cache_image_truncated", "cache_generation_mismatch", "cache_event_time_rejected",
    "cache_network_unproven", "cache_parent_unknown", "cache_parent_known",
    "cache_parent_explicit_zero", "cache_parent_invalid", "cache_parent_conflict"
  };
  if (reason) for (size_t i = 0; i < sizeof(allowed) / sizeof(allowed[0]); ++i)
    if (!strcmp(reason, allowed[i])) return allowed[i];
  return "reason_unavailable";
}
static int enter(void) {
  if (!atomic_load(&s_enabled) || now_ms() >= s_deadline) return 0;
  if (atomic_flag_test_and_set(&s_lock)) { dropped(&s_drop_lock); return 0; }
  if (!atomic_load(&s_enabled) || now_ms() >= s_deadline) { atomic_flag_clear(&s_lock); return 0; }
  return 1;
}
static int append(const char *data, size_t n) {
  if (n > TRACE_CAP - TRACE_FOOTER_RESERVE - s_used) { dropped(&s_drop_capacity); return 0; }
  memcpy(s_buffer + s_used, data, n); s_used += n;
  return 1;
}
static int scoped_values(uint32_t pid, uint64_t birth, uint64_t key,
                         const char *name, const char *path, const char *parent) {
  for (unsigned i = 0; i < s_generations; ++i) {
    if (pid == s_actors[i].pid &&
        (!birth || !s_actors[i].birth || birth == s_actors[i].birth) &&
        (!key || !s_actors[i].key || key == s_actors[i].key) &&
        ((birth && birth == s_actors[i].birth) || (key && key == s_actors[i].key))) {
      if (birth) s_actors[i].birth = birth;
      if (key) s_actors[i].key = key;
      return 1;
    }
  }
  if (!equal_image(name) && !equal_image(path) && !equal_image(parent)) return 0;
  if (pid && (key || birth)) {
    if (s_generations == TRACE_IDENTITIES) { dropped(&s_drop_identity); return 0; }
    s_actors[s_generations].pid = pid; s_actors[s_generations].birth = birth;
    s_actors[s_generations++].key = key;
  }
  return 1;
}
static int scoped(const EdrBehaviorRecord *r) {
  return r && scoped_values(r->pid, r->process_creation_filetime_100ns, r->process_start_key,
                            r->process_name, r->exe_path, r->parent_name);
}
static int write_bytes(const char *data, size_t n) {
#ifdef _WIN32
  DWORD written = 0;
  return WriteFile(s_file, data, (DWORD)n, &written, NULL) && written == n;
#else
  return write(s_file, data, n) == (ssize_t)n;
#endif
}

static int trace_start(const char *path, const char *image, unsigned seconds,
                       int parent_identity_only) {
  /* Lifecycle-owned startup; a stopped session is never silently reused. */
  if (s_buffer || !path || !path[0] || !image || !image[0] || !token(image, sizeof(s_image)) ||
      strchr(image, ':') || !seconds || seconds > 300u) return -1;
#ifdef _WIN32
  WCHAR wide[1024]; PSECURITY_DESCRIPTOR sd = NULL;
  if (strlen(path) < 4u || path[1] != ':' || (path[2] != '\\' && path[2] != '/') ||
      strchr(path + 2, ':') || !MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, wide, 1024) ||
      !ConvertStringSecurityDescriptorToSecurityDescriptorW(
          L"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)", SDDL_REVISION_1, &sd, NULL)) return -1;
  SECURITY_ATTRIBUTES sa = {sizeof(sa), sd, FALSE};
  s_file = CreateFileW(wide, GENERIC_WRITE, FILE_SHARE_READ, &sa, CREATE_NEW,
                       FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
  LocalFree(sd); if (s_file == INVALID_HANDLE_VALUE) return -1;
#else
  if (path[0] != '/') return -1;
  s_file = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
  if (s_file < 0) return -1;
#endif
  s_buffer = malloc(TRACE_CAP);
  if (!s_buffer) {
#ifdef _WIN32
    CloseHandle(s_file); s_file = INVALID_HANDLE_VALUE;
#else
    close(s_file); s_file = -1;
#endif
    return -1;
  }
  s_used = s_written = 0; s_events = s_buffered_events = s_persisted_events = s_generations = s_batches = 0;
  atomic_store(&s_parent_identity_only, parent_identity_only);
  atomic_store(&s_drop_capacity, 0); atomic_store(&s_drop_lock, 0);
  atomic_store(&s_drop_identity, 0); atomic_store(&s_drop_batch, 0); atomic_store(&s_drop_format, 0);
  snprintf(s_image, sizeof(s_image), "%s", image);
  s_deadline = now_ms() + (uint64_t)seconds * 1000u;
  char header[640]; int n = snprintf(header, sizeof(header),
      "{\"kind\":\"session\",\"schema\":\"edr.validation_trace.v1\",\"image\":\"%s\","
      "\"duration_s\":%u,\"capacity_bytes\":%u,\"generation_limit\":%u,\"batch_limit\":%u,"
      "\"purpose\":\"%s\",\"agent_version\":\"%s\",\"build_sha\":\"unknown\"}\n",
      image, seconds, TRACE_CAP, TRACE_IDENTITIES, TRACE_IDENTITIES,
      parent_identity_only ? "parent_identity" : "egress_validation",
      token(EDR_AGENT_VERSION_STRING, 128) ? EDR_AGENT_VERSION_STRING : "unknown");
  append(header, (size_t)n); atomic_store(&s_enabled, 1); return 0;
}
int edr_validation_trace_start(const char *path, const char *image, unsigned seconds) {
  return trace_start(path, image, seconds, 0);
}
int edr_validation_trace_start_parent(const char *path, const char *image, unsigned seconds) {
  return trace_start(path, image, seconds, 1);
}
void edr_validation_trace_start_from_env(void) {
  const char *path = getenv("EDR_VALIDATION_TRACE_PATH");
  const char *image = getenv("EDR_VALIDATION_TRACE_IMAGE");
  const char *purpose = getenv("EDR_VALIDATION_TRACE_PURPOSE");
  if (!path || !path[0]) return;
  if (purpose && purpose[0] && strcmp(purpose, "parent_identity") != 0 &&
      strcmp(purpose, "egress_validation") != 0) {
    fprintf(stderr, "[validation_trace] unsupported local diagnostic purpose\n");
    return;
  }
  int parent_identity = purpose && strcmp(purpose, "parent_identity") == 0;
  if (trace_start(path, image, 300u, parent_identity) != 0)
    fprintf(stderr, "[validation_trace] protected local session could not start\n");
}
int edr_validation_trace_enabled(void) {
  return atomic_load(&s_enabled) && now_ms() < s_deadline;
}
static void event_locked(uint32_t pid, uint64_t birth, uint64_t key, int64_t ns,
                         unsigned type, const char *event_id, const char *stage, const char *reason,
                         uint32_t ppid, uint32_t parent_state, uint32_t projection_version,
                         uint64_t required_fields, const char *rule_id, const char *change_reason,
                         const char *wire_event_id) {
  char line[1536], wire_mapping[384] = "";
  if (wire_event_id) {
    snprintf(wire_mapping, sizeof(wire_mapping),
        ",\"source_event_id\":\"%s\",\"wire_event_id\":\"%s\"",
        token(event_id, EDR_BR_ID_LEN) ? event_id : "",
        token(wire_event_id, EDR_BR_ID_LEN) ? wire_event_id : "");
  }
  uint32_t effective_state = parent_state == EDR_PARENT_PID_UNKNOWN && ppid
      ? EDR_PARENT_PID_KNOWN : parent_state;
  int n = snprintf(line, sizeof(line),
      "{\"kind\":\"event\",\"sequence\":%u,\"pid\":%u,\"birth\":\"%llu\",\"start_key\":\"%llu\","
      "\"event_ns\":\"%lld\",\"type\":%u,\"event_id\":\"%s\",\"stage\":\"%s\",\"reason\":\"%s\","
      "\"ppid\":%u,\"parent_pid_state\":%u,\"parent_pid_effective_state\":%u,"
      "\"projection_version\":%u,\"required_evidence_fields\":\"%llu\",\"rule_id\":\"%s\","
      "\"change_reason\":\"%s\"%s}\n",
      ++s_events, pid, (unsigned long long)birth, (unsigned long long)key, (long long)ns, type,
      token(event_id, EDR_BR_ID_LEN) ? event_id : "",
      token(stage, 96) ? stage : "invalid_diagnostic_token",
      atomic_load(&s_parent_identity_only) ? parent_reason(reason) :
          (token(reason, 96) ? reason : "invalid_diagnostic_token"), ppid, parent_state, effective_state,
      projection_version, (unsigned long long)required_fields,
      token(rule_id, 96) ? rule_id : "",
      token(change_reason, 96) ? change_reason : "invalid_diagnostic_token", wire_mapping);
  if (n > 0 && (size_t)n < sizeof(line)) {
    if (append(line, (size_t)n)) ++s_buffered_events;
  } else dropped(&s_drop_format);
}
void edr_validation_trace_event(const EdrBehaviorRecord *r, const char *stage, const char *reason) {
  if (!selected_stage(stage)) return;
  if (!enter()) return;
  if (scoped(r)) event_locked(r->pid, r->process_creation_filetime_100ns, r->process_start_key,
                              r->event_time_ns, (unsigned)r->type, r->event_id, stage, reason,
                              r->ppid, r->parent_pid_state, r->evidence_projection_version,
                              r->required_evidence_fields,
                              stage && strcmp(stage, "p0_rule") == 0 ? reason : "", "not_compared", NULL);
  atomic_flag_clear(&s_lock);
}
void edr_validation_trace_parent_change(const EdrBehaviorRecord *r,
                                       uint32_t previous_ppid, uint8_t previous_state,
                                       const char *stage) {
  if (!selected_stage(stage)) return;
  if (!enter()) return;
  if (scoped(r)) {
    const char *change;
    uint8_t before = edr_parent_pid_effective_state(previous_ppid, previous_state);
    uint8_t after = edr_parent_pid_effective_state(r->ppid, r->parent_pid_state);
    if (after == EDR_PARENT_PID_CONFLICT) change = "conflict_retained_or_detected";
    else if (after == EDR_PARENT_PID_INVALID) change = "invalid_retained";
    else if (before == EDR_PARENT_PID_UNKNOWN && after == EDR_PARENT_PID_KNOWN)
      change = "unknown_completed";
    else if (previous_ppid != r->ppid || previous_state != r->parent_pid_state)
      change = "parent_value_or_state_changed";
    else if (after == EDR_PARENT_PID_UNKNOWN) change = "unknown_retained";
    else if (after == EDR_PARENT_PID_EXPLICIT_ZERO) change = "explicit_zero_retained";
    else change = "known_retained";
    event_locked(r->pid, r->process_creation_filetime_100ns, r->process_start_key,
        r->event_time_ns, (unsigned)r->type, r->event_id, stage, "parent_identity",
        r->ppid, r->parent_pid_state, r->evidence_projection_version,
        r->required_evidence_fields, "", change, NULL);
  }
  atomic_flag_clear(&s_lock);
}
void edr_validation_trace_parent_wire(const EdrBehaviorRecord *r,
                                    uint32_t wire_ppid, uint32_t wire_state,
                                    uint32_t projection_version, uint64_t required_fields,
                                    const char *rule_id, const char *wire_event_id) {
  if (!enter()) return;
  if (scoped(r)) event_locked(r->pid, r->process_creation_filetime_100ns, r->process_start_key,
      r->event_time_ns, (unsigned)r->type, r->event_id, "wire", "parent_identity",
      wire_ppid, wire_state, projection_version, required_fields, rule_id, "final_projection",
      wire_event_id ? wire_event_id : r->event_id);
  atomic_flag_clear(&s_lock);
}
void edr_validation_trace_interest(const EdrSensorInterestEvent *e, int64_t ns,
                                  const char *stage, const char *reason) {
  if (atomic_load(&s_parent_identity_only)) return;
  if (!e || !enter()) return;
  if (scoped_values(e->pid, e->process_creation_filetime_100ns, e->process_start_key,
                    e->process_name, NULL, e->parent_process_name))
    event_locked(e->pid, e->process_creation_filetime_100ns, e->process_start_key,
                  ns, (unsigned)e->type, "", stage, reason, e->parent_pid,
                  EDR_PARENT_PID_UNKNOWN, 0u, 0u, "", "not_compared", NULL);
  atomic_flag_clear(&s_lock);
}
void edr_validation_trace_bind(const EdrBehaviorRecord *r, const char *batch_id,
                             const uint8_t *wire, size_t length) {
  if (!batch_id || !wire || !length || !enter()) return;
  if (scoped(r)) {
    char b[65], p[65];
    if (edr_sha256_hex((const uint8_t *)batch_id, strlen(batch_id), b) == 0 &&
        edr_sha256_hex(wire, length, p) == 0) {
      unsigned found = 0;
      for (unsigned i = 0; i < s_batches; ++i) if (!strcmp(s_batch_sha[i], b)) found = 1;
      if (!found && s_batches == TRACE_IDENTITIES) {
        dropped(&s_drop_batch); atomic_flag_clear(&s_lock); return;
      }
      if (!found) snprintf(s_batch_sha[s_batches++], 65, "%s", b);
      char line[384]; int n = snprintf(line, sizeof(line),
          "{\"kind\":\"encoded\",\"event_id\":\"%s\",\"batch_id_sha256\":\"%s\","
          "\"payload_sha256\":\"%s\",\"payload_bytes\":%llu}\n",
          token(r->event_id, sizeof(r->event_id)) ? r->event_id : "", b, p, (unsigned long long)length);
      if (n > 0 && (size_t)n < sizeof(line)) append(line, (size_t)n);
      else dropped(&s_drop_format);
    } else dropped(&s_drop_format);
  }
  atomic_flag_clear(&s_lock);
}
void edr_validation_trace_request(const char *batch_id, const void *body, size_t length,
                                  const char *content_type) {
  if (atomic_load(&s_parent_identity_only)) return;
  if (!batch_id || !body || !content_type || !enter()) return;
  char hash[65];
  if (edr_sha256_hex((const uint8_t *)batch_id, strlen(batch_id), hash) == 0) {
    for (unsigned i = 0; i < s_batches; ++i) if (!strcmp(hash, s_batch_sha[i])) {
      const char *kind = !strcmp(content_type, "application/x-protobuf") ? "protobuf" :
                         !strcmp(content_type, "application/json") ? "json" : NULL;
      char header[192]; int n = snprintf(header, sizeof(header),
          "{\"kind\":\"request\",\"batch_id_sha256\":\"%s\",\"encoding\":\"%s\",\"body_hex\":\"",
          hash, kind ? kind : "unknown");
      if (!kind || n <= 0 || (size_t)n >= sizeof(header)) dropped(&s_drop_format);
      else if (length <= TRACE_CAP / 2u && length * 2u + (size_t)n + 3u <= TRACE_CAP - TRACE_FOOTER_RESERVE - s_used) {
        static const char hex[] = "0123456789abcdef";
        const uint8_t *bytes = body; append(header, (size_t)n);
        for (size_t j = 0; j < length; ++j) {
          s_buffer[s_used++] = hex[bytes[j] >> 4u]; s_buffer[s_used++] = hex[bytes[j] & 15u];
        }
        append("\"}\n", 3u);
      } else dropped(&s_drop_capacity);
      break;
    }
  }
  atomic_flag_clear(&s_lock);
}
void edr_validation_trace_flush(void) {
  if (!s_buffer || atomic_flag_test_and_set(&s_lock)) return;
  int closing = !atomic_load(&s_enabled) || now_ms() >= s_deadline;
  if (closing) atomic_store(&s_enabled, 0);
  int ok = 1;
  while (s_written < s_used && ok) {
    size_t n = s_used - s_written; if (n > 65536u) n = 65536u;
    ok = write_bytes(s_buffer + s_written, n); if (ok) s_written += n;
  }
  if (ok) s_persisted_events = s_buffered_events;
  if (closing && ok) {
    unsigned capacity = atomic_load(&s_drop_capacity), locked = atomic_load(&s_drop_lock);
    unsigned identity = atomic_load(&s_drop_identity), batch = atomic_load(&s_drop_batch);
    unsigned format = atomic_load(&s_drop_format);
    /* One snapshot supplies both the compatibility total and its causes.
     * Producer lock misses are best-effort local observations at close. */
    char status[TRACE_FOOTER_RESERVE]; int n = snprintf(status, sizeof(status),
        "{\"kind\":\"closed\",\"events\":%u,\"persisted_events\":%u,\"dropped\":%u,"
        "\"drop_capacity\":%u,\"drop_lock\":%u,\"drop_identity\":%u,\"drop_batch\":%u,"
        "\"drop_format\":%u,\"bytes\":%llu}\n",
        s_events, s_persisted_events, capacity + locked + identity + batch + format,
        capacity, locked, identity, batch, format, (unsigned long long)s_written);
    if (n > 0 && (size_t)n < sizeof(status)) ok = write_bytes(status, (size_t)n);
    else { dropped(&s_drop_format); ok = 0; }
  }
  if (closing || !ok) {
    atomic_store(&s_enabled, 0);
#ifdef _WIN32
    if (!FlushFileBuffers(s_file)) ok = 0;
    CloseHandle(s_file); s_file = INVALID_HANDLE_VALUE;
#else
    if (fsync(s_file)) ok = 0;
    close(s_file); s_file = -1;
#endif
    free(s_buffer); s_buffer = NULL;
    if (!ok) fprintf(stderr, "[validation_trace] local write failed; observation incomplete\n");
  }
  atomic_flag_clear(&s_lock);
}
void edr_validation_trace_stop(void) {
  atomic_store(&s_enabled, 0); edr_validation_trace_flush();
}
