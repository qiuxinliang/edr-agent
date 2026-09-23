/* Bounded local diagnostic sink. Collection never waits on filesystem I/O.
 * Do not use this as an evidence cache, export queue, or admission authority. */
#include "edr/network_admission_trace_win.h"
#include "cJSON.h"
#include <sddl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef EDR_COLLECTOR_NETWORK_TESTING
#include "collector_network_test.h"
#define WriteFile edr_network_test_write_file
#endif

static SRWLOCK s_buffer_lock = SRWLOCK_INIT, s_writer_lock = SRWLOCK_INIT;
static EdrNetworkAdmissionTrace s_records[EDR_NETWORK_TRACE_LIMIT];
static uint32_t s_count, s_written, s_port;
static uint64_t s_deadline;
static volatile LONG s_enabled, s_inflight;
static volatile LONG64 s_sequence, s_contention, s_limit_dropped;
static HANDLE s_file = INVALID_HANDLE_VALUE;
static DWORD s_write_error;

static uint64_t trace_now_filetime(void) {
  FILETIME ft;
  GetSystemTimePreciseAsFileTime(&ft);
  return ((uint64_t)ft.dwHighDateTime << 32u) | ft.dwLowDateTime;
}

static int trace_write(const char *text) {
  DWORD written = 0, bytes = (DWORD)strlen(text);
  BOOL ok = bytes <= 4096u && WriteFile(s_file, text, bytes, &written, NULL);
  if (!ok || written != bytes) {
    s_write_error = bytes > 4096u ? ERROR_BUFFER_OVERFLOW : (ok ? ERROR_WRITE_FAULT : GetLastError());
    if (!s_write_error) s_write_error = ERROR_WRITE_FAULT;
    fprintf(stderr, "[network_trace] output failed win32_error=%lu; diagnostic incomplete\n",
            (unsigned long)s_write_error);
    InterlockedExchange(&s_enabled, 0);
    return 0;
  }
  return 1;
}

static int trace_start(const char *path, uint32_t port, uint32_t duration_ms) {
  WCHAR wide[1024];
  PSECURITY_DESCRIPTOR sd = NULL;
  SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, FALSE};
  char header[512];
  /* A previous owner must join its producers and stop before reconfiguration. */
  if (s_file != INVALID_HANDLE_VALUE || InterlockedCompareExchange(&s_inflight, 0, 0)) return -1;
  if (!path || !path[0]) return 0;
  if (!port || port > 65535u || !duration_ms || duration_ms > EDR_NETWORK_TRACE_MAX_MS ||
      !(((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z')) &&
        path[1] == ':' && (path[2] == '\\' || path[2] == '/')) ||
      strchr(path + 2, ':') ||
      !MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, wide, 1024)) {
    fprintf(stderr, "[network_trace] invalid local output path, port, or duration; disabled\n");
    return -1;
  }
  /* No inherited broad read access; SYSTEM, administrators and file owner only.
   * CREATE_NEW never truncates or appends to a previous investigation. */
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
          L"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)", SDDL_REVISION_1, &sd, NULL)) {
    fprintf(stderr, "[network_trace] cannot create protected ACL win32_error=%lu; disabled\n",
            (unsigned long)GetLastError());
    return -1;
  }
  sa.lpSecurityDescriptor = sd;
  s_file = CreateFileW(wide, GENERIC_WRITE, FILE_SHARE_READ, &sa, CREATE_NEW,
                       FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
  DWORD error = GetLastError();
  LocalFree(sd);
  if (s_file == INVALID_HANDLE_VALUE) {
    fprintf(stderr, "[network_trace] cannot create new output file win32_error=%lu; disabled\n",
            (unsigned long)error);
    return -1;
  }
  s_count = s_written = 0u;
  s_port = port;
  s_write_error = 0u;
  s_deadline = GetTickCount64() + duration_ms;
  InterlockedExchange64(&s_sequence, 0);
  InterlockedExchange64(&s_contention, 0);
  InterlockedExchange64(&s_limit_dropped, 0);
  InterlockedExchange(&s_inflight, 0);
  snprintf(header, sizeof(header),
      "{\"kind\":\"session\",\"schema\":\"edr.network_admission.v1\",\"agent_pid\":%lu,"
      "\"started_filetime\":\"%llu\",\"scope\":\"loopback\",\"destination_port\":%u,"
      "\"duration_ms\":%u,\"event_limit\":%u,\"stage_not_run\":-1}\n",
      (unsigned long)GetCurrentProcessId(), (unsigned long long)trace_now_filetime(),
      port, duration_ms, EDR_NETWORK_TRACE_LIMIT);
  if (!trace_write(header)) {
    CloseHandle(s_file); s_file = INVALID_HANDLE_VALUE; return -1;
  }
  InterlockedExchange(&s_enabled, 1);
  return 1;
}

int edr_network_trace_start(const char *path, uint32_t port, uint32_t duration_ms) {
  AcquireSRWLockExclusive(&s_writer_lock);
  int result = trace_start(path, port, duration_ms);
  ReleaseSRWLockExclusive(&s_writer_lock);
  return result;
}

void edr_network_trace_start_from_env(void) {
  const char *path = getenv("EDR_NETWORK_ADMISSION_TRACE_PATH");
  const char *port = getenv("EDR_NETWORK_ADMISSION_TRACE_PORT");
  char *end = NULL;
  unsigned long value = port ? strtoul(port, &end, 10) : 0u;
  if (!path || !path[0]) return;
  if (!port || !port[0] || !end || *end || !value || value > 65535u) {
    fprintf(stderr, "[network_trace] EDR_NETWORK_ADMISSION_TRACE_PORT must be 1..65535; disabled\n");
    return;
  }
  (void)edr_network_trace_start(path, (uint32_t)value, EDR_NETWORK_TRACE_MAX_MS);
}

static int trace_loopback(const char *ip) {
  return !strcmp(ip, "127.0.0.1") || !strcmp(ip, "::1");
}

void edr_network_trace_prepare(EdrNetworkAdmissionTrace *t,
                             const EVENT_RECORD *record, const EdrEventSlot *slot,
                             const EdrSensorInterestEvent *interest) {
  memset(t, 0, sizeof(*t));
  if (!InterlockedCompareExchange(&s_enabled, 0, 0) || GetTickCount64() >= s_deadline) return;
  t->prepared = 1;
  t->event_ns = slot->timestamp_ns;
  t->observed_filetime = trace_now_filetime();
  t->header_pid = record->EventHeader.ProcessId;
  t->payload_pid = interest ? interest->pid : 0u;
  t->event_id = record->EventHeader.EventDescriptor.Id;
  t->opcode = record->EventHeader.EventDescriptor.Opcode;
  const GUID *g = &record->EventHeader.ProviderId;
  snprintf(t->provider, sizeof(t->provider), "%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
      (unsigned long)g->Data1, g->Data2, g->Data3, g->Data4[0], g->Data4[1],
      g->Data4[2], g->Data4[3], g->Data4[4], g->Data4[5], g->Data4[6], g->Data4[7]);
  t->actor_bound = t->interest = t->writeback = t->admitted = t->published = -1;
  t->reason = "not_completed";
}

void edr_network_trace_begin(EdrNetworkAdmissionTrace *t, const EdrBehaviorRecord *br) {
  if (!t || !t->prepared || !InterlockedCompareExchange(&s_enabled, 0, 0)) return;
  if (br->net_dport != s_port || !trace_loopback(br->net_src) || !trace_loopback(br->net_dst)) return;
  AcquireSRWLockExclusive(&s_buffer_lock);
  /* Serialize reservation with deadline close, not with file I/O. */
  if (!InterlockedCompareExchange(&s_enabled, 0, 0) || GetTickCount64() >= s_deadline) {
    ReleaseSRWLockExclusive(&s_buffer_lock);
    return;
  }
  InterlockedIncrement(&s_inflight);
  t->sequence = (uint64_t)InterlockedIncrement64(&s_sequence);
  ReleaseSRWLockExclusive(&s_buffer_lock);
  /* Consume the owner's already-decoded record: parsing again would allocate
   * another event ID and distort the observed pipeline. */
  t->pid = br->pid;
  t->input_start_key = br->process_start_key;
  t->input_birth = br->process_creation_filetime_100ns;
  t->sport = br->net_sport; t->dport = br->net_dport;
  snprintf(t->src, sizeof(t->src), "%s", br->net_src);
  snprintf(t->dst, sizeof(t->dst), "%s", br->net_dst);
  snprintf(t->protocol, sizeof(t->protocol), "%s", br->net_proto);
}

void edr_network_trace_identity(EdrNetworkAdmissionTrace *t, const EdrBehaviorRecord *br) {
  if (!t || !t->sequence) return;
  t->start_key = br->process_start_key;
  t->birth = br->process_creation_filetime_100ns;
  snprintf(t->process_name, sizeof(t->process_name), "%s", br->process_name);
}

void edr_network_trace_actor(EdrNetworkAdmissionTrace *t, const EdrBehaviorRecord *br,
                             int bound, DWORD error) {
  if (!t || !t->sequence) return;
  t->actor_bound = bound;
  t->actor_error = error;
  t->actor_start_key = br->process_start_key;
  t->actor_birth = br->process_creation_filetime_100ns;
  snprintf(t->actor_reason, sizeof(t->actor_reason), "%s", br->process_generation_source);
  edr_network_trace_identity(t, br);
}

int edr_network_trace_admission(EdrNetworkAdmissionTrace *t, int admitted, const char *reason) {
  if (t && t->sequence) { t->admitted = admitted; t->reason = reason; }
  return admitted;
}

void edr_network_trace_finish(EdrNetworkAdmissionTrace *t) {
  if (!t || !t->sequence) return;
  if (!TryAcquireSRWLockExclusive(&s_buffer_lock)) {
    InterlockedIncrement64(&s_contention);
  } else {
    if (s_count < EDR_NETWORK_TRACE_LIMIT) s_records[s_count++] = *t;
    else InterlockedIncrement64(&s_limit_dropped);
    ReleaseSRWLockExclusive(&s_buffer_lock);
  }
  t->sequence = 0u;
  InterlockedDecrement(&s_inflight);
}

static cJSON *trace_u64(cJSON *j, const char *key, uint64_t value) {
  char text[32];
  snprintf(text, sizeof(text), "%llu", (unsigned long long)value);
  return cJSON_AddStringToObject(j, key, text); /* exact, never a lossy JSON double */
}

static int trace_record(const EdrNetworkAdmissionTrace *t) {
  cJSON *j = cJSON_CreateObject();
  if (!j) return 0;
  int ok = 1;
#define TRACE_ADD(expr) do { if (!(expr)) ok = 0; } while (0)
  TRACE_ADD(cJSON_AddStringToObject(j, "kind", "event"));
  TRACE_ADD(trace_u64(j, "sequence", t->sequence));
  TRACE_ADD(trace_u64(j, "event_ns", t->event_ns));
  TRACE_ADD(trace_u64(j, "observed_filetime", t->observed_filetime));
  TRACE_ADD(trace_u64(j, "input_start_key", t->input_start_key));
  TRACE_ADD(trace_u64(j, "input_birth_filetime", t->input_birth));
  TRACE_ADD(trace_u64(j, "actor_start_key", t->actor_start_key));
  TRACE_ADD(trace_u64(j, "actor_birth_filetime", t->actor_birth));
  TRACE_ADD(trace_u64(j, "process_start_key", t->start_key));
  TRACE_ADD(trace_u64(j, "process_creation_filetime_100ns", t->birth));
  TRACE_ADD(cJSON_AddStringToObject(j, "provider", t->provider));
  TRACE_ADD(cJSON_AddNumberToObject(j, "event_id", t->event_id));
  TRACE_ADD(cJSON_AddNumberToObject(j, "opcode", t->opcode));
  TRACE_ADD(cJSON_AddNumberToObject(j, "header_pid", t->header_pid));
  TRACE_ADD(cJSON_AddNumberToObject(j, "payload_pid", t->payload_pid));
  TRACE_ADD(cJSON_AddNumberToObject(j, "decoded_pid", t->pid));
  TRACE_ADD(cJSON_AddStringToObject(j, "src_ip", t->src));
  TRACE_ADD(cJSON_AddStringToObject(j, "dst_ip", t->dst));
  TRACE_ADD(cJSON_AddStringToObject(j, "protocol", t->protocol));
  TRACE_ADD(cJSON_AddNumberToObject(j, "src_port", t->sport));
  TRACE_ADD(cJSON_AddNumberToObject(j, "dst_port", t->dport));
  TRACE_ADD(cJSON_AddStringToObject(j, "process_name", t->process_name));
  TRACE_ADD(cJSON_AddStringToObject(j, "actor_reason", t->actor_reason));
  TRACE_ADD(cJSON_AddNumberToObject(j, "actor_win32_error", t->actor_error));
  TRACE_ADD(cJSON_AddNumberToObject(j, "actor_bound", t->actor_bound));
  TRACE_ADD(cJSON_AddNumberToObject(j, "interest_admitted", t->interest));
  TRACE_ADD(cJSON_AddNumberToObject(j, "identity_writeback", t->writeback));
  TRACE_ADD(cJSON_AddNumberToObject(j, "collector_admitted", t->admitted));
  TRACE_ADD(cJSON_AddNumberToObject(j, "bus_published", t->published));
  TRACE_ADD(cJSON_AddStringToObject(j, "reason", t->reason));
#undef TRACE_ADD
  char line[4096];
  ok = ok && cJSON_PrintPreallocated(j, line, (int)sizeof(line) - 2, 0);
  if (ok) { strcat(line, "\n"); ok = trace_write(line); }
  cJSON_Delete(j);
  return ok;
}

/* Caller holds writer lock, never the producer lock during file operations. */
static void trace_drain(void) {
  while (!s_write_error) {
    EdrNetworkAdmissionTrace record;
    AcquireSRWLockExclusive(&s_buffer_lock);
    if (s_written >= s_count) { ReleaseSRWLockExclusive(&s_buffer_lock); break; }
    record = s_records[s_written];
    ReleaseSRWLockExclusive(&s_buffer_lock);
    if (!trace_record(&record)) {
      if (!s_write_error) s_write_error = ERROR_NOT_ENOUGH_MEMORY;
      InterlockedExchange(&s_enabled, 0);
      fprintf(stderr, "[network_trace] record serialization/write failed; diagnostic incomplete\n");
      break;
    }
    ++s_written;
  }
}

static void trace_close(const char *reason) {
  char footer[512];
  snprintf(footer, sizeof(footer),
      "{\"kind\":\"summary\",\"reason\":\"%s\",\"selected\":%lld,\"written\":%u,"
      "\"diagnostic_contention_dropped\":%lld,\"diagnostic_limit_dropped\":%lld,"
      "\"inflight\":%ld,\"write_error\":%lu}\n", reason,
      (long long)InterlockedCompareExchange64(&s_sequence, 0, 0), s_written,
      (long long)InterlockedCompareExchange64(&s_contention, 0, 0),
      (long long)InterlockedCompareExchange64(&s_limit_dropped, 0, 0),
      (long)InterlockedCompareExchange(&s_inflight, 0, 0), (unsigned long)s_write_error);
  if (!s_write_error) (void)trace_write(footer);
  CloseHandle(s_file); s_file = INVALID_HANDLE_VALUE;
}

void edr_network_trace_flush(void) {
  AcquireSRWLockExclusive(&s_writer_lock);
  if (s_file != INVALID_HANDLE_VALUE) {
    trace_drain();
    int close_now = 0;
    AcquireSRWLockExclusive(&s_buffer_lock);
    if (GetTickCount64() >= s_deadline) {
      InterlockedExchange(&s_enabled, 0);
      close_now = !InterlockedCompareExchange(&s_inflight, 0, 0);
    }
    ReleaseSRWLockExclusive(&s_buffer_lock);
    if (close_now) {
      trace_drain(); /* include finishes concurrent with the first drain */
      trace_close("deadline");
    }
  }
  ReleaseSRWLockExclusive(&s_writer_lock);
}

void edr_network_trace_stop(void) {
  InterlockedExchange(&s_enabled, 0);
  AcquireSRWLockExclusive(&s_writer_lock);
  if (s_file != INVALID_HANDLE_VALUE) { trace_drain(); trace_close("collector_stop"); }
  ReleaseSRWLockExclusive(&s_writer_lock);
}
