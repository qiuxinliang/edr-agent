#include "edr/preprocess.h"

#include "edr/resource.h"
#include "edr/attack_surface_report.h"
#include "edr/config.h"
#include "edr/collector.h"
#include "edr/behavior_from_slot.h"
#include "edr/behavior_alert_emit.h"
#include "edr/behavior_proto.h"
#include "edr/behavior_proto_c.h"
#include "edr/behavior_wire.h"
#include "edr/command.h"
#include "edr/dedup.h"
#include "edr/detection_decision.h"
#include "edr/emit_rules.h"
#include "edr/event_batch.h"
#include "edr/event_bus.h"
#include "edr/heartbeat.h"
#include "edr/net_fanout_detector.h"
#include "edr/ave_cross_engine_feed.h"
#include "edr/local_evidence_cache.h"
#include "edr/pid_history_pmfe.h"
#include "edr/correlation_engine.h"
#include "edr/p0_rule_direct_emit.h"
#include "edr/p0_rule_ir.h"
#include "edr/p0_source_only_contract.h"
#include "edr/pmfe.h"
#include "edr/process_tree_cache.h"
#include "edr/storage_queue.h"
#include "edr/time_util.h"
#include "edr/transport_sink.h"
#include "edr/types.h"
#include "edr/windows_event_policy.h"
#include "edr/process_create_coalescer.h"
#include "edr/process_evidence_worker.h"
#include "edr/process_generation.h"
#include "edr/windows_file_identity.h"
#include "edr/file_read_deferred.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#include <sddl.h>
static HANDLE s_thread;
static volatile LONG s_stop_preprocess;
#else
#include <pthread.h>
#include <unistd.h>
static pthread_t s_thread;
static volatile int s_stop_preprocess;
#endif

static int s_preprocess_active;

static EdrEventBus *s_bus;
static unsigned s_telemetry_sampling_pct = 100u;
static uint64_t s_sampling_dropped;
static uint64_t s_sampling_kept;

#ifdef _WIN32
#define EDR_P0_TOKEN_IDENTITY_CACHE 128u
typedef struct {
  uint32_t pid;
  uint64_t process_start_key;
  uint64_t process_creation_filetime_100ns;
  char canonical_path[EDR_BR_STR_LONG];
  char username[EDR_BR_STR_SHORT];
  char domain[EDR_BR_STR_SHORT];
  char user_sid[EDR_BR_STR_SHORT];
  char logon_id[64];
  uint8_t valid;
} EdrP0TokenIdentityCacheEntry;
static EdrP0TokenIdentityCacheEntry s_p0_token_identity_cache[EDR_P0_TOKEN_IDENTITY_CACHE];
static uint32_t s_p0_token_identity_next;
static EdrFileReadDeferred s_file_read_deferred;
#endif

/** 与 [agent] 对齐，写入每条 BehaviorRecord（线格式 / nanopb 与 endpoint_id 一致） */
static char s_cfg_endpoint_id[128];
static char s_cfg_tenant_id[128];

static void copy_trunc(char *dst, size_t cap, const char *src) {
  size_t i = 0;
  if (!dst || cap == 0u) {
    return;
  }
  if (!src) {
    dst[0] = '\0';
    return;
  }
  for (; i + 1u < cap && src[i]; i++) {
    dst[i] = src[i];
  }
  dst[i] = '\0';
}

static void sync_agent_ids_from_cfg(const EdrConfig *cfg) {
  if (!cfg) {
    return;
  }
  copy_trunc(s_cfg_endpoint_id, sizeof(s_cfg_endpoint_id), cfg->agent.endpoint_id);
  copy_trunc(s_cfg_tenant_id, sizeof(s_cfg_tenant_id), cfg->agent.tenant_id);
}

static void apply_agent_ids_to_record(EdrBehaviorRecord *br) {
  if (!br) {
    return;
  }
  if (s_cfg_tenant_id[0]) {
    copy_trunc(br->tenant_id, sizeof(br->tenant_id), s_cfg_tenant_id);
  }
  if (s_cfg_endpoint_id[0] && strcmp(s_cfg_endpoint_id, "auto") != 0) {
    copy_trunc(br->endpoint_id, sizeof(br->endpoint_id), s_cfg_endpoint_id);
  }
}

static void sync_sampling_from_cfg(const EdrConfig *cfg) {
  unsigned pct = 100u;
  if (cfg) {
    pct = cfg->platform.telemetry_sampling_pct;
  }
  if (pct > 100u) {
    pct = 100u;
  }
  s_telemetry_sampling_pct = pct;
}

static uint32_t sampling_hash_bytes(uint32_t h, const void *data, size_t len) {
  const unsigned char *p = (const unsigned char *)data;
  for (size_t i = 0; i < len; i++) {
    h ^= (uint32_t)p[i];
    h *= 16777619u;
  }
  return h;
}

static uint32_t sampling_hash_cstr(uint32_t h, const char *s) {
  return s && s[0] ? sampling_hash_bytes(h, s, strlen(s)) : h;
}

static uint32_t edr_preprocess_sampling_hash_record(const EdrBehaviorRecord *br) {
  uint32_t h = 2166136261u;
  if (!br) {
    return h;
  }
  h = sampling_hash_bytes(h, &br->type, sizeof(br->type));
  h = sampling_hash_bytes(h, &br->pid, sizeof(br->pid));
  h = sampling_hash_bytes(h, &br->event_time_ns, sizeof(br->event_time_ns));
  h = sampling_hash_cstr(h, br->endpoint_id);
  h = sampling_hash_cstr(h, br->process_name);
  h = sampling_hash_cstr(h, br->cmdline);
  h = sampling_hash_cstr(h, br->exe_path);
  h = sampling_hash_cstr(h, br->file_path);
  h = sampling_hash_cstr(h, br->dns_query);
  h = sampling_hash_cstr(h, br->net_dst);
  h = sampling_hash_bytes(h, &br->net_dport, sizeof(br->net_dport));
  return h;
}

static int edr_preprocess_sampling_exempt(const EdrBehaviorRecord *br) {
  if (!br) {
    return 0;
  }
  if (br->priority == 0u) {
    return 1;
  }
  switch (br->type) {
  case EDR_EVENT_PROCESS_INJECT:
  case EDR_EVENT_THREAD_CREATE_REMOTE:
  case EDR_EVENT_PROTOCOL_SHELLCODE:
  case EDR_EVENT_WEBSHELL_DETECTED:
  case EDR_EVENT_PMFE_SCAN_RESULT:
  case EDR_EVENT_BEHAVIOR_ONNX_ALERT:
    return 1;
  default:
    return 0;
  }
}

static int edr_preprocess_sampling_allow(const EdrBehaviorRecord *br) {
  unsigned pct = s_telemetry_sampling_pct;
  if (!br) {
    return 0;
  }
  if (pct >= 100u || edr_preprocess_sampling_exempt(br)) {
    s_sampling_kept++;
    return 1;
  }
  if (pct == 0u) {
    s_sampling_dropped++;
    return 0;
  }
  if ((edr_preprocess_sampling_hash_record(br) % 100u) < pct) {
    s_sampling_kept++;
    return 1;
  }
  s_sampling_dropped++;
  return 0;
}

void edr_preprocess_apply_sampling_pct(uint32_t pct) {
  if (pct > 100u) {
    pct = 100u;
  }
  s_telemetry_sampling_pct = pct;
}

uint64_t edr_preprocess_sampling_dropped_count(void) { return s_sampling_dropped; }
uint64_t edr_preprocess_sampling_kept_count(void) { return s_sampling_kept; }
uint32_t edr_preprocess_sampling_pct(void) { return s_telemetry_sampling_pct; }

static int p0_direct_emit_enabled(void) {
  const char *v = getenv("EDR_P0_DIRECT_EMIT");
  if (!v || !v[0]) {
    return 1;
  }
  if ((v[0] == '0' || v[0] == 'n' || v[0] == 'N' || v[0] == 'o' || v[0] == 'O') &&
      (v[1] == '\0' || v[1] == ' ' || v[1] == '\t' || v[1] == '\r' || v[1] == '\n')) {
    return 0;
  }
  return 1;
}

static void format_record_time_ns(int64_t ns, char *out, size_t cap) {
  if (!out || cap == 0u) {
    return;
  }
  out[0] = '\0';
  if (ns <= 0) {
    return;
  }
  time_t sec = (time_t)(ns / 1000000000LL);
  struct tm tmv;
#ifdef _WIN32
  if (gmtime_s(&tmv, &sec) != 0) {
    return;
  }
#else
  if (!gmtime_r(&sec, &tmv)) {
    return;
  }
#endif
  (void)strftime(out, cap, "%Y-%m-%dT%H:%M:%SZ", &tmv);
}

static uint64_t filetime_100ns_to_unix_ns(uint64_t filetime_100ns) {
  const uint64_t unix_epoch_100ns = 116444736000000000ULL;
  if (filetime_100ns <= unix_epoch_100ns) return 0u;
  return (filetime_100ns - unix_epoch_100ns) * 100u;
}

#ifdef _WIN32
static int evidence_json_escape(const char *in, char *out, size_t cap) {
  static const char hex[] = "0123456789abcdef";
  size_t used = 0u;
  if (!out || cap == 0u) return 0;
  if (!in) in = "";
  for (const unsigned char *p = (const unsigned char *)in; *p; ++p) {
    size_t need = 1u;
    if (*p == '"' || *p == '\\') need = 2u;
    else if (*p < 0x20u) need = 6u;
    if (used + need >= cap) {
      out[0] = '\0';
      return 0;
    }
    if (*p == '"' || *p == '\\') {
      out[used++] = '\\';
      out[used++] = (char)*p;
    } else if (*p < 0x20u) {
      out[used++] = '\\'; out[used++] = 'u'; out[used++] = '0'; out[used++] = '0';
      out[used++] = hex[*p >> 4u]; out[used++] = hex[*p & 0x0fu];
    } else {
      out[used++] = (char)*p;
    }
  }
  out[used] = '\0';
  return 1;
}
#endif

#ifdef _WIN32
static int p0_token_identity_cache_same_generation(const EdrP0TokenIdentityCacheEntry *entry,
                                                    const EdrBehaviorRecord *br) {
  const char *path;
  EdrWindowsUtf8PathCompareResult path_compare;
  if (!entry || !entry->valid || !br || entry->pid != br->pid ||
      !br->process_start_key || !br->process_creation_filetime_100ns ||
      entry->process_start_key != br->process_start_key ||
      entry->process_creation_filetime_100ns != br->process_creation_filetime_100ns) {
    return 0;
  }
  path = br->image_path_canonical[0] ? br->image_path_canonical : br->exe_path;
  if (!path[0] || !entry->canonical_path[0]) {
    return 0;
  }
  path_compare = edr_windows_utf8_path_compare_ci(entry->canonical_path, path);
  if (path_compare != EDR_WINDOWS_UTF8_PATH_COMPARE_MATCH) {
    return 0;
  }
  return 1;
}

static void p0_mark_file_read_collector_evidence(EdrBehaviorRecord *br, const char *reason) {
  const EdrP0SourceOnlyReason *contract;
  if (!br || br->type != EDR_EVENT_FILE_READ || !reason || !reason[0]) return;
  /* A missing file path cannot support a truthful target-path assertion.  The
   * one registered nullable-path reason retains the source identity without
   * fabricating a filename. */
  if (!br->file_path[0]) reason = EDR_P0_FILE_READ_REASON_CANONICAL_PATH_UNRESOLVED;
  contract = edr_p0_source_only_reason_find(reason);
  if (!contract || contract->stage != EDR_P0_SOURCE_ONLY_STAGE_COLLECTOR_EVIDENCE_GATE ||
      strcmp(contract->gate_id, EDR_P0_FILE_READ_METADATA_GATE) != 0) {
    return;
  }
  snprintf(br->source_completeness, sizeof(br->source_completeness), "%s",
           "NOT_EVALUABLE");
  snprintf(br->collector_evidence_gate, sizeof(br->collector_evidence_gate), "%s",
           EDR_P0_FILE_READ_METADATA_GATE);
  snprintf(br->collector_evidence_reason, sizeof(br->collector_evidence_reason), "%s",
           reason);
}

static const char *p0_file_read_live_generation_reason(const char *live_reason) {
  if (!live_reason || !live_reason[0] ||
      strcmp(live_reason, "etw_process_start_key_unavailable") == 0) {
    return EDR_P0_FILE_READ_REASON_START_KEY_MISSING;
  }
  if (strcmp(live_reason, "process_start_key_mismatch") == 0 ||
      strcmp(live_reason, "telemetry_pid_mismatch") == 0 ||
      strcmp(live_reason, "live_creation_filetime_mismatch") == 0) {
    return EDR_P0_FILE_READ_REASON_GENERATION_MISMATCH;
  }
  return EDR_P0_FILE_READ_REASON_LIVE_GENERATION_UNAVAILABLE;
}

/* A live target query validates the target PID generation.  Kernel-Process
 * Start supplies the target key in its payload; EVENT_HEADER extended data is
 * intentionally not used here because it identifies the logging process.
 * Kernel-File actor events use that key when the provider exposes it; the
 * ARM64 schema may omit it. EventHeader.TimeStamp remains event time and is
 * never a creation surrogate. */
static const char *p0_process_path_basename(const char *path);

static int p0_bind_process_generation(EdrBehaviorRecord *br) {
  HANDLE process = NULL;
  FILETIME created, exited, kernel, user;
  ULARGE_INTEGER observed;
  EdrLiveProcessGeneration live;
  uint64_t source_start_key;
  uint64_t source_creation;
  uint64_t event_unix_ns;
  uint64_t creation_unix_ns;
  char reason[64];
  if (!br || br->is_security_4688 ||
      (br->type != EDR_EVENT_PROCESS_CREATE && br->type != EDR_EVENT_FILE_READ) ||
      (br->type == EDR_EVENT_PROCESS_CREATE &&
       !edr_process_create_is_lifecycle_authoritative(br))) {
    return 0;
  }
  source_start_key = br->process_start_key;
  source_creation = br->process_creation_filetime_100ns;
  if (!br->pid) {
    snprintf(br->process_generation_source, sizeof(br->process_generation_source), "%s",
             "live_process_pid_unavailable");
    p0_mark_file_read_collector_evidence(
        br, EDR_P0_FILE_READ_REASON_LIVE_GENERATION_UNAVAILABLE);
    return 0;
  }
  process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, br->pid);
  if (!process) {
    snprintf(br->process_generation_source, sizeof(br->process_generation_source), "%s",
             "live_process_open_failed");
    p0_mark_file_read_collector_evidence(br,
                                         EDR_P0_FILE_READ_REASON_LIVE_GENERATION_UNAVAILABLE);
    return 0;
  }
  reason[0] = '\0';
  memset(&live, 0, sizeof(live));
  if (!edr_process_generation_query_live(process, &live, reason, sizeof(reason)) ||
      live.pid != br->pid ||
      (source_start_key != 0u && live.process_start_key != source_start_key) ||
      !GetProcessTimes(process, &created, &exited, &kernel, &user)) {
    const char *failure_reason =
        live.pid != 0u && live.pid != br->pid ? "telemetry_pid_mismatch" :
        (source_start_key != 0u && live.process_start_key != 0u &&
         live.process_start_key != source_start_key ? "process_start_key_mismatch" :
         (reason[0] ? reason : "live_generation_query_failed"));
    CloseHandle(process);
    snprintf(br->process_generation_source, sizeof(br->process_generation_source), "%s",
             failure_reason);
    p0_mark_file_read_collector_evidence(
        br, p0_file_read_live_generation_reason(failure_reason));
    return 0;
  }
  observed.LowPart = created.dwLowDateTime;
  observed.HighPart = created.dwHighDateTime;
  if (!live.creation_filetime_100ns || observed.QuadPart != live.creation_filetime_100ns ||
      (source_creation != 0u && source_creation != live.creation_filetime_100ns)) {
    CloseHandle(process);
    snprintf(br->process_generation_source, sizeof(br->process_generation_source), "%s",
             "live_creation_filetime_mismatch");
    p0_mark_file_read_collector_evidence(br,
                                         EDR_P0_FILE_READ_REASON_GENERATION_MISMATCH);
    return 0;
  }
  creation_unix_ns = filetime_100ns_to_unix_ns(live.creation_filetime_100ns);
  event_unix_ns = br->event_time_ns > 0 ? (uint64_t)br->event_time_ns : 0u;
  /* A process-start event may be delivered late, but its recorded timestamp
   * must stay close to and never materially predate the queried creation. A
   * five-second bound covers observed Security/Kernel delivery skew without
   * accepting an arbitrary current occupant of a reused PID. */
  if (br->type == EDR_EVENT_PROCESS_CREATE &&
      (!event_unix_ns || !creation_unix_ns ||
       event_unix_ns + 100000000ULL < creation_unix_ns ||
       event_unix_ns > creation_unix_ns + 5000000000ULL)) {
    CloseHandle(process);
    snprintf(br->process_generation_source, sizeof(br->process_generation_source), "%s",
             "live_generation_event_time_mismatch");
    return 0;
  }
  /* Kernel-File Read does not carry ProcessStartKey on every supported
   * provider architecture. A live query is still generation-safe when the
   * ETW event timestamp proves the current PID lifetime already existed at
   * the time of the Read. A reused PID necessarily has a later creation
   * FILETIME and is rejected here. */
  if (br->type == EDR_EVENT_FILE_READ &&
      (!event_unix_ns || !creation_unix_ns || event_unix_ns < creation_unix_ns)) {
    CloseHandle(process);
    snprintf(br->process_generation_source, sizeof(br->process_generation_source), "%s",
             "file_read_live_generation_event_time_mismatch");
    p0_mark_file_read_collector_evidence(
        br, EDR_P0_FILE_READ_REASON_GENERATION_MISMATCH);
    return 0;
  }
  if (br->type == EDR_EVENT_PROCESS_CREATE && !br->cmdline[0]) {
    reason[0] = '\0';
    if (edr_process_command_line_query_live(process, br->cmdline, sizeof(br->cmdline),
                                            reason, sizeof(reason))) {
      snprintf(br->command_line_origin, sizeof(br->command_line_origin), "%s",
               "live_same_generation");
    } else {
      /* The process may exit between ETW delivery and this bounded query.
       * Keep the raw source, but never borrow a PID-only command line from a
       * new process occupant or present an incomplete string as evaluable. */
      br->cmdline[0] = '\0';
      snprintf(br->command_line_origin, sizeof(br->command_line_origin), "%s",
               "live_same_generation_unavailable");
    }
  }
  if (br->type == EDR_EVENT_FILE_READ) {
    char actor_path[EDR_BR_STR_LONG];
    /* The same handle already proved PID, StartKey, FILETIME and event-time
     * order. A collector-cache miss must not leave a valid actor unnamed,
     * nor may the target file path be substituted for its executable. */
    if (!edr_windows_process_image_path_utf8(process, actor_path, sizeof(actor_path)) ||
        !actor_path[0]) {
      CloseHandle(process);
      p0_mark_file_read_collector_evidence(br, EDR_P0_FILE_READ_REASON_ACTOR_IMAGE_UNRESOLVED);
      return 0;
    }
    copy_trunc(br->exe_path, sizeof(br->exe_path), actor_path);
    copy_trunc(br->image_path_canonical, sizeof(br->image_path_canonical), actor_path);
    copy_trunc(br->process_name, sizeof(br->process_name), p0_process_path_basename(actor_path));
    copy_trunc(br->image_path_resolution_status, sizeof(br->image_path_resolution_status), "RESOLVED");
    copy_trunc(br->image_path_resolution_source, sizeof(br->image_path_resolution_source), "live_same_generation");
  }
  CloseHandle(process);
  br->process_start_key = live.process_start_key;
  br->process_creation_filetime_100ns = live.creation_filetime_100ns;
  snprintf(br->process_generation_source, sizeof(br->process_generation_source), "%s",
           br->type == EDR_EVENT_PROCESS_CREATE
               ? (source_start_key != 0u ? "kernel_payload_live_telemetry"
                                         : "target_live_telemetry")
               : (source_start_key != 0u
                      ? "etw_start_key_live_telemetry"
                      : "file_read_pid_event_time_live_telemetry"));
  return 1;
}

static const char *p0_process_path_basename(const char *path) {
  const char *base = path;
  if (!path) return "";
  for (const char *cursor = path; *cursor; ++cursor) {
    if (*cursor == '\\' || *cursor == '/') base = cursor + 1;
  }
  return base;
}

/* A parent which predates Agent startup has only a Toolhelp PID/name warmup
 * entry.  Recover its generation from one live process handle, never from the
 * PID alone: telemetry StartKey, telemetry/CreateProcess FILETIME and the
 * queried image path all belong to that handle.  A replacement which reused
 * the PID after the child was created is rejected by the creation-time order. */
static int p0_resolve_live_parent_generation(const EdrBehaviorRecord *child,
                                             ProcessTreeEntry *out_parent) {
  HANDLE process = NULL;
  FILETIME created, exited, kernel, user;
  ULARGE_INTEGER observed;
  EdrLiveProcessGeneration live;
  char path[EDR_BR_STR_LONG];
  char cmdline[EDR_BR_STR_LONG];
  char reason[64];
  uint64_t parent_creation_ns;
  uint64_t child_event_ns;
  if (out_parent) memset(out_parent, 0, sizeof(*out_parent));
  if (!child || !out_parent || child->type != EDR_EVENT_PROCESS_CREATE ||
      child->ppid == 0u || child->process_creation_filetime_100ns == 0u) {
    return 0;
  }
  process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, child->ppid);
  if (!process) return 0;
  memset(&live, 0, sizeof(live));
  reason[0] = '\0';
  if (!edr_process_generation_query_live(process, &live, reason, sizeof(reason)) ||
      live.pid != child->ppid || live.process_start_key == 0u ||
      live.creation_filetime_100ns == 0u ||
      !GetProcessTimes(process, &created, &exited, &kernel, &user)) {
    CloseHandle(process);
    return 0;
  }
  observed.LowPart = created.dwLowDateTime;
  observed.HighPart = created.dwHighDateTime;
  if (observed.QuadPart != live.creation_filetime_100ns ||
      live.creation_filetime_100ns > child->process_creation_filetime_100ns ||
      !edr_windows_process_image_path_utf8(process, path, sizeof(path)) || !path[0]) {
    CloseHandle(process);
    return 0;
  }
  parent_creation_ns = filetime_100ns_to_unix_ns(live.creation_filetime_100ns);
  child_event_ns = child->event_time_ns > 0 ? (uint64_t)child->event_time_ns : 0u;
  if (parent_creation_ns == 0u || child_event_ns == 0u ||
      parent_creation_ns > child_event_ns + 100000000ULL) {
    CloseHandle(process);
    return 0;
  }
  cmdline[0] = '\0';
  reason[0] = '\0';
  (void)edr_process_command_line_query_live(process, cmdline, sizeof(cmdline),
                                            reason, sizeof(reason));
  CloseHandle(process);
  memset(out_parent, 0, sizeof(*out_parent));
  out_parent->pid = child->ppid;
  out_parent->process_start_key = live.process_start_key;
  out_parent->creation_filetime_100ns = live.creation_filetime_100ns;
  out_parent->start_time_ns = parent_creation_ns;
  out_parent->last_seen_ns = child_event_ns;
  snprintf(out_parent->process_name, sizeof(out_parent->process_name), "%s",
           p0_process_path_basename(path));
  snprintf(out_parent->cmdline, sizeof(out_parent->cmdline), "%s", cmdline);
  snprintf(out_parent->exe_path, sizeof(out_parent->exe_path), "%s", path);
  (void)edr_pt_cache_put_generation(
      child->ppid, 0u, p0_process_path_basename(path), cmdline, path, NULL,
      parent_creation_ns, live.process_start_key, live.creation_filetime_100ns);
  /* The current record is already bound by the validated live handle. Cache
   * pressure or an older same-generation timestamp must not erase that fact;
   * insertion is best-effort only for later descendants. */
  return 1;
}

static int enrich_process_token_identity(EdrBehaviorRecord *br) {
  HANDLE process = NULL;
  HANDLE token = NULL;
  TOKEN_USER *token_user = NULL;
  DWORD required = 0u;
  TOKEN_STATISTICS statistics;
  DWORD statistics_size = 0u;
  LPSTR sid = NULL;
  char account[EDR_BR_STR_SHORT];
  char domain[EDR_BR_STR_SHORT];
  DWORD account_cap = (DWORD)sizeof(account);
  DWORD domain_cap = (DWORD)sizeof(domain);
  SID_NAME_USE sid_use;
  int resolved = 0;
  uint64_t actual_creation_filetime = 0u;
  char live_path[EDR_BR_STR_LONG];
  char correlated_target_sid[EDR_BR_STR_SHORT];
  char correlated_target_logon[64];
  DWORD open_error = ERROR_SUCCESS;
  int validate_4688_target = 0;
  int target_4688_mismatch = 0;
  int path_invalid_utf8 = 0;

  if (!br || br->type != EDR_EVENT_PROCESS_CREATE || br->is_security_4688 || br->pid == 0u) {
    return 0;
  }
  memset(correlated_target_sid, 0, sizeof(correlated_target_sid));
  memset(correlated_target_logon, 0, sizeof(correlated_target_logon));
  validate_4688_target = strcmp(br->identity_quality, "target_4688") == 0;
  if (validate_4688_target) {
    /* A 4688 has no raw ProcessStartKey.  It is only advisory until the live
     * token of the already StartKey/FILETIME/path-bound process agrees
     * with both Target Subject values.  This prevents delayed A/then-PID-reuse
     * B 4688 records from lending B an A identity. */
    snprintf(correlated_target_sid, sizeof(correlated_target_sid), "%s", br->user_sid);
    snprintf(correlated_target_logon, sizeof(correlated_target_logon), "%s", br->logon_id);
    /* Do not let raw Security data survive a failed live validation.  The
     * fields below are repopulated only from the exact-bound process token. */
    br->username[0] = '\0';
    br->domain[0] = '\0';
    br->user_sid[0] = '\0';
    br->logon_id[0] = '\0';
    if (!correlated_target_sid[0] || !correlated_target_logon[0]) {
      snprintf(br->identity_source, sizeof(br->identity_source), "%s",
               "target_4688_incomplete");
      snprintf(br->identity_quality, sizeof(br->identity_quality), "%s", "unavailable");
      snprintf(br->source_completeness, sizeof(br->source_completeness), "%s",
               "NOT_EVALUABLE");
      return 0;
    }
  }
  if (br->image_path_canonical[0] &&
      edr_windows_utf8_path_compare_ci(br->image_path_canonical,
                                        br->image_path_canonical) ==
          EDR_WINDOWS_UTF8_PATH_COMPARE_INVALID_UTF8) {
    path_invalid_utf8 = 1;
    goto done;
  }
  if (!validate_4688_target && (br->username[0] || br->user_sid[0])) {
    return 0;
  }
  if (!br->process_start_key || !br->process_creation_filetime_100ns ||
      !br->image_path_canonical[0]) {
    open_error = ERROR_INVALID_PARAMETER;
    goto done;
  }
  process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, br->pid);
  if (!process) {
    open_error = GetLastError();
    goto done;
  }
  {
    FILETIME created, exited, kernel, user;
    ULARGE_INTEGER created_value;
    uint64_t telemetry_creation = 0u;
    char generation_reason[64];
    generation_reason[0] = '\0';
    if (!edr_process_generation_validate_live(process, br->pid, br->process_start_key,
                                              &telemetry_creation, generation_reason,
                                              sizeof(generation_reason)) ||
        !GetProcessTimes(process, &created, &exited, &kernel, &user)) {
      open_error = GetLastError();
      goto done;
    }
    created_value.LowPart = created.dwLowDateTime;
    created_value.HighPart = created.dwHighDateTime;
    actual_creation_filetime = created_value.QuadPart;
    if (!actual_creation_filetime || actual_creation_filetime != telemetry_creation ||
        actual_creation_filetime != br->process_creation_filetime_100ns) {
      open_error = ERROR_INVALID_PARAMETER;
      goto done;
    }
    if (!edr_windows_process_image_path_utf8(process, live_path, sizeof(live_path))) {
      open_error = GetLastError();
      path_invalid_utf8 = open_error == ERROR_NO_UNICODE_TRANSLATION;
      goto done;
    }
    {
      EdrWindowsUtf8PathCompareResult path_compare =
          edr_windows_utf8_path_compare_ci(live_path, br->image_path_canonical);
      if (path_compare != EDR_WINDOWS_UTF8_PATH_COMPARE_MATCH) {
        path_invalid_utf8 = path_compare == EDR_WINDOWS_UTF8_PATH_COMPARE_INVALID_UTF8;
        open_error = path_invalid_utf8 ? ERROR_NO_UNICODE_TRANSLATION : ERROR_INVALID_PARAMETER;
        goto done;
      }
    }
  }
  for (uint32_t i = 0u; i < EDR_P0_TOKEN_IDENTITY_CACHE; i++) {
    EdrP0TokenIdentityCacheEntry *entry = &s_p0_token_identity_cache[i];
    if (!p0_token_identity_cache_same_generation(entry, br)) {
      continue;
    }
    if (validate_4688_target &&
        (strcmp(entry->user_sid, correlated_target_sid) != 0 ||
         strcmp(entry->logon_id, correlated_target_logon) != 0)) {
      target_4688_mismatch = 1;
      open_error = ERROR_INVALID_DATA;
      goto done;
    }
    snprintf(br->username, sizeof(br->username), "%s", entry->username);
    snprintf(br->domain, sizeof(br->domain), "%s", entry->domain);
    snprintf(br->user_sid, sizeof(br->user_sid), "%s", entry->user_sid);
    snprintf(br->logon_id, sizeof(br->logon_id), "%s", entry->logon_id);
    snprintf(br->identity_source, sizeof(br->identity_source), "%s",
             validate_4688_target ? "token_cache_4688_validated" : "token_cache");
    snprintf(br->identity_quality, sizeof(br->identity_quality), "%s", "token_sid");
    resolved = 1;
    goto done;
  }
  if (!OpenProcessToken(process, TOKEN_QUERY, &token)) {
    open_error = GetLastError();
    goto done;
  }
  (void)GetTokenInformation(token, TokenUser, NULL, 0u, &required);
  if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || required == 0u) {
    goto done;
  }
  token_user = (TOKEN_USER *)malloc(required);
  if (!token_user || !GetTokenInformation(token, TokenUser, token_user, required, &required) ||
      !ConvertSidToStringSidA(token_user->User.Sid, &sid) || !sid || !sid[0]) {
    goto done;
  }
  snprintf(br->user_sid, sizeof(br->user_sid), "%s", sid);
  if (LookupAccountSidA(NULL, token_user->User.Sid, account, &account_cap, domain, &domain_cap,
                        &sid_use)) {
    snprintf(br->domain, sizeof(br->domain), "%s", domain);
    if (domain[0]) {
      snprintf(br->username, sizeof(br->username), "%s\\%s", domain, account);
    } else {
      snprintf(br->username, sizeof(br->username), "%s", account);
    }
  }
  if (GetTokenInformation(token, TokenStatistics, &statistics, sizeof(statistics), &statistics_size)) {
    snprintf(br->logon_id, sizeof(br->logon_id), "0x%08lx%08lx",
             (unsigned long)statistics.AuthenticationId.HighPart,
             (unsigned long)statistics.AuthenticationId.LowPart);
  }
  if (validate_4688_target &&
      (strcmp(br->user_sid, correlated_target_sid) != 0 ||
       strcmp(br->logon_id, correlated_target_logon) != 0)) {
    target_4688_mismatch = 1;
    open_error = ERROR_INVALID_DATA;
    goto done;
  }
  snprintf(br->identity_source, sizeof(br->identity_source), "%s",
           validate_4688_target ? "token_query_4688_validated" : "token_query");
  snprintf(br->identity_quality, sizeof(br->identity_quality), "%s", "token_sid");
  resolved = 1;
done:
  if (sid) {
    LocalFree(sid);
  }
  free(token_user);
  if (token) {
    CloseHandle(token);
  }
  if (process) {
    CloseHandle(process);
  }
  if (resolved) {
    EdrP0TokenIdentityCacheEntry *entry =
        &s_p0_token_identity_cache[s_p0_token_identity_next++ % EDR_P0_TOKEN_IDENTITY_CACHE];
    memset(entry, 0, sizeof(*entry));
    entry->pid = br->pid;
    entry->process_start_key = br->process_start_key;
    entry->process_creation_filetime_100ns = actual_creation_filetime;
    snprintf(entry->canonical_path, sizeof(entry->canonical_path), "%s", br->image_path_canonical);
    snprintf(entry->username, sizeof(entry->username), "%s", br->username);
    snprintf(entry->domain, sizeof(entry->domain), "%s", br->domain);
    snprintf(entry->user_sid, sizeof(entry->user_sid), "%s", br->user_sid);
    snprintf(entry->logon_id, sizeof(entry->logon_id), "%s", br->logon_id);
    entry->valid = 1u;
  } else {
    if (path_invalid_utf8) {
      br->username[0] = '\0';
      br->domain[0] = '\0';
      br->user_sid[0] = '\0';
      br->logon_id[0] = '\0';
      snprintf(br->identity_source, sizeof(br->identity_source), "%s",
               validate_4688_target ? "target_4688_live_path_invalid_utf8" :
                                      "token_path_invalid_utf8");
      snprintf(br->identity_quality, sizeof(br->identity_quality), "%s", "unavailable");
      snprintf(br->image_path_resolution_source, sizeof(br->image_path_resolution_source),
               "%s", "invalid_utf8");
      snprintf(br->image_path_resolution_status, sizeof(br->image_path_resolution_status),
               "%s", "NOT_EVALUABLE");
      snprintf(br->source_completeness, sizeof(br->source_completeness), "%s",
               "NOT_EVALUABLE");
    } else if (validate_4688_target) {
      br->username[0] = '\0';
      br->domain[0] = '\0';
      br->user_sid[0] = '\0';
      br->logon_id[0] = '\0';
      snprintf(br->identity_source, sizeof(br->identity_source), "%s",
               target_4688_mismatch ? "target_4688_live_mismatch" :
                                       "target_4688_live_unavailable");
      snprintf(br->identity_quality, sizeof(br->identity_quality), "%s", "unavailable");
      snprintf(br->source_completeness, sizeof(br->source_completeness), "%s",
               "NOT_EVALUABLE");
    } else {
      snprintf(br->identity_source, sizeof(br->identity_source), "%s",
               open_error == ERROR_ACCESS_DENIED ? "token_access_denied" : "token_query");
      snprintf(br->identity_quality, sizeof(br->identity_quality), "%s",
               open_error == ERROR_ACCESS_DENIED ? "access_denied" : "unavailable");
    }
  }
  return resolved;
}
#endif

static const char *p0_process_create_not_evaluable_reason(const EdrBehaviorRecord *br) {
#ifdef _WIN32
  if (!br || br->type != EDR_EVENT_PROCESS_CREATE) {
    return NULL;
  }
  if (br->is_security_4688) {
    return "security_4688_enrichment";
  }
  /* The current authenticated IR has no artifact hash/signature/file-id
   * predicates.  A background pathname-snapshot timeout therefore cannot
   * suppress an otherwise complete chain/cmd/user detection.  Terminal block
   * authority is separately rejected in the direct emitter and policy layer. */
  if (strcmp(br->identity_source, "target_4688_live_mismatch") == 0) {
    return "target_4688_live_identity_mismatch";
  }
  if (strcmp(br->identity_source, "target_4688_incomplete") == 0) {
    return "target_4688_identity_incomplete";
  }
  if (strcmp(br->identity_source, "target_4688_live_unavailable") == 0) {
    return "target_4688_live_identity_unavailable";
  }
  if (strcmp(br->identity_source, "target_4688_live_path_invalid_utf8") == 0) {
    return "target_4688_live_identity_unavailable";
  }
  if (strcmp(br->identity_source, "token_path_invalid_utf8") == 0) {
    return "image_path_not_resolved";
  }
  /* A parser or record-boundary omission is named in source_truncated_fields.
   * It remains authoritative even if a later coalescer stage records a
   * correlation status in source_completeness. */
  if (strcmp(br->source_completeness, "TRUNCATED") == 0 ||
      br->source_truncated_fields[0] != '\0') {
    return "source_fields_truncated";
  }
  if (strcmp(br->source_completeness, "NOT_EVALUABLE") == 0) {
    return "process_generation_or_correlation_unavailable";
  }
  if (strcmp(br->source_completeness, "COALESCE_BACKPRESSURE") == 0) {
    return "coalescer_backpressure";
  }
  if (!br->process_creation_filetime_100ns) {
    return "missing_process_generation";
  }
  if ((br->image_path_raw[0] && strcmp(br->image_path_resolution_status, "RESOLVED") != 0) ||
      strcmp(br->image_path_resolution_status, "NOT_EVALUABLE") == 0) {
    return "image_path_not_resolved";
  }
  if (!br->process_name[0] || !br->exe_path[0]) {
    return "missing_process_identity";
  }
  if (!br->cmdline[0]) {
    return "missing_cmdline";
  }
  if (br->ppid == 0u || strcmp(br->parent_resolution_status, "RESOLVED") != 0 ||
      !br->parent_path[0] || !br->parent_creation_time[0]) {
    return "missing_parent_generation";
  }
  if (strcmp(br->identity_quality, "target_4688") != 0 &&
      strcmp(br->identity_quality, "token_sid") != 0) {
    return strcmp(br->identity_quality, "creator_fallback") == 0
        ? "creator_only_identity" : "missing_target_identity";
  }
  if (!br->username[0] && !br->user_sid[0]) {
    return "missing_target_identity";
  }
#else
  (void)br;
#endif
  return NULL;
}

static void p0_mark_not_evaluable(EdrBehaviorRecord *br, const char *reason) {
  EdrBehaviorRecord built;
  if (!br || !reason) return;
  if (!edr_p0_source_only_build_pre_evaluation_record(br, reason, &built)) {
    fprintf(stderr, "[P0] unregistered or malformed pre-evaluation reason rejected: %s\n",
            reason);
    return;
  }
  *br = built;
}

static void enrich_process_integrity_context(EdrBehaviorRecord *br) {
  if (!br || br->type != EDR_EVENT_PROCESS_CREATE || br->pid == 0u) {
    return;
  }
  if (br->ppid > 0u) {
    ProcessTreeEntry parent;
    int parent_from_live = 0;
    int parent_snapshot = edr_pt_cache_snapshot_at(
        br->ppid, (uint64_t)(br->event_time_ns > 0 ? br->event_time_ns : 0), &parent);
#ifdef _WIN32
    if ((parent_snapshot != 0 || parent.process_start_key == 0u ||
         parent.creation_filetime_100ns == 0u || parent.start_time_ns == 0u) &&
        p0_resolve_live_parent_generation(br, &parent)) {
      parent_snapshot = 0;
      parent_from_live = 1;
    }
#endif
    if (parent_snapshot == 0 &&
        parent.process_start_key != 0u &&
        parent.creation_filetime_100ns != 0u && parent.start_time_ns != 0u) {
      /* The historical cache, not raw 4688 fields or a current PID lookup,
       * owns the parent generation.  Overwrite any earlier unbound display
       * values so an A->B PID reuse cannot borrow B's path or FILETIME. */
      snprintf(br->parent_name, sizeof(br->parent_name), "%s", parent.process_name);
      snprintf(br->parent_path, sizeof(br->parent_path), "%s", parent.exe_path);
      format_record_time_ns((int64_t)filetime_100ns_to_unix_ns(
                                parent.creation_filetime_100ns), br->parent_creation_time,
                            sizeof(br->parent_creation_time));
      snprintf(br->parent_resolution_source, sizeof(br->parent_resolution_source), "%s",
               parent_from_live ? "live_parent_generation" : "process_tree_cache");
      snprintf(br->parent_resolution_status, sizeof(br->parent_resolution_status), "%s",
               parent.process_name[0] && parent.exe_path[0] && br->parent_creation_time[0] ?
                   "RESOLVED" : "NOT_EVALUABLE");
    } else {
      /* A PID-only lookup cannot establish a parent generation.  Keep the
       * source record and let the P0 pre-evaluation gate emit the registered
       * missing_parent_generation disposition instead of borrowing a current
       * process that may have reused this PID. */
      br->parent_creation_time[0] = '\0';
      snprintf(br->parent_resolution_source, sizeof(br->parent_resolution_source), "%s",
               "generation_unavailable");
      snprintf(br->parent_resolution_status, sizeof(br->parent_resolution_status), "%s",
               "NOT_EVALUABLE");
    }
  }
  if (edr_process_create_is_lifecycle_authoritative(br) && br->process_start_key != 0u &&
      br->process_creation_filetime_100ns != 0u) {
    (void)edr_pt_cache_put_generation(
        br->pid, br->ppid, br->process_name, br->cmdline, br->exe_path, br->parent_name,
        (uint64_t)(br->event_time_ns > 0 ? br->event_time_ns : 0), br->process_start_key,
        br->process_creation_filetime_100ns);
  }
  {
    uint32_t chain_depth = 0u;
    edr_pt_cache_fill_record_at(
        br->pid, (uint64_t)(br->event_time_ns > 0 ? br->event_time_ns : 0),
        br->grandparent_name, sizeof(br->grandparent_name), br->grandparent_path,
        sizeof(br->grandparent_path), &br->grandparent_pid, br->parent_cmdline,
        sizeof(br->parent_cmdline), &chain_depth);
    if (chain_depth > 0u) {
      br->process_chain_depth = chain_depth;
    }
  }
  if (!br->process_creation_time[0]) {
    format_record_time_ns((int64_t)(br->process_creation_filetime_100ns
                                        ? filetime_100ns_to_unix_ns(
                                              br->process_creation_filetime_100ns)
                                        : (uint64_t)(br->event_time_ns > 0 ?
                                                         br->event_time_ns : 0)),
                          br->process_creation_time, sizeof(br->process_creation_time));
  }
  /* Hashing and Authenticode verification run in process_evidence_worker.
   * This worker is also used by the coalescer deadline, never by an ETW
   * callback or this hot preprocess path. */
#ifdef _WIN32
  (void)enrich_process_token_identity(br);
#endif
}

static void log_p0_runtime_state(void) {
  EdrP0RuleIrBinding binding;
  edr_p0_rule_ir_lazy_init();
  const char *ir_source = "";
  const char *ir_sha256 = "";
  size_t ir_plain_size = 0u;
  (void)edr_p0_rule_ir_get_bundle_info(&ir_source, &ir_plain_size, &ir_sha256);
  memset(&binding, 0, sizeof(binding));
  (void)edr_p0_rule_ir_get_binding(&binding);
  fprintf(stderr, "[P0] direct_emit=%s ir_ready=%d rules=%d bundle=%s ir_plain_size=%zu ir_sha256=%s ir_source=%s\n",
          p0_direct_emit_enabled() ? "on" : "off",
          edr_p0_rule_ir_is_ready(),
          edr_p0_rule_ir_rule_count(),
          binding.rules_bundle_version[0] ? binding.rules_bundle_version : "unknown",
          ir_plain_size,
          (ir_sha256 && ir_sha256[0]) ? ir_sha256 : "unknown",
          (ir_source && ir_source[0]) ? ir_source : "unknown");
}

static void emit_behavior_record(const EdrBehaviorRecord *br) {
  if (!br) {
    return;
  }
  uint8_t buf[16384];
  size_t n = 0;
  const char *enc = getenv("EDR_BEHAVIOR_ENCODING");
  if (!enc || enc[0] == '\0' || strcmp(enc, "protobuf") == 0) {
#ifdef EDR_HAVE_NANOPB
    n = edr_behavior_record_encode_protobuf(br, buf, sizeof(buf));
#endif
    if (n == 0) {
      n = edr_behavior_wire_encode(br, buf, sizeof(buf));
    }
  } else if (enc && strcmp(enc, "protobuf_c") == 0) {
    n = edr_behavior_record_encode_protobuf_c(br, buf, sizeof(buf));
    if (n == 0) {
      n = edr_behavior_wire_encode(br, buf, sizeof(buf));
    }
  } else {
    n = edr_behavior_wire_encode(br, buf, sizeof(buf));
  }
  if (n > 0) {
    (void)edr_event_batch_push(buf, n);
  }
}

/* behavior_summary flush 的 emit 回调：直接复用统一编码 + 入批次路径。 */
static void emit_summary_record(const EdrBehaviorRecord *br) {
  emit_behavior_record(br);
}

/* 节流的行为簇摘要 flush：最多每 ~30s 扫描一次已关闭窗口的聚合槽。 */
static void poll_summary_flush(void) {
  static uint64_t s_last_flush_mono_ns;
  uint64_t mono = edr_monotonic_ns();
  if (s_last_flush_mono_ns != 0u && mono - s_last_flush_mono_ns < 30000000000ULL) {
    return;
  }
  s_last_flush_mono_ns = mono;
  int64_t now_ns = (int64_t)time(NULL) * 1000000000LL;
  edr_local_evidence_cache_flush_summaries(now_ns, emit_summary_record);
}

static int p0_process_create_candidate(const EdrBehaviorRecord *br) {
#ifdef _WIN32
  if (!br || br->type != EDR_EVENT_PROCESS_CREATE) return 0;
  /* Fast manifest-backed prefilter.  A full rule match is allowed when all
   * fields are present; otherwise only a process/path interest match may
   * reserve bounded coalescer capacity. */
  if (edr_p0_rule_ir_br_matches_any(br)) return 1;
  return edr_p0_rule_ir_is_interesting_process_name(br->process_name) ||
         edr_p0_rule_ir_is_interesting_process_name(br->exe_path) ||
         edr_p0_rule_ir_is_interesting_process_name(br->image_path_canonical);
#else
  (void)br;
  return 0;
#endif
}

static void apply_process_evidence(EdrBehaviorRecord *br) {
#ifdef _WIN32
  EdrProcessEvidence requested;
  EdrProcessEvidence evidence;
  uint64_t generation;
  int evidence_ready;
  int identity_evaluable;
  const char *artifact_quality;
  const char *artifact_reason;
  char file_identity[EDR_WINDOWS_FILE_IDENTITY_V1_CAP * 2u];
  char hash_value[96], hash_quality[64], hash_reason[160], signature_status[64], signature_source[96];
  char signer[1024], thumbprint[192], revocation[64], signature_quality[64], signature_reason[160];
  int n;
  if (!br || br->type != EDR_EVENT_PROCESS_CREATE || br->is_security_4688) return;
  /* Never spend the bounded wait on ordinary ProcessCreate traffic.  The
   * coalescer already admits only P0-interest records to this evidence path;
   * non-candidates proceed without a synchronous hash/WVT wait. */
  if (!p0_process_create_candidate(br)) return;
  generation = br->process_start_key;
  memset(&requested, 0, sizeof(requested));
  evidence_ready = edr_process_evidence_request(
      br->image_path_canonical[0] ? br->image_path_canonical : br->exe_path,
      generation, edr_monotonic_ns(), &requested);
  evidence = requested;
  if (!evidence_ready &&
      (strcmp(requested.hash_reason, "queued") == 0 ||
       strcmp(requested.hash_reason, "identity_revalidation_pending") == 0)) {
    evidence_ready = edr_process_evidence_wait(
        br->image_path_canonical[0] ? br->image_path_canonical : br->exe_path,
        generation, edr_monotonic_ns(), 1000ULL * 1000000ULL, &evidence);
  }
  if (!evidence_ready && !evidence.file_identity[0]) {
    snprintf(evidence.file_identity, sizeof(evidence.file_identity), "%s",
             requested.file_identity);
    evidence.file_write_time = requested.file_write_time;
  }
  /* The worker owns one handle for this pathname snapshot, but that handle is
   * first opened after the ProcessCreate event.  Do not promote its hash into
   * the process image field: A may already be running while path P now names
   * B.  Keep the snapshot only in explicitly non-authoritative evidence. */
  identity_evaluable = edr_windows_file_identity_valid(evidence.file_identity);
  if (!evidence.file_identity[0]) {
    artifact_quality = "NOT_EVALUABLE";
    artifact_reason = "file_identity_unavailable";
  } else if (!identity_evaluable) {
    /* Retain an old XOR-shaped value only as telemetry. It cannot become
     * image/action authority or an evaluable artifact identity. */
    artifact_quality = "NOT_EVALUABLE";
    artifact_reason = "legacy_file_identity_non_authoritative";
  } else {
    artifact_quality = "non_authoritative";
    artifact_reason = "process_image_section_unavailable";
  }
  if (!evidence_json_escape(evidence.file_identity, file_identity, sizeof(file_identity)) ||
      !evidence_json_escape(evidence.sha256, hash_value, sizeof(hash_value)) ||
      !evidence_json_escape(evidence.hash_quality, hash_quality, sizeof(hash_quality)) ||
      !evidence_json_escape(evidence.hash_reason, hash_reason, sizeof(hash_reason)) ||
      !evidence_json_escape(evidence.signature_status, signature_status, sizeof(signature_status)) ||
      !evidence_json_escape(evidence.signature_source, signature_source, sizeof(signature_source)) ||
      !evidence_json_escape(evidence.signer, signer, sizeof(signer)) ||
      !evidence_json_escape(evidence.thumbprint, thumbprint, sizeof(thumbprint)) ||
      !evidence_json_escape(evidence.revocation, revocation, sizeof(revocation)) ||
      !evidence_json_escape(evidence.signature_quality, signature_quality, sizeof(signature_quality)) ||
      !evidence_json_escape(evidence.signature_reason, signature_reason, sizeof(signature_reason))) {
    snprintf(br->detection_context, sizeof(br->detection_context),
             "%s", "{\"evidence\":{\"omitted\":true,\"reason\":\"evidence_json_escape_overflow\"}}");
    return;
  }
  n = snprintf(br->detection_context, sizeof(br->detection_context),
               "{\"evidence\":{\"artifact\":{\"source\":\"post_event_path_snapshot\",\"quality\":\"%s\",\"reason\":\"%s\"},\"file_identity\":\"%s\",\"hash\":{\"value\":\"%s\",\"source\":\"background_file_hash\",\"quality\":\"%s\",\"reason\":\"%s\"},"
               "\"signature\":{\"status\":\"%s\",\"source\":\"%s\",\"signer\":\"%s\",\"thumbprint\":\"%s\",\"revocation\":\"%s\",\"quality\":\"%s\",\"reason\":\"%s\"}}}",
               artifact_quality, artifact_reason, file_identity, hash_value, hash_quality,
               hash_reason, signature_status,
               signature_source, signer, thumbprint, revocation, signature_quality, signature_reason);
  if (n < 0 || (size_t)n >= sizeof(br->detection_context)) {
    snprintf(br->detection_context, sizeof(br->detection_context),
             "%s", "{\"evidence\":{\"omitted\":true,\"reason\":\"evidence_json_capacity\"}}");
  }
#else
  (void)br;
#endif
}

/* Resource pressure may shed ordinary telemetry, but it is never authority to
 * discard a potential P0 input.  A drop is safe only after the active,
 * verified IR has evaluated the actual record and proved it matches no rule.
 * If the IR is unavailable, preserving the record is the fail-closed choice:
 * a legacy/process fallback or a later ruleset-not-evaluable disposition must
 * still be able to observe it. */
static int p0_resource_throttle_proven_miss(const EdrBehaviorRecord *br) {
  if (!br) {
    return 0;
  }
  edr_p0_rule_ir_lazy_init();
  if (!edr_p0_rule_ir_is_ready()) {
    return 0;
  }
  return edr_p0_rule_ir_br_matches_any(br) ? 0 : 1;
}

/* Collector evidence gates are an authority boundary, not ordinary telemetry:
 * once marked, they bypass rule matching, generic admission and enforcement.
 * The return value is intentionally ignored here because the common durable
 * source-only owner latches unhealthy/retry state on failure. */
static int p0_process_collector_evidence_gate(EdrBehaviorRecord *br) {
  int outcome;
  if (!br || !br->collector_evidence_gate[0]) return 0;
  outcome = edr_p0_rule_emit_collector_evidence_gate(br);
#ifdef _WIN32
  edr_collector_file_read_metadata_gate_delivery_result(br->event_id, outcome);
#else
  (void)outcome;
#endif
  return 1;
}

#ifdef _WIN32
static const char *p0_file_read_unavailable_reason(const EdrBehaviorRecord *br) {
  if (!br || br->type != EDR_EVENT_FILE_READ || br->collector_evidence_gate[0]) return NULL;
  if (!br->file_path[0]) {
    return EDR_P0_FILE_READ_REASON_CANONICAL_PATH_UNRESOLVED;
  }
  if (!br->image_path_canonical[0] || strcmp(br->image_path_resolution_status, "RESOLVED") != 0)
    return EDR_P0_FILE_READ_REASON_ACTOR_IMAGE_UNRESOLVED;
  if (!br->process_start_key) return EDR_P0_FILE_READ_REASON_START_KEY_MISSING;
  if (!br->process_creation_filetime_100ns ||
      (strcmp(br->process_generation_source, "etw_start_key_live_telemetry") != 0 &&
       strcmp(br->process_generation_source,
              "file_read_pid_event_time_live_telemetry") != 0)) {
    return p0_file_read_live_generation_reason(br->process_generation_source);
  }
  return NULL;
}

static int p0_file_read_evaluation_ready(void) {
  return edr_collector_file_read_p0_capability_healthy() &&
         edr_p0_rule_source_only_capability_healthy_for_event(EDR_EVENT_FILE_READ, NULL, 0u);
}

static void p0_file_read_deferred_observe(const EdrBehaviorRecord *br, const char *outcome) {
  uint64_t total = s_file_read_deferred.admitted + s_file_read_deferred.rejected +
                   s_file_read_deferred.released + s_file_read_deferred.expired;
  edr_p0_rule_observe_validation_stage(br, "file_read_deferred", outcome);
  if (total <= 8u || (total & 127u) == 0u) {
    fprintf(stderr, "[FileRead] deferred=%u admitted=%llu released=%llu expired=%llu rejected=%llu outcome=%s event=%s pid=%u\n",
            s_file_read_deferred.count, (unsigned long long)s_file_read_deferred.admitted,
            (unsigned long long)s_file_read_deferred.released,
            (unsigned long long)s_file_read_deferred.expired,
            (unsigned long long)s_file_read_deferred.rejected, outcome, br->event_id, br->pid);
  }
}
#endif

static void process_ready_record(EdrBehaviorRecord br, const EdrEventSlot *slot);

static void process_one_record(EdrBehaviorRecord br, const EdrEventSlot *slot) {
  if (slot && slot->attack_surface_hint) {
    edr_attack_surface_etw_signal();
  }
#if defined(__linux__) && !defined(_WIN32)
  /* Windows 在 ETW 回调中调用；Linux 行为事件（含未来 audit/eBPF 注入）在此对齐 */
  if (slot && (slot->type == EDR_EVENT_PROCESS_CREATE || slot->type == EDR_EVENT_PROCESS_TERMINATE)) {
    edr_pmfe_on_process_lifecycle_hint();
  }
#endif
  apply_agent_ids_to_record(&br);
  if (p0_process_collector_evidence_gate(&br)) {
    /* A collector capability assertion is intentionally source-only.  It may
     * not flow through matching, alert admission, correlation, or action. */
    return;
  }
  apply_process_evidence(&br);
  /* Token identity is bound to the same live ProcessStartKey/FILETIME handle,
   * not to a pathname artifact reopened after ProcessCreate. */
  enrich_process_integrity_context(&br);
  edr_local_evidence_cache_observe_process(&br);
  edr_local_evidence_cache_enrich_behavior(&br);
  edr_windows_event_policy_apply(&br);
  edr_pid_history_pmfe_fill_record(&br);
#ifdef _WIN32
  {
    const char *file_read_reason = p0_file_read_unavailable_reason(&br);
    if (file_read_reason) p0_mark_file_read_collector_evidence(&br, file_read_reason);
  }
#endif
  if (p0_process_collector_evidence_gate(&br)) {
    return;
  }
  {
    const char *not_evaluable_reason = p0_process_create_not_evaluable_reason(&br);
    edr_p0_rule_observe_validation_stage(
        &br, "process_evidence",
        not_evaluable_reason ? not_evaluable_reason : "complete");
    /* A rule whose complete predicate already matched the authenticated IR
     * does not become unevaluable merely because unrelated enrichment (for
     * example user, parent, or asynchronous artifact evidence) was lost when
     * a short-lived process exited.  Preserve the missing-field provenance on
     * the combined source+alert frame.  Records which only look interesting,
     * but do not yet satisfy a rule, still take the durable source-only gate.
     * Block/action authority remains independently fail-closed on an exact
     * generation and action-authoritative file identity. */
    if (not_evaluable_reason && p0_process_create_candidate(&br) &&
        !edr_p0_rule_ir_br_matches_any(&br)) {
      p0_mark_not_evaluable(&br, not_evaluable_reason);
      edr_local_evidence_cache_record_behavior(&br);
      /* Required Windows P0 evidence is absent: retain a source-only,
       * high-priority record through the one bounded retry handoff rather
       * than matching a partial record or silently dropping a SQLite fault. */
      (void)edr_p0_rule_emit_pre_evaluation_gate(&br, not_evaluable_reason);
      return;
    }
  }
#ifdef _WIN32
  if (br.type == EDR_EVENT_FILE_READ && !p0_file_read_evaluation_ready()) {
    /* Reserve this bounded wait for signed-IR path interest. Ordinary reads
     * retain the existing local-evidence path and cannot evict P0 candidates. */
    if (!edr_p0_rule_ir_file_read_path_may_match(br.file_path, NULL)) {
      edr_local_evidence_cache_record_behavior(&br);
      return;
    }
    if (edr_file_read_deferred_push(&s_file_read_deferred, &br, edr_monotonic_ns())) {
      p0_file_read_deferred_observe(&br, "held");
    } else {
      p0_file_read_deferred_observe(&br, "capacity_unavailable");
      p0_mark_file_read_collector_evidence(&br, EDR_P0_FILE_READ_REASON_DEFERRED_CAPACITY);
      (void)p0_process_collector_evidence_gate(&br);
    }
    return;
  }
#endif
  process_ready_record(br, slot);
}

/* Deferred reads arrive here with their original validated actor/path tuple.
 * Do not re-open a PID or replace it with a later occupant after the wait. */
static void process_ready_record(EdrBehaviorRecord br, const EdrEventSlot *slot) {
  /* AGT-010: low-priority records can be shed only after all fields on which
   * P0 matching depends have been enriched and the active IR has proved a
   * miss.  Inotify intentionally uses priority=1; doing this before parent
   * or chain enrichment would silently erase valid file/process P0 inputs. */
  if (edr_resource_preprocess_throttle_active() && slot && slot->priority != 0u &&
      slot->attack_surface_hint == 0u && p0_resource_throttle_proven_miss(&br)) {
    return;
  }
  /* P0 owns its hard-invalid, registry-attribution, internal-command, and
   * policy guards. Evaluate before generic admission so a local-only source
   * can still be represented by one combined source+alert frame. */
  int p0_emitted = edr_p0_rule_try_emit(&br);
  edr_correlation_evaluate(&br); /* 集成点 B：序列/合流关联（总开关默认关时为 no-op） */
  edr_net_fanout_on_event(&br);
  {
    EdrDetectionDecision dd;
    edr_detection_decision_evaluate(&br, &dd);
    if (dd.drop) {
      edr_local_evidence_cache_record_behavior(&br);
      return;
    }
    /* EQS enforcement：低上传价值（local_only）不投递平台，仅进本地证据缓存
     * （普通事件在缓存内 coalesce → 由 behavior_summary 周期性以一条摘要替代逐条）。
     * 仅 emit_context / emit_alert 继续走候选与上传路径。drop 已在上面拦下。 */
    if (dd.selection_action[0] != '\0' && strcmp(dd.selection_action, "local_only") == 0) {
      edr_local_evidence_cache_record_behavior(&br);
      return;
    }
  }
  if (!edr_preprocess_should_emit(&br)) {
    if (p0_emitted > 0) {
      edr_local_evidence_cache_record_behavior(&br);
    }
    return;
  }
  edr_local_evidence_cache_record_behavior(&br);
  edr_pmfe_on_preprocess_slot(slot, &br);
  /* P2 T9：Shellcode / Webshell / PMFE → AVE 行为槽（E 组 46–47、53–54） */
  if (edr_windows_event_policy_should_emit(&br)) {
    edr_ave_cross_engine_feed_from_record(&br);
  }
  (void)edr_command_dispatch_recommended_forensics(&br);
  if (!edr_local_evidence_cache_is_candidate(&br)) {
    return;
  }
  if (!edr_preprocess_sampling_allow(&br)) {
    return;
  }
  if (p0_emitted > 0) {
    return;
  }
  emit_behavior_record(&br);
}

static void process_pending_file_reads(int stopping) {
#ifdef _WIN32
  EdrBehaviorRecord ready;
  int result;
  while ((result = edr_file_read_deferred_pop(&s_file_read_deferred, edr_monotonic_ns(),
                                              p0_file_read_evaluation_ready(), stopping, &ready)) != 0) {
    if (result == 1) {
      p0_file_read_deferred_observe(&ready, "released");
      process_ready_record(ready, NULL);
    } else {
      p0_file_read_deferred_observe(&ready, stopping ? "shutdown" : "timeout");
      p0_mark_file_read_collector_evidence(&ready, stopping ? EDR_P0_FILE_READ_REASON_DEFERRED_SHUTDOWN
                                                         : EDR_P0_FILE_READ_REASON_DEFERRED_TIMEOUT);
      (void)p0_process_collector_evidence_gate(&ready);
    }
  }
#else
  (void)stopping;
#endif
}

static void process_pending_process_creates(void) {
#ifdef _WIN32
  EdrBehaviorRecord ready;
  while (edr_process_coalescer_poll(edr_monotonic_ns(), &ready)) {
    /* Deadline represents one candidate generation; this is the sole
     * NOT_EVALUABLE path when Security 4688 never arrives. */
    process_one_record(ready, NULL);
  }
#endif
}

static void poll_p0_source_only_durable_retry(void) {
  EdrBehaviorRecord committed;
  /* Startup may see the queue before the authenticated IR becomes ready; run
   * the idempotent lifecycle recovery on each preprocess turn so it can emit
   * the required loss audit later without reopening a P0 action window. */
  (void)edr_p0_rule_source_only_recover_after_queue_open();
  /* The retry lane is bounded to eight records; draining all immediately
   * avoids a recovered SQLite queue unnecessarily holding FileRead P0 paused.
   * Each attempt still occurs outside collector/A4.4 locks. */
  while (edr_p0_rule_poll_source_only_durable_retry(&committed)) {
#ifdef _WIN32
    if (strcmp(committed.collector_evidence_gate,
               EDR_P0_FILE_READ_METADATA_GATE) == 0) {
      edr_collector_file_read_metadata_gate_delivery_result(committed.event_id, 1);
    }
#endif
  }
#ifdef _WIN32
  /* Staged FileKey-capacity records use the existing event bus and arrive
   * back here for the one SQLite durable write above. */
  edr_collector_file_read_metadata_gate_retry();
#endif
  /* A retry may have just committed the restart-loss audit (or the final
   * retained source assertion). Re-evaluate the latch only after that commit. */
  (void)edr_p0_rule_source_only_recover_after_queue_open();
  process_pending_file_reads(0);
}

static void process_one_slot(const EdrEventSlot *slot) {
  EdrBehaviorRecord br;
#ifdef _WIN32
  /* Expiry is checked before an arriving record can observe a prior slot, so
   * a delayed 4688/PID reuse event can never join an expired generation. */
  process_pending_process_creates();
#endif
  edr_behavior_from_slot(slot, &br);
  if (br.collector_evidence_gate[0]) {
    process_one_record(br, slot);
    return;
  }
#ifdef _WIN32
  if (br.type == EDR_EVENT_PROCESS_CREATE) {
    EdrBehaviorRecord ready;
    if (!br.is_security_4688) {
      /* Revision one identifies the initial kernel observation, including
       * partial evidence. A later 4688 join increments it independently. */
      if (br.evidence_revision == 0u) br.evidence_revision = 1u;
      (void)p0_bind_process_generation(&br);
      /* Capture the target token while the newly-created process is most
       * likely still alive.  Waiting for the bounded 4688 correlation window
       * made short-lived processes lose user identity even when their target
       * generation was valid.  The later enrichment call is idempotent. */
      if (br.process_start_key != 0u &&
          br.process_creation_filetime_100ns != 0u) {
        (void)enrich_process_token_identity(&br);
      }
      /* Publish the exact lifecycle generation before a coalesced 4688 wait.
       * A child can arrive after A exits and PID B begins; keeping A's
       * StartKey/FILETIME interval now prevents later parent enrichment from
       * replacing that historical parent with B. */
      if (edr_process_create_is_lifecycle_authoritative(&br) && br.pid != 0u &&
          br.process_start_key != 0u && br.process_creation_filetime_100ns != 0u) {
        (void)edr_pt_cache_put_generation(
            br.pid, br.ppid, br.process_name, br.cmdline, br.exe_path, br.parent_name,
            (uint64_t)(br.event_time_ns > 0 ? br.event_time_ns : 0), br.process_start_key,
            br.process_creation_filetime_100ns);
      }
    }
    int candidate = p0_process_create_candidate(&br);
    /* Start bounded evidence work before waiting for an out-of-order 4688. */
    if (candidate && !br.is_security_4688) {
      EdrProcessEvidence ignored;
      (void)edr_process_evidence_request(br.image_path_canonical[0] ? br.image_path_canonical : br.exe_path,
                                         br.process_start_key,
                                         edr_monotonic_ns(), &ignored);
    }
    switch (edr_process_coalescer_submit(&br, candidate, edr_monotonic_ns(), &ready)) {
      case EDR_PROCESS_COALESCE_HOLD: return;
      case EDR_PROCESS_COALESCE_READY: process_one_record(ready, slot); return;
      default: break;
    }
  } else if (br.type == EDR_EVENT_FILE_READ) {
    /* File reads are tied to the actor only after a live StartKey/creation
     * tuple agrees with an available ETW StartKey, or the event timestamp
     * proves that the queried live PID generation already existed. */
    (void)p0_bind_process_generation(&br);
  }
#endif
  process_one_record(br, slot);
}

#ifdef _WIN32
static DWORD WINAPI preprocess_main(void *arg) {
#else
static void *preprocess_main(void *arg) {
#endif
  (void)arg;
  for (;;) {
    edr_health_beat(EDR_HEALTH_PREPROCESS);
    EdrEventSlot slot;
    if (edr_event_bus_try_pop(s_bus, &slot)) {
      process_one_slot(&slot);
      process_pending_process_creates();
      poll_p0_source_only_durable_retry();
      edr_event_batch_poll_timeout();
      edr_storage_queue_poll_drain();
      edr_local_evidence_cache_poll_maintenance();
      edr_correlation_poll_maintenance(0); /* 内部节流；同预处理线程，满足契约 */
      poll_summary_flush();
      continue;
    }
    edr_event_batch_poll_timeout();
    process_pending_process_creates();
    poll_p0_source_only_durable_retry();
    edr_storage_queue_poll_drain();
    edr_local_evidence_cache_poll_maintenance();
    edr_correlation_poll_maintenance(0); /* 空闲期兜底排空注入 + 定期清扫 */
    poll_summary_flush();
#ifdef _WIN32
    if (s_stop_preprocess) {
      while (edr_event_bus_try_pop(s_bus, &slot)) {
        process_one_slot(&slot);
      }
      process_pending_file_reads(1);
      poll_p0_source_only_durable_retry();
      edr_storage_queue_poll_drain();
      edr_local_evidence_cache_poll_maintenance();
      break;
    }
    (void)edr_event_bus_wait(s_bus, 25u);
#else
    if (s_stop_preprocess) {
      while (edr_event_bus_try_pop(s_bus, &slot)) {
        process_one_slot(&slot);
      }
      poll_p0_source_only_durable_retry();
      edr_storage_queue_poll_drain();
      edr_local_evidence_cache_poll_maintenance();
      break;
    }
    (void)edr_event_bus_wait(s_bus, 10u);
#endif
  }
#ifdef _WIN32
  return 0;
#else
  return NULL;
#endif
}

EdrError edr_preprocess_start(EdrEventBus *bus, const EdrConfig *cfg) {
  EdrConfig defaults;
  if (!bus) {
    return EDR_ERR_INVALID_ARG;
  }
  if (s_preprocess_active) {
    return EDR_OK;
  }
  if (!cfg) {
    edr_config_apply_defaults(&defaults);
    cfg = &defaults;
  }
  {
    size_t max_bytes = (size_t)cfg->upload.batch_max_size_mb * 1024u * 1024u;
    if (max_bytes == 0) {
      max_bytes = EDR_EVENT_BATCH_CAP;
    }
    EdrError be = edr_event_batch_init(max_bytes, cfg->upload.batch_max_events,
                                       cfg->upload.batch_timeout_s);
    if (be != EDR_OK) {
      return be;
    }
  }
  edr_dedup_configure(cfg->preprocessing.dedup_window_s,
                      cfg->preprocessing.high_freq_threshold);
  edr_emit_rules_configure(cfg);
  sync_sampling_from_cfg(cfg);
  log_p0_runtime_state();
  edr_dedup_init();
  edr_pt_cache_init();
  (void)edr_pt_cache_warmup();
  edr_process_coalescer_reset();
  if (!edr_process_evidence_worker_start()) {
    edr_pt_cache_shutdown();
    edr_event_batch_shutdown();
    return EDR_ERR_INTERNAL;
  }
  sync_agent_ids_from_cfg(cfg);
  s_bus = bus;
#ifdef _WIN32
  memset(&s_file_read_deferred, 0, sizeof(s_file_read_deferred));
  s_stop_preprocess = 0;
  s_thread = CreateThread(NULL, 0, preprocess_main, NULL, 0, NULL);
  if (!s_thread) {
    s_bus = NULL;
    edr_process_evidence_worker_stop();
    edr_event_batch_shutdown();
    return EDR_ERR_INTERNAL;
  }
#else
  s_stop_preprocess = 0;
  if (pthread_create(&s_thread, NULL, preprocess_main, NULL) != 0) {
    s_bus = NULL;
    edr_process_evidence_worker_stop();
    edr_event_batch_shutdown();
    return EDR_ERR_INTERNAL;
  }
#endif
  s_preprocess_active = 1;
  return EDR_OK;
}

void edr_preprocess_apply_config(const EdrConfig *cfg) {
  if (!s_preprocess_active || !cfg) {
    return;
  }
  edr_dedup_configure(cfg->preprocessing.dedup_window_s, cfg->preprocessing.high_freq_threshold);
  edr_emit_rules_configure(cfg);
  sync_sampling_from_cfg(cfg);
  sync_agent_ids_from_cfg(cfg);
}

void edr_preprocess_copy_agent_ids(char *endpoint_id, size_t endpoint_cap, char *tenant_id, size_t tenant_cap) {
  if (endpoint_id && endpoint_cap > 0) {
    snprintf(endpoint_id, endpoint_cap, "%s", s_cfg_endpoint_id);
  }
  if (tenant_id && tenant_cap > 0) {
    snprintf(tenant_id, tenant_cap, "%s", s_cfg_tenant_id);
  }
}

void edr_preprocess_stop(void) {
  if (!s_preprocess_active) {
    return;
  }
#ifdef _WIN32
  InterlockedExchange(&s_stop_preprocess, 1);
  edr_event_bus_wake(s_bus);
  if (s_thread) {
    WaitForSingleObject(s_thread, 60000);
    CloseHandle(s_thread);
    s_thread = NULL;
  }
#else
  s_stop_preprocess = 1;
  edr_event_bus_wake(s_bus);
  pthread_join(s_thread, NULL);
#endif
  s_bus = NULL;
  edr_process_evidence_worker_stop();
  edr_process_coalescer_reset();
  s_preprocess_active = 0;
  edr_pt_cache_shutdown();
  edr_event_batch_shutdown();
  edr_emit_rules_configure(NULL);
  edr_dedup_reset();
}
