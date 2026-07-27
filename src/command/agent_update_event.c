#include "edr/agent_update_event.h"

#include "cJSON.h"
#include "edr/ingest_http.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <direct.h>
#include <io.h>
#include <windows.h>
#define EDR_PATH_SEP '\\'
#else
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#define EDR_PATH_SEP '/'
#endif

typedef struct PendingEvent {
  uint64_t seq;
  char path[1024];
} PendingEvent;

static int safe_component(const char *value, char *out, size_t cap) {
  size_t used = 0;
  if (!value || !value[0] || !out || cap < 2u) return 0;
  for (const unsigned char *p = (const unsigned char *)value; *p; ++p) {
    if (used + 1u >= cap) return 0;
    out[used++] = (isalnum(*p) || *p == '.' || *p == '_' || *p == '-') ? (char)*p : '_';
  }
  out[used] = '\0';
  return used > 0u;
}

static int make_dir(const char *path) {
#ifdef _WIN32
  if (CreateDirectoryA(path, NULL) || GetLastError() == ERROR_ALREADY_EXISTS) return 0;
#else
  if (mkdir(path, 0700) == 0 || errno == EEXIST) return 0;
#endif
  return -1;
}

static int make_dirs(const char *path) {
  char copy[1024];
  size_t length;
  if (!path || !path[0] || strlen(path) >= sizeof(copy)) return -1;
  snprintf(copy, sizeof(copy), "%s", path);
  length = strlen(copy);
  for (size_t i = 1u; i < length; ++i) {
    if (copy[i] != '/' && copy[i] != '\\') continue;
#ifdef _WIN32
    if (i == 2u && copy[1] == ':') continue;
#endif
    char saved = copy[i];
    copy[i] = '\0';
    if (copy[0] && make_dir(copy) != 0) return -1;
    copy[i] = saved;
  }
  return make_dir(copy);
}

void edr_agent_update_event_default_dir(char *out, size_t cap) {
  if (!out || cap == 0u) return;
#ifdef _WIN32
  char program_data[MAX_PATH];
  DWORD n = GetEnvironmentVariableA("ProgramData", program_data, sizeof(program_data));
  if (!n || n >= sizeof(program_data)) snprintf(program_data, sizeof(program_data), "C:\\ProgramData");
  snprintf(out, cap, "%s\\FDSecurity\\state\\agent-update-events", program_data);
#else
  const char *override = getenv("EDR_AGENT_UPDATE_EVENT_OUTBOX");
  snprintf(out, cap, "%s", override && override[0] ? override : "/tmp/edr_agent_update_events");
#endif
}

static int sync_file(FILE *file) {
  if (fflush(file) != 0) return -1;
#ifdef _WIN32
  return _commit(_fileno(file));
#else
  return fsync(fileno(file));
#endif
}

static int atomic_replace(const char *temporary, const char *path) {
#ifdef _WIN32
  return MoveFileExA(temporary, path, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) ? 0 : -1;
#else
  return rename(temporary, path);
#endif
}

static int write_atomic(const char *path, const char *body) {
  char temporary[1100];
  FILE *file;
  snprintf(temporary, sizeof(temporary), "%s.tmp-%lu", path,
#ifdef _WIN32
           (unsigned long)GetCurrentProcessId()
#else
           (unsigned long)getpid()
#endif
  );
  file = fopen(temporary, "wb");
  if (!file) return -1;
  size_t length = strlen(body);
  int ok = fwrite(body, 1u, length, file) == length && sync_file(file) == 0;
  if (fclose(file) != 0) ok = 0;
  if (!ok || atomic_replace(temporary, path) != 0) {
    remove(temporary);
    return -1;
  }
  return 0;
}

static int valid_context(const EdrAgentUpdateEventContext *context) {
  return context && context->task_id[0] && context->command_id[0] &&
         context->operation[0] && context->artifact_id[0] &&
         context->artifact_sha256[0] && context->target_version[0];
}

int edr_agent_update_event_persist(const char *outbox_dir,
                                   const EdrAgentUpdateEventContext *context,
                                   uint64_t event_seq, const char *status,
                                   int progress, const char *detail_json,
                                   const char *reported_at) {
  char safe_command[160], path[1024];
  cJSON *root = NULL, *detail = NULL;
  char *body = NULL;
  int rc = -1;
  if (!outbox_dir || !outbox_dir[0] || !valid_context(context) || event_seq == 0u ||
      !status || !status[0] || progress < 0 || progress > 100 ||
      !safe_component(context->command_id, safe_command, sizeof(safe_command))) return -1;
  detail = cJSON_Parse(detail_json && detail_json[0] ? detail_json : "{}");
  if (!cJSON_IsObject(detail)) { cJSON_Delete(detail); return -1; }
  root = cJSON_CreateObject();
  if (!root) { cJSON_Delete(detail); return -1; }
  if (!cJSON_GetObjectItemCaseSensitive(detail, "operation") &&
      !cJSON_AddStringToObject(detail, "operation", context->operation)) goto done;
  if (!cJSON_GetObjectItemCaseSensitive(detail, "artifact_id") &&
      !cJSON_AddStringToObject(detail, "artifact_id", context->artifact_id)) goto done;
  if (!cJSON_GetObjectItemCaseSensitive(detail, "sha256") &&
      !cJSON_AddStringToObject(detail, "sha256", context->artifact_sha256)) goto done;
  if (!cJSON_GetObjectItemCaseSensitive(detail, "version") &&
      !cJSON_AddStringToObject(detail, "version", context->target_version)) goto done;
  if (context->campaign_id[0] && !cJSON_GetObjectItemCaseSensitive(detail, "campaign_id") &&
      !cJSON_AddStringToObject(detail, "campaign_id", context->campaign_id)) goto done;
  char event_id[320];
  snprintf(event_id, sizeof(event_id), "%s-%020llu", safe_command,
           (unsigned long long)event_seq);
#define ADD_STRING(name, value) do { if (!cJSON_AddStringToObject(root, name, value)) goto done; } while (0)
  ADD_STRING("task_id", context->task_id);
  ADD_STRING("command_id", context->command_id);
  ADD_STRING("event_id", event_id);
  ADD_STRING("status", status);
  if (!cJSON_AddNumberToObject(root, "event_seq", (double)event_seq) ||
      !cJSON_AddNumberToObject(root, "progress", progress)) goto done;
  if (!cJSON_AddItemToObject(root, "detail", detail)) goto done;
  detail = NULL;
  if (reported_at && reported_at[0]) ADD_STRING("reported_at", reported_at);
#undef ADD_STRING
  body = cJSON_PrintUnformatted(root);
  if (!body || make_dirs(outbox_dir) != 0) goto done;
  snprintf(path, sizeof(path), "%s%c%s-%020llu.pending.json", outbox_dir,
           EDR_PATH_SEP, safe_command, (unsigned long long)event_seq);
  rc = write_atomic(path, body);
done:
  free(body);
  cJSON_Delete(detail);
  cJSON_Delete(root);
  return rc;
}

static int ack_checkpoint_path(const char *dir, char *out, size_t cap) {
  int n = snprintf(out, cap, "%s%cacked.seq", dir, EDR_PATH_SEP);
  return n > 0 && (size_t)n < cap;
}

static uint64_t read_ack_checkpoint(const char *dir) {
  char path[1024], buffer[64];
  if (!ack_checkpoint_path(dir, path, sizeof(path))) return 0u;
  FILE *file = fopen(path, "rb");
  if (!file) return 0u;
  size_t n = fread(buffer, 1u, sizeof(buffer) - 1u, file);
  fclose(file);
  buffer[n] = '\0';
  char *end = NULL;
  unsigned long long value = strtoull(buffer, &end, 10);
  return end && (*end == '\0' || *end == '\r' || *end == '\n') ? (uint64_t)value : 0u;
}

static int write_ack_checkpoint(const char *dir, uint64_t seq) {
  char path[1024], body[64];
  if (!ack_checkpoint_path(dir, path, sizeof(path))) return -1;
  snprintf(body, sizeof(body), "%llu", (unsigned long long)seq);
  return write_atomic(path, body);
}

static int pending_compare(const void *left, const void *right) {
  const PendingEvent *a = (const PendingEvent *)left;
  const PendingEvent *b = (const PendingEvent *)right;
  return a->seq < b->seq ? -1 : a->seq > b->seq ? 1 : strcmp(a->path, b->path);
}

static int add_pending(PendingEvent **events, size_t *count, size_t *capacity,
                       const char *dir, const char *name) {
  const char *suffix = ".pending.json";
  size_t n = strlen(name), suffix_len = strlen(suffix);
  if (n <= suffix_len || strcmp(name + n - suffix_len, suffix) != 0) return 0;
  const char *dash = name + n - suffix_len;
  while (dash > name && dash[-1] != '-') --dash;
  if (dash == name || strlen(dash) != 20u + suffix_len) return 0;
  char *end = NULL;
  unsigned long long parsed = strtoull(dash, &end, 10);
  if (!end || strcmp(end, suffix) != 0 || parsed == 0u) return 0;
  if (*count == *capacity) {
    size_t next = *capacity ? *capacity * 2u : 8u;
    PendingEvent *grown = (PendingEvent *)realloc(*events, next * sizeof(**events));
    if (!grown) return -1;
    *events = grown; *capacity = next;
  }
  PendingEvent *event = &(*events)[(*count)++];
  event->seq = (uint64_t)parsed;
  snprintf(event->path, sizeof(event->path), "%s%c%s", dir, EDR_PATH_SEP, name);
  return 0;
}

static int collect_pending(const char *dir, PendingEvent **events, size_t *count) {
  size_t capacity = 0u;
  *events = NULL; *count = 0u;
#ifdef _WIN32
  char pattern[1024];
  WIN32_FIND_DATAA data;
  snprintf(pattern, sizeof(pattern), "%s\\*.pending.json", dir);
  HANDLE find = FindFirstFileA(pattern, &data);
  if (find == INVALID_HANDLE_VALUE) return GetLastError() == ERROR_FILE_NOT_FOUND ? 0 : -1;
  do {
    if (!(data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
        add_pending(events, count, &capacity, dir, data.cFileName) != 0) {
      FindClose(find); free(*events); *events = NULL; return -1;
    }
  } while (FindNextFileA(find, &data));
  FindClose(find);
#else
  DIR *directory = opendir(dir);
  if (!directory) return errno == ENOENT ? 0 : -1;
  struct dirent *entry;
  while ((entry = readdir(directory)) != NULL) {
    if (add_pending(events, count, &capacity, dir, entry->d_name) != 0) {
      closedir(directory); free(*events); *events = NULL; return -1;
    }
  }
  closedir(directory);
#endif
  qsort(*events, *count, sizeof(**events), pending_compare);
  return 0;
}

static char *read_event(const char *path) {
  FILE *file = fopen(path, "rb");
  if (!file) return NULL;
  if (fseek(file, 0, SEEK_END) != 0) { fclose(file); return NULL; }
  long length = ftell(file);
  if (length <= 0 || length > 1024L * 1024L || fseek(file, 0, SEEK_SET) != 0) {
    fclose(file); return NULL;
  }
  char *body = (char *)malloc((size_t)length + 1u);
  if (!body || fread(body, 1u, (size_t)length, file) != (size_t)length) {
    free(body); fclose(file); return NULL;
  }
  body[length] = '\0';
  fclose(file);
  return body;
}

static int response_accepted(const char *response) {
  cJSON *root = cJSON_Parse(response ? response : "");
  const cJSON *accepted = cJSON_IsObject(root) ? cJSON_GetObjectItemCaseSensitive(root, "accepted") : NULL;
  if (!cJSON_IsBool(accepted) && cJSON_IsObject(root)) {
    const cJSON *data = cJSON_GetObjectItemCaseSensitive(root, "data");
    if (cJSON_IsObject(data)) accepted = cJSON_GetObjectItemCaseSensitive(data, "accepted");
  }
  int ok = cJSON_IsTrue(accepted);
  cJSON_Delete(root);
  return ok;
}

int edr_agent_update_event_flush(const char *outbox_dir,
                                 EdrAgentUpdateEventPostFn post_fn, void *user,
                                 uint64_t *last_acked_seq) {
  PendingEvent *events = NULL;
  size_t count = 0u;
  int flushed = 0;
  if (!outbox_dir || !post_fn || collect_pending(outbox_dir, &events, &count) != 0) return -1;
  uint64_t checkpoint = read_ack_checkpoint(outbox_dir);
  if (last_acked_seq) *last_acked_seq = checkpoint;
  for (size_t i = 0; i < count; ++i) {
    if (events[i].seq <= checkpoint) {
      if (remove(events[i].path) != 0) { free(events); return -1; }
      flushed++;
      continue;
    }
    char response[4096];
    char *body = read_event(events[i].path);
    response[0] = '\0';
    if (!body || post_fn(body, response, sizeof(response), user) != 0 ||
        !response_accepted(response)) {
      free(body); free(events); return flushed;
    }
    free(body);
    if (write_ack_checkpoint(outbox_dir, events[i].seq) != 0) { free(events); return -1; }
    if (remove(events[i].path) != 0) { free(events); return -1; }
    checkpoint = events[i].seq;
    if (last_acked_seq) *last_acked_seq = checkpoint;
    flushed++;
  }
  free(events);
  return flushed;
}

static int ingest_post(const char *body_json, char *response, size_t response_cap, void *user) {
  (void)user;
  return edr_ingest_http_post_json_suffix("ingest/agent-upgrade-event", body_json,
                                          response, response_cap);
}

int edr_agent_update_event_flush_ingest(const char *outbox_dir,
                                        uint64_t *last_acked_seq) {
  return edr_agent_update_event_flush(outbox_dir, ingest_post, NULL, last_acked_seq);
}
