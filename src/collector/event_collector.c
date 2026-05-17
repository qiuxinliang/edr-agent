#include "edr/event_collector.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAX_COLLECTORS 8
#define EVENT_QUEUE_SIZE 4096

static EventCollector *g_collectors[MAX_COLLECTORS];
static int g_collector_count = 0;
static ProcessEvent g_event_queue[EVENT_QUEUE_SIZE];
static int g_queue_head = 0;
static int g_queue_tail = 0;
static CRITICAL_SECTION g_queue_lock;
static HANDLE g_queue_event = NULL;

static void event_queue_push(const ProcessEvent *event) {
  EnterCriticalSection(&g_queue_lock);
  memcpy(&g_event_queue[g_queue_head], event, sizeof(ProcessEvent));
  g_queue_head = (g_queue_head + 1) % EVENT_QUEUE_SIZE;
  LeaveCriticalSection(&g_queue_lock);
  SetEvent(g_queue_event);
}

static int event_queue_pop(ProcessEvent *event, int timeout_ms) {
  DWORD wait_result = WaitForSingleObject(g_queue_event, timeout_ms);
  if (wait_result != WAIT_OBJECT_0) {
    return -1;
  }
  
  EnterCriticalSection(&g_queue_lock);
  if (g_queue_head == g_queue_tail) {
    LeaveCriticalSection(&g_queue_lock);
    ResetEvent(g_queue_event);
    return -1;
  }
  memcpy(event, &g_event_queue[g_queue_tail], sizeof(ProcessEvent));
  g_queue_tail = (g_queue_tail + 1) % EVENT_QUEUE_SIZE;
  if (g_queue_head == g_queue_tail) {
    ResetEvent(g_queue_event);
  }
  LeaveCriticalSection(&g_queue_lock);
  return 0;
}

static DWORD WINAPI collector_thread(LPVOID param) {
  EventCollector *collector = (EventCollector *)param;
  ProcessEvent event;
  
  while (1) {
    if (collector->get_event(collector, &event, 100) == 0) {
      event_queue_push(&event);
    }
  }
  return 0;
}

static int snapshot_collector_init(EventCollector *collector);
static int snapshot_collector_start(EventCollector *collector);
static int snapshot_collector_stop(EventCollector *collector);
static int snapshot_collector_get_event(EventCollector *collector, ProcessEvent *event, int timeout_ms);
static void snapshot_collector_cleanup(EventCollector *collector);

static EventCollector g_snapshot_collector = {
  .source_type = EVENT_SOURCE_SNAPSHOT,
  .name = "snapshot",
  .init = snapshot_collector_init,
  .start = snapshot_collector_start,
  .stop = snapshot_collector_stop,
  .get_event = snapshot_collector_get_event,
  .cleanup = snapshot_collector_cleanup,
  .private_data = NULL
};

typedef struct {
  HANDLE thread;
  int running;
  uint64_t last_snapshot;
} SnapshotCollectorData;

static int snapshot_collector_init(EventCollector *collector) {
  SnapshotCollectorData *data = (SnapshotCollectorData *)malloc(sizeof(SnapshotCollectorData));
  if (!data) return -1;
  data->thread = NULL;
  data->running = 0;
  data->last_snapshot = 0;
  collector->private_data = data;
  return 0;
}

static int snapshot_collector_start(EventCollector *collector) {
  SnapshotCollectorData *data = (SnapshotCollectorData *)collector->private_data;
  data->running = 1;
  data->thread = CreateThread(NULL, 0, collector_thread, collector, 0, NULL);
  return data->thread ? 0 : -1;
}

static int snapshot_collector_stop(EventCollector *collector) {
  SnapshotCollectorData *data = (SnapshotCollectorData *)collector->private_data;
  data->running = 0;
  if (data->thread) {
    WaitForSingleObject(data->thread, INFINITE);
    CloseHandle(data->thread);
    data->thread = NULL;
  }
  return 0;
}

static int snapshot_collector_get_event(EventCollector *collector, ProcessEvent *event, int timeout_ms) {
  SnapshotCollectorData *data = (SnapshotCollectorData *)collector->private_data;
  (void)timeout_ms;
  
  uint64_t now = GetTickCount64() * 10000;
  if (now - data->last_snapshot < 3000000000ULL) {
    return -1;
  }
  data->last_snapshot = now;
  
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snap == INVALID_HANDLE_VALUE) return -1;
  
  PROCESSENTRY32W pe;
  pe.dwSize = sizeof(pe);
  if (!Process32FirstW(snap, &pe)) {
    CloseHandle(snap);
    return -1;
  }
  
  memset(event, 0, sizeof(ProcessEvent));
  event->type = EVENT_TYPE_PROCESS_CREATE;
  event->source = EVENT_SOURCE_SNAPSHOT;
  event->timestamp = now;
  event->pid = pe.th32ProcessID;
  event->ppid = pe.th32ParentProcessID;
  
  WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, event->process_name, sizeof(event->process_name), NULL, NULL);
  
  if (event->pid != 0) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, event->pid);
    if (hProcess) {
      WCHAR path[MAX_PATH];
      DWORD size = MAX_PATH;
      if (QueryFullProcessImageNameW(hProcess, 0, path, &size)) {
        WideCharToMultiByte(CP_UTF8, 0, path, -1, event->exe_path, sizeof(event->exe_path), NULL, NULL);
      }
      CloseHandle(hProcess);
    }
  }
  
  CloseHandle(snap);
  return 0;
}

static void snapshot_collector_cleanup(EventCollector *collector) {
  SnapshotCollectorData *data = (SnapshotCollectorData *)collector->private_data;
  if (data) {
    free(data);
    collector->private_data = NULL;
  }
}

int edr_event_collector_init(EventSourceType sources) {
  InitializeCriticalSection(&g_queue_lock);
  g_queue_event = CreateEvent(NULL, TRUE, FALSE, NULL);
  g_collector_count = 0;
  
  if (sources & EVENT_SOURCE_SNAPSHOT) {
    if (g_snapshot_collector.init(&g_snapshot_collector) == 0) {
      g_collectors[g_collector_count++] = &g_snapshot_collector;
    }
  }
  
  return g_collector_count > 0 ? 0 : -1;
}

int edr_event_collector_start(void) {
  for (int i = 0; i < g_collector_count; i++) {
    if (g_collectors[i]->start(g_collectors[i]) != 0) {
      return -1;
    }
  }
  return 0;
}

int edr_event_collector_stop(void) {
  for (int i = 0; i < g_collector_count; i++) {
    g_collectors[i]->stop(g_collectors[i]);
  }
  return 0;
}

int edr_event_collector_get(ProcessEvent *event, int timeout_ms) {
  return event_queue_pop(event, timeout_ms);
}

void edr_event_collector_cleanup(void) {
  for (int i = 0; i < g_collector_count; i++) {
    g_collectors[i]->cleanup(g_collectors[i]);
  }
  CloseHandle(g_queue_event);
  DeleteCriticalSection(&g_queue_lock);
}

int edr_event_collector_get_source(ProcessEvent *event, EventSourceType *out_source) {
  if (!event || !out_source) return -1;
  *out_source = event->source;
  return 0;
}