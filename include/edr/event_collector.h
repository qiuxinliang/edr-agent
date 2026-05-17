#ifndef EDR_EVENT_COLLECTOR_H
#define EDR_EVENT_COLLECTOR_H

#include <stdint.h>

#if defined(_WIN32)
#include <windows.h>
#endif

typedef enum {
  EVENT_SOURCE_ETW = 1,
  EVENT_SOURCE_WMI = 2,
  EVENT_SOURCE_SNAPSHOT = 4,
  EVENT_SOURCE_ALL = 0xFF
} EventSourceType;

typedef enum {
  EVENT_TYPE_PROCESS_CREATE,
  EVENT_TYPE_PROCESS_TERMINATE,
  EVENT_TYPE_THREAD_CREATE,
  EVENT_TYPE_THREAD_TERMINATE,
  EVENT_TYPE_FILE_CREATE,
  EVENT_TYPE_FILE_DELETE,
  EVENT_TYPE_FILE_READ,
  EVENT_TYPE_FILE_WRITE,
  EVENT_TYPE_REGISTRY_CREATE,
  EVENT_TYPE_REGISTRY_DELETE,
  EVENT_TYPE_REGISTRY_SET_VALUE,
  EVENT_TYPE_NETWORK_CONNECT,
  EVENT_TYPE_UNKNOWN
} EventType;

typedef struct {
  EventType type;
  EventSourceType source;
  uint64_t timestamp;
  uint32_t pid;
  uint32_t ppid;
  uint32_t tid;
  char process_name[256];
  char exe_path[512];
  char cmdline[1024];
  char parent_name[256];
  char user[64];
  char file_path[512];
  char registry_path[512];
  char network_ip[46];
  uint16_t network_port;
} ProcessEvent;

typedef struct EventCollector EventCollector;

struct EventCollector {
  EventSourceType source_type;
  const char *name;
  int (*init)(EventCollector *collector);
  int (*start)(EventCollector *collector);
  int (*stop)(EventCollector *collector);
  int (*get_event)(EventCollector *collector, ProcessEvent *event, int timeout_ms);
  void (*cleanup)(EventCollector *collector);
  void *private_data;
};

int edr_event_collector_init(EventSourceType sources);
int edr_event_collector_start(void);
int edr_event_collector_stop(void);
int edr_event_collector_get(ProcessEvent *event, int timeout_ms);
void edr_event_collector_cleanup(void);

int edr_event_collector_get_source(ProcessEvent *event, EventSourceType *out_source);

#endif