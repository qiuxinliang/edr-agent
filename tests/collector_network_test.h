#ifndef EDR_COLLECTOR_NETWORK_TEST_H
#define EDR_COLLECTOR_NETWORK_TEST_H
#ifndef EDR_COLLECTOR_NETWORK_TESTING
#error Test-only collector entry points
#endif
#include <windows.h>
#include <evntcons.h>
#include "edr/collector.h"
#include "edr/behavior_record.h"
#include "edr/event_bus.h"
#include "edr/process_generation.h"
#include "edr/sensor_interest.h"
void edr_collector_network_test_reset(EdrEventBus *bus);
void edr_collector_network_test_feed(EVENT_RECORD *record, uint64_t event_ns);
void edr_collector_network_test_health(EdrCollectorHealth *out);
int edr_collector_network_test_bind_actor(EdrBehaviorRecord *record);
void edr_collector_network_test_self_identity(const EdrLiveProcessGeneration *identity);
int edr_collector_network_test_self_record(const EdrBehaviorRecord *record);
int edr_collector_network_test_self_interest(const EdrSensorInterestEvent *event);
HANDLE WINAPI edr_network_test_open_process(DWORD access, BOOL inherit, DWORD pid);
BOOL WINAPI edr_network_test_close_handle(HANDLE process);
DWORD WINAPI edr_network_test_wait_process(HANDLE process, DWORD milliseconds);
BOOL WINAPI edr_network_test_process_times(HANDLE process, LPFILETIME created,
                                          LPFILETIME exited, LPFILETIME kernel, LPFILETIME user);
int edr_network_test_query_generation(void *process, EdrLiveProcessGeneration *out,
                                       char *reason, size_t cap);
int edr_network_test_image_path(void *process, char *out, size_t cap);
BOOL WINAPI edr_network_test_write_file(HANDLE file, LPCVOID data, DWORD size,
                                        LPDWORD written, LPOVERLAPPED overlapped);
#endif
