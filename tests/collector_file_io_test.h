#ifndef EDR_COLLECTOR_FILE_IO_TEST_H
#define EDR_COLLECTOR_FILE_IO_TEST_H

#ifndef EDR_COLLECTOR_FILE_IO_TESTING
#error Test-only collector entry points
#endif

#include <windows.h>
#include <evntcons.h>
#include "edr/event_bus.h"
#include "edr/collector.h"

void edr_collector_file_io_test_reset(EdrEventBus *bus);
uint64_t edr_collector_file_io_test_new_epoch(void);
void edr_collector_file_io_test_feed(EVENT_RECORD *record, uint64_t event_ns);
int edr_collector_file_io_test_pending(EdrEventSlot *slot);
void edr_collector_file_io_test_health(EdrCollectorHealth *health);
/* Test-owned injection at the real binding append boundary. */
void edr_collector_file_io_test_before_binding(EdrEventSlot *slot);

#endif
