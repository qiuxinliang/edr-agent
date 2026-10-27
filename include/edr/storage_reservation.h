#ifndef EDR_STORAGE_RESERVATION_H
#define EDR_STORAGE_RESERVATION_H
#include <stdint.h>
/* Derived balance on the existing protected command lock file. The JSONL
 * owner remains authoritative; startup reconstructs before optional writers.
 * A mapped lock-free load adds no stat, lock, scan or write to admission. */
uint64_t edr_storage_artifact_reserved(void);
/* Owner-only: caller holds the command file lock. offset 0 remains its lock. */
int edr_storage_reservation_attach(int fd, const char *owner_path);
void edr_storage_reservation_publish(uint64_t bytes);
/* Explicit installer/read-only process only: no map/file changes. Refuses an
 * already attached runtime owner, so it cannot replace a live shared balance. */
int edr_storage_reservation_readonly_snapshot(uint64_t bytes);
#endif
