#ifndef EDR_FILE_KEY_LIFETIME_H
#define EDR_FILE_KEY_LIFETIME_H

#include <stdint.h>

/* FileKey names outlive individual FileObjects. Only NameDelete ends the
 * name interval; equal boundary timestamps cannot prove event ordering. */
static inline int edr_file_key_lifetime_contains(uint64_t named_at,
                                                uint64_t deleted_at,
                                                uint64_t event_at) {
  return named_at != 0u && event_at >= named_at &&
         (deleted_at == 0u || event_at < deleted_at);
}

/* Bound late decode history, not the lifetime of a still-open name. */
static inline int edr_file_key_lifetime_expired(uint64_t deleted_at,
                                               uint64_t event_at,
                                               uint64_t retention_ns) {
  return deleted_at != 0u && event_at > deleted_at &&
         event_at - deleted_at > retention_ns;
}

#endif
