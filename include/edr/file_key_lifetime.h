#ifndef EDR_FILE_KEY_LIFETIME_H
#define EDR_FILE_KEY_LIFETIME_H

#include <stdint.h>

/* Select the newest name before checking whether it has ended. Otherwise
 * a closed newer generation could resurrect an older, unclosed path when a
 * NameDelete was missed for that older generation. */
static inline int edr_file_key_lifetime_is_newer(uint64_t named_at,
                                                uint64_t event_at,
                                                uint64_t selected_at) {
  return named_at != 0u && named_at <= event_at && named_at > selected_at;
}

/* A newer NameCreate also bounds an older binding when its NameDelete was
 * missed. Keep the earliest observed upper bound, including out-of-order
 * delivery, so expiry of newer history cannot resurrect an older path. */
static inline uint64_t edr_file_key_lifetime_end(uint64_t named_at,
                                                uint64_t ended_at,
                                                uint64_t next_name_at) {
  if (next_name_at <= named_at) return ended_at;
  return ended_at == 0u || next_name_at < ended_at ? next_name_at : ended_at;
}

/* FileKey names outlive individual FileObjects. NameDelete or a newer name
 * ends the interval; equal boundary timestamps cannot prove event ordering. */
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
