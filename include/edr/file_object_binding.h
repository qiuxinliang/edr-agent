#ifndef EDR_FILE_OBJECT_BINDING_H
#define EDR_FILE_OBJECT_BINDING_H

#include "edr/file_key_lifetime.h"
#include <stddef.h>
#include <string.h>

/* A closed FileKey name is not authority over a newer, independently proven
 * FileObject lifetime. Conflicting live names must still fail closed. */
static inline const char *edr_file_mutation_binding_select(
    const char *key_path, const char *object_path, int key_rejected,
    int key_expired, int *conflict) {
  if (conflict) *conflict = 0;
  if (key_path && object_path) {
    const unsigned char *a = (const unsigned char *)key_path;
    const unsigned char *b = (const unsigned char *)object_path;
    while (*a && *b) {
      unsigned char ac = (*a >= 'A' && *a <= 'Z') ? (unsigned char)(*a + 32) : *a;
      unsigned char bc = (*b >= 'A' && *b <= 'Z') ? (unsigned char)(*b + 32) : *b;
      if (ac != bc) break;
      ++a; ++b;
    }
    if (*a || *b) {
      if (conflict) *conflict = 1;
      return NULL;
    }
  }
  if (key_path) return key_path;
  return (!key_rejected || key_expired) ? object_path : NULL;
}

/* Matches the maximum intact path admitted by EdrSensorInterestEvent. */
#define EDR_FILE_OBJECT_PATH_CAP 1024u
typedef enum {
  EDR_FILE_OBJECT_MISSING = 0,
  EDR_FILE_OBJECT_RESOLVED,
  EDR_FILE_OBJECT_CLOSED,
  EDR_FILE_OBJECT_PATH_UNAVAILABLE,
  EDR_FILE_OBJECT_CONFLICT,
  EDR_FILE_OBJECT_HISTORY_DISCARDED,
  EDR_FILE_OBJECT_UNKNOWN_BOUNDARY
} EdrFileObjectResolutionStatus;

typedef struct {
  uint64_t object;
  uint64_t opened_at;
  uint64_t closed_at;
  EdrFileObjectResolutionStatus status;
  char path[EDR_FILE_OBJECT_PATH_CAP];
} EdrFileObjectBinding;

typedef struct {
  size_t next;
  uint64_t discarded_through;
  uint64_t last_evicted_object;
  uint64_t last_evicted_at;
  uint64_t evictions;
} EdrFileObjectHistory;

typedef struct {
  EdrFileObjectResolutionStatus status;
  uint64_t opened_at;
  uint64_t closed_at;
} EdrFileObjectResolution;

static inline const char *edr_file_object_resolution_name(EdrFileObjectResolutionStatus status) {
  switch (status) {
    case EDR_FILE_OBJECT_RESOLVED: return "resolved";
    case EDR_FILE_OBJECT_CLOSED: return "lifetime_ended";
    case EDR_FILE_OBJECT_PATH_UNAVAILABLE: return "path_unavailable";
    case EDR_FILE_OBJECT_CONFLICT: return "same_time_conflict";
    case EDR_FILE_OBJECT_HISTORY_DISCARDED: return "object_history_discarded";
    case EDR_FILE_OBJECT_UNKNOWN_BOUNDARY: return "unidentified_boundary";
    default: return "no_retained_lifetime";
  }
}

/* Preserve the boundaries, but revoke only paths whose identity may have
 * been affected. object=0 denotes a genuinely unidentified provider boundary. */
static inline void edr_file_object_binding_quarantine(EdrFileObjectBinding *entries,
    size_t count, uint64_t object, uint64_t through, EdrFileObjectResolutionStatus status) {
  for (size_t i = 0; i < count; ++i) {
    EdrFileObjectBinding *entry = &entries[i];
    if ((!object || entry->object == object) && entry->opened_at && entry->opened_at <= through) {
      entry->path[0] = '\0';
      entry->status = status;
    }
  }
}

static inline void edr_file_object_binding_unknown_boundary(EdrFileObjectBinding *entries,
    size_t count, EdrFileObjectHistory *history, uint64_t at) {
  edr_file_object_binding_quarantine(entries, count, 0, at, EDR_FILE_OBJECT_UNKNOWN_BOUNDARY);
  if (at > history->discarded_through) history->discarded_through = at;
}

/* Caller serializes access and clears this session-local history on restart.
 * The object namespace is distinct from FileKey; never cast one into the other. */
static inline EdrFileObjectBinding *edr_file_object_binding_slot(
    EdrFileObjectBinding *entries, size_t count, EdrFileObjectHistory *history) {
  for (size_t i = 0; i < count; ++i) {
    if (!entries[i].object) return &entries[i];
  }
  if (!count) return NULL;
  EdrFileObjectBinding *slot = &entries[history->next++ % count];
  uint64_t discarded = slot->closed_at > slot->opened_at ? slot->closed_at : slot->opened_at;
  /* Admission watermark prevents a discarded Close/reuse from being undone
   * by a delayed Create. Existing paths are revoked only for this object:
   * a known A eviction is not evidence against an intact B lifetime. */
  edr_file_object_binding_quarantine(entries, count, slot->object, discarded,
                                    EDR_FILE_OBJECT_HISTORY_DISCARDED);
  history->last_evicted_object = slot->object;
  history->last_evicted_at = discarded;
  history->evictions++;
  if (discarded > history->discarded_through) history->discarded_through = discarded;
  return slot;
}

static inline void edr_file_object_binding_open(EdrFileObjectBinding *entries,
    size_t count, EdrFileObjectHistory *history, uint64_t object, uint64_t at, const char *path) {
  EdrFileObjectBinding *slot = NULL;
  uint64_t end = 0u;
  if (!object || !at) return;
  if (at <= history->discarded_through) {
    for (size_t i = 0; i < count; ++i) {
      EdrFileObjectBinding *entry = &entries[i];
      if (entry->object == object && entry->opened_at == at) {
        if (entry->status == EDR_FILE_OBJECT_RESOLVED &&
            (!path || strcmp(entry->path, path) != 0)) {
          entry->path[0] = '\0';
          entry->status = EDR_FILE_OBJECT_CONFLICT;
        }
        return;
      }
    }
    /* Ignoring a late same-object Create would leave its older resident
     * lifetime usable after this newly observed reuse. */
    edr_file_object_binding_quarantine(entries, count, object, at,
                                      EDR_FILE_OBJECT_HISTORY_DISCARDED);
    return;
  }
  for (size_t i = 0; i < count; ++i) {
    EdrFileObjectBinding *entry = &entries[i];
    if (entry->object != object) continue;
    if (entry->opened_at == at) {
      /* Conflicting same-time deliveries remain quarantined, including after
       * another duplicate of the original name. */
      if (entry->status == EDR_FILE_OBJECT_RESOLVED &&
          (!path || strcmp(entry->path, path) != 0)) {
        entry->path[0] = '\0';
        entry->status = EDR_FILE_OBJECT_CONFLICT;
      }
      return;
    }
  }
  /* Reserve before bounding older lifetimes with this Create. Otherwise an
   * evicted old entry would carry the current at as a synthetic Close and
   * the admission floor would reject the very Create that established it. */
  slot = edr_file_object_binding_slot(entries, count, history);
  if (!slot) return;
  if (at <= history->discarded_through) {
    edr_file_object_binding_quarantine(entries, count, object, at,
                                      EDR_FILE_OBJECT_HISTORY_DISCARDED);
    memset(slot, 0, sizeof(*slot));
    return;
  }
  for (size_t i = 0; i < count; ++i) {
    EdrFileObjectBinding *entry = &entries[i];
    if (entry->object != object) continue;
    if (entry->opened_at) {
      entry->closed_at = edr_file_key_lifetime_end(entry->opened_at, entry->closed_at, at);
      end = edr_file_key_lifetime_end(at, end, entry->opened_at);
    } else if (entry->closed_at >= at && (!end || entry->closed_at < end)) {
      end = entry->closed_at;
    }
  }
  memset(slot, 0, sizeof(*slot));
  slot->object = object;
  slot->opened_at = at;
  slot->closed_at = end;
  slot->status = EDR_FILE_OBJECT_PATH_UNAVAILABLE;
  if (path && path[0] && strlen(path) < sizeof(slot->path)) {
    memcpy(slot->path, path, strlen(path) + 1u);
    slot->status = EDR_FILE_OBJECT_RESOLVED;
  }
}

static inline void edr_file_object_binding_close(EdrFileObjectBinding *entries,
    size_t count, EdrFileObjectHistory *history, uint64_t object, uint64_t at) {
  EdrFileObjectBinding *latest = NULL;
  if (!object || !at) return;
  if (at <= history->discarded_through) {
    edr_file_object_binding_quarantine(entries, count, object, at,
                                      EDR_FILE_OBJECT_HISTORY_DISCARDED);
    return;
  }
  for (size_t i = 0; i < count; ++i) {
    EdrFileObjectBinding *entry = &entries[i];
    if (entry->object != object || entry->opened_at > at) continue;
    if (!entry->opened_at && entry->closed_at == at) return;
    if (!latest || entry->opened_at > latest->opened_at) latest = entry;
  }
  if (latest && latest->opened_at) {
    if (!latest->closed_at || at < latest->closed_at) latest->closed_at = at;
  }
  /* Keep the closing event even when an older generation exists: a newer
   * Create can arrive after this Close and still needs the upper bound. */
  latest = edr_file_object_binding_slot(entries, count, history);
  if (!latest) return;
  memset(latest, 0, sizeof(*latest));
  if (at <= history->discarded_through) return;
  latest->object = object;
  latest->closed_at = at;
}

static inline const char *edr_file_object_binding_resolve_detail(
    const EdrFileObjectBinding *entries, size_t count, const EdrFileObjectHistory *history,
    uint64_t object, uint64_t at, EdrFileObjectResolution *detail) {
  const EdrFileObjectBinding *latest = NULL;
  (void)history; /* Admission floor is not a global invalidation of residents. */
  if (detail) memset(detail, 0, sizeof(*detail));
  if (!object || !at) return NULL;
  for (size_t i = 0; i < count; ++i) {
    const EdrFileObjectBinding *entry = &entries[i];
    if (entry->object != object || !entry->opened_at || entry->opened_at > at) continue;
    if (!latest || entry->opened_at > latest->opened_at) latest = entry;
  }
  if (!latest) return NULL;
  EdrFileObjectResolutionStatus status = latest->status;
  if (status == EDR_FILE_OBJECT_RESOLVED &&
      !edr_file_key_lifetime_contains(latest->opened_at, latest->closed_at, at))
    status = EDR_FILE_OBJECT_CLOSED;
  if (detail) {
    detail->status = status;
    detail->opened_at = latest->opened_at;
    detail->closed_at = latest->closed_at;
  }
  return status == EDR_FILE_OBJECT_RESOLVED && latest->path[0] ? latest->path : NULL;
}

static inline const char *edr_file_object_binding_resolve(
    const EdrFileObjectBinding *entries, size_t count, const EdrFileObjectHistory *history,
    uint64_t object, uint64_t at) {
  return edr_file_object_binding_resolve_detail(entries, count, history, object, at, NULL);
}
#endif
