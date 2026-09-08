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
typedef struct {
  uint64_t object;
  uint64_t opened_at;
  uint64_t closed_at;
  char path[EDR_FILE_OBJECT_PATH_CAP];
} EdrFileObjectBinding;

typedef struct {
  size_t next;
  uint64_t discarded_through;
} EdrFileObjectHistory;

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
  /* Losing a lifetime boundary must never resurrect an older path. Metadata
   * at or before this watermark cannot establish a new trusted binding. */
  if (discarded > history->discarded_through) history->discarded_through = discarded;
  return slot;
}

static inline void edr_file_object_binding_open(EdrFileObjectBinding *entries,
    size_t count, EdrFileObjectHistory *history, uint64_t object, uint64_t at, const char *path) {
  EdrFileObjectBinding *slot = NULL;
  uint64_t end = 0u;
  if (!object || !at || at <= history->discarded_through) return;
  for (size_t i = 0; i < count; ++i) {
    EdrFileObjectBinding *entry = &entries[i];
    if (entry->object != object) continue;
    if (entry->opened_at == at) {
      /* Conflicting same-time deliveries remain quarantined, including after
       * another duplicate of the original name. */
      if (!path || strcmp(entry->path, path) != 0) entry->path[0] = '\0';
      return;
    }
    if (entry->opened_at) {
      entry->closed_at = edr_file_key_lifetime_end(entry->opened_at, entry->closed_at, at);
      end = edr_file_key_lifetime_end(at, end, entry->opened_at);
    } else if (entry->closed_at >= at && (!end || entry->closed_at < end)) {
      end = entry->closed_at;
    }
  }
  slot = edr_file_object_binding_slot(entries, count, history);
  if (!slot) return;
  memset(slot, 0, sizeof(*slot));
  if (at <= history->discarded_through) return;
  slot->object = object;
  slot->opened_at = at;
  slot->closed_at = end;
  if (path && strlen(path) < sizeof(slot->path)) memcpy(slot->path, path, strlen(path) + 1u);
}

static inline void edr_file_object_binding_close(EdrFileObjectBinding *entries,
    size_t count, EdrFileObjectHistory *history, uint64_t object, uint64_t at) {
  EdrFileObjectBinding *latest = NULL;
  if (!object || !at || at <= history->discarded_through) return;
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

static inline const char *edr_file_object_binding_resolve(
    const EdrFileObjectBinding *entries, size_t count, const EdrFileObjectHistory *history,
    uint64_t object, uint64_t at) {
  const EdrFileObjectBinding *latest = NULL;
  if (!object || !at || at <= history->discarded_through) return NULL;
  for (size_t i = 0; i < count; ++i) {
    const EdrFileObjectBinding *entry = &entries[i];
    if (entry->object != object || !entry->opened_at || entry->opened_at > at) continue;
    if (!latest || entry->opened_at > latest->opened_at) latest = entry;
  }
  return latest && latest->opened_at > history->discarded_through && latest->path[0] &&
      edr_file_key_lifetime_contains(latest->opened_at, latest->closed_at, at)
      ? latest->path : NULL;
}
#endif
