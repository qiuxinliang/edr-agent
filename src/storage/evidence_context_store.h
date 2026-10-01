#ifndef EDR_EVIDENCE_CONTEXT_STORE_H
#define EDR_EVIDENCE_CONTEXT_STORE_H

#include <sqlite3.h>
#include <stdint.h>

/* Private SQLite owner for context format compatibility. Version 0 is the
 * shipped string-key layout; 1 is resumable migration; 2 is compact. */
typedef struct {
  sqlite3 *db;
  int format;
  char error[192];
} EdrContextStore;

typedef struct {
  EdrContextStore *store;
  sqlite3_stmt *candidate_find, *candidate_insert;
  sqlite3_stmt *fact_find, *fact_number;
  sqlite3_stmt *ref_insert, *old_delete;
  sqlite3_stmt *lookup;
} EdrContextWriter;

/* Read-only guard, called before normal startup can change schema or pragmas. */
int edr_context_store_check_format(EdrContextStore *store, sqlite3 *db);
int edr_context_store_open(EdrContextStore *store, sqlite3 *db);
int edr_context_store_begin_upgrade(EdrContextStore *store);
/* Caller owns a stopped Agent/exclusive connection. Each batch commits all
 * moves atomically, and never deletes a fact or a candidate for capacity. */
int edr_context_store_migrate_batch(EdrContextStore *store, unsigned limit,
                                    unsigned *moved, int *complete);
sqlite3_stmt *edr_context_store_prepare_lookup(EdrContextStore *store);
int edr_context_store_bind_lookup(EdrContextStore *store, sqlite3_stmt *stmt,
                                  const char *artifact_id);
int edr_context_writer_open(EdrContextStore *store, EdrContextWriter *writer);
int edr_context_writer_put(EdrContextWriter *writer, const char *artifact_id,
                           const char *candidate_id, const char *fact_id,
                           const char *candidate_json, sqlite3_int64 created_ns, int created_null,
                           const char *upload_status, const char *minio_key);
void edr_context_writer_close(EdrContextWriter *writer);
int edr_context_store_collect_facts(EdrContextStore *store, unsigned *removed);
int edr_context_store_expire(EdrContextStore *store, sqlite3_int64 cutoff,
                             unsigned *removed);
/* Atomically remove a bounded reference batch and only its now-unreferenced
 * facts/dictionary entries. Counts describe committed rows, excluding keys. */
int edr_context_store_evict(EdrContextStore *store, int orphans_only,
                            unsigned limit, unsigned *removed, unsigned *facts_removed);

#endif
