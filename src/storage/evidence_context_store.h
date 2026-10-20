#ifndef EDR_EVIDENCE_CONTEXT_STORE_H
#define EDR_EVIDENCE_CONTEXT_STORE_H

#include <sqlite3.h>
#include <stdint.h>

/* Private SQLite owner for context format compatibility. Version 0 is the
 * shipped string-key layout; 1 is resumable migration; 2 is compact. */
typedef struct {
  sqlite3 *db;
  int format;
  int sqlite_error_code; /* Original SQLite failure; rollback does not overwrite it. */
  char error[192];
} EdrContextStore;

typedef struct {
  EdrContextStore *store;
  sqlite3_stmt *candidate_find, *candidate_insert;
  sqlite3_stmt *fact_find, *fact_number;
  sqlite3_stmt *ref_insert, *old_delete;
  sqlite3_stmt *lookup;
  sqlite3_stmt *legacy_insert;
  int migrate_existing;
} EdrContextWriter;

/* Read-only guard, called before normal startup can change schema or pragmas. */
int edr_context_store_check_format(EdrContextStore *store, sqlite3 *db);
int edr_context_store_open(EdrContextStore *store, sqlite3 *db);
int edr_context_store_begin_upgrade(EdrContextStore *store);
/* Installed by the cache owner after its additive retention metadata exists.
 * Durable SQL guards keep older maintenance from independently breaking groups. */
int edr_context_store_install_retention_guards(EdrContextStore *store);
/* Current schema owners avoid rebuilding an identical named trigger/view. Missing
 * or changed definitions are replaced inside a nested-safe private savepoint. */
int edr_context_store_ensure_schema_object(EdrContextStore *store, const char *kind,
                                      const char *name,
                                      const char *create_sql);
/* Caller owns a stopped Agent/exclusive connection. Each batch commits all
 * moves atomically, and never deletes a fact or a candidate for capacity. */
int edr_context_store_migrate_batch(EdrContextStore *store, unsigned limit,
                                    unsigned *moved, int *complete);
sqlite3_stmt *edr_context_store_prepare_lookup(EdrContextStore *store);
int edr_context_store_bind_lookup(EdrContextStore *store, sqlite3_stmt *stmt,
                                  const char *artifact_id);
/* Normal writes keep an existing legacy identity in place. Only the explicit
 * migration owner may replace it with a compact reference in its transaction. */
int edr_context_writer_open(EdrContextStore *store, EdrContextWriter *writer,
                            int migrate_existing);
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

typedef struct {
  unsigned candidates, references, artifacts, facts;
  unsigned work_rows; /* Includes examined dictionaries and shared facts. */
  /* Conservative literal field bytes examined for this group, including
   * shared facts. This bounds work; it is not reclaimed or physical bytes. */
  uint64_t payload_bytes;
} EdrContextRetirement;

/* Caller owns BEGIN IMMEDIATE and has checked investigation/action/window
 * protection. Only a policy-1 retirement_eligible candidate can be removed.
 * Returns 0 for a complete group, 1 for protected/over-budget, -1 on error.
 * A private savepoint rolls back this helper on either unsuccessful result;
 * the caller still owns commit/rollback. Counts become durable only on commit.
 * Result 1 reports examined work (saturating the exceeded limit), but no
 * deleted rows. The caller must charge that work to its maintenance slice.
 * max_rows is 1..4096, including dictionaries and conservatively shared facts.
 * SQLite may materialize one oversized row before its size is known; these
 * work limits therefore bound group traversal, not physical I/O or memory. */
int edr_context_store_retire_candidate(EdrContextStore *store,
                                       const char *candidate_id,
                                       unsigned max_rows, uint64_t max_bytes,
                                       int (*yield_required)(void *), void *yield_context,
                                       EdrContextRetirement *out);

#endif
