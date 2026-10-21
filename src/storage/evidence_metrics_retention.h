#ifndef EDR_EVIDENCE_METRICS_RETENTION_H
#define EDR_EVIDENCE_METRICS_RETENTION_H

#include <sqlite3.h>

/* Ordinary minute counters only. Zero holds durable summaries/the clock;
 * malformed or unknown legacy timestamps/values remain protected. */
#define EDR_METRICS_EXPIRY_CONDITION \
  "typeof(minute_unix)='integer' AND minute_unix>0 AND typeof(value)='integer'"
#define EDR_METRICS_EXPIRY_BYTES \
  "COALESCE(length(CAST(endpoint_id AS BLOB)),0)+COALESCE(length(CAST(metric_name AS BLOB)),0)"

/* Shared by the readonly installer preflight and the cache owner. The owner
 * must recheck under BEGIN IMMEDIATE before deletion. Never bootstrap an
 * unknown trigger/FK owner or an already initialized clock. Returns 0/1 or
 * a negative SQLite error; existence is not a promise of enough free pages. */
static int evidence_metrics_bootstrap_eligible(sqlite3 *db, sqlite3_int64 cutoff) {
  sqlite3_stmt *st=NULL;
  int rc=sqlite3_prepare_v2(db,
    "SELECT NOT EXISTS(SELECT 1 FROM metrics WHERE minute_unix=0 AND endpoint_id='' "
    "AND metric_name='local_retention_v1_active_ms') "
    "AND NOT EXISTS(SELECT 1 FROM sqlite_master WHERE type='trigger' AND tbl_name='metrics' COLLATE NOCASE) "
    "AND NOT EXISTS(SELECT 1 FROM sqlite_master AS s,pragma_foreign_key_list(s.name) AS f "
    "WHERE s.type='table' AND f.\"table\"='metrics' COLLATE NOCASE) "
    "AND EXISTS(SELECT 1 FROM metrics WHERE minute_unix<?1 AND " EDR_METRICS_EXPIRY_CONDITION ");",
    -1,&st,NULL);
  if (rc==SQLITE_OK) rc=sqlite3_bind_int64(st,1,cutoff);
  if (rc==SQLITE_OK) rc=sqlite3_step(st);
  int result=rc==SQLITE_ROW ? (sqlite3_column_int(st,0)!=0) : -rc;
  sqlite3_finalize(st);
  return result;
}
#endif
