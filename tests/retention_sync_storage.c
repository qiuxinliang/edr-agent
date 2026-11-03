/* This translation unit belongs only to the explicit attribution test target.
 * Define real delegates before the macros; include the unchanged production
 * owner after them. No WAL/commit hook or SQLite return value is replaced. */
#ifndef EDR_RETENTION_SYNC_ATTRIBUTION
#error "retention_sync_storage.c is test-only"
#endif
#include "retention_sync_probe.h"

static int retention_sync_exec(sqlite3 *db, const char *sql,
    int (*callback)(void *,int,char **,char **), void *arg, char **error,
    const char *function, unsigned line) {
  int reclaim=retention_reclaim_exec_begin(sql);
  int token=retention_sync_probe_enter(RS_API_EXEC,function,line,sql,-1);
  int result=sqlite3_exec(db,sql,callback,arg,error);
  retention_sync_probe_leave(token,result);
  retention_reclaim_exec_end(reclaim,result);
  return result;
}
static int retention_sync_step(sqlite3_stmt *statement, const char *function, unsigned line) {
  int token=retention_sync_probe_enter(RS_API_STEP,function,line,
      retention_sync_probe_active() ? sqlite3_sql(statement) : NULL,-1);
  int result=sqlite3_step(statement);
  retention_sync_probe_leave(token,result);
  retention_reclaim_step(statement,function,result);
  return result;
}
static sqlite3_int64 retention_sync_column_int64(sqlite3_stmt *statement,int column,const char *function) {
  sqlite3_int64 result=sqlite3_column_int64(statement,column);
  retention_reclaim_column(statement,function,column,result);
  return result;
}
static int retention_sync_checkpoint(sqlite3 *db, const char *name, int mode,
    int *log, int *checkpointed, const char *function, unsigned line) {
  int reclaim=retention_reclaim_checkpoint_begin(function);
  int token=retention_sync_probe_enter(RS_API_CHECKPOINT,function,line,NULL,mode);
  int result=sqlite3_wal_checkpoint_v2(db,name,mode,log,checkpointed);
  retention_sync_probe_leave(token,result);
  retention_reclaim_checkpoint_end(reclaim,result);
  return result;
}
#define sqlite3_exec(db,sql,callback,arg,error) \
  retention_sync_exec(db,sql,callback,arg,error,__func__,__LINE__)
#define sqlite3_step(statement) retention_sync_step(statement,__func__,__LINE__)
#define sqlite3_column_int64(statement,column) retention_sync_column_int64(statement,column,__func__)
#define sqlite3_wal_checkpoint_v2(db,name,mode,log,checkpointed) \
  retention_sync_checkpoint(db,name,mode,log,checkpointed,__func__,__LINE__)
#include "../src/storage/local_evidence_cache.c"

/* Called only by the single-threaded fixture. This copies existing owner
 * memory; it never calls get_status, SQL, filesystem helpers, or locks. */
void retention_sync_storage_snapshot(RetentionReclaimMemory *out) {
  out->admitted=s_status.candidate_admitted;out->rejected=s_status.candidate_rejected;
  out->retired=s_status.retention_groups_retired;out->held=s_status.retention_groups_held;
  out->maintenance=s_status.maintenance_runs;out->failures=s_status.retention_failures;
  out->db_bytes=s_status.db_bytes;out->wal_bytes=s_status.wal_bytes;
  out->pending=s_maintenance_reclaim_pages;out->pressure=(unsigned)s_maintenance_pressure_pending;
  out->state=s_maintenance_work_state;out->drain=(unsigned)s_retirement_drain_pending;
  out->physical_available=s_status.physical_accounting_available;
}
