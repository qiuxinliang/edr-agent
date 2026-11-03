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
  int token=retention_sync_probe_enter(RS_API_EXEC,function,line,sql,-1);
  int result=sqlite3_exec(db,sql,callback,arg,error);
  retention_sync_probe_leave(token,result);
  return result;
}
static int retention_sync_step(sqlite3_stmt *statement, const char *function, unsigned line) {
  int token=retention_sync_probe_enter(RS_API_STEP,function,line,
      retention_sync_probe_active() ? sqlite3_sql(statement) : NULL,-1);
  int result=sqlite3_step(statement);
  retention_sync_probe_leave(token,result);
  return result;
}
static int retention_sync_checkpoint(sqlite3 *db, const char *name, int mode,
    int *log, int *checkpointed, const char *function, unsigned line) {
  int token=retention_sync_probe_enter(RS_API_CHECKPOINT,function,line,NULL,mode);
  int result=sqlite3_wal_checkpoint_v2(db,name,mode,log,checkpointed);
  retention_sync_probe_leave(token,result);
  return result;
}
#define sqlite3_exec(db,sql,callback,arg,error) \
  retention_sync_exec(db,sql,callback,arg,error,__func__,__LINE__)
#define sqlite3_step(statement) retention_sync_step(statement,__func__,__LINE__)
#define sqlite3_wal_checkpoint_v2(db,name,mode,log,checkpointed) \
  retention_sync_checkpoint(db,name,mode,log,checkpointed,__func__,__LINE__)
#include "../src/storage/local_evidence_cache.c"
