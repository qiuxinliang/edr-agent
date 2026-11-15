/* Bounded in-memory observer. No output until preflight has returned. */
#include "static_sql.h"
static const char *diag_phase="entry", *diag_last_sql=NULL;
static sqlite3 *diag_main_db=NULL, *diag_memory_db=NULL;
static int diag_busy_ms=-1, diag_progress_ops=-1, diag_open_flags=0;
static struct {
  const char *kind, *phase, *api, *db_kind;
  int rc, extended, primary, truncated;
  char sql[1025];
} diag_first;

static const char *diag_safe_sql(const char *sql) {
  if (!sql) return NULL;
  for (size_t i=0;i<sizeof(diag_static_sql)/sizeof(diag_static_sql[0]);++i)
    if (!strcmp(sql,diag_static_sql[i])) return diag_static_sql[i];
  if (!strncmp(sql,"PRAGMA table_info(",18)) return "PRAGMA table_info(<schema identifier>);";
  if (!strncmp(sql,"SELECT COALESCE(SUM(128",23)) return "SELECT COALESCE(SUM(128 + <per-column byte inventory>),0) FROM <schema identifier>;";
  return "<non-static SQL omitted>";
}
static void diag_capture(const char *kind,const char *api,int rc,sqlite3 *db,const char *sql) {
  if (diag_first.kind) return;
  diag_first.kind=kind; diag_first.api=api; diag_first.phase=diag_phase; diag_first.rc=rc;
  diag_first.extended=db ? sqlite3_extended_errcode(db) : -1;
  diag_first.primary=diag_first.extended<0 ? -1 : (diag_first.extended&255);
  diag_first.db_kind=db==diag_main_db && db ? "main_readonly" : db==diag_memory_db && db ? "private_memory" : "unavailable";
  const char *safe=diag_safe_sql(sql ? sql : diag_last_sql);
  if (safe) {
    diag_first.truncated=strlen(safe)>=sizeof(diag_first.sql);
    snprintf(diag_first.sql,sizeof(diag_first.sql),"%s",safe);
  }
}
#define DIAG_MARK(phase) (diag_phase=(phase))
static void diag_complete(int rc,sqlite3 *db) {
  if (rc) diag_capture(rc==1 ? "capacity_rejection" : "logical_rejection","preflight",rc,db,NULL);
}
static int diag_open_v2(const char *path,sqlite3 **db,int flags,const char *vfs) {
  int rc=sqlite3_open_v2(path,db,flags,vfs);
  diag_open_flags=flags; diag_main_db=*db;
  if (rc!=SQLITE_OK) diag_capture("sqlite_api_error","sqlite3_open_v2",rc,*db,NULL);
  return rc;
}
static int diag_open(const char *path,sqlite3 **db) {
  int rc=sqlite3_open(path,db);
  diag_memory_db=*db;
  if (rc!=SQLITE_OK) diag_capture("sqlite_api_error","sqlite3_open",rc,*db,NULL);
  return rc;
}
static int diag_prepare(sqlite3 *db,const char *sql,int n,sqlite3_stmt **st,const char **tail) {
  diag_last_sql=diag_safe_sql(sql);
  int rc=sqlite3_prepare_v2(db,sql,n,st,tail);
  if (rc!=SQLITE_OK) diag_capture("sqlite_api_error","sqlite3_prepare_v2",rc,db,sql);
  return rc;
}
static int diag_step(sqlite3_stmt *st) {
  const char *sql=sqlite3_sql(st);
  diag_last_sql=diag_safe_sql(sql);
  int rc=sqlite3_step(st);
  if (rc!=SQLITE_ROW && rc!=SQLITE_DONE && rc!=SQLITE_OK)
    diag_capture("sqlite_api_error","sqlite3_step",rc,sqlite3_db_handle(st),sql);
  return rc;
}
static int diag_exec(sqlite3 *db,const char *sql,int (*callback)(void *,int,char **,char **),void *arg,char **error) {
  diag_last_sql=diag_safe_sql(sql);
  int rc=sqlite3_exec(db,sql,callback,arg,error);
  if (rc!=SQLITE_OK) diag_capture("sqlite_api_error","sqlite3_exec",rc,db,sql);
  return rc;
}
static int diag_busy(sqlite3 *db,int ms) {
  diag_busy_ms=ms;
  return sqlite3_busy_timeout(db,ms);
}
static void diag_progress(sqlite3 *db,int n,int (*callback)(void *),void *arg) {
  diag_progress_ops=n;
  sqlite3_progress_handler(db,n,callback,arg);
}
static void diag_json_string(const char *s) {
  if (!s) {fputs("null",stdout);return;}
  putchar('"');
  for (;*s;++s) {
    unsigned char c=(unsigned char)*s;
    if (c=='"' || c=='\\') {putchar('\\');putchar(c);}
    else if (c<32 || c>=127) printf("\\u%04x",c);
    else putchar(c);
  }
  putchar('"');
}
static void diag_print(int rc,uint64_t elapsed) {
  printf("{\"result\":%d,\"elapsed_ms\":%llu,\"sqlite_version\":",rc,(unsigned long long)elapsed);
  diag_json_string(sqlite3_libversion());
  printf(",\"readonly_open_flags\":%d,\"busy_timeout_ms\":%d,\"progress_ops\":%d,\"first_failure\":",diag_open_flags,diag_busy_ms,diag_progress_ops);
  if (!diag_first.kind) fputs("null",stdout);
  else {
    fputs("{\"kind\":",stdout);diag_json_string(diag_first.kind);
    fputs(",\"phase\":",stdout);diag_json_string(diag_first.phase);
    fputs(",\"api\":",stdout);diag_json_string(diag_first.api);
    fputs(",\"database\":",stdout);diag_json_string(diag_first.db_kind);
    printf(",\"return_code\":%d,\"sqlite_primary_code\":%d,\"sqlite_extended_code\":%d,\"static_sql\":",diag_first.rc,diag_first.primary,diag_first.extended);
    diag_json_string(diag_first.sql[0] ? diag_first.sql : NULL);
    printf(",\"sql_truncated\":%s}",diag_first.truncated ? "true" : "false");
  }
  fputs("}\n",stdout);
}
#define sqlite3_open_v2 diag_open_v2
#define sqlite3_open diag_open
#define sqlite3_prepare_v2 diag_prepare
#define sqlite3_step diag_step
#define sqlite3_exec diag_exec
#define sqlite3_busy_timeout diag_busy
#define sqlite3_progress_handler diag_progress
