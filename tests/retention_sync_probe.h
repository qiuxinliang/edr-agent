#ifndef EDR_TEST_RETENTION_SYNC_PROBE_H
#define EDR_TEST_RETENTION_SYNC_PROBE_H

/* Fixed-memory, single-threaded attribution for the two synthetic pressure
 * rounds only. No SQL, paths, or bound values are retained or printed. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sqlite3.h>

enum { RS_ENTRY_OTHER, RS_ENTRY_INITIAL, RS_ENTRY_POLL, RS_ENTRY_RETRY, RS_ENTRIES };
enum { RS_API_ENTRY, RS_API_EXEC, RS_API_STEP, RS_API_CHECKPOINT };
enum { RS_FILE_UNKNOWN, RS_FILE_MAIN, RS_FILE_WAL, RS_FILE_JOURNAL, RS_FILE_TEMP, RS_FILES };
enum { RS_SQL_NONE, RS_SQL_SELECT, RS_SQL_INSERT, RS_SQL_UPDATE, RS_SQL_DELETE,
       RS_SQL_BEGIN, RS_SQL_COMMIT, RS_SQL_ROLLBACK, RS_SQL_SAVEPOINT,
       RS_SQL_RELEASE, RS_SQL_PRAGMA, RS_SQL_OTHER };
enum { RS_ERROR_OVERFLOW=1, RS_ERROR_STACK=2, RS_ERROR_BUCKETS=4,
       RS_ERROR_UNKNOWN=8, RS_ERROR_RECONCILE=16, RS_ERROR_PHASE=32 };

int retention_sync_probe_active(void);
int retention_sync_probe_enter(unsigned api, const char *function, unsigned line,
                               const char *sql, int checkpoint_mode);
void retention_sync_probe_leave(int token, int sqlite_result);

#ifdef RETENTION_SYNC_PROBE_IMPLEMENTATION
#define RS_BUCKET_LIMIT 256u
#define RS_STACK_LIMIT 16u
typedef struct {
  unsigned round, entry, api, sql, line;
  const char *function;
  int mode, parent;
  uint64_t calls, failures, rows, done, ok;
  int first_failure, last_failure;
  uint64_t syncs[RS_FILES], ticks[RS_FILES], sync_failures[RS_FILES];
  uint64_t writes[RS_FILES], write_failures[RS_FILES];
  uint64_t previous_checkpoint_intervals, previous_checkpoint_zero_writes;
  uint64_t previous_checkpoint_write_bytes;
  uint64_t zero_between_syncs;
} RetentionSyncBucket;
typedef struct { unsigned bucket; int zero_between; } RetentionSyncFrame;
typedef struct {
  uint64_t entries[RS_ENTRIES], syncs, ticks, writes;
  uint64_t raw_syncs, raw_ticks, raw_writes;
  uint64_t maintenance, retired, held;
  unsigned completed;
} RetentionSyncRound;
static struct {
  int enabled, active, last_checkpoint_known;
  unsigned round, entry, depth, count, errors;
  uint64_t all_writes, last_checkpoint_end_writes;
  uint64_t start_syncs, start_ticks, start_writes;
  RetentionSyncFrame stack[RS_STACK_LIMIT];
  RetentionSyncBucket buckets[RS_BUCKET_LIMIT];
  RetentionSyncRound rounds[2];
} retention_sync_probe;

static void rs_add(uint64_t *value, uint64_t delta) {
  if (UINT64_MAX-*value<delta) retention_sync_probe.errors|=RS_ERROR_OVERFLOW;
  else *value+=delta;
}
static unsigned rs_sql_class(const char *sql) {
  char word[12]; unsigned n=0;
  if (!sql) return RS_SQL_NONE;
  while (*sql==' ' || *sql=='\t' || *sql=='\r' || *sql=='\n') ++sql;
  while ((*sql>='a' && *sql<='z') || (*sql>='A' && *sql<='Z')) {
    if (n+1u>=sizeof(word)) return RS_SQL_OTHER;
    word[n++]=(*sql>='a' && *sql<='z') ? (char)(*sql-'a'+'A') : *sql;
    ++sql;
  }
  word[n]='\0';
  static const char *const words[]={"", "SELECT", "INSERT", "UPDATE", "DELETE",
      "BEGIN", "COMMIT", "ROLLBACK", "SAVEPOINT", "RELEASE", "PRAGMA"};
  for (unsigned i=1;i<sizeof(words)/sizeof(words[0]);++i)
    if (!strcmp(word,words[i])) return i;
  return RS_SQL_OTHER;
}
static int rs_bucket(unsigned api, const char *function, unsigned line,
                     unsigned sql, int mode, int parent) {
  for (unsigned i=0;i<retention_sync_probe.count;++i) {
    RetentionSyncBucket *b=&retention_sync_probe.buckets[i];
    if (b->round==retention_sync_probe.round && b->entry==retention_sync_probe.entry &&
        b->api==api && b->sql==sql && b->line==line && b->mode==mode &&
        b->parent==parent && !strcmp(b->function,function)) return (int)i;
  }
  if (retention_sync_probe.count==RS_BUCKET_LIMIT) {
    retention_sync_probe.errors|=RS_ERROR_BUCKETS; return -1;
  }
  unsigned index=retention_sync_probe.count++;
  RetentionSyncBucket *b=&retention_sync_probe.buckets[index];
  b->round=retention_sync_probe.round; b->entry=retention_sync_probe.entry;
  b->api=api; b->sql=sql; b->line=line; b->mode=mode; b->parent=parent;
  b->function=function;
  return (int)index;
}
int retention_sync_probe_active(void) { return retention_sync_probe.active; }
int retention_sync_probe_enter(unsigned api, const char *function, unsigned line,
                               const char *sql, int checkpoint_mode) {
  if (!retention_sync_probe.active) return 0;
  if (retention_sync_probe.depth==RS_STACK_LIMIT) {
    retention_sync_probe.errors|=RS_ERROR_STACK; return -1;
  }
  int parent=retention_sync_probe.depth ?
      (int)retention_sync_probe.stack[retention_sync_probe.depth-1u].bucket : -1;
  int index=rs_bucket(api,function,line,rs_sql_class(sql),checkpoint_mode,parent);
  if (index<0) return -1;
  RetentionSyncBucket *b=&retention_sync_probe.buckets[index];
  int zero_between=0;
  rs_add(&b->calls,1);
  if (api==RS_API_CHECKPOINT && retention_sync_probe.last_checkpoint_known) {
    uint64_t bytes=retention_sync_probe.all_writes-retention_sync_probe.last_checkpoint_end_writes;
    rs_add(&b->previous_checkpoint_intervals,1);
    rs_add(&b->previous_checkpoint_write_bytes,bytes);
    if (!bytes) { rs_add(&b->previous_checkpoint_zero_writes,1); zero_between=1; }
  }
  retention_sync_probe.stack[retention_sync_probe.depth].bucket=(unsigned)index;
  retention_sync_probe.stack[retention_sync_probe.depth++].zero_between=zero_between;
  return (int)retention_sync_probe.depth;
}
void retention_sync_probe_leave(int token, int result) {
  if (!token || token<0) return;
  if (!retention_sync_probe.active || (unsigned)token!=retention_sync_probe.depth) {
    retention_sync_probe.errors|=RS_ERROR_STACK; return;
  }
  RetentionSyncBucket *b=&retention_sync_probe.buckets[
      retention_sync_probe.stack[--retention_sync_probe.depth].bucket];
  if (result==SQLITE_OK) rs_add(&b->ok,1);
  else if (b->api==RS_API_STEP && result==SQLITE_ROW) rs_add(&b->rows,1);
  else if (b->api==RS_API_STEP && result==SQLITE_DONE) rs_add(&b->done,1);
  else {
    if (!b->failures) b->first_failure=result;
    rs_add(&b->failures,1); b->last_failure=result;
  }
  if (b->api==RS_API_CHECKPOINT) {
    retention_sync_probe.last_checkpoint_end_writes=retention_sync_probe.all_writes;
    retention_sync_probe.last_checkpoint_known=1;
  }
}
static RetentionSyncBucket *rs_current(void) {
  int index=retention_sync_probe.depth ?
      (int)retention_sync_probe.stack[retention_sync_probe.depth-1u].bucket :
      rs_bucket(RS_API_ENTRY,"fixture",0,RS_SQL_NONE,-1,-1);
  return index<0 ? NULL : &retention_sync_probe.buckets[index];
}
static void rs_write(unsigned kind, uint64_t bytes, int result) {
  if (!retention_sync_probe.enabled) return;
  rs_add(&retention_sync_probe.all_writes,bytes);
  if (!retention_sync_probe.active) return;
  if (kind>=RS_FILES) kind=RS_FILE_UNKNOWN;
  RetentionSyncBucket *b=rs_current();
  rs_add(&retention_sync_probe.rounds[retention_sync_probe.round].writes,bytes);
  if (b) {
    rs_add(&b->writes[kind],bytes);
    if (result!=SQLITE_OK) rs_add(&b->write_failures[kind],1);
  }
}
static void rs_sync(unsigned kind, uint64_t ticks, int result) {
  if (!retention_sync_probe.active) return;
  if (kind>=RS_FILES) kind=RS_FILE_UNKNOWN;
  if (kind==RS_FILE_UNKNOWN || !retention_sync_probe.depth)
    retention_sync_probe.errors|=RS_ERROR_UNKNOWN;
  RetentionSyncBucket *b=rs_current();
  RetentionSyncRound *r=&retention_sync_probe.rounds[retention_sync_probe.round];
  rs_add(&r->syncs,1); rs_add(&r->ticks,ticks);
  if (b) {
    rs_add(&b->syncs[kind],1); rs_add(&b->ticks[kind],ticks);
    if (result!=SQLITE_OK) rs_add(&b->sync_failures[kind],1);
    if (b->api==RS_API_CHECKPOINT && retention_sync_probe.depth &&
        retention_sync_probe.stack[retention_sync_probe.depth-1u].zero_between)
      rs_add(&b->zero_between_syncs,1);
  }
}
static void rs_reset(void) {
  memset(&retention_sync_probe,0,sizeof(retention_sync_probe));
  retention_sync_probe.enabled=1;
}
static void rs_round_begin(unsigned round, uint64_t syncs, uint64_t ticks, uint64_t writes) {
  if (round>=2 || retention_sync_probe.active || retention_sync_probe.depth ||
      retention_sync_probe.rounds[round].completed) {
    retention_sync_probe.errors|=RS_ERROR_PHASE; return;
  }
  retention_sync_probe.active=1; retention_sync_probe.round=round;
  retention_sync_probe.entry=RS_ENTRY_OTHER;
  /* Raw fixture checkpoints outside this measured phase are not wrapped.
   * Do not claim an interval across that deliberately unobserved boundary. */
  retention_sync_probe.last_checkpoint_known=0;
  retention_sync_probe.start_syncs=syncs; retention_sync_probe.start_ticks=ticks;
  retention_sync_probe.start_writes=writes;
}
static void rs_entry_begin(unsigned entry) {
  if (!retention_sync_probe.active) return;
  if (entry>=RS_ENTRIES || retention_sync_probe.entry!=RS_ENTRY_OTHER || retention_sync_probe.depth) {
    retention_sync_probe.errors|=RS_ERROR_PHASE; return;
  }
  retention_sync_probe.entry=entry;
  rs_add(&retention_sync_probe.rounds[retention_sync_probe.round].entries[entry],1);
}
static void rs_entry_end(void) {
  if (!retention_sync_probe.active) return;
  if (retention_sync_probe.depth) retention_sync_probe.errors|=RS_ERROR_STACK;
  retention_sync_probe.entry=RS_ENTRY_OTHER;
}
static void rs_round_end(uint64_t syncs, uint64_t ticks, uint64_t writes,
                         uint64_t maintenance, uint64_t retired, uint64_t held) {
  if (!retention_sync_probe.active) { retention_sync_probe.errors|=RS_ERROR_PHASE; return; }
  RetentionSyncRound *r=&retention_sync_probe.rounds[retention_sync_probe.round];
  if (retention_sync_probe.depth || retention_sync_probe.entry!=RS_ENTRY_OTHER)
    retention_sync_probe.errors|=RS_ERROR_STACK;
  if (syncs<retention_sync_probe.start_syncs || ticks<retention_sync_probe.start_ticks ||
      writes<retention_sync_probe.start_writes) retention_sync_probe.errors|=RS_ERROR_RECONCILE;
  else {
    r->raw_syncs=syncs-retention_sync_probe.start_syncs;
    r->raw_ticks=ticks-retention_sync_probe.start_ticks;
    r->raw_writes=writes-retention_sync_probe.start_writes;
  }
  uint64_t sum_syncs=0,sum_ticks=0,sum_writes=0;
  for (unsigned i=0;i<retention_sync_probe.count;++i) {
    const RetentionSyncBucket *b=&retention_sync_probe.buckets[i];
    if (b->round!=retention_sync_probe.round) continue;
    for (unsigned f=0;f<RS_FILES;++f) {
      rs_add(&sum_syncs,b->syncs[f]); rs_add(&sum_ticks,b->ticks[f]); rs_add(&sum_writes,b->writes[f]);
    }
  }
  if (sum_syncs!=r->syncs || sum_syncs!=r->raw_syncs || sum_ticks!=r->ticks ||
      sum_ticks!=r->raw_ticks || sum_writes!=r->writes || sum_writes!=r->raw_writes)
    retention_sync_probe.errors|=RS_ERROR_RECONCILE;
  r->maintenance=maintenance; r->retired=retired; r->held=held; r->completed=1;
  retention_sync_probe.active=0;
}
static int rs_report(uint64_t hz) {
  static const char *const entries[]={"other","initial_record","poll","retry_record"};
  static const char *const apis[]={"unwrapped","exec","step","checkpoint"};
  static const char *const sqls[]={"none","select_prefix","insert_prefix","update_prefix",
      "delete_prefix","begin_prefix","commit_prefix","rollback_prefix","savepoint_prefix",
      "release_prefix","pragma_prefix","other_prefix"};
  static const char *const kinds[]={"unknown","main","wal","journal","temp"};
  for (unsigned round=0;round<2;++round) {
    const RetentionSyncRound *r=&retention_sync_probe.rounds[round];
    if (!r->completed) retention_sync_probe.errors|=RS_ERROR_PHASE;
    printf("retention_sync_round round=%u initial_record=%llu poll=%llu retry_record=%llu "
        "maintenance=%llu retired=%llu held=%llu syncs=%llu ticks=%llu writes=%llu "
        "raw_syncs=%llu raw_ticks=%llu raw_writes=%llu completed=%u\n",round,
        (unsigned long long)r->entries[RS_ENTRY_INITIAL],(unsigned long long)r->entries[RS_ENTRY_POLL],
        (unsigned long long)r->entries[RS_ENTRY_RETRY],(unsigned long long)r->maintenance,
        (unsigned long long)r->retired,(unsigned long long)r->held,(unsigned long long)r->syncs,
        (unsigned long long)r->ticks,(unsigned long long)r->writes,(unsigned long long)r->raw_syncs,
        (unsigned long long)r->raw_ticks,(unsigned long long)r->raw_writes,r->completed);
  }
  for (unsigned i=0;i<retention_sync_probe.count;++i) {
    const RetentionSyncBucket *b=&retention_sync_probe.buckets[i];
    printf("retention_sync_scope id=%u round=%u entry=%s api=%s function=%s line=%u sql=%s "
        "mode=%d parent=%d calls=%llu ok=%llu rows=%llu done=%llu failures=%llu first_failure=%d last_failure=%d "
        "previous_wrapped_checkpoint_intervals=%llu previous_wrapped_checkpoint_zero_writes=%llu "
        "previous_wrapped_checkpoint_write_bytes=%llu zero_between_syncs=%llu\n",i,b->round,entries[b->entry],apis[b->api],
        b->function,b->line,sqls[b->sql],b->mode,b->parent,(unsigned long long)b->calls,
        (unsigned long long)b->ok,(unsigned long long)b->rows,(unsigned long long)b->done,
        (unsigned long long)b->failures,b->first_failure,b->last_failure,(unsigned long long)b->previous_checkpoint_intervals,
        (unsigned long long)b->previous_checkpoint_zero_writes,(unsigned long long)b->previous_checkpoint_write_bytes,
        (unsigned long long)b->zero_between_syncs);
    for (unsigned f=0;f<RS_FILES;++f) if (b->syncs[f] || b->writes[f])
      printf("retention_sync_io id=%u file=%s syncs=%llu ticks=%llu sync_failures=%llu "
          "writes=%llu write_failures=%llu\n",i,kinds[f],(unsigned long long)b->syncs[f],
          (unsigned long long)b->ticks[f],(unsigned long long)b->sync_failures[f],
          (unsigned long long)b->writes[f],(unsigned long long)b->write_failures[f]);
  }
  printf("retention_sync_contract errors=%u buckets=%u limit=256 depth_limit=16 tick_hz=%llu "
      "exclusive_io=true api_elapsed_measured=false transaction_success_claimed=false "
      "performance_comparison=false\n",retention_sync_probe.errors,retention_sync_probe.count,
      (unsigned long long)hz);
  return fflush(stdout)==0 && retention_sync_probe.errors==0 ? 0 : -1;
}

/* Pure collector contracts: no filesystem, real SQLite call, or VM action. */
static int rs_contract(void) {
  int commit,checkpoint;
  rs_reset(); rs_round_begin(0,10,100,1000); rs_entry_begin(RS_ENTRY_INITIAL);
  commit=retention_sync_probe_enter(RS_API_EXEC,"exec_sql",1,"COMMIT;",-1);
  rs_sync(RS_FILE_WAL,7,SQLITE_OK); rs_write(RS_FILE_WAL,13,SQLITE_OK);
  checkpoint=retention_sync_probe_enter(RS_API_CHECKPOINT,"wal_hook",2,NULL,SQLITE_CHECKPOINT_PASSIVE);
  rs_sync(RS_FILE_MAIN,11,SQLITE_IOERR); rs_write(RS_FILE_MAIN,17,SQLITE_OK);
  retention_sync_probe_leave(checkpoint,SQLITE_BUSY); retention_sync_probe_leave(commit,SQLITE_OK);
  rs_entry_end(); rs_round_end(12,118,1030,1,2,0);
  if (retention_sync_probe.errors || retention_sync_probe.count!=2 ||
      retention_sync_probe.buckets[0].syncs[RS_FILE_WAL]!=1 ||
      retention_sync_probe.buckets[0].syncs[RS_FILE_MAIN]!=0 ||
      retention_sync_probe.buckets[1].parent!=0 || retention_sync_probe.buckets[1].failures!=1 ||
      retention_sync_probe.buckets[1].last_failure!=SQLITE_BUSY ||
      retention_sync_probe.buckets[1].sync_failures[RS_FILE_MAIN]!=1) return -1;
  rs_round_begin(1,12,118,1030); rs_entry_begin(RS_ENTRY_POLL);
  checkpoint=retention_sync_probe_enter(RS_API_CHECKPOINT,"wal_hook",2,NULL,SQLITE_CHECKPOINT_PASSIVE);
  retention_sync_probe_leave(checkpoint,SQLITE_OK);
  if (retention_sync_probe.buckets[2].previous_checkpoint_intervals) return -1;
  checkpoint=retention_sync_probe_enter(RS_API_CHECKPOINT,"wal_hook",2,NULL,SQLITE_CHECKPOINT_PASSIVE);
  rs_sync(RS_FILE_MAIN,5,SQLITE_OK); retention_sync_probe_leave(checkpoint,SQLITE_OK);
  checkpoint=retention_sync_probe_enter(RS_API_CHECKPOINT,"wal_hook",2,NULL,SQLITE_CHECKPOINT_PASSIVE);
  retention_sync_probe_leave(checkpoint,SQLITE_OK); rs_entry_end(); rs_round_end(13,123,1030,0,0,0);
  if (retention_sync_probe.errors || retention_sync_probe.buckets[2].previous_checkpoint_intervals!=2 ||
      retention_sync_probe.buckets[2].previous_checkpoint_zero_writes!=2 ||
      retention_sync_probe.buckets[2].zero_between_syncs!=1) return -1;
  rs_reset(); rs_round_begin(0,0,0,0);
  commit=retention_sync_probe_enter(RS_API_EXEC,"exec_sql",1,"COMMIT;",-1);
  retention_sync_probe.buckets[0].syncs[RS_FILE_WAL]=UINT64_MAX;
  rs_sync(RS_FILE_WAL,0,SQLITE_OK);
  if (!(retention_sync_probe.errors&RS_ERROR_OVERFLOW)) return -1;
  rs_reset(); rs_round_begin(0,0,0,0);
  commit=retention_sync_probe_enter(RS_API_EXEC,"exec_sql",1,"COMMIT;",-1);
  rs_round_end(0,0,0,0,0,0);
  if (!(retention_sync_probe.errors&RS_ERROR_STACK)) return -1;
  rs_reset(); rs_round_begin(0,0,0,0);
  for (unsigned i=0;i<RS_STACK_LIMIT;++i)
    if (retention_sync_probe_enter(RS_API_EXEC,"nested",i,"COMMIT;",-1)<1) return -1;
  if (retention_sync_probe_enter(RS_API_EXEC,"overflow",0,"COMMIT;",-1)!=-1 ||
      !(retention_sync_probe.errors&RS_ERROR_STACK)) return -1;
  rs_reset(); rs_round_begin(0,0,0,0);
  for (unsigned i=0;i<RS_BUCKET_LIMIT;++i) {
    commit=retention_sync_probe_enter(RS_API_STEP,"bounded",i,"SELECT 1",-1);
    retention_sync_probe_leave(commit,SQLITE_ROW);
  }
  if (retention_sync_probe_enter(RS_API_STEP,"overflow",0,"SELECT 1",-1)!=-1 ||
      !(retention_sync_probe.errors&RS_ERROR_BUCKETS)) return -1;
  rs_reset(); rs_round_begin(0,0,0,0); rs_sync(RS_FILE_WAL,1,SQLITE_OK);
  if (!(retention_sync_probe.errors&RS_ERROR_UNKNOWN)) return -1;
  memset(&retention_sync_probe,0,sizeof(retention_sync_probe));
  puts("retention_sync_probe_contract=PASS"); return fflush(stdout)==0 ? 0 : -1;
}
#endif
#endif
