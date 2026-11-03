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
       RS_ERROR_UNKNOWN=8, RS_ERROR_RECONCILE=16, RS_ERROR_PHASE=32, RS_ERROR_RECLAIM=64 };

int retention_sync_probe_active(void);
int retention_sync_probe_enter(unsigned api, const char *function, unsigned line,
                               const char *sql, int checkpoint_mode);
void retention_sync_probe_leave(int token, int sqlite_result);
typedef struct {
  uint64_t admitted,rejected,retired,held,maintenance,failures,db_bytes,wal_bytes;
  unsigned pending,pressure,state,drain,physical_available;
} RetentionReclaimMemory;
void retention_sync_storage_snapshot(RetentionReclaimMemory *out);
void retention_reclaim_step(sqlite3_stmt *,const char *,int);
void retention_reclaim_column(sqlite3_stmt *,const char *,int,sqlite3_int64);
int retention_reclaim_exec_begin(const char *sql);
void retention_reclaim_exec_end(int token,int result);
int retention_reclaim_checkpoint_begin(const char *function);
void retention_reclaim_checkpoint_end(int token,int result);

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

/* Only observations from the unchanged owner are joined here. In particular,
 * no post-vacuum freelist query or filesystem stat is issued by the probe. */
#define RR_ENTRY_LIMIT 512u
#define RR_SLICE_LIMIT 256u
enum { RR_LIMIT=1, RR_PAIR=2, RR_REQUEST=3, RR_STALE=4, RR_MISSING=5,
       RR_VALUE=6, RR_RESULT=7, RR_RECONCILE=8 };
enum { RR_PAGES=1, RR_FREE=2, RR_LIVE=3 };
typedef struct { unsigned entry,valid; uint64_t seq; sqlite3_int64 a,b; } ReclaimRow;
typedef struct { uint64_t calls,ok,failures; int first_failure; sqlite3_int64 last_target; } ReclaimTruncate;
typedef struct {
  unsigned id,round,entry,completed,slices,after_status_refreshed,after_owner_refreshed;
  uint64_t free_reads,last_free_seq; sqlite3_int64 last_free;
  RetentionReclaimMemory before,after;
} ReclaimEntry;
typedef struct {
  unsigned id,entry_id,round,entry,request_pages,pending_before,completed,error;
  ReclaimRow free,pre,post,live;
  uint64_t begin_seq,end_seq,checkpoint_begin_seq,checkpoint_end_seq;
  int vacuum_rc,checkpoint_rc,vacuum_returned,checkpoint_returned,logical_known;
  uint64_t logical_removed;
  RetentionReclaimMemory before,after_vacuum,after_checkpoint;
  ReclaimTruncate truncates[2][2]; /* vacuum/checkpoint, main/wal */
} ReclaimSlice;
static struct {
  unsigned entries,slices,current_entry,current_slice,errors,first_failure;
  uint64_t seq,row_seq;
  sqlite3_stmt *row_statement;
  unsigned row_kind,row_mask;
  sqlite3_int64 row_page_count;
  ReclaimRow free,pages,live;
  ReclaimEntry entry[RR_ENTRY_LIMIT];
  ReclaimSlice slice[RR_SLICE_LIMIT];
} retention_reclaim;
static void rr_fail(unsigned reason) {
  retention_sync_probe.errors|=RS_ERROR_RECLAIM;
  ++retention_reclaim.errors;
  if (!retention_reclaim.first_failure) retention_reclaim.first_failure=reason;
  if (retention_reclaim.current_slice && !retention_reclaim.slice[retention_reclaim.current_slice-1u].error)
    retention_reclaim.slice[retention_reclaim.current_slice-1u].error=reason;
}
static uint64_t rr_next(void) {
  if (retention_reclaim.seq==UINT64_MAX) { rr_fail(RR_LIMIT); return 0; }
  return ++retention_reclaim.seq;
}
static void rr_entry_begin(unsigned kind,const RetentionReclaimMemory *memory) {
  if (retention_reclaim.current_entry || retention_reclaim.entries==RR_ENTRY_LIMIT) {
    rr_fail(RR_LIMIT); return;
  }
  ReclaimEntry *e=&retention_reclaim.entry[retention_reclaim.entries++];
  e->id=retention_reclaim.entries;e->round=retention_sync_probe.round;e->entry=kind;e->before=*memory;
  retention_reclaim.current_entry=e->id;
  memset(&retention_reclaim.free,0,sizeof(ReclaimRow));
  memset(&retention_reclaim.pages,0,sizeof(ReclaimRow));
  memset(&retention_reclaim.live,0,sizeof(ReclaimRow));
  retention_reclaim.row_statement=NULL;retention_reclaim.row_kind=retention_reclaim.row_mask=0;
  (void)rr_next();
}
static void rr_entry_end(const RetentionReclaimMemory *memory) {
  if (!retention_reclaim.current_entry) { rr_fail(RR_PAIR); return; }
  ReclaimEntry *e=&retention_reclaim.entry[retention_reclaim.current_entry-1u];
  if (retention_reclaim.current_slice) {
    rr_fail(RR_MISSING);retention_reclaim.current_slice=0;
  }
  e->after=*memory;e->completed=1;
  /* The fixture places these ends after its pre-existing get_status call.
   * Poll snapshots remain memory-only, including early returns. */
  e->after_status_refreshed=e->entry==RS_ENTRY_INITIAL || e->entry==RS_ENTRY_RETRY;
  if (e->entry==RS_ENTRY_POLL)
    for (unsigned i=0;i<retention_reclaim.slices;++i)
      if (retention_reclaim.slice[i].entry_id==e->id && retention_reclaim.slice[i].completed)
        e->after_owner_refreshed=1; /* Existing reclaim finish refreshes before return. */
  if (e->after.admitted<e->before.admitted || e->after.rejected<e->before.rejected ||
      e->after.retired<e->before.retired || e->after.maintenance<e->before.maintenance)
    rr_fail(RR_RECONCILE);
  retention_reclaim.current_entry=0;retention_reclaim.row_statement=NULL;
  (void)rr_next();
}
void retention_reclaim_step(sqlite3_stmt *statement,const char *function,int result) {
  if (!retention_sync_probe.active) return;
  retention_reclaim.row_seq=rr_next();retention_reclaim.row_statement=NULL;
  retention_reclaim.row_mask=retention_reclaim.row_kind=0;
  if (result!=SQLITE_ROW || !retention_reclaim.current_entry) return;
  unsigned kind=!strcmp(function,"sqlite_database_page_bytes") ? RR_PAGES :
      !strcmp(function,"sqlite_maintenance_reclaim_poll") ? RR_FREE :
      !strcmp(function,"sqlite_live_size_over_limit") ? RR_LIVE : 0;
  if (kind) { retention_reclaim.row_statement=statement;retention_reclaim.row_kind=kind; }
}
static void rr_observe(unsigned kind,uint64_t seq,sqlite3_int64 a,sqlite3_int64 b) {
  if (!retention_reclaim.current_entry || !seq || seq!=retention_reclaim.row_seq) {
    rr_fail(RR_STALE);return;
  }
  ReclaimRow row={retention_reclaim.current_entry,1,seq,a,b};
  if (a<0 || (kind==RR_PAGES && (b<512 || b>65536 || ((uint64_t)b&((uint64_t)b-1u))))) {
    rr_fail(RR_VALUE);return;
  }
  if (kind==RR_FREE) {
    retention_reclaim.free=row;
    ReclaimEntry *e=&retention_reclaim.entry[row.entry-1u];
    ++e->free_reads;e->last_free_seq=seq;e->last_free=a;
  } else if (kind==RR_LIVE) retention_reclaim.live=row;
  else {
    retention_reclaim.pages=row;
    if (retention_reclaim.current_slice) {
      ReclaimSlice *s=&retention_reclaim.slice[retention_reclaim.current_slice-1u];
      if (s->vacuum_returned && s->vacuum_rc==SQLITE_OK && !s->checkpoint_begin_seq && !s->post.valid)
        s->post=row;
    }
  }
}
void retention_reclaim_column(sqlite3_stmt *statement,const char *function,int column,sqlite3_int64 value) {
  if (!retention_sync_probe.active || !retention_reclaim.current_entry) return;
  unsigned kind=!strcmp(function,"sqlite_database_page_bytes") ? RR_PAGES :
      !strcmp(function,"sqlite_maintenance_reclaim_poll") ? RR_FREE :
      !strcmp(function,"sqlite_live_size_over_limit") ? RR_LIVE : 0;
  if (!kind) return;
  if (statement!=retention_reclaim.row_statement || kind!=retention_reclaim.row_kind ||
      (column!=0 && !(kind==RR_PAGES && column==1))) { rr_fail(RR_STALE);return; }
  if (kind!=RR_PAGES) {
    if (retention_reclaim.row_mask) { rr_fail(RR_STALE);return; }
    retention_reclaim.row_mask=1;rr_observe(kind,retention_reclaim.row_seq,value,0);return;
  }
  if (column==0 && !retention_reclaim.row_mask) {
    retention_reclaim.row_page_count=value;retention_reclaim.row_mask=1;
  } else if (column==1 && retention_reclaim.row_mask==1) {
    retention_reclaim.row_mask=3;
    rr_observe(kind,retention_reclaim.row_seq,retention_reclaim.row_page_count,value);
  } else rr_fail(RR_STALE);
}
/* 0 is another SQL operation; -1 is an invalid version of this fixed command. */
static int rr_request(const char *sql) {
  static const char prefix[]="PRAGMA incremental_vacuum(";
  if (!sql || strncmp(sql,prefix,sizeof(prefix)-1u)) return 0;
  const char *p=sql+sizeof(prefix)-1u;unsigned n=0,digits=0;
  while (*p>='0' && *p<='9') {
    if (n>256u/10u || n*10u+(unsigned)(*p-'0')>256u) return -1;
    n=n*10u+(unsigned)(*p++-'0');++digits;
  }
  return digits && n && !strcmp(p,");") ? (int)n : -1;
}
static int rr_start(int request,const RetentionReclaimMemory *memory) {
  if (!request) return 0;
  if (request<0) { rr_fail(RR_REQUEST);return -1; }
  if (!retention_reclaim.current_entry || retention_reclaim.current_slice ||
      retention_reclaim.slices==RR_SLICE_LIMIT) { rr_fail(RR_LIMIT);return -1; }
  ReclaimSlice *s=&retention_reclaim.slice[retention_reclaim.slices++];
  s->id=retention_reclaim.slices;s->entry_id=retention_reclaim.current_entry;
  s->round=retention_sync_probe.round;s->entry=retention_sync_probe.entry;
  s->request_pages=(unsigned)request;s->free=retention_reclaim.free;
  s->pre=retention_reclaim.pages;s->live=retention_reclaim.live;s->begin_seq=rr_next();
  s->vacuum_rc=s->checkpoint_rc=-1;
  s->before=*memory;s->pending_before=s->before.pending;
  retention_reclaim.current_slice=s->id;
  ++retention_reclaim.entry[s->entry_id-1u].slices;
  if (!s->free.valid || !s->pre.valid || s->free.entry!=s->entry_id || s->pre.entry!=s->entry_id ||
      s->free.seq>=s->pre.seq || s->pre.seq>=s->begin_seq) rr_fail(RR_STALE);
  uint64_t expected=s->pending_before<256u ? s->pending_before : 256u;
  if (s->free.a>=0 && (uint64_t)s->free.a<expected) expected=(uint64_t)s->free.a;
  if (!expected || expected!=s->request_pages) rr_fail(RR_REQUEST);
  return (int)s->id;
}
int retention_reclaim_exec_begin(const char *sql) {
  if (!retention_sync_probe.active) return 0;
  int request=rr_request(sql);
  if (!request) return 0;
  RetentionReclaimMemory memory;retention_sync_storage_snapshot(&memory);
  return rr_start(request,&memory);
}
void retention_reclaim_exec_end(int token,int result) {
  if (token<=0) return;
  if ((unsigned)token!=retention_reclaim.current_slice) { rr_fail(RR_PAIR);return; }
  ReclaimSlice *s=&retention_reclaim.slice[token-1];
  s->vacuum_rc=result;s->vacuum_returned=1;s->end_seq=rr_next();
  retention_sync_storage_snapshot(&s->after_vacuum);
  if (result!=SQLITE_OK) { rr_fail(RR_RESULT);retention_reclaim.current_slice=0; }
}
int retention_reclaim_checkpoint_begin(const char *function) {
  if (!retention_sync_probe.active || strcmp(function,"sqlite_maintenance_checkpoint") ||
      !retention_reclaim.current_slice) return 0;
  ReclaimSlice *s=&retention_reclaim.slice[retention_reclaim.current_slice-1u];
  s->checkpoint_begin_seq=rr_next();
  if (!s->vacuum_returned || s->vacuum_rc!=SQLITE_OK || !s->post.valid ||
      s->post.entry!=s->entry_id || s->entry_id!=retention_reclaim.current_entry ||
      s->post.seq<=s->end_seq || s->post.seq>=s->checkpoint_begin_seq) rr_fail(RR_MISSING);
  else if (s->post.b!=s->pre.b || s->post.a>s->pre.a) rr_fail(RR_VALUE);
  else if (!s->error) { s->logical_known=1;s->logical_removed=(uint64_t)(s->pre.a-s->post.a); }
  return (int)s->id;
}
void retention_reclaim_checkpoint_end(int token,int result) {
  if (token<=0) return;
  if ((unsigned)token!=retention_reclaim.current_slice) { rr_fail(RR_PAIR);return; }
  ReclaimSlice *s=&retention_reclaim.slice[token-1];
  s->checkpoint_rc=result;s->checkpoint_returned=1;s->checkpoint_end_seq=rr_next();
  retention_sync_storage_snapshot(&s->after_checkpoint);
  if (result!=SQLITE_OK) rr_fail(RR_RESULT);
  s->completed=!s->error && s->logical_known;
  retention_reclaim.current_slice=0;
}
static void rr_truncate(unsigned file,sqlite3_int64 target,int result) {
  if (!retention_sync_probe.active || !retention_reclaim.current_slice ||
      (file!=RS_FILE_MAIN && file!=RS_FILE_WAL)) return;
  ReclaimSlice *s=&retention_reclaim.slice[retention_reclaim.current_slice-1u];
  ReclaimTruncate *t=&s->truncates[s->checkpoint_begin_seq ? 1 : 0][file==RS_FILE_WAL];
  ++t->calls;t->last_target=target;
  if (result==SQLITE_OK) ++t->ok;
  else { if (!t->failures) t->first_failure=result;++t->failures; }
}

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
  memset(&retention_reclaim,0,sizeof(retention_reclaim));
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
  RetentionReclaimMemory memory;retention_sync_storage_snapshot(&memory);
  rr_entry_begin(entry,&memory);
}
static void rs_entry_end(void) {
  if (!retention_sync_probe.active) return;
  if (retention_sync_probe.depth) retention_sync_probe.errors|=RS_ERROR_STACK;
  RetentionReclaimMemory memory;retention_sync_storage_snapshot(&memory);
  rr_entry_end(&memory);
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
static void rr_memory_report(const char *prefix,const RetentionReclaimMemory *m) {
#define RR_MEMORY_U64(field) printf(" %s_" #field "=%llu",prefix,(unsigned long long)m->field)
#define RR_MEMORY_U32(field) printf(" %s_" #field "=%u",prefix,m->field)
  RR_MEMORY_U64(admitted);RR_MEMORY_U64(rejected);RR_MEMORY_U64(retired);RR_MEMORY_U64(held);
  RR_MEMORY_U64(maintenance);RR_MEMORY_U64(failures);RR_MEMORY_U64(db_bytes);RR_MEMORY_U64(wal_bytes);
  RR_MEMORY_U32(pending);RR_MEMORY_U32(pressure);RR_MEMORY_U32(state);RR_MEMORY_U32(drain);
  RR_MEMORY_U32(physical_available);
#undef RR_MEMORY_U64
#undef RR_MEMORY_U32
}
static uint64_t rr_reconcile(void) {
  uint64_t counted[2][RS_ENTRIES]={{0}},retired[2]={0},maintenance[2]={0};
  unsigned slices=0;uint64_t vacuum_calls=0;
  for (unsigned i=0;i<retention_reclaim.entries;++i) {
    const ReclaimEntry *e=&retention_reclaim.entry[i];
    if (!e->completed || e->round>=2 || e->entry>=RS_ENTRIES) { rr_fail(RR_PAIR);continue; }
    ++counted[e->round][e->entry];slices+=e->slices;
    if (e->after.retired>=e->before.retired) rs_add(&retired[e->round],e->after.retired-e->before.retired);
    else rr_fail(RR_RECONCILE);
    if (e->after.maintenance>=e->before.maintenance)
      rs_add(&maintenance[e->round],e->after.maintenance-e->before.maintenance);
    else rr_fail(RR_RECONCILE);
  }
  for (unsigned i=0;i<retention_sync_probe.count;++i) {
    const RetentionSyncBucket *b=&retention_sync_probe.buckets[i];
    if (b->api==RS_API_EXEC && b->sql==RS_SQL_PRAGMA && !strcmp(b->function,"exec_sql"))
      rs_add(&vacuum_calls,b->calls);
  }
  if (slices!=retention_reclaim.slices || vacuum_calls!=slices || retention_reclaim.current_entry ||
      retention_reclaim.current_slice) rr_fail(RR_RECONCILE);
  for (unsigned r=0;r<2;++r) {
    for (unsigned e=0;e<RS_ENTRIES;++e)
      if (counted[r][e]!=retention_sync_probe.rounds[r].entries[e]) rr_fail(RR_RECONCILE);
    if (retired[r]!=retention_sync_probe.rounds[r].retired ||
        maintenance[r]!=retention_sync_probe.rounds[r].maintenance) rr_fail(RR_RECONCILE);
  }
  return vacuum_calls;
}
static void rr_report(void) {
  static const char *const entries[]={"other","initial_record","poll","retry_record"};
  uint64_t vacuum_calls=rr_reconcile();
  for (unsigned i=0;i<retention_reclaim.entries;++i) {
    const ReclaimEntry *e=&retention_reclaim.entry[i];
    printf("retention_reclaim_entry id=%u round=%u entry=%s completed=%u slices=%u "
        "after_status_refreshed=%u after_owner_refreshed=%u free_reads=%llu last_free_seq=%llu last_free=%lld",
        e->id,e->round,entries[e->entry],e->completed,e->slices,e->after_status_refreshed,e->after_owner_refreshed,
        (unsigned long long)e->free_reads,(unsigned long long)e->last_free_seq,(long long)e->last_free);
    rr_memory_report("before",&e->before);rr_memory_report("after",&e->after);putchar('\n');
  }
  for (unsigned i=0;i<retention_reclaim.slices;++i) {
    const ReclaimSlice *s=&retention_reclaim.slice[i];
    if (!s->completed) rr_fail(RR_MISSING);
    printf("retention_reclaim_slice id=%u entry_id=%u round=%u entry=%s request_pages=%u pending_before=%u "
        "free_before=%lld free_seq=%llu pre_seq=%llu pre_pages=%lld pre_page_size=%lld "
        "vacuum_begin_seq=%llu vacuum_end_seq=%llu vacuum_rc=%d "
        "post_seq=%llu post_pages=%lld post_page_size=%lld checkpoint_begin_seq=%llu checkpoint_end_seq=%llu "
        "checkpoint_rc=%d logical_removed_known=%d logical_page_count_removed=%llu "
        "completed=%u error=%u post_free_observed=0 free_known=%u pre_known=%u post_known=%u "
        "live_known=%u live_seq=%llu live_bytes=%lld",
        s->id,s->entry_id,s->round,entries[s->entry],s->request_pages,s->pending_before,
        (long long)s->free.a,(unsigned long long)s->free.seq,(unsigned long long)s->pre.seq,
        (long long)s->pre.a,(long long)s->pre.b,(unsigned long long)s->begin_seq,
        (unsigned long long)s->end_seq,s->vacuum_rc,(unsigned long long)s->post.seq,
        (long long)s->post.a,(long long)s->post.b,(unsigned long long)s->checkpoint_begin_seq,
        (unsigned long long)s->checkpoint_end_seq,s->checkpoint_rc,s->logical_known,
        (unsigned long long)s->logical_removed,s->completed,s->error,s->free.valid,s->pre.valid,s->post.valid,s->live.valid,
        (unsigned long long)s->live.seq,(long long)s->live.a);
    rr_memory_report("before",&s->before);rr_memory_report("after_vacuum",&s->after_vacuum);
    rr_memory_report("after_checkpoint",&s->after_checkpoint);putchar('\n');
    for (unsigned phase=0;phase<2;++phase) for (unsigned file=0;file<2;++file) {
      const ReclaimTruncate *t=&s->truncates[phase][file];
      if (t->calls) printf("retention_reclaim_truncate slice_id=%u phase=%s file=%s calls=%llu ok=%llu "
          "failures=%llu first_failure=%d last_target=%lld\n",s->id,phase ? "checkpoint" : "vacuum",
          file ? "wal" : "main",(unsigned long long)t->calls,(unsigned long long)t->ok,
          (unsigned long long)t->failures,t->first_failure,(long long)t->last_target);
    }
  }
  printf("retention_reclaim_contract errors=%u first_failure=%u entries=%u slices=%u entry_limit=512 "
      "slice_limit=256 vacuum_calls=%llu added_sql=0 added_stat=0 post_free_observed=0 "
      "logical_delta_is_freelist_delta=false truncate_target_is_reclaimed_bytes=false "
      "slice_memory_snapshots_fresh=false live_is_vacuum_snapshot=false\n",retention_reclaim.errors,retention_reclaim.first_failure,
      retention_reclaim.entries,retention_reclaim.slices,(unsigned long long)vacuum_calls);
}
static int rs_report(uint64_t hz) {
  static const char *const entries[]={"other","initial_record","poll","retry_record"};
  static const char *const apis[]={"unwrapped","exec","step","checkpoint"};
  static const char *const sqls[]={"none","select_prefix","insert_prefix","update_prefix",
      "delete_prefix","begin_prefix","commit_prefix","rollback_prefix","savepoint_prefix",
      "release_prefix","pragma_prefix","other_prefix"};
  static const char *const kinds[]={"unknown","main","wal","journal","temp"};
  rr_report();
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

/* Synthetic observations exercise the collector only, not SQLite or a file. */
static void rr_contract_row(unsigned kind,sqlite3_int64 a,sqlite3_int64 b) {
  retention_reclaim.row_seq=rr_next();rr_observe(kind,retention_reclaim.row_seq,a,b);
}
static void rr_contract_setup(const RetentionReclaimMemory *m,sqlite3_int64 free_pages) {
  rs_reset();retention_sync_probe.active=1;retention_sync_probe.entry=RS_ENTRY_POLL;
  rr_entry_begin(RS_ENTRY_POLL,m);
  rr_contract_row(RR_FREE,free_pages,0);rr_contract_row(RR_PAGES,100,4096);
}
static int rr_contract(void) {
  RetentionReclaimMemory m={0};m.pending=4096;
  int token,checkpoint;
  if (rr_request("PRAGMA incremental_vacuum(257);")!=-1 ||
      rr_request("PRAGMA incremental_vacuum(0);")!=-1 ||
      rr_request("PRAGMA incremental_vacuum(8);SELECT 1;")!=-1 ||
      rr_request("PRAGMA incremental_vacuum(256);")!=256) return -1;
  rr_contract_setup(&m,8);token=rr_start(8,&m);
  retention_reclaim_exec_end(token,SQLITE_OK);rr_contract_row(RR_PAGES,91,4096);
  checkpoint=retention_reclaim_checkpoint_begin("sqlite_maintenance_checkpoint");
  rr_truncate(RS_FILE_MAIN,91*4096,SQLITE_OK);rr_truncate(RS_FILE_WAL,0,SQLITE_OK);
  retention_reclaim_checkpoint_end(checkpoint,SQLITE_OK);rr_entry_end(&m);
  /* Logical page reduction is not freelist reduction: pointer-map pages can
   * also disappear. Do not assert page_count delta equals request N. */
  if (retention_reclaim.errors || !retention_reclaim.slice[0].completed ||
      !retention_reclaim.slice[0].logical_known || retention_reclaim.slice[0].logical_removed!=9 ||
      retention_reclaim.slice[0].truncates[1][0].calls!=1 ||
      retention_reclaim.slice[0].truncates[1][1].last_target!=0) return -1;
  rr_contract_setup(&m,8);token=rr_start(8,&m);retention_reclaim_exec_end(token,SQLITE_OK);
  rr_contract_row(RR_PAGES,92,4096);
  checkpoint=retention_reclaim_checkpoint_begin("sqlite_maintenance_checkpoint");
  retention_reclaim_checkpoint_end(checkpoint,SQLITE_BUSY);
  if (retention_reclaim.first_failure!=RR_RESULT || retention_reclaim.slice[0].completed ||
      !retention_reclaim.slice[0].logical_known || retention_reclaim.slice[0].logical_removed!=8) return -1;
  rr_contract_setup(&m,8);
  sqlite3_stmt *opaque=(sqlite3_stmt *)(void *)&m;
  retention_reclaim_step(opaque,"sqlite_database_page_bytes",SQLITE_ROW);
  retention_reclaim_column(opaque,"sqlite_database_page_bytes",0,100);
  retention_reclaim_step(opaque,"sqlite_database_page_bytes",SQLITE_DONE);
  retention_reclaim_column(opaque,"sqlite_database_page_bytes",1,4096);
  if (retention_reclaim.first_failure!=RR_STALE) return -1;
  rr_contract_setup(&m,8);(void)rr_start(9,&m);
  if (retention_reclaim.first_failure!=RR_REQUEST) return -1;
  rr_contract_setup(&m,0);(void)rr_start(1,&m);
  if (retention_reclaim.first_failure!=RR_REQUEST) return -1;
  rr_contract_setup(&m,8);retention_reclaim.pages.seq=retention_reclaim.free.seq;
  (void)rr_start(8,&m);if (retention_reclaim.first_failure!=RR_STALE) return -1;
  rr_contract_setup(&m,8);retention_reclaim.pages.entry=2;
  (void)rr_start(8,&m);if (retention_reclaim.first_failure!=RR_STALE) return -1;
  rr_contract_setup(&m,8);token=rr_start(8,&m);
  retention_reclaim_exec_end(token,SQLITE_FULL);
  if (retention_reclaim.first_failure!=RR_RESULT || retention_reclaim.slice[0].logical_known ||
      retention_reclaim.slice[0].logical_removed || retention_reclaim.current_slice) return -1;
  rr_contract_setup(&m,8);token=rr_start(8,&m);retention_reclaim_exec_end(token,SQLITE_OK);
  (void)retention_reclaim_checkpoint_begin("sqlite_maintenance_checkpoint");
  if (retention_reclaim.first_failure!=RR_MISSING || retention_reclaim.slice[0].logical_known) return -1;
  rr_contract_setup(&m,8);token=rr_start(8,&m);retention_reclaim_exec_end(token,SQLITE_OK);
  rr_contract_row(RR_PAGES,92,4096);retention_reclaim.slice[0].post.seq=retention_reclaim.slice[0].pre.seq;
  (void)retention_reclaim_checkpoint_begin("sqlite_maintenance_checkpoint");
  if (retention_reclaim.first_failure!=RR_MISSING || retention_reclaim.slice[0].logical_known) return -1;
  rr_contract_setup(&m,8);token=rr_start(8,&m);retention_reclaim_exec_end(token,SQLITE_OK);
  rr_contract_row(RR_PAGES,92,4096);retention_reclaim.slice[0].post.entry=2;
  (void)retention_reclaim_checkpoint_begin("sqlite_maintenance_checkpoint");
  if (retention_reclaim.first_failure!=RR_MISSING || retention_reclaim.slice[0].logical_known) return -1;
  rr_contract_setup(&m,8);retention_reclaim.entries=RR_ENTRY_LIMIT;retention_reclaim.current_entry=0;
  rr_entry_begin(RS_ENTRY_POLL,&m);if (retention_reclaim.first_failure!=RR_LIMIT) return -1;
  rr_contract_setup(&m,8);retention_reclaim.slices=RR_SLICE_LIMIT;
  (void)rr_start(8,&m);if (retention_reclaim.first_failure!=RR_LIMIT) return -1;
  /* Missing post-guard observations remain unknown even without a checkpoint. */
  rr_contract_setup(&m,8);token=rr_start(8,&m);retention_reclaim_exec_end(token,SQLITE_OK);
  rr_entry_end(&m);if (retention_reclaim.first_failure!=RR_MISSING || retention_reclaim.slice[0].logical_known) return -1;
  rr_contract_setup(&m,8);rr_entry_end(&m);(void)rr_reconcile();
  if (retention_reclaim.first_failure!=RR_RECONCILE) return -1;
  rr_contract_setup(&m,8);rr_entry_end(&m);
  retention_sync_probe.rounds[0].entries[RS_ENTRY_POLL]=1;
  if (rr_reconcile()!=0 || retention_reclaim.errors) return -1;
  rs_reset();return 0;
}

/* Pure collector contracts: no filesystem, real SQLite call, or VM action. */
static int rs_contract(void) {
  int commit,checkpoint;
  if (rr_contract()!=0) return -1;
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
