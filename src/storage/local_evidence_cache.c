#include "edr/local_evidence_cache.h"

#include "edr/time_util.h"
#include "edr/windows_event_policy.h"

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(EDR_HAVE_SQLITE)
#include <sqlite3.h>
#include <sys/stat.h>
#endif

#define EDR_EVIDENCE_PROC_SLOTS 1024u
#define EDR_EVIDENCE_RING_SLOTS 2048u

typedef struct {
  uint32_t pid;
  uint32_t ppid;
  int64_t last_seen_ns;
  char endpoint_id[48];
  char tenant_id[64];
  char name[256];
  char path[1024];
  char cmdline[1024];
  char parent_name[256];
  char parent_path[512];
} ProcSlot;

typedef struct {
  uint8_t used;
  int64_t event_time_ns;
  uint32_t type;
  uint32_t pid;
  uint32_t ppid;
  char endpoint_id[48];
  char process_name[128];
  char file_path[256];
  char net_dst[64];
  uint32_t net_dport;
} RingSlot;

static ProcSlot s_proc[EDR_EVIDENCE_PROC_SLOTS];
static RingSlot s_ring[EDR_EVIDENCE_RING_SLOTS];
static uint32_t s_ring_pos;
static EdrEvidenceCacheStatus s_status;
static uint64_t s_last_maintenance_ns;

#if defined(EDR_HAVE_SQLITE)
static sqlite3 *s_db;
#endif

static void set_error(const char *msg) {
  snprintf(s_status.last_error, sizeof(s_status.last_error), "%s", msg ? msg : "");
}

static const char *base_name(const char *path) {
  const char *b = path && path[0] ? path : "";
  for (const char *p = b; *p; p++) {
    if (*p == '/' || *p == '\\') {
      b = p + 1;
    }
  }
  return b;
}

static void copy_s(char *dst, size_t cap, const char *src) {
  if (!dst || cap == 0u) {
    return;
  }
  snprintf(dst, cap, "%s", src ? src : "");
}

static int64_t now_unix_ns(void) {
  time_t t = time(NULL);
  return (int64_t)t * 1000000000LL;
}

static int64_t record_time_ns(const EdrBehaviorRecord *r) {
  if (r && r->event_time_ns > 0) {
    return r->event_time_ns;
  }
  return now_unix_ns();
}

static int same_endpoint(const ProcSlot *p, const EdrBehaviorRecord *r) {
  if (!p || !r) {
    return 0;
  }
  if (p->endpoint_id[0] && r->endpoint_id[0] && strcmp(p->endpoint_id, r->endpoint_id) != 0) {
    return 0;
  }
  return 1;
}

static ProcSlot *find_proc(uint32_t pid, const char *endpoint_id) {
  if (pid == 0u) {
    return NULL;
  }
  for (size_t i = 0; i < EDR_EVIDENCE_PROC_SLOTS; i++) {
    ProcSlot *p = &s_proc[i];
    if (p->pid != pid) {
      continue;
    }
    if (endpoint_id && endpoint_id[0] && p->endpoint_id[0] && strcmp(p->endpoint_id, endpoint_id) != 0) {
      continue;
    }
    return p;
  }
  return NULL;
}

static ProcSlot *alloc_proc(uint32_t pid, const EdrBehaviorRecord *r) {
  ProcSlot *empty = NULL;
  ProcSlot *oldest = &s_proc[0];
  for (size_t i = 0; i < EDR_EVIDENCE_PROC_SLOTS; i++) {
    ProcSlot *p = &s_proc[i];
    if (p->pid == pid && same_endpoint(p, r)) {
      return p;
    }
    if (p->pid == 0u && empty == NULL) {
      empty = p;
    }
    if (p->last_seen_ns < oldest->last_seen_ns) {
      oldest = p;
    }
  }
  ProcSlot *p = empty ? empty : oldest;
  memset(p, 0, sizeof(*p));
  p->pid = pid;
  return p;
}

static int should_update_process_cache(const EdrBehaviorRecord *r) {
  if (!r || r->pid == 0u) {
    return 0;
  }
  return r->process_name[0] || r->exe_path[0] || r->cmdline[0] || r->ppid != 0u ||
         r->parent_name[0] || r->parent_path[0];
}

static void process_cache_update(const EdrBehaviorRecord *r) {
  if (!should_update_process_cache(r)) {
    return;
  }
  ProcSlot *p = alloc_proc(r->pid, r);
  if (!p) {
    return;
  }
  p->pid = r->pid;
  if (r->ppid != 0u) {
    p->ppid = r->ppid;
  }
  p->last_seen_ns = record_time_ns(r);
  if (r->endpoint_id[0]) {
    copy_s(p->endpoint_id, sizeof(p->endpoint_id), r->endpoint_id);
  }
  if (r->tenant_id[0]) {
    copy_s(p->tenant_id, sizeof(p->tenant_id), r->tenant_id);
  }
  if (r->process_name[0]) {
    copy_s(p->name, sizeof(p->name), r->process_name);
  } else if (r->exe_path[0] && !p->name[0]) {
    copy_s(p->name, sizeof(p->name), base_name(r->exe_path));
  }
  if (r->exe_path[0]) {
    copy_s(p->path, sizeof(p->path), r->exe_path);
  }
  if (r->cmdline[0]) {
    copy_s(p->cmdline, sizeof(p->cmdline), r->cmdline);
  }
  if (r->parent_name[0]) {
    copy_s(p->parent_name, sizeof(p->parent_name), r->parent_name);
  }
  if (r->parent_path[0]) {
    copy_s(p->parent_path, sizeof(p->parent_path), r->parent_path);
  }
}

void edr_local_evidence_cache_enrich_behavior(EdrBehaviorRecord *r) {
  if (!r) {
    return;
  }
  ProcSlot *p = find_proc(r->pid, r->endpoint_id);
  if (p) {
    if (r->ppid == 0u && p->ppid != 0u) {
      r->ppid = p->ppid;
    }
    if (!r->process_name[0] && p->name[0]) {
      copy_s(r->process_name, sizeof(r->process_name), p->name);
    }
    if (!r->exe_path[0] && p->path[0]) {
      copy_s(r->exe_path, sizeof(r->exe_path), p->path);
    }
    if (!r->cmdline[0] && p->cmdline[0]) {
      copy_s(r->cmdline, sizeof(r->cmdline), p->cmdline);
    }
    if (!r->parent_name[0] && p->parent_name[0]) {
      copy_s(r->parent_name, sizeof(r->parent_name), p->parent_name);
    }
    if (!r->parent_path[0] && p->parent_path[0]) {
      copy_s(r->parent_path, sizeof(r->parent_path), p->parent_path);
    }
  }
  if (!r->parent_name[0] && r->ppid != 0u) {
    ProcSlot *pp = find_proc(r->ppid, r->endpoint_id);
    if (pp) {
      if (pp->name[0]) {
        copy_s(r->parent_name, sizeof(r->parent_name), pp->name);
      }
      if (pp->path[0]) {
        copy_s(r->parent_path, sizeof(r->parent_path), pp->path);
      }
    }
  }
  if (!r->process_name[0] && r->exe_path[0]) {
    copy_s(r->process_name, sizeof(r->process_name), base_name(r->exe_path));
  }
}

static void ring_record(const EdrBehaviorRecord *r) {
  RingSlot *s = &s_ring[s_ring_pos++ % EDR_EVIDENCE_RING_SLOTS];
  memset(s, 0, sizeof(*s));
  s->used = 1u;
  s->event_time_ns = record_time_ns(r);
  s->type = (uint32_t)r->type;
  s->pid = r->pid;
  s->ppid = r->ppid;
  s->net_dport = r->net_dport;
  copy_s(s->endpoint_id, sizeof(s->endpoint_id), r->endpoint_id);
  copy_s(s->process_name, sizeof(s->process_name), r->process_name);
  copy_s(s->file_path, sizeof(s->file_path), r->file_path);
  copy_s(s->net_dst, sizeof(s->net_dst), r->net_dst);
}

static const char *engine_from_context(const char *ctx) {
  const char *p = ctx ? strstr(ctx, "\"engine\":\"") : NULL;
  static char e[32];
  e[0] = '\0';
  if (!p) {
    return "";
  }
  p += 10;
  size_t n = 0;
  while (p[n] && p[n] != '"' && n + 1u < sizeof(e)) {
    e[n] = p[n];
    n++;
  }
  e[n] = '\0';
  return e;
}

#if defined(EDR_HAVE_SQLITE)
static int exec_sql(const char *sql) {
  char *err = NULL;
  if (!s_db) {
    return -1;
  }
  int rc = sqlite3_exec(s_db, sql, NULL, NULL, &err);
  if (rc != SQLITE_OK) {
    set_error(err ? err : "sqlite exec failed");
    sqlite3_free(err);
    return -1;
  }
  return 0;
}

static void bind_text(sqlite3_stmt *st, int idx, const char *s) {
  sqlite3_bind_text(st, idx, s ? s : "", -1, SQLITE_TRANSIENT);
}

static void upsert_process_sqlite(const EdrBehaviorRecord *r) {
  if (!s_db || !r || r->pid == 0u) {
    return;
  }
  const char *sql =
      "INSERT INTO process_cache(endpoint_id,tenant_id,pid,ppid,name,path,cmdline,parent_name,parent_path,"
      "first_seen_ns,last_seen_ns) VALUES(?,?,?,?,?,?,?,?,?,?,?) "
      "ON CONFLICT(endpoint_id,pid) DO UPDATE SET "
      "tenant_id=excluded.tenant_id,ppid=CASE WHEN excluded.ppid<>0 THEN excluded.ppid ELSE process_cache.ppid END,"
      "name=CASE WHEN excluded.name<>'' THEN excluded.name ELSE process_cache.name END,"
      "path=CASE WHEN excluded.path<>'' THEN excluded.path ELSE process_cache.path END,"
      "cmdline=CASE WHEN excluded.cmdline<>'' THEN excluded.cmdline ELSE process_cache.cmdline END,"
      "parent_name=CASE WHEN excluded.parent_name<>'' THEN excluded.parent_name ELSE process_cache.parent_name END,"
      "parent_path=CASE WHEN excluded.parent_path<>'' THEN excluded.parent_path ELSE process_cache.parent_path END,"
      "last_seen_ns=excluded.last_seen_ns;";
  sqlite3_stmt *st = NULL;
  if (sqlite3_prepare_v2(s_db, sql, -1, &st, NULL) != SQLITE_OK) {
    set_error("prepare process_cache failed");
    return;
  }
  int64_t ts = record_time_ns(r);
  bind_text(st, 1, r->endpoint_id);
  bind_text(st, 2, r->tenant_id);
  sqlite3_bind_int64(st, 3, (sqlite3_int64)r->pid);
  sqlite3_bind_int64(st, 4, (sqlite3_int64)r->ppid);
  bind_text(st, 5, r->process_name);
  bind_text(st, 6, r->exe_path);
  bind_text(st, 7, r->cmdline);
  bind_text(st, 8, r->parent_name);
  bind_text(st, 9, r->parent_path);
  sqlite3_bind_int64(st, 10, (sqlite3_int64)ts);
  sqlite3_bind_int64(st, 11, (sqlite3_int64)ts);
  if (sqlite3_step(st) != SQLITE_DONE) {
    set_error("upsert process_cache failed");
  }
  sqlite3_finalize(st);
}

static void insert_event_sqlite(const EdrBehaviorRecord *r) {
  if (!s_db || !r) {
    return;
  }
  const char *sql =
      "INSERT INTO event_cache(event_id,endpoint_id,tenant_id,event_time_ns,type,pid,ppid,process_name,"
      "exe_path,cmdline,file_path,dns_query,net_src,net_dst,net_sport,net_dport,reg_key_path,"
      "reg_value_name,reg_op,detection_context) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);";
  sqlite3_stmt *st = NULL;
  if (sqlite3_prepare_v2(s_db, sql, -1, &st, NULL) != SQLITE_OK) {
    set_error("prepare event_cache failed");
    return;
  }
  bind_text(st, 1, r->event_id);
  bind_text(st, 2, r->endpoint_id);
  bind_text(st, 3, r->tenant_id);
  sqlite3_bind_int64(st, 4, (sqlite3_int64)record_time_ns(r));
  sqlite3_bind_int64(st, 5, (sqlite3_int64)r->type);
  sqlite3_bind_int64(st, 6, (sqlite3_int64)r->pid);
  sqlite3_bind_int64(st, 7, (sqlite3_int64)r->ppid);
  bind_text(st, 8, r->process_name);
  bind_text(st, 9, r->exe_path);
  bind_text(st, 10, r->cmdline);
  bind_text(st, 11, r->file_path);
  bind_text(st, 12, r->dns_query);
  bind_text(st, 13, r->net_src);
  bind_text(st, 14, r->net_dst);
  sqlite3_bind_int64(st, 15, (sqlite3_int64)r->net_sport);
  sqlite3_bind_int64(st, 16, (sqlite3_int64)r->net_dport);
  bind_text(st, 17, r->reg_key_path);
  bind_text(st, 18, r->reg_value_name);
  bind_text(st, 19, r->reg_op);
  bind_text(st, 20, r->detection_context);
  if (sqlite3_step(st) != SQLITE_DONE) {
    set_error("insert event_cache failed");
    s_status.records_dropped++;
  } else {
    s_status.records_written++;
  }
  sqlite3_finalize(st);
}

static void upsert_file_sqlite(const EdrBehaviorRecord *r) {
  if (!s_db || !r || (!r->file_path[0] && !r->exe_path[0])) {
    return;
  }
  const char *sql =
      "INSERT INTO file_evidence(endpoint_id,path,sha256,pid,last_seen_ns) VALUES(?,?,?,?,?) "
      "ON CONFLICT(endpoint_id,path) DO UPDATE SET sha256=excluded.sha256,pid=excluded.pid,"
      "last_seen_ns=excluded.last_seen_ns;";
  sqlite3_stmt *st = NULL;
  if (sqlite3_prepare_v2(s_db, sql, -1, &st, NULL) != SQLITE_OK) {
    return;
  }
  bind_text(st, 1, r->endpoint_id);
  bind_text(st, 2, r->file_path[0] ? r->file_path : r->exe_path);
  bind_text(st, 3, r->exe_hash);
  sqlite3_bind_int64(st, 4, (sqlite3_int64)r->pid);
  sqlite3_bind_int64(st, 5, (sqlite3_int64)record_time_ns(r));
  (void)sqlite3_step(st);
  sqlite3_finalize(st);
}

static void upsert_network_sqlite(const EdrBehaviorRecord *r) {
  if (!s_db || !r || (!r->net_dst[0] && !r->dns_query[0])) {
    return;
  }
  const char *sql =
      "INSERT INTO network_ioc(endpoint_id,remote_ip,remote_url,dst_port,pid,last_seen_ns) "
      "VALUES(?,?,?,?,?,?) "
      "ON CONFLICT(endpoint_id,remote_ip,remote_url,dst_port,pid) DO UPDATE SET "
      "last_seen_ns=excluded.last_seen_ns;";
  sqlite3_stmt *st = NULL;
  if (sqlite3_prepare_v2(s_db, sql, -1, &st, NULL) != SQLITE_OK) {
    return;
  }
  bind_text(st, 1, r->endpoint_id);
  bind_text(st, 2, r->net_dst);
  bind_text(st, 3, r->dns_query);
  sqlite3_bind_int64(st, 4, (sqlite3_int64)r->net_dport);
  sqlite3_bind_int64(st, 5, (sqlite3_int64)r->pid);
  sqlite3_bind_int64(st, 6, (sqlite3_int64)record_time_ns(r));
  (void)sqlite3_step(st);
  sqlite3_finalize(st);
}

static void upsert_registry_sqlite(const EdrBehaviorRecord *r) {
  if (!s_db || !r || !r->reg_key_path[0]) {
    return;
  }
  const char *sql =
      "INSERT INTO registry_evidence(endpoint_id,key_path,value_name,op,pid,last_seen_ns) "
      "VALUES(?,?,?,?,?,?) "
      "ON CONFLICT(endpoint_id,key_path,value_name,op,pid) DO UPDATE SET last_seen_ns=excluded.last_seen_ns;";
  sqlite3_stmt *st = NULL;
  if (sqlite3_prepare_v2(s_db, sql, -1, &st, NULL) != SQLITE_OK) {
    return;
  }
  bind_text(st, 1, r->endpoint_id);
  bind_text(st, 2, r->reg_key_path);
  bind_text(st, 3, r->reg_value_name);
  bind_text(st, 4, r->reg_op);
  sqlite3_bind_int64(st, 5, (sqlite3_int64)r->pid);
  sqlite3_bind_int64(st, 6, (sqlite3_int64)record_time_ns(r));
  (void)sqlite3_step(st);
  sqlite3_finalize(st);
}

static void sqlite_record(const EdrBehaviorRecord *r) {
  if (!s_db) {
    return;
  }
  (void)exec_sql("BEGIN IMMEDIATE;");
  upsert_process_sqlite(r);
  insert_event_sqlite(r);
  upsert_file_sqlite(r);
  upsert_network_sqlite(r);
  upsert_registry_sqlite(r);
  (void)exec_sql("COMMIT;");
}

static int db_size_over_limit(void) {
  if (!s_status.path[0] || s_status.max_db_mb == 0u) {
    return 0;
  }
  struct stat st;
  if (stat(s_status.path, &st) != 0) {
    return 0;
  }
  uint64_t limit = (uint64_t)s_status.max_db_mb * 1024ULL * 1024ULL;
  return limit > 0u && (uint64_t)st.st_size > limit;
}

static void sqlite_maintenance(void) {
  if (!s_db) {
    return;
  }
  s_status.maintenance_runs++;
  int64_t cutoff = now_unix_ns() - (int64_t)s_status.retention_hours * 3600LL * 1000000000LL;
  sqlite3_stmt *st = NULL;
  const char *tables[] = {"event_cache", "process_cache", "file_evidence", "network_ioc", "registry_evidence"};
  const char *cols[] = {"event_time_ns", "last_seen_ns", "last_seen_ns", "last_seen_ns", "last_seen_ns"};
  for (size_t i = 0; i < sizeof(tables) / sizeof(tables[0]); i++) {
    char sql[160];
    snprintf(sql, sizeof(sql), "DELETE FROM %s WHERE %s < ?;", tables[i], cols[i]);
    if (sqlite3_prepare_v2(s_db, sql, -1, &st, NULL) == SQLITE_OK) {
      sqlite3_bind_int64(st, 1, (sqlite3_int64)cutoff);
      (void)sqlite3_step(st);
      sqlite3_finalize(st);
      st = NULL;
    }
  }
  if (db_size_over_limit()) {
    (void)exec_sql("DELETE FROM event_cache WHERE rowid IN (SELECT rowid FROM event_cache ORDER BY event_time_ns ASC LIMIT 1000);");
    (void)exec_sql("PRAGMA wal_checkpoint(TRUNCATE);");
    (void)exec_sql("VACUUM;");
  } else {
    (void)exec_sql("PRAGMA wal_checkpoint(PASSIVE);");
  }
}
#endif

int edr_local_evidence_cache_open(const char *path, uint32_t max_db_mb,
                                  uint32_t retention_hours) {
  memset(&s_status, 0, sizeof(s_status));
  memset(s_proc, 0, sizeof(s_proc));
  memset(s_ring, 0, sizeof(s_ring));
  s_ring_pos = 0;
  s_status.max_db_mb = max_db_mb ? max_db_mb : 128u;
  s_status.retention_hours = retention_hours ? retention_hours : 24u;
  copy_s(s_status.path, sizeof(s_status.path), (path && path[0]) ? path : "local_evidence_cache.db");

#if defined(EDR_HAVE_SQLITE)
  if (sqlite3_open(s_status.path, &s_db) != SQLITE_OK || !s_db) {
    s_db = NULL;
    set_error("sqlite open failed");
    return -1;
  }
  s_status.db_open = 1;
  (void)exec_sql("PRAGMA journal_mode=WAL;");
  (void)exec_sql("PRAGMA synchronous=NORMAL;");
  const char *schema =
      "CREATE TABLE IF NOT EXISTS process_cache ("
      "endpoint_id TEXT NOT NULL,tenant_id TEXT,pid INTEGER NOT NULL,ppid INTEGER,"
      "name TEXT,path TEXT,cmdline TEXT,parent_name TEXT,parent_path TEXT,"
      "first_seen_ns INTEGER,last_seen_ns INTEGER,PRIMARY KEY(endpoint_id,pid));"
      "CREATE TABLE IF NOT EXISTS event_cache ("
      "id INTEGER PRIMARY KEY AUTOINCREMENT,event_id TEXT,endpoint_id TEXT,tenant_id TEXT,"
      "event_time_ns INTEGER,type INTEGER,pid INTEGER,ppid INTEGER,process_name TEXT,exe_path TEXT,"
      "cmdline TEXT,file_path TEXT,dns_query TEXT,net_src TEXT,net_dst TEXT,net_sport INTEGER,"
      "net_dport INTEGER,reg_key_path TEXT,reg_value_name TEXT,reg_op TEXT,detection_context TEXT);"
      "CREATE INDEX IF NOT EXISTS idx_event_cache_ep_time ON event_cache(endpoint_id,event_time_ns);"
      "CREATE INDEX IF NOT EXISTS idx_event_cache_pid_time ON event_cache(endpoint_id,pid,event_time_ns);"
      "CREATE TABLE IF NOT EXISTS file_evidence ("
      "endpoint_id TEXT NOT NULL,path TEXT NOT NULL,sha256 TEXT,pid INTEGER,last_seen_ns INTEGER,"
      "PRIMARY KEY(endpoint_id,path));"
      "CREATE TABLE IF NOT EXISTS network_ioc ("
      "endpoint_id TEXT NOT NULL,remote_ip TEXT NOT NULL,remote_url TEXT NOT NULL,dst_port INTEGER NOT NULL,"
      "pid INTEGER NOT NULL,last_seen_ns INTEGER,"
      "PRIMARY KEY(endpoint_id,remote_ip,remote_url,dst_port,pid));"
      "CREATE TABLE IF NOT EXISTS registry_evidence ("
      "endpoint_id TEXT NOT NULL,key_path TEXT NOT NULL,value_name TEXT NOT NULL,op TEXT NOT NULL,"
      "pid INTEGER NOT NULL,last_seen_ns INTEGER,"
      "PRIMARY KEY(endpoint_id,key_path,value_name,op,pid));"
      "CREATE TABLE IF NOT EXISTS forensic_jobs ("
      "task_id TEXT PRIMARY KEY,status TEXT,evidence_refs TEXT,upload_refs TEXT,error TEXT,"
      "retryable INTEGER,updated_ns INTEGER);";
  if (exec_sql(schema) != 0) {
    edr_local_evidence_cache_close();
    return -1;
  }
  sqlite_maintenance();
  return 0;
#else
  (void)path;
  set_error("sqlite disabled");
  return -1;
#endif
}

void edr_local_evidence_cache_close(void) {
#if defined(EDR_HAVE_SQLITE)
  if (s_db) {
    (void)exec_sql("PRAGMA wal_checkpoint(TRUNCATE);");
    sqlite3_close(s_db);
    s_db = NULL;
  }
#endif
  s_status.db_open = 0;
}

void edr_local_evidence_cache_record_behavior(const EdrBehaviorRecord *r) {
  if (!r) {
    return;
  }
  process_cache_update(r);
  ring_record(r);
  const char *eng = engine_from_context(r->detection_context);
  if (eng[0]) {
    copy_s(s_status.last_engine, sizeof(s_status.last_engine), eng);
  }
  s_status.last_event_time_ns = record_time_ns(r);
  if (!edr_windows_event_policy_should_persist(r)) {
    s_status.records_skipped++;
    return;
  }
#if defined(EDR_HAVE_SQLITE)
  if (s_db) {
    sqlite_record(r);
  } else {
    s_status.records_dropped++;
  }
#else
  s_status.records_dropped++;
#endif
}

void edr_local_evidence_cache_poll_maintenance(void) {
  uint64_t now = edr_monotonic_ns();
  if (now - s_last_maintenance_ns < 60000000000ULL) {
    return;
  }
  s_last_maintenance_ns = now;
#if defined(EDR_HAVE_SQLITE)
  sqlite_maintenance();
#endif
}

void edr_local_evidence_cache_get_status(EdrEvidenceCacheStatus *out) {
  if (!out) {
    return;
  }
  EdrEvidenceCacheStatus st = s_status;
  uint32_t proc_n = 0;
  uint32_t ring_n = 0;
  for (size_t i = 0; i < EDR_EVIDENCE_PROC_SLOTS; i++) {
    if (s_proc[i].pid != 0u) {
      proc_n++;
    }
  }
  for (size_t i = 0; i < EDR_EVIDENCE_RING_SLOTS; i++) {
    if (s_ring[i].used) {
      ring_n++;
    }
  }
  st.process_slots_used = proc_n;
  st.ring_events = ring_n;
  *out = st;
}

static void json_escape(char *dst, size_t cap, const char *s) {
  if (!dst || cap == 0u) {
    return;
  }
  size_t o = 0;
  dst[o++] = '"';
  if (!s) {
    s = "";
  }
  for (; *s && o + 2u < cap; s++) {
    unsigned char c = (unsigned char)*s;
    if (c == '"' || c == '\\') {
      dst[o++] = '\\';
      dst[o++] = (char)c;
    } else if (c < 0x20u) {
      dst[o++] = ' ';
    } else {
      dst[o++] = (char)c;
    }
  }
  if (o + 1u < cap) {
    dst[o++] = '"';
  }
  dst[o < cap ? o : cap - 1u] = '\0';
}

typedef struct {
  int has_type;
  uint32_t type;
  uint32_t pid;
  uint32_t limit;
  uint32_t time_window_s;
  char endpoint_id[48];
  char process_name_contains[128];
  char cmdline_contains[256];
  char file_path_contains[256];
  char remote_ip[64];
  char registry_key_contains[256];
} RtqFilter;

static int contains_ci(const char *haystack, const char *needle) {
  if (!needle || !needle[0]) {
    return 1;
  }
  if (!haystack || !haystack[0]) {
    return 0;
  }
  size_t nn = strlen(needle);
  for (const char *h = haystack; *h; h++) {
    size_t i = 0;
    while (i < nn && h[i] &&
           tolower((unsigned char)h[i]) == tolower((unsigned char)needle[i])) {
      i++;
    }
    if (i == nn) {
      return 1;
    }
  }
  return 0;
}

static int json_get_string(const char *json, const char *key, char *out, size_t cap) {
  if (!json || !key || !out || cap == 0u) {
    return -1;
  }
  out[0] = '\0';
  char pat[80];
  snprintf(pat, sizeof(pat), "\"%s\"", key);
  const char *p = strstr(json, pat);
  if (!p) {
    return -1;
  }
  const char *colon = strchr(p + strlen(pat), ':');
  if (!colon) {
    return -1;
  }
  const char *q = strchr(colon + 1, '"');
  if (!q) {
    return -1;
  }
  q++;
  size_t o = 0;
  while (*q && *q != '"' && o + 1u < cap) {
    if (*q == '\\' && q[1]) {
      q++;
      if (*q == 'n' || *q == 'r' || *q == 't') {
        out[o++] = ' ';
      } else {
        out[o++] = *q;
      }
      q++;
      continue;
    }
    out[o++] = *q++;
  }
  out[o] = '\0';
  return out[0] ? 0 : -1;
}

static int json_get_u32(const char *json, const char *key, uint32_t *out) {
  if (!json || !key || !out) {
    return -1;
  }
  char pat[80];
  snprintf(pat, sizeof(pat), "\"%s\"", key);
  const char *p = strstr(json, pat);
  if (!p) {
    return -1;
  }
  const char *colon = strchr(p + strlen(pat), ':');
  if (!colon) {
    return -1;
  }
  while (*++colon && (isspace((unsigned char)*colon) || *colon == '"')) {
  }
  char *end = NULL;
  unsigned long v = strtoul(colon, &end, 10);
  if (end == colon || v > 0xffffffffUL) {
    return -1;
  }
  *out = (uint32_t)v;
  return 0;
}

static uint32_t event_type_from_name(const char *s, int *ok) {
  if (ok) {
    *ok = 1;
  }
  if (!s || !s[0]) {
    if (ok) {
      *ok = 0;
    }
    return 0u;
  }
  if (strcmp(s, "process") == 0 || strcmp(s, "process_create") == 0) {
    return (uint32_t)EDR_EVENT_PROCESS_CREATE;
  }
  if (strcmp(s, "network") == 0 || strcmp(s, "net") == 0 || strcmp(s, "connect") == 0) {
    return (uint32_t)EDR_EVENT_NET_CONNECT;
  }
  if (strcmp(s, "dns") == 0) {
    return (uint32_t)EDR_EVENT_NET_DNS_QUERY;
  }
  if (strcmp(s, "tls") == 0) {
    return (uint32_t)EDR_EVENT_NET_TLS_HANDSHAKE;
  }
  if (strcmp(s, "file") == 0 || strcmp(s, "file_write") == 0) {
    return (uint32_t)EDR_EVENT_FILE_WRITE;
  }
  if (strcmp(s, "registry") == 0 || strcmp(s, "reg") == 0) {
    return (uint32_t)EDR_EVENT_REG_SET_VALUE;
  }
  if (strcmp(s, "script") == 0 || strcmp(s, "powershell") == 0) {
    return (uint32_t)EDR_EVENT_SCRIPT_POWERSHELL;
  }
  if (strcmp(s, "webshell") == 0) {
    return (uint32_t)EDR_EVENT_WEBSHELL_DETECTED;
  }
  if (strcmp(s, "shellcode") == 0) {
    return (uint32_t)EDR_EVENT_PROTOCOL_SHELLCODE;
  }
  if (strcmp(s, "pmfe") == 0) {
    return (uint32_t)EDR_EVENT_PMFE_SCAN_RESULT;
  }
  char *end = NULL;
  unsigned long v = strtoul(s, &end, 10);
  if (end != s && *end == '\0' && v <= 0xffffffffUL) {
    return (uint32_t)v;
  }
  if (ok) {
    *ok = 0;
  }
  return 0u;
}

static void parse_rtq_filter(const char *json, RtqFilter *f) {
  memset(f, 0, sizeof(*f));
  f->limit = 50u;
  f->time_window_s = 600u;
  if (!json) {
    return;
  }
  (void)json_get_string(json, "endpoint_id", f->endpoint_id, sizeof(f->endpoint_id));
  (void)json_get_string(json, "process_name_contains", f->process_name_contains,
                        sizeof(f->process_name_contains));
  (void)json_get_string(json, "cmdline_contains", f->cmdline_contains, sizeof(f->cmdline_contains));
  (void)json_get_string(json, "file_path_contains", f->file_path_contains,
                        sizeof(f->file_path_contains));
  (void)json_get_string(json, "remote_ip", f->remote_ip, sizeof(f->remote_ip));
  (void)json_get_string(json, "registry_key_contains", f->registry_key_contains,
                        sizeof(f->registry_key_contains));
  (void)json_get_u32(json, "pid", &f->pid);
  (void)json_get_u32(json, "limit", &f->limit);
  (void)json_get_u32(json, "time_window_s", &f->time_window_s);
  if (f->limit == 0u || f->limit > 500u) {
    f->limit = 50u;
  }
  if (f->time_window_s == 0u || f->time_window_s > 86400u) {
    f->time_window_s = 600u;
  }
  char et[64];
  if (json_get_string(json, "event_type", et, sizeof(et)) != 0) {
    (void)json_get_string(json, "type", et, sizeof(et));
  }
  if (et[0]) {
    int ok = 0;
    uint32_t ty = event_type_from_name(et, &ok);
    if (ok) {
      f->has_type = 1;
      f->type = ty;
    }
  }
}

static int rtq_match_common(const RtqFilter *f, uint32_t type, uint32_t pid,
                            int64_t event_time_ns, const char *endpoint_id,
                            const char *process_name, const char *cmdline,
                            const char *file_path, const char *remote_ip,
                            const char *registry_key) {
  int64_t cutoff = now_unix_ns() - (int64_t)f->time_window_s * 1000000000LL;
  if (event_time_ns > 0 && event_time_ns < cutoff) {
    return 0;
  }
  if (f->has_type && f->type != type) {
    return 0;
  }
  if (f->pid != 0u && f->pid != pid) {
    return 0;
  }
  if (f->endpoint_id[0] && endpoint_id && endpoint_id[0] &&
      strcmp(f->endpoint_id, endpoint_id) != 0) {
    return 0;
  }
  if (!contains_ci(process_name, f->process_name_contains)) {
    return 0;
  }
  if (!contains_ci(cmdline, f->cmdline_contains)) {
    return 0;
  }
  if (!contains_ci(file_path, f->file_path_contains)) {
    return 0;
  }
  if (f->remote_ip[0] && (!remote_ip || strcmp(f->remote_ip, remote_ip) != 0)) {
    return 0;
  }
  if (!contains_ci(registry_key, f->registry_key_contains)) {
    return 0;
  }
  return 1;
}

static void appendf(char *out, size_t cap, size_t *off, const char *fmt, ...) {
  if (!out || !off || *off >= cap) {
    return;
  }
  va_list ap;
  va_start(ap, fmt);
  int n = vsnprintf(out + *off, cap - *off, fmt, ap);
  va_end(ap);
  if (n < 0) {
    return;
  }
  size_t nn = (size_t)n;
  if (nn >= cap - *off) {
    *off = cap - 1u;
  } else {
    *off += nn;
  }
}

static void append_event_json(char *out, size_t cap, size_t *off, int *first,
                              const char *source, int64_t event_time_ns,
                              uint32_t type, uint32_t pid, uint32_t ppid,
                              const char *endpoint_id, const char *process_name,
                              const char *exe_path, const char *cmdline,
                              const char *file_path, const char *dns_query,
                              const char *remote_ip, uint32_t dst_port,
                              const char *registry_key, const char *registry_value,
                              const char *registry_op) {
  char ep[120], pn[320], xp[1200], cl[1200], fp[1200], dns[640], rip[120], rk[1200], rv[640], ro[80];
  json_escape(ep, sizeof(ep), endpoint_id);
  json_escape(pn, sizeof(pn), process_name);
  json_escape(xp, sizeof(xp), exe_path);
  json_escape(cl, sizeof(cl), cmdline);
  json_escape(fp, sizeof(fp), file_path);
  json_escape(dns, sizeof(dns), dns_query);
  json_escape(rip, sizeof(rip), remote_ip);
  json_escape(rk, sizeof(rk), registry_key);
  json_escape(rv, sizeof(rv), registry_value);
  json_escape(ro, sizeof(ro), registry_op);
  appendf(out, cap, off, "%s{\"source\":\"%s\",\"event_time_ns\":%lld,\"type\":%u,"
                          "\"pid\":%u,\"ppid\":%u,\"endpoint_id\":%s,\"process_name\":%s,"
                          "\"exe_path\":%s,\"cmdline\":%s,\"file_path\":%s,\"dns_query\":%s,"
                          "\"remote_ip\":%s,\"dst_port\":%u,\"registry_key\":%s,"
                          "\"registry_value\":%s,\"registry_op\":%s}",
          *first ? "" : ",", source ? source : "", (long long)event_time_ns, type, pid, ppid,
          ep, pn, xp, cl, fp, dns, rip, dst_port, rk, rv, ro);
  *first = 0;
}

int edr_local_evidence_cache_query_json(const char *payload_json, char *out, size_t cap) {
  if (!out || cap == 0u) {
    return -1;
  }
  RtqFilter f;
  parse_rtq_filter(payload_json, &f);
  size_t off = 0;
  int first = 1;
  uint32_t returned = 0;
  uint32_t scanned = 0;
  appendf(out, cap, &off, "{\"source\":\"mixed\",\"partial\":false,\"rows\":[");
  uint32_t ring_pos = s_ring_pos;
  for (uint32_t i = 0; i < EDR_EVIDENCE_RING_SLOTS && returned < f.limit; i++) {
    const RingSlot *r = &s_ring[(ring_pos + EDR_EVIDENCE_RING_SLOTS - 1u - i) % EDR_EVIDENCE_RING_SLOTS];
    if (!r->used) {
      continue;
    }
    scanned++;
    if (!rtq_match_common(&f, r->type, r->pid, r->event_time_ns, r->endpoint_id,
                          r->process_name, "", r->file_path, r->net_dst, "")) {
      continue;
    }
    append_event_json(out, cap, &off, &first, "ring", r->event_time_ns, r->type, r->pid,
                      r->ppid, r->endpoint_id, r->process_name, "", "", r->file_path,
                      "", r->net_dst, r->net_dport, "", "", "");
    returned++;
  }
#if defined(EDR_HAVE_SQLITE)
  if (s_db && returned < f.limit) {
    const char *sql =
        "SELECT event_time_ns,type,pid,ppid,endpoint_id,process_name,exe_path,cmdline,"
        "file_path,dns_query,net_dst,net_dport,reg_key_path,reg_value_name,reg_op "
        "FROM event_cache WHERE event_time_ns>=? ORDER BY event_time_ns DESC LIMIT ?;";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(s_db, sql, -1, &st, NULL) == SQLITE_OK) {
      int64_t cutoff = now_unix_ns() - (int64_t)f.time_window_s * 1000000000LL;
      sqlite3_bind_int64(st, 1, (sqlite3_int64)cutoff);
      sqlite3_bind_int64(st, 2, (sqlite3_int64)(f.limit * 20u + 100u));
      while (sqlite3_step(st) == SQLITE_ROW && returned < f.limit) {
        scanned++;
        int64_t ts = sqlite3_column_int64(st, 0);
        uint32_t ty = (uint32_t)sqlite3_column_int64(st, 1);
        uint32_t pid = (uint32_t)sqlite3_column_int64(st, 2);
        uint32_t ppid = (uint32_t)sqlite3_column_int64(st, 3);
        const char *ep = (const char *)sqlite3_column_text(st, 4);
        const char *pn = (const char *)sqlite3_column_text(st, 5);
        const char *xp = (const char *)sqlite3_column_text(st, 6);
        const char *cl = (const char *)sqlite3_column_text(st, 7);
        const char *fp = (const char *)sqlite3_column_text(st, 8);
        const char *dns = (const char *)sqlite3_column_text(st, 9);
        const char *rip = (const char *)sqlite3_column_text(st, 10);
        uint32_t dport = (uint32_t)sqlite3_column_int64(st, 11);
        const char *rk = (const char *)sqlite3_column_text(st, 12);
        const char *rv = (const char *)sqlite3_column_text(st, 13);
        const char *ro = (const char *)sqlite3_column_text(st, 14);
        if (!rtq_match_common(&f, ty, pid, ts, ep, pn, cl, fp, rip, rk)) {
          continue;
        }
        append_event_json(out, cap, &off, &first, "sqlite", ts, ty, pid, ppid, ep, pn,
                          xp, cl, fp, dns, rip, dport, rk, rv, ro);
        returned++;
      }
      sqlite3_finalize(st);
    }
  }
#endif
  appendf(out, cap, &off, "],\"rows_scanned\":%u,\"rows_returned\":%u}", scanned, returned);
  out[cap - 1u] = '\0';
  return 0;
}

static void append_proc_json(char *out, size_t cap, size_t *off, int *first,
                             const char *source, const ProcSlot *p) {
  char ep[120], tn[160], nm[320], path[1200], cmd[1200], pn[320], pp[640];
  json_escape(ep, sizeof(ep), p ? p->endpoint_id : "");
  json_escape(tn, sizeof(tn), p ? p->tenant_id : "");
  json_escape(nm, sizeof(nm), p ? p->name : "");
  json_escape(path, sizeof(path), p ? p->path : "");
  json_escape(cmd, sizeof(cmd), p ? p->cmdline : "");
  json_escape(pn, sizeof(pn), p ? p->parent_name : "");
  json_escape(pp, sizeof(pp), p ? p->parent_path : "");
  appendf(out, cap, off, "%s{\"source\":\"%s\",\"endpoint_id\":%s,\"tenant_id\":%s,"
                          "\"pid\":%u,\"ppid\":%u,\"name\":%s,\"path\":%s,\"cmdline\":%s,"
                          "\"parent_name\":%s,\"parent_path\":%s,\"last_seen_ns\":%lld}",
          *first ? "" : ",", source ? source : "", ep, tn, p ? p->pid : 0u,
          p ? p->ppid : 0u, nm, path, cmd, pn, pp, p ? (long long)p->last_seen_ns : 0LL);
  *first = 0;
}

int edr_local_evidence_cache_process_tree_json(uint32_t pid, const char *endpoint_id,
                                               char *out, size_t cap) {
  if (!out || cap == 0u || pid == 0u) {
    return -1;
  }
  ProcSlot *root = find_proc(pid, endpoint_id);
  size_t off = 0;
  int first = 1;
  uint32_t children = 0;
  appendf(out, cap, &off, "{\"pid\":%u,\"root\":", pid);
  if (root) {
    int only = 1;
    append_proc_json(out, cap, &off, &only, "memory", root);
  } else {
    appendf(out, cap, &off, "null");
  }
  appendf(out, cap, &off, ",\"children\":[");
  for (size_t i = 0; i < EDR_EVIDENCE_PROC_SLOTS && children < 64u; i++) {
    ProcSlot *p = &s_proc[i];
    if (p->pid == 0u || p->ppid != pid) {
      continue;
    }
    if (endpoint_id && endpoint_id[0] && p->endpoint_id[0] && strcmp(endpoint_id, p->endpoint_id) != 0) {
      continue;
    }
    append_proc_json(out, cap, &off, &first, "memory", p);
    children++;
  }
#if defined(EDR_HAVE_SQLITE)
  if (s_db && children < 64u) {
    const char *sql =
        "SELECT endpoint_id,tenant_id,pid,ppid,name,path,cmdline,parent_name,parent_path,last_seen_ns "
        "FROM process_cache WHERE ppid=? ORDER BY last_seen_ns DESC LIMIT 64;";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(s_db, sql, -1, &st, NULL) == SQLITE_OK) {
      sqlite3_bind_int64(st, 1, (sqlite3_int64)pid);
      while (sqlite3_step(st) == SQLITE_ROW && children < 64u) {
        ProcSlot tmp;
        memset(&tmp, 0, sizeof(tmp));
        copy_s(tmp.endpoint_id, sizeof(tmp.endpoint_id), (const char *)sqlite3_column_text(st, 0));
        if (endpoint_id && endpoint_id[0] && tmp.endpoint_id[0] && strcmp(endpoint_id, tmp.endpoint_id) != 0) {
          continue;
        }
        copy_s(tmp.tenant_id, sizeof(tmp.tenant_id), (const char *)sqlite3_column_text(st, 1));
        tmp.pid = (uint32_t)sqlite3_column_int64(st, 2);
        tmp.ppid = (uint32_t)sqlite3_column_int64(st, 3);
        copy_s(tmp.name, sizeof(tmp.name), (const char *)sqlite3_column_text(st, 4));
        copy_s(tmp.path, sizeof(tmp.path), (const char *)sqlite3_column_text(st, 5));
        copy_s(tmp.cmdline, sizeof(tmp.cmdline), (const char *)sqlite3_column_text(st, 6));
        copy_s(tmp.parent_name, sizeof(tmp.parent_name), (const char *)sqlite3_column_text(st, 7));
        copy_s(tmp.parent_path, sizeof(tmp.parent_path), (const char *)sqlite3_column_text(st, 8));
        tmp.last_seen_ns = sqlite3_column_int64(st, 9);
        append_proc_json(out, cap, &off, &first, "sqlite", &tmp);
        children++;
      }
      sqlite3_finalize(st);
    }
  }
#endif
  appendf(out, cap, &off, "],\"child_count\":%u}", children);
  out[cap - 1u] = '\0';
  return root || children ? 0 : -2;
}

void edr_local_evidence_cache_status_json(char *out, size_t cap) {
  if (!out || cap == 0u) {
    return;
  }
  EdrEvidenceCacheStatus st;
  edr_local_evidence_cache_get_status(&st);
  char path[640];
  char err[220];
  char eng[80];
  json_escape(path, sizeof(path), st.path);
  json_escape(err, sizeof(err), st.last_error);
  json_escape(eng, sizeof(eng), st.last_engine);
  snprintf(out, cap,
           "\"evidence_cache\":{\"db_open\":%s,\"path\":%s,\"max_db_mb\":%u,"
           "\"retention_hours\":%u,\"records_written\":%llu,\"records_dropped\":%llu,"
           "\"records_skipped\":%llu,"
           "\"maintenance_runs\":%llu,\"process_slots_used\":%u,\"ring_events\":%u,"
           "\"last_engine\":%s,\"last_event_time_ns\":%lld,\"last_error\":%s}",
           st.db_open ? "true" : "false", path, st.max_db_mb, st.retention_hours,
           (unsigned long long)st.records_written, (unsigned long long)st.records_dropped,
           (unsigned long long)st.records_skipped,
           (unsigned long long)st.maintenance_runs, st.process_slots_used, st.ring_events,
           eng, (long long)st.last_event_time_ns, err);
}
