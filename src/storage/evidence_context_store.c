#if defined(EDR_HAVE_SQLITE)
#include "evidence_context_store.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(EdrContextStore *s, const char *operation) {
  snprintf(s->error, sizeof(s->error), "%s: %s", operation, sqlite3_errmsg(s->db));
  return -1;
}

static int sql(EdrContextStore *s, const char *text) {
  if (sqlite3_exec(s->db, text, NULL, NULL, NULL) != SQLITE_OK)
    return fail(s, "context SQL failed");
  return 0;
}

static int prepare(EdrContextStore *s, sqlite3_stmt **st, const char *text) {
  if (sqlite3_prepare_v2(s->db, text, -1, st, NULL) != SQLITE_OK)
    return fail(s, "prepare context statement failed");
  return 0;
}

static int text(sqlite3_stmt *st, int n, const char *value) {
  return value ? sqlite3_bind_text(st, n, value, -1, SQLITE_TRANSIENT)
               : sqlite3_bind_null(st, n);
}

static void reset(sqlite3_stmt *st) {
  sqlite3_reset(st);
  sqlite3_clear_bindings(st);
}

static int version(EdrContextStore *s) {
  sqlite3_stmt *st = NULL;
  int v = -1;
  if (prepare(s, &st, "PRAGMA user_version") == 0 && sqlite3_step(st) == SQLITE_ROW)
    v = sqlite3_column_int(st, 0);
  sqlite3_finalize(st);
  if (v < 0 || v > 2) {
    snprintf(s->error, sizeof(s->error), "unsupported evidence cache format %d", v);
    return -1;
  }
  return v;
}

static const char legacy_schema[] =
    "CREATE TABLE IF NOT EXISTS context_facts ("
    "fact_id TEXT PRIMARY KEY,endpoint_id TEXT,tenant_id TEXT,"
    "manifest_template_json TEXT NOT NULL,created_ns INTEGER,updated_ns INTEGER);"
    "CREATE INDEX IF NOT EXISTS idx_context_facts_ep_time ON context_facts(endpoint_id,updated_ns);"
    "CREATE TABLE IF NOT EXISTS candidate_context_refs ("
    "artifact_id TEXT PRIMARY KEY,candidate_id TEXT NOT NULL,fact_id TEXT NOT NULL,"
    "candidate_id_json TEXT NOT NULL,created_ns INTEGER,upload_status TEXT,minio_key TEXT,"
    "UNIQUE(candidate_id,fact_id));"
    "CREATE INDEX IF NOT EXISTS idx_candidate_context_refs_candidate ON candidate_context_refs(candidate_id,created_ns);"
    "CREATE INDEX IF NOT EXISTS idx_candidate_context_refs_fact ON candidate_context_refs(fact_id);";

static const char compact_schema[] =
    "CREATE TABLE context_fact_keys (id INTEGER PRIMARY KEY,fact_id TEXT NOT NULL UNIQUE "
    "REFERENCES context_facts(fact_id));"
    "CREATE TABLE context_candidates (id INTEGER PRIMARY KEY,candidate_id TEXT NOT NULL UNIQUE,"
    "candidate_id_json TEXT NOT NULL);"
    "CREATE TABLE compact_context_refs (id INTEGER PRIMARY KEY,"
    "candidate_key INTEGER NOT NULL REFERENCES context_candidates(id),"
    "fact_key INTEGER NOT NULL REFERENCES context_fact_keys(id),"
    "source_identity BLOB,artifact_override TEXT UNIQUE,candidate_json_override TEXT,"
    "created_ns INTEGER,upload_status TEXT,minio_key TEXT,"
    "CHECK((source_identity IS NOT NULL AND length(source_identity)=32 AND artifact_override IS NULL) OR "
    "(source_identity IS NULL AND artifact_override IS NOT NULL)),"
    "UNIQUE(candidate_key,source_identity),UNIQUE(candidate_key,fact_key));"
    "CREATE INDEX idx_compact_context_candidate_time ON compact_context_refs(candidate_key,created_ns);"
    "CREATE INDEX idx_compact_context_fact ON compact_context_refs(fact_key);"
    "CREATE INDEX idx_compact_context_time ON compact_context_refs(created_ns,candidate_key);";

static int views(EdrContextStore *s) {
  if (sql(s, "DROP VIEW IF EXISTS materialized_artifacts;"
             "DROP VIEW IF EXISTS context_reference_projection;") != 0) return -1;
  const char *projection = s->format ?
      "CREATE VIEW context_reference_projection AS "
      "SELECT artifact_id,candidate_id,fact_id,candidate_id_json,created_ns,upload_status,minio_key "
      "FROM candidate_context_refs UNION ALL "
      "SELECT COALESCE(r.artifact_override,c.candidate_id||':post_context:'||lower(hex(r.source_identity))),"
      "c.candidate_id,f.fact_id,COALESCE(r.candidate_json_override,c.candidate_id_json),"
      "r.created_ns,r.upload_status,r.minio_key FROM compact_context_refs r "
      "JOIN context_candidates c ON c.id=r.candidate_key JOIN context_fact_keys f ON f.id=r.fact_key;"
      : "CREATE VIEW context_reference_projection AS SELECT artifact_id,candidate_id,fact_id,"
        "candidate_id_json,created_ns,upload_status,minio_key FROM candidate_context_refs;";
  if (sql(s, projection) != 0) return -1;
  return sql(s,
      "CREATE VIEW materialized_artifacts AS "
      "SELECT artifact_id,endpoint_id,tenant_id,candidate_id,artifact_type,path,sha256,"
      "manifest_json,created_ns,upload_status,minio_key FROM artifacts a "
      "WHERE a.artifact_type<>'post_context' OR NOT EXISTS ("
      "SELECT 1 FROM context_reference_projection r WHERE r.artifact_id=a.artifact_id) "
      "UNION ALL SELECT r.artifact_id,f.endpoint_id,f.tenant_id,r.candidate_id,'post_context','','',"
      "replace(f.manifest_template_json,'\"candidate_id\":null','\"candidate_id\":'||r.candidate_id_json),"
      "CASE WHEN f.updated_ns>r.created_ns THEN f.updated_ns ELSE r.created_ns END,"
      "r.upload_status,r.minio_key FROM context_reference_projection r "
      "JOIN context_facts f ON f.fact_id=r.fact_id;");
}

int edr_context_store_check_format(EdrContextStore *s, sqlite3 *db) {
  memset(s, 0, sizeof(*s));
  s->db = db;
  s->format = version(s);
  return s->format < 0 ? -1 : 0;
}

int edr_context_store_open(EdrContextStore *s, sqlite3 *db) {
  if (edr_context_store_check_format(s, db) != 0) return -1;
  if (sql(s, "PRAGMA foreign_keys=ON;") != 0) return -1;
  /* Do not create missing compact tables on a versioned database: that would
   * turn corruption into an apparently successful empty store. */
  if (s->format) {
    sqlite3_stmt *st = NULL;
    if (prepare(s, &st, "SELECT r.id,c.candidate_id,f.id FROM compact_context_refs r "
                        "JOIN context_candidates c ON c.id=r.candidate_key "
                        "JOIN context_fact_keys f ON f.id=r.fact_key LIMIT 0") != 0) return -1;
    sqlite3_finalize(st);
  } else if (sql(s, legacy_schema) != 0) return -1;
  if (sql(s, "BEGIN IMMEDIATE;") != 0) return -1;
  if (views(s) != 0 || sql(s, "COMMIT;") != 0) {
    sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
    return -1;
  }
  return 0;
}

int edr_context_store_begin_upgrade(EdrContextStore *s) {
  if (s->format) return 0;
  if (sql(s, "BEGIN IMMEDIATE;") != 0) return -1;
  if (sql(s, compact_schema) != 0) goto rollback;
  s->format = 1;
  if (views(s) != 0 || sql(s, "PRAGMA user_version=1;COMMIT;") != 0) goto rollback;
  return 0;
rollback:
  sqlite3_exec(s->db, "ROLLBACK", NULL, NULL, NULL);
  s->format = 0;
  return -1;
}

/* Only byte-exact lowercase identities use the compact representation. All
 * other historical artifact IDs retain their original text without guessing. */
static int decode_source(const char *artifact, size_t *prefix, unsigned char out[32]) {
  static const char marker[] = ":post_context:";
  size_t n = artifact ? strlen(artifact) : 0;
  if (n < sizeof(marker) - 1 + 64) return 0;
  *prefix = n - (sizeof(marker) - 1) - 64;
  if (memcmp(artifact + *prefix, marker, sizeof(marker) - 1) != 0) return 0;
  for (unsigned i = 0; i < 64; ++i) {
    unsigned char ch = (unsigned char)artifact[n - 64 + i];
    int nibble = ch >= '0' && ch <= '9' ? ch - '0' : ch >= 'a' && ch <= 'f' ? ch - 'a' + 10 : -1;
    if (nibble < 0) return 0;
    if (!(i & 1)) out[i / 2] = (unsigned char)(nibble << 4);
    else out[i / 2] |= (unsigned char)nibble;
  }
  return 1;
}

sqlite3_stmt *edr_context_store_prepare_lookup(EdrContextStore *s) {
  sqlite3_stmt *st = NULL;
  const char *query = s->format ?
      "SELECT c.candidate_id,f.fact_id,r.created_ns FROM compact_context_refs r "
      "JOIN context_candidates c ON c.id=r.candidate_key JOIN context_fact_keys f ON f.id=r.fact_key "
      "WHERE r.candidate_key=(SELECT id FROM context_candidates WHERE candidate_id=?1) AND r.source_identity=?2 "
      "UNION ALL SELECT c.candidate_id,f.fact_id,r.created_ns FROM compact_context_refs r "
      "JOIN context_candidates c ON c.id=r.candidate_key JOIN context_fact_keys f ON f.id=r.fact_key "
      "WHERE r.artifact_override=?3 "
      "UNION ALL SELECT candidate_id,fact_id,created_ns FROM candidate_context_refs WHERE artifact_id=?3;"
      : "SELECT candidate_id,fact_id,created_ns FROM candidate_context_refs WHERE artifact_id=?3;";
  if (prepare(s, &st, query) != 0) return NULL;
  return st;
}

int edr_context_store_bind_lookup(EdrContextStore *s, sqlite3_stmt *st, const char *artifact) {
  unsigned char source[32];
  size_t prefix = 0;
  reset(st);
  if (decode_source(artifact, &prefix, source)) {
    if (sqlite3_bind_text(st, 1, artifact, (int)prefix, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_blob(st, 2, source, 32, SQLITE_TRANSIENT) != SQLITE_OK)
      return fail(s, "bind context identity failed");
  }
  return text(st, 3, artifact) == SQLITE_OK ? 0 : fail(s, "bind context artifact failed");
}

void edr_context_writer_close(EdrContextWriter *w) {
  sqlite3_finalize(w->candidate_find); sqlite3_finalize(w->candidate_insert);
  sqlite3_finalize(w->fact_find); sqlite3_finalize(w->fact_number);
  sqlite3_finalize(w->ref_insert); sqlite3_finalize(w->old_delete);
  sqlite3_finalize(w->lookup);
  memset(w, 0, sizeof(*w));
}

int edr_context_writer_open(EdrContextStore *s, EdrContextWriter *w) {
  memset(w, 0, sizeof(*w)); w->store = s;
  if (!s->format) {
    return prepare(s, &w->ref_insert,
      "INSERT INTO candidate_context_refs(artifact_id,candidate_id,fact_id,candidate_id_json,created_ns,upload_status,minio_key) "
      "VALUES(?1,?2,?3,?4,?5,?6,?7) ON CONFLICT(artifact_id) DO UPDATE SET "
      "candidate_id=excluded.candidate_id,fact_id=excluded.fact_id,candidate_id_json=excluded.candidate_id_json,"
      "created_ns=excluded.created_ns,upload_status=excluded.upload_status,minio_key=excluded.minio_key;");
  }
  if (prepare(s, &w->candidate_find, "SELECT id,candidate_id_json FROM context_candidates WHERE candidate_id=?") ||
      prepare(s, &w->candidate_insert, "INSERT INTO context_candidates(candidate_id,candidate_id_json) VALUES(?,?)") ||
      prepare(s, &w->fact_find, "SELECT id FROM context_fact_keys WHERE fact_id=?") ||
      prepare(s, &w->fact_number, "INSERT INTO context_fact_keys(fact_id) VALUES(?)") ||
      prepare(s, &w->old_delete, "DELETE FROM candidate_context_refs WHERE artifact_id=?") ||
      prepare(s, &w->ref_insert,
        "INSERT INTO compact_context_refs(candidate_key,fact_key,source_identity,artifact_override,candidate_json_override,"
        "created_ns,upload_status,minio_key) VALUES(?1,?2,?3,?4,?5,?6,?7,?8) "
        "ON CONFLICT(candidate_key,source_identity) DO UPDATE SET fact_key=excluded.fact_key,candidate_json_override=excluded.candidate_json_override,"
        "created_ns=excluded.created_ns,upload_status=excluded.upload_status,minio_key=excluded.minio_key "
        "ON CONFLICT(artifact_override) DO UPDATE SET fact_key=excluded.fact_key,candidate_json_override=excluded.candidate_json_override,"
        "created_ns=excluded.created_ns,upload_status=excluded.upload_status,minio_key=excluded.minio_key;") ||
      !(w->lookup = edr_context_store_prepare_lookup(s))) {
    edr_context_writer_close(w); return -1;
  }
  return 0;
}

int edr_context_writer_put(EdrContextWriter *w, const char *artifact, const char *candidate,
                           const char *fact, const char *candidate_json, sqlite3_int64 created, int created_null,
                           const char *upload, const char *key) {
  EdrContextStore *s = w->store;
  if (!sqlite3_get_autocommit(s->db) && artifact && candidate && fact && candidate_json) {
    if (!s->format) {
      sqlite3_stmt *st = w->ref_insert; reset(st);
      if (text(st, 1, artifact) != SQLITE_OK || text(st, 2, candidate) != SQLITE_OK ||
          text(st, 3, fact) != SQLITE_OK || text(st, 4, candidate_json) != SQLITE_OK ||
          (created_null ? sqlite3_bind_null(st, 5) : sqlite3_bind_int64(st, 5, created)) != SQLITE_OK ||
          text(st, 6, upload) != SQLITE_OK || text(st, 7, key) != SQLITE_OK)
        return fail(s, "bind legacy context reference failed");
      if (sqlite3_step(st) == SQLITE_DONE) return 0;
      return fail(s, "write legacy context reference failed");
    }
  } else { snprintf(s->error, sizeof(s->error), "context reference requires valid input and transaction"); return -1; }
  sqlite3_stmt *st = w->lookup;
  if (edr_context_store_bind_lookup(s, st, artifact) != 0) return -1;
  int rc = sqlite3_step(st);
  if (rc == SQLITE_ROW) {
    const char *owner = (const char *)sqlite3_column_text(st, 0);
    if (!owner || strcmp(owner, candidate)) {
      snprintf(s->error, sizeof(s->error), "context artifact candidate conflict"); reset(st); return -1;
    }
    rc = sqlite3_step(st);
  }
  if (rc != SQLITE_DONE) { fail(s, "ambiguous context artifact identity"); reset(st); return -1; }
  reset(st);
  sqlite3_int64 candidate_key, fact_key;
  const char *override = NULL;
  st = w->candidate_find; reset(st);
  if (text(st, 1, candidate) != SQLITE_OK) return fail(s, "bind context candidate lookup failed");
  rc = sqlite3_step(st);
  if (rc == SQLITE_ROW) {
    candidate_key = sqlite3_column_int64(st, 0);
    const char *json = (const char *)sqlite3_column_text(st, 1);
    if (!json || strcmp(json, candidate_json)) override = candidate_json;
  } else if (rc == SQLITE_DONE) {
    sqlite3_stmt *insert = w->candidate_insert; reset(insert);
    if (text(insert, 1, candidate) != SQLITE_OK || text(insert, 2, candidate_json) != SQLITE_OK)
      return fail(s, "bind context candidate failed");
    if (sqlite3_step(insert) != SQLITE_DONE) { fail(s, "intern context candidate failed"); reset(st); return -1; }
    candidate_key = sqlite3_last_insert_rowid(s->db);
  } else { fail(s, "read context candidate failed"); reset(st); return -1; }
  reset(st);
  st = w->fact_find; reset(st);
  if (text(st, 1, fact) != SQLITE_OK) return fail(s, "bind context fact lookup failed");
  rc = sqlite3_step(st);
  if (rc == SQLITE_ROW) {
    fact_key = sqlite3_column_int64(st, 0);
  } else if (rc == SQLITE_DONE) {
    sqlite3_stmt *insert = w->fact_number; reset(insert);
    if (text(insert, 1, fact) != SQLITE_OK) return fail(s, "bind context fact key failed");
    if (sqlite3_step(insert) != SQLITE_DONE) {
      fail(s, "intern context fact failed (missing fact or storage error)"); reset(st); return -1;
    }
    fact_key = sqlite3_last_insert_rowid(s->db);
  } else { fail(s, "read context fact key failed"); reset(st); return -1; }
  reset(st);
  unsigned char source[32]; size_t prefix = 0;
  int canonical = decode_source(artifact, &prefix, source) && strlen(candidate) == prefix &&
                  memcmp(artifact, candidate, prefix) == 0;
  st = w->ref_insert; reset(st);
  if (sqlite3_bind_int64(st, 1, candidate_key) != SQLITE_OK || sqlite3_bind_int64(st, 2, fact_key) != SQLITE_OK ||
      (canonical ? sqlite3_bind_blob(st, 3, source, 32, SQLITE_TRANSIENT) : text(st, 4, artifact)) != SQLITE_OK ||
      text(st, 5, override) != SQLITE_OK ||
      (created_null ? sqlite3_bind_null(st, 6) : sqlite3_bind_int64(st, 6, created)) != SQLITE_OK ||
      text(st, 7, upload) != SQLITE_OK || text(st, 8, key) != SQLITE_OK)
    return fail(s, "bind compact context reference failed");
  if (sqlite3_step(st) != SQLITE_DONE) return fail(s, "write compact context reference failed");
  /* Moving an enriched legacy row is part of the same caller-owned transaction. */
  st = w->old_delete; reset(st);
  if (text(st, 1, artifact) != SQLITE_OK) return fail(s, "bind moved legacy reference failed");
  if (sqlite3_step(st) != SQLITE_DONE) return fail(s, "remove moved legacy reference failed");
  return 0;
}

int edr_context_store_migrate_batch(EdrContextStore *s, unsigned limit,
                                    unsigned *moved, int *complete) {
  EdrContextWriter writer;
  sqlite3_stmt *read = NULL;
  *moved = 0; *complete = 0;
  if (!s->format || !limit || limit > 64) {
    snprintf(s->error, sizeof(s->error), "context migration requires format 1/2 and 1..64 rows"); return -1;
  }
  if (sql(s, "BEGIN IMMEDIATE;") != 0) return -1;
  if (edr_context_writer_open(s, &writer) != 0) goto rollback;
  if (prepare(s, &read, "SELECT artifact_id,candidate_id,fact_id,candidate_id_json,created_ns,upload_status,minio_key "
                        "FROM candidate_context_refs ORDER BY rowid LIMIT 1;") != 0) goto done;
  for (unsigned i = 0; i < limit; ++i) {
    int rc = sqlite3_step(read);
    if (rc == SQLITE_DONE) { *complete = 1; break; }
    if (rc != SQLITE_ROW) { fail(s, "read migration reference failed"); goto done; }
    char *v[6] = {0};
    const int columns[] = {0, 1, 2, 3, 5, 6};
    int allocated = 1;
    for (unsigned j = 0; j < 6; ++j) {
      if (sqlite3_column_type(read, columns[j]) != SQLITE_NULL) {
        const char *value = (const char *)sqlite3_column_text(read, columns[j]);
        if (sqlite3_column_type(read, columns[j]) != SQLITE_TEXT || !value ||
            strlen(value) != (size_t)sqlite3_column_bytes(read, columns[j])) allocated = 0;
        v[j] = sqlite3_mprintf("%s", sqlite3_column_text(read, columns[j]));
        if (!v[j]) allocated = 0;
      }
    }
    sqlite3_int64 created = sqlite3_column_int64(read, 4);
    int created_null = sqlite3_column_type(read, 4) == SQLITE_NULL;
    if (!created_null && sqlite3_column_type(read, 4) != SQLITE_INTEGER) allocated = 0;
    reset(read);
    rc = allocated ? edr_context_writer_put(&writer, v[0], v[1], v[2], v[3], created, created_null, v[4], v[5]) : -1;
    for (unsigned j = 0; j < 6; ++j) sqlite3_free(v[j]);
    if (rc != 0) { if (!allocated) snprintf(s->error, sizeof(s->error), "migration row has invalid storage type, text encoding or allocation failed"); goto done; }
    ++*moved;
  }
  sqlite3_finalize(read); read = NULL;
  edr_context_writer_close(&writer);
  if (*complete && sql(s, "PRAGMA user_version=2;") != 0) goto rollback;
  if (sql(s, "COMMIT;") != 0) goto rollback;
  if (*complete) s->format = 2;
  return 0;
done:
  sqlite3_finalize(read);
  edr_context_writer_close(&writer);
rollback:
  sqlite3_exec(s->db, "ROLLBACK", NULL, NULL, NULL);
  *moved = 0; *complete = 0;
  return -1;
}

int edr_context_store_collect_facts(EdrContextStore *s, unsigned *removed) {
  *removed = 0;
  if (s->format && sql(s, "DELETE FROM context_fact_keys WHERE NOT EXISTS (SELECT 1 FROM compact_context_refs r "
                         "WHERE r.fact_key=context_fact_keys.id);") != 0) return -1;
  const char *query = s->format ?
    "DELETE FROM context_facts WHERE NOT EXISTS (SELECT 1 FROM candidate_context_refs r WHERE r.fact_id=context_facts.fact_id) "
    "AND NOT EXISTS(SELECT 1 FROM context_fact_keys k WHERE k.fact_id=context_facts.fact_id);"
    : "DELETE FROM context_facts WHERE NOT EXISTS (SELECT 1 FROM candidate_context_refs r WHERE r.fact_id=context_facts.fact_id);";
  if (sql(s, query) != 0) return -1;
  *removed = (unsigned)sqlite3_changes(s->db);
  if (s->format && sql(s, "DELETE FROM context_candidates WHERE NOT EXISTS (SELECT 1 FROM compact_context_refs r "
                         "WHERE r.candidate_key=context_candidates.id);") != 0) return -1;
  return 0;
}

int edr_context_store_expire(EdrContextStore *s, sqlite3_int64 cutoff, unsigned *removed) {
  sqlite3_stmt *st = NULL; *removed = 0;
  if (!s->format) return 0; /* legacy expiration remains owned by the existing loop */
  if (prepare(s, &st, "DELETE FROM compact_context_refs WHERE created_ns<?") != 0) return -1;
  sqlite3_bind_int64(st, 1, cutoff);
  int rc = sqlite3_step(st); sqlite3_finalize(st);
  if (rc != SQLITE_DONE) return fail(s, "expire compact context references failed");
  *removed = (unsigned)sqlite3_changes(s->db); return 0;
}

int edr_context_store_evict(EdrContextStore *s, int orphans, unsigned limit, unsigned *removed) {
  *removed = 0;
  if (!s->format || !limit || limit > 4096) return -1;
  if (sql(s, "BEGIN IMMEDIATE;CREATE TEMP TABLE IF NOT EXISTS context_reclaim(kind INTEGER,id INTEGER);"
             "DELETE FROM context_reclaim;") != 0) goto rollback;
  const char *orphan_query =
    "INSERT INTO context_reclaim SELECT kind,id FROM ("
    "SELECT 0 kind,r.rowid id,r.created_ns stamp FROM candidate_context_refs r "
    "WHERE NOT EXISTS(SELECT 1 FROM p0_candidates p WHERE p.candidate_id=r.candidate_id) UNION ALL "
    "SELECT 1,r.id,r.created_ns FROM compact_context_refs r WHERE candidate_key IN ("
    "SELECT c.id FROM context_candidates c WHERE NOT EXISTS(SELECT 1 FROM p0_candidates p WHERE p.candidate_id=c.candidate_id))) "
    "ORDER BY stamp,kind,id LIMIT ?;";
  const char *oldest_query =
    "INSERT INTO context_reclaim SELECT kind,id FROM ("
    "SELECT 0 kind,rowid id,created_ns stamp FROM candidate_context_refs UNION ALL "
    "SELECT 1,id,created_ns FROM compact_context_refs) ORDER BY stamp,kind,id LIMIT ?;";
  sqlite3_stmt *st = NULL;
  if (prepare(s, &st, orphans ? orphan_query : oldest_query) != 0) goto rollback;
  sqlite3_bind_int(st, 1, (int)limit); int rc = sqlite3_step(st); sqlite3_finalize(st);
  if (rc != SQLITE_DONE) { fail(s, "select context reclaim failed"); goto rollback; }
  if (sql(s, "DELETE FROM candidate_context_refs WHERE rowid IN (SELECT id FROM context_reclaim WHERE kind=0)") != 0) goto rollback;
  unsigned count = (unsigned)sqlite3_changes(s->db);
  if (sql(s, "DELETE FROM compact_context_refs WHERE id IN (SELECT id FROM context_reclaim WHERE kind=1)") != 0) goto rollback;
  count += (unsigned)sqlite3_changes(s->db);
  if (sql(s, "DELETE FROM context_reclaim;COMMIT;") != 0) goto rollback;
  *removed = count; return 0;
rollback:
  sqlite3_exec(s->db, "ROLLBACK", NULL, NULL, NULL); return -1;
}

#endif
