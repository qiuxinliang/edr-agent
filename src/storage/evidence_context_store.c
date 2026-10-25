#if defined(EDR_HAVE_SQLITE)
#include "evidence_context_store.h"
#include "cJSON.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(EdrContextStore *s, const char *operation) {
  s->sqlite_error_code = sqlite3_extended_errcode(s->db);
  snprintf(s->error, sizeof(s->error), "%s: sqlite=%d %s", operation,
           s->sqlite_error_code, sqlite3_errmsg(s->db));
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
  if (v < 0 || v > 5) {
    snprintf(s->error, sizeof(s->error), "unsupported evidence cache format %d", v);
    return -1;
  }
  if (v >= 3) {
    /* An unsupported reader rejects user_version before replacing views.
     * Never interpret an arbitrary future/corrupt marker as a supported store. */
    int valid = 0;
    if (prepare(s, &st, "SELECT 1 FROM context_retirement_progress r JOIN p0_candidates p "
        "ON p.candidate_id=r.candidate_id WHERE r.phase=2 AND p.retention_policy_version=1 "
        "AND p.local_retention_state='retirement_eligible' LIMIT 1;") == 0)
      valid = sqlite3_step(st) == SQLITE_ROW;
    sqlite3_finalize(st);
    if (!valid) {
      snprintf(s->error,sizeof(s->error),"unsupported evidence cache retirement fence %d",v);
      return -1;
    }
    v -= 3;
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

/* SQLite retains CREATE text without its final semicolon. Exact byte matching
 * is intentional: a same-name old or damaged guard is never accepted merely
 * because it exists. The caller supplies only its authoritative SQL constant.
 * SAVEPOINT also makes a standalone replacement atomic on CREATE failure. */
int edr_context_store_ensure_schema_object(EdrContextStore *s, const char *kind,
                                      const char *name,
                                      const char *create_sql) {
  sqlite3_stmt *st = NULL; char *drop = NULL; int result = -1, matches = 0;
  if (!s || !s->db || !name || !create_sql || !kind ||
      (strcmp(kind,"trigger") && strcmp(kind,"view"))) return -1;
  if (sql(s, "SAVEPOINT startup_schema_object;") != 0) return -1;
  if (prepare(s, &st, "SELECT sql FROM main.sqlite_schema WHERE type=?1 AND name=?2;") != 0 ||
      sqlite3_bind_text(st, 1, kind, -1, SQLITE_STATIC) != SQLITE_OK ||
      sqlite3_bind_text(st, 2, name, -1, SQLITE_STATIC) != SQLITE_OK) goto done;
  int step = sqlite3_step(st);
  if (step == SQLITE_ROW) {
    size_t expected = strlen(create_sql);
    if (expected && create_sql[expected - 1u] == ';') --expected;
    const char *stored = (const char *)sqlite3_column_text(st, 0);
    int bytes = sqlite3_column_bytes(st, 0);
    matches = sqlite3_column_type(st, 0) == SQLITE_TEXT && stored && bytes >= 0 &&
        (size_t)bytes == expected && !memcmp(stored, create_sql, expected);
    if (sqlite3_step(st) != SQLITE_DONE) { fail(s, "read schema definition failed"); goto done; }
  } else if (step != SQLITE_DONE) { fail(s, "read schema definition failed"); goto done; }
  sqlite3_finalize(st); st = NULL;
  if (!matches) {
    drop = sqlite3_mprintf("DROP %s IF EXISTS \"%w\";", kind, name);
    if (!drop) { snprintf(s->error,sizeof(s->error),"allocate schema replacement failed"); goto done; }
    if (sql(s, drop) != 0 || sql(s, create_sql) != 0) goto done;
  }
  if (sql(s, "RELEASE startup_schema_object;") != 0) goto done;
  result = 0;
done:
  sqlite3_finalize(st); sqlite3_free(drop);
  if (result) {
    /* A quota/FULL error may have rolled back the whole SQLite transaction.
     * Never replace the original failure with a missing-savepoint diagnostic. */
    (void)sqlite3_exec(s->db,"ROLLBACK TO startup_schema_object;RELEASE startup_schema_object;",NULL,NULL,NULL);
  }
  return result;
}

static int views(EdrContextStore *s) {
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
  if (edr_context_store_ensure_schema_object(s,"view","context_reference_projection",projection) != 0) return -1;
  return edr_context_store_ensure_schema_object(s,"view","materialized_artifacts",
      "CREATE VIEW materialized_artifacts AS "
      "SELECT artifact_id,endpoint_id,tenant_id,candidate_id,artifact_type,path,sha256,"
      "manifest_json,created_ns,upload_status,minio_key FROM artifacts a "
      "WHERE NOT EXISTS(SELECT 1 FROM p0_candidates p WHERE p.candidate_id=a.candidate_id AND p.local_retention_state='retirement_eligible') "
      "AND (a.artifact_type<>'post_context' OR NOT EXISTS ("
      "SELECT 1 FROM context_reference_projection r WHERE r.artifact_id=a.artifact_id)) "
      "UNION ALL SELECT r.artifact_id,f.endpoint_id,f.tenant_id,r.candidate_id,'post_context','','',"
      "replace(f.manifest_template_json,'\"candidate_id\":null','\"candidate_id\":'||r.candidate_id_json),"
      "CASE WHEN f.updated_ns>r.created_ns THEN f.updated_ns ELSE r.created_ns END,"
      "r.upload_status,r.minio_key FROM context_reference_projection r "
      "JOIN context_facts f ON f.fact_id=r.fact_id WHERE NOT EXISTS(SELECT 1 FROM p0_candidates p "
      "WHERE p.candidate_id=r.candidate_id AND p.local_retention_state='retirement_eligible');");
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

/* At most one small progress row per existing policy owner; no payloads or
 * tombstones. Validation cursors are disposable, physical-drain intent is not.
 * Replays, delivery changes and scope changes invalidate proof before deletion.
 * Once logically retired, a candidate cannot acquire a new delivery/reference.
 * Shared fact payload updates remain legal: their scope and references, rather
 * than payload age, determine whether the fact can be physically removed. */
static int retirement_progress_schema(EdrContextStore *s) {
  if (sql(s,
      "CREATE TABLE IF NOT EXISTS context_retirement_progress("
      "candidate_id TEXT PRIMARY KEY REFERENCES p0_candidates(candidate_id) ON DELETE CASCADE,"
      "phase INTEGER NOT NULL CHECK(phase BETWEEN 0 AND 2),reason INTEGER NOT NULL CHECK(reason IN(0,1)),"
      "legacy_cursor TEXT NOT NULL DEFAULT '',compact_cursor INTEGER NOT NULL DEFAULT 0 CHECK(compact_cursor>=0));"
      "CREATE INDEX IF NOT EXISTS idx_context_retirement_phase ON context_retirement_progress(phase);"
      "CREATE TRIGGER IF NOT EXISTS retirement_progress_candidate_write BEFORE UPDATE ON p0_candidates "
      "WHEN OLD.local_retention_state='retirement_eligible' "
      "BEGIN SELECT RAISE(ABORT,'candidate retirement in progress'); END;"
      "CREATE TRIGGER IF NOT EXISTS retirement_progress_candidate_invalidate AFTER UPDATE ON p0_candidates "
      "BEGIN DELETE FROM context_retirement_progress WHERE candidate_id=OLD.candidate_id AND phase<2; END;"
      "CREATE TRIGGER IF NOT EXISTS retirement_progress_fact_scope BEFORE UPDATE OF fact_id,endpoint_id,tenant_id ON context_facts "
      "WHEN (NEW.fact_id IS NOT OLD.fact_id OR NEW.endpoint_id IS NOT OLD.endpoint_id OR NEW.tenant_id IS NOT OLD.tenant_id) "
      "AND EXISTS(SELECT 1 FROM context_reference_projection r JOIN context_retirement_progress p ON p.candidate_id=r.candidate_id "
      "WHERE r.fact_id=OLD.fact_id AND p.phase=2) "
      "BEGIN SELECT RAISE(ABORT,'retiring context fact scope is immutable'); END;"
      "CREATE TRIGGER IF NOT EXISTS retirement_progress_fact_invalidate AFTER UPDATE OF fact_id,endpoint_id,tenant_id ON context_facts "
      "WHEN NEW.fact_id IS NOT OLD.fact_id OR NEW.endpoint_id IS NOT OLD.endpoint_id OR NEW.tenant_id IS NOT OLD.tenant_id "
      "BEGIN DELETE FROM context_retirement_progress WHERE phase<2 AND candidate_id IN("
      "SELECT candidate_id FROM context_reference_projection WHERE fact_id=OLD.fact_id OR fact_id=NEW.fact_id); END;") != 0) return -1;
  static const struct { const char *table, *owner; } tables[] = {
    {"artifacts", "%s.candidate_id"},
    {"candidate_context_refs", "%s.candidate_id"},
    {"context_candidates", "%s.candidate_id"},
    {"compact_context_refs", "(SELECT candidate_id FROM context_candidates WHERE id=%s.candidate_key)"}
  };
  for (unsigned i=0; i<(s->format ? 4u : 2u); ++i) {
    char *old=sqlite3_mprintf(tables[i].owner,"OLD"), *fresh=sqlite3_mprintf(tables[i].owner,"NEW");
    if (!old || !fresh) { sqlite3_free(old); sqlite3_free(fresh); return -1; }
    for (unsigned op=0; op<3; ++op) {
      const char *event=op==0 ? "INSERT" : op==1 ? "UPDATE" : "DELETE";
      char *statement=sqlite3_mprintf(
          "CREATE TRIGGER IF NOT EXISTS retirement_progress_%s_%s AFTER %s ON %s "
          "BEGIN DELETE FROM context_retirement_progress WHERE phase<2 AND (candidate_id=%s OR candidate_id=%s); END;",
          tables[i].table,event,event,tables[i].table,op==0 ? fresh : old,op==2 ? old : fresh);
      int rc=statement ? sql(s,statement) : -1; sqlite3_free(statement);
      if (!rc && op<2) {
        statement=sqlite3_mprintf(
          "CREATE TRIGGER IF NOT EXISTS retirement_freeze_%s_%s BEFORE %s ON %s "
          "WHEN EXISTS(SELECT 1 FROM p0_candidates WHERE local_retention_state='retirement_eligible' "
          "AND (candidate_id=%s OR candidate_id=%s)) "
          "BEGIN SELECT RAISE(ABORT,'candidate retirement in progress'); END;",
          tables[i].table,event,event,tables[i].table,op==0 ? fresh : old,fresh);
        rc=statement ? sql(s,statement) : -1; sqlite3_free(statement);
      }
      if (rc) { sqlite3_free(old); sqlite3_free(fresh); return -1; }
    }
    sqlite3_free(old); sqlite3_free(fresh);
  }
  if (s->format && sql(s,
      "CREATE TRIGGER IF NOT EXISTS retirement_progress_fact_key_update BEFORE UPDATE ON context_fact_keys "
      "WHEN EXISTS(SELECT 1 FROM compact_context_refs r JOIN context_candidates c ON c.id=r.candidate_key "
      "JOIN context_retirement_progress p ON p.candidate_id=c.candidate_id WHERE r.fact_key=OLD.id AND p.phase=2) "
      "BEGIN SELECT RAISE(ABORT,'retiring fact dictionary is immutable'); END;"
      "CREATE TRIGGER IF NOT EXISTS retirement_progress_fact_key_invalidate AFTER UPDATE ON context_fact_keys "
      "BEGIN DELETE FROM context_retirement_progress WHERE phase<2 AND candidate_id IN(SELECT c.candidate_id "
      "FROM compact_context_refs r JOIN context_candidates c ON c.id=r.candidate_key WHERE r.fact_key IN(OLD.id,NEW.id)); END;")!=0) return -1;
  return 0;
}

int edr_context_store_retirement_schema_pages(EdrContextStore *s,
    uint64_t pages, uint64_t page_size, uint64_t *required) {
  sqlite3 *model = NULL; sqlite3_stmt *objects = NULL, *existing = NULL;
  int result = -1, step;
  if (!s || !s->db || !required || page_size < 512 || page_size > 65536 || pages > UINT32_MAX) return -1;
  *required = 0;
  /* Render the SAME DDL into a bounded, empty private catalog. The placeholders
   * have no endpoint data and only satisfy CREATE TRIGGER's table lookup.
   * This is neither a copy of the evidence DB nor a speculative new schema. */
  if (sqlite3_open(":memory:",&model) != SQLITE_OK) goto done;
  EdrContextStore probe = {0}; probe.db=model; probe.format=s->format;
  if (sql(&probe,"PRAGMA max_page_count=64;"
      "CREATE TABLE p0_candidates(candidate_id TEXT);CREATE TABLE artifacts(candidate_id TEXT);"
      "CREATE TABLE context_facts(fact_id TEXT);CREATE TABLE candidate_context_refs(candidate_id TEXT);"
      "CREATE TABLE context_candidates(id INTEGER,candidate_id TEXT);"
      "CREATE TABLE compact_context_refs(candidate_key INTEGER,fact_key INTEGER);"
      "CREATE TABLE context_fact_keys(id INTEGER);") || retirement_progress_schema(&probe)) goto done;
  if (sqlite3_prepare_v2(model,"SELECT type,name,sql,rootpage FROM sqlite_master WHERE "
      "type='trigger' OR tbl_name='context_retirement_progress';",-1,&objects,NULL)!=SQLITE_OK ||
      prepare(s,&existing,"SELECT type,sql FROM sqlite_master WHERE name=?1;")!=0) goto done;
  /* A rowid catalog branch has at least two children. Charging a whole split
   * path per new object deliberately overestimates normal packed catalogs;
   * do not infer free space inside already occupied catalog pages. Add a leaf
   * and overflow allowance for the literal DDL/record header and actual roots.
   * This admission bound is conservative, not a promise against later IO/busy. */
  uint64_t depth=1;
  for (uint64_t n=pages; n>1; n=(n+1)/2) ++depth;
  /* Maximum reserved region (255), database header (100), B-tree header and
   * cell-pointer allowance (16). Per-record headers are charged below. */
  uint64_t usable=page_size-255u-100u-16u;
  while ((step=sqlite3_step(objects))==SQLITE_ROW) {
    reset(existing);
    if (sqlite3_bind_value(existing,1,sqlite3_column_value(objects,1))!=SQLITE_OK) goto done;
    int found=sqlite3_step(existing);
    if (found==SQLITE_ROW) {
      const char *kind=(const char *)sqlite3_column_text(objects,0);
      const char *old_kind=(const char *)sqlite3_column_text(existing,0);
      int a=sqlite3_column_bytes(objects,2), b=sqlite3_column_bytes(existing,1);
      if (!kind || !old_kind || strcmp(kind,old_kind) || a!=b ||
          sqlite3_column_type(objects,2)!=sqlite3_column_type(existing,1) ||
          (a && memcmp(sqlite3_column_text(objects,2),sqlite3_column_text(existing,1),(size_t)a))) goto done;
      continue;
    }
    if (found!=SQLITE_DONE) goto done;
    uint64_t bytes=(uint64_t)sqlite3_column_bytes(objects,2)+
                   (uint64_t)sqlite3_column_bytes(objects,1)*2u+128u;
    *required += depth+1u+(bytes+usable-1u)/usable+
                 (sqlite3_column_int64(objects,3)>0 ? 1u : 0u);
  }
  if (step==SQLITE_DONE) result=0;
done:
  sqlite3_finalize(objects); sqlite3_finalize(existing); if(model)sqlite3_close(model);
  return result;
}

int edr_context_store_sync_retirement_fence(EdrContextStore *s) {
  sqlite3_stmt *st=NULL; int pending=-1;
  if (!s || sqlite3_get_autocommit(s->db)) return -1;
  if (prepare(s,&st,"SELECT 1 FROM context_retirement_progress WHERE phase=2 LIMIT 1;")==0) {
    int rc=sqlite3_step(st);
    if (rc==SQLITE_ROW || rc==SQLITE_DONE) pending=rc==SQLITE_ROW;
  }
  sqlite3_finalize(st); if(pending<0)return -1;
  st=NULL; int current=-1;
  if (prepare(s,&st,"PRAGMA user_version;")==0 && sqlite3_step(st)==SQLITE_ROW)
    current=sqlite3_column_int(st,0);
  sqlite3_finalize(st); if(current<0)return -1;
  if (current==s->format+(pending ? 3 : 0)) return 0;
  char statement[64];
  snprintf(statement,sizeof(statement),"PRAGMA user_version=%d;",s->format+(pending ? 3 : 0));
  return sql(s,statement);
}

static int set_layout_version(EdrContextStore *s, int layout) {
  sqlite3_stmt *st=NULL; int raw=-1;
  if (prepare(s,&st,"PRAGMA user_version;")==0 && sqlite3_step(st)==SQLITE_ROW)
    raw=sqlite3_column_int(st,0);
  sqlite3_finalize(st); if(raw<0 || raw>5)return -1;
  char statement[64];
  snprintf(statement,sizeof(statement),"PRAGMA user_version=%d;",layout+(raw>=3 ? 3 : 0));
  return sql(s,statement);
}

int edr_context_store_install_retention_guards(EdrContextStore *s) {
  if (retirement_progress_schema(s) != 0) return -1;
  if (sql(s,
      "CREATE TRIGGER IF NOT EXISTS candidate_retention_delete BEFORE DELETE ON p0_candidates "
      "WHEN NOT(OLD.retention_policy_version=1 AND OLD.local_retention_state='retirement_eligible') "
      "OR EXISTS(SELECT 1 FROM context_reference_projection WHERE candidate_id=OLD.candidate_id) "
      "BEGIN SELECT RAISE(ABORT,'candidate retirement owner required'); END;"
      "CREATE TRIGGER IF NOT EXISTS candidate_artifact_retention_delete BEFORE DELETE ON artifacts "
      "WHEN (EXISTS(SELECT 1 FROM p0_candidates p WHERE p.candidate_id=OLD.candidate_id AND p.local_retention_state!='retirement_eligible') "
      "AND NOT(OLD.artifact_type='post_context' AND EXISTS(SELECT 1 FROM context_reference_projection r JOIN context_facts f ON f.fact_id=r.fact_id "
      "WHERE r.artifact_id=OLD.artifact_id AND r.candidate_id=OLD.candidate_id AND f.endpoint_id IS OLD.endpoint_id AND f.tenant_id IS OLD.tenant_id "
      "AND replace(f.manifest_template_json,'\"candidate_id\":null','\"candidate_id\":'||r.candidate_id_json) IS OLD.manifest_json))) "
      "OR (OLD.artifact_type='process_command_line' AND EXISTS(SELECT 1 FROM p0_candidates p WHERE p.subject_command_fact_id=OLD.artifact_id OR p.parent_command_fact_id=OLD.artifact_id)) "
      "BEGIN SELECT RAISE(ABORT,'retained candidate artifact dependency'); END;"
      "CREATE TRIGGER IF NOT EXISTS context_fact_retention_delete BEFORE DELETE ON context_facts "
      "WHEN EXISTS(SELECT 1 FROM context_reference_projection WHERE fact_id=OLD.fact_id) "
      "BEGIN SELECT RAISE(ABORT,'referenced context fact'); END;") != 0) return -1;
  /* A migration first writes the exact replacement in the compact layout.
   * The old row then has two identical projected identities in one transaction.
   * No migration or old maintenance can remove the final retained reference. */
  if (edr_context_store_ensure_schema_object(s,"trigger","context_legacy_ref_retention_delete",s->format ?
      "CREATE TRIGGER context_legacy_ref_retention_delete BEFORE DELETE ON candidate_context_refs "
      "WHEN EXISTS(SELECT 1 FROM p0_candidates WHERE candidate_id=OLD.candidate_id AND local_retention_state!='retirement_eligible') "
      "AND NOT EXISTS(SELECT 1 FROM compact_context_refs r JOIN context_candidates c ON c.id=r.candidate_key JOIN context_fact_keys f ON f.id=r.fact_key "
      "WHERE c.candidate_id=OLD.candidate_id AND f.fact_id=OLD.fact_id AND COALESCE(r.artifact_override,c.candidate_id||':post_context:'||lower(hex(r.source_identity)))=OLD.artifact_id "
      "AND COALESCE(r.candidate_json_override,c.candidate_id_json) IS OLD.candidate_id_json AND r.created_ns IS OLD.created_ns AND r.upload_status IS OLD.upload_status AND r.minio_key IS OLD.minio_key) "
      "BEGIN SELECT RAISE(ABORT,'retained candidate context reference'); END;" :
      "CREATE TRIGGER context_legacy_ref_retention_delete BEFORE DELETE ON candidate_context_refs "
      "WHEN EXISTS(SELECT 1 FROM p0_candidates WHERE candidate_id=OLD.candidate_id AND local_retention_state!='retirement_eligible') "
      "BEGIN SELECT RAISE(ABORT,'retained candidate context reference'); END;") != 0) return -1;
  if (!s->format) return 0;
  return sql(s,
      "CREATE TRIGGER IF NOT EXISTS context_compact_ref_retention_delete BEFORE DELETE ON compact_context_refs "
      "WHEN EXISTS(SELECT 1 FROM context_candidates c JOIN p0_candidates p ON p.candidate_id=c.candidate_id WHERE c.id=OLD.candidate_key AND p.local_retention_state!='retirement_eligible') "
      "BEGIN SELECT RAISE(ABORT,'retained candidate compact reference'); END;"
      "CREATE TRIGGER IF NOT EXISTS context_fact_key_retention_delete BEFORE DELETE ON context_fact_keys "
      "WHEN EXISTS(SELECT 1 FROM compact_context_refs WHERE fact_key=OLD.id) "
      "BEGIN SELECT RAISE(ABORT,'referenced context fact key'); END;"
      "CREATE TRIGGER IF NOT EXISTS context_candidate_key_retention_delete BEFORE DELETE ON context_candidates "
      "WHEN EXISTS(SELECT 1 FROM compact_context_refs WHERE candidate_key=OLD.id) "
      "BEGIN SELECT RAISE(ABORT,'referenced context candidate key'); END;");
}

int edr_context_store_begin_upgrade(EdrContextStore *s) {
  s->sqlite_error_code = SQLITE_OK;
  if (s->format) return 0;
  if (sql(s, "BEGIN IMMEDIATE;") != 0) return -1;
  if (sql(s, compact_schema) != 0) goto rollback;
  s->format = 1;
  if (views(s) != 0) goto rollback;
  sqlite3_stmt *guard=NULL;
  if (prepare(s,&guard,"SELECT 1 FROM sqlite_master WHERE type='trigger' AND name='candidate_retention_delete';") != 0) goto rollback;
  int guarded=sqlite3_step(guard)==SQLITE_ROW; sqlite3_finalize(guard);
  if ((guarded && edr_context_store_install_retention_guards(s)!=0) ||
      set_layout_version(s,1)!=0 || sql(s,"COMMIT;")!=0) goto rollback;
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
      "SELECT c.candidate_id,f.fact_id,r.created_ns,1 FROM compact_context_refs r "
      "JOIN context_candidates c ON c.id=r.candidate_key JOIN context_fact_keys f ON f.id=r.fact_key "
      "WHERE r.candidate_key=(SELECT id FROM context_candidates WHERE candidate_id=?1) AND r.source_identity=?2 "
      "UNION ALL SELECT c.candidate_id,f.fact_id,r.created_ns,1 FROM compact_context_refs r "
      "JOIN context_candidates c ON c.id=r.candidate_key JOIN context_fact_keys f ON f.id=r.fact_key "
      "WHERE r.artifact_override=?3 "
      "UNION ALL SELECT candidate_id,fact_id,created_ns,0 FROM candidate_context_refs WHERE artifact_id=?3;"
      : "SELECT candidate_id,fact_id,created_ns,0 FROM candidate_context_refs WHERE artifact_id=?3;";
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
  sqlite3_finalize(w->legacy_insert);
  memset(w, 0, sizeof(*w));
}

static const char legacy_ref_upsert[] =
    "INSERT INTO candidate_context_refs(artifact_id,candidate_id,fact_id,candidate_id_json,created_ns,upload_status,minio_key) "
    "VALUES(?1,?2,?3,?4,?5,?6,?7) ON CONFLICT(artifact_id) DO UPDATE SET "
    "candidate_id=excluded.candidate_id,fact_id=excluded.fact_id,candidate_id_json=excluded.candidate_id_json,"
    "created_ns=excluded.created_ns,upload_status=excluded.upload_status,minio_key=excluded.minio_key;";

int edr_context_writer_open(EdrContextStore *s, EdrContextWriter *w,
                            int migrate_existing) {
  memset(w, 0, sizeof(*w)); w->store = s;
  if (migrate_existing != 0 && migrate_existing != 1) {
    snprintf(s->error, sizeof(s->error), "context writer migration mode invalid"); return -1;
  }
  w->migrate_existing = migrate_existing;
  if (!s->format) {
    return prepare(s, &w->ref_insert, legacy_ref_upsert);
  }
  if (prepare(s, &w->candidate_find, "SELECT id,candidate_id_json FROM context_candidates WHERE candidate_id=?") ||
      prepare(s, &w->candidate_insert, "INSERT INTO context_candidates(candidate_id,candidate_id_json) VALUES(?,?)") ||
      prepare(s, &w->fact_find, "SELECT id FROM context_fact_keys WHERE fact_id=?") ||
      prepare(s, &w->fact_number, "INSERT INTO context_fact_keys(fact_id) VALUES(?)") ||
      (migrate_existing && prepare(s, &w->old_delete, "DELETE FROM candidate_context_refs WHERE artifact_id=?")) ||
      (!migrate_existing && prepare(s, &w->legacy_insert, legacy_ref_upsert)) ||
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
  sqlite3_stmt *legacy = !s->format ? w->ref_insert : NULL;
  if (sqlite3_get_autocommit(s->db) || !artifact || !candidate || !fact || !candidate_json) {
    snprintf(s->error, sizeof(s->error), "context reference requires valid input and transaction"); return -1;
  }
  if (s->format) {
    sqlite3_stmt *lookup = w->lookup;
    if (edr_context_store_bind_lookup(s, lookup, artifact) != 0) return -1;
    int rc = sqlite3_step(lookup);
    if (rc == SQLITE_ROW) {
      const char *owner = (const char *)sqlite3_column_text(lookup, 0);
      if (!owner || strcmp(owner, candidate)) {
        snprintf(s->error, sizeof(s->error), "context artifact candidate conflict"); reset(lookup); return -1;
      }
      if (sqlite3_column_type(lookup, 3) != SQLITE_INTEGER ||
          (sqlite3_column_int(lookup, 3) != 0 && sqlite3_column_int(lookup, 3) != 1)) {
        snprintf(s->error, sizeof(s->error), "context reference layout invalid"); reset(lookup); return -1;
      }
      if (!w->migrate_existing && sqlite3_column_int(lookup, 3) == 0) legacy = w->legacy_insert;
      rc = sqlite3_step(lookup);
    }
    if (rc != SQLITE_DONE) { fail(s, "ambiguous context artifact identity"); reset(lookup); return -1; }
    reset(lookup);
  }
  if (legacy) {
    sqlite3_stmt *st = legacy; reset(st);
    if (text(st, 1, artifact) != SQLITE_OK || text(st, 2, candidate) != SQLITE_OK ||
        text(st, 3, fact) != SQLITE_OK || text(st, 4, candidate_json) != SQLITE_OK ||
        (created_null ? sqlite3_bind_null(st, 5) : sqlite3_bind_int64(st, 5, created)) != SQLITE_OK ||
        text(st, 6, upload) != SQLITE_OK || text(st, 7, key) != SQLITE_OK)
      return fail(s, "bind legacy context reference failed");
    if (sqlite3_step(st) == SQLITE_DONE) return 0;
    return fail(s, "write legacy context reference failed");
  }
  sqlite3_stmt *st;
  int rc;
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
  /* Only explicit migration moves an existing legacy row. */
  if (w->migrate_existing) {
    st = w->old_delete; reset(st);
    if (text(st, 1, artifact) != SQLITE_OK) return fail(s, "bind moved legacy reference failed");
    if (sqlite3_step(st) != SQLITE_DONE) return fail(s, "remove moved legacy reference failed");
  }
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
  if (edr_context_writer_open(s, &writer, 1) != 0) goto rollback;
  /* Follow the existing artifact primary-key index. Rowid order can scatter
   * each small batch across the wide artifact/candidate indexes, exhausting
   * the migration reserve and repeating work after rollback. Identity order
   * keeps related references together without a sort buffer or a new index. */
  if (prepare(s, &read, "SELECT artifact_id,candidate_id,fact_id,candidate_id_json,created_ns,upload_status,minio_key "
                        "FROM candidate_context_refs ORDER BY artifact_id LIMIT 1;") != 0) goto done;
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
  if (*complete && set_layout_version(s,2) != 0) goto rollback;
  /* Reuse the migration transaction for bounded reclamation. Separate FULL
   * vacuum commits and a second WAL checkpoint dominated small Windows
   * batches. Scaling reclamation with the validated row limit lets the
   * caller's reserve guard split and roll back the entire unit together. */
  char reclaim[64];
  snprintf(reclaim, sizeof(reclaim), "PRAGMA incremental_vacuum(%u);", limit);
  if (sql(s, reclaim) != 0) goto rollback;
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
  /* Select identities through the existing covering index before touching
   * fact rows. A direct DELETE scan reads pages containing the wide manifest
   * bodies even when every fact is still referenced. Rowids are used only
   * inside this statement; no persistent identity or deletion predicate changes. */
  const char *query = s->format ?
    "DELETE FROM context_facts WHERE rowid IN (SELECT f.rowid FROM context_facts f "
    "WHERE NOT EXISTS (SELECT 1 FROM candidate_context_refs r WHERE r.fact_id=f.fact_id) "
    "AND NOT EXISTS(SELECT 1 FROM context_fact_keys k WHERE k.fact_id=f.fact_id));"
    : "DELETE FROM context_facts WHERE rowid IN (SELECT f.rowid FROM context_facts f "
      "WHERE NOT EXISTS (SELECT 1 FROM candidate_context_refs r WHERE r.fact_id=f.fact_id));";
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

int edr_context_store_evict(EdrContextStore *s, int orphans, unsigned limit,
                            unsigned *removed, unsigned *facts_removed) {
  *removed = 0; *facts_removed = 0;
  if (!limit || limit > 4096) return -1;
  if (sql(s, "BEGIN IMMEDIATE;CREATE TEMP TABLE IF NOT EXISTS context_reclaim("
             "kind INTEGER,id INTEGER,fact_id TEXT,candidate_key INTEGER);"
             "DELETE FROM context_reclaim;") != 0) goto rollback;
  const char *orphan_query =
    "INSERT INTO context_reclaim(kind,id) SELECT kind,id FROM ("
    "SELECT 0 kind,r.rowid id,r.created_ns stamp FROM candidate_context_refs r "
    "WHERE NOT EXISTS(SELECT 1 FROM p0_candidates p WHERE p.candidate_id=r.candidate_id) UNION ALL "
    "SELECT 1,r.id,r.created_ns FROM compact_context_refs r WHERE candidate_key IN ("
    "SELECT c.id FROM context_candidates c WHERE NOT EXISTS(SELECT 1 FROM p0_candidates p WHERE p.candidate_id=c.candidate_id))) "
    "ORDER BY stamp,kind,id LIMIT ?;";
  const char *oldest_query =
    "INSERT INTO context_reclaim(kind,id) SELECT kind,id FROM ("
    "SELECT 0 kind,rowid id,created_ns stamp FROM candidate_context_refs UNION ALL "
    "SELECT 1,id,created_ns FROM compact_context_refs) ORDER BY stamp,kind,id LIMIT ?;";
  sqlite3_stmt *st = NULL;
  const char *query = orphans ? orphan_query : oldest_query;
  if (!s->format) {
    query = orphans
        ? "INSERT INTO context_reclaim(kind,id) SELECT 0,r.rowid FROM candidate_context_refs r "
          "WHERE NOT EXISTS(SELECT 1 FROM p0_candidates p WHERE p.candidate_id=r.candidate_id) "
          "ORDER BY r.created_ns,r.rowid LIMIT ?;"
        : "INSERT INTO context_reclaim(kind,id) SELECT 0,rowid FROM candidate_context_refs "
          "ORDER BY created_ns,rowid LIMIT ?;";
  }
  if (prepare(s, &st, query) != 0) goto rollback;
  sqlite3_bind_int(st, 1, (int)limit); int rc = sqlite3_step(st); sqlite3_finalize(st);
  if (rc != SQLITE_DONE) { fail(s, "select context reclaim failed"); goto rollback; }
  /* Resolve identities only for the selected batch, before unlinking it.
   * These identities never outlive this transaction or survive key reuse. */
  if (sql(s, "UPDATE context_reclaim SET fact_id=(SELECT r.fact_id FROM candidate_context_refs r "
             "WHERE r.rowid=context_reclaim.id) WHERE kind=0;") != 0) goto rollback;
  if (s->format && sql(s,
      "UPDATE context_reclaim SET (fact_id,candidate_key)=(SELECT f.fact_id,r.candidate_key "
      "FROM compact_context_refs r JOIN context_fact_keys f ON f.id=r.fact_key "
      "WHERE r.id=context_reclaim.id) WHERE kind=1;") != 0) goto rollback;
  if (prepare(s, &st, "SELECT COUNT(*) FROM context_reclaim WHERE fact_id IS NULL;") != 0) goto rollback;
  rc = sqlite3_step(st);
  int missing_identity = rc != SQLITE_ROW || sqlite3_column_int(st, 0) != 0;
  sqlite3_finalize(st);
  if (missing_identity) { fail(s, "context reclaim identity unavailable"); goto rollback; }
  if (sql(s, "DELETE FROM candidate_context_refs WHERE rowid IN (SELECT id FROM context_reclaim WHERE kind=0)") != 0) goto rollback;
  unsigned count = (unsigned)sqlite3_changes(s->db);
  if (s->format) {
    if (sql(s, "DELETE FROM compact_context_refs WHERE id IN (SELECT id FROM context_reclaim WHERE kind=1)") != 0) goto rollback;
    count += (unsigned)sqlite3_changes(s->db);
    if (sql(s, "DELETE FROM context_fact_keys WHERE fact_id IN (SELECT fact_id FROM context_reclaim) "
               "AND NOT EXISTS(SELECT 1 FROM compact_context_refs r WHERE r.fact_key=context_fact_keys.id);") != 0) goto rollback;
  }
  query = s->format
      ? "DELETE FROM context_facts WHERE fact_id IN (SELECT fact_id FROM context_reclaim) "
        "AND NOT EXISTS(SELECT 1 FROM candidate_context_refs r WHERE r.fact_id=context_facts.fact_id) "
        "AND NOT EXISTS(SELECT 1 FROM context_fact_keys k WHERE k.fact_id=context_facts.fact_id);"
      : "DELETE FROM context_facts WHERE fact_id IN (SELECT fact_id FROM context_reclaim) "
        "AND NOT EXISTS(SELECT 1 FROM candidate_context_refs r WHERE r.fact_id=context_facts.fact_id);";
  if (sql(s, query) != 0) goto rollback;
  unsigned fact_count = (unsigned)sqlite3_changes(s->db);
  if (s->format && sql(s,
      "DELETE FROM context_candidates WHERE id IN (SELECT candidate_key FROM context_reclaim) "
      "AND NOT EXISTS(SELECT 1 FROM compact_context_refs r WHERE r.candidate_key=context_candidates.id);") != 0) goto rollback;
  if (sql(s, "DELETE FROM context_reclaim;COMMIT;") != 0) goto rollback;
  *removed = count; *facts_removed = fact_count; return 0;
rollback:
  sqlite3_exec(s->db, "ROLLBACK", NULL, NULL, NULL); return -1;
}

static int retirement_error(EdrContextStore *s, const char *cause, int result) {
  snprintf(s->error, sizeof(s->error), "%s", cause);
  return result;
}

static int retirement_column(sqlite3_stmt *st, const char *name) {
  for (int i = 0; i < sqlite3_column_count(st); ++i)
    if (!strcmp(sqlite3_column_name(st, i), name)) return i;
  return -1;
}

/* Identity comparisons must not accept a matching prefix before an embedded
 * NUL, including databases originally created without modern constraints. */
static const char *retirement_text(sqlite3_stmt *st, int column) {
  if (column < 0 || sqlite3_column_type(st, column) != SQLITE_TEXT) return NULL;
  const char *value = (const char *)sqlite3_column_text(st, column);
  return value && (size_t)sqlite3_column_bytes(st, column) == strlen(value)
      ? value : NULL;
}

static int retirement_equal(sqlite3_stmt *st, const char *column, const char *value) {
  const char *actual = retirement_text(st, retirement_column(st, column));
  return actual && !strcmp(actual, value);
}

/* SELECTs below return original fields, plus a few bounded identity fields.
 * Counting the latter again intentionally overestimates the amount of work.
 * No SQLite page/index/WAL size is inferred from these literal byte counts. */
static int retirement_charge(sqlite3_stmt *st, unsigned *rows, uint64_t *bytes,
                              unsigned max_rows, uint64_t max_bytes) {
  if (*rows >= max_rows) return 1;
  ++*rows;
  uint64_t added = 0;
  for (int i = 0; i < sqlite3_column_count(st); ++i) {
    int type = sqlite3_column_type(st, i);
    uint64_t n = type == SQLITE_NULL ? 0u :
        type == SQLITE_INTEGER || type == SQLITE_FLOAT ? 8u :
        (uint64_t)sqlite3_column_bytes(st, i);
    if (n > max_bytes - added) { *bytes = max_bytes; return 1; }
    added += n;
  }
  if (added > max_bytes - *bytes) { *bytes = max_bytes; return 1; }
  *bytes += added;
  return 0;
}

static int retirement_json_identity(EdrContextStore *s, const char *json,
                                     const char *candidate) {
  /* cJSON strings are NUL-terminated. Do not let an encoded NUL make an
   * otherwise different identity compare equal to a valid prefix. */
  if (!json || strstr(json, "\\u0000"))
    return retirement_error(s, "retirement context candidate identity invalid", -1);
  cJSON *value = cJSON_ParseWithOpts(json, NULL, 1);
  int valid = cJSON_IsString(value) && value->valuestring &&
              !strcmp(value->valuestring, candidate);
  cJSON_Delete(value);
  return valid ? 0 : retirement_error(s, "retirement context candidate identity invalid", -1);
}

static int retirement_save_progress(EdrContextStore *s, const char *id, int phase, int pressure,
                                     const char *legacy, sqlite3_int64 compact) {
  sqlite3_stmt *st=NULL;
  if (prepare(s,&st,"INSERT INTO context_retirement_progress(candidate_id,phase,legacy_cursor,compact_cursor,reason) "
      "VALUES(?1,?2,?3,?4,?5) ON CONFLICT(candidate_id) DO UPDATE SET phase=excluded.phase,reason=excluded.reason,"
      "legacy_cursor=excluded.legacy_cursor,compact_cursor=excluded.compact_cursor;") != 0) return -1;
  int rc=text(st,1,id)==SQLITE_OK && sqlite3_bind_int(st,2,phase)==SQLITE_OK &&
      text(st,3,legacy)==SQLITE_OK && sqlite3_bind_int64(st,4,compact)==SQLITE_OK && sqlite3_bind_int(st,5,pressure!=0)==SQLITE_OK && sqlite3_step(st)==SQLITE_DONE;
  sqlite3_finalize(st);
  return rc ? 0 : fail(s,"save retirement progress failed");
}

/* Proof advances by indexed reference identity, with no deletion until both
 * layouts have been proved. Every intervening owner/reference mutation drops
 * that proof. Logical retirement and the phase-2 marker commit atomically;
 * readers then report unavailable, and frozen ownership prevents resurrection.
 * Each drain unit removes one edge and only its now-unreferenced fact/keys.
 * A deadline stops BETWEEN units, preserving committed progress on restart. */
int edr_context_store_retire_candidate(EdrContextStore *s,
                                       const char *candidate_id, int pressure,
                                       unsigned max_rows, uint64_t max_bytes,
                                       int (*yield_required)(void *), void *yield_context,
                                       EdrContextRetirement *out) {
  sqlite3_stmt *st=NULL, *ref=NULL;
  char *endpoint=NULL, *tenant=NULL, *bundle=NULL, *legacy=NULL;
  sqlite3_int64 candidate_rowid=0, bundle_rowid=0, candidate_key=0, cursor=0;
  unsigned rows=0; uint64_t bytes=0;
  int result=-1, rc, phase=0, saved=0;
  EdrContextRetirement counts={0};
  if (out) memset(out,0,sizeof(*out));
  if (!s || !s->db || !out || !candidate_id || !candidate_id[0] ||
      !max_rows || max_rows>4096u || !max_bytes || sqlite3_get_autocommit(s->db)) {
    if (s) retirement_error(s,"candidate retirement requires a bounded caller transaction",-1);
    return -1;
  }
  if (sql(s,"SAVEPOINT context_candidate_retirement;") != 0) return -1;
  bundle=sqlite3_mprintf("%s:p0_context_bundle:candidate",candidate_id);
  if (prepare(s,&st,"SELECT phase,legacy_cursor,compact_cursor,reason FROM context_retirement_progress WHERE candidate_id=?;") != 0) goto done;
  if (text(st,1,candidate_id)!=SQLITE_OK) goto storage_failed;
  rc=sqlite3_step(st);
  if (rc==SQLITE_ROW) {
    phase=sqlite3_column_int(st,0); cursor=sqlite3_column_int64(st,2);
    if (phase==2) pressure=sqlite3_column_int(st,3);
    const char *value=retirement_text(st,1);
    if (phase<0 || phase>2 || cursor<0 || !value) { retirement_error(s,"invalid retirement progress; evidence preserved",-1); goto done; }
    legacy=sqlite3_mprintf("%s",value); saved=1;
  } else if (rc==SQLITE_DONE) legacy=sqlite3_mprintf("");
  else goto storage_failed;
  sqlite3_finalize(st); st=NULL;
  if (!bundle || !legacy) { retirement_error(s,"retirement progress allocation failed",-1); goto done; }
  if (prepare(s, &st, "SELECT rowid,* FROM p0_candidates WHERE candidate_id=?;") != 0)
    goto done;
  if (text(st, 1, candidate_id) != SQLITE_OK || (rc = sqlite3_step(st)) != SQLITE_ROW) {
    if (sqlite3_errcode(s->db) != SQLITE_OK && sqlite3_errcode(s->db) != SQLITE_DONE)
      fail(s, "read retirement candidate failed");
    else retirement_error(s, "retirement candidate identity unavailable", -1);
    goto done;
  }
  if (retirement_charge(st, &rows, &bytes, max_rows, max_bytes)) goto unfinished;
  int policy = retirement_column(st, "retention_policy_version");
  if (policy < 0 || sqlite3_column_type(st, policy) != SQLITE_INTEGER ||
      sqlite3_column_int64(st, policy) != 1 ||
      !retirement_equal(st, "local_retention_state", phase==2 ? "retirement_eligible" : "retained")) {
    result = retirement_error(s, "candidate retention policy protects this group", 1);
    goto done;
  }
  const char *scope = retirement_text(st, retirement_column(st, "endpoint_id"));
  const char *owner = retirement_text(st, retirement_column(st, "tenant_id"));
  if (!scope || !scope[0] || !owner || !owner[0]) {
    result = retirement_error(s, "candidate retirement scope is unclassified", 1);
    goto done;
  }
  endpoint = sqlite3_mprintf("%s", scope);
  tenant = sqlite3_mprintf("%s", owner);
  candidate_rowid = sqlite3_column_int64(st, 0);
  if (!endpoint || !tenant) {
    retirement_error(s, "candidate retirement scope allocation failed", -1);
    goto done;
  }
  sqlite3_finalize(st); st = NULL;

  if (prepare(s, &st, "SELECT rowid,* FROM artifacts WHERE candidate_id=? LIMIT 2;") != 0)
    goto done;
  if (text(st, 1, candidate_id) != SQLITE_OK) { fail(s, "bind retirement artifact failed"); goto done; }
  unsigned bundles = 0;
  while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
    if (yield_required && yield_required(yield_context)) { goto unfinished; }
    if (retirement_charge(st, &rows, &bytes, max_rows, max_bytes)) goto unfinished;
    if (!retirement_equal(st, "artifact_type", "p0_context_bundle") ||
        !retirement_equal(st, "artifact_id", bundle) ||
        !retirement_equal(st, "upload_status", "local_manifest") ||
        !retirement_equal(st, "minio_key", "") ||
        !retirement_equal(st, "endpoint_id", endpoint) ||
        !retirement_equal(st, "tenant_id", tenant)) {
      result = retirement_error(s, "candidate artifact owner or delivery state is protected", 1);
      goto done;
    }
    if (++bundles != 1u) {
      retirement_error(s, "retirement candidate bundle identity ambiguous", -1);
      goto done;
    }
    bundle_rowid = sqlite3_column_int64(st, 0);
  }
  if (rc != SQLITE_DONE) { fail(s, "read retirement artifacts failed"); goto done; }
  if (bundles != 1u) {
    retirement_error(s, "retirement candidate bundle unavailable", -1);
    goto done;
  }
  sqlite3_finalize(st); st = NULL;

  if (s->format) {
    if (prepare(s, &st, "SELECT * FROM context_candidates WHERE candidate_id=?;") != 0)
      goto done;
    if (text(st, 1, candidate_id) != SQLITE_OK) { fail(s, "bind retirement dictionary failed"); goto done; }
    rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
      if (retirement_charge(st, &rows, &bytes, max_rows, max_bytes)) goto unfinished;
      candidate_key = sqlite3_column_int64(st, retirement_column(st, "id"));
      if (candidate_key <= 0) {
        retirement_error(s, "retirement candidate dictionary identity invalid", -1);
        goto done;
      }
      if (retirement_json_identity(s, retirement_text(st,
            retirement_column(st, "candidate_id_json")), candidate_id) != 0) goto done;
    } else if (rc != SQLITE_DONE) { fail(s, "read retirement dictionary failed"); goto done; }
    sqlite3_finalize(st); st = NULL;
  }


  int layout=phase==2 ? 0 : phase;
  for (;;) {
    if (yield_required && yield_required(yield_context)) goto unfinished;
    if (rows>=max_rows || bytes>=max_bytes) goto unfinished;
    if (layout>(s->format ? 1 : 0)) {
      if (phase==2) break;
      /* The proof is complete in the current writer transaction. This is the
       * only point where a retained group becomes unavailable to consumers. */
      phase=2; layout=0;
      if (retirement_save_progress(s,candidate_id,phase,pressure,legacy,cursor)!=0) goto done;
      saved=1;
      if (prepare(s,&st,"UPDATE p0_candidates SET local_retention_state='retirement_eligible' "
          "WHERE candidate_id=? AND retention_policy_version=1 AND local_retention_state='retained';")!=0) goto done;
      if (text(st,1,candidate_id)!=SQLITE_OK || sqlite3_step(st)!=SQLITE_DONE || sqlite3_changes(s->db)!=1) goto storage_failed;
      sqlite3_finalize(st); st=NULL; ++counts.progressed;
      if (edr_context_store_sync_retirement_fence(s)!=0) goto done;
      continue;
    }
    int compact=layout;
    if (compact && !candidate_key) { ++layout; continue; }
    int first=phase==2 || (compact ? cursor==0 : legacy[0]=='\0');
    const char *query=compact ? (first ?
        "SELECT r.id,r.candidate_key,r.fact_key,r.source_identity,r.artifact_override,"
        "r.candidate_json_override,r.created_ns,r.upload_status,r.minio_key,f.fact_id "
        "FROM compact_context_refs r LEFT JOIN context_fact_keys f ON f.id=r.fact_key "
        "WHERE r.candidate_key=?1 ORDER BY r.fact_key LIMIT 1;" :
        "SELECT r.id,r.candidate_key,r.fact_key,r.source_identity,r.artifact_override,"
        "r.candidate_json_override,r.created_ns,r.upload_status,r.minio_key,f.fact_id "
        "FROM compact_context_refs r LEFT JOIN context_fact_keys f ON f.id=r.fact_key "
        "WHERE r.candidate_key=?1 AND r.fact_key>?2 ORDER BY r.fact_key LIMIT 1;") : (first ?
        "SELECT rowid,* FROM candidate_context_refs WHERE candidate_id=?1 ORDER BY fact_id LIMIT 1;" :
        "SELECT rowid,* FROM candidate_context_refs WHERE candidate_id=?1 AND fact_id>?2 ORDER BY fact_id LIMIT 1;");
    if (prepare(s,&ref,query)!=0) goto done;
    if ((compact ? sqlite3_bind_int64(ref,1,candidate_key) : text(ref,1,candidate_id))!=SQLITE_OK ||
        (!first && (compact ? sqlite3_bind_int64(ref,2,cursor) : text(ref,2,legacy))!=SQLITE_OK)) goto storage_failed;
    rc=sqlite3_step(ref);
    if (rc==SQLITE_DONE) {
      sqlite3_finalize(ref); ref=NULL; ++layout;
      if (phase!=2 && layout<=1) { phase=layout; ++counts.progressed; }
      continue;
    }
    if (rc!=SQLITE_ROW) goto storage_failed;
    if (retirement_charge(ref,&rows,&bytes,max_rows,max_bytes)) goto unfinished;
    if (!compact) {
      const char *artifact=retirement_text(ref,retirement_column(ref,"artifact_id"));
      if (!artifact || !artifact[0]) { retirement_error(s,"retirement reference artifact identity invalid",-1); goto done; }
    } else {
      int source=retirement_column(ref,"source_identity"), override=retirement_column(ref,"artifact_override");
      const char *artifact=retirement_text(ref,override);
      if (!((sqlite3_column_type(ref,source)==SQLITE_BLOB && sqlite3_column_bytes(ref,source)==32 &&
             sqlite3_column_type(ref,override)==SQLITE_NULL) ||
            (sqlite3_column_type(ref,source)==SQLITE_NULL && artifact && artifact[0]))) {
        retirement_error(s,"retirement compact reference identity invalid",-1); goto done;
      }
    }
    if (!retirement_equal(ref,"upload_status","local_manifest") || !retirement_equal(ref,"minio_key","")) {
      result=retirement_error(s,"candidate reference delivery state is protected",1); goto done;
    }
    int json=retirement_column(ref,compact ? "candidate_json_override" : "candidate_id_json");
    if ((!compact || sqlite3_column_type(ref,json)!=SQLITE_NULL) &&
        retirement_json_identity(s,retirement_text(ref,json),candidate_id)!=0) goto done;
    const char *fact=retirement_text(ref,retirement_column(ref,"fact_id"));
    if (!fact || !fact[0]) { retirement_error(s,"retirement reference fact identity unavailable",-1); goto done; }
    sqlite3_int64 ref_id=sqlite3_column_int64(ref,0);
    sqlite3_int64 fact_key=compact ? sqlite3_column_int64(ref,retirement_column(ref,"fact_key")) : 0;
    if (compact && fact_key<=0) { retirement_error(s,"retirement fact dictionary identity invalid",-1); goto done; }
    if (prepare(s,&st,"SELECT * FROM context_facts WHERE fact_id=?;")!=0) goto done;
    if (text(st,1,fact)!=SQLITE_OK || sqlite3_step(st)!=SQLITE_ROW) {
      retirement_error(s,"retirement referenced fact unavailable",-1); goto done;
    }
    if (retirement_charge(st,&rows,&bytes,max_rows,max_bytes)) goto unfinished;
    if (!retirement_equal(st,"endpoint_id",endpoint) || !retirement_equal(st,"tenant_id",tenant)) {
      result=retirement_error(s,"retirement fact belongs to another scope",1); goto done;
    }
    sqlite3_finalize(st); st=NULL;
    if (s->format) {
      if (prepare(s,&st,"SELECT * FROM context_fact_keys WHERE fact_id=?;")!=0) goto done;
      if (text(st,1,fact)!=SQLITE_OK) goto storage_failed;
      rc=sqlite3_step(st);
      if (rc==SQLITE_ROW) {
        if (retirement_charge(st,&rows,&bytes,max_rows,max_bytes)) goto unfinished;
      } else if (rc!=SQLITE_DONE) goto storage_failed;
      sqlite3_finalize(st); st=NULL;
    }
    /* A complete unit has been proved and charged. Do not yield between its
     * edge and fact/key deletion; an I/O error rolls back this whole slice. */
    if (phase==2) {
      query=compact ? "DELETE FROM compact_context_refs WHERE id=?1 AND candidate_key=?2;" :
          "DELETE FROM candidate_context_refs WHERE rowid=?1 AND candidate_id=?2;";
      if (prepare(s,&st,query)!=0) goto done;
      if (sqlite3_bind_int64(st,1,ref_id)!=SQLITE_OK ||
          (compact ? sqlite3_bind_int64(st,2,candidate_key) : text(st,2,candidate_id))!=SQLITE_OK ||
          sqlite3_step(st)!=SQLITE_DONE || sqlite3_changes(s->db)!=1) goto storage_failed;
      sqlite3_finalize(st); st=NULL; ++counts.references;
      if (s->format) {
        if (prepare(s,&st,"DELETE FROM context_fact_keys WHERE fact_id=? AND NOT EXISTS("
            "SELECT 1 FROM compact_context_refs r WHERE r.fact_key=context_fact_keys.id);")!=0) goto done;
        if (text(st,1,fact)!=SQLITE_OK || sqlite3_step(st)!=SQLITE_DONE) goto storage_failed;
        sqlite3_finalize(st); st=NULL;
      }
      query=s->format ? "DELETE FROM context_facts WHERE fact_id=? AND NOT EXISTS(SELECT 1 FROM "
          "candidate_context_refs r WHERE r.fact_id=context_facts.fact_id) AND NOT EXISTS("
          "SELECT 1 FROM context_fact_keys k WHERE k.fact_id=context_facts.fact_id);" :
          "DELETE FROM context_facts WHERE fact_id=? AND NOT EXISTS(SELECT 1 FROM candidate_context_refs r WHERE r.fact_id=context_facts.fact_id);";
      if (prepare(s,&st,query)!=0) goto done;
      if (text(st,1,fact)!=SQLITE_OK || sqlite3_step(st)!=SQLITE_DONE) goto storage_failed;
      counts.facts+=(unsigned)sqlite3_changes(s->db);
      sqlite3_finalize(st); st=NULL;
    } else if (compact) cursor=fact_key;
    else {
      char *next=sqlite3_mprintf("%s",fact);
      if (!next) { retirement_error(s,"retirement cursor allocation failed",-1); goto done; }
      sqlite3_free(legacy); legacy=next;
    }
    ++counts.progressed;
    sqlite3_finalize(ref); ref=NULL;
  }
  if (s->format && candidate_key) {
    if (prepare(s, &st, "DELETE FROM context_candidates WHERE id=?1 AND candidate_id=?2 "
        "AND NOT EXISTS(SELECT 1 FROM compact_context_refs r WHERE r.candidate_key=context_candidates.id);") != 0)
      goto done;
    if (sqlite3_bind_int64(st, 1, candidate_key) != SQLITE_OK || text(st, 2, candidate_id) != SQLITE_OK ||
        sqlite3_step(st) != SQLITE_DONE || sqlite3_changes(s->db) != 1) {
      fail(s, "delete retirement candidate dictionary failed"); goto done;
    }
    sqlite3_finalize(st); st = NULL;
  }
  if (prepare(s, &st, "DELETE FROM artifacts WHERE rowid=?1 AND artifact_id=?2 AND candidate_id=?3;") != 0)
    goto done;
  if (sqlite3_bind_int64(st, 1, bundle_rowid) != SQLITE_OK || text(st, 2, bundle) != SQLITE_OK ||
      text(st, 3, candidate_id) != SQLITE_OK || sqlite3_step(st) != SQLITE_DONE || sqlite3_changes(s->db) != 1) {
    fail(s, "delete retirement bundle failed"); goto done;
  }
  sqlite3_finalize(st); st = NULL;
  if (prepare(s, &st, "DELETE FROM p0_candidates WHERE rowid=?1 AND candidate_id=?2 "
      "AND retention_policy_version=1 AND local_retention_state='retirement_eligible';") != 0) goto done;
  if (sqlite3_bind_int64(st, 1, candidate_rowid) != SQLITE_OK || text(st, 2, candidate_id) != SQLITE_OK ||
      sqlite3_step(st) != SQLITE_DONE || sqlite3_changes(s->db) != 1) {
    fail(s, "delete retirement candidate failed"); goto done;
  }
  sqlite3_finalize(st); st = NULL;
  if (edr_context_store_sync_retirement_fence(s)!=0) goto done;
  counts.candidates=1; counts.artifacts=1; ++counts.progressed;
  result=0; goto done;
unfinished:
  sqlite3_finalize(st); st=NULL; sqlite3_finalize(ref); ref=NULL;
  if (counts.progressed && retirement_save_progress(s,candidate_id,phase,pressure,legacy,cursor)!=0) goto done;
  result=2; goto done;
storage_failed:
  fail(s,"retirement progress storage failed");
done:
  sqlite3_finalize(st); sqlite3_finalize(ref);
  if (result==1 && phase==2) result=-1;
  if (result<0 || result==1) {
    if (sql(s,"ROLLBACK TO context_candidate_retirement;")!=0) result=-1;
    if (result==1 && saved && phase<2) {
      if (prepare(s,&st,"DELETE FROM context_retirement_progress WHERE candidate_id=? AND phase<2;")!=0 ||
          text(st,1,candidate_id)!=SQLITE_OK || sqlite3_step(st)!=SQLITE_DONE) result=-1;
      sqlite3_finalize(st);
    }
    memset(&counts,0,sizeof(counts));
  }
  if (sql(s,"RELEASE context_candidate_retirement;")!=0) {
    result=-1;
    sqlite3_exec(s->db,"ROLLBACK TO context_candidate_retirement;RELEASE context_candidate_retirement;",NULL,NULL,NULL);
  }
  sqlite3_free(endpoint); sqlite3_free(tenant); sqlite3_free(bundle); sqlite3_free(legacy);
  if (result>=0) { counts.pressure=pressure!=0; counts.work_rows=rows; counts.payload_bytes=bytes; *out=counts; }
  return result;
}

#endif
