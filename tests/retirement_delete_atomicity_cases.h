/* Synthetic retirement failure boundaries. Included after the existing
 * retention fixtures; no test-only hooks enter the production owner. */
static void test_retirement_delete_failure_boundaries(void) {
  const int64_t now=INT64_C(1700000000000000000),old=now-INT64_C(360000000000000);
  const char *queries[]={
      "SELECT * FROM p0_candidates ORDER BY candidate_id",
      "SELECT * FROM artifacts ORDER BY artifact_id",
      "SELECT * FROM context_facts ORDER BY fact_id",
      "SELECT * FROM candidate_context_refs ORDER BY artifact_id",
      "SELECT * FROM context_reference_projection ORDER BY artifact_id",
      "SELECT * FROM context_retirement_progress ORDER BY candidate_id"};
  const char *physical_queries[]={
      "SELECT * FROM context_fact_keys ORDER BY id",
      "SELECT * FROM context_candidates ORDER BY id",
      "SELECT * FROM compact_context_refs ORDER BY id"};
  for(int format=0;format<3;++format) for(int failure=0;failure<5;++failure) {
    if(failure==1 && !format) continue; /* Legacy has no dictionary keys. */
    char path[512],before[6][65],physical_before[3][65],after[65],keeper[65];sqlite3 *db=NULL;
    EdrContextStore store;EdrContextRetirement disposition;
    assert(make_test_sqlite_path(path,sizeof(path))==0);
    edr_local_evidence_cache_test_set_now_unix_ns(now);
    assert(test_open_legacy_context(path,32,72)==0);edr_local_evidence_cache_close();
    assert(sqlite3_open(path,&db)==SQLITE_OK);
    compact_exec(db,"PRAGMA foreign_keys=ON;");
    retention_group_fixture(db,"atomic-units",1,old,old,old+1);
    retention_group_fixture(db,"atomic-keeper",0,old,old,old+1);
    compact_exec(db,"WITH RECURSIVE n(x) AS(SELECT 0 UNION ALL SELECT x+1 FROM n WHERE x<16) "
        "INSERT INTO context_facts SELECT printf('atomic-%02d',x),'retention-endpoint','retention-tenant',"
        "printf('{\"source\":%d}',x),1,1 FROM n;");
    for(unsigned i=0;i<17;++i) {
      char fact[32];snprintf(fact,sizeof(fact),"atomic-%02u",i);
      retention_ref_fixture(db,"atomic-units",fact,old);
    }
    retention_ref_fixture(db,"atomic-keeper","atomic-16",old);
    retention_upgrade_refs(db,format);
    assert(edr_context_store_open(&store,db)==0);
    if(format==1) {
      unsigned moved=0;int complete=0;
      assert(edr_context_store_migrate_batch(&store,1,&moved,&complete)==0 && moved==1 && !complete);
      assert(compact_scalar(db,"SELECT COUNT(*) FROM compact_context_refs r JOIN context_candidates c ON c.id=r.candidate_key WHERE c.candidate_id='atomic-units'")==1);
    }
    compact_exec(db,"BEGIN IMMEDIATE;INSERT INTO context_retirement_progress(candidate_id,phase,reason) "
        "VALUES('atomic-units',2,0);UPDATE p0_candidates SET local_retention_state='retirement_eligible' "
        "WHERE candidate_id='atomic-units';");
    assert(edr_context_store_sync_retirement_fence(&store)==0);compact_exec(db,"COMMIT;");
    for(unsigned i=0;i<6;++i) compact_startup_rowset_hash(db,queries[i],before[i]);
    if(format) for(unsigned i=0;i<3;++i) compact_startup_rowset_hash(db,physical_queries[i],physical_before[i]);
    compact_startup_rowset_hash(db,"SELECT * FROM materialized_artifacts WHERE candidate_id='atomic-keeper' ORDER BY artifact_id",keeper);
    if(failure==0) {
      compact_exec(db,"CREATE TRIGGER injected_ref_failure BEFORE DELETE ON candidate_context_refs "
          "WHEN OLD.fact_id='atomic-03' BEGIN SELECT RAISE(FAIL,'injected reference first cause'); END;");
      if(format) compact_exec(db,"CREATE TRIGGER injected_compact_failure BEFORE DELETE ON compact_context_refs "
          "WHEN OLD.fact_key IN(SELECT id FROM context_fact_keys WHERE fact_id='atomic-03') "
          "BEGIN SELECT RAISE(FAIL,'injected reference first cause'); END;");
    } else if(failure==1) compact_exec(db,"CREATE TRIGGER injected_key_failure BEFORE DELETE ON context_fact_keys "
        "BEGIN SELECT RAISE(FAIL,'injected key first cause'); END;");
    else if(failure==2) compact_exec(db,"CREATE TRIGGER injected_fact_failure BEFORE DELETE ON context_facts "
        "WHEN OLD.fact_id='atomic-03' BEGIN SELECT RAISE(FAIL,'injected fact first cause'); END;");
    else if(failure==3) compact_exec(db,"CREATE TRIGGER injected_progress_failure BEFORE UPDATE ON context_retirement_progress "
        "BEGIN SELECT RAISE(FAIL,'injected progress first cause'); END;");
    else compact_exec(db,"CREATE TABLE commit_parent(id INTEGER PRIMARY KEY);"
        "CREATE TABLE commit_child(id REFERENCES commit_parent(id) DEFERRABLE INITIALLY DEFERRED);"
        "CREATE TRIGGER injected_commit_failure AFTER DELETE ON context_facts BEGIN INSERT INTO commit_child VALUES(1); END;");
    compact_exec(db,"BEGIN IMMEDIATE;");
    int result=edr_context_store_retire_candidate(&store,"atomic-units",0,failure==3 ? 15u : 256u,
        4096000u,NULL,NULL,&disposition);
    if(failure==4) {
      assert(result==0);
      assert(sqlite3_exec(db,"COMMIT",NULL,NULL,NULL)==SQLITE_CONSTRAINT);
      compact_exec(db,"ROLLBACK;");
    } else {
      if(result>=0 || !strstr(store.error,"first cause")) fprintf(stderr,"atomicity format=%d failure=%d result=%d error=%s\n",format,failure,result,store.error);
      assert(result<0 && strstr(store.error,"first cause"));
      assert(!disposition.references && !disposition.facts && !disposition.progressed);
      /* Check the owner's SAVEPOINT rollback before the caller rolls back. */
      for(unsigned i=0;i<6;++i) {compact_startup_rowset_hash(db,queries[i],after);assert(!strcmp(before[i],after));}
      if(format) for(unsigned i=0;i<3;++i) {compact_startup_rowset_hash(db,physical_queries[i],after);assert(!strcmp(physical_before[i],after));}
      compact_exec(db,"ROLLBACK;");
    }
    if(format) for(unsigned i=0;i<3;++i) {compact_startup_rowset_hash(db,physical_queries[i],after);assert(!strcmp(physical_before[i],after));}
    for(unsigned i=0;i<6;++i) {compact_startup_rowset_hash(db,queries[i],after);assert(!strcmp(before[i],after));}
    assert(compact_scalar(db,"SELECT COUNT(*) FROM pragma_foreign_key_check")==0);
    compact_exec(db,"DROP TRIGGER IF EXISTS injected_ref_failure;DROP TRIGGER IF EXISTS injected_compact_failure;"
        "DROP TRIGGER IF EXISTS injected_key_failure;DROP TRIGGER IF EXISTS injected_fact_failure;"
        "DROP TRIGGER IF EXISTS injected_progress_failure;DROP TRIGGER IF EXISTS injected_commit_failure;");
    assert(sqlite3_close(db)==SQLITE_OK);assert(sqlite3_open(path,&db)==SQLITE_OK);
    assert(edr_context_store_open(&store,db)==0);
    compact_exec(db,"PRAGMA foreign_keys=ON;BEGIN IMMEDIATE;");
    assert(edr_context_store_retire_candidate(&store,"atomic-units",0,256u,4096000u,NULL,NULL,&disposition)==0);
    assert(disposition.references==17 && disposition.facts==16 && disposition.candidates==1);
    compact_exec(db,"COMMIT;");
    assert(compact_scalar(db,"SELECT COUNT(*) FROM candidate_context_refs r LEFT JOIN context_facts f ON f.fact_id=r.fact_id WHERE f.fact_id IS NULL")==0);
    if(format) assert(compact_scalar(db,"SELECT COUNT(*) FROM compact_context_refs r LEFT JOIN context_fact_keys f ON f.id=r.fact_key LEFT JOIN context_candidates c ON c.id=r.candidate_key WHERE f.id IS NULL OR c.id IS NULL")==0);
    assert(compact_scalar(db,"SELECT COUNT(*) FROM context_facts")==1);
    assert(compact_scalar(db,"SELECT COUNT(*) FROM context_reference_projection")==1);
    assert(compact_scalar(db,"SELECT COUNT(*) FROM pragma_foreign_key_check")==0);
    compact_startup_rowset_hash(db,"SELECT * FROM materialized_artifacts WHERE candidate_id='atomic-keeper' ORDER BY artifact_id",after);
    assert(!strcmp(keeper,after));
    assert(sqlite3_close(db)==SQLITE_OK);cleanup_test_sqlite_path(path);
  }
  edr_local_evidence_cache_test_set_now_unix_ns(0);
  puts("retirement failure boundaries: legacy/mixed/compact reference/key/fact/progress/commit rollback, first cause, reopen retry, keeper content passed");
}
