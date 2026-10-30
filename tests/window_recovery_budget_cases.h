/* Synthetic, exact-page-cap startup fixtures. Included after shared helpers. */
#if defined(EDR_HAVE_SQLITE)
static void window_budget_fill(sqlite3 *db, const char *state, const char *gap) {
  startup_fill_pages(db, 256);
  compact_exec(db, "PRAGMA max_page_count=256;");
  sqlite3_stmt *pad = NULL, *metadata = NULL;
  assert(sqlite3_prepare_v2(db,"UPDATE p0_candidates SET cmdline=?1",-1,&pad,NULL)==SQLITE_OK);
  assert(sqlite3_prepare_v2(db,"UPDATE p0_candidates SET context_window_state=?1,context_window_gap_reason=?2",-1,&metadata,NULL)==SQLITE_OK);
  char padding[4096]; memset(padding,'p',sizeof(padding));
  int found = 0; unsigned length = 0;
  for (; length < sizeof(padding); ++length) {
    compact_exec(db,"BEGIN IMMEDIATE;");
    assert(sqlite3_bind_text(pad,1,padding,(int)length,SQLITE_STATIC)==SQLITE_OK);
    int pad_rc=sqlite3_step(pad); sqlite3_reset(pad);
    if (pad_rc==SQLITE_DONE) {
      assert(sqlite3_bind_text(metadata,1,state,-1,SQLITE_STATIC)==SQLITE_OK);
      assert(sqlite3_bind_text(metadata,2,gap,-1,SQLITE_STATIC)==SQLITE_OK);
      int rc=sqlite3_step(metadata); sqlite3_reset(metadata);
      if(rc==SQLITE_FULL) found=1; else assert(rc==SQLITE_DONE);
    } else assert(pad_rc==SQLITE_FULL);
    if(!sqlite3_get_autocommit(db)) compact_exec(db,"ROLLBACK;");
    if(found) break;
  }
  assert(found);
  assert(sqlite3_bind_text(pad,1,padding,(int)length,SQLITE_STATIC)==SQLITE_OK);
  assert(sqlite3_step(pad)==SQLITE_DONE); sqlite3_finalize(pad);
  assert(sqlite3_step(metadata)==SQLITE_FULL); sqlite3_finalize(metadata);
  assert(sqlite3_get_autocommit(db));
  compact_exec(db,"PRAGMA wal_checkpoint(TRUNCATE);");
  printf("window_budget_fixture padding=%u pages=%lld free=%lld state=%s original_sqlite=13\n",length,
      (long long)compact_scalar(db,"PRAGMA page_count"),(long long)compact_scalar(db,"PRAGMA freelist_count"),state);
}


/* Use the existing delegating test VFS to refuse the WAL commit frame.
 * A current-schema fixture performs no earlier startup mutation. The test
 * requires a retained first FULL plus this I/O cause, so a failure at another
 * phase cannot accidentally satisfy the recovery contract. */
static sqlite3_io_methods window_budget_failure_methods;
static int window_budget_commit_denied;
static int window_budget_commit_write(sqlite3_file *file, const void *data, int amount, sqlite3_int64 offset) {
  const unsigned char *bytes=(const unsigned char *)data;
  if(!window_budget_commit_denied && amount>=8 && offset>=32 && (offset-32)%4120==0 &&
      (bytes[4] || bytes[5] || bytes[6] || bytes[7])) {
    window_budget_commit_denied=1; return SQLITE_IOERR_WRITE;
  }
  RetentionBenchFile *f=(RetentionBenchFile *)file;
  return f->real->pMethods->xWrite(f->real,data,amount,offset);
}
static int window_budget_failure_open(sqlite3_vfs *v, const char *name, sqlite3_file *file, int flags, int *out) {
  int rc=retention_bench_open(v,name,file,flags,out);
  if(file->pMethods && (flags&SQLITE_OPEN_WAL)) file->pMethods=&window_budget_failure_methods;
  return rc;
}

static void window_budget_query(const char *state, const char *gap, int64_t now) {
  char out[16384]; EdrSoarCommandMeta meta; memset(&meta,0,sizeof(meta));
  meta.issued_at_unix_ms=now/1000000LL;meta.deadline_ms=60000;
  EdrCommandResultAuthorization *a=&meta.result_authorization;
  strcpy(a->command_id,"window-budget-query");strcpy(a->command_type,"rtq_query");
  strcpy(a->tenant_id,"tenant-window");strcpy(a->endpoint_id,"ep-window-replacement");
  a->expires_unix_ms=meta.issued_at_unix_ms+60000;
  snprintf(a->content_contract,sizeof(a->content_contract),
      "{\"schema\":\"edr.command.result-purpose.v1\",\"kind\":\"cached_rtq\",\"max_bytes\":16383,\"max_rows\":20,\"window_s\":600,\"issued_unix_ms\":%lld,\"request\":{\"limit\":20,\"time_window_s\":600}}",(long long)meta.issued_at_unix_ms);
  int rc=edr_local_evidence_cache_query_authorized_json(a->command_id,&meta,out,sizeof(out));
  if(rc) fprintf(stderr,"window_budget_query rc=%d error=%s\n",rc,out);
  assert(rc==0);
  cJSON *root=cJSON_Parse(out); assert(root);
  const cJSON *rows=cJSON_GetObjectItemCaseSensitive(root,"rows"), *row=NULL;
  int found=0;
  cJSON_ArrayForEach(row,rows) {
    const cJSON *observed_state=cJSON_GetObjectItemCaseSensitive(row,"context_window_state");
    if(!observed_state) continue;
    const cJSON *observed_gap=cJSON_GetObjectItemCaseSensitive(row,"context_window_gap_reason");
    assert(cJSON_IsString(observed_state) && !strcmp(observed_state->valuestring,state));
    assert(cJSON_IsString(observed_gap) && !strcmp(observed_gap->valuestring,gap));
    ++found;
  }
  assert(found==1);
  const cJSON *manifest=cJSON_GetObjectItemCaseSensitive(root,"manifest");
  const cJSON *coverage=cJSON_GetObjectItemCaseSensitive(manifest,"coverage_status");
  assert(cJSON_IsString(coverage) && !strcmp(coverage->valuestring,"partial"));
  assert(strstr(out,"window_observation_gap")); cJSON_Delete(root);
}

static void test_window_recovery_budget(int enforce) {
  const int64_t base=INT64_C(1793100000000000000);
  char queue_path[640];assert(make_test_sqlite_path(queue_path,sizeof(queue_path))==0);
  edr_storage_queue_configure(8,1);assert(edr_storage_queue_open(queue_path)==EDR_OK);
  static const char *evidence_queries[]={
    "SELECT * FROM artifacts ORDER BY artifact_id",
    "SELECT * FROM context_facts ORDER BY fact_id",
    "SELECT * FROM candidate_context_refs ORDER BY artifact_id",
    "SELECT * FROM materialized_artifacts ORDER BY artifact_id",
    "SELECT * FROM context_reference_projection ORDER BY artifact_id",
    "SELECT * FROM compact_context_refs ORDER BY id",
    "SELECT * FROM context_fact_keys ORDER BY id",
    "SELECT * FROM context_candidates ORDER BY id"
  };
  /* FULL terminal/live, invalid spec, normal terminal/live, retry UPDATE
   * refusal, non-FULL refusal, retry COMMIT refusal, activation gap, expiry. */
  for(unsigned mode=0;mode<(enforce?10u:2u);++mode) {
    const int full=mode!=3 && mode!=4 && mode!=6;
    const int live=mode==1 || mode==4 || mode==7 || mode==8;
    const int fails=mode==2 || mode==5 || mode==6 || mode==7;
    const char *initial_state=live?"active":mode==9?"expired":"interrupted";
    const char *initial_gap=live?"service_restart_gap":mode==2?"invalid_window_metadata":
        mode==9?"restart_after_window":"live_generation_unverified";
    char combined[96];
    if(mode==8) { snprintf(combined,sizeof(combined),"activation_gap+%s",initial_gap); initial_gap=combined; }
    const char *final_state=full&&live?"interrupted":initial_state;
    const char *final_gap=full&&live?(mode==8?"activation_gap+window_capacity_replaced":"window_capacity_replaced"):initial_gap;
    char path[640],before[8][65],after[65],owner[65],sql[384];
    sqlite3 *db=NULL; sqlite3_vfs failure_vfs; EdrBehaviorRecord candidate,context; EdrEvidenceCacheStatus status;
    assert(make_test_sqlite_path(path,sizeof(path))==0);
    edr_local_evidence_cache_test_set_now_unix_ns(base);
    edr_local_evidence_cache_test_set_retention_monotonic_ms(1000);
    s_test_monotonic_ns=UINT64_C(1000000000);
    test_setenv("EDR_EVIDENCE_CONTEXT_WINDOW_S","60");
    assert(edr_local_evidence_cache_open(path,8,1)==0);
    init_window_replacement_candidate(&candidate,0,base);
    context=candidate;context.type=EDR_EVENT_FILE_WRITE;context.net_dport=0;context.net_dst[0]='\0';
    context.event_time_ns=base-INT64_C(1000000000);
    strcpy(context.event_id,"budget-pre-context");strcpy(context.file_path,"C:\\UserData\\budget-pre.bin");
    assert(!edr_local_evidence_cache_is_candidate(&context));
    edr_local_evidence_cache_record_behavior(&context);
    edr_local_evidence_cache_record_behavior(&candidate);
    context.event_time_ns=base+INT64_C(500000000);
    strcpy(context.event_id,"budget-post-context");strcpy(context.file_path,"C:\\UserData\\budget-post.bin");
    edr_local_evidence_cache_record_behavior(&context);
    edr_local_evidence_cache_close();
    assert(sqlite3_open(path,&db)==SQLITE_OK);
    assert(compact_scalar(db,"SELECT COUNT(*) FROM p0_candidates WHERE context_window_state='active'")==1);
    assert(compact_scalar(db,"SELECT COUNT(*) FROM context_reference_projection")>0);
    assert(compact_scalar(db,"SELECT COUNT(*) FROM context_facts")>0);
    if(mode==2) compact_exec(db,"UPDATE p0_candidates SET context_window_spec='{\"roles\":[]}'");
    if(mode==8) compact_exec(db,"UPDATE p0_candidates SET context_window_gap_reason='activation_gap'");
    if(mode==5 || mode==6) compact_exec(db,mode==5?
        "CREATE TRIGGER window_budget_refusal BEFORE UPDATE ON p0_candidates WHEN NEW.context_window_spec='' BEGIN SELECT RAISE(ABORT,'budget retry refused'); END;":
        "CREATE TRIGGER window_budget_refusal BEFORE UPDATE ON p0_candidates BEGIN SELECT RAISE(ABORT,'budget non-full refused'); END;");
    if(full) window_budget_fill(db,initial_state,initial_gap);
    sqlite3_int64 pages=compact_scalar(db,"PRAGMA page_count");
    compact_exec(db,"CREATE TEMP TABLE window_budget_expected AS SELECT * FROM p0_candidates;");
    compact_startup_rowset_hash(db,"SELECT * FROM p0_candidates ORDER BY candidate_id",owner);
    if(!fails) {
      snprintf(sql,sizeof(sql),"UPDATE window_budget_expected SET context_window_state='%s',context_window_gap_reason='%s'%s;",
          final_state,final_gap,full?",context_window_spec=''":"");
      compact_exec(db,sql);
    }
    for(unsigned i=0;i<8;++i)compact_startup_rowset_hash(db,evidence_queries[i],before[i]);
    edr_local_evidence_cache_test_set_window_recovery_identity(live?1:0);
    s_test_monotonic_ns=mode==9?UINT64_C(62000000000):UINT64_C(2000000000);
    edr_local_evidence_cache_test_set_now_unix_ns(base+(mode==9?INT64_C(61000000000):INT64_C(1000000000)));
    if(mode==7) {
      window_budget_commit_denied=0;
      retention_bench_vfs_parent=sqlite3_vfs_find(NULL);assert(retention_bench_vfs_parent);
      failure_vfs=*retention_bench_vfs_parent;failure_vfs.pNext=NULL;
      failure_vfs.zName="window-budget-commit-refusal";
      failure_vfs.szOsFile+=(int)sizeof(RetentionBenchFile);failure_vfs.xOpen=window_budget_failure_open;
      window_budget_failure_methods=retention_bench_methods;window_budget_failure_methods.xWrite=window_budget_commit_write;
      assert(sqlite3_vfs_register(&failure_vfs,1)==SQLITE_OK);
    }
    int rc=edr_local_evidence_cache_open(path,1,1);
    if(mode==7) {
      assert(sqlite3_vfs_register(retention_bench_vfs_parent,1)==SQLITE_OK);
      assert(sqlite3_vfs_unregister(&failure_vfs)==SQLITE_OK);
      assert(window_budget_commit_denied==1);
    }
    edr_local_evidence_cache_get_status(&status);
    printf("window_budget_reopen mode=%u rc=%d error=%s\n",mode,rc,status.last_error);fflush(stdout);
    if(enforce) {
      assert(fails?rc<0:rc==0);
      assert(compact_scalar(db,"PRAGMA page_count")<=pages);
      compact_startup_rowset_hash(db,"SELECT * FROM window_budget_expected ORDER BY candidate_id",after);
      char actual[65];compact_startup_rowset_hash(db,"SELECT * FROM p0_candidates ORDER BY candidate_id",actual);
      assert(!strcmp(after,actual));
      for(unsigned i=0;i<8;++i) {
        compact_startup_rowset_hash(db,evidence_queries[i],after);assert(!strcmp(before[i],after));
      }
      if(fails) {
        assert(!status.db_open && status.last_error[0]);
        assert(!strcmp(owner,actual));
        assert(strstr(status.last_error,mode==6?"sqlite=1811":"sqlite=13"));
        if(mode==5 || mode==7) assert(strstr(status.last_error,"retry:"));
        if(mode==5) assert(strstr(status.last_error,"sqlite=1811"));
        if(mode==7) assert(strstr(status.last_error,"disk I/O error"));
      } else {
        assert(status.context_windows_used==(live&&!full?1u:0u));
        window_budget_query(final_state,final_gap,base+(mode==9?INT64_C(61000000000):INT64_C(1000000000)));
        edr_local_evidence_cache_close();
        assert(edr_local_evidence_cache_open(path,1,1)==0);
        window_budget_query(final_state,final_gap,base+(mode==9?INT64_C(61000000000):INT64_C(1000000000)));
        compact_startup_rowset_hash(db,"SELECT * FROM p0_candidates ORDER BY candidate_id",after);
        assert(!strcmp(after,actual));
        /* Replay of the original event cannot rearm a consumed terminal plan. */
        edr_local_evidence_cache_record_behavior(&candidate);
        compact_startup_rowset_hash(db,"SELECT * FROM p0_candidates ORDER BY candidate_id",after);
        assert(!strcmp(after,actual));
        edr_local_evidence_cache_get_status(&status);
        assert(status.context_windows_used==(live&&!full?1u:0u));
      }
    }
    edr_local_evidence_cache_close();assert(sqlite3_close(db)==SQLITE_OK);cleanup_test_sqlite_path(path);
  }
  test_unsetenv("EDR_EVIDENCE_CONTEXT_WINDOW_S");
  edr_local_evidence_cache_test_set_window_recovery_identity(-1);
  edr_local_evidence_cache_test_set_retention_monotonic_ms(-1);
  edr_local_evidence_cache_test_set_now_unix_ns(0);
  s_test_monotonic_ns=UINT64_C(1000000000);
  edr_storage_queue_close();cleanup_test_sqlite_path(queue_path);
  if(enforce) puts("window_budget_contract full_terminal_live=1 ordinary_spec_preserved=1 invalid_spec_preserved=1 evidence_refs_floor_preserved=1 retry_rollback=1 legacy_gap_enum=1 query_and_replay=1");
  else puts("window_budget_probe observations_only=1");
}
#endif
