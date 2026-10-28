/* Production cache persistence and signed query, with only synthetic records. */
#if defined(EDR_HAVE_SQLITE)
static void retained_recall_export(const char *env_name,const EdrSoarCommandMeta *meta,const char *detail) {
  const char *path=getenv(env_name);if(!path || !path[0])return;
  const EdrCommandResultAuthorization *a=&meta->result_authorization;
  cJSON *root=cJSON_CreateObject();assert(root);
  cJSON_AddStringToObject(root,"schema","edr.synthetic-recall-fixture.v1");
  cJSON_AddStringToObject(root,"command_id",a->command_id);
  cJSON_AddStringToObject(root,"tenant_id",a->tenant_id);cJSON_AddStringToObject(root,"endpoint_id",a->endpoint_id);
  cJSON_AddNumberToObject(root,"issued_unix_ms",(double)meta->issued_at_unix_ms);
  cJSON_AddStringToObject(root,"content_contract_json",a->content_contract);
  cJSON_AddStringToObject(root,"detail_json",detail);
  char *encoded=cJSON_PrintUnformatted(root);assert(encoded);
  FILE *f=fopen(path,"wb");assert(f);assert(fwrite(encoded,1,strlen(encoded),f)==strlen(encoded));assert(fclose(f)==0);
  cJSON_free(encoded);cJSON_Delete(root);
}
static int retained_recall_rows(const char *json, const char *source) {
  cJSON *root=cJSON_Parse(json); assert(root);
  const cJSON *rows=cJSON_GetObjectItemCaseSensitive(root,"rows"),*row=NULL;
  int count=0;
  cJSON_ArrayForEach(row,rows) {
    const cJSON *s=cJSON_GetObjectItemCaseSensitive(row,"source");
    if (!source || (cJSON_IsString(s) && !strcmp(s->valuestring,source))) ++count;
  }
  assert(cJSON_IsFalse(cJSON_GetObjectItemCaseSensitive(root,"absence_is_evidence")));
  cJSON_Delete(root);return count;
}
static void retained_recall_contract(EdrSoarCommandMeta *meta, const EdrBehaviorRecord *owner,
                                    int64_t now, const char *request, unsigned rows) {
  memset(meta,0,sizeof(*meta)); meta->issued_at_unix_ms=now/1000000LL;meta->deadline_ms=60000;
  EdrCommandResultAuthorization *a=&meta->result_authorization;
  snprintf(a->command_id,sizeof(a->command_id),"retained-context-query");
  snprintf(a->command_type,sizeof(a->command_type),"rtq_query");
  snprintf(a->tenant_id,sizeof(a->tenant_id),"%s",owner->tenant_id);
  snprintf(a->endpoint_id,sizeof(a->endpoint_id),"%s",owner->endpoint_id);
  a->expires_unix_ms=meta->issued_at_unix_ms+60000;
  snprintf(a->content_contract,sizeof(a->content_contract),
      "{\"schema\":\"edr.command.result-purpose.v1\",\"kind\":\"cached_rtq\",\"max_bytes\":16383,\"max_rows\":%u,\"window_s\":600,\"issued_unix_ms\":%lld,\"event_type\":11,\"request\":%s}",
      rows,(long long)meta->issued_at_unix_ms,request);
}
static void test_retained_context_recall(int enforce) {
  const int64_t base=INT64_C(1793100000000000000),now=base+INT64_C(2000000000);
  for (unsigned layout=0;layout<2u;++layout) {
    char path[640],queue_path[640],out[16384];EdrBehaviorRecord owner,pre,post;
    assert(make_test_sqlite_path(path,sizeof(path))==0);
    assert(make_test_sqlite_path(queue_path,sizeof(queue_path))==0);
    edr_storage_queue_configure(16,24);assert(edr_storage_queue_open(queue_path)==EDR_OK);
    edr_pt_cache_init();edr_local_evidence_cache_test_set_now_unix_ns(base);
    assert((layout ? edr_local_evidence_cache_open(path,16,24) : test_open_legacy_context(path,16,24))==0);
    init_window_replacement_candidate(&owner,0,base);
    pre=owner;pre.type=EDR_EVENT_FILE_WRITE;pre.net_dport=0;pre.net_dst[0]=0;pre.detection_context[0]=0;
    pre.event_time_ns=base-INT64_C(1000000000);
    snprintf(pre.event_id,sizeof(pre.event_id),"retained-pre-source");
    snprintf(pre.file_path,sizeof(pre.file_path),"C:\\UserData\\retained-pre.bin");
    snprintf(pre.cmdline,sizeof(pre.cmdline),"private-command-must-not-export");
    assert(!edr_local_evidence_cache_is_candidate(&pre));
    edr_local_evidence_cache_record_behavior(&pre);
    edr_local_evidence_cache_record_behavior(&owner);
    snprintf(owner.event_id,sizeof(owner.event_id),"second-retained-owner");
    owner.event_time_ns+=INT64_C(100000000);edr_local_evidence_cache_record_behavior(&owner);
    post=pre;post.event_time_ns=base+INT64_C(1000000000);
    snprintf(post.event_id,sizeof(post.event_id),"retained-post-source");
    snprintf(post.file_path,sizeof(post.file_path),"C:\\UserData\\retained-post.bin");
    edr_local_evidence_cache_record_behavior(&post);
    edr_local_evidence_cache_close();edr_pt_cache_shutdown();
    edr_local_evidence_cache_test_set_now_unix_ns(now);
    assert(edr_local_evidence_cache_open(path,16,24)==0);
    EdrSoarCommandMeta meta;retained_recall_contract(&meta,&owner,now,"{\"event_type\":\"file_write\"}",50);
    EdrCommandResultAuthorization *a=&meta.result_authorization;
    int result=edr_local_evidence_cache_query_authorized_json(a->command_id,&meta,out,sizeof(out));
    if(result)fprintf(stderr,"retained query failure: %s\n",out);assert(result==0);
    int pre_rows=retained_recall_rows(out,"context_pre"),post_rows=retained_recall_rows(out,"context_post");
    printf("retained_context layout=%u pre=%d post=%d private_fields=0\n",layout,pre_rows,post_rows);
    assert(!strstr(out,"private-command-must-not-export"));
    if(enforce) {
      assert(pre_rows==1 && post_rows==1 && retained_recall_rows(out,NULL)==2);
      assert(strstr(out,"retained-pre.bin") && strstr(out,"retained-post.bin"));
    }
    if(layout==1u)retained_recall_export("EDR_TEST_RETAINED_QUERY_OUTPUT",&meta,out);
    if(enforce) {
      /* Same retained DB, signed generation and domain isolation. */
      char request[384];snprintf(request,sizeof(request),"{\"event_type\":\"file_write\",\"pid\":%u,\"process_start_key\":\"%llu\",\"process_creation_filetime_100ns\":\"%llu\"}",
          post.pid,(unsigned long long)post.process_start_key,(unsigned long long)post.process_creation_filetime_100ns);
      retained_recall_contract(&meta,&owner,now,request,50);
      assert(edr_local_evidence_cache_query_authorized_json(a->command_id,&meta,out,sizeof(out))==0);
      assert(retained_recall_rows(out,NULL)==2);
      snprintf(a->tenant_id,sizeof(a->tenant_id),"wrong-tenant");
      assert(edr_local_evidence_cache_query_authorized_json(a->command_id,&meta,out,sizeof(out))==0);
      assert(retained_recall_rows(out,NULL)==0);
      retained_recall_contract(&meta,&owner,now,"{\"event_type\":\"file_write\",\"pid\":97001}",50);
      assert(edr_local_evidence_cache_query_authorized_json(a->command_id,&meta,out,sizeof(out))==0);
      assert(retained_recall_rows(out,NULL)==0);
      retained_recall_contract(&meta,&owner,now,"{\"event_type\":\"file_write\",\"limit\":1}",1);
      assert(edr_local_evidence_cache_query_authorized_json(a->command_id,&meta,out,sizeof(out))==0);
      assert(retained_recall_rows(out,NULL)==1 && strstr(out,"\"partial\":true"));
      retained_recall_contract(&meta,&owner,now,"{\"event_type\":\"file_write\"}",50);
      assert(edr_local_evidence_cache_query_authorized_json(a->command_id,&meta,out,512)<0);
      assert(strstr(out,"byte budget"));
      /* Corruption is a visible failure, not an empty success or raw export. */
      sqlite3 *db=NULL;assert(sqlite3_open(path,&db)==SQLITE_OK);
      compact_exec(db,"UPDATE context_facts SET manifest_template_json=replace(manifest_template_json,'retained-post.bin','tampered-post.bin') WHERE instr(manifest_template_json,'p0_post_context_event.v1')>0;");
      sqlite3_close(db);
      assert(edr_local_evidence_cache_query_authorized_json(a->command_id,&meta,out,sizeof(out))<0);
      assert(strstr(out,"hash or identity invalid"));
      assert(sqlite3_open(path,&db)==SQLITE_OK);
      compact_exec(db,"UPDATE context_facts SET manifest_template_json=replace(manifest_template_json,'tampered-post.bin','retained-post.bin') WHERE instr(manifest_template_json,'p0_post_context_event.v1')>0;");
      if(layout) compact_exec(db,"UPDATE compact_context_refs SET artifact_override=(SELECT candidate_id FROM context_candidates WHERE id=candidate_key)||':post_context:'||lower(hex(source_identity))||char(0)||'junk',source_identity=NULL WHERE source_identity IS NOT NULL;");
      else compact_exec(db,"UPDATE candidate_context_refs SET artifact_id=artifact_id||char(0)||'junk' WHERE instr(artifact_id,':post_context:')>0;");
      sqlite3_close(db);
      assert(edr_local_evidence_cache_query_authorized_json(a->command_id,&meta,out,sizeof(out))<0);
      assert(strstr(out,"hash or identity invalid"));
    }
    edr_local_evidence_cache_close();edr_storage_queue_close();
    cleanup_test_sqlite_path(path);cleanup_test_sqlite_path(queue_path);
  }
  edr_local_evidence_cache_test_set_now_unix_ns(0);
}
static void test_retained_context_unknown_actor(void) {
  const int64_t base=INT64_C(1793100000000000000),now=base+INT64_C(2000000000);
  for(unsigned layout=0;layout<2u;++layout) {
    char path[640],queue_path[640],out[16384];EdrBehaviorRecord owner,pre,post;
    assert(make_test_sqlite_path(path,sizeof(path))==0);
    assert(make_test_sqlite_path(queue_path,sizeof(queue_path))==0);
    edr_storage_queue_configure(16,24);assert(edr_storage_queue_open(queue_path)==EDR_OK);
    edr_pt_cache_init();edr_local_evidence_cache_test_set_now_unix_ns(base);
    assert((layout?edr_local_evidence_cache_open(path,16,24):test_open_legacy_context(path,16,24))==0);
    init_window_replacement_candidate(&owner,0,base);
    assert(put_generation(owner.pid,4,"window-owner.exe","parent","C:\\Parent.exe","system",
        (uint64_t)(base-INT64_C(120000000000)),owner.process_start_key)==0);
    assert(edr_pt_cache_mark_alive_generation(owner.pid,owner.process_start_key,
        owner.process_creation_filetime_100ns,(uint64_t)base)==0);
    pre=owner;pre.pid=98000;pre.ppid=owner.pid;pre.type=EDR_EVENT_FILE_WRITE;
    pre.net_dport=0;pre.net_dst[0]=0;pre.detection_context[0]=0;
    /* A source supplies child birth but no StartKey. The actor remains
     * unbound; the parent snapshot at child birth independently proves the
     * relationship admitted by ring_related_to_record/context_window_matches. */
    pre.process_start_key=0;
    pre.process_creation_filetime_100ns=test_unix_ns_to_filetime((uint64_t)(base-INT64_C(10000000000)));
    snprintf(pre.process_name,sizeof(pre.process_name),"unknown-child.exe");
    snprintf(pre.exe_path,sizeof(pre.exe_path),"C:\\UnknownChild.exe");
    pre.event_time_ns=base-INT64_C(1000000000);
    snprintf(pre.event_id,sizeof(pre.event_id),"unknown-child-pre");
    snprintf(pre.file_path,sizeof(pre.file_path),"C:\\UserData\\unknown-child-pre.bin");
    assert(!edr_local_evidence_cache_is_candidate(&pre));
    edr_local_evidence_cache_record_behavior(&pre);
    edr_local_evidence_cache_record_behavior(&owner);
    post=pre;post.event_time_ns=base+INT64_C(1000000000);
    snprintf(post.event_id,sizeof(post.event_id),"unknown-child-post");
    snprintf(post.file_path,sizeof(post.file_path),"C:\\UserData\\unknown-child-post.bin");
    edr_local_evidence_cache_record_behavior(&post);
    char candidate[200];sqlite_candidate_id_for_source_event(path,owner.event_id,candidate,sizeof(candidate));
    assert(sqlite_post_artifact_count(path,candidate,post.event_id)==1u);
    edr_local_evidence_cache_close();edr_pt_cache_shutdown();
    edr_local_evidence_cache_test_set_now_unix_ns(now);assert(edr_local_evidence_cache_open(path,16,24)==0);
    EdrSoarCommandMeta meta;retained_recall_contract(&meta,&owner,now,"{\"event_type\":\"file_write\"}",50);
    EdrCommandResultAuthorization *a=&meta.result_authorization;
    int result=edr_local_evidence_cache_query_authorized_json(a->command_id,&meta,out,sizeof(out));
    if(result)fprintf(stderr,"unknown actor retained query failure: %s\n",out);assert(result==0);
    assert(retained_recall_rows(out,"context_pre")==1 && retained_recall_rows(out,"context_post")==1);
    assert(strstr(out,"\"process_start_key\":\"0\"") && strstr(out,"\"process_creation_filetime_100ns\":\"0\""));
    if(layout==1u)retained_recall_export("EDR_TEST_RETAINED_UNKNOWN_OUTPUT",&meta,out);
    char request[384];snprintf(request,sizeof(request),"{\"event_type\":\"file_write\",\"pid\":%u,\"process_start_key\":\"%llu\",\"process_creation_filetime_100ns\":\"%llu\"}",
        pre.pid,(unsigned long long)owner.process_start_key,(unsigned long long)owner.process_creation_filetime_100ns);
    retained_recall_contract(&meta,&owner,now,request,50);
    assert(edr_local_evidence_cache_query_authorized_json(a->command_id,&meta,out,sizeof(out))==0);
    assert(retained_recall_rows(out,NULL)==0);
    printf("retained_unknown_actor layout=%u pre=1 post=1 generation_scope_excluded=1\n",layout);
    edr_local_evidence_cache_close();edr_storage_queue_close();cleanup_test_sqlite_path(path);cleanup_test_sqlite_path(queue_path);
  }
  edr_local_evidence_cache_test_set_now_unix_ns(0);
}
static void test_retained_context_adjacent_ns(void) {
  const int64_t base=INT64_C(1793100000000000000),now=base+INT64_C(2000000000);
  for(unsigned layout=0;layout<2u;++layout) {
    char path[640],queue_path[640],out[16384];EdrBehaviorRecord owner,pre;
    assert(make_test_sqlite_path(path,sizeof(path))==0);assert(make_test_sqlite_path(queue_path,sizeof(queue_path))==0);
    edr_storage_queue_configure(16,24);assert(edr_storage_queue_open(queue_path)==EDR_OK);
    edr_pt_cache_init();edr_local_evidence_cache_test_set_now_unix_ns(base);
    assert((layout?edr_local_evidence_cache_open(path,16,24):test_open_legacy_context(path,16,24))==0);
    init_window_replacement_candidate(&owner,0,base);
    pre=owner;pre.type=EDR_EVENT_FILE_WRITE;pre.net_dport=0;pre.net_dst[0]=0;pre.detection_context[0]=0;
    pre.file_key=1u;
    pre.event_time_ns=base-INT64_C(1000000000);snprintf(pre.file_path,sizeof(pre.file_path),"C:\\UserData\\adjacent.bin");
    snprintf(pre.event_id,sizeof(pre.event_id),"adjacent-pre-one");assert(!edr_local_evidence_cache_is_candidate(&pre));
    edr_local_evidence_cache_record_behavior(&pre);
    /* Distinct object identities bypass ordinary sampling; legacy pre
     * snapshots retain their exact times, but do not store file_key. */
    pre.file_key=2u;++pre.event_time_ns;snprintf(pre.event_id,sizeof(pre.event_id),"adjacent-pre-two");edr_local_evidence_cache_record_behavior(&pre);
    edr_local_evidence_cache_record_behavior(&owner);
    edr_local_evidence_cache_close();edr_pt_cache_shutdown();
    edr_local_evidence_cache_test_set_now_unix_ns(now);assert(edr_local_evidence_cache_open(path,16,24)==0);
    EdrSoarCommandMeta meta;retained_recall_contract(&meta,&owner,now,"{\"event_type\":\"file_write\"}",50);
    EdrCommandResultAuthorization *a=&meta.result_authorization;
    int result=edr_local_evidence_cache_query_authorized_json(a->command_id,&meta,out,sizeof(out));
    if(result)fprintf(stderr,"adjacent ns query failure: %s\n",out);assert(result==0);
    assert(retained_recall_rows(out,"context_pre")==2 && retained_recall_rows(out,NULL)==2);
    /* Inspect exact decimal tokens: cJSON double parsing would itself round
     * these independently retained events to the same numeric value. */
    assert(strstr(out,"\"event_time_ns\":1793099999000000000") && strstr(out,"\"event_time_ns\":1793099999000000001"));
    if(layout==1u)retained_recall_export("EDR_TEST_RETAINED_ADJACENT_OUTPUT",&meta,out);
    printf("retained_adjacent_ns layout=%u independent_pre=2 exact_nanoseconds=1\n",layout);
    edr_local_evidence_cache_close();edr_storage_queue_close();cleanup_test_sqlite_path(path);cleanup_test_sqlite_path(queue_path);
  }
  edr_local_evidence_cache_test_set_now_unix_ns(0);
}
#endif

#if defined(EDR_HAVE_SQLITE)
static void retained_recall_replace_pre_time(const char *path, const char *before, const char *after) {
  sqlite3 *db=NULL;sqlite3_stmt *st=NULL;assert(sqlite3_open(path,&db)==SQLITE_OK);
  assert(sqlite3_prepare_v2(db,"UPDATE artifacts SET manifest_json=replace(manifest_json,?1,?2) WHERE artifact_type='p0_context_bundle';",-1,&st,NULL)==SQLITE_OK);
  assert(sqlite3_bind_text(st,1,before,-1,SQLITE_TRANSIENT)==SQLITE_OK);
  assert(sqlite3_bind_text(st,2,after,-1,SQLITE_TRANSIENT)==SQLITE_OK);
  assert(sqlite3_step(st)==SQLITE_DONE && sqlite3_changes(db)==1);
  sqlite3_finalize(st);sqlite3_close(db);
}

static void test_retained_context_scientific_time(void) {
  const int64_t base=INT64_C(1793100000000000000),now=base+INT64_C(2000000000);
  const char *first="1.793099999000000000e18",*second="1.793099999000000001e+18";
  /* Fractional nanoseconds can round to an integer double, while overflow
   * can round to an integer or infinity. None may inherit that rounding. */
  const char *invalid[]={"1.7930999990000000001e18","9.223372036854775808e18","1e1000"};
  for(unsigned layout=0;layout<2u;++layout) {
    char path[640],queue_path[640],out[16384];EdrBehaviorRecord owner,pre;
    assert(make_test_sqlite_path(path,sizeof(path))==0);assert(make_test_sqlite_path(queue_path,sizeof(queue_path))==0);
    edr_storage_queue_configure(16,24);assert(edr_storage_queue_open(queue_path)==EDR_OK);
    edr_pt_cache_init();edr_local_evidence_cache_test_set_now_unix_ns(base);
    assert((layout?edr_local_evidence_cache_open(path,16,24):test_open_legacy_context(path,16,24))==0);
    init_window_replacement_candidate(&owner,0,base);
    pre=owner;pre.type=EDR_EVENT_FILE_WRITE;pre.net_dport=0;pre.net_dst[0]=0;pre.detection_context[0]=0;
    pre.file_key=1u;pre.event_time_ns=base-INT64_C(1000000000);
    snprintf(pre.file_path,sizeof(pre.file_path),"C:\\UserData\\scientific-time.bin");
    snprintf(pre.event_id,sizeof(pre.event_id),"scientific-pre-one");assert(!edr_local_evidence_cache_is_candidate(&pre));
    edr_local_evidence_cache_record_behavior(&pre);
    pre.file_key=2u;++pre.event_time_ns;snprintf(pre.event_id,sizeof(pre.event_id),"scientific-pre-two");
    edr_local_evidence_cache_record_behavior(&pre);edr_local_evidence_cache_record_behavior(&owner);
    edr_local_evidence_cache_close();edr_pt_cache_shutdown();
    /* Model the supported historical JSON representation without parsing it
     * through cJSON: that would itself erase the independent nanosecond. */
    retained_recall_replace_pre_time(path,"1793099999000000000",first);
    retained_recall_replace_pre_time(path,"1793099999000000001",second);
    sqlite3 *db=NULL;sqlite3_stmt *st=NULL;assert(sqlite3_open(path,&db)==SQLITE_OK);
    assert(sqlite3_prepare_v2(db,"SELECT json_array_length(manifest_json,'$.context'),json_type(manifest_json,'$.context[0].event_time_ns'),json_type(manifest_json,'$.context[1].event_time_ns') FROM artifacts WHERE artifact_type='p0_context_bundle';",-1,&st,NULL)==SQLITE_OK);
    assert(sqlite3_step(st)==SQLITE_ROW && sqlite3_column_int(st,0)==2);
    assert(!strcmp((const char *)sqlite3_column_text(st,1),"real") && !strcmp((const char *)sqlite3_column_text(st,2),"real"));
    sqlite3_finalize(st);sqlite3_close(db);
    edr_local_evidence_cache_test_set_now_unix_ns(now);assert(edr_local_evidence_cache_open(path,16,24)==0);
    EdrSoarCommandMeta meta;retained_recall_contract(&meta,&owner,now,"{\"event_type\":\"file_write\"}",50);
    EdrCommandResultAuthorization *a=&meta.result_authorization;
    int result=edr_local_evidence_cache_query_authorized_json(a->command_id,&meta,out,sizeof(out));
    if(result)fprintf(stderr,"scientific time query failure: %s\n",out);assert(result==0);
    assert(retained_recall_rows(out,"context_pre")==2 && retained_recall_rows(out,NULL)==2);
    assert(strstr(out,"\"event_time_ns\":1793099999000000000") && strstr(out,"\"event_time_ns\":1793099999000000001"));
    const char *previous=first;
    for(unsigned i=0;i<sizeof(invalid)/sizeof(invalid[0]);++i) {
      retained_recall_replace_pre_time(path,previous,invalid[i]);previous=invalid[i];
      assert(edr_local_evidence_cache_query_authorized_json(a->command_id,&meta,out,sizeof(out))<0);
      assert(strstr(out,"pre-context event invalid"));
    }
    /* A failed recall must leave the connection usable for a repaired row. */
    retained_recall_replace_pre_time(path,previous,first);
    assert(edr_local_evidence_cache_query_authorized_json(a->command_id,&meta,out,sizeof(out))==0);
    assert(retained_recall_rows(out,"context_pre")==2);
    printf("retained_scientific_time layout=%u independent_pre=2 exact_nanoseconds=1 fractional_rejected=1 overflow_rejected=1\n",layout);
    edr_local_evidence_cache_close();edr_storage_queue_close();cleanup_test_sqlite_path(path);cleanup_test_sqlite_path(queue_path);
  }
  edr_local_evidence_cache_test_set_now_unix_ns(0);
}
#endif
