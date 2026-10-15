/* Synthetic-only harness. Run through run_queue_retention_comparison.py. */
#include "edr/storage_queue.h"
#include "edr/egress_batch_policy.h"
#include "edr/transport_sink.h"
#include "edr/sha256.h"
#include "edr/types.h"
#include "edr/v1/event.pb.h"
#include <pb_encode.h>
#include <pb_decode.h>
#include <sqlite3.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/resource.h>
#include <sys/stat.h>

static time_t fixture_time=1700000000;
static unsigned send_calls;
static uint64_t peak_physical;
time_t benchmark_time(time_t *out) { if(out) *out=fixture_time;return fixture_time; }
uint64_t benchmark_total_changes(void);
int edr_ingest_http_configured(void){return 1;}
int edr_ingest_http_circuit_open(void){return 0;}
int edr_ingest_http_telemetry_deferred(void){return 0;}
int edr_transport_v2_report_events(const char *id,const uint8_t *head,size_t hlen,const uint8_t *payload,size_t len) {
  (void)id;(void)head;(void)hlen;(void)payload;(void)len;send_calls++;return -1;
}
static void wr(uint8_t *p,uint32_t n){for(unsigned i=0;i<4u;i++)p[i]=(uint8_t)(n>>(8u*i));}
static uint32_t rd(const uint8_t *p){return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;}
static uint64_t file_bytes(const char *path){struct stat s;return stat(path,&s)==0?(uint64_t)s.st_size:0;}
static uint64_t physical(const char *path,uint64_t *db,uint64_t *wal,uint64_t *shm){
  char side[512];*db=file_bytes(path);snprintf(side,sizeof(side),"%s-wal",path);*wal=file_bytes(side);
  snprintf(side,sizeof(side),"%s-shm",path);*shm=file_bytes(side);uint64_t total=*db+*wal+*shm;
  if(total>peak_physical)peak_physical=total;return total;
}
static edr_v1_BehaviorEvent *make_wire(unsigned index,uint8_t wire[131072]) {
  edr_v1_BehaviorEvent *ev=calloc(1,sizeof(*ev));assert(ev);
  snprintf(ev->event_id,sizeof(ev->event_id),"event-%08u",index);
  strcpy(ev->endpoint_id,"synthetic-endpoint");strcpy(ev->tenant_id,"synthetic-tenant");
  ev->event_time_ns=(INT64_C(1700000000)+(index/4u)*3601+(index%4u)*60)*INT64_C(1000000000);
  ev->type=EDR_EVENT_PROCESS_CREATE;ev->pid=1000u+index;ev->ppid=4u;
  ev->process_start_key=10000u+index;ev->process_creation_filetime_100ns=UINT64_C(133444444444444444)+index;
  ev->has_parent_pid_state=true;ev->parent_pid_state=1u;
  strcpy(ev->parent_name,"ordinary-parent");strcpy(ev->parent_path,"synthetic-parent-path");
  ev->has_process_context=true;ev->process_context.has_parent_cmdline=true;
  memset(ev->cmdline,'c',90000u);ev->cmdline[90000]='\0';
  strcpy(ev->ave_result_json,"{\"p0_disposition\":\"NOT_EVALUABLE\",\"source_contract_version\":\"p0-source-only-v2\","
    "\"stage\":\"pre_evaluation\",\"gate_id\":\"P0_PROCESS_EVIDENCE_GATE\",\"reason\":\"evidence_enrichment_timeout\","
    "\"parent_process_start_key\":\"111\",\"parent_process_creation_filetime_100ns\":\"133444444000000000\"}");
  size_t parent=30000u;
  for(unsigned attempt=0;attempt<3u;attempt++){
    memset(ev->process_context.parent_cmdline,'p',parent);ev->process_context.parent_cmdline[parent]='\0';
    pb_ostream_t out=pb_ostream_from_buffer(wire+16,131072u-16u);
    assert(pb_encode(&out,edr_v1_BehaviorEvent_fields,ev));
    if(out.bytes_written==131072u-16u)break;
    assert(out.bytes_written<131072u-16u);parent+=131072u-16u-out.bytes_written;
  }
  wr(wire,EDR_TRANSPORT_BATCH_MAGIC_RAW);wr(wire+4,1u);wr(wire+8,131072u-12u);wr(wire+12,131072u-16u);
  return ev;
}
static EdrError commit(EdrStorageQueueP0SourceOnlyLatch *latch,const edr_v1_BehaviorEvent *ev,const uint8_t *wire) {
#ifdef LOCAL_TYPED
  EdrStorageQueueLocalEvidenceOwner owner={0};owner.version=1u;
  owner.diagnostic_reason="evidence_enrichment_timeout";owner.endpoint_id=ev->endpoint_id;owner.tenant_id=ev->tenant_id;
  owner.event_time_ns=ev->event_time_ns;owner.event_type=ev->type;owner.pid=ev->pid;owner.parent_pid=ev->ppid;
  owner.process_start_key=ev->process_start_key;owner.process_creation_filetime_100ns=ev->process_creation_filetime_100ns;
  owner.parent_process_start_key=111u;owner.parent_process_creation_filetime_100ns=UINT64_C(133444444000000000);
  return edr_storage_queue_p0_source_only_commit_local_typed(latch,ev->event_id,ev->event_id,wire,131072u,0,0,&owner);
#else
  return edr_storage_queue_p0_source_only_commit_local(latch,ev->event_id,ev->event_id,wire,131072u,0,0);
#endif
}
static void inventory(const char *path,unsigned round,unsigned accepted,unsigned refused,unsigned total,unsigned rejected) {
  sqlite3 *db=NULL;sqlite3_stmt *st=NULL;assert(sqlite3_open(path,&db)==SQLITE_OK);
  assert(sqlite3_prepare_v2(db,"SELECT payload FROM event_queue WHERE status='local_evidence';",-1,&st,NULL)==SQLITE_OK);
  uint64_t rows=0,bytes=0,complete=0;int64_t first=INT64_MAX,last=0;
  while(sqlite3_step(st)==SQLITE_ROW){
    const uint8_t *wire=sqlite3_column_blob(st,0);int len=sqlite3_column_bytes(st,0);assert(len==131072);
    edr_v1_BehaviorEvent *ev=calloc(1,sizeof(*ev));assert(ev);pb_istream_t in=pb_istream_from_buffer(wire+16,rd(wire+12));
    assert(pb_decode(&in,edr_v1_BehaviorEvent_fields,ev));rows++;bytes+=(uint64_t)len;
    if(ev->event_time_ns<first)first=ev->event_time_ns;if(ev->event_time_ns>last)last=ev->event_time_ns;
    unsigned index;assert(sscanf(ev->event_id,"event-%u",&index)==1);
    if(ev->pid==1000u+index && ev->process_start_key==10000u+index &&
       ev->process_creation_filetime_100ns==UINT64_C(133444444444444444)+index && ev->ppid==4u &&
       ev->has_parent_pid_state && ev->parent_pid_state==1u && strlen(ev->cmdline)==90000u &&
       strlen(ev->process_context.parent_cmdline)>30000u && strstr(ev->ave_result_json,"133444444000000000"))complete++;
    free(ev);
  }
  sqlite3_finalize(st);assert(sqlite3_close(db)==SQLITE_OK);
  uint64_t dbb,wal,shm;physical(path,&dbb,&wal,&shm);
  printf("{\"window\":%u,\"admitted\":%u,\"rejected\":%u,\"total_admitted\":%u,\"total_rejected\":%u,"
     "\"retained_rows\":%llu,\"payload_bytes\":%llu,\"chain_complete_rows\":%llu,"
     "\"event_min_ns\":%lld,\"event_max_ns\":%lld,\"freshest_age_s\":%lld,"
     "\"db_bytes\":%llu,\"wal_bytes\":%llu,\"shm_bytes\":%llu,\"sampled_physical_peak_bytes\":%llu,"
     "\"sqlite_total_changes_proxy\":%llu,\"source_upload_calls\":%u}\n",round,accepted,refused,total,rejected,
     (unsigned long long)rows,(unsigned long long)bytes,(unsigned long long)complete,
     (long long)(rows?first:0),(long long)last,(long long)(last?fixture_time-last/1000000000:0),
     (unsigned long long)dbb,(unsigned long long)wal,(unsigned long long)shm,(unsigned long long)peak_physical,
     (unsigned long long)benchmark_total_changes(),send_calls);
  assert(rows==complete);
}
int main(int argc,char **argv) {
  assert(argc==2);const char *path=argv[1];remove(path);uint8_t wire[131072],previous_wire[131072];
  edr_v1_BehaviorEvent *previous=NULL;unsigned total=0,rejected=0;
  EdrSha256Ctx input_hash;edr_sha256_init(&input_hash);
  edr_storage_queue_configure(1u,1u);assert(edr_storage_queue_open(path)==EDR_OK);
  for(unsigned round=0;round<12u;round++){
    unsigned accepted=0,refused=0;
    for(unsigned offset=0;offset<4u;offset++){
      unsigned index=round*4u+offset;fixture_time=1700000000+(time_t)round*3601+(time_t)offset*60;
#ifdef LOCAL_TYPED
      edr_storage_queue_test_set_local_retention_elapsed((uint64_t)round*3601u+offset*60u);
#endif
      edr_storage_queue_test_run_cleanup();
      edr_v1_BehaviorEvent *ev=make_wire(index,wire);EdrStorageQueueP0SourceOnlyLatch latch;
      edr_sha256_update(&input_hash,wire,sizeof(wire));
      char reason[96];assert(!edr_egress_batch_validate(wire,12,wire+12,131060u,reason,sizeof(reason)));
      assert(edr_storage_queue_p0_source_only_latch_prepare_local(&latch)==EDR_OK);
      EdrError result=commit(&latch,ev,wire);
      if(result==EDR_OK){accepted++;total++;free(previous);previous=ev;memcpy(previous_wire,wire,sizeof(wire));}
      else {assert(result==EDR_ERR_QUEUE_FULL && previous);refused++;rejected++;
        assert(commit(&latch,previous,previous_wire)==EDR_OK);free(ev);}
      uint64_t db,wal,shm;physical(path,&db,&wal,&shm);
    }
    edr_storage_queue_poll_drain();assert(send_calls==0u);inventory(path,round,accepted,refused,total,rejected);
  }
  uint8_t terminal[20]={0x42,0x41,0x54,0x31,1,0,0,0,8,0,0,0,4,0,0,0,0xa0,0xa1,0xa5,0x5a};
  EdrError admitted=edr_storage_queue_enqueue("terminal-20",terminal,sizeof(terminal),0,1);
  sqlite3 *db=NULL;sqlite3_stmt *st=NULL;assert(sqlite3_open(path,&db)==SQLITE_OK);
  assert(sqlite3_prepare_v2(db,"SELECT payload FROM event_queue WHERE batch_id='terminal-20';",-1,&st,NULL)==SQLITE_OK);
  int readable=sqlite3_step(st)==SQLITE_ROW && sqlite3_column_bytes(st,0)==20 && !memcmp(sqlite3_column_blob(st,0),terminal,20);
  sqlite3_finalize(st);sqlite3_close(db);struct rusage r;assert(getrusage(RUSAGE_SELF,&r)==0);
  uint8_t digest[32];char input_hex[65];static const char hex[]="0123456789abcdef";edr_sha256_final(&input_hash,digest);
  for(unsigned i=0;i<32u;i++){input_hex[2*i]=hex[digest[i]>>4];input_hex[2*i+1]=hex[digest[i]&15u];}input_hex[64]=0;
  printf("{\"terminal20_admitted\":%s,\"terminal20_exact_readable\":%s,\"source_upload_calls\":%u,"
      "\"cpu_user_s\":%.6f,\"cpu_system_s\":%.6f,\"input_blocks\":%ld,\"output_blocks\":%ld,\"max_rss_raw\":%ld,"
      "\"input_stream_sha256\":\"%s\",\"sqlite_version\":\"%s\","
      "\"io_limit\":\"OS block counters are unavailable as zero on this host; SQLite total_changes and sampled file peaks are proxies, not measured device write amplification\"}\n",
      admitted==EDR_OK?"true":"false",readable?"true":"false",send_calls,
      r.ru_utime.tv_sec+r.ru_utime.tv_usec/1000000.,r.ru_stime.tv_sec+r.ru_stime.tv_usec/1000000.,r.ru_inblock,r.ru_oublock,r.ru_maxrss,input_hex,sqlite3_libversion());
  free(previous);edr_storage_queue_close();return 0;
}
