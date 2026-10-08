#include "edr/command_state.h"
#include "edr/command_result_json.h"
#include "edr/egress_request_policy.h"
#include "edr/sha256.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef _WIN32
#include <process.h>
#include <windows.h>
#define pid _getpid
#define env(k,v) _putenv_s(k,v)
#else
#include <unistd.h>
#include <sys/wait.h>
#define pid getpid
#define env(k,v) setenv(k,v,1)
#endif
#define CHECK(x) do {if(!(x)){fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#x);exit(1);}}while(0)
void edr_local_evidence_cache_record_command_result(const char *a,const char *b,const char *c,
    int d,int e,const char *f,const char *g) {(void)a;(void)b;(void)c;(void)d;(void)e;(void)f;(void)g;}
static EdrSoarCommandMeta task(const char *id) {
  EdrSoarCommandMeta m={0};
  snprintf(m.result_authorization.command_id,sizeof(m.result_authorization.command_id),"%s",id);
  strcpy(m.result_authorization.command_type,"noop");strcpy(m.result_authorization.tenant_id,"tenant");strcpy(m.result_authorization.endpoint_id,"ep");
  m.result_authorization.expires_unix_ms=(int64_t)time(NULL)*1000+600000;
  CHECK(edr_command_result_bind_contract(&m.result_authorization,(const uint8_t*)"{}",2,(int64_t)time(NULL)*1000)==0);
  return m;
}
static EdrCommandStateRecord *record(const char *id) {
  EdrCommandStateRecord *r=calloc(1,sizeof(*r));CHECK(r);
  CHECK(edr_command_state_begin(id,"noop",NULL,NULL,r)==EDR_COMMAND_STATE_BEGIN_DUP_FINAL);return r;
}
static void finish(const char *id) {
  EdrSoarCommandMeta m=task(id);
  CHECK(edr_command_state_begin(id,"noop",&m,NULL,NULL)==EDR_COMMAND_STATE_BEGIN_READY);
  CHECK(edr_command_state_finish(id,"noop",&m,"ok",1,0,"synthetic diagnostic","",1)==0);
}
static unsigned char *file_bytes(const char *path,size_t *size) {
  FILE *f=fopen(path,"rb");CHECK(f&&fseek(f,0,SEEK_END)==0);long n=ftell(f);CHECK(n>=0);rewind(f);
  unsigned char *b=malloc((size_t)n+1);CHECK(b&&fread(b,1,(size_t)n,f)==(size_t)n);CHECK(!ferror(f)&&fclose(f)==0);
  *size=(size_t)n;b[n]=0;return b;
}
static void run_child(const char *exe,const char *mode,const char *path) {
#ifdef _WIN32
  CHECK(_spawnl(_P_WAIT,exe,exe,mode,path,NULL)==0);
#else
  pid_t child=fork();CHECK(child>=0);
  if(!child){execl(exe,exe,mode,path,(char*)NULL);_exit(127);}
  int status;CHECK(waitpid(child,&status,0)==child&&WIFEXITED(status)&&WEXITSTATUS(status)==0);
#endif
}
static void assert_corruption_preserved(const char *exe,const char *path,const char *corrupt) {
  size_t clean_n,before_n,after_n;unsigned char *clean=file_bytes(path,&clean_n);
  FILE *f=fopen(path,"ab");CHECK(f&&fputs(corrupt,f)>=0&&fclose(f)==0);
  unsigned char *before=file_bytes(path,&before_n);
  run_child(exe,"--compact",path);unsigned char *after=file_bytes(path,&after_n);
  CHECK(before_n==after_n&&!memcmp(before,after,before_n));free(before);free(after);
  /* Restore only this test's private fixture before the next independent case. */
  f=fopen(path,"wb");CHECK(f&&fwrite(clean,1,clean_n,f)==clean_n&&fclose(f)==0);free(clean);
}
static void verify_owners(void) {
  EdrCommandStateRecord *r=record("compact-acked");CHECK(!r->report_pending);
  EdrSoarCommandMeta m=task("compact-acked");
  CHECK(edr_command_state_finish("compact-acked","noop",&m,"ok",1,0,"synthetic diagnostic","",1)==0);
  CHECK(edr_command_state_finish("compact-acked","noop",&m,"failed",3,1,"different","",1)!=0);
  free(r);r=record("compact-acked");CHECK(!r->report_pending);
  char *body=edr_command_result_http_json("ep","test",r->command_id,r->command_type,r->execution_status,r->exit_code,r->detail,(int64_t)time(NULL)*1000,"","","");
  CHECK(body&&!edr_command_state_result_authorized("tenant","ep",body,strlen(body)));free(body);free(r);
  r=record("compact-pending");CHECK(r->report_pending&&!r->report_policy_held);free(r);
  r=record("compact-held");CHECK(r->report_pending&&r->report_policy_held&&!strcmp(r->report_last_error,"synthetic policy hold"));free(r);
  for(unsigned i=0;i<160;i++){char id[64];snprintf(id,sizeof(id),"compact-noise-%u",i);r=record(id);CHECK(r->report_pending);free(r);}
}
static void verify_soft_floor(const char *path) {
  size_t base_n,before_n,after_n;unsigned char *base=file_bytes(path,&base_n);
  CHECK(base_n>131072);unsigned char *newline=memchr(base,'\n',base_n);CHECK(newline);
  size_t line_n=(size_t)(newline-base)+1;
  /* Tiny retry-history appends cannot repeatedly rescan/replace a file whose
   * necessary owner floor already exceeds the emergency threshold. */
  for(unsigned i=0;i<3;i++) {
    FILE *f=fopen(path,"ab");CHECK(f&&fwrite(base,1,line_n,f)==line_n&&fclose(f)==0);
    unsigned char *before=file_bytes(path,&before_n);edr_command_state_compact_if_needed();
    unsigned char *after=file_bytes(path,&after_n);
    CHECK(before_n==after_n&&!memcmp(before,after,before_n));free(before);free(after);
  }
  /* Significant new superseded history still triggers emergency compaction
   * during the interval, and no necessary owner is removed. */
  FILE *f=fopen(path,"ab");CHECK(f);
  for(size_t n=0;n<65536;n+=line_n)CHECK(fwrite(base,1,line_n,f)==line_n);
  CHECK(fclose(f)==0);edr_command_state_compact_if_needed();
  unsigned char *after=file_bytes(path,&after_n);CHECK(after_n==base_n);free(after);free(base);
  verify_owners();
}
static int owner_allows(const EdrCommandStateRecord *r) {
  char *body=edr_command_result_http_json("ep","test",r->command_id,r->command_type,
    r->execution_status,r->exit_code,r->detail,(int64_t)time(NULL)*1000,"","","");
  CHECK(body);int ok=edr_command_state_result_authorized("tenant","ep",body,strlen(body));free(body);return ok;
}
static void verify_many_ack_collection(void) {
  EdrCommandStateRecord *batch=calloc(2,sizeof(*batch));CHECK(batch);
  int n=edr_command_state_collect_pending(batch,2);CHECK(n==2);
  for(int i=0;i<n;i++){CHECK(!strncmp(batch[i].command_id,"late-pending-",13)&&owner_allows(&batch[i]));}
  free(batch);
}
static void test_many_ack_collection(const char *exe,const char *directory) {
  char path[1024],lock[1100];snprintf(path,sizeof(path),"%s/many_ack.jsonl",directory);
  CHECK(env("EDR_COMMAND_STATE_DB",path)==0);CHECK(env("EDR_COMMAND_STATE_MAX_BYTES","104857600")==0);
  for(unsigned i=0;i<520;i++) {
    char id[64];snprintf(id,sizeof(id),"many-ack-%u",i);finish(id);
    EdrCommandStateRecord *r=record(id);CHECK(edr_command_state_mark_reported(r)==0);free(r);
  }
  for(unsigned i=0;i<3;i++){char id[64];snprintf(id,sizeof(id),"late-pending-%u",i);finish(id);}
  CHECK(env("EDR_COMMAND_STATE_MAX_BYTES","65536")==0);edr_command_state_compact_if_needed();
  verify_many_ack_collection();run_child(exe,"--many",path);
  EdrCommandStateRecord *batch=calloc(2,sizeof(*batch));CHECK(batch);
  for(unsigned turn=0;turn<2;turn++) {
    int n=edr_command_state_collect_pending(batch,2);CHECK(n==(turn==0?2:1));
    for(int i=0;i<n;i++) {
      CHECK(!strncmp(batch[i].command_id,"late-pending-",13)&&owner_allows(&batch[i]));
      CHECK(edr_command_state_mark_reported(&batch[i])==0);CHECK(!owner_allows(&batch[i]));
    }
  }
  CHECK(edr_command_state_collect_pending(batch,2)==0);free(batch);
  EdrCommandStateRecord *r=record("many-ack-519");CHECK(!r->report_pending);free(r);
  remove(path);snprintf(lock,sizeof(lock),"%s.lock",path);remove(lock);
}
int main(int argc,char **argv) {
  if(argc==3) {
    CHECK(env("EDR_COMMAND_STATE_DB",argv[2])==0);
    if(!strcmp(argv[1],"--verify"))verify_owners();
    else if(!strcmp(argv[1],"--compact"))edr_command_state_compact_if_needed();
    else if(!strcmp(argv[1],"--many"))verify_many_ack_collection();
    else CHECK(0);return 0;
  }
  char directory[256],path[1024],lock[1100];
  snprintf(directory,sizeof(directory),"./command-compaction-%ld",(long)pid());
  snprintf(path,sizeof(path),"%s/command_state.jsonl",directory);
  remove(path);snprintf(lock,sizeof(lock),"%s.lock",path);remove(lock);
  CHECK(env("EDR_COMMAND_STATE_DB",path)==0);CHECK(env("EDR_COMMAND_STATE_MAX_BYTES","104857600")==0);
  finish("compact-acked");EdrCommandStateRecord *r=record("compact-acked");CHECK(edr_command_state_mark_reported(r)==0);free(r);
  finish("compact-pending");finish("compact-held");r=record("compact-held");CHECK(edr_command_state_mark_report_held(r,"synthetic policy hold")==0);free(r);
  for(unsigned i=0;i<160;i++){char id[64];snprintf(id,sizeof(id),"compact-noise-%u",i);finish(id);}
  size_t before_n,after_n;unsigned char *before=file_bytes(path,&before_n);CHECK(before_n>131072);
  CHECK(env("EDR_COMMAND_STATE_MAX_BYTES","65536")==0);CHECK(env("EDR_COMMAND_STATE_COMPACT_KEEP_LINES","64")==0);CHECK(env("EDR_COMMAND_STATE_COMPACT_TARGET_BYTES","32768")==0);
  edr_command_state_compact_if_needed();unsigned char *after=file_bytes(path,&after_n);CHECK(after_n<before_n);
  verify_owners();
  verify_soft_floor(path);run_child(argv[0],"--verify",path);
  free(before);free(after);
  /* Corrupt/truncated state is not a compaction opportunity. Keep every byte
   * for the existing recovery owner rather than replacing it with a suffix. */
  assert_corruption_preserved(argv[0],path,"{\"record\":\"command_state\",\"final\":1,\"command_id\":\"compact-acked\",\"command_id\":\"compact-pending\",\"idempotency_key\":\"\"}\n");
  assert_corruption_preserved(argv[0],path,"{\"record\":\"command_state\",\"final\":1,\"command_id\":\"compact-acked\",\"idempotency_key\":\"\"} {}\n");
  assert_corruption_preserved(argv[0],path,"{\"record\":\"command_state\",\"final\":1,\"command_id\":\"compact-acked\\u0000-other\",\"idempotency_key\":\"\"}\n");
  assert_corruption_preserved(argv[0],path,"{\"record\":\"incomplete");
  remove(path);remove(lock);
  test_many_ack_collection(argv[0],directory);
  puts("command compaction: pending/held/ACK owners survive compaction and process restart; replay cannot reopen ACK; corrupt owner/tail retained; soft-floor retry scans bounded; >512 ACK owners cannot starve pending batches");return 0;
}
