/* Actual bounded producer -> tar -> command owner -> outbox, synthetic files
 * only. No Agent init, collectors, transport grants or service loop. */
#include "edr/response.h"
#include "edr/response_utils.h"
#include "edr/command_state.h"
#include "edr/command_executor.h"
#include "edr/command_cancel.h"
#include "edr/storage_reservation.h"
#include "edr/storage_physical_guard.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef _WIN32
#include <windows.h>
#define env(k,v) _putenv_s(k,v)
#else
#include <unistd.h>
#define env(k,v) setenv(k,v,1)
#endif

static void start_owner(const char *id,EdrSoarCommandMeta *meta) {
  memset(meta,0,sizeof(*meta));snprintf(meta->idempotency_key,sizeof(meta->idempotency_key),"%s",id);
  meta->issued_at_unix_ms=(int64_t)time(NULL)*1000LL;meta->deadline_ms=300000;
  int retry=0;assert(edr_command_state_begin(id,"collect_forensic",meta,&retry,NULL)==0);
}

int main(void) {
  char root[700];
#ifdef _WIN32
  char temp[MAX_PATH];assert(GetTempPathA(sizeof(temp),temp));
  assert(GetTempFileNameA(temp,"efs",0,root));assert(DeleteFileA(root));
#else
  strcpy(root,"/tmp/edr-forensic-stage.XXXXXX");assert(mkdtemp(root));
#endif
  assert(response_mkdir_p(root)==0);
  char path[1000];
  snprintf(path,sizeof(path),"%s/state.jsonl",root);env("EDR_COMMAND_STATE_DB",path);
  snprintf(path,sizeof(path),"%s/inbox",root);env("EDR_COMMAND_INBOX_DIR",path);
  snprintf(path,sizeof(path),"%s/outbox",root);env("EDR_UPLOAD_OUTBOX_DIR",path);
  snprintf(path,sizeof(path),"%s/audit.log",root);env("EDR_CMD_AUDIT_PATH",path);
  env("EDR_FORENSIC_OUT",root);env("EDR_CMD_ENABLED","1");env("EDR_FORENSIC_COPY_PATHS","1");
  env("EDR_FORENSIC_COLLECTOR","1");env("EDR_FORENSIC_COLLECTOR_STRICT","0");
  snprintf(path,sizeof(path),"%s/synthetic.txt",root);
  FILE *file=fopen(path,"wb");assert(file);assert(fputs("bounded synthetic forensic evidence",file)>=0);assert(!fclose(file));
  EdrCommandStateCapacityStats stats;assert(edr_command_state_get_capacity_stats(&stats)==0);
  EdrSoarCommandMeta meta;start_owner("bounded",&meta);
  edr_response_collect_forensic("bounded",(const uint8_t *)path,strlen(path),&meta);
  edr_command_executor_shutdown();
  assert(edr_command_state_get_capacity_stats(&stats)==0 && !stats.artifact_reserved_bytes);
  char artifact[1000];snprintf(artifact,sizeof(artifact),"%s/bounded.tgz",root);
  uint64_t bytes=edr_storage_file_size(artifact);assert(bytes>0 && bytes<64u*1024u*1024u);
  snprintf(artifact,sizeof(artifact),"%s/bounded.tgz.staging",root);assert(edr_storage_file_size(artifact)==0);
  assert(edr_command_state_has_final("bounded",&meta)==0); /* no false upload success */
  EdrSoarCommandMeta owned;assert(edr_command_state_artifact_meta("bounded","collect_forensic",&owned)==1);
  env("EDR_FORENSIC_COLLECTOR_STRICT","1");start_owner("strict",&meta);
  edr_response_collect_forensic("strict",(const uint8_t *)path,strlen(path),&meta);
  assert(edr_command_state_has_final("strict",&meta)==1);
  snprintf(artifact,sizeof(artifact),"%s/strict.work",root);assert(edr_storage_file_size(artifact)==0);
  assert(!edr_storage_artifact_reserved());
  env("EDR_FORENSIC_COLLECTOR_STRICT","0");start_owner("expired",&meta);
  meta.issued_at_unix_ms=1;meta.deadline_ms=1;
  edr_response_collect_forensic("expired",(const uint8_t *)path,strlen(path),&meta);
  assert(edr_command_state_has_final("expired",&meta)==1 && !edr_storage_artifact_reserved());
  snprintf(artifact,sizeof(artifact),"%s/expired.work/copied_00",root);
  uint64_t expired_bytes=edr_storage_file_size(artifact);
  fprintf(stderr,"expired command copied_bytes=%llu (required=0)\n",(unsigned long long)expired_bytes);
  assert(expired_bytes==0);
  start_owner("cancelled",&meta);
  assert(edr_command_cancel_begin("cancelled") && edr_command_cancel_request("cancelled"));
  edr_response_collect_forensic("cancelled",(const uint8_t *)path,strlen(path),&meta);
  edr_command_cancel_end("cancelled");
  assert(edr_command_state_has_final("cancelled",&meta)==1 && !edr_storage_artifact_reserved());
  snprintf(artifact,sizeof(artifact),"%s/cancelled.work/copied_00",root);
  assert(edr_storage_file_size(artifact)==0);
  EdrCommandStateRecord cancelled;int cancelled_retry=0;
  assert(edr_command_state_begin("cancelled","collect_forensic",&meta,&cancelled_retry,&cancelled)==EDR_COMMAND_STATE_BEGIN_DUP_FINAL);
  assert(strstr(cancelled.detail,"copy cancelled") && !strstr(cancelled.detail,root));
  start_owner("unsupported",&meta);
  edr_response_collect_forensic("unsupported",(const uint8_t *)root,strlen(root),&meta);
  assert(edr_command_state_has_final("unsupported",&meta)==1 && !edr_storage_artifact_reserved());
  EdrCommandStateRecord record;int retry=0;
  assert(edr_command_state_begin("unsupported","collect_forensic",&meta,&retry,&record)==EDR_COMMAND_STATE_BEGIN_DUP_FINAL);
  assert(strstr(record.detail,"source unavailable or unsupported") && !strstr(record.detail,root));
  edr_command_executor_shutdown();
  printf("baseline_producer archive_bytes=%llu stage_published=1 false_upload_success=0 strict_external_refused=1 expired_writer_not_started=1 bounded_copy_cause_terminal=1\n",
      (unsigned long long)bytes);
  return 0;
}
