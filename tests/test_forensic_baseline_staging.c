/* Actual bounded producer -> tar -> command owner -> outbox, synthetic files
 * only. No Agent init, collectors, transport grants or service loop. */
#include "edr/response.h"
#include "edr/forensic_worker.h"
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
#include <io.h>
#define env(k,v) _putenv_s(k,v)
#else
#include <unistd.h>
#include <sys/file.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <signal.h>
#define env(k,v) setenv(k,v,1)
#endif

static void start_owner(const char *id,EdrSoarCommandMeta *meta) {
  memset(meta,0,sizeof(*meta));snprintf(meta->idempotency_key,sizeof(meta->idempotency_key),"%s",id);
  meta->issued_at_unix_ms=(int64_t)time(NULL)*1000LL;meta->deadline_ms=300000;
  int retry=0;assert(edr_command_state_begin(id,"collect_forensic",meta,&retry,NULL)==0);
}

#ifdef _WIN32
static void test_blocked_owner(const char *root,const char *source) {
  EdrSoarCommandMeta meta;start_owner("blocked-owner",&meta);
  char path[1000];snprintf(path,sizeof(path),"%s/state.jsonl.lock",root);
  FILE *lock=fopen(path,"r+b");assert(lock);
  HANDLE handle=(HANDLE)_get_osfhandle(_fileno(lock));OVERLAPPED overlap={0};
  assert(LockFileEx(handle,LOCKFILE_EXCLUSIVE_LOCK,0,1,0,&overlap));
  char exe[32768],command[35000];assert(GetModuleFileNameA(NULL,exe,sizeof(exe)));
  assert(snprintf(command,sizeof(command),"\"%s\" --blocked-command \"%s\"",exe,source)<(int)sizeof(command));
  STARTUPINFOA startup={0};PROCESS_INFORMATION process={0};startup.cb=sizeof(startup);
  ULONGLONG before=GetTickCount64();
  assert(CreateProcessA(exe,command,NULL,NULL,FALSE,CREATE_NO_WINDOW,NULL,NULL,&startup,&process));
  DWORD waited=WaitForSingleObject(process.hProcess,5000),code=1;
  if(waited!=WAIT_OBJECT_0){TerminateProcess(process.hProcess,1);WaitForSingleObject(process.hProcess,1000);}
  assert(GetExitCodeProcess(process.hProcess,&code));
  ULONGLONG elapsed=GetTickCount64()-before;
  CloseHandle(process.hThread);CloseHandle(process.hProcess);
  assert(UnlockFileEx(handle,0,1,0,&overlap) && !fclose(lock));
  fprintf(stderr,"blocked_owner elapsed_ms=%llu exit=%lu\n",(unsigned long long)elapsed,(unsigned long)code);
  assert(waited==WAIT_OBJECT_0 && code==0 && elapsed<2500);
  assert(edr_command_state_has_final("blocked-owner",&meta)==0);
}
#else
static void test_blocked_owner(const char *root, const char *source) {
  EdrSoarCommandMeta meta;start_owner("blocked-owner",&meta);meta.deadline_ms=1000;
  char path[1000];snprintf(path,sizeof(path),"%s/state.jsonl.lock",root);
  FILE *lock=fopen(path,"r+b");assert(lock && !flock(fileno(lock),LOCK_EX));
  pid_t child=fork();assert(child>=0);
  if(!child) {
    fclose(lock);alarm(5);
    edr_response_collect_forensic("blocked-owner",(const uint8_t *)source,strlen(source),&meta);
    _exit(0);
  }
  struct timespec before,after;assert(!clock_gettime(CLOCK_MONOTONIC,&before));
  int status=0;assert(waitpid(child,&status,0)==child);
  assert(!clock_gettime(CLOCK_MONOTONIC,&after));
  double elapsed=after.tv_sec-before.tv_sec+(after.tv_nsec-before.tv_nsec)/1e9;
  assert(!flock(fileno(lock),LOCK_UN) && !fclose(lock));
  fprintf(stderr,"blocked_owner elapsed=%.3f exited=%d status=%d\n",elapsed,WIFEXITED(status),status);
  assert(WIFEXITED(status) && WEXITSTATUS(status)==0 && elapsed<2.5);
  assert(edr_command_state_has_final("blocked-owner",&meta)==0);
}

static void test_blocked_audit(const char *root,const char *source) {
  EdrSoarCommandMeta meta;start_owner("blocked-audit",&meta);meta.deadline_ms=1000;
  char path[1000];snprintf(path,sizeof(path),"%s/audit.pipe",root);assert(!mkfifo(path,0600));
  env("EDR_CMD_AUDIT_PATH",path);
  struct timespec before,after;assert(!clock_gettime(CLOCK_MONOTONIC,&before));
  edr_response_collect_forensic("blocked-audit",(const uint8_t *)source,strlen(source),&meta);
  assert(!clock_gettime(CLOCK_MONOTONIC,&after));
  double elapsed=after.tv_sec-before.tv_sec+(after.tv_nsec-before.tv_nsec)/1e9;
  fprintf(stderr,"blocked_audit elapsed=%.3f\n",elapsed);assert(elapsed<2.5);
  assert(edr_command_state_has_final("blocked-audit",&meta)==0);
  snprintf(path,sizeof(path),"%s/audit.log",root);env("EDR_CMD_AUDIT_PATH",path);
}
#endif

int main(int argc,char **argv) {
  edr_response_forensic_register_worker();
  if(argc==3 && !strcmp(argv[1],EDR_FORENSIC_WORKER_ARG))return edr_forensic_io_worker_main(argv[2]);
  if(argc==3 && !strcmp(argv[1],"--blocked-command")) {
    EdrSoarCommandMeta meta={0};strcpy(meta.idempotency_key,"blocked-owner");
    meta.issued_at_unix_ms=(int64_t)time(NULL)*1000LL;meta.deadline_ms=1000;
    edr_response_collect_forensic("blocked-owner",(const uint8_t *)argv[2],strlen(argv[2]),&meta);return 0;
  }
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
  test_blocked_owner(root,path);
#ifndef _WIN32
  test_blocked_audit(root,path);
#endif
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
  start_owner("report-intent",&meta);
  EdrForensicIoRequest report={0};EdrForensicIoResult receipt={0};
  report.version=EDR_FORENSIC_IO_VERSION;report.operation=4;report.timeout_ms=1000;
  report.meta=meta;strcpy(report.command_id,"report-intent");report.report_pending=1;report.preflight_failure=-1;
  assert(!edr_forensic_io_run(&report,&receipt,NULL,NULL));
  assert(edr_command_state_begin("report-intent","collect_forensic",&meta,&retry,&record)==EDR_COMMAND_STATE_BEGIN_DUP_FINAL);
  assert(record.report_pending==1); /* No network initialization in the child must not drop delivery intent. */
  edr_command_executor_shutdown();
  printf("baseline_producer archive_bytes=%llu stage_published=1 false_upload_success=0 strict_external_refused=1 expired_writer_not_started=1 bounded_copy_cause_terminal=1\n",
      (unsigned long long)bytes);
  return 0;
}
