/* Exercise real metadata I/O and retries; only remote upload and terminal
 * handoff are replaced. CRT hooks inject write/close/publish failures. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "edr/command_state.h"
#include "edr/sha256.h"
#include "edr/forensic_path.h"
#include "edr/forensic_worker.h"
static size_t hash_operations;
static int fail_sync_worker;
static unsigned sync_worker_calls;
static const char *test_executable;
static int policy_result;
static int64_t fake_now_ms=1000000;
#define EDR_UPLOAD_OUTBOX_NOW_MS() fake_now_ms
static int measured_hash_worker(const EdrForensicIoRequest *request,EdrForensicIoResult *result,EdrResponseCancelCheck cancel,void *user) {
  if(request->operation==2)hash_operations++;
  if(request->operation==3) {sync_worker_calls++;if(fail_sync_worker)return -1;}
  return edr_forensic_io_run(request,result,cancel,user);
}
int edr_egress_is_policy_hold(int rc) {return rc==-3||rc==-4||rc==-7;}
int edr_egress_upload_preflight(const char *id,const char *upload,const char *path,const char *sha,uint64_t *size) {(void)id;(void)upload;(void)path;(void)sha;if(size)*size=24;return policy_result;}
#ifdef _WIN32
#include <windows.h>
#include <direct.h>
#include <process.h>
static void env(const char *key, const char *value) { _putenv_s(key, value); }
#else
#include <sys/stat.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/statvfs.h>
static uint64_t forced_available_bytes;
static int outbox_test_statvfs(const char *path,struct statvfs *out) {
  if(!forced_available_bytes)return statvfs(path,out);
  memset(out,0,sizeof(*out));out->f_frsize=1;out->f_bavail=forced_available_bytes;return 0;
}
#define statvfs(path,out) outbox_test_statvfs(path,out)
static void env(const char *key, const char *value) { setenv(key, value, 1); }
#endif

/* Pause the first publisher after its last absent-record read, before its
 * metadata admission. This is a real CRT boundary, not a policy substitute. */
static void (*missing_terminal_record_hook)(void);
static FILE *injected_path_file(EdrForensicPath *guard,const char *mode) {
  FILE *f=edr_forensic_path_file(guard,mode);
  const char *path=edr_forensic_path_text(guard);
  if(!f && !strcmp(mode,"rb") && strstr(path,"upload_cmd_concurrent_A_") &&
      strstr(path,".pending.failed") && missing_terminal_record_hook) {
    void (*hook)(void)=missing_terminal_record_hook;missing_terminal_record_hook=NULL;hook();
  }
  return f;
}
static int fail_flush, fail_close, close_after_flush, fail_publish, fail_fdopen;
static int fail_terminal_receipt, terminal_new;
static int fail_upload_receipt;
static unsigned metadata_flushes;
static int injected_fflush(FILE *file) {
  metadata_flushes++;
  if (fail_flush) { fail_flush = 0; errno = ENOSPC; return EOF; }
  if (fail_close) { close_after_flush = 1; fail_close = 0; }
  return fflush(file);
}
static int injected_fclose(FILE *file) {
  int rc = fclose(file);
  if (close_after_flush) { close_after_flush = 0; errno = ENOSPC; return EOF; }
  return rc;
}
#ifdef _WIN32
static unsigned publish_rejections, move_attempts, move_retry_wait_ms, transient_move_failures;
static DWORD transient_move_error;
static unsigned fail_rename_flush_countdown;
static BOOL injected_flush_buffers(HANDLE file) {
  if(fail_rename_flush_countdown && --fail_rename_flush_countdown==0) {
    SetLastError(ERROR_WRITE_FAULT);return FALSE;
  }
  return FlushFileBuffers(file);
}
static void injected_move_sleep(DWORD ms) {move_retry_wait_ms+=ms;Sleep(ms);}
static int injected_move(EdrForensicPath *src,EdrForensicPath *dst,int replace) {
  move_attempts++;
  /* Existing fail_publish=1 means one whole publication fails, including its
   * bounded retry budget. Do not silently weaken the existing failure cases. */
  if (fail_publish) {
    if(++publish_rejections==3u){fail_publish=0;publish_rejections=0;}
    SetLastError(ERROR_ACCESS_DENIED);return -1;
  }
  if(transient_move_failures) {transient_move_failures--;SetLastError(transient_move_error);return -1;}
  return edr_forensic_path_move(src,dst,replace);
}
static FILE *injected_fdopen(int fd, const char *mode) {
  if (fail_fdopen && !strcmp(mode,"wb")) { fail_fdopen = 0; errno = ENOMEM; return NULL; }
  return _fdopen(fd, mode);
}
#define FlushFileBuffers injected_flush_buffers
#define _fdopen injected_fdopen
#define Sleep injected_move_sleep
#else
static int injected_rename(int srcfd,const char *src,int dstfd,const char *dst) {
  if (fail_publish) { fail_publish = 0; errno = EACCES; return -1; }
  return renameat(srcfd,src,dstfd,dst);
}
static int injected_link(int srcfd,const char *src,int dstfd,const char *dst,int flags) {
  if (fail_publish) { fail_publish = 0; errno = EACCES; return -1; }
  return linkat(srcfd,src,dstfd,dst,flags);
}
static FILE *injected_fdopen(int fd, const char *mode) {
  if (fail_fdopen && !strcmp(mode,"wb")) { fail_fdopen = 0; errno = ENOMEM; return NULL; }
  return fdopen(fd, mode);
}
#define fdopen injected_fdopen
#define renameat injected_rename
#define linkat injected_link
#endif
/* Embed the same guarded implementation so faults still hit the actual
 * fdopen/rename boundary after it moved out of the outbox owner. */
#include "../src/forensic/forensic_path.c"
#define edr_forensic_path_file injected_path_file
#ifdef _WIN32
#define edr_forensic_path_move injected_move
#endif
#define fflush injected_fflush
#define fclose injected_fclose
#define edr_forensic_io_run measured_hash_worker
#include "../src/command/command_upload_outbox.c"
#undef edr_forensic_io_run
#undef edr_forensic_path_file
#undef fflush
#undef fclose
#ifdef _WIN32
#undef edr_forensic_path_move
#undef Sleep
#undef _fdopen
#undef FlushFileBuffers
#else
#undef renameat
#undef fdopen
#undef linkat
#undef statvfs
#endif

/* Make failed state flushes leave complete readable bytes, as a real failed
 * fsync/_commit can. Recovery must flush again before retiring the upload. */
static int fail_state_flush;
static unsigned owner_flushes;
static int state_test_fflush(FILE *file) {
  owner_flushes++;
  int rc = fflush(file);
  if (fail_state_flush > 0) { fail_state_flush--; errno = EIO; return EOF; }
  return rc;
}
#define fflush state_test_fflush
#include "../src/command/command_state.c"
#undef fflush

static int upload_calls, upload_fail, terminal_calls, terminal_fail, audits;
static char last_command[128], last_sha[65], last_error[128];
static EdrSoarCommandMeta last_meta;
static int last_partial, last_upload_ok;
void edr_command_executor_wake(void) {}
void edr_command_audit_both(const char *id, const char *message) {
  (void)id; assert(message && message[0]); audits++;
}
int edr_transport_v2_upload_file(const char *id, const char *path, const char *sha,
                                char *key, size_t cap) {
  assert(id && id[0] && path && path[0]);
  assert(strlen(sha) == 64u);
  upload_calls++;
  if(fail_upload_receipt) {fail_upload_receipt=0;fail_publish=1;}
  snprintf(last_command, sizeof(last_command), "%s", id);
  snprintf(last_sha, sizeof(last_sha), "%s", sha);
  if (upload_fail) return -1;
  snprintf(key, cap, "evidence/%s/%s", id, sha);
  return 0;
}
int edr_response_forensic_complete_queued_upload(const char *id, const char *type,
    const EdrSoarCommandMeta *meta, const char *path, const char *sha, const char *key,
    const char *source, int partial, int ok, const char *error) {
  assert(id && id[0] && type && path && sha && source);
  assert(!ok || (key && key[0]));
  terminal_calls++;
  last_meta = *meta; last_partial = partial; last_upload_ok = ok;
  snprintf(last_error, sizeof(last_error), "%s", error);
  if (terminal_fail) return -1;
  char detail[2600];
  snprintf(detail, sizeof(detail), "object=%s;sha=%s;partial=%d;error=%s", key, sha, partial, error);
  int rc = edr_command_state_finish_once(id, type, meta, ok ? "ok" : "failed",
      ok ? EdrCmdExecOk : EdrCmdExecFailed, ok ? 0 : 9, detail, "", 1);
  if (rc == 0) terminal_new++;
  if (fail_terminal_receipt) { fail_terminal_receipt = 0; fail_publish = 1; }
  return rc < 0 ? rc : 0;
}
int edr_local_evidence_cache_record_command_result(const char *id, const char *type,
    const char *status, int execution, int code, const char *detail, const char *artifacts) {
  (void)id; (void)type; (void)status; (void)execution; (void)code; (void)detail; (void)artifacts;
  return 0;
}
static void put(const char *path, const char *text) {
  FILE *f = fopen(path, "wb"); assert(f);
  size_t n = strlen(text); assert(fwrite(text, 1, n, f) == n); assert(fclose(f) == 0);
}
static int exists(const char *path) {
  struct stat st; return stat(path, &st) == 0;
}
static void contents(const char *path, char *out, size_t cap) {
  FILE *f = fopen(path, "rb"); assert(f);
  size_t n = fread(out, 1, cap - 1u, f); assert(!ferror(f) && feof(f));
  out[n] = 0; assert(fclose(f) == 0);
}
static void make_dir(const char *path) {
#ifdef _WIN32
  assert(_mkdir(path) == 0);
#else
  assert(mkdir(path, 0700) == 0);
#endif
}
static void remove_dir(const char *path) {
#ifdef _WIN32
  assert(_rmdir(path) == 0);
#else
  assert(rmdir(path) == 0);
#endif
}
static int remove_synthetic_hold(const char *path) {
#ifdef _WIN32
  for(unsigned attempt=0;attempt<6;attempt++) {
    if(!remove(path))return 0;
    DWORD error=GetLastError();
    if(attempt==5 || (error!=ERROR_SHARING_VIOLATION && error!=ERROR_ACCESS_DENIED && error!=ERROR_LOCK_VIOLATION))return -1;
    fprintf(stderr,"synthetic hold cleanup retry win32=%lu\n",error);Sleep(20);
  }
  return -1;
#else
  return remove(path);
#endif
}
static char root[700], dir[800], bundle[900], sha[65];
static EdrSoarCommandMeta meta;
static void setup(const char *name) {
  snprintf(dir, sizeof(dir), "%s/%s", root, name); make_dir(dir);
  snprintf(bundle, sizeof(bundle), "%s/bundle.tgz", dir); put(bundle, "bounded forensic fixture");
  assert(edr_sha256_hex((const uint8_t *)"bounded forensic fixture", strlen("bounded forensic fixture"), sha) == 0);
  env("EDR_UPLOAD_OUTBOX_DIR", dir);
  char state[1000], inbox[1000];
  snprintf(state, sizeof(state), "%s/state.jsonl", dir); env("EDR_COMMAND_STATE_DB", state);
  snprintf(inbox, sizeof(inbox), "%s/inbox", dir); env("EDR_COMMAND_INBOX_DIR", inbox);
  EdrCommandStateCapacityStats capacity;
  assert(edr_command_state_get_capacity_stats(&capacity)==0);
  terminal_new = fail_terminal_receipt = 0;
  policy_result=0;hash_operations=0;
  upload_calls = upload_fail = terminal_calls = terminal_fail = audits = 0;
  fake_now_ms=1000000; metadata_flushes=0;
  owner_flushes=0;
}
static void pending_path(char *path, size_t cap, const char *id) {
  snprintf(path, cap, "%s/upload_%s_%s.pending", dir, id, sha);
}
static void legacy(const char *path, const char *id, int bad) {
  char raw[3000];
  snprintf(raw, sizeof(raw), "command_id=%s\nbundle_path=%s\nsha256=%s\nmanifest_path=retained-manifest\ncreated_unix_ms=1\nfuture_metadata=retained\n",
           id, bundle, bad ? "not-a-hash" : sha); put(path, raw);
}
static unsigned temporary_files(void) {
  unsigned count = 0;
#ifdef _WIN32
  char pattern[1000]; snprintf(pattern, sizeof(pattern), "%s/*.tmp.*", dir);
  WIN32_FIND_DATAA found;
  HANDLE scan = FindFirstFileA(pattern, &found);
  if (scan == INVALID_HANDLE_VALUE) return 0;
  do { if (!(found.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) count++; }
  while (FindNextFileA(scan, &found));
  FindClose(scan);
#else
  DIR *scan = opendir(dir); assert(scan);
  struct dirent *entry;
  while ((entry = readdir(scan)) != NULL) if (strstr(entry->d_name, ".tmp.")) count++;
  closedir(scan);
#endif
  return count;
}

static void test_enqueue_failures(void) {
  setup("enqueue"); char path[1200]; pending_path(path, sizeof(path), "cmd_queue");
  fail_fdopen = 1;
  assert(edr_command_upload_outbox_write_legacy("cmd_queue", bundle, sha, "manifest") != 0 && !exists(path));
  assert(fail_fdopen == 0);
  assert(temporary_files() == 0u);
  fail_flush = 1;
  assert(edr_command_upload_outbox_write_legacy("cmd_queue", bundle, sha, "manifest") != 0 && !exists(path));
  assert(fail_flush == 0);
  fail_close = 1;
  assert(edr_command_upload_outbox_write_legacy("cmd_queue", bundle, sha, "manifest") != 0 && !exists(path));
  assert(fail_close == 0 && close_after_flush == 0);
  fail_publish = 1;
  assert(edr_command_upload_outbox_write_legacy("cmd_queue", bundle, sha, "manifest") != 0 && !exists(path));
  assert(fail_publish == 0);
  assert(edr_command_upload_outbox_write_legacy("cmd_queue", bundle, sha, "manifest") == 0 && exists(path));
  assert(edr_command_upload_outbox_write_legacy("cmd_queue", bundle, sha, "manifest") == 0);
  assert(edr_command_upload_outbox_write_legacy("cmd_queue", bundle, sha, "conflict") != 0);
  char blocked[1000]; snprintf(blocked, sizeof(blocked), "%s/not-a-directory", dir); put(blocked, "blocked");
  env("EDR_UPLOAD_OUTBOX_DIR", blocked);
  assert(edr_command_upload_outbox_write_legacy("cmd_blocked", bundle, sha, "") != 0);
}
#ifdef _WIN32
static void test_windows_readable_metadata_requires_durability(void) {
  setup("windows-readable-not-durable");char path[1200];
  pending_path(path,sizeof(path),"cmd_flush");
  /* First flush precedes rename; second fails after the real native rename. */
  fail_rename_flush_countdown=2;fail_sync_worker=1;sync_worker_calls=0;
  assert(edr_command_upload_outbox_write_legacy("cmd_flush",bundle,sha,"")==-1);
  assert(!fail_rename_flush_countdown && exists(path) && exists(bundle));
  assert(sync_worker_calls==1 && !upload_calls);
  assert(edr_command_upload_outbox_write_legacy("cmd_flush",bundle,sha,"")==-1);
  assert(sync_worker_calls==2 && exists(path) && exists(bundle));
  fail_sync_worker=0;
  assert(edr_command_upload_outbox_write_legacy("cmd_flush",bundle,sha,"")==0);
  assert(sync_worker_calls==3 && !upload_calls && exists(bundle));
  puts("PASS: post-rename flush failure retains readable metadata; failed durability confirmation rejects replay; real worker reflush recovers");
}
static void test_windows_bounded_metadata_publication(void) {
  const DWORD errors[]={ERROR_ACCESS_DENIED,ERROR_SHARING_VIOLATION,ERROR_LOCK_VIOLATION};
  for(size_t i=0;i<sizeof(errors)/sizeof(errors[0]);i++) {
    char name[64],path[1200];snprintf(name,sizeof(name),"windows-transient-%lu",errors[i]);setup(name);
    pending_path(path,sizeof(path),"cmd_move");transient_move_error=errors[i];transient_move_failures=2u;
    move_attempts=move_retry_wait_ms=0u;
    assert(edr_command_upload_outbox_write_legacy("cmd_move",bundle,sha,"")==0 && exists(path) && exists(bundle));
    assert(move_attempts==3u && move_retry_wait_ms>0u && move_retry_wait_ms<=60u && !transient_move_failures);
  }
  setup("windows-permanent-denial");char path[1200],before[8192],after[8192];int attempted;
  pending_path(path,sizeof(path),"cmd_move");move_attempts=move_retry_wait_ms=0u;
  assert(edr_command_upload_outbox_write_legacy("cmd_move",bundle,sha,"")==0);
  assert(move_attempts==1u && move_retry_wait_ms==0u);contents(path,before,sizeof(before));
  transient_move_error=ERROR_ACCESS_DENIED;transient_move_failures=3u;move_attempts=move_retry_wait_ms=0u;
  assert(edr_command_upload_outbox_flush_one(path,&attempted)==-2 && attempted);
  assert(move_attempts==3u && move_retry_wait_ms<=60u && !transient_move_failures);
  contents(path,after,sizeof(after));assert(!strcmp(before,after) && exists(bundle));
  assert(temporary_files()==0u); /* Only this failed write's own scratch is removed. */
  setup("windows-nonretryable-denial");
  transient_move_error=ERROR_FILE_NOT_FOUND;transient_move_failures=1u;move_attempts=move_retry_wait_ms=0u;
  assert(edr_command_upload_outbox_write_legacy("cmd_no_retry",bundle,sha,"")==-1);
  assert(move_attempts==1u && move_retry_wait_ms==0u && !transient_move_failures && exists(bundle));
  puts("Windows metadata publication: errors 5/32/33 recover within 3 attempts; persistent denial retains pending/artifact; success/nonretryable one call; scheduled wait <=60ms PASS");
}
#endif
/* Exercise the existing volume reserve without filling the host disk. */
static void test_metadata_physical_admission(void) {
  setup("physical-admission");
  char path[1200], before[8192], after[8192];
  pending_path(path, sizeof(path), "cmd_physical");
  env("EDR_STORAGE_MIN_FREE_MB", "17592186044415");
  int rc = edr_command_upload_outbox_write_legacy("cmd_physical", bundle, sha, "manifest");
  printf("outbox_physical_admission blocked_enqueue_rc=%d pending_exists=%d temporary_files=%u\n",
         rc, exists(path), temporary_files()); fflush(stdout);
  assert(rc != 0 && !exists(path) && temporary_files() == 0u);
  env("EDR_STORAGE_MIN_FREE_MB", "0");
  assert(edr_command_upload_outbox_write_legacy("cmd_physical", bundle, sha, "manifest") == 0);
  contents(path, before, sizeof(before));
  env("EDR_STORAGE_MIN_FREE_MB", "17592186044415");
  /* A no-write replay neither spends disk nor changes the committed record. */
  assert(edr_command_upload_outbox_write_legacy("cmd_physical", bundle, sha, "manifest") == 0);
  hash_operations = 0;
  int attempted = 99;
  assert(edr_command_upload_outbox_flush_one(path, &attempted) == -2);
  assert(!attempted && !hash_operations && !upload_calls && !terminal_calls && temporary_files() == 0u);
  contents(path, after, sizeof(after)); assert(!strcmp(before, after));
  printf("outbox_physical_admission blocked_upload_attempts=%d blocked_hash_operations=%zu pending_preserved=%d\n",
         upload_calls, hash_operations, exists(path));
  char hold[1300]; snprintf(hold, sizeof(hold), "%s.policy-held", path);
  policy_result = EDR_EGRESS_REQUEST_DENIED;
  assert(edr_command_upload_outbox_flush_one(path, &attempted) == EDR_EGRESS_LOCAL_STATE_FAILURE);
  assert(!attempted && !hash_operations && !upload_calls && !exists(hold) && exists(bundle));
  contents(path, after, sizeof(after)); assert(!strcmp(before, after));
  env("EDR_STORAGE_MIN_FREE_MB", "0");
  assert(edr_command_upload_outbox_flush_one(path, &attempted) == EDR_EGRESS_REQUEST_DENIED);
  assert(!attempted && !hash_operations && !upload_calls && exists(hold));
  policy_result = 0;
  assert(edr_command_upload_outbox_flush_one(path, &attempted) == 1 && attempted == 1);
  assert(upload_calls == 1 && !exists(path) && !exists(hold) && exists(bundle));
  printf("outbox_physical_admission recovered_upload_attempts=%d artifact_preserved=%d\n",
         upload_calls, exists(bundle));
}
static void test_legacy_upgrade(void) {
  setup("legacy"); char path[1200], done[1240], raw[8192]; int attempted;
  snprintf(path, sizeof(path), "%s/upload_cmd_old_123.pending", dir); legacy(path, "cmd_old", 0);
  upload_fail = 1;
  assert(edr_command_upload_outbox_flush_one(path, &attempted) == -1 && attempted == 1 && exists(path));
  upload_fail = 0;
  fake_now_ms+=61000;
  assert(edr_command_upload_outbox_flush_one(path, &attempted) == 1 && attempted == 1 && !exists(path));
  assert(upload_calls == 2 && terminal_calls == 0 && !strcmp(last_command, "cmd_old") && !strcmp(last_sha, sha));
  snprintf(done, sizeof(done), "%s.done", path); contents(done, raw, sizeof(raw));
  assert(strstr(raw, "future_metadata=retained\n") && strstr(raw, "manifest_path=retained-manifest\n"));
  assert(strstr(raw, "object_key=evidence/cmd_old/"));
}
static void test_reopen_after_terminal_failure(void) {
  setup("terminal"); char path[1200], done[1240], raw[8192]; int attempted;
  assert(edr_command_queue_forensic_upload("cmd_terminal", "yara_scan", &meta, bundle, sha, "builtin", 1) == 0);
  pending_path(path, sizeof(path), "cmd_terminal"); terminal_fail = 1;
  assert(edr_command_upload_outbox_flush_one(path, &attempted) == -2 && attempted == 1 && exists(path));
  contents(path, raw, sizeof(raw)); assert(strstr(raw, "object_key=evidence/cmd_terminal/"));
  assert(!strstr(raw, "terminal_persisted="));
  /* Re-enqueue and a fresh file read preserve the confirmed object receipt. */
  assert(edr_command_queue_forensic_upload("cmd_terminal", "yara_scan", &meta, bundle, sha, "builtin", 1) == 0);
  assert(remove(bundle) == 0); terminal_fail = 0;
  assert(edr_command_upload_outbox_flush_one(path, &attempted) == 1 && attempted == 0 && !exists(path));
  assert(upload_calls == 1 && terminal_calls == 2 && last_partial == 1 && last_upload_ok == 1);
  assert(!strcmp(meta.idempotency_key, last_meta.idempotency_key));
  assert(!strcmp(meta.soar_correlation_id, last_meta.soar_correlation_id));
  assert(!strcmp(meta.playbook_run_id, last_meta.playbook_run_id));
  assert(!strcmp(meta.playbook_step_id, last_meta.playbook_step_id));
  snprintf(done, sizeof(done), "%s.done", path); contents(done, raw, sizeof(raw));
  assert(strstr(raw, "terminal_persisted=uploaded\n"));
}
static void test_rename_retry(void) {
  setup("rename"); char path[1200], done[1240]; int attempted;
  assert(edr_command_queue_forensic_upload("cmd_rename", "collect_forensic", &meta, bundle, sha, "builtin", 0) == 0);
  pending_path(path, sizeof(path), "cmd_rename"); snprintf(done, sizeof(done), "%s.done", path); make_dir(done);
  assert(edr_command_upload_outbox_flush_one(path, &attempted) == -2 && attempted == 1 && exists(path));
  assert(upload_calls == 1 && terminal_calls == 1 && audits > 0);
  remove_dir(done);
  /* Recover the two identical files left by a process exit between link/unlink. */
  char receipt[8192]; contents(path, receipt, sizeof(receipt)); put(done, receipt);
  assert(edr_command_upload_outbox_flush_one(path, &attempted) == 1 && attempted == 0 && !exists(path));
  assert(upload_calls == 1 && terminal_calls == 1);
  assert(edr_command_queue_forensic_upload("cmd_rename", "collect_forensic", &meta, bundle, sha, "builtin", 0) == 0);
  assert(!exists(path));
}
static void test_receipt_failure(void) {
  setup("receipt"); char path[1200], raw[8192]; int attempted;
  assert(edr_command_queue_forensic_upload("cmd_receipt", "collect_forensic", &meta, bundle, sha, "builtin", 0) == 0);
  pending_path(path, sizeof(path), "cmd_receipt"); fail_upload_receipt = 1;
  assert(edr_command_upload_outbox_flush_one(path, &attempted) == -2 && attempted == 1 && exists(path));
  assert(terminal_calls == 0); contents(path, raw, sizeof(raw)); assert(!strstr(raw, "object_key="));
  assert(edr_command_upload_outbox_flush_one(path, &attempted) == 1);
  assert(upload_calls == 2 && !strcmp(last_command, "cmd_receipt") && !strcmp(last_sha, sha));
}
static void test_terminal_commit_before_receipt_failure(void) {
  setup("terminal-receipt"); char path[1200], before[65], after[65]; int attempted;
  assert(edr_command_queue_forensic_upload("cmd_receipt_final", "collect_forensic", &meta, bundle, sha, "builtin", 0) == 0);
  pending_path(path, sizeof(path), "cmd_receipt_final"); fail_terminal_receipt = 1;
  assert(edr_command_upload_outbox_flush_one(path, &attempted) == -2 && attempted == 1 && exists(path));
  assert(terminal_new == 1 && upload_calls == 1);
  EdrCommandStateRecord records[2];
  int count = edr_command_state_collect_pending(records, 2u); assert(count == 1);
  assert(edr_command_state_mark_reported(&records[0]) == 0);
  const char *state_path = getenv("EDR_COMMAND_STATE_DB"); assert(file_hash(state_path, before) == 0);
  /* Re-open both durable files after ACK. No terminal/ACK/backoff fields change. */
  assert(edr_command_upload_outbox_flush_one(path, &attempted) == 1 && attempted == 0 && !exists(path));
  assert(terminal_new == 1 && upload_calls == 1);
  assert(file_hash(state_path, after) == 0 && !strcmp(before, after));
  assert(edr_command_state_collect_pending(records, 2u) == 0);
}

static void test_readable_terminal_is_not_a_durable_commit(void) {
  setup("state-flush"); char path[1200], raw[8192]; int attempted;
  assert(edr_command_queue_forensic_upload("cmd_state_flush", "collect_forensic", &meta, bundle, sha, "builtin", 0) == 0);
  pending_path(path, sizeof(path), "cmd_state_flush"); fail_state_flush = 2;
  assert(edr_command_upload_outbox_flush_one(path, &attempted) == -2 && attempted == 1 && exists(path));
  assert(exists(getenv("EDR_COMMAND_STATE_DB")));
  /* The matching readable terminal must still fail while storage cannot sync. */
  assert(edr_command_upload_outbox_flush_one(path, &attempted) == -2 && attempted == 0 && exists(path));
  contents(path, raw, sizeof(raw)); assert(!strstr(raw, "terminal_persisted="));
  assert(fail_state_flush == 0);
  assert(edr_command_upload_outbox_flush_one(path, &attempted) == 1 && attempted == 0 && !exists(path));
  assert(upload_calls == 1);
}

static void test_failure_receipt_survives_artifact_recovery(void) {
  setup("fixed-failure"); char path[1200]; int attempted;
  assert(edr_command_queue_forensic_upload("cmd_fixed_failure", "collect_forensic", &meta, bundle, sha, "builtin", 0) == 0);
  pending_path(path, sizeof(path), "cmd_fixed_failure"); assert(remove(bundle) == 0);
  fail_terminal_receipt = 1;
  assert(edr_command_upload_outbox_flush_one(path, &attempted) == -2 && attempted == 0 && exists(path));
  assert(terminal_new == 1 && !last_upload_ok);
  put(bundle, "bounded forensic fixture");
  assert(edr_command_upload_outbox_flush_one(path, &attempted) == 0 && attempted == 0 && !exists(path));
  assert(terminal_new == 1 && upload_calls == 0 && !last_upload_ok);
  assert(strstr(last_error, "missing"));
}

static void test_bad_records_do_not_spend_upload_budget(void) {
  setup("invalid"); char bad[1200], valid[1200], failed[1240]; int attempted;
  snprintf(bad, sizeof(bad), "%s/bad.pending", dir); legacy(bad, "cmd_bad", 1);
  assert(edr_command_upload_outbox_flush_one(bad, &attempted) == 0 && attempted == 0 && !exists(bad));
  snprintf(failed, sizeof(failed), "%s.failed", bad); assert(exists(failed));
  char duplicate[3000];
  snprintf(duplicate, sizeof(duplicate), "command_id=cmd_bad\nbundle_path=%s\nsha256=%s\n\ncommand_id=conflict\n", bundle, sha);
  put(bad, duplicate); assert(remove(failed) == 0);
  assert(edr_command_upload_outbox_flush_one(bad, &attempted) == 0 && attempted == 0);
  legacy(bad, "cmd_missing", 0); assert(remove(bundle) == 0);
  assert(edr_command_upload_outbox_flush_one(bad, &attempted) == -2 && attempted == 0); /* retained destination collision */
  assert(remove(failed) == 0);
  assert(edr_command_upload_outbox_flush_one(bad, &attempted) == 0 && attempted == 0);
  put(bundle, "bounded forensic fixture");
  assert(edr_command_queue_forensic_upload("cmd_valid", "collect_forensic", &meta, bundle, sha, "builtin", 0) == 0);
  pending_path(valid, sizeof(valid), "cmd_valid");
  assert(edr_command_upload_outbox_flush_one(valid, &attempted) == 1 && attempted == 1);
  assert(upload_calls == 1 && terminal_calls == 1);
}
static void test_hash_and_missing_terminal(void) {
  setup("hash"); char path[1200]; int attempted;
  assert(edr_command_queue_forensic_upload("cmd_hash", "collect_forensic", &meta, bundle, sha, "builtin", 0) == 0);
  pending_path(path, sizeof(path), "cmd_hash"); put(bundle, "changed bytes");
  assert(edr_command_upload_outbox_flush_one(path, &attempted) == 0 && attempted == 0);
  assert(upload_calls == 0 && terminal_calls == 1 && !last_upload_ok && strstr(last_error, "hash changed"));
  setup("missing");
  assert(edr_command_queue_forensic_upload("cmd_missing", "collect_forensic", &meta, bundle, sha, "builtin", 0) == 0);
  pending_path(path, sizeof(path), "cmd_missing"); assert(remove(bundle) == 0); terminal_fail = 1;
  assert(edr_command_upload_outbox_flush_one(path, &attempted) == -2 && attempted == 0 && exists(path));
  terminal_fail = 0;
  assert(edr_command_upload_outbox_flush_one(path, &attempted) == 0 && attempted == 0);
  assert(upload_calls == 0 && terminal_calls == 2 && !last_upload_ok && strstr(last_error, "missing"));
}
static void test_policy_hold_before_hash(void) {
  setup("policy-held");char path[1200],before[8192],after[8192],hold[1250];int attempted=99;
  assert(edr_command_queue_forensic_upload("cmd_hold","collect_forensic",&meta,bundle,sha,"builtin",0)==0);
  pending_path(path,sizeof(path),"cmd_hold");contents(path,before,sizeof(before));
  snprintf(hold,sizeof(hold),"%s.policy-held",path);policy_result=EDR_EGRESS_REQUEST_DENIED;hash_operations=0;
  for(int i=0;i<3;i++)assert(edr_command_upload_outbox_flush_one(path,&attempted)==EDR_EGRESS_REQUEST_DENIED && !attempted);
  assert(hash_operations==0 && upload_calls==0 && terminal_calls==0 && exists(bundle) && exists(hold));
  /* Drop all volatile counters and reopen durable state, as restart would. */
  hash_operations=0;assert(edr_command_upload_outbox_flush_one(path,&attempted)==EDR_EGRESS_REQUEST_DENIED);
  contents(path,after,sizeof(after));assert(!strcmp(before,after) && hash_operations==0);
#ifdef _WIN32
  assert(_spawnl(_P_WAIT,test_executable,test_executable,"--held-restart",path,NULL)==0);
#else
  pid_t child=fork();assert(child>=0);
  if(!child){execl(test_executable,test_executable,"--held-restart",path,(char*)NULL);_exit(127);}
  int status=0;assert(waitpid(child,&status,0)==child && WIFEXITED(status) && WEXITSTATUS(status)==0);
#endif
  /* A policy revision permits only a fresh admission decision, not upload or
   * an ACK. The old business record and artifact must still be untouched. */
  put(hold,"edr.egress-hold.v1\ncmd_hold\nminimal-egress-v3\n-3\n1\n");
  assert(edr_command_upload_outbox_flush_one(path,&attempted)==EDR_EGRESS_REQUEST_DENIED && !attempted);
  char held_command[160];assert(edr_hold_read(hold,held_command,sizeof(held_command))==EDR_EGRESS_REQUEST_DENIED);
  contents(path,after,sizeof(after));assert(!strcmp(before,after) && !hash_operations && !upload_calls && !terminal_calls);
  policy_result=EDR_EGRESS_AUTHORIZATION_EXPIRED;
  assert(edr_command_upload_outbox_flush_one(path,&attempted)==EDR_EGRESS_AUTHORIZATION_EXPIRED && !attempted);
  assert(remove_synthetic_hold(hold)==0);fail_flush=1;
  assert(edr_command_upload_outbox_flush_one(path,&attempted)==EDR_EGRESS_LOCAL_STATE_FAILURE && !attempted);
  assert(!hash_operations && exists(path));
  policy_result=0;upload_fail=1;
  assert(edr_command_upload_outbox_flush_one(path,&attempted)==-1 && attempted && hash_operations>0 && !exists(hold));
  upload_fail=0;fake_now_ms+=61000;
  assert(edr_command_upload_outbox_flush_one(path,&attempted)==1 && !exists(path));
}

static void test_durable_retry_and_deadline(void) {
  setup("durable-retry");char path[1200],raw[8192];int attempted=0;
  assert(edr_command_queue_forensic_upload("cmd_retry","collect_forensic",&meta,bundle,sha,"builtin",0)==0);
  pending_path(path,sizeof(path),"cmd_retry");upload_fail=1;metadata_flushes=0;
  assert(edr_command_upload_outbox_flush_one(path,&attempted)==-1 && attempted);
  assert(metadata_flushes==1u);contents(path,raw,sizeof(raw));
  assert(strstr(raw,"attempts=1\n") && strstr(raw,"retry_after_unix_ms=1060000\n"));
  hash_operations=0;metadata_flushes=0;
  for(int i=0;i<4;i++)assert(edr_command_upload_outbox_flush_one(path,&attempted)==-6 && !attempted);
  assert(!hash_operations && !metadata_flushes && upload_calls==1);
#ifdef _WIN32
  assert(_spawnl(_P_WAIT,test_executable,test_executable,"--retry-restart",path,NULL)==0);
#else
  pid_t child=fork();assert(child>=0);
  if(!child){execl(test_executable,test_executable,"--retry-restart",path,(char*)NULL);_exit(127);}
  int status=0;assert(waitpid(child,&status,0)==child && WIFEXITED(status) && WEXITSTATUS(status)==0);
#endif
  fake_now_ms=1060000;
  assert(edr_command_upload_outbox_flush_one(path,&attempted)==-1 && attempted);
  contents(path,raw,sizeof(raw));assert(strstr(raw,"attempts=2\n") && strstr(raw,"retry_after_unix_ms=1180000\n"));
  fake_now_ms=1000000+UPLOAD_DELIVERY_WINDOW_MS;
  hash_operations=0;
  assert(edr_command_upload_outbox_flush_one(path,&attempted)==0 && !attempted && exists(bundle));
  assert(!hash_operations && strstr(last_error,"deadline") && terminal_new==1);
  assert(edr_command_queue_forensic_upload("cmd_retry","collect_forensic",&meta,bundle,sha,"builtin",0)==0);
  assert(!exists(path)); /* failed tombstone prevents a new retry horizon */
  printf("outbox_retry due_failure_metadata_flushes=1 not_due_hash_operations=0 not_due_writes=0 restart_persisted=1\n");
}
static void test_retry_persist_failure_and_unknown_deadline(void) {
  setup("retry-storage-failed");char path[1200],before[8192],after[8192];int attempted=0;
  assert(edr_command_queue_forensic_upload("cmd_retry_disk","collect_forensic",&meta,bundle,sha,"builtin",0)==0);
  pending_path(path,sizeof(path),"cmd_retry_disk");contents(path,before,sizeof(before));
  upload_fail=1;fail_flush=1;
  assert(edr_command_upload_outbox_flush_one(path,&attempted)==EDR_UPLOAD_OUTBOX_RETRY_PERSIST_FAILED);
  assert(attempted && upload_calls==1 && !terminal_calls);
  contents(path,after,sizeof(after));assert(!strcmp(before,after) && exists(bundle));
  setup("unknown-deadline");
  snprintf(path,sizeof(path),"%s/unknown.pending",dir);
  snprintf(before,sizeof(before),"command_id=unknown\nbundle_path=%s\nsha256=%s\n",bundle,sha);put(path,before);
  hash_operations=0;
  assert(edr_command_upload_outbox_flush_one(path,&attempted)==0 && !attempted);
  snprintf(after,sizeof(after),"%s.failed",path);assert(exists(after) && exists(bundle));
  assert(!hash_operations && !upload_calls && !terminal_calls);
  printf("outbox_unknown deadline_unknown_quarantined=1 evidence_preserved=1 failed_network_retry_persist_distinct=1\n");
}

static void test_owner_final_preserved(void) {
  setup("owner-final");char path[1200],before[65],after[65];int attempted;
  assert(edr_command_queue_forensic_upload("cmd_final","collect_forensic",&meta,bundle,sha,"builtin",0)==0);
  pending_path(path,sizeof(path),"cmd_final");
  assert(edr_command_state_finish_once("cmd_final","collect_forensic",&meta,"cancelled",EdrCmdExecFailed,130,"cancelled","",1)==0);
  assert(file_hash(getenv("EDR_COMMAND_STATE_DB"),before)==0);
  assert(edr_command_upload_outbox_flush_one(path,&attempted)==0 && !attempted && exists(bundle));
  assert(!upload_calls && !terminal_calls);
  assert(file_hash(getenv("EDR_COMMAND_STATE_DB"),after)==0 && !strcmp(before,after));
}

static void test_staging_owner_recovery(void) {
  setup("staging-owner");EdrCommandArtifactStage stage={0};
  strcpy(stage.command_id,"cmd_stage");strcpy(stage.command_type,"collect_forensic");stage.meta=meta;
  strcpy(stage.meta.idempotency_key,"stage|sigv2|signature");
  snprintf(stage.artifact,sizeof(stage.artifact),"%s/published.tgz",dir);
  snprintf(stage.staging,sizeof(stage.staging),"%s.staging",stage.artifact);
  snprintf(stage.workspace,sizeof(stage.workspace),"%s/work",dir);
  stage.peak_bytes=129u*1024u*1024u;stage.phase=1;
  int retry=0;assert(edr_command_state_begin(stage.command_id,stage.command_type,&stage.meta,&retry,NULL)==0);
  owner_flushes=metadata_flushes=0;
  assert(edr_command_state_artifact_begin(&stage)==0 && owner_flushes==1);
  assert(edr_command_state_artifact_begin(&stage)==1 && owner_flushes==1);
  assert(edr_storage_artifact_reserved()==stage.peak_bytes);
  uint64_t available=0;EdrStoragePhysicalSnapshot snapshot;
  assert(edr_storage_volume_available(stage.staging,&available)==0 && available>stage.peak_bytes);
  assert(edr_storage_physical_admit(stage.staging,available-stage.peak_bytes/2,1,&snapshot)==-1);
  assert(edr_storage_physical_admit_owned(stage.staging,available-stage.peak_bytes/2,1,stage.peak_bytes,&snapshot)==0);
  size_t cursor=0;EdrCommandArtifactStage recovered;
  assert(edr_command_state_artifact_next(&cursor,&recovered)==0);
  assert(edr_command_upload_outbox_publish_stage(&stage)==-1);
  put(stage.staging,"bounded forensic fixture");
  fail_state_flush=2;
  assert(edr_command_state_artifact_ready(stage.command_id,sha)==-1);
  assert(edr_storage_artifact_reserved()==UINT64_MAX);
  assert(edr_storage_physical_admit(stage.staging,1,1,&snapshot)==-2);
  EdrCommandStateCapacityStats stats;
  assert(edr_command_state_get_capacity_stats(&stats)==-1 && edr_storage_artifact_reserved()==UINT64_MAX);
  assert(edr_command_state_get_capacity_stats(&stats)==0);
  assert(stats.artifact_reserved_bytes==2u*EDR_COMMAND_STATE_LINE_CAP+12288u);
  assert(edr_storage_artifact_reserved()==stats.artifact_reserved_bytes);
#ifdef _WIN32
  assert(_spawnl(_P_WAIT,test_executable,test_executable,"--stage-restart",stage.command_id,NULL)==0);
#else
  pid_t child=fork();assert(child>=0);
  if(!child){execl(test_executable,test_executable,"--stage-restart",stage.command_id,(char*)NULL);_exit(127);}
  int status=0;assert(waitpid(child,&status,0)==child && WIFEXITED(status) && WEXITSTATUS(status)==0);
#endif
  assert(!exists(stage.staging) && exists(stage.artifact));
  assert(edr_storage_artifact_reserved()==0); /* shared mapping observes child release */
  assert(edr_command_state_get_capacity_stats(&stats)==0 && !stats.artifact_reserved_bytes);
  EdrSoarCommandMeta frozen;
  assert(edr_command_state_artifact_meta(stage.command_id,stage.command_type,&frozen)==1);
  assert(!strcmp(frozen.idempotency_key,stage.meta.idempotency_key));
  char path[1200];pending_path(path,sizeof(path),stage.command_id);assert(exists(path));
  printf("staging_owner initial_reserved=%llu publishing_reserved=%u restart_publish=1 other_owner_credit_denied=1 unknown_retained=1\n",
      (unsigned long long)stage.peak_bytes,2u*EDR_COMMAND_STATE_LINE_CAP+12288u);
}

static void test_staging_interrupted_and_final(void) {
  setup("stage-interrupted");EdrCommandArtifactStage stage={0};
  strcpy(stage.command_id,"cmd_interrupted");strcpy(stage.command_type,"collect_forensic");stage.meta=meta;
  snprintf(stage.artifact,sizeof(stage.artifact),"%s/published.tgz",dir);
  snprintf(stage.staging,sizeof(stage.staging),"%s.staging",stage.artifact);
  snprintf(stage.workspace,sizeof(stage.workspace),"%s/work",dir);
  stage.peak_bytes=129u*1024u*1024u;stage.phase=1;
  int retry=0;assert(edr_command_state_begin(stage.command_id,stage.command_type,&stage.meta,&retry,NULL)==0);
  assert(edr_command_state_artifact_begin(&stage)==0);put(stage.staging,"bounded forensic fixture");
#ifdef _WIN32
  assert(_spawnl(_P_WAIT,test_executable,test_executable,"--stage-interrupted",stage.command_id,NULL)==0);
#else
  pid_t child=fork();assert(child>=0);
  if(!child){execl(test_executable,test_executable,"--stage-interrupted",stage.command_id,(char*)NULL);_exit(127);}
  int status=0;assert(waitpid(child,&status,0)==child && WIFEXITED(status) && WEXITSTATUS(status)==0);
#endif
  assert(edr_storage_artifact_reserved()==stage.peak_bytes && exists(stage.staging));
  assert(edr_command_state_has_final(stage.command_id,&stage.meta)==1);
  setup("stage-final");
  strcpy(stage.command_id,"cmd_stage_final");
  snprintf(stage.artifact,sizeof(stage.artifact),"%s/published.tgz",dir);
  snprintf(stage.staging,sizeof(stage.staging),"%s.staging",stage.artifact);
  snprintf(stage.workspace,sizeof(stage.workspace),"%s/work",dir);
  assert(edr_command_state_begin(stage.command_id,stage.command_type,&stage.meta,&retry,NULL)==0);
  assert(edr_command_state_artifact_begin(&stage)==0);put(stage.staging,"bounded forensic fixture");
  assert(edr_command_state_artifact_ready(stage.command_id,sha)==0);
  stage.phase=2;strcpy(stage.sha256,sha);
  assert(edr_command_state_finish_once(stage.command_id,stage.command_type,&stage.meta,"cancelled",
      EdrCmdExecFailed,130,"cancelled","",1)==0);
  assert(edr_command_upload_outbox_publish_stage(&stage)==0 && !edr_storage_artifact_reserved());
  assert(exists(stage.staging) && !exists(stage.artifact) && !upload_calls && !terminal_calls);
  printf("staging_terminal interrupted_final=1 unknown_writer_reserve_retained=1 duplicate_recovery_skipped=1 final_owner_growth_released=1 files_preserved=1\n");
}
#ifndef _WIN32
static void test_stage_own_metadata_credit(void) {
  setup("stage-credit");EdrCommandArtifactStage stage={0};
  strcpy(stage.command_id,"cmd_credit");strcpy(stage.command_type,"collect_forensic");stage.meta=meta;
  snprintf(stage.artifact,sizeof(stage.artifact),"%s/published.tgz",dir);
  snprintf(stage.staging,sizeof(stage.staging),"%s.staging",stage.artifact);
  snprintf(stage.workspace,sizeof(stage.workspace),"%s/work",dir);
  stage.peak_bytes=129u*1024u*1024u;stage.phase=1;
  int retry=0;assert(edr_command_state_begin(stage.command_id,stage.command_type,&stage.meta,&retry,NULL)==0);
  owner_flushes=metadata_flushes=0;
  assert(edr_command_state_artifact_begin(&stage)==0);put(stage.staging,"bounded forensic fixture");
  assert(edr_command_state_artifact_ready(stage.command_id,sha)==0);
  stage.phase=2;strcpy(stage.sha256,sha);
  uint64_t credit=edr_storage_artifact_reserved(),floor=0;
  assert(credit>0 && edr_storage_min_free_bytes(&floor)==0);
  /* Exactly the existing floor plus this owner's complete publishing promise
   * (outbox copy and remaining owner record), with no unreserved spare bytes. */
  forced_available_bytes=floor+credit;
  assert(!metadata_space_available(stage.artifact));
  assert(metadata_space_available_owned(stage.artifact,credit));
  assert(edr_command_upload_outbox_publish_stage(&stage)==0);
  forced_available_bytes=0;
  assert(!edr_storage_artifact_reserved() && !upload_calls && owner_flushes==3u && metadata_flushes==1u);
  printf("stage_cost begin_ready_release_owner_flushes=%u enqueue_metadata_flushes=%u exact_metadata_credit_published=1\n",
      owner_flushes,metadata_flushes);
}
#endif
/* A second process attempts the same handoff while A is paused immediately
 * before metadata admission. Probe the actual owner lock nonblockingly first:
 * old code is deterministically free and lets the competitor release A; fixed
 * code holds it and the competitor must wait until A's publication is durable. */
static EdrCommandArtifactStage concurrent_stage;
static int handoff_lock_held, competitor_joined;
static uint64_t borrowed_floor_bytes;
static char competitor_marker[1200];
#ifdef _WIN32
static intptr_t competitor_process;
#else
static pid_t competitor_process;
#endif
static void wait_competitor(void) {
  if(competitor_joined)return;
#ifdef _WIN32
  assert(WaitForSingleObject((HANDLE)competitor_process,10000)==WAIT_OBJECT_0);
  DWORD result=99;assert(GetExitCodeProcess((HANDLE)competitor_process,&result) && result==0);
  CloseHandle((HANDLE)competitor_process);
#else
  int status=0;assert(waitpid(competitor_process,&status,0)==competitor_process);
  assert(WIFEXITED(status) && WEXITSTATUS(status)==0);
#endif
  competitor_joined=1;
}
static void concurrent_handoff_boundary(void) {
  char lock_path[1100];snprintf(lock_path,sizeof(lock_path),"%s.lock",getenv("EDR_COMMAND_STATE_DB"));
  FILE *probe=state_open_lock_secure(lock_path);assert(probe);
#ifdef _WIN32
  HANDLE file=(HANDLE)_get_osfhandle(_fileno(probe));OVERLAPPED ov={0};
  BOOL acquired=LockFileEx(file,LOCKFILE_EXCLUSIVE_LOCK|LOCKFILE_FAIL_IMMEDIATELY,0,1,0,&ov);
  if(acquired)assert(UnlockFileEx(file,0,1,0,&ov));
  else assert(GetLastError()==ERROR_LOCK_VIOLATION);
#else
  int acquired=flock(fileno(probe),LOCK_EX|LOCK_NB)==0;
  if(acquired)assert(flock(fileno(probe),LOCK_UN)==0);
  else assert(errno==EWOULDBLOCK || errno==EAGAIN);
#endif
  assert(fclose(probe)==0);handoff_lock_held=!acquired;
#ifdef _WIN32
  competitor_process=_spawnl(_P_NOWAIT,test_executable,test_executable,"--concurrent-publish",
      concurrent_stage.command_id,competitor_marker,NULL);assert(competitor_process!=-1);
#else
  competitor_process=fork();assert(competitor_process>=0);
  if(!competitor_process){execl(test_executable,test_executable,"--concurrent-publish",
      concurrent_stage.command_id,competitor_marker,(char*)NULL);_exit(127);}
#endif
  unsigned waits=0;
  while(!exists(competitor_marker) && waits++<5000u) {
#ifdef _WIN32
    Sleep(1);
#else
    struct timespec pause={0,1000000};nanosleep(&pause,NULL);
#endif
  }
  assert(exists(competitor_marker));
  if(!handoff_lock_held) {
    wait_competitor(); /* Old A now carries stale credit while only B remains. */
    uint64_t floor=0;assert(edr_storage_min_free_bytes(&floor)==0);
    uint64_t reserved=edr_storage_artifact_reserved();EdrStoragePhysicalSnapshot snapshot;
    uint64_t stale=2u*EDR_COMMAND_STATE_LINE_CAP+12288u;
    assert(edr_storage_physical_admit_owned(concurrent_stage.artifact,12288u,0,stale,&snapshot)==0);
    borrowed_floor_bytes=floor+reserved-snapshot.min_free_bytes;
  }
}
static void create_stage_fixture(EdrCommandArtifactStage *stage,const char *id,int ready) {
  memset(stage,0,sizeof(*stage));snprintf(stage->command_id,sizeof(stage->command_id),"%s",id);
  strcpy(stage->command_type,"collect_forensic");stage->meta=meta;
  snprintf(stage->meta.idempotency_key,sizeof(stage->meta.idempotency_key),"%s|stage",id);
  snprintf(stage->artifact,sizeof(stage->artifact),"%s/%s.tgz",dir,id);
  snprintf(stage->staging,sizeof(stage->staging),"%s.staging",stage->artifact);
  snprintf(stage->workspace,sizeof(stage->workspace),"%s/%s.work",dir,id);
  stage->peak_bytes=129u*1024u*1024u;stage->phase=1;int retry=0;
  assert(edr_command_state_begin(id,stage->command_type,&stage->meta,&retry,NULL)==0);
  assert(edr_command_state_artifact_begin(stage)==0);put(stage->staging,"bounded forensic fixture");
  if(ready){assert(edr_command_state_artifact_ready(id,sha)==0);stage->phase=2;strcpy(stage->sha256,sha);}
}
static void test_concurrent_handoff_credit(void) {
  setup("concurrent-credit");EdrCommandArtifactStage other;
  create_stage_fixture(&concurrent_stage,"cmd_concurrent_A",1);
  create_stage_fixture(&other,"cmd_concurrent_B",0);
  snprintf(competitor_marker,sizeof(competitor_marker),"%s/competitor.started",dir);
  handoff_lock_held=competitor_joined=0;borrowed_floor_bytes=0;
  missing_terminal_record_hook=concurrent_handoff_boundary;
  int result=edr_command_upload_outbox_publish_stage(&concurrent_stage);
  assert(missing_terminal_record_hook==NULL);wait_competitor();
  printf("concurrent_handoff owner_lock_held=%d other_owner_floor_borrowed=%llu reservation_after=%llu\n",
      handoff_lock_held,(unsigned long long)borrowed_floor_bytes,(unsigned long long)edr_storage_artifact_reserved());fflush(stdout);
  assert(handoff_lock_held && borrowed_floor_bytes==0 && result==0);
  assert(edr_storage_artifact_reserved()==other.peak_bytes);
  unsigned prior_flushes=metadata_flushes;
  assert(edr_command_upload_outbox_publish_stage(&concurrent_stage)==0);
  assert(metadata_flushes==prior_flushes); /* phase3 neither reacquires credit nor rewrites metadata */
  assert(edr_storage_artifact_reserved()==other.peak_bytes && exists(other.staging));
  assert(edr_command_state_artifact_abandon(other.command_id)==0);
  /* A metadata write failure must leave the same phase2 owner and credit. */
  setup("handoff-failure");create_stage_fixture(&concurrent_stage,"cmd_handoff_failed",1);
  uint64_t before=edr_storage_artifact_reserved();fail_flush=1;
  assert(edr_command_upload_outbox_publish_stage(&concurrent_stage)!=0);
  assert(edr_storage_artifact_reserved()==before);
  size_t cursor=0;EdrCommandArtifactStage pending;
  assert(edr_command_state_artifact_next(&cursor,&pending)==1 && pending.phase==2 &&
      !strcmp(pending.command_id,concurrent_stage.command_id));
  assert(exists(concurrent_stage.artifact) && !upload_calls);
  assert(edr_command_upload_outbox_publish_stage(&concurrent_stage)==0 && !edr_storage_artifact_reserved());
  puts("handoff_failure phase2_credit_retained=1 retry_idempotent=1 no_remote_upload=1");
}

static void test_ancestor_outbox(void) {
  setup("ancestor-boundary");
  char alias[1000],pending[1200],actual[1200],cmd[2400];
  snprintf(alias,sizeof(alias),"%s/redirect",root);
#ifdef _WIN32
  snprintf(cmd,sizeof(cmd),"cmd.exe /d /c mklink /J \"%s\" \"%s\" >NUL",alias,dir);
  assert(system(cmd)==0);
#else
  (void)cmd;assert(symlink(dir,alias)==0);
#endif
  env("EDR_UPLOAD_OUTBOX_DIR",alias);
  int enqueue=edr_command_upload_outbox_write_legacy("redirected",bundle,sha,"");
  pending_path(actual,sizeof(actual),"redirected");int outside_written=exists(actual);
  env("EDR_UPLOAD_OUTBOX_DIR",dir);
  assert(edr_command_upload_outbox_write_legacy("read_redirected",bundle,sha,"")==0);
  snprintf(pending,sizeof(pending),"%s/upload_read_redirected_%s.pending",alias,sha);
  int attempted=99;int flush=edr_command_upload_outbox_flush_one(pending,&attempted);
  printf("ancestor_outbox enqueue_rc=%d outside_written=%d flush_rc=%d attempted=%d uploads=%d\n",enqueue,outside_written,flush,attempted,upload_calls);fflush(stdout);
  assert(enqueue!=0 && !outside_written && flush==-2 && !attempted && !upload_calls && exists(bundle));
#ifdef _WIN32
  assert(RemoveDirectoryA(alias));
#else
  assert(unlink(alias)==0);
#endif
}

int main(int argc,char **argv) {
  if(argc==3 && !strcmp(argv[1],EDR_FORENSIC_WORKER_ARG))return edr_forensic_io_worker_main(argv[2]);
  test_executable=argv[0];
  if(argc==4 && !strcmp(argv[1],"--concurrent-publish")) {
    put(argv[3],"started");
    EdrCommandStateCapacityStats stats;assert(edr_command_state_get_capacity_stats(&stats)==0);
    FILE *lock=state_lock_acquire();assert(lock);cJSON *record=artifact_latest_locked(argv[2]);
    EdrCommandArtifactStage stage;assert(record && artifact_fill(record,&stage)==0);
    const cJSON *a=cJSON_GetObjectItemCaseSensitive(record,"artifact_stage");
    snprintf(stage.sha256,sizeof(stage.sha256),"%s",result_text(a,"sha256"));
    stage.phase=2;cJSON_Delete(record);state_lock_release(lock);
    assert(edr_command_upload_outbox_publish_stage(&stage)==0);return 0;
  }
  if(argc==3 && !strcmp(argv[1],"--stage-interrupted")) {
    EdrCommandStateCapacityStats stats;assert(edr_command_state_get_capacity_stats(&stats)==0);
    size_t cursor=0;EdrCommandArtifactStage stage;
    assert(edr_command_state_artifact_next(&cursor,&stage)==1 && !strcmp(stage.command_id,argv[2]));
    assert(stage.phase==1 && stage.interrupted && edr_command_state_artifact_abandon(stage.command_id)==-1);
    assert(edr_command_upload_outbox_publish_stage(&stage)==0);
    assert(edr_command_state_has_final(stage.command_id,&stage.meta)==1);
    assert(edr_storage_artifact_reserved()==stage.peak_bytes && exists(stage.staging));
    cursor=0;assert(edr_command_state_artifact_next(&cursor,&stage)==0);
    assert(!upload_calls && !metadata_flushes);return 0;
  }
  if(argc==3 && !strcmp(argv[1],"--stage-restart")) {
    EdrCommandStateCapacityStats stats;assert(edr_command_state_get_capacity_stats(&stats)==0 && stats.artifact_reserved_bytes>0);
    size_t cursor=0;EdrCommandArtifactStage stage;
    assert(edr_command_state_artifact_next(&cursor,&stage)==1 && !strcmp(stage.command_id,argv[2]));
    assert(edr_command_state_artifact_abandon(stage.command_id)==-1);
    assert(edr_command_upload_outbox_publish_stage(&stage)==0 && !edr_storage_artifact_reserved());
    assert(!upload_calls && metadata_flushes==1u && owner_flushes==1u);return 0;
  }
  if(argc==3 && !strcmp(argv[1],"--retry-restart")) {
    int attempted=99;
    assert(edr_command_upload_outbox_flush_one(argv[2],&attempted)==-6);
    assert(!attempted && !hash_operations && !metadata_flushes && !upload_calls);return 0;
  }
  if(argc==3 && !strcmp(argv[1],"--held-restart")) {
    policy_result=EDR_EGRESS_REQUEST_DENIED;int attempted=99;
    assert(edr_command_upload_outbox_flush_one(argv[2],&attempted)==EDR_EGRESS_REQUEST_DENIED);
    assert(!attempted && !hash_operations && !upload_calls && !terminal_calls);return 0;
  }
#ifdef _WIN32
  char temp[MAX_PATH]; assert(GetTempPathA(sizeof(temp), temp));
  assert(GetTempFileNameA(temp, "euo", 0, root)); assert(DeleteFileA(root)); make_dir(root);
  char original_cwd[MAX_PATH];
  DWORD cwd_size = GetCurrentDirectoryA(sizeof(original_cwd), original_cwd);
  assert(cwd_size > 0 && cwd_size < sizeof(original_cwd));
  /* Reproduce a drive-relative C: resolving to its root regardless of whether
   * this CI worker normally checks out on C: or another drive. */
  if (root[1] == ':' && (root[2] == '\\' || root[2] == '/')) {
    char drive_root[] = {root[0], ':', '\\', 0};
    assert(SetCurrentDirectoryA(drive_root));
  }
#else
  snprintf(root, sizeof(root), "%s/edr-upload-outbox.XXXXXX", getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp");
  assert(mkdtemp(root));
#endif
  strcpy(meta.idempotency_key, "idempotency|retained"); strcpy(meta.soar_correlation_id, "correlation");
  strcpy(meta.playbook_run_id, "run"); strcpy(meta.playbook_step_id, "step");
  if (argc == 2 && !strcmp(argv[1], "--credit-handoff")) {
    test_concurrent_handoff_credit();return 0;
  }
  if (argc == 2 && !strcmp(argv[1], "--physical-admission")) {
    test_metadata_physical_admission();
    puts("outbox physical admission contract passed"); return 0;
  }
  test_ancestor_outbox();
  test_metadata_physical_admission();
  test_concurrent_handoff_credit();
  test_durable_retry_and_deadline();test_retry_persist_failure_and_unknown_deadline();test_owner_final_preserved();
  test_staging_owner_recovery();test_staging_interrupted_and_final();
#ifndef _WIN32
  test_stage_own_metadata_credit();
#endif
  test_policy_hold_before_hash();
#ifdef _WIN32
  test_windows_bounded_metadata_publication();
  test_windows_readable_metadata_requires_durability();
#endif
  test_enqueue_failures(); test_legacy_upgrade(); test_reopen_after_terminal_failure();
  test_rename_retry(); test_receipt_failure(); test_terminal_commit_before_receipt_failure();
  test_readable_terminal_is_not_a_durable_commit(); test_failure_receipt_survives_artifact_recovery();
  test_bad_records_do_not_spend_upload_budget(); test_hash_and_missing_terminal();
#ifdef _WIN32
  assert(SetCurrentDirectoryA(original_cwd));
#endif
  puts("forensic upload outbox contract passed"); return 0;
}
