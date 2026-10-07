/* Exercise real metadata I/O and retries; only remote upload and terminal
 * handoff are replaced. CRT hooks inject write/close/publish failures. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "edr/command_state.h"
#include "edr/sha256.h"
static size_t hashed_bytes;
static const char *test_executable;
static int policy_result;
static void measured_hash(EdrSha256Ctx *ctx,const uint8_t *bytes,size_t n) {hashed_bytes+=n;edr_sha256_update(ctx,bytes,n);}
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
static void env(const char *key, const char *value) { setenv(key, value, 1); }
#endif

static int fail_flush, fail_close, close_after_flush, fail_publish, fail_fdopen;
static int fail_terminal_receipt, terminal_new;
static int injected_fflush(FILE *file) {
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
static BOOL WINAPI injected_move(LPCSTR src, LPCSTR dst, DWORD flags) {
  if (fail_publish) { fail_publish = 0; SetLastError(ERROR_ACCESS_DENIED); return FALSE; }
  return MoveFileExA(src, dst, flags);
}
static FILE *injected_fdopen(int fd, const char *mode) {
  if (fail_fdopen) { fail_fdopen = 0; errno = ENOMEM; return NULL; }
  return _fdopen(fd, mode);
}
#define _fdopen injected_fdopen
#define MoveFileExA injected_move
#else
static int injected_rename(const char *src, const char *dst) {
  if (fail_publish) { fail_publish = 0; errno = EACCES; return -1; }
  return rename(src, dst);
}
static int injected_link(const char *src, const char *dst) {
  if (fail_publish) { fail_publish = 0; errno = EACCES; return -1; }
  return link(src, dst);
}
static FILE *injected_fdopen(int fd, const char *mode) {
  if (fail_fdopen) { fail_fdopen = 0; errno = ENOMEM; return NULL; }
  return fdopen(fd, mode);
}
#define fdopen injected_fdopen
#define rename injected_rename
#define link injected_link
#endif
#define fflush injected_fflush
#define fclose injected_fclose
#define edr_sha256_update measured_hash
#include "../src/command/command_upload_outbox.c"
#undef edr_sha256_update
#undef fflush
#undef fclose
#ifdef _WIN32
#undef MoveFileExA
#undef _fdopen
#else
#undef rename
#undef fdopen
#undef link
#endif

/* Make failed state flushes leave complete readable bytes, as a real failed
 * fsync/_commit can. Recovery must flush again before retiring the upload. */
static int fail_state_flush;
static int state_test_fflush(FILE *file) {
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
void edr_local_evidence_cache_record_command_result(const char *id, const char *type,
    const char *status, int execution, int code, const char *detail, const char *artifacts) {
  (void)id; (void)type; (void)status; (void)execution; (void)code; (void)detail; (void)artifacts;
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
  terminal_new = fail_terminal_receipt = 0;
  policy_result=0;hashed_bytes=0;
  upload_calls = upload_fail = terminal_calls = terminal_fail = audits = 0;
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
static void test_legacy_upgrade(void) {
  setup("legacy"); char path[1200], done[1240], raw[8192]; int attempted;
  snprintf(path, sizeof(path), "%s/upload_cmd_old_123.pending", dir); legacy(path, "cmd_old", 0);
  upload_fail = 1;
  assert(edr_command_upload_outbox_flush_one(path, &attempted) == -1 && attempted == 1 && exists(path));
  upload_fail = 0;
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
  pending_path(path, sizeof(path), "cmd_receipt"); fail_publish = 1;
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
  snprintf(hold,sizeof(hold),"%s.policy-held",path);policy_result=EDR_EGRESS_REQUEST_DENIED;hashed_bytes=0;
  for(int i=0;i<3;i++)assert(edr_command_upload_outbox_flush_one(path,&attempted)==EDR_EGRESS_REQUEST_DENIED && !attempted);
  assert(hashed_bytes==0 && upload_calls==0 && terminal_calls==0 && exists(bundle) && exists(hold));
  /* Drop all volatile counters and reopen durable state, as restart would. */
  hashed_bytes=0;assert(edr_command_upload_outbox_flush_one(path,&attempted)==EDR_EGRESS_REQUEST_DENIED);
  contents(path,after,sizeof(after));assert(!strcmp(before,after) && hashed_bytes==0);
#ifdef _WIN32
  assert(_spawnl(_P_WAIT,test_executable,test_executable,"--held-restart",path,NULL)==0);
#else
  pid_t child=fork();assert(child>=0);
  if(!child){execl(test_executable,test_executable,"--held-restart",path,(char*)NULL);_exit(127);}
  int status=0;assert(waitpid(child,&status,0)==child && WIFEXITED(status) && WEXITSTATUS(status)==0);
#endif
  policy_result=EDR_EGRESS_AUTHORIZATION_EXPIRED;
  assert(edr_command_upload_outbox_flush_one(path,&attempted)==EDR_EGRESS_AUTHORIZATION_EXPIRED && !attempted);
  assert(remove(hold)==0);fail_flush=1;
  assert(edr_command_upload_outbox_flush_one(path,&attempted)==EDR_EGRESS_LOCAL_STATE_FAILURE && !attempted);
  assert(!hashed_bytes && exists(path));
  policy_result=0;upload_fail=1;
  assert(edr_command_upload_outbox_flush_one(path,&attempted)==-1 && attempted && hashed_bytes>0 && !exists(hold));
  upload_fail=0;assert(edr_command_upload_outbox_flush_one(path,&attempted)==1 && !exists(path));
}
int main(int argc,char **argv) {
  test_executable=argv[0];
  if(argc==3 && !strcmp(argv[1],"--held-restart")) {
    policy_result=EDR_EGRESS_REQUEST_DENIED;int attempted=99;
    assert(edr_command_upload_outbox_flush_one(argv[2],&attempted)==EDR_EGRESS_REQUEST_DENIED);
    assert(!attempted && !hashed_bytes && !upload_calls && !terminal_calls);return 0;
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
  test_policy_hold_before_hash();
  test_enqueue_failures(); test_legacy_upgrade(); test_reopen_after_terminal_failure();
  test_rename_retry(); test_receipt_failure(); test_terminal_commit_before_receipt_failure();
  test_readable_terminal_is_not_a_durable_commit(); test_failure_receipt_survives_artifact_recovery();
  test_bad_records_do_not_spend_upload_budget(); test_hash_and_missing_terminal();
#ifdef _WIN32
  assert(SetCurrentDirectoryA(original_cwd));
#endif
  puts("forensic upload outbox contract passed"); return 0;
}
