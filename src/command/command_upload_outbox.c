/* File-backed forensic uploads. Existing line records remain readable after upgrade. */
#include "command_upload_outbox.h"
#include "edr/command.h"
#include "edr/command_executor.h"
#include "edr/command_util.h"
#include "edr/response.h"
#include "edr/response_utils.h"
#include "edr/sha256.h"
#include "edr/forensic_path.h"
#include "edr/forensic_worker.h"
#include "edr/storage_physical_guard.h"
#include "edr/transport_v2.h"
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef _WIN32
#include <windows.h>
#include <io.h>
#include <fcntl.h>
#include <sys/stat.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/random.h>
#endif
#endif

static FILE *hold_open_read(const char *path);
static int write_record(const char *path,const char *raw,int replace);
static int remove_metadata(const char *path);
#define EDR_HOLD_OPEN_READ(path) hold_open_read(path)
#define EDR_HOLD_ATOMIC_WRITE(path,raw) write_record(path,raw,1)
#define EDR_HOLD_REMOVE(path) remove_metadata(path)
#include "egress_hold.h"
#undef EDR_HOLD_OPEN_READ
#undef EDR_HOLD_ATOMIC_WRITE
#undef EDR_HOLD_REMOVE

#define UPLOAD_RECORD_CAP 8192u
#ifndef EDR_UPLOAD_OUTBOX_NOW_MS
#define EDR_UPLOAD_OUTBOX_NOW_MS() ((int64_t)time(NULL) * 1000LL)
#endif
/* Same finite delivery horizon as admitted command-result authority. Legacy
 * records derive it from their original creation time, never restart time. */
#define UPLOAD_DELIVERY_WINDOW_MS (24LL * 60LL * 60LL * 1000LL)

typedef struct {
  char raw[UPLOAD_RECORD_CAP];
  char command_id[128], bundle[1024], sha[65], manifest[1024];
  char kind[48], type[80], source[80], object_key[1024], failure_reason[32];
  EdrSoarCommandMeta meta;
  int partial, terminal_persisted;
  uint64_t attempts;
  int64_t created_ms, retry_after_ms, deadline_ms;
} UploadRecord;

static int read_record(const char *path, UploadRecord *record);

static int metadata_space_available_owned(const char *path,uint64_t artifact_credit) {
  EdrStoragePhysicalSnapshot snapshot;
  /* The current record is already included in volume usage. Budget the new
   * bounded staging copy plus allocation/directory overhead. Only publication
   * from a verified stage can use that owner's durable metadata credit; all
   * other outbox writes retain the complete protected floor. */
  if (edr_storage_physical_admit_owned(path, UPLOAD_RECORD_CAP + 4096u, 0, artifact_credit, &snapshot) == 0)
    return 1;
  edr_command_audit_both("", snapshot.cause ? snapshot.cause : "forensic metadata space unavailable");
  return 0;
}
static int metadata_space_available(const char *path) {return metadata_space_available_owned(path,0u);}

void edr_command_upload_outbox_dir(char *out, size_t cap) {
  const char *dir = getenv("EDR_UPLOAD_OUTBOX_DIR");
  if (!dir || !dir[0]) dir = getenv("EDR_COMMAND_OUTBOX_DIR");
#ifdef _WIN32
  if (!dir || !dir[0]) dir = "C:\\Program Files\\FDSecurity\\upload_outbox";
#else
  if (!dir || !dir[0]) dir = "/tmp/edr_upload_outbox";
#endif
  snprintf(out, cap, "%s", dir);
}

static int plain_value(const char *value, size_t cap) {
  if (!value) return 0;
  for (size_t i = 0; i < cap; ++i) {
    if (!value[i]) return 1;
    if (value[i] == '\r' || value[i] == '\n') return 0;
  }
  return 0;
}

static int flush_file(FILE *f) {
  if (fflush(f) != 0) return -1;
#ifdef _WIN32
  return _commit(_fileno(f));
#else
  return fsync(fileno(f));
#endif
}

static int sync_parent(const char *path) {
#ifdef _WIN32
  EdrForensicIoRequest *q=calloc(1,sizeof(*q));if(!q)return -1;
  q->version=1;q->operation=3;q->timeout_ms=300000u;
  int n=snprintf(q->staging,sizeof(q->staging),"%s",path);
  EdrForensicIoResult receipt={0};
  int rc=n<0 || (size_t)n>=sizeof(q->staging) ? -1 : edr_forensic_io_run(q,&receipt,NULL,NULL);
  free(q);return rc;
#else
  EdrForensicPath *guard=NULL;
  if(edr_forensic_path_acquire(path,0,&guard))return -1;
  int rc=edr_forensic_path_sync_parent(guard);
  edr_forensic_path_release(guard);return rc;
#endif
}

static int move_guarded(EdrForensicPath *from,EdrForensicPath *to,int replace) {
#ifdef _WIN32
  for(unsigned attempt=0;attempt<3u;attempt++) {
    if(!edr_forensic_path_move(from,to,replace))return 0;
    DWORD error=GetLastError();
    if(attempt==2u || (error!=ERROR_ACCESS_DENIED && error!=ERROR_SHARING_VIOLATION && error!=ERROR_LOCK_VIOLATION)) {
      char cause[96];snprintf(cause,sizeof(cause),"forensic file publication failed; win32_error=%lu",error);
      edr_command_audit_both("",cause);SetLastError(error);return -1;
    }
    Sleep((attempt+1u)*10u);
  }
  return -1;
#else
  return edr_forensic_path_move(from,to,replace);
#endif
}
static int move_record(const char *from,const char *to,int replace) {
  EdrForensicPath *a=NULL,*b=NULL;int rc=-1;
  if(!edr_forensic_path_acquire(from,0,&a) && !edr_forensic_path_acquire(to,0,&b))rc=move_guarded(a,b,replace);
  edr_forensic_path_release(b);edr_forensic_path_release(a);return rc;
}
/* Publish complete metadata only after the file contents are flushed. A failed
 * replacement retains the previous pending record for recovery. */
static int write_record_owned(const char *path, const char *raw, int replace,uint64_t credit) {
  char tmp[1240];
  EdrForensicPath *target=NULL,*scratch=NULL;
  if(edr_forensic_path_acquire(path,1,&target))return -1;
  if(!metadata_space_available_owned(path,credit)) {edr_forensic_path_release(target);return -1;}
#ifdef _WIN32
  static volatile LONG sequence;
  unsigned long serial=(unsigned long)InterlockedIncrement(&sequence),pid=GetCurrentProcessId();
#else
  static unsigned long sequence;
  unsigned long serial=__atomic_add_fetch(&sequence,1,__ATOMIC_RELAXED),pid=(unsigned long)getpid();
#endif
  char nonce[17]="";
#ifndef _WIN32
  unsigned char random[8];
#if defined(__linux__)
  if(getrandom(random,sizeof(random),GRND_NONBLOCK)!=(ssize_t)sizeof(random)) {
    edr_forensic_path_release(target);return -1;
  }
#else
  arc4random_buf(random,sizeof(random));
#endif
  for(size_t i=0;i<sizeof(random);i++)snprintf(nonce+i*2,3,"%02x",random[i]);
#endif
  FILE *f=NULL;
  if(snprintf(tmp,sizeof(tmp),"%s.tmp.%lu.%lu%s",path,pid,serial,nonce)<(int)sizeof(tmp) &&
      !edr_forensic_path_acquire(tmp,0,&scratch))f=edr_forensic_path_file(scratch,"wbx");
  if(!f) {
    edr_forensic_path_release(scratch);edr_forensic_path_release(target);
    edr_command_audit_both("", "forensic upload metadata open failed");return -1;
  }
  size_t size = strlen(raw);
  int ok = size < UPLOAD_RECORD_CAP && fwrite(raw, 1, size, f) == size && flush_file(f) == 0;
  if (fclose(f) != 0) ok = 0;
  if (ok) ok = move_guarded(scratch, target, replace) == 0;
  if (!ok) {
    (void)edr_forensic_path_remove_temp(scratch);
    edr_command_audit_both("", "forensic upload metadata write, flush or publication failed");
  }
  edr_forensic_path_release(scratch);edr_forensic_path_release(target);
  return ok ? 0 : -1;
}
static int write_record(const char *path,const char *raw,int replace) {
  return write_record_owned(path,raw,replace,0u);
}

static FILE *hold_open_read(const char *path) {
  EdrForensicPath *guard=NULL;
  if(edr_forensic_path_acquire(path,0,&guard))return NULL;
  uint64_t ignored=0;int present=edr_forensic_path_size(guard,&ignored);
  FILE *f=present ? NULL : edr_forensic_path_file(guard,"rb");
  edr_forensic_path_release(guard);
  if(present==1)errno=ENOENT;else if(!f)errno=EIO;
  return f;
}
static int remove_metadata(const char *path) {
  EdrForensicPath *guard=NULL;
  if(edr_forensic_path_acquire(path,0,&guard)){errno=EIO;return -1;}
  uint64_t ignored=0;int present=edr_forensic_path_size(guard,&ignored);
  int rc=present ? -1 : edr_forensic_path_remove_temp(guard);
  if(!rc)rc=edr_forensic_path_sync_parent(guard);
  edr_forensic_path_release(guard);
  if(present==1)errno=ENOENT;else if(rc)errno=EIO;
  return rc;
}

static int file_hash(const char *path, char sha[65]) {
  if(!path || strlen(path)>=sizeof(((EdrForensicIoRequest *)0)->staging))return -1;
  EdrForensicIoRequest *request=calloc(1,sizeof(*request));if(!request)return -1;
  request->version=1;request->operation=2;request->timeout_ms=300000u;
  snprintf(request->staging,sizeof(request->staging),"%s",path);
  EdrForensicIoResult receipt={0};int rc=edr_forensic_io_run(request,&receipt,NULL,NULL);free(request);
  if(!rc)snprintf(sha,65,"%s",receipt.sha256);
  return rc;
}

static int hash_valid(const char *sha) {
  if (strlen(sha) != 64u) return 0;
  for (size_t i = 0; i < 64u; ++i) if (!isxdigit((unsigned char)sha[i])) return 0;
  return 1;
}

static int queue_upload(const char *command_id, const char *type, const EdrSoarCommandMeta *meta,
                        const char *bundle, const char *sha, const char *manifest,
                        const char *source, int partial,uint64_t artifact_credit) {
  EdrSoarCommandMeta empty;
  memset(&empty, 0, sizeof(empty));
  if (!meta) meta = &empty;
  if (!plain_value(command_id, 128u) || !command_id[0] || !plain_value(bundle, 1024u) || !bundle[0] ||
      !plain_value(sha, 65u) || !hash_valid(sha) || !plain_value(manifest, 1024u) ||
      !plain_value(type, 80u) || !plain_value(source, 80u) ||
      !plain_value(meta->idempotency_key, sizeof(meta->idempotency_key)) ||
      !plain_value(meta->soar_correlation_id, sizeof(meta->soar_correlation_id)) ||
      !plain_value(meta->playbook_run_id, sizeof(meta->playbook_run_id)) ||
      !plain_value(meta->playbook_step_id, sizeof(meta->playbook_step_id))) return -1;
  char actual[65];
  if (file_hash(bundle, actual) != 0) return -1;
  for (size_t i = 0; i < 64u; ++i) if (actual[i] != tolower((unsigned char)sha[i])) return -1;
  char dir[700], path[1200], safe[128], raw[UPLOAD_RECORD_CAP];
  edr_command_upload_outbox_dir(dir, sizeof(dir));
  strcpy(safe, command_id);
  for (char *p = safe; *p; ++p) if (!isalnum((unsigned char)*p) && *p != '-' && *p != '_') *p = '_';
  /* Atomic publication does not overwrite another command's existing record. */
  int n = snprintf(raw, sizeof(raw),
      "kind=%s\ncommand_id=%s\ncommand_type=%s\nbundle_path=%s\nsha256=%s\nmanifest_path=%s\n"
      "source=%s\npartial=%d\nidempotency_key=%s\nsoar_correlation_id=%s\nplaybook_run_id=%s\n"
      "playbook_step_id=%s\ncreated_unix_ms=%lld\ndelivery_deadline_unix_ms=%lld\n",
      type[0] ? "forensic_terminal" : "", command_id, type, bundle, actual, manifest,
      source, partial ? 1 : 0, meta->idempotency_key, meta->soar_correlation_id,
      meta->playbook_run_id, meta->playbook_step_id, (long long)EDR_UPLOAD_OUTBOX_NOW_MS(),
      (long long)(meta->result_authorization.expires_unix_ms > 0
        ? meta->result_authorization.expires_unix_ms : EDR_UPLOAD_OUTBOX_NOW_MS() + UPLOAD_DELIVERY_WINDOW_MS));
  if (n < 0 || (size_t)n >= sizeof(raw)) return -1;
  /* Command id and content identify an idempotent enqueue across process restarts. */
  n = snprintf(path, sizeof(path), "%s/upload_%s_%s.pending", dir, safe, actual);
  if (n < 0 || (size_t)n >= sizeof(path)) return -1;
  UploadRecord prior;
  char prior_path[1240];snprintf(prior_path,sizeof(prior_path),"%s",path);
  int prior_rc = read_record(path, &prior);
  if (prior_rc != 0) {
    char done[1240];
    if (snprintf(done, sizeof(done), "%s.done", path) >= (int)sizeof(done)) return -1;
    snprintf(prior_path,sizeof(prior_path),"%s",done);
    prior_rc = read_record(done, &prior);
    if (prior_rc != 0) {
      if (snprintf(done, sizeof(done), "%s.failed", path) >= (int)sizeof(done)) return -1;
      snprintf(prior_path,sizeof(prior_path),"%s",done);
      prior_rc = read_record(done, &prior);
    }
  }
  if (prior_rc != 0 && write_record_owned(path, raw, 0, artifact_credit) == 0) {
    if(!artifact_credit)edr_command_executor_wake();
    return 0;
  }
  /* A repeated enqueue preserves the uploaded receipt and SOAR metadata.
   * Re-read after a competing publisher wins the no-replace operation. */
  if (prior_rc != 0) {
    snprintf(prior_path,sizeof(prior_path),"%s",path);prior_rc = read_record(path, &prior);
  }
  if (prior_rc != 0 || strcmp(prior.command_id, command_id) ||
      strcmp(prior.type, type) || strcmp(prior.bundle, bundle) || strcmp(prior.sha, actual) ||
      strcmp(prior.manifest, manifest) || strcmp(prior.source, source) ||
      prior.partial != !!partial || strcmp(prior.meta.idempotency_key, meta->idempotency_key) ||
      strcmp(prior.meta.soar_correlation_id, meta->soar_correlation_id) ||
      strcmp(prior.meta.playbook_run_id, meta->playbook_run_id) ||
      strcmp(prior.meta.playbook_step_id, meta->playbook_step_id)) return -1;
  /* A previous rename may be readable after its final durability flush
   * failed. Re-confirm durability before accepting an idempotent record. */
  if (sync_parent(prior_path) != 0) return -1;
  if(!artifact_credit)edr_command_executor_wake();
  return 0;
}

int edr_command_upload_outbox_write_legacy(const char *command_id, const char *bundle,
                                         const char *sha256, const char *manifest) {
  return queue_upload(command_id, "", NULL, bundle, sha256, manifest ? manifest : "", "", 0,0u);
}

int edr_command_queue_forensic_upload(const char *command_id, const char *command_type,
                                    const EdrSoarCommandMeta *meta, const char *artifact,
                                    const char *sha256, const char *source, int partial) {
  return queue_upload(command_id, command_type ? command_type : "collect_forensic", meta,
                      artifact, sha256, "", source ? source : "builtin", partial,0u);
}

/* Called only with the existing command owner lock held. It performs no
 * command-state calls; wake workers after handoff releases that lock. */
static int publish_stage_locked(const EdrCommandArtifactStage *stage,uint64_t credit) {
  EdrForensicPath *staging=NULL,*artifact=NULL;uint64_t bytes=0;int rc=-1;
  if(edr_forensic_path_acquire(stage->staging,0,&staging) ||
     edr_forensic_path_acquire(stage->artifact,0,&artifact))goto done;
  int present=edr_forensic_path_size(staging,&bytes);
  if(present<0)goto done;
  if(bytes && move_guarded(staging,artifact,0)) {
    /* Keep both directory chains through recovery hash and durable handoff. */
    char actual[65];
    if(file_hash(stage->artifact,actual) || strcmp(actual,stage->sha256))goto done;
  }
  rc=queue_upload(stage->command_id,stage->command_type,&stage->meta,
       stage->artifact,stage->sha256,"","builtin",0,credit);
done:
  edr_forensic_path_release(artifact);edr_forensic_path_release(staging);return rc;
}

int edr_command_upload_outbox_publish_stage(const EdrCommandArtifactStage *stage) {
  if(!stage)return -1;
  if(stage->phase==1 && stage->interrupted) {
    int final=edr_command_state_has_final(stage->command_id,&stage->meta);
    if(final<0)return -1;
    if(!final && edr_response_forensic_complete_queued_upload(stage->command_id,stage->command_type,
        &stage->meta,stage->staging,"","","builtin",0,0,
        "collection interrupted by service restart; prior writer unknown; local evidence and reservation retained"))return -1;
    return edr_command_state_artifact_mark_interrupted(stage->command_id);
  }
  if(stage->phase!=2 || !hash_valid(stage->sha256))return -1;
  int rc=edr_command_state_artifact_handoff(stage,publish_stage_locked);
  if(!rc)edr_command_executor_wake();
  return rc;
}

/* One bounded read preserves the exact legacy metadata when adding receipts. */
static int read_record(const char *path, UploadRecord *r) {
  memset(r, 0, sizeof(*r));
  EdrForensicPath *guard=NULL;
  if(edr_forensic_path_acquire(path,0,&guard))return -1;
  FILE *f=edr_forensic_path_file(guard,"rb");
  if(!f){edr_forensic_path_release(guard);return -1;}
  size_t size = fread(r->raw, 1, sizeof(r->raw) - 1u, f);
  int ok = !ferror(f), extra = fgetc(f);
  if (ferror(f)) ok = 0;
  if (fclose(f) != 0) ok = 0;
  edr_forensic_path_release(guard);
  if (!ok) return -1;
  if (extra != EOF || memchr(r->raw, 0, size)) return 1;
  struct Field { const char *key; char *value; size_t cap; int seen; } fields[] = {
#define F(key, member) {key, r->member, sizeof(r->member), 0}
      F("kind", kind), F("command_id", command_id), F("command_type", type),
      F("bundle_path", bundle), F("sha256", sha), F("manifest_path", manifest),
      F("source", source), F("object_key", object_key), F("failure_reason", failure_reason),
      F("idempotency_key", meta.idempotency_key),
      F("soar_correlation_id", meta.soar_correlation_id), F("playbook_run_id", meta.playbook_run_id),
      F("playbook_step_id", meta.playbook_step_id)
#undef F
  };
  char copy[UPLOAD_RECORD_CAP];
  memcpy(copy, r->raw, size + 1u);
  int partial_seen = 0, terminal_seen = 0;
  unsigned number_seen = 0;
  for (char *line = copy; line;) {
    char *next = strchr(line, '\n');
    if (next) *next++ = 0;
    size_t len = strlen(line);
    if (len && line[len - 1u] == '\r') line[--len] = 0;
    if (!line[0]) { line = next; continue; }
    char *equal = strchr(line, '=');
    if (!equal) return 1;
    *equal++ = 0;
    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); ++i) {
      if (strcmp(line, fields[i].key) == 0) {
        if (fields[i].seen++ || !plain_value(equal, fields[i].cap)) return 1;
        strcpy(fields[i].value, equal);
      }
    }
    if (!strcmp(line, "partial")) {
      if (partial_seen++ || (strcmp(equal, "0") && strcmp(equal, "1"))) return 1;
      r->partial = equal[0] == '1';
    }
    if (!strcmp(line, "terminal_persisted")) {
      if (terminal_seen++ || (strcmp(equal, "uploaded") && strcmp(equal, "failed"))) return 1;
      r->terminal_persisted = !strcmp(equal, "uploaded") ? 1 : 2;
    }
    const char *numbers[] = {"created_unix_ms", "delivery_deadline_unix_ms", "retry_after_unix_ms", "attempts"};
    for (unsigned i = 0; i < sizeof(numbers)/sizeof(numbers[0]); ++i) {
      if (strcmp(line, numbers[i])) continue;
      uint64_t value = 0;
      if ((number_seen & (1u << i)) || edr_storage_parse_u64(equal, &value) || value > INT64_MAX) return 1;
      number_seen |= 1u << i;
      if (i == 0) r->created_ms = (int64_t)value;
      else if (i == 1) r->deadline_ms = (int64_t)value;
      else if (i == 2) r->retry_after_ms = (int64_t)value;
      else r->attempts = value;
    }
    line = next;
  }
  if (!r->command_id[0] || !r->bundle[0] || !hash_valid(r->sha) ||
      (r->kind[0] && strcmp(r->kind, "forensic_terminal")) ||
      (r->failure_reason[0] && strcmp(r->failure_reason, "artifact_missing") &&
       strcmp(r->failure_reason, "artifact_hash_changed") &&
       strcmp(r->failure_reason, "delivery_deadline_exceeded") &&
       strcmp(r->failure_reason, "command_owner_final")) ||
      (r->failure_reason[0] && r->object_key[0]) ||
      (r->terminal_persisted == 1 && !r->object_key[0]) ||
      (r->terminal_persisted == 2 && r->object_key[0])) return 1;
  if (!r->deadline_ms && r->created_ms > 0 && r->created_ms <= INT64_MAX - UPLOAD_DELIVERY_WINDOW_MS)
    r->deadline_ms = r->created_ms + UPLOAD_DELIVERY_WINDOW_MS;
  return 0;
}

/* Replace only retry bookkeeping, preserving frozen/forward-compatible fields.
 * Failed attempts require one durable update. Success keeps the original
 * receipt-only write count. A crash inside the network call is still an
 * uncertain attempt; the stable upload id/hash preserves remote idempotency. */
static int persist_retry(const char *path, UploadRecord *r, int64_t now) {
  char raw[UPLOAD_RECORD_CAP]; size_t used = 0;
  for (const char *p = r->raw; *p;) {
    const char *end = strchr(p, '\n'); size_t n = end ? (size_t)(end-p)+1u : strlen(p);
    if (strncmp(p,"attempts=",9) && strncmp(p,"retry_after_unix_ms=",20)) {
      if (n >= sizeof(raw)-used) return -1;
      memcpy(raw+used,p,n); used+=n;
    }
    p += n;
  }
  uint64_t base=60u, cap=900u, v=0u;
  const char *s=getenv("EDR_UPLOAD_OUTBOX_RETRY_BACKOFF_S");
  if (s && !edr_storage_parse_u64(s,&v)) base=v<10u?10u:v>3600u?3600u:v;
  s=getenv("EDR_UPLOAD_OUTBOX_MAX_BACKOFF_S");
  if (s && !edr_storage_parse_u64(s,&v)) cap=v<base?base:v>86400u?86400u:v;
  uint64_t attempts=r->attempts<INT64_MAX?r->attempts+1u:INT64_MAX;
  uint64_t delay=base*(attempts>5u?5u:attempts); if(delay>cap)delay=cap;
  int64_t retry=now>INT64_MAX-(int64_t)delay*1000LL?INT64_MAX:now+(int64_t)delay*1000LL;
  int n=snprintf(raw+used,sizeof(raw)-used,"%sattempts=%llu\nretry_after_unix_ms=%lld\n",
      used && raw[used-1]!='\n'?"\n":"",(unsigned long long)attempts,(long long)retry);
  if(n<0 || (size_t)n>=sizeof(raw)-used || write_record(path,raw,1))return -1;
  strcpy(r->raw,raw);r->attempts=attempts;r->retry_after_ms=retry;return 0;
}

static int add_receipt(const char *path, UploadRecord *r, const char *key, const char *value) {
  if (!plain_value(value, 1024u)) return -1;
  size_t used = strlen(r->raw);
  int n = snprintf(r->raw + used, sizeof(r->raw) - used, "%s%s=%s\n",
                   used && r->raw[used - 1u] != '\n' ? "\n" : "", key, value);
  if (n < 0 || (size_t)n >= sizeof(r->raw) - used) return -1;
  return write_record(path, r->raw, 1);
}

static int retire_record(const char *path, const char *command_id, const char *suffix) {
  char done[1240];
  if (snprintf(done, sizeof(done), "%s.%s", path, suffix) >= (int)sizeof(done)) return -2;
  if (move_record(path, done, 0) != 0) {
    /* A POSIX crash between link and unlink can leave both complete copies.
     * Retire only an exact duplicate; keep a conflicting receipt untouched. */
    char pending_sha[65], done_sha[65];
    if (file_hash(path, pending_sha) == 0 && file_hash(done, done_sha) == 0 &&
        !strcmp(pending_sha, done_sha) && remove_metadata(path) == 0) {
#ifndef _WIN32
      if (sync_parent(done) != 0) return -2;
#endif
      return !strcmp(suffix, "done") ? 1 : 0;
    }
    edr_command_audit_both(command_id, "forensic upload state transition failed; recovery files retained");
    return -2;
  }
  return !strcmp(suffix, "done") ? 1 : 0;
}

static int flush_guarded(const char *path, int *upload_attempted, EdrForensicPath **artifact_guard) {
  *upload_attempted = 0;
  UploadRecord r;
  int rc = read_record(path, &r);
  if (rc < 0) {
    edr_command_audit_both("", "forensic upload record read failed; pending record retained");
    return -2;
  }
  if (rc > 0) {
    edr_command_audit_both(r.command_id, "malformed forensic upload metadata; record quarantined");
    return retire_record(path, r.command_id, "failed");
  }
  const int terminal = !strcmp(r.kind, "forensic_terminal");
  if (r.terminal_persisted)
    return retire_record(path, r.command_id, r.terminal_persisted == 1 ? "done" : "failed");
  if(!r.deadline_ms && !r.object_key[0] && !r.failure_reason[0]) {
    edr_command_audit_both(r.command_id,
        "forensic upload delivery deadline unavailable; metadata quarantined and artifact retained");
    return retire_record(path,r.command_id,"failed");
  }
  int64_t now = EDR_UPLOAD_OUTBOX_NOW_MS();
  if (!r.object_key[0] && !r.failure_reason[0]) {
    if (r.deadline_ms > 0 && now >= r.deadline_ms) {
      strcpy(r.failure_reason,"delivery_deadline_exceeded");
      if(add_receipt(path,&r,"failure_reason",r.failure_reason))return -2;
    } else if (r.retry_after_ms > now) return -6;
  }
  const char *error = !strcmp(r.failure_reason, "artifact_missing")
      ? "artifact missing before upload retry"
      : !strcmp(r.failure_reason, "artifact_hash_changed")
          ? "artifact hash changed before upload retry"
          : !strcmp(r.failure_reason,"delivery_deadline_exceeded")
              ? "artifact delivery deadline exceeded; local evidence retained"
              : !strcmp(r.failure_reason,"command_owner_final")
                  ? "command owner already final; local evidence retained" : "";
  if (!strcmp(r.failure_reason,"command_owner_final")) return retire_record(path,r.command_id,"failed");
  if (!r.object_key[0] && !r.failure_reason[0]) {
    char hold_path[1400];
    if (snprintf(hold_path,sizeof(hold_path),"%s.policy-held",path)>=(int)sizeof(hold_path)) return -2;
    uint64_t permitted_size=0;
    int admission=edr_egress_upload_preflight(r.command_id,r.command_id,r.bundle,r.sha,&permitted_size);
    if (edr_egress_is_policy_hold(admission)) {
      int held=metadata_space_available(hold_path)
          ? edr_hold_write(hold_path,r.command_id,admission) : EDR_EGRESS_LOCAL_STATE_FAILURE;
      edr_command_audit_both(r.command_id, held==EDR_EGRESS_LOCAL_STATE_FAILURE
          ? "forensic policy hold persistence failed; original pending and artifact retained"
          : "forensic upload policy held; original pending and artifact retained");
      return held;
    }
    if (admission || edr_hold_clear(hold_path)) return -2;
    /* Do not start a remote upload when its local receipt cannot be staged.
     * Recheck at publication because other writers may consume free space. */
    if (!metadata_space_available(path)) return -2;
    /* The worker's hash guard ends with its process. Retain the same artifact
     * directory chain in this owner through transport and receipt publication. */
    if(edr_forensic_path_acquire(r.bundle,0,artifact_guard)) {
      edr_command_audit_both(r.command_id,"forensic artifact directory unsafe or unavailable; pending retained");return -2;
    }
    char actual[65];
    int hash_rc = file_hash(r.bundle, actual);
    if (hash_rc != 0) {
      if (hash_rc != -2) {
        edr_command_audit_both(r.command_id, "forensic artifact read failed; upload retained for retry");
        return -2;
      }
      error = "artifact missing before upload retry";
      strcpy(r.failure_reason, "artifact_missing");
    } else {
      for (size_t i = 0; i < 64u; ++i) if (actual[i] != tolower((unsigned char)r.sha[i])) {
        error = "artifact hash changed before upload retry";
        strcpy(r.failure_reason, "artifact_hash_changed");
        break;
      }
    }
    if (r.failure_reason[0] && add_receipt(path, &r, "failure_reason", r.failure_reason) != 0) {
      edr_command_audit_both(r.command_id, "forensic upload failure receipt persist failed; pending record retained");
      return -2;
    }
    if (!error[0]) {
      /* A final command cannot acquire a second delivery/terminal owner. A
       * recorded object receipt above still finishes its original handoff. */
      if (terminal) {
        int final=edr_command_state_has_final(r.command_id,&r.meta);
        if(final<0)return -2;
        if(final>0) {
          if(add_receipt(path,&r,"failure_reason","command_owner_final"))return -2;
          return retire_record(path,r.command_id,"failed");
        }
      }
      *upload_attempted = 1;
      int upload_rc=edr_transport_v2_upload_file(r.command_id, r.bundle, r.sha, r.object_key, sizeof(r.object_key));
      if (edr_egress_is_policy_hold(upload_rc)) {
        *upload_attempted=0;
        int held=metadata_space_available(hold_path)
            ? edr_hold_write(hold_path,r.command_id,upload_rc) : EDR_EGRESS_LOCAL_STATE_FAILURE;
        if(held==EDR_EGRESS_LOCAL_STATE_FAILURE) edr_command_audit_both(r.command_id,"forensic policy hold persistence failed; pending retained");
        return held;
      }
      if (upload_rc != 0 || !r.object_key[0]) {
        if (persist_retry(path,&r,now)) {
          edr_command_audit_both(r.command_id,"forensic retry schedule persistence failed; pending retained");
          return EDR_UPLOAD_OUTBOX_RETRY_PERSIST_FAILED;
        }
        return -1;
      }
      if (add_receipt(path, &r, "object_key", r.object_key) != 0) {
        edr_command_audit_both(r.command_id, "forensic upload receipt persist failed; pending record retained");
        return -2;
      }
    }
  }
  if (terminal && !r.terminal_persisted) {
    if (edr_response_forensic_complete_queued_upload(r.command_id, r.type, &r.meta, r.bundle, r.sha,
          r.object_key, r.source, r.partial, r.object_key[0] != 0, error) != 0) {
      edr_command_audit_both(r.command_id, "forensic upload terminal state persist failed; pending record retained");
      return -2;
    }
    if (add_receipt(path, &r, "terminal_persisted", r.object_key[0] ? "uploaded" : "failed") != 0) {
      edr_command_audit_both(r.command_id, "forensic terminal receipt persist failed; pending record retained");
      return -2;
    }
  }
  if (error[0]) edr_command_audit_both(r.command_id, error);
  return retire_record(path, r.command_id, r.object_key[0] ? "done" : "failed");
}

int edr_command_upload_outbox_flush_one(const char *path,int *upload_attempted) {
  if(!upload_attempted)return -2;
  *upload_attempted=0;EdrForensicPath *guard=NULL;
  if(edr_forensic_path_acquire(path,0,&guard)) {
    edr_command_audit_both("","forensic outbox directory unsafe or unavailable; pending retained");return -2;
  }
  EdrForensicPath *artifact_guard=NULL;
  int rc=flush_guarded(path,upload_attempted,&artifact_guard);
  edr_forensic_path_release(artifact_guard);edr_forensic_path_release(guard);return rc;
}
