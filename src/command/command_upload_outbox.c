/* File-backed forensic uploads. Existing line records remain readable after upgrade. */
#include "command_upload_outbox.h"
#include "edr/command.h"
#include "edr/command_executor.h"
#include "edr/command_util.h"
#include "edr/response.h"
#include "edr/response_utils.h"
#include "edr/sha256.h"
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
#endif

#include "egress_hold.h"

#define UPLOAD_RECORD_CAP 8192u

typedef struct {
  char raw[UPLOAD_RECORD_CAP];
  char command_id[128], bundle[1024], sha[65], manifest[1024];
  char kind[48], type[80], source[80], object_key[1024], failure_reason[32];
  EdrSoarCommandMeta meta;
  int partial, terminal_persisted;
} UploadRecord;

static int read_record(const char *path, UploadRecord *record);

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

#ifndef _WIN32
static int sync_parent(const char *path) {
  char parent[1200];
  if (strlen(path) >= sizeof(parent)) return -1;
  strcpy(parent, path);
  char *slash = strrchr(parent, '/');
  if (slash) { if (slash == parent) slash[1] = 0; else *slash = 0; }
  else strcpy(parent, ".");
  int fd = open(parent, O_RDONLY);
  if (fd < 0) return -1;
  int rc = fsync(fd);
  if (close(fd) != 0) rc = -1;
  return rc;
}
#endif

static int move_record(const char *from, const char *to, int replace) {
#ifdef _WIN32
  DWORD flags = MOVEFILE_WRITE_THROUGH | (replace ? MOVEFILE_REPLACE_EXISTING : 0);
  return MoveFileExA(from, to, flags) ? 0 : -1;
#else
  if (replace) { if (rename(from, to) != 0) return -1; }
  else {
    if (link(from, to) != 0) return -1;
    if (unlink(from) != 0) { (void)unlink(to); return -1; }
  }
  return sync_parent(to);
#endif
}

/* Publish complete metadata only after the file contents are flushed. A failed
 * replacement retains the previous pending record for recovery. */
static int write_record(const char *path, const char *raw, int replace) {
  char tmp[1240];
#ifdef _WIN32
  static volatile LONG sequence;
  if (snprintf(tmp, sizeof(tmp), "%s.tmp.%lu.%ld", path,
               (unsigned long)GetCurrentProcessId(), (long)InterlockedIncrement(&sequence)) >= (int)sizeof(tmp)) return -1;
  int fd = _open(tmp, _O_WRONLY | _O_CREAT | _O_EXCL | _O_BINARY, _S_IREAD | _S_IWRITE);
  FILE *f = fd < 0 ? NULL : _fdopen(fd, "wb");
  if (!f && fd >= 0) _close(fd);
#else
  if (snprintf(tmp, sizeof(tmp), "%s.tmp.XXXXXX", path) >= (int)sizeof(tmp)) return -1;
  int fd = mkstemp(tmp);
  FILE *f = fd < 0 ? NULL : fdopen(fd, "wb");
  if (!f && fd >= 0) close(fd);
#endif
  if (!f) {
    if (fd >= 0) (void)remove(tmp);
    edr_command_audit_both("", "forensic upload metadata open failed");
    return -1;
  }
  size_t size = strlen(raw);
  int ok = size < UPLOAD_RECORD_CAP && fwrite(raw, 1, size, f) == size && flush_file(f) == 0;
  if (fclose(f) != 0) ok = 0;
  if (ok) ok = move_record(tmp, path, replace) == 0;
  if (!ok) {
    (void)remove(tmp);
    edr_command_audit_both("", "forensic upload metadata write, flush or publication failed");
  }
  return ok ? 0 : -1;
}

static int file_hash(const char *path, char sha[65]) {
  FILE *f = fopen(path, "rb");
  if (!f) return errno == ENOENT ? -2 : -1;
  EdrSha256Ctx ctx;
  edr_sha256_init(&ctx);
  unsigned char bytes[16384], digest[EDR_SHA256_DIGEST_LEN];
  size_t size;
  while ((size = fread(bytes, 1, sizeof(bytes), f)) > 0u) edr_sha256_update(&ctx, bytes, size);
  int ok = !ferror(f);
  if (fclose(f) != 0) ok = 0;
  if (!ok) return -1;
  edr_sha256_final(&ctx, digest);
  for (size_t i = 0; i < sizeof(digest); ++i) snprintf(sha + i * 2u, 3u, "%02x", digest[i]);
  return 0;
}

static int hash_valid(const char *sha) {
  if (strlen(sha) != 64u) return 0;
  for (size_t i = 0; i < 64u; ++i) if (!isxdigit((unsigned char)sha[i])) return 0;
  return 1;
}

static int queue_upload(const char *command_id, const char *type, const EdrSoarCommandMeta *meta,
                        const char *bundle, const char *sha, const char *manifest,
                        const char *source, int partial) {
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
  if (response_mkdir_p(dir) != 0) return -1;
  strcpy(safe, command_id);
  for (char *p = safe; *p; ++p) if (!isalnum((unsigned char)*p) && *p != '-' && *p != '_') *p = '_';
  /* Atomic publication does not overwrite another command's existing record. */
  int n = snprintf(raw, sizeof(raw),
      "kind=%s\ncommand_id=%s\ncommand_type=%s\nbundle_path=%s\nsha256=%s\nmanifest_path=%s\n"
      "source=%s\npartial=%d\nidempotency_key=%s\nsoar_correlation_id=%s\nplaybook_run_id=%s\n"
      "playbook_step_id=%s\ncreated_unix_ms=%lld\n",
      type[0] ? "forensic_terminal" : "", command_id, type, bundle, actual, manifest,
      source, partial ? 1 : 0, meta->idempotency_key, meta->soar_correlation_id,
      meta->playbook_run_id, meta->playbook_step_id, (long long)time(NULL) * 1000LL);
  if (n < 0 || (size_t)n >= sizeof(raw)) return -1;
  /* Command id and content identify an idempotent enqueue across process restarts. */
  n = snprintf(path, sizeof(path), "%s/upload_%s_%s.pending", dir, safe, actual);
  if (n < 0 || (size_t)n >= sizeof(path)) return -1;
  UploadRecord prior;
  int prior_rc = read_record(path, &prior);
  if (prior_rc != 0) {
    char done[1240];
    if (snprintf(done, sizeof(done), "%s.done", path) >= (int)sizeof(done)) return -1;
    prior_rc = read_record(done, &prior);
  }
  if (prior_rc != 0 && write_record(path, raw, 0) == 0) {
    edr_command_executor_wake();
    return 0;
  }
  /* A repeated enqueue preserves the uploaded receipt and SOAR metadata.
   * Re-read after a competing publisher wins the no-replace operation. */
  if (prior_rc != 0) prior_rc = read_record(path, &prior);
  if (prior_rc != 0 || strcmp(prior.command_id, command_id) ||
      strcmp(prior.type, type) || strcmp(prior.bundle, bundle) || strcmp(prior.sha, actual) ||
      strcmp(prior.manifest, manifest) || strcmp(prior.source, source) ||
      prior.partial != !!partial || strcmp(prior.meta.idempotency_key, meta->idempotency_key) ||
      strcmp(prior.meta.soar_correlation_id, meta->soar_correlation_id) ||
      strcmp(prior.meta.playbook_run_id, meta->playbook_run_id) ||
      strcmp(prior.meta.playbook_step_id, meta->playbook_step_id)) return -1;
#ifndef _WIN32
  if (sync_parent(path) != 0) return -1;
#endif
  edr_command_executor_wake();
  return 0;
}

int edr_command_upload_outbox_write_legacy(const char *command_id, const char *bundle,
                                         const char *sha256, const char *manifest) {
  return queue_upload(command_id, "", NULL, bundle, sha256, manifest ? manifest : "", "", 0);
}

int edr_command_queue_forensic_upload(const char *command_id, const char *command_type,
                                    const EdrSoarCommandMeta *meta, const char *artifact,
                                    const char *sha256, const char *source, int partial) {
  return queue_upload(command_id, command_type ? command_type : "collect_forensic", meta,
                      artifact, sha256, "", source ? source : "builtin", partial);
}

/* One bounded read preserves the exact legacy metadata when adding receipts. */
static int read_record(const char *path, UploadRecord *r) {
  memset(r, 0, sizeof(*r));
  FILE *f = fopen(path, "rb");
  if (!f) return -1;
  size_t size = fread(r->raw, 1, sizeof(r->raw) - 1u, f);
  int ok = !ferror(f), extra = fgetc(f);
  if (ferror(f)) ok = 0;
  if (fclose(f) != 0) ok = 0;
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
    line = next;
  }
  if (!r->command_id[0] || !r->bundle[0] || !hash_valid(r->sha) ||
      (r->kind[0] && strcmp(r->kind, "forensic_terminal")) ||
      (r->failure_reason[0] && strcmp(r->failure_reason, "artifact_missing") &&
       strcmp(r->failure_reason, "artifact_hash_changed")) ||
      (r->failure_reason[0] && r->object_key[0]) ||
      (r->terminal_persisted == 1 && !r->object_key[0]) ||
      (r->terminal_persisted == 2 && r->object_key[0])) return 1;
  return 0;
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
        !strcmp(pending_sha, done_sha) && remove(path) == 0) {
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

int edr_command_upload_outbox_flush_one(const char *path, int *upload_attempted) {
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
  const char *error = !strcmp(r.failure_reason, "artifact_missing")
      ? "artifact missing before upload retry"
      : !strcmp(r.failure_reason, "artifact_hash_changed")
          ? "artifact hash changed before upload retry" : "";
  if (!r.object_key[0] && !r.failure_reason[0]) {
    char hold_path[1400];
    if (snprintf(hold_path,sizeof(hold_path),"%s.policy-held",path)>=(int)sizeof(hold_path)) return -2;
    uint64_t permitted_size=0;
    int admission=edr_egress_upload_preflight(r.command_id,r.command_id,r.bundle,r.sha,&permitted_size);
    if (edr_egress_is_policy_hold(admission)) {
      int held=edr_hold_write(hold_path,r.command_id,admission);
      edr_command_audit_both(r.command_id, held==EDR_EGRESS_LOCAL_STATE_FAILURE
          ? "forensic policy hold persistence failed; original pending and artifact retained"
          : "forensic upload policy held; original pending and artifact retained");
      return held;
    }
    if (admission || edr_hold_clear(hold_path)) return -2;
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
      *upload_attempted = 1;
      int upload_rc=edr_transport_v2_upload_file(r.command_id, r.bundle, r.sha, r.object_key, sizeof(r.object_key));
      if (edr_egress_is_policy_hold(upload_rc)) {
        *upload_attempted=0;
        int held=edr_hold_write(hold_path,r.command_id,upload_rc);
        if(held==EDR_EGRESS_LOCAL_STATE_FAILURE) edr_command_audit_both(r.command_id,"forensic policy hold persistence failed; pending retained");
        return held;
      }
      if (upload_rc != 0 || !r.object_key[0]) return -1;
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
