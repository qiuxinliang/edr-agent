#include "edr/process_evidence_worker.h"
#include "edr/sha256.h"
#include "edr/time_util.h"
#include "edr/windows_file_identity.h"

#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <wincrypt.h>
#include <mscat.h>
#include <wintrust.h>
#include <softpub.h>

#define EDR_EVIDENCE_SLOTS EDR_PROCESS_EVIDENCE_CAPACITY
#define EDR_EVIDENCE_MAX_BYTES (16ULL * 1024ULL * 1024ULL)
#define EDR_EVIDENCE_HASH_MAX_NS (1000ULL * 1000000ULL)
#define EDR_EVIDENCE_QUEUE_MAX_NS (5000ULL * 1000000ULL)
#define EDR_EVIDENCE_STALL_NS (10000ULL * 1000000ULL)
/* Cover the three-second 4688 join plus the bounded evidence wait. Ready
 * results, not file handles, are protected from burst eviction here. */
#define EDR_EVIDENCE_RETAIN_NS (5000ULL * 1000000ULL)
#ifndef WTD_CACHE_ONLY_URL_RETRIEVAL
#define WTD_CACHE_ONLY_URL_RETRIEVAL 0x00001000u
#endif
typedef struct {
  char path[1024]; uint64_t generation; uint64_t queued_ns;
  char file_identity[EDR_WINDOWS_FILE_IDENTITY_V1_CAP];
  uint64_t file_write_time;
  /* A queued slot owns this handle until the worker transfers it to its
   * local job. The pathname is only a revalidation input, never an owner. */
  HANDLE owned_file;
  EdrProcessEvidence evidence;
  uint64_t last_used_ns;
  uint8_t queued, inflight, ready;
} EvidenceSlot;
static EvidenceSlot s_slots[EDR_EVIDENCE_SLOTS];
static SRWLOCK s_lock = SRWLOCK_INIT;
static HANDLE s_thread, s_wake; static volatile LONG s_stop;
static volatile LONGLONG s_active_started_ns;
/* A stuck WinVerifyTrust call cannot be safely cancelled.  Keep its handles
 * and slot storage alive after shutdown timeout; a later start is fail-closed
 * rather than racing the worker with freed state. */
static volatile LONG s_terminal_unhealthy;
static EdrProcessEvidenceMetrics s_metrics;

#ifdef EDR_PROCESS_EVIDENCE_TESTING
typedef struct {
  char identity[2][EDR_WINDOWS_FILE_IDENTITY_V1_CAP];
  uint64_t write_time[2];
  unsigned cursor;
  int enabled;
  int synthetic_wvt_result;
} EvidenceWvtPathTestHook;
static EvidenceWvtPathTestHook s_test_wvt_path_hook;

void edr_process_evidence_test_set_wvt_path_sequence(
    const char *before_identity, uint64_t before_write_time_100ns,
    const char *after_identity, uint64_t after_write_time_100ns) {
  memset(&s_test_wvt_path_hook, 0, sizeof(s_test_wvt_path_hook));
  if (!before_identity || !after_identity) return;
  snprintf(s_test_wvt_path_hook.identity[0],
           sizeof(s_test_wvt_path_hook.identity[0]), "%s", before_identity);
  snprintf(s_test_wvt_path_hook.identity[1],
           sizeof(s_test_wvt_path_hook.identity[1]), "%s", after_identity);
  s_test_wvt_path_hook.write_time[0] = before_write_time_100ns;
  s_test_wvt_path_hook.write_time[1] = after_write_time_100ns;
  s_test_wvt_path_hook.enabled = 1;
}

void edr_process_evidence_test_set_synthetic_wvt_result(int enabled) {
  s_test_wvt_path_hook.synthetic_wvt_result = enabled ? 1 : 0;
}
#endif

/* WinVerifyTrust has no safe cancellation primitive.  A slow call is made
 * visible as a recoverable worker stall: P0 requests fail closed immediately
 * while the worker is still allowed to return and resume service. */
static int evidence_worker_stalled(uint64_t now) {
  LONGLONG started = InterlockedCompareExchange64(&s_active_started_ns, 0, 0);
  return started > 0 && now >= (uint64_t)started &&
         now - (uint64_t)started >= EDR_EVIDENCE_STALL_NS;
}

static void evidence_mark_stalled(void) {
  AcquireSRWLockExclusive(&s_lock);
  s_metrics.worker_stalled = 1u;
  s_metrics.backpressure++;
  ReleaseSRWLockExclusive(&s_lock);
}

static void evidence_clear(EdrProcessEvidence *e, const char *reason) {
  memset(e, 0, sizeof(*e));
  strcpy(e->hash_quality, "unknown"); strcpy(e->hash_reason, reason);
  strcpy(e->signature_status, "unknown"); strcpy(e->signature_source, "WinVerifyTrust");
  strcpy(e->signature_quality, "unknown"); strcpy(e->signature_reason, reason);
  strcpy(e->revocation, "unknown");
}

static int file_identity_equal(const char *left, const char *right) {
  return edr_windows_file_identity_valid(left) &&
         edr_windows_file_identity_valid(right) && strcmp(left, right) == 0;
}

static void evidence_slot_close_owned_handle(EvidenceSlot *slot) {
  if (slot && slot->owned_file && slot->owned_file != INVALID_HANDLE_VALUE) {
    CloseHandle(slot->owned_file);
  }
  if (slot) slot->owned_file = NULL;
}

static void evidence_slot_reset(EvidenceSlot *slot) {
  if (!slot) return;
  evidence_slot_close_owned_handle(slot);
  memset(slot, 0, sizeof(*slot));
}

static int capture_file_identity_handle(HANDLE h, EdrProcessEvidence *e) {
  if (!e) return 0;
  return edr_windows_file_identity_from_handle((void *)h, e->file_identity,
                                               sizeof(e->file_identity),
                                               &e->file_write_time);
}

static int evidence_handle_matches(HANDLE file, const char *expected_identity,
                                   uint64_t expected_write_time) {
  EdrProcessEvidence observed;
  memset(&observed, 0, sizeof(observed));
  return capture_file_identity_handle(file, &observed) &&
         edr_windows_file_identity_snapshot_matches(expected_identity, expected_write_time,
                                                    observed.file_identity,
                                                    observed.file_write_time);
}

static int evidence_path_and_handle_match(const char *path, HANDLE file,
                                          const char *expected_identity,
                                          uint64_t expected_write_time) {
  char path_identity[EDR_WINDOWS_FILE_IDENTITY_V1_CAP];
  uint64_t path_write_time = 0u;
  if (!path || !path[0] ||
      !evidence_handle_matches(file, expected_identity, expected_write_time) ||
      !edr_windows_file_identity_from_path(path, path_identity, sizeof(path_identity),
                                           &path_write_time)) {
    return 0;
  }
#ifdef EDR_PROCESS_EVIDENCE_TESTING
  if (s_test_wvt_path_hook.enabled && s_test_wvt_path_hook.cursor < 2u) {
    unsigned index = s_test_wvt_path_hook.cursor++;
    snprintf(path_identity, sizeof(path_identity), "%s",
             s_test_wvt_path_hook.identity[index]);
    path_write_time = s_test_wvt_path_hook.write_time[index];
  }
#endif
  return edr_windows_file_identity_snapshot_matches(expected_identity, expected_write_time,
                                                    path_identity, path_write_time);
}

static int hash_file_same_handle(HANDLE file, uint64_t started,
                                 const char *expected_identity,
                                 uint64_t expected_write_time,
                                 EdrProcessEvidence *e) {
  uint8_t buf[32768], d[EDR_SHA256_DIGEST_LEN];
  DWORD read = 0u;
  uint64_t total = 0u;
  EdrProcessEvidence after;
  EdrSha256Ctx ctx; static const char hex[]="0123456789abcdef";
  LARGE_INTEGER zero;
  if (!file || file == INVALID_HANDLE_VALUE || !e || !expected_identity ||
      !evidence_handle_matches(file, expected_identity, expected_write_time)) {
    if (e) strcpy(e->hash_reason, "file_changed_after_enqueue");
    return 0;
  }
  snprintf(e->file_identity, sizeof(e->file_identity), "%s", expected_identity);
  e->file_write_time = expected_write_time;
  zero.QuadPart = 0;
  if (!SetFilePointerEx(file, zero, NULL, FILE_BEGIN)) {
    strcpy(e->hash_reason, "file_rewind_failed");
    return 0;
  }
  edr_sha256_init(&ctx);
  for (;;) {
    if (!ReadFile(file, buf, (DWORD)sizeof(buf), &read, NULL)) {
      strcpy(e->hash_reason, "file_read_failed"); return 0;
    }
    if (read == 0u) break;
    total += read;
    if (total > EDR_EVIDENCE_MAX_BYTES ||
        edr_monotonic_ns() - started > EDR_EVIDENCE_HASH_MAX_NS) {
      strcpy(e->hash_reason, total > EDR_EVIDENCE_MAX_BYTES ? "file_size_limit" : "hash_deadline"); return 0;
    }
    edr_sha256_update(&ctx, buf, read);
  }
  memset(&after, 0, sizeof(after));
  if (!capture_file_identity_handle(file, &after) ||
      !edr_windows_file_identity_snapshot_matches(expected_identity, expected_write_time,
                                                  after.file_identity,
                                                  after.file_write_time)) {
    strcpy(e->hash_reason, "file_changed_during_hash"); return 0;
  }
  edr_sha256_final(&ctx, d);
  for (size_t i=0;i<EDR_SHA256_DIGEST_LEN;i++) { e->sha256[i*2]=hex[d[i]>>4]; e->sha256[i*2+1]=hex[d[i]&15]; }
  e->sha256[64]=0; strcpy(e->hash_quality,"captured"); e->hash_reason[0]=0; return 1;
}
/* The provider state is created from WINTRUST_FILE_INFO.hFile, so this leaf
 * certificate belongs to the same opened object that produced the hash. */
static int signature_subject_and_thumbprint_from_wvt(HANDLE state, EdrProcessEvidence *e) {
  CRYPT_PROVIDER_DATA *provider;
  CRYPT_PROVIDER_SGNR *signer;
  CRYPT_PROVIDER_CERT *cert;
  DWORD cb;
  BYTE hash[64];
  static const char hex[] = "0123456789abcdef";
  if (!state || !e) return 0;
  provider = WTHelperProvDataFromStateData(state);
  signer = provider ? WTHelperGetProvSignerFromChain(provider, 0u, FALSE, 0u) : NULL;
  cert = signer ? WTHelperGetProvCertFromChain(signer, 0u) : NULL;
  if (!cert || !cert->pCert) return 0;
  if (!CertGetNameStringA(cert->pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0u, NULL,
                          e->signer, (DWORD)sizeof(e->signer)) || !e->signer[0]) {
    return 0;
  }
  cb = (DWORD)sizeof(hash);
  if (!CertGetCertificateContextProperty(cert->pCert, CERT_SHA1_HASH_PROP_ID, hash, &cb) ||
      cb == 0u || cb > 32u) {
    e->signer[0] = '\0';
    return 0;
  }
  for (DWORD i = 0u; i < cb && i * 2u + 1u < sizeof(e->thumbprint); ++i) {
    e->thumbprint[i * 2u] = hex[hash[i] >> 4];
    e->thumbprint[i * 2u + 1u] = hex[hash[i] & 15u];
  }
  return e->signer[0] && e->thumbprint[0];
}

/* Windows system binaries may be signed through a system catalog rather than
 * carrying an embedded PKCS#7 blob. Resolve that catalog from the hash of the
 * same held file object; never reopen the mutable pathname as evidence owner. */
static LONG verify_catalog_signature(const WCHAR *path, HANDLE file,
                                     EdrProcessEvidence *e) {
  HCATADMIN admin = NULL;
  HCATINFO catalog = NULL;
  BYTE hash[64];
  DWORD hash_size = (DWORD)sizeof(hash);
  WCHAR member_tag[sizeof(hash) * 2u + 1u];
  CATALOG_INFO catalog_info;
  WINTRUST_CATALOG_INFO ci;
  WINTRUST_DATA wd;
  GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
  LONG result = TRUST_E_NOSIGNATURE;
  LARGE_INTEGER zero;

  memset(&catalog_info, 0, sizeof(catalog_info));
  memset(&ci, 0, sizeof(ci));
  memset(&wd, 0, sizeof(wd));
  zero.QuadPart = 0;
  if (!path || !file || file == INVALID_HANDLE_VALUE || !e ||
      !SetFilePointerEx(file, zero, NULL, FILE_BEGIN) ||
      !CryptCATAdminAcquireContext2(&admin, NULL, L"SHA256", NULL, 0u) ||
      !CryptCATAdminCalcHashFromFileHandle2(admin, file, &hash_size, hash, 0u) ||
      hash_size == 0u || hash_size > (DWORD)sizeof(hash)) {
    goto cleanup;
  }
  static const WCHAR hex[] = L"0123456789ABCDEF";
  for (DWORD i = 0u; i < hash_size; ++i) {
    member_tag[i * 2u] = hex[hash[i] >> 4];
    member_tag[i * 2u + 1u] = hex[hash[i] & 15u];
  }
  member_tag[hash_size * 2u] = L'\0';
  catalog = CryptCATAdminEnumCatalogFromHash(admin, hash, hash_size, 0u, NULL);
  if (!catalog) goto cleanup;
  catalog_info.cbStruct = sizeof(catalog_info);
  if (!CryptCATCatalogInfoFromContext(catalog, &catalog_info, 0u)) goto cleanup;

  ci.cbStruct = sizeof(ci);
  ci.pcwszCatalogFilePath = catalog_info.wszCatalogFile;
  ci.pcwszMemberTag = member_tag;
  ci.pcwszMemberFilePath = path;
  ci.hMemberFile = file;
  ci.pbCalculatedFileHash = hash;
  ci.cbCalculatedFileHash = hash_size;
  ci.hCatAdmin = admin;
  wd.cbStruct = sizeof(wd);
  wd.dwUIChoice = WTD_UI_NONE;
  wd.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
  wd.dwUnionChoice = WTD_CHOICE_CATALOG;
  wd.pCatalog = &ci;
  wd.dwProvFlags = WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT |
                   WTD_CACHE_ONLY_URL_RETRIEVAL;
  wd.dwStateAction = WTD_STATEACTION_VERIFY;
  result = WinVerifyTrust(NULL, &action, &wd);
  if (result == ERROR_SUCCESS) {
    strcpy(e->revocation, "cache_only");
    if (signature_subject_and_thumbprint_from_wvt(wd.hWVTStateData, e)) {
      strcpy(e->signature_status, "verified");
      snprintf(e->signature_quality, sizeof(e->signature_quality), "%s",
               "verified_catalog_cache_chain");
      snprintf(e->signature_reason, sizeof(e->signature_reason), "%s",
               "verified_catalog_cache_only");
      strcpy(e->signature_source, "WinVerifyTrust_handle_catalog");
    } else {
      result = TRUST_E_SUBJECT_NOT_TRUSTED;
      strcpy(e->signature_status, "unknown");
      strcpy(e->signature_quality, "unknown");
      strcpy(e->signature_reason, "catalog_signer_info_not_found");
    }
  }
  wd.dwStateAction = WTD_STATEACTION_CLOSE;
  (void)WinVerifyTrust(NULL, &action, &wd);

cleanup:
  if (catalog) CryptCATAdminReleaseCatalogContext(admin, catalog, 0u);
  if (admin) CryptCATAdminReleaseContext(admin, 0u);
  return result;
}

static void evidence_mark_path_or_handle_changed(EdrProcessEvidence *e, const char *reason) {
  if (!e) return;
  e->sha256[0] = '\0';
  strcpy(e->hash_quality, "unknown");
  strcpy(e->hash_reason, reason);
  e->signature_status[0] = '\0';
  strcpy(e->signature_status, "unknown");
  strcpy(e->signature_quality, "unknown");
  strcpy(e->signature_reason, reason);
  strcpy(e->revocation, "unknown");
  e->signer[0] = '\0';
  e->thumbprint[0] = '\0';
}

/* WinVerifyTrust still receives a pathname in addition to hFile. Revalidate
 * the held object's lossless identity and write time both before and after
 * the call, so a pathname A->B swap cannot acquire the evidence owner. */
static void verify_signature(const char *path, HANDLE file,
                             const char *expected_identity,
                             uint64_t expected_write_time,
                             EdrProcessEvidence *e) {
  WINTRUST_FILE_INFO fi; WINTRUST_DATA wd; GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2; WCHAR wide[1024];
  LARGE_INTEGER zero;
  memset(&fi,0,sizeof(fi)); memset(&wd,0,sizeof(wd));
  if (!file || file == INVALID_HANDLE_VALUE || !e ||
      !evidence_path_and_handle_match(path, file, expected_identity, expected_write_time)) {
    evidence_mark_path_or_handle_changed(e, "file_changed_before_wvt");
    return;
  }
  if (
      MultiByteToWideChar(CP_UTF8,0,path,-1,wide,(int)(sizeof(wide)/sizeof(wide[0]))) <= 0) {
    strcpy(e->signature_reason,"path_encoding_failed");
    return;
  }
  zero.QuadPart = 0;
  if (!SetFilePointerEx(file, zero, NULL, FILE_BEGIN)) {
    strcpy(e->signature_reason, "file_rewind_failed");
    return;
  }
  fi.cbStruct=sizeof(fi); fi.pcwszFilePath=wide; fi.hFile=file;
  wd.cbStruct=sizeof(wd); wd.dwUIChoice=WTD_UI_NONE;
  wd.fdwRevocationChecks=WTD_REVOKE_WHOLECHAIN; wd.dwUnionChoice=WTD_CHOICE_FILE; wd.pFile=&fi;
  /* P0 preprocess must not inherit network latency from certificate URL
   * retrieval. Cache-only chain/revocation evaluation is deterministic and
   * its reduced freshness is reported explicitly in the evidence tuple. */
  wd.dwProvFlags=WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT |
                 WTD_CACHE_ONLY_URL_RETRIEVAL;
  wd.dwStateAction=WTD_STATEACTION_VERIFY;
#ifdef EDR_PROCESS_EVIDENCE_TESTING
  if (s_test_wvt_path_hook.synthetic_wvt_result) {
    strcpy(e->revocation, "checked");
    strcpy(e->signature_status, "verified");
    strcpy(e->signature_quality, "verified_chain");
    strcpy(e->signature_reason, "synthetic_verified");
    strcpy(e->signer, "synthetic-held-A");
    strcpy(e->thumbprint, "0123456789abcdef0123456789abcdef01234567");
  } else
#endif
  {
    LONG rc=WinVerifyTrust(NULL,&action,&wd);
    if (rc==ERROR_SUCCESS) {
      strcpy(e->revocation,"cache_only");
      if (signature_subject_and_thumbprint_from_wvt(wd.hWVTStateData,e)) {
        strcpy(e->signature_status,"verified");
        strcpy(e->signature_quality,"verified_cache_chain");
        strcpy(e->signature_reason,"verified_cache_only");
      } else {
        strcpy(e->signature_status,"unknown"); strcpy(e->signature_quality,"unknown"); strcpy(e->signature_reason,"signer_info_not_found");
      }
    }
    else if (rc == TRUST_E_NOSIGNATURE) {
      wd.dwStateAction=WTD_STATEACTION_CLOSE;
      (void)WinVerifyTrust(NULL,&action,&wd);
      memset(&wd, 0, sizeof(wd));
      rc = verify_catalog_signature(wide, file, e);
      if (rc != ERROR_SUCCESS && strcmp(e->signature_reason, "catalog_signer_info_not_found") != 0) {
        snprintf(e->signature_reason,sizeof(e->signature_reason),"winverifytrust_%08lx",(unsigned long)rc);
        strcpy(e->revocation,"cache_only_failed");
      }
    }
    else {
      snprintf(e->signature_reason,sizeof(e->signature_reason),"winverifytrust_%08lx",(unsigned long)rc);
      if (rc == CERT_E_REVOKED || rc == CRYPT_E_REVOKED) strcpy(e->revocation,"revoked");
      else strcpy(e->revocation,"cache_only_failed");
    }
    if (wd.cbStruct != 0u) {
      wd.dwStateAction=WTD_STATEACTION_CLOSE;
      (void)WinVerifyTrust(NULL,&action,&wd);
    }
  }
  if (!evidence_path_and_handle_match(path, file, expected_identity, expected_write_time)) {
    evidence_mark_path_or_handle_changed(e, "file_changed_during_wvt");
  }
}
static DWORD WINAPI worker(void *unused) {
  (void)unused;
  while (!InterlockedCompareExchange(&s_stop,0,0)) {
    EvidenceSlot job, *chosen=NULL;
    HANDLE held_file = NULL;
    uint64_t now=edr_monotonic_ns();
    int hash_attempted = 0;
    int signature_attempted = 0;
    int hash_ok = 0;
    int queue_deadline = 0;
    memset(&job, 0, sizeof(job));
    AcquireSRWLockExclusive(&s_lock);
    for (uint32_t i=0;i<EDR_EVIDENCE_SLOTS;i++) if (s_slots[i].queued) {
      chosen=&s_slots[i];
      job=*chosen;
      /* Ownership moves once, under the slot lock. The worker closes this
       * exact initial handle on every terminal path. */
      held_file=chosen->owned_file;
      job.owned_file=held_file;
      chosen->owned_file=NULL;
      chosen->queued=0;
      chosen->inflight=1;
      s_metrics.hash_admissions++;
      s_metrics.signature_admissions++;
      break;
    }
    ReleaseSRWLockExclusive(&s_lock);
    if (!chosen) { WaitForSingleObject(s_wake,50); continue; }
    InterlockedExchange64(&s_active_started_ns, (LONGLONG)now);
    evidence_clear(&job.evidence,"short_lived_or_not_ready");
    snprintf(job.evidence.file_identity, sizeof(job.evidence.file_identity), "%s",
             job.file_identity);
    job.evidence.file_write_time=job.file_write_time;
    if (now - job.queued_ns > EDR_EVIDENCE_QUEUE_MAX_NS) {
      queue_deadline = 1;
      strcpy(job.evidence.hash_reason,"worker_deadline");
      strcpy(job.evidence.signature_reason,"worker_deadline");
    }
    else {
      hash_attempted = 1;
      hash_ok = hash_file_same_handle(held_file, now, job.file_identity,
                                      job.file_write_time, &job.evidence);
      if (hash_ok) {
        signature_attempted = 1;
        verify_signature(job.path, held_file, job.file_identity, job.file_write_time,
                         &job.evidence);
        if (!evidence_handle_matches(held_file, job.file_identity, job.file_write_time)) {
          evidence_mark_path_or_handle_changed(&job.evidence,
                                               "file_changed_during_verification");
        } else if (strcmp(job.evidence.hash_quality, "captured") == 0 &&
                   strcmp(job.evidence.signature_source, "WinVerifyTrust") == 0) {
          strcpy(job.evidence.signature_source, "WinVerifyTrust_handle");
        }
      } else {
        job.evidence.sha256[0] = '\0'; strcpy(job.evidence.hash_quality, "unknown");
        strcpy(job.evidence.signature_status, "unknown");
        strcpy(job.evidence.signature_quality, "unknown");
        strcpy(job.evidence.signature_reason, "hash_identity_unavailable");
      }
    }
    if (held_file && held_file != INVALID_HANDLE_VALUE) CloseHandle(held_file);
    job.owned_file=NULL;
    AcquireSRWLockExclusive(&s_lock);
    if (hash_attempted) s_metrics.hash_attempts++;
    if (signature_attempted) s_metrics.signature_attempts++;
    if (queue_deadline) s_metrics.queue_deadlines++;
    /* A reused cache slot or PID generation is stale work; do not publish it. */
    if (chosen->inflight && chosen->generation==job.generation &&
        strcmp(chosen->path,job.path)==0 &&
        file_identity_equal(chosen->file_identity, job.file_identity) &&
        chosen->file_write_time==job.file_write_time) {
      /* Cache identity is canonical path + file identity + process generation.
       * A result whose generation/path slot was reused is never published. */
      snprintf(chosen->file_identity, sizeof(chosen->file_identity), "%s",
               job.file_identity);
      chosen->file_write_time = job.file_write_time;
      chosen->evidence=job.evidence; chosen->inflight=0; chosen->ready=1;
    } else {
      if (chosen->inflight) chosen->inflight=0;
      s_metrics.stale_rejected++;
    }
    s_metrics.worker_stalled = 0u;
    ReleaseSRWLockExclusive(&s_lock);
    InterlockedExchange64(&s_active_started_ns, 0);
  }
  return 0;
}
int edr_process_evidence_worker_start(void) {
  if (s_thread) return 1;
  if (InterlockedCompareExchange(&s_terminal_unhealthy, 0, 0)) return 0;
  memset(s_slots, 0, sizeof(s_slots));
  memset(&s_metrics, 0, sizeof(s_metrics));
  InterlockedExchange64(&s_active_started_ns, 0);
  s_stop = 0;
  s_wake = CreateEventW(NULL, FALSE, FALSE, NULL);
  if (!s_wake) return 0;
  s_thread = CreateThread(NULL, 0, worker, NULL, 0, NULL);
  if (!s_thread) { CloseHandle(s_wake); s_wake = NULL; return 0; }
  return 1;
}
void edr_process_evidence_worker_stop(void) {
  DWORD waited;
  if (!s_thread) return;
  InterlockedExchange(&s_stop,1);
  if (s_wake) SetEvent(s_wake);
  waited = WaitForSingleObject(s_thread, 60000);
  if (waited != WAIT_OBJECT_0) {
    /* Do not close either handle or clear globals: the thread can still use
     * both while WinVerifyTrust is blocked.  This process is terminally
     * unhealthy and intentionally cannot restart the worker. */
    AcquireSRWLockExclusive(&s_lock);
    /* The active worker owns only its detached in-flight handle. It will not
     * pick another queued slot after s_stop, so close each still-queued owner
     * here rather than leaking handles during a terminal WVT stall. */
    for (uint32_t i = 0u; i < EDR_EVIDENCE_SLOTS; ++i) {
      if (s_slots[i].queued) {
        evidence_slot_close_owned_handle(&s_slots[i]);
        s_slots[i].queued = 0u;
      }
    }
    s_metrics.shutdown_timeouts++;
    s_metrics.terminal_unhealthy = 1u;
    ReleaseSRWLockExclusive(&s_lock);
    InterlockedExchange(&s_terminal_unhealthy, 1);
    return;
  }
  AcquireSRWLockExclusive(&s_lock);
  for (uint32_t i = 0u; i < EDR_EVIDENCE_SLOTS; ++i) {
    evidence_slot_reset(&s_slots[i]);
  }
  ReleaseSRWLockExclusive(&s_lock);
  CloseHandle(s_thread);
  if (s_wake) CloseHandle(s_wake);
  s_thread=NULL;
  s_wake=NULL;
}
/* Caller holds s_lock. The first successful capture owns this generation's
 * pathname snapshot; a later request is a retrieval, not a new observation
 * of whatever now happens to occupy that path. It is never image authority. */
static int evidence_find_snapshot_locked(const char *path, uint64_t generation,
                                          uint64_t now, EdrProcessEvidence *out,
                                          int *ready) {
  for (uint32_t i = 0u; i < EDR_EVIDENCE_SLOTS; ++i) {
    EvidenceSlot *slot = &s_slots[i];
    if (slot->generation != generation || strcmp(slot->path, path) != 0) continue;
    if (slot->ready) {
      *out = slot->evidence;
      slot->last_used_ns = now;
      s_metrics.ready_hits++;
      *ready = 1;
      return 1;
    }
    if (slot->queued || slot->inflight) {
      snprintf(out->file_identity, sizeof(out->file_identity), "%s", slot->file_identity);
      out->file_write_time = slot->file_write_time;
      strcpy(out->hash_reason, "identity_revalidation_pending");
      strcpy(out->signature_reason, "identity_revalidation_pending");
      s_metrics.pending_reuse++;
      *ready = 0;
      return 1;
    }
  }
  return 0;
}

int edr_process_evidence_request(const char *path,uint64_t generation,uint64_t now,EdrProcessEvidence *out) {
  EdrProcessEvidence current;
  void *opened_file = NULL;
  EvidenceSlot *slot = NULL;
  int ready = 0;
  if (!out) return 0;
  evidence_clear(out, "not_requested");
  if (!path || !path[0] || !generation) { strcpy(out->hash_reason,"missing_identity"); strcpy(out->signature_reason,"missing_identity"); return 0; }
  if (strlen(path) >= sizeof(s_slots[0].path)) {
    evidence_clear(out, "path_capacity");
    return 0;
  }
  if (InterlockedCompareExchange(&s_terminal_unhealthy, 0, 0)) {
    strcpy(out->hash_reason, "worker_terminal_unhealthy");
    strcpy(out->signature_reason, "worker_terminal_unhealthy");
    return 0;
  }
  if (evidence_worker_stalled(now)) {
    evidence_mark_stalled();
    strcpy(out->hash_reason, "evidence_worker_stalled");
    strcpy(out->signature_reason, "evidence_worker_stalled");
    return 0;
  }
  AcquireSRWLockExclusive(&s_lock);
  s_metrics.requests_total++;
  if (evidence_find_snapshot_locked(path, generation, now, out, &ready)) {
    ReleaseSRWLockExclusive(&s_lock);
    return ready;
  }
  s_metrics.misses++;
  ReleaseSRWLockExclusive(&s_lock);
  memset(&current, 0, sizeof(current));
  if (!edr_windows_file_identity_open_readonly_diagnostic(
          path, &opened_file, current.file_identity,
          sizeof(current.file_identity), &current.file_write_time,
          out->hash_reason, sizeof(out->hash_reason))) {
    if (!out->hash_reason[0]) {
      strcpy(out->hash_reason, "file_identity_unavailable");
    }
    snprintf(out->signature_reason, sizeof(out->signature_reason), "%s",
             out->hash_reason);
    return 0;
  }
  /* Return the snapshot identity before hashing, but never use it to bind an
   * enforcement target: the process's image section has not been captured. */
  snprintf(out->file_identity, sizeof(out->file_identity), "%s", current.file_identity);
  out->file_write_time = current.file_write_time;
  AcquireSRWLockExclusive(&s_lock);
  /* Another producer may have captured the generation while the handle was
   * opened outside the lock. It remains the owner; close this losing handle. */
  if (evidence_find_snapshot_locked(path, generation, now, out, &ready)) {
    ReleaseSRWLockExclusive(&s_lock);
    CloseHandle((HANDLE)opened_file);
    return ready;
  }
  for (uint32_t i=0;i<EDR_EVIDENCE_SLOTS;i++) if (!s_slots[i].queued && !s_slots[i].inflight && !s_slots[i].ready) { slot=&s_slots[i]; break; }
  if (!slot) {
    for (uint32_t i=0;i<EDR_EVIDENCE_SLOTS;i++) {
      if (s_slots[i].ready && now >= s_slots[i].queued_ns &&
          now - s_slots[i].queued_ns >= EDR_EVIDENCE_RETAIN_NS &&
          (!slot || s_slots[i].last_used_ns < slot->last_used_ns)) slot=&s_slots[i];
    }
    if (slot) s_metrics.cache_evictions++;
  }
  if (!slot) {
    s_metrics.backpressure++;
    strcpy(out->hash_reason,"evidence_backpressure");
    strcpy(out->signature_reason,"evidence_backpressure");
    ReleaseSRWLockExclusive(&s_lock);
    CloseHandle((HANDLE)opened_file);
    return 0;
  }
  evidence_slot_reset(slot);
  snprintf(slot->path,sizeof(slot->path),"%s",path);
  slot->generation=generation;
  snprintf(slot->file_identity, sizeof(slot->file_identity), "%s", current.file_identity);
  slot->file_write_time=current.file_write_time;
  slot->owned_file=(HANDLE)opened_file;
  opened_file=NULL;
  slot->queued_ns=now;
  slot->last_used_ns=now;
  slot->queued=1;
  s_metrics.queued++;
  strcpy(out->hash_reason,"queued");
  strcpy(out->signature_reason,"queued");
  ReleaseSRWLockExclusive(&s_lock);
  SetEvent(s_wake);
  return 0;
}

static int evidence_lookup_ready(const char *path, uint64_t generation, uint64_t now,
                                 EdrProcessEvidence *out) {
  if (!path || !path[0] || !generation || !out) return 0;
  /* The result was captured and revalidated through the worker-owned handle.
   * Do not reopen the pathname here: a short-lived process may already have
   * deleted it, and a replacement pathname is not the owner of this
   * process-generation snapshot. */
  AcquireSRWLockExclusive(&s_lock);
  for (uint32_t i = 0u; i < EDR_EVIDENCE_SLOTS; ++i) {
    EvidenceSlot *slot = &s_slots[i];
    if (slot->generation != generation || strcmp(slot->path, path) != 0) continue;
    if (slot->ready) {
      *out = slot->evidence;
      slot->last_used_ns = now;
      s_metrics.ready_hits++;
      ReleaseSRWLockExclusive(&s_lock);
      return 1;
    }
    break;
  }
  ReleaseSRWLockExclusive(&s_lock);
  return 0;
}

int edr_process_evidence_poll(const char *path, uint64_t generation, uint64_t now,
                              EdrProcessEvidence *out) {
  if (!out) return -1;
  evidence_clear(out, "queued");
  if (!path || !path[0] || !generation) {
    strcpy(out->hash_reason, "missing_identity");
    strcpy(out->signature_reason, "missing_identity");
    return -1;
  }
  if (InterlockedCompareExchange(&s_terminal_unhealthy, 0, 0)) {
    strcpy(out->hash_reason, "worker_terminal_unhealthy");
    strcpy(out->signature_reason, "worker_terminal_unhealthy");
    return -1;
  }
  if (evidence_worker_stalled(now)) {
    evidence_mark_stalled();
    strcpy(out->hash_reason, "evidence_worker_stalled");
    strcpy(out->signature_reason, "evidence_worker_stalled");
    return -1;
  }
  return evidence_lookup_ready(path, generation, now, out);
}

void edr_process_evidence_note_wait_timeout(void) {
  AcquireSRWLockExclusive(&s_lock);
  s_metrics.wait_timeouts++;
  ReleaseSRWLockExclusive(&s_lock);
}

int edr_process_evidence_wait(const char *path, uint64_t generation, uint64_t now,
                              uint64_t max_wait_ns, EdrProcessEvidence *out) {
  uint64_t deadline;
  if (!out) return 0;
  evidence_clear(out, "not_requested");
  if (!path || !path[0] || !generation || !max_wait_ns) {
    strcpy(out->hash_reason, "missing_identity");
    strcpy(out->signature_reason, "missing_identity");
    return 0;
  }
  if (InterlockedCompareExchange(&s_terminal_unhealthy, 0, 0)) {
    strcpy(out->hash_reason, "worker_terminal_unhealthy");
    strcpy(out->signature_reason, "worker_terminal_unhealthy");
    return 0;
  }
  if (evidence_worker_stalled(now)) {
    evidence_mark_stalled();
    strcpy(out->hash_reason, "evidence_worker_stalled");
    strcpy(out->signature_reason, "evidence_worker_stalled");
    return 0;
  }
  deadline = now + max_wait_ns;
  for (;;) {
    uint64_t current = edr_monotonic_ns();
    if (evidence_worker_stalled(current)) {
      evidence_mark_stalled();
      strcpy(out->hash_reason, "evidence_worker_stalled");
      strcpy(out->signature_reason, "evidence_worker_stalled");
      return 0;
    }
    if (evidence_lookup_ready(path, generation, current, out)) return 1;
    if (current >= deadline) {
      edr_process_evidence_note_wait_timeout();
      strcpy(out->hash_reason, "evidence_wait_timeout");
      strcpy(out->signature_reason, "evidence_wait_timeout");
      return 0;
    }
    {
      uint64_t remaining_ns = deadline - current;
      DWORD wait_ms = (DWORD)((remaining_ns + 999999ULL) / 1000000ULL);
      if (wait_ms > 5u) wait_ms = 5u;
      /* s_wake is an auto-reset work-queue event with exactly one consumer:
       * the evidence worker. A request waiter must not steal that signal and
       * delay the very work it is waiting for. Bounded polling is independent
       * of queue wake ownership and still observes ready results promptly. */
      Sleep(wait_ms);
    }
  }
}

void edr_process_evidence_worker_get_metrics(EdrProcessEvidenceMetrics *out) {
  if (!out) return;
  AcquireSRWLockShared(&s_lock);
  *out=s_metrics; out->capacity=EDR_EVIDENCE_SLOTS;
  for (uint32_t i=0;i<EDR_EVIDENCE_SLOTS;i++) {
    if (s_slots[i].queued || s_slots[i].inflight || s_slots[i].ready) out->slots_used++;
  }
  ReleaseSRWLockShared(&s_lock);
}
#else
int edr_process_evidence_worker_start(void) { return 1; }
void edr_process_evidence_worker_stop(void) {}
int edr_process_evidence_request(const char *path,uint64_t generation,uint64_t now,EdrProcessEvidence *out) { (void)path;(void)generation;(void)now; if (out) { memset(out,0,sizeof(*out)); strcpy(out->hash_quality,"unknown"); strcpy(out->hash_reason,"windows_only"); strcpy(out->signature_status,"unknown"); strcpy(out->signature_source,"windows_only"); strcpy(out->signature_quality,"unknown"); strcpy(out->signature_reason,"windows_only"); strcpy(out->revocation,"unknown"); } return 0; }
int edr_process_evidence_wait(const char *path,uint64_t generation,uint64_t now,uint64_t max_wait_ns,EdrProcessEvidence *out) { (void)path;(void)generation;(void)now;(void)max_wait_ns; if (out) { memset(out,0,sizeof(*out)); strcpy(out->hash_quality,"unknown"); strcpy(out->hash_reason,"windows_only"); strcpy(out->signature_status,"unknown"); strcpy(out->signature_source,"windows_only"); strcpy(out->signature_quality,"unknown"); strcpy(out->signature_reason,"windows_only"); strcpy(out->revocation,"unknown"); } return 0; }
int edr_process_evidence_poll(const char *path,uint64_t generation,uint64_t now,EdrProcessEvidence *out) {
  (void)edr_process_evidence_wait(path,generation,now,0u,out);
  return -1;
}
void edr_process_evidence_note_wait_timeout(void) {}
void edr_process_evidence_worker_get_metrics(EdrProcessEvidenceMetrics *out) { if (out) memset(out, 0, sizeof(*out)); }
#endif
