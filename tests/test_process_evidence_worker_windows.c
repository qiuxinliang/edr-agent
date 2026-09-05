#include "edr/process_evidence_worker.h"
#include "edr/time_util.h"
#include "edr/windows_file_identity.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

static void write_fixture(const char *path, const char *body) {
  HANDLE file;
  DWORD written = 0u;
  file = CreateFileA(path, GENERIC_WRITE, 0u, NULL, CREATE_ALWAYS,
                     FILE_ATTRIBUTE_NORMAL, NULL);
  assert(file != INVALID_HANDLE_VALUE);
  assert(WriteFile(file, body, (DWORD)strlen(body), &written, NULL));
  assert(written == (DWORD)strlen(body));
  assert(CloseHandle(file));
}

static void make_fixture_paths(char a_path[MAX_PATH], char b_path[MAX_PATH]) {
  char temp[MAX_PATH];
  assert(GetTempPathA((DWORD)sizeof(temp), temp) > 0u);
  assert(GetTempFileNameA(temp, "eda", 0u, a_path) != 0u);
  assert(GetTempFileNameA(temp, "edb", 0u, b_path) != 0u);
  write_fixture(a_path, "A-content");
  write_fixture(b_path, "B-content");
}

static void assert_no_b_evidence(const EdrProcessEvidence *e,
                                 const char *a_identity, const char *b_identity) {
  assert(e != NULL);
  assert(strcmp(e->file_identity, a_identity) == 0);
  assert(strcmp(e->file_identity, b_identity) != 0);
  assert(e->sha256[0] == '\0');
  assert(strcmp(e->hash_quality, "unknown") == 0);
  assert(strcmp(e->signature_status, "unknown") == 0);
  assert(e->signer[0] == '\0');
  assert(e->thumbprint[0] == '\0');
}

static void test_held_owner_denies_modify_restore_and_swap(void) {
  char a_path[MAX_PATH], b_path[MAX_PATH];
  char a_identity[EDR_WINDOWS_FILE_IDENTITY_V1_CAP];
  uint64_t a_write_time = 0u;
  void *owner = NULL;
  HANDLE writer;
  make_fixture_paths(a_path, b_path);
  assert(edr_windows_file_identity_open_readonly(a_path, &owner, a_identity,
                                                 sizeof(a_identity), &a_write_time));
  /* An in-place writer cannot even obtain FILE_WRITE_ATTRIBUTES, so it cannot
   * modify A and restore its FILETIME while the evidence owner is held. */
  writer = CreateFileA(a_path, GENERIC_WRITE | FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ,
                       NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  assert(writer == INVALID_HANDLE_VALUE);
  /* Replacing A with B (and therefore a B->A rollback later) requires delete
   * sharing, which the single evidence owner deliberately never grants. */
  assert(!MoveFileExA(b_path, a_path, MOVEFILE_REPLACE_EXISTING));
  assert(edr_windows_file_identity_snapshot_matches(a_identity, a_write_time,
                                                     a_identity, a_write_time));
  assert(CloseHandle((HANDLE)owner));
  (void)DeleteFileA(a_path);
  (void)DeleteFileA(b_path);
}

static void test_injected_wvt_path_swaps_never_publish_b(void) {
  char a_path[MAX_PATH], b_path[MAX_PATH];
  char a_identity[EDR_WINDOWS_FILE_IDENTITY_V1_CAP];
  char b_identity[EDR_WINDOWS_FILE_IDENTITY_V1_CAP];
  uint64_t a_write_time = 0u, b_write_time = 0u;
  EdrProcessEvidence request, result;
  uint64_t now;

  make_fixture_paths(a_path, b_path);
  assert(edr_windows_file_identity_from_path(a_path, a_identity, sizeof(a_identity),
                                              &a_write_time));
  assert(edr_windows_file_identity_from_path(b_path, b_identity, sizeof(b_identity),
                                              &b_write_time));
  assert(strcmp(a_identity, b_identity) != 0);
  assert(edr_process_evidence_worker_start());

  /* A captured then path B before WVT: the pre-WVT revalidation rejects it. */
  edr_process_evidence_test_set_wvt_path_sequence(b_identity, b_write_time,
                                                   b_identity, b_write_time);
  edr_process_evidence_test_set_synthetic_wvt_result(1);
  memset(&request, 0, sizeof(request));
  now = edr_monotonic_ns();
  assert(edr_process_evidence_request(a_path, 1001u, now, &request) == 0);
  memset(&result, 0, sizeof(result));
  assert(edr_process_evidence_wait(a_path, 1001u, edr_monotonic_ns(),
                                   1000ULL * 1000000ULL, &result));
  assert_no_b_evidence(&result, a_identity, b_identity);
  assert(strcmp(result.signature_reason, "file_changed_before_wvt") == 0);

  /* The path can also change after the API has read it. The synthetic WVT
   * result proves that post-WVT validation clears A's hash/signature instead
   * of publishing a B-associated evidence tuple. */
  edr_process_evidence_test_set_wvt_path_sequence(a_identity, a_write_time,
                                                   b_identity, b_write_time);
  edr_process_evidence_test_set_synthetic_wvt_result(1);
  memset(&request, 0, sizeof(request));
  assert(edr_process_evidence_request(a_path, 1002u, edr_monotonic_ns(), &request) == 0);
  memset(&result, 0, sizeof(result));
  assert(edr_process_evidence_wait(a_path, 1002u, edr_monotonic_ns(),
                                   1000ULL * 1000000ULL, &result));
  assert_no_b_evidence(&result, a_identity, b_identity);
  assert(strcmp(result.signature_reason, "file_changed_during_wvt") == 0);

  /* B -> A before WVT is still a failed A snapshot.  Seeing A again does not
   * retroactively make the intervening pathname B authoritative. */
  edr_process_evidence_test_set_wvt_path_sequence(b_identity, b_write_time,
                                                   a_identity, a_write_time);
  edr_process_evidence_test_set_synthetic_wvt_result(1);
  memset(&request, 0, sizeof(request));
  assert(edr_process_evidence_request(a_path, 1003u, edr_monotonic_ns(), &request) == 0);
  memset(&result, 0, sizeof(result));
  assert(edr_process_evidence_wait(a_path, 1003u, edr_monotonic_ns(),
                                   1000ULL * 1000000ULL, &result));
  assert_no_b_evidence(&result, a_identity, b_identity);
  assert(strcmp(result.signature_reason, "file_changed_before_wvt") == 0);

  edr_process_evidence_worker_stop();
  (void)DeleteFileA(a_path);
  (void)DeleteFileA(b_path);
}

static void test_missing_identity_stays_unavailable(void) {
  EdrProcessEvidence evidence;
  memset(&evidence, 0, sizeof(evidence));
  assert(edr_process_evidence_request("Z:\\edr-never-exists\\missing.exe", 9u,
                                      edr_monotonic_ns(), &evidence) == 0);
  assert(evidence.file_identity[0] == '\0');
  assert(strcmp(evidence.hash_quality, "unknown") == 0);
  assert(strcmp(evidence.signature_quality, "unknown") == 0);
  assert(strcmp(evidence.hash_reason, "file_identity_unavailable") == 0);
  assert(strcmp(evidence.signature_reason, "file_identity_unavailable") == 0);
}

static void test_ready_snapshot_survives_short_lived_path_cleanup(void) {
  char a_path[MAX_PATH], b_path[MAX_PATH];
  EdrProcessEvidence request, first, cached;
  make_fixture_paths(a_path, b_path);
  assert(edr_process_evidence_worker_start());
  edr_process_evidence_test_set_wvt_path_sequence(NULL, 0u, NULL, 0u);
  edr_process_evidence_test_set_synthetic_wvt_result(1);
  memset(&request, 0, sizeof(request));
  assert(edr_process_evidence_request(a_path, 2001u, edr_monotonic_ns(), &request) == 0);
  memset(&first, 0, sizeof(first));
  assert(edr_process_evidence_wait(a_path, 2001u, edr_monotonic_ns(),
                                   1000ULL * 1000000ULL, &first));
  assert(first.sha256[0] != '\0');
  assert(DeleteFileA(a_path));
  memset(&cached, 0, sizeof(cached));
  assert(edr_process_evidence_wait(a_path, 2001u, edr_monotonic_ns(),
                                   50ULL * 1000000ULL, &cached));
  assert(strcmp(cached.file_identity, first.file_identity) == 0);
  assert(strcmp(cached.sha256, first.sha256) == 0);
  /* The real preprocess path calls request again after the 4688 deadline,
   * not wait directly. That second request must not reopen the deleted path. */
  assert(edr_process_evidence_request(a_path, 2001u, edr_monotonic_ns(), &cached));
  assert(strcmp(cached.file_identity, first.file_identity) == 0);
  assert(strcmp(cached.sha256, first.sha256) == 0);
  /* A replacement B is not the owner of generation A's historical snapshot.
   * Only a new generation may capture B. Neither snapshot is image authority. */
  assert(MoveFileExA(b_path, a_path, 0u));
  assert(edr_process_evidence_request(a_path, 2001u, edr_monotonic_ns(), &cached));
  assert(strcmp(cached.file_identity, first.file_identity) == 0);
  assert(strcmp(cached.sha256, first.sha256) == 0);
  assert(!edr_process_evidence_request(a_path, 2002u, edr_monotonic_ns(), &request));
  assert(edr_process_evidence_wait(a_path, 2002u, edr_monotonic_ns(),
                                   1000ULL * 1000000ULL, &cached));
  assert(strcmp(cached.file_identity, first.file_identity) != 0);
  assert(strcmp(cached.sha256, first.sha256) != 0);
  edr_process_evidence_worker_stop();
  assert(DeleteFileA(a_path));
  (void)DeleteFileA(b_path);
}

static void test_snapshot_burst_retention_is_bounded(void) {
  char a_path[MAX_PATH], b_path[MAX_PATH];
  EdrProcessEvidence request, result;
  EdrProcessEvidenceMetrics metrics;
  uint64_t started = edr_monotonic_ns();
  make_fixture_paths(a_path, b_path);
  assert(edr_process_evidence_worker_start());
  edr_process_evidence_test_set_wvt_path_sequence(NULL, 0u, NULL, 0u);
  edr_process_evidence_test_set_synthetic_wvt_result(1);
  for (uint64_t i = 1u; i <= 32u; ++i) {
    assert(!edr_process_evidence_request(a_path, 3000u+i, started, &request));
    assert(edr_process_evidence_wait(a_path, 3000u+i, edr_monotonic_ns(),
                                     1000ULL * 1000000ULL, &result));
    assert(result.sha256[0]);
  }
  assert(!edr_process_evidence_request(a_path, 4000u, started, &request));
  assert(strcmp(request.hash_reason, "evidence_backpressure") == 0);
  assert(edr_process_evidence_request(a_path, 3001u, started, &result));
  edr_process_evidence_worker_get_metrics(&metrics);
  assert(metrics.capacity == 32u && metrics.slots_used == 32u);
  assert(metrics.cache_evictions == 0u && metrics.backpressure == 1u);
  Sleep(5100u);
  assert(!edr_process_evidence_request(a_path, 4000u, edr_monotonic_ns(), &request));
  assert(strcmp(request.hash_reason, "queued") == 0);
  assert(edr_process_evidence_wait(a_path, 4000u, edr_monotonic_ns(),
                                   1000ULL * 1000000ULL, &result));
  edr_process_evidence_worker_get_metrics(&metrics);
  assert(metrics.cache_evictions == 1u && metrics.slots_used == 32u);
  edr_process_evidence_worker_stop();
  assert(DeleteFileA(a_path));
  assert(DeleteFileA(b_path));
}

static void test_share_and_reparse_denial_stay_not_evaluable(void) {
  char a_path[MAX_PATH], b_path[MAX_PATH];
  void *owner = NULL;
  char identity[EDR_WINDOWS_FILE_IDENTITY_V1_CAP];
  uint64_t write_time = 0u;
  HANDLE writer;
  EdrProcessEvidence evidence;
  make_fixture_paths(a_path, b_path);
  assert(edr_windows_file_identity_open_readonly(a_path, &owner, identity,
                                                 sizeof(identity), &write_time));
  /* No write share means neither a byte update nor a FILETIME restore can
   * begin while A's single evidence owner is live. */
  writer = CreateFileA(a_path, GENERIC_WRITE | FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ,
                       NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  assert(writer == INVALID_HANDLE_VALUE);
  assert(CloseHandle((HANDLE)owner));

  /* The test seam takes the same no-identity branch as a real reparse point;
   * it avoids symlink privilege assumptions in native CI. */
  edr_windows_file_identity_test_force_reparse_denied(1);
  memset(&evidence, 0, sizeof(evidence));
  assert(edr_process_evidence_request(a_path, 1004u, edr_monotonic_ns(), &evidence) == 0);
  assert(evidence.file_identity[0] == '\0');
  assert(strcmp(evidence.hash_quality, "unknown") == 0);
  assert(strcmp(evidence.signature_quality, "unknown") == 0);
  assert(strcmp(evidence.hash_reason, "file_identity_unavailable") == 0);
  assert(strcmp(evidence.signature_reason, "file_identity_unavailable") == 0);
  edr_windows_file_identity_test_force_reparse_denied(0);
  (void)DeleteFileA(a_path);
  (void)DeleteFileA(b_path);
}

static void test_real_windows_snapshot_then_delete(void) {
  char a_path[MAX_PATH], b_path[MAX_PATH], system_dir[MAX_PATH], source[MAX_PATH];
  EdrProcessEvidence request, first, retained;
  make_fixture_paths(a_path, b_path);
  assert(GetSystemDirectoryA(system_dir, (UINT)sizeof(system_dir)) > 0u);
  assert(snprintf(source, sizeof(source), "%s\\WindowsPowerShell\\v1.0\\powershell.exe",
                   system_dir) < (int)sizeof(source));
  /* Only read/copy a genuine system binary. Never execute the copy. */
  assert(CopyFileA(source, a_path, FALSE));
  assert(edr_process_evidence_worker_start());
  edr_process_evidence_test_set_wvt_path_sequence(NULL, 0u, NULL, 0u);
  edr_process_evidence_test_set_synthetic_wvt_result(0);
  assert(!edr_process_evidence_request(a_path, 5001u, edr_monotonic_ns(), &request));
  assert(edr_process_evidence_wait(a_path, 5001u, edr_monotonic_ns(),
                                   5000ULL * 1000000ULL, &first));
  assert(strlen(first.sha256) == 64u);
  assert(strcmp(first.hash_quality, "captured") == 0);
  assert(strcmp(first.signature_status, "verified") == 0);
  assert(first.signer[0] && first.thumbprint[0]);
  assert(strcmp(first.revocation, "cache_only") == 0);
  assert(strcmp(first.signature_source, "WinVerifyTrust_handle") == 0 ||
         strcmp(first.signature_source, "WinVerifyTrust_handle_catalog") == 0);
  if (strcmp(first.signature_source, "WinVerifyTrust_handle_catalog") == 0) {
    assert(strcmp(first.signature_quality, "verified_catalog_cache_chain") == 0);
    assert(strcmp(first.signature_reason, "verified_catalog_cache_only") == 0);
  } else {
    assert(strcmp(first.signature_quality, "verified_cache_chain") == 0);
    assert(strcmp(first.signature_reason, "verified_cache_only") == 0);
  }
  assert(DeleteFileA(a_path));
  assert(edr_process_evidence_request(a_path, 5001u, edr_monotonic_ns(), &retained));
  assert(memcmp(&first, &retained, sizeof(first)) == 0);
  printf("real Windows snapshot retained: sha256=%s signature=%s reason=%s\n",
         retained.sha256, retained.signature_status, retained.signature_reason);
  edr_process_evidence_worker_stop();
  assert(DeleteFileA(b_path));
}

int main(void) {
  test_held_owner_denies_modify_restore_and_swap();
  test_injected_wvt_path_swaps_never_publish_b();
  test_ready_snapshot_survives_short_lived_path_cleanup();
  test_snapshot_burst_retention_is_bounded();
  test_missing_identity_stays_unavailable();
  test_share_and_reparse_denial_stay_not_evaluable();
  test_real_windows_snapshot_then_delete();
  puts("process evidence worker Windows TOCTOU contract: ok");
  return 0;
}
#else
int main(void) {
  return 0;
}
#endif
