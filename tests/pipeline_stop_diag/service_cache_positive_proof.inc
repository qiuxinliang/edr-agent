
/* Unshipped diagnostic only; one call from the still-registered P0 worker's
 * normal exit tail. The real status getter takes its ordinary cache lock and
 * performs inventory reads. Counters are process-local completed commits,
 * not an independent reopen/crash-durability assertion. Never emit path text. */
#ifdef _WIN32
void service_diag_emit_cache_positive_proof(void) {
  const int saved_errno = errno;
  const DWORD saved_error = GetLastError();
  const DWORD process_id = GetCurrentProcessId();
  const DWORD thread_id = GetCurrentThreadId();
  EdrEvidenceCacheStatus proof_status;
  size_t path_length = 0u;
  char path_sha256[65] = {0};
  unsigned path_hash_valid = 0u;
  memset(&proof_status, 0, sizeof(proof_status));
  edr_local_evidence_cache_get_status(&proof_status);
  while (path_length < sizeof(proof_status.path) && proof_status.path[path_length])
    ++path_length;
  if (path_length > 0u && path_length < sizeof(proof_status.path) &&
      edr_sha256_hex((const uint8_t *)proof_status.path, path_length, path_sha256) == 0)
    path_hash_valid = 1u;
  fprintf(stderr,
      "[preprocess] worker cache proof {\"schema\":\"edr.test.service-cache-positive-proof.v1\","
      "\"version\":1,\"pid\":%lu,\"tid\":%lu,\"status_getter_calls\":1,"
      "\"db_open\":%d,\"storage_format\":%u,\"path_hash_valid\":%u,"
      "\"cache_path_sha256\":\"%s\",\"context_facts_written\":%llu,"
      "\"context_refs_written\":%llu,\"candidate_records_written\":%llu,"
      "\"retention_clock_valid\":%u,"
      "\"pipeline_source_sha256\":\"@PIPELINE_SOURCE_SHA256@\","
      "\"cache_source_sha256\":\"@CACHE_SOURCE_SHA256@\"}\n",
      (unsigned long)process_id, (unsigned long)thread_id,
      proof_status.db_open, proof_status.storage_format, path_hash_valid, path_sha256,
      (unsigned long long)proof_status.context_facts_written,
      (unsigned long long)proof_status.context_refs_written,
      (unsigned long long)proof_status.records_written,
      proof_status.retention_clock_valid);
  fflush(stderr);
  SetLastError(saved_error); errno = saved_errno;
}
#endif
