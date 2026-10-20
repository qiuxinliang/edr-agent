/* Test-only parent. Same suspended/Job/typed-exit pattern as
 * tests/test_agent_update_contract.c::run_public_invocation.
 * Include before the sole diagnostic main; only --worker16 enters the worker.
 * Sampled fixture/log limits are guards, not atomic disk or memory quotas. */
#ifdef _WIN32
#include <wchar.h>
#define DIAG_FILE_CAP (UINT64_C(256) * 1024u * 1024u)
#define DIAG_LOG_CAP (UINT64_C(1024) * 1024u)
static uint64_t diag_prior_fixture_bytes, diag_prior_log_bytes;

static int diag_tree_bytes(const wchar_t *path, unsigned depth,
                           uint64_t *bytes, unsigned *entries) {
  wchar_t pattern[4096], child[4096];
  WIN32_FIND_DATAW data;
  if (depth > 4u || wcslen(path) + 3u >= 4096u) return 0;
  swprintf(pattern, 4096u, L"%ls\\*", path);
  HANDLE found = FindFirstFileW(pattern, &data);
  if (found == INVALID_HANDLE_VALUE) return 0;
  int ok = 1;
  for (;;) {
    if (wcscmp(data.cFileName, L".") && wcscmp(data.cFileName, L"..")) {
      if (++*entries > 128u || (data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) ||
          wcslen(path) + wcslen(data.cFileName) + 2u >= 4096u) { ok = 0; break; }
      swprintf(child, 4096u, L"%ls\\%ls", path, data.cFileName);
      if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
        if (!diag_tree_bytes(child, depth + 1u, bytes, entries)) { ok = 0; break; }
      } else {
        uint64_t size = ((uint64_t)data.nFileSizeHigh << 32) | data.nFileSizeLow;
        if (size > DIAG_FILE_CAP || *bytes > DIAG_FILE_CAP - size) { ok = 0; break; }
        *bytes += size;
      }
    }
    if (!FindNextFileW(found, &data)) {
      if (GetLastError() != ERROR_NO_MORE_FILES) ok = 0;
      break;
    }
  }
  if (!FindClose(found)) ok = 0;
  return ok;
}

static int diag_env_compare(const void *left, const void *right) {
  return _wcsicmp(*(const wchar_t * const *)left, *(const wchar_t * const *)right);
}

static wchar_t *diag_clean_environment(const wchar_t *work) {
  wchar_t *original = GetEnvironmentStringsW();
  if (!original) return NULL;
  /* Do not import runtime EDR overrides or a foreign temp directory. The
   * worker's canonical rule path comes from its configured source contract. */
  wchar_t *clean = (wchar_t *)calloc(65536u, sizeof(wchar_t));
  size_t used = 0u;
  if (!clean) { FreeEnvironmentStringsW(original); return NULL; }
  for (const wchar_t *p = original; *p; p += wcslen(p) + 1u) {
    size_t length = wcslen(p) + 1u;
    if (!_wcsnicmp(p, L"EDR_", 4u) || !_wcsnicmp(p, L"TEMP=", 5u) ||
        !_wcsnicmp(p, L"TMP=", 4u)) continue;
    if (used + length + 2u >= 65536u) goto fail;
    memcpy(clean + used, p, length * sizeof(wchar_t)); used += length;
  }
  if (!FreeEnvironmentStringsW(original)) { original = NULL; goto fail; }
  original = NULL;
  for (unsigned i = 0; i < 2u; ++i) {
    const wchar_t *key = i ? L"TMP=" : L"TEMP=";
    size_t length = wcslen(key) + wcslen(work) + 1u;
    if (used + length + 1u >= 65536u) goto fail;
    wcscpy(clean + used, key); wcscat(clean + used, work); used += length;
  }
  clean[used] = L'\0';
  /* Custom CreateProcess environment blocks are sorted case-insensitively. */
  wchar_t **rows = (wchar_t **)calloc(32768u, sizeof(wchar_t *));
  wchar_t *sorted = (wchar_t *)calloc(65536u, sizeof(wchar_t));
  if (!rows || !sorted) { free(rows); free(sorted); goto fail; }
  size_t count = 0u, offset = 0u;
  for (wchar_t *p = clean; *p; p += wcslen(p) + 1u) {
    if (count == 32768u) { free(rows); free(sorted); goto fail; }
    rows[count++] = p;
  }
  qsort(rows, count, sizeof(*rows), diag_env_compare);
  for (size_t i = 0; i < count; ++i) {
    size_t length = wcslen(rows[i]) + 1u;
    memcpy(sorted + offset, rows[i], length * sizeof(wchar_t)); offset += length;
  }
  free(rows); free(clean); return sorted;
fail:
  if (original) FreeEnvironmentStringsW(original);
  free(clean); return NULL;
}

static int diag_windows_supervise_case(const char *profile, ULONGLONG started) {
  const wchar_t *wide_profile = !strcmp(profile, "ready") ? L"ready" : L"missing";
  const ULONGLONG work_until = started + 85000u, final_until = started + 90000u;
  HANDLE job = NULL, output = INVALID_HANDLE_VALUE, error = INVALID_HANDLE_VALUE;
  HANDLE input = INVALID_HANDLE_VALUE;
  PROCESS_INFORMATION pi; memset(&pi, 0, sizeof(pi));
  wchar_t executable[4096], work[4096], out[4096], err[4096], command[4096];
  wchar_t *environment = NULL;
  int accepted = 0, cleanup_ok = 1, assigned = 0, code_known = 0;
  int termination_attempted = 0, natural_zero = 0, parent_deadline_exceeded = 0;
  DWORD code = 0, native_error = 0;
  const char *cause = "preflight";
  uint64_t peak_files = 0, final_files = 0, out_bytes = 0, err_bytes = 0;
  unsigned samples = 0;
  FILETIME creation = {0}, exit_time, kernel_time, user_time;
  if (GetTickCount64() >= work_until) { cause = "shared_work_budget_exhausted"; goto finish; }
  DWORD n = GetModuleFileNameW(NULL, executable, 4096u);
  if (!n || n >= 4096u) goto finish;
  n = GetCurrentDirectoryW(4096u, work);
  if (!n || n + 40u >= 4096u) goto finish;
  wcscat(work, L"\\pipeline-stop-16-"); wcscat(work, wide_profile);
  cause = "fresh_fixture";
  if (!CreateDirectoryW(work, NULL)) goto finish;
  if (wcslen(work) + 20u >= 4096u) goto finish;
  swprintf(out, 4096u, L"%ls\\worker.stdout.log", work);
  swprintf(err, 4096u, L"%ls\\worker.stderr.log", work);
  if (wcslen(executable) + 32u >= 4096u) goto finish;
  swprintf(command, 4096u, L"\"%ls\" --worker16-%ls", executable, wide_profile);
  environment = diag_clean_environment(work);
  if (!environment) goto finish;
  SECURITY_ATTRIBUTES sa = { (DWORD)sizeof(sa), NULL, TRUE };
  output = CreateFileW(out, GENERIC_WRITE, FILE_SHARE_READ, &sa, CREATE_NEW,
                       FILE_ATTRIBUTE_NORMAL, NULL);
  error = CreateFileW(err, GENERIC_WRITE, FILE_SHARE_READ, &sa, CREATE_NEW,
                      FILE_ATTRIBUTE_NORMAL, NULL);
  input = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                      &sa, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (output == INVALID_HANDLE_VALUE || error == INVALID_HANDLE_VALUE ||
      input == INVALID_HANDLE_VALUE) goto finish;
  job = CreateJobObjectW(NULL, NULL);
  if (!job) goto finish;
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limit; memset(&limit, 0, sizeof(limit));
  limit.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
  if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation,
                               &limit, (DWORD)sizeof(limit))) goto finish;
  STARTUPINFOW si; memset(&si, 0, sizeof(si)); si.cb = (DWORD)sizeof(si);
  si.dwFlags = STARTF_USESTDHANDLES;
  si.hStdInput = input; si.hStdOutput = output; si.hStdError = error;
  cause = "owned_child_create_assign_resume";
  if (!CreateProcessW(executable, command, NULL, NULL, TRUE,
      CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
      environment, work, &si, &pi)) goto finish;
  if (!GetProcessTimes(pi.hProcess, &creation, &exit_time, &kernel_time, &user_time)) goto finish;
  if (!AssignProcessToJobObject(job, pi.hProcess)) goto finish;
  assigned = 1;
  if (ResumeThread(pi.hThread) != 1u) goto finish;
  cause = "running";
  for (;;) {
    DWORD waited = WaitForSingleObject(pi.hProcess, 100u);
    LARGE_INTEGER os, es;
    if (!GetFileSizeEx(output, &os) || !GetFileSizeEx(error, &es) ||
        os.QuadPart < 0 || es.QuadPart < 0) { cause = "log_metadata_unknown"; goto finish; }
    out_bytes = (uint64_t)os.QuadPart; err_bytes = (uint64_t)es.QuadPart;
    if (out_bytes > DIAG_LOG_CAP - diag_prior_log_bytes ||
        err_bytes > DIAG_LOG_CAP - diag_prior_log_bytes - out_bytes) {
      cause = "combined_log_cap"; goto finish;
    }
    uint64_t bytes = diag_prior_fixture_bytes; unsigned entries = 0;
    if (!diag_tree_bytes(work, 0u, &bytes, &entries)) { cause = "fixture_guard"; goto finish; }
    ++samples; final_files = bytes; if (bytes > peak_files) peak_files = bytes;
    if (GetTickCount64() >= work_until) { cause = "worker_deadline"; goto finish; }
    if (waited == WAIT_OBJECT_0) break;
    if (waited != WAIT_TIMEOUT) { cause = "wait_unknown"; goto finish; }
  }
  if (!GetExitCodeProcess(pi.hProcess, &code)) { cause = "exit_unknown"; goto finish; }
  code_known = 1;
  for (;;) {
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION accounting;
    if (!QueryInformationJobObject(job, JobObjectBasicAccountingInformation,
        &accounting, (DWORD)sizeof(accounting), NULL)) { cause = "job_unknown"; goto finish; }
    if (accounting.ActiveProcesses == 0u) { natural_zero = 1; break; }
    if (GetTickCount64() >= work_until) { cause = "job_not_naturally_empty"; goto finish; }
    Sleep(10u);
  }
  /* Recheck after all Job descendants have naturally exited, so late output
   * cannot turn an over-cap stream into an accepted worker receipt. */
  LARGE_INTEGER final_out, final_err;
  if (!GetFileSizeEx(output, &final_out) || !GetFileSizeEx(error, &final_err) ||
      final_out.QuadPart < 0 || final_err.QuadPart < 0) { cause = "final_log_unknown"; goto finish; }
  out_bytes = (uint64_t)final_out.QuadPart; err_bytes = (uint64_t)final_err.QuadPart;
  if (out_bytes > DIAG_LOG_CAP - diag_prior_log_bytes ||
        err_bytes > DIAG_LOG_CAP - diag_prior_log_bytes - out_bytes) {
    cause = "combined_log_cap"; goto finish;
  }
  { uint64_t bytes = diag_prior_fixture_bytes; unsigned entries = 0;
    if (!diag_tree_bytes(work, 0u, &bytes, &entries)) { cause = "final_fixture_guard"; goto finish; }
    ++samples; final_files = bytes; if (bytes > peak_files) peak_files = bytes;
  }
  cause = code == 0u ? "worker_complete" : "worker_nonzero";
  accepted = code == 0u;
finish:
  native_error = GetLastError();
  if (!accepted && pi.hProcess && !natural_zero) {
    termination_attempted = 1;
    if (assigned && !TerminateJobObject(job, 90u)) cleanup_ok = 0;
    if (!assigned && !TerminateProcess(pi.hProcess, 90u)) cleanup_ok = 0;
    DWORD left = GetTickCount64() < final_until ? (DWORD)(final_until - GetTickCount64()) : 0u;
    if (WaitForSingleObject(pi.hProcess, left) != WAIT_OBJECT_0) cleanup_ok = 0;
    if (assigned) {
      for (;;) {
        JOBOBJECT_BASIC_ACCOUNTING_INFORMATION accounting;
        if (!QueryInformationJobObject(job, JobObjectBasicAccountingInformation,
            &accounting, (DWORD)sizeof(accounting), NULL)) { cleanup_ok = 0; break; }
        if (!accounting.ActiveProcesses) break;
        if (GetTickCount64() >= final_until) { cleanup_ok = 0; break; }
        Sleep(10u);
      }
    }
  }
  if (pi.hThread && !CloseHandle(pi.hThread)) cleanup_ok = 0;
  if (pi.hProcess && !CloseHandle(pi.hProcess)) cleanup_ok = 0;
  if (input != INVALID_HANDLE_VALUE && !CloseHandle(input)) cleanup_ok = 0;
  if (output != INVALID_HANDLE_VALUE && !CloseHandle(output)) cleanup_ok = 0;
  if (error != INVALID_HANDLE_VALUE && !CloseHandle(error)) cleanup_ok = 0;
  if (job && !CloseHandle(job)) cleanup_ok = 0;
  free(environment);
  if (GetTickCount64() >= final_until) { cleanup_ok = 0; parent_deadline_exceeded = 1; }
  int emitted = printf("{\"schema\":\"edr.private.pipeline-parent.v1\",\"cause\":\"%s\","
         "\"profile\":\"%s\",\"accepted\":%s,\"child_pid\":%lu,\"child_birth_filetime\":%llu,"
         "\"child_exit_known\":%s,\"child_exit_code\":%ld,\"job_natural_zero\":%s,"
         "\"termination_attempted\":%s,\"cleanup_verified\":%s,\"parent_deadline_exceeded\":%s,\"elapsed_ms\":%llu,"
         "\"stdout_bytes\":%llu,\"stderr_bytes\":%llu,\"fixture_sampled_peak_bytes\":%llu,"
         "\"fixture_final_sample_bytes\":%llu,\"fixture_samples\":%u,\"last_error_diagnostic_only\":%lu}\n",
         cause, profile, accepted && cleanup_ok ? "true" : "false", (unsigned long)pi.dwProcessId,
         (unsigned long long)(((uint64_t)creation.dwHighDateTime << 32) | creation.dwLowDateTime),
         code_known ? "true" : "false", (long)(LONG)code, natural_zero ? "true" : "false",
         termination_attempted ? "true" : "false", cleanup_ok ? "true" : "false",
         parent_deadline_exceeded ? "true" : "false", (unsigned long long)(GetTickCount64() - started), (unsigned long long)out_bytes,
         (unsigned long long)err_bytes, (unsigned long long)peak_files,
         (unsigned long long)final_files, samples, (unsigned long)native_error);
  if (emitted < 0 || fflush(stdout)) return 90;
  if (accepted && cleanup_ok) {
    diag_prior_fixture_bytes = final_files;
    diag_prior_log_bytes += out_bytes + err_bytes;
    return 0;
  }
  return 90;
}

static int diag_windows_supervise(void) {
  ULONGLONG started = GetTickCount64();
  /* Two distinct inputs, each launched at most once; the second never resets
   * the shared work/cleanup clocks or the combined file/log allowances. */
  int code = diag_windows_supervise_case("ready", started);
  if (code) return code;
  return diag_windows_supervise_case("missing", started);
}
#endif
