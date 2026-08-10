#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <wctype.h>

static const wchar_t *DEFAULT_INSTALL_DIR = L"C:\\Program Files\\FDSecurity";
static const wchar_t *DEFAULT_SERVICE_NAME = L"FDSecurityAgent";

static const wchar_t *arg_value(int argc, wchar_t **argv, const wchar_t *key) {
  for (int i = 1; i + 1 < argc; ++i) {
    if (_wcsicmp(argv[i], key) == 0) return argv[i + 1];
  }
  return L"";
}

static int has_flag(int argc, wchar_t **argv, const wchar_t *key) {
  for (int i = 1; i < argc; ++i) {
    if (_wcsicmp(argv[i], key) == 0) return 1;
  }
  return 0;
}

static void append_log_utf8(const wchar_t *path, const wchar_t *line) {
  if (!path || !path[0]) return;
  HANDLE h = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS,
                         FILE_ATTRIBUTE_NORMAL, NULL);
  if (h == INVALID_HANDLE_VALUE) return;
  SYSTEMTIME st;
  GetLocalTime(&st);
  wchar_t wide[4096];
  _snwprintf(wide, sizeof(wide) / sizeof(wide[0]), L"%04u-%02u-%02uT%02u:%02u:%02u.%03u %ls\r\n",
             (unsigned)st.wYear, (unsigned)st.wMonth, (unsigned)st.wDay, (unsigned)st.wHour,
             (unsigned)st.wMinute, (unsigned)st.wSecond, (unsigned)st.wMilliseconds, line);
  wide[(sizeof(wide) / sizeof(wide[0])) - 1] = 0;
  int need = WideCharToMultiByte(CP_UTF8, 0, wide, -1, NULL, 0, NULL, NULL);
  if (need > 1) {
    char *buf = (char *)calloc((size_t)need, 1);
    if (buf) {
      WideCharToMultiByte(CP_UTF8, 0, wide, -1, buf, need, NULL, NULL);
      DWORD written = 0;
      WriteFile(h, buf, (DWORD)strlen(buf), &written, NULL);
      free(buf);
    }
  }
  CloseHandle(h);
}

static void log_msg(const wchar_t *log_path, const wchar_t *prefix, const wchar_t *value) {
  wchar_t line[2048];
  _snwprintf(line, sizeof(line) / sizeof(line[0]), L"%ls%ls", prefix ? prefix : L"", value ? value : L"");
  line[(sizeof(line) / sizeof(line[0])) - 1] = 0;
  append_log_utf8(log_path, line);
}

static void join_path(wchar_t *out, size_t cap, const wchar_t *dir, const wchar_t *name) {
  if (!out || cap == 0) return;
  const wchar_t *d = (dir && dir[0]) ? dir : DEFAULT_INSTALL_DIR;
  size_t n = wcslen(d);
  const wchar_t *sep = (n > 0 && (d[n - 1] == L'\\' || d[n - 1] == L'/')) ? L"" : L"\\";
  _snwprintf(out, cap, L"%ls%ls%ls", d, sep, name ? name : L"");
  out[cap - 1] = 0;
}

static int file_exists(const wchar_t *path) {
  DWORD attr = GetFileAttributesW(path);
  return attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY);
}

static int dir_exists(const wchar_t *path) {
  DWORD attr = GetFileAttributesW(path);
  return attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY);
}

static void ensure_dir(const wchar_t *path, const wchar_t *log_path) {
  if (!path || !path[0] || dir_exists(path)) return;
  if (!CreateDirectoryW(path, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
    wchar_t line[1024];
    _snwprintf(line, sizeof(line) / sizeof(line[0]), L"mkdir_failed path=%ls gle=%lu", path, GetLastError());
    line[(sizeof(line) / sizeof(line[0])) - 1] = 0;
    append_log_utf8(log_path, line);
  }
}

static void system_exe_path(wchar_t *out, size_t cap, const wchar_t *name) {
  if (!out || cap == 0) return;
  wchar_t sys[MAX_PATH];
  UINT n = GetSystemDirectoryW(sys, (UINT)(sizeof(sys) / sizeof(sys[0])));
  if (n == 0 || n >= (sizeof(sys) / sizeof(sys[0]))) {
    _snwprintf(out, cap, L"%ls", name ? name : L"");
  } else {
    _snwprintf(out, cap, L"%ls\\%ls", sys, name ? name : L"");
  }
  out[cap - 1] = 0;
}

static void windows_powershell_path(wchar_t *out, size_t cap) {
  if (!out || cap == 0) return;
  wchar_t windows_dir[MAX_PATH];
  UINT n = GetWindowsDirectoryW(windows_dir, (UINT)(sizeof(windows_dir) / sizeof(windows_dir[0])));
  if (n == 0 || n >= (sizeof(windows_dir) / sizeof(windows_dir[0]))) {
    _snwprintf(out, cap, L"powershell.exe");
  } else {
    _snwprintf(out, cap, L"%ls\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", windows_dir);
  }
  out[cap - 1] = 0;
}

static void quote_arg(wchar_t *out, size_t cap, const wchar_t *value) {
  if (!out || cap == 0) return;
  size_t pos = 0;
  out[pos++] = L'"';
  for (const wchar_t *p = value ? value : L""; *p && pos + 2 < cap; ++p) {
    if (*p == L'"') out[pos++] = L'\\';
    out[pos++] = *p;
  }
  if (pos + 1 < cap) out[pos++] = L'"';
  out[pos] = 0;
}

static void trim_ascii(char *s) {
  if (!s) return;
  char *p = s;
  while (*p && isspace((unsigned char)*p)) ++p;
  if (p != s) memmove(s, p, strlen(p) + 1);
  size_t n = strlen(s);
  while (n > 0 && isspace((unsigned char)s[n - 1])) s[--n] = 0;
}

static int read_toml_scalar(const wchar_t *path, const char *key, wchar_t *out, size_t out_cap) {
  if (!out || out_cap == 0) return 0;
  out[0] = 0;
  if (!path || !path[0] || !key || !key[0]) return 0;

  FILE *f = _wfopen(path, L"rb");
  if (!f) return 0;
  char line[4096];
  size_t key_len = strlen(key);
  while (fgets(line, sizeof(line), f)) {
    char *p = line;
    while (*p && isspace((unsigned char)*p)) ++p;
    if (*p == '#' || *p == 0) continue;
    if (strncmp(p, key, key_len) != 0) continue;
    p += key_len;
    while (*p && isspace((unsigned char)*p)) ++p;
    if (*p != '=') continue;
    ++p;
    while (*p && isspace((unsigned char)*p)) ++p;

    char value[2048];
    value[0] = 0;
    if (*p == '"') {
      ++p;
      size_t pos = 0;
      while (*p && *p != '"' && pos + 1 < sizeof(value)) {
        value[pos++] = *p++;
      }
      value[pos] = 0;
    } else {
      size_t pos = 0;
      while (*p && *p != '#' && *p != '\r' && *p != '\n' && pos + 1 < sizeof(value)) {
        value[pos++] = *p++;
      }
      value[pos] = 0;
      trim_ascii(value);
    }
    fclose(f);
    if (!value[0]) return 0;
    int n = MultiByteToWideChar(CP_UTF8, 0, value, -1, out, (int)out_cap);
    if (n <= 0) {
      n = MultiByteToWideChar(CP_ACP, 0, value, -1, out, (int)out_cap);
    }
    if (n <= 0) {
      out[0] = 0;
      return 0;
    }
    out[out_cap - 1] = 0;
    return 1;
  }
  fclose(f);
  return 0;
}

static void trim_wide_trailing_slashes(wchar_t *s) {
  if (!s) return;
  size_t n = wcslen(s);
  while (n > 0 && (s[n - 1] == L'/' || s[n - 1] == L'\\')) {
    s[--n] = 0;
  }
}

static const wchar_t *collector_arch_token(void) {
#if defined(_M_ARM64) || defined(__aarch64__)
  return L"arm64";
#else
  return L"amd64";
#endif
}

static int build_forensic_manifest_url(wchar_t *out, size_t cap, const wchar_t *rest_base,
                                       const wchar_t *kind) {
  if (!out || cap == 0) return 0;
  out[0] = 0;
  if (!rest_base || !rest_base[0] || !kind || !kind[0]) return 0;
  wchar_t base[1024];
  _snwprintf(base, sizeof(base) / sizeof(base[0]), L"%ls", rest_base);
  base[(sizeof(base) / sizeof(base[0])) - 1] = 0;
  trim_wide_trailing_slashes(base);
  if (!base[0]) return 0;
  int n = _snwprintf(out, cap,
                     L"%ls/agent/forensic-collector/manifest?kind=%ls&os=windows&arch=%ls",
                     base, kind, collector_arch_token());
  out[cap - 1] = 0;
  return n > 0 && (size_t)n < cap;
}

static void sanitize_thumbprint(const wchar_t *in, wchar_t *out, size_t cap) {
  if (!out || cap == 0) return;
  size_t pos = 0;
  for (const wchar_t *p = in ? in : L""; *p && pos + 1 < cap; ++p) {
    wchar_t ch = *p;
    if ((ch >= L'0' && ch <= L'9') || (ch >= L'a' && ch <= L'f') || (ch >= L'A' && ch <= L'F')) {
      out[pos++] = (wchar_t)towupper(ch);
    }
  }
  out[pos] = 0;
}

static int run_process_wait(const wchar_t *exe_path, const wchar_t *args, const wchar_t *work_dir,
                            const wchar_t *log_path, DWORD timeout_ms) {
  wchar_t qexe[MAX_PATH * 2];
  wchar_t cmd[8192];
  quote_arg(qexe, sizeof(qexe) / sizeof(qexe[0]), exe_path);
  _snwprintf(cmd, sizeof(cmd) / sizeof(cmd[0]), L"%ls %ls", qexe, args ? args : L"");
  cmd[(sizeof(cmd) / sizeof(cmd[0])) - 1] = 0;

  wchar_t line[8192];
  _snwprintf(line, sizeof(line) / sizeof(line[0]), L"run exe=%ls args=%ls", exe_path, args ? args : L"");
  line[(sizeof(line) / sizeof(line[0])) - 1] = 0;
  append_log_utf8(log_path, line);

  STARTUPINFOW si;
  PROCESS_INFORMATION pi;
  ZeroMemory(&si, sizeof(si));
  ZeroMemory(&pi, sizeof(pi));
  si.cb = sizeof(si);
  si.dwFlags = STARTF_USESHOWWINDOW;
  si.wShowWindow = SW_HIDE;

  SECURITY_ATTRIBUTES sa;
  ZeroMemory(&sa, sizeof(sa));
  sa.nLength = sizeof(sa);
  sa.bInheritHandle = TRUE;
  HANDLE child_log = INVALID_HANDLE_VALUE;
  HANDLE child_stdin = INVALID_HANDLE_VALUE;
  if (log_path && log_path[0]) {
    child_log = CreateFileW(log_path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_ALWAYS,
                            FILE_ATTRIBUTE_NORMAL, NULL);
    child_stdin = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING,
                              FILE_ATTRIBUTE_NORMAL, NULL);
    if (child_log != INVALID_HANDLE_VALUE && child_stdin != INVALID_HANDLE_VALUE) {
      si.dwFlags |= STARTF_USESTDHANDLES;
      si.hStdInput = child_stdin;
      si.hStdOutput = child_log;
      si.hStdError = child_log;
    } else {
      if (child_log != INVALID_HANDLE_VALUE) CloseHandle(child_log);
      if (child_stdin != INVALID_HANDLE_VALUE) CloseHandle(child_stdin);
      child_log = INVALID_HANDLE_VALUE;
      child_stdin = INVALID_HANDLE_VALUE;
    }
  }

  BOOL inherit_handles = child_log != INVALID_HANDLE_VALUE;
  BOOL ok = CreateProcessW(exe_path, cmd, NULL, NULL, inherit_handles, CREATE_NO_WINDOW, NULL, work_dir, &si, &pi);
  if (!ok) {
    DWORD create_error = GetLastError();
    if (child_log != INVALID_HANDLE_VALUE) CloseHandle(child_log);
    if (child_stdin != INVALID_HANDLE_VALUE) CloseHandle(child_stdin);
    _snwprintf(line, sizeof(line) / sizeof(line[0]), L"run_failed gle=%lu exe=%ls", create_error, exe_path);
    line[(sizeof(line) / sizeof(line[0])) - 1] = 0;
    append_log_utf8(log_path, line);
    return 9001;
  }
  DWORD wait = WaitForSingleObject(pi.hProcess, timeout_ms ? timeout_ms : 30000);
  DWORD exit_code = 9002;
  if (wait == WAIT_TIMEOUT) {
    TerminateProcess(pi.hProcess, 9002);
    append_log_utf8(log_path, L"run_timeout");
  } else {
    GetExitCodeProcess(pi.hProcess, &exit_code);
  }
  if (child_log != INVALID_HANDLE_VALUE) CloseHandle(child_log);
  if (child_stdin != INVALID_HANDLE_VALUE) CloseHandle(child_stdin);
  _snwprintf(line, sizeof(line) / sizeof(line[0]), L"run_exit code=%lu", exit_code);
  line[(sizeof(line) / sizeof(line[0])) - 1] = 0;
  append_log_utf8(log_path, line);
  CloseHandle(pi.hThread);
  CloseHandle(pi.hProcess);
  return (int)exit_code;
}

static void delete_file_if_exists(const wchar_t *path, const wchar_t *log_path) {
  if (!path || !path[0]) return;
  DWORD attr = GetFileAttributesW(path);
  if (attr == INVALID_FILE_ATTRIBUTES || (attr & FILE_ATTRIBUTE_DIRECTORY)) return;
  if (DeleteFileW(path)) return;

  DWORD first_error = GetLastError();
  if (first_error == ERROR_ACCESS_DENIED) {
    SetFileAttributesW(path, FILE_ATTRIBUTE_NORMAL);
    if (DeleteFileW(path)) {
      append_log_utf8(log_path, L"delete_recovered_after_attribute_reset");
      return;
    }

    wchar_t takeown[MAX_PATH * 2], icacls[MAX_PATH * 2], qpath[MAX_PATH * 4], args[MAX_PATH * 6];
    system_exe_path(takeown, sizeof(takeown) / sizeof(takeown[0]), L"takeown.exe");
    system_exe_path(icacls, sizeof(icacls) / sizeof(icacls[0]), L"icacls.exe");
    quote_arg(qpath, sizeof(qpath) / sizeof(qpath[0]), path);
    _snwprintf(args, sizeof(args) / sizeof(args[0]), L"/F %ls /A", qpath);
    args[(sizeof(args) / sizeof(args[0])) - 1] = 0;
    (void)run_process_wait(takeown, args, NULL, log_path, 30000);
    _snwprintf(args, sizeof(args) / sizeof(args[0]),
               L"%ls /inheritance:r /grant:r \"*S-1-5-18:F\" /grant:r \"*S-1-5-32-544:F\" /C /Q", qpath);
    args[(sizeof(args) / sizeof(args[0])) - 1] = 0;
    (void)run_process_wait(icacls, args, NULL, log_path, 30000);
    if (DeleteFileW(path)) {
      append_log_utf8(log_path, L"delete_recovered_after_acl_reset");
      return;
    }
  }

  {
    wchar_t line[2048];
    _snwprintf(line, sizeof(line) / sizeof(line[0]), L"delete_failed path=%ls gle=%lu", path, GetLastError());
    line[(sizeof(line) / sizeof(line[0])) - 1] = 0;
    append_log_utf8(log_path, line);
  }
}

static void delete_glob(const wchar_t *pattern, const wchar_t *log_path) {
  WIN32_FIND_DATAW fd;
  HANDLE h = FindFirstFileW(pattern, &fd);
  if (h == INVALID_HANDLE_VALUE) return;
  wchar_t base[MAX_PATH * 2];
  wcsncpy(base, pattern, sizeof(base) / sizeof(base[0]));
  base[(sizeof(base) / sizeof(base[0])) - 1] = 0;
  wchar_t *slash = wcsrchr(base, L'\\');
  if (slash) *(slash + 1) = 0;
  do {
    if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
    wchar_t path[MAX_PATH * 2];
    _snwprintf(path, sizeof(path) / sizeof(path[0]), L"%ls%ls", slash ? base : L"", fd.cFileName);
    path[(sizeof(path) / sizeof(path[0])) - 1] = 0;
    delete_file_if_exists(path, log_path);
  } while (FindNextFileW(h, &fd));
  FindClose(h);
}

static int stop_service_by_name(const wchar_t *service_name, const wchar_t *log_path) {
  SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
  if (!scm) return 0;
  SC_HANDLE svc = OpenServiceW(scm, service_name, SERVICE_STOP | SERVICE_QUERY_STATUS);
  if (!svc) {
    CloseServiceHandle(scm);
    return 0;
  }
  SERVICE_STATUS_PROCESS ssp;
  DWORD bytes = 0;
  if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &bytes) &&
      ssp.dwCurrentState != SERVICE_STOPPED) {
    SERVICE_STATUS ss;
    ControlService(svc, SERVICE_CONTROL_STOP, &ss);
    for (int i = 0; i < 40; ++i) {
      Sleep(250);
      if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &bytes) &&
          ssp.dwCurrentState == SERVICE_STOPPED) {
        break;
      }
    }
  }
  wchar_t line[512];
  _snwprintf(line, sizeof(line) / sizeof(line[0]), L"stop_service name=%ls", service_name);
  line[(sizeof(line) / sizeof(line[0])) - 1] = 0;
  append_log_utf8(log_path, line);
  CloseServiceHandle(svc);
  CloseServiceHandle(scm);
  return 1;
}

static int process_running_by_name(const wchar_t *image_name);

static int start_service_by_name(const wchar_t *service_name, const wchar_t *log_path) {
  SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
  if (!scm) return 2;
  SC_HANDLE svc = OpenServiceW(scm, service_name, SERVICE_START | SERVICE_QUERY_STATUS);
  if (!svc) {
    CloseServiceHandle(scm);
    return 3;
  }
  BOOL start_ok = StartServiceW(svc, 0, NULL);
  DWORD start_error = start_ok ? ERROR_SUCCESS : GetLastError();
  if (!start_ok && start_error != ERROR_SERVICE_ALREADY_RUNNING) {
    wchar_t line[512];
    _snwprintf(line, sizeof(line) / sizeof(line[0]), L"start_service_failed name=%ls gle=%lu", service_name,
               start_error);
    line[(sizeof(line) / sizeof(line[0])) - 1] = 0;
    append_log_utf8(log_path, line);
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return 4;
  }
  SERVICE_STATUS_PROCESS ssp;
  DWORD bytes = 0;
  int ok = 0;
  for (int i = 0; i < 40; ++i) {
    Sleep(250);
    if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &bytes) &&
        ssp.dwCurrentState == SERVICE_RUNNING) {
      ok = 1;
      break;
    }
  }
  int process_ok = 0;
  if (ok) {
    for (int i = 0; i < 40; ++i) {
      if (process_running_by_name(L"FDSensor.exe")) {
        process_ok = 1;
        break;
      }
      Sleep(250);
    }
  }
  wchar_t line[512];
  _snwprintf(line, sizeof(line) / sizeof(line[0]),
             L"start_service name=%ls service_running=%d process_running=%d start_gle=%lu", service_name, ok,
             process_ok, start_error);
  line[(sizeof(line) / sizeof(line[0])) - 1] = 0;
  append_log_utf8(log_path, line);
  CloseServiceHandle(svc);
  CloseServiceHandle(scm);
  return (ok && process_ok) ? 0 : 5;
}

static int service_running_by_name(const wchar_t *service_name) {
  int running = 0;
  SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
  if (!scm) return 0;
  SC_HANDLE svc = OpenServiceW(scm, service_name, SERVICE_QUERY_STATUS);
  if (!svc) {
    CloseServiceHandle(scm);
    return 0;
  }
  SERVICE_STATUS_PROCESS ssp;
  DWORD bytes = 0;
  if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &bytes) &&
      ssp.dwCurrentState == SERVICE_RUNNING) {
    running = 1;
  }
  CloseServiceHandle(svc);
  CloseServiceHandle(scm);
  return running;
}

static void delete_service_by_name(const wchar_t *service_name, const wchar_t *log_path) {
  SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
  if (!scm) return;
  SC_HANDLE svc = OpenServiceW(scm, service_name, DELETE | SERVICE_STOP | SERVICE_QUERY_STATUS);
  if (!svc) {
    CloseServiceHandle(scm);
    return;
  }
  SERVICE_STATUS ss;
  ControlService(svc, SERVICE_CONTROL_STOP, &ss);
  DeleteService(svc);
  wchar_t line[512];
  _snwprintf(line, sizeof(line) / sizeof(line[0]), L"delete_service name=%ls gle=%lu", service_name, GetLastError());
  line[(sizeof(line) / sizeof(line[0])) - 1] = 0;
  append_log_utf8(log_path, line);
  CloseServiceHandle(svc);
  CloseServiceHandle(scm);
}

static void stop_process_by_name(const wchar_t *image_name, const wchar_t *log_path) {
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snap == INVALID_HANDLE_VALUE) return;
  PROCESSENTRY32W pe;
  ZeroMemory(&pe, sizeof(pe));
  pe.dwSize = sizeof(pe);
  if (Process32FirstW(snap, &pe)) {
    do {
      if (_wcsicmp(pe.szExeFile, image_name) != 0) continue;
      HANDLE p = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, pe.th32ProcessID);
      if (!p) continue;
      TerminateProcess(p, 0);
      WaitForSingleObject(p, 3000);
      CloseHandle(p);
      wchar_t line[512];
      _snwprintf(line, sizeof(line) / sizeof(line[0]), L"stop_process image=%ls pid=%lu", image_name,
                 pe.th32ProcessID);
      line[(sizeof(line) / sizeof(line[0])) - 1] = 0;
      append_log_utf8(log_path, line);
    } while (Process32NextW(snap, &pe));
  }
  CloseHandle(snap);
}

static int process_running_by_name(const wchar_t *image_name) {
  int found = 0;
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snap == INVALID_HANDLE_VALUE) return 0;
  PROCESSENTRY32W pe;
  ZeroMemory(&pe, sizeof(pe));
  pe.dwSize = sizeof(pe);
  if (Process32FirstW(snap, &pe)) {
    do {
      if (_wcsicmp(pe.szExeFile, image_name) == 0) {
        found = 1;
        break;
      }
    } while (Process32NextW(snap, &pe));
  }
  CloseHandle(snap);
  return found;
}

static int stage_stop_runtime(const wchar_t *install_dir, const wchar_t *log_path) {
  append_log_utf8(log_path, L"stage=stop-runtime begin");
  wchar_t schtasks[MAX_PATH * 2];
  system_exe_path(schtasks, sizeof(schtasks) / sizeof(schtasks[0]), L"schtasks.exe");
  (void)run_process_wait(schtasks, L"/End /TN \"FDSecurityAgent\"", install_dir, log_path, 30000);
  (void)run_process_wait(schtasks, L"/End /TN \"EdrAgent\"", install_dir, log_path, 30000);
  stop_service_by_name(DEFAULT_SERVICE_NAME, log_path);
  stop_service_by_name(L"EdrAgent", log_path);
  stop_process_by_name(L"FDSensor.exe", log_path);
  stop_process_by_name(L"edr_agent.exe", log_path);
  wchar_t path[MAX_PATH * 2];
  join_path(path, sizeof(path) / sizeof(path[0]), install_dir, L"FDSensor.pid");
  delete_file_if_exists(path, log_path);
  join_path(path, sizeof(path) / sizeof(path[0]), install_dir, L"edr_agent.pid");
  delete_file_if_exists(path, log_path);
  append_log_utf8(log_path, L"stage=stop-runtime ok");
  return 0;
}

static void write_clean_report(const wchar_t *report_path, const wchar_t *install_dir, int keep_queue, int keep_evidence) {
  if (!report_path || !report_path[0]) return;
  HANDLE h = CreateFileW(report_path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (h == INVALID_HANDLE_VALUE) return;
  (void)install_dir;
  char json[1024];
  snprintf(json, sizeof(json),
           "{\r\n  \"status\": \"ok\",\r\n  \"engine\": \"native_worker\",\r\n  \"keep_offline_queue\": %s,\r\n  \"keep_evidence_cache\": %s\r\n}\r\n",
           keep_queue ? "true" : "false", keep_evidence ? "true" : "false");
  DWORD written = 0;
  WriteFile(h, json, (DWORD)strlen(json), &written, NULL);
  CloseHandle(h);
}

static int stage_clean_cache(const wchar_t *install_dir, const wchar_t *log_path, const wchar_t *report_path,
                             int keep_queue, int keep_evidence) {
  append_log_utf8(log_path, L"stage=clean-cache begin");
  wchar_t pattern[MAX_PATH * 2];
  if (!keep_queue) {
    join_path(pattern, sizeof(pattern) / sizeof(pattern[0]), install_dir, L"queue\\edr_queue.db*");
    delete_glob(pattern, log_path);
    join_path(pattern, sizeof(pattern) / sizeof(pattern[0]), install_dir, L"edr_queue.db*");
    delete_glob(pattern, log_path);
  }
  join_path(pattern, sizeof(pattern) / sizeof(pattern[0]), install_dir, L"queue\\edr_queue.db.lock");
  delete_file_if_exists(pattern, log_path);
  if (!keep_evidence) {
    join_path(pattern, sizeof(pattern) / sizeof(pattern[0]), install_dir, L"evidence\\local_evidence_cache.db*");
    delete_glob(pattern, log_path);
    join_path(pattern, sizeof(pattern) / sizeof(pattern[0]), install_dir, L"local_evidence_cache.db*");
    delete_glob(pattern, log_path);
  }
  write_clean_report(report_path, install_dir, keep_queue, keep_evidence);
  append_log_utf8(log_path, L"stage=clean-cache ok");
  return 0;
}

static void set_machine_env(const wchar_t *name, const wchar_t *value, const wchar_t *log_path) {
  HKEY key;
  LONG rc = RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment",
                            0, NULL, 0, KEY_SET_VALUE, NULL, &key, NULL);
  if (rc != ERROR_SUCCESS) {
    wchar_t line[512];
    _snwprintf(line, sizeof(line) / sizeof(line[0]), L"env_open_failed name=%ls rc=%ld", name, rc);
    append_log_utf8(log_path, line);
    return;
  }
  if (value && value[0]) {
    RegSetValueExW(key, name, 0, REG_SZ, (const BYTE *)value, (DWORD)((wcslen(value) + 1) * sizeof(wchar_t)));
  } else {
    RegDeleteValueW(key, name);
  }
  RegCloseKey(key);
}

static void broadcast_env_changed(void) {
  DWORD_PTR ignored = 0;
  SendMessageTimeoutW(HWND_BROADCAST, WM_SETTINGCHANGE, 0, (LPARAM)L"Environment", SMTO_ABORTIFHUNG, 3000, &ignored);
}

static void ensure_runtime_dirs(const wchar_t *install_dir, const wchar_t *log_path) {
  const wchar_t *dirs[] = {L"certs", L"queue", L"evidence", L"state", L"logs", L"diagnostics",
                           L"upload_outbox", L"forensic", L"collector", L"isolation", NULL};
  wchar_t path[MAX_PATH * 2];
  for (int i = 0; dirs[i]; ++i) {
    join_path(path, sizeof(path) / sizeof(path[0]), install_dir, dirs[i]);
    ensure_dir(path, log_path);
  }
}

static int run_icacls(const wchar_t *args, const wchar_t *install_dir, const wchar_t *log_path) {
  wchar_t exe[MAX_PATH * 2];
  system_exe_path(exe, sizeof(exe) / sizeof(exe[0]), L"icacls.exe");
  return run_process_wait(exe, args, install_dir, log_path, 30000);
}

static int run_takeown(const wchar_t *args, const wchar_t *install_dir, const wchar_t *log_path) {
  wchar_t exe[MAX_PATH * 2];
  system_exe_path(exe, sizeof(exe) / sizeof(exe[0]), L"takeown.exe");
  return run_process_wait(exe, args, install_dir, log_path, 30000);
}

static int stage_harden_acl(const wchar_t *install_dir, const wchar_t *log_path) {
  append_log_utf8(log_path, L"stage=harden-acl begin");
  ensure_runtime_dirs(install_dir, log_path);
  wchar_t qdir[MAX_PATH * 2], qpath[MAX_PATH * 2], args[4096], path[MAX_PATH * 2];
  quote_arg(qdir, sizeof(qdir) / sizeof(qdir[0]), install_dir);

  _snwprintf(args, sizeof(args) / sizeof(args[0]),
             L"%ls /grant:r \"*S-1-5-18:(OI)(CI)F\" /grant:r \"*S-1-5-32-544:(OI)(CI)F\" /grant:r \"*S-1-5-32-545:(OI)(CI)RX\" /C /Q",
             qdir);
  args[(sizeof(args) / sizeof(args[0])) - 1] = 0;
  (void)run_icacls(args, install_dir, log_path);

  const wchar_t *sensitive_dirs[] = {L"certs", L"queue", L"evidence", L"state", L"logs", L"diagnostics",
                                     L"upload_outbox", L"forensic", L"collector", L"isolation", NULL};
  for (int i = 0; sensitive_dirs[i]; ++i) {
    join_path(path, sizeof(path) / sizeof(path[0]), install_dir, sensitive_dirs[i]);
    quote_arg(qpath, sizeof(qpath) / sizeof(qpath[0]), path);
    _snwprintf(args, sizeof(args) / sizeof(args[0]), L"/F %ls /A /R /D Y", qpath);
    args[(sizeof(args) / sizeof(args[0])) - 1] = 0;
    (void)run_takeown(args, install_dir, log_path);
    _snwprintf(args, sizeof(args) / sizeof(args[0]),
               L"%ls /inheritance:r /grant:r \"*S-1-5-18:(OI)(CI)F\" /grant:r \"*S-1-5-32-544:(OI)(CI)F\" /T /C /Q",
               qpath);
    args[(sizeof(args) / sizeof(args[0])) - 1] = 0;
    int acl_rc = run_icacls(args, install_dir, log_path);
    if (_wcsicmp(sensitive_dirs[i], L"queue") == 0 && acl_rc != 0) {
      append_log_utf8(log_path, L"queue_acl_repair_failed");
      return 52;
    }
  }

  join_path(path, sizeof(path) / sizeof(path[0]), install_dir, L"queue\\edr_queue.db.lock");
  delete_file_if_exists(path, log_path);
  if (file_exists(path)) {
    append_log_utf8(log_path, L"stale_queue_lock_remove_failed");
    return 53;
  }

  const struct {
    const wchar_t *name;
    const wchar_t *users_grant;
  } uninstaller_files[] = {
      {L"unins000.exe", L"RX"},
      {L"unins000.dat", L"R"},
      {NULL, NULL},
  };
  for (int i = 0; uninstaller_files[i].name; ++i) {
    join_path(path, sizeof(path) / sizeof(path[0]), install_dir, uninstaller_files[i].name);
    if (file_exists(path)) {
      quote_arg(qpath, sizeof(qpath) / sizeof(qpath[0]), path);
      _snwprintf(args, sizeof(args) / sizeof(args[0]),
                 L"%ls /grant:r \"*S-1-5-18:F\" /grant:r \"*S-1-5-32-544:F\" /grant:r \"*S-1-5-32-545:%ls\" /C /Q",
                 qpath, uninstaller_files[i].users_grant);
      args[(sizeof(args) / sizeof(args[0])) - 1] = 0;
      run_icacls(args, install_dir, log_path);
    }
  }

  join_path(path, sizeof(path) / sizeof(path[0]), install_dir, L"agent.toml");
  if (file_exists(path)) {
    quote_arg(qpath, sizeof(qpath) / sizeof(qpath[0]), path);
    _snwprintf(args, sizeof(args) / sizeof(args[0]),
               L"%ls /inheritance:r /grant:r \"*S-1-5-18:F\" /grant:r \"*S-1-5-32-544:F\" /C /Q",
               qpath);
    args[(sizeof(args) / sizeof(args[0])) - 1] = 0;
    run_icacls(args, install_dir, log_path);
  }
  append_log_utf8(log_path, L"stage=harden-acl ok");
  return 0;
}

static void set_runtime_env(const wchar_t *install_dir, const wchar_t *config_path, const wchar_t *log_path) {
  wchar_t path[MAX_PATH * 2], rest_base[1024], url[1400];
  set_machine_env(L"EDR_UPLOAD_FILE_RETRIES", L"3", log_path);
  set_machine_env(L"EDR_UPLOAD_FILE_RETRY_BACKOFF_MS", L"750", log_path);
  join_path(path, sizeof(path) / sizeof(path[0]), install_dir, L"forensic");
  set_machine_env(L"EDR_FORENSIC_OUT", path, log_path);
  set_machine_env(L"EDR_FORENSIC_COLLECTOR", L"1", log_path);
  join_path(path, sizeof(path) / sizeof(path[0]), install_dir, L"collector\\forensic_collector.exe");
  set_machine_env(L"EDR_FORENSIC_COLLECTOR_BIN", path, log_path);
  join_path(path, sizeof(path) / sizeof(path[0]), install_dir, L"collector\\forensic_collector_builtin.exe");
  set_machine_env(L"EDR_FORENSIC_COLLECTOR_BUILTIN_BIN", path, log_path);
  join_path(path, sizeof(path) / sizeof(path[0]), install_dir, L"collector\\velociraptor.exe");
  set_machine_env(L"EDR_VELOCIRAPTOR_BIN", path, log_path);
  set_machine_env(L"EDR_FORENSIC_VERSION_CHECK_SEC", L"900", log_path);
  set_machine_env(L"EDR_FORENSIC_PREFETCH_RETRY_SEC", L"900", log_path);
  set_machine_env(L"EDR_FORENSIC_COLLECTOR_AUTOFETCH", L"1", log_path);
  rest_base[0] = 0;
  if (read_toml_scalar(config_path, "rest_base_url", rest_base, sizeof(rest_base) / sizeof(rest_base[0]))) {
    trim_wide_trailing_slashes(rest_base);
    if (build_forensic_manifest_url(url, sizeof(url) / sizeof(url[0]), rest_base, L"adapter")) {
      set_machine_env(L"EDR_FORENSIC_ADAPTER_MANIFEST_URL", url, log_path);
    }
    if (build_forensic_manifest_url(url, sizeof(url) / sizeof(url[0]), rest_base, L"velociraptor")) {
      set_machine_env(L"EDR_FORENSIC_COLLECTOR_MANIFEST_URL", url, log_path);
    }
    append_log_utf8(log_path, L"forensic_manifest_env_configured");
  } else {
    append_log_utf8(log_path, L"forensic_manifest_env_skipped rest_base_url_missing");
  }
  join_path(path, sizeof(path) / sizeof(path[0]), install_dir, L"logs\\command_audit.log");
  set_machine_env(L"EDR_CMD_AUDIT_PATH", path, log_path);
  join_path(path, sizeof(path) / sizeof(path[0]), install_dir, L"FDSensor.pid");
  set_machine_env(L"EDR_SELF_PROTECT_PIDFILE", path, log_path);
  join_path(path, sizeof(path) / sizeof(path[0]), install_dir, L"isolation\\isolated.stamp");
  set_machine_env(L"EDR_ISOLATE_STAMP_PATH", path, log_path);
  broadcast_env_changed();
}

static void clear_runtime_env(const wchar_t *log_path) {
  const wchar_t *names[] = {L"EDR_UPLOAD_FILE_RETRIES", L"EDR_UPLOAD_FILE_RETRY_BACKOFF_MS", L"EDR_FORENSIC_OUT",
                            L"EDR_FORENSIC_COLLECTOR", L"EDR_FORENSIC_COLLECTOR_BIN",
                            L"EDR_FORENSIC_COLLECTOR_BUILTIN_BIN", L"EDR_VELOCIRAPTOR_BIN",
                            L"EDR_FORENSIC_VERSION_CHECK_SEC", L"EDR_FORENSIC_PREFETCH_RETRY_SEC",
                            L"EDR_FORENSIC_COLLECTOR_AUTOFETCH",
                            L"EDR_FORENSIC_ADAPTER_MANIFEST_URL", L"EDR_FORENSIC_COLLECTOR_MANIFEST_URL",
                            L"EDR_CMD_AUDIT_PATH", L"EDR_SELF_PROTECT_PIDFILE", L"EDR_ISOLATE_STAMP_PATH",
                            L"EDR_GRPC_REQUIRE_MTLS", L"EDR_ISOLATE_HOOK", L"EDR_CMD_ENABLED", NULL};
  for (int i = 0; names[i]; ++i) set_machine_env(names[i], L"", log_path);
  broadcast_env_changed();
}

static int toml_header_sanity(const char *buf, DWORD len, int *bad_line) {
  DWORD i = 0;
  int line = 1;
  int checked = 0;
  if (len >= 3 && (unsigned char)buf[0] == 0xEF && (unsigned char)buf[1] == 0xBB &&
      (unsigned char)buf[2] == 0xBF) {
    i = 3;
  }
  while (i < len && checked < 24) {
    DWORD start = i;
    while (i < len && buf[i] != '\n' && buf[i] != '\r') i++;
    DWORD end = i;
    while (start < end && (buf[start] == ' ' || buf[start] == '\t')) start++;
    while (end > start && (buf[end - 1] == ' ' || buf[end - 1] == '\t')) end--;
    if (end > start && buf[start] != '#') {
      checked++;
      if (buf[start] != '[') {
        int has_eq = 0;
        for (DWORD j = start; j < end; ++j) {
          if (buf[j] == '=') {
            has_eq = 1;
            break;
          }
        }
        if (!has_eq) {
          if (bad_line) *bad_line = line;
          return 0;
        }
      }
    }
    if (i < len && buf[i] == '\r') i++;
    if (i < len && buf[i] == '\n') i++;
    line++;
  }
  return 1;
}

static int stage_validate_config(const wchar_t *install_dir, const wchar_t *exe_path,
                                 const wchar_t *config_path, const wchar_t *log_path) {
  append_log_utf8(log_path, L"stage=validate-config begin");
  HANDLE h = CreateFileW(config_path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
                         FILE_ATTRIBUTE_NORMAL, NULL);
  if (h == INVALID_HANDLE_VALUE) {
    log_msg(log_path, L"config_missing path=", config_path);
    return 10;
  }
  LARGE_INTEGER sz;
  if (!GetFileSizeEx(h, &sz) || sz.QuadPart <= 0) {
    CloseHandle(h);
    append_log_utf8(log_path, L"config_empty");
    return 11;
  }
  DWORD to_read = (DWORD)((sz.QuadPart > 65536) ? 65536 : sz.QuadPart);
  char *buf = (char *)calloc((size_t)to_read + 1, 1);
  DWORD got = 0;
  int rc = 0;
  if (!buf || !ReadFile(h, buf, to_read, &got, NULL) || got == 0) {
    rc = 12;
  } else {
    int bad_line = 0;
    if (!toml_header_sanity(buf, got, &bad_line)) {
      wchar_t line[256];
      _snwprintf(line, sizeof(line) / sizeof(line[0]), L"config_toml_sanity_failed line=%d", bad_line);
      line[(sizeof(line) / sizeof(line[0])) - 1] = 0;
      append_log_utf8(log_path, line);
      rc = 13;
    }
  }
  if (buf) free(buf);
  CloseHandle(h);
  if (rc == 0) {
    if (exe_path && exe_path[0] && file_exists(exe_path)) {
      wchar_t qcfg[MAX_PATH * 2], args[4096];
      quote_arg(qcfg, sizeof(qcfg) / sizeof(qcfg[0]), config_path);
      _snwprintf(args, sizeof(args) / sizeof(args[0]), L"--config %ls --config-test", qcfg);
      args[(sizeof(args) / sizeof(args[0])) - 1] = 0;
      int test_rc = run_process_wait(exe_path, args, install_dir, log_path, 15000);
      if (test_rc != 0) {
        wchar_t line[256];
        _snwprintf(line, sizeof(line) / sizeof(line[0]), L"config_test_failed rc=%d", test_rc);
        line[(sizeof(line) / sizeof(line[0])) - 1] = 0;
        append_log_utf8(log_path, line);
        return 14;
      }
    } else {
      append_log_utf8(log_path, L"config_test_skipped_exe_missing");
    }
    wchar_t line[512];
    _snwprintf(line, sizeof(line) / sizeof(line[0]), L"stage=validate-config ok size=%lld",
               (long long)sz.QuadPart);
    line[(sizeof(line) / sizeof(line[0])) - 1] = 0;
    append_log_utf8(log_path, line);
  }
  return rc;
}

static int stage_install_service(const wchar_t *install_dir, const wchar_t *exe_path, const wchar_t *config_path,
                                 const wchar_t *service_name, const wchar_t *display_name,
                                 const wchar_t *log_path) {
  append_log_utf8(log_path, L"stage=install-service begin");
  if (!file_exists(exe_path)) {
    log_msg(log_path, L"exe_missing path=", exe_path);
    return 30;
  }
  if (!file_exists(config_path)) {
    log_msg(log_path, L"config_missing path=", config_path);
    return 31;
  }
  ensure_runtime_dirs(install_dir, log_path);
  int acl_rc = stage_harden_acl(install_dir, log_path);
  if (acl_rc != 0) return acl_rc;
  set_runtime_env(install_dir, config_path, log_path);
  delete_service_by_name(L"EdrAgent", log_path);

  wchar_t qexe[MAX_PATH * 2], qcfg[MAX_PATH * 2], qsvc[256], bin_path[4096];
  quote_arg(qexe, sizeof(qexe) / sizeof(qexe[0]), exe_path);
  quote_arg(qcfg, sizeof(qcfg) / sizeof(qcfg[0]), config_path);
  quote_arg(qsvc, sizeof(qsvc) / sizeof(qsvc[0]), service_name);
  _snwprintf(bin_path, sizeof(bin_path) / sizeof(bin_path[0]), L"%ls --service --service-name %ls --config %ls",
             qexe, qsvc, qcfg);
  bin_path[(sizeof(bin_path) / sizeof(bin_path[0])) - 1] = 0;

  SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
  if (!scm) {
    log_msg(log_path, L"open_scm_failed service=", service_name);
    return 32;
  }

  SC_HANDLE svc = OpenServiceW(scm, service_name, SERVICE_ALL_ACCESS);
  if (svc) {
    if (!ChangeServiceConfigW(svc, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, bin_path,
                              NULL, NULL, NULL, NULL, NULL, display_name)) {
      DWORD gle = GetLastError();
      wchar_t line[512];
      _snwprintf(line, sizeof(line) / sizeof(line[0]), L"change_service_config_failed gle=%lu", gle);
      line[(sizeof(line) / sizeof(line[0])) - 1] = 0;
      append_log_utf8(log_path, line);
      CloseServiceHandle(svc);
      CloseServiceHandle(scm);
      return 34;
    }
    append_log_utf8(log_path, L"service_existing_reconfigured");
  } else {
    svc = CreateServiceW(scm, service_name, display_name, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
                         SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, bin_path, NULL, NULL, NULL, NULL, NULL);
    if (!svc) {
      DWORD gle = GetLastError();
      wchar_t line[512];
      _snwprintf(line, sizeof(line) / sizeof(line[0]), L"create_service_failed gle=%lu", gle);
      line[(sizeof(line) / sizeof(line[0])) - 1] = 0;
      append_log_utf8(log_path, line);
      CloseServiceHandle(scm);
      return 33;
    }
    append_log_utf8(log_path, L"service_created");
  }

  SERVICE_DESCRIPTIONW desc;
  desc.lpDescription = L"FDSecurity endpoint sensor";
  if (!ChangeServiceConfig2W(svc, SERVICE_CONFIG_DESCRIPTION, &desc)) {
    append_log_utf8(log_path, L"service_description_config_warning");
  }
  SC_ACTION actions[2];
  actions[0].Type = SC_ACTION_RESTART;
  actions[0].Delay = 60000;
  actions[1].Type = SC_ACTION_RESTART;
  actions[1].Delay = 60000;
  SERVICE_FAILURE_ACTIONSW failure;
  ZeroMemory(&failure, sizeof(failure));
  failure.dwResetPeriod = 86400;
  failure.cActions = 2;
  failure.lpsaActions = actions;
  if (!ChangeServiceConfig2W(svc, SERVICE_CONFIG_FAILURE_ACTIONS, &failure)) {
    DWORD gle = GetLastError();
    wchar_t line[512];
    _snwprintf(line, sizeof(line) / sizeof(line[0]), L"service_failure_actions_config_failed gle=%lu", gle);
    line[(sizeof(line) / sizeof(line[0])) - 1] = 0;
    append_log_utf8(log_path, line);
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return 35;
  }

  CloseServiceHandle(svc);
  CloseServiceHandle(scm);
  append_log_utf8(log_path, L"stage=install-service ok");
  return 0;
}

static int stage_install_autorun(const wchar_t *install_dir, const wchar_t *exe_path, const wchar_t *config_path,
                                 const wchar_t *log_path) {
  append_log_utf8(log_path, L"stage=install-autorun begin");
  if (!file_exists(exe_path)) {
    log_msg(log_path, L"exe_missing path=", exe_path);
    return 40;
  }
  if (!file_exists(config_path)) {
    log_msg(log_path, L"config_missing path=", config_path);
    return 41;
  }
  ensure_runtime_dirs(install_dir, log_path);
  int acl_rc = stage_harden_acl(install_dir, log_path);
  if (acl_rc != 0) return acl_rc;
  set_runtime_env(install_dir, config_path, log_path);

  wchar_t script[MAX_PATH * 2], powershell[MAX_PATH * 2], qscript[MAX_PATH * 4], args[8192];
  join_path(script, sizeof(script) / sizeof(script[0]), install_dir, L"edr_windows_autorun.ps1");
  if (!file_exists(script)) {
    log_msg(log_path, L"autorun_script_missing path=", script);
    return 42;
  }
  windows_powershell_path(powershell, sizeof(powershell) / sizeof(powershell[0]));
  quote_arg(qscript, sizeof(qscript) / sizeof(qscript[0]), script);
  _snwprintf(args, sizeof(args) / sizeof(args[0]),
             L"-NoProfile -NonInteractive -ExecutionPolicy Bypass -File %ls -Action Install -NoStart -HardenAcl",
             qscript);
  args[(sizeof(args) / sizeof(args[0])) - 1] = 0;
  int rc = run_process_wait(powershell, args, install_dir, log_path, 120000);
  if (rc != 0) return 43;
  append_log_utf8(log_path, L"stage=install-autorun ok");
  return 0;
}

static int stage_start_autorun(const wchar_t *install_dir, const wchar_t *log_path) {
  append_log_utf8(log_path, L"stage=start-autorun begin");
  if (process_running_by_name(L"FDSensor.exe")) {
    append_log_utf8(log_path, L"stage=start-autorun ok already_running=1");
    return 0;
  }

  wchar_t schtasks[MAX_PATH * 2];
  system_exe_path(schtasks, sizeof(schtasks) / sizeof(schtasks[0]), L"schtasks.exe");
  int rc = run_process_wait(schtasks, L"/Run /TN \"FDSecurityAgent\"", install_dir, log_path, 30000);
  if (rc != 0) {
    append_log_utf8(log_path, L"scheduled_task_start_failed");
    return 44;
  }

  for (int i = 0; i < 60; ++i) {
    Sleep(250);
    if (process_running_by_name(L"FDSensor.exe")) {
      append_log_utf8(log_path, L"stage=start-autorun ok process_running=1");
      return 0;
    }
  }
  (void)run_process_wait(schtasks, L"/Query /TN \"FDSecurityAgent\" /V /FO LIST", install_dir, log_path, 30000);
  append_log_utf8(log_path, L"scheduled_task_started_without_agent_process");
  return 45;
}

static int stage_start_runtime(const wchar_t *install_dir, const wchar_t *exe_path, const wchar_t *config_path,
                               const wchar_t *log_path) {
  append_log_utf8(log_path, L"stage=start-runtime begin");
  if (!file_exists(exe_path)) {
    log_msg(log_path, L"exe_missing path=", exe_path);
    return 20;
  }
  if (!file_exists(config_path)) {
    log_msg(log_path, L"config_missing path=", config_path);
    return 21;
  }
  wchar_t qexe[MAX_PATH * 2], qcfg[MAX_PATH * 2], cmd[MAX_PATH * 5];
  quote_arg(qexe, sizeof(qexe) / sizeof(qexe[0]), exe_path);
  quote_arg(qcfg, sizeof(qcfg) / sizeof(qcfg[0]), config_path);
  _snwprintf(cmd, sizeof(cmd) / sizeof(cmd[0]), L"%ls --config %ls", qexe, qcfg);
  cmd[(sizeof(cmd) / sizeof(cmd[0])) - 1] = 0;
  STARTUPINFOW si;
  PROCESS_INFORMATION pi;
  ZeroMemory(&si, sizeof(si));
  ZeroMemory(&pi, sizeof(pi));
  si.cb = sizeof(si);
  si.dwFlags = STARTF_USESHOWWINDOW;
  si.wShowWindow = SW_HIDE;
  BOOL ok = CreateProcessW(exe_path, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW | BELOW_NORMAL_PRIORITY_CLASS, NULL,
                           install_dir, &si, &pi);
  if (!ok) {
    wchar_t line[512];
    _snwprintf(line, sizeof(line) / sizeof(line[0]), L"create_process_failed gle=%lu", GetLastError());
    line[(sizeof(line) / sizeof(line[0])) - 1] = 0;
    append_log_utf8(log_path, line);
    return 22;
  }
  WaitForSingleObject(pi.hProcess, 4000);
  DWORD exit_code = STILL_ACTIVE;
  GetExitCodeProcess(pi.hProcess, &exit_code);
  wchar_t line[512];
  if (exit_code == STILL_ACTIVE) {
    _snwprintf(line, sizeof(line) / sizeof(line[0]), L"stage=start-runtime ok pid=%lu", pi.dwProcessId);
    append_log_utf8(log_path, line);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
  }
  _snwprintf(line, sizeof(line) / sizeof(line[0]), L"process_exited_early exit_code=%lu", exit_code);
  append_log_utf8(log_path, line);
  CloseHandle(pi.hThread);
  CloseHandle(pi.hProcess);
  return 23;
}

static void run_etw_uninstall_cleanup(const wchar_t *install_dir, const wchar_t *log_path) {
  wchar_t exe[MAX_PATH * 2];
  join_path(exe, sizeof(exe) / sizeof(exe[0]), install_dir, L"FDSensor.exe");
  if (!file_exists(exe)) {
    join_path(exe, sizeof(exe) / sizeof(exe[0]), install_dir, L"edr_agent.exe");
  }
  if (!file_exists(exe)) {
    append_log_utf8(log_path, L"etw_cleanup_skipped exe_missing");
    return;
  }
  append_log_utf8(log_path, L"etw_cleanup_begin");
  run_process_wait(exe, L"--etw-uninstall-cleanup", install_dir, log_path, 30000);
  append_log_utf8(log_path, L"etw_cleanup_done");
}

static void remove_client_certificate_from_store(const wchar_t *install_dir, const wchar_t *log_path,
                                                 const wchar_t *store, const wchar_t *thumbprint) {
  wchar_t tp[160];
  sanitize_thumbprint(thumbprint, tp, sizeof(tp) / sizeof(tp[0]));
  if (!tp[0]) {
    append_log_utf8(log_path, L"client_cert_cleanup_skipped thumbprint_missing");
    return;
  }

  const wchar_t *scope = L"LocalMachine";
  if (store && wcsstr(store, L"CurrentUser")) scope = L"CurrentUser";

  wchar_t line[512];
  _snwprintf(line, sizeof(line) / sizeof(line[0]), L"client_cert_cleanup_begin store=%ls\\My thumbprint=%ls", scope, tp);
  line[(sizeof(line) / sizeof(line[0])) - 1] = 0;
  append_log_utf8(log_path, line);

  wchar_t powershell[MAX_PATH * 2], args[4096];
  system_exe_path(powershell, sizeof(powershell) / sizeof(powershell[0]), L"WindowsPowerShell\\v1.0\\powershell.exe");
  if (!file_exists(powershell)) {
    system_exe_path(powershell, sizeof(powershell) / sizeof(powershell[0]), L"powershell.exe");
  }
  _snwprintf(args, sizeof(args) / sizeof(args[0]),
             L"-NoProfile -ExecutionPolicy Bypass -Command \"try{$tp='%ls';$p='Cert:\\%ls\\My\\'+$tp;if(Test-Path -LiteralPath $p){Remove-Item -LiteralPath $p -DeleteKey -Force -ErrorAction Stop;Write-Host 'client_cert_removed'}else{Write-Host 'client_cert_not_found'}}catch{Write-Host ('client_cert_remove_failed='+$_.Exception.Message)};exit 0\"",
             tp, scope);
  args[(sizeof(args) / sizeof(args[0])) - 1] = 0;
  run_process_wait(powershell, args, install_dir, log_path, 30000);

  wchar_t certutil[MAX_PATH * 2], cert_args[512];
  system_exe_path(certutil, sizeof(certutil) / sizeof(certutil[0]), L"certutil.exe");
  if (file_exists(certutil)) {
    _snwprintf(cert_args, sizeof(cert_args) / sizeof(cert_args[0]), L"%ls-delstore My %ls",
               wcscmp(scope, L"CurrentUser") == 0 ? L"-user " : L"", tp);
    cert_args[(sizeof(cert_args) / sizeof(cert_args[0])) - 1] = 0;
    run_process_wait(certutil, cert_args, install_dir, log_path, 30000);
  }
  append_log_utf8(log_path, L"client_cert_cleanup_done");
}

static int stage_uninstall_runtime(const wchar_t *install_dir, const wchar_t *log_path) {
  append_log_utf8(log_path, L"stage=uninstall-runtime begin");
  wchar_t config_path[MAX_PATH * 2], endpoint_id[256], tenant_id[256], cert_store[256], cert_thumbprint[256];
  join_path(config_path, sizeof(config_path) / sizeof(config_path[0]), install_dir, L"agent.toml");
  endpoint_id[0] = tenant_id[0] = cert_store[0] = cert_thumbprint[0] = 0;
  read_toml_scalar(config_path, "endpoint_id", endpoint_id, sizeof(endpoint_id) / sizeof(endpoint_id[0]));
  read_toml_scalar(config_path, "tenant_id", tenant_id, sizeof(tenant_id) / sizeof(tenant_id[0]));
  read_toml_scalar(config_path, "client_cert_store", cert_store, sizeof(cert_store) / sizeof(cert_store[0]));
  read_toml_scalar(config_path, "client_cert_thumbprint", cert_thumbprint,
                   sizeof(cert_thumbprint) / sizeof(cert_thumbprint[0]));
  wchar_t identity_line[1024];
  _snwprintf(identity_line, sizeof(identity_line) / sizeof(identity_line[0]),
             L"uninstall_identity endpoint_id=%ls tenant_id=%ls client_cert_store=%ls client_cert_thumbprint=%ls",
             endpoint_id[0] ? endpoint_id : L"-", tenant_id[0] ? tenant_id : L"-", cert_store[0] ? cert_store : L"-",
             cert_thumbprint[0] ? cert_thumbprint : L"-");
  identity_line[(sizeof(identity_line) / sizeof(identity_line[0])) - 1] = 0;
  append_log_utf8(log_path, identity_line);

  stop_service_by_name(DEFAULT_SERVICE_NAME, log_path);
  stop_service_by_name(L"EdrAgent", log_path);
  delete_service_by_name(DEFAULT_SERVICE_NAME, log_path);
  delete_service_by_name(L"EdrAgent", log_path);
  run_etw_uninstall_cleanup(install_dir, log_path);
  stop_process_by_name(L"FDSensor.exe", log_path);
  stop_process_by_name(L"edr_agent.exe", log_path);
  wchar_t schtasks[MAX_PATH * 2];
  system_exe_path(schtasks, sizeof(schtasks) / sizeof(schtasks[0]), L"schtasks.exe");
  run_process_wait(schtasks, L"/Delete /F /TN \"FDSecurityAgent\"", install_dir, log_path, 30000);
  run_process_wait(schtasks, L"/Delete /F /TN \"EdrAgent\"", install_dir, log_path, 30000);
  remove_client_certificate_from_store(install_dir, log_path, cert_store, cert_thumbprint);
  clear_runtime_env(log_path);
  append_log_utf8(log_path, L"stage=uninstall-runtime ok");
  return 0;
}

static int stage_write_health_summary(const wchar_t *install_dir, const wchar_t *config_path,
                                      const wchar_t *report_path, const wchar_t *log_path) {
  append_log_utf8(log_path, L"stage=write-health-summary begin");
  if (!report_path || !report_path[0]) {
    append_log_utf8(log_path, L"health_report_missing_path");
    return 50;
  }
  HANDLE existing = CreateFileW(report_path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
                                FILE_ATTRIBUTE_NORMAL, NULL);
  if (existing != INVALID_HANDLE_VALUE) {
    LARGE_INTEGER sz;
    if (GetFileSizeEx(existing, &sz) && sz.QuadPart > 0) {
      CloseHandle(existing);
      append_log_utf8(log_path, L"health_report_exists_keep_existing");
      return 0;
    }
    CloseHandle(existing);
  }
  HANDLE h = CreateFileW(report_path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (h == INVALID_HANDLE_VALUE) {
    append_log_utf8(log_path, L"health_report_create_failed");
    return 51;
  }
  (void)install_dir;
  int cfg = file_exists(config_path);
  int proc = process_running_by_name(L"FDSensor.exe");
  int svc = service_running_by_name(DEFAULT_SERVICE_NAME);
  char json[1024];
  snprintf(json, sizeof(json),
           "{\r\n"
           "  \"created_by\": \"FDSecurityInstallerWorker\",\r\n"
           "  \"status\": \"%s\",\r\n"
           "  \"agent_toml\": %s,\r\n"
           "  \"agent_process_running\": %s,\r\n"
           "  \"service_running\": %s\r\n"
           "}\r\n",
           (cfg && (proc || svc)) ? "ok" : "warning", cfg ? "true" : "false", proc ? "true" : "false",
           svc ? "true" : "false");
  DWORD written = 0;
  WriteFile(h, json, (DWORD)strlen(json), &written, NULL);
  CloseHandle(h);
  append_log_utf8(log_path, L"stage=write-health-summary ok");
  return 0;
}

static void json_escape_wide_utf8(const wchar_t *value, char *out, size_t cap) {
  if (!out || cap == 0) return;
  char utf8[1024];
  utf8[0] = 0;
  if (value && value[0]) {
    WideCharToMultiByte(CP_UTF8, 0, value, -1, utf8, (int)sizeof(utf8), NULL, NULL);
    utf8[sizeof(utf8) - 1] = 0;
  }
  size_t pos = 0;
  for (const unsigned char *p = (const unsigned char *)utf8; *p && pos + 2 < cap; ++p) {
    if (*p == '"' || *p == '\\') out[pos++] = '\\';
    if (*p >= 0x20) out[pos++] = (char)*p;
  }
  out[pos] = 0;
}

static int write_lifecycle_journal(const wchar_t *journal_path, const wchar_t *task_id,
                                   const wchar_t *command_id, const wchar_t *action,
                                   int rc, const char *detail) {
  if (!journal_path || !journal_path[0]) return 0;
  char task[512], command[768], action_utf8[128];
  json_escape_wide_utf8(task_id, task, sizeof(task));
  json_escape_wide_utf8(command_id, command, sizeof(command));
  json_escape_wide_utf8(action, action_utf8, sizeof(action_utf8));
  char json[2048];
  snprintf(json, sizeof(json),
           "{\r\n  \"schema\": \"edr.endpoint.lifecycle.journal.v1\",\r\n"
           "  \"task_id\": \"%s\",\r\n  \"command_id\": \"%s\",\r\n"
           "  \"action\": \"%s\",\r\n  \"status\": \"%s\",\r\n"
           "  \"succeeded\": %s,\r\n  \"exit_code\": %d,\r\n"
           "  \"detail\": \"%s\"\r\n}\r\n",
           task, command, action_utf8, rc == 0 ? "succeeded" : "failed",
           rc == 0 ? "true" : "false", rc, detail ? detail : "lifecycle worker completed");
  wchar_t temporary[MAX_PATH * 2];
  _snwprintf(temporary, sizeof(temporary) / sizeof(temporary[0]), L"%ls.tmp", journal_path);
  temporary[(sizeof(temporary) / sizeof(temporary[0])) - 1] = 0;
  HANDLE h = CreateFileW(temporary, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS,
                         FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, NULL);
  if (h == INVALID_HANDLE_VALUE) return 0;
  DWORD written = 0;
  BOOL ok = WriteFile(h, json, (DWORD)strlen(json), &written, NULL) &&
            written == (DWORD)strlen(json) && FlushFileBuffers(h);
  CloseHandle(h);
  if (!ok || !MoveFileExW(temporary, journal_path,
                          MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
    DeleteFileW(temporary);
    return 0;
  }
  return 1;
}

static int stage_lifecycle_restart(const wchar_t *service_name, const wchar_t *journal_path,
                                   const wchar_t *task_id, const wchar_t *command_id,
                                   const wchar_t *action, DWORD delay_ms,
                                   const wchar_t *log_path) {
  append_log_utf8(log_path, L"stage=lifecycle-restart begin");
  if (delay_ms > 30000) delay_ms = 30000;
  Sleep(delay_ms);
  int stopped = stop_service_by_name(service_name, log_path);
  int rc = stopped ? start_service_by_name(service_name, log_path) : 6;
  const char *detail = rc == 0 ? "Agent service restarted and process is running" :
                                 "Agent service restart failed health verification";
  if (!write_lifecycle_journal(journal_path, task_id, command_id, action, rc, detail)) {
    append_log_utf8(log_path, L"lifecycle_journal_write_failed");
    return rc == 0 ? 7 : rc;
  }
  append_log_utf8(log_path, rc == 0 ? L"stage=lifecycle-restart ok" :
                                      L"stage=lifecycle-restart failed");
  return rc;
}

static int launch_uninstaller_detached(const wchar_t *install_dir, const wchar_t *service_name,
                                       int keep_data, const wchar_t *attestation_url,
                                       const wchar_t *attestation_token, const wchar_t *task_id,
                                       const wchar_t *endpoint_id, const wchar_t *log_path) {
  wchar_t uninstaller[MAX_PATH * 2], quoted_exe[MAX_PATH * 4], quoted_dir[MAX_PATH * 4];
  wchar_t quoted_service[MAX_PATH * 2], quoted_url[4096], quoted_token[1024];
  wchar_t quoted_task[1024], quoted_endpoint[1024];
  join_path(uninstaller, sizeof(uninstaller) / sizeof(uninstaller[0]), install_dir, L"uninstall.exe");
  if (!file_exists(uninstaller)) {
    append_log_utf8(log_path, L"lifecycle_uninstall_missing_uninstall_exe");
    return 8;
  }
  quote_arg(quoted_exe, sizeof(quoted_exe) / sizeof(quoted_exe[0]), uninstaller);
  quote_arg(quoted_dir, sizeof(quoted_dir) / sizeof(quoted_dir[0]), install_dir);
  quote_arg(quoted_service, sizeof(quoted_service) / sizeof(quoted_service[0]), service_name);
  quote_arg(quoted_url, sizeof(quoted_url) / sizeof(quoted_url[0]), attestation_url);
  quote_arg(quoted_token, sizeof(quoted_token) / sizeof(quoted_token[0]), attestation_token);
  quote_arg(quoted_task, sizeof(quoted_task) / sizeof(quoted_task[0]), task_id);
  quote_arg(quoted_endpoint, sizeof(quoted_endpoint) / sizeof(quoted_endpoint[0]), endpoint_id);
  wchar_t command[8192];
  _snwprintf(command, sizeof(command) / sizeof(command[0]),
             L"%ls --silent --install-dir %ls --service-name %ls%ls "
             L"--attestation-url %ls --attestation-token %ls --task-id %ls --endpoint-id %ls",
             quoted_exe, quoted_dir, quoted_service, keep_data ? L" --keep-data" : L"",
             quoted_url, quoted_token, quoted_task, quoted_endpoint);
  command[(sizeof(command) / sizeof(command[0])) - 1] = 0;
  STARTUPINFOW startup;
  PROCESS_INFORMATION process;
  ZeroMemory(&startup, sizeof(startup));
  ZeroMemory(&process, sizeof(process));
  startup.cb = sizeof(startup);
  startup.dwFlags = STARTF_USESHOWWINDOW;
  startup.wShowWindow = SW_HIDE;
  if (!CreateProcessW(NULL, command, NULL, NULL, FALSE,
                      CREATE_NO_WINDOW | DETACHED_PROCESS, NULL, install_dir,
                      &startup, &process)) {
    append_log_utf8(log_path, L"lifecycle_uninstall_launch_failed");
    return 9;
  }
  CloseHandle(process.hThread);
  append_log_utf8(log_path, L"lifecycle_uninstall_launched");
  DWORD wait_result = WaitForSingleObject(process.hProcess, 300000);
  if (wait_result == WAIT_TIMEOUT) {
    append_log_utf8(log_path, L"lifecycle_uninstall_completion_timeout");
    CloseHandle(process.hProcess);
    return 10;
  }
  if (wait_result != WAIT_OBJECT_0) {
    append_log_utf8(log_path, L"lifecycle_uninstall_wait_failed");
    CloseHandle(process.hProcess);
    return 11;
  }
  DWORD exit_code = ERROR_GEN_FAILURE;
  if (!GetExitCodeProcess(process.hProcess, &exit_code)) {
    append_log_utf8(log_path, L"lifecycle_uninstall_exit_code_unavailable");
    CloseHandle(process.hProcess);
    return 12;
  }
  CloseHandle(process.hProcess);
  if (exit_code != 0) {
    wchar_t line[256];
    _snwprintf(line, sizeof(line) / sizeof(line[0]),
               L"lifecycle_uninstall_failed exit_code=%lu", (unsigned long)exit_code);
    line[(sizeof(line) / sizeof(line[0])) - 1] = 0;
    append_log_utf8(log_path, line);
    return (int)exit_code;
  }
  append_log_utf8(log_path, L"lifecycle_uninstall_completed");
  return 0;
}

static int stage_lifecycle_teardown(const wchar_t *install_dir, const wchar_t *service_name,
                                    const wchar_t *journal_path, const wchar_t *task_id,
                                    const wchar_t *command_id, const wchar_t *action,
                                    DWORD delay_ms, int keep_data, const wchar_t *attestation_url,
                                    const wchar_t *attestation_token, const wchar_t *endpoint_id,
                                    const wchar_t *log_path) {
  append_log_utf8(log_path, L"stage=lifecycle-teardown begin");
  if (delay_ms < 5000) delay_ms = 5000;
  if (delay_ms > 120000) delay_ms = 120000;
  Sleep(delay_ms);
  int rc = 64;
  const char *detail = "unsupported lifecycle teardown action";
  if (_wcsicmp(action, L"offboard") == 0) {
    rc = stop_service_by_name(service_name, log_path) ? 0 : 6;
    detail = rc == 0 ? "Agent service stopped after offboard handoff" :
                       "Agent offboard service stop failed";
  } else if (_wcsicmp(action, L"uninstall") == 0) {
    rc = launch_uninstaller_detached(install_dir, service_name, keep_data, attestation_url,
                                     attestation_token, task_id, endpoint_id, log_path);
    detail = rc == 0 ? "Native uninstaller completed after command-result handoff" :
                       "Native uninstaller failed after command-result handoff";
  }
  if (!write_lifecycle_journal(journal_path, task_id, command_id, action, rc, detail)) {
    append_log_utf8(log_path, L"lifecycle_teardown_journal_write_failed");
    return rc == 0 ? 7 : rc;
  }
  append_log_utf8(log_path, rc == 0 ? L"stage=lifecycle-teardown accepted" :
                                      L"stage=lifecycle-teardown failed");
  return rc;
}

static void usage(void) {
  fwprintf(stderr,
           L"FDSecurityInstallerWorker --stage <stop-runtime|clean-cache|validate-config|harden-acl|install-service|install-autorun|start-autorun|start-runtime|start-service|lifecycle-restart|lifecycle-offboard|lifecycle-uninstall|uninstall-runtime|write-health-summary> "
           L"[--install-dir <dir>] [--config <path>] [--exe <path>] [--log <path>] [--report <path>]\n");
}

int main(void) {
  int argc = 0;
  wchar_t **argv = CommandLineToArgvW(GetCommandLineW(), &argc);
  if (!argv) return 99;
  const wchar_t *stage = arg_value(argc, argv, L"--stage");
  const wchar_t *install_dir = arg_value(argc, argv, L"--install-dir");
  const wchar_t *log_path = arg_value(argc, argv, L"--log");
  const wchar_t *report_path = arg_value(argc, argv, L"--report");
  const wchar_t *journal_path = arg_value(argc, argv, L"--journal");
  const wchar_t *task_id = arg_value(argc, argv, L"--task-id");
  const wchar_t *command_id = arg_value(argc, argv, L"--command-id");
  const wchar_t *action = arg_value(argc, argv, L"--action");
  const wchar_t *delay_raw = arg_value(argc, argv, L"--delay-ms");
  const wchar_t *attestation_url = arg_value(argc, argv, L"--attestation-url");
  const wchar_t *attestation_token = arg_value(argc, argv, L"--attestation-token");
  const wchar_t *endpoint_id = arg_value(argc, argv, L"--endpoint-id");
  wchar_t default_log[MAX_PATH * 2], default_cfg[MAX_PATH * 2], default_exe[MAX_PATH * 2];
  join_path(default_log, sizeof(default_log) / sizeof(default_log[0]), install_dir, L"diagnostics\\installer-worker.log");
  join_path(default_cfg, sizeof(default_cfg) / sizeof(default_cfg[0]), install_dir, L"agent.toml");
  join_path(default_exe, sizeof(default_exe) / sizeof(default_exe[0]), install_dir, L"FDSensor.exe");
  if (!install_dir || !install_dir[0]) install_dir = DEFAULT_INSTALL_DIR;
  if (!log_path || !log_path[0]) log_path = default_log;
  const wchar_t *config_path = arg_value(argc, argv, L"--config");
  const wchar_t *exe_path = arg_value(argc, argv, L"--exe");
  if (!config_path || !config_path[0]) config_path = default_cfg;
  if (!exe_path || !exe_path[0]) exe_path = default_exe;
  const wchar_t *svc = arg_value(argc, argv, L"--service-name");
  if (!svc || !svc[0]) svc = DEFAULT_SERVICE_NAME;
  const wchar_t *display = arg_value(argc, argv, L"--display-name");
  if (!display || !display[0]) display = L"FDSecurity Endpoint Agent";

  int rc = 64;
  if (!stage || !stage[0]) {
    usage();
    rc = 64;
  } else if (_wcsicmp(stage, L"stop-runtime") == 0) {
    rc = stage_stop_runtime(install_dir, log_path);
  } else if (_wcsicmp(stage, L"clean-cache") == 0) {
    rc = stage_clean_cache(install_dir, log_path, report_path, has_flag(argc, argv, L"--keep-offline-queue"),
                           has_flag(argc, argv, L"--keep-evidence-cache"));
  } else if (_wcsicmp(stage, L"validate-config") == 0) {
    rc = stage_validate_config(install_dir, exe_path, config_path, log_path);
  } else if (_wcsicmp(stage, L"harden-acl") == 0) {
    rc = stage_harden_acl(install_dir, log_path);
  } else if (_wcsicmp(stage, L"install-service") == 0) {
    rc = stage_install_service(install_dir, exe_path, config_path, svc, display, log_path);
  } else if (_wcsicmp(stage, L"install-autorun") == 0) {
    rc = stage_install_autorun(install_dir, exe_path, config_path, log_path);
  } else if (_wcsicmp(stage, L"start-autorun") == 0) {
    rc = stage_start_autorun(install_dir, log_path);
  } else if (_wcsicmp(stage, L"start-runtime") == 0) {
    rc = stage_start_runtime(install_dir, exe_path, config_path, log_path);
  } else if (_wcsicmp(stage, L"start-service") == 0) {
    rc = start_service_by_name(svc, log_path);
  } else if (_wcsicmp(stage, L"lifecycle-restart") == 0) {
    DWORD delay_ms = delay_raw && delay_raw[0] ? (DWORD)_wtoi(delay_raw) : 2000;
    if (!journal_path[0] || !task_id[0] || !command_id[0] ||
        _wcsicmp(action, L"restart") != 0) {
      append_log_utf8(log_path, L"lifecycle_restart_invalid_arguments");
      rc = 64;
    } else {
      rc = stage_lifecycle_restart(svc, journal_path, task_id, command_id, action,
                                   delay_ms, log_path);
    }
  } else if (_wcsicmp(stage, L"lifecycle-offboard") == 0 ||
             _wcsicmp(stage, L"lifecycle-uninstall") == 0) {
    DWORD delay_ms = delay_raw && delay_raw[0] ? (DWORD)_wtoi(delay_raw) : 30000;
    const wchar_t *expected_action = _wcsicmp(stage, L"lifecycle-offboard") == 0
                                         ? L"offboard" : L"uninstall";
    if (!journal_path[0] || !task_id[0] || !command_id[0] ||
        _wcsicmp(action, expected_action) != 0 ||
        (_wcsicmp(expected_action, L"uninstall") == 0 &&
         (!attestation_url[0] || !attestation_token[0] || !endpoint_id[0]))) {
      append_log_utf8(log_path, L"lifecycle_teardown_invalid_arguments");
      rc = 64;
    } else {
      rc = stage_lifecycle_teardown(install_dir, svc, journal_path, task_id, command_id,
                                    action, delay_ms, has_flag(argc, argv, L"--keep-data"),
                                    attestation_url, attestation_token, endpoint_id, log_path);
    }
  } else if (_wcsicmp(stage, L"uninstall-runtime") == 0) {
    rc = stage_uninstall_runtime(install_dir, log_path);
  } else if (_wcsicmp(stage, L"write-health-summary") == 0) {
    rc = stage_write_health_summary(install_dir, config_path, report_path, log_path);
  } else {
    usage();
    rc = 64;
  }
  LocalFree(argv);
  return rc;
}
