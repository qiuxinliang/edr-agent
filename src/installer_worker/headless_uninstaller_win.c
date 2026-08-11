#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <shellapi.h>
#include <stdio.h>
#include <wchar.h>

#define EDR_UNINSTALL_TITLE L"FDSecurity Agent Uninstaller"
#define EDR_UNINSTALL_SCRIPT L"uninstall.ps1"
static const char *HEADLESS_UNINSTALLER_CAPABILITIES =
    "{\"schema\":\"edr.windows.native-capabilities.v1\","
    "\"component\":\"headless-uninstaller\","
    "\"uninstall_attestation\":\"v2\","
    "\"powershell_token_handoff\":true}";

static int has_flag(int argc, wchar_t **argv, const wchar_t *flag) {
  int i;
  for (i = 1; i < argc; ++i) {
    if (_wcsicmp(argv[i], flag) == 0) return 1;
  }
  return 0;
}

static const wchar_t *arg_value(int argc, wchar_t **argv, const wchar_t *name) {
  size_t name_len = wcslen(name);
  int i;
  for (i = 1; i < argc; ++i) {
    if (_wcsicmp(argv[i], name) == 0 && i + 1 < argc) return argv[i + 1];
    if (_wcsnicmp(argv[i], name, name_len) == 0 && argv[i][name_len] == L'=') {
      return argv[i] + name_len + 1;
    }
  }
  return NULL;
}

static int write_capability_probe(const wchar_t *path, const char *payload) {
  HANDLE file;
  DWORD written = 0;
  size_t length;
  if (!path || !path[0] || !payload) return 0;
  file = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS,
                     FILE_ATTRIBUTE_NORMAL, NULL);
  if (file == INVALID_HANDLE_VALUE) return 0;
  length = strlen(payload);
  if (!WriteFile(file, payload, (DWORD)length, &written, NULL) || written != (DWORD)length) {
    CloseHandle(file);
    return 0;
  }
  CloseHandle(file);
  return 1;
}

static int file_exists(const wchar_t *path) {
  DWORD attrs = GetFileAttributesW(path);
  return attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY);
}

static int get_executable_directory(wchar_t *out, size_t out_count) {
  DWORD n;
  wchar_t *slash;
  if (!out || out_count < 2) return 0;
  n = GetModuleFileNameW(NULL, out, (DWORD)out_count);
  if (n == 0 || n >= out_count) return 0;
  slash = wcsrchr(out, L'\\');
  if (!slash) return 0;
  *slash = L'\0';
  return 1;
}

static int join_path(wchar_t *out, size_t out_count, const wchar_t *dir, const wchar_t *name) {
  int written;
  size_t len;
  if (!out || !dir || !name || out_count < 2) return 0;
  len = wcslen(dir);
  written = _snwprintf(out, out_count, len > 0 && (dir[len - 1] == L'\\' || dir[len - 1] == L'/')
                                              ? L"%ls%ls"
                                              : L"%ls\\%ls",
                       dir, name);
  if (written < 0 || (size_t)written >= out_count) {
    out[out_count - 1] = L'\0';
    return 0;
  }
  return 1;
}

static int ensure_directory(const wchar_t *path) {
  if (CreateDirectoryW(path, NULL)) return 1;
  return GetLastError() == ERROR_ALREADY_EXISTS;
}

static int get_powershell_log_path(wchar_t *out, size_t out_count) {
  wchar_t program_data[MAX_PATH * 2];
  wchar_t vendor_dir[MAX_PATH * 3];
  wchar_t state_dir[MAX_PATH * 3];
  DWORD n = GetEnvironmentVariableW(L"ProgramData", program_data,
                                    (DWORD)(sizeof(program_data) / sizeof(program_data[0])));
  if (n == 0 || n >= sizeof(program_data) / sizeof(program_data[0])) return 0;
  if (!join_path(vendor_dir, sizeof(vendor_dir) / sizeof(vendor_dir[0]),
                 program_data, L"FDSecurity") ||
      !ensure_directory(vendor_dir) ||
      !join_path(state_dir, sizeof(state_dir) / sizeof(state_dir[0]),
                 vendor_dir, L"state") ||
      !ensure_directory(state_dir)) {
    return 0;
  }
  return join_path(out, out_count, state_dir, L"uninstall-powershell-last.log");
}

static void append_utf8_line(const wchar_t *path, const wchar_t *line) {
  HANDLE file;
  int size;
  char *utf8;
  DWORD written = 0;
  if (!path || !path[0] || !line) return;
  file = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                     NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (file == INVALID_HANDLE_VALUE) return;
  size = WideCharToMultiByte(CP_UTF8, 0, line, -1, NULL, 0, NULL, NULL);
  if (size > 1) {
    utf8 = (char *)HeapAlloc(GetProcessHeap(), 0, (SIZE_T)size + 2);
    if (utf8) {
      WideCharToMultiByte(CP_UTF8, 0, line, -1, utf8, size, NULL, NULL);
      utf8[size - 1] = '\r';
      utf8[size] = '\n';
      WriteFile(file, utf8, (DWORD)size + 1, &written, NULL);
      HeapFree(GetProcessHeap(), 0, utf8);
    }
  }
  CloseHandle(file);
}

static int append_text(wchar_t *out, size_t out_count, size_t *used, const wchar_t *text) {
  size_t n;
  if (!out || !used || !text) return 0;
  n = wcslen(text);
  if (*used + n + 1 > out_count) return 0;
  memcpy(out + *used, text, n * sizeof(wchar_t));
  *used += n;
  out[*used] = L'\0';
  return 1;
}

/* Quote one argument using the CommandLineToArgvW escaping rules. */
static int append_quoted_arg(wchar_t *out, size_t out_count, size_t *used, const wchar_t *arg) {
  size_t backslashes = 0;
  const wchar_t *p;
  if (!append_text(out, out_count, used, L"\"")) return 0;
  for (p = arg; ; ++p) {
    if (*p == L'\\') {
      ++backslashes;
      continue;
    }
    if (*p == L'\"') {
      while (backslashes > 0) {
        if (!append_text(out, out_count, used, L"\\\\")) return 0;
        --backslashes;
      }
      if (!append_text(out, out_count, used, L"\\\"")) return 0;
      continue;
    }
    if (*p == L'\0') {
      while (backslashes > 0) {
        if (!append_text(out, out_count, used, L"\\\\")) return 0;
        --backslashes;
      }
      break;
    }
    while (backslashes > 0) {
      if (!append_text(out, out_count, used, L"\\")) return 0;
      --backslashes;
    }
    {
      wchar_t one[2] = {*p, L'\0'};
      if (!append_text(out, out_count, used, one)) return 0;
    }
  }
  return append_text(out, out_count, used, L"\"");
}

static int build_powershell_parameters(wchar_t *out, size_t out_count, const wchar_t *script,
                                       const wchar_t *install_dir, const wchar_t *service_name,
                                       DWORD parent_pid, int keep_data,
                                       const wchar_t *attestation_url,
                                       const wchar_t *attestation_token,
                                       const wchar_t *task_id,
                                       const wchar_t *endpoint_id) {
  size_t used = 0;
  wchar_t pid_text[32];
  out[0] = L'\0';
  _snwprintf(pid_text, sizeof(pid_text) / sizeof(pid_text[0]), L"%lu", (unsigned long)parent_pid);
  if (!append_text(out, out_count, &used, L"-NoProfile -NonInteractive -ExecutionPolicy Bypass -File ")) return 0;
  if (!append_quoted_arg(out, out_count, &used, script)) return 0;
  if (!append_text(out, out_count, &used, L" -InstallDir ")) return 0;
  if (!append_quoted_arg(out, out_count, &used, install_dir)) return 0;
  if (!append_text(out, out_count, &used, L" -ParentProcessId ")) return 0;
  if (!append_text(out, out_count, &used, pid_text)) return 0;
  if (service_name && service_name[0]) {
    if (!append_text(out, out_count, &used, L" -ServiceName ")) return 0;
    if (!append_quoted_arg(out, out_count, &used, service_name)) return 0;
  }
  if (attestation_url && attestation_url[0] && attestation_token && attestation_token[0] &&
      task_id && task_id[0] && endpoint_id && endpoint_id[0]) {
    if (!append_text(out, out_count, &used, L" -AttestationURL ") ||
        !append_quoted_arg(out, out_count, &used, attestation_url) ||
        !append_text(out, out_count, &used, L" -AttestationToken ") ||
        !append_quoted_arg(out, out_count, &used, attestation_token) ||
        !append_text(out, out_count, &used, L" -LifecycleTaskID ") ||
        !append_quoted_arg(out, out_count, &used, task_id) ||
        !append_text(out, out_count, &used, L" -EndpointID ") ||
        !append_quoted_arg(out, out_count, &used, endpoint_id)) {
      return 0;
    }
  }
  if (keep_data) {
    if (!append_text(out, out_count, &used, L" -PreserveDiagnostics -RemoveProgramFiles")) return 0;
  } else if (!append_text(out, out_count, &used, L" -RemoveData -RemoveProgramFiles")) {
    return 0;
  }
  return 1;
}

static int current_process_is_elevated(void) {
  HANDLE token = NULL;
  TOKEN_ELEVATION elevation;
  DWORD returned = 0;
  int elevated = 0;
  if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
    if (GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &returned)) {
      elevated = elevation.TokenIsElevated != 0;
    }
    CloseHandle(token);
  }
  return elevated;
}

static int wait_for_process(HANDLE process) {
  DWORD exit_code = ERROR_GEN_FAILURE;
  if (!process) return ERROR_INVALID_HANDLE;
  if (WaitForSingleObject(process, INFINITE) != WAIT_OBJECT_0) {
    exit_code = GetLastError();
  } else if (!GetExitCodeProcess(process, &exit_code)) {
    exit_code = GetLastError();
  }
  CloseHandle(process);
  return (int)exit_code;
}

static int run_powershell_direct(const wchar_t *powershell_path, const wchar_t *parameters,
                                 const wchar_t *install_dir, int silent) {
  wchar_t command[32768];
  wchar_t diagnostic_path[MAX_PATH * 4];
  size_t used = 0;
  STARTUPINFOW startup;
  PROCESS_INFORMATION process;
  SECURITY_ATTRIBUTES security;
  HANDLE diagnostic = INVALID_HANDLE_VALUE;
  HANDLE input = INVALID_HANDLE_VALUE;
  BOOL inherit_handles = FALSE;
  if (!append_quoted_arg(command, sizeof(command) / sizeof(command[0]), &used,
                         powershell_path) ||
      !append_text(command, sizeof(command) / sizeof(command[0]), &used, L" ") ||
      !append_text(command, sizeof(command) / sizeof(command[0]), &used, parameters)) {
    return ERROR_INSUFFICIENT_BUFFER;
  }
  ZeroMemory(&startup, sizeof(startup));
  ZeroMemory(&process, sizeof(process));
  startup.cb = sizeof(startup);
  startup.dwFlags = STARTF_USESHOWWINDOW;
  startup.wShowWindow = silent ? SW_HIDE : SW_SHOWNORMAL;
  diagnostic_path[0] = L'\0';
  if (get_powershell_log_path(diagnostic_path,
                              sizeof(diagnostic_path) / sizeof(diagnostic_path[0]))) {
    DeleteFileW(diagnostic_path);
    append_utf8_line(diagnostic_path, L"uninstall_powershell_launch mode=direct elevated=true");
    ZeroMemory(&security, sizeof(security));
    security.nLength = sizeof(security);
    security.bInheritHandle = TRUE;
    diagnostic = CreateFileW(diagnostic_path, FILE_APPEND_DATA,
                             FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                             &security, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (diagnostic != INVALID_HANDLE_VALUE) {
      input = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                          &security, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
      if (input != INVALID_HANDLE_VALUE) {
        startup.dwFlags |= STARTF_USESTDHANDLES;
        startup.hStdInput = input;
        startup.hStdOutput = diagnostic;
        startup.hStdError = diagnostic;
        inherit_handles = TRUE;
      }
    }
  }
  if (!CreateProcessW(powershell_path, command, NULL, NULL, inherit_handles,
                      silent ? CREATE_NO_WINDOW : 0, NULL, install_dir, &startup, &process)) {
    int error = (int)GetLastError();
    if (input != INVALID_HANDLE_VALUE) CloseHandle(input);
    if (diagnostic != INVALID_HANDLE_VALUE) CloseHandle(diagnostic);
    return error;
  }
  if (input != INVALID_HANDLE_VALUE) CloseHandle(input);
  if (diagnostic != INVALID_HANDLE_VALUE) CloseHandle(diagnostic);
  CloseHandle(process.hThread);
  {
    int rc = wait_for_process(process.hProcess);
    wchar_t result[128];
    _snwprintf(result, sizeof(result) / sizeof(result[0]),
               L"uninstall_powershell_exit_code=%d", rc);
    result[(sizeof(result) / sizeof(result[0])) - 1] = L'\0';
    append_utf8_line(diagnostic_path, result);
    return rc;
  }
}

static int run_uninstall_script(const wchar_t *script, const wchar_t *install_dir,
                                const wchar_t *service_name, int silent, int keep_data,
                                const wchar_t *attestation_url,
                                const wchar_t *attestation_token,
                                const wchar_t *task_id,
                                const wchar_t *endpoint_id) {
  wchar_t parameters[32768];
  wchar_t system_dir[MAX_PATH * 2];
  wchar_t powershell_path[MAX_PATH * 4];
  wchar_t diagnostic_path[MAX_PATH * 4];
  SHELLEXECUTEINFOW exec_info;
  if (!build_powershell_parameters(parameters, sizeof(parameters) / sizeof(parameters[0]), script,
                                   install_dir, service_name, GetCurrentProcessId(), keep_data,
                                   attestation_url, attestation_token, task_id, endpoint_id)) {
    return ERROR_INSUFFICIENT_BUFFER;
  }
  if (GetSystemDirectoryW(system_dir, (UINT)(sizeof(system_dir) / sizeof(system_dir[0]))) == 0 ||
      !join_path(powershell_path, sizeof(powershell_path) / sizeof(powershell_path[0]), system_dir,
                 L"WindowsPowerShell\\v1.0\\powershell.exe") ||
      !file_exists(powershell_path)) {
    return ERROR_FILE_NOT_FOUND;
  }

  /* A lifecycle worker runs as LocalSystem in session 0. Asking ShellExecute
   * for the interactive `runas` verb there can never complete a UAC consent
   * flow. An already elevated process must preserve its token and launch
   * PowerShell directly; only a manual, non-elevated invocation needs UAC. */
  if (current_process_is_elevated()) {
    return run_powershell_direct(powershell_path, parameters, install_dir, silent);
  }

  diagnostic_path[0] = L'\0';
  if (get_powershell_log_path(diagnostic_path,
                              sizeof(diagnostic_path) / sizeof(diagnostic_path[0]))) {
    DeleteFileW(diagnostic_path);
    append_utf8_line(diagnostic_path,
                     L"uninstall_powershell_launch mode=runas elevated=false");
  }

  ZeroMemory(&exec_info, sizeof(exec_info));
  exec_info.cbSize = sizeof(exec_info);
  exec_info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
  if (silent) exec_info.fMask |= SEE_MASK_FLAG_NO_UI;
  exec_info.lpVerb = L"runas";
  exec_info.lpFile = powershell_path;
  exec_info.lpParameters = parameters;
  exec_info.lpDirectory = install_dir;
  exec_info.nShow = silent ? SW_HIDE : SW_SHOWNORMAL;
  if (!ShellExecuteExW(&exec_info)) return (int)GetLastError();
  if (!exec_info.hProcess) return ERROR_INVALID_HANDLE;
  {
    int rc = wait_for_process(exec_info.hProcess);
    wchar_t result[128];
    _snwprintf(result, sizeof(result) / sizeof(result[0]),
               L"uninstall_powershell_exit_code=%d", rc);
    result[(sizeof(result) / sizeof(result[0])) - 1] = L'\0';
    append_utf8_line(diagnostic_path, result);
    return rc;
  }
}

static void show_error(int silent, const wchar_t *message, DWORD code) {
  wchar_t detail[1024];
  if (silent) return;
  _snwprintf(detail, sizeof(detail) / sizeof(detail[0]), L"%ls\n\n错误代码: %lu", message,
             (unsigned long)code);
  MessageBoxW(NULL, detail, EDR_UNINSTALL_TITLE, MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
}

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE previous, PWSTR command_line, int show_command) {
  int argc = 0;
  wchar_t **argv = NULL;
  wchar_t exe_dir[MAX_PATH * 4];
  wchar_t install_dir[MAX_PATH * 4];
  wchar_t script_path[MAX_PATH * 4];
  const wchar_t *requested_dir;
  const wchar_t *service_name;
  const wchar_t *attestation_url;
  const wchar_t *attestation_token;
  const wchar_t *task_id;
  const wchar_t *endpoint_id;
  int silent;
  int keep_data;
  int rc;
  (void)instance;
  (void)previous;
  (void)command_line;
  (void)show_command;

  argv = CommandLineToArgvW(GetCommandLineW(), &argc);
  if (!argv) return (int)GetLastError();
  {
    const wchar_t *capability_probe = arg_value(argc, argv, L"--capability-probe");
    if (capability_probe && capability_probe[0]) {
      int probe_ok = write_capability_probe(capability_probe, HEADLESS_UNINSTALLER_CAPABILITIES);
      LocalFree(argv);
      return probe_ok ? 0 : ERROR_WRITE_FAULT;
    }
  }
  silent = has_flag(argc, argv, L"/S") || has_flag(argc, argv, L"/SILENT") ||
           has_flag(argc, argv, L"/VERYSILENT") || has_flag(argc, argv, L"--silent");
  keep_data = has_flag(argc, argv, L"/KEEPDATA") || has_flag(argc, argv, L"--keep-data");

  if (!get_executable_directory(exe_dir, sizeof(exe_dir) / sizeof(exe_dir[0]))) {
    show_error(silent, L"无法确定卸载程序所在目录。", GetLastError());
    LocalFree(argv);
    return ERROR_PATH_NOT_FOUND;
  }
  requested_dir = arg_value(argc, argv, L"/INSTALLDIR");
  if (!requested_dir) requested_dir = arg_value(argc, argv, L"--install-dir");
  service_name = arg_value(argc, argv, L"/SERVICENAME");
  if (!service_name) service_name = arg_value(argc, argv, L"--service-name");
  attestation_url = arg_value(argc, argv, L"--attestation-url");
  attestation_token = arg_value(argc, argv, L"--attestation-token");
  task_id = arg_value(argc, argv, L"--task-id");
  endpoint_id = arg_value(argc, argv, L"--endpoint-id");
  _snwprintf(install_dir, sizeof(install_dir) / sizeof(install_dir[0]), L"%ls",
             requested_dir && requested_dir[0] ? requested_dir : exe_dir);
  if (!join_path(script_path, sizeof(script_path) / sizeof(script_path[0]), install_dir,
                 EDR_UNINSTALL_SCRIPT) || !file_exists(script_path)) {
    show_error(silent, L"未找到 uninstall.ps1，无法执行完整卸载。", ERROR_FILE_NOT_FOUND);
    LocalFree(argv);
    return ERROR_FILE_NOT_FOUND;
  }

  if (!silent) {
    const wchar_t *prompt = keep_data
                                ? L"将完整卸载 FDSecurity Agent，并将日志和诊断数据归档到 ProgramData。是否继续？"
                                : L"将完整卸载 FDSecurity Agent，并删除配置、证书、队列、日志和程序文件。是否继续？";
    if (MessageBoxW(NULL, prompt, EDR_UNINSTALL_TITLE,
                    MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2 | MB_SETFOREGROUND) != IDYES) {
      LocalFree(argv);
      return ERROR_CANCELLED;
    }
  }

  rc = run_uninstall_script(script_path, install_dir, service_name, silent, keep_data,
                            attestation_url, attestation_token, task_id, endpoint_id);
  if (rc == 0) {
    if (!silent) {
      MessageBoxW(NULL,
                  keep_data ? L"FDSecurity Agent 已卸载，日志和诊断数据已归档到 ProgramData。"
                            : L"FDSecurity Agent 已卸载。程序目录将在本窗口关闭后清理。",
                  EDR_UNINSTALL_TITLE, MB_OK | MB_ICONINFORMATION | MB_SETFOREGROUND);
    }
  } else if (rc == ERROR_CANCELLED) {
    show_error(silent, L"管理员授权已取消，未执行卸载。", (DWORD)rc);
  } else {
    show_error(silent, L"卸载执行失败，请检查管理员权限，或以管理员 PowerShell 运行 uninstall.ps1。", (DWORD)rc);
  }
  LocalFree(argv);
  return rc;
}
