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
                                       DWORD parent_pid, int keep_data) {
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
  size_t used = 0;
  STARTUPINFOW startup;
  PROCESS_INFORMATION process;
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
  if (!CreateProcessW(powershell_path, command, NULL, NULL, FALSE,
                      silent ? CREATE_NO_WINDOW : 0, NULL, install_dir, &startup, &process)) {
    return (int)GetLastError();
  }
  CloseHandle(process.hThread);
  return wait_for_process(process.hProcess);
}

static int run_uninstall_script(const wchar_t *script, const wchar_t *install_dir,
                                const wchar_t *service_name, int silent, int keep_data) {
  wchar_t parameters[32768];
  wchar_t system_dir[MAX_PATH * 2];
  wchar_t powershell_path[MAX_PATH * 4];
  SHELLEXECUTEINFOW exec_info;
  if (!build_powershell_parameters(parameters, sizeof(parameters) / sizeof(parameters[0]), script,
                                   install_dir, service_name, GetCurrentProcessId(), keep_data)) {
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
  return wait_for_process(exec_info.hProcess);
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
  int silent;
  int keep_data;
  int rc;
  (void)instance;
  (void)previous;
  (void)command_line;
  (void)show_command;

  argv = CommandLineToArgvW(GetCommandLineW(), &argc);
  if (!argv) return (int)GetLastError();
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

  rc = run_uninstall_script(script_path, install_dir, service_name, silent, keep_data);
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
