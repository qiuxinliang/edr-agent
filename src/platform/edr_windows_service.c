#include "edr/agent_main.h"
#include "edr/windows_service.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <windows.h>
#include <winsvc.h>

static SERVICE_STATUS_HANDLE g_status_handle;
static SERVICE_STATUS g_status;
static char g_table_service_name[256];

static void edr_svc_report_state(DWORD state, DWORD win32_exit, DWORD wait_hint) {
  if (!g_status_handle) {
    return;
  }
  g_status.dwCurrentState = state;
  g_status.dwWin32ExitCode = win32_exit;
  g_status.dwWaitHint = wait_hint;
  if (state == SERVICE_START_PENDING) {
    g_status.dwControlsAccepted = 0;
  } else if (state == SERVICE_RUNNING) {
    g_status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
  } else if (state == SERVICE_STOP_PENDING) {
    g_status.dwControlsAccepted = 0;
  } else {
    g_status.dwControlsAccepted = 0;
  }
  SetServiceStatus(g_status_handle, &g_status);
}

static void WINAPI edr_svc_ctrl_handler(DWORD ctrl) {
  if (ctrl == SERVICE_CONTROL_STOP || ctrl == SERVICE_CONTROL_SHUTDOWN) {
    edr_svc_report_state(SERVICE_STOP_PENDING, NO_ERROR, 25000u);
    edr_agent_shutdown(edr_agent_main_active_for_stop());
  }
}

static void edr_svc_after_init_before_run(void *user) {
  (void)user;
  edr_svc_report_state(SERVICE_RUNNING, NO_ERROR, 0u);
}

static void WINAPI edr_ServiceMain(DWORD dwArgc, LPSTR *lpszArgv) {
  const char *config = "";
  for (DWORD i = 0u; i < dwArgc; i++) {
    if (strcmp(lpszArgv[i], "--config") == 0 && i + 1u < dwArgc) {
      config = lpszArgv[++i];
      continue;
    }
    if (strcmp(lpszArgv[i], "--service") == 0 && i + 1u < dwArgc) {
      i++;
      continue;
    }
  }

  memset(&g_status, 0, sizeof(g_status));
  g_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
  g_status.dwCurrentState = SERVICE_START_PENDING;
  g_status.dwControlsAccepted = 0;
  g_status.dwWin32ExitCode = NO_ERROR;
  g_status.dwServiceSpecificExitCode = 0;
  g_status.dwCheckPoint = 0;
  g_status.dwWaitHint = 3000u;

  g_status_handle = RegisterServiceCtrlHandlerA(g_table_service_name, edr_svc_ctrl_handler);
  if (!g_status_handle) {
    fprintf(stderr, "[service] RegisterServiceCtrlHandler failed: %lu\n", GetLastError());
    return;
  }
  edr_svc_report_state(SERVICE_START_PENDING, NO_ERROR, 10000u);

  EdrAgentMainOptions opt;
  memset(&opt, 0, sizeof(opt));
  opt.after_init_before_run = edr_svc_after_init_before_run;
  int rc = edr_agent_application_main(config, &opt);

  if (rc == 0) {
    g_status.dwWin32ExitCode = NO_ERROR;
    g_status.dwServiceSpecificExitCode = 0;
  } else {
    g_status.dwWin32ExitCode = ERROR_SERVICE_SPECIFIC_ERROR;
    g_status.dwServiceSpecificExitCode = (DWORD)(rc & 0xFFFF);
  }
  g_status.dwCurrentState = SERVICE_STOPPED;
  g_status.dwControlsAccepted = 0;
  g_status.dwWaitHint = 0;
  g_status.dwCheckPoint = 0;
  if (g_status_handle) {
    SetServiceStatus(g_status_handle, &g_status);
  }
}

static int edr_argv_has_service_flag(int argc, char **argv) {
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--service") == 0) {
      return i;
    }
  }
  return -1;
}

static void edr_extract_service_name(int argc, char **argv, int svc_index, char *out, size_t outsz) {
  const char *name = "EdrAgent";
  if (svc_index + 1 < argc && argv[svc_index + 1][0] != '\0' && argv[svc_index + 1][0] != '-') {
    name = argv[svc_index + 1];
  } else {
    const char *env = getenv("EDR_SERVICE_NAME");
    if (env && env[0]) {
      name = env;
    }
  }
  (void)snprintf(out, outsz, "%s", name);
}

int edr_windows_service_dispatch_if_requested(int argc, char **argv) {
  int si = edr_argv_has_service_flag(argc, argv);
  if (si < 0) {
    return -1;
  }
  edr_extract_service_name(argc, argv, si, g_table_service_name, sizeof(g_table_service_name));

  SERVICE_TABLE_ENTRYA table[2];
  memset(table, 0, sizeof(table));
  table[0].lpServiceName = g_table_service_name;
  table[0].lpServiceProc = (LPSERVICE_MAIN_FUNCTIONA)edr_ServiceMain;
  table[1].lpServiceName = NULL;
  table[1].lpServiceProc = NULL;

  if (!StartServiceCtrlDispatcherA(table)) {
    DWORD e = GetLastError();
    fprintf(stderr, "[service] StartServiceCtrlDispatcher failed: %lu", e);
    if (e == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
      fprintf(stderr, " (process was not started by the Service Control Manager; use `sc create` + `sc start` with the same **Service name** as **`--service`**, or omit **--**service for console mode)\n");
    } else {
      fputc('\n', stderr);
    }
    return 1;
  }
  return 0;
}
