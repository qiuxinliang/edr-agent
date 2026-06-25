#ifdef _MSC_VER
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif
#ifndef _CRT_NONSTDC_NO_WARNINGS
#define _CRT_NONSTDC_NO_WARNINGS
#endif
#endif

#include "edr/agent.h"
#include "edr/ave_sdk.h"
#include "edr/collector.h"
#include "edr/config.h"
#include "edr/dedup.h"
#include "edr/event_batch.h"
#include "edr/command.h"
#include "edr/local_evidence_cache.h"
#include "edr/resource.h"
#include "edr/self_protect.h"
#include "edr/watchdog.h"
#include "edr/storage_queue.h"
#include "edr/transport_sink.h"
#include "edr/pmfe.h"
#include "edr/net_fanout_detector.h"
#include "edr/shellcode_detector.h"
#include "edr/webshell_detector.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
static EdrAgent *g_agent_for_sig;
static void edr_on_sigint(int s) {
  (void)s;
  if (g_agent_for_sig) {
    edr_agent_shutdown(g_agent_for_sig);
  }
}
#endif

#ifdef _WIN32
#include <windows.h>
static EdrAgent *g_agent_for_ctrl;
static SERVICE_STATUS_HANDLE g_service_status_handle;
static SERVICE_STATUS g_service_status;
static const char *g_service_name = "FDSecurityAgent";
static const char *g_service_config_path;

static const char *edr_default_windows_config_path(void) {
  static const char path[] = "C:\\Program Files\\FDSecurity\\agent.toml";
  static const char legacy_path[] = "C:\\Program Files\\EDR Agent\\agent.toml";
  DWORD attrs = GetFileAttributesA(path);
  if (attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY)) {
    return path;
  }
  attrs = GetFileAttributesA(legacy_path);
  if (attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY)) {
    return legacy_path;
  }
  return NULL;
}

static BOOL WINAPI edr_on_console_ctrl(DWORD t) {
  if (t == CTRL_C_EVENT || t == CTRL_CLOSE_EVENT || t == CTRL_BREAK_EVENT) {
    if (g_agent_for_ctrl) {
      edr_agent_shutdown(g_agent_for_ctrl);
    }
    return TRUE;
  }
  return FALSE;
}

static int edr_path_is_absolute_win(const char *path) {
  if (!path || !path[0]) {
    return 0;
  }
  if ((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z')) {
    return path[1] == ':' && (path[2] == '\\' || path[2] == '/');
  }
  return (path[0] == '\\' && path[1] == '\\');
}

static void edr_ensure_parent_dirs_win(const char *path) {
  char tmp[MAX_PATH * 4];
  size_t n = 0;
  if (!path || !path[0]) {
    return;
  }
  n = strlen(path);
  if (n == 0 || n >= sizeof(tmp)) {
    return;
  }
  memcpy(tmp, path, n + 1u);
  for (size_t i = 0; tmp[i]; i++) {
    if (tmp[i] == '/') {
      tmp[i] = '\\';
    }
  }
  char *last = strrchr(tmp, '\\');
  if (!last) {
    return;
  }
  *last = '\0';
  for (char *p = tmp; *p; p++) {
    if (*p != '\\') {
      continue;
    }
    if (p == tmp || (p > tmp && p[-1] == ':') || (p > tmp && p[-1] == '\\')) {
      continue;
    }
    *p = '\0';
    (void)CreateDirectoryA(tmp, NULL);
    *p = '\\';
  }
  (void)CreateDirectoryA(tmp, NULL);
}

typedef struct EdrWindowsInstallOptions {
  const char *api_base;
  const char *enroll_token;
  const char *install_dir;
  const char *output;
  const char *ca_cert;
  int trust_ca;
  int install_autorun;
  int install_service;
  int harden_acl;
  int force_enroll;
  int enable_response_actions;
} EdrWindowsInstallOptions;

static int edr_win_get_exe_dir(char *out, size_t cap) {
  DWORD n = 0;
  char *last_slash = NULL;
  char *last_backslash = NULL;
  char *last = NULL;
  if (!out || cap == 0) {
    return 0;
  }
  n = GetModuleFileNameA(NULL, out, (DWORD)cap);
  if (n == 0 || (size_t)n >= cap) {
    return 0;
  }
  last_slash = strrchr(out, '/');
  last_backslash = strrchr(out, '\\');
  last = (last_backslash && (!last_slash || last_backslash > last_slash)) ? last_backslash
                                                                          : last_slash;
  if (!last) {
    return 0;
  }
  *last = '\0';
  return 1;
}

static int edr_win_join_path(char *out, size_t cap, const char *base, const char *leaf) {
  size_t nb = 0;
  int n = 0;
  if (!out || cap == 0 || !base || !base[0] || !leaf || !leaf[0]) {
    return 0;
  }
  nb = strlen(base);
  if (base[nb - 1u] == '\\' || base[nb - 1u] == '/') {
    n = snprintf(out, cap, "%s%s", base, leaf);
    return n > 0 && (size_t)n < cap;
  }
  n = snprintf(out, cap, "%s\\%s", base, leaf);
  return n > 0 && (size_t)n < cap;
}

static int edr_win_find_packaged_file(char *out, size_t cap, const char *exe_dir,
                                      const char *name) {
  char candidate[MAX_PATH * 4];
  char scripts_dir[MAX_PATH * 4];
  if (!edr_win_join_path(candidate, sizeof(candidate), exe_dir, name)) {
    return 0;
  }
  if (GetFileAttributesA(candidate) != INVALID_FILE_ATTRIBUTES) {
    if (strlen(candidate) >= cap) {
      return 0;
    }
    memcpy(out, candidate, strlen(candidate) + 1u);
    return 1;
  }
  if (!edr_win_join_path(scripts_dir, sizeof(scripts_dir), exe_dir, "scripts")) {
    return 0;
  }
  if (!edr_win_join_path(candidate, sizeof(candidate), scripts_dir, name)) {
    return 0;
  }
  if (GetFileAttributesA(candidate) != INVALID_FILE_ATTRIBUTES) {
    if (strlen(candidate) >= cap) {
      return 0;
    }
    memcpy(out, candidate, strlen(candidate) + 1u);
    return 1;
  }
  return 0;
}

static int edr_win_cmd_append_raw(char *cmd, size_t cap, const char *s) {
  size_t used = 0;
  size_t add = 0;
  if (!cmd || !s) {
    return 0;
  }
  used = strlen(cmd);
  add = strlen(s);
  if (used + add + 1u >= cap) {
    return 0;
  }
  memcpy(cmd + used, s, add + 1u);
  return 1;
}

static int edr_win_cmd_append_arg(char *cmd, size_t cap, const char *arg) {
  size_t used = 0;
  size_t backslashes = 0;
  if (!cmd || !arg) {
    return 0;
  }
  used = strlen(cmd);
  if (used > 0 && !edr_win_cmd_append_raw(cmd, cap, " ")) {
    return 0;
  }
  if (!edr_win_cmd_append_raw(cmd, cap, "\"")) {
    return 0;
  }
  for (const char *p = arg; *p; p++) {
    if (*p == '\\') {
      backslashes++;
      continue;
    }
    if (*p == '"') {
      while (backslashes > 0) {
        if (!edr_win_cmd_append_raw(cmd, cap, "\\\\")) {
          return 0;
        }
        backslashes--;
      }
      if (!edr_win_cmd_append_raw(cmd, cap, "\\\"")) {
        return 0;
      }
      continue;
    }
    while (backslashes > 0) {
      if (!edr_win_cmd_append_raw(cmd, cap, "\\")) {
        return 0;
      }
      backslashes--;
    }
    char tmp[2] = {*p, '\0'};
    if (!edr_win_cmd_append_raw(cmd, cap, tmp)) {
      return 0;
    }
  }
  while (backslashes > 0) {
    if (!edr_win_cmd_append_raw(cmd, cap, "\\\\")) {
      return 0;
    }
    backslashes--;
  }
  return edr_win_cmd_append_raw(cmd, cap, "\"");
}

static int edr_win_append_named_arg(char *cmd, size_t cap, const char *name, const char *value) {
  if (!edr_win_cmd_append_arg(cmd, cap, name)) {
    return 0;
  }
  return edr_win_cmd_append_arg(cmd, cap, value);
}

static int edr_win_run_and_wait(const char *cmd, const char *workdir) {
  STARTUPINFOA si;
  PROCESS_INFORMATION pi;
  DWORD exit_code = 1;
  char mutable_cmd[32768];
  if (!cmd || strlen(cmd) >= sizeof(mutable_cmd)) {
    return 1;
  }
  memset(&si, 0, sizeof(si));
  memset(&pi, 0, sizeof(pi));
  si.cb = sizeof(si);
  snprintf(mutable_cmd, sizeof(mutable_cmd), "%s", cmd);
  if (!CreateProcessA(NULL, mutable_cmd, NULL, NULL, FALSE, 0, NULL, workdir, &si, &pi)) {
    fprintf(stderr, "[install] CreateProcess failed: %lu\n", (unsigned long)GetLastError());
    return 1;
  }
  WaitForSingleObject(pi.hProcess, INFINITE);
  if (!GetExitCodeProcess(pi.hProcess, &exit_code)) {
    exit_code = 1;
  }
  CloseHandle(pi.hThread);
  CloseHandle(pi.hProcess);
  return (int)exit_code;
}

static int edr_windows_install(const EdrWindowsInstallOptions *opt) {
  char exe_dir[MAX_PATH * 4];
  char script[MAX_PATH * 4];
  char service_script[MAX_PATH * 4];
  char output[MAX_PATH * 4];
  char exe_path[MAX_PATH * 4];
  char ca_cert[MAX_PATH * 4];
  char cmd[32768];
  int rc = 0;
  const char *install_dir = NULL;
  if (!opt || !opt->api_base || !opt->api_base[0] || !opt->enroll_token ||
      !opt->enroll_token[0]) {
    fprintf(stderr, "[install] --api-base and --enroll-token are required\n");
    return 2;
  }
  if (opt->install_service && opt->install_autorun) {
    fprintf(stderr, "[install] choose only one runtime mode: --install-service or --install-autorun\n");
    return 2;
  }
  if (!edr_win_get_exe_dir(exe_dir, sizeof(exe_dir))) {
    fprintf(stderr, "[install] cannot resolve executable directory\n");
    return 1;
  }
  install_dir = (opt->install_dir && opt->install_dir[0]) ? opt->install_dir : exe_dir;
  if (!edr_win_find_packaged_file(script, sizeof(script), exe_dir, "edr_agent_install.ps1")) {
    fprintf(stderr,
            "[install] edr_agent_install.ps1 not found beside FDSensor.exe or under scripts\\\n");
    return 1;
  }
  if (opt->output && opt->output[0]) {
    if (strlen(opt->output) >= sizeof(output)) {
      fprintf(stderr, "[install] output path is too long\n");
      return 1;
    }
    snprintf(output, sizeof(output), "%s", opt->output);
  } else if (!edr_win_join_path(output, sizeof(output), install_dir, "agent.toml")) {
    fprintf(stderr, "[install] cannot compose agent.toml path\n");
    return 1;
  }
  if (opt->ca_cert && opt->ca_cert[0]) {
    if (strlen(opt->ca_cert) >= sizeof(ca_cert)) {
      fprintf(stderr, "[install] CA certificate path is too long\n");
      return 1;
    }
    snprintf(ca_cert, sizeof(ca_cert), "%s", opt->ca_cert);
  } else if (!edr_win_join_path(ca_cert, sizeof(ca_cert), install_dir, "certs\\ca.pem")) {
    fprintf(stderr, "[install] cannot compose CA certificate path\n");
    return 1;
  }
  if (!edr_win_join_path(exe_path, sizeof(exe_path), install_dir, "FDSensor.exe")) {
    fprintf(stderr, "[install] cannot compose FDSensor.exe path\n");
    return 1;
  }

  cmd[0] = '\0';
  if (!edr_win_cmd_append_arg(cmd, sizeof(cmd), "powershell.exe") ||
      !edr_win_cmd_append_arg(cmd, sizeof(cmd), "-NoProfile") ||
      !edr_win_cmd_append_arg(cmd, sizeof(cmd), "-ExecutionPolicy") ||
      !edr_win_cmd_append_arg(cmd, sizeof(cmd), "Bypass") ||
      !edr_win_cmd_append_arg(cmd, sizeof(cmd), "-File") ||
      !edr_win_cmd_append_arg(cmd, sizeof(cmd), script) ||
      !edr_win_append_named_arg(cmd, sizeof(cmd), "-ApiBase", opt->api_base) ||
      !edr_win_append_named_arg(cmd, sizeof(cmd), "-EnrollToken", opt->enroll_token) ||
      !edr_win_append_named_arg(cmd, sizeof(cmd), "-Output", output) ||
      !edr_win_append_named_arg(cmd, sizeof(cmd), "-CaCertPath", ca_cert)) {
    fprintf(stderr, "[install] command line too long\n");
    return 1;
  }
  if (opt->trust_ca && !edr_win_cmd_append_arg(cmd, sizeof(cmd), "-TrustCa")) {
    return 1;
  }
  if (opt->install_autorun && !edr_win_cmd_append_arg(cmd, sizeof(cmd), "-InstallAutorun")) {
    return 1;
  }
  if (opt->harden_acl && !edr_win_cmd_append_arg(cmd, sizeof(cmd), "-HardenAcl")) {
    return 1;
  }
  if (opt->force_enroll && !edr_win_cmd_append_arg(cmd, sizeof(cmd), "-ForceEnroll")) {
    return 1;
  }

  fprintf(stderr, "[install] enrolling endpoint and writing %s\n", output);
  rc = edr_win_run_and_wait(cmd, exe_dir);
  if (rc != 0) {
    fprintf(stderr, "[install] edr_agent_install.ps1 failed: %d\n", rc);
    return rc;
  }
  if (!opt->install_service) {
    fprintf(stderr, "[install] completed. Start with: FDSensor.exe --config \"%s\"\n", output);
    return 0;
  }

  if (!edr_win_find_packaged_file(service_script, sizeof(service_script), exe_dir,
                                  "windows_service_install.ps1")) {
    fprintf(stderr,
            "[install] windows_service_install.ps1 not found beside FDSensor.exe or under scripts\\\n");
    return 1;
  }
  cmd[0] = '\0';
  if (!edr_win_cmd_append_arg(cmd, sizeof(cmd), "powershell.exe") ||
      !edr_win_cmd_append_arg(cmd, sizeof(cmd), "-NoProfile") ||
      !edr_win_cmd_append_arg(cmd, sizeof(cmd), "-ExecutionPolicy") ||
      !edr_win_cmd_append_arg(cmd, sizeof(cmd), "Bypass") ||
      !edr_win_cmd_append_arg(cmd, sizeof(cmd), "-File") ||
      !edr_win_cmd_append_arg(cmd, sizeof(cmd), service_script) ||
      !edr_win_append_named_arg(cmd, sizeof(cmd), "-Action", "Install") ||
      !edr_win_append_named_arg(cmd, sizeof(cmd), "-ServiceName", g_service_name) ||
      !edr_win_append_named_arg(cmd, sizeof(cmd), "-ExePath", exe_path) ||
      !edr_win_append_named_arg(cmd, sizeof(cmd), "-ConfigPath", output) ||
      !edr_win_append_named_arg(cmd, sizeof(cmd), "-InstallDir", install_dir) ||
      !edr_win_append_named_arg(cmd, sizeof(cmd), "-DataDir", install_dir)) {
    fprintf(stderr, "[install] service command line too long\n");
    return 1;
  }
  if (opt->enable_response_actions &&
      !edr_win_cmd_append_arg(cmd, sizeof(cmd), "-EnableResponseActions")) {
    return 1;
  }
  fprintf(stderr, "[install] installing Windows service %s\n", g_service_name);
  rc = edr_win_run_and_wait(cmd, exe_dir);
  if (rc != 0) {
    fprintf(stderr, "[install] windows_service_install.ps1 failed: %d\n", rc);
  }
  return rc;
}
#endif

static void print_usage(const char *argv0) {
  fprintf(stderr,
          "Usage: %s [--config <path>] [--config-test] [--service] [--service-name <name>] "
          "[--etw-uninstall-cleanup]\n",
          argv0);
  fprintf(stderr,
          "       %s --install --api-base <url> --enroll-token <token> "
          "[--trust-ca] [--install-autorun|--install-service] [--force-enroll]\n",
          argv0);
  fprintf(stderr,
          "  FDSecurity Sensor - endpoint runtime "
          "(collection/preprocess/batch/HTTP control/RTR/RTQ/AVE paths enabled)\n");
}

#ifdef _WIN32
static void edr_service_set_status(DWORD state, DWORD win32_exit, DWORD wait_hint_ms);
#endif

static int edr_agent_run_main(const char *config) {
  EdrAgent *agent = edr_agent_create();
  if (!agent) {
    return 1;
  }
#ifdef _WIN32
  g_agent_for_ctrl = agent;
  SetConsoleCtrlHandler(edr_on_console_ctrl, TRUE);
#else
  g_agent_for_sig = agent;
  edr_self_protect_set_shutdown_hook(edr_on_sigint);
#endif
  EdrError e = edr_agent_init(agent, config ? config : "");
  if (e != EDR_OK) {
    fprintf(stderr, "edr_agent_init failed: %d\n", (int)e);
    edr_agent_destroy(agent);
    return 1;
  }
  {
    const char *qpath = getenv("EDR_QUEUE_PATH");
    const EdrConfig *ac = edr_agent_get_config(agent);
    if (ac) {
      edr_storage_queue_configure(ac->offline.max_queue_size_mb, ac->offline.retention_hours);
    }
    if ((!qpath || !qpath[0]) && ac && ac->offline.queue_db_path[0]) {
      qpath = ac->offline.queue_db_path;
    }
#ifdef _WIN32
    edr_ensure_parent_dirs_win(qpath);
#endif
    EdrError sq = edr_storage_queue_open(qpath);
    if (sq == EDR_ERR_QUEUE_LOCKED) {
      fprintf(stderr,
              "[queue] another agent instance appears to be running; exiting before collector start\n");
      edr_agent_destroy(agent);
      return 1;
    }
    if (sq != EDR_OK && qpath && qpath[0]) {
#ifdef _WIN32
      if (!edr_path_is_absolute_win(qpath)) {
        char fallback[MAX_PATH * 4];
        snprintf(fallback, sizeof(fallback), "%s",
                 "C:\\Program Files\\FDSecurity\\queue\\edr_queue.db");
        edr_ensure_parent_dirs_win(fallback);
        sq = edr_storage_queue_open(fallback);
        if (sq == EDR_OK) {
          fprintf(stderr, "[queue] using install-dir path (%s)\n", fallback);
        } else if (sq == EDR_ERR_QUEUE_LOCKED) {
          fprintf(stderr,
                  "[queue] another agent instance appears to be running; exiting before collector start\n");
          edr_agent_destroy(agent);
          return 1;
        } else {
          fprintf(stderr, "[queue] open failed (%s): %d\n", qpath, (int)sq);
        }
      } else
#endif
      {
        fprintf(stderr, "[queue] open failed (%s): %d\n", qpath, (int)sq);
      }
    }
  }
  {
    const EdrConfig *ac = edr_agent_get_config(agent);
    const char *epath = getenv("EDR_EVIDENCE_CACHE_PATH");
    if ((!epath || !epath[0]) && ac && ac->offline.evidence_cache_path[0]) {
      epath = ac->offline.evidence_cache_path;
    }
#ifdef _WIN32
    edr_ensure_parent_dirs_win(epath);
#endif
    if (edr_local_evidence_cache_open(epath,
                                      ac ? ac->offline.evidence_cache_max_size_mb : 128u,
                                      ac ? ac->offline.evidence_cache_retention_hours : 24u) != 0) {
#ifdef _WIN32
      if (epath && epath[0] && !edr_path_is_absolute_win(epath)) {
        char fallback[MAX_PATH * 4];
        snprintf(fallback, sizeof(fallback), "%s",
                 "C:\\Program Files\\FDSecurity\\evidence\\local_evidence_cache.db");
        edr_ensure_parent_dirs_win(fallback);
        if (edr_local_evidence_cache_open(fallback,
                                          ac ? ac->offline.evidence_cache_max_size_mb : 128u,
                                          ac ? ac->offline.evidence_cache_retention_hours : 24u) == 0) {
          fprintf(stderr, "[local_evidence_cache] using install-dir path (%s)\n", fallback);
        } else {
          EdrEvidenceCacheStatus st;
          edr_local_evidence_cache_get_status(&st);
          fprintf(stderr, "[local_evidence_cache] open failed (%s): %s\n",
                  epath ? epath : "", st.last_error[0] ? st.last_error : "unknown");
        }
      } else
#endif
      {
        EdrEvidenceCacheStatus st;
        edr_local_evidence_cache_get_status(&st);
        fprintf(stderr, "[local_evidence_cache] open failed (%s): %s\n",
                epath ? epath : "", st.last_error[0] ? st.last_error : "unknown");
      }
    }
  }
  edr_command_bind_config(edr_agent_get_config(agent));
  edr_pmfe_bind_config(edr_agent_get_config(agent));
  edr_pmfe_set_event_bus(edr_agent_event_bus(agent));
  {
    EdrError pe = edr_pmfe_init();
    if (pe != EDR_OK) {
      fprintf(stderr, "edr_pmfe_init failed: %d\n", (int)pe);
    }
  }
  edr_transport_init_from_config(edr_agent_get_config(agent));
  {
    EdrError se =
        edr_shellcode_detector_init(edr_agent_get_config(agent), edr_agent_event_bus(agent));
    if (se != EDR_OK) {
      fprintf(stderr, "shellcode_detector init failed: %d\n", (int)se);
    }
  }
  {
    EdrError we = edr_webshell_detector_init(edr_agent_get_config(agent), edr_agent_event_bus(agent));
    if (we != EDR_OK) {
      fprintf(stderr, "webshell_detector init failed: %d\n", (int)we);
    }
  }
  {
    EdrError ne = edr_net_fanout_init(edr_agent_get_config(agent));
    if (ne != EDR_OK) {
      fprintf(stderr, "net_fanout init failed: %d\n", (int)ne);
    }
  }
#ifdef _WIN32
  edr_service_set_status(SERVICE_RUNNING, NO_ERROR, 0);
#endif
  e = edr_agent_run(agent);
  {
    uint64_t dd = 0, rr = 0;
    edr_dedup_get_stats(&dd, &rr);
    fprintf(stderr,
            "[preprocess] wire_events=%lu wire_bytes=%zu batches=%lu "
            "batch_bytes=%zu batch_lz4=%lu batch_timeout_flushes=%llu "
            "bus_hw80=%llu bus_dropped=%llu dedup_drops=%llu rate_drops=%llu "
            "queue_pending=%llu\n",
            edr_transport_wire_events_count(), edr_transport_wire_bytes_count(),
            edr_transport_batch_count(), edr_transport_batch_bytes_count(),
            edr_transport_batch_lz4_count(),
            (unsigned long long)edr_event_batch_timeout_flush_count(),
            (unsigned long long)edr_event_bus_high_water_hits(
                edr_agent_event_bus(agent)),
            (unsigned long long)edr_event_bus_dropped_total(
                edr_agent_event_bus(agent)),
            (unsigned long long)dd, (unsigned long long)rr,
            (unsigned long long)edr_storage_queue_pending_count());
    fprintf(stderr,
            "[command] handled=%lu unknown=%lu rejected=%lu exec_ok=%lu exec_fail=%lu\n",
            edr_command_handled_count(), edr_command_unknown_count(),
            edr_command_rejected_count(), edr_command_exec_ok_count(),
            edr_command_exec_fail_count());
    fprintf(stderr, "[resource] emergency=%lu\n", edr_resource_emergency_count());
    {
      unsigned long sub = 0, done = 0, drop = 0;
      edr_pmfe_get_stats(&sub, &done, &drop);
      fprintf(stderr, "[pmfe] submitted=%lu completed=%lu dropped=%lu\n", sub, done, drop);
    }
    {
      AVEStatus avst;
      if (AVE_GetStatus(&avst) == AVE_OK) {
        fprintf(stderr,
                "[ave/behavior] feed=%llu enq=%llu q_full_sync=%llu bypass=%llu deq=%llu "
                "infer_ok=%llu infer_fail=%llu q_depth=%d q_cap=%u mon=%d\n",
                (unsigned long long)avst.behavior_feed_total, (unsigned long long)avst.behavior_queue_enqueued,
                (unsigned long long)avst.behavior_queue_full_sync_fallback,
                (unsigned long long)avst.behavior_feed_sync_bypass,
                (unsigned long long)avst.behavior_worker_dequeued, (unsigned long long)avst.behavior_infer_ok,
                (unsigned long long)avst.behavior_infer_fail, avst.behavior_event_queue_size,
                (unsigned)avst.behavior_queue_capacity, avst.behavior_monitor_running ? 1 : 0);
      }
    }
  }
  edr_pmfe_shutdown();
  edr_shellcode_detector_shutdown();
  edr_webshell_detector_shutdown();
  edr_net_fanout_shutdown();
  edr_transport_shutdown();
  edr_local_evidence_cache_close();
  edr_storage_queue_close();
  edr_agent_destroy(agent);
  return e == EDR_OK ? 0 : 1;
}

static int edr_agent_config_test_main(const char *config) {
  EdrConfig cfg;
  memset(&cfg, 0, sizeof(cfg));
  EdrError e = edr_config_load(config ? config : "", &cfg);
  if (e != EDR_OK) {
    fprintf(stderr, "config test failed: %d\n", (int)e);
    edr_config_free_heap(&cfg);
    return 1;
  }
  edr_config_free_heap(&cfg);
  fprintf(stderr, "config test ok\n");
  return 0;
}

#ifdef _WIN32
static void edr_service_set_status(DWORD state, DWORD win32_exit, DWORD wait_hint_ms) {
  if (!g_service_status_handle) {
    return;
  }
  g_service_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
  g_service_status.dwCurrentState = state;
  g_service_status.dwWin32ExitCode = win32_exit;
  g_service_status.dwWaitHint = wait_hint_ms;
  g_service_status.dwControlsAccepted =
      (state == SERVICE_RUNNING) ? (SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN) : 0;
  if (state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING) {
    g_service_status.dwCheckPoint++;
  } else {
    g_service_status.dwCheckPoint = 0;
  }
  SetServiceStatus(g_service_status_handle, &g_service_status);
}

static void WINAPI edr_service_ctrl_handler(DWORD ctrl) {
  if (ctrl == SERVICE_CONTROL_STOP || ctrl == SERVICE_CONTROL_SHUTDOWN) {
    edr_service_set_status(SERVICE_STOP_PENDING, NO_ERROR, 30000);
    if (g_agent_for_ctrl) {
      edr_agent_shutdown(g_agent_for_ctrl);
    }
  }
}

static void WINAPI edr_service_main(DWORD argc, LPSTR *argv) {
  (void)argc;
  (void)argv;
  g_service_status_handle =
      RegisterServiceCtrlHandlerA(g_service_name, edr_service_ctrl_handler);
  if (!g_service_status_handle) {
    return;
  }
  edr_service_set_status(SERVICE_START_PENDING, NO_ERROR, 30000);
  int rc = edr_agent_run_main(g_service_config_path);
  edr_service_set_status(SERVICE_STOPPED, rc == 0 ? NO_ERROR : ERROR_SERVICE_SPECIFIC_ERROR, 0);
}
#endif

int main(int argc, char **argv) {
  const char *config = NULL;
  int run_as_service = 0;
  int config_test = 0;
  int watchdog_mode = 0;
  long watchdog_parent_pid = 0;
#ifdef _WIN32
  int install_mode = 0;
  int install_arg_seen = 0;
  EdrWindowsInstallOptions install_opt;
  memset(&install_opt, 0, sizeof(install_opt));
#endif
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
      print_usage(argv[0]);
      return 0;
    }
    if (strcmp(argv[i], "--etw-uninstall-cleanup") == 0) {
      edr_collector_stop_orphan_etw_session();
      return 0;
    }
    if (strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
      config = argv[++i];
      continue;
    }
    if (strcmp(argv[i], "--config-test") == 0) {
      config_test = 1;
      continue;
    }
#ifdef _WIN32
    if (strcmp(argv[i], "--install") == 0) {
      install_mode = 1;
      continue;
    }
    if (strcmp(argv[i], "--api-base") == 0 && i + 1 < argc) {
      install_arg_seen = 1;
      install_opt.api_base = argv[++i];
      continue;
    }
    if (strcmp(argv[i], "--enroll-token") == 0 && i + 1 < argc) {
      install_arg_seen = 1;
      install_opt.enroll_token = argv[++i];
      continue;
    }
    if (strcmp(argv[i], "--install-dir") == 0 && i + 1 < argc) {
      install_arg_seen = 1;
      install_opt.install_dir = argv[++i];
      continue;
    }
    if (strcmp(argv[i], "--output") == 0 && i + 1 < argc) {
      install_arg_seen = 1;
      install_opt.output = argv[++i];
      continue;
    }
    if (strcmp(argv[i], "--ca-cert") == 0 && i + 1 < argc) {
      install_arg_seen = 1;
      install_opt.ca_cert = argv[++i];
      continue;
    }
    if (strcmp(argv[i], "--trust-ca") == 0) {
      install_arg_seen = 1;
      install_opt.trust_ca = 1;
      continue;
    }
    if (strcmp(argv[i], "--install-autorun") == 0) {
      install_arg_seen = 1;
      install_opt.install_autorun = 1;
      continue;
    }
    if (strcmp(argv[i], "--install-service") == 0) {
      install_arg_seen = 1;
      install_opt.install_service = 1;
      continue;
    }
    if (strcmp(argv[i], "--harden-acl") == 0) {
      install_arg_seen = 1;
      install_opt.harden_acl = 1;
      continue;
    }
    if (strcmp(argv[i], "--force-enroll") == 0) {
      install_arg_seen = 1;
      install_opt.force_enroll = 1;
      continue;
    }
    if (strcmp(argv[i], "--enable-response-actions") == 0) {
      install_arg_seen = 1;
      install_opt.enable_response_actions = 1;
      continue;
    }
#else
    if (strcmp(argv[i], "--install") == 0 || strcmp(argv[i], "--api-base") == 0 ||
        strcmp(argv[i], "--enroll-token") == 0 || strcmp(argv[i], "--install-dir") == 0 ||
        strcmp(argv[i], "--output") == 0 || strcmp(argv[i], "--ca-cert") == 0 ||
        strcmp(argv[i], "--trust-ca") == 0 || strcmp(argv[i], "--install-autorun") == 0 ||
        strcmp(argv[i], "--install-service") == 0 || strcmp(argv[i], "--harden-acl") == 0 ||
        strcmp(argv[i], "--force-enroll") == 0 ||
        strcmp(argv[i], "--enable-response-actions") == 0) {
      fprintf(stderr, "--install is only supported by Windows packages\n");
      return 2;
    }
#endif
    if (strcmp(argv[i], "--watchdog") == 0) {
      watchdog_mode = 1;
      continue;
    }
    if (strcmp(argv[i], "--parent-pid") == 0 && i + 1 < argc) {
      watchdog_parent_pid = strtol(argv[++i], NULL, 10);
      continue;
    }
    if (strcmp(argv[i], "--service") == 0) {
      run_as_service = 1;
      continue;
    }
    if (strcmp(argv[i], "--service-name") == 0 && i + 1 < argc) {
#ifdef _WIN32
      g_service_name = argv[++i];
#else
      i++;
#endif
      continue;
    }
    fprintf(stderr, "unknown argument: %s\n", argv[i]);
    print_usage(argv[0]);
    return 1;
  }

#ifdef _WIN32
  if (!install_mode && install_arg_seen) {
    fprintf(stderr, "installer arguments require --install\n");
    return 2;
  }
  if (install_mode) {
    if (config && !install_opt.output) {
      install_opt.output = config;
    }
    return edr_windows_install(&install_opt);
  }
  if (!config) {
    config = edr_default_windows_config_path();
  }
  if (config_test) {
    return edr_agent_config_test_main(config);
  }
  if (run_as_service) {
    SERVICE_TABLE_ENTRYA table[] = {
        {(LPSTR)g_service_name, edr_service_main},
        {NULL, NULL},
    };
    g_service_config_path = config;
    if (!StartServiceCtrlDispatcherA(table)) {
      DWORD err = GetLastError();
      fprintf(stderr, "StartServiceCtrlDispatcher failed: %lu\n", (unsigned long)err);
      return 1;
    }
    return 0;
  }
#else
  (void)run_as_service;
#endif

  if (config_test) {
    return edr_agent_config_test_main(config);
  }

  edr_self_protect_set_exec_context(argv[0], config ? config : "");
  if (watchdog_mode) {
    return edr_watchdog_run(watchdog_parent_pid, argv[0], config ? config : "");
  }

  return edr_agent_run_main(config);
}
