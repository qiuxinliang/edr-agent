/* §19 P2：攻击面 inventory 维度（服务/计划任务/自启动/账号组/共享）。
 * 约束：best-effort，只读采集；任一维度失败不得使整个快照失败。 */

#include "edr/attack_surface_inventory.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
/* windows.h 必须先于 lm.h / winsvc.h：后者依赖 DWORD/LPBYTE 等 Windows 类型，
 * 否则 MSVC 报 C2061/C2065 未声明类型（MinGW/Clang 头文件较宽松不暴露）。 */
#include <windows.h>
#include <lm.h>
#include <winsvc.h>
#else
#include <dirent.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#define AS_INV_SERVICES_MAX 128
#define AS_INV_TASKS_MAX 128
#define AS_INV_STARTUP_MAX 128
#define AS_INV_ACCOUNTS_MAX 128
#define AS_INV_GROUPS_MAX 64
#define AS_INV_SHARES_MAX 64

#if defined(__GNUC__) || defined(__clang__)
#define AS_INV_UNUSED __attribute__((unused))
#else
#define AS_INV_UNUSED
#endif

static void inv_json_escape(FILE *f, const char *s) {
  fputc('"', f);
  for (; s && *s; s++) {
    unsigned char c = (unsigned char)*s;
    if (c == '"' || c == '\\') {
      fputc('\\', f);
      fputc((int)c, f);
    } else if (c < 32u) {
      fprintf(f, "\\u%04x", (unsigned)c);
    } else {
      fputc((int)c, f);
    }
  }
  fputc('"', f);
}

static void trim_line(char *s) {
  size_t n;
  if (!s) return;
  while (*s && isspace((unsigned char)*s)) {
    memmove(s, s + 1, strlen(s));
  }
  n = strlen(s);
  while (n > 0 && isspace((unsigned char)s[n - 1])) {
    s[--n] = 0;
  }
}

static int contains_ci(const char *hay, const char *needle) {
  size_t nn;
  if (!hay || !needle || !needle[0]) return 0;
  nn = strlen(needle);
  for (const char *p = hay; *p; p++) {
    size_t i = 0;
    while (i < nn && p[i] && tolower((unsigned char)p[i]) == tolower((unsigned char)needle[i])) {
      i++;
    }
    if (i == nn) return 1;
  }
  return 0;
}

static int path_risk_level(const char *p) {
  if (!p || !p[0]) return 0;
  if (contains_ci(p, "\\temp\\") || contains_ci(p, "/tmp/") || contains_ci(p, "/var/tmp/") ||
      contains_ci(p, "\\users\\") || contains_ci(p, "/home/") || contains_ci(p, "/users/")) {
    return 2;
  }
  if (contains_ci(p, "appdata\\local\\temp") || contains_ci(p, "downloads")) return 2;
  return 0;
}

static AS_INV_UNUSED const char *risk_reason_for_path(const char *p) {
  return path_risk_level(p) > 0 ? "Executable or persistence path is under a user-writable/temp location" : "";
}

#ifdef _WIN32
static const char *svc_start_type_text(DWORD t) {
  switch (t) {
  case SERVICE_AUTO_START: return "auto";
  case SERVICE_BOOT_START: return "boot";
  case SERVICE_SYSTEM_START: return "system";
  case SERVICE_DEMAND_START: return "manual";
  case SERVICE_DISABLED: return "disabled";
  default: return "unknown";
  }
}

static const char *svc_state_text(DWORD s) {
  switch (s) {
  case SERVICE_RUNNING: return "running";
  case SERVICE_STOPPED: return "stopped";
  case SERVICE_PAUSED: return "paused";
  case SERVICE_START_PENDING: return "start_pending";
  case SERVICE_STOP_PENDING: return "stop_pending";
  default: return "unknown";
  }
}

static int win_service_path(SC_HANDLE scm, const char *name, char *path, size_t cap, char *acct, size_t acap,
                            DWORD *start_type) {
  SC_HANDLE svc;
  DWORD need = 0;
  QUERY_SERVICE_CONFIGA *cfg;
  path[0] = 0;
  acct[0] = 0;
  if (start_type) *start_type = 0;
  svc = OpenServiceA(scm, name, SERVICE_QUERY_CONFIG);
  if (!svc) return -1;
  (void)QueryServiceConfigA(svc, NULL, 0, &need);
  if (need == 0) {
    CloseServiceHandle(svc);
    return -1;
  }
  cfg = (QUERY_SERVICE_CONFIGA *)malloc(need);
  if (!cfg) {
    CloseServiceHandle(svc);
    return -1;
  }
  if (QueryServiceConfigA(svc, cfg, need, &need)) {
    snprintf(path, cap, "%s", cfg->lpBinaryPathName ? cfg->lpBinaryPathName : "");
    snprintf(acct, acap, "%s", cfg->lpServiceStartName ? cfg->lpServiceStartName : "");
    if (start_type) *start_type = cfg->dwStartType;
  }
  free(cfg);
  CloseServiceHandle(svc);
  return path[0] ? 0 : -1;
}

static void emit_windows_services(FILE *f, EdrAsurfInventorySummary *s) {
  SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
  DWORD need = 0, count = 0, resume = 0;
  ENUM_SERVICE_STATUS_PROCESSA *rows = NULL;
  int emitted = 0, truncated = 0;
  fprintf(f, "\"services\":{\"items\":[");
  if (scm) {
    (void)EnumServicesStatusExA(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, NULL, 0, &need, &count,
                                &resume, NULL);
    rows = (ENUM_SERVICE_STATUS_PROCESSA *)malloc(need ? need : 1u);
    resume = 0;
    if (rows && EnumServicesStatusExA(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, (LPBYTE)rows,
                                      need, &need, &count, &resume, NULL)) {
      for (DWORD i = 0; i < count; i++) {
        char path[768], acct[256];
        DWORD st = 0;
        int risk = 0;
        if (emitted >= AS_INV_SERVICES_MAX) { truncated = 1; break; }
        (void)win_service_path(scm, rows[i].lpServiceName, path, sizeof(path), acct, sizeof(acct), &st);
        risk = path_risk_level(path);
        if (st == SERVICE_AUTO_START) s->auto_start_service_count++;
        if (emitted) fputc(',', f);
        fprintf(f, "{\"id\":"); inv_json_escape(f, rows[i].lpServiceName);
        fprintf(f, ",\"name\":"); inv_json_escape(f, rows[i].lpServiceName);
        fprintf(f, ",\"displayName\":"); inv_json_escape(f, rows[i].lpDisplayName ? rows[i].lpDisplayName : "");
        fprintf(f, ",\"state\":"); inv_json_escape(f, svc_state_text(rows[i].ServiceStatusProcess.dwCurrentState));
        fprintf(f, ",\"startType\":"); inv_json_escape(f, svc_start_type_text(st));
        fprintf(f, ",\"account\":"); inv_json_escape(f, acct);
        fprintf(f, ",\"binaryPath\":"); inv_json_escape(f, path);
        fprintf(f, ",\"pid\":%lu", (unsigned long)rows[i].ServiceStatusProcess.dwProcessId);
        fprintf(f, ",\"riskLevel\":%d,\"riskReason\":", risk); inv_json_escape(f, risk_reason_for_path(path));
        fprintf(f, "}");
        emitted++;
      }
    }
    free(rows);
    CloseServiceHandle(scm);
  }
  s->service_count = emitted;
  fprintf(f, "],\"truncated\":%s},", truncated ? "true" : "false");
}

static void emit_windows_startup(FILE *f, EdrAsurfInventorySummary *s) {
  HKEY roots[2] = {HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER};
  const char *root_names[2] = {"HKLM", "HKCU"};
  const char *subkeys[2] = {"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                            "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"};
  int emitted = 0, truncated = 0;
  fprintf(f, "\"startupItems\":{\"items\":[");
  for (int r = 0; r < 2; r++) {
    for (int k = 0; k < 2; k++) {
      HKEY h = NULL;
      if (RegOpenKeyExA(roots[r], subkeys[k], 0, KEY_READ, &h) != ERROR_SUCCESS) continue;
      for (DWORD idx = 0;; idx++) {
        char name[256], val[1024];
        DWORD ncap = sizeof(name), vcap = sizeof(val), type = 0;
        LONG rr;
        if (emitted >= AS_INV_STARTUP_MAX) { truncated = 1; break; }
        rr = RegEnumValueA(h, idx, name, &ncap, NULL, &type, (LPBYTE)val, &vcap);
        if (rr != ERROR_SUCCESS) break;
        if (type != REG_SZ && type != REG_EXPAND_SZ) continue;
        val[sizeof(val) - 1] = 0;
        int risk = path_risk_level(val);
        if (risk > 0) s->persistence_finding_count++;
        if (emitted) fputc(',', f);
        fprintf(f, "{\"id\":"); inv_json_escape(f, name);
        fprintf(f, ",\"source\":");
        char src[256]; snprintf(src, sizeof(src), "%s\\%s", root_names[r], subkeys[k]); inv_json_escape(f, src);
        fprintf(f, ",\"name\":"); inv_json_escape(f, name);
        fprintf(f, ",\"command\":"); inv_json_escape(f, val);
        fprintf(f, ",\"enabled\":true,\"riskLevel\":%d,\"riskReason\":", risk); inv_json_escape(f, risk_reason_for_path(val));
        fprintf(f, "}");
        emitted++;
      }
      RegCloseKey(h);
      if (truncated) break;
    }
  }
  s->startup_item_count = emitted;
  fprintf(f, "],\"truncated\":%s},", truncated ? "true" : "false");
}

static void emit_windows_tasks(FILE *f, EdrAsurfInventorySummary *s) {
  char root[MAX_PATH];
  WIN32_FIND_DATAA fd;
  HANDLE h;
  int emitted = 0, truncated = 0;
  snprintf(root, sizeof(root), "%s\\System32\\Tasks\\*", getenv("WINDIR") ? getenv("WINDIR") : "C:\\Windows");
  fprintf(f, "\"scheduledTasks\":{\"items\":[");
  h = FindFirstFileA(root, &fd);
  if (h != INVALID_HANDLE_VALUE) {
    do {
      if (fd.cFileName[0] == '.') continue;
      if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
      if (emitted >= AS_INV_TASKS_MAX) { truncated = 1; break; }
      if (emitted) fputc(',', f);
      fprintf(f, "{\"id\":"); inv_json_escape(f, fd.cFileName);
      fprintf(f, ",\"path\":");
      char p[MAX_PATH]; snprintf(p, sizeof(p), "%s\\System32\\Tasks\\%s", getenv("WINDIR") ? getenv("WINDIR") : "C:\\Windows", fd.cFileName);
      inv_json_escape(f, p);
      fprintf(f, ",\"name\":"); inv_json_escape(f, fd.cFileName);
      fprintf(f, ",\"enabled\":true,\"principal\":\"\",\"triggers\":[\"task-scheduler\"],\"actions\":[],\"riskLevel\":1,\"riskReason\":\"Scheduled task definition present\"}");
      emitted++;
    } while (FindNextFileA(h, &fd));
    FindClose(h);
  }
  s->scheduled_task_count = emitted;
  s->enabled_scheduled_task_count = emitted;
  fprintf(f, "],\"truncated\":%s},", truncated ? "true" : "false");
}

static void wstr_to_utf8(const wchar_t *w, char *out, size_t cap) {
  if (!out || cap == 0u) return;
  out[0] = 0;
  if (!w) return;
  WideCharToMultiByte(CP_UTF8, 0, w, -1, out, (int)cap, NULL, NULL);
  out[cap - 1u] = 0;
}

static void emit_windows_accounts_groups(FILE *f, EdrAsurfInventorySummary *s) {
  DWORD level = 1, pref = MAX_PREFERRED_LENGTH, entries = 0, total = 0, user_resume = 0;
  LPUSER_INFO_1 users = NULL;
  int emitted = 0, trunc = 0;
  fprintf(f, "\"localAccounts\":{\"items\":[");
  if (NetUserEnum(NULL, level, FILTER_NORMAL_ACCOUNT, (LPBYTE *)&users, pref, &entries, &total,
                  &user_resume) == NERR_Success && users) {
    for (DWORD i = 0; i < entries; i++) {
      char name[256];
      int disabled = (users[i].usri1_flags & UF_ACCOUNTDISABLE) != 0;
      int priv = users[i].usri1_priv == USER_PRIV_ADMIN;
      if (emitted >= AS_INV_ACCOUNTS_MAX) { trunc = 1; break; }
      wstr_to_utf8(users[i].usri1_name, name, sizeof(name));
      if (priv) s->privileged_account_count++;
      if (emitted) fputc(',', f);
      fprintf(f, "{\"name\":"); inv_json_escape(f, name);
      fprintf(f, ",\"sid\":\"\",\"enabled\":%s,\"privileged\":%s,\"groups\":[],\"riskLevel\":%d,\"riskReason\":", disabled ? "false" : "true", priv ? "true" : "false", priv ? 3 : 0);
      inv_json_escape(f, priv ? "Local administrator account" : "");
      fprintf(f, "}");
      emitted++;
    }
    NetApiBufferFree(users);
  }
  fprintf(f, "],\"truncated\":%s},", trunc ? "true" : "false");

  LOCALGROUP_INFO_0 *groups = NULL;
  DWORD_PTR group_resume = 0;
  entries = total = 0;
  emitted = 0; trunc = 0;
  fprintf(f, "\"localGroups\":{\"items\":[");
  if (NetLocalGroupEnum(NULL, 0, (LPBYTE *)&groups, pref, &entries, &total,
                        &group_resume) == NERR_Success && groups) {
    for (DWORD i = 0; i < entries; i++) {
      char name[256];
      int priv;
      if (emitted >= AS_INV_GROUPS_MAX) { trunc = 1; break; }
      wstr_to_utf8(groups[i].lgrpi0_name, name, sizeof(name));
      priv = contains_ci(name, "Administrators") || contains_ci(name, "Remote Desktop") || contains_ci(name, "Backup Operators");
      if (priv) s->admin_group_member_count++;
      if (emitted) fputc(',', f);
      fprintf(f, "{\"name\":"); inv_json_escape(f, name);
      fprintf(f, ",\"sid\":\"\",\"memberCount\":0,\"members\":[],\"privileged\":%s,\"riskLevel\":%d,\"riskReason\":", priv ? "true" : "false", priv ? 2 : 0);
      inv_json_escape(f, priv ? "Privileged local group" : "");
      fprintf(f, "}");
      emitted++;
    }
    NetApiBufferFree(groups);
  }
  fprintf(f, "],\"truncated\":%s},", trunc ? "true" : "false");
}

static void emit_windows_shares(FILE *f, EdrAsurfInventorySummary *s) {
  SHARE_INFO_1 *shares = NULL;
  DWORD entries = 0, total = 0, resume = 0, pref = MAX_PREFERRED_LENGTH;
  int emitted = 0, trunc = 0;
  fprintf(f, "\"shares\":{\"items\":[");
  if (NetShareEnum(NULL, 1, (LPBYTE *)&shares, pref, &entries, &total, &resume) == NERR_Success && shares) {
    for (DWORD i = 0; i < entries; i++) {
      char name[256], remark[512];
      int admin;
      if (emitted >= AS_INV_SHARES_MAX) { trunc = 1; break; }
      wstr_to_utf8(shares[i].shi1_netname, name, sizeof(name));
      wstr_to_utf8(shares[i].shi1_remark, remark, sizeof(remark));
      admin = name[0] && name[strlen(name) - 1] == '$';
      if (emitted) fputc(',', f);
      fprintf(f, "{\"name\":"); inv_json_escape(f, name);
      fprintf(f, ",\"path\":\"\",\"type\":\"smb\",\"remark\":"); inv_json_escape(f, remark);
      fprintf(f, ",\"adminShare\":%s,\"riskLevel\":%d,\"riskReason\":", admin ? "true" : "false", admin ? 0 : 1);
      inv_json_escape(f, admin ? "" : "Non-admin SMB share present; review ACLs and write access");
      fprintf(f, "}");
      if (!admin) s->risky_share_count++;
      emitted++;
    }
    NetApiBufferFree(shares);
  }
  s->share_count = emitted;
  fprintf(f, "],\"truncated\":%s}", trunc ? "true" : "false");
}

#else
static FILE *run_reader(const char *cmd, const char *arg1, const char *arg2, pid_t *child_out) {
  int pfd[2];
  pid_t pid;
  if (child_out) *child_out = -1;
  if (pipe(pfd) != 0) return NULL;
  pid = fork();
  if (pid < 0) {
    close(pfd[0]); close(pfd[1]); return NULL;
  }
  if (pid == 0) {
    close(pfd[0]);
    (void)dup2(pfd[1], STDOUT_FILENO);
    close(pfd[1]);
    if (arg2) execlp(cmd, cmd, arg1, arg2, (char *)NULL);
    else if (arg1) execlp(cmd, cmd, arg1, (char *)NULL);
    else execlp(cmd, cmd, (char *)NULL);
    _exit(127);
  }
  close(pfd[1]);
  if (child_out) *child_out = pid;
  return fdopen(pfd[0], "r");
}

static void close_reader(FILE *fp, pid_t child) {
  if (fp) fclose(fp);
  if (child > 0) (void)waitpid(child, NULL, 0);
}

static void emit_linux_services(FILE *f, EdrAsurfInventorySummary *s) {
  pid_t child = -1;
  FILE *fp = run_reader("systemctl", "list-unit-files", "--type=service", &child);
  char line[1024];
  int emitted = 0, truncated = 0;
  fprintf(f, "\"services\":{\"items\":[");
  if (fp) {
    while (fgets(line, sizeof(line), fp)) {
      char unit[256], state[80];
      trim_line(line);
      if (!strstr(line, ".service")) continue;
      if (sscanf(line, "%255s %79s", unit, state) != 2) continue;
      if (emitted >= AS_INV_SERVICES_MAX) { truncated = 1; break; }
      if (strcmp(state, "enabled") == 0 || strcmp(state, "static") == 0) s->auto_start_service_count++;
      if (emitted) fputc(',', f);
      fprintf(f, "{\"id\":"); inv_json_escape(f, unit);
      fprintf(f, ",\"name\":"); inv_json_escape(f, unit);
      fprintf(f, ",\"displayName\":"); inv_json_escape(f, unit);
      fprintf(f, ",\"state\":\"unknown\",\"startType\":"); inv_json_escape(f, state);
      fprintf(f, ",\"account\":\"\",\"binaryPath\":\"\",\"pid\":null,\"riskLevel\":0,\"riskReason\":\"\"}");
      emitted++;
    }
  }
  close_reader(fp, child);
  s->service_count = emitted;
  fprintf(f, "],\"truncated\":%s},", truncated ? "true" : "false");
}

static void emit_linux_cron_tasks(FILE *f, EdrAsurfInventorySummary *s) {
  const char *paths[] = {"/etc/crontab", "/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly"};
  int emitted = 0, truncated = 0;
  fprintf(f, "\"scheduledTasks\":{\"items\":[");
  for (size_t pi = 0; pi < sizeof(paths) / sizeof(paths[0]); pi++) {
    struct stat st;
    if (stat(paths[pi], &st) != 0) continue;
    if (S_ISDIR(st.st_mode)) {
      DIR *d = opendir(paths[pi]);
      struct dirent *de;
      if (!d) continue;
      while ((de = readdir(d)) != NULL) {
        if (de->d_name[0] == '.') continue;
        if (emitted >= AS_INV_TASKS_MAX) { truncated = 1; break; }
        if (emitted) fputc(',', f);
        char id[512]; snprintf(id, sizeof(id), "%s/%s", paths[pi], de->d_name);
        fprintf(f, "{\"id\":"); inv_json_escape(f, id);
        fprintf(f, ",\"path\":"); inv_json_escape(f, id);
        fprintf(f, ",\"name\":"); inv_json_escape(f, de->d_name);
        fprintf(f, ",\"enabled\":true,\"principal\":\"root\",\"triggers\":[\"cron\"],\"actions\":[],\"riskLevel\":1,\"riskReason\":\"Cron/system periodic task present\"}");
        emitted++;
      }
      closedir(d);
    } else if (S_ISREG(st.st_mode)) {
      if (emitted >= AS_INV_TASKS_MAX) { truncated = 1; break; }
      if (emitted) fputc(',', f);
      fprintf(f, "{\"id\":"); inv_json_escape(f, paths[pi]);
      fprintf(f, ",\"path\":"); inv_json_escape(f, paths[pi]);
      fprintf(f, ",\"name\":"); inv_json_escape(f, paths[pi]);
      fprintf(f, ",\"enabled\":true,\"principal\":\"root\",\"triggers\":[\"cron\"],\"actions\":[],\"riskLevel\":1,\"riskReason\":\"System crontab present\"}");
      emitted++;
    }
    if (truncated) break;
  }
  s->scheduled_task_count = emitted;
  s->enabled_scheduled_task_count = emitted;
  fprintf(f, "],\"truncated\":%s},", truncated ? "true" : "false");
}

static void emit_linux_accounts_groups(FILE *f, EdrAsurfInventorySummary *s) {
  FILE *fp = fopen("/etc/passwd", "r");
  char line[1024];
  int emitted = 0, trunc = 0;
  fprintf(f, "\"localAccounts\":{\"items\":[");
  if (fp) {
    while (fgets(line, sizeof(line), fp)) {
      char *name, *x, *uid_s, *gid_s, *gecos, *home, *shell;
      int uid = -1, priv = 0;
      trim_line(line);
      name = strtok(line, ":"); x = strtok(NULL, ":"); uid_s = strtok(NULL, ":"); gid_s = strtok(NULL, ":");
      gecos = strtok(NULL, ":"); home = strtok(NULL, ":"); shell = strtok(NULL, ":");
      (void)x; (void)gid_s; (void)gecos;
      if (!name || !uid_s) continue;
      if (emitted >= AS_INV_ACCOUNTS_MAX) { trunc = 1; break; }
      uid = atoi(uid_s);
      priv = uid == 0;
      if (priv) s->privileged_account_count++;
      if (emitted) fputc(',', f);
      fprintf(f, "{\"name\":"); inv_json_escape(f, name);
      fprintf(f, ",\"sid\":\"\",\"enabled\":true,\"uid\":%d,\"home\":", uid); inv_json_escape(f, home ? home : "");
      fprintf(f, ",\"shell\":"); inv_json_escape(f, shell ? shell : "");
      fprintf(f, ",\"privileged\":%s,\"groups\":[],\"riskLevel\":%d,\"riskReason\":", priv ? "true" : "false", priv ? 3 : 0);
      inv_json_escape(f, priv ? "UID 0 account" : "");
      fprintf(f, "}");
      emitted++;
    }
    fclose(fp);
  }
  fprintf(f, "],\"truncated\":%s},", trunc ? "true" : "false");

  fp = fopen("/etc/group", "r");
  emitted = 0; trunc = 0;
  fprintf(f, "\"localGroups\":{\"items\":[");
  if (fp) {
    while (fgets(line, sizeof(line), fp)) {
      char *name, *x, *gid_s, *members;
      int priv = 0;
      trim_line(line);
      name = strtok(line, ":"); x = strtok(NULL, ":"); gid_s = strtok(NULL, ":"); members = strtok(NULL, ":");
      (void)x; (void)gid_s;
      if (!name) continue;
      if (emitted >= AS_INV_GROUPS_MAX) { trunc = 1; break; }
      priv = strcmp(name, "sudo") == 0 || strcmp(name, "wheel") == 0 || strcmp(name, "docker") == 0 || strcmp(name, "lxd") == 0;
      if (priv && members && members[0]) s->admin_group_member_count++;
      if (emitted) fputc(',', f);
      fprintf(f, "{\"name\":"); inv_json_escape(f, name);
      fprintf(f, ",\"sid\":\"\",\"memberCount\":%d,\"membersRaw\":", members && members[0] ? 1 : 0); inv_json_escape(f, members ? members : "");
      fprintf(f, ",\"privileged\":%s,\"riskLevel\":%d,\"riskReason\":", priv ? "true" : "false", priv ? 2 : 0);
      inv_json_escape(f, priv ? "Privileged local group" : "");
      fprintf(f, "}");
      emitted++;
    }
    fclose(fp);
  }
  fprintf(f, "],\"truncated\":%s},", trunc ? "true" : "false");
}

static void emit_linux_startup(FILE *f, EdrAsurfInventorySummary *s) {
  const char *paths[] = {"/etc/rc.local", "/etc/profile", "/etc/profile.d"};
  int emitted = 0, trunc = 0;
  fprintf(f, "\"startupItems\":{\"items\":[");
  for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
    struct stat st;
    if (stat(paths[i], &st) != 0) continue;
    if (emitted >= AS_INV_STARTUP_MAX) { trunc = 1; break; }
    if (emitted) fputc(',', f);
    fprintf(f, "{\"id\":"); inv_json_escape(f, paths[i]);
    fprintf(f, ",\"source\":\"linux-startup\",\"name\":"); inv_json_escape(f, paths[i]);
    fprintf(f, ",\"command\":"); inv_json_escape(f, paths[i]);
    fprintf(f, ",\"enabled\":true,\"riskLevel\":1,\"riskReason\":\"Startup path present\"}");
    emitted++;
  }
  s->startup_item_count = emitted;
  fprintf(f, "],\"truncated\":%s},", trunc ? "true" : "false");
}

static void emit_linux_shares(FILE *f, EdrAsurfInventorySummary *s) {
  const char *paths[] = {"/etc/samba/smb.conf", "/etc/exports"};
  int emitted = 0;
  fprintf(f, "\"shares\":{\"items\":[");
  for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
    struct stat st;
    if (stat(paths[i], &st) != 0) continue;
    if (emitted) fputc(',', f);
    fprintf(f, "{\"name\":"); inv_json_escape(f, i == 0 ? "samba-config" : "nfs-exports");
    fprintf(f, ",\"path\":"); inv_json_escape(f, paths[i]);
    fprintf(f, ",\"type\":"); inv_json_escape(f, i == 0 ? "smb" : "nfs");
    fprintf(f, ",\"remark\":\"share configuration present\",\"adminShare\":false,\"riskLevel\":1,\"riskReason\":\"Review share configuration for guest/write/no_root_squash exposure\"}");
    emitted++;
  }
  s->share_count = emitted;
  fprintf(f, "],\"truncated\":false}");
}
#endif

void edr_asurf_inventory_write_json(FILE *f, int listeners_only, EdrAsurfInventorySummary *summary) {
  EdrAsurfInventorySummary zero;
  if (!summary) summary = &zero;
  memset(summary, 0, sizeof(*summary));
  if (listeners_only) {
    fprintf(f, "\"services\":{\"items\":[],\"truncated\":false},");
    fprintf(f, "\"scheduledTasks\":{\"items\":[],\"truncated\":false},");
    fprintf(f, "\"startupItems\":{\"items\":[],\"truncated\":false},");
    fprintf(f, "\"localAccounts\":{\"items\":[],\"truncated\":false},");
    fprintf(f, "\"localGroups\":{\"items\":[],\"truncated\":false},");
    fprintf(f, "\"shares\":{\"items\":[],\"truncated\":false}");
    return;
  }
#ifdef _WIN32
  emit_windows_services(f, summary);
  emit_windows_tasks(f, summary);
  emit_windows_startup(f, summary);
  emit_windows_accounts_groups(f, summary);
  emit_windows_shares(f, summary);
#else
  emit_linux_services(f, summary);
  emit_linux_cron_tasks(f, summary);
  emit_linux_startup(f, summary);
  emit_linux_accounts_groups(f, summary);
  emit_linux_shares(f, summary);
#endif
}
