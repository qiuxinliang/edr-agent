#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#include <tlhelp32.h>
#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#endif

#include "edr/command_util.h"
#include "edr/response.h"

#define RTQ_MAX_RESULTS    500
#define RTQ_MAX_RESULT_STR (128 * 1024)

typedef struct rtq_filter {
    int has_process;
    char process_name[260];
    char process_path[520];
    char process_cmdline[4096];
    char process_user[128];
    int process_pid_min;
    int process_pid_max;

    int has_network;
    char network_remote_ip[64];
    int network_remote_port;
    char network_state[32];
    char network_proto[16];

    int has_file;
    char file_path[520];
    char file_sha256[65];
    char file_ext[16];
    long long file_size_min;
    long long file_size_max;
} rtq_filter;

static int parse_rtq_filter(const uint8_t *pl, size_t len, rtq_filter *f) {
    (void)pl; (void)len;
    memset(f, 0, sizeof(*f));

    {
        char v[260] = {0};
        edr_parse_json_string(pl, len, "process_name", v, sizeof(v));
        if (v[0]) { f->has_process = 1; snprintf(f->process_name, sizeof(f->process_name), "%s", v); }
    }
    {
        char v[520] = {0};
        edr_parse_json_string(pl, len, "process_path", v, sizeof(v));
        if (v[0]) { f->has_process = 1; snprintf(f->process_path, sizeof(f->process_path), "%s", v); }
    }
    {
        char v[4096] = {0};
        edr_parse_json_string(pl, len, "process_cmdline", v, sizeof(v));
        if (v[0]) { f->has_process = 1; snprintf(f->process_cmdline, sizeof(f->process_cmdline), "%s", v); }
    }
    {
        char v[128] = {0};
        edr_parse_json_string(pl, len, "process_user", v, sizeof(v));
        if (v[0]) { f->has_process = 1; snprintf(f->process_user, sizeof(f->process_user), "%s", v); }
    }
    {
        int v = 0;
        edr_parse_json_int(pl, len, "process_pid_min", &v);
        if (v >= 0) { f->has_process = 1; f->process_pid_min = v; }
    }
    {
        int v = 0;
        edr_parse_json_int(pl, len, "process_pid_max", &v);
        if (v > 0) { f->has_process = 1; f->process_pid_max = v; }
    }

    {
        char v[64] = {0};
        edr_parse_json_string(pl, len, "network_remote_ip", v, sizeof(v));
        if (v[0]) { f->has_network = 1; snprintf(f->network_remote_ip, sizeof(f->network_remote_ip), "%s", v); }
    }
    {
        int v = 0;
        edr_parse_json_int(pl, len, "network_remote_port", &v);
        if (v > 0) { f->has_network = 1; f->network_remote_port = v; }
    }
    {
        char v[32] = {0};
        edr_parse_json_string(pl, len, "network_state", v, sizeof(v));
        if (v[0]) { f->has_network = 1; snprintf(f->network_state, sizeof(f->network_state), "%s", v); }
    }
    {
        char v[16] = {0};
        edr_parse_json_string(pl, len, "network_proto", v, sizeof(v));
        if (v[0]) { f->has_network = 1; snprintf(f->network_proto, sizeof(f->network_proto), "%s", v); }
    }

    {
        char v[520] = {0};
        edr_parse_json_string(pl, len, "file_path", v, sizeof(v));
        if (v[0]) { f->has_file = 1; snprintf(f->file_path, sizeof(f->file_path), "%s", v); }
    }
    {
        char v[65] = {0};
        edr_parse_json_string(pl, len, "file_sha256", v, sizeof(v));
        if (v[0]) { f->has_file = 1; snprintf(f->file_sha256, sizeof(f->file_sha256), "%s", v); }
    }
    {
        char v[16] = {0};
        edr_parse_json_string(pl, len, "file_ext", v, sizeof(v));
        if (v[0]) { f->has_file = 1; snprintf(f->file_ext, sizeof(f->file_ext), "%s", v); }
    }

    return (f->has_process || f->has_network || f->has_file) ? 0 : -1;
}

static int str_contains_icase(const char *haystack, const char *needle) {
    if (!needle || !needle[0]) return 1;
    if (!haystack) return 0;
#ifdef _WIN32
    char *a = _strdup(haystack);
    char *b = _strdup(needle);
    if (!a || !b) { free(a); free(b); return 0; }
    for (char *p = a; *p; p++) *p = (char)tolower((unsigned char)*p);
    for (char *p = b; *p; p++) *p = (char)tolower((unsigned char)*p);
    char *found = strstr(a, b);
    free(a); free(b);
    return found ? 1 : 0;
#else
    char *a = strdup(haystack);
    char *b = strdup(needle);
    if (!a || !b) { free(a); free(b); return 0; }
    for (char *p = a; *p; p++) *p = (char)tolower((unsigned char)*p);
    for (char *p = b; *p; p++) *p = (char)tolower((unsigned char)*p);
    char *found = strstr(a, b);
    free(a); free(b);
    return found ? 1 : 0;
#endif
}

#ifdef _WIN32
static int match_processes(rtq_filter *f, char *buf, int cap, int *offset) {
    HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (h == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    int count = 0;
    if (Process32FirstW(h, &pe)) {
        do {
            char name[260] = {0}, cmdline[4096] = {0};
            WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, name, sizeof(name), NULL, NULL);

            int ok = 1;
            if (f->process_name[0] && !str_contains_icase(name, f->process_name)) ok = 0;
            if (f->process_pid_max > 0 && (int)pe.th32ProcessID > f->process_pid_max) ok = 0;
            if (f->process_pid_min > 0 && (int)pe.th32ProcessID < f->process_pid_min) ok = 0;

            if (ok && count < RTQ_MAX_RESULTS && *offset < cap - 512) {
                if (count > 0) *offset += snprintf(buf + *offset, (size_t)(cap - *offset), ",");
                *offset += snprintf(buf + *offset, (size_t)(cap - *offset),
                    "{\"type\":\"process\",\"pid\":%lu,\"name\":\"", (unsigned long)pe.th32ProcessID);
                for (const char *p = name; *p; p++) {
                    if (*p == '"' || *p == '\\') buf[(*offset)++] = '\\';
                    buf[(*offset)++] = *p;
                }
                *offset += snprintf(buf + *offset, (size_t)(cap - *offset), "\",\"ppid\":%lu}",
                    (unsigned long)pe.th32ParentProcessID);
                count++;
            }
        } while (Process32NextW(h, &pe));
    }
    CloseHandle(h);
    return count;
}

static int match_network(rtq_filter *f, char *buf, int cap, int *offset) {
    (void)f; (void)buf; (void)cap; (void)offset;
    return 0;
}
#endif

static int execute_rtq_local(char *result_buf, int cap) {
    int offset = 0;
    int total = 0;
    offset += snprintf(result_buf + offset, (size_t)(cap - offset), "{\"results\":[\n");

    rtq_filter filter;
    memset(&filter, 0, sizeof(filter));

    if (filter.has_process) {
#ifdef _WIN32
        int n = match_processes(&filter, result_buf, cap, &offset);
        if (n >= 0) total += n;
#else
        (void)&filter;
#endif
    }

    offset += snprintf(result_buf + offset, (size_t)(cap - offset), "\n],\"total\":%d}", total);
    return total;
}

void edr_response_rtq_execute(const char *cmd_id, const uint8_t *pl,
                               size_t len, const EdrSoarCommandMeta *sm) {
    if (!edr_command_dangerous_enabled()) {
        g_cmd_rejected++;
        edr_command_audit_both(cmd_id, "reject rtq_execute: policy disabled");
        edr_command_emit_always(cmd_id, sm, EdrCmdExecRejected, 1, "policy disabled");
        return;
    }

    rtq_filter filter;
    if (parse_rtq_filter(pl, len, &filter) != 0) {
        g_cmd_exec_fail++;
        edr_command_audit_both(cmd_id, "rtq_execute: no filter conditions");
        edr_command_emit_always(cmd_id, sm, EdrCmdExecFailed, 2, "no filter conditions");
        return;
    }

    char *result = (char *)malloc(RTQ_MAX_RESULT_STR);
    if (!result) {
        g_cmd_exec_fail++;
        edr_command_emit_always(cmd_id, sm, EdrCmdExecFailed, 3, "oom");
        return;
    }

    int offset = 0;
    int total = 0;
    int has_proc = filter.has_process;
    int has_net = filter.has_network;
    int has_file = filter.has_file;

    offset += snprintf(result + offset, (size_t)(RTQ_MAX_RESULT_STR - offset),
        "{\"results\":[\n");

#ifdef _WIN32
    if (has_proc) {
        int n = match_processes(&filter, result, RTQ_MAX_RESULT_STR, &offset);
        if (n >= 0) total += n;
    }
    if (has_net) {
        int n = match_network(&filter, result, RTQ_MAX_RESULT_STR, &offset);
        if (n >= 0) total += n;
    }
#else
    if (has_proc) {
        FILE *p = popen("ps -eo pid,ppid,user,comm,args --no-headers 2>/dev/null", "r");
        if (p) {
            char line[4096];
            while (fgets(line, sizeof(line), p) && total < RTQ_MAX_RESULTS) {
                int loc_pid = 0, loc_ppid = 0;
                char loc_user[64] = {0}, loc_comm[256] = {0};
                char rest[2560] = {0};
                (void)sscanf(line, "%d %d %63s %255s %2559[^\n]",
                    &loc_pid, &loc_ppid, loc_user, loc_comm, rest);
                int ok = 1;
                if (filter.process_name[0] && !str_contains_icase(loc_comm, filter.process_name)) ok = 0;
                if (filter.process_user[0] && !str_contains_icase(loc_user, filter.process_user)) ok = 0;
                if (filter.process_pid_max > 0 && loc_pid > filter.process_pid_max) ok = 0;
                if (filter.process_pid_min > 0 && loc_pid < filter.process_pid_min) ok = 0;
                if (filter.process_cmdline[0] && !str_contains_icase(rest, filter.process_cmdline)) ok = 0;
                if (ok) {
                    if (total > 0) offset += snprintf(result + offset, (size_t)(RTQ_MAX_RESULT_STR - offset), ",");
                    offset += snprintf(result + offset, (size_t)(RTQ_MAX_RESULT_STR - offset),
                        "{\"type\":\"process\",\"pid\":%d,\"name\":\"", loc_pid);
                    for (const char *q = loc_comm; *q; q++) {
                        if (*q == '"' || *q == '\\') result[offset++] = '\\';
                        result[offset++] = *q;
                    }
                    offset += snprintf(result + offset, (size_t)(RTQ_MAX_RESULT_STR - offset),
                        "\",\"user\":\"%s\"}", loc_user);
                    total++;
                }
            }
            pclose(p);
        }
    }
    if (has_net) {
        FILE *p = popen("ss -tunap 2>/dev/null || netstat -an 2>/dev/null", "r");
        if (p) {
            char line[1024];
            int net_count = total;
            while (fgets(line, sizeof(line), p) && total < RTQ_MAX_RESULTS) {
                if (total > net_count) {
                    offset += snprintf(result + offset, (size_t)(RTQ_MAX_RESULT_STR - offset), ",");
                    offset += snprintf(result + offset, (size_t)(RTQ_MAX_RESULT_STR - offset),
                        "{\"type\":\"network\",\"line\":\"");
                    for (const char *q = line; *q; q++) {
                        if (*q == '\n' || *q == '\r') break;
                        if (*q == '"' || *q == '\\') result[offset++] = '\\';
                        result[offset++] = *q;
                    }
                    offset += snprintf(result + offset, (size_t)(RTQ_MAX_RESULT_STR - offset), "\"}");
                    total++;
                }
            }
            pclose(p);
        }
    }
#endif
    (void)has_file;

    offset += snprintf(result + offset, (size_t)(RTQ_MAX_RESULT_STR - offset),
        "\n],\"total\":%d,\"error\":null}", total);

    g_cmd_handled++; g_cmd_exec_ok++;
    edr_command_audit_both(cmd_id, "rtq_execute: ok");
    edr_command_emit_always(cmd_id, sm, EdrCmdExecOk, 0, result);
    free(result);
}
