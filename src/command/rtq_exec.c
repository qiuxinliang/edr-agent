#include <ctype.h>
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
#else
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#include "edr/command_util.h"
#include "edr/response.h"
#include "edr/sha256.h"
#include "edr/shell_exec.h"

#define RTQ_MAX_RESULTS    500
#define RTQ_MAX_RESULT_STR (128 * 1024)
#define RTQ_FILE_HASH_MAX  (64 * 1024 * 1024)
#define RTQ_FILE_SCAN_MAX  2000
#define RTQ_FILE_SCAN_DEPTH 3

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
        if (edr_parse_json_int(pl, len, "process_pid_min", &v) && v >= 0) {
            f->has_process = 1; f->process_pid_min = v;
        }
    }
    {
        int v = 0;
        if (edr_parse_json_int(pl, len, "process_pid_max", &v) && v > 0) {
            f->has_process = 1; f->process_pid_max = v;
        }
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

static void append_json_escaped(char *buf, int cap, int *offset, const char *s) {
    if (!buf || !offset || *offset >= cap || !s) return;
    for (const char *p = s; *p && *offset < cap - 2; p++) {
        unsigned char ch = (unsigned char)*p;
        if (ch == '"' || ch == '\\') {
            if (*offset < cap - 2) buf[(*offset)++] = '\\';
            buf[(*offset)++] = (char)ch;
        } else if (ch == '\n') {
            if (*offset < cap - 3) {
                buf[(*offset)++] = '\\';
                buf[(*offset)++] = 'n';
            }
        } else if (ch == '\r') {
            if (*offset < cap - 3) {
                buf[(*offset)++] = '\\';
                buf[(*offset)++] = 'r';
            }
        } else if (ch == '\t') {
            if (*offset < cap - 3) {
                buf[(*offset)++] = '\\';
                buf[(*offset)++] = 't';
            }
        } else if (ch >= 32) {
            buf[(*offset)++] = (char)ch;
        }
    }
    if (*offset < cap) buf[*offset] = '\0';
}

static void append_json_kv_str(char *buf, int cap, int *offset, const char *key, const char *value) {
    *offset += snprintf(buf + *offset, (size_t)(cap - *offset), ",\"%s\":\"", key);
    append_json_escaped(buf, cap, offset, value ? value : "");
    *offset += snprintf(buf + *offset, (size_t)(cap - *offset), "\"");
}

static int str_contains_icase(const char *haystack, const char *needle);

static int file_has_ext(const char *path, const char *ext) {
    if (!ext || !ext[0]) return 1;
    if (!path) return 0;
    const char *dot = strrchr(path, '.');
    if (!dot) return 0;
    return str_contains_icase(dot, ext);
}

static int hash_file_if_needed(const char *path, const char *expected, char out65[65]) {
    out65[0] = '\0';
    if (!expected || !expected[0]) return 1;
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return 0; }
    long sz = ftell(f);
    if (sz < 0 || sz > RTQ_FILE_HASH_MAX) { fclose(f); return 0; }
    rewind(f);
    uint8_t *buf = (uint8_t *)malloc((size_t)sz);
    if (!buf) { fclose(f); return 0; }
    size_t got = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (got != (size_t)sz) { free(buf); return 0; }
    edr_sha256_hex(buf, (size_t)sz, out65);
    free(buf);
    return str_contains_icase(out65, expected);
}

#ifndef _WIN32
static int append_file_result(rtq_filter *f, const char *path, char *buf, int cap, int *offset, int *total) {
    if (!path || !path[0] || *total >= RTQ_MAX_RESULTS || *offset >= cap - 512) return 0;
    if (f->file_path[0] && !str_contains_icase(path, f->file_path)) return 0;
    if (!file_has_ext(path, f->file_ext)) return 0;

    struct stat st;
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode)) return 0;
    if (f->file_size_min > 0 && (long long)st.st_size < f->file_size_min) return 0;
    if (f->file_size_max > 0 && (long long)st.st_size > f->file_size_max) return 0;

    char sha[65] = {0};
    if (!hash_file_if_needed(path, f->file_sha256, sha)) return 0;
    if (*total > 0) *offset += snprintf(buf + *offset, (size_t)(cap - *offset), ",");
    *offset += snprintf(buf + *offset, (size_t)(cap - *offset), "{\"type\":\"file\",\"path\":\"");
    append_json_escaped(buf, cap, offset, path);
    *offset += snprintf(buf + *offset, (size_t)(cap - *offset), "\",\"size\":%lld", (long long)st.st_size);
    if (sha[0]) append_json_kv_str(buf, cap, offset, "sha256", sha);
    *offset += snprintf(buf + *offset, (size_t)(cap - *offset), "}");
    (*total)++;
    return 1;
}

static void scan_files_limited(rtq_filter *f, const char *root, int depth, int *scanned,
                               char *buf, int cap, int *offset, int *total) {
    if (!root || !root[0] || depth < 0 || *scanned >= RTQ_FILE_SCAN_MAX || *total >= RTQ_MAX_RESULTS) return;
    struct stat st;
    if (stat(root, &st) != 0) return;
    if (S_ISREG(st.st_mode)) {
        (*scanned)++;
        (void)append_file_result(f, root, buf, cap, offset, total);
        return;
    }
    if (!S_ISDIR(st.st_mode)) return;
    DIR *d = opendir(root);
    if (!d) return;
    struct dirent *de;
    while ((de = readdir(d)) != NULL && *scanned < RTQ_FILE_SCAN_MAX && *total < RTQ_MAX_RESULTS) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) continue;
        char child[1024];
        snprintf(child, sizeof(child), "%s/%s", root, de->d_name);
        scan_files_limited(f, child, depth - 1, scanned, buf, cap, offset, total);
    }
    closedir(d);
}
#endif

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
            char name[260] = {0};
            WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, name, sizeof(name), NULL, NULL);

            int ok = 1;
            if (f->process_name[0] && !str_contains_icase(name, f->process_name)) ok = 0;
            if (f->process_pid_max > 0 && (int)pe.th32ProcessID > f->process_pid_max) ok = 0;
            if (f->process_pid_min > 0 && (int)pe.th32ProcessID < f->process_pid_min) ok = 0;
            if (f->process_cmdline[0] || f->process_user[0]) ok = 0;

            char path[520] = {0};
            if (ok && f->process_path[0]) {
                HANDLE hp = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
                if (hp) {
                    DWORD sz = sizeof(path);
                    if (!QueryFullProcessImageNameA(hp, 0, path, &sz)) path[0] = '\0';
                    CloseHandle(hp);
                }
                if (!path[0] || !str_contains_icase(path, f->process_path)) ok = 0;
            }

            if (ok && count < RTQ_MAX_RESULTS && *offset < cap - 512) {
                if (count > 0) *offset += snprintf(buf + *offset, (size_t)(cap - *offset), ",");
                *offset += snprintf(buf + *offset, (size_t)(cap - *offset),
                    "{\"type\":\"process\",\"pid\":%lu,\"name\":\"", (unsigned long)pe.th32ProcessID);
                append_json_escaped(buf, cap, offset, name);
                *offset += snprintf(buf + *offset, (size_t)(cap - *offset), "\",\"ppid\":%lu",
                    (unsigned long)pe.th32ParentProcessID);
                if (path[0]) append_json_kv_str(buf, cap, offset, "path", path);
                *offset += snprintf(buf + *offset, (size_t)(cap - *offset), "}");
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
#else
static void read_proc_exe_path(int pid, char *out, size_t out_cap) {
    if (!out || out_cap == 0) return;
    out[0] = '\0';
    char link_path[64];
    snprintf(link_path, sizeof(link_path), "/proc/%d/exe", pid);
    ssize_t n = readlink(link_path, out, out_cap - 1);
    if (n > 0) out[n] = '\0';
}

static int match_processes(rtq_filter *f, char *buf, int cap, int *offset, int *total) {
    FILE *p = popen("ps -eo pid,ppid,user,comm,args 2>/dev/null", "r");
    if (!p) return 0;

    int count = 0;
    char line[4096];
    while (fgets(line, sizeof(line), p) && *total < RTQ_MAX_RESULTS) {
        int loc_pid = 0, loc_ppid = 0;
        char loc_user[64] = {0}, loc_comm[256] = {0};
        char rest[2560] = {0};
        (void)sscanf(line, "%d %d %63s %255s %2559[^\n]",
            &loc_pid, &loc_ppid, loc_user, loc_comm, rest);
        if (loc_pid <= 0) continue;

        char path[1024] = {0};
        if (f->process_path[0]) read_proc_exe_path(loc_pid, path, sizeof(path));

        int ok = 1;
        if (f->process_name[0] && !str_contains_icase(loc_comm, f->process_name)) ok = 0;
        if (f->process_user[0] && !str_contains_icase(loc_user, f->process_user)) ok = 0;
        if (f->process_pid_max > 0 && loc_pid > f->process_pid_max) ok = 0;
        if (f->process_pid_min > 0 && loc_pid < f->process_pid_min) ok = 0;
        if (f->process_cmdline[0] && !str_contains_icase(rest, f->process_cmdline)) ok = 0;
        if (f->process_path[0] && !str_contains_icase(path, f->process_path)) ok = 0;
        if (!ok || *offset >= cap - 1024) continue;

        if (*total > 0) *offset += snprintf(buf + *offset, (size_t)(cap - *offset), ",");
        *offset += snprintf(buf + *offset, (size_t)(cap - *offset),
            "{\"type\":\"process\",\"pid\":%d,\"ppid\":%d,\"name\":\"", loc_pid, loc_ppid);
        append_json_escaped(buf, cap, offset, loc_comm);
        append_json_kv_str(buf, cap, offset, "user", loc_user);
        append_json_kv_str(buf, cap, offset, "cmdline", rest);
        if (path[0]) append_json_kv_str(buf, cap, offset, "path", path);
        *offset += snprintf(buf + *offset, (size_t)(cap - *offset), "}");
        (*total)++;
        count++;
    }
    pclose(p);
    return count;
}

static void strip_brackets(char *s) {
    size_t n;
    if (!s) return;
    n = strlen(s);
    if (n >= 2 && s[0] == '[' && s[n - 1] == ']') {
        memmove(s, s + 1, n - 2);
        s[n - 2] = '\0';
    }
}

static int is_port_text(const char *s) {
    if (!s || !s[0]) return 0;
    if (strcmp(s, "*") == 0) return 1;
    for (const char *p = s; *p; p++) {
        if (!isdigit((unsigned char)*p)) return 0;
    }
    return 1;
}

static int split_addr_port(const char *addr, char *ip, size_t ip_cap, int *port) {
    if (!addr || !ip || ip_cap == 0 || !port) return 0;
    ip[0] = '\0';
    *port = 0;
    char tmp[256];
    snprintf(tmp, sizeof(tmp), "%s", addr);

    char *sep = strrchr(tmp, ':');
    if (!sep || !sep[1] || !is_port_text(sep + 1)) {
        sep = strrchr(tmp, '.');
    }
    if (!sep || !sep[1] || !is_port_text(sep + 1)) {
        snprintf(ip, ip_cap, "%s", tmp);
        strip_brackets(ip);
        return 0;
    }

    *sep = '\0';
    snprintf(ip, ip_cap, "%s", tmp);
    strip_brackets(ip);
    if (strcmp(sep + 1, "*") != 0) *port = atoi(sep + 1);
    return *port > 0;
}

static void extract_ss_process(const char *tail, char *proc, size_t proc_cap, int *pid) {
    if (proc && proc_cap > 0) proc[0] = '\0';
    if (pid) *pid = 0;
    if (!tail) return;

    const char *q = strchr(tail, '"');
    if (q && proc && proc_cap > 0) {
        const char *e = strchr(q + 1, '"');
        if (e && e > q + 1) {
            size_t n = (size_t)(e - q - 1);
            if (n >= proc_cap) n = proc_cap - 1;
            memcpy(proc, q + 1, n);
            proc[n] = '\0';
        }
    }
    const char *p = strstr(tail, "pid=");
    if (p && pid) *pid = atoi(p + 4);
}

static int append_network_result(rtq_filter *f, const char *proto, const char *state,
                                 const char *local_addr, const char *remote_addr,
                                 const char *tail, char *buf, int cap, int *offset, int *total) {
    char remote_ip[128] = {0};
    int remote_port = 0;
    split_addr_port(remote_addr, remote_ip, sizeof(remote_ip), &remote_port);

    if (f->network_proto[0] && !str_contains_icase(proto, f->network_proto)) return 0;
    if (f->network_state[0] && !str_contains_icase(state, f->network_state)) return 0;
    if (f->network_remote_ip[0] &&
        !str_contains_icase(remote_ip, f->network_remote_ip) &&
        !str_contains_icase(remote_addr, f->network_remote_ip)) return 0;
    if (f->network_remote_port > 0 && remote_port != f->network_remote_port) return 0;
    if (*total >= RTQ_MAX_RESULTS || *offset >= cap - 1024) return 0;

    char local_ip[128] = {0};
    int local_port = 0;
    char proc[128] = {0};
    int pid = 0;
    split_addr_port(local_addr, local_ip, sizeof(local_ip), &local_port);
    extract_ss_process(tail, proc, sizeof(proc), &pid);

    if (*total > 0) *offset += snprintf(buf + *offset, (size_t)(cap - *offset), ",");
    *offset += snprintf(buf + *offset, (size_t)(cap - *offset), "{\"type\":\"network\"");
    append_json_kv_str(buf, cap, offset, "proto", proto);
    append_json_kv_str(buf, cap, offset, "state", state);
    append_json_kv_str(buf, cap, offset, "local_addr", local_addr);
    append_json_kv_str(buf, cap, offset, "local_ip", local_ip);
    if (local_port > 0) *offset += snprintf(buf + *offset, (size_t)(cap - *offset), ",\"local_port\":%d", local_port);
    append_json_kv_str(buf, cap, offset, "remote_addr", remote_addr);
    append_json_kv_str(buf, cap, offset, "remote_ip", remote_ip);
    if (remote_port > 0) *offset += snprintf(buf + *offset, (size_t)(cap - *offset), ",\"remote_port\":%d", remote_port);
    if (pid > 0) *offset += snprintf(buf + *offset, (size_t)(cap - *offset), ",\"pid\":%d", pid);
    if (proc[0]) append_json_kv_str(buf, cap, offset, "process_name", proc);
    *offset += snprintf(buf + *offset, (size_t)(cap - *offset), "}");
    (*total)++;
    return 1;
}

static int scan_ss_network(rtq_filter *f, char *buf, int cap, int *offset, int *total) {
    FILE *p = popen("ss -tunapH 2>/dev/null", "r");
    if (!p) return 0;

    int count = 0;
    char line[2048];
    while (fgets(line, sizeof(line), p) && *total < RTQ_MAX_RESULTS) {
        char proto[16] = {0}, state[32] = {0}, recvq[32] = {0}, sendq[32] = {0};
        char local_addr[256] = {0}, remote_addr[256] = {0}, tail[1024] = {0};
        int n = sscanf(line, "%15s %31s %31s %31s %255s %255s %1023[^\n]",
                       proto, state, recvq, sendq, local_addr, remote_addr, tail);
        if (n < 6) continue;
        if (append_network_result(f, proto, state, local_addr, remote_addr, tail, buf, cap, offset, total)) {
            count++;
        }
    }
    pclose(p);
    return count;
}

static int scan_netstat_network(rtq_filter *f, char *buf, int cap, int *offset, int *total) {
    FILE *p = popen("netstat -an 2>/dev/null", "r");
    if (!p) return 0;

    int count = 0;
    char line[2048];
    while (fgets(line, sizeof(line), p) && *total < RTQ_MAX_RESULTS) {
        char proto[16] = {0}, recvq[32] = {0}, sendq[32] = {0};
        char local_addr[256] = {0}, remote_addr[256] = {0}, state[32] = {0}, tail[1024] = {0};
        int n = sscanf(line, "%15s %31s %31s %255s %255s %31s %1023[^\n]",
                       proto, recvq, sendq, local_addr, remote_addr, state, tail);
        if (n < 5 || (!str_contains_icase(proto, "tcp") && !str_contains_icase(proto, "udp"))) continue;
        if (n < 6) snprintf(state, sizeof(state), "%s", "");
        if (append_network_result(f, proto, state, local_addr, remote_addr, tail, buf, cap, offset, total)) {
            count++;
        }
    }
    pclose(p);
    return count;
}

static int match_network(rtq_filter *f, char *buf, int cap, int *offset, int *total) {
    int count = scan_ss_network(f, buf, cap, offset, total);
    if (count == 0) count += scan_netstat_network(f, buf, cap, offset, total);
    return count;
}

static int match_files(rtq_filter *f, char *buf, int cap, int *offset, int *total) {
    int scanned = 0;
    int before = *total;
    if (f->file_path[0]) {
        scan_files_limited(f, f->file_path, RTQ_FILE_SCAN_DEPTH, &scanned, buf, cap, offset, total);
    } else if (f->file_ext[0]) {
        scan_files_limited(f, "/tmp", RTQ_FILE_SCAN_DEPTH, &scanned, buf, cap, offset, total);
        scan_files_limited(f, "/var/tmp", RTQ_FILE_SCAN_DEPTH, &scanned, buf, cap, offset, total);
    }
    return *total - before;
}
#endif

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
        (void)match_processes(&filter, result, RTQ_MAX_RESULT_STR, &offset, &total);
    }
    if (has_net) {
        (void)match_network(&filter, result, RTQ_MAX_RESULT_STR, &offset, &total);
    }
    if (has_file) {
        (void)match_files(&filter, result, RTQ_MAX_RESULT_STR, &offset, &total);
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
