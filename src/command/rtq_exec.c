#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include <tlhelp32.h>
#include <iphlpapi.h>
#include <winevt.h>
#include <wintrust.h>
#include <softpub.h>
#ifdef _MSC_VER
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "wevtapi.lib")
#endif
#else
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#include "edr/command_util.h"
#include "edr/local_evidence_cache.h"
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

    int has_registry;
    char registry_path[520];
    char registry_value[260];

    int has_eventlog;
    char eventlog_channel[128];
    char eventlog_query[512];

    int has_script;
    char script_content[1024];
    char script_engine[64];
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
    {
        char v[520] = {0};
        edr_parse_json_string(pl, len, "registry_path", v, sizeof(v));
        if (v[0]) { f->has_registry = 1; snprintf(f->registry_path, sizeof(f->registry_path), "%s", v); }
    }
    {
        char v[260] = {0};
        edr_parse_json_string(pl, len, "registry_value", v, sizeof(v));
        if (v[0]) { f->has_registry = 1; snprintf(f->registry_value, sizeof(f->registry_value), "%s", v); }
    }
    {
        char v[128] = {0};
        edr_parse_json_string(pl, len, "eventlog_channel", v, sizeof(v));
        if (v[0]) { f->has_eventlog = 1; snprintf(f->eventlog_channel, sizeof(f->eventlog_channel), "%s", v); }
    }
    {
        char v[512] = {0};
        edr_parse_json_string(pl, len, "eventlog_query", v, sizeof(v));
        if (v[0]) { f->has_eventlog = 1; snprintf(f->eventlog_query, sizeof(f->eventlog_query), "%s", v); }
    }
    {
        char v[1024] = {0};
        edr_parse_json_string(pl, len, "script_content", v, sizeof(v));
        if (v[0]) {
            f->has_script = 1;
            f->has_process = 1;
            snprintf(f->script_content, sizeof(f->script_content), "%s", v);
            if (!f->process_cmdline[0]) snprintf(f->process_cmdline, sizeof(f->process_cmdline), "%s", v);
        }
    }
    {
        char v[64] = {0};
        edr_parse_json_string(pl, len, "script_engine", v, sizeof(v));
        if (v[0]) { f->has_script = 1; snprintf(f->script_engine, sizeof(f->script_engine), "%s", v); }
    }

    return (f->has_process || f->has_network || f->has_file || f->has_registry || f->has_eventlog || f->has_script) ? 0 : -1;
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

static int append_json_array_items_to_result(char *buf, int cap, int *offset, int *total,
                                             const char *array_json, uint32_t returned) {
    if (!buf || !offset || !total || !array_json || returned == 0 || *offset >= cap - 1024) return 0;
    const char *b = strchr(array_json, '[');
    const char *e = strrchr(array_json, ']');
    if (!b || !e || e <= b + 1) return 0;
    b++;
    while (b < e && isspace((unsigned char)*b)) b++;
    while (e > b && isspace((unsigned char)e[-1])) e--;
    if (e <= b) return 0;
    size_t n = (size_t)(e - b);
    if (n >= (size_t)(cap - *offset - 128)) return 0;
    if (*total > 0) *offset += snprintf(buf + *offset, (size_t)(cap - *offset), ",");
    *offset += snprintf(buf + *offset, (size_t)(cap - *offset), "%.*s", (int)n, b);
    *total += (int)returned;
    return (int)returned;
}

static int str_contains_icase(const char *haystack, const char *needle);

static int str_eq_icase(const char *a, const char *b) {
    if (!a || !b) return 0;
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) return 0;
        a++;
        b++;
    }
    return *a == '\0' && *b == '\0';
}

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
    return str_eq_icase(out65, expected);
}

#ifdef _WIN32
static int hash_file_sha256_limited(const char *path, char out65[65]) {
    out65[0] = '\0';
    if (!path || !path[0]) return -1;
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
    long sz = ftell(f);
    if (sz < 0 || sz > RTQ_FILE_HASH_MAX) { fclose(f); return -1; }
    rewind(f);

    EdrSha256Ctx ctx;
    edr_sha256_init(&ctx);
    unsigned char chunk[32768];
    for (;;) {
        size_t n = fread(chunk, 1, sizeof(chunk), f);
        if (n > 0) edr_sha256_update(&ctx, chunk, n);
        if (n < sizeof(chunk)) {
            if (ferror(f)) { fclose(f); return -1; }
            break;
        }
    }
    fclose(f);

    uint8_t digest[EDR_SHA256_DIGEST_LEN];
    static const char hx[] = "0123456789abcdef";
    edr_sha256_final(&ctx, digest);
    for (size_t i = 0; i < EDR_SHA256_DIGEST_LEN; i++) {
        out65[i * 2] = hx[(digest[i] >> 4) & 0xf];
        out65[i * 2 + 1] = hx[digest[i] & 0xf];
    }
    out65[64] = '\0';
    return 0;
}
#endif

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
static void query_process_path(DWORD pid, char *path, size_t cap) {
    if (!path || cap == 0) return;
    path[0] = '\0';
    HANDLE hp = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hp) {
        DWORD sz = (DWORD)cap;
        if (!QueryFullProcessImageNameA(hp, 0, path, &sz)) path[0] = '\0';
        CloseHandle(hp);
    }
}

static void query_process_user(DWORD pid, char *user, size_t cap) {
    if (!user || cap == 0) return;
    user[0] = '\0';
    HANDLE hp = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hp) return;
    HANDLE tok = NULL;
    if (!OpenProcessToken(hp, TOKEN_QUERY, &tok)) { CloseHandle(hp); return; }
    DWORD need = 0;
    GetTokenInformation(tok, TokenUser, NULL, 0, &need);
    TOKEN_USER *tu = (TOKEN_USER *)malloc(need);
    if (tu && GetTokenInformation(tok, TokenUser, tu, need, &need)) {
        char name[128] = {0}, domain[128] = {0};
        DWORD nlen = sizeof(name), dlen = sizeof(domain);
        SID_NAME_USE use;
        if (LookupAccountSidA(NULL, tu->User.Sid, name, &nlen, domain, &dlen, &use)) {
            snprintf(user, cap, "%s\\%s", domain, name);
        }
    }
    free(tu);
    CloseHandle(tok);
    CloseHandle(hp);
}

static void query_process_integrity_level(DWORD pid, char *level, size_t cap) {
    if (!level || cap == 0) return;
    level[0] = '\0';
    HANDLE hp = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hp) return;
    HANDLE tok = NULL;
    if (!OpenProcessToken(hp, TOKEN_QUERY, &tok)) { CloseHandle(hp); return; }
    DWORD need = 0;
    GetTokenInformation(tok, TokenIntegrityLevel, NULL, 0, &need);
    TOKEN_MANDATORY_LABEL *tml = (TOKEN_MANDATORY_LABEL *)malloc(need);
    if (tml && GetTokenInformation(tok, TokenIntegrityLevel, tml, need, &need)) {
        DWORD rid = *GetSidSubAuthority(
            tml->Label.Sid,
            (DWORD)(*GetSidSubAuthorityCount(tml->Label.Sid) - 1));
        const char *name = "unknown";
        if (rid >= SECURITY_MANDATORY_PROTECTED_PROCESS_RID) name = "protected_process";
        else if (rid >= SECURITY_MANDATORY_SYSTEM_RID) name = "system";
        else if (rid >= SECURITY_MANDATORY_HIGH_RID) name = "high";
        else if (rid >= SECURITY_MANDATORY_MEDIUM_RID) name = "medium";
        else if (rid >= SECURITY_MANDATORY_LOW_RID) name = "low";
        else if (rid >= SECURITY_MANDATORY_UNTRUSTED_RID) name = "untrusted";
        snprintf(level, cap, "%s", name);
    }
    free(tml);
    CloseHandle(tok);
    CloseHandle(hp);
}

static void query_file_signature_status(const char *path, char *status, size_t cap) {
    if (!status || cap == 0) return;
    status[0] = '\0';
    if (!path || !path[0]) return;
    wchar_t wpath[MAX_PATH * 2];
    if (MultiByteToWideChar(CP_UTF8, 0, path, -1, wpath, (int)(sizeof(wpath) / sizeof(wpath[0]))) <= 0 &&
        MultiByteToWideChar(CP_ACP, 0, path, -1, wpath, (int)(sizeof(wpath) / sizeof(wpath[0]))) <= 0) {
        snprintf(status, cap, "unknown");
        return;
    }

    WINTRUST_FILE_INFO file_info;
    memset(&file_info, 0, sizeof(file_info));
    file_info.cbStruct = sizeof(file_info);
    file_info.pcwszFilePath = wpath;

    WINTRUST_DATA trust_data;
    memset(&trust_data, 0, sizeof(trust_data));
    trust_data.cbStruct = sizeof(trust_data);
    trust_data.dwUIChoice = WTD_UI_NONE;
    trust_data.fdwRevocationChecks = WTD_REVOKE_NONE;
    trust_data.dwUnionChoice = WTD_CHOICE_FILE;
    trust_data.pFile = &file_info;
    trust_data.dwStateAction = WTD_STATEACTION_IGNORE;
    trust_data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG rc = WinVerifyTrust(NULL, &action, &trust_data);
    if (rc == ERROR_SUCCESS) snprintf(status, cap, "trusted");
    else if (rc == TRUST_E_NOSIGNATURE) snprintf(status, cap, "unsigned");
    else snprintf(status, cap, "untrusted");
}

static void query_process_cmdline_wmic(DWORD pid, char *cmd, size_t cap) {
    if (!cmd || cap == 0) return;
    cmd[0] = '\0';
    char q[256];
    snprintf(q, sizeof(q), "wmic process where ProcessId=%lu get CommandLine /value 2>NUL", (unsigned long)pid);
    FILE *p = _popen(q, "r");
    if (!p) return;
    char line[2048];
    while (fgets(line, sizeof(line), p)) {
        char *v = strstr(line, "CommandLine=");
        if (v) {
            v += strlen("CommandLine=");
            size_t n = strcspn(v, "\r\n");
            if (n >= cap) n = cap - 1;
            memcpy(cmd, v, n);
            cmd[n] = '\0';
            break;
        }
    }
    _pclose(p);
}

static void ipv4_to_text(DWORD addr, char *out, size_t cap);
static const char *tcp_state_text(DWORD s);

static void append_process_network_by_pid(DWORD pid, char *buf, int cap, int *offset) {
    if (!buf || !offset || pid == 0 || *offset >= cap - 256) return;
    int started = 0;
    int added = 0;
    DWORD sz = 0;

#define RTQ_NET_ARRAY_BEGIN() do { \
    if (!started) { \
        *offset += snprintf(buf + *offset, (size_t)(cap - *offset), ",\"network_by_pid\":["); \
        started = 1; \
    } \
} while (0)
#define RTQ_NET_ARRAY_SEP() do { \
    if (added > 0) *offset += snprintf(buf + *offset, (size_t)(cap - *offset), ","); \
} while (0)

    GetExtendedTcpTable(NULL, &sz, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    PMIB_TCPTABLE_OWNER_PID tcp = (PMIB_TCPTABLE_OWNER_PID)malloc(sz);
    if (tcp && GetExtendedTcpTable(tcp, &sz, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
        for (DWORD i = 0; i < tcp->dwNumEntries && added < 16 && *offset < cap - 512; i++) {
            if (tcp->table[i].dwOwningPid != pid) continue;
            char lip[64], rip[64];
            ipv4_to_text(tcp->table[i].dwLocalAddr, lip, sizeof(lip));
            ipv4_to_text(tcp->table[i].dwRemoteAddr, rip, sizeof(rip));
            int lp = ntohs((u_short)tcp->table[i].dwLocalPort);
            int rp = ntohs((u_short)tcp->table[i].dwRemotePort);
            RTQ_NET_ARRAY_BEGIN();
            RTQ_NET_ARRAY_SEP();
            *offset += snprintf(buf + *offset, (size_t)(cap - *offset), "{\"proto\":\"tcp\"");
            append_json_kv_str(buf, cap, offset, "state", tcp_state_text(tcp->table[i].dwState));
            append_json_kv_str(buf, cap, offset, "local_ip", lip);
            *offset += snprintf(buf + *offset, (size_t)(cap - *offset), ",\"local_port\":%d", lp);
            append_json_kv_str(buf, cap, offset, "remote_ip", rip);
            if (rp > 0) *offset += snprintf(buf + *offset, (size_t)(cap - *offset), ",\"remote_port\":%d", rp);
            *offset += snprintf(buf + *offset, (size_t)(cap - *offset), "}");
            added++;
        }
    }
    free(tcp);

    sz = 0;
    GetExtendedUdpTable(NULL, &sz, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    PMIB_UDPTABLE_OWNER_PID udp = (PMIB_UDPTABLE_OWNER_PID)malloc(sz);
    if (udp && GetExtendedUdpTable(udp, &sz, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
        for (DWORD i = 0; i < udp->dwNumEntries && added < 16 && *offset < cap - 512; i++) {
            if (udp->table[i].dwOwningPid != pid) continue;
            char lip[64];
            ipv4_to_text(udp->table[i].dwLocalAddr, lip, sizeof(lip));
            int lp = ntohs((u_short)udp->table[i].dwLocalPort);
            RTQ_NET_ARRAY_BEGIN();
            RTQ_NET_ARRAY_SEP();
            *offset += snprintf(buf + *offset, (size_t)(cap - *offset), "{\"proto\":\"udp\"");
            append_json_kv_str(buf, cap, offset, "local_ip", lip);
            *offset += snprintf(buf + *offset, (size_t)(cap - *offset), ",\"local_port\":%d}", lp);
            added++;
        }
    }
    free(udp);

    if (started) *offset += snprintf(buf + *offset, (size_t)(cap - *offset), "]");

#undef RTQ_NET_ARRAY_BEGIN
#undef RTQ_NET_ARRAY_SEP
}

static int match_processes(rtq_filter *f, char *buf, int cap, int *offset, int *total) {
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

            char path[520] = {0};
            char user[260] = {0};
            char cmdline[2048] = {0};
            char integrity[64] = {0};
            char exe_sha256[65] = {0};
            char signature[32] = {0};
            char parent_path[520] = {0};
            char parent_cmdline[2048] = {0};
            char parent_name[260] = {0};
            if (ok && f->process_path[0]) {
                query_process_path(pe.th32ProcessID, path, sizeof(path));
                if (!path[0] || !str_contains_icase(path, f->process_path)) ok = 0;
            }
            if (ok && f->process_user[0]) {
                query_process_user(pe.th32ProcessID, user, sizeof(user));
                if (!user[0] || !str_contains_icase(user, f->process_user)) ok = 0;
            }
            if (ok && (f->process_cmdline[0] || f->script_content[0] || f->script_engine[0])) {
                query_process_cmdline_wmic(pe.th32ProcessID, cmdline, sizeof(cmdline));
                if (f->process_cmdline[0] && !str_contains_icase(cmdline, f->process_cmdline)) ok = 0;
                if (f->script_engine[0] && !str_contains_icase(cmdline, f->script_engine)) ok = 0;
            }

            if (ok && *total < RTQ_MAX_RESULTS && *offset < cap - 8192) {
                if (!path[0]) query_process_path(pe.th32ProcessID, path, sizeof(path));
                if (!user[0]) query_process_user(pe.th32ProcessID, user, sizeof(user));
                if (!cmdline[0]) query_process_cmdline_wmic(pe.th32ProcessID, cmdline, sizeof(cmdline));
                query_process_integrity_level(pe.th32ProcessID, integrity, sizeof(integrity));
                if (path[0]) {
                    (void)hash_file_sha256_limited(path, exe_sha256);
                    query_file_signature_status(path, signature, sizeof(signature));
                }
                if (pe.th32ParentProcessID > 0) {
                    query_process_path(pe.th32ParentProcessID, parent_path, sizeof(parent_path));
                    query_process_cmdline_wmic(pe.th32ParentProcessID, parent_cmdline, sizeof(parent_cmdline));
                    if (parent_path[0]) {
                        const char *base = strrchr(parent_path, '\\');
                        snprintf(parent_name, sizeof(parent_name), "%s", base ? base + 1 : parent_path);
                    }
                }

                if (*total > 0) *offset += snprintf(buf + *offset, (size_t)(cap - *offset), ",");
                *offset += snprintf(buf + *offset, (size_t)(cap - *offset),
                    "{\"type\":\"process\",\"pid\":%lu,\"name\":\"", (unsigned long)pe.th32ProcessID);
                append_json_escaped(buf, cap, offset, name);
                *offset += snprintf(buf + *offset, (size_t)(cap - *offset), "\",\"ppid\":%lu",
                    (unsigned long)pe.th32ParentProcessID);
                if (path[0]) append_json_kv_str(buf, cap, offset, "path", path);
                if (user[0]) append_json_kv_str(buf, cap, offset, "user", user);
                if (cmdline[0]) append_json_kv_str(buf, cap, offset, "cmdline", cmdline);
                if (integrity[0]) append_json_kv_str(buf, cap, offset, "integrity_level", integrity);
                if (exe_sha256[0]) append_json_kv_str(buf, cap, offset, "exe_hash", exe_sha256);
                if (signature[0]) append_json_kv_str(buf, cap, offset, "signature", signature);
                if (parent_name[0]) append_json_kv_str(buf, cap, offset, "parent_name", parent_name);
                if (parent_path[0]) append_json_kv_str(buf, cap, offset, "parent_path", parent_path);
                if (parent_cmdline[0]) append_json_kv_str(buf, cap, offset, "parent_cmdline", parent_cmdline);
                append_process_network_by_pid(pe.th32ProcessID, buf, cap, offset);
                *offset += snprintf(buf + *offset, (size_t)(cap - *offset), "}");
                (*total)++;
                count++;
            }
        } while (Process32NextW(h, &pe));
    }
    CloseHandle(h);
    return count;
}

static void ipv4_to_text(DWORD addr, char *out, size_t cap) {
    struct in_addr a;
    a.S_un.S_addr = addr;
    snprintf(out, cap, "%s", inet_ntoa(a));
}

static const char *tcp_state_text(DWORD s) {
    switch (s) {
    case MIB_TCP_STATE_CLOSED: return "CLOSED";
    case MIB_TCP_STATE_LISTEN: return "LISTEN";
    case MIB_TCP_STATE_SYN_SENT: return "SYN_SENT";
    case MIB_TCP_STATE_SYN_RCVD: return "SYN_RCVD";
    case MIB_TCP_STATE_ESTAB: return "ESTABLISHED";
    case MIB_TCP_STATE_FIN_WAIT1: return "FIN_WAIT1";
    case MIB_TCP_STATE_FIN_WAIT2: return "FIN_WAIT2";
    case MIB_TCP_STATE_CLOSE_WAIT: return "CLOSE_WAIT";
    case MIB_TCP_STATE_CLOSING: return "CLOSING";
    case MIB_TCP_STATE_LAST_ACK: return "LAST_ACK";
    case MIB_TCP_STATE_TIME_WAIT: return "TIME_WAIT";
    case MIB_TCP_STATE_DELETE_TCB: return "DELETE_TCB";
    default: return "UNKNOWN";
    }
}

static int append_win_network(rtq_filter *f, const char *proto, const char *state,
                              const char *local_ip, int local_port, const char *remote_ip,
                              int remote_port, DWORD pid, char *buf, int cap, int *offset, int *total) {
    if (f->network_proto[0] && !str_contains_icase(proto, f->network_proto)) return 0;
    if (f->network_state[0] && !str_contains_icase(state, f->network_state)) return 0;
    if (f->network_remote_ip[0] && !str_contains_icase(remote_ip, f->network_remote_ip)) return 0;
    if (f->network_remote_port > 0 && remote_port != f->network_remote_port) return 0;
    if (*total >= RTQ_MAX_RESULTS || *offset >= cap - 1024) return 0;
    if (*total > 0) *offset += snprintf(buf + *offset, (size_t)(cap - *offset), ",");
    *offset += snprintf(buf + *offset, (size_t)(cap - *offset), "{\"type\":\"network\"");
    append_json_kv_str(buf, cap, offset, "proto", proto);
    append_json_kv_str(buf, cap, offset, "state", state);
    append_json_kv_str(buf, cap, offset, "local_ip", local_ip);
    *offset += snprintf(buf + *offset, (size_t)(cap - *offset), ",\"local_port\":%d", local_port);
    append_json_kv_str(buf, cap, offset, "remote_ip", remote_ip);
    if (remote_port > 0) *offset += snprintf(buf + *offset, (size_t)(cap - *offset), ",\"remote_port\":%d", remote_port);
    if (pid > 0) *offset += snprintf(buf + *offset, (size_t)(cap - *offset), ",\"pid\":%lu", (unsigned long)pid);
    *offset += snprintf(buf + *offset, (size_t)(cap - *offset), "}");
    (*total)++;
    return 1;
}

static int match_network(rtq_filter *f, char *buf, int cap, int *offset, int *total) {
    int count = 0;
    DWORD sz = 0;
    GetExtendedTcpTable(NULL, &sz, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    PMIB_TCPTABLE_OWNER_PID tcp = (PMIB_TCPTABLE_OWNER_PID)malloc(sz);
    if (tcp && GetExtendedTcpTable(tcp, &sz, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
        for (DWORD i = 0; i < tcp->dwNumEntries && *total < RTQ_MAX_RESULTS; i++) {
            char lip[64], rip[64];
            ipv4_to_text(tcp->table[i].dwLocalAddr, lip, sizeof(lip));
            ipv4_to_text(tcp->table[i].dwRemoteAddr, rip, sizeof(rip));
            int lp = ntohs((u_short)tcp->table[i].dwLocalPort);
            int rp = ntohs((u_short)tcp->table[i].dwRemotePort);
            if (append_win_network(f, "tcp", tcp_state_text(tcp->table[i].dwState), lip, lp, rip, rp, tcp->table[i].dwOwningPid, buf, cap, offset, total)) count++;
        }
    }
    free(tcp);
    sz = 0;
    GetExtendedUdpTable(NULL, &sz, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    PMIB_UDPTABLE_OWNER_PID udp = (PMIB_UDPTABLE_OWNER_PID)malloc(sz);
    if (udp && GetExtendedUdpTable(udp, &sz, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
        for (DWORD i = 0; i < udp->dwNumEntries && *total < RTQ_MAX_RESULTS; i++) {
            char lip[64];
            ipv4_to_text(udp->table[i].dwLocalAddr, lip, sizeof(lip));
            int lp = ntohs((u_short)udp->table[i].dwLocalPort);
            if (append_win_network(f, "udp", "", lip, lp, "", 0, udp->table[i].dwOwningPid, buf, cap, offset, total)) count++;
        }
    }
    free(udp);
    return count;
}

static int append_win_file_result(rtq_filter *f, const char *path, const WIN32_FIND_DATAA *fd,
                                  char *buf, int cap, int *offset, int *total) {
    if (!path || !fd || *total >= RTQ_MAX_RESULTS || *offset >= cap - 1024) return 0;
    if (fd->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) return 0;
    if (f->file_path[0] && !str_contains_icase(path, f->file_path)) return 0;
    if (!file_has_ext(path, f->file_ext)) return 0;
    LARGE_INTEGER sz;
    sz.HighPart = (LONG)fd->nFileSizeHigh;
    sz.LowPart = fd->nFileSizeLow;
    if (f->file_size_min > 0 && sz.QuadPart < f->file_size_min) return 0;
    if (f->file_size_max > 0 && sz.QuadPart > f->file_size_max) return 0;
    char sha[65] = {0};
    if (!hash_file_if_needed(path, f->file_sha256, sha)) return 0;
    if (*total > 0) *offset += snprintf(buf + *offset, (size_t)(cap - *offset), ",");
    *offset += snprintf(buf + *offset, (size_t)(cap - *offset), "{\"type\":\"file\",\"path\":\"");
    append_json_escaped(buf, cap, offset, path);
    *offset += snprintf(buf + *offset, (size_t)(cap - *offset), "\",\"size\":%lld", (long long)sz.QuadPart);
    if (sha[0]) append_json_kv_str(buf, cap, offset, "sha256", sha);
    *offset += snprintf(buf + *offset, (size_t)(cap - *offset), "}");
    (*total)++;
    return 1;
}

static void scan_win_files_limited(rtq_filter *f, const char *root, int depth, int *scanned,
                                   char *buf, int cap, int *offset, int *total) {
    if (!root || !root[0] || depth < 0 || *scanned >= RTQ_FILE_SCAN_MAX || *total >= RTQ_MAX_RESULTS) return;
    DWORD attr = GetFileAttributesA(root);
    if (attr == INVALID_FILE_ATTRIBUTES) return;
    if (!(attr & FILE_ATTRIBUTE_DIRECTORY)) {
        WIN32_FIND_DATAA fd;
        memset(&fd, 0, sizeof(fd));
        HANDLE h = FindFirstFileA(root, &fd);
        if (h != INVALID_HANDLE_VALUE) {
            (*scanned)++;
            (void)append_win_file_result(f, root, &fd, buf, cap, offset, total);
            FindClose(h);
        }
        return;
    }
    char pattern[1024];
    snprintf(pattern, sizeof(pattern), "%s\\*", root);
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0) continue;
        char child[1024];
        snprintf(child, sizeof(child), "%s\\%s", root, fd.cFileName);
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            scan_win_files_limited(f, child, depth - 1, scanned, buf, cap, offset, total);
        } else {
            (*scanned)++;
            (void)append_win_file_result(f, child, &fd, buf, cap, offset, total);
        }
    } while (FindNextFileA(h, &fd) && *scanned < RTQ_FILE_SCAN_MAX && *total < RTQ_MAX_RESULTS);
    FindClose(h);
}

static int match_files(rtq_filter *f, char *buf, int cap, int *offset, int *total) {
    int scanned = 0;
    int before = *total;
    if (f->file_sha256[0]) {
        if (f->file_path[0]) {
            DWORD attr = GetFileAttributesA(f->file_path);
            if (attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY)) {
                scan_win_files_limited(f, f->file_path, 0, &scanned, buf, cap, offset, total);
            }
        }
    } else if (f->file_path[0]) {
        scan_win_files_limited(f, f->file_path, RTQ_FILE_SCAN_DEPTH, &scanned, buf, cap, offset, total);
    } else if (f->file_ext[0]) {
        scan_win_files_limited(f, "C:\\Windows\\Temp", RTQ_FILE_SCAN_DEPTH, &scanned, buf, cap, offset, total);
        scan_win_files_limited(f, "C:\\Users\\Public", RTQ_FILE_SCAN_DEPTH, &scanned, buf, cap, offset, total);
    }
    return *total - before;
}

static int split_registry_path(const char *path, HKEY *root, char *subkey, size_t cap) {
    if (!path || !root || !subkey || cap == 0) return 0;
    const char *p = strchr(path, '\\');
    size_t n = p ? (size_t)(p - path) : strlen(path);
    char hive[64];
    if (n >= sizeof(hive)) n = sizeof(hive) - 1;
    memcpy(hive, path, n);
    hive[n] = '\0';
    if (_stricmp(hive, "HKLM") == 0 || _stricmp(hive, "HKEY_LOCAL_MACHINE") == 0) *root = HKEY_LOCAL_MACHINE;
    else if (_stricmp(hive, "HKCU") == 0 || _stricmp(hive, "HKEY_CURRENT_USER") == 0) *root = HKEY_CURRENT_USER;
    else if (_stricmp(hive, "HKCR") == 0 || _stricmp(hive, "HKEY_CLASSES_ROOT") == 0) *root = HKEY_CLASSES_ROOT;
    else if (_stricmp(hive, "HKU") == 0 || _stricmp(hive, "HKEY_USERS") == 0) *root = HKEY_USERS;
    else return 0;
    snprintf(subkey, cap, "%s", p ? p + 1 : "");
    return 1;
}

static int match_registry(rtq_filter *f, char *buf, int cap, int *offset, int *total) {
    HKEY root, key;
    char subkey[520];
    if (!split_registry_path(f->registry_path, &root, subkey, sizeof(subkey))) return 0;
    if (RegOpenKeyExA(root, subkey, 0, KEY_READ, &key) != ERROR_SUCCESS) return 0;
    int count = 0;
    for (DWORD i = 0; i < 128 && *total < RTQ_MAX_RESULTS; i++) {
        char name[260];
        BYTE data[1024];
        DWORD name_len = sizeof(name), data_len = sizeof(data), type = 0;
        LONG rc = RegEnumValueA(key, i, name, &name_len, NULL, &type, data, &data_len);
        if (rc != ERROR_SUCCESS) break;
        if (f->registry_value[0] && !str_contains_icase(name, f->registry_value)) continue;
        if (*offset >= cap - 1024) break;
        if (*total > 0) *offset += snprintf(buf + *offset, (size_t)(cap - *offset), ",");
        *offset += snprintf(buf + *offset, (size_t)(cap - *offset), "{\"type\":\"registry\"");
        append_json_kv_str(buf, cap, offset, "key", f->registry_path);
        append_json_kv_str(buf, cap, offset, "value", name[0] ? name : "(Default)");
        *offset += snprintf(buf + *offset, (size_t)(cap - *offset), ",\"reg_type\":%lu", (unsigned long)type);
        if ((type == REG_SZ || type == REG_EXPAND_SZ) && data_len > 0) append_json_kv_str(buf, cap, offset, "data", (const char *)data);
        *offset += snprintf(buf + *offset, (size_t)(cap - *offset), "}");
        (*total)++;
        count++;
    }
    RegCloseKey(key);
    return count;
}

static int wide_to_utf8_str(LPCWSTR src, char *out, size_t cap) {
    if (!out || cap == 0) return 0;
    out[0] = '\0';
    if (!src || !src[0]) return 0;
    int n = WideCharToMultiByte(CP_UTF8, 0, src, -1, out, (int)cap, NULL, NULL);
    if (n <= 0) {
        out[0] = '\0';
        return 0;
    }
    out[cap - 1] = '\0';
    return 1;
}

static int evt_variant_u64(const EVT_VARIANT *v, unsigned long long *out) {
    if (!v || !out) return 0;
    switch (v->Type & EVT_VARIANT_TYPE_MASK) {
    case EvtVarTypeByte:
        *out = (unsigned long long)v->ByteVal;
        return 1;
    case EvtVarTypeUInt16:
        *out = (unsigned long long)v->UInt16Val;
        return 1;
    case EvtVarTypeUInt32:
    case EvtVarTypeHexInt32:
        *out = (unsigned long long)v->UInt32Val;
        return 1;
    case EvtVarTypeUInt64:
    case EvtVarTypeHexInt64:
        *out = (unsigned long long)v->UInt64Val;
        return 1;
    default:
        return 0;
    }
}

static void append_eventlog_u64(EVT_VARIANT *values, DWORD count, EVT_SYSTEM_PROPERTY_ID id,
                                const char *key, char *buf, int cap, int *offset) {
    if (!values || id >= count || !key) return;
    unsigned long long v = 0;
    if (!evt_variant_u64(&values[id], &v)) return;
    *offset += snprintf(buf + *offset, (size_t)(cap - *offset), ",\"%s\":%llu", key, v);
}

static void append_eventlog_wstr(EVT_VARIANT *values, DWORD count, EVT_SYSTEM_PROPERTY_ID id,
                                 const char *key, char *buf, int cap, int *offset) {
    if (!values || id >= count || !key) return;
    if ((values[id].Type & EVT_VARIANT_TYPE_MASK) != EvtVarTypeString || !values[id].StringVal) return;
    char tmp[512];
    if (wide_to_utf8_str(values[id].StringVal, tmp, sizeof(tmp))) {
        append_json_kv_str(buf, cap, offset, key, tmp);
    }
}

static void append_eventlog_time(EVT_VARIANT *values, DWORD count, char *buf, int cap, int *offset) {
    if (!values || EvtSystemTimeCreated >= count) return;
    if ((values[EvtSystemTimeCreated].Type & EVT_VARIANT_TYPE_MASK) != EvtVarTypeFileTime) return;
    ULONGLONG ftv = values[EvtSystemTimeCreated].FileTimeVal;
    FILETIME ft;
    ft.dwLowDateTime = (DWORD)(ftv & 0xffffffffULL);
    ft.dwHighDateTime = (DWORD)(ftv >> 32);
    SYSTEMTIME st;
    if (!FileTimeToSystemTime(&ft, &st)) return;
    char ts[64];
    snprintf(ts, sizeof(ts), "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ",
             (unsigned)st.wYear, (unsigned)st.wMonth, (unsigned)st.wDay,
             (unsigned)st.wHour, (unsigned)st.wMinute, (unsigned)st.wSecond,
             (unsigned)st.wMilliseconds);
    append_json_kv_str(buf, cap, offset, "timestamp", ts);
}

static void append_eventlog_xml(EVT_HANDLE event, char *buf, int cap, int *offset) {
    DWORD used = 0, prop_count = 0;
    if (EvtRender(NULL, event, EvtRenderEventXml, 0, NULL, &used, &prop_count)) return;
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || used == 0) return;
    wchar_t *xml = (wchar_t *)malloc(used);
    if (!xml) return;
    if (EvtRender(NULL, event, EvtRenderEventXml, used, xml, &used, &prop_count)) {
        char xml_utf8[4096];
        if (wide_to_utf8_str(xml, xml_utf8, sizeof(xml_utf8))) {
            append_json_kv_str(buf, cap, offset, "xml", xml_utf8);
            if (used > sizeof(xml_utf8)) {
                *offset += snprintf(buf + *offset, (size_t)(cap - *offset), ",\"xml_truncated\":true");
            }
        }
    }
    free(xml);
}

static void append_eventlog_evidence(EVT_HANDLE render_ctx, EVT_HANDLE event,
                                     char *buf, int cap, int *offset) {
    if (!render_ctx || !event || *offset >= cap - 2048) return;
    DWORD used = 0, prop_count = 0;
    if (EvtRender(render_ctx, event, EvtRenderEventValues, 0, NULL, &used, &prop_count)) return;
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || used == 0) return;
    EVT_VARIANT *values = (EVT_VARIANT *)malloc(used);
    if (!values) return;
    if (EvtRender(render_ctx, event, EvtRenderEventValues, used, values, &used, &prop_count)) {
        append_eventlog_wstr(values, prop_count, EvtSystemProviderName, "provider", buf, cap, offset);
        append_eventlog_u64(values, prop_count, EvtSystemEventID, "event_id", buf, cap, offset);
        append_eventlog_u64(values, prop_count, EvtSystemEventRecordId, "record_id", buf, cap, offset);
        append_eventlog_u64(values, prop_count, EvtSystemLevel, "level", buf, cap, offset);
        append_eventlog_u64(values, prop_count, EvtSystemProcessID, "process_id", buf, cap, offset);
        append_eventlog_u64(values, prop_count, EvtSystemThreadID, "thread_id", buf, cap, offset);
        append_eventlog_wstr(values, prop_count, EvtSystemComputer, "computer", buf, cap, offset);
        append_eventlog_time(values, prop_count, buf, cap, offset);
    }
    free(values);
    if (*offset < cap - 8192) append_eventlog_xml(event, buf, cap, offset);
}

static int match_eventlog(rtq_filter *f, char *buf, int cap, int *offset, int *total) {
    wchar_t channel[128];
    wchar_t query[512];
    MultiByteToWideChar(CP_UTF8, 0, f->eventlog_channel[0] ? f->eventlog_channel : "System", -1, channel, 128);
    MultiByteToWideChar(CP_UTF8, 0, f->eventlog_query[0] ? f->eventlog_query : "*", -1, query, 512);
    EVT_HANDLE h = EvtQuery(NULL, channel, query, EvtQueryChannelPath | EvtQueryReverseDirection);
    if (!h) return 0;
    EVT_HANDLE render_ctx = EvtCreateRenderContext(0, NULL, EvtRenderContextSystem);
    int count = 0;
    EVT_HANDLE events[16];
    DWORD returned = 0;
    while (*total < RTQ_MAX_RESULTS && EvtNext(h, 16, events, 1000, 0, &returned)) {
        for (DWORD i = 0; i < returned && *total < RTQ_MAX_RESULTS; i++) {
            if (*offset >= cap - 512) { EvtClose(events[i]); continue; }
            if (*total > 0) *offset += snprintf(buf + *offset, (size_t)(cap - *offset), ",");
            *offset += snprintf(buf + *offset, (size_t)(cap - *offset), "{\"type\":\"eventlog\"");
            append_json_kv_str(buf, cap, offset, "channel", f->eventlog_channel[0] ? f->eventlog_channel : "System");
            append_json_kv_str(buf, cap, offset, "query", f->eventlog_query[0] ? f->eventlog_query : "*");
            append_eventlog_evidence(render_ctx, events[i], buf, cap, offset);
            *offset += snprintf(buf + *offset, (size_t)(cap - *offset), "}");
            (*total)++;
            count++;
            EvtClose(events[i]);
        }
    }
    if (render_ctx) EvtClose(render_ctx);
    EvtClose(h);
    return count;
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
    if (f->file_sha256[0]) {
        if (f->file_path[0]) {
            struct stat st;
            if (stat(f->file_path, &st) == 0 && S_ISREG(st.st_mode)) {
                scan_files_limited(f, f->file_path, 0, &scanned, buf, cap, offset, total);
            }
        }
    } else if (f->file_path[0]) {
        scan_files_limited(f, f->file_path, RTQ_FILE_SCAN_DEPTH, &scanned, buf, cap, offset, total);
    } else if (f->file_ext[0]) {
        scan_files_limited(f, "/tmp", RTQ_FILE_SCAN_DEPTH, &scanned, buf, cap, offset, total);
        scan_files_limited(f, "/var/tmp", RTQ_FILE_SCAN_DEPTH, &scanned, buf, cap, offset, total);
    }
    return *total - before;
}
#endif

static int match_file_hash_cache(rtq_filter *f, char *buf, int cap, int *offset, int *total) {
    if (!f || !f->file_sha256[0]) return 0;
    size_t rows_cap = RTQ_MAX_RESULT_STR / 2u;
    char *rows = (char *)malloc(rows_cap);
    if (!rows) return 0;
    uint32_t returned = 0;
    uint32_t scanned = 0;
    if (edr_local_evidence_cache_query_file_hash_json(f->file_sha256, f->file_path,
                                                      f->file_ext, RTQ_MAX_RESULTS,
                                                      rows, rows_cap,
                                                      &returned, &scanned) != 0) {
        free(rows);
        return 0;
    }
    (void)scanned;
    int appended = append_json_array_items_to_result(buf, cap, offset, total, rows, returned);
    free(rows);
    return appended;
}

static int match_files_cache_first(rtq_filter *f, char *buf, int cap, int *offset, int *total) {
    if (!f) return 0;
    int before = *total;
    int cache_hits = 0;
    if (f->file_sha256[0]) {
        cache_hits = match_file_hash_cache(f, buf, cap, offset, total);
    }
    if (!f->file_sha256[0] || (cache_hits == 0 && f->file_path[0])) {
        (void)match_files(f, buf, cap, offset, total);
    }
    return *total - before;
}

void edr_response_rtq_execute(const char *cmd_id, const uint8_t *pl,
                               size_t len, const EdrSoarCommandMeta *sm) {
    if (!edr_command_rtq_readonly_enabled()) {
        g_cmd_rejected++;
        edr_command_audit_both(cmd_id, "reject rtq_execute: readonly RTQ disabled");
        edr_command_emit_always(cmd_id, sm, EdrCmdExecRejected, 1, "readonly RTQ disabled");
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
    int has_registry = filter.has_registry;
    int has_eventlog = filter.has_eventlog;

    offset += snprintf(result + offset, (size_t)(RTQ_MAX_RESULT_STR - offset),
        "{\"results\":[\n");

#ifdef _WIN32
    if (has_proc) {
        (void)match_processes(&filter, result, RTQ_MAX_RESULT_STR, &offset, &total);
    }
    if (has_net) {
        (void)match_network(&filter, result, RTQ_MAX_RESULT_STR, &offset, &total);
    }
    if (has_file) {
        (void)match_files_cache_first(&filter, result, RTQ_MAX_RESULT_STR, &offset, &total);
    }
    if (has_registry) {
        (void)match_registry(&filter, result, RTQ_MAX_RESULT_STR, &offset, &total);
    }
    if (has_eventlog) {
        (void)match_eventlog(&filter, result, RTQ_MAX_RESULT_STR, &offset, &total);
    }
#else
    if (has_proc) {
        (void)match_processes(&filter, result, RTQ_MAX_RESULT_STR, &offset, &total);
    }
    if (has_net) {
        (void)match_network(&filter, result, RTQ_MAX_RESULT_STR, &offset, &total);
    }
    if (has_file) {
        (void)match_files_cache_first(&filter, result, RTQ_MAX_RESULT_STR, &offset, &total);
    }
#endif
    (void)has_file;
    (void)has_registry;
    (void)has_eventlog;

    offset += snprintf(result + offset, (size_t)(RTQ_MAX_RESULT_STR - offset),
        "\n],\"total\":%d,\"error\":null}", total);

    g_cmd_handled++; g_cmd_exec_ok++;
    edr_command_audit_both(cmd_id, "rtq_execute: ok");
    edr_command_emit_always(cmd_id, sm, EdrCmdExecOk, 0, result);
    free(result);
}
