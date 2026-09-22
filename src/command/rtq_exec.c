#include <ctype.h>
#include <stdarg.h>
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
#include "edr/command_cancel.h"
#include "edr/command_state.h"
#include "edr/behavior_record.h"
#include "edr/local_evidence_cache.h"
#include "edr/process_generation.h"
#include "edr/response.h"
#include "edr/sha256.h"
#include "edr/shell_exec.h"

#define RTQ_MAX_RESULTS    500
/* Command results are durably replayed through EdrCommandStateRecord.detail.
 * Keep the complete RTQ JSON below that fixed limit; otherwise a restart or
 * async report path can cut a JSON string in half and turn successful rows
 * into an endpoint error. */
#define RTQ_MAX_RESULT_STR ((int)EDR_COMMAND_STATE_DETAIL_CAP - 1024)
#define RTQ_RESULT_FOOTER_RESERVE 5120
#define RTQ_COLLECTOR_RESULT_CAP (RTQ_MAX_RESULT_STR - RTQ_RESULT_FOOTER_RESERVE)
#define RTQ_ROW_CAP RTQ_MAX_RESULT_STR
#define RTQ_FILE_HASH_MAX  (64 * 1024 * 1024)
#define RTQ_FILE_SCAN_MAX  2000
#define RTQ_FILE_SCAN_DEPTH 3
#define RTQ_SAMPLER_TIMEOUT_SEC 3
#define RTQ_SAMPLER_OUTPUT_MAX (64 * 1024)

typedef struct rtq_errors {
    char json[4096];
    int offset;
    int count;
    int warning_count;
} rtq_errors;

typedef struct rtq_filter {
    const char *command_id;
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
    int file_cache_attempted;
    int file_cache_hits;
    uint32_t file_cache_candidates;
    int file_path_scanned;

    int has_registry;
    char registry_path[520];
    char registry_value[260];
    char registry_mode[16];

    int has_eventlog;
    char eventlog_channel[128];
    char eventlog_query[512];

    int has_script;
    char script_content[1024];
    char script_engine[64];
} rtq_filter;

static int rtq_cancelled(const rtq_filter *f) {
    return f && f->command_id && edr_command_cancel_requested(f->command_id);
}

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
        char v[16] = {0};
        edr_parse_json_string(pl, len, "registry_mode", v, sizeof(v));
        snprintf(f->registry_mode, sizeof(f->registry_mode), "%s", v[0] ? v : "exact");
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
        if (v[0]) {
            f->has_script = 1;
            f->has_process = 1;
            snprintf(f->script_engine, sizeof(f->script_engine), "%s", v);
        }
    }

    return (f->has_process || f->has_network || f->has_file || f->has_registry || f->has_eventlog || f->has_script) ? 0 : -1;
}

static int rtq_appendf(char *buf, int cap, int *offset, const char *fmt, ...) {
    if (!buf || !offset || !fmt || cap <= 0 || *offset < 0 || *offset >= cap) return 0;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf + *offset, (size_t)(cap - *offset), fmt, ap);
    va_end(ap);
    if (n < 0 || n >= cap - *offset) {
        *offset = cap - 1;
        buf[*offset] = '\0';
        return 0;
    }
    *offset += n;
    return 1;
}

static int append_json_escaped(char *buf, int cap, int *offset, const char *s) {
    if (!buf || !offset || *offset < 0 || *offset >= cap || !s) return 0;
    for (const char *p = s; *p; p++) {
        unsigned char ch = (unsigned char)*p;
        if (ch == '"' || ch == '\\') {
            if (*offset >= cap - 2) goto overflow;
            buf[(*offset)++] = '\\';
            buf[(*offset)++] = (char)ch;
        } else if (ch == '\n') {
            if (*offset >= cap - 2) goto overflow;
            buf[(*offset)++] = '\\';
            buf[(*offset)++] = 'n';
        } else if (ch == '\r') {
            if (*offset >= cap - 2) goto overflow;
            buf[(*offset)++] = '\\';
            buf[(*offset)++] = 'r';
        } else if (ch == '\t') {
            if (*offset >= cap - 2) goto overflow;
            buf[(*offset)++] = '\\';
            buf[(*offset)++] = 't';
        } else if (ch >= 32) {
            if (*offset >= cap - 1) goto overflow;
            buf[(*offset)++] = (char)ch;
        }
    }
    buf[*offset] = '\0';
    return 1;

overflow:
    *offset = cap - 1;
    buf[*offset] = '\0';
    return 0;
}

static int append_json_kv_str(char *buf, int cap, int *offset, const char *key, const char *value) {
    return rtq_appendf(buf, cap, offset, ",\"%s\":\"", key) &&
           append_json_escaped(buf, cap, offset, value ? value : "") &&
           rtq_appendf(buf, cap, offset, "\"");
}

static int rtq_commit_row(char *buf, int cap, int *offset, int *total,
                          const char *row, int row_len, int *truncated) {
    if (!buf || !offset || !total || !row || row_len <= 0 ||
        *offset < 0 || *offset >= cap) {
        if (truncated) *truncated = 1;
        return 0;
    }
    int separator = *total > 0 ? 1 : 0;
    if (row_len >= cap || separator + row_len >= cap - *offset) {
        if (truncated) *truncated = 1;
        return 0;
    }
    if (separator) buf[(*offset)++] = ',';
    memcpy(buf + *offset, row, (size_t)row_len);
    *offset += row_len;
    buf[*offset] = '\0';
    (*total)++;
    return 1;
}

static void rtq_error_init(rtq_errors *errs) {
    if (!errs) return;
    errs->json[0] = '\0';
    errs->offset = 0;
    errs->count = 0;
    errs->warning_count = 0;
}

static void rtq_error_append(rtq_errors *errs, const char *source, const char *code,
                             const char *message, int retryable) {
    if (!errs) return;
    char row[2048];
    int row_offset = 0;
    row[0] = '\0';
    if (!rtq_appendf(row, (int)sizeof(row), &row_offset, "{\"source\":\"") ||
        !append_json_escaped(row, (int)sizeof(row), &row_offset, source ? source : "rtq") ||
        !rtq_appendf(row, (int)sizeof(row), &row_offset, "\",\"code\":\"") ||
        !append_json_escaped(row, (int)sizeof(row), &row_offset, code ? code : "collector_failed") ||
        !rtq_appendf(row, (int)sizeof(row), &row_offset, "\",\"message\":\"") ||
        !append_json_escaped(row, (int)sizeof(row), &row_offset,
                             message ? message : "RTQ collector failed")) {
        return;
    }
    int warning = code && (strcmp(code, "partial_access") == 0 ||
                           strcmp(code, "result_truncated") == 0);
    if (!rtq_appendf(row, (int)sizeof(row), &row_offset,
                     "\",\"retryable\":%s,\"severity\":\"%s\"}",
                     retryable ? "true" : "false", warning ? "warning" : "error")) {
        return;
    }
    int separator = errs->count > 0 ? 1 : 0;
    if (separator + row_offset >= (int)sizeof(errs->json) - errs->offset) return;
    if (separator) errs->json[errs->offset++] = ',';
    memcpy(errs->json + errs->offset, row, (size_t)row_offset);
    errs->offset += row_offset;
    errs->json[errs->offset] = '\0';
    errs->count++;
    if (warning) errs->warning_count++;
}

static void trim_sampler_output(char *s) {
    if (!s) return;
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r' || s[n - 1] == ' ' || s[n - 1] == '\t')) {
        s[--n] = '\0';
    }
    char *p = s;
    while (*p == '\n' || *p == '\r' || *p == ' ' || *p == '\t') p++;
    if (p != s) memmove(s, p, strlen(p) + 1u);
}

static void sampler_error_message(char *out, size_t cap, const char *cmd, int exit_code,
                                  const char *output) {
    if (!out || cap == 0) return;
    char detail[512];
    snprintf(detail, sizeof(detail), "%s", output && output[0] ? output : "no stderr/stdout");
    trim_sampler_output(detail);
    snprintf(out, cap, "sampler command failed: %s exit_code=%d detail=%s",
             cmd ? cmd : "", exit_code, detail[0] ? detail : "empty output");
}

static int append_json_array_items_to_result(char *buf, int cap, int *offset, int *total,
                                             const char *array_json, uint32_t returned,
                                             int *truncated) {
    if (!buf || !offset || !total || !array_json || returned == 0) return 0;
    const char *b = strchr(array_json, '[');
    if (!b) {
        if (truncated) *truncated = 1;
        return 0;
    }
    int committed = 0;
    int depth = 0;
    int in_string = 0;
    int escaped = 0;
    int array_closed = 0;
    const char *row_start = NULL;
    for (const char *p = b + 1; *p; p++) {
        char ch = *p;
        if (in_string) {
            if (escaped) {
                escaped = 0;
            } else if (ch == '\\') {
                escaped = 1;
            } else if (ch == '"') {
                in_string = 0;
            }
            continue;
        }
        if (ch == '"') {
            in_string = 1;
            continue;
        }
        if (ch == '{') {
            if (depth == 0) row_start = p;
            depth++;
            continue;
        }
        if (ch == '}' && depth > 0) {
            depth--;
            if (depth == 0 && row_start) {
                int row_len = (int)(p - row_start + 1);
                if (!rtq_commit_row(buf, cap, offset, total, row_start, row_len, truncated)) {
                    return committed;
                }
                committed++;
                row_start = NULL;
            }
            continue;
        }
        if (ch == ']' && depth == 0) {
            array_closed = 1;
            break;
        }
    }
    if (!array_closed || depth != 0 || (uint32_t)committed < returned) {
        if (truncated) *truncated = 1;
    }
    return committed;
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
static int append_file_result(rtq_filter *f, const char *path, char *buf, int cap,
                              int *offset, int *total, int *truncated) {
    if (!path || !path[0]) return 0;
    if (*total >= RTQ_MAX_RESULTS) {
        if (truncated) *truncated = 1;
        return 0;
    }
    if (f->file_path[0] && !str_contains_icase(path, f->file_path)) return 0;
    if (!file_has_ext(path, f->file_ext)) return 0;

    struct stat st;
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode)) return 0;
    if (f->file_size_min > 0 && (long long)st.st_size < f->file_size_min) return 0;
    if (f->file_size_max > 0 && (long long)st.st_size > f->file_size_max) return 0;

    char sha[65] = {0};
    if (!hash_file_if_needed(path, f->file_sha256, sha)) return 0;
    char row[RTQ_ROW_CAP];
    int row_offset = 0;
    row[0] = '\0';
    int ok = rtq_appendf(row, (int)sizeof(row), &row_offset, "{\"type\":\"file\",\"path\":\"") &&
             append_json_escaped(row, (int)sizeof(row), &row_offset, path) &&
             rtq_appendf(row, (int)sizeof(row), &row_offset, "\",\"size\":%lld",
                         (long long)st.st_size);
    if (ok && sha[0]) ok = append_json_kv_str(row, (int)sizeof(row), &row_offset, "sha256", sha);
    if (ok) ok = rtq_appendf(row, (int)sizeof(row), &row_offset, "}");
    if (!ok) {
        if (truncated) *truncated = 1;
        return 0;
    }
    return rtq_commit_row(buf, cap, offset, total, row, row_offset, truncated);
}

static void scan_files_limited(rtq_filter *f, const char *root, int depth, int *scanned,
                               char *buf, int cap, int *offset, int *total, int *truncated) {
    if (!root || !root[0] || depth < 0 || *scanned >= RTQ_FILE_SCAN_MAX || *total >= RTQ_MAX_RESULTS) return;
    struct stat st;
    if (stat(root, &st) != 0) return;
    if (S_ISREG(st.st_mode)) {
        (*scanned)++;
        (void)append_file_result(f, root, buf, cap, offset, total, truncated);
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
        scan_files_limited(f, child, depth - 1, scanned, buf, cap, offset, total, truncated);
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
        else name = "untrusted";
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

#define RTQ_PROCESS_FILE_METADATA_CACHE_MAX 64
typedef struct rtq_process_file_metadata {
    char path[520];
    char sha256[65];
    char signature[32];
} rtq_process_file_metadata;

static void query_process_file_metadata_cached(
    const char *path, rtq_process_file_metadata *cache, int *cache_count,
    char sha256[65], char signature[32]) {
    if (!sha256 || !signature) return;
    sha256[0] = '\0';
    signature[0] = '\0';
    if (!path || !path[0] || !cache || !cache_count) return;
    for (int i = 0; i < *cache_count; i++) {
        if (_stricmp(cache[i].path, path) == 0) {
            snprintf(sha256, 65, "%s", cache[i].sha256);
            snprintf(signature, 32, "%s", cache[i].signature);
            return;
        }
    }

    (void)hash_file_sha256_limited(path, sha256);
    query_file_signature_status(path, signature, 32);
    if (*cache_count >= RTQ_PROCESS_FILE_METADATA_CACHE_MAX) return;
    rtq_process_file_metadata *entry = &cache[*cache_count];
    memset(entry, 0, sizeof(*entry));
    snprintf(entry->path, sizeof(entry->path), "%s", path);
    snprintf(entry->sha256, sizeof(entry->sha256), "%s", sha256);
    snprintf(entry->signature, sizeof(entry->signature), "%s", signature);
    (*cache_count)++;
}

/* Use the same bounded, validated native query as process-generation-bound
 * command consumers.  RTQ owns the PID-to-handle lookup here, while the
 * shared helper owns reply validation and the UTF-8 capacity check. */
static int query_process_cmdline_native(DWORD pid, char *cmd, size_t cap, DWORD *error_code) {
    if (cmd && cap > 0) cmd[0] = '\0';
    if (error_code) *error_code = ERROR_SUCCESS;
    if (!cmd || cap < 2u || pid == 0) return -1;

    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!process) {
        if (error_code) *error_code = GetLastError();
        return -1;
    }
    char reason[64] = {0};
    int ok = edr_process_command_line_query_live(process, cmd, cap,
                                                 reason, sizeof(reason));
    CloseHandle(process);
    if (ok) return 1;

    if (error_code) {
        if (strcmp(reason, "command_line_too_long") == 0) {
            *error_code = ERROR_INSUFFICIENT_BUFFER;
        } else if (strcmp(reason, "command_line_buffer_unavailable") == 0) {
            *error_code = ERROR_OUTOFMEMORY;
        } else if (strcmp(reason, "command_line_encoding_invalid") == 0 ||
                   strcmp(reason, "command_line_encoding_failed") == 0) {
            *error_code = ERROR_NO_UNICODE_TRANSLATION;
        } else if (strcmp(reason, "command_line_reply_invalid") == 0) {
            *error_code = ERROR_INVALID_DATA;
        } else if (strcmp(reason, "command_line_api_unavailable") == 0) {
            *error_code = ERROR_PROC_NOT_FOUND;
        } else if (strcmp(reason, "command_line_query_failed") == 0) {
            *error_code = ERROR_GEN_FAILURE;
        } else {
            *error_code = ERROR_GEN_FAILURE;
        }
    }
    return -1;
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
        (void)rtq_appendf(buf, cap, offset, ",\"network_by_pid\":["); \
        started = 1; \
    } \
} while (0)
#define RTQ_NET_ARRAY_SEP() do { \
    if (added > 0) (void)rtq_appendf(buf, cap, offset, ","); \
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
            (void)rtq_appendf(buf, cap, offset, "{\"proto\":\"tcp\"");
            append_json_kv_str(buf, cap, offset, "state", tcp_state_text(tcp->table[i].dwState));
            append_json_kv_str(buf, cap, offset, "local_ip", lip);
            (void)rtq_appendf(buf, cap, offset, ",\"local_port\":%d", lp);
            append_json_kv_str(buf, cap, offset, "remote_ip", rip);
            if (rp > 0) (void)rtq_appendf(buf, cap, offset, ",\"remote_port\":%d", rp);
            (void)rtq_appendf(buf, cap, offset, "}");
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
            (void)rtq_appendf(buf, cap, offset, "{\"proto\":\"udp\"");
            append_json_kv_str(buf, cap, offset, "local_ip", lip);
            (void)rtq_appendf(buf, cap, offset, ",\"local_port\":%d}", lp);
            added++;
        }
    }
    free(udp);

    if (started) (void)rtq_appendf(buf, cap, offset, "]");

#undef RTQ_NET_ARRAY_BEGIN
#undef RTQ_NET_ARRAY_SEP
}

static int match_processes(rtq_filter *f, char *buf, int cap, int *offset, int *total,
                           rtq_errors *errs, int *truncated) {
    HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (h == INVALID_HANDLE_VALUE) {
        rtq_error_append(errs, "process", "snapshot_failed",
                         "CreateToolhelp32Snapshot failed", 1);
        return -1;
    }
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    int count = 0;
    int cmdline_queried = 0;
    int cmdline_sampled = 0;
    int cmdline_access_denied = 0;
    int cmdline_too_long = 0;
    int cmdline_failed = 0;
    int parent_cmdline_queried = 0;
    int parent_cmdline_sampled = 0;
    int parent_cmdline_access_denied = 0;
    int parent_cmdline_too_long = 0;
    int parent_cmdline_failed = 0;
    rtq_process_file_metadata file_metadata_cache[RTQ_PROCESS_FILE_METADATA_CACHE_MAX];
    int file_metadata_cache_count = 0;
    memset(file_metadata_cache, 0, sizeof(file_metadata_cache));
    if (Process32FirstW(h, &pe)) {
        do {
            if (rtq_cancelled(f)) break;
            char name[260] = {0};
            WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, name, sizeof(name), NULL, NULL);

            int ok = 1;
            if (f->process_name[0] && !str_contains_icase(name, f->process_name)) ok = 0;
            if (f->process_pid_max > 0 && (int)pe.th32ProcessID > f->process_pid_max) ok = 0;
            if (f->process_pid_min > 0 && (int)pe.th32ProcessID < f->process_pid_min) ok = 0;

            char path[520] = {0};
            char user[260] = {0};
            char cmdline[EDR_BR_STR_CMDLINE] = {0};
            char integrity[64] = {0};
            char exe_sha256[65] = {0};
            char signature[32] = {0};
            char parent_path[520] = {0};
            char parent_cmdline[EDR_BR_STR_CMDLINE] = {0};
            char parent_name[260] = {0};
            int process_cmdline_queried = 0;
            if (ok && f->process_path[0]) {
                query_process_path(pe.th32ProcessID, path, sizeof(path));
                if (!path[0] || !str_contains_icase(path, f->process_path)) ok = 0;
            }
            if (ok && f->process_user[0]) {
                query_process_user(pe.th32ProcessID, user, sizeof(user));
                if (!user[0] || !str_contains_icase(user, f->process_user)) ok = 0;
            }
            if (ok && (f->process_cmdline[0] || f->script_content[0] || f->script_engine[0])) {
                DWORD cmdline_error = ERROR_SUCCESS;
                process_cmdline_queried = 1;
                cmdline_queried++;
                int cmdline_rc = query_process_cmdline_native(pe.th32ProcessID, cmdline,
                                                              sizeof(cmdline), &cmdline_error);
                if (cmdline_rc >= 0) cmdline_sampled++;
                else if (cmdline_error == ERROR_ACCESS_DENIED) cmdline_access_denied++;
                else if (cmdline_error == ERROR_INSUFFICIENT_BUFFER) cmdline_too_long++;
                else cmdline_failed++;
                if (f->process_cmdline[0] && !str_contains_icase(cmdline, f->process_cmdline)) ok = 0;
                if (f->script_engine[0] && !str_contains_icase(name, f->script_engine) &&
                    !str_contains_icase(cmdline, f->script_engine)) ok = 0;
            }

            if (ok && *total < RTQ_MAX_RESULTS) {
                if (!path[0]) query_process_path(pe.th32ProcessID, path, sizeof(path));
                if (!user[0]) query_process_user(pe.th32ProcessID, user, sizeof(user));
                if (!process_cmdline_queried) {
                    DWORD cmdline_error = ERROR_SUCCESS;
                    process_cmdline_queried = 1;
                    cmdline_queried++;
                    int cmdline_rc = query_process_cmdline_native(pe.th32ProcessID, cmdline,
                                                                  sizeof(cmdline), &cmdline_error);
                    if (cmdline_rc >= 0) cmdline_sampled++;
                    else if (cmdline_error == ERROR_ACCESS_DENIED) cmdline_access_denied++;
                    else if (cmdline_error == ERROR_INSUFFICIENT_BUFFER) cmdline_too_long++;
                    else cmdline_failed++;
                }
                query_process_integrity_level(pe.th32ProcessID, integrity, sizeof(integrity));
                if (path[0]) {
                    query_process_file_metadata_cached(path, file_metadata_cache,
                                                       &file_metadata_cache_count,
                                                       exe_sha256, signature);
                }
                if (pe.th32ParentProcessID > 0) {
                    query_process_path(pe.th32ParentProcessID, parent_path, sizeof(parent_path));
                    DWORD parent_cmdline_error = ERROR_SUCCESS;
                    parent_cmdline_queried++;
                    int parent_cmdline_rc = query_process_cmdline_native(
                        pe.th32ParentProcessID, parent_cmdline, sizeof(parent_cmdline),
                        &parent_cmdline_error);
                    if (parent_cmdline_rc >= 0) parent_cmdline_sampled++;
                    else if (parent_cmdline_error == ERROR_ACCESS_DENIED) parent_cmdline_access_denied++;
                    else if (parent_cmdline_error == ERROR_INSUFFICIENT_BUFFER) parent_cmdline_too_long++;
                    else parent_cmdline_failed++;
                    if (parent_path[0]) {
                        const char *base = strrchr(parent_path, '\\');
                        snprintf(parent_name, sizeof(parent_name), "%s", base ? base + 1 : parent_path);
                    }
                }

                char row[RTQ_ROW_CAP];
                int row_offset = 0;
                row[0] = '\0';
                int row_ok = rtq_appendf(row, (int)sizeof(row), &row_offset,
                    "{\"type\":\"process\",\"pid\":%lu,\"name\":\"",
                    (unsigned long)pe.th32ProcessID) &&
                    append_json_escaped(row, (int)sizeof(row), &row_offset, name) &&
                    rtq_appendf(row, (int)sizeof(row), &row_offset, "\",\"ppid\":%lu",
                                (unsigned long)pe.th32ParentProcessID);
                if (row_ok && path[0]) row_ok = append_json_kv_str(row, (int)sizeof(row), &row_offset, "path", path);
                if (row_ok && user[0]) row_ok = append_json_kv_str(row, (int)sizeof(row), &row_offset, "user", user);
                if (row_ok && cmdline[0]) row_ok = append_json_kv_str(row, (int)sizeof(row), &row_offset, "cmdline", cmdline);
                if (row_ok && integrity[0]) row_ok = append_json_kv_str(row, (int)sizeof(row), &row_offset, "integrity_level", integrity);
                if (row_ok && exe_sha256[0]) row_ok = append_json_kv_str(row, (int)sizeof(row), &row_offset, "exe_hash", exe_sha256);
                if (row_ok && signature[0]) row_ok = append_json_kv_str(row, (int)sizeof(row), &row_offset, "signature", signature);
                if (row_ok && parent_name[0]) row_ok = append_json_kv_str(row, (int)sizeof(row), &row_offset, "parent_name", parent_name);
                if (row_ok && parent_path[0]) row_ok = append_json_kv_str(row, (int)sizeof(row), &row_offset, "parent_path", parent_path);
                if (row_ok && parent_cmdline[0]) row_ok = append_json_kv_str(row, (int)sizeof(row), &row_offset, "parent_cmdline", parent_cmdline);
                if (row_ok) append_process_network_by_pid(pe.th32ProcessID, row, (int)sizeof(row), &row_offset);
                if (row_ok && row_offset < (int)sizeof(row) - 1) {
                    row_ok = rtq_appendf(row, (int)sizeof(row), &row_offset, "}");
                } else {
                    row_ok = 0;
                }
                if (!row_ok || !rtq_commit_row(buf, cap, offset, total, row, row_offset, truncated)) {
                    if (truncated) *truncated = 1;
                    break;
                }
                count++;
            }
        } while (Process32NextW(h, &pe));
    }
    CloseHandle(h);
    if (cmdline_queried && cmdline_too_long > 0) {
        char message[256];
        snprintf(message, sizeof(message),
                 "native process_cmdline exceeded the bounded UTF-8 capacity of %u bytes; omitted and not used as complete match text; too_long=%d",
                 (unsigned)(EDR_BR_STR_CMDLINE - 1u), cmdline_too_long);
        rtq_error_append(errs, "process_cmdline", "too_long", message, 0);
    }
    if (cmdline_queried && cmdline_sampled == 0 &&
        (cmdline_access_denied + cmdline_failed) > 0) {
        char message[256];
        snprintf(message, sizeof(message),
                 "native command-line sampling unavailable for all candidates; access_denied=%d failed=%d",
                 cmdline_access_denied, cmdline_failed);
        rtq_error_append(errs, "process_cmdline", "collector_unavailable", message, 0);
    } else if (cmdline_queried && (cmdline_access_denied + cmdline_failed) > 0) {
        char message[256];
        snprintf(message, sizeof(message),
                 "native command-line sampling was partial; sampled=%d access_denied=%d failed=%d",
                 cmdline_sampled, cmdline_access_denied, cmdline_failed);
        rtq_error_append(errs, "process_cmdline", "partial_access", message, 0);
    }
    if (parent_cmdline_queried && parent_cmdline_too_long > 0) {
        char message[256];
        snprintf(message, sizeof(message),
                 "native parent_cmdline exceeded the bounded UTF-8 capacity of %u bytes; omitted from the row; too_long=%d",
                 (unsigned)(EDR_BR_STR_CMDLINE - 1u), parent_cmdline_too_long);
        rtq_error_append(errs, "parent_cmdline", "too_long", message, 0);
    }
    if (parent_cmdline_queried && parent_cmdline_sampled == 0 &&
        (parent_cmdline_access_denied + parent_cmdline_failed) > 0) {
        char message[256];
        snprintf(message, sizeof(message),
                 "native parent_cmdline sampling unavailable for all rows; access_denied=%d failed=%d",
                 parent_cmdline_access_denied, parent_cmdline_failed);
        rtq_error_append(errs, "parent_cmdline", "collector_unavailable", message, 0);
    } else if (parent_cmdline_queried &&
               (parent_cmdline_access_denied + parent_cmdline_failed) > 0) {
        char message[256];
        snprintf(message, sizeof(message),
                 "native parent_cmdline sampling was partial; sampled=%d access_denied=%d failed=%d",
                 parent_cmdline_sampled, parent_cmdline_access_denied, parent_cmdline_failed);
        rtq_error_append(errs, "parent_cmdline", "partial_access", message, 0);
    }
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
                              int remote_port, DWORD pid, char *buf, int cap, int *offset,
                              int *total, int *truncated) {
    if (f->network_proto[0] && !str_contains_icase(proto, f->network_proto)) return 0;
    if (f->network_state[0] && !str_contains_icase(state, f->network_state)) return 0;
    if (f->network_remote_ip[0] && !str_contains_icase(remote_ip, f->network_remote_ip)) return 0;
    if (f->network_remote_port > 0 && remote_port != f->network_remote_port) return 0;
    if (*total >= RTQ_MAX_RESULTS) {
        if (truncated) *truncated = 1;
        return 0;
    }
    char row[2048];
    int row_offset = 0;
    row[0] = '\0';
    int ok = rtq_appendf(row, (int)sizeof(row), &row_offset, "{\"type\":\"network\"") &&
             append_json_kv_str(row, (int)sizeof(row), &row_offset, "proto", proto) &&
             append_json_kv_str(row, (int)sizeof(row), &row_offset, "state", state) &&
             append_json_kv_str(row, (int)sizeof(row), &row_offset, "local_ip", local_ip) &&
             rtq_appendf(row, (int)sizeof(row), &row_offset, ",\"local_port\":%d", local_port) &&
             append_json_kv_str(row, (int)sizeof(row), &row_offset, "remote_ip", remote_ip);
    if (ok && remote_port > 0) ok = rtq_appendf(row, (int)sizeof(row), &row_offset, ",\"remote_port\":%d", remote_port);
    if (ok && pid > 0) ok = rtq_appendf(row, (int)sizeof(row), &row_offset, ",\"pid\":%lu", (unsigned long)pid);
    if (ok) ok = rtq_appendf(row, (int)sizeof(row), &row_offset, "}");
    if (!ok) {
        if (truncated) *truncated = 1;
        return 0;
    }
    return rtq_commit_row(buf, cap, offset, total, row, row_offset, truncated);
}

static int match_network(rtq_filter *f, char *buf, int cap, int *offset, int *total,
                         rtq_errors *errs, int *truncated) {
    int count = 0;
    DWORD tcp_rc = ERROR_SUCCESS;
    DWORD udp_rc = ERROR_SUCCESS;
    DWORD sz = 0;
    tcp_rc = GetExtendedTcpTable(NULL, &sz, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    PMIB_TCPTABLE_OWNER_PID tcp = (PMIB_TCPTABLE_OWNER_PID)malloc(sz);
    if (tcp) tcp_rc = GetExtendedTcpTable(tcp, &sz, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    else if (sz > 0) tcp_rc = ERROR_OUTOFMEMORY;
    if (tcp && tcp_rc == NO_ERROR) {
        for (DWORD i = 0; i < tcp->dwNumEntries && *total < RTQ_MAX_RESULTS; i++) {
            char lip[64], rip[64];
            ipv4_to_text(tcp->table[i].dwLocalAddr, lip, sizeof(lip));
            ipv4_to_text(tcp->table[i].dwRemoteAddr, rip, sizeof(rip));
            int lp = ntohs((u_short)tcp->table[i].dwLocalPort);
            int rp = ntohs((u_short)tcp->table[i].dwRemotePort);
            if (append_win_network(f, "tcp", tcp_state_text(tcp->table[i].dwState), lip, lp,
                                   rip, rp, tcp->table[i].dwOwningPid, buf, cap, offset,
                                   total, truncated)) count++;
        }
    }
    free(tcp);
    sz = 0;
    udp_rc = GetExtendedUdpTable(NULL, &sz, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    PMIB_UDPTABLE_OWNER_PID udp = (PMIB_UDPTABLE_OWNER_PID)malloc(sz);
    if (udp) udp_rc = GetExtendedUdpTable(udp, &sz, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    else if (sz > 0) udp_rc = ERROR_OUTOFMEMORY;
    if (udp && udp_rc == NO_ERROR) {
        for (DWORD i = 0; i < udp->dwNumEntries && *total < RTQ_MAX_RESULTS; i++) {
            char lip[64];
            ipv4_to_text(udp->table[i].dwLocalAddr, lip, sizeof(lip));
            int lp = ntohs((u_short)udp->table[i].dwLocalPort);
            if (append_win_network(f, "udp", "", lip, lp, "", 0,
                                   udp->table[i].dwOwningPid, buf, cap, offset, total,
                                   truncated)) count++;
        }
    }
    free(udp);
    if (tcp_rc != NO_ERROR && udp_rc != NO_ERROR) {
        char message[192];
        snprintf(message, sizeof(message),
                 "Windows IP helper collectors failed; tcp_error=%lu udp_error=%lu",
                 (unsigned long)tcp_rc, (unsigned long)udp_rc);
        rtq_error_append(errs, "network", "collector_failed", message, 1);
    } else if (tcp_rc != NO_ERROR || udp_rc != NO_ERROR) {
        char message[192];
        snprintf(message, sizeof(message),
                 "Windows IP helper collection partial; tcp_error=%lu udp_error=%lu",
                 (unsigned long)tcp_rc, (unsigned long)udp_rc);
        rtq_error_append(errs, "network", "partial_failure", message, 1);
    }
    return count;
}

static int append_win_file_result(rtq_filter *f, const char *path, const WIN32_FIND_DATAA *fd,
                                  char *buf, int cap, int *offset, int *total,
                                  int *truncated) {
    if (!path || !fd) return 0;
    if (*total >= RTQ_MAX_RESULTS) {
        if (truncated) *truncated = 1;
        return 0;
    }
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
    char row[RTQ_ROW_CAP];
    int row_offset = 0;
    row[0] = '\0';
    int ok = rtq_appendf(row, (int)sizeof(row), &row_offset, "{\"type\":\"file\",\"path\":\"") &&
             append_json_escaped(row, (int)sizeof(row), &row_offset, path) &&
             rtq_appendf(row, (int)sizeof(row), &row_offset, "\",\"size\":%lld",
                         (long long)sz.QuadPart);
    if (ok && sha[0]) ok = append_json_kv_str(row, (int)sizeof(row), &row_offset, "sha256", sha);
    if (ok) ok = rtq_appendf(row, (int)sizeof(row), &row_offset, "}");
    if (!ok) {
        if (truncated) *truncated = 1;
        return 0;
    }
    return rtq_commit_row(buf, cap, offset, total, row, row_offset, truncated);
}

static void scan_win_files_limited(rtq_filter *f, const char *root, int depth, int *scanned,
                                   char *buf, int cap, int *offset, int *total, int *truncated) {
    if (rtq_cancelled(f)) return;
    if (!root || !root[0] || depth < 0 || *scanned >= RTQ_FILE_SCAN_MAX || *total >= RTQ_MAX_RESULTS) return;
    DWORD attr = GetFileAttributesA(root);
    if (attr == INVALID_FILE_ATTRIBUTES) return;
    if (!(attr & FILE_ATTRIBUTE_DIRECTORY)) {
        WIN32_FIND_DATAA fd;
        memset(&fd, 0, sizeof(fd));
        HANDLE h = FindFirstFileA(root, &fd);
        if (h != INVALID_HANDLE_VALUE) {
            (*scanned)++;
            (void)append_win_file_result(f, root, &fd, buf, cap, offset, total, truncated);
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
        if (rtq_cancelled(f)) break;
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0) continue;
        char child[1024];
        snprintf(child, sizeof(child), "%s\\%s", root, fd.cFileName);
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            scan_win_files_limited(f, child, depth - 1, scanned, buf, cap, offset, total,
                                   truncated);
        } else {
            (*scanned)++;
            (void)append_win_file_result(f, child, &fd, buf, cap, offset, total, truncated);
        }
    } while (FindNextFileA(h, &fd) && *scanned < RTQ_FILE_SCAN_MAX && *total < RTQ_MAX_RESULTS);
    FindClose(h);
}

static int match_files(rtq_filter *f, char *buf, int cap, int *offset, int *total,
                       int *truncated) {
    int scanned = 0;
    int before = *total;
    if (f->file_path[0]) f->file_path_scanned = 1;
    if (f->file_sha256[0]) {
        if (f->file_path[0]) {
            DWORD attr = GetFileAttributesA(f->file_path);
            if (attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY)) {
                scan_win_files_limited(f, f->file_path, 0, &scanned, buf, cap, offset,
                                       total, truncated);
            }
        }
    } else if (f->file_path[0]) {
        scan_win_files_limited(f, f->file_path, RTQ_FILE_SCAN_DEPTH, &scanned, buf, cap,
                               offset, total, truncated);
    } else if (f->file_ext[0]) {
        scan_win_files_limited(f, "C:\\Windows\\Temp", RTQ_FILE_SCAN_DEPTH, &scanned, buf,
                               cap, offset, total, truncated);
        scan_win_files_limited(f, "C:\\Users\\Public", RTQ_FILE_SCAN_DEPTH, &scanned, buf,
                               cap, offset, total, truncated);
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

static int match_registry_key(rtq_filter *f, HKEY root, const char *subkey,
                              const char *display_path, int depth, int subtree,
                              int *keys_scanned, int *access_denied,
                              char *buf, int cap, int *offset, int *total,
                              int *truncated) {
    if (rtq_cancelled(f) || *keys_scanned >= 512 || *total >= RTQ_MAX_RESULTS) return 0;
    HKEY key = NULL;
    LONG open_rc = RegOpenKeyExA(root, subkey, 0, KEY_READ, &key);
    if (open_rc != ERROR_SUCCESS) {
        if (open_rc == ERROR_ACCESS_DENIED) (*access_denied)++;
        return 0;
    }
    (*keys_scanned)++;
    int count = 0;
    for (DWORD i = 0; i < 128 && *total < RTQ_MAX_RESULTS; i++) {
        if (rtq_cancelled(f)) break;
        char name[260];
        BYTE data[1024];
        DWORD name_len = sizeof(name), data_len = sizeof(data), type = 0;
        LONG rc = RegEnumValueA(key, i, name, &name_len, NULL, &type, data, &data_len);
        if (rc != ERROR_SUCCESS) break;
        if (f->registry_value[0] && !str_contains_icase(name, f->registry_value)) continue;
        char row[RTQ_ROW_CAP];
        int row_offset = 0;
        row[0] = '\0';
        int row_ok = rtq_appendf(row, (int)sizeof(row), &row_offset,
                                 "{\"type\":\"registry\"") &&
                     append_json_kv_str(row, (int)sizeof(row), &row_offset,
                                        "key", display_path) &&
                     append_json_kv_str(row, (int)sizeof(row), &row_offset,
                                        "value", name[0] ? name : "(Default)") &&
                     rtq_appendf(row, (int)sizeof(row), &row_offset,
                                 ",\"reg_type\":%lu", (unsigned long)type);
        if ((type == REG_SZ || type == REG_EXPAND_SZ) && data_len > 0) {
            data[sizeof(data) - 1u] = 0;
            if (row_ok) {
                row_ok = append_json_kv_str(row, (int)sizeof(row), &row_offset,
                                             "data", (const char *)data);
            }
        }
        if (row_ok) row_ok = rtq_appendf(row, (int)sizeof(row), &row_offset, "}");
        if (!row_ok || !rtq_commit_row(buf, cap, offset, total, row, row_offset, truncated)) {
            if (truncated) *truncated = 1;
            break;
        }
        count++;
    }
    if (subtree && depth < 4 && *keys_scanned < 512 && *total < RTQ_MAX_RESULTS) {
        for (DWORD i = 0; i < 256 && *keys_scanned < 512 && *total < RTQ_MAX_RESULTS; i++) {
            if (rtq_cancelled(f)) break;
            char child[260];
            DWORD child_len = sizeof(child);
            FILETIME modified;
            LONG enum_rc = RegEnumKeyExA(key, i, child, &child_len, NULL, NULL, NULL, &modified);
            if (enum_rc == ERROR_NO_MORE_ITEMS) break;
            if (enum_rc != ERROR_SUCCESS) continue;
            char child_subkey[780];
            char child_display[900];
            snprintf(child_subkey, sizeof(child_subkey), "%s%s%s",
                     subkey, subkey[0] ? "\\" : "", child);
            snprintf(child_display, sizeof(child_display), "%s\\%s", display_path, child);
            count += match_registry_key(f, root, child_subkey, child_display, depth + 1,
                                        subtree, keys_scanned, access_denied,
                                        buf, cap, offset, total, truncated);
        }
    }
    RegCloseKey(key);
    return count;
}

static int match_registry(rtq_filter *f, char *buf, int cap, int *offset, int *total,
                          rtq_errors *errs, int *truncated) {
    HKEY root;
    char subkey[520];
    if (!split_registry_path(f->registry_path, &root, subkey, sizeof(subkey))) {
        rtq_error_append(errs, "registry", "invalid_hive",
                         "registry_path must start with a supported Windows hive", 0);
        return -1;
    }
    int keys_scanned = 0;
    int access_denied = 0;
    int subtree = _stricmp(f->registry_mode, "subtree") == 0;
    int count = match_registry_key(f, root, subkey, f->registry_path, 0, subtree,
                                   &keys_scanned, &access_denied,
                                   buf, cap, offset, total, truncated);
    if (keys_scanned == 0) {
        rtq_error_append(errs, "registry", access_denied ? "access_denied" : "key_not_found",
                         access_denied ? "registry key access denied" : "registry key not found",
                         0);
    } else if (access_denied > 0) {
        char message[192];
        snprintf(message, sizeof(message),
                 "registry subtree sampling partial; keys_scanned=%d access_denied=%d",
                 keys_scanned, access_denied);
        rtq_error_append(errs, "registry", "partial_access", message, 0);
    }
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
    (void)rtq_appendf(buf, cap, offset, ",\"%s\":%llu", key, v);
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
                (void)rtq_appendf(buf, cap, offset, ",\"xml_truncated\":true");
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

static int match_eventlog(rtq_filter *f, char *buf, int cap, int *offset, int *total,
                          rtq_errors *errs, int *truncated) {
    wchar_t channel[128];
    wchar_t query[512];
    if (MultiByteToWideChar(CP_UTF8, 0, f->eventlog_channel[0] ? f->eventlog_channel : "System",
                            -1, channel, 128) <= 0 ||
        MultiByteToWideChar(CP_UTF8, 0, f->eventlog_query[0] ? f->eventlog_query : "*",
                            -1, query, 512) <= 0) {
        rtq_error_append(errs, "eventlog", "invalid_utf8",
                         "eventlog channel or query is not valid UTF-8", 0);
        return -1;
    }
    EVT_HANDLE h = EvtQuery(NULL, channel, query, EvtQueryChannelPath | EvtQueryReverseDirection);
    if (!h) {
        DWORD err = GetLastError();
        char message[192];
        snprintf(message, sizeof(message), "EvtQuery failed win32_error=%lu", (unsigned long)err);
        rtq_error_append(errs, "eventlog",
                         err == ERROR_ACCESS_DENIED ? "access_denied" : "query_failed",
                         message, err != ERROR_ACCESS_DENIED);
        return -1;
    }
    EVT_HANDLE render_ctx = EvtCreateRenderContext(0, NULL, EvtRenderContextSystem);
    if (!render_ctx) {
        rtq_error_append(errs, "eventlog", "render_context_failed",
                         "EvtCreateRenderContext failed; rows may lack evidence fields", 1);
    }
    int count = 0;
    int capacity_stop = 0;
    EVT_HANDLE events[16];
    DWORD returned = 0;
    while (*total < RTQ_MAX_RESULTS && EvtNext(h, 16, events, 1000, 0, &returned)) {
        if (rtq_cancelled(f)) {
            for (DWORD i = 0; i < returned; i++) EvtClose(events[i]);
            break;
        }
        for (DWORD i = 0; i < returned && *total < RTQ_MAX_RESULTS; i++) {
            char row[RTQ_ROW_CAP];
            int row_offset = 0;
            row[0] = '\0';
            int row_ok = rtq_appendf(row, (int)sizeof(row), &row_offset,
                                     "{\"type\":\"eventlog\"") &&
                         append_json_kv_str(row, (int)sizeof(row), &row_offset, "channel",
                                            f->eventlog_channel[0] ? f->eventlog_channel : "System") &&
                         append_json_kv_str(row, (int)sizeof(row), &row_offset, "query",
                                            f->eventlog_query[0] ? f->eventlog_query : "*");
            if (row_ok) {
                append_eventlog_evidence(render_ctx, events[i], row, (int)sizeof(row),
                                         &row_offset);
                row_ok = row_offset < (int)sizeof(row) - 1;
            }
            if (row_ok) row_ok = rtq_appendf(row, (int)sizeof(row), &row_offset, "}");
            if (!row_ok ||
                !rtq_commit_row(buf, cap, offset, total, row, row_offset, truncated)) {
                if (truncated) *truncated = 1;
                for (DWORD j = i; j < returned; j++) EvtClose(events[j]);
                capacity_stop = 1;
                break;
            }
            count++;
            EvtClose(events[i]);
        }
        if (capacity_stop) break;
    }
    if (*total >= RTQ_MAX_RESULTS && truncated) *truncated = 1;
    DWORD next_error = capacity_stop ? ERROR_SUCCESS : GetLastError();
    if (next_error != ERROR_SUCCESS && next_error != ERROR_NO_MORE_ITEMS &&
        next_error != ERROR_TIMEOUT) {
        char message[192];
        snprintf(message, sizeof(message), "EvtNext failed win32_error=%lu",
                 (unsigned long)next_error);
        rtq_error_append(errs, "eventlog", "enumeration_failed", message, 1);
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

static int match_processes(rtq_filter *f, char *buf, int cap, int *offset, int *total,
                           rtq_errors *errs, int *truncated) {
    const char *cmd = "ps -eo pid,ppid,user,comm,args";
    char *output = (char *)malloc(RTQ_SAMPLER_OUTPUT_MAX);
    if (!output) {
        rtq_error_append(errs, "process", "oom", "process sampler output allocation failed", 1);
        return -1;
    }
    int exit_code = 0;
    if (edr_shell_exec(cmd, RTQ_SAMPLER_TIMEOUT_SEC, output, RTQ_SAMPLER_OUTPUT_MAX, &exit_code) != 0 ||
        exit_code != 0) {
        char msg[768];
        sampler_error_message(msg, sizeof(msg), cmd, exit_code, output);
        rtq_error_append(errs, "process", exit_code == 124 ? "sampler_timeout" : "sampler_failed", msg, 1);
        free(output);
        return -1;
    }

#if !defined(__linux__)
    if (f->process_path[0]) {
        rtq_error_append(errs, "process", "process_path_unsupported",
                         "process_path requires /proc/<pid>/exe and is unavailable on this platform", 0);
    }
#endif

    int count = 0;
    char *save = NULL;
    char *line = strtok_r(output, "\n", &save);
    while (line && *total < RTQ_MAX_RESULTS) {
        char *cur = line;
        line = strtok_r(NULL, "\n", &save);
        int loc_pid = 0, loc_ppid = 0;
        char loc_user[64] = {0}, loc_comm[256] = {0};
        char rest[2560] = {0};
        (void)sscanf(cur, "%d %d %63s %255s %2559[^\n]",
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
        if (f->script_engine[0] && !str_contains_icase(loc_comm, f->script_engine) &&
            !str_contains_icase(rest, f->script_engine)) ok = 0;
        if (f->process_path[0] && !str_contains_icase(path, f->process_path)) ok = 0;
        if (!ok) continue;

        char row[RTQ_ROW_CAP];
        int row_offset = 0;
        row[0] = '\0';
        int row_ok = rtq_appendf(row, (int)sizeof(row), &row_offset,
            "{\"type\":\"process\",\"pid\":%d,\"ppid\":%d,\"name\":\"",
            loc_pid, loc_ppid) &&
            append_json_escaped(row, (int)sizeof(row), &row_offset, loc_comm) &&
            rtq_appendf(row, (int)sizeof(row), &row_offset, "\"") &&
            append_json_kv_str(row, (int)sizeof(row), &row_offset, "user", loc_user) &&
            append_json_kv_str(row, (int)sizeof(row), &row_offset, "cmdline", rest);
        if (row_ok && path[0]) {
            row_ok = append_json_kv_str(row, (int)sizeof(row), &row_offset, "path", path);
        }
        if (row_ok) row_ok = rtq_appendf(row, (int)sizeof(row), &row_offset, "}");
        if (!row_ok || !rtq_commit_row(buf, cap, offset, total, row, row_offset, truncated)) {
            if (truncated) *truncated = 1;
            break;
        }
        count++;
    }
    free(output);
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
    size_t addr_len = strlen(addr);
    if (addr_len >= sizeof(tmp)) return 0;
    memcpy(tmp, addr, addr_len + 1u);

    char *sep = strrchr(tmp, ':');
    if (!sep || !sep[1] || !is_port_text(sep + 1)) {
        sep = strrchr(tmp, '.');
    }
    if (!sep || !sep[1] || !is_port_text(sep + 1)) {
        size_t ip_len = strlen(tmp);
        if (ip_len >= ip_cap) return 0;
        memcpy(ip, tmp, ip_len + 1u);
        strip_brackets(ip);
        return 0;
    }

    *sep = '\0';
    size_t ip_len = strlen(tmp);
    if (ip_len >= ip_cap) return 0;
    memcpy(ip, tmp, ip_len + 1u);
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
                                 const char *tail, char *buf, int cap, int *offset, int *total,
                                 int *truncated) {
    char remote_ip[128] = {0};
    int remote_port = 0;
    split_addr_port(remote_addr, remote_ip, sizeof(remote_ip), &remote_port);

    if (f->network_proto[0] && !str_contains_icase(proto, f->network_proto)) return 0;
    if (f->network_state[0] && !str_contains_icase(state, f->network_state)) return 0;
    if (f->network_remote_ip[0] &&
        !str_contains_icase(remote_ip, f->network_remote_ip) &&
        !str_contains_icase(remote_addr, f->network_remote_ip)) return 0;
    if (f->network_remote_port > 0 && remote_port != f->network_remote_port) return 0;
    if (*total >= RTQ_MAX_RESULTS) {
        if (truncated) *truncated = 1;
        return 0;
    }

    char local_ip[128] = {0};
    int local_port = 0;
    char proc[128] = {0};
    int pid = 0;
    split_addr_port(local_addr, local_ip, sizeof(local_ip), &local_port);
    extract_ss_process(tail, proc, sizeof(proc), &pid);

    char row[4096];
    int row_offset = 0;
    row[0] = '\0';
    int ok = rtq_appendf(row, (int)sizeof(row), &row_offset, "{\"type\":\"network\"") &&
             append_json_kv_str(row, (int)sizeof(row), &row_offset, "proto", proto) &&
             append_json_kv_str(row, (int)sizeof(row), &row_offset, "state", state) &&
             append_json_kv_str(row, (int)sizeof(row), &row_offset, "local_addr", local_addr) &&
             append_json_kv_str(row, (int)sizeof(row), &row_offset, "local_ip", local_ip);
    if (ok && local_port > 0) ok = rtq_appendf(row, (int)sizeof(row), &row_offset, ",\"local_port\":%d", local_port);
    if (ok) ok = append_json_kv_str(row, (int)sizeof(row), &row_offset, "remote_addr", remote_addr);
    if (ok) ok = append_json_kv_str(row, (int)sizeof(row), &row_offset, "remote_ip", remote_ip);
    if (ok && remote_port > 0) ok = rtq_appendf(row, (int)sizeof(row), &row_offset, ",\"remote_port\":%d", remote_port);
    if (ok && pid > 0) ok = rtq_appendf(row, (int)sizeof(row), &row_offset, ",\"pid\":%d", pid);
    if (ok && proc[0]) ok = append_json_kv_str(row, (int)sizeof(row), &row_offset, "process_name", proc);
    if (ok) ok = rtq_appendf(row, (int)sizeof(row), &row_offset, "}");
    if (!ok) {
        if (truncated) *truncated = 1;
        return 0;
    }
    return rtq_commit_row(buf, cap, offset, total, row, row_offset, truncated);
}

static int scan_ss_network(rtq_filter *f, char *buf, int cap, int *offset, int *total,
                           int *sampler_ok, char *err_msg, size_t err_cap, int *truncated) {
    const char *cmd = "ss -tunapH";
    if (sampler_ok) *sampler_ok = 0;
    char *output = (char *)malloc(RTQ_SAMPLER_OUTPUT_MAX);
    if (!output) {
        if (err_msg && err_cap > 0) snprintf(err_msg, err_cap, "network sampler output allocation failed");
        return 0;
    }
    int exit_code = 0;
    if (edr_shell_exec(cmd, RTQ_SAMPLER_TIMEOUT_SEC, output, RTQ_SAMPLER_OUTPUT_MAX, &exit_code) != 0 ||
        exit_code != 0) {
        if (err_msg && err_cap > 0) sampler_error_message(err_msg, err_cap, cmd, exit_code, output);
        free(output);
        return 0;
    }
    if (sampler_ok) *sampler_ok = 1;

    int count = 0;
    char *save = NULL;
    char *line = strtok_r(output, "\n", &save);
    while (line && *total < RTQ_MAX_RESULTS) {
        char *cur = line;
        line = strtok_r(NULL, "\n", &save);
        char proto[16] = {0}, state[32] = {0}, recvq[32] = {0}, sendq[32] = {0};
        char local_addr[256] = {0}, remote_addr[256] = {0}, tail[1024] = {0};
        int n = sscanf(cur, "%15s %31s %31s %31s %255s %255s %1023[^\n]",
                       proto, state, recvq, sendq, local_addr, remote_addr, tail);
        if (n < 6) continue;
        if (append_network_result(f, proto, state, local_addr, remote_addr, tail, buf, cap,
                                  offset, total, truncated)) {
            count++;
        }
    }
    free(output);
    return count;
}

static int scan_netstat_network(rtq_filter *f, char *buf, int cap, int *offset, int *total,
                                int *sampler_ok, char *err_msg, size_t err_cap,
                                int *truncated) {
    const char *cmd = "netstat -an";
    if (sampler_ok) *sampler_ok = 0;
    char *output = (char *)malloc(RTQ_SAMPLER_OUTPUT_MAX);
    if (!output) {
        if (err_msg && err_cap > 0) snprintf(err_msg, err_cap, "network sampler output allocation failed");
        return 0;
    }
    int exit_code = 0;
    if (edr_shell_exec(cmd, RTQ_SAMPLER_TIMEOUT_SEC, output, RTQ_SAMPLER_OUTPUT_MAX, &exit_code) != 0 ||
        exit_code != 0) {
        if (err_msg && err_cap > 0) sampler_error_message(err_msg, err_cap, cmd, exit_code, output);
        free(output);
        return 0;
    }
    if (sampler_ok) *sampler_ok = 1;

    int count = 0;
    char *save = NULL;
    char *line = strtok_r(output, "\n", &save);
    while (line && *total < RTQ_MAX_RESULTS) {
        char *cur = line;
        line = strtok_r(NULL, "\n", &save);
        char proto[16] = {0}, recvq[32] = {0}, sendq[32] = {0};
        char local_addr[256] = {0}, remote_addr[256] = {0}, state[32] = {0}, tail[1024] = {0};
        int n = sscanf(cur, "%15s %31s %31s %255s %255s %31s %1023[^\n]",
                       proto, recvq, sendq, local_addr, remote_addr, state, tail);
        if (n < 5 || (!str_contains_icase(proto, "tcp") && !str_contains_icase(proto, "udp"))) continue;
        if (n < 6) snprintf(state, sizeof(state), "%s", "");
        if (append_network_result(f, proto, state, local_addr, remote_addr, tail, buf, cap,
                                  offset, total, truncated)) {
            count++;
        }
    }
    free(output);
    return count;
}

static int match_network(rtq_filter *f, char *buf, int cap, int *offset, int *total,
                         rtq_errors *errs, int *truncated) {
    int ss_ok = 0;
    int netstat_ok = 0;
    char ss_err[768] = {0};
    char netstat_err[768] = {0};
    int count = scan_ss_network(f, buf, cap, offset, total, &ss_ok, ss_err, sizeof(ss_err),
                                truncated);
    if (ss_ok) return count;
    count = scan_netstat_network(f, buf, cap, offset, total, &netstat_ok, netstat_err,
                                 sizeof(netstat_err), truncated);
    if (!netstat_ok) {
        char msg[1600];
        snprintf(msg, sizeof(msg), "all network samplers failed; ss=%s; netstat=%s",
                 ss_err[0] ? ss_err : "not attempted/empty error",
                 netstat_err[0] ? netstat_err : "not attempted/empty error");
        rtq_error_append(errs, "network", "sampler_failed", msg, 1);
    }
    return count;
}

static int match_files(rtq_filter *f, char *buf, int cap, int *offset, int *total,
                       int *truncated) {
    int scanned = 0;
    int before = *total;
    if (f->file_path[0]) f->file_path_scanned = 1;
    if (f->file_sha256[0]) {
        if (f->file_path[0]) {
            struct stat st;
            if (stat(f->file_path, &st) == 0 && S_ISREG(st.st_mode)) {
                scan_files_limited(f, f->file_path, 0, &scanned, buf, cap, offset, total,
                                   truncated);
            }
        }
    } else if (f->file_path[0]) {
        scan_files_limited(f, f->file_path, RTQ_FILE_SCAN_DEPTH, &scanned, buf, cap, offset,
                           total, truncated);
    } else if (f->file_ext[0]) {
        scan_files_limited(f, "/tmp", RTQ_FILE_SCAN_DEPTH, &scanned, buf, cap, offset, total,
                           truncated);
        scan_files_limited(f, "/var/tmp", RTQ_FILE_SCAN_DEPTH, &scanned, buf, cap, offset,
                           total, truncated);
    }
    return *total - before;
}
#endif

static int match_file_hash_cache(rtq_filter *f, char *buf, int cap, int *offset, int *total,
                                 rtq_errors *errs, int *truncated) {
    if (!f || !f->file_sha256[0]) return 0;
    f->file_cache_attempted = 1;
    size_t rows_cap = RTQ_MAX_RESULT_STR / 2u;
    char *rows = (char *)malloc(rows_cap);
    if (!rows) return 0;
    uint32_t returned = 0;
    uint32_t scanned = 0;
    int cache_truncated = 0;
    if (edr_local_evidence_cache_query_file_hash_json(f->file_sha256, f->file_path,
                                                      f->file_ext, RTQ_MAX_RESULTS,
                                                      rows, rows_cap,
                                                      &returned, &scanned,
                                                      &cache_truncated) != 0) {
        rtq_error_append(errs, "file_hash_cache", "cache_query_failed",
                         "local evidence hash cache query failed", 1);
        free(rows);
        return 0;
    }
    f->file_cache_candidates = scanned;
    int appended = append_json_array_items_to_result(buf, cap, offset, total, rows, returned,
                                                     truncated);
    if (cache_truncated && truncated) *truncated = 1;
    f->file_cache_hits = appended;
    free(rows);
    return appended;
}

static int match_files_cache_first(rtq_filter *f, char *buf, int cap, int *offset, int *total,
                                   rtq_errors *errs, int *truncated) {
    if (!f) return 0;
    int before = *total;
    int cache_hits = 0;
    if (f->file_sha256[0]) {
        cache_hits = match_file_hash_cache(f, buf, cap, offset, total, errs, truncated);
    }
    if (!f->file_sha256[0] || (cache_hits == 0 && f->file_path[0])) {
        (void)match_files(f, buf, cap, offset, total, truncated);
    }
    return *total - before;
}

void edr_response_rtq_execute(const char *cmd_id, const uint8_t *pl,
                               size_t len, const EdrSoarCommandMeta *sm) {
    if (!edr_command_rtq_readonly_enabled()) {
        g_cmd_rejected++;
        edr_command_audit_both(cmd_id, "reject rtq_execute: readonly RTQ disabled");
        edr_command_emit_always_typed(cmd_id, "rtq_execute", sm, EdrCmdExecRejected, 1, "readonly RTQ disabled");
        return;
    }

    rtq_filter filter;
    if (parse_rtq_filter(pl, len, &filter) != 0) {
        g_cmd_exec_fail++;
        edr_command_audit_both(cmd_id, "rtq_execute: no filter conditions");
        edr_command_emit_always_typed(cmd_id, "rtq_execute", sm, EdrCmdExecFailed, 2, "no filter conditions");
        return;
    }
    filter.command_id = cmd_id;

    char *result = (char *)malloc(RTQ_MAX_RESULT_STR);
    if (!result) {
        g_cmd_exec_fail++;
        edr_command_emit_always_typed(cmd_id, "rtq_execute", sm, EdrCmdExecFailed, 3, "oom");
        return;
    }

    int offset = 0;
    int total = 0;
    int has_proc = filter.has_process;
    int has_net = filter.has_network;
    int has_file = filter.has_file;
    int has_registry = filter.has_registry;
    int has_eventlog = filter.has_eventlog;
    int output_truncated = 0;
    rtq_errors errors;
    rtq_error_init(&errors);

    (void)rtq_appendf(result, RTQ_MAX_RESULT_STR, &offset, "{\"results\":[\n");

#ifdef _WIN32
    if (has_proc) {
        (void)match_processes(&filter, result, RTQ_COLLECTOR_RESULT_CAP, &offset, &total,
                              &errors, &output_truncated);
    }
    if (rtq_cancelled(&filter)) goto cancelled;
    if (has_net) {
        (void)match_network(&filter, result, RTQ_COLLECTOR_RESULT_CAP, &offset, &total,
                            &errors, &output_truncated);
    }
    if (rtq_cancelled(&filter)) goto cancelled;
    if (has_file) {
        (void)match_files_cache_first(&filter, result, RTQ_COLLECTOR_RESULT_CAP, &offset,
                                      &total, &errors, &output_truncated);
    }
    if (rtq_cancelled(&filter)) goto cancelled;
    if (has_registry) {
        (void)match_registry(&filter, result, RTQ_COLLECTOR_RESULT_CAP, &offset, &total,
                             &errors, &output_truncated);
    }
    if (rtq_cancelled(&filter)) goto cancelled;
    if (has_eventlog) {
        (void)match_eventlog(&filter, result, RTQ_COLLECTOR_RESULT_CAP, &offset, &total,
                             &errors, &output_truncated);
    }
    if (rtq_cancelled(&filter)) goto cancelled;
#else
    if (has_proc) {
        (void)match_processes(&filter, result, RTQ_COLLECTOR_RESULT_CAP, &offset, &total,
                              &errors, &output_truncated);
    }
    if (rtq_cancelled(&filter)) goto cancelled;
    if (has_net) {
        (void)match_network(&filter, result, RTQ_COLLECTOR_RESULT_CAP, &offset, &total,
                            &errors, &output_truncated);
    }
    if (rtq_cancelled(&filter)) goto cancelled;
    if (has_file) {
        (void)match_files_cache_first(&filter, result, RTQ_COLLECTOR_RESULT_CAP, &offset,
                                      &total, &errors, &output_truncated);
    }
    if (rtq_cancelled(&filter)) goto cancelled;
    if (has_registry) {
        rtq_error_append(&errors, "registry", "platform_unsupported",
                         "registry collector is only available on Windows", 0);
    }
    if (has_eventlog) {
        rtq_error_append(&errors, "eventlog", "platform_unsupported",
                         "eventlog collector is only available on Windows", 0);
    }
#endif
    (void)has_file;
    (void)has_registry;
    (void)has_eventlog;

    if (output_truncated || total >= RTQ_MAX_RESULTS ||
        offset >= RTQ_COLLECTOR_RESULT_CAP - 1024) {
        output_truncated = 1;
        rtq_error_append(&errors, "command_result_transport", "result_truncated",
                         "RTQ rows exceeded the durable inline result limit; complete rows were retained",
                         0);
    }

    const char *cache_status = !filter.file_sha256[0]
                                   ? "not_requested"
                                   : (filter.file_cache_hits > 0 ? "hit" : "miss");
    (void)rtq_appendf(result, RTQ_MAX_RESULT_STR, &offset,
        "\n],\"total\":%d,\"truncated\":%s,\"meta\":{\"file_hash\":{\"cache_status\":\"%s\",\"cache_attempted\":%s,"
        "\"cache_hits\":%d,\"cache_candidates_scanned\":%u,\"path_scanned\":%s}},\"error\":",
        total, output_truncated ? "true" : "false", cache_status,
        filter.file_cache_attempted ? "true" : "false",
        filter.file_cache_hits, filter.file_cache_candidates,
        filter.file_path_scanned ? "true" : "false");
    if (errors.count > errors.warning_count) {
        (void)rtq_appendf(result, RTQ_MAX_RESULT_STR, &offset, "\"");
        (void)append_json_escaped(result, RTQ_MAX_RESULT_STR, &offset,
                                  "one or more RTQ collectors failed");
        (void)rtq_appendf(result, RTQ_MAX_RESULT_STR, &offset,
                          "\",\"errors\":[%s],\"warning_count\":%d}",
                          errors.json, errors.warning_count);
    } else {
        (void)rtq_appendf(result, RTQ_MAX_RESULT_STR, &offset,
                          "null,\"errors\":[%s],\"warning_count\":%d}",
                          errors.json, errors.warning_count);
    }

    g_cmd_handled++; g_cmd_exec_ok++;
    edr_command_audit_both(cmd_id, "rtq_execute: ok");
    edr_command_emit_always_typed(cmd_id, "rtq_execute", sm, EdrCmdExecOk, 0, result);
    free(result);
    return;

cancelled:
    free(result);
    g_cmd_exec_fail++;
    edr_command_audit_both(cmd_id, "rtq_execute: cancelled during collection");
    edr_command_emit_always_typed_status(cmd_id, "rtq_execute", sm, EdrCmdExecFailed, 130,
                                         "RTQ collection cancelled", "cancelled");
}
