#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <tlhelp32.h>
#include <iphlpapi.h>
#include <winevt.h>
#ifdef _MSC_VER
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
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
#include "edr/rtq_contract.h"
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
    int overflowed;
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
    int file_scan_limit;
    int file_depth_limit;
    int file_unavailable;
    int file_hash_size_limit;
    int file_path_missing;
    int file_cache_failed;

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

#ifdef _WIN32
static int wide_to_utf8_str(LPCWSTR src, char *out, size_t cap);
static int utf8_to_wide_str(const char *src, WCHAR *out, size_t count) {
    return src && out && count > 0 &&
           MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, src, -1, out, (int)count) > 0;
}
static DWORD win_file_attributes(const char *path) {
    WCHAR wide[1024];
    if (!utf8_to_wide_str(path, wide, sizeof(wide) / sizeof(wide[0]))) {
        SetLastError(ERROR_NO_UNICODE_TRANSLATION);
        return INVALID_FILE_ATTRIBUTES;
    }
    return GetFileAttributesW(wide);
}
#endif

static int rtq_cancelled(const rtq_filter *f) {
    return f && f->command_id && edr_command_cancel_requested(f->command_id);
}

static int rtq_sampler_cancel_check(void *user) {
    return rtq_cancelled((const rtq_filter *)user);
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
        if (edr_parse_json_int(pl, len, "process_pid_min", &v) && v > 0) {
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
        } else if (ch < 32) {
            if (*offset >= cap - 6) goto overflow;
            static const char hex[] = "0123456789abcdef";
            buf[(*offset)++] = '\\'; buf[(*offset)++] = 'u';
            buf[(*offset)++] = '0'; buf[(*offset)++] = '0';
            buf[(*offset)++] = hex[ch >> 4]; buf[(*offset)++] = hex[ch & 15];
        } else {
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

/* Shared event scope belongs to the batch. Charge its encoded bytes against
 * the same fixed result budget so even escaped input cannot crowd out the
 * diagnostics/footer needed by durable replay. */
static int eventlog_batch_metadata(const rtq_filter *f, char *buf, int cap) {
    int offset = 0;
    if (!f || !buf || cap <= 0) return -1;
    buf[0] = '\0';
    if (!f->has_eventlog) return 0;
    if (!rtq_appendf(buf, cap, &offset,
                     "\"eventlog\":{\"schema\":\"" EDR_RTQ_EVENTLOG_BATCH_SCHEMA "\"") ||
        !append_json_kv_str(buf, cap, &offset, "channel",
                            f->eventlog_channel[0] ? f->eventlog_channel : "System") ||
        !append_json_kv_str(buf, cap, &offset, "query",
                            f->eventlog_query[0] ? f->eventlog_query : "*") ||
        !rtq_appendf(buf, cap, &offset, "},")) return -1;
    return offset;
}

static int rtq_commit_row(char *buf, int cap, int *offset, int *total,
                          const char *row, int row_len, int *truncated) {
    if (!buf || !offset || !total || !row || row_len <= 0 ||
        *offset < 0 || *offset >= cap) {
        if (truncated) *truncated = 1;
        return 0;
    }
    int separator = *total > 0 ? 1 : 0;
    if (*total >= RTQ_MAX_RESULTS || row_len >= cap || separator + row_len >= cap - *offset) {
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
    errs->overflowed = 0;
}

static void rtq_error_append(rtq_errors *errs, const char *source, const char *code,
                             const char *message, int retryable) {
    if (!errs || errs->overflowed) return;
    char diagnostic_key[192];
    snprintf(diagnostic_key, sizeof(diagnostic_key), "\"source\":\"%s\",\"code\":\"%s\"", source ? source : "rtq", code ? code : "collector_failed");
    if (strstr(errs->json, diagnostic_key)) return;
    char row[512];
    char bounded_message[129];
    snprintf(bounded_message, sizeof(bounded_message), "%s", message ? message : "RTQ collector failed");
    int row_offset = 0;
    row[0] = '\0';
    if (!rtq_appendf(row, (int)sizeof(row), &row_offset, "{\"source\":\"") ||
        !append_json_escaped(row, (int)sizeof(row), &row_offset, source ? source : "rtq") ||
        !rtq_appendf(row, (int)sizeof(row), &row_offset, "\",\"code\":\"") ||
        !append_json_escaped(row, (int)sizeof(row), &row_offset, code ? code : "collector_failed") ||
        !rtq_appendf(row, (int)sizeof(row), &row_offset, "\",\"message\":\"") ||
        !append_json_escaped(row, (int)sizeof(row), &row_offset,
                             bounded_message)) {
        return;
    }
    int warning = code && (strcmp(code, "partial_access") == 0 ||
                           strcmp(code, "result_truncated") == 0 ||
                           strcmp(code, "scan_limit") == 0 ||
                           strcmp(code, "scan_depth_limit") == 0 ||
                           strcmp(code, "field_unavailable") == 0 ||
                           strcmp(code, "hash_size_limit") == 0);
    if (!rtq_appendf(row, (int)sizeof(row), &row_offset,
                     "\",\"retryable\":%s,\"severity\":\"%s\"}",
                     retryable ? "true" : "false", warning ? "warning" : "error")) {
        return;
    }
    int separator = errs->count > 0 ? 1 : 0;
    if (errs->count >= 31 || separator + row_offset + 160 >= (int)sizeof(errs->json) - errs->offset) {
        /* Reserve a terminal diagnostic so a later failure cannot disappear
         * behind a full warning array. The signed projection keeps this code. */
        const char *overflow = "{\"source\":\"command_result_transport\",\"code\":\"collector_failed\",\"severity\":\"error\",\"retryable\":false}";
        if (separator) errs->json[errs->offset++] = ',';
        size_t length = strlen(overflow);
        memcpy(errs->json + errs->offset, overflow, length + 1);
        errs->offset += (int)length;
        errs->count++;
        errs->overflowed = 1;
        return;
    }
    if (separator) errs->json[errs->offset++] = ',';
    memcpy(errs->json + errs->offset, row, (size_t)row_offset);
    errs->offset += row_offset;
    errs->json[errs->offset] = '\0';
    errs->count++;
    if (warning) errs->warning_count++;
}

static void rtq_sampler_complete_lines(char *output, const char *source, rtq_errors *errs) {
    size_t length = strlen(output);
    if (length < RTQ_SAMPLER_OUTPUT_MAX - 1u) return;
    rtq_error_append(errs, source, "scan_limit", "sampler output exceeded bounded capacity", 0);
    if (length && output[length - 1] != '\n') {
        char *last = strrchr(output, '\n');
        if (last) last[1] = '\0';
        else output[0] = '\0';
    }
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

static void canonical_network_state(const char *input, char *out, size_t cap) {
    if (!edr_rtq_network_state_normalize(input, out, cap) && cap) out[0] = '\0';
}

static int file_has_ext(const char *path, const char *ext) {
    if (!ext || !ext[0]) return 1;
    if (!path) return 0;
    const char *dot = strrchr(path, '.');
    if (!dot) return 0;
    return str_eq_icase(dot, ext) ||
           (ext[0] != '.' && str_eq_icase(dot + 1, ext));
}

/* 1 match/no hash requested, 0 mismatch, -1 unreadable, -2 size limit. */
static int hash_file_if_needed(const rtq_filter *filter, const char *path, const char *expected, char out65[65]) {
    out65[0] = '\0';
    if (!expected || !expected[0]) return 1;
#ifdef _WIN32
    WCHAR wide[1024];
    if (!utf8_to_wide_str(path, wide, sizeof(wide) / sizeof(wide[0]))) return -1;
    FILE *file = _wfopen(wide, L"rb");
#else
    FILE *file = fopen(path, "rb");
#endif
    if (!file) return -1;
    if (fseek(file, 0, SEEK_END) != 0) { fclose(file); return -1; }
    long size = ftell(file);
    if (size < 0) { fclose(file); return -1; }
    if (size > RTQ_FILE_HASH_MAX) { fclose(file); return -2; }
    rewind(file);
    EdrSha256Ctx ctx;
    edr_sha256_init(&ctx);
    unsigned char chunk[32768];
    size_t hashed = 0;
    for (;;) {
        if (rtq_cancelled(filter)) { fclose(file); return -1; }
        size_t count = fread(chunk, 1, sizeof(chunk), file);
        if (count > RTQ_FILE_HASH_MAX - hashed) { fclose(file); return -2; }
        hashed += count;
        if (count) edr_sha256_update(&ctx, chunk, count);
        if (count < sizeof(chunk)) {
            if (ferror(file)) { fclose(file); return -1; }
            break;
        }
    }
    fclose(file);
    if (hashed != (size_t)size) return -1;
    uint8_t digest[EDR_SHA256_DIGEST_LEN];
    static const char hex[] = "0123456789abcdef";
    edr_sha256_final(&ctx, digest);
    for (size_t i = 0; i < sizeof(digest); i++) {
        out65[i * 2] = hex[digest[i] >> 4];
        out65[i * 2 + 1] = hex[digest[i] & 15];
    }
    out65[64] = '\0';
    return str_eq_icase(out65, expected);
}

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
    int hash_rc = hash_file_if_needed(f, path, f->file_sha256, sha);
    if (hash_rc <= 0) {
        if (hash_rc == -2) f->file_hash_size_limit = 1;
        else if (hash_rc < 0) f->file_unavailable = 1;
        return 0;
    }
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
    if (rtq_cancelled(f) || !root || !root[0]) return;
    if (depth < 0) { f->file_depth_limit = 1; return; }
    if (*scanned >= RTQ_FILE_SCAN_MAX) { f->file_scan_limit = 1; return; }
    if (*total >= RTQ_MAX_RESULTS) { *truncated = 1; return; }
    struct stat st;
    if (lstat(root, &st) != 0) {
        if (errno == ENOENT && strcmp(root, f->file_path) == 0) f->file_path_missing = 1;
        else f->file_unavailable = 1;
        return;
    }
    /* Do not follow symlinks outside the requested bounded tree. */
    if (S_ISLNK(st.st_mode)) { f->file_unavailable = 1; return; }
    if (S_ISREG(st.st_mode)) {
        (*scanned)++;
        (void)append_file_result(f, root, buf, cap, offset, total, truncated);
        return;
    }
    if (!S_ISDIR(st.st_mode)) return;
    DIR *dir = opendir(root);
    if (!dir) { f->file_unavailable = 1; return; }
    struct dirent *entry;
    errno = 0;
    while ((entry = readdir(dir)) != NULL) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        if (rtq_cancelled(f)) break;
        if (*scanned >= RTQ_FILE_SCAN_MAX) { f->file_scan_limit = 1; break; }
        if (*total >= RTQ_MAX_RESULTS || *truncated) { *truncated = 1; break; }
        char child[1024];
        int written = snprintf(child, sizeof(child), "%s/%s", root, entry->d_name);
        if (written < 0 || written >= (int)sizeof(child)) { f->file_unavailable = 1; continue; }
        scan_files_limited(f, child, depth - 1, scanned, buf, cap, offset, total, truncated);
        errno = 0;
    }
    if (errno) f->file_unavailable = 1;
    closedir(dir);
}

#endif

static int str_contains_icase(const char *haystack, const char *needle) {
    if (!needle || !needle[0]) return 1;
    if (!haystack) return 0;
    for (const char *start = haystack; *start; start++) {
        size_t i = 0;
        while (needle[i] && start[i] &&
               tolower((unsigned char)needle[i]) == tolower((unsigned char)start[i])) i++;
        if (!needle[i]) return 1;
    }
    return 0;
}

#ifdef _WIN32
static void query_process_path(DWORD pid, char *path, size_t cap) {
    if (!path || cap == 0) return;
    path[0] = '\0';
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (process) {
        WCHAR wide[1024];
        DWORD count = sizeof(wide) / sizeof(wide[0]);
        if (QueryFullProcessImageNameW(process, 0, wide, &count)) (void)wide_to_utf8_str(wide, path, cap);
        CloseHandle(process);
    }
}

static void query_process_user(DWORD pid, char *user, size_t cap) {
    if (!user || cap == 0) return;
    user[0] = '\0';
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!process) return;
    HANDLE token = NULL;
    if (!OpenProcessToken(process, TOKEN_QUERY, &token)) { CloseHandle(process); return; }
    DWORD need = 0;
    GetTokenInformation(token, TokenUser, NULL, 0, &need);
    TOKEN_USER *info = need > 0 && need <= 65536 ? (TOKEN_USER *)malloc(need) : NULL;
    if (info && GetTokenInformation(token, TokenUser, info, need, &need)) {
        WCHAR name[128], domain[128], combined[258];
        DWORD name_length = 128, domain_length = 128;
        SID_NAME_USE use;
        if (LookupAccountSidW(NULL, info->User.Sid, name, &name_length, domain, &domain_length, &use)) {
            int written = swprintf(combined, sizeof(combined) / sizeof(combined[0]), L"%ls\\%ls", domain, name);
            if (written >= 0) (void)wide_to_utf8_str(combined, user, cap);
        }
    }
    free(info);
    CloseHandle(token);
    CloseHandle(process);
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
    int has_entry = Process32FirstW(h, &pe);
    DWORD enumeration_error = has_entry ? ERROR_SUCCESS : GetLastError();
    if (has_entry) {
        do {
            if (rtq_cancelled(f)) break;
            char name[780] = {0};
            if (!wide_to_utf8_str(pe.szExeFile, name, sizeof(name))) {
                rtq_error_append(errs, "process", "field_unavailable", "process name could not be read completely", 0);
                continue;
            }

            int ok = 1;
            if (f->process_name[0] && !str_contains_icase(name, f->process_name)) ok = 0;
            if (f->process_pid_max > 0 && (int)pe.th32ProcessID > f->process_pid_max) ok = 0;
            if (f->process_pid_min > 0 && (int)pe.th32ProcessID < f->process_pid_min) ok = 0;

            char path[520] = {0};
            char user[260] = {0};
            char cmdline[8193] = {0};
            if (ok && f->process_path[0]) {
                query_process_path(pe.th32ProcessID, path, sizeof(path));
                if (!path[0]) rtq_error_append(errs, "process", "field_unavailable", "process path could not be read", 0);
                if (!path[0] || !str_contains_icase(path, f->process_path)) ok = 0;
            }
            if (ok && f->process_user[0]) {
                query_process_user(pe.th32ProcessID, user, sizeof(user));
                if (!user[0]) rtq_error_append(errs, "process", "field_unavailable", "requested process owner could not be read", 0);
                if (!user[0] || !str_contains_icase(user, f->process_user)) ok = 0;
            }
            if (ok && (f->process_cmdline[0] || f->script_content[0] || f->script_engine[0])) {
                DWORD cmdline_error = ERROR_SUCCESS;
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

            if (ok) {
                if (!path[0]) query_process_path(pe.th32ProcessID, path, sizeof(path));
                if (!path[0]) rtq_error_append(errs, "process", "field_unavailable", "process path could not be read", 0);

                char row[RTQ_ROW_CAP];
                int row_offset = 0;
                row[0] = '\0';
                int row_ok = rtq_appendf(row, (int)sizeof(row), &row_offset,
                    "{\"type\":\"process\",\"pid\":%lu,\"name\":\"",
                    (unsigned long)pe.th32ProcessID) &&
                    append_json_escaped(row, (int)sizeof(row), &row_offset, name) &&
                    rtq_appendf(row, (int)sizeof(row), &row_offset, "\"");
                if (row_ok && path[0]) row_ok = append_json_kv_str(row, (int)sizeof(row), &row_offset, "path", path);
                if (row_ok && user[0]) row_ok = append_json_kv_str(row, (int)sizeof(row), &row_offset, "user", user);
                if (row_ok && cmdline[0]) row_ok = append_json_kv_str(row, (int)sizeof(row), &row_offset, "cmdline", cmdline);
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
        } while ((has_entry = Process32NextW(h, &pe)) != FALSE);
        if (!has_entry) enumeration_error = GetLastError();
    }
    if (!*truncated && !rtq_cancelled(f) && enumeration_error != ERROR_SUCCESS && enumeration_error != ERROR_NO_MORE_FILES) {
        rtq_error_append(errs, "process", "enumeration_failed", "process snapshot enumeration failed", 1);
    }
    CloseHandle(h);
    if (cmdline_queried && cmdline_too_long > 0) {
        char message[256];
        snprintf(message, sizeof(message),
                 "native process_cmdline exceeded the bounded UTF-8 capacity of %u bytes; omitted and not used as complete match text; too_long=%d",
                 (unsigned)8192, cmdline_too_long);
        rtq_error_append(errs, "process_cmdline", "field_unavailable", message, 0);
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
    if (f->network_proto[0] && !str_eq_icase(proto, f->network_proto)) return 0;
    if (f->network_state[0] && !str_eq_icase(state, f->network_state)) return 0;
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

/* The table can grow between size discovery and the read. Retry only that
 * bounded race, retain cancellation, and never allocate an unbounded table. */
static void *read_win_network_table(rtq_filter *f, int tcp, ULONG family, DWORD *error) {
    DWORD size = 0;
    *error = tcp ? GetExtendedTcpTable(NULL, &size, FALSE, family, TCP_TABLE_OWNER_PID_ALL, 0)
                 : GetExtendedUdpTable(NULL, &size, FALSE, family, UDP_TABLE_OWNER_PID, 0);
    for (int attempt = 0; attempt < 3 && !rtq_cancelled(f); attempt++) {
        if (*error != ERROR_INSUFFICIENT_BUFFER || size == 0 || size > 4u * 1024u * 1024u) return NULL;
        void *table = malloc(size);
        if (!table) { *error = ERROR_OUTOFMEMORY; return NULL; }
        *error = tcp ? GetExtendedTcpTable(table, &size, FALSE, family, TCP_TABLE_OWNER_PID_ALL, 0)
                     : GetExtendedUdpTable(table, &size, FALSE, family, UDP_TABLE_OWNER_PID, 0);
        if (*error == NO_ERROR) return table;
        free(table);
    }
    return NULL;
}

static int ipv6_to_text(const UCHAR address[16], DWORD scope, char *out, size_t cap) {
    char text[INET6_ADDRSTRLEN];
    if (!InetNtopA(AF_INET6, (void *)address, text, sizeof(text))) return 0;
    int length = scope ? snprintf(out, cap, "%s%%%lu", text, (unsigned long)scope)
                       : snprintf(out, cap, "%s", text);
    return length >= 0 && (size_t)length < cap;
}

static int match_network(rtq_filter *f, char *buf, int cap, int *offset, int *total,
                         rtq_errors *errs, int *truncated) {
    int before = *total;
    int requested = 0, failed = 0;
    int include_tcp = !f->network_proto[0] || str_eq_icase(f->network_proto, "TCP");
    int include_udp = !f->network_proto[0] || str_eq_icase(f->network_proto, "UDP");
    if (str_eq_icase(f->network_state, "UNCONN")) include_tcp = 0;
    if (f->network_state[0] && !str_eq_icase(f->network_state, "UNCONN") &&
        !str_eq_icase(f->network_state, "UNKNOWN")) include_udp = 0;
    /* Windows owner-PID UDP tables contain local endpoints only. A remote
     * predicate cannot be established from that table, even on IPv6. */
    if (include_udp && (f->network_remote_ip[0] || f->network_remote_port > 0)) {
        rtq_error_append(errs, "network", include_tcp ? "field_unavailable" : "collector_unavailable",
                         "Windows UDP owner tables do not expose remote peers", 0);
        include_udp = 0;
    }
    for (int tcp = 1; tcp >= 0; tcp--) {
        if ((tcp && !include_tcp) || (!tcp && !include_udp)) continue;
        for (int version = 4; version <= 6; version += 2) {
            if (rtq_cancelled(f) || *truncated) return *total - before;
            DWORD error;
            requested++;
            void *table = read_win_network_table(f, tcp, version == 4 ? AF_INET : AF_INET6, &error);
            if (!table) { failed++; continue; }
            DWORD count = *(DWORD *)table;
            for (DWORD i = 0; i < count; i++) {
                if (rtq_cancelled(f) || *truncated) break;
                char local[64] = {0}, remote[64] = {0};
                DWORD local_port = 0, remote_port = 0, pid = 0, state = 0;
                if (tcp && version == 4) {
                    MIB_TCPROW_OWNER_PID *row = &((PMIB_TCPTABLE_OWNER_PID)table)->table[i];
                    ipv4_to_text(row->dwLocalAddr, local, sizeof(local));
                    ipv4_to_text(row->dwRemoteAddr, remote, sizeof(remote));
                    local_port = row->dwLocalPort; remote_port = row->dwRemotePort;
                    pid = row->dwOwningPid; state = row->dwState;
                } else if (tcp) {
                    MIB_TCP6ROW_OWNER_PID *row = &((PMIB_TCP6TABLE_OWNER_PID)table)->table[i];
                    if (!ipv6_to_text(row->ucLocalAddr, row->dwLocalScopeId, local, sizeof(local)) ||
                        !ipv6_to_text(row->ucRemoteAddr, row->dwRemoteScopeId, remote, sizeof(remote))) {
                        rtq_error_append(errs, "network", "field_unavailable", "IPv6 address conversion failed", 0);
                        continue;
                    }
                    local_port = row->dwLocalPort; remote_port = row->dwRemotePort;
                    pid = row->dwOwningPid; state = row->dwState;
                } else if (version == 4) {
                    MIB_UDPROW_OWNER_PID *row = &((PMIB_UDPTABLE_OWNER_PID)table)->table[i];
                    ipv4_to_text(row->dwLocalAddr, local, sizeof(local));
                    local_port = row->dwLocalPort; pid = row->dwOwningPid;
                } else {
                    MIB_UDP6ROW_OWNER_PID *row = &((PMIB_UDP6TABLE_OWNER_PID)table)->table[i];
                    if (!ipv6_to_text(row->ucLocalAddr, row->dwLocalScopeId, local, sizeof(local))) {
                        rtq_error_append(errs, "network", "field_unavailable", "IPv6 address conversion failed", 0);
                        continue;
                    }
                    local_port = row->dwLocalPort; pid = row->dwOwningPid;
                }
                (void)append_win_network(f, tcp ? "tcp" : "udp", tcp ? tcp_state_text(state) : "UNCONN",
                                        local, ntohs((u_short)local_port), remote, ntohs((u_short)remote_port),
                                        pid, buf, cap, offset, total, truncated);
            }
            free(table);
        }
    }
    if (failed) rtq_error_append(errs, "network", failed == requested ? "collector_failed" : "partial_failure",
                                  "Windows IP helper table collection failed", 1);
    return *total - before;
}

static int append_win_file_result(rtq_filter *f, const char *path, const WIN32_FIND_DATAW *fd,
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
    int hash_rc = hash_file_if_needed(f, path, f->file_sha256, sha);
    if (hash_rc <= 0) {
        if (hash_rc == -2) f->file_hash_size_limit = 1;
        else if (hash_rc < 0) f->file_unavailable = 1;
        return 0;
    }
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
    if (rtq_cancelled(f) || !root || !root[0]) return;
    if (depth < 0) { f->file_depth_limit = 1; return; }
    if (*scanned >= RTQ_FILE_SCAN_MAX) { f->file_scan_limit = 1; return; }
    if (*total >= RTQ_MAX_RESULTS) { *truncated = 1; return; }
    DWORD attr = win_file_attributes(root);
    if (attr == INVALID_FILE_ATTRIBUTES) {
        DWORD error = GetLastError();
        if ((error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) &&
            strcmp(root, f->file_path) == 0) f->file_path_missing = 1;
        else f->file_unavailable = 1;
        return;
    }
    if (attr & FILE_ATTRIBUTE_REPARSE_POINT) { f->file_unavailable = 1; return; }
    char pattern[1024];
    int written = snprintf(pattern, sizeof(pattern), "%s%s", root,
                           attr & FILE_ATTRIBUTE_DIRECTORY ? "\\*" : "");
    if (written < 0 || written >= (int)sizeof(pattern)) { f->file_unavailable = 1; return; }
    WCHAR wide_pattern[1024];
    if (!utf8_to_wide_str(pattern, wide_pattern, sizeof(wide_pattern) / sizeof(wide_pattern[0]))) {
        f->file_unavailable = 1; return;
    }
    WIN32_FIND_DATAW data;
    HANDLE handle = FindFirstFileW(wide_pattern, &data);
    if (handle == INVALID_HANDLE_VALUE) {
        if (GetLastError() != ERROR_FILE_NOT_FOUND) f->file_unavailable = 1;
        return;
    }
    int stopped = 0;
    do {
        if (!wcscmp(data.cFileName, L".") || !wcscmp(data.cFileName, L"..")) continue;
        char name[1040];
        if (!wide_to_utf8_str(data.cFileName, name, sizeof(name))) { f->file_unavailable = 1; continue; }
        if (rtq_cancelled(f)) { stopped = 1; break; }
        if (*scanned >= RTQ_FILE_SCAN_MAX) { f->file_scan_limit = 1; stopped = 1; break; }
        if (*total >= RTQ_MAX_RESULTS || *truncated) { *truncated = 1; stopped = 1; break; }
        if (data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) { f->file_unavailable = 1; continue; }
        char child[1024];
        written = attr & FILE_ATTRIBUTE_DIRECTORY
                    ? snprintf(child, sizeof(child), "%s\\%s", root, name)
                    : snprintf(child, sizeof(child), "%s", root);
        if (written < 0 || written >= (int)sizeof(child)) { f->file_unavailable = 1; continue; }
        if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            scan_win_files_limited(f, child, depth - 1, scanned, buf, cap, offset, total, truncated);
        } else {
            (*scanned)++;
            (void)append_win_file_result(f, child, &data, buf, cap, offset, total, truncated);
        }
    } while (FindNextFileW(handle, &data));
    if (!stopped && GetLastError() != ERROR_NO_MORE_FILES) f->file_unavailable = 1;
    FindClose(handle);
}

static int match_files(rtq_filter *f, char *buf, int cap, int *offset, int *total,
                       int *truncated) {
    int scanned = 0;
    int before = *total;
    if (f->file_path[0]) f->file_path_scanned = 1;
    if (f->file_sha256[0]) {
        if (f->file_path[0]) {
            DWORD attr = win_file_attributes(f->file_path);
            if (attr == INVALID_FILE_ATTRIBUTES || !(attr & FILE_ATTRIBUTE_DIRECTORY)) {
                scan_win_files_limited(f, f->file_path, 0, &scanned, buf, cap, offset,
                                       total, truncated);
            } else f->file_unavailable = 1;
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
                              int *truncated, rtq_errors *errs) {
    if (rtq_cancelled(f)) return 0;
    if (*keys_scanned >= 512) { rtq_error_append(errs, "registry", "scan_limit", "registry key limit reached", 0); return 0; }
    if (*total >= RTQ_MAX_RESULTS) { *truncated = 1; return 0; }
    HKEY key = NULL;
    WCHAR wide_subkey[1024];
    if (!utf8_to_wide_str(subkey, wide_subkey, sizeof(wide_subkey) / sizeof(wide_subkey[0]))) {
        rtq_error_append(errs, "registry", "field_unavailable", "registry path conversion failed", 0);
        return 0;
    }
    LONG open_rc = RegOpenKeyExW(root, wide_subkey, 0, KEY_READ, &key);
    if (open_rc != ERROR_SUCCESS) {
        if (open_rc == ERROR_ACCESS_DENIED) (*access_denied)++;
        else if (open_rc != ERROR_FILE_NOT_FOUND && open_rc != ERROR_PATH_NOT_FOUND)
            rtq_error_append(errs, "registry", "enumeration_failed", "registry key open failed", 1);
        else if (depth > 0)
            rtq_error_append(errs, "registry", "field_unavailable", "registry child disappeared during enumeration", 0);
        return 0;
    }
    (*keys_scanned)++;
    DWORD subkeys = 0, values = 0;
    LONG info_rc = RegQueryInfoKeyW(key, NULL, NULL, NULL, &subkeys, NULL, NULL,
                                  &values, NULL, NULL, NULL, NULL);
    if (info_rc != ERROR_SUCCESS) rtq_error_append(errs, "registry", "enumeration_failed", "registry key metadata failed", 1);
    if (values > 128 || (subtree && subkeys > 256)) rtq_error_append(errs, "registry", "scan_limit", "registry per-key enumeration limit reached", 0);
    if (subtree && depth >= 4 && subkeys > 0) rtq_error_append(errs, "registry", "scan_depth_limit", "registry subtree depth limit reached", 0);
    int count = 0;
    for (DWORD i = 0; i < 128 && !*truncated; i++) {
        if (rtq_cancelled(f)) break;
        WCHAR wide_name[260], data[1024] = {0};
        char name[1040];
        DWORD name_len = sizeof(wide_name) / sizeof(wide_name[0]), data_len = sizeof(data), type = 0;
        LONG rc = RegEnumValueW(key, i, wide_name, &name_len, NULL, &type, (BYTE *)data, &data_len);
        if (rc == ERROR_NO_MORE_ITEMS) break;
        if (rc == ERROR_MORE_DATA) {
            rtq_error_append(errs, "registry", "field_unavailable", "registry value exceeds bounded data capacity", 0);
            continue;
        }
        if (rc != ERROR_SUCCESS) {
            rtq_error_append(errs, "registry", "enumeration_failed", "registry value enumeration failed", 1);
            break;
        }
        if (!wide_to_utf8_str(wide_name, name, sizeof(name))) {
            if (!wide_name[0]) name[0] = '\0';
            else { rtq_error_append(errs, "registry", "field_unavailable", "registry name conversion failed", 0); continue; }
        }
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
        char display_data[4200] = {0};
        if (type == REG_SZ || type == REG_EXPAND_SZ) {
            if (data_len > sizeof(data) || data_len % sizeof(WCHAR) ||
                (data_len > 0 && data[data_len / sizeof(WCHAR) - 1] != 0) ||
                (data[0] && !wide_to_utf8_str(data, display_data, sizeof(display_data)))) {
                rtq_error_append(errs, "registry", "field_unavailable", "registry string is not complete", 0);
                continue;
            }
        } else if (type == REG_DWORD && data_len == sizeof(DWORD)) {
            DWORD value; memcpy(&value, data, sizeof(value));
            snprintf(display_data, sizeof(display_data), "%lu", (unsigned long)value);
        } else if (type == REG_QWORD && data_len == sizeof(uint64_t)) {
            uint64_t value; memcpy(&value, data, sizeof(value));
            snprintf(display_data, sizeof(display_data), "%llu", (unsigned long long)value);
        } else {
            /* Bounded hex also preserves binary and MULTI_SZ bytes without
             * inventing a single-string interpretation. */
            static const char hex[] = "0123456789abcdef";
            for (DWORD j = 0; j < data_len && j < sizeof(data); j++) {
                display_data[j * 2] = hex[((BYTE *)data)[j] >> 4];
                display_data[j * 2 + 1] = hex[((BYTE *)data)[j] & 15];
            }
        }
        if (row_ok) row_ok = append_json_kv_str(row, (int)sizeof(row), &row_offset,
                                               "data", display_data);
        if (row_ok) row_ok = rtq_appendf(row, (int)sizeof(row), &row_offset, "}");
        if (!row_ok || !rtq_commit_row(buf, cap, offset, total, row, row_offset, truncated)) {
            if (truncated) *truncated = 1;
            break;
        }
        count++;
    }
    if (subtree && depth < 4 && subkeys > 0 && *total >= RTQ_MAX_RESULTS) *truncated = 1;
    if (subtree && depth < 4 && *keys_scanned < 512 && !*truncated) {
        for (DWORD i = 0; i < 256 && *keys_scanned < 512 && !*truncated; i++) {
            if (rtq_cancelled(f)) break;
            WCHAR wide_child[260];
            char child[1040];
            DWORD child_len = sizeof(wide_child) / sizeof(wide_child[0]);
            FILETIME modified;
            LONG enum_rc = RegEnumKeyExW(key, i, wide_child, &child_len, NULL, NULL, NULL, &modified);
            if (enum_rc == ERROR_NO_MORE_ITEMS) break;
            if (enum_rc != ERROR_SUCCESS) {
                rtq_error_append(errs, "registry", "field_unavailable", "registry child key could not be enumerated", 0);
                continue;
            }
            if (!wide_to_utf8_str(wide_child, child, sizeof(child))) {
                rtq_error_append(errs, "registry", "field_unavailable", "registry child name conversion failed", 0);
                continue;
            }
            char child_subkey[1024];
            char child_display[900];
            int key_length = snprintf(child_subkey, sizeof(child_subkey), "%s%s%s",
                     subkey, subkey[0] ? "\\" : "", child);
            int display_length = snprintf(child_display, sizeof(child_display), "%s\\%s", display_path, child);
            if (key_length < 0 || key_length >= (int)sizeof(child_subkey) ||
                display_length < 0 || display_length >= (int)sizeof(child_display)) {
                rtq_error_append(errs, "registry", "field_unavailable", "registry child path exceeds bounded capacity", 0);
                continue;
            }
            count += match_registry_key(f, root, child_subkey, child_display, depth + 1,
                                        subtree, keys_scanned, access_denied,
                                        buf, cap, offset, total, truncated, errs);
        }
        if (*keys_scanned >= 512) rtq_error_append(errs, "registry", "scan_limit", "registry key limit reached", 0);
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
                                   buf, cap, offset, total, truncated, errs);
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
    int n = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, src, -1, out, (int)cap, NULL, NULL);
    if (n <= 0) {
        out[0] = '\0';
        return 0;
    }
    out[cap - 1] = '\0';
    return 1;
}

static int evt_variant_u64(const EVT_VARIANT *v, unsigned long long *out) {
    if (!v || !out || (v->Type & EVT_VARIANT_TYPE_ARRAY)) return 0;
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

static int append_eventlog_u64(EVT_VARIANT *values, DWORD count, EVT_SYSTEM_PROPERTY_ID id,
                               const char *key, char *buf, int cap, int *offset) {
    unsigned long long value = 0;
    if (!values || id >= count || !evt_variant_u64(&values[id], &value)) return 0;
    if ((!strcmp(key, "event_id") && value > 65535) ||
        (!strcmp(key, "record_id") && (value == 0 || value > 9007199254740991ULL))) return 0;
    return rtq_appendf(buf, cap, offset, ",\"%s\":%llu", key, value);
}

static int append_eventlog_wstr(EVT_VARIANT *values, DWORD count, EVT_SYSTEM_PROPERTY_ID id,
                                const char *key, char *buf, int cap, int *offset) {
    if (!values || id >= count || values[id].Type != EvtVarTypeString) return 0;
    char text[512];
    return wide_to_utf8_str(values[id].StringVal, text, sizeof(text)) &&
           append_json_kv_str(buf, cap, offset, key, text);
}

static int append_eventlog_time(EVT_VARIANT *values, DWORD count, char *buf, int cap, int *offset) {
    if (!values || EvtSystemTimeCreated >= count ||
        values[EvtSystemTimeCreated].Type != EvtVarTypeFileTime) return 0;
    ULONGLONG value = values[EvtSystemTimeCreated].FileTimeVal;
    FILETIME time;
    time.dwLowDateTime = (DWORD)value;
    time.dwHighDateTime = (DWORD)(value >> 32);
    SYSTEMTIME utc;
    if (!FileTimeToSystemTime(&time, &utc)) return 0;
    char timestamp[64];
    snprintf(timestamp, sizeof(timestamp), "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ",
             (unsigned)utc.wYear, (unsigned)utc.wMonth, (unsigned)utc.wDay,
             (unsigned)utc.wHour, (unsigned)utc.wMinute, (unsigned)utc.wSecond,
             (unsigned)utc.wMilliseconds);
    return append_json_kv_str(buf, cap, offset, "timestamp", timestamp);
}

static int append_eventlog_evidence(EVT_HANDLE context, EVT_HANDLE event,
                                    char *buf, int cap, int *offset) {
    DWORD used = 0, count = 0;
    if (!context || !event || EvtRender(context, event, EvtRenderEventValues, 0, NULL, &used, &count) ||
        GetLastError() != ERROR_INSUFFICIENT_BUFFER || used == 0 || used > 65536) return 0;
    EVT_VARIANT *values = (EVT_VARIANT *)malloc(used);
    if (!values) return 0;
    int complete = EvtRender(context, event, EvtRenderEventValues, used, values, &used, &count) &&
                   count <= used / sizeof(EVT_VARIANT) &&
                   append_eventlog_wstr(values, count, EvtSystemProviderName, "provider", buf, cap, offset) &&
                   append_eventlog_u64(values, count, EvtSystemEventID, "event_id", buf, cap, offset) &&
                   append_eventlog_u64(values, count, EvtSystemEventRecordId, "record_id", buf, cap, offset) &&
                   append_eventlog_time(values, count, buf, cap, offset);
    if (complete) {
        (void)append_eventlog_u64(values, count, EvtSystemLevel, "level", buf, cap, offset);
        (void)append_eventlog_u64(values, count, EvtSystemProcessID, "process_id", buf, cap, offset);
        (void)append_eventlog_u64(values, count, EvtSystemThreadID, "thread_id", buf, cap, offset);
    }
    free(values);
    return complete && *offset < cap - 1;
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
        rtq_error_append(errs, "eventlog", "render_context_failed", "EvtCreateRenderContext failed", 1);
        EvtClose(h);
        return -1;
    }
    int before = *total;
    DWORD next_error = ERROR_SUCCESS;
    while (!rtq_cancelled(f) && !*truncated) {
        EVT_HANDLE events[10];
        DWORD returned = 0;
        if (!EvtNext(h, 10, events, 1000, 0, &returned)) {
            next_error = GetLastError();
            break;
        }
        if (returned == 0) break;
        for (DWORD i = 0; i < returned; i++) {
            if (rtq_cancelled(f) || *truncated) {
                for (DWORD j = i; j < returned; j++) EvtClose(events[j]);
                break;
            }
            char row[RTQ_ROW_CAP];
            int row_offset = 0;
            int row_ok = rtq_appendf(row, (int)sizeof(row), &row_offset, "{\"type\":\"eventlog\"");
            if (!row_ok || !append_eventlog_evidence(render_ctx, events[i], row, (int)sizeof(row), &row_offset)) {
                rtq_error_append(errs, "eventlog", "field_unavailable", "event system metadata could not be read completely", 0);
            } else {
                row_ok = rtq_appendf(row, (int)sizeof(row), &row_offset, "}");
                if (!row_ok || !rtq_commit_row(buf, cap, offset, total, row, row_offset, truncated)) *truncated = 1;
            }
            EvtClose(events[i]);
        }
    }
    if (next_error == ERROR_TIMEOUT) rtq_error_append(errs, "eventlog", "sampler_timeout", "event enumeration timed out", 1);
    else if (next_error != ERROR_SUCCESS && next_error != ERROR_NO_MORE_ITEMS)
        rtq_error_append(errs, "eventlog", "enumeration_failed", "EvtNext failed", 1);
    EvtClose(render_ctx);
    EvtClose(h);
    return *total - before;
}

#else
#if defined(__linux__)
static void read_proc_exe_path(int pid, char *out, size_t out_cap) {
    if (!out || out_cap == 0) return;
    out[0] = '\0';
    char link_path[64];
    snprintf(link_path, sizeof(link_path), "/proc/%d/exe", pid);
    ssize_t n = readlink(link_path, out, out_cap - 1);
    if (n > 0) out[n] = '\0';
}
#endif

typedef struct rtq_process_args {
    int pid;
    const char *text;
} rtq_process_args;

static int rtq_ps_pid(char **cursor, int *pid) {
    char *end = NULL;
    errno = 0;
    long value = strtol(*cursor, &end, 10);
    if (errno || end == *cursor || value <= 0 || value > 2147483647L ||
        (*end != ' ' && *end != '\t')) return 0;
    while (*end == ' ' || *end == '\t') end++;
    *cursor = end;
    *pid = (int)value;
    return 1;
}

static int rtq_process_args_compare(const void *left, const void *right) {
    int a = ((const rtq_process_args *)left)->pid;
    int b = ((const rtq_process_args *)right)->pid;
    return a < b ? -1 : a > b;
}

static const char *rtq_process_args_find(const rtq_process_args *rows, size_t count, int pid) {
    size_t start = 0, end = count;
    while (start < end) {
        size_t middle = start + (end - start) / 2;
        if (rows[middle].pid < pid) start = middle + 1;
        else end = middle;
    }
    if (start == count || rows[start].pid != pid ||
        (start + 1 < count && rows[start + 1].pid == pid)) return NULL;
    return rows[start].text;
}

static int match_processes(rtq_filter *f, char *buf, int cap, int *offset, int *total,
                           rtq_errors *errs, int *truncated) {
    int needs_cmdline = f->process_cmdline[0] || f->script_content[0] || f->script_engine[0];
    int needs_user = f->process_user[0] != 0;
    const char *cmd = needs_user ? "ps -eo pid,user,comm" : "ps -eo pid,comm";
    char *output = (char *)malloc(RTQ_SAMPLER_OUTPUT_MAX);
    if (!output) {
        rtq_error_append(errs, "process", "oom", "process sampler output allocation failed", 1);
        return -1;
    }
    int exit_code = 0;
    if (edr_shell_exec_cancellable(cmd, RTQ_SAMPLER_TIMEOUT_SEC, output, RTQ_SAMPLER_OUTPUT_MAX, &exit_code, rtq_sampler_cancel_check, f) != 0 ||
        exit_code != 0) {
        char msg[768];
        sampler_error_message(msg, sizeof(msg), cmd, exit_code, output);
        rtq_error_append(errs, "process", exit_code == 124 ? "sampler_timeout" : "sampler_failed", msg, 1);
        free(output);
        return -1;
    }

    rtq_sampler_complete_lines(output, "process", errs);

    char *args_output = NULL;
    rtq_process_args *args_rows = NULL;
    size_t args_count = 0;
    if (needs_cmdline) {
        const char *args_cmd = "ps -ww -eo pid,args";
        args_output = (char *)malloc(RTQ_SAMPLER_OUTPUT_MAX);
        if (!args_output) {
            rtq_error_append(errs, "process_cmdline", "oom", "process command-line sampler allocation failed", 1);
            free(output);
            return -1;
        }
        exit_code = 0;
        if (edr_shell_exec_cancellable(args_cmd, RTQ_SAMPLER_TIMEOUT_SEC, args_output, RTQ_SAMPLER_OUTPUT_MAX,
                                       &exit_code, rtq_sampler_cancel_check, f) != 0 || exit_code != 0) {
            char message[768];
            sampler_error_message(message, sizeof(message), args_cmd, exit_code, args_output);
            rtq_error_append(errs, "process_cmdline", exit_code == 124 ? "sampler_timeout" : "sampler_failed", message, 1);
            free(args_output);
            free(output);
            return -1;
        }
        rtq_sampler_complete_lines(args_output, "process_cmdline", errs);
        size_t lines = 1;
        for (const char *c = args_output; *c; c++) if (*c == '\n') lines++;
        args_rows = (rtq_process_args *)calloc(lines, sizeof(*args_rows));
        if (!args_rows) {
            rtq_error_append(errs, "process_cmdline", "oom", "process command-line index allocation failed", 1);
            free(args_output);
            free(output);
            return -1;
        }
        char *args_save = NULL;
        for (char *line = strtok_r(args_output, "\n", &args_save); line && !rtq_cancelled(f);
             line = strtok_r(NULL, "\n", &args_save)) {
            char *text = line;
            int pid = 0;
            if (!rtq_ps_pid(&text, &pid)) continue;
            args_rows[args_count].pid = pid;
            args_rows[args_count].text = *text && strlen(text) <= 8192u ? text : NULL;
            args_count++;
        }
        qsort(args_rows, args_count, sizeof(*args_rows), rtq_process_args_compare);
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
    while (line && !rtq_cancelled(f) && !*truncated) {
        char *cur = line;
        line = strtok_r(NULL, "\n", &save);
        int loc_pid = 0;
        char loc_user[128] = {0}, loc_comm[256] = {0};
        if (!rtq_ps_pid(&cur, &loc_pid)) continue;
        if (needs_user) {
            char *end = cur;
            while (*end && *end != ' ' && *end != '\t') end++;
            size_t length = (size_t)(end - cur);
            if (length == 0 || length >= sizeof(loc_user)) {
                rtq_error_append(errs, "process", "field_unavailable", "process sampler owner exceeded field capacity", 0);
                continue;
            }
            memcpy(loc_user, cur, length);
            while (*end == ' ' || *end == '\t') end++;
            cur = end;
        }
        if (!*cur || strlen(cur) >= sizeof(loc_comm)) {
            rtq_error_append(errs, "process", "field_unavailable", "process sampler record exceeded field capacity", 0);
            continue;
        }
        memcpy(loc_comm, cur, strlen(cur) + 1u);

        char path[1024] = {0};

        int ok = 1;
        if (f->process_name[0] && !str_contains_icase(loc_comm, f->process_name)) ok = 0;
        if (f->process_user[0] && !str_contains_icase(loc_user, f->process_user)) ok = 0;
        if (f->process_pid_max > 0 && loc_pid > f->process_pid_max) ok = 0;
        if (f->process_pid_min > 0 && loc_pid < f->process_pid_min) ok = 0;
        if (!ok) continue;
        const char *rest = needs_cmdline ? rtq_process_args_find(args_rows, args_count, loc_pid) : "";
        if (!rest) {
            rtq_error_append(errs, "process_cmdline", "field_unavailable", "requested process command line was missing or exceeded field capacity", 0);
            rest = "";
        }
        if (f->process_cmdline[0] && !str_contains_icase(rest, f->process_cmdline)) continue;
        if (f->script_engine[0] && !str_contains_icase(loc_comm, f->script_engine) &&
            !str_contains_icase(rest, f->script_engine)) continue;
#if defined(__linux__)
        {
            read_proc_exe_path(loc_pid, path, sizeof(path));
            if (!path[0] || strlen(path) >= sizeof(path) - 1u) {
                rtq_error_append(errs, "process", "field_unavailable", "requested process path could not be read completely", 0);
                if (f->process_path[0]) continue;
                path[0] = '\0';
            }
        }
#endif

        if (f->process_path[0] && !str_contains_icase(path, f->process_path)) ok = 0;
        if (!ok) continue;

        char row[RTQ_ROW_CAP];
        int row_offset = 0;
        row[0] = '\0';
        int row_ok = rtq_appendf(row, (int)sizeof(row), &row_offset,
            "{\"type\":\"process\",\"pid\":%d,\"name\":\"",
            loc_pid) &&
            append_json_escaped(row, (int)sizeof(row), &row_offset, loc_comm) &&
            rtq_appendf(row, (int)sizeof(row), &row_offset, "\"");
        if (row_ok && needs_user) row_ok = append_json_kv_str(row, (int)sizeof(row), &row_offset, "user", loc_user);
        if (row_ok && needs_cmdline && rest[0]) row_ok = append_json_kv_str(row, (int)sizeof(row), &row_offset, "cmdline", rest);
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
    free(args_rows);
    free(args_output);
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
    char normalized_state[32];
    canonical_network_state(state, normalized_state, sizeof(normalized_state));
    state = normalized_state;
    proto = str_contains_icase(proto, "udp") ? "udp" : "tcp";
    if (!state[0]) state = !strcmp(proto, "udp") ? "UNCONN" : "UNKNOWN";
    char remote_ip[128] = {0};
    int remote_port = 0;
    split_addr_port(remote_addr, remote_ip, sizeof(remote_ip), &remote_port);

    if (f->network_proto[0] && !str_eq_icase(proto, f->network_proto)) return 0;
    if (f->network_state[0] && !str_eq_icase(state, f->network_state)) return 0;
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
                           int *sampler_ok, char *err_msg, size_t err_cap, int *truncated, rtq_errors *errs) {
    const char *cmd = "ss -tunapH";
    if (sampler_ok) *sampler_ok = 0;
    char *output = (char *)malloc(RTQ_SAMPLER_OUTPUT_MAX);
    if (!output) {
        if (err_msg && err_cap > 0) snprintf(err_msg, err_cap, "network sampler output allocation failed");
        return 0;
    }
    int exit_code = 0;
    if (edr_shell_exec_cancellable(cmd, RTQ_SAMPLER_TIMEOUT_SEC, output, RTQ_SAMPLER_OUTPUT_MAX, &exit_code, rtq_sampler_cancel_check, f) != 0 ||
        exit_code != 0) {
        if (err_msg && err_cap > 0) sampler_error_message(err_msg, err_cap, cmd, exit_code, output);
        free(output);
        return 0;
    }
    if (sampler_ok) *sampler_ok = 1;
    rtq_sampler_complete_lines(output, "network", errs);

    int count = 0;
    char *save = NULL;
    char *line = strtok_r(output, "\n", &save);
    while (line && !rtq_cancelled(f) && !*truncated) {
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
                                int *truncated, rtq_errors *errs) {
    const char *cmd = "netstat -an";
    if (sampler_ok) *sampler_ok = 0;
    char *output = (char *)malloc(RTQ_SAMPLER_OUTPUT_MAX);
    if (!output) {
        if (err_msg && err_cap > 0) snprintf(err_msg, err_cap, "network sampler output allocation failed");
        return 0;
    }
    int exit_code = 0;
    if (edr_shell_exec_cancellable(cmd, RTQ_SAMPLER_TIMEOUT_SEC, output, RTQ_SAMPLER_OUTPUT_MAX, &exit_code, rtq_sampler_cancel_check, f) != 0 ||
        exit_code != 0) {
        if (err_msg && err_cap > 0) sampler_error_message(err_msg, err_cap, cmd, exit_code, output);
        free(output);
        return 0;
    }
    if (sampler_ok) *sampler_ok = 1;
    rtq_sampler_complete_lines(output, "network", errs);

    int count = 0;
    char *save = NULL;
    char *line = strtok_r(output, "\n", &save);
    while (line && !rtq_cancelled(f) && !*truncated) {
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
                                truncated, errs);
    if (ss_ok) return count;
    count = scan_netstat_network(f, buf, cap, offset, total, &netstat_ok, netstat_err,
                                 sizeof(netstat_err), truncated, errs);
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
            if (lstat(f->file_path, &st) != 0 || S_ISREG(st.st_mode)) {
                scan_files_limited(f, f->file_path, 0, &scanned, buf, cap, offset, total,
                                   truncated);
            } else f->file_unavailable = 1;
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
    size_t rows_cap = cap > *offset + 3 ? (size_t)(cap - *offset) : 0;
    if (rows_cap == 0) { *truncated = 1; return 0; }
    char *rows = (char *)malloc(rows_cap);
    if (!rows) {
        f->file_cache_failed = 1;
        rtq_error_append(errs, "file_hash_cache", "oom", "hash cache allocation failed", 1);
        return 0;
    }
    uint32_t returned = 0;
    uint32_t scanned = 0;
    int cache_truncated = 0;
    if (edr_local_evidence_cache_query_file_hash_json(f->file_sha256, f->file_path,
                                                      f->file_ext, RTQ_MAX_RESULTS,
                                                      rows, rows_cap,
                                                      &returned, &scanned,
                                                      &cache_truncated) != 0) {
        f->file_cache_failed = 1;
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
    if (f->file_scan_limit) rtq_error_append(errs, "file", "scan_limit", "file scan item limit reached", 0);
    if (f->file_depth_limit) rtq_error_append(errs, "file", "scan_depth_limit", "file scan depth limit reached", 0);
    if (f->file_unavailable) rtq_error_append(errs, "file", "field_unavailable", "some requested files could not be read", 0);
    if (f->file_hash_size_limit) rtq_error_append(errs, "file", "hash_size_limit", "file exceeds bounded hash size", 0);
    if (f->file_path_missing) rtq_error_append(errs, "file", "path_not_found", "requested path not found", 0);
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
    char canonical_state[32];
    canonical_network_state(filter.network_state, canonical_state, sizeof(canonical_state));
    snprintf(filter.network_state, sizeof(filter.network_state), "%s", canonical_state);

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
    char eventlog_meta[4096];
    int eventlog_meta_len = eventlog_batch_metadata(&filter, eventlog_meta, (int)sizeof(eventlog_meta));
    if (eventlog_meta_len < 0 || eventlog_meta_len >= RTQ_COLLECTOR_RESULT_CAP) {
        free(result);
        g_cmd_exec_fail++;
        edr_command_emit_always_typed(cmd_id, "rtq_execute", sm, EdrCmdExecFailed, 3,
                                      "eventlog batch metadata exceeds result budget");
        return;
    }
    const int collector_result_cap = RTQ_COLLECTOR_RESULT_CAP - eventlog_meta_len;
    int output_truncated = 0;
    rtq_errors errors;
    rtq_error_init(&errors);

    (void)rtq_appendf(result, RTQ_MAX_RESULT_STR, &offset, "{\"results\":[\n");

#ifdef _WIN32
    if (has_proc) {
        (void)match_processes(&filter, result, collector_result_cap, &offset, &total,
                              &errors, &output_truncated);
    }
    if (rtq_cancelled(&filter)) goto cancelled;
    if (has_net) {
        (void)match_network(&filter, result, collector_result_cap, &offset, &total,
                            &errors, &output_truncated);
    }
    if (rtq_cancelled(&filter)) goto cancelled;
    if (has_file) {
        (void)match_files_cache_first(&filter, result, collector_result_cap, &offset,
                                      &total, &errors, &output_truncated);
    }
    if (rtq_cancelled(&filter)) goto cancelled;
    if (has_registry) {
        (void)match_registry(&filter, result, collector_result_cap, &offset, &total,
                             &errors, &output_truncated);
    }
    if (rtq_cancelled(&filter)) goto cancelled;
    if (has_eventlog) {
        (void)match_eventlog(&filter, result, collector_result_cap, &offset, &total,
                             &errors, &output_truncated);
    }
    if (rtq_cancelled(&filter)) goto cancelled;
#else
    if (has_proc) {
        (void)match_processes(&filter, result, collector_result_cap, &offset, &total,
                              &errors, &output_truncated);
    }
    if (rtq_cancelled(&filter)) goto cancelled;
    if (has_net) {
        (void)match_network(&filter, result, collector_result_cap, &offset, &total,
                            &errors, &output_truncated);
    }
    if (rtq_cancelled(&filter)) goto cancelled;
    if (has_file) {
        (void)match_files_cache_first(&filter, result, collector_result_cap, &offset,
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

    if (output_truncated) {
        output_truncated = 1;
        rtq_error_append(&errors, "command_result_transport", "result_truncated",
                         "RTQ rows exceeded the durable inline result limit; complete rows were retained",
                         0);
    }

    const char *cache_status = !filter.file_sha256[0]
                                   ? "not_requested"
                                   : (filter.file_cache_failed ? "unavailable" :
                                      filter.file_cache_hits > 0 ? "hit" : "miss");
    const char *scope = filter.file_sha256[0]
                           ? (filter.file_path[0] ? "cache_and_exact_path" : "cache_only")
                           : (filter.file_path[0] ? "path_scan" : "bounded_default_roots");
    if (errors.count) (void)rtq_appendf(result, RTQ_MAX_RESULT_STR, &offset, "\n],\"partial\":true");
    else (void)rtq_appendf(result, RTQ_MAX_RESULT_STR, &offset, "\n]");
    (void)rtq_appendf(result, RTQ_MAX_RESULT_STR, &offset,
        ",\"total\":%d,\"truncated\":%s,\"meta\":{%s\"file_hash\":{\"scope\":\"%s\",\"cache_status\":\"%s\",\"cache_attempted\":%s,"
        "\"cache_hits\":%d,\"cache_candidates_scanned\":%u,\"path_scanned\":%s}},\"error\":",
        total, output_truncated ? "true" : "false", eventlog_meta, scope, cache_status,
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
