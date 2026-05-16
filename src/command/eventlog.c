#ifdef _WIN32
#include <windows.h>
#include <winevt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#else
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#endif

#include "edr/command_util.h"
#include "edr/ingest_http.h"
#include "edr/response.h"

#ifdef _WIN32
#pragma comment(lib, "wevtapi.lib")

#define EVT_MAX_XML (256 * 1024)

static int eventlog_query_to_file(const char *channel, int max_events, FILE *f) {
    const wchar_t *wchannel = NULL;
    wchar_t wbuf[256];
    if (channel && channel[0]) {
        MultiByteToWideChar(CP_UTF8, 0, channel, -1, wbuf, 256);
        wchannel = wbuf;
    } else {
        wchannel = L"Security";
    }

    EVT_HANDLE hQuery = EvtQuery(NULL, wchannel, L"*", EvtQueryChannelPath);
    if (!hQuery) return -1;

    EVT_HANDLE events[32];
    DWORD returned = 0;
    int total = 0;
    int first = 1;

    while (total < max_events) {
        if (!EvtNext(hQuery, 32, events, INFINITE, 0, &returned))
            break;
        for (DWORD i = 0; i < returned && total < max_events; i++) {
            DWORD bufUsed = 0, propCount = 0;
            EvtRender(NULL, events[i], EvtRenderEventXml, 0, NULL, &bufUsed, &propCount);
            if (bufUsed > 0 && bufUsed < EVT_MAX_XML) {
                WCHAR *wxml = (WCHAR *)malloc((bufUsed + 1) * sizeof(WCHAR));
                if (wxml) {
                    if (EvtRender(NULL, events[i], EvtRenderEventXml,
                                  bufUsed + 1, wxml, &bufUsed, &propCount)) {
                        int utf8Len = WideCharToMultiByte(CP_UTF8, 0, wxml, -1, NULL, 0, NULL, NULL);
                        if (utf8Len > 1) {
                            char *utf8 = (char *)malloc(utf8Len);
                            if (utf8) {
                                WideCharToMultiByte(CP_UTF8, 0, wxml, -1, utf8, utf8Len, NULL, NULL);
                                if (!first) fprintf(f, ",\n");
                                first = 0;
                                fputc('"', f);
                                for (int k = 0; k < utf8Len - 1; k++) {
                                    unsigned char c = (unsigned char)utf8[k];
                                    if (c == '"') fputs("\\\"", f);
                                    else if (c == '\\') fputs("\\\\", f);
                                    else if (c == '\n') fputs("\\n", f);
                                    else if (c == '\r') fputs("\\r", f);
                                    else if (c == '\t') fputs("\\t", f);
                                    else if (c < 0x20) fprintf(f, "\\u%04x", (unsigned)c);
                                    else fputc((int)c, f);
                                }
                                fputc('"', f);
                                total++;
                                free(utf8);
                            }
                        }
                    }
                    free(wxml);
                }
            }
            EvtClose(events[i]);
        }
    }
    EvtClose(hQuery);
    return total;
}
#else
static int eventlog_query_to_file(const char *channel, int max_events, FILE *f) {
    const char *cmd = "journalctl --output=json -n ";
    char buf[512];
    snprintf(buf, sizeof(buf), "%s%d", cmd, max_events > 0 ? max_events : 100);
    (void)channel;

    FILE *p = popen(buf, "r");
    if (!p) {
        fprintf(f, "[]");
        return 0;
    }
    char line[8192];
    int first = 1, count = 0;
    while (fgets(line, sizeof(line), p) && count < max_events) {
        size_t l = strlen(line);
        if (l > 0 && line[l-1] == '\n') line[l-1] = '\0';
        if (!first) fprintf(f, ",\n");
        first = 0;
        fprintf(f, "%s", line);
        count++;
    }
    pclose(p);
    return count;
}
#endif

void edr_response_eventlog_view(const char *cmd_id, const uint8_t *pl,
                                 size_t len, const EdrSoarCommandMeta *sm) {
    if (!edr_command_dangerous_enabled()) {
        g_cmd_rejected++;
        edr_command_audit_both(cmd_id, "reject eventlog_view: policy disabled");
        edr_command_emit_always(cmd_id, sm, EdrCmdExecRejected, 1, "policy disabled");
        return;
    }

    char channel[64] = "Security";
    int max_events = 100;
    (void)edr_parse_json_string(pl, len, "channel", channel, sizeof(channel));
    (void)edr_parse_json_int(pl, len, "max_events", &max_events);
    if (max_events <= 0 || max_events > 1000) max_events = 100;

    char json_path[1024];
    snprintf(json_path, sizeof(json_path),
#ifdef _WIN32
             "evtlog_%s_%lld.json",
#else
             "/tmp/evtlog_%s_%lld.json",
#endif
             cmd_id ? cmd_id : "unknown", (long long)time(NULL));

    FILE *f = fopen(json_path, "w");
    if (!f) {
        g_cmd_exec_fail++;
        edr_command_audit_both(cmd_id, "eventlog_view: cannot create output file");
        edr_command_emit_always(cmd_id, sm, EdrCmdExecFailed, 2, "cannot create output file");
        return;
    }

    fprintf(f, "{\"channel\":\"%s\",\"events\":[\n", channel);
    int count = eventlog_query_to_file(channel, max_events, f);
    fprintf(f, "\n],\"total\":%d}", count);
    fclose(f);

    char sha[65];
    {
        FILE *fh = fopen(json_path, "rb");
        if (fh) {
            fseek(fh, 0, SEEK_END);
            long fsz = ftell(fh);
            fseek(fh, 0, SEEK_SET);
            uint8_t *fbuf = (uint8_t *)malloc((size_t)(fsz + 1));
            if (fbuf) {
                fread(fbuf, 1, (size_t)fsz, fh);
                edr_sha256_hex(fbuf, (size_t)fsz, sha);
                free(fbuf);
            }
            fclose(fh);
        }
    }

    char minio_key[256] = {0};
    edr_ingest_http_upload_file_multipart(cmd_id, json_path, sha, minio_key, sizeof(minio_key));
    remove(json_path);

    char result[512];
    snprintf(result, sizeof(result), "EVTLOG_OK channel=%s count=%d minio_key=%s",
             channel, count, minio_key[0] ? minio_key : "");
    g_cmd_handled++; g_cmd_exec_ok++;
    edr_command_audit_both(cmd_id, "eventlog_view: ok");
    edr_command_emit_always(cmd_id, sm, EdrCmdExecOk, 0, result);
}
