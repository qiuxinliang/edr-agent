#ifdef _WIN32
#include <windows.h>
#include <stdio.h>
#else
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#endif

#include "edr/command_util.h"
#include "edr/ingest_http.h"
#include "edr/response.h"
#include "edr/shell_exec.h"

#ifdef _WIN32

#define REG_MAX_NAME 16384
#define REG_MAX_DATA (256 * 1024)

static HKEY parse_root(const char *key_path, char **subkey_out) {
    if (strncmp(key_path, "HKLM\\", 5) == 0 || strncmp(key_path, "HKLM/", 5) == 0) {
        *subkey_out = (char *)key_path + 5; return HKEY_LOCAL_MACHINE;
    }
    if (strncmp(key_path, "HKCU\\", 5) == 0 || strncmp(key_path, "HKCU/", 5) == 0) {
        *subkey_out = (char *)key_path + 5; return HKEY_CURRENT_USER;
    }
    if (strncmp(key_path, "HKU\\", 4) == 0 || strncmp(key_path, "HKU/", 4) == 0) {
        *subkey_out = (char *)key_path + 4; return HKEY_USERS;
    }
    if (strncmp(key_path, "HKCR\\", 5) == 0 || strncmp(key_path, "HKCR/", 5) == 0) {
        *subkey_out = (char *)key_path + 5; return HKEY_CLASSES_ROOT;
    }
    if (strncmp(key_path, "HKCC\\", 5) == 0 || strncmp(key_path, "HKCC/", 5) == 0) {
        *subkey_out = (char *)key_path + 5; return HKEY_CURRENT_CONFIG;
    }
    return NULL;
}

static void format_data(FILE *f, DWORD type, const BYTE *data, DWORD size) {
    switch (type) {
    case REG_SZ:
    case REG_EXPAND_SZ:
    case REG_MULTI_SZ: {
        char *tmp = (char *)malloc(size + 1);
        if (tmp) {
            memcpy(tmp, data, size);
            tmp[size] = '\0';
            for (DWORD j = 0; j < size; j++) {
                if (tmp[j] == '"') fprintf(f, "\\\"");
                else if (tmp[j] == '\\') fprintf(f, "\\\\");
                else if (tmp[j] == '\n') fprintf(f, "\\n");
                else if (tmp[j] == '\r') fprintf(f, "\\r");
                else if (tmp[j] == '\t') fprintf(f, "\\t");
                else if ((unsigned char)tmp[j] >= 32) putc(tmp[j], f);
                else fprintf(f, "\\x%02x", (unsigned char)tmp[j]);
            }
            free(tmp);
        }
        break;
    }
    case REG_DWORD:
        if (size >= 4) fprintf(f, "0x%08lx", *(const DWORD *)data);
        break;
    case REG_QWORD:
        if (size >= 8) {
            unsigned long long v = 0;
            memcpy(&v, data, sizeof(v));
            fprintf(f, "0x%016llx", v);
        }
        break;
    default:
        fprintf(f, "hex:");
        for (DWORD j = 0; j < size && j < 128; j++)
            fprintf(f, "%02x", data[j]);
        break;
    }
}

static void enum_values(FILE *f, HKEY root, const char *subkey,
                        int *first, int *count) {
    HKEY hKey;
    if (RegOpenKeyExA(root, subkey, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return;

    char name[REG_MAX_NAME];
    BYTE data[REG_MAX_DATA];
    DWORD nameSize, dataSize, type;
    DWORD idx = 0;

    while (1) {
        nameSize = REG_MAX_NAME;
        dataSize = REG_MAX_DATA;
        LONG lr = RegEnumValueA(hKey, idx, name, &nameSize, NULL,
                                &type, data, &dataSize);
        if (lr != ERROR_SUCCESS) break;

        if (!*first) fprintf(f, ",\n");
        fprintf(f, "    {\"name\":\"%s\",\"type\":%lu,\"data\":\"", name, (unsigned long)type);
        format_data(f, type, data, dataSize);
        fprintf(f, "\"}");
        *first = 0;
        (*count)++;
        idx++;
    }
    RegCloseKey(hKey);
}

static void enum_subkeys_recursive(FILE *f, HKEY root, const char *subkey,
                                   int *first, int *count, int max_depth, int depth) {
    if (depth >= max_depth) return;
    enum_values(f, root, subkey, first, count);

    HKEY hKey;
    if (RegOpenKeyExA(root, subkey, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return;

    char subName[256];
    DWORD si = 0;
    while (RegEnumKeyA(hKey, si, subName, 256) == ERROR_SUCCESS) {
        char full[520];
        snprintf(full, sizeof(full), "%s\\%s", subkey, subName);
        enum_subkeys_recursive(f, root, full, first, count, max_depth, depth + 1);
        si++;
    }
    RegCloseKey(hKey);
}

void edr_response_reg_query(const char *cmd_id, const uint8_t *pl,
                             size_t len, const EdrSoarCommandMeta *sm) {
    if (!edr_command_dangerous_enabled()) {
        g_cmd_rejected++;
        edr_command_audit_both(cmd_id, "reject reg_query: policy disabled");
        edr_command_emit_always(cmd_id, sm, EdrCmdExecRejected, 1, "policy disabled");
        return;
    }

    char key_path[520];
    int recursive = 0;
    (void)edr_parse_json_string(pl, len, "key", key_path, sizeof(key_path));
    (void)edr_parse_json_int(pl, len, "recursive", &recursive);

    if (!key_path[0]) {
        g_cmd_exec_fail++;
        edr_command_audit_both(cmd_id, "reg_query: missing key");
        edr_command_emit_always(cmd_id, sm, EdrCmdExecFailed, 2, "missing key");
        return;
    }

    char *subkey = NULL;
    HKEY root = parse_root(key_path, &subkey);
    if (!root || !subkey) {
        g_cmd_exec_fail++;
        edr_command_audit_both(cmd_id, "reg_query: invalid key path");
        edr_command_emit_always(cmd_id, sm, EdrCmdExecFailed, 3, "invalid key path");
        return;
    }

    char json_path[1024];
    snprintf(json_path, sizeof(json_path), "reg_%s_%lld.json",
             cmd_id ? cmd_id : "unknown", (long long)time(NULL));

    FILE *f = fopen(json_path, "w");
    if (!f) {
        g_cmd_exec_fail++;
        edr_command_audit_both(cmd_id, "reg_query: cannot create output file");
        edr_command_emit_always(cmd_id, sm, EdrCmdExecFailed, 4, "cannot create output");
        return;
    }

    fprintf(f, "{\"key\":\"%s\",\"values\":[\n", key_path);
    int first = 1, count = 0;
    if (recursive) {
        enum_subkeys_recursive(f, root, subkey, &first, &count, 5, 0);
    } else {
        enum_values(f, root, subkey, &first, &count);
    }
    fprintf(f, "\n],\"total\":%d}", count);
    fclose(f);

    char sha[65] = {0};
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
    snprintf(result, sizeof(result), "REG_OK key=%s count=%d minio_key=%s",
             key_path, count, minio_key[0] ? minio_key : "");
    g_cmd_handled++; g_cmd_exec_ok++;
    edr_command_audit_both(cmd_id, "reg_query: ok");
    edr_command_emit_always(cmd_id, sm, EdrCmdExecOk, 0, result);
}

#else

void edr_response_reg_query(const char *cmd_id, const uint8_t *pl,
                             size_t len, const EdrSoarCommandMeta *sm) {
    char key_path[520];
    (void)edr_parse_json_string(pl, len, "key", key_path, sizeof(key_path));
    char result[256];
    snprintf(result, sizeof(result), "REG_UNSUPPORTED key=%s (non-Windows platform)", key_path[0] ? key_path : "");
    g_cmd_handled++; g_cmd_exec_ok++;
    edr_command_audit_both(cmd_id, "reg_query: unsupported platform");
    edr_command_emit_always(cmd_id, sm, EdrCmdExecOk, 0, result);
}

#endif
