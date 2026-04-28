/*
 * P0 Alert Enrichment - 父进程信息补全
 *
 * 当P0告警产生时，如果缺少父进程信息，通过Windows API补充
 */
#include "edr/enrich_parent_info.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>

#pragma comment(lib, "psapi.lib")

int enrich_parent_info_by_pid(uint32_t ppid, char *parent_name, size_t name_len,
                             char *parent_path, size_t path_len) {
    if (ppid == 0) {
        if (parent_name && name_len > 0) {
            snprintf(parent_name, name_len, "System");
        }
        if (parent_path && path_len > 0) {
            snprintf(parent_path, path_len, "N/A");
        }
        return 0;
    }

    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ppid);
    if (!h) {
        return -1;
    }

    DWORD size = 0;
    if (parent_path && path_len > 0) {
        if (QueryFullProcessImageNameW(h, 0, NULL, &size) || GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
            wchar_t wpath[MAX_PATH];
            size = MAX_PATH;
            if (QueryFullProcessImageNameW(h, 0, wpath, &size)) {
                WideCharToMultiByte(CP_UTF8, 0, wpath, -1, parent_path, (int)path_len, NULL, NULL);
                parent_path[path_len - 1] = 0;
            } else {
                parent_path[0] = 0;
            }
        } else {
            parent_path[0] = 0;
        }
    }

    if (parent_name && name_len > 0) {
        if (parent_path[0]) {
            const char *base = strrchr(parent_path, '\\');
            base = base ? base + 1 : parent_path;
            snprintf(parent_name, name_len, "%s", base);
        } else {
            snprintf(parent_name, name_len, "pid-%u", ppid);
        }
    }

    CloseHandle(h);
    return 0;
}

#elif defined(__linux__)

#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>
#include <stdio.h>

int enrich_parent_info_by_pid(uint32_t ppid, char *parent_name, size_t name_len,
                             char *parent_path, size_t path_len) {
    if (ppid == 0) {
        if (parent_name && name_len > 0) snprintf(parent_name, name_len, "swapper/0");
        if (parent_path && path_len > 0) snprintf(parent_path, path_len, "/sbin/init");
        return 0;
    }

    char link_path[64];
    snprintf(link_path, sizeof(link_path), "/proc/%u/exe", ppid);

    ssize_t len = readlink(link_path, parent_path, path_len - 1);
    if (len > 0) {
        parent_path[len] = 0;
        if (parent_name && name_len > 0) {
            const char *base = strrchr(parent_path, '/');
            base = base ? base + 1 : parent_path;
            snprintf(parent_name, name_len, "%s", base);
        }
        return 0;
    }

    if (parent_name && name_len > 0) snprintf(parent_name, name_len, "pid-%u", ppid);
    if (parent_path && path_len > 0) parent_path[0] = 0;
    return -1;
}

#else

int enrich_parent_info_by_pid(uint32_t ppid, char *parent_name, size_t name_len,
                             char *parent_path, size_t path_len) {
    if (parent_name && name_len > 0) snprintf(parent_name, name_len, "pid-%u", ppid);
    if (parent_path && path_len > 0) parent_path[0] = 0;
    return 0;
}

#endif
