/* Windows-only：WSA、IPv4 字符串、进程短名 — 供 attack_surface_report / attack_surface_egress 使用 */

#ifdef _WIN32

#include "edr/attack_surface_win_util.h"

#include <stdio.h>
#include <string.h>

static int s_wsa_ok;

void edr_asurf_win_ensure_wsa(void) {
  if (s_wsa_ok) {
    return;
  }
  WSADATA w;
  if (WSAStartup(MAKEWORD(2, 2), &w) == 0) {
    s_wsa_ok = 1;
  }
}

void edr_asurf_win_ipv4_to_string(DWORD addr, char *buf, size_t cap) {
  if (!buf || cap == 0) {
    return;
  }
  buf[0] = 0;
  struct in_addr ia;
  ia.S_un.S_addr = addr;
  if (!InetNtopA(AF_INET, &ia, buf, (DWORD)cap)) {
    snprintf(buf, cap, "0.0.0.0");
  }
}

void edr_asurf_win_bind_scope_v4(const char *bind, char *scope, size_t cap) {
  if (!scope || cap == 0) {
    return;
  }
  if (!bind || !bind[0]) {
    snprintf(scope, cap, "lan");
    return;
  }
  if (strcmp(bind, "127.0.0.1") == 0) {
    snprintf(scope, cap, "loopback");
    return;
  }
  if (strcmp(bind, "0.0.0.0") == 0) {
    snprintf(scope, cap, "public");
    return;
  }
  snprintf(scope, cap, "lan");
}

void edr_asurf_win_ipv6_to_string(const unsigned char addr[16], char *buf, size_t cap) {
  if (!buf || cap == 0) {
    return;
  }
  buf[0] = 0;
  if (!InetNtopA(AF_INET6, addr, buf, (DWORD)cap)) {
    snprintf(buf, cap, "::");
  }
}

void edr_asurf_win_bind_scope_v6(const char *bind, char *scope, size_t cap) {
  if (!scope || cap == 0) {
    return;
  }
  if (!bind || !bind[0]) {
    snprintf(scope, cap, "lan");
    return;
  }
  if (strcmp(bind, "::1") == 0) {
    snprintf(scope, cap, "loopback");
    return;
  }
  if (strcmp(bind, "::") == 0) {
    snprintf(scope, cap, "public");
    return;
  }
  /* fe80::/10 链路本地 */
  if (strncmp(bind, "fe80:", 5) == 0 || strncmp(bind, "FE80:", 5) == 0) {
    snprintf(scope, cap, "lan");
    return;
  }
  snprintf(scope, cap, "lan");
}

void edr_asurf_win_pid_exe_name(DWORD pid, char *out, size_t cap) {
  if (!out || cap == 0) {
    return;
  }
  out[0] = 0;
  HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
  if (!h) {
    h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
  }
  if (!h) {
    return;
  }
  char path[1024];
  DWORD n = (DWORD)sizeof(path);
  if (QueryFullProcessImageNameA(h, 0, path, &n)) {
    const char *base = strrchr(path, '\\');
    snprintf(out, cap, "%s", base ? base + 1 : path);
  }
  CloseHandle(h);
}

#endif
