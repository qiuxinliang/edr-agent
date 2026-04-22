/* Windows-only helpers for §19 attack surface (GetExtendedTcpTable / process name). */

#ifndef EDR_ATTACK_SURFACE_WIN_UTIL_H
#define EDR_ATTACK_SURFACE_WIN_UTIL_H

#ifdef _WIN32
#include <stddef.h>
#include <windows.h>

void edr_asurf_win_ensure_wsa(void);

/** `addr` 为 IPv4 **网络字节序**（与 MIB_*ROW 中 dwLocalAddr/dwRemoteAddr 一致）。 */
void edr_asurf_win_ipv4_to_string(DWORD addr, char *buf, size_t cap);

/** 与 Linux `scope_for_bind` 对齐：loopback / public(0.0.0.0) / lan */
void edr_asurf_win_bind_scope_v4(const char *bind_str, char *scope, size_t cap);

/** `addr` 为 16 字节 IPv6 地址（与 MIB_TCP6ROW 中 ucLocalAddr 一致）。 */
void edr_asurf_win_ipv6_to_string(const unsigned char addr[16], char *buf, size_t cap);

/** IPv6 绑定 scope：::1 loopback；:: / [::] 全网；fe80:: 链路本地；其余多为 lan */
void edr_asurf_win_bind_scope_v6(const char *bind_str, char *scope, size_t cap);

/** 进程映像文件名（不含路径）；失败则 `out[0]=0`。 */
void edr_asurf_win_pid_exe_name(DWORD pid, char *out, size_t cap);

#endif

#endif
