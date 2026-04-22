/**
 * Windows 监听套接字枚举（TCP/UDP IPv4+IPv6 LISTEN），供 §19 攻击面与 §21 PMFE 共用。
 * 实现带进程内 TTL 缓存（默认约 2s），多线程安全；底层仍为 GetExtendedTcpTable/Udp。
 */
#ifndef EDR_LISTEN_TABLE_WIN_H
#define EDR_LISTEN_TABLE_WIN_H

#ifdef _WIN32

#include <stddef.h>

struct EdrConfig;

/** 从 `[attack_surface].win_listen_cache_ttl_ms` 与环境变量 `EDR_WIN_LISTEN_CACHE_TTL_MS` 更新有效 TTL，并清空缓存。由 `edr_config_load` 调用。 */
void edr_win_listen_apply_config(const struct EdrConfig *cfg);

/** 与 attack_surface AsListener 核心字段对齐的一条监听（无 id/proc，由调用方补全）。 */
typedef struct {
  int pid;
  int port;
  char bind[160];
  char scope[20];
  char proto[8];
} EdrWinListenRow;

/**
 * 枚举本机监听（与 `attack_surface_report.c` 原 `collect_listeners_win32` 同源）。
 * 在 TTL 内复用缓存快照，按 max_out 拷贝；若总行数超过 max_out 或快照在内部缓冲已截断则 *truncated=1。
 * @param out 行缓冲（至少 max_out 条）
 * @param max_out 上限（如 256 / 2048）
 * @param truncated 输出 1 表示截断
 * @return 拷贝行数
 */
int edr_win_listen_collect_rows(EdrWinListenRow *out, int max_out, int *truncated);

#endif

#endif
