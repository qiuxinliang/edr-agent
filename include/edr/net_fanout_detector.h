#ifndef EDR_NET_FANOUT_DETECTOR_H
#define EDR_NET_FANOUT_DETECTOR_H

#include "edr/behavior_record.h"
#include "edr/error.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct EdrConfig;

/**
 * 端侧网络扇出/扫描检测器:同一进程在窗口内对**同一目的端口**连接**大量不同目的 IP**
 * (扫描敏感端口,如 445/3389/22 等)→ 判定为端口/主机扫描或横向探测(MITRE T1046/T1018)。
 * 复用端侧真实 net_dst/net_dport(服务端只拿到占位值,故必须在端侧做)。单线程(preprocess 线程)。
 */

/* ---- 可测核心(不依赖 agent 全局/配置文件) ---- */

typedef struct {
  uint32_t window_s;              /* 滑动窗口(秒);0 视为 120 */
  uint32_t distinct_ip_threshold; /* 同 (pid,dport) 窗口内不同 IP 阈值;0 视为 50 */
  uint16_t ports[32];             /* 扫描敏感端口集合 */
  int n_ports;                    /* ports 有效数;<=0 时所有端口都计 */
} EdrNetFanoutCfg;

typedef struct EdrNetFanoutState EdrNetFanoutState;

EdrNetFanoutState *edr_net_fanout_state_create(const EdrNetFanoutCfg *cfg);
void edr_net_fanout_state_destroy(EdrNetFanoutState *s);

/** 观察一次连接;**刚跨过阈值**(应产警)返回 1,否则 0。dst_ip 为点分/字符串目的地址。 */
int edr_net_fanout_observe(EdrNetFanoutState *s, uint32_t pid, uint16_t dport, const char *dst_ip, uint64_t now_ns);

/* ---- agent 集成(文件内单例) ---- */

EdrError edr_net_fanout_init(const struct EdrConfig *cfg);
void edr_net_fanout_on_event(const EdrBehaviorRecord *br);
void edr_net_fanout_shutdown(void);

#ifdef __cplusplus
}
#endif

#endif
