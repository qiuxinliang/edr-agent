/* net_fanout 内部状态布局(core.c 与 detector.c 共享;非公开 API)。 */
#ifndef EDR_NET_FANOUT_INTERNAL_H
#define EDR_NET_FANOUT_INTERNAL_H

#include "edr/net_fanout_detector.h"

#include <stdint.h>

#define EDR_NF_BUCKETS 256u /* (pid,dport) 桶数(直接映射 + 碰撞覆盖) */
#define EDR_NF_IPSET 128u   /* 每桶 distinct IP 集合槽数(开放寻址) */

typedef struct {
  uint8_t used;
  uint8_t alerted;
  uint32_t pid;
  uint16_t dport;
  uint64_t window_start_ns;
  uint32_t distinct;
  uint32_t ipset[EDR_NF_IPSET]; /* FNV32(dst);0=空槽 */
} NfBucket;

struct EdrNetFanoutState {
  EdrNetFanoutCfg cfg;
  uint64_t window_ns;
  NfBucket buckets[EDR_NF_BUCKETS];
};

#endif
