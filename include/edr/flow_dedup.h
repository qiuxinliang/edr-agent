#ifndef EDR_FLOW_DEDUP_H
#define EDR_FLOW_DEDUP_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * P0 优化 #2：流级首段扫描去重。
 *
 * Shellcode/漏洞利用特征都出现在连接起始（SMB negotiate、RDP connect、HTTP 请求头、TLS ClientHello）。
 * 本表按 4 元组（方向无关）记录每条连接已深扫的载荷字节数，超过预算后该连接后续分段直接跳过深扫，
 * 把大文件/长连接的逐包 entropy/YARA 成本降几个数量级。
 *
 * 直接映射（direct-mapped）定长表：O(1)、内存有界、碰撞即覆盖（启发式去重，过扫安全、不会漏扫起始）。
 * 当前 WinDivert 仅单消费线程，无需加锁；若将来多线程消费需自行串行化。
 */

/** 流标识：端点地址哈希 + 端口（构造时已规范化为方向无关）。 */
typedef struct {
  uint32_t ha; /* hash(addr_a) */
  uint32_t hb; /* hash(addr_b) */
  uint16_t pa; /* port_a */
  uint16_t pb; /* port_b */
} EdrFlowKey;

typedef struct EdrFlowTable EdrFlowTable;

/** FNV-1a 32 位字符串哈希（用于把文本地址折成 EdrFlowKey 的端点哈希）。 */
uint32_t edr_flow_hash_str(const char *s);

/** 用两端（地址哈希, 端口）构造方向无关的规范流键。 */
void edr_flow_key_make(EdrFlowKey *out, uint32_t src_hash, uint16_t src_port, uint32_t dst_hash, uint16_t dst_port);

/** 创建定长流表；slots 会向上取到 2 的幂（下限 64，上限 1<<20）。失败返回 NULL。 */
EdrFlowTable *edr_flow_table_create(uint32_t slots);
void edr_flow_table_destroy(EdrFlowTable *t);

/**
 * 判定是否应对该连接的本段载荷做深扫，并累计已扫字节。
 *  - budget_bytes==0：始终深扫（不限，等价旧行为）。
 *  - 命中且已扫 ≥ budget：返回 0（跳过深扫）。
 *  - 命中且未达预算：累加字节，返回 1。
 *  - 未命中/碰撞：占用槽位、重置计数，返回 1。
 * now_ns 仅用于槽位老化（陈旧槽位可被新流复用）。t 为 NULL 时返回 1（不去重）。
 */
int edr_flow_table_admit(EdrFlowTable *t, const EdrFlowKey *k, uint32_t payload_len, uint32_t budget_bytes,
                         uint64_t now_ns);

/**
 * P1 优化 #4：包级令牌桶限速（用于约束深扫速率，突发时降采样）。
 * 速率 per_sec 令牌/秒，桶容量 = per_sec（1 秒突发）。per_sec==0 视为不限（始终放行）。
 */
typedef struct {
  double tokens;
  uint64_t last_ns;
} EdrTokenBucket;

/** 消费一个令牌：放行返回 1，被限速返回 0。tb 为 NULL 时返回 1。 */
int edr_token_bucket_admit(EdrTokenBucket *tb, uint32_t per_sec, uint64_t now_ns);

#ifdef __cplusplus
}
#endif

#endif
