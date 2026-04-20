/* §18.3.5.4 P2：`egressTop` 出站聚合（Linux：`ss`；其它平台暂空） */

#ifndef EDR_ATTACK_SURFACE_EGRESS_H
#define EDR_ATTACK_SURFACE_EGRESS_H

struct EdrConfig;

typedef struct {
  char remote_ip[64];
  int remote_port;
  int pid;
  char proc_name[160];
  int connection_count;
  /** 1 时 JSON 输出 `riskTag`（非 RFC1918 且非常见基础设施端口） */
  int mark_risk;
} EdrAsurfEgressRow;

/**
 * 按 (remote_ip, remote_port, pid) 聚合 ESTAB 连接，按 connection_count 降序取前 `egress_top_n` 条。
 * `suspicious_conn_total`：每条匹配「公网远端且非 53/80/443/123/853」的流各计 1。
 */
void edr_asurf_collect_egress(const struct EdrConfig *cfg, EdrAsurfEgressRow *out, int max_out, int *n_out,
                              int *suspicious_conn_total, int *truncated);

#endif
