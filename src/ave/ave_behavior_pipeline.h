/**
 * P2 行为管线：MPMC 事件队列 + 监控线程 + PID 异常分（ONNX/启发式）。
 * 由 ave_sdk.c 调用；不对外导出 ABI。
 */
#ifndef EDR_AVE_BEHAVIOR_PIPELINE_H
#define EDR_AVE_BEHAVIOR_PIPELINE_H

#include "edr/ave_sdk.h"

struct EdrConfig;

void edr_ave_bp_init(void);
void edr_ave_bp_shutdown(void);

/** 与 RegisterCallbacks 同步；可在监控运行中更新 */
void edr_ave_bp_set_callbacks(const AVECallbacks *callbacks);

/**
 * 启动消费线程（需已注册且含 on_behavior_alert；若配置关闭则不调起线程）。
 * @return AVE_OK / AVE_ERR_INVALID_PARAM / AVE_ERR_INTERNAL
 */
int edr_ave_bp_start_monitor(const struct EdrConfig *cfg);

void edr_ave_bp_feed(const AVEBehaviorEvent *event);

/**
 * B3b：static.onnx 扫描结论写入行为 PID 槽，供 §5.5 特征维 44–45（与《11》PidHistory.ave_* 对齐）。
 * @param verdict_edr_enum `EDRVerdict` 数值 0..9
 */
void edr_ave_bp_merge_static_scan(uint32_t pid, float max_confidence, int verdict_edr_enum);

int edr_ave_bp_get_flags(uint32_t pid, AVEBehaviorFlags *flags_out);
int edr_ave_bp_get_score(uint32_t pid, float *score_out);
void edr_ave_bp_notify_exit(uint32_t pid);

uint32_t edr_ave_bp_queue_depth(void);
/** 与 **`edr_ave_bp_queue_depth`** 对照；当前为固定环容量 **4096** */
uint32_t edr_ave_bp_queue_capacity(void);
int edr_ave_bp_monitor_running(void);

/** 填充 `AVEStatus` 中行为 MPMC / ONNX 推理计数（供 **`AVE_GetStatus`**） */
void edr_ave_bp_fill_metrics(AVEStatus *status_out);

#endif
