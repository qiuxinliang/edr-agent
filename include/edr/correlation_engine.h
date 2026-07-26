/**
 * 端侧有状态关联引擎（多事件 / 时序 / 阈值），补足单事件 P0 IR 无法表达的检测。
 *
 * 设计要点（见方案评审）：
 *  - 两个集成点，分居不同线程，各自独占一张状态表，避免跨线程竞争：
 *      A. edr_correlation_observe_interest —— 采集最早的兴趣门控处（采集/ETW 线程）。
 *         看得到「全火喉」（含随后会被 sensor_interest / collector 丢弃的高频事件），
 *         只做有界计数；仅当窗口内聚合达阈值才发一条告警，个体事件仍照常丢弃、不上云。
 *         服务：阈值 / 频率类规则（端口扫描、批量加密、DNS 隧道…）。
 *      B. edr_correlation_evaluate —— process_one_slot 第 5 步（P0 直出）之后（预处理线程）。
 *         对已准入并富化的 BehaviorRecord 推进状态机；集齐序列才发一条告警。
 *         服务：序列 / 合流类规则（注入三步、凭证读→外联…）。
 *  - 总开关 EDR_CORRELATION_ENABLE 默认关；关闭时所有入口为 no-op。
 *  - 命中发射复用 §12.4 行为告警通道（edr_behavior_alert_emit_to_batch），
 *    并复用 P0 的四层限流（全局/租户/端点/去重），rule_id 以 R-CORR-* 独立命名空间。
 */
#ifndef EDR_CORRELATION_ENGINE_H
#define EDR_CORRELATION_ENGINE_H

#include "edr/behavior_record.h"
#include "edr/sensor_interest.h"

#include <stddef.h>
#include <stdint.h>

/** 总开关：EDR_CORRELATION_ENABLE=1/true/yes/on 才启用；默认关（no-op）。 */
int edr_correlation_enabled(void);

/** Apply product policy without requiring process-level environment changes. */
void edr_correlation_configure(int enabled, int inject_feedback_enabled);

/** Whether AVE injection/credential verdicts may be fed into correlation. */
int edr_correlation_inject_feedback_enabled(void);

/** 懒加载规则包与状态表；幂等，可重复调用。 */
void edr_correlation_lazy_init(void);

/** 重新加载规则包（下发新版本后触发）。 */
void edr_correlation_reload(void);

/**
 * 集成点 A（阈值/频率）：观测采集兴趣门控处的事件（在丢弃决策之前调用）。
 * 由采集/ETW 线程独占调用。
 */
void edr_correlation_observe_interest(const EdrSensorInterestEvent *ev);

/**
 * 集成点 B（序列/合流）：在 P0 直出之后对已富化 BehaviorRecord 推进状态机。
 * 由预处理线程独占调用。
 */
void edr_correlation_evaluate(const EdrBehaviorRecord *br);

/**
 * 集成点 B'（Windows 注入回灌）：AVE 行为裁决判定为注入类（behavior_flags 命中
 * 注入位）时调用。Windows 上注入由 AVE 引擎对多事件序列内部推理得出裁决，不以
 * 离散 PROCESS_INJECT 记录流经 process_one_slot；本入口把该低频高置信裁决合成一条
 * 最小 PROCESS_INJECT 记录喂序列评估，使注入信号可参与跨引擎关联（如“注入后外联”）。
 *
 * 精准/低开销：仅由 AVE 裁决回调（本就受推理阈值节流的低频路径）在注入类裁决时调用，
 * 不新增采集、无新线程、不碰 ETW 热路径。总开关关时为 no-op。
 *
 * 线程安全：本函数可能在 AVE 裁决线程调用，而序列状态表由预处理线程独占。为避免热路径
 * 加锁，注入信号仅被原子写入一个小 pending 环；真正入序列表的动作延迟到预处理线程下一次
 * edr_correlation_evaluate（或 poll_maintenance）时排空，从而保持“序列表单一写者”不变式。
 *
 * technique：具体注入子技法（如 "hollowing"/"remote_thread"/"lsass"/"reflective"/"alloc_exec"），
 * 由调用方从 AVE behavior_flags 派生；随证据链与图边上报，供后端/图计算精确归因。可为 NULL。
 */
void edr_correlation_note_injection(uint32_t pid, const char *process_name,
                                    int64_t event_time_ns, const char *technique);

typedef struct EdrCorrelationInjectionObservation {
  uint32_t pid;
  int64_t event_time_ns;
  char process_name[256];
  char technique[32];
  char source[32];
} EdrCorrelationInjectionObservation;

/** Return the latest AVE-confirmed injection observation for pid. This is a
 * process-level correlation signal; it does not imply that pid wrote a
 * particular VAD unless source/target telemetry is available. */
int edr_correlation_latest_injection(uint32_t pid,
                                     EdrCorrelationInjectionObservation *out);

/**
 * 集成点 B''（凭证转储回灌）：AVE 行为裁决判定为凭证转储类（LSASS/SAM/NTDS 等）时调用。
 * 与 note_injection 同一机制（AVE 裁决线程写 pending 环，预处理线程排空），但合成一条带
 * 凭证标记路径的 FILE_READ 记录，直接被 R-CORR-CRED-EXFIL-001 覆盖 —— 使“LSASS 内存转储
 * → 外联”这一头号手法（无落地文件、file_read 规则抓不到）纳入关联检测面。
 * technique：凭证子技法（"lsass_dump"/"sam_dump"/"ntds"/"inject_lsass"），随证据链上报。
 */
void edr_correlation_note_cred_access(uint32_t pid, const char *process_name,
                                      int64_t event_time_ns, const char *technique);

/** 周期维护：过期窗口回收、注入 pending 排空。搭 local_evidence_cache ~60s 周期调用。
 * 契约：本函数写序列状态表，必须与 edr_correlation_evaluate 同在预处理线程调用。 */
void edr_correlation_poll_maintenance(int64_t now_ns);

/** 运行指标（可经 agent 状态 JSON 导出）。 */
typedef struct {
  int enabled;
  int loaded;
  char bundle_version[128];
  uint32_t rule_count;      /* 已加载规则数（阈值+序列） */
  uint32_t active_states;   /* 当前活跃状态槽数 */
  uint64_t observed;        /* 集成点 A 观测事件数 */
  uint64_t evaluated;       /* 集成点 B 评估事件数 */
  uint64_t fired;           /* 关联命中发射数 */
  uint64_t suppressed;      /* 被限流/去重抑制数 */
  uint64_t evicted;         /* LRU/过期回收数 */
  uint64_t inject_fed;      /* AVE 注入回灌被排空并入序列表的条数 */
  uint64_t inject_dropped;  /* 注入 pending 环覆盖丢弃的条数 */
  uint64_t rate_dropped;    /* 触发引擎级发射上限被丢弃的条数 */
} EdrCorrelationStatus;

void edr_correlation_get_status(EdrCorrelationStatus *out);

/** 状态导出为紧凑 JSON（供健康遥测/验证脚本读取）。返回写入长度（不含结尾 NUL）。 */
int edr_correlation_status_json(char *out, size_t cap);

#endif
