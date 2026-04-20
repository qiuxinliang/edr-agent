/**
 * P1 四层抑制：L2 文件哈希白名单、L3 文件 IOC、L4 行为/不可豁免（SQLite，可选）。
 * 顺序由 ave_sdk.c 编排。
 */
#ifndef EDR_AVE_SUPPRESSION_H
#define EDR_AVE_SUPPRESSION_H

struct EdrConfig;
struct AVEScanResult;
struct AVEBehaviorEvent;

/** @return 1 命中白名单（应跳过 ONNX），0 未命中或不可用 */
int edr_ave_file_hash_whitelist_hit(const struct EdrConfig *cfg, const char sha256_hex[65]);

/**
 * @param severity_out 可选；命中时写入 severity（1–3，默认 3）
 * @return 1 命中 IOC（已知恶意哈希），0 未命中
 */
int edr_ave_ioc_file_hit(const struct EdrConfig *cfg, const char sha256_hex[65], int *severity_out);

/** @return 1 命中 `ioc_ip` 表（需与 `ensure_ioc_schema` 扩展表一致） */
int edr_ave_ioc_ip_hit(const struct EdrConfig *cfg, const char *ip_utf8);

/** @return 1 命中 `ioc_domain` 表 */
int edr_ave_ioc_domain_hit(const struct EdrConfig *cfg, const char *domain_utf8);

/**
 * 根据事件中网络/文件字段写 `ioc_*_hit`（内部调用上述 hit；无库或空字段则不改或仅清逻辑）。
 */
void edr_ave_behavior_event_apply_ioc(const struct EdrConfig *cfg, struct AVEBehaviorEvent *ev);

/**
 * L4：平台「不可豁免」哈希（表 `file_behavior_non_exempt`）。
 * @param escalate_malware_out 若非 NULL：1=按恶意定级，0=至少可疑带
 * @return 1 命中
 */
int edr_ave_l4_non_exempt_hit(const struct EdrConfig *cfg, const char sha256_hex[65],
                              int *escalate_malware_out);

/** ONNX 之后：若 IOC 命中，将 final_* 置为 IOC_CONFIRMED，保留 raw_ai_* */
void edr_ave_overlay_ioc_post_ai(struct AVEScanResult *out, int severity);

/**
 * L4 覆盖：设置 sig_behavior_override / needs_l2_review，并按 escalate_malware 抬升 final_*。
 * 若已为 VERDICT_IOC_CONFIRMED 则不改 verdict，仅可置行为标志（调用方控制）。
 */
void edr_ave_apply_l4_non_exempt(struct AVEScanResult *out, int escalate_malware, float fp_floor,
                                 float l3_trigger);

/** L4×实时行为：与 `behavior_non_exempt` 同覆盖语义，`rule_name=behavior_realtime` */
void edr_ave_apply_l4_realtime_behavior(struct AVEScanResult *out, int escalate_malware, float fp_floor,
                                        float l3_trigger);

#endif
