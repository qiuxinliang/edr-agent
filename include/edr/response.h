#ifndef EDR_RESPONSE_H
#define EDR_RESPONSE_H

#include "edr/command.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 主机隔离/恢复已统一到 command_stub.c 的 do_isolate / do_restore_host(真实 OS 网络隔离)。
 * 旧的 stamp-only edr_response_isolate / _restore_host / _isolate_auto_from_shellcode 已删除。 */
void edr_response_put_file(const char *cmd_id, const uint8_t *pl, size_t len,
                           const EdrSoarCommandMeta *sm);

void edr_response_collect_forensic(const char *cmd_id, const uint8_t *pl, size_t len,
                                   const EdrSoarCommandMeta *sm);
void edr_response_targeted_forensic(const char *cmd_id, const uint8_t *pl, size_t len,
                                    const EdrSoarCommandMeta *sm);
void edr_response_deep_forensic(const char *cmd_id, const uint8_t *pl, size_t len,
                                const EdrSoarCommandMeta *sm);

/* 取证外移共享入口:跑外部 collector 生成产物,成功后由 agent 经 transport v2 上传(通信只走 agent)。
 * 返回 0=成功(do_upload 时 minio_key 已填);>0=collector 非0退出;<0=启动/超时/验签失败。 */
int edr_response_forensic_run_external(const char *cmd_id, const char *scope, const uint8_t *payload,
                                       size_t payload_len, const char *artifact_ext, int do_upload,
                                       char *minio_key, size_t key_cap, char *detail,
                                       size_t detail_cap);
/* 取证外移是否启用(EDR_FORENSIC_COLLECTOR=1)。 */
int edr_response_forensic_external_enabled(void);

/* ── 取证异步生命周期(velo 采集硬取消支持)──
 * 受理:由 5 个 forensic 处理器在外移启用时调用,非阻塞 spawn + 登记单槽任务。
 *   返回 0=已受理(完成由 poll 上报终态); 1=busy(已有采集在跑); <0=spawn/解析/下载失败(调用方据此决定 in-process 回退)。 */
int edr_response_forensic_async_accept(const char *cmd_id, const char *command_type,
                                       const EdrSoarCommandMeta *sm, const char *scope,
                                       const uint8_t *payload, size_t payload_len,
                                       const char *artifact_ext, int do_upload,
                                       char *detail, size_t detail_cap);
/* agent 主循环周期调用:收割已完成采集(velo→builtin 两段、上传、唯一终态上报)。 */
void edr_response_forensic_async_poll(void);
/* 取消正在运行的采集:target_cmd_id 为空=取消当前。返回 1=已请求取消;0=无匹配运行中任务。 */
int edr_response_forensic_async_cancel(const char *target_cmd_id);
/* agent 关闭时调用:kill 在跑的 velo 并补报"已取消"。 */
void edr_response_forensic_async_abort_shutdown(void);
/* 是否有采集在运行(busy 查询)。 */
int edr_response_forensic_async_active(void);

void edr_response_memory_dump(const char *cmd_id, const uint8_t *pl, size_t len,
                              const EdrSoarCommandMeta *sm);
void edr_response_yara_scan(const char *cmd_id, const uint8_t *pl, size_t len,
                            const EdrSoarCommandMeta *sm);
void edr_response_pmfe_scan(const char *cmd_id, const uint8_t *pl, size_t len,
                            const EdrSoarCommandMeta *sm);

void edr_response_rtr_shell(const char *cmd_id, const uint8_t *pl, size_t len,
                            const EdrSoarCommandMeta *sm);

void edr_response_eventlog_view(const char *cmd_id, const uint8_t *pl, size_t len,
                                const EdrSoarCommandMeta *sm);
void edr_response_reg_query(const char *cmd_id, const uint8_t *pl, size_t len,
                            const EdrSoarCommandMeta *sm);
void edr_response_rtq_execute(const char *cmd_id, const uint8_t *pl, size_t len,
                              const EdrSoarCommandMeta *sm);

#ifdef __cplusplus
}
#endif

#endif
