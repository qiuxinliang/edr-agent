/**
 * 深度取证采集器启动器 — 对标 CrowdStrike Falcon Forensics Collector。
 * Agent 负责：下载 collector 可执行文件 → 验证签名 → CreateProcess(Job+低优) → 监控 → 报告。
 */
#ifndef EDR_DEEP_COLLECTOR_H
#define EDR_DEEP_COLLECTOR_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
  EDR_DC_OK = 0,
  EDR_DC_ERR_DOWNLOAD = -1,
  EDR_DC_ERR_SIGNATURE = -2,
  EDR_DC_ERR_SPAWN = -3,
  EDR_DC_ERR_TIMEOUT = -4,
  EDR_DC_ERR_CRASH = -5,
  EDR_DC_ERR_DISABLED = -6,
  EDR_DC_ERR_CANCELLED = -7,
} EdrDeepCollectorError;

typedef struct {
  const char *download_url;
  const char *expected_sha256;
  const char *output_dir;
  const char *upload_url;
  const char *scope;
  uint32_t timeout_s;
} EdrDeepCollectorParams;

/**
 * 启动深度取证采集器。
 * 返回 EDR_DC_OK 成功（采集器已在后台运行，异步监控）。
 * 其他返回值表示启动阶段失败。
 *
 * 监控：Agent 的主循环应周期性调用 edr_deep_collector_poll()
 *       来收集子进程状态变化。
 */
int edr_deep_collector_launch(const EdrDeepCollectorParams *params);

/**
 * 在 Agent 主循环中周期性调用。
 * 返回：>0 采集器仍在运行，0 采集器已完成，<0 失败。
 * 如果 completed，out_exit_code 和 out_detail 被填充。
 */
int edr_deep_collector_poll(int *out_exit_code, char *out_detail, size_t detail_cap);

/** 强制终止采集器（前端 cancel 或 Agent shutdown）。 */
void edr_deep_collector_kill(void);

/** 判断当前是否有采集器在运行。 */
int edr_deep_collector_is_running(void);

typedef struct {
  int ready;
  int emulation_supported;
  char binary_arch[16];
  char execution_mode[32];
  char detail[128];
} EdrVelociraptorRuntime;

/**
 * Report the actual Velociraptor child-process runtime, including PE
 * architecture and the Windows x64-emulation gate. File presence alone is not
 * considered healthy.
 */
void edr_deep_collector_get_velociraptor_runtime(EdrVelociraptorRuntime *out);

/**
 * 同步运行规格 — 取证生成外移用（memory_dump 等）。
 * 通信硬约束:collector 只在本地落产物,不接收 upload-url、不做任何网络 I/O。
 */
typedef struct {
  const char *collector_bin; /* 可空:空则用 EDR_FORENSIC_COLLECTOR_BIN 或平台默认 */
  const char *scope;         /* "memory_dump" 等 */
  const char *output_dir;    /* 本地产物目录 */
  const char *extra_args;    /* 透传 collector,如 "--pid=1234 --full"（已做基本清洗） */
  uint32_t timeout_s;        /* 0 表示默认 300s */
  uint32_t cpu_limit_percent; /* Windows Job CPU 硬上限；0=默认 10，交互式查询可单独提高 */
  int needs_velociraptor;    /* 1=velo 层(运行前确保 velociraptor 就绪到其槽位);0=builtin/其它,不拉 velo */
  int (*cancel_requested)(void *user); /* blocking 模式每 100ms 检查；非零时终止整个子进程树 */
  void *cancel_user;
} EdrCollectorRunSpec;

/**
 * 同步 spawn + 等待(带超时) + 返回。绝不传 upload-url(agent 独占后端通道)。
 * 返回 0=成功(collector 退出码 0,产物已落地);<0=启动/超时/崩溃;>0=collector 非 0 退出码。
 * out_detail 写诊断(可为 NULL)。
 *
 * collector 退出码约定(与 Go 适配器 forensic-collector/main.go 对齐,供调用方做兜底判断):
 *   0=成功; 2=带 warning 完成; 3=velociraptor 非0退出; 4=超时;
 *   5=找不到 velociraptor(调用方据此回退 C baseline forensic_collector_builtin);
 *   6=参数/请求错误; 7=适配器内部错误(打包等)。
 */
int edr_deep_collector_run_blocking(const EdrCollectorRunSpec *spec,
                                    char *out_detail, size_t detail_cap);

/**
 * 异步 spawn(非阻塞)——用同一 EdrCollectorRunSpec 契约(.req/--out-file 由调用方拼进 extra_args),
 * 复用 dc_resolve_verify(平台固定地址下载 + SHA256 校验),spawn 后立即返回,进程登记到单例。
 * 之后由 agent 主循环周期调 edr_deep_collector_poll() 收割,edr_deep_collector_kill() 取消。
 * 返回 EDR_DC_OK 已受理并在后台运行;EDR_DC_ERR_SPAWN 已有采集在跑(busy)或 spawn 失败;
 *      其它<0 为路径解析/下载/校验失败(out_detail 写诊断)。
 * 单槽:同一时刻只允许一个采集;busy 时调用方应返回"忙"。
 */
int edr_deep_collector_spawn(const EdrCollectorRunSpec *spec, char *out_detail, size_t detail_cap);

/** 后台预取/版本检查 adapter 与 Velociraptor；已在运行时自动合并，不阻塞命令热路径。 */
void edr_deep_collector_schedule_runtime_refresh(void);

#endif
