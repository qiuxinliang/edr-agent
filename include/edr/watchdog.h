#ifndef EDR_WATCHDOG_H
#define EDR_WATCHDOG_H

#ifdef __cplusplus
extern "C" {
#endif

struct EdrConfig;

/**
 * §B2 伴生 watchdog 进程（抗 kill，互守）。
 *
 * 同一 `edr_agent` 二进制有两种角色：
 *  - 正常 agent：`edr_agent --config <cfg>`；启动时若启用则 spawn 一个 watchdog 伴生进程。
 *  - watchdog：`edr_agent --watchdog --parent-pid <pid> --config <cfg>`；极简循环，
 *    监控 agent 存活（pid + 心跳文件新鲜度），死/僵则按 `--config` 重新拉起 agent。
 *
 * 互守：agent 主循环也检查 watchdog 存活，watchdog 死则重新 spawn。任一被 kill，
 * 由另一方拉起。干净退出时 agent 写 stop stamp，watchdog 见之则不再重启并自退（防卸载后复活）。
 */

/** main() 早期记录 argv[0] 与 --config 路径，供后续 spawn/re-exec 使用。 */
void edr_self_protect_set_exec_context(const char *argv0, const char *config_path);

/** agent 侧：若启用（cfg 或 EDR_SELF_PROTECT_WATCHDOG_PROCESS=1）则 spawn/adopt 伴生 watchdog。返回 1=有伴生，0=无。 */
int edr_watchdog_maybe_spawn_companion(const struct EdrConfig *cfg);

/** agent 侧：主循环每轮调用 —— touch 心跳文件 + 检查伴生 watchdog 存活，死则重 spawn。 */
void edr_watchdog_agent_tick(const struct EdrConfig *cfg);

/** agent 侧：干净退出时写 stop stamp（阻止 watchdog 复活）。 */
void edr_watchdog_agent_on_shutdown(const struct EdrConfig *cfg);

/** watchdog 角色入口（由 main.c 的 --watchdog 路由调用）。阻塞至 stop stamp 或致命错误。返回进程退出码。 */
int edr_watchdog_run(long parent_pid, const char *argv0, const char *config_path);

#ifdef __cplusplus
}
#endif

#endif
