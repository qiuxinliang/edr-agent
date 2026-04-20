#ifndef EDR_AGENT_H
#define EDR_AGENT_H

#include "config.h"
#include "error.h"
#include "event_bus.h"

typedef struct EdrAgent EdrAgent;

EdrAgent *edr_agent_create(void);
void edr_agent_destroy(EdrAgent *agent);

/** 加载配置、初始化事件总线、§5/§9/§12 子模块与采集（Windows）。 */
EdrError edr_agent_init(EdrAgent *agent, const char *config_path);

/** 阻塞运行直至 shutdown；循环内包含资源轮询、自保护 tick、可选配置热重载。 */
EdrError edr_agent_run(EdrAgent *agent);

void edr_agent_shutdown(EdrAgent *agent);

const EdrConfig *edr_agent_get_config(const EdrAgent *agent);

EdrEventBus *edr_agent_event_bus(EdrAgent *agent);

#endif
