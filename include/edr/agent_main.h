#ifndef EDR_AGENT_MAIN_H
#define EDR_AGENT_MAIN_H

#include "edr/agent.h"

/** Optional hook after full init (PMFE/shellcode/webshell/transport) and before **`edr_agent_run`** — e.g. Windows SCM **SERVICE_RUNNING**. */
typedef void (*EdrAgentAfterInitHook)(void *user);

typedef struct {
  EdrAgentAfterInitHook after_init_before_run;
  void *after_init_user;
} EdrAgentMainOptions;

/** Full agent lifecycle: create → init → subsystems → **`edr_agent_run`** → shutdown prints → destroy. Returns **0** on **`EDR_OK`**. */
int edr_agent_application_main(const char *config_path, const EdrAgentMainOptions *options);

/** Set after **create**, cleared before **destroy** — for Windows **SERVICE_CONTROL_STOP** → **`edr_agent_shutdown`**. */
EdrAgent *edr_agent_main_active_for_stop(void);

#endif
