#ifndef EDR_AGENT_UPDATE_H
#define EDR_AGENT_UPDATE_H

#include "edr/config.h"

#define EDR_AGENT_VERSION_STRING "0.3.0"

int edr_agent_exe_path(char *out, size_t cap);
int edr_agent_check_update(const EdrConfig *cfg);
int edr_agent_startup_update(const EdrConfig *cfg);

#endif
