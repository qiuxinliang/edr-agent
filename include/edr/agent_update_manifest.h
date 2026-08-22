#ifndef EDR_AGENT_UPDATE_MANIFEST_H
#define EDR_AGENT_UPDATE_MANIFEST_H
#include <stddef.h>
#include "edr/agent_update_command.h"
int edr_agent_update_manifest_fragment(const EdrAgentUpdateRuntimeInfo *info, char *out, size_t cap);
#endif
