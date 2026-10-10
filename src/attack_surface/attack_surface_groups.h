#ifndef EDR_ATTACK_SURFACE_GROUPS_H
#define EDR_ATTACK_SURFACE_GROUPS_H
#include "cJSON.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>

typedef enum {
  EDR_ASURF_FULL, EDR_ASURF_LISTENERS, EDR_ASURF_INVENTORY,
  EDR_ASURF_POLICY, EDR_ASURF_NETWORK
} EdrAttackSurfaceMode;

/* Shared by strict command admission and the periodic collection owner.
 * Listener-only ETW snapshots use their existing reason, not this selector. */
static inline int edr_asurf_periodic_group_mode(const char *group,
                                               EdrAttackSurfaceMode *out) {
  EdrAttackSurfaceMode mode;
  if (!group) return 0;
  if (!strcmp(group, "full")) mode = EDR_ASURF_FULL;
  else if (!strcmp(group, "networkOnly")) mode = EDR_ASURF_NETWORK;
  else if (!strcmp(group, "inventoryOnly")) mode = EDR_ASURF_INVENTORY;
  else if (!strcmp(group, "policyOnly")) mode = EDR_ASURF_POLICY;
  else return 0;
  if (out) *out = mode;
  return 1;
}

static inline const char *edr_asurf_mode_name(EdrAttackSurfaceMode mode) {
  switch (mode) {
    case EDR_ASURF_LISTENERS: return "listenersOnly";
    case EDR_ASURF_INVENTORY: return "inventoryOnly";
    case EDR_ASURF_POLICY: return "policyOnly";
    case EDR_ASURF_NETWORK: return "networkOnly";
    default: return "full";
  }
}
static inline int edr_asurf_samples_listeners(EdrAttackSurfaceMode mode) {
  return mode == EDR_ASURF_FULL || mode == EDR_ASURF_LISTENERS || mode == EDR_ASURF_NETWORK;
}
static inline int edr_asurf_samples_inventory(EdrAttackSurfaceMode mode) {
  return mode == EDR_ASURF_FULL || mode == EDR_ASURF_INVENTORY;
}
static inline int edr_asurf_samples_policy(EdrAttackSurfaceMode mode) {
  return mode == EDR_ASURF_FULL || mode == EDR_ASURF_POLICY;
}
static inline int edr_asurf_samples_egress(EdrAttackSurfaceMode mode) {
  return mode == EDR_ASURF_FULL || mode == EDR_ASURF_NETWORK;
}

/* A normal signed/manual command remains full. The component selector is only
 * consumed by internal, periodic commands; ETW's existing listener-only path
 * is handled separately by the command owner. */
static inline EdrAttackSurfaceMode edr_asurf_periodic_payload_mode(
    const char *command_id, const uint8_t *payload, size_t payload_len) {
  if (!command_id || strncmp(command_id, "auto-asurf-", 11u) != 0 ||
      !payload || !payload_len || payload_len > 4096u) return EDR_ASURF_FULL;
  cJSON *root = cJSON_ParseWithLength((const char *)payload, payload_len);
  EdrAttackSurfaceMode mode = EDR_ASURF_FULL;
  const cJSON *group = cJSON_GetObjectItemCaseSensitive(root, "collection_group");
  if (cJSON_IsString(group)) (void)edr_asurf_periodic_group_mode(group->valuestring, &mode);
  cJSON_Delete(root);
  return mode;
}

static inline void edr_asurf_remove_group(cJSON *root, cJSON *summary,
                                         const char *const *fields,
                                         const char *const *counts) {
  for (size_t i = 0; fields[i]; ++i) cJSON_DeleteItemFromObjectCaseSensitive(root, fields[i]);
  for (size_t i = 0; counts[i]; ++i) cJSON_DeleteItemFromObjectCaseSensitive(summary, counts[i]);
}
/* Unsampled fields are absent, never fresh empty collections. The server's
 * per-group merge retains their data and collection timestamps. */
static inline int edr_asurf_project_sampled_groups(cJSON *root, EdrAttackSurfaceMode mode) {
  if (!cJSON_IsObject(root)) return -1;
  cJSON *summary = cJSON_GetObjectItemCaseSensitive(root, "summary");
  const char *const listeners[] = {"listeners", "webServices", "processHighlights", NULL};
  const char *const listener_counts[] = {"listenerCount", "publicListenerCount", "webInstanceCount", NULL};
  const char *const inventory[] = {"services", "scheduledTasks", "startupItems", "localAccounts", "localGroups", "shares", "browserExtensions", "installedSoftware", NULL};
  const char *const inventory_counts[] = {"serviceCount", "autoStartServiceCount", "scheduledTaskCount", "enabledScheduledTaskCount", "startupItemCount", "privilegedAccountCount", "adminGroupMemberCount", "shareCount", "riskyShareCount", "persistenceFindingCount", "browserExtensionCount", "installedSoftwareCount", NULL};
  const char *const policy[] = {"policy", "firewall", "securityPolicy", NULL};
  const char *const policy_counts[] = {NULL};
  const char *const egress[] = {"egressTop", NULL};
  const char *const egress_counts[] = {"suspiciousEgressCount", NULL};
  if (!edr_asurf_samples_listeners(mode)) edr_asurf_remove_group(root, summary, listeners, listener_counts);
  if (!edr_asurf_samples_inventory(mode)) edr_asurf_remove_group(root, summary, inventory, inventory_counts);
  if (!edr_asurf_samples_policy(mode)) edr_asurf_remove_group(root, summary, policy, policy_counts);
  if (!edr_asurf_samples_egress(mode)) edr_asurf_remove_group(root, summary, egress, egress_counts);
  if (cJSON_IsObject(summary) && !summary->child)
    cJSON_DeleteItemFromObjectCaseSensitive(root, "summary");
  cJSON_DeleteItemFromObjectCaseSensitive(root, "snapshotKind");
  return cJSON_AddStringToObject(root, "snapshotKind", edr_asurf_mode_name(mode)) ? 0 : -1;
}
#endif
