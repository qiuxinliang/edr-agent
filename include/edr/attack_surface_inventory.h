#ifndef EDR_ATTACK_SURFACE_INVENTORY_H
#define EDR_ATTACK_SURFACE_INVENTORY_H

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  int service_count;
  int auto_start_service_count;
  int scheduled_task_count;
  int enabled_scheduled_task_count;
  int startup_item_count;
  int privileged_account_count;
  int admin_group_member_count;
  int share_count;
  int risky_share_count;
  int persistence_finding_count;
} EdrAsurfInventorySummary;

/* P2 attack-surface inventory dimensions. Emits JSON object members:
 * services, scheduledTasks, startupItems, localAccounts, localGroups, shares.
 * listeners_only keeps the schema present but avoids expensive persistence/account scans. */
void edr_asurf_inventory_write_json(FILE *f, int listeners_only, EdrAsurfInventorySummary *summary);

#ifdef __cplusplus
}
#endif

#endif
