/* 非 Windows：监听表与优先级占位（返回 MED，刷新为空） */

#include "edr/pmfe.h"

void edr_pmfe_listen_table_refresh(void) {}

EdrPmfeScanPriority edr_pmfe_compute_priority(uint32_t pid) {
  (void)pid;
  return EDR_PMFE_PRIO_MED;
}

void edr_pmfe_host_policy_init(void) {}

void edr_pmfe_host_policy_shutdown(void) {}
