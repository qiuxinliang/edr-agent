#ifndef EDR_PMFE_IDLE_SCANNER_H
#define EDR_PMFE_IDLE_SCANNER_H

#include "edr/config.h"

#include <stdbool.h>
#include <stdint.h>

void pmfe_idle_scanner_init(const EdrConfig *cfg);
void pmfe_idle_scanner_tick(void);
void pmfe_idle_scanner_stop(void);
bool pmfe_idle_scanner_running(void);

#endif
