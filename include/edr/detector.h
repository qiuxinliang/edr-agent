#ifndef EDR_DETECTOR_H
#define EDR_DETECTOR_H

#include "edr/config.h"
#include "edr/error.h"
#include "edr/event_bus.h"

typedef EdrError (*EdrDetectorInitFn)(const EdrConfig *cfg, EdrEventBus *bus);
typedef void (*EdrDetectorShutdownFn)(void);

typedef struct {
  const char *name;
  EdrDetectorInitFn init;
  EdrDetectorShutdownFn shutdown;
} EdrDetector;

#endif