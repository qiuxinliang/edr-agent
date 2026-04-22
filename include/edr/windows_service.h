#ifndef EDR_WINDOWS_SERVICE_H
#define EDR_WINDOWS_SERVICE_H

/**
 * If **`argv`** contains **`--service`**, connects to SCM (**`StartServiceCtrlDispatcher`**)
 * and blocks until the service stops. Otherwise returns **-1** (caller runs normal **`main`**).
 * @return exit code **0**–**255** when service path was taken; **-1** if not a service invocation.
 */
int edr_windows_service_dispatch_if_requested(int argc, char **argv);

#endif
