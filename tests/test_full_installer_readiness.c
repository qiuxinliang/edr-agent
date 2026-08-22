#include "edr/full_installer_readiness.h"
#include "edr/agent_update_manifest.h"
#include <stdio.h>
#include <string.h>

typedef struct { int files, config, uninstall, service, task, module; } State;
static int file(void *p, const char *x) { const char *names[] = {"FDSensor.exe", "agent.toml", "unins000.exe", "unins000.dat"}; for (int i=0;i<4;i++) if (strstr(x,names[i])) return (((State *)p)->files & (1<<i)) != 0; return 0; }
static int config(void *p, const char *x) { (void)x; return ((State *)p)->config; }
static int uninstall(void *p, const char *x) { (void)x; return ((State *)p)->uninstall; }
static int service(void *p, const char *x) { (void)x; return ((State *)p)->service; }
static int task(void *p, const char *x) { (void)x; return ((State *)p)->task; }
static int module(void *p, const char *x) { (void)x; return ((State *)p)->module; }

int main(void) {
  EdrFullInstallerReadinessDeps d = {0}; State s = {15,1,1,0,1,1}; char reason[128];
  d.ctx=&s; d.regular_file=file; d.readable_config=config; d.uninstall_provenance=uninstall;
  d.service_identity=service; d.task_identity=task; d.current_module=module;
  if (!edr_full_installer_readiness_probe(&d, "C:/FDS", reason, sizeof(reason)) || strcmp(reason,"ready")) return 1;
  s.service=1; s.task=0; if (!edr_full_installer_readiness_probe(&d, "C:/FDS", reason, sizeof(reason)) || strcmp(reason,"ready")) return 12;
  s.service=1; s.task=1; if (edr_full_installer_readiness_probe(&d,"C:/FDS",reason,sizeof(reason)) || strcmp(reason,"installation_identity_conflict")) return 2;
  s.service=0; s.task=0; if (edr_full_installer_readiness_probe(&d,"C:/FDS",reason,sizeof(reason)) || strcmp(reason,"installation_identity_mismatch")) return 3;
  s.task=1; s.uninstall=0; if (edr_full_installer_readiness_probe(&d,"C:/FDS",reason,sizeof(reason)) || strcmp(reason,"uninstaller_provenance_missing_or_mismatch")) return 4;
  s.uninstall=1; s.module=0; if (edr_full_installer_readiness_probe(&d,"C:/FDS",reason,sizeof(reason)) || strcmp(reason,"current_module_identity_mismatch")) return 5;
  s.module=1; s.files=14; if (edr_full_installer_readiness_probe(&d,"C:/FDS",reason,sizeof(reason)) || strstr(reason,"installation_baseline_missing_FDSensor.exe") == NULL) return 6;
  s.files=13; if (edr_full_installer_readiness_probe(&d,"C:/FDS",reason,sizeof(reason)) || strstr(reason,"agent.toml") == NULL) return 7;
  s.files=11; if (edr_full_installer_readiness_probe(&d,"C:/FDS",reason,sizeof(reason)) || strstr(reason,"unins000.exe") == NULL) return 8;
  s.files=7; if (edr_full_installer_readiness_probe(&d,"C:/FDS",reason,sizeof(reason)) || strstr(reason,"unins000.dat") == NULL) return 9;
  s.files=15; s.config=0; if (edr_full_installer_readiness_probe(&d,"C:/FDS",reason,sizeof(reason)) || strcmp(reason,"agent_config_unreadable")) return 10;
  s.config=1; s.task=1; s.module=1; if (!edr_full_installer_readiness_probe(&d,"C:/FDS",reason,sizeof(reason))) return 11;
  EdrAgentUpdateRuntimeInfo info = {0};
  info.ready = 1; info.protocol_version = 5; info.materialized = 1; info.full_installer_ready = 1;
  snprintf(info.source, sizeof(info.source), "embedded");
  snprintf(info.full_installer_reason, sizeof(info.full_installer_reason), "ready");
  snprintf(info.installation_family, sizeof(info.installation_family), "embedded_full_installer");
  snprintf(info.installation_baseline, sizeof(info.installation_baseline), "3.2.343");
  char fragment[1024];
  if (edr_agent_update_manifest_fragment(&info, fragment, sizeof(fragment)) != 0 ||
      strstr(fragment, "full_installer_ready") == NULL || strstr(fragment, "installation_family") == NULL) return 13;
  puts("full_installer_readiness_core: PASS"); return 0;
}
