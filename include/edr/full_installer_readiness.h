#ifndef EDR_FULL_INSTALLER_READINESS_H
#define EDR_FULL_INSTALLER_READINESS_H

#include <stddef.h>

typedef int (*EdrReadinessFileFn)(void *ctx, const char *path);
typedef int (*EdrReadinessIdentityFn)(void *ctx, const char *expected_exe);

typedef struct EdrFullInstallerReadinessDeps {
  void *ctx;
  EdrReadinessFileFn regular_file;
  EdrReadinessFileFn readable_config;
  EdrReadinessFileFn uninstall_provenance;
  EdrReadinessIdentityFn service_identity;
  EdrReadinessIdentityFn task_identity;
  EdrReadinessIdentityFn current_module;
} EdrFullInstallerReadinessDeps;

int edr_full_installer_readiness_probe(const EdrFullInstallerReadinessDeps *deps,
                                       const char *directory, char *reason, size_t reason_cap);

/* Production baseline entry point. Runtime Windows adapters and snapshot
 * contract tests call this wrapper so they share the same gate as the Agent. */
int edr_full_installer_baseline_ready(const EdrFullInstallerReadinessDeps *deps,
                                      const char *directory, char *reason, size_t reason_cap);

#endif
