#ifndef EDR_WINDOWS_NATIVE_MANIFEST_H
#define EDR_WINDOWS_NATIVE_MANIFEST_H

#ifdef _WIN32

#include <windows.h>

/* The package manifest is the shared trust boundary for Agent readiness and
 * native uninstall.  The returned identity is the SHA-256 of the manifest
 * bytes, not of any caller-owned representation. */
int edr_windows_native_manifest_validate(const wchar_t *install_dir,
                                         char manifest_sha256[65]);
int edr_windows_native_manifest_name_safe(const char *name);

#endif

#endif
