#ifndef EDR_PROCESS_TOKEN_PERMISSIONS_WIN_H
#define EDR_PROCESS_TOKEN_PERMISSIONS_WIN_H

#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

/* Private, testable I/O boundary. The caller owns a token opened from its
 * already generation-validated process handle. Do not reopen by PID here. */
static int edr_token_permissions_query(HANDLE token, char *integrity, size_t cap,
                                        uint32_t *elevation_out) {
  TOKEN_ELEVATION_TYPE elevation;
  TOKEN_MANDATORY_LABEL *label = NULL;
  DWORD bytes = 0u;
  DWORD rid;
  const char *level;
  int written, ok = 0;
  if (integrity && cap) integrity[0] = '\0';
  if (elevation_out) *elevation_out = 0u;
  if (!token || !integrity || !cap || !elevation_out) return 0;
  if (!GetTokenInformation(token, TokenElevationType, &elevation, sizeof(elevation), &bytes)) return 0;
  bytes = 0u;
  (void)GetTokenInformation(token, TokenIntegrityLevel, NULL, 0u, &bytes);
  if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || !bytes || bytes > 65536u) return 0;
  label = (TOKEN_MANDATORY_LABEL *)malloc(bytes);
  if (!label || !GetTokenInformation(token, TokenIntegrityLevel, label, bytes, &bytes) ||
      !IsValidSid(label->Label.Sid) || !*GetSidSubAuthorityCount(label->Label.Sid)) goto done;
  rid = *GetSidSubAuthority(label->Label.Sid, *GetSidSubAuthorityCount(label->Label.Sid) - 1u);
  level = rid >= SECURITY_MANDATORY_SYSTEM_RID ? "System"
      : rid >= SECURITY_MANDATORY_HIGH_RID ? "High"
      : rid >= SECURITY_MANDATORY_MEDIUM_RID ? "Medium"
      : rid >= SECURITY_MANDATORY_LOW_RID ? "Low" : "Untrusted";
  written = snprintf(integrity, cap, "%s", level);
  if (written < 0 || (size_t)written >= cap) { integrity[0] = '\0'; goto done; }
  *elevation_out = (uint32_t)elevation;
  ok = 1;
done:
  free(label);
  return ok;
}
#endif
