#ifndef EDR_PROCESS_SID_ACCOUNT_WIN_H
#define EDR_PROCESS_SID_ACCOUNT_WIN_H

/* Win32 types are supplied by the owning preprocessing translation unit. */
#include <stdio.h>
#include <string.h>
#include "edr/behavior_record.h"

/* Resolve only the SID already attested at startup. No process handle or PID
 * lookup is needed, so an exited actor or reused PID cannot change identity.
 * Return 1 when filled, 0 when inapplicable, -1 with the real Win32 failure. */
static int edr_process_snapshot_account_name(EdrBehaviorRecord *record, DWORD *error) {
  PSID sid = NULL;
  WCHAR account[EDR_BR_STR_SHORT] = {0}, domain[EDR_BR_STR_SHORT] = {0};
  char account_utf8[EDR_BR_STR_SHORT] = {0}, domain_utf8[EDR_BR_STR_SHORT] = {0};
  char username[EDR_BR_STR_SHORT] = {0};
  DWORD account_cap = EDR_BR_STR_SHORT, domain_cap = EDR_BR_STR_SHORT;
  SID_NAME_USE use;
  int written, result = -1;
  if (error) *error = ERROR_SUCCESS;
  if (!record || record->username[0] || !record->user_sid[0] ||
      strcmp(record->identity_source, "kernel_process_token") != 0 ||
      strcmp(record->identity_quality, "token_sid") != 0) return 0;
  {
    const char *known = strcmp(record->user_sid, "S-1-5-18") == 0 ? "SYSTEM" :
        strcmp(record->user_sid, "S-1-5-19") == 0 ? "LOCAL SERVICE" :
        strcmp(record->user_sid, "S-1-5-20") == 0 ? "NETWORK SERVICE" : NULL;
    if (known) {
      snprintf(record->username, sizeof(record->username), "%s", known);
      snprintf(record->domain, sizeof(record->domain), "%s", "NT AUTHORITY");
      return 1;
    }
  }
  if (!ConvertStringSidToSidA(record->user_sid, &sid)) goto failed;
  if (!LookupAccountSidW(NULL, sid, account, &account_cap, domain, &domain_cap, &use)) goto failed;
  if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, account, -1,
                           account_utf8, sizeof(account_utf8), NULL, NULL) ||
      !WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, domain, -1,
                           domain_utf8, sizeof(domain_utf8), NULL, NULL)) goto failed;
  if (!account_utf8[0]) {
    if (error) *error = ERROR_NONE_MAPPED;
    goto done;
  }
  written = domain_utf8[0]
      ? snprintf(username, sizeof(username), "%s\\%s", domain_utf8, account_utf8)
      : snprintf(username, sizeof(username), "%s", account_utf8);
  if (written < 0 || (size_t)written >= sizeof(username)) {
    if (error) *error = ERROR_INSUFFICIENT_BUFFER;
    goto done;
  }
  memcpy(record->username, username, (size_t)written + 1u);
  snprintf(record->domain, sizeof(record->domain), "%s", domain_utf8);
  result = 1;
  goto done;
failed:
  if (error) *error = GetLastError();
done:
  if (sid) LocalFree(sid);
  return result;
}
#endif
