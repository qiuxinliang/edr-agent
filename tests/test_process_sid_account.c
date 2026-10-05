#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>
typedef unsigned long DWORD;
typedef void *PSID;
typedef wchar_t WCHAR;
typedef int SID_NAME_USE;
#define ERROR_SUCCESS 0
#define ERROR_NONE_MAPPED 1332
#define ERROR_INSUFFICIENT_BUFFER 122
#define CP_UTF8 65001
#define WC_ERR_INVALID_CHARS 128
static DWORD last_error;
static int lookup_fail, lookup_count, conversion_fail, long_names, unicode_name, empty_domain;
static char observed_sid[128];
static int ConvertStringSidToSidA(const char *text, PSID *sid) {
  if (strncmp(text, "S-", 2)) { last_error = 87; return 0; }
  snprintf(observed_sid, sizeof(observed_sid), "%s", text);
  *sid = malloc(1); return *sid != NULL;
}
static int LookupAccountSidW(const void *system, PSID sid, WCHAR *name, DWORD *nc,
    WCHAR *domain, DWORD *dc, SID_NAME_USE *use) {
  (void)system; (void)sid; (void)nc; (void)dc; (void)use;
  lookup_count++;
  if (lookup_fail) { last_error = ERROR_NONE_MAPPED; return 0; }
  if (long_names) {
    wmemset(name, L'a', 200); name[200] = 0;
    wmemset(domain, L'd', 200); domain[200] = 0;
  } else { wcscpy(name, unicode_name ? L"用户" : L"alice"); if (!empty_domain) wcscpy(domain, L"CORP"); }
  return 1;
}
static int WideCharToMultiByte(unsigned cp, unsigned flags, const WCHAR *wide,
    int length, char *out, int capacity, void *def, void *used) {
  (void)cp; (void)flags; (void)length; (void)def; (void)used;
  if (conversion_fail) { last_error = 1113; return 0; }
  if (wide[0] == L'用') { strcpy(out, "用户"); return 7; }
  size_t n = wcstombs(out, wide, (size_t)capacity);
  if (n == (size_t)-1 || n >= (size_t)capacity) { last_error = 122; return 0; }
  out[n] = 0; return (int)n + 1;
}
static DWORD GetLastError(void) { return last_error; }
static void LocalFree(PSID sid) { free(sid); }
#include "../src/preprocess/process_sid_account_win.h"
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"failed line %d\n",__LINE__); return 1; } } while (0)
int main(void) {
  EdrBehaviorRecord record = {0}, before;
  DWORD error;
  record.process_start_key = 12345;
  record.process_creation_filetime_100ns = 134067461411440000;
  record.pid = 9336; /* No process API exists in this test: PID is irrelevant. */
  strcpy(record.user_sid, "S-1-5-21-111-1001");
  strcpy(record.logon_id, "0x1234");
  strcpy(record.identity_source, "kernel_process_token");
  strcpy(record.identity_quality, "token_sid");
  before = record;
  CHECK(edr_process_snapshot_account_name(&record, &error) == 1);
  CHECK(!strcmp(observed_sid, before.user_sid));
  CHECK(!strcmp(record.username, "CORP\\alice"));
  CHECK(!strcmp(record.user_sid, before.user_sid) && !strcmp(record.logon_id, before.logon_id));
  CHECK(!strcmp(record.identity_quality, before.identity_quality));
  EdrBehaviorRecord identities = record;
  memset(identities.username, 0, sizeof(identities.username));
  memset(identities.domain, 0, sizeof(identities.domain));
  CHECK(!memcmp(&identities, &before, sizeof(identities)));
  CHECK(edr_process_snapshot_account_name(&record, &error) == 0 && lookup_count == 1);
  record = before; lookup_fail = 1;
  CHECK(edr_process_snapshot_account_name(&record, &error) == -1 && error == ERROR_NONE_MAPPED);
  CHECK(!memcmp(&record, &before, sizeof(record)));
  lookup_fail = 0; strcpy(record.identity_source, "creator_fallback");
  CHECK(edr_process_snapshot_account_name(&record, &error) == 0 && lookup_count == 2);
  record = before; conversion_fail = 1;
  CHECK(edr_process_snapshot_account_name(&record, &error) == -1 && error == 1113);
  CHECK(!memcmp(&record, &before, sizeof(record)));
  conversion_fail = 0; long_names = 1;
  CHECK(edr_process_snapshot_account_name(&record, &error) == -1 && error == ERROR_INSUFFICIENT_BUFFER);
  CHECK(!memcmp(&record, &before, sizeof(record)));
  long_names = 0;
  record = before; strcpy(record.user_sid, "invalid"); before = record;
  CHECK(edr_process_snapshot_account_name(&record, &error) == -1 && error == 87);
  CHECK(!memcmp(&record, &before, sizeof(record)));
  record = (EdrBehaviorRecord){0};
  strcpy(record.identity_source, "kernel_process_token");
  strcpy(record.identity_quality, "token_sid");
  strcpy(record.user_sid, "S-1-5-18");
  strcpy(record.creator_username, "OTHER\\bob");
  before = record;
  int prior_queries = lookup_count;
  CHECK(edr_process_snapshot_account_name(&record, &error) == 1);
  CHECK(!strcmp(record.username, "SYSTEM") && !strcmp(record.domain, "NT AUTHORITY") && lookup_count == prior_queries);
  CHECK(!strcmp(record.creator_username, before.creator_username));
  record = before; strcpy(record.user_sid, "S-1-5-21-111-1001"); unicode_name = 1;
  CHECK(edr_process_snapshot_account_name(&record, &error) == 1);
  CHECK(!strcmp(record.username, "CORP\\用户"));
  CHECK(!strcmp(record.creator_username, "OTHER\\bob"));
  record = before; strcpy(record.user_sid, "S-1-5-21-111-1001");
  unicode_name = 0; empty_domain = 1;
  CHECK(edr_process_snapshot_account_name(&record, &error) == 1);
  CHECK(!strcmp(record.username, "alice") && !record.domain[0]);
  puts("saved SID account enrichment passed");
  return 0;
}
