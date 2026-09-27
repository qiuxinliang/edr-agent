#include "edr/etw_guids_win.h"
#include <winevt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Read the OS registration independently of the collector's constant. Enabling
 * an unregistered ETW GUID can succeed without delivering any WFAS events. */
int main(void) {
  EVT_HANDLE publisher = NULL;
  EVT_VARIANT *property = NULL;
  DWORD needed = 0, used = 0, error = ERROR_SUCCESS;
  const char *stage = "open WFAS publisher";
  int result = 1;

  publisher = EvtOpenPublisherMetadata(NULL,
      L"Microsoft-Windows-Windows Firewall With Advanced Security", NULL, 0, 0);
  if (!publisher) { error = GetLastError(); goto done; }
  stage = "size publisher GUID";
  if (EvtGetPublisherMetadataProperty(publisher, EvtPublisherMetadataPublisherGuid,
                                     0, 0, NULL, &needed)) {
    error = ERROR_INVALID_DATA; goto done;
  }
  error = GetLastError();
  if (error != ERROR_INSUFFICIENT_BUFFER) goto done;
  if (needed < sizeof(*property) || needed > 65536u) {
    error = ERROR_INVALID_DATA; goto done;
  }
  property = (EVT_VARIANT *)malloc(needed);
  if (!property) { error = ERROR_NOT_ENOUGH_MEMORY; goto done; }
  stage = "read publisher GUID";
  if (!EvtGetPublisherMetadataProperty(publisher, EvtPublisherMetadataPublisherGuid,
                                      0, needed, property, &used)) {
    error = GetLastError(); goto done;
  }
  stage = "compare collector GUID with Windows registration";
  if (property->Type != EvtVarTypeGuid || !property->GuidVal ||
      memcmp(property->GuidVal, &EDR_ETW_GUID_WINFIREWALL_WFAS, sizeof(GUID)) != 0) {
    error = ERROR_INVALID_DATA; goto done;
  }
  puts("PASS WFAS collector GUID matches the registered Windows provider");
  result = 0;
done:
  if (result) fprintf(stderr, "WFAS provider test failed: %s (error=%lu)\n",
                      stage, (unsigned long)error);
  free(property);
  if (publisher) EvtClose(publisher);
  return result;
}
