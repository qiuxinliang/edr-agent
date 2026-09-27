#ifndef EDR_PROCESS_START_TOKEN_WIN_H
#define EDR_PROCESS_START_TOKEN_WIN_H

#include <windows.h>
#include <sddl.h>
#include <stdlib.h>
#include "edr/behavior_record.h"
#include "edr/process_generation.h"
#include "edr/windows_file_identity.h"
#include "etw_slot_text.h"

/* Snapshot only the startup SID/LUID using the ProcessStart handle already
 * validated by the collector. No PID reopen, account lookup, or asynchronous
 * work runs here. Return -1 for envelope capacity loss, 0 for unavailable. */
static int edr_process_start_token_capture(HANDLE process,
    const EdrLiveProcessGeneration *live, const EdrBehaviorRecord *source,
    EdrEventSlot *slot) {
  FILETIME created, exited, kernel, user;
  HANDLE token = NULL;
  TOKEN_USER *owner = NULL;
  TOKEN_STATISTICS stats;
  DWORD bytes = 0u;
  LPSTR sid = NULL;
  char path[EDR_BR_STR_LONG], logon[32];
  int result = 0;
  size_t original_length;
  uint32_t original_size;
  if (!slot) return 0;
  slot->process_token_snapshot_pid = 0u;
  slot->process_token_snapshot_start_key = 0u;
  slot->process_token_snapshot_creation_filetime_100ns = 0u;
  slot->process_token_snapshot_truncated = 0u;
  if (!process || !live || !source || source->type != EDR_EVENT_PROCESS_CREATE ||
      source->is_security_4688 || !source->pid || live->pid != source->pid ||
      !live->process_start_key || !source->process_creation_filetime_100ns ||
      live->creation_filetime_100ns != source->process_creation_filetime_100ns ||
      (source->process_start_key && source->process_start_key != live->process_start_key) ||
      !source->image_path_canonical[0] ||
      !GetProcessTimes(process, &created, &exited, &kernel, &user) ||
      (((uint64_t)created.dwHighDateTime << 32u) | created.dwLowDateTime) !=
          live->creation_filetime_100ns ||
      GetProcessId(process) != live->pid ||
      !edr_windows_process_image_path_utf8(process, path, sizeof(path)) ||
      edr_windows_utf8_path_compare_ci(path, source->image_path_canonical) !=
          EDR_WINDOWS_UTF8_PATH_COMPARE_MATCH ||
      !OpenProcessToken(process, TOKEN_QUERY, &token)) return 0;
  (void)GetTokenInformation(token, TokenUser, NULL, 0u, &bytes);
  if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || !bytes || bytes > 65536u) goto done;
  owner = (TOKEN_USER *)malloc(bytes);
  if (!owner || !GetTokenInformation(token, TokenUser, owner, bytes, &bytes) ||
      !IsValidSid(owner->User.Sid) || !ConvertSidToStringSidA(owner->User.Sid, &sid) ||
      !GetTokenInformation(token, TokenStatistics, &stats, sizeof(stats), &bytes)) goto done;
  snprintf(logon, sizeof(logon), "0x%llx",
      (unsigned long long)(((uint64_t)(uint32_t)stats.AuthenticationId.HighPart << 32u) |
                           stats.AuthenticationId.LowPart));
  original_length = strnlen((const char *)slot->data, sizeof(slot->data));
  original_size = slot->size;
  if (edr_collector_slot_append_kv(slot, "user_sid", sid) != EDR_SLOT_KV_APPENDED ||
      edr_collector_slot_append_kv(slot, "logon_id", logon) != EDR_SLOT_KV_APPENDED) {
    /* Never publish half a tuple. Keep the loss on this exact slot even when
     * there is no space for textual truncation metadata. */
    if (original_length < sizeof(slot->data)) slot->data[original_length] = '\0';
    slot->size = original_size;
    slot->process_token_snapshot_truncated = 1u;
    result = -1;
    goto done;
  }
  slot->process_token_snapshot_pid = live->pid;
  slot->process_token_snapshot_start_key = live->process_start_key;
  slot->process_token_snapshot_creation_filetime_100ns = live->creation_filetime_100ns;
  result = 1;
done:
  if (sid) LocalFree(sid);
  free(owner);
  CloseHandle(token);
  return result;
}
#endif
