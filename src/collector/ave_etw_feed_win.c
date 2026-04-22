/**
 * Windows ETW → AVE 行为管线（可设 EDR_AVE_ETW_FEED=0 关闭）。
 */

#if !defined(_WIN32)
#error ave_etw_feed_win.c is Windows-only
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <evntcons.h>

#include "ave_etw_feed_win.h"

#include "edr/ave_sdk.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void edr_ave_etw_feed_from_event(PEVENT_RECORD rec, EdrEventType ty, uint64_t ts_ns,
                                 const char *opt_target_ip, const char *opt_target_domain) {
  const char *e = getenv("EDR_AVE_ETW_FEED");
  if (e && e[0] == '0') {
    return;
  }
  if (!rec) {
    return;
  }
  if (ty == EDR_EVENT_PROCESS_TERMINATE) {
    AVE_NotifyProcessExit((uint32_t)rec->EventHeader.ProcessId);
    return;
  }

  AVEBehaviorEvent ev;
  memset(&ev, 0, sizeof(ev));
  ev.pid = (uint32_t)rec->EventHeader.ProcessId;
  ev.timestamp_ns = (int64_t)ts_ns;
  ev.severity_hint = (ty == EDR_EVENT_SCRIPT_POWERSHELL || ty == EDR_EVENT_AUTH_FAILED) ? (uint8_t)0
                                                                                        : (uint8_t)1;

  switch (ty) {
    case EDR_EVENT_PROCESS_CREATE:
      ev.event_type = AVE_EVT_PROCESS_CREATE;
      break;
    case EDR_EVENT_PROCESS_INJECT:
      ev.event_type = AVE_EVT_PROCESS_INJECT;
      break;
    case EDR_EVENT_DLL_LOAD:
    case EDR_EVENT_DRIVER_LOAD:
      ev.event_type = AVE_EVT_DLL_LOAD;
      break;
    case EDR_EVENT_FILE_WRITE:
    case EDR_EVENT_FILE_CREATE:
    case EDR_EVENT_FILE_DELETE:
    case EDR_EVENT_FILE_RENAME:
      ev.event_type = AVE_EVT_FILE_WRITE;
      break;
    case EDR_EVENT_NET_CONNECT:
    case EDR_EVENT_NET_LISTEN:
      ev.event_type = AVE_EVT_NET_CONNECT;
      break;
    case EDR_EVENT_NET_DNS_QUERY:
      ev.event_type = AVE_EVT_NET_DNS;
      break;
    case EDR_EVENT_REG_CREATE_KEY:
    case EDR_EVENT_REG_SET_VALUE:
    case EDR_EVENT_REG_DELETE_KEY:
      ev.event_type = AVE_EVT_REG_WRITE;
      break;
    case EDR_EVENT_AUTH_LOGIN:
    case EDR_EVENT_AUTH_FAILED:
    case EDR_EVENT_AUTH_LOGOUT:
    case EDR_EVENT_AUTH_PRIVILEGE_ESC:
      ev.event_type = AVE_EVT_AUTH_EVENT;
      break;
    case EDR_EVENT_SCRIPT_POWERSHELL:
    case EDR_EVENT_SCRIPT_WMI:
      ev.event_type = AVE_EVT_PROCESS_CREATE;
      break;
    default:
      ev.event_type = AVE_EVT_PROCESS_CREATE;
      break;
  }

  if (opt_target_ip && opt_target_ip[0]) {
    snprintf(ev.target_ip, sizeof(ev.target_ip), "%s", opt_target_ip);
  }
  if (opt_target_domain && opt_target_domain[0]) {
    snprintf(ev.target_domain, sizeof(ev.target_domain), "%s", opt_target_domain);
  }

  AVE_FeedEvent(&ev);
}
