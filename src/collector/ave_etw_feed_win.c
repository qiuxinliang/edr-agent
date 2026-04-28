/**
 * Windows ETW → AVE 行为管线（可设 EDR_AVE_ETW_FEED=0 关闭）。
 * A3.2：`EDR_AVE_ETW_ASYNC=1` 时经内部队列+工作线程 `AVE_FeedEvent`，默认关（**与 TDH/总线解耦**；terminate 不走路径）。
 */

#if !defined(_WIN32)
#error ave_etw_feed_win.c is Windows-only
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <guiddef.h>
#include <basetsd.h>
#include <initguid.h>

#include <evntcons.h>

#include "ave_etw_feed_win.h"

#include "edr/ave_sdk.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* A3：对 AVE_FeedEvent 可 1/N 分频（不作用于 TDH/总线；terminate 仍总是 NotifyProcessExit） */
static int edr_ave_feed_every_n_skip(void) {
  const char *e = getenv("EDR_AVE_ETW_FEED_EVERY_N");
  if (!e || !e[0]) {
    return 0;
  }
  char *end = NULL;
  unsigned long n = strtoul(e, &end, 10);
  (void)end;
  if (n <= 1u) {
    return 0;
  }
  static volatile LONG s_tick;
  LONG v = InterlockedIncrement(&s_tick);
  if ((unsigned long)(v - 1) % n != 0u) {
    return 1;
  }
  return 0;
}

/* ---- A3.2：ETW 回调内仅入队，工作线程 `AVE_FeedEvent`；队列满时回退为同步，避免零喂入。 ---- */
#define EDR_AVE_ASYNC_CAP 256u

static INIT_ONCE s_ave_once = INIT_ONCE_STATIC_INIT;
static CRITICAL_SECTION s_ave_cs;
static HANDLE s_ave_sem; /* 待消费条数 */
static HANDLE s_ave_thread;
static volatile LONG s_ave_ok; /* 1=异步可用 */

static AVEBehaviorEvent s_ave_ring[EDR_AVE_ASYNC_CAP];
static uint32_t s_ave_head; /* 读位置 */
static uint32_t s_ave_count;

static int edr_ave_async_wanted(void) {
  const char *e = getenv("EDR_AVE_ETW_ASYNC");
  if (!e || !e[0]) {
    return 0;
  }
  if (e[0] == '0') {
    return 0;
  }
  if (e[0] == '1' && e[1] == '\0') {
    return 1;
  }
  if (_stricmp(e, "true") == 0 || _stricmp(e, "yes") == 0) {
    return 1;
  }
  return 0;
}

static DWORD WINAPI edr_ave_async_thread(void *arg) {
  (void)arg;
  for (;;) {
    DWORD w = WaitForSingleObject(s_ave_sem, INFINITE);
    if (w != WAIT_OBJECT_0) {
      continue;
    }
    AVEBehaviorEvent ev;
    memset(&ev, 0, sizeof(ev));
    EnterCriticalSection(&s_ave_cs);
    if (s_ave_count == 0u) {
      LeaveCriticalSection(&s_ave_cs);
      continue;
    }
    ev = s_ave_ring[s_ave_head % EDR_AVE_ASYNC_CAP];
    s_ave_head = (s_ave_head + 1u) % EDR_AVE_ASYNC_CAP;
    s_ave_count--;
    LeaveCriticalSection(&s_ave_cs);
    AVE_FeedEvent(&ev);
  }
  /* not reached */
  /* return 0; */
}

static BOOL WINAPI edr_ave_init_once_fn(PINIT_ONCE pOnce, PVOID arg, PVOID *pContext) {
  (void)pOnce;
  (void)arg;
  (void)pContext;
  InitializeCriticalSection(&s_ave_cs);
  s_ave_sem = CreateSemaphoreW(NULL, 0, (LONG)EDR_AVE_ASYNC_CAP, NULL);
  if (!s_ave_sem) {
    DeleteCriticalSection(&s_ave_cs);
    s_ave_ok = 0;
    return TRUE; /* 仍使 InitOnce 置完成，之后走同步回退；勿返回 FALSE（会使 INIT_ONCE 未定义） */
  }
  s_ave_thread = CreateThread(NULL, 0, edr_ave_async_thread, NULL, 0, NULL);
  if (!s_ave_thread) {
    (void)CloseHandle(s_ave_sem);
    s_ave_sem = NULL;
    DeleteCriticalSection(&s_ave_cs);
    s_ave_ok = 0;
    return TRUE;
  }
  s_ave_ok = 1;
  return TRUE;
}

static int edr_ave_async_try_enqueue(const AVEBehaviorEvent *ev) {
  InitOnceExecuteOnce(&s_ave_once, edr_ave_init_once_fn, NULL, NULL);
  if (!s_ave_ok) {
    return 0;
  }
  int ok = 0;
  EnterCriticalSection(&s_ave_cs);
  if (s_ave_count < EDR_AVE_ASYNC_CAP) {
    uint32_t t = s_ave_head + s_ave_count;
    s_ave_ring[t % EDR_AVE_ASYNC_CAP] = *ev;
    s_ave_count++;
    ok = 1;
  }
  LeaveCriticalSection(&s_ave_cs);
  if (ok) {
    (void)ReleaseSemaphore(s_ave_sem, 1, NULL);
  }
  return ok;
}

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
  if (edr_ave_feed_every_n_skip()) {
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
    case EDR_EVENT_FILE_READ:
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

  if (edr_ave_async_wanted()) {
    if (edr_ave_async_try_enqueue(&ev)) {
      return;
    }
  }
  AVE_FeedEvent(&ev);
}
