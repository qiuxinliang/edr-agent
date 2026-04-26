/**
 * A4.4 二期：有界 SPSC+信号量+CS。见 ADR。`edr_collector_decode_from_a44_item` 在 collector_win.c。
 */
#if !defined(_WIN32)
void edr_a44_split_path_win_c_only_non_win(void) {}
#else

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <process.h>
#include <windows.h>

#include "edr/edr_a44_split_path_win.h"
#include "edr/event_bus.h"
#include "edr/error.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void edr_collector_decode_from_a44_item(const EdrA44QueueItem *it);

#ifndef EDR_A44_QUEUE_CAP
#define EDR_A44_QUEUE_CAP 512u
#endif

static int edr_a44_yes(const char *e) {
  if (!e || !e[0]) {
    return 0;
  }
  if (e[0] == '1' && e[1] == 0) {
    return 1;
  }
  {
    int a = (e[0] | 32);
    return a == (int)'y' || a == (int)'t';
  }
}

int edr_a44_split_path_enabled(void) { return edr_a44_yes(getenv("EDR_A44_SPLIT_PATH")); }

int edr_a44_item_pack(PEVENT_RECORD r, uint64_t ts_ns, EdrEventType ty, const char *tag, EdrA44QueueItem *out,
                      int *reason_sync) {
  if (!r || !out) {
    return -1;
  }
  if (reason_sync) {
    *reason_sync = 0;
  }
  if (r->ExtendedDataCount != 0) {
    if (reason_sync) {
      *reason_sync = 1;
    }
    return 1;
  }
  if (r->UserDataLength > (USHORT)EDR_A44_MAX_USERDATA) {
    if (reason_sync) {
      *reason_sync = 2;
    }
    return 1;
  }
  memset(out, 0, sizeof(*out));
  out->ts_ns = ts_ns;
  out->ty = ty;
  if (tag) {
    snprintf(out->tag, sizeof(out->tag), "%s", tag);
  }
  memcpy(&out->evh, &r->EventHeader, sizeof(out->evh));
  out->udlen = r->UserDataLength;
  out->edcount = 0;
  out->buffer_context = r->BufferContext;
  if (r->UserData && r->UserDataLength > 0) {
    memcpy(out->ud, r->UserData, (size_t)r->UserDataLength);
  }
  return 0;
}

void edr_a44_item_to_event_record(const EdrA44QueueItem *it, EVENT_RECORD *er) {
  if (!it || !er) {
    return;
  }
  memset(er, 0, sizeof(*er));
  memcpy(&er->EventHeader, &it->evh, sizeof(er->EventHeader));
  er->UserDataLength = it->udlen;
  er->ExtendedDataCount = 0;
  er->BufferContext = it->buffer_context;
  er->UserData = (PVOID)it->ud;
  er->ExtendedData = NULL;
}

static CRITICAL_SECTION s_a44_lock;
static EdrA44QueueItem s_a44_buf[EDR_A44_QUEUE_CAP];
static uint32_t s_a44_head, s_a44_tail;
static HANDLE s_a44_hFree, s_a44_hData;
static HANDLE s_a44_thr;
static volatile LONG s_a44_life; /* 1=run 0=stop */
static volatile LONG64 s_a44_drop; /* 满队时回退同线程 或 弃标 */

static void edr_a44_decode_one_popped(EdrA44QueueItem *it) { edr_collector_decode_from_a44_item(it); }

static void edr_a44_pop_and_decode_one(void) {
  EnterCriticalSection(&s_a44_lock);
  EdrA44QueueItem it = s_a44_buf[s_a44_head % EDR_A44_QUEUE_CAP];
  s_a44_head = (s_a44_head + 1u) % EDR_A44_QUEUE_CAP;
  LeaveCriticalSection(&s_a44_lock);
  (void)ReleaseSemaphore(s_a44_hFree, 1, NULL);
  edr_a44_decode_one_popped(&it);
}

static unsigned __stdcall edr_a44_decode_trampoline(void *arg) {
  (void)arg;
  for (;;) {
    DWORD w = WaitForSingleObject(s_a44_hData, 80);
    if (w == WAIT_OBJECT_0) {
      edr_a44_pop_and_decode_one();
    }
    if (InterlockedCompareExchange(&s_a44_life, 0, 0) == 0) {
      /* 退停：etw 已收束后，尽力排空剩余槽（非阻塞取 Data） */
      for (;;) {
        w = WaitForSingleObject(s_a44_hData, 0);
        if (w != WAIT_OBJECT_0) {
          break;
        }
        edr_a44_pop_and_decode_one();
      }
      break;
    }
  }
  return 0u;
}

EdrError edr_a44_split_path_start(EdrEventBus *bus) {
  (void)bus;
  if (!edr_a44_split_path_enabled()) {
    return EDR_OK;
  }
  if (s_a44_thr) {
    return EDR_OK;
  }
  InitializeCriticalSection(&s_a44_lock);
  s_a44_head = 0u;
  s_a44_tail = 0u;
  s_a44_life = 1;
  s_a44_hFree = CreateSemaphoreW(NULL, (LONG)EDR_A44_QUEUE_CAP, (LONG)EDR_A44_QUEUE_CAP, NULL);
  s_a44_hData = CreateSemaphoreW(NULL, 0, (LONG)EDR_A44_QUEUE_CAP, NULL);
  if (!s_a44_hFree || !s_a44_hData) {
    DeleteCriticalSection(&s_a44_lock);
    return EDR_ERR_INTERNAL;
  }
  s_a44_thr = (HANDLE)_beginthreadex(NULL, 0, edr_a44_decode_trampoline, NULL, 0, NULL);
  if (!s_a44_thr) {
    CloseHandle(s_a44_hFree);
    CloseHandle(s_a44_hData);
    s_a44_hFree = s_a44_hData = NULL;
    DeleteCriticalSection(&s_a44_lock);
    return EDR_ERR_INTERNAL;
  }
  (void)fprintf(stderr, "[collector_win] A4.4 split: decode thread started (cap=%u)\n", (unsigned)EDR_A44_QUEUE_CAP);
  return EDR_OK;
}

int edr_a44_try_push(const EdrA44QueueItem *it) {
  if (!it || !s_a44_thr || s_a44_life == 0) {
    return 0;
  }
  if (WaitForSingleObject(s_a44_hFree, 0) != WAIT_OBJECT_0) {
    (void)InterlockedAdd64(&s_a44_drop, 1);
    return 0;
  }
  EnterCriticalSection(&s_a44_lock);
  s_a44_buf[s_a44_tail % EDR_A44_QUEUE_CAP] = *it;
  s_a44_tail = (s_a44_tail + 1u) % EDR_A44_QUEUE_CAP;
  LeaveCriticalSection(&s_a44_lock);
  (void)ReleaseSemaphore(s_a44_hData, 1, NULL);
  return 1;
}

uint64_t edr_a44_dropped_total(void) { return (uint64_t)s_a44_drop; }

void edr_a44_split_path_stop(void) {
  if (!s_a44_thr) {
    return;
  }
  (void)InterlockedExchange(&s_a44_life, 0);
  (void)ReleaseSemaphore(s_a44_hData, 1, NULL);
  (void)WaitForSingleObject(s_a44_thr, 25000);
  CloseHandle(s_a44_thr);
  s_a44_thr = NULL;
  if (s_a44_hFree) {
    CloseHandle(s_a44_hFree);
  }
  if (s_a44_hData) {
    CloseHandle(s_a44_hData);
  }
  s_a44_hFree = s_a44_hData = NULL;
  DeleteCriticalSection(&s_a44_lock);
  (void)fprintf(stderr, "[collector_win] A4.4 split: decode joined (a44_drop=%" PRId64 ")\n", (int64_t)s_a44_drop);
}

#endif
