/**
 * 最小化 AVE SDK 自检：AVE_Init / AVE_GetVersion / AVE_ScanFile（首个可选参数为待扫文件）。
 */
#include "edr/ave_sdk.h"

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <stdatomic.h>
#ifdef _WIN32
#include <windows.h>
static void pause_ms(void) { Sleep(1); }
#else
#include <time.h>
static void pause_ms(void) { struct timespec d = {0, 1000000L}; nanosleep(&d, NULL); }
#endif

static atomic_int s_block_callback;
static atomic_uint s_callbacks;
static void AVE_CALL on_behavior(const AVEBehaviorAlert *alert, void *user_data) {
  (void)user_data;
  assert(alert->pid >= 5000u && alert->pid <= 5020u);
  atomic_fetch_add(&s_callbacks, 1u);
  while (atomic_load(&s_block_callback)) pause_ms();
}

static void test_behavior_drain(void) {
  AVECallbacks callbacks = {0};
  AVEBehaviorEvent event = {0};
  AVEStatus status;
  callbacks.on_behavior_alert = on_behavior;
  assert(AVE_RegisterCallbacks(&callbacks) == AVE_OK);
  assert(AVE_StartBehaviorMonitor() == AVE_OK);
  event.event_type = AVE_EVT_LSASS_ACCESS;
  event.pid = 5000u;
  event.severity_hint = 255u;
  event.behavior_flags = UINT32_MAX;
  atomic_store(&s_block_callback, 1);
  assert(AVE_FeedEventEx(&event, sizeof(event)) == AVE_OK);
  for (unsigned i = 0; i < 5000u && !atomic_load(&s_callbacks); ++i) pause_ms();
  assert(atomic_load(&s_callbacks) == 1u);
  for (unsigned i = 1; i <= 20; ++i) {
    event.pid = 5000u + i;
    assert(AVE_FeedEventEx(&event, sizeof(event)) == AVE_OK);
  }
  assert(AVE_DrainBehaviorMonitor(5u) == AVE_ERR_TIMEOUT);
  assert(AVE_GetStatus(&status) == AVE_OK);
  assert(status.behavior_queue_enqueued == 21u);
  assert(status.behavior_worker_dequeued == 1u);
  assert(status.behavior_event_queue_size == 20);
  assert(AVE_FeedEventEx(&event, sizeof(event)) == AVE_ERR_NOT_INITIALIZED);
  assert(AVE_StartBehaviorMonitor() != AVE_OK);
  atomic_store(&s_block_callback, 0);
  assert(AVE_DrainBehaviorMonitor(5000u) == AVE_OK);
  assert(AVE_DrainBehaviorMonitor(0u) == AVE_OK);
  assert(AVE_GetStatus(&status) == AVE_OK);
  assert(status.behavior_worker_dequeued == 21u);
  assert(status.behavior_event_queue_size == 0);
  assert(!status.behavior_monitor_running);
  assert(atomic_load(&s_callbacks) == 21u);
}

int main(int argc, char **argv) {
  AVEConfig cfg = {0};
  cfg.max_concurrent_scans = 2;
  cfg.behavior_monitor_enabled = true;

  int r = AVE_Init(&cfg);
  if (r != AVE_OK) {
    fprintf(stderr, "AVE_Init failed: %d\n", r);
    return 1;
  }

  printf("AVE_GetVersion: %s\n", AVE_GetVersion());

  if (argc > 1) {
    AVEScanResult res;
    r = AVE_ScanFile(argv[1], &res);
    printf("AVE_ScanFile -> %d final_verdict=%d confidence=%.4f path=%s\n", r, (int)res.final_verdict,
           res.final_confidence, res.scanned_path);
  }

  test_behavior_drain();
  AVE_Shutdown();
  assert(AVE_Init(&cfg) == AVE_OK);
  AVE_Shutdown();
  return 0;
}
