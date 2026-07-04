#include "edr/ave_sdk.h"
#include "edr/ave_cross_engine_feed.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_feed_count;
static AVEBehaviorEvent g_last_event;

AVE_EXPORT void AVE_CALL AVE_FeedEvent(const AVEBehaviorEvent *event) {
  assert(event != NULL);
  g_last_event = *event;
  g_feed_count++;
}

static void reset_capture(void) {
  memset(&g_last_event, 0, sizeof(g_last_event));
  g_feed_count = 0;
}

static void test_rejects_pid_only_process_create(void) {
  EdrBehaviorRecord r;
  edr_behavior_record_init(&r);
  r.type = EDR_EVENT_PROCESS_CREATE;
  r.pid = 4242u;

  reset_capture();
  edr_ave_cross_engine_feed_from_record(&r);
  assert(g_feed_count == 0);
}

static void test_accepts_enriched_process_create(void) {
  EdrBehaviorRecord r;
  edr_behavior_record_init(&r);
  r.type = EDR_EVENT_PROCESS_CREATE;
  r.pid = 4243u;
  r.ppid = 100u;
  snprintf(r.process_name, sizeof(r.process_name), "%s", "powershell.exe");
  snprintf(r.exe_path, sizeof(r.exe_path), "%s", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");
  snprintf(r.cmdline, sizeof(r.cmdline), "%s", "powershell.exe -NoP -Command hostname");

  reset_capture();
  edr_ave_cross_engine_feed_from_record(&r);
  assert(g_feed_count == 1);
  assert(g_last_event.pid == 4243u);
  assert(g_last_event.ppid == 100u);
  assert(g_last_event.event_type == AVE_EVT_PROCESS_CREATE);
  assert(strstr(g_last_event.target_path, "powershell.exe") != NULL);
}

static void test_rejects_file_without_process_identity(void) {
  EdrBehaviorRecord r;
  edr_behavior_record_init(&r);
  r.type = EDR_EVENT_FILE_WRITE;
  r.pid = 5000u;
  snprintf(r.file_path, sizeof(r.file_path), "%s", "C:\\Users\\test\\AppData\\Local\\Temp\\a.tmp");

  reset_capture();
  edr_ave_cross_engine_feed_from_record(&r);
  assert(g_feed_count == 0);
}

static void test_accepts_enriched_file_signal(void) {
  EdrBehaviorRecord r;
  edr_behavior_record_init(&r);
  r.type = EDR_EVENT_FILE_WRITE;
  r.pid = 5001u;
  snprintf(r.process_name, sizeof(r.process_name), "%s", "powershell.exe");
  snprintf(r.exe_path, sizeof(r.exe_path), "%s", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");
  snprintf(r.file_path, sizeof(r.file_path), "%s", "C:\\Users\\test\\AppData\\Local\\Temp\\note.locked");
  snprintf(r.file_op, sizeof(r.file_op), "%s", "write");

  reset_capture();
  edr_ave_cross_engine_feed_from_record(&r);
  assert(g_feed_count == 1);
  assert(g_last_event.event_type == AVE_EVT_FILE_WRITE);
  assert(strstr(g_last_event.target_path, "note.locked") != NULL);
  assert(g_last_event.suspicious_extension_burst == 1u);
}

int main(void) {
  test_rejects_pid_only_process_create();
  test_accepts_enriched_process_create();
  test_rejects_file_without_process_identity();
  test_accepts_enriched_file_signal();
  puts("ave_cross_engine_feed_quality ok");
  return 0;
}
