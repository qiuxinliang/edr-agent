#include "edr/config.h"
#include "edr/resource.h"

#include <assert.h>
#include <stdint.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
static void wait_for_sample_window(void) { Sleep(650); }
#else
#include <time.h>
static void wait_for_sample_window(void) {
  struct timespec delay = {0, 650000000L};
  nanosleep(&delay, NULL);
}
#endif

int main(void) {
  EdrConfig cfg;
  EdrResourceSample first;
  EdrResourceSample after_same_config;
  EdrResourceSample after_reenable;

  memset(&cfg, 0, sizeof(cfg));
  cfg.resource_limit.cpu_limit_percent = 80u;
  cfg.resource_limit.emergency_cpu_limit = 95u;

  edr_resource_init(&cfg);
  wait_for_sample_window();
  edr_resource_poll();
  edr_resource_get_sample(&first);
  assert(first.sample_count == 1u);
  assert(first.sampler_reset_count == 1u);
  assert(first.process_id != 0u);
  assert(first.logical_processor_count != 0u);
  assert(first.cpu_sample_window_ms >= 500u);
  assert(first.cpu_avg_10s_x100 <= first.cpu_max_60s_x100);
  assert(first.cpu_avg_60s_x100 <= first.cpu_max_60s_x100);

  edr_resource_reconfigure(&cfg);
  wait_for_sample_window();
  edr_resource_poll();
  edr_resource_get_sample(&after_same_config);
  assert(after_same_config.sample_count == first.sample_count + 1u);
  assert(after_same_config.sampler_reset_count == first.sampler_reset_count);
#ifdef _WIN32
  assert(after_same_config.thread_sample_count == first.thread_sample_count);
  assert(after_same_config.thread_sample_age_ms >= 500u);
#endif

  cfg.resource_limit.cpu_limit_percent = 0u;
  edr_resource_reconfigure(&cfg);
  cfg.resource_limit.cpu_limit_percent = 80u;
  edr_resource_reconfigure(&cfg);
  edr_resource_get_sample(&after_reenable);
  assert(after_reenable.sample_count == after_same_config.sample_count);
  assert(after_reenable.sampler_reset_count == first.sampler_reset_count + 1u);

  edr_resource_shutdown();
  return 0;
}
