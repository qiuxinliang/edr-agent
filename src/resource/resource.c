/* §12 资源限制 — CPU/内存粗采样与超限告警 */

#include "edr/resource.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <sys/resource.h>
#include <sys/time.h>
#include <unistd.h>
#endif

static const EdrConfig *s_cfg;
static unsigned long s_emergency;
/** 1：预处理应跳过低优先级（AGT-010；POSIX 由 resource_poll 置位） */
static int s_preprocess_throttle;
static struct {
#ifndef _WIN32
  struct timeval wall;
  struct rusage ru;
#else
  /* MSVC C 不允许零成员 struct；仅占位 */
  unsigned char _unused;
#endif
} s_last;

static void sample_init(void) {
#ifndef _WIN32
  gettimeofday(&s_last.wall, NULL);
  getrusage(RUSAGE_SELF, &s_last.ru);
#endif
}

void edr_resource_init(const EdrConfig *cfg) {
  s_cfg = cfg;
  s_emergency = 0;
  s_preprocess_throttle = 0;
  sample_init();
}

void edr_resource_shutdown(void) { s_cfg = NULL; }

unsigned long edr_resource_emergency_count(void) { return s_emergency; }

bool edr_resource_preprocess_throttle_active(void) {
  const char *force = getenv("EDR_PREPROCESS_THROTTLE");
  if (force && force[0] == '1') {
    return true;
  }
#ifndef _WIN32
  return s_preprocess_throttle != 0;
#else
  return false;
#endif
}

void edr_resource_poll(void) {
  if (!s_cfg || s_cfg->resource_limit.cpu_limit_percent == 0u) {
    return;
  }
  /* 默认 TOML 中 cpu_limit_percent=1 仅作占位，避免无意义刷屏；需严格监控时设 EDR_RESOURCE_STRICT=1 */
  if (s_cfg->resource_limit.cpu_limit_percent < 5u) {
    const char *st = getenv("EDR_RESOURCE_STRICT");
    if (!st || st[0] != '1') {
      return;
    }
  }

#ifndef _WIN32
  struct timeval now;
  struct rusage ru;
  gettimeofday(&now, NULL);
  getrusage(RUSAGE_SELF, &ru);

  double wall_s = (double)(now.tv_sec - s_last.wall.tv_sec) +
                  (double)(now.tv_usec - s_last.wall.tv_usec) / 1e6;
  if (wall_s < 0.5) {
    return;
  }

  double ut = (double)(ru.ru_utime.tv_sec - s_last.ru.ru_utime.tv_sec) +
              (double)(ru.ru_utime.tv_usec - s_last.ru.ru_utime.tv_usec) / 1e6;
  double st = (double)(ru.ru_stime.tv_sec - s_last.ru.ru_stime.tv_sec) +
              (double)(ru.ru_stime.tv_usec - s_last.ru.ru_stime.tv_usec) / 1e6;
  double cpu_frac = (ut + st) / wall_s;
  unsigned pct = (unsigned)(cpu_frac * 100.0);
  long rss = ru.ru_maxrss;

  s_last.wall = now;
  s_last.ru = ru;

  bool cpu_bad = pct > s_cfg->resource_limit.cpu_limit_percent &&
                 pct > s_cfg->resource_limit.emergency_cpu_limit;
  bool mem_bad = false;
  unsigned long rss_mb = 0;

  if (s_cfg->resource_limit.memory_limit_mb > 0u) {
#if defined(__APPLE__)
    rss_mb = (unsigned long)rss / (1024ul * 1024ul);
#else
    rss_mb = (unsigned long)rss / 1024ul;
#endif
    if (rss_mb > (unsigned long)s_cfg->resource_limit.memory_limit_mb) {
      mem_bad = true;
      fprintf(stderr, "[resource] RSS 约 %lu MB 超过 memory_limit_mb=%u\n", rss_mb,
              s_cfg->resource_limit.memory_limit_mb);
    }
  }

  if (cpu_bad) {
    s_emergency++;
    fprintf(stderr, "[resource] CPU 约 %u%% 超过上限 %u%%（emergency=%lu）\n", pct,
            s_cfg->resource_limit.cpu_limit_percent, s_emergency);
    s_preprocess_throttle = 1;
  } else if (mem_bad) {
    s_preprocess_throttle = 1;
  } else {
    s_preprocess_throttle = 0;
  }
#else
  (void)s_cfg;
#endif
}
