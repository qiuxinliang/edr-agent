#include "edr/time_util.h"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <time.h>
#endif

uint64_t edr_monotonic_ns(void) {
#ifdef _WIN32
  static LARGE_INTEGER freq;
  static int has_freq;
  LARGE_INTEGER c;
  if (!has_freq) {
    QueryPerformanceFrequency(&freq);
    has_freq = 1;
  }
  QueryPerformanceCounter(&c);
  return (uint64_t)((double)c.QuadPart / (double)freq.QuadPart * 1e9);
#else
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
    return 0;
  }
  return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
#endif
}
