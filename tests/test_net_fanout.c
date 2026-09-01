/* 端侧网络扇出/扫描检测器核心逻辑单测(纯逻辑,跨平台)。 */

#include "edr/net_fanout_detector.h"
#include "edr/ave_sdk.h"
#include "edr/behavior_alert_emit.h"
#include "edr/behavior_record.h"
#include "edr/resource.h"
#include "edr/time_util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
static void set_env_value(const char *name, const char *value) {
  _putenv_s(name, value ? value : "");
}
#else
static void set_env_value(const char *name, const char *value) {
  setenv(name, value ? value : "", 1);
}
#endif

static unsigned s_emitted_alerts;
static AVEBehaviorAlert s_last_alert;

void edr_behavior_alert_emit_to_batch(const AVEBehaviorAlert *alert) {
  if (!alert) {
    return;
  }
  s_last_alert = *alert;
  s_emitted_alerts++;
}

bool edr_resource_preprocess_throttle_active(void) {
  return false;
}

uint64_t edr_monotonic_ns(void) {
  return 1000000000ULL;
}

static int fail(const char *m) {
  fprintf(stderr, "fail: %s\n", m);
  return 1;
}

static EdrNetFanoutState *mk(void) {
  EdrNetFanoutCfg c;
  memset(&c, 0, sizeof(c));
  c.window_s = 2;
  c.distinct_ip_threshold = 5;
  c.ports[0] = 445;
  c.ports[1] = 3389;
  c.n_ports = 2;
  return edr_net_fanout_state_create(&c);
}

/* 构造第 i 个不同 IP 字符串 */
static const char *ip(int i, char *buf) {
  sprintf(buf, "10.0.%d.%d", i / 256, i % 256);
  return buf;
}

static int test_detector_rejects_unrepresentable_alert_identity(void) {
  EdrBehaviorRecord record;
  memset(&record, 0, sizeof(record));
  record.type = EDR_EVENT_NET_CONNECT;
  record.pid = 4242u;
  record.net_dport = 445u;
  snprintf(record.net_dst, sizeof(record.net_dst), "%s", "198.51.100.10");
  snprintf(record.process_name, sizeof(record.process_name), "%s", "scanner.exe");
  memset(record.exe_path, 'x', sizeof(record.exe_path) - 1u);
  record.exe_path[sizeof(record.exe_path) - 1u] = '\0';

  set_env_value("EDR_NET_FANOUT_ENABLE", "1");
  set_env_value("EDR_NET_FANOUT_THRESHOLD", "1");
  set_env_value("EDR_NET_FANOUT_PORTS", "445");
  s_emitted_alerts = 0u;
  memset(&s_last_alert, 0, sizeof(s_last_alert));
  if (edr_net_fanout_init(NULL) != EDR_OK) {
    return fail("detector init failed");
  }

  edr_net_fanout_on_event(&record);
  if (s_emitted_alerts != 0u) {
    edr_net_fanout_shutdown();
    return fail("overlong process path must not produce a truncated alert");
  }

  snprintf(record.exe_path, sizeof(record.exe_path), "%s", "/usr/bin/scanner");
  snprintf(record.net_dst, sizeof(record.net_dst), "%s", "198.51.100.11");
  edr_net_fanout_on_event(&record);
  if (s_emitted_alerts != 1u || strcmp(s_last_alert.process_path, "/usr/bin/scanner") != 0) {
    edr_net_fanout_shutdown();
    return fail("losslessly representable process path must emit unchanged");
  }

  edr_net_fanout_shutdown();
  set_env_value("EDR_NET_FANOUT_ENABLE", "");
  set_env_value("EDR_NET_FANOUT_THRESHOLD", "");
  set_env_value("EDR_NET_FANOUT_PORTS", "");
  return 0;
}

int main(void) {
  char b[32];
  uint64_t t = 1000000000ull; /* 1s */

  /* 1) 达阈值命中:前 4 个不命中,第 5 个命中并返回 distinct=5 */
  {
    EdrNetFanoutState *s = mk();
    for (int i = 0; i < 4; i++) {
      if (edr_net_fanout_observe(s, 100, 445, ip(i, b), t) != 0) {
        return fail("should not hit before threshold");
      }
    }
    if (edr_net_fanout_observe(s, 100, 445, ip(4, b), t) != 5) {
      return fail("should hit at 5th distinct IP (return distinct=5)");
    }
    /* 冷却:再加更多同桶不再重复命中 */
    if (edr_net_fanout_observe(s, 100, 445, ip(5, b), t) != 0) {
      return fail("cooldown: no repeat alert in same window");
    }
    edr_net_fanout_state_destroy(s);
  }

  /* 2) 重复 IP 不增加 distinct */
  {
    EdrNetFanoutState *s = mk();
    for (int i = 0; i < 10; i++) {
      edr_net_fanout_observe(s, 1, 445, "1.1.1.1", t); /* 同一 IP 10 次 */
    }
    if (edr_net_fanout_observe(s, 1, 445, "1.1.1.2", t) != 0) {
      return fail("duplicate IPs must not inflate distinct (only 2 here)");
    }
    edr_net_fanout_state_destroy(s);
  }

  /* 3) 窗口过期重置:4 个后跨窗,再来不应立即命中(从 1 计) */
  {
    EdrNetFanoutState *s = mk();
    for (int i = 0; i < 4; i++) {
      edr_net_fanout_observe(s, 7, 445, ip(i, b), t);
    }
    uint64_t later = t + 3ull * 1000000000ull; /* 3s > window 2s */
    if (edr_net_fanout_observe(s, 7, 445, ip(100, b), later) != 0) {
      return fail("window expiry should reset distinct");
    }
    edr_net_fanout_state_destroy(s);
  }

  /* 4) 分键隔离:不同 pid / 不同 dport 不共享 */
  {
    EdrNetFanoutState *s = mk();
    for (int i = 0; i < 4; i++) {
      edr_net_fanout_observe(s, 200, 445, ip(i, b), t);
    }
    /* 同样 4 个 IP 但 pid 不同 / dport 不同,各自从头计,不应命中 */
    if (edr_net_fanout_observe(s, 201, 445, ip(0, b), t) != 0) {
      return fail("different pid must not share state");
    }
    if (edr_net_fanout_observe(s, 200, 3389, ip(0, b), t) != 0) {
      return fail("different dport must not share state");
    }
    edr_net_fanout_state_destroy(s);
  }

  /* 5) 非扫描端口不计(443 不在集合) */
  {
    EdrNetFanoutState *s = mk();
    for (int i = 0; i < 50; i++) {
      if (edr_net_fanout_observe(s, 9, 443, ip(i, b), t) != 0) {
        return fail("non-scan port (443) must never alert");
      }
    }
    edr_net_fanout_state_destroy(s);
  }

  /* 6) NULL/空 IP 安全 */
  if (edr_net_fanout_observe(NULL, 1, 445, "1.2.3.4", t) != 0) {
    return fail("null state must be safe");
  }
  if (test_detector_rejects_unrepresentable_alert_identity() != 0) {
    return 1;
  }

  printf("ok: net_fanout distinct/window/key-isolation/port-filter/cooldown/lossless-alert\n");
  return 0;
}
