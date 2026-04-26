/**
 * A1：ETW 回调/分桶/空载荷 可观测，见 include/edr/etw_observability_win.h
 * P2：同口径一行可追加到 `EDR_ETW_OBS_EXPORT_PATH`（与 stderr [etw_obs] 同内容），便于 SRE/远端采集。
 */
#if !defined(_WIN32)
#error etw_observability_win.c is Windows-only
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include "edr/etw_observability_win.h"
#include "edr/edr_a44_split_path_win.h"
#include "edr/event_bus.h"
#include "edr/etw_tdh_win.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define EDR_ETW_OBS_NTAG 12

static volatile LONG64 s_etw_callback_total;
static volatile LONG64 s_by_tag[EDR_ETW_OBS_NTAG];
static volatile LONG64 s_slot_payload_empty;

/* A4.4 第一期：单线程消费者回调内 3 段 QPC 累计 + 次计数（= EDR_A44_CB_PHASE_MEAS 1） */
static volatile LONG64 s_a44_ph_ns[3];
static volatile LONG64 s_a44_ph_cnt[3];

int edr_etw_observability_a44_cb_phase_meas_enabled(void) {
  static int s_init, s_on;
  if (!s_init) {
    const char *e = getenv("EDR_A44_CB_PHASE_MEAS");
    s_on = (e && (e[0] == '1' || (e[0] | 32) == 'y' || (e[0] | 32) == 't')) ? 1 : 0;
    s_init = 1;
  }
  return s_on;
}

void edr_etw_observability_add_a44_phase_ns(unsigned phase, int64_t ns) {
  if (phase > 2u) {
    return;
  }
  if (ns < 0) {
    return;
  }
  (void)InterlockedAdd64(&s_a44_ph_ns[phase], ns);
  (void)InterlockedAdd64(&s_a44_ph_cnt[phase], 1);
}

static int edr_tag_bucket(const char *t) {
  if (!t) {
    return 10;
  }
  if (strcmp(t, "kproc") == 0) {
    return 0;
  }
  if (strcmp(t, "kfile") == 0) {
    return 1;
  }
  if (strcmp(t, "knet") == 0) {
    return 2;
  }
  if (strcmp(t, "kreg") == 0) {
    return 3;
  }
  if (strcmp(t, "dns") == 0) {
    return 4;
  }
  if (strcmp(t, "ps") == 0) {
    return 5;
  }
  if (strcmp(t, "sec") == 0) {
    return 6;
  }
  if (strcmp(t, "wmi") == 0) {
    return 7;
  }
  if (strcmp(t, "tcpip") == 0) {
    return 8;
  }
  if (strcmp(t, "wf") == 0) {
    return 9;
  }
  if (strcmp(t, "unk") == 0) {
    return 10;
  }
  return 11;
}

void edr_etw_observability_on_callback(const char *prov_tag) {
  (void)InterlockedAdd64(&s_etw_callback_total, 1);
  (void)InterlockedAdd64(&s_by_tag[edr_tag_bucket(prov_tag)], 1);
}

void edr_etw_observability_on_slot_payload_empty(void) {
  (void)InterlockedAdd64(&s_slot_payload_empty, 1);
}

/* 将当前累计指标打印到 `out`；末尾带换行。与 stderr [etw_obs] 行一致。 */
static void edr_etw_observability_fprint(const EdrEventBus *bus, FILE *out) {
  if (!bus || !out) {
    return;
  }
  int64_t tdh_err = 0, tdh_ok = 0;
  edr_tdh_win_get_property_stats(&tdh_err, &tdh_ok);
  int64_t tdh_denom = tdh_err + tdh_ok;
  int pct = 0;
  if (tdh_denom > 0 && tdh_err > 0) {
    pct = (int)((100LL * tdh_err) / tdh_denom);
    if (pct > 100) {
      pct = 100;
    }
  }
  uint64_t pushed = edr_event_bus_pushed_total((EdrEventBus *)bus);
  uint64_t dropped = edr_event_bus_dropped_total((EdrEventBus *)bus);
  uint64_t hw = edr_event_bus_high_water_hits((EdrEventBus *)bus);
  uint32_t used = edr_event_bus_used_approx((EdrEventBus *)bus);
  fprintf(out,
          "[etw_obs] etw_cb=%" PRId64
          " tag[kp,kf,kn,kr,dns,ps,sec,wm,tc,wf,un,ot]=["
          "%" PRId64 ",%" PRId64 ",%" PRId64 ",%" PRId64 ",%" PRId64 ",%" PRId64 ",%" PRId64 ",%" PRId64
          ",%" PRId64 ",%" PRId64 ",%" PRId64 ",%" PRId64
          "] pl0=%" PRId64
          " bus{push=%" PRIu64 " drop=%" PRIu64 " use=%" PRIu32 " hw80=%" PRIu64
          "}"
          " tdh{api_err=%" PRId64 " line_ok=%" PRId64 " err~%d%%"
          "}",
          s_etw_callback_total, s_by_tag[0], s_by_tag[1], s_by_tag[2], s_by_tag[3], s_by_tag[4], s_by_tag[5],
          s_by_tag[6], s_by_tag[7], s_by_tag[8], s_by_tag[9], s_by_tag[10], s_by_tag[11], s_slot_payload_empty, pushed, dropped, used, hw, tdh_err, tdh_ok, pct);
  if (s_a44_ph_cnt[0] > 0 || s_a44_ph_cnt[1] > 0 || s_a44_ph_cnt[2] > 0) {
    int a0 = 0, a1 = 0, a2 = 0;
    if (s_a44_ph_cnt[0] > 0) {
      a0 = (int)(s_a44_ph_ns[0] / s_a44_ph_cnt[0] / 1000);
    }
    if (s_a44_ph_cnt[1] > 0) {
      a1 = (int)(s_a44_ph_ns[1] / s_a44_ph_cnt[1] / 1000);
    }
    if (s_a44_ph_cnt[2] > 0) {
      a2 = (int)(s_a44_ph_ns[2] / s_a44_ph_cnt[2] / 1000);
    }
    fprintf(out, " a44_us_avg[pre,tdh,bus]=[%d,%d,%d] a44_n=[%" PRId64 ",%" PRId64 ",%" PRId64 "]", a0, a1, a2,
            s_a44_ph_cnt[0], s_a44_ph_cnt[1], s_a44_ph_cnt[2]);
  }
  {
    const uint64_t a44qd = edr_a44_dropped_total();
    if (edr_a44_split_path_enabled() || a44qd > 0) {
      fprintf(out, " a44_q_drops=%" PRIu64, a44qd);
    }
  }
  fputc('\n', out);
}

void edr_etw_observability_print_line(const EdrEventBus *bus) {
  if (!bus) {
    return;
  }
  edr_etw_observability_fprint(bus, stderr);
  fflush(stderr);

  {
    /* P2 A1.1：将 [etw_obs] 行镜像到本地文件，供 shipper/长基线归档。仅在首次成功 fopen 时写入。 */
    static FILE *s_exp_fp;
    static int s_exp_inited; /* 0: try once; 1: done (may have fp or not) */
    if (!s_exp_inited) {
      s_exp_inited = 1;
      const char *path = getenv("EDR_ETW_OBS_EXPORT_PATH");
      if (path && path[0]) {
#if defined(_MSC_VER)
        if (fopen_s(&s_exp_fp, path, "a") != 0) {
          s_exp_fp = NULL;
        }
#else
        s_exp_fp = fopen(path, "a");
#endif
        if (!s_exp_fp) {
          (void)fprintf(stderr, "[etw_obs] export: fopen(%s) failed, mirror disabled\n", path);
          fflush(stderr);
        }
      }
    }
    if (s_exp_fp) {
      edr_etw_observability_fprint(bus, s_exp_fp);
      fflush(s_exp_fp);
    }
  }
}
