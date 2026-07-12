/* §21 PMFE：预处理阶段自动入队 — Windows：ETW shellcode；Linux：`EDR_PMFE_ETW_AUTO` + webshell 检测 */

#include "edr/pmfe.h"
#include "edr/detection_decision.h"

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#if defined(__linux__) && !defined(_WIN32)
#include <stdio.h>
#include <unistd.h>
#endif

#ifdef _WIN32
#include <stdio.h>
#include <windows.h>

/** 在 ETW1 文本中查找 `key=value` 行（key 不含 '='） */
static int etw1_line_value(const uint8_t *data, uint32_t len, const char *key, char *out, size_t out_cap) {
  if (!data || len == 0u || !key || !out || out_cap == 0u) {
    return -1;
  }
  char buf[8192];
  size_t n = len;
  if (n >= sizeof(buf)) {
    n = sizeof(buf) - 1u;
  }
  memcpy(buf, data, n);
  buf[n] = '\0';

  size_t kl = strlen(key);
  if (kl + 2u >= sizeof(buf)) {
    return -1;
  }
  char pfx[96];
  if (kl + 2u > sizeof(pfx)) {
    return -1;
  }
  memcpy(pfx, key, kl);
  pfx[kl] = '=';
  pfx[kl + 1u] = '\0';

  for (char *p = buf; *p;) {
    char *nl = strchr(p, '\n');
    size_t linelen = nl ? (size_t)(nl - p) : strlen(p);
    if (linelen > kl + 1u && strncmp(p, pfx, kl + 1u) == 0) {
      size_t vl = linelen - (kl + 1u);
      if (vl >= out_cap) {
        vl = out_cap - 1u;
      }
      memcpy(out, p + kl + 1u, vl);
      out[vl] = '\0';
      return 0;
    }
    if (!nl) {
      break;
    }
    p = nl + 1;
  }
  return -1;
}

#endif

#if defined(__linux__) || defined(_WIN32)
static int pmfe_auto_allowed_by_profile(const EdrBehaviorRecord *br) {
  const char *modern = getenv("EDR_DETECTION_PMFE_AUTO");
  const char *legacy = getenv("EDR_PMFE_ETW_AUTO");
  if ((modern && modern[0] == '0') || (legacy && legacy[0] == '0')) {
    return 0;
  }
  if (legacy && legacy[0] == '1' && (!modern || modern[0] != '0')) {
    return 1;
  }
  if (!br) {
    return 0;
  }
  EdrBehaviorRecord copy = *br;
  EdrDetectionDecision d;
  edr_detection_decision_evaluate(&copy, &d);
  return d.trigger_pmfe_scan ? 1 : 0;
}

static int pmfe_is_self_pid(uint32_t pid) {
  if (pid == 0u) {
    return 1;
  }
#if defined(_WIN32)
  return pid == (uint32_t)GetCurrentProcessId();
#elif defined(__linux__)
  return pid == (uint32_t)getpid();
#else
  return 0;
#endif
}

static int pmfe_queue_profile_scan(const EdrEventSlot *slot, const EdrBehaviorRecord *br, const char *reason) {
  if (!slot || !br || br->type == EDR_EVENT_PMFE_SCAN_RESULT || pmfe_is_self_pid(br->pid)) {
    return -1;
  }
  EdrPmfeTriggerBand band = (slot->priority == 0u) ? EDR_PMFE_BAND_P0 : EDR_PMFE_BAND_P1;
  int rc = edr_pmfe_submit_etw_scan_ex(reason && reason[0] ? reason : "profile_trigger", br->pid, band, 0);
  if (rc == 0) {
    fprintf(stderr, "[pmfe][pre] profile auto_queued pid=%u type=%d band=%u reason=%s\n", (unsigned)br->pid,
            (int)br->type, (unsigned)band, reason && reason[0] ? reason : "profile_trigger");
  }
  return rc;
}
#endif

void edr_pmfe_on_preprocess_slot(const EdrEventSlot *slot, const EdrBehaviorRecord *br) {
  if (!slot || !br) {
    return;
  }
#if defined(__linux__) && !defined(_WIN32)
  if (!pmfe_auto_allowed_by_profile(br)) {
    return;
  }
  if (br->type != EDR_EVENT_WEBSHELL_DETECTED) {
    (void)pmfe_queue_profile_scan(slot, br, "profile_trigger");
    return;
  }
  if (pmfe_is_self_pid(br->pid)) {
    return;
  }
  EdrPmfeTriggerBand band = (slot->priority == 0u) ? EDR_PMFE_BAND_P0 : EDR_PMFE_BAND_P1;
  if (edr_pmfe_submit_etw_scan_ex("webshell", br->pid, band, 0) == 0) {
    fprintf(stderr, "[pmfe][pre] linux auto_queued webshell pid=%u band=%u\n", (unsigned)br->pid, (unsigned)band);
  }
#elif defined(_WIN32)
  if (!pmfe_auto_allowed_by_profile(br)) {
    return;
  }
  if (br->type != EDR_EVENT_PROTOCOL_SHELLCODE) {
    (void)pmfe_queue_profile_scan(slot, br, "profile_trigger");
    return;
  }

  char score_s[40];
  char recommended_s[16];
  char alert_id[64];
  char trigger[48];
  if (etw1_line_value(slot->data, slot->size, "pmfe_recommended", recommended_s,
                      sizeof(recommended_s)) != 0 || strcmp(recommended_s, "1") != 0) {
    return;
  }
  if (etw1_line_value(slot->data, slot->size, "score", score_s, sizeof(score_s)) != 0) {
    return;
  }
  double score = strtod(score_s, NULL);
  double th = 0.65;
  const char *ts = getenv("EDR_PMFE_ETW_SHELLCODE_SCORE");
  if (ts && ts[0]) {
    th = strtod(ts, NULL);
  }
  if (score < th) {
    return;
  }

  uint32_t target = br->pid;

  DWORD self = GetCurrentProcessId();
  if (target == 0u || target == (uint32_t)self) {
    return;
  }

  char va_s[48];
  uint64_t hint_va = 0ull;
  if (etw1_line_value(slot->data, slot->size, "va", va_s, sizeof(va_s)) == 0) {
    hint_va = strtoull(va_s, NULL, 0);
  } else if (etw1_line_value(slot->data, slot->size, "hint", va_s, sizeof(va_s)) == 0) {
    hint_va = strtoull(va_s, NULL, 0);
  }

  alert_id[0] = '\0';
  trigger[0] = '\0';
  (void)etw1_line_value(slot->data, slot->size, "alert_id", alert_id, sizeof(alert_id));
  (void)etw1_line_value(slot->data, slot->size, "pmfe_trigger", trigger, sizeof(trigger));
  EdrPmfeTriggerBand band = strcmp(trigger, "known_exploit") == 0 ? EDR_PMFE_BAND_P0 : EDR_PMFE_BAND_P1;
  char reason[64];
  snprintf(reason, sizeof(reason), "shellcode:%.46s", alert_id[0] ? alert_id : "unlinked");

  if (edr_pmfe_submit_etw_scan_ex(reason, target, band, hint_va) == 0) {
    fprintf(stderr, "[pmfe][etw] auto_queued shellcode alert_id=%s trigger=%s score=%.4f target_pid=%u band=%u hint=0x%llx\n",
            alert_id[0] ? alert_id : "unlinked", trigger[0] ? trigger : "unknown", score,
            (unsigned)target, (unsigned)band, (unsigned long long)hint_va);
  }
#else
  (void)slot;
  (void)br;
#endif
}
