#include "edr/forensic_trigger.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#define ft_now_ms() ((uint64_t)GetTickCount64())
#else
#include <unistd.h>
#define ft_now_ms() ((uint64_t)(time(NULL) * 1000ULL))
#endif

static EdrForensicAutoConfig g_cfg;
static EdrForensicTrigger g_queue[EDR_FT_QUEUE_CAPACITY];
static uint32_t g_head;
static uint32_t g_tail;
static uint32_t g_count;
static bool g_initialized;
static uint64_t g_last_trigger_ms;
static uint32_t g_hour_triggered;
static uint64_t g_hour_start_ms;
static uint64_t g_mitre_cooldowns[EDR_FT_MAX_MITRE_TRIGGERS];

static void ft_reset_hour(uint64_t now_ms) {
  g_hour_start_ms = now_ms;
  g_hour_triggered = 0;
}

static bool ft_enqueue(const EdrForensicTrigger *t) {
  if (g_count >= EDR_FT_QUEUE_CAPACITY) return false;
  (void)memcpy(&g_queue[g_tail], t, sizeof(*t));
  g_tail = (g_tail + 1) % EDR_FT_QUEUE_CAPACITY;
  g_count++;
  return true;
}

void edr_forensic_trigger_init(const EdrForensicAutoConfig *cfg) {
  (void)memcpy(&g_cfg, cfg, sizeof(g_cfg));
  (void)memset(g_queue, 0, sizeof(g_queue));
  g_head = 0;
  g_tail = 0;
  g_count = 0;
  g_last_trigger_ms = 0;
  g_initialized = true;
  uint64_t now = ft_now_ms();
  ft_reset_hour(now);
  (void)memset(g_mitre_cooldowns, 0, sizeof(g_mitre_cooldowns));
}

void edr_forensic_trigger_shutdown(void) {
  g_initialized = false;
  g_head = 0;
  g_tail = 0;
  g_count = 0;
}

void edr_forensic_trigger_evaluate(const EdrEventSlot *slot,
                                   const EdrBehaviorRecord *rec) {
  if (!g_initialized || !g_cfg.enabled) return;
  if (!slot || !rec) return;

  uint64_t now_ms = ft_now_ms();

  if (g_hour_start_ms == 0 || now_ms - g_hour_start_ms > 3600000ULL) {
    ft_reset_hour(now_ms);
  }

  bool should = false;
  EdrForensicTriggerScope scope = EDR_FT_SCOPE_QUICK;

  if (g_cfg.trigger_on_p0 && slot->priority == 0) {
    should = true;
    scope = EDR_FT_SCOPE_FULL;
  }

  if (!should && rec->mitre_ttp_count > 0) {
    for (int i = 0; i < rec->mitre_ttp_count; i++) {
      for (uint32_t j = 0; j < g_cfg.mitre_trigger_count; j++) {
        if (strstr(rec->mitre_ttps[i], g_cfg.trigger_mitre[j])) {
          uint64_t cd = g_cfg.per_mitre_cooldown_s * 1000ULL;
          if (cd == 0 || (now_ms - g_mitre_cooldowns[j]) >= cd) {
            should = true;
            scope = EDR_FT_SCOPE_FULL;
            g_mitre_cooldowns[j] = now_ms;
          }
          break;
        }
      }
      if (should) break;
    }
  }

  if (!should) return;

  if (g_cfg.cooldown_s > 0 && g_last_trigger_ms > 0) {
    if (now_ms - g_last_trigger_ms < (uint64_t)g_cfg.cooldown_s * 1000ULL) {
      return;
    }
  }

  if (g_cfg.max_per_hour > 0 && g_hour_triggered >= g_cfg.max_per_hour) {
    return;
  }

  EdrForensicTrigger t;
  (void)memset(&t, 0, sizeof(t));
  snprintf(t.reason, sizeof(t.reason), "priority=%u mitre_count=%d",
           (unsigned)slot->priority, rec->mitre_ttp_count);
  t.source_event_id[0] = 0;
  t.source_event_id[1] = (uint64_t)slot->type;
  t.target_pid = rec->pid;
  if (rec->exe_path[0]) {
    strncpy(t.target_path, rec->exe_path, sizeof(t.target_path) - 1);
    t.target_path[sizeof(t.target_path) - 1] = '\0';
  } else if (rec->file_path[0]) {
    strncpy(t.target_path, rec->file_path, sizeof(t.target_path) - 1);
    t.target_path[sizeof(t.target_path) - 1] = '\0';
  }
  t.scope = scope;
  t.created_ns = now_ms * 1000000ULL;
  if (rec->mitre_ttp_count > 0) {
    strncpy(t.mitre_tag, rec->mitre_ttps[0], sizeof(t.mitre_tag) - 1);
    t.mitre_tag[sizeof(t.mitre_tag) - 1] = '\0';
  }

  if (ft_enqueue(&t)) {
    g_last_trigger_ms = now_ms;
    g_hour_triggered++;
  }
}

bool edr_forensic_trigger_try_pop(EdrForensicTrigger *out) {
  if (!g_initialized || g_count == 0) return false;
  (void)memcpy(out, &g_queue[g_head], sizeof(*out));
  g_head = (g_head + 1) % EDR_FT_QUEUE_CAPACITY;
  g_count--;
  return true;
}

uint32_t edr_forensic_trigger_backlog(void) {
  return g_count;
}
