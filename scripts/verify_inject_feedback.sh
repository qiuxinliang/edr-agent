#!/usr/bin/env bash
# verify_inject_feedback.sh
#
# 验证 Windows 注入信号回灌链路：AVE 注入裁决 → edr_correlation_note_injection
# → pending 环 → 预处理线程排空 → 注入后外联规则(R-CORR-INJECT-C2-001)命中，
# 并测量误报防护（内网出站不触发）与数据量指标。
#
# 两种模式：
#   (A) 宿主机逻辑验证（默认，任何平台）：编译一个链接真实 correlation_engine.c 的
#       harness，用 stub 模拟 AVE 裁决形状与后续网络事件，确定性地验证整条判定逻辑
#       ——不需要真实 AVE 模型。这覆盖“回灌逻辑是否正确”。
#   (B) 端上真实验证（Windows + AVE 行为模型）：见文末步骤，用真实注入样本触发 AVE 裁决，
#       读 agent 的 [correlation] 遥测行评估真实命中与数据量。
#
# 用法：  bash scripts/verify_inject_feedback.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CC="${CC:-cc}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "== (A) 宿主机逻辑验证 =="

cat > "$TMP/harness.c" <<'EOF'
#include "edr/correlation_engine.h"
#include "edr/ave_sdk.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int g_fired = 0;
static char g_last[4090];
void edr_behavior_alert_emit_to_batch(const AVEBehaviorAlert *a) {
  g_fired++;
  snprintf(g_last, sizeof(g_last), "%s", a->user_subject_json);
}
static unsigned long long g_now = 1000000000ULL;
unsigned long long edr_monotonic_ns(void) { return g_now; }

/* 模拟一次 AVE 注入裁决回调对关联引擎的作用（对应 agent.c edr_agent_on_behavior_alert
 * 中命中注入掩码后调用 note_injection 的那步）。 */
static void simulate_ave_injection_verdict(unsigned pid, const char *pname) {
  edr_correlation_note_injection(pid, pname, (long long)g_now, "hollowing");
}
static void net(unsigned pid, const char *dst) {
  EdrBehaviorRecord b;
  memset(&b, 0, sizeof(b));
  b.type = EDR_EVENT_NET_CONNECT; b.pid = pid; b.net_dport = 443;
  b.event_time_ns = (long long)g_now;
  snprintf(b.net_dst, sizeof(b.net_dst), "%s", dst);
  snprintf(b.process_name, sizeof(b.process_name), "%s", "victim.exe");
  edr_correlation_evaluate(&b);
}

int main(void) {
  EdrCorrelationStatus st;
  int rc = 0;

  setenv("EDR_CORRELATION_ENABLE", "1", 1);
  edr_correlation_reload();

  /* TP：注入裁决 + 公网外联 → C2 命中 */
  g_fired = 0;
  simulate_ave_injection_verdict(700, "victim.exe");
  net(700, "203.0.113.7");
  if (g_fired != 1 || !strstr(g_last, "R-CORR-INJECT-C2-001")) {
    printf("  [FAIL] 注入+公网外联 未命中 C2\n"); rc = 1;
  } else {
    printf("  [OK]   注入+公网外联 → R-CORR-INJECT-C2-001 命中\n");
  }

  /* FP 防护：注入裁决 + 内网连接 → 不得命中 */
  edr_correlation_reload(); g_fired = 0;
  simulate_ave_injection_verdict(701, "victim.exe");
  net(701, "192.168.1.10");
  net(701, "10.0.0.5");
  net(701, "127.0.0.1");
  if (g_fired != 0) {
    printf("  [FAIL] 注入+内网连接 误命中(%d)\n", g_fired); rc = 1;
  } else {
    printf("  [OK]   注入+内网连接 → 不命中（误报防护生效）\n");
  }

  /* FP 防护：仅注入、无外联 → 不得命中（注入单发不足以定性） */
  edr_correlation_reload(); g_fired = 0;
  simulate_ave_injection_verdict(702, "victim.exe");
  edr_correlation_poll_maintenance((long long)g_now);
  if (g_fired != 0) {
    printf("  [FAIL] 仅注入无外联 误命中\n"); rc = 1;
  } else {
    printf("  [OK]   仅注入无外联 → 不命中\n");
  }

  /* 关闭开关 → 完全 no-op */
  setenv("EDR_CORRELATION_INJECT_FEEDBACK_TEST_OFF", "1", 1); /* 说明用途；实际开关在 agent.c */
  setenv("EDR_CORRELATION_ENABLE", "0", 1);
  edr_correlation_reload(); g_fired = 0;
  simulate_ave_injection_verdict(703, "x.exe");
  net(703, "203.0.113.9");
  if (g_fired != 0) { printf("  [FAIL] 关闭后仍触发\n"); rc = 1; }
  else { printf("  [OK]   总开关关闭 → 完全 no-op\n"); }

  /* 打印指标（对应端上 [correlation] 遥测行的字段） */
  setenv("EDR_CORRELATION_ENABLE", "1", 1);
  edr_correlation_reload();
  simulate_ave_injection_verdict(704, "victim.exe");
  net(704, "198.51.100.2");
  edr_correlation_get_status(&st);
  printf("  指标: inject_fed=%llu inject_dropped=%llu fired=%llu active_states=%u\n",
         (unsigned long long)st.inject_fed, (unsigned long long)st.inject_dropped,
         (unsigned long long)st.fired, st.active_states);
  return rc;
}
EOF

# correlation_engine 依赖 cJSON(规则下发) 与 sha256(版本指纹)，一并链接。
"$CC" -I "$ROOT/include" -I "$ROOT/third_party/cjson" -Wall -Wextra -Wno-unused-parameter \
  "$TMP/harness.c" "$ROOT/src/preprocess/correlation_engine.c" \
  "$ROOT/third_party/cjson/cJSON.c" "$ROOT/src/command/sha256.c" -o "$TMP/harness"
"$TMP/harness"
echo "== (A) 逻辑验证通过 =="

cat <<'DOC'

== (B) 端上真实验证（Windows + AVE 行为模型）==

前置：装有 AVE 行为模型、能产生注入裁决(behavior_flags 命中注入位)的 Windows agent。

步骤：
  1) 启用关联引擎与注入回灌（默认已开；如需显式）：
       set EDR_CORRELATION_ENABLE=1
       set EDR_CORRELATION_INJECT_FEEDBACK=1
     采集自适应预算保持默认（EDR_ADAPTIVE_COLLECTION_ADMIT_BUDGET_PER_MIN=1200）。
  2) 记录基线：从 agent stderr 抓取一行 [correlation] 遥测，记下 inject_fed / fired。
  3) 运行一个“注入 + 公网外联”样本（受控靶机上的良性远程线程注入器，注入后连公网 IP）。
  4) 复查 [correlation] 遥测：inject_fed 应 +1、fired 应 +1，且后端出现一条
     subject_type=edr_correlation / rule_id=R-CORR-INJECT-C2-001 的告警。

== 误报与数据量评估要点（把这些数读出来再下结论）==

  误报：
    - 在“合法注入类软件”基线机上（EDR/调试器/.NET JIT/反作弊等）跑一段时间，
      观察 fired 是否上涨。外网出站谓词已排除本地/内网通信；若仍误报，多为
      AVE 注入判定本身误报 —— 此时用 EDR_CORRELATION_INJECT_FEEDBACK=0 单独回滚
      注入回灌（不影响其它规则），并反馈 AVE 注入模型精度。
    - C2 规则误报率 ≈ AVE 注入判定误报率 ×「该进程公网外联的比例」。

  数据量：
    - 注入回灌会对命中进程 raise 自适应采集（默认 180s），使其后续 net/file/reg
      被放行。额外放行量受既有全局预算硬约束（默认 1200 events/min，60s 滑窗），
      与 P0 直出的 raise 共用同一预算，不新增独立出口。
    - 关注 agent 健康遥测里的 adaptive_collection_boosts 增速与 sensor_interest
      matched/dropped 比例；若额外数据超预期，调低 EDR_ADAPTIVE_COLLECTION_TTL_S
      或 EDR_ADAPTIVE_COLLECTION_ADMIT_BUDGET_PER_MIN。
DOC
