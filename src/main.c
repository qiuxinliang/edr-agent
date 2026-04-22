#include "edr/agent.h"
#include "edr/ave_sdk.h"
#include "edr/dedup.h"
#include "edr/event_batch.h"
#include "edr/command.h"
#include "edr/grpc_client.h"
#include "edr/resource.h"
#include "edr/self_protect.h"
#include "edr/storage_queue.h"
#include "edr/transport_sink.h"
#include "edr/pmfe.h"
#include "edr/shellcode_detector.h"
#include "edr/webshell_detector.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
static EdrAgent *g_agent_for_sig;
static void edr_on_sigint(int s) {
  (void)s;
  if (g_agent_for_sig) {
    edr_agent_shutdown(g_agent_for_sig);
  }
}
#endif

#ifdef _WIN32
#include <wchar.h>
#include <windows.h>
/** 未传 --config 时，若 exe 同目录存在 agent.toml 则自动加载（安装目录 / 计划任务未带参数时仍可读配置）。 */
static int win_agent_toml_next_to_exe(char *out_utf8, size_t out_cap) {
  wchar_t wpath[MAX_PATH];
  DWORD n = GetModuleFileNameW(NULL, wpath, MAX_PATH);
  if (n == 0 || n >= MAX_PATH) {
    return 0;
  }
  wchar_t *slash = wcsrchr(wpath, L'\\');
  if (!slash) {
    slash = wcsrchr(wpath, L'/');
  }
  if (!slash) {
    return 0;
  }
  slash++;
  {
    const wchar_t *s = L"agent.toml";
    size_t j = 0;
    while (s[j] != 0 && (slash + j) < wpath + MAX_PATH - 1) {
      slash[j] = s[j];
      j++;
    }
    slash[j] = L'\0';
  }
  {
    DWORD at = GetFileAttributesW(wpath);
    if (at == INVALID_FILE_ATTRIBUTES || (at & FILE_ATTRIBUTE_DIRECTORY)) {
      return 0;
    }
  }
  if (WideCharToMultiByte(CP_UTF8, 0, wpath, -1, out_utf8, (int)out_cap, NULL, NULL) <= 1) {
    return 0;
  }
  return 1;
}

static EdrAgent *g_agent_for_ctrl;
static BOOL WINAPI edr_on_console_ctrl(DWORD t) {
  if (t == CTRL_C_EVENT || t == CTRL_CLOSE_EVENT || t == CTRL_BREAK_EVENT) {
    if (g_agent_for_ctrl) {
      edr_agent_shutdown(g_agent_for_ctrl);
    }
    return TRUE;
  }
  return FALSE;
}
#endif

static void print_usage(const char *argv0) {
  fprintf(stderr, "用法: %s [--config <path>]\n", argv0);
  fprintf(stderr,
          "  Windows: 若未指定 --config 且与 exe 同目录存在 agent.toml，将自动加载该文件。\n"
          "  EDR Agent — 端点实现（初版：采集/预处理/批次/gRPC/指令/AVE 等已接通，见 README「实现状态快照」；"
          "设计见 ../Cauld Design/EDR_端点详细设计_v1.0.md）\n");
}

int main(int argc, char **argv) {
  const char *config = NULL;
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
      print_usage(argv[0]);
      return 0;
    }
    if (strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
      config = argv[++i];
      continue;
    }
    fprintf(stderr, "未知参数: %s\n", argv[i]);
    print_usage(argv[0]);
    return 1;
  }

#ifdef _WIN32
  static char s_win_cfg_auto[4096];
  if ((!config || !config[0]) && win_agent_toml_next_to_exe(s_win_cfg_auto, sizeof(s_win_cfg_auto))) {
    config = s_win_cfg_auto;
  }
#endif

  EdrAgent *agent = edr_agent_create();
  if (!agent) {
    return 1;
  }
#ifdef _WIN32
  g_agent_for_ctrl = agent;
  SetConsoleCtrlHandler(edr_on_console_ctrl, TRUE);
#else
  g_agent_for_sig = agent;
  edr_self_protect_set_shutdown_hook(edr_on_sigint);
#endif
  EdrError e = edr_agent_init(agent, config ? config : "");
  if (e != EDR_OK) {
    fprintf(stderr, "edr_agent_init 失败: %d\n", (int)e);
    edr_agent_destroy(agent);
    return 1;
  }
  {
    const char *qpath = getenv("EDR_QUEUE_PATH");
    const EdrConfig *ac = edr_agent_get_config(agent);
    if ((!qpath || !qpath[0]) && ac && ac->offline.queue_db_path[0]) {
      qpath = ac->offline.queue_db_path;
    }
    EdrError sq = edr_storage_queue_open(qpath);
    if (sq != EDR_OK && qpath && qpath[0]) {
      fprintf(stderr, "队列打开失败 (%s): %d\n", qpath, (int)sq);
    }
  }
  edr_command_bind_config(edr_agent_get_config(agent));
  edr_pmfe_bind_config(edr_agent_get_config(agent));
  edr_pmfe_set_event_bus(edr_agent_event_bus(agent));
  {
    EdrError pe = edr_pmfe_init();
    if (pe != EDR_OK) {
      fprintf(stderr, "edr_pmfe_init 失败: %d\n", (int)pe);
    }
  }
  edr_transport_init_from_config(edr_agent_get_config(agent));
  {
    EdrError se =
        edr_shellcode_detector_init(edr_agent_get_config(agent), edr_agent_event_bus(agent));
    if (se != EDR_OK) {
      fprintf(stderr, "shellcode_detector 初始化失败: %d\n", (int)se);
    }
  }
  {
    EdrError we = edr_webshell_detector_init(edr_agent_get_config(agent), edr_agent_event_bus(agent));
    if (we != EDR_OK) {
      fprintf(stderr, "webshell_detector 初始化失败: %d\n", (int)we);
    }
  }
  e = edr_agent_run(agent);
  {
    uint64_t dd = 0, rr = 0;
    edr_dedup_get_stats(&dd, &rr);
    fprintf(stderr,
            "[preprocess] wire_events=%lu wire_bytes=%lu batches=%lu "
            "batch_bytes=%lu batch_lz4=%lu batch_timeout_flushes=%llu "
            "bus_hw80=%llu bus_dropped=%llu dedup_drops=%llu rate_drops=%llu "
            "queue_pending=%llu\n",
            edr_transport_wire_events_count(), edr_transport_wire_bytes_count(),
            edr_transport_batch_count(), edr_transport_batch_bytes_count(),
            edr_transport_batch_lz4_count(),
            (unsigned long long)edr_event_batch_timeout_flush_count(),
            (unsigned long long)edr_event_bus_high_water_hits(
                edr_agent_event_bus(agent)),
            (unsigned long long)edr_event_bus_dropped_total(
                edr_agent_event_bus(agent)),
            (unsigned long long)dd, (unsigned long long)rr,
            (unsigned long long)edr_storage_queue_pending_count());
    fprintf(stderr, "[grpc] rpc_ok=%lu rpc_fail=%lu\n", edr_grpc_client_rpc_ok(),
            edr_grpc_client_rpc_fail());
    fprintf(stderr,
            "[command] handled=%lu unknown=%lu rejected=%lu exec_ok=%lu exec_fail=%lu\n",
            edr_command_handled_count(), edr_command_unknown_count(),
            edr_command_rejected_count(), edr_command_exec_ok_count(),
            edr_command_exec_fail_count());
    fprintf(stderr, "[resource] emergency=%lu\n", edr_resource_emergency_count());
    {
      unsigned long sub = 0, done = 0, drop = 0;
      edr_pmfe_get_stats(&sub, &done, &drop);
      fprintf(stderr, "[pmfe] submitted=%lu completed=%lu dropped=%lu\n", sub, done, drop);
    }
    {
      AVEStatus avst;
      if (AVE_GetStatus(&avst) == AVE_OK) {
        fprintf(stderr,
                "[ave/behavior] feed=%llu enq=%llu q_full_sync=%llu bypass=%llu deq=%llu "
                "infer_ok=%llu infer_fail=%llu q_depth=%d q_cap=%u mon=%d\n",
                (unsigned long long)avst.behavior_feed_total, (unsigned long long)avst.behavior_queue_enqueued,
                (unsigned long long)avst.behavior_queue_full_sync_fallback,
                (unsigned long long)avst.behavior_feed_sync_bypass,
                (unsigned long long)avst.behavior_worker_dequeued, (unsigned long long)avst.behavior_infer_ok,
                (unsigned long long)avst.behavior_infer_fail, avst.behavior_event_queue_size,
                (unsigned)avst.behavior_queue_capacity, avst.behavior_monitor_running ? 1 : 0);
      }
    }
  }
  edr_pmfe_shutdown();
  edr_shellcode_detector_shutdown();
  edr_webshell_detector_shutdown();
  edr_transport_shutdown();
  edr_storage_queue_close();
  edr_agent_destroy(agent);
  return e == EDR_OK ? 0 : 1;
}
