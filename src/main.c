#include "edr/agent.h"
#include "edr/collector.h"
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

static void print_usage(const char *prog) {
  const char *name = (prog && prog[0]) ? prog : "edr_agent";
  fprintf(stderr,
          "%s — EDR 端点 Agent\n"
          "\n"
          "用法:\n"
          "  %s [--config <path>]\n"
          "  不带任何参数时显示本说明并退出。\n"
          "\n"
          "选项:\n"
          "  --config <path>   加载 agent.toml（推荐始终显式指定）\n"
          "  --etw-uninstall-cleanup   停止本程序使用的 ETW 实时会话（卸载脚本调用；无其它初始化）\n"
          "  -h, --help, -help, /?   显示本说明并退出\n"
          "\n"
          "环境变量:\n"
          "  EDR_CONSOLE_HEARTBEAT_SEC   控制台 [heartbeat] 间隔（秒）；0=关闭；未设置则用 agent.toml\n"
          "                              的 [server] keepalive_interval_s（钳位 10~600）。\n"
          "\n",
          name, name);
#ifdef _WIN32
  fprintf(stderr,
          "说明 (Windows):\n"
          "  安装包生成的计划任务与快捷方式会附带 --config 指向安装目录下的 agent.toml。\n"
          "  便携 zip 解压后请运行: %s --config .\\agent.toml\n"
          "\n"
          "Inno 安装包 EDRAgentSetup.exe（与本程序不同）静默安装并注册时，可在安装包命令行传入\n"
          "（须同时指定 API 与 Token，或两者均省略；Token 会出现在安装进程命令行）：\n"
          "  /VERYSILENT /SUPPRESSMSGBOXES /NORESTART\n"
          "  /EDR_API_BASE=<平台 REST 根 URL>  /EDR_ENROLL_TOKEN=<注册 Token>\n"
          "  短参数: /API= /TOK= ；跳过 TLS 校验: /EDR_INSECURE_TLS=1 或 /TLS=1（或 /MERGETASKS=enrollinsecure）\n"
          "  完整参数与安全提示见仓库内 docs/AGENT_INSTALLER.md（Release 一键安装 · Windows）。\n"
          "\n",
          name);
#endif
  fprintf(stderr,
          "更多: README「实现状态快照」与仓库内设计文档。\n");
}

int main(int argc, char **argv) {
#ifdef _WIN32
  /* 控制台/管道默认多为一页 GBK(936)；进程内改为 UTF-8(65001)，与源码字面量(UTF-8)一致，避免 [grpc]/[self_protect] 等中文在 cmd 乱码 */
  (void)SetConsoleOutputCP(65001);
  (void)SetConsoleCP(65001);
#endif
  const char *config = NULL;
  const char *prog = (argc > 0 && argv[0]) ? argv[0] : "edr_agent";

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--etw-uninstall-cleanup") == 0) {
      edr_collector_stop_orphan_etw_session();
      return 0;
    }
  }

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0 ||
        strcmp(argv[i], "-help") == 0 || strcmp(argv[i], "/?") == 0) {
      print_usage(prog);
      return 0;
    }
    if (strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
      config = argv[++i];
      continue;
    }
    fprintf(stderr, "未知参数: %s\n", argv[i]);
    print_usage(prog);
    return 1;
  }

  if (argc < 2) {
    print_usage(prog);
    return 0;
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
