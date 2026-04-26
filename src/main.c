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
#include "edr/edr_log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <locale.h>
#endif

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
          "  EDR_ETW_OBS=1  (仅 Windows) 在 [heartbeat] 同周期多打一行 [etw_obs]：ETW 回调、按 tag 分桶、\n"
          "                              空 slot 载荷、总线 push/drop、TDH 属性 API 错误率等（累计量）。\n"
          "  EDR_ETW_OBS_EXPORT_PATH  (仅 Windows)  与 EDR_ETW_OBS=1 同用：将同一条 [etw_obs] 行追加到该路径\n"
          "                              （本地/共享盘，供 log shipper）；见 README 与「OPS」文档。\n"
          "  EDR_AVE_ETW_FEED_EVERY_N=K  (仅 Windows) 仅对 AVE 行为喂入 1/K 分频，不影响 TDH/总线；见 README。\n"
          "  EDR_AVE_ETW_ASYNC=1         (仅 Windows) A3.2：非 terminate 的 `AVE_FeedEvent` 入队+工作线程；\n"
          "                              默认关。队列满时同线程同步喂入。terminate 不走路径。见 README。\n"
          "  EDR_ETW_BUFFER_KB=NN       (仅 Windows) 覆盖 [collection] 实时 ETW 缓冲每块 KB(4-1024)。\n"
          "  EDR_ETW_FLUSH_TIMER_S=SS   (仅 Windows) 覆盖 FlushTimer 秒(1-300)。\n"
          "  EDR_TDH_LIGHT_PATH=1     (仅 Windows) A3.3：DNS-Client 在已解出 qname 时省一次 QueryType TDH；\n"
          "                              未解出时回退全量；见 README。默认=关。\n"
          "  EDR_A44_CB_PHASE_MEAS=1  (仅 Windows) A4.4 第一期：在 ETW 回调累计 pre/TDH/入总线 的 QPC 时间；\n"
          "                              与 EDR_ETW_OBS=1 同用则在 [etw_obs] 行尾打 a44_us_avg… 与样本数。默认=关。\n"
          "  EDR_A44_SPLIT_PATH=1      (仅 Windows) A4.4 第二期：将 UserData 有界 入队，解线程 再 Tdh+总线；\n"
          "                              与 EDR_ETW_OBS=1 时 [etw_obs] 上还有 a44_q_drops=…；默认=关。见 ADR 与 README。\n"
          "  EDR_TDH_LIGHT_PATH_PS=1   (仅 Windows) A3.3+：PowerShell 在已出 script 行 时 省 path TDH 试探；\n"
          "                              须 会签 v1.1+ 与门闩；与 EDR_TDH_LIGHT_PATH=1 独立。默认=关。\n"
          "  EDR_TDH_LIGHT_PATH_TCPIP=1 (仅 Windows) A3.3+ P1：TCPIP **EventId 1002**（监听）时先试 Local*/PID 子集，\n"
          "                              未出槽行再全量；须 P0/会签 对表。与 PS/DNS 独立。默认=关。\n"
          "  EDR_AGENT_VERBOSE           1=详细 stderr（ONNX/传输/攻击面上报成功等，默认关）。\n"
          "  EDR_AGENT_SHUTDOWN_LOG      1=退出时打印 [preprocess]/[grpc] 等统计行（默认同关，\n"
          "                              与 EDR_AGENT_VERBOSE=1 时也会打印）。\n"
          "  EDR_SHELCODE_LOG            1=壳代码/WinDivert 逐包与 pcap 提示（细粒度，默认同上）。\n"
          "  EDR_NO_CONSOLE_UTF8=1        (仅 Windows) 不切换控制台为 UTF-8 代码页。\n"
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
  /* 管道/重定向时 glibc 等常对 stderr 全缓冲，排障时首条含换行日志会迟滞；行缓冲后 [ave]/[config] 等尽快可见。 */
#if !defined(_WIN32)
  (void)setvbuf(stderr, NULL, _IOLBF, 0);
#endif
#ifdef _WIN32
  {
    const char *nou8 = getenv("EDR_NO_CONSOLE_UTF8");
    if (!nou8 || strcmp(nou8, "1") != 0) {
      (void)SetConsoleOutputCP(65001);
      (void)SetConsoleCP(65001);
      {
        static const char *loc_cands[] = {".UTF-8", ".utf8", "C.UTF-8", "C.utf8", "en_US.UTF-8", "zh_CN.UTF-8", NULL};
        int loc_set = 0;
        for (int li = 0; loc_cands[li] && !loc_set; li++) {
          if (setlocale(LC_ALL, loc_cands[li])) {
            loc_set = 1;
          }
        }
        if (!loc_set) {
          (void)setlocale(LC_CTYPE, ".utf8");
        }
      }
      (void)fflush(stdout);
      (void)fflush(stderr);
      {
        HANDLE h = GetStdHandle(STD_ERROR_HANDLE);
        if (h && h != INVALID_HANDLE_VALUE) {
          DWORD m = 0;
          if (GetConsoleMode(h, &m)) {
            (void)SetConsoleMode(h, m | 0x0004u);
          }
        }
        h = GetStdHandle(STD_OUTPUT_HANDLE);
        if (h && h != INVALID_HANDLE_VALUE) {
          DWORD m = 0;
          if (GetConsoleMode(h, &m)) {
            (void)SetConsoleMode(h, m | 0x0004u);
          }
        }
      }
    }
  }
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
  if (edr_log_want_shutdown_stats()) {
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
