#include "edr/agent_main.h"
#ifdef _WIN32
#include "edr/windows_service.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void print_usage(const char *argv0) {
  fprintf(stderr, "用法: %s [--config <path>]", argv0);
#ifdef _WIN32
  fprintf(stderr, " [--service [<服务名>]]");
#endif
  fprintf(stderr, "\n");
  fprintf(stderr,
          "  EDR Agent — 端点实现（初版：采集/预处理/批次/gRPC/指令/AVE 等已接通，见 README「实现状态快照」；"
          "设计见 ../Cauld Design/EDR_端点详细设计_v1.0.md）\n");
#ifdef _WIN32
  fprintf(stderr,
          "  Windows **--service**：须由 **SCM** 启动（**`sc create` / `sc start`**）；**`--service`** 后的名称须与 **`sc create`** 的"
          "服务名一致（缺省 **EdrAgent**）。也可用环境变量 **`EDR_SERVICE_NAME`** 当 **binPath** 未带名称时。\n");
#endif
}

int main(int argc, char **argv) {
#ifdef _WIN32
  {
    int svc_rc = edr_windows_service_dispatch_if_requested(argc, argv);
    if (svc_rc >= 0) {
      return svc_rc;
    }
  }
#endif
  const char *config = NULL;
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
      print_usage(argv[0]);
      return 0;
    }
#ifdef _WIN32
    if (strcmp(argv[i], "--service") == 0) {
      if (i + 1 < argc && argv[i + 1][0] != '-') {
        i++;
      }
      continue;
    }
#endif
    if (strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
      config = argv[++i];
      continue;
    }
    fprintf(stderr, "未知参数: %s\n", argv[i]);
    print_usage(argv[0]);
    return 1;
  }

  return edr_agent_application_main(config ? config : "", NULL);
}
