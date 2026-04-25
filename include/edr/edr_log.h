/**
 *  stderr 诊断：生产默认安静；排障时设 EDR_AGENT_VERBOSE=1 或各子系统开关（见 main --help 与 README）。
 */
#ifndef EDR_EDR_LOG_H
#define EDR_EDR_LOG_H

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/** 非 0：打印详细诊断（ONNX 加载、传输/gRPC 横幅、上报面成功、WinDivert 包级日志等）。 */
int edr_log_verbose(void);

/**
 * 非 0：进程退出时打印 [preprocess]/[grpc]/[command] 等统计块。
 * 未设置或 0 时不打印；或当 edr_log_verbose() 为真时等同开启。
 */
int edr_log_want_shutdown_stats(void);

/** 非 0：WinDivert/壳代码检测的逐包/抓包等噪声；另可用 EDR_SHELCODE_LOG=1 单独开启。 */
int edr_log_shelldcode_windivert_verbose(void);

#ifdef __cplusplus
}
#endif

#define EDR_LOGV(...)                                                                                                  \
  do {                                                                                                                 \
    if (edr_log_verbose()) {                                                                                           \
      fprintf(stderr, __VA_ARGS__);                                                                                  \
    }                                                                                                                  \
  } while (0)

#define EDR_LOGE(...) fprintf(stderr, __VA_ARGS__)

#define EDR_LOGV_SHEL(...)                                                                                             \
  do {                                                                                                                 \
    if (edr_log_shelldcode_windivert_verbose()) {                                                                    \
      fprintf(stderr, __VA_ARGS__);                                                                                  \
    }                                                                                                                  \
  } while (0)

#endif
