#ifndef EDR_FL_ROUND_H
#define EDR_FL_ROUND_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum FLRoundPhase {
  FL_ROUND_IDLE = 0,
  FL_ROUND_ANNOUNCED,
  FL_ROUND_TRAINING,
  FL_ROUND_UPLOADING,
  FL_ROUND_DONE,
  FL_ROUND_SKIPPED,
  FL_ROUND_ERROR,
} FLRoundPhase;

void fl_round_init(void);
void fl_round_shutdown(void);

FLRoundPhase fl_round_get_phase(void);

/** 单测 / 联调：注入一次 Round（`fl_protocol_thread` 也会按配置 mock） */
void fl_round_mock_inject(uint64_t round_id);

/** 由 `fl_trainer` 线程入口调用 */
void fl_round_protocol_thread_loop(volatile int *stop_flag, uint32_t mock_interval_s);
void fl_round_trainer_thread_loop(volatile int *stop_flag);

#ifdef __cplusplus
}
#endif

#endif
