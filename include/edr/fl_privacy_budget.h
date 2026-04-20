#ifndef EDR_FL_PRIVACY_BUDGET_H
#define EDR_FL_PRIVACY_BUDGET_H

#ifdef __cplusplus
extern "C" {
#endif

int fl_privacy_budget_open(const char *path);
void fl_privacy_budget_close(void);
/** 若未超过 `max_rounds` 则持久化 +1 并返回 0；否则返回 1 */
int fl_privacy_budget_try_consume_one(int max_rounds);
int fl_privacy_budget_get(int *participated_out, int max_rounds_cap);

#ifdef __cplusplus
}
#endif

#endif
