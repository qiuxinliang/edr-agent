#ifndef EDR_COMMAND_CANCEL_H
#define EDR_COMMAND_CANCEL_H

#ifdef __cplusplus
extern "C" {
#endif

/* Active-command registry shared by executor lanes and cancellable handlers. */
int edr_command_cancel_begin(const char *command_id);
void edr_command_cancel_end(const char *command_id);
int edr_command_cancel_request(const char *command_id);
int edr_command_cancel_request_all(void);
void edr_command_cancel_reset_all(void);
int edr_command_cancel_requested(const char *command_id);

#ifdef __cplusplus
}
#endif

#endif
