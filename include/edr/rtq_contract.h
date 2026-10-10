#ifndef EDR_RTQ_CONTRACT_H
#define EDR_RTQ_CONTRACT_H

#include <ctype.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#define EDR_RTQ_EVENTLOG_BATCH_SCHEMA "edr.rtq.eventlog-batch.v1"

/* The validator, live collector and signed result projection share the same
 * state spelling. The signed request itself is never rewritten. */
static inline int edr_rtq_network_state_normalize(const char *input, char *out, size_t cap) {
    if (!input || !out || strlen(input) >= cap) return 0;
    size_t i = 0;
    for (; input[i]; i++) out[i] = input[i] == '-' ? '_' : (char)toupper((unsigned char)input[i]);
    out[i] = '\0';
    const char *alias = !strcmp(out, "ESTAB") ? "ESTABLISHED" :
                        !strcmp(out, "SYN_RECV") ? "SYN_RCVD" :
                        !strcmp(out, "FIN_WAIT_1") ? "FIN_WAIT1" :
                        !strcmp(out, "FIN_WAIT_2") ? "FIN_WAIT2" :
                        !strcmp(out, "CLOSE") ? "CLOSED" : NULL;
    if (alias) {
        if (strlen(alias) >= cap) return 0;
        snprintf(out, cap, "%s", alias);
    }
    return 1;
}

static inline int edr_rtq_network_state_supported(const char *input) {
    static const char *const states[] = {
        "CLOSED", "LISTEN", "SYN_SENT", "SYN_RCVD", "ESTABLISHED", "FIN_WAIT1",
        "FIN_WAIT2", "CLOSE_WAIT", "CLOSING", "LAST_ACK", "TIME_WAIT", "DELETE_TCB", "UNCONN", "UNKNOWN"
    };
    char state[32];
    if (!edr_rtq_network_state_normalize(input, state, sizeof(state))) return 0;
    for (size_t i = 0; i < sizeof(states) / sizeof(states[0]); i++) if (!strcmp(state, states[i])) return 1;
    return 0;
}
#endif
