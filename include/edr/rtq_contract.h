#ifndef EDR_RTQ_CONTRACT_H
#define EDR_RTQ_CONTRACT_H

#include <ctype.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

// cJSON strings use NUL termination. Reject encoded NUL before decoding so a
// signed predicate cannot be shortened by string consumers after validation.
static inline int rtq_payload_text_valid(const uint8_t *payload, size_t length) {
  for (size_t i = 0; i < length; i++) {
    unsigned char first = payload[i];
    if (!first) return 0;
    if (first < 0x80u) continue;
    size_t extra = first >= 0xc2u && first <= 0xdfu ? 1u :
                   first >= 0xe0u && first <= 0xefu ? 2u :
                   first >= 0xf0u && first <= 0xf4u ? 3u : 0u;
    if (!extra || i + extra >= length) return 0;
    unsigned char second = payload[i + 1u];
    if ((first == 0xe0u && second < 0xa0u) || (first == 0xedu && second >= 0xa0u) ||
        (first == 0xf0u && second < 0x90u) || (first == 0xf4u && second >= 0x90u)) return 0;
    for (size_t j = 1u; j <= extra; j++) {
      if ((payload[i + j] & 0xc0u) != 0x80u) return 0;
    }
    i += extra;
  }
  for (size_t i = 0; i + 1u < length; i++) {
    if (payload[i] != '\\') continue;
    if (i + 5u < length && payload[i + 1u] == 'u' &&
        !memcmp(payload + i + 2u, "0000", 4u)) return 0;
    i++; // Skip escaped backslashes, including literal "\\\\u0000" text.
  }
  return 1;
}

#define EDR_RTQ_PROCESS_BATCH_SCHEMA "edr.rtq.process-batch.v1"

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
