#include "edr/shell_session.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static char s_output[32768];
static size_t s_output_len;
static size_t s_max_chunk;

static void capture_output(const char *session_id, uint64_t seq, const char *data, size_t len,
                           int exit_code, bool closed, void *user) {
  (void)session_id;
  (void)seq;
  (void)exit_code;
  (void)closed;
  (void)user;
  if (!data || len == 0u) return;
  if (len > s_max_chunk) s_max_chunk = len;
  size_t remaining = sizeof(s_output) - 1u - s_output_len;
  size_t copy_len = len < remaining ? len : remaining;
  memcpy(s_output + s_output_len, data, copy_len);
  s_output_len += copy_len;
  s_output[s_output_len] = '\0';
}

static void require_true(int condition, const char *message) {
  if (condition) return;
  fprintf(stderr, "FAIL: %s (bytes=%zu max_chunk=%zu)\n",
          message, s_output_len, s_max_chunk);
  exit(1);
}

int main(void) {
  const char *session_id = "test-shell-stream";
  const char command[] =
      "printf 'BEGIN-RTR\\n'; i=0; while [ $i -lt 12000 ]; do printf A; "
      "i=$((i+1)); done; printf '\\nEND-RTR\\n'\n";

  edr_shell_session_init(1u, 10u, EDR_SS_BUF_KB, capture_output, NULL);
  require_true(edr_shell_session_open(session_id, "/bin/sh") == 0,
               "open test shell session");
  require_true(edr_shell_session_input(session_id, command, sizeof(command) - 1u) == 0,
               "write long shell command");

  for (int i = 0; i < 500 && strstr(s_output, "END-RTR") == NULL; i++) {
    edr_shell_session_poll();
    usleep(10000u);
  }

  require_true(strstr(s_output, "BEGIN-RTR") != NULL, "receive beginning of long output");
  require_true(strstr(s_output, "END-RTR") != NULL, "receive end of long output");
  require_true(s_output_len >= 12000u, "receive complete long output body");
  require_true(s_max_chunk <= EDR_SS_STREAM_CHUNK_BYTES,
               "stream chunks fit durable command result capacity");

  edr_shell_session_close(session_id);
  edr_shell_session_shutdown();
  puts("ok");
  return 0;
}
