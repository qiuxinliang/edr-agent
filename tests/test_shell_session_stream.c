#include "edr/shell_session.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#include <io.h>
#define TEST_SHELL "cmd.exe /D /Q"
#else
#include <pthread.h>
#include <unistd.h>
#include <time.h>
#define TEST_SHELL "/bin/sh"
#endif

static uint64_t test_now_ms(void) {
#ifdef _WIN32
  return GetTickCount64();
#else
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
#endif
}

static void test_sleep_ms(unsigned milliseconds) {
#ifdef _WIN32
  Sleep(milliseconds);
#else
  usleep(milliseconds * 1000u);
#endif
}

static char s_output[32768];
static size_t s_output_len;
static size_t s_max_chunk;
#ifndef _WIN32
static volatile int s_poll_running;
#endif

static int capture_output(const char *session_id, uint64_t seq, const char *data, size_t len,
                           int exit_code, bool closed, const EdrCommandResultAuthorization *authorization, void *user) {
  (void)session_id;
  (void)seq;
  (void)exit_code;
  (void)closed;
  (void)user;
  if (!authorization || strcmp(authorization->command_id, session_id) ||
      strcmp(authorization->tenant_id, "synthetic-tenant")) {
    fputs("FAIL: session lost its original result authority\n", stderr); exit(1);
  }
  if (!data || len == 0u) return 0;
  if (len > s_max_chunk) s_max_chunk = len;
  size_t remaining = sizeof(s_output) - 1u - s_output_len;
  size_t copy_len = len < remaining ? len : remaining;
  memcpy(s_output + s_output_len, data, copy_len);
  s_output_len += copy_len;
  s_output[s_output_len] = '\0';
  return 0;
}

static void require_true(int condition, const char *message) {
  if (condition) return;
  fprintf(stderr, "FAIL: %s (bytes=%zu max_chunk=%zu)\n",
          message, s_output_len, s_max_chunk);
  exit(1);
}

#ifndef _WIN32
static void *poll_sessions(void *unused) {
  (void)unused;
  while (s_poll_running) {
    edr_shell_session_poll();
    usleep(1000u);
  }
  return NULL;
}

static void exercise_concurrent_lifecycle(void) {
  pthread_t poll_thread;
  const char input[] = "printf 'rtr-race-check\\n'\n";

  edr_shell_session_init(2u, 10u, EDR_SS_BUF_KB, capture_output, NULL);
  s_poll_running = 1;
  require_true(pthread_create(&poll_thread, NULL, poll_sessions, NULL) == 0,
               "start concurrent shell poll thread");

  for (int i = 0; i < 50; i++) {
    char session_id[64];
    snprintf(session_id, sizeof(session_id), "test-shell-race-%d", i);
    EdrCommandResultAuthorization authority = {0};
    snprintf(authority.command_id, sizeof(authority.command_id), "%s", session_id);
    snprintf(authority.tenant_id, sizeof(authority.tenant_id), "synthetic-tenant");
    require_true(edr_shell_session_open(session_id, "/bin/sh", &authority) == 0,
                 "open shell while poll thread is active");
    require_true(edr_shell_session_input(session_id, input, sizeof(input) - 1u) == 0,
                 "write shell while poll thread is active");
    usleep(2000u);
    edr_shell_session_close(session_id);
  }

  s_poll_running = 0;
  require_true(pthread_join(poll_thread, NULL) == 0,
               "join concurrent shell poll thread");
  edr_shell_session_shutdown();
}
#endif

typedef struct {
  bool allow_data, allow_closed, first_pending;
  char pending[EDR_SS_STREAM_CHUNK_BYTES];
  size_t pending_len;
  uint64_t pending_seq, next_seq, first_refusal_ms;
  unsigned data_attempts, closed_attempts, accepted_chunks, closed_accepted;
  int closed_exit_code;
  char output[32768];
  size_t output_len;
} PressureCapture;

static int capture_pressure(const char *id, uint64_t seq, const char *data, size_t len,
    int exit_code, bool closed, const EdrCommandResultAuthorization *authority, void *user) {
  PressureCapture *capture = (PressureCapture *)user;
  require_true(authority && !strcmp(authority->command_id, id) &&
      !strcmp(authority->tenant_id, "synthetic-tenant"), "pressure retry retains authority");
  require_true(seq == capture->next_seq, "refusal does not consume or skip a sequence");
  if (closed) {
    require_true(data == NULL && len == 0u, "close has no substituted output");
    require_true(!capture->first_pending, "close follows acceptance of pending data");
    if (capture->closed_attempts) {
      require_true(capture->closed_exit_code == exit_code, "close retry retains exit status");
    }
    capture->closed_exit_code = exit_code;
    capture->closed_attempts++;
    if (!capture->allow_closed) return -1;
    capture->closed_accepted++;
    capture->next_seq++;
    return 0;
  }
  require_true(data && len > 0u && len <= EDR_SS_STREAM_CHUNK_BYTES,
      "each pending data chunk has a finite durable size");
  if (!capture->accepted_chunks) {
    capture->data_attempts++;
    if (!capture->first_pending) {
      capture->first_pending = true;
      capture->pending_seq = seq;
      capture->pending_len = len;
      memcpy(capture->pending, data, len);
      capture->first_refusal_ms = test_now_ms();
    } else {
      require_true(capture->pending_seq == seq && capture->pending_len == len &&
          !memcmp(capture->pending, data, len), "retry preserves every byte of original chunk");
    }
    if (!capture->allow_data) return -1;
    capture->first_pending = false;
  }
  require_true(capture->allow_data, "no later data overtakes a refused chunk");
  require_true(capture->output_len + len < sizeof(capture->output), "bounded test capture");
  memcpy(capture->output + capture->output_len, data, len);
  capture->output_len += len;
  capture->output[capture->output_len] = '\0';
  capture->accepted_chunks++;
  capture->next_seq++;
  return 0;
}

static void poll_for_ms(unsigned duration) {
  uint64_t until = test_now_ms() + duration;
  do {
    edr_shell_session_poll();
    test_sleep_ms(2u);
  } while (test_now_ms() < until);
}

static EdrCommandResultAuthorization test_authority(const char *id) {
  EdrCommandResultAuthorization authority = {0};
  snprintf(authority.command_id, sizeof(authority.command_id), "%s", id);
  snprintf(authority.tenant_id, sizeof(authority.tenant_id), "synthetic-tenant");
  return authority;
}

static void exercise_durable_pressure(void) {
  const char *id = "test-shell-pressure";
  EdrCommandResultAuthorization authority = test_authority(id);
  PressureCapture capture = {0};
  capture.next_seq = 1u;
#ifdef _WIN32
  const char command[] = "echo BEGIN-PRESSURE\r\n"
      "for /L %i in (1,1,30) do @echo "
      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n"
      "echo END-PRESSURE\r\nexit 7\r\n";
  const char denied_input[] = "echo MUST-NOT-RUN\r\n";
#else
  const char command[] = "printf 'BEGIN-PRESSURE\\n'; i=0; while [ $i -lt 3000 ]; do "
      "printf A; i=$((i+1)); done; printf '\\nEND-PRESSURE\\n'; exit 7\n";
  const char denied_input[] = "printf 'MUST-NOT-RUN\\n'\n";
#endif
  edr_shell_session_init(1u, 15u, EDR_SS_BUF_KB, capture_pressure, &capture);
  require_true(edr_shell_session_open(id, TEST_SHELL, &authority) == 0, "open pressure shell");
  require_true(edr_shell_session_input(id, command, sizeof(command)-1u) == 0, "start finite output producer");
  uint64_t deadline = test_now_ms() + 5000u;
  while (!capture.data_attempts && test_now_ms() < deadline) poll_for_ms(10u);
  require_true(capture.data_attempts == 1u, "observe first durable refusal");
  require_true(edr_shell_session_input(id, denied_input, sizeof(denied_input)-1u) != 0,
      "pressure rejects new input");
  require_true(edr_shell_session_active_count() == 1u, "pending data retains session ownership");
  poll_for_ms(850u);
  require_true(capture.data_attempts >= 2u && capture.data_attempts <= 4u,
      "hundreds of polls produce bounded backoff retries");
  require_true(capture.accepted_chunks == 0u && capture.output_len == 0u &&
      capture.closed_attempts == 0u, "refused output cannot advance to later data or close");
  unsigned refused_attempts = capture.data_attempts;
  capture.allow_data = true;
  deadline = test_now_ms() + 7000u;
  while (!capture.closed_attempts && test_now_ms() < deadline) poll_for_ms(10u);
  require_true(capture.closed_attempts == 1u, "drain exited child before close refusal");
  require_true(capture.closed_exit_code == 7, "retain actual child exit code after backpressure");
  char *begin = strstr(capture.output, "BEGIN-PRESSURE");
  char *end = strstr(capture.output, "END-PRESSURE");
  require_true(begin && end && end > begin, "both output boundaries survive pressure");
  size_t body_bytes = 0u;
  for (char *p = begin + strlen("BEGIN-PRESSURE"); p < end; p++) if (*p == 'A') body_bytes++;
  require_true(body_bytes == 3000u, "all original output bytes survive process exit");
  require_true(strstr(capture.output, "MUST-NOT-RUN") == NULL, "refused input never executes");
  require_true(capture.accepted_chunks >= 2u, "exited child output drains across bounded chunks");
  require_true(edr_shell_session_active_count() == 1u && capture.closed_accepted == 0u,
      "undurable close retains the only session slot");
  require_true(edr_shell_session_open("must-not-reuse-slot", TEST_SHELL, &authority) != 0,
      "new session cannot replace undurable close");
  require_true(edr_shell_session_input(id, denied_input, sizeof(denied_input)-1u) != 0,
      "closed but undurable session rejects input");
  poll_for_ms(850u);
  require_true(capture.closed_attempts >= 2u && capture.closed_attempts <= 4u &&
      edr_shell_session_active_count() == 1u, "close retries back off while keeping ownership");
  capture.allow_closed = true;
  deadline = test_now_ms() + 5000u;
  while (edr_shell_session_active_count() && test_now_ms() < deadline) poll_for_ms(10u);
  require_true(capture.closed_accepted == 1u && edr_shell_session_active_count() == 0u,
      "slot releases only after durable close acceptance");
  require_true(edr_shell_session_open(id, TEST_SHELL, &authority) == 0, "accepted close permits slot reuse");
  edr_shell_session_close(id);
  edr_shell_session_shutdown();
  printf("pressure: data refusals=%u close attempts=%u complete body=%zu bytes\n",
      refused_attempts, capture.closed_attempts, body_bytes);
}

static void exercise_timeout_during_pressure(void) {
  const char *id = "test-shell-pressure-timeout";
  EdrCommandResultAuthorization authority = test_authority(id);
  PressureCapture capture = {0};
  capture.next_seq = 1u;
  capture.allow_closed = true;
#ifdef _WIN32
  const char command[] = "echo TIMEOUT-PENDING\r\n";
#else
  const char command[] = "printf 'TIMEOUT-PENDING\\n'\n";
#endif
  edr_shell_session_init(1u, 1u, EDR_SS_BUF_KB, capture_pressure, &capture);
  require_true(edr_shell_session_open(id, TEST_SHELL, &authority) == 0, "open pressure timeout shell");
  require_true(edr_shell_session_input(id, command, sizeof(command)-1u) == 0, "start timeout producer");
  uint64_t deadline = test_now_ms() + 5000u;
  while (!capture.data_attempts && test_now_ms() < deadline) poll_for_ms(10u);
  require_true(capture.data_attempts > 0u, "timeout test sees initial output");
  poll_for_ms(1400u);
  require_true(capture.accepted_chunks == 0u && edr_shell_session_active_count() == 1u,
      "timeout cannot discard pending output or its session slot");
  capture.allow_data = true;
  deadline = test_now_ms() + 5000u;
  while (edr_shell_session_active_count() && test_now_ms() < deadline) poll_for_ms(10u);
  require_true(capture.closed_accepted == 1u && capture.closed_exit_code != 0 &&
      strstr(capture.output, "TIMEOUT-PENDING") != NULL,
      "timeout stops producer yet delivers pending bytes before terminal status");
  edr_shell_session_shutdown();
}

#ifdef _WIN32
/* This child uses real inherited pipe handles and OS process lifetime. The
 * independent events let the parent prove the pipe is closed while the child
 * is still waiting, without replacing PeekNamedPipe or process APIs. */
static int child_close_output_then_wait(const char *closed_name, const char *release_name) {
  HANDLE closed = OpenEventA(EVENT_MODIFY_STATE, FALSE, closed_name);
  HANDLE release = OpenEventA(SYNCHRONIZE, FALSE, release_name);
  if (!closed || !release) return 91;
  HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
  HANDLE error = GetStdHandle(STD_ERROR_HANDLE);
  /* The CRT can own separate inherited descriptors for these handles. Close
   * those too so the parent really observes a broken pipe, not an empty one. */
  _close(_fileno(stdout));
  _close(_fileno(stderr));
  if (output && output != INVALID_HANDLE_VALUE) CloseHandle(output);
  if (error && error != INVALID_HANDLE_VALUE && error != output) CloseHandle(error);
  SetStdHandle(STD_OUTPUT_HANDLE, NULL);
  SetStdHandle(STD_ERROR_HANDLE, NULL);
  if (!SetEvent(closed)) return 92;
  DWORD waited = WaitForSingleObject(release, 10000u);
  CloseHandle(closed);
  CloseHandle(release);
  return waited == WAIT_OBJECT_0 ? 7 : 93;
}

static void exercise_closed_pipe_before_exit(bool timeout) {
  const char *id = timeout ? "test-closed-pipe-timeout" : "test-closed-pipe-still-active";
  EdrCommandResultAuthorization authority = test_authority(id);
  PressureCapture capture = {0};
  capture.next_seq = 1u;
  capture.allow_data = true;
  capture.allow_closed = true;
  char executable[32768], closed_name[160], release_name[176], command[33120];
  DWORD path_length = GetModuleFileNameA(NULL, executable, sizeof(executable));
  require_true(path_length > 0u && path_length < sizeof(executable), "locate real test child executable");
  snprintf(closed_name, sizeof(closed_name), "Local\\edr-shell-pipe-closed-%lu-%llu-%u",
      (unsigned long)GetCurrentProcessId(), (unsigned long long)GetTickCount64(), timeout ? 1u : 0u);
  snprintf(release_name, sizeof(release_name), "%s-release", closed_name);
  HANDLE closed = CreateEventA(NULL, TRUE, FALSE, closed_name);
  HANDLE release = CreateEventA(NULL, TRUE, FALSE, release_name);
  require_true(closed && release, "create bounded child synchronization events");
  int command_length = snprintf(command, sizeof(command), "\"%s\" --close-output-child %s %s",
      executable, closed_name, release_name);
  require_true(command_length > 0 && (size_t)command_length < sizeof(command), "bound child command");
  edr_shell_session_init(1u, timeout ? 2u : 8u, EDR_SS_BUF_KB, capture_pressure, &capture);
  require_true(edr_shell_session_open(id, command, &authority) == 0, "open real close-output child");
  uint64_t deadline = test_now_ms() + 5000u;
  while (WaitForSingleObject(closed, 0u) != WAIT_OBJECT_0 && test_now_ms() < deadline) {
    poll_for_ms(5u);
  }
  require_true(WaitForSingleObject(closed, 0u) == WAIT_OBJECT_0,
      "child actually closes pipe handles before waiting");
  poll_for_ms(200u);
  require_true(capture.closed_attempts == 0u && edr_shell_session_active_count() == 1u,
      "pipe failure cannot manufacture successful exit or release a running child's Job");
  if (!timeout) require_true(SetEvent(release) != 0, "allow child to finish with real exit code");
  deadline = test_now_ms() + 6000u;
  while (edr_shell_session_active_count() && test_now_ms() < deadline) poll_for_ms(10u);
  require_true(capture.closed_accepted == 1u && edr_shell_session_active_count() == 0u &&
      capture.closed_exit_code == (timeout ? 1 : 7), "close reports actual exit or timeout status");
  CloseHandle(closed);
  CloseHandle(release);
  edr_shell_session_shutdown();
  printf("closed pipe: running owner retained; %s exit=%d\n",
      timeout ? "timeout" : "normal", capture.closed_exit_code);
}
#endif

int main(int argc, char **argv) {
#ifdef _WIN32
  if (argc == 4 && !strcmp(argv[1], "--close-output-child")) {
    return child_close_output_then_wait(argv[2], argv[3]);
  }
#else
  (void)argc;
  (void)argv;
#endif
  const char *session_id = "test-shell-stream";
  EdrCommandResultAuthorization authority = {0};
  snprintf(authority.command_id, sizeof(authority.command_id), "%s", session_id);
  snprintf(authority.tenant_id, sizeof(authority.tenant_id), "synthetic-tenant");
#ifdef _WIN32
  const char command[] = "echo BEGIN-RTR\r\nfor /L %i in (1,1,120) do @echo "
      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\necho END-RTR\r\n";
#else
  const char command[] =
      "printf 'BEGIN-RTR\\n'; i=0; while [ $i -lt 12000 ]; do printf A; "
      "i=$((i+1)); done; printf '\\nEND-RTR\\n'\n";
#endif

  edr_shell_session_init(1u, 10u, EDR_SS_BUF_KB, capture_output, NULL);
  require_true(edr_shell_session_open(session_id, TEST_SHELL, &authority) == 0,
               "open test shell session");
  require_true(edr_shell_session_input(session_id, command, sizeof(command) - 1u) == 0,
               "write long shell command");

  for (int i = 0; i < 500 && strstr(s_output, "END-RTR") == NULL; i++) {
    edr_shell_session_poll();
    test_sleep_ms(10u);
  }

  require_true(strstr(s_output, "BEGIN-RTR") != NULL, "receive beginning of long output");
  require_true(strstr(s_output, "END-RTR") != NULL, "receive end of long output");
  require_true(s_output_len >= 12000u, "receive complete long output body");
  require_true(s_max_chunk <= EDR_SS_STREAM_CHUNK_BYTES,
               "stream chunks fit durable command result capacity");

  edr_shell_session_close(session_id);
  edr_shell_session_shutdown();
#ifndef _WIN32
  exercise_concurrent_lifecycle();
#endif
  exercise_durable_pressure();
  exercise_timeout_during_pressure();
#ifdef _WIN32
  exercise_closed_pipe_before_exit(false);
  exercise_closed_pipe_before_exit(true);
#endif
  puts("ok");
  return 0;
}
