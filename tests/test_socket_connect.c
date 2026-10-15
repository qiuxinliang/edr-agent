#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
typedef SOCKET TestSocket;
typedef int TestSocklen;
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
typedef int TestSocket;
typedef socklen_t TestSocklen;
#endif

enum Scenario {
  NATIVE_IO, IMMEDIATE_SUCCESS, IMMEDIATE_FAILURE, WRITABLE_SUCCESS,
  WRITABLE_REFUSED, EXCEPTION_REFUSED, EXCEPTION_WITHOUT_ERROR,
  SO_ERROR_FAILURE, SELECT_TIMEOUT, SELECT_FAILURE, NOT_READY
};
static enum Scenario scenario;
static TestSocket current_socket;
static int select_calls, error_calls;
#ifdef _WIN32
static u_long blocking_mode;
static int test_ioctlsocket(SOCKET fd, long command, u_long *value) {
  int result = ioctlsocket(fd, command, value);
  if (result == 0 && command == (long)FIONBIO) blocking_mode = *value;
  return result;
}
#endif

static int test_connect(TestSocket fd, const struct sockaddr *addr, int len) {
  if (scenario == NATIVE_IO) return connect(fd, addr, len);
  if (scenario == IMMEDIATE_SUCCESS) return 0;
#ifdef _WIN32
  WSASetLastError(scenario == IMMEDIATE_FAILURE ? WSAECONNREFUSED : WSAEWOULDBLOCK);
#else
  errno = scenario == IMMEDIATE_FAILURE ? ECONNREFUSED : EINPROGRESS;
#endif
  return -1;
}

static int test_select(int nfds, fd_set *readable, fd_set *writable,
                       fd_set *failed, struct timeval *timeout) {
  if (scenario == NATIVE_IO)
    return select(nfds, readable, writable, failed, timeout);
  ++select_calls;
  assert(readable == NULL);
  assert(writable && FD_ISSET(current_socket, writable));
  /* Reproduces the WinSock contract even on a POSIX test host. */
  assert(failed && FD_ISSET(current_socket, failed));
  assert(timeout && timeout->tv_sec == 1 && timeout->tv_usec == 234000);
  FD_ZERO(writable);
  FD_ZERO(failed);
  if (scenario == SELECT_TIMEOUT) return 0;
  if (scenario == SELECT_FAILURE) return -1;
  if (scenario == NOT_READY) return 1;
  if (scenario == EXCEPTION_REFUSED || scenario == EXCEPTION_WITHOUT_ERROR)
    FD_SET(current_socket, failed);
  else
    FD_SET(current_socket, writable);
  return 1;
}

static int test_getsockopt(TestSocket fd, int level, int option,
                           char *value, TestSocklen *len) {
  int socket_error;
  if (scenario == NATIVE_IO) return getsockopt(fd, level, option, value, len);
  ++error_calls;
  assert(fd == current_socket && level == SOL_SOCKET && option == SO_ERROR);
  assert(*len == sizeof(socket_error));
  if (scenario == SO_ERROR_FAILURE) return -1;
  socket_error = (scenario == WRITABLE_REFUSED || scenario == EXCEPTION_REFUSED)
#ifdef _WIN32
      ? WSAECONNREFUSED : 0;
#else
      ? ECONNREFUSED : 0;
#endif
  memcpy(value, &socket_error, sizeof(socket_error));
  return 0;
}

/* Compile the production helper, replacing only its external socket I/O. */
#define connect test_connect
#define select test_select
#define getsockopt test_getsockopt
#ifdef _WIN32
#define ioctlsocket test_ioctlsocket
#endif
#include "socket_connect.h"
#undef connect
#undef select
#undef getsockopt
#ifdef _WIN32
#undef ioctlsocket
#endif

static void close_socket(TestSocket fd) {
#ifdef _WIN32
  assert(closesocket(fd) == 0);
#else
  assert(close(fd) == 0);
#endif
}

static void assert_blocking(TestSocket fd) {
#ifdef _WIN32
  (void)fd;
  assert(blocking_mode == 0);
#else
  int flags = fcntl(fd, F_GETFL, 0);
  assert(flags >= 0 && !(flags & O_NONBLOCK));
#endif
}

static double monotonic_ms(void) {
#ifdef _WIN32
  return (double)GetTickCount64();
#else
  struct timespec ts;
  assert(clock_gettime(CLOCK_MONOTONIC, &ts) == 0);
  return ts.tv_sec * 1000.0 + ts.tv_nsec / 1000000.0;
#endif
}

int main(void) {
  struct sockaddr_in address;
  TestSocklen address_len = sizeof(address);
  TestSocket listener, client, accepted;
  double started;
#ifdef _WIN32
  WSADATA data;
  assert(WSAStartup(MAKEWORD(2, 2), &data) == 0);
#endif
  memset(&address, 0, sizeof(address));
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

  for (scenario = IMMEDIATE_SUCCESS; scenario <= NOT_READY; ++scenario) {
    int expected = scenario == IMMEDIATE_SUCCESS || scenario == WRITABLE_SUCCESS ? 0 : -1;
    current_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    assert(current_socket != EDR_SOCKET_INVALID);
    select_calls = error_calls = 0;
    assert(socket_connect_with_timeout(current_socket, (struct sockaddr *)&address,
                                       sizeof(address), 1234) == expected);
    assert_blocking(current_socket);
    assert(select_calls == (scenario >= WRITABLE_SUCCESS ? 1 : 0));
    assert(error_calls == (scenario >= WRITABLE_SUCCESS && scenario <= SO_ERROR_FAILURE ? 1 : 0));
    close_socket(current_socket);
  }

  scenario = NATIVE_IO;
  listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  assert(listener != EDR_SOCKET_INVALID);
  /* Obtain a closed loopback port. A bound, non-listening socket may silently
   * drop SYNs on some hosts, which would test timeout rather than refusal. */
  assert(bind(listener, (struct sockaddr *)&address, sizeof(address)) == 0);
  assert(getsockname(listener, (struct sockaddr *)&address, &address_len) == 0);
  close_socket(listener);
  client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  assert(client != EDR_SOCKET_INVALID);
  started = monotonic_ms();
  assert(socket_connect_with_timeout(client, (struct sockaddr *)&address,
                                     sizeof(address), 10000) == -1);
  assert_blocking(client);
  /* A refused connect must complete well before its ten-second deadline. */
  assert(monotonic_ms() - started < 5000.0);
  close_socket(client);

  listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  assert(listener != EDR_SOCKET_INVALID);
  address.sin_port = 0;
  assert(bind(listener, (struct sockaddr *)&address, sizeof(address)) == 0);
  assert(getsockname(listener, (struct sockaddr *)&address, &address_len) == 0);
  assert(listen(listener, 1) == 0);
  client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  assert(client != EDR_SOCKET_INVALID);
  assert(socket_connect_with_timeout(client, (struct sockaddr *)&address,
                                     sizeof(address), 3000) == 0);
  assert_blocking(client);
  accepted = accept(listener, NULL, NULL);
  assert(accepted != EDR_SOCKET_INVALID);
  assert(send(client, "ok", 2, 0) == 2);
  {
    char received[2];
    assert(recv(accepted, received, sizeof(received), MSG_WAITALL) == 2);
    assert(memcmp(received, "ok", 2) == 0);
  }
  close_socket(accepted);
  close_socket(client);
  close_socket(listener);
#ifdef _WIN32
  assert(WSACleanup() == 0);
#endif
  puts("Socket connect success, refusal, readiness, timeout and error contracts passed");
  return 0;
}
