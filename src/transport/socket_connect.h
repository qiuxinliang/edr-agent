#ifndef EDR_SOCKET_CONNECT_H
#define EDR_SOCKET_CONNECT_H

/* Private transport boundary, shared with the native socket regression. */
#include <errno.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
typedef SOCKET EdrSocket;
#define EDR_SOCKET_INVALID INVALID_SOCKET
#else
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/time.h>
typedef int EdrSocket;
#define EDR_SOCKET_INVALID (-1)
#endif

static int socket_set_nonblocking(EdrSocket fd, int enabled) {
#ifdef _WIN32
  u_long mode = enabled ? 1ul : 0ul;
  return ioctlsocket(fd, FIONBIO, &mode) == 0 ? 0 : -1;
#else
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0) return -1;
  if (enabled) flags |= O_NONBLOCK;
  else flags &= ~O_NONBLOCK;
  return fcntl(fd, F_SETFL, flags) == 0 ? 0 : -1;
#endif
}

static int socket_connect_with_timeout(EdrSocket fd, const struct sockaddr *addr,
                                       int addr_len, int timeout_ms) {
  if (socket_set_nonblocking(fd, 1) != 0) {
    return -1;
  }
  if (connect(fd, addr, addr_len) == 0) {
    return socket_set_nonblocking(fd, 0);
  }
#ifdef _WIN32
  if (WSAGetLastError() != WSAEWOULDBLOCK && WSAGetLastError() != WSAEINPROGRESS) {
    (void)socket_set_nonblocking(fd, 0);
    return -1;
  }
#else
  if (errno != EINPROGRESS && errno != EWOULDBLOCK) {
    (void)socket_set_nonblocking(fd, 0);
    return -1;
  }
#endif
  fd_set writable, failed;
  struct timeval timeout;
  FD_ZERO(&writable);
  FD_SET(fd, &writable);
  FD_ZERO(&failed);
  FD_SET(fd, &failed);
  timeout.tv_sec = timeout_ms / 1000;
  timeout.tv_usec = (timeout_ms % 1000) * 1000;
  /* Winsock reports refused nonblocking connects through exceptfds.
   * Waiting only for writefds turns each refused address into a full timeout. */
  int selected = select((int)fd + 1, NULL, &writable, &failed, &timeout);
  int socket_error = 0;
#ifdef _WIN32
  int error_len = (int)sizeof(socket_error);
#else
  socklen_t error_len = (socklen_t)sizeof(socket_error);
#endif
  if (selected <= 0 || (!FD_ISSET(fd, &writable) && !FD_ISSET(fd, &failed)) ||
      getsockopt(fd, SOL_SOCKET, SO_ERROR, (char *)&socket_error, &error_len) != 0 ||
      socket_error != 0 || !FD_ISSET(fd, &writable)) {
    (void)socket_set_nonblocking(fd, 0);
    return -1;
  }
  return socket_set_nonblocking(fd, 0);
}

#endif
