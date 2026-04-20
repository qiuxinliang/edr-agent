#include "fl_http_upload.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
static int fl_net_init(void) {
  WSADATA w;
  return WSAStartup(MAKEWORD(2, 2), &w);
}
static void fl_net_done(void) {
  WSACleanup();
}
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
static int fl_net_init(void) {
  return 0;
}
static void fl_net_done(void) {}
#endif

#ifdef EDR_HAVE_OPENSSL_FL
#include <openssl/opensslv.h>
#include <openssl/ssl.h>
#endif

static int parse_http_url(const char *url, char *host, size_t host_cap, char *path, size_t path_cap,
                          int *out_port, int *out_https) {
  const char *p;
  *out_https = 0;
  *out_port = 80;
  if (!url || strncmp(url, "http://", 7u) == 0) {
    p = url + 7;
  } else if (strncmp(url, "https://", 8u) == 0) {
    p = url + 8;
    *out_https = 1;
    *out_port = 443;
  } else {
    return -1;
  }
  {
    const char *slash = strchr(p, '/');
    const char *colon = strchr(p, ':');
    size_t host_len;
    if (colon && slash && colon < slash) {
      host_len = (size_t)(colon - p);
      if (host_len >= host_cap) {
        return -1;
      }
      memcpy(host, p, host_len);
      host[host_len] = '\0';
      *out_port = atoi(colon + 1);
    } else if (slash) {
      host_len = (size_t)(slash - p);
      if (host_len >= host_cap) {
        return -1;
      }
      memcpy(host, p, host_len);
      host[host_len] = '\0';
    } else {
      snprintf(host, host_cap, "%s", p);
    }
    if (slash) {
      snprintf(path, path_cap, "%s", slash);
    } else {
      snprintf(path, path_cap, "/");
    }
  }
  return 0;
}

static int tcp_connect_host(const char *host, int port, int *out_fd) {
  struct addrinfo hints;
  struct addrinfo *res = NULL;
  char portstr[16];
  int fd = -1;

  memset(&hints, 0, sizeof(hints));
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_family = AF_UNSPEC;
  snprintf(portstr, sizeof(portstr), "%d", port);
  if (getaddrinfo(host, portstr, &hints, &res) != 0 || !res) {
    return -1;
  }
#ifdef _WIN32
  fd = (int)socket(res->ai_family, res->ai_socktype, res->ai_protocol);
#else
  fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
#endif
  if (fd < 0) {
    freeaddrinfo(res);
    return -1;
  }
  if (connect(fd, res->ai_addr, (int)res->ai_addrlen) != 0) {
    freeaddrinfo(res);
#ifdef _WIN32
    closesocket(fd);
#else
    close(fd);
#endif
    return -1;
  }
  freeaddrinfo(res);
  *out_fd = fd;
  return 0;
}

static int send_recv_http_payload(int fd, void *ssl_or_null, const char *host, const char *path,
                                  const char *content_type, const char *body, size_t body_len) {
  char req[65536];
  int sn;
  (void)host;

  sn = snprintf(req, sizeof(req),
                "POST %s HTTP/1.1\r\n"
                "Host: %s\r\n"
                "Content-Type: %s\r\n"
                "Content-Length: %zu\r\n"
                "Connection: close\r\n"
                "\r\n",
                path, host, content_type ? content_type : "application/json", body_len);
  if (sn <= 0 || (size_t)sn >= sizeof(req)) {
    return -1;
  }

#ifdef EDR_HAVE_OPENSSL_FL
  if (ssl_or_null) {
    SSL *ssl = (SSL *)ssl_or_null;
    if (SSL_write(ssl, req, sn) <= 0) {
      return -1;
    }
    if (body_len > 0u && SSL_write(ssl, body, body_len) <= 0) {
      return -1;
    }
    {
      char buf[4096];
      int n = SSL_read(ssl, buf, (int)sizeof(buf) - 1);
      if (n > 0) {
        return 0;
      }
    }
    return 0;
  }
#else
  (void)ssl_or_null;
#endif

  if (send(fd, req, (size_t)sn, 0) < 0) {
    return -1;
  }
  if (body_len > 0u && send(fd, body, body_len, 0) < 0) {
    return -1;
  }
  {
    char buf[4096];
    int n = recv(fd, buf, sizeof(buf) - 1, 0);
    if (n > 0) {
      return 0;
    }
  }
  return 0;
}

#ifdef EDR_HAVE_OPENSSL_FL
static int fl_https_post_openssl(const char *host, int port, const char *path, const char *content_type,
                                 const char *body, size_t body_len) {
  SSL_CTX *ctx = NULL;
  SSL *ssl = NULL;
  int fd = -1;
  int ret = -1;
  const char *insec = getenv("EDR_FL_HTTPS_INSECURE");
  const char *cafile = getenv("EDR_FL_HTTPS_CA_FILE");

  OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  ctx = SSL_CTX_new(TLS_client_method());
#else
  ctx = SSL_CTX_new(SSLv23_client_method());
#endif
  if (!ctx) {
    return -1;
  }
  if (cafile && cafile[0]) {
    (void)SSL_CTX_load_verify_locations(ctx, cafile, NULL);
  } else {
    (void)SSL_CTX_set_default_verify_paths(ctx);
  }
  if (insec && insec[0] == '1') {
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
  } else {
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
  }

  if (tcp_connect_host(host, port, &fd) != 0) {
    SSL_CTX_free(ctx);
    return -1;
  }

  ssl = SSL_new(ctx);
  if (!ssl) {
    goto done_sock;
  }
  SSL_set_fd(ssl, fd);
  if (!SSL_set_tlsext_host_name(ssl, host)) {
    goto done_ssl;
  }

  if (SSL_connect(ssl) != 1) {
    goto done_ssl;
  }

  ret = send_recv_http_payload(fd, ssl, host, path, content_type, body, body_len);

done_ssl:
  if (ssl) {
    SSL_shutdown(ssl);
    SSL_free(ssl);
  }
done_sock:
#ifdef _WIN32
  if (fd >= 0) {
    closesocket(fd);
  }
#else
  if (fd >= 0) {
    close(fd);
  }
#endif
  SSL_CTX_free(ctx);
  return ret;
}
#endif

int fl_http_post_body(const char *url, const char *content_type, const char *body, size_t body_len) {
  char host[256];
  char path[512];
  int port;
  int https;
  int fd = -1;
  int ret = -1;

  if (!url || !body || body_len > 4000000u) {
    return -1;
  }
  if (parse_http_url(url, host, sizeof(host), path, sizeof(path), &port, &https) != 0) {
    return -1;
  }
  if (https) {
#ifdef EDR_HAVE_OPENSSL_FL
    return fl_https_post_openssl(host, port, path, content_type, body, body_len);
#else
    (void)content_type;
    return -1;
#endif
  }

  if (fl_net_init() != 0) {
    return -1;
  }
  if (tcp_connect_host(host, port, &fd) != 0) {
    fl_net_done();
    return -1;
  }
  ret = send_recv_http_payload(fd, NULL, host, path, content_type, body, body_len);
#ifdef _WIN32
  if (fd >= 0) {
    closesocket(fd);
  }
#else
  if (fd >= 0) {
    close(fd);
  }
#endif
  fl_net_done();
  return ret;
}
