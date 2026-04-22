#include "edr/metrics_http.h"

#include "edr/event_bus.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include "edr/attack_surface_win_util.h"
#include "edr/shellcode_detector.h"

static volatile LONG s_metrics_run;
static HANDLE s_metrics_thread;
static SOCKET s_metrics_listen = INVALID_SOCKET;
static EdrEventBus *s_metrics_bus;

static int metrics_parse_bind(const char *bind, char *host, size_t host_cap, unsigned short *port_out) {
  if (!bind || !host || host_cap < 4u || !port_out) {
    return -1;
  }
  const char *colon = strrchr(bind, ':');
  if (!colon || colon == bind) {
    return -1;
  }
  size_t hl = (size_t)(colon - bind);
  if (hl == 0u || hl >= host_cap) {
    return -1;
  }
  memcpy(host, bind, hl);
  host[hl] = '\0';
  int p = atoi(colon + 1);
  if (p < 1 || p > 65535) {
    return -1;
  }
  *port_out = (unsigned short)p;
  return 0;
}

static int metrics_send_all(SOCKET c, const char *data, int len) {
  int sent = 0;
  while (sent < len) {
    int n = send(c, data + sent, len - sent, 0);
    if (n <= 0) {
      return -1;
    }
    sent += n;
  }
  return 0;
}

static DWORD WINAPI edr_metrics_thread_main(void *arg) {
  (void)arg;
  while (InterlockedCompareExchange(&s_metrics_run, 0, 0) != 0) {
    struct sockaddr_in cli;
    int clen = (int)sizeof(cli);
    SOCKET c = accept(s_metrics_listen, (struct sockaddr *)&cli, &clen);
    if (c == INVALID_SOCKET) {
      break;
    }
    char req[1024];
    int nr = recv(c, req, (int)sizeof(req) - 1, 0);
    if (nr <= 0) {
      closesocket(c);
      continue;
    }
    req[nr] = '\0';
    int want_metrics = (strstr(req, "GET /metrics") != NULL);
    int want_health = (strstr(req, "GET /health") != NULL || strstr(req, "GET / ") != NULL);
    if (!want_metrics && !want_health) {
      (void)metrics_send_all(c, "HTTP/1.1 404 Not Found\r\nConnection: close\r\nContent-Length: 0\r\n\r\n", 66);
      closesocket(c);
      continue;
    }
    if (want_health && !want_metrics) {
      (void)metrics_send_all(c, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nok\n", 76);
      closesocket(c);
      continue;
    }
    uint64_t dropped = 0, hw = 0;
    uint32_t cap = 0, used = 0;
    if (s_metrics_bus) {
      dropped = edr_event_bus_dropped_total(s_metrics_bus);
      hw = edr_event_bus_high_water_hits(s_metrics_bus);
      cap = edr_event_bus_capacity(s_metrics_bus);
      used = edr_event_bus_used_approx(s_metrics_bus);
    }
    unsigned long long rp = 0, re = 0, sk = 0, mf = 0, ap = 0, bd = 0, dd = 0;
    edr_shellcode_windivert_stats_snapshot(&rp, &re, &sk, &mf, &ap, &bd, &dd);
    char body[2048];
    int bl = snprintf(
        body, sizeof(body),
        "# HELP edr_event_bus_dropped_total Events dropped because the ring buffer was full.\n"
        "# TYPE edr_event_bus_dropped_total counter\n"
        "edr_event_bus_dropped_total %llu\n"
        "# HELP edr_event_bus_high_water_hits_total Times used slots reached >=80%% of capacity.\n"
        "# TYPE edr_event_bus_high_water_hits_total counter\n"
        "edr_event_bus_high_water_hits_total %llu\n"
        "# HELP edr_event_bus_capacity_slots Ring buffer capacity (slots).\n"
        "# TYPE edr_event_bus_capacity_slots gauge\n"
        "edr_event_bus_capacity_slots %u\n"
        "# HELP edr_event_bus_used_slots_approx Approximate used slots (see event_bus.c).\n"
        "# TYPE edr_event_bus_used_slots_approx gauge\n"
        "edr_event_bus_used_slots_approx %u\n"
        "# HELP edr_shellcode_windivert_recv_packets_total WinDivert recv packet count (§17).\n"
        "# TYPE edr_shellcode_windivert_recv_packets_total counter\n"
        "edr_shellcode_windivert_recv_packets_total %llu\n"
        "# HELP edr_shellcode_windivert_recv_errors_total WinDivert recv errors.\n"
        "# TYPE edr_shellcode_windivert_recv_errors_total counter\n"
        "edr_shellcode_windivert_recv_errors_total %llu\n"
        "# HELP edr_shellcode_windivert_rows_skipped_total Rows skipped in capture path.\n"
        "# TYPE edr_shellcode_windivert_rows_skipped_total counter\n"
        "edr_shellcode_windivert_rows_skipped_total %llu\n"
        "# HELP edr_shellcode_windivert_monitor_filtered_total Packets filtered by monitor_* toggles.\n"
        "# TYPE edr_shellcode_windivert_monitor_filtered_total counter\n"
        "edr_shellcode_windivert_monitor_filtered_total %llu\n"
        "# HELP edr_shellcode_windivert_alerts_pushed_total Shellcode alerts successfully pushed to bus.\n"
        "# TYPE edr_shellcode_windivert_alerts_pushed_total counter\n"
        "edr_shellcode_windivert_alerts_pushed_total %llu\n"
        "# HELP edr_shellcode_windivert_bus_drops_total Shellcode alerts dropped (bus full).\n"
        "# TYPE edr_shellcode_windivert_bus_drops_total counter\n"
        "edr_shellcode_windivert_bus_drops_total %llu\n"
        "# HELP edr_shellcode_windivert_alert_dedup_suppressed_total Dedup suppressed alerts (30s window).\n"
        "# TYPE edr_shellcode_windivert_alert_dedup_suppressed_total counter\n"
        "edr_shellcode_windivert_alert_dedup_suppressed_total %llu\n",
        (unsigned long long)dropped, (unsigned long long)hw, (unsigned)cap, (unsigned)used, rp, re, sk, mf, ap, bd, dd);
    if (bl < 0 || bl >= (int)sizeof(body)) {
      bl = (int)sizeof(body) - 1;
      body[bl] = '\0';
    }
    char hdr[160];
    int hl = snprintf(hdr, sizeof(hdr),
                      "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nConnection: close\r\nContent-Length: "
                      "%d\r\n\r\n",
                      bl);
    if (hl > 0) {
      (void)metrics_send_all(c, hdr, hl);
    }
    (void)metrics_send_all(c, body, bl);
    closesocket(c);
  }
  return 0;
}

void edr_metrics_http_start_if_configured(EdrEventBus *bus) {
  const char *bind = getenv("EDR_AGENT_METRICS_BIND");
  if (!bind || !bind[0]) {
    return;
  }
  char host[256];
  unsigned short port = 0;
  if (metrics_parse_bind(bind, host, sizeof(host), &port) != 0) {
    fprintf(stderr, "[metrics] EDR_AGENT_METRICS_BIND invalid (use host:port, e.g. 127.0.0.1:9123)\n");
    return;
  }
  edr_asurf_win_ensure_wsa();
  SOCKET ls = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (ls == INVALID_SOCKET) {
    fprintf(stderr, "[metrics] socket failed\n");
    return;
  }
  BOOL one = 1;
  (void)setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, (const char *)&one, sizeof(one));
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  if (InetPtonA(AF_INET, host, &addr.sin_addr) != 1) {
    fprintf(stderr, "[metrics] bind host must be IPv4 literal for this build: %s\n", host);
    closesocket(ls);
    return;
  }
  if (bind(ls, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    fprintf(stderr, "[metrics] bind(%s:%u) failed: %d\n", host, (unsigned)port, (int)WSAGetLastError());
    closesocket(ls);
    return;
  }
  if (listen(ls, 4) != 0) {
    fprintf(stderr, "[metrics] listen failed\n");
    closesocket(ls);
    return;
  }
  s_metrics_bus = bus;
  s_metrics_listen = ls;
  InterlockedExchange(&s_metrics_run, 1);
  s_metrics_thread = CreateThread(NULL, 0, edr_metrics_thread_main, NULL, 0, NULL);
  if (!s_metrics_thread) {
    InterlockedExchange(&s_metrics_run, 0);
    closesocket(ls);
    s_metrics_listen = INVALID_SOCKET;
    s_metrics_bus = NULL;
    fprintf(stderr, "[metrics] CreateThread failed\n");
    return;
  }
  fprintf(stderr, "[metrics] listening on http://%s:%u/metrics\n", host, (unsigned)port);
}

void edr_metrics_http_stop(void) {
  InterlockedExchange(&s_metrics_run, 0);
  if (s_metrics_listen != INVALID_SOCKET) {
    closesocket(s_metrics_listen);
    s_metrics_listen = INVALID_SOCKET;
  }
  if (s_metrics_thread) {
    (void)WaitForSingleObject(s_metrics_thread, 8000);
    CloseHandle(s_metrics_thread);
    s_metrics_thread = NULL;
  }
  s_metrics_bus = NULL;
}

#else

void edr_metrics_http_start_if_configured(EdrEventBus *bus) { (void)bus; }

void edr_metrics_http_stop(void) {}

#endif
