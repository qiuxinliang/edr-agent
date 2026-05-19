/**
 * Linux 采集：M1 使用 inotify 监视目录，将文件事件以 ETW1 文本格式推入事件总线，
 * 与 `behavior_from_slot` / Windows TDH 输出对齐。
 * 可选 **`EDR_LINUX_PROC_CONNECTOR=1`**：通过内核 proc connector（NETLINK）订阅 fork/exec/exit，
 * 以 **≤2 次/秒** 触发 **`edr_pmfe_on_process_lifecycle_hint`**（与 PMFE 内 1s 去抖叠加），刷新宿主监听表。
 * 本文件仅应由 CMake 在目标为 Linux 时编入。
 */
#if !defined(__linux__)
#error "collector_linux.c is Linux-only; use collector_stub.c on other POSIX systems"
#endif

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <linux/netlink.h>
#include <linux/connector.h>
#include <linux/cn_proc.h>

#include "edr/collector.h"
#include "edr/config.h"
#include "edr/error.h"
#include "edr/event_bus.h"
#include "edr/pmfe.h"
#include "edr/types.h"

#define MAX_WATCHES 32
#define INOTIFY_READ_BUF 16384

typedef struct {
  int wd;
  char dir[PATH_MAX];
} watch_entry_t;

static watch_entry_t s_watches[MAX_WATCHES];
static int s_nwatch;

static EdrEventBus *s_bus;
static int s_ifd = -1;
static int s_pipe[2] = {-1, -1};
static volatile int s_stop;
static pthread_t s_thread;
static int s_started;

/** 可选：内核 proc connector（NETLINK），`EDR_LINUX_PROC_CONNECTOR=1` 时启用，用于 `edr_pmfe_on_process_lifecycle_hint` 去抖刷新监听表 */
static pthread_t s_proc_thread;
static int s_proc_thread_valid;
static int s_nl_sock = -1;

static uint64_t edr_realtime_ns(void) {
  struct timespec ts;
  if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
    return 0;
  }
  return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void trim_spaces(char *s) {
  if (!s || !s[0]) {
    return;
  }
  char *p = s;
  while (*p == ' ' || *p == '\t') {
    p++;
  }
  if (p != s) {
    memmove(s, p, strlen(p) + 1u);
  }
  size_t n = strlen(s);
  while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\t')) {
    s[--n] = '\0';
  }
}

static const char *lookup_dir(int wd) {
  for (int i = 0; i < s_nwatch; i++) {
    if (s_watches[i].wd == wd) {
      return s_watches[i].dir;
    }
  }
  return "";
}

static EdrEventType map_inotify_mask(uint32_t mask) {
  if ((mask & (IN_DELETE | IN_DELETE_SELF)) != 0u) {
    return EDR_EVENT_FILE_DELETE;
  }
  if ((mask & IN_CREATE) != 0u) {
    return EDR_EVENT_FILE_CREATE;
  }
  if ((mask & (IN_MOVED_FROM | IN_MOVED_TO)) != 0u) {
    return EDR_EVENT_FILE_RENAME;
  }
  if ((mask & (IN_MODIFY | IN_CLOSE_WRITE | IN_ATTRIB)) != 0u) {
    return EDR_EVENT_FILE_WRITE;
  }
  /* IN_OPEN / IN_ACCESS 等仍上报为写侧活动，便于观测 */
  return EDR_EVENT_FILE_WRITE;
}

static int build_etw1_payload(uint8_t *out, size_t cap, const char *fullpath) {
  unsigned pid = (unsigned)getpid();
  int n = snprintf((char *)out, cap, "ETW1\nprov=inotify\npid=%u\nfile=%s\n", pid, fullpath);
  if (n < 0 || (size_t)n >= cap) {
    return -1;
  }
  return n;
}

static void push_inotify_event(uint32_t mask, const char *fullpath) {
  if (!s_bus || !fullpath || !fullpath[0]) {
    return;
  }
  EdrEventSlot slot;
  memset(&slot, 0, sizeof(slot));
  slot.timestamp_ns = edr_realtime_ns();
  slot.type = map_inotify_mask(mask);
  slot.consumed = false;
  slot.priority = 1;
  int plen = build_etw1_payload(slot.data, EDR_MAX_EVENT_PAYLOAD, fullpath);
  if (plen < 0) {
    return;
  }
  slot.size = (uint32_t)plen;
  (void)edr_event_bus_try_push(s_bus, &slot);
}

static void process_inotify_buffer(const char *buf, ssize_t len) {
  for (ssize_t i = 0; i < len;) {
    const struct inotify_event *ev = (const struct inotify_event *)(buf + i);
    size_t step = sizeof(struct inotify_event) + (size_t)ev->len;
    i += (ssize_t)step;

    const char *base = lookup_dir(ev->wd);
    if (!base[0]) {
      continue;
    }
    char full[PATH_MAX * 2];
    if (ev->len > 0u) {
      if (snprintf(full, sizeof(full), "%s/%s", base, ev->name) >= (int)sizeof(full)) {
        continue;
      }
    } else {
      if (snprintf(full, sizeof(full), "%s", base) >= (int)sizeof(full)) {
        continue;
      }
    }
    push_inotify_event(ev->mask, full);
  }
}

static int add_watches(int ifd) {
  s_nwatch = 0;
  const char *env = getenv("EDR_INOTIFY_PATHS");
  const char *csv = (env && env[0]) ? env : "/tmp";
  char *dup = strdup(csv);
  if (!dup) {
    return -1;
  }
  char *save = NULL;
  for (char *tok = strtok_r(dup, ",", &save); tok != NULL; tok = strtok_r(NULL, ",", &save)) {
    trim_spaces(tok);
    if (!tok[0]) {
      continue;
    }
    if (s_nwatch >= MAX_WATCHES) {
      fprintf(stderr, "[collector_linux] 已达 inotify 监视上限 (%d)，忽略后续路径\n", MAX_WATCHES);
      break;
    }
    struct stat st;
    if (stat(tok, &st) != 0 || !S_ISDIR(st.st_mode)) {
      fprintf(stderr, "[collector_linux] 跳过非目录或不可访问路径: %s\n", tok);
      continue;
    }
    uint32_t mask = IN_ALL_EVENTS;
    int wd = inotify_add_watch(ifd, tok, mask);
    if (wd < 0) {
      fprintf(stderr, "[collector_linux] inotify_add_watch 失败 %s: %s\n", tok, strerror(errno));
      continue;
    }
    s_watches[s_nwatch].wd = wd;
    snprintf(s_watches[s_nwatch].dir, sizeof(s_watches[s_nwatch].dir), "%s", tok);
    s_nwatch++;
  }
  free(dup);
  return s_nwatch > 0 ? 0 : -1;
}

static void close_pipe_pair(void) {
  if (s_pipe[0] >= 0) {
    close(s_pipe[0]);
    s_pipe[0] = -1;
  }
  if (s_pipe[1] >= 0) {
    close(s_pipe[1]);
    s_pipe[1] = -1;
  }
}

static void *inotify_thread_main(void *arg) {
  (void)arg;
  char buf[INOTIFY_READ_BUF] __attribute__((aligned(sizeof(struct inotify_event))));

  while (!s_stop) {
    struct pollfd fds[2];
    fds[0].fd = s_ifd;
    fds[0].events = POLLIN;
    fds[1].fd = s_pipe[0];
    fds[1].events = POLLIN;
    int pr = poll(fds, 2u, 1000);
    if (pr < 0) {
      if (errno == EINTR) {
        continue;
      }
      break;
    }
    if (s_stop) {
      break;
    }
    if ((fds[1].revents & (POLLIN | POLLHUP)) != 0) {
      char drain[16];
      (void)read(s_pipe[0], drain, sizeof(drain));
      break;
    }
    if ((fds[0].revents & POLLIN) == 0) {
      continue;
    }
    for (;;) {
      ssize_t n = read(s_ifd, buf, sizeof(buf));
      if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
          break;
        }
        break;
      }
      if (n == 0) {
        break;
      }
      process_inotify_buffer(buf, n);
    }
  }
  return NULL;
}

static int proc_send_mcast_op(int sock, enum proc_cn_mcast_op op) {
  char buff[sizeof(struct nlmsghdr) + sizeof(struct cn_msg) + sizeof(int)];
  struct nlmsghdr *hdr = (struct nlmsghdr *)buff;
  memset(buff, 0, sizeof(buff));
  hdr->nlmsg_len = (uint32_t)sizeof(buff);
  hdr->nlmsg_type = NLMSG_DONE;
  hdr->nlmsg_flags = 0;
  hdr->nlmsg_seq = 0;
  hdr->nlmsg_pid = (uint32_t)getpid();
  struct cn_msg *msg = (struct cn_msg *)NLMSG_DATA(hdr);
  msg->id.idx = CN_IDX_PROC;
  msg->id.val = CN_VAL_PROC;
  msg->seq = 0;
  msg->ack = 0;
  msg->flags = 0;
  msg->len = sizeof(int);
  memcpy((unsigned char *)msg + sizeof(struct cn_msg), &op, sizeof(int));
  if (send(sock, buff, hdr->nlmsg_len, 0) < 0) {
    return -1;
  }
  return 0;
}

static int proc_connector_register(void) {
  s_nl_sock = socket(PF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC, NETLINK_CONNECTOR);
  if (s_nl_sock < 0) {
    fprintf(stderr, "[collector_linux] proc_connector socket: %s\n", strerror(errno));
    return -1;
  }
  struct sockaddr_nl sa;
  memset(&sa, 0, sizeof(sa));
  sa.nl_family = AF_NETLINK;
  sa.nl_groups = CN_IDX_PROC;
  sa.nl_pid = (uint32_t)getpid();
  if (bind(s_nl_sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
    fprintf(stderr, "[collector_linux] proc_connector bind: %s\n", strerror(errno));
    close(s_nl_sock);
    s_nl_sock = -1;
    return -1;
  }
  if (proc_send_mcast_op(s_nl_sock, PROC_CN_MCAST_LISTEN) != 0) {
    fprintf(stderr, "[collector_linux] proc_connector subscribe failed: %s\n", strerror(errno));
    close(s_nl_sock);
    s_nl_sock = -1;
    return -1;
  }
  return 0;
}

static void *proc_connector_thread_main(void *arg) {
  (void)arg;
  char buf[8192];
  uint64_t last_hint_ns = 0;
  struct timespec ts;
  while (!s_stop) {
    struct pollfd pfd;
    pfd.fd = s_nl_sock;
    pfd.events = POLLIN;
    int pr = poll(&pfd, 1u, 1000);
    if (pr < 0) {
      if (errno == EINTR) {
        continue;
      }
      break;
    }
    if (s_stop) {
      break;
    }
    if (pr == 0) {
      continue;
    }
    if ((pfd.revents & POLLIN) == 0) {
      continue;
    }
    ssize_t n = recv(s_nl_sock, buf, sizeof(buf), MSG_DONTWAIT);
    if (n <= 0) {
      continue;
    }
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
      continue;
    }
    uint64_t now_ns = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
    if (now_ns - last_hint_ns < 500000000ULL) {
      continue;
    }
    last_hint_ns = now_ns;
    edr_pmfe_on_process_lifecycle_hint();
  }
  return NULL;
}

EdrError edr_collector_start(EdrEventBus *bus, const EdrConfig *cfg) {
  if (!bus) {
    return EDR_ERR_INVALID_ARG;
  }
  if (!cfg || !cfg->collection.etw_enabled) {
    return EDR_OK;
  }
  if (s_started) {
    return EDR_OK;
  }

  s_bus = bus;
  s_stop = 0;

  if (pipe(s_pipe) != 0) {
    s_bus = NULL;
    return EDR_ERR_INTERNAL;
  }

  s_ifd = inotify_init1(IN_CLOEXEC | IN_NONBLOCK);
  if (s_ifd < 0) {
    close_pipe_pair();
    s_bus = NULL;
    fprintf(stderr, "[collector_linux] inotify_init1: %s\n", strerror(errno));
    return EDR_ERR_INTERNAL;
  }

  if (add_watches(s_ifd) != 0) {
    fprintf(stderr, "[collector_linux] 无有效监视目录。可设置 EDR_INOTIFY_PATHS（逗号分隔），默认 /tmp\n");
    close(s_ifd);
    s_ifd = -1;
    close_pipe_pair();
    s_bus = NULL;
    return EDR_ERR_INVALID_ARG;
  }

  if (pthread_create(&s_thread, NULL, inotify_thread_main, NULL) != 0) {
    close(s_ifd);
    s_ifd = -1;
    close_pipe_pair();
    s_bus = NULL;
    return EDR_ERR_INTERNAL;
  }

  s_proc_thread_valid = 0;
  const char *pc = getenv("EDR_LINUX_PROC_CONNECTOR");
  if (pc && pc[0] == '1') {
    if (proc_connector_register() == 0) {
      if (pthread_create(&s_proc_thread, NULL, proc_connector_thread_main, NULL) != 0) {
        fprintf(stderr, "[collector_linux] proc_connector pthread_create failed\n");
        (void)proc_send_mcast_op(s_nl_sock, PROC_CN_MCAST_IGNORE);
        close(s_nl_sock);
        s_nl_sock = -1;
      } else {
        s_proc_thread_valid = 1;
      }
    }
  }

  s_started = 1;
  return EDR_OK;
}

void edr_collector_stop(void) {
  if (!s_started) {
    return;
  }
  s_stop = 1;
  if (s_pipe[1] >= 0) {
    char b = 0;
    (void)write(s_pipe[1], &b, 1);
  }
  if (s_proc_thread_valid) {
    (void)pthread_join(s_proc_thread, NULL);
    s_proc_thread_valid = 0;
    if (s_nl_sock >= 0) {
      (void)proc_send_mcast_op(s_nl_sock, PROC_CN_MCAST_IGNORE);
      close(s_nl_sock);
      s_nl_sock = -1;
    }
  }
  (void)pthread_join(s_thread, NULL);
  s_started = 0;
  s_stop = 0;

  if (s_ifd >= 0) {
    for (int i = 0; i < s_nwatch; i++) {
      (void)inotify_rm_watch(s_ifd, s_watches[i].wd);
    }
    s_nwatch = 0;
    close(s_ifd);
    s_ifd = -1;
  }
  close_pipe_pair();
  s_bus = NULL;
}

void edr_collector_stop_orphan_etw_session(void) {}
