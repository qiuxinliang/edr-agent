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
#include "edr/adaptive_collection.h"
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
static pthread_t s_audit_thread;
static int s_audit_thread_valid;
static FILE *s_audit_fp;
static char s_audit_path[PATH_MAX];
static pthread_t s_ebpf_thread;
static int s_ebpf_thread_valid;
static FILE *s_ebpf_fp;

static EdrCollectorHealth s_health;

typedef struct {
  const char *name;
  int x86_64_nr;
  EdrEventType event_type;
} LinuxAuditSyscallMap;

static const LinuxAuditSyscallMap kAuditSyscalls[] = {
    {"execve", 59, EDR_EVENT_PROCESS_CREATE},
    {"connect", 42, EDR_EVENT_NET_CONNECT},
    {"openat", 257, EDR_EVENT_FILE_READ},
    {"rename", 82, EDR_EVENT_FILE_RENAME},
    {"renameat", 264, EDR_EVENT_FILE_RENAME},
    {"renameat2", 316, EDR_EVENT_FILE_RENAME},
    {"unlink", 87, EDR_EVENT_FILE_DELETE},
    {"unlinkat", 263, EDR_EVENT_FILE_DELETE},
    {"chmod", 90, EDR_EVENT_FILE_PERMISSION_CHANGE},
    {"fchmod", 91, EDR_EVENT_FILE_PERMISSION_CHANGE},
    {"fchmodat", 268, EDR_EVENT_FILE_PERMISSION_CHANGE},
    {"chown", 92, EDR_EVENT_FILE_PERMISSION_CHANGE},
    {"fchown", 93, EDR_EVENT_FILE_PERMISSION_CHANGE},
    {"lchown", 94, EDR_EVENT_FILE_PERMISSION_CHANGE},
    {"fchownat", 260, EDR_EVENT_FILE_PERMISSION_CHANGE},
    {"setuid", 105, EDR_EVENT_AUTH_PRIVILEGE_ESC},
    {"ptrace", 101, EDR_EVENT_PROCESS_INJECT},
    {"init_module", 175, EDR_EVENT_DRIVER_LOAD},
    {"finit_module", 313, EDR_EVENT_DRIVER_LOAD},
    {"delete_module", 176, EDR_EVENT_DRIVER_LOAD},
};

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

static void copy_between_quotes(const char *line, const char *key, char *out, size_t cap) {
  if (!out || cap == 0u) {
    return;
  }
  out[0] = '\0';
  const char *p = strstr(line, key);
  if (!p) {
    return;
  }
  p += strlen(key);
  if (*p == '"') {
    p++;
    size_t i = 0;
    while (p[i] && p[i] != '"' && i + 1u < cap) {
      out[i] = p[i];
      i++;
    }
    out[i] = '\0';
  } else {
    size_t i = 0;
    while (p[i] && p[i] != ' ' && p[i] != '\n' && i + 1u < cap) {
      out[i] = p[i];
      i++;
    }
    out[i] = '\0';
  }
}

static long audit_long_field(const char *line, const char *key, long defv) {
  const char *p = strstr(line, key);
  if (!p) {
    return defv;
  }
  p += strlen(key);
  char *end = NULL;
  long v = strtol(p, &end, 10);
  return end != p ? v : defv;
}

static const LinuxAuditSyscallMap *audit_lookup_syscall(const char *line) {
  char name[64];
  copy_between_quotes(line, "syscall=", name, sizeof(name));
  if (!name[0]) {
    return NULL;
  }
  for (size_t i = 0; i < sizeof(kAuditSyscalls) / sizeof(kAuditSyscalls[0]); i++) {
    if (strcmp(name, kAuditSyscalls[i].name) == 0) {
      return &kAuditSyscalls[i];
    }
  }
  char *end = NULL;
  long nr = strtol(name, &end, 10);
  if (end == name) {
    return NULL;
  }
  for (size_t i = 0; i < sizeof(kAuditSyscalls) / sizeof(kAuditSyscalls[0]); i++) {
    if (nr == kAuditSyscalls[i].x86_64_nr) {
      return &kAuditSyscalls[i];
    }
  }
  return NULL;
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
  if (!edr_event_bus_try_push(s_bus, &slot)) {
    s_health.collector_dropped++;
  }
}

static void push_audit_event(const char *line) {
  if (!s_bus || !line || !line[0]) {
    return;
  }
  const LinuxAuditSyscallMap *m = audit_lookup_syscall(line);
  if (!m) {
    return;
  }
  char comm[128], exe[PATH_MAX], auid[64];
  copy_between_quotes(line, "comm=", comm, sizeof(comm));
  copy_between_quotes(line, "exe=", exe, sizeof(exe));
  copy_between_quotes(line, "auid=", auid, sizeof(auid));
  long pid = audit_long_field(line, "pid=", 0);
  long ppid = audit_long_field(line, "ppid=", 0);
  EdrEventSlot slot;
  memset(&slot, 0, sizeof(slot));
  slot.timestamp_ns = edr_realtime_ns();
  slot.type = m->event_type;
  slot.priority = 0;
  slot.consumed = false;
  int n = snprintf((char *)slot.data, EDR_MAX_EVENT_PAYLOAD,
                   "ETW1\nprov=auditd\nsensor=auditd\nsyscall=%s\npid=%ld\nppid=%ld\nimg=%s\nprocess=%s\nauid=%s\nraw=%.900s\n",
                   m->name, pid, ppid, exe[0] ? exe : "-", comm[0] ? comm : "-", auid[0] ? auid : "-", line);
  if (n <= 0 || (size_t)n >= EDR_MAX_EVENT_PAYLOAD) {
    return;
  }
  slot.size = (uint32_t)n;
  s_health.auditd_events++;
  s_health.security_audit_visible = 1;
  if (m->event_type == EDR_EVENT_PROCESS_CREATE) {
    s_health.powershell_visible |= (strstr(comm, "powershell") || strstr(exe, "powershell") ||
                                    strstr(comm, "pwsh") || strstr(exe, "pwsh")) ? 1 : 0;
  }
  if (!edr_event_bus_try_push(s_bus, &slot)) {
    s_health.collector_dropped++;
  }
}

static void push_ebpf_trace_event(const char *line) {
  if (!s_bus || !line || !line[0]) {
    return;
  }
  EdrEventType type = EDR_EVENT_PROCESS_CREATE;
  const char *op = "execve";
  if (strstr(line, "connect")) {
    type = EDR_EVENT_NET_CONNECT;
    op = "connect";
  } else if (strstr(line, "openat")) {
    type = EDR_EVENT_FILE_READ;
    op = "openat";
  } else if (strstr(line, "rename")) {
    type = EDR_EVENT_FILE_RENAME;
    op = "rename";
  } else if (strstr(line, "unlink")) {
    type = EDR_EVENT_FILE_DELETE;
    op = "unlink";
  } else if (strstr(line, "chmod") || strstr(line, "chown")) {
    type = EDR_EVENT_FILE_PERMISSION_CHANGE;
    op = strstr(line, "chown") ? "chown" : "chmod";
  } else if (strstr(line, "setuid")) {
    type = EDR_EVENT_AUTH_PRIVILEGE_ESC;
    op = "setuid";
  } else if (strstr(line, "ptrace")) {
    type = EDR_EVENT_PROCESS_INJECT;
    op = "ptrace";
  } else if (strstr(line, "module")) {
    type = EDR_EVENT_DRIVER_LOAD;
    op = "module_load";
  } else if (!strstr(line, "execve")) {
    return;
  }
  EdrEventSlot slot;
  memset(&slot, 0, sizeof(slot));
  slot.timestamp_ns = edr_realtime_ns();
  slot.type = type;
  slot.priority = 0;
  int n = snprintf((char *)slot.data, EDR_MAX_EVENT_PAYLOAD,
                   "ETW1\nprov=ebpf\nsensor=ebpf\nsyscall=%s\npid=0\nraw=%.1100s\n", op, line);
  if (n <= 0 || (size_t)n >= EDR_MAX_EVENT_PAYLOAD) {
    return;
  }
  slot.size = (uint32_t)n;
  s_health.ebpf_events++;
  if (!edr_event_bus_try_push(s_bus, &slot)) {
    s_health.collector_dropped++;
  }
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

static void *audit_thread_main(void *arg) {
  (void)arg;
  char line[4096];
  while (!s_stop && s_audit_fp) {
    if (fgets(line, sizeof(line), s_audit_fp)) {
      push_audit_event(line);
      continue;
    }
    if (feof(s_audit_fp)) {
      clearerr(s_audit_fp);
      usleep(250000);
      continue;
    }
    snprintf(s_health.auditd_last_error, sizeof(s_health.auditd_last_error), "read_failed:%s", strerror(errno));
    break;
  }
  return NULL;
}

static void *ebpf_trace_thread_main(void *arg) {
  (void)arg;
  char line[2048];
  while (!s_stop && s_ebpf_fp) {
    if (fgets(line, sizeof(line), s_ebpf_fp)) {
      push_ebpf_trace_event(line);
      continue;
    }
    if (feof(s_ebpf_fp)) {
      clearerr(s_ebpf_fp);
      usleep(250000);
      continue;
    }
    snprintf(s_health.ebpf_last_error, sizeof(s_health.ebpf_last_error), "read_failed:%s", strerror(errno));
    break;
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
  memset(&s_health, 0, sizeof(s_health));
  s_health.etw_or_inotify_enabled = 1;
  s_health.ebpf_enabled = cfg->collection.ebpf_enabled ? 1 : 0;
  if (cfg->collection.ebpf_enabled) {
    snprintf(s_health.ebpf_last_error, sizeof(s_health.ebpf_last_error), "%s", "loader_not_configured");
  }

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

  s_audit_thread_valid = 0;
  s_audit_fp = NULL;
  int audit_on = cfg->collection.auditd_enabled ? 1 : 0;
  const char *ae = getenv("EDR_LINUX_AUDITD");
  if (ae && ae[0]) {
    audit_on = (ae[0] == '1') ? 1 : 0;
  }
  if (audit_on) {
    snprintf(s_audit_path, sizeof(s_audit_path), "%s",
             cfg->collection.auditd_log_path[0] ? cfg->collection.auditd_log_path : "/var/log/audit/audit.log");
    const char *ap = getenv("EDR_LINUX_AUDITD_LOG");
    if (ap && ap[0]) {
      snprintf(s_audit_path, sizeof(s_audit_path), "%s", ap);
    }
    s_audit_fp = fopen(s_audit_path, "r");
    s_health.auditd_enabled = 1;
    if (!s_audit_fp) {
      snprintf(s_health.auditd_last_error, sizeof(s_health.auditd_last_error), "open_failed:%s", strerror(errno));
    } else {
      s_health.auditd_running = 1;
      (void)fseek(s_audit_fp, 0, SEEK_END);
      if (pthread_create(&s_audit_thread, NULL, audit_thread_main, NULL) != 0) {
        snprintf(s_health.auditd_last_error, sizeof(s_health.auditd_last_error), "%s", "pthread_create_failed");
        fclose(s_audit_fp);
        s_audit_fp = NULL;
      } else {
        s_audit_thread_valid = 1;
      }
    }
  }

  s_ebpf_thread_valid = 0;
  s_ebpf_fp = NULL;
  const char *ebpf_trace = getenv("EDR_LINUX_EBPF_TRACE_PIPE");
  if (cfg->collection.ebpf_enabled && ebpf_trace && ebpf_trace[0] == '1') {
    const char *tp = getenv("EDR_LINUX_EBPF_TRACE_PIPE_PATH");
    if (!tp || !tp[0]) {
      tp = "/sys/kernel/debug/tracing/trace_pipe";
    }
    s_ebpf_fp = fopen(tp, "r");
    if (!s_ebpf_fp) {
      snprintf(s_health.ebpf_last_error, sizeof(s_health.ebpf_last_error), "trace_pipe_open_failed:%s", strerror(errno));
    } else {
      s_health.ebpf_loaded = 1;
      snprintf(s_health.ebpf_last_error, sizeof(s_health.ebpf_last_error), "%s", "");
      if (pthread_create(&s_ebpf_thread, NULL, ebpf_trace_thread_main, NULL) != 0) {
        snprintf(s_health.ebpf_last_error, sizeof(s_health.ebpf_last_error), "%s", "trace_pipe_thread_failed");
        fclose(s_ebpf_fp);
        s_ebpf_fp = NULL;
        s_health.ebpf_loaded = 0;
      } else {
        s_ebpf_thread_valid = 1;
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
  if (s_audit_thread_valid) {
    (void)pthread_join(s_audit_thread, NULL);
    s_audit_thread_valid = 0;
  }
  if (s_audit_fp) {
    fclose(s_audit_fp);
    s_audit_fp = NULL;
  }
  if (s_ebpf_thread_valid) {
    (void)pthread_cancel(s_ebpf_thread);
    (void)pthread_join(s_ebpf_thread, NULL);
    s_ebpf_thread_valid = 0;
  }
  if (s_ebpf_fp) {
    fclose(s_ebpf_fp);
    s_ebpf_fp = NULL;
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

int edr_collector_get_health(EdrCollectorHealth *out_health) {
  EdrAdaptiveCollectionStatus adaptive;
  if (!out_health) {
    return -1;
  }
  *out_health = s_health;
  if (s_bus) {
    out_health->queue_dropped = edr_event_bus_dropped_total(s_bus);
  }
  memset(&adaptive, 0, sizeof(adaptive));
  edr_adaptive_collection_get_status(&adaptive);
  out_health->adaptive_collection_enabled = adaptive.enabled;
  out_health->adaptive_collection_active = adaptive.active;
  out_health->adaptive_collection_ttl_s = adaptive.ttl_s;
  out_health->adaptive_collection_remaining_s = adaptive.remaining_s;
  out_health->adaptive_collection_min_severity = adaptive.min_severity;
  out_health->adaptive_collection_level = adaptive.level;
  out_health->adaptive_collection_boosts = adaptive.boosts;
  out_health->adaptive_collection_last_boost_unix_ms = adaptive.last_boost_unix_ms;
  snprintf(out_health->adaptive_collection_last_rule_id,
           sizeof(out_health->adaptive_collection_last_rule_id), "%s", adaptive.last_rule_id);
  return 0;
}
