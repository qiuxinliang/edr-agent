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
#include "edr/heartbeat.h"
#include "edr/pmfe.h"
#include "edr/sensor_interest.h"
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
  int aarch64_nr;
  EdrEventType event_type;
} LinuxAuditSyscallMap;

static const LinuxAuditSyscallMap kAuditSyscalls[] = {
    {"execve", 59, 221, EDR_EVENT_PROCESS_CREATE},
    {"connect", 42, 203, EDR_EVENT_NET_CONNECT},
    {"openat", 257, 56, EDR_EVENT_FILE_READ},
    {"rename", 82, -1, EDR_EVENT_FILE_RENAME},
    {"renameat", 264, 38, EDR_EVENT_FILE_RENAME},
    {"renameat2", 316, 276, EDR_EVENT_FILE_RENAME},
    {"unlink", 87, -1, EDR_EVENT_FILE_DELETE},
    {"unlinkat", 263, 35, EDR_EVENT_FILE_DELETE},
    {"chmod", 90, -1, EDR_EVENT_FILE_PERMISSION_CHANGE},
    {"fchmod", 91, 52, EDR_EVENT_FILE_PERMISSION_CHANGE},
    {"fchmodat", 268, 53, EDR_EVENT_FILE_PERMISSION_CHANGE},
    {"chown", 92, -1, EDR_EVENT_FILE_PERMISSION_CHANGE},
    {"fchown", 93, 55, EDR_EVENT_FILE_PERMISSION_CHANGE},
    {"lchown", 94, -1, EDR_EVENT_FILE_PERMISSION_CHANGE},
    {"fchownat", 260, 54, EDR_EVENT_FILE_PERMISSION_CHANGE},
    {"setuid", 105, 146, EDR_EVENT_AUTH_PRIVILEGE_ESC},
    {"ptrace", 101, 117, EDR_EVENT_PROCESS_INJECT},
    {"process_vm_readv", 310, 270, EDR_EVENT_PROCESS_INJECT},
    {"process_vm_writev", 311, 271, EDR_EVENT_PROCESS_INJECT},
    {"memfd_create", 319, 279, EDR_EVENT_PROCESS_INJECT},
    {"init_module", 175, 105, EDR_EVENT_DRIVER_LOAD},
    {"finit_module", 313, 273, EDR_EVENT_DRIVER_LOAD},
    {"delete_module", 176, 106, EDR_EVENT_DRIVER_LOAD},
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

static unsigned long audit_hex_field(const char *line, const char *key, unsigned long defv) {
  const char *p = strstr(line, key);
  if (!p) {
    return defv;
  }
  p += strlen(key);
  char *end = NULL;
  unsigned long value = strtoul(p, &end, 16);
  return end != p ? value : defv;
}

static int env_truthy(const char *key) {
  const char *v = getenv(key);
  return v && (v[0] == '1' || v[0] == 'y' || v[0] == 'Y' || v[0] == 't' || v[0] == 'T');
}

static int audit_append_field(char *buf, size_t cap, const char *out_key, const char *value) {
  if (!buf || !out_key || !value || cap == 0u) {
    return 0;
  }
  size_t used = strnlen(buf, cap);
  if (used == cap) {
    return 0;
  }
  size_t remaining = cap - used;
  size_t key_len = strlen(out_key);
  size_t value_len = strlen(value);
  if (key_len >= remaining) {
    return 0;
  }
  memcpy(buf + used, out_key, key_len);
  used += key_len;
  remaining -= key_len;
  if (remaining < 3u || value_len > remaining - 3u) {
    return 0;
  }
  buf[used++] = '=';
  memcpy(buf + used, value, value_len);
  used += value_len;
  buf[used++] = '\n';
  buf[used] = '\0';
  return 1;
}

static int audit_copy_optional(const char *line, const char *key, const char *out_key,
                               char *buf, size_t cap) {
  char val[PATH_MAX];
  copy_between_quotes(line, key, val, sizeof(val));
  if (!val[0]) {
    return 1;
  }
  return audit_append_field(buf, cap, out_key, val);
}

static int audit_append_unsigned(char *buf, size_t cap, const char *out_key, unsigned long value) {
  char text[32];
  int n = snprintf(text, sizeof(text), "%lu", value);
  if (n < 0 || (size_t)n >= sizeof(text)) {
    return 0;
  }
  return audit_append_field(buf, cap, out_key, text);
}

static int audit_append_raw_prefix(char *buf, size_t cap, const char *line, size_t limit) {
  char raw[1101];
  if (!line || limit >= sizeof(raw)) {
    return 0;
  }
  size_t len = 0u;
  while (len < limit && line[len]) {
    len++;
  }
  memcpy(raw, line, len);
  raw[len] = '\0';
  if (!audit_append_field(buf, cap, "raw", raw)) {
    return 0;
  }
  return line[len] == '\0' || audit_append_field(buf, cap, "raw_truncated", "true");
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
  int aarch64 = strstr(line, "arch=c00000b7") != NULL;
  for (size_t i = 0; i < sizeof(kAuditSyscalls) / sizeof(kAuditSyscalls[0]); i++) {
    int expected = aarch64 ? kAuditSyscalls[i].aarch64_nr : kAuditSyscalls[i].x86_64_nr;
    if (expected >= 0 && nr == expected) {
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

static uint32_t edr_linux_inotify_default_mask(void) {
  uint32_t mask = IN_CREATE | IN_CLOSE_WRITE | IN_MOVED_FROM | IN_MOVED_TO |
                  IN_DELETE | IN_DELETE_SELF | IN_ATTRIB;
  const char *v = getenv("EDR_INOTIFY_INCLUDE_MODIFY");
  if (v && (v[0] == '1' || v[0] == 'y' || v[0] == 'Y' || v[0] == 't' || v[0] == 'T')) {
    mask |= IN_MODIFY;
  }
  if ((v = getenv("EDR_INOTIFY_VERBOSE_ACCESS")) != NULL &&
      (v[0] == '1' || v[0] == 'y' || v[0] == 'Y' || v[0] == 't' || v[0] == 'T')) {
    mask |= IN_OPEN | IN_ACCESS | IN_CLOSE_NOWRITE;
  }
  return mask;
}

static int edr_linux_map_inotify_mask(uint32_t mask, EdrEventType *out_type) {
  if (!out_type) {
    return 0;
  }
  if ((mask & (IN_DELETE | IN_DELETE_SELF)) != 0u) {
    *out_type = EDR_EVENT_FILE_DELETE;
    return 1;
  }
  if ((mask & IN_CREATE) != 0u) {
    *out_type = EDR_EVENT_FILE_CREATE;
    return 1;
  }
  if ((mask & (IN_MOVED_FROM | IN_MOVED_TO)) != 0u) {
    *out_type = EDR_EVENT_FILE_RENAME;
    return 1;
  }
  if ((mask & IN_ATTRIB) != 0u) {
    *out_type = EDR_EVENT_FILE_PERMISSION_CHANGE;
    return 1;
  }
  if ((mask & (IN_CLOSE_WRITE | IN_MODIFY)) != 0u) {
    *out_type = EDR_EVENT_FILE_WRITE;
    return 1;
  }
  return 0;
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
  if (!edr_linux_map_inotify_mask(mask, &slot.type)) {
    return;
  }
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
  char comm[128], exe[PATH_MAX], auid[64], uid[64], gid[64], ses[64];
  copy_between_quotes(line, "comm=", comm, sizeof(comm));
  copy_between_quotes(line, "exe=", exe, sizeof(exe));
  copy_between_quotes(line, "auid=", auid, sizeof(auid));
  copy_between_quotes(line, "uid=", uid, sizeof(uid));
  copy_between_quotes(line, "gid=", gid, sizeof(gid));
  copy_between_quotes(line, "ses=", ses, sizeof(ses));
  long pid = audit_long_field(line, "pid=", 0);
  long ppid = audit_long_field(line, "ppid=", 0);
  unsigned long target_pid = 0;
  if (strcmp(m->name, "ptrace") == 0) {
    target_pid = audit_hex_field(line, "a1=", 0);
  } else if (strcmp(m->name, "process_vm_readv") == 0 || strcmp(m->name, "process_vm_writev") == 0) {
    target_pid = audit_hex_field(line, "a0=", 0);
  }
  EdrEventSlot slot;
  memset(&slot, 0, sizeof(slot));
  slot.timestamp_ns = edr_realtime_ns();
  slot.type = m->event_type;
  slot.priority = 0;
  slot.consumed = false;
  int n = snprintf((char *)slot.data, EDR_MAX_EVENT_PAYLOAD,
                   "ETW1\nprov=auditd\nsensor=auditd\nsyscall=%s\npid=%ld\nppid=%ld\nimg=%s\nprocess=%s\nauid=%s\nuid=%s\ngid=%s\nsession=%s\n",
                   m->name, pid, ppid, exe[0] ? exe : "-", comm[0] ? comm : "-", auid[0] ? auid : "-",
                   uid[0] ? uid : "-", gid[0] ? gid : "-", ses[0] ? ses : "-");
  if (n <= 0 || (size_t)n >= EDR_MAX_EVENT_PAYLOAD) {
    return;
  }
  if (!audit_copy_optional(line, "cwd=", "cwd", (char *)slot.data, EDR_MAX_EVENT_PAYLOAD) ||
      !audit_copy_optional(line, "name=", "file", (char *)slot.data, EDR_MAX_EVENT_PAYLOAD) ||
      !audit_copy_optional(line, "addr=", "dst", (char *)slot.data, EDR_MAX_EVENT_PAYLOAD) ||
      !audit_copy_optional(line, "family=", "family", (char *)slot.data, EDR_MAX_EVENT_PAYLOAD) ||
      !audit_copy_optional(line, "success=", "success", (char *)slot.data, EDR_MAX_EVENT_PAYLOAD) ||
      !audit_copy_optional(line, "exit=", "exit", (char *)slot.data, EDR_MAX_EVENT_PAYLOAD) ||
      (target_pid > 0 &&
       !audit_append_unsigned((char *)slot.data, EDR_MAX_EVENT_PAYLOAD, "target_pid", target_pid)) ||
      (env_truthy("EDR_LINUX_INCLUDE_RAW_AUDIT") &&
       !audit_append_raw_prefix((char *)slot.data, EDR_MAX_EVENT_PAYLOAD, line, 900u))) {
    s_health.collector_dropped++;
    return;
  }
  slot.size = (uint32_t)strlen((char *)slot.data);
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
  } else if (strstr(line, "process_vm_writev")) {
    type = EDR_EVENT_PROCESS_INJECT;
    op = "process_vm_writev";
  } else if (strstr(line, "process_vm_readv")) {
    type = EDR_EVENT_PROCESS_INJECT;
    op = "process_vm_readv";
  } else if (strstr(line, "memfd_create")) {
    type = EDR_EVENT_PROCESS_INJECT;
    op = "memfd_create";
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
  long pid = audit_long_field(line, "pid=", 0);
  int n = snprintf((char *)slot.data, EDR_MAX_EVENT_PAYLOAD,
                   "ETW1\nprov=ebpf\nsensor=ebpf\nsyscall=%s\npid=%ld\n", op, pid);
  if (n <= 0 || (size_t)n >= EDR_MAX_EVENT_PAYLOAD) {
    return;
  }
  if (!audit_copy_optional(line, "comm=", "process", (char *)slot.data, EDR_MAX_EVENT_PAYLOAD) ||
      !audit_copy_optional(line, "exe=", "img", (char *)slot.data, EDR_MAX_EVENT_PAYLOAD) ||
      !audit_copy_optional(line, "file=", "file", (char *)slot.data, EDR_MAX_EVENT_PAYLOAD) ||
      !audit_copy_optional(line, "path=", "file", (char *)slot.data, EDR_MAX_EVENT_PAYLOAD) ||
      !audit_copy_optional(line, "dst=", "dst", (char *)slot.data, EDR_MAX_EVENT_PAYLOAD) ||
      !audit_copy_optional(line, "dport=", "dport", (char *)slot.data, EDR_MAX_EVENT_PAYLOAD) ||
      !audit_copy_optional(line, "target_pid=", "target_pid", (char *)slot.data, EDR_MAX_EVENT_PAYLOAD) ||
      !audit_copy_optional(line, "name=", "memfd_name", (char *)slot.data, EDR_MAX_EVENT_PAYLOAD) ||
      (env_truthy("EDR_LINUX_INCLUDE_RAW_EBPF") &&
       !audit_append_raw_prefix((char *)slot.data, EDR_MAX_EVENT_PAYLOAD, line, 1100u))) {
    s_health.collector_dropped++;
    return;
  }
  slot.size = (uint32_t)strlen((char *)slot.data);
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
      fprintf(stderr, "[collector_linux] inotify watch limit reached (%d); ignoring remaining paths\n", MAX_WATCHES);
      break;
    }
    struct stat st;
    if (stat(tok, &st) != 0 || !S_ISDIR(st.st_mode)) {
      fprintf(stderr, "[collector_linux] skipping non-directory or inaccessible path: %s\n", tok);
      continue;
    }
    uint32_t mask = edr_linux_inotify_default_mask();
    int wd = inotify_add_watch(ifd, tok, mask);
    if (wd < 0) {
      fprintf(stderr, "[collector_linux] inotify_add_watch failed %s: %s\n", tok, strerror(errno));
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
    /* inotify poll 超时 1s，空闲也会跳动，不会误报“卡死” */
    edr_health_beat(EDR_HEALTH_COLLECTOR);
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
      if (read(s_pipe[0], drain, sizeof(drain)) < 0 && errno != EAGAIN && errno != EINTR) {
        fprintf(stderr, "[collector] shutdown pipe read failed: %s\n", strerror(errno));
      }
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
    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
      clearerr(s_ebpf_fp);
      usleep(100000);
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
    fprintf(stderr, "[collector_linux] no valid watch directories; set EDR_INOTIFY_PATHS (comma-separated), default /tmp\n");
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
  int ebpf_trace_on = cfg->collection.ebpf_enabled && !(ebpf_trace && ebpf_trace[0] == '0');
  if (ebpf_trace_on) {
    const char *tp = getenv("EDR_LINUX_EBPF_TRACE_PIPE_PATH");
    if (!tp || !tp[0]) {
      tp = "/run/edr-agent/ebpf-events.pipe";
    }
    int trace_fd = open(tp, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (trace_fd < 0) {
      snprintf(s_health.ebpf_last_error, sizeof(s_health.ebpf_last_error), "trace_pipe_open_failed:%s", strerror(errno));
    } else {
      s_ebpf_fp = fdopen(trace_fd, "r");
      if (!s_ebpf_fp) {
        close(trace_fd);
        snprintf(s_health.ebpf_last_error, sizeof(s_health.ebpf_last_error), "trace_pipe_fdopen_failed:%s", strerror(errno));
      }
    }
    if (s_ebpf_fp) {
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

int edr_collector_stop(void) {
  if (!s_started) {
    return 1;
  }
  s_stop = 1;
  if (s_pipe[1] >= 0) {
    char b = 0;
    if (write(s_pipe[1], &b, 1) != 1 && errno != EAGAIN && errno != EINTR) {
      fprintf(stderr, "[collector] shutdown pipe write failed: %s\n", strerror(errno));
    }
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
  return 1;
}

void edr_collector_stop_orphan_etw_session(void) {}

void edr_collector_register_policy_canary_process(uint32_t pid, const char *command) {
  (void)pid;
  (void)command;
}

int edr_collector_get_health(EdrCollectorHealth *out_health) {
  EdrAdaptiveCollectionStatus adaptive;
  EdrSensorInterestStatus si;
  if (!out_health) {
    return -1;
  }
  *out_health = s_health;
  if (s_bus) {
    out_health->queue_dropped = edr_event_bus_dropped_total(s_bus);
  }
  memset(&si, 0, sizeof(si));
  edr_sensor_interest_get_status(&si);
  out_health->sensor_interest_enabled = si.enabled;
  out_health->sensor_interest_loaded = si.loaded;
  out_health->sensor_interest_file_read_full_admission = si.file_read_full_admission;
  out_health->sensor_interest_file_write_full_admission = si.file_write_full_admission;
  out_health->sensor_interest_registry_set_full_admission = si.registry_set_full_admission;
  out_health->sensor_interest_full_admission_contract_valid = si.full_admission_contract_valid;
  out_health->sensor_interest_p0_binding_valid = si.p0_binding_valid;
  snprintf(out_health->sensor_interest_version, sizeof(out_health->sensor_interest_version), "%s", si.version);
  snprintf(out_health->sensor_interest_rules_version, sizeof(out_health->sensor_interest_rules_version), "%s", si.rules_version);
  snprintf(out_health->sensor_interest_p0_artifact_sha256,
           sizeof(out_health->sensor_interest_p0_artifact_sha256), "%s", si.p0_artifact_sha256);
  snprintf(out_health->sensor_interest_p0_rule_coverage_sha256,
           sizeof(out_health->sensor_interest_p0_rule_coverage_sha256), "%s", si.p0_rule_coverage_sha256);
  snprintf(out_health->sensor_interest_manifest_sha256,
           sizeof(out_health->sensor_interest_manifest_sha256), "%s", si.sensor_interest_manifest_sha256);
  snprintf(out_health->sensor_interest_manifest_hash_mode,
           sizeof(out_health->sensor_interest_manifest_hash_mode), "%s", si.sensor_interest_manifest_hash_mode);
  out_health->sensor_interest_p0_artifact_rule_count = si.p0_artifact_rule_count;
  out_health->sensor_interest_snapshot_epoch = si.snapshot_epoch;
  out_health->sensor_interest_process_names = si.process_name_count;
  out_health->sensor_interest_process_prefixes = si.process_prefix_count;
  out_health->sensor_interest_ports = si.port_count;
  out_health->sensor_interest_file_prefixes = si.file_prefix_count;
  out_health->sensor_interest_file_contains = si.file_contains_count;
  out_health->sensor_interest_registry_prefixes = si.registry_prefix_count;
  out_health->sensor_interest_registry_contains = si.registry_contains_count;
  out_health->sensor_interest_cmd_tokens = si.cmd_token_count;
  out_health->sensor_interest_parent_child_pairs = si.parent_child_pair_count;
  out_health->sensor_interest_required_fields = si.attack_stage_required_field_count;
  out_health->sensor_interest_checked = si.checked;
  out_health->sensor_interest_matched = si.matched;
  out_health->sensor_interest_dropped = si.dropped;
  out_health->sensor_interest_provider_hits = si.provider_hits;
  out_health->sensor_interest_adaptive_hits = si.adaptive_hits;
  out_health->sensor_interest_process_hits = si.process_hits;
  out_health->sensor_interest_port_hits = si.port_hits;
  out_health->sensor_interest_path_hits = si.path_hits;
  out_health->sensor_interest_registry_hits = si.registry_hits;
  out_health->sensor_interest_parent_child_hits = si.parent_child_hits;
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
