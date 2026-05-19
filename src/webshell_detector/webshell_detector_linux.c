#if !defined(__linux__)
#error "webshell_detector_linux.c is Linux-only"
#endif

#include "edr/webshell_detector.h"

#include "edr/ave_sdk.h"
#include "edr/config.h"
#include "edr/event_bus.h"
#include "edr/grpc_client.h"
#include "edr/types.h"
#include "edr/webshell_forensic.h"

#include <dirent.h>
#include <errno.h>
#include <fnmatch.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#ifdef EDR_HAVE_YARA
#include <yara.h>
#endif

#define WEBSHELL_MAX_ROOTS 64
#define WEBSHELL_MAX_WATCHES 4096
#define WEBSHELL_INOTIFY_BUF 16384

typedef struct {
  char root[PATH_MAX];
  char service_name[32];
  uint16_t port;
} WebRoot;

typedef struct {
  int wd;
  char dir[PATH_MAX];
} WatchEntry;

typedef struct {
  char rule_name[128];
  float confidence;
  int matched;
} WebshellRuleMatch;

static const EdrConfig *s_cfg;
static EdrEventBus *s_bus;
static int s_started;
static int s_ifd = -1;
static int s_pipe[2] = {-1, -1};
static pthread_t s_thread;
static volatile int s_stop;

static WebRoot s_roots[WEBSHELL_MAX_ROOTS];
static size_t s_root_count;
static WatchEntry s_watches[WEBSHELL_MAX_WATCHES];
static size_t s_watch_count;

#ifdef EDR_HAVE_YARA
static YR_RULES *s_yara_rules;
static int s_yara_inited;
#endif

static const char *kExtAllow[] = {
    ".php", ".php3", ".php4", ".php5", ".php7", ".phtml", ".phar", ".asp", ".aspx", ".cer", ".asa", ".jsp", ".jspx",
    ".jspf", ".shtml", ".stm", ".py",  ".pl",   ".rb",   ".cgi",  ".htaccess", ".user.ini", ".exe", ".elf", ".so",
    ".dll", NULL};

static const char *kWhitelist[] = {"*/wp-includes/*", "*/wp-admin/*", "*/thinkphp/library/*", "*/vendor/laravel/*",
                                   NULL};

static uint64_t now_ns(void) {
  struct timespec ts;
  if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
    return 0;
  }
  return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void ms_sleep(unsigned ms) { usleep(ms * 1000u); }

static int starts_with_ci(const char *s, const char *prefix) {
  size_t n = strlen(prefix);
  return strncasecmp(s, prefix, n) == 0;
}

static const char *ext_of(const char *path) {
  const char *dot = strrchr(path, '.');
  return dot ? dot : "";
}

static int ext_allowed(const char *path) {
  const char *ext = ext_of(path);
  for (int i = 0; kExtAllow[i]; i++) {
    if (strcasecmp(ext, kExtAllow[i]) == 0) {
      return 1;
    }
  }
  return 0;
}

static int pre_filter(const char *full_path) {
  struct stat st;
  if (stat(full_path, &st) != 0 || !S_ISREG(st.st_mode)) {
    return 0;
  }
  if (!ext_allowed(full_path)) {
    return 0;
  }
  for (int i = 0; kWhitelist[i]; i++) {
    if (fnmatch(kWhitelist[i], full_path, FNM_PATHNAME) == 0) {
      return 0;
    }
  }
  uint64_t max_bytes = (uint64_t)s_cfg->webshell_detector.max_file_size_mb * 1024ULL * 1024ULL;
  if ((uint64_t)st.st_size == 0u || (uint64_t)st.st_size > max_bytes) {
    return 0;
  }
  off_t size1 = st.st_size;
  ms_sleep(200u);
  if (stat(full_path, &st) != 0 || !S_ISREG(st.st_mode)) {
    return 0;
  }
  if (st.st_size != size1) {
    ms_sleep(s_cfg->webshell_detector.defer_retry_ms);
    if (stat(full_path, &st) != 0 || !S_ISREG(st.st_mode)) {
      return 0;
    }
  }
  return 1;
}

static void infer_service(const char *path, char *svc, size_t svc_cap, uint16_t *port) {
  if (strstr(path, "nginx") != NULL) {
    snprintf(svc, svc_cap, "%s", "Nginx");
    *port = 80;
  } else if (strstr(path, "apache") != NULL || strstr(path, "httpd") != NULL) {
    snprintf(svc, svc_cap, "%s", "Apache");
    *port = 80;
  } else if (strstr(path, "tomcat") != NULL) {
    snprintf(svc, svc_cap, "%s", "Tomcat");
    *port = 8080;
  } else {
    snprintf(svc, svc_cap, "%s", "WebService");
    *port = 80;
  }
}

static void add_root(const char *path) {
  if (!path || !path[0] || s_root_count >= WEBSHELL_MAX_ROOTS) {
    return;
  }
  struct stat st;
  if (stat(path, &st) != 0 || !S_ISDIR(st.st_mode)) {
    return;
  }
  for (size_t i = 0; i < s_root_count; i++) {
    if (strcmp(s_roots[i].root, path) == 0) {
      return;
    }
  }
  WebRoot *r = &s_roots[s_root_count++];
  memset(r, 0, sizeof(*r));
  snprintf(r->root, sizeof(r->root), "%s", path);
  infer_service(path, r->service_name, sizeof(r->service_name), &r->port);
}

static void discover_web_roots(void) {
  s_root_count = 0;
  add_root("/var/www/html");
  add_root("/usr/share/nginx/html");
  add_root("/srv/www");
  add_root("/opt/tomcat/webapps");
  add_root("/var/lib/tomcat/webapps");

  const char *extra = getenv("EDR_WEBSHELL_ROOTS");
  if (!extra || !extra[0]) {
    return;
  }
  char *dup = strdup(extra);
  if (!dup) {
    return;
  }
  char *save = NULL;
  for (char *tok = strtok_r(dup, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
    while (*tok == ' ' || *tok == '\t') {
      tok++;
    }
    add_root(tok);
  }
  free(dup);
}

static const WebRoot *find_root_for_path(const char *path) {
  const WebRoot *best = NULL;
  size_t best_len = 0;
  for (size_t i = 0; i < s_root_count; i++) {
    size_t n = strlen(s_roots[i].root);
    if (n > best_len && starts_with_ci(path, s_roots[i].root)) {
      best = &s_roots[i];
      best_len = n;
    }
  }
  return best;
}

static void normalize_path(char *s) {
  for (; *s; s++) {
    if (*s == '\\') {
      *s = '/';
    }
  }
}

static void infer_web_url(const WebRoot *root, const char *file_path, char *out, size_t out_cap) {
  if (!root || !out || out_cap == 0u) {
    return;
  }
  char host[128] = "localhost";
  (void)gethostname(host, sizeof(host));
  const char *rel = file_path + strlen(root->root);
  if (*rel == '/' || *rel == '\\') {
    rel++;
  }
  char rel_norm[PATH_MAX];
  snprintf(rel_norm, sizeof(rel_norm), "/%s", rel);
  normalize_path(rel_norm);
  if (root->port == 80u) {
    snprintf(out, out_cap, "http://%s%s", host, rel_norm);
  } else if (root->port == 443u) {
    snprintf(out, out_cap, "https://%s%s", host, rel_norm);
  } else {
    snprintf(out, out_cap, "http://%s:%u%s", host, (unsigned)root->port, rel_norm);
  }
}

static float confidence_for_rule(const char *rule) {
  if (!rule || !rule[0]) {
    return 0.0f;
  }
  if (strcmp(rule, "PHP_Webshell_ChinaChopper") == 0) {
    return 1.0f;
  }
  if (strcmp(rule, "PHP_Webshell_OneLiners") == 0 || strcmp(rule, "JSP_Webshell_ClassLoader") == 0) {
    return 0.95f;
  }
  if (strcmp(rule, "JSP_Webshell_Runtime_Exec") == 0 || strcmp(rule, "ASPX_Webshell_Eval") == 0) {
    return 0.90f;
  }
  if (strcmp(rule, "ASPX_Webshell_CommandExec") == 0) {
    return 0.85f;
  }
  if (strcmp(rule, "PHP_Webshell_FunctionObfuscation") == 0) {
    return 0.80f;
  }
  if (strcmp(rule, "PHP_Webshell_SystemCommand") == 0) {
    return 0.75f;
  }
  if (strcmp(rule, "PHP_Webshell_FilesystemWrite") == 0) {
    return 0.70f;
  }
  if (strcmp(rule, "Generic_Webshell_Encoding_Layering") == 0) {
    return 0.65f;
  }
  return 0.60f;
}

static int read_file_small(const char *path, char **out_buf, size_t *out_len) {
  *out_buf = NULL;
  *out_len = 0u;
  FILE *f = fopen(path, "rb");
  if (!f) {
    return -1;
  }
  if (fseek(f, 0, SEEK_END) != 0) {
    fclose(f);
    return -1;
  }
  long sz = ftell(f);
  if (sz <= 0 || sz > (long)(10 * 1024 * 1024)) {
    fclose(f);
    return -1;
  }
  if (fseek(f, 0, SEEK_SET) != 0) {
    fclose(f);
    return -1;
  }
  char *buf = (char *)malloc((size_t)sz + 1u);
  if (!buf) {
    fclose(f);
    return -1;
  }
  size_t n = fread(buf, 1, (size_t)sz, f);
  fclose(f);
  buf[n] = '\0';
  *out_buf = buf;
  *out_len = n;
  return 0;
}

#ifdef EDR_HAVE_YARA
static int is_rule_file(const char *name) {
  const char *dot = strrchr(name, '.');
  if (!dot) {
    return 0;
  }
  return strcmp(dot, ".yar") == 0 || strcmp(dot, ".yara") == 0;
}

static int yara_compile_cb(int err_level, const char *file_name, int line_number, const YR_RULE *rule,
                           const char *message, void *user_data) {
  (void)err_level;
  (void)rule;
  (void)user_data;
  fprintf(stderr, "[webshell_detector] yara compile error file=%s line=%d msg=%s\n", file_name ? file_name : "-",
          line_number, message ? message : "-");
  return 0;
}

static int yara_scan_cb(int msg, void *msg_data, void *user_data) {
  WebshellRuleMatch *m = (WebshellRuleMatch *)user_data;
  if (msg == CALLBACK_MSG_RULE_MATCHING && m && !m->matched) {
    const YR_RULE *r = (const YR_RULE *)msg_data;
    if (r) {
      snprintf(m->rule_name, sizeof(m->rule_name), "%s", r->identifier);
      m->confidence = confidence_for_rule(r->identifier);
      m->matched = 1;
      return CALLBACK_ABORT;
    }
  }
  return CALLBACK_CONTINUE;
}

static void unload_yara(void) {
  if (s_yara_rules) {
    yr_rules_destroy(s_yara_rules);
    s_yara_rules = NULL;
  }
  if (s_yara_inited) {
    yr_finalize();
    s_yara_inited = 0;
  }
}

static int load_yara(const char *dir) {
  if (!dir || !dir[0]) {
    return 0;
  }
  if (yr_initialize() != ERROR_SUCCESS) {
    return -1;
  }
  s_yara_inited = 1;
  YR_COMPILER *c = NULL;
  if (yr_compiler_create(&c) != ERROR_SUCCESS || !c) {
    unload_yara();
    return -1;
  }
  yr_compiler_set_callback(c, yara_compile_cb, NULL);
  DIR *d = opendir(dir);
  if (!d) {
    yr_compiler_destroy(c);
    unload_yara();
    return -1;
  }
  int loaded = 0;
  for (;;) {
    struct dirent *ent = readdir(d);
    if (!ent) {
      break;
    }
    if (ent->d_name[0] == '.' || !is_rule_file(ent->d_name)) {
      continue;
    }
    char full[PATH_MAX];
    snprintf(full, sizeof(full), "%s/%s", dir, ent->d_name);
    FILE *fp = fopen(full, "rb");
    if (!fp) {
      continue;
    }
    int nerr = yr_compiler_add_file(c, fp, NULL, full);
    fclose(fp);
    if (nerr == 0) {
      loaded++;
    }
  }
  closedir(d);
  if (loaded <= 0) {
    yr_compiler_destroy(c);
    unload_yara();
    return 0;
  }
  if (yr_compiler_get_rules(c, &s_yara_rules) != ERROR_SUCCESS || !s_yara_rules) {
    yr_compiler_destroy(c);
    unload_yara();
    return -1;
  }
  yr_compiler_destroy(c);
  fprintf(stderr, "[webshell_detector] yara rules loaded=%d from %s\n", loaded, dir);
  return loaded;
}
#endif

static int fallback_match_text(const char *text, WebshellRuleMatch *out) {
  if (!text || !out) {
    return 0;
  }
  if ((strcasestr(text, "eval(") && strcasestr(text, "$_POST")) || strcasestr(text, "eval(base64_decode($_POST")) {
    snprintf(out->rule_name, sizeof(out->rule_name), "%s", "PHP_Webshell_OneLiners");
    out->confidence = 0.95f;
    out->matched = 1;
    return 1;
  }
  if (strcasestr(text, "Runtime.getRuntime().exec(") && strcasestr(text, "request.getParameter")) {
    snprintf(out->rule_name, sizeof(out->rule_name), "%s", "JSP_Webshell_Runtime_Exec");
    out->confidence = 0.90f;
    out->matched = 1;
    return 1;
  }
  if ((strcasestr(text, "Process.Start(") || strcasestr(text, "new Process()")) && strcasestr(text, "Request.")) {
    snprintf(out->rule_name, sizeof(out->rule_name), "%s", "ASPX_Webshell_CommandExec");
    out->confidence = 0.85f;
    out->matched = 1;
    return 1;
  }
  return 0;
}

static int scan_webshell(const char *path, WebshellRuleMatch *out) {
  memset(out, 0, sizeof(*out));
  float ave_conf = 0.0f;
  AVEScanResult avr;
  memset(&avr, 0, sizeof(avr));
  if (AVE_ScanFile(path, &avr) == AVE_OK && avr.final_confidence > 0.0f) {
    ave_conf = avr.final_confidence;
  }

#ifdef EDR_HAVE_YARA
  if (s_yara_rules) {
    WebshellRuleMatch m;
    memset(&m, 0, sizeof(m));
    if (yr_rules_scan_file(s_yara_rules, path, 0, yara_scan_cb, &m, 0) == ERROR_SUCCESS && m.matched) {
      float c = m.confidence * 0.7f + ave_conf * 0.3f;
      if (ave_conf > c) {
        c = ave_conf;
      }
      m.confidence = c;
      *out = m;
      return 1;
    }
  }
#endif

  char *buf = NULL;
  size_t len = 0;
  if (read_file_small(path, &buf, &len) != 0) {
    return 0;
  }
  (void)len;
  WebshellRuleMatch m;
  memset(&m, 0, sizeof(m));
  if (fallback_match_text(buf, &m)) {
    float c = m.confidence * 0.7f + ave_conf * 0.3f;
    if (ave_conf > c) {
      c = ave_conf;
    }
    m.confidence = c;
    *out = m;
    free(buf);
    return 1;
  }
  free(buf);
  return 0;
}

static int push_alert_event(const char *path, const char *action, const WebRoot *root, const WebshellRuleMatch *m) {
  if (!s_bus || !path || !root || !m) {
    return 0;
  }
  char url[512];
  char alert_id[64];
  char fp[32];
  char object_key[512];
  char staged_path[1024];
  int file_uploaded = 0;
  edr_webshell_make_alert_id(alert_id, sizeof(alert_id));
  if (edr_webshell_file_fingerprint(path, fp, sizeof(fp)) != 0) {
    fp[0] = '\0';
  }
  object_key[0] = '\0';
  staged_path[0] = '\0';
  {
    struct stat st;
    uint64_t up_max = (uint64_t)s_cfg->webshell_detector.max_upload_size_mb * 1024ULL * 1024ULL;
    if (s_cfg->webshell_detector.upload_webshell_files && stat(path, &st) == 0 && (uint64_t)st.st_size <= up_max) {
      const char *tenant = "tenant_default";
      if (s_cfg->agent.tenant_id[0]) {
        tenant = s_cfg->agent.tenant_id;
      }
      if (edr_grpc_client_upload_file(alert_id, path, fp[0] ? fp : "", object_key, sizeof(object_key)) == 0 &&
          object_key[0]) {
        file_uploaded = 1;
      } else {
        const char *root_dir =
            s_cfg->shellcode_detector.forensic_dir[0] ? s_cfg->shellcode_detector.forensic_dir : "/tmp/edr_forensic";
        file_uploaded = edr_webshell_stage_file(path, root_dir, tenant, alert_id, object_key, sizeof(object_key),
                                                staged_path, sizeof(staged_path));
      }
    }
  }
  infer_web_url(root, path, url, sizeof(url));
  EdrEventSlot slot;
  memset(&slot, 0, sizeof(slot));
  slot.timestamp_ns = now_ns();
  slot.type = EDR_EVENT_WEBSHELL_DETECTED;
  slot.priority = (m->confidence >= s_cfg->webshell_detector.l2_review_threshold) ? 0 : 1;
  slot.consumed = false;
  int n = snprintf((char *)slot.data, EDR_MAX_EVENT_PAYLOAD,
                   "ETW1\nprov=webshell\ndetector=yara\nrule=%s\nscore=%.6f\nfile=%s\nscript=service=%s action=%s "
                   "url=%s alert_id=%s file_fp=%s file_uploaded=%d object_key=%s local_path=%s\n",
                   m->rule_name, m->confidence, path, root->service_name, action ? action : "-", url, alert_id,
                   fp[0] ? fp : "-", file_uploaded, object_key[0] ? object_key : "-", staged_path[0] ? staged_path : "-");
  if (n < 0 || (size_t)n >= EDR_MAX_EVENT_PAYLOAD) {
    return -1;
  }
  slot.size = (uint32_t)n;
  if (!edr_event_bus_try_push(s_bus, &slot)) {
    fprintf(stderr, "[webshell_detector] event bus full, drop alert: %s\n", path);
  }
  return 0;
}

static const char *wd_to_dir(int wd) {
  for (size_t i = 0; i < s_watch_count; i++) {
    if (s_watches[i].wd == wd) {
      return s_watches[i].dir;
    }
  }
  return NULL;
}

static void maybe_add_watch_recursive(const char *path);

static void add_watch(const char *path) {
  if (s_watch_count >= s_cfg->webshell_detector.max_watch_dirs || s_watch_count >= WEBSHELL_MAX_WATCHES) {
    return;
  }
  for (size_t i = 0; i < s_watch_count; i++) {
    if (strcmp(s_watches[i].dir, path) == 0) {
      return;
    }
  }
  int wd = inotify_add_watch(s_ifd, path, IN_CREATE | IN_CLOSE_WRITE | IN_MOVED_TO);
  if (wd < 0) {
    return;
  }
  s_watches[s_watch_count].wd = wd;
  snprintf(s_watches[s_watch_count].dir, sizeof(s_watches[s_watch_count].dir), "%s", path);
  s_watch_count++;
}

static void maybe_add_watch_recursive(const char *path) {
  add_watch(path);
  if (!s_cfg->webshell_detector.monitor_subdirs) {
    return;
  }
  DIR *d = opendir(path);
  if (!d) {
    return;
  }
  for (;;) {
    struct dirent *ent = readdir(d);
    if (!ent) {
      break;
    }
    if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) {
      continue;
    }
    if (ent->d_type != DT_DIR) {
      continue;
    }
    char sub[PATH_MAX];
    snprintf(sub, sizeof(sub), "%s/%s", path, ent->d_name);
    maybe_add_watch_recursive(sub);
  }
  closedir(d);
}

static void handle_change(const char *full_path, const char *action) {
  if (!full_path || !full_path[0]) {
    return;
  }
  const WebRoot *root = find_root_for_path(full_path);
  if (!root) {
    return;
  }
  if (!pre_filter(full_path)) {
    return;
  }
  WebshellRuleMatch m;
  if (!scan_webshell(full_path, &m)) {
    return;
  }
  if (m.confidence < (float)s_cfg->webshell_detector.alert_threshold) {
    return;
  }
  (void)push_alert_event(full_path, action, root, &m);
  fprintf(stderr, "[webshell_detector] alert %.2f rule=%s file=%s\n", m.confidence, m.rule_name, full_path);
}

static void process_inotify_buffer(const char *buf, ssize_t len) {
  for (ssize_t i = 0; i < len;) {
    const struct inotify_event *ev = (const struct inotify_event *)(buf + i);
    i += (ssize_t)(sizeof(struct inotify_event) + ev->len);
    const char *dir = wd_to_dir(ev->wd);
    if (!dir) {
      continue;
    }
    if ((ev->mask & IN_ISDIR) != 0u) {
      if ((ev->mask & (IN_CREATE | IN_MOVED_TO)) != 0u && ev->len > 0u && s_cfg->webshell_detector.monitor_subdirs) {
        char new_dir[PATH_MAX];
        snprintf(new_dir, sizeof(new_dir), "%s/%s", dir, ev->name);
        maybe_add_watch_recursive(new_dir);
      }
      continue;
    }
    if (ev->len == 0u) {
      continue;
    }
    char full[PATH_MAX];
    snprintf(full, sizeof(full), "%s/%s", dir, ev->name);
    if ((ev->mask & IN_CREATE) != 0u) {
      handle_change(full, "created");
    } else if ((ev->mask & IN_MOVED_TO) != 0u) {
      handle_change(full, "moved_in");
    } else if ((ev->mask & IN_CLOSE_WRITE) != 0u) {
      handle_change(full, "modified");
    }
  }
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

static void *watcher_thread(void *arg) {
  (void)arg;
  char buf[WEBSHELL_INOTIFY_BUF] __attribute__((aligned(sizeof(struct inotify_event))));
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
    if ((fds[1].revents & (POLLIN | POLLHUP)) != 0) {
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

EdrError edr_webshell_detector_init(const EdrConfig *cfg, EdrEventBus *bus) {
  if (!cfg) {
    return EDR_ERR_INVALID_ARG;
  }
  if (!cfg->webshell_detector.enabled) {
    return EDR_OK;
  }
  if (s_started) {
    return EDR_OK;
  }

  s_cfg = cfg;
  s_bus = bus;
  discover_web_roots();
  if (s_root_count == 0u) {
    fprintf(stderr, "[webshell_detector] no web roots discovered, set EDR_WEBSHELL_ROOTS to enable\n");
    return EDR_OK;
  }

#ifdef EDR_HAVE_YARA
  if (load_yara(cfg->webshell_detector.webshell_rules_dir) < 0) {
    fprintf(stderr, "[webshell_detector] yara unavailable, fallback to builtin rules\n");
  }
#endif

  if (pipe(s_pipe) != 0) {
    return EDR_ERR_INTERNAL;
  }
  s_ifd = inotify_init1(IN_CLOEXEC | IN_NONBLOCK);
  if (s_ifd < 0) {
    close_pipe_pair();
    return EDR_ERR_INTERNAL;
  }
  s_watch_count = 0;
  for (size_t i = 0; i < s_root_count; i++) {
    maybe_add_watch_recursive(s_roots[i].root);
  }
  if (s_watch_count == 0u) {
    close(s_ifd);
    s_ifd = -1;
    close_pipe_pair();
    return EDR_OK;
  }
  s_stop = 0;
  if (pthread_create(&s_thread, NULL, watcher_thread, NULL) != 0) {
    close(s_ifd);
    s_ifd = -1;
    close_pipe_pair();
    return EDR_ERR_INTERNAL;
  }
  s_started = 1;
  fprintf(stderr, "[webshell_detector] started roots=%zu watches=%zu\n", s_root_count, s_watch_count);
  return EDR_OK;
}

void edr_webshell_detector_shutdown(void) {
  if (!s_started) {
    return;
  }
  s_stop = 1;
  if (s_pipe[1] >= 0) {
    char b = 0;
    (void)write(s_pipe[1], &b, 1);
  }
  (void)pthread_join(s_thread, NULL);
  if (s_ifd >= 0) {
    for (size_t i = 0; i < s_watch_count; i++) {
      (void)inotify_rm_watch(s_ifd, s_watches[i].wd);
    }
    close(s_ifd);
    s_ifd = -1;
  }
  close_pipe_pair();
  s_watch_count = 0;
  s_root_count = 0;
  s_started = 0;
  s_cfg = NULL;
  s_bus = NULL;
#ifdef EDR_HAVE_YARA
  unload_yara();
#endif
}
