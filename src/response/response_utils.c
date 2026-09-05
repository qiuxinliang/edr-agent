#include "edr/response.h"
#include "edr/response_utils.h"
#include "edr/command_util.h"
#include "edr/config.h"
#include "edr/deep_collector.h"
#include "edr/error.h"
#include "edr/ingest_http.h"
#include "edr/pmfe.h"
#include "edr/sha256.h"
#include "edr/shell_session.h"
#include "edr/edr_log.h"
#include "edr/pe_verify.h"
#include "edr/shell_exec.h"
#include "cJSON.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <direct.h>
#include <process.h>
#include <windows.h>
#include <dbghelp.h>
#pragma comment(lib, "dbghelp.lib")
#else
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

int response_isolation_status_verified(const char *json, int expect_isolated) {
  const char *end = NULL;
  cJSON *root = json ? cJSON_ParseWithOpts(json, &end, 1) : NULL;
  if (!cJSON_IsObject(root)) { cJSON_Delete(root); return 0; }
  int count = 0;
  for (const cJSON *p = root->child; p; p = p->next) {
    for (const cJSON *q = p->next; q; q = q->next) {
      if (p->string && q->string && strcmp(p->string, q->string) == 0) {
        cJSON_Delete(root); return 0;
      }
    }
    count++;
  }
  const cJSON *schema = cJSON_GetObjectItemCaseSensitive(root, "schema");
  const cJSON *isolated = cJSON_GetObjectItemCaseSensitive(root, "isolated");
  const cJSON *restored = cJSON_GetObjectItemCaseSensitive(root, "restored");
  const cJSON *verified = cJSON_GetObjectItemCaseSensitive(root, "enforcement_verified");
  int ok = count == 4 && cJSON_IsString(schema) &&
      strcmp(schema->valuestring, "edr.isolation.status.v1") == 0 &&
      cJSON_IsTrue(verified) && cJSON_IsBool(isolated) && cJSON_IsBool(restored) &&
      (expect_isolated ? (cJSON_IsTrue(isolated) && cJSON_IsFalse(restored))
                       : (cJSON_IsFalse(isolated) && cJSON_IsTrue(restored)));
  cJSON_Delete(root);
  return ok;
}

int response_forensic_copy_one_file(const char *src, const char *dst) {
#ifdef _WIN32
  return CopyFileA(src, dst, FALSE) ? 0 : -1;
#else
  int fi = open(src, O_RDONLY);
  if (fi < 0) {
    return -1;
  }
  int fo = open(dst, O_CREAT | O_WRONLY | O_TRUNC, 0644);
  if (fo < 0) {
    close(fi);
    return -1;
  }
  char buf[65536];
  ssize_t nr;
  while ((nr = read(fi, buf, sizeof(buf))) > 0) {
    ssize_t off = 0;
    while (off < nr) {
      ssize_t nw = write(fo, buf + off, (size_t)(nr - off));
      if (nw <= 0) {
        close(fi);
        close(fo);
        return -1;
      }
      off += nw;
    }
  }
  close(fi);
  close(fo);
  return nr < 0 ? -1 : 0;
#endif
}

void response_forensic_copy_lines(const char *jobdir, const uint8_t *pl, size_t len) {
  const char *e = getenv("EDR_FORENSIC_COPY_PATHS");
  if (!e || e[0] != '1' || !pl || len == 0u) {
    return;
  }
  char work[8192];
  if (len >= sizeof(work)) {
    len = sizeof(work) - 1u;
  }
  memcpy(work, pl, len);
  work[len] = 0;
  char *p = work;
  int idx = 0;
  for (;;) {
    char *line = p;
    char *nl = strchr(p, '\n');
    if (nl) {
      *nl = 0;
    }
    while (*line == ' ' || *line == '\r') {
      line++;
    }
    if (line[0] && line[0] != '#') {
      char dst[900];
#ifdef _WIN32
      snprintf(dst, sizeof(dst), "%s\\copied_%02d", jobdir, idx++);
#else
      snprintf(dst, sizeof(dst), "%s/copied_%02d", jobdir, idx++);
#endif
      (void)response_forensic_copy_one_file(line, dst);
    }
    if (!nl) {
      break;
    }
    p = nl + 1;
  }
}

void response_sanitize_job_name(const char *src, char *dst, size_t cap) {
  if (!dst || cap == 0u) {
    return;
  }
  size_t j = 0u;
  if (src) {
    for (size_t i = 0u; src[i] && j + 1u < cap; i++) {
      unsigned char c = (unsigned char)src[i];
      if (isalnum(c) || c == '-' || c == '_' || c == '.') {
        dst[j++] = (char)c;
      } else {
        dst[j++] = '_';
      }
    }
  }
  if (j == 0u) {
    snprintf(dst, cap, "%s", "job");
    return;
  }
  dst[j] = '\0';
}

int response_forensic_build_collector_paths(const char *outdir, char separator,
                                            const char *scope, const char *job,
                                            long long timestamp, const char *artifact_ext,
                                            char *reqpath, size_t reqpath_cap,
                                            char *artifact, size_t artifact_cap,
                                            char *extra_args, size_t extra_args_cap) {
  int written;
  if (!reqpath || reqpath_cap == 0u || !artifact || artifact_cap == 0u ||
      !extra_args || extra_args_cap == 0u) {
    return -1;
  }
  reqpath[0] = '\0';
  artifact[0] = '\0';
  extra_args[0] = '\0';
  if (!outdir || !outdir[0] || !scope || !scope[0] || !job || !job[0] ||
      !artifact_ext || !artifact_ext[0]) {
    return -1;
  }

  written = snprintf(reqpath, reqpath_cap, "%s%c%s_%s_%lld.req",
                     outdir, separator, scope, job, timestamp);
  if (written < 0 || (size_t)written >= reqpath_cap) {
    goto invalid;
  }
  written = snprintf(artifact, artifact_cap, "%s%c%s_%s_%lld.%s",
                     outdir, separator, scope, job, timestamp, artifact_ext);
  if (written < 0 || (size_t)written >= artifact_cap) {
    goto invalid;
  }
  written = snprintf(extra_args, extra_args_cap, "--request=%s --out-file=%s",
                     reqpath, artifact);
  if (written < 0 || (size_t)written >= extra_args_cap) {
    goto invalid;
  }
  return 0;

invalid:
  reqpath[0] = '\0';
  artifact[0] = '\0';
  extra_args[0] = '\0';
  return -1;
}

int response_forensic_external_failure_must_not_fallback(int collector_rc) {
  return collector_rc == EDR_FORENSIC_EXTERNAL_ERR_BOUNDS;
}

int response_mkdir_p(const char *path) {
  if (!path || !path[0]) {
    return -1;
  }
  char tmp[1024];
  size_t n = strlen(path);
  if (n >= sizeof(tmp)) {
    return -1;
  }
  memcpy(tmp, path, n + 1u);
  for (char *p = tmp + 1; *p; p++) {
    if (*p == '/' || *p == '\\') {
      char bak = *p;
      *p = '\0';
#ifdef _WIN32
      if (_mkdir(tmp) != 0 && errno != EEXIST) {
        return -1;
      }
#else
      if (mkdir(tmp, 0755) != 0 && errno != EEXIST) {
        return -1;
      }
#endif
      *p = bak;
    }
  }
#ifdef _WIN32
  if (_mkdir(tmp) != 0 && errno != EEXIST) {
    return -1;
  }
#else
  if (mkdir(tmp, 0755) != 0 && errno != EEXIST) {
    return -1;
  }
#endif
  return 0;
}

int response_make_tar_bundle(const char *dir, const char *bundle_path) {
  if (!dir || !dir[0] || !bundle_path || !bundle_path[0]) {
    return -1;
  }
#ifdef _WIN32
  intptr_t rc = _spawnlp(_P_WAIT, "tar", "tar", "czf", bundle_path, "-C", dir, ".", NULL);
  return (rc == 0) ? 0 : -1;
#else
  pid_t pid = fork();
  if (pid < 0) {
    return -1;
  }
  if (pid == 0) {
    execlp("tar", "tar", "czf", bundle_path, "-C", dir, ".", (char *)NULL);
    _exit(127);
  }
  int st = 0;
  if (waitpid(pid, &st, 0) < 0) {
    return -1;
  }
  return (WIFEXITED(st) && WEXITSTATUS(st) == 0) ? 0 : -1;
#endif
}

int response_split_args(char *buf, char *argv[], size_t argv_cap) {
  if (!buf || !argv || argv_cap < 2u) {
    return -1;
  }
  size_t argc = 0u;
  char *p = buf;
  while (*p) {
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') {
      p++;
    }
    if (!*p) {
      break;
    }
    if (argc + 1u >= argv_cap) {
      return -1;
    }
    argv[argc++] = p;
    while (*p && *p != ' ' && *p != '\t' && *p != '\r' && *p != '\n') {
      p++;
    }
    if (*p) {
      *p++ = '\0';
    }
  }
  argv[argc] = NULL;
  return (argc > 0u) ? (int)argc : -1;
}

int response_run_hook_no_shell(const char *hook_cmdline) {
  if (!hook_cmdline || !hook_cmdline[0]) {
    return -1;
  }
  char cmd[1024];
  size_t n = strlen(hook_cmdline);
  if (n >= sizeof(cmd)) {
    return -1;
  }
  memcpy(cmd, hook_cmdline, n + 1u);
  char *argv[32];
  int argc = response_split_args(cmd, argv, sizeof(argv) / sizeof(argv[0]));
  if (argc <= 0) {
    return -1;
  }
#ifdef _WIN32
  intptr_t rc = _spawnvp(_P_WAIT, argv[0], (const char *const *)argv);
  return (rc == 0) ? 0 : -1;
#else
  pid_t pid = fork();
  if (pid < 0) {
    return -1;
  }
  if (pid == 0) {
    execvp(argv[0], argv);
    _exit(127);
  }
  int st = 0;
  if (waitpid(pid, &st, 0) < 0) {
    return -1;
  }
  return (WIFEXITED(st) && WEXITSTATUS(st) == 0) ? 0 : -1;
#endif
}
