#include "edr/forensic_limits.h"
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
#include <io.h>
#include <fcntl.h>
#include <sys/stat.h>
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
  int has_management_reachable = 0;
  for (const cJSON *p = root->child; p; p = p->next) {
    if (!p->string) {
      cJSON_Delete(root); return 0;
    }
    for (const cJSON *q = p->next; q; q = q->next) {
      if (p->string && q->string && strcmp(p->string, q->string) == 0) {
        cJSON_Delete(root); return 0;
      }
    }
    if (strcmp(p->string, "schema") != 0 &&
        strcmp(p->string, "isolated") != 0 &&
        strcmp(p->string, "restored") != 0 &&
        strcmp(p->string, "enforcement_verified") != 0) {
      if (strcmp(p->string, "management_reachable") != 0 ||
          (!cJSON_IsBool(p) && !cJSON_IsNull(p))) {
        cJSON_Delete(root); return 0;
      }
      has_management_reachable = 1;
    }
    count++;
  }
  const cJSON *schema = cJSON_GetObjectItemCaseSensitive(root, "schema");
  const cJSON *isolated = cJSON_GetObjectItemCaseSensitive(root, "isolated");
  const cJSON *restored = cJSON_GetObjectItemCaseSensitive(root, "restored");
  const cJSON *verified = cJSON_GetObjectItemCaseSensitive(root, "enforcement_verified");
  int ok = count == 4 + has_management_reachable && cJSON_IsString(schema) &&
      strcmp(schema->valuestring, "edr.isolation.status.v1") == 0 &&
      cJSON_IsTrue(verified) && cJSON_IsBool(isolated) && cJSON_IsBool(restored) &&
      (expect_isolated ? (cJSON_IsTrue(isolated) && cJSON_IsFalse(restored))
                       : (cJSON_IsFalse(isolated) && cJSON_IsTrue(restored)));
  cJSON_Delete(root);
  return ok;
}

int response_isolation_observation_valid(const char *json) {
  cJSON *root = json ? cJSON_ParseWithOpts(json, NULL, 1) : NULL;
  if (!cJSON_IsObject(root)) { cJSON_Delete(root); return 0; }
  int count = 0;
  for (const cJSON *p = root->child; p; p = p->next) {
    if (!p->string || (strcmp(p->string, "schema") && strcmp(p->string, "state") &&
        strcmp(p->string, "restoration_verified") && strcmp(p->string, "reason"))) {
      cJSON_Delete(root); return 0;
    }
    for (const cJSON *q = p->next; q; q = q->next) {
      if (q->string && strcmp(p->string, q->string) == 0) { cJSON_Delete(root); return 0; }
    }
    count++;
  }
  const cJSON *schema = cJSON_GetObjectItemCaseSensitive(root, "schema");
  const cJSON *state = cJSON_GetObjectItemCaseSensitive(root, "state");
  const cJSON *restored = cJSON_GetObjectItemCaseSensitive(root, "restoration_verified");
  const cJSON *reason = cJSON_GetObjectItemCaseSensitive(root, "reason");
  int ok = count == 4 && cJSON_IsString(schema) &&
      strcmp(schema->valuestring, "edr.isolation.observation.v2") == 0 &&
      cJSON_IsString(state) && cJSON_IsBool(restored) && cJSON_IsString(reason) &&
      strlen(reason->valuestring) <= 160 &&
      (strcmp(state->valuestring, "normal") == 0 ||
       strcmp(state->valuestring, "isolated") == 0 || strcmp(state->valuestring, "unknown") == 0) &&
      (!cJSON_IsTrue(restored) || strcmp(state->valuestring, "normal") == 0);
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

/* This path owns only a bounded, on-demand copy. Keep the original handle
 * through validation; never reopen it for content or remove a partial copy. */
#ifdef _WIN32
#include "edr/windows_file_identity.h"
#endif
#ifdef EDR_RESPONSE_COPY_TESTING
static void (*response_copy_test_chunk)(const char *, const char *);
void response_copy_test_set_chunk(void (*callback)(const char *, const char *)) {
  response_copy_test_chunk = callback;
}
#endif
static int response_forensic_copy_limited(const char *src, const char *dst, size_t *remaining) {
  FILE *in = NULL, *out = NULL;
  const char *failure = "source_open_failed";
  int result = EDR_RESPONSE_COPY_SOURCE_UNAVAILABLE;
  size_t copied = 0;
#ifdef _WIN32
  void *native = NULL;
  char identity[EDR_WINDOWS_FILE_IDENTITY_V1_CAP], observed[EDR_WINDOWS_FILE_IDENTITY_V1_CAP];
  uint64_t write_time = 0, observed_time = 0;
  LARGE_INTEGER before_size, after_size;
  if (!edr_windows_file_identity_open_readonly(src, &native, identity, sizeof(identity), &write_time)) goto done;
  HANDLE source = (HANDLE)native;
  if (GetFileType(source) != FILE_TYPE_DISK || !GetFileSizeEx(source, &before_size) || before_size.QuadPart < 0) {
    CloseHandle(source); failure = "source_not_regular"; goto done;
  }
  int input_fd = _open_osfhandle((intptr_t)source, _O_RDONLY | _O_BINARY | _O_NOINHERIT);
  if (input_fd < 0) { CloseHandle(source); goto done; }
  in = _fdopen(input_fd, "rb");
  if (!in) { _close(input_fd); goto done; }
  failure = "destination_create_failed";
  result = EDR_RESPONSE_COPY_DESTINATION_FAILED;
  HANDLE target = CreateFileA(dst, GENERIC_WRITE, 0, NULL, CREATE_NEW,
      FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
  if (target == INVALID_HANDLE_VALUE) goto done;
  int output_fd = _open_osfhandle((intptr_t)target, _O_WRONLY | _O_BINARY | _O_NOINHERIT);
  if (output_fd < 0) { CloseHandle(target); goto done; }
  out = _fdopen(output_fd, "wb");
  if (!out) { _close(output_fd); goto done; }
#else
  struct stat before, after, named;
  int input_fd = open(src, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
  if (input_fd < 0) goto done;
  if (fstat(input_fd, &before) || !S_ISREG(before.st_mode) || before.st_size < 0) {
    close(input_fd); failure = "source_not_regular"; goto done;
  }
  in = fdopen(input_fd, "rb");
  if (!in) { close(input_fd); goto done; }
  failure = "destination_create_failed";
  result = EDR_RESPONSE_COPY_DESTINATION_FAILED;
  int output_fd = open(dst, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
  if (output_fd < 0) goto done;
  out = fdopen(output_fd, "wb");
  if (!out) { close(output_fd); goto done; }
#endif
  char buf[65536]; size_t n;
  failure = NULL; result = 0;
  while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
    if (n > *remaining) { failure = "aggregate_byte_budget_exceeded"; result = EDR_RESPONSE_BYTE_BUDGET_EXCEEDED; break; }
    size_t written = fwrite(buf, 1, n, out);
    *remaining -= written; copied += written;
    if (written != n) { failure = "destination_write_failed"; result = EDR_RESPONSE_COPY_DESTINATION_FAILED; break; }
#ifdef EDR_RESPONSE_COPY_TESTING
    if (response_copy_test_chunk) response_copy_test_chunk(src, dst);
#endif
  }
  if (!failure && ferror(in)) { failure = "source_read_failed"; result = EDR_RESPONSE_COPY_SOURCE_UNAVAILABLE; }
  if (!failure) {
#ifdef _WIN32
    if (!GetFileSizeEx(source, &after_size) || before_size.QuadPart != after_size.QuadPart ||
        (uint64_t)after_size.QuadPart != copied ||
        !edr_windows_file_identity_from_handle(source, observed, sizeof(observed), &observed_time) ||
        !edr_windows_file_identity_snapshot_matches(identity, write_time, observed, observed_time) ||
        !edr_windows_file_identity_from_path(src, observed, sizeof(observed), &observed_time) ||
        !edr_windows_file_identity_snapshot_matches(identity, write_time, observed, observed_time))
      { failure = "source_identity_or_content_changed"; result = EDR_RESPONSE_COPY_IDENTITY_CHANGED; }
#else
    if (fstat(input_fd, &after) || lstat(src, &named) || !S_ISREG(named.st_mode) ||
        before.st_dev != after.st_dev || before.st_ino != after.st_ino ||
        before.st_dev != named.st_dev || before.st_ino != named.st_ino ||
        before.st_size != after.st_size || (uint64_t)after.st_size != copied ||
#ifdef __APPLE__
        before.st_mtimespec.tv_sec != after.st_mtimespec.tv_sec || before.st_mtimespec.tv_nsec != after.st_mtimespec.tv_nsec ||
        before.st_ctimespec.tv_sec != after.st_ctimespec.tv_sec || before.st_ctimespec.tv_nsec != after.st_ctimespec.tv_nsec ||
#else
        before.st_mtim.tv_sec != after.st_mtim.tv_sec || before.st_mtim.tv_nsec != after.st_mtim.tv_nsec ||
        before.st_ctim.tv_sec != after.st_ctim.tv_sec || before.st_ctim.tv_nsec != after.st_ctim.tv_nsec ||
#endif
        before.st_mode != after.st_mode || after.st_nlink == 0)
      { failure = "source_identity_or_content_changed"; result = EDR_RESPONSE_COPY_IDENTITY_CHANGED; }
#endif
  }
done:
  if (in && fclose(in) && !failure) { failure = "source_close_failed"; result = EDR_RESPONSE_COPY_SOURCE_UNAVAILABLE; }
  if (out && fclose(out) && !failure) { failure = "destination_close_failed"; result = EDR_RESPONSE_COPY_DESTINATION_FAILED; }
  if (failure) fprintf(stderr, "[forensic] bounded_copy_%s; partial evidence retained\n", failure);
  return result;
}

int response_forensic_copy_lines(const char *jobdir, const uint8_t *pl, size_t len) {
  const char *e = getenv("EDR_FORENSIC_COPY_PATHS");
  if (!e || e[0] != '1' || !pl || len == 0u) {
    return 0;
  }
  char work[8192];
  if (len >= sizeof(work)) {
    return EDR_RESPONSE_BYTE_BUDGET_EXCEEDED;
  }
  memcpy(work, pl, len);
  work[len] = 0;
  char *p = work;
  int idx = 0;
  size_t remaining = EDR_FORENSIC_BASELINE_MAX_BYTES - 4096u;
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
      int written = snprintf(dst, sizeof(dst), "%s\\copied_%02d", jobdir, idx++);
#else
      int written = snprintf(dst, sizeof(dst), "%s/copied_%02d", jobdir, idx++);
#endif
      if (written < 0 || (size_t)written >= sizeof(dst) ||
          idx >= (int)EDR_FORENSIC_BASELINE_MAX_FILES) return EDR_RESPONSE_BYTE_BUDGET_EXCEEDED;
      int result = response_forensic_copy_limited(line, dst, &remaining);
      if (result != 0) return result;
    }
    if (!nl) {
      break;
    }
    p = nl + 1;
  }
  return 0;
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
  if (separator == '\\') {
    /* CreateProcess parses the complete command line. The installed Windows
     * output directory lives below Program Files, so both values must remain
     * one argv element when they cross that boundary. Windows paths cannot
     * contain a double quote; reject one instead of emitting ambiguous args. */
    if (strchr(reqpath, '"') || strchr(artifact, '"')) {
      goto invalid;
    }
    written = snprintf(extra_args, extra_args_cap,
                       "--request=\"%s\" --out-file=\"%s\"", reqpath, artifact);
  } else {
    written = snprintf(extra_args, extra_args_cap, "--request=%s --out-file=%s",
                       reqpath, artifact);
  }
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
  char *first = tmp + 1;
#ifdef _WIN32
  /* C: is drive-relative; attempting to create it can target the drive root
   * when the caller's working directory is on another drive. */
  if (n >= 3u && isalpha((unsigned char)tmp[0]) && tmp[1] == ':' &&
      (tmp[2] == '/' || tmp[2] == '\\')) first = tmp + 3;
#endif
  for (char *p = first; *p; p++) {
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

static uint64_t response_tar_now_ms(void) {
#ifdef _WIN32
  return GetTickCount64();
#else
  struct timespec now;
  if(clock_gettime(CLOCK_MONOTONIC,&now))return UINT64_MAX;
  return (uint64_t)now.tv_sec*1000u+(uint64_t)now.tv_nsec/1000000u;
#endif
}
#ifdef EDR_RESPONSE_TAR_TESTING
static const char *response_tar_test_binary;
void response_tar_test_set_binary(const char *path) {response_tar_test_binary=path;}
#endif
#ifdef _WIN32
static int response_tar_quote(const char *path,char *out,size_t cap) {
  if(!path || strchr(path,'"'))return -1;
  size_t n=strlen(path), trailing=0;
  while(trailing<n && path[n-1-trailing]=='\\')trailing++;
  if(n+trailing+3u>cap)return -1;
  out[0]='"';memcpy(out+1,path,n);
  memset(out+1+n,'\\',trailing);out[1+n+trailing]='"';out[2+n+trailing]=0;return 0;
}
#endif
int response_make_tar_bundle(const char *dir,const char *bundle_path,uint32_t timeout_ms,
                             EdrResponseCancelCheck cancel,void *cancel_user) {
  if(!dir || !*dir || !bundle_path || !*bundle_path || !timeout_ms || timeout_ms>300000u)return -1;
  if(cancel && cancel(cancel_user))return EDR_DC_ERR_CANCELLED;
  uint64_t started=response_tar_now_ms();if(started==UINT64_MAX)return -1;
#ifdef _WIN32
  int output_fd=_open(bundle_path,_O_WRONLY|_O_CREAT|_O_EXCL|_O_BINARY|_O_NOINHERIT,_S_IREAD|_S_IWRITE);
  FILE *output=output_fd<0?NULL:_fdopen(output_fd,"wb");
  if(!output && output_fd>=0)_close(output_fd);
#else
  int output_fd=open(bundle_path,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
  FILE *output=output_fd<0?NULL:fdopen(output_fd,"wb");
  if(!output && output_fd>=0)close(output_fd);
#endif
  if(!output)return -1;
  int result=-1,finished=0;size_t written=0;
  unsigned char buffer[16384];
#ifdef _WIN32
  HANDLE reader=NULL,writer=NULL,input=NULL,errors=NULL,job=NULL;
  PROCESS_INFORMATION process={0};STARTUPINFOEXA startup={0};
  char binary[1100],quoted_binary[2204],quoted_dir[2204],command[4500];
  UINT n=GetSystemDirectoryA(binary,sizeof(binary));
  if(!n || n+9u>=sizeof(binary))goto done;
  memcpy(binary+n,"\\tar.exe",9);
#ifdef EDR_RESPONSE_TAR_TESTING
  if(response_tar_test_binary) {
    if(strlen(response_tar_test_binary)>=sizeof(binary))goto done;
    strcpy(binary,response_tar_test_binary);
  }
#endif
  if(response_tar_quote(binary,quoted_binary,sizeof(quoted_binary)) ||
      response_tar_quote(dir,quoted_dir,sizeof(quoted_dir)))goto done;
  int length=snprintf(command,sizeof(command),"%s czf - -C %s .",quoted_binary,quoted_dir);
  if(length<0 || (size_t)length>=sizeof(command))goto done;
  SECURITY_ATTRIBUTES security={sizeof(security),NULL,TRUE};
  /* Bounded on-demand buffer: a 4KiB default plus timed process waits can
   * throttle a healthy archive below its existing command deadline. */
  if(!CreatePipe(&reader,&writer,&security,65536) || !SetHandleInformation(reader,HANDLE_FLAG_INHERIT,0))goto done;
  input=CreateFileA("NUL",GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,&security,OPEN_EXISTING,0,NULL);
  errors=CreateFileA("NUL",GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,&security,OPEN_EXISTING,0,NULL);
  if(input==INVALID_HANDLE_VALUE || errors==INVALID_HANDLE_VALUE)goto done;
  job=CreateJobObjectA(NULL,NULL);if(!job)goto done;
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits={0};
  limits.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
  JOBOBJECT_CPU_RATE_CONTROL_INFORMATION cpu={0};
  cpu.ControlFlags=JOB_OBJECT_CPU_RATE_CONTROL_ENABLE|JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP;
  cpu.CpuRate=1000; /* Existing external collector CPU ceiling. */
  if(!SetInformationJobObject(job,JobObjectExtendedLimitInformation,&limits,sizeof(limits)) ||
      !SetInformationJobObject(job,JobObjectCpuRateControlInformation,&cpu,sizeof(cpu)))goto done;
  SIZE_T attr_size=0;InitializeProcThreadAttributeList(NULL,1,0,&attr_size);
  startup.lpAttributeList=HeapAlloc(GetProcessHeap(),0,attr_size);
  if(!startup.lpAttributeList)goto done;
  if(!InitializeProcThreadAttributeList(startup.lpAttributeList,1,0,&attr_size)) {
    HeapFree(GetProcessHeap(),0,startup.lpAttributeList);startup.lpAttributeList=NULL;goto done;
  }
  HANDLE inherited[]={writer,input,errors};
  if(!UpdateProcThreadAttribute(startup.lpAttributeList,0,PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
      inherited,sizeof(inherited),NULL,NULL))goto done;
  startup.StartupInfo.cb=sizeof(startup);startup.StartupInfo.dwFlags=STARTF_USESTDHANDLES;
  startup.StartupInfo.hStdOutput=writer;startup.StartupInfo.hStdInput=input;startup.StartupInfo.hStdError=errors;
  if(!CreateProcessA(binary,command,NULL,NULL,TRUE,
      CREATE_SUSPENDED|CREATE_NO_WINDOW|EXTENDED_STARTUPINFO_PRESENT,NULL,NULL,
      &startup.StartupInfo,&process))goto done;
  if(!AssignProcessToJobObject(job,process.hProcess) || ResumeThread(process.hThread)==(DWORD)-1)goto stop;
  CloseHandle(writer);writer=NULL;
  while(1) {
    if(cancel && cancel(cancel_user)){result=EDR_DC_ERR_CANCELLED;break;}
    uint64_t now=response_tar_now_ms();
    if(now==UINT64_MAX || now-started>=timeout_ms){result=EDR_DC_ERR_TIMEOUT;break;}
    DWORD available=0,count=0;int broken=0;
    if(!PeekNamedPipe(reader,NULL,0,NULL,&available,NULL)) {
      if(GetLastError()!=ERROR_BROKEN_PIPE)break;
      available=0;broken=1;
    }
    if(available) {
      DWORD amount=available<sizeof(buffer)?available:(DWORD)sizeof(buffer);
      if(!ReadFile(reader,buffer,amount,&count,NULL) || !count)break;
      if(count>EDR_FORENSIC_BASELINE_MAX_BYTES-written){result=EDR_RESPONSE_BYTE_BUDGET_EXCEEDED;break;}
      if(fwrite(buffer,1,count,output)!=count)break;written+=count;
      continue;
    }
    if(finished && broken) {
      DWORD code=1;result=GetExitCodeProcess(process.hProcess,&code) && code==0?0:-1;break;
    }
    if(finished){Sleep(1);continue;}
    DWORD waited=WaitForSingleObject(process.hProcess,1);
    if(waited==WAIT_OBJECT_0) {
      finished=1;continue; /* Drain bytes written between Peek and child exit. */
    }
    if(waited!=WAIT_TIMEOUT)break;
  }
stop:
  if(!finished || result!=0) {
    (void)TerminateJobObject(job,1);(void)TerminateProcess(process.hProcess,1);
    if(WaitForSingleObject(process.hProcess,5000)!=WAIT_OBJECT_0)result=EDR_RESPONSE_WRITER_UNCONFIRMED;
  }
done:
  if(process.hThread)CloseHandle(process.hThread);
  if(process.hProcess)CloseHandle(process.hProcess);
  if(job)CloseHandle(job);
  if(startup.lpAttributeList){DeleteProcThreadAttributeList(startup.lpAttributeList);HeapFree(GetProcessHeap(),0,startup.lpAttributeList);}
  if(reader)CloseHandle(reader);if(writer)CloseHandle(writer);
  if(input && input!=INVALID_HANDLE_VALUE)CloseHandle(input);
  if(errors && errors!=INVALID_HANDLE_VALUE)CloseHandle(errors);
#else
  const char *binary="tar";
#ifdef EDR_RESPONSE_TAR_TESTING
  if(response_tar_test_binary)binary=response_tar_test_binary;
#endif
  int pipes[2];if(pipe(pipes)){fclose(output);return -1;}
  if(fcntl(pipes[0],F_SETFL,O_NONBLOCK)<0 || fcntl(pipes[0],F_SETFD,FD_CLOEXEC)<0 ||
      fcntl(pipes[1],F_SETFD,FD_CLOEXEC)<0) {
    close(pipes[0]);close(pipes[1]);fclose(output);return -1;
  }
  pid_t child=fork();
  if(child<0){close(pipes[0]);close(pipes[1]);fclose(output);return -1;}
  if(child==0) {
    if(setpgid(0,0) || dup2(pipes[1],STDOUT_FILENO)<0)_exit(126);
    close(pipes[0]);close(pipes[1]);
    execlp(binary,binary,"czf","-","-C",dir,".",(char *)NULL);_exit(127);
  }
  close(pipes[1]);(void)setpgid(child,child);int status=0;
  while(1) {
    if(cancel && cancel(cancel_user)){result=EDR_DC_ERR_CANCELLED;break;}
    uint64_t now=response_tar_now_ms();
    if(now==UINT64_MAX || now-started>=timeout_ms){result=EDR_DC_ERR_TIMEOUT;break;}
    ssize_t count=read(pipes[0],buffer,sizeof(buffer));
    if(count>0) {
      if((size_t)count>EDR_FORENSIC_BASELINE_MAX_BYTES-written){result=EDR_RESPONSE_BYTE_BUDGET_EXCEEDED;break;}
      if(fwrite(buffer,1,(size_t)count,output)!=(size_t)count)break;
      written+=(size_t)count;continue;
    }
    if(count<0 && errno!=EAGAIN && errno!=EINTR)break;
    if(!finished) {
      pid_t waited=waitpid(child,&status,WNOHANG);
      if(waited==child)finished=1;
      else if(waited<0 && errno!=EINTR)break;
    }
    if(finished && count==0){result=WIFEXITED(status)&&WEXITSTATUS(status)==0?0:-1;break;}
    struct timespec pause={0,1000000};(void)nanosleep(&pause,NULL);
  }
  close(pipes[0]);
  if(finished && result!=0)(void)kill(-child,SIGKILL);
  if(!finished) {
    (void)kill(-child,SIGKILL);(void)kill(child,SIGKILL);
    for(unsigned tries=0;tries<200u;tries++) {
      pid_t waited=waitpid(child,&status,WNOHANG);
      if(waited==child){finished=1;break;}
      if(waited<0 && errno!=EINTR)break;
      struct timespec pause={0,25000000};(void)nanosleep(&pause,NULL);
    }
    if(!finished)result=EDR_RESPONSE_WRITER_UNCONFIRMED;
  }
#endif
  if(fclose(output) && result!=EDR_RESPONSE_WRITER_UNCONFIRMED)result=-1;
  /* Failed/partial staging belongs to its durable owner; never unlink it here. */
  return result;
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
