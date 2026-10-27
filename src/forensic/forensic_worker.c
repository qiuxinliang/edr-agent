#include "edr/forensic_worker.h"
#include "edr/forensic_path.h"
#include "edr/forensic_limits.h"
#include "edr/deep_collector.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <wchar.h>
#ifdef _WIN32
#include <windows.h>
#include <io.h>
#else
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <sys/socket.h>
#include <sys/wait.h>
#ifdef __APPLE__
#include <mach-o/dyld.h>
#endif
extern char **environ;
#endif

typedef struct { EdrForensicIoRequest request; EdrForensicIoResult result; } IoExchange;
static uint64_t io_clock(void) {
#ifdef _WIN32
  return GetTickCount64();
#else
  struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))return UINT64_MAX;
  return (uint64_t)t.tv_sec*1000u+(uint64_t)t.tv_nsec/1000000u;
#endif
}
#ifdef EDR_FORENSIC_IO_TESTING
static void io_block_test(const EdrForensicIoRequest *q,unsigned phase) {
  if((q->operation>>8)!=phase)return;
  char path[900];snprintf(path,sizeof(path),"%s/blocked",q->workspace);
  EdrForensicPath *guard=NULL;
  if(edr_forensic_path_acquire(path,1,&guard))abort();
  FILE *f=edr_forensic_path_file(guard,"wbx");if(!f)abort();
  if(fprintf(f,"%u",phase)<0 || fclose(f))abort();edr_forensic_path_release(guard);
  /* Actual synchronous kernel read, with a live writer and no data. Only the
   * outside process supervisor can end this deliberately blocked test I/O. */
#ifdef _WIN32
  HANDLE reader,writer;DWORD n;char byte;
  if(!CreatePipe(&reader,&writer,NULL,0))abort();
  (void)ReadFile(reader,&byte,1,&n,NULL);CloseHandle(reader);CloseHandle(writer);
#else
  int pipes[2];char byte;if(pipe(pipes))abort();
  (void)read(pipes[0],&byte,1);close(pipes[0]);close(pipes[1]);
#endif
}
#else
#define io_block_test(q,phase) ((void)0)
#endif
static void io_work(const EdrForensicIoRequest *q,EdrForensicIoResult *r) {
  memset(r,0,sizeof(*r));r->version=1;r->rc=-1;
  if(q->version!=1 || q->payload_len>=sizeof(q->payload) || !q->timeout_ms || q->timeout_ms>300000u ||
     !memchr(q->workspace,0,sizeof(q->workspace)) || !memchr(q->staging,0,sizeof(q->staging)) ||
     !memchr(q->manifest,0,sizeof(q->manifest)))return;
  uint32_t operation=q->operation;
#ifdef EDR_FORENSIC_IO_TESTING
  operation&=255u;
#endif
  if(operation==2) {r->phase=5;r->rc=edr_forensic_path_hash(q->staging,r->sha256);return;}
  if(operation==3) {r->phase=4;io_block_test(q,4);r->rc=edr_forensic_path_sync_file(q->staging);return;}
  if(operation!=1)return;
  uint64_t started=io_clock();uint32_t remaining=q->timeout_ms;
  EdrForensicPath *manifest=NULL,*staging=NULL;char path[800];
  r->phase=1;io_block_test(q,1);
  if(snprintf(path,sizeof(path),"%s/manifest.txt",q->workspace)>=(int)sizeof(path) ||
     edr_forensic_path_acquire(path,1,&manifest) || edr_forensic_path_acquire(q->staging,0,&staging))goto done;
  FILE *f=edr_forensic_path_file(manifest,"wbx");if(!f)goto done;
  size_t size=strlen(q->manifest);int ok=fwrite(q->manifest,1,size,f)==size;
  if(fclose(f))ok=0;
  if(!ok || !edr_forensic_storage_ready(q->workspace))goto done;
  uint64_t now=io_clock();
  if(started==UINT64_MAX || now==UINT64_MAX || now-started>=remaining){r->rc=EDR_DC_ERR_TIMEOUT;goto done;}
  remaining-=(uint32_t)(now-started);
  r->phase=2;io_block_test(q,2);r->rc=response_forensic_copy_lines(q->workspace,q->payload,q->payload_len,&remaining,NULL,NULL);
  if(r->rc)goto done;
  r->phase=3;io_block_test(q,3);r->rc=remaining ? response_make_tar_bundle(q->workspace,q->staging,remaining,NULL,NULL) : EDR_DC_ERR_TIMEOUT;
  if(r->rc)goto done;
  r->phase=4;io_block_test(q,4);r->rc=-1;
  f=edr_forensic_path_file(staging,"r+b");if(!f)goto done;
#ifdef _WIN32
  ok=_commit(_fileno(f))==0;
#else
  ok=fsync(fileno(f))==0;
#endif
  if(fclose(f))ok=0;
  if(!ok)goto done;
  r->phase=5;io_block_test(q,5);r->rc=edr_forensic_path_hash(q->staging,r->sha256);
done:
  edr_forensic_path_release(staging);edr_forensic_path_release(manifest);
}

int edr_forensic_io_worker_main(const char *endpoint) {
  if(!endpoint || !*endpoint)return 2;
  char *end=NULL;errno=0;unsigned long long value=strtoull(endpoint,&end,10);
  if(errno || !end || *end || !value)return 2;
#ifdef _WIN32
  HANDLE mapping=(HANDLE)(uintptr_t)value;
  IoExchange *shared=MapViewOfFile(mapping,FILE_MAP_READ|FILE_MAP_WRITE,0,0,sizeof(IoExchange));
  if(!shared)return 2;
  EdrForensicIoRequest request=shared->request;io_work(&request,&shared->result);
  UnmapViewOfFile(shared);CloseHandle(mapping);
#else
  if(value!=3)return 2;
  IoExchange shared;memset(&shared,0,sizeof(shared));size_t used=0;
  while(used<sizeof(shared.request)) {
    ssize_t n=read(3,(char *)&shared.request+used,sizeof(shared.request)-used);
    if(n<0 && errno==EINTR)continue;if(n<=0)return 2;used+=(size_t)n;
  }
  /* tar stays in this worker's process group, so the supervisor kills the
   * complete finite job. No inherited endpoint may keep a receipt alive. */
  if(fcntl(3,F_SETFD,FD_CLOEXEC)<0)return 2;
  response_tar_set_worker_group();
  io_work(&shared.request,&shared.result);used=0;
  while(used<sizeof(shared.result)) {
    ssize_t n=write(3,(char *)&shared.result+used,sizeof(shared.result)-used);
    if(n<0 && errno==EINTR)continue;if(n<=0)return 2;used+=(size_t)n;
  }
  close(3);
#endif
  return 0;
}

int edr_forensic_io_run(const EdrForensicIoRequest *q,EdrForensicIoResult *out,
                       EdrResponseCancelCheck cancel,void *user) {
  if(!q || !out)return -1;
  memset(out,0,sizeof(*out));out->rc=-1;
  if(!q->timeout_ms || q->timeout_ms>300000u)return EDR_DC_ERR_TIMEOUT;
  if(cancel && cancel(user))return EDR_DC_ERR_CANCELLED;
  uint64_t started=io_clock();if(started==UINT64_MAX)return -1;
  int result=-1,finished=0;
#ifdef _WIN32
  HANDLE mapping=NULL,job=NULL;IoExchange *shared=NULL;
  PROCESS_INFORMATION process={0};STARTUPINFOEXW startup={0};
  wchar_t binary[32768],command[32880];
  DWORD length=GetModuleFileNameW(NULL,binary,32768);
  if(!length || length>=32768)return -1;
  SECURITY_ATTRIBUTES security={sizeof(security),NULL,TRUE};
  mapping=CreateFileMappingW(INVALID_HANDLE_VALUE,&security,PAGE_READWRITE,0,sizeof(IoExchange),NULL);
  if(!mapping)goto done;
  shared=MapViewOfFile(mapping,FILE_MAP_READ|FILE_MAP_WRITE,0,0,sizeof(IoExchange));if(!shared)goto done;
  memset(shared,0,sizeof(*shared));shared->request=*q;
  job=CreateJobObjectW(NULL,NULL);if(!job)goto done;
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits={0};limits.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
  JOBOBJECT_CPU_RATE_CONTROL_INFORMATION cpu={0};cpu.ControlFlags=JOB_OBJECT_CPU_RATE_CONTROL_ENABLE|JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP;cpu.CpuRate=1000;
  if(!SetInformationJobObject(job,JobObjectExtendedLimitInformation,&limits,sizeof(limits)) ||
     !SetInformationJobObject(job,JobObjectCpuRateControlInformation,&cpu,sizeof(cpu)))goto done;
  SIZE_T bytes=0;InitializeProcThreadAttributeList(NULL,1,0,&bytes);
  startup.lpAttributeList=HeapAlloc(GetProcessHeap(),0,bytes);if(!startup.lpAttributeList)goto done;
  if(!InitializeProcThreadAttributeList(startup.lpAttributeList,1,0,&bytes)) {
    HeapFree(GetProcessHeap(),0,startup.lpAttributeList);startup.lpAttributeList=NULL;goto done;
  }
  if(!UpdateProcThreadAttribute(startup.lpAttributeList,0,PROC_THREAD_ATTRIBUTE_HANDLE_LIST,&mapping,sizeof(mapping),NULL,NULL))goto done;
  startup.StartupInfo.cb=sizeof(startup);
  int n=swprintf(command,32880,L"\"%ls\" --forensic-io-worker-v1 %llu",binary,(unsigned long long)(uintptr_t)mapping);
  if(n<0 || n>=32880)goto done;
  if(!CreateProcessW(binary,command,NULL,NULL,TRUE,CREATE_SUSPENDED|CREATE_NO_WINDOW|EXTENDED_STARTUPINFO_PRESENT,
      NULL,NULL,&startup.StartupInfo,&process))goto done;
  if(!AssignProcessToJobObject(job,process.hProcess) || ResumeThread(process.hThread)==(DWORD)-1)goto stop;
  for(;;) {
    if(cancel && cancel(user)){result=EDR_DC_ERR_CANCELLED;break;}
    uint64_t now=io_clock();if(now==UINT64_MAX || now-started>=q->timeout_ms){result=EDR_DC_ERR_TIMEOUT;break;}
    DWORD wait=WaitForSingleObject(process.hProcess,10);
    if(wait==WAIT_OBJECT_0) {DWORD code=1;finished=1;
      if(GetExitCodeProcess(process.hProcess,&code) && !code && shared->result.version==1) {*out=shared->result;result=out->rc;}
      break;
    }
    if(wait!=WAIT_TIMEOUT)break;
  }
stop:
  if(!finished) {
    (void)TerminateJobObject(job,1);(void)TerminateProcess(process.hProcess,1);
    if(WaitForSingleObject(process.hProcess,1000)!=WAIT_OBJECT_0)result=EDR_RESPONSE_WRITER_UNCONFIRMED;
  }
done:
  if(process.hThread)CloseHandle(process.hThread);if(process.hProcess)CloseHandle(process.hProcess);
  if(job)CloseHandle(job);
  if(startup.lpAttributeList){DeleteProcThreadAttributeList(startup.lpAttributeList);HeapFree(GetProcessHeap(),0,startup.lpAttributeList);}
  if(shared)UnmapViewOfFile(shared);if(mapping)CloseHandle(mapping);
#else
  int sockets[2];if(socketpair(AF_UNIX,SOCK_STREAM,0,sockets))return -1;
  if(fcntl(sockets[0],F_SETFD,FD_CLOEXEC)<0 || fcntl(sockets[1],F_SETFD,FD_CLOEXEC)<0 ||
      fcntl(sockets[0],F_SETFL,O_NONBLOCK)<0){close(sockets[0]);close(sockets[1]);return -1;}
#ifdef __APPLE__
  int no_signal=1;if(setsockopt(sockets[0],SOL_SOCKET,SO_NOSIGPIPE,&no_signal,sizeof(no_signal))){close(sockets[0]);close(sockets[1]);return -1;}
  char binary[4096];uint32_t capacity=sizeof(binary);
  if(_NSGetExecutablePath(binary,&capacity)){close(sockets[0]);close(sockets[1]);return -1;}
#else
  const char *binary="/proc/self/exe";
#endif
  posix_spawn_file_actions_t actions;posix_spawnattr_t attr;pid_t child=-1;
  if(posix_spawn_file_actions_init(&actions)){close(sockets[0]);close(sockets[1]);return -1;}
  if(posix_spawnattr_init(&attr)){posix_spawn_file_actions_destroy(&actions);close(sockets[0]);close(sockets[1]);return -1;}
  int setup=posix_spawn_file_actions_addclose(&actions,sockets[0]);
  if(!setup)setup=posix_spawn_file_actions_adddup2(&actions,sockets[1],3);
  if(!setup && sockets[1]!=3)setup=posix_spawn_file_actions_addclose(&actions,sockets[1]);
  if(!setup)setup=posix_spawnattr_setflags(&attr,POSIX_SPAWN_SETPGROUP);
  if(!setup)setup=posix_spawnattr_setpgroup(&attr,0);
  char *argv[]={(char *)binary,EDR_FORENSIC_WORKER_ARG,"3",NULL};
  int spawn=setup ? setup : posix_spawn(&child,binary,&actions,&attr,argv,environ);
  posix_spawn_file_actions_destroy(&actions);posix_spawnattr_destroy(&attr);close(sockets[1]);
  if(spawn){close(sockets[0]);return -1;}
  size_t sent=0,received=0;int status=0;
  for(;;) {
    if(cancel && cancel(user)){result=EDR_DC_ERR_CANCELLED;break;}
    uint64_t now=io_clock();if(now==UINT64_MAX || now-started>=q->timeout_ms){result=EDR_DC_ERR_TIMEOUT;break;}
    if(sent<sizeof(*q)) {
#ifdef __APPLE__
      int flags=0;
#else
      int flags=MSG_NOSIGNAL;
#endif
      ssize_t n=send(sockets[0],(const char *)q+sent,sizeof(*q)-sent,flags);
      if(n>0)sent+=(size_t)n;else if(n<0 && errno!=EAGAIN && errno!=EINTR)break;
    }
    if(received<sizeof(*out)) {
      ssize_t n=recv(sockets[0],(char *)out+received,sizeof(*out)-received,0);
      if(n>0)received+=(size_t)n;else if(n<0 && errno!=EAGAIN && errno!=EINTR)break;
    }
    pid_t waited=waitpid(child,&status,WNOHANG);
    if(waited==child) {
      finished=1;
      if(received<sizeof(*out)) {
        ssize_t n=recv(sockets[0],(char *)out+received,sizeof(*out)-received,0);
        if(n>0)received+=(size_t)n;
      }
      if(received==sizeof(*out) && WIFEXITED(status) && WEXITSTATUS(status)==0 && out->version==1)result=out->rc;
      break;
    }
    if(waited<0 && errno!=EINTR)break;
    struct timespec delay={0,1000000};nanosleep(&delay,NULL);
  }
  if(!finished) {
    (void)kill(-child,SIGKILL);(void)kill(child,SIGKILL);
    uint64_t stop=io_clock();
    for(unsigned attempt=0;attempt<1000u;attempt++) {
      uint64_t now=io_clock();if(now==UINT64_MAX || stop==UINT64_MAX || now-stop>=1000u)break;
      pid_t waited=waitpid(child,&status,WNOHANG);if(waited==child){finished=1;break;}
      if(waited<0 && errno!=EINTR)break;
      struct timespec delay={0,1000000};nanosleep(&delay,NULL);
    }
    if(!finished)result=EDR_RESPONSE_WRITER_UNCONFIRMED;
  }
  close(sockets[0]);
#endif
  return result;
}
