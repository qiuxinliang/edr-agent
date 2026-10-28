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
#include <process.h>
#include <io.h>
#else
#include <pthread.h>
#include <stdatomic.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/time.h>
#ifdef __APPLE__
#include <mach-o/dyld.h>
#endif
extern char **environ;
#endif

static EdrForensicCommandWorker command_worker;
static int in_worker;
void edr_forensic_io_set_command_worker(EdrForensicCommandWorker worker) { command_worker=worker; }
int edr_forensic_io_in_worker(void) { return in_worker; }
#ifndef _WIN32
static void io_expired_group(int signal_number) {
  (void)signal_number;(void)kill(0,SIGKILL);_exit(2);
}
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
static void io_test_block_read(void) {
#ifdef _WIN32
  HANDLE reader,writer;DWORD n;char byte;
  if(!CreatePipe(&reader,&writer,NULL,0))abort();
  (void)ReadFile(reader,&byte,1,&n,NULL);CloseHandle(reader);CloseHandle(writer);
#else
  int pipes[2];char byte;if(pipe(pipes))abort();
  (void)read(pipes[0],&byte,1);close(pipes[0]);close(pipes[1]);
#endif
}
static void io_block_test(const EdrForensicIoRequest *q,unsigned phase) {
  if((q->operation>>8)!=phase)return;
  unsigned long descendant=0;
#ifdef _WIN32
  if(phase==3) {
    wchar_t binary[32768],command[32880];
    DWORD length=GetModuleFileNameW(NULL,binary,32768);
    if(!length || length>=32768)abort();
    if(swprintf(command,32880,L"\"%ls\" --forensic-io-worker-v1 blocked-descendant",binary)<0)abort();
    STARTUPINFOW startup={0};PROCESS_INFORMATION child={0};startup.cb=sizeof(startup);
    if(!CreateProcessW(binary,command,NULL,NULL,FALSE,CREATE_NO_WINDOW,NULL,NULL,&startup,&child))abort();
    descendant=child.dwProcessId;CloseHandle(child.hThread);CloseHandle(child.hProcess);
  }
#endif
  char path[900];snprintf(path,sizeof(path),"%s/blocked",q->workspace);
  EdrForensicPath *guard=NULL;
  if(edr_forensic_path_acquire(path,1,&guard))abort();
  FILE *f=edr_forensic_path_file(guard,"wbx");if(!f)abort();
  if(fprintf(f,"%u %lu",phase,descendant)<0 || fclose(f))abort();edr_forensic_path_release(guard);
  /* A live writer and no bytes cause a real synchronous kernel read. */
  io_test_block_read();
}
#else
#define io_block_test(q,phase) ((void)0)
#endif
static void io_work(const EdrForensicIoRequest *q,EdrForensicIoResult *r) {
  memset(r,0,sizeof(*r));r->version=EDR_FORENSIC_IO_VERSION;r->rc=-1;
  if(q->version!=EDR_FORENSIC_IO_VERSION || q->payload_len>=sizeof(q->payload) || !q->timeout_ms || q->timeout_ms>300000u ||
     !memchr(q->workspace,0,sizeof(q->workspace)) || !memchr(q->staging,0,sizeof(q->staging)) ||
     !memchr(q->manifest,0,sizeof(q->manifest)))return;
  uint32_t operation=q->operation;
#ifdef EDR_FORENSIC_IO_TESTING
  operation&=255u;
#endif
  if(operation==4) {r->phase=6;if(command_worker)r->rc=command_worker(q,r);return;}
  if(operation==2 || operation==3) {
    EdrForensicPath *guard=NULL;char identity[65];
    if(!memchr(q->expected_parent,0,sizeof(q->expected_parent)) ||
       edr_forensic_path_acquire(q->staging,0,&guard))return;
    if(edr_forensic_path_identity(guard,identity) ||
       (q->expected_parent[0] && strcmp(identity,q->expected_parent))) {edr_forensic_path_release(guard);return;}
    edr_forensic_path_pin(guard);
    if(operation==2) {r->phase=5;r->rc=edr_forensic_path_hash(q->staging,r->sha256);}
    else {r->phase=4;io_block_test(q,4);r->rc=edr_forensic_path_sync_file(q->staging);}
    edr_forensic_path_release(guard);return;
  }
  if(operation!=1)return;
  uint64_t started=io_clock();uint32_t remaining=q->timeout_ms;
  EdrForensicPath *manifest=NULL,*staging=NULL;char path[800];
  r->phase=1;io_block_test(q,1);
  if(snprintf(path,sizeof(path),"%s/manifest.txt",q->workspace)>=(int)sizeof(path) ||
     edr_forensic_path_acquire(path,1,&manifest) || edr_forensic_path_acquire(q->staging,0,&staging))goto done;
  edr_forensic_path_pin(manifest);edr_forensic_path_pin(staging);
  if(edr_forensic_path_identity(staging,r->directory_identity))goto done;
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
  in_worker=1;
#ifdef EDR_FORENSIC_IO_TESTING
  if(!strcmp(endpoint,"blocked-descendant")){io_test_block_read();return 2;}
#endif
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
  /* A crashed supervisor must not leave a permanently blocked POSIX writer.
   * The private worker owns this process group; its timer kills descendants
   * too. Recovery still retains evidence/credit until quiescence is proven. */
  if(getpgrp()!=getpid() || !shared.request.timeout_ms || shared.request.timeout_ms>300000u)return 2;
  struct sigaction expire={0};expire.sa_handler=io_expired_group;sigemptyset(&expire.sa_mask);
  struct itimerval timer={0};uint64_t budget=(uint64_t)shared.request.timeout_ms+1000u;
  timer.it_value.tv_sec=(time_t)(budget/1000u);timer.it_value.tv_usec=(suseconds_t)(budget%1000u)*1000;
  if(sigaction(SIGALRM,&expire,NULL) || setitimer(ITIMER_REAL,&timer,NULL))return 2;
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

static int io_run_process(const EdrForensicIoRequest *q,EdrForensicIoResult *out,
                       EdrResponseCancelCheck cancel,void *user) {
  if(!q || !out)return -1;
  memset(out,0,sizeof(*out));out->rc=-1;
  if(!q->timeout_ms || q->timeout_ms>300000u)return EDR_DC_ERR_TIMEOUT;
  if(cancel && cancel(user))return EDR_DC_ERR_CANCELLED;
  if(in_worker) {io_work(q,out);return out->rc;}
  uint64_t started=io_clock();if(started==UINT64_MAX)return -1;
  int result=-1,finished=0;
  io_block_test(q,6); /* Actual blocking I/O before process creation, tests only. */
  if(cancel && cancel(user))return EDR_DC_ERR_CANCELLED;
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
  if(cancel && cancel(user)){result=EDR_DC_ERR_CANCELLED;goto stop;}
  if(!AssignProcessToJobObject(job,process.hProcess) || ResumeThread(process.hThread)==(DWORD)-1)goto stop;
  for(;;) {
    if(cancel && cancel(user)){result=EDR_DC_ERR_CANCELLED;break;}
    uint64_t now=io_clock();if(now==UINT64_MAX || now-started>=q->timeout_ms){result=EDR_DC_ERR_TIMEOUT;break;}
    DWORD wait=WaitForSingleObject(process.hProcess,10);
    if(wait==WAIT_OBJECT_0) {DWORD code=1;finished=1;
      if(GetExitCodeProcess(process.hProcess,&code) && !code && shared->result.version==EDR_FORENSIC_IO_VERSION) {*out=shared->result;result=out->rc;}
      break;
    }
    if(wait!=WAIT_TIMEOUT)break;
  }
stop:
  /* A signalled worker does not prove tar/other descendants have exited.
   * Confirm the whole job before allowing the owner to release growth credit. */
  if(process.hProcess) {
    (void)TerminateJobObject(job,1);
    if(!finished)(void)TerminateProcess(process.hProcess,1);
    uint64_t stop=io_clock();int stopped=0;
    for(unsigned attempt=0;attempt<100u;attempt++) {
      JOBOBJECT_BASIC_ACCOUNTING_INFORMATION accounting={0};
      if(QueryInformationJobObject(job,JobObjectBasicAccountingInformation,&accounting,sizeof(accounting),NULL) &&
          !accounting.ActiveProcesses && WaitForSingleObject(process.hProcess,0)==WAIT_OBJECT_0){stopped=1;break;}
      uint64_t now=io_clock();if(stop==UINT64_MAX || now==UINT64_MAX || now-stop>=1000u)break;
      Sleep(10);
    }
    if(!stopped)result=EDR_RESPONSE_WRITER_UNCONFIRMED;
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
      if(received==sizeof(*out) && WIFEXITED(status) && WEXITSTATUS(status)==0 && out->version==EDR_FORENSIC_IO_VERSION)result=out->rc;
      break;
    }
    if(waited<0 && errno!=EINTR)break;
    struct timespec delay={0,1000000};nanosleep(&delay,NULL);
  }
  if(!finished || kill(-child,0)==0 || errno!=ESRCH) {
    (void)kill(-child,SIGKILL);if(!finished)(void)kill(child,SIGKILL);
    uint64_t stop=io_clock();int group_stopped=0;
    for(unsigned attempt=0;attempt<1000u;attempt++) {
      if(!finished) {
        pid_t waited=waitpid(child,&status,WNOHANG);if(waited==child)finished=1;
        else if(waited<0 && errno!=EINTR)break;
      }
      if(finished && kill(-child,0)<0 && errno==ESRCH){group_stopped=1;break;}
      uint64_t now=io_clock();if(now==UINT64_MAX || stop==UINT64_MAX || now-stop>=1000u)break;
      struct timespec delay={0,1000000};nanosleep(&delay,NULL);
    }
    if(!group_stopped)result=EDR_RESPONSE_WRITER_UNCONFIRMED;
  }
  close(sockets[0]);
#endif
  return result;
}

/* Process creation itself can block on an image/volume/filter. One on-demand
 * launcher slot bounds that boundary too. If it cannot retire, later requests
 * fail closed instead of accumulating threads or starting untracked writers.
 * It owns copied input and never touches caller memory after the caller exits. */
#ifdef _WIN32
typedef volatile LONG IoAtomic;
static int io_load(IoAtomic *p) {return (int)InterlockedCompareExchange(p,0,0);}
static void io_store(IoAtomic *p,int value) {InterlockedExchange(p,value);}
static int io_take(IoAtomic *p) {return InterlockedCompareExchange(p,1,0)==0;}
static int io_drop(IoAtomic *p) {return (int)InterlockedDecrement(p);}
#else
typedef _Atomic int IoAtomic;
static int io_load(IoAtomic *p) {return atomic_load(p);}
static void io_store(IoAtomic *p,int value) {atomic_store(p,value);}
static int io_take(IoAtomic *p) {int zero=0;return atomic_compare_exchange_strong(p,&zero,1);}
static int io_drop(IoAtomic *p) {return atomic_fetch_sub(p,1)-1;}
#endif
static IoAtomic launcher_busy;
typedef struct {
  EdrForensicIoRequest request;
  EdrForensicIoResult result;
  IoAtomic references,done,abort;
  int rc;
} IoLaunch;
static int io_launch_cancel(void *arg) {return io_load(&((IoLaunch *)arg)->abort);}
static void io_launch_release(IoLaunch *job) {if(!io_drop(&job->references))free(job);}
#ifdef _WIN32
static unsigned __stdcall io_launch(void *arg)
#else
static void *io_launch(void *arg)
#endif
{
  IoLaunch *job=arg;
  job->rc=io_run_process(&job->request,&job->result,io_launch_cancel,job);
  io_store(&job->done,1);io_store(&launcher_busy,0);io_launch_release(job);
  return 0;
}

int edr_forensic_io_run(const EdrForensicIoRequest *q,EdrForensicIoResult *out,
                       EdrResponseCancelCheck cancel,void *user) {
  if(!q || !out)return -1;
  memset(out,0,sizeof(*out));out->rc=-1;
  if(!q->timeout_ms || q->timeout_ms>300000u)return EDR_DC_ERR_TIMEOUT;
  if(cancel && cancel(user))return EDR_DC_ERR_CANCELLED;
  if(in_worker){io_work(q,out);return out->rc;}
  uint64_t start=io_clock();if(start==UINT64_MAX)return -1;
  if(!io_take(&launcher_busy))return EDR_RESPONSE_WRITER_UNCONFIRMED;
  IoLaunch *job=calloc(1,sizeof(*job));
  if(!job){io_store(&launcher_busy,0);return -1;}
  job->request=*q;io_store(&job->references,2);
#ifdef _WIN32
  uintptr_t thread=_beginthreadex(NULL,0,io_launch,job,0,NULL);
  int launched=thread!=0;if(thread)CloseHandle((HANDLE)thread);
#else
  pthread_t thread;int launched=pthread_create(&thread,NULL,io_launch,job)==0;
  if(launched)pthread_detach(thread);
#endif
  if(!launched){free(job);io_store(&launcher_busy,0);return -1;}
  int failure=0,rc=-1;uint64_t stopping=0;
  for(;;) {
    if(io_load(&job->done)) {
      *out=job->result;rc=failure ? (job->rc==EDR_RESPONSE_WRITER_UNCONFIRMED ? job->rc : failure) : job->rc;break;
    }
    uint64_t now=io_clock();
    if(!failure) {
      if(cancel && cancel(user))failure=EDR_DC_ERR_CANCELLED;
      else if(now==UINT64_MAX || now-start>=q->timeout_ms)failure=EDR_DC_ERR_TIMEOUT;
      if(failure){stopping=now;io_store(&job->abort,1);}
    }
    if(failure && (now==UINT64_MAX || stopping==UINT64_MAX || now-stopping>=1000u)) {
      rc=EDR_RESPONSE_WRITER_UNCONFIRMED;break;
    }
#ifdef _WIN32
    Sleep(10);
#else
    struct timespec delay={0,10000000};nanosleep(&delay,NULL);
#endif
  }
  io_launch_release(job);return rc;
}
