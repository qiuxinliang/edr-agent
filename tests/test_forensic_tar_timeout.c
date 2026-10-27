/* Real child-process supervision; only synthetic files and the test's own child. */
#include "edr/response_utils.h"
#include "edr/deep_collector.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef _WIN32
#include <windows.h>
#include <direct.h>
#else
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#endif
static void pause_ms(unsigned ms) {
#ifdef _WIN32
  Sleep(ms);
#else
  struct timespec pause={ms/1000u,(long)(ms%1000u)*1000000L};nanosleep(&pause,NULL);
#endif
}
static int cancel_now(void *unused) {(void)unused;return 1;}
static unsigned long long test_monotonic_ms(void) {
#ifdef _WIN32
  return (unsigned long long)GetTickCount64();
#else
  struct timespec now;assert(clock_gettime(CLOCK_MONOTONIC,&now)==0);
  return (unsigned long long)now.tv_sec*1000u+(unsigned long long)now.tv_nsec/1000000u;
#endif
}
static int cancel_when_started(void *path) {
#ifdef _WIN32
  WIN32_FILE_ATTRIBUTE_DATA info;
  return GetFileAttributesExA((const char *)path,GetFileExInfoStandard,&info) && (info.nFileSizeLow || info.nFileSizeHigh);
#else
  struct stat st;return !stat((const char *)path,&st) && st.st_size>0;
#endif
}
static int remove_synthetic(const char *path) {
#ifdef _WIN32
  /* A terminated Windows child can leave transient close completion. Keep
   * cleanup bounded and restricted to this fixture's own file. */
  for(unsigned i=0;i<6;i++) {
    if(!remove(path))return 0;
    DWORD error=GetLastError();
    if(i==5 || (error!=ERROR_SHARING_VIOLATION && error!=ERROR_ACCESS_DENIED && error!=ERROR_LOCK_VIOLATION))return -1;
    fprintf(stderr,"synthetic archive cleanup retry win32=%lu\n",error);Sleep(20);
  }
  return -1;
#else
  return remove(path);
#endif
}
int main(int argc,char **argv) {
  if(argc==6 && !strcmp(argv[1],"czf")) {
    char bytes[20000];memset(bytes,'s',sizeof(bytes));
    unsigned count=getenv("EDR_SYNTHETIC_TAR_OVERFLOW")?3400u:1u;
    for(unsigned i=0;i<count;i++)if(fwrite(bytes,1,sizeof(bytes),stdout)!=sizeof(bytes))return 2;
    if(fflush(stdout))return 2;
    pause_ms(20000);return 0;
  }
  assert(argc==1);char root[900],work[1000],archive[1100],source[1100],self[1100];
#ifdef _WIN32
  char temp[780];assert(GetTempPathA(sizeof(temp),temp));
  snprintf(root,sizeof(root),"%star-supervision-%lu",temp,(unsigned long)GetCurrentProcessId());
  assert(_mkdir(root)==0);assert(GetModuleFileNameA(NULL,self,sizeof(self))>0);
#else
  snprintf(root,sizeof(root),"/tmp/tar-supervision-%lu",(unsigned long)getpid());
  assert(mkdir(root,0700)==0);assert(realpath(argv[0],self));
#endif
  snprintf(work,sizeof(work),"%s/work",root);assert(response_mkdir_p(work)==0);
  snprintf(source,sizeof(source),"%s/source.txt",work);
  FILE *f=fopen(source,"wb");assert(f);fputs("synthetic tar evidence\n",f);assert(fclose(f)==0);
  snprintf(archive,sizeof(archive),"%s/archive.tgz",root);
  assert(response_make_tar_bundle(work,archive,30000,NULL,NULL)==0);
  f=fopen(archive,"rb");assert(f);assert(fgetc(f)!=EOF);assert(fclose(f)==0);assert(remove_synthetic(archive)==0);
  assert(response_make_tar_bundle(work,archive,1000,cancel_now,NULL)==EDR_DC_ERR_CANCELLED);
  assert(fopen(archive,"rb")==NULL);
  response_tar_test_set_binary(self);
  assert(response_make_tar_bundle(work,archive,1000,NULL,NULL)==EDR_DC_ERR_TIMEOUT);
  f=fopen(archive,"rb");assert(f);assert(fgetc(f)=='s');assert(fclose(f)==0);assert(remove_synthetic(archive)==0);
  /* The child offers >64MiB. The production parent must stop before writing
   * byte 64MiB+1, even though the source is an uncooperative process. */
#ifdef _WIN32
  _putenv_s("EDR_SYNTHETIC_TAR_OVERFLOW","1");
#else
  setenv("EDR_SYNTHETIC_TAR_OVERFLOW","1",1);
#endif
  unsigned long long overflow_started=test_monotonic_ms();
  int overflow_rc=response_make_tar_bundle(work,archive,15000,NULL,NULL);
  f=fopen(archive,"rb");assert(f);assert(fseek(f,0,SEEK_END)==0);
  fprintf(stderr,"tar_overflow rc=%d elapsed_ms=%llu bytes=%ld\n",overflow_rc,
      test_monotonic_ms()-overflow_started,ftell(f));
  assert(overflow_rc==EDR_RESPONSE_BYTE_BUDGET_EXCEEDED);
  assert(ftell(f)>0 && ftell(f)<=64L*1024L*1024L);assert(fclose(f)==0);assert(remove_synthetic(archive)==0);
#ifdef _WIN32
  _putenv_s("EDR_SYNTHETIC_TAR_OVERFLOW","");
#else
  unsetenv("EDR_SYNTHETIC_TAR_OVERFLOW");
#endif
  assert(response_make_tar_bundle(work,archive,5000,cancel_when_started,archive)==EDR_DC_ERR_CANCELLED);
  f=fopen(archive,"rb");assert(f);assert(fgetc(f)=='s');assert(fclose(f)==0);assert(remove_synthetic(archive)==0);
  response_tar_test_set_binary(NULL);
  assert(remove(source)==0);
#ifdef _WIN32
  assert(_rmdir(work)==0);assert(_rmdir(root)==0);
#else
  assert(rmdir(work)==0);assert(rmdir(root)==0);
#endif
  puts("PASS: real archive, cancel before spawn, bounded timeout, running cancellation, hard 64MiB output cap; partial evidence retained");return 0;
}
