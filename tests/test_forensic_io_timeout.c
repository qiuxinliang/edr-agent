#include "edr/forensic_worker.h"
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
#include <unistd.h>
#endif
static uint64_t now_ms(void) {
#ifdef _WIN32
  return GetTickCount64();
#else
  struct timespec t;assert(!clock_gettime(CLOCK_MONOTONIC,&t));return (uint64_t)t.tv_sec*1000u+t.tv_nsec/1000000u;
#endif
}
static int cancel_now(void *p) {(void)p;return 1;}
int main(int argc,char **argv) {
  if(argc==3 && !strcmp(argv[1],EDR_FORENSIC_WORKER_ARG))return edr_forensic_io_worker_main(argv[2]);
  assert(argc==1);char root[700];
#ifdef _WIN32
  char temp[600];assert(GetTempPathA(sizeof(temp),temp));assert(GetTempFileNameA(temp,"efi",0,root));assert(DeleteFileA(root));assert(!_mkdir(root));
#else
  strcpy(root,"/tmp/edr-io-deadline.XXXXXX");assert(mkdtemp(root));
#endif
  EdrForensicIoRequest q={0};EdrForensicIoResult result={0};q.version=1;q.operation=1;q.timeout_ms=2000;
  strcpy(q.manifest,"synthetic evidence; hard deadline contract\n");
  for(unsigned phase=0;phase<=5;phase++) {
    snprintf(q.workspace,sizeof(q.workspace),"%s/phase-%u",root,phase);
    snprintf(q.staging,sizeof(q.staging),"%s/phase-%u.staging",root,phase);
    q.operation=1u|(phase<<8);uint64_t started=now_ms();
    int rc=edr_forensic_io_run(&q,&result,NULL,NULL);uint64_t elapsed=now_ms()-started;
    printf("worker phase=%u rc=%d elapsed_ms=%llu\n",phase,rc,(unsigned long long)elapsed);fflush(stdout);
    if(!phase){assert(rc==0 && strlen(result.sha256)==64);continue;}
    assert(rc==EDR_DC_ERR_TIMEOUT && elapsed>=1900 && elapsed<3500);
    char marker[900];snprintf(marker,sizeof(marker),"%s/blocked",q.workspace);
    FILE *f=fopen(marker,"rb");assert(f);assert(fgetc(f)==(int)('0'+phase));assert(!fclose(f));
  }
  q.operation=1;assert(edr_forensic_io_run(&q,&result,cancel_now,NULL)==EDR_DC_ERR_CANCELLED);
  q.timeout_ms=0;assert(edr_forensic_io_run(&q,&result,NULL,NULL)==EDR_DC_ERR_TIMEOUT);
  puts("PASS: real worker archive; synchronous blocked reads at five phases terminate within deadline+bounded confirmation; cancel/expired never spawn");return 0;
}
