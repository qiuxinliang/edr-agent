#include "edr/validation_trace.h"
#include "edr/sha256.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#define sleep_ms(n) Sleep(n)
static void path_for(char *path, size_t cap, unsigned n) {
  char temp[MAX_PATH]; assert(GetTempPathA(sizeof(temp), temp));
  snprintf(path, cap, "%sedr-trace-%lu-%u.jsonl", temp, (unsigned long)GetCurrentProcessId(), n);
}
#else
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>
static void sleep_ms(unsigned n) { struct timespec t = {n / 1000, (long)(n % 1000) * 1000000}; nanosleep(&t,NULL); }
static void path_for(char *path, size_t cap, unsigned n) {
  snprintf(path, cap, "/tmp/edr-trace-%ld-%u.jsonl", (long)getpid(), n);
}
#endif
static char *read_all(const char *path) {
  FILE *f=fopen(path,"rb"); assert(f); assert(!fseek(f,0,SEEK_END)); long n=ftell(f);
  assert(n>0 && n<=8*1024*1024); rewind(f); char *s=calloc((size_t)n+1,1); assert(s);
  assert(fread(s,1,(size_t)n,f)==(size_t)n); fclose(f); return s;
}
int main(void) {
  char path[1024], hash[65]; path_for(path,sizeof(path),1); remove(path);
  assert(edr_validation_trace_start(path,"bad/name.exe",300)==-1);
  assert(edr_validation_trace_start(path,"truth.exe",301)==-1);
  assert(edr_validation_trace_start(path,"truth.exe",300)==0);
  assert(edr_validation_trace_start(path,"truth.exe",300)==-1);
  EdrBehaviorRecord r; memset(&r,0,sizeof(r));
  r.pid=100; r.process_creation_filetime_100ns=1000; r.process_start_key=2000;
  strcpy(r.event_id,"source-1"); strcpy(r.process_name,"TRUTH.EXE");
  strcpy(r.cmdline,"synthetic-secret-command"); strcpy(r.username,"synthetic-secret-user");
  edr_validation_trace_event(&r,"p0_evaluation","proven_miss");
  strcpy(r.process_name,"other.exe"); edr_validation_trace_event(&r,"local_retention","ordinary_hot_ring_only");
  r.process_creation_filetime_100ns++; edr_validation_trace_event(&r,"foreign-generation","");
  r.process_creation_filetime_100ns--; r.process_start_key++; edr_validation_trace_event(&r,"conflicting-key","");
  r.process_start_key--; r.pid++; edr_validation_trace_event(&r,"foreign-pid",""); r.pid--;
  const uint8_t wire[]={1,2,3,255};
  edr_validation_trace_bind(&r,"batch-1",wire,sizeof(wire));
  edr_validation_trace_request("batch-foreign","secret",6,"application/json");
  edr_validation_trace_request("batch-1","{}",2,"application/json");
  edr_validation_trace_request("batch-1",wire,sizeof(wire),"application/x-protobuf");
  r.pid=101; r.process_creation_filetime_100ns=1001; r.process_start_key=2001;
  strcpy(r.parent_name,"truth.exe"); edr_validation_trace_event(&r,"child","observed");
  edr_validation_trace_event(&r,"invalid\"token","contains secret");
  edr_validation_trace_stop();
  char *s=read_all(path);
  assert(strstr(s,"proven_miss") && strstr(s,"ordinary_hot_ring_only") && strstr(s,"\"stage\":\"child\""));
  assert(!strstr(s,"foreign-") && !strstr(s,"conflicting-key") && !strstr(s,"secret"));
  assert(strstr(s,"\"body_hex\":\"7b7d\"") && strstr(s,"\"body_hex\":\"010203ff\""));
  assert(!edr_sha256_hex(wire,sizeof(wire),hash) && strstr(s,hash));
  assert(strstr(s,"\"kind\":\"closed\"") && strstr(s,"\"dropped\":0")); free(s);
#ifndef _WIN32
  struct stat st; assert(!stat(path,&st) && (st.st_mode & 0777)==0600);
#endif
  assert(edr_validation_trace_start(path,"truth.exe",300)==-1); remove(path);
  path_for(path,sizeof(path),2); remove(path);
  assert(edr_validation_trace_start(path,"truth.exe",1)==0);
  sleep_ms(1100); edr_validation_trace_event(&r,"after-expiry",""); edr_validation_trace_flush();
  s=read_all(path); assert(!strstr(s,"after-expiry") && strstr(s,"\"kind\":\"closed\"")); free(s); remove(path);
  path_for(path,sizeof(path),3); remove(path);
  assert(edr_validation_trace_start(path,"truth.exe",300)==0);
  for (unsigned i=0;i<140;i++) { r.pid=100+i;r.process_creation_filetime_100ns=1000+i;r.process_start_key=2000+i;edr_validation_trace_event(&r,"identity-cap",""); }
  edr_validation_trace_stop(); s=read_all(path); assert(strstr(s,"\"dropped\":12"));free(s);remove(path);
  path_for(path,sizeof(path),4);remove(path);assert(edr_validation_trace_start(path,"truth.exe",300)==0);
  edr_validation_trace_bind(&r,"batch-1",wire,sizeof(wire));
  char *body=calloc(1024*1024,1);assert(body);
  for(unsigned i=0;i<5;i++) edr_validation_trace_request("batch-1",body,1024*1024,"application/x-protobuf");
  free(body);edr_validation_trace_stop();s=read_all(path);assert(strstr(s,"\"dropped\":2"));free(s);remove(path);
  puts("bounded validation trace contracts passed");return 0;
}
