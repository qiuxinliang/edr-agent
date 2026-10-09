#include "edr/validation_trace.h"
#include "edr/sha256.h"
#include "edr/agent_update.h"
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
static void set_trace_env(const char *key, const char *value) {
#ifdef _WIN32
  assert(_putenv_s(key, value ? value : "") == 0);
#else
  assert(value ? setenv(key, value, 1) == 0 : unsetenv(key) == 0);
#endif
}
static void stage_has(const char *data, const char *stage, const char *value) {
  char marker[128]; snprintf(marker, sizeof(marker), "\"stage\":\"%s\"", stage);
  const char *line = strstr(data, marker); assert(line);
  while (line > data && line[-1] != '\n') line--;
  const char *end = strchr(line, '\n'); assert(end);
  const char *found = strstr(line, value); assert(found && found < end);
}
static void parent_identity_contract(void) {
  char path[1024]; path_for(path, sizeof(path), 5); remove(path);
  assert(!edr_validation_trace_enabled());
  assert(edr_validation_trace_start_parent(path, "truth.exe", 301) == -1);
  assert(edr_validation_trace_start_parent(path, "truth.exe", 300) == 0);
  assert(edr_validation_trace_enabled());
  EdrBehaviorRecord r; memset(&r, 0, sizeof(r));
  r.pid = 9001u; r.process_start_key = 991122u;
  r.process_creation_filetime_100ns = 133444736000000000ULL;
  r.event_time_ns = 1700000000000000000LL;
  strcpy(r.event_id, "same-preprocess-event"); strcpy(r.process_name, "truth.exe");
  strcpy(r.cmdline, "synthetic-secret-command"); strcpy(r.username, "synthetic-secret-user");
  strcpy(r.user_sid, "synthetic-secret-sid"); strcpy(r.parent_path, "synthetic-secret-path");
  edr_validation_trace_event(&r, "normalized", "decoded");
  /* Parent purpose accepts only the numeric diagnostic, even if a producer
   * accidentally supplies token-shaped identity text as its generic reason. */
  edr_validation_trace_event(&r, "unsafe_reason", r.user_sid);
  edr_parent_pid_merge(&r.ppid, &r.parent_pid_state, 299u, EDR_PARENT_PID_KNOWN);
  edr_validation_trace_parent_change(&r, 0u, EDR_PARENT_PID_UNKNOWN, "enriched");
  edr_validation_trace_event(&r, "p0_rule", "R-EXEC-001");
  /* Assert actual projected arguments, rather than a copy of source values. */
  edr_validation_trace_parent_wire(&r, 4242u, EDR_PARENT_PID_KNOWN, 3u,
                                   UINT64_MAX, "R-EXEC-001", NULL);
  assert(r.ppid == 299u && r.parent_pid_state == EDR_PARENT_PID_KNOWN);
  edr_validation_trace_parent_wire(NULL, 777u, EDR_PARENT_PID_KNOWN, 3u, 0u, "unattributed", NULL);
  edr_validation_trace_parent_change(&r, 299u, EDR_PARENT_PID_KNOWN, "known_again");
  r.parent_pid_state = EDR_PARENT_PID_CONFLICT;
  edr_validation_trace_parent_change(&r, 299u, EDR_PARENT_PID_KNOWN, "conflict");
  r.ppid = 0u; r.parent_pid_state = EDR_PARENT_PID_EXPLICIT_ZERO;
  edr_validation_trace_parent_change(&r, 0u, EDR_PARENT_PID_EXPLICIT_ZERO, "explicit_zero");
  r.parent_pid_state = EDR_PARENT_PID_INVALID;
  edr_validation_trace_parent_change(&r, 0u, EDR_PARENT_PID_INVALID, "invalid_parent");
  r.ppid = 299u; r.parent_pid_state = EDR_PARENT_PID_UNKNOWN;
  edr_validation_trace_event(&r, "legacy_known", "decoded");
  edr_validation_trace_parent_wire(&r, 0u, 260u, 3u, 0u, "R-EXEC-001", "aggregate-wire-event");
  const uint8_t wire[] = {1u, 2u, 3u, 255u};
  edr_validation_trace_bind(&r, "parent-batch", wire, sizeof(wire));
  const char *body = "{\"synthetic_secret\":\"not-needed-for-parent\"}";
  edr_validation_trace_request("parent-batch", body, strlen(body), "application/json");
  edr_validation_trace_request("parent-batch", wire, sizeof(wire), "application/x-protobuf");
  r.process_start_key++; strcpy(r.process_name, "other.exe");
  edr_validation_trace_parent_change(&r, 0u, EDR_PARENT_PID_UNKNOWN, "foreign_parent_tuple");
  edr_validation_trace_stop(); assert(!edr_validation_trace_enabled()); char *s = read_all(path);
  assert(strstr(s, "\"purpose\":\"parent_identity\"") && !strstr(s, "body_hex"));
  assert(strstr(s, "\"agent_version\":\"" EDR_AGENT_VERSION_STRING "\"") &&
         strstr(s, "\"build_sha\":\"unknown\""));
  assert(!strstr(s, "synthetic-secret") && !strstr(s, "synthetic_secret") &&
         !strstr(s, "foreign_parent_tuple") && !strstr(s, "unattributed"));
  stage_has(s, "normalized", "\"ppid\":0,\"parent_pid_state\":0");
  stage_has(s, "enriched", "\"ppid\":299,\"parent_pid_state\":1");
  stage_has(s, "enriched", "\"change_reason\":\"unknown_completed\"");
  stage_has(s, "wire", "\"ppid\":4242,\"parent_pid_state\":1");
  stage_has(s, "wire", "\"projection_version\":3");
  stage_has(s, "wire", "\"required_evidence_fields\":\"18446744073709551615\"");
  stage_has(s, "wire", "\"rule_id\":\"R-EXEC-001\"");
  stage_has(s, "wire", "\"source_event_id\":\"same-preprocess-event\"");
  stage_has(s, "wire", "\"wire_event_id\":\"same-preprocess-event\"");
  assert(strstr(s, "\"source_event_id\":\"same-preprocess-event\",\"wire_event_id\":\"aggregate-wire-event\""));
  stage_has(s, "p0_rule", "\"rule_id\":\"R-EXEC-001\"");
  stage_has(s, "known_again", "\"change_reason\":\"known_retained\"");
  stage_has(s, "conflict", "\"ppid\":299,\"parent_pid_state\":4");
  stage_has(s, "explicit_zero", "\"ppid\":0,\"parent_pid_state\":2");
  stage_has(s, "invalid_parent", "\"ppid\":0,\"parent_pid_state\":3");
  stage_has(s, "legacy_known", "\"parent_pid_state\":0,\"parent_pid_effective_state\":1");
  assert(strstr(s, "\"parent_pid_state\":260")); /* No uint8 wire truncation. */
  stage_has(s, "normalized", "\"event_id\":\"same-preprocess-event\"");
  stage_has(s, "enriched", "\"event_id\":\"same-preprocess-event\"");
  stage_has(s, "wire", "\"event_id\":\"same-preprocess-event\"");
  assert(strstr(s, "\"kind\":\"encoded\"") && strstr(s, "\"dropped\":0"));
#ifndef _WIN32
  struct stat st; assert(!stat(path, &st) && (st.st_mode & 0777) == 0600);
#endif
  free(s); assert(edr_validation_trace_start_parent(path, "truth.exe", 300) == -1); remove(path);

  /* Exercise the production environment selector, not just the new API. */
  path_for(path, sizeof(path), 6); remove(path);
  set_trace_env("EDR_VALIDATION_TRACE_PATH", path); set_trace_env("EDR_VALIDATION_TRACE_IMAGE", "truth.exe");
  set_trace_env("EDR_VALIDATION_TRACE_PURPOSE", "invalid_purpose");
  edr_validation_trace_start_from_env(); FILE *f = fopen(path, "rb"); assert(!f);
  set_trace_env("EDR_VALIDATION_TRACE_PURPOSE", "parent_identity");
  edr_validation_trace_start_from_env(); strcpy(r.process_name, "truth.exe");
  edr_validation_trace_event(&r, "env_parent", "decoded");
  edr_validation_trace_bind(&r, "env-parent-batch", wire, sizeof(wire));
  edr_validation_trace_request("env-parent-batch", body, strlen(body), "application/json");
  edr_validation_trace_stop(); s = read_all(path);
  assert(strstr(s, "parent_identity") && strstr(s, "env_parent") && !strstr(s, "body_hex"));
  free(s); remove(path); set_trace_env("EDR_VALIDATION_TRACE_PATH", NULL);
  set_trace_env("EDR_VALIDATION_TRACE_IMAGE", NULL); set_trace_env("EDR_VALIDATION_TRACE_PURPOSE", NULL);

  path_for(path, sizeof(path), 7); remove(path);
  assert(edr_validation_trace_start_parent(path, "truth.exe", 1) == 0);
  sleep_ms(1100); assert(!edr_validation_trace_enabled());
  edr_validation_trace_event(&r, "parent_after_expiry", "decoded");
  edr_validation_trace_flush(); s = read_all(path);
  assert(!strstr(s, "parent_after_expiry") && strstr(s, "\"kind\":\"closed\""));
  free(s); remove(path);
  path_for(path, sizeof(path), 8); remove(path);
  assert(edr_validation_trace_start_parent(path, "truth.exe", 300) == 0);
  for (unsigned i = 0u; i < 140u; i++) {
    r.pid = 100u + i; r.process_start_key = 2000u + i; r.process_creation_filetime_100ns = 1000u + i;
    edr_validation_trace_event(&r, "parent_identity_cap", "decoded");
  }
  edr_validation_trace_stop(); s = read_all(path); assert(strstr(s, "\"dropped\":12")); free(s); remove(path);
  path_for(path, sizeof(path), 9); remove(path);
  assert(edr_validation_trace_start_parent(path, "truth.exe", 300) == 0);
  for (unsigned i = 0u; i < 40000u; i++) edr_validation_trace_event(&r, "parent_byte_cap", "decoded");
  edr_validation_trace_stop(); s = read_all(path); assert(!strstr(s, "\"dropped\":0")); free(s); remove(path);
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
  EdrSensorInterestEvent exited = {0};
  exited.type = EDR_EVENT_PROCESS_TERMINATE; exited.pid = r.pid;
  exited.process_creation_filetime_100ns = r.process_creation_filetime_100ns;
  /* Exit has a typed target birth but no target StartKey or full image name. */
  edr_validation_trace_interest(&exited, 123456789, "process_exit", "ave_notified");
  exited.process_creation_filetime_100ns++;
  edr_validation_trace_interest(&exited, 123456789, "foreign-exit", "");
  exited.process_creation_filetime_100ns = 0;
  edr_validation_trace_interest(&exited, 123456789, "foreign-pid-only-exit", "");
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
  assert(strstr(s,"\"birth\":\"1000\",\"start_key\":\"0\",\"event_ns\":\"123456789\",\"type\":2,\"event_id\":\"\",\"stage\":\"process_exit\""));
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
  parent_identity_contract();
  puts("bounded validation trace contracts passed");return 0;
}
