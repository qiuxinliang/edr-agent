#include "edr/storage_physical_guard.h"
#include <assert.h>
#include <stdio.h>
#ifndef _WIN32
#include <unistd.h>
#include <sys/wait.h>
#endif
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#include <process.h>
#define env(k,v) _putenv_s(k,v)
#else
#define env(k,v) setenv(k,v,1)
#endif
int main(int argc, char **argv) {
  EdrStoragePhysicalSnapshot s;
  uint64_t value=0;
#ifdef _WIN32
  if(argc==3 && !strcmp(argv[1],"--reservation-child")) {
    int fd=_open(argv[2],_O_RDWR|_O_BINARY);assert(fd>=0);
    assert(edr_storage_reservation_attach(fd,argv[2])==0);
    assert(edr_storage_artifact_reserved()==123u);
    edr_storage_reservation_publish(456u);assert(_close(fd)==0);return 0;
  }
#endif
  /* Called only by the isolated native-volume fixture. It supplies a file
   * below its newly created mount; this executable never allocates disk data. */
  if (argc == 4 && !strcmp(argv[1], "--test-volume")) {
    int full = !strcmp(argv[3], "full");
    assert(full || !strcmp(argv[3], "recovered"));
    env("EDR_STORAGE_OWNER_PROTECTED_BYTES", "0");
    env("EDR_COMMAND_STATE_OWNER_BUDGET_BYTES", "1");
    env("EDR_STORAGE_MIN_FREE_MB", "0");
    assert(edr_storage_volume_available(argv[2], &value) == 0);
    assert(value > 4096 && value < 128u*1024u*1024u);
    assert(edr_storage_physical_admit(argv[2], 4096, 0, &s) == (full ? -1 : 0));
    assert(edr_storage_physical_admit(argv[2], 4096, 1, &s) == 0);
    assert(edr_storage_physical_admit(argv[2], value+4096, 1, &s) == -1);
    printf("{\"phase\":\"%s\",\"volume_available_bytes\":%llu,\"ordinary_refused\":%s,\"reserved_small_allowed\":true,\"reserved_oversize_refused\":true}\n",
           argv[3], (unsigned long long)value, full ? "true" : "false");
    return 0;
  }
  assert(argc == 1);
  assert(edr_storage_reservation_readonly_snapshot(123u)==0 && edr_storage_artifact_reserved()==123u);
  edr_storage_reservation_publish(UINT64_MAX);
  assert(edr_storage_artifact_reserved()==UINT64_MAX);
  assert(edr_storage_physical_admit(".",1,1,&s)==-2); /* startup failed before mapping */
  edr_storage_reservation_publish(0u);
  assert(edr_storage_file_size(NULL)==UINT64_MAX);
  assert(edr_storage_file_size("")==UINT64_MAX);
  assert(edr_storage_file_size(".")==UINT64_MAX);
#ifdef _WIN32
  char temp[MAX_PATH],mapped[MAX_PATH],replacement[MAX_PATH],self[MAX_PATH];
  assert(GetTempPathA(sizeof(temp),temp));
  assert(GetTempFileNameA(temp,"erg",0,mapped));
  int map_fd=_open(mapped,_O_RDWR|_O_BINARY);assert(map_fd>=0);
  assert(edr_storage_reservation_attach(map_fd,mapped)==0);
  edr_storage_reservation_publish(123u);
  assert(edr_storage_reservation_readonly_snapshot(1u)==-1 && edr_storage_artifact_reserved()==123u);
  DWORD self_size=GetModuleFileNameA(NULL,self,sizeof(self));assert(self_size && self_size<sizeof(self));
  assert(_spawnl(_P_WAIT,self,self,"--reservation-child",mapped,NULL)==0);
  assert(edr_storage_artifact_reserved()==456u); /* actual new process, same mapping */
  assert(GetTempFileNameA(temp,"erg",0,replacement));
  int replacement_fd=_open(replacement,_O_RDWR|_O_BINARY);assert(replacement_fd>=0);
  /* Supplying a different real fd with the same owner key must remap by
   * volume/file identity. This does not pretend that a mapped Windows file
   * can always be renamed; the production identity check is the boundary. */
  assert(edr_storage_reservation_attach(replacement_fd,mapped)==0);
  edr_storage_reservation_publish(789u);
  assert(edr_storage_reservation_attach(map_fd,mapped)==0 && edr_storage_artifact_reserved()==456u);
  assert(edr_storage_reservation_attach(replacement_fd,mapped)==0 && edr_storage_artifact_reserved()==789u);
  edr_storage_reservation_publish(0u);
  assert(_close(map_fd)==0 && _close(replacement_fd)==0);
  /* Shared mappings deliberately survive readers until this process exits.
   * Keep these two tiny synthetic TEMP files for the test evidence inventory. */
  puts("Windows reservation: exec child shared balance, fd identity remap, runtime/read-only separation PASS");
#else
  char fixture[]="/tmp/edr-stat-accounting.XXXXXX";
  int fd=mkstemp(fixture);assert(fd>=0);
  assert(write(fd,"12345",5)==5 && close(fd)==0);
  assert(edr_storage_file_size(fixture)==5);
  char child[128];snprintf(child,sizeof(child),"%s/child",fixture);
  assert(edr_storage_file_size(child)==UINT64_MAX); /* ENOTDIR != missing */
  assert(unlink(fixture)==0);
  char mapped[]="/tmp/edr-reservation-map.XXXXXX";
  int map_fd=mkstemp(mapped);assert(map_fd>=0);
  assert(edr_storage_reservation_attach(map_fd,mapped)==0);
  edr_storage_reservation_publish(123u);assert(edr_storage_artifact_reserved()==123u);
  assert(edr_storage_reservation_readonly_snapshot(1u)==-1 && edr_storage_artifact_reserved()==123u);
  pid_t child_pid=fork();assert(child_pid>=0);
  if(!child_pid){edr_storage_reservation_publish(456u);_exit(0);}
  int child_status=0;assert(waitpid(child_pid,&child_status,0)==child_pid && WIFEXITED(child_status));
  assert(edr_storage_artifact_reserved()==456u); /* shared, not a TU/process-local copy */
  char replacement[]="/tmp/edr-reservation-replacement.XXXXXX";
  int replacement_fd=mkstemp(replacement);assert(replacement_fd>=0);
  assert(rename(replacement,mapped)==0);
  assert(edr_storage_reservation_attach(replacement_fd,mapped)==0);
  edr_storage_reservation_publish(789u);assert(edr_storage_artifact_reserved()==789u);
  assert(edr_storage_reservation_attach(map_fd,mapped)==0);
  assert(edr_storage_artifact_reserved()==456u); /* same path, different fd identity */
  assert(edr_storage_reservation_attach(replacement_fd,mapped)==0 && edr_storage_artifact_reserved()==789u);
  edr_storage_reservation_publish(0u);
  assert(close(map_fd)==0 && close(replacement_fd)==0 && unlink(mapped)==0);
  assert(edr_storage_file_size(fixture)==0); /* genuinely absent WAL */
  assert(symlink(fixture,fixture)==0);
  assert(edr_storage_file_size(fixture)==UINT64_MAX); /* ELOOP != empty */
  assert(unlink(fixture)==0);
#endif
  assert(edr_storage_add_bytes(UINT64_MAX,1)==UINT64_MAX);
  assert(edr_storage_parse_u64("18446744073709551615",&value)==0 && value==UINT64_MAX);
  assert(edr_storage_parse_u64("18446744073709551616",&value)!=0);
  assert(edr_storage_parse_u64("-1",&value)!=0);
  assert(edr_storage_parse_u64("1x",&value)!=0);
  assert(edr_storage_physical_evaluate(110,10,100,0,&s)==0 && s.required_bytes==110);
  assert(edr_storage_physical_evaluate(109,10,100,0,&s)==-1);
  assert(edr_storage_physical_evaluate(10,10,100,1,&s)==0);
  assert(edr_storage_physical_evaluate(9,10,100,1,&s)==-1);
  assert(edr_storage_physical_evaluate(UINT64_MAX,UINT64_MAX,1,0,&s)==-2);
  env("EDR_STORAGE_OWNER_PROTECTED_BYTES","0");
  env("EDR_COMMAND_STATE_OWNER_BUDGET_BYTES","0"); env("EDR_STORAGE_MIN_FREE_MB","0");
  assert(edr_storage_min_free_bytes(&value)==0);
  assert(value==3u*EDR_COMMAND_STATE_DEFAULT_OWNER_BUDGET_BYTES+24u*1024u*1024u);
  uint64_t automatic=value;
  env("EDR_COMMAND_STATE_OWNER_BUDGET_BYTES","1");
  env("EDR_STORAGE_OWNER_PROTECTED_BYTES","100000000");
  assert(edr_storage_min_free_bytes(&value)==0 && value==300000000u+24u*1024u*1024u);
  env("EDR_STORAGE_OWNER_PROTECTED_BYTES","0");
  env("EDR_COMMAND_STATE_OWNER_BUDGET_BYTES","0");
  env("EDR_STORAGE_MIN_FREE_MB","1");
  assert(edr_storage_min_free_bytes(&value)==0 && value==automatic);
  env("EDR_STORAGE_MIN_FREE_MB","1024");
  assert(edr_storage_min_free_bytes(&value)==0 && value==1024ULL*1024*1024);
  env("EDR_STORAGE_MIN_FREE_MB","18446744073709551615");
  assert(edr_storage_physical_admit("guard.db",1,0,&s)==-2);
  env("EDR_STORAGE_MIN_FREE_MB","1048576000");
  assert(edr_storage_physical_admit("guard.db",1,0,&s)==-1);
  assert(edr_storage_physical_admit("guard.db",1,1,&s)==0);
  env("EDR_STORAGE_OWNER_PROTECTED_BYTES","unavailable");
  assert(edr_storage_physical_admit("guard.db",1,0,&s)==-2 && !strcmp(s.cause,"owner_accounting_unavailable"));
  assert(edr_storage_physical_admit("guard.db",1,1,&s)==0);
  assert(edr_storage_physical_admit("guard.db",UINT64_MAX,1,&s)==-1);
  env("EDR_STORAGE_MIN_FREE_MB","invalid");
  assert(edr_storage_physical_admit("guard.db",1,1,&s)==-2 && !strcmp(s.cause,"physical_configuration_invalid"));
  env("EDR_STORAGE_OWNER_PROTECTED_BYTES","0");
  env("EDR_STORAGE_MIN_FREE_MB","0");
  assert(edr_storage_physical_admit("nonexistent-guard-dir/sub/guard.db",4096,0,&s)==0);
  assert(s.available_bytes>s.required_bytes);
  assert(edr_storage_physical_admit("",1,0,&s)==-2);
  puts("storage physical guard: arithmetic, low-space refusal, reserved completion, real volume PASS");
  return 0;
}
