#include "edr/storage_physical_guard.h"
#include <assert.h>
#include <stdio.h>
#ifdef _WIN32
#define env(k,v) _putenv_s(k,v)
#else
#define env(k,v) setenv(k,v,1)
#endif
int main(int argc, char **argv) {
  EdrStoragePhysicalSnapshot s;
  uint64_t value=0;
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
