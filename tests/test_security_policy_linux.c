/* The Linux collector uses POSIX process I/O. On macOS this exercises that
 * production branch with command fixtures; it is not a native Linux host test. */
#if defined(__APPLE__) && !defined(__linux__)
#define __linux__ 1
#endif
#include "../src/attack_surface/security_policy_collect.c"
#include "cJSON.h"
#include <assert.h>
#include <sys/stat.h>

static void script(const char *dir, const char *name, const char *body) {
  char path[1024];
  snprintf(path, sizeof(path), "%s/%s", dir, name);
  FILE *fp = fopen(path, "w");
  assert(fp);
  assert(fprintf(fp, "#!/bin/sh\n%s\n", body) > 0);
  assert(fclose(fp) == 0);
  assert(chmod(path, 0700) == 0);
}

static void check(const char *status, const char *exit_code, int blocked,
                  int known, int enabled, const char *profile) {
  assert(setenv("TEST_UFW_STATUS", status, 1) == 0);
  assert(setenv("TEST_UFW_EXIT", exit_code, 1) == 0);
  assert(setenv("TEST_IPTABLES_BLOCK", blocked ? "1" : "0", 1) == 0);
  EdrSecurityPolicySnap snap;
  snap_clear(&snap);
  collect_linux_fw(&snap);
  assert(snap.top_fw_enabled_known == known && snap.sp_fw_enabled_known == known);
  if (known) { assert(snap.top_fw_enabled == enabled && snap.sp_fw_enabled == enabled); }
  assert(strcmp(snap.top_fw_profile, profile) == 0);
  FILE *fp = tmpfile();
  assert(fp);
  EdrConfig cfg;
  memset(&cfg, 0, sizeof(cfg));
  edr_security_policy_snap_write_policy_object(fp, &cfg, &snap);
  assert(fflush(fp) == 0);
  rewind(fp);
  char raw[8192];
  size_t n = fread(raw, 1, sizeof(raw)-1, fp);
  raw[n] = 0;
  fclose(fp);
  cJSON *root = cJSON_Parse(raw);
  assert(root);
  cJSON *value = cJSON_GetObjectItemCaseSensitive(cJSON_GetObjectItemCaseSensitive(root,"firewall"),"firewallEnabled");
  assert(known ? (enabled ? cJSON_IsTrue(value) : cJSON_IsFalse(value)) : cJSON_IsNull(value));
  cJSON_Delete(root);
}

int main(void) {
  char dir[] = "/tmp/edr-ufw-test-XXXXXX";
  assert(mkdtemp(dir));
  const char *commands[] = {"sh", "wc", "grep"};
  const char *paths[] = {"/bin/sh", "/usr/bin/wc", "/usr/bin/grep"};
  char path[1024];
  for (int i=0;i<3;i++) {
    snprintf(path,sizeof(path),"%s/%s",dir,commands[i]);
    assert(symlink(paths[i],path)==0);
  }
  script(dir,"ufw","[ \"$LC_ALL\" = C ] || exit 2\nprintf '%s\\n' \"$TEST_UFW_STATUS\"\ni=0; while [ $i -lt 1000 ]; do printf 'rule line\\n'; i=$((i+1)); done\nexit \"$TEST_UFW_EXIT\"");
  script(dir,"iptables","[ \"$TEST_IPTABLES_BLOCK\" = 1 ] || exit 1\nprintf '%s\\n' '-P INPUT DROP' '-P OUTPUT ACCEPT'");
  script(dir,"iptables-save","exit 1");
  assert(setenv("PATH",dir,1)==0);
  check("Status: active","0",0,1,1,"ufw:active");
  check("Status: inactive","0",0,1,0,"ufw:inactive");
  check("Status: inactive","0",1,1,1,"iptables");
  check("Status: active","1",0,0,0,"");
  check("ERROR: active rules unavailable","0",0,0,0,"");
  check("Status: inactive (unknown)","0",0,0,0,"");
  check("","0",0,0,0,"");
  snprintf(path,sizeof(path),"%s/ufw",dir);
  assert(unlink(path)==0);
  check("Status: active","0",0,0,0,"");
  script(dir,"nft","exit 0");
  check("","0",0,0,0,"nftables:present");
  const char *cleanup[] = {"sh","wc","grep","iptables","iptables-save","nft"};
  for (unsigned i=0;i<sizeof(cleanup)/sizeof(cleanup[0]);i++) {
    snprintf(path,sizeof(path),"%s/%s",dir,cleanup[i]);
    assert(unlink(path)==0);
  }
  assert(rmdir(dir)==0);
  return 0;
}
