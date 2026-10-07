#ifndef EDR_COMMAND_EGRESS_HOLD_H
#define EDR_COMMAND_EGRESS_HOLD_H
/* Delivery metadata only. The queued payload and evidence are never rewritten.
 * The existing file owners share this small atomic sidecar I/O boundary. */
#include "edr/egress_request_policy.h"
#include "edr/egress_batch_policy.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef _WIN32
#include <windows.h>
#include <io.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif
static int edr_hold_read(const char *path, char *command, size_t cap) {
  FILE *f=fopen(path,"rb");
  if (!f) return errno==ENOENT?0:EDR_EGRESS_LOCAL_STATE_FAILURE;
  char schema[32], id[160], policy[96], code[32], stamp[40];
  int ok=fgets(schema,sizeof(schema),f)&&fgets(id,sizeof(id),f)&&
      fgets(policy,sizeof(policy),f)&&fgets(code,sizeof(code),f)&&fgets(stamp,sizeof(stamp),f);
  if (ferror(f)) ok=0;
  if (fclose(f)) ok=0;
  if (!ok || strcmp(schema,"edr.egress-hold.v1\n")) return EDR_EGRESS_LOCAL_STATE_FAILURE;
  id[strcspn(id,"\r\n")]=0; policy[strcspn(policy,"\r\n")]=0;
  int rc=atoi(code);
  if (!id[0] || strlen(id)>=cap || !edr_egress_is_policy_hold(rc)) return EDR_EGRESS_LOCAL_STATE_FAILURE;
  memcpy(command,id,strlen(id)+1u);
  /* A new policy is re-evaluated, never treated as permission or ACK. */
  return strcmp(policy,EDR_EGRESS_POLICY_VERSION)?0:rc;
}
static int edr_hold_write(const char *path,const char *command,int rc) {
  if (!command || !command[0] || strlen(command)>=128u || strpbrk(command,"\r\n") || !edr_egress_is_policy_hold(rc))
    return EDR_EGRESS_LOCAL_STATE_FAILURE;
  char existing[160];int previous=edr_hold_read(path,existing,sizeof(existing));
  if (previous==rc && !strcmp(command,existing)) return rc;
  if (previous==EDR_EGRESS_LOCAL_STATE_FAILURE) return previous;
  char temporary[1400];
  if (snprintf(temporary,sizeof(temporary),"%s.tmp",path)>=(int)sizeof(temporary)) return EDR_EGRESS_LOCAL_STATE_FAILURE;
  FILE *f=fopen(temporary,"wb");if(!f)return EDR_EGRESS_LOCAL_STATE_FAILURE;
  int ok=fprintf(f,"edr.egress-hold.v1\n%s\n%s\n%d\n%lld\n",command,EDR_EGRESS_POLICY_VERSION,rc,(long long)time(NULL))>0;
  if (fflush(f)) ok=0;
#ifdef _WIN32
  if (_commit(_fileno(f)))ok=0;
#else
  if (fsync(fileno(f)))ok=0;
#endif
  if (fclose(f))ok=0;
#ifdef _WIN32
  if (ok && !MoveFileExA(temporary,path,MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH))ok=0;
#else
  if (ok && rename(temporary,path))ok=0;
  if (ok) {
    char parent[1400];snprintf(parent,sizeof(parent),"%s",path);
    char *slash=strrchr(parent,'/');if(slash)*slash=0;else strcpy(parent,".");
    int fd=open(parent,O_RDONLY);if(fd<0)ok=0;else {if(fsync(fd))ok=0;close(fd);}
  }
#endif
  if(!ok){(void)remove(temporary);return EDR_EGRESS_LOCAL_STATE_FAILURE;}
  return rc;
}
static int edr_hold_clear(const char *path) {
  return remove(path)==0 || errno==ENOENT?0:EDR_EGRESS_LOCAL_STATE_FAILURE;
}
#endif
