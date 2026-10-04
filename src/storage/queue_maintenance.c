#include "edr/queue_maintenance.h"
#include "edr/storage_queue.h"
#include "edr/config.h"
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int absolute_path(const char *path) {
  if (!path || !path[0]) return 0;
#ifdef _WIN32
  return (strlen(path)>=3 && path[1]==':' && (path[2]=='/'||path[2]=='\\')) ||
         (path[0]=='\\' && path[1]=='\\');
#else
  return path[0]=='/';
#endif
}
static int number(const char *text,uint64_t *out) {
  char *end=NULL;
  if (!text || !text[0] || text[0]=='-' || text[0]=='+') return 0;
  errno=0; unsigned long long value=strtoull(text,&end,10);
  if (errno || !end || *end) return 0;
  *out=(uint64_t)value; return 1;
}
static int hex_bytes(const char *text,uint8_t *out,size_t bytes) {
  if (!text || strlen(text)!=bytes*2) return 0;
  for (size_t i=0;i<bytes;i++) {
    unsigned value=0;
    for (unsigned k=0;k<2;k++) {
      char c=text[i*2+k];
      unsigned digit=c>='0'&&c<='9'?(unsigned)(c-'0'):c>='a'&&c<='f'?(unsigned)(c-'a'+10):16;
      if (digit>=16) return 0;
      value=(value<<4)|digit;
    }
    out[i]=(uint8_t)value;
  }
  return 1;
}

int edr_storage_queue_maintenance_main(int argc,char **argv) {
  EdrStorageQueueRecoveryRequest request; EdrStorageQueueRecoveryReport report;
  const char *config_path=NULL; const char *queue_path=NULL;
  memset(&request,0,sizeof(request)); request.version=1; request.max_batches=32;
  unsigned supplied=0;
  for (int i=2;i<argc;i++) {
    const char *option=argv[i]; uint64_t value;
    if (!strcmp(option,"--apply")) { request.apply=1; continue; }
    if (i+1>=argc) goto invalid;
    const char *argument=argv[++i];
    if (!strcmp(option,"--config")) config_path=argument;
    else if (!strcmp(option,"--queue")) queue_path=argument;
    else if (!strcmp(option,"--limit") && number(argument,&value) && value>0 && value<=32)
      request.max_batches=(unsigned)value;
    else if (!strcmp(option,"--after-row-id") && number(argument,&value) && value<=(uint64_t)INT64_MAX)
      request.after_row_id=value;
    else if (!strcmp(option,"--target-owner-version") && number(argument,&value) && value==3) {
      request.target_owner_version=3; supplied|=1;
    } else if (!strcmp(option,"--expected-owner-version") && number(argument,&value) && (value==2||value==3)) {
      request.expected_owner.owner_version=(unsigned)value; supplied|=2;
    } else if (!strcmp(option,"--expected-queue-nonce") && hex_bytes(argument,request.expected_owner.queue_nonce,16)) supplied|=4;
    else if (!strcmp(option,"--expected-counter") && number(argument,&value)) { request.expected_owner.latch_counter=value; supplied|=8; }
    else if (!strcmp(option,"--expected-epoch") && number(argument,&value)) { request.expected_owner.latch_epoch=value; supplied|=16; }
    else if (!strcmp(option,"--expected-inventory-sha256")) {
      uint8_t digest[32]; if (!hex_bytes(argument,digest,32)) goto invalid;
      memcpy(request.expected_inventory_sha256,argument,65); supplied|=32;
    } else goto invalid;
  }
  if (!absolute_path(config_path) || (queue_path && !absolute_path(queue_path)) ||
      (request.apply && supplied!=63)) goto invalid;
  EdrConfig cfg; memset(&cfg,0,sizeof(cfg));
  EdrError result=edr_config_load(config_path,&cfg);
  if (result!=EDR_OK) { fprintf(stderr,"queue recovery: configuration parse failed (%d)\n",result); return 2; }
  if (!queue_path) queue_path=cfg.offline.queue_db_path;
  if (!absolute_path(queue_path) || !cfg.agent.tenant_id[0] || !cfg.agent.endpoint_id[0]) {
    edr_config_free_heap(&cfg); fprintf(stderr,"queue recovery: absolute queue and configured tenant/endpoint required\n"); return 2;
  }
  request.tenant_id=cfg.agent.tenant_id; request.endpoint_id=cfg.agent.endpoint_id;
  edr_storage_queue_configure(cfg.offline.max_queue_size_mb,cfg.offline.retention_hours);
  /* Populate the complete immutable binding from a read-only check, but
   * retain the operator's nonce/counter/epoch/owner/SHA as the authorization. */
  if (request.apply) {
    EdrStorageQueueRecoveryRequest check=request; check.apply=0;
    EdrStorageQueueRecoveryReport current;
    result=edr_storage_queue_recover_v1(queue_path,&check,&current);
    if (result!=EDR_OK) { edr_config_free_heap(&cfg); fprintf(stderr,"queue recovery: check failed (%d) %s\n",result,current.reason); return 2; }
    request.expected_owner.latched=current.current_owner.latched;
    request.expected_owner.recovery_required=current.current_owner.recovery_required;
    memcpy(request.expected_owner.recovery_event_id,current.current_owner.recovery_event_id,sizeof(request.expected_owner.recovery_event_id));
    memcpy(request.expected_owner.recovery_batch_id,current.current_owner.recovery_batch_id,sizeof(request.expected_owner.recovery_batch_id));
  }
  result=edr_storage_queue_recover_v1(queue_path,&request,&report);
  char nonce[33]; static const char hex[]="0123456789abcdef";
  for (unsigned i=0;i<16;i++) { nonce[i*2]=hex[report.current_owner.queue_nonce[i]>>4]; nonce[i*2+1]=hex[report.current_owner.queue_nonce[i]&15]; }
  nonce[32]='\0';
  /* No raw event, command line, path, credential or original batch ID is printed. */
  printf("{\"version\":1,\"result\":%d,\"applied\":%d,\"reason\":\"%s\","
    "\"owner_version\":%u,\"queue_nonce\":\"%s\",\"counter\":%llu,\"epoch\":%llu,"
    "\"inventory_sha256\":\"%s\",\"selected_batches\":%llu,\"selected_bytes\":%llu,"
    "\"projected_batches\":%llu,\"retained_unresolved\":%llu,"
    "\"legacy_owner_unacknowledged\":%llu,\"resumed_terminal_frames\":%llu,\"resumed_projections\":%llu,"
    "\"last_event_row_id\":%llu}\n",
    result,report.applied,report.reason,report.current_owner.owner_version,nonce,
    (unsigned long long)report.current_owner.latch_counter,(unsigned long long)report.current_owner.latch_epoch,
    report.inventory_sha256,(unsigned long long)report.selected_batches,(unsigned long long)report.selected_bytes,
    (unsigned long long)report.projected_batches,(unsigned long long)report.retained_unresolved,
    (unsigned long long)report.legacy_owner_unacknowledged,(unsigned long long)report.resumed_terminal_frames,
    (unsigned long long)report.resumed_projections,
    (unsigned long long)report.last_event_row_id);
  edr_config_free_heap(&cfg); return result==EDR_OK?0:2;
invalid:
  fprintf(stderr,"usage: --queue-recover-v1 --config ABS [--queue ABS] [--limit 1..32] [--after-row-id N] "
    "[--apply --target-owner-version 3 --expected-owner-version 2|3 --expected-queue-nonce HEX32 "
    "--expected-counter N --expected-epoch N --expected-inventory-sha256 HEX64]\n");
  return 2;
}
