#ifndef EDR_TEST_P0_TERMINAL_ASSOCIATION_FIXTURE_H
#define EDR_TEST_P0_TERMINAL_ASSOCIATION_FIXTURE_H
/* Synthetic production-schema fixtures; no rule matcher or action executes.
 * Real codec/storage and isolated TLS consumers share this exact contract. */
#include "edr/egress_batch_policy.h"
#include "edr/p0_terminal_identity.h"
#include "edr/transport_sink.h"
#include "edr/types.h"
#include "edr/v1/event.pb.h"
#include <pb_encode.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct EdrTestP0TerminalFixture {
  char terminal_key[96],source_event_id[48],rule_id[64],generation_key[32];
  uint8_t *wire[3]; /* 0 intent, 1 source/result, 2 combined alert */
  size_t length[3];
} EdrTestP0TerminalFixture;
static inline void edr_test_p0_terminal_fixture_free(EdrTestP0TerminalFixture *f) {
  for (unsigned i=0;i<3;i++) { free(f->wire[i]); f->wire[i]=NULL; f->length[i]=0; }
}
static inline void edr_test_p0_terminal_put_u32(uint8_t *p,uint32_t value) {
  for (unsigned i=0;i<4;i++) p[i]=(uint8_t)(value>>(i*8));
}
static inline int edr_test_p0_terminal_fixture_init(EdrTestP0TerminalFixture *f,
    unsigned number,const char *tenant,const char *endpoint) {
  static const char path[]="C:\\synthetic\\p0-required.exe";
  static const char json_path[]="C:\\\\synthetic\\\\p0-required.exe";
  static const char file_id[]="win-fileid-v1:0000000000000001:00112233445566778899aabbccddeeff";
  static const char bundle_sha[]="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  edr_v1_BehaviorEvent *ev=calloc(1,sizeof(*ev));
  if (!f || !ev || !tenant || !endpoint) { free(ev); return 0; }
  memset(f,0,sizeof(*f));
  snprintf(f->source_event_id,sizeof(f->source_event_id),"synthetic-p0-source-%u",number);
  snprintf(f->rule_id,sizeof(f->rule_id),"synthetic-p0-rule");
  ev->type=EDR_EVENT_PROCESS_CREATE; ev->pid=4242; ev->priority=0;
  ev->event_time_ns=1700000000000000000LL+(int64_t)number;
  ev->process_start_key=UINT64_C(0xfedcba9876543210);
  ev->process_creation_filetime_100ns=UINT64_C(133444000000000000);
  snprintf(ev->event_id,sizeof(ev->event_id),"%s",f->source_event_id);
  snprintf(ev->tenant_id,sizeof(ev->tenant_id),"%s",tenant);
  snprintf(ev->endpoint_id,sizeof(ev->endpoint_id),"%s",endpoint);
  snprintf(ev->exe_path,sizeof(ev->exe_path),"%s",path);
  snprintf(ev->image_path_canonical,sizeof(ev->image_path_canonical),"%s",path);
  snprintf(ev->cmdline,sizeof(ev->cmdline),"synthetic-required-rule-fact");
  snprintf(f->generation_key,sizeof(f->generation_key),"startkey-%016llx",
    (unsigned long long)ev->process_start_key);
  if (!edr_p0_terminal_identity_key(tenant,endpoint,f->rule_id,f->source_event_id,
      ev->pid,ev->process_start_key,ev->process_creation_filetime_100ns,path,file_id,
      f->terminal_key,sizeof(f->terminal_key))) goto fail;
  for (unsigned kind=0;kind<3;kind++) {
    int n=snprintf(ev->ave_result_json,sizeof(ev->ave_result_json),
      "{\"evidence\":{\"artifact\":{\"source\":\"process_image_section\",\"quality\":\"action_authoritative\"},"
      "\"file_identity\":\"%s\"},\"enforcement_terminal\":{\"phase\":\"%s\",\"terminal_key\":\"%s\","
      "\"rule_id\":\"%s\",\"rules_bundle_version\":\"synthetic-v1\",\"rules_bundle_sha256\":\"%s\","
      "\"source_event_key\":\"%s\",\"source_event_id\":\"%s\",\"process_pid\":4242,"
      "\"planned_action\":\"terminate_process\",\"process\":{\"generation_key\":\"%s\","
      "\"creation_filetime_100ns\":133444000000000000,\"canonical_image_path\":\"%s\","
      "\"file_identity\":\"%s\",\"file_identity_available\":true},%s}}",
      file_id,kind?"result":"intent",f->terminal_key,f->rule_id,bundle_sha,f->source_event_id,
      f->source_event_id,f->generation_key,json_path,file_id,kind?
      "\"attempted\":true,\"succeeded\":true,\"action\":\"terminate_process\",\"error_code\":0,\"message\":\"synthetic-action-result\"":
      "\"requested\":true");
    if (n<0 || (size_t)n>=sizeof(ev->ave_result_json)) goto fail;
    ev->has_behavior_alert=kind==2;
    if (kind==2) {
      ev->behavior_alert.pid=ev->pid; ev->behavior_alert.timestamp_ns=ev->event_time_ns;
      ev->behavior_alert.anomaly_score=0.9f;
      snprintf(ev->behavior_alert.process_path,sizeof(ev->behavior_alert.process_path),"%s",path);
      n=snprintf(ev->behavior_alert.user_subject_json,sizeof(ev->behavior_alert.user_subject_json),
        "{\"subject_type\":\"edr_dynamic_rule\",\"rule_id\":\"%s\",\"rules_bundle_version\":\"synthetic-v1\","
        "\"rules_bundle_sha256\":\"%s\",\"context\":{\"pid\":4242,\"event_type\":1,\"source_event_id\":\"%s\","
        "\"endpoint_id\":\"%s\",\"tenant_id\":\"%s\",\"process_path\":\"%s\",\"canonical_image_path\":\"%s\","
        "\"process_start_key\":\"%llu\",\"process_creation_filetime_100ns\":\"133444000000000000\",\"file_identity\":\"%s\"},"
        "\"enforcement\":{\"requested\":true,\"attempted\":true,\"succeeded\":true,\"action\":\"terminate_process\",\"error_code\":0}}",
        f->rule_id,bundle_sha,f->source_event_id,endpoint,tenant,json_path,json_path,
        (unsigned long long)ev->process_start_key,file_id);
      if (n<0 || (size_t)n>=sizeof(ev->behavior_alert.user_subject_json)) goto fail;
    }
    f->wire[kind]=malloc(65536); if (!f->wire[kind]) goto fail;
    pb_ostream_t out=pb_ostream_from_buffer(f->wire[kind]+16,65520);
    if (!pb_encode(&out,edr_v1_BehaviorEvent_fields,ev)) goto fail;
    f->length[kind]=out.bytes_written+16;
    edr_test_p0_terminal_put_u32(f->wire[kind],EDR_TRANSPORT_BATCH_MAGIC_RAW);
    edr_test_p0_terminal_put_u32(f->wire[kind]+4,1);
    edr_test_p0_terminal_put_u32(f->wire[kind]+8,(uint32_t)out.bytes_written+4);
    edr_test_p0_terminal_put_u32(f->wire[kind]+12,(uint32_t)out.bytes_written);
  }
  free(ev); return 1;
fail:
  free(ev); edr_test_p0_terminal_fixture_free(f); return 0;
}
#endif
