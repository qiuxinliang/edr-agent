#ifndef EDR_TEST_PMFE_ASSOCIATION_FIXTURE_H
#define EDR_TEST_PMFE_ASSOCIATION_FIXTURE_H

/* Synthetic detector contract fixtures only. The original satisfies the
 * production shellcode evidence schema; it does not run a shellcode matcher. */
#include "edr/behavior_record.h"
#include <stdio.h>
#include <string.h>

static inline void edr_test_pmfe_original(EdrBehaviorRecord *r,unsigned number,int64_t time_ns) {
  memset(r,0,sizeof(*r)); r->type=EDR_EVENT_PROTOCOL_SHELLCODE;
  r->pid=4242u; r->priority=2u; r->event_time_ns=time_ns;
  r->process_start_key=UINT64_C(0xfedcba9876543210);
  r->process_creation_filetime_100ns=UINT64_C(133444000000000000);
  snprintf(r->endpoint_id,sizeof(r->endpoint_id),"synthetic-pmfe-endpoint");
  snprintf(r->tenant_id,sizeof(r->tenant_id),"synthetic-pmfe-tenant");
  snprintf(r->event_id,sizeof(r->event_id),"original-source-%u",number);
  snprintf(r->detection_context,sizeof(r->detection_context),
    "{\"rule_id\":\"agent_decision_v1\",\"process\":{\"pid\":4242},\"engine_evidence\":{"
    "\"schema\":\"shellcode_result_v1\",\"alert_id\":\"sc-local-%u\",\"owner\":{\"pid\":4242},"
    "\"detection\":{\"detector\":\"synthetic-matched-shellcode\",\"rule\":\"synthetic-payload-signature\",\"score\":0.9},"
    "\"payload\":{\"sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}}}",number);
}
static inline void edr_test_pmfe_result(EdrBehaviorRecord *r,unsigned number,int64_t time_ns,
    const char *status,const char *verdict) {
  edr_test_pmfe_original(r,number,time_ns); r->type=EDR_EVENT_PMFE_SCAN_RESULT;
  snprintf(r->event_id,sizeof(r->event_id),"result-source-%u",number);
  snprintf(r->detection_context,sizeof(r->detection_context),
    "{\"rule_id\":\"agent_decision_v1\",\"process\":{\"pid\":4242},\"engine_evidence\":{"
    "\"schema\":\"pmfe_result_v1\",\"detector\":\"pmfe\",\"source_alert_id\":\"sc-local-%u\","
    "\"followup_only\":true,\"status\":\"%s\",\"verdict\":\"%s\",\"signals\":{\"stomp_suspicious\":0}}}",
    number,status,verdict);
}

#endif
