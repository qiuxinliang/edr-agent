#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "cJSON.h"
#include "edr/attack_surface_report.h"
#include "edr/attack_surface_egress.h"
#include "edr/attack_surface_inventory.h"
#include "edr/security_policy_collect.h"
#include "edr/egress_request_policy.h"
#include "edr/egress_batch_policy.h"
static int policy_collections,egress_collections,inventory_collections,post_calls;
static size_t body_bytes;
void edr_security_policy_snap_collect(const EdrConfig *cfg,EdrSecurityPolicySnap *out) { (void)cfg; memset(out,0,sizeof(*out));policy_collections++; }
void edr_security_policy_snap_write_policy_object(FILE *f,const EdrConfig *cfg,const EdrSecurityPolicySnap *s) { (void)cfg;(void)s;fputs("{}",f); }
void edr_asurf_collect_egress(const EdrConfig *cfg,EdrAsurfEgressRow *out,int max,int *n,int *s,int *t) { (void)cfg;(void)out;(void)max;*n=*s=*t=0;egress_collections++; }
void edr_asurf_inventory_write_json(FILE *f,const EdrConfig *cfg,int listeners_only,EdrAsurfInventorySummary *summary) { (void)cfg;(void)listeners_only;memset(summary,0,sizeof(*summary));fputs("\"syntheticInventory\":{}",f);inventory_collections++; }
int edr_ingest_http_get_suffix(const char *s,char *r,size_t c) { (void)s;(void)r;(void)c;abort(); }
int edr_ingest_http_post_json_suffix(const char *s,const char *body,char *r,size_t c) {
  (void)r;(void)c;post_calls++;body_bytes=strlen(body);
  assert(policy_collections==1 && egress_collections==1 && inventory_collections==1);
  cJSON *root=cJSON_Parse(body);assert(root);cJSON_Delete(root);
  char reason[128];int rc=edr_egress_request_validate("POST",s,"application/json",body,body_bytes,reason,sizeof(reason));
  assert(rc==EDR_EGRESS_REQUEST_DENIED && !strcmp(reason,"egress_purpose_not_allowed"));return rc;
}
int main(void) {
  EdrConfig cfg={0};strcpy(cfg.agent.endpoint_id,"synthetic-endpoint");
  cfg.attack_surface.enabled=1;cfg.attack_surface.defender_enabled=cfg.attack_surface.egress_enabled=1;
  char detail[512];
  for(int i=0;i<3;i++) {
    int rc=edr_attack_surface_execute("manual-audit",NULL,0,&cfg,detail,sizeof(detail));
    assert(rc==EDR_EGRESS_REQUEST_DENIED && !strcmp(detail,"attack_surface_policy_held"));
  }
  assert(!policy_collections && !egress_collections && !inventory_collections && !post_calls && !body_bytes);
  puts("PASS: three denied attack-surface polls perform no collection, snapshot or HTTP");return 0;
}
