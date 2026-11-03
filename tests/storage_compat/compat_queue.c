/* Only the transport boundary is replaced; no ACK or network is claimed. */
#define main compat_unused_original_main
#define edr_transport_v2_report_events compat_unused_original_transport
#include COMPAT_TEST_SOURCE
#undef edr_transport_v2_report_events
#undef main
#include "compat_common.h"
static cJSON *compat_queue_records;
static unsigned compat_seen;
static uint8_t *compat_wire(unsigned generation,unsigned item,size_t *length) {
  /* Existing admissible detection-context fixture; ordinary telemetry is
   * intentionally policy-held and must never be made deliverable for this test. */
  size_t original_len=0;uint8_t *original=make_wire(1,0,0,compat_endpoint,&original_len);
  edr_v1_BehaviorEvent *event=calloc(1,sizeof(*event));compat_need(event!=NULL,"event_alloc");
  pb_istream_t input=pb_istream_from_buffer(original+16u,original_len-16u);
  compat_need(pb_decode(&input,edr_v1_BehaviorEvent_fields,event),"fixture_decode");free(original);
  snprintf(event->event_id,sizeof(event->event_id),"storage-source-%05u",generation*10u+item);
  strcpy(event->tenant_id,compat_tenant);
  char projection_reason[96];compat_need(edr_egress_event_project(event,projection_reason,sizeof(projection_reason)),"fixture_owner_projection");
  uint8_t *raw=malloc(65536);compat_need(raw!=NULL,"wire_alloc");
  pb_ostream_t output=pb_ostream_from_buffer(raw+16u,65520u);
  compat_need(pb_encode(&output,edr_v1_BehaviorEvent_fields,event),"fixture_encode");free(event);
  size_t raw_len=output.bytes_written+16u;wr(raw,EDR_TRANSPORT_BATCH_MAGIC_RAW);wr(raw+4u,1u);wr(raw+8u,(uint32_t)raw_len-12u);wr(raw+12u,(uint32_t)output.bytes_written);
  if(!item){*length=raw_len;return raw;}
  size_t body=raw_len-12u;uint8_t *wire=malloc((size_t)LZ4_compressBound((int)body)+12u);compat_need(wire!=NULL,"wire_alloc");
  wr(wire,EDR_TRANSPORT_BATCH_MAGIC_LZ4);wr(wire+4u,1u);wr(wire+8u,(uint32_t)body);
  int n=LZ4_compress_default((char *)raw+12u,(char *)wire+12u,(int)body,LZ4_compressBound((int)body));compat_need(n>0,"compress");
  free(raw);*length=(size_t)n+12u;return wire;
}
static cJSON *compat_queue_fact(unsigned generation,unsigned item,const uint8_t *wire,size_t n) {
  char id[64],sha[65];snprintf(id,sizeof(id),"storage-compat-%u-%u",generation,item);compat_sha(wire,n,sha);
  cJSON *r=cJSON_CreateObject();cJSON_AddStringToObject(r,"batch_id",id);cJSON_AddStringToObject(r,"wire_sha256",sha);cJSON_AddNumberToObject(r,"wire_bytes",(double)n);cJSON_AddBoolToObject(r,"compressed",item!=0u);return r;
}
int edr_transport_v2_report_events(const char *id,const uint8_t *header,size_t h,const uint8_t *body,size_t n) {
  compat_need(!strcmp(compat_stage,"read")&&h==12u&&n<65536u,"unexpected_transport");
  unsigned generation=0,item=0;char tail=0;
  if(strncmp(id,"storage-compat-",15u))return -1; /* Existing unrelated Agent rows remain unacknowledged. */
  compat_need(sscanf(id,"storage-compat-%u-%u%c",&generation,&item,&tail)==2&&generation>=1u&&generation<=compat_generations&&item<2u,"batch_identity");
  unsigned bit=1u<<((generation-1u)*2u+item);compat_need(!(compat_seen&bit),"duplicate_delivery");
  char why[96];compat_need(edr_egress_batch_validate(header,h,body,n,why,sizeof(why)),"real_codec_egress_validation");
  uint8_t wire[65548];memcpy(wire,header,h);memcpy(wire+h,body,n);
  size_t expected_len=0;uint8_t *expected=compat_wire(generation,item,&expected_len);
  compat_need(expected_len==h+n&&!memcmp(expected,wire,expected_len),"persisted_wire_changed");
  uint8_t raw[65536];size_t raw_len=n;
  if(item) {int decoded=LZ4_decompress_safe((const char *)body,(char *)raw,(int)n,sizeof(raw));compat_need(decoded>0,"lz4_decode");raw_len=(size_t)decoded;}
  else memcpy(raw,body,n);
  compat_need(raw_len>=4u&&rd(raw)==raw_len-4u,"frame_bounds");
  edr_v1_BehaviorEvent *event=calloc(1,sizeof(*event));compat_need(event!=NULL,"event_alloc");
  pb_istream_t input=pb_istream_from_buffer(raw+4u,raw_len-4u);compat_need(pb_decode(&input,edr_v1_BehaviorEvent_fields,event),"protobuf_decode");
  char event_id[64];snprintf(event_id,sizeof(event_id),"storage-source-%05u",generation*10u+item);
  compat_need(!strcmp(event->event_id,event_id)&&!strcmp(event->tenant_id,compat_tenant)&&!strcmp(event->endpoint_id,compat_endpoint)&&event->type==EDR_EVENT_NET_CONNECT&&event->pid==42u&&event->has_behavior_alert,"decoded_record_identity");
  cJSON_AddItemToArray(compat_queue_records,compat_queue_fact(generation,item,wire,h+n));compat_seen|=bit;free(event);free(expected);
  return -1; /* Persisted pending row remains unacknowledged. */
}
int main(int argc,char **argv) {
  compat_args(argc,argv);compat_queue_records=cJSON_CreateArray();
  compat_need(compat_selected==compat_retention,"queue_retention_arguments_must_match");
#ifdef _WIN32
  compat_need(_putenv_s("EDR_QUEUE_DRAIN_INTERVAL_MS","0")==0,"drain_interval");
#else
  compat_need(setenv("EDR_QUEUE_DRAIN_INTERVAL_MS","0",1)==0,"drain_interval");
#endif
  edr_storage_queue_configure(compat_max_mb,compat_retention);compat_need(edr_storage_queue_open(argv[2])==EDR_OK,"queue_owner_open");
  if(strcmp(compat_stage,"read")) {
    unsigned generation=!strcmp(compat_stage,"append")?2u:1u;
    for(unsigned item=0;item<2u;item++) {size_t n=0;uint8_t *wire=compat_wire(generation,item,&n);char id[64];snprintf(id,sizeof(id),"storage-compat-%u-%u",generation,item);
      char why[96];compat_need(edr_egress_batch_validate(wire,12u,wire+12u,n-12u,why,sizeof(why)),why);
      compat_need(edr_storage_queue_batch_presence(id,wire,n)==0,"fixture_already_present");
      compat_need(edr_storage_queue_enqueue(id,wire,n,item!=0u,0)==EDR_OK,"queue_owner_write");
      cJSON_AddItemToArray(compat_queue_records,compat_queue_fact(generation,item,wire,n));free(wire);}
  } else {
    /* Installed Agent retries can be up to 300 s in the future. Advance only
     * the existing test delivery-clock seam on this disposable read copy;
     * no persisted retry field or TTL is rewritten by the adapter. */
    edr_storage_queue_test_set_delivery_time((int64_t)time(NULL)+301);
    for(unsigned poll=0;poll<16u&&compat_seen!=((1u<<(compat_generations*2u))-1u);poll++) {
      if(poll) {
#ifdef _WIN32
        Sleep(210);
#else
        struct timespec pause={0,210000000};nanosleep(&pause,NULL);
#endif
      }
      edr_storage_queue_poll_drain();
    }
    compat_need(compat_seen==((1u<<(compat_generations*2u))-1u),"queue_readback_missing");
  }
  edr_storage_queue_close();cJSON *receipt=compat_receipt("queue",compat_queue_records);
  cJSON_AddBoolToObject(receipt,"real_codec",1);cJSON_AddBoolToObject(receipt,"server_ack",0);
  cJSON_AddNumberToObject(receipt,"delivery_clock_advance_s",!strcmp(compat_stage,"read")?301:0);
  cJSON_AddBoolToObject(receipt,"virtual_retry_eligibility_only",!strcmp(compat_stage,"read"));
  cJSON_AddBoolToObject(receipt,"read_by_poll_drain",!strcmp(compat_stage,"read"));compat_print(receipt);return 0;
}
