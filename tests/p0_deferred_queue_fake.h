/* Queue-port fake for P0 state-machine tests. Real transactions, recovery,
 * capacity and corruption are exercised by test_storage_queue_sqlite. */
#include <stdlib.h>
#include <string.h>
typedef struct { char key[65]; uint32_t family; uint8_t *payload; size_t length; int state; } DeferredFakeRow;
static DeferredFakeRow deferred_rows[64];
static unsigned deferred_count, deferred_completions, deferred_retries;
static int deferred_write_fails, deferred_complete_fails;
static int deferred_contains_fails, deferred_retry_fails, deferred_fail_fails;
static unsigned deferred_peeks;
static void deferred_fake_reset(void) {
  for (unsigned i=0;i<deferred_count;++i) free(deferred_rows[i].payload);
  memset(deferred_rows,0,sizeof(deferred_rows));
  deferred_count=deferred_completions=deferred_retries=0;
  deferred_write_fails=deferred_complete_fails=0;
  deferred_contains_fails=deferred_retry_fails=deferred_fail_fails=0;
  deferred_peeks=0;
}
int edr_storage_queue_p0_deferred_contains(const char *key) {
  if (deferred_contains_fails) return -1;
  for (unsigned i=0;i<deferred_count;++i) if (!strcmp(key,deferred_rows[i].key)) return 1;
  return 0;
}
EdrError edr_storage_queue_p0_deferred_retain(const char *key,uint32_t family,const uint8_t *p,size_t n) {
  if (deferred_write_fails || deferred_count==64u) return EDR_ERR_SQLITE_WRITE;
  for (unsigned i=0;i<deferred_count;++i) if (!strcmp(key,deferred_rows[i].key))
    return deferred_rows[i].length==n && !memcmp(p,deferred_rows[i].payload,n) ? EDR_OK : EDR_ERR_SQLITE_WRITE;
  DeferredFakeRow *r=&deferred_rows[deferred_count];
  r->payload=malloc(n); if(!r->payload) return EDR_ERR_SQLITE_WRITE;
  memcpy(r->payload,p,n); r->length=n; r->family=family; strcpy(r->key,key); deferred_count++;
  return EDR_OK;
}
int edr_storage_queue_p0_deferred_peek(uint32_t healthy,char key[65],uint8_t **p,size_t *n) {
  deferred_peeks++;
  for(unsigned i=0;i<deferred_count;++i) if(!deferred_rows[i].state && (healthy&deferred_rows[i].family)) {
    *p=malloc(deferred_rows[i].length); if(!*p) return -1;
    *n=deferred_rows[i].length; memcpy(*p,deferred_rows[i].payload,*n); strcpy(key,deferred_rows[i].key); return 1;
  }
  return 0;
}
EdrError edr_storage_queue_p0_deferred_complete(const char *key,const char *batch,const uint8_t *p,size_t n,const char *reason) {
  (void)batch;(void)p;(void)n;(void)reason;
  if(deferred_complete_fails) return EDR_ERR_SQLITE_WRITE;
  for(unsigned i=0;i<deferred_count;++i) if(!strcmp(key,deferred_rows[i].key)) {
    if(!deferred_rows[i].state) {deferred_rows[i].state=1; deferred_completions++;}
    return EDR_OK;
  }
  return EDR_ERR_SQLITE_WRITE;
}
EdrError edr_storage_queue_p0_deferred_retry(const char *key,const char *reason) {
  (void)key;(void)reason;deferred_retries++;
  return deferred_retry_fails ? EDR_ERR_SQLITE_WRITE : EDR_OK;
}
EdrError edr_storage_queue_p0_deferred_fail(const char *key,const char *reason) {
  (void)reason;
  if (deferred_fail_fails) return EDR_ERR_SQLITE_WRITE;
  for(unsigned i=0;i<deferred_count;++i) if(!strcmp(key,deferred_rows[i].key)) {deferred_rows[i].state=2;return EDR_OK;}
  return EDR_ERR_SQLITE_WRITE;
}
