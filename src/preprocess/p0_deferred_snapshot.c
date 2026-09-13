#include "edr/p0_deferred_snapshot.h"
#include "edr/storage_queue.h"
#include "cJSON.h"
#include <errno.h>
#include <float.h>
#include <limits.h>
#include <math.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum FieldKind { F_TEXT, F_UNSIGNED, F_SIGNED, F_FLOAT, F_MITRE };
typedef struct { const char *name; size_t offset, size; enum FieldKind kind; } Field;
#define FIELD(n,k) {#n, offsetof(EdrBehaviorRecord,n), sizeof(((EdrBehaviorRecord *)0)->n), k},
#define TEXT(n) FIELD(n,F_TEXT)
#define UNSIGNED(n) FIELD(n,F_UNSIGNED)
#define SIGNED(n) FIELD(n,F_SIGNED)
#define FLOAT(n) FIELD(n,F_FLOAT)
#define MITRE(n) FIELD(n,F_MITRE)
static const Field fields[] = {
#include "p0_deferred_fields.inc"
};
#undef MITRE
#undef FLOAT
#undef SIGNED
#undef UNSIGNED
#undef TEXT
#undef FIELD

static uint64_t load_unsigned(const void *p, size_t n) {
  uint64_t a; uint32_t b; uint8_t c;
  if (n == sizeof(a)) { memcpy(&a,p,n); return a; }
  if (n == sizeof(b)) { memcpy(&b,p,n); return b; }
  memcpy(&c,p,1); return c;
}
static int64_t load_signed(const void *p, size_t n) {
  int64_t a; int b;
  if (n == sizeof(a)) { memcpy(&a,p,n); return a; }
  memcpy(&b,p,sizeof(b)); return b;
}
static int add_text(cJSON *o, const char *key, const char *s, size_t cap) {
  return memchr(s,0,cap) && cJSON_AddStringToObject(o,key,s) != NULL;
}
static int copy_text(const cJSON *o, const char *key, char *out, size_t cap) {
  const cJSON *v = cJSON_GetObjectItemCaseSensitive(o,key);
  if (!cJSON_IsString(v) || !v->valuestring || strlen(v->valuestring) >= cap) return 0;
  memcpy(out,v->valuestring,strlen(v->valuestring)+1u);
  return 1;
}

int edr_p0_deferred_snapshot_encode(const EdrBehaviorRecord *r,
    const EdrP0RuleIrBinding *b, const char *rule_id, char **out, size_t *length) {
  cJSON *root = NULL, *record = NULL;
  char *json = NULL;
  if (!out || !length) return 0;
  *out = NULL; *length = 0u;
  if (!r || !b || !rule_id || !rule_id[0] || strlen(rule_id) >= 64u ||
      !r->event_id[0] || !r->endpoint_id[0] || !r->tenant_id[0]) return 0;
  root = cJSON_CreateObject();
  if (!root || !cJSON_AddNumberToObject(root,"schema",1) ||
      !cJSON_AddStringToObject(root,"rule_id",rule_id) ||
      !add_text(root,"bundle_version",b->rules_bundle_version,sizeof(b->rules_bundle_version)) ||
      !add_text(root,"bundle_sha256",b->artifact_sha256,sizeof(b->artifact_sha256)) ||
      !(record = cJSON_AddObjectToObject(root,"record"))) goto done;
  for (size_t i=0; i<sizeof(fields)/sizeof(fields[0]); ++i) {
    const Field *f = &fields[i];
    const void *p = (const char *)r + f->offset;
    char number[32];
    if (f->kind == F_TEXT) {
      if (!add_text(record,f->name,p,f->size)) goto done;
    } else if (f->kind == F_MITRE) {
      cJSON *array = cJSON_AddArrayToObject(record,f->name);
      if (!array) goto done;
      for (size_t j=0; j<EDR_BR_MAX_MITRE; ++j) {
        cJSON *v;
        if (!memchr(r->mitre_ttps[j],0,sizeof(r->mitre_ttps[j]))) goto done;
        v = cJSON_CreateString(r->mitre_ttps[j]);
        if (!v) goto done;
        if (!cJSON_AddItemToArray(array,v)) { cJSON_Delete(v); goto done; }
      }
    } else if (f->kind == F_FLOAT) {
      float value; memcpy(&value,p,sizeof(value));
      if (!isfinite(value) || !cJSON_AddNumberToObject(record,f->name,value)) goto done;
    } else {
      if (f->kind == F_UNSIGNED)
        snprintf(number,sizeof(number),"%llu",(unsigned long long)load_unsigned(p,f->size));
      else snprintf(number,sizeof(number),"%lld",(long long)load_signed(p,f->size));
      if (!cJSON_AddStringToObject(record,f->name,number)) goto done;
    }
  }
  json = cJSON_PrintUnformatted(root);
  if (json) { *length = strlen(json); *out = json; }
done:
  cJSON_Delete(root);
  return json != NULL;
}

int edr_p0_deferred_snapshot_decode(const char *json, size_t length,
    EdrBehaviorRecord *r, EdrP0RuleIrBinding *b, char *rule_id, size_t rule_cap) {
  const char *end = NULL;
  cJSON *root = NULL;
  const cJSON *record, *schema;
  int ok = 0;
  if (!json || !length || length > EDR_STORAGE_QUEUE_P0_DEFERRED_MAX_PAYLOAD_BYTES ||
      !r || !b || !rule_id || !rule_cap) return 0;
  memset(r,0,sizeof(*r)); memset(b,0,sizeof(*b)); rule_id[0]=0;
  root = cJSON_ParseWithLengthOpts(json,length,&end,0);
  if (!root || end != json+length || !cJSON_IsObject(root) || cJSON_GetArraySize(root)!=5) goto done;
  schema=cJSON_GetObjectItemCaseSensitive(root,"schema");
  record=cJSON_GetObjectItemCaseSensitive(root,"record");
  if (!cJSON_IsNumber(schema) || schema->valuedouble!=1.0 || !cJSON_IsObject(record) ||
      cJSON_GetArraySize(record)!=(int)(sizeof(fields)/sizeof(fields[0])) ||
      !copy_text(root,"rule_id",rule_id,rule_cap) ||
      !copy_text(root,"bundle_version",b->rules_bundle_version,sizeof(b->rules_bundle_version)) ||
      !copy_text(root,"bundle_sha256",b->artifact_sha256,sizeof(b->artifact_sha256))) goto done;
  for (size_t i=0; i<sizeof(fields)/sizeof(fields[0]); ++i) {
    const Field *f=&fields[i];
    void *p=(char *)r+f->offset;
    const cJSON *v=cJSON_GetObjectItemCaseSensitive(record,f->name);
    char canonical[32], *tail=NULL;
    if (f->kind==F_TEXT) {
      if (!copy_text(record,f->name,p,f->size)) goto done;
    } else if (f->kind==F_MITRE) {
      if (!cJSON_IsArray(v) || cJSON_GetArraySize(v)!=EDR_BR_MAX_MITRE) goto done;
      for (size_t j=0; j<EDR_BR_MAX_MITRE; ++j) {
        const cJSON *s=cJSON_GetArrayItem(v,(int)j);
        if (!cJSON_IsString(s) || !s->valuestring || strlen(s->valuestring)>=sizeof(r->mitre_ttps[j])) goto done;
        memcpy(r->mitre_ttps[j],s->valuestring,strlen(s->valuestring)+1u);
      }
    } else if (f->kind==F_FLOAT) {
      float value;
      if (!cJSON_IsNumber(v) || !isfinite(v->valuedouble) || fabs(v->valuedouble)>FLT_MAX) goto done;
      value=(float)v->valuedouble; memcpy(p,&value,sizeof(value));
    } else {
      if (!cJSON_IsString(v) || !v->valuestring || !v->valuestring[0]) goto done;
      errno=0;
      if (f->kind==F_UNSIGNED) {
        uint64_t a=(uint64_t)strtoull(v->valuestring,&tail,10);
        snprintf(canonical,sizeof(canonical),"%llu",(unsigned long long)a);
        if (errno || !tail || *tail || strcmp(canonical,v->valuestring)) goto done;
        if (f->size==8u) memcpy(p,&a,8u);
        else if (f->size==4u && a<=UINT32_MAX) { uint32_t n=(uint32_t)a; memcpy(p,&n,4u); }
        else if (f->size==1u && a<=UINT8_MAX) { uint8_t n=(uint8_t)a; memcpy(p,&n,1u); }
        else goto done;
      } else {
        int64_t a=(int64_t)strtoll(v->valuestring,&tail,10);
        snprintf(canonical,sizeof(canonical),"%lld",(long long)a);
        if (errno || !tail || *tail || strcmp(canonical,v->valuestring)) goto done;
        if (f->size==8u) memcpy(p,&a,8u);
        else if (f->size==sizeof(int) && a>=INT_MIN && a<=INT_MAX) { int n=(int)a; memcpy(p,&n,sizeof(n)); }
        else goto done;
      }
    }
  }
  if (!rule_id[0] || !r->event_id[0] || !r->endpoint_id[0] || !r->tenant_id[0] ||
      r->mitre_ttp_count<0 || r->mitre_ttp_count>(int)EDR_BR_MAX_MITRE) goto done;
  ok=1;
done:
  cJSON_Delete(root);
  if (!ok) { memset(r,0,sizeof(*r)); memset(b,0,sizeof(*b)); rule_id[0]=0; }
  return ok;
}
