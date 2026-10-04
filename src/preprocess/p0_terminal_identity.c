#include "edr/p0_terminal_identity.h"
#include "edr/sha256.h"
#include <stdio.h>
#include <string.h>
static void commit_text(EdrSha256Ctx *ctx,const char *text) {
  uint32_t n=(uint32_t)strlen(text); uint8_t len[4],zero=0;
  for (unsigned i=0;i<4;i++) len[i]=(uint8_t)(n>>(8u*i));
  edr_sha256_update(ctx,len,sizeof(len));
  edr_sha256_update(ctx,(const uint8_t*)text,n); edr_sha256_update(ctx,&zero,1);
}
int edr_p0_terminal_identity_key(const char *tenant,const char *endpoint,
    const char *rule,const char *event,uint32_t pid,uint64_t start_key,
    uint64_t birth,const char *canonical_path,const char *file_identity,
    char *out,size_t capacity) {
  if (!out || capacity<80 || !tenant || !tenant[0] || !endpoint || !endpoint[0] ||
      !rule || !rule[0] || !event || !event[0] || !pid || !start_key || !birth ||
      !canonical_path || !canonical_path[0] || !file_identity || !file_identity[0]) return 0;
  char pid_text[16],start[32],creation[32],hex[65]; uint8_t digest[32]; EdrSha256Ctx ctx;
  snprintf(pid_text,sizeof(pid_text),"%u",pid);
  snprintf(start,sizeof(start),"%016llx",(unsigned long long)start_key);
  snprintf(creation,sizeof(creation),"%016llx",(unsigned long long)birth);
  const char *fields[]={"edr-p0-enforcement-terminal-v1",tenant,endpoint,rule,event,
    pid_text,start,creation,canonical_path,file_identity};
  edr_sha256_init(&ctx);
  for (size_t i=0;i<sizeof(fields)/sizeof(fields[0]);i++) commit_text(&ctx,fields[i]);
  edr_sha256_final(&ctx,digest);
  for (unsigned i=0;i<32;i++) { static const char digits[]="0123456789abcdef";
    hex[i*2]=digits[digest[i]>>4]; hex[i*2+1]=digits[digest[i]&15]; }
  hex[64]=0; snprintf(out,capacity,"p0-enforcement-%s",hex); return 1;
}
