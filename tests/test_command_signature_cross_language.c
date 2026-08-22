#include "edr/command_signature.h"
#include "edr/config.h"
#include "cJSON.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const EdrConfig *edr_command_get_config(void) { return NULL; }

static unsigned char b64val(char c) { if(c>='A'&&c<='Z')return (unsigned char)(c-'A'); if(c>='a'&&c<='z')return (unsigned char)(c-'a'+26); if(c>='0'&&c<='9')return (unsigned char)(c-'0'+52); if(c=='-')return 62; return 63; }
static size_t b64decode(const char *s, unsigned char *out, size_t cap) { size_t n=0; unsigned acc=0,bits=0; for(;*s;s++){ if(*s=='=')break; acc=(acc<<6)|b64val(*s); bits+=6; if(bits>=8){bits-=8;if(n<cap)out[n++]=(unsigned char)((acc>>bits)&255u);}} return n; }
static char *read_all(const char *path) { FILE *f=fopen(path,"rb"); if(!f)return NULL; fseek(f,0,SEEK_END); long n=ftell(f); rewind(f); char *p=(char*)calloc((size_t)n+1,1); if(p)fread(p,1,(size_t)n,f); fclose(f); return p; }

int main(int argc, char **argv) {
  const char *fixture = argc > 1 ? argv[1] : "command_sigv2_fixture.json";
  char *raw=read_all(fixture); if(!raw)return 2; cJSON *j=cJSON_Parse(raw); free(raw); if(!j)return 3;
  const char *id=cJSON_GetObjectItem(j,"command_id")->valuestring, *type=cJSON_GetObjectItem(j,"command_type")->valuestring, *idem=cJSON_GetObjectItem(j,"idempotency_key")->valuestring, *pem=cJSON_GetObjectItem(j,"public_key_pem")->valuestring, *pb64=cJSON_GetObjectItem(j,"payload")->valuestring;
  unsigned char payload[1024]; size_t payload_len=b64decode(pb64,payload,sizeof(payload)); EdrSoarCommandMeta m; memset(&m,0,sizeof(m)); snprintf(m.idempotency_key,sizeof(m.idempotency_key),"%s",idem); m.issued_at_unix_ms=(int64_t)cJSON_GetObjectItem(j,"issued_at_unix_ms")->valuedouble; m.deadline_ms=(uint32_t)cJSON_GetObjectItem(j,"deadline_ms")->valuedouble; setenv("EDR_COMMAND_SIGNING_PUBLIC_KEY",pem,1);
  CommandSignaturePolicy policy={1}; char reason[160]; if(!edr_command_signature_verify(id,type,payload,payload_len,&m,&policy,reason,sizeof(reason)))return 4;
  unsigned char bad[1024]; memcpy(bad,payload,payload_len); bad[0]^=1; if(edr_command_signature_verify(id,type,bad,payload_len,&m,&policy,reason,sizeof(reason)))return 5;
  if(edr_command_signature_verify(id,"restore_host",payload,payload_len,&m,&policy,reason,sizeof(reason)))return 6;
  EdrSoarCommandMeta timebad=m; timebad.issued_at_unix_ms++; if(edr_command_signature_verify(id,type,payload,payload_len,&timebad,&policy,reason,sizeof(reason)))return 7;
  EdrSoarCommandMeta sigbad=m; sigbad.idempotency_key[strlen(sigbad.idempotency_key)-1] = sigbad.idempotency_key[strlen(sigbad.idempotency_key)-1]=='A'?'B':'A'; if(edr_command_signature_verify(id,type,payload,payload_len,&sigbad,&policy,reason,sizeof(reason)))return 8;
  cJSON_Delete(j); puts("command_signature_cross_language: PASS"); return 0;
}
