#include "edr/command_signature.h"
#include "edr/sha256.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void command_signature_idempotency_value(const char *, char *, size_t);
int command_signature_extract_sigv2(const char *, char *, size_t, uint8_t *, size_t, size_t *);
int command_signature_extract_sigv1(const char *, char[65]);
int command_public_key_pem(char *, size_t);
int command_verify_ed25519_pem(const char *, const uint8_t *, size_t, const uint8_t *, size_t);
void hmac_sha256_hex(const char *, const uint8_t *, size_t, char[65]);
int edr_command_signature_verify(const char *cmd_id, const char *cmd_type, const uint8_t *payload,
                                 size_t payload_len, const EdrSoarCommandMeta *sm,
                                 const CommandSignaturePolicy *policy, char *reason, size_t reason_cap) {
  int required = policy && policy->required;
  char idem[512];
  command_signature_idempotency_value(sm ? sm->idempotency_key : NULL, idem, sizeof(idem));
  if (required && !idem[0]) { snprintf(reason, reason_cap, "missing idempotency key"); return 0; }
  char payload_hash[65];
  (void)edr_sha256_hex(payload ? payload : (const uint8_t *)"", payload_len, payload_hash);
  char canonical[1024];
  snprintf(canonical, sizeof(canonical), "%s\n%s\n%s\n%lld\n%u\n%s", cmd_id ? cmd_id : "",
           cmd_type ? cmd_type : "", idem, (long long)(sm ? sm->issued_at_unix_ms : 0),
           (unsigned)(sm ? sm->deadline_ms : 0), payload_hash);
  char alg[32]; uint8_t sig2[96]; size_t sig2_len = 0;
  if (command_signature_extract_sigv2(sm ? sm->idempotency_key : NULL, alg, sizeof(alg), sig2, sizeof(sig2), &sig2_len)) {
    if (strcmp(alg, "ed25519") != 0) { snprintf(reason, reason_cap, "unsupported command signature algorithm: %s", alg); return 0; }
    if (sig2_len != 64u) { snprintf(reason, reason_cap, "invalid command sigv2 signature length"); return 0; }
    char public_key_pem[4096];
    if (!command_public_key_pem(public_key_pem, sizeof(public_key_pem))) { snprintf(reason, reason_cap, "command sigv2 public key missing"); return 0; }
    int ok = command_verify_ed25519_pem(public_key_pem, (const uint8_t *)canonical, strlen(canonical), sig2, sig2_len);
    if (ok == -1) { snprintf(reason, reason_cap, "command sigv2 requires OpenSSL verification support"); return 0; }
    if (!ok) { snprintf(reason, reason_cap, "invalid command sigv2 signature"); return 0; }
    return 1;
  }
  char configured_public_key[4096]; int has_public_key = command_public_key_pem(configured_public_key, sizeof(configured_public_key));
  const char *accept_legacy = getenv("EDR_COMMAND_ACCEPT_LEGACY_HMAC");
  if (required && has_public_key && !(accept_legacy && accept_legacy[0] == '1')) { snprintf(reason, reason_cap, "missing command sigv2 signature"); return 0; }
  const char *key = getenv("EDR_COMMAND_SIGNING_KEY");
  if ((!key || !key[0]) && !required) return 1;
  if (!key || !key[0]) { snprintf(reason, reason_cap, "command signature required but no sigv2 public key or EDR_COMMAND_SIGNING_KEY configured"); return 0; }
  char got[65];
  if (!command_signature_extract_sigv1(sm ? sm->idempotency_key : NULL, got)) { if (required) { snprintf(reason, reason_cap, "missing command signature"); return 0; } return 1; }
  char want[65]; hmac_sha256_hex(key, (const uint8_t *)canonical, strlen(canonical), want);
  if (strcmp(got, want) != 0) { snprintf(reason, reason_cap, "invalid command signature"); return 0; }
  return 1;
}
