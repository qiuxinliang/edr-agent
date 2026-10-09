#!/usr/bin/env bash
# TEST ONLY: real production matcher/codec with system libraries. This does not
# satisfy or change the release CMake PCRE2 producer-provenance gate.
set -euo pipefail
source_root="$(cd "$(dirname "$0")/.." && pwd)"
pcre2_prefix="${EDR_TEST_PCRE2_PREFIX:-/opt/homebrew/opt/pcre2}"
crypto_prefix="${EDR_TEST_OPENSSL_PREFIX:-/opt/homebrew/opt/openssl@3}"
compiler="${CC:-clang}"
test_root="$(mktemp -d "${TMPDIR:-/tmp}/edr-real-ir-test.XXXXXX")"
finish_test() {
  test_status=$?
  if [[ "$test_status" -ne 0 ]]; then
    echo "TEST ONLY real IR contract failed (exit $test_status)." >&2
    for test_log in "$test_root"/*.log; do
      [[ -f "$test_log" ]] || continue
      rg "Assertion failed:|^FAIL:|fixture.*failed|fixture authority unavailable" "$test_log" | sed 's/ context=.*$//' >&2 || true
    done
  fi
  rm -rf "$test_root"
}
trap finish_test EXIT
if [[ ! -f "$pcre2_prefix/include/pcre2.h" || ! -f "$crypto_prefix/include/openssl/evp.h" ]]; then
  echo 'Required TEST ONLY PCRE2/OpenSSL headers unavailable; set EDR_TEST_PCRE2_PREFIX and EDR_TEST_OPENSSL_PREFIX.' >&2
  exit 2
fi
sources=(
 tests/test_p0_source_only_durable_contract.c tests/stub_command_fact_resolver.c
 src/forensic/process_tree_cache.c
 src/core/validation_trace.c
 src/preprocess/p0_source_only_contract.c src/preprocess/p0_rule_direct_emit.c
 src/preprocess/p0_deferred_snapshot.c src/preprocess/windows_file_identity.c
 src/preprocess/p0_rule_ir.c src/preprocess/p0_rule_match.c src/preprocess/behavior_record.c
 src/preprocess/encrypt_p0_rules.c src/preprocess/preprocess_env.c
 src/detection/policy_enforcement.c src/detection/policy_v2.c
 src/serialize/alert_governor.c src/serialize/behavior_alert_emit.c src/serialize/behavior_proto.c
 src/preprocess/p0_terminal_identity.c src/command/sha256.c src/proto/edr/v1/event.pb.c src/transport/egress_batch_policy.c
 third_party/cjson/cJSON.c third_party/nanopb/pb_common.c
 third_party/nanopb/pb_encode.c third_party/nanopb/pb_decode.c
)
absolute_sources=()
for src in "${sources[@]}"; do absolute_sources+=("$source_root/$src"); done
"$compiler" -std=c11 -D_DEFAULT_SOURCE -DEDR_P0_DIRECT_EMIT_TESTING=1 \
 -DEDR_HAVE_NANOPB=1 -DPB_FIELD_32BIT=1 -DEDR_HAVE_OPENSSL_FL=1 -DEDR_OS_POSIX=1 \
 -I"$source_root/include" -I"$source_root/src/proto" -I"$source_root/third_party/cjson" \
 -I"$source_root/third_party/nanopb" -I"$pcre2_prefix/include" -I"$crypto_prefix/include" \
 "${absolute_sources[@]}" -L"$pcre2_prefix/lib" -L"$crypto_prefix/lib" \
 -lpcre2-8 -lcrypto -lpthread -lm -o "$test_root/source_contract"
cat > "$test_root/envelope.c" <<'C'
#include "edr/encrypt_p0_rules.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
int main(int argc, char **argv) {
  FILE *in, *out; long size; uint8_t *plain, *wire; size_t len;
  if (argc != 4 || !(in=fopen(argv[1],"rb"))) return 2;
  if (fseek(in,0,SEEK_END) || (size=ftell(in))<=0 || fseek(in,0,SEEK_SET)) return 2;
  plain=malloc((size_t)size); if (!plain || fread(plain,1,(size_t)size,in)!=(size_t)size) return 2;
  fclose(in);
  if (edr_p0_encrypt_encrypt_edr1_for_test(plain,(size_t)size,&wire,&len)) return 3;
  free(plain);
  out=fopen(argv[2],"wb"); if (!out || fwrite(wire,1,len,out)!=len || fclose(out)) return 2;
  wire[len-1]^=1; /* Authentication failure, without changing decoded claims. */
  out=fopen(argv[3],"wb"); if (!out || fwrite(wire,1,len,out)!=len || fclose(out)) return 2;
  free(wire); return 0;
}
C
"$compiler" -std=c11 -DEDR_HAVE_OPENSSL_FL=1 -DEDR_P0_ENCRYPT_TESTING=1 \
 -I"$source_root/include" -I"$crypto_prefix/include" \
 "$test_root/envelope.c" "$source_root/src/preprocess/encrypt_p0_rules.c" \
 -L"$crypto_prefix/lib" -lcrypto -o "$test_root/envelope"
"$test_root/envelope" "$source_root/config/p0_rule_bundle_ir_v1.json" \
 "$test_root/fixture.enc" "$test_root/tampered.enc"
cd "$test_root"
EDR_P0_IR_PATH="$source_root/config/p0_rule_bundle_ir_v1.json" ./source_contract >plain.log 2>&1
EDR_P0_IR_PATH="$test_root/fixture.enc" ./source_contract >encrypted.log 2>&1
if EDR_P0_IR_PATH="$test_root/tampered.enc" ./source_contract >tampered.log 2>&1; then
  echo 'FAIL: tampered authenticated envelope admitted.' >&2
  exit 1
fi
# Select non-sensitive evidence only, without fixture bodies or key material.
if ! rg -q 'decrypt .* failed: -3' tampered.log; then
  cat tampered.log >&2
  echo 'FAIL: negative result did not establish envelope authentication failure.' >&2
  exit 1
fi
echo 'PASS: real PCRE2 matcher, plaintext and AES-GCM EDR1 source/terminal wire contract; tampered authentication tag rejected.'
echo 'Scope: system libraries TEST ONLY; persistence capture stub; no production producer, publisher-signature, HTTP or Windows-native claim.'
