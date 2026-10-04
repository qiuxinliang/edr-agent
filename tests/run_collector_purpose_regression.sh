#!/usr/bin/env bash
# TEST ONLY: expected exit 1 reproduces the pre-fix child argument bypass.
set -euo pipefail
source_root="$(cd "$(dirname "$0")/.." && pwd)"
baseline=8fed2f9ae7dc018804e56d4ca747078727d41156
fixture_root="$(mktemp -d "${TMPDIR:-/tmp}/edr-collector-before.XXXXXX")"
trap 'rm -rf "$fixture_root"' EXIT
mkdir "$fixture_root/source"
git -C "$source_root" archive "$baseline" | tar -x -C "$fixture_root/source"
# Only the synthetic contract is replaced. All collector and policy owners
# remain from the exact archived commit; it never launches a real collector.
cp "$source_root/tests/test_deep_collector_manifest.c" "$fixture_root/source/tests/"
cd "$fixture_root/source"
"${CC:-cc}" -std=gnu11 -Iinclude -Ithird_party/cjson -Isrc/proto -Ithird_party/nanopb -Ithird_party/lz4 \
 -DEDR_HAVE_LZ4=1 -DPB_FIELD_32BIT=1 \
 tests/test_deep_collector_manifest.c src/command/sha256.c \
 src/transport/egress_batch_policy.c src/transport/egress_request_policy.c \
 src/proto/edr/v1/event.pb.c third_party/nanopb/pb_common.c third_party/nanopb/pb_decode.c \
 third_party/cjson/cJSON.c third_party/lz4/lz4.c -lm -lpthread \
 -o "$fixture_root/collector-before" > "$fixture_root/build.log" 2>&1 || {
   echo 'Infrastructure build failure; pre-fix regression not established.' >&2; exit 2;
 }
status=0
env -i PATH="$PATH" TMPDIR="$fixture_root/" EDR_FORENSIC_COLLECTOR_BIN="$fixture_root/no-real-collector" \
 "$fixture_root/collector-before" > "$fixture_root/test.log" 2>&1 || status=$?
if [[ "$status" != 1 ]] || ! rg -q '^FAIL: blocking collector rejects unsupported egress' "$fixture_root/test.log" || \
   ! rg -q '^FAIL: legacy launch rejects an independent upload URL' "$fixture_root/test.log"; then
 echo 'Required pre-fix assertions did not fail; no reproduced regression claim.' >&2; exit 2
fi
printf '%s\n' 'REPRODUCED: forbidden child arguments and legacy upload URL rejected by the test contract but accepted by pre-fix code. Synthetic only; expected FAIL exit 1.'
exit 1
