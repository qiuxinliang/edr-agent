#!/usr/bin/env bash
# TEST ONLY. Reproduce the historical FAIL without running the service entry
# point, reading a real queue/configuration, or importing the new egress guard.
# A reproduced regression deliberately exits 1, exactly like receiver --baseline.
# Usage: EDR_TEST_OPENSSL_PREFIX=/optional/openssl/prefix bash tests/run_egress_baseline_regression.sh
set -euo pipefail
trap 'echo "TEST ONLY infrastructure command failed; historical FAIL evidence not established." >&2; exit 2' ERR

if [[ "${1:-}" == "--help" ]]; then
  echo 'TEST ONLY: bash tests/run_egress_baseline_regression.sh'
  echo 'Optional: EDR_TEST_OPENSSL_PREFIX=/path/to/openssl; EDR_TEST_BUILD_JOBS=6.'
  echo 'Expected exit 1 means the historical regression FAIL was reproduced; exit 2 means an infrastructure/evidence error.'
  exit 0
fi
if [[ $# -ne 0 ]]; then echo 'Unsupported argument; use --help.' >&2; exit 2; fi

source_root="$(cd "$(dirname "$0")/.." && pwd)"
baseline_commit='7c43dc2d30f9c05292ca5cce6dfe893d2dc39528'
crypto_prefix="${EDR_TEST_OPENSSL_PREFIX:-}"
build_jobs="${EDR_TEST_BUILD_JOBS:-6}"
case "$build_jobs" in ''|*[!0-9]*|0) echo 'EDR_TEST_BUILD_JOBS must be a positive integer.' >&2; exit 2;; esac
for executable in git tar cmake ninja python3; do
  if ! command -v "$executable" >/dev/null 2>&1; then
    echo "Required TEST ONLY executable unavailable: $executable" >&2; exit 2
  fi
done
if [[ -z "$crypto_prefix" && -f /opt/homebrew/opt/openssl@3/include/openssl/ssl.h ]]; then
  crypto_prefix=/opt/homebrew/opt/openssl@3
fi
if [[ -n "$crypto_prefix" && ! -f "$crypto_prefix/include/openssl/ssl.h" ]]; then
  echo 'OpenSSL prefix has no include/openssl/ssl.h; correct EDR_TEST_OPENSSL_PREFIX.' >&2; exit 2
fi
if [[ ! -x "$crypto_prefix/bin/openssl" ]] && ! command -v openssl >/dev/null 2>&1; then
  echo 'OpenSSL executable unavailable; set EDR_TEST_OPENSSL_PREFIX or install it on the test host.' >&2; exit 2
fi
if ! git -C "$source_root" cat-file -e "$baseline_commit^{commit}"; then
  echo 'Exact baseline commit is unavailable locally; no fetch or replacement ref is used.' >&2; exit 2
fi

test_root="$(mktemp -d "${TMPDIR:-/tmp}/edr-egress-baseline.XXXXXX")"
trap 'rm -rf "$test_root"' EXIT
archive_root="$test_root/source"
build_root="$test_root/build"
mkdir "$archive_root"
git -C "$source_root" archive "$baseline_commit" | tar -x -C "$archive_root"
if [[ -f "$archive_root/src/transport/egress_request_policy.c" ]]; then
  echo 'Baseline unexpectedly contains the new guard; refusing contaminated evidence.' >&2; exit 2
fi
# Copy only the synthetic entry point and loopback receiver. All production
# implementations and their dependency selection remain from the exact archive.
cp "$source_root/tests/test_egress_tls_client.c" "$archive_root/tests/"
cp "$source_root/tests/test_egress_tls_receiver.py" "$archive_root/tests/"
cat >> "$archive_root/tests/CMakeLists.txt" <<'CMAKE'

# TEST ONLY baseline client: exact archived production sources, no egress policy.
if(WIN32 OR NOT SQLite3_FOUND OR NOT OpenSSL_FOUND)
  message(FATAL_ERROR "TEST ONLY baseline needs a native POSIX build, SQLite and OpenSSL")
endif()
get_target_property(_baseline_agent_sources edr_agent SOURCES)
set(_baseline_client_sources)
foreach(_source IN LISTS _baseline_agent_sources)
  if(NOT _source MATCHES "(^|/)main\\.c$|\\.rc$")
    if(IS_ABSOLUTE "${_source}")
      list(APPEND _baseline_client_sources "${_source}")
    else()
      list(APPEND _baseline_client_sources "${CMAKE_SOURCE_DIR}/${_source}")
    endif()
  endif()
endforeach()
add_executable(test_egress_tls_client test_egress_tls_client.c ${_baseline_client_sources})
target_include_directories(test_egress_tls_client PRIVATE
  $<TARGET_PROPERTY:edr_agent,INCLUDE_DIRECTORIES>)
target_compile_definitions(test_egress_tls_client PRIVATE
  $<TARGET_PROPERTY:edr_agent,COMPILE_DEFINITIONS>)
target_compile_options(test_egress_tls_client PRIVATE
  $<TARGET_PROPERTY:edr_agent,COMPILE_OPTIONS>)
target_link_libraries(test_egress_tls_client PRIVATE
  $<TARGET_PROPERTY:edr_agent,LINK_LIBRARIES>)
edr_apply_test_warnings(test_egress_tls_client)
CMAKE

openssl_options=()
fixture_path="$PATH"
if [[ -n "$crypto_prefix" ]]; then
  openssl_options+=("-DOPENSSL_ROOT_DIR=$crypto_prefix" "-DCMAKE_PREFIX_PATH=$crypto_prefix")
  if [[ -x "$crypto_prefix/bin/openssl" ]]; then fixture_path="$crypto_prefix/bin:$fixture_path"; fi
fi
# This is deliberately Debug/CTest with the explicit P0 IR/PCRE2 test stub,
# not a production/release producer. AVE, codec, SQLite, TLS and ACK owners are
# real. Build logs stay temporary and contain no request body or certificate key.
if ! cmake -S "$archive_root" -B "$build_root" -G Ninja \
    -DCMAKE_BUILD_TYPE=Debug -DEDR_BUILD_TESTS=ON \
    -DEDR_P0_RULE_IR_ALLOW_TEST_STUB=ON -DEDR_REQUIRE_PCRE2=OFF \
    -DEDR_REQUIRE_YARA=OFF -DEDR_WITH_YARA=OFF -DEDR_REQUIRE_SQLITE=ON \
    -DEDR_WITH_HTTP2_CURL=OFF -DEDR_WITH_INGEST_HTTPS_OPENSSL=ON \
    -DEDR_BUILD_AVE_SHARED_LIB=OFF -DEDR_WITH_FORENSIC_COLLECTOR=ON \
    -DEDR_WITH_ZSTD=ON "${openssl_options[@]}" > "$test_root/configure.log" 2>&1; then
  echo 'Baseline configure failed; check native SQLite/OpenSSL/compiler availability and prefix. Regression was not run.' >&2
  exit 2
fi
if ! cmake --build "$build_root" --target test_egress_tls_client -j "$build_jobs" > "$test_root/build.log" 2>&1; then
  echo 'Archived production-source baseline client failed to build. Regression was not run.' >&2; exit 2
fi

# The receiver creates a second temporary root for CA, synthetic SQLite and
# AVE state, and uses it as the child cwd. Remove inherited EDR configuration
# overrides entirely. TLS verification and ordinary request budgets stay enabled.
cd "$test_root"
receiver_exit=0
env -i PATH="$fixture_path" TMPDIR="$test_root/" \
  python3 -B "$archive_root/tests/test_egress_tls_receiver.py" \
    --client "$build_root/tests/test_egress_tls_client" --baseline \
    > "$test_root/receiver-report.json" 2> "$test_root/receiver-error.log" || receiver_exit=$?
if [[ "$receiver_exit" -ne 1 ]]; then
  echo "Baseline receiver returned $receiver_exit, expected historical regression FAIL (1); evidence not established." >&2
  exit 2
fi

if ! python3 -I - "$test_root/receiver-report.json" <<'PY'
import json
import sys
from pathlib import Path

report = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
assert report["baseline_expected_failure"] is True and report["passed"] is False
assert report["synthetic_only"] is True and report["production_connections"] == 0
scenario = next(item for item in report["scenarios"] if item["mode"] == "positive")
assert scenario["client_exit"] == 1 and scenario["receiver_business_failures"] > 0
forbidden = (
    "/api/v1/ingest/report-command-result", "/api/v1/ingest/upload-file",
    "/api/v1/endpoints/synthetic-endpoint/attack-surface",
    "/api/v1/ingest/agent-upgrade-event", "/api/v1/ingest/unknown",
)
counts = {route: scenario["classes"].get(route, 0) for route in forbidden}
assert all(count > 0 for count in counts.values()), "forbidden categories were not observed"
metrics = scenario["client_metrics"][0]
assert metrics["detector_inputs"] == metrics["detected"] == 1 and metrics["enqueued"] == 3
assert metrics["collection_source"] == "synthetic_fixture" and metrics["failed_checks"] > 0
untrusted = next(item for item in report["scenarios"] if item["mode"] == "wrong-ca")
assert untrusted["received_requests"] == 0
print(json.dumps({
    "regression_result": "FAIL", "historical_failure_reproduced": True,
    "baseline_commit": "7c43dc2d30f9c05292ca5cce6dfe893d2dc39528",
    "original_receiver_exit": 1, "received_requests": scenario["received_requests"],
    "received_body_bytes": scenario["received_body_bytes"],
    "receiver_business_failures": scenario["receiver_business_failures"],
    "observed_forbidden_categories": counts, "production_connections": 0,
}, sort_keys=True))
PY
then
  echo 'Historical FAIL occurred, but required receiver evidence did not validate; reproduction incomplete.' >&2
  exit 2
fi
echo 'REPRODUCED historical regression FAIL. Original test failure is preserved; this script deliberately exits 1.'
exit 1
