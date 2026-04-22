#!/usr/bin/env bash
# T-SC-000: Regenerate shellcode baselines and verify (emit + build targets + ctest + eval).
# Usage (from repo edr-agent/):
#   bash scripts/shellcode_corpus/t_sc_000_verify.sh [CMAKE_BINARY_DIR]
# Default CMAKE_BINARY_DIR is ./build . On MSVC multi-config trees, pass your out dir
# (e.g. build) and ensure you built Release so eval_shellcode_corpus.exe exists under build/Release/.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

python3 scripts/shellcode_corpus/emit_baseline_variants.py

BUILD="${1:-build}"
if [[ ! -f "$BUILD/CMakeCache.txt" ]]; then
  echo "t_sc_000_verify: no CMakeCache at $BUILD — configure first (cmake -B $BUILD ...)" >&2
  exit 1
fi

cmake --build "$BUILD" --target test_shellcode test_shellcode_corpus eval_shellcode_corpus

if grep -q '^CMAKE_CONFIGURATION_TYPES:INTERNAL=' "$BUILD/CMakeCache.txt" 2>/dev/null; then
  ctest --test-dir "$BUILD" -C Release -R shellcode --output-on-failure
else
  ctest --test-dir "$BUILD" -R shellcode --output-on-failure
fi

EVAL=""
if [[ -f "$BUILD/eval_shellcode_corpus" ]]; then
  EVAL="$BUILD/eval_shellcode_corpus"
elif [[ -f "$BUILD/Release/eval_shellcode_corpus.exe" ]]; then
  EVAL="$BUILD/Release/eval_shellcode_corpus.exe"
elif [[ -f "$BUILD/eval_shellcode_corpus.exe" ]]; then
  EVAL="$BUILD/eval_shellcode_corpus.exe"
else
  echo "t_sc_000_verify: eval_shellcode_corpus not found under $BUILD" >&2
  exit 1
fi

"$EVAL" --mode manifest | tail -4
# T-SC-001 pipeline --strict is run by: ctest -R shellcode (shellcode_corpus_pipeline_eval)
echo "T-SC-000 verify: OK"
