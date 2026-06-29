#!/usr/bin/env bash
# forensic_collector 契约冒烟测试：用 agent (deep_collector.c) 的真实参数形式跑一遍，
# 断言退出码 0、--out-file 产出且是合法 tar.gz。
#
# 用法：BIN=/path/to/forensic_collector ./contract_smoke.sh
# 默认 BIN 顺序：$BIN > ./forensic_collector > build/forensic_collector
set -euo pipefail

BIN="${BIN:-}"
if [[ -z "$BIN" ]]; then
  for cand in ./forensic_collector build/forensic_collector ./build/forensic_collector; do
    [[ -x "$cand" ]] && BIN="$cand" && break
  done
fi
if [[ -z "$BIN" || ! -x "$BIN" ]]; then
  echo "FAIL: forensic_collector binary not found (set BIN=...)" >&2
  exit 1
fi

WORK="$(mktemp -d)"
OUT_DIR="$WORK/out"
OUT_FILE="$WORK/bundle.tar.gz"
trap 'rm -rf "$WORK"' EXIT

fail() { echo "FAIL: $1" >&2; exit 1; }

# 1) agent 形式：--key=value，带 --out-file
"$BIN" --scope=standard --output-dir="$OUT_DIR" --timeout=60 --out-file="$OUT_FILE" \
  || fail "collector exited non-zero (--key=value form)"
[[ -f "$OUT_FILE" ]] || fail "--out-file not produced"
tar tzf "$OUT_FILE" >/dev/null 2>&1 || fail "--out-file is not a valid tar.gz"
tar tzf "$OUT_FILE" | grep -q "manifest.json" || fail "bundle missing manifest.json"
echo "OK: --key=value + out-file bundle valid"

# 2) 空格形式：--key value
OUT2="$WORK/out2"; BUNDLE2="$WORK/b2.tar.gz"
"$BIN" --scope standard --output-dir "$OUT2" --timeout 60 --out-file "$BUNDLE2" \
  || fail "collector exited non-zero (space form)"
[[ -f "$BUNDLE2" ]] || fail "space-form --out-file not produced"
echo "OK: space-form args accepted"

# 3) triage scope 无 out-file：仅落 output-dir
OUT3="$WORK/out3"
"$BIN" --scope=triage --output-dir="$OUT3" || fail "triage scope exited non-zero"
[[ -f "$OUT3/manifest.json" ]] || fail "triage scope produced no manifest"
echo "OK: triage scope writes output-dir"

echo "ALL CONTRACT CHECKS PASSED"
