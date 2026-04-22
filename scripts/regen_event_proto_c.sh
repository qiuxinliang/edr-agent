#!/usr/bin/env sh
# 使用 protoc-gen-c 生成 edr.v1 的 C API（event.pb-c.c / event.pb-c.h）
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
OUT="src/proto_c/edr/v1"
mkdir -p "$OUT"

if ! command -v protoc >/dev/null 2>&1; then
  echo "需要 protoc" >&2
  exit 1
fi

GEN_C="protoc-gen-c"
if ! command -v protoc-gen-c >/dev/null 2>&1; then
  for cand in \
    "$ROOT/third_party/protobuf-c/protoc-gen-c/protoc-gen-c" \
    "$ROOT/third_party/protobuf-c/protoc-c/protoc-gen-c"; do
    if test -x "$cand"; then
      GEN_C="$cand"
      break
    fi
  done
  if test "$GEN_C" = "protoc-gen-c"; then
    echo "需要 protoc-gen-c（brew install protobuf-c，或在 third_party/protobuf-c 下 configure && make）" >&2
    exit 1
  fi
fi

exec protoc \
  --proto_path="$ROOT/proto" \
  --plugin=protoc-gen-c="$GEN_C" \
  --c_out="$OUT" \
  "$ROOT/proto/edr/v1/event.proto"
