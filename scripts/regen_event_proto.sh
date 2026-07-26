#!/usr/bin/env sh
# 从 proto/edr/v1/event.proto 重新生成 nanopb 的 event.pb.c / event.pb.h
# 依赖：Python 3.10+（protobuf 7.x 与 third_party/nanopb 生成器一致）、third_party/nanopb
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
python3 third_party/nanopb/generator/nanopb_generator.py \
  -I proto \
  -f proto/edr/v1/event.options \
  proto/edr/v1/event.proto \
  -D src/proto

python3 - <<'PY'
from pathlib import Path

for name in ("event.pb.c", "event.pb.h"):
    path = Path("src/proto/edr/v1") / name
    path.write_text(path.read_text().rstrip() + "\n")
PY
