#!/usr/bin/env python3
"""
A2.3（录制级锚点）：固定 ETW1 文本槽载荷的 **UTF-8 字节** 与 SHA-256，防无意改行序/键名/换行符。
改 `fixtures/tdh/etw1_kernel_process_pimg_v1.golden` 后须同步更新本文件中的 EXPECTED_SHA256，
并跑 `bash edr-backend/scripts/collect_p0_b24_evidence.sh` / CI precheck。
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

# 与 etw1_kernel_process_pimg_v1.golden 文件内容一致（变更时重算并更新）
EXPECTED_SHA256 = "e072b33769799bd91ff1117701f899fd4fd771807bc8c92d973a51b156ce9ceb"


def _root() -> Path:
    return Path(__file__).resolve().parent.parent


def main() -> int:
    golden = _root() / "fixtures" / "tdh" / "etw1_kernel_process_pimg_v1.golden"
    if not golden.is_file():
        print(f"FAIL: missing {golden}", file=sys.stderr)
        return 1
    raw = golden.read_bytes()
    if raw.startswith(b"\xef\xbb\xbf"):
        print("FAIL: golden must be UTF-8 without BOM", file=sys.stderr)
        return 1
    h = hashlib.sha256(raw).hexdigest()
    if h != EXPECTED_SHA256:
        print(
            f"FAIL: sha256 mismatch\n  got      {h}\n  expected {EXPECTED_SHA256}\n"
            f"  (update EXPECTED after intentional change to {golden.name})",
            file=sys.stderr,
        )
        return 1
    if not raw.startswith(b"ETW1\n"):
        print("FAIL: must start with ETW1 + newline (slot text contract)", file=sys.stderr)
        return 1
    if b"pimg=" not in raw or b"img=" not in raw:
        print("FAIL: sample must include img= and pimg= (parent/child) lines", file=sys.stderr)
        return 1
    print(f"OK: ETW1 payload golden {golden.name} sha256 {h}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
