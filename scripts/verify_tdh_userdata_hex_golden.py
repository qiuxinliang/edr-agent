#!/usr/bin/env python3
"""
A2.3 / P3：对 **UserData 原始字节** 做十六进制金体与 SHA-256 锚定（**可选** 门闩，与 ETW1 文本金体并列）。

- 不依赖 Windows / Tdh*；在任意 OS 上可跑，与 precheck 同机。
- 多份 `fixtures/tdh/userdata_*.hex`；**有意**改内容后须更新下表 EXPECTED。

用法: python3 edr-agent/scripts/verify_tdh_userdata_hex_golden.py
"""

from __future__ import annotations

import hashlib
import re
import sys
from pathlib import Path
from typing import List, Tuple

# (fixtures/tdh/relative_name, expected_sha256)
GOLDEN_USERDATA: List[Tuple[str, str]] = [
    ("userdata_synth_p3_v1.hex", "630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd"),
    ("userdata_medium_p3_v2.hex", "471fb943aa23c511f6f72f8d1652d9c880cfa392ad80503120547703e56a2be5"),
]

_HEX_BYTE = re.compile(r"\b[0-9A-Fa-f]{2}\b")


def _root() -> Path:
    return Path(__file__).resolve().parent.parent


def _parse_userdata_hex_text(raw: str) -> bytes:
    out: bytearray = bytearray()
    for line in raw.splitlines():
        cut = line.split("#", 1)[0].strip()
        if not cut:
            continue
        for m in _HEX_BYTE.finditer(cut):
            out.append(int(m.group(0), 16))
    return bytes(out)


def _verify_one(rel: str, want_sha: str) -> int:
    fixture = _root() / "fixtures" / "tdh" / rel
    if not fixture.is_file():
        print(f"FAIL: missing {fixture}", file=sys.stderr)
        return 1
    text = fixture.read_text(encoding="utf-8")
    if text.startswith("\ufeff"):
        print(f"FAIL: {rel} must be UTF-8 without BOM", file=sys.stderr)
        return 1
    data = _parse_userdata_hex_text(text)
    if not data:
        print(f"FAIL: no hex bytes parsed in {rel}", file=sys.stderr)
        return 1
    h = hashlib.sha256(data).hexdigest()
    if h != want_sha:
        print(
            f"FAIL: {rel} sha256 mismatch\n  got      {h}\n  expected {want_sha}\n"
            f"  (intentional change: update GOLDEN_USERDATA in {Path(__file__).name})",
            file=sys.stderr,
        )
        return 1
    print(f"OK: UserData hex golden {rel} len={len(data)} sha256={h}")
    return 0


def main() -> int:
    for rel, want in GOLDEN_USERDATA:
        if (rc := _verify_one(rel, want)) != 0:
            return rc
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
