#!/usr/bin/env python3
"""
Apply five structural deformations to a *local lab-only* raw shellcode file.
Output: <out_dir>/lab_v00.bin … lab_v04.bin — DO NOT commit outputs if they
originate from third-party malware.

Transforms (evaluation-oriented, not polymorphic packers):
  v00 identity
  v01 single-byte XOR 0x5A
  v02 prepend 64-byte pseudo-random high-entropy prefix
  v03 append 128-byte 0x90 sled
  v04 duplicate payload twice (2x concatenation)
"""

from __future__ import annotations

import argparse
import os
import struct


def prng_bytes(n: int, seed: int = 0xC0FFEE) -> bytes:
    out = bytearray(n)
    x = seed & 0xFFFFFFFF
    for i in range(n):
        x = (1103515245 * x + 12345) & 0x7FFFFFFF
        out[i] = x & 0xFF
    return bytes(out)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("input", help="Path to raw shellcode bytes (lab only)")
    ap.add_argument("out_dir", help="Output directory (must exist or will be created)")
    args = ap.parse_args()
    with open(args.input, "rb") as f:
        raw = f.read()
    if len(raw) == 0 or len(raw) > 4 * 1024 * 1024:
        raise SystemExit("refuse empty or >4MiB input")
    os.makedirs(args.out_dir, exist_ok=True)
    v0 = raw
    v1 = bytes(b ^ 0x5A for b in raw)
    v2 = prng_bytes(64) + raw
    v3 = raw + bytes([0x90]) * 128
    v4 = raw + raw
    for i, blob in enumerate((v0, v1, v2, v3, v4)):
        p = os.path.join(args.out_dir, f"lab_v{i:02d}.bin")
        with open(p, "wb") as wf:
            wf.write(blob)
        print("wrote", p, "len", len(blob))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
