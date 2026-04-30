#!/usr/bin/env python3
"""
将 P0 规则 JSON 用 AES-256-GCM 加密，输出 .enc 文件。
与 edr-agent 内 encrypt_p0_rules.c 的解密逻辑配对使用。

用法:
  python3 scripts/encrypt_p0_rules.py --input p0_rule_bundle_ir_v1.json --output p0_rule_bundle_ir_v1.json.enc
  python3 scripts/encrypt_p0_rules.py --input p0_rule_bundle_ir_v1.json --output -   (stdout)

格式 (EDR1):
  4 bytes   MAGIC  "EDR1"
  12 bytes  NONCE  (random, 96-bit)
  n bytes   CIPHERTEXT  (AES-256-GCM)
  16 bytes  TAG   (GCM authentication tag)

密钥: HKDF-SHA256(seed, salt="edr-p0-rule-v1", info="aes-256-gcm-rule", len=32)
seed 为固定 32 字节（与 C 端 encrypt_p0_rules.c 中一致）。
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import os
import pathlib
import struct
import sys

MAGIC = b"EDR1"
SEED = bytes([
    0x7f, 0xe1, 0x4a, 0xd2, 0x91, 0x3b, 0x88, 0x5c,
    0x2d, 0xf6, 0x0e, 0x73, 0xa9, 0x44, 0xcb, 0x1f,
    0x68, 0x35, 0xd7, 0x0b, 0xea, 0x52, 0x99, 0x7d,
    0x1c, 0x4e, 0xb8, 0x30, 0xf2, 0x65, 0xa1, 0x8e,
])
HKDF_SALT = b"edr-p0-rule-v1"
HKDF_INFO = b"aes-256-gcm-rule"
KEY_LEN = 32
NONCE_LEN = 12
TAG_LEN = 16


def hkdf_sha256(salt: bytes, ikm: bytes, info: bytes, length: int) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    result = b""
    counter = 1
    while len(result) < length:
        t = hmac.new(prk, result + info + bytes([counter]), hashlib.sha256).digest()
        result += t
        counter += 1
    return result[:length]


def aes_256_gcm_encrypt(plaintext: bytes, key: bytes) -> bytes:
    if len(key) != KEY_LEN:
        raise ValueError(f"key must be {KEY_LEN} bytes")
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = os.urandom(NONCE_LEN)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    tagged = ciphertext  # AESGCM already appends 16B tag
    return MAGIC + nonce + tagged


def main() -> int:
    ap = argparse.ArgumentParser(description="encrypt P0 rule bundle JSON -> EDR1 format")
    ap.add_argument("--input", type=pathlib.Path, required=True)
    ap.add_argument("--output", type=str, required=True)
    ap.add_argument("--no-crypto-check", action="store_true",
                    help="skip cryptography package check (CI/offline)")
    args = ap.parse_args()

    if not args.no_crypto_check:
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: F811
        except ImportError:
            print("ERROR: 'cryptography' package required. pip install cryptography", file=sys.stderr)
            print("  or use --no-crypto-check if you're in a build environment with it pre-installed",
                  file=sys.stderr)
            return 1

    data = args.input.read_bytes()
    if len(data) > 4 * 1024 * 1024:
        print("ERROR: input too large (>4 MiB)", file=sys.stderr)
        return 2

    key = hkdf_sha256(HKDF_SALT, SEED, HKDF_INFO, KEY_LEN)
    encrypted = aes_256_gcm_encrypt(data, key)

    if args.output == "-":
        sys.stdout.buffer.write(encrypted)
    else:
        out_path = pathlib.Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(encrypted)
        print(f"encrypted: {len(encrypted)} bytes -> {out_path}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
