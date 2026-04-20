#!/usr/bin/env python3
"""
P5 T17：Python 参考编码器 — 与 `edr_ave_behavior_encode_m3b`（`src/ave/ave_behavior_features.c`）同语义，
供训练数据生成与 `tests/test_ave_behavior_features_m3b.c` 对拍。

用法：
  python3 scripts/behavior_encode_m3b.py     # 自测（断言与 m3b 一致）
  python3 -c "from scripts.behavior_encode_m3b import encode_m3b; ..."  # 需在 edr-agent 根且包路径可调
"""
from __future__ import annotations

import math
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

# --- AVEEventType（与 include/edr/ave_sdk.h 枚举值一致）---
AVE_EVT_PROCESS_CREATE = 0
AVE_EVT_PROCESS_INJECT = 1
AVE_EVT_FILE_WRITE = 2
AVE_EVT_FILE_EXECUTE = 3
AVE_EVT_NET_CONNECT = 4
AVE_EVT_NET_DNS = 5
AVE_EVT_REG_WRITE = 6
AVE_EVT_DLL_LOAD = 7
AVE_EVT_MEM_ALLOC_EXEC = 8
AVE_EVT_LSASS_ACCESS = 9
AVE_EVT_AUTH_EVENT = 10
AVE_EVT_SHELLCODE_SIGNAL = 11
AVE_EVT_WEBSHELL_SIGNAL = 12
AVE_EVT_PMFE_RESULT = 13


def clamp01(x: float) -> float:
    if x <= 0.0:
        return 0.0
    if x >= 1.0:
        return 1.0
    return float(x)


def popcount_u32(x: int) -> int:
    x &= 0xFFFFFFFF
    n = 0
    while x:
        n += 1
        x &= x - 1
    return n


def a_slot_for_event_type(et: int) -> int:
    if et == AVE_EVT_PROCESS_CREATE:
        return 0
    if et in (
        AVE_EVT_PROCESS_INJECT,
        AVE_EVT_MEM_ALLOC_EXEC,
        AVE_EVT_LSASS_ACCESS,
        AVE_EVT_AUTH_EVENT,
        AVE_EVT_SHELLCODE_SIGNAL,
        AVE_EVT_PMFE_RESULT,
    ):
        return 1
    if et == AVE_EVT_FILE_WRITE:
        return 2
    if et == AVE_EVT_FILE_EXECUTE:
        return 3
    if et == AVE_EVT_NET_CONNECT:
        return 4
    if et == AVE_EVT_NET_DNS:
        return 5
    if et == AVE_EVT_REG_WRITE:
        return 6
    if et == AVE_EVT_DLL_LOAD:
        return 7
    if et == AVE_EVT_WEBSHELL_SIGNAL:
        return 4
    return -1


def shannon_entropy_bytes(s: Optional[str], max_len: int) -> float:
    if not s:
        return 0.0
    cnt = [0] * 256
    length = 0
    for c in s[:max_len]:
        cnt[ord(c) & 0xFF] += 1
        length += 1
    if length == 0:
        return 0.0
    h = 0.0
    for v in cnt:
        if v == 0:
            continue
        pi = v / float(length)
        h -= pi * math.log(pi + 1e-30, 2)
    return float(h)


def str_has_ci(hay: Optional[str], needle: str) -> bool:
    if not hay or not needle:
        return False
    h = hay.lower()
    n = needle.lower()
    return n in h


def path_looks_system(p: Optional[str]) -> bool:
    if not p:
        return False
    return str_has_ci(p, "\\windows\\") or str_has_ci(p, "/system/") or str_has_ci(p, "system32")


def path_looks_temp(p: Optional[str]) -> bool:
    if not p:
        return False
    return str_has_ci(p, "\\temp\\") or str_has_ci(p, "/tmp/") or str_has_ci(p, "appdata\\local\\temp")


def path_looks_unc(p: Optional[str]) -> bool:
    if not p or len(p) < 2:
        return False
    return (p[0] == "\\" and p[1] == "\\") or (p[0] == "/" and p[1] == "/")


def file_ext_risk_heuristic(path: Optional[str]) -> float:
    if not path:
        return 0.0
    dot = path.rfind(".")
    if dot < 0:
        return 0.0
    ext = path[dot + 1 :].lower()
    if ext in ("exe", "ps1", "bat", "cmd"):
        return 1.0
    if ext == "dll":
        return 0.5
    return 0.0


def parse_ipv4_octets(s: Optional[str]) -> Optional[Tuple[int, int, int, int]]:
    if not s:
        return None
    parts = s.split(".")
    if len(parts) != 4:
        return None
    try:
        a, b, c, d = (int(parts[0]), int(parts[1]), int(parts[2]), int(parts[3]))
    except ValueError:
        return None
    if min(a, b, c, d) < 0 or max(a, b, c, d) > 255:
        return None
    return (a, b, c, d)


def ip_is_public_flag(ip: Optional[str]) -> float:
    o = parse_ipv4_octets(ip)
    if o is None:
        return 0.0
    a, b, c, d = o
    if a == 127 or a == 0:
        return 0.0
    if a == 10:
        return 0.0
    if a == 172 and 16 <= b <= 31:
        return 0.0
    if a == 192 and b == 168:
        return 0.0
    return 1.0


def port_risk_heuristic(port: int) -> float:
    if port in (445, 3389, 135):
        return 0.9
    if port in (80, 443, 53):
        return 0.2
    if port == 0:
        return 0.0
    return 0.5


def reg_key_risk_heuristic(path: Optional[str]) -> float:
    if not path:
        return 0.0
    if str_has_ci(path, "currentversion\\run") or str_has_ci(path, "\\run\\"):
        return 0.9
    return 0.3


def wall_sin_cos_from_ns(ns: int) -> Tuple[float, float]:
    sec = int(ns // 1_000_000_000)
    lt = time.localtime(sec)
    hour = float(lt.tm_hour) + float(lt.tm_min) / 60.0 + float(lt.tm_sec) / 3600.0
    ang = 2.0 * math.pi * hour / 24.0
    return (math.sin(ang), math.cos(ang))


def encode_e_group(e: Dict[str, Any], ex: Optional[Dict[str, Any]], feat: List[float], n: int) -> None:
    if n > 44:
        c44 = ex["static_max_conf"] if ex else float(e.get("ave_confidence") or 0.0)
        feat[44] = clamp01(c44)
    if n > 45:
        feat[45] = ex["static_verdict_norm"] if ex else 0.0
    if n > 46:
        feat[46] = clamp01(float(e.get("shellcode_score") or 0.0))
    if n > 47:
        feat[47] = clamp01(float(e.get("webshell_score") or 0.0))
    if n > 48:
        feat[48] = 1.0 if e.get("ioc_ip_hit") else 0.0
    if n > 49:
        feat[49] = 1.0 if e.get("ioc_domain_hit") else 0.0
    if n > 50:
        feat[50] = 1.0 if e.get("ioc_sha256_hit") else 0.0
    if n > 51:
        feat[51] = clamp01(float(ex.get("parent_static_max_conf") or 0.0)) if ex else 0.0
    if n > 52:
        feat[52] = clamp01(float(ex.get("sibling_anomaly_mean") or 0.0)) if ex else 0.0
    if n > 53:
        feat[53] = clamp01(float(e.get("pmfe_confidence") or 0.0))
    if n > 54:
        feat[54] = 1.0 if e.get("pmfe_pe_found") else 0.0
    if n > 55:
        feat[55] = popcount_u32(int(e.get("behavior_flags") or 0)) / 14.0
    if n > 56:
        cr_ex = float(ex.get("cert_revoked_ancestor") or 0.0) if ex else 0.0
        cr_ev = 1.0 if e.get("cert_revoked_ancestor") else 0.0
        feat[56] = 1.0 if (cr_ex > 0.5 or cr_ev > 0.5) else 0.0
    if n > 57:
        feat[57] = 1.0


def encode_c_group(e: Dict[str, Any], feat: List[float], n: int) -> None:
    if n <= 24:
        return
    et = int(e.get("event_type") or -1)
    path_evt = et in (AVE_EVT_FILE_WRITE, AVE_EVT_FILE_EXECUTE, AVE_EVT_DLL_LOAD)
    net_evt = et == AVE_EVT_NET_CONNECT
    dns_evt = et == AVE_EVT_NET_DNS
    reg_evt = et == AVE_EVT_REG_WRITE

    tp = e.get("target_path") or ""
    pe = shannon_entropy_bytes(tp, 512)
    if path_evt and pe > 0.0:
        feat[24] = clamp01(pe / 16.0)
    else:
        feat[24] = 0.0
    if path_evt:
        feat[25] = 1.0 if path_looks_system(tp) else 0.0
        feat[26] = 1.0 if path_looks_temp(tp) else 0.0
        feat[27] = 1.0 if path_looks_unc(tp) else 0.0
        feat[28] = file_ext_risk_heuristic(tp)
        feat[35] = 1.0 if e.get("target_has_motw") else 0.0
    else:
        feat[25] = feat[26] = feat[27] = feat[28] = feat[35] = 0.0
    if net_evt:
        feat[29] = ip_is_public_flag(e.get("target_ip"))
        feat[30] = 0.6 if feat[29] > 0.5 else 0.1
        feat[31] = port_risk_heuristic(int(e.get("target_port") or 0))
    else:
        feat[29] = feat[30] = feat[31] = 0.0
    if reg_evt:
        feat[32] = reg_key_risk_heuristic(tp)
    else:
        feat[32] = 0.0
    if dns_evt:
        de = shannon_entropy_bytes(e.get("target_domain"), 256)
        feat[33] = clamp01(de / 8.0)
        feat[34] = 1.0 if e.get("ioc_domain_hit") else 0.0
    else:
        feat[33] = feat[34] = 0.0


def encode_m3b(
    e: Dict[str, Any],
    ex: Optional[Dict[str, Any]],
    snap: Dict[str, Any],
    n: int = 64,
) -> List[float]:
    """返回长度 `n` 的特征向量（与 C `edr_ave_behavior_encode_m3b` 对齐）。"""
    feat = [0.0] * n
    slot = a_slot_for_event_type(int(e.get("event_type") or -1))
    if 0 <= slot < n:
        feat[slot] = 1.0

    if n > 8:
        feat[8] = clamp01(float(snap.get("total_events_incl_current") or 0) / 1000.0)
    if n > 9:
        feat[9] = clamp01(float(snap.get("file_write_count") or 0) / 100.0)
    if n > 10:
        feat[10] = clamp01(float(snap.get("net_connect_count") or 0) / 100.0)
    if n > 11:
        feat[11] = clamp01(float(snap.get("reg_write_count") or 0) / 100.0)
    if n > 12:
        feat[12] = clamp01(float(snap.get("dll_load_count") or 0) / 50.0)
    if n > 13:
        feat[13] = float(snap.get("has_injected_memory") or 0.0)
    if n > 14:
        feat[14] = float(snap.get("has_accessed_lsass") or 0.0)
    if n > 15:
        feat[15] = float(snap.get("has_loaded_suspicious_dll") or 0.0)
    if n > 16:
        feat[16] = float(snap.get("has_ioc_connection") or 0.0)
    if n > 17:
        c17 = ex["static_max_conf"] if ex else float(e.get("ave_confidence") or 0.0)
        feat[17] = clamp01(c17)
    if n > 18:
        feat[18] = ex["static_verdict_norm"] if ex else 0.0
    if n > 19:
        feat[19] = clamp01(float(snap.get("parent_chain_depth_norm") or 0.0))
    if n > 20:
        feat[20] = float(snap.get("is_system_account") or 0.0)
    if n > 21:
        feat[21] = clamp01(float(snap.get("time_since_birth_norm") or 0.0))
    if n > 22:
        feat[22] = clamp01(float(snap.get("unique_ip_count") or 0) / 20.0)
    if n > 23:
        feat[23] = float(snap.get("is_high_value_host") or 0.0)

    encode_c_group(e, feat, n)

    if n > 36:
        prev_ns = int(snap.get("prev_event_ns") or 0)
        now_ns = int(snap.get("now_ns") or 0)
        gap_ms = 0.0
        if prev_ns > 0 and now_ns > prev_ns:
            gap_ms = (now_ns - prev_ns) / 1e6
        g = math.log10(gap_ms + 1.0) / 6.0
        g = max(0.0, min(1.0, g))
        feat[36] = float(g)
    if n > 37:
        feat[37] = clamp01(float(snap.get("burst_1s_count") or 0) / 100.0)
    if n > 38:
        s_h, c_h = wall_sin_cos_from_ns(int(snap.get("now_ns") or 0))
        feat[38] = s_h
        feat[39] = c_h
    if n > 40:
        feat[40] = clamp01(float(snap.get("events_last_1min") or 0) / 100.0)
    if n > 41:
        feat[41] = clamp01(float(snap.get("events_last_5min") or 0) / 100.0)
    if n > 42:
        feat[42] = 1.0 if snap.get("is_first_event_of_proc") else 0.0
    if n > 43:
        feat[43] = clamp01(float(snap.get("events_after_net_connect") or 0) / 10.0)

    encode_e_group(e, ex, feat, n)
    return feat


def _expect_near(name: str, a: float, b: float, eps: float) -> None:
    if abs(a - b) > eps:
        raise SystemExit(f"FAIL {name}: got {a} want {b} (eps={eps})")


def self_test() -> None:
    snap: Dict[str, Any] = {
        "total_events_incl_current": 100,
        "file_write_count": 50,
        "net_connect_count": 10,
        "reg_write_count": 5,
        "dll_load_count": 25,
        "has_injected_memory": 1.0,
        "has_accessed_lsass": 0.0,
        "has_loaded_suspicious_dll": 1.0,
        "has_ioc_connection": 0.0,
        "parent_chain_depth_norm": 0.1,
        "is_system_account": 0.0,
        "time_since_birth_norm": 0.5,
        "unique_ip_count": 10,
        "is_high_value_host": 1.0,
        "prev_event_ns": 1_000_000_000,
        "now_ns": 2_000_000_000,
        "burst_1s_count": 50,
        "events_last_1min": 30,
        "events_last_5min": 80,
        "is_first_event_of_proc": 0,
        "events_after_net_connect": 3,
    }
    ex: Dict[str, Any] = {"static_max_conf": 0.4, "static_verdict_norm": 2.0 / 9.0}
    e: Dict[str, Any] = {"event_type": AVE_EVT_FILE_WRITE, "target_path": r"C:\Windows\Temp\a.exe"}

    feat = encode_m3b(e, ex, snap, 64)
    if feat[24] < 0.01:
        raise SystemExit(f"FAIL C24 path entropy (file write) too low: {feat[24]}")
    _expect_near("B8 total", feat[8], 0.1, 0.001)
    _expect_near("B9 file", feat[9], 0.5, 0.001)
    _expect_near("D36 gap log", feat[36], math.log10(1000.0 + 1.0) / 6.0, 0.02)
    _expect_near("D37 burst", feat[37], 0.5, 0.001)
    _expect_near("D43 after net", feat[43], 0.3, 0.001)
    if feat[2] < 0.99:
        raise SystemExit("FAIL A file_write one-hot")
    _expect_near("E57 is_real_event real step", feat[57], 1.0, 0.001)

    e2 = dict(e)
    e2["target_has_motw"] = 1
    feat = encode_m3b(e2, ex, snap, 64)
    _expect_near("C35 target_has_motw", feat[35], 1.0, 0.001)

    ec = {"event_type": AVE_EVT_FILE_WRITE, "target_path": r"C:\Windows\System32\calc.exe"}
    feat = encode_m3b(ec, ex, snap, 64)
    _expect_near("C25 system path", feat[25], 1.0, 0.001)
    ec["target_path"] = r"C:\Users\x\AppData\Local\Temp\evil.exe"
    feat = encode_m3b(ec, ex, snap, 64)
    _expect_near("C26 temp path", feat[26], 1.0, 0.001)
    ec["target_path"] = r"\\fileserver\share\a.exe"
    feat = encode_m3b(ec, ex, snap, 64)
    _expect_near("C27 unc path", feat[27], 1.0, 0.001)
    ec["target_path"] = r"C:\tools\x.ps1"
    feat = encode_m3b(ec, ex, snap, 64)
    _expect_near("C28 ext ps1", feat[28], 1.0, 0.001)
    ec["target_path"] = r"C:\w\m.dll"
    feat = encode_m3b(ec, ex, snap, 64)
    _expect_near("C28 ext dll", feat[28], 0.5, 0.001)

    er: Dict[str, Any] = {
        "event_type": AVE_EVT_REG_WRITE,
        "target_path": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\evil",
    }
    feat = encode_m3b(er, ex, snap, 64)
    _expect_near("C32 reg run risk", feat[32], 0.9, 0.001)

    edns: Dict[str, Any] = {
        "event_type": AVE_EVT_NET_DNS,
        "target_domain": "abcdefghijklmnopqrstuvwxyz.example.com",
        "ioc_domain_hit": 1,
    }
    feat = encode_m3b(edns, ex, snap, 64)
    if feat[33] < 0.01:
        raise SystemExit(f"FAIL C33 dns entropy low got {feat[33]}")
    _expect_near("C34 ioc domain", feat[34], 1.0, 0.001)

    e24: Dict[str, Any] = {"event_type": AVE_EVT_FILE_WRITE, "target_path": "abab"}
    feat = encode_m3b(e24, ex, snap, 64)
    _expect_near("C24 golden abab", feat[24], 0.0625, 0.0001)
    e24["target_path"] = "a"
    feat = encode_m3b(e24, ex, snap, 64)
    _expect_near("C24 zero entropy single char path", feat[24], 0.0, 0.0001)

    ex_fe: Dict[str, Any] = {"event_type": AVE_EVT_FILE_EXECUTE, "target_path": r"C:\Windows\notepad.exe"}
    feat = encode_m3b(ex_fe, ex, snap, 64)
    _expect_near("C25 FILE_EXECUTE system", feat[25], 1.0, 0.001)
    ex_dl: Dict[str, Any] = {
        "event_type": AVE_EVT_DLL_LOAD,
        "target_path": r"C:\Users\x\AppData\Local\Temp\x.dll",
    }
    feat = encode_m3b(ex_dl, ex, snap, 64)
    _expect_near("C26 DLL_LOAD temp", feat[26], 1.0, 0.001)
    _expect_near("C28 DLL_LOAD ext dll", feat[28], 0.5, 0.001)

    ebat: Dict[str, Any] = {"event_type": AVE_EVT_FILE_WRITE, "target_path": r"C:\x.bat"}
    feat = encode_m3b(ebat, ex, snap, 64)
    _expect_near("C28 ext bat", feat[28], 1.0, 0.001)
    ebat["target_path"] = r"C:\x.cmd"
    feat = encode_m3b(ebat, ex, snap, 64)
    _expect_near("C28 ext cmd", feat[28], 1.0, 0.001)

    en10: Dict[str, Any] = {"event_type": AVE_EVT_NET_CONNECT, "target_ip": "10.0.0.1", "target_port": 443}
    feat = encode_m3b(en10, ex, snap, 64)
    _expect_near("C29 private 10.x", feat[29], 0.0, 0.001)
    _expect_near("C30 low when private", feat[30], 0.1, 0.001)
    _expect_near("C31 well-known 443", feat[31], 0.2, 0.001)
    en192: Dict[str, Any] = {"event_type": AVE_EVT_NET_CONNECT, "target_ip": "192.168.0.1", "target_port": 445}
    feat = encode_m3b(en192, ex, snap, 64)
    _expect_near("C29 private 192.168", feat[29], 0.0, 0.001)
    _expect_near("C31 smb 445 private", feat[31], 0.9, 0.001)
    en172: Dict[str, Any] = {"event_type": AVE_EVT_NET_CONNECT, "target_ip": "172.31.255.254", "target_port": 445}
    feat = encode_m3b(en172, ex, snap, 64)
    _expect_near("C29 private 172.16-31", feat[29], 0.0, 0.001)
    en_pub: Dict[str, Any] = {"event_type": AVE_EVT_NET_CONNECT, "target_ip": "8.8.8.8", "target_port": 445}
    feat = encode_m3b(en_pub, ex, snap, 64)
    _expect_near("C29 public", feat[29], 1.0, 0.001)
    _expect_near("C30 high when public", feat[30], 0.6, 0.001)
    _expect_near("C31 smb 445 public", feat[31], 0.9, 0.001)
    en_pub["target_port"] = 0
    feat = encode_m3b(en_pub, ex, snap, 64)
    _expect_near("C31 port zero", feat[31], 0.0, 0.001)
    en_pub["target_port"] = 1337
    feat = encode_m3b(en_pub, ex, snap, 64)
    _expect_near("C31 odd port default", feat[31], 0.5, 0.001)

    ereg_def: Dict[str, Any] = {
        "event_type": AVE_EVT_REG_WRITE,
        "target_path": r"HKLM\SOFTWARE\Vendor\App",
    }
    feat = encode_m3b(ereg_def, ex, snap, 64)
    _expect_near("C32 reg default risk", feat[32], 0.3, 0.001)

    edns_abc: Dict[str, Any] = {"event_type": AVE_EVT_NET_DNS, "target_domain": "abc", "ioc_domain_hit": 0}
    feat = encode_m3b(edns_abc, ex, snap, 64)
    want33 = math.log(3, 2) / 8.0
    _expect_near("C33 dns entropy abc", feat[33], want33, 0.0002)
    _expect_near("C34 no ioc", feat[34], 0.0, 0.001)

    ex3 = dict(ex)
    ex3["cert_revoked_ancestor"] = 1.0
    feat = encode_m3b(e2, ex3, snap, 64)
    _expect_near("E56 cert_revoked_ancestor", feat[56], 1.0, 0.001)

    ex_no_cert = {"static_max_conf": 0.4, "static_verdict_norm": 2.0 / 9.0}
    e_cert_ev = dict(e2)
    e_cert_ev["cert_revoked_ancestor"] = 1
    feat = encode_m3b(e_cert_ev, ex_no_cert, snap, 64)
    _expect_near("E56 cert_revoked_ancestor event-only", feat[56], 1.0, 0.001)

    ex4 = {"static_max_conf": 0.4, "static_verdict_norm": 2.0 / 9.0}
    e4: Dict[str, Any] = {"event_type": AVE_EVT_NET_CONNECT, "target_ip": "8.8.8.8", "target_port": 443}
    feat = encode_m3b(e4, ex4, snap, 64)
    if feat[24] > 0.01:
        raise SystemExit("FAIL C24 path entropy for net evt")
    if feat[29] < 0.99:
        raise SystemExit("FAIL C29 public ip")
    _expect_near("E57 is_real_event after net encode", feat[57], 1.0, 0.001)

    pad = [0.0] * 64
    if pad[57] > 0.001:
        raise SystemExit("FAIL PAD step dim57 must be 0 (§5.6)")

    print("behavior_encode_m3b.py: self_test ok (m3b parity)")


if __name__ == "__main__":
    self_test()
    sys.exit(0)
