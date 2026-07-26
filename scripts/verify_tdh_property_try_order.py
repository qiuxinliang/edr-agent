#!/usr/bin/env python3
# A2.3：回归 edr_tdh_win.c 中 `proc_try`（及可选 `file_try`）与 fixtures 一致，防无意中重排小表。
# 无需 Windows / TDH 运行时。仓库根：python3 edr-agent/scripts/verify_tdh_property_try_order.py
from __future__ import annotations

import re
import sys
from pathlib import Path


def _parse_c_wstr_array(src: str, name: str) -> list[str]:
    """Extract ordered L"..." string literals from `static const EdrPropTry name[] = { ... };`."""
    m = re.search(
        r"static\s+const\s+EdrPropTry\s+"
        + re.escape(name)
        + r"\s*\[\s*\]\s*=\s*\{",
        src,
    )
    if not m:
        raise ValueError(f"array {name} not found")
    i = m.end()
    depth = 1
    buf = []
    while i < len(src) and depth > 0:
        ch = src[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                break
        buf.append(ch)
        i += 1
    body = "".join(buf)
    out: list[str] = []
    for wm in re.finditer(r'L"([^"]*)"', body):
        s = wm.group(1)
        if s:  # skip empty, though C rarely has
            out.append(s)
    if not out:
        raise ValueError(f"no L\"...\" entries in {name}")
    return out


def _load_fixture(path: Path) -> list[str]:
    lines: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        lines.append(s)
    if not lines:
        raise ValueError("empty fixture after stripping comments")
    return lines


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    c_file = root / "src" / "collector" / "etw_tdh_win.c"
    if not c_file.is_file():
        print("FAIL: missing", c_file, file=sys.stderr)
        return 1
    src = c_file.read_text(encoding="utf-8")
    fx_dir = root / "fixtures" / "tdh"
    try:
        proc_c = _parse_c_wstr_array(src, "proc_try")
    except ValueError as e:
        print("FAIL: parse C:", e, file=sys.stderr)
        return 1
    f_proc = fx_dir / "kernel_process_prop_try_v1.txt"
    if f_proc.is_file():
        want = _load_fixture(f_proc)
        if proc_c != want:
            print("FAIL: proc_try order differs from fixture", f_proc, file=sys.stderr)
            for i, (a, b) in enumerate(zip(proc_c, want)):
                if a != b:
                    print(f"  first diff at [{i}]: C={a!r} fixture={b!r}", file=sys.stderr)
                    break
            else:
                n = min(len(proc_c), len(want))
                if len(proc_c) != len(want):
                    print(
                        f"  length C={len(proc_c)} fixture={len(want)} (cmp first {n})",
                        file=sys.stderr,
                    )
            return 1
    else:
        print("WARN: no fixture, skip proc_try check:", f_proc, file=sys.stderr)
    try:
        file_c = _parse_c_wstr_array(src, "file_try")
    except ValueError as e:
        print("FAIL: parse C file_try:", e, file=sys.stderr)
        return 1
    f_file = fx_dir / "kernel_file_prop_try_v1.txt"
    if f_file.is_file():
        want_f = _load_fixture(f_file)
        if file_c != want_f:
            print("FAIL: file_try order differs from", f_file, file=sys.stderr)
            return 1
    print("OK: TDH EdrPropTry order matches fixtures (proc", len(proc_c), "file", len(file_c), ")")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
