#!/usr/bin/env python3
# A2.3：核对进程正文、独立身份及文件字段别名的完整顺序。
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


def _check_orders(root: Path) -> dict[str, int]:
    c_file = root / "src" / "collector" / "etw_tdh_win.c"
    src = c_file.read_text(encoding="utf-8")
    fx_dir = root / "fixtures" / "tdh"
    counts = {}
    for name, fixture in (
        ("proc_try", "kernel_process_prop_try_v1.txt"),
        ("proc_identity_try", "kernel_process_identity_try_v1.txt"),
        ("file_try", "kernel_file_prop_try_v1.txt"),
    ):
        actual = _parse_c_wstr_array(src, name)
        expected = _load_fixture(fx_dir / fixture)
        if actual != expected:
            difference = next(
                (f"first diff at [{i}]: C={a!r} fixture={b!r}"
                 for i, (a, b) in enumerate(zip(actual, expected)) if a != b),
                f"length C={len(actual)} fixture={len(expected)}",
            )
            raise ValueError(f"{name} order differs from {fixture}: {difference}")
        counts[name] = len(actual)
    return counts


def main() -> int:
    try:
        counts = _check_orders(Path(__file__).resolve().parent.parent)
    except (OSError, ValueError) as error:
        print("FAIL:", error, file=sys.stderr)
        return 1
    print("OK: TDH EdrPropTry order matches fixtures", counts)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
