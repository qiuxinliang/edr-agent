#!/usr/bin/env python3
# 从 edr-backend/platform/config/p0_golden_vectors.json 生成
#   edr-agent/src/preprocess/p0_golden_vectors_data.inc
# 与 validate_p0_golden_vectors.py 共用同一母版。仓库根下：
#   python3 edr-agent/scripts/gen_p0_golden_vectors_inc.py
#   python3 edr-agent/scripts/gen_p0_golden_vectors_inc.py --check  # 无改动则 0
import argparse
import json
import os
import re
import sys
from typing import Any, List


def c_string_escape(s: str) -> str:
    out: List[str] = []
    for ch in s:
        o = ord(ch)
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif 32 <= o < 127:
            out.append(ch)
        else:
            out.append(f"\\x{o:02x}")
    return "".join(out)


def load_cases(path: str) -> List[Any]:
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    return data.get("cases") or []


def c_embed_cases(all_cases: List[Any]) -> List[Any]:
    """仅 process_create 写入 .inc，供 C 的 edr_p0_rule_matches 对拍（非 PC 用 edr_p0_ir_record_golden_test）。"""
    out: List[Any] = []
    for c in all_cases:
        ev = c.get("ev") or {}
        et = (ev.get("event_type") or "process_create").strip()
        if et == "process_create":
            out.append(c)
    return out


def render_inc(cases: List[Any]) -> str:
    lines = [
        "/* 由 edr-agent/scripts/gen_p0_golden_vectors_inc.py 自 p0_golden_vectors.json 生成，勿手改。 */",
        "#ifndef P0_GOLDEN_VECTORS_DATA_INC",
        "#define P0_GOLDEN_VECTORS_DATA_INC",
        f"#define P0_GOLDEN_N {len(cases)}",
    ]
    if not cases:
        lines += ["#endif", ""]
        return "\n".join(lines)

    for i, c in enumerate(cases):
        rid = c.get("rule_id", "")
        exp = 1 if c.get("expect_hit") else 0
        ev = c.get("ev") or {}
        pn = str(ev.get("process_name", "") or "")
        cmd = str(ev.get("cmdline", "") or "")
        if not re.match(r"^R-[-A-Z0-9]+$", rid):
            print(f"bad rule_id at {i}", file=sys.stderr)
            raise SystemExit(1)
        lines.append(f'static const char p0_gv_r{i}[] = "{c_string_escape(rid)}";')
        lines.append(f'static const char p0_gv_p{i}[] = "{c_string_escape(pn)}";')
        lines.append(f'static const char p0_gv_c{i}[] = "{c_string_escape(cmd)}";')
        lines.append(f"static const int p0_gv_e{i} = {exp};")

    lines.append("static const char *p0_golden_rule_id[] = {")
    lines.append(", ".join(f"p0_gv_r{i}" for i in range(len(cases))) + ", };")
    lines.append("static const char *p0_golden_process_name[] = {")
    lines.append(", ".join(f"p0_gv_p{i}" for i in range(len(cases))) + ", };")
    lines.append("static const char *p0_golden_cmdline[] = {")
    lines.append(", ".join(f"p0_gv_c{i}" for i in range(len(cases))) + ", };")
    lines.append("static const int p0_golden_expect[] = {")
    lines.append(", ".join(f"p0_gv_e{i}" for i in range(len(cases))) + ", };")
    lines.append("#endif")
    lines.append("")
    return "\n".join(lines) + "\n"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--repo-root",
        default=os.path.abspath(
            os.path.join(os.path.dirname(__file__), os.pardir, os.pardir)
        ),
    )
    ap.add_argument(
        "--out",
        default=None,
        help="default: <repo>/edr-agent/src/preprocess/p0_golden_vectors_data.inc",
    )
    ap.add_argument(
        "--check",
        action="store_true",
        help="write to temp, compare to existing out; exit 1 if differ",
    )
    args = ap.parse_args()
    root = os.path.abspath(args.repo_root)
    jpath = os.path.join(root, "edr-backend", "platform", "config", "p0_golden_vectors.json")
    out = args.out
    if not out:
        out = os.path.join(root, "edr-agent", "src", "preprocess", "p0_golden_vectors_data.inc")

    all_cases = load_cases(jpath)
    cases = c_embed_cases(all_cases)
    body = render_inc(cases)

    if args.check:
        if not os.path.isfile(out):
            print(f"check: missing {out}", file=sys.stderr)
            sys.exit(1)
        with open(out, encoding="utf-8") as f:
            old = f.read()
        if old != body:
            print(f"check: {out} is out of date; run: python3 edr-agent/scripts/gen_p0_golden_vectors_inc.py", file=sys.stderr)
            sys.exit(1)
        print("check: p0_golden_vectors_data.inc is up to date")
        return

    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8", newline="\n") as f:
        f.write(body)
    print(
        f"ok: wrote {out} (C embed {len(cases)} process_create; JSON total {len(all_cases)} cases)"
    )


if __name__ == "__main__":
    main()
