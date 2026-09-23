#!/usr/bin/env python3
"""Run inert Windows rule inputs through the real Agent PCRE2 replay binary.

No case command is executed. Exit 1 means semantic failures, exit 2 means the
validation could not run. This is deliberately separate from generated golden
tests: known gaps must remain visible until their owning contract is repaired.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys


def main():
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--replay", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cases", type=Path, default=root / "tests/fixtures/windows_rule_audit_cases.json")
    args = parser.parse_args()
    bundle = root / "config/p0_rule_bundle_ir_v1.json"
    raw = bundle.read_bytes()
    ir = json.loads(raw)
    cases = json.loads(args.cases.read_text(encoding="utf-8"))["cases"]
    env = os.environ.copy()
    env["EDR_P0_IR_PATH"] = str(bundle)
    results = []
    for case in cases:
        ev = case["event"]
        fields = [case["rule_id"], ev["event_type"], ev.get("process_name", ""),
                  ev.get("parent_name", ""), ev.get("cmdline", ""), ev.get("file_path", ""),
                  ev.get("process_path", ""), str(ev.get("dest_port", 0)),
                  ev.get("registry_path", ""), ev.get("registry_value_name", ""),
                  ev.get("registry_value_data", "")]
        run = subprocess.run([str(args.replay.resolve()), *fields], env=env,
                             text=True, capture_output=True, timeout=30, shell=False)
        if run.returncode != 0 or run.stdout.strip() not in {"0", "1"}:
            raise RuntimeError(f"{case['case_id']}: replay unavailable (exit={run.returncode}): {run.stderr[-1000:]}")
        hit = run.stdout.strip() == "1"
        results.append({**case, "actual_match": hit,
                        "status": "PASS" if hit == case["expect_match"] else "FAIL"})
    failed = sum(item["status"] == "FAIL" for item in results)
    report = {"schema": "edr.windows-rule-audit-result.v1", "host_os": platform.system(),
              "host_arch": platform.machine(), "scope": "constructed-event PCRE2 matcher replay; no native collection or end-to-end claim",
              "bundle_version": ir["rules_bundle_version"],
              "bundle_sha256": hashlib.sha256(raw).hexdigest(), "case_count": len(results),
              "passed": len(results) - failed, "failed": failed, "cases": results}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Windows rule matcher audit: {len(results)-failed}/{len(results)} passed; {failed} semantic gaps; {args.output}")
    return 1 if failed else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.TimeoutExpired) as error:
        print(f"Windows rule validation unavailable: {error}", file=sys.stderr)
        raise SystemExit(2)
