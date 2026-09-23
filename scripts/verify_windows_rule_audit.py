#!/usr/bin/env python3
"""Run inert Windows rule inputs through the real Agent PCRE2 replay binary.

No case command is executed. Exit 1 means semantic failures, exit 2 means the
validation could not run. This is deliberately separate from generated golden
tests: known gaps must remain visible until their owning contract is repaired.
"""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys


def windows_native_architecture():
    """Query the kernel, because an emulated Python can report its own ISA."""
    if platform.system() != "Windows":
        raise RuntimeError("--native-windows requires a Windows host")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    try:
        query = kernel.IsWow64Process2
    except AttributeError as error:
        raise RuntimeError("native architecture verification requires IsWow64Process2") from error
    kernel.GetCurrentProcess.argtypes = []
    kernel.GetCurrentProcess.restype = ctypes.c_void_p
    query.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ushort),
                     ctypes.POINTER(ctypes.c_ushort)]
    query.restype = ctypes.c_int
    process_machine, native_machine = ctypes.c_ushort(), ctypes.c_ushort()
    if not query(kernel.GetCurrentProcess(), ctypes.byref(process_machine),
                 ctypes.byref(native_machine)):
        raise ctypes.WinError(ctypes.get_last_error())
    architecture = {0x8664: "amd64", 0xAA64: "arm64"}.get(native_machine.value)
    if not architecture:
        raise RuntimeError(f"unsupported native Windows machine: 0x{native_machine.value:04x}")
    return architecture


def verify_native_replay(root, replay):
    architecture = windows_native_architecture()
    # CTest may be launched by PowerShell 7. Its module path must not make
    # Windows PowerShell 5.1 import modules for an incompatible runtime.
    powershell_env = {key: value for key, value in os.environ.items()
                      if key.upper() != "PSMODULEPATH"}
    check = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
         "-File", str(root / "scripts/Assert-WindowsPeArchitecture.ps1"),
         "-Path", str(replay.resolve()), "-Architecture", architecture],
        text=True, capture_output=True, timeout=30, shell=False, env=powershell_env)
    if check.returncode != 0:
        raise RuntimeError(f"native replay PE verification failed: {check.stderr[-1000:] or check.stdout[-1000:]}")
    return architecture


def main():
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--replay", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cases", type=Path, default=root / "tests/fixtures/windows_rule_audit_cases.json")
    parser.add_argument("--native-windows", action="store_true",
                        help="require a Windows kernel and a replay PE matching its native architecture")
    args = parser.parse_args()
    # Never leave an earlier success artifact behind when this run is unavailable.
    args.output.unlink(missing_ok=True)
    native_architecture = verify_native_replay(root, args.replay) if args.native_windows else None
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
              "native_windows_verified": args.native_windows,
              "native_windows_arch": native_architecture,
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
