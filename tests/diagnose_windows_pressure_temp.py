"""One opt-in synthetic C/D path comparison; never a replacement release gate.

Run the same native pressure contract once in each existing temporary volume,
with its unchanged 150-second deadline. Preserve failures and fixtures. Remove
this diagnostic and its workflow input after the path hypothesis is resolved.
"""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time


def progress(log):
    result = []
    for line in log.splitlines():
        match = re.search(r"\[pressure_fixture\] phase=(\w+) n=(\d+) us=(\d+) "
                          r"rd=(\d+) wr=(\d+) sync=(\d+).*vfs_s=(\d+)/([\d.]+)/([\d.]+)", line)
        if match:
            values = match.groups()
            result.append(dict(zip(("phase", "n", "wall_us", "read_bytes", "write_bytes",
                                    "sync_calls", "delegate_sync_calls", "sync_us", "sync_max_us"),
                                   (values[0], *(int(v) for v in values[1:7]),
                                    float(values[7]), float(values[8])))))
    return result


def run_case(exe, parent, label, output):
    if shutil.disk_usage(parent).free < 2 * 1024**3:
        raise RuntimeError("synthetic comparison requires 2GiB free on each selected volume")
    scratch = Path(tempfile.mkdtemp(prefix="edr-pressure-path-", dir=parent))
    environment = {k: v for k, v in os.environ.items() if not k.upper().startswith("EDR_")}
    environment.update(TMP=str(scratch), TEMP=str(scratch))
    log_path = output / (label + ".log")
    started = time.monotonic()
    with log_path.open("xb") as log:
        try:
            child = subprocess.run([str(exe), "--pressure-continuation-empty"],
                                   env=environment, stdin=subprocess.DEVNULL,
                                   stdout=log, stderr=subprocess.STDOUT, timeout=150, check=False)
            outcome = {"exit_code": child.returncode, "timed_out": False}
        except subprocess.TimeoutExpired:
            # subprocess.run kills and waits for this one owned child.
            outcome = {"exit_code": None, "timed_out": True}
    with log_path.open("rb") as log:
        raw = log.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        raise RuntimeError("synthetic comparison output exceeded 1MiB")
    outcome.update(label=label, scratch=str(scratch), deadline_seconds=150,
                   wall_seconds=time.monotonic() - started, log_sha256=hashlib.sha256(raw).hexdigest(),
                   progress=progress(raw.decode("utf-8", errors="replace")))
    (output / (label + ".json")).write_text(json.dumps(outcome, indent=2), encoding="utf-8")
    return outcome


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if os.name != "nt" or os.environ.get("GITHUB_ACTIONS") != "true":
        raise SystemExit("explicit Windows GitHub-hosted synthetic diagnosis only")
    exe = args.build_dir.resolve(strict=True) / "tests/test_local_evidence_cache_candidate.exe"
    if not exe.is_file():
        raise SystemExit("native contract executable missing")
    # Resolve the actual API used by make_test_sqlite_path; Python's TEMP/TMP
    # ordering is not evidence of where the Windows fixture writes.
    buffer = ctypes.create_unicode_buffer(32768)
    length = ctypes.windll.kernel32.GetTempPathW(len(buffer), buffer)
    if not 0 < length < len(buffer):
        raise SystemExit("GetTempPathW unavailable")
    profile = Path(buffer.value).resolve(strict=True)
    runner = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    args.output.mkdir(parents=True, exist_ok=False)
    binding = {"schema": "edr.test.pressure-temp-comparison.v1", "diagnostic_only": True,
               "source_sha": os.environ["GITHUB_SHA"], "exe_sha256": hashlib.sha256(exe.read_bytes()).hexdigest(),
               "profile_temp": str(profile), "runner_temp": str(runner),
               "distinct_volumes": profile.drive.lower() != runner.drive.lower(),
               "same_executable": True, "input_owners": 4200, "automatic_retry": False}
    (args.output / "binding.json").write_text(json.dumps(binding, indent=2), encoding="utf-8")
    if not binding["distinct_volumes"]:
        raise SystemExit("path hypothesis not testable: profile and runner share a volume")
    results = [run_case(exe, profile, "profile", args.output),
               run_case(exe, runner, "runner", args.output)]
    summary = {**binding, "results": results, "release_gate_overridden": False}
    (args.output / "result.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps({"diagnostic_only": True, "results": [
        {k: row[k] for k in ("label", "exit_code", "timed_out", "wall_seconds")}
        for row in results], "release_gate_overridden": False}))


if __name__ == "__main__":
    main()
