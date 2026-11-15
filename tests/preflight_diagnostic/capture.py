"""Bounded diagnostics for the synthetic CI rollback fixture only.

before --install-dir DIR --probe-root DIR --output-root NEWDIR --synthetic-ci
after  (same options) --baseline-exe EXE --failure ORIGINAL_REASON

Before performs configuration parsing and file metadata reads only. After never
replaces the original Setup failure with a diagnostic result.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

FLOOR = 2 * 1024**3
DIRECTORY_LIMIT = 900 * 1024**2
LOG_LIMIT = 256 * 1024
DEFAULT_PATH = r"C:\Program Files\FDSecurity\evidence\local_evidence_cache.db"


def write_new(path, value):
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=True, indent=2)
        stream.write("\n")


def metadata(path):
    try:
        value = path.stat()
        return dict(exists=True, device=value.st_dev, file_id=value.st_ino,
                    bytes=value.st_size, modified_ns=value.st_mtime_ns,
                    created_ns=getattr(value, "st_birthtime_ns", None))
    except FileNotFoundError:
        return {"exists": False}


def files(path):
    return {name: metadata(Path(str(path) + suffix))
            for name, suffix in (("db", ""), ("wal", "-wal"), ("shm", "-shm"))}


def parse_offline(raw):
    try:
        import tomllib
    except ImportError as error:
        raise RuntimeError("diagnostic configuration reader requires Python 3.11+") from error
    document = tomllib.loads(raw.decode("utf-8-sig"))
    section = document.get("offline", {})
    if not isinstance(section, dict):
        raise ValueError("offline configuration must be a table")
    return section


def identify(install_dir):
    install_dir = install_dir.resolve()
    config = install_dir / "agent.toml"
    with config.open("rb") as stream:
        before = os.fstat(stream.fileno())
        raw = stream.read(131073)
        after = os.fstat(stream.fileno())
    if len(raw) > 131072:
        raise ValueError("configuration exceeds diagnostic input limit")
    if (before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_ino, after.st_size, after.st_mtime_ns):
        raise ValueError("configuration changed while identifying input")
    current = config.stat()
    if (current.st_dev, current.st_ino) != (after.st_dev, after.st_ino):
        raise ValueError("configuration replaced while identifying input")
    offline = parse_offline(raw)
    configured = offline.get("evidence_cache_path", DEFAULT_PATH)
    if not isinstance(configured, str):
        configured = DEFAULT_PATH
    if len(configured.encode("utf-8")) >= 1024 or "\0" in configured:
        raise ValueError("unsupported configuration path length or embedded NUL")
    override = os.environ.get("EDR_EVIDENCE_CACHE_PATH", "")
    selected = override or configured or "local_evidence_cache.db"
    selected_path = Path(selected)
    if not selected_path.is_absolute():
        selected_path = install_dir / selected_path
    budget = offline.get("evidence_cache_max_size_mb", 128)
    if type(budget) is not int or not 0 <= budget <= 0x7fffffff:
        budget = 128
    return dict(config=str(config), config_sha256=hashlib.sha256(raw).hexdigest(),
                config_bytes=len(raw), config_identity=metadata(config),
                collector_cwd=str(Path.cwd()), cli_cwd=str(install_dir),
                environment_scope="collector parent only; original Setup child inheritance assumed, not observed",
                evidence_path_override=override or None,
                selection="environment" if override else "config" if configured else "relative_fallback",
                path=str(selected_path.absolute()), configured_budget_mb=budget,
                effective_budget_mb=budget or 128, files=files(selected_path))


def input_binding(value):
    return {key: value[key] for key in ("config", "config_sha256", "config_bytes",
            "cli_cwd", "evidence_path_override", "path", "configured_budget_mb")}


def check_budget(root, deadline):
    if time.monotonic() >= deadline:
        raise TimeoutError("collector 90-second deadline reached")
    entries = list(root.rglob("*"))
    if len(entries) > 150 or any(p.is_symlink() for p in entries):
        raise ValueError("diagnostic directory identity or file limit")
    if sum(p.stat().st_size for p in entries if p.is_file()) > DIRECTORY_LIMIT:
        raise ValueError("diagnostic directory exceeds 900 MiB")
    if shutil.disk_usage(root).free < FLOOR:
        raise ValueError("diagnostic disk reserve reached")


def run_logged(root, label, command, cwd, seconds, deadline):
    check_budget(root, deadline)
    start = time.monotonic()
    record = dict(command_image=str(command[0]), timeout=False, output_limit=False)
    with (root / (label + ".stdout")).open("xb") as out, (
            root / (label + ".stderr")).open("xb") as err:
        process = subprocess.Popen(command, cwd=cwd, stdout=out, stderr=err)
        try:
            while process.poll() is None:
                record["timeout"] = time.monotonic() >= min(deadline, start + seconds)
                record["output_limit"] = max(os.fstat(out.fileno()).st_size,
                                              os.fstat(err.fileno()).st_size) >= LOG_LIMIT
                if record["timeout"] or record["output_limit"]:
                    process.kill()
                    break
                time.sleep(.02)
            process.wait(timeout=2)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=2)
        record.update(exit=process.returncode, elapsed_ms=round((time.monotonic() - start) * 1000),
                      stdout_bytes=os.fstat(out.fileno()).st_size,
                      stderr_bytes=os.fstat(err.fileno()).st_size)
    # Stop a finite producer at the boundary and bound retained raw output too.
    for suffix in ("stdout", "stderr"):
        path = root / (label + "." + suffix)
        if path.stat().st_size > LOG_LIMIT:
            with path.open("r+b") as stream:
                stream.truncate(LOG_LIMIT)
            record["output_limit"] = True
    write_new(root / (label + ".json"), record)
    check_budget(root, deadline)
    return record


def digest(path, deadline):
    if not path.exists():
        return None
    value = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            if time.monotonic() >= deadline:
                raise TimeoutError("collector deadline during copy verification")
            block = stream.read(1024 * 1024)
            if not block:
                break
            value.update(block)
    return dict(bytes=path.stat().st_size, sha256=value.hexdigest())


def probe_result(root, label, record):
    try:
        value = json.loads((root / (label + ".stdout")).read_text())
        record["inspection"] = {key: value[key] for key in
            ("result", "first_failure", "elapsed_ms") if key in value}
    except (ValueError, UnicodeError):
        record["inspection_unavailable"] = True
    return record


def stable_copy(args, path, root, deadline):
    reserve = sum(value.get("bytes", 0) for value in files(path).values()) + 16 * 1024**2
    if reserve > DIRECTORY_LIMIT or shutil.disk_usage(root).free < FLOOR + reserve:
        return {"skipped": "stable copy cannot fit original disk reserve and directory budget"}
    target = root / "stable.db"
    if target.exists():
        raise ValueError("stable destination already exists")
    # Separate process provides the hard outer bound even during blocked I/O.
    worker = """import sqlite3,sys,time,os
from pathlib import Path
source,target,limit=sys.argv[1],sys.argv[2],int(sys.argv[3])
end=time.monotonic()+5.5
def progress(status,left,total):
 if time.monotonic()>=end: raise TimeoutError('backup deadline')
 if os.path.getsize(target)>limit: raise RuntimeError('backup size limit')
 if __import__('shutil').disk_usage(Path(target).parent).free<2147483648: raise RuntimeError('disk reserve')
with sqlite3.connect(Path(source).absolute().as_uri()+'?mode=ro',uri=True,timeout=.2) as src:
 with sqlite3.connect(target) as dst: src.backup(dst,pages=256,progress=progress,sleep=.01)
"""
    result = run_logged(root, "backup", [sys.executable, "-I", "-B", "-c", worker,
                        str(path), str(target), str(DIRECTORY_LIMIT - 16 * 1024**2)],
                        args.install_dir, 6, deadline)
    if result["exit"] or result["timeout"]:
        return dict(completed=False, process=result)
    baseline = {suffix: digest(Path(str(target) + suffix), deadline) for suffix in ("", "-wal")}
    results = {}
    for mode in ("original", "trace"):
        label = "stable-" + mode
        results[mode] = probe_result(root, label, run_logged(root, label,
            [str(args.probe_root / ("preflight-" + mode + ".exe")), str(target),
             str(args.selected["configured_budget_mb"])], args.install_dir, 6, deadline))
        if {s: digest(Path(str(target) + s), deadline) for s in baseline} != baseline:
            raise ValueError("stable-copy probe changed DB or WAL")
    return dict(completed=True, scope="consistent backup after live input changed; no original-CI causal proof",
                db_wal_sha256=baseline, probes=results)


def collect(args):
    deadline = time.monotonic() + 90
    os.umask(0o077)
    root = args.output_root.absolute()
    if args.stage == "before":
        if shutil.disk_usage(root.parent).free < FLOOR + 16 * 1024**2:
            raise ValueError("before requires original disk reserve plus 16 MiB diagnostic allowance")
        root.mkdir(mode=0o700, parents=False)
        value = identify(args.install_dir)
        write_new(root / "before.json", value)
        return {"stage": "before", "input": str(root / "before.json"), "sql_executed": False}
    before = json.loads((root / "before.json").read_text(encoding="utf-8"))
    if (root / "after.json").exists():
        raise ValueError("after diagnostics already recorded; retries are disabled")
    report = dict(stage="after", first_failure=args.failure, diagnostics={}, status="incomplete")
    # Preserve the original failure before any after-phase collection can fail.
    write_new(root / "original-failure.json", {"reason": args.failure})
    try:
        args.selected = identify(args.install_dir)
        write_new(root / "after-input.json", args.selected)
        if input_binding(before) != input_binding(args.selected):
            raise ValueError("configuration or selected input changed after before stage")
        path = Path(args.selected["path"])
        report["live_changed_before_diagnostics"] = before["files"] != args.selected["files"]
        report["diagnostics"]["original_723_cli"] = run_logged(root, "original-723-cli",
            [str(args.baseline_exe), "--storage-space-preflight", "--config", before["config"],
             "--output", str(root / "original-723.floor")], args.install_dir, 20, deadline)
        for mode in ("original", "trace"):
            label = "live-" + mode
            report["diagnostics"][mode] = probe_result(root, label, run_logged(root, label,
                [str(args.probe_root / ("preflight-" + mode + ".exe")), str(path),
                 str(before["configured_budget_mb"])], args.install_dir, 6, deadline))
        report["files_after_diagnostics"] = files(path)
        report["configuration_changed_during_diagnostics"] = input_binding(identify(args.install_dir)) != input_binding(before)
        report["live_changed"] = (report["live_changed_before_diagnostics"] or
                                  report["files_after_diagnostics"] != args.selected["files"])
        if args.stable_copy_on_change and report["live_changed"]:
            report["stable_copy"] = stable_copy(args, path, root, deadline)
        report["status"] = "collected"
    except Exception as error:
        report["diagnostic_error"] = {"type": type(error).__name__, "cause": str(error)[:300]}
    write_new(root / "after.json", report)
    return report


def verify_ci_scope(args):
    if sys.platform != "win32" or os.environ.get("GITHUB_ACTIONS") != "true":
        raise ValueError("capture CLI is restricted to the Windows GitHub Actions synthetic fixture")
    if os.environ.get("GITHUB_REPOSITORY") != "qiuxinliang/edr-agent":
        raise ValueError("capture CLI repository identity mismatch")
    if str(args.install_dir).replace("/", "\\").rstrip("\\").lower() != r"c:\edr-agent-setup-lifecycle-smoke":
        raise ValueError("capture CLI requires the fixed rollback-baseline synthetic installation")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stage", choices=("before", "after"))
    parser.add_argument("--install-dir", type=Path, required=True)
    parser.add_argument("--probe-root", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--synthetic-ci", action="store_true", required=True)
    parser.add_argument("--baseline-exe", type=Path)
    parser.add_argument("--failure")
    parser.add_argument("--stable-copy-on-change", action="store_true")
    args = parser.parse_args()
    verify_ci_scope(args)
    args.install_dir = args.install_dir.absolute()
    args.probe_root = args.probe_root.absolute()
    args.output_root = args.output_root.absolute()
    if args.baseline_exe:
        args.baseline_exe = args.baseline_exe.absolute()
    if args.stage == "after" and (not args.baseline_exe or not args.failure):
        parser.error("after requires original --baseline-exe and --failure")
    result = collect(args)
    encoded = json.dumps(result, ensure_ascii=True)
    if len(encoded.encode()) > 8192:
        encoded = json.dumps({"stage": args.stage, "report": str(args.output_root / "after.json"),
                              "first_failure": (args.failure or "")[:1024],
                              "summary": "details retained in bounded files"})
    print(encoded)
    return 0 if args.stage == "before" or result.get("status") == "collected" else 1


if __name__ == "__main__":
    raise SystemExit(main())
