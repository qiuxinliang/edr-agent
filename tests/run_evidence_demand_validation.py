#!/usr/bin/env python3
"""Bounded counterfactuals on frozen synthetic copies; never alters live policy.

Variant failures are expected evidence, not grounds to relax the oracle.
This runs the actual cache and authorized reader with a test-only rule stub.
"""
import argparse
import copy
from decimal import Decimal
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess

from retention_comparison_support import (
    SOURCES, QUEUE_SOURCES, compiler_flags, compile_command, compiler_identity,
    dependencies, execute_benchmark, export_git_snapshot, failure_report,
    includes, runtime_environment, storage_reservation_sources, verify_git_snapshot)


PATCHES = {
    "tier": (
        '  if (generation_known && pre_count) { *reason = "causal_context"; return 2; }',
        '  /* Experiment: identity/context alone does not promote a candidate. */'),
    "file": (
        '  if (evidence_is_low_value_file_noise(r)) {\n    return 0;\n  }',
        '  if (r->type == EDR_EVENT_FILE_WRITE && !evidence_text_has_high_signal(r)) return 0;\n'
        '  if (evidence_is_low_value_file_noise(r)) {\n    return 0;\n  }'),
    "window": (
        '  sqlite3_stmt *st = NULL; char state[32]; int64_t from, until;',
        '  /* Experiment: no post window for non-priority FILE_WRITE. Pre is unchanged. */\n'
        '  if (r->type == EDR_EVENT_FILE_WRITE && !evidence_has_priority_or_high_confidence_context(r))\n'
        '    return window_metadata_set(id, "expired", NULL, "");\n'
        '  sqlite3_stmt *st = NULL; char state[32]; int64_t from, until;'),
}
SCENES = ("file_anchor", "priority_anchor", "network_anchor", "shared_anchor", "replay_anchor", "no_anchor")
QUESTIONS = {
    "file_anchor": "Can a later investigator retrieve one staging-executable action and its one pre/two distinct post file actions? This is a declared investigation need, not an attack-positive label.",
    "priority_anchor": "Does a typed local P1 retention hint preserve its file context? This does not invoke production alert-parent ownership/minimum-residence.",
    "network_anchor": "Can a network-port candidate preserve surrounding file actions? Port 445 is synthetic input, not a detected real attack.",
    "shared_anchor": "Do two overlapping candidate owners preserve all independently authored actions, without interpreting two representations as two actions?",
    "replay_anchor": "Does replay of the exact source preserve surrounding facts while the anchor still denotes one action?",
    "no_anchor": "Can a delayed inquiry retrieve ordinary file actions after reopen without any candidate? A limitation here is not a new regression.",
}


def checked_map(checks):
    if not isinstance(checks, list) or not checks:
        raise ValueError("Checks must be a nonempty list")
    mapped = {}
    for check in checks:
        if (not isinstance(check, dict) or not isinstance(check.get("stage"), str)
                or not check["stage"] or not isinstance(check.get("fact"), str)
                or not check["fact"] or not isinstance(check.get("pass"), bool)
                or "actual" not in check or "expected" not in check):
            raise ValueError("Incomplete check receipt")
        key = (check["stage"], check["fact"])
        if key in mapped: raise ValueError("Duplicate check receipt")
        if check["pass"] != (check["actual"] == check["expected"]):
            raise ValueError("Check verdict conflicts with observed values")
        mapped[key] = check
    return mapped


def explain_actions(value, directory):
    """Map projected rows to pre-authored actions, never infer action count from rows.

    In this fixture every action has a distinct path/time/actor tuple. That is
    NOT a general production deduplication rule for otherwise unidentifiable
    events. Exact full-source identity is unavailable in historical pre rows.
    """
    if (value.get("scene") not in SCENES or not isinstance(value.get("delay_minutes"), int)
            or not 0 <= value["delay_minutes"] <= 300):
        raise ValueError("Missing or invalid experiment identity/delay")
    raw = checked_map(value.get("checks"))
    required = {("isolation", "wrong tenant rows"), ("isolation", "wrong generation rows"),
                ("integrity", "all-layout dangling references"),
                ("integrity", "projection versus physical refs")}
    stages = [("reopened", "reopened")]
    if value["delay_minutes"]: stages.append(("delayed", "delayed"))
    required.update((stage, "returned identity/type/time field violations") for stage, _ in stages)
    if not required.issubset(raw): raise ValueError("Missing isolation, integrity or returned-field checks")
    base = 1793100000000000000
    truth = [("pre", "C:\\UserData\\required-pre.bin", base - 1000000000),
             ("post-one", "C:\\UserData\\required-post.bin", base + 1000000000),
             ("post-two", "C:\\UserData\\required-post.bin", base + 1001000000)]
    if value["scene"] not in ("network_anchor", "no_anchor"):
        truth.append(("anchor", "C:\\Temp\\required-anchor.exe", base))
    if value["scene"] == "shared_anchor":
        truth.append(("second-anchor", "C:\\Temp\\second-anchor.exe", base + 100000000))
    explanations, functional = [], []
    for stage, label in stages:
        path = directory / ("query-" + label + ".json")
        if not path.is_file(): raise ValueError("Missing required query receipt: " + label)
        rows = json.loads(path.read_text(), parse_float=Decimal)["rows"]
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            raise ValueError("Query rows must be an array of objects")
        for action, full_path, stamp in truth:
            matches = [r for r in rows if r.get("file_path") == full_path
                       and r.get("event_time_ns") == stamp and r.get("type") == 11
                       and r.get("pid") == 97000 and r.get("endpoint_id") == "demand-endpoint"
                       and r.get("process_start_key") == "97000"
                       and r.get("process_creation_filetime_100ns") == "133700000000097000"]
            explanations.append({"stage": stage, "action_id": action,
                "expected_occurrences": 1, "matched_representations": len(matches),
                "sources": [r.get("source") for r in matches],
                "duplicate_representation": max(0, len(matches) - 1),
                "classification": "missing" if not matches else "duplicate_representation" if len(matches) > 1 else "present"})
            functional.append({"stage": stage, "fact": "action:" + action,
                               "expected": 1, "actual": int(bool(matches)), "pass": bool(matches)})
    # Keep the raw row-count oracle and its failures verbatim; explain them.
    for check in value["checks"]:
        if check["stage"] in ("isolation", "integrity") or "field violations" in check["fact"]:
            functional.append(check)
    value["action_explanations"] = explanations
    value["functional_checks"] = functional
    value["oracle_scope"] = "known synthetic action tuples; raw row checks retained; not generic deduplication"
    return value


def compare(value, base=None):
    current = checked_map(value.get("functional_checks"))
    checks = list(current.values())
    if base is None:
        return "PASS_SYNTHETIC_CONTRACT" if all(x["pass"] for x in checks) else "BASELINE_LIMIT_OBSERVED"
    prior = checked_map(base.get("functional_checks"))
    if set(current) != set(prior): raise ValueError("Compared check keys differ")
    value["regressions"] = [x for x in checks if not x["pass"] and prior[x["stage"], x["fact"]]["pass"]]
    return "FAIL" if value["regressions"] else "INCONCLUSIVE" if any(not x["pass"] for x in base["functional_checks"]) else "PASS_SYNTHETIC_CONTRACT"


def boundary_exit_code(results):
    expected = {(v, s, m) for v in ("baseline", "tier", "short")
                for s in ("file_anchor", "priority_anchor", "network_anchor")
                for m in (0, 59, 60, 61)}
    observed = {(x.get("variant"), x.get("scene"), x.get("minute")) for x in results}
    return 0 if len(results) == len(expected) and observed == expected and all(x.get("status") == "PASS" for x in results) else 1


def boundary_experiment(previous, out, dependency_prefix):
    """Reuse bound local binaries; test strict one-hour retirement boundaries."""
    previous = previous.resolve()
    prior_metadata = json.loads((previous / "metadata.json").read_text())
    results = []
    columns = ("candidate_id", "event_time_ns", "created_ns", "retention_value_class",
               "context_post_until_ns", "context_window_protect_until_active_ms",
               "alert_context_protect_until_active_ms", "local_retention_state")
    for variant in ("baseline", "tier", "short"):
        binary = previous / (variant + (".exe" if os.name == "nt" else ".bin"))
        binary_hash = sha(binary)
        for scene in ("file_anchor", "priority_anchor", "network_anchor"):
            initial = None
            for minute in (0, 59, 60, 61):
                directory = out / f"{variant}-{scene}-{minute}m"; directory.mkdir()
                execution = execute_benchmark([str(binary), scene, "1", str(minute)], directory,
                    runtime_environment(directory, dependency_prefix), 30)
                if execution["exit_code"] != 0 or execution["timed_out"]:
                    raise RuntimeError("TTL boundary process failed: " + directory.name)
                values = [json.loads(line) for line in (directory / "stdout.log").read_text().splitlines() if line.startswith("{")]
                if len(values) != 1: raise RuntimeError("Missing boundary receipt")
                value = explain_actions(values[0], directory)
                uri = (directory / "evidence.db").as_uri() + "?mode=ro"
                with sqlite3.connect(uri, uri=True) as db:
                    timing = [dict(zip(columns, row)) for row in db.execute("SELECT " + ",".join(columns) + " FROM p0_candidates")]
                    clock = db.execute("SELECT value FROM metrics WHERE metric_name='local_retention_v1_active_ms'").fetchone()
                if not minute: initial = timing
                target_stage = "delayed" if minute else "reopened"
                actions = [x for x in value["functional_checks"] if x["stage"] == target_stage and x["fact"].startswith("action:")]
                expected = int(minute <= 60)  # Production retirement uses strict '< cutoff'.
                coverage_ok = bool(actions) and all(x["actual"] == expected for x in actions)
                invariants_ok = all(x["pass"] for x in value["functional_checks"]
                    if x["stage"] in ("integrity", "isolation") or "field violations" in x["fact"])
                receipt = {"variant": variant, "scene": scene, "minute": minute,
                    "selected_hours": 1, "recent_hours": 1, "expected_present": bool(expected),
                    "status": "PASS" if coverage_ok and invariants_ok else "FAIL",
                    "initial_timing": initial, "remaining_timing": timing,
                    "durable_active_ms": clock[0] if clock else None,
                    "query_actions": actions, "binary_sha256": binary_hash,
                    "input_sha256": value["input_sha256"],
                    "query_point": "after minute maintenance polls, cache close and startup reopen",
                    "query_wall_ns": 1793100000000000000 + (minute * 60000000000 if minute else 2000000000),
                    "query_monotonic_ms": 1000 + (minute * 60000 if minute else 2000)}
                (directory / "result.json").write_text(json.dumps(receipt, indent=2) + "\n")
                results.append(receipt)
        if sha(binary) != binary_hash: raise RuntimeError("Reused binary changed during experiment")
    for scene in ("file_anchor", "priority_anchor", "network_anchor"):
        if len({x["input_sha256"] for x in results if x["scene"] == scene}) != 1:
            raise RuntimeError("TTL comparison input changed: " + scene)
    metadata = {"baseline": prior_metadata["baseline"], "previous_experiment": str(previous),
        "previous_metadata_sha256": sha(previous / "metadata.json"),
        "analysis_sha256": sha(Path(__file__)),
        "scope": "36 synthetic process runs, 9 configurations at 0/59/60/61 simulated minutes",
        "limits": "No real-time soak; startup maintenance participates; no claim of exact wall-time GC latency; P1 local hint is not an alert-parent owner"}
    (out / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
    (out / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    summary = {state: sum(x["status"] == state for x in results) for state in ("PASS", "FAIL")}
    (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary))
    return boundary_exit_code(results)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def apply_variant(source, variant):
    path = source / "src/storage/local_evidence_cache.c"
    original = path.read_text()
    before = sha(path)
    if variant in PATCHES:
        old, new = PATCHES[variant]
        if original.count(old) != 1:
            raise ValueError("Counterfactual patch anchor is not unique: " + variant)
        path.write_text(original.replace(old, new))
    return {"variant": variant, "path": "src/storage/local_evidence_cache.c",
            "before_sha256": before, "after_sha256": sha(path),
            "patch": PATCHES.get(variant), "experimental_only": True}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--baseline", default="cf47a921")
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--cc", default=os.environ.get("CC", "cl" if os.name == "nt" else "cc"))
    p.add_argument("--dependency-prefix", type=Path)
    p.add_argument("--boundary-from", type=Path, help="Reuse a completed experiment's binaries for 1h TTL boundary probes")
    args = p.parse_args()
    repo = Path(__file__).resolve().parents[1]
    out = args.output.resolve()
    if out == repo or repo in out.parents or (out.exists() and any(out.iterdir())):
        p.error("Use a new external empty output directory")
    out.mkdir(parents=True, exist_ok=True)
    stage = failure_report(out)
    if args.boundary_from:
        stage["stage"] = "ttl_boundary"
        return boundary_experiment(args.boundary_from, out, args.dependency_prefix)
    revision = subprocess.check_output(["git", "rev-parse", args.baseline + "^{commit}"], cwd=repo, text=True).strip()
    frozen = out / "frozen"; frozen.mkdir()
    binding = export_git_snapshot(repo, revision, frozen, ("src", "include", "third_party"), out / "source-binding.json")
    harness = ("evidence_demand_validation.c", "evidence_retention_comparison.c", "retention_benchmark_support.h")
    for name in harness:
        shutil.copyfile(repo / "tests" / name, out / name)
    inc, libraries, deps = dependencies(args.dependency_prefix)
    metadata = {
        "baseline": revision, "compiler": compiler_identity(args.cc), "dependency_sha256": deps,
        "harness_sha256": {name: sha(out / name) for name in harness},
        "budget_mib": 16, "recent_hours": 1, "baseline_selected_hours": 4,
        "time_scope": "simulated retention clock; not a real-time soak",
        "truth_scope": "pre-authored synthetic file actions, independent required markers and multiplicities",
        "query_scope": "actual authorized cache reader, no network signature verification",
        "scenario_questions": QUESTIONS,
        "contract_scope": "4h selected retention versus a 2h investigation is the counterfactual contract; 1h/2h and no-anchor scenes intentionally probe existing limits",
        "cost_verdict": "INCONCLUSIVE_SINGLE_RUN_PER_CASE; mechanism observations, not performance acceptance",
        "dependency_binding_limit": "POSIX shared libraries are not byte-bound by existing dependencies(); flags and SQLite runtime version recorded",
        "missing": ["ETW", "production rule execution", "server/UI/model", "real observed full input stream",
                    "device I/O", "physical disk peak", "supported installed updater compatibility"],
        "adoption": "NOT_ELIGIBLE_FOR_DEFAULT_CHANGE",
    }
    (out / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
    results = {}
    for variant in ("baseline", "tier", "file", "window", "short"):
        stage["stage"] = "compile_" + variant
        source = out / variant
        shutil.copytree(frozen, source, symlinks=True)
        mutation = apply_variant(source, variant)
        variant_binding = copy.deepcopy(binding)
        variant_binding["entries"][mutation["path"]]["materialized_sha256"] = mutation["after_sha256"]
        (out / (variant + "-mutation.json")).write_text(json.dumps(mutation, indent=2) + "\n")
        defines = ['EDR_AGENT_VERSION_STRING="demand-validation"', 'EDR_HAVE_LZ4=1',
                   'EDR_HAVE_ZSTD=1', 'EDR_HAVE_NANOPB=1', 'EDR_HAVE_SQLITE=1',
                   'EDR_LOCAL_EVIDENCE_CACHE_TESTING=1', 'PB_FIELD_32BIT=1',
                   'BENCH_REAL_QUEUE=1', 'BENCH_HAS_PARENT_CONTEXT_BINDING=1',
                   'BENCH_SOURCE="demand"', 'BENCH_SELECTED_HOURS=4']
        flags = compiler_flags(defines, [out, *includes(source), *inc])
        if os.name != "nt": flags += ["-O2"]
        binary = out / (variant + (".exe" if os.name == "nt" else ".bin"))
        cmd = compile_command(args.cc, flags, [out / harness[0], *[source / x for x in SOURCES + QUEUE_SOURCES + storage_reservation_sources(source)]], binary, libraries)
        (out / (variant + "-compile.json")).write_text(json.dumps(cmd, indent=2) + "\n")
        with (out / (variant + "-build.log")).open("x") as log:
            subprocess.run(cmd, cwd=out, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=180)
        results[variant] = {}
        for scene in SCENES:
            for selected, delay in ((4, 0), (4, 120), (1, 120)):
                key = f"{scene}-selected{selected}-delay{delay}"
                stage["stage"] = variant + "/" + key
                directory = out / (variant + "-" + key); directory.mkdir()
                actual_selected = 1 if variant == "short" else selected
                run = execute_benchmark([str(binary), scene, str(actual_selected), str(delay)], directory,
                                        runtime_environment(directory, args.dependency_prefix), 30)
                if run["exit_code"] != 0 or run["timed_out"]:
                    raise RuntimeError("Experiment execution failed: " + variant + "/" + key)
                lines = [x for x in (directory / "stdout.log").read_text().splitlines() if x.startswith("{")]
                if len(lines) != 1: raise RuntimeError("Missing single experiment receipt")
                value = json.loads(lines[0]); results[variant][key] = value
                explain_actions(value, directory)
                if variant == "baseline" and scene != "no_anchor" and not value["anchor_candidate"]:
                    raise RuntimeError("The intended baseline anchor was not admitted by the existing policy")
                if variant != "baseline":
                    base = results["baseline"][key]
                    if value["input_sha256"] != base["input_sha256"]:
                        raise RuntimeError("Counterfactual input mismatch")
                    value["comparison"] = compare(value, base)
                else:
                    value["comparison"] = compare(value)
                (directory / "result.json").write_text(json.dumps(value, indent=2) + "\n")
        verify_git_snapshot(source, variant_binding)
    verify_git_snapshot(frozen, binding)
    for name in harness:
        if sha(out / name) != metadata["harness_sha256"][name]: raise RuntimeError("Frozen harness changed")
    (out / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    summary = {v: {state: sum(r["comparison"] == state for r in rows.values())
                   for state in sorted({r["comparison"] for r in rows.values()})} for v, rows in results.items()}
    (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary))


if __name__ == "__main__":
    raise SystemExit(main())
