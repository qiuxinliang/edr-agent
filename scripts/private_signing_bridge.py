"""Hosted-only transport to the private USB signer; never runs on the key host."""
import argparse
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import time
import uuid

SOURCE = "qiuxinliang/edr-agent"
SIGNER = "qiuxinliang/edr-agent-signing"
WORKFLOW = "sign.yml"
RELEASE_WORKFLOW = ".github/workflows/edr-agent-client-release.yml"


def api(path, data=None):
    command = ["gh", "api", path]
    if data is not None:
        command += ["--method", "POST", "--input", "-"]
    # No POST retry: a lost response must not generate duplicate signing jobs.
    for attempt in range(3 if data is None else 1):
        try:
            result = subprocess.run(command, input=json.dumps(data) if data is not None else None,
                                    text=True, capture_output=True, timeout=35)
        except subprocess.TimeoutExpired:
            result = None
        if result is not None and result.returncode == 0:
            return json.loads(result.stdout) if result.stdout.strip() else None
        if data is None and attempt < 2:
            time.sleep(2 ** attempt)
    # Never include gh stderr, which can contain credential/HTTP diagnostics.
    raise RuntimeError("GitHub API request failed; check scoped Actions permission, token expiry and connectivity")


def validate_request(run, attempt, commit, version, phase, request_id):
    if not re.fullmatch(r"[1-9][0-9]*", str(run)) or not re.fullmatch(r"[1-9][0-9]*", str(attempt)):
        raise ValueError("Invalid source run identity")
    if not re.fullmatch(r"[a-f0-9]{40}", commit) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise ValueError("Invalid source commit/version")
    if phase not in {"native", "installer", "manifest"} or not re.fullmatch(r"[a-f0-9]{32}", request_id):
        raise ValueError("Invalid phase/request identity")


def validate_source(run, attempt, commit, version, info):
    if (info.get("repository", {}).get("full_name") != SOURCE
            or info.get("head_repository", {}).get("full_name") != SOURCE
            or info.get("path") != RELEASE_WORKFLOW
            or str(info.get("id")) != str(run)
            or str(info.get("run_attempt")) != str(attempt)
            or info.get("head_sha") != commit or info.get("status") != "in_progress"):
        raise ValueError("Source must be the active matching EDR release run, not a fork, stale attempt or other workflow")
    event, branch = info.get("event"), info.get("head_branch")
    if not ((event == "push" and branch == "win_" + version)
            or (event == "workflow_dispatch" and branch == "main")):
        raise ValueError("USB signing accepts release tags or a manual release from main only")


def select_artifacts(items, run, commit, phase):
    result = []
    for arch in ("amd64", "arm64"):
        matches = [a for a in items if a.get("name") == f"usb-{phase}-request-{arch}"]
        if len(matches) != 1:
            raise ValueError("Expected exactly one request artifact per architecture")
        artifact = matches[0]
        origin = artifact.get("workflow_run", {})
        if (artifact.get("expired") or str(origin.get("id")) != str(run)
                or origin.get("head_sha") != commit):
            raise ValueError("Request artifact is expired or belongs to another run/commit")
        result.append(str(artifact["id"]))
    return result


def title(run, attempt, phase, request_id):
    return f"sign / {run} / {attempt} / {phase} / {request_id}"


def output(**values):
    with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as stream:
        for key, value in values.items():
            stream.write(f"{key}={value}\n")


def admit(args):
    validate_request(args.run, args.attempt, args.commit, args.version, args.phase, args.request_id)
    info = api(f"repos/{SOURCE}/actions/runs/{args.run}")
    validate_source(args.run, args.attempt, args.commit, args.version, info)
    # Hosted admission rejects untrusted requests before scheduling the USB host.
    items = []
    for page in range(1, 11):
        batch = api(f"repos/{SOURCE}/actions/runs/{args.run}/artifacts?per_page=100&page={page}")["artifacts"]
        items.extend(batch)
        if len(batch) < 100:
            break
    else:
        raise ValueError("Unexpected artifact count; refusing ambiguous release admission")
    output(artifact_ids=",".join(select_artifacts(items, args.run, args.commit, args.phase)))


def dispatch(args):
    request_id = uuid.uuid4().hex
    validate_request(args.run, args.attempt, args.commit, args.version, args.phase, request_id)
    validate_source(args.run, args.attempt, args.commit, args.version,
                    api(f"repos/{SOURCE}/actions/runs/{args.run}"))
    expected_title = title(args.run, args.attempt, args.phase, request_id)
    private_run = None
    succeeded = False
    def cancelled(_signum, _frame):
        raise InterruptedError("Source release cancelled")
    signal.signal(signal.SIGTERM, cancelled)
    try:
        api(f"repos/{SIGNER}/actions/workflows/{WORKFLOW}/dispatches", {
            "ref": "main", "inputs": {"source_run": str(args.run), "source_attempt": str(args.attempt),
            "source_commit": args.commit, "version": args.version, "phase": args.phase, "request_id": request_id}})
        deadline = time.monotonic() + 1800
        while time.monotonic() < deadline:
            if private_run is None:
                runs = api(f"repos/{SIGNER}/actions/workflows/{WORKFLOW}/runs?event=workflow_dispatch&branch=main&per_page=100")["workflow_runs"]
                matches = [r for r in runs if r.get("display_title") == expected_title]
                if len(matches) > 1:
                    raise RuntimeError("Duplicate private signing requests; refusing ambiguous response")
                if matches:
                    private_run = matches[0]["id"]
                    print(f"Private signing run: {private_run}", flush=True)
            if private_run is not None:
                state = api(f"repos/{SIGNER}/actions/runs/{private_run}")
                if state["status"] == "completed":
                    if state["conclusion"] != "success":
                        raise RuntimeError(f"Private signing run {private_run} failed: {state['conclusion']}; inspect its admission/USB diagnostics")
                    output(signing_run_id=private_run)
                    succeeded = True
                    return
            time.sleep(15)
        raise TimeoutError("Private signer unavailable or timed out after 30 minutes; check UTM login, USB and Runner status")
    finally:
        if not succeeded and private_run is not None:
            try:
                api(f"repos/{SIGNER}/actions/runs/{private_run}/cancel", {})
            except RuntimeError:
                print(f"Could not cancel private run {private_run}; inspect it manually. Its own timeout remains enforced.", flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("dispatch", "admit"))
    for name in ("run", "attempt", "commit", "version", "phase"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--request-id", default="")
    args = parser.parse_args()
    if not os.environ.get("GH_TOKEN"):
        raise RuntimeError("USB_SIGNING_TOKEN missing: configure the dedicated cross-repository Actions credential")
    (dispatch if args.mode == "dispatch" else admit)(args)


if __name__ == "__main__":
    main()
