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
RELEASE_BRANCHES = {"main", "codex/release-workflow-convergence"}


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


def validate_request(run, attempt, commit, version, request_id):
    if not re.fullmatch(r"[1-9][0-9]*", str(run)) or not re.fullmatch(r"[1-9][0-9]*", str(attempt)):
        raise ValueError("Invalid source run identity")
    if not re.fullmatch(r"[a-f0-9]{40}", commit) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise ValueError("Invalid source commit/version")
    if not re.fullmatch(r"[a-f0-9]{32}", request_id):
        raise ValueError("Invalid request identity")


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
            or (event == "workflow_dispatch" and (branch in RELEASE_BRANCHES
                or (branch == "codex/cache-deploy-compat-registry" and version == "3.2.747")
                or (branch == "codex/utm-cache-recall-748" and version == "3.2.748")))):
        raise ValueError("USB signing accepts release tags or a manual release from an explicitly trusted release branch only")


def select_artifacts(items, run, commit):
    result = []
    for arch in ("amd64", "arm64"):
        matches = [a for a in items if a.get("name") == f"release-input-{arch}"]
        if len(matches) != 1:
            raise ValueError("Expected exactly one request artifact per architecture")
        artifact = matches[0]
        origin = artifact.get("workflow_run", {})
        if (artifact.get("expired") or str(origin.get("id")) != str(run)
                or origin.get("head_sha") != commit):
            raise ValueError("Request artifact is expired or belongs to another run/commit")
        result.append(str(artifact["id"]))
    return result


def title(run, attempt, request_id):
    return f"finalize / {run} / {attempt} / {request_id}"


def output(**values):
    with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as stream:
        for key, value in values.items():
            stream.write(f"{key}={value}\n")


def admit(args):
    validate_request(args.run, args.attempt, args.commit, args.version, args.request_id)
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
    output(artifact_ids=",".join(select_artifacts(items, args.run, args.commit)))


def context(args):
    # Normal finalization only: an independent executor/recovery is not exposed.
    run, attempt = str(args.run), str(args.attempt)
    validate_request(run,attempt,args.commit,args.version,args.request_id)
    if os.environ.get('RECOVERY_MODE','false') not in ('false',''):
        raise ValueError('Normal finalization cannot enable recovery')
    source=dict(repository=SOURCE,run_id=run,attempt=attempt,commit=args.commit)
    executor=dict(source)
    for key,want in (('EXECUTOR_RUN',run),('EXECUTOR_ATTEMPT',attempt),('EXECUTOR_COMMIT',args.commit)):
        if os.environ.get(key,want)!=want:raise ValueError('Normal executor differs from source')
    validate_source(run,attempt,args.commit,args.version,api(f'repos/{SOURCE}/actions/runs/{run}'))
    items=[];page=1
    while True:
        batch=api(f'repos/{SOURCE}/actions/runs/{run}/artifacts?per_page=100&page={page}')['artifacts'];items.extend(batch)
        if len(batch)<100:break
        page+=1
        if page>100:raise ValueError('Artifact inventory exceeded bound')
    ids=select_artifacts(items,run,args.commit)
    inputs=[dict(id=i,name=x['name'],size_in_bytes=x['size_in_bytes'],digest=x['digest']) for i in ids for x in items if str(x['id'])==i]
    return dict(source=source,executor=executor,version=args.version,request_id=args.request_id,scope='headless',inputs=inputs)

def validate_private_run(info, expected_title, *, expected_run=None, expected_commit=None, expected_attempt=None):
    if (info.get('repository', {}).get('full_name') != SIGNER
            or info.get('head_repository', {}).get('full_name') != SIGNER
            or info.get('path') != '.github/workflows/' + WORKFLOW
            or info.get('event') != 'workflow_dispatch' or info.get('head_branch') != 'main'
            or info.get('display_title') != expected_title
            or not re.fullmatch(r'[a-f0-9]{40}', info.get('head_sha', ''))
            or not re.fullmatch(r'[1-9][0-9]*', str(info.get('run_attempt', '')))
            or (expected_run is not None and str(info.get('id')) != str(expected_run))
            or (expected_commit is not None and info.get('head_sha') != expected_commit)
            or (expected_attempt is not None and str(info.get('run_attempt')) != str(expected_attempt))):
        raise ValueError('Private signing run identity or request binding changed')


def save_signing_result(private_run, private_commit, private_attempt, request_id):
    output(signing_run_id=private_run, request_id=request_id,
           signing_commit=private_commit, signing_attempt=private_attempt)
    with Path(os.environ['GITHUB_ENV']).open('a', encoding='utf-8') as stream:
        for key, value in dict(REQUEST_ID=request_id, SIGNING_RUN=private_run,
                               SIGNING_ATTEMPT=private_attempt, SIGNING_COMMIT=private_commit).items():
            stream.write(f'{key}={value}\n')


def download(args):
    value = context(args)
    run = str(args.signing_run or os.environ.get('SIGNING_RUN', ''))
    commit, attempt = os.environ.get('SIGNING_COMMIT', ''), os.environ.get('SIGNING_ATTEMPT', '')
    validate_request(run, attempt, commit, value['version'], value['request_id'])
    info = api(f'repos/{SIGNER}/actions/runs/{run}')
    source = value['source']
    validate_private_run(info, title(source['run_id'], source['attempt'], value['request_id']),
                         expected_run=run, expected_commit=commit, expected_attempt=attempt)
    if info.get('status') != 'completed' or info.get('conclusion') != 'success':
        raise ValueError('Private result is not a successful complete signing run')
    args.signing_run, args.signing_commit, args.signing_attempt = run, commit, attempt
    from usb_release_transport import download as download_release
    release_token = os.environ.get('USB_SIGNING_RELEASE_TOKEN', '')
    if not release_token:
        raise RuntimeError('USB_SIGNING_RELEASE_TOKEN missing: configure the private-repository Contents credential')
    actions_token = os.environ['GH_TOKEN']
    try:
        # Admission uses the two-repository Actions credential. Only the private
        # Release transfer receives this separately scoped Contents credential.
        os.environ['GH_TOKEN'] = release_token
        download_release(args, value)
    finally:
        os.environ['GH_TOKEN'] = actions_token


def dispatch(args):
    request_id = uuid.uuid4().hex
    validate_request(args.run, args.attempt, args.commit, args.version, request_id)
    validate_source(args.run, args.attempt, args.commit, args.version,
                    api(f"repos/{SOURCE}/actions/runs/{args.run}"))
    expected_title = title(args.run, args.attempt, request_id)
    private_run = None
    private_commit = private_attempt = None
    succeeded = False
    last_progress = None
    hardware_queue_since = None
    def cancelled(_signum, _frame):
        raise InterruptedError("Source release cancelled")
    signal.signal(signal.SIGTERM, cancelled)
    try:
        api(f"repos/{SIGNER}/actions/workflows/{WORKFLOW}/dispatches", {
            "ref": "main", "inputs": {"source_run": str(args.run), "source_attempt": str(args.attempt),
            "source_commit": args.commit, "version": args.version, "request_id": request_id,
            "executor_run": str(args.run), "executor_attempt": str(args.attempt),
            "executor_commit": args.commit, "recovery": False}})
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
                validate_private_run(state,expected_title,expected_run=private_run,expected_commit=private_commit,expected_attempt=private_attempt)
                private_commit, private_attempt = state["head_sha"], str(state["run_attempt"])
                if state["status"] == "completed":
                    if state["conclusion"] != "success":
                        raise RuntimeError(f"Private signing run {private_run} failed: {state['conclusion']}; inspect its admission/USB diagnostics")
                    validate_source(args.run,args.attempt,args.commit,args.version,api(f"repos/{SOURCE}/actions/runs/{args.run}"))
                    save_signing_result(private_run,private_commit,private_attempt,request_id)
                    succeeded = True
                    return
                jobs = api(f"repos/{SIGNER}/actions/runs/{private_run}/jobs?per_page=100")["jobs"]
                progress = tuple((j['name'], j['status'], j.get('conclusion')) for j in jobs)
                if progress != last_progress:
                    print('Signing progress: ' + ', '.join(f'{n}: {c or s}' for n, s, c in progress), flush=True)
                    last_progress = progress
                queued = any(j['name'] == 'finalize' and j['status'] == 'queued' for j in jobs)
                if queued:
                    hardware_queue_since = hardware_queue_since or time.monotonic()
                    if time.monotonic() - hardware_queue_since >= 300:
                        raise TimeoutError('USB Runner queued for 5 minutes; start UTM, log in as certificate owner and check Runner availability. Build inputs are retained.')
                else:
                    hardware_queue_since = None
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
    parser.add_argument("mode", choices=("dispatch", "admit", "download"))
    for name in ("run", "attempt", "commit", "version"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--request-id", default="")
    parser.add_argument("--signing-run", default="")
    parser.add_argument("--directory", default="finalized")
    args = parser.parse_args()
    if not os.environ.get("GH_TOKEN"):
        raise RuntimeError("USB_SIGNING_TOKEN missing: configure the dedicated cross-repository Actions credential")
    {'dispatch':dispatch,'admit':admit,'download':download}[args.mode](args)


if __name__ == "__main__":
    main()
