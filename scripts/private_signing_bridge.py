"""Release admission and transport shared by hosted recovery and the USB signer."""
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


def validate_source(run, attempt, commit, version, info, *, recovery=False):
    if (info.get("repository", {}).get("full_name") != SOURCE
            or info.get("head_repository", {}).get("full_name") != SOURCE
            or info.get("path") != RELEASE_WORKFLOW
            or str(info.get("id")) != str(run)
            or str(info.get("run_attempt")) != str(attempt)
            or info.get("head_sha") != commit
            or info.get("status") != ("completed" if recovery else "in_progress")
            or (recovery and info.get("conclusion") != "failure")):
        raise ValueError("Source must match the original EDR release run and latest attempt; recovery requires a failed completed run")
    event, branch = info.get("event"), info.get("head_branch")
    if not ((event == "push" and branch == "win_" + version)
            or (event == "workflow_dispatch" and branch in RELEASE_BRANCHES)):
        raise ValueError("USB signing accepts release tags or a manual release from an explicitly trusted release branch only")


def select_artifacts(items, run, commit):
    result = []
    for arch in ("amd64", "arm64"):
        matches = [a for a in items if a.get("name") == f"release-input-{arch}"]
        if len(matches) != 1:
            raise ValueError("Expected exactly one request artifact per architecture")
        artifact = matches[0]
        origin = artifact.get("workflow_run") or {}
        if (artifact.get("expired") is not False or str(origin.get("id")) != str(run)
                or origin.get("head_sha") != commit
                or type(artifact.get("id")) is not int or artifact["id"] <= 0
                or type(artifact.get("size_in_bytes")) is not int or artifact["size_in_bytes"] <= 0
                or not isinstance(artifact.get("digest"), str)
                or not re.fullmatch(r"sha256:[a-f0-9]{64}", artifact['digest'])):
            raise ValueError("Request artifact is expired or belongs to another run/commit")
        result.append(str(artifact["id"]))
    return result


def pages(path, field):
    values = []
    for page in range(1, 11):
        batch = api(f"{path}&page={page}")[field]
        values.extend(batch)
        if len(batch) < 100:
            return values
    raise ValueError("Unexpected result count; refusing ambiguous release admission")


def validate_executor(executor, info, *, recovery):
    if (info.get("repository", {}).get("full_name") != SOURCE
            or info.get("head_repository", {}).get("full_name") != SOURCE
            or info.get("path") != RELEASE_WORKFLOW
            or str(info.get("id")) != executor["run_id"]
            or str(info.get("run_attempt")) != executor["attempt"]
            or info.get("head_sha") != executor["commit"]
            or info.get("status") != "in_progress"):
        raise ValueError("Executor is cancelled, completed, stale or not the trusted release workflow")
    if recovery and (info.get("event") != "workflow_dispatch"
                     or info.get("head_branch") not in RELEASE_BRANCHES):
        raise ValueError("Recovery executor must be a manual run from a trusted release branch")


def validate_context(value):
    source, executor = value["source"], value["executor"]
    recovery_flag = os.environ.get("RECOVERY_MODE", "false")
    if recovery_flag not in ("true", "false", ""):
        raise ValueError("Invalid recovery mode")
    recovery = recovery_flag == "true"
    if recovery != (source != executor):
        raise ValueError("Only explicit recovery can separate source from executor")
    source_info = api(f"repos/{SOURCE}/actions/runs/{source['run_id']}")
    validate_source(source['run_id'], source['attempt'], source['commit'], value['version'],
                    source_info, recovery=recovery)
    executor_info = (source_info if not recovery
                     else api(f"repos/{SOURCE}/actions/runs/{executor['run_id']}"))
    validate_executor(executor, executor_info, recovery=recovery)
    if recovery:
        jobs = pages(f"repos/{SOURCE}/actions/runs/{source['run_id']}/attempts/{source['attempt']}/jobs?per_page=100", "jobs")
        for arch in ("amd64", "arm64"):
            matches = [job for job in jobs if job.get("name", "").startswith(f"Build Windows {arch} (")]
            if (len(matches) != 1 or matches[0].get("status") != "completed"
                    or matches[0].get("conclusion") != "success"
                    or str(matches[0].get("run_attempt")) != source['attempt']):
                raise ValueError(f"Recovery requires the original successful {arch} native build")
    return value


def context(args):
    """Construct and revalidate one exact source/executor/input contract."""
    run = str(getattr(args, 'run', '') or os.environ.get('SOURCE_RUN', ''))
    attempt = str(getattr(args, 'attempt', '') or os.environ.get('SOURCE_ATTEMPT', ''))
    commit = getattr(args, 'commit', '') or os.environ.get('SOURCE_COMMIT', '')
    version = (getattr(args, 'version', '') or os.environ.get('USB_VERSION', '')
               or os.environ.get('EDR_AGENT_RELEASE_TAG', '').removeprefix('win_'))
    request_id = getattr(args, 'request_id', '') or os.environ.get('REQUEST_ID', '')
    validate_request(run, attempt, commit, version, request_id)
    executor_values = [os.environ.get(key, '') for key in ('EXECUTOR_RUN', 'EXECUTOR_ATTEMPT', 'EXECUTOR_COMMIT')]
    if any(executor_values) and not all(executor_values):
        raise ValueError('Executor identity must be a complete run/attempt/commit tuple')
    executor_run = str(os.environ.get('EXECUTOR_RUN', '') or run)
    executor_attempt = str(os.environ.get('EXECUTOR_ATTEMPT', '') or attempt)
    executor_commit = os.environ.get('EXECUTOR_COMMIT', '') or commit
    validate_request(executor_run, executor_attempt, executor_commit, version, request_id)
    value = dict(source=dict(repository=SOURCE, run_id=run, attempt=attempt, commit=commit),
                 executor=dict(repository=SOURCE, run_id=executor_run, attempt=executor_attempt, commit=executor_commit),
                 version=version, request_id=request_id, scope='headless', inputs=[])
    validate_context(value)
    items = pages(f"repos/{SOURCE}/actions/runs/{run}/artifacts?per_page=100", 'artifacts')
    ids = select_artifacts(items, run, commit)
    value['inputs'] = [dict(id=artifact_id, name=item['name'], size_in_bytes=item['size_in_bytes'], digest=item['digest'])
                       for artifact_id in ids for item in items if str(item['id']) == artifact_id]
    if len(value['inputs']) != 2 or len(set(ids)) != 2:
        raise ValueError('Expected two distinct immutable source inputs')
    return value


def title(run, attempt, request_id):
    return f"finalize / {run} / {attempt} / {request_id}"


def output(**values):
    with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as stream:
        for key, value in values.items():
            stream.write(f"{key}={value}\n")


def admit(args):
    value = context(args)
    output(artifact_ids=','.join(item['id'] for item in value['inputs']))


def recover_check(args):
    if (os.environ.get('RECOVERY_MODE') != 'true'
            or os.environ.get('WINDOWS_RELEASE_MODE') != 'usb'
            or os.environ.get('EDR_RELEASE_CANDIDATE') != 'true'):
        raise ValueError('Recovery is restricted to an explicit USB candidate')
    if (os.environ.get('GITHUB_REPOSITORY') != SOURCE
            or os.environ.get('EXECUTOR_RUN') != os.environ.get('GITHUB_RUN_ID')
            or os.environ.get('EXECUTOR_ATTEMPT') != os.environ.get('GITHUB_RUN_ATTEMPT')
            or os.environ.get('EXECUTOR_COMMIT') != os.environ.get('GITHUB_SHA')):
        raise ValueError('Recovery executor must retain the actual GitHub run identity')
    # Preparation has no signing request yet; this identity is not dispatched.
    args.request_id = uuid.uuid4().hex
    value = context(args)
    output(artifact_ids=','.join(item['id'] for item in value['inputs']),
           source_run=value['source']['run_id'], source_attempt=value['source']['attempt'],
           source_commit=value['source']['commit'])


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
    args.request_id = request_id
    value = context(args)
    args.run, args.attempt, args.commit = (value['source'][name] for name in ('run_id', 'attempt', 'commit'))
    args.version = value['version']
    expected_title = title(args.run, args.attempt, request_id)
    private_run = None
    private_commit = None
    private_attempt = None
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
            "executor_run": value['executor']['run_id'], "executor_attempt": value['executor']['attempt'],
            "executor_commit": value['executor']['commit'],
            "recovery": str(value['source'] != value['executor']).lower()}})
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
                validate_private_run(state, expected_title, expected_run=private_run,
                                     expected_commit=private_commit, expected_attempt=private_attempt)
                private_commit = state['head_sha']
                private_attempt = str(state['run_attempt'])
                if state["status"] == "completed":
                    if state["conclusion"] != "success":
                        raise RuntimeError(f"Private signing run {private_run} failed: {state['conclusion']}; inspect its admission/USB diagnostics")
                    validate_context(value)
                    save_signing_result(private_run, private_commit, private_attempt, request_id)
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
                state = api(f"repos/{SIGNER}/actions/runs/{private_run}")
                validate_private_run(state, expected_title, expected_run=private_run,
                                     expected_commit=private_commit, expected_attempt=private_attempt)
                if state.get('status') != 'completed':
                    api(f"repos/{SIGNER}/actions/runs/{private_run}/cancel", {})
            except (RuntimeError, ValueError):
                print(f"Could not cancel private run {private_run}; inspect it manually. Its own timeout remains enforced.", flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("dispatch", "admit", "recover-check", "download", "check-active"))
    for name in ("run", "attempt", "commit", "version"):
        parser.add_argument("--" + name, default='')
    parser.add_argument("--request-id", default="")
    parser.add_argument('--signing-run', default='')
    parser.add_argument('--directory', type=Path, default=Path('finalized'))
    args = parser.parse_args()
    if not os.environ.get("GH_TOKEN"):
        raise RuntimeError("USB_SIGNING_TOKEN missing: configure the dedicated cross-repository Actions credential")
    if args.mode == 'check-active':
        context(args)
        print('Source, active executor and immutable inputs verified before returning results')
    else:
        {'dispatch': dispatch, 'admit': admit, 'recover-check': recover_check, 'download': download}[args.mode](args)


if __name__ == "__main__":
    main()
