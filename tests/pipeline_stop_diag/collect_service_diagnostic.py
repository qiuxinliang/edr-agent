"""Export fixed SCM diagnostic metadata only; never read Agent logs or databases."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat

ALLOWED = (
    'intent.json', 'result.json', 'stop-result-frozen.json',
    'seed-copy-receipt.json', 'runtime-closure.json', 'scm-sampler-selected.json',
)
FILE_CAP = 131072
TOTAL_CAP = 524288


def need(ok, cause):
    if not ok:
        raise ValueError(cause)


def regular(path, directory=False):
    for item in (path, *path.parents):
        s = item.lstat()
        need(not stat.S_ISLNK(s.st_mode) and
             not getattr(s, 'st_file_attributes', 0) & 0x400, 'reparse_refused')
    s = path.stat()
    need(stat.S_ISDIR(s.st_mode) if directory else stat.S_ISREG(s.st_mode),
         'regular_type_required')
    return s


def parse(raw):
    def pairs(items):
        value = {}
        for key, entry in items:
            need(key not in value, 'duplicate_json_key')
            value[key] = entry
        return value
    def constant(_):
        raise ValueError('nonfinite_json')
    value = json.loads(raw.decode('utf-8', 'strict'), object_pairs_hook=pairs,
                       parse_constant=constant)
    need(type(value) is dict, 'metadata_object_required')
    return value


def collect(case, output, runner_temp, source, token):
    need(re.fullmatch('[a-f0-9]{40}', source) and
         re.fullmatch('[a-f0-9]{32}', token), 'identity_shape')
    case, output, runner_temp = map(lambda p: Path(os.path.abspath(p)),
                                    (case, output, runner_temp))
    regular(runner_temp, True)
    need(case.parent == runner_temp and case.name == 'edr-ci-service-' + token and
         output.parent == runner_temp and output.name == 'service-stop-qa-' + token
         and not output.exists(), 'exclusive_fixed_directories')
    regular(case, True)
    data, values, total = {}, {}, 0
    for name in ALLOWED:
        path = case / name
        if not path.exists():
            need(not path.is_symlink(), 'missing_leaf_symlink')
            continue
        before = regular(path)
        need(0 < before.st_size <= FILE_CAP, 'metadata_file_cap')
        with path.open('rb') as stream:
            raw = stream.read(before.st_size + 1)
            held = os.fstat(stream.fileno())
        after = regular(path)
        fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns')
        need(len(raw) == before.st_size and
             all(getattr(before, k) == getattr(after, k) == getattr(held, k)
                 for k in fields), 'metadata_changed')
        total += len(raw)
        need(total <= TOTAL_CAP, 'metadata_total_cap')
        data[name], values[name] = raw, parse(raw)
    for name in ('intent.json', 'result.json'):
        need(name in values and values[name].get('source_sha') == source and
             values[name].get('token') == token, 'bound_intent_and_result_required')
    result = values['result.json']
    need(result.get('schema') == 'edr.ci-isolated-service-diagnostic.v1' and
         result.get('whole_recovery_accepted') is False and
         result.get('diagnostic_agent_not_release') is True, 'diagnostic_scope')
    frozen = values.get('stop-result-frozen.json')
    need(result.get('stop_result') == frozen, 'original_stop_result_mismatch')
    if frozen is not None:
        need(frozen.get('schema') == 'edr.ci-service-stop-frozen.v1' and
             frozen.get('observation_can_change_result') is False and
             type(frozen.get('wait_ms')) is int and frozen['wait_ms'] == 45000,
             'frozen_stop_contract')
    accepted = result.get('diagnostic_accepted') is True
    if accepted:
        need(frozen is not None and frozen.get('status') == 'returned_zero',
             'accepted_without_original_stop_success')
    manifest = dict(schema='edr.ci-selected-service-metadata.v1', source_sha=source,
                    token=token, diagnostic_claimed_accepted=accepted,
                    full_service_rollback_accepted=False,
                    raw_agent_log_or_db_exported=False,
                    missing=[n for n in ALLOWED if n not in data],
                    files=[dict(name=n, bytes=len(raw),
                                sha256=hashlib.sha256(raw).hexdigest())
                           for n, raw in data.items()])
    manifest_raw = (json.dumps(manifest, sort_keys=True, indent=2) + '\n').encode()
    need(total + len(manifest_raw) <= TOTAL_CAP, 'manifest_total_cap')
    output.mkdir()
    for name, raw in (*data.items(), ('manifest.json', manifest_raw)):
        with (output / name).open('xb') as stream:
            need(stream.write(raw) == len(raw), 'metadata_short_write')
    return manifest


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--case', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--source', required=True)
    p.add_argument('--token', required=True)
    a = p.parse_args()
    value = collect(a.case, a.output, Path(os.environ['RUNNER_TEMP']), a.source, a.token)
    print(json.dumps(dict(metadata_collected=True,
                         diagnostic_claimed_accepted=value['diagnostic_claimed_accepted'],
                         full_service_rollback_accepted=False)))
