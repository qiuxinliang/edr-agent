"""Exercise the real IR loader's supported registry-name predicate boundary.
Usage: python test_registry_ir_empty_contract.py REAL_REPLAY_EXE OUTDIR
The executable must use production p0_rule_ir.c and PCRE2 with the existing
EDR_P0_RULE_IR_TESTING test-bundle entry point, never p0_rule_ir_stub.c.
"""
import json
import os
from pathlib import Path
import subprocess
import sys

exe, out = map(Path, sys.argv[1:])
out.mkdir(parents=True, exist_ok=True)
conditions = [
    ({'registry_value_name_in': ['A']}, True),
    ({'registry_value_name_in': ['']}, False),
    ({'registry_dword_any': [{'path_regex': 'a', 'value_name': '', 'value': 0}]}, False),
    ({'registry_value_name_regex_any': ['^$']}, False),
    ({'registry_value_name_eq': ''}, False),
    ({'registry_value_name_ne': ''}, False),
    ({'registry_value_name_present': True}, False),
]
for number, (condition, accepted) in enumerate(conditions):
    path = out / f'case-{number}.json'
    path.write_text(json.dumps({'kind': 'edr_p0_rule_bundle_ir_v1',
        'ir_schema_version': 10, 'rules_bundle_version': 'registry-empty-contract',
        'rule_count': 1, 'sensor_interest_manifest_sha256': 'a'*64,
        'sensor_interest_manifest_hash_mode': 'raw-json-v1-p0-artifact-sha256-zeroed',
        'rules': [{'effect': 'security_alert', 'id': 'name',
            'event_type': 'registry_set', 'condition': condition}]}))
    result = subprocess.run([str(exe.resolve()), 'name', 'registry_set',
        'fixture.exe', '', '', '', '', '0', 'a', '', '0'],
        env=dict(os.environ, EDR_P0_IR_PATH=str(path.resolve())),
        capture_output=True, text=True, timeout=10)
    (out / f'case-{number}.stderr').write_text(result.stderr)
    if accepted:
        assert result.returncode == 0 and result.stdout.strip() == '0', result.stderr
        hit_args = [str(exe.resolve()), 'name', 'registry_set',
            'fixture.exe', '', '', '', '', '0', 'a', 'A', '0']
        hit = subprocess.run(hit_args, env=dict(os.environ,
            EDR_P0_IR_PATH=str(path.resolve())), capture_output=True,
            text=True, timeout=10, check=True)
        assert hit.stdout.strip() == '1', hit.stderr
    else:
        assert result.returncode == 2 and 'real PCRE2 IR unavailable' in result.stderr, result.stderr
print('real IR registry-name loader: valid positive and six rejection boundaries passed')
