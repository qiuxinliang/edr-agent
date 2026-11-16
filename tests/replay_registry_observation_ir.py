"""Replay native builder output through the production PCRE2 IR executable.

Usage: python replay_registry_observation_ir.py NATIVE_LOG P0_REPLAY_EXE OUTDIR
The native fixture emits UTF-8 bytes as hex; values are arguments, never code.
"""
import json
import os
from pathlib import Path
import subprocess
import sys

log, exe, directory = map(Path, sys.argv[1:])
directory.mkdir(parents=True, exist_ok=True)
bundle = directory / 'registry-ir.json'
rules = []
for i, name in enumerate(('A', '65', '中', '')):
    rules.append({'effect': 'security_alert', 'id': f'name{i}',
                  'event_type': 'registry_set',
                  'condition': {'registry_value_name_in': [name]}})
# Empty default-name predicates may be rejected by the rule contract. Test the
# three explicit names; unknown/default must match none of these names.
rules = rules[:3]
bundle.write_text(json.dumps({'kind': 'edr_p0_rule_bundle_ir_v1',
    'ir_schema_version': 10, 'rules_bundle_version': 'registry-observation-fixture',
    'rule_count': len(rules), 'sensor_interest_manifest_sha256': 'a'*64,
    'sensor_interest_manifest_hash_mode': 'raw-json-v1-p0-artifact-sha256-zeroed',
    'rules': rules}), encoding='utf-8')
count = 0
for line in log.read_text(encoding='utf-8').splitlines():
    if not line.startswith('IR_REPLAY '):
        continue
    fields = dict(x.split('=', 1) for x in line.split()[1:])
    observation = int(fields['observation'])
    name = bytes.fromhex(fields['name_hex']).decode('utf-8')
    for i, target in enumerate(('A', '65', '中')):
        result = subprocess.run([str(exe.resolve()), f'name{i}', 'registry_set',
            'fixture.exe', '', '', '', '', '0',
            r'\REGISTRY\MACHINE\Software\EDRLab', name, ''],
            env=dict(os.environ, EDR_P0_IR_PATH=str(bundle.resolve())),
            capture_output=True, text=True, timeout=10, check=True)
        expected = observation == 1 and name == target
        assert result.stdout.strip() == str(int(expected)), (observation, name, target, result.stdout)
    count += 1
assert count >= 10, 'native observation rows missing'
print(f'production IR replay: {count} rows, {count*3} exact-name decisions passed')
