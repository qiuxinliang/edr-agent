"""One fixed synthetic native cost attribution; never overrides a release gate."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import tempfile

from retention_comparison_support import execute_benchmark, runtime_environment


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if os.name != 'nt' or os.environ.get('GITHUB_ACTIONS') != 'true':
        raise SystemExit('explicit native Windows CI diagnostic only')
    binary = args.build_dir.resolve(strict=True) / 'tests/test_local_evidence_cache_candidate.exe'
    if not binary.is_file():
        raise SystemExit('native contract executable missing')
    parent = Path(os.environ['RUNNER_TEMP']).resolve(strict=True)
    args.output.mkdir(parents=True, exist_ok=False)
    scratch = Path(tempfile.mkdtemp(prefix='retention-cost-', dir=parent))
    binding = {'source_sha': os.environ['GITHUB_SHA'], 'diagnostic_only': True,
               'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
               'scratch': str(scratch), 'deadline_seconds': 150,
               'release_gate_overridden': False, 'automatic_retry': False}
    (args.output / 'binding.json').write_text(json.dumps(binding, indent=2), encoding='utf-8')
    # This fixed C entry point has no subprocesses. subprocess.run kills and
    # waits for the owned child on timeout; retain its first failure and files.
    result = execute_benchmark([str(binary), '--retention-cost-diagnostic'],
                               scratch, runtime_environment(scratch), 150)
    for name in ('stdout.log', 'stderr.log', 'execution.json'):
        source = scratch / name
        if source.stat().st_size > 1024 * 1024:
            raise RuntimeError('diagnostic output exceeded 1MiB')
        (args.output / name).write_bytes(source.read_bytes())
    print(json.dumps({**binding, 'exit_code': result['exit_code'],
                      'timed_out': result['timed_out'], 'wall_seconds': result['wall_seconds']}))
    if result['exit_code'] != 0 or result['timed_out']:
        raise SystemExit('bounded retention cost diagnostic did not complete')


if __name__ == '__main__':
    main()
