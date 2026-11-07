"""One fixed synthetic native cost attribution; never overrides a release gate."""
import argparse
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import tempfile

from retention_comparison_support import execute_benchmark, runtime_environment


def windows_contract_temp_path():
    """Use the Win32 GetTempPath owner, not Python's temporary-path precedence."""
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    get_temp_path = kernel32.GetTempPathW
    get_temp_path.argtypes = [wintypes.DWORD, wintypes.LPWSTR]
    get_temp_path.restype = wintypes.DWORD
    # Match the native fixture's MAX_PATH capacity. The Unicode API retains the
    # same Windows resolver without decoding an ANSI path as Python UTF-8.
    buffer = ctypes.create_unicode_buffer(260)
    length = get_temp_path(len(buffer), buffer)
    if not length:
        raise OSError(ctypes.get_last_error(), 'GetTempPathW failed')
    if length >= len(buffer) or not buffer.value:
        raise RuntimeError('GetTempPathW exceeded the native fixture path capacity')
    path = Path(buffer.value)
    if not path.is_absolute():
        raise RuntimeError('GetTempPathW returned a relative path')
    path = path.resolve(strict=True)
    if not path.is_dir():
        raise RuntimeError('GetTempPathW did not resolve to a directory')
    return path


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--preserve-contract-volumes', action='store_true',
                        help='Keep work and temporary stores under their original contract roots')
    parser.add_argument('--sync-attribution', action='store_true',
                        help='Use the isolated SQLite call-scope diagnostic binary')
    args = parser.parse_args(argv)
    if os.name != 'nt' or os.environ.get('GITHUB_ACTIONS') != 'true':
        raise SystemExit('explicit native Windows CI diagnostic only')
    build = args.build_dir.resolve(strict=True)
    binary_name = ('test_retention_sync_attribution.exe' if args.sync_attribution
                   else 'test_local_evidence_cache_candidate.exe')
    binary = build / 'tests' / binary_name
    if not binary.is_file():
        raise SystemExit('native contract executable missing')
    parent = Path(os.environ['RUNNER_TEMP']).resolve(strict=True)
    # Resolve the original Windows temp owner before runtime_environment changes
    # TEMP/TMP for the child. CTest uses build as cwd; native temporary fixtures
    # use GetTempPath. A single RUNNER_TEMP scratch would change that layout.
    temp_parent = windows_contract_temp_path() if args.preserve_contract_volumes else parent
    args.output.mkdir(parents=True, exist_ok=False)
    if args.preserve_contract_volumes:
        scratch = Path(tempfile.mkdtemp(prefix='retention-cost-work-', dir=build))
        temporary = Path(tempfile.mkdtemp(prefix='retention-cost-temp-', dir=temp_parent))
    else:
        scratch = Path(tempfile.mkdtemp(prefix='retention-cost-', dir=parent))
        temporary = scratch
    binding = {'source_sha': os.environ['GITHUB_SHA'], 'diagnostic_only': True,
               'binary_name': binary_name, 'sync_attribution': args.sync_attribution,
               'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
               'scratch': str(scratch), 'deadline_seconds': 150,
               'layout_mode': ('preserve_contract_volumes' if args.preserve_contract_volumes
                               else 'legacy_single_scratch'),
               'work_directory': str(scratch), 'temp_directory': str(temporary),
               'contract_work_directory': str(build),
               'contract_temp_directory': (str(temp_parent) if args.preserve_contract_volumes else None),
               'temp_path_owner': ('GetTempPathW' if args.preserve_contract_volumes else 'RUNNER_TEMP'),
               'physical_device_identity_proven': False,
               'layout_limit': 'Directory roots do not establish physical device identity or full-suite replay.',
               'fixture_limit': 'Same cases and scale; realtime event timestamps, not byte-identical inputs.',
               'release_gate_overridden': False, 'automatic_retry': False}
    (args.output / 'binding.json').write_text(json.dumps(binding, indent=2), encoding='utf-8')
    # This fixed C entry point has no subprocesses. subprocess.run kills and
    # waits for the owned child on timeout; retain its first failure and files.
    result = execute_benchmark([str(binary), '--retention-cost-diagnostic'],
                               scratch, runtime_environment(temporary), 150)
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
