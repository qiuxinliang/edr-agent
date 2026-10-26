"""Test-only compiler/process boundary for source-bound retention comparisons."""
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import shlex
import shutil
import subprocess
import sys
import tarfile
import time

CODEC_SOURCES = [
    'src/preprocess/p0_terminal_identity.c', 'src/command/sha256.c',
    'src/transport/egress_batch_policy.c', 'src/transport/egress_request_policy.c',
    'src/transport/egress_purpose_json.c', 'src/proto/edr/v1/event.pb.c',
    'third_party/nanopb/pb_common.c', 'third_party/nanopb/pb_encode.c',
    'third_party/nanopb/pb_decode.c', 'third_party/cjson/cJSON.c',
    'third_party/lz4/lz4.c',
]


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def failure_report(directory):
    """Retain an early stage failure without exception text, argv or environment."""
    state = {'stage': 'prepare'}
    original = sys.excepthook

    def report(kind, error, traceback):
        causes = {subprocess.TimeoutExpired: 'bounded_subprocess_timed_out',
                  subprocess.CalledProcessError: 'bounded_subprocess_failed',
                  FileNotFoundError: 'required_file_or_tool_missing'}
        record = {'stage': state['stage'], 'type': kind.__name__,
                  'cause': causes.get(kind, 'comparison_stage_failed')}
        try:
            with (directory/'failure.json').open('x', encoding='utf-8') as output:
                output.write(json.dumps(record, indent=2)+'\n')
        except OSError:
            print('Unable to persist bounded comparison failure metadata', file=sys.stderr)
        original(kind, error, traceback)

    sys.excepthook = report
    return state


def export_git_snapshot(repo, revision, destination, folders, binding_path):
    """Export exact Git bytes, checking link blobs and materialized target closure."""
    # Git archive otherwise applies a Windows runner's core.autocrlf=true.
    # This invocation changes no repository or global Git configuration.
    archive = subprocess.check_output(['git', '-c', 'core.autocrlf=false',
        '-c', 'core.eol=lf', 'archive', revision, *folders], cwd=repo, timeout=30)
    bindings, expected = {}, {}
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        entries = {}
        for member in tar.getmembers():
            path = PurePosixPath(member.name)
            if (path.is_absolute() or '..' in path.parts or '\\' in member.name or
                    ':' in member.name or member.name in entries):
                raise RuntimeError('Unexpected archive path')
            if not (member.isfile() or member.isdir() or member.issym()):
                raise RuntimeError('Unsupported archive entry')
            entries[member.name] = member
            if member.issym():
                target = posixpath.normpath(posixpath.join(posixpath.dirname(member.name), member.linkname))
                if (target.startswith('/') or target == '..' or target.startswith('../') or
                        '\\' in member.linkname or ':' in member.linkname):
                    raise RuntimeError('Archive symlink escapes source snapshot')
        for relative, member in entries.items():
            if member.isdir():
                continue
            blob = subprocess.check_output(['git', 'show', revision+':'+relative], cwd=repo, timeout=30)
            archived = member.linkname.encode('utf-8') if member.issym() else tar.extractfile(member).read()
            if archived != blob:
                raise RuntimeError('Baseline Git blob mismatch: '+relative)
            expected[relative] = blob
        tracked = subprocess.check_output(['git', 'ls-tree', '-r', '--name-only', '-z',
            revision, '--', *folders], cwd=repo, timeout=30)
        if set(expected) != {name.decode('utf-8') for name in tracked.split(b'\0') if name}:
            raise RuntimeError('Baseline archive does not cover the complete tracked source tree')

        def resolve(relative, seen):
            if relative in seen or relative not in expected:
                raise RuntimeError('Baseline symlink target closure is missing or cyclic')
            member = entries[relative]
            if not member.issym():
                return relative, [relative]
            target = posixpath.normpath(posixpath.join(posixpath.dirname(relative), member.linkname))
            resolved, closure = resolve(target, seen | {relative})
            return resolved, [relative, *closure]

        # Check the complete closure before extraction. Windows tarfile links
        # may be created successfully but remain unreadable (EINVAL). Materialize
        # their verified targets without depending on native symlink behavior.
        closures = {relative: resolve(relative, set()) for relative in expected}
        if os.name == 'nt':
            tar.extractall(destination, members=[member for member in entries.values()
                                                if not member.issym()])
            for relative, member in entries.items():
                if member.issym():
                    (destination/relative).write_bytes(expected[closures[relative][0]])
        else:
            tar.extractall(destination)
        for relative, blob in expected.items():
            path, member = destination/relative, entries[relative]
            resolved, closure = closures[relative]
            if path.read_bytes() != expected[resolved]:
                raise RuntimeError('Baseline materialized source mismatch: '+relative)
            physical_link = os.readlink(path) if path.is_symlink() else None
            if member.issym() and path.is_symlink() and path.resolve() != (destination/resolved).resolve():
                raise RuntimeError('Baseline symlink resolves outside its declared target')
            bindings[relative] = {'kind': 'symlink' if member.issym() else 'file',
                'git_blob_sha256': hashlib.sha256(blob).hexdigest(), 'git_blob_bytes': len(blob),
                'resolved_path': resolved, 'materialized_sha256': digest(path),
                'physical_symlink_target': physical_link,
                'target_closure_sha256': {name: hashlib.sha256(expected[name]).hexdigest() for name in closure}}
    record = {'revision': revision, 'git_archive_autocrlf': False, 'git_archive_eol': 'lf',
              'all_tracked_blobs_verified': True, 'entries': bindings}
    with binding_path.open('x', encoding='utf-8') as output:
        output.write(json.dumps(record, sort_keys=True, indent=2)+'\n')
    return record


def verify_git_snapshot(directory, binding):
    for relative, record in binding['entries'].items():
        path = directory/relative
        actual_link = os.readlink(path) if path.is_symlink() else None
        if actual_link != record['physical_symlink_target'] or digest(path) != record['materialized_sha256']:
            raise RuntimeError('Frozen Git source or symlink changed: '+relative)


def includes(source):
    return [source / p for p in ('.', 'include', 'third_party/cjson',
            'third_party/nanopb', 'src/proto', 'third_party/lz4')]


def compiler_flags(defines, include_paths, native_machine=None):
    if os.name == 'nt':
        flags = ['/nologo', '/std:c11', '/experimental:c11atomics', '/utf-8',
                 '/O2', '/MD', '/UNDEBUG', '/we4013', '/D_CRT_SECURE_NO_WARNINGS',
                 '/D_CRT_NONSTDC_NO_WARNINGS', '/D_WIN32_WINNT=0x0A00']
        if native_machine:
            flags += ['/D' + {'amd64': '_AMD64_=1', 'arm64': '_ARM64_=1'}[native_machine]]
        return flags + ['/D' + x for x in defines] + ['/I' + str(x) for x in include_paths]
    return ['-g', '-std=c11', '-D_DEFAULT_SOURCE', '-Wall', '-Wextra',
            '-Wno-unused-parameter', '-Wno-unused-function', '-UNDEBUG',
            *['-D' + x for x in defines], *['-I' + str(x) for x in include_paths]]


def dependencies(prefix=None):
    """Use the installed, locked vcpkg closure on Windows; never download here."""
    if os.name == 'nt':
        if not prefix:
            raise ValueError('Native Windows requires --dependency-prefix from the locked vcpkg owner')
        prefix = Path(prefix).resolve()
        sqlite = prefix / 'lib/sqlite3.lib'
        zstd = next((prefix / 'lib' / p for p in ('zstd.lib', 'libzstd.lib')
                     if (prefix / 'lib' / p).is_file()), None)
        paths = [prefix / 'include/sqlite3.h', prefix / 'include/zstd.h', sqlite]
        if zstd is None:
            raise ValueError('Locked vcpkg zstd import library is missing')
        paths += [zstd]
        paths += [p for p in (prefix / 'bin').glob('*.dll') if p.name.lower() in
                  ('sqlite3.dll', 'zstd.dll', 'libzstd.dll')]
        if any(not p.is_file() for p in paths):
            raise ValueError('Locked SQLite/zstd development closure is missing')
        return [prefix / 'include'], [str(sqlite), str(zstd), 'advapi32.lib', 'ws2_32.lib'], {
            str(p): digest(p) for p in paths}
    try:
        value = subprocess.check_output(['pkg-config', '--cflags', '--libs',
                                        'sqlite3', 'libzstd'], text=True,
                                       stderr=subprocess.DEVNULL, timeout=30)
        return [], shlex.split(value) + ['-lm', '-pthread'], {}
    except (FileNotFoundError, subprocess.CalledProcessError):
        flags = ['-lsqlite3', '-lzstd', '-lm', '-pthread']
        if Path('/opt/homebrew/include').is_dir():
            flags = ['-isystem', '/opt/homebrew/include', '-L/opt/homebrew/lib',
                     '-Wl,-rpath,/opt/homebrew/lib', *flags]
        return [], flags, {}


def compile_command(cc, flags, sources, binary, libraries):
    if os.name != 'nt':
        return [cc, *flags, *map(str, sources), '-o', str(binary), *libraries]
    objects = binary.parent / (binary.stem + '-objects')
    objects.mkdir()
    return [cc, *flags, '/Fo' + str(objects) + os.sep, '/Fe' + str(binary),
            *map(str, sources), '/link', *libraries]


def runtime_environment(directory, prefix=None):
    """Synthetic stores cannot inherit a live Agent's EDR_* path overrides."""
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith('EDR_')}
    env['TEMP'] = env['TMP'] = env['TMPDIR'] = str(directory)
    if os.name == 'nt' and prefix:
        env['PATH'] = str(Path(prefix) / 'bin') + os.pathsep + env.get('PATH', '')
    return env


def compiler_identity(cc):
    path = shutil.which(cc)
    if not path:
        raise ValueError('Comparison compiler was not found: ' + cc)
    return {'path': path, 'sha256': digest(path),
            'msvc_tools_version': os.environ.get('VCToolsVersion'),
            'windows_sdk_version': os.environ.get('WindowsSDKVersion')}


def execute_benchmark(argv, directory, env, timeout):
    """Persist partial output and terminal status before the caller evaluates it."""
    stdout_path, stderr_path = directory/'stdout.log', directory/'stderr.log'
    result = {'arguments': list(map(str, argv)), 'timeout_seconds': timeout,
              'exit_code': None, 'timed_out': False}
    started = time.monotonic()
    with stdout_path.open('xb') as stdout, stderr_path.open('xb') as stderr:
        try:
            child = subprocess.run(argv, cwd=directory, env=env, stdin=subprocess.DEVNULL,
                                   stdout=stdout, stderr=stderr, timeout=timeout)
            result['exit_code'] = child.returncode
        except subprocess.TimeoutExpired:
            result['timed_out'] = True
        except OSError as error:
            result['launch_error'] = type(error).__name__
            result['launch_errno'] = error.errno
    result.update({'wall_seconds': time.monotonic()-started,
                   'stdout_bytes': stdout_path.stat().st_size,
                   'stderr_bytes': stderr_path.stat().st_size,
                   'stdout_sha256': digest(stdout_path), 'stderr_sha256': digest(stderr_path)})
    with (directory/'execution.json').open('x', encoding='utf-8') as output:
        output.write(json.dumps(result, indent=2)+'\n')
    return result


def verify_native(binary, values, expected):
    if not expected:
        return
    data = binary.read_bytes()
    if data[:2] != b'MZ':
        raise ValueError('Expected a Windows PE benchmark executable')
    pe = int.from_bytes(data[0x3c:0x40], 'little')
    machine = {'amd64': 0x8664, 'arm64': 0xaa64}[expected]
    if data[pe:pe+4] != b'PE\0\0' or int.from_bytes(data[pe+4:pe+6], 'little') != machine:
        raise ValueError('Benchmark PE architecture differs from the requested native machine')
    if int(values['native_machine']) != machine or int(values['process_machine']) != 0:
        raise ValueError('Benchmark was emulated or ran on a different native Windows machine')
    if not values['process_io_available'] or values['process_io_available'] == '0':
        raise ValueError('Native Windows process I/O measurement was unavailable')


SOURCES = [
    'src/preprocess/detection_decision.c', 'src/preprocess/detection_profile.c',
    'src/preprocess/behavior_from_slot.c', 'src/detection/policy_v2.c',
    'src/storage/local_evidence_cache.c', 'src/storage/evidence_context_store.c',
    'src/storage/evidence_cache_migration.c', 'src/forensic/process_tree_cache.c',
    'src/preprocess/behavior_record.c', 'src/preprocess/p0_rule_match.c',
    'src/preprocess/windows_event_policy.c', 'src/preprocess/windows_file_identity.c',
    'src/preprocess/p0_rule_ir_stub.c', 'src/command/sha256.c',
    'src/serialize/behavior_proto.c', 'third_party/nanopb/pb_encode.c',
    'third_party/cjson/cJSON.c', 'src/preprocess/p0_terminal_identity.c',
    'src/transport/egress_batch_policy.c', 'src/transport/egress_request_policy.c',
    'src/transport/egress_purpose_json.c', 'src/proto/edr/v1/event.pb.c',
    'third_party/nanopb/pb_common.c', 'third_party/nanopb/pb_decode.c',
    'third_party/lz4/lz4.c', 'src/core/validation_trace.c',
]
QUEUE_SOURCES = ['src/storage/queue_sqlite.c', 'src/transport/report_events_ack.c']
