"""Test-only compiler/process boundary for source-bound retention comparisons."""
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
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
