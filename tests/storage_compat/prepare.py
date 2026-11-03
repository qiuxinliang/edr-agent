"""Export fixed source and append test targets; never edits the product checkout."""
import argparse, hashlib, io, json, subprocess, tarfile
from pathlib import Path

PINS = {
    'legacy': 'b51bc3d825e6d5666535463b34eb708201e6fda7',
    'candidate': 'd4e837790c53861c99d31ee127c55a5ef1f06f4a',
}

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--repo', required=True, type=Path)
    p.add_argument('--output', required=True, type=Path)
    p.add_argument('--role', required=True, choices=PINS)
    a = p.parse_args()
    commit = PINS[a.role]
    actual = subprocess.check_output(['git', '-C', str(a.repo), 'rev-parse', commit], text=True, timeout=30).strip()
    if actual != commit:
        raise ValueError('source commit mismatch')
    a.output.mkdir(parents=True, exist_ok=False)
    archive = subprocess.check_output(['git', '-C', str(a.repo), 'archive', commit], timeout=30)
    with tarfile.open(fileobj=io.BytesIO(archive)) as t:
        root = a.output.resolve()
        for member in t.getmembers():
            target = (root / member.name).resolve()
            target.relative_to(root)
            if member.issym():
                (target.parent / member.linkname).resolve().relative_to(root)
            elif not (member.isfile() or member.isdir()):
                raise ValueError('unsupported archive member')
        t.extractall(a.output)
    files = {}
    for root in ('src', 'include', 'third_party', 'tests', 'cmake'):
        for file in sorted((a.output / root).rglob('*')):
            if file.is_file():
                files[file.relative_to(a.output).as_posix()] = hashlib.sha256(file.read_bytes()).hexdigest()
    files['CMakeLists.txt'] = hashlib.sha256((a.output / 'CMakeLists.txt').read_bytes()).hexdigest()
    for relative in ('vcpkg.json', 'vcpkg-configuration.json', 'dependencies.lock.json',
                     'scripts/bootstrap_pinned_vcpkg.ps1'):
        files[relative] = hashlib.sha256((a.output / relative).read_bytes()).hexdigest()
    for file in sorted((a.output / 'triplets').rglob('*')):
        if file.is_file():
            files[file.relative_to(a.output).as_posix()] = hashlib.sha256(file.read_bytes()).hexdigest()
    tools = Path(__file__).resolve().parent
    with (a.output / 'CMakeLists.txt').open('a') as f:
        f.write(f'\n# Isolated storage compatibility test adapter only.\nset(COMPAT_SOURCE_COMMIT "{commit}")\ninclude("{tools.as_posix()}/targets.cmake")\n')
    record = {'schema': 'edr.test.storage-compat-source.v1', 'source_commit': commit,
              'git_archive_sha256': hashlib.sha256(archive).hexdigest(),
              'cmake_overlay_sha256': hashlib.sha256((a.output / 'CMakeLists.txt').read_bytes()).hexdigest(),
              'files_before_test_overlay': files,
              'overlay': {x.name: hashlib.sha256(x.read_bytes()).hexdigest()
                          for x in sorted(tools.iterdir()) if x.is_file()}}
    (a.output.parent / (a.role + '-source.json')).write_text(json.dumps(record, sort_keys=True, indent=2) + '\n')
    print(json.dumps({'role': a.role, 'source_commit': commit, 'source': str(a.output), 'files': len(files)}))

if __name__ == '__main__':
    main()
