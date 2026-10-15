"""Execute the production local preflight against synthetic files only."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
import uuid

parser = argparse.ArgumentParser()
parser.add_argument('--client', type=Path, required=True)
args = parser.parse_args()
client = str(args.client.resolve())

if os.name == 'nt':
    import ctypes
    from ctypes import wintypes
    # Independent OS ACL boundary: no production security helper or subprocess.
    acl_api = ctypes.WinDLL('advapi32', use_last_error=True)
    acl_kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    acl_api.GetFileSecurityW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD,
                                        ctypes.c_void_p, wintypes.DWORD,
                                        ctypes.POINTER(wintypes.DWORD)]
    acl_api.GetFileSecurityW.restype = wintypes.BOOL
    acl_api.SetFileSecurityW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p]
    acl_api.SetFileSecurityW.restype = wintypes.BOOL
    acl_api.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.DWORD)]
    acl_api.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
    acl_api.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [
        ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.DWORD)]
    acl_api.ConvertSecurityDescriptorToStringSecurityDescriptorW.restype = wintypes.BOOL
    acl_kernel.LocalFree.argtypes = [ctypes.c_void_p]
    acl_kernel.LocalFree.restype = ctypes.c_void_p

    def free_security_buffer(buffer):
        if acl_kernel.LocalFree(buffer):
            raise ctypes.WinError(ctypes.get_last_error())

def private_acl(path, unsafe=False):
    if os.name == 'nt':
        sddl = 'D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)' + ('(A;;FA;;;WD)' if unsafe else '')
        descriptor = ctypes.c_void_p()
        if not acl_api.ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl, 1, ctypes.byref(descriptor), None):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            # DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION:
            # set the same protected DACL without changing owner or group.
            if not acl_api.SetFileSecurityW(str(path), 0x80000004, descriptor):
                raise ctypes.WinError(ctypes.get_last_error())
        finally:
            free_security_buffer(descriptor)

def permissions(path):
    if os.name == 'nt':
        # OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
        # DACL_SECURITY_INFORMATION, including the descriptor control flags.
        size = wintypes.DWORD()
        ok = acl_api.GetFileSecurityW(str(path), 7, None, 0, ctypes.byref(size))
        error = ctypes.get_last_error()
        if ok or error != 122 or not size.value:  # ERROR_INSUFFICIENT_BUFFER
            raise ctypes.WinError(error)
        descriptor = ctypes.create_string_buffer(size.value)
        if not acl_api.GetFileSecurityW(str(path), 7, descriptor, len(descriptor), ctypes.byref(size)):
            raise ctypes.WinError(ctypes.get_last_error())
        text = ctypes.c_void_p()
        if not acl_api.ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descriptor, 1, 7, ctypes.byref(text), None):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            assert text.value, 'empty security descriptor'
            return ctypes.wstring_at(text.value)
        finally:
            free_security_buffer(text)
    st = path.stat()
    return (st.st_mode, st.st_uid, st.st_gid)

with tempfile.TemporaryDirectory(prefix='edr-space-preflight-') as directory:
    root = Path(directory)
    state = root/'state'/'command_state.jsonl'
    config = root/'agent.toml'
    config.write_text('[offline]\ncommand_state_owner_budget_mb = 1\nstorage_min_free_mb = 0\n')
    env = dict(os.environ, EDR_COMMAND_STATE_DB=str(state),
               EDR_STORAGE_MIN_FREE_MB='999999', EDR_STORAGE_OWNER_PROTECTED_BYTES='unavailable')
    def invoke(name, flags, expected=0):
        output = root/(name+'.floor')
        result = subprocess.run([client, '--storage-space-preflight', *flags,
                                 '--output', str(output)], env=env, capture_output=True, timeout=10)
        assert result.returncode == expected, (name, result.returncode, result.stderr.decode(errors='replace'))
        assert not result.stdout, (name, 'unexpected stdout')
        if expected:
            assert not output.exists(), (name, 'failure emitted usable floor')
            return None
        raw = output.read_bytes()
        assert raw and raw.isdigit() and raw == str(int(raw)).encode(), (name, raw)
        return int(raw)
    # Fresh install must not create a real/default state directory or lock.
    default = invoke('defaults', ['--defaults'])
    assert default > 24*1024*1024 and not state.parent.exists()
    invoke('empty-config', ['--config', ''], 2)
    assert invoke('missing-config', ['--config', str(root/'absent')], 3) is None
    assert not state.parent.exists()
    assert invoke('missing-state-directory', ['--config', str(config)]) == 27*1024*1024
    assert not state.parent.exists(), 'inventory created missing owner directory'
    state.parent.mkdir(mode=0o700)
    private_acl(state.parent)
    parent_permissions = permissions(state.parent)
    assert invoke('empty-owner', ['--config', str(config)]) == 27*1024*1024
    assert not state.exists(), 'preflight created the owner database'
    # A valid legacy owner larger than a newly lowered budget remains protected.
    line = json.dumps({'record':'command_state','command_id':'legacy-owner','final':0,
                       'detail':'x'*65536}, separators=(',',':')).encode()+b'\n'
    state.write_bytes(line*20)
    state.chmod(0o600)
    private_acl(state)
    owner_permissions = permissions(state)
    before = state.read_bytes()
    before_hash = hashlib.sha256(before).hexdigest()
    protected = invoke('legacy-owner', ['--config', str(config)])
    assert protected > 27*1024*1024 and hashlib.sha256(state.read_bytes()).hexdigest() == before_hash
    assert permissions(state) == owner_permissions and permissions(state.parent) == parent_permissions
    # User-configured physical floor takes precedence without accepting inherited
    # environment values as a substitute for the selected local config.
    config.write_text('[offline]\ncommand_state_owner_budget_mb=1\nstorage_min_free_mb=64\n')
    assert invoke('configured-floor', ['--config', str(config)]) == 64*1024*1024
    state.write_bytes(before+b'{torn')
    corrupt = state.read_bytes()
    invoke('corrupt-owner', ['--config', str(config)], 4)
    assert state.read_bytes() == corrupt
    assert permissions(state) == owner_permissions and permissions(state.parent) == parent_permissions
    state.write_bytes(before)
    if os.name != 'nt':
        state.chmod(0o666)
        invoke('unsafe-owner-permissions', ['--config', str(config)], 4)
        assert state.stat().st_mode & 0o777 == 0o666, 'inventory repaired rejected permissions'
        state.chmod(0o600)
        state.parent.chmod(0o755)
        invoke('unsafe-parent-permissions', ['--config', str(config)], 4)
        assert state.parent.stat().st_mode & 0o777 == 0o755
        state.parent.chmod(0o700)
        import fcntl
        with Path(str(state)+'.lock').open('rb') as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            invoke('owner-lock-busy', ['--config', str(config)], 4)
    else:
        private_acl(state, unsafe=True)
        rejected_acl = permissions(state)
        invoke('unsafe-owner-acl', ['--config', str(config)], 4)
        assert permissions(state) == rejected_acl and state.read_bytes() == before
        private_acl(state)
        private_acl(state.parent, unsafe=True)
        rejected_parent_acl = permissions(state.parent)
        invoke('unsafe-parent-acl', ['--config', str(config)], 4)
        assert permissions(state.parent) == rejected_parent_acl and state.read_bytes() == before
        private_acl(state.parent)
        import msvcrt
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.CreateEventW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR]
        kernel.CreateEventW.restype = wintypes.HANDLE
        kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        kernel.WaitForSingleObject.restype = wintypes.DWORD
        kernel.SetEvent.argtypes = [wintypes.HANDLE]
        kernel.SetEvent.restype = wintypes.BOOL
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.CloseHandle.restype = wintypes.BOOL

        def contended_inventory(name, release, deadline=False, attempt_cap=False):
            prefix = 'Local\\EDRInventory-' + uuid.uuid4().hex
            events = {}
            child = None
            output = root/(name+'.floor')
            try:
                for label in ('observed', 'sleeping', 'resume'):
                    ctypes.set_last_error(0)
                    handle = kernel.CreateEventW(None, True, False, prefix+'-'+label)
                    assert handle and ctypes.get_last_error() != 183, 'event must be exclusive'
                    events[label] = handle
                mode = 'deadline' if deadline else ('attempt_cap' if attempt_cap else 'observe')
                child_env = dict(env, EDR_PREFLIGHT_TEST_MODE=mode,
                                 EDR_PREFLIGHT_TEST_EVENT_PREFIX=prefix)
                with Path(str(state)+'.lock').open('r+b') as lock:
                    msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
                    locked = True
                    started = time.monotonic()
                    try:
                        child = subprocess.Popen([client, '--storage-space-preflight', '--config', str(config),
                                                  '--output', str(output)], env=child_env,
                                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        # A real LockFileEx failure, not elapsed startup time,
                        # authorizes the parent to release its actual byte lock.
                        assert kernel.WaitForSingleObject(events['observed'], 5000) == 0, name
                        if deadline:
                            assert kernel.WaitForSingleObject(events['sleeping'], 5000) == 0, name
                        if release:
                            msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)
                            locked = False
                        if deadline:
                            assert kernel.SetEvent(events['resume']), name
                        stdout, stderr = child.communicate(timeout=5)
                    finally:
                        if locked:
                            msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)
                elapsed = time.monotonic()-started
                expected = 0 if release and not deadline else 7
                assert child.returncode == expected, (name, child.returncode, stderr.decode(errors='replace'))
                assert not stdout and elapsed < 8, (name, elapsed)
                trace = re.findall(rb'inventory_test attempts=(\d+) conflicts=(\d+) sleeps=(\d+) mode=(observe|deadline|attempt_cap)', stderr)
                assert len(trace) == 1, (name, stderr)
                attempts, conflicts, sleeps = (int(value) for value in trace[0][:3])
                assert conflicts >= 1 and sleeps >= 1, name
                if deadline:
                    # The real lock is now free: an erroneous post-deadline
                    # attempt would succeed and invalidate this assertion.
                    assert attempts == conflicts == sleeps == 1, name
                elif attempt_cap:
                    assert attempts == conflicts == 41 and sleeps == 40, name
                elif release:
                    assert attempts >= 2 and attempts > conflicts, name
                else:
                    assert attempts == conflicts and elapsed >= 0.9, (name, elapsed)
                if expected:
                    assert b'storage preflight: owner_lock_timeout\n' in stderr.replace(b'\r\n', b'\n'), name
                    assert not output.exists(), (name, 'failure emitted usable floor')
                else:
                    assert output.read_bytes() == str(64*1024*1024).encode(), name
                assert hashlib.sha256(state.read_bytes()).hexdigest() == before_hash, name
            finally:
                if child is not None and child.poll() is None:
                    child.kill()
                    child.communicate(timeout=3)
                for handle in events.values():
                    assert kernel.CloseHandle(handle)
            print(json.dumps({'case': name, 'exit': child.returncode,
                              'attempts': attempts, 'conflicts': conflicts, 'sleeps': sleeps,
                              'clock_mode': trace[0][3].decode('ascii'),
                              'elapsed_seconds': round(elapsed, 6)}, sort_keys=True), flush=True)

        contended_inventory('owner-lock-released', release=True)
        contended_inventory('owner-lock-timeout', release=False)
        contended_inventory('owner-lock-deadline', release=True, deadline=True)
        contended_inventory('owner-lock-attempt-cap', release=False, attempt_cap=True)
        assert permissions(state) == owner_permissions and permissions(state.parent) == parent_permissions
    config.write_text('[offline\n')
    invoke('corrupt-config', ['--config', str(config)], 3)
    invoke('ambiguous', ['--config', str(config), '--defaults'], 2)
    # Output is exclusive, never truncate an existing caller-selected file.
    output = root/'existing.floor'; output.write_bytes(b'preserve')
    result = subprocess.run([client, '--storage-space-preflight', '--defaults', '--output', str(output)],
                            env=env, capture_output=True, timeout=10)
    assert result.returncode == 5 and output.read_bytes() == b'preserve'
    print('storage_space_preflight: defaults/config/missing-state/legacy-owner/ACL/corruption/output cases passed; real config/parser/owner lock; JSONL and owner ACL unchanged; no Agent startup')
