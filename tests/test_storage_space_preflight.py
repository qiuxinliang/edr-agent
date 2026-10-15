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

        def queued_inventory(name, mode='observe', release=False, held=True, expected=7):
            # The ordinary event and subprocess bounds stay 5 s / 8 s. Only the
            # dedicated self-watchdog case has an absolute 25 s parent budget.
            watchdog = mode == 'stall'
            prefix = 'Local\\EDRInventory-' + uuid.uuid4().hex
            events = {}
            child = None
            lock = None
            locked = False
            output = root/(name+'.floor')
            labels = ('q-pending', 'q-cancel-entered', 'q-grant', 'q-resume',
                      'q-completion-ready', 'q-completion-resume', 'q-stall-entered',
                      'q-stall-resume', 'q-finished', 'q-finish-resume')
            started = time.monotonic()
            try:
                for label in labels:
                    ctypes.set_last_error(0)
                    handle = kernel.CreateEventW(None, True, False, prefix+'-'+label)
                    assert handle and ctypes.get_last_error() != 183, 'event must be exclusive'
                    events[label] = handle
                if held:
                    lock = Path(str(state)+'.lock').open('r+b')
                    msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
                    locked = True
                child_env = dict(env, EDR_PREFLIGHT_TEST_MODE=mode,
                                 EDR_PREFLIGHT_TEST_EVENT_PREFIX=prefix)
                child_started = time.monotonic()
                child = subprocess.Popen([client, '--storage-space-preflight', '--config', str(config),
                                          '--output', str(output)], env=child_env,
                                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                def wait_event(label):
                    assert kernel.WaitForSingleObject(events[label], 5000) == 0, (name, label)
                def release_holder():
                    nonlocal locked
                    lock.seek(0)
                    msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)
                    locked = False
                if held:
                    # A real ERROR_IO_PENDING establishes contention. No
                    # startup sleep may stand in for a pending OS lock request.
                    wait_event('q-pending')
                if mode == 'late_grant':
                    wait_event('q-cancel-entered')
                    release_holder()
                    wait_event('q-grant')  # child observed its real kernel event
                    assert kernel.SetEvent(events['q-resume'])
                elif mode in ('completion_expired', 'completion_expired_unlock_failure'):
                    if held:
                        release_holder()
                    wait_event('q-completion-ready')
                    time.sleep(1.1)  # real monotonic deadline; no fake clock
                    assert kernel.SetEvent(events['q-completion-resume'])
                elif release:
                    release_holder()
                if watchdog:
                    wait_event('q-stall-entered')
                    # A native unsignalled event deliberately blocks cleanup.
                    # The real CLI watchdog, not parent.kill, must end it.
                    remaining = 25-(time.monotonic()-started)
                    assert remaining > 0
                    stdout, stderr = child.communicate(timeout=remaining)
                    child_elapsed = time.monotonic()-child_started
                else:
                    wait_event('q-finished')
                    assert child.poll() is None, (name, 'child exited before release proof')
                    if locked:
                        release_holder()
                    # A distinct handle must acquire the byte while the child
                    # remains alive; process exit cannot explain its release.
                    with Path(str(state)+'.lock').open('r+b') as probe:
                        msvcrt.locking(probe.fileno(), msvcrt.LK_NBLCK, 1)
                        msvcrt.locking(probe.fileno(), msvcrt.LK_UNLCK, 1)
                    assert kernel.SetEvent(events['q-finish-resume'])
                    stdout, stderr = child.communicate(timeout=5)
                    child_elapsed = time.monotonic()-child_started
                elapsed = time.monotonic()-started
                assert child.returncode == expected, (name, child.returncode, stderr.decode(errors='replace'))
                assert not stdout and elapsed < (25 if watchdog else 8), (name, elapsed)
                trace = [json.loads(value) for value in re.findall(rb'queued_test (\{[^\r\n]+\})', stderr)]
                assert len(trace) == 1, (name, stderr)
                observed = trace[0]
                assert observed['mode'] == mode
                if mode in ('watchdog_event_failure', 'watchdog_thread_failure'):
                    assert observed['requests'] == observed['inventory_scan_calls'] == 0
                    assert b'deadline_unavailable' in stderr
                elif mode == 'before_request':
                    assert observed['point'] == 'returned' and observed['rc'] == 10
                    assert observed['elapsed_ms'] >= 1100 and child_elapsed >= 1.0
                    assert all(observed[key] == 0 for key in (
                        'requests', 'lock_pending', 'cancel_calls', 'lock_completions',
                        'unlock_requests', 'unlock_pending', 'unlock_completions',
                        'inventory_scan_calls')), observed
                else:
                    assert observed['requests'] == 1, observed
                    assert observed['lock_pending'] == int(held), observed
                    if watchdog:
                        assert observed['point'] == 'cleanup_stall_entered' and child_elapsed >= 14.5
                        assert observed['cancel_calls'] == observed['inventory_scan_calls'] == 0
                    else:
                        assert observed['point'] == 'returned' and observed['rc'] == expected
                        assert observed['lock_completions'] == 1
                        assert observed['lock_completion_error'] == (995 if held and not release and mode == 'observe' else 0)
                        assert observed['inventory_scan_calls'] == int(
                            expected in (0, 4) and mode != 'completion_expired_unlock_failure')
                        if mode == 'late_grant':
                            assert observed['cancel_calls'] == 1 and observed['cancel_error'] in (0, 1168)
                        elif held and not release and mode == 'observe':
                            assert observed['cancel_calls'] == 1 and observed['cancel_error'] == 0
                        else:
                            assert observed['cancel_calls'] == 0
                        unlocks = int(observed['lock_completion_error'] == 0)
                        assert observed['unlock_requests'] == observed['unlock_completions'] == unlocks
                        assert observed['unlock_completion_error'] == (
                            5 if mode in ('unlock_failure', 'completion_expired_unlock_failure') else 0)
                        if mode == 'completion_expired_unlock_failure':
                            assert child_elapsed >= 1.0
                            assert b'storage preflight: owner accounting or policy unavailable\n' in stderr.replace(b'\r\n', b'\n')
                if expected:
                    assert not output.exists(), (name, 'failure emitted usable floor')
                else:
                    assert output.read_bytes() == str(64*1024*1024).encode(), name
                if expected in (7, 9, 10):
                    assert child_elapsed >= 0.9, (name, 'admission expired before its budget')
                    reason = {7: b'owner_lock_timeout', 9: b'owner_lock_granted_expired',
                              10: b'owner_lock_deadline_before_request'}[expected]
                    assert b'storage preflight: ' + reason + b'\n' in stderr.replace(b'\r\n', b'\n')
                assert hashlib.sha256(state.read_bytes()).hexdigest() == before_hash, name
            finally:
                if child is not None and child.poll() is None:
                    child.kill()
                    child.communicate(timeout=3)
                if locked:
                    release_holder()
                if lock is not None:
                    lock.close()
                for handle in events.values():
                    assert kernel.CloseHandle(handle)
            print(json.dumps({'case': name, 'exit': child.returncode, 'observation': observed,
                              'elapsed_seconds': round(elapsed, 6),
                              'child_elapsed_seconds': round(child_elapsed, 6)}, sort_keys=True), flush=True)

        queued_inventory('owner-lock-released', release=True, expected=0)
        queued_inventory('owner-lock-timeout')
        queued_inventory('owner-lock-late-grant', mode='late_grant', expected=9)
        queued_inventory('owner-lock-completion-expired', mode='completion_expired', expected=9)
        queued_inventory('owner-lock-immediate-completion-expired', mode='completion_expired', held=False, expected=9)
        queued_inventory('owner-lock-expired-unlock-failure', mode='completion_expired_unlock_failure', held=False, expected=4)
        queued_inventory('owner-lock-deadline-before-request', mode='before_request', held=False, expected=10)
        queued_inventory('owner-unlock-failure', mode='unlock_failure', held=False, expected=4)
        queued_inventory('watchdog-event-unavailable', mode='watchdog_event_failure', held=False, expected=8)
        queued_inventory('watchdog-thread-unavailable', mode='watchdog_thread_failure', held=False, expected=8)
        queued_inventory('preflight-cleanup-watchdog', mode='stall', expected=124)
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
