"""Execute the production local preflight against synthetic files only."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

parser = argparse.ArgumentParser()
parser.add_argument('--client', type=Path, required=True)
args = parser.parse_args()
client = str(args.client.resolve())

def windows_ps(script):
    encoded = base64.b64encode(script.encode('utf-16-le')).decode('ascii')
    # Windows Python normalizes environment keys to uppercase. Remove every
    # spelling so PS5.1 rebuilds its own path instead of importing CI's PS7 modules.
    env = {key: value for key, value in os.environ.items()
           if key.upper() != 'PSMODULEPATH'}
    return subprocess.check_output(['powershell.exe', '-NoProfile', '-NonInteractive',
                                    '-EncodedCommand', encoded], env=env, timeout=10).decode().strip()

def private_acl(path, unsafe=False):
    if os.name == 'nt':
        quoted = "'" + str(path).replace("'", "''") + "'"
        sddl = 'D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)' + ('(A;;FA;;;WD)' if unsafe else '')
        windows_ps("$ErrorActionPreference='Stop';$p=" + quoted + ";$a=Get-Acl -LiteralPath $p;"
                   "$a.SetSecurityDescriptorSddlForm('" + sddl + "',"
                   "[Security.AccessControl.AccessControlSections]::Access);Set-Acl -LiteralPath $p -AclObject $a")

def permissions(path):
    if os.name == 'nt':
        quoted = "'" + str(path).replace("'", "''") + "'"
        return windows_ps("$ErrorActionPreference='Stop';(Get-Acl -LiteralPath " + quoted + ').Sddl')
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
        with Path(str(state)+'.lock').open('r+b') as lock:
            msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
            try:
                invoke('owner-lock-busy', ['--config', str(config)], 4)
            finally:
                msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)
    config.write_text('[offline\n')
    invoke('corrupt-config', ['--config', str(config)], 3)
    invoke('ambiguous', ['--config', str(config), '--defaults'], 2)
    # Output is exclusive, never truncate an existing caller-selected file.
    output = root/'existing.floor'; output.write_bytes(b'preserve')
    result = subprocess.run([client, '--storage-space-preflight', '--defaults', '--output', str(output)],
                            env=env, capture_output=True, timeout=10)
    assert result.returncode == 5 and output.read_bytes() == b'preserve'
    print('storage_space_preflight: defaults/config/missing-state/legacy-owner/ACL/corruption/output cases passed; real config/parser/owner lock; JSONL and owner ACL unchanged; no Agent startup')
