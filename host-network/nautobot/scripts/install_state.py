#!/usr/bin/env python3
"""Fixed first-install journal and guarded acceptance. No remote orchestration."""
import fcntl
import hashlib
import json
import tempfile
import os
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
import backend_guard as guard
from rollback_install import ALLOWED

BASE = Path('/var/lib/nautobot-backend-install')


def write(value):
    fd, name = tempfile.mkstemp(prefix='state-', dir=BASE)
    temp = Path(name)
    with os.fdopen(fd, 'w') as f:
        os.fchmod(f.fileno(), 0o600)
        json.dump(value, f);f.flush();os.fsync(f.fileno())
    os.replace(temp, BASE / 'state.json')


def main(action):
    if os.geteuid() != 0:
        raise RuntimeError('root required')
    if guard.run(['hostname','-s']).strip() != 'j2-svpi4mf' or guard.run(['id','-u','nautobot']).strip() != '999':
        raise RuntimeError('target identity drift')
    state_file = BASE / 'state.json'
    if action == 'prepare':
        if state_file.exists():
            raise RuntimeError('existing operation state')
        expected = json.loads(guard.trusted(BASE / 'inputs.json'))
        if set(expected['files']) != ALLOWED or expected['baseline'] != 'all_owned_files_absent':
            raise RuntimeError('unexpected installation manifest')
        if any(Path(x).exists() or Path(x).is_symlink() for x in ALLOWED):
            raise RuntimeError('existing artifact; first-install contract only')
        if guard.table() is not None or guard.run(['/usr/bin/ss','-H','-ltn','sport','=',':8080']).strip():
            raise RuntimeError('guard/listener already present')
        expected['status'] = 'prepared'
        write(expected)
    elif action == 'accept':
        value = json.loads(guard.trusted(state_file))
        if value['status'] != 'prepared':
            raise RuntimeError('not pending')
        for name, sha in value['files'].items():
            if hashlib.sha256(guard.trusted(Path(name)).encode()).hexdigest() != sha:
                raise RuntimeError('installed artifact mismatch')
        guard.verify(guard.table(), value['table_digest'])
        if guard.run(['/usr/bin/ss','-H','-ltn','sport','=',':8080']).strip():
            raise RuntimeError('unexpected application start')
        value['status'] = 'accepted'
        write(value)
        guard.run(['systemctl','stop','nautobot-backend-install-rollback.timer'])
    else:
        raise ValueError('invalid action')


if __name__ == '__main__':
    try:
        with open(BASE / 'lock', 'a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            main(sys.argv[1])
    except Exception as exc:
        print('GUARD_INSTALL_FAILED: ' + (str(exc) if isinstance(exc, RuntimeError) else type(exc).__name__), file=sys.stderr)
        sys.exit(1)
